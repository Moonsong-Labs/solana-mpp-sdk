//! `(payee, mint)`-keyed registry of open channels with single-flight
//! deduplication on first-touch auto-open.
//!
//! Two concurrent first requests against the same `(payee, mint)` pair
//! must not each spin up a fresh channel: each open burns a fee from
//! the operator's budget, and the duplicate channel is unrecoverable
//! once the second open lands. The registry serialises that decision
//! through a `(payee, mint)` slot so only one caller runs the opener;
//! every other caller waits and either picks up the resulting handle
//! or retries one round.
//!
//! Two maps:
//!
//! - `sessions: DashMap<(payee, mint), Arc<Mutex<(OpenedChannel, ActiveSession)>>>`
//!   holds each open channel's wire-level snapshot paired with its
//!   off-chain meter, behind a per-channel mutex so voucher signing is
//!   serialised within a channel without serialising across channels.
//! - `in_flight: DashMap<(payee, mint), Arc<Notify>>` is the first-touch
//!   slot. Vacant entry: caller wins, runs the opener, removes the
//!   slot, broadcasts to waiters, then publishes into `sessions`.
//!   Occupied entry: caller waits, then re-checks `sessions` once.
//!
//! On the success path the cell is published into `sessions` before
//! the slot is removed and waiters are woken, so a waiter's re-check
//! always sees the new cell instead of racing into a "slot empty,
//! sessions empty" gap. On the failure path the slot is released and
//! waiters are woken first; the loser's re-check returns
//! `SessionOpenContended` so the caller's outer retry can become the
//! next winner. Bounding the loser's loop to one round avoids livelock
//! under a stuck opener.
//!
//! A `Notify` permit only wakes waiters that are already registered,
//! so losers register on the entry's `Notified` future via `enable()`
//! while still under the dashmap entry guard. That way the winner's
//! `notify_waiters()` (whether it fires from the explicit failure
//! branch or from the RAII guard's `Drop`) is guaranteed to reach them.
//! The RAII guard in the winner's frame also covers panics and
//! future-cancellation: if `opener().await` is dropped or unwinds, the
//! slot is still removed and waiters still wake, so a leaked entry
//! never strands future callers.

use std::sync::Arc;

use dashmap::DashMap;
use solana_pubkey::Pubkey;
use tokio::sync::{Mutex, Notify};

use crate::client::session::ActiveSession;
use crate::error::ClientError;
use crate::protocol::intents::session::BpsSplit;

/// On-chain / wire-level shape of an open channel.
///
/// Pairs with an [`ActiveSession`] (off-chain meter) inside the
/// registry's per-channel mutex. `Clone` so callers reading through
/// the mutex can take a cheap snapshot for read-only inspection
/// without holding the lock.
#[derive(Clone)]
pub struct OpenedChannel {
    pub channel_id: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub deposit: u64,
    pub splits: Vec<BpsSplit>,
    pub authorized_signer: Pubkey,
    pub salt: u64,
    pub canonical_bump: u8,
    pub program_id: Pubkey,
    pub expires_at: Option<i64>,
}

/// Per-channel cell shared across the registry. Voucher signing and
/// receipt application happen under this mutex so concurrent fetches
/// against the same channel can't double-spend a cumulative.
pub type SessionCell = Arc<Mutex<(OpenedChannel, ActiveSession)>>;

/// `(payee, mint)`-keyed registry of open channels with single-flight
/// on the first auto-open per key.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: DashMap<(Pubkey, Pubkey), SessionCell>,
    in_flight: DashMap<(Pubkey, Pubkey), Arc<Notify>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lookup an existing cell. Returns `None` if no channel has been
    /// opened for this `(payee, mint)` pair (or if `forget` was called
    /// since the last open).
    pub fn lookup(&self, payee: &Pubkey, mint: &Pubkey) -> Option<SessionCell> {
        self.sessions.get(&(*payee, *mint)).map(|e| e.value().clone())
    }

    /// Resolve to the `(payee, mint)` cell, opening exactly once on
    /// first-touch. Concurrent callers either become the single winner
    /// (running `opener`) or wait on the winner's `Notify` and pick up
    /// the resulting cell.
    ///
    /// If the winner's opener failed, the slot is released and waiters
    /// wake to a still-empty `sessions` map. The loser's re-check
    /// returns `SessionOpenContended` so the caller's outer retry
    /// policy decides whether to try again as the next winner. Bounded
    /// to one re-check so livelock stays out of the registry itself.
    pub async fn get_or_open<F, Fut>(
        &self,
        payee: &Pubkey,
        mint: &Pubkey,
        opener: F,
    ) -> Result<SessionCell, ClientError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(OpenedChannel, ActiveSession), ClientError>>,
    {
        let key = (*payee, *mint);

        if let Some(entry) = self.sessions.get(&key) {
            return Ok(entry.value().clone());
        }

        // Claim the in-flight slot or wait on whoever did. Can't hold
        // the dashmap entry guard across an await (deadlocks the
        // shard), and `notify_waiters` doesn't bank a permit, so a
        // loser has to register on the `Notified` future via
        // `enable()` while still under the entry guard. A bare
        // `notified().await` after dropping the guard would strand
        // the loser if the winner fires in between.
        let notify = match self.in_flight.entry(key) {
            dashmap::Entry::Occupied(slot) => {
                let waiter = slot.get().clone();
                let notified = waiter.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                drop(slot);
                notified.await;

                // One re-check. If the cell still isn't there the
                // winner's opener failed; bounce so the caller's next
                // attempt can claim a fresh slot.
                return match self.sessions.get(&key) {
                    Some(entry) => Ok(entry.value().clone()),
                    None => Err(ClientError::SessionOpenContended),
                };
            }
            dashmap::Entry::Vacant(slot) => {
                let notify = Arc::new(Notify::new());
                slot.insert(notify.clone());
                notify
            }
        };

        // Winner. The RAII guard removes the in-flight slot and wakes
        // waiters on drop, which also covers panic and future-cancel
        // in the opener. Drop order matters: on success we publish
        // into `sessions` before the guard drops at end-of-scope, so
        // a woken waiter's re-check sees the new cell instead of an
        // empty map.
        let _guard = InFlightGuard {
            in_flight: &self.in_flight,
            notify,
            key,
        };

        let (opened, active) = opener().await?;
        let cell = Arc::new(Mutex::new((opened, active)));
        self.sessions.insert(key, cell.clone());
        Ok(cell)
    }

    /// Removes the cached session for `(payee, mint)`.
    ///
    /// Used by the high-level fetch flow when a channel transitions
    /// out of `Open` (e.g. tombstoned after a forced close) and the
    /// next request should mint a fresh channel.
    ///
    /// Callers must not invoke `forget` while a `get_or_open` is in
    /// flight against the same `(payee, mint)` pair; the registry
    /// does not enforce it. If `forget` races a winner that has
    /// already returned from its on-chain `opener` but hasn't
    /// published the cell into `sessions` yet, the published cell
    /// gets promptly removed by `forget`, leaking the cell (already
    /// paid for on-chain) into the winner's caller while the next
    /// `get_or_open` mints a fresh channel. The operator's fee budget
    /// gets billed twice for the same `(payee, mint)`. The
    /// higher-level fetch wiring is responsible for sequencing
    /// `forget` after a `close` has confirmed and while no concurrent
    /// open is racing it (typically by holding the per-cell mutex
    /// across close+forget).
    ///
    /// Does not cancel an in-flight `get_or_open`: the winner still
    /// returns its `Ok(cell)` to its caller. The cell is just no
    /// longer reachable through the registry afterward.
    pub fn forget(&self, payee: &Pubkey, mint: &Pubkey) {
        self.sessions.remove(&(*payee, *mint));
    }
}

/// RAII guard that cleans up the in-flight slot and wakes waiters
/// when it drops. Held by the winning `get_or_open` caller for the
/// duration of the opener so a panic or future-cancel in the opener
/// never leaks the slot. The shared `Arc<Notify>` is the same one
/// stored in the dashmap entry, so waiters that registered via
/// `Notified::enable` before we dropped the entry guard still wake on
/// this notification.
struct InFlightGuard<'a> {
    in_flight: &'a DashMap<(Pubkey, Pubkey), Arc<Notify>>,
    notify: Arc<Notify>,
    key: (Pubkey, Pubkey),
}

impl<'a> Drop for InFlightGuard<'a> {
    fn drop(&mut self) {
        self.in_flight.remove(&self.key);
        self.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use solana_keychain::{MemorySigner, SolanaSigner};
    use solana_sdk::signature::Keypair;

    fn fresh_signer() -> Arc<dyn SolanaSigner> {
        let kp = Keypair::new();
        let signer =
            MemorySigner::from_bytes(&kp.to_bytes()).expect("memory signer accepts bytes");
        Arc::new(signer)
    }

    fn fresh_channel(channel_id: Pubkey, payee: Pubkey, mint: Pubkey) -> OpenedChannel {
        OpenedChannel {
            channel_id,
            payee,
            mint,
            deposit: 1_000_000,
            splits: vec![],
            authorized_signer: Pubkey::new_from_array([0u8; 32]),
            salt: 0,
            canonical_bump: 254,
            program_id: Pubkey::new_from_array([1u8; 32]),
            expires_at: None,
        }
    }

    fn fresh_active(channel_id: Pubkey) -> ActiveSession {
        ActiveSession::new(channel_id, fresh_signer(), 0, 1_000_000)
    }

    fn fresh_open(
        channel_id: Pubkey,
        payee: Pubkey,
        mint: Pubkey,
    ) -> (OpenedChannel, ActiveSession) {
        (
            fresh_channel(channel_id, payee, mint),
            fresh_active(channel_id),
        )
    }

    #[tokio::test]
    async fn lookup_missing_returns_none() {
        let reg = SessionRegistry::new();
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        assert!(reg.lookup(&payee, &mint).is_none());
    }

    #[tokio::test]
    async fn lookup_after_get_or_open_returns_arc() {
        let reg = SessionRegistry::new();
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let channel_id = Pubkey::new_unique();

        let cell = reg
            .get_or_open(&payee, &mint, || async {
                Ok(fresh_open(channel_id, payee, mint))
            })
            .await
            .expect("opener succeeds");

        let looked = reg.lookup(&payee, &mint).expect("lookup hits");
        assert!(Arc::ptr_eq(&cell, &looked));

        let guard = looked.lock().await;
        assert_eq!(guard.0.channel_id, channel_id);
    }

    #[tokio::test]
    async fn concurrent_get_or_open_against_same_key_calls_opener_once() {
        // Ten tasks fight for the same (payee, mint). Exactly one
        // runs the opener; the other nine resolve to the same
        // Arc<Mutex<...>>.
        let reg = Arc::new(SessionRegistry::new());
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let channel_id = Pubkey::new_unique();
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(10);
        for _ in 0..10 {
            let reg = reg.clone();
            let counter = counter.clone();
            handles.push(tokio::spawn(async move {
                reg.get_or_open(&payee, &mint, || async {
                    counter.fetch_add(1, Ordering::SeqCst);
                    // Yield back to the scheduler so the other tasks
                    // reach the in_flight slot before we finish.
                    // Without this the winner can race to completion
                    // before any loser observes the slot.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(fresh_open(channel_id, payee, mint))
                })
                .await
                .expect("get_or_open resolves")
            }));
        }

        let mut cells = Vec::with_capacity(10);
        for h in handles {
            cells.push(h.await.expect("task joins"));
        }

        assert_eq!(counter.load(Ordering::SeqCst), 1, "opener ran exactly once");

        // All ten tasks resolved to the same cell.
        let first = cells[0].clone();
        for c in &cells[1..] {
            assert!(Arc::ptr_eq(&first, c), "all callers share the same cell");
        }
    }

    #[tokio::test]
    async fn opener_failure_lets_next_caller_retry() {
        let reg = SessionRegistry::new();
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let result = reg
            .get_or_open(&payee, &mint, || async {
                Err(ClientError::ProtocolViolation("opener failed".into()))
            })
            .await;
        match result {
            Ok(_) => panic!("first opener should have failed"),
            Err(ClientError::ProtocolViolation(_)) => {}
            Err(other) => panic!("expected ProtocolViolation, got {other:?}"),
        }
        // The winner here propagates its own error. The loser path
        // that surfaces SessionOpenContended is exercised separately
        // by the concurrency tests below.

        // No cached cell after a failed open.
        assert!(reg.lookup(&payee, &mint).is_none());

        // Second caller becomes the new winner and succeeds.
        let channel_id = Pubkey::new_unique();
        let cell = reg
            .get_or_open(&payee, &mint, || async {
                Ok(fresh_open(channel_id, payee, mint))
            })
            .await
            .expect("second opener succeeds");

        let guard = cell.lock().await;
        assert_eq!(guard.0.channel_id, channel_id);
    }

    #[tokio::test]
    async fn forget_drops_entry_so_next_call_re_opens() {
        let reg = SessionRegistry::new();
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let first_id = Pubkey::new_unique();

        reg.get_or_open(&payee, &mint, || async {
            Ok(fresh_open(first_id, payee, mint))
        })
        .await
        .expect("first open");

        assert!(reg.lookup(&payee, &mint).is_some());

        reg.forget(&payee, &mint);
        assert!(reg.lookup(&payee, &mint).is_none());

        // The next call has to run a fresh opener that lands a
        // different channel_id. If forget were a no-op the cached
        // cell would short-circuit the new opener and we'd see the
        // old id.
        let second_id = Pubkey::new_unique();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_inner = counter.clone();
        let cell = reg
            .get_or_open(&payee, &mint, || async move {
                counter_inner.fetch_add(1, Ordering::SeqCst);
                Ok(fresh_open(second_id, payee, mint))
            })
            .await
            .expect("second open after forget");

        assert_eq!(counter.load(Ordering::SeqCst), 1, "second opener ran");
        let guard = cell.lock().await;
        assert_eq!(guard.0.channel_id, second_id);
        assert_ne!(guard.0.channel_id, first_id);
    }

    /// Regression for the publish-vs-notify ordering bug: if the
    /// winner removed the in-flight slot and notified waiters before
    /// inserting into `sessions`, a waiter scheduled into that gap
    /// would see an empty `sessions` map on its single re-check and
    /// falsely return `SessionOpenContended` even though the open
    /// succeeded. The fix publishes into `sessions` first; this test
    /// pins it by mixing several scheduler yield points into the
    /// opener so any drift in the ordering reliably surfaces.
    #[tokio::test]
    async fn winner_publishes_session_before_notifying_waiters() {
        let reg = Arc::new(SessionRegistry::new());
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let channel_id = Pubkey::new_unique();
        let counter = Arc::new(AtomicUsize::new(0));

        // Winner starts first via a tiny lead, with multiple yield
        // points in the opener so the scheduler has many chances to
        // hand control to losers between "remove slot + notify" and
        // "insert into sessions" if the ordering is wrong.
        let winner_reg = reg.clone();
        let winner_counter = counter.clone();
        let winner = tokio::spawn(async move {
            winner_reg
                .get_or_open(&payee, &mint, || async move {
                    winner_counter.fetch_add(1, Ordering::SeqCst);
                    for _ in 0..10 {
                        tokio::task::yield_now().await;
                    }
                    Ok(fresh_open(channel_id, payee, mint))
                })
                .await
        });

        // Give the winner a head start so it claims the in-flight
        // slot before the losers race for it. Without this the
        // losers can win the slot themselves, defeating the test.
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Five losers. Their opener returns Err, so if any of them
        // ever wins the slot the test fails loudly via the assertion
        // on the opener counter at the end.
        let mut loser_handles = Vec::with_capacity(5);
        for _ in 0..5 {
            let loser_reg = reg.clone();
            let loser_counter = counter.clone();
            loser_handles.push(tokio::spawn(async move {
                loser_reg
                    .get_or_open(&payee, &mint, || async move {
                        loser_counter.fetch_add(1, Ordering::SeqCst);
                        Err(ClientError::ProtocolViolation("loser opener".into()))
                    })
                    .await
            }));
        }

        let winner_cell = winner
            .await
            .expect("winner task joins")
            .expect("winner opener succeeds");

        for h in loser_handles {
            let result = h.await.expect("loser task joins");
            match result {
                Ok(cell) => {
                    assert!(
                        Arc::ptr_eq(&winner_cell, &cell),
                        "loser resolved to a different cell than the winner"
                    );
                }
                Err(other) => panic!(
                    "loser saw an error after a successful open; \
                     this is the publish-vs-notify regression: {other:?}"
                ),
            }
        }

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one opener ran (the winner's); losers must never have claimed the slot"
        );
    }

    /// Regression for the lost-wakeup bug: a bare
    /// `waiter.notified().await` on the loser path lets the winner's
    /// `notify_waiters()` fire between the entry-guard drop and the
    /// future being polled, in which case the loser never wakes. The
    /// fix builds the `Notified` future and calls `enable()` while
    /// still under the entry guard so the loser is registered before
    /// the winner can possibly fire.
    ///
    /// The winner runs first with a custom opener that signals "slot
    /// claimed" via a `Notify` and then awaits a "go" signal. While
    /// it's suspended the in-flight slot is occupied, so any
    /// concurrent caller hits the `Occupied` arm. The loser is
    /// spawned, races in, registers as a waiter, and suspends. The
    /// winner is released, finishes its opener, publishes the cell,
    /// and the RAII guard fires `notify_waiters()`. The loser has to
    /// observe the wakeup, re-check `sessions`, and resolve to the
    /// winner's cell.
    ///
    /// Whole thing runs under a `tokio::time::timeout`. Without the
    /// fix the wakeup is lost in the gap between the guard drop in
    /// the loser's `Occupied` arm and the loser polling `Notified`
    /// for the first time, the loser never wakes, and the timeout
    /// fires. Repeated for many iterations because the bug surfaces
    /// only on specific scheduler interleavings; with the fix every
    /// iteration completes well under the timeout.
    #[tokio::test]
    async fn loser_woken_after_winner_notifies_does_not_livelock() {
        for iter in 0..50 {
            let reg = Arc::new(SessionRegistry::new());
            let payee = Pubkey::new_unique();
            let mint = Pubkey::new_unique();
            let channel_id = Pubkey::new_unique();

            let winner_in = Arc::new(tokio::sync::Notify::new());
            let winner_go = Arc::new(tokio::sync::Notify::new());

            let winner_reg = reg.clone();
            let winner_in_signal = winner_in.clone();
            let winner_go_wait = winner_go.clone();
            let winner = tokio::spawn(async move {
                winner_reg
                    .get_or_open(&payee, &mint, || async move {
                        winner_in_signal.notify_one();
                        winner_go_wait.notified().await;
                        Ok(fresh_open(channel_id, payee, mint))
                    })
                    .await
            });

            // Wait for the winner to enter its opener. By this point
            // the in-flight slot is occupied, so the loser is forced
            // into the `Occupied` branch.
            winner_in.notified().await;

            let loser_reg = reg.clone();
            let loser = tokio::spawn(async move {
                loser_reg
                    .get_or_open(&payee, &mint, || async move {
                        // The loser can't reach this branch under
                        // the coordination above. If it does, the
                        // test setup is broken, not the registry.
                        Err(ClientError::ProtocolViolation(
                            "loser opener ran; coordination broken".into(),
                        ))
                    })
                    .await
            });

            // Give the loser a moment to enter the `Occupied` branch
            // and start awaiting on `Notified`. Then release the
            // winner; its RAII guard fires `notify_waiters()`, which
            // has to reach the loser.
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
            winner_go.notify_one();

            let joined = tokio::time::timeout(Duration::from_secs(5), async {
                let w = winner.await.expect("winner task joins");
                let l = loser.await.expect("loser task joins");
                (w, l)
            })
            .await
            .unwrap_or_else(|_| panic!("iteration {iter}: timeout, loser never woken"));

            match joined.0 {
                Ok(_) => {}
                Err(e) => panic!("iteration {iter}: winner failed: {e:?}"),
            }
            match joined.1 {
                Ok(_) => {}
                Err(other) => panic!("iteration {iter}: loser failed: {other:?}"),
            }
        }
    }

    /// Regression for the panic-leaks-slot bug: if the opener panics
    /// (or the future is cancelled) while suspended, the in-flight
    /// slot must still be released. Without the RAII guard, the slot
    /// stays occupied forever and every subsequent `get_or_open` hangs.
    ///
    /// We drive the panic via a `tokio::spawn`+`JoinHandle::await`,
    /// which surfaces the unwind as a `JoinError` rather than tearing
    /// down the test runtime. After observing the join error, we run a
    /// fresh `get_or_open` against the same key and assert it
    /// completes (i.e. the slot was released by the guard's drop).
    #[tokio::test]
    async fn winner_panic_releases_in_flight_slot() {
        let reg = Arc::new(SessionRegistry::new());
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let panicking_reg = reg.clone();
        let panicking = tokio::spawn(async move {
            panicking_reg
                .get_or_open(&payee, &mint, || async {
                    panic!("opener panicked");
                })
                .await
        });

        match panicking.await {
            Ok(_) => panic!("opener was supposed to panic, not return"),
            Err(join_err) => assert!(
                join_err.is_panic(),
                "expected JoinError::is_panic(), got {join_err:?}"
            ),
        }

        // The slot should have been cleaned up by the RAII guard's
        // drop during unwind. A fresh open must succeed within a
        // bounded time; if the slot is leaked the call hangs forever
        // waiting on a Notify that will never fire.
        let channel_id = Pubkey::new_unique();
        let cell = tokio::time::timeout(
            Duration::from_secs(5),
            reg.get_or_open(&payee, &mint, || async {
                Ok(fresh_open(channel_id, payee, mint))
            }),
        )
        .await
        .expect("fresh open must complete; in-flight slot was leaked")
        .expect("fresh open succeeds");

        let guard = cell.lock().await;
        assert_eq!(guard.0.channel_id, channel_id);
    }

    /// Companion to `winner_panic_releases_in_flight_slot`: same shape
    /// but the failure mode is future-cancellation (caller dropped the
    /// future) rather than a panic. The RAII guard covers both.
    #[tokio::test]
    async fn winner_cancellation_releases_in_flight_slot() {
        let reg = Arc::new(SessionRegistry::new());
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let cancelled_reg = reg.clone();
        let started = Arc::new(tokio::sync::Notify::new());
        let started_signal = started.clone();
        let cancelled = tokio::spawn(async move {
            cancelled_reg
                .get_or_open(&payee, &mint, || async move {
                    started_signal.notify_one();
                    // Hang here until the task is aborted.
                    std::future::pending::<()>().await;
                    unreachable!("opener never resolves")
                })
                .await
        });

        // Wait for the opener to be in flight before aborting so the
        // abort lands while we're suspended at `opener().await`.
        started.notified().await;
        cancelled.abort();
        let _ = cancelled.await;

        // Fresh open must complete; if the guard didn't run on cancel,
        // this call would hang on the leaked Notify.
        let channel_id = Pubkey::new_unique();
        let cell = tokio::time::timeout(
            Duration::from_secs(5),
            reg.get_or_open(&payee, &mint, || async {
                Ok(fresh_open(channel_id, payee, mint))
            }),
        )
        .await
        .expect("fresh open must complete; in-flight slot was leaked")
        .expect("fresh open succeeds");

        let guard = cell.lock().await;
        assert_eq!(guard.0.channel_id, channel_id);
    }
}
