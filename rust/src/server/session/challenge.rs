//! Challenge cache, intent binding, and a sweeper for expired entries.
//!
//! Every challenge the server hands out lives here until the action
//! handler commits it or the sweeper evicts it. Three rules:
//!
//! 1. Single-use. An id walks `Available -> Pending -> Consumed` once.
//!    Two tasks racing on the same id: one wins, the other gets
//!    `ChallengeInFlight`.
//! 2. Intent binding. Each record carries a typed [`ChallengeIntent`];
//!    reserving with the wrong discriminant gets
//!    `ChallengeIntentMismatch`.
//! 3. Bounded lifetime. The sweeper drops Available and Consumed
//!    entries older than `2 * challenge_ttl_seconds`. Pending entries
//!    survive until [`PENDING_HARD_CEILING_SECONDS`] so a slow
//!    broadcast can't lose its reservation to a sweep landing between
//!    `send_transaction` returning Ok and the post-broadcast commit.
//!    The hard ceiling still reclaims a Pending record from a handler
//!    that never returns.
//!
//! Storage is a [`dashmap::DashMap`]. The `Available -> Pending`
//! transition runs inside `entry().and_modify`, so the check-and-set
//! sits under DashMap's per-shard write lock; concurrent reservations
//! on the same key serialise on that lock without a separate critical
//! section.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use solana_hash::Hash;
use solana_pubkey::Pubkey;

use crate::error::SessionError;
use crate::protocol::intents::session::Split;

/// Hard ceiling on Pending lifetime. Above the standard sweep window
/// so a slow broadcast keeps its reservation, well below anything a
/// leaked handler would need to choke the cache. The SDK's
/// `broadcast_confirm_timeout` defaults to 30s, so 30 minutes is room
/// to spare.
pub const PENDING_HARD_CEILING_SECONDS: i64 = 30 * 60;

/// Why a challenge was issued. Handlers check intent on entry so a
/// cross-action submission (e.g. a `TopUp` challenge presented to
/// `open`) is rejected before any RPC or store work.
///
/// `Open` carries advertised splits and deposit bounds because the
/// open handler re-validates them against the submitted payload.
/// `TopUp` and `Close` only carry `channel_id`; the channel record is
/// the splits source at handle time, so duplicating them here would
/// drift.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ChallengeIntent {
    Open {
        payee: Pubkey,
        mint: Pubkey,
        advertised_splits: Vec<Split>,
        min_deposit: u64,
        max_deposit: u64,
    },
    TopUp {
        channel_id: Pubkey,
    },
    Close {
        channel_id: Pubkey,
    },
}

/// Discriminant-only view of [`ChallengeIntent`]. Handlers pass this
/// to `reserve` instead of building a full intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeIntentDiscriminant {
    Open,
    TopUp,
    Close,
}

impl From<&ChallengeIntent> for ChallengeIntentDiscriminant {
    fn from(intent: &ChallengeIntent) -> Self {
        match intent {
            ChallengeIntent::Open { .. } => Self::Open,
            ChallengeIntent::TopUp { .. } => Self::TopUp,
            ChallengeIntent::Close { .. } => Self::Close,
        }
    }
}

/// Lifecycle of a challenge record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeState {
    Available,
    Pending,
    Consumed,
}

/// One row in [`ChallengeCache`], keyed by challenge id.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChallengeRecord {
    pub intent: ChallengeIntent,
    pub external_id: Option<String>,
    /// Unix seconds when issued; drives the sweep TTL.
    pub issued_at: i64,
    /// Blockhash the server fetched when issuing the challenge.
    /// Handlers compare the submitted tx's `recent_blockhash` against
    /// this before broadcast.
    pub recent_blockhash: Hash,
    pub state: ChallengeState,
}

impl ChallengeRecord {
    pub fn new(
        intent: ChallengeIntent,
        external_id: Option<String>,
        issued_at: i64,
        recent_blockhash: Hash,
    ) -> Self {
        Self {
            intent,
            external_id,
            issued_at,
            recent_blockhash,
            state: ChallengeState::Available,
        }
    }
}

/// In-process challenge cache.
///
/// Cloning hands out a new [`Arc`] handle; clones share state. The
/// sweeper task holds one of those handles.
#[derive(Debug, Clone)]
pub struct ChallengeCache {
    inner: Arc<DashMap<String, ChallengeRecord>>,
    /// Per-record TTL in seconds. `reserve` rejects records older
    /// than this. The sweeper uses `2 * ttl` separately so a slow
    /// handler doesn't race the sweep on its own Pending record.
    ttl_seconds: u32,
}

impl ChallengeCache {
    pub fn new(ttl_seconds: u32) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            ttl_seconds,
        }
    }

    /// Per-record TTL `reserve` enforces.
    pub fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    /// Register a fresh challenge. Returns
    /// [`SessionError::ChallengeAlreadyIssued`] if `id` is already in
    /// the cache. The HMAC id is deterministic over realm, method,
    /// intent, and the encoded body, so two factory calls against an
    /// unchanged body and blockhash produce the same id; the typed
    /// error lets a polling operator distinguish that benign collision
    /// from a real double-insert.
    pub fn insert(&self, id: String, record: ChallengeRecord) -> Result<(), SessionError> {
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(id) {
            Entry::Occupied(_) => Err(SessionError::ChallengeAlreadyIssued),
            Entry::Vacant(slot) => {
                slot.insert(record);
                Ok(())
            }
        }
    }

    /// Atomically flip `Available -> Pending` and return a snapshot of
    /// the record at reservation time.
    ///
    /// Failure modes:
    /// - `ChallengeUnbound`: id not in cache, or already `Consumed`.
    /// - `ChallengeInFlight`: another caller already flipped to
    ///   `Pending` and hasn't committed or released.
    /// - `ChallengeIntentMismatch`: cached intent doesn't match
    ///   `expected`.
    /// - `ChallengeExpired`: record age exceeds `ttl_seconds`. The
    ///   expired entry is evicted on the way out, so a retry on the
    ///   same id reports `ChallengeUnbound`.
    ///
    /// The check-and-set runs inside `DashMap::entry().and_modify`, so
    /// concurrent callers on the same id serialise on DashMap's shard
    /// write lock and exactly one sees `Available`.
    pub fn reserve(
        &self,
        id: &str,
        expected: ChallengeIntentDiscriminant,
    ) -> Result<ChallengeRecord, SessionError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.reserve_at(id, expected, now)
    }

    /// `reserve` with the wall-clock injected. [`Self::reserve`]
    /// delegates here. Lets unit tests construct expired records
    /// without sleeping.
    pub fn reserve_at(
        &self,
        id: &str,
        expected: ChallengeIntentDiscriminant,
        now: i64,
    ) -> Result<ChallengeRecord, SessionError> {
        use dashmap::mapref::entry::Entry;

        let ttl = self.ttl_seconds as i64;
        match self.inner.entry(id.to_string()) {
            Entry::Vacant(_) => Err(SessionError::ChallengeUnbound),
            Entry::Occupied(mut slot) => {
                let record = slot.get_mut();
                let age = now.saturating_sub(record.issued_at);
                if age > ttl {
                    let age_u64 = age.max(0) as u64;
                    slot.remove();
                    return Err(SessionError::ChallengeExpired {
                        age: age_u64,
                        max: self.ttl_seconds as u64,
                    });
                }
                if ChallengeIntentDiscriminant::from(&record.intent) != expected {
                    return Err(SessionError::ChallengeIntentMismatch);
                }
                match record.state {
                    ChallengeState::Available => {
                        record.state = ChallengeState::Pending;
                        Ok(record.clone())
                    }
                    ChallengeState::Pending => Err(SessionError::ChallengeInFlight),
                    ChallengeState::Consumed => Err(SessionError::ChallengeUnbound),
                }
            }
        }
    }

    /// Move a Pending challenge to Consumed. Called from the action
    /// handler's success path after the on-chain effect lands.
    /// Rejects if the record is missing or not Pending.
    pub fn commit(&self, id: &str) -> Result<(), SessionError> {
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(id.to_string()) {
            Entry::Vacant(_) => Err(SessionError::ChallengeUnbound),
            Entry::Occupied(mut slot) => {
                let record = slot.get_mut();
                if record.state != ChallengeState::Pending {
                    return Err(SessionError::InternalError(format!(
                        "commit on non-pending challenge: state {:?}",
                        record.state
                    )));
                }
                record.state = ChallengeState::Consumed;
                Ok(())
            }
        }
    }

    /// Move a Pending reservation back to Available. Called from the
    /// failure path so the client can retry without burning the
    /// challenge.
    pub fn release(&self, id: &str) -> Result<(), SessionError> {
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(id.to_string()) {
            Entry::Vacant(_) => Err(SessionError::ChallengeUnbound),
            Entry::Occupied(mut slot) => {
                let record = slot.get_mut();
                if record.state != ChallengeState::Pending {
                    return Err(SessionError::InternalError(format!(
                        "release on non-pending challenge: state {:?}",
                        record.state
                    )));
                }
                record.state = ChallengeState::Available;
                Ok(())
            }
        }
    }

    /// Drop entries past their cache lifetime. `Available` and
    /// `Consumed` records age out once `now - issued_at` exceeds
    /// `ttl_seconds` (the sweeper passes `2 * challenge_ttl_seconds`).
    /// `Pending` records are spared until
    /// [`PENDING_HARD_CEILING_SECONDS`] so a slow broadcast can't lose
    /// its reservation to a sweep landing between `send_transaction`
    /// returning Ok and the post-broadcast `commit`; the hard ceiling
    /// still reclaims a Pending record from a handler that never
    /// returns.
    pub fn evict_expired(&self, ttl_seconds: u32, now: i64) {
        let ttl = ttl_seconds as i64;
        self.inner.retain(|_, record| {
            let age = now.saturating_sub(record.issued_at);
            match record.state {
                ChallengeState::Pending => age <= PENDING_HARD_CEILING_SECONDS,
                ChallengeState::Available | ChallengeState::Consumed => age <= ttl,
            }
        });
    }

    /// Clone the record at `id` if present. Test-only; production
    /// callers go through `reserve` / `commit` / `release`.
    #[cfg(test)]
    pub(crate) fn get(&self, id: &str) -> Option<ChallengeRecord> {
        self.inner.get(id).map(|r| r.clone())
    }

    /// Entry count, handy for sweep tests.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_intent() -> ChallengeIntent {
        ChallengeIntent::Open {
            payee: Pubkey::new_from_array([1u8; 32]),
            mint: Pubkey::new_from_array([2u8; 32]),
            advertised_splits: vec![],
            min_deposit: 1_000,
            max_deposit: 10_000,
        }
    }

    fn topup_intent() -> ChallengeIntent {
        ChallengeIntent::TopUp {
            channel_id: Pubkey::new_from_array([3u8; 32]),
        }
    }

    fn record(intent: ChallengeIntent, issued_at: i64) -> ChallengeRecord {
        ChallengeRecord::new(intent, None, issued_at, Hash::new_from_array([0u8; 32]))
    }

    /// Wall-clock now in unix seconds. Tests that hit the live
    /// `reserve` (not `reserve_at`) need records issued moments ago,
    /// otherwise the TTL check trips against the placeholder
    /// timestamps the other tests use.
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    #[test]
    fn reserve_then_commit_consumes_challenge() {
        let cache = ChallengeCache::new(300);
        cache
            .insert("c1".into(), record(open_intent(), now_secs()))
            .unwrap();

        let snapshot = cache
            .reserve("c1", ChallengeIntentDiscriminant::Open)
            .unwrap();
        assert_eq!(snapshot.state, ChallengeState::Pending);

        cache.commit("c1").unwrap();
        let after = cache.get("c1").unwrap();
        assert_eq!(after.state, ChallengeState::Consumed);

        // Reserving a Consumed record returns Unbound.
        let err = cache
            .reserve("c1", ChallengeIntentDiscriminant::Open)
            .unwrap_err();
        assert!(matches!(err, SessionError::ChallengeUnbound), "{err:?}");
    }

    #[test]
    fn reserve_then_release_returns_to_available() {
        let cache = ChallengeCache::new(300);
        cache
            .insert("c2".into(), record(open_intent(), now_secs()))
            .unwrap();

        cache
            .reserve("c2", ChallengeIntentDiscriminant::Open)
            .unwrap();
        cache.release("c2").unwrap();

        let after = cache.get("c2").unwrap();
        assert_eq!(after.state, ChallengeState::Available);

        // Released id is reservable again.
        cache
            .reserve("c2", ChallengeIntentDiscriminant::Open)
            .expect("released challenge must reserve cleanly");
    }

    #[test]
    fn reserve_pending_rejects_second_caller_with_in_flight() {
        let cache = ChallengeCache::new(300);
        cache
            .insert("c3".into(), record(open_intent(), now_secs()))
            .unwrap();

        cache
            .reserve("c3", ChallengeIntentDiscriminant::Open)
            .unwrap();
        let err = cache
            .reserve("c3", ChallengeIntentDiscriminant::Open)
            .unwrap_err();
        assert!(matches!(err, SessionError::ChallengeInFlight), "{err:?}");
    }

    #[test]
    fn reserve_consumed_rejects_with_already_used() {
        let cache = ChallengeCache::new(300);
        cache
            .insert("c4".into(), record(open_intent(), now_secs()))
            .unwrap();

        cache
            .reserve("c4", ChallengeIntentDiscriminant::Open)
            .unwrap();
        cache.commit("c4").unwrap();

        // A Consumed presentation comes back as `ChallengeUnbound`,
        // matching the 402 a client sees for a missing id. Pin the
        // variant so the wire-form code stays stable.
        let err = cache
            .reserve("c4", ChallengeIntentDiscriminant::Open)
            .unwrap_err();
        assert!(matches!(err, SessionError::ChallengeUnbound), "{err:?}");
    }

    #[test]
    fn reserve_intent_mismatch_rejects_with_intent_mismatch() {
        let cache = ChallengeCache::new(300);
        cache
            .insert("c5".into(), record(topup_intent(), now_secs()))
            .unwrap();

        let err = cache
            .reserve("c5", ChallengeIntentDiscriminant::Open)
            .unwrap_err();
        assert!(
            matches!(err, SessionError::ChallengeIntentMismatch),
            "{err:?}"
        );

        // A mismatch reservation must not have flipped state.
        let snapshot = cache.get("c5").unwrap();
        assert_eq!(snapshot.state, ChallengeState::Available);
    }

    #[test]
    fn reserve_rejects_expired_challenge() {
        // ttl 60s; record issued at t=0, caller arrives at t=200,
        // well past the TTL. `reserve` should refuse with
        // `ChallengeExpired { age, max }` and evict the dead record
        // so a retry on the same id reports `ChallengeUnbound`
        // instead of a second `ChallengeExpired`.
        let cache = ChallengeCache::new(60);
        cache.insert("c6".into(), record(open_intent(), 0)).unwrap();

        let err = cache
            .reserve_at("c6", ChallengeIntentDiscriminant::Open, 200)
            .unwrap_err();
        match err {
            SessionError::ChallengeExpired { age, max } => {
                assert_eq!(age, 200);
                assert_eq!(max, 60);
            }
            other => panic!("expected ChallengeExpired, got: {other:?}"),
        }

        // Entry was evicted; the next call sees an empty slot.
        assert!(cache.get("c6").is_none());
        let err = cache
            .reserve_at("c6", ChallengeIntentDiscriminant::Open, 201)
            .unwrap_err();
        assert!(matches!(err, SessionError::ChallengeUnbound), "{err:?}");
    }

    #[test]
    fn evict_expired_drops_old_entries_only() {
        let cache = ChallengeCache::new(300);
        cache
            .insert("old".into(), record(open_intent(), 0))
            .unwrap();
        cache
            .insert("fresh".into(), record(open_intent(), 100))
            .unwrap();

        // ttl 50, now 100: `old` is 100s (drop), `fresh` is 0s (keep).
        cache.evict_expired(50, 100);

        assert!(cache.get("old").is_none());
        assert!(cache.get("fresh").is_some());
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reserve_serializes() {
        // Hammer the same id from many tokio tasks. One task sees
        // Available and flips to Pending; the rest see
        // `ChallengeInFlight`. The first reservation on a clean
        // Available record can only succeed once.
        let cache = ChallengeCache::new(300);
        cache
            .insert("race".into(), record(open_intent(), now_secs()))
            .unwrap();

        let mut handles = Vec::new();
        for _ in 0..32 {
            let cache = cache.clone();
            handles.push(tokio::spawn(async move {
                cache.reserve("race", ChallengeIntentDiscriminant::Open)
            }));
        }

        let mut wins = 0usize;
        let mut in_flight = 0usize;
        for h in handles {
            match h.await.unwrap() {
                Ok(_) => wins += 1,
                Err(SessionError::ChallengeInFlight) => in_flight += 1,
                Err(other) => panic!("unexpected reservation error: {other:?}"),
            }
        }
        assert_eq!(wins, 1, "exactly one reservation must win");
        assert_eq!(in_flight, 31, "every losing reservation is in-flight");
    }

    #[test]
    fn evict_spares_pending_past_ttl_window() {
        // Without the Pending exemption a sweep landing mid-broadcast
        // would evict the record and turn the post-broadcast commit
        // into `ChallengeUnbound`, even though the cluster accepted
        // the tx.
        let cache = ChallengeCache::new(60);
        cache
            .insert("slow".into(), record(open_intent(), 0))
            .unwrap();
        cache
            .reserve_at("slow", ChallengeIntentDiscriminant::Open, 0)
            .expect("reserve flips state to Pending");

        cache.evict_expired(120, 200);

        let snap = cache
            .get("slow")
            .expect("Pending record must survive a sweep at 200s with ttl 60");
        assert_eq!(snap.state, ChallengeState::Pending);

        cache
            .commit("slow")
            .expect("commit must not surface ChallengeUnbound after a Pending-spared sweep");
        let after = cache.get("slow").expect("record stays after commit");
        assert_eq!(after.state, ChallengeState::Consumed);
    }

    #[test]
    fn evict_reclaims_pending_past_hard_ceiling() {
        let cache = ChallengeCache::new(60);
        cache
            .insert("leaked".into(), record(open_intent(), 0))
            .unwrap();
        cache
            .reserve_at("leaked", ChallengeIntentDiscriminant::Open, 0)
            .expect("reserve flips state to Pending");

        let past_ceiling = PENDING_HARD_CEILING_SECONDS + 1;
        cache.evict_expired(120, past_ceiling);

        assert!(
            cache.get("leaked").is_none(),
            "Pending record past the hard ceiling must be reclaimed",
        );
    }

    #[test]
    fn evict_drops_consumed_at_normal_ttl() {
        let cache = ChallengeCache::new(60);
        cache
            .insert("done".into(), record(open_intent(), 0))
            .unwrap();
        cache
            .reserve_at("done", ChallengeIntentDiscriminant::Open, 0)
            .expect("reserve");
        cache.commit("done").expect("commit");

        cache.evict_expired(120, 200);
        assert!(
            cache.get("done").is_none(),
            "Consumed record must evict on the normal ttl window"
        );
    }

    #[test]
    fn duplicate_insert_returns_typed_already_issued() {
        let cache = ChallengeCache::new(60);
        cache
            .insert("dup".into(), record(open_intent(), 0))
            .unwrap();
        let err = cache
            .insert("dup".into(), record(open_intent(), 0))
            .expect_err("second insert on the same id must reject");
        assert!(
            matches!(err, SessionError::ChallengeAlreadyIssued),
            "expected ChallengeAlreadyIssued, got {err:?}"
        );
    }
}
