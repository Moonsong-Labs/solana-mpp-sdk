//! Challenge cache, intent binding, and the sweeper that evicts expired entries.
//!
//! Every server-issued challenge lives here from the moment a factory hands
//! it to the operator until the matching action handler commits or a
//! background sweep evicts it. The cache enforces three invariants:
//!
//! 1. Single-use. A given challenge id walks `Available -> Pending ->
//!    Consumed` exactly once. The reservation step is atomic: two
//!    handler tasks racing on the same id observe one `Advanced` and
//!    one `ChallengeInFlight`.
//! 2. Intent binding. Each record is tagged with a typed
//!    [`ChallengeIntent`]. Reservation rejects with
//!    `ChallengeIntentMismatch` if the action handler's discriminant
//!    does not match the cached intent's discriminant.
//! 3. Bounded lifetime. A background sweeper drops every record older
//!    than `2 * challenge_ttl_seconds` regardless of state, so a
//!    leaked Pending record cannot wedge the cache.
//!
//! The internal storage is a [`dashmap::DashMap`]. The `Available ->
//! Pending` transition uses `entry().and_modify()` so the check-and-set is
//! performed inside the per-shard write lock that DashMap holds during the
//! closure; concurrent reservations against the same key serialise on that
//! shard lock rather than relying on a separate critical section.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use solana_hash::Hash;
use solana_pubkey::Pubkey;

use crate::error::SessionError;
use crate::protocol::intents::session::Split;

/// Why a challenge was issued. The handler asserts intent match on entry
/// so cross-action reuse (e.g. presenting a `TopUp` challenge to the
/// `open` handler) is rejected before any RPC or store work runs.
///
/// `Open` carries advertised splits and deposit bounds because the open
/// handler re-validates them against the submitted payload. `TopUp` and
/// `Close` are bound to a known `channel_id`; the channel record is the
/// authoritative source for splits at handle-time, so the intent does
/// not duplicate them.
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

/// Discriminant-only view of [`ChallengeIntent`]. The reservation API takes
/// the discriminant so handlers can assert "I expect a TopUp challenge"
/// without having to construct a full intent value.
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

/// Three-state lifecycle for a challenge record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeState {
    Available,
    Pending,
    Consumed,
}

/// One row in [`ChallengeCache`]. Every challenge the server hands out
/// has a matching record keyed on the challenge id.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChallengeRecord {
    pub intent: ChallengeIntent,
    pub external_id: Option<String>,
    /// Unix seconds when the challenge was issued. Drives sweep TTL.
    pub issued_at: i64,
    /// The blockhash the server fetched at challenge time and committed
    /// to the client. Action handlers compare the submitted tx's
    /// `recent_blockhash` against this byte-for-byte before broadcast.
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
/// Cloning the cache hands out a new [`Arc`] handle; all clones share
/// the same underlying state. The sweeper task holds one such handle.
#[derive(Debug, Clone)]
pub struct ChallengeCache {
    inner: Arc<DashMap<String, ChallengeRecord>>,
    /// Per-record TTL in seconds. `reserve` rejects records whose age
    /// (against wall-clock `now`) exceeds this bound. The sweeper
    /// applies a `2 * ttl` window separately so a slow handler does not
    /// race the sweep on its own Pending record.
    ttl_seconds: u32,
}

impl ChallengeCache {
    pub fn new(ttl_seconds: u32) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            ttl_seconds,
        }
    }

    /// Per-record TTL the cache enforces inside `reserve`.
    pub fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    /// Register a freshly minted challenge. Rejects if `id` is already
    /// in the cache; that would mean the HMAC challenge id collided
    /// (vanishingly unlikely) or a caller tried to insert the same
    /// challenge twice.
    pub fn insert(&self, id: String, record: ChallengeRecord) -> Result<(), SessionError> {
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(id) {
            Entry::Occupied(_) => Err(SessionError::InternalError(
                "duplicate challenge id".to_string(),
            )),
            Entry::Vacant(slot) => {
                slot.insert(record);
                Ok(())
            }
        }
    }

    /// Atomically transition `Available -> Pending` and return a snapshot
    /// of the record as it stood at reservation time.
    ///
    /// Failure modes:
    /// - `ChallengeUnbound`: id not in the cache, or already `Consumed`.
    /// - `ChallengeInFlight`: another caller already moved this id to
    ///   `Pending` and has not yet committed or released.
    /// - `ChallengeIntentMismatch`: cached intent's discriminant differs
    ///   from `expected`.
    /// - `ChallengeExpired`: record age exceeds the cache's
    ///   `ttl_seconds`. The expired entry is evicted on the way out so
    ///   a follow-up reservation on the same id reports `ChallengeUnbound`.
    ///
    /// The check-and-set runs inside `DashMap::entry().and_modify`, so
    /// two concurrent callers on the same id serialise on DashMap's
    /// shard write lock; exactly one observes `Available` and flips it.
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

    /// Test-friendly `reserve` that takes the wall-clock as an argument
    /// instead of reading `SystemTime::now`. The public [`Self::reserve`]
    /// delegates here. Splitting this out lets unit tests construct
    /// expired records deterministically without sleeping.
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

    /// Mark a Pending challenge as Consumed. Called from the action
    /// handler's success path after the on-chain effect has been
    /// observed. Rejects if the record is missing or not Pending.
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

    /// Release a Pending reservation back to Available. Called from the
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

    /// Drop every entry whose age (relative to `now`) exceeds
    /// `ttl_seconds`. The sweeper task calls this with `2 *
    /// challenge_ttl_seconds`; entries past their issue TTL get a grace
    /// window before being reclaimed so a slow handler does not race
    /// the sweep on its own Pending record.
    pub fn evict_expired(&self, ttl_seconds: u32, now: i64) {
        let ttl = ttl_seconds as i64;
        self.inner
            .retain(|_, record| now.saturating_sub(record.issued_at) <= ttl);
    }

    /// Test-only helper: clone the record at `id` if present.
    pub fn get(&self, id: &str) -> Option<ChallengeRecord> {
        self.inner.get(id).map(|r| r.clone())
    }

    /// Total entries currently held. Useful for sweep tests.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` if no entries are held.
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

    /// Wall-clock now in unix seconds. Tests that exercise the live
    /// `reserve` (not `reserve_at`) must construct records as if they
    /// were issued seconds ago, otherwise the freshly added TTL check
    /// trips against the mid-1970s placeholder timestamps every other
    /// test was using.
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

        // A second reservation on a Consumed record is unbound.
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

        // Released id must be reservable again.
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

        // Spec wording calls a Consumed presentation `ChallengeUnbound`
        // (the cache "no longer holds an Available record under that id"),
        // which is the same outward-facing 402 the client sees for a
        // missing id. Pin the variant so the wire-form code stays stable.
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

        // A failed mismatch reservation must NOT have flipped state.
        let snapshot = cache.get("c5").unwrap();
        assert_eq!(snapshot.state, ChallengeState::Available);
    }

    #[test]
    fn reserve_rejects_expired_challenge() {
        // ttl 60s; record was issued at t=0 and the caller arrives at
        // t=200, comfortably past the per-record TTL. `reserve` must
        // refuse the reservation with `ChallengeExpired { age, max }`
        // and evict the dead record so a follow-up reservation reports
        // `ChallengeUnbound` rather than a second `ChallengeExpired`
        // for the same id.
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

        // Entry is gone; the next call sees an empty slot.
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

        // ttl 50, now 100: "old" is 100s old (drop), "fresh" is 0s old (keep).
        cache.evict_expired(50, 100);

        assert!(cache.get("old").is_none());
        assert!(cache.get("fresh").is_some());
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reserve_serializes() {
        // Fan a high contention burst out across many tokio tasks against
        // the same id. Exactly one task observes Available and flips to
        // Pending; everyone else sees ChallengeInFlight or, if the test
        // re-races against itself across iterations of the same record,
        // ChallengeUnbound after the winner commits. The first reservation
        // from a clean Available record can only be `Ok` for one task.
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
}
