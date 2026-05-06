//! Per-channel server-side state.
//!
//! `ChannelStore` holds what the server knows about each open channel:
//! who's paying, the deposit, the watermark of vouchers we've accepted,
//! and the on-chain settled value once a close confirms.
//!
//! `advance_watermark` is the only piece that has to be atomic. Two
//! concurrent vouchers at the same cumulative will both call it; one
//! wins (`Advanced`), the others get `Conflict` with the winner's
//! cached receipt so we hand back the exact bytes the network saw,
//! not a fresh re-derivation.
//!
//! `InMemoryChannelStore` is for tests and single-process demos.
//! Anything production wants TTLs, persistence, and a real CAS.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use tokio::sync::RwLock;

use crate::protocol::intents::session::{SignedVoucher, Split};

// ── Status, record, outcome, error ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelStatus {
    Open,
    CloseAttempting,
    Closing,
    ClosedPending,
    ClosedFinalized,
}

#[derive(Debug, Clone)]
pub struct ChannelRecord {
    pub channel_id: Pubkey,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub salt: u64,
    pub program_id: Pubkey,
    pub authorized_signer: Pubkey,
    pub deposit: u64,
    pub accepted_cumulative: u64,
    pub on_chain_settled: u64,
    pub last_voucher: Option<SignedVoucher>,
    pub close_tx: Option<Signature>,
    pub status: ChannelStatus,
    pub splits: Vec<Split>,
}

#[derive(Debug, Clone)]
pub enum AdvanceOutcome {
    Advanced {
        prior: u64,
    },
    Conflict {
        current: u64,
        winner_signature: [u8; 64],
        winner_receipt: Vec<u8>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("channel {0} not found")]
    NotFound(Pubkey),

    #[error("channel {0} already exists")]
    AlreadyExists(Pubkey),

    #[error("illegal status transition for channel {channel_id}: {from:?} -> {to:?}")]
    IllegalTransition {
        channel_id: Pubkey,
        from: ChannelStatus,
        to: ChannelStatus,
    },

    #[error("store request timed out")]
    Timeout,

    #[error("store connection lost")]
    ConnectionLost,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("{0}")]
    Other(String),
}

// ── Trait ──────────────────────────────────────────────────────────────────

#[async_trait]
pub trait ChannelStore: Send + Sync {
    async fn get(&self, channel_id: &Pubkey) -> Result<Option<ChannelRecord>, StoreError>;

    async fn insert(&self, record: ChannelRecord) -> Result<(), StoreError>;

    /// Advance the accepted watermark from `expected` to `new` atomically,
    /// caching `signature` + `receipt_bytes` as the winner's receipt.
    /// The winner sees `Advanced { prior }`; everyone else gets
    /// `Conflict { current, winner_signature, winner_receipt }` so
    /// they can hand back the network-committed receipt verbatim.
    async fn advance_watermark(
        &self,
        channel_id: &Pubkey,
        expected: u64,
        new: u64,
        signature: [u8; 64],
        receipt_bytes: Vec<u8>,
    ) -> Result<AdvanceOutcome, StoreError>;

    async fn record_deposit(
        &self,
        channel_id: &Pubkey,
        new_deposit: u64,
    ) -> Result<(), StoreError>;

    async fn record_on_chain_settled(
        &self,
        channel_id: &Pubkey,
        settled: u64,
    ) -> Result<(), StoreError>;

    async fn record_last_voucher(
        &self,
        channel_id: &Pubkey,
        voucher: SignedVoucher,
    ) -> Result<(), StoreError>;

    async fn record_close_signature(
        &self,
        channel_id: &Pubkey,
        sig: Signature,
    ) -> Result<(), StoreError>;

    // Status mutators. One forward edge per call; self-edges other than
    // `ClosedFinalized -> ClosedFinalized` come back as
    // `IllegalTransition`. The finalized self-edge is there so a repeated
    // commitment poll is a no-op. If a flow needs to re-enter a close
    // mutator (fork rollback, etc.), bookkeep that at the call-site
    // rather than widening this trait.
    async fn mark_close_attempting(&self, channel_id: &Pubkey) -> Result<(), StoreError>;

    async fn mark_close_rollback(&self, channel_id: &Pubkey) -> Result<(), StoreError>;

    /// Recovery-only rollback from `Closing` to `Open`. Inspect calls
    /// this when it sees a `Closing` store record against an on-chain
    /// `Open` channel (probable fork rollback of `request_close`).
    /// Kept separate from `mark_close_rollback` so the regular close
    /// path can't widen its rollback scope by accident.
    async fn mark_recovery_rollback_from_closing(
        &self,
        channel_id: &Pubkey,
    ) -> Result<(), StoreError>;

    async fn mark_closing(&self, channel_id: &Pubkey) -> Result<(), StoreError>;

    async fn mark_closed_pending(
        &self,
        channel_id: &Pubkey,
        tx: Signature,
    ) -> Result<(), StoreError>;

    async fn mark_closed_finalized(&self, channel_id: &Pubkey) -> Result<(), StoreError>;

    async fn list_by_status(
        &self,
        statuses: &[ChannelStatus],
    ) -> Result<Vec<ChannelRecord>, StoreError>;

    async fn delete(&self, channel_id: &Pubkey) -> Result<(), StoreError>;

    async fn voucher_cache_insert(
        &self,
        channel_id: &Pubkey,
        cumulative: u64,
        signature: [u8; 64],
        receipt_bytes: Vec<u8>,
    ) -> Result<(), StoreError>;

    async fn voucher_cache_lookup(
        &self,
        channel_id: &Pubkey,
        cumulative: u64,
    ) -> Result<Option<(Vec<u8>, [u8; 64])>, StoreError>;
}

// ── In-memory implementation ───────────────────────────────────────────────

/// In-memory `ChannelStore` for tests and single-process demos.
///
/// Not production-grade. The voucher cache and records map grow
/// unboundedly, closed records stick around until you `delete` them,
/// and nothing gets persisted. A production backend needs TTL + LRU
/// on the voucher cache and a retention policy on closed records.
pub struct InMemoryChannelStore {
    inner: Arc<RwLock<InMemoryInner>>,
}

struct InMemoryInner {
    records: HashMap<Pubkey, ChannelRecord>,
    /// Replay cache keyed by `(channel_id, cumulative)`. Value is
    /// `(receipt_bytes, signature)`; CAS losers hand the cached
    /// receipt back to their client unchanged.
    voucher_cache: HashMap<(Pubkey, u64), (Vec<u8>, [u8; 64])>,
}

impl Default for InMemoryChannelStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryChannelStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(InMemoryInner {
                records: HashMap::new(),
                voucher_cache: HashMap::new(),
            })),
        }
    }
}

fn check_transition(
    channel_id: Pubkey,
    from: ChannelStatus,
    to: ChannelStatus,
) -> Result<(), StoreError> {
    use ChannelStatus::*;
    let ok = matches!(
        (from, to),
        // forward edges
        (Open, CloseAttempting)
            | (Open, Closing)
            | (Open, ClosedPending)
            // Recovery edge: Open jumps straight to Finalized when
            // inspect finds the chain tombstoned with settled revenue
            // and no unsettled delta. The channel closed cleanly
            // without ever passing through CloseAttempting in this
            // server's store.
            | (Open, ClosedFinalized)
            | (CloseAttempting, ClosedPending)
            | (CloseAttempting, Open)
            | (Closing, ClosedPending)
            | (ClosedPending, ClosedFinalized)
            | (ClosedFinalized, ClosedFinalized)
    );
    if ok {
        Ok(())
    } else {
        Err(StoreError::IllegalTransition {
            channel_id,
            from,
            to,
        })
    }
}

#[async_trait]
impl ChannelStore for InMemoryChannelStore {
    async fn get(&self, channel_id: &Pubkey) -> Result<Option<ChannelRecord>, StoreError> {
        Ok(self.inner.read().await.records.get(channel_id).cloned())
    }

    async fn insert(&self, record: ChannelRecord) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        if g.records.contains_key(&record.channel_id) {
            return Err(StoreError::AlreadyExists(record.channel_id));
        }
        g.records.insert(record.channel_id, record);
        Ok(())
    }

    async fn advance_watermark(
        &self,
        channel_id: &Pubkey,
        expected: u64,
        new: u64,
        signature: [u8; 64],
        receipt_bytes: Vec<u8>,
    ) -> Result<AdvanceOutcome, StoreError> {
        let mut g = self.inner.write().await;
        let record = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        if record.accepted_cumulative == expected && new > expected {
            let prior = record.accepted_cumulative;
            record.accepted_cumulative = new;
            g.voucher_cache
                .insert((*channel_id, new), (receipt_bytes, signature));
            return Ok(AdvanceOutcome::Advanced { prior });
        }
        let current = record.accepted_cumulative;
        let cache_key = (*channel_id, current);
        match g.voucher_cache.get(&cache_key).cloned() {
            Some((receipt, sig)) => Ok(AdvanceOutcome::Conflict {
                current,
                winner_signature: sig,
                winner_receipt: receipt,
            }),
            None => Err(StoreError::Other(format!(
                "cas conflict at cumulative {current} but winner receipt not cached"
            ))),
        }
    }

    async fn record_deposit(
        &self,
        channel_id: &Pubkey,
        new_deposit: u64,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        r.deposit = new_deposit;
        Ok(())
    }

    async fn record_on_chain_settled(
        &self,
        channel_id: &Pubkey,
        settled: u64,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        r.on_chain_settled = settled;
        Ok(())
    }

    async fn record_last_voucher(
        &self,
        channel_id: &Pubkey,
        voucher: SignedVoucher,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        r.last_voucher = Some(voucher);
        Ok(())
    }

    async fn record_close_signature(
        &self,
        channel_id: &Pubkey,
        sig: Signature,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        r.close_tx = Some(sig);
        Ok(())
    }

    async fn mark_close_attempting(&self, channel_id: &Pubkey) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        check_transition(*channel_id, r.status, ChannelStatus::CloseAttempting)?;
        r.status = ChannelStatus::CloseAttempting;
        Ok(())
    }

    async fn mark_close_rollback(&self, channel_id: &Pubkey) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        check_transition(*channel_id, r.status, ChannelStatus::Open)?;
        r.status = ChannelStatus::Open;
        Ok(())
    }

    async fn mark_recovery_rollback_from_closing(
        &self,
        channel_id: &Pubkey,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        if r.status != ChannelStatus::Closing {
            return Err(StoreError::IllegalTransition {
                channel_id: *channel_id,
                from: r.status,
                to: ChannelStatus::Open,
            });
        }
        r.status = ChannelStatus::Open;
        Ok(())
    }

    async fn mark_closing(&self, channel_id: &Pubkey) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        check_transition(*channel_id, r.status, ChannelStatus::Closing)?;
        r.status = ChannelStatus::Closing;
        Ok(())
    }

    async fn mark_closed_pending(
        &self,
        channel_id: &Pubkey,
        tx: Signature,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        check_transition(*channel_id, r.status, ChannelStatus::ClosedPending)?;
        r.status = ChannelStatus::ClosedPending;
        r.close_tx = Some(tx);
        Ok(())
    }

    async fn mark_closed_finalized(&self, channel_id: &Pubkey) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        let r = g
            .records
            .get_mut(channel_id)
            .ok_or(StoreError::NotFound(*channel_id))?;
        check_transition(*channel_id, r.status, ChannelStatus::ClosedFinalized)?;
        r.status = ChannelStatus::ClosedFinalized;
        Ok(())
    }

    async fn list_by_status(
        &self,
        statuses: &[ChannelStatus],
    ) -> Result<Vec<ChannelRecord>, StoreError> {
        let g = self.inner.read().await;
        Ok(g.records
            .values()
            .filter(|r| statuses.contains(&r.status))
            .cloned()
            .collect())
    }

    async fn delete(&self, channel_id: &Pubkey) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        if g.records.remove(channel_id).is_none() {
            return Err(StoreError::NotFound(*channel_id));
        }
        Ok(())
    }

    async fn voucher_cache_insert(
        &self,
        channel_id: &Pubkey,
        cumulative: u64,
        signature: [u8; 64],
        receipt_bytes: Vec<u8>,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.write().await;
        g.voucher_cache
            .insert((*channel_id, cumulative), (receipt_bytes, signature));
        Ok(())
    }

    async fn voucher_cache_lookup(
        &self,
        channel_id: &Pubkey,
        cumulative: u64,
    ) -> Result<Option<(Vec<u8>, [u8; 64])>, StoreError> {
        let g = self.inner.read().await;
        Ok(g.voucher_cache.get(&(*channel_id, cumulative)).cloned())
    }
}

// ── Generic KV store (charge intent replay protection) ──
//
// Charge stores `(signature, status)` pairs to reject double-spends of
// the same on-chain signature. An opaque JSON blob keyed by string is
// the right shape for that, and it's deliberately separate from the
// session intent's typed `ChannelStore`: different problems, no
// migration planned.

use std::future::Future;
use std::pin::Pin;

pub trait Store: Send + Sync {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>;

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    fn delete(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Insert only if the key isn't already there. Returns `true` on
    /// insert, `false` on collision.
    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>>;
}

pub struct MemoryStore {
    data: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            data: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
    {
        let result = self.data.lock().expect("store lock poisoned").get(key).cloned();
        Box::pin(async move {
            match result {
                Some(raw) => {
                    let value = serde_json::from_str(&raw)
                        .map_err(|e| StoreError::Serialization(e.to_string()))?;
                    Ok(Some(value))
                }
                None => Ok(None),
            }
        })
    }

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let key = key.to_string();
        let serialized =
            serde_json::to_string(&value).map_err(|e| StoreError::Serialization(e.to_string()));
        Box::pin(async move {
            let serialized = serialized?;
            self.data.lock().expect("store lock poisoned").insert(key, serialized);
            Ok(())
        })
    }

    fn delete(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        self.data.lock().expect("store lock poisoned").remove(key);
        Box::pin(async { Ok(()) })
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let key = key.to_string();
        let serialized =
            serde_json::to_string(&value).map_err(|e| StoreError::Serialization(e.to_string()));
        Box::pin(async move {
            let serialized = serialized?;
            use std::collections::hash_map::Entry;
            let mut data = self.data.lock().expect("store lock poisoned");
            match data.entry(key) {
                Entry::Occupied(_) => Ok(false),
                Entry::Vacant(e) => {
                    e.insert(serialized);
                    Ok(true)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::intents::session::{SigType, SignedVoucher, Split, VoucherData};

    fn pk(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }

    fn signed_voucher(channel_id: Pubkey, cumulative: u64) -> SignedVoucher {
        SignedVoucher {
            voucher: VoucherData {
                channel_id: bs58::encode(channel_id.as_ref()).into_string(),
                cumulative_amount: cumulative.to_string(),
                expires_at: None,
            },
            signer: bs58::encode([0x33u8; 32]).into_string(),
            signature: bs58::encode([0x44u8; 64]).into_string(),
            signature_type: SigType::Ed25519,
        }
    }

    fn split(recipient: Pubkey, share_bps: u16) -> Split {
        Split::Bps {
            recipient,
            share_bps,
        }
    }

    fn record(channel_id: Pubkey, deposit: u64) -> ChannelRecord {
        ChannelRecord {
            channel_id,
            payer: pk(0xA1),
            payee: pk(0xA2),
            mint: pk(0xA3),
            salt: 0xCAFE,
            program_id: pk(0xA4),
            authorized_signer: pk(0xA5),
            deposit,
            accepted_cumulative: 0,
            on_chain_settled: 0,
            last_voucher: None,
            close_tx: None,
            status: ChannelStatus::Open,
            splits: vec![split(pk(0xB1), 5_000)],
        }
    }

    fn make_sig(b: u8) -> [u8; 64] {
        [b; 64]
    }

    fn make_signature(b: u8) -> Signature {
        Signature::from(make_sig(b))
    }

    // ── Insert / get ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn insert_and_get() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();
        let got = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(got.channel_id, cid);
        assert_eq!(got.deposit, 1_000);
        assert_eq!(got.status, ChannelStatus::Open);
    }

    #[tokio::test]
    async fn insert_rejects_duplicate() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();
        let err = store.insert(record(cid, 2_000)).await.unwrap_err();
        assert!(matches!(err, StoreError::AlreadyExists(p) if p == cid));
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = InMemoryChannelStore::new();
        assert!(store.get(&pk(0xFF)).await.unwrap().is_none());
    }

    // ── advance_watermark ────────────────────────────────────────────────────

    #[tokio::test]
    async fn advance_watermark_monotonic() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        let r1 = store
            .advance_watermark(&cid, 0, 100, make_sig(1), b"r1".to_vec())
            .await
            .unwrap();
        assert!(matches!(r1, AdvanceOutcome::Advanced { prior: 0 }));

        let r2 = store
            .advance_watermark(&cid, 100, 250, make_sig(2), b"r2".to_vec())
            .await
            .unwrap();
        assert!(matches!(r2, AdvanceOutcome::Advanced { prior: 100 }));

        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 250);
    }

    #[tokio::test]
    async fn advance_watermark_rejects_regression() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        // Winner
        store
            .advance_watermark(&cid, 0, 100, make_sig(1), b"win".to_vec())
            .await
            .unwrap();

        // Loser presents stale expected=0 with new=50; CAS rejects.
        let outcome = store
            .advance_watermark(&cid, 0, 50, make_sig(2), b"lose".to_vec())
            .await
            .unwrap();
        match outcome {
            AdvanceOutcome::Conflict {
                current,
                winner_signature,
                winner_receipt,
            } => {
                assert_eq!(current, 100);
                assert_eq!(winner_signature, make_sig(1));
                assert_eq!(winner_receipt, b"win".to_vec());
            }
            _ => panic!("expected Conflict, got {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn advance_watermark_rejects_equality() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        store
            .advance_watermark(&cid, 0, 100, make_sig(1), b"win".to_vec())
            .await
            .unwrap();

        // expected (0) matches the current watermark, but new (100) is
        // also the current watermark, so the strict-greater check rejects.
        let outcome = store
            .advance_watermark(&cid, 0, 100, make_sig(2), b"lose".to_vec())
            .await
            .unwrap();
        assert!(matches!(outcome, AdvanceOutcome::Conflict { current: 100, .. }));
    }

    #[tokio::test]
    async fn advance_watermark_returns_conflict_on_equality_after_winner() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        // Winner advances 0 -> 100 and caches its receipt at (cid, 100).
        let outcome = store
            .advance_watermark(&cid, 0, 100, make_sig(0xAA), b"alpha".to_vec())
            .await
            .unwrap();
        assert!(matches!(outcome, AdvanceOutcome::Advanced { prior: 0 }));

        // Replay: the loser read the record after the winner committed,
        // so its `expected == new == 100`. The CAS sees
        // `accepted_cumulative == expected` but `new > expected` is false,
        // falls into the cache-lookup branch, and hands back the winner's
        // entry unchanged.
        let outcome = store
            .advance_watermark(&cid, 100, 100, make_sig(0xBB), b"beta".to_vec())
            .await
            .unwrap();
        match outcome {
            AdvanceOutcome::Conflict {
                current,
                winner_signature,
                winner_receipt,
            } => {
                assert_eq!(current, 100);
                assert_eq!(winner_signature, make_sig(0xAA));
                assert_eq!(winner_receipt, b"alpha".to_vec());
            }
            other => panic!("expected Conflict, got {other:?}"),
        }

        // Watermark still reflects the winner.
        assert_eq!(store.get(&cid).await.unwrap().unwrap().accepted_cumulative, 100);
    }

    #[tokio::test]
    async fn advance_watermark_returns_other_on_strict_regression_with_no_cached_winner() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        // Caller-bug shape: `expected = 50`, `new = 25` against a fresh
        // record (watermark 0). The CAS branch fails the equality check,
        // the cache lookup at `(cid, 0)` misses since no winner ever
        // committed, and the fallback fires.
        let err = store
            .advance_watermark(&cid, 50, 25, make_sig(0), b"x".to_vec())
            .await
            .unwrap_err();
        match err {
            StoreError::Other(msg) => assert!(
                msg.contains("cas conflict at cumulative 0"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected StoreError::Other, got {other:?}"),
        }

        // Store should be untouched.
        assert_eq!(store.get(&cid).await.unwrap().unwrap().accepted_cumulative, 0);
    }

    #[tokio::test]
    async fn advance_watermark_conflict_returns_winner_receipt() {
        let store = Arc::new(InMemoryChannelStore::new());
        let cid = pk(1);
        store.insert(record(cid, 10_000)).await.unwrap();

        // Both tasks aim for the same watermark; the inner write lock
        // serialises them so one wins and the other reads the cached
        // receipt back.
        let s1 = store.clone();
        let s2 = store.clone();
        let h1 = tokio::spawn(async move {
            s1.advance_watermark(&cid, 0, 500, make_sig(0xAA), b"alpha".to_vec())
                .await
                .unwrap()
        });
        let h2 = tokio::spawn(async move {
            s2.advance_watermark(&cid, 0, 500, make_sig(0xBB), b"beta".to_vec())
                .await
                .unwrap()
        });
        let (a, b) = (h1.await.unwrap(), h2.await.unwrap());

        let (advanced, conflict) = match (a, b) {
            (a @ AdvanceOutcome::Advanced { .. }, b @ AdvanceOutcome::Conflict { .. }) => (a, b),
            (a @ AdvanceOutcome::Conflict { .. }, b @ AdvanceOutcome::Advanced { .. }) => (b, a),
            other => panic!("expected one Advanced + one Conflict, got {other:?}"),
        };
        let prior = match advanced {
            AdvanceOutcome::Advanced { prior } => prior,
            _ => unreachable!(),
        };
        assert_eq!(prior, 0);

        match conflict {
            AdvanceOutcome::Conflict {
                current,
                winner_signature,
                winner_receipt,
            } => {
                assert_eq!(current, 500);
                // Whichever call landed first owns the cached pair; the
                // loser sees those exact bytes.
                assert!(winner_signature == make_sig(0xAA) || winner_signature == make_sig(0xBB));
                assert!(winner_receipt == b"alpha".to_vec() || winner_receipt == b"beta".to_vec());
                let expected_receipt = if winner_signature == make_sig(0xAA) {
                    b"alpha".to_vec()
                } else {
                    b"beta".to_vec()
                };
                assert_eq!(winner_receipt, expected_receipt);
            }
            _ => unreachable!(),
        }
    }

    // ── Status transitions ────────────────────────────────────────────────────

    #[tokio::test]
    async fn status_transitions_open_to_close_attempting_to_closed_pending_to_finalized() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        store.mark_close_attempting(&cid).await.unwrap();
        assert_eq!(
            store.get(&cid).await.unwrap().unwrap().status,
            ChannelStatus::CloseAttempting
        );

        let sig = make_signature(7);
        store.mark_closed_pending(&cid, sig).await.unwrap();
        let r = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(r.status, ChannelStatus::ClosedPending);
        assert_eq!(r.close_tx, Some(sig));

        store.mark_closed_finalized(&cid).await.unwrap();
        assert_eq!(
            store.get(&cid).await.unwrap().unwrap().status,
            ChannelStatus::ClosedFinalized
        );
    }

    #[tokio::test]
    async fn mark_close_rollback_returns_to_open() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        store.mark_close_attempting(&cid).await.unwrap();
        store.mark_close_rollback(&cid).await.unwrap();
        assert_eq!(
            store.get(&cid).await.unwrap().unwrap().status,
            ChannelStatus::Open
        );

        // Voucher acceptance still works after a rollback.
        let outcome = store
            .advance_watermark(&cid, 0, 50, make_sig(9), b"r".to_vec())
            .await
            .unwrap();
        assert!(matches!(outcome, AdvanceOutcome::Advanced { .. }));
    }

    #[tokio::test]
    async fn record_mutators_update_fields() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        store.record_deposit(&cid, 5_000).await.unwrap();
        assert_eq!(store.get(&cid).await.unwrap().unwrap().deposit, 5_000);

        store.record_on_chain_settled(&cid, 1_234).await.unwrap();
        assert_eq!(
            store.get(&cid).await.unwrap().unwrap().on_chain_settled,
            1_234
        );

        let v = signed_voucher(cid, 999);
        store.record_last_voucher(&cid, v.clone()).await.unwrap();
        assert_eq!(store.get(&cid).await.unwrap().unwrap().last_voucher, Some(v));

        let sig = make_signature(0x77);
        store.record_close_signature(&cid, sig).await.unwrap();
        assert_eq!(store.get(&cid).await.unwrap().unwrap().close_tx, Some(sig));
    }

    // ── Voucher cache ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn voucher_cache_insert_lookup_miss_then_hit() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        assert!(store
            .voucher_cache_lookup(&cid, 100)
            .await
            .unwrap()
            .is_none());

        store
            .voucher_cache_insert(&cid, 100, make_sig(1), b"r".to_vec())
            .await
            .unwrap();

        let (receipt, sig) = store.voucher_cache_lookup(&cid, 100).await.unwrap().unwrap();
        assert_eq!(receipt, b"r".to_vec());
        assert_eq!(sig, make_sig(1));
    }

    #[tokio::test]
    async fn voucher_cache_is_per_channel_and_per_cumulative() {
        let store = InMemoryChannelStore::new();
        let c1 = pk(1);
        let c2 = pk(2);
        store
            .voucher_cache_insert(&c1, 100, make_sig(1), b"c1-100".to_vec())
            .await
            .unwrap();
        store
            .voucher_cache_insert(&c2, 100, make_sig(2), b"c2-100".to_vec())
            .await
            .unwrap();
        store
            .voucher_cache_insert(&c1, 200, make_sig(3), b"c1-200".to_vec())
            .await
            .unwrap();

        let (r1, _) = store.voucher_cache_lookup(&c1, 100).await.unwrap().unwrap();
        let (r2, _) = store.voucher_cache_lookup(&c2, 100).await.unwrap().unwrap();
        let (r3, _) = store.voucher_cache_lookup(&c1, 200).await.unwrap().unwrap();
        assert_eq!(r1, b"c1-100".to_vec());
        assert_eq!(r2, b"c2-100".to_vec());
        assert_eq!(r3, b"c1-200".to_vec());
    }

    // ── list_by_status, delete ───────────────────────────────────────────────

    #[tokio::test]
    async fn list_by_status_filters_correctly() {
        let store = InMemoryChannelStore::new();
        let open1 = pk(1);
        let open2 = pk(2);
        let closing = pk(3);
        let pending = pk(4);
        store.insert(record(open1, 1_000)).await.unwrap();
        store.insert(record(open2, 1_000)).await.unwrap();
        store.insert(record(closing, 1_000)).await.unwrap();
        store.insert(record(pending, 1_000)).await.unwrap();

        store.mark_closing(&closing).await.unwrap();
        store.mark_close_attempting(&pending).await.unwrap();
        store
            .mark_closed_pending(&pending, make_signature(1))
            .await
            .unwrap();

        let mut opens = store
            .list_by_status(&[ChannelStatus::Open])
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.channel_id)
            .collect::<Vec<_>>();
        opens.sort();
        assert_eq!(opens, vec![open1, open2]);

        let multi = store
            .list_by_status(&[ChannelStatus::Closing, ChannelStatus::ClosedPending])
            .await
            .unwrap();
        assert_eq!(multi.len(), 2);
    }

    #[tokio::test]
    async fn delete_removes_record() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();
        store.delete(&cid).await.unwrap();
        assert!(store.get(&cid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_missing_returns_not_found() {
        let store = InMemoryChannelStore::new();
        let err = store.delete(&pk(1)).await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    // ── Illegal transitions ──────────────────────────────────────────────────

    #[tokio::test]
    async fn illegal_state_transition_closed_finalized_to_open_fails() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();
        store.mark_close_attempting(&cid).await.unwrap();
        store
            .mark_closed_pending(&cid, make_signature(1))
            .await
            .unwrap();
        store.mark_closed_finalized(&cid).await.unwrap();

        let err = store.mark_close_rollback(&cid).await.unwrap_err();
        assert!(matches!(
            err,
            StoreError::IllegalTransition {
                from: ChannelStatus::ClosedFinalized,
                to: ChannelStatus::Open,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn illegal_state_transition_close_attempting_to_finalized_skipping_pending_fails() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();
        store.mark_close_attempting(&cid).await.unwrap();

        let err = store.mark_closed_finalized(&cid).await.unwrap_err();
        assert!(matches!(
            err,
            StoreError::IllegalTransition {
                from: ChannelStatus::CloseAttempting,
                to: ChannelStatus::ClosedFinalized,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn topup_during_concurrent_voucher_preserves_watermark() {
        // Regression: a targeted mutator like `record_deposit` running
        // alongside `advance_watermark` shouldn't clobber the watermark.
        let store = Arc::new(InMemoryChannelStore::new());
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        let s1 = store.clone();
        let s2 = store.clone();
        let h1 = tokio::spawn(async move {
            s1.advance_watermark(&cid, 0, 700, make_sig(1), b"v".to_vec())
                .await
                .unwrap()
        });
        let h2 = tokio::spawn(async move { s2.record_deposit(&cid, 5_000).await.unwrap() });
        let _ = h1.await.unwrap();
        let _ = h2.await.unwrap();

        let r = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(r.accepted_cumulative, 700);
        assert_eq!(r.deposit, 5_000);
    }

    #[tokio::test]
    async fn closing_to_open_rollback_uses_recovery_mutator() {
        // Trait-level mark_close_rollback only takes CloseAttempting to
        // Open. A Closing record needs the recovery mutator. Cover
        // both: recovery mutator succeeds, regular mutator rejects with
        // IllegalTransition.
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();
        store.mark_closing(&cid).await.unwrap();
        assert_eq!(
            store.get(&cid).await.unwrap().unwrap().status,
            ChannelStatus::Closing
        );

        // mark_close_rollback rejects Closing.
        let err = store.mark_close_rollback(&cid).await.unwrap_err();
        assert!(matches!(
            err,
            StoreError::IllegalTransition {
                from: ChannelStatus::Closing,
                to: ChannelStatus::Open,
                ..
            }
        ));

        // Recovery mutator drives Closing back to Open cleanly.
        store
            .mark_recovery_rollback_from_closing(&cid)
            .await
            .unwrap();
        assert_eq!(
            store.get(&cid).await.unwrap().unwrap().status,
            ChannelStatus::Open
        );
    }

    #[tokio::test]
    async fn recovery_rollback_rejects_non_closing_states() {
        // Recovery mutator only accepts Closing as the from-state. Any
        // other from-state surfaces as IllegalTransition.
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();

        let err = store
            .mark_recovery_rollback_from_closing(&cid)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::IllegalTransition {
                from: ChannelStatus::Open,
                to: ChannelStatus::Open,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn mark_closed_finalized_idempotent() {
        let store = InMemoryChannelStore::new();
        let cid = pk(1);
        store.insert(record(cid, 1_000)).await.unwrap();
        store.mark_close_attempting(&cid).await.unwrap();
        store
            .mark_closed_pending(&cid, make_signature(1))
            .await
            .unwrap();
        store.mark_closed_finalized(&cid).await.unwrap();
        // The self-edge on Finalized is legal and should be a no-op.
        store.mark_closed_finalized(&cid).await.unwrap();
    }
}
