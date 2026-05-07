//! Off-chain voucher meter for one open channel.
//!
//! `ActiveSession` owns the session signer plus three watermarks:
//!
//! - `signed_cumulative`: the highest cumulative this client has produced
//!   a signed voucher for. Leads `accepted_cumulative` while a request is
//!   in flight.
//! - `accepted_cumulative`: the highest cumulative the server has
//!   acknowledged via a `SessionReceipt`. Persisted in the client's
//!   resume record so a fresh process can pick up where it left off.
//! - `current_deposit`: the on-chain deposit cap. `signed_cumulative`
//!   may never exceed it without bricking the channel; top-ups widen it.
//!
//! The struct enforces three invariants client-side, before bytes leave
//! the process:
//!
//! 1. Strictly monotonic `signed_cumulative`: never sign at the prior
//!    cumulative or below.
//! 2. `signed_cumulative <= current_deposit`. Over-deposit vouchers get
//!    `VoucherOverDeposit` from the server, but we'd rather catch it here
//!    so the in-flight request never costs the network round trip.
//! 3. Failed signs leave the prior watermark intact. A KMS hiccup doesn't
//!    brick the session by jumping the watermark past a value that was
//!    never actually emitted.
//!
//! Resume from a persisted record uses [`ActiveSession::from_record`];
//! both watermarks initialise to the stored `accepted_cumulative` so the
//! next sign starts strictly above it.

use std::sync::Arc;

use solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::client::session::receipt::SessionReceipt;
use crate::error::ClientError;
use crate::program::payment_channels::voucher::build_signed_payload;
use crate::protocol::intents::session::{SigType, SignedVoucher, VoucherData};
use crate::store::ChannelRecord;

/// Tracks the off-chain voucher meter for a single open channel.
///
/// One `ActiveSession` per `(channel_id, signer)` pair. Cloning is not
/// supported because two clones would race the watermark; share via
/// `Arc<Mutex<ActiveSession>>` if you need cross-task access.
pub struct ActiveSession {
    channel_id: Pubkey,
    accepted_cumulative: u64,
    signed_cumulative: u64,
    current_deposit: u64,
    signer: Arc<dyn SolanaSigner>,
}

impl ActiveSession {
    /// Fresh-channel constructor. Use after a successful `open`.
    ///
    /// `initial_cumulative` is normally `0`; pass a non-zero value only
    /// when bootstrapping from an external source of truth (e.g. tests).
    pub fn new(
        channel_id: Pubkey,
        signer: Arc<dyn SolanaSigner>,
        initial_cumulative: u64,
        initial_deposit: u64,
    ) -> Self {
        Self {
            channel_id,
            accepted_cumulative: initial_cumulative,
            signed_cumulative: initial_cumulative,
            current_deposit: initial_deposit,
            signer,
        }
    }

    /// Resume from a persisted client record.
    ///
    /// Both watermarks initialise to `record.accepted_cumulative`. The
    /// in-flight delta a previous process may have signed but not landed
    /// is intentionally lost: we never replay a voucher we can't prove the
    /// server saw, and signing strictly above the persisted watermark is
    /// always safe.
    ///
    /// Fails fast if `signer.pubkey()` does not match
    /// `record.authorized_signer`. A wrong-key resume would silently
    /// produce vouchers the server rejects on the first sign attempt;
    /// catching it at construction time keeps the failure mode loud and
    /// puts the diagnostic next to the buggy caller, not at the next
    /// voucher submission.
    pub fn from_record(
        record: &ChannelRecord,
        signer: Arc<dyn SolanaSigner>,
    ) -> Result<Self, ClientError> {
        let signer_pubkey = signer.pubkey();
        if signer_pubkey != record.authorized_signer {
            return Err(ClientError::ProtocolViolation(format!(
                "from_record: signer pubkey {} does not match record authorized_signer {}",
                signer_pubkey, record.authorized_signer
            )));
        }
        Ok(Self {
            channel_id: record.channel_id,
            accepted_cumulative: record.accepted_cumulative,
            signed_cumulative: record.accepted_cumulative,
            current_deposit: record.deposit,
            signer,
        })
    }

    pub fn channel_id(&self) -> Pubkey {
        self.channel_id
    }

    pub fn accepted_cumulative(&self) -> u64 {
        self.accepted_cumulative
    }

    pub fn signed_cumulative(&self) -> u64 {
        self.signed_cumulative
    }

    pub fn current_deposit(&self) -> u64 {
        self.current_deposit
    }

    /// Base58 of the session signer's pubkey, for the `authorizedSigner`
    /// field on `OpenPayload`.
    pub fn authorized_signer_base58(&self) -> String {
        bs58::encode(self.signer.pubkey().to_bytes()).into_string()
    }

    fn channel_id_base58(&self) -> String {
        bs58::encode(self.channel_id.to_bytes()).into_string()
    }

    /// Widen the deposit cap after a successful top-up.
    ///
    /// Caller must have proof the top-up landed on chain; this just
    /// updates the local cap so subsequent vouchers can use the new
    /// headroom.
    pub fn set_deposit(&mut self, new_deposit: u64) {
        self.current_deposit = new_deposit;
    }

    /// Sign a voucher at an absolute cumulative.
    ///
    /// Order of checks (matters: callers want to know which invariant
    /// they violated):
    ///
    /// 1. `cumulative > signed_cumulative` (strictly).
    /// 2. `cumulative <= current_deposit`.
    /// 3. `expires_at` in `Some(>= 0)` or `None`. `Some(0)` collapses to
    ///    `None` (the wire form omits the field; the on-chain `i64` slot
    ///    reads as zero either way).
    /// 4. Sign via the configured signer. A failure here leaves the
    ///    watermark untouched so the session stays usable.
    pub async fn sign_voucher(
        &mut self,
        cumulative: u64,
        expires_at: Option<i64>,
    ) -> Result<SignedVoucher, ClientError> {
        if cumulative <= self.signed_cumulative {
            return Err(ClientError::VoucherMonotonicityViolation {
                attempted: cumulative,
                last_signed: self.signed_cumulative,
            });
        }
        if cumulative > self.current_deposit {
            return Err(ClientError::VoucherExceedsDeposit {
                cumulative,
                deposit: self.current_deposit,
            });
        }

        let normalized_expires_at = match expires_at {
            None => None,
            Some(0) => {
                tracing::warn!(
                    channel_id = %self.channel_id_base58(),
                    cumulative,
                    "expires_at=Some(0) collapsed to None; emit None for no-expiry vouchers"
                );
                None
            }
            Some(ts) if ts < 0 => {
                return Err(ClientError::InvalidExpiresAt(format!(
                    "negative expires_at not allowed: {ts}"
                )));
            }
            Some(ts) => Some(ts),
        };

        let payload =
            build_signed_payload(&self.channel_id, cumulative, normalized_expires_at.unwrap_or(0));

        let signature = self
            .signer
            .sign_message(&payload)
            .await
            .map_err(|e| ClientError::Signer(format!("{e}")))?;
        let signature_bytes: [u8; 64] = <[u8; 64]>::from(signature);

        let expires_at_wire = match normalized_expires_at {
            Some(ts) => Some(
                OffsetDateTime::from_unix_timestamp(ts)
                    .map_err(|e| {
                        ClientError::InvalidExpiresAt(format!(
                            "expires_at {ts} out of range: {e}"
                        ))
                    })?
                    .format(&Rfc3339)
                    .map_err(|e| {
                        ClientError::InvalidExpiresAt(format!("RFC3339 format failed: {e}"))
                    })?,
            ),
            None => None,
        };

        // Advance the watermark only after the signer returns; a failure
        // above this line leaves the session free to retry at the same
        // cumulative without claiming a signature we don't actually have.
        self.signed_cumulative = cumulative;

        Ok(SignedVoucher {
            voucher: VoucherData {
                channel_id: self.channel_id_base58(),
                cumulative_amount: cumulative.to_string(),
                expires_at: expires_at_wire,
            },
            signer: self.authorized_signer_base58(),
            signature: bs58::encode(signature_bytes).into_string(),
            signature_type: SigType::Ed25519,
        })
    }

    /// Sign a voucher for `signed_cumulative + delta`.
    ///
    /// Checked addition: a `delta` that overflows `u64` returns
    /// `VoucherArithmeticOverflow` rather than wrapping.
    pub async fn sign_increment(
        &mut self,
        delta: u64,
        expires_at: Option<i64>,
    ) -> Result<SignedVoucher, ClientError> {
        let target = self
            .signed_cumulative
            .checked_add(delta)
            .ok_or(ClientError::VoucherArithmeticOverflow)?;
        self.sign_voucher(target, expires_at).await
    }

    /// Apply a server-issued receipt.
    ///
    /// The server can never legitimately acknowledge more than we signed:
    /// `accepted > signed` would mean the server forged a voucher under
    /// our key. Treat as a protocol violation.
    ///
    /// Older or duplicate receipts (`accepted < self.accepted_cumulative`)
    /// are ignored. Out-of-order receipt delivery is normal.
    ///
    /// Voucher receipts always carry `accepted_cumulative`; close and
    /// charge-success receipts leave it unset and never flow through
    /// here. A missing field is a protocol violation, not a silent
    /// no-op.
    pub fn on_receipt_accepted(&mut self, receipt: &SessionReceipt) -> Result<(), ClientError> {
        let expected_reference = self.channel_id_base58();
        if receipt.reference != expected_reference {
            return Err(ClientError::ProtocolViolation(format!(
                "receipt reference mismatch: expected {expected_reference}, got {}",
                receipt.reference
            )));
        }
        let received = receipt.accepted_cumulative.ok_or_else(|| {
            ClientError::ProtocolViolation(
                "receipt missing acceptedCumulative for voucher acknowledgement".into(),
            )
        })?;
        if received > self.signed_cumulative {
            return Err(ClientError::ProtocolViolation(format!(
                "receipt accepted_cumulative {} exceeds signed {}",
                received, self.signed_cumulative
            )));
        }
        if received > self.accepted_cumulative {
            self.accepted_cumulative = received;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
    use solana_keychain::MemorySigner;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer as _;

    /// Deterministic in-process signer. Uses the same `MemorySigner`
    /// path the production SDK exercises so signature bytes match end
    /// to end.
    fn fresh_signer() -> (Arc<dyn SolanaSigner>, [u8; 32]) {
        let kp = Keypair::new();
        let pubkey_bytes = kp.pubkey().to_bytes();
        let signer = MemorySigner::from_bytes(&kp.to_bytes()).expect("memory signer accepts bytes");
        (Arc::new(signer), pubkey_bytes)
    }

    fn fresh_session(deposit: u64) -> (ActiveSession, [u8; 32]) {
        let (signer, pubkey_bytes) = fresh_signer();
        let channel_id = Pubkey::new_unique();
        (ActiveSession::new(channel_id, signer, 0, deposit), pubkey_bytes)
    }

    /// Minimal `SessionReceipt` for the watermark tests. Other fields
    /// don't affect `on_receipt_accepted`, so they get filler values.
    fn make_receipt(reference: String, accepted_cumulative: u64) -> SessionReceipt {
        SessionReceipt {
            method: "solana".into(),
            intent: "session".into(),
            reference,
            status: "success".into(),
            accepted_cumulative: Some(accepted_cumulative),
            spent: Some(0),
            tx_hash: None,
            extras: serde_json::Map::new(),
        }
    }

    /// Build a `ChannelRecord` against a known authorized_signer. Only
    /// signer, deposit, and accepted_cumulative matter here; the rest
    /// is filler to satisfy the struct shape.
    fn record_for(
        authorized_signer: Pubkey,
        deposit: u64,
        accepted_cumulative: u64,
    ) -> ChannelRecord {
        ChannelRecord {
            channel_id: Pubkey::new_unique(),
            payer: Pubkey::new_unique(),
            payee: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            salt: 0,
            program_id: Pubkey::new_unique(),
            authorized_signer,
            deposit,
            accepted_cumulative,
            on_chain_settled: 0,
            last_voucher: None,
            close_tx: None,
            status: crate::store::ChannelStatus::Open,
            splits: vec![],
        }
    }

    #[tokio::test]
    async fn sign_voucher_advances_signed_cumulative() {
        let (mut s, _) = fresh_session(10_000);
        assert_eq!(s.signed_cumulative(), 0);

        let v = s.sign_voucher(100, None).await.expect("first voucher");
        assert_eq!(s.signed_cumulative(), 100);
        assert_eq!(v.voucher.cumulative_amount, "100");

        let v = s.sign_voucher(250, None).await.expect("second voucher");
        assert_eq!(s.signed_cumulative(), 250);
        assert_eq!(v.voucher.cumulative_amount, "250");
    }

    #[tokio::test]
    async fn sign_voucher_rejects_regression() {
        let (mut s, _) = fresh_session(10_000);
        s.sign_voucher(500, None).await.expect("first voucher");

        let err = s.sign_voucher(400, None).await.expect_err("regression rejected");
        assert!(matches!(
            err,
            ClientError::VoucherMonotonicityViolation {
                attempted: 400,
                last_signed: 500,
            }
        ));
        // Watermark unchanged after rejection.
        assert_eq!(s.signed_cumulative(), 500);
    }

    #[tokio::test]
    async fn sign_voucher_rejects_equality() {
        let (mut s, _) = fresh_session(10_000);
        s.sign_voucher(500, None).await.expect("first voucher");

        let err = s.sign_voucher(500, None).await.expect_err("equality rejected");
        assert!(matches!(
            err,
            ClientError::VoucherMonotonicityViolation {
                attempted: 500,
                last_signed: 500,
            }
        ));
    }

    #[tokio::test]
    async fn sign_voucher_rejects_over_deposit_without_bricking() {
        let (mut s, _) = fresh_session(1_000);
        s.sign_voucher(500, None).await.expect("first voucher");

        let err = s
            .sign_voucher(2_000, None)
            .await
            .expect_err("over-deposit rejected");
        assert!(matches!(
            err,
            ClientError::VoucherExceedsDeposit {
                cumulative: 2_000,
                deposit: 1_000,
            }
        ));
        assert_eq!(s.signed_cumulative(), 500);

        // Channel is not bricked: a valid voucher within deposit still signs.
        let v = s.sign_voucher(750, None).await.expect("recovery voucher signs");
        assert_eq!(s.signed_cumulative(), 750);
        assert_eq!(v.voucher.cumulative_amount, "750");
    }

    #[tokio::test]
    async fn sign_increment_advances_by_delta() {
        let (mut s, _) = fresh_session(10_000);
        s.sign_voucher(100, None).await.expect("seed");

        let v = s.sign_increment(50, None).await.expect("increment signs");
        assert_eq!(s.signed_cumulative(), 150);
        assert_eq!(v.voucher.cumulative_amount, "150");

        // Overflow short-circuits with VoucherArithmeticOverflow rather
        // than wrapping; `u64::MAX - signed_cumulative + 1` overflows.
        let err = s
            .sign_increment(u64::MAX, None)
            .await
            .expect_err("overflow rejected");
        assert!(matches!(err, ClientError::VoucherArithmeticOverflow));
    }

    #[tokio::test]
    async fn signature_verifies_against_48_byte_payload() {
        // Voucher payload bytes have to match what the on-chain ed25519
        // precompile expects. If build_signed_payload's layout drifts,
        // every voucher breaks. Re-derive the payload and verify with a
        // stand-alone dalek verifier.
        let (mut s, pubkey_bytes) = fresh_session(10_000_000);
        let cumulative = 1_234_567u64;
        let expires_at = 1_700_000_000i64;

        let v = s
            .sign_voucher(cumulative, Some(expires_at))
            .await
            .expect("voucher signs");

        let payload = build_signed_payload(&s.channel_id(), cumulative, expires_at);
        assert_eq!(payload.len(), 48);

        let signature_bytes = bs58::decode(&v.signature)
            .into_vec()
            .expect("bs58 signature decodes");
        let signature_arr: [u8; 64] = signature_bytes
            .try_into()
            .expect("signature is 64 bytes");
        let dalek_signature = DalekSignature::from_bytes(&signature_arr);

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).expect("valid pubkey");
        verifying_key
            .verify(&payload, &dalek_signature)
            .expect("signature verifies under the SDK's payload bytes");
    }

    #[tokio::test]
    async fn sign_voucher_collapses_zero_expiry_to_none() {
        let (mut s, _) = fresh_session(10_000);
        let v = s
            .sign_voucher(100, Some(0))
            .await
            .expect("zero expiry signs");
        assert!(v.voucher.expires_at.is_none(), "Some(0) collapses to None");

        // Wire shape omits the field entirely (camelCase `expiresAt`
        // never appears in the JSON) rather than rendering as null.
        let json = serde_json::to_value(&v.voucher).expect("voucher serializes");
        let obj = json.as_object().expect("voucher is a JSON object");
        assert!(
            !obj.contains_key("expiresAt"),
            "expiresAt key must be absent on no-expiry vouchers, got: {json:?}"
        );
    }

    #[tokio::test]
    async fn sign_voucher_rejects_negative_expiry() {
        let (mut s, _) = fresh_session(10_000);
        let err = s
            .sign_voucher(100, Some(-1))
            .await
            .expect_err("negative expiry rejected");
        assert!(matches!(err, ClientError::InvalidExpiresAt(_)));
        assert_eq!(s.signed_cumulative(), 0);
    }

    #[tokio::test]
    async fn from_record_resumes_watermark() {
        // After resume, signing at or below the persisted watermark
        // must reject.
        let (signer, _) = fresh_signer();
        let record = record_for(signer.pubkey(), 5_000, 1_000);

        let mut s = ActiveSession::from_record(&record, signer).expect("matched signer");
        assert_eq!(s.signed_cumulative(), 1_000);
        assert_eq!(s.accepted_cumulative(), 1_000);
        assert_eq!(s.current_deposit(), 5_000);

        // At the persisted watermark: rejected (strict monotonicity).
        let err = s
            .sign_voucher(1_000, None)
            .await
            .expect_err("at-watermark signing rejected after resume");
        assert!(matches!(
            err,
            ClientError::VoucherMonotonicityViolation {
                attempted: 1_000,
                last_signed: 1_000,
            }
        ));

        // Below the watermark: rejected.
        let err = s
            .sign_voucher(500, None)
            .await
            .expect_err("below-watermark signing rejected after resume");
        assert!(matches!(
            err,
            ClientError::VoucherMonotonicityViolation {
                attempted: 500,
                last_signed: 1_000,
            }
        ));

        // Strictly above: signs.
        s.sign_voucher(1_500, None).await.expect("above-watermark signs");
        assert_eq!(s.signed_cumulative(), 1_500);
    }

    #[tokio::test]
    async fn from_record_rejects_signer_mismatch() {
        // Resume with a signer that doesn't match the record. Should
        // fail at construction with a ProtocolViolation naming the
        // mismatch, not silently produce vouchers the server rejects.
        let (record_signer, _) = fresh_signer();
        let (other_signer, _) = fresh_signer();
        let record = record_for(record_signer.pubkey(), 5_000, 0);

        match ActiveSession::from_record(&record, other_signer) {
            Ok(_) => panic!("mismatched signer should have been rejected"),
            Err(ClientError::ProtocolViolation(msg)) => {
                assert!(
                    msg.contains("does not match"),
                    "expected diagnostic to mention the mismatch, got: {msg}"
                );
            }
            Err(other) => panic!("expected ProtocolViolation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn on_receipt_accepted_advances_watermark() {
        let (mut s, _) = fresh_session(10_000);
        s.sign_voucher(500, None).await.expect("seed");
        assert_eq!(s.accepted_cumulative(), 0);

        let reference = bs58::encode(s.channel_id().to_bytes()).into_string();
        let receipt = make_receipt(reference.clone(), 300);
        s.on_receipt_accepted(&receipt).expect("first receipt applies");
        assert_eq!(s.accepted_cumulative(), 300);

        // Forward progress.
        let receipt = make_receipt(reference.clone(), 500);
        s.on_receipt_accepted(&receipt).expect("forward receipt applies");
        assert_eq!(s.accepted_cumulative(), 500);

        // Out-of-order / duplicate: silently OK, watermark unchanged.
        let stale = make_receipt(reference, 200);
        s.on_receipt_accepted(&stale).expect("stale receipt is benign");
        assert_eq!(s.accepted_cumulative(), 500);
    }

    #[tokio::test]
    async fn on_receipt_accepted_rejects_wrong_reference() {
        let (mut s, _) = fresh_session(10_000);
        s.sign_voucher(500, None).await.expect("seed");

        let bogus = bs58::encode(Pubkey::new_unique().to_bytes()).into_string();
        let receipt = make_receipt(bogus, 200);
        let err = s
            .on_receipt_accepted(&receipt)
            .expect_err("wrong reference rejected");
        assert!(matches!(err, ClientError::ProtocolViolation(_)));
        assert_eq!(s.accepted_cumulative(), 0);
    }

    #[tokio::test]
    async fn on_receipt_accepted_rejects_accepted_over_signed() {
        let (mut s, _) = fresh_session(10_000);
        s.sign_voucher(500, None).await.expect("seed");

        let reference = bs58::encode(s.channel_id().to_bytes()).into_string();
        let receipt = make_receipt(reference, 600);
        let err = s
            .on_receipt_accepted(&receipt)
            .expect_err("accepted > signed rejected");
        assert!(matches!(err, ClientError::ProtocolViolation(_)));
        assert_eq!(s.accepted_cumulative(), 0);
    }

    /// A voucher receipt without `acceptedCumulative` is malformed.
    /// The server only omits the field on terminal receipts (close,
    /// charge-success), which never flow through this method, so we
    /// surface a `ProtocolViolation` rather than leave the watermark
    /// stuck.
    #[tokio::test]
    async fn on_receipt_accepted_rejects_missing_accepted_cumulative() {
        let (mut s, _) = fresh_session(10_000);
        s.sign_voucher(500, None).await.expect("seed");

        let reference = bs58::encode(s.channel_id().to_bytes()).into_string();
        let mut receipt = make_receipt(reference, 0);
        receipt.accepted_cumulative = None;

        let err = s
            .on_receipt_accepted(&receipt)
            .expect_err("missing acceptedCumulative rejected");
        match err {
            ClientError::ProtocolViolation(msg) => {
                assert!(
                    msg.contains("acceptedCumulative"),
                    "expected diagnostic to name the missing field, got: {msg}"
                );
            }
            other => panic!("expected ProtocolViolation, got {other:?}"),
        }
        assert_eq!(s.accepted_cumulative(), 0);
    }
}
