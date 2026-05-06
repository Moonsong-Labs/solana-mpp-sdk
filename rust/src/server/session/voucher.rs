//! `verify_voucher`: check the voucher payload then advance the
//! watermark via CAS.
//!
//! The order matters. Signature, signer, deposit cap, monotonicity,
//! min-delta, and expiry checks all run before the replay cache is
//! consulted. The cache lookup happens atomically inside
//! `ChannelStore::advance_watermark`, keyed on
//! `(channel_id, cumulative)`. Keying on the signature wouldn't be
//! safe because the signature is attacker-controlled until
//! verification passes, so a pre-verify cache hit could be forged for
//! a voucher we never accepted.
//!
//! On a CAS conflict the loser gets the winner's cached receipt bytes
//! back. Those are what the network committed to for that cumulative;
//! deriving a fresh receipt would yield diverging timestamps for the
//! same watermark.

use solana_pubkey::Pubkey;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::SessionError;
use crate::program::payment_channels::voucher::{
    build_signed_payload, verify_voucher_signature, VoucherSignatureError,
};
use crate::protocol::core::{MethodName, Receipt, ReceiptStatus};
use crate::protocol::intents::session::SignedVoucher;
use crate::server::session::{rfc3339_now, METHOD_NAME};
use crate::store::{AdvanceOutcome, ChannelStatus, ChannelStore};

use super::SessionConfig;

/// Parsed voucher fields between verification and the CAS in
/// [`run_verify_voucher`]. Internal only.
struct ParsedVoucher {
    channel_id: Pubkey,
    cumulative_amount: u64,
    expires_at: i64,
    sig_bytes: [u8; 64],
}

/// Decode the wire fields of a [`SignedVoucher`] without touching the
/// store. Malformed cumulative / expiry / channel-id strings come
/// back as `InvalidAmount`; malformed signature or pubkey bytes
/// collapse to `VoucherSignatureInvalid` so the caller can't tell
/// which structural check failed.
fn parse_signed_voucher(signed: &SignedVoucher) -> Result<(ParsedVoucher, [u8; 32]), SessionError> {
    let channel_id = decode_pubkey(&signed.voucher.channel_id, "channelId")?;
    let cumulative_amount: u64 = signed
        .voucher
        .cumulative_amount
        .parse()
        .map_err(|e| SessionError::InvalidAmount(format!("cumulativeAmount: {e}")))?;
    let expires_at: i64 = match signed.voucher.expires_at.as_deref() {
        None => 0,
        Some(s) => time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map_err(|e| SessionError::InvalidAmount(format!("expiresAt: {e}")))?
            .unix_timestamp(),
    };

    let signer_bytes = decode_fixed::<32>(&signed.signer)
        .map_err(|_| SessionError::VoucherSignatureInvalid)?;
    let sig_bytes = decode_fixed::<64>(&signed.signature)
        .map_err(|_| SessionError::VoucherSignatureInvalid)?;

    Ok((
        ParsedVoucher {
            channel_id,
            cumulative_amount,
            expires_at,
            sig_bytes,
        },
        signer_bytes,
    ))
}

fn decode_pubkey(raw: &str, field: &'static str) -> Result<Pubkey, SessionError> {
    let bytes = bs58::decode(raw)
        .into_vec()
        .map_err(|e| SessionError::InvalidAmount(format!("{field}: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SessionError::InvalidAmount(format!("{field}: not 32 bytes")))?;
    Ok(Pubkey::new_from_array(arr))
}

fn decode_fixed<const N: usize>(raw: &str) -> Result<[u8; N], ()> {
    let bytes = bs58::decode(raw).into_vec().map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

fn now_unix_seconds() -> Result<i64, SessionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| SessionError::InternalError(format!("system clock before unix epoch: {e}")))
}

/// JSON receipt the handler returns and also caches as the winner's
/// bytes for `(channel_id, cumulative)`.
///
/// `reference: bs58(channel_id)` because voucher acceptance is
/// off-chain and there's no tx signature until close. `accepted` is
/// the new watermark; `spent` is `accepted - prior_watermark`. Voucher
/// acceptance has no challenge so `challenge_id` is left empty. The
/// close handler reuses this builder when stamping the apply-voucher
/// cache entry, so future replays of that voucher see the same shape.
pub(crate) fn build_voucher_receipt(channel_id: &Pubkey, accepted: u64, spent: u64) -> Receipt {
    Receipt {
        status: ReceiptStatus::Success,
        method: MethodName::from(METHOD_NAME),
        timestamp: rfc3339_now(),
        reference: channel_id.to_string(),
        challenge_id: String::new(),
        accepted_cumulative: Some(accepted.to_string()),
        spent: Some(spent.to_string()),
        tx_hash: None,
        refunded: None,
    }
}

/// Run `verify_voucher` against the given store and config. The
/// `SessionMethod` entry point just threads `self.store()` and
/// `self.config()` in here. Splitting the logic out as a free function
/// lets the unit tests below drive the full state machine without
/// standing up a `SessionMethod` (which would need a live RPC to run
/// the sweeper).
pub(crate) async fn run_verify_voucher(
    store: &dyn ChannelStore,
    config: &SessionConfig,
    signed: &SignedVoucher,
) -> Result<Receipt, SessionError> {
    let (parsed, signer_bytes) = parse_signed_voucher(signed)?;
    let ParsedVoucher {
        channel_id,
        cumulative_amount,
        expires_at,
        sig_bytes,
    } = parsed;

    // Load the record. Absent channel and non-Open status both come
    // back as the same `field: "channelId"` mismatch so a probing
    // attacker can't distinguish "channel doesn't exist" from
    // "channel isn't Open"; operators see the distinction via
    // tracing, not via the wire error.
    let record = store
        .get(&channel_id)
        .await?
        .ok_or_else(|| SessionError::OnChainStateMismatch {
            field: "channelId",
            expected: "open channel".into(),
            got: channel_id.to_string(),
        })?;
    if record.status != ChannelStatus::Open {
        return Err(SessionError::OnChainStateMismatch {
            field: "channelId",
            expected: "open channel".into(),
            got: channel_id.to_string(),
        });
    }

    // Reconstruct the 48-byte payload the signer signed.
    let payload = build_signed_payload(&channel_id, cumulative_amount, expires_at);

    // Verify the ed25519 signature. `MalformedKey` and
    // `VerificationFailed` both collapse to the same wire error:
    // either way the voucher is rejected, no need to leak which
    // structural check failed.
    match verify_voucher_signature(&signer_bytes, &sig_bytes, &payload) {
        Ok(()) => {}
        Err(VoucherSignatureError::MalformedKey | VoucherSignatureError::VerificationFailed) => {
            return Err(SessionError::VoucherSignatureInvalid);
        }
    }

    // Signer has to match the channel's `authorized_signer`.
    let signer_pk = Pubkey::new_from_array(signer_bytes);
    if signer_pk != record.authorized_signer {
        return Err(SessionError::VoucherWrongSigner {
            expected: record.authorized_signer,
            got: signer_pk,
        });
    }

    // Cumulative can't exceed the on-chain deposit cap.
    if cumulative_amount > record.deposit {
        return Err(SessionError::VoucherOverDeposit {
            deposit: record.deposit,
            got: cumulative_amount,
        });
    }

    // Strict regression check. Equality with the current watermark
    // falls through to the CAS below, whose conflict branch hands
    // back the winner's cached receipt.
    if cumulative_amount < record.accepted_cumulative {
        return Err(SessionError::VoucherCumulativeRegression {
            stored: record.accepted_cumulative,
            got: cumulative_amount,
        });
    }

    // Reject `cumulative_amount == 0` outright. It can't advance the
    // watermark and would slip past the min-delta gate when both
    // sides are zero, so don't accept the wasted round-trip.
    if cumulative_amount == 0 {
        return Err(SessionError::InvalidAmount(
            "cumulativeAmount must be > 0".into(),
        ));
    }

    // Min-delta gate. `min_voucher_delta == 0` disables the check.
    let min_required = record
        .accepted_cumulative
        .checked_add(config.min_voucher_delta)
        .ok_or_else(|| {
            SessionError::InvalidAmount(format!(
                "accepted_cumulative + min_voucher_delta overflows u64 (accepted={}, min_delta={})",
                record.accepted_cumulative, config.min_voucher_delta
            ))
        })?;
    if cumulative_amount < min_required {
        return Err(SessionError::VoucherDeltaTooSmall {
            min: min_required,
            got: cumulative_amount,
        });
    }

    // Expiry. `expires_at == 0` is the wire encoding for "no
    // expiry"; only enforce non-zero values. The skew window absorbs
    // wall-clock drift between the client's signing host and ours.
    if expires_at != 0 {
        let now = now_unix_seconds()?;
        let cutoff = expires_at.saturating_add(i64::from(config.clock_skew_seconds));
        if now >= cutoff {
            return Err(SessionError::VoucherExpired {
                now,
                expires_at,
            });
        }
    }

    // Build the acceptance receipt. Cached bytes equal what the
    // caller sees, so a CAS loser reads the same JSON the network
    // committed to. `spent = cumulative_amount - accepted_cumulative`
    // never underflows thanks to the regression and zero-cumulative
    // guards above.
    let spent = cumulative_amount - record.accepted_cumulative;
    let receipt = build_voucher_receipt(&channel_id, cumulative_amount, spent);
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|e| SessionError::InternalError(format!("serialize voucher receipt: {e}")))?;

    // CAS advances `accepted_cumulative`, stamps `last_voucher`, and
    // seeds the replay cache in one critical section. Two callers at
    // the same cumulative both succeed: one wins (`Advanced`), the
    // other reads back the cached winner bytes (`Conflict`). A
    // deserialize failure on the conflict branch is a state bug
    // (corrupted cache or schema drift), not a client error.
    match store
        .advance_watermark(
            &channel_id,
            record.accepted_cumulative,
            cumulative_amount,
            signed.clone(),
            sig_bytes,
            receipt_bytes,
        )
        .await?
    {
        AdvanceOutcome::Advanced { prior: _ } => Ok(receipt),
        AdvanceOutcome::Conflict {
            current: _,
            winner_signature: _,
            winner_receipt,
        } => serde_json::from_slice::<Receipt>(&winner_receipt).map_err(|e| {
            SessionError::InternalError(format!(
                "voucher replay cache corrupted: cannot deserialize winner receipt: {e}"
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `run_verify_voucher`. The handler is off-chain
    //! validation plus a store CAS, so no RPC roundtrip is needed.
    //! Tests use `ed25519_dalek::SigningKey` directly because the
    //! `VoucherSigner` blanket impl lives on it and the handler
    //! verifies against raw 32-byte ed25519 pubkeys; `MemorySigner`
    //! would just add a bridging layer without testing anything new.
    use super::*;
    use crate::program::payment_channels::voucher::VoucherSigner;
    use crate::protocol::intents::session::{SigType, SignedVoucher, Split, VoucherData};
    use crate::server::session::{
        Network, Pricing, SessionConfig, DEFAULT_CLOCK_SKEW_SECONDS,
        DEFAULT_VOUCHER_CHECK_GRACE_SECONDS,
    };
    use crate::store::{ChannelRecord, ChannelStatus, InMemoryChannelStore};
    use ed25519_dalek::SigningKey;
    use solana_commitment_config::CommitmentConfig;
    use std::sync::Arc;
    use std::time::Duration;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }

    fn fresh_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn channel_id_from_signer(authorized_signer: &Pubkey) -> Pubkey {
        // We do not need a canonical PDA here. The handler loads by
        // `signed.voucher.channel_id` rather than re-deriving, so any
        // deterministic pubkey distinct from the signer works.
        let mut bytes = authorized_signer.to_bytes();
        bytes[0] ^= 0x55;
        Pubkey::new_from_array(bytes)
    }

    fn base_record(channel_id: Pubkey, authorized_signer: Pubkey, deposit: u64) -> ChannelRecord {
        ChannelRecord {
            channel_id,
            payer: pk(0xA1),
            payee: pk(0xA2),
            mint: pk(0xA3),
            salt: 0xCAFE,
            program_id: pk(0xA4),
            authorized_signer,
            deposit,
            accepted_cumulative: 0,
            on_chain_settled: 0,
            last_voucher: None,
            close_tx: None,
            status: ChannelStatus::Open,
            splits: Vec::<Split>::new(),
        }
    }

    fn base_config(min_voucher_delta: u64, clock_skew_seconds: u32) -> SessionConfig {
        SessionConfig {
            operator: pk(1),
            payee: pk(2),
            mint: pk(3),
            decimals: 6,
            network: Network::Localnet,
            program_id: pk(4),
            pricing: Pricing {
                amount_per_unit: 1,
                unit_type: "request".into(),
            },
            splits: Vec::new(),
            max_deposit: 1_000_000,
            min_deposit: 1,
            min_voucher_delta,
            voucher_ttl_seconds: 60,
            grace_period_seconds: 86_400,
            challenge_ttl_seconds: 300,
            commitment: CommitmentConfig::confirmed(),
            broadcast_confirm_timeout: Duration::from_secs(30),
            clock_skew_seconds,
            voucher_check_grace_seconds: DEFAULT_VOUCHER_CHECK_GRACE_SECONDS,
            fee_payer: None,
            payee_signer: None,
            realm: Some("test".into()),
            secret_key: Some("test-secret".into()),
        }
    }

    /// Mint a wire `SignedVoucher` for the given channel and
    /// cumulative, signed by `signer`. `expires_at` becomes RFC3339
    /// when `Some`, omitted otherwise.
    fn mint_voucher(
        signer: &SigningKey,
        channel_id: &Pubkey,
        cumulative: u64,
        expires_at: Option<i64>,
    ) -> SignedVoucher {
        let payload =
            build_signed_payload(channel_id, cumulative, expires_at.unwrap_or(0));
        let signature = signer
            .sign_voucher_payload(&payload)
            .expect("dalek signer is infallible");
        let pubkey_bytes = signer.verifying_key_bytes();
        let expires_str = expires_at.map(|ts| {
            time::OffsetDateTime::from_unix_timestamp(ts)
                .expect("timestamp in range")
                .format(&time::format_description::well_known::Rfc3339)
                .expect("rfc3339 format")
        });
        SignedVoucher {
            voucher: VoucherData {
                channel_id: bs58::encode(channel_id.as_ref()).into_string(),
                cumulative_amount: cumulative.to_string(),
                expires_at: expires_str,
            },
            signer: bs58::encode(pubkey_bytes).into_string(),
            signature: bs58::encode(signature).into_string(),
            signature_type: SigType::Ed25519,
        }
    }

    #[tokio::test]
    async fn accept_first_voucher_advances_watermark() {
        let signer = fresh_signing_key(0x11);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 1_000))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        let v = mint_voucher(&signer, &cid, 100, None);
        let receipt = run_verify_voucher(&store, &config, &v).await.unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(receipt.reference, cid.to_string());

        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 100);
        assert!(stored.last_voucher.is_some(), "last_voucher must be persisted on Advanced");
    }

    #[tokio::test]
    async fn signature_invalid_rejects() {
        let signer = fresh_signing_key(0x12);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 1_000))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        let mut v = mint_voucher(&signer, &cid, 100, None);
        // Flip a byte inside the signature, keeping its base58
        // length.
        let mut sig_bytes = bs58::decode(&v.signature).into_vec().unwrap();
        sig_bytes[5] ^= 0xFF;
        v.signature = bs58::encode(&sig_bytes).into_string();

        let err = run_verify_voucher(&store, &config, &v).await.unwrap_err();
        assert!(matches!(err, SessionError::VoucherSignatureInvalid), "got {err:?}");

        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 0, "rejected voucher must not advance");
    }

    #[tokio::test]
    async fn wrong_signer_rejects() {
        let authorized_signer_key = fresh_signing_key(0x21);
        let attacker_signer = fresh_signing_key(0x22);
        let authorized = Pubkey::new_from_array(authorized_signer_key.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 1_000))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        // Attacker signs the voucher: it verifies under their own
        // pubkey but the channel pins a different `authorized_signer`.
        let v = mint_voucher(&attacker_signer, &cid, 100, None);
        let err = run_verify_voucher(&store, &config, &v).await.unwrap_err();
        match err {
            SessionError::VoucherWrongSigner { expected, got } => {
                assert_eq!(expected, authorized);
                assert_eq!(
                    got,
                    Pubkey::new_from_array(attacker_signer.verifying_key_bytes())
                );
            }
            other => panic!("expected VoucherWrongSigner, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn over_deposit_rejects() {
        let signer = fresh_signing_key(0x31);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 500))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        let v = mint_voucher(&signer, &cid, 501, None);
        let err = run_verify_voucher(&store, &config, &v).await.unwrap_err();
        match err {
            SessionError::VoucherOverDeposit { deposit, got } => {
                assert_eq!(deposit, 500);
                assert_eq!(got, 501);
            }
            other => panic!("expected VoucherOverDeposit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn regression_rejects() {
        let signer = fresh_signing_key(0x41);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        let mut record = base_record(cid, authorized, 10_000);
        record.accepted_cumulative = 100;
        store.insert(record).await.unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        let v = mint_voucher(&signer, &cid, 50, None);
        let err = run_verify_voucher(&store, &config, &v).await.unwrap_err();
        match err {
            SessionError::VoucherCumulativeRegression { stored, got } => {
                assert_eq!(stored, 100);
                assert_eq!(got, 50);
            }
            other => panic!("expected VoucherCumulativeRegression, got {other:?}"),
        }

        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 100);
    }

    #[tokio::test]
    async fn equality_returns_winner_receipt_via_cas() {
        // Two vouchers at the same cumulative race through the CAS.
        // The store linearises them: one wins (Advanced), the other
        // loses (Conflict). The loser surfaces the winner's cached
        // receipt bytes unchanged.
        let signer = fresh_signing_key(0x51);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = Arc::new(InMemoryChannelStore::new());
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        let config = Arc::new(base_config(0, DEFAULT_CLOCK_SKEW_SECONDS));

        // Two distinct vouchers at the same cumulative. Different
        // expiries give different wire bytes and different signatures;
        // both still verify because the signed payload is the
        // `(channel_id, cumulative, expires_at)` triple.
        let v_a = mint_voucher(&signer, &cid, 500, Some(2_000_000_000));
        let v_b = mint_voucher(&signer, &cid, 500, Some(2_100_000_000));
        assert_ne!(v_a.signature, v_b.signature, "test setup expects distinct sigs");

        let s_a = store.clone();
        let c_a = config.clone();
        let v_a_cloned = v_a.clone();
        let h_a = tokio::spawn(async move {
            run_verify_voucher(s_a.as_ref(), c_a.as_ref(), &v_a_cloned).await
        });
        let s_b = store.clone();
        let c_b = config.clone();
        let v_b_cloned = v_b.clone();
        let h_b = tokio::spawn(async move {
            run_verify_voucher(s_b.as_ref(), c_b.as_ref(), &v_b_cloned).await
        });
        let r_a = h_a.await.unwrap().unwrap();
        let r_b = h_b.await.unwrap().unwrap();

        // Both calls succeed; the watermark advanced once.
        assert_eq!(r_a.status, ReceiptStatus::Success);
        assert_eq!(r_b.status, ReceiptStatus::Success);
        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 500);

        // Both callers should land on the cached receipt at
        // `(cid, 500)` byte-for-byte.
        let cached = store.voucher_cache_lookup(&cid, 500).await.unwrap().unwrap();
        let cached_receipt: Receipt = serde_json::from_slice(&cached.0).unwrap();

        // Both outcomes agree on `reference` and `status` because
        // they both land on the cached winner.
        assert_eq!(r_a.reference, cached_receipt.reference);
        assert_eq!(r_b.reference, cached_receipt.reference);
        assert_eq!(r_a.timestamp, cached_receipt.timestamp);
        // Loser's `timestamp` should equal the winner's; if both saw
        // their own freshly-built receipts the timestamps would
        // diverge whenever the `rfc3339_now()` calls fell on
        // different seconds.
        assert_eq!(r_a.timestamp, r_b.timestamp, "loser must surface winner's timestamp");
    }

    #[tokio::test]
    async fn delta_too_small_rejects() {
        let signer = fresh_signing_key(0x61);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        let config = base_config(1_000, DEFAULT_CLOCK_SKEW_SECONDS);

        let v = mint_voucher(&signer, &cid, 999, None);
        let err = run_verify_voucher(&store, &config, &v).await.unwrap_err();
        match err {
            SessionError::VoucherDeltaTooSmall { min, got } => {
                assert_eq!(min, 1_000);
                assert_eq!(got, 999);
            }
            other => panic!("expected VoucherDeltaTooSmall, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delta_zero_disables_check() {
        // With `min_voucher_delta = 0`, even a 1-unit voucher on a
        // fresh record (`accepted_cumulative = 0`) clears the gate.
        let signer = fresh_signing_key(0x71);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        let v = mint_voucher(&signer, &cid, 1, None);
        let receipt = run_verify_voucher(&store, &config, &v).await.unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Success);

        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 1);
    }

    #[tokio::test]
    async fn expired_rejects_with_skew_window() {
        let signer = fresh_signing_key(0x81);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        // Tight skew so a deeply-past expiry is clearly stale.
        let config = base_config(0, 1);

        // Far in the past, expired even with a generous skew.
        let v = mint_voucher(&signer, &cid, 100, Some(1_000_000));
        let err = run_verify_voucher(&store, &config, &v).await.unwrap_err();
        match err {
            SessionError::VoucherExpired { now: _, expires_at } => {
                assert_eq!(expires_at, 1_000_000);
            }
            other => panic!("expected VoucherExpired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn expired_at_boundary_rejects() {
        // Pin the boundary: `expires_at = now - clock_skew` makes
        // the cutoff `now`, so the handler's `now >= cutoff` rejects.
        // Capturing `now` right before the call guarantees the
        // handler's clock read is the same second or later.
        let signer = fresh_signing_key(0xA1);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        let clock_skew: u32 = 30;
        let config = base_config(0, clock_skew);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now - i64::from(clock_skew);
        let v = mint_voucher(&signer, &cid, 100, Some(expires_at));
        let err = run_verify_voucher(&store, &config, &v).await.unwrap_err();
        match err {
            SessionError::VoucherExpired { now: _, expires_at: e } => {
                assert_eq!(e, expires_at);
            }
            other => panic!("expected VoucherExpired, got {other:?}"),
        }

        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 0);
    }

    #[tokio::test]
    async fn zero_cumulative_voucher_with_zero_min_delta_rejected() {
        // Without the explicit guard, `cumulative_amount = 0` on a
        // fresh record (`accepted_cumulative == 0`) with
        // `min_voucher_delta == 0` would slip past the regression
        // check (`0 < 0` is false) and the min-delta check
        // (`0 < 0+0` is false). The zero-cumulative guard rejects it
        // with `InvalidAmount` because a zero voucher does not
        // advance state.
        let signer = fresh_signing_key(0xB1);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        let v = mint_voucher(&signer, &cid, 0, None);
        let err = run_verify_voucher(&store, &config, &v).await.unwrap_err();
        match err {
            SessionError::InvalidAmount(msg) => {
                assert!(msg.contains("cumulativeAmount"), "unexpected message: {msg}");
            }
            other => panic!("expected InvalidAmount, got {other:?}"),
        }

        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 0);
    }

    #[tokio::test]
    async fn equality_after_advance_returns_winner_via_cas() {
        // Sequential equality replay. First call advances 0 to 500;
        // second call reads after and presents
        // `cumulative_amount == accepted_cumulative == 500`. The CAS
        // sees `expected == accepted_cumulative` but `new > expected`
        // is false, falls into the cache-lookup branch, and hands
        // back the winner's receipt unchanged.
        let signer = fresh_signing_key(0xC1);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        let v_first = mint_voucher(&signer, &cid, 500, Some(2_000_000_000));
        let r_first = run_verify_voucher(&store, &config, &v_first).await.unwrap();
        assert_eq!(r_first.status, ReceiptStatus::Success);

        // Watermark advanced.
        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 500);

        // Second voucher at the same cumulative, signed independently;
        // different expiry yields a different wire signature.
        let v_replay = mint_voucher(&signer, &cid, 500, Some(2_100_000_000));
        assert_ne!(v_first.signature, v_replay.signature);
        let r_replay = run_verify_voucher(&store, &config, &v_replay).await.unwrap();

        // Replay surfaces the winner's cached receipt unchanged:
        // matching reference and timestamp regardless of the second
        // the replay observed.
        assert_eq!(r_replay.reference, r_first.reference);
        assert_eq!(r_replay.timestamp, r_first.timestamp);
        assert_eq!(r_replay.status, ReceiptStatus::Success);

        // Replay does not advance the watermark past 500.
        let stored = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(stored.accepted_cumulative, 500);
    }

    #[tokio::test]
    async fn receipt_carries_accepted_cumulative_and_spent() {
        // Two sequential accepts: 0 to 300, then 300 to 750. Each
        // receipt should carry `acceptedCumulative` at its watermark
        // and `spent` as the delta from the prior watermark, both
        // serialised as camelCase JSON strings.
        let signer = fresh_signing_key(0xD1);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        let v1 = mint_voucher(&signer, &cid, 300, None);
        let r1 = run_verify_voucher(&store, &config, &v1).await.unwrap();
        assert_eq!(r1.accepted_cumulative.as_deref(), Some("300"));
        assert_eq!(r1.spent.as_deref(), Some("300"));

        // Round-trip the JSON to pin the camelCase wire shape.
        let json = serde_json::to_value(&r1).unwrap();
        assert_eq!(json["acceptedCumulative"], serde_json::json!("300"));
        assert_eq!(json["spent"], serde_json::json!("300"));
        let parsed: Receipt = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.accepted_cumulative.as_deref(), Some("300"));
        assert_eq!(parsed.spent.as_deref(), Some("300"));

        let v2 = mint_voucher(&signer, &cid, 750, None);
        let r2 = run_verify_voucher(&store, &config, &v2).await.unwrap();
        assert_eq!(r2.accepted_cumulative.as_deref(), Some("750"));
        assert_eq!(r2.spent.as_deref(), Some("450"));
    }

    #[tokio::test]
    async fn not_yet_expired_within_skew_accepts() {
        let signer = fresh_signing_key(0x91);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = channel_id_from_signer(&authorized);
        let store = InMemoryChannelStore::new();
        store
            .insert(base_record(cid, authorized, 10_000))
            .await
            .unwrap();
        let config = base_config(0, DEFAULT_CLOCK_SKEW_SECONDS);

        // Far-future expiry. The skew window doesn't matter here;
        // this test exercises the accept path where `expires_at` is
        // non-zero and `now < expires_at + clock_skew`.
        let v = mint_voucher(&signer, &cid, 100, Some(4_000_000_000));
        let receipt = run_verify_voucher(&store, &config, &v).await.unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Success);
    }
}
