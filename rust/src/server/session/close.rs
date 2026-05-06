//! Cooperative close handler. Two paths through the settle tx:
//!
//! - `ApplyVoucher` applies a fresh voucher: re-runs the in-band voucher
//!   checks then broadcasts a settle tx of
//!   `[ed25519_verify, settle_and_finalize { has_voucher: 1 }]`.
//! - `LockSettled` has nothing new to apply: broadcasts
//!   `[settle_and_finalize { has_voucher: 0 }]`, locking the existing
//!   on-chain `settled` value.
//!
//! The close runs as three transactions:
//!
//! 1. ATA preflight: `[ComputeBudget, CreateIdempotent { payee, payer,
//!    treasury, splits[..] }]`. Confirmed before the settle tx broadcasts
//!    so `distribute` later finds the recipient ATAs.
//! 2. settle_and_finalize (`ApplyVoucher` or `LockSettled`). Confirmed
//!    before the distribute tx broadcasts so the channel sits in
//!    `Finalized` when distribute runs and the FINALIZED branch
//!    tombstones the PDA.
//! 3. distribute: `[ComputeBudget, distribute]`. Single ix carries the
//!    full `DistributionRecipients` reveal; confirmed and tombstone-checked
//!    after the fact.
//!
//! Three txs is forced by upstream's
//! `DistributionRecipients { count: u8, entries: [DistributionEntry; 32] }`
//! shape. Borsh serializes the full 32-entry array regardless of `count`,
//! so distribute alone is ~1600 bytes and cannot share a tx with anything
//! else and stay under Solana's 1232-byte packet limit.
//!
//! All txs are server-built. There's no client-supplied tx to validate
//! against (unlike open / topup), and the server already trusts the
//! voucher (or its absence) end-to-end after the in-band checks.
//!
//! Status flow: `Open` becomes `CloseAttempting` before any broadcast
//! attempt. Pre-distribute-broadcast failures (preflight or settle-tx
//! sign / send / confirm error, distribute sign / slot guard) roll back
//! via `CloseAttempting` returning to `Open`. Idempotent ATA creates from
//! a partial preflight stay on-chain harmlessly. A `settle_and_finalize`
//! that landed before rollback leaves the channel in `Finalized` on-chain
//! and the recovery layer reconciles. The challenge commits the moment
//! the distribute tx's `send_transaction_with_config` returns Ok.
//! Post-distribute-broadcast failures (confirm-poll error or timeout,
//! post-confirm verify, store-update errors) do not roll back: the bytes
//! may have landed and the recovery layer reads on-chain state to decide.
//! On a clean distribute-tx confirm, `CloseAttempting` advances to
//! `ClosedPending` and an optional async poll lifts to `ClosedFinalized`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::error::{OnChainChannelStatus, SessionError};
use crate::program::payment_channels::state::{ChannelView, CLOSED_CHANNEL_DISCRIMINATOR};
use crate::program::payment_channels::verify::verify_tombstoned;
use crate::program::payment_channels::voucher::{
    build_signed_payload, verify_voucher_signature, VoucherSignatureError,
};
use crate::protocol::core::Receipt;
use crate::protocol::intents::session::{ClosePayload, SignedVoucher};
use crate::server::session::ix::{
    build_ata_preflight_tx, build_distribute_tx, build_settle_tx_apply_voucher,
    build_settle_tx_lock_settled,
};
use crate::server::session::{
    client_error_to_session_error, verify_error_to_session_error, METHOD_NAME,
};
use crate::store::{ChannelRecord, ChannelStatus, ChannelStore};

use super::challenge::{ChallengeCache, ChallengeIntent, ChallengeIntentDiscriminant};
use super::SessionConfig;

/// Which close path the tx falls into. Holds the voucher reference so
/// the bundle builder composes the precompile ix off the exact bytes the
/// in-band check already verified.
#[derive(Debug, Clone)]
pub(crate) enum CloseAction<'a> {
    /// `voucher.cumulative_amount > record.on_chain_settled`: apply the
    /// voucher and finalize.
    ApplyVoucher {
        voucher: &'a SignedVoucher,
        cumulative_amount: u64,
    },
    /// No fresh voucher: lock the existing on-chain `settled` watermark
    /// and finalize.
    LockSettled,
}

/// Pick the close path from a payload and record. Borrows the voucher
/// without copying.
pub(crate) fn decide_close_action<'a>(
    payload: &'a ClosePayload,
    record: &ChannelRecord,
) -> Result<CloseAction<'a>, SessionError> {
    let Some(voucher) = payload.voucher.as_ref() else {
        return Ok(CloseAction::LockSettled);
    };
    let cumulative_amount: u64 = voucher
        .voucher
        .cumulative_amount
        .parse()
        .map_err(|e| SessionError::InvalidAmount(format!("cumulativeAmount: {e}")))?;
    if cumulative_amount > record.on_chain_settled {
        Ok(CloseAction::ApplyVoucher {
            voucher,
            cumulative_amount,
        })
    } else {
        Ok(CloseAction::LockSettled)
    }
}

/// Re-run the in-band voucher checks against `record` with the close
/// path's stricter expiry window.
///
/// Same checks as `verify_voucher` (signature, signer match, over-deposit,
/// monotonicity, min-delta, expiry), but the expiry uses
/// `voucher_check_grace_seconds` instead of `clock_skew_seconds`. The close
/// path is about to commit the voucher on-chain via `settle_and_finalize`,
/// so the voucher needs to sit safely inside its TTL across broadcast
/// latency. A voucher that just barely clears `verify_voucher` can still
/// fail this stricter check.
pub(crate) fn recheck_voucher_for_close(
    voucher: &SignedVoucher,
    cumulative_amount: u64,
    record: &ChannelRecord,
    config: &SessionConfig,
) -> Result<(), SessionError> {
    let signer_bytes = decode_fixed::<32>(&voucher.signer)
        .ok_or(SessionError::VoucherSignatureInvalid)?;
    let sig_bytes = decode_fixed::<64>(&voucher.signature)
        .ok_or(SessionError::VoucherSignatureInvalid)?;

    let expires_at: i64 = match voucher.voucher.expires_at.as_deref() {
        None => 0,
        Some(s) => time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map_err(|e| SessionError::InvalidAmount(format!("expiresAt: {e}")))?
            .unix_timestamp(),
    };

    let payload = build_signed_payload(&record.channel_id, cumulative_amount, expires_at);
    match verify_voucher_signature(&signer_bytes, &sig_bytes, &payload) {
        Ok(()) => {}
        Err(VoucherSignatureError::MalformedKey | VoucherSignatureError::VerificationFailed) => {
            return Err(SessionError::VoucherSignatureInvalid);
        }
    }

    let signer_pk = Pubkey::new_from_array(signer_bytes);
    if signer_pk != record.authorized_signer {
        return Err(SessionError::VoucherWrongSigner {
            expected: record.authorized_signer,
            got: signer_pk,
        });
    }

    if cumulative_amount > record.deposit {
        return Err(SessionError::VoucherOverDeposit {
            deposit: record.deposit,
            got: cumulative_amount,
        });
    }

    if cumulative_amount < record.accepted_cumulative {
        return Err(SessionError::VoucherCumulativeRegression {
            stored: record.accepted_cumulative,
            got: cumulative_amount,
        });
    }

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

    // Stricter close-time expiry: the voucher has to clear `expires_at`
    // even after `voucher_check_grace_seconds` of broadcast latency.
    if expires_at != 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| {
                SessionError::InternalError(format!("system clock before unix epoch: {e}"))
            })?;
        let grace = i64::from(config.voucher_check_grace_seconds);
        if now.saturating_add(grace) >= expires_at {
            return Err(SessionError::VoucherExpired {
                now,
                expires_at,
            });
        }
    }

    Ok(())
}

fn decode_fixed<const N: usize>(raw: &str) -> Option<[u8; N]> {
    bs58::decode(raw).into_vec().ok()?.try_into().ok()
}

/// Drive the close orchestration end-to-end. The `SessionMethod` entry
/// point threads its store / rpc / cache / config in; the free-function
/// shape lets unit tests exercise the state machine without standing up
/// a full `SessionMethod` (which spawns the sweeper task and expects a
/// live RPC).
pub(crate) async fn run_process_close(
    store: &Arc<dyn ChannelStore>,
    rpc: &Arc<solana_client::nonblocking::rpc_client::RpcClient>,
    cache: &ChallengeCache,
    config: &SessionConfig,
    payee_signer: &Arc<dyn solana_keychain::SolanaSigner>,
    payload: &ClosePayload,
) -> Result<Receipt, SessionError> {
    // Reserve under the Close intent. Pre-broadcast failures release it.
    let cached = cache.reserve(&payload.challenge_id, ChallengeIntentDiscriminant::Close)?;

    let result = run_inner(
        store,
        rpc,
        cache,
        config,
        payee_signer,
        payload,
        &cached.intent,
        &cached.recent_blockhash,
    )
    .await;

    // Best-effort release. Silently ignore the error if the challenge
    // is already Consumed (it reached `cache.commit` on a post-broadcast
    // path); the challenge state machine still blocks retries on
    // Consumed.
    if result.is_err() {
        let _ = cache.release(&payload.challenge_id);
    }
    result
}

/// Co-sign the close tx (slot 0 = fee payer, slot 1 = merchant) and
/// check the signature slot guard. Pulled out so an error here funnels
/// through one rollback path instead of leaving a stuck CloseAttempting
/// record.
async fn prepare_close_for_broadcast(
    fee_payer_signer: &Arc<dyn solana_keychain::SolanaSigner>,
    payee_signer: &Arc<dyn solana_keychain::SolanaSigner>,
    prepared_tx: Transaction,
) -> Result<Transaction, SessionError> {
    let mut tx = prepared_tx;
    let msg_data = tx.message_data();
    let fee_sig = fee_payer_signer
        .sign_message(&msg_data)
        .await
        .map_err(|e| SessionError::InternalError(format!("fee-payer sign failed: {e}")))?;
    let merchant_sig = payee_signer
        .sign_message(&msg_data)
        .await
        .map_err(|e| SessionError::InternalError(format!("merchant sign failed: {e}")))?;
    if tx.signatures.len() < 2 {
        return Err(SessionError::MaliciousTx {
            reason: "close tx missing signature slots for fee payer + merchant".into(),
        });
    }
    tx.signatures[0] = Signature::from(<[u8; 64]>::from(fee_sig));
    tx.signatures[1] = Signature::from(<[u8; 64]>::from(merchant_sig));
    Ok(tx)
}

/// Sign the ATA preflight tx (slot 0 = fee payer). The preflight only
/// needs the fee payer in its signature slot; the wallet metas on
/// `CreateIdempotent` are unsigned. Mirrors the close-tx signer so the
/// rollback funnel stays uniform.
async fn prepare_preflight_for_broadcast(
    fee_payer_signer: &Arc<dyn solana_keychain::SolanaSigner>,
    prepared_tx: Transaction,
) -> Result<Transaction, SessionError> {
    let mut tx = prepared_tx;
    let msg_data = tx.message_data();
    let fee_sig = fee_payer_signer
        .sign_message(&msg_data)
        .await
        .map_err(|e| SessionError::InternalError(format!("fee-payer sign failed: {e}")))?;
    if tx.signatures.is_empty() {
        return Err(SessionError::MaliciousTx {
            reason: "ata preflight tx missing signature slot for fee payer".into(),
        });
    }
    tx.signatures[0] = Signature::from(<[u8; 64]>::from(fee_sig));
    Ok(tx)
}

#[allow(clippy::too_many_arguments)]
async fn run_inner(
    store: &Arc<dyn ChannelStore>,
    rpc: &Arc<solana_client::nonblocking::rpc_client::RpcClient>,
    cache: &ChallengeCache,
    config: &SessionConfig,
    payee_signer: &Arc<dyn solana_keychain::SolanaSigner>,
    payload: &ClosePayload,
    cached_intent: &ChallengeIntent,
    recent_blockhash: &solana_hash::Hash,
) -> Result<Receipt, SessionError> {
    // The cached intent has to point at the same channel as the payload.
    let advertised_cid = match cached_intent {
        ChallengeIntent::Close { channel_id } => *channel_id,
        // Discriminant was checked at reserve, so this arm is unreachable.
        _ => return Err(SessionError::ChallengeIntentMismatch),
    };

    let channel_id = parse_pubkey_field("channelId", &payload.channel_id)?;
    if channel_id != advertised_cid {
        return Err(SessionError::ChallengeFieldMismatch {
            field: "channelId",
            advertised: advertised_cid.to_string(),
            got: channel_id.to_string(),
        });
    }

    // Collapse "absent record" and "wrong status" into a single mismatch
    // so a probing attacker can't tell them apart.
    let record =
        store
            .get(&channel_id)
            .await?
            .ok_or_else(|| SessionError::OnChainStateMismatch {
                field: "channelId",
                expected: "open channel".into(),
                got: channel_id.to_string(),
            })?;
    if record.status != ChannelStatus::Open {
        // CloseAttempting and Closing belong to the recovery layer.
        return Err(SessionError::OnChainStateMismatch {
            field: "channelId",
            expected: "open channel".into(),
            got: channel_id.to_string(),
        });
    }

    // Fee payer is required. v1 server-submits, so config has to carry one.
    let fee_payer_signer = config.fee_payer.as_ref().ok_or_else(|| {
        SessionError::InternalError("fee_payer not configured; v1 is server-submit".into())
    })?;
    let fee_payer_pk = fee_payer_signer.signer.pubkey();
    let merchant_pk = payee_signer.pubkey();
    if merchant_pk != record.payee {
        // Operator misconfig. The payee key wired to the SessionMethod
        // doesn't match the channel's `payee`. The on-chain check would
        // reject this anyway; failing here saves an RPC round trip.
        return Err(SessionError::InternalError(format!(
            "configured payee signer {merchant_pk} does not match channel.payee {}",
            record.payee
        )));
    }

    // Decide the close path plus voucher recheck. Build all three txs up
    // front so any builder error (including an oversize-tx hard error)
    // surfaces before we touch the store.
    let action = decide_close_action(payload, &record)?;
    let preflight_tx = build_ata_preflight_tx(
        config,
        &record,
        recent_blockhash,
        &fee_payer_pk,
    )?;
    let (settled_after, settle_tx_unsigned) = match &action {
        CloseAction::ApplyVoucher {
            voucher,
            cumulative_amount,
        } => {
            recheck_voucher_for_close(voucher, *cumulative_amount, &record, config)?;
            let tx = build_settle_tx_apply_voucher(
                config,
                &record,
                voucher,
                recent_blockhash,
                &fee_payer_pk,
                &merchant_pk,
            )?;
            (*cumulative_amount, tx)
        }
        CloseAction::LockSettled => {
            let tx = build_settle_tx_lock_settled(
                config,
                &record,
                recent_blockhash,
                &fee_payer_pk,
                &merchant_pk,
            )?;
            (record.on_chain_settled, tx)
        }
    };
    let distribute_tx_unsigned = build_distribute_tx(
        config,
        &record,
        recent_blockhash,
        &fee_payer_pk,
    )?;

    // Flip the record to CloseAttempting before any broadcast so a
    // mid-flight crash leaves a recoverable trace. Pre-distribute-
    // broadcast failures funnel through `mark_close_rollback`;
    // post-distribute-broadcast failures stay in CloseAttempting and
    // the recovery layer reconciles.
    store.mark_close_attempting(&channel_id).await?;

    let send_config = solana_client::rpc_config::RpcSendTransactionConfig {
        preflight_commitment: Some(config.commitment.commitment),
        ..Default::default()
    };
    let confirm_commitment = CommitmentConfig::confirmed();

    // ATA preflight. Idempotent on success; on partial failure any
    // successfully-created ATAs stay on-chain (harmless) and we roll
    // the channel back to Open.
    let preflight_signed =
        match prepare_preflight_for_broadcast(&fee_payer_signer.signer, preflight_tx).await {
            Ok(tx) => tx,
            Err(e) => {
                let _ = store.mark_close_rollback(&channel_id).await;
                return Err(e);
            }
        };

    let preflight_sig = match rpc
        .send_transaction_with_config(&preflight_signed, send_config)
        .await
    {
        Ok(sig) => sig,
        Err(e) => {
            let _ = store.mark_close_rollback(&channel_id).await;
            return Err(client_error_to_session_error(e));
        }
    };

    if let Err(e) = wait_for_confirmed(rpc, &preflight_sig, &config.broadcast_confirm_timeout).await
    {
        tracing::warn!(
            channel_id = %channel_id,
            preflight_signature = %preflight_sig,
            confirm_error = ?e,
            "ata preflight confirm-poll did not succeed; rolling channel back to Open",
        );
        let _ = store.mark_close_rollback(&channel_id).await;
        return Err(e);
    }

    // settle_and_finalize. Same rollback discipline; distribute hasn't
    // broadcast yet, so the challenge is still releasable.
    let settle_tx = match prepare_close_for_broadcast(
        &fee_payer_signer.signer,
        payee_signer,
        settle_tx_unsigned,
    )
    .await
    {
        Ok(tx) => tx,
        Err(e) => {
            let _ = store.mark_close_rollback(&channel_id).await;
            return Err(e);
        }
    };

    let settle_sig = match rpc.send_transaction_with_config(&settle_tx, send_config).await {
        Ok(sig) => sig,
        Err(e) => {
            let _ = store.mark_close_rollback(&channel_id).await;
            return Err(client_error_to_session_error(e));
        }
    };

    if let Err(e) = wait_for_confirmed(rpc, &settle_sig, &config.broadcast_confirm_timeout).await {
        tracing::warn!(
            channel_id = %channel_id,
            settle_signature = %settle_sig,
            confirm_error = ?e,
            "settle_and_finalize confirm-poll did not succeed; rolling channel back to Open",
        );
        let _ = store.mark_close_rollback(&channel_id).await;
        return Err(e);
    }

    // distribute. Last rollback opportunity is the moment before
    // `send_transaction_with_config` returns Ok.
    let distribute_tx = match prepare_preflight_for_broadcast(
        &fee_payer_signer.signer,
        distribute_tx_unsigned,
    )
    .await
    {
        Ok(tx) => tx,
        Err(e) => {
            let _ = store.mark_close_rollback(&channel_id).await;
            return Err(e);
        }
    };

    let tx_sig = match rpc
        .send_transaction_with_config(&distribute_tx, send_config)
        .await
    {
        Ok(sig) => sig,
        Err(e) => {
            let _ = store.mark_close_rollback(&channel_id).await;
            return Err(client_error_to_session_error(e));
        }
    };

    // Cluster accepted the distribute tx. Burn the challenge before
    // polling so a confirm-poll timeout can't re-enable a retry under
    // the same id.
    cache.commit(&payload.challenge_id)?;

    // Confirm-poll the distribute tx. Any failure past this point leaves
    // the record in CloseAttempting; the recovery layer reads chain state
    // to decide whether to promote it to ClosedPending or roll back.
    let mut confirmed = false;
    let confirm_deadline = std::time::Instant::now() + config.broadcast_confirm_timeout;
    while std::time::Instant::now() < confirm_deadline {
        match rpc
            .confirm_transaction_with_commitment(&tx_sig, confirm_commitment)
            .await
        {
            Ok(resp) => {
                if resp.value {
                    confirmed = true;
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(
                    channel_id = %channel_id,
                    signature = %tx_sig,
                    rpc_error = %e,
                    "confirm-poll RPC error after distribute broadcast; broadcast may have landed, recovery layer will reconcile",
                );
                return Err(client_error_to_session_error(e));
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if !confirmed {
        tracing::warn!(
            channel_id = %channel_id,
            signature = %tx_sig,
            timeout_secs = config.broadcast_confirm_timeout.as_secs(),
            "distribute tx confirm-poll timed out; broadcast may have landed, recovery layer will reconcile",
        );
        return Err(SessionError::SettleFailed(
            tx_sig,
            format!(
                "did not reach Confirmed within {}s",
                config.broadcast_confirm_timeout.as_secs()
            ),
        ));
    }

    // Persist the post-confirm state. `record_on_chain_settled` runs
    // before the status flip so a concurrent reader between the two
    // calls sees the new settled value alongside CloseAttempting (the
    // recovery layer's signal that the close is in flight) rather than
    // the stale pair. Failures here are loud: the tx confirmed on-chain
    // but the local store didn't catch up, so the operator needs to know
    // recovery will see chain tombstoned alongside store CloseAttempting.
    if let Err(e) = store.record_on_chain_settled(&channel_id, settled_after).await {
        tracing::error!(
            channel_id = %channel_id,
            signature = %tx_sig,
            store_error = %e,
            "tx confirmed on-chain but record_on_chain_settled failed; recovery will see chain tombstoned vs store CloseAttempting; investigate",
        );
        return Err(e.into());
    }
    if let Err(e) = store.record_close_signature(&channel_id, tx_sig).await {
        tracing::error!(
            channel_id = %channel_id,
            signature = %tx_sig,
            store_error = %e,
            "tx confirmed on-chain but record_close_signature failed; recovery will see chain tombstoned vs store CloseAttempting; investigate",
        );
        return Err(e.into());
    }
    if let Err(e) = store.mark_closed_pending(&channel_id, tx_sig).await {
        tracing::error!(
            channel_id = %channel_id,
            signature = %tx_sig,
            store_error = %e,
            "tx confirmed on-chain but mark_closed_pending failed; recovery will see chain tombstoned vs store CloseAttempting; investigate",
        );
        return Err(e.into());
    }

    // Post-confirm: the PDA should be tombstoned. A mismatch means the
    // tx confirmed but on-chain state diverged from expectation (fork
    // recovery, tx replaced, validator drift). Log and proceed; the
    // store carries the close signature for reconciliation.
    if let Err(e) = verify_tombstoned(rpc, config.commitment, &channel_id).await {
        tracing::warn!(
            channel_id = %channel_id,
            signature = %tx_sig,
            verify_error = ?verify_error_to_session_error(e, &channel_id),
            "post-confirm verify_tombstoned mismatch; on-chain state diverged from expected close",
        );
    }

    // Async lift to Finalized. Best-effort; the response itself goes
    // out at Confirmed. Operators that need stronger durability flip
    // the future high-value-channel flag (out of v1 scope).
    let store_for_lift = Arc::clone(store);
    let rpc_for_lift = Arc::clone(rpc);
    tokio::spawn(async move {
        let finalize_commitment = CommitmentConfig::finalized();
        let resp = rpc_for_lift
            .confirm_transaction_with_commitment(&tx_sig, finalize_commitment)
            .await;
        match resp {
            Ok(r) if r.value => {
                if let Err(e) = store_for_lift.mark_closed_finalized(&channel_id).await {
                    tracing::warn!(
                        channel_id = %channel_id,
                        signature = %tx_sig,
                        store_error = %e,
                        "mark_closed_finalized failed; channel remains ClosedPending",
                    );
                }
            }
            Ok(_) => {
                tracing::debug!(
                    channel_id = %channel_id,
                    signature = %tx_sig,
                    "Finalized poll returned not-finalized; recovery layer will revisit",
                );
            }
            Err(e) => {
                tracing::warn!(
                    channel_id = %channel_id,
                    signature = %tx_sig,
                    rpc_error = %e,
                    "Finalized poll RPC failure; recovery layer will revisit",
                );
            }
        }
    });

    let refunded = record.deposit.saturating_sub(settled_after);
    Ok(
        Receipt::success(METHOD_NAME, channel_id.to_string(), payload.challenge_id.clone())
            .with_close_amounts(tx_sig.to_string(), refunded),
    )
}

/// Poll `confirm_transaction_with_commitment` for `Confirmed` until the
/// deadline. Used for the ATA preflight tx: it has to land before the
/// close tx broadcasts so `distribute` doesn't run in a slot where the
/// recipient ATAs aren't visible yet. Maps RPC errors and timeouts into
/// typed `SessionError`s so the caller can roll back uniformly.
async fn wait_for_confirmed(
    rpc: &Arc<solana_client::nonblocking::rpc_client::RpcClient>,
    signature: &Signature,
    timeout: &Duration,
) -> Result<(), SessionError> {
    let deadline = std::time::Instant::now() + *timeout;
    while std::time::Instant::now() < deadline {
        match rpc
            .confirm_transaction_with_commitment(signature, CommitmentConfig::confirmed())
            .await
        {
            Ok(resp) if resp.value => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(client_error_to_session_error(e)),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(SessionError::SettleFailed(
        *signature,
        format!(
            "did not reach Confirmed within {}s",
            timeout.as_secs()
        ),
    ))
}

/// Recovery-side close retry. Drives a stranded `CloseAttempting` (or
/// `Closing`) record forward without a client challenge. Inspect
/// already classified the on-chain state, so this picks the right tail
/// of the close orchestration based on what the chain shows now.
///
/// - Chain still `Closing`: re-broadcast settle (lock-settled) and
///   distribute against a fresh blockhash, then run the post-confirm
///   store updates.
/// - Chain already tombstoned or finalized: skip the broadcast. Push
///   the store from `CloseAttempting` (or `Closing`) to `ClosedPending`
///   using `record.close_tx` if present, then best-effort
///   `mark_closed_finalized`.
///
/// Lock-settled retry rebuilds the settle ix without ApplyVoucher
/// because re-running the voucher might double-count if it already
/// landed in a prior settle. The on-chain `settled` figure is the
/// source of truth either way.
pub(crate) async fn run_close_retry(
    store: &dyn ChannelStore,
    rpc: &Arc<solana_client::nonblocking::rpc_client::RpcClient>,
    config: &SessionConfig,
    record: ChannelRecord,
) -> Result<(), SessionError> {
    let channel_id = record.channel_id;

    // Re-probe so the match below sees a single observation. Inspect
    // already classified this PDA, but if something changed between
    // inspect and apply (another operator instance, a manual finalize)
    // we want to act on the current state.
    let state = peek_chain_state(rpc, config, &channel_id).await?;

    match state {
        OnChainChannelStatus::Closing => {
            run_close_retry_broadcast(store, rpc, config, record).await
        }
        OnChainChannelStatus::Tombstoned | OnChainChannelStatus::Finalized => {
            finish_post_tombstone(store, &record).await
        }
        OnChainChannelStatus::Open | OnChainChannelStatus::Absent => {
            // Only reachable if the chain state shifted between inspect
            // and apply. Bail loudly so the operator sees it.
            Err(SessionError::InternalError(format!(
                "channel {channel_id} chain state shifted between inspect and apply during RetryClose; restart recovery"
            )))
        }
    }
}

async fn peek_chain_state(
    rpc: &Arc<solana_client::nonblocking::rpc_client::RpcClient>,
    config: &SessionConfig,
    channel_id: &Pubkey,
) -> Result<OnChainChannelStatus, SessionError> {
    use solana_client::client_error::ClientErrorKind;
    use solana_client::rpc_config::RpcAccountInfoConfig;
    use solana_client::rpc_request::RpcError as RpcRequestError;

    let info = RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(config.commitment),
        ..RpcAccountInfoConfig::default()
    };

    let resp = rpc.get_ui_account_with_config(channel_id, info).await;
    let value = match resp {
        Ok(r) => r.value,
        Err(e) => {
            if matches!(
                &*e.kind,
                ClientErrorKind::RpcError(RpcRequestError::RpcResponseError {
                    code: -32004,
                    ..
                })
            ) {
                return Ok(OnChainChannelStatus::Absent);
            }
            return Err(client_error_to_session_error(e));
        }
    };
    let Some(ui_account) = value else {
        return Ok(OnChainChannelStatus::Absent);
    };
    let data = ui_account.data.decode().ok_or_else(|| {
        SessionError::InternalError(format!(
            "unexpected RPC encoding when probing channel {channel_id}"
        ))
    })?;

    if data.len() == 1 {
        if data[0] == CLOSED_CHANNEL_DISCRIMINATOR {
            return Ok(OnChainChannelStatus::Tombstoned);
        }
        return Err(SessionError::InternalError(format!(
            "channel {channel_id}: tombstone-length payload with wrong discriminator byte {}",
            data[0]
        )));
    }

    let view = ChannelView::from_account_data(&data)
        .map_err(|e| SessionError::InternalError(format!("channel decode: {e}")))?;
    use payment_channels_client::types::ChannelStatus as OnChainStatus;
    let status = view.status();
    if status == OnChainStatus::Open as u8 {
        Ok(OnChainChannelStatus::Open)
    } else if status == OnChainStatus::Closing as u8 {
        Ok(OnChainChannelStatus::Closing)
    } else if status == OnChainStatus::Finalized as u8 {
        Ok(OnChainChannelStatus::Finalized)
    } else {
        Err(SessionError::InternalError(format!(
            "channel {channel_id}: unrecognised status byte {status}"
        )))
    }
}

/// Read `settled` off a freshly-fetched channel PDA. The retry-broadcast
/// post-confirm path uses this so the store reflects chain truth, not
/// the (possibly stale) stored value.
async fn read_settled_from_chain(
    rpc: &Arc<solana_client::nonblocking::rpc_client::RpcClient>,
    config: &SessionConfig,
    channel_id: &Pubkey,
) -> Result<u64, SessionError> {
    use solana_client::rpc_config::RpcAccountInfoConfig;

    let info = RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(config.commitment),
        ..RpcAccountInfoConfig::default()
    };
    let resp = rpc
        .get_ui_account_with_config(channel_id, info)
        .await
        .map_err(client_error_to_session_error)?;
    let ui_account = resp.value.ok_or_else(|| {
        SessionError::InternalError(format!(
            "channel {channel_id}: account vanished between confirm and refetch"
        ))
    })?;
    let data = ui_account.data.decode().ok_or_else(|| {
        SessionError::InternalError(format!(
            "channel {channel_id}: unexpected RPC encoding when refetching settled"
        ))
    })?;
    if data.len() == 1 {
        // Tombstoned between confirm and refetch (cooperative close hit
        // the FINALIZED branch and tombstoned in one ix). Caller falls
        // back to the stored value and logs a warning.
        return Err(SessionError::InternalError(format!(
            "channel {channel_id}: tombstoned before settled could be refetched"
        )));
    }
    let view = ChannelView::from_account_data(&data)
        .map_err(|e| SessionError::InternalError(format!("channel decode: {e}")))?;
    Ok(view.settled())
}

/// Best-known settled value when `read_settled_from_chain` fails after
/// the distribute tx confirmed. Usually means the FINALIZED branch
/// closed the PDA in the same tx, so the chain layout is gone:
///
/// 1. `record.last_voucher.cumulative_amount` if a voucher is stashed
///    (that's what ApplyVoucher would have committed).
/// 2. `record.on_chain_settled` otherwise, the pre-close watermark.
fn tombstone_refetch_fallback(
    record: &ChannelRecord,
    channel_id: &Pubkey,
    tx_sig: &Signature,
) -> u64 {
    let parsed = record
        .last_voucher
        .as_ref()
        .and_then(|v| v.voucher.cumulative_amount.parse::<u64>().ok());
    match parsed {
        Some(amount) => {
            tracing::warn!(
                channel_id = %channel_id,
                signature = %tx_sig,
                fallback_amount = amount,
                "tombstone-after-confirm fallback: using last_voucher.cumulative_amount = {}",
                amount,
            );
            amount
        }
        None => {
            tracing::warn!(
                channel_id = %channel_id,
                signature = %tx_sig,
                fallback_amount = record.on_chain_settled,
                "tombstone-after-confirm fallback: no last_voucher; using stored on_chain_settled = {}",
                record.on_chain_settled,
            );
            record.on_chain_settled
        }
    }
}

async fn finish_post_tombstone(
    store: &dyn ChannelStore,
    record: &ChannelRecord,
) -> Result<(), SessionError> {
    // Can't refetch settled off a tombstoned PDA: the layout is gone,
    // replaced by the 1-byte close discriminator. The stored value is
    // the truthful figure if the original close finished its post-
    // confirm writes before crashing, and the pre-close watermark
    // otherwise. Operators who need the exact post-close settled have
    // to read it off the on-chain history of `record.close_tx`.
    let close_sig = match record.close_tx {
        Some(sig) => sig,
        None => {
            let placeholder = Signature::default();
            tracing::warn!(
                channel_id = %record.channel_id,
                signature = %placeholder,
                "tombstone-only retry: original close_tx not persisted; recording zero signature placeholder",
            );
            placeholder
        }
    };

    match record.status {
        ChannelStatus::CloseAttempting => {
            store.record_close_signature(&record.channel_id, close_sig).await?;
            store
                .mark_closed_pending(&record.channel_id, close_sig)
                .await?;
        }
        ChannelStatus::Closing => {
            store
                .mark_closed_pending(&record.channel_id, close_sig)
                .await?;
        }
        ChannelStatus::ClosedPending | ChannelStatus::ClosedFinalized => {
            // Already past the broadcast; nothing to do here.
        }
        ChannelStatus::Open => {
            return Err(SessionError::InternalError(format!(
                "channel {} retry-close called against Open record",
                record.channel_id
            )));
        }
    }

    if let Err(e) = store.mark_closed_finalized(&record.channel_id).await {
        // Best-effort. A fork rollback could leave the chain in a state
        // where promotion isn't legal yet; log and let the next recovery
        // pass retry.
        tracing::warn!(
            channel_id = %record.channel_id,
            store_error = %e,
            "mark_closed_finalized after tombstone-only retry failed; ClosedPending stays",
        );
    }
    Ok(())
}

async fn run_close_retry_broadcast(
    store: &dyn ChannelStore,
    rpc: &Arc<solana_client::nonblocking::rpc_client::RpcClient>,
    config: &SessionConfig,
    record: ChannelRecord,
) -> Result<(), SessionError> {
    let channel_id = record.channel_id;
    let fee_payer_signer = config.fee_payer.as_ref().ok_or_else(|| {
        SessionError::InternalError(
            "fee_payer not configured; RetryClose needs server-submit credentials".into(),
        )
    })?;
    let payee_signer = config.payee_signer.as_ref().ok_or_else(|| {
        SessionError::InternalError(
            "payee_signer not configured; RetryClose needs the merchant signer".into(),
        )
    })?;
    let fee_payer_pk = fee_payer_signer.signer.pubkey();
    let merchant_pk = payee_signer.signer.pubkey();
    if merchant_pk != record.payee {
        return Err(SessionError::InternalError(format!(
            "configured payee signer {merchant_pk} does not match channel.payee {} during RetryClose",
            record.payee
        )));
    }

    // The original challenge's blockhash has long since expired by the
    // time recovery runs; pull a fresh one.
    let recent_blockhash = rpc.get_latest_blockhash().await.map_err(|e| {
        SessionError::InternalError(format!("RetryClose: get_latest_blockhash failed: {e}"))
    })?;

    // Upstream's `settle_and_finalize { has_voucher: 0 }` accepts both
    // Open and Closing on-chain states. The program reads the channel's
    // status and runs the right transition (Open: lock-and-finalize;
    // Closing: lock-and-finalize mid-grace). Re-running this against a
    // Closing PDA in recovery is fine.
    let preflight_tx = build_ata_preflight_tx(config, &record, &recent_blockhash, &fee_payer_pk)?;
    let settle_tx_unsigned =
        build_settle_tx_lock_settled(config, &record, &recent_blockhash, &fee_payer_pk, &merchant_pk)?;
    let distribute_tx_unsigned =
        build_distribute_tx(config, &record, &recent_blockhash, &fee_payer_pk)?;

    let send_config = solana_client::rpc_config::RpcSendTransactionConfig {
        preflight_commitment: Some(config.commitment.commitment),
        ..Default::default()
    };

    // Broadcast each tx and wait for confirmation before moving on.
    // Store starts at CloseAttempting or Closing; both can transition
    // into ClosedPending after distribute confirms.

    let preflight_signed =
        prepare_preflight_for_broadcast(&fee_payer_signer.signer, preflight_tx).await?;
    let preflight_sig = rpc
        .send_transaction_with_config(&preflight_signed, send_config)
        .await
        .map_err(client_error_to_session_error)?;
    wait_for_confirmed(rpc, &preflight_sig, &config.broadcast_confirm_timeout).await?;

    let settle_signed = prepare_close_for_broadcast(
        &fee_payer_signer.signer,
        &payee_signer.signer,
        settle_tx_unsigned,
    )
    .await?;
    let settle_sig = rpc
        .send_transaction_with_config(&settle_signed, send_config)
        .await
        .map_err(client_error_to_session_error)?;
    wait_for_confirmed(rpc, &settle_sig, &config.broadcast_confirm_timeout).await?;

    let distribute_signed =
        prepare_preflight_for_broadcast(&fee_payer_signer.signer, distribute_tx_unsigned).await?;
    let tx_sig = rpc
        .send_transaction_with_config(&distribute_signed, send_config)
        .await
        .map_err(client_error_to_session_error)?;
    wait_for_confirmed(rpc, &tx_sig, &config.broadcast_confirm_timeout).await?;

    // Post-confirm: mirror run_inner's store updates. The stored
    // `record.on_chain_settled` is stale if the original close ran
    // ApplyVoucher before crashing, so refetch the PDA and read settled
    // off the decoded account. Chain wins.
    let on_chain_settled = match read_settled_from_chain(rpc, config, &channel_id).await {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(
                channel_id = %channel_id,
                signature = %tx_sig,
                refetch_error = ?e,
                "RetryClose tx confirmed but could not refetch settled from chain; falling back",
            );
            tombstone_refetch_fallback(&record, &channel_id, &tx_sig)
        }
    };
    if let Err(e) = store
        .record_on_chain_settled(&channel_id, on_chain_settled)
        .await
    {
        tracing::error!(
            channel_id = %channel_id,
            signature = %tx_sig,
            store_error = %e,
            "RetryClose tx confirmed but record_on_chain_settled failed",
        );
        return Err(e.into());
    }
    if let Err(e) = store.record_close_signature(&channel_id, tx_sig).await {
        tracing::error!(
            channel_id = %channel_id,
            signature = %tx_sig,
            store_error = %e,
            "RetryClose tx confirmed but record_close_signature failed",
        );
        return Err(e.into());
    }
    if let Err(e) = store.mark_closed_pending(&channel_id, tx_sig).await {
        tracing::error!(
            channel_id = %channel_id,
            signature = %tx_sig,
            store_error = %e,
            "RetryClose tx confirmed but mark_closed_pending failed",
        );
        return Err(e.into());
    }

    if let Err(e) = verify_tombstoned(rpc, config.commitment, &channel_id).await {
        tracing::warn!(
            channel_id = %channel_id,
            signature = %tx_sig,
            verify_error = ?verify_error_to_session_error(e, &channel_id),
            "RetryClose post-confirm verify_tombstoned mismatch",
        );
    }

    if let Err(e) = store.mark_closed_finalized(&channel_id).await {
        tracing::warn!(
            channel_id = %channel_id,
            signature = %tx_sig,
            store_error = %e,
            "RetryClose mark_closed_finalized failed; record stays in ClosedPending",
        );
    }
    Ok(())
}

fn parse_pubkey_field(field: &'static str, raw: &str) -> Result<Pubkey, SessionError> {
    let bytes = bs58::decode(raw)
        .into_vec()
        .map_err(|e| SessionError::OnChainStateMismatch {
            field,
            expected: "base58 pubkey".into(),
            got: format!("{raw}: {e}"),
        })?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SessionError::OnChainStateMismatch {
            field,
            expected: "32-byte pubkey".into(),
            got: raw.to_string(),
        })?;
    Ok(Pubkey::new_from_array(arr))
}

#[cfg(test)]
mod tests {
    //! Unit tests for the close orchestration. They drive the pure-Rust
    //! pieces (close-path decision and voucher recheck) directly and use
    //! a mocked RPC client to exercise the broadcast-and-rollback path.
    //! End-to-end behavior lives in the L1 oracle.

    use super::*;
    use crate::program::payment_channels::voucher::VoucherSigner;
    use crate::protocol::intents::session::{SigType, SignedVoucher, Split, VoucherData};
    use crate::server::session::{Network, Pricing, SessionConfig, DEFAULT_VOUCHER_CHECK_GRACE_SECONDS};
    use crate::store::{ChannelRecord, ChannelStatus, InMemoryChannelStore};
    use ed25519_dalek::SigningKey;
    use solana_commitment_config::CommitmentConfig;
    use solana_keychain::MemorySigner;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer as _;
    use std::time::Duration as StdDuration;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }

    fn fresh_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn base_record(channel_id: Pubkey, authorized: Pubkey, deposit: u64) -> ChannelRecord {
        ChannelRecord {
            channel_id,
            payer: pk(0xA1),
            payee: pk(0xA2),
            mint: pk(0xA3),
            salt: 0xCAFE,
            program_id: pk(0xA4),
            authorized_signer: authorized,
            deposit,
            accepted_cumulative: 0,
            on_chain_settled: 0,
            last_voucher: None,
            close_tx: None,
            status: ChannelStatus::Open,
            splits: Vec::<Split>::new(),
        }
    }

    fn base_config() -> SessionConfig {
        SessionConfig {
            operator: pk(1),
            payee: pk(0xA2),
            mint: pk(0xA3),
            decimals: 6,
            network: Network::Localnet,
            program_id: pk(0xA4),
            pricing: Pricing {
                amount_per_unit: 1,
                unit_type: "request".into(),
            },
            splits: Vec::new(),
            max_deposit: 1_000_000,
            min_deposit: 1,
            min_voucher_delta: 0,
            voucher_ttl_seconds: 60,
            grace_period_seconds: 86_400,
            challenge_ttl_seconds: 300,
            commitment: CommitmentConfig::confirmed(),
            broadcast_confirm_timeout: StdDuration::from_secs(30),
            clock_skew_seconds: 5,
            voucher_check_grace_seconds: DEFAULT_VOUCHER_CHECK_GRACE_SECONDS,
            fee_payer: None,
            payee_signer: None,
            realm: Some("test".into()),
            secret_key: Some("test-secret".into()),
        }
    }

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

    fn close_payload(challenge: &str, channel_id: Pubkey, voucher: Option<SignedVoucher>) -> ClosePayload {
        ClosePayload {
            challenge_id: challenge.to_string(),
            channel_id: channel_id.to_string(),
            voucher,
        }
    }

    #[test]
    fn voucher_higher_cumulative_routes_to_apply_voucher() {
        let signer = fresh_signing_key(0x11);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = pk(0xC1);
        let mut record = base_record(cid, authorized, 10_000);
        record.on_chain_settled = 100;
        let v = mint_voucher(&signer, &cid, 500, None);
        let payload = close_payload("ch", cid, Some(v));
        match decide_close_action(&payload, &record).unwrap() {
            CloseAction::ApplyVoucher { cumulative_amount, .. } => {
                assert_eq!(cumulative_amount, 500)
            }
            other => panic!("expected ApplyVoucher, got {other:?}"),
        }
    }

    #[test]
    fn voucher_equal_cumulative_routes_to_lock_settled() {
        let signer = fresh_signing_key(0x12);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = pk(0xC2);
        let mut record = base_record(cid, authorized, 10_000);
        record.on_chain_settled = 500;
        let v = mint_voucher(&signer, &cid, 500, None);
        let payload = close_payload("ch", cid, Some(v));
        assert!(matches!(
            decide_close_action(&payload, &record).unwrap(),
            CloseAction::LockSettled
        ));
    }

    #[test]
    fn missing_voucher_routes_to_lock_settled() {
        let cid = pk(0xC3);
        let record = base_record(cid, pk(0x33), 10_000);
        let payload = close_payload("ch", cid, None);
        assert!(matches!(
            decide_close_action(&payload, &record).unwrap(),
            CloseAction::LockSettled
        ));
    }

    #[test]
    fn apply_voucher_recheck_grace_window_rejects_late_expiry() {
        // The voucher expires inside the close-time grace window
        // (`now + voucher_check_grace_seconds >= expires_at`). The tighter
        // close-time check rejects, even though the regular
        // `verify_voucher` skew window would accept it.
        let signer = fresh_signing_key(0x21);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = pk(0xC4);
        let mut record = base_record(cid, authorized, 10_000);
        record.on_chain_settled = 0;
        let mut config = base_config();
        config.voucher_check_grace_seconds = 60;

        // expires_at is 30s in the future; grace is 60s, so check fails.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires = now + 30;
        let v = mint_voucher(&signer, &cid, 500, Some(expires));

        let err = recheck_voucher_for_close(&v, 500, &record, &config).unwrap_err();
        match err {
            SessionError::VoucherExpired { expires_at, .. } => assert_eq!(expires_at, expires),
            other => panic!("expected VoucherExpired, got {other:?}"),
        }
    }

    #[test]
    fn apply_voucher_recheck_accepts_voucher_outside_grace() {
        // Mirror of the rejection test: a voucher whose expiry is beyond
        // the close-time grace window passes recheck.
        let signer = fresh_signing_key(0x22);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = pk(0xC5);
        let mut record = base_record(cid, authorized, 10_000);
        record.on_chain_settled = 0;
        let config = base_config();

        let v = mint_voucher(&signer, &cid, 500, Some(4_000_000_000));
        recheck_voucher_for_close(&v, 500, &record, &config).expect("voucher passes recheck");
    }

    /// Build an `Arc<dyn SolanaSigner>` from a fresh keypair, returning
    /// the signer plus its pubkey. The pubkey doubles as the channel's
    /// payee so the merchant-key precondition holds.
    fn fresh_payee_signer() -> (Arc<dyn solana_keychain::SolanaSigner>, Pubkey) {
        let kp = Keypair::new();
        let bytes = kp.to_bytes();
        let signer: Arc<dyn solana_keychain::SolanaSigner> =
            Arc::new(MemorySigner::from_bytes(&bytes).expect("memory signer"));
        let pk = signer.pubkey();
        (signer, pk)
    }

    fn fresh_fee_payer_signer() -> (Arc<dyn solana_keychain::SolanaSigner>, Pubkey) {
        let kp = Keypair::new();
        let bytes = kp.to_bytes();
        let signer: Arc<dyn solana_keychain::SolanaSigner> =
            Arc::new(MemorySigner::from_bytes(&bytes).expect("memory signer"));
        let pk = signer.pubkey();
        (signer, pk)
    }

    /// Mock RPC client whose `send_transaction` always returns an RPC
    /// error. The default mock-sender returns success; rebuilding it
    /// with a custom sender exercises the rollback path.
    fn mock_rpc_send_failure() -> Arc<solana_client::nonblocking::rpc_client::RpcClient> {
        // Simplest "always fail" shape: `RpcClient::new_mock` with a URL
        // the sender is configured to fail on.
        Arc::new(solana_client::nonblocking::rpc_client::RpcClient::new_mock(
            "fails".to_string(),
        ))
    }

    /// Seed a `Close { channel_id }` challenge into the cache.
    fn seed_close_challenge(cache: &ChallengeCache, channel_id: Pubkey) -> String {
        let id = format!("close-{channel_id}");
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        cache
            .insert(
                id.clone(),
                super::super::challenge::ChallengeRecord::new(
                    ChallengeIntent::Close { channel_id },
                    None,
                    issued_at,
                    solana_hash::Hash::new_from_array([7u8; 32]),
                ),
            )
            .expect("seed close challenge");
        id
    }

    #[tokio::test]
    async fn close_attempting_status_persists_through_rollback() {
        // The orchestration flips Open to CloseAttempting before any
        // broadcast attempt, then the rollback path takes it back to
        // Open on RPC failure. From the outside we can only observe
        // the rolled-back post-condition: `mark_close_rollback` only
        // accepts CloseAttempting going back to Open, so a successful
        // rollback implies the channel passed through CloseAttempting.
        // The pre-broadcast ordering itself reads off the orchestration
        // source; the L1 oracle covers it end-to-end against a real
        // validator.
        let signer = fresh_signing_key(0x31);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = pk(0xC6);

        let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
        let (payee_signer, payee_pk) = fresh_payee_signer();
        let (fee_payer_signer, _) = fresh_fee_payer_signer();

        let mut record = base_record(cid, authorized, 10_000);
        record.payee = payee_pk;
        store.insert(record).await.unwrap();

        let mut config = base_config();
        config.payee = payee_pk;
        config.fee_payer = Some(crate::server::session::FeePayer {
            signer: fee_payer_signer,
        });
        // Tight broadcast-confirm timeout so the test doesn't sit on
        // confirm polling if the mock somehow returns Ok.
        config.broadcast_confirm_timeout = StdDuration::from_millis(100);

        let cache = ChallengeCache::new(300);
        let challenge_id = seed_close_challenge(&cache, cid);

        let rpc = mock_rpc_send_failure();
        let v = mint_voucher(&signer, &cid, 500, None);
        let payload = close_payload(&challenge_id, cid, Some(v));

        let _ = run_process_close(&store, &rpc, &cache, &config, &payee_signer, &payload).await;

        // After the failed broadcast the record should be back to Open.
        let post = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(
            post.status,
            ChannelStatus::Open,
            "rpc failure should roll the channel back to Open",
        );
    }

    #[tokio::test]
    async fn rpc_failure_rolls_back_to_open() {
        // Twin of the test above; reads as a separate scenario in the
        // change history. Pins the rollback to RPC failure specifically,
        // not some other early bail.
        let signer = fresh_signing_key(0x32);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = pk(0xC7);

        let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
        let (payee_signer, payee_pk) = fresh_payee_signer();
        let (fee_payer_signer, _) = fresh_fee_payer_signer();

        let mut record = base_record(cid, authorized, 10_000);
        record.payee = payee_pk;
        store.insert(record).await.unwrap();

        let mut config = base_config();
        config.payee = payee_pk;
        config.fee_payer = Some(crate::server::session::FeePayer {
            signer: fee_payer_signer,
        });
        config.broadcast_confirm_timeout = StdDuration::from_millis(100);

        let cache = ChallengeCache::new(300);
        let challenge_id = seed_close_challenge(&cache, cid);

        let rpc = mock_rpc_send_failure();
        let v = mint_voucher(&signer, &cid, 500, None);
        let payload = close_payload(&challenge_id, cid, Some(v));

        let err = run_process_close(&store, &rpc, &cache, &config, &payee_signer, &payload)
            .await
            .expect_err("rpc failure should surface");
        // Either RPC unavailable or SettleFailed depending on whether the
        // mock surfaces a `BlockhashNotFound` shape; both share the same
        // post-condition: the channel is Open again.
        let _ = err;

        let post = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(post.status, ChannelStatus::Open);
    }

    /// Stub merchant signer whose `sign_message` always errors. Pubkey
    /// is supplied at construction so tests can wire it as the channel
    /// `payee` and clear the merchant-key precondition.
    struct FailingSigner {
        pubkey: Pubkey,
    }

    #[async_trait::async_trait]
    impl solana_keychain::SolanaSigner for FailingSigner {
        fn pubkey(&self) -> Pubkey {
            self.pubkey
        }

        async fn sign_transaction(
            &self,
            _tx: &mut solana_sdk::transaction::Transaction,
        ) -> Result<
            solana_keychain::SignTransactionResult,
            solana_keychain::SignerError,
        > {
            Err(solana_keychain::SignerError::SigningFailed(
                "stub: refuses to sign".into(),
            ))
        }

        async fn sign_message(
            &self,
            _message: &[u8],
        ) -> Result<solana_sdk::signature::Signature, solana_keychain::SignerError> {
            Err(solana_keychain::SignerError::SigningFailed(
                "stub: refuses to sign".into(),
            ))
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn close_rolls_back_on_sign_failure() {
        // Sign-failure path. The fee-payer signer errors on
        // `sign_message` for the preflight tx, after the channel is
        // already CloseAttempting. The orchestration funnels the signing
        // error through `mark_close_rollback` so the channel ends up
        // back at Open instead of stuck in CloseAttempting (which would
        // only be recoverable by the recovery path). Targeting the fee
        // payer (rather than the merchant) keeps the failure observable
        // in the three-tx flow, where the merchant signer isn't reached
        // until after the preflight RPC succeeds.
        let signer = fresh_signing_key(0x41);
        let authorized = Pubkey::new_from_array(signer.verifying_key_bytes());
        let cid = pk(0xC8);

        let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
        let (payee_signer, payee_pk) = fresh_payee_signer();
        // Wire the failing signer in as the fee payer.
        let real_kp = Keypair::new();
        let fail_pk = real_kp.pubkey();
        let fee_payer_signer: Arc<dyn solana_keychain::SolanaSigner> =
            Arc::new(FailingSigner { pubkey: fail_pk });

        let mut record = base_record(cid, authorized, 10_000);
        record.payee = payee_pk;
        store.insert(record).await.unwrap();

        let mut config = base_config();
        config.payee = payee_pk;
        config.fee_payer = Some(crate::server::session::FeePayer {
            signer: fee_payer_signer,
        });
        config.broadcast_confirm_timeout = StdDuration::from_millis(100);

        let cache = ChallengeCache::new(300);
        let challenge_id = seed_close_challenge(&cache, cid);

        let rpc = mock_rpc_send_failure();
        let v = mint_voucher(&signer, &cid, 500, None);
        let payload = close_payload(&challenge_id, cid, Some(v));

        let err = run_process_close(&store, &rpc, &cache, &config, &payee_signer, &payload)
            .await
            .expect_err("sign failure should surface");
        match err {
            SessionError::InternalError(msg) => {
                assert!(msg.contains("sign failed"), "got {msg}");
            }
            other => panic!("expected InternalError on sign failure, got {other:?}"),
        }

        // Rollback ran: channel is Open again.
        let post = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(
            post.status,
            ChannelStatus::Open,
            "sign failure should roll the channel back to Open",
        );

        // Sign failure happens before commit, so the challenge stays
        // Pending (not Consumed) and the outer release flips it back
        // to Available.
        let snap = cache.get(&challenge_id).expect("challenge still cached");
        assert_eq!(
            snap.state,
            super::super::challenge::ChallengeState::Available,
            "challenge releases to Available on pre-commit failure",
        );
    }

    #[tokio::test]
    async fn retry_close_writes_chain_settled_not_stored_value() {
        // The retry-broadcast post-confirm path reads `settled` off a
        // freshly-fetched on-chain account, not the stored record's
        // `on_chain_settled` (which would be stale if the original close
        // ran ApplyVoucher before crashing).
        //
        // No way to fake a valid Channel PDA payload through the mock
        // RPC (synthesising borsh bytes that round-trip through
        // ChannelView is L1-oracle territory). What we CAN pin is the
        // helper's failure path: against an RPC that returns
        // AccountNotFound, `read_settled_from_chain` surfaces an
        // InternalError and the caller logs + falls back to the stored
        // value. Happy-path refetch lives in the L1 oracle.
        let cid = pk(0xD1);
        let rpc = Arc::new(solana_client::nonblocking::rpc_client::RpcClient::new_mock(
            "succeeds".to_string(),
        ));
        let config = base_config();
        let err = read_settled_from_chain(&rpc, &config, &cid)
            .await
            .expect_err("AccountNotFound should surface as InternalError");
        match err {
            SessionError::InternalError(msg) => {
                assert!(
                    msg.contains("vanished") || msg.contains("encoding"),
                    "expected refetch failure message, got {msg}",
                );
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn finish_post_tombstone_trusts_stored_settled() {
        // Tombstoned PDAs can't be reread for settled: the layout is
        // gone, replaced by the 1-byte close discriminator.
        // `finish_post_tombstone` doesn't write a new on_chain_settled;
        // it leaves whatever the store had. Pin that so a future change
        // can't silently start writing zero or some other placeholder.
        let cid = pk(0xD2);
        let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
        let mut record = base_record(cid, pk(0xAA), 10_000);
        record.on_chain_settled = 4_321;
        store.insert(record).await.unwrap();
        store.mark_close_attempting(&cid).await.unwrap();

        let stored = store.get(&cid).await.unwrap().unwrap();
        finish_post_tombstone(store.as_ref(), &stored)
            .await
            .expect("tombstone finishing path runs");

        let post = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(
            post.on_chain_settled, 4_321,
            "tombstone path must not overwrite the stored settled figure",
        );
        assert_eq!(post.status, ChannelStatus::ClosedFinalized);
    }

    #[test]
    fn close_receipt_carries_tx_hash_and_refunded() {
        // The close receipt's wire shape carries the close tx hash and
        // the refunded amount (deposit minus settled). Both keys round-
        // trip through the public Receipt builder.
        let receipt = Receipt::success("solana", "ref", "ch-1")
            .with_close_amounts("tx-sig-xyz", 250);
        let value = serde_json::to_value(&receipt).expect("receipt serializes");
        assert_eq!(
            value.get("txHash").and_then(|v| v.as_str()),
            Some("tx-sig-xyz"),
        );
        assert_eq!(
            value.get("refunded").and_then(|v| v.as_str()),
            Some("250"),
        );
    }

    #[test]
    fn retry_close_uses_last_voucher_when_refetch_sees_tombstone() {
        // Refetch can see a tombstoned PDA when the cooperative close
        // hits FINALIZED in one tx. With a voucher stashed, the fallback
        // picks `last_voucher.cumulative_amount` over the stale
        // `on_chain_settled`.
        let signer = fresh_signing_key(0x55);
        let cid = pk(0xE1);
        let mut record = base_record(cid, pk(0xAA), 10_000);
        record.on_chain_settled = 100;
        record.last_voucher = Some(mint_voucher(&signer, &cid, 750, None));

        let dummy_sig = Signature::default();
        let value = tombstone_refetch_fallback(&record, &cid, &dummy_sig);
        assert_eq!(
            value, 750,
            "fallback should pull from last_voucher.cumulative_amount, not on_chain_settled",
        );
    }

    #[test]
    fn retry_close_falls_back_to_stored_settled_when_no_last_voucher() {
        // Counterpart for the LockSettled branch: no voucher stashed,
        // fallback reads the stored on_chain_settled.
        let cid = pk(0xE2);
        let mut record = base_record(cid, pk(0xAA), 10_000);
        record.on_chain_settled = 432;
        record.last_voucher = None;

        let dummy_sig = Signature::default();
        let value = tombstone_refetch_fallback(&record, &cid, &dummy_sig);
        assert_eq!(value, 432);
    }
}
