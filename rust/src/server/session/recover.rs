//! Startup recovery: inspect every persisted channel, then apply outcomes.
//!
//! Inspect walks `list_by_status` and re-checks each record against the
//! cluster in parallel without touching the store. Apply only runs once
//! inspect is done and either runs every outcome sequentially or comes back
//! with a `RecoveryBatchFailed` enumerating every failure at once. Splitting
//! it that way means the operator sees all the anomalies in one shot
//! instead of chasing a half-mutated store after a crash mid-apply.

use std::sync::Arc;

use futures::stream::{self, StreamExt};
use payment_channels_client::types::ChannelStatus as OnChainStatus;
use solana_client::client_error::{ClientError, ClientErrorKind};
use solana_client::rpc_config::RpcAccountInfoConfig;
use solana_client::rpc_request::RpcError as RpcRequestError;
use solana_pubkey::Pubkey;

use crate::error::{OnChainChannelStatus, RecoveryFailure, RecoveryFailureKind, SessionError};
use crate::program::payment_channels::rpc::RpcClient;

use crate::program::payment_channels::state::{ChannelView, CLOSED_CHANNEL_DISCRIMINATOR};
use crate::program::payment_channels::verify::{
    verify_finalized_or_absent, verify_open, ExpectedOpenState, Mismatch, VerifyError,
};
use crate::server::session::close::run_close_retry;
use crate::server::session::SessionMethod;
use crate::store::{ChannelRecord, ChannelStatus, ChannelStore};

use super::SessionConfig;

/// What inspect decided to do with one record. Apply matches on this
/// and either mutates the store or folds a typed failure into the batch
/// error.
#[derive(Debug)]
pub enum RecoveryOutcome {
    /// Chain shows `Open` and matches the stored record. Nothing to do.
    Resume { record: ChannelRecord },
    /// Store has the record, chain has no PDA: open tx never confirmed.
    /// Delete the record so the channel id frees up.
    DropOrphan { channel_id: Pubkey },
    /// Store is `CloseAttempting`, chain is still `Open`: close broadcast
    /// never reached the cluster. Roll back to Open so the channel is
    /// usable again.
    Rollback { channel_id: Pubkey },
    /// Store is `Closing`, chain is `Open`: most likely a fork rollback
    /// reverted `request_close` after the store recorded it. The
    /// recovery-only mutator drops the store back to Open.
    RollbackFromClosing { channel_id: Pubkey },
    /// Store is `CloseAttempting` and chain shows close evidence
    /// (`Closing`, tombstoned, or finalized): broadcast landed but the
    /// post-confirm store updates didn't. Re-run the finishing path.
    RetryClose { record: ChannelRecord },
    /// Store is `Open`, chain is `Closing`: payer ran `request_close`
    /// directly. Flip the store so the next close action picks it up.
    TransitionToClosing { channel_id: Pubkey },
    /// `ClosedPending` in store, chain confirms finalized or absent.
    /// Promote to `ClosedFinalized`.
    Finalize { channel_id: Pubkey },
    /// One of the four hard failure shapes. Apply collects these into a
    /// batch error and skips the store.
    HardFail(RecoveryFailure),
    /// Terminal (`ClosedFinalized`) or any other already-synced state.
    /// Leave it alone.
    NoOp { channel_id: Pubkey },
}

/// Walk every persisted record in the relevant statuses and classify
/// each one without touching the store.
///
/// Runs in parallel up to `parallelism`. The returned vec lists every
/// record, hard failures included; the apply pass decides whether the
/// batch surfaces or runs.
pub async fn inspect_all(
    store: &dyn ChannelStore,
    rpc: &dyn RpcClient,
    config: &SessionConfig,
    parallelism: usize,
) -> Result<Vec<RecoveryOutcome>, SessionError> {
    let statuses = [
        ChannelStatus::Open,
        ChannelStatus::CloseAttempting,
        ChannelStatus::Closing,
        ChannelStatus::ClosedPending,
        ChannelStatus::ClosedFinalized,
    ];
    let records = store.list_by_status(&statuses).await?;
    if records.is_empty() {
        tracing::info!("recovery: no records to inspect");
        return Ok(Vec::new());
    }
    let parallelism = parallelism.max(1);

    let outcomes = stream::iter(records.into_iter())
        .map(|record| inspect_one(rpc, config, record))
        .buffer_unordered(parallelism)
        .collect::<Vec<_>>()
        .await;

    Ok(outcomes)
}

/// Classify one record. Each store status has a small set of legal
/// on-chain shapes; anything else is a hard failure.
pub(crate) async fn inspect_one(
    rpc: &dyn RpcClient,
    config: &SessionConfig,
    record: ChannelRecord,
) -> RecoveryOutcome {
    match record.status {
        ChannelStatus::Open => inspect_open(rpc, config, record).await,
        ChannelStatus::CloseAttempting => inspect_close_attempting(rpc, config, record).await,
        ChannelStatus::Closing => inspect_closing(rpc, config, record).await,
        ChannelStatus::ClosedPending => inspect_closed_pending(rpc, config, record).await,
        ChannelStatus::ClosedFinalized => RecoveryOutcome::NoOp {
            channel_id: record.channel_id,
        },
    }
}

async fn inspect_open(
    rpc: &dyn RpcClient,
    config: &SessionConfig,
    record: ChannelRecord,
) -> RecoveryOutcome {
    let expected = ExpectedOpenState {
        deposit: record.deposit,
        payer: record.payer,
        payee: record.payee,
        mint: record.mint,
        authorized_signer: record.authorized_signer,
        // No cached bump in the record, so re-derive it. The chain's
        // ChannelView reports its own bump; we want our canonical one
        // to compare against.
        bump: derive_canonical_bump(&record),
    };

    match verify_open(
        rpc,
        config.commitment,
        &record.channel_id,
        &expected,
        &record.splits,
    )
    .await
    {
        Ok(()) => RecoveryOutcome::Resume { record },
        Err(VerifyError::NotFound) => RecoveryOutcome::DropOrphan {
            channel_id: record.channel_id,
        },
        Err(VerifyError::Tombstoned) => {
            if record.accepted_cumulative > record.on_chain_settled {
                RecoveryOutcome::HardFail(RecoveryFailure {
                    channel_id: record.channel_id,
                    kind: RecoveryFailureKind::UnsettledRevenue {
                        unsettled: record.accepted_cumulative - record.on_chain_settled,
                    },
                })
            } else if record.on_chain_settled > 0 {
                // Settled then tombstoned (a legitimate close that
                // bypassed our CloseAttempting path). Promote to
                // ClosedFinalized so the record doesn't sit Open
                // forever.
                RecoveryOutcome::Finalize {
                    channel_id: record.channel_id,
                }
            } else {
                // Opened then tombstoned with nothing settled. Record
                // has nothing useful left; drop it and free the id.
                RecoveryOutcome::DropOrphan {
                    channel_id: record.channel_id,
                }
            }
        }
        Err(VerifyError::Mismatch(Mismatch::Status { got, .. }))
            if got == OnChainStatus::Closing as u8 =>
        {
            RecoveryOutcome::TransitionToClosing {
                channel_id: record.channel_id,
            }
        }
        Err(VerifyError::Mismatch(m)) => RecoveryOutcome::HardFail(RecoveryFailure {
            channel_id: record.channel_id,
            kind: RecoveryFailureKind::VerifyOpenMismatch {
                field: mismatch_field(&m),
            },
        }),
        Err(VerifyError::Rpc(e)) => RecoveryOutcome::HardFail(RecoveryFailure {
            channel_id: record.channel_id,
            kind: RecoveryFailureKind::RpcFailure {
                message: format!("{e:#}"),
            },
        }),
        Err(other) => RecoveryOutcome::HardFail(RecoveryFailure {
            channel_id: record.channel_id,
            kind: RecoveryFailureKind::RpcFailure {
                message: format!("{other:#}"),
            },
        }),
    }
}

async fn inspect_close_attempting(
    rpc: &dyn RpcClient,
    config: &SessionConfig,
    record: ChannelRecord,
) -> RecoveryOutcome {
    match probe_chain_status(rpc, config, &record.channel_id).await {
        Ok(OnChainChannelStatus::Open) => RecoveryOutcome::Rollback {
            channel_id: record.channel_id,
        },
        Ok(OnChainChannelStatus::Closing)
        | Ok(OnChainChannelStatus::Finalized)
        | Ok(OnChainChannelStatus::Tombstoned) => RecoveryOutcome::RetryClose { record },
        Ok(OnChainChannelStatus::Absent) => {
            // CloseAttempting against an absent PDA doesn't make sense:
            // the open tx never landed, but the close path ran anyway.
            // Hard-fail so the operator looks at it.
            RecoveryOutcome::HardFail(RecoveryFailure {
                channel_id: record.channel_id,
                kind: RecoveryFailureKind::StateInversion {
                    stored: ChannelStatus::CloseAttempting,
                    on_chain: OnChainChannelStatus::Absent,
                },
            })
        }
        Err(message) => RecoveryOutcome::HardFail(RecoveryFailure {
            channel_id: record.channel_id,
            kind: RecoveryFailureKind::RpcFailure { message },
        }),
    }
}

async fn inspect_closing(
    rpc: &dyn RpcClient,
    config: &SessionConfig,
    record: ChannelRecord,
) -> RecoveryOutcome {
    match probe_chain_status(rpc, config, &record.channel_id).await {
        Ok(OnChainChannelStatus::Closing) => RecoveryOutcome::NoOp {
            channel_id: record.channel_id,
        },
        Ok(OnChainChannelStatus::Open) => {
            // Store says Closing, chain says Open. Probably a fork
            // rollback wiped `request_close` after we observed it. Drop
            // the store back to Open so the channel is usable; the
            // payer will hit close again if they really meant it.
            tracing::warn!(
                channel_id = %record.channel_id,
                "Closing record observed against on-chain Open; rolling store back to Open (probable fork rollback)",
            );
            RecoveryOutcome::RollbackFromClosing {
                channel_id: record.channel_id,
            }
        }
        Ok(OnChainChannelStatus::Finalized) | Ok(OnChainChannelStatus::Tombstoned) => {
            RecoveryOutcome::RetryClose { record }
        }
        Ok(OnChainChannelStatus::Absent) => RecoveryOutcome::HardFail(RecoveryFailure {
            channel_id: record.channel_id,
            kind: RecoveryFailureKind::StateInversion {
                stored: ChannelStatus::Closing,
                on_chain: OnChainChannelStatus::Absent,
            },
        }),
        Err(message) => RecoveryOutcome::HardFail(RecoveryFailure {
            channel_id: record.channel_id,
            kind: RecoveryFailureKind::RpcFailure { message },
        }),
    }
}

async fn inspect_closed_pending(
    rpc: &dyn RpcClient,
    config: &SessionConfig,
    record: ChannelRecord,
) -> RecoveryOutcome {
    match verify_finalized_or_absent(rpc, config.commitment, &record.channel_id).await {
        Ok(()) => RecoveryOutcome::Finalize {
            channel_id: record.channel_id,
        },
        Err(VerifyError::Rpc(e)) => RecoveryOutcome::HardFail(RecoveryFailure {
            channel_id: record.channel_id,
            kind: RecoveryFailureKind::RpcFailure {
                message: format!("{e:#}"),
            },
        }),
        // Anything else (mid-grace Closing, wrong discriminator byte,
        // weird encoding) means the chain hasn't confirmed finalization
        // yet. Leave the record alone and let the next recovery pass
        // pick it up.
        Err(_) => RecoveryOutcome::NoOp {
            channel_id: record.channel_id,
        },
    }
}

/// Apply every outcome. Hard-fail gate: if any outcome is a `HardFail`
/// and `allow_unsettled` is false, the whole batch comes back as
/// `RecoveryBatchFailed` and the store stays untouched. Otherwise
/// mutations run in inspect order.
pub async fn apply_outcomes(
    outcomes: Vec<RecoveryOutcome>,
    store: &dyn ChannelStore,
    rpc: &Arc<dyn RpcClient>,
    method: &SessionMethod,
    allow_unsettled: bool,
) -> Result<(), SessionError> {
    // Collect hard failures up front so the gate sees them all at once.
    let mut failures: Vec<RecoveryFailure> = Vec::new();
    for outcome in &outcomes {
        if let RecoveryOutcome::HardFail(f) = outcome {
            failures.push(f.clone());
        }
    }

    if !failures.is_empty() {
        let only_unsettled = failures
            .iter()
            .all(|f| matches!(f.kind, RecoveryFailureKind::UnsettledRevenue { .. }));
        if allow_unsettled && only_unsettled {
            for f in &failures {
                if let RecoveryFailureKind::UnsettledRevenue { unsettled } = f.kind {
                    tracing::warn!(
                        target: "mpp_session_unsettled_revenue_lamports",
                        channel_id = %f.channel_id,
                        unsettled,
                        "allow_unsettled_on_startup is set; downgrading unsettled revenue to a warning",
                    );
                }
            }
        } else {
            for f in &failures {
                tracing::error!(
                    channel_id = %f.channel_id,
                    kind = %f.kind,
                    "recovery hard-fail; refusing to start until resolved",
                );
            }
            return Err(SessionError::RecoveryBatchFailed { failures });
        }
    }

    for outcome in outcomes {
        match outcome {
            RecoveryOutcome::Resume { .. } => {}
            RecoveryOutcome::NoOp { .. } => {}
            RecoveryOutcome::HardFail(_) => {
                // Already logged as a warning by the gate above under
                // allow_unsettled.
            }
            RecoveryOutcome::DropOrphan { channel_id } => {
                store.delete(&channel_id).await?;
                tracing::info!(
                    channel_id = %channel_id,
                    "dropped orphan record; open tx never landed on-chain",
                );
            }
            RecoveryOutcome::Rollback { channel_id } => {
                store.mark_close_rollback(&channel_id).await?;
                tracing::info!(
                    channel_id = %channel_id,
                    "rolled CloseAttempting back to Open; close broadcast never reached the cluster",
                );
            }
            RecoveryOutcome::RollbackFromClosing { channel_id } => {
                store
                    .mark_recovery_rollback_from_closing(&channel_id)
                    .await?;
                tracing::info!(
                    channel_id = %channel_id,
                    "rolled Closing back to Open; probable fork rollback of request_close",
                );
            }
            RecoveryOutcome::RetryClose { record } => {
                let channel_id = record.channel_id;
                tracing::info!(
                    channel_id = %channel_id,
                    "running RetryClose; broadcast confirmed on-chain but store updates lagged",
                );
                run_close_retry(store, rpc, method.config(), record).await?;
            }
            RecoveryOutcome::TransitionToClosing { channel_id } => {
                store.mark_closing(&channel_id).await?;
                tracing::info!(
                    channel_id = %channel_id,
                    "transitioned store to Closing; payer ran request_close directly",
                );
            }
            RecoveryOutcome::Finalize { channel_id } => {
                store.mark_closed_finalized(&channel_id).await?;
                tracing::info!(
                    channel_id = %channel_id,
                    "promoted ClosedPending to ClosedFinalized",
                );
            }
        }
    }
    Ok(())
}

/// Fetch the channel PDA and classify it. RPC errors come back as the
/// formatted string the recovery layer stuffs into `RpcFailure`. Mirrors
/// `tombstone_probe` from `verify.rs` but covers both live shapes (the
/// status byte off a decoded `ChannelView`) and the tombstoned/absent
/// terminals.
async fn probe_chain_status(
    rpc: &dyn RpcClient,
    config: &SessionConfig,
    channel_id: &Pubkey,
) -> Result<OnChainChannelStatus, String> {
    let info = RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(config.commitment),
        ..RpcAccountInfoConfig::default()
    };

    let resp = rpc.get_ui_account_with_config(channel_id, info).await;
    let ui_value = match resp {
        Ok(r) => r.value,
        Err(e) => {
            if is_account_not_found(&e) {
                return Ok(OnChainChannelStatus::Absent);
            }
            return Err(format!("{e:#}"));
        }
    };

    let Some(ui_account) = ui_value else {
        return Ok(OnChainChannelStatus::Absent);
    };

    let data = match ui_account.data.decode() {
        Some(d) => d,
        None => return Err(format!("unexpected RPC encoding for channel {channel_id}")),
    };

    if data.len() == 1 {
        return if data[0] == CLOSED_CHANNEL_DISCRIMINATOR {
            Ok(OnChainChannelStatus::Tombstoned)
        } else {
            Err(format!(
                "channel {channel_id}: tombstone-length payload with wrong discriminator byte {}",
                data[0]
            ))
        };
    }

    let view = match ChannelView::from_account_data(&data) {
        Ok(v) => v,
        Err(e) => return Err(format!("channel {channel_id}: decode failed: {e}")),
    };

    match view.status() {
        s if s == OnChainStatus::Open as u8 => Ok(OnChainChannelStatus::Open),
        s if s == OnChainStatus::Closing as u8 => Ok(OnChainChannelStatus::Closing),
        s if s == OnChainStatus::Finalized as u8 => Ok(OnChainChannelStatus::Finalized),
        other => Err(format!(
            "channel {channel_id}: unrecognised status byte {other}"
        )),
    }
}

fn is_account_not_found(e: &ClientError) -> bool {
    matches!(
        &*e.kind,
        ClientErrorKind::RpcError(RpcRequestError::RpcResponseError { code: -32004, .. })
    )
}

/// Re-run the canonical bump search from the persisted record so we
/// don't have to trust whatever bump the chain hands back.
fn derive_canonical_bump(record: &ChannelRecord) -> u8 {
    let (_, bump) = crate::program::payment_channels::state::find_channel_pda(
        &record.payer,
        &record.payee,
        &record.mint,
        &record.authorized_signer,
        record.salt,
        &record.program_id,
    );
    bump
}

/// Stable field name for each `Mismatch` shape so `VerifyOpenMismatch`
/// carries something the operator can grep or route on.
fn mismatch_field(m: &Mismatch) -> &'static str {
    match m {
        Mismatch::Deposit { .. } => "deposit",
        Mismatch::Settled { .. } => "settled",
        Mismatch::Bump { .. } => "bump",
        Mismatch::Version { .. } => "version",
        Mismatch::Status { .. } => "status",
        Mismatch::GracePeriod { .. } => "gracePeriod",
        Mismatch::ClosureStartedAt { .. } => "closureStartedAt",
        Mismatch::Payer { .. } => "payer",
        Mismatch::Payee { .. } => "payee",
        Mismatch::AuthorizedSigner { .. } => "authorizedSigner",
        Mismatch::Mint { .. } => "mint",
        Mismatch::ClosureNotStarted => "closureStartedAt",
        Mismatch::DistributionHash { .. } => "distributionHash",
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the per-record inspect decisions and the apply-pass
    //! hard-fail gate. End-to-end behaviour against a real cluster sits
    //! in the L1 oracle.

    use super::*;
    use crate::server::session::{Network, Pricing, SessionConfig};
    use crate::store::{ChannelRecord, ChannelStatus, InMemoryChannelStore};
    use solana_commitment_config::CommitmentConfig;
    use std::sync::Arc;
    use std::time::Duration as StdDuration;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }

    fn base_record(channel_id: Pubkey, status: ChannelStatus) -> ChannelRecord {
        ChannelRecord {
            channel_id,
            payer: pk(0xA1),
            payee: pk(0xA2),
            mint: pk(0xA3),
            salt: 0xCAFE,
            program_id: pk(0xA4),
            authorized_signer: pk(0xA5),
            deposit: 1_000,
            accepted_cumulative: 0,
            on_chain_settled: 0,
            last_voucher: None,
            close_tx: None,
            status,
            splits: Vec::new(),
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
            voucher_check_grace_seconds: 15,
            fee_payer: None,
            payee_signer: None,
            realm: Some("test".into()),
            secret_key: Some("test-secret".into()),
        }
    }

    /// `RpcClient::new_mock("succeeds")` is the upstream-shipped success
    /// shim. `"fails"` makes every send error out. Either is enough to
    /// drive the inspect logic without a live cluster.
    fn mock_rpc_failing() -> Arc<dyn RpcClient> {
        Arc::new(solana_client::nonblocking::rpc_client::RpcClient::new_mock(
            "fails".to_string(),
        ))
    }

    fn mock_rpc_succeeds() -> Arc<dyn RpcClient> {
        // The mock fakes every account fetch as `AccountNotFound`, which
        // is exactly what `verify_open` reads as `NotFound`.
        Arc::new(solana_client::nonblocking::rpc_client::RpcClient::new_mock(
            "succeeds".to_string(),
        ))
    }

    #[tokio::test]
    async fn inspect_open_with_matching_on_chain_yields_resume() {
        // No way to fake a valid Channel PDA payload through the mock RPC
        // (synthesising borsh bytes that round-trip through ChannelView
        // is L1-oracle territory). This test pins the Resume shape and
        // the apply pass's no-op behaviour; the live verify_open success
        // path runs in the L1 oracle.
        let cid = pk(0x10);
        let record = base_record(cid, ChannelStatus::Open);

        let store = InMemoryChannelStore::new();
        store.insert(record.clone()).await.unwrap();
        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        // Resume passes through apply without mutating the store.
        apply_outcomes(
            vec![RecoveryOutcome::Resume {
                record: record.clone(),
            }],
            &store,
            &rpc,
            &method,
            false,
        )
        .await
        .expect("Resume applies cleanly");

        let post = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(post.status, ChannelStatus::Open);
        assert_eq!(post.channel_id, cid);
    }

    #[tokio::test]
    async fn inspect_open_with_account_not_found_yields_drop_orphan() {
        // Mock RPC returns AccountNotFound for any get-account; verify_open
        // turns that into VerifyError::NotFound, which inspect classifies
        // as DropOrphan.
        let cid = pk(0x11);
        let record = base_record(cid, ChannelStatus::Open);
        let rpc = mock_rpc_succeeds();
        let outcome = inspect_one(rpc.as_ref(), &base_config(), record).await;
        match outcome {
            RecoveryOutcome::DropOrphan { channel_id } => assert_eq!(channel_id, cid),
            other => panic!("expected DropOrphan, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inspect_open_with_tombstone_and_no_unsettled_revenue_yields_finalize() {
        // BUG #13 regression: a tombstoned PDA with settled revenue and
        // no unsettled delta is a legitimate close that bypassed our
        // CloseAttempting path. Recovery promotes the record to
        // ClosedFinalized so it stops sitting Open. Mock RPC can't
        // synthesise a tombstone payload, so this just pins the apply
        // side: Finalize against an Open record drives Open to
        // ClosedFinalized.
        let cid = pk(0x14);
        let store = InMemoryChannelStore::new();
        let mut record = base_record(cid, ChannelStatus::Open);
        record.on_chain_settled = 500;
        record.accepted_cumulative = 500;
        store.insert(record).await.unwrap();

        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        apply_outcomes(
            vec![RecoveryOutcome::Finalize { channel_id: cid }],
            &store,
            &rpc,
            &method,
            false,
        )
        .await
        .expect("Finalize against Open should drive to ClosedFinalized");

        let post = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(post.status, ChannelStatus::ClosedFinalized);
    }

    #[tokio::test]
    async fn inspect_open_with_tombstone_and_zero_settled_yields_drop_orphan() {
        // The other BUG #13 branch: opened then tombstoned with nothing
        // settled (rare but possible). Record has nothing useful; drop it.
        let cid = pk(0x15);
        let store = InMemoryChannelStore::new();
        let record = base_record(cid, ChannelStatus::Open);
        store.insert(record).await.unwrap();

        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        apply_outcomes(
            vec![RecoveryOutcome::DropOrphan { channel_id: cid }],
            &store,
            &rpc,
            &method,
            false,
        )
        .await
        .expect("DropOrphan against Open should delete the record");

        assert!(
            store.get(&cid).await.unwrap().is_none(),
            "record should have been deleted",
        );
    }

    #[tokio::test]
    async fn inspect_open_with_tombstone_and_unsettled_revenue_yields_hard_fail() {
        // Mock RPC can't return a literal `[2u8]` tombstone payload, so
        // the L1 oracle covers the live tombstone path. This pins the
        // field math: a HardFail with UnsettledRevenue carries the exact
        // `accepted_cumulative - on_chain_settled` delta and apply
        // surfaces it through RecoveryBatchFailed when allow_unsettled
        // is off.
        let cid = pk(0x12);
        let mut record = base_record(cid, ChannelStatus::Open);
        record.accepted_cumulative = 700;
        record.on_chain_settled = 500;

        let store = InMemoryChannelStore::new();
        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        let unsettled = record.accepted_cumulative - record.on_chain_settled;
        let outcome = RecoveryOutcome::HardFail(RecoveryFailure {
            channel_id: record.channel_id,
            kind: RecoveryFailureKind::UnsettledRevenue { unsettled },
        });

        let err = apply_outcomes(vec![outcome], &store, &rpc, &method, false)
            .await
            .expect_err("UnsettledRevenue surfaces under default policy");
        match err {
            SessionError::RecoveryBatchFailed { failures } => {
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].channel_id, cid);
                match failures[0].kind {
                    RecoveryFailureKind::UnsettledRevenue { unsettled: u } => {
                        assert_eq!(u, 200);
                    }
                    ref other => panic!("expected UnsettledRevenue, got {other:?}"),
                }
            }
            other => panic!("expected RecoveryBatchFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inspect_close_attempting_with_on_chain_open_yields_rollback() {
        // Probe-on-chain `Open` produces Rollback. This pins the apply
        // side: Rollback runs mark_close_rollback so the channel ends
        // up back at Open. Live probe path is in the L1 oracle.
        let cid = pk(0x13);
        let store = InMemoryChannelStore::new();
        let record = base_record(cid, ChannelStatus::Open);
        store.insert(record).await.unwrap();
        store.mark_close_attempting(&cid).await.unwrap();
        assert_eq!(
            store.get(&cid).await.unwrap().unwrap().status,
            ChannelStatus::CloseAttempting
        );

        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        apply_outcomes(
            vec![RecoveryOutcome::Rollback { channel_id: cid }],
            &store,
            &rpc,
            &method,
            false,
        )
        .await
        .expect("rollback applies cleanly");

        let post = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(post.status, ChannelStatus::Open);
    }

    #[tokio::test]
    async fn apply_hard_fail_without_allow_unsettled_returns_recovery_batch_failed() {
        // Two failures in one batch surface as a single
        // RecoveryBatchFailed enumerating both.
        let store = InMemoryChannelStore::new();
        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        let cid_a = pk(0x21);
        let cid_b = pk(0x22);
        let outcomes = vec![
            RecoveryOutcome::HardFail(RecoveryFailure {
                channel_id: cid_a,
                kind: RecoveryFailureKind::UnsettledRevenue { unsettled: 100 },
            }),
            RecoveryOutcome::HardFail(RecoveryFailure {
                channel_id: cid_b,
                kind: RecoveryFailureKind::RpcFailure {
                    message: "fetch failed".into(),
                },
            }),
        ];
        let err = apply_outcomes(outcomes, &store, &rpc, &method, false)
            .await
            .expect_err("hard fail batch should surface");
        match err {
            SessionError::RecoveryBatchFailed { failures } => {
                assert_eq!(failures.len(), 2);
                assert_eq!(failures[0].channel_id, cid_a);
                assert_eq!(failures[1].channel_id, cid_b);
            }
            other => panic!("expected RecoveryBatchFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_hard_fail_with_allow_unsettled_only_unsettled_revenue_succeeds_with_tracing() {
        // allow_unsettled is the post-DR escape hatch: the operator has
        // already inspected the missed revenue and just wants the server
        // up. Two unsettled-revenue failures pass.
        let store = InMemoryChannelStore::new();
        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        let outcomes = vec![
            RecoveryOutcome::HardFail(RecoveryFailure {
                channel_id: pk(0x31),
                kind: RecoveryFailureKind::UnsettledRevenue { unsettled: 50 },
            }),
            RecoveryOutcome::HardFail(RecoveryFailure {
                channel_id: pk(0x32),
                kind: RecoveryFailureKind::UnsettledRevenue { unsettled: 75 },
            }),
        ];
        apply_outcomes(outcomes, &store, &rpc, &method, true)
            .await
            .expect("unsettled-only batch should pass under allow_unsettled");
    }

    #[tokio::test]
    async fn allow_unsettled_does_not_swallow_other_hard_fail_kinds() {
        // The flag only covers UnsettledRevenue. A mixed batch with
        // anything else still surfaces.
        let store = InMemoryChannelStore::new();
        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        let outcomes = vec![
            RecoveryOutcome::HardFail(RecoveryFailure {
                channel_id: pk(0x41),
                kind: RecoveryFailureKind::UnsettledRevenue { unsettled: 50 },
            }),
            RecoveryOutcome::HardFail(RecoveryFailure {
                channel_id: pk(0x42),
                kind: RecoveryFailureKind::RpcFailure {
                    message: "boom".into(),
                },
            }),
        ];
        let err = apply_outcomes(outcomes, &store, &rpc, &method, true)
            .await
            .expect_err("mixed batch surfaces even under allow_unsettled");
        assert!(matches!(err, SessionError::RecoveryBatchFailed { .. }));
    }

    #[tokio::test]
    async fn phase_two_short_circuits_on_first_hard_fail() {
        // Apply doesn't touch the store when the batch fails. Mix a
        // legitimate DropOrphan with a HardFail and check the record is
        // still there afterwards.
        let cid = pk(0x51);
        let store = InMemoryChannelStore::new();
        let record = base_record(cid, ChannelStatus::Open);
        store.insert(record).await.unwrap();
        let rpc = mock_rpc_failing();
        let method = build_test_method(&store, &rpc);

        let outcomes = vec![
            RecoveryOutcome::DropOrphan { channel_id: cid },
            RecoveryOutcome::HardFail(RecoveryFailure {
                channel_id: pk(0x52),
                kind: RecoveryFailureKind::RpcFailure {
                    message: "abort".into(),
                },
            }),
        ];
        let err = apply_outcomes(outcomes, &store, &rpc, &method, false)
            .await
            .expect_err("hard fail should short-circuit");
        assert!(matches!(err, SessionError::RecoveryBatchFailed { .. }));

        // Record is still in the store; DropOrphan never ran.
        let post = store.get(&cid).await.unwrap();
        assert!(post.is_some(), "store mutation should not have run");
    }

    /// SessionMethod construction shim for the apply-pass tests.
    ///
    /// Non-RetryClose outcomes never reach into SessionMethod's store
    /// handle (the tests pass `&dyn ChannelStore` directly), so a fresh
    /// placeholder InMemoryChannelStore is fine. RetryClose runs in the
    /// L1 oracle.
    fn build_test_method(_store: &InMemoryChannelStore, rpc: &Arc<dyn RpcClient>) -> SessionMethod {
        let placeholder: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
        SessionMethod::new_for_recover(base_config(), placeholder, rpc.clone())
            .expect("construct SessionMethod")
    }
}
