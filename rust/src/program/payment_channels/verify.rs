//! RPC-based verification of on-chain Channel state.
//!
//! Server handlers use these to assert on-chain state matches expectations
//! after `open` / `top_up` / `settle_and_finalize` / `distribute` complete.

use payment_channels_client::types::ChannelStatus;
use solana_account_decoder_client_types::{UiAccount, UiAccountEncoding};
use solana_client::client_error::{ClientError, ClientErrorKind};
use solana_client::rpc_config::RpcAccountInfoConfig;
use solana_client::rpc_request::RpcError;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use tracing::debug;

use crate::program::payment_channels::rpc::RpcClient;
use crate::program::payment_channels::state::{ChannelView, CLOSED_CHANNEL_DISCRIMINATOR};

/// Build the `RpcAccountInfoConfig` used by every `verify_*` helper.
///
/// `Base64` is the cheapest encoding that round-trips raw account bytes:
/// `Base58` is size-limited by the RPC server, `Base64Zstd` adds a
/// decompression step we do not need for ~200-byte channel PDAs, and
/// `JsonParsed` would force the RPC to attempt program-specific parsing
/// (which it cannot do for the payment_channels program).
fn account_info_config(commitment: CommitmentConfig) -> RpcAccountInfoConfig {
    RpcAccountInfoConfig {
        encoding: Some(UiAccountEncoding::Base64),
        commitment: Some(commitment),
        ..RpcAccountInfoConfig::default()
    }
}

/// Decode a `UiAccount` payload back to raw bytes.
///
/// `UiAccountData::decode()` handles every binary encoding the RPC may
/// return (`LegacyBinary` / `Base58` / `Base64` / `Base64Zstd`); it only
/// returns `None` for `JsonParsed`, which we never request via
/// `account_info_config`. Any `None` here therefore signals the RPC
/// returned a shape we did not ask for, and is surfaced as the typed
/// `VerifyError::UnexpectedEncoding` variant.
fn decode_ui_account(channel_id: &Pubkey, ui: &UiAccount) -> Result<Vec<u8>, VerifyError> {
    ui.data.decode().ok_or(VerifyError::UnexpectedEncoding {
        channel_id: *channel_id,
    })
}

/// Per-field on-chain state mismatches. Each variant carries the typed
/// expected and observed values so callers can match on the specific field
/// without parsing strings. Propagates into `VerifyError::Mismatch` via the
/// `#[from]` impl below.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Mismatch {
    #[error("deposit mismatch: expected {expected}, got {got}")]
    Deposit { expected: u64, got: u64 },
    #[error("settled mismatch: expected {expected}, got {got}")]
    Settled { expected: u64, got: u64 },
    #[error("bump mismatch: expected {expected}, got {got}")]
    Bump { expected: u8, got: u8 },
    #[error("version mismatch: expected 1, got {got}")]
    Version { got: u8 },
    #[error("status mismatch: expected {expected}, got {got}")]
    Status { expected: u8, got: u8 },
    #[error("grace period mismatch: expected {expected}, got {got}")]
    GracePeriod { expected: u32, got: u32 },
    /// Reserved for callers that need to verify a specific closure timestamp
    /// (e.g. confirming a finalize landed within an expected window). No
    /// helper currently constructs this variant; `verify_closing` only checks
    /// that closure has started via `ClosureNotStarted`.
    #[error("closure_started_at mismatch: expected {expected}, got {got}")]
    ClosureStartedAt { expected: i64, got: i64 },
    #[error("payer mismatch: expected {expected}, got {got}")]
    Payer {
        expected: solana_pubkey::Pubkey,
        got: solana_pubkey::Pubkey,
    },
    #[error("payee mismatch: expected {expected}, got {got}")]
    Payee {
        expected: solana_pubkey::Pubkey,
        got: solana_pubkey::Pubkey,
    },
    #[error("authorized_signer mismatch: expected {expected}, got {got}")]
    AuthorizedSigner {
        expected: solana_pubkey::Pubkey,
        got: solana_pubkey::Pubkey,
    },
    #[error("mint mismatch: expected {expected}, got {got}")]
    Mint {
        expected: solana_pubkey::Pubkey,
        got: solana_pubkey::Pubkey,
    },
    #[error("closure not started: closure_started_at == 0 but verify_closing was called")]
    ClosureNotStarted,
    #[error("distribution_hash mismatch: expected {expected_b58}, got {got_b58}",
        expected_b58 = bs58::encode(expected).into_string(),
        got_b58 = bs58::encode(got).into_string())]
    DistributionHash { expected: [u8; 32], got: [u8; 32] },
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("channel account not found")]
    NotFound,
    #[error("channel account is tombstoned (data.len == 1, discriminator == 2)")]
    Tombstoned,
    #[error("channel account has wrong length for tombstone: expected 1, got {data_len}")]
    WrongLength { data_len: usize },
    #[error(
        "channel account has tombstone length but wrong discriminator: expected 2, got {byte}"
    )]
    WrongDiscriminator { byte: u8 },
    #[error(transparent)]
    Mismatch(#[from] Mismatch),
    #[error("unexpected RPC encoding for channel {channel_id}: expected Base64")]
    UnexpectedEncoding { channel_id: Pubkey },
    #[error(transparent)]
    Rpc(#[from] ClientError),
    #[error("channel decode failed: {0}")]
    Decode(#[from] std::io::Error),
}

pub struct ExpectedOpenState {
    pub deposit: u64,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub bump: u8,
}

/// Fetch the Channel PDA at the caller-supplied commitment (typically
/// `SessionConfig::commitment`; defaults to `Confirmed`) and assert the
/// post-`open` invariants: account exists, not tombstoned, supported
/// version, status `Open`, every persistent identity field matches
/// `expected`, and the on-chain `distribution_hash` matches the off-chain
/// digest of `expected_splits`.
///
/// `expected_splits` is a borrowed slice of the SDK's typed `Split` (the
/// typed twin of the wire `BpsSplit`); the body converts to upstream
/// `DistributionEntry` internally via the `From<&Split>` impls. `&[]` is
/// the legal zero-recipients case (vanilla payer-payee channel, payee
/// receives the full pool at distribute via the implicit-remainder rule).
/// The hash check runs last so the cheaper field comparisons can
/// short-circuit first.
pub async fn verify_open(
    rpc: &dyn RpcClient,
    commitment: CommitmentConfig,
    channel_id: &Pubkey,
    expected: &ExpectedOpenState,
    expected_splits: &[crate::protocol::intents::session::Split],
) -> Result<(), VerifyError> {
    let ui_account = rpc
        .get_ui_account_with_config(channel_id, account_info_config(commitment))
        .await?
        .value
        .ok_or(VerifyError::NotFound)?;

    let data = decode_ui_account(channel_id, &ui_account)?;

    reject_tombstone_shape(&data)?;

    let view = ChannelView::from_account_data(&data)?;

    if view.version() != 1 {
        return Err(Mismatch::Version {
            got: view.version(),
        }
        .into());
    }
    if view.status() != ChannelStatus::Open as u8 {
        return Err(Mismatch::Status {
            expected: ChannelStatus::Open as u8,
            got: view.status(),
        }
        .into());
    }
    if view.deposit() != expected.deposit {
        return Err(Mismatch::Deposit {
            expected: expected.deposit,
            got: view.deposit(),
        }
        .into());
    }
    if view.payer() != expected.payer {
        return Err(Mismatch::Payer {
            expected: expected.payer,
            got: view.payer(),
        }
        .into());
    }
    if view.payee() != expected.payee {
        return Err(Mismatch::Payee {
            expected: expected.payee,
            got: view.payee(),
        }
        .into());
    }
    if view.mint() != expected.mint {
        return Err(Mismatch::Mint {
            expected: expected.mint,
            got: view.mint(),
        }
        .into());
    }
    if view.authorized_signer() != expected.authorized_signer {
        return Err(Mismatch::AuthorizedSigner {
            expected: expected.authorized_signer,
            got: view.authorized_signer(),
        }
        .into());
    }
    if view.bump() != expected.bump {
        return Err(Mismatch::Bump {
            expected: expected.bump,
            got: view.bump(),
        }
        .into());
    }

    let expected_entries: Vec<payment_channels_client::types::DistributionEntry> =
        expected_splits.iter().map(Into::into).collect();
    let expected_hash =
        crate::program::payment_channels::splits::distribution_hash(&expected_entries);
    let got_hash = view.distribution_hash();
    if got_hash != expected_hash {
        return Err(Mismatch::DistributionHash {
            expected: expected_hash,
            got: got_hash,
        }
        .into());
    }

    Ok(())
}

/// Verify a `top_up` confirmed and return the on-chain `deposit`.
///
/// Asserts the account exists, isn't tombstoned, has the supported
/// version, and is still in `Open`. Rejects with [`Mismatch::Deposit`]
/// if `view.deposit() < expected_new_deposit` (the tx confirmed but
/// the chain didn't move the deposit as far as we expected). Returns
/// `Ok(actual)` whenever the chain sits at or above the expected
/// value, so the caller can fold a concurrent-topup race into its
/// own deposit policy without losing the actual chain figure.
pub async fn verify_topup_reconciling(
    rpc: &dyn RpcClient,
    commitment: CommitmentConfig,
    channel_id: &Pubkey,
    expected_new_deposit: u64,
) -> Result<u64, VerifyError> {
    let ui_account = rpc
        .get_ui_account_with_config(channel_id, account_info_config(commitment))
        .await?
        .value
        .ok_or(VerifyError::NotFound)?;
    let data = decode_ui_account(channel_id, &ui_account)?;
    reject_tombstone_shape(&data)?;
    let view = ChannelView::from_account_data(&data)?;
    if view.version() != 1 {
        return Err(Mismatch::Version {
            got: view.version(),
        }
        .into());
    }
    if view.status() != ChannelStatus::Open as u8 {
        return Err(Mismatch::Status {
            expected: ChannelStatus::Open as u8,
            got: view.status(),
        }
        .into());
    }
    let actual = view.deposit();
    if actual < expected_new_deposit {
        return Err(Mismatch::Deposit {
            expected: expected_new_deposit,
            got: actual,
        }
        .into());
    }
    Ok(actual)
}

/// Verify a `settle` left the channel still `Open` with the expected
/// settled amount. Settle does not transition status; finalize does.
pub async fn verify_settled(
    rpc: &dyn RpcClient,
    commitment: CommitmentConfig,
    channel_id: &Pubkey,
    expected_settled: u64,
) -> Result<(), VerifyError> {
    let ui_account = rpc
        .get_ui_account_with_config(channel_id, account_info_config(commitment))
        .await?
        .value
        .ok_or(VerifyError::NotFound)?;
    let data = decode_ui_account(channel_id, &ui_account)?;
    reject_tombstone_shape(&data)?;
    let view = ChannelView::from_account_data(&data)?;

    if view.version() != 1 {
        return Err(Mismatch::Version {
            got: view.version(),
        }
        .into());
    }
    if view.status() != ChannelStatus::Open as u8 {
        return Err(Mismatch::Status {
            expected: ChannelStatus::Open as u8,
            got: view.status(),
        }
        .into());
    }
    if view.settled() != expected_settled {
        return Err(Mismatch::Settled {
            expected: expected_settled,
            got: view.settled(),
        }
        .into());
    }
    Ok(())
}

/// Verify the channel is in the `Closing` window with the expected settled
/// amount and grace period, and that `closure_started_at` has been
/// populated by the on-chain transition.
pub async fn verify_closing(
    rpc: &dyn RpcClient,
    commitment: CommitmentConfig,
    channel_id: &Pubkey,
    expected_settled: u64,
    expected_grace_period: u32,
) -> Result<(), VerifyError> {
    let ui_account = rpc
        .get_ui_account_with_config(channel_id, account_info_config(commitment))
        .await?
        .value
        .ok_or(VerifyError::NotFound)?;
    let data = decode_ui_account(channel_id, &ui_account)?;
    reject_tombstone_shape(&data)?;
    let view = ChannelView::from_account_data(&data)?;

    if view.version() != 1 {
        return Err(Mismatch::Version {
            got: view.version(),
        }
        .into());
    }
    if view.status() != ChannelStatus::Closing as u8 {
        return Err(Mismatch::Status {
            expected: ChannelStatus::Closing as u8,
            got: view.status(),
        }
        .into());
    }
    if view.settled() != expected_settled {
        return Err(Mismatch::Settled {
            expected: expected_settled,
            got: view.settled(),
        }
        .into());
    }
    if view.grace_period() != expected_grace_period {
        return Err(Mismatch::GracePeriod {
            expected: expected_grace_period,
            got: view.grace_period(),
        }
        .into());
    }
    if view.closure_started_at() == 0 {
        return Err(Mismatch::ClosureNotStarted.into());
    }
    Ok(())
}

/// Pure-function classification of a fetched account payload against the
/// on-chain tombstone shape. Mirrors the upstream program's
/// defense-in-depth posture: both the realloc'd length AND the
/// `CLOSED_CHANNEL_DISCRIMINATOR` byte are required.
fn classify_tombstone(data: &[u8]) -> ClassifiedShape {
    match data.len() {
        1 if data[0] == CLOSED_CHANNEL_DISCRIMINATOR => ClassifiedShape::Tombstoned,
        1 => ClassifiedShape::WrongDiscriminator { byte: data[0] },
        n => ClassifiedShape::WrongLength { data_len: n },
    }
}

enum ClassifiedShape {
    Tombstoned,
    WrongDiscriminator { byte: u8 },
    WrongLength { data_len: usize },
}

/// Short-circuit guard for the live-channel verify helpers. Returns
/// `Err` when the fetched payload is the program-emitted tombstone or a
/// 1-byte payload with the wrong discriminator; returns `Ok(())` for any
/// other length so the caller falls through to `ChannelView::from_account_data`,
/// which surfaces wrong-length non-tombstone bytes as `Decode(io::Error)`,
/// the documented behavior for malformed `Channel` bytes.
fn reject_tombstone_shape(data: &[u8]) -> Result<(), VerifyError> {
    match classify_tombstone(data) {
        ClassifiedShape::Tombstoned => Err(VerifyError::Tombstoned),
        ClassifiedShape::WrongDiscriminator { byte } => {
            Err(VerifyError::WrongDiscriminator { byte })
        }
        ClassifiedShape::WrongLength { .. } => Ok(()),
    }
}

/// Result of probing a channel PDA for tombstone state.
///
/// Centralizes the fetch + decode + AccountNotFound classification used by
/// both `verify_tombstoned` (strict) and `verify_finalized_or_absent`
/// (broad). The two public helpers differ only in how they map `Absent`
/// and how they treat the two non-tombstone-but-exists shapes, so the
/// shared boilerplate lives here.
enum TombstoneProbe {
    /// Account exists, `data.len() == 1`, and `data[0] ==
    /// CLOSED_CHANNEL_DISCRIMINATOR` (program-emitted tombstone).
    Tombstoned,
    /// Account exists but `data.len() != 1`.
    WrongLength { data_len: usize },
    /// Account exists with `data.len() == 1` but the byte is not
    /// `CLOSED_CHANNEL_DISCRIMINATOR`.
    WrongDiscriminator { byte: u8 },
    /// Account does not exist on the cluster: either `Ok(value: None)` or
    /// the typed `AccountNotFound` (JSON-RPC code `-32004`).
    Absent,
}

/// Fetch the channel PDA and classify it for tombstone verification.
///
/// Some RPC providers report a missing account as `Ok(value: None)`,
/// others as a typed `RpcResponseError { code: -32004, .. }`. Both are
/// folded into `TombstoneProbe::Absent`. `ClientError.kind` is
/// `Box<ClientErrorKind>` on the 3.x track, hence the `*` deref in the
/// pattern.
async fn tombstone_probe(
    rpc: &dyn RpcClient,
    commitment: CommitmentConfig,
    channel_id: &Pubkey,
) -> Result<TombstoneProbe, VerifyError> {
    match rpc
        .get_ui_account_with_config(channel_id, account_info_config(commitment))
        .await
    {
        Ok(resp) => match resp.value {
            Some(ui_account) => {
                let data = decode_ui_account(channel_id, &ui_account)?;
                Ok(match classify_tombstone(&data) {
                    ClassifiedShape::Tombstoned => TombstoneProbe::Tombstoned,
                    ClassifiedShape::WrongDiscriminator { byte } => {
                        TombstoneProbe::WrongDiscriminator { byte }
                    }
                    ClassifiedShape::WrongLength { data_len } => {
                        TombstoneProbe::WrongLength { data_len }
                    }
                })
            }
            None => Ok(TombstoneProbe::Absent),
        },
        Err(e) => match &*e.kind {
            ClientErrorKind::RpcError(RpcError::RpcResponseError { code: -32004, .. }) => {
                Ok(TombstoneProbe::Absent)
            }
            _ => Err(e.into()),
        },
    }
}

/// Verify post-close state: the PDA exists, `data.len() == 1`, and
/// `data[0] == CLOSED_CHANNEL_DISCRIMINATOR` (the program-emitted
/// tombstone shape).
///
/// Strict variant. Any other outcome is rejected:
/// - account absent (`Ok(value: None)` or RPC `AccountNotFound`) yields
///   `VerifyError::NotFound`,
/// - account exists with `data.len() != 1` yields
///   `VerifyError::WrongLength { data_len }`,
/// - account exists with `data.len() == 1` but `data[0] !=
///   CLOSED_CHANNEL_DISCRIMINATOR` yields
///   `VerifyError::WrongDiscriminator { byte }`.
///
/// Use this whenever the caller needs evidence that the channel was in
/// fact created and then closed by the program. Callers who can also
/// accept "account absent" as evidence of finalization (because they
/// hold independent proof the channel previously existed and was
/// closed) should use `verify_finalized_or_absent` instead.
pub async fn verify_tombstoned(
    rpc: &dyn RpcClient,
    commitment: CommitmentConfig,
    channel_id: &Pubkey,
) -> Result<(), VerifyError> {
    match tombstone_probe(rpc, commitment, channel_id).await? {
        TombstoneProbe::Tombstoned => Ok(()),
        TombstoneProbe::WrongLength { data_len } => Err(VerifyError::WrongLength { data_len }),
        TombstoneProbe::WrongDiscriminator { byte } => {
            Err(VerifyError::WrongDiscriminator { byte })
        }
        TombstoneProbe::Absent => Err(VerifyError::NotFound),
    }
}

/// Verify the channel PDA is either tombstoned (`data.len() == 1` with
/// `data[0] == CLOSED_CHANNEL_DISCRIMINATOR`) or absent on the cluster.
///
/// Broad variant: intentionally weaker than `verify_tombstoned`. It
/// accepts "account absent" (`Ok(value: None)` or RPC `AccountNotFound`,
/// JSON-RPC code `-32004`) as success in addition to the program-emitted
/// tombstone.
///
/// This helper is for callers that already hold independent evidence the
/// channel was created and finalized on-chain (for example, a recorded
/// `close_tx` signature in a local store). Under that precondition,
/// "absent" is acceptable evidence of finalization, since a finalize
/// path that fully reclaims rent is observationally identical to a PDA
/// that never existed.
///
/// Callers WITHOUT such independent evidence MUST use
/// `verify_tombstoned` instead. Otherwise "channel was finalized" and
/// "channel never existed" become indistinguishable, and recovery code
/// will treat unrelated absent PDAs as already-closed.
pub async fn verify_finalized_or_absent(
    rpc: &dyn RpcClient,
    commitment: CommitmentConfig,
    channel_id: &Pubkey,
) -> Result<(), VerifyError> {
    match tombstone_probe(rpc, commitment, channel_id).await? {
        TombstoneProbe::Tombstoned => Ok(()),
        TombstoneProbe::Absent => {
            debug!(
                channel_id = %channel_id,
                "channel PDA absent; accepting as finalized given caller-held close evidence"
            );
            Ok(())
        }
        TombstoneProbe::WrongLength { data_len } => Err(VerifyError::WrongLength { data_len }),
        TombstoneProbe::WrongDiscriminator { byte } => {
            Err(VerifyError::WrongDiscriminator { byte })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognises_canonical_tombstone_at_literal_byte_two() {
        // The literal `2` here is the byte taken straight from upstream's
        // program/payment_channels/src/state/common.rs
        // (AccountDiscriminator::ClosedChannel = 2). DO NOT replace with
        // CLOSED_CHANNEL_DISCRIMINATOR; that would make the test
        // self-referential and lose its drift-detection role.
        assert!(matches!(
            classify_tombstone(&[2u8]),
            ClassifiedShape::Tombstoned
        ));
    }

    #[test]
    fn classify_flags_wrong_discriminator_at_length_one() {
        // AccountDiscriminator::Channel == 1 on-chain; not a valid tombstone.
        assert!(matches!(
            classify_tombstone(&[1]),
            ClassifiedShape::WrongDiscriminator { byte: 1 }
        ));
        // Zero-byte: the program rejects this on every load anyway, but the
        // SDK-side classification still surfaces it as a typed mismatch.
        assert!(matches!(
            classify_tombstone(&[0]),
            ClassifiedShape::WrongDiscriminator { byte: 0 }
        ));
    }

    #[test]
    fn classify_flags_wrong_lengths_including_the_old_speculative_eight() {
        // 8 is the SDK's pre-bump speculative shape; pinning it as a
        // regression sentinel against any future drift back to length-8.
        assert!(matches!(
            classify_tombstone(&[0u8; 8]),
            ClassifiedShape::WrongLength { data_len: 8 }
        ));
        assert!(matches!(
            classify_tombstone(&[]),
            ClassifiedShape::WrongLength { data_len: 0 }
        ));
    }
}
