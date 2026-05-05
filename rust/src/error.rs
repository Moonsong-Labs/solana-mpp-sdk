//! SDK-wide error types.
//!
//! Two enums:
//!
//! - `Error` is the older charge-intent surface, a flat enum for the
//!   one-shot pay-once flow. Kept as-is so the charge code path doesn't
//!   churn.
//! - `SessionError` is the typed surface for the session intent. Each
//!   variant maps to an HTTP status and a stable `MppErrorCode` so 402
//!   responses, receipts, and observability all key off the same id.

use http::StatusCode;
use solana_pubkey::Pubkey;
use solana_signature::Signature;

use crate::protocol::core::MppErrorCode;
use crate::store::{ChannelStatus, StoreError};

/// Errors produced by the Solana MPP charge intent.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Transaction not found or not yet confirmed")]
    TransactionNotFound,

    #[error("Transaction failed on-chain: {0}")]
    TransactionFailed(String),

    #[error("No matching transfer instruction found")]
    NoTransferInstruction,

    #[error("Amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: String, actual: String },

    #[error("Recipient mismatch: expected {expected}, got {actual}")]
    RecipientMismatch { expected: String, actual: String },

    #[error("Token mint mismatch: expected {expected}, got {actual}")]
    MintMismatch { expected: String, actual: String },

    #[error("Destination ATA does not belong to expected recipient")]
    AtaMismatch,

    #[error("Transaction signature already consumed")]
    SignatureConsumed,

    #[error("Simulation failed: {0}")]
    SimulationFailed(String),

    #[error("Missing transaction data in credential payload")]
    MissingTransaction,

    #[error("Missing signature in credential payload")]
    MissingSignature,

    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(String),

    #[error("Splits consume the entire amount")]
    SplitsExceedAmount,

    #[error("Splits exceed maximum of 8 entries")]
    TooManySplits,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Challenge expired at {0}")]
    ChallengeExpired(String),

    #[error("Challenge ID mismatch — not issued by this server")]
    ChallengeMismatch,

    #[error("{0}")]
    Other(String),
}

/// Result type alias for the charge intent.
pub type Result<T> = std::result::Result<T, Error>;

// ── Session intent error surface ──────────────────────────────────────────

/// Opaque wrapper around RPC errors, decoupled from any specific
/// `solana-client` major version.
///
/// Carries a stringified message. Callers that want structured handling
/// should branch on [`SessionError::code`] rather than peering inside;
/// that keeps the public error surface stable when upstream bumps the
/// RPC client.
///
/// Inner field is private and the type is `#[non_exhaustive]` so we can
/// add endpoint / status / body fields later without breaking callers.
/// Use [`RpcError::message`] to read the payload.
#[derive(Debug, Clone, thiserror::Error)]
#[error("rpc error: {0}")]
#[non_exhaustive]
pub struct RpcError(String);

impl RpcError {
    /// Stringified RPC failure message.
    ///
    /// Branch on [`MppErrorCode`] for routing; use this for the
    /// underlying context when rendering logs.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl From<solana_client::client_error::ClientError> for RpcError {
    fn from(e: solana_client::client_error::ClientError) -> Self {
        // `{e:#}` walks the source chain so we see endpoint/status/body
        // instead of just the top-level summary.
        Self(format!("{e:#}"))
    }
}

/// Channel lifecycle as recovery sees it.
///
/// `Absent` is the recovery-only state for a PDA the cluster has never
/// seen or has GC'd. The rest mirrors the on-chain `Status` byte plus
/// the `Tombstoned` close marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OnChainChannelStatus {
    Open,
    Closing,
    Finalized,
    Tombstoned,
    Absent,
}

/// Typed reason a single channel failed recovery.
///
/// Covers the four shapes the inspect phase produces: unsettled
/// revenue lying around at startup, an RPC fetch that failed, stored
/// status disagreeing with on-chain in a way we can't reconcile, or a
/// `verify_open` field check failing during inspection.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RecoveryFailureKind {
    #[error("unsettled revenue on startup ({unsettled} units)")]
    UnsettledRevenue { unsettled: u64 },

    #[error("rpc failure: {message}")]
    RpcFailure {
        // Stringified so the recovery surface stays version-agnostic.
        // Field is `message` rather than `source` because thiserror would
        // otherwise treat a `source` field as a source-chain link and
        // require `std::error::Error`.
        message: String,
    },

    #[error("state inversion: stored {stored:?}, on-chain {on_chain:?}")]
    StateInversion {
        stored: ChannelStatus,
        on_chain: OnChainChannelStatus,
    },

    #[error("verify_open mismatch on field {field}")]
    VerifyOpenMismatch { field: &'static str },
}

/// One channel's failure inside `RecoveryBatchFailed`.
///
/// Startup recovery inspects every persisted channel before touching
/// the store. Either every outcome applies, or this batch comes back.
/// Each failure pairs the channel id with a typed reason so operators
/// can route on it without parsing strings.
#[derive(Debug, Clone, thiserror::Error)]
#[error("channel {channel_id}: {kind}")]
#[non_exhaustive]
pub struct RecoveryFailure {
    pub channel_id: Pubkey,
    #[source]
    pub kind: RecoveryFailureKind,
}

/// Errors from the session intent server lifecycle.
///
/// Each variant maps to an HTTP status via [`SessionError::http_status`]
/// and a wire-form code via [`SessionError::code`]. Handlers carry the
/// typed enum internally and only render at the response boundary, so
/// "what happened" stays separate from "how to ship it on the wire".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    // ── Challenge lifecycle ───────────────────────────────────────────────
    #[error("challenge id absent, expired, or already consumed")]
    ChallengeUnbound,

    #[error("a request bound to this challenge is already in flight")]
    ChallengeInFlight,

    #[error("challenge id has already been used")]
    ChallengeAlreadyUsed,

    #[error("challenge intent does not match the request")]
    ChallengeIntentMismatch,

    #[error("challenge field {field} mismatch: advertised {advertised}, got {got}")]
    ChallengeFieldMismatch {
        field: &'static str,
        advertised: String,
        got: String,
    },

    #[error("challenge expired: age {age}s exceeds max {max}s")]
    ChallengeExpired { age: u64, max: u64 },

    // ── Open / topup preflight ────────────────────────────────────────────
    #[error("splits hash mismatch: expected {expected_hash:x?}, got {got_hash:x?}")]
    SplitsMismatch {
        expected_hash: [u8; 32],
        got_hash: [u8; 32],
    },

    #[error("deposit {got} out of range [{min}, {max}]")]
    DepositOutOfRange { min: u64, max: u64, got: u64 },

    #[error("bump mismatch: canonical {canonical}, got {got}")]
    BumpMismatch { canonical: u8, got: u8 },

    #[error("ata preflight failed for recipient {recipient}: {cause}")]
    AtaPreflightFailed { recipient: Pubkey, cause: String },

    #[error("on-chain state mismatch on field {field}: expected {expected}, got {got}")]
    OnChainStateMismatch {
        field: &'static str,
        expected: String,
        got: String,
    },

    #[error("channel version mismatch: supported {supported}, got {got}")]
    ChannelVersionMismatch { supported: u8, got: u8 },

    // ── Tx-shape validation ───────────────────────────────────────────────
    #[error("malicious or malformed transaction: {reason}")]
    MaliciousTx { reason: String },

    #[error("fee-payer in wrong transaction slot: expected {expected}, got {got}")]
    BadFeePayerSlot { expected: Pubkey, got: Pubkey },

    #[error("recent blockhash mismatch: expected {expected}, got {got}")]
    BlockhashMismatch { expected: String, got: String },

    // ── Voucher ───────────────────────────────────────────────────────────
    #[error("voucher signature failed verification")]
    VoucherSignatureInvalid,

    #[error("voucher signed by wrong key: expected {expected}, got {got}")]
    VoucherWrongSigner { expected: Pubkey, got: Pubkey },

    #[error("voucher cumulative regressed: stored {stored}, got {got}")]
    VoucherCumulativeRegression { stored: u64, got: u64 },

    #[error("voucher cumulative {got} exceeds deposit cap {deposit}")]
    VoucherOverDeposit { deposit: u64, got: u64 },

    #[error("voucher expired: now {now} >= expires_at {expires_at}")]
    VoucherExpired { now: i64, expires_at: i64 },

    #[error("voucher delta below minimum: min {min}, got {got}")]
    VoucherDeltaTooSmall { min: u64, got: u64 },

    // ── Topup-specific ────────────────────────────────────────────────────
    #[error("invalid status for topup: channel is {status:?}")]
    InvalidStatusForTopup { status: ChannelStatus },

    #[error("topup would exceed max deposit: current {current} + additional {additional} > max {max}")]
    MaxDepositExceeded {
        current: u64,
        additional: u64,
        max: u64,
    },

    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    // ── Settlement / on-chain submission ──────────────────────────────────
    #[error("open transaction {0} did not confirm")]
    OpenTxUnconfirmed(Signature),

    #[error("topup tx {0} failed: {1}")]
    TopUpFailed(Signature, String),

    #[error("settle tx {0} failed: {1}")]
    SettleFailed(Signature, String),

    #[error("distribute tx {0} failed: {1}")]
    DistributeFailed(Signature, String),

    // ── Recovery ──────────────────────────────────────────────────────────
    #[error("channel {channel_id}: unsettled revenue on startup ({unsettled} units)")]
    UnsettledRevenueOnStartup { channel_id: Pubkey, unsettled: u64 },

    #[error("recovery rpc failure for channel {channel_id}: {source}")]
    RecoveryRpcFailure {
        channel_id: Pubkey,
        #[source]
        source: RpcError,
    },

    #[error("recovery batch failed: {} failure(s)", .failures.len())]
    RecoveryBatchFailed { failures: Vec<RecoveryFailure> },

    // ── Infra ─────────────────────────────────────────────────────────────
    #[error("store unavailable: {0}")]
    StoreUnavailable(#[from] StoreError),

    #[error("rpc unavailable: {0}")]
    RpcUnavailable(#[from] RpcError),

    /// Catch-all for unexpected server-side failures (5xx to the
    /// client). Prefer a typed variant for anything operators will
    /// want to route on.
    #[error("internal server error: {0}")]
    InternalError(String),
}

impl From<solana_client::client_error::ClientError> for SessionError {
    fn from(e: solana_client::client_error::ClientError) -> Self {
        SessionError::RpcUnavailable(RpcError::from(e))
    }
}

impl SessionError {
    /// Wire-form code emitted on 402 responses and receipts.
    pub fn code(&self) -> MppErrorCode {
        use MppErrorCode as C;
        match self {
            SessionError::ChallengeUnbound => C::ChallengeUnbound,
            SessionError::ChallengeInFlight => C::ChallengeInFlight,
            SessionError::ChallengeAlreadyUsed => C::ChallengeAlreadyUsed,
            SessionError::ChallengeIntentMismatch => C::ChallengeIntentMismatch,
            SessionError::ChallengeFieldMismatch { .. } => C::ChallengeFieldMismatch,
            SessionError::ChallengeExpired { .. } => C::ChallengeExpired,
            SessionError::SplitsMismatch { .. } => C::SplitsMismatch,
            SessionError::DepositOutOfRange { .. } => C::DepositOutOfRange,
            SessionError::BumpMismatch { .. } => C::BumpMismatch,
            SessionError::AtaPreflightFailed { .. } => C::AtaPreflightFailed,
            SessionError::OnChainStateMismatch { .. } => C::OnChainStateMismatch,
            SessionError::ChannelVersionMismatch { .. } => C::ChannelVersionMismatch,
            SessionError::MaliciousTx { .. } => C::MaliciousTx,
            SessionError::BadFeePayerSlot { .. } => C::BadFeePayerSlot,
            SessionError::BlockhashMismatch { .. } => C::BlockhashMismatch,
            SessionError::VoucherSignatureInvalid => C::VoucherSignatureInvalid,
            SessionError::VoucherWrongSigner { .. } => C::VoucherWrongSigner,
            SessionError::VoucherCumulativeRegression { .. } => C::VoucherCumulativeRegression,
            SessionError::VoucherOverDeposit { .. } => C::VoucherOverDeposit,
            SessionError::VoucherExpired { .. } => C::VoucherExpired,
            SessionError::VoucherDeltaTooSmall { .. } => C::VoucherDeltaTooSmall,
            SessionError::InvalidStatusForTopup { .. } => C::InvalidStatusForTopup,
            SessionError::MaxDepositExceeded { .. } => C::MaxDepositExceeded,
            SessionError::InvalidAmount(_) => C::InvalidAmount,
            SessionError::OpenTxUnconfirmed(_) => C::OpenTxUnconfirmed,
            SessionError::TopUpFailed(_, _) => C::TopUpFailed,
            SessionError::SettleFailed(_, _) => C::SettleFailed,
            SessionError::DistributeFailed(_, _) => C::DistributeFailed,
            SessionError::UnsettledRevenueOnStartup { .. } => C::UnsettledRevenueOnStartup,
            SessionError::RecoveryRpcFailure { .. } => C::RecoveryRpcFailure,
            SessionError::RecoveryBatchFailed { .. } => C::RecoveryBatchFailed,
            SessionError::StoreUnavailable(_) => C::StoreUnavailable,
            SessionError::RpcUnavailable(_) => C::RpcUnavailable,
            SessionError::InternalError(_) => C::InternalError,
        }
    }

    /// HTTP status to render on the response.
    ///
    /// `402` is the normal client-facing protocol bucket (challenge,
    /// voucher, deposit, splits).
    ///
    /// `409` is for well-formed requests that conflict with current
    /// state: `MaliciousTx`, `BlockhashMismatch`,
    /// `InvalidStatusForTopup`, `OnChainStateMismatch`. Re-signing
    /// won't help.
    ///
    /// `503` is for transient broadcast or preflight failures that
    /// happened after a valid signed payload reached us (RPC dropped,
    /// validator congestion, blockhash expired, `CreateIdempotent`
    /// preflight failed). Standard "retry later".
    ///
    /// `500` is recovery and infra failures the operator has to fix.
    pub fn http_status(&self) -> StatusCode {
        match self {
            // 409: well-formed request, conflicting state.
            SessionError::MaliciousTx { .. }
            | SessionError::BlockhashMismatch { .. }
            | SessionError::InvalidStatusForTopup { .. }
            | SessionError::OnChainStateMismatch { .. } => StatusCode::CONFLICT,

            // 503: transient server-side broadcast and preflight
            // failures; re-signing on the client won't help.
            SessionError::OpenTxUnconfirmed(_)
            | SessionError::TopUpFailed(_, _)
            | SessionError::SettleFailed(_, _)
            | SessionError::DistributeFailed(_, _)
            | SessionError::AtaPreflightFailed { .. } => StatusCode::SERVICE_UNAVAILABLE,

            // 500: recovery and infra failures.
            SessionError::UnsettledRevenueOnStartup { .. }
            | SessionError::RecoveryRpcFailure { .. }
            | SessionError::RecoveryBatchFailed { .. }
            | SessionError::StoreUnavailable(_)
            | SessionError::RpcUnavailable(_)
            | SessionError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // Everything else: 402, client can fix it.
            _ => StatusCode::PAYMENT_REQUIRED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_errors_are_402_with_typed_codes() {
        assert_eq!(
            SessionError::ChallengeUnbound.http_status(),
            StatusCode::PAYMENT_REQUIRED
        );
        assert_eq!(
            SessionError::ChallengeUnbound.code(),
            MppErrorCode::ChallengeUnbound
        );
    }

    #[test]
    fn voucher_errors_are_402() {
        let cases = [
            SessionError::VoucherSignatureInvalid,
            SessionError::VoucherCumulativeRegression {
                stored: 100,
                got: 50,
            },
            SessionError::VoucherOverDeposit {
                deposit: 1_000,
                got: 1_500,
            },
            SessionError::VoucherDeltaTooSmall { min: 100, got: 50 },
            SessionError::VoucherExpired {
                now: 200,
                expires_at: 100,
            },
        ];
        for err in cases {
            assert_eq!(err.http_status(), StatusCode::PAYMENT_REQUIRED, "{err}");
        }
    }

    #[test]
    fn on_chain_state_mismatch_is_409() {
        let err = SessionError::OnChainStateMismatch {
            field: "deposit",
            expected: "1000".into(),
            got: "999".into(),
        };
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(err.code(), MppErrorCode::OnChainStateMismatch);
    }

    #[test]
    fn ata_preflight_failed_is_503() {
        let err = SessionError::AtaPreflightFailed {
            recipient: Pubkey::new_from_array([3u8; 32]),
            cause: "create_idempotent rejected".into(),
        };
        assert_eq!(err.http_status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code(), MppErrorCode::AtaPreflightFailed);
    }

    #[test]
    fn malicious_tx_blockhash_mismatch_and_invalid_topup_status_are_409() {
        assert_eq!(
            SessionError::MaliciousTx {
                reason: "x".into()
            }
            .http_status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            SessionError::BlockhashMismatch {
                expected: "abc".into(),
                got: "def".into(),
            }
            .http_status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            SessionError::InvalidStatusForTopup {
                status: ChannelStatus::Closing
            }
            .http_status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn broadcast_failures_are_503() {
        let sig = Signature::default();
        let cases: [SessionError; 4] = [
            SessionError::OpenTxUnconfirmed(sig),
            SessionError::TopUpFailed(sig, "rpc dropped".into()),
            SessionError::SettleFailed(sig, "blockhash expired".into()),
            SessionError::DistributeFailed(sig, "validator congested".into()),
        ];
        for err in cases {
            assert_eq!(err.http_status(), StatusCode::SERVICE_UNAVAILABLE, "{err}");
        }
    }

    #[test]
    fn recovery_and_infra_errors_are_500() {
        assert_eq!(
            SessionError::UnsettledRevenueOnStartup {
                channel_id: Pubkey::new_from_array([1u8; 32]),
                unsettled: 999,
            }
            .http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let store_err: SessionError = StoreError::Timeout.into();
        assert_eq!(store_err.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(store_err.code(), MppErrorCode::StoreUnavailable);

        let rpc_err: SessionError = RpcError("connection reset".into()).into();
        assert_eq!(rpc_err.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(rpc_err.code(), MppErrorCode::RpcUnavailable);
    }

    #[test]
    fn recovery_failure_carries_typed_kind() {
        let f = RecoveryFailure {
            channel_id: Pubkey::new_from_array([7u8; 32]),
            kind: RecoveryFailureKind::UnsettledRevenue { unsettled: 42 },
        };
        let err: SessionError = SessionError::RecoveryBatchFailed { failures: vec![f] };
        assert_eq!(err.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code(), MppErrorCode::RecoveryBatchFailed);
    }
}
