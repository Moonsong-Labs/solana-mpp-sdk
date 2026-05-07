//! Wire-form error codes for 402 problem-json bodies and
//! `Payment-Receipt` headers.
//!
//! `MppErrorCode` is the camelCase token both sides agree on. Servers
//! tag 402 responses with one of these so the client can switch on a
//! stable identifier rather than parsing free-form prose. The same
//! token rides along on `Payment-Receipt` when a receipt carries a
//! non-success status.

use serde::{Deserialize, Serialize};

/// Wire-form error code emitted on 402 responses and receipts.
///
/// Serialised as camelCase: `ChallengeUnbound` becomes
/// `"challengeUnbound"`, `VoucherOverDeposit` becomes
/// `"voucherOverDeposit"`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum MppErrorCode {
    // Challenge lifecycle.
    ChallengeUnbound,
    ChallengeInFlight,
    ChallengeAlreadyUsed,
    /// Wire-form for a duplicate challenge factory call against the
    /// same HMAC id; see `SessionError::ChallengeAlreadyIssued`.
    ChallengeAlreadyIssued,
    ChallengeIntentMismatch,
    ChallengeFieldMismatch,
    ChallengeExpired,

    // Open / topup preflight.
    SplitsMismatch,
    DepositOutOfRange,
    BumpMismatch,
    AtaPreflightFailed,
    OnChainStateMismatch,
    ChannelVersionMismatch,

    // Tx-shape validation.
    MaliciousTx,
    BadFeePayerSlot,
    BlockhashMismatch,

    // Voucher.
    VoucherSignatureInvalid,
    VoucherWrongSigner,
    VoucherCumulativeRegression,
    VoucherOverDeposit,
    VoucherExpired,
    VoucherDeltaTooSmall,

    // Topup-specific.
    InvalidStatusForTopup,
    MaxDepositExceeded,
    InvalidAmount,

    // Close / finalize / withdraw.
    PayerAlreadyWithdrawn,

    // Settlement / on-chain submission.
    OpenTxUnconfirmed,
    TopUpFailed,
    SettleFailed,
    DistributeFailed,

    // Recovery.
    UnsettledRevenueOnStartup,
    RecoveryRpcFailure,
    RecoveryBatchFailed,

    // Infra: server-side dependency unavailable.
    StoreUnavailable,
    RpcUnavailable,

    // Catch-all for unexpected 5xx-class failures.
    InternalError,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_cases() -> [(MppErrorCode, &'static str); 9] {
        [
            (MppErrorCode::ChallengeUnbound, "\"challengeUnbound\""),
            (MppErrorCode::VoucherOverDeposit, "\"voucherOverDeposit\""),
            (MppErrorCode::InvalidStatusForTopup, "\"invalidStatusForTopup\""),
            (MppErrorCode::PayerAlreadyWithdrawn, "\"payerAlreadyWithdrawn\""),
            (MppErrorCode::RecoveryRpcFailure, "\"recoveryRpcFailure\""),
            (MppErrorCode::RecoveryBatchFailed, "\"recoveryBatchFailed\""),
            (MppErrorCode::StoreUnavailable, "\"storeUnavailable\""),
            (MppErrorCode::RpcUnavailable, "\"rpcUnavailable\""),
            (MppErrorCode::InternalError, "\"internalError\""),
        ]
    }

    #[test]
    fn camel_case_wire_form() {
        for (code, expected) in wire_cases() {
            assert_eq!(serde_json::to_string(&code).unwrap(), expected);
        }
    }

    #[test]
    fn round_trips_through_json() {
        for (code, _) in wire_cases() {
            let json = serde_json::to_string(&code).unwrap();
            let back: MppErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, back);
        }
    }

    // Pin upstream's PayerAlreadyWithdrawn discriminant. Drift here means the
    // wire form mismatches the on-chain emitter.
    #[test]
    fn upstream_payer_already_withdrawn_discriminant_is_pinned() {
        use payment_channels_client::errors::PaymentChannelsError;
        assert_eq!(PaymentChannelsError::PayerAlreadyWithdrawn as u32, 0x26);
    }
}
