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

    #[test]
    fn camel_case_wire_form() {
        let cases = [
            (MppErrorCode::ChallengeUnbound, "\"challengeUnbound\""),
            (MppErrorCode::VoucherOverDeposit, "\"voucherOverDeposit\""),
            (MppErrorCode::InvalidStatusForTopup, "\"invalidStatusForTopup\""),
            (MppErrorCode::RecoveryRpcFailure, "\"recoveryRpcFailure\""),
            (MppErrorCode::RecoveryBatchFailed, "\"recoveryBatchFailed\""),
            (MppErrorCode::StoreUnavailable, "\"storeUnavailable\""),
            (MppErrorCode::RpcUnavailable, "\"rpcUnavailable\""),
            (MppErrorCode::InternalError, "\"internalError\""),
        ];
        for (code, expected) in cases {
            assert_eq!(serde_json::to_string(&code).unwrap(), expected);
        }
    }

    #[test]
    fn round_trips_through_json() {
        let code = MppErrorCode::VoucherCumulativeRegression;
        let json = serde_json::to_string(&code).unwrap();
        let back: MppErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}
