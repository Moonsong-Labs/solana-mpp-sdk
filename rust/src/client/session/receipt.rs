//! Receipt body the client receives from the server.
//!
//! Only the two fields `ActiveSession::on_receipt_accepted` needs to
//! advance its watermark; the rest of the receipt shape lands when
//! `PaidResponse` does.

/// Receipt body returned by the server on a session payment.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionReceipt {
    /// Channel id the receipt is bound to, base58. Mirrors the `reference`
    /// field on the wire-form receipt.
    pub reference: String,
    /// Cumulative the server acknowledged consuming.
    pub accepted_cumulative: u64,
}
