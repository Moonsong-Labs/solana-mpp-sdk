//! Tracing constants for the session lifecycle.
//!
//! Spans sit on the lifecycle methods (`process_open`, `verify_voucher`,
//! `process_topup`, `process_close`, `recover`). Per-request events
//! (`channel opened`, `voucher accepted`, `channel closed`) are emitted
//! against the `mpp::session` target so a subscriber can filter them as
//! a group.
//!
//! `verify_voucher` runs at `debug` because it fires on every paid
//! request; the rest run at `info`. A subscriber at INFO still sees the
//! `voucher accepted` event but loses the surrounding span context;
//! enable DEBUG on `solana_mpp::server::session` to keep the breadcrumb.

/// Target for session lifecycle events. Route this separately from the
/// per-tx `warn` / `error` lines the handlers also emit.
pub(crate) const TARGET: &str = "mpp::session";

/// `branch` field values recorded on the `session.process_close` span
/// once the handler picks between the two close paths.
pub(crate) const CLOSE_BRANCH_APPLY_VOUCHER: &str = "apply_voucher";
pub(crate) const CLOSE_BRANCH_LOCK_SETTLED: &str = "lock_settled";
