//! Client-side session intent: voucher signing, transaction building,
//! single-flight registry, and the high-level fetch entrypoint.

mod active_session;
mod receipt;

pub use active_session::ActiveSession;
pub use receipt::SessionReceipt;
