//! Client-side session intent: voucher signing, transaction building,
//! single-flight registry, and the high-level fetch entrypoint.

mod active_session;
pub mod paid_response;
pub mod policy;
mod receipt;
pub mod registry;
pub mod session_client;

pub use active_session::ActiveSession;
pub use paid_response::PaidResponse;
pub use policy::{select_session_challenge, ClientPolicy, ResolvedPolicy};
pub use receipt::SessionReceipt;
pub use registry::{OpenedChannel, SessionCell, SessionRegistry};
pub use session_client::{OpenTxBuild, SessionClient};
