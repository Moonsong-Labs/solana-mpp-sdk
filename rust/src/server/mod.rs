//! Server-side MPP support.
//!
//! The server module is split by intent:
//! - [`charge`] handles one-shot Solana charge challenges and verification.
//! - [`session`] handles session challenges, vouchers, and channel lifecycle.
//! - [`html`] renders browser payment-link responses.

pub mod charge;
pub mod html;
pub mod session;

pub use charge::{check_network_blockhash, ChargeOptions, Config, Mpp, VerificationError};
pub use session::{
    FeePayer, Network, OpenChallengeOptions, PayeeSigner, Pricing, RecoveryOptions,
    SessionBuilder, SessionConfig, SessionMethod,
};
