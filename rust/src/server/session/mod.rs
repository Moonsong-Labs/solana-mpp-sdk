//! Session intent server-side lifecycle.
//!
//! Public surface (assembled across this directory):
//!
//! - [`SessionConfig`]: operator-supplied configuration.
//! - [`SessionMethod`]: not directly constructible, only
//!   `SessionBuilder::recover().await?` produces one.
//! - [`SessionBuilder`]: builder with `with_store` / `with_rpc` /
//!   `with_recovery_options` / `recover`.
//!
//! Submodule layout:
//!
//! - [`challenge`]: challenge cache, intent binding, sweeper.
//! - [`open`] / [`voucher`] / [`topup`] / [`close`]: per-action handlers.
//! - [`ix`]: settle-bundle assembly.
//! - [`recover`]: two-phase startup recovery.
//!
//! The skeleton is intentionally empty for now; each action handler lands
//! in its own follow-up alongside its tests.

pub mod challenge;
pub mod close;
pub mod ix;
pub mod open;
pub mod recover;
pub mod topup;
pub mod voucher;
