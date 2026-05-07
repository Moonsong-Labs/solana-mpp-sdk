//! Program boundary for `Moonsong-Labs/solana-payment-channels`.
//!
//! Everything that touches program bytes lives here. The SDK owns the three
//! byte contracts (voucher signed payload, ed25519 precompile ix, Channel
//! PDA) as hand-written modules; the program
//! source is read-only reference documentation, never vendored. The Codama-
//! generated client is the external `payment_channels_client` crate (pinned
//! by rev in `Cargo.toml`); import directly from
//! `payment_channels_client::{accounts, instructions, programs, types}`
//! anywhere in the SDK. No wrapper module, no re-exports at this layer.
//!
//! Downstream modules (server, client, protocol) consume this module's typed
//! Rust values and never reach into the program boundary layout directly.

// SDK-owned byte-contract implementations.
pub mod voucher;  // 48-byte signed voucher payload + 160-byte ed25519 precompile ix composer
pub mod state;    // Channel PDA derivation + typed ChannelView

// SDK-owned orchestration and RPC helpers.
pub mod ix;
pub mod rpc;
pub mod verify;

// SDK-owned splits canonicalization. Mirrors upstream's preimage layout
// and blake3 digest path so the SDK can compute distribution_hash values
// that match what the on-chain `distribute` ix expects.
pub mod splits;

// Canonical open / top-up tx ix lists. Shared between client (build)
// and server (validate) so the bytes line up at validation time.
pub mod canonical_tx;
