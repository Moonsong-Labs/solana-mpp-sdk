//! Splits canonicalization for the payment-channels distribute byte
//! contract.
//!
//! Mirrors upstream's `DistributionPreimage` byte layout:
//! `count(u32 LE) || entries(n * 34)` where each entry is
//! `recipient(32 bytes) || bps(u16 little-endian, 2 bytes)`. The blake3
//! digest of that preimage is the value stored in
//! `Channel.distribution_hash` and re-computed by `distribute` on chain.
//!
//! Validation (`Σ bps <= 10_000`, dedup, `count <= 32`, recipient != PDA) is
//! the program's job. The SDK enforces a tighter `MAX_SPLITS = 8` cap at
//! handler entry to keep the close-time tx set under the 1232-byte packet
//! limit. Both functions here are pure byte mechanics so callers can
//! compute hashes for inspection or negative tests without pre-validating
//! the input.

use solana_pubkey::Pubkey;

pub use payment_channels_client::types::DistributionEntry;

/// Treasury owner for distribute residual sweeps on the `Finalized`
/// branch. Hand-declared because the upstream client crate does not
/// re-export the constant from `program/payment_channels/src/constants.rs`.
///
/// The L0 fixture in `tests/session_l0_splits.rs` guards against typos
/// when manually re-syncing this constant after an upstream rev bump:
/// it asserts the bytes here match a hand-written copy. The real
/// upstream-parity check happens in the L1 distribute oracle, which
/// derives the treasury ATA from `TREASURY_OWNER` and submits a real
/// distribute ix against the loaded program; if the SDK's copy drifts
/// from upstream's, the on-chain treasury-account check rejects the
/// transaction and the oracle fails. Replace before mainnet deploy.
pub const TREASURY_OWNER: Pubkey = Pubkey::new_from_array([
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
]);

/// Canonical preimage for a list of active distribution entries.
///
/// Layout: `count(u32 LE) || entries[..count]` where each entry is
/// `recipient(32) || bps(u16 LE)`. Output length is `4 + 34 * entries.len()`.
/// The on-chain validator caps `count` at 32 and rejects longer inputs;
/// this helper is pure byte mechanics and does not enforce the cap.
pub fn canonical_preimage(entries: &[DistributionEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 34 * entries.len());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(entry.recipient.as_ref());
        out.extend_from_slice(&entry.bps.to_le_bytes());
    }
    out
}

/// Blake3 digest of `canonical_preimage(entries)`. The on-chain program
/// computes the same digest via the `sol_blake3` syscall; both produce
/// byte-identical output for any input.
pub fn distribution_hash(entries: &[DistributionEntry]) -> [u8; 32] {
    *blake3::hash(&canonical_preimage(entries)).as_bytes()
}
