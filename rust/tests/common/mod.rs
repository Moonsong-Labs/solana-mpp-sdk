//! Shared helpers for L1 oracle tests.
//!
//! Cargo treats every top-level file in `tests/` as a separate integration
//! crate, so consumers `mod common;` this module rather than depending on
//! it as a library. Members may go unused in any single oracle, hence the
//! crate-wide `dead_code` allow.

#![allow(dead_code)]

use payment_channels_client::programs::PAYMENT_CHANNELS_ID;
use solana_address::Address;
use solana_pubkey::Pubkey as MppPubkey;

pub fn program_so_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/payment_channels.so")
}

pub fn program_id_address() -> Address {
    PAYMENT_CHANNELS_ID
}

pub fn program_id_mpp() -> MppPubkey {
    MppPubkey::new_from_array(PAYMENT_CHANNELS_ID.to_bytes())
}

/// Bridge a `solana_address::Address` (2.x byte layout used by litesvm) into
/// the SDK's `solana_pubkey::Pubkey` (3.x). Both are 32-byte newtypes; the
/// hop is a no-op at the byte level.
pub fn to_mpp(addr: &Address) -> MppPubkey {
    MppPubkey::new_from_array(addr.to_bytes())
}

/// Read the `amount` field of a classic SPL Token account from raw account
/// bytes. The `Account` layout starts with `mint: Pubkey` (32B) and
/// `owner: Pubkey` (32B), so `amount: u64` (LE) sits at offset `64..72`.
/// Token-2022 accounts share this prefix, so the helper works for both as
/// long as we only need the base balance and not extension state.
pub fn spl_token_amount(account_data: &[u8]) -> u64 {
    let slice: [u8; 8] = account_data
        .get(64..72)
        .expect("token account data shorter than the SPL Account layout")
        .try_into()
        .expect("8-byte slice");
    u64::from_le_bytes(slice)
}
