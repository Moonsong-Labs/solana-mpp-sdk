//! L0 byte fixtures for splits canonicalization.
//!
//! Pins the preimage layout (`count(1) || entries(n × 34)` where each
//! entry is `recipient(32) || bps(u16 LE)`) and the blake3 digest against
//! hand-computed values. Drift in upstream's preimage shape or the SDK's
//! blake3 dep surfaces here without rebuilding the program `.so`.
//!
//! Also typo-checks the SDK's hand-declared `TREASURY_OWNER` placeholder
//! against a hand-written byte literal in the same file. The real
//! upstream-parity check is the L1 distribute oracle.

use payment_channels_client::types::DistributionEntry;
use solana_address::Address;
use solana_mpp::program::payment_channels::splits::{
    canonical_preimage, distribution_hash, TREASURY_OWNER,
};

#[test]
fn empty_distribution_preimage_is_count_byte_only() {
    let preimage = canonical_preimage(&[]);
    assert_eq!(preimage, vec![0u8]);

    let expected_hash: [u8; 32] = *blake3::hash(&[0u8]).as_bytes();
    assert_eq!(distribution_hash(&[]), expected_hash);
}

#[test]
fn single_entry_pins_layout_and_hash() {
    let entry = DistributionEntry {
        recipient: Address::new_from_array([0x11; 32]),
        bps: 1234,
    };
    let preimage = canonical_preimage(std::slice::from_ref(&entry));

    let mut expected = Vec::with_capacity(35);
    expected.push(1u8);                       // count
    expected.extend_from_slice(&[0x11; 32]);  // recipient
    expected.extend_from_slice(&1234u16.to_le_bytes()); // bps LE
    assert_eq!(preimage, expected);
    assert_eq!(preimage.len(), 1 + 34);

    let expected_hash: [u8; 32] = *blake3::hash(&expected).as_bytes();
    assert_eq!(distribution_hash(&[entry]), expected_hash);
}

#[test]
fn three_entries_pin_layout_and_hash() {
    let entries = [
        DistributionEntry {
            recipient: Address::new_from_array([0x22; 32]),
            bps: 5000,
        },
        DistributionEntry {
            recipient: Address::new_from_array([0x33; 32]),
            bps: 3000,
        },
        DistributionEntry {
            recipient: Address::new_from_array([0x44; 32]),
            bps: 1500,
        },
    ];
    let preimage = canonical_preimage(&entries);

    let mut expected = Vec::with_capacity(1 + 3 * 34);
    expected.push(3u8);
    for (recipient_byte, bps) in [(0x22u8, 5000u16), (0x33, 3000), (0x44, 1500)] {
        expected.extend_from_slice(&[recipient_byte; 32]);
        expected.extend_from_slice(&bps.to_le_bytes());
    }
    assert_eq!(preimage, expected);
    assert_eq!(preimage.len(), 1 + 3 * 34);

    let expected_hash: [u8; 32] = *blake3::hash(&expected).as_bytes();
    assert_eq!(distribution_hash(&entries), expected_hash);
}

#[test]
fn treasury_owner_byte_typo_detector() {
    // Typo-detector for the SDK's hand-declared TREASURY_OWNER. Compares
    // the constant's bytes against the same hand-written literal Tobi
    // typed when first hand-declaring the constant. This catches a
    // single-byte typo in the SDK copy, but it does NOT cross-check
    // against upstream's `program/payment_channels/src/constants.rs` --
    // both literals live in this repo. The real upstream-parity check
    // is the L1 distribute oracle, which exercises the constant by
    // deriving the treasury ATA and running a real distribute ix
    // against the loaded program. Replace before mainnet deploy.
    let expected: [u8; 32] = [
        0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
        0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
        0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
        0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    ];
    assert_eq!(TREASURY_OWNER.to_bytes(), expected);
}

#[test]
fn max_count_32_entries_pin_layout_and_hash() {
    // Upper-bound case. 32 distinct recipients with distinct bps values
    // sum to (1+2+...+32) = 528, well under upstream's 10_000 cap, so
    // the fixture is a legal on-chain configuration as well as the
    // maximum-length input the SDK helper supports without producing a
    // digest no real channel could commit.
    let entries: Vec<DistributionEntry> = (0..32)
        .map(|i| DistributionEntry {
            recipient: Address::new_from_array([(i as u8 + 1); 32]),
            bps: (i as u16) + 1,
        })
        .collect();
    let preimage = canonical_preimage(&entries);

    // Total length: count(1) + 32 * (recipient(32) + bps(2)) = 1089.
    assert_eq!(preimage.len(), 1 + 32 * 34);
    assert_eq!(preimage[0], 32);
    for i in 0..32 {
        let offset = 1 + i * 34;
        let expected_recipient = [(i as u8 + 1); 32];
        assert_eq!(&preimage[offset..offset + 32], &expected_recipient[..]);
        let expected_bps = ((i as u16) + 1).to_le_bytes();
        assert_eq!(&preimage[offset + 32..offset + 34], &expected_bps[..]);
    }

    let expected_hash: [u8; 32] = *blake3::hash(&preimage).as_bytes();
    assert_eq!(distribution_hash(&entries), expected_hash);
}
