//! Session intent wire types, aligned to:
//! - `Moonsong-Labs/solana-payment-channels` — `docs/002-http-protocol.md` (HTTP routes,
//!   credential envelopes).
//! - `Moonsong-Labs/solana-payment-channels` — `docs/001-payment-channel-state-machine.md`
//!   (Voucher shape; Borsh-signed bytes).
//! - `solana-foundation/mpp-specs` — `draft-solana-session-00` (envelope shape).
//!
//! Notable divergence vs draft-00: vouchers are signed over the 48-byte Borsh
//! payload (`build_signed_payload`), not over JCS-canonical JSON.

use serde::{Deserialize, Serialize};

// ── Voucher ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherData {
    pub channel_id: String,            // base58 Channel PDA
    pub cumulative_amount: String,     // u64 decimal
    /// RFC3339 wire format. `None` means "no expiry"; the field is omitted
    /// from the JSON rather than rendered as `"1970-01-01T00:00:00Z"`.
    /// `Some(0)` is collapsed to `None` at the client emission boundary
    /// (see `ActiveSession::sign_voucher`) so the on-chain `i64` slot for
    /// an absent expiry consistently reads as zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigType {
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedVoucher {
    pub voucher: VoucherData,
    pub signer: String,                // base58 Ed25519 public key
    pub signature: String,             // base58 Ed25519 signature over borsh(Voucher)
    pub signature_type: SigType,
}

// ── Challenge request (MPP `request` auth-param, post-base64url + JCS) ─────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    pub amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_type: Option<String>,
    pub recipient: String,             // primary payee pubkey (base58)
    pub currency: String,              // mint pubkey (base58)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub method_details: MethodDetails,
}

/// Reused across all four session challenge phases (open, voucher, topup,
/// close); field optionality reflects "needed at this phase," not "server
/// doesn't have a value."
///
/// - Required for the client to build the open ix: `channel_program`,
///   `minimum_deposit`, `distribution_splits`.
/// - Open-time advisory, on-chain authoritative thereafter:
///   `grace_period_seconds`, `ttl_seconds`, `min_voucher_delta`. Pinned
///   into the `Channel` account at open; later challenges for a live
///   channel may omit them and verifiers read from chain
///   (`ChannelView::grace_period`, `verify_closing`).
/// - Server-co-signed flow only (present together): `fee_payer`,
///   `fee_payer_key`, `recent_blockhash`. See the `recent_blockhash` field
///   doc for why it has to be server-supplied in that flow.
/// - Hint, not a binding: `network` (the client typically already knows it
///   from its configured RPC endpoint; inherited from the charge intent's
///   `MethodDetails`). Resume hint: `channel_id`.
///
/// Wire deserialization does not enforce required-at-open: a server sending
/// e.g. `grace_period_seconds: None` on an open challenge slips past serde.
/// That check belongs in the server's open handler, not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub channel_program: String,       // program_id (base58)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,    // resume
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer_key: Option<String>,
    /// Base58-encoded Solana `Hash`. Blockhash the client MUST use when building
    /// the open/topup/close tx; server commits to this value for the co-sign and
    /// will NOT refresh it. If the blockhash expires before submit, the client
    /// must fetch a fresh 402 challenge and rebuild the tx. Present whenever
    /// `fee_payer_key` is present (the server-co-signed flow, where the server
    /// supplies both the fee payer and the blockhash the client must build over).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_voucher_delta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_seconds: Option<u32>,
    /// Merchant-advertised splits attached to the open challenge.
    ///
    /// Wire shape (this is the SDK's serialization contract, independent of
    /// how the on-chain account stores splits): `0..=MAX_SPLITS` entries,
    /// every `shareBps` in `1..=10_000`, `Σ shareBps <= 10_000`. The
    /// remainder `10_000 - Σ shareBps` is the payee's implicit share,
    /// including the "everything to payee" case (empty array).
    ///
    /// `wire_to_typed` enforces the per-entry bounds; the sum check and the
    /// translation into the `distribution_hash` preimage stay with the
    /// canonicalization layer (`splits.rs`).
    ///
    /// Note that the on-chain account at the currently pinned upstream rev
    /// still records fixed per-recipient amounts. The bps form here is the
    /// forward-aligned shape that pairs with the upstream `distribute` ix
    /// that introduces the bps `InvalidSplitConfig` rule; the L1 oracles
    /// build the legacy amount form directly and bypass the wire/typed
    /// bridge.
    pub distribution_splits: Vec<BpsSplit>,
    pub minimum_deposit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BpsSplit {
    pub recipient: String,
    pub share_bps: u16,
}

// ── Internal typed split (typed twin of BpsSplit) ──────────────────────────
//
// `BpsSplit` above is the wire form (base58 `String` recipients). `Split`
// below is the internal typed form stored in `ChannelRecord` and passed to
// low-level builders. Base58 ↔ `Pubkey` conversion happens exactly once, at
// the wire boundary via `wire_to_typed` / `typed_to_wire`. Downstream
// handlers and recovery never re-parse strings; invalid base58 is rejected
// at `store.insert` before any record is persisted.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Split {
    Bps {
        recipient: solana_pubkey::Pubkey,
        share_bps: u16,
    },
}

/// Decode wire `BpsSplit`s (base58 recipient strings) into the internal
/// `Split::Bps` form. Rejects non-canonical base58, wrong-length decodes,
/// `share_bps == 0`, or `share_bps > 10_000` via the supplied error mapper.
/// Callers at the wire boundary (`store.insert`, handler entry points) map
/// to `StoreError::Serialization` or `SessionError::InvalidSplit`.
///
/// The bounds mirror the on-chain `InvalidSplitConfig` rule: every entry's
/// `shareBps` is in `1..=10_000` and `Σ shareBps ≤ 10_000` (the wire layer
/// enforces only the per-entry bound; the sum check stays with the
/// canonicalization layer that builds the `distribution_hash` preimage).
pub fn wire_to_typed<E>(
    splits: &[BpsSplit],
    mut err: impl FnMut(String) -> E,
) -> Result<Vec<Split>, E> {
    splits
        .iter()
        .map(|s| {
            if s.share_bps == 0 {
                return Err(err(
                    "share_bps must be > 0; zero entries are rejected on-chain".into(),
                ));
            }
            if s.share_bps > 10_000 {
                return Err(err(format!(
                    "share_bps must be <= 10000, got {}",
                    s.share_bps
                )));
            }
            let bytes = bs58::decode(&s.recipient)
                .into_vec()
                .map_err(|e| err(format!("non-canonical base58 in split recipient: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| err("split recipient must decode to 32 bytes".into()))?;
            Ok(Split::Bps {
                recipient: solana_pubkey::Pubkey::new_from_array(arr),
                share_bps: s.share_bps,
            })
        })
        .collect()
}

/// Re-encode internal `Split` values to the wire `BpsSplit` form. Infallible:
/// `Pubkey` is always round-trippable to base58.
pub fn typed_to_wire(splits: &[Split]) -> Vec<BpsSplit> {
    splits
        .iter()
        .map(|s| match s {
            Split::Bps { recipient, share_bps } => BpsSplit {
                recipient: bs58::encode(recipient.as_ref()).into_string(),
                share_bps: *share_bps,
            },
        })
        .collect()
}

// ── Credential actions (Authorization header / POST bodies) ────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum SessionAction {
    Open(OpenPayload),
    /// Flattened: wire form is
    /// `{"action":"voucher", "voucher":{...}, "signer":"...", "signature":"...",
    ///   "signatureType":"ed25519"}`, the `SignedVoucher` fields sit beside
    /// the action tag, no nested voucher wrapper.
    Voucher(SignedVoucher),
    TopUp(TopUpPayload),
    Close(ClosePayload),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPayload {
    pub challenge_id: String,
    pub channel_id: String,
    pub payer: String,
    pub payee: String,
    pub mint: String,
    pub authorized_signer: String,
    pub salt: String,                  // u64 decimal
    pub bump: u8,                      // advisory; server re-derives canonical
    pub deposit_amount: String,
    /// Splits the client commits to at open. Same shape rules as
    /// `MethodDetails::distribution_splits` (`0..=MAX_SPLITS` entries,
    /// every `shareBps > 0`, `Σ shareBps ≤ 10_000`, payee implicit
    /// remainder). Server validates these match the cached challenge's
    /// splits before submitting the open transaction.
    pub distribution_splits: Vec<BpsSplit>,
    pub transaction: String,           // base64 partial-signed open tx
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopUpPayload {
    // The topup flow binds the on-chain `top_up` to the challenge issued in the
    // prior 402, so a topup not preceded by a fresh challenge is rejected.
    pub challenge_id: String,
    pub channel_id: String,
    pub additional_amount: String,
    pub transaction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClosePayload {
    pub challenge_id: String,
    pub channel_id: String,
    /// `Some` when `cumulative > on-chain settled`. `None` when nothing new to commit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher: Option<SignedVoucher>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // 32 bytes of `0x11` rendered as base58. Stable across runs; used as a
    // valid recipient payload that decodes back to a 32-byte Pubkey.
    fn valid_recipient_b58() -> String {
        bs58::encode([0x11u8; 32]).into_string()
    }

    #[test]
    fn wire_to_typed_accepts_valid_split() {
        let splits = vec![BpsSplit {
            recipient: valid_recipient_b58(),
            share_bps: 7_500,
        }];
        let typed = wire_to_typed(&splits, |m| m).expect("valid split decodes");
        assert_eq!(typed.len(), 1);
        match &typed[0] {
            Split::Bps {
                recipient,
                share_bps,
            } => {
                assert_eq!(recipient.to_bytes(), [0x11u8; 32]);
                assert_eq!(*share_bps, 7_500);
            }
        }
    }

    #[test]
    fn wire_to_typed_rejects_zero_share_bps() {
        let splits = vec![BpsSplit {
            recipient: valid_recipient_b58(),
            share_bps: 0,
        }];
        let err = wire_to_typed(&splits, |m| m).unwrap_err();
        assert!(
            err.contains("share_bps must be > 0"),
            "expected zero-bps rejection, got: {err}"
        );
    }

    #[test]
    fn wire_to_typed_rejects_share_bps_above_cap() {
        let splits = vec![BpsSplit {
            recipient: valid_recipient_b58(),
            share_bps: 10_001,
        }];
        let err = wire_to_typed(&splits, |m| m).unwrap_err();
        assert!(
            err.contains("share_bps must be <= 10000"),
            "expected over-cap rejection, got: {err}"
        );
    }

    #[test]
    fn wire_to_typed_rejects_non_base58_recipient() {
        let splits = vec![BpsSplit {
            recipient: "not!base58".into(),
            share_bps: 5_000,
        }];
        let err = wire_to_typed(&splits, |m| m).unwrap_err();
        assert!(
            err.contains("non-canonical base58"),
            "expected base58 rejection, got: {err}"
        );
    }

    #[test]
    fn wire_to_typed_rejects_wrong_length_recipient() {
        // 16 bytes of base58 — decodes successfully but to the wrong length.
        let splits = vec![BpsSplit {
            recipient: bs58::encode([0x22u8; 16]).into_string(),
            share_bps: 5_000,
        }];
        let err = wire_to_typed(&splits, |m| m).unwrap_err();
        assert!(
            err.contains("must decode to 32 bytes"),
            "expected length rejection, got: {err}"
        );
    }

    #[test]
    fn wire_to_typed_accepts_empty_splits() {
        // `0..=MAX_SPLITS` allows zero entries; the payee absorbs the full
        // deposit via the implicit-remainder rule documented on
        // `MethodDetails::distribution_splits`.
        let typed = wire_to_typed::<String>(&[], |m| m).expect("empty splits decode");
        assert!(typed.is_empty());
    }

    #[test]
    fn wire_typed_roundtrip_preserves_values() {
        let splits = vec![
            BpsSplit {
                recipient: valid_recipient_b58(),
                share_bps: 6_000,
            },
            BpsSplit {
                recipient: bs58::encode([0x22u8; 32]).into_string(),
                share_bps: 3_000,
            },
        ];
        let typed = wire_to_typed(&splits, |m| m).expect("decode");
        let back = typed_to_wire(&typed);
        assert_eq!(back, splits);
    }
}
