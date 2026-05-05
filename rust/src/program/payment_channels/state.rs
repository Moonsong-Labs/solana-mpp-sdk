//! Channel PDA derivation.
//!
//! The on-chain payment-channels program stores per-channel state under a
//! Program Derived Address (PDA) keyed by the participants, the mint, the
//! authorized off-chain signer, and a caller-supplied salt. The seed order
//! defined here MUST match the program's expected derivation byte-for-byte;
//! a divergence makes `open` create an account the program cannot rediscover
//! on subsequent calls.
//!
//! `Pubkey::find_program_address` performs the bump search and returns the
//! canonical (PDA, bump) pair, where the bump is the largest `u8` such that
//! the seeds plus the bump produce a non-curve address.

use solana_pubkey::Pubkey;

/// Channel PDA seeds: `[b"channel", payer, payee, mint, authorized_signer, salt_le]`.
///
/// Returns the seed slices in the exact order the on-chain program consumes
/// them. `salt_le_bytes` is the little-endian encoding of the channel salt.
pub fn channel_seeds<'a>(
    payer: &'a Pubkey,
    payee: &'a Pubkey,
    mint: &'a Pubkey,
    authorized_signer: &'a Pubkey,
    salt_le_bytes: &'a [u8; 8],
) -> [&'a [u8]; 6] {
    [
        b"channel",
        payer.as_ref(),
        payee.as_ref(),
        mint.as_ref(),
        authorized_signer.as_ref(),
        salt_le_bytes.as_ref(),
    ]
}

/// Derive the canonical `(PDA, bump)` for a channel.
///
/// Encodes `salt` as little-endian bytes, builds the seed array via
/// [`channel_seeds`], and runs `Pubkey::find_program_address` against
/// `program_id` to find the canonical bump.
pub fn find_channel_pda(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    let salt_le = salt.to_le_bytes();
    let seeds = channel_seeds(payer, payee, mint, authorized_signer, &salt_le);
    Pubkey::find_program_address(&seeds, program_id)
}

/// On-chain byte tag for a tombstoned channel PDA.
///
/// Mirrors the value of `AccountDiscriminator::ClosedChannel` declared in
/// upstream's `program/payment_channels/src/state/common.rs` (where the
/// enum carries `#[repr(u8)]` with explicit values `Channel = 1,
/// ClosedChannel = 2`). The codama-generated client at
/// `payment_channels_client::types::AccountDiscriminator` is
/// Borsh-derived without an explicit repr, so `as u8` on it would return
/// the declaration index, not the on-chain byte. Sourced as a literal
/// here, with the upstream reference comment as the tripwire if upstream
/// ever renumbers.
pub const CLOSED_CHANNEL_DISCRIMINATOR: u8 = 2;

/// Typed view over a Channel PDA account. Owns the decoded struct: the
/// Codama-generated `Channel::from_bytes` returns an owned value, so storing
/// a borrow (`&'a Channel`) would borrow from a temporary and fail to
/// compile. Accessors take `&self` and return borrowed or `Copy` field
/// values as appropriate, keeping the API ergonomic for callers.
///
/// Reads from the upstream `payment_channels_client::accounts::Channel` type
/// (Codama-produced). If Codama renames the type at a future upstream rev,
/// adjust the import.
pub struct ChannelView {
    inner: payment_channels_client::accounts::Channel,
}

impl ChannelView {
    /// Decode a Channel PDA account payload. Propagates the underlying
    /// `Channel::from_bytes` `io::Error` so the caller can wrap it in
    /// whatever error type fits its layer.
    pub fn from_account_data(data: &[u8]) -> Result<Self, std::io::Error> {
        let inner = payment_channels_client::accounts::Channel::from_bytes(data)?;
        Ok(Self { inner })
    }
}

// Delegate accessors. These are thin typed getters over `inner`; names match
// the on-chain Channel field list.
//
// The Codama output uses `solana_address::Address` rather than
// `solana_pubkey::Pubkey` for 32-byte account keys. `Pubkey::new_from_array`
// takes `[u8; 32]`, so we go through `.to_bytes()` on the way out; both
// types are wire-equivalent.
//
// Only the accessors required by `verify.rs` and the L1 oracles are exposed
// today. Future call sites that need additional Channel fields
// (e.g. `discriminator`) should add them alongside the call site that uses
// them.
impl ChannelView {
    pub fn version(&self) -> u8 {
        self.inner.version
    }
    pub fn bump(&self) -> u8 {
        self.inner.bump
    }
    pub fn status(&self) -> u8 {
        self.inner.status
    }
    pub fn deposit(&self) -> u64 {
        self.inner.deposit
    }
    pub fn settled(&self) -> u64 {
        self.inner.settled
    }
    /// Cumulative amount the program has paid out across all `distribute`
    /// calls so far. The next `distribute` only moves `settled - paid_out`,
    /// so a stale `paid_out` would let a duplicate `distribute` re-pay the
    /// same pool until escrow runs dry. The L1 distribute oracle asserts
    /// this advances by the distributed sum to close that regression class.
    pub fn paid_out(&self) -> u64 {
        self.inner.paid_out
    }
    pub fn closure_started_at(&self) -> i64 {
        self.inner.closure_started_at
    }
    /// Unix ts of the payer's one-shot refund via `withdraw_payer`; 0 means
    /// the `deposit - settled` refund leg has not run yet. Always 0 for
    /// `Open` and `Closing` channels; advances once the channel is in
    /// `Finalized`.
    pub fn payer_withdrawn_at(&self) -> i64 {
        self.inner.payer_withdrawn_at
    }
    pub fn grace_period(&self) -> u32 {
        self.inner.grace_period
    }
    pub fn distribution_hash(&self) -> [u8; 32] {
        self.inner.distribution_hash
    }
    pub fn payer(&self) -> Pubkey {
        Pubkey::new_from_array(self.inner.payer.to_bytes())
    }
    pub fn payee(&self) -> Pubkey {
        Pubkey::new_from_array(self.inner.payee.to_bytes())
    }
    pub fn authorized_signer(&self) -> Pubkey {
        Pubkey::new_from_array(self.inner.authorized_signer.to_bytes())
    }
    pub fn mint(&self) -> Pubkey {
        Pubkey::new_from_array(self.inner.mint.to_bytes())
    }
}
