//! Canonical instruction list for the open and top-up transactions.
//!
//! The open and top-up txs have a fixed instruction order: a compute-budget
//! prelude (price then limit), zero or more `CreateIdempotent` ATA ixs at
//! open time (none at top-up; the channel vault was created during open),
//! and the upstream payment-channels ix at the tail. This ordering is part
//! of the byte contract between client and server. Both sides build the
//! list through the helpers below so the resulting `Vec<Instruction>` is
//! byte-equal between caller and validator. A client that re-orders or
//! inserts ixs gets rejected at the slot-by-slot byte compare in
//! `server/session/tx_shape::validate_canonical_multi_ix_tx_shape`.
//!
//! Recipient ATA ordering matches the input order of `splits`. The same
//! order feeds `splits::canonical_preimage`, so a client that reshuffles
//! splits is caught at the splits-hash check too.

use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use payment_channels_client::instructions::{OpenBuilder, TopUpBuilder};
use payment_channels_client::programs::PAYMENT_CHANNELS_ID;
use payment_channels_client::types::{DistributionEntry, OpenArgs, TopUpArgs};

use crate::program::payment_channels::state::find_channel_pda;
use crate::protocol::intents::session::Split;

/// Default compute-unit price (micro-lamports per CU). v1 wire contract:
/// client and server both bake this exact value into the canonical
/// prelude, and the tx-shape gate byte-checks it. No per-request
/// override yet; until that lands this constant is the only valid value
/// on the wire.
pub const DEFAULT_COMPUTE_UNIT_PRICE: u64 = 1;

/// Default compute-unit limit. 200_000 covers `open` and `top_up` with
/// headroom on the largest split layouts the SDK supports. Same wire
/// contract as `DEFAULT_COMPUTE_UNIT_PRICE`.
pub const DEFAULT_COMPUTE_UNIT_LIMIT: u32 = 200_000;

/// Inputs needed to rebuild the canonical open ix list. Both client
/// and server populate this struct from the same wire fields, so the
/// resulting `Vec<Instruction>` matches across the two callers.
pub struct CanonicalOpenInputs<'a> {
    pub program_id: Pubkey,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub salt: u64,
    pub deposit: u64,
    pub grace_period_seconds: u32,
    pub splits: &'a [Split],
    /// The channel PDA derived from the inputs above. Threaded through
    /// because callers usually have it on hand from a prior PDA-derivation
    /// step; passing it in avoids deriving the PDA twice.
    pub channel_id: Pubkey,
    pub compute_unit_price: u64,
    pub compute_unit_limit: u32,
}

/// Inputs for rebuilding the canonical top-up ix list.
pub struct CanonicalTopupInputs {
    pub program_id: Pubkey,
    pub payer: Pubkey,
    pub channel_id: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    pub compute_unit_price: u64,
    pub compute_unit_limit: u32,
}

/// Build the canonical open ix list:
/// `[set_compute_unit_price, set_compute_unit_limit,
///   create_idempotent_ata(payee), create_idempotent_ata(payer),
///   create_idempotent_ata(splits[0].recipient), ..., open]`.
///
/// The ATA-create ordering is deterministic: payee, then payer, then
/// each split recipient in the order they appear in `splits`. A client
/// that re-orders splits (or inserts a recipient) trips both the
/// slot-by-slot byte compare here and the `distribution_hash` check
/// that consumes `splits::canonical_preimage`.
///
/// The channel PDA's escrow ATA is intentionally NOT in this list: the
/// upstream `open` ix creates it itself (non-idempotently), and a
/// preceding `CreateIdempotent` would race with that and trip
/// `IllegalOwner` when upstream's `CreateAta` runs. The payer's funding
/// ATA must exist before broadcast (payer needs tokens to deposit), so
/// the `CreateIdempotent` for it is a no-op in practice; it's kept in
/// the canonical list so a defensive client doesn't have to special-case
/// the "already exists" path. Payee and split-recipient ATAs are not
/// used by `open` itself but are required by the close-time `distribute`
/// ix; creating them at open time avoids a separate preflight tx later.
pub fn build_canonical_open_ixs(inputs: &CanonicalOpenInputs<'_>) -> Vec<Instruction> {
    let mut ixs = Vec::with_capacity(4 + inputs.splits.len());

    ixs.push(ComputeBudgetInstruction::set_compute_unit_price(
        inputs.compute_unit_price,
    ));
    ixs.push(ComputeBudgetInstruction::set_compute_unit_limit(
        inputs.compute_unit_limit,
    ));

    let token_program = spl_token_id();
    let funding = inputs.payer;

    ixs.push(create_ata_idempotent_ix(
        &funding,
        &inputs.payee,
        &inputs.mint,
        &token_program,
    ));
    ixs.push(create_ata_idempotent_ix(
        &funding,
        &inputs.payer,
        &inputs.mint,
        &token_program,
    ));
    for split in inputs.splits {
        let recipient = match split {
            Split::Bps { recipient, .. } => *recipient,
        };
        ixs.push(create_ata_idempotent_ix(
            &funding,
            &recipient,
            &inputs.mint,
            &token_program,
        ));
    }

    ixs.push(build_canonical_open_ix(inputs));
    ixs
}

/// Build the canonical top-up ix list:
/// `[set_compute_unit_price, set_compute_unit_limit, top_up]`.
///
/// Top-up has no ATA-create slots: the payer's ATA is asserted at open
/// time (and the open ix would have rejected if it was missing) and the
/// channel vault was created by the open ix itself. The compute-budget
/// prelude is the only thing standing between the client's signing and
/// the upstream `top_up` ix.
pub fn build_canonical_topup_ixs(inputs: &CanonicalTopupInputs) -> Vec<Instruction> {
    vec![
        ComputeBudgetInstruction::set_compute_unit_price(inputs.compute_unit_price),
        ComputeBudgetInstruction::set_compute_unit_limit(inputs.compute_unit_limit),
        build_canonical_topup_ix(inputs),
    ]
}

/// Build the canonical payment-channels `open` ix matching what an
/// honest client emits via upstream's `OpenBuilder`. The full open-tx
/// list (including compute-budget prelude and ATA creates) lives in
/// `build_canonical_open_ixs`; this helper exposes just the trailing
/// payment-channels ix for callers that want to inspect or re-derive
/// it standalone.
pub fn build_canonical_open_ix(inputs: &CanonicalOpenInputs<'_>) -> Instruction {
    // Event authority PDA, single seed `b"event_authority"`. Upstream
    // declares it in `program/payment_channels/src/event_engine.rs`
    // but the Codama client doesn't re-export it.
    let (event_authority_pk, _) =
        Pubkey::find_program_address(&[b"event_authority"], &inputs.program_id);

    let token_program_pk = spl_token_id();
    let token_program = pk_to_addr(&token_program_pk);
    let ata_program = pk_to_addr(&ata_program_id());

    let payer_addr = pk_to_addr(&inputs.payer);
    let payee_addr = pk_to_addr(&inputs.payee);
    let mint_addr = pk_to_addr(&inputs.mint);
    let auth_addr = pk_to_addr(&inputs.authorized_signer);
    let channel_addr = pk_to_addr(&inputs.channel_id);

    // ATAs derive against classic SPL Token in v1; using a different
    // token program here would yield a different ATA.
    let payer_token_account_pk = ata_address(&inputs.payer, &inputs.mint, &token_program_pk);
    let channel_token_account_pk =
        ata_address(&inputs.channel_id, &inputs.mint, &token_program_pk);
    let payer_token_account_addr = pk_to_addr(&payer_token_account_pk);
    let channel_token_account_addr = pk_to_addr(&channel_token_account_pk);

    let open_args = OpenArgs {
        salt: inputs.salt,
        deposit: inputs.deposit,
        grace_period: inputs.grace_period_seconds,
        recipients: splits_to_recipients(inputs.splits),
    };

    OpenBuilder::new()
        .payer(payer_addr)
        .payee(payee_addr)
        .mint(mint_addr)
        .authorized_signer(auth_addr)
        .channel(channel_addr)
        .payer_token_account(payer_token_account_addr)
        .channel_token_account(channel_token_account_addr)
        .token_program(token_program)
        .system_program(pk_to_addr(&solana_sdk_ids::system_program::ID))
        .rent(pk_to_addr(&solana_sdk_ids::sysvar::rent::ID))
        .associated_token_program(ata_program)
        .event_authority(pk_to_addr(&event_authority_pk))
        .self_program(PAYMENT_CHANNELS_ID)
        .open_args(open_args)
        .instruction()
}

/// Build the canonical payment-channels `top_up` ix matching what an
/// honest client emits via upstream's `TopUpBuilder`.
pub fn build_canonical_topup_ix(inputs: &CanonicalTopupInputs) -> Instruction {
    let token_program_pk = spl_token_id();
    let token_program = pk_to_addr(&token_program_pk);

    let payer_addr = pk_to_addr(&inputs.payer);
    let mint_addr = pk_to_addr(&inputs.mint);
    let channel_addr = pk_to_addr(&inputs.channel_id);

    let payer_token_account_pk = ata_address(&inputs.payer, &inputs.mint, &token_program_pk);
    let channel_token_account_pk =
        ata_address(&inputs.channel_id, &inputs.mint, &token_program_pk);

    TopUpBuilder::new()
        .payer(payer_addr)
        .channel(channel_addr)
        .payer_token_account(pk_to_addr(&payer_token_account_pk))
        .channel_token_account(pk_to_addr(&channel_token_account_pk))
        .mint(mint_addr)
        .token_program(token_program)
        .top_up_args(TopUpArgs {
            amount: inputs.amount,
        })
        .instruction()
}

// ── Local helpers (shared with server/session handlers via re-export) ─

/// SDK-side cap on distribution splits. The on-chain program accepts
/// up to 32 recipients, but the cold-start ATA preflight tx and the
/// distribute tx both exceed Solana's 1232-byte packet limit before
/// reaching 32 recipients. 8 keeps all four close txs (preflight,
/// apply-voucher settle, lock-settled settle, distribute) under the
/// limit with a margin. `validate_open_tx_shape` rejects opens above
/// the cap so an operator can't accept an open they can't later close.
pub const MAX_SPLITS: usize = 8;

/// Convert typed `Split`s to the `Vec<DistributionEntry>` upstream's
/// builders expect. Pure mapping; the cap is enforced earlier in
/// `validate_open_tx_shape`.
pub fn splits_to_recipients(splits: &[Split]) -> Vec<DistributionEntry> {
    splits.iter().map(DistributionEntry::from).collect()
}

pub fn pk_to_addr(pk: &Pubkey) -> Address {
    Address::new_from_array(pk.to_bytes())
}

pub fn addr_to_pk(addr: &Address) -> Pubkey {
    Pubkey::new_from_array(addr.to_bytes())
}

/// 32-byte program id for classic SPL Token, in v3 `Pubkey` form. The
/// upstream `spl-associated-token-account-client` 2.x crate would hand
/// us a v2 `Pubkey` here, so we go through bytes once.
pub fn spl_token_id() -> Pubkey {
    Pubkey::new_from_array(spl_token::id().to_bytes())
}

/// 32-byte program id for the associated token program. Same v2-to-v3
/// bridge as above.
pub fn ata_program_id() -> Pubkey {
    Pubkey::new_from_array(spl_associated_token_account_client::program::ID.to_bytes())
}

/// Derive an associated token address for `(wallet, mint, token_program)`
/// using v3 `Pubkey` throughout. Mirrors
/// `spl_associated_token_account_client::address::get_associated_token_address_with_program_id`,
/// which takes v2 types.
pub fn ata_address(wallet: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let (pda, _) = Pubkey::find_program_address(
        &[wallet.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program_id(),
    );
    pda
}

/// Build a `CreateIdempotent` ix in v3 `Pubkey` terms. Discriminator `1`
/// is `CreateIdempotent` per the upstream
/// `spl-associated-token-account-client` 2.x crate. The hand-rolled
/// shape avoids the v2 / v3 `Instruction` type mismatch that calling
/// `spl_associated_token_account_client::instruction::create_associated_token_account_idempotent`
/// would force at the call site.
///
/// `pub(crate)` so the close-path tx assembler in `server/session/ix.rs`
/// shares the byte layout instead of carrying a duplicate copy.
pub(crate) fn create_ata_idempotent_ix(
    funding: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let ata = ata_address(wallet, mint, token_program);
    Instruction {
        program_id: ata_program_id(),
        accounts: vec![
            AccountMeta::new(*funding, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*wallet, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![1],
    }
}

/// Helper for callers that want the channel PDA + canonical bump
/// without knowing they live under the program-state module.
pub fn derive_channel_pda(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    find_channel_pda(payer, payee, mint, authorized_signer, salt, program_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }

    fn program_id() -> Pubkey {
        Pubkey::new_from_array(PAYMENT_CHANNELS_ID.to_bytes())
    }

    fn open_inputs<'a>(splits: &'a [Split]) -> CanonicalOpenInputs<'a> {
        let payer = pk(0xA1);
        let payee = pk(0xA2);
        let mint = pk(0xA3);
        let signer = pk(0xA4);
        let salt = 7u64;
        let pid = program_id();
        let (channel_id, _bump) = derive_channel_pda(&payer, &payee, &mint, &signer, salt, &pid);
        CanonicalOpenInputs {
            program_id: pid,
            payer,
            payee,
            mint,
            authorized_signer: signer,
            salt,
            deposit: 1_000_000,
            grace_period_seconds: 60,
            splits,
            channel_id,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        }
    }

    fn topup_inputs() -> CanonicalTopupInputs {
        CanonicalTopupInputs {
            program_id: program_id(),
            payer: pk(0xA1),
            channel_id: pk(0xC1),
            mint: pk(0xA3),
            amount: 250_000,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        }
    }

    #[test]
    fn open_ix_list_orders_compute_budget_first_then_atas_then_open() {
        let splits: Vec<Split> = Vec::new();
        let ixs = build_canonical_open_ixs(&open_inputs(&splits));
        // 0..2 are compute-budget; 2..4 are CreateIdempotent
        // (payee, payer); 4 is the payment-channels open ix.
        assert_eq!(ixs.len(), 5);

        let cb_id = solana_sdk_ids::compute_budget::ID;
        let ata_id = ata_program_id();
        let pc_id = program_id();

        assert_eq!(ixs[0].program_id, cb_id);
        assert_eq!(ixs[1].program_id, cb_id);
        // SetComputeUnitPrice has discriminator 3, SetComputeUnitLimit is 2.
        assert_eq!(ixs[0].data[0], 3);
        assert_eq!(ixs[1].data[0], 2);

        assert_eq!(ixs[2].program_id, ata_id);
        assert_eq!(ixs[3].program_id, ata_id);

        assert_eq!(ixs[4].program_id, pc_id);
    }

    #[test]
    fn open_ix_list_includes_one_ata_per_split_recipient() {
        let splits = vec![
            Split::Bps {
                recipient: pk(0xB1),
                share_bps: 4_000,
            },
            Split::Bps {
                recipient: pk(0xB2),
                share_bps: 3_000,
            },
        ];
        let ixs = build_canonical_open_ixs(&open_inputs(&splits));
        // 2 prelude + 2 fixed ATAs (payee, payer) + 2 split-recipient
        // ATAs + 1 open.
        assert_eq!(ixs.len(), 7);

        let ata_id = ata_program_id();
        // Recipient ATA ordering matches the input split order. The
        // wallet sits at account index 2 of `CreateIdempotent`.
        assert_eq!(ixs[4].program_id, ata_id);
        assert_eq!(ixs[5].program_id, ata_id);
        assert_eq!(ixs[4].accounts[2].pubkey, pk(0xB1));
        assert_eq!(ixs[5].accounts[2].pubkey, pk(0xB2));
    }

    #[test]
    fn topup_ix_list_is_two_compute_budget_ixs_plus_top_up() {
        let ixs = build_canonical_topup_ixs(&topup_inputs());
        assert_eq!(ixs.len(), 3);

        let cb_id = solana_sdk_ids::compute_budget::ID;
        let pc_id = program_id();
        assert_eq!(ixs[0].program_id, cb_id);
        assert_eq!(ixs[1].program_id, cb_id);
        assert_eq!(ixs[2].program_id, pc_id);
    }

    #[test]
    fn same_inputs_produce_byte_equal_ix_lists() {
        let splits = vec![Split::Bps {
            recipient: pk(0xB1),
            share_bps: 10_000,
        }];
        let a = build_canonical_open_ixs(&open_inputs(&splits));
        let b = build_canonical_open_ixs(&open_inputs(&splits));
        assert_eq!(a.len(), b.len());
        for (lhs, rhs) in a.iter().zip(b.iter()) {
            assert_eq!(lhs.program_id, rhs.program_id);
            assert_eq!(lhs.data, rhs.data);
            assert_eq!(lhs.accounts.len(), rhs.accounts.len());
            for (la, ra) in lhs.accounts.iter().zip(rhs.accounts.iter()) {
                assert_eq!(la.pubkey, ra.pubkey);
                assert_eq!(la.is_signer, ra.is_signer);
                assert_eq!(la.is_writable, ra.is_writable);
            }
        }

        let t1 = build_canonical_topup_ixs(&topup_inputs());
        let t2 = build_canonical_topup_ixs(&topup_inputs());
        assert_eq!(t1.len(), t2.len());
        for (lhs, rhs) in t1.iter().zip(t2.iter()) {
            assert_eq!(lhs.program_id, rhs.program_id);
            assert_eq!(lhs.data, rhs.data);
        }
    }
}
