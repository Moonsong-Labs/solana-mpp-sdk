//! L1 integration oracle for the SDK's `distribute` byte contract.
//!
//! Loads the pinned program binary into litesvm, opens a channel with
//! bps recipients, settles one voucher to populate the distributable
//! pool, then submits the upstream `DistributeBuilder` from the `Open`
//! state. Two cases:
//!
//!   1. clean-division pool (no within-pool residual): pins the byte
//!      contract and recipient-ATA ordering;
//!   2. non-divisible pool: pins floor-division per-recipient shares
//!      and confirms the residual stays escrowed on the Open path.
//!
//! Covers only the `Open`-state distribute path. The `Finalized` branch
//! (which tombstones the channel and sweeps to the treasury) is exercised
//! separately by `session_l1_tombstone_oracle.rs`, which drives the full
//! close lifecycle end-to-end and asserts the resulting 1-byte tombstone
//! shape.

mod common;

use common::{program_id_address, program_id_mpp, program_so_path, spl_token_amount, to_mpp};
use ed25519_dalek::SigningKey;
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::{DistributeBuilder, OpenBuilder, SettleBuilder};
use payment_channels_client::types::{
    ChannelStatus, DistributeArgs, DistributionEntry, OpenArgs, SettleArgs, VoucherArgs,
};
use solana_address::Address;
use solana_message::Message;
use solana_mpp::program::payment_channels::{
    splits::TREASURY_OWNER,
    state::{find_channel_pda, ChannelView},
    voucher::build_verify_ix,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

#[test]
fn sdk_built_distribute_tx_lands_against_loaded_program() {
    // Clean-division case. pool = settled = 600_000 with bps 3000 / 2000 /
    // 5000 produces exact floor shares 180_000 / 120_000 / 300_000 summing
    // to 600_000 (no within-pool residual). Pins the byte contract and
    // the recipient-ATA remaining-accounts ordering.
    run_distribute_oracle(DistributeFixture {
        salt: 7,
        deposit: 1_000_000,
        settled: 600_000,
        recip_a_bps: 3000,
        recip_b_bps: 2000,
        payee_bps_remainder: 5000,
        expected_recip_a: 180_000,
        expected_recip_b: 120_000,
        expected_payee: 300_000,
        expected_distributed_sum: 600_000,
        expected_escrow_after: 400_000,
    });
}

#[test]
fn distribute_floors_recipient_shares_and_keeps_residual_in_escrow() {
    // Non-divisible case. pool = 1_000_001 with bps 3000 / 3000 / 4000
    // produces floor shares 300_000 / 300_000 / 400_000 summing to
    // 1_000_000. Within-pool residual is 1: the distribute ix transfers
    // 1_000_000, leaves the 1-lamport residual sitting in the escrow ATA
    // on the Open path. The dust-sweep behavior upstream describes is the
    // Finalized path; not exercised here.
    run_distribute_oracle(DistributeFixture {
        salt: 8,
        deposit: 2_000_000,
        settled: 1_000_001,
        recip_a_bps: 3000,
        recip_b_bps: 3000,
        payee_bps_remainder: 4000,
        expected_recip_a: 300_000,
        expected_recip_b: 300_000,
        expected_payee: 400_000,
        expected_distributed_sum: 1_000_000,
        // deposit - distributed = 2_000_000 - 1_000_000 = 1_000_000.
        // That total holds (deposit - settled) unsettled = 999_999
        // PLUS residual = 1.
        expected_escrow_after: 1_000_000,
    });
}

struct DistributeFixture {
    salt: u64,
    deposit: u64,
    settled: u64,
    recip_a_bps: u16,
    recip_b_bps: u16,
    payee_bps_remainder: u16, // documentation only; on-chain payee_bps is implicit
    expected_recip_a: u64,
    expected_recip_b: u64,
    expected_payee: u64,
    expected_distributed_sum: u64,
    expected_escrow_after: u64,
}

fn run_distribute_oracle(f: DistributeFixture) {
    // Sum check belongs to the test author, not the program.
    assert_eq!(
        f.recip_a_bps as u32 + f.recip_b_bps as u32 + f.payee_bps_remainder as u32,
        10_000,
        "test fixture bps must sum to 10000"
    );
    assert_eq!(
        f.expected_recip_a + f.expected_recip_b + f.expected_payee,
        f.expected_distributed_sum,
        "test fixture floor shares must sum to the distributed total"
    );

    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program binary");

    // Identities. The voucher signer uses ed25519_dalek::SigningKey
    // directly (matching the pattern in session_l1_ed25519_oracle.rs);
    // the SDK's voucher::build_verify_ix has a blanket impl of
    // VoucherSigner for SigningKey, so this is the canonical way to
    // produce the precompile ix without re-implementing the signing
    // path. The corresponding verifying-key bytes feed the open ix's
    // authorized_signer slot.
    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let authorized_signer_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let authorized_signer = Address::new_from_array(authorized_signer_bytes);

    let payee = Address::new_from_array([0xeeu8; 32]);
    let recip_a = Address::new_from_array([0xa1u8; 32]);
    let recip_b = Address::new_from_array([0xb2u8; 32]);

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&mint_authority.pubkey(), 1_000_000_000).unwrap();

    let token_program_id = litesvm_token::TOKEN_ID;
    let mint = CreateMint::new(&mut svm, &mint_authority)
        .decimals(6)
        .token_program_id(&token_program_id)
        .send()
        .expect("create mint");

    // Payer ATA + funding. Mint enough for the deposit and headroom.
    let payer_token_account = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .owner(&payer.pubkey())
        .send()
        .expect("create payer ATA");
    MintTo::new(
        &mut svm,
        &mint_authority,
        &mint,
        &payer_token_account,
        f.deposit + 1_000_000,
    )
    .send()
    .expect("mint to payer ATA");

    // Recipient ATAs and treasury ATA. The `litesvm_token` builder's
    // `.owner()` setter accepts whatever pubkey type the existing oracles
    // pass it (verified via `session_l1_open_oracle.rs:56-59`, which uses
    // `&payer.pubkey()` from a `Keypair`). For arbitrary `Address`-typed
    // owners, bridge through `solana_pubkey::Pubkey::new_from_array(owner
    // .to_bytes())`. The bridge keeps the type that `.owner()` expects in
    // scope without forcing the test to know the umbrella crate's exact
    // re-export shape.
    let payee_token_account = create_ata(&mut svm, &payer, &mint, &payee, &token_program_id);
    let recip_a_token_account = create_ata(&mut svm, &payer, &mint, &recip_a, &token_program_id);
    let recip_b_token_account = create_ata(&mut svm, &payer, &mint, &recip_b, &token_program_id);
    let treasury_owner = Address::new_from_array(TREASURY_OWNER.to_bytes());
    let treasury_token_account =
        create_ata(&mut svm, &payer, &mint, &treasury_owner, &token_program_id);

    let grace_period: u32 = 60;

    let (channel_pda_mpp, _bump) = find_channel_pda(
        &to_mpp(&payer.pubkey()),
        &to_mpp(&payee),
        &to_mpp(&mint),
        &MppPubkey::new_from_array(authorized_signer_bytes),
        f.salt,
        &program_id_mpp(),
    );
    let channel_pda = Address::new_from_array(channel_pda_mpp.to_bytes());

    let channel_token_account = Address::new_from_array(
        get_associated_token_address_with_program_id(
            &AtaPubkey::new_from_array(channel_pda.to_bytes()),
            &AtaPubkey::new_from_array(mint.to_bytes()),
            &AtaPubkey::new_from_array(token_program_id.to_bytes()),
        )
        .to_bytes(),
    );

    // Two active recipients.
    let recipients = vec![
        DistributionEntry {
            recipient: recip_a,
            bps: f.recip_a_bps,
        },
        DistributionEntry {
            recipient: recip_b,
            bps: f.recip_b_bps,
        },
    ];
    let open_args = OpenArgs {
        salt: f.salt,
        deposit: f.deposit,
        grace_period,
        recipients: recipients.clone(),
    };

    let (event_authority_mpp, _) =
        MppPubkey::find_program_address(&[b"event_authority"], &program_id_mpp());
    let event_authority = Address::new_from_array(event_authority_mpp.to_bytes());
    let ata_program =
        Address::new_from_array(spl_associated_token_account_client::program::ID.to_bytes());

    // Open the channel.
    let open_ix = OpenBuilder::new()
        .payer(payer.pubkey())
        .payee(payee)
        .mint(mint)
        .authorized_signer(authorized_signer)
        .channel(channel_pda)
        .payer_token_account(payer_token_account)
        .channel_token_account(channel_token_account)
        .token_program(token_program_id)
        .system_program(system_program::ID)
        .rent(sysvar::rent::ID)
        .associated_token_program(ata_program)
        .event_authority(event_authority)
        .self_program(program_id_address())
        .open_args(open_args)
        .instruction();
    let open_tx = Transaction::new(
        &[&payer],
        Message::new(&[open_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(open_tx).expect("open lands");

    // Settle one voucher. The SDK's `voucher::build_verify_ix` produces
    // the ed25519 precompile ix from a `VoucherSigner` (impl on
    // `ed25519_dalek::SigningKey`), encapsulating signature production
    // and the canonical 160-byte precompile data layout. The settle ix
    // submits in the same tx so its `instructions_sysvar` walk lands on
    // a precompile ix at index 0.
    let channel_id_mpp = MppPubkey::new_from_array(channel_pda.to_bytes());
    let precompile_ix = build_verify_ix(&channel_id_mpp, f.settled, 0, &signing_key)
        .expect("in-process dalek signer is infallible");

    let settle_ix = SettleBuilder::new()
        .channel(channel_pda)
        .instructions_sysvar(sysvar::instructions::ID)
        .settle_args(SettleArgs {
            voucher: VoucherArgs {
                channel_id: channel_pda,
                cumulative_amount: f.settled,
                expires_at: 0,
            },
        })
        .instruction();

    svm.expire_blockhash();
    let settle_tx = Transaction::new(
        &[&payer],
        Message::new(&[precompile_ix, settle_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(settle_tx).expect("settle lands");

    let post_settle = svm.get_account(&channel_pda).expect("channel pda exists");
    let post_settle_view =
        ChannelView::from_account_data(&post_settle.data).expect("decode channel");
    assert_eq!(post_settle_view.settled(), f.settled, "settle bumps settled");
    assert_eq!(
        post_settle_view.status(),
        ChannelStatus::Open as u8,
        "settle leaves status=Open"
    );

    // Snapshot ATA balances pre-distribute so the deltas are exact.
    let pre_payee = spl_token_amount(&svm.get_account(&payee_token_account).unwrap().data);
    let pre_recip_a = spl_token_amount(&svm.get_account(&recip_a_token_account).unwrap().data);
    let pre_recip_b = spl_token_amount(&svm.get_account(&recip_b_token_account).unwrap().data);
    let pre_treasury = spl_token_amount(&svm.get_account(&treasury_token_account).unwrap().data);
    let pre_escrow = spl_token_amount(&svm.get_account(&channel_token_account).unwrap().data);
    assert_eq!(
        pre_escrow, f.deposit,
        "escrow holds full deposit before distribute"
    );

    // Distribute from Open state. Recipient ATAs attach as remaining
    // accounts in the same order as args.recipients; upstream's
    // distribute::process zips them with remaining accounts, so the
    // order is load-bearing.
    let distribute_ix = DistributeBuilder::new()
        .channel(channel_pda)
        .payer(payer.pubkey())
        .channel_token_account(channel_token_account)
        .payer_token_account(payer_token_account)
        .payee_token_account(payee_token_account)
        .treasury_token_account(treasury_token_account)
        .mint(mint)
        .token_program(token_program_id)
        .distribute_args(DistributeArgs { recipients })
        .add_remaining_account(solana_instruction::AccountMeta::new(
            recip_a_token_account,
            false,
        ))
        .add_remaining_account(solana_instruction::AccountMeta::new(
            recip_b_token_account,
            false,
        ))
        .instruction();

    svm.expire_blockhash();
    let distribute_tx = Transaction::new(
        &[&payer],
        Message::new(&[distribute_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(distribute_tx).expect("distribute lands");

    // Per-account balance assertions. Each delta is exact (`==`), not
    // `>=`: residual on the Open path stays in the channel escrow ATA, not
    // on payee.
    let post_payee = spl_token_amount(&svm.get_account(&payee_token_account).unwrap().data);
    let post_recip_a = spl_token_amount(&svm.get_account(&recip_a_token_account).unwrap().data);
    let post_recip_b = spl_token_amount(&svm.get_account(&recip_b_token_account).unwrap().data);
    let post_treasury = spl_token_amount(&svm.get_account(&treasury_token_account).unwrap().data);
    let post_escrow = spl_token_amount(&svm.get_account(&channel_token_account).unwrap().data);

    assert_eq!(
        post_recip_a - pre_recip_a,
        f.expected_recip_a,
        "recip_a floor share"
    );
    assert_eq!(
        post_recip_b - pre_recip_b,
        f.expected_recip_b,
        "recip_b floor share"
    );
    assert_eq!(post_payee - pre_payee, f.expected_payee, "payee floor share");
    assert_eq!(
        post_treasury - pre_treasury,
        0,
        "treasury unchanged on Open path"
    );
    assert_eq!(
        pre_escrow - post_escrow,
        f.expected_distributed_sum,
        "escrow debits by the distributed sum"
    );
    assert_eq!(
        post_escrow, f.expected_escrow_after,
        "escrow holds (deposit - distributed) = unsettled portion + within-pool residual"
    );

    // Channel state: still Open, settled unchanged, deposit unchanged.
    let post_distribute = svm.get_account(&channel_pda).expect("channel pda exists");
    let post_distribute_view =
        ChannelView::from_account_data(&post_distribute.data).expect("decode post channel");
    assert_eq!(
        post_distribute_view.status(),
        ChannelStatus::Open as u8,
        "channel stays Open after Open-path distribute; Finalized branch is covered by session_l1_tombstone_oracle.rs"
    );
    assert_eq!(
        post_distribute_view.settled(),
        f.settled,
        "settled unchanged by distribute"
    );
    assert_eq!(
        post_distribute_view.deposit(),
        f.deposit,
        "deposit unchanged by distribute"
    );
    // After an Open-path distribute, the upstream program advances
    // paid_out to equal settled: the entire pool (transferred shares plus
    // any within-pool residual that stays escrowed) is accounted as paid.
    // A stale paid_out would let a duplicate distribute re-pay the same
    // pool, so pinning this equality closes that regression class even
    // though the per-recipient balance deltas alone would not.
    assert_eq!(
        post_distribute_view.paid_out(),
        f.settled,
        "paid_out advances to settled (catches duplicate-distribute regressions)"
    );
}

/// Derive an ATA and create it on-chain. Bridges between
/// `solana_address::Address` (the type the SDK and the upstream client
/// crate use) and the pubkey type the `litesvm_token` builder's
/// `.owner()` setter expects (the same type `&payer.pubkey()` produces in
/// the existing oracles, sourced from `solana_sdk::Keypair`).
fn create_ata(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Address,
    owner: &Address,
    token_program_id: &Address,
) -> Address {
    let owner_pubkey = MppPubkey::new_from_array(owner.to_bytes());
    let ata = Address::new_from_array(
        get_associated_token_address_with_program_id(
            &AtaPubkey::new_from_array(owner.to_bytes()),
            &AtaPubkey::new_from_array(mint.to_bytes()),
            &AtaPubkey::new_from_array(token_program_id.to_bytes()),
        )
        .to_bytes(),
    );
    CreateAssociatedTokenAccount::new(svm, payer, mint)
        .owner(&owner_pubkey)
        .send()
        .expect("create ATA");
    ata
}
