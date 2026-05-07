//! L1 integration oracle for the FINALIZED-branch distribute path.
//!
//! Two test cases drive the full close lifecycle (open + settle +
//! settle_and_finalize + distribute) against the pinned program binary
//! and exercise distinct FINALIZED-branch behaviors:
//!
//!   1. `finalized_distribute_tombstones_pda_to_one_byte_with_expected_discriminator`
//!      - Vanilla payer-payee channel (count=0 splits). Pins the
//!        tombstone byte shape (`[2u8]`), program ownership, and the
//!        clean-pool case where payee absorbs everything and treasury
//!        receives nothing.
//!   2. `finalized_distribute_with_recipients_sweeps_within_pool_residual_to_treasury`
//!      - Two bps recipients with a non-divisible pool (settled =
//!        1_000_001, bps 3000/3000/4000 yields floor shares summing to
//!        1_000_000 with 1 lamport residual). Pins the FINALIZED-branch
//!        residual-sweep math: the within-pool residual goes to the
//!        treasury ATA, distinct from the Open path where it stays in
//!        escrow.
//!
//! Both tests assert the post-distribute PDA bytes equal `[2u8]` (the
//! literal on-chain `AccountDiscriminator::ClosedChannel` value), the
//! account stays program-owned, and the SDK-side
//! `CLOSED_CHANNEL_DISCRIMINATOR` const tracks reality. Together they
//! pin the wire-contract gap that pure synthetic-byte unit tests leave
//! open and exercise both the trivial-residual and non-trivial-residual
//! arithmetic in the FINALIZED branch.

mod common;

use common::{program_id_address, program_id_mpp, program_so_path, spl_token_amount, to_mpp};
use ed25519_dalek::SigningKey;
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::{
    DistributeBuilder, OpenBuilder, SettleAndFinalizeBuilder, SettleBuilder,
};
use payment_channels_client::types::{
    DistributeArgs, DistributionEntry, OpenArgs, SettleAndFinalizeArgs, SettleArgs, VoucherArgs,
};
use solana_address::Address;
use solana_message::Message;
use solana_mpp::program::payment_channels::{
    splits::TREASURY_OWNER,
    state::CLOSED_CHANNEL_DISCRIMINATOR,
    state::find_channel_pda,
    voucher::build_verify_ix,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

#[test]
fn finalized_distribute_tombstones_pda_to_one_byte_with_expected_discriminator() {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program binary");

    let payer = Keypair::new();
    let payee_keypair = Keypair::new();
    let mint_authority = Keypair::new();
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let authorized_signer_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let authorized_signer = Address::new_from_array(authorized_signer_bytes);
    let payee = Address::new_from_array(payee_keypair.pubkey().to_bytes());

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&payee_keypair.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&mint_authority.pubkey(), 1_000_000_000).unwrap();

    let token_program_id = litesvm_token::TOKEN_ID;
    let mint = CreateMint::new(&mut svm, &mint_authority)
        .decimals(6)
        .token_program_id(&token_program_id)
        .send()
        .expect("create mint");

    let payer_token_account = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .owner(&payer.pubkey())
        .send()
        .expect("create payer ATA");
    MintTo::new(
        &mut svm,
        &mint_authority,
        &mint,
        &payer_token_account,
        2_000_000,
    )
    .send()
    .expect("mint to payer ATA");

    // Vanilla payer-payee shape: empty recipients, payee receives the
    // full pool implicitly on distribute. Treasury ATA is required by
    // the distribute ix even when recipients is empty (residual sweep
    // target).
    let payee_token_account = create_ata(&mut svm, &payer, &mint, &payee, &token_program_id);
    let treasury_owner = Address::new_from_array(TREASURY_OWNER.to_bytes());
    let treasury_token_account =
        create_ata(&mut svm, &payer, &mint, &treasury_owner, &token_program_id);

    let recipients: Vec<DistributionEntry> = Vec::new();

    let salt: u64 = 99;
    let deposit: u64 = 1_000_000;
    let settled: u64 = 600_000;
    let grace_period: u32 = 60;

    let open_args = OpenArgs {
        salt,
        deposit,
        grace_period,
        recipients: recipients.clone(),
    };

    let (channel_pda_mpp, _bump) = find_channel_pda(
        &to_mpp(&payer.pubkey()),
        &to_mpp(&payee),
        &to_mpp(&mint),
        &MppPubkey::new_from_array(authorized_signer_bytes),
        salt,
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

    let (event_authority_mpp, _) =
        MppPubkey::find_program_address(&[b"event_authority"], &program_id_mpp());
    let event_authority = Address::new_from_array(event_authority_mpp.to_bytes());
    let ata_program =
        Address::new_from_array(spl_associated_token_account_client::program::ID.to_bytes());

    // 1. Open the channel.
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

    // 2. Settle one voucher.
    let channel_id_mpp = MppPubkey::new_from_array(channel_pda.to_bytes());
    let precompile_ix = build_verify_ix(&channel_id_mpp, settled, 0, &signing_key)
        .expect("in-process dalek signer is infallible");
    let settle_ix = SettleBuilder::new()
        .channel(channel_pda)
        .instructions_sysvar(sysvar::instructions::ID)
        .settle_args(SettleArgs {
            voucher: VoucherArgs {
                channel_id: channel_pda,
                cumulative_amount: settled,
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

    // 3. settle_and_finalize with has_voucher=0 (locks current settled).
    let zero_voucher = VoucherArgs {
        channel_id: channel_pda,
        cumulative_amount: 0,
        expires_at: 0,
    };
    let settle_finalize_ix = SettleAndFinalizeBuilder::new()
        .merchant(payee_keypair.pubkey())
        .channel(channel_pda)
        .instructions_sysvar(sysvar::instructions::ID)
        .settle_and_finalize_args(SettleAndFinalizeArgs {
            voucher: zero_voucher,
            has_voucher: 0,
        })
        .instruction();
    svm.expire_blockhash();
    let settle_finalize_tx = Transaction::new(
        &[&payer, &payee_keypair],
        Message::new(&[settle_finalize_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(settle_finalize_tx)
        .expect("settle_and_finalize lands");

    // Snapshot pre-distribute balances so we can verify the FINALIZED
    // branch's payer refund + payee distribution + treasury sweep.
    let pre_payer_token = spl_token_amount(&svm.get_account(&payer_token_account).unwrap().data);
    let pre_payee_token = spl_token_amount(&svm.get_account(&payee_token_account).unwrap().data);
    let pre_treasury_token =
        spl_token_amount(&svm.get_account(&treasury_token_account).unwrap().data);
    let pre_escrow = spl_token_amount(&svm.get_account(&channel_token_account).unwrap().data);
    assert_eq!(
        pre_escrow, deposit,
        "escrow holds the full deposit before distribute"
    );

    // 4. Distribute from FINALIZED state. count=0 means no
    // remaining-account ATAs are passed; the payee gets the implicit
    // 100% of the (settled - paid_out) pool, the payer gets refunded
    // (deposit - settled), and any residual sweeps to the treasury.
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
        .instruction();
    svm.expire_blockhash();
    let distribute_tx = Transaction::new(
        &[&payer],
        Message::new(&[distribute_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(distribute_tx)
        .expect("distribute (FINALIZED branch) lands");

    // The load-bearing assertions: after FINALIZED-branch distribute,
    // the channel PDA is reallocated in-place to a 1-byte ClosedChannel
    // tombstone with the discriminator byte == 2.
    let post = svm
        .get_account(&channel_pda)
        .expect("channel PDA still exists after FINALIZED distribute");

    // Literal-byte assertion: confirms the real on-chain bytes are what
    // upstream's protocol doc says they should be. Uses literal `2`,
    // NOT CLOSED_CHANNEL_DISCRIMINATOR, to detect upstream-side drift.
    assert_eq!(
        post.data,
        vec![2u8],
        "post-FINALIZED-distribute PDA must be exactly [2u8] per upstream's documented tombstone shape"
    );
    // SDK-side const drift detection: confirms the SDK's belief about
    // the discriminator byte still matches the real on-chain byte.
    assert_eq!(
        post.data,
        vec![CLOSED_CHANNEL_DISCRIMINATOR],
        "SDK's CLOSED_CHANNEL_DISCRIMINATOR const must match the real on-chain byte"
    );
    assert_eq!(
        post.owner.to_bytes(),
        program_id_address().to_bytes(),
        "tombstoned PDA must remain owned by the program"
    );

    // The escrow ATA should have been swept to treasury, with the payee
    // receiving the settled portion and the payer refunded the unspent
    // headroom.
    let post_payer_token =
        spl_token_amount(&svm.get_account(&payer_token_account).unwrap().data);
    let post_payee_token =
        spl_token_amount(&svm.get_account(&payee_token_account).unwrap().data);
    let post_treasury_token =
        spl_token_amount(&svm.get_account(&treasury_token_account).unwrap().data);
    let post_escrow_account = svm.get_account(&channel_token_account);

    let payee_received = post_payee_token - pre_payee_token;
    let payer_refunded = post_payer_token - pre_payer_token;
    let treasury_swept = post_treasury_token - pre_treasury_token;

    assert_eq!(
        payee_received, settled,
        "payee should receive the full settled amount on FINALIZED distribute"
    );
    assert_eq!(
        payer_refunded,
        deposit - settled,
        "payer should be refunded (deposit - settled) on FINALIZED distribute"
    );
    assert_eq!(
        treasury_swept, 0,
        "treasury sweep should be zero when there is no within-pool residual"
    );
    // The escrow ATA itself is closed by the FINALIZED branch (rent
    // reclaimed); litesvm reports either None or a zero-lamport account.
    if let Some(escrow_post) = post_escrow_account {
        assert_eq!(
            escrow_post.lamports, 0,
            "escrow ATA should be closed (zero lamports) after FINALIZED distribute"
        );
    }
}

#[test]
fn finalized_distribute_with_recipients_sweeps_within_pool_residual_to_treasury() {
    // Non-divisible-pool fixture: settled = 1_000_001 with bps
    // 3000 / 3000 / 4000 yields floor shares 300_000 / 300_000 / 400_000
    // summing to 1_000_000. Within-pool residual is 1 lamport.
    //
    // Under the Open path the residual stays in escrow (covered by
    // session_l1_distribute_oracle.rs). Under the FINALIZED path here,
    // upstream's distribute sweeps the residual to the treasury ATA before
    // closing the escrow. Pinning that delta is the load-bearing
    // contract this test exists for.

    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program binary");

    let payer = Keypair::new();
    let payee_keypair = Keypair::new();
    let mint_authority = Keypair::new();
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let authorized_signer_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let authorized_signer = Address::new_from_array(authorized_signer_bytes);
    let payee = Address::new_from_array(payee_keypair.pubkey().to_bytes());
    let recip_a = Address::new_from_array([0xa1u8; 32]);
    let recip_b = Address::new_from_array([0xb2u8; 32]);

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&payee_keypair.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&mint_authority.pubkey(), 1_000_000_000).unwrap();

    let token_program_id = litesvm_token::TOKEN_ID;
    let mint = CreateMint::new(&mut svm, &mint_authority)
        .decimals(6)
        .token_program_id(&token_program_id)
        .send()
        .expect("create mint");

    let payer_token_account = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .owner(&payer.pubkey())
        .send()
        .expect("create payer ATA");
    MintTo::new(
        &mut svm,
        &mint_authority,
        &mint,
        &payer_token_account,
        3_000_000,
    )
    .send()
    .expect("mint to payer ATA");

    let payee_token_account = create_ata(&mut svm, &payer, &mint, &payee, &token_program_id);
    let recip_a_token_account = create_ata(&mut svm, &payer, &mint, &recip_a, &token_program_id);
    let recip_b_token_account = create_ata(&mut svm, &payer, &mint, &recip_b, &token_program_id);
    let treasury_owner = Address::new_from_array(TREASURY_OWNER.to_bytes());
    let treasury_token_account =
        create_ata(&mut svm, &payer, &mint, &treasury_owner, &token_program_id);

    let recip_a_bps: u16 = 3000;
    let recip_b_bps: u16 = 3000;
    let recipients = vec![
        DistributionEntry {
            recipient: recip_a,
            bps: recip_a_bps,
        },
        DistributionEntry {
            recipient: recip_b,
            bps: recip_b_bps,
        },
    ];

    let salt: u64 = 100;
    let deposit: u64 = 2_000_000;
    let settled: u64 = 1_000_001;
    let grace_period: u32 = 60;

    let open_args = OpenArgs {
        salt,
        deposit,
        grace_period,
        recipients: recipients.clone(),
    };

    let (channel_pda_mpp, _bump) = find_channel_pda(
        &to_mpp(&payer.pubkey()),
        &to_mpp(&payee),
        &to_mpp(&mint),
        &MppPubkey::new_from_array(authorized_signer_bytes),
        salt,
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

    let (event_authority_mpp, _) =
        MppPubkey::find_program_address(&[b"event_authority"], &program_id_mpp());
    let event_authority = Address::new_from_array(event_authority_mpp.to_bytes());
    let ata_program =
        Address::new_from_array(spl_associated_token_account_client::program::ID.to_bytes());

    // 1. Open the channel.
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

    // 2. Settle one voucher to populate the FINALIZED-branch pool.
    let channel_id_mpp = MppPubkey::new_from_array(channel_pda.to_bytes());
    let precompile_ix = build_verify_ix(&channel_id_mpp, settled, 0, &signing_key)
        .expect("in-process dalek signer is infallible");
    let settle_ix = SettleBuilder::new()
        .channel(channel_pda)
        .instructions_sysvar(sysvar::instructions::ID)
        .settle_args(SettleArgs {
            voucher: VoucherArgs {
                channel_id: channel_pda,
                cumulative_amount: settled,
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

    // 3. settle_and_finalize with has_voucher=0 (locks current settled).
    let zero_voucher = VoucherArgs {
        channel_id: channel_pda,
        cumulative_amount: 0,
        expires_at: 0,
    };
    let settle_finalize_ix = SettleAndFinalizeBuilder::new()
        .merchant(payee_keypair.pubkey())
        .channel(channel_pda)
        .instructions_sysvar(sysvar::instructions::ID)
        .settle_and_finalize_args(SettleAndFinalizeArgs {
            voucher: zero_voucher,
            has_voucher: 0,
        })
        .instruction();
    svm.expire_blockhash();
    let settle_finalize_tx = Transaction::new(
        &[&payer, &payee_keypair],
        Message::new(&[settle_finalize_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(settle_finalize_tx)
        .expect("settle_and_finalize lands");

    // Snapshot pre-distribute balances.
    let pre_payer_token = spl_token_amount(&svm.get_account(&payer_token_account).unwrap().data);
    let pre_payee_token = spl_token_amount(&svm.get_account(&payee_token_account).unwrap().data);
    let pre_recip_a = spl_token_amount(&svm.get_account(&recip_a_token_account).unwrap().data);
    let pre_recip_b = spl_token_amount(&svm.get_account(&recip_b_token_account).unwrap().data);
    let pre_treasury_token =
        spl_token_amount(&svm.get_account(&treasury_token_account).unwrap().data);
    let pre_escrow = spl_token_amount(&svm.get_account(&channel_token_account).unwrap().data);
    assert_eq!(
        pre_escrow, deposit,
        "escrow holds the full deposit before distribute"
    );

    // 4. Distribute from FINALIZED state with the two bps recipients
    // attached as remaining accounts.
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
    svm.send_transaction(distribute_tx)
        .expect("distribute (FINALIZED branch) lands");

    // Tombstone shape assertions: same as the zero-residual case.
    let post = svm
        .get_account(&channel_pda)
        .expect("channel PDA still exists after FINALIZED distribute");
    assert_eq!(
        post.data,
        vec![2u8],
        "post-FINALIZED-distribute PDA must be exactly [2u8] per upstream's documented tombstone shape"
    );
    assert_eq!(
        post.data,
        vec![CLOSED_CHANNEL_DISCRIMINATOR],
        "SDK's CLOSED_CHANNEL_DISCRIMINATOR const must match the real on-chain byte"
    );
    assert_eq!(
        post.owner.to_bytes(),
        program_id_address().to_bytes(),
        "tombstoned PDA must remain owned by the program"
    );

    // Floor-share math: pool = settled = 1_000_001, payee_bps =
    // 10_000 - 3000 - 3000 = 4000. Floor shares are 300_000 / 300_000 /
    // 400_000, summing to 1_000_000. Within-pool residual is 1 lamport.
    let post_payer_token =
        spl_token_amount(&svm.get_account(&payer_token_account).unwrap().data);
    let post_payee_token =
        spl_token_amount(&svm.get_account(&payee_token_account).unwrap().data);
    let post_recip_a = spl_token_amount(&svm.get_account(&recip_a_token_account).unwrap().data);
    let post_recip_b = spl_token_amount(&svm.get_account(&recip_b_token_account).unwrap().data);
    let post_treasury_token =
        spl_token_amount(&svm.get_account(&treasury_token_account).unwrap().data);
    let post_escrow_account = svm.get_account(&channel_token_account);

    let payee_received = post_payee_token - pre_payee_token;
    let recip_a_received = post_recip_a - pre_recip_a;
    let recip_b_received = post_recip_b - pre_recip_b;
    let payer_refunded = post_payer_token - pre_payer_token;
    let treasury_swept = post_treasury_token - pre_treasury_token;

    assert_eq!(
        recip_a_received, 300_000,
        "recip_a should receive its bps floor share"
    );
    assert_eq!(
        recip_b_received, 300_000,
        "recip_b should receive its bps floor share"
    );
    assert_eq!(
        payee_received, 400_000,
        "payee should receive the implicit-remainder bps floor share"
    );
    assert_eq!(
        payer_refunded,
        deposit - settled,
        "payer should be refunded (deposit - settled) on FINALIZED distribute"
    );
    assert_eq!(
        treasury_swept, 1,
        "treasury should receive the 1-lamport within-pool residual on FINALIZED distribute"
    );
    if let Some(escrow_post) = post_escrow_account {
        assert_eq!(
            escrow_post.lamports, 0,
            "escrow ATA should be closed (zero lamports) after FINALIZED distribute"
        );
    }
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
