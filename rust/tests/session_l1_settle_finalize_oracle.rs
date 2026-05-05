//! L1 integration oracle for the `settle_and_finalize` ix.
//!
//! Two test cases pin the two `has_voucher` shapes upstream's
//! cooperative-close branch supports:
//!
//!   - has_voucher = 1: applies a fresh voucher first (bumps settled),
//!     then transitions the channel to Finalized. Bundled with the
//!     ed25519 precompile ix at index 0 (the program walks the
//!     instructions sysvar to find the precompile result).
//!   - has_voucher = 0: locks whatever is already in `settled` and
//!     transitions to Finalized. No precompile ix is bundled.
//!
//! Asserts the SDK's `ChannelView` decodes both post-states correctly:
//! status == Finalized, settled reflects the expected value.

mod common;

use common::{program_id_address, program_id_mpp, program_so_path, to_mpp};
use ed25519_dalek::SigningKey;
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::{
    OpenBuilder, RequestCloseBuilder, SettleAndFinalizeBuilder, SettleBuilder,
};
use payment_channels_client::types::{
    ChannelStatus, DistributionEntry, DistributionRecipients, OpenArgs, SettleAndFinalizeArgs,
    SettleArgs, VoucherArgs,
};
use solana_address::Address;
use solana_message::Message;
use solana_mpp::program::payment_channels::{
    state::{find_channel_pda, ChannelView},
    voucher::build_verify_ix,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

/// Common open + (optional) settle scaffolding shared by both test cases.
/// Returns `(svm, payer, payee_keypair, channel_pda, last_settled)`.
/// The `payee_keypair` is needed because settle_and_finalize requires the
/// merchant (channel payee) as a transaction signer.
fn open_channel(
    initial_settle: u64,
    salt: u64,
) -> (LiteSVM, Keypair, Keypair, Address, u64) {
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

    let zero_entry = DistributionEntry {
        recipient: Address::new_from_array([0u8; 32]),
        bps: 0,
    };
    let entries: [DistributionEntry; 32] = std::array::from_fn(|_| zero_entry.clone());
    let recipients = DistributionRecipients { count: 0, entries };

    let deposit: u64 = 1_000_000;
    let grace_period: u32 = 60;

    let open_args = OpenArgs {
        salt,
        deposit,
        grace_period,
        recipients,
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

    if initial_settle > 0 {
        let channel_id_mpp = MppPubkey::new_from_array(channel_pda.to_bytes());
        let precompile_ix = build_verify_ix(&channel_id_mpp, initial_settle, 0, &signing_key)
            .expect("in-process dalek signer is infallible");
        let settle_ix = SettleBuilder::new()
            .channel(channel_pda)
            .instructions_sysvar(sysvar::instructions::ID)
            .settle_args(SettleArgs {
                voucher: VoucherArgs {
                    channel_id: channel_pda,
                    cumulative_amount: initial_settle,
                    expires_at: 0,
                },
            })
            .instruction();
        svm.expire_blockhash();
        let settle_tx = Transaction::new(
            &[&payer],
            Message::new(
                &[precompile_ix, settle_ix],
                Some(&payer.pubkey()),
            ),
            svm.latest_blockhash(),
        );
        svm.send_transaction(settle_tx).expect("settle lands");
    }

    (svm, payer, payee_keypair, channel_pda, initial_settle)
}

#[test]
fn settle_and_finalize_with_voucher_applies_then_finalizes() {
    // has_voucher = 1: open + settle to 300_000, then submit
    // settle_and_finalize with a fresh voucher at cumulative=500_000 (must
    // be > current settled per upstream's monotonicity rule). Asserts
    // post-state has settled == 500_000 and status == Finalized.
    let (mut svm, payer, payee_keypair, channel_pda, _) = open_channel(300_000, 11);

    // Build the voucher signer matching the open's authorized_signer.
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let final_voucher_amount: u64 = 500_000;

    let channel_id_mpp = MppPubkey::new_from_array(channel_pda.to_bytes());
    let precompile_ix =
        build_verify_ix(&channel_id_mpp, final_voucher_amount, 0, &signing_key)
            .expect("in-process dalek signer is infallible");

    let settle_finalize_ix = SettleAndFinalizeBuilder::new()
        .merchant(payee_keypair.pubkey())
        .channel(channel_pda)
        .instructions_sysvar(sysvar::instructions::ID)
        .settle_and_finalize_args(SettleAndFinalizeArgs {
            voucher: VoucherArgs {
                channel_id: channel_pda,
                cumulative_amount: final_voucher_amount,
                expires_at: 0,
            },
            has_voucher: 1,
        })
        .instruction();

    svm.expire_blockhash();
    // Both payer (fee payer) and payee (merchant signer) sign.
    let tx = Transaction::new(
        &[&payer, &payee_keypair],
        Message::new(
            &[precompile_ix, settle_finalize_ix],
            Some(&payer.pubkey()),
        ),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .expect("settle_and_finalize with voucher lands");

    let post = svm.get_account(&channel_pda).expect("channel pda exists");
    let view = ChannelView::from_account_data(&post.data).expect("decode channel");
    assert_eq!(
        view.status(),
        ChannelStatus::Finalized as u8,
        "settle_and_finalize should transition status to Finalized"
    );
    assert_eq!(
        view.settled(),
        final_voucher_amount,
        "with has_voucher=1, settled advances to the voucher's cumulative_amount"
    );
    assert_eq!(
        view.closure_started_at(),
        0,
        "settle_and_finalize from Open writes closure_started_at = 0"
    );
}

#[test]
fn settle_and_finalize_without_voucher_locks_current_settled() {
    // has_voucher = 0: open + settle to 300_000, then submit
    // settle_and_finalize with has_voucher=0. The voucher field is
    // ignored; settled stays at 300_000 and status flips to Finalized.
    let (mut svm, payer, payee_keypair, channel_pda, last_settled) = open_channel(300_000, 12);
    assert_eq!(last_settled, 300_000);

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
    let tx = Transaction::new(
        &[&payer, &payee_keypair],
        Message::new(&[settle_finalize_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .expect("settle_and_finalize without voucher lands");

    let post = svm.get_account(&channel_pda).expect("channel pda exists");
    let view = ChannelView::from_account_data(&post.data).expect("decode channel");
    assert_eq!(
        view.status(),
        ChannelStatus::Finalized as u8,
        "settle_and_finalize should transition status to Finalized"
    );
    assert_eq!(
        view.settled(),
        last_settled,
        "with has_voucher=0, settled stays at the prior value"
    );
    assert_eq!(
        view.closure_started_at(),
        0,
        "settle_and_finalize from Open writes closure_started_at = 0"
    );
}

#[test]
fn settle_and_finalize_from_closing_state_finalizes_mid_grace() {
    // Branch A of the cooperative-close protocol: open, settle, then
    // request_close to enter Closing, then settle_and_finalize mid-grace
    // to transition Closing -> Finalized. Exercises the deadline-arithmetic
    // path inside settle_and_finalize that the Open-state tests don't reach,
    // and pins the closure_started_at = 0 reset that fires on the
    // Closing -> Finalized transition.
    let (mut svm, payer, payee_keypair, channel_pda, last_settled) = open_channel(300_000, 13);
    assert_eq!(last_settled, 300_000);

    // Advance the SVM clock so request_close's `Clock::get()?.unix_timestamp`
    // lands at a non-zero value. Without this, the default litesvm clock has
    // unix_timestamp = 0 and the closure_started_at reset assertion below
    // would be untestable (post-state 0 == pre-state 0). Picking a value well
    // below `closure_started_at + grace_period` so the mid-grace deadline
    // check inside settle_and_finalize still accepts the tx.
    let mut clock = svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.unix_timestamp = 1_700_000_000;
    svm.set_sysvar(&clock);

    // Submit request_close to enter the Closing state.
    let request_close_ix = RequestCloseBuilder::new()
        .payer(payer.pubkey())
        .channel(channel_pda)
        .instruction();
    svm.expire_blockhash();
    let request_close_tx = Transaction::new(
        &[&payer],
        Message::new(&[request_close_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(request_close_tx)
        .expect("request_close lands");

    // Sanity-check the pre-finalize state: Closing, settled unchanged,
    // closure_started_at populated.
    let pre = svm
        .get_account(&channel_pda)
        .expect("channel pda exists after request_close");
    let pre_view = ChannelView::from_account_data(&pre.data).expect("decode channel");
    assert_eq!(
        pre_view.status(),
        ChannelStatus::Closing as u8,
        "post-request_close status should be Closing"
    );
    assert_eq!(
        pre_view.settled(),
        last_settled,
        "request_close should not touch settled"
    );
    assert!(
        pre_view.closure_started_at() != 0,
        "request_close should populate closure_started_at"
    );

    // Submit settle_and_finalize with has_voucher = 0 mid-grace. Mirrors
    // the without-voucher Open-path test but starts from Closing.
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
    let tx = Transaction::new(
        &[&payer, &payee_keypair],
        Message::new(&[settle_finalize_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .expect("settle_and_finalize from Closing lands mid-grace");

    let post = svm.get_account(&channel_pda).expect("channel pda exists");
    let view = ChannelView::from_account_data(&post.data).expect("decode channel");
    assert_eq!(
        view.status(),
        ChannelStatus::Finalized as u8,
        "settle_and_finalize from Closing should transition to Finalized"
    );
    assert_eq!(
        view.settled(),
        last_settled,
        "with has_voucher=0, settled stays at the prior value"
    );
    assert_eq!(
        view.closure_started_at(),
        0,
        "settle_and_finalize from Closing should reset closure_started_at to 0"
    );
}
