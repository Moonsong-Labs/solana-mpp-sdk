//! L1 integration oracle for the `request_close` ix.
//!
//! Loads the pinned program binary into litesvm, opens a channel,
//! submits `request_close` signed by the payer, then asserts the SDK's
//! `ChannelView` decodes the post-state correctly. Pins the
//! `request_close` wire contract: account list, signer requirement,
//! status transition, and the `closure_started_at` / `grace_period`
//! writes.

mod common;

use common::{program_id_address, program_id_mpp, program_so_path, to_mpp};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::{OpenBuilder, RequestCloseBuilder};
use payment_channels_client::types::{ChannelStatus, OpenArgs};
use solana_address::Address;
use solana_message::Message;
use solana_mpp::program::payment_channels::state::{find_channel_pda, ChannelView};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

#[test]
fn request_close_transitions_channel_to_closing_with_timestamp() {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program binary");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    let authorized_signer_bytes: [u8; 32] = [0x42u8; 32];
    let authorized_signer = Address::new_from_array(authorized_signer_bytes);
    let payee = Address::new_from_array([0xeeu8; 32]);

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
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

    // Vanilla payer-payee channel: empty recipients, payee gets implicit
    // 100% on distribute. request_close does not depend on the splits
    // shape, so an empty-recipients channel is the minimum-fixture form.
    let recipients = Vec::new();

    let salt: u64 = 42;
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

    // Confirm the open landed with the expected pre-state.
    let post_open = svm.get_account(&channel_pda).expect("channel pda exists");
    let post_open_view =
        ChannelView::from_account_data(&post_open.data).expect("decode channel");
    assert_eq!(
        post_open_view.status(),
        ChannelStatus::Open as u8,
        "post-open status should be Open"
    );
    assert_eq!(
        post_open_view.closure_started_at(),
        0,
        "post-open closure_started_at should be 0"
    );
    assert_eq!(
        post_open_view.grace_period(),
        grace_period,
        "grace_period should match the OpenArgs value"
    );

    // Capture the SVM clock before request_close so we can assert the
    // closure_started_at lands in the >=now range. litesvm initialises
    // the sysvar clock; the post-state should match unix_timestamp.
    let pre_clock = svm
        .get_sysvar::<solana_sdk::clock::Clock>();

    // Submit request_close. Two accounts (payer signer, channel writable),
    // no args, no remaining accounts.
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

    // Decode and assert.
    let post_close = svm
        .get_account(&channel_pda)
        .expect("channel pda still exists after request_close");
    let post_close_view =
        ChannelView::from_account_data(&post_close.data).expect("decode post-close channel");

    assert_eq!(
        post_close_view.status(),
        ChannelStatus::Closing as u8,
        "request_close should transition status to Closing"
    );
    assert!(
        post_close_view.closure_started_at() >= pre_clock.unix_timestamp,
        "request_close should write a closure_started_at >= the clock at submission \
         time (got {}, pre_clock.unix_timestamp = {})",
        post_close_view.closure_started_at(),
        pre_clock.unix_timestamp
    );
    assert_eq!(
        post_close_view.grace_period(),
        grace_period,
        "grace_period should be unchanged by request_close"
    );
    assert_eq!(
        post_close_view.deposit(),
        deposit,
        "deposit should be unchanged by request_close"
    );
    assert_eq!(
        post_close_view.settled(),
        0,
        "settled should be unchanged (zero) by request_close"
    );
    assert_eq!(
        post_close_view.payer(),
        to_mpp(&payer.pubkey()),
        "payer field unchanged"
    );
    assert_eq!(
        post_close_view.payee(),
        to_mpp(&payee),
        "payee field unchanged"
    );
}
