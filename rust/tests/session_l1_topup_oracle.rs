//! L1 integration oracle for the SDK's `top_up` wiring.
//!
//! Loads the pinned program binary into litesvm, opens a channel via the
//! Codama-generated `OpenBuilder`, then submits a `top_up` ix via the upstream
//! `TopUpBuilder` and decodes the resulting Channel PDA via the SDK's
//! `ChannelView`. Asserts that the on-chain `deposit` field advances by
//! exactly the top-up amount and that the channel stays in `Open` status with
//! `version == 1`. If the SDK's account wiring or the upstream builder shape
//! ever drifts, the program rejects the tx and the test fails.
//!
//! Setup mirrors `session_l1_open_oracle.rs`; shared SVM/type-bridge helpers
//! live in `tests/common/mod.rs`.

mod common;

use common::{program_id_address, program_id_mpp, program_so_path, spl_token_amount, to_mpp};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::{OpenBuilder, TopUpBuilder};
use payment_channels_client::types::{
    ChannelStatus, DistributionEntry, DistributionRecipients, OpenArgs, TopUpArgs,
};
use solana_address::Address;
use solana_message::Message;
use solana_mpp::program::payment_channels::state::{find_channel_pda, ChannelView};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

#[test]
fn sdk_built_top_up_advances_channel_deposit() {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program binary");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    let authorized_signer = Keypair::new();
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

    // Mint enough to cover the open deposit AND the top-up. The top-up adds
    // 250_000 to a 1_000_000 deposit, so 5_000_000 leaves ~3.75M slack.
    MintTo::new(
        &mut svm,
        &mint_authority,
        &mint,
        &payer_token_account,
        5_000_000,
    )
    .send()
    .expect("mint to payer ATA");

    let salt: u64 = 42;
    let initial_deposit: u64 = 1_000_000;
    let extra_amount: u64 = 250_000;
    let grace_period: u32 = 60;

    let (channel_pda_mpp, bump) = find_channel_pda(
        &to_mpp(&payer.pubkey()),
        &to_mpp(&payee),
        &to_mpp(&mint),
        &to_mpp(&authorized_signer.pubkey()),
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

    // Open the channel. Distribution shape mirrors the open oracle: one
    // recipient (the payee) absorbs the full deposit. The fixed-amount
    // shape is what upstream pins at this rev; future revs flip to
    // basis-points and this construction updates alongside.
    let zero_entry = DistributionEntry {
        recipient: Address::new_from_array([0u8; 32]),
        amount: 0,
    };
    let entries: [DistributionEntry; 32] = std::array::from_fn(|i| {
        if i == 0 {
            DistributionEntry {
                recipient: payee,
                amount: initial_deposit,
            }
        } else {
            zero_entry.clone()
        }
    });
    let open_args = OpenArgs {
        salt,
        deposit: initial_deposit,
        grace_period,
        recipients: DistributionRecipients { count: 1, entries },
    };

    let (event_authority_mpp, _event_authority_bump) =
        MppPubkey::find_program_address(&[b"event_authority"], &program_id_mpp());
    let event_authority = Address::new_from_array(event_authority_mpp.to_bytes());

    let ata_program =
        Address::new_from_array(spl_associated_token_account_client::program::ID.to_bytes());

    let open_ix = OpenBuilder::new()
        .payer(payer.pubkey())
        .payee(payee)
        .mint(mint)
        .authorized_signer(authorized_signer.pubkey())
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

    // Decode initial channel state via the SDK's typed view. Anchors the
    // pre-topup invariants the program is supposed to set at open: status
    // Open, version 1, the deposit we asked for, the canonical bump we
    // derived off-chain, settled and payer_withdrawn_at both zero.
    let pre = svm.get_account(&channel_pda).expect("channel pda exists");
    let pre_view = ChannelView::from_account_data(&pre.data).expect("decode pre channel");
    assert_eq!(pre_view.version(), 1, "open should set version=1");
    assert_eq!(pre_view.bump(), bump, "open should record canonical bump");
    assert_eq!(
        pre_view.status(),
        ChannelStatus::Open as u8,
        "open should leave status=Open"
    );
    assert_eq!(
        pre_view.deposit(),
        initial_deposit,
        "open should record requested deposit"
    );
    assert_eq!(pre_view.settled(), 0, "open should leave settled=0");
    assert_eq!(
        pre_view.payer_withdrawn_at(),
        0,
        "open should leave payer_withdrawn_at=0 (refund leg has not run)"
    );

    // Snapshot ATA balances right before the top-up. The Channel.deposit
    // counter is a proxy for "tokens moved", but it doesn't pin which
    // accounts moved them: upstream's `top_up::process` validates `mint`
    // and `channel_token_account` (canonical escrow ATA), but it never
    // checks `payer_token_account`, so a miswired source ATA would still
    // round-trip the deposit advance. Pinning balance deltas closes that.
    let pre_payer_balance = spl_token_amount(
        &svm.get_account(&payer_token_account)
            .expect("payer ATA")
            .data,
    );
    let pre_channel_balance = spl_token_amount(
        &svm.get_account(&channel_token_account)
            .expect("channel ATA")
            .data,
    );

    // Refresh the blockhash before the top-up as a defensive guard against
    // dedupe; cheap, and it isolates the two txs even if their messages
    // happen to be hash-equivalent in some future setup.
    svm.expire_blockhash();

    let top_up_ix = TopUpBuilder::new()
        .payer(payer.pubkey())
        .channel(channel_pda)
        .payer_token_account(payer_token_account)
        .channel_token_account(channel_token_account)
        .mint(mint)
        .token_program(token_program_id)
        .top_up_args(TopUpArgs {
            amount: extra_amount,
        })
        .instruction();

    let top_up_tx = Transaction::new(
        &[&payer],
        Message::new(&[top_up_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    let top_up_result = svm.send_transaction(top_up_tx);
    assert!(
        top_up_result.is_ok(),
        "top_up tx rejected by program; SDK account wiring or builder shape diverged: {top_up_result:?}"
    );

    // Decode post-topup state. Upstream's `top_up::process` only mutates
    // `deposit` (a single `set_deposit(deposit + amount)` call); every
    // other channel field stays at its open-time value. This block pins
    // both halves: the deposit advance is exact, and nothing else drifts.
    let post = svm.get_account(&channel_pda).expect("channel pda exists");
    let post_view = ChannelView::from_account_data(&post.data).expect("decode post channel");
    assert_eq!(
        post_view.deposit(),
        initial_deposit + extra_amount,
        "deposit should advance by exactly the top-up amount"
    );
    assert_eq!(
        post_view.status(),
        ChannelStatus::Open as u8,
        "top_up must not transition status"
    );
    assert_eq!(post_view.version(), 1, "version must be unchanged");
    assert_eq!(post_view.settled(), 0, "top_up must not touch settled");
    assert_eq!(
        post_view.payer_withdrawn_at(),
        0,
        "top_up must not touch payer_withdrawn_at"
    );

    // Token balances must move in lockstep with the `deposit` counter:
    // exactly `extra_amount` debited from the payer's ATA, exactly
    // `extra_amount` credited to the channel escrow ATA, and zero net
    // change anywhere else. Catches cases where the program (or a
    // miswired SDK builder) advances the counter without actually moving
    // the right tokens between the right accounts.
    let post_payer_balance = spl_token_amount(
        &svm.get_account(&payer_token_account)
            .expect("payer ATA")
            .data,
    );
    let post_channel_balance = spl_token_amount(
        &svm.get_account(&channel_token_account)
            .expect("channel ATA")
            .data,
    );
    assert_eq!(
        pre_payer_balance - post_payer_balance,
        extra_amount,
        "payer ATA should debit by exactly the top-up amount"
    );
    assert_eq!(
        post_channel_balance - pre_channel_balance,
        extra_amount,
        "channel escrow ATA should credit by exactly the top-up amount"
    );
}
