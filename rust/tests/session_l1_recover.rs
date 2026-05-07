//! L1 oracle for `SessionBuilder::recover` against a litesvm cluster.
//!
//! Three scenarios:
//! - healthy resume (record matches on-chain Open),
//! - drop orphan (record but no on-chain channel),
//! - hard-fail unsettled revenue (`accepted_cumulative > on_chain_settled`
//!   and the channel is tombstoned on-chain).
//!
//! Each scenario stands up a real channel (or deliberately skips it),
//! seeds a matching `InMemoryChannelStore` record, and goes through
//! the public `SessionBuilder::recover` so `inspect_all` and
//! `apply_outcomes` both run.

mod common;

use std::sync::Arc;

use common::lite_svm_client::LiteSvmClient;
use common::{program_id_address, program_id_mpp, program_so_path, to_mpp};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::OpenBuilder;
use payment_channels_client::types::{DistributionEntry, DistributionRecipients, OpenArgs};
use solana_address::Address;
use solana_message::Message;
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_mpp::program::payment_channels::state::find_channel_pda;
use solana_mpp::server::session::{session, Network, Pricing, SessionConfig};
use solana_mpp::{
    ChannelRecord, ChannelStatus, ChannelStore, InMemoryChannelStore, RecoveryFailureKind,
    SessionError,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

/// litesvm with the program loaded, mint + ATA wired, and a fresh
/// channel sitting at `Open`. The returned bag is everything a
/// recover scenario needs to build a matching store record.
struct OpenedFixture {
    svm: LiteSVM,
    payer: Keypair,
    payee: Address,
    mint: Address,
    authorized_signer: Keypair,
    salt: u64,
    deposit: u64,
    channel_pda: MppPubkey,
}

fn open_one_channel() -> OpenedFixture {
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
    let (channel_pda_mpp, _bump) = find_channel_pda(
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

    let deposit: u64 = 1_000_000;
    let grace_period: u32 = 60;
    let zero_entry = DistributionEntry {
        recipient: Address::new_from_array([0u8; 32]),
        bps: 0,
    };
    let entries: [DistributionEntry; 32] = std::array::from_fn(|i| {
        if i == 0 {
            DistributionEntry {
                recipient: payee,
                bps: 10_000,
            }
        } else {
            zero_entry.clone()
        }
    });
    let open_args = OpenArgs {
        salt,
        deposit,
        grace_period,
        recipients: DistributionRecipients { count: 1, entries },
    };

    let (event_authority_mpp, _) =
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

    let tx = Transaction::new(
        &[&payer],
        Message::new(&[open_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("open tx lands");

    OpenedFixture {
        svm,
        payer,
        payee,
        mint,
        authorized_signer,
        salt,
        deposit,
        channel_pda: channel_pda_mpp,
    }
}

fn config_for(fixture: &OpenedFixture) -> SessionConfig {
    let mut config = SessionConfig::new_with_defaults(
        MppPubkey::new_from_array([0xaau8; 32]),
        to_mpp(&fixture.payee),
        to_mpp(&fixture.mint),
        6,
        Network::Localnet,
        program_id_mpp(),
        Pricing {
            amount_per_unit: 1_000,
            unit_type: "request".into(),
        },
    );
    config.min_deposit = 1;
    config.max_deposit = 10_000_000;
    // On-chain `grace_period` is 60 (program multiplies by 60 on
    // settle). `grace_period_seconds` here is what the SDK persists;
    // recover doesn't diff against it.
    config.grace_period_seconds = 60;
    config.realm = Some("test".into());
    config.secret_key = Some("test-secret-key-recover".into());
    config
}

fn record_matching(fixture: &OpenedFixture) -> ChannelRecord {
    ChannelRecord {
        channel_id: fixture.channel_pda,
        payer: to_mpp(&fixture.payer.pubkey()),
        payee: to_mpp(&fixture.payee),
        mint: to_mpp(&fixture.mint),
        salt: fixture.salt,
        program_id: program_id_mpp(),
        authorized_signer: to_mpp(&fixture.authorized_signer.pubkey()),
        deposit: fixture.deposit,
        accepted_cumulative: 0,
        on_chain_settled: 0,
        last_voucher: None,
        close_tx: None,
        status: ChannelStatus::Open,
        splits: vec![solana_mpp::Split::Bps {
            recipient: to_mpp(&fixture.payee),
            share_bps: 10_000,
        }],
    }
}

#[tokio::test]
async fn recover_resumes_a_healthy_open_channel_without_mutating_the_store() {
    let fixture = open_one_channel();
    let record = record_matching(&fixture);
    let cid = record.channel_id;

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    store.insert(record.clone()).await.unwrap();

    let config = config_for_existing(&record, &fixture);
    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(fixture.svm));

    let _method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc)
        .recover()
        .await
        .expect("recover succeeds against a healthy on-chain Open channel");

    let post = store.get(&cid).await.unwrap().expect("record still present");
    assert_eq!(post.status, ChannelStatus::Open);
    assert_eq!(post.deposit, fixture.deposit);
}

/// `config_for` but with the record's `payee`, `mint`, `program_id`
/// copied across so the config and store agree on identity. Recover
/// only reads the record, not the config, so it's mostly cosmetic.
fn config_for_existing(record: &ChannelRecord, fixture: &OpenedFixture) -> SessionConfig {
    let mut config = config_for(fixture);
    config.payee = record.payee;
    config.mint = record.mint;
    config.program_id = record.program_id;
    config
}

#[tokio::test]
async fn recover_drops_an_orphan_record_when_the_chain_has_no_pda() {
    // Clean SVM, no open channel; the record's channel_id points at
    // a PDA that never existed.
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program binary");

    // Record's channel_id is well-formed but the PDA isn't there.
    let payer = MppPubkey::new_from_array([0x11u8; 32]);
    let payee = MppPubkey::new_from_array([0x22u8; 32]);
    let mint = MppPubkey::new_from_array([0x33u8; 32]);
    let authorized_signer = MppPubkey::new_from_array([0x44u8; 32]);
    let salt: u64 = 7;
    let (channel_pda, _) = find_channel_pda(
        &payer,
        &payee,
        &mint,
        &authorized_signer,
        salt,
        &program_id_mpp(),
    );

    let record = ChannelRecord {
        channel_id: channel_pda,
        payer,
        payee,
        mint,
        salt,
        program_id: program_id_mpp(),
        authorized_signer,
        deposit: 1_000_000,
        accepted_cumulative: 0,
        on_chain_settled: 0,
        last_voucher: None,
        close_tx: None,
        status: ChannelStatus::Open,
        splits: vec![],
    };

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    store.insert(record.clone()).await.unwrap();

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    let mut config = SessionConfig::new_with_defaults(
        MppPubkey::new_from_array([0xaau8; 32]),
        payee,
        mint,
        6,
        Network::Localnet,
        program_id_mpp(),
        Pricing {
            amount_per_unit: 1_000,
            unit_type: "request".into(),
        },
    );
    config.min_deposit = 1;
    config.max_deposit = 10_000_000;
    config.realm = Some("test".into());
    config.secret_key = Some("test-secret-key-recover-orphan".into());

    let _method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc)
        .recover()
        .await
        .expect("recover succeeds; orphan path is non-fatal");

    // DropOrphan deleted the record.
    let post = store.get(&channel_pda).await.unwrap();
    assert!(post.is_none(), "orphan record must be dropped on recover");
}

#[tokio::test]
async fn recover_hard_fails_when_record_has_unsettled_revenue_against_a_tombstoned_channel() {
    // Open a real channel, then overwrite the PDA with a tombstone.
    // An Open record with `accepted_cumulative > on_chain_settled`
    // against a tombstoned PDA is the unsettled-revenue case recover
    // refuses to start under.
    let fixture = open_one_channel();
    let cid = fixture.channel_pda;
    let mut record = record_matching_for(&fixture);
    record.accepted_cumulative = 250_000;
    record.on_chain_settled = 100_000;
    let config = config_for(&fixture);

    let mut svm = fixture.svm;

    // Stomp the PDA with the 1-byte tombstone (discriminator 2) the
    // program would write on close. Doing it directly keeps the test
    // self-contained.
    let cid_addr = Address::new_from_array(cid.to_bytes());
    let mut tombstoned = svm
        .get_account(&cid_addr)
        .expect("channel account exists post-open");
    tombstoned.data = vec![2u8]; // CLOSED_CHANNEL_DISCRIMINATOR
    svm.set_account(cid_addr, tombstoned)
        .expect("write tombstone payload");

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    store.insert(record.clone()).await.unwrap();

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    let err = session(config)
        .with_store(store.clone())
        .with_rpc(rpc)
        .recover()
        .await
        .expect_err("unsettled revenue must hard-fail recover");

    match err {
        SessionError::RecoveryBatchFailed { failures } => {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].channel_id, cid);
        }
        other => panic!("expected RecoveryBatchFailed, got {other:?}"),
    }

    // Store untouched: the gate refused before any apply ran.
    let post = store.get(&cid).await.unwrap().expect("record still present");
    assert_eq!(post.accepted_cumulative, 250_000);
}

fn record_matching_for(fixture: &OpenedFixture) -> ChannelRecord {
    record_matching(fixture)
}

#[tokio::test]
async fn recover_hard_fails_when_closed_pending_record_lacks_close_tx_evidence() {
    // Clean SVM (no open channel) plus a `ClosedPending` record with
    // `close_tx = None` and an absent PDA. Without `close_tx` evidence
    // recovery cannot tell finalized-and-GC'd apart from never-existed,
    // so the gate must refuse to promote to `ClosedFinalized`.
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program binary");

    let payer = MppPubkey::new_from_array([0x55u8; 32]);
    let payee = MppPubkey::new_from_array([0x66u8; 32]);
    let mint = MppPubkey::new_from_array([0x77u8; 32]);
    let authorized_signer = MppPubkey::new_from_array([0x88u8; 32]);
    let salt: u64 = 99;
    let (channel_pda, _) = find_channel_pda(
        &payer,
        &payee,
        &mint,
        &authorized_signer,
        salt,
        &program_id_mpp(),
    );

    let record = ChannelRecord {
        channel_id: channel_pda,
        payer,
        payee,
        mint,
        salt,
        program_id: program_id_mpp(),
        authorized_signer,
        deposit: 500_000,
        accepted_cumulative: 0,
        on_chain_settled: 0,
        last_voucher: None,
        close_tx: None,
        status: ChannelStatus::ClosedPending,
        splits: vec![],
    };

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    store.insert(record.clone()).await.unwrap();

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    let mut config = SessionConfig::new_with_defaults(
        MppPubkey::new_from_array([0xaau8; 32]),
        payee,
        mint,
        6,
        Network::Localnet,
        program_id_mpp(),
        Pricing {
            amount_per_unit: 1_000,
            unit_type: "request".into(),
        },
    );
    config.min_deposit = 1;
    config.max_deposit = 10_000_000;
    config.realm = Some("test".into());
    config.secret_key = Some("test-secret-key-recover-missing-evidence".into());

    let err = session(config)
        .with_store(store.clone())
        .with_rpc(rpc)
        .recover()
        .await
        .expect_err("missing close_tx evidence must hard-fail recover");

    match err {
        SessionError::RecoveryBatchFailed { failures } => {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].channel_id, channel_pda);
            assert!(
                matches!(failures[0].kind, RecoveryFailureKind::MissingCloseEvidence),
                "expected MissingCloseEvidence, got {:?}",
                failures[0].kind
            );
        }
        other => panic!("expected RecoveryBatchFailed, got {other:?}"),
    }

    let post = store.get(&channel_pda).await.unwrap().expect("record retained");
    assert_eq!(post.status, ChannelStatus::ClosedPending);
}
