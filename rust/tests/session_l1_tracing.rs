//! Pins the session lifecycle tracing schema.
//!
//! Each test drives one lifecycle method end-to-end against a live
//! litesvm cluster and asserts the spans and events documented for
//! `mpp::session` show up in the captured tracing output with the right
//! field values. The handler-oracle setup is reused verbatim; only the
//! assertions differ.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::lite_svm_client::LiteSvmClient;
use common::{program_id_address, program_id_mpp, program_so_path, to_mpp};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::OpenBuilder;
use payment_channels_client::types::{DistributionEntry, OpenArgs};
use solana_address::Address;
use solana_message::{Message as MppMessage, Message};
use solana_mpp::program::payment_channels::canonical_tx::{
    build_canonical_open_ixs, CanonicalOpenInputs, DEFAULT_COMPUTE_UNIT_LIMIT,
    DEFAULT_COMPUTE_UNIT_PRICE,
};
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_mpp::program::payment_channels::state::find_channel_pda;
use solana_mpp::program::payment_channels::voucher::build_signed_payload;
use solana_mpp::server::session::{
    session, FeePayer, Network, OpenChallengeOptions, PayeeSigner, Pricing, SessionConfig,
};
use solana_mpp::{
    ChannelRecord, ChannelStatus, ChannelStore, ClosePayload, InMemoryChannelStore, OpenPayload,
    SigType, SignedVoucher, Split, VoucherData,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;
use tracing_test::traced_test;

/// Boot a litesvm cluster with the payment-channels program loaded,
/// create a 6-decimal mint, fund the payer ATA, and airdrop SOL to any
/// extra keypairs the caller passes in. Returns the loaded SVM plus the
/// payer's keypair, the payer's ATA address, and the mint address.
fn boot_svm_with_mint(extra_airdrops: &[&Keypair]) -> (LiteSVM, Keypair, Address, Address) {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&mint_authority.pubkey(), 1_000_000_000).unwrap();
    for kp in extra_airdrops {
        svm.airdrop(&kp.pubkey(), 5_000_000_000).unwrap();
    }

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

    (svm, payer, payer_token_account, mint)
}

/// Boot a litesvm cluster ready to drive an Open through
/// `SessionMethod::process_open`.
fn boot_open(secret_key: &'static str, salt: u64, deposit: u64) -> OpenSetup {
    let authorized_signer = Keypair::new();
    let fee_payer_kp = Keypair::new();
    let payee = Address::new_from_array([0xeeu8; 32]);

    let (svm, payer, _payer_token_account, mint) = boot_svm_with_mint(&[&fee_payer_kp]);

    OpenSetup {
        svm,
        payer,
        fee_payer_kp,
        authorized_signer,
        payee,
        mint,
        secret_key,
        salt,
        deposit,
    }
}

struct OpenSetup {
    svm: LiteSVM,
    payer: Keypair,
    fee_payer_kp: Keypair,
    authorized_signer: Keypair,
    payee: Address,
    mint: Address,
    secret_key: &'static str,
    salt: u64,
    deposit: u64,
}

/// End-state of `prepare_open`: a recovered `SessionMethod`, the canonical
/// open ix list, plus everything `assemble_open_payload` needs.
struct PreparedOpen {
    method: solana_mpp::server::session::SessionMethod,
    challenge_id: String,
    canonical_ixs: Vec<solana_instruction::Instruction>,
    blockhash: solana_hash::Hash,
    payer_pk: MppPubkey,
    payee_pk: MppPubkey,
    mint_pk: MppPubkey,
    signer_pk: MppPubkey,
    splits_typed: Vec<Split>,
    channel_pda: MppPubkey,
    canonical_bump: u8,
    fee_payer_addr: Address,
    salt: u64,
    deposit: u64,
    payer_keypair: Keypair,
}

async fn prepare_open(setup: OpenSetup) -> PreparedOpen {
    let OpenSetup {
        svm,
        payer,
        fee_payer_kp,
        authorized_signer,
        payee,
        mint,
        secret_key,
        salt,
        deposit,
    } = setup;

    let payee_pk = to_mpp(&payee);
    let mint_pk = to_mpp(&mint);
    let payer_pk = to_mpp(&payer.pubkey());
    let signer_pk = to_mpp(&authorized_signer.pubkey());

    let (channel_pda, canonical_bump) = find_channel_pda(
        &payer_pk,
        &payee_pk,
        &mint_pk,
        &signer_pk,
        salt,
        &program_id_mpp(),
    );

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let fee_payer_signer: Arc<dyn solana_keychain::SolanaSigner> =
        Arc::new(solana_keychain::MemorySigner::from_bytes(&fee_payer_kp.to_bytes()).unwrap());

    let mut config = SessionConfig::new_with_defaults(
        MppPubkey::new_from_array([0xa1u8; 32]),
        payee_pk,
        mint_pk,
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
    config.grace_period_seconds = 60;
    config.fee_payer = Some(FeePayer {
        signer: fee_payer_signer,
    });
    config.realm = Some("test".into());
    config.secret_key = Some(secret_key.into());
    config.splits = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover with empty store");

    let challenge = method
        .build_challenge_for_open(OpenChallengeOptions::default())
        .await
        .expect("issue open challenge");

    let splits_typed = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    let canonical_ixs = build_canonical_open_ixs(&CanonicalOpenInputs {
        program_id: program_id_mpp(),
        payer: payer_pk,
        payee: payee_pk,
        mint: mint_pk,
        authorized_signer: signer_pk,
        salt,
        deposit,
        grace_period_seconds: 60,
        splits: &splits_typed,
        channel_id: channel_pda,
        compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
        compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
    });

    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let fee_payer_addr = Address::new_from_array(fee_payer_kp.pubkey().to_bytes());

    PreparedOpen {
        method,
        challenge_id: challenge.id,
        canonical_ixs,
        blockhash,
        payer_pk,
        payee_pk,
        mint_pk,
        signer_pk,
        splits_typed,
        channel_pda,
        canonical_bump,
        fee_payer_addr,
        salt,
        deposit,
        payer_keypair: payer,
    }
}

fn assemble_open_payload(prepared: &PreparedOpen) -> OpenPayload {
    let mut tx = solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
        &prepared.canonical_ixs,
        Some(&prepared.fee_payer_addr),
        &prepared.blockhash,
    ));
    tx.signatures = vec![
        solana_signature::Signature::default();
        tx.message.header.num_required_signatures as usize
    ];
    let msg_data = tx.message_data();
    let payer_sig = solana_sdk::signer::Signer::sign_message(&prepared.payer_keypair, &msg_data);
    let payer_slot = tx
        .message
        .account_keys
        .iter()
        .position(|k| k.to_bytes() == prepared.payer_keypair.pubkey().to_bytes())
        .expect("payer is in account_keys");
    tx.signatures[payer_slot] =
        solana_signature::Signature::from(<[u8; 64]>::from(payer_sig));

    let tx_bytes = bincode::serialize(&tx).unwrap();
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, tx_bytes);

    OpenPayload {
        challenge_id: prepared.challenge_id.clone(),
        channel_id: prepared.channel_pda.to_string(),
        payer: prepared.payer_pk.to_string(),
        payee: prepared.payee_pk.to_string(),
        mint: prepared.mint_pk.to_string(),
        authorized_signer: prepared.signer_pk.to_string(),
        salt: prepared.salt.to_string(),
        bump: prepared.canonical_bump,
        deposit_amount: prepared.deposit.to_string(),
        distribution_splits: solana_mpp::typed_to_wire(&prepared.splits_typed),
        transaction: tx_b64,
    }
}

#[tokio::test]
#[traced_test]
async fn process_open_emits_session_process_open_span() {
    let setup = boot_open("test-secret-key-tracing-open", 71, 1_000_000);
    let channel_pda_b58 = {
        let (cid, _) = find_channel_pda(
            &to_mpp(&setup.payer.pubkey()),
            &to_mpp(&setup.payee),
            &to_mpp(&setup.mint),
            &to_mpp(&setup.authorized_signer.pubkey()),
            setup.salt,
            &program_id_mpp(),
        );
        cid.to_string()
    };
    let payer_b58 = to_mpp(&setup.payer.pubkey()).to_string();
    let signer_b58 = to_mpp(&setup.authorized_signer.pubkey()).to_string();

    let prepared = prepare_open(setup).await;
    let payload = assemble_open_payload(&prepared);

    prepared
        .method
        .process_open(&payload)
        .await
        .expect("process_open succeeds end-to-end");

    assert!(
        logs_contain("session.process_open"),
        "tracing output should include the session.process_open span",
    );
    assert!(
        logs_contain(&channel_pda_b58),
        "open span should carry the channel id base58 = {channel_pda_b58}",
    );
    assert!(
        logs_contain(&payer_b58),
        "open span should carry the payer base58 = {payer_b58}",
    );
    assert!(
        logs_contain(&signer_b58),
        "open span should carry the authorized_signer base58 = {signer_b58}",
    );
}

/// Boot litesvm, open a channel through upstream's `OpenBuilder`, seed
/// the matching record, and hand back the `SessionMethod` + signing key
/// so the test can submit a voucher.
async fn prepare_voucher(
    secret_key: &'static str,
    salt: u64,
    deposit: u64,
    signer_seed: u8,
) -> (
    solana_mpp::server::session::SessionMethod,
    SigningKey,
    MppPubkey,
) {
    let voucher_signer_dalek = SigningKey::from_bytes(&[signer_seed; 32]);
    let voucher_signer_pubkey = voucher_signer_dalek.verifying_key();
    let authorized_signer_addr =
        Address::new_from_array(voucher_signer_pubkey.to_bytes());
    let payee = Address::new_from_array([0xeeu8; 32]);

    let (mut svm, payer, payer_token_account, mint) = boot_svm_with_mint(&[]);
    let token_program_id = litesvm_token::TOKEN_ID;

    let (channel_pda_mpp, _bump) = find_channel_pda(
        &to_mpp(&payer.pubkey()),
        &to_mpp(&payee),
        &to_mpp(&mint),
        &to_mpp(&authorized_signer_addr),
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

    let recipients = vec![DistributionEntry {
        recipient: payee,
        bps: 10_000,
    }];
    let open_args = OpenArgs {
        salt,
        deposit,
        grace_period: 60,
        recipients,
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
        .authorized_signer(authorized_signer_addr)
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

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let record = ChannelRecord {
        channel_id: channel_pda_mpp,
        payer: to_mpp(&payer.pubkey()),
        payee: to_mpp(&payee),
        mint: to_mpp(&mint),
        salt,
        program_id: program_id_mpp(),
        authorized_signer: to_mpp(&authorized_signer_addr),
        deposit,
        accepted_cumulative: 0,
        on_chain_settled: 0,
        last_voucher: None,
        close_tx: None,
        status: ChannelStatus::Open,
        splits: vec![Split::Bps {
            recipient: to_mpp(&payee),
            share_bps: 10_000,
        }],
    };
    store.insert(record).await.unwrap();

    let fee_payer_kp = Keypair::new();
    svm.airdrop(&fee_payer_kp.pubkey(), 5_000_000_000).unwrap();
    let fee_payer_signer: Arc<dyn solana_keychain::SolanaSigner> =
        Arc::new(solana_keychain::MemorySigner::from_bytes(&fee_payer_kp.to_bytes()).unwrap());

    let mut config = SessionConfig::new_with_defaults(
        MppPubkey::new_from_array([0xa1u8; 32]),
        to_mpp(&payee),
        to_mpp(&mint),
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
    config.grace_period_seconds = 60;
    config.fee_payer = Some(FeePayer {
        signer: fee_payer_signer,
    });
    config.realm = Some("test".into());
    config.secret_key = Some(secret_key.into());

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));
    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover succeeds");

    (method, voucher_signer_dalek, channel_pda_mpp)
}

#[tokio::test]
#[traced_test]
async fn verify_voucher_emits_voucher_accepted_event() {
    let (method, signer, channel_pda) =
        prepare_voucher("test-secret-key-tracing-voucher", 211, 1_000_000, 0x37).await;

    let cumulative: u64 = 250_000;
    let payload = build_signed_payload(&channel_pda, cumulative, 0);
    let signature = signer.sign(&payload);
    let signed = SignedVoucher {
        voucher: VoucherData {
            channel_id: channel_pda.to_string(),
            cumulative_amount: cumulative.to_string(),
            expires_at: None,
        },
        signer: bs58::encode(signer.verifying_key().to_bytes()).into_string(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
        signature_type: SigType::Ed25519,
    };

    method.verify_voucher(&signed).await.expect("accepts");

    assert!(
        logs_contain("voucher accepted"),
        "expected the `voucher accepted` event in captured tracing output",
    );
    assert!(
        logs_contain(&channel_pda.to_string()),
        "voucher event should carry the channel id base58",
    );
    assert!(
        logs_contain("accepted_cumulative=250000"),
        "voucher event should carry accepted_cumulative",
    );
    assert!(
        logs_contain("spent=250000"),
        "voucher event should carry spent",
    );
    assert!(
        logs_contain("session.verify_voucher"),
        "event should be wrapped in the session.verify_voucher span",
    );
}

/// Open a channel through upstream's `OpenBuilder` and stand up a
/// `SessionMethod` ready to drive `process_close` along the lock-settled
/// branch.
async fn prepare_close(
    secret_key: &'static str,
    salt: u64,
    deposit: u64,
) -> (
    solana_mpp::server::session::SessionMethod,
    MppPubkey,
) {
    let authorized_signer = Keypair::new();
    let payee_kp = Keypair::new();
    let payee = Address::new_from_array(payee_kp.pubkey().to_bytes());

    let (mut svm, payer, payer_token_account, mint) = boot_svm_with_mint(&[&payee_kp]);
    let token_program_id = litesvm_token::TOKEN_ID;

    let payer_pk = to_mpp(&payer.pubkey());
    let payee_pk = to_mpp(&payee);
    let mint_pk = to_mpp(&mint);
    let signer_pk = to_mpp(&authorized_signer.pubkey());
    let (channel_pda_mpp, _bump) =
        find_channel_pda(&payer_pk, &payee_pk, &mint_pk, &signer_pk, salt, &program_id_mpp());
    let channel_pda = Address::new_from_array(channel_pda_mpp.to_bytes());
    let channel_token_account = Address::new_from_array(
        get_associated_token_address_with_program_id(
            &AtaPubkey::new_from_array(channel_pda.to_bytes()),
            &AtaPubkey::new_from_array(mint.to_bytes()),
            &AtaPubkey::new_from_array(token_program_id.to_bytes()),
        )
        .to_bytes(),
    );

    let recipients = vec![DistributionEntry {
        recipient: payee,
        bps: 10_000,
    }];
    let open_args = OpenArgs {
        salt,
        deposit,
        grace_period: 60,
        recipients,
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
    let open_tx = Transaction::new(
        &[&payer],
        Message::new(&[open_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(open_tx).expect("open lands");

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let record = ChannelRecord {
        channel_id: channel_pda_mpp,
        payer: payer_pk,
        payee: payee_pk,
        mint: mint_pk,
        salt,
        program_id: program_id_mpp(),
        authorized_signer: signer_pk,
        deposit,
        accepted_cumulative: 0,
        on_chain_settled: 0,
        last_voucher: None,
        close_tx: None,
        status: ChannelStatus::Open,
        splits: vec![Split::Bps {
            recipient: payee_pk,
            share_bps: 10_000,
        }],
    };
    store.insert(record).await.unwrap();

    let fee_payer_kp = Keypair::new();
    svm.airdrop(&fee_payer_kp.pubkey(), 5_000_000_000).unwrap();
    let fee_payer_signer: Arc<dyn solana_keychain::SolanaSigner> =
        Arc::new(solana_keychain::MemorySigner::from_bytes(&fee_payer_kp.to_bytes()).unwrap());
    let payee_msigner: Arc<dyn solana_keychain::SolanaSigner> =
        Arc::new(solana_keychain::MemorySigner::from_bytes(&payee_kp.to_bytes()).unwrap());

    let mut config = SessionConfig::new_with_defaults(
        MppPubkey::new_from_array([0xa1u8; 32]),
        payee_pk,
        mint_pk,
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
    config.grace_period_seconds = 60;
    config.fee_payer = Some(FeePayer {
        signer: fee_payer_signer,
    });
    config.payee_signer = Some(PayeeSigner {
        signer: payee_msigner,
    });
    config.realm = Some("test".into());
    config.secret_key = Some(secret_key.into());
    config.splits = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    config.broadcast_confirm_timeout = Duration::from_secs(2);

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));
    let method = session(config)
        .with_store(store)
        .with_rpc(rpc)
        .recover()
        .await
        .expect("recover succeeds");

    (method, channel_pda_mpp)
}

#[tokio::test]
#[traced_test]
async fn process_close_emits_channel_closed_event() {
    let (method, channel_pda) = prepare_close("test-secret-key-tracing-close", 311, 1_000_000).await;

    let challenge = method
        .build_challenge_for_close(&channel_pda)
        .await
        .expect("issue close challenge");

    // LockSettled branch: no voucher, zero settled, full deposit refunds.
    let payload = ClosePayload {
        challenge_id: challenge.id,
        channel_id: channel_pda.to_string(),
        voucher: None,
    };
    method.process_close(&payload).await.expect("close succeeds");

    assert!(
        logs_contain("channel closed"),
        "expected the `channel closed` event in captured tracing output",
    );
    assert!(
        logs_contain(&channel_pda.to_string()),
        "channel closed event should carry channel id base58",
    );
    assert!(
        logs_contain("refunded=1000000"),
        "lock-settled close with zero spend refunds the full deposit",
    );
    assert!(
        logs_contain("session.process_close"),
        "event should be wrapped in the session.process_close span",
    );
    assert!(
        logs_contain("lock_settled"),
        "process_close span should record branch = lock_settled once the action is decided",
    );
}
