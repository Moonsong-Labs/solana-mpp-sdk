//! L1 oracle for `process_topup` against a litesvm cluster.
//!
//! Loads the program, opens a channel, seeds the matching record,
//! builds the canonical multi-ix top-up tx, then walks the intent
//! through challenge issuance, broadcast, and verify. After confirm,
//! store and chain both show the deposit advanced by `additional_amount`.
//!
//! The rejection cases each tamper one slot of the canonical multi-ix
//! list and assert `MaliciousTx`: payment-channels ix data,
//! compute-budget limit, ix order, missing ix, and an extra ix appended
//! after the top-up.

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
use solana_message::Message as MppMessage;
use solana_mpp::program::payment_channels::canonical_tx::{
    build_canonical_topup_ixs, CanonicalTopupInputs, DEFAULT_COMPUTE_UNIT_LIMIT,
    DEFAULT_COMPUTE_UNIT_PRICE,
};
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_mpp::program::payment_channels::state::{find_channel_pda, ChannelView};
use solana_mpp::server::session::{session, FeePayer, Network, Pricing, SessionConfig};
use solana_mpp::{
    ChannelRecord, ChannelStatus, ChannelStore, InMemoryChannelStore, MppErrorCode, SessionError,
    TopUpPayload,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

/// Common setup: open a channel through `OpenBuilder` (so the channel
/// byte layout matches what `recover` will see), seed the matching
/// record, and return the prepared `SessionMethod` plus everything
/// needed to assemble a top-up tx.
#[allow(dead_code)]
struct PreparedTopup {
    method: solana_mpp::server::session::SessionMethod,
    rpc: Arc<dyn MppRpcClient>,
    challenge_id: String,
    canonical_ixs: Vec<solana_instruction::Instruction>,
    blockhash: solana_hash::Hash,
    fee_payer_addr: Address,
    channel_pda_mpp: MppPubkey,
    payer_pk: MppPubkey,
    mint_pk: MppPubkey,
    additional_amount: u64,
    initial_deposit: u64,
    store: Arc<dyn ChannelStore>,
    payer_keypair: Keypair,
}

async fn prepare_topup(
    secret_key: &'static str,
    salt: u64,
    additional_amount: u64,
    initial_deposit: u64,
    max_deposit: u64,
) -> PreparedTopup {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

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
        deposit: initial_deposit,
        grace_period: 60,
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
    let open_tx = Transaction::new(
        &[&payer],
        Message::new(&[open_ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(open_tx).expect("open lands");

    let fee_payer_kp = Keypair::new();
    svm.airdrop(&fee_payer_kp.pubkey(), 5_000_000_000).unwrap();

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let record = ChannelRecord {
        channel_id: channel_pda_mpp,
        payer: to_mpp(&payer.pubkey()),
        payee: to_mpp(&payee),
        mint: to_mpp(&mint),
        salt,
        program_id: program_id_mpp(),
        authorized_signer: to_mpp(&authorized_signer.pubkey()),
        deposit: initial_deposit,
        accepted_cumulative: 0,
        on_chain_settled: 0,
        last_voucher: None,
        close_tx: None,
        status: ChannelStatus::Open,
        splits: vec![solana_mpp::Split::Bps {
            recipient: to_mpp(&payee),
            share_bps: 10_000,
        }],
    };
    store.insert(record.clone()).await.unwrap();

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
    config.max_deposit = max_deposit;
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
        .expect("recover succeeds against open channel");

    let challenge = method
        .build_challenge_for_topup(&channel_pda_mpp)
        .await
        .expect("issue topup challenge");

    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let canonical_ixs = build_canonical_topup_ixs(&CanonicalTopupInputs {
        program_id: program_id_mpp(),
        payer: to_mpp(&payer.pubkey()),
        channel_id: channel_pda_mpp,
        mint: to_mpp(&mint),
        amount: additional_amount,
        compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
        compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
    });

    let fee_payer_addr = Address::new_from_array(fee_payer_kp.pubkey().to_bytes());

    PreparedTopup {
        method,
        rpc,
        challenge_id: challenge.id,
        canonical_ixs,
        blockhash,
        fee_payer_addr,
        channel_pda_mpp,
        payer_pk: to_mpp(&payer.pubkey()),
        mint_pk: to_mpp(&mint),
        additional_amount,
        initial_deposit,
        store,
        payer_keypair: payer,
    }
}

fn assemble_topup_payload(
    prepared: &PreparedTopup,
    canonical_ixs: &[solana_instruction::Instruction],
) -> TopUpPayload {
    let mut tx = solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
        canonical_ixs,
        Some(&prepared.fee_payer_addr),
        &prepared.blockhash,
    ));
    tx.signatures = vec![
        solana_signature::Signature::default();
        tx.message.header.num_required_signatures as usize
    ];
    let msg_data = tx.message_data();
    let payer_sig =
        solana_sdk::signer::Signer::sign_message(&prepared.payer_keypair, &msg_data);
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

    TopUpPayload {
        challenge_id: prepared.challenge_id.clone(),
        channel_id: prepared.channel_pda_mpp.to_string(),
        additional_amount: prepared.additional_amount.to_string(),
        transaction: tx_b64,
    }
}

#[tokio::test]
async fn process_topup_advances_chain_deposit_and_store_record() {
    let prepared =
        prepare_topup("test-secret-key-topup-l1", 99, 250_000, 1_000_000, 10_000_000).await;

    // Pin canonical multi-ix length so a future drift in the builder
    // shows up here.
    assert_eq!(
        prepared.canonical_ixs.len(),
        3,
        "canonical topup list shape changed; update fixture",
    );

    let payload = assemble_topup_payload(&prepared, &prepared.canonical_ixs);
    let _receipt = prepared
        .method
        .process_topup(&payload)
        .await
        .expect("topup succeeds end-to-end");

    let post = prepared
        .store
        .get(&prepared.channel_pda_mpp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        post.deposit,
        prepared.initial_deposit + prepared.additional_amount
    );

    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = prepared
        .rpc
        .clone()
        .get_ui_account_with_config(&prepared.channel_pda_mpp, info)
        .await
        .unwrap();
    let data = resp.value.unwrap().data.decode().unwrap();
    let view = ChannelView::from_account_data(&data).unwrap();
    assert_eq!(
        view.deposit(),
        prepared.initial_deposit + prepared.additional_amount
    );
}

#[tokio::test]
async fn topup_beyond_max_deposit_rejects() {
    // `config.max_deposit` set tight enough that the new deposit
    // would exceed the cap. Cap check runs before broadcast.
    let initial_deposit = 1_000_000u64;
    let prepared = prepare_topup(
        "test-secret-key-topup-cap-l1",
        207,
        200,
        initial_deposit,
        initial_deposit + 100,
    )
    .await;

    let payload = assemble_topup_payload(&prepared, &prepared.canonical_ixs);
    let err = prepared
        .method
        .process_topup(&payload)
        .await
        .expect_err("topup over the cap must reject");
    assert!(
        matches!(err, SessionError::MaxDepositExceeded { .. }),
        "expected MaxDepositExceeded, got {err:?}"
    );

    let post = prepared
        .store
        .get(&prepared.channel_pda_mpp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(post.deposit, initial_deposit);

    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = prepared
        .rpc
        .clone()
        .get_ui_account_with_config(&prepared.channel_pda_mpp, info)
        .await
        .unwrap();
    let data = resp.value.unwrap().data.decode().unwrap();
    let view = ChannelView::from_account_data(&data).unwrap();
    assert_eq!(
        view.deposit(),
        initial_deposit,
        "chain deposit must not advance when the cap rejects"
    );
}

#[tokio::test]
async fn tampered_payment_channels_ix_data_rejects() {
    // Flip a byte inside the payment-channels top_up ix's data.
    let prepared = prepare_topup(
        "test-secret-key-topup-tamper",
        251,
        250_000,
        1_000_000,
        10_000_000,
    )
    .await;

    let mut tampered = prepared.canonical_ixs.clone();
    let last = tampered.last_mut().expect("top-up ix is the tail");
    last.data[1] ^= 0xFF;

    let payload = assemble_topup_payload(&prepared, &tampered);
    let err = prepared
        .method
        .process_topup(&payload)
        .await
        .expect_err("tampered payment-channels top_up ix must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
        "expected MaliciousTx mismatch, got {err:?}"
    );
}

#[tokio::test]
async fn tampered_topup_compute_budget_rejects() {
    // Flip the SetComputeUnitLimit value at slot 1.
    let prepared = prepare_topup(
        "test-secret-key-topup-cb-tamper",
        263,
        250_000,
        1_000_000,
        10_000_000,
    )
    .await;

    let mut tampered = prepared.canonical_ixs.clone();
    tampered[1].data[1] ^= 0xFF;

    let payload = assemble_topup_payload(&prepared, &tampered);
    let err = prepared
        .method
        .process_topup(&payload)
        .await
        .expect_err("tampered compute-budget limit must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
        "expected MaliciousTx mismatch, got {err:?}"
    );
}

#[tokio::test]
async fn reordered_ixs_reject_as_malicious() {
    // Swap the two compute-budget ixs.
    let prepared = prepare_topup(
        "test-secret-key-topup-reorder",
        271,
        250_000,
        1_000_000,
        10_000_000,
    )
    .await;

    let mut reordered = prepared.canonical_ixs.clone();
    reordered.swap(0, 1);

    let payload = assemble_topup_payload(&prepared, &reordered);
    let err = prepared
        .method
        .process_topup(&payload)
        .await
        .expect_err("reordered ixs must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
        "expected MaliciousTx mismatch, got {err:?}"
    );
}

#[tokio::test]
async fn missing_ix_rejects_as_malicious() {
    // Drop the SetComputeUnitPrice ix.
    let prepared = prepare_topup(
        "test-secret-key-topup-missing",
        281,
        250_000,
        1_000_000,
        10_000_000,
    )
    .await;

    let mut shortened = prepared.canonical_ixs.clone();
    shortened.remove(0);

    let payload = assemble_topup_payload(&prepared, &shortened);
    let err = prepared
        .method
        .process_topup(&payload)
        .await
        .expect_err("missing ix must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch") || reason.contains("expected")),
        "expected MaliciousTx for ix-list mismatch, got {err:?}"
    );
}

#[tokio::test]
async fn extra_ix_rejects_as_malicious() {
    // Append a system-transfer (1 lamport, fee-payer to attacker).
    let prepared = prepare_topup(
        "test-secret-key-topup-extra-ix",
        311,
        250_000,
        1_000_000,
        10_000_000,
    )
    .await;
    let attacker = Keypair::new();

    let mut padded = prepared.canonical_ixs.clone();
    let system_program_id = MppPubkey::new_from_array(system_program::ID.to_bytes());
    let fee_payer_pk_mpp = MppPubkey::new_from_array(prepared.fee_payer_addr.to_bytes());
    let attacker_pk_mpp = to_mpp(&attacker.pubkey());
    let mut transfer_data = Vec::with_capacity(12);
    transfer_data.extend_from_slice(&2u32.to_le_bytes());
    transfer_data.extend_from_slice(&1u64.to_le_bytes());
    padded.push(solana_instruction::Instruction {
        program_id: system_program_id,
        accounts: vec![
            solana_instruction::AccountMeta::new(fee_payer_pk_mpp, true),
            solana_instruction::AccountMeta::new(attacker_pk_mpp, false),
        ],
        data: transfer_data,
    });

    let payload = assemble_topup_payload(&prepared, &padded);
    let err = prepared
        .method
        .process_topup(&payload)
        .await
        .expect_err("smuggled extra ix must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch") || reason.contains("expected")),
        "expected MaliciousTx for ix-list mismatch, got {err:?}"
    );

    let post = prepared
        .store
        .get(&prepared.channel_pda_mpp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(post.deposit, prepared.initial_deposit);

    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = prepared
        .rpc
        .clone()
        .get_ui_account_with_config(&prepared.channel_pda_mpp, info)
        .await
        .unwrap();
    let data = resp.value.unwrap().data.decode().unwrap();
    let view = ChannelView::from_account_data(&data).unwrap();
    assert_eq!(view.deposit(), prepared.initial_deposit);
}

#[tokio::test]
async fn signature_vec_below_required_rejects() {
    // Header still says two required sigs; vec is truncated to one
    // so the slot-0 overwrite would wipe the lone client sig and
    // broadcast a tx the cluster rejects after the fact.
    let prepared = prepare_topup(
        "test-secret-key-topup-short-sig",
        419,
        250_000,
        1_000_000,
        10_000_000,
    )
    .await;

    let mut tx = solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
        &prepared.canonical_ixs,
        Some(&prepared.fee_payer_addr),
        &prepared.blockhash,
    ));
    assert_eq!(tx.message.header.num_required_signatures, 2);
    tx.signatures = vec![solana_signature::Signature::default()];

    let tx_bytes = bincode::serialize(&tx).unwrap();
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, tx_bytes);

    let payload = TopUpPayload {
        challenge_id: prepared.challenge_id.clone(),
        channel_id: prepared.channel_pda_mpp.to_string(),
        additional_amount: prepared.additional_amount.to_string(),
        transaction: tx_b64,
    };

    let err = prepared
        .method
        .process_topup(&payload)
        .await
        .expect_err("short signature vec must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("expected 2 signatures")),
        "expected MaliciousTx for short sig vec, got {err:?}"
    );

    let post = prepared
        .store
        .get(&prepared.channel_pda_mpp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(post.deposit, prepared.initial_deposit);
}

#[tokio::test]
async fn mid_list_ix_insertion_rejects_as_malicious() {
    // Splice a system-transfer between the compute-budget prelude and
    // the upstream `top_up` ix. The length check fires before any
    // per-slot diff, so we assert on the error code instead of the
    // reason string.
    let prepared = prepare_topup(
        "test-secret-key-topup-mid-insert",
        421,
        250_000,
        1_000_000,
        10_000_000,
    )
    .await;
    let attacker = Keypair::new();

    let mut spliced = prepared.canonical_ixs.clone();
    let system_program_id = MppPubkey::new_from_array(system_program::ID.to_bytes());
    let fee_payer_pk_mpp = MppPubkey::new_from_array(prepared.fee_payer_addr.to_bytes());
    let attacker_pk_mpp = to_mpp(&attacker.pubkey());
    let mut transfer_data = Vec::with_capacity(12);
    transfer_data.extend_from_slice(&2u32.to_le_bytes());
    transfer_data.extend_from_slice(&1u64.to_le_bytes());
    let transfer_ix = solana_instruction::Instruction {
        program_id: system_program_id,
        accounts: vec![
            solana_instruction::AccountMeta::new(fee_payer_pk_mpp, true),
            solana_instruction::AccountMeta::new(attacker_pk_mpp, false),
        ],
        data: transfer_data,
    };
    // Slot 2 sits right after the two compute-budget ixs; the upstream
    // top_up ix that was at slot 2 shifts to slot 3.
    spliced.insert(2, transfer_ix);

    let payload = assemble_topup_payload(&prepared, &spliced);
    let err = prepared
        .method
        .process_topup(&payload)
        .await
        .expect_err("mid-list ix insertion must reject");
    assert_eq!(
        err.code(),
        MppErrorCode::MaliciousTx,
        "expected MaliciousTx for mid-list insertion, got {err:?}"
    );

    let post = prepared
        .store
        .get(&prepared.channel_pda_mpp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(post.deposit, prepared.initial_deposit);
}
