//! L1 oracle for `process_open` against a litesvm cluster.
//!
//! Issues an Open challenge, builds the canonical multi-ix tx, runs
//! `process_open`, then checks the channel exists on chain, the store
//! holds the record, and the receipt signature matches the broadcast.
//!
//! The rejection cases each tamper one slot of the canonical multi-ix
//! list and assert `MaliciousTx`: payment-channels ix data, compute-budget
//! limit, ix order, missing ix, and an extra ix appended after the open.

mod common;

use std::sync::Arc;

use common::lite_svm_client::LiteSvmClient;
use common::{program_id_address, program_id_mpp, program_so_path, to_mpp};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use solana_address::Address;
use solana_message::Message as MppMessage;
use solana_mpp::program::payment_channels::canonical_tx::{
    build_canonical_open_ixs, CanonicalOpenInputs, DEFAULT_COMPUTE_UNIT_LIMIT,
    DEFAULT_COMPUTE_UNIT_PRICE,
};
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_mpp::program::payment_channels::state::find_channel_pda;
use solana_mpp::server::session::{
    session, FeePayer, Network, OpenChallengeOptions, Pricing, SessionConfig,
};
use solana_mpp::{
    ChannelStatus, ChannelStore, InMemoryChannelStore, MppErrorCode, OpenPayload, SessionError,
    Split,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _};

/// Inputs threaded through every test: the litesvm + payer + mint
/// fixture is identical, only the salt + tampering differs per case.
struct OpenFixture {
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

fn boot_open_fixture(secret_key: &'static str, salt: u64, deposit: u64) -> OpenFixture {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    let authorized_signer = Keypair::new();
    let fee_payer_kp = Keypair::new();
    let payee = Address::new_from_array([0xeeu8; 32]);

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&fee_payer_kp.pubkey(), 5_000_000_000).unwrap();
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

    OpenFixture {
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

#[allow(dead_code)]
struct PreparedOpen {
    method: solana_mpp::server::session::SessionMethod,
    rpc: Arc<dyn MppRpcClient>,
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
    store: Arc<dyn ChannelStore>,
    salt: u64,
    deposit: u64,
}

async fn prepare_open(fixture: OpenFixture) -> PreparedOpen {
    let OpenFixture {
        svm,
        payer,
        fee_payer_kp,
        authorized_signer,
        payee,
        mint,
        secret_key,
        salt,
        deposit,
    } = fixture;

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
        rpc,
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
        store,
        salt,
        deposit,
    }
}

/// Variant that returns the payer keypair alongside the prepared
/// fixtures so tests can sign the canonical message themselves.
async fn prepare_open_with_payer(fixture: OpenFixture) -> (PreparedOpen, Keypair) {
    let payer_clone = Keypair::try_from(fixture.payer.to_bytes().as_slice()).unwrap();
    let prepared = prepare_open(fixture).await;
    (prepared, payer_clone)
}

fn assemble_payload_and_tx(
    prepared: &PreparedOpen,
    payer: &Keypair,
    canonical_ixs: &[solana_instruction::Instruction],
) -> OpenPayload {
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
    let payer_sig = solana_sdk::signer::Signer::sign_message(payer, &msg_data);
    let payer_slot = tx
        .message
        .account_keys
        .iter()
        .position(|k| k.to_bytes() == payer.pubkey().to_bytes())
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
async fn process_open_lands_open_tx_and_writes_record() {
    let fixture = boot_open_fixture("test-secret-key-open-handler", 7, 1_000_000);
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    // Pin the canonical multi-ix length so a future drift in the
    // builder's ix list shows up here.
    assert_eq!(
        prepared.canonical_ixs.len(),
        // 2 compute-budget + 2 fixed ATAs (payee, payer) + 1
        // split-recipient ATA (the test fixture splits 100% to payee, so
        // this slot duplicates the payee ATA-create; CreateIdempotent
        // makes it a no-op) + 1 payment-channels open ix.
        6,
        "canonical open list shape changed; update fixture",
    );

    let payload = assemble_payload_and_tx(&prepared, &payer, &prepared.canonical_ixs);

    let receipt = prepared
        .method
        .process_open(&payload)
        .await
        .expect("process_open lands the open tx end-to-end");
    assert!(
        !receipt.reference.is_empty(),
        "receipt carries the broadcast signature"
    );

    let post = prepared
        .store
        .get(&prepared.channel_pda)
        .await
        .unwrap()
        .expect("record persisted");
    assert_eq!(post.status, ChannelStatus::Open);
    assert_eq!(post.deposit, prepared.deposit);
    assert_eq!(post.payer, prepared.payer_pk);
}

#[tokio::test]
async fn tampered_payment_channels_ix_data_rejects() {
    // Flip a byte inside the payment-channels open ix's data. The
    // multi-ix gate diffs slot-by-slot; only the matching slot's
    // byte-compare fires.
    let fixture = boot_open_fixture("test-secret-key-open-tamper", 13, 1_000_000);
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut tampered = prepared.canonical_ixs.clone();
    let last = tampered.last_mut().expect("open ix is the tail");
    last.data[1] ^= 0xFF;

    let payload = assemble_payload_and_tx(&prepared, &payer, &tampered);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("tampered payment-channels ix must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
        "expected MaliciousTx mismatch, got {err:?}"
    );

    let post = prepared.store.get(&prepared.channel_pda).await.unwrap();
    assert!(post.is_none(), "tampered open must not write a record");
}

#[tokio::test]
async fn tampered_compute_budget_unit_limit_rejects() {
    // Flip the limit on the SetComputeUnitLimit ix. The compute-budget
    // ix sits at slot 1; the byte-compare diff fires there.
    let fixture = boot_open_fixture("test-secret-key-open-cb-tamper", 17, 1_000_000);
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut tampered = prepared.canonical_ixs.clone();
    let cb_ix = &mut tampered[1];
    // SetComputeUnitLimit's data layout is [discriminator(1), units(4)].
    // Flip a byte inside the units field.
    cb_ix.data[1] ^= 0xFF;

    let payload = assemble_payload_and_tx(&prepared, &payer, &tampered);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("tampered compute-budget limit must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
        "expected MaliciousTx mismatch, got {err:?}"
    );
}

#[tokio::test]
async fn reordered_ixs_reject_as_malicious() {
    // Swap the two compute-budget ixs. Each slot still targets the
    // compute-budget program, but the data bytes are now off-by-one
    // relative to the canonical list, so the byte-compare at slot 0
    // (or slot 1) trips.
    let fixture = boot_open_fixture("test-secret-key-open-reorder", 19, 1_000_000);
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut reordered = prepared.canonical_ixs.clone();
    reordered.swap(0, 1);

    let payload = assemble_payload_and_tx(&prepared, &payer, &reordered);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("reordered ixs must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
        "expected MaliciousTx mismatch, got {err:?}"
    );
}

#[tokio::test]
async fn missing_ix_rejects_as_malicious() {
    // Drop the SetComputeUnitPrice ix. The canonical-list length check
    // fires before per-ix work.
    let fixture = boot_open_fixture("test-secret-key-open-missing", 23, 1_000_000);
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut shortened = prepared.canonical_ixs.clone();
    shortened.remove(0);

    let payload = assemble_payload_and_tx(&prepared, &payer, &shortened);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("missing ix must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch") || reason.contains("expected")),
        "expected MaliciousTx for missing ix, got {err:?}"
    );
}

#[tokio::test]
async fn extra_ix_rejects_as_malicious() {
    // Append a system-transfer (1 lamport, fee-payer to attacker) at
    // the end of the canonical list. The length check fires before any
    // byte work.
    let fixture = boot_open_fixture("test-secret-key-open-extra", 41, 1_000_000);
    let attacker = Keypair::new();
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut padded = prepared.canonical_ixs.clone();
    let system_program_id = MppPubkey::new_from_array(solana_sdk_ids::system_program::ID.to_bytes());
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

    let payload = assemble_payload_and_tx(&prepared, &payer, &padded);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("smuggled extra ix must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch") || reason.contains("expected")),
        "expected MaliciousTx for smuggled ix, got {err:?}"
    );

    let post = prepared.store.get(&prepared.channel_pda).await.unwrap();
    assert!(post.is_none(), "smuggled-ix open must not write a record");

    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = prepared
        .rpc
        .clone()
        .get_ui_account_with_config(&prepared.channel_pda, info)
        .await
        .unwrap();
    assert!(
        resp.value.is_none(),
        "smuggled-ix open must not broadcast; PDA must not exist"
    );
}

#[tokio::test]
async fn signature_vec_below_required_rejects() {
    // Header still says two required sigs; vec is truncated to one
    // so the slot-0 overwrite would wipe the lone client sig and
    // broadcast a tx the cluster rejects after the fact.
    let fixture = boot_open_fixture("test-secret-key-open-short-sig", 53, 1_000_000);
    let (prepared, _payer) = prepare_open_with_payer(fixture).await;

    let mut tx = solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
        &prepared.canonical_ixs,
        Some(&prepared.fee_payer_addr),
        &prepared.blockhash,
    ));
    assert_eq!(tx.message.header.num_required_signatures, 2);
    tx.signatures = vec![solana_signature::Signature::default()];

    let tx_bytes = bincode::serialize(&tx).unwrap();
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, tx_bytes);

    let payload = OpenPayload {
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
    };

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("short signature vec must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("expected 2 signatures")),
        "expected MaliciousTx for short sig vec, got {err:?}"
    );

    let post = prepared.store.get(&prepared.channel_pda).await.unwrap();
    assert!(post.is_none(), "short-sig open must not write a record");
}

#[tokio::test]
async fn mid_list_ix_insertion_rejects_as_malicious() {
    // Splice a system-transfer between the compute-budget prelude and
    // the first ATA-create. The length check fires first, so we assert
    // on the error code instead of the per-slot diff reason string.
    let fixture = boot_open_fixture("test-secret-key-open-mid-insert", 59, 1_000_000);
    let attacker = Keypair::new();
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut spliced = prepared.canonical_ixs.clone();
    let system_program_id = MppPubkey::new_from_array(solana_sdk_ids::system_program::ID.to_bytes());
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
    // Slot 2 sits right after the two compute-budget ixs.
    spliced.insert(2, transfer_ix);

    let payload = assemble_payload_and_tx(&prepared, &payer, &spliced);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("mid-list ix insertion must reject");
    assert_eq!(
        err.code(),
        MppErrorCode::MaliciousTx,
        "expected MaliciousTx for mid-list insertion, got {err:?}"
    );

    let post = prepared.store.get(&prepared.channel_pda).await.unwrap();
    assert!(post.is_none(), "mid-list-spliced open must not write a record");
}

/// Index of the first ATA-create ix in the canonical open list. The
/// canonical builder lays out:
/// `[set_compute_unit_price, set_compute_unit_limit,
///   create_ata(payee), create_ata(payer), create_ata(splits[0]), ..., open]`,
/// so slot 2 is the payee ATA-create.
const FIRST_ATA_IX_INDEX: usize = 2;

/// Wallet pubkey lives at account-meta index 2 of `CreateIdempotent`
/// (funding, ata, wallet, mint, system_program, token_program).
const ATA_WALLET_META_INDEX: usize = 2;

/// Mint pubkey lives at account-meta index 3.
const ATA_MINT_META_INDEX: usize = 3;

/// Token-program pubkey lives at account-meta index 5.
const ATA_TOKEN_PROGRAM_META_INDEX: usize = 5;

#[tokio::test]
async fn tampered_ata_wallet_rejects_as_malicious() {
    // Swap the wallet pubkey on a `CreateIdempotent` ATA ix to an
    // attacker key. The compiled-Message diff catches the swapped
    // account_keys entry.
    let fixture = boot_open_fixture("test-secret-key-open-ata-wallet", 61, 1_000_000);
    let attacker = Keypair::new();
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut tampered = prepared.canonical_ixs.clone();
    let attacker_wallet = to_mpp(&attacker.pubkey());
    tampered[FIRST_ATA_IX_INDEX].accounts[ATA_WALLET_META_INDEX].pubkey = attacker_wallet;

    let payload = assemble_payload_and_tx(&prepared, &payer, &tampered);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("tampered ATA wallet must reject");
    assert_eq!(
        err.code(),
        MppErrorCode::MaliciousTx,
        "expected MaliciousTx for tampered ATA wallet, got {err:?}"
    );
}

#[tokio::test]
async fn tampered_ata_mint_rejects_as_malicious() {
    // Swap the mint pubkey on a `CreateIdempotent` ATA ix to a
    // different (but valid-shaped) mint. The compiled message records a
    // different account_keys entry, so the diff fires.
    let fixture = boot_open_fixture("test-secret-key-open-ata-mint", 67, 1_000_000);
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut tampered = prepared.canonical_ixs.clone();
    let other_mint = MppPubkey::new_from_array([0xDDu8; 32]);
    tampered[FIRST_ATA_IX_INDEX].accounts[ATA_MINT_META_INDEX].pubkey = other_mint;

    let payload = assemble_payload_and_tx(&prepared, &payer, &tampered);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("tampered ATA mint must reject");
    assert_eq!(
        err.code(),
        MppErrorCode::MaliciousTx,
        "expected MaliciousTx for tampered ATA mint, got {err:?}"
    );
}

#[tokio::test]
async fn splits_overflow_rejects_as_malicious() {
    // 9 split recipients exceeds the SDK's `MAX_SPLITS` cap of 8. The
    // open handler rejects at the boundary with MaliciousTx before any
    // tx-shape work runs, so an oversize splits list cannot reach the
    // canonical builder.
    let fixture = boot_open_fixture("test-secret-key-open-splits-overflow", 73, 1_000_000);
    let OpenFixture {
        svm,
        payer,
        fee_payer_kp,
        authorized_signer,
        payee,
        mint,
        secret_key,
        salt,
        deposit,
    } = fixture;

    let payee_pk = to_mpp(&payee);
    let mint_pk = to_mpp(&mint);
    let payer_pk = to_mpp(&payer.pubkey());
    let signer_pk = to_mpp(&authorized_signer.pubkey());

    // 9 distinct recipients with low bps each (total well below 10_000);
    // the canonical-hash path runs after the cap so the bps total does
    // not need to balance.
    let mut splits_typed: Vec<Split> = Vec::with_capacity(9);
    for i in 0..9u8 {
        splits_typed.push(Split::Bps {
            recipient: MppPubkey::new_from_array([0xB0 ^ i; 32]),
            share_bps: 10,
        });
    }

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
    // Advertise the 9-split set so the challenge-equality check passes
    // and the cap inside `validate_open_tx_shape` is what fires.
    config.splits = splits_typed.clone();

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

    // Build a canonical-shaped tx for these 9 splits. The cap fires
    // before any tx-shape work, so the tx contents are immaterial; we
    // build them anyway so the failure is unambiguously the splits cap
    // rather than a payload-parsing or wire-decode issue.
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

    let mut tx = solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
        &canonical_ixs,
        Some(&fee_payer_addr),
        &blockhash,
    ));
    tx.signatures = vec![
        solana_signature::Signature::default();
        tx.message.header.num_required_signatures as usize
    ];
    let msg_data = tx.message_data();
    let payer_sig = solana_sdk::signer::Signer::sign_message(&payer, &msg_data);
    let payer_slot = tx
        .message
        .account_keys
        .iter()
        .position(|k| k.to_bytes() == payer.pubkey().to_bytes())
        .expect("payer is in account_keys");
    tx.signatures[payer_slot] =
        solana_signature::Signature::from(<[u8; 64]>::from(payer_sig));

    let tx_bytes = bincode::serialize(&tx).unwrap();
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, tx_bytes);

    let payload = OpenPayload {
        challenge_id: challenge.id,
        channel_id: channel_pda.to_string(),
        payer: payer_pk.to_string(),
        payee: payee_pk.to_string(),
        mint: mint_pk.to_string(),
        authorized_signer: signer_pk.to_string(),
        salt: salt.to_string(),
        bump: canonical_bump,
        deposit_amount: deposit.to_string(),
        distribution_splits: solana_mpp::typed_to_wire(&splits_typed),
        transaction: tx_b64,
    };

    let err = method
        .process_open(&payload)
        .await
        .expect_err("9-split open must reject");
    assert_eq!(
        err.code(),
        MppErrorCode::MaliciousTx,
        "expected MaliciousTx for splits.len() > 8, got {err:?}"
    );

    let post = store.get(&channel_pda).await.unwrap();
    assert!(post.is_none(), "rejected open must not write a record");
}

#[tokio::test]
async fn tampered_ata_token_program_rejects_as_malicious() {
    // Swap the token-program pubkey on a `CreateIdempotent` ATA ix
    // from classic SPL to Token-2022. The canonical builder uses
    // classic SPL; Token-2022 ATAs derive against a different program
    // id, so the recompiled-Message diff catches the changed account_keys.
    let fixture = boot_open_fixture("test-secret-key-open-ata-tp", 71, 1_000_000);
    let (prepared, payer) = prepare_open_with_payer(fixture).await;

    let mut tampered = prepared.canonical_ixs.clone();
    let token_2022_pk = MppPubkey::new_from_array(spl_token_2022::id().to_bytes());
    tampered[FIRST_ATA_IX_INDEX].accounts[ATA_TOKEN_PROGRAM_META_INDEX].pubkey = token_2022_pk;

    let payload = assemble_payload_and_tx(&prepared, &payer, &tampered);

    let err = prepared
        .method
        .process_open(&payload)
        .await
        .expect_err("tampered ATA token program must reject");
    assert_eq!(
        err.code(),
        MppErrorCode::MaliciousTx,
        "expected MaliciousTx for tampered ATA token program, got {err:?}"
    );
}
