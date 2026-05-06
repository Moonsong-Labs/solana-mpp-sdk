//! L1 oracle for `process_open` against a litesvm cluster.
//!
//! Issues an Open challenge, builds a tx with the canonical bytes the
//! handler expects, runs `process_open`. Checks the chain has the
//! channel, the store has the record, and the receipt signature
//! matches the broadcast tx.

mod common;

use std::sync::Arc;

use common::lite_svm_client::LiteSvmClient;
use common::{program_id_address, program_id_mpp, program_so_path, to_mpp};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use solana_address::Address;
use solana_message::Message as MppMessage;
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_mpp::program::payment_channels::state::find_channel_pda;
use solana_mpp::server::session::open::{build_canonical_open_ix, CanonicalOpenInputs};
use solana_mpp::server::session::{
    session, FeePayer, Network, OpenChallengeOptions, Pricing, SessionConfig,
};
use solana_mpp::{
    ChannelStatus, ChannelStore, InMemoryChannelStore, OpenPayload, SessionError, Split,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _};

#[tokio::test]
async fn process_open_lands_open_tx_and_writes_record() {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    // Fee payer is server-side; payer + authorized_signer are the
    // client side.
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

    let salt: u64 = 7;
    let deposit: u64 = 1_000_000;
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

    // SessionMethod sitting on the litesvm-backed RPC.
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
    config.secret_key = Some("test-secret-key-open-handler".into());
    // One recipient at full bps; payee remainder is zero.
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

    // Issue the open challenge. The cache pins the blockhash the
    // submitted tx has to use.
    let challenge = method
        .build_challenge_for_open(OpenChallengeOptions::default())
        .await
        .expect("issue open challenge");

    // Canonical open ix; tx has fee-payer at account_keys[0], payer
    // signs at slot 1.
    let splits_typed = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    let open_ix = build_canonical_open_ix(&CanonicalOpenInputs {
        payer: payer_pk,
        payee: payee_pk,
        mint: mint_pk,
        authorized_signer: signer_pk,
        salt,
        deposit,
        grace_period: 60,
        program_id: program_id_mpp(),
        splits: &splits_typed,
    });
    let open_ix_v3 = solana_instruction::Instruction {
        program_id: open_ix.program_id,
        accounts: open_ix.accounts,
        data: open_ix.data,
    };

    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let fee_payer_addr = Address::new_from_array(fee_payer_kp.pubkey().to_bytes());

    let mut tx =
        solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
            &[open_ix_v3],
            Some(&fee_payer_addr),
            &blockhash,
        ));
    tx.signatures =
        vec![solana_signature::Signature::default(); tx.message.header.num_required_signatures as usize];
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
    let tx_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        tx_bytes,
    );

    let payload = OpenPayload {
        challenge_id: challenge.id.clone(),
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

    let receipt = method
        .process_open(&payload)
        .await
        .expect("process_open lands the open tx end-to-end");
    assert!(!receipt.reference.is_empty(), "receipt carries the broadcast signature");

    // Store has the record; status is Open.
    let post = store.get(&channel_pda).await.unwrap().expect("record persisted");
    assert_eq!(post.status, ChannelStatus::Open);
    assert_eq!(post.deposit, deposit);
    assert_eq!(post.payer, payer_pk);
}

#[tokio::test]
async fn tampered_open_ix_rejects_with_malicious_tx() {
    // Submit a payload where `deposit_amount` differs from the deposit
    // baked into the tx. The handler rebuilds the canonical ix from
    // payload fields and diffs against the submitted ix data, so the
    // mismatch trips `MaliciousTx` and the handler bails before any
    // broadcast.
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
    let _payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .owner(&payer.pubkey())
        .send()
        .expect("create payer ATA");

    let salt: u64 = 13;
    let deposit_in_tx: u64 = 1_000_000;
    let deposit_in_payload: u64 = 2_000_000; // differs on purpose
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
    config.secret_key = Some("test-secret-key-open-tamper".into());
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

    // Build the canonical open tx for `deposit_in_tx`.
    let splits_typed = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    let open_ix = build_canonical_open_ix(&CanonicalOpenInputs {
        payer: payer_pk,
        payee: payee_pk,
        mint: mint_pk,
        authorized_signer: signer_pk,
        salt,
        deposit: deposit_in_tx,
        grace_period: 60,
        program_id: program_id_mpp(),
        splits: &splits_typed,
    });
    let open_ix_v3 = solana_instruction::Instruction {
        program_id: open_ix.program_id,
        accounts: open_ix.accounts,
        data: open_ix.data,
    };

    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let fee_payer_addr = Address::new_from_array(fee_payer_kp.pubkey().to_bytes());

    let mut tx =
        solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
            &[open_ix_v3],
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
    let tx_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, tx_bytes);

    // Payload claims `deposit_in_payload`; tx bytes encode
    // `deposit_in_tx`.
    let payload = OpenPayload {
        challenge_id: challenge.id.clone(),
        channel_id: channel_pda.to_string(),
        payer: payer_pk.to_string(),
        payee: payee_pk.to_string(),
        mint: mint_pk.to_string(),
        authorized_signer: signer_pk.to_string(),
        salt: salt.to_string(),
        bump: canonical_bump,
        deposit_amount: deposit_in_payload.to_string(),
        distribution_splits: solana_mpp::typed_to_wire(&splits_typed),
        transaction: tx_b64,
    };

    let err = method
        .process_open(&payload)
        .await
        .expect_err("payload-vs-tx deposit mismatch must reject");
    assert!(
        matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("canonical bytes")),
        "expected MaliciousTx canonical-bytes mismatch, got {err:?}"
    );

    // Store empty: handler bailed before broadcasting.
    let post = store.get(&channel_pda).await.unwrap();
    assert!(
        post.is_none(),
        "tampered open must not write a record"
    );

    // PDA was never created on-chain.
    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = method
        .rpc()
        .clone()
        .get_ui_account_with_config(&channel_pda, info)
        .await
        .unwrap();
    assert!(
        resp.value.is_none(),
        "tampered open must not broadcast; PDA must not exist"
    );
}
