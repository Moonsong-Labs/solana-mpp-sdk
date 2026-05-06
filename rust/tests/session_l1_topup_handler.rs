//! L1 oracle for `process_topup` against a litesvm cluster.
//!
//! Loads the program, opens a channel, seeds the matching record,
//! builds a canonical top-up tx, then walks the intent through
//! challenge issuance, broadcast, and verify. After confirm, store
//! and chain both show the deposit advanced by exactly
//! `additional_amount`.

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
use solana_mpp::program::payment_channels::state::{find_channel_pda, ChannelView};
use solana_mpp::server::session::topup::{build_canonical_topup_ix, CanonicalTopupInputs};
use solana_mpp::server::session::{session, FeePayer, Network, Pricing, SessionConfig};
use solana_mpp::{
    ChannelRecord, ChannelStatus, ChannelStore, InMemoryChannelStore, SessionError, TopUpPayload,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

#[tokio::test]
async fn process_topup_advances_chain_deposit_and_store_record() {
    // litesvm + a real Open via upstream's `OpenBuilder` so the
    // channel byte layout is what `recover` will see.
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

    let salt: u64 = 99;
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

    let initial_deposit: u64 = 1_000_000;
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

    // SessionMethod with a fee-payer keypair the test controls; SDK
    // wraps it in `MemorySigner` and litesvm has it funded.
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
    config.max_deposit = 10_000_000;
    config.grace_period_seconds = 60;
    config.fee_payer = Some(FeePayer {
        signer: fee_payer_signer,
    });
    config.realm = Some("test".into());
    config.secret_key = Some("test-secret-key-topup-l1".into());

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover succeeds against open channel");

    // The challenge cache lives inside the method; this seeds it.
    let challenge = method
        .build_challenge_for_topup(&channel_pda_mpp)
        .await
        .expect("issue topup challenge");

    // Canonical top-up ix in a partially-signed tx; slot 0 is the
    // fee payer, payer signs slot 1.
    let additional_amount: u64 = 250_000;
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let topup_ix = build_canonical_topup_ix(&CanonicalTopupInputs {
        payer: to_mpp(&payer.pubkey()),
        mint: to_mpp(&mint),
        channel_id: channel_pda_mpp,
        additional_amount,
    });
    let topup_ix_v3 = solana_instruction::Instruction {
        program_id: topup_ix.program_id,
        accounts: topup_ix.accounts,
        data: topup_ix.data,
    };

    // `validate_topup_tx_shape` wants fee-payer at account_keys[0]
    // with the payer signing.
    let fee_payer_addr = Address::new_from_array(fee_payer_kp.pubkey().to_bytes());

    // v3 `Transaction` directly. solana-instruction is on the same
    // major as solana_transaction here so the ix wires straight in.
    use solana_message::Message as MppMessage;
    let mut tx = solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
        &[topup_ix_v3],
        Some(&fee_payer_addr),
        &blockhash,
    ));
    // Slot 0 is the fee payer (left default; the SDK fills it on
    // broadcast). Payer's slot we sign here.
    tx.signatures = vec![solana_signature::Signature::default(); tx.message.header.num_required_signatures as usize];
    let msg_data = tx.message_data();
    let payer_sig = solana_sdk::signer::Signer::sign_message(&payer, &msg_data);
    // Payer's keypair sits at signature slot 1, after the fee payer.
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

    let payload = TopUpPayload {
        challenge_id: challenge.id.clone(),
        channel_id: channel_pda_mpp.to_string(),
        additional_amount: additional_amount.to_string(),
        transaction: tx_b64,
    };

    // Walk the handler.
    let _receipt = method
        .process_topup(&payload)
        .await
        .expect("topup succeeds end-to-end");

    // Both chain and store reflect the new deposit.
    let post = store.get(&channel_pda_mpp).await.unwrap().unwrap();
    assert_eq!(post.deposit, initial_deposit + additional_amount);

    let svm = method.rpc().clone();
    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = svm
        .get_ui_account_with_config(&channel_pda_mpp, info)
        .await
        .unwrap();
    let data = resp.value.unwrap().data.decode().unwrap();
    let view = ChannelView::from_account_data(&data).unwrap();
    assert_eq!(view.deposit(), initial_deposit + additional_amount);
}

#[tokio::test]
async fn topup_beyond_max_deposit_rejects() {
    // Happy-path setup but with `config.max_deposit` tight enough
    // that the new deposit would exceed the cap. Cap check runs
    // before broadcast, so the chain stays at its initial deposit.
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

    let salt: u64 = 207;
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

    let initial_deposit: u64 = 1_000_000;
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
    // Cap is tighter than initial_deposit + additional_amount below.
    config.max_deposit = initial_deposit + 100;
    config.grace_period_seconds = 60;
    config.fee_payer = Some(FeePayer {
        signer: fee_payer_signer,
    });
    config.realm = Some("test".into());
    config.secret_key = Some("test-secret-key-topup-cap-l1".into());

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

    let additional_amount: u64 = 200; // 100 over the cap
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let topup_ix = build_canonical_topup_ix(&CanonicalTopupInputs {
        payer: to_mpp(&payer.pubkey()),
        mint: to_mpp(&mint),
        channel_id: channel_pda_mpp,
        additional_amount,
    });
    let topup_ix_v3 = solana_instruction::Instruction {
        program_id: topup_ix.program_id,
        accounts: topup_ix.accounts,
        data: topup_ix.data,
    };

    let fee_payer_addr = Address::new_from_array(fee_payer_kp.pubkey().to_bytes());
    use solana_message::Message as MppMessage;
    let mut tx = solana_transaction::Transaction::new_unsigned(MppMessage::new_with_blockhash(
        &[topup_ix_v3],
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

    let payload = TopUpPayload {
        challenge_id: challenge.id.clone(),
        channel_id: channel_pda_mpp.to_string(),
        additional_amount: additional_amount.to_string(),
        transaction: tx_b64,
    };

    let err = method
        .process_topup(&payload)
        .await
        .expect_err("topup over the cap must reject");
    assert!(
        matches!(err, SessionError::MaxDepositExceeded { .. }),
        "expected MaxDepositExceeded, got {err:?}"
    );

    // Store untouched; handler bailed before broadcast.
    let post = store.get(&channel_pda_mpp).await.unwrap().unwrap();
    assert_eq!(post.deposit, initial_deposit);

    // Chain unchanged.
    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let svm = method.rpc().clone();
    let resp = svm
        .get_ui_account_with_config(&channel_pda_mpp, info)
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
