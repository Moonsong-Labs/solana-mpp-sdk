//! L1 oracle scaffolding for `process_close`.
//!
//! Close runs three back-to-back txs: idempotent ATA preflight,
//! `settle_and_finalize` (with or without a voucher), then
//! `distribute`. With upstream's `Vec<DistributionEntry>` recipients,
//! all three txs fit under Solana's 1232-byte packet limit. Litesvm
//! exercises the same byte path here; real-cluster validation is on
//! the L2 surfpool list.
//!
//! Both close paths are covered: lock-settled (no voucher, just
//! tombstones the existing on-chain `settled` watermark) and
//! apply-voucher (signs a voucher under the channel's
//! `authorized_signer`, applies it via `settle_and_finalize`, then
//! distributes).

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::lite_svm_client::LiteSvmClient;
use common::{program_id_address, program_id_mpp, program_so_path, spl_token_amount, to_mpp};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::OpenBuilder;
use payment_channels_client::types::{DistributionEntry, OpenArgs};
use solana_address::Address;
use solana_message::Message;
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_mpp::program::payment_channels::state::{find_channel_pda, CLOSED_CHANNEL_DISCRIMINATOR};
use solana_mpp::program::payment_channels::voucher::build_signed_payload;
use solana_mpp::server::session::{
    session, FeePayer, Network, PayeeSigner, Pricing, SessionConfig,
};
use solana_mpp::{
    ChannelRecord, ChannelStatus, ChannelStore, ClosePayload, InMemoryChannelStore, SigType,
    SignedVoucher, Split, VoucherData,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

#[tokio::test]
async fn lock_settled_close_tombstones_channel_and_advances_store() {
    // litesvm + program loaded + a fresh mint.
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    let authorized_signer = Keypair::new();
    // `settle_and_finalize` requires the merchant signer to equal
    // the channel's `payee`. Hold the keypair so SessionMethod can
    // sign through `MemorySigner`.
    let payee_kp = Keypair::new();
    let payee = Address::new_from_array(payee_kp.pubkey().to_bytes());

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&payee_kp.pubkey(), 1_000_000_000).unwrap();
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

    // Open with a single payee at full bps. Distribute's
    // remaining-accounts list is then one entry, the payee ATA the
    // ATA preflight creates.
    let salt: u64 = 17;
    let deposit: u64 = 1_000_000;
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

    // Seed the store record, bring up the SessionMethod.
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
    store.insert(record.clone()).await.unwrap();

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
    config.secret_key = Some("test-secret-key-close-l1".into());
    config.splits = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    // The async finalize lift polls at Finalized commitment; litesvm
    // is synchronous, so a short timeout suffices.
    config.broadcast_confirm_timeout = Duration::from_secs(2);

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover succeeds against open channel");

    // Close challenge bound to this channel.
    let challenge = method
        .build_challenge_for_close(&channel_pda_mpp)
        .await
        .expect("issue close challenge");

    // LockSettled path: no voucher, just lock the existing on-chain
    // `settled` (zero in this fixture) and tombstone the PDA.
    let payload = ClosePayload {
        challenge_id: challenge.id.clone(),
        channel_id: channel_pda_mpp.to_string(),
        voucher: None,
    };

    let receipt = method
        .process_close(&payload)
        .await
        .expect("process_close succeeds end-to-end on the lock-settled path");
    assert!(
        !receipt.reference.is_empty(),
        "receipt carries the distribute tx signature"
    );

    // PDA was rewritten to the 1-byte ClosedChannel tombstone.
    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let svm_rpc = method.rpc().clone();
    let resp = svm_rpc
        .get_ui_account_with_config(&channel_pda_mpp, info)
        .await
        .unwrap();
    let data = resp.value.expect("PDA still present").data.decode().unwrap();
    assert_eq!(
        data,
        vec![CLOSED_CHANNEL_DISCRIMINATOR],
        "post-close PDA should be the 1-byte tombstone"
    );

    // Store ends up at ClosedPending or ClosedFinalized depending on
    // whether the async finalize lift beat us to it.
    let post = store.get(&channel_pda_mpp).await.unwrap().unwrap();
    assert!(
        matches!(
            post.status,
            ChannelStatus::ClosedPending | ChannelStatus::ClosedFinalized
        ),
        "expected ClosedPending or ClosedFinalized, got {:?}",
        post.status
    );
    assert!(post.close_tx.is_some(), "close tx signature should be recorded");
}

#[tokio::test]
async fn apply_voucher_close_tombstones_channel_and_advances_store() {
    // litesvm + program loaded + a fresh mint. The shape mirrors the
    // lock-settled case but the channel is opened with an
    // `authorized_signer` keypair distinct from the payer so the
    // voucher signature path actually exercises a non-payer signer.
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    // ed25519 signing key the test holds. Its verifying key becomes the
    // channel's `authorized_signer`, so any voucher we forge below
    // verifies under the same pubkey upstream's `settle_and_finalize`
    // checks against.
    let voucher_signer = SigningKey::from_bytes(&[0x5au8; 32]);
    let voucher_signer_pubkey = voucher_signer.verifying_key();
    let authorized_signer_addr =
        Address::new_from_array(voucher_signer_pubkey.to_bytes());
    // Merchant key for the cooperative-close path.
    let payee_kp = Keypair::new();
    let payee = Address::new_from_array(payee_kp.pubkey().to_bytes());

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&payee_kp.pubkey(), 1_000_000_000).unwrap();
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

    // Single payee at full bps; distribute remaining-accounts is one
    // entry, the payee ATA the preflight creates.
    let salt: u64 = 19;
    let deposit: u64 = 1_000_000;
    let payer_pk = to_mpp(&payer.pubkey());
    let payee_pk = to_mpp(&payee);
    let mint_pk = to_mpp(&mint);
    let signer_pk = to_mpp(&authorized_signer_addr);
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
    let payee_token_account_addr = Address::new_from_array(
        get_associated_token_address_with_program_id(
            &AtaPubkey::new_from_array(payee.to_bytes()),
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

    // Seed the store record, bring up the SessionMethod.
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
    store.insert(record.clone()).await.unwrap();

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
    config.secret_key = Some("test-secret-key-close-l1-voucher".into());
    config.splits = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    config.broadcast_confirm_timeout = Duration::from_secs(2);

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover succeeds against open channel");

    // Sign a voucher at cumulative=600_000 against the channel's
    // authorized_signer. < deposit so the voucher actually settles a
    // partial pool; > 0 so the apply-voucher branch fires (lock-settled
    // would no-op the watermark at 0).
    let cumulative: u64 = 600_000;
    let payload_bytes = build_signed_payload(&channel_pda_mpp, cumulative, 0);
    let signature = voucher_signer.sign(&payload_bytes);
    let signed = SignedVoucher {
        voucher: VoucherData {
            channel_id: channel_pda_mpp.to_string(),
            cumulative_amount: cumulative.to_string(),
            expires_at: None,
        },
        signer: bs58::encode(voucher_signer_pubkey.to_bytes()).into_string(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
        signature_type: SigType::Ed25519,
    };

    // Pre-close payee token balance (should be zero given a fresh mint).
    let svm_handle = rpc.clone();
    let pre_payee = read_token_balance(&svm_handle, &payee_token_account_addr).await;

    // Issue the close challenge and run the apply-voucher path.
    let challenge = method
        .build_challenge_for_close(&channel_pda_mpp)
        .await
        .expect("issue close challenge");
    let payload = ClosePayload {
        challenge_id: challenge.id.clone(),
        channel_id: channel_pda_mpp.to_string(),
        voucher: Some(signed.clone()),
    };

    let receipt = method
        .process_close(&payload)
        .await
        .expect("process_close succeeds end-to-end on the apply-voucher path");

    // Receipt shape: reference is the channel id, tx_hash carries the
    // distribute signature, refunded is deposit - cumulative.
    // Apply-voucher closes also surface the `acceptedCumulative` /
    // `spent` fields a `verify_voucher` receipt would for the same
    // voucher.
    assert_eq!(receipt.reference, channel_pda_mpp.to_string());
    let tx_hash = receipt
        .tx_hash
        .as_deref()
        .expect("apply-voucher close receipt carries the distribute tx signature");
    assert!(!tx_hash.is_empty(), "tx_hash should be non-empty");
    assert_eq!(
        receipt.refunded.as_deref(),
        Some((deposit - cumulative).to_string().as_str()),
    );
    assert_eq!(
        receipt.accepted_cumulative.as_deref(),
        Some(cumulative.to_string().as_str()),
        "apply-voucher close receipt carries acceptedCumulative",
    );
    assert_eq!(
        receipt.spent.as_deref(),
        Some(cumulative.to_string().as_str()),
        "spent = cumulative - prior_accepted (prior=0 here)",
    );

    // PDA tombstoned to the 1-byte ClosedChannel discriminator.
    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let svm_rpc = method.rpc().clone();
    let resp = svm_rpc
        .get_ui_account_with_config(&channel_pda_mpp, info)
        .await
        .unwrap();
    let data = resp.value.expect("PDA still present").data.decode().unwrap();
    assert_eq!(
        data,
        vec![CLOSED_CHANNEL_DISCRIMINATOR],
        "post-close PDA should be the 1-byte tombstone"
    );

    // Store: ClosedPending or ClosedFinalized, on_chain_settled tracks
    // the voucher's cumulative_amount, and the close tx signature is
    // recorded.
    let post = store.get(&channel_pda_mpp).await.unwrap().unwrap();
    assert!(
        matches!(
            post.status,
            ChannelStatus::ClosedPending | ChannelStatus::ClosedFinalized
        ),
        "expected ClosedPending or ClosedFinalized, got {:?}",
        post.status,
    );
    assert_eq!(
        post.on_chain_settled, cumulative,
        "store should record the voucher's cumulative_amount as the on-chain settled watermark",
    );
    assert!(
        post.close_tx.is_some(),
        "close tx signature should be recorded",
    );

    // Recipient ATA received its bps share. Single payee at 10_000 bps,
    // so payee absorbs the full settled pool.
    let post_payee = read_token_balance(&svm_handle, &payee_token_account_addr).await;
    assert_eq!(
        post_payee - pre_payee,
        cumulative,
        "payee ATA should have received the full settled pool at 10_000 bps",
    );
}

#[tokio::test]
async fn close_apply_voucher_rejects_with_regression_when_concurrent_voucher_advanced_watermark() {
    // A verify_voucher call lands at cumulative 900_000 before close
    // runs. Close then submits a stale voucher at 300_000; the
    // in-band recheck (and the watermark CAS behind it) reject with
    // VoucherCumulativeRegression instead of committing the older
    // voucher and silently dropping the difference.
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    let voucher_signer = SigningKey::from_bytes(&[0x6au8; 32]);
    let voucher_signer_pubkey = voucher_signer.verifying_key();
    let authorized_signer_addr =
        Address::new_from_array(voucher_signer_pubkey.to_bytes());
    let payee_kp = Keypair::new();
    let payee = Address::new_from_array(payee_kp.pubkey().to_bytes());

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&payee_kp.pubkey(), 1_000_000_000).unwrap();
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

    let salt: u64 = 23;
    let deposit: u64 = 1_000_000;
    let payer_pk = to_mpp(&payer.pubkey());
    let payee_pk = to_mpp(&payee);
    let mint_pk = to_mpp(&mint);
    let signer_pk = to_mpp(&authorized_signer_addr);
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
    store.insert(record.clone()).await.unwrap();

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
    config.secret_key = Some("test-secret-close-race".into());
    config.splits = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    config.broadcast_confirm_timeout = Duration::from_secs(2);

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover succeeds against open channel");

    // Land a verify_voucher at 900_000 first.
    let high_cumulative: u64 = 900_000;
    let high_payload = build_signed_payload(&channel_pda_mpp, high_cumulative, 0);
    let high_sig = voucher_signer.sign(&high_payload);
    let high_voucher = SignedVoucher {
        voucher: VoucherData {
            channel_id: channel_pda_mpp.to_string(),
            cumulative_amount: high_cumulative.to_string(),
            expires_at: None,
        },
        signer: bs58::encode(voucher_signer_pubkey.to_bytes()).into_string(),
        signature: bs58::encode(high_sig.to_bytes()).into_string(),
        signature_type: SigType::Ed25519,
    };
    method
        .verify_voucher(&high_voucher)
        .await
        .expect("high voucher accepted");
    let mid = store.get(&channel_pda_mpp).await.unwrap().unwrap();
    assert_eq!(mid.accepted_cumulative, high_cumulative);

    // Close presents a stale lower-cumulative voucher.
    let stale_cumulative: u64 = 300_000;
    let stale_payload_bytes = build_signed_payload(&channel_pda_mpp, stale_cumulative, 0);
    let stale_sig = voucher_signer.sign(&stale_payload_bytes);
    let stale_voucher = SignedVoucher {
        voucher: VoucherData {
            channel_id: channel_pda_mpp.to_string(),
            cumulative_amount: stale_cumulative.to_string(),
            expires_at: None,
        },
        signer: bs58::encode(voucher_signer_pubkey.to_bytes()).into_string(),
        signature: bs58::encode(stale_sig.to_bytes()).into_string(),
        signature_type: SigType::Ed25519,
    };
    let challenge = method
        .build_challenge_for_close(&channel_pda_mpp)
        .await
        .expect("issue close challenge");
    let payload = ClosePayload {
        challenge_id: challenge.id.clone(),
        channel_id: channel_pda_mpp.to_string(),
        voucher: Some(stale_voucher),
    };

    let err = method
        .process_close(&payload)
        .await
        .expect_err("close with stale voucher must reject");
    assert!(
        matches!(
            err,
            solana_mpp::SessionError::VoucherCumulativeRegression { .. }
        ),
        "expected VoucherCumulativeRegression, got {err:?}",
    );

    // Pre-broadcast rejection: status stays Open and the watermark
    // sits at the higher accepted voucher.
    let post = store.get(&channel_pda_mpp).await.unwrap().unwrap();
    assert_eq!(post.status, ChannelStatus::Open);
    assert_eq!(post.accepted_cumulative, high_cumulative);
}

/// Read the SPL Token balance at `ata_addr` via the same RPC the
/// SessionMethod is using. Decodes through `spl_token_amount` so the
/// helper covers classic and Token-2022 base layouts identically.
async fn read_token_balance(
    rpc: &Arc<dyn MppRpcClient>,
    ata_addr: &Address,
) -> u64 {
    let pk = MppPubkey::new_from_array(ata_addr.to_bytes());
    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = rpc
        .get_ui_account_with_config(&pk, info)
        .await
        .expect("rpc get_ui_account succeeds");
    let Some(ui) = resp.value else {
        return 0;
    };
    let data = ui.data.decode().expect("base64 decodes");
    spl_token_amount(&data)
}
