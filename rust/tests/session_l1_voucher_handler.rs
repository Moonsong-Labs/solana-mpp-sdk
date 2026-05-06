//! L1 oracle for `verify_voucher`, called through a `SessionMethod`
//! built via `recover()`.
//!
//! Voucher acceptance is off-chain and CAS-mediated, but the only way
//! callers reach it is via a recovered method. So we stand the method
//! up against litesvm, open a real channel with a known
//! `authorized_signer`, and confirm the watermark advances on accept.

mod common;

use std::sync::Arc;

use common::lite_svm_client::LiteSvmClient;
use common::{program_id_address, program_id_mpp, program_so_path, to_mpp};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::OpenBuilder;
use payment_channels_client::types::{DistributionEntry, DistributionRecipients, OpenArgs};
use solana_address::Address;
use solana_message::Message;
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_mpp::program::payment_channels::state::find_channel_pda;
use solana_mpp::program::payment_channels::voucher::build_signed_payload;
use solana_mpp::server::session::{session, FeePayer, Network, Pricing, SessionConfig};
use solana_mpp::{
    ChannelRecord, ChannelStatus, ChannelStore, InMemoryChannelStore, SigType, SignedVoucher,
    VoucherData,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_sdk_ids::{system_program, sysvar};
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;

#[tokio::test]
async fn verify_voucher_advances_watermark_against_a_recovered_session_method() {
    // litesvm + a real Open channel via upstream's `OpenBuilder`.
    // `authorized_signer` is a fresh ed25519 key we keep around for
    // signing vouchers.
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    // `authorized_signer` is an `Address` and never signs anything
    // on-chain. The bytes get pinned through the Channel PDA so the
    // off-chain voucher signer check has something to compare against.
    let voucher_signer_dalek = SigningKey::from_bytes(&[0x37u8; 32]);
    let voucher_signer_pubkey = voucher_signer_dalek.verifying_key();
    let authorized_signer_addr =
        Address::new_from_array(voucher_signer_pubkey.to_bytes());

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

    let salt: u64 = 31;
    let deposit: u64 = 1_000_000;
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

    // Seed the store record + bring up SessionMethod via recover().
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
        splits: vec![solana_mpp::Split::Bps {
            recipient: to_mpp(&payee),
            share_bps: 10_000,
        }],
    };
    store.insert(record.clone()).await.unwrap();

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
    config.secret_key = Some("test-secret-key-voucher-l1".into());

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));
    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover succeeds");

    // Sign a voucher at cumulative=100_000.
    let cumulative: u64 = 100_000;
    let payload = build_signed_payload(&channel_pda_mpp, cumulative, 0);
    let signature = voucher_signer_dalek.sign(&payload);
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

    let receipt = method
        .verify_voucher(&signed)
        .await
        .expect("voucher accepted");
    assert_eq!(receipt.accepted_cumulative.as_deref(), Some("100000"));
    assert_eq!(receipt.spent.as_deref(), Some("100000"));

    let post = store.get(&channel_pda_mpp).await.unwrap().unwrap();
    assert_eq!(post.accepted_cumulative, cumulative);

    // Re-submitting the same voucher returns the cached receipt;
    // spent doesn't double-count.
    let receipt2 = method
        .verify_voucher(&signed)
        .await
        .expect("second voucher returns the cached receipt");
    assert_eq!(receipt2.accepted_cumulative.as_deref(), Some("100000"));

    // A regression below the watermark rejects.
    let payload_back = build_signed_payload(&channel_pda_mpp, 50_000, 0);
    let sig_back = voucher_signer_dalek.sign(&payload_back);
    let signed_back = SignedVoucher {
        voucher: VoucherData {
            channel_id: channel_pda_mpp.to_string(),
            cumulative_amount: "50000".to_string(),
            expires_at: None,
        },
        signer: bs58::encode(voucher_signer_pubkey.to_bytes()).into_string(),
        signature: bs58::encode(sig_back.to_bytes()).into_string(),
        signature_type: SigType::Ed25519,
    };
    let err = method
        .verify_voucher(&signed_back)
        .await
        .expect_err("regression rejects");
    assert!(matches!(
        err,
        solana_mpp::SessionError::VoucherCumulativeRegression { .. }
    ));

    // Over-deposit voucher rejects.
    let big = deposit + 1;
    let payload_big = build_signed_payload(&channel_pda_mpp, big, 0);
    let sig_big = voucher_signer_dalek.sign(&payload_big);
    let signed_big = SignedVoucher {
        voucher: VoucherData {
            channel_id: channel_pda_mpp.to_string(),
            cumulative_amount: big.to_string(),
            expires_at: None,
        },
        signer: bs58::encode(voucher_signer_pubkey.to_bytes()).into_string(),
        signature: bs58::encode(sig_big.to_bytes()).into_string(),
        signature_type: SigType::Ed25519,
    };
    let err = method
        .verify_voucher(&signed_big)
        .await
        .expect_err("over-deposit voucher rejects");
    assert!(matches!(
        err,
        solana_mpp::SessionError::VoucherOverDeposit { .. }
    ));
}

#[tokio::test]
async fn expired_voucher_rejects() {
    // Open channel + recovered method, then submit a voucher whose
    // `expires_at` sits in the past. Expiry tolerates 5s of wall-clock
    // skew (default `clock_skew_seconds`); 100s back is well past it.
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    let voucher_signer_dalek = SigningKey::from_bytes(&[0x4du8; 32]);
    let voucher_signer_pubkey = voucher_signer_dalek.verifying_key();
    let authorized_signer_addr =
        Address::new_from_array(voucher_signer_pubkey.to_bytes());
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

    let salt: u64 = 91;
    let deposit: u64 = 1_000_000;
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
        splits: vec![solana_mpp::Split::Bps {
            recipient: to_mpp(&payee),
            share_bps: 10_000,
        }],
    };
    store.insert(record.clone()).await.unwrap();

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
    config.secret_key = Some("test-secret-key-voucher-expired-l1".into());

    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));
    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover succeeds");

    // Voucher at a positive cumulative, `expires_at` 100s in the past.
    // The signed payload is `(channel_id, cumulative, expires_at)`, so
    // the signature has to commit to the same i64 the wire field
    // decodes to.
    let cumulative: u64 = 50_000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expires_unix = now - 100;
    let expires_str = time::OffsetDateTime::from_unix_timestamp(expires_unix)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let payload_bytes = build_signed_payload(&channel_pda_mpp, cumulative, expires_unix);
    let signature = voucher_signer_dalek.sign(&payload_bytes);
    let signed = SignedVoucher {
        voucher: VoucherData {
            channel_id: channel_pda_mpp.to_string(),
            cumulative_amount: cumulative.to_string(),
            expires_at: Some(expires_str),
        },
        signer: bs58::encode(voucher_signer_pubkey.to_bytes()).into_string(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
        signature_type: SigType::Ed25519,
    };

    let err = method
        .verify_voucher(&signed)
        .await
        .expect_err("expired voucher must reject");
    assert!(
        matches!(err, solana_mpp::SessionError::VoucherExpired { .. }),
        "expected VoucherExpired, got {err:?}"
    );

    // Watermark unchanged.
    let post = store.get(&channel_pda_mpp).await.unwrap().unwrap();
    assert_eq!(post.accepted_cumulative, 0);
}
