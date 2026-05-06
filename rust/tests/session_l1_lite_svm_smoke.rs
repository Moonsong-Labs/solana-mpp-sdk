//! Smoke check: `LiteSvmClient` satisfies `RpcClient` and round-trips
//! the four methods the lifecycle handlers actually call (latest
//! blockhash, fetch account, send tx, confirm tx).

mod common;

use std::sync::Arc;

use common::lite_svm_client::LiteSvmClient;
use litesvm::LiteSVM;
use solana_address::Address;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcSendTransactionConfig};
use solana_commitment_config::CommitmentConfig;
use solana_message::Message;
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_pubkey::Pubkey as SdkPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _, transaction::Transaction};
use solana_system_interface::instruction as system_ix;

#[tokio::test]
async fn lite_svm_client_round_trips_through_the_trait() {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let recipient = Keypair::new();
    let recipient_pk_sdk = SdkPubkey::new_from_array(recipient.pubkey().to_bytes());

    let client: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(svm));

    // get_latest_blockhash
    let blockhash = client
        .get_latest_blockhash()
        .await
        .expect("blockhash through the trait");
    assert_ne!(blockhash, solana_hash::Hash::default());

    // get_ui_account_with_config: an unfunded recipient is None.
    let info = RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        ..RpcAccountInfoConfig::default()
    };
    let resp = client
        .get_ui_account_with_config(&recipient_pk_sdk, info.clone())
        .await
        .expect("get_ui_account through the trait");
    assert!(resp.value.is_none());

    // send_transaction_with_config: a system transfer should land.
    let payer_addr = Address::new_from_array(payer.pubkey().to_bytes());
    let recipient_addr = Address::new_from_array(recipient.pubkey().to_bytes());
    let ix = system_ix::transfer(&payer_addr, &recipient_addr, 5_000_000);
    let tx = Transaction::new(
        &[&payer],
        Message::new(&[ix], Some(&payer.pubkey())),
        blockhash,
    );
    let send_config = RpcSendTransactionConfig {
        preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
        ..Default::default()
    };
    let sig = client
        .send_transaction_with_config(&tx, send_config)
        .await
        .expect("send_transaction through the trait");

    // confirm_transaction_with_commitment: the freshly-sent tx is committed.
    let confirm = client
        .confirm_transaction_with_commitment(&sig, CommitmentConfig::confirmed())
        .await
        .expect("confirm_transaction through the trait");
    assert!(confirm.value, "freshly-sent tx must read as confirmed");

    // Recipient now has the lamports.
    let resp = client
        .get_ui_account_with_config(&recipient_pk_sdk, info)
        .await
        .expect("post-send fetch through the trait");
    let value = resp.value.expect("recipient account exists after transfer");
    assert_eq!(value.lamports, 5_000_000);
}
