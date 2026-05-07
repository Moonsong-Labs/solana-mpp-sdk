//! `RpcClient` impl that drives an in-process `LiteSVM`.
//!
//! litesvm doesn't speak HTTP, so the real RPC client can't stand in
//! when an L1 oracle wants to walk a handler all the way through.
//! Wraps a `LiteSVM` behind the SDK's `RpcClient` trait; everything
//! goes through `tokio::sync::Mutex` because `LiteSVM` is `!Sync` but
//! the trait wants `Send + Sync`.
//!
//! Pubkey/Hash/Signature plumbing: litesvm rides `solana-pubkey` 4.x
//! via `solana-account` 3.4, the SDK is still on 3.x. Both are 32-byte
//! newtypes so each boundary hop just goes through raw bytes.

#![allow(dead_code)]

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use solana_account_decoder_client_types::{UiAccount, UiAccountData, UiAccountEncoding};
use solana_client::client_error::{
    ClientError as SdkClientError, ClientErrorKind, Result as SdkClientResult,
};
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcSendTransactionConfig};
use solana_client::rpc_response::{Response, RpcResponseContext, RpcResult as SdkRpcResult};
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash as SdkHash;
use solana_mpp::program::payment_channels::rpc::RpcClient;
use solana_pubkey::Pubkey as SdkPubkey;
use solana_signature::Signature as SdkSignature;
use solana_transaction::Transaction as SdkTransaction;
use tokio::sync::Mutex;

use litesvm::LiteSVM;
use solana_address::Address as LitesvmAddress;

/// Lets the lifecycle handlers drive a `LiteSVM` through the SDK's
/// `RpcClient` trait.
pub struct LiteSvmClient {
    svm: Arc<Mutex<LiteSVM>>,
}

impl LiteSvmClient {
    pub fn new(svm: LiteSVM) -> Self {
        Self {
            svm: Arc::new(Mutex::new(svm)),
        }
    }

    /// Hand the lock back so a test can poke the SVM between handler
    /// calls (set a sysvar, airdrop, etc).
    pub fn svm(&self) -> Arc<Mutex<LiteSVM>> {
        self.svm.clone()
    }
}

fn sdk_pubkey_to_litesvm(p: &SdkPubkey) -> LitesvmAddress {
    LitesvmAddress::new_from_array(p.to_bytes())
}

fn sdk_tx_bytes_to_versioned(
    tx: &SdkTransaction,
) -> Result<solana_transaction::versioned::VersionedTransaction, SdkClientError> {
    // litesvm's `send_transaction` takes anything `Into<VersionedTransaction>`,
    // and `solana_transaction::Transaction` is on the same major here, so
    // the conversion is just the type's own `From`.
    Ok(tx.clone().into())
}

fn map_litesvm_send_err(meta: litesvm::types::FailedTransactionMetadata) -> SdkClientError {
    // litesvm doesn't have a wire-shaped failure type. The SDK's
    // `client_error_to_session_error` only special-cases BlockhashNotFound
    // and the -32004 AccountNotFound RPC code, neither of which lines up
    // with a litesvm `TransactionError`. Wrap as `Custom` so the handler
    // treats it as a generic broadcast failure.
    SdkClientError::new_with_request(
        ClientErrorKind::Custom(format!("litesvm send_transaction failed: {:?}", meta.err)),
        solana_client::rpc_request::RpcRequest::SendTransaction,
    )
}

#[async_trait]
impl RpcClient for LiteSvmClient {
    async fn get_ui_account_with_config(
        &self,
        pubkey: &SdkPubkey,
        config: RpcAccountInfoConfig,
    ) -> SdkRpcResult<Option<UiAccount>> {
        let address = sdk_pubkey_to_litesvm(pubkey);
        let svm = self.svm.lock().await;
        let account = svm.get_account(&address);
        let context = RpcResponseContext {
            slot: 0,
            api_version: None,
        };
        let value = account.map(|a| {
            // Match the requested encoding so `UiAccountData::decode`
            // on the response keeps working. SDK only ever asks for
            // Base64.
            let encoding = config.encoding.unwrap_or(UiAccountEncoding::Base64);
            let blob = match encoding {
                UiAccountEncoding::Base64 => {
                    base64::engine::general_purpose::STANDARD.encode(&a.data)
                }
                UiAccountEncoding::Base58 => bs58::encode(&a.data).into_string(),
                _ => base64::engine::general_purpose::STANDARD.encode(&a.data),
            };
            let owner_b58 = bs58::encode(a.owner.to_bytes()).into_string();
            UiAccount {
                lamports: a.lamports,
                data: UiAccountData::Binary(blob, encoding),
                owner: owner_b58,
                executable: a.executable,
                rent_epoch: a.rent_epoch,
                space: Some(a.data.len() as u64),
            }
        });
        Ok(Response { context, value })
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &SdkTransaction,
        _config: RpcSendTransactionConfig,
    ) -> SdkClientResult<SdkSignature> {
        let vtx = sdk_tx_bytes_to_versioned(transaction)?;
        let mut svm = self.svm.lock().await;
        let result = svm.send_transaction(vtx);
        match result {
            Ok(meta) => {
                // `TransactionMetadata.signature` is already the SDK's
                // `solana_signature::Signature` 3.x type.
                Ok(meta.signature)
            }
            Err(e) => Err(map_litesvm_send_err(e)),
        }
    }

    async fn confirm_transaction_with_commitment(
        &self,
        signature: &SdkSignature,
        _commitment_config: CommitmentConfig,
    ) -> SdkRpcResult<bool> {
        // litesvm commits synchronously inside `send_transaction`, so
        // any sig we hold is already final. Still check history so a
        // fabricated signature reads back `false` instead of a phantom
        // success. litesvm keeps failed-but-included txs in history
        // too, so filter to `Ok(_)` to mean "execution succeeded".
        let svm = self.svm.lock().await;
        let value = matches!(svm.get_transaction(signature), Some(Ok(_)));
        Ok(Response {
            context: RpcResponseContext {
                slot: 0,
                api_version: None,
            },
            value,
        })
    }

    async fn get_latest_blockhash(&self) -> SdkClientResult<SdkHash> {
        let svm = self.svm.lock().await;
        Ok(svm.latest_blockhash())
    }
}
