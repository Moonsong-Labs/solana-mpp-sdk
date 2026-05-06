//! Async RPC trait the server-side code talks to instead of the
//! concrete `solana_client` type.
//!
//! Existed because litesvm doesn't speak HTTP, so the test harness
//! couldn't stand in for the real RPC client without something to
//! abstract over. Surface is the four methods the handlers actually
//! call. Method signatures match upstream verbatim so the production
//! impl is a straight delegation and call sites don't translate types.

use async_trait::async_trait;
use solana_account_decoder_client_types::UiAccount;
use solana_client::client_error::Result as ClientResult;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcSendTransactionConfig};
use solana_client::rpc_response::RpcResult;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

/// What the lifecycle handlers, recovery loop, and verify helpers ask
/// of an RPC.
#[async_trait]
pub trait RpcClient: Send + Sync {
    /// Fetch one account at the caller's commitment + encoding. The
    /// SDK only ever asks for `Base64` so the `data.decode()` on the
    /// response stays on the fast path.
    async fn get_ui_account_with_config(
        &self,
        pubkey: &Pubkey,
        config: RpcAccountInfoConfig,
    ) -> RpcResult<Option<UiAccount>>;

    /// Submit a signed tx. Returns the first signature on success.
    /// Preflight + commitment behaviour come from `config`.
    async fn send_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: RpcSendTransactionConfig,
    ) -> ClientResult<Signature>;

    /// Has `signature` reached the requested commitment yet. `true`
    /// means committed at or above; `false` means callers poll again.
    async fn confirm_transaction_with_commitment(
        &self,
        signature: &Signature,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<bool>;

    /// Latest cluster blockhash. Challenge factories pin tx lifetimes
    /// off this; the close path uses it for the server-built settle
    /// and distribute txs.
    async fn get_latest_blockhash(&self) -> ClientResult<Hash>;
}

/// Real-cluster impl: every method just forwards to the concrete
/// `solana_client::nonblocking::rpc_client::RpcClient`. Only cost over
/// a direct call is the virtual dispatch.
#[async_trait]
impl RpcClient for solana_client::nonblocking::rpc_client::RpcClient {
    async fn get_ui_account_with_config(
        &self,
        pubkey: &Pubkey,
        config: RpcAccountInfoConfig,
    ) -> RpcResult<Option<UiAccount>> {
        solana_client::nonblocking::rpc_client::RpcClient::get_ui_account_with_config(
            self, pubkey, config,
        )
        .await
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: RpcSendTransactionConfig,
    ) -> ClientResult<Signature> {
        solana_client::nonblocking::rpc_client::RpcClient::send_transaction_with_config(
            self,
            transaction,
            config,
        )
        .await
    }

    async fn confirm_transaction_with_commitment(
        &self,
        signature: &Signature,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<bool> {
        solana_client::nonblocking::rpc_client::RpcClient::confirm_transaction_with_commitment(
            self,
            signature,
            commitment_config,
        )
        .await
    }

    async fn get_latest_blockhash(&self) -> ClientResult<Hash> {
        solana_client::nonblocking::rpc_client::RpcClient::get_latest_blockhash(self).await
    }
}
