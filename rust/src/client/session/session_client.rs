//! Low-level transaction builders for the session intent.
//!
//! `SessionClient` owns one signer plus an `RpcClient` and produces:
//!
//! - `build_open_tx` and `build_topup_tx`: partial-signed txs the higher
//!   layer wraps in `OpenPayload` / `TopUpPayload` and ships to the
//!   server. Slot 0 (fee payer) stays empty; the payer slot is filled
//!   via the configured signer. The server co-signs and broadcasts.
//! - `request_close`, `finalize`, `withdraw_payer`, `distribute`,
//!   `distribute_with_splits`: payer-fee-paid escape routes the client
//!   submits directly without server cooperation.
//!
//! The open and top-up paths drive the canonical builders shared with
//! the server (`program::payment_channels::canonical_tx`) so the bytes
//! match across both halves of the protocol; a divergence trips
//! `validate_canonical_multi_ix_tx_shape` server-side at submit time.

use std::sync::Arc;

use base64::Engine;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use payment_channels_client::instructions::{
    DistributeBuilder, FinalizeBuilder, RequestCloseBuilder, WithdrawPayerBuilder,
};
use payment_channels_client::types::DistributeArgs;

use crate::error::ClientError;
use crate::program::payment_channels::canonical_tx::{
    ata_address, build_canonical_open_ixs, build_canonical_topup_ixs, derive_channel_pda,
    pk_to_addr, spl_token_id, splits_to_recipients, CanonicalOpenInputs, CanonicalTopupInputs,
    DEFAULT_COMPUTE_UNIT_LIMIT, DEFAULT_COMPUTE_UNIT_PRICE,
};
use crate::program::payment_channels::rpc::RpcClient as MppRpcClient;
use crate::program::payment_channels::splits::TREASURY_OWNER;
use crate::program::payment_channels::state::ChannelView;
use crate::protocol::intents::session::{wire_to_typed, BpsSplit, Split};
use crate::store::ChannelStatus;

use solana_account_decoder_client_types::{UiAccount, UiAccountEncoding};
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcSendTransactionConfig};
use solana_commitment_config::CommitmentConfig;

/// Low-level builder for the session intent's on-chain transactions.
///
/// One `SessionClient` per `(signer, rpc, program)` triple. Cloning is
/// cheap because every field is `Arc`-backed; share freely across tasks.
pub struct SessionClient {
    signer: Arc<dyn SolanaSigner>,
    rpc: Arc<dyn MppRpcClient>,
    program: Pubkey,
}

/// Output of `build_open_tx`. Carries the derived channel id, the
/// canonical bump, and the partial-signed `Transaction` ready for the
/// server to co-sign.
///
/// Slot 0 of `transaction.signatures` is the empty fee-payer slot; the
/// payer slot is already filled by the configured signer. Use
/// `to_wire_string` to render the base64 form the open payload carries.
pub struct OpenTxBuild {
    pub channel_id: Pubkey,
    pub canonical_bump: u8,
    pub transaction: Transaction,
}

impl OpenTxBuild {
    /// Render the partial-signed transaction as the base64 string the
    /// `OpenPayload.transaction` field carries on the wire. Round-trips
    /// via `bincode` (same encoding the server expects when it decodes
    /// the field for `validate_canonical_multi_ix_tx_shape`).
    pub fn to_wire_string(&self) -> String {
        let bytes = bincode::serialize(&self.transaction).expect("bincode serialize Transaction");
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}

impl SessionClient {
    pub fn new(signer: Arc<dyn SolanaSigner>, rpc: Arc<dyn MppRpcClient>, program: Pubkey) -> Self {
        Self {
            signer,
            rpc,
            program,
        }
    }

    /// Reject Token-2022 mints up front. v1 only supports classic SPL
    /// Token; the server's `process_open` mint-owner check would
    /// reject Token-2022 anyway, but catching it here saves the
    /// network round trip and lets the higher layer surface a typed
    /// `ProtocolViolation` before any signing happens.
    pub async fn validate_classic_spl_mint(&self, mint: &Pubkey) -> Result<(), ClientError> {
        let ui = self
            .rpc
            .get_ui_account_with_config(mint, base64_account_info_config())
            .await
            .map_err(|e| ClientError::Rpc(format!("get_account({mint}): {e}")))?
            .value
            .ok_or_else(|| ClientError::ProtocolViolation(format!("mint {mint} not found")))?;

        let owner_bytes = decode_pubkey_b58(&ui.owner).ok_or_else(|| {
            ClientError::ProtocolViolation(format!(
                "mint {mint} returned a non-base58 owner string"
            ))
        })?;

        if owner_bytes == spl_token::id().to_bytes() {
            Ok(())
        } else if owner_bytes == spl_token_2022::id().to_bytes() {
            Err(ClientError::ProtocolViolation(format!(
                "mint {mint} is Token-2022; v1 SDK only supports classic SPL Token"
            )))
        } else {
            let owner = Pubkey::new_from_array(owner_bytes);
            Err(ClientError::ProtocolViolation(format!(
                "mint {mint} is owned by {owner}, expected classic SPL Token"
            )))
        }
    }

    /// Build a partial-signed `open` transaction.
    ///
    /// Pre-flight: rejects Token-2022 mints. The payer slot is signed by
    /// `self.signer`; the fee-payer slot stays empty so the server can
    /// drop its co-signature in. The authorized signer is forced to the
    /// payer key in v1 to avoid silent split-key configurations: a
    /// caller that wants a separate session signer asks the higher
    /// layer, which builds the open with the same key it owns.
    ///
    /// The ix list goes through the canonical builder shared with the
    /// server; a divergence trips
    /// `validate_canonical_multi_ix_tx_shape` server-side. The
    /// resulting transaction's bytes match what the server would
    /// reconstruct from the same wire fields.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_open_tx(
        &self,
        fee_payer: &Pubkey,
        recent_blockhash: &Hash,
        payee: &Pubkey,
        mint: &Pubkey,
        salt: u64,
        deposit: u64,
        splits: &[BpsSplit],
        grace_period_seconds: u32,
    ) -> Result<OpenTxBuild, ClientError> {
        self.validate_classic_spl_mint(mint).await?;

        let payer = self.signer.pubkey();
        let authorized_signer = payer;

        let (channel_id, canonical_bump) =
            derive_channel_pda(&payer, payee, mint, &authorized_signer, salt, &self.program);

        let typed_splits = wire_to_typed(splits, |e| ClientError::ProtocolViolation(e.to_string()))?;

        let canonical_ixs = build_canonical_open_ixs(&CanonicalOpenInputs {
            program_id: self.program,
            payer,
            payee: *payee,
            mint: *mint,
            authorized_signer,
            salt,
            deposit,
            grace_period_seconds,
            splits: &typed_splits,
            channel_id,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        });

        let tx = self
            .build_two_sig_tx(canonical_ixs, fee_payer, recent_blockhash, &payer, "open")
            .await?;

        Ok(OpenTxBuild {
            channel_id,
            canonical_bump,
            transaction: tx,
        })
    }

    /// Build a partial-signed `top_up` transaction.
    ///
    /// Same shape rules as `build_open_tx`: payer slot signed, fee-payer
    /// slot empty for server co-sign. No splits, no PDA derivation
    /// (the channel already exists), no Token-2022 check (the channel
    /// could not have opened against a Token-2022 mint in v1).
    pub async fn build_topup_tx(
        &self,
        fee_payer: &Pubkey,
        recent_blockhash: &Hash,
        channel_id: &Pubkey,
        mint: &Pubkey,
        amount: u64,
    ) -> Result<Transaction, ClientError> {
        let payer = self.signer.pubkey();

        let canonical_ixs = build_canonical_topup_ixs(&CanonicalTopupInputs {
            program_id: self.program,
            payer,
            channel_id: *channel_id,
            mint: *mint,
            amount,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        });

        self.build_two_sig_tx(canonical_ixs, fee_payer, recent_blockhash, &payer, "topup")
            .await
    }

    /// Submit the upstream `request_close` ix as the payer. Allowed only
    /// from `Open`. Starts the on-chain grace window; merchant or
    /// crank-runner picks up `finalize` after the grace period.
    /// Confirms before returning.
    pub async fn request_close(&self, channel_id: &Pubkey) -> Result<Signature, ClientError> {
        let _view = self
            .fetch_view_and_check_status(channel_id, &[ChannelStatus::Open], "request_close")
            .await?;

        let payer = self.signer.pubkey();
        let mut builder = RequestCloseBuilder::new();
        builder
            .payer(pk_to_addr(&payer))
            .channel(pk_to_addr(channel_id));

        self.submit_payer_ixs(vec![builder.instruction()], &payer)
            .await
    }

    /// Submit the upstream `finalize` ix from `Closing`. Permissionless
    /// post-grace transition to `Finalized`. Confirms before returning.
    ///
    /// Note: at the pinned upstream rev `finalize` returns
    /// `PaymentChannelsError::NotImplemented` from the cluster; the
    /// builder is wired up but live calls fail. The escape route is
    /// kept here for forward compatibility and for L1 oracles to drive
    /// the path once upstream lands the implementation.
    pub async fn finalize(&self, channel_id: &Pubkey) -> Result<Signature, ClientError> {
        let _view = self
            .fetch_view_and_check_status(channel_id, &[ChannelStatus::Closing], "finalize")
            .await?;

        let payer = self.signer.pubkey();
        let mut builder = FinalizeBuilder::new();
        builder.channel(pk_to_addr(channel_id));

        self.submit_payer_ixs(vec![builder.instruction()], &payer)
            .await
    }

    /// Submit the upstream `withdraw_payer` ix from `Finalized`. Pulls
    /// the unsettled remainder back to the payer's funding ATA.
    /// Confirms before returning.
    ///
    /// Same upstream-stub caveat as `finalize` at the pinned rev: the
    /// builder ships, the live ix returns `NotImplemented`.
    pub async fn withdraw_payer(&self, channel_id: &Pubkey) -> Result<Signature, ClientError> {
        let view = self
            .fetch_view_and_check_status(
                channel_id,
                &[ChannelStatus::ClosedFinalized],
                "withdraw_payer",
            )
            .await?;

        let payer = self.signer.pubkey();
        let mint = view.mint();
        let token_program_pk = spl_token_id();
        let payer_token_account = ata_address(&payer, &mint, &token_program_pk);
        let channel_token_account = ata_address(channel_id, &mint, &token_program_pk);

        let mut builder = WithdrawPayerBuilder::new();
        builder
            .payer(pk_to_addr(&payer))
            .channel(pk_to_addr(channel_id))
            .channel_token_account(pk_to_addr(&channel_token_account))
            .payer_token_account(pk_to_addr(&payer_token_account))
            .mint(pk_to_addr(&mint))
            .token_program(pk_to_addr(&token_program_pk));

        self.submit_payer_ixs(vec![builder.instruction()], &payer)
            .await
    }

    /// Submit the upstream `distribute` ix using `splits_cache`.
    /// Confirms before returning.
    ///
    /// The on-chain channel record does not store the `BpsSplit` list;
    /// it stores the precommitted `distribution_hash`. Without the
    /// original splits the client cannot reconstruct the args, so this
    /// helper requires the caller to hand them back. `None` returns
    /// `SplitsUnavailable`; pass `Some(splits)` (typically pulled from
    /// the resume record) to proceed.
    pub async fn distribute(
        &self,
        channel_id: &Pubkey,
        splits_cache: Option<&[BpsSplit]>,
    ) -> Result<Signature, ClientError> {
        match splits_cache {
            Some(splits) => self.distribute_with_splits(channel_id, splits).await,
            None => Err(ClientError::SplitsUnavailable),
        }
    }

    /// Same as `distribute` but with the splits already in hand.
    /// Intentionally restricted to `Closing` or `ClosedFinalized`:
    /// pre-close distributes ride in the normal close orchestration, so
    /// this escape route is reserved for the post-close window where
    /// the cooperative path has already been attempted. Confirms before
    /// returning. The SDK-internal `CloseAttempting` and `ClosedPending`
    /// statuses never come back from the on-chain status byte, so they
    /// are not surfaced to this gate.
    ///
    /// Permissionless on-chain: any caller may submit `distribute` for
    /// any channel, and the configured signer pays the network fee
    /// regardless of whether it owns the channel.
    pub async fn distribute_with_splits(
        &self,
        channel_id: &Pubkey,
        splits: &[BpsSplit],
    ) -> Result<Signature, ClientError> {
        let view = self
            .fetch_view_and_check_status(
                channel_id,
                &[ChannelStatus::Closing, ChannelStatus::ClosedFinalized],
                "distribute_with_splits",
            )
            .await?;

        let typed_splits =
            wire_to_typed(splits, |e| ClientError::ProtocolViolation(e.to_string()))?;

        let payer = self.signer.pubkey();
        let mint = view.mint();
        let token_program_pk = spl_token_id();
        let payee = view.payee();

        let channel_token_account = ata_address(channel_id, &mint, &token_program_pk);
        let payer_token_account = ata_address(&payer, &mint, &token_program_pk);
        let payee_token_account = ata_address(&payee, &mint, &token_program_pk);
        let treasury_token_account = ata_address(&TREASURY_OWNER, &mint, &token_program_pk);

        let recipients = splits_to_recipients(&typed_splits);

        let mut builder = DistributeBuilder::new();
        builder
            .channel(pk_to_addr(channel_id))
            .payer(pk_to_addr(&payer))
            .channel_token_account(pk_to_addr(&channel_token_account))
            .payer_token_account(pk_to_addr(&payer_token_account))
            .payee_token_account(pk_to_addr(&payee_token_account))
            .treasury_token_account(pk_to_addr(&treasury_token_account))
            .mint(pk_to_addr(&mint))
            .token_program(pk_to_addr(&token_program_pk))
            .distribute_args(DistributeArgs { recipients });

        for split in &typed_splits {
            let Split::Bps { recipient, .. } = split;
            let recipient_ata = ata_address(recipient, &mint, &token_program_pk);
            builder.add_remaining_account(AccountMeta::new(pk_to_addr(&recipient_ata), false));
        }

        self.submit_payer_ixs(vec![builder.instruction()], &payer)
            .await
    }

    // ── Shared helpers ──────────────────────────────────────────────

    async fn fetch_view_and_check_status(
        &self,
        channel_id: &Pubkey,
        required: &[ChannelStatus],
        operation: &'static str,
    ) -> Result<ChannelView, ClientError> {
        let ui = self
            .rpc
            .get_ui_account_with_config(channel_id, base64_account_info_config())
            .await
            .map_err(|e| ClientError::Rpc(format!("get_account({channel_id}): {e}")))?
            .value
            .ok_or_else(|| {
                ClientError::ProtocolViolation(format!("channel {channel_id} not found"))
            })?;

        let data = decode_ui_account(&ui).ok_or_else(|| {
            ClientError::ProtocolViolation(format!(
                "channel {channel_id} returned non-binary RPC encoding"
            ))
        })?;

        let view = ChannelView::from_account_data(&data)
            .map_err(|e| ClientError::ProtocolViolation(format!("decode channel view: {e}")))?;

        let mapped_status = map_upstream_status(view.status()).ok_or_else(|| {
            ClientError::ProtocolViolation(format!(
                "channel {channel_id} reports unknown status byte {}",
                view.status()
            ))
        })?;
        if !required.contains(&mapped_status) {
            return Err(ClientError::BadEscapeRouteForState {
                current_status: mapped_status,
                operation,
            });
        }
        Ok(view)
    }

    /// Build a tx with two signature slots (slot 0 fee-payer, payer
    /// slot signed by `self.signer`). Used by the open and top-up
    /// builders.
    ///
    /// Rejects `fee_payer == payer`: `Message::new_with_blockhash` dedups
    /// identical signers into a single slot, which collapses the 2-sig
    /// shape the server's `validate_canonical_multi_ix_tx_shape` gate
    /// requires. The server would reject as `MaliciousTx`; catch it here
    /// and skip the round trip.
    async fn build_two_sig_tx(
        &self,
        ixs: Vec<Instruction>,
        fee_payer: &Pubkey,
        recent_blockhash: &Hash,
        payer: &Pubkey,
        kind: &'static str,
    ) -> Result<Transaction, ClientError> {
        if fee_payer == payer {
            return Err(ClientError::ProtocolViolation(format!(
                "fee_payer ({fee_payer}) must differ from payer ({payer}); v1 requires server-fee-payer for {kind} tx"
            )));
        }
        let fee_payer_addr = pk_to_addr(fee_payer);
        let message = Message::new_with_blockhash(&ixs, Some(&fee_payer_addr), recent_blockhash);
        self.sign_payer_slot(message, payer, kind).await
    }

    /// Build a payer-fee-paid tx, sign with `self.signer`, and submit
    /// via the configured RPC. Used by every escape route. Polls
    /// `confirm_transaction_with_commitment` at `Confirmed` after
    /// broadcast, mirroring the server-side close path so callers see a
    /// signature only after the tx has landed.
    async fn submit_payer_ixs(
        &self,
        ixs: Vec<Instruction>,
        payer: &Pubkey,
    ) -> Result<Signature, ClientError> {
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| ClientError::Rpc(format!("get_latest_blockhash: {e}")))?;

        let payer_addr = pk_to_addr(payer);
        let message = Message::new_with_blockhash(&ixs, Some(&payer_addr), &blockhash);
        let tx = self.sign_payer_slot(message, payer, "escape-route").await?;

        let tx_sig = self
            .rpc
            .send_transaction_with_config(&tx, RpcSendTransactionConfig::default())
            .await
            .map_err(|e| ClientError::Rpc(format!("send_transaction: {e}")))?;

        wait_for_confirmed(&self.rpc, &tx_sig, ESCAPE_ROUTE_CONFIRM_TIMEOUT).await?;
        Ok(tx_sig)
    }

    /// Sign the payer's slot only; leave the other slots zeroed for a
    /// downstream co-signer to fill.
    async fn sign_payer_slot(
        &self,
        message: Message,
        payer: &Pubkey,
        kind: &'static str,
    ) -> Result<Transaction, ClientError> {
        let mut tx = Transaction::new_unsigned(message);
        tx.signatures = vec![
            Signature::default();
            tx.message.header.num_required_signatures as usize
        ];

        let payer_addr = pk_to_addr(payer);
        let payer_slot = tx
            .message
            .account_keys
            .iter()
            .position(|k| *k == payer_addr)
            .ok_or_else(|| {
                ClientError::ProtocolViolation(format!(
                    "payer key missing from {kind} tx account_keys"
                ))
            })?;

        let msg_data = tx.message_data();
        let sig = self
            .signer
            .sign_message(&msg_data)
            .await
            .map_err(|e| ClientError::Signer(format!("sign_message for {kind} tx: {e}")))?;
        tx.signatures[payer_slot] = Signature::from(<[u8; 64]>::from(sig));
        Ok(tx)
    }
}

/// How long an escape route polls `confirm_transaction_with_commitment`
/// after broadcasting before giving up. Mirrors the server-side close
/// path's default `broadcast_confirm_timeout` so the two halves of the
/// protocol wait on roughly the same envelope.
const ESCAPE_ROUTE_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Poll `confirm_transaction_with_commitment` for `Confirmed` until the
/// deadline. Mirrors the helper in `server/session/close.rs`. RPC errors
/// and timeouts both surface as `ClientError::OnChainFailed` carrying
/// the broadcast signature so the caller can correlate logs with chain
/// state and recover the signature for manual polling: the tx may
/// already have landed despite the confirm RPC failing.
async fn wait_for_confirmed(
    rpc: &Arc<dyn MppRpcClient>,
    signature: &Signature,
    timeout: std::time::Duration,
) -> Result<(), ClientError> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        match rpc
            .confirm_transaction_with_commitment(signature, CommitmentConfig::confirmed())
            .await
        {
            Ok(resp) if resp.value => return Ok(()),
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::OnChainFailed(
                    *signature,
                    format!("confirm: {e}"),
                ))
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Err(ClientError::OnChainFailed(
        *signature,
        format!("did not reach Confirmed within {}s", timeout.as_secs()),
    ))
}

// ── Module-private helpers ────────────────────────────────────────────

/// Account-info config for SDK-side reads. `Confirmed` matches the
/// commitment the server defaults to and the encoding mirrors what
/// `verify.rs` requests.
fn base64_account_info_config() -> RpcAccountInfoConfig {
    RpcAccountInfoConfig {
        encoding: Some(UiAccountEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        ..RpcAccountInfoConfig::default()
    }
}

/// Decode the `UiAccount.data` payload back to raw bytes. Returns
/// `None` on `JsonParsed`, the only encoding `UiAccountData::decode`
/// rejects; the SDK never asks for it, so a `None` here is a
/// programming error or a misbehaving RPC.
fn decode_ui_account(ui: &UiAccount) -> Option<Vec<u8>> {
    ui.data.decode()
}

/// Decode a base58 pubkey into 32 bytes.
fn decode_pubkey_b58(s: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(s).into_vec().ok()?;
    bytes.try_into().ok()
}

/// Map the on-chain status byte (Open=0, Finalized=1, Closing=2) to the
/// SDK's 5-state `ChannelStatus`. The SDK-internal `CloseAttempting`
/// and `ClosedPending` states never appear on chain, so they are not
/// produced here.
fn map_upstream_status(byte: u8) -> Option<ChannelStatus> {
    match byte {
        0 => Some(ChannelStatus::Open),
        1 => Some(ChannelStatus::ClosedFinalized),
        2 => Some(ChannelStatus::Closing),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use solana_account_decoder_client_types::UiAccountData;
    use solana_address::Address;
    use solana_client::client_error::Result as ClientResult;
    use solana_client::rpc_response::{Response, RpcResponseContext, RpcResult};
    use solana_keychain::MemorySigner;
    use solana_sdk::signature::Keypair;

    /// Test double for `MppRpcClient`: hands back a single configured
    /// account on `get_ui_account_with_config` and stubs the rest.
    struct MockRpc {
        // (owner_b58, base64_data, lamports)
        account: Option<(String, String, u64)>,
        blockhash: Hash,
    }

    impl MockRpc {
        fn empty() -> Self {
            Self {
                account: None,
                blockhash: Hash::new_from_array([7u8; 32]),
            }
        }

        fn with_mint_owner(owner: &Pubkey) -> Self {
            Self {
                account: Some((
                    bs58::encode(owner.to_bytes()).into_string(),
                    base64::engine::general_purpose::STANDARD.encode([0u8; 82]),
                    1_000,
                )),
                blockhash: Hash::new_from_array([7u8; 32]),
            }
        }
    }

    #[async_trait]
    impl MppRpcClient for MockRpc {
        async fn get_ui_account_with_config(
            &self,
            _pubkey: &Pubkey,
            _config: RpcAccountInfoConfig,
        ) -> RpcResult<Option<UiAccount>> {
            let value = self.account.as_ref().map(|(owner, blob, lamports)| UiAccount {
                lamports: *lamports,
                data: UiAccountData::Binary(blob.clone(), UiAccountEncoding::Base64),
                owner: owner.clone(),
                executable: false,
                rent_epoch: 0,
                space: Some(82),
            });
            Ok(Response {
                context: RpcResponseContext {
                    slot: 0,
                    api_version: None,
                },
                value,
            })
        }

        async fn send_transaction_with_config(
            &self,
            _transaction: &Transaction,
            _config: RpcSendTransactionConfig,
        ) -> ClientResult<Signature> {
            Ok(Signature::default())
        }

        async fn confirm_transaction_with_commitment(
            &self,
            _signature: &Signature,
            _commitment_config: CommitmentConfig,
        ) -> RpcResult<bool> {
            Ok(Response {
                context: RpcResponseContext {
                    slot: 0,
                    api_version: None,
                },
                value: true,
            })
        }

        async fn get_latest_blockhash(&self) -> ClientResult<Hash> {
            Ok(self.blockhash)
        }
    }

    fn fresh_signer() -> Arc<dyn SolanaSigner> {
        let kp = Keypair::new();
        let signer =
            MemorySigner::from_bytes(&kp.to_bytes()).expect("memory signer accepts bytes");
        Arc::new(signer)
    }

    fn dummy_program() -> Pubkey {
        Pubkey::new_from_array([0xA0u8; 32])
    }

    /// Build a `SessionClient` against the mock RPC with a fresh
    /// in-memory signer and `dummy_program()`. Returns the signer's
    /// payer key for assertions.
    fn client_with_rpc(rpc: MockRpc) -> (SessionClient, Pubkey) {
        let signer = fresh_signer();
        let payer = signer.pubkey();
        let rpc: Arc<dyn MppRpcClient> = Arc::new(rpc);
        (SessionClient::new(signer, rpc, dummy_program()), payer)
    }

    /// Mock RPC reporting the mint as classic SPL Token; the default
    /// shape for tests that only need `validate_classic_spl_mint` to
    /// pass.
    fn classic_mint_client() -> (SessionClient, Pubkey) {
        client_with_rpc(MockRpc::with_mint_owner(&Pubkey::new_from_array(
            spl_token::id().to_bytes(),
        )))
    }

    #[tokio::test]
    async fn to_wire_string_round_trips_through_bincode_decode() {
        let (client, _payer) = classic_mint_client();

        let fee_payer = Pubkey::new_from_array([0xFEu8; 32]);
        let payee = Pubkey::new_from_array([0xA2u8; 32]);
        let mint = Pubkey::new_from_array([0xA3u8; 32]);
        let blockhash = Hash::new_from_array([0x77u8; 32]);

        let build = client
            .build_open_tx(&fee_payer, &blockhash, &payee, &mint, 7, 1_000_000, &[], 60)
            .await
            .expect("open tx builds with classic mint owner");

        let wire = build.to_wire_string();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&wire)
            .expect("base64 decodes");
        let decoded: Transaction =
            bincode::deserialize(&bytes).expect("bincode decodes the same Transaction");

        assert_eq!(decoded.message.header, build.transaction.message.header);
        assert_eq!(
            decoded.message.account_keys,
            build.transaction.message.account_keys
        );
        assert_eq!(
            decoded.message.recent_blockhash,
            build.transaction.message.recent_blockhash
        );
        assert_eq!(
            decoded.message.instructions.len(),
            build.transaction.message.instructions.len()
        );
        assert_eq!(decoded.signatures, build.transaction.signatures);
    }

    #[tokio::test]
    async fn validate_classic_spl_mint_rejects_token_2022() {
        let token_2022 = Pubkey::new_from_array(spl_token_2022::id().to_bytes());
        let (client, _payer) = client_with_rpc(MockRpc::with_mint_owner(&token_2022));

        let mint = Pubkey::new_from_array([0xA3u8; 32]);
        let err = client
            .validate_classic_spl_mint(&mint)
            .await
            .expect_err("token-2022 owner must be rejected");
        match err {
            ClientError::ProtocolViolation(msg) => {
                assert!(
                    msg.contains("Token-2022"),
                    "expected diagnostic to mention Token-2022, got: {msg}"
                );
            }
            other => panic!("expected ProtocolViolation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_classic_spl_mint_rejects_missing_account() {
        let (client, _payer) = client_with_rpc(MockRpc::empty());

        let mint = Pubkey::new_from_array([0xA3u8; 32]);
        let err = client
            .validate_classic_spl_mint(&mint)
            .await
            .expect_err("missing mint must be rejected");
        assert!(matches!(err, ClientError::ProtocolViolation(_)), "{err:?}");
    }

    /// `Message::new_with_blockhash` dedups identical signers into a
    /// single slot, which collapses the 2-sig shape and pushes the payer
    /// signature into slot 0 (the server's fee-payer slot). The server
    /// would reject with `MaliciousTx`; surface a typed `ProtocolViolation`
    /// at the SDK boundary instead.
    #[tokio::test]
    async fn build_open_tx_rejects_fee_payer_equals_payer() {
        let (client, payer) = classic_mint_client();

        let payee = Pubkey::new_from_array([0xA2u8; 32]);
        let mint = Pubkey::new_from_array([0xA3u8; 32]);
        let blockhash = Hash::new_from_array([0x77u8; 32]);

        // fee_payer == payer must be rejected.
        let result = client
            .build_open_tx(&payer, &blockhash, &payee, &mint, 7, 1_000_000, &[], 60)
            .await;
        match result {
            Ok(_) => panic!("fee_payer == payer must be rejected, got Ok build"),
            Err(ClientError::ProtocolViolation(msg)) => {
                assert!(
                    msg.contains("fee_payer") && msg.contains("must differ from payer"),
                    "expected typed fee_payer/payer diagnostic, got: {msg}"
                );
            }
            Err(other) => panic!("expected ProtocolViolation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_topup_tx_includes_compute_budget_and_signs_payer_slot() {
        let (client, payer) = classic_mint_client();

        let fee_payer = Pubkey::new_from_array([0xFEu8; 32]);
        let mint = Pubkey::new_from_array([0xA3u8; 32]);
        let channel_id = Pubkey::new_from_array([0xC1u8; 32]);
        let blockhash = Hash::new_from_array([0x77u8; 32]);

        let tx = client
            .build_topup_tx(&fee_payer, &blockhash, &channel_id, &mint, 250_000)
            .await
            .expect("topup tx builds");

        // Canonical top-up shape is 3 ixs: [set_price, set_limit, top_up].
        assert_eq!(
            tx.message.instructions.len(),
            3,
            "expected canonical 3-ix top-up shape"
        );

        // Compute-budget ixs sit at slots 0 and 1.
        let cb_id = solana_address::Address::new_from_array(
            solana_sdk_ids::compute_budget::ID.to_bytes(),
        );
        let prog_at = |idx: usize| -> Address {
            tx.message.account_keys[tx.message.instructions[idx].program_id_index as usize]
        };
        assert_eq!(prog_at(0), cb_id);
        assert_eq!(prog_at(1), cb_id);

        // Slot 2 is the payment-channels ix.
        let pc_id = payment_channels_client::programs::PAYMENT_CHANNELS_ID;
        assert_eq!(prog_at(2), pc_id);

        // Fee-payer slot stays empty; the payer slot is signed.
        let fee_payer_addr = pk_to_addr(&fee_payer);
        let payer_addr = pk_to_addr(&payer);
        let fee_slot = tx
            .message
            .account_keys
            .iter()
            .position(|k| *k == fee_payer_addr)
            .expect("fee payer key in account_keys");
        let payer_slot = tx
            .message
            .account_keys
            .iter()
            .position(|k| *k == payer_addr)
            .expect("payer key in account_keys");

        assert_eq!(
            tx.signatures[fee_slot],
            Signature::default(),
            "fee-payer slot must stay empty for server co-sign"
        );
        assert_ne!(
            tx.signatures[payer_slot],
            Signature::default(),
            "payer slot must be filled by the configured signer"
        );
    }

    /// Pins that `build_open_tx` ships the exact same ix bytes as the
    /// canonical builder. The wire contract relies on byte equality
    /// between caller and validator; reordering or adding an ix here
    /// would trip the server's `validate_canonical_multi_ix_tx_shape`.
    /// The L1 oracle catches divergence end-to-end; this is a local
    /// regression catch.
    ///
    /// Uses a non-empty splits list to pin split-recipient ATA ordering
    /// and `account_keys` layout. Bps don't have to sum to 10_000; the
    /// canonical builder doesn't enforce that.
    #[tokio::test]
    async fn build_open_tx_ix_list_matches_canonical_builder() {
        let (client, payer) = classic_mint_client();
        let program = dummy_program();

        let fee_payer = Pubkey::new_from_array([0xFEu8; 32]);
        let payee = Pubkey::new_from_array([0xA2u8; 32]);
        let mint = Pubkey::new_from_array([0xA3u8; 32]);
        let blockhash = Hash::new_from_array([0x77u8; 32]);
        let salt = 7u64;
        let deposit = 1_000_000u64;
        let grace_period_seconds = 60u32;
        let split_recipient_a = Pubkey::new_from_array([0xB1u8; 32]);
        let split_recipient_b = Pubkey::new_from_array([0xB2u8; 32]);
        let splits = vec![
            BpsSplit {
                recipient: bs58::encode(split_recipient_a.to_bytes()).into_string(),
                share_bps: 5000,
            },
            BpsSplit {
                recipient: bs58::encode(split_recipient_b.to_bytes()).into_string(),
                share_bps: 3000,
            },
        ];

        let build = client
            .build_open_tx(
                &fee_payer,
                &blockhash,
                &payee,
                &mint,
                salt,
                deposit,
                &splits,
                grace_period_seconds,
            )
            .await
            .expect("open tx builds with classic mint owner");

        let (channel_id, _bump) =
            derive_channel_pda(&payer, &payee, &mint, &payer, salt, &program);
        let typed_splits = wire_to_typed(&splits, |e| {
            ClientError::ProtocolViolation(e.to_string())
        })
        .expect("typed_splits roundtrip");
        let canonical_ixs = build_canonical_open_ixs(&CanonicalOpenInputs {
            program_id: program,
            payer,
            payee,
            mint,
            authorized_signer: payer,
            salt,
            deposit,
            grace_period_seconds,
            splits: &typed_splits,
            channel_id,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        });

        let fee_payer_addr = pk_to_addr(&fee_payer);
        let expected_message =
            Message::new_with_blockhash(&canonical_ixs, Some(&fee_payer_addr), &blockhash);

        assert_eq!(
            build.transaction.message.header,
            expected_message.header,
            "open tx header must match the canonical builder's"
        );
        assert_eq!(
            build.transaction.message.account_keys, expected_message.account_keys,
            "open tx account_keys must match the canonical builder's"
        );
        assert_eq!(
            build.transaction.message.recent_blockhash, expected_message.recent_blockhash,
            "open tx blockhash must round-trip into the message"
        );
        assert_eq!(
            build.transaction.message.instructions.len(),
            expected_message.instructions.len(),
            "open tx ix count must match the canonical list"
        );
        for (i, (got, want)) in build
            .transaction
            .message
            .instructions
            .iter()
            .zip(expected_message.instructions.iter())
            .enumerate()
        {
            assert_eq!(
                got.program_id_index, want.program_id_index,
                "open tx ix slot {i} program_id_index drift",
            );
            assert_eq!(got.accounts, want.accounts, "open tx ix slot {i} accounts drift");
            assert_eq!(got.data, want.data, "open tx ix slot {i} data drift");
        }
    }

    /// Same byte-equality pin for the top-up path. Top-up is simpler
    /// (3-ix list, no PDA derivation, no splits) so the test mirrors
    /// `build_open_tx_ix_list_matches_canonical_builder` with the
    /// inputs that path actually consumes.
    #[tokio::test]
    async fn build_topup_tx_ix_list_matches_canonical_builder() {
        let (client, payer) = classic_mint_client();
        let program = dummy_program();

        let fee_payer = Pubkey::new_from_array([0xFEu8; 32]);
        let mint = Pubkey::new_from_array([0xA3u8; 32]);
        let channel_id = Pubkey::new_from_array([0xC1u8; 32]);
        let blockhash = Hash::new_from_array([0x77u8; 32]);
        let amount = 250_000u64;

        let tx = client
            .build_topup_tx(&fee_payer, &blockhash, &channel_id, &mint, amount)
            .await
            .expect("topup tx builds");

        let canonical_ixs = build_canonical_topup_ixs(&CanonicalTopupInputs {
            program_id: program,
            payer,
            channel_id,
            mint,
            amount,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        });

        let fee_payer_addr = pk_to_addr(&fee_payer);
        let expected_message =
            Message::new_with_blockhash(&canonical_ixs, Some(&fee_payer_addr), &blockhash);

        assert_eq!(
            tx.message.header, expected_message.header,
            "topup tx header must match the canonical builder's"
        );
        assert_eq!(
            tx.message.account_keys, expected_message.account_keys,
            "topup tx account_keys must match the canonical builder's"
        );
        assert_eq!(
            tx.message.recent_blockhash, expected_message.recent_blockhash,
            "topup tx blockhash must round-trip into the message"
        );
        assert_eq!(
            tx.message.instructions.len(),
            expected_message.instructions.len(),
            "topup tx ix count must match the canonical list"
        );
        for (i, (got, want)) in tx
            .message
            .instructions
            .iter()
            .zip(expected_message.instructions.iter())
            .enumerate()
        {
            assert_eq!(
                got.program_id_index, want.program_id_index,
                "topup tx ix slot {i} program_id_index drift",
            );
            assert_eq!(got.accounts, want.accounts, "topup tx ix slot {i} accounts drift");
            assert_eq!(got.data, want.data, "topup tx ix slot {i} data drift");
        }
    }
}
