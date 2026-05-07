#![cfg(all(feature = "client", feature = "server"))]
//! Client builders feeding the server lifecycle in one process against
//! a litesvm cluster. Each test stands up a `SessionMethod` and an
//! `RpcClient`-backed `SessionClient` over the same SVM and walks the
//! lifecycle through the public client surface (no HTTP, no canonical
//! shortcut). Gated on `client` since `SessionClient` and
//! `ActiveSession` are themselves `client`-gated.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use common::lite_svm_client::LiteSvmClient;
use common::{program_id_address, program_id_mpp, program_so_path, to_mpp};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::SETTLE_AND_FINALIZE_DISCRIMINATOR;
use solana_address::Address;
use solana_client::client_error::Result as SdkClientResult;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcSendTransactionConfig};
use solana_client::rpc_response::RpcResult as SdkRpcResult;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash as SdkHash;
use solana_keychain::{MemorySigner, SolanaSigner};
use solana_mpp::program::payment_channels::canonical_tx::{
    build_canonical_open_ixs, CanonicalOpenInputs, DEFAULT_COMPUTE_UNIT_LIMIT,
    DEFAULT_COMPUTE_UNIT_PRICE,
};
use solana_mpp::program::payment_channels::rpc::RpcClient as MppRpcClient;
use solana_mpp::program::payment_channels::state::CLOSED_CHANNEL_DISCRIMINATOR;
use solana_mpp::server::session::{
    session, FeePayer, Network, OpenChallengeOptions, PayeeSigner, Pricing, SessionConfig,
};
use solana_mpp::{
    typed_to_wire, BpsSplit, ChannelStatus, ChannelStore, ClosePayload, InMemoryChannelStore,
    MppErrorCode, OpenPayload, SessionClient, Split, TopUpPayload,
};
use solana_pubkey::Pubkey as MppPubkey;
use solana_pubkey_v2::Pubkey as AtaPubkey;
use solana_sdk::{signature::Keypair, signer::Signer as _};
use solana_signature::Signature as SdkSignature;
use solana_transaction::Transaction as SdkTransaction;
use spl_associated_token_account_client::address::get_associated_token_address_with_program_id;
use std::sync::Mutex as StdMutex;

/// Shared litesvm fixture: one mint, one funded payer ATA, one
/// fee-payer keypair, one merchant keypair (acts as the channel's
/// `payee` and signs `settle_and_finalize` on the close path).
struct Fixture {
    svm: LiteSVM,
    payer: Keypair,
    fee_payer_kp: Keypair,
    payee_kp: Keypair,
    payee: Address,
    mint: Address,
}

fn boot_fixture() -> Fixture {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id_address(), program_so_path())
        .expect("load program");

    let payer = Keypair::new();
    let mint_authority = Keypair::new();
    let payee_kp = Keypair::new();
    let fee_payer_kp = Keypair::new();
    let payee = Address::new_from_array(payee_kp.pubkey().to_bytes());

    svm.airdrop(&payer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&fee_payer_kp.pubkey(), 5_000_000_000).unwrap();
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
    MintTo::new(&mut svm, &mint_authority, &mint, &payer_token_account, 50_000_000)
        .send()
        .expect("mint to payer ATA");

    Fixture {
        svm,
        payer,
        fee_payer_kp,
        payee_kp,
        payee,
        mint,
    }
}

/// Build a `SessionConfig` matching the fixture. `realm` and
/// `secret_key` are required for `recover()`; the per-test secret keeps
/// challenge ids unique across tests sharing the process HMAC namespace.
fn config_for_fixture(
    fx: &Fixture,
    secret_key: &'static str,
    splits: Vec<Split>,
) -> SessionConfig {
    let payee_pk = to_mpp(&fx.payee);
    let mint_pk = to_mpp(&fx.mint);
    let fee_payer_signer: Arc<dyn SolanaSigner> =
        Arc::new(MemorySigner::from_bytes(&fx.fee_payer_kp.to_bytes()).unwrap());
    let payee_signer: Arc<dyn SolanaSigner> =
        Arc::new(MemorySigner::from_bytes(&fx.payee_kp.to_bytes()).unwrap());

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
    config.max_deposit = 50_000_000;
    config.min_voucher_delta = 1;
    config.grace_period_seconds = 60;
    config.fee_payer = Some(FeePayer {
        signer: fee_payer_signer,
    });
    config.payee_signer = Some(PayeeSigner {
        signer: payee_signer,
    });
    config.realm = Some("test".into());
    config.secret_key = Some(secret_key.into());
    config.splits = splits;
    // process_close polls at Confirmed; litesvm commits synchronously,
    // so a short timeout is fine.
    config.broadcast_confirm_timeout = std::time::Duration::from_secs(2);
    config
}

/// Build a `SessionClient` over the same litesvm as the server, signing
/// as the fixture's payer. v1 pins `authorized_signer == payer`, so
/// vouchers signed here verify against the channel PDA the server records.
fn session_client_for_payer(
    payer: &Keypair,
    rpc: Arc<dyn MppRpcClient>,
) -> SessionClient {
    let signer: Arc<dyn SolanaSigner> =
        Arc::new(MemorySigner::from_bytes(&payer.to_bytes()).unwrap());
    SessionClient::new(signer, rpc, program_id_mpp())
}

/// Re-encode a tx into the base64 string used by
/// `OpenPayload.transaction` / `TopUpPayload.transaction`. The
/// compute-budget tamper case mutates an ix in place before re-encoding.
fn encode_tx(tx: &SdkTransaction) -> String {
    let bytes = bincode::serialize(tx).unwrap();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Assemble an `OpenPayload` around `tx`. Mirrors what
/// `MppSessionClient` does in production, kept inline so the test stays
/// at the `SessionClient` boundary.
fn build_open_payload(
    challenge_id: String,
    payer_pk: MppPubkey,
    payee_pk: MppPubkey,
    mint_pk: MppPubkey,
    channel_id: MppPubkey,
    canonical_bump: u8,
    salt: u64,
    deposit: u64,
    splits: &[BpsSplit],
    tx: &SdkTransaction,
) -> OpenPayload {
    OpenPayload {
        challenge_id,
        channel_id: bs58::encode(channel_id.to_bytes()).into_string(),
        payer: bs58::encode(payer_pk.to_bytes()).into_string(),
        payee: bs58::encode(payee_pk.to_bytes()).into_string(),
        mint: bs58::encode(mint_pk.to_bytes()).into_string(),
        // SessionClient pins authorized_signer to payer.
        authorized_signer: bs58::encode(payer_pk.to_bytes()).into_string(),
        salt: salt.to_string(),
        bump: canonical_bump,
        deposit_amount: deposit.to_string(),
        distribution_splits: splits.to_vec(),
        transaction: encode_tx(tx),
    }
}

/// Slot-by-slot diff against the canonical builder. Not a correctness
/// check (that lives in `canonical_tx::tests`); just a sharper failure
/// surface than the server-side `MaliciousTx` rejection if the client
/// and server builders ever drift.
fn assert_open_tx_matches_canonical(
    tx: &SdkTransaction,
    payer_pk: MppPubkey,
    payee_pk: MppPubkey,
    mint_pk: MppPubkey,
    channel_id: MppPubkey,
    salt: u64,
    deposit: u64,
    splits: &[Split],
    grace_period_seconds: u32,
) {
    let canonical_ixs = build_canonical_open_ixs(&CanonicalOpenInputs {
        program_id: program_id_mpp(),
        payer: payer_pk,
        payee: payee_pk,
        mint: mint_pk,
        // SessionClient pins authorized_signer to payer in v1.
        authorized_signer: payer_pk,
        salt,
        deposit,
        grace_period_seconds,
        splits,
        channel_id,
        compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
        compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
    });

    assert_eq!(
        tx.message.instructions.len(),
        canonical_ixs.len(),
        "client open tx ix count drifted from canonical builder",
    );
    let account_keys = &tx.message.account_keys;
    for (i, (got, want)) in tx
        .message
        .instructions
        .iter()
        .zip(canonical_ixs.iter())
        .enumerate()
    {
        let got_program_id = account_keys[got.program_id_index as usize];
        let want_program_id = Address::new_from_array(want.program_id.to_bytes());
        assert_eq!(
            got_program_id, want_program_id,
            "open tx slot {i} program id drift",
        );
        assert_eq!(got.data, want.data, "open tx slot {i} data drift");
        assert_eq!(
            got.accounts.len(),
            want.accounts.len(),
            "open tx slot {i} account count drift",
        );
        for (j, (got_idx, want_meta)) in got.accounts.iter().zip(want.accounts.iter()).enumerate() {
            let got_key = account_keys[*got_idx as usize];
            let want_key = Address::new_from_array(want_meta.pubkey.to_bytes());
            assert_eq!(
                got_key, want_key,
                "open tx slot {i} account meta {j} key drift",
            );
        }
    }
}

/// Read the raw on-chain bytes for a key via the same RPC the
/// SessionMethod is using.
async fn read_account_bytes(
    rpc: &Arc<dyn MppRpcClient>,
    pk: &MppPubkey,
) -> Option<Vec<u8>> {
    let info = RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = rpc.get_ui_account_with_config(pk, info).await.unwrap();
    resp.value.map(|ui| ui.data.decode().expect("base64 decodes"))
}

/// Solana ed25519 precompile program id (`Ed25519SigVerify111...`).
/// The lock-settled test asserts the close path never broadcasts a tx
/// targeting this program.
const ED25519_PRECOMPILE_PROGRAM_ID: [u8; 32] = solana_sdk_ids::ed25519_program::ID.to_bytes();

/// `RpcClient` decorator that captures every successful broadcast.
/// The close path runs three back-to-back txs (ATA preflight,
/// settle_and_finalize, distribute); the no-precompile check looks
/// for an ed25519 ix in any of them. Only used by the lock-settled
/// test.
struct CapturingRpc {
    inner: Arc<dyn MppRpcClient>,
    sent: Arc<StdMutex<Vec<SdkTransaction>>>,
}

impl CapturingRpc {
    fn new(inner: Arc<dyn MppRpcClient>) -> Self {
        Self {
            inner,
            sent: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn captured(&self) -> Vec<SdkTransaction> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl MppRpcClient for CapturingRpc {
    async fn get_ui_account_with_config(
        &self,
        pubkey: &MppPubkey,
        config: RpcAccountInfoConfig,
    ) -> SdkRpcResult<Option<solana_account_decoder_client_types::UiAccount>> {
        self.inner.get_ui_account_with_config(pubkey, config).await
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &SdkTransaction,
        config: RpcSendTransactionConfig,
    ) -> SdkClientResult<SdkSignature> {
        let sig = self.inner.send_transaction_with_config(transaction, config).await?;
        self.sent.lock().unwrap().push(transaction.clone());
        Ok(sig)
    }

    async fn confirm_transaction_with_commitment(
        &self,
        signature: &SdkSignature,
        commitment_config: CommitmentConfig,
    ) -> SdkRpcResult<bool> {
        self.inner
            .confirm_transaction_with_commitment(signature, commitment_config)
            .await
    }

    async fn get_latest_blockhash(&self) -> SdkClientResult<SdkHash> {
        self.inner.get_latest_blockhash().await
    }
}

/// Read the SPL Token balance at `ata`. The `amount` field is at
/// offset 64..72 in the classic Token layout; Token-2022 uses the same
/// shape for the base balance.
async fn read_token_balance(rpc: &Arc<dyn MppRpcClient>, ata: &MppPubkey) -> u64 {
    read_account_bytes(rpc, ata)
        .await
        .map_or(0, |bytes| common::spl_token_amount(&bytes))
}

/// Tick the litesvm blockhash by one slot. The challenge HMAC id is
/// deterministic over realm, method, intent, and the encoded body, and
/// the body carries `recent_blockhash`. Without a tick, back-to-back
/// challenge factory calls against the same channel collide on the id
/// and the second one trips `ChallengeAlreadyIssued`.
async fn advance_blockhash(client: &Arc<LiteSvmClient>) {
    let svm = client.svm();
    let mut svm = svm.lock().await;
    svm.expire_blockhash();
}

// ── Test cases ─────────────────────────────────────────────────────

#[tokio::test]
async fn build_open_tx_round_trips_through_process_open() {
    let fx = boot_fixture();
    let payer_pk = to_mpp(&fx.payer.pubkey());
    let payee_pk = to_mpp(&fx.payee);
    let mint_pk = to_mpp(&fx.mint);

    let splits_typed = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    let splits_wire: Vec<BpsSplit> = typed_to_wire(&splits_typed);

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let config = config_for_fixture(&fx, "test-secret-client-roundtrip-open", splits_typed.clone());
    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(fx.svm));

    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover with empty store");

    let client = session_client_for_payer(&fx.payer, rpc.clone());

    let salt: u64 = 7;
    let deposit: u64 = 1_000_000;
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let fee_payer_pk =
        MppPubkey::new_from_array(fx.fee_payer_kp.pubkey().to_bytes());

    let build = client
        .build_open_tx(
            &fee_payer_pk,
            &blockhash,
            &payee_pk,
            &mint_pk,
            salt,
            deposit,
            &splits_wire,
            method.config().grace_period_seconds,
        )
        .await
        .expect("client builds open tx");

    // Pre-flight diff so a builder drift fails here with the slot
    // index instead of as a generic MaliciousTx at the server gate.
    assert_open_tx_matches_canonical(
        &build.transaction,
        payer_pk,
        payee_pk,
        mint_pk,
        build.channel_id,
        salt,
        deposit,
        &splits_typed,
        method.config().grace_period_seconds,
    );

    let challenge = method
        .build_challenge_for_open(OpenChallengeOptions::default())
        .await
        .expect("issue open challenge");

    let payload = build_open_payload(
        challenge.id.clone(),
        payer_pk,
        payee_pk,
        mint_pk,
        build.channel_id,
        build.canonical_bump,
        salt,
        deposit,
        &splits_wire,
        &build.transaction,
    );

    let receipt = method
        .process_open(&payload)
        .await
        .expect("process_open lands the open tx");
    assert!(
        !receipt.reference.is_empty(),
        "receipt carries the broadcast signature"
    );

    let post = store
        .get(&build.channel_id)
        .await
        .unwrap()
        .expect("channel record persisted");
    assert_eq!(post.status, ChannelStatus::Open);
    assert_eq!(post.deposit, deposit);
    assert_eq!(post.accepted_cumulative, 0);
    assert_eq!(post.payer, payer_pk);
}

#[tokio::test]
async fn tampered_compute_budget_ix_rejects_with_malicious_tx() {
    // Sign the tx, then overwrite the SetComputeUnitLimit value at
    // ix slot 1. Server rebuilds the canonical message and the diff
    // fires.
    let fx = boot_fixture();
    let payer_pk = to_mpp(&fx.payer.pubkey());
    let payee_pk = to_mpp(&fx.payee);
    let mint_pk = to_mpp(&fx.mint);

    let splits_typed = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    let splits_wire: Vec<BpsSplit> = typed_to_wire(&splits_typed);

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let config =
        config_for_fixture(&fx, "test-secret-client-roundtrip-cb-tamper", splits_typed.clone());
    let rpc: Arc<dyn MppRpcClient> = Arc::new(LiteSvmClient::new(fx.svm));
    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover with empty store");

    let client = session_client_for_payer(&fx.payer, rpc.clone());

    let salt: u64 = 11;
    let deposit: u64 = 1_000_000;
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let fee_payer_pk =
        MppPubkey::new_from_array(fx.fee_payer_kp.pubkey().to_bytes());

    let mut build = client
        .build_open_tx(
            &fee_payer_pk,
            &blockhash,
            &payee_pk,
            &mint_pk,
            salt,
            deposit,
            &splits_wire,
            method.config().grace_period_seconds,
        )
        .await
        .expect("client builds open tx");

    // SetComputeUnitLimit ix data is `[discriminator(2), units(4 LE)]`.
    // Slot 1 of the canonical open list is the limit ix; rewriting
    // the units to 123_456 forces a divergence against the server's
    // recompile.
    let target_data: Vec<u8> = {
        let mut d = vec![2u8];
        d.extend_from_slice(&123_456u32.to_le_bytes());
        d
    };
    build.transaction.message.instructions[1].data = target_data;

    let challenge = method
        .build_challenge_for_open(OpenChallengeOptions::default())
        .await
        .expect("issue open challenge");

    let payload = build_open_payload(
        challenge.id,
        payer_pk,
        payee_pk,
        mint_pk,
        build.channel_id,
        build.canonical_bump,
        salt,
        deposit,
        &splits_wire,
        &build.transaction,
    );

    let err = method
        .process_open(&payload)
        .await
        .expect_err("tampered compute-budget limit must reject");
    assert_eq!(
        err.code(),
        MppErrorCode::MaliciousTx,
        "expected MaliciousTx for tampered compute-budget limit, got {err:?}"
    );

    let post = store.get(&build.channel_id).await.unwrap();
    assert!(post.is_none(), "rejected open must not write a record");
}

#[tokio::test]
async fn voucher_topup_close_full_lifecycle() {
    // Open, five voucher increments, top-up, one more voucher above
    // the prior cap, then apply-voucher close. Each voucher verifies
    // against `authorized_signer` (the payer key, which SessionClient
    // pins for v1). Close lands an apply-voucher settle and a
    // distribute that drains the floor share into the payee ATA.
    let fx = boot_fixture();
    let payer_pk = to_mpp(&fx.payer.pubkey());
    let payee_pk = to_mpp(&fx.payee);
    let mint_pk = to_mpp(&fx.mint);
    let payee_ata_pk = MppPubkey::new_from_array(
        get_associated_token_address_with_program_id(
            &AtaPubkey::new_from_array(fx.payee.to_bytes()),
            &AtaPubkey::new_from_array(fx.mint.to_bytes()),
            &AtaPubkey::new_from_array(litesvm_token::TOKEN_ID.to_bytes()),
        )
        .to_bytes(),
    );

    let splits_typed = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    let splits_wire: Vec<BpsSplit> = typed_to_wire(&splits_typed);

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let config = config_for_fixture(&fx, "test-secret-client-roundtrip-full", splits_typed.clone());
    let fee_payer_pk = MppPubkey::new_from_array(fx.fee_payer_kp.pubkey().to_bytes());
    let svm_rpc = Arc::new(LiteSvmClient::new(fx.svm));
    let rpc: Arc<dyn MppRpcClient> = svm_rpc.clone();
    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover with empty store");

    let client = session_client_for_payer(&fx.payer, rpc.clone());

    // ── Open ────────────────────────────────────────────────────
    let salt: u64 = 23;
    let deposit: u64 = 1_000_000;
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let build = client
        .build_open_tx(
            &fee_payer_pk,
            &blockhash,
            &payee_pk,
            &mint_pk,
            salt,
            deposit,
            &splits_wire,
            method.config().grace_period_seconds,
        )
        .await
        .expect("client builds open tx");
    let channel_id = build.channel_id;

    let challenge = method
        .build_challenge_for_open(OpenChallengeOptions::default())
        .await
        .expect("issue open challenge");
    let payload = build_open_payload(
        challenge.id,
        payer_pk,
        payee_pk,
        mint_pk,
        channel_id,
        build.canonical_bump,
        salt,
        deposit,
        &splits_wire,
        &build.transaction,
    );
    method.process_open(&payload).await.expect("open lands");

    // ── 5 voucher increments ───────────────────────────────────
    let signer: Arc<dyn SolanaSigner> =
        Arc::new(MemorySigner::from_bytes(&fx.payer.to_bytes()).unwrap());
    let mut active = solana_mpp::ActiveSession::new(channel_id, signer.clone(), 0, deposit);

    let mut last_signed: Option<solana_mpp::SignedVoucher> = None;
    let increment = 100_000u64;
    for step in 1..=5u64 {
        let signed = active
            .sign_increment(increment, None)
            .await
            .expect("voucher signs");
        let receipt = method
            .verify_voucher(&signed)
            .await
            .expect("voucher accepted");
        let expected = (step * increment).to_string();
        assert_eq!(
            receipt.accepted_cumulative.as_deref(),
            Some(expected.as_str()),
            "receipt cumulative drifted at step {step}",
        );
        let post = store.get(&channel_id).await.unwrap().unwrap();
        assert_eq!(
            post.accepted_cumulative,
            step * increment,
            "store watermark drifted at step {step}",
        );
        last_signed = Some(signed);
    }
    let pre_topup_record = store.get(&channel_id).await.unwrap().unwrap();
    assert_eq!(pre_topup_record.accepted_cumulative, 5 * increment);
    let _ = last_signed.expect("at least one voucher signed");

    // ── Top-up ─────────────────────────────────────────────────
    let topup_amount = 500_000u64;
    let topup_blockhash = rpc.get_latest_blockhash().await.unwrap();
    let topup_tx = client
        .build_topup_tx(
            &fee_payer_pk,
            &topup_blockhash,
            &channel_id,
            &mint_pk,
            topup_amount,
        )
        .await
        .expect("client builds topup tx");
    let topup_challenge = method
        .build_challenge_for_topup(&channel_id)
        .await
        .expect("issue topup challenge");
    let topup_payload = TopUpPayload {
        challenge_id: topup_challenge.id,
        channel_id: channel_id.to_string(),
        additional_amount: topup_amount.to_string(),
        transaction: encode_tx(&topup_tx),
    };
    method
        .process_topup(&topup_payload)
        .await
        .expect("topup lands");
    let new_deposit = deposit + topup_amount;
    let post_topup = store.get(&channel_id).await.unwrap().unwrap();
    assert_eq!(post_topup.deposit, new_deposit, "deposit advances by top-up");
    active.set_deposit(new_deposit);

    // ── One more voucher above the old cap ─────────────────────
    let post_topup_voucher_target = 5 * increment + 200_000;
    let post_topup_voucher = active
        .sign_voucher(post_topup_voucher_target, None)
        .await
        .expect("voucher signs above prior cap");
    method
        .verify_voucher(&post_topup_voucher)
        .await
        .expect("post-topup voucher accepted");
    let post_voucher = store.get(&channel_id).await.unwrap().unwrap();
    assert_eq!(post_voucher.accepted_cumulative, post_topup_voucher_target);

    // The voucher close commits has to sit strictly above
    // `accepted_cumulative + min_voucher_delta`; the close handler
    // reapplies the same delta gate verify_voucher uses, so reusing
    // the prior voucher would trip `VoucherDeltaTooSmall`.
    let final_target = post_topup_voucher_target + 100_000;
    let final_voucher = active
        .sign_voucher(final_target, None)
        .await
        .expect("close voucher signs above the verify_voucher watermark");

    // ── Apply-voucher close ────────────────────────────────────
    let pre_payee_balance = read_token_balance(&rpc, &payee_ata_pk).await;

    // Advance the blockhash so the close challenge id differs from
    // the prior topup challenge id (only `recent_blockhash` varies
    // between them, and litesvm doesn't tick on synchronous calls).
    advance_blockhash(&svm_rpc).await;

    let close_challenge = method
        .build_challenge_for_close(&channel_id)
        .await
        .expect("issue close challenge");
    let close_payload = ClosePayload {
        challenge_id: close_challenge.id,
        channel_id: channel_id.to_string(),
        voucher: Some(final_voucher.clone()),
    };
    let close_receipt = method
        .process_close(&close_payload)
        .await
        .expect("apply-voucher close succeeds");
    assert_eq!(close_receipt.reference, channel_id.to_string());

    // PDA tombstoned to the 1-byte ClosedChannel discriminator.
    let post_data = read_account_bytes(&rpc, &channel_id)
        .await
        .expect("channel PDA still present after close");
    assert_eq!(
        post_data,
        vec![CLOSED_CHANNEL_DISCRIMINATOR],
        "post-close PDA should be the 1-byte tombstone",
    );

    // Payee absorbs the full settled pool (single 10_000-bps split).
    // If the fixture is ever switched to multi-split or a partial-bps
    // payee share, recompute the expected delta from `splits_typed`
    // instead of trusting `final_target`.
    assert_eq!(splits_typed.len(), 1, "single-split fixture assumed");
    match &splits_typed[0] {
        Split::Bps { recipient, share_bps } => {
            assert_eq!(*share_bps, 10_000, "100% bps assumed");
            assert_eq!(*recipient, payee_pk, "recipient is payee in this fixture");
        }
        other => panic!("unexpected split variant in fixture: {other:?}"),
    }
    let post_payee_balance = read_token_balance(&rpc, &payee_ata_pk).await;
    assert_eq!(
        post_payee_balance - pre_payee_balance,
        final_target,
        "payee ATA receives the full settled pool",
    );

    // Store ends at ClosedPending or ClosedFinalized.
    let post_close = store.get(&channel_id).await.unwrap().unwrap();
    assert!(
        matches!(
            post_close.status,
            ChannelStatus::ClosedPending | ChannelStatus::ClosedFinalized
        ),
        "expected ClosedPending or ClosedFinalized after close, got {:?}",
        post_close.status,
    );
    assert_eq!(post_close.on_chain_settled, final_target);
    assert!(post_close.close_tx.is_some());
}

#[tokio::test]
async fn close_lock_settled_no_voucher_round_trip() {
    // Open plus a couple of vouchers (off-chain only; the chain's
    // settled stays 0). Closing with `voucher: None` picks the
    // lock-settled path: settle_and_finalize fires with `has_voucher=0`
    // and no ed25519 precompile ix is broadcast.
    let fx = boot_fixture();
    let payer_pk = to_mpp(&fx.payer.pubkey());
    let payee_pk = to_mpp(&fx.payee);
    let mint_pk = to_mpp(&fx.mint);

    let splits_typed = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    let splits_wire: Vec<BpsSplit> = typed_to_wire(&splits_typed);

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let config = config_for_fixture(&fx, "test-secret-client-roundtrip-locksettled", splits_typed.clone());
    let fee_payer_pk = MppPubkey::new_from_array(fx.fee_payer_kp.pubkey().to_bytes());

    // Capture every broadcast tx so the post-close assertion can scan
    // for an ed25519 precompile ix.
    let svm_rpc = Arc::new(LiteSvmClient::new(fx.svm));
    let capturing = Arc::new(CapturingRpc::new(svm_rpc.clone()));
    let rpc: Arc<dyn MppRpcClient> = capturing.clone();

    let method = session(config)
        .with_store(store.clone())
        .with_rpc(rpc.clone())
        .recover()
        .await
        .expect("recover with empty store");

    let client = session_client_for_payer(&fx.payer, rpc.clone());

    let salt: u64 = 41;
    let deposit: u64 = 800_000;
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let build = client
        .build_open_tx(
            &fee_payer_pk,
            &blockhash,
            &payee_pk,
            &mint_pk,
            salt,
            deposit,
            &splits_wire,
            method.config().grace_period_seconds,
        )
        .await
        .expect("client builds open tx");
    let channel_id = build.channel_id;

    let open_challenge = method
        .build_challenge_for_open(OpenChallengeOptions::default())
        .await
        .expect("issue open challenge");
    let payload = build_open_payload(
        open_challenge.id,
        payer_pk,
        payee_pk,
        mint_pk,
        channel_id,
        build.canonical_bump,
        salt,
        deposit,
        &splits_wire,
        &build.transaction,
    );
    method.process_open(&payload).await.expect("open lands");

    // Two off-chain vouchers; the chain's settled watermark stays at
    // zero, so closing with `voucher: None` is a real lock-settled
    // and not a misclassified apply-voucher.
    let signer: Arc<dyn SolanaSigner> =
        Arc::new(MemorySigner::from_bytes(&fx.payer.to_bytes()).unwrap());
    let mut active = solana_mpp::ActiveSession::new(channel_id, signer.clone(), 0, deposit);
    for step in 1..=2u64 {
        let v = active
            .sign_increment(50_000, None)
            .await
            .expect("voucher signs");
        method
            .verify_voucher(&v)
            .await
            .expect("voucher accepted");
        assert_eq!(
            store.get(&channel_id).await.unwrap().unwrap().accepted_cumulative,
            step * 50_000,
        );
    }

    // Snapshot the broadcast count so the post-close scan skips the
    // open tx (vouchers don't broadcast).
    let pre_close_count = capturing.captured().len();

    // Tick the blockhash so the close challenge gets a fresh HMAC id.
    advance_blockhash(&svm_rpc).await;

    let close_challenge = method
        .build_challenge_for_close(&channel_id)
        .await
        .expect("issue close challenge");
    let close_payload = ClosePayload {
        challenge_id: close_challenge.id,
        channel_id: channel_id.to_string(),
        voucher: None,
    };
    let receipt = method
        .process_close(&close_payload)
        .await
        .expect("lock-settled close succeeds");
    assert!(!receipt.reference.is_empty(), "receipt carries a tx signature");

    // Tombstone shape.
    let data = read_account_bytes(&rpc, &channel_id)
        .await
        .expect("channel PDA present after close");
    assert_eq!(
        data,
        vec![CLOSED_CHANNEL_DISCRIMINATOR],
        "post-close PDA must be the 1-byte tombstone",
    );

    // Lock-settled commits the chain's existing settled, which is 0
    // here. `last_voucher` still reflects voucher-handler accepts
    // (lock-settled close doesn't clear it), so don't assert on it.
    let post = store.get(&channel_id).await.unwrap().unwrap();
    assert_eq!(
        post.on_chain_settled, 0,
        "lock-settled commits the chain's existing settled (0 here)",
    );
    assert!(
        matches!(
            post.status,
            ChannelStatus::ClosedPending | ChannelStatus::ClosedFinalized
        ),
        "expected ClosedPending or ClosedFinalized, got {:?}",
        post.status,
    );

    // Scan every close-phase tx for an ed25519 precompile ix.
    // Apply-voucher close emits one; lock-settled close should not.
    let captured = capturing.captured();
    assert!(
        captured.len() > pre_close_count,
        "close should broadcast at least one tx; captured={} pre={}",
        captured.len(),
        pre_close_count,
    );
    let ed25519_program_addr = Address::new_from_array(ED25519_PRECOMPILE_PROGRAM_ID);
    let mpp_program_addr = program_id_address();
    for (offset, tx) in captured.iter().enumerate().skip(pre_close_count) {
        for (i, ix) in tx.message.instructions.iter().enumerate() {
            let prog = tx.message.account_keys[ix.program_id_index as usize];
            assert_ne!(
                prog, ed25519_program_addr,
                "close-phase tx #{offset} ix {i} unexpectedly targets the ed25519 precompile; \
                 lock-settled path must not emit a voucher precompile ix",
            );
        }
    }

    // Pin `has_voucher == 0` on the settle_and_finalize ix. Layout
    // (borsh, no Anchor): byte 0 is the 1-byte program discriminator
    // (`SETTLE_AND_FINALIZE_DISCRIMINATOR == 4`), bytes 1..49 are
    // `VoucherArgs` (channel_id: Address[32], cumulative_amount: u64,
    // expires_at: i64), byte 49 is `has_voucher: u8`. Total 50 bytes.
    let settle_ix_data = captured
        .iter()
        .skip(pre_close_count)
        .find_map(|tx| {
            tx.message.instructions.iter().find_map(|ix| {
                let prog = tx.message.account_keys[ix.program_id_index as usize];
                let discriminator = ix.data.first().copied();
                if prog == mpp_program_addr
                    && discriminator == Some(SETTLE_AND_FINALIZE_DISCRIMINATOR)
                {
                    Some(ix.data.clone())
                } else {
                    None
                }
            })
        })
        .expect("settle_and_finalize ix must appear in the close-phase txs");
    assert_eq!(
        settle_ix_data.len(),
        50,
        "settle_and_finalize ix data must be 50 bytes (1 discriminator + 48 voucher args + 1 has_voucher), got {}",
        settle_ix_data.len(),
    );
    assert_eq!(
        settle_ix_data[49], 0,
        "lock-settled close must invoke settle_and_finalize with has_voucher == 0, got {}",
        settle_ix_data[49],
    );
}
