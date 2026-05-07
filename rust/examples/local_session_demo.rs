//! Local session lifecycle demo over a real solana-test-validator.
//!
//! Run a validator with the program loaded:
//!
//! ```text
//! solana-test-validator --reset \
//!   --bpf-program <PROGRAM_ID> rust/tests/fixtures/payment_channels.so
//! ```
//!
//! Then in another shell, from `rust/`:
//!
//! ```text
//! cargo run --example local_session_demo --features="server,client"
//! ```
//!
//! The server-side `SessionMethod` and the client-side `SessionClient`
//! both live in this binary; the "transport" between them is direct
//! method calls. Channel-program traffic still rides real RPC, so the
//! lifecycle handlers run end-to-end against the loaded program.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keychain::{MemorySigner, SolanaSigner};
use solana_message::Message;
use solana_mpp::program::payment_channels::canonical_tx::pk_to_addr;
use solana_mpp::server::session::{
    session, FeePayer, Network, OpenChallengeOptions, PayeeSigner, Pricing, SessionConfig,
    SessionMethod,
};
use solana_mpp::{
    typed_to_wire, ActiveSession, BpsSplit, ChannelStore, ClosePayload, InMemoryChannelStore,
    MppRpcClient, OpenPayload, Receipt, SessionClient, Split, TopUpPayload,
};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient as RealRpcClient;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer as _;
use solana_signature::Signature;
use solana_transaction::Transaction;
use payment_channels_client::programs::PAYMENT_CHANNELS_ID;

const RPC_URL: &str = "http://127.0.0.1:8899";
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
const AIRDROP_LAMPORTS: u64 = 10 * LAMPORTS_PER_SOL;
const MINT_DECIMALS: u8 = 6;
const MINT_INITIAL_AMOUNT: u64 = 50_000_000;
const SPL_MINT_LEN: u64 = 82;

// Hand-rolled so the demo stays on solana-pubkey 3.x throughout,
// instead of bridging through the 2.x copies the upstream spl-*
// helpers compile against.
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
const SPL_TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// Fresh keypairs, mint, and ATA over a real validator. An HTTP demo
/// will reuse this shape; once it lands, lift this struct (and `boot`)
/// into `examples/common/local_demo_fixture.rs`.
#[allow(dead_code)] // payer_ata + raw_rpc are read by the HTTP demo
struct LocalDemoFixture {
    payer: Keypair,
    payee: Keypair,
    fee_payer: Keypair,
    mint: Pubkey,
    payer_ata: Pubkey,
    payee_ata: Pubkey,
    rpc: Arc<dyn MppRpcClient>,
    raw_rpc: Arc<RealRpcClient>,
    program_id: Pubkey,
}

impl LocalDemoFixture {
    async fn boot(rpc_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        println!("setting up local fixture (rpc={rpc_url})");
        let raw_rpc = Arc::new(RealRpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        ));
        let rpc: Arc<dyn MppRpcClient> = raw_rpc.clone();

        let payer = Keypair::new();
        let payee = Keypair::new();
        let fee_payer = Keypair::new();

        for (label, kp) in [
            ("payer", &payer),
            ("payee", &payee),
            ("fee_payer", &fee_payer),
        ] {
            airdrop(&raw_rpc, &keypair_pubkey(kp), AIRDROP_LAMPORTS).await?;
            println!("airdropped 10 SOL to {label} {}", kp.pubkey());
        }

        let mint_kp = Keypair::new();
        let mint = keypair_pubkey(&mint_kp);
        create_mint(&raw_rpc, &payer, &mint_kp, MINT_DECIMALS).await?;
        println!("created mint {mint} (decimals {MINT_DECIMALS})");

        let payer_pk = keypair_pubkey(&payer);
        let payee_pk = keypair_pubkey(&payee);
        let payer_ata =
            ata_address(&payer_pk, &mint, &SPL_TOKEN_PROGRAM_ID);
        let payee_ata =
            ata_address(&payee_pk, &mint, &SPL_TOKEN_PROGRAM_ID);
        create_ata(&raw_rpc, &payer, &payer_pk, &mint).await?;
        // Pre-create the payee's ATA so the close path's distribute ix
        // lands in one tx without preflight churn.
        create_ata(&raw_rpc, &payer, &payee_pk, &mint).await?;
        mint_to(
            &raw_rpc,
            &payer,
            &mint,
            &payer_ata,
            MINT_INITIAL_AMOUNT,
        )
        .await?;
        println!("minted {MINT_INITIAL_AMOUNT} base units to payer ATA {payer_ata}");

        let program_id = Pubkey::new_from_array(PAYMENT_CHANNELS_ID.to_bytes());

        Ok(Self {
            payer,
            payee,
            fee_payer,
            mint,
            payer_ata,
            payee_ata,
            rpc,
            raw_rpc,
            program_id,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let fixture = LocalDemoFixture::boot(RPC_URL).await?;

    let payee_pk = keypair_pubkey(&fixture.payee);
    let splits_typed = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];

    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let config = build_session_config(&fixture, splits_typed.clone());
    let method = session(config)
        .with_store(store.clone())
        .with_rpc(fixture.rpc.clone())
        .recover()
        .await?;

    let payer_signer: Arc<dyn SolanaSigner> = Arc::new(
        MemorySigner::from_bytes(&fixture.payer.to_bytes())
            .expect("memory signer accepts keypair bytes"),
    );
    let session_client =
        SessionClient::new(payer_signer.clone(), fixture.rpc.clone(), fixture.program_id);

    // open
    let initial_deposit = 10_000_000u64;
    let salt = rand::random::<u64>();
    let channel_id = open_phase(
        &method,
        &session_client,
        &fixture,
        &splits_typed,
        salt,
        initial_deposit,
    )
    .await?;

    let mut active = ActiveSession::new(channel_id, payer_signer.clone(), 0, initial_deposit);

    // three voucher increments
    let per_request = 100_000u64;
    voucher_loop(&method, &mut active, per_request, 3).await?;

    // top-up
    let topup_amount = 500_000u64;
    let new_deposit = topup_phase(
        &method,
        &session_client,
        &fixture,
        &channel_id,
        initial_deposit,
        topup_amount,
    )
    .await?;
    active.set_deposit(new_deposit);

    // one more voucher above the prior cap
    voucher_loop(&method, &mut active, 50_000u64, 1).await?;

    // close (apply-voucher path)
    let close_receipt = close_phase(&method, &mut active, &channel_id).await?;

    print_summary(&fixture, &active, &close_receipt, started).await?;
    Ok(())
}

fn build_session_config(fixture: &LocalDemoFixture, splits: Vec<Split>) -> SessionConfig {
    let payee_pk = keypair_pubkey(&fixture.payee);
    let mint_pk = fixture.mint;
    let fee_payer_signer: Arc<dyn SolanaSigner> = Arc::new(
        MemorySigner::from_bytes(&fixture.fee_payer.to_bytes()).expect("memory signer accepts bytes"),
    );
    let payee_signer: Arc<dyn SolanaSigner> = Arc::new(
        MemorySigner::from_bytes(&fixture.payee.to_bytes()).expect("memory signer accepts bytes"),
    );

    // Operator pubkey is advisory in the challenge body; throwaway is fine for a demo.
    let operator = Pubkey::new_from_array([0xa1u8; 32]);

    let mut config = SessionConfig::new_with_defaults(
        operator,
        payee_pk,
        mint_pk,
        MINT_DECIMALS,
        Network::Localnet,
        fixture.program_id,
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
    config.realm = Some("local-demo".into());
    config.secret_key = Some("local-demo-secret-rotate-in-prod".into());
    config.splits = splits;
    config.broadcast_confirm_timeout = Duration::from_secs(45);
    config
}

async fn open_phase(
    method: &SessionMethod,
    client: &SessionClient,
    fixture: &LocalDemoFixture,
    splits_typed: &[Split],
    salt: u64,
    deposit: u64,
) -> Result<Pubkey, Box<dyn std::error::Error>> {
    let payer_pk = keypair_pubkey(&fixture.payer);
    let payee_pk = keypair_pubkey(&fixture.payee);
    let fee_payer_pk = keypair_pubkey(&fixture.fee_payer);
    let splits_wire: Vec<BpsSplit> = typed_to_wire(splits_typed);

    let blockhash = fixture.rpc.get_latest_blockhash().await?;
    let build = client
        .build_open_tx(
            &fee_payer_pk,
            &blockhash,
            &payee_pk,
            &fixture.mint,
            salt,
            deposit,
            &splits_wire,
            method.config().grace_period_seconds,
        )
        .await?;

    let challenge = method
        .build_challenge_for_open(OpenChallengeOptions::default())
        .await?;

    let payload = OpenPayload {
        challenge_id: challenge.id,
        channel_id: bs58::encode(build.channel_id.to_bytes()).into_string(),
        payer: bs58::encode(payer_pk.to_bytes()).into_string(),
        payee: bs58::encode(payee_pk.to_bytes()).into_string(),
        mint: bs58::encode(fixture.mint.to_bytes()).into_string(),
        // SessionClient pins authorized_signer to payer in v1.
        authorized_signer: bs58::encode(payer_pk.to_bytes()).into_string(),
        salt: salt.to_string(),
        bump: build.canonical_bump,
        deposit_amount: deposit.to_string(),
        distribution_splits: splits_wire,
        transaction: encode_tx(&build.transaction),
    };

    method.process_open(&payload).await?;
    println!(
        "opened channel {} with deposit {}",
        build.channel_id, deposit
    );
    Ok(build.channel_id)
}

async fn voucher_loop(
    method: &SessionMethod,
    active: &mut ActiveSession,
    per_request: u64,
    iterations: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    for n in 1..=iterations {
        let signed = active.sign_increment(per_request, None).await?;
        let receipt = method.verify_voucher(&signed).await?;
        let cumulative = receipt
            .accepted_cumulative
            .as_deref()
            .unwrap_or("?");
        println!("voucher #{n} accepted at cumulative {cumulative}");
    }
    Ok(())
}

async fn topup_phase(
    method: &SessionMethod,
    client: &SessionClient,
    fixture: &LocalDemoFixture,
    channel_id: &Pubkey,
    prior_deposit: u64,
    additional: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let fee_payer_pk = keypair_pubkey(&fixture.fee_payer);
    let blockhash = fixture.rpc.get_latest_blockhash().await?;

    let topup_tx = client
        .build_topup_tx(
            &fee_payer_pk,
            &blockhash,
            channel_id,
            &fixture.mint,
            additional,
        )
        .await?;

    let challenge = method.build_challenge_for_topup(channel_id).await?;
    let payload = TopUpPayload {
        challenge_id: challenge.id,
        channel_id: channel_id.to_string(),
        additional_amount: additional.to_string(),
        transaction: encode_tx(&topup_tx),
    };
    method.process_topup(&payload).await?;
    let new_deposit = prior_deposit + additional;
    println!(
        "topped up channel {channel_id}: deposit {prior_deposit} to {new_deposit}"
    );
    Ok(new_deposit)
}

async fn close_phase(
    method: &SessionMethod,
    active: &mut ActiveSession,
    channel_id: &Pubkey,
) -> Result<Receipt, Box<dyn std::error::Error>> {
    // Sign one final voucher above the verify_voucher watermark; the
    // close handler reapplies the same delta gate, so reusing the prior
    // voucher would trip VoucherDeltaTooSmall.
    let final_target = active
        .signed_cumulative()
        .checked_add(50_000)
        .expect("final voucher fits in u64");
    let final_voucher = active.sign_voucher(final_target, None).await?;

    let challenge = method.build_challenge_for_close(channel_id).await?;
    let payload = ClosePayload {
        challenge_id: challenge.id,
        channel_id: channel_id.to_string(),
        voucher: Some(final_voucher),
    };
    let receipt = method.process_close(&payload).await?;
    let settled = receipt
        .accepted_cumulative
        .as_deref()
        .unwrap_or("0");
    println!(
        "closed channel {channel_id}; settled {settled}; tombstone confirmed"
    );
    Ok(receipt)
}

async fn print_summary(
    fixture: &LocalDemoFixture,
    active: &ActiveSession,
    close_receipt: &Receipt,
    started: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    let payee_balance = read_token_balance(&fixture.rpc, &fixture.payee_ata).await?;
    let elapsed = started.elapsed();
    let refunded = close_receipt.refunded.as_deref().unwrap_or("0");
    let tx = close_receipt.tx_hash.as_deref().unwrap_or("?");

    println!();
    println!("summary");
    println!("  channel              {}", active.channel_id());
    println!("  signed cumulative    {}", active.signed_cumulative());
    println!("  payee ata balance    {payee_balance}");
    println!("  refunded             {refunded}");
    println!("  close tx             {tx}");
    println!("  elapsed              {:.2}s", elapsed.as_secs_f64());
    Ok(())
}

// wire helpers

fn encode_tx(tx: &Transaction) -> String {
    let bytes = bincode::serialize(tx).expect("transaction serializes");
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn keypair_pubkey(kp: &Keypair) -> Pubkey {
    Pubkey::new_from_array(kp.pubkey().to_bytes())
}

// rpc plumbing

async fn airdrop(
    rpc: &RealRpcClient,
    pk: &Pubkey,
    lamports: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let sig = rpc.request_airdrop(pk, lamports).await?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if rpc.confirm_transaction(&sig).await? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {sig} to confirm").into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn create_mint(
    rpc: &RealRpcClient,
    payer: &Keypair,
    mint_kp: &Keypair,
    decimals: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let payer_pk = keypair_pubkey(payer);
    let mint_pk = keypair_pubkey(mint_kp);

    let rent = rpc
        .get_minimum_balance_for_rent_exemption(SPL_MINT_LEN as usize)
        .await?;
    let create_account_ix = solana_system_interface::instruction::create_account(
        &pk_to_addr(&payer_pk),
        &pk_to_addr(&mint_pk),
        rent,
        SPL_MINT_LEN,
        &pk_to_addr(&SPL_TOKEN_PROGRAM_ID),
    );
    // solana_system_interface already returns a 3.x Instruction; no bridging needed.

    let init_mint_ix = build_initialize_mint2_ix(&mint_pk, &payer_pk, decimals);

    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = sign_two_kp_tx(
        vec![create_account_ix, init_mint_ix],
        payer,
        &[mint_kp],
        &blockhash,
    );
    rpc.send_and_confirm_transaction(&tx).await?;
    Ok(())
}

async fn create_ata(
    rpc: &RealRpcClient,
    funder: &Keypair,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<(), Box<dyn std::error::Error>> {
    let funder_pk = keypair_pubkey(funder);
    let ix = build_create_ata_idempotent_ix(&funder_pk, owner, mint, &SPL_TOKEN_PROGRAM_ID);
    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = sign_two_kp_tx(vec![ix], funder, &[], &blockhash);
    rpc.send_and_confirm_transaction(&tx).await?;
    Ok(())
}

async fn mint_to(
    rpc: &RealRpcClient,
    mint_authority: &Keypair,
    mint: &Pubkey,
    destination_ata: &Pubkey,
    amount: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority_pk = keypair_pubkey(mint_authority);
    let ix = build_mint_to_ix(mint, destination_ata, &authority_pk, amount);
    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = sign_two_kp_tx(vec![ix], mint_authority, &[], &blockhash);
    rpc.send_and_confirm_transaction(&tx).await?;
    Ok(())
}

/// Sign a tx with the fee payer plus zero or more extra keypairs whose
/// pubkeys are required signers in the message. Used for the setup
/// helpers, not the SDK's own builds.
fn sign_two_kp_tx(
    ixs: Vec<Instruction>,
    fee_payer: &Keypair,
    extras: &[&Keypair],
    blockhash: &Hash,
) -> Transaction {
    let fee_payer_addr = pk_to_addr(&keypair_pubkey(fee_payer));
    let message = Message::new_with_blockhash(&ixs, Some(&fee_payer_addr), blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let required = tx.message.header.num_required_signatures as usize;
    tx.signatures = vec![Signature::default(); required];

    sign_slot(&mut tx, fee_payer);
    for kp in extras {
        sign_slot(&mut tx, kp);
    }
    tx
}

fn sign_slot(tx: &mut Transaction, kp: &Keypair) {
    let pk_addr = pk_to_addr(&keypair_pubkey(kp));
    let idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| *k == pk_addr)
        .expect("signer pubkey appears in account_keys");
    let sig_bytes = kp.sign_message(&tx.message_data()).as_ref().to_vec();
    let arr: [u8; 64] = sig_bytes.try_into().expect("ed25519 signature is 64 bytes");
    tx.signatures[idx] = Signature::from(arr);
}

async fn read_token_balance(
    rpc: &Arc<dyn MppRpcClient>,
    ata: &Pubkey,
) -> Result<u64, Box<dyn std::error::Error>> {
    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = rpc.get_ui_account_with_config(ata, info).await?;
    let Some(ui) = resp.value else {
        return Ok(0);
    };
    let bytes = ui.data.decode().ok_or("ata account data not base64")?;
    let amount_bytes: [u8; 8] = bytes
        .get(64..72)
        .ok_or("ata account shorter than spl token layout")?
        .try_into()
        .expect("8-byte slice");
    Ok(u64::from_le_bytes(amount_bytes))
}

// hand-rolled ix builders
//
// The upstream spl-token / spl-associated-token-account-client crates on
// crates.io still compile against solana-pubkey 2.x. Building these ixs
// by hand keeps the demo on solana-pubkey 3.x throughout instead of
// bridging through bytes for every ix.

fn build_initialize_mint2_ix(mint: &Pubkey, mint_authority: &Pubkey, decimals: u8) -> Instruction {
    // SPL Token InitializeMint2 layout: [tag=20, decimals, mint_authority(32),
    // freeze_authority_option(1 + 32 if Some)].
    let mut data = Vec::with_capacity(1 + 1 + 32 + 1);
    data.push(20);
    data.push(decimals);
    data.extend_from_slice(&mint_authority.to_bytes());
    data.push(0); // COption::None for freeze authority
    Instruction {
        program_id: pk_to_addr(&SPL_TOKEN_PROGRAM_ID),
        accounts: vec![AccountMeta::new(pk_to_addr(mint), false)],
        data,
    }
}

fn build_create_ata_idempotent_ix(
    funder: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let ata = ata_address(owner, mint, token_program);
    Instruction {
        program_id: pk_to_addr(&ASSOCIATED_TOKEN_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(pk_to_addr(funder), true),
            AccountMeta::new(pk_to_addr(&ata), false),
            AccountMeta::new_readonly(pk_to_addr(owner), false),
            AccountMeta::new_readonly(pk_to_addr(mint), false),
            AccountMeta::new_readonly(pk_to_addr(&SYSTEM_PROGRAM_ID), false),
            AccountMeta::new_readonly(pk_to_addr(token_program), false),
        ],
        data: vec![1], // CreateIdempotent
    }
}

fn build_mint_to_ix(
    mint: &Pubkey,
    destination_ata: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    // SPL Token MintTo: [tag=7, amount(8 LE)].
    let mut data = Vec::with_capacity(1 + 8);
    data.push(7);
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: pk_to_addr(&SPL_TOKEN_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(pk_to_addr(mint), false),
            AccountMeta::new(pk_to_addr(destination_ata), false),
            AccountMeta::new_readonly(pk_to_addr(authority), true),
        ],
        data,
    }
}

fn ata_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let seeds = &[
        owner.as_ref(),
        token_program.as_ref(),
        mint.as_ref(),
    ];
    Pubkey::find_program_address(seeds, &ASSOCIATED_TOKEN_PROGRAM_ID).0
}

