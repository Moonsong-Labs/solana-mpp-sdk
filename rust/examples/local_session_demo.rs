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

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use solana_keychain::{MemorySigner, SolanaSigner};
use solana_mpp::server::session::{
    session, FeePayer, Network, OpenChallengeOptions, PayeeSigner, Pricing, SessionConfig,
    SessionMethod,
};
use solana_mpp::{
    typed_to_wire, ActiveSession, BpsSplit, ChannelStore, ClosePayload, InMemoryChannelStore,
    OpenPayload, Receipt, SessionClient, Split, TopUpPayload,
};
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use common::local_demo_fixture::{
    keypair_pubkey, read_token_balance, LocalDemoFixture, MINT_DECIMALS,
};

const RPC_URL: &str = "http://127.0.0.1:8899";

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
