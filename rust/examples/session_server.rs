//! Operator-facing session server.
//!
//! Loads its config from environment variables, builds a `SessionMethod`
//! over an in-memory channel store and a real Solana RPC client, then
//! mounts the four channel-management routes on the bind address and
//! blocks on Ctrl-C. An operator chains their own metered route(s) on
//! top of [`solana_mpp::server::session::router`] when they want to call
//! `verify_voucher` from the same axum app; see the module docs of
//! `solana_mpp::server::session::serve` for the operator-responsibility
//! checklist (rate limits, request timeouts, TLS termination).
//!
//! ## Required env vars
//!
//! - `MPP_RPC_URL` (e.g. `https://api.devnet.solana.com`)
//! - `MPP_MINT` (base58 SPL Token mint pubkey)
//! - `MPP_PAYEE` (base58 payee pubkey; this is also the channel signer
//!   for the close path, so the keypair at `MPP_PAYEE_KEY` has to derive
//!   to this pubkey)
//! - `MPP_FEE_PAYER_KEY` (path to a Solana CLI keypair JSON file, the
//!   `[u8; 64]` array format)
//! - `MPP_PAYEE_KEY` (path to a Solana CLI keypair JSON file)
//! - `MPP_SECRET_KEY` (HMAC key for challenge ids; rotate per deployment)
//! - `MPP_MAX_DEPOSIT` (u64, in base units of the configured mint; the
//!   server rejects `open` requests with `deposit > max_deposit`. Pick
//!   this deliberately, an unbounded upper cap is a footgun.)
//!
//! ## Optional env vars
//!
//! - `MPP_PROGRAM_ID` (default: the pinned payment-channels program id)
//! - `MPP_NETWORK` = `devnet` | `mainnet` | `mainnet-beta` | `localnet` (default: `devnet`)
//! - `MPP_BIND_ADDR` (defaults to localhost; set
//!   `MPP_BIND_ADDR=0.0.0.0:8080` to expose externally)
//! - `MPP_AMOUNT_PER_UNIT` (default: `1000`, i.e. 1 cent at 6 decimals)
//! - `MPP_DECIMALS` (default: `6`)
//! - `MPP_MIN_DEPOSIT` (u64, default: `0`)
//! - `MPP_MIN_VOUCHER_DELTA` (u64, default: `1000`; the minimum
//!   increment between successive vouchers on a channel)
//! - `MPP_GRACE_PERIOD_SECONDS` (u64, default: `86400`; the on-chain
//!   close grace window for cooperative settlement)
//! - `MPP_OPERATOR` (base58 pubkey; defaults to `MPP_PAYEE`. Set this
//!   when multiple payees share infrastructure and the operator
//!   identity needs to be distinct in the challenge body.)
//!
//! Run it from `rust/`:
//!
//! ```text
//! MPP_RPC_URL=https://api.devnet.solana.com \
//! MPP_MINT=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v \
//! MPP_PAYEE=<base58-payee> \
//! MPP_FEE_PAYER_KEY=./fee-payer.json \
//! MPP_PAYEE_KEY=./payee.json \
//! MPP_SECRET_KEY=<long-random-secret> \
//! MPP_MAX_DEPOSIT=1000000000000 \
//! cargo run --example session_server --features="server,client"
//! ```

use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use payment_channels_client::programs::PAYMENT_CHANNELS_ID;
use solana_commitment_config::CommitmentConfig;
use solana_keychain::{MemorySigner, SolanaSigner};
use solana_mpp::server::session::{
    serve, session, FeePayer, Network, PayeeSigner, Pricing, SessionConfig,
};
use solana_mpp::{InMemoryChannelStore, MppRpcClient};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient as RealRpcClient;
use solana_sdk::signature::Keypair;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = env_required("MPP_RPC_URL")?;
    let bind_str = env_or("MPP_BIND_ADDR", "127.0.0.1:8080")?;
    let bind: SocketAddr = bind_str
        .parse()
        .map_err(|e| format!("MPP_BIND_ADDR {bind_str:?} is not a SocketAddr: {e}"))?;

    let cfg = build_session_config_from_env()?;

    let rpc: Arc<dyn MppRpcClient> = Arc::new(RealRpcClient::new_with_commitment(
        rpc_url,
        CommitmentConfig::confirmed(),
    ));
    let store = Arc::new(InMemoryChannelStore::new());

    let method = Arc::new(
        session(cfg)
            .with_store(store)
            .with_rpc(rpc)
            .recover()
            .await?,
    );

    eprintln!("session_server listening on http://{bind}");
    serve(method, bind).await?;
    Ok(())
}

fn build_session_config_from_env() -> Result<SessionConfig, Box<dyn std::error::Error>> {
    let payee = env_pubkey("MPP_PAYEE")?;
    let mint = env_pubkey("MPP_MINT")?;
    let decimals = env_u8("MPP_DECIMALS", 6)?;
    let network = env_network(Network::Devnet)?;
    let program_id = match env::var("MPP_PROGRAM_ID") {
        Ok(s) => Pubkey::from_str(&s)
            .map_err(|e| format!("MPP_PROGRAM_ID is not a valid base58 pubkey: {e}"))?,
        Err(_) => Pubkey::new_from_array(PAYMENT_CHANNELS_ID.to_bytes()),
    };
    let amount_per_unit = env_u64("MPP_AMOUNT_PER_UNIT", 1_000)?;

    let fee_payer_signer = load_signer_arc("MPP_FEE_PAYER_KEY")?;
    let payee_signer = load_signer_arc("MPP_PAYEE_KEY")?;
    let secret_key = env_required("MPP_SECRET_KEY")?;

    // Operator identity is advisory; surfacing it from env keeps the
    // challenge body honest about who's serving when multiple operators
    // share infrastructure.
    let operator = match env::var("MPP_OPERATOR") {
        Ok(s) => Pubkey::from_str(&s)
            .map_err(|e| format!("MPP_OPERATOR is not a valid base58 pubkey: {e}"))?,
        Err(_) => payee,
    };

    // `SessionConfig::new_with_defaults` initialises `max_deposit` to 0,
    // which would gate every open request out with `DepositOutOfRange`.
    // Require the operator to choose an upper bound rather than baking in
    // a giant silent default.
    let max_deposit = env_u64_required("MPP_MAX_DEPOSIT")?;
    let min_deposit = env_u64("MPP_MIN_DEPOSIT", 0)?;
    let min_voucher_delta = env_u64("MPP_MIN_VOUCHER_DELTA", 1_000)?;
    let grace_period_seconds = env_u32("MPP_GRACE_PERIOD_SECONDS", 24 * 60 * 60)?;

    let mut config = SessionConfig::new_with_defaults(
        operator,
        payee,
        mint,
        decimals,
        network,
        program_id,
        Pricing {
            amount_per_unit,
            unit_type: "request".into(),
        },
    );
    config.max_deposit = max_deposit;
    config.min_deposit = min_deposit;
    config.min_voucher_delta = min_voucher_delta;
    config.grace_period_seconds = grace_period_seconds;
    config.fee_payer = Some(FeePayer {
        signer: fee_payer_signer,
    });
    config.payee_signer = Some(PayeeSigner {
        signer: payee_signer,
    });
    config.secret_key = Some(secret_key);
    config.realm = Some("session".into());
    Ok(config)
}

fn env_required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} must be set").into())
}

fn env_or(name: &str, default: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(env::var(name).unwrap_or_else(|_| default.into()))
}

fn env_pubkey(name: &str) -> Result<Pubkey, Box<dyn std::error::Error>> {
    let s = env_required(name)?;
    Pubkey::from_str(&s).map_err(|e| format!("{name} is not a valid base58 pubkey: {e}").into())
}

fn env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(s) => s
            .parse::<u64>()
            .map_err(|e| format!("{name} is not a u64: {e}").into()),
        Err(_) => Ok(default),
    }
}

fn env_u64_required(name: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = env_required(name)?;
    s.parse::<u64>()
        .map_err(|e| format!("{name} is not a u64: {e}").into())
}

fn env_u32(name: &str, default: u32) -> Result<u32, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(s) => s
            .parse::<u32>()
            .map_err(|e| format!("{name} is not a u32: {e}").into()),
        Err(_) => Ok(default),
    }
}

fn env_u8(name: &str, default: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(s) => s
            .parse::<u8>()
            .map_err(|e| format!("{name} is not a u8: {e}").into()),
        Err(_) => Ok(default),
    }
}

fn env_network(default: Network) -> Result<Network, Box<dyn std::error::Error>> {
    match env::var("MPP_NETWORK") {
        Ok(s) => match s.as_str() {
            "devnet" => Ok(Network::Devnet),
            "mainnet" | "mainnet-beta" => Ok(Network::MainnetBeta),
            "localnet" => Ok(Network::Localnet),
            other => Err(format!(
                "MPP_NETWORK must be devnet|mainnet|localnet, got {other}"
            )
            .into()),
        },
        Err(_) => Ok(default),
    }
}

fn load_keypair_from_path(path: &str) -> Result<Keypair, Box<dyn std::error::Error>> {
    // Solana CLI keypair format: a JSON array of 64 u8 values.
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let arr: Vec<u8> = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {path} as JSON byte array: {e}"))?;
    Keypair::try_from(arr.as_slice())
        .map_err(|e| format!("{path} is not a valid Solana keypair: {e}").into())
}

fn load_signer_arc(path_env: &str) -> Result<Arc<dyn SolanaSigner>, Box<dyn std::error::Error>> {
    let path = env_required(path_env)?;
    let kp = load_keypair_from_path(&path)?;
    let signer: Arc<dyn SolanaSigner> = Arc::new(
        MemorySigner::from_bytes(&kp.to_bytes())
            .map_err(|e| format!("MemorySigner construction failed for {path_env}: {e}"))?,
    );
    Ok(signer)
}
