//! Full HTTP session demo: SDK server + client end-to-end over real HTTP.
//!
//! Drives the channel lifecycle over a localhost socket:
//!
//! - Boots a fresh fixture (keypairs, mint, ATA) against a running
//!   `solana-test-validator`.
//! - Spawns the SDK's session server (axum router with the four
//!   channel-management routes plus a `/paid` metered example route)
//!   on an ephemeral `127.0.0.1` port chosen by the OS. The bound URL
//!   is printed at startup.
//! - Builds an `MppSessionClient` against the server URL and calls
//!   `fetch(/paid)` several times. The first call lands a 402, the
//!   client auto-opens a channel, retries with `Authorization: Payment
//!   <voucher>`, and the same path serves the subsequent requests.
//! - Closes the channel cooperatively via `MppSessionClient::close`.
//!
//! Prerequisites: a running `solana-test-validator --reset --bpf-program
//! <PROGRAM_ID> rust/tests/fixtures/payment_channels.so` on
//! `http://127.0.0.1:8899`. The local demo's README walks the setup;
//! reuse the same validator instance.
//!
//! Run:
//!
//! ```text
//! cargo run --example http_session_demo --features="server,client"
//! ```

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use solana_keychain::{MemorySigner, SolanaSigner};
use solana_mpp::server::session::{
    router as session_router, session, FeePayer, Network, OpenChallengeOptions, PayeeSigner,
    Pricing, SessionConfig, SessionMethod,
};
use solana_mpp::{
    base64url_decode, base64url_encode, extract_payment_scheme, format_receipt,
    format_www_authenticate, ChannelStore, ClientConfig, ClientPolicy, CloseReceipt, HttpOptions,
    InMemoryChannelStore, MppErrorCode, MppSessionClient, SessionAction, SessionError, Split,
    PAYMENT_RECEIPT_HEADER,
};
use solana_pubkey::Pubkey;
use tokio::sync::oneshot;

use common::local_demo_fixture::{keypair_pubkey, read_token_balance, LocalDemoFixture};

const RPC_URL: &str = "http://127.0.0.1:8899";
const BIND_ADDR: &str = "127.0.0.1:0";
const REQUEST_COUNT: usize = 4;

// Matches the SDK's production parser cap on the Authorization payload.
// A well-formed voucher token is a few hundred bytes; anything beyond
// 16 KiB is either garbage or someone probing for an allocation amp.
const MAX_PAYMENT_TOKEN_LEN: usize = 16 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let started = Instant::now();
    let fixture = LocalDemoFixture::boot(RPC_URL).await?;

    let payee_pk = keypair_pubkey(&fixture.payee);
    let mint_pk = fixture.mint;

    // Build the session method against the loaded program.
    let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
    let config = build_session_config(&fixture);
    let method = Arc::new(
        session(config)
            .with_store(store)
            .with_rpc(fixture.rpc.clone())
            .recover()
            .await?,
    );

    // Bind first so the URL is reachable before the client is built.
    let bind: SocketAddr = BIND_ADDR.parse()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let local_addr = listener.local_addr()?;
    let server_base_url = format!("http://{local_addr}");
    println!("session server listening on {server_base_url}");

    // App: the four channel-management routes from the SDK, plus a
    // `/paid` metered route that pretends to be the operator's resource.
    // `router(method)` already wires its own state and bakes out as
    // `Router<()>`; merging in a separately-stated paid router keeps
    // the state types straight.
    let paid_router = Router::new()
        .route("/paid", get(paid_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(method.clone());
    let app = session_router(method.clone()).merge(paid_router);

    // Shutdown channel: the client signals here once the lifecycle
    // finishes, then the serve task drains in-flight requests and
    // returns. `oneshot::Receiver` resolves to `Result<_, RecvError>`,
    // so wrap it to give axum the `Future<Output = ()>` shape it wants.
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
    });

    // Client points at the in-process server. The client uses the same
    // mint and program the server is configured with; the policy floor
    // matches the server's configured `min_voucher_delta` so apply-server-caps
    // doesn't reject the resolved value.
    let payer_signer: Arc<dyn SolanaSigner> = Arc::new(
        MemorySigner::from_bytes(&fixture.payer.to_bytes())
            .expect("memory signer accepts payer keypair bytes"),
    );
    let client = MppSessionClient::new(ClientConfig {
        rpc: fixture.rpc.clone(),
        signer: payer_signer,
        program: fixture.program_id,
        policy: ClientPolicy {
            auto_open: true,
            auto_topup: false,
            max_deposit: 50_000_000,
            max_cumulative: u64::MAX,
            min_voucher_delta: 1,
            voucher_ttl_seconds: 120,
            open_timeout: Duration::from_secs(60),
            topup_timeout: Duration::from_secs(60),
        },
        http_options: HttpOptions {
            timeout: Duration::from_secs(60),
            ..HttpOptions::default()
        },
        server_base_url: server_base_url.clone(),
    })?;

    // Drive the metered route. First call lands a 402, auto-opens the
    // channel, and retries with a voucher. Subsequent calls reuse the
    // same channel and sign incremental vouchers.
    let paid_url = format!("{server_base_url}/paid");
    for n in 1..=REQUEST_COUNT {
        let resp = client.fetch(&paid_url).await?;
        let cumulative = resp
            .accepted_cumulative()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".into());
        let spent = resp
            .spent()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".into());
        println!(
            "request {n}: status {} body {} bytes cumulative {} spent {}",
            resp.status(),
            resp.bytes().len(),
            cumulative,
            spent
        );
    }

    // Find the channel id behind the cell so close can target it.
    let cell = client
        .active_session(&payee_pk, &mint_pk)
        .expect("active session present after fetch loop");
    let (channel_id, signed_cumulative) = {
        let guard = cell.lock().await;
        (guard.0.channel_id, guard.1.signed_cumulative())
    };

    // Cooperative close. POSTs `/channel/close-challenge` then
    // `/channel/close`; the server's close handler signs and broadcasts
    // `settle_and_finalize`.
    let close_receipt = client.close(&channel_id).await?;

    // Stop the server. The handle awaits the drain before returning.
    let _ = shutdown_tx.send(());
    match server_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("server task exited with error: {e}"),
        Err(e) => eprintln!("server task join error: {e}"),
    }

    print_summary(
        &fixture,
        &channel_id,
        REQUEST_COUNT,
        signed_cumulative,
        &close_receipt,
        started,
    )
    .await?;
    Ok(())
}

// Install a tracing subscriber so the SDK's structured spans and events
// surface on stderr. `RUST_LOG` controls the filter; default to info for
// the SDK and the per-request `mpp::session` target so the demo prints
// the lifecycle breadcrumbs out of the box.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("solana_mpp=info,mpp::session=info"));
    let _ = fmt().with_env_filter(filter).with_target(true).try_init();
}

fn build_session_config(fixture: &LocalDemoFixture) -> SessionConfig {
    let payee_pk = keypair_pubkey(&fixture.payee);
    let mint_pk = fixture.mint;
    let fee_payer_signer: Arc<dyn SolanaSigner> = Arc::new(
        MemorySigner::from_bytes(&fixture.fee_payer.to_bytes())
            .expect("memory signer accepts fee_payer keypair bytes"),
    );
    let payee_signer: Arc<dyn SolanaSigner> = Arc::new(
        MemorySigner::from_bytes(&fixture.payee.to_bytes())
            .expect("memory signer accepts payee keypair bytes"),
    );

    // Operator pubkey is advisory in the challenge body; throwaway is fine for a demo.
    let operator = Pubkey::new_from_array([0xa1u8; 32]);

    let mut config = SessionConfig::new_with_defaults(
        operator,
        payee_pk,
        mint_pk,
        common::local_demo_fixture::MINT_DECIMALS,
        Network::Localnet,
        fixture.program_id,
        Pricing {
            amount_per_unit: 1_000,
            unit_type: "request".into(),
        },
    );
    // Auto-open deposits `min_deposit` on the first 402, so it has to
    // cover several rounds of `amount_per_unit` (1000) without tripping
    // the client's MaxCumulativeExceeded policy gate. 10M base units is
    // plenty for the four-request demo loop.
    config.min_deposit = 10_000_000;
    config.max_deposit = 50_000_000;
    config.min_voucher_delta = 1;
    config.grace_period_seconds = 60;
    config.fee_payer = Some(FeePayer {
        signer: fee_payer_signer,
    });
    config.payee_signer = Some(PayeeSigner {
        signer: payee_signer,
    });
    config.realm = Some("http-demo".into());
    config.secret_key = Some("http-demo-secret-rotate-in-prod".into());
    config.splits = vec![Split::Bps {
        recipient: payee_pk,
        share_bps: 10_000,
    }];
    config.broadcast_confirm_timeout = Duration::from_secs(45);
    config
}

/// `/paid` handler. Authenticated requests verify the voucher and
/// return a small JSON body with a `Payment-Receipt` header; unauthenticated
/// requests emit a 402 with a fresh open challenge in `WWW-Authenticate`.
///
/// Errors out of `verify_voucher` go back as typed HTTP responses so the
/// client's typed-error parser can switch on `MppErrorCode`. The receipt
/// header carries the same code in a minimal error envelope, matching the
/// shape the SDK's built-in channel routes emit on the close-flow paths.
async fn paid_handler(State(method): State<Arc<SessionMethod>>, headers: HeaderMap) -> Response {
    if let Some(token) = parse_payment_token(&headers) {
        if token.len() > MAX_PAYMENT_TOKEN_LEN {
            return (StatusCode::BAD_REQUEST, "payment token too large\n").into_response();
        }
        return handle_paid_with_credential(method.as_ref(), token).await;
    }

    // Vary `external_id` per call so two 402s issued in the same slot
    // don't collide on the same challenge id. The SDK's challenge cache
    // rejects duplicate ids; with default options the encoded request
    // body is identical across rapid calls (same blockhash, same fields),
    // so the derived id repeats. An operator running this pattern in
    // production should pick a stable, unique-per-request value (request
    // id, trace id, etc.); a random u64 is plenty for the demo.
    let opts = OpenChallengeOptions {
        external_id: Some(format!("paid-{:016x}", rand::random::<u64>())),
        ..OpenChallengeOptions::default()
    };
    match method.build_challenge_for_open(opts).await {
        Ok(challenge) => {
            let www_auth = match format_www_authenticate(&challenge) {
                Ok(v) => v,
                Err(e) => return server_error(format!("format www-authenticate: {e}")),
            };
            let mut resp = (
                StatusCode::PAYMENT_REQUIRED,
                "payment required\n",
            )
                .into_response();
            match HeaderValue::from_str(&www_auth) {
                Ok(hv) => {
                    resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
                }
                Err(e) => return server_error(format!("www-authenticate header value: {e}")),
            }
            resp
        }
        Err(e) => server_error(format!("build open challenge: {e}")),
    }
}

/// Pull a `Payment <token>` credential out of the `Authorization` header.
///
/// Delegates the scheme split to `extract_payment_scheme`, which handles
/// the comma-separated multi-scheme case and avoids the per-request
/// lowercase allocation the original handler did. The returned slice
/// excludes the scheme prefix and surrounding whitespace; it's the raw
/// token the rest of the path treats as `base64url(JCS(SessionAction))`.
fn parse_payment_token(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get(header::AUTHORIZATION)?;
    let auth_str = auth.to_str().ok()?;
    let element = extract_payment_scheme(auth_str)?;
    // `extract_payment_scheme` returns the element with the scheme prefix
    // intact (e.g. "Payment abc123"). Strip the prefix and surrounding
    // whitespace; the empty case falls through as `None`.
    let (_, rest) = element.split_once(' ')?;
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Decode the `Authorization: Payment <base64url(JCS(SessionAction))>`
/// payload, accept only the voucher variant, and call into
/// `verify_voucher`. Successes return a 200 with a `Payment-Receipt`
/// header; failures map through `paid_error_response` so the client sees
/// a typed `MppErrorCode`.
async fn handle_paid_with_credential(method: &SessionMethod, token: &str) -> Response {
    let bytes = match base64url_decode(token) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("authorization base64url decode: {e}\n"),
            )
                .into_response();
        }
    };
    let action: SessionAction = match serde_json::from_slice(&bytes) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("authorization payload decode: {e}\n"),
            )
                .into_response();
        }
    };
    let signed = match action {
        SessionAction::Voucher(v) => v,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "paid route only accepts voucher actions\n",
            )
                .into_response();
        }
    };

    match method.verify_voucher(&signed).await {
        Ok(receipt) => paid_success_response(&receipt),
        Err(err) => paid_error_response(&err),
    }
}

/// 200 with the success receipt in the `Payment-Receipt` header plus a
/// tiny JSON body the operator's clients can sanity-check.
fn paid_success_response(receipt: &solana_mpp::Receipt) -> Response {
    let header_value = match format_receipt(receipt) {
        Ok(v) => v,
        Err(e) => return server_error(format!("format receipt header: {e}")),
    };
    let body = serde_json::json!({ "ok": true, "service": "paid-demo" });
    let mut resp = (StatusCode::OK, body.to_string()).into_response();
    if let Ok(hv) = HeaderValue::from_str(&header_value) {
        resp.headers_mut()
            .insert(HeaderName::from_static(PAYMENT_RECEIPT_HEADER), hv);
    }
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Mirror the SDK's built-in channel routes on the metered surface: pick
/// the status from `SessionError::http_status`, write the `errorCode` into
/// the JSON body, and attach the same code in a JCS+base64url
/// `Payment-Receipt` envelope so the client's typed-error parser surfaces
/// an `MppErrorCode` instead of falling back to status-only.
fn paid_error_response(err: &SessionError) -> Response {
    let status = err.http_status();
    let code = err.code();
    let body_bytes =
        serde_json::to_vec(&serde_json::json!({ "errorCode": code })).expect("errorCode json");

    let mut resp = (status, body_bytes).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(hv) = format_error_receipt_header(code) {
        if let Ok(value) = HeaderValue::from_str(&hv) {
            resp.headers_mut()
                .insert(HeaderName::from_static(PAYMENT_RECEIPT_HEADER), value);
        }
    }
    resp
}

/// Build the `Payment-Receipt` header value for an error response.
///
/// Mirrors `server::session::serve::format_error_receipt` (kept private
/// in the SDK): a minimal receipt envelope with `status: "error"` plus
/// the `errorCode` at the top level, JCS-canonicalized and base64url-
/// encoded. The client's typed-error parser only reads `errorCode`, so
/// the empty `reference` / `challengeId` slots don't gate the round-trip.
fn format_error_receipt_header(code: MppErrorCode) -> Option<String> {
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    let value = serde_json::json!({
        "status": "error",
        "method": "solana",
        "timestamp": timestamp,
        "reference": "",
        "challengeId": "",
        "errorCode": code,
    });
    let jcs = serde_json_canonicalizer::to_string(&value).ok()?;
    Some(base64url_encode(jcs.as_bytes()))
}

fn server_error(message: String) -> Response {
    tracing::error!(target: "mpp::session", "paid handler 500: {message}");
    (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
}

async fn print_summary(
    fixture: &LocalDemoFixture,
    channel_id: &Pubkey,
    request_count: usize,
    signed_cumulative: u64,
    close_receipt: &CloseReceipt,
    started: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    let payee_balance = read_token_balance(&fixture.rpc, &fixture.payee_ata).await?;
    let elapsed = started.elapsed();
    let refunded = close_receipt
        .refunded
        .map(|v| v.to_string())
        .unwrap_or_else(|| "0".into());
    let tx = close_receipt
        .tx_hash
        .as_deref()
        .unwrap_or("?");

    println!();
    println!("summary");
    println!("  channel              {channel_id}");
    println!("  total fetch requests {request_count}");
    println!("  signed cumulative    {signed_cumulative}");
    println!("  payee ata balance    {payee_balance}");
    println!("  refunded             {refunded}");
    println!("  close tx             {tx}");
    println!("  elapsed              {:.2}s", elapsed.as_secs_f64());
    Ok(())
}
