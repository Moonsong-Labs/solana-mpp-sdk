//! Axum bindings for [`SessionMethod`].
//!
//! [`serve`] boots an HTTP listener that mounts the four channel-management
//! routes the client `MppSessionClient` POSTs against:
//!
//! - `POST /channel/open` (body: [`OpenPayload`])
//! - `POST /channel/topup` (body: [`TopUpPayload`])
//! - `POST /channel/close-challenge` (body: `{"channelId":"<base58>"}`)
//! - `POST /channel/close` (body: [`ClosePayload`])
//!
//! Voucher verification rides the `Authorization: Payment <base64url-JCS>`
//! header on the operator's metered endpoints. The serve helper does not
//! mount a metered route because the SDK can't assume where the operator's
//! paid resource lives. Operators compose this `Router` (exposed via
//! [`router`]) with their own metered handler that calls
//! [`SessionMethod::verify_voucher`] under the hood.
//!
//! Errors raised by the lifecycle methods become HTTP responses via
//! [`SessionError::http_status`]. The response also carries a
//! `Payment-Receipt` header whose JSON body has `status: "error"` and an
//! `errorCode` field that mirrors [`SessionError::code`], so the client's
//! typed-error parser surfaces an [`MppErrorCode`] alongside the status
//! line instead of falling back to status-only.
//!
//! ## Operator responsibilities
//!
//! The helper ships a minimal surface; production deployments wrap the
//! [`router`] output with their own `tower` middleware before binding.
//! Rate limiting, request timeouts, body-size caps, and concurrency limits
//! are not applied here; reach for `tower_http::limit::RequestBodyLimitLayer`,
//! `tower::limit::ConcurrencyLimitLayer`, and `tower::timeout::TimeoutLayer`
//! as needed. TLS termination is on the operator too, typically via a
//! reverse proxy or an axum TLS adapter like `axum-server::tls_rustls`;
//! [`serve`] binds plain TCP. [`serve`] ties shutdown to Ctrl-C for
//! one-shot demos; use [`serve_with_shutdown`] when integrating with an
//! operator's existing signal handling.

use std::future::Future;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Json, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use serde::Deserialize;
use serde_json::json;
use solana_pubkey::Pubkey;
use thiserror::Error;
use tower_http::trace::TraceLayer;

use crate::error::SessionError;
use crate::protocol::core::{Receipt, PAYMENT_RECEIPT_HEADER};
use crate::protocol::intents::session::{ClosePayload, OpenPayload, TopUpPayload};
use crate::server::session::SessionMethod;

/// Errors raised by [`serve`] itself. Per-request failures flow through
/// the HTTP response, not this enum.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ServeError {
    /// `TcpListener::bind` rejected the address (port in use, permission denied, ...).
    #[error("bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    /// `axum::serve` exited with an error after a successful bind.
    #[error("axum serve loop exited: {0}")]
    Serve(#[source] std::io::Error),
}

/// Bind to `addr` and serve the close-flow routes until Ctrl-C.
///
/// Convenience wrapper for the common case where the SDK's four routes
/// are all that's needed in-process. Operators that want extra routes
/// (or their own signal handling) should call [`router`] directly and
/// drive `axum::serve` themselves, or reach for [`serve_with_shutdown`].
pub async fn serve(method: Arc<SessionMethod>, addr: SocketAddr) -> Result<(), ServeError> {
    serve_with_shutdown(method, addr, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Bind to `addr` and serve the close-flow routes until `shutdown`
/// resolves. The future feeds axum's graceful-shutdown plumbing, so
/// resolving it drains in-flight connections instead of aborting.
/// Operators with their own signal handling (SIGTERM + SIGINT, supervisor
/// channels, ...) pass the appropriate future in here.
pub async fn serve_with_shutdown<F>(
    method: Arc<SessionMethod>,
    addr: SocketAddr,
    shutdown: F,
) -> Result<(), ServeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let app = router(method);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| ServeError::Bind { addr, source })?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(ServeError::Serve)?;
    Ok(())
}

/// Build the close-flow router. Operators chain their metered endpoint(s)
/// on top with `.route(...)` before handing the result to `axum::serve`.
pub fn router(method: Arc<SessionMethod>) -> Router {
    Router::new()
        .route("/channel/open", post(open_handler))
        .route("/channel/topup", post(topup_handler))
        .route("/channel/close-challenge", post(close_challenge_handler))
        .route("/channel/close", post(close_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(method)
}

/// JSON body shape for `POST /channel/close-challenge`. Mirrors what the
/// client hand-rolls, declared here so axum gives us JSON validation and
/// a typed extractor. `deny_unknown_fields` blocks a stray voucher or
/// open payload from squeezing through this route on `channelId` alone.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CloseChallengeRequest {
    channel_id: String,
}

async fn open_handler(
    State(method): State<Arc<SessionMethod>>,
    Json(payload): Json<OpenPayload>,
) -> Response {
    match method.process_open(&payload).await {
        Ok(receipt) => receipt_response(&receipt),
        Err(err) => error_response(&err),
    }
}

async fn topup_handler(
    State(method): State<Arc<SessionMethod>>,
    Json(payload): Json<TopUpPayload>,
) -> Response {
    match method.process_topup(&payload).await {
        Ok(receipt) => receipt_response(&receipt),
        Err(err) => error_response(&err),
    }
}

async fn close_challenge_handler(
    State(method): State<Arc<SessionMethod>>,
    Json(payload): Json<CloseChallengeRequest>,
) -> Response {
    let channel_id = match Pubkey::from_str(&payload.channel_id) {
        Ok(pk) => pk,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid channelId: {e}")).into_response();
        }
    };
    // The challenge body matches what an operator's 402 handler emits on
    // the open and voucher flows.
    match method.build_challenge_for_close(&channel_id).await {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => error_response(&err),
    }
}

async fn close_handler(
    State(method): State<Arc<SessionMethod>>,
    Json(payload): Json<ClosePayload>,
) -> Response {
    match method.process_close(&payload).await {
        Ok(receipt) => receipt_response(&receipt),
        Err(err) => error_response(&err),
    }
}

/// 200 with the success receipt in the `Payment-Receipt` header. Body
/// is empty; the client reads everything from the header.
fn receipt_response(receipt: &Receipt) -> Response {
    let header_value = match crate::protocol::core::format_receipt(receipt) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to format Payment-Receipt header on success");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("receipt header serialization: {e}"),
            )
                .into_response();
        }
    };
    let mut resp = StatusCode::OK.into_response();
    if let Ok(hv) = HeaderValue::from_str(&header_value) {
        resp.headers_mut()
            .insert(HeaderName::from_static(PAYMENT_RECEIPT_HEADER), hv);
    }
    resp
}

/// Map a [`SessionError`] to an HTTP response. The body is the JSON
/// `{"errorCode": "..."}` shape the client falls back to when the
/// receipt header is missing; the `Payment-Receipt` header carries the
/// same code inside the receipt extras so a typed `MppErrorCode`
/// round-trips back to the client.
fn error_response(err: &SessionError) -> Response {
    let status = err.http_status();
    let code = err.code();
    let body = json!({ "errorCode": code });
    let body_bytes = serde_json::to_vec(&body).expect("errorCode JSON serializes");

    let mut resp = (status, body_bytes).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(header_value) = format_error_receipt(err, code) {
        if let Ok(hv) = HeaderValue::from_str(&header_value) {
            resp.headers_mut()
                .insert(HeaderName::from_static(PAYMENT_RECEIPT_HEADER), hv);
        }
    }
    resp
}

/// Build the `Payment-Receipt` header value for an error response.
///
/// The wire `Receipt` enum only carries `status: "success" | "error"`
/// and the typed surface has no `extras` field, so to land the
/// `errorCode` the client expects we hand-build the JSON: a minimal
/// receipt envelope plus `errorCode` at the top level, JCS-canonicalized
/// and base64url-encoded. Matches the shape the client's
/// `error_receipt_header_with_code` test helper emits.
///
/// `_err` is unused: `SessionError` variants don't surface a channel id
/// or challenge id back to the handler, so `reference` and `challengeId`
/// are emitted as empty strings. The client's typed-error parser only
/// reads `errorCode`, so the empty values don't gate the round-trip.
fn format_error_receipt(
    _err: &SessionError,
    code: crate::protocol::core::MppErrorCode,
) -> Option<String> {
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
    Some(crate::protocol::core::base64url_encode(jcs.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_succeeds_on_ephemeral_port() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("ephemeral bind");
        let local = listener.local_addr().expect("local addr");
        assert_eq!(local.ip(), addr.ip());
        assert_ne!(local.port(), 0, "ephemeral bind must allocate a port");
    }

    /// Compile-time pin on `serve_with_shutdown`'s public signature.
    /// Body never runs; the function is here so that any drift on
    /// `(Arc<SessionMethod>, SocketAddr, F)` surfaces as a compile
    /// error instead of breaking the HTTP demo silently.
    #[allow(dead_code)]
    fn serve_with_shutdown_signature_is_stable(
        method: Arc<SessionMethod>,
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = Result<(), ServeError>> + Send {
        serve_with_shutdown(method, addr, std::future::ready(()))
    }

    /// Round-trip the error-path receipt shape through the client's
    /// `SessionReceipt::parse_header` so the typed `MppErrorCode` lands
    /// in `extras["errorCode"]`. Locks the wire-form bridge between the
    /// server's error mapping and the client's typed-error detection.
    #[cfg(feature = "client")]
    #[test]
    fn format_error_receipt_round_trips_through_session_receipt() {
        use crate::client::session::SessionReceipt;
        use crate::protocol::core::MppErrorCode;

        let err = SessionError::ChallengeExpired { age: 2, max: 1 };
        let header = format_error_receipt(&err, err.code()).expect("header");
        let parsed = SessionReceipt::parse_header(&header).expect("parse");
        assert_eq!(parsed.status, "error");
        let code = parsed
            .extras
            .get("errorCode")
            .cloned()
            .expect("errorCode in extras");
        let typed: MppErrorCode = serde_json::from_value(code).expect("MppErrorCode");
        assert_eq!(typed, MppErrorCode::ChallengeExpired);
    }
}
