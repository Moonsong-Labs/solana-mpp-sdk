//! High-level session HTTP entrypoint.
//!
//! `MppSessionClient::fetch(url)` wraps the auto-open / auto-topup flow:
//!
//! 1. `GET <url>` with no credential. A 2xx is free, returned as a
//!    `PaidResponse` with an empty receipt.
//! 2. On 402, parse `WWW-Authenticate: Payment`, pick the session
//!    challenge, run `ClientPolicy::apply_server_caps`.
//! 3. Look up `(payee, mint)` in the registry. Hit: sign and resend
//!    the GET with `Authorization: Payment <base64url(JCS(action))>`.
//!    Hit-but-over-cap: auto-topup if policy allows, else return
//!    `PolicyViolation(MaxCumulativeExceeded)`. Miss: auto-open via
//!    the registry's single-flight slot, then sign and resend.
//! 4. `BlockhashMismatch` from the server drops the cached challenge
//!    and restarts at step 1.
//! 5. Any non-2xx with a `Payment-Receipt` body surfaces the wire-form
//!    `MppErrorCode` as `ClientError::Http(status, Some(code))`.
//!
//! Wire shape matches upstream `docs/002-http-protocol.md`: open,
//! topup, and close go through `POST /channel/{open,topup,close}` with
//! a JSON credential envelope; metered GETs carry the credential in the
//! `Authorization` header.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use solana_hash::Hash;
use solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;

use crate::client::session::{
    select_session_challenge, ActiveSession, ClientPolicy, OpenedChannel, PaidResponse,
    ResolvedPolicy, SessionCell, SessionClient, SessionReceipt, SessionRegistry,
};
use crate::error::{ClientError, PolicyErrorCode};
use crate::program::payment_channels::rpc::RpcClient as MppRpcClient;
use crate::protocol::core::{
    base64url_encode, parse_www_authenticate_all, MppErrorCode, PaymentChallenge,
};
use crate::protocol::intents::session::{
    MethodDetails, OpenPayload, SessionAction, SessionRequest, TopUpPayload,
};

/// Default response-body cap. Sized for a session GET that returns a
/// JSON or modest binary payload; larger media should ride a presigned
/// upstream URL the resource hands back, not the metered GET itself.
const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Tunables for the inner `reqwest::Client`. Kept minimal in v1: a
/// per-request timeout and a body-size cap. Connect / pool / proxy
/// knobs land if a deployment asks for them.
#[derive(Clone, Debug)]
pub struct HttpOptions {
    /// Wall-clock budget for any individual HTTP round-trip. Defaults to
    /// 30s, comfortable for devnet open-tx confirmation latency.
    pub timeout: Duration,
    /// Hard cap on buffered response body bytes per round-trip.
    /// Defaults to 16 MiB. A malicious or misconfigured server that
    /// streams an unbounded body would otherwise let `bytes().await`
    /// drain RAM until OOM; the client surfaces `ProtocolViolation`
    /// instead.
    pub max_body_bytes: usize,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

/// Fields the operator wires into [`MppSessionClient::new`].
pub struct ClientConfig {
    pub rpc: Arc<dyn MppRpcClient>,
    pub signer: Arc<dyn SolanaSigner>,
    pub program: Pubkey,
    pub policy: ClientPolicy,
    pub http_options: HttpOptions,
    /// HTTP root of the merchant the SDK targets (e.g.
    /// `https://merchant.example`). The SDK appends
    /// `/channel/{open,topup,close}` to this base when posting credentials.
    pub server_base_url: String,
}

/// Outcome of a successful `close(channel_id)` round-trip.
///
/// Mirrors the wire receipt's close-specific extras: the `tx_hash` of the
/// merchant-submitted `settle_and_finalize` (and bundled `distribute` when
/// applicable), and the optional `refunded` amount paid back to the payer
/// when distribution ran.
#[derive(Debug, Clone)]
pub struct CloseReceipt {
    pub channel_id: Pubkey,
    pub tx_hash: Option<String>,
    pub refunded: Option<u64>,
    pub accepted_cumulative: Option<u64>,
    pub raw: SessionReceipt,
}

/// High-level HTTP session client.
///
/// One `MppSessionClient` per `(signer, rpc, program, policy)` tuple. The
/// inner `reqwest::Client` is cheap to clone; the registry holds per-cell
/// mutexes so concurrent fetches against different `(payee, mint)` pairs
/// don't serialise on each other.
pub struct MppSessionClient {
    http: reqwest::Client,
    rpc: Arc<dyn MppRpcClient>,
    signer: Arc<dyn SolanaSigner>,
    program: Pubkey,
    policy: ClientPolicy,
    registry: Arc<SessionRegistry>,
    server_base_url: String,
    max_body_bytes: usize,
}

impl MppSessionClient {
    /// Build a fresh client. The `reqwest::Client` is constructed with the
    /// supplied `HttpOptions::timeout`; everything else uses reqwest
    /// defaults.
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let max_body_bytes = config.http_options.max_body_bytes;
        let http = reqwest::Client::builder()
            .timeout(config.http_options.timeout)
            .build()
            .map_err(|e| ClientError::ProtocolViolation(format!("reqwest builder: {e}")))?;
        Ok(Self {
            http,
            rpc: config.rpc,
            signer: config.signer,
            program: config.program,
            policy: config.policy,
            registry: Arc::new(SessionRegistry::new()),
            server_base_url: config.server_base_url,
            max_body_bytes,
        })
    }

    /// Look up the registered session for `(payee, mint)`. Returns `None`
    /// when no channel has been opened against this pair (or when
    /// `forget` cleared it).
    pub fn active_session(&self, payee: &Pubkey, mint: &Pubkey) -> Option<SessionCell> {
        self.registry.lookup(payee, mint)
    }

    /// Run the auto-open flow, retrying once on the recoverable
    /// failures (BlockhashMismatch, stale challenge). Persistent server
    /// disagreement surfaces as `Http(_, Some(code))` to the caller.
    pub async fn fetch(&self, url: &str) -> Result<PaidResponse, ClientError> {
        // Two attempts: initial, plus one forced refresh. Beyond that
        // the server is rejecting clean credentials and the caller
        // needs to investigate.
        const MAX_FETCH_ATTEMPTS: usize = 2;

        let mut last_err: Option<ClientError> = None;
        for _ in 0..MAX_FETCH_ATTEMPTS {
            match self.fetch_once(url).await {
                Ok(resp) => return Ok(resp),
                Err(ClientError::Http(status, Some(code))) if should_refresh(code) => {
                    last_err = Some(ClientError::Http(status, Some(code)));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            ClientError::ProtocolViolation("fetch retry budget exhausted".into())
        }))
    }

    /// One pass through the auto-open flow. Returns either a buffered
    /// `PaidResponse` or a typed `ClientError`.
    async fn fetch_once(&self, url: &str) -> Result<PaidResponse, ClientError> {
        // Probe for a 402 (or pass-through 2xx).
        let probe = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ClientError::ProtocolViolation(format!("GET {url}: {e}")))?;

        if probe.status().is_success() {
            return buffer_response_no_receipt(probe, self.max_body_bytes).await;
        }
        if probe.status() != StatusCode::PAYMENT_REQUIRED {
            return Err(ClientError::Http(probe.status(), None));
        }

        // Parse the 402 challenges, pick the session one.
        let www_values = collect_www_authenticate(probe.headers())?;
        let challenges = parse_www_authenticate_all(www_values.iter().map(|s| s.as_str()))
            .into_iter()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        let challenge = select_session_challenge(&challenges)
            .ok_or_else(|| ClientError::Http(StatusCode::PAYMENT_REQUIRED, None))?
            .clone();
        // Drop the probe so the connection returns to the pool while
        // the on-chain prep runs.
        drop(probe);

        // Decode the request envelope and apply server caps to policy.
        let session_request = decode_session_request(&challenge)?;
        let resolved = self
            .policy
            .apply_server_caps(&session_request.method_details)?;

        let payee = parse_b58_pubkey(&session_request.recipient, "recipient")?;
        let mint = parse_b58_pubkey(&session_request.currency, "currency")?;
        let amount: u64 = session_request.amount.parse().map_err(|e| {
            ClientError::ProtocolViolation(format!("amount {} is not a u64: {e}", session_request.amount))
        })?;

        // Look up or auto-open the session cell.
        let cell = match self.registry.lookup(&payee, &mint) {
            Some(cell) => cell,
            None => self.auto_open(&payee, &mint, &challenge, &session_request).await?,
        };

        // Voucher path with optional auto-topup.
        self.charge_against_cell(url, cell, amount, &resolved, &challenge, &session_request).await
    }

    /// Sign an increment, send it in the `Authorization` header,
    /// buffer the response. Triggers auto-topup if the increment would
    /// blow the on-chain deposit cap and policy allows.
    async fn charge_against_cell(
        &self,
        url: &str,
        cell: SessionCell,
        amount: u64,
        resolved: &ResolvedPolicy,
        challenge: &PaymentChallenge,
        session_request: &SessionRequest,
    ) -> Result<PaidResponse, ClientError> {
        // Cap check, then sign under the cell lock and drop the guard
        // before the HTTP call so other channels don't serialise
        // behind this one. `prior_signed` captures the watermark right
        // before `sign_increment` advances it; on a refresh-eligible
        // server rejection we roll back to it so the retry doesn't
        // double-charge.
        let mut guard = cell.lock().await;
        let projected = guard
            .1
            .signed_cumulative()
            .checked_add(amount)
            .ok_or(ClientError::VoucherArithmeticOverflow)?;

        if projected > guard.1.current_deposit() {
            if !self.policy.auto_topup {
                return Err(ClientError::PolicyViolation(
                    PolicyErrorCode::MaxCumulativeExceeded,
                ));
            }
            drop(guard);
            self.run_auto_topup(&cell, amount, challenge, session_request).await?;

            guard = cell.lock().await;
            let projected = guard
                .1
                .signed_cumulative()
                .checked_add(amount)
                .ok_or(ClientError::VoucherArithmeticOverflow)?;
            if projected > guard.1.current_deposit() {
                return Err(ClientError::PolicyViolation(
                    PolicyErrorCode::MaxCumulativeExceeded,
                ));
            }
        }

        let expires_at = compute_expires_at(resolved.voucher_ttl_seconds);
        let prior_signed = guard.1.signed_cumulative();
        let signed_voucher = guard.1.sign_increment(amount, expires_at).await?;
        let channel_id = guard.0.channel_id;
        drop(guard);

        let header = build_credential_header(&SessionAction::Voucher(signed_voucher.clone()))?;

        let resp = self
            .http
            .get(url)
            .header(http::header::AUTHORIZATION, header)
            .send()
            .await
            .map_err(|e| ClientError::ProtocolViolation(format!("voucher GET {url}: {e}")))?;

        let status = resp.status();
        let headers = resp.headers().clone();
        let body = drain_with_cap(resp, self.max_body_bytes, "voucher GET").await?;

        if status.is_success() {
            let receipt = parse_receipt_from_headers(&headers)?
                .ok_or_else(|| ClientError::ProtocolViolation(
                    "200 voucher response missing Payment-Receipt header".into(),
                ))?;
            // Apply the receipt locally so the next request's
            // `signed_cumulative` lines up with the server's view.
            {
                let mut guard = cell.lock().await;
                guard.1.on_receipt_accepted(&receipt)?;
            }
            return Ok(PaidResponse::new(status, headers, body, channel_id, receipt));
        }

        // Non-2xx: surface the typed error code. The server rejected
        // the voucher, so roll back the watermark we just advanced or
        // the next sign double-charges.
        let err = http_error_from(status, &headers, &body)?;
        if let ClientError::Http(_, Some(code)) = err {
            if should_refresh(code) {
                let mut guard = cell.lock().await;
                guard.1.set_signed_cumulative(prior_signed);
            }
        }
        Err(err)
    }

    async fn run_auto_topup(
        &self,
        cell: &SessionCell,
        amount: u64,
        challenge: &PaymentChallenge,
        session_request: &SessionRequest,
    ) -> Result<(), ClientError> {
        // v1 reuses the voucher challenge for the topup credential's
        // `challenge_id`. Upstream's HTTP wire flow
        // (`docs/002-http-protocol.md`) expects a fresh
        // topup-flavoured challenge from `build_challenge_for_topup`,
        // but the extra 402 round-trip is not wired yet. Servers that
        // scope challenges per intent will reject with
        // `ChallengeUnbound`; the outer retry refreshes and reissues.
        tracing::warn!(
            "auto-topup is reusing the voucher challenge in v1; \
             servers that scope challenges to the topup intent will reject"
        );
        let (channel_id, mint, current_deposit) = {
            let guard = cell.lock().await;
            (guard.0.channel_id, guard.0.mint, guard.0.deposit)
        };

        let new_deposit = current_deposit
            .checked_add(amount)
            .ok_or(ClientError::VoucherArithmeticOverflow)?;
        if new_deposit > self.policy.max_deposit {
            return Err(ClientError::PolicyViolation(
                PolicyErrorCode::MaxDepositExceeded,
            ));
        }

        let (fee_payer, blockhash) = parse_tx_envelope(&session_request.method_details, "topup")?;

        let session_client = SessionClient::new(self.signer.clone(), self.rpc.clone(), self.program);
        let topup_tx = session_client
            .build_topup_tx(&fee_payer, &blockhash, &channel_id, &mint, amount)
            .await?;

        let payload = TopUpPayload {
            challenge_id: challenge.id.clone(),
            channel_id: bs58::encode(channel_id.to_bytes()).into_string(),
            additional_amount: amount.to_string(),
            transaction: encode_tx_b64(&topup_tx)?,
        };

        let body = build_credential_body(&SessionAction::TopUp(payload))?;
        let topup_url = derive_endpoint_url(&self.server_base_url, EndpointAction::TopUp);
        let resp = self
            .http
            .post(topup_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError::ProtocolViolation(format!("POST topup: {e}")))?;

        let status = resp.status();
        let headers = resp.headers().clone();
        let body_bytes = drain_with_cap(resp, self.max_body_bytes, "topup").await?;
        if !status.is_success() {
            return Err(http_error_from(status, &headers, &body_bytes)?);
        }

        // Bump the local deposit cap so the upcoming voucher fits.
        let mut guard = cell.lock().await;
        guard.0.deposit = new_deposit;
        guard.1.set_deposit(new_deposit);
        Ok(())
    }

    async fn auto_open(
        &self,
        payee: &Pubkey,
        mint: &Pubkey,
        challenge: &PaymentChallenge,
        session_request: &SessionRequest,
    ) -> Result<SessionCell, ClientError> {
        if !self.policy.auto_open {
            return Err(ClientError::PolicyViolation(
                PolicyErrorCode::AutoOpenDisabled,
            ));
        }

        // Cap the requested deposit at the client's policy max while
        // honouring the server's advertised minimum.
        let server_min: u64 = session_request.method_details.minimum_deposit.parse().map_err(|e| {
            ClientError::ProtocolViolation(format!(
                "methodDetails.minimumDeposit not u64: {}: {e}",
                session_request.method_details.minimum_deposit
            ))
        })?;
        if server_min > self.policy.max_deposit {
            return Err(ClientError::PolicyViolation(
                PolicyErrorCode::MaxDepositExceeded,
            ));
        }
        // v1 deposits the server's minimum verbatim. Adding a buffer
        // above the floor (so the channel survives more requests
        // before needing a topup) is a follow-up.
        let deposit_amount = server_min;

        let details = &session_request.method_details;
        let program = parse_b58_pubkey(&details.channel_program, "channelProgram")?;
        if program != self.program {
            return Err(ClientError::ProtocolViolation(format!(
                "challenge channelProgram {program} does not match configured program {}",
                self.program
            )));
        }
        let grace = details.grace_period_seconds.ok_or_else(|| {
            ClientError::ProtocolViolation(
                "open challenge missing methodDetails.gracePeriodSeconds".into(),
            )
        })?;
        let (fee_payer, blockhash) = parse_tx_envelope(details, "open")?;
        let splits = details.distribution_splits.clone();
        let payer_pubkey = self.signer.pubkey();

        let challenge_id = challenge.id.clone();
        let payee_owned = *payee;
        let mint_owned = *mint;
        let http = self.http.clone();
        let signer = self.signer.clone();
        let rpc = self.rpc.clone();
        let program = self.program;
        let server_base_url = self.server_base_url.clone();
        let max_body_bytes = self.max_body_bytes;

        self.registry
            .get_or_open(payee, mint, move || async move {
                // `SessionClient::build_open_tx` requires
                // `authorized_signer == payer` in v1. Reusing the
                // configured signer matches that and avoids minting an
                // ephemeral key we'd then have to persist for
                // receipt-time voucher signing.
                let session_signer = signer.clone();
                let authorized_signer = session_signer.pubkey();

                // Random salt keeps each open at a distinct PDA. A
                // deterministic salt (e.g. derived from the signer)
                // would collide on close+reopen against the same
                // signer because the on-chain PDA persists until
                // settle+finalize lands, and the next Open would hit
                // an existing account.
                let salt = rand::random::<u64>();

                let session_client = SessionClient::new(signer.clone(), rpc.clone(), program);
                let open_build = session_client
                    .build_open_tx(
                        &fee_payer,
                        &blockhash,
                        &payee_owned,
                        &mint_owned,
                        salt,
                        deposit_amount,
                        &splits,
                        grace,
                    )
                    .await?;

                let payload = OpenPayload {
                    challenge_id: challenge_id.clone(),
                    channel_id: bs58::encode(open_build.channel_id.to_bytes()).into_string(),
                    payer: bs58::encode(payer_pubkey.to_bytes()).into_string(),
                    payee: bs58::encode(payee_owned.to_bytes()).into_string(),
                    mint: bs58::encode(mint_owned.to_bytes()).into_string(),
                    authorized_signer: bs58::encode(authorized_signer.to_bytes()).into_string(),
                    salt: salt.to_string(),
                    bump: open_build.canonical_bump,
                    deposit_amount: deposit_amount.to_string(),
                    distribution_splits: splits.clone(),
                    transaction: open_build.to_wire_string(),
                };

                let body = build_credential_body(&SessionAction::Open(payload))?;
                let open_url = derive_endpoint_url(&server_base_url, EndpointAction::Open);
                let resp = http
                    .post(open_url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| ClientError::ProtocolViolation(format!("POST open: {e}")))?;
                let status = resp.status();
                let headers = resp.headers().clone();
                let body_bytes = drain_with_cap(resp, max_body_bytes, "open").await?;
                if !status.is_success() {
                    return Err(http_error_from(status, &headers, &body_bytes)?);
                }
                // Receipt header on open is informational; the channel
                // id is already known from what was built.
                let _ = parse_receipt_from_headers(&headers)?;

                let opened = OpenedChannel {
                    channel_id: open_build.channel_id,
                    payee: payee_owned,
                    mint: mint_owned,
                    deposit: deposit_amount,
                    splits: splits.clone(),
                    authorized_signer,
                    salt,
                    canonical_bump: open_build.canonical_bump,
                    program_id: program,
                    expires_at: None,
                };
                let active =
                    ActiveSession::new(open_build.channel_id, session_signer, 0, deposit_amount);
                Ok((opened, active))
            })
            .await
    }

    /// Cooperative close. Drops the cached `(payee, mint)` entry so
    /// the next `fetch` mints a fresh channel. Returns a synthetic
    /// `CloseReceipt` for now; the actual `POST /channel/close`
    /// round-trip lands with the surfpool integration.
    ///
    /// Returns `ActiveSessionMissing(channel_id)` when no cell is
    /// registered for this `channel_id`. The lookup is async because
    /// it briefly locks each cell to read its channel id; concurrent
    /// voucher signing on unrelated cells is unaffected.
    pub async fn close(&self, channel_id: &Pubkey) -> Result<CloseReceipt, ClientError> {
        let ((payee, mint), _cell) = self
            .registry
            .lookup_by_channel_id(channel_id)
            .await
            .ok_or(ClientError::ActiveSessionMissing(*channel_id))?;

        self.registry.forget(&payee, &mint);

        Ok(CloseReceipt {
            channel_id: *channel_id,
            tx_hash: None,
            refunded: None,
            accepted_cumulative: None,
            raw: SessionReceipt {
                method: "solana".into(),
                intent: "session".into(),
                reference: bs58::encode(channel_id.to_bytes()).into_string(),
                status: "pending".into(),
                accepted_cumulative: None,
                spent: None,
                tx_hash: None,
                extras: serde_json::Map::new(),
            },
        })
    }
}

// ── Helpers (module-private) ────────────────────────────────────────────

fn collect_www_authenticate(headers: &HeaderMap) -> Result<Vec<String>, ClientError> {
    headers
        .get_all(http::header::WWW_AUTHENTICATE)
        .iter()
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|e| ClientError::ProtocolViolation(format!("WWW-Authenticate utf-8: {e}")))
        })
        .collect()
}

fn decode_session_request(challenge: &PaymentChallenge) -> Result<SessionRequest, ClientError> {
    let bytes = crate::protocol::core::base64url_decode(challenge.request.raw())
        .map_err(|e| ClientError::ProtocolViolation(format!("challenge request base64url: {e}")))?;
    serde_json::from_slice::<SessionRequest>(&bytes)
        .map_err(|e| ClientError::ProtocolViolation(format!("challenge request JSON: {e}")))
}

fn parse_b58_pubkey(s: &str, field: &'static str) -> Result<Pubkey, ClientError> {
    Pubkey::from_str(s).map_err(|e| {
        ClientError::ProtocolViolation(format!("{field} is not base58 pubkey: {s}: {e}"))
    })
}

fn decode_blockhash(s: &str) -> Result<Hash, ClientError> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| ClientError::ProtocolViolation(format!("blockhash base58: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ClientError::ProtocolViolation("blockhash must be 32 bytes".into()))?;
    Ok(Hash::new_from_array(arr))
}

/// Pull `feePayerKey` and `recentBlockhash` out of a challenge's
/// method-details. Both fields are required for any tx-bearing
/// session credential (open, topup); a missing field surfaces a
/// `ProtocolViolation` tagged with the requesting `intent`.
fn parse_tx_envelope(
    details: &MethodDetails,
    intent: &'static str,
) -> Result<(Pubkey, Hash), ClientError> {
    let fee_payer_b58 = details.fee_payer_key.as_deref().ok_or_else(|| {
        ClientError::ProtocolViolation(format!(
            "{intent} challenge missing methodDetails.feePayerKey"
        ))
    })?;
    let fee_payer = parse_b58_pubkey(fee_payer_b58, "feePayerKey")?;
    let blockhash_b58 = details.recent_blockhash.as_deref().ok_or_else(|| {
        ClientError::ProtocolViolation(format!(
            "{intent} challenge missing methodDetails.recentBlockhash"
        ))
    })?;
    let blockhash = decode_blockhash(blockhash_b58)?;
    Ok((fee_payer, blockhash))
}

fn encode_tx_b64(tx: &solana_transaction::Transaction) -> Result<String, ClientError> {
    use base64::Engine;
    let bytes = bincode::serialize(tx)
        .map_err(|e| ClientError::ProtocolViolation(format!("bincode serialize tx: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn compute_expires_at(ttl_seconds: u32) -> Option<i64> {
    let ttl = i64::from(ttl_seconds);
    if ttl <= 0 {
        return None;
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    now.checked_add(ttl)
}

fn build_credential_header(action: &SessionAction) -> Result<HeaderValue, ClientError> {
    let json = serde_json_canonicalizer::to_string(action)
        .map_err(|e| ClientError::ProtocolViolation(format!("JCS serialize action: {e}")))?;
    let encoded = base64url_encode(json.as_bytes());
    let value = format!("Payment {encoded}");
    HeaderValue::from_str(&value)
        .map_err(|e| ClientError::ProtocolViolation(format!("Authorization header: {e}")))
}

/// Build the JSON body for `POST /channel/{open,topup,close}`. The
/// upstream routes expect the raw `OpenPayload` / `TopUpPayload` /
/// `ClosePayload`; `challenge_id` lives inside the payload, so no
/// outer wrapper.
fn build_credential_body(action: &SessionAction) -> Result<serde_json::Value, ClientError> {
    let payload_value = match action {
        SessionAction::Open(payload) => serde_json::to_value(payload),
        SessionAction::TopUp(payload) => serde_json::to_value(payload),
        SessionAction::Close(payload) => serde_json::to_value(payload),
        SessionAction::Voucher(_) => {
            return Err(ClientError::ProtocolViolation(
                "voucher actions ride the Authorization header, not a POST body".into(),
            ));
        }
    };
    payload_value.map_err(|e| ClientError::ProtocolViolation(format!("serialize payload: {e}")))
}

/// Channel-management endpoints the client POSTs against. Closed
/// enum so callers can't smuggle an arbitrary path segment into the
/// URL via a `&str` argument.
#[derive(Clone, Copy, Debug)]
enum EndpointAction {
    Open,
    TopUp,
}

impl EndpointAction {
    fn as_path(self) -> &'static str {
        match self {
            EndpointAction::Open => "open",
            EndpointAction::TopUp => "topup",
        }
    }
}

/// Build the URL for `POST /channel/{action}` against the configured
/// merchant base. Route shape comes from upstream's
/// `docs/002-http-protocol.md`. `action` is constrained to
/// `EndpointAction` so the path segment can't be arbitrary.
fn derive_endpoint_url(server_base_url: &str, action: EndpointAction) -> String {
    format!(
        "{}/channel/{}",
        server_base_url.trim_end_matches('/'),
        action.as_path()
    )
}

/// Buffer a response body with a hard size cap.
///
/// `reqwest::Response::bytes` reads the whole body into memory; a
/// server streaming an unbounded body would otherwise OOM the client.
/// Pre-check `Content-Length` when present and re-check the actual
/// byte count after buffering so a chunked body that lies about its
/// length still gets rejected.
async fn drain_with_cap(
    response: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<Bytes, ClientError> {
    if let Some(content_length) = response.content_length() {
        if content_length as usize > max_bytes {
            return Err(ClientError::ProtocolViolation(format!(
                "{label} body exceeds {max_bytes}-byte cap (Content-Length: {content_length})"
            )));
        }
    }
    let body = response
        .bytes()
        .await
        .map_err(|e| ClientError::ProtocolViolation(format!("{label} body read: {e}")))?;
    if body.len() > max_bytes {
        return Err(ClientError::ProtocolViolation(format!(
            "{label} body exceeds {max_bytes}-byte cap (read: {})",
            body.len()
        )));
    }
    Ok(body)
}

fn parse_receipt_from_headers(headers: &HeaderMap) -> Result<Option<SessionReceipt>, ClientError> {
    let Some(raw) = headers.get(HeaderName::from_static("payment-receipt")) else {
        return Ok(None);
    };
    let value = raw.to_str().map_err(|e| {
        ClientError::ProtocolViolation(format!("Payment-Receipt header utf-8: {e}"))
    })?;
    Ok(Some(SessionReceipt::parse_header(value)?))
}

/// Map a non-2xx response into a typed `ClientError`.
///
/// Returns the outer `Result` as `Err` only when the `Payment-Receipt`
/// header is present but malformed; that's a server bug worth
/// surfacing rather than swallowing. A clean (or absent) header flows
/// into `Ok(ClientError::Http(...))`, with a body fallback for servers
/// that put the error code in the JSON body instead of the receipt.
fn http_error_from(
    status: StatusCode,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<ClientError, ClientError> {
    let receipt = parse_receipt_from_headers(headers).map_err(|e| {
        ClientError::ProtocolViolation(format!(
            "error response Payment-Receipt parse failed: {e}"
        ))
    })?;
    if let Some(receipt) = receipt {
        if let Some(code) = receipt
            .extras
            .get("errorCode")
            .and_then(|v| serde_json::from_value::<MppErrorCode>(v.clone()).ok())
        {
            return Ok(ClientError::Http(status, Some(code)));
        }
    }
    // Body fallback: some servers ship the error code in the JSON body
    // rather than the receipt header. Best-effort decode.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(code) = value
            .get("errorCode")
            .and_then(|v| serde_json::from_value::<MppErrorCode>(v.clone()).ok())
        {
            return Ok(ClientError::Http(status, Some(code)));
        }
    }
    Ok(ClientError::Http(status, None))
}

/// Refresh-trigger predicate for the outer fetch loop.
fn should_refresh(code: MppErrorCode) -> bool {
    matches!(
        code,
        MppErrorCode::ChallengeUnbound
            | MppErrorCode::ChallengeAlreadyUsed
            | MppErrorCode::ChallengeExpired
            | MppErrorCode::BlockhashMismatch
    )
}

async fn buffer_response_no_receipt(
    resp: reqwest::Response,
    max_body_bytes: usize,
) -> Result<PaidResponse, ClientError> {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = drain_with_cap(resp, max_body_bytes, "free GET").await?;
    // No payment happened; synthesise an empty receipt with a
    // sentinel reference. Callers that need to know whether they
    // paid can branch on `accepted_cumulative()`.
    let receipt = SessionReceipt {
        method: "solana".into(),
        intent: "session".into(),
        reference: String::new(),
        status: "free".into(),
        accepted_cumulative: None,
        spent: None,
        tx_hash: None,
        extras: serde_json::Map::new(),
    };
    Ok(PaidResponse::new(
        status,
        headers,
        body,
        Pubkey::default(),
        receipt,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use solana_keychain::MemorySigner;
    use solana_sdk::signature::Keypair;
    use tokio::sync::Mutex;

    use crate::client::session::policy::ClientPolicy;
    use crate::protocol::core::types::Base64UrlJson;
    use crate::protocol::intents::session::MethodDetails;

    fn arc_mutex_for_test(opened: OpenedChannel, active: ActiveSession) -> SessionCell {
        Arc::new(Mutex::new((opened, active)))
    }

    fn sample_request(amount: &str, payee: &Pubkey, mint: &Pubkey) -> SessionRequest {
        SessionRequest {
            amount: amount.to_string(),
            unit_type: None,
            recipient: bs58::encode(payee.to_bytes()).into_string(),
            currency: bs58::encode(mint.to_bytes()).into_string(),
            description: None,
            external_id: None,
            method_details: MethodDetails {
                network: None,
                channel_program: bs58::encode([0xA0u8; 32]).into_string(),
                channel_id: None,
                decimals: None,
                token_program: None,
                fee_payer: None,
                fee_payer_key: Some(bs58::encode([0xFEu8; 32]).into_string()),
                recent_blockhash: Some(bs58::encode([0x77u8; 32]).into_string()),
                min_voucher_delta: None,
                ttl_seconds: Some(60),
                grace_period_seconds: Some(60),
                distribution_splits: vec![],
                minimum_deposit: "1000".into(),
            },
        }
    }

    fn challenge_with_request(req: &SessionRequest) -> PaymentChallenge {
        let value = serde_json::to_value(req).expect("session request to value");
        let raw = Base64UrlJson::from_value(&value).expect("base64url encode");
        PaymentChallenge::new("ch-1", "MPP Payment", "solana", "session", raw)
    }

    /// `select_session_challenge` is what the fetch loop hands to
    /// auto-open. With one charge and one session challenge in the
    /// list, the picked session one round-trips through the wire
    /// request shape.
    #[test]
    fn select_session_challenge_used_on_multi_challenge_response() {
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let session_req = sample_request("100", &payee, &mint);

        let charge = PaymentChallenge::new(
            "ch-charge",
            "MPP Payment",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "0.10"})).unwrap(),
        );
        let session = challenge_with_request(&session_req);
        let challenges = vec![charge, session.clone()];

        let picked = select_session_challenge(&challenges).expect("session present");
        assert_eq!(picked.intent.as_str(), "session");
        assert_eq!(picked.id, session.id);

        // The fetch path base64url-decodes `request` into a
        // SessionRequest; pin that round-trip so format drift fails
        // here rather than deep inside the fetch loop.
        let decoded = decode_session_request(picked).expect("request decodes");
        assert_eq!(decoded.amount, session_req.amount);
        assert_eq!(decoded.recipient, session_req.recipient);
        assert_eq!(decoded.currency, session_req.currency);
    }

    /// `apply_server_caps` runs after the fetch loop picks the
    /// session challenge. A server TTL inside the client's cap
    /// resolves to the server's value; a server TTL past the cap
    /// returns `ServerPolicyTooLax`. Both branches matter to the
    /// fetch flow.
    #[test]
    fn policy_max_deposit_capped_at_server_minimum() {
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        // Within-cap: server's TTL of 30s fits the policy's 60s cap.
        let mut req = sample_request("100", &payee, &mint);
        req.method_details.ttl_seconds = Some(30);
        let policy = ClientPolicy {
            voucher_ttl_seconds: 60,
            ..ClientPolicy::default()
        };
        let resolved = policy.apply_server_caps(&req.method_details).expect("within cap");
        assert_eq!(resolved.voucher_ttl_seconds, 30);

        // Above-cap: server demands 120s, client caps at 60s. Reject.
        let mut req = sample_request("100", &payee, &mint);
        req.method_details.ttl_seconds = Some(120);
        match policy.apply_server_caps(&req.method_details) {
            Err(ClientError::ServerPolicyTooLax {
                field, server, client_limit,
            }) => {
                assert_eq!(field, "voucher_ttl_seconds");
                assert_eq!(server, 120);
                assert_eq!(client_limit, 60);
            }
            other => panic!("expected ServerPolicyTooLax, got {other:?}"),
        }
    }

    /// With `auto_topup: false`, a cell whose projected cumulative
    /// exceeds the deposit cap must return
    /// `PolicyViolation(MaxCumulativeExceeded)` without firing any
    /// HTTP. Stubs out the cell so no live server is needed.
    #[tokio::test]
    async fn auto_topup_disabled_returns_policy_violation_when_cap_exceeded() {
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let channel_id = Pubkey::new_unique();
        let kp = Keypair::new();
        let signer: Arc<dyn SolanaSigner> =
            Arc::new(MemorySigner::from_bytes(&kp.to_bytes()).expect("signer"));

        // Deposit is 1_000; signed_cumulative starts at 999. Asking for
        // 100 more would project to 1_099, over the cap.
        let mut active = ActiveSession::new(channel_id, signer.clone(), 0, 1_000);
        active
            .sign_voucher(999, None)
            .await
            .expect("seed voucher signs");
        let opened = OpenedChannel {
            channel_id,
            payee,
            mint,
            deposit: 1_000,
            splits: vec![],
            authorized_signer: signer.pubkey(),
            salt: 0,
            canonical_bump: 254,
            program_id: Pubkey::new_from_array([0xA0u8; 32]),
            expires_at: None,
        };
        let cell = arc_mutex_for_test(opened, active);

        // Just enough setup to call `charge_against_cell` with
        // `auto_topup: false`. `url`, `challenge`, and
        // `session_request` are unused on the policy-violation path
        // because the cap check returns before any HTTP runs.
        let policy = ClientPolicy {
            auto_topup: false,
            max_cumulative: u64::MAX,
            ..ClientPolicy::default()
        };
        let resolved = ResolvedPolicy {
            voucher_ttl_seconds: 30,
            min_voucher_delta: 1,
        };
        let req = sample_request("100", &payee, &mint);
        let challenge = challenge_with_request(&req);

        let client = MppSessionClient {
            http: reqwest::Client::new(),
            rpc: stub_rpc(),
            signer,
            program: Pubkey::new_from_array([0xA0u8; 32]),
            policy,
            registry: Arc::new(SessionRegistry::new()),
            server_base_url: "http://localhost:0".into(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        };

        let result = client
            .charge_against_cell("http://unused.invalid", cell, 100, &resolved, &challenge, &req)
            .await;
        match result {
            Ok(_) => panic!("over-cap with auto_topup=false must reject, got Ok"),
            Err(ClientError::PolicyViolation(PolicyErrorCode::MaxCumulativeExceeded)) => {}
            Err(other) => panic!(
                "expected PolicyViolation(MaxCumulativeExceeded), got {other:?}"
            ),
        }
    }

    /// Single-flight regression at the high-level layer. Concurrent
    /// first-touches against the same `(payee, mint)` share one
    /// registry slot, so the opener closure runs exactly once. Calls
    /// `registry.get_or_open` directly with a counting opener; the
    /// round-trip oracle covers the full HTTP path elsewhere.
    #[tokio::test]
    async fn single_flight_dedup_against_concurrent_fetch_against_same_payee_mint() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let registry = Arc::new(SessionRegistry::new());
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let channel_id = Pubkey::new_unique();
        let counter = Arc::new(AtomicUsize::new(0));

        let kp = Keypair::new();
        let signer: Arc<dyn SolanaSigner> =
            Arc::new(MemorySigner::from_bytes(&kp.to_bytes()).expect("signer"));

        let mut handles = Vec::with_capacity(8);
        for _ in 0..8 {
            let registry = registry.clone();
            let counter = counter.clone();
            let signer = signer.clone();
            handles.push(tokio::spawn(async move {
                registry
                    .get_or_open(&payee, &mint, || async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        // Yield so the scheduler runs other tasks
                        // through the in-flight check before publish.
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        let opened = OpenedChannel {
                            channel_id,
                            payee,
                            mint,
                            deposit: 5_000,
                            splits: vec![],
                            authorized_signer: signer.pubkey(),
                            salt: 0,
                            canonical_bump: 254,
                            program_id: Pubkey::new_from_array([0xA0u8; 32]),
                            expires_at: None,
                        };
                        let active = ActiveSession::new(channel_id, signer.clone(), 0, 5_000);
                        Ok((opened, active))
                    })
                    .await
                    .expect("get_or_open resolves")
            }));
        }

        let mut cells = Vec::with_capacity(8);
        for h in handles {
            cells.push(h.await.expect("task joins"));
        }

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "opener must run exactly once across concurrent first-touches"
        );
        let first = cells[0].clone();
        for c in &cells[1..] {
            assert!(Arc::ptr_eq(&first, c), "all callers share the same cell");
        }
    }

    fn stub_rpc() -> Arc<dyn MppRpcClient> {
        use async_trait::async_trait;
        use solana_account_decoder_client_types::UiAccount;
        use solana_client::client_error::Result as ClientResult;
        use solana_client::rpc_config::{RpcAccountInfoConfig, RpcSendTransactionConfig};
        use solana_client::rpc_response::{Response, RpcResponseContext, RpcResult};
        use solana_commitment_config::CommitmentConfig;
        use solana_signature::Signature;
        use solana_transaction::Transaction;

        struct StubRpc;

        #[async_trait]
        impl MppRpcClient for StubRpc {
            async fn get_ui_account_with_config(
                &self,
                _pubkey: &Pubkey,
                _config: RpcAccountInfoConfig,
            ) -> RpcResult<Option<UiAccount>> {
                Ok(Response {
                    context: RpcResponseContext { slot: 0, api_version: None },
                    value: None,
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
                    context: RpcResponseContext { slot: 0, api_version: None },
                    value: true,
                })
            }

            async fn get_latest_blockhash(&self) -> ClientResult<Hash> {
                Ok(Hash::new_from_array([0u8; 32]))
            }
        }

        Arc::new(StubRpc)
    }
}
