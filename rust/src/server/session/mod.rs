//! Session intent server-side lifecycle.
//!
//! Public surface:
//!
//! - [`SessionConfig`]: operator-supplied configuration.
//! - [`SessionMethod`]: only constructible via
//!   `SessionBuilder::recover().await?`.
//! - [`SessionBuilder`]: `with_store` / `with_rpc` /
//!   `with_recovery_options` / `recover`.
//!
//! Submodules:
//!
//! - [`challenge`]: cache, intent binding, sweeper.
//! - [`open`] / [`voucher`] / [`topup`] / [`close`]: per-action handlers.
//! - [`ix`]: settle-bundle assembly.
//! - [`recover`]: two-phase startup recovery.

pub mod challenge;
pub mod close;
pub mod ix;
pub mod open;
pub mod recover;
pub mod topup;
pub mod voucher;

use std::sync::Arc;
use std::time::Duration;

use solana_client::client_error::ClientError;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::{Transaction, TransactionError};
use tokio::task::JoinHandle;

use crate::error::SessionError;
use crate::program::payment_channels::state::find_channel_pda;
use crate::program::payment_channels::verify::{verify_open, ExpectedOpenState, Mismatch, VerifyError};
use crate::protocol::core::{compute_challenge_id, Base64UrlJson, MethodName, PaymentChallenge, Receipt};
use crate::protocol::intents::session::{
    typed_to_wire, wire_to_typed, MethodDetails, OpenPayload, SessionRequest, Split,
};
use crate::store::{ChannelRecord, ChannelStatus, ChannelStore};

use challenge::{ChallengeCache, ChallengeIntent, ChallengeIntentDiscriminant, ChallengeRecord};
use open::{validate_open_tx_shape, DecodedOpenTx};

pub(crate) const METHOD_NAME: &str = "solana";
const SESSION_INTENT: &str = "session";

/// Default realm in the WWW-Authenticate header. Matches charge's
/// `"MPP Payment"` so a session-only operator doesn't need to set
/// the realm explicitly; charge keeps its own copy of the constant
/// because the two surfaces are otherwise unrelated.
const DEFAULT_REALM: &str = "MPP Payment";

/// Env var holding the HMAC secret. Same name as charge so running
/// both intents in one process only takes one variable.
const SECRET_KEY_ENV_VAR: &str = "MPP_SECRET_KEY";

const DEFAULT_CHALLENGE_TTL_SECONDS: u32 = 300;
pub(crate) const DEFAULT_CLOCK_SKEW_SECONDS: u32 = 5;
pub(crate) const DEFAULT_VOUCHER_CHECK_GRACE_SECONDS: u32 = 15;

/// Cluster this session lives on. The string form is the chain-id slug
/// in DIDs and `methodDetails.network`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    MainnetBeta,
    Devnet,
    Localnet,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::MainnetBeta => "mainnet-beta",
            Network::Devnet => "devnet",
            Network::Localnet => "localnet",
        }
    }
}

/// Per-unit pricing advertised in the 402 challenge body.
#[derive(Debug, Clone)]
pub struct Pricing {
    pub amount_per_unit: u64,
    pub unit_type: String,
}

/// Server-side fee-payer signer. The SDK never persists key material;
/// wrap your custody (env, KMS, HSM, wallet file) in a
/// [`solana_keychain::SolanaSigner`] and pass it through.
#[derive(Clone)]
pub struct FeePayer {
    pub signer: Arc<dyn solana_keychain::SolanaSigner>,
}

impl std::fmt::Debug for FeePayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeePayer")
            .field("pubkey", &self.signer.pubkey())
            .finish()
    }
}

/// Operator-supplied config. Hand it to [`SessionBuilder`] before
/// `recover()`. Store and RPC client come in through the builder, not
/// here.
#[derive(Clone)]
pub struct SessionConfig {
    pub operator: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub decimals: u8,
    pub network: Network,
    pub program_id: Pubkey,
    pub pricing: Pricing,
    /// `Σ share_bps <= 10_000`; payee gets the remainder.
    pub splits: Vec<Split>,
    pub max_deposit: u64,
    pub min_deposit: u64,
    pub min_voucher_delta: u64,
    pub voucher_ttl_seconds: u32,
    pub grace_period_seconds: u32,
    /// Challenge cache lifetime cap. Defaults to 300s.
    pub challenge_ttl_seconds: u32,
    /// Commitment level for RPC reads inside the lifecycle. Threaded
    /// through to the upstream `verify_*` helpers. Defaults to
    /// `Confirmed`.
    pub commitment: CommitmentConfig,
    /// How long to wait for the open tx to land at `Confirmed` before
    /// giving up with `OpenTxUnconfirmed`. Defaults to 30s, comfortable
    /// for devnet round-trips.
    pub broadcast_confirm_timeout: Duration,
    /// Wall-clock slack the voucher TTL check tolerates. Defaults to
    /// 5s.
    pub clock_skew_seconds: u32,
    /// Grace window after a voucher's `expires_at` for transient RPC
    /// delay between sign and submit. Defaults to 15s.
    pub voucher_check_grace_seconds: u32,
    pub fee_payer: Option<FeePayer>,
    /// Realm advertised in the WWW-Authenticate header. Falls back to
    /// [`DEFAULT_REALM`] (`"MPP Payment"`) when `None`.
    pub realm: Option<String>,
    /// HMAC key for deterministic challenge ids. Set this to something
    /// unique to your deployment. `None` falls back to the
    /// `MPP_SECRET_KEY` env var; if both are missing,
    /// [`SessionBuilder::recover`] errors out.
    pub secret_key: Option<String>,
}

impl SessionConfig {
    /// Config with reasonable defaults. The required identifiers
    /// (`operator`, `payee`, `mint`, `program_id`) still need to be
    /// provided. `secret_key` stays `None` so the resolver can pick
    /// up `MPP_SECRET_KEY` from the env.
    pub fn new_with_defaults(
        operator: Pubkey,
        payee: Pubkey,
        mint: Pubkey,
        decimals: u8,
        network: Network,
        program_id: Pubkey,
        pricing: Pricing,
    ) -> Self {
        Self {
            operator,
            payee,
            mint,
            decimals,
            network,
            program_id,
            pricing,
            splits: Vec::new(),
            max_deposit: 0,
            min_deposit: 0,
            min_voucher_delta: 0,
            voucher_ttl_seconds: 60,
            grace_period_seconds: 24 * 60 * 60,
            challenge_ttl_seconds: DEFAULT_CHALLENGE_TTL_SECONDS,
            commitment: CommitmentConfig::confirmed(),
            broadcast_confirm_timeout: Duration::from_secs(30),
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
            voucher_check_grace_seconds: DEFAULT_VOUCHER_CHECK_GRACE_SECONDS,
            fee_payer: None,
            realm: None,
            secret_key: None,
        }
    }
}

/// Pick the secret key from config, falling back to the env var.
/// Returns `InternalError` when neither is set, matching the shape of
/// other recover-time misconfiguration errors.
fn resolve_secret_key(opt: &Option<String>) -> Result<String, SessionError> {
    if let Some(s) = opt {
        return Ok(s.clone());
    }
    std::env::var(SECRET_KEY_ENV_VAR).map_err(|_| {
        SessionError::InternalError(format!(
            "Missing {SECRET_KEY_ENV_VAR} env var or session config secret_key field"
        ))
    })
}

/// Pick the realm, defaulting to [`DEFAULT_REALM`].
fn resolve_realm(opt: &Option<String>) -> String {
    opt.clone().unwrap_or_else(|| DEFAULT_REALM.to_string())
}

/// Advisory fields a caller can attach to an `Open` challenge.
/// Both description and external id are pure passthrough.
#[derive(Debug, Clone, Default)]
pub struct OpenChallengeOptions {
    pub description: Option<String>,
    pub external_id: Option<String>,
}

/// Tuning knobs for the recovery walk that runs before
/// `SessionMethod` is built.
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// When true, unsettled mid-session revenue is a warning instead
    /// of a fatal startup error. Off by default; only flip if you've
    /// thought through the audit story.
    pub allow_unsettled_on_startup: bool,
    /// Concurrency cap on the per-channel inspect phase.
    pub parallelism: usize,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            allow_unsettled_on_startup: false,
            parallelism: 8,
        }
    }
}

/// Handoff between `prepare_open` and `finalize_open`: the co-signed
/// transaction plus the typed values needed for the on-chain verify
/// and the persisted channel record. Internal only.
struct PreparedOpen {
    tx: Transaction,
    channel_id: Pubkey,
    payer: Pubkey,
    payee: Pubkey,
    mint: Pubkey,
    authorized_signer: Pubkey,
    salt: u64,
    deposit: u64,
    canonical_bump: u8,
    payload_splits: Vec<Split>,
}

/// Server-side handler for the session intent.
///
/// Only built via [`SessionBuilder::recover`]; recovery has to run
/// before we'll serve anything.
pub struct SessionMethod {
    config: SessionConfig,
    /// HMAC secret resolved at construction (from config or env) so
    /// the hot path doesn't re-read the env.
    secret_key: String,
    /// Realm with the default applied.
    realm: String,
    store: Arc<dyn ChannelStore>,
    rpc: Arc<RpcClient>,
    cache: ChallengeCache,
    /// Plain `JoinHandle` because `SessionMethod` is not `Clone`, so
    /// the `Drop` impl owns the only handle. If we ever make this
    /// `Clone`, switch to `Arc<JoinHandle>` and guard on
    /// `strong_count == 1` so the sweeper outlives every clone.
    sweeper: JoinHandle<()>,
}

impl std::fmt::Debug for SessionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionMethod")
            .field("operator", &self.config.operator)
            .field("payee", &self.config.payee)
            .field("mint", &self.config.mint)
            .field("network", &self.config.network)
            .finish()
    }
}

impl SessionMethod {
    /// Build a fresh handler and spawn the background sweeper that
    /// evicts cache entries older than `2 * challenge_ttl_seconds`.
    ///
    /// `pub(crate)` because [`SessionBuilder::recover`] is the only
    /// supported public entry; action handlers and recovery code in
    /// this crate use it directly.
    ///
    /// If `recover()` errors out mid-flight, this `SessionMethod` is
    /// dropped on the way out and the `Drop` impl aborts the sweeper.
    /// Keep that cleanup intact when changing the recovery flow.
    pub(crate) fn new_for_recover(
        config: SessionConfig,
        store: Arc<dyn ChannelStore>,
        rpc: Arc<RpcClient>,
    ) -> Result<Self, SessionError> {
        let secret_key = resolve_secret_key(&config.secret_key)?;
        let realm = resolve_realm(&config.realm);
        let cache = ChallengeCache::new(config.challenge_ttl_seconds);
        let sweeper = spawn_sweeper(cache.clone(), config.challenge_ttl_seconds);
        Ok(Self {
            config,
            secret_key,
            realm,
            store,
            rpc,
            cache,
            sweeper,
        })
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub fn store(&self) -> &Arc<dyn ChannelStore> {
        &self.store
    }

    pub fn rpc(&self) -> &Arc<RpcClient> {
        &self.rpc
    }

    pub fn cache(&self) -> &ChallengeCache {
        &self.cache
    }

    /// Issue an `Open` challenge bound to the configured payee,
    /// mint, splits, and deposit bounds.
    pub async fn build_challenge_for_open(
        &self,
        opts: OpenChallengeOptions,
    ) -> Result<PaymentChallenge, SessionError> {
        let blockhash = self.rpc.get_latest_blockhash().await?;

        let intent = ChallengeIntent::Open {
            payee: self.config.payee,
            mint: self.config.mint,
            advertised_splits: self.config.splits.clone(),
            min_deposit: self.config.min_deposit,
            max_deposit: self.config.max_deposit,
        };

        let request = self.session_request_for_open(&opts, &blockhash);
        let encoded = Base64UrlJson::from_typed(&request)
            .map_err(|e| SessionError::InternalError(format!("encode open body: {e}")))?;

        let challenge = self.build_challenge(encoded, opts.description.as_deref())?;

        let issued_at = now_unix_seconds();
        self.cache.insert(
            challenge.id.clone(),
            ChallengeRecord::new(intent, opts.external_id, issued_at, blockhash),
        )?;
        Ok(challenge)
    }

    /// Wire-shape `SessionRequest` for an `Open` challenge. Pure: no
    /// RPC, no cache mutation, so unit tests can pin the body without
    /// a live cluster. Handlers re-validate against the cached
    /// `ChallengeIntent`, so this is the advertised wire body, not
    /// the source of truth.
    fn session_request_for_open(
        &self,
        opts: &OpenChallengeOptions,
        blockhash: &solana_hash::Hash,
    ) -> SessionRequest {
        let unit_type = if self.config.pricing.unit_type.is_empty() {
            None
        } else {
            Some(self.config.pricing.unit_type.clone())
        };
        SessionRequest {
            amount: self.config.pricing.amount_per_unit.to_string(),
            unit_type,
            recipient: self.config.payee.to_string(),
            currency: self.config.mint.to_string(),
            description: opts.description.clone(),
            external_id: opts.external_id.clone(),
            method_details: MethodDetails {
                network: Some(self.config.network.as_str().to_string()),
                channel_program: self.config.program_id.to_string(),
                channel_id: None,
                decimals: Some(self.config.decimals),
                token_program: None,
                fee_payer: self.config.fee_payer.as_ref().map(|_| true),
                fee_payer_key: self
                    .config
                    .fee_payer
                    .as_ref()
                    .map(|f| f.signer.pubkey().to_string()),
                recent_blockhash: self
                    .config
                    .fee_payer
                    .as_ref()
                    .map(|_| blockhash.to_string()),
                min_voucher_delta: Some(self.config.min_voucher_delta.to_string()),
                ttl_seconds: Some(self.config.voucher_ttl_seconds),
                grace_period_seconds: Some(self.config.grace_period_seconds),
                distribution_splits: typed_to_wire(&self.config.splits),
                minimum_deposit: self.config.min_deposit.to_string(),
            },
        }
    }

    /// Issue a `TopUp` challenge for a known channel id, using the
    /// channel's persisted splits as the wire shape.
    pub async fn build_challenge_for_topup(
        &self,
        channel_id: &Pubkey,
    ) -> Result<PaymentChallenge, SessionError> {
        let record = self
            .store
            .get(channel_id)
            .await?
            .ok_or_else(|| SessionError::InternalError(format!("unknown channel {channel_id}")))?;

        let blockhash = self.rpc.get_latest_blockhash().await?;
        let intent = ChallengeIntent::TopUp {
            channel_id: *channel_id,
        };

        let request = self.session_request_for_known_channel(channel_id, &record.splits, &blockhash);
        let encoded = Base64UrlJson::from_typed(&request)
            .map_err(|e| SessionError::InternalError(format!("encode topup body: {e}")))?;
        let challenge = self.build_challenge(encoded, None)?;

        let issued_at = now_unix_seconds();
        self.cache.insert(
            challenge.id.clone(),
            ChallengeRecord::new(intent, None, issued_at, blockhash),
        )?;
        Ok(challenge)
    }

    /// Issue a `Close` challenge for a known channel id.
    pub async fn build_challenge_for_close(
        &self,
        channel_id: &Pubkey,
    ) -> Result<PaymentChallenge, SessionError> {
        // Bail early if the channel is unknown. The close handler
        // checks again, but no point handing out a challenge we
        // already know we can't honour.
        let record = self
            .store
            .get(channel_id)
            .await?
            .ok_or_else(|| SessionError::InternalError(format!("unknown channel {channel_id}")))?;

        let blockhash = self.rpc.get_latest_blockhash().await?;
        let intent = ChallengeIntent::Close {
            channel_id: *channel_id,
        };

        let request = self.session_request_for_known_channel(channel_id, &record.splits, &blockhash);
        let encoded = Base64UrlJson::from_typed(&request)
            .map_err(|e| SessionError::InternalError(format!("encode close body: {e}")))?;
        let challenge = self.build_challenge(encoded, None)?;

        let issued_at = now_unix_seconds();
        self.cache.insert(
            challenge.id.clone(),
            ChallengeRecord::new(intent, None, issued_at, blockhash),
        )?;
        Ok(challenge)
    }

    /// Shared `SessionRequest` builder for topup and close. Both
    /// target a known channel and reuse its persisted splits.
    fn session_request_for_known_channel(
        &self,
        channel_id: &Pubkey,
        splits: &[Split],
        blockhash: &solana_hash::Hash,
    ) -> SessionRequest {
        let unit_type = if self.config.pricing.unit_type.is_empty() {
            None
        } else {
            Some(self.config.pricing.unit_type.clone())
        };
        SessionRequest {
            amount: self.config.pricing.amount_per_unit.to_string(),
            unit_type,
            recipient: self.config.payee.to_string(),
            currency: self.config.mint.to_string(),
            description: None,
            external_id: None,
            method_details: MethodDetails {
                network: Some(self.config.network.as_str().to_string()),
                channel_program: self.config.program_id.to_string(),
                channel_id: Some(channel_id.to_string()),
                decimals: Some(self.config.decimals),
                token_program: None,
                fee_payer: self.config.fee_payer.as_ref().map(|_| true),
                fee_payer_key: self
                    .config
                    .fee_payer
                    .as_ref()
                    .map(|f| f.signer.pubkey().to_string()),
                recent_blockhash: self
                    .config
                    .fee_payer
                    .as_ref()
                    .map(|_| blockhash.to_string()),
                min_voucher_delta: Some(self.config.min_voucher_delta.to_string()),
                ttl_seconds: Some(self.config.voucher_ttl_seconds),
                grace_period_seconds: Some(self.config.grace_period_seconds),
                distribution_splits: typed_to_wire(splits),
                minimum_deposit: self.config.min_deposit.to_string(),
            },
        }
    }

    /// Server entry point for the `open` action.
    ///
    /// Checks the cached challenge, the wire payload, and the client's
    /// partial-signed tx, then co-signs as fee payer, broadcasts, and
    /// persists the channel record.
    ///
    /// The challenge gets reserved before any RPC. Anything that fails
    /// before `send_transaction` succeeds releases the reservation so
    /// the client can retry. Once `send_transaction` returns Ok the
    /// cluster has accepted the tx and the challenge flips to Consumed
    /// immediately, before the confirm poll: otherwise a confirm-poll
    /// timeout could let the client re-broadcast the same intent
    /// against a tx that's still landing. After Consumed, any later
    /// error (timeout, verify failure) bubbles up with the challenge
    /// already burned and recovery handles signature reconciliation.
    pub async fn process_open(
        &self,
        payload: &OpenPayload,
    ) -> Result<Receipt, SessionError> {
        // Reserve under `Open` intent.
        let cached = self
            .cache
            .reserve(&payload.challenge_id, ChallengeIntentDiscriminant::Open)?;

        // Pre-broadcast validation. Anything failing here releases the
        // reservation so the client can retry.
        let prepared = match self.prepare_open(payload, &cached).await {
            Ok(p) => p,
            Err(e) => {
                // Best-effort release; swallow the secondary error so the
                // primary failure reaches the caller.
                let _ = self.cache.release(&payload.challenge_id);
                return Err(e);
            }
        };

        // Broadcast. Once `send_transaction` returns Ok the cluster has
        // accepted the tx, so from here on we never release the
        // challenge.
        let send_config = solana_client::rpc_config::RpcSendTransactionConfig {
            preflight_commitment: Some(self.config.commitment.commitment),
            ..Default::default()
        };
        let tx_sig = match self.rpc.send_transaction_with_config(&prepared.tx, send_config).await {
            Ok(sig) => sig,
            Err(e) => {
                let _ = self.cache.release(&payload.challenge_id);
                return Err(client_error_to_session_error(e));
            }
        };

        // Commit before the confirm poll. A 30s timeout doesn't mean the
        // tx failed, just that we haven't seen Confirmed yet; releasing
        // would let the client re-broadcast a duplicate while the
        // original lands. Recovery reconciles unconfirmed signatures.
        self.cache.commit(&payload.challenge_id)?;

        // Confirm + verify + persist. Errors propagate with the
        // challenge already consumed.
        self.finalize_open(payload, prepared, tx_sig).await
    }

    /// Pre-broadcast prep. Runs every check from the cached challenge
    /// through tx-shape co-signing. Failures here are safe to release.
    async fn prepare_open(
        &self,
        payload: &OpenPayload,
        cached: &ChallengeRecord,
    ) -> Result<PreparedOpen, SessionError> {
        // Decode wire splits and check the cached intent's advertised
        // fields against the payload.
        let payload_splits = wire_to_typed(&payload.distribution_splits, |m| {
            SessionError::ChallengeFieldMismatch {
                field: "distributionSplits",
                advertised: "<cached>".into(),
                got: m,
            }
        })?;

        let (advertised_payee, advertised_mint, advertised_splits, min_deposit, max_deposit) =
            match &cached.intent {
                ChallengeIntent::Open {
                    payee,
                    mint,
                    advertised_splits,
                    min_deposit,
                    max_deposit,
                } => (*payee, *mint, advertised_splits.clone(), *min_deposit, *max_deposit),
                // Discriminant was checked at reserve, so this arm is
                // unreachable.
                _ => {
                    return Err(SessionError::ChallengeIntentMismatch);
                }
            };

        let payload_payee = parse_pubkey_field("payee", &payload.payee)?;
        if payload_payee != advertised_payee {
            return Err(SessionError::ChallengeFieldMismatch {
                field: "payee",
                advertised: advertised_payee.to_string(),
                got: payload_payee.to_string(),
            });
        }
        let payload_mint = parse_pubkey_field("mint", &payload.mint)?;
        if payload_mint != advertised_mint {
            return Err(SessionError::ChallengeFieldMismatch {
                field: "mint",
                advertised: advertised_mint.to_string(),
                got: payload_mint.to_string(),
            });
        }
        if payload_splits != advertised_splits {
            return Err(SessionError::ChallengeFieldMismatch {
                field: "distributionSplits",
                advertised: format!("{advertised_splits:?}"),
                got: format!("{payload_splits:?}"),
            });
        }

        let deposit: u64 = payload
            .deposit_amount
            .parse()
            .map_err(|e| SessionError::InvalidAmount(format!("depositAmount: {e}")))?;
        if deposit < min_deposit || deposit > max_deposit {
            return Err(SessionError::DepositOutOfRange {
                min: min_deposit,
                max: max_deposit,
                got: deposit,
            });
        }

        // Re-derive `(channel_pda, canonical_bump)` and reject on
        // drift before doing any tx-shape work.
        let payer = parse_pubkey_field("payer", &payload.payer)?;
        let authorized_signer =
            parse_pubkey_field("authorizedSigner", &payload.authorized_signer)?;
        let salt: u64 = payload
            .salt
            .parse()
            .map_err(|e| SessionError::InvalidAmount(format!("salt: {e}")))?;
        let (expected_pda, canonical_bump) = find_channel_pda(
            &payer,
            &payload_payee,
            &payload_mint,
            &authorized_signer,
            salt,
            &self.config.program_id,
        );
        let claimed_pda = parse_pubkey_field("channelId", &payload.channel_id)?;
        if claimed_pda != expected_pda {
            return Err(SessionError::OnChainStateMismatch {
                field: "channelId",
                expected: expected_pda.to_string(),
                got: claimed_pda.to_string(),
            });
        }
        if payload.bump != canonical_bump {
            return Err(SessionError::BumpMismatch {
                canonical: canonical_bump,
                got: payload.bump,
            });
        }

        // Compare the submitted tx against the canonical bytes.
        let DecodedOpenTx {
            mut tx,
            channel_id,
            salt: tx_salt,
            deposit: tx_deposit,
            grace_period: tx_grace,
            canonical_bump: tx_bump,
        } = validate_open_tx_shape(payload, &payload_splits, &self.config, &cached.recent_blockhash)?;
        // Sanity asserts. The canonical-bytes comparison above already
        // covers equivalence, but a typed cross-check gives a clearer
        // error if the payload-vs-tx parsing layers drift.
        debug_assert_eq!(tx_salt, salt);
        debug_assert_eq!(tx_deposit, deposit);
        debug_assert_eq!(tx_grace, self.config.grace_period_seconds);
        debug_assert_eq!(tx_bump, canonical_bump);
        debug_assert_eq!(channel_id, expected_pda);

        // Co-sign as fee payer. Signature slot 0 is the fee-payer.
        let fee_payer = self.config.fee_payer.as_ref().ok_or_else(|| {
            SessionError::InternalError("fee_payer not configured; v1 is server-submit".into())
        })?;
        let msg_data = tx.message_data();
        let sig = fee_payer
            .signer
            .sign_message(&msg_data)
            .await
            .map_err(|e| SessionError::InternalError(format!("fee-payer sign failed: {e}")))?;
        if tx.signatures.is_empty() {
            return Err(SessionError::MaliciousTx {
                reason: "transaction missing signature slot for fee payer".into(),
            });
        }
        tx.signatures[0] = Signature::from(<[u8; 64]>::from(sig));

        Ok(PreparedOpen {
            tx,
            channel_id,
            payer,
            payee: payload_payee,
            mint: payload_mint,
            authorized_signer,
            salt,
            deposit,
            canonical_bump,
            payload_splits,
        })
    }

    /// Post-broadcast finalisation. By the time this runs the challenge
    /// is already Consumed, so failures bubble up without releasing.
    /// A confirm-poll timeout returns `OpenTxUnconfirmed(sig)` so the
    /// real signature ends up in operator logs; recovery handles
    /// signatures that landed late.
    async fn finalize_open(
        &self,
        payload: &OpenPayload,
        prepared: PreparedOpen,
        tx_sig: Signature,
    ) -> Result<Receipt, SessionError> {
        let PreparedOpen {
            tx: _,
            channel_id,
            payer,
            payee: payload_payee,
            mint: payload_mint,
            authorized_signer,
            salt,
            deposit,
            canonical_bump,
            payload_splits,
        } = prepared;

        // Poll for Confirmed, bounded by `broadcast_confirm_timeout`.
        let confirm_commitment = CommitmentConfig::confirmed();
        let mut confirmed = false;
        let confirm_deadline = std::time::Instant::now() + self.config.broadcast_confirm_timeout;
        while std::time::Instant::now() < confirm_deadline {
            let resp = self
                .rpc
                .confirm_transaction_with_commitment(&tx_sig, confirm_commitment)
                .await
                .map_err(client_error_to_session_error)?;
            if resp.value {
                confirmed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if !confirmed {
            tracing::warn!(
                signature = %tx_sig,
                timeout_secs = self.config.broadcast_confirm_timeout.as_secs(),
                "open tx broadcast but failed to confirm within timeout; channel may or may not exist; recovery layer will reconcile",
            );
            return Err(SessionError::OpenTxUnconfirmed(tx_sig));
        }

        // On-chain verify. Map `VerifyError` onto the public surface
        // error, carrying the offending field name.
        verify_open(
            &self.rpc,
            self.config.commitment,
            &channel_id,
            &ExpectedOpenState {
                deposit,
                payer,
                payee: payload_payee,
                mint: payload_mint,
                authorized_signer,
                bump: canonical_bump,
            },
            &payload_splits,
        )
        .await
        .map_err(|e| verify_error_to_session_error(e, &channel_id))?;

        // Insert only after verify succeeds, so a cluster-disagreement
        // never writes through to the store.
        let record = ChannelRecord {
            channel_id,
            payer,
            payee: payload_payee,
            mint: payload_mint,
            salt,
            program_id: self.config.program_id,
            authorized_signer,
            deposit,
            accepted_cumulative: 0,
            on_chain_settled: 0,
            last_voucher: None,
            close_tx: None,
            status: ChannelStatus::Open,
            splits: payload_splits,
        };
        self.store.insert(record).await?;

        Ok(Receipt {
            status: crate::protocol::core::ReceiptStatus::Success,
            method: MethodName::from(METHOD_NAME),
            timestamp: rfc3339_now(),
            reference: tx_sig.to_string(),
            challenge_id: payload.challenge_id.clone(),
            accepted_cumulative: None,
            spent: None,
        })
    }

    /// Server entry point for voucher submission.
    ///
    /// Off-chain validation plus an atomic store CAS: signature and
    /// payload checks first, then `advance_watermark` linearises the
    /// per-channel race. CAS losers get the winner's cached receipt
    /// bytes back, so two callers at the same cumulative see the same
    /// receipt the network committed to.
    pub async fn verify_voucher(
        &self,
        signed: &crate::protocol::intents::session::SignedVoucher,
    ) -> Result<Receipt, SessionError> {
        voucher::run_verify_voucher(self.store.as_ref(), &self.config, signed).await
    }

    fn build_challenge(
        &self,
        encoded: Base64UrlJson,
        description: Option<&str>,
    ) -> Result<PaymentChallenge, SessionError> {
        // Trailing `None`s match `compute_challenge_id`'s
        // `expires`/`digest`/`opaque` slots. Sessions don't pin an
        // expiry into the HMAC input (cache TTL covers that) and
        // there's no body digest or opaque echo to commit.
        let id = compute_challenge_id(
            &self.secret_key,
            &self.realm,
            METHOD_NAME,
            SESSION_INTENT,
            encoded.raw(),
            None, // expires
            None, // digest
            None, // opaque
        );
        Ok(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: METHOD_NAME.into(),
            intent: SESSION_INTENT.into(),
            request: encoded,
            expires: None,
            description: description.map(str::to_string),
            digest: None,
            opaque: None,
        })
    }

    /// Realm with the default applied. Use this when building
    /// WWW-Authenticate headers so reads see the resolved value, not
    /// the raw `Option<String>` from config.
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

impl Drop for SessionMethod {
    fn drop(&mut self) {
        // We're not `Clone`, so this drop owns the only sweeper handle
        // and aborting unconditionally is safe.
        self.sweeper.abort();
    }
}

/// Hand a config in, get a builder back. Set the store and RPC
/// client on the builder before calling `recover()`.
pub fn session(config: SessionConfig) -> SessionBuilder {
    SessionBuilder {
        config,
        store: None,
        rpc: None,
        recovery: RecoveryOptions::default(),
    }
}

pub struct SessionBuilder {
    config: SessionConfig,
    store: Option<Arc<dyn ChannelStore>>,
    rpc: Option<Arc<RpcClient>>,
    recovery: RecoveryOptions,
}

impl SessionBuilder {
    pub fn with_store(mut self, store: Arc<dyn ChannelStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_rpc(mut self, rpc: Arc<RpcClient>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    pub fn with_recovery_options(mut self, opts: RecoveryOptions) -> Self {
        self.recovery = opts;
        self
    }

    /// Run startup recovery and produce a [`SessionMethod`] only after
    /// every persisted channel has been reconciled with the cluster.
    ///
    /// The recovery walk itself isn't here yet. For now this checks
    /// that store and RPC are wired (so misconfig surfaces obviously)
    /// and returns a typed "not yet implemented" so callers can still
    /// depend on the builder shape.
    pub async fn recover(self) -> Result<SessionMethod, SessionError> {
        let store = self.store.ok_or_else(|| {
            SessionError::InternalError("session builder missing store; call with_store".into())
        })?;
        let rpc = self.rpc.ok_or_else(|| {
            SessionError::InternalError("session builder missing rpc; call with_rpc".into())
        })?;

        // Build the eventual handler shape so `cargo check` keeps
        // exercising it before the recovery walk exists. Drop it
        // straight away so the sweeper doesn't keep running.
        // `new_for_recover` resolves `secret_key` and `realm` up front
        // so a bad secret config fails here, not on first challenge.
        let _ = self.recovery;
        drop(SessionMethod::new_for_recover(self.config, store, rpc)?);

        Err(SessionError::InternalError(
            "recover not yet implemented".to_string(),
        ))
    }
}

fn spawn_sweeper(cache: ChallengeCache, ttl_seconds: u32) -> JoinHandle<()> {
    // Tick every `ttl_seconds` and reclaim entries older than
    // `2 * ttl` so a Pending record gets a grace window before being
    // evicted out from under a slow handler.
    let period = ttl_seconds.max(1) as u64;
    let evict_age = ttl_seconds.saturating_mul(2);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(period));
        // Skip the immediate first tick: cache is empty at startup.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            cache.evict_expired(evict_age, now_unix_seconds());
        }
    })
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Decode a base58 pubkey field from a wire payload.
fn parse_pubkey_field(field: &'static str, raw: &str) -> Result<Pubkey, SessionError> {
    let bytes = bs58::decode(raw)
        .into_vec()
        .map_err(|e| SessionError::OnChainStateMismatch {
            field,
            expected: "base58 pubkey".into(),
            got: format!("{raw}: {e}"),
        })?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SessionError::OnChainStateMismatch {
            field,
            expected: "32-byte pubkey".into(),
            got: raw.to_string(),
        })?;
    Ok(Pubkey::new_from_array(arr))
}

/// Map a `solana_client::ClientError` to the right `SessionError`.
///
/// The blanket `From<ClientError>` lands every RPC failure in
/// `RpcUnavailable` (5xx), which is wrong for blockhash expiry: the
/// client can fix it by grabbing a fresh challenge. This helper sniffs
/// `BlockhashNotFound` out of the simulated-tx path and routes it to
/// `BlockhashMismatch` (409). Everything else falls through to
/// `RpcUnavailable`.
///
/// Most blockhash-expiry signals only surface at simulation time
/// because the upstream client exposes `TransactionError` only after
/// the cluster has tried the tx. Pre-send detection isn't reliable, so
/// this catches the post-send case and treats the rest as transient.
fn client_error_to_session_error(e: ClientError) -> SessionError {
    if matches!(e.get_transaction_error(), Some(TransactionError::BlockhashNotFound)) {
        return SessionError::BlockhashMismatch {
            expected: "challenge-bound recent blockhash".to_string(),
            got: "BlockhashNotFound (expired or unknown to the cluster)".to_string(),
        };
    }
    SessionError::from(e)
}

/// Map `verify_open`'s `VerifyError` to a `SessionError`, carrying
/// the offending on-chain field name on the conflict variants.
fn verify_error_to_session_error(e: VerifyError, channel_id: &Pubkey) -> SessionError {
    match e {
        VerifyError::NotFound => SessionError::OnChainStateMismatch {
            field: "channel",
            expected: format!("Channel PDA at {channel_id}"),
            got: "account not found".into(),
        },
        VerifyError::Tombstoned => SessionError::OnChainStateMismatch {
            field: "channel",
            expected: "Open status".into(),
            got: "tombstoned (closed)".into(),
        },
        VerifyError::WrongLength { data_len } => SessionError::OnChainStateMismatch {
            field: "channel",
            expected: "Channel PDA bytes".into(),
            got: format!("unexpected data.len() == {data_len}"),
        },
        VerifyError::WrongDiscriminator { byte } => SessionError::OnChainStateMismatch {
            field: "channel",
            expected: "Channel discriminator".into(),
            got: format!("discriminator byte == {byte}"),
        },
        VerifyError::Mismatch(m) => mismatch_to_session_error(m),
        VerifyError::UnexpectedEncoding { channel_id } => SessionError::OnChainStateMismatch {
            field: "channel",
            expected: "Base64 RPC encoding".into(),
            got: format!("unsupported encoding for {channel_id}"),
        },
        VerifyError::Rpc(err) => err.into(),
        VerifyError::Decode(err) => SessionError::InternalError(format!("channel decode: {err}")),
    }
}

fn mismatch_to_session_error(m: Mismatch) -> SessionError {
    use Mismatch as M;
    match m {
        M::Deposit { expected, got } => SessionError::OnChainStateMismatch {
            field: "deposit",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::Settled { expected, got } => SessionError::OnChainStateMismatch {
            field: "settled",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::Bump { expected, got } => SessionError::BumpMismatch {
            canonical: expected,
            got,
        },
        M::Version { got } => SessionError::ChannelVersionMismatch { supported: 1, got },
        M::Status { expected, got } => SessionError::OnChainStateMismatch {
            field: "status",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::GracePeriod { expected, got } => SessionError::OnChainStateMismatch {
            field: "gracePeriod",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::ClosureStartedAt { expected, got } => SessionError::OnChainStateMismatch {
            field: "closureStartedAt",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::Payer { expected, got } => SessionError::OnChainStateMismatch {
            field: "payer",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::Payee { expected, got } => SessionError::OnChainStateMismatch {
            field: "payee",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::AuthorizedSigner { expected, got } => SessionError::OnChainStateMismatch {
            field: "authorizedSigner",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::Mint { expected, got } => SessionError::OnChainStateMismatch {
            field: "mint",
            expected: expected.to_string(),
            got: got.to_string(),
        },
        M::ClosureNotStarted => SessionError::OnChainStateMismatch {
            field: "closureStartedAt",
            expected: ">0".into(),
            got: "0".into(),
        },
        M::DistributionHash { expected, got } => SessionError::SplitsMismatch {
            expected_hash: expected,
            got_hash: got,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryChannelStore;
    use solana_hash::Hash;

    fn dummy_method() -> SessionMethod {
        // Local URL only; these tests exercise the pure body builder
        // and never hit the RPC.
        let rpc = Arc::new(RpcClient::new("http://127.0.0.1:8899".to_string()));
        let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
        let config = SessionConfig {
            operator: Pubkey::new_from_array([1u8; 32]),
            payee: Pubkey::new_from_array([2u8; 32]),
            mint: Pubkey::new_from_array([3u8; 32]),
            decimals: 6,
            network: Network::Localnet,
            program_id: Pubkey::new_from_array([4u8; 32]),
            pricing: Pricing {
                amount_per_unit: 1_000,
                unit_type: "request".into(),
            },
            splits: Vec::new(),
            max_deposit: 100_000,
            min_deposit: 1_000,
            min_voucher_delta: 0,
            voucher_ttl_seconds: 60,
            grace_period_seconds: 86_400,
            challenge_ttl_seconds: 300,
            commitment: CommitmentConfig::confirmed(),
            broadcast_confirm_timeout: Duration::from_secs(30),
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
            voucher_check_grace_seconds: DEFAULT_VOUCHER_CHECK_GRACE_SECONDS,
            fee_payer: None,
            realm: Some("Test Realm".into()),
            secret_key: Some("test-secret-key".into()),
        };
        SessionMethod::new_for_recover(config, store, rpc).expect("construct SessionMethod")
    }

    #[tokio::test]
    async fn external_id_appears_in_open_challenge_body() {
        // `external_id` flows from `OpenChallengeOptions` into the wire
        // body's `externalId`. The cache record carries the same value;
        // this test pins the wire path since that's what the client
        // sees.
        let method = dummy_method();
        let opts = OpenChallengeOptions {
            description: Some("rent-a-frame".into()),
            external_id: Some("ext-123".into()),
        };
        let request = method.session_request_for_open(&opts, &Hash::new_from_array([0u8; 32]));
        let value = serde_json::to_value(&request).expect("request serializes");
        assert_eq!(value.get("externalId"), Some(&serde_json::json!("ext-123")));

        // Round-trip through `Base64UrlJson` to confirm the encoded
        // body also carries the field.
        let encoded = Base64UrlJson::from_typed(&request).expect("encode body");
        let decoded: serde_json::Value = encoded.decode_value().expect("decode body");
        assert_eq!(
            decoded.get("externalId"),
            Some(&serde_json::json!("ext-123"))
        );
    }

    #[tokio::test]
    async fn open_commits_challenge_before_confirm_poll() {
        // Pin the post-broadcast ordering inside `process_open`. Once
        // `send_transaction` returns Ok, the cache moves to Consumed
        // before the confirm poll runs; a later `OpenTxUnconfirmed`
        // therefore leaves the record Consumed, not Available, so the
        // client can't re-broadcast a duplicate if the original lands
        // a moment after the timeout.
        //
        // The cache state machine runs directly here; driving the
        // surrounding broadcast/verify/persist needs a live cluster
        // and the L1 oracle covers that. This test just locks the
        // ordering `process_open` relies on.
        let method = dummy_method();
        let challenge_id = "test-challenge-id-open-commit-ordering".to_string();
        let intent = ChallengeIntent::Open {
            payee: method.config.payee,
            mint: method.config.mint,
            advertised_splits: Vec::new(),
            min_deposit: method.config.min_deposit,
            max_deposit: method.config.max_deposit,
        };
        let issued_at = now_unix_seconds();
        method
            .cache
            .insert(
                challenge_id.clone(),
                ChallengeRecord::new(intent, None, issued_at, Hash::new_from_array([0u8; 32])),
            )
            .expect("seed challenge record");

        // Reserve then commit, mirroring `process_open` after
        // `send_transaction` returns Ok.
        method
            .cache
            .reserve(&challenge_id, ChallengeIntentDiscriminant::Open)
            .expect("reserve fresh challenge");
        method
            .cache
            .commit(&challenge_id)
            .expect("commit pending challenge");

        let snapshot = method
            .cache
            .get(&challenge_id)
            .expect("record stays in cache after commit");
        assert_eq!(
            snapshot.state,
            challenge::ChallengeState::Consumed,
            "challenge must be Consumed after commit, not Available"
        );

        // A second reservation on the same id must fail no matter
        // what happens to the original tx.
        let err = method
            .cache
            .reserve(&challenge_id, ChallengeIntentDiscriminant::Open)
            .expect_err("second reserve on Consumed challenge must reject");
        assert!(
            matches!(err, SessionError::ChallengeUnbound),
            "expected ChallengeUnbound on retry, got {err:?}"
        );
    }

    #[tokio::test]
    async fn omitted_external_id_is_absent_from_open_challenge_body() {
        // `skip_serializing_if = "Option::is_none"` means an absent
        // `external_id` should omit the JSON key entirely, not emit
        // `null`.
        let method = dummy_method();
        let opts = OpenChallengeOptions {
            description: None,
            external_id: None,
        };
        let request = method.session_request_for_open(&opts, &Hash::new_from_array([0u8; 32]));
        let value = serde_json::to_value(&request).expect("request serializes");
        assert!(
            value.get("externalId").is_none(),
            "externalId must be absent when not supplied; got: {value}"
        );

        let encoded = Base64UrlJson::from_typed(&request).expect("encode body");
        let decoded: serde_json::Value = encoded.decode_value().expect("decode body");
        assert!(
            decoded.get("externalId").is_none(),
            "decoded body must not carry externalId; got: {decoded}"
        );
    }
}
