//! Session intent server-side lifecycle.
//!
//! Public surface (assembled across this directory):
//!
//! - [`SessionConfig`]: operator-supplied configuration.
//! - [`SessionMethod`]: not directly constructible, only
//!   `SessionBuilder::recover().await?` produces one.
//! - [`SessionBuilder`]: builder with `with_store` / `with_rpc` /
//!   `with_recovery_options` / `recover`.
//!
//! Submodule layout:
//!
//! - [`challenge`]: challenge cache, intent binding, sweeper.
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

const METHOD_NAME: &str = "solana";
const SESSION_INTENT: &str = "session";

/// Default realm advertised in the WWW-Authenticate header. Mirrors
/// `charge`'s `"MPP Payment"`. They are independent intents but share
/// the 402 framing, so a session-only operator would not need to
/// configure the realm explicitly. Charge keeps its own copy of the
/// constant because the two surfaces are otherwise unrelated.
const DEFAULT_REALM: &str = "MPP Payment";

/// Env var holding the HMAC secret. Same name as charge so an operator
/// running both intents on one process only sets one variable.
const SECRET_KEY_ENV_VAR: &str = "MPP_SECRET_KEY";

const DEFAULT_CHALLENGE_TTL_SECONDS: u32 = 300;
const DEFAULT_CLOCK_SKEW_SECONDS: u32 = 5;
const DEFAULT_VOUCHER_CHECK_GRACE_SECONDS: u32 = 15;

/// Solana cluster the session lives on. The string form doubles as the
/// chain id slug embedded in DIDs and in `methodDetails.network`.
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

/// Per-unit pricing the operator advertises in the 402 challenge body.
#[derive(Debug, Clone)]
pub struct Pricing {
    pub amount_per_unit: u64,
    pub unit_type: String,
}

/// Server-side fee-payer signer. The SDK does not persist key material;
/// the operator wraps their custody (env, KMS, HSM, wallet file) inside
/// a [`solana_keychain::SolanaSigner`] impl and hands it through here.
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

/// Operator-supplied configuration. Wired into [`SessionBuilder`] before
/// `recover()` produces a [`SessionMethod`]; the store and RPC client
/// flow in through the builder, not through here.
#[derive(Clone)]
pub struct SessionConfig {
    pub operator: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub decimals: u8,
    pub network: Network,
    pub program_id: Pubkey,
    pub pricing: Pricing,
    /// `Σ share_bps <= 10_000`; the payee receives the implicit
    /// remainder.
    pub splits: Vec<Split>,
    pub max_deposit: u64,
    pub min_deposit: u64,
    pub min_voucher_delta: u64,
    pub voucher_ttl_seconds: u32,
    pub grace_period_seconds: u32,
    /// Bound on challenge cache lifetime. Defaults to 300s.
    pub challenge_ttl_seconds: u32,
    /// Commitment level used for RPC reads inside the lifecycle. The
    /// upstream `verify_*` helpers thread this through. Defaults to
    /// `Confirmed`.
    pub commitment: CommitmentConfig,
    /// How long the open-tx broadcast loop waits for the cluster to
    /// surface the submitted signature at `Confirmed` before giving up
    /// and returning `OpenTxUnconfirmed`. Defaults to 30s, which covers
    /// devnet round-trips with headroom.
    pub broadcast_confirm_timeout: Duration,
    /// Slack the voucher TTL check tolerates relative to wall-clock
    /// drift. Defaults to 5s.
    pub clock_skew_seconds: u32,
    /// How long after a voucher's `expires_at` the server will still
    /// accept it (covers transient RPC delay between the client's
    /// signing and the server's processing). Defaults to 15s.
    pub voucher_check_grace_seconds: u32,
    pub fee_payer: Option<FeePayer>,
    /// Realm advertised in the WWW-Authenticate header. `None` falls
    /// back to [`DEFAULT_REALM`] (`"MPP Payment"`).
    pub realm: Option<String>,
    /// HMAC key used to derive deterministic challenge ids. Operators
    /// MUST set this to a secret unique to their deployment.
    /// `None` falls back to the `MPP_SECRET_KEY` env var; if both are
    /// absent, [`SessionBuilder::recover`] returns an error.
    pub secret_key: Option<String>,
}

impl SessionConfig {
    /// Produce a config with sane defaults for everything that has one.
    /// Required identifiers (`operator`, `payee`, `mint`, `program_id`)
    /// still need to be set by the caller. `secret_key` is left `None`
    /// so the resolver in [`SessionBuilder::recover`] can fall back to
    /// the `MPP_SECRET_KEY` env var.
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

/// Resolve the operator's `secret_key` Option into a concrete string,
/// falling back to the `MPP_SECRET_KEY` env var. Returns
/// [`SessionError::InternalError`] if neither is set so the operator
/// gets the same shape they get for other recover-time misconfiguration.
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

/// Resolve the operator's `realm` Option, defaulting to
/// [`DEFAULT_REALM`].
fn resolve_realm(opt: &Option<String>) -> String {
    opt.clone().unwrap_or_else(|| DEFAULT_REALM.to_string())
}

/// Optional advisory fields a caller can attach to an `Open` challenge.
/// Description and external id flow into the challenge itself; both are
/// pure passthrough.
#[derive(Debug, Clone, Default)]
pub struct OpenChallengeOptions {
    pub description: Option<String>,
    pub external_id: Option<String>,
}

/// Tuning knobs for the recovery walk that gates `SessionMethod`
/// construction.
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// If true, the recovery walk treats unsettled mid-session revenue
    /// as a warning rather than a fatal error. Off by default; flip
    /// only if you understand the audit implications.
    pub allow_unsettled_on_startup: bool,
    /// Concurrency cap for the per-channel inspect phase.
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

/// Output of `prepare_open`: the co-signed transaction plus the typed
/// values needed by `finalize_open` to verify on-chain state and persist
/// the channel record. Held only between broadcast preparation and the
/// confirm-poll handoff; never crosses the public API.
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
/// Constructed exclusively through [`SessionBuilder::recover`]; recovery
/// is a hard prerequisite for serving requests.
pub struct SessionMethod {
    config: SessionConfig,
    /// Resolved HMAC secret. Materialised once during construction from
    /// `config.secret_key` or the `MPP_SECRET_KEY` env var so the hot
    /// path never re-reads the env.
    secret_key: String,
    /// Resolved realm string with the default applied.
    realm: String,
    store: Arc<dyn ChannelStore>,
    rpc: Arc<RpcClient>,
    cache: ChallengeCache,
    /// Plain `JoinHandle` because `SessionMethod` is not `Clone`; `Drop`
    /// always owns the only handle. If `SessionMethod` ever becomes
    /// `Clone`, switch to `Arc<JoinHandle>` with a `strong_count == 1`
    /// guard so the sweeper survives until the last clone is dropped.
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
    /// Construct a fresh handler. Spawns the background sweeper that
    /// evicts cache entries older than `2 * challenge_ttl_seconds`.
    ///
    /// `pub(crate)` because [`SessionBuilder::recover`] is the sole
    /// supported entry point. Action handlers and recovery code inside
    /// this crate may use this directly.
    ///
    /// If `recover()` returns `Err` mid-flight (e.g. the on-chain walk
    /// fails), the `SessionMethod` returned here is dropped at the end
    /// of the failed call. The `Drop` impl below aborts the sweeper, so
    /// no background task survives a failed recovery. Future changes
    /// to the recovery flow must preserve this cleanup invariant.
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

    /// Issue an `Open` challenge bound to the operator's advertised
    /// payee, mint, splits, and deposit bounds.
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

    /// Build the typed `SessionRequest` that goes on the wire for an
    /// `Open` challenge. Pure: no RPC, no cache mutation, lets unit
    /// tests pin the body shape without spinning up a live cluster.
    /// Action handlers re-validate intent fields against the cached
    /// `ChallengeIntent` on entry, so the wire body is the client-facing
    /// advertisement, not the source of truth.
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

    /// Issue a `TopUp` challenge bound to a known channel id and the
    /// channel's persisted splits.
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

    /// Issue a `Close` challenge bound to a known channel id.
    pub async fn build_challenge_for_close(
        &self,
        channel_id: &Pubkey,
    ) -> Result<PaymentChallenge, SessionError> {
        // Surface a typed error early if the channel is not known to
        // this server; the close handler will redo this check, but
        // failing here avoids handing out a challenge we already know
        // we cannot honour.
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

    /// Shared `SessionRequest` factory for topup and close challenges,
    /// both of which target a known channel and reuse the channel's
    /// persisted splits as the advertised wire shape.
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
    /// Validates the cached challenge, the wire payload, and the client's
    /// partial-signed transaction, then co-signs as fee payer, broadcasts,
    /// and persists the resulting channel record.
    ///
    /// Challenge lifecycle around broadcast: the reservation is taken
    /// before any RPC work. Errors raised BEFORE `send_transaction` lands
    /// release the reservation so the client can retry without burning a
    /// challenge. The moment the cluster accepts the transaction
    /// (`send_transaction` returns Ok), the challenge is committed
    /// (Pending to Consumed). This closes a retry-window race: a
    /// confirm-poll timeout returning `OpenTxUnconfirmed(sig)` while the
    /// transaction lands a moment later would otherwise let the client
    /// retry under the same challenge id and broadcast a second open for
    /// the same intent. After commit, any subsequent error (timeout or
    /// `verify_open` failure) propagates to the caller with the challenge
    /// already consumed; reconciliation of an unconfirmed signature is
    /// the recovery layer's job.
    pub async fn process_open(
        &self,
        payload: &OpenPayload,
    ) -> Result<Receipt, SessionError> {
        // 1. Reserve the challenge for `Open` intent.
        let cached = self
            .cache
            .reserve(&payload.challenge_id, ChallengeIntentDiscriminant::Open)?;

        // 2 to 5. Pre-broadcast validation. Any error here releases the
        //         reservation so the client can retry.
        let prepared = match self.prepare_open(payload, &cached).await {
            Ok(p) => p,
            Err(e) => {
                // Release best-effort; ignore the secondary error so the
                // primary failure surfaces to the caller.
                let _ = self.cache.release(&payload.challenge_id);
                return Err(e);
            }
        };

        // 6. Broadcast. Once `send_transaction` returns Ok, the cluster
        //    has accepted the tx and the challenge MUST be marked
        //    Consumed. From here on out, no error path may release.
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

        // Commit the challenge BEFORE the confirm poll. A confirm-poll
        // timeout at 30s does not mean the tx failed; it just means the
        // server has not seen Confirmed yet. Releasing here would let the
        // client re-broadcast against a tx that may still land, producing
        // a duplicate. The recovery layer reconciles unconfirmed signatures.
        self.cache.commit(&payload.challenge_id)?;

        // 6b to 8. Confirm + verify + persist. Errors propagate with the
        //          challenge already consumed.
        self.finalize_open(payload, prepared, tx_sig).await
    }

    /// Pre-broadcast preparation. Validates everything from the cached
    /// challenge through tx-shape co-signing. Errors here are safe to
    /// release the reservation against.
    async fn prepare_open(
        &self,
        payload: &OpenPayload,
        cached: &ChallengeRecord,
    ) -> Result<PreparedOpen, SessionError> {
        // 2. Decode wire splits to typed `Split`s, then assert the cached
        //    intent's advertised fields match the payload.
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
                // Discriminant was checked at reserve; this arm is unreachable.
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

        // 3. Re-derive (channel_pda, canonical_bump). Reject on PDA or bump
        //    drift before any tx-shape work runs.
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

        // 4. Validate the client's tx shape against the canonical bytes.
        let DecodedOpenTx {
            mut tx,
            channel_id,
            salt: tx_salt,
            deposit: tx_deposit,
            grace_period: tx_grace,
            canonical_bump: tx_bump,
        } = validate_open_tx_shape(payload, &payload_splits, &self.config, &cached.recent_blockhash)?;
        // Cross-check the decoded values match what the payload claimed.
        // These are post-hoc sanity asserts; the canonical-bytes comparison
        // already covers byte equivalence, but the typed-value cross-check
        // surfaces a clearer error if the payload-vs-tx parsing layers ever
        // drift.
        debug_assert_eq!(tx_salt, salt);
        debug_assert_eq!(tx_deposit, deposit);
        debug_assert_eq!(tx_grace, self.config.grace_period_seconds);
        debug_assert_eq!(tx_bump, canonical_bump);
        debug_assert_eq!(channel_id, expected_pda);

        // 5. Co-sign as fee payer. Slot 0 is the fee-payer signature.
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

    /// Post-broadcast finalisation. The challenge is already committed
    /// before this runs; failures here propagate to the caller without
    /// releasing. A confirm-poll timeout surfaces `OpenTxUnconfirmed(sig)`
    /// so the operator log carries the real signature; the recovery layer
    /// reconciles signatures that landed but did not confirm in time.
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

        // Poll for Confirmed commitment, bounded by the operator-configured
        // `broadcast_confirm_timeout`.
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

        // Mandatory on-chain verify. Map the typed VerifyError onto the
        // surface error with the offending field name.
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

        // Persist the record. Hold the insert until verify succeeds so a
        // cluster-disagreement does not write through to the store.
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
        })
    }

    fn build_challenge(
        &self,
        encoded: Base64UrlJson,
        description: Option<&str>,
    ) -> Result<PaymentChallenge, SessionError> {
        // Trailing `None`s are `expires`, `digest`, `opaque` per the
        // signature in `protocol::core::challenge::compute_challenge_id`.
        // Sessions do not pin an explicit expiry on the HMAC input
        // (the cache TTL handles that out-of-band) and have no body
        // digest or opaque echo to commit, so all three are None.
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

    /// Realm string with the default applied. Use this in
    /// WWW-Authenticate header construction so reads see the resolved
    /// value, not the operator's `Option<String>`.
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

impl Drop for SessionMethod {
    fn drop(&mut self) {
        // `SessionMethod` is not `Clone`, so this drop owns the only
        // handle to the sweeper task. Aborting unconditionally is safe.
        self.sweeper.abort();
    }
}

/// Entry point: hand a config in, get a builder back. Wire the store
/// and RPC client through the builder before calling `recover()`.
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
    /// The recovery walk itself is filled in by a follow-up. This
    /// skeleton validates that the store and RPC client are wired up
    /// (so misconfiguration surfaces an obvious error) and then
    /// returns a typed "not yet implemented" failure. Downstream
    /// callers can still take a compile-time dependency on the
    /// builder shape today.
    pub async fn recover(self) -> Result<SessionMethod, SessionError> {
        let store = self.store.ok_or_else(|| {
            SessionError::InternalError("session builder missing store; call with_store".into())
        })?;
        let rpc = self.rpc.ok_or_else(|| {
            SessionError::InternalError("session builder missing rpc; call with_rpc".into())
        })?;

        // Construct the eventual handler shape so the type stays
        // exercised by `cargo check` even before the recovery walk
        // lands. Drop it immediately so the sweeper is not left
        // running. `new_for_recover` resolves `secret_key` / `realm`
        // up front, so a bad secret config fails here rather than at
        // first challenge issuance.
        let _ = self.recovery;
        drop(SessionMethod::new_for_recover(self.config, store, rpc)?);

        Err(SessionError::InternalError(
            "recover not yet implemented".to_string(),
        ))
    }
}

fn spawn_sweeper(cache: ChallengeCache, ttl_seconds: u32) -> JoinHandle<()> {
    // Wake every `ttl_seconds`. Each tick reclaims entries older than
    // `2 * ttl` so a Pending record gets a grace window before being
    // evicted out from under a slow handler.
    let period = ttl_seconds.max(1) as u64;
    let evict_age = ttl_seconds.saturating_mul(2);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(period));
        // Skip the immediate first tick; the cache is empty at startup.
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

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Decode a base58-encoded pubkey field from a wire payload.
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

/// Map a `solana_client::ClientError` into the right `SessionError`.
///
/// The blanket `From<ClientError>` impl lands every RPC failure in
/// `RpcUnavailable` (5xx), which is wrong for blockhash expiry: that is a
/// client-recoverable condition, the client should re-acquire a challenge
/// with a fresh blockhash. This helper sniffs `BlockhashNotFound`
/// surfaced via the simulated-tx path (returned as `TransactionError`)
/// and routes it to `BlockhashMismatch` (4xx, 409) so the client backs
/// off correctly. Anything else falls through to `RpcUnavailable`.
///
/// Note: many blockhash-expiry signals only show up at simulation time
/// because the Solana RPC API exposes the `TransactionError` only when
/// the cluster has actually attempted the tx. Pre-send "blockhash too old"
/// detection is not reliably exposed by the upstream client; this helper
/// catches the common case (post-send signal) and otherwise treats the
/// failure as transient infra.
fn client_error_to_session_error(e: ClientError) -> SessionError {
    if matches!(e.get_transaction_error(), Some(TransactionError::BlockhashNotFound)) {
        return SessionError::BlockhashMismatch {
            expected: "challenge-bound recent blockhash".to_string(),
            got: "BlockhashNotFound (expired or unknown to the cluster)".to_string(),
        };
    }
    SessionError::from(e)
}

/// Map `verify_open`'s `VerifyError` into a typed `SessionError`,
/// surfacing the offending on-chain field name in the conflict variants.
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
        // Local URL only; no RPC call is made by these tests because we
        // exercise the pure body builder directly.
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
        // External id flows from `OpenChallengeOptions` into the wire
        // body's `externalId` field. The challenge factory stores the
        // same value on the cache `ChallengeRecord`; this test pins the
        // wire path because that is the surface the client sees.
        let method = dummy_method();
        let opts = OpenChallengeOptions {
            description: Some("rent-a-frame".into()),
            external_id: Some("ext-123".into()),
        };
        let request = method.session_request_for_open(&opts, &Hash::new_from_array([0u8; 32]));
        let value = serde_json::to_value(&request).expect("request serializes");
        assert_eq!(value.get("externalId"), Some(&serde_json::json!("ext-123")));

        // Round-trip through Base64UrlJson to confirm the encoded body
        // also carries the field.
        let encoded = Base64UrlJson::from_typed(&request).expect("encode body");
        let decoded: serde_json::Value = encoded.decode_value().expect("decode body");
        assert_eq!(
            decoded.get("externalId"),
            Some(&serde_json::json!("ext-123"))
        );
    }

    #[tokio::test]
    async fn open_commits_challenge_before_confirm_poll() {
        // Pins the post-broadcast ordering inside `process_open`:
        // once `send_transaction` returns Ok, the cache is moved to
        // Consumed BEFORE the confirm poll. A confirm-poll timeout
        // later returning `OpenTxUnconfirmed` must therefore leave the
        // record in Consumed state, not Available; otherwise the
        // client could re-broadcast a duplicate tx for the same
        // intent if the original lands a moment after the timeout.
        //
        // We exercise the cache state machine directly here because
        // driving the surrounding broadcast + verify + persist surface
        // needs a live cluster. The live path is covered by the L1
        // oracle; this test locks the invariant `process_open`
        // depends on.
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

        // Reserve, then commit, mirroring the order `process_open`
        // performs once `send_transaction` returns Ok.
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

        // A second reservation under the same id must not succeed,
        // regardless of whether the original tx ultimately confirmed.
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
        // `serde(skip_serializing_if = "Option::is_none")` on
        // `SessionRequest::external_id` means an absent option must
        // omit the JSON key entirely, not render it as `null`.
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
