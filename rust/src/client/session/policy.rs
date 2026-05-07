//! Caller-side policy knobs and 402-response challenge selection for the
//! session intent.
//!
//! [`ClientPolicy`] holds the caps callers set before issuing a fetch.
//! [`ClientPolicy::apply_server_caps`] reconciles those caps with the
//! server-advertised values on a 402 challenge, and
//! [`select_session_challenge`] picks the session challenge out of a
//! multi-challenge response.

use std::time::Duration;

use crate::error::ClientError;
use crate::protocol::core::PaymentChallenge;
use crate::protocol::intents::session::MethodDetails;

/// Caller-side policy knobs for the high-level fetch loop.
///
/// `auto_open` is on by default so the first session request opens a
/// channel without manual setup; `auto_topup` is off so callers opt in
/// before the SDK tops up a drained channel. `max_deposit` caps any
/// single open or topup; `max_cumulative` caps the running cumulative on
/// signed vouchers; `min_voucher_delta` is the floor for per-voucher
/// increments the SDK is willing to sign.
#[derive(Clone, Debug)]
pub struct ClientPolicy {
    /// If a 402 says "no channel yet", open one rather than returning an
    /// error.
    pub auto_open: bool,
    /// If a 402 says "channel exhausted", top it up rather than returning
    /// an error.
    pub auto_topup: bool,
    /// Max units the SDK will fund on any single open or topup.
    pub max_deposit: u64,
    /// Cap on the running cumulative the SDK will sign on a voucher.
    pub max_cumulative: u64,
    /// Floor on per-voucher delta the SDK will sign. A server advertising
    /// a larger `min_voucher_delta` demands bigger increments than the
    /// client is willing to issue, so [`apply_server_caps`] rejects it.
    ///
    /// [`apply_server_caps`]: ClientPolicy::apply_server_caps
    pub min_voucher_delta: u64,
    /// Max voucher TTL the SDK will accept from a server. Servers that
    /// advertise longer TTLs hold vouchers in flight longer than the
    /// client wants to be on the hook for.
    pub voucher_ttl_seconds: u32,
    /// Wall-clock budget for the open round-trip.
    pub open_timeout: Duration,
    /// Wall-clock budget for the topup round-trip.
    pub topup_timeout: Duration,
}

impl Default for ClientPolicy {
    fn default() -> Self {
        Self {
            auto_open: true,
            auto_topup: false,
            // 100 USDC at 6 decimals; tune per use case.
            max_deposit: 100_000_000,
            // Trust the on-voucher cumulative ceiling at the protocol layer
            // unless callers set a tighter cap.
            max_cumulative: u64::MAX,
            // Strict-greater monotonicity at minimum.
            min_voucher_delta: 1,
            voucher_ttl_seconds: 60,
            open_timeout: Duration::from_secs(30),
            topup_timeout: Duration::from_secs(30),
        }
    }
}

/// The policy values actually used after server caps are applied.
///
/// Each field is the server-advertised value when present and within client
/// caps, otherwise the client default. Returned by
/// [`ClientPolicy::apply_server_caps`].
#[derive(Clone, Debug)]
pub struct ResolvedPolicy {
    /// The voucher TTL the SDK will respect for this channel.
    pub voucher_ttl_seconds: u32,
    /// Resolved per-voucher minimum delta. Zero means the server disabled
    /// the gate; only the strict-greater monotonicity check on
    /// `signed_cumulative` still applies.
    pub min_voucher_delta: u64,
}

impl ClientPolicy {
    /// Resolve the effective policy for a server's advertised values.
    ///
    /// The server's `voucher_ttl_seconds` and `min_voucher_delta` win when
    /// they fit inside the client's caps; otherwise the client's value
    /// stands. A server value that exceeds the cap returns
    /// [`ClientError::ServerPolicyTooLax`].
    ///
    /// Both caps read as upper bounds on what the client will tolerate:
    /// `voucher_ttl_seconds` is the longest TTL the client accepts, and
    /// `min_voucher_delta` is the largest per-voucher floor the client
    /// will sign for. Server values above either reject.
    pub fn apply_server_caps(
        &self,
        server: &MethodDetails,
    ) -> Result<ResolvedPolicy, ClientError> {
        let voucher_ttl_seconds = match server.ttl_seconds {
            Some(s) if s > self.voucher_ttl_seconds => {
                return Err(ClientError::ServerPolicyTooLax {
                    field: "voucher_ttl_seconds",
                    server: s.into(),
                    client_limit: self.voucher_ttl_seconds.into(),
                });
            }
            Some(s) => s,
            None => self.voucher_ttl_seconds,
        };
        if voucher_ttl_seconds == 0 {
            return Err(ClientError::ProtocolViolation(
                "voucher_ttl_seconds resolved to 0; vouchers would expire immediately".into(),
            ));
        }

        let min_voucher_delta = match server.min_voucher_delta.as_deref() {
            Some(raw) => {
                let parsed: u64 = raw.parse().map_err(|e| {
                    ClientError::ProtocolViolation(format!(
                        "min_voucher_delta is not a u64: {raw}: {e}"
                    ))
                })?;
                if parsed > self.min_voucher_delta {
                    return Err(ClientError::ServerPolicyTooLax {
                        field: "min_voucher_delta",
                        server: parsed,
                        client_limit: self.min_voucher_delta,
                    });
                }
                parsed
            }
            None => self.min_voucher_delta,
        };

        Ok(ResolvedPolicy {
            voucher_ttl_seconds,
            min_voucher_delta,
        })
    }
}

/// Pick the first session-method challenge from a 402 response.
///
/// Returns the first challenge with `method == "solana"` and
/// `intent == "session"`, or `None` when none is present (e.g. a server
/// that only advertises charge challenges). `MethodName` and `IntentName`
/// already normalize to lowercase on construction, so the literal
/// comparison is case-insensitive.
pub fn select_session_challenge(challenges: &[PaymentChallenge]) -> Option<&PaymentChallenge> {
    challenges
        .iter()
        .find(|c| c.method.as_str() == "solana" && c.intent.as_str() == "session")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::types::Base64UrlJson;

    fn method_details_with(
        ttl: Option<u32>,
        min_delta: Option<&str>,
    ) -> MethodDetails {
        MethodDetails {
            network: None,
            channel_program: "11111111111111111111111111111111".to_string(),
            channel_id: None,
            decimals: None,
            token_program: None,
            fee_payer: None,
            fee_payer_key: None,
            recent_blockhash: None,
            min_voucher_delta: min_delta.map(str::to_string),
            ttl_seconds: ttl,
            grace_period_seconds: None,
            distribution_splits: Vec::new(),
            minimum_deposit: "0".to_string(),
        }
    }

    fn challenge(method: &str, intent: &str) -> PaymentChallenge {
        PaymentChallenge::new(
            "id",
            "realm",
            method,
            intent,
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        )
    }

    #[test]
    fn apply_server_caps_clamps_within_cap() {
        let policy = ClientPolicy {
            voucher_ttl_seconds: 60,
            min_voucher_delta: 100,
            ..ClientPolicy::default()
        };
        let server = method_details_with(Some(30), Some("50"));
        let resolved = policy.apply_server_caps(&server).expect("within caps");
        assert_eq!(resolved.voucher_ttl_seconds, 30);
        assert_eq!(resolved.min_voucher_delta, 50);
    }

    #[test]
    fn apply_server_caps_rejects_above_cap_with_server_policy_too_lax() {
        let policy = ClientPolicy {
            voucher_ttl_seconds: 60,
            min_voucher_delta: 100,
            ..ClientPolicy::default()
        };
        let server = method_details_with(Some(120), None);
        match policy.apply_server_caps(&server) {
            Err(ClientError::ServerPolicyTooLax {
                field,
                server,
                client_limit,
            }) => {
                assert_eq!(field, "voucher_ttl_seconds");
                assert_eq!(server, 120);
                assert_eq!(client_limit, 60);
            }
            other => panic!("expected ServerPolicyTooLax, got {other:?}"),
        }
    }

    #[test]
    fn apply_server_caps_rejects_min_delta_above_cap() {
        let policy = ClientPolicy {
            min_voucher_delta: 1,
            ..ClientPolicy::default()
        };
        let server = method_details_with(None, Some("1000"));
        match policy.apply_server_caps(&server) {
            Err(ClientError::ServerPolicyTooLax {
                field,
                server,
                client_limit,
            }) => {
                assert_eq!(field, "min_voucher_delta");
                assert_eq!(server, 1000);
                assert_eq!(client_limit, 1);
            }
            other => panic!("expected ServerPolicyTooLax, got {other:?}"),
        }
    }

    #[test]
    fn apply_server_caps_falls_back_to_client_when_server_silent() {
        let policy = ClientPolicy {
            voucher_ttl_seconds: 45,
            min_voucher_delta: 7,
            ..ClientPolicy::default()
        };
        let server = method_details_with(None, None);
        let resolved = policy.apply_server_caps(&server).expect("client defaults");
        assert_eq!(resolved.voucher_ttl_seconds, 45);
        assert_eq!(resolved.min_voucher_delta, 7);
    }

    #[test]
    fn apply_server_caps_rejects_zero_ttl_with_protocol_violation() {
        let policy = ClientPolicy::default();
        let server = method_details_with(Some(0), None);
        match policy.apply_server_caps(&server) {
            Err(ClientError::ProtocolViolation(msg)) => {
                assert!(msg.contains("voucher_ttl_seconds"), "msg: {msg}");
            }
            other => panic!("expected ProtocolViolation, got {other:?}"),
        }
    }

    #[test]
    fn apply_server_caps_rejects_unparseable_min_delta() {
        let policy = ClientPolicy::default();
        let server = method_details_with(None, Some("not-a-number"));
        match policy.apply_server_caps(&server) {
            Err(ClientError::ProtocolViolation(msg)) => {
                assert!(msg.contains("min_voucher_delta"), "msg: {msg}");
            }
            other => panic!("expected ProtocolViolation, got {other:?}"),
        }
    }

    #[test]
    fn select_session_challenge_picks_solana_session() {
        let challenges = vec![
            challenge("solana", "charge"),
            challenge("solana", "session"),
        ];
        let picked = select_session_challenge(&challenges).expect("session present");
        assert_eq!(picked.method.as_str(), "solana");
        assert_eq!(picked.intent.as_str(), "session");
    }

    #[test]
    fn select_session_challenge_returns_none_when_only_charge_challenges() {
        let challenges = vec![
            challenge("solana", "charge"),
            challenge("bitcoin", "charge"),
        ];
        assert!(select_session_challenge(&challenges).is_none());
    }

    #[test]
    fn select_session_challenge_skips_non_solana_session() {
        // A "bitcoin/session" challenge should not be picked by the Solana
        // session selector.
        let challenges = vec![challenge("bitcoin", "session"), challenge("solana", "session")];
        let picked = select_session_challenge(&challenges).expect("solana session present");
        assert_eq!(picked.method.as_str(), "solana");
    }
}
