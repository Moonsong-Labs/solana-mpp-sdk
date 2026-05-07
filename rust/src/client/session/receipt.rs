//! Receipt body the client receives from the server.
//!
//! `SessionReceipt` is the typed form of the decoded `Payment-Receipt`
//! header. Wire form is `Payment-Receipt: <base64url(JSON)>`, and
//! `parse_header` does the base64url plus JSON decode in one step.
//! Unknown JSON fields land in `extras` so forward-compat additions
//! don't break older clients.
//!
//! The server emits `acceptedCumulative` and `spent` as decimal
//! strings, matching how on-chain `u64` slots ride through the rest
//! of the protocol. Both fields are also optional because
//! `Receipt::success` leaves them unset on receipts that don't carry
//! voucher metering (lock-settled close, etc.). The
//! `option_string_or_int_u64` adapter accepts string or integer on
//! read and emits string on write, so a round-trip matches what the
//! server actually puts on the wire.

use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::protocol::core::base64url_decode;

/// Cap on the size of an inbound `Payment-Receipt` header. Real receipts
/// are well under a kilobyte; the cap keeps a hostile or buggy server
/// from forcing large allocations through `base64url_decode` and
/// `serde_json::from_slice`.
const MAX_RECEIPT_HEADER_LEN: usize = 64 * 1024;

/// Receipt body returned by the server on a session payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct SessionReceipt {
    /// Method name, e.g. "solana".
    pub method: String,
    /// Intent name, e.g. "session".
    pub intent: String,
    /// Channel id the receipt is bound to, base58. Mirrors the
    /// `reference` field on the wire-form receipt.
    pub reference: String,
    /// Receipt status, e.g. "success" or "error".
    pub status: String,
    /// Cumulative the server acknowledged consuming. Wire form is a
    /// decimal string (`"300"`); the adapter parses it to `u64` on
    /// read and re-emits the string on write. Absent on receipts
    /// without voucher metering (lock-settled close, charge success
    /// without an off-chain meter), so it's `Option<u64>` and skipped
    /// when `None`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_string_or_int_u64"
    )]
    pub accepted_cumulative: Option<u64>,
    /// Amount this request consumed
    /// (`current.cumulative - prior.cumulative`). Same string-on-wire
    /// treatment as `accepted_cumulative`, absent for the same reasons.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_string_or_int_u64"
    )]
    pub spent: Option<u64>,
    /// On-chain transaction signature, attached on close receipts.
    /// Wire field is `txHash` via the struct-level
    /// `rename_all = "camelCase"`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tx_hash: Option<String>,
    /// Additional JSON fields the server emits. Flatten-collected so
    /// forward-compat extensions are readable without bumping this
    /// type.
    #[serde(flatten)]
    pub extras: serde_json::Map<String, serde_json::Value>,
}

/// Serde adapter for optional `u64` fields the server emits as decimal
/// strings. Accepts JSON string or integer on read, always emits string
/// on write so a re-encoded `SessionReceipt` matches the server's
/// bytes. Absent fields parse as `None`; `serialize_none` would yield
/// `null`, but the field-level `skip_serializing_if = "Option::is_none"`
/// keeps `None` values out of the JSON entirely.
mod option_string_or_int_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrInt {
            Str(String),
            Int(u64),
        }
        let opt: Option<StringOrInt> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(StringOrInt::Str(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
            Some(StringOrInt::Int(n)) => Ok(Some(n)),
        }
    }

    pub fn serialize<S: Serializer>(value: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => s.serialize_str(&v.to_string()),
            None => s.serialize_none(),
        }
    }
}

impl SessionReceipt {
    /// Parse a `Payment-Receipt: <base64url(JSON)>` header value. The
    /// caller strips the header name and colon; this takes only the
    /// base64url payload.
    ///
    /// Inputs over `MAX_RECEIPT_HEADER_LEN` are rejected before
    /// touching the base64 decoder.
    pub fn parse_header(value: &str) -> Result<Self, ClientError> {
        if value.len() > MAX_RECEIPT_HEADER_LEN {
            return Err(ClientError::ProtocolViolation(format!(
                "Payment-Receipt header exceeds {MAX_RECEIPT_HEADER_LEN}-byte cap"
            )));
        }
        let bytes = base64url_decode(value).map_err(|e| {
            ClientError::ProtocolViolation(format!("Payment-Receipt base64url decode: {e}"))
        })?;
        let receipt: SessionReceipt = serde_json::from_slice(&bytes).map_err(|e| {
            ClientError::ProtocolViolation(format!("Payment-Receipt JSON decode: {e}"))
        })?;
        Ok(receipt)
    }

    /// Consume the receipt and return the JSON payload. Convenient for
    /// callers that want to read custom `extras` fields without going
    /// through the typed view.
    pub fn into_inner(self) -> serde_json::Value {
        serde_json::to_value(self).expect("SessionReceipt serializes to JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::base64url_encode;

    fn encode_header(body: &serde_json::Value) -> String {
        base64url_encode(&serde_json::to_vec(body).expect("serialize"))
    }

    fn sample_receipt() -> SessionReceipt {
        let extras = serde_json::Map::from_iter([
            ("challengeId".into(), serde_json::Value::String("ch-1".into())),
            (
                "timestamp".into(),
                serde_json::Value::String("2026-05-07T00:00:00Z".into()),
            ),
        ]);
        SessionReceipt {
            method: "solana".into(),
            intent: "session".into(),
            reference: "11111111111111111111111111111111".into(),
            status: "success".into(),
            accepted_cumulative: Some(750),
            spent: Some(250),
            tx_hash: Some("sig-abc".into()),
            extras,
        }
    }

    #[test]
    fn session_receipt_parse_header_round_trips() {
        let original = sample_receipt();
        let json = serde_json::to_vec(&original).expect("serialize");
        let header = base64url_encode(&json);

        let parsed = SessionReceipt::parse_header(&header).expect("parse");

        assert_eq!(parsed.method, original.method);
        assert_eq!(parsed.intent, original.intent);
        assert_eq!(parsed.reference, original.reference);
        assert_eq!(parsed.status, original.status);
        assert_eq!(parsed.accepted_cumulative, original.accepted_cumulative);
        assert_eq!(parsed.spent, original.spent);
        assert_eq!(parsed.tx_hash, original.tx_hash);
        assert_eq!(parsed.extras, original.extras);

        // The two extras keys survived the flatten round-trip.
        assert_eq!(
            parsed.extras.get("challengeId"),
            Some(&serde_json::Value::String("ch-1".into()))
        );
        assert_eq!(
            parsed.extras.get("timestamp"),
            Some(&serde_json::Value::String("2026-05-07T00:00:00Z".into()))
        );
    }

    #[test]
    fn session_receipt_parse_header_rejects_malformed_base64() {
        // Picks chars outside the base64url alphabet so `URL_SAFE_NO_PAD`
        // refuses the input.
        let err = SessionReceipt::parse_header("not-valid-base64-url!@#$")
            .expect_err("malformed base64 should reject");
        match err {
            ClientError::ProtocolViolation(msg) => {
                assert!(
                    msg.contains("base64url"),
                    "expected message to mention base64url, got: {msg}"
                );
            }
            other => panic!("expected ProtocolViolation, got {other:?}"),
        }
    }

    /// String form is what production servers actually emit; the int
    /// form below is the also-accepted fallback.
    #[test]
    fn parse_header_accepts_server_wire_form_with_string_amounts() {
        let header = encode_header(&serde_json::json!({
            "method": "solana",
            "intent": "session",
            "reference": "abc",
            "status": "success",
            "acceptedCumulative": "500",
            "spent": "100",
            "txHash": "sig123",
        }));

        let parsed = SessionReceipt::parse_header(&header).expect("string-form parses");

        assert_eq!(parsed.accepted_cumulative, Some(500));
        assert_eq!(parsed.spent, Some(100));
        assert_eq!(parsed.tx_hash, Some("sig123".into()));
    }

    /// Plain JSON integers also parse, for non-Rust servers (or a
    /// future cleanup) that put numbers directly on the wire.
    #[test]
    fn parse_header_accepts_int_form_for_amounts() {
        let header = encode_header(&serde_json::json!({
            "method": "solana",
            "intent": "session",
            "reference": "abc",
            "status": "success",
            "acceptedCumulative": 500,
            "spent": 100,
            "txHash": "sig123",
        }));

        let parsed = SessionReceipt::parse_header(&header).expect("int-form parses");

        assert_eq!(parsed.accepted_cumulative, Some(500));
        assert_eq!(parsed.spent, Some(100));
        assert_eq!(parsed.tx_hash, Some("sig123".into()));
    }

    /// Lock-settled close and charge-success receipts ship without
    /// the amount fields. Parsing has to yield `None` rather than fail
    /// with a missing-field error.
    #[test]
    fn parse_header_accepts_receipt_without_amounts() {
        let header = encode_header(&serde_json::json!({
            "method": "solana",
            "intent": "session",
            "reference": "abc",
            "status": "success",
            "txHash": "sig123",
        }));

        let parsed = SessionReceipt::parse_header(&header).expect("amount-less receipt parses");

        assert!(
            parsed.accepted_cumulative.is_none(),
            "absent acceptedCumulative deserializes as None"
        );
        assert!(parsed.spent.is_none(), "absent spent deserializes as None");
        assert_eq!(parsed.tx_hash, Some("sig123".into()));
    }

    /// `serde(flatten)` collects only fields the typed view didn't
    /// claim. If the rename mapping breaks, `acceptedCumulative` could
    /// leak into `extras` while still populating the typed slot, so
    /// pin the boundary here.
    #[test]
    fn parse_header_keeps_typed_fields_out_of_extras() {
        let header = encode_header(&serde_json::json!({
            "method": "solana",
            "intent": "session",
            "reference": "abc",
            "status": "success",
            "acceptedCumulative": "500",
            "spent": "100",
            "extra": "foo",
        }));

        let parsed = SessionReceipt::parse_header(&header).expect("parses");

        assert_eq!(parsed.accepted_cumulative, Some(500));
        assert_eq!(parsed.spent, Some(100));
        assert!(
            parsed.extras.get("acceptedCumulative").is_none(),
            "acceptedCumulative must not double-up in extras"
        );
        assert!(
            parsed.extras.get("spent").is_none(),
            "spent must not double-up in extras"
        );
        assert_eq!(
            parsed.extras.get("extra"),
            Some(&serde_json::Value::String("foo".into())),
            "unknown fields land in extras"
        );
    }

    /// Oversized input is rejected before `base64url_decode` and
    /// `serde_json::from_slice` allocate against it.
    #[test]
    fn parse_header_rejects_oversized_input() {
        let oversized = "A".repeat(MAX_RECEIPT_HEADER_LEN + 1);
        let err = SessionReceipt::parse_header(&oversized)
            .expect_err("oversized header should reject");
        match err {
            ClientError::ProtocolViolation(msg) => {
                assert!(
                    msg.contains("cap"),
                    "expected message to mention the cap, got: {msg}"
                );
            }
            other => panic!("expected ProtocolViolation, got {other:?}"),
        }
    }

    /// Re-serializing a receipt has to emit the string form for
    /// `acceptedCumulative` and `spent`, matching what the server puts
    /// on the wire.
    #[test]
    fn serialize_emits_string_form_for_amounts_matching_server() {
        let receipt = SessionReceipt {
            method: "solana".into(),
            intent: "session".into(),
            reference: "abc".into(),
            status: "success".into(),
            accepted_cumulative: Some(500),
            spent: Some(100),
            tx_hash: None,
            extras: serde_json::Map::new(),
        };

        let value = serde_json::to_value(&receipt).expect("serialize");
        let obj = value.as_object().expect("receipt is a JSON object");

        assert_eq!(
            obj.get("acceptedCumulative"),
            Some(&serde_json::Value::String("500".into())),
            "acceptedCumulative must be the string form on the wire"
        );
        assert_eq!(
            obj.get("spent"),
            Some(&serde_json::Value::String("100".into())),
            "spent must be the string form on the wire"
        );
    }

    /// When both amount fields are `None`, the JSON drops them
    /// entirely (no `null` leak), matching what `Receipt::success`
    /// produces. Catches a `skip_serializing_if` flip-off.
    #[test]
    fn serialize_omits_amounts_when_none() {
        let receipt = SessionReceipt {
            method: "solana".into(),
            intent: "session".into(),
            reference: "abc".into(),
            status: "success".into(),
            accepted_cumulative: None,
            spent: None,
            tx_hash: Some("sig-close".into()),
            extras: serde_json::Map::new(),
        };

        let value = serde_json::to_value(&receipt).expect("serialize");
        let obj = value.as_object().expect("receipt is a JSON object");

        assert!(
            obj.get("acceptedCumulative").is_none(),
            "None acceptedCumulative must be omitted, got: {value:?}"
        );
        assert!(
            obj.get("spent").is_none(),
            "None spent must be omitted, got: {value:?}"
        );
    }
}
