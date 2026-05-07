//! Pre-buffered HTTP response after a successful session payment.
//!
//! The high-level fetch flow drains the `reqwest::Response` body into
//! `bytes::Bytes` and parses the `Payment-Receipt` header before
//! handing back this struct. That makes `text()` / `json::<T>()`
//! sync, repeatable, and decoupled from the underlying transport.

use std::str::Utf8Error;

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use solana_pubkey::Pubkey;

use crate::client::session::SessionReceipt;

/// HTTP response with the body pre-drained, plus the typed receipt and
/// the channel id that paid for it. Cheap to clone-by-reference; the
/// body itself is an `Arc`-backed `Bytes` so accessor calls don't copy.
#[derive(Debug)]
pub struct PaidResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    channel_id: Pubkey,
    receipt: SessionReceipt,
}

impl PaidResponse {
    /// Compose a `PaidResponse` from a fully-buffered HTTP body and a
    /// parsed receipt. The high-level fetch builds this after draining
    /// the response and decoding the `Payment-Receipt` header.
    pub fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        channel_id: Pubkey,
        receipt: SessionReceipt,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            channel_id,
            receipt,
        }
    }

    /// Underlying HTTP status returned by the server.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// All response headers, including `Payment-Receipt`.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Raw response body. Call repeatedly without consuming the response.
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// Channel id whose voucher paid for this request.
    pub fn channel_id(&self) -> Pubkey {
        self.channel_id
    }

    /// Cumulative the server acknowledged after this request landed.
    /// `None` when the receipt was a non-voucher acknowledgement
    /// (lock-settled close, charge success), where the server omits the
    /// field entirely.
    pub fn accepted_cumulative(&self) -> Option<u64> {
        self.receipt.accepted_cumulative
    }

    /// Amount consumed by this single request
    /// (`current.cumulative - prior.cumulative`). `None` for the same
    /// reasons as [`Self::accepted_cumulative`].
    pub fn spent(&self) -> Option<u64> {
        self.receipt.spent
    }

    /// Typed view of the decoded `Payment-Receipt` header.
    pub fn receipt(&self) -> &SessionReceipt {
        &self.receipt
    }

    /// Decode the response body as UTF-8.
    pub fn text(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Decode the response body as JSON into a typed value.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_receipt(reference: &str) -> SessionReceipt {
        SessionReceipt {
            method: "solana".into(),
            intent: "session".into(),
            reference: reference.into(),
            status: "success".into(),
            accepted_cumulative: Some(0),
            spent: Some(0),
            tx_hash: None,
            extras: serde_json::Map::new(),
        }
    }

    fn make_response(body: &'static [u8]) -> PaidResponse {
        let channel_id = Pubkey::new_unique();
        let receipt = empty_receipt(&bs58::encode(channel_id.to_bytes()).into_string());
        response_with(channel_id, receipt, Bytes::from_static(body))
    }

    fn response_with(channel_id: Pubkey, receipt: SessionReceipt, body: Bytes) -> PaidResponse {
        PaidResponse::new(StatusCode::OK, HeaderMap::new(), body, channel_id, receipt)
    }

    #[test]
    fn paid_response_text_and_json_are_idempotent() {
        let resp = make_response(br#"{"hello":"world"}"#);

        let first_text = resp.text().expect("first text");
        let second_text = resp.text().expect("second text");
        assert_eq!(first_text, r#"{"hello":"world"}"#);
        assert_eq!(first_text, second_text);

        let first_json: serde_json::Value = resp.json().expect("first json");
        let second_json: serde_json::Value = resp.json().expect("second json");
        assert_eq!(first_json, second_json);
        assert_eq!(
            first_json,
            serde_json::json!({ "hello": "world" }),
            "json shape preserved"
        );
    }

    #[test]
    fn paid_response_amount_accessors_forward_to_receipt() {
        // Voucher receipt: amount fields populated.
        let channel_id = Pubkey::new_unique();
        let mut voucher_receipt =
            empty_receipt(&bs58::encode(channel_id.to_bytes()).into_string());
        voucher_receipt.accepted_cumulative = Some(750);
        voucher_receipt.spent = Some(250);
        let resp = response_with(channel_id, voucher_receipt, Bytes::from_static(b""));
        assert_eq!(resp.accepted_cumulative(), Some(750));
        assert_eq!(resp.spent(), Some(250));

        // Close-style receipt: amounts absent.
        let channel_id = Pubkey::new_unique();
        let mut close_receipt =
            empty_receipt(&bs58::encode(channel_id.to_bytes()).into_string());
        close_receipt.accepted_cumulative = None;
        close_receipt.spent = None;
        let resp = response_with(channel_id, close_receipt, Bytes::from_static(b""));
        assert!(resp.accepted_cumulative().is_none());
        assert!(resp.spent().is_none());
    }

    #[test]
    fn paid_response_json_round_trips_typed_struct() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Body {
            foo: i32,
            bar: String,
        }

        let resp = make_response(br#"{"foo":42,"bar":"baz"}"#);
        let body: Body = resp.json().expect("typed json");
        assert_eq!(
            body,
            Body {
                foo: 42,
                bar: "baz".into(),
            }
        );
    }
}
