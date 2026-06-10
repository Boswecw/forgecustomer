//! Stripe integration. The security-critical webhook signature verification and minimal
//! event-envelope parsing live here; Checkout/session creation and subscription state
//! application are separate service/repository work.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum WebhookError {
    #[error("malformed Stripe-Signature header")]
    MalformedHeader,
    #[error("signature timestamp outside tolerance")]
    TimestampOutOfTolerance,
    #[error("no matching signature")]
    NoMatch,
    #[error("webhook secret not configured")]
    NotConfigured,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum StripeEventError {
    #[error("malformed Stripe event payload")]
    MalformedPayload,
    #[error("missing Stripe event id")]
    MissingEventId,
    #[error("missing Stripe event type")]
    MissingEventType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StripeWebhookReceiptStatus {
    Received,
    Ignored,
}

impl StripeWebhookReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Ignored => "ignored",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedStripeEvent {
    pub id: String,
    pub event_type: String,
    pub created: Option<i64>,
    pub object_id: Option<String>,
    pub object_type: Option<String>,
    pub payload_summary: Value,
    pub receipt_status: StripeWebhookReceiptStatus,
}

/// Events ForgeCustomer understands at receipt time. State application for these events
/// lands in the follow-up commerce slice; unsupported events are acknowledged and ignored.
pub fn is_supported_webhook_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "checkout.session.completed"
            | "customer.subscription.created"
            | "customer.subscription.updated"
            | "customer.subscription.deleted"
            | "invoice.paid"
            | "invoice.payment_failed"
    )
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_string)
}

/// Parse a verified Stripe event payload into a minimal, non-PII summary.
pub fn parse_event(payload: &[u8]) -> Result<ParsedStripeEvent, StripeEventError> {
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| StripeEventError::MalformedPayload)?;
    let id = string_field(&value, "id").ok_or(StripeEventError::MissingEventId)?;
    let event_type = string_field(&value, "type").ok_or(StripeEventError::MissingEventType)?;
    let created = value.get("created").and_then(Value::as_i64);
    let object = value
        .get("data")
        .and_then(|v| v.get("object"))
        .cloned()
        .unwrap_or(Value::Null);
    let object_id = string_field(&object, "id");
    let object_type = string_field(&object, "object");
    let receipt_status = if is_supported_webhook_event(&event_type) {
        StripeWebhookReceiptStatus::Received
    } else {
        StripeWebhookReceiptStatus::Ignored
    };

    let payload_summary = json!({
        "event_id": id,
        "event_type": event_type,
        "created": created,
        "object_id": object_id,
        "object_type": object_type,
    });

    Ok(ParsedStripeEvent {
        id,
        event_type,
        created,
        object_id,
        object_type,
        payload_summary,
        receipt_status,
    })
}

/// Verify a Stripe webhook signature.
///
/// The `Stripe-Signature` header looks like `t=<ts>,v1=<sig>,v1=<sig2>`. We compute
/// `HMAC_SHA256(secret, "<ts>.<payload>")` and compare against each provided `v1` value in
/// **constant time**. `tolerance_secs` bounds replay by timestamp skew.
pub fn verify_signature(
    payload: &[u8],
    sig_header: &str,
    secret: &str,
    now_unix: i64,
    tolerance_secs: i64,
) -> Result<(), WebhookError> {
    if secret.is_empty() {
        return Err(WebhookError::NotConfigured);
    }

    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<Vec<u8>> = Vec::new();

    for part in sig_header.split(',') {
        let (k, v) = part.split_once('=').ok_or(WebhookError::MalformedHeader)?;
        match k.trim() {
            "t" => {
                timestamp = Some(
                    v.trim()
                        .parse()
                        .map_err(|_| WebhookError::MalformedHeader)?,
                );
            }
            "v1" => {
                let bytes = hex::decode(v.trim()).map_err(|_| WebhookError::MalformedHeader)?;
                signatures.push(bytes);
            }
            _ => {} // ignore other schemes (e.g. v0)
        }
    }

    let ts = timestamp.ok_or(WebhookError::MalformedHeader)?;
    if (now_unix - ts).abs() > tolerance_secs {
        return Err(WebhookError::TimestampOutOfTolerance);
    }
    if signatures.is_empty() {
        return Err(WebhookError::MalformedHeader);
    }

    let signed_payload = {
        let mut v = Vec::with_capacity(payload.len() + 16);
        v.extend_from_slice(ts.to_string().as_bytes());
        v.push(b'.');
        v.extend_from_slice(payload);
        v
    };

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| WebhookError::NotConfigured)?;
    mac.update(&signed_payload);
    let expected = mac.finalize().into_bytes();

    // Constant-time compare against each candidate; OR the results to avoid early-out.
    let mut matched = 0u8;
    for sig in &signatures {
        if sig.len() == expected.len() {
            matched |= expected.as_slice().ct_eq(sig).unwrap_u8();
        }
    }
    if matched == 1 {
        Ok(())
    } else {
        Err(WebhookError::NoMatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn sign(payload: &[u8], secret: &str, ts: i64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        let mut data = ts.to_string().into_bytes();
        data.push(b'.');
        data.extend_from_slice(payload);
        mac.update(&data);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn accepts_valid_signature() {
        let payload = br#"{"id":"evt_1"}"#;
        let secret = "whsec_test";
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign(payload, secret, ts));
        assert!(verify_signature(payload, &header, secret, ts + 5, 300).is_ok());
    }

    #[test]
    fn rejects_tampered_payload() {
        let secret = "whsec_test";
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign(br#"{"id":"evt_1"}"#, secret, ts));
        let err = verify_signature(br#"{"id":"evt_2"}"#, &header, secret, ts, 300).unwrap_err();
        assert_eq!(err, WebhookError::NoMatch);
    }

    #[test]
    fn rejects_wrong_secret() {
        let payload = br#"{"id":"evt_1"}"#;
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign(payload, "whsec_a", ts));
        assert_eq!(
            verify_signature(payload, &header, "whsec_b", ts, 300).unwrap_err(),
            WebhookError::NoMatch
        );
    }

    #[test]
    fn rejects_replay_outside_tolerance() {
        let payload = br#"{"id":"evt_1"}"#;
        let secret = "whsec_test";
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign(payload, secret, ts));
        assert_eq!(
            verify_signature(payload, &header, secret, ts + 10_000, 300).unwrap_err(),
            WebhookError::TimestampOutOfTolerance
        );
    }

    #[test]
    fn rejects_malformed_header() {
        assert_eq!(
            verify_signature(b"{}", "garbage", "s", 0, 300).unwrap_err(),
            WebhookError::MalformedHeader
        );
    }

    #[test]
    fn unconfigured_secret_fails_closed() {
        assert_eq!(
            verify_signature(b"{}", "t=1,v1=ab", "", 1, 300).unwrap_err(),
            WebhookError::NotConfigured
        );
    }

    #[test]
    fn parses_supported_event_summary_without_customer_pii() {
        let parsed = parse_event(
            br#"{
              "id":"evt_1",
              "type":"customer.subscription.updated",
              "created":1700000000,
              "data":{"object":{"id":"sub_1","object":"subscription","customer":"cus_secret"}}
            }"#,
        )
        .expect("event");

        assert_eq!(parsed.id, "evt_1");
        assert_eq!(parsed.event_type, "customer.subscription.updated");
        assert_eq!(parsed.object_id.as_deref(), Some("sub_1"));
        assert_eq!(parsed.object_type.as_deref(), Some("subscription"));
        assert_eq!(parsed.receipt_status, StripeWebhookReceiptStatus::Received);
        assert!(parsed.payload_summary.get("customer").is_none());
    }

    #[test]
    fn unsupported_event_is_ignored_but_parseable() {
        let parsed =
            parse_event(br#"{ "id":"evt_2", "type":"payment_intent.created" }"#).expect("event");

        assert_eq!(parsed.receipt_status, StripeWebhookReceiptStatus::Ignored);
    }

    #[test]
    fn malformed_event_fails_closed() {
        assert_eq!(
            parse_event(br#"{ "type":"invoice.paid" }"#).unwrap_err(),
            StripeEventError::MissingEventId
        );
    }
}
