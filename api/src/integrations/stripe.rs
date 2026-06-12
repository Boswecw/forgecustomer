//! Stripe integration. The security-critical webhook signature verification, event
//! extraction, and Checkout Session creation live here; durable subscription projection is
//! applied by the commerce repository after signature verification.

use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::domain::subscription::{normalize_stripe_status, SubscriptionStatus};

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

#[derive(Debug, thiserror::Error)]
pub enum CheckoutError {
    #[error("Stripe secret key is not configured")]
    NotConfigured,
    #[error("Stripe transport error: {0}")]
    Transport(String),
    #[error("Stripe Checkout returned status {0}")]
    ApiStatus(u16),
    #[error("Stripe Checkout response did not include a session id")]
    MissingSessionId,
    #[error("Stripe Checkout response did not include a checkout URL")]
    MissingCheckoutUrl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSessionRequest {
    pub price_id: String,
    pub customer_id: String,
    pub plan_version_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct StripeCheckoutSessionResponse {
    id: Option<String>,
    url: Option<String>,
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

pub fn build_checkout_session_form(request: &CheckoutSessionRequest) -> Vec<(String, String)> {
    vec![
        ("mode".into(), "subscription".into()),
        ("success_url".into(), request.success_url.clone()),
        ("cancel_url".into(), request.cancel_url.clone()),
        ("line_items[0][price]".into(), request.price_id.clone()),
        ("line_items[0][quantity]".into(), "1".into()),
        ("client_reference_id".into(), request.customer_id.clone()),
        (
            "metadata[forgecustomer_customer_id]".into(),
            request.customer_id.clone(),
        ),
        (
            "metadata[plan_version_id]".into(),
            request.plan_version_id.clone(),
        ),
        (
            "subscription_data[metadata][forgecustomer_customer_id]".into(),
            request.customer_id.clone(),
        ),
        (
            "subscription_data[metadata][plan_version_id]".into(),
            request.plan_version_id.clone(),
        ),
        ("allow_promotion_codes".into(), "true".into()),
    ]
}

pub async fn create_checkout_session(
    http: &reqwest::Client,
    api_base: &str,
    secret_key: &str,
    request: &CheckoutSessionRequest,
    idempotency_key: Option<&str>,
) -> Result<CheckoutSession, CheckoutError> {
    if secret_key.is_empty() {
        return Err(CheckoutError::NotConfigured);
    }

    let form = build_checkout_session_form(request);
    let mut builder = http
        .post(format!(
            "{}/v1/checkout/sessions",
            api_base.trim_end_matches('/')
        ))
        .bearer_auth(secret_key)
        .form(&form);

    if let Some(key) = idempotency_key.filter(|key| !key.trim().is_empty()) {
        builder = builder.header("Idempotency-Key", key.trim());
    }

    let response = builder
        .send()
        .await
        .map_err(|error| CheckoutError::Transport(error.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(CheckoutError::ApiStatus(status.as_u16()));
    }

    let session: StripeCheckoutSessionResponse = response
        .json()
        .await
        .map_err(|error| CheckoutError::Transport(error.to_string()))?;
    Ok(CheckoutSession {
        id: session.id.ok_or(CheckoutError::MissingSessionId)?,
        url: session.url.ok_or(CheckoutError::MissingCheckoutUrl)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingPortalSession {
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct StripeBillingPortalResponse {
    url: Option<String>,
}

/// Create a Stripe Billing Customer Portal session for an existing Stripe customer.
///
/// The portal is Stripe-hosted and lets the customer cancel, switch plans, or update their
/// payment method. Any resulting change is applied to ForgeCustomer truth only via the verified
/// webhook path — this call mints an ephemeral session and persists nothing. Reuses
/// `CheckoutError` so HTTP mapping stays consistent with checkout (`stripe_checkout_error`).
pub async fn create_billing_portal_session(
    http: &reqwest::Client,
    api_base: &str,
    secret_key: &str,
    stripe_customer_id: &str,
    return_url: &str,
    idempotency_key: Option<&str>,
) -> Result<BillingPortalSession, CheckoutError> {
    if secret_key.is_empty() {
        return Err(CheckoutError::NotConfigured);
    }

    let form = vec![
        ("customer".to_string(), stripe_customer_id.to_string()),
        ("return_url".to_string(), return_url.to_string()),
    ];
    let mut builder = http
        .post(format!(
            "{}/v1/billing_portal/sessions",
            api_base.trim_end_matches('/')
        ))
        .bearer_auth(secret_key)
        .form(&form);

    if let Some(key) = idempotency_key.filter(|key| !key.trim().is_empty()) {
        builder = builder.header("Idempotency-Key", key.trim());
    }

    let response = builder
        .send()
        .await
        .map_err(|error| CheckoutError::Transport(error.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(CheckoutError::ApiStatus(status.as_u16()));
    }

    let session: StripeBillingPortalResponse = response
        .json()
        .await
        .map_err(|error| CheckoutError::Transport(error.to_string()))?;
    Ok(BillingPortalSession {
        url: session.url.ok_or(CheckoutError::MissingCheckoutUrl)?,
    })
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
    pub object: Value,
    pub payload_summary: Value,
    pub receipt_status: StripeWebhookReceiptStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeCheckoutCompleted {
    pub stripe_checkout_session_id: String,
    pub customer_id: Option<Uuid>,
    pub plan_version_id: Option<Uuid>,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeSubscriptionChange {
    pub stripe_subscription_id: String,
    pub stripe_customer_id: Option<String>,
    pub customer_id: Option<Uuid>,
    pub plan_version_id: Option<Uuid>,
    pub stripe_price_id: Option<String>,
    pub status: SubscriptionStatus,
    pub current_period_start: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeInvoiceChange {
    pub stripe_invoice_id: String,
    pub stripe_subscription_id: String,
    pub status: SubscriptionStatus,
    pub invoice_status: String,
    pub amount_due_cents: Option<i64>,
    pub currency: Option<String>,
}

/// Events ForgeCustomer understands at receipt time. Supported events are transactionally
/// applied by the commerce repository; unsupported events are acknowledged and ignored.
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

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key)?.as_bool()
}

fn integer_field(value: &Value, key: &str) -> Option<i64> {
    value.get(key)?.as_i64()
}

fn uuid_field(value: &Value, key: &str) -> Option<Uuid> {
    string_field(value, key).and_then(|value| Uuid::parse_str(&value).ok())
}

fn metadata_string(value: &Value, key: &str) -> Option<String> {
    value.get("metadata").and_then(|v| string_field(v, key))
}

fn metadata_uuid(value: &Value, key: &str) -> Option<Uuid> {
    metadata_string(value, key).and_then(|value| Uuid::parse_str(&value).ok())
}

fn unix_seconds(value: Option<i64>) -> Option<DateTime<Utc>> {
    Utc.timestamp_opt(value?, 0).single()
}

fn subscription_price_id(value: &Value) -> Option<String> {
    let first_item = value.get("items")?.get("data")?.as_array()?.first()?;
    first_item
        .get("price")
        .and_then(|price| string_field(price, "id"))
        .or_else(|| {
            first_item
                .get("plan")
                .and_then(|plan| string_field(plan, "id"))
        })
}

/// Extract a normalized subscription change from a Stripe subscription object — the same
/// shape arrives in webhook `data.object` payloads and `GET /v1/subscriptions/{id}`
/// responses, so webhook processing and admin resync share this extraction.
fn subscription_change_from_object(
    object: &Value,
    default_status: &str,
) -> Option<StripeSubscriptionChange> {
    let raw_status = string_field(object, "status").unwrap_or_else(|| default_status.to_string());
    Some(StripeSubscriptionChange {
        stripe_subscription_id: string_field(object, "id")?,
        stripe_customer_id: string_field(object, "customer"),
        customer_id: metadata_uuid(object, "forgecustomer_customer_id"),
        plan_version_id: metadata_uuid(object, "plan_version_id"),
        stripe_price_id: subscription_price_id(object),
        status: normalize_stripe_status(&raw_status),
        current_period_start: unix_seconds(integer_field(object, "current_period_start")),
        current_period_end: unix_seconds(integer_field(object, "current_period_end")),
        cancel_at_period_end: bool_field(object, "cancel_at_period_end").unwrap_or(false),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum SubscriptionFetchError {
    #[error("Stripe secret key is not configured")]
    NotConfigured,
    #[error("Stripe transport error: {0}")]
    Transport(String),
    #[error("Stripe subscriptions API returned status {0}")]
    ApiStatus(u16),
    #[error("Stripe subscription response was missing required fields")]
    MalformedResponse,
}

/// Fetch current subscription truth from Stripe (admin resync path). Unknown statuses
/// fail closed to `incomplete` via the shared normalization.
pub async fn fetch_subscription(
    http: &reqwest::Client,
    api_base: &str,
    secret_key: &str,
    stripe_subscription_id: &str,
) -> Result<StripeSubscriptionChange, SubscriptionFetchError> {
    if secret_key.is_empty() {
        return Err(SubscriptionFetchError::NotConfigured);
    }

    let response = http
        .get(format!(
            "{}/v1/subscriptions/{stripe_subscription_id}",
            api_base.trim_end_matches('/')
        ))
        .bearer_auth(secret_key)
        .send()
        .await
        .map_err(|error| SubscriptionFetchError::Transport(error.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(SubscriptionFetchError::ApiStatus(status.as_u16()));
    }

    let object: Value = response
        .json()
        .await
        .map_err(|error| SubscriptionFetchError::Transport(error.to_string()))?;
    subscription_change_from_object(&object, "incomplete")
        .ok_or(SubscriptionFetchError::MalformedResponse)
}

fn invoice_status(event_type: &str, object: &Value) -> String {
    let raw = string_field(object, "status").unwrap_or_else(|| match event_type {
        "invoice.paid" => "paid".to_string(),
        _ => "open".to_string(),
    });
    match raw.as_str() {
        "paid" | "open" | "void" | "uncollectible" | "draft" => raw,
        _ if event_type == "invoice.paid" => "paid".to_string(),
        _ => "open".to_string(),
    }
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
        object,
        payload_summary,
        receipt_status,
    })
}

impl ParsedStripeEvent {
    pub fn created_at(&self) -> Option<DateTime<Utc>> {
        unix_seconds(self.created)
    }

    pub fn checkout_completed(&self) -> Option<StripeCheckoutCompleted> {
        if self.event_type != "checkout.session.completed" {
            return None;
        }
        Some(StripeCheckoutCompleted {
            stripe_checkout_session_id: string_field(&self.object, "id")?,
            customer_id: metadata_uuid(&self.object, "forgecustomer_customer_id")
                .or_else(|| uuid_field(&self.object, "client_reference_id")),
            plan_version_id: metadata_uuid(&self.object, "plan_version_id"),
            stripe_customer_id: string_field(&self.object, "customer"),
            stripe_subscription_id: string_field(&self.object, "subscription"),
        })
    }

    pub fn subscription_change(&self) -> Option<StripeSubscriptionChange> {
        if !matches!(
            self.event_type.as_str(),
            "customer.subscription.created"
                | "customer.subscription.updated"
                | "customer.subscription.deleted"
        ) {
            return None;
        }
        let default_status = if self.event_type == "customer.subscription.deleted" {
            "canceled"
        } else {
            "incomplete"
        };
        subscription_change_from_object(&self.object, default_status)
    }

    pub fn invoice_change(&self) -> Option<StripeInvoiceChange> {
        if !matches!(
            self.event_type.as_str(),
            "invoice.paid" | "invoice.payment_failed"
        ) {
            return None;
        }
        Some(StripeInvoiceChange {
            stripe_invoice_id: string_field(&self.object, "id")?,
            stripe_subscription_id: string_field(&self.object, "subscription")?,
            status: if self.event_type == "invoice.paid" {
                SubscriptionStatus::Active
            } else {
                SubscriptionStatus::PastDue
            },
            invoice_status: invoice_status(&self.event_type, &self.object),
            amount_due_cents: integer_field(&self.object, "amount_due"),
            currency: string_field(&self.object, "currency"),
        })
    }
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
    fn checkout_session_form_uses_server_side_subscription_mode() {
        let form = build_checkout_session_form(&CheckoutSessionRequest {
            price_id: "price_123".into(),
            customer_id: "cust_uuid".into(),
            plan_version_id: "plan_version_uuid".into(),
            success_url: "https://example.com/success".into(),
            cancel_url: "https://example.com/cancel".into(),
        });

        assert!(form.contains(&("mode".into(), "subscription".into())));
        assert!(form.contains(&("line_items[0][price]".into(), "price_123".into())));
        assert!(form.contains(&("client_reference_id".into(), "cust_uuid".into())));
        assert!(form.contains(&(
            "subscription_data[metadata][plan_version_id]".into(),
            "plan_version_uuid".into()
        )));
    }

    #[tokio::test]
    async fn billing_portal_session_requires_secret_key() {
        // Empty secret fails closed before any network call (mirrors checkout).
        let err = create_billing_portal_session(
            &reqwest::Client::new(),
            "https://api.stripe.test",
            "",
            "cus_123",
            "https://example.com/account.html",
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CheckoutError::NotConfigured));
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
    fn extracts_checkout_completion_references() {
        let customer_id = Uuid::new_v4();
        let plan_version_id = Uuid::new_v4();
        let payload = format!(
            r#"{{
              "id":"evt_checkout",
              "type":"checkout.session.completed",
              "created":1700000000,
              "data":{{"object":{{
                "id":"cs_test_1",
                "object":"checkout.session",
                "customer":"cus_123",
                "subscription":"sub_123",
                "metadata":{{
                  "forgecustomer_customer_id":"{customer_id}",
                  "plan_version_id":"{plan_version_id}"
                }}
              }}}}
            }}"#
        );
        let parsed = parse_event(payload.as_bytes()).expect("event");
        let checkout = parsed.checkout_completed().expect("checkout completion");

        assert_eq!(checkout.stripe_checkout_session_id, "cs_test_1");
        assert_eq!(checkout.customer_id, Some(customer_id));
        assert_eq!(checkout.plan_version_id, Some(plan_version_id));
        assert_eq!(checkout.stripe_customer_id.as_deref(), Some("cus_123"));
        assert_eq!(checkout.stripe_subscription_id.as_deref(), Some("sub_123"));
    }

    #[test]
    fn extracts_subscription_change_with_plan_metadata_and_price() {
        let customer_id = Uuid::new_v4();
        let plan_version_id = Uuid::new_v4();
        let payload = format!(
            r#"{{
              "id":"evt_sub",
              "type":"customer.subscription.updated",
              "created":1700000000,
              "data":{{"object":{{
                "id":"sub_123",
                "object":"subscription",
                "customer":"cus_123",
                "status":"active",
                "current_period_start":1700000000,
                "current_period_end":1702592000,
                "cancel_at_period_end":false,
                "metadata":{{
                  "forgecustomer_customer_id":"{customer_id}",
                  "plan_version_id":"{plan_version_id}"
                }},
                "items":{{"data":[{{"price":{{"id":"price_123"}}}}]}}
              }}}}
            }}"#
        );
        let parsed = parse_event(payload.as_bytes()).expect("event");
        let change = parsed.subscription_change().expect("subscription change");

        assert_eq!(change.stripe_subscription_id, "sub_123");
        assert_eq!(change.customer_id, Some(customer_id));
        assert_eq!(change.plan_version_id, Some(plan_version_id));
        assert_eq!(change.stripe_price_id.as_deref(), Some("price_123"));
        assert_eq!(change.status, SubscriptionStatus::Active);
        assert!(change.current_period_end.is_some());
    }

    #[test]
    fn extracts_invoice_payment_failure_as_past_due() {
        let parsed = parse_event(
            br#"{
              "id":"evt_invoice",
              "type":"invoice.payment_failed",
              "created":1700000000,
              "data":{"object":{
                "id":"in_123",
                "object":"invoice",
                "subscription":"sub_123",
                "status":"open",
                "amount_due":2999,
                "currency":"usd"
              }}
            }"#,
        )
        .expect("event");
        let invoice = parsed.invoice_change().expect("invoice change");

        assert_eq!(invoice.stripe_invoice_id, "in_123");
        assert_eq!(invoice.stripe_subscription_id, "sub_123");
        assert_eq!(invoice.status, SubscriptionStatus::PastDue);
        assert_eq!(invoice.invoice_status, "open");
        assert_eq!(invoice.amount_due_cents, Some(2999));
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
