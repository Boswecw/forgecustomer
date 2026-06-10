//! Security boundary integration tests exercised through the real router.
//!
//! These cover the mandatory auth checks that do not require a live database:
//!  * unauthenticated requests to protected routes fail closed
//!  * a (valid) customer token cannot satisfy an admin route
//!  * a valid operator token clears admin authentication
//!  * public routes need no token

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

use forgecustomer_api::config::Config;
use forgecustomer_api::routes::build_router;
use forgecustomer_api::state::AppState;

const SUPA_ISS: &str = "https://proj.supabase.co/auth/v1";
const SUPA_AUD: &str = "authenticated";
const SUPA_SECRET: &str = "supabase-secret";
const ADMIN_ISS: &str = "https://operators.local";
const ADMIN_AUD: &str = "forgecustomer-admin";
const ADMIN_SECRET: &str = "admin-secret";
const STRIPE_WEBHOOK_SECRET: &str = "whsec_test";

fn test_state() -> AppState {
    // A throwaway base64 32-byte Ed25519 seed.
    let seed = base64_seed();
    std::env::set_var("DATABASE_URL", "postgres://user@127.0.0.1:1/none");
    std::env::set_var("SUPABASE_JWT_ISSUER", SUPA_ISS);
    std::env::set_var("SUPABASE_JWT_AUDIENCE", SUPA_AUD);
    std::env::set_var("SUPABASE_JWT_SECRET", SUPA_SECRET);
    std::env::set_var("ADMIN_JWT_ISSUER", ADMIN_ISS);
    std::env::set_var("ADMIN_JWT_AUDIENCE", ADMIN_AUD);
    std::env::set_var("ADMIN_JWT_SECRET", ADMIN_SECRET);
    std::env::set_var("STRIPE_WEBHOOK_SECRET", STRIPE_WEBHOOK_SECRET);
    std::env::set_var("ENTITLEMENT_SIGNING_PRIVATE_KEY", &seed);
    std::env::set_var("ENTITLEMENT_SIGNING_KEY_ID", "entitlement-key-1");
    let config = Config::from_env().expect("config");
    AppState::build(config).expect("state")
}

fn base64_seed() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([3u8; 32])
}

fn now() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
}

fn jwt(claims: Value, secret: &str) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn stripe_signature(payload: &[u8], ts: i64, secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    let mut data = ts.to_string().into_bytes();
    data.push(b'.');
    data.extend_from_slice(payload);
    mac.update(&data);
    format!("t={ts},v1={}", hex::encode(mac.finalize().into_bytes()))
}

async fn status_of(req: Request<Body>) -> StatusCode {
    let app = build_router(test_state());
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn unauthenticated_admin_route_is_rejected() {
    let req = Request::builder()
        .uri("/v1/admin/customers")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn customer_token_cannot_access_admin_route() {
    // A perfectly valid *customer* token, presented to an admin route.
    let token = jwt(
        json!({ "sub": "11111111-1111-1111-1111-111111111111",
                "iss": SUPA_ISS, "aud": SUPA_AUD, "exp": now() + 3600 }),
        SUPA_SECRET,
    );
    let req = Request::builder()
        .uri("/v1/admin/customers")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    // The admin validator (different issuer/audience/secret) rejects it.
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_operator_token_clears_admin_auth() {
    let token = jwt(
        json!({ "sub": "operator-7", "roles": ["support"],
                "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }),
        ADMIN_SECRET,
    );
    let req = Request::builder()
        .uri("/v1/admin/customers")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    // Auth passes; the handler itself is pending → 501 (NOT 401/403).
    assert_eq!(status_of(req).await, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn public_health_needs_no_token() {
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::OK);
}

#[tokio::test]
async fn account_provision_requires_customer_auth() {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/account/provision")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn account_provision_validates_customer_profile_input_before_db_write() {
    let token = jwt(
        json!({ "sub": "11111111-1111-1111-1111-111111111111",
                "email": "user@example.com",
                "iss": SUPA_ISS, "aud": SUPA_AUD, "exp": now() + 3600 }),
        SUPA_SECRET,
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/account/provision")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "country_code": "USA" }).to_string()))
        .unwrap();

    let app = build_router(test_state());
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    assert_eq!(body["error"]["details"]["field"], "country_code");
}

#[tokio::test]
async fn stripe_webhook_requires_signature() {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/webhooks/stripe")
        .header("content-type", "application/json")
        .body(Body::from(r#"{ "id": "evt_1", "type": "invoice.paid" }"#))
        .unwrap();

    assert_eq!(status_of(req).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn stripe_webhook_rejects_bad_signature_before_db_write() {
    let payload = br#"{ "id": "evt_1", "type": "invoice.paid" }"#;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/webhooks/stripe")
        .header("content-type", "application/json")
        .header("stripe-signature", "t=1700000000,v1=deadbeef")
        .body(Body::from(&payload[..]))
        .unwrap();

    assert_eq!(status_of(req).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn stripe_webhook_rejects_malformed_signed_event_before_db_write() {
    let payload = br#"{ "type": "invoice.paid" }"#;
    let ts = now() as i64;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/webhooks/stripe")
        .header("content-type", "application/json")
        .header(
            "stripe-signature",
            stripe_signature(payload, ts, STRIPE_WEBHOOK_SECRET),
        )
        .body(Body::from(&payload[..]))
        .unwrap();

    let app = build_router(test_state());
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "BAD_REQUEST");
}

#[tokio::test]
async fn error_responses_use_the_error_contract() {
    let req = Request::builder()
        .uri("/v1/admin/customers")
        .body(Body::empty())
        .unwrap();
    let app = build_router(test_state());
    let res = app.oneshot(req).await.unwrap();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "UNAUTHENTICATED");
    assert!(body["error"]["correlation_id"].is_string());
}
