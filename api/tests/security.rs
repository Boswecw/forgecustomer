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
/// Throwaway Ed25519 test keypair (PKCS8 private / SPKI public) standing in for Forge
/// Command's Token Authority signing key: operator tokens are signed with the private key,
/// and the admin validator verifies them with the public key.
const ADMIN_ED_PRIVATE_PEM: &str =
    "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIK0QNf3nxqiBF98HL/aSUWke0fE4CuryMonE9nhFvqnL\n-----END PRIVATE KEY-----\n";
const ADMIN_ED_PUBLIC_PEM: &str =
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAYOHufz/uvwEGo+RUA4tUz7spzpbs9LKrY6FtlgydMGY=\n-----END PUBLIC KEY-----\n";
const STRIPE_WEBHOOK_SECRET: &str = "whsec_test";

fn test_config() -> Config {
    // A throwaway base64 32-byte Ed25519 seed.
    let seed = base64_seed();
    std::env::set_var("DATABASE_URL", "postgres://user@127.0.0.1:1/none");
    // The unreachable test database must fail fast, not wait out the default timeout.
    std::env::set_var("DATABASE_ACQUIRE_TIMEOUT_SECS", "1");
    std::env::set_var("SUPABASE_JWT_ISSUER", SUPA_ISS);
    std::env::set_var("SUPABASE_JWT_AUDIENCE", SUPA_AUD);
    std::env::set_var("SUPABASE_JWT_SECRET", SUPA_SECRET);
    std::env::set_var("ADMIN_JWT_ISSUER", ADMIN_ISS);
    std::env::set_var("ADMIN_JWT_AUDIENCE", ADMIN_AUD);
    std::env::set_var("ADMIN_JWT_PUBLIC_KEY", ADMIN_ED_PUBLIC_PEM);
    std::env::set_var("STRIPE_WEBHOOK_SECRET", STRIPE_WEBHOOK_SECRET);
    std::env::set_var("ENTITLEMENT_SIGNING_PRIVATE_KEY", &seed);
    std::env::set_var("ENTITLEMENT_SIGNING_KEY_ID", "entitlement-key-1");
    // Pinned for every test (env vars are process-global, so tests must agree on the
    // values): a small body cap so the oversized-body test stays cheap, and the default
    // request timeout so only the dedicated timeout test (which overrides the parsed
    // config directly) observes a short deadline.
    std::env::set_var("MAX_BODY_BYTES", "2048");
    std::env::set_var("REQUEST_TIMEOUT_SECS", "30");
    std::env::set_var("RATE_LIMIT_PER_MINUTE", "300");
    std::env::set_var("UPDATE_ROLLOUT_SECRET", "security-test-rollout-secret");
    std::env::set_var(
        "RELEASE_ARTIFACT_BASE_URL",
        "https://downloads.example.test/authorforge",
    );
    Config::from_env().expect("config")
}

fn test_state() -> AppState {
    AppState::build(test_config()).expect("state")
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

/// Mint an EdDSA operator token the way Forge Command's Token Authority does, signed with
/// the test Ed25519 private key the admin validator is configured to trust.
fn admin_jwt(claims: Value) -> String {
    encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &EncodingKey::from_ed_pem(ADMIN_ED_PRIVATE_PEM.as_bytes()).unwrap(),
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
    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["support"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let req = Request::builder()
        .uri("/v1/admin/customers")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    // Auth passes (NOT 401/403); the listing then fails on the unreachable test
    // database, proving the boundary sits in front of the data access.
    assert_eq!(status_of(req).await, StatusCode::INTERNAL_SERVER_ERROR);

    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["support"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let req = Request::builder()
        .uri("/v1/admin/fleets")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn admin_mutations_require_admin_role() {
    // A valid operator token WITHOUT the `admin` role: reads pass auth, mutations 403.
    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["support"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let id = "9f1c2d3e-4b5a-6789-0abc-def012345678";
    for uri in [
        format!("/v1/admin/customers/{id}/suspend"),
        format!("/v1/admin/customers/{id}/restore"),
        format!("/v1/admin/subscriptions/{id}/resync"),
        format!("/v1/admin/licenses/{id}/revoke"),
        format!("/v1/admin/fleets/{id}/policy"),
        "/v1/admin/releases".to_string(),
        format!("/v1/admin/releases/{id}/artifacts"),
        format!("/v1/admin/releases/{id}/validate"),
        format!("/v1/admin/releases/{id}/publish"),
        format!("/v1/admin/releases/{id}/block"),
        "/v1/admin/update-campaigns".to_string(),
        format!("/v1/admin/update-campaigns/{id}/pause"),
        format!("/v1/admin/update-campaigns/{id}/resume"),
        format!("/v1/admin/update-campaigns/{id}/revoke"),
        format!("/v1/admin/update-campaigns/{id}/rollout"),
        format!("/v1/admin/update-campaigns/{id}/holds"),
        format!("/v1/admin/release-artifacts/{id}/quarantine"),
        format!("/v1/admin/deletion-requests/{id}/advance"),
        format!("/v1/admin/deletion-requests/{id}/reject"),
        format!("/v1/admin/deletion-requests/{id}/execute"),
        "/v1/admin/licenses".to_string(),
        "/v1/admin/entitlements/override".to_string(),
        "/v1/admin/usage/adjust".to_string(),
    ] {
        // A superset body that deserializes for every mutation route (serde ignores
        // unknown fields), so the role gate — not body validation — is what rejects.
        let body = json!({
            "reason": "support cleanup",
            "customer_id": "9f1c2d3e-4b5a-6789-0abc-def012345678",
            "meter_key": "cloud_tokens",
            "amount": -100,
            "feature_key": "authorforge.cloud.enabled",
            "value": true,
            "display_name": "Default fleet",
            "update_ring": "standard",
            "release_channel": "stable",
            "product_key": "authorforge",
            "version": "1.0.1",
            "build_id": "20260612.abcd",
            "platform": "linux",
            "architecture": "x86_64",
            "package_format": "appimage",
            "artifact_role": "bootstrap",
            "storage_key": "authorforge/1.0.1/linux-x86_64.appimage",
            "size_bytes": 123,
            "sha256": "a".repeat(64),
            "tauri_signature": "tauri-signature",
            "signing_key_id": "tauri-key-1",
            "os_signature_status": "verified",
            "target_release_id": id,
            "campaign_slug": "authorforge-test-campaign",
            "rollout_percentage": 0,
            "fleet_id": id
        });
        let req = Request::builder()
            .method("POST")
            .uri(&uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("idempotency-key", "role-check-1")
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(status_of(req).await, StatusCode::FORBIDDEN, "{uri}");
    }

    let body = json!({ "reason": "support cleanup" });
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/admin/update-campaigns/{id}/holds/{id}"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("idempotency-key", "role-check-delete-1")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_mutations_validate_reason_before_db_write() {
    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["admin"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/customers/9f1c2d3e-4b5a-6789-0abc-def012345678/suspend")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "reason": "x" }).to_string()))
        .unwrap();

    let app = build_router(test_state());
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    assert_eq!(body["error"]["details"]["field"], "reason");
}

#[tokio::test]
async fn admin_usage_adjust_requires_idempotency_key() {
    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["admin"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/usage/adjust")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "customer_id": "9f1c2d3e-4b5a-6789-0abc-def012345678",
                "meter_key": "cloud_tokens",
                "amount": -100,
                "reason": "refund correction"
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn fleet_update_admin_mutations_require_idempotency_key() {
    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["admin"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/releases/9f1c2d3e-4b5a-6789-0abc-def012345678/publish")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "reason": "publish validated release" }).to_string(),
        ))
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn fleet_update_admin_mutations_validate_before_db_write() {
    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["admin"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/update-campaigns/9f1c2d3e-4b5a-6789-0abc-def012345678/rollout")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("idempotency-key", "bad-rollout-1")
        .body(Body::from(
            json!({ "reason": "raise rollout", "rollout_percentage": 101 }).to_string(),
        ))
        .unwrap();

    let app = build_router(test_state());
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    assert_eq!(body["error"]["details"]["field"], "rollout_percentage");
}

#[tokio::test]
async fn release_pipeline_admin_mutations_validate_before_db_write() {
    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["admin"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/releases/9f1c2d3e-4b5a-6789-0abc-def012345678/artifacts")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("idempotency-key", "bad-artifact-1")
        .body(Body::from(
            json!({
                "reason": "register artifact",
                "platform": "linux",
                "architecture": "x86_64",
                "package_format": "appimage",
                "artifact_role": "bootstrap",
                "storage_key": "authorforge/1.0.1/linux-x86_64.appimage",
                "size_bytes": 123,
                "sha256": "not-a-digest",
                "signing_key_id": "tauri-key-1",
                "os_signature_status": "verified"
            })
            .to_string(),
        ))
        .unwrap();

    let app = build_router(test_state());
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    assert_eq!(body["error"]["details"]["field"], "sha256");
}

#[tokio::test]
async fn operator_scope_admin_satisfies_mutation_gate() {
    // Forge Command's Token Authority issues `scope` (not `roles`); scope "admin" must
    // satisfy the admin role gate. Auth + role + reason pass, then the unreachable DB 500s.
    let token = admin_jwt(json!({
        "sub": "forge_command_local", "scope": "admin",
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600
    }));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/customers/9f1c2d3e-4b5a-6789-0abc-def012345678/suspend")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("idempotency-key", "scope-admin-1")
        .body(Body::from(
            json!({ "reason": "scope-derived admin role" }).to_string(),
        ))
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::INTERNAL_SERVER_ERROR);
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
async fn public_release_distribution_routes_need_no_token() {
    let req = Request::builder()
        .uri("/v1/products/authorforge/releases/latest?channel=stable")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::INTERNAL_SERVER_ERROR);

    let req = Request::builder()
        .uri("/v1/products/authorforge/downloads?platform=linux&arch=x86_64")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::INTERNAL_SERVER_ERROR);
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
async fn licensing_routes_require_customer_auth() {
    // Listing endpoints.
    for uri in [
        "/v1/licenses",
        "/v1/installations",
        "/v1/devices",
        "/v1/updates/authorforge/windows/x86_64/1.0.0",
    ] {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED, "{uri}");
    }
    // Registration.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/installations")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn parameterized_installation_routes_match_and_require_auth() {
    // A 401 (not 404) proves the parameterized route matches AND fails closed without
    // auth. This guards the axum 0.7 `:id` path syntax.
    let id = "9f1c2d3e-4b5a-6789-0abc-def012345678";
    for action in ["activate", "heartbeat", "deactivate", "update-events"] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/installations/{id}/{action}"))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED, "{action}");
    }
}

#[tokio::test]
async fn entitlement_routes_require_customer_auth() {
    let req = Request::builder()
        .uri("/v1/entitlements/current")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);

    for uri in ["/v1/entitlements/check", "/v1/entitlements/offline-lease"] {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn entitlement_keys_remain_public() {
    let req = Request::builder()
        .uri("/v1/entitlements/keys")
        .body(Body::empty())
        .unwrap();
    let app = build_router(test_state());
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["schema"], "forge.entitlements.v1");
    assert_eq!(body["keys"][0]["alg"], "Ed25519");
}

#[tokio::test]
async fn deletion_routes_require_customer_auth() {
    let req = Request::builder()
        .uri("/v1/account/deletion-request")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);

    for uri in [
        "/v1/account/deletion-request",
        "/v1/account/deletion-request/cancel",
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED, "{uri}");
    }

    let req = Request::builder()
        .uri("/v1/subscriptions")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn usage_routes_require_customer_auth() {
    let req = Request::builder()
        .uri("/v1/usage/current")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);

    for uri in [
        "/v1/usage/check",
        "/v1/usage/reserve",
        "/v1/usage/commit",
        "/v1/usage/release",
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn billing_portal_requires_customer_auth() {
    // The self-service Billing Portal door is a customer route — it must fail closed
    // without a customer token, before any Stripe call or DB lookup.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/billing-portal")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "return_url": "https://example.com/account.html" }).to_string(),
        ))
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn parameterized_admin_routes_match_and_require_auth() {
    let id = "9f1c2d3e-4b5a-6789-0abc-def012345678";
    for uri in [
        format!("/v1/admin/customers/{id}/suspend"),
        format!("/v1/admin/customers/{id}/restore"),
        format!("/v1/admin/subscriptions/{id}/resync"),
        format!("/v1/admin/licenses/{id}/revoke"),
        format!("/v1/admin/fleets/{id}/policy"),
        format!("/v1/admin/releases/{id}/artifacts"),
        format!("/v1/admin/releases/{id}/validate"),
        format!("/v1/admin/releases/{id}/publish"),
        format!("/v1/admin/releases/{id}/block"),
        format!("/v1/admin/update-campaigns/{id}/pause"),
        format!("/v1/admin/update-campaigns/{id}/resume"),
        format!("/v1/admin/update-campaigns/{id}/revoke"),
        format!("/v1/admin/update-campaigns/{id}/rollout"),
        format!("/v1/admin/update-campaigns/{id}/holds"),
        format!("/v1/admin/release-artifacts/{id}/quarantine"),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED, "{uri}");
    }

    for uri in [
        format!("/v1/admin/fleets/{id}"),
        format!("/v1/admin/releases/{id}"),
        format!("/v1/admin/update-campaigns/{id}"),
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED, "{uri}");
    }

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/admin/update-campaigns/{id}/holds/{id}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::UNAUTHORIZED);
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
async fn oversized_request_body_is_rejected() {
    // 8 KiB against the 2 KiB test cap (MAX_BODY_BYTES). The webhook route has no
    // token gate in front of the body read, so a 413 here proves the configured cap —
    // not signature verification or handler logic — rejected the request.
    let payload = vec![b'{'; 8 * 1024];
    let req = Request::builder()
        .method("POST")
        .uri("/v1/webhooks/stripe")
        .header("content-type", "application/json")
        .header("stripe-signature", "t=1,v1=ab")
        .body(Body::from(payload))
        .unwrap();
    assert_eq!(status_of(req).await, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn slow_requests_time_out_fail_closed() {
    // Shrink the request timeout well below the 1s database acquire timeout: the admin
    // listing clears auth, then hangs on the unreachable test database, so the timeout
    // layer must answer first.
    let mut config = test_config();
    config.request_timeout = std::time::Duration::from_millis(100);
    let app = build_router(AppState::build(config).expect("state"));

    let token = admin_jwt(json!({ "sub": "operator-7", "roles": ["support"],
        "iss": ADMIN_ISS, "aud": ADMIN_AUD, "exp": now() + 3600 }));
    let req = Request::builder()
        .uri("/v1/admin/customers")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    // The timeout response still flows out through the security-header and correlation
    // layers (layer ordering in `build_router`).
    assert_eq!(
        res.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert!(res.headers().get("x-correlation-id").is_some());
}

#[tokio::test]
async fn rate_limited_requests_get_429_through_the_contract() {
    let mut config = test_config();
    config.rate_limit_per_minute = 2;
    let app = build_router(AppState::build(config).expect("state"));

    // A fixed-window boundary can reset the budget at most once mid-test, so five
    // requests against a budget of two must surface at least one 429.
    let mut throttled = None;
    for _ in 0..5 {
        let req = Request::builder()
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            throttled = Some(res);
            break;
        }
        assert_eq!(res.status(), StatusCode::OK);
    }
    let res = throttled.expect("budget of 2 must throttle within 5 requests");

    assert!(res.headers().get("retry-after").is_some());
    // The 429 flows out through the security-header and correlation layers and renders
    // through the shared error contract.
    assert_eq!(
        res.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "RATE_LIMITED");
    assert!(body["error"]["correlation_id"].is_string());
}

#[tokio::test]
async fn rate_limit_budgets_are_per_client() {
    let mut config = test_config();
    config.rate_limit_per_minute = 1;
    let app = build_router(AppState::build(config).expect("state"));

    // Exhaust client A's budget (the rightmost x-forwarded-for entry is the key).
    let mut saw_throttle = false;
    for _ in 0..3 {
        let req = Request::builder()
            .uri("/v1/health")
            .header("x-forwarded-for", "203.0.113.7")
            .body(Body::empty())
            .unwrap();
        let status = app.clone().oneshot(req).await.unwrap().status();
        saw_throttle |= status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(saw_throttle, "client A must be throttled");

    // Client B's budget is untouched by A's burst.
    let req = Request::builder()
        .uri("/v1/health")
        .header("x-forwarded-for", "203.0.113.8")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "client B must not be throttled"
    );
}

#[tokio::test]
async fn hostile_correlation_ids_are_replaced() {
    // Client-supplied correlation ids land in audit rows and logs, so oversized or
    // non-log-safe values must be swapped for a generated id rather than echoed.
    for hostile in [&"x".repeat(4096), "spaces and (parens)"] {
        let req = Request::builder()
            .uri("/v1/health")
            .header("x-correlation-id", hostile)
            .body(Body::empty())
            .unwrap();
        let app = build_router(test_state());
        let res = app.oneshot(req).await.unwrap();
        let echoed = res
            .headers()
            .get("x-correlation-id")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(echoed.starts_with("corr_"), "got {echoed}");
    }

    // A tame client id is still honored end to end.
    let req = Request::builder()
        .uri("/v1/health")
        .header("x-correlation-id", "client-trace.42")
        .body(Body::empty())
        .unwrap();
    let app = build_router(test_state());
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(
        res.headers().get("x-correlation-id").unwrap(),
        "client-trace.42"
    );
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
