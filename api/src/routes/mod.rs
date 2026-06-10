//! HTTP routing. Public routes need no auth; customer routes resolve a [`CustomerContext`];
//! admin routes resolve an [`AdminContext`] validated against the separate operator issuer.
//!
//! Handlers whose full behavior depends on remaining MVP wiring (licensing, entitlement
//! snapshot assembly, usage, and admin flows) return `NOT_IMPLEMENTED` but still enforce
//! the correct auth boundary, so the security contract is testable today.

pub mod catalog;
pub mod entitlements;
pub mod health;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::{AdminContext, AuthUserContext, CustomerContext};
use crate::domain::checkout::{validate_checkout_input, CheckoutInput};
use crate::domain::customer::{
    normalize_email_claim, validate_provision_profile, ProvisionProfileInput,
};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::integrations::stripe::{
    create_checkout_session, parse_event, verify_signature, CheckoutError, CheckoutSessionRequest,
    WebhookError,
};
use crate::middleware as mw;
use crate::repositories::commerce::{StripeWebhookApplyError, StripeWebhookRecordOutcome};
use crate::repositories::{commerce, customers};
use crate::state::AppState;

/// Assemble the full application router.
pub fn build_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/v1/health", get(health::health))
        .route("/v1/ready", get(health::ready))
        .route("/v1/version", get(health::version))
        .route("/v1/products", get(catalog::list_products))
        .route("/v1/plans", get(catalog::list_plans))
        .route("/v1/entitlements/keys", get(entitlements::keys));

    let customer = Router::new()
        .route("/v1/account", get(account_get))
        .route("/v1/account/provision", post(account_provision))
        .route("/v1/subscriptions", get(subscriptions_get))
        .route("/v1/licenses", get(licenses_get))
        .route(
            "/v1/installations",
            get(installations_list).post(installations_register),
        )
        .route(
            "/v1/installations/{id}/activate",
            post(installation_activate),
        )
        .route(
            "/v1/installations/{id}/heartbeat",
            post(installation_heartbeat),
        )
        .route(
            "/v1/installations/{id}/deactivate",
            post(installation_deactivate),
        )
        .route("/v1/devices", get(devices_get))
        .route("/v1/entitlements/current", get(entitlements::current))
        .route("/v1/entitlements/check", post(entitlements_check))
        .route(
            "/v1/entitlements/offline-lease",
            post(entitlements::offline_lease),
        )
        .route("/v1/usage/check", post(usage_check))
        .route("/v1/usage/reserve", post(usage_reserve))
        .route("/v1/usage/commit", post(usage_commit))
        .route("/v1/usage/release", post(usage_release))
        .route("/v1/usage/current", get(usage_current))
        .route("/v1/checkout", post(checkout_create));

    let webhooks = Router::new().route("/v1/webhooks/stripe", post(stripe_webhook));

    let admin = Router::new()
        .route("/v1/admin/customers", get(admin_customers))
        .route("/v1/admin/customers/{id}/suspend", post(admin_suspend))
        .route("/v1/admin/customers/{id}/restore", post(admin_restore))
        .route("/v1/admin/subscriptions/{id}/resync", post(admin_resync))
        .route("/v1/admin/licenses", post(admin_issue_license))
        .route("/v1/admin/licenses/{id}/revoke", post(admin_revoke_license))
        .route("/v1/admin/entitlements/override", post(admin_override))
        .route("/v1/admin/usage/adjust", post(admin_usage_adjust))
        .route("/v1/admin/audit", get(admin_audit));

    public
        .merge(customer)
        .merge(webhooks)
        .merge(admin)
        .layer(axum::middleware::from_fn(mw::security_headers))
        .layer(axum::middleware::from_fn(mw::correlation_id))
        .with_state(state)
}

/// Placeholder response for endpoints whose DB-backed behavior is pending MVP wiring.
fn pending(what: &str) -> AppError {
    AppError::new(
        ErrorCode::NotImplemented,
        format!("{what} is not yet implemented."),
    )
}

#[derive(Debug, Default, Deserialize)]
struct ProvisionAccountRequest {
    display_name: Option<String>,
    country_code: Option<String>,
    timezone: Option<String>,
}

#[derive(Debug, Serialize)]
struct AccountProvisionResponse {
    customer_id: Uuid,
    auth_user_id: Uuid,
    customer_type: String,
    display_name: Option<String>,
    status: String,
    country_code: Option<String>,
    timezone: Option<String>,
    created: bool,
}

#[derive(Debug, Serialize)]
struct StripeWebhookResponse {
    received: bool,
    duplicate: bool,
    event_id: String,
    event_type: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct CheckoutCreateRequest {
    product_key: Option<String>,
    plan_key: String,
    success_url: String,
    cancel_url: String,
}

#[derive(Debug, Serialize)]
struct CheckoutCreateResponse {
    checkout_session_id: Uuid,
    stripe_checkout_session_id: String,
    checkout_url: String,
    status: String,
}

fn stripe_webhook_error(error: WebhookError) -> AppError {
    match error {
        WebhookError::NotConfigured => AppError::new(
            ErrorCode::Internal,
            "Stripe webhook verification is not configured.",
        ),
        _ => AppError::bad_request("Invalid Stripe webhook signature.")
            .with_details(json!({ "reason": error.to_string() })),
    }
}

fn stripe_checkout_error(error: CheckoutError) -> AppError {
    match error {
        CheckoutError::NotConfigured => {
            AppError::new(ErrorCode::Internal, "Stripe Checkout is not configured.")
        }
        CheckoutError::ApiStatus(_) | CheckoutError::Transport(_) => AppError::new(
            ErrorCode::ServiceUnavailable,
            "Stripe Checkout is currently unavailable.",
        )
        .with_details(json!({ "reason": error.to_string() })),
        CheckoutError::MissingSessionId | CheckoutError::MissingCheckoutUrl => {
            AppError::internal("Stripe Checkout returned an incomplete response.")
        }
    }
}

fn stripe_webhook_apply_error(error: StripeWebhookApplyError) -> AppError {
    tracing::error!(error = %error, "failed to apply Stripe webhook event");
    AppError::new(
        ErrorCode::ServiceUnavailable,
        "Stripe webhook event could not be applied.",
    )
}

fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

// --- Customer endpoints (auth enforced via CustomerContext) ----------------

async fn account_get(ctx: CustomerContext) -> AppResult<Json<Value>> {
    let id = ctx.require_active()?;
    // Profile read is RLS-safe; full assembly pending.
    Ok(Json(
        json!({ "customer_id": id, "auth_user_id": ctx.auth_user_id }),
    ))
}

async fn account_provision(
    auth: AuthUserContext,
    State(state): State<AppState>,
    Json(request): Json<ProvisionAccountRequest>,
) -> AppResult<Json<AccountProvisionResponse>> {
    let validated = validate_provision_profile(ProvisionProfileInput {
        display_name: request.display_name.as_deref(),
        country_code: request.country_code.as_deref(),
        timezone: request.timezone.as_deref(),
    })
    .map_err(|err| AppError::validation(err.message).with_details(json!({ "field": err.field })))?;

    let email = normalize_email_claim(auth.email.as_deref());
    let provisioned = customers::provision_for_auth_user(
        &state.pool,
        auth.auth_user_id,
        email.as_deref(),
        validated.display_name.as_deref(),
        validated.country_code.as_deref(),
        validated.timezone.as_deref(),
    )
    .await?;

    let profile = provisioned.profile;
    Ok(Json(AccountProvisionResponse {
        customer_id: profile.id,
        auth_user_id: profile.auth_user_id,
        customer_type: profile.customer_type,
        display_name: profile.display_name,
        status: profile.status,
        country_code: profile.country_code,
        timezone: profile.timezone,
        created: provisioned.created,
    }))
}

async fn subscriptions_get(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Subscription summary"))
}

async fn licenses_get(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("License listing"))
}

async fn installations_list(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Installation listing"))
}

async fn installations_register(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Installation registration"))
}

async fn installation_activate(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Installation activation"))
}

async fn installation_heartbeat(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Installation heartbeat"))
}

async fn installation_deactivate(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Installation deactivation"))
}

async fn devices_get(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Device listing"))
}

async fn entitlements_check(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Entitlement check"))
}

async fn usage_check(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Usage check"))
}

async fn usage_reserve(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Usage reservation"))
}

async fn usage_commit(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Usage commit"))
}

async fn usage_release(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Usage release"))
}

async fn usage_current(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Usage summary"))
}

async fn checkout_create(
    ctx: CustomerContext,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CheckoutCreateRequest>,
) -> AppResult<Json<CheckoutCreateResponse>> {
    let customer_id = ctx.require_active()?;
    let validated = validate_checkout_input(CheckoutInput {
        product_key: request.product_key.as_deref(),
        plan_key: &request.plan_key,
        success_url: &request.success_url,
        cancel_url: &request.cancel_url,
    })
    .map_err(|err| AppError::validation(err.message).with_details(json!({ "field": err.field })))?;

    let plan = commerce::find_active_checkout_plan(
        &state.pool,
        &validated.product_key,
        &validated.plan_key,
    )
    .await?
    .ok_or_else(|| AppError::not_found("No active checkout plan matched the request."))?;
    let stripe_price_id = plan.stripe_price_id.as_deref().ok_or_else(|| {
        AppError::validation("Selected plan is not available for Stripe Checkout.")
            .with_details(json!({ "field": "plan_key" }))
    })?;

    let stripe_session = create_checkout_session(
        &state.http,
        &state.config.stripe_secret_key,
        &CheckoutSessionRequest {
            price_id: stripe_price_id.to_string(),
            customer_id: customer_id.to_string(),
            plan_version_id: plan.plan_version_id.to_string(),
            success_url: validated.success_url,
            cancel_url: validated.cancel_url,
        },
        idempotency_key(&headers),
    )
    .await
    .map_err(stripe_checkout_error)?;

    let checkout = commerce::record_checkout_session(
        &state.pool,
        customer_id,
        plan.plan_version_id,
        &stripe_session.id,
    )
    .await?;

    Ok(Json(CheckoutCreateResponse {
        checkout_session_id: checkout.id,
        stripe_checkout_session_id: checkout.stripe_checkout_session_id,
        checkout_url: stripe_session.url,
        status: checkout.status,
    }))
}

// --- Stripe webhook (no JWT; signature verified in the handler) ------------

async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Json<StripeWebhookResponse>> {
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::bad_request("Missing Stripe-Signature header."))?;

    verify_signature(
        &body,
        signature,
        &state.config.stripe_webhook_secret,
        chrono::Utc::now().timestamp(),
        300,
    )
    .map_err(stripe_webhook_error)?;

    let event = parse_event(&body).map_err(|error| {
        AppError::bad_request("Malformed Stripe event payload.")
            .with_details(json!({ "reason": error.to_string() }))
    })?;
    let record = commerce::process_stripe_webhook_event(&state.pool, &event)
        .await
        .map_err(stripe_webhook_apply_error)?;
    let duplicate = matches!(record.outcome, StripeWebhookRecordOutcome::Duplicate);

    Ok(Json(StripeWebhookResponse {
        received: !duplicate,
        duplicate,
        event_id: event.id,
        event_type: event.event_type,
        status: record.status,
    }))
}

// --- Admin endpoints (auth enforced via AdminContext) ----------------------

async fn admin_customers(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin customer listing"))
}
async fn admin_suspend(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin suspend"))
}
async fn admin_restore(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin restore"))
}
async fn admin_resync(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin subscription resync"))
}
async fn admin_issue_license(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin license issuance"))
}
async fn admin_revoke_license(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin license revocation"))
}
async fn admin_override(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin entitlement override"))
}
async fn admin_usage_adjust(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin usage adjustment"))
}
async fn admin_audit(_admin: AdminContext) -> AppResult<Json<Value>> {
    Err(pending("Admin audit read"))
}
