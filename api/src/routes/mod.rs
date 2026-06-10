//! HTTP routing. Public routes need no auth; customer routes resolve a [`CustomerContext`];
//! admin routes resolve an [`AdminContext`] validated against the separate operator issuer.
//!
//! Handlers whose full behavior depends on remaining MVP wiring (DB-backed commerce,
//! licensing and usage flows) return `NOT_IMPLEMENTED` but still enforce the correct auth
//! boundary, so the security contract is testable today.

pub mod catalog;
pub mod entitlements;
pub mod health;

use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::auth::{AdminContext, CustomerContext};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::middleware as mw;
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

// --- Customer endpoints (auth enforced via CustomerContext) ----------------

async fn account_get(ctx: CustomerContext) -> AppResult<Json<Value>> {
    let id = ctx.require_active()?;
    // Profile read is RLS-safe; full assembly pending.
    Ok(Json(
        json!({ "customer_id": id, "auth_user_id": ctx.auth_user_id }),
    ))
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

async fn checkout_create(ctx: CustomerContext) -> AppResult<Json<Value>> {
    ctx.require_active()?;
    Err(pending("Checkout session creation"))
}

// --- Stripe webhook (no JWT; signature verified in the handler) ------------

async fn stripe_webhook() -> AppResult<Json<Value>> {
    Err(pending("Stripe webhook processing"))
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
