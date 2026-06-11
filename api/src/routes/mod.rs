//! HTTP routing. Public routes need no auth; customer routes resolve a [`CustomerContext`];
//! admin routes resolve an [`AdminContext`] validated against the separate operator issuer
//! (Forge Command), with mutations additionally gated on the `admin` operator role.
//!
//! Every route is fully implemented; auth boundaries (customer vs operator, role-gated
//! mutations) are enforced ahead of all data access.

pub mod catalog;
pub mod entitlements;
pub mod health;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::auth::{AdminContext, AuthUserContext, CustomerContext};
use crate::domain::admin::{
    clean_adjustment_amount, clean_device_limit, clean_override_value, clean_period_key,
    clean_reason,
};
use crate::domain::checkout::{validate_checkout_input, CheckoutInput};
use crate::domain::customer::{
    normalize_email_claim, validate_provision_profile, ProvisionProfileInput,
};
use crate::domain::entitlement::clean_entitlement_key;
use crate::domain::installation::{clean_app_version, validate_registration, RegistrationInput};
use crate::domain::usage::{
    clean_usage_amount, decide, period_key_for, quota_key_candidates, Decision,
};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::integrations::stripe::{
    create_checkout_session, fetch_subscription, parse_event, verify_signature, CheckoutError,
    CheckoutSessionRequest, SubscriptionFetchError, WebhookError,
};
use crate::middleware as mw;
use crate::repositories::commerce::{StripeWebhookApplyError, StripeWebhookRecordOutcome};
use crate::repositories::licensing::{self, ActivationError, RegistrationError};
use crate::repositories::usage as usage_repo;
use crate::repositories::{admin, commerce, customers, privacy};
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
        .route(
            "/v1/account/deletion-request",
            get(deletion_request_get).post(deletion_request_create),
        )
        .route(
            "/v1/account/deletion-request/cancel",
            post(deletion_request_cancel),
        )
        .route("/v1/subscriptions", get(subscriptions_get))
        .route("/v1/licenses", get(licenses_get))
        .route(
            "/v1/installations",
            get(installations_list).post(installations_register),
        )
        .route(
            "/v1/installations/:id/activate",
            post(installation_activate),
        )
        .route(
            "/v1/installations/:id/heartbeat",
            post(installation_heartbeat),
        )
        .route(
            "/v1/installations/:id/deactivate",
            post(installation_deactivate),
        )
        .route("/v1/devices", get(devices_get))
        .route("/v1/entitlements/current", get(entitlements::current))
        .route("/v1/entitlements/check", post(entitlements::check))
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
        .route("/v1/admin/customers/:id/suspend", post(admin_suspend))
        .route("/v1/admin/customers/:id/restore", post(admin_restore))
        .route("/v1/admin/subscriptions/:id/resync", post(admin_resync))
        .route("/v1/admin/licenses", post(admin_issue_license))
        .route("/v1/admin/licenses/:id/revoke", post(admin_revoke_license))
        .route("/v1/admin/entitlements/override", post(admin_override))
        .route("/v1/admin/usage/adjust", post(admin_usage_adjust))
        .route("/v1/admin/audit", get(admin_audit))
        .route("/v1/admin/deletion-requests", get(admin_deletion_list))
        .route(
            "/v1/admin/deletion-requests/:id/advance",
            post(admin_deletion_advance),
        )
        .route(
            "/v1/admin/deletion-requests/:id/reject",
            post(admin_deletion_reject),
        )
        .route(
            "/v1/admin/deletion-requests/:id/execute",
            post(admin_deletion_execute),
        );

    let request_timeout = state.config.request_timeout;
    let max_body_bytes = state.config.max_body_bytes;

    public
        .merge(customer)
        .merge(webhooks)
        .merge(admin)
        // Layer order matters (later = outer): guard rejections (429/503/413) still flow
        // back out through security_headers and correlation_id, so they carry the
        // standard headers. Timeouts render 503 (retriable; Stripe re-delivers webhooks
        // and processing is idempotent). DefaultBodyLimit governs axum extractors
        // (otherwise capped at axum's 2 MiB default, ignoring config);
        // RequestBodyLimitLayer enforces the same cap for any direct body reads. The
        // rate limiter sits outside both so a throttled client spends no body/timeout
        // machinery, but inside correlation_id so the 429 is attributable.
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            request_timeout,
        ))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            mw::rate_limit::enforce,
        ))
        .layer(axum::middleware::from_fn(mw::security_headers))
        .layer(axum::middleware::from_fn(mw::correlation_id))
        .with_state(state)
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

#[derive(Debug, Deserialize)]
struct InstallationRegisterRequest {
    install_key: String,
    product_key: Option<String>,
    app_version: Option<String>,
    device_public_key: Option<String>,
    device_label: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstallationRegisterResponse {
    installation_id: Uuid,
    install_key: String,
    product_key: String,
    app_version: Option<String>,
    status: String,
    device_id: Option<Uuid>,
    created: bool,
    reactivated: bool,
}

#[derive(Debug, Default, Deserialize)]
struct InstallationActivateRequest {
    license_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct InstallationActivateResponse {
    activation_id: Uuid,
    license_id: Uuid,
    installation_id: Uuid,
    activated_at: chrono::DateTime<chrono::Utc>,
    device_limit: u32,
    active_devices: u32,
    already_active: bool,
}

#[derive(Debug, Default, Deserialize)]
struct InstallationHeartbeatRequest {
    app_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstallationDeactivateResponse {
    installation_id: Uuid,
    status: String,
    released_activations: u64,
    already_deactivated: bool,
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

/// Parse a path id ourselves so malformed ids render through the error contract instead
/// of axum's plain-text rejection.
fn parse_path_id(raw: &str) -> AppResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| AppError::bad_request("Path id must be a UUID."))
}

fn correlation_id(correlation: &Option<Extension<mw::CorrelationId>>) -> Option<&str> {
    correlation
        .as_ref()
        .map(|Extension(correlation)| correlation.0.as_str())
}

fn installation_validation_error(
    error: crate::domain::installation::InstallationValidationError,
) -> AppError {
    AppError::validation(error.message).with_details(json!({ "field": error.field }))
}

fn registration_error(error: RegistrationError) -> AppError {
    match error {
        RegistrationError::UnknownProduct => AppError::not_found("Unknown or inactive product."),
        RegistrationError::ProductMismatch => AppError::new(
            ErrorCode::Conflict,
            "This install key is already registered for a different product.",
        ),
        RegistrationError::Db(error) => error.into(),
    }
}

fn activation_error(error: ActivationError) -> AppError {
    match error {
        ActivationError::InstallationNotFound => AppError::not_found("Installation not found."),
        ActivationError::InstallationDeactivated => AppError::new(
            ErrorCode::Conflict,
            "Installation is deactivated; register it again before activating.",
        ),
        ActivationError::LicenseNotFound => AppError::not_found("License not found."),
        ActivationError::NoActiveLicense => {
            AppError::not_found("No active license covers this product.")
        }
        ActivationError::LicenseNotActive(status) => AppError::forbidden("License is not active.")
            .with_details(json!({ "license_status": status })),
        ActivationError::RevocationBlocked => AppError::new(
            ErrorCode::Revoked,
            "Activation is blocked by an explicit revocation.",
        ),
        ActivationError::DeviceLimitReached {
            device_limit,
            active_devices,
        } => AppError::new(
            ErrorCode::DeviceLimitReached,
            "Device limit reached; deactivate another installation to free a slot.",
        )
        .with_details(json!({
            "device_limit": device_limit,
            "active_devices": active_devices,
        })),
        ActivationError::Db(error) => error.into(),
    }
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

async fn subscriptions_get(
    ctx: CustomerContext,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let subscriptions = commerce::list_customer_subscriptions(&state.pool, customer_id).await?;
    Ok(Json(json!({ "subscriptions": subscriptions })))
}

// --- Account deletion (customer side) ---------------------------------------

fn deletion_error(error: privacy::DeletionError) -> AppError {
    match error {
        privacy::DeletionError::NotFound => AppError::not_found("Deletion request not found."),
        privacy::DeletionError::InvalidState(status) => AppError::new(
            ErrorCode::Conflict,
            "The deletion request is not in a state that allows this transition.",
        )
        .with_details(json!({ "request_status": status })),
        privacy::DeletionError::CoolingOffActive => AppError::new(
            ErrorCode::Conflict,
            "The cooling-off period has not elapsed yet.",
        ),
        privacy::DeletionError::SubscriptionStillActive => AppError::new(
            ErrorCode::Conflict,
            "Cancel the customer's subscriptions at Stripe (and resync) before executing deletion.",
        ),
        privacy::DeletionError::Db(error) => error.into(),
    }
}

#[derive(Debug, Default, Deserialize)]
struct DeletionRequestCreate {
    reason: Option<String>,
}

async fn deletion_request_create(
    ctx: CustomerContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Json(request): Json<DeletionRequestCreate>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let reason = match request.reason.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => {
            Some(clean_reason(value).map_err(admin_validation_error)?)
        }
        _ => None,
    };

    let requested = privacy::request_deletion(
        &state.pool,
        customer_id,
        reason.as_deref(),
        correlation_id(&correlation),
    )
    .await?;
    Ok(Json(json!({
        "request": requested.request,
        "created": requested.created,
    })))
}

async fn deletion_request_get(
    ctx: CustomerContext,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let request = privacy::latest_request(&state.pool, customer_id)
        .await?
        .ok_or_else(|| AppError::not_found("No deletion request exists."))?;
    Ok(Json(json!({ "request": request })))
}

async fn deletion_request_cancel(
    ctx: CustomerContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let request = privacy::cancel_request(&state.pool, customer_id, correlation_id(&correlation))
        .await
        .map_err(deletion_error)?;
    Ok(Json(json!({ "request": request })))
}

async fn licenses_get(
    ctx: CustomerContext,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let licenses = licensing::list_licenses(&state.pool, customer_id).await?;
    Ok(Json(json!({ "licenses": licenses })))
}

async fn installations_list(
    ctx: CustomerContext,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let installations = licensing::list_installations(&state.pool, customer_id).await?;
    Ok(Json(json!({ "installations": installations })))
}

async fn installations_register(
    ctx: CustomerContext,
    State(state): State<AppState>,
    Json(request): Json<InstallationRegisterRequest>,
) -> AppResult<Json<InstallationRegisterResponse>> {
    let customer_id = ctx.require_active()?;
    let validated = validate_registration(RegistrationInput {
        install_key: &request.install_key,
        product_key: request.product_key.as_deref(),
        app_version: request.app_version.as_deref(),
        device_public_key: request.device_public_key.as_deref(),
        device_label: request.device_label.as_deref(),
    })
    .map_err(installation_validation_error)?;

    let registered = licensing::register_installation(&state.pool, customer_id, &validated)
        .await
        .map_err(registration_error)?;

    let installation = registered.installation;
    Ok(Json(InstallationRegisterResponse {
        installation_id: installation.id,
        install_key: installation.install_key,
        product_key: installation.product_key,
        app_version: installation.app_version,
        status: installation.status,
        device_id: installation.device_id,
        created: registered.created,
        reactivated: registered.reactivated,
    }))
}

async fn installation_activate(
    ctx: CustomerContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
    Json(request): Json<InstallationActivateRequest>,
) -> AppResult<Json<InstallationActivateResponse>> {
    let customer_id = ctx.require_active()?;
    let installation_id = parse_path_id(&id)?;

    let outcome = licensing::activate_installation(
        &state.pool,
        customer_id,
        installation_id,
        request.license_id,
        correlation_id(&correlation),
    )
    .await
    .map_err(activation_error)?;

    Ok(Json(InstallationActivateResponse {
        activation_id: outcome.activation_id,
        license_id: outcome.license_id,
        installation_id: outcome.installation_id,
        activated_at: outcome.activated_at,
        device_limit: outcome.device_limit,
        active_devices: outcome.active_devices,
        already_active: outcome.already_active,
    }))
}

async fn installation_heartbeat(
    ctx: CustomerContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Option<Json<InstallationHeartbeatRequest>>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let installation_id = parse_path_id(&id)?;
    let app_version = request
        .as_ref()
        .and_then(|Json(request)| request.app_version.as_deref());
    let app_version = clean_app_version(app_version).map_err(installation_validation_error)?;

    let row = licensing::heartbeat_installation(
        &state.pool,
        customer_id,
        installation_id,
        app_version.as_deref(),
    )
    .await?
    .ok_or_else(|| AppError::not_found("Installation not found."))?;

    Ok(Json(json!({
        "installation_id": row.id,
        "status": row.status,
        "app_version": row.app_version,
        "last_heartbeat_at": row.last_heartbeat_at,
    })))
}

async fn installation_deactivate(
    ctx: CustomerContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
) -> AppResult<Json<InstallationDeactivateResponse>> {
    let customer_id = ctx.require_active()?;
    let installation_id = parse_path_id(&id)?;

    let outcome = licensing::deactivate_installation(
        &state.pool,
        customer_id,
        installation_id,
        correlation_id(&correlation),
    )
    .await
    .map_err(activation_error)?;

    Ok(Json(InstallationDeactivateResponse {
        installation_id: outcome.installation_id,
        status: outcome.status,
        released_activations: outcome.released_activations,
        already_deactivated: outcome.already_deactivated,
    }))
}

async fn devices_get(
    ctx: CustomerContext,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let devices = licensing::list_devices(&state.pool, customer_id).await?;
    Ok(Json(json!({ "devices": devices })))
}

// --- Usage endpoints (reserve → commit → release; quota-gated, idempotent) --

fn usage_error(error: usage_repo::UsageError) -> AppError {
    match error {
        usage_repo::UsageError::MeterNotFound => AppError::not_found("Unknown usage meter."),
        usage_repo::UsageError::ReservationNotFound => {
            AppError::not_found("Reservation not found.")
        }
        usage_repo::UsageError::ReservationNotCommittable(status) => AppError::new(
            ErrorCode::Conflict,
            "Reservation can no longer be committed.",
        )
        .with_details(json!({ "reservation_status": status })),
        usage_repo::UsageError::Db(error) => error.into(),
    }
}

fn quota_exceeded(denied: usage_repo::DeniedDecision) -> AppError {
    AppError::new(
        ErrorCode::QuotaExceeded,
        "The requested amount exceeds the remaining quota.",
    )
    .with_details(json!({
        "reason": denied.reason,
        "limit": denied.limit,
        "used": denied.used,
        "reserved": denied.reserved,
        "remaining_before": denied.remaining_before,
    }))
}

/// Resolve the quota limit for a meter from the assembled entitlement quotas: the
/// cadence-qualified key (`cloud_tokens.monthly`) wins over the bare meter key.
/// `None` means the meter is uncapped for this customer.
async fn meter_quota_limit(
    state: &AppState,
    customer_id: Uuid,
    product_key: &str,
    meter: &usage_repo::MeterRow,
) -> AppResult<Option<f64>> {
    let loaded = crate::repositories::entitlements::load_entitlement_inputs(
        &state.pool,
        customer_id,
        product_key,
    )
    .await?
    .ok_or_else(|| AppError::not_found("Unknown or inactive product."))?;
    let result = crate::domain::entitlement::evaluate(&loaded.inputs);
    let [primary, fallback] = quota_key_candidates(&meter.key, &meter.reset_cadence);
    Ok(result
        .quotas
        .get(&primary)
        .or_else(|| result.quotas.get(&fallback))
        .copied())
}

fn clean_meter_key(value: &str) -> AppResult<String> {
    clean_entitlement_key(value).map_err(|message| {
        AppError::validation(message).with_details(json!({ "field": "meter_key" }))
    })
}

fn clean_amount(value: f64) -> AppResult<f64> {
    clean_usage_amount(value)
        .map_err(|message| AppError::validation(message).with_details(json!({ "field": "amount" })))
}

#[derive(Debug, Deserialize)]
struct UsageCheckRequest {
    meter_key: String,
    amount: Option<f64>,
    product_key: Option<String>,
}

async fn usage_check(
    ctx: CustomerContext,
    State(state): State<AppState>,
    Json(request): Json<UsageCheckRequest>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let product_key = entitlements::clean_product_key(request.product_key.as_deref())?;
    let meter_key = clean_meter_key(&request.meter_key)?;
    let amount = match request.amount {
        Some(amount) => clean_amount(amount)?,
        None => 0.0,
    };

    let meter = usage_repo::find_meter(&state.pool, &meter_key)
        .await?
        .ok_or_else(|| AppError::not_found("Unknown usage meter."))?;
    let limit = meter_quota_limit(&state, customer_id, &product_key, &meter).await?;
    let period_key = period_key_for(&meter.reset_cadence, chrono::Utc::now());
    let (used, reserved) =
        usage_repo::read_totals(&state.pool, customer_id, &meter_key, &period_key).await?;

    let decision = decide(amount, used, reserved, limit);
    Ok(Json(json!({
        "meter_key": meter_key,
        "period_key": period_key,
        "allowed": decision.decision == Decision::Allow,
        "requested": amount,
        "limit": limit,
        "used": used,
        "reserved": reserved,
        "remaining_before": decision.remaining_before,
        "reason": decision.reason,
    })))
}

#[derive(Debug, Deserialize)]
struct UsageReserveRequest {
    meter_key: String,
    amount: f64,
    product_key: Option<String>,
}

async fn usage_reserve(
    ctx: CustomerContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Json(request): Json<UsageReserveRequest>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let key = idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Usage reservations require an Idempotency-Key header.")
    })?;
    let product_key = entitlements::clean_product_key(request.product_key.as_deref())?;
    let meter_key = clean_meter_key(&request.meter_key)?;
    let amount = clean_amount(request.amount)?;

    let meter = usage_repo::find_meter(&state.pool, &meter_key)
        .await?
        .ok_or_else(|| AppError::not_found("Unknown usage meter."))?;
    let limit = meter_quota_limit(&state, customer_id, &product_key, &meter).await?;
    let period_key = period_key_for(&meter.reset_cadence, chrono::Utc::now());
    let ttl = chrono::Duration::from_std(state.config.usage_reservation_ttl)
        .map_err(|_| AppError::internal("Invalid reservation TTL configuration."))?;

    let outcome = usage_repo::reserve(
        &state.pool,
        usage_repo::ReserveInput {
            customer_id,
            meter_key: &meter_key,
            amount,
            limit,
            period_key: &period_key,
            ttl,
            idempotency_key: key,
            correlation_id: correlation_id(&correlation),
        },
    )
    .await
    .map_err(usage_error)?;

    match outcome {
        usage_repo::ReserveOutcome::Reserved(reservation) => Ok(Json(json!({
            "reservation": reservation,
            "replayed": false,
        }))),
        usage_repo::ReserveOutcome::Replayed(reservation) => Ok(Json(json!({
            "reservation": reservation,
            "replayed": true,
        }))),
        usage_repo::ReserveOutcome::Denied(denied) => Err(quota_exceeded(denied)),
    }
}

#[derive(Debug, Deserialize)]
struct UsageCommitRequest {
    reservation_id: Option<String>,
    meter_key: Option<String>,
    amount: Option<f64>,
    product_key: Option<String>,
}

async fn usage_commit(
    ctx: CustomerContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Json(request): Json<UsageCommitRequest>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let key = idempotency_key(&headers)
        .ok_or_else(|| AppError::bad_request("Usage commits require an Idempotency-Key header."))?;
    let product_key = entitlements::clean_product_key(request.product_key.as_deref())?;

    // Resolve the mode and the meter/limit/period it charges against. Reservation
    // commits charge the reservation's own period; direct commits charge now.
    let (mode, meter, period_key) = match (&request.reservation_id, &request.meter_key) {
        (Some(raw), None) => {
            let reservation_id = Uuid::parse_str(raw.trim()).map_err(|_| {
                AppError::validation("must be a UUID")
                    .with_details(json!({ "field": "reservation_id" }))
            })?;
            let reservation =
                usage_repo::find_reservation(&state.pool, customer_id, reservation_id)
                    .await?
                    .ok_or_else(|| AppError::not_found("Reservation not found."))?;
            let meter = usage_repo::find_meter(&state.pool, &reservation.meter_key)
                .await?
                .ok_or_else(|| AppError::not_found("Unknown usage meter."))?;
            (
                usage_repo::CommitMode::Reservation(reservation_id),
                meter,
                reservation.period_key,
            )
        }
        (None, Some(raw_meter)) => {
            let meter_key = clean_meter_key(raw_meter)?;
            let amount = clean_amount(request.amount.ok_or_else(|| {
                AppError::validation("is required for direct commits")
                    .with_details(json!({ "field": "amount" }))
            })?)?;
            let meter = usage_repo::find_meter(&state.pool, &meter_key)
                .await?
                .ok_or_else(|| AppError::not_found("Unknown usage meter."))?;
            let period_key = period_key_for(&meter.reset_cadence, chrono::Utc::now());
            (
                usage_repo::CommitMode::Direct { meter_key, amount },
                meter,
                period_key,
            )
        }
        _ => {
            return Err(
                AppError::validation("Provide reservation_id, or meter_key with amount.")
                    .with_details(json!({ "field": "reservation_id" })),
            );
        }
    };

    let limit = meter_quota_limit(&state, customer_id, &product_key, &meter).await?;
    let outcome = usage_repo::commit(
        &state.pool,
        usage_repo::CommitInput {
            customer_id,
            mode,
            limit,
            period_key: &period_key,
            threshold_percents: &state.config.usage_threshold_percents,
            idempotency_key: key,
            correlation_id: correlation_id(&correlation),
        },
    )
    .await
    .map_err(usage_error)?;

    match outcome {
        usage_repo::CommitOutcome::Committed {
            event,
            used_after,
            thresholds_crossed,
        } => Ok(Json(json!({
            "event": event,
            "used_after": used_after,
            "thresholds_crossed": thresholds_crossed,
            "replayed": false,
        }))),
        usage_repo::CommitOutcome::Replayed(event) => Ok(Json(json!({
            "event": event,
            "replayed": true,
        }))),
        usage_repo::CommitOutcome::Denied(denied) => Err(quota_exceeded(denied)),
    }
}

#[derive(Debug, Deserialize)]
struct UsageReleaseRequest {
    reservation_id: String,
}

async fn usage_release(
    ctx: CustomerContext,
    State(state): State<AppState>,
    Json(request): Json<UsageReleaseRequest>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let reservation_id = Uuid::parse_str(request.reservation_id.trim()).map_err(|_| {
        AppError::validation("must be a UUID").with_details(json!({ "field": "reservation_id" }))
    })?;

    let outcome = usage_repo::release(&state.pool, customer_id, reservation_id)
        .await?
        .ok_or_else(|| AppError::not_found("Reservation not found."))?;
    match outcome {
        usage_repo::ReleaseOutcome::Released { amount } => Ok(Json(json!({
            "reservation_id": reservation_id,
            "status": "released",
            "released_amount": amount,
            "changed": true,
        }))),
        usage_repo::ReleaseOutcome::AlreadyTerminal { status } => Ok(Json(json!({
            "reservation_id": reservation_id,
            "status": status,
            "changed": false,
        }))),
    }
}

#[derive(Debug, Default, Deserialize)]
struct UsageCurrentQuery {
    product_key: Option<String>,
}

async fn usage_current(
    ctx: CustomerContext,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<UsageCurrentQuery>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let product_key = entitlements::clean_product_key(query.product_key.as_deref())?;

    let loaded = crate::repositories::entitlements::load_entitlement_inputs(
        &state.pool,
        customer_id,
        &product_key,
    )
    .await?
    .ok_or_else(|| AppError::not_found("Unknown or inactive product."))?;
    let result = crate::domain::entitlement::evaluate(&loaded.inputs);

    let rows = usage_repo::current_usage(&state.pool, customer_id).await?;
    let meters: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let [primary, fallback] = quota_key_candidates(&row.meter_key, &row.reset_cadence);
            let limit = result
                .quotas
                .get(&primary)
                .or_else(|| result.quotas.get(&fallback))
                .copied();
            let remaining = limit.map(|limit| limit - row.used - row.reserved);
            json!({
                "meter_key": row.meter_key,
                "unit": row.unit,
                "reset_cadence": row.reset_cadence,
                "period_key": row.period_key,
                "used": row.used,
                "reserved": row.reserved,
                "limit": limit,
                "remaining": remaining,
            })
        })
        .collect();

    Ok(Json(json!({ "product_key": product_key, "usage": meters })))
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
        &state.config.stripe_api_base,
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

// --- Admin endpoints (Forge Command surface; auth via AdminContext) --------
//
// Reads require any valid operator token; mutations additionally require the `admin`
// operator role and a written reason that lands in commercial audit.

fn admin_validation_error(error: crate::domain::admin::AdminValidationError) -> AppError {
    AppError::validation(error.message).with_details(json!({ "field": error.field }))
}

fn admin_error(error: admin::AdminError) -> AppError {
    match error {
        admin::AdminError::CustomerNotFound => AppError::not_found("Customer not found."),
        admin::AdminError::ProductNotFound => AppError::not_found("Unknown or inactive product."),
        admin::AdminError::LicenseNotFound => AppError::not_found("License not found."),
        admin::AdminError::MeterNotFound => AppError::not_found("Unknown usage meter."),
        admin::AdminError::Db(error) => error.into(),
    }
}

fn subscription_fetch_error(error: SubscriptionFetchError) -> AppError {
    match error {
        SubscriptionFetchError::NotConfigured => {
            AppError::new(ErrorCode::Internal, "Stripe API access is not configured.")
        }
        SubscriptionFetchError::ApiStatus(404) => {
            AppError::not_found("Stripe no longer knows this subscription.")
        }
        SubscriptionFetchError::ApiStatus(_) | SubscriptionFetchError::Transport(_) => {
            AppError::new(
                ErrorCode::ServiceUnavailable,
                "Stripe is currently unavailable for resync.",
            )
            .with_details(json!({ "reason": error.to_string() }))
        }
        SubscriptionFetchError::MalformedResponse => {
            AppError::internal("Stripe returned an unusable subscription payload.")
        }
    }
}

fn parse_rfc3339(
    value: Option<&str>,
    field: &'static str,
) -> AppResult<Option<chrono::DateTime<chrono::Utc>>> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(raw) => chrono::DateTime::parse_from_rfc3339(raw)
            .map(|value| Some(value.with_timezone(&chrono::Utc)))
            .map_err(|_| {
                AppError::validation("must be an RFC 3339 timestamp")
                    .with_details(json!({ "field": field }))
            }),
        None => Ok(None),
    }
}

#[derive(Debug, Default, Deserialize)]
struct AdminCustomersQuery {
    email: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn admin_customers(
    _admin: AdminContext,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AdminCustomersQuery>,
) -> AppResult<Json<Value>> {
    let email = match query.email.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => {
            if value.len() > 320 || !value.contains('@') {
                return Err(AppError::validation("must be an email address")
                    .with_details(json!({ "field": "email" })));
            }
            Some(value)
        }
        _ => None,
    };
    let status = match query.status.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => {
            if !matches!(
                value,
                "pending" | "active" | "suspended" | "closed" | "anonymized"
            ) {
                return Err(AppError::validation("unknown customer status")
                    .with_details(json!({ "field": "status" })));
            }
            Some(value)
        }
        _ => None,
    };
    let limit = query.limit.unwrap_or(25).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).clamp(0, 100_000);

    let customers = admin::list_customers(
        &state.pool,
        admin::CustomerFilter {
            email,
            status,
            limit,
            offset,
        },
    )
    .await?;
    Ok(Json(json!({ "customers": customers })))
}

#[derive(Debug, Deserialize)]
struct AdminReasonRequest {
    reason: String,
}

async fn admin_suspend(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let customer_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let outcome = admin::suspend_customer(
        &state.pool,
        &operator.operator_id,
        customer_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({
        "customer_id": outcome.customer_id,
        "from_status": outcome.from_status,
        "status": outcome.status,
        "changed": outcome.changed,
    })))
}

async fn admin_restore(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let customer_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let outcome = admin::restore_customer(
        &state.pool,
        &operator.operator_id,
        customer_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({
        "customer_id": outcome.customer_id,
        "from_status": outcome.from_status,
        "status": outcome.status,
        "changed": outcome.changed,
    })))
}

async fn admin_resync(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let subscription_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let target = commerce::find_subscription_for_resync(&state.pool, subscription_id)
        .await?
        .ok_or_else(|| AppError::not_found("Subscription not found."))?;
    let change = fetch_subscription(
        &state.http,
        &state.config.stripe_api_base,
        &state.config.stripe_secret_key,
        &target.stripe_subscription_id,
    )
    .await
    .map_err(subscription_fetch_error)?;

    let outcome = commerce::apply_admin_resync(
        &state.pool,
        target.id,
        &change,
        &operator.operator_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(stripe_webhook_apply_error)?
    .ok_or_else(|| AppError::not_found("Subscription not found."))?;

    Ok(Json(json!({
        "subscription_id": outcome.subscription_id,
        "customer_id": outcome.customer_id,
        "status": outcome.status,
        "changed": outcome.changed,
        "license_change": outcome.license_change,
    })))
}

#[derive(Debug, Deserialize)]
struct AdminIssueLicenseRequest {
    customer_id: String,
    product_key: Option<String>,
    device_limit: Option<i64>,
    expires_at: Option<String>,
    reason: String,
}

async fn admin_issue_license(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Json(request): Json<AdminIssueLicenseRequest>,
) -> AppResult<Json<admin::IssuedLicenseRow>> {
    operator.require_role("admin")?;
    let customer_id = Uuid::parse_str(request.customer_id.trim()).map_err(|_| {
        AppError::validation("must be a UUID").with_details(json!({ "field": "customer_id" }))
    })?;
    let product_key = entitlements::clean_product_key(request.product_key.as_deref())?;
    let device_limit = clean_device_limit(request.device_limit).map_err(admin_validation_error)?;
    let expires_at = parse_rfc3339(request.expires_at.as_deref(), "expires_at")?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let license = admin::issue_license(
        &state.pool,
        admin::IssueLicenseInput {
            operator_id: &operator.operator_id,
            customer_id,
            product_key: &product_key,
            device_limit,
            expires_at,
            reason: &reason,
            correlation_id: correlation_id(&correlation),
        },
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(license))
}

async fn admin_revoke_license(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let license_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let outcome = admin::revoke_license(
        &state.pool,
        &operator.operator_id,
        license_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({
        "license_id": outcome.license_id,
        "customer_id": outcome.customer_id,
        "status": outcome.status,
        "changed": outcome.changed,
    })))
}

#[derive(Debug, Deserialize)]
struct AdminOverrideRequest {
    customer_id: String,
    product_key: Option<String>,
    feature_key: Option<String>,
    quota_key: Option<String>,
    /// Omit (or send null) to clear the active override(s) for the key.
    value: Option<Value>,
    expires_at: Option<String>,
    reason: String,
}

async fn admin_override(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Json(request): Json<AdminOverrideRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let customer_id = Uuid::parse_str(request.customer_id.trim()).map_err(|_| {
        AppError::validation("must be a UUID").with_details(json!({ "field": "customer_id" }))
    })?;
    let product_key = entitlements::clean_product_key(request.product_key.as_deref())?;
    let (field, raw_key) = match (&request.feature_key, &request.quota_key) {
        (Some(feature), None) => ("feature_key", feature.as_str()),
        (None, Some(quota)) => ("quota_key", quota.as_str()),
        _ => {
            return Err(
                AppError::validation("Provide exactly one of feature_key or quota_key.")
                    .with_details(json!({ "field": "feature_key" })),
            );
        }
    };
    let key = clean_entitlement_key(raw_key)
        .map_err(|message| AppError::validation(message).with_details(json!({ "field": field })))?;
    let value = match &request.value {
        Some(Value::Null) | None => None,
        Some(value) => Some(clean_override_value(value).map_err(admin_validation_error)?),
    };
    let expires_at = parse_rfc3339(request.expires_at.as_deref(), "expires_at")?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let outcome = admin::set_entitlement_override(
        &state.pool,
        &operator.operator_id,
        admin::OverrideInput {
            customer_id,
            product_key: &product_key,
            feature_key: (field == "feature_key").then_some(key.as_str()),
            quota_key: (field == "quota_key").then_some(key.as_str()),
            value,
            expires_at,
            reason: &reason,
        },
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({
        "override_id": outcome.override_id,
        "cleared_overrides": outcome.cleared,
        "key": key,
    })))
}

#[derive(Debug, Deserialize)]
struct AdminUsageAdjustRequest {
    customer_id: String,
    meter_key: String,
    amount: f64,
    period_key: Option<String>,
    reason: String,
}

async fn admin_usage_adjust(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Json(request): Json<AdminUsageAdjustRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let key = idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Usage adjustments require an Idempotency-Key header.")
    })?;
    let customer_id = Uuid::parse_str(request.customer_id.trim()).map_err(|_| {
        AppError::validation("must be a UUID").with_details(json!({ "field": "customer_id" }))
    })?;
    let meter_key = clean_entitlement_key(&request.meter_key).map_err(|message| {
        AppError::validation(message).with_details(json!({ "field": "meter_key" }))
    })?;
    let amount = clean_adjustment_amount(request.amount).map_err(admin_validation_error)?;
    let period_key =
        clean_period_key(request.period_key.as_deref()).map_err(admin_validation_error)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let outcome = admin::adjust_usage(
        &state.pool,
        admin::UsageAdjustmentInput {
            operator_id: &operator.operator_id,
            customer_id,
            meter_key: &meter_key,
            amount,
            period_key: &period_key,
            idempotency_key: key,
            reason: &reason,
            correlation_id: correlation_id(&correlation),
        },
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({
        "usage_event_id": outcome.usage_event_id,
        "customer_id": outcome.customer_id,
        "meter_key": outcome.meter_key,
        "period_key": outcome.period_key,
        "amount": outcome.amount,
        "replayed": outcome.replayed,
    })))
}

#[derive(Debug, Default, Deserialize)]
struct AdminDeletionListQuery {
    status: Option<String>,
    limit: Option<i64>,
}

async fn admin_deletion_list(
    _admin: AdminContext,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AdminDeletionListQuery>,
) -> AppResult<Json<Value>> {
    let status = match query.status.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => {
            if !matches!(
                value,
                "requested"
                    | "verified"
                    | "cooling_off"
                    | "processing"
                    | "completed"
                    | "rejected"
                    | "canceled"
            ) {
                return Err(AppError::validation("unknown deletion request status")
                    .with_details(json!({ "field": "status" })));
            }
            Some(value)
        }
        _ => None,
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 200);

    let requests = privacy::list_requests(&state.pool, status, limit).await?;
    Ok(Json(json!({ "requests": requests })))
}

async fn admin_deletion_advance(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let request_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let cooling_off = chrono::Duration::from_std(state.config.deletion_cooling_off)
        .map_err(|_| AppError::internal("Invalid cooling-off configuration."))?;

    let updated = privacy::advance_request(
        &state.pool,
        &operator.operator_id,
        request_id,
        cooling_off,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(deletion_error)?;
    Ok(Json(json!({ "request": updated })))
}

async fn admin_deletion_reject(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let request_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let updated = privacy::reject_request(
        &state.pool,
        &operator.operator_id,
        request_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(deletion_error)?;
    Ok(Json(json!({ "request": updated })))
}

async fn admin_deletion_execute(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    let request_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let updated = privacy::execute_deletion(
        &state.pool,
        &operator.operator_id,
        request_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(deletion_error)?;
    Ok(Json(json!({ "request": updated })))
}

#[derive(Debug, Default, Deserialize)]
struct AdminAuditQuery {
    customer_id: Option<String>,
    event_type: Option<String>,
    limit: Option<i64>,
}

async fn admin_audit(
    _admin: AdminContext,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AdminAuditQuery>,
) -> AppResult<Json<Value>> {
    let customer_id = match query.customer_id.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => Some(Uuid::parse_str(value).map_err(|_| {
            AppError::validation("must be a UUID").with_details(json!({ "field": "customer_id" }))
        })?),
        _ => None,
    };
    let event_type = match query.event_type.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => {
            Some(clean_entitlement_key(value).map_err(|message| {
                AppError::validation(message).with_details(json!({ "field": "event_type" }))
            })?)
        }
        _ => None,
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 200);

    let events = admin::list_audit_events(
        &state.pool,
        admin::AuditFilter {
            customer_id,
            event_type: event_type.as_deref(),
            limit,
        },
    )
    .await?;
    Ok(Json(json!({ "events": events })))
}
