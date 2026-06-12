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
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::auth::{AdminContext, AuthUserContext, CustomerContext};
use crate::domain::admin::{
    clean_adjustment_amount, clean_artifact_architecture, clean_artifact_platform,
    clean_artifact_role, clean_build_id, clean_campaign_slug, clean_device_limit,
    clean_optional_display_name, clean_optional_markdown, clean_os_signature_status,
    clean_override_value, clean_package_format, clean_period_key, clean_reason,
    clean_release_channel_key, clean_release_version, clean_rollout_percentage, clean_sha256,
    clean_signing_key_id, clean_size_bytes, clean_storage_key, clean_tauri_signature,
    clean_update_ring,
};
use crate::domain::checkout::{validate_checkout_input, CheckoutInput};
use crate::domain::customer::{
    normalize_email_claim, validate_provision_profile, ProvisionProfileInput,
};
use crate::domain::entitlement::clean_entitlement_key;
use crate::domain::installation::{clean_app_version, validate_registration, RegistrationInput};
use crate::domain::updates::{
    clean_update_architecture, clean_update_event_type, clean_update_failure_code,
    clean_update_package_format, clean_update_platform, rollout_allows, version_at_least,
    version_greater, UpdateValidationError,
};
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
use crate::repositories::updates as update_repo;
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
        .route(
            "/v1/products/:product_key/releases/latest",
            get(public_latest_release),
        )
        .route(
            "/v1/products/:product_key/downloads",
            get(public_bootstrap_download),
        )
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
        .route(
            "/v1/installations/:id/update-events",
            post(installation_update_event),
        )
        .route(
            "/v1/updates/authorforge/:target/:arch/:current_version",
            get(authorforge_update_check),
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
        .route("/v1/admin/fleets", get(admin_fleets))
        .route("/v1/admin/fleets/:id", get(admin_fleet))
        .route("/v1/admin/fleets/:id/policy", post(admin_fleet_policy))
        .route(
            "/v1/admin/releases",
            get(admin_releases).post(admin_release_create),
        )
        .route("/v1/admin/releases/:id", get(admin_release))
        .route(
            "/v1/admin/releases/:id/artifacts",
            post(admin_release_artifact_register),
        )
        .route(
            "/v1/admin/releases/:id/validate",
            post(admin_release_validate),
        )
        .route(
            "/v1/admin/releases/:id/publish",
            post(admin_release_publish),
        )
        .route("/v1/admin/releases/:id/block", post(admin_release_block))
        .route(
            "/v1/admin/update-campaigns",
            post(admin_update_campaign_create),
        )
        .route("/v1/admin/update-campaigns/:id", get(admin_update_campaign))
        .route(
            "/v1/admin/update-campaigns/:id/pause",
            post(admin_update_campaign_pause),
        )
        .route(
            "/v1/admin/update-campaigns/:id/resume",
            post(admin_update_campaign_resume),
        )
        .route(
            "/v1/admin/update-campaigns/:id/revoke",
            post(admin_update_campaign_revoke),
        )
        .route(
            "/v1/admin/update-campaigns/:id/rollout",
            post(admin_update_campaign_rollout),
        )
        .route(
            "/v1/admin/update-campaigns/:campaign_id/holds",
            post(admin_update_campaign_hold_add),
        )
        .route(
            "/v1/admin/update-campaigns/:campaign_id/holds/:fleet_id",
            delete(admin_update_campaign_hold_remove),
        )
        .route("/v1/admin/update-failures", get(admin_update_failures))
        .route(
            "/v1/admin/release-artifacts/:id/quarantine",
            post(admin_release_artifact_quarantine),
        )
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
    default_fleet_id: Uuid,
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
    build_id: Option<String>,
    platform: Option<String>,
    architecture: Option<String>,
    package_format: Option<String>,
    updater_version: Option<String>,
    device_public_key: Option<String>,
    device_label: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstallationRegisterResponse {
    installation_id: Uuid,
    fleet_id: Option<Uuid>,
    install_key: String,
    product_key: String,
    app_version: Option<String>,
    build_id: Option<String>,
    platform: Option<String>,
    architecture: Option<String>,
    package_format: Option<String>,
    updater_version: Option<String>,
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
struct TauriUpdateResponse {
    version: String,
    url: String,
    signature: String,
    notes: Option<String>,
    pub_date: String,
}

#[derive(Debug, Default, Deserialize)]
struct PublicLatestReleaseQuery {
    channel: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicDownloadQuery {
    platform: String,
    arch: String,
    channel: Option<String>,
    package_format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationUpdateEventRequest {
    campaign_id: Option<Uuid>,
    release_id: Option<Uuid>,
    event_type: String,
    from_version: Option<String>,
    from_build_id: Option<String>,
    to_version: Option<String>,
    to_build_id: Option<String>,
    failure_code: Option<String>,
    failure_class: Option<String>,
    occurred_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminReleaseCreateRequest {
    product_key: String,
    version: String,
    build_id: String,
    release_channel: Option<String>,
    release_channel_key: Option<String>,
    changelog_markdown: Option<String>,
    release_notes: Option<String>,
    minimum_supported_version: Option<String>,
    minimum_updater_version: Option<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct AdminArtifactRegisterRequest {
    platform: String,
    architecture: String,
    package_format: String,
    artifact_role: String,
    storage_key: String,
    size_bytes: i64,
    sha256: String,
    tauri_signature: Option<String>,
    signing_key_id: String,
    os_signature_status: String,
    reason: String,
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

fn clean_public_release_channel(value: Option<&str>) -> AppResult<String> {
    clean_release_channel_key(value.unwrap_or("stable")).map_err(admin_validation_error)
}

async fn public_latest_release(
    State(state): State<AppState>,
    Path(product_key): Path<String>,
    Query(query): Query<PublicLatestReleaseQuery>,
) -> AppResult<Json<Value>> {
    let product_key = entitlements::clean_product_key(Some(&product_key))?;
    let channel = clean_public_release_channel(query.channel.as_deref())?;
    let release = update_repo::latest_published_release(&state.pool, &product_key, &channel)
        .await?
        .ok_or_else(|| AppError::not_found("Published release not found."))?;
    Ok(Json(json!({ "release": release })))
}

async fn public_bootstrap_download(
    State(state): State<AppState>,
    Path(product_key): Path<String>,
    Query(query): Query<PublicDownloadQuery>,
) -> AppResult<Json<Value>> {
    let product_key = entitlements::clean_product_key(Some(&product_key))?;
    let channel = clean_public_release_channel(query.channel.as_deref())?;
    let platform = clean_artifact_platform(&query.platform).map_err(admin_validation_error)?;
    let architecture = clean_artifact_architecture(&query.arch).map_err(admin_validation_error)?;
    let package_format = match query.package_format.as_deref() {
        Some(value) => Some(clean_package_format(value).map_err(admin_validation_error)?),
        None => None,
    };

    let download = update_repo::bootstrap_download(
        &state.pool,
        update_repo::BootstrapDownloadInput {
            product_key: &product_key,
            channel_key: &channel,
            platform: &platform,
            architecture: &architecture,
            package_format: package_format.as_deref(),
        },
    )
    .await?
    .ok_or_else(|| AppError::not_found("Bootstrap download not found."))?;

    Ok(Json(json!({
        "product_key": download.product_key,
        "version": download.version,
        "build_id": download.build_id,
        "release_channel": download.release_channel_key,
        "platform": download.platform,
        "architecture": download.architecture,
        "package_format": download.package_format,
        "download_url": artifact_url(&state, &download.storage_key)?,
        "sha256": download.sha256,
        "size_bytes": download.size_bytes,
        "release_notes": download.release_notes,
        "published_at": download.published_at,
    })))
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
        default_fleet_id: provisioned.default_fleet_id,
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
        build_id: request.build_id.as_deref(),
        platform: request.platform.as_deref(),
        architecture: request.architecture.as_deref(),
        package_format: request.package_format.as_deref(),
        updater_version: request.updater_version.as_deref(),
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
        fleet_id: installation.fleet_id,
        install_key: installation.install_key,
        product_key: installation.product_key,
        app_version: installation.app_version,
        build_id: installation.build_id,
        platform: installation.platform,
        architecture: installation.architecture,
        package_format: installation.package_format,
        updater_version: installation.updater_version,
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

fn update_validation_error(error: UpdateValidationError) -> AppError {
    AppError::validation(error.message).with_details(json!({ "field": error.field }))
}

fn update_event_error(error: update_repo::UpdateEventError) -> AppError {
    match error {
        update_repo::UpdateEventError::InstallationNotFound => {
            AppError::not_found("Installation not found.")
        }
        update_repo::UpdateEventError::CampaignNotFound => {
            AppError::not_found("Update campaign not found.")
        }
        update_repo::UpdateEventError::ReleaseNotFound => AppError::not_found("Release not found."),
        update_repo::UpdateEventError::InvalidCampaignRelease => AppError::new(
            ErrorCode::Conflict,
            "Update campaign does not target the supplied release.",
        ),
        update_repo::UpdateEventError::Db(error) => error.into(),
    }
}

fn required_header(headers: &HeaderMap, name: &'static str) -> AppResult<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            AppError::bad_request(format!("{name} header is required."))
                .with_details(json!({ "field": name }))
        })
}

fn optional_header(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn parse_uuid_header(value: &str, field: &'static str) -> AppResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| {
        AppError::bad_request("header must be a UUID").with_details(json!({ "field": field }))
    })
}

fn clean_optional_update_version(
    value: Option<&str>,
    field: &'static str,
) -> AppResult<Option<String>> {
    clean_app_version(value).map_err(|error| {
        AppError::validation(error.message).with_details(json!({ "field": field }))
    })
}

fn artifact_url(state: &AppState, storage_key: &str) -> AppResult<String> {
    let storage_key = storage_key.trim();
    if storage_key.starts_with("https://") || storage_key.starts_with("http://") {
        return Ok(storage_key.to_string());
    }
    let base = state.config.release_artifact_base_url.trim();
    if base.is_empty() {
        return Err(AppError::new(
            ErrorCode::ServiceUnavailable,
            "Release artifact URL base is not configured.",
        ));
    }
    Ok(format!(
        "{}/{}",
        base.trim_end_matches('/'),
        storage_key.trim_start_matches('/')
    ))
}

async fn authorforge_update_check(
    ctx: CustomerContext,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((target, arch, current_version)): Path<(String, String, String)>,
) -> AppResult<Response> {
    let customer_id = ctx.require_active()?;
    let rollout_secret = state.config.update_rollout_secret.trim();
    if rollout_secret.is_empty() {
        return Err(AppError::new(
            ErrorCode::ServiceUnavailable,
            "Update rollout secret is not configured.",
        ));
    }

    let installation_header = required_header(&headers, "x-forge-installation-id")?;
    let installation_id = parse_uuid_header(&installation_header, "x-forge-installation-id")?;
    let current_build_id = clean_update_failure_code(
        optional_header(&headers, "x-forge-build-id").as_deref(),
        "x-forge-build-id",
    )
    .map_err(update_validation_error)?;
    let updater_version = clean_optional_update_version(
        optional_header(&headers, "x-forge-updater-version").as_deref(),
        "x-forge-updater-version",
    )?;
    let package_format =
        clean_update_package_format(optional_header(&headers, "x-forge-package-format").as_deref())
            .map_err(update_validation_error)?;
    let platform = clean_update_platform(&target).map_err(update_validation_error)?;
    let architecture = clean_update_architecture(&arch).map_err(update_validation_error)?;
    let current_version = clean_optional_update_version(Some(&current_version), "current_version")?
        .ok_or_else(|| {
            AppError::validation("current_version is required")
                .with_details(json!({ "field": "current_version" }))
        })?;

    let candidates = update_repo::candidate_rows(
        &state.pool,
        update_repo::UpdateLookupInput {
            customer_id,
            installation_id,
            product_key: "authorforge",
            platform: &platform,
            architecture: &architecture,
            package_format: &package_format,
        },
    )
    .await?;

    for candidate in candidates {
        let Some(signature) = candidate
            .tauri_signature
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(published_at) = candidate.published_at else {
            continue;
        };
        if !version_greater(&candidate.version, &current_version) {
            continue;
        }
        if let Some(minimum) = candidate.minimum_supported_version.as_deref() {
            if !version_at_least(&current_version, minimum) {
                continue;
            }
        }
        if let Some(minimum) = candidate.minimum_updater_version.as_deref() {
            let Some(updater_version) = updater_version.as_deref() else {
                continue;
            };
            if !version_at_least(updater_version, minimum) {
                continue;
            }
        }
        if current_build_id.as_deref() == Some(candidate.build_id.as_str()) {
            continue;
        }
        if !rollout_allows(
            rollout_secret,
            candidate.campaign_id,
            installation_id,
            candidate.rollout_percentage,
        )
        .map_err(update_validation_error)?
        {
            continue;
        }

        let response = TauriUpdateResponse {
            version: candidate.version,
            url: artifact_url(&state, &candidate.storage_key)?,
            signature: signature.to_string(),
            notes: candidate.changelog_markdown,
            pub_date: published_at.to_rfc3339(),
        };
        return Ok(Json(response).into_response());
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn installation_update_event(
    ctx: CustomerContext,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<InstallationUpdateEventRequest>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let installation_id = parse_path_id(&id)?;
    let event_id_raw = idempotency_key(&headers)
        .ok_or_else(|| AppError::bad_request("Update events require an Idempotency-Key header."))?;
    let event_id = Uuid::parse_str(event_id_raw).map_err(|_| {
        AppError::bad_request("Idempotency-Key must be the update event UUID.")
            .with_details(json!({ "field": "idempotency-key" }))
    })?;
    let event_type =
        clean_update_event_type(&request.event_type).map_err(update_validation_error)?;
    let from_version =
        clean_optional_update_version(request.from_version.as_deref(), "from_version")?;
    let to_version = clean_optional_update_version(request.to_version.as_deref(), "to_version")?;
    let from_build_id =
        clean_update_failure_code(request.from_build_id.as_deref(), "from_build_id")
            .map_err(update_validation_error)?;
    let to_build_id = clean_update_failure_code(request.to_build_id.as_deref(), "to_build_id")
        .map_err(update_validation_error)?;
    let failure_code = clean_update_failure_code(request.failure_code.as_deref(), "failure_code")
        .map_err(update_validation_error)?;
    let failure_class =
        clean_update_failure_code(request.failure_class.as_deref(), "failure_class")
            .map_err(update_validation_error)?;
    let occurred_at = parse_rfc3339(request.occurred_at.as_deref(), "occurred_at")?
        .unwrap_or_else(chrono::Utc::now);

    let receipt = update_repo::record_update_event(
        &state.pool,
        update_repo::UpdateEventInput {
            event_id,
            customer_id,
            installation_id,
            campaign_id: request.campaign_id,
            release_id: request.release_id,
            event_type: &event_type,
            from_version: from_version.as_deref(),
            from_build_id: from_build_id.as_deref(),
            to_version: to_version.as_deref(),
            to_build_id: to_build_id.as_deref(),
            failure_code: failure_code.as_deref(),
            failure_class: failure_class.as_deref(),
            occurred_at,
        },
    )
    .await
    .map_err(update_event_error)?;

    Ok(Json(json!({
        "event_id": receipt.event_id,
        "event_type": receipt.event_type,
        "received": receipt.received,
    })))
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
        admin::AdminError::FleetNotFound => AppError::not_found("Fleet not found."),
        admin::AdminError::ReleaseNotFound => AppError::not_found("Release not found."),
        admin::AdminError::CampaignNotFound => AppError::not_found("Update campaign not found."),
        admin::AdminError::ArtifactNotFound => AppError::not_found("Release artifact not found."),
        admin::AdminError::FleetHoldNotFound => AppError::not_found("Fleet hold not found."),
        admin::AdminError::InvalidState(message) => AppError::new(ErrorCode::Conflict, message),
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

async fn admin_fleets(
    _admin: AdminContext,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let fleets = admin::list_fleets(&state.pool).await?;
    Ok(Json(json!({ "fleets": fleets })))
}

async fn admin_fleet(
    _admin: AdminContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let fleet_id = parse_path_id(&id)?;
    let fleet = admin::read_fleet(&state.pool, fleet_id)
        .await?
        .ok_or_else(|| AppError::not_found("Fleet not found."))?;
    Ok(Json(json!({ "fleet": fleet })))
}

#[derive(Debug, Default, Deserialize)]
struct AdminFleetPolicyRequest {
    display_name: Option<String>,
    update_ring: Option<String>,
    release_channel: Option<String>,
    release_channel_key: Option<String>,
    beta_enrolled: Option<bool>,
    reason: String,
}

async fn admin_fleet_policy(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminFleetPolicyRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Fleet policy updates require an Idempotency-Key header.")
    })?;
    let fleet_id = parse_path_id(&id)?;
    let display_name = clean_optional_display_name(request.display_name.as_deref())
        .map_err(admin_validation_error)?;
    let update_ring = match request.update_ring.as_deref() {
        Some(value) => Some(clean_update_ring(value).map_err(admin_validation_error)?),
        None => None,
    };
    let channel_raw = request
        .release_channel
        .as_deref()
        .or(request.release_channel_key.as_deref());
    let release_channel_key = match channel_raw {
        Some(value) => Some(clean_release_channel_key(value).map_err(admin_validation_error)?),
        None => None,
    };
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let fleet = admin::update_fleet_policy(
        &state.pool,
        admin::UpdateFleetPolicyInput {
            operator_id: &operator.operator_id,
            fleet_id,
            display_name: display_name.as_deref(),
            update_ring: update_ring.as_deref(),
            release_channel_key: release_channel_key.as_deref(),
            beta_enrolled: request.beta_enrolled,
            reason: &reason,
            correlation_id: correlation_id(&correlation),
        },
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "fleet": fleet })))
}

async fn admin_releases(
    _admin: AdminContext,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let releases = admin::list_releases(&state.pool).await?;
    Ok(Json(json!({ "releases": releases })))
}

async fn admin_release_create(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Json(request): Json<AdminReleaseCreateRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Release registration requires an Idempotency-Key header.")
    })?;
    let product_key = entitlements::clean_product_key(Some(&request.product_key))?;
    let version = clean_release_version(&request.version).map_err(admin_validation_error)?;
    let build_id = clean_build_id(&request.build_id).map_err(admin_validation_error)?;
    let channel_raw = request
        .release_channel
        .as_deref()
        .or(request.release_channel_key.as_deref())
        .unwrap_or("stable");
    let release_channel_key =
        clean_release_channel_key(channel_raw).map_err(admin_validation_error)?;
    let changelog_raw = request
        .changelog_markdown
        .as_deref()
        .or(request.release_notes.as_deref());
    let changelog_markdown = clean_optional_markdown(changelog_raw, "changelog_markdown", 16_000)
        .map_err(admin_validation_error)?;
    let minimum_supported_version = match request.minimum_supported_version.as_deref() {
        Some(value) => Some(clean_release_version(value).map_err(admin_validation_error)?),
        None => None,
    };
    let minimum_updater_version = match request.minimum_updater_version.as_deref() {
        Some(value) => Some(clean_release_version(value).map_err(admin_validation_error)?),
        None => None,
    };
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let release = admin::create_release(
        &state.pool,
        admin::CreateReleaseInput {
            operator_id: &operator.operator_id,
            product_key: &product_key,
            version: &version,
            build_id: &build_id,
            release_channel_key: &release_channel_key,
            changelog_markdown: changelog_markdown.as_deref(),
            minimum_supported_version: minimum_supported_version.as_deref(),
            minimum_updater_version: minimum_updater_version.as_deref(),
            reason: &reason,
            correlation_id: correlation_id(&correlation),
        },
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "release": release })))
}

async fn admin_release(
    _admin: AdminContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let release_id = parse_path_id(&id)?;
    let release = admin::read_release(&state.pool, release_id)
        .await?
        .ok_or_else(|| AppError::not_found("Release not found."))?;
    Ok(Json(json!({ "release": release })))
}

async fn admin_release_artifact_register(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminArtifactRegisterRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Artifact registration requires an Idempotency-Key header.")
    })?;
    let release_id = parse_path_id(&id)?;
    let platform = clean_artifact_platform(&request.platform).map_err(admin_validation_error)?;
    let architecture =
        clean_artifact_architecture(&request.architecture).map_err(admin_validation_error)?;
    let package_format =
        clean_package_format(&request.package_format).map_err(admin_validation_error)?;
    let artifact_role =
        clean_artifact_role(&request.artifact_role).map_err(admin_validation_error)?;
    let storage_key = clean_storage_key(&request.storage_key).map_err(admin_validation_error)?;
    let size_bytes = clean_size_bytes(request.size_bytes).map_err(admin_validation_error)?;
    let sha256 = clean_sha256(&request.sha256).map_err(admin_validation_error)?;
    let tauri_signature = clean_tauri_signature(request.tauri_signature.as_deref())
        .map_err(admin_validation_error)?;
    let signing_key_id =
        clean_signing_key_id(&request.signing_key_id).map_err(admin_validation_error)?;
    let os_signature_status =
        clean_os_signature_status(&request.os_signature_status).map_err(admin_validation_error)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;

    let artifact = admin::register_artifact(
        &state.pool,
        admin::RegisterArtifactInput {
            operator_id: &operator.operator_id,
            release_id,
            platform: &platform,
            architecture: &architecture,
            package_format: &package_format,
            artifact_role: &artifact_role,
            storage_key: &storage_key,
            size_bytes,
            sha256: &sha256,
            tauri_signature: tauri_signature.as_deref(),
            signing_key_id: &signing_key_id,
            os_signature_status: &os_signature_status,
            reason: &reason,
            correlation_id: correlation_id(&correlation),
        },
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "artifact": artifact })))
}

async fn admin_release_validate(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Release validation requires an Idempotency-Key header.")
    })?;
    let release_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let release = admin::validate_release(
        &state.pool,
        &operator.operator_id,
        release_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "release": release })))
}

async fn admin_release_publish(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Release publication requires an Idempotency-Key header.")
    })?;
    let release_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let release = admin::publish_release(
        &state.pool,
        &operator.operator_id,
        release_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "release": release })))
}

async fn admin_release_block(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Release block requires an Idempotency-Key header.")
    })?;
    let release_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let release = admin::block_release(
        &state.pool,
        &operator.operator_id,
        release_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "release": release })))
}

async fn admin_update_campaign(
    _admin: AdminContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let campaign_id = parse_path_id(&id)?;
    let campaign = admin::read_campaign(&state.pool, campaign_id)
        .await?
        .ok_or_else(|| AppError::not_found("Update campaign not found."))?;
    Ok(Json(json!({ "campaign": campaign })))
}

#[derive(Debug, Deserialize)]
struct AdminCampaignCreateRequest {
    product_key: String,
    target_release_id: Uuid,
    campaign_slug: String,
    release_channel: Option<String>,
    release_channel_key: Option<String>,
    target_update_ring: Option<String>,
    rollout_percentage: Option<i64>,
    starts_at: Option<String>,
    emergency: Option<bool>,
    reason: String,
}

async fn admin_update_campaign_create(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Json(request): Json<AdminCampaignCreateRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Campaign creation requires an Idempotency-Key header.")
    })?;
    let product_key = entitlements::clean_product_key(Some(&request.product_key))?;
    let campaign_slug =
        clean_campaign_slug(&request.campaign_slug).map_err(admin_validation_error)?;
    let channel_raw = request
        .release_channel
        .as_deref()
        .or(request.release_channel_key.as_deref())
        .unwrap_or("stable");
    let release_channel_key =
        clean_release_channel_key(channel_raw).map_err(admin_validation_error)?;
    let target_update_ring =
        clean_update_ring(request.target_update_ring.as_deref().unwrap_or("standard"))
            .map_err(admin_validation_error)?;
    if clean_rollout_percentage(request.rollout_percentage.unwrap_or(0))
        .map_err(admin_validation_error)?
        != 0
    {
        return Err(
            AppError::validation("campaign creation starts at 0% rollout")
                .with_details(json!({ "field": "rollout_percentage" })),
        );
    }
    let starts_at = parse_rfc3339(request.starts_at.as_deref(), "starts_at")?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let campaign = admin::create_campaign(
        &state.pool,
        admin::CreateCampaignInput {
            operator_id: &operator.operator_id,
            product_key: &product_key,
            target_release_id: request.target_release_id,
            campaign_slug: &campaign_slug,
            release_channel_key: &release_channel_key,
            target_update_ring: &target_update_ring,
            starts_at,
            emergency: request.emergency.unwrap_or(false),
            reason: &reason,
            correlation_id: correlation_id(&correlation),
        },
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "campaign": campaign })))
}

async fn campaign_reason_mutation<F, Fut>(
    operator: AdminContext,
    state: AppState,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    id: String,
    request: AdminReasonRequest,
    mutate: F,
) -> AppResult<Json<Value>>
where
    F: FnOnce(AppState, String, Uuid, String, Option<String>) -> Fut,
    Fut: std::future::Future<Output = Result<admin::AdminCampaignRow, admin::AdminError>>,
{
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Campaign mutation requires an Idempotency-Key header.")
    })?;
    let campaign_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let correlation = correlation_id(&correlation).map(str::to_string);
    let campaign = mutate(
        state,
        operator.operator_id,
        campaign_id,
        reason,
        correlation,
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "campaign": campaign })))
}

async fn admin_update_campaign_pause(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    campaign_reason_mutation(
        operator,
        state,
        correlation,
        headers,
        id,
        request,
        |state, operator_id, campaign_id, reason, correlation| async move {
            admin::pause_campaign(
                &state.pool,
                &operator_id,
                campaign_id,
                &reason,
                correlation.as_deref(),
            )
            .await
        },
    )
    .await
}

async fn admin_update_campaign_resume(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    campaign_reason_mutation(
        operator,
        state,
        correlation,
        headers,
        id,
        request,
        |state, operator_id, campaign_id, reason, correlation| async move {
            admin::resume_campaign(
                &state.pool,
                &operator_id,
                campaign_id,
                &reason,
                correlation.as_deref(),
            )
            .await
        },
    )
    .await
}

async fn admin_update_campaign_revoke(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    campaign_reason_mutation(
        operator,
        state,
        correlation,
        headers,
        id,
        request,
        |state, operator_id, campaign_id, reason, correlation| async move {
            admin::revoke_campaign(
                &state.pool,
                &operator_id,
                campaign_id,
                &reason,
                correlation.as_deref(),
            )
            .await
        },
    )
    .await
}

#[derive(Debug, Deserialize)]
struct AdminCampaignRolloutRequest {
    rollout_percentage: i64,
    reason: String,
}

async fn admin_update_campaign_rollout(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminCampaignRolloutRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Rollout changes require an Idempotency-Key header.")
    })?;
    let campaign_id = parse_path_id(&id)?;
    let rollout_percentage =
        clean_rollout_percentage(request.rollout_percentage).map_err(admin_validation_error)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let campaign = admin::set_campaign_rollout(
        &state.pool,
        &operator.operator_id,
        campaign_id,
        rollout_percentage,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "campaign": campaign })))
}

#[derive(Debug, Deserialize)]
struct AdminFleetHoldRequest {
    fleet_id: Uuid,
    reason: String,
}

async fn admin_update_campaign_hold_add(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(campaign_id): Path<String>,
    Json(request): Json<AdminFleetHoldRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers)
        .ok_or_else(|| AppError::bad_request("Fleet holds require an Idempotency-Key header."))?;
    let campaign_id = parse_path_id(&campaign_id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let hold = admin::add_fleet_hold(
        &state.pool,
        &operator.operator_id,
        campaign_id,
        request.fleet_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "hold": hold })))
}

async fn admin_update_campaign_hold_remove(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path((campaign_id, fleet_id)): Path<(String, String)>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Fleet hold removal requires an Idempotency-Key header.")
    })?;
    let campaign_id = parse_path_id(&campaign_id)?;
    let fleet_id = parse_path_id(&fleet_id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let hold = admin::remove_fleet_hold(
        &state.pool,
        &operator.operator_id,
        campaign_id,
        fleet_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "hold": hold })))
}

async fn admin_update_failures(
    _admin: AdminContext,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let failures = admin::list_update_failures(&state.pool).await?;
    Ok(Json(json!({ "failures": failures })))
}

async fn admin_release_artifact_quarantine(
    operator: AdminContext,
    State(state): State<AppState>,
    correlation: Option<Extension<mw::CorrelationId>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AdminReasonRequest>,
) -> AppResult<Json<Value>> {
    operator.require_role("admin")?;
    idempotency_key(&headers).ok_or_else(|| {
        AppError::bad_request("Artifact quarantine requires an Idempotency-Key header.")
    })?;
    let artifact_id = parse_path_id(&id)?;
    let reason = clean_reason(&request.reason).map_err(admin_validation_error)?;
    let artifact = admin::quarantine_artifact(
        &state.pool,
        &operator.operator_id,
        artifact_id,
        &reason,
        correlation_id(&correlation),
    )
    .await
    .map_err(admin_error)?;
    Ok(Json(json!({ "artifact": artifact })))
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
