//! Entitlement endpoints: published verification keys, signed snapshot issuance,
//! feature/quota checks, and signed offline-lease issuance.
//!
//! Snapshots and leases are evaluated fail-closed from current commercial truth, signed
//! with the active Ed25519 key, and recorded for audit/replay before being returned.

use axum::extract::{Query, State};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::CustomerContext;
use crate::domain::entitlement::{clean_entitlement_key, evaluate, FeatureValue};
use crate::domain::snapshot::{EntitlementSnapshot, SCHEMA_VERSION};
use crate::domain::usage::{decide, Decision};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::middleware::CorrelationId;
use crate::repositories::entitlements::{self, LeaseError};
use crate::state::AppState;

/// Publish verification keys (id → base64 public key) for snapshot verification, including
/// keys retained for the rotation overlap window.
pub async fn keys(State(state): State<AppState>) -> AppResult<Json<Value>> {
    let keys: Vec<Value> = state
        .key_ring
        .published()
        .into_iter()
        .map(|(id, pubkey)| json!({ "key_id": id, "public_key": pubkey, "alg": "Ed25519" }))
        .collect();
    Ok(Json(
        json!({ "schema": "forge.entitlements.v1", "keys": keys }),
    ))
}

#[derive(Debug, Default, Deserialize)]
pub struct SnapshotQuery {
    product_key: Option<String>,
    installation_id: Option<String>,
}

fn clean_product_key(value: Option<&str>) -> AppResult<String> {
    let value = match value.map(str::trim) {
        Some(v) if !v.is_empty() => v,
        _ => return Ok("authorforge".to_string()),
    };
    if value.len() > 120 || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(AppError::validation(
            "product_key must contain only letters, numbers, and underscores",
        )
        .with_details(json!({ "field": "product_key" })));
    }
    Ok(value.to_string())
}

fn parse_id(raw: &str, field: &'static str) -> AppResult<Uuid> {
    Uuid::parse_str(raw.trim())
        .map_err(|_| AppError::validation("must be a UUID").with_details(json!({ "field": field })))
}

/// Current signed entitlement snapshot for the caller. With `installation_id`, the
/// snapshot is bound to that installation and its product; otherwise `product_key`
/// (default `authorforge`) selects the product. Every issued snapshot is stored for
/// audit/replay verification.
pub async fn current(
    ctx: CustomerContext,
    State(state): State<AppState>,
    Query(query): Query<SnapshotQuery>,
) -> AppResult<Json<EntitlementSnapshot>> {
    let customer_id = ctx.require_active()?;

    let mut product_key = clean_product_key(query.product_key.as_deref())?;
    let installation_id = match query.installation_id.as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() => {
            let id = parse_id(raw, "installation_id")?;
            let (id, installation_product) =
                entitlements::find_owned_installation(&state.pool, customer_id, id)
                    .await?
                    .ok_or_else(|| AppError::not_found("Installation not found."))?;
            product_key = installation_product;
            Some(id)
        }
        _ => None,
    };

    let loaded = entitlements::load_entitlement_inputs(&state.pool, customer_id, &product_key)
        .await?
        .ok_or_else(|| AppError::not_found("Unknown or inactive product."))?;
    let result = evaluate(&loaded.inputs);

    let issued_at = chrono::Utc::now();
    let ttl = chrono::Duration::from_std(state.config.snapshot_ttl)
        .map_err(|_| AppError::internal("Invalid snapshot TTL configuration."))?;
    let expires_at = issued_at + ttl;

    let mut snapshot = EntitlementSnapshot {
        schema_version: SCHEMA_VERSION.to_string(),
        customer_id: customer_id.to_string(),
        installation_id: installation_id.map(|id| id.to_string()),
        product: loaded.product_key.clone(),
        issued_at: issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        expires_at: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        features: result.features,
        quotas: result.quotas,
        key_id: String::new(),
        signature: String::new(),
    };
    state
        .signer
        .sign_snapshot(&mut snapshot)
        .map_err(|_| AppError::internal("Failed to sign the entitlement snapshot."))?;
    let payload = serde_json::to_value(&snapshot)
        .map_err(|_| AppError::internal("Failed to serialize the entitlement snapshot."))?;

    entitlements::store_snapshot(
        &state.pool,
        customer_id,
        installation_id,
        loaded.product_id,
        &snapshot,
        &payload,
        expires_at,
    )
    .await?;

    Ok(Json(snapshot))
}

#[derive(Debug, Default, Deserialize)]
pub struct EntitlementCheckRequest {
    product_key: Option<String>,
    feature_key: Option<String>,
    quota_key: Option<String>,
    /// For quota checks: the amount about to be consumed. Defaults to 0, which answers
    /// "is this meter currently within quota".
    amount: Option<f64>,
}

/// Check a single feature or quota against current commercial truth. Advisory and
/// read-only: reservations and their recorded decisions are the usage endpoints' job.
pub async fn check(
    ctx: CustomerContext,
    State(state): State<AppState>,
    Json(request): Json<EntitlementCheckRequest>,
) -> AppResult<Json<Value>> {
    let customer_id = ctx.require_active()?;
    let product_key = clean_product_key(request.product_key.as_deref())?;

    let (kind, raw_key) = match (&request.feature_key, &request.quota_key) {
        (Some(feature), None) => ("feature", feature.as_str()),
        (None, Some(quota)) => ("quota", quota.as_str()),
        _ => {
            return Err(
                AppError::validation("Provide exactly one of feature_key or quota_key.")
                    .with_details(json!({ "field": "feature_key" })),
            );
        }
    };
    let key = clean_entitlement_key(raw_key)
        .map_err(|message| AppError::validation(message).with_details(json!({ "field": kind })))?;

    let loaded = entitlements::load_entitlement_inputs(&state.pool, customer_id, &product_key)
        .await?
        .ok_or_else(|| AppError::not_found("Unknown or inactive product."))?;
    let result = evaluate(&loaded.inputs);

    if kind == "feature" {
        let value = result.features.get(&key);
        // Fail closed: an absent feature or an explicit false is not allowed.
        let allowed = match value {
            Some(FeatureValue::Bool(value)) => *value,
            Some(_) => true,
            None => false,
        };
        return Ok(Json(json!({
            "kind": "feature",
            "key": key,
            "allowed": allowed,
            "value": value,
        })));
    }

    let limit = result.quotas.get(&key).copied();
    let usage = entitlements::meter_usage(&state.pool, customer_id, &key).await?;
    let requested = request.amount.unwrap_or(0.0);
    let decision = decide(requested, usage.used, usage.reserved, limit);
    Ok(Json(json!({
        "kind": "quota",
        "key": key,
        "allowed": decision.decision == Decision::Allow,
        "limit": limit,
        "used": usage.used,
        "reserved": usage.reserved,
        "remaining_before": decision.remaining_before,
        "requested": requested,
        "reason": decision.reason,
    })))
}

#[derive(Debug, Deserialize)]
pub struct OfflineLeaseRequest {
    installation_id: String,
}

fn lease_error(error: LeaseError) -> AppError {
    match error {
        LeaseError::InstallationNotFound => AppError::not_found("Installation not found."),
        LeaseError::InstallationDeactivated => AppError::new(
            ErrorCode::Conflict,
            "Installation is deactivated; register it again first.",
        ),
        LeaseError::NoActiveActivation => AppError::new(
            ErrorCode::Conflict,
            "Installation has no active license activation; activate it first.",
        ),
        LeaseError::LicenseNotActive(status) => {
            AppError::forbidden("License is not active; no new lease.")
                .with_details(json!({ "license_status": status }))
        }
        LeaseError::RevocationBlocked => AppError::new(
            ErrorCode::Revoked,
            "Lease issuance is blocked by an explicit revocation.",
        ),
        LeaseError::Signing(error) => {
            tracing::error!(error = %error, "failed to sign offline lease");
            AppError::internal("Failed to sign the offline lease.")
        }
        LeaseError::Db(error) => error.into(),
    }
}

/// Issue a signed offline lease for an activated installation. Suspended customers are
/// rejected at the auth boundary; revoked licenses/devices and explicit revocation
/// records never receive a new lease.
///
/// The lease struct is returned directly (not via `serde_json::Value`, which would
/// re-sort keys) so the wire JSON field order matches the canonical signed byte order
/// and clients can verify the signature from the received document.
pub async fn offline_lease(
    ctx: CustomerContext,
    State(state): State<AppState>,
    correlation: Option<Extension<CorrelationId>>,
    Json(request): Json<OfflineLeaseRequest>,
) -> AppResult<Json<crate::domain::lease::OfflineLease>> {
    let customer_id = ctx.require_active()?;
    let installation_id = parse_id(&request.installation_id, "installation_id")?;
    let ttl = chrono::Duration::from_std(state.config.offline_grace)
        .map_err(|_| AppError::internal("Invalid offline grace configuration."))?;

    let issued = entitlements::issue_offline_lease(
        &state.pool,
        &state.signer,
        customer_id,
        installation_id,
        ttl,
        correlation
            .as_ref()
            .map(|Extension(correlation)| correlation.0.as_str()),
    )
    .await
    .map_err(lease_error)?;

    Ok(Json(issued.lease))
}
