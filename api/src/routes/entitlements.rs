//! Entitlement endpoints. The published-keys endpoint is fully implemented (public, used
//! by clients to verify snapshots). Snapshot issuance is wired to the signer; the data
//! gathering of grants/overrides from the database is the remaining MVP work and is marked
//! explicitly.

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::auth::CustomerContext;
use crate::error::{AppError, AppResult, ErrorCode};
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

/// Current signed entitlement snapshot for the caller.
///
/// NOTE (MVP follow-up): gathering plan/grant/override inputs from the database and
/// assembling the [`crate::domain::entitlement::EntitlementInputs`] is implemented in the
/// entitlement service work; this handler returns NOT_IMPLEMENTED until that is wired so we
/// never ship an unsigned or partially-evaluated snapshot.
pub async fn current(ctx: CustomerContext) -> AppResult<Json<Value>> {
    let _customer_id = ctx.require_active()?;
    Err(AppError::new(
        ErrorCode::NotImplemented,
        "Entitlement snapshot assembly is not yet implemented.",
    ))
}

/// Issue a signed offline lease. Suspended/revoked customers never receive a new lease.
pub async fn offline_lease(ctx: CustomerContext) -> AppResult<Json<Value>> {
    let _customer_id = ctx.require_active()?;
    Err(AppError::new(
        ErrorCode::NotImplemented,
        "Offline lease issuance is not yet implemented.",
    ))
}
