//! Liveness, readiness, and version endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

/// Liveness: the process is up.
pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Readiness: the database is reachable. Returns 503 if not.
pub async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query_scalar::<_, i32>("select 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(e) => {
            tracing::warn!(error = %e, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "not_ready" })),
            )
        }
    }
}

/// Version / build information.
pub async fn version(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "service": "forgecustomer-api",
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": option_env!("GIT_SHA").unwrap_or("unknown"),
        "app_env": state.config.app_env,
    }))
}
