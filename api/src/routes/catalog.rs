//! Public product & plan catalog endpoints.

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::error::AppResult;
use crate::repositories::catalog;
use crate::state::AppState;

pub async fn list_products(State(state): State<AppState>) -> AppResult<Json<Value>> {
    let products = catalog::list_products(&state.pool).await?;
    Ok(Json(json!({ "products": products })))
}

pub async fn list_plans(State(state): State<AppState>) -> AppResult<Json<Value>> {
    let plans = catalog::list_plans(&state.pool).await?;
    Ok(Json(json!({ "plans": plans })))
}
