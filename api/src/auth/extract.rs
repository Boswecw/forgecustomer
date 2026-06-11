//! Axum extractors that enforce authentication and resolve request context.
//!
//! `CustomerContext` validates a Supabase JWT and resolves the business customer.
//! `AdminContext` validates an operator JWT against the *separate* admin issuer/audience —
//! a customer token can never satisfy it.

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::auth::{bearer_token, AdminContext, AuthUserContext, CustomerContext};
use crate::error::{AppError, ErrorCode};
use crate::middleware::CorrelationId;
use crate::state::AppState;

fn correlation(parts: &Parts) -> Option<String> {
    parts.extensions.get::<CorrelationId>().map(|c| c.0.clone())
}

fn auth_header(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

#[async_trait]
impl FromRequestParts<AppState> for CustomerContext {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let corr = correlation(parts);
        let attach = |e: AppError| match &corr {
            Some(id) => e.with_correlation(id.clone()),
            None => e,
        };

        let token = bearer_token(auth_header(parts)).map_err(attach)?;
        let claims = state.customer_validator.validate(token).map_err(attach)?;

        let auth_user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
            attach(AppError::new(
                ErrorCode::InvalidToken,
                "Token subject is not a valid user id.",
            ))
        })?;

        // Resolve the business customer. Missing profile => forbidden (fail closed).
        let row = crate::repositories::customers::find_by_auth_user_id(&state.pool, auth_user_id)
            .await
            .map_err(|e| attach(AppError::from(e)))?;

        let (customer_id, status) = match row {
            Some(r) => (Some(r.id), Some(r.status)),
            None => (None, None),
        };

        Ok(CustomerContext {
            auth_user_id: claims.sub,
            customer_id,
            status,
        })
    }
}

impl CustomerContext {
    /// Require a fully provisioned, non-suspended, non-terminated customer for
    /// privileged product actions. Anonymized/closed accounts fail closed.
    pub fn require_active(&self) -> Result<Uuid, AppError> {
        let id = self.customer_id.ok_or_else(|| {
            AppError::new(ErrorCode::Forbidden, "No customer profile is provisioned.")
        })?;
        if self.is_suspended() {
            return Err(AppError::new(
                ErrorCode::CustomerSuspended,
                "This customer account is suspended.",
            ));
        }
        if matches!(self.status.as_deref(), Some("anonymized") | Some("closed")) {
            return Err(AppError::new(
                ErrorCode::Forbidden,
                "This customer account is closed.",
            ));
        }
        Ok(id)
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUserContext {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let corr = correlation(parts);
        let attach = |e: AppError| match &corr {
            Some(id) => e.with_correlation(id.clone()),
            None => e,
        };

        let token = bearer_token(auth_header(parts)).map_err(attach)?;
        let claims = state.customer_validator.validate(token).map_err(attach)?;

        let auth_user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
            attach(AppError::new(
                ErrorCode::InvalidToken,
                "Token subject is not a valid user id.",
            ))
        })?;

        Ok(AuthUserContext {
            auth_user_id,
            email: claims.email,
        })
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AdminContext {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let corr = correlation(parts);
        let attach = |e: AppError| match &corr {
            Some(id) => e.with_correlation(id.clone()),
            None => e,
        };

        let token = bearer_token(auth_header(parts)).map_err(attach)?;
        // Validated against the ADMIN issuer/audience only.
        let claims = state.admin_validator.validate(token).map_err(attach)?;

        let roles = claims.operator_roles();
        Ok(AdminContext {
            operator_id: claims.sub,
            roles,
        })
    }
}
