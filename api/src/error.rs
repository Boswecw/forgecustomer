//! The single error contract for the API. Every failure renders as:
//! `{ "error": { "code, message, correlation_id, details } }`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// Stable machine-readable error codes (mirrored in `docs/API.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Unauthenticated,
    InvalidToken,
    TokenExpired,
    WrongAudience,
    Forbidden,
    CustomerSuspended,
    NotFound,
    Conflict,
    IdempotencyReplay,
    ValidationFailed,
    QuotaExceeded,
    DeviceLimitReached,
    Revoked,
    RateLimited,
    Internal,
    ServiceUnavailable,
    NotImplemented,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthenticated => "UNAUTHENTICATED",
            ErrorCode::InvalidToken => "INVALID_TOKEN",
            ErrorCode::TokenExpired => "TOKEN_EXPIRED",
            ErrorCode::WrongAudience => "WRONG_AUDIENCE",
            ErrorCode::Forbidden => "FORBIDDEN",
            ErrorCode::CustomerSuspended => "CUSTOMER_SUSPENDED",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::Conflict => "CONFLICT",
            ErrorCode::IdempotencyReplay => "IDEMPOTENCY_REPLAY",
            ErrorCode::ValidationFailed => "VALIDATION_FAILED",
            ErrorCode::QuotaExceeded => "QUOTA_EXCEEDED",
            ErrorCode::DeviceLimitReached => "DEVICE_LIMIT_REACHED",
            ErrorCode::Revoked => "REVOKED",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::Internal => "INTERNAL",
            ErrorCode::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            ErrorCode::NotImplemented => "NOT_IMPLEMENTED",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            ErrorCode::Unauthenticated
            | ErrorCode::InvalidToken
            | ErrorCode::TokenExpired
            | ErrorCode::WrongAudience => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden | ErrorCode::CustomerSuspended | ErrorCode::Revoked => {
                StatusCode::FORBIDDEN
            }
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Conflict | ErrorCode::IdempotencyReplay => StatusCode::CONFLICT,
            ErrorCode::ValidationFailed => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::QuotaExceeded | ErrorCode::DeviceLimitReached => {
                StatusCode::PAYMENT_REQUIRED
            }
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

/// The application error type carried through handlers.
#[derive(Debug)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub correlation_id: Option<String>,
    pub details: Value,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            correlation_id: None,
            details: json!({}),
        }
    }

    pub fn with_correlation(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    // Ergonomic constructors for the common cases.
    pub fn unauthenticated(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthenticated, msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, msg)
    }
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::ValidationFailed, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, msg)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": {
                "code": self.code.as_str(),
                "message": self.message,
                "correlation_id": self.correlation_id,
                "details": self.details,
            }
        });
        (self.code.status(), Json(body)).into_response()
    }
}

/// Database errors map to INTERNAL without leaking detail to the client.
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error");
        AppError::internal("A database error occurred.")
    }
}

pub type AppResult<T> = Result<T, AppError>;
