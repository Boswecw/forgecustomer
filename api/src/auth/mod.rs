//! Authentication & authorization: JWT validation, customer context, admin context.
//!
//! Customer tokens are validated against the Supabase issuer/audience; admin tokens
//! against the operator issuer/audience. The two are kept strictly separate so a customer
//! token can never authorize an admin route.

use jsonwebtoken::{decode, errors::ErrorKind, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod extract;

use crate::error::{AppError, ErrorCode};

/// Claims we read from a validated token. Registered claims (exp/aud/iss) are validated by
/// `jsonwebtoken` itself; we deserialize the subset we use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — Supabase auth user id (customer) or operator id (admin).
    pub sub: String,
    /// Optional Supabase email claim. ForgeCustomer may project it into customer contact
    /// records, but Supabase Auth remains the login/email-verification authority.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    /// Operator roles/capabilities (admin tokens).
    #[serde(default)]
    pub roles: Vec<String>,
    pub exp: usize,
}

/// Validates JWTs for a particular issuer/audience using an HS256 secret.
#[derive(Clone)]
pub struct JwtValidator {
    key: DecodingKey,
    validation: Validation,
    configured: bool,
}

impl JwtValidator {
    pub fn hs256(secret: &str, issuer: &str, audience: &str) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "aud", "iss"]);
        // Fail closed on expiry: no clock-skew leeway for access tokens.
        validation.leeway = 0;
        Self {
            key: DecodingKey::from_secret(secret.as_bytes()),
            validation,
            configured: !secret.is_empty(),
        }
    }

    /// Validate a bearer token, returning claims or a fail-closed [`AppError`].
    pub fn validate(&self, token: &str) -> Result<Claims, AppError> {
        if !self.configured {
            // Fail closed: never accept tokens when no verification secret is configured.
            return Err(AppError::new(
                ErrorCode::Internal,
                "token verification is not configured",
            ));
        }
        match decode::<Claims>(token, &self.key, &self.validation) {
            Ok(data) => Ok(data.claims),
            Err(e) => Err(map_jwt_error(&e)),
        }
    }
}

fn map_jwt_error(e: &jsonwebtoken::errors::Error) -> AppError {
    match e.kind() {
        ErrorKind::ExpiredSignature => {
            AppError::new(ErrorCode::TokenExpired, "The access token has expired.")
        }
        ErrorKind::InvalidAudience => {
            AppError::new(ErrorCode::WrongAudience, "The token audience is invalid.")
        }
        ErrorKind::InvalidIssuer => {
            AppError::new(ErrorCode::InvalidToken, "The token issuer is invalid.")
        }
        ErrorKind::InvalidSignature => {
            AppError::new(ErrorCode::InvalidToken, "The token signature is invalid.")
        }
        _ => AppError::new(ErrorCode::InvalidToken, "The access token is invalid."),
    }
}

/// Resolved customer context attached to a request after authentication. The business
/// `customer_id` is resolved separately from the auth subject.
#[derive(Debug, Clone)]
pub struct CustomerContext {
    pub auth_user_id: String,
    pub customer_id: Option<Uuid>,
    pub status: Option<String>,
}

impl CustomerContext {
    pub fn is_suspended(&self) -> bool {
        matches!(self.status.as_deref(), Some("suspended"))
    }
}

/// Supabase-authenticated user context before a ForgeCustomer business profile exists.
#[derive(Debug, Clone)]
pub struct AuthUserContext {
    pub auth_user_id: Uuid,
    pub email: Option<String>,
}

/// Resolved admin/operator context.
#[derive(Debug, Clone)]
pub struct AdminContext {
    pub operator_id: String,
    pub roles: Vec<String>,
}

impl AdminContext {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Extract a bearer token from an `Authorization` header value.
pub fn bearer_token(header: Option<&str>) -> Result<&str, AppError> {
    let value = header.ok_or_else(|| AppError::unauthenticated("Missing Authorization header."))?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::unauthenticated("Malformed Authorization header."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    const SECRET: &str = "test-secret";
    const ISS: &str = "https://proj.supabase.co/auth/v1";
    const AUD: &str = "authenticated";

    fn now() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
    }

    fn token(claims: serde_json::Value, secret: &str) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn validator() -> JwtValidator {
        JwtValidator::hs256(SECRET, ISS, AUD)
    }

    #[test]
    fn accepts_valid_token() {
        let t = token(
            json!({ "sub": "user-1", "iss": ISS, "aud": AUD, "exp": now() + 3600 }),
            SECRET,
        );
        let claims = validator().validate(&t).expect("valid");
        assert_eq!(claims.sub, "user-1");
    }

    #[test]
    fn rejects_expired_token() {
        let t = token(
            json!({ "sub": "u", "iss": ISS, "aud": AUD, "exp": now() - 10 }),
            SECRET,
        );
        let err = validator().validate(&t).unwrap_err();
        assert_eq!(err.code, ErrorCode::TokenExpired);
    }

    #[test]
    fn rejects_wrong_audience() {
        let t = token(
            json!({ "sub": "u", "iss": ISS, "aud": "someone-else", "exp": now() + 3600 }),
            SECRET,
        );
        let err = validator().validate(&t).unwrap_err();
        assert_eq!(err.code, ErrorCode::WrongAudience);
    }

    #[test]
    fn rejects_wrong_issuer() {
        let t = token(
            json!({ "sub": "u", "iss": "https://evil", "aud": AUD, "exp": now() + 3600 }),
            SECRET,
        );
        let err = validator().validate(&t).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidToken);
    }

    #[test]
    fn rejects_bad_signature() {
        let t = token(
            json!({ "sub": "u", "iss": ISS, "aud": AUD, "exp": now() + 3600 }),
            "wrong-secret",
        );
        let err = validator().validate(&t).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidToken);
    }

    #[test]
    fn unconfigured_validator_fails_closed() {
        let v = JwtValidator::hs256("", ISS, AUD);
        let t = token(
            json!({ "sub": "u", "iss": ISS, "aud": AUD, "exp": now() + 3600 }),
            "",
        );
        assert!(v.validate(&t).is_err());
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer_token(Some("Bearer abc")).unwrap(), "abc");
        assert!(bearer_token(None).is_err());
        assert!(bearer_token(Some("Basic abc")).is_err());
    }
}
