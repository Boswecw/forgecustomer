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
    /// Operator capability scope. Forge Command's Token Authority issues a `scope` string
    /// (e.g. "admin") rather than a `roles` array; [`Claims::operator_roles`] bridges them.
    #[serde(default)]
    pub scope: Option<String>,
    pub exp: usize,
}

impl Claims {
    /// Operator roles for admin authorization.
    ///
    /// Forge Command's Token Authority mints EdDSA operator tokens carrying a `scope`
    /// string instead of a `roles` array. When `roles` is empty we derive it from `scope`,
    /// mapping the full scope `*` to the `admin` role and otherwise treating each
    /// whitespace-separated scope token as a role of the same name.
    pub fn operator_roles(&self) -> Vec<String> {
        if !self.roles.is_empty() {
            return self.roles.clone();
        }
        match self.scope.as_deref() {
            Some(scope) => scope
                .split_whitespace()
                .map(|token| if token == "*" { "admin" } else { token }.to_string())
                .collect(),
            None => Vec::new(),
        }
    }
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

    /// Build a validator for EdDSA (Ed25519) tokens verified against a PEM-encoded public
    /// key. Forge Command's Token Authority signs operator tokens with Ed25519 and publishes
    /// the SPKI public key; ForgeCustomer verifies admin tokens against it — no shared
    /// secret. An empty or unparseable key fails closed (never accepts a token).
    pub fn eddsa(public_key_pem: &str, issuer: &str, audience: &str) -> Self {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "aud", "iss"]);
        // Fail closed on expiry: no clock-skew leeway for operator tokens.
        validation.leeway = 0;
        match DecodingKey::from_ed_pem(public_key_pem.as_bytes()) {
            Ok(key) => Self {
                key,
                validation,
                configured: true,
            },
            Err(_) => Self {
                // Fail closed: an unconfigured/unparseable key can never verify a token.
                key: DecodingKey::from_secret(&[]),
                validation,
                configured: false,
            },
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

    /// Require an operator role for privileged admin mutations (fail closed). Forge
    /// Command mints operator tokens; reads need any valid operator token, mutations
    /// need the named role.
    pub fn require_role(&self, role: &str) -> Result<(), AppError> {
        if self.has_role(role) {
            Ok(())
        } else {
            Err(AppError::forbidden(format!(
                "This operation requires the '{role}' operator role."
            )))
        }
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

    fn claims_with(roles: Vec<&str>, scope: Option<&str>) -> Claims {
        Claims {
            sub: "op".into(),
            email: None,
            role: None,
            roles: roles.into_iter().map(String::from).collect(),
            scope: scope.map(String::from),
            exp: 0,
        }
    }

    #[test]
    fn operator_roles_prefers_explicit_roles() {
        let claims = claims_with(vec!["admin"], Some("read:foo"));
        assert_eq!(claims.operator_roles(), vec!["admin".to_string()]);
    }

    #[test]
    fn operator_roles_derives_from_scope_when_roles_absent() {
        let claims = claims_with(vec![], Some("admin"));
        assert_eq!(claims.operator_roles(), vec!["admin".to_string()]);
    }

    #[test]
    fn operator_roles_maps_wildcard_scope_to_admin() {
        let claims = claims_with(vec![], Some("*"));
        assert!(claims.operator_roles().contains(&"admin".to_string()));
    }

    #[test]
    fn operator_roles_empty_without_roles_or_scope() {
        assert!(claims_with(vec![], None).operator_roles().is_empty());
    }

    #[test]
    fn eddsa_unconfigured_key_fails_closed() {
        let v = JwtValidator::eddsa("", "forge_command_local", "forgecustomer-admin");
        assert!(v.validate("any.token.here").is_err());
    }
}
