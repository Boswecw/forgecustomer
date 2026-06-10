//! Environment-driven configuration. Secrets are loaded here and never logged.

use std::time::Duration;

/// Application configuration assembled from environment variables.
#[derive(Clone)]
pub struct Config {
    pub app_env: String,
    pub host: String,
    pub port: u16,

    pub database_url: String,

    pub supabase_jwt_issuer: String,
    pub supabase_jwt_audience: String,
    /// HS256 secret used to verify Supabase JWTs (the project JWT secret).
    pub supabase_jwt_secret: String,

    pub admin_jwt_issuer: String,
    pub admin_jwt_audience: String,
    /// HS256 secret used to verify operator/admin JWTs.
    pub admin_jwt_secret: String,

    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,

    pub entitlement_signing_private_key: String,
    pub entitlement_signing_key_id: String,

    pub dataforge_api_url: String,
    pub dataforge_service_token: String,

    pub snapshot_ttl: Duration,
    pub offline_grace: Duration,

    pub request_timeout: Duration,
    pub max_body_bytes: usize,
}

/// Configuration errors. Missing required variables fail closed at startup.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
}

fn require(key: &'static str) -> Result<String, ConfigError> {
    std::env::var(key).map_err(|_| ConfigError::Missing(key))
}

fn optional(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_u64(key: &'static str, default: u64) -> Result<u64, ConfigError> {
    match std::env::var(key) {
        Ok(v) => v
            .parse::<u64>()
            .map_err(|e| ConfigError::Invalid(key, e.to_string())),
        Err(_) => Ok(default),
    }
}

impl Config {
    /// Load configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let port = optional("PORT", "8080")
            .parse::<u16>()
            .map_err(|e| ConfigError::Invalid("PORT", e.to_string()))?;

        let snapshot_ttl_hours = parse_u64("ENTITLEMENT_SNAPSHOT_TTL_HOURS", 24)?;
        let offline_grace_days = parse_u64("OFFLINE_GRACE_DAYS", 14)?;

        Ok(Self {
            app_env: optional("APP_ENV", "development"),
            host: optional("HOST", "0.0.0.0"),
            port,
            database_url: require("DATABASE_URL")?,
            supabase_jwt_issuer: require("SUPABASE_JWT_ISSUER")?,
            supabase_jwt_audience: optional("SUPABASE_JWT_AUDIENCE", "authenticated"),
            supabase_jwt_secret: optional("SUPABASE_JWT_SECRET", ""),
            admin_jwt_issuer: require("ADMIN_JWT_ISSUER")?,
            admin_jwt_audience: require("ADMIN_JWT_AUDIENCE")?,
            admin_jwt_secret: optional("ADMIN_JWT_SECRET", ""),
            stripe_secret_key: optional("STRIPE_SECRET_KEY", ""),
            stripe_webhook_secret: optional("STRIPE_WEBHOOK_SECRET", ""),
            entitlement_signing_private_key: require("ENTITLEMENT_SIGNING_PRIVATE_KEY")?,
            entitlement_signing_key_id: optional("ENTITLEMENT_SIGNING_KEY_ID", "entitlement-key-1"),
            dataforge_api_url: optional("DATAFORGE_API_URL", ""),
            dataforge_service_token: optional("DATAFORGE_SERVICE_TOKEN", ""),
            snapshot_ttl: Duration::from_secs(snapshot_ttl_hours * 3600),
            offline_grace: Duration::from_secs(offline_grace_days * 86400),
            request_timeout: Duration::from_secs(parse_u64("REQUEST_TIMEOUT_SECS", 30)?),
            max_body_bytes: parse_u64("MAX_BODY_BYTES", 1024 * 1024)? as usize,
        })
    }
}
