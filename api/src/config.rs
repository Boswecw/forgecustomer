//! Environment-driven configuration. Secrets are loaded here and never logged.

use std::time::Duration;

/// Application configuration assembled from environment variables.
#[derive(Clone)]
pub struct Config {
    pub app_env: String,
    pub host: String,
    pub port: u16,

    pub database_url: String,
    /// How long pool acquisition may retry connecting before failing closed.
    pub database_acquire_timeout: Duration,

    pub supabase_jwt_issuer: String,
    pub supabase_jwt_audience: String,
    /// HS256 secret used to verify Supabase JWTs (the project JWT secret).
    pub supabase_jwt_secret: String,

    pub admin_jwt_issuer: String,
    pub admin_jwt_audience: String,
    /// PEM-encoded Ed25519 public key used to verify operator/admin JWTs minted by Forge
    /// Command's Token Authority. Empty = the admin surface fails closed.
    pub admin_jwt_public_key: String,

    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
    /// Stripe API base URL; overridable for mocked end-to-end tests.
    pub stripe_api_base: String,

    pub entitlement_signing_private_key: String,
    pub entitlement_signing_key_id: String,

    pub dataforge_api_url: String,
    pub dataforge_service_token: String,

    pub snapshot_ttl: Duration,
    pub offline_grace: Duration,
    /// How long a deletion request rests in cooling-off before it may be processed.
    pub deletion_cooling_off: Duration,
    /// How long a usage reservation holds quota before it auto-expires.
    pub usage_reservation_ttl: Duration,
    /// Usage thresholds (percent of limit) that emit `quota_threshold_reached`.
    pub usage_threshold_percents: Vec<u8>,

    pub request_timeout: Duration,
    pub max_body_bytes: usize,
    /// Per-client request budget per minute (`0` disables rate limiting).
    pub rate_limit_per_minute: u32,
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

/// Parse a comma-separated list of percentages (1–100), e.g. "80,100".
fn parse_percent_list(key: &'static str, default: &[u8]) -> Result<Vec<u8>, ConfigError> {
    let raw = match std::env::var(key) {
        Ok(value) => value,
        Err(_) => return Ok(default.to_vec()),
    };
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let pct = part
            .parse::<u8>()
            .ok()
            .filter(|pct| (1..=100).contains(pct))
            .ok_or(ConfigError::Invalid(
                key,
                "must be comma-separated percentages between 1 and 100".to_string(),
            ))?;
        out.push(pct);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
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
            database_acquire_timeout: Duration::from_secs(parse_u64(
                "DATABASE_ACQUIRE_TIMEOUT_SECS",
                30,
            )?),
            supabase_jwt_issuer: require("SUPABASE_JWT_ISSUER")?,
            supabase_jwt_audience: optional("SUPABASE_JWT_AUDIENCE", "authenticated"),
            supabase_jwt_secret: optional("SUPABASE_JWT_SECRET", ""),
            admin_jwt_issuer: require("ADMIN_JWT_ISSUER")?,
            admin_jwt_audience: require("ADMIN_JWT_AUDIENCE")?,
            admin_jwt_public_key: optional("ADMIN_JWT_PUBLIC_KEY", ""),
            stripe_secret_key: optional("STRIPE_SECRET_KEY", ""),
            stripe_webhook_secret: optional("STRIPE_WEBHOOK_SECRET", ""),
            stripe_api_base: optional("STRIPE_API_BASE", "https://api.stripe.com"),
            entitlement_signing_private_key: require("ENTITLEMENT_SIGNING_PRIVATE_KEY")?,
            entitlement_signing_key_id: optional("ENTITLEMENT_SIGNING_KEY_ID", "entitlement-key-1"),
            dataforge_api_url: optional("DATAFORGE_API_URL", ""),
            dataforge_service_token: optional("DATAFORGE_SERVICE_TOKEN", ""),
            snapshot_ttl: Duration::from_secs(snapshot_ttl_hours * 3600),
            offline_grace: Duration::from_secs(offline_grace_days * 86400),
            deletion_cooling_off: Duration::from_secs(
                parse_u64("DELETION_COOLING_OFF_DAYS", 14)? * 86400,
            ),
            usage_reservation_ttl: Duration::from_secs(parse_u64(
                "USAGE_RESERVATION_TTL_SECS",
                900,
            )?),
            usage_threshold_percents: parse_percent_list("USAGE_THRESHOLD_PERCENTS", &[80, 100])?,
            request_timeout: Duration::from_secs(parse_u64("REQUEST_TIMEOUT_SECS", 30)?),
            max_body_bytes: parse_u64("MAX_BODY_BYTES", 1024 * 1024)? as usize,
            rate_limit_per_minute: u32::try_from(parse_u64("RATE_LIMIT_PER_MINUTE", 300)?)
                .map_err(|_| {
                    ConfigError::Invalid("RATE_LIMIT_PER_MINUTE", "value too large".to_string())
                })?,
        })
    }
}
