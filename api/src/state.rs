//! Shared application state injected into handlers.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::auth::JwtValidator;
use crate::config::Config;
use crate::services::signing::{Signer25519, VerifyingKeyRing};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: PgPool,
    pub signer: Arc<Signer25519>,
    pub key_ring: Arc<VerifyingKeyRing>,
    pub customer_validator: JwtValidator,
    pub admin_validator: JwtValidator,
    pub http: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("signing key error: {0}")]
    Signing(#[from] crate::services::signing::SigningError),
    #[error("database pool error: {0}")]
    Pool(#[from] sqlx::Error),
    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),
}

impl AppState {
    /// Build application state from configuration. The database pool connects lazily so the
    /// process can start (and serve `/v1/health`) before the database is reachable.
    pub fn build(config: Config) -> Result<Self, StateError> {
        let signer = Signer25519::from_base64_seed(
            &config.entitlement_signing_key_id,
            &config.entitlement_signing_private_key,
        )?;

        let mut key_ring = VerifyingKeyRing::new();
        key_ring.add_signer(&signer);

        let customer_validator = JwtValidator::hs256(
            &config.supabase_jwt_secret,
            &config.supabase_jwt_issuer,
            &config.supabase_jwt_audience,
        );
        let admin_validator = JwtValidator::hs256(
            &config.admin_jwt_secret,
            &config.admin_jwt_issuer,
            &config.admin_jwt_audience,
        );

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect_lazy(&config.database_url)?;

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        Ok(Self {
            config: Arc::new(config),
            pool,
            signer: Arc::new(signer),
            key_ring: Arc::new(key_ring),
            customer_validator,
            admin_validator,
            http,
        })
    }
}
