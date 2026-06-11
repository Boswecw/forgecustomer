//! ForgeCustomer API entry point — thin wrapper over the `forgecustomer_api` library.

use std::net::SocketAddr;
use std::time::Duration;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use forgecustomer_api::config::Config;
use forgecustomer_api::integrations::dataforge::DataforgeClient;
use forgecustomer_api::state::AppState;
use forgecustomer_api::{routes, workers};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = Config::from_env().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let host = config.host.clone();
    let port = config.port;
    let app_env = config.app_env.clone();
    let dataforge_url = config.dataforge_api_url.clone();
    let dataforge_token = config.dataforge_service_token.clone();

    let state = AppState::build(config).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Spawn the outbox publisher when DataForge is configured. Its absence never blocks
    // the API from starting.
    if !dataforge_url.is_empty() {
        let worker_state = state.clone();
        let client = DataforgeClient::new(state.http.clone(), dataforge_url, dataforge_token);
        tokio::spawn(async move {
            workers::outbox::run(worker_state, client, Duration::from_secs(5)).await;
        });
    }

    // Reservation expiry sweeper: reclaims quota held by abandoned reservations.
    let sweeper_state = state.clone();
    tokio::spawn(async move {
        workers::usage::run(sweeper_state, Duration::from_secs(30)).await;
    });

    let app = routes::build_router(state);

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;
    tracing::info!(%addr, env = %app_env, "ForgeCustomer API starting");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,forgecustomer_api=debug"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}
