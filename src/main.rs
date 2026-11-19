//! VSM bootstrap: load and validate configuration before serving.

mod authz;
mod config;
mod error;
mod oidc;
mod ovpn;
mod session;
mod state;
mod vault;

pub mod web;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Registry;

use crate::oidc::OidcClient;
use crate::session::{RedisStore, SessionStore};
use crate::state::AppState;
use crate::vault::VaultClient;

const APP_CONFIG_PATH: &str = "config/vsm/app.json";
const MAPPINGS_CONFIG_PATH: &str = "config/vsm/vpn_group_mapping.json";

#[tokio::main]
async fn main() {
    // Start at info so startup messages are visible, then raise the level once
    // the environment is known (development enables debug tracing).
    let (filter, log_level) = reload::Layer::new(LevelFilter::INFO);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    if let Err(error) = run(&log_level).await {
        eprintln!("vsm: startup failed: {error:#}");
        std::process::exit(1);
    }
}

async fn run(log_level: &reload::Handle<LevelFilter, Registry>) -> Result<()> {
    let (config, mappings) =
        config::load(Path::new(APP_CONFIG_PATH), Path::new(MAPPINGS_CONFIG_PATH))
            .context("failed to load configuration")?;

    if config.is_development() {
        log_level
            .modify(|filter| *filter = LevelFilter::DEBUG)
            .context("failed to enable debug logging")?;
        tracing::info!("ENV=development: debug logging enabled");
    }

    // Never log the custom CA value: it may be an inline PEM blob.
    let trust_source = if config.custom_vault_ca.is_some() {
        "embedded webpki roots plus a configured custom Vault CA"
    } else {
        "embedded webpki roots"
    };
    tracing::info!("TLS trust source: {trust_source}");

    tracing::info!(
        env = %config.env,
        hostname = %config.hostname,
        redis_host = %config.redis_host,
        redis_port = config.redis_port,
        vault_url = %config.vault_url,
        auth_issuer = %config.auth_issuer,
        auth_client_id = %config.auth_client_id,
        auth_username_field = %config.auth_username_field,
        auth_groups_field = %config.auth_groups_field,
        mappings = mappings.len(),
        "configuration loaded"
    );

    let store: Arc<dyn SessionStore> = Arc::new(
        RedisStore::connect(&config.redis_host, config.redis_port)
            .await
            .context("failed to connect to redis")?,
    );
    // `new` still performs discovery with the dedicated client, but a
    // discovery failure is retained inside it and surfaced as 502 on
    // /auth/login; only an HTTP-client construction failure aborts startup.
    let oidc = Arc::new(
        OidcClient::new(&config)
            .await
            .context("failed to build OIDC HTTP client")?,
    );
    let vault = Arc::new(
        VaultClient::new(
            config.vault_url.clone(),
            config.custom_vault_ca.as_deref(),
            !config.is_development(),
        )
        .context("failed to build Vault HTTP client")?,
    );

    let state = AppState {
        config: Arc::new(config),
        mappings: Arc::new(mappings),
        store,
        oidc,
        vault,
    };

    let app = web::router(state);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", 3000))
        .await
        .context("failed to bind listener")?;
    axum::serve(listener, app)
        .await
        .context("failed to serve")?;

    Ok(())
}
