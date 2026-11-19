//! Shared application state for the web handlers.

use std::sync::Arc;

use axum::extract::FromRef;
use cookie::Key;

use crate::config::{AppConfig, Mapping};
use crate::oidc::OidcClient;
use crate::session::SessionStore;
use crate::vault::VaultClient;

/// State shared by the web handlers and the cookie key source.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub mappings: Arc<Vec<Mapping>>,
    pub store: Arc<dyn SessionStore>,
    pub oidc: Arc<OidcClient>,
    pub vault: Arc<VaultClient>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        crate::session::signing_key(&state.config.flask_secret)
    }
}
