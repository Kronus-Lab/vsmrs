//! HTTP handlers, wired into the axum router.

pub mod api;
pub mod auth;
pub mod portal;
pub mod static_files;

use std::sync::OnceLock;

use axum::routing::{get, post};
use axum::Router;
use minijinja::{AutoEscape, Environment, Value};
use rust_embed::RustEmbed;

use crate::state::AppState;

/// Compile-time embedded templates, with a mounted `templates/` directory
/// taking precedence when one is present (CWD is the app root).
#[derive(RustEmbed)]
#[folder = "templates/"]
struct EmbeddedTemplates;

/// Shared minijinja environment: HTML templates are auto-escaped, data
/// templates such as `template.ovpn` are not.
pub(crate) mod templates {
    use super::*;

    fn embedded_source(name: &str) -> Option<String> {
        EmbeddedTemplates::get(name).map(|file| String::from_utf8_lossy(&file.data).into_owned())
    }

    /// Returns a template's source, preferring a mounted directory file.
    pub(crate) fn source(name: &str) -> Option<String> {
        match std::fs::read(std::path::Path::new("templates").join(name)) {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => embedded_source(name),
        }
    }

    pub(crate) fn environment() -> &'static Environment<'static> {
        static ENVIRONMENT: OnceLock<Environment<'static>> = OnceLock::new();

        ENVIRONMENT.get_or_init(|| {
            let mut environment = Environment::new();
            environment.set_auto_escape_callback(|name| {
                if name.ends_with(".html") {
                    AutoEscape::Html
                } else {
                    AutoEscape::None
                }
            });
            for name in EmbeddedTemplates::iter() {
                if let Some(source) = source(&name) {
                    environment
                        .add_template_owned(name.to_string(), source)
                        .unwrap_or_else(|error| panic!("invalid template {name}: {error}"));
                }
            }
            environment
        })
    }

    /// Renders one of the registered templates with the given context.
    pub(crate) fn render<V: Into<Value>>(
        name: &str,
        context: V,
    ) -> Result<String, minijinja::Error> {
        environment().get_template(name)?.render(context)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn template_is_embedded_for_diskless_runtime() {
            let source = embedded_source("base.html").expect("base.html is embedded");
            assert!(source.contains("<!DOCTYPE html>"));
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(portal::index))
        .route("/static/{*path}", get(static_files::file))
        .route("/api/whoami", get(api::whoami))
        .route("/api/servers/{server}", post(api::download))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", get(auth::logout_get).post(auth::logout))
        .with_state(state)
}
