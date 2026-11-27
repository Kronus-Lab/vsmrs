//! HTTP handlers, wired into the axum router.

pub mod api;
pub mod auth;
pub mod portal;
pub mod static_files;

use std::path::Path;
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

    /// Returns a template's source from `root`, preferring a mounted file over
    /// the embedded default.
    fn source_from(name: &str, root: &Path) -> Option<String> {
        match std::fs::read(root.join(name)) {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => embedded_source(name),
        }
    }

    /// Returns a template's source, preferring the mounted `templates/` file.
    pub(crate) fn source(name: &str) -> Option<String> {
        source_from(name, Path::new("templates"))
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

        /// A uniquely named temp template root removed on drop, even on panic.
        struct TempTemplateRoot(std::path::PathBuf);

        impl TempTemplateRoot {
            fn new(label: &str, name: &str, contents: &str) -> Self {
                let unique = format!(
                    "vsm-templates-{label}-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("system clock is after the unix epoch")
                        .as_nanos()
                );
                let root = std::env::temp_dir().join(unique);
                std::fs::create_dir_all(&root).expect("create template temp root");
                std::fs::write(root.join(name), contents).expect("write template override");
                Self(root)
            }
        }

        impl Drop for TempTemplateRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn template_is_embedded_for_diskless_runtime() {
            let source = embedded_source("base.html").expect("base.html is embedded");
            assert!(source.contains("<!DOCTYPE html>"));
        }

        #[test]
        fn mounted_template_overrides_embedded_source() {
            let marker = "<!-- mounted base.html override -->";
            let root = TempTemplateRoot::new("override", "base.html", marker);

            let source = source_from("base.html", &root.0).expect("template source is available");
            assert_eq!(source, marker);
            assert_ne!(
                source,
                embedded_source("base.html").expect("base.html is embedded")
            );
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
