//! Loads and validates the VSM configuration files.
//!
//! Both files are read from paths supplied by the caller; `main` passes the
//! app-root-relative defaults (`config/vsm/app.json` and
//! `config/vsm/vpn_group_mapping.json`).

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use url::Url;

/// Minimum `SESSION_SECRET` length outside development, in bytes.
const MIN_PRODUCTION_SECRET_BYTES: usize = 32;

/// Settings read from `config/vsm/app.json`.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub session_secret: String,
    pub env: String,
    pub hostname: String,
    pub redis_host: String,
    pub redis_port: u16,
    pub vault_url: Url,
    pub custom_vault_ca: Option<String>,
    pub auth_issuer: Url,
    pub auth_client_id: String,
    pub auth_client_secret: String,
    pub auth_username_field: String,
    pub auth_groups_field: String,
}

impl AppConfig {
    /// Whether the app runs in the development environment.
    pub fn is_development(&self) -> bool {
        self.env == "development"
    }
}

/// One group-to-VPN-server mapping from `config/vsm/vpn_group_mapping.json`.
///
/// The `vault_*` fields are consumed by the download route; they are validated
/// here so a bad mapping aborts startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub vpn_server: String,
    pub idp_group: String,
    pub vault_metadata_mountpoint: String,
    pub vault_metadata_path: String,
    pub vault_pki_mountpoint: String,
    pub vault_jwt_role: String,
    pub vault_jwt_path: String,
}

/// Reads and validates the app config and the VPN group mappings.
///
/// Returns an error when either file is unreadable, is not valid JSON, is
/// missing a required key, contains an empty required value, has an invalid
/// port or absolute URL, or maps two servers to the same `vpn_server`.
pub fn load(app_path: &Path, mappings_path: &Path) -> Result<(AppConfig, Vec<Mapping>)> {
    let app_value = read_json(app_path)?;
    let app_object = app_value
        .as_object()
        .with_context(|| format!("{} must contain a JSON object", app_path.display()))?;
    let config = parse_app_config(app_object)?;

    let mappings_value = read_json(mappings_path)?;
    let entries = mappings_value
        .as_array()
        .with_context(|| format!("{} must contain a JSON array", mappings_path.display()))?;

    let mut mappings = Vec::with_capacity(entries.len());
    let mut seen_servers = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let mapping = parse_mapping(entry).with_context(|| format!("mapping at index {index}"))?;
        if !seen_servers.insert(mapping.vpn_server.clone()) {
            bail!(
                "duplicate vpn_server `{}` in {}",
                mapping.vpn_server,
                mappings_path.display()
            );
        }
        tracing::info!(
            vpn_server = %mapping.vpn_server,
            idp_group = %mapping.idp_group,
            "loaded mapping"
        );
        mappings.push(mapping);
    }

    Ok((config, mappings))
}

fn parse_app_config(raw: &Map<String, Value>) -> Result<AppConfig> {
    let env = required_string(raw, "ENV")?;
    let is_development = env == "development";

    let session_secret = required_string(raw, "SESSION_SECRET")?;
    if session_secret.len() < MIN_PRODUCTION_SECRET_BYTES {
        if is_development {
            tracing::warn!(
                "SESSION_SECRET is shorter than {MIN_PRODUCTION_SECRET_BYTES} bytes; \
                 this is only acceptable in development"
            );
        } else {
            bail!(
                "SESSION_SECRET must be at least {MIN_PRODUCTION_SECRET_BYTES} bytes \
                 when ENV is not development"
            );
        }
    }

    let redis_port_text = required_string(raw, "REDIS_PORT")?;
    let redis_port = redis_port_text
        .parse::<u16>()
        .with_context(|| format!("REDIS_PORT `{redis_port_text}` is not a valid port"))?;

    Ok(AppConfig {
        session_secret,
        env,
        hostname: required_string(raw, "HOSTNAME")?,
        redis_host: required_string(raw, "REDIS_HOST")?,
        redis_port,
        vault_url: absolute_url(raw, "VAULT_URL")?,
        custom_vault_ca: optional_string(raw, "CUSTOM_VAULT_CA")?,
        auth_issuer: absolute_url(raw, "AUTH_ISSUER")?,
        auth_client_id: required_string(raw, "AUTH_CLIENT_ID")?,
        auth_client_secret: required_string(raw, "AUTH_CLIENT_SECRET")?,
        auth_username_field: required_string(raw, "AUTH_USERNAME_FIELD")?,
        auth_groups_field: required_string(raw, "AUTH_GROUPS_FIELD")?,
    })
}

fn parse_mapping(entry: &Value) -> Result<Mapping> {
    let raw = entry
        .as_object()
        .context("mapping must contain a JSON object")?;

    Ok(Mapping {
        vpn_server: required_string(raw, "vpn_server")?,
        idp_group: required_string(raw, "idp_group")?,
        vault_metadata_mountpoint: required_string(raw, "vault_metadata_mountpoint")?,
        vault_metadata_path: required_string(raw, "vault_metadata_path")?,
        vault_pki_mountpoint: required_string(raw, "vault_pki_mountpoint")?,
        vault_jwt_role: required_string(raw, "vault_jwt_role")?,
        vault_jwt_path: required_string(raw, "vault_jwt_path")?,
    })
}

fn read_json(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse config file {} as JSON", path.display()))
}

fn required_string(raw: &Map<String, Value>, key: &str) -> Result<String> {
    let value = raw
        .get(key)
        .with_context(|| format!("missing required key `{key}`"))?;
    let text = value
        .as_str()
        .with_context(|| format!("key `{key}` must be a string"))?;

    if text.trim().is_empty() {
        bail!("key `{key}` must not be empty");
    }

    Ok(text.to_owned())
}

fn optional_string(raw: &Map<String, Value>, key: &str) -> Result<Option<String>> {
    match raw.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.trim().is_empty() => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => bail!("key `{key}` must be a string"),
    }
}

fn absolute_url(raw: &Map<String, Value>, key: &str) -> Result<Url> {
    let text = required_string(raw, key)?;
    let url = Url::parse(&text).with_context(|| format!("`{key}` is not a valid URL: `{text}`"))?;

    if !url.has_host() {
        bail!("`{key}` must be an absolute URL with a host: `{text}`");
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const REFERENCE_APP: &str = r#"{
        "HOSTNAME": "vsm.local.kronus.network",
        "REDIS_HOST": "localhost",
        "REDIS_PORT": "6379",
        "VAULT_URL": "http://hcv.local.kronus.network",
        "AUTH_ISSUER": "http://kc.local.kronus.network/realms/devel",
        "AUTH_CLIENT_ID": "vsm",
        "AUTH_CLIENT_SECRET": "devel1234",
        "AUTH_USERNAME_FIELD": "preferred_username",
        "AUTH_GROUPS_FIELD": "groups",
        "ENV": "development",
        "SESSION_SECRET": "itsasecret"
    }"#;

    const REFERENCE_MAPPINGS: &str = r#"[
        {
            "vpn_server": "myserver",
            "idp_group": "/example",
            "vault_metadata_mountpoint": "vpnmeta",
            "vault_metadata_path": "develmeta",
            "vault_pki_mountpoint": "vpn/devel",
            "vault_jwt_role": "test-role",
            "vault_jwt_path": "jwt"
        },
        {
            "vpn_server": "myserver2",
            "idp_group": "/example",
            "vault_metadata_mountpoint": "vpnmeta",
            "vault_metadata_path": "develmeta",
            "vault_pki_mountpoint": "vpn/devel",
            "vault_jwt_role": "test-role",
            "vault_jwt_path": "jwt"
        }
    ]"#;

    /// Writes the two config files into a uniquely named temp directory so the
    /// four tests can run in parallel.
    fn write_fixtures(tag: &str, app_json: &str, mappings_json: &str) -> (PathBuf, PathBuf) {
        let unique = format!(
            "vsm-config-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is before the unix epoch")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).expect("create fixture directory");

        let app_path = dir.join("app.json");
        let mappings_path = dir.join("vpn_group_mapping.json");
        std::fs::write(&app_path, app_json).expect("write app fixture");
        std::fs::write(&mappings_path, mappings_json).expect("write mappings fixture");

        (app_path, mappings_path)
    }

    #[test]
    fn accepts_reference_config() {
        let (app_path, mappings_path) =
            write_fixtures("accepts", REFERENCE_APP, REFERENCE_MAPPINGS);

        let (config, mappings) = load(&app_path, &mappings_path).expect("reference config loads");

        assert_eq!(config.redis_port, 6379);
        assert_eq!(mappings.len(), 2);
        assert!(config.is_development());
        assert_eq!(config.auth_username_field, "preferred_username");
        assert_eq!(config.auth_groups_field, "groups");
    }

    #[test]
    fn rejects_duplicate_vpn_server() {
        let duplicate_mappings = r#"[
            {
                "vpn_server": "myserver",
                "idp_group": "/example",
                "vault_metadata_mountpoint": "vpnmeta",
                "vault_metadata_path": "develmeta",
                "vault_pki_mountpoint": "vpn/devel",
                "vault_jwt_role": "test-role",
                "vault_jwt_path": "jwt"
            },
            {
                "vpn_server": "myserver",
                "idp_group": "/example2",
                "vault_metadata_mountpoint": "vpnmeta",
                "vault_metadata_path": "develmeta",
                "vault_pki_mountpoint": "vpn/devel",
                "vault_jwt_role": "test-role",
                "vault_jwt_path": "jwt"
            }
        ]"#;
        let (app_path, mappings_path) =
            write_fixtures("duplicate", REFERENCE_APP, duplicate_mappings);

        let error = load(&app_path, &mappings_path).expect_err("duplicate servers are rejected");

        let message = format!("{error:#}");
        assert!(message.contains("duplicate"), "unexpected error: {message}");
    }

    #[test]
    fn rejects_missing_groups_field() {
        let app_without_groups = REFERENCE_APP.replace("\"AUTH_GROUPS_FIELD\": \"groups\",", "");
        let (app_path, mappings_path) =
            write_fixtures("missing-groups", &app_without_groups, REFERENCE_MAPPINGS);

        let error = load(&app_path, &mappings_path).expect_err("missing groups field is rejected");

        let message = format!("{error:#}");
        assert!(
            message.contains("AUTH_GROUPS_FIELD"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn rejects_bad_port() {
        let app_with_bad_port =
            REFERENCE_APP.replace("\"REDIS_PORT\": \"6379\"", "\"REDIS_PORT\": \"not-a-port\"");
        let (app_path, mappings_path) =
            write_fixtures("bad-port", &app_with_bad_port, REFERENCE_MAPPINGS);

        let error = load(&app_path, &mappings_path).expect_err("invalid port is rejected");

        let message = format!("{error:#}");
        assert!(
            message.contains("REDIS_PORT"),
            "unexpected error: {message}"
        );
    }
}
