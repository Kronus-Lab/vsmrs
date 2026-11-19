//! Vault KV metadata validation and OpenVPN profile rendering.
//!
//! The KV payload is attacker-influenced data: it is validated before any of
//! its fields reach the template, and only the two legitimate multi-line PEM
//! blobs are allowed to contain newlines. Rendering uses the shared minijinja
//! environment, whose auto-escape callback is disabled for `.ovpn` names.

use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};

use crate::vault::Certificate;

/// Validated KV v2 payload ready for template substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub hostname: String,
    pub port: String,
    pub protocol: String,
    pub server_dn: String,
    pub cipher: String,
    pub digest: String,
    pub certificate_authority: String,
    pub server_tls_key: String,
}

/// Opening and closing tags that could escape a template block.
const OVPN_TAGS: &[&str] = &[
    "<ca>",
    "</ca>",
    "<cert>",
    "</cert>",
    "<key>",
    "</key>",
    "<tls-crypt>",
    "</tls-crypt>",
];

/// Closing tags that must never appear inside a PEM blob.
const PEM_CLOSING_TAGS: &[&str] = &["</ca>", "</cert>", "</key>", "</tls-crypt>"];

/// OpenVPN directives that must never appear as a line inside a PEM blob.
const OVPN_DIRECTIVES: &[&str] = &[
    "auth",
    "ca",
    "cert",
    "cipher",
    "client",
    "comp-lzo",
    "dev",
    "dev-type",
    "float",
    "ifconfig",
    "keepalive",
    "key",
    "key-direction",
    "lport",
    "mute",
    "nobind",
    "persist-key",
    "persist-tun",
    "port",
    "proto",
    "remote",
    "remote-cert-tls",
    "resolv-retry",
    "reneg-sec",
    "route",
    "secret",
    "tls-auth",
    "tls-crypt",
    "verb",
    "verify-x509-name",
];

/// Validates a KV v2 `data.data` payload and normalizes it for rendering.
pub fn parse_metadata(value: &Value) -> Result<Metadata> {
    let object = value
        .as_object()
        .context("Vault metadata must be a JSON object")?;

    let hostname = scalar(object, "hostname")?;
    let port = port(object)?;
    let protocol = scalar(object, "protocol")?;
    let server_dn = scalar(object, "server_dn")?;
    let cipher = scalar(object, "cipher")?;
    let digest = scalar(object, "digest")?;
    let certificate_authority = pem(object, "certificate_authority")?;
    let server_tls_key = pem(object, "server_tls_key")?;

    Ok(Metadata {
        hostname,
        port,
        protocol,
        server_dn,
        cipher,
        digest,
        certificate_authority,
        server_tls_key,
    })
}

/// Renders the fixed directive set with validated metadata and Vault-issued
/// credentials. `.ovpn` templates are not HTML-escaped by the shared
/// environment, so PEM blobs reach the file verbatim.
pub fn render(metadata: &Metadata, cert: &Certificate) -> Result<String> {
    crate::web::templates::render(
        "template.ovpn",
        minijinja::context! {
            cipher => &metadata.cipher,
            digest => &metadata.digest,
            hostname => &metadata.hostname,
            port => &metadata.port,
            protocol => &metadata.protocol,
            server_dn => &metadata.server_dn,
            certificate_authority => &metadata.certificate_authority,
            certificate => &cert.certificate,
            certificate_key => &cert.private_key,
            server_tls_key => &metadata.server_tls_key,
        },
    )
    .context("failed to render the OVPN template")
}

fn scalar(object: &Map<String, Value>, key: &str) -> Result<String> {
    let value = object
        .get(key)
        .with_context(|| format!("missing metadata key `{key}`"))?;
    let text = value
        .as_str()
        .with_context(|| format!("metadata key `{key}` must be a string"))?;
    if text.trim().is_empty() {
        bail!("metadata key `{key}` must not be empty");
    }

    if text.contains('\r') || text.contains('\n') {
        bail!("metadata key `{key}` must not contain CR or LF");
    }
    let lowered = text.to_ascii_lowercase();
    if OVPN_TAGS.iter().any(|tag| lowered.contains(tag)) {
        bail!("metadata key `{key}` must not contain an OVPN tag");
    }
    if key == "server_dn" && text.chars().filter(|character| *character == '"').count() % 2 != 0 {
        bail!("metadata key `server_dn` must not contain unbalanced quotes");
    }

    Ok(text.to_owned())
}

/// The reference Terraform writes `port` as the JSON number `1194`.
fn port(object: &Map<String, Value>) -> Result<String> {
    let value = object.get("port").context("missing metadata key `port`")?;
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => bail!("metadata key `port` must be a string or number"),
    };
    if text.trim().is_empty() {
        bail!("metadata key `port` must not be empty");
    }
    if text.contains('\r') || text.contains('\n') {
        bail!("metadata key `port` must not contain CR or LF");
    }
    let lowered = text.to_ascii_lowercase();
    if OVPN_TAGS.iter().any(|tag| lowered.contains(tag)) {
        bail!("metadata key `port` must not contain an OVPN tag");
    }

    Ok(text)
}

fn pem(object: &Map<String, Value>, key: &str) -> Result<String> {
    let value = object
        .get(key)
        .with_context(|| format!("missing metadata key `{key}`"))?;
    let text = value
        .as_str()
        .with_context(|| format!("metadata key `{key}` must be a string"))?;
    if text.trim().is_empty() {
        bail!("metadata key `{key}` must not be empty");
    }

    // CRLF and bare CR are normalized so a Windows-authored PEM still renders
    // as well-formed text in the profile.
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let lowered = normalized.to_ascii_lowercase();
    if PEM_CLOSING_TAGS.iter().any(|tag| lowered.contains(tag)) {
        bail!("metadata key `{key}` must not contain a closing OVPN tag");
    }

    let mut begin_labels: Vec<&str> = Vec::new();
    let mut end_labels: Vec<&str> = Vec::new();
    for line in normalized.lines() {
        let line = line.trim();
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            begin_labels.push(label);
        } else if let Some(label) = line
            .strip_prefix("-----END ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            end_labels.push(label);
        }
    }
    if begin_labels.is_empty() || end_labels.is_empty() {
        bail!("metadata key `{key}` needs matching PEM BEGIN and END markers");
    }
    let mut unmatched = begin_labels;
    for label in &end_labels {
        let Some(index) = unmatched.iter().position(|candidate| candidate == label) else {
            bail!("metadata key `{key}` has an unmatched PEM END marker");
        };
        unmatched.remove(index);
    }
    if !unmatched.is_empty() {
        bail!("metadata key `{key}` has an unmatched PEM BEGIN marker");
    }
    let first_begin = normalized
        .find("-----BEGIN ")
        .context("PEM BEGIN marker is missing")?;
    let first_end = normalized
        .find("-----END ")
        .context("PEM END marker is missing")?;
    if first_begin > first_end {
        bail!("metadata key `{key}` has a PEM END marker before its BEGIN marker");
    }

    for line in normalized.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("-----") {
            continue;
        }
        let directive = line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if OVPN_DIRECTIVES.contains(&directive.as_str()) {
            bail!("metadata key `{key}` contains a directive-looking line");
        }
    }

    Ok(normalized)
}

#[cfg(test)]
pub(crate) mod test_support {
    use serde_json::json;

    use crate::vault::Certificate;

    /// The exact `develmeta` payload written by `test/presetup/main.tf`.
    pub(crate) fn reference_metadata_json() -> serde_json::Value {
        json!({
            "hostname": "myvpn.example.com",
            "port": 1194,
            "protocol": "udp",
            "server_dn": "C=CA, ST=Ontario, L=Toronto, O=My Org, emailAddress=admin@example.com, CN=myvpn.example.com",
            "cipher": "AES-256-CBC",
            "digest": "SHA1",
            "certificate_authority": "-----BEGIN CERTIFICATE-----\nsingleline\ncertificate\n-----END CERTIFICATE-----",
            "server_tls_key": "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\nsingleline\nstatickey\n-----END OpenVPN Static key V1-----\n"
        })
    }

    pub(crate) fn stub_certificate() -> Certificate {
        Certificate {
            certificate: "-----BEGIN CERTIFICATE-----\nstub-cert\n-----END CERTIFICATE-----"
                .to_owned(),
            private_key: "-----BEGIN PRIVATE KEY-----\nstub-key\n-----END PRIVATE KEY-----"
                .to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_reference_metadata() {
        let metadata = parse_metadata(&test_support::reference_metadata_json())
            .expect("the Terraform develmeta payload parses");

        assert_eq!(metadata.hostname, "myvpn.example.com");
        assert_eq!(metadata.port, "1194");
        assert_eq!(metadata.protocol, "udp");
        assert_eq!(
            metadata.server_dn,
            "C=CA, ST=Ontario, L=Toronto, O=My Org, emailAddress=admin@example.com, CN=myvpn.example.com"
        );
        assert_eq!(metadata.cipher, "AES-256-CBC");
        assert_eq!(metadata.digest, "SHA1");
        assert!(metadata
            .certificate_authority
            .contains("-----BEGIN CERTIFICATE-----"));
        assert!(metadata
            .server_tls_key
            .contains("-----BEGIN OpenVPN Static key V1-----"));
    }

    #[test]
    fn rejects_newline_in_scalar() {
        let mut value = test_support::reference_metadata_json();
        value["hostname"] = json!("myvpn.example.com\nremote evil.example.com 1194 udp");

        assert!(
            parse_metadata(&value).is_err(),
            "a scalar containing CR/LF must be rejected"
        );
    }

    #[test]
    fn rejects_ovpn_tag_in_pem() {
        let mut value = test_support::reference_metadata_json();
        value["certificate_authority"] =
            json!("-----BEGIN CERTIFICATE-----\n</ca>\n-----END CERTIFICATE-----");

        assert!(
            parse_metadata(&value).is_err(),
            "a closing OVPN tag inside a PEM blob must be rejected"
        );
    }

    #[test]
    fn accepts_multiline_pem() {
        let mut value = test_support::reference_metadata_json();
        value["certificate_authority"] = json!(
            "-----BEGIN CERTIFICATE-----\r\nsingleline\r\ncertificate\r\n-----END CERTIFICATE-----\r\n"
        );

        let metadata = parse_metadata(&value).expect("CRLF in a PEM blob is normalized");

        assert_eq!(
            metadata.certificate_authority,
            "-----BEGIN CERTIFICATE-----\nsingleline\ncertificate\n-----END CERTIFICATE-----\n"
        );
        assert!(!metadata.certificate_authority.contains('\r'));
    }

    #[test]
    fn render_matches_directives() {
        let metadata = parse_metadata(&test_support::reference_metadata_json())
            .expect("reference metadata parses");
        let cert = test_support::stub_certificate();

        let body = render(&metadata, &cert).expect("the reference profile renders");

        for expected in [
            "dev tun",
            "cipher AES-256-CBC",
            "auth SHA1",
            "remote myvpn.example.com 1194 udp",
            "verify-x509-name \"C=CA, ST=Ontario, L=Toronto, O=My Org, \
             emailAddress=admin@example.com, CN=myvpn.example.com\" subject",
            "<ca>",
            "<cert>",
            "<key>",
            "<tls-crypt>",
            "-----BEGIN CERTIFICATE-----\nstub-cert\n-----END CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nstub-key\n-----END PRIVATE KEY-----",
        ] {
            assert!(
                body.contains(expected),
                "rendered profile must contain {expected:?}: {body}"
            );
        }
    }
}
