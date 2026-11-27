//! Vault JWT/KV/PKI client used by the download handler.
//!
//! One `reqwest::Client` is built per app state with an explicit trust store:
//! the embedded webpki roots, optionally extended by `CUSTOM_VAULT_CA` (inline
//! PEM or a path to a mounted PEM file). The system store is never consulted,
//! which is what lets the binary run in `FROM scratch`. Verification is
//! disabled only for development.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use url::Url;

use crate::config::Mapping;
use crate::ovpn::{parse_metadata, Metadata};

/// A Vault-issued short-lived client certificate and its private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub certificate: String,
    pub private_key: String,
}

/// Client for the three Vault calls the download flow needs.
pub struct VaultClient {
    base_url: Url,
    client: reqwest::Client,
}

impl VaultClient {
    /// Builds the HTTP client with embedded roots plus an optional custom CA.
    ///
    /// The CA value is deliberately never logged: it may be an inline PEM
    /// blob. Only a static trust-source line is emitted.
    pub fn new(base_url: Url, custom_ca: Option<&str>, verify: bool) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca) = custom_ca {
            // An inline PEM is identified by its BEGIN marker; anything else
            // is a path to a mounted PEM file.
            let pem = if ca.contains("-----BEGIN ") {
                ca.to_owned()
            } else {
                std::fs::read_to_string(ca).context("failed to read the custom Vault CA file")?
            };
            let mut added = false;
            for certificate in rustls_pemfile::certs(&mut pem.as_bytes()) {
                let certificate = certificate.context("invalid PEM in the custom Vault CA")?;
                roots
                    .add(certificate)
                    .context("failed to add the custom Vault CA to the root store")?;
                added = true;
            }
            if !added {
                bail!("the configured custom Vault CA contains no PEM certificates");
            }
        }

        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let mut builder = reqwest::Client::builder();
        if verify {
            builder = builder.use_preconfigured_tls(tls);
        } else {
            // Development only; the caller has already checked the environment.
            builder = builder.danger_accept_invalid_certs(true);
        }
        // Never follow a Vault redirect: a 3xx could replay the JWT body or
        // the X-Vault-Token header to an attacker-controlled origin.
        let client = builder
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build the Vault HTTP client")?;

        tracing::debug!(
            verify,
            custom_ca_configured = custom_ca.is_some(),
            "Vault client built with embedded webpki roots"
        );

        Ok(Self { base_url, client })
    }

    /// Logs in with the session's access token and returns `auth.client_token`.
    pub async fn jwt_login(&self, jwt: &str, mapping: &Mapping) -> Result<String> {
        let url = self.endpoint(&format!("v1/auth/{}/login", mapping.vault_jwt_path))?;
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({ "role": mapping.vault_jwt_role, "jwt": jwt }))
            .send()
            .await
            .context("Vault JWT login request failed")?;
        let body = success_body(response, "Vault JWT login").await?;
        let token = body
            .get("auth")
            .and_then(|auth| auth.get("client_token"))
            .and_then(Value::as_str)
            .context("Vault JWT login response has no auth.client_token")?;

        Ok(token.to_owned())
    }

    /// Reads KV v2 metadata from `data.data` and validates every field.
    pub async fn read_metadata(&self, token: &str, mapping: &Mapping) -> Result<Metadata> {
        let url = self.endpoint(&format!(
            "v1/{}/data/{}",
            mapping.vault_metadata_mountpoint, mapping.vault_metadata_path
        ))?;
        let response = self
            .client
            .get(url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .context("Vault metadata request failed")?;
        let body = success_body(response, "Vault metadata read").await?;
        let data = body
            .get("data")
            .and_then(|outer| outer.get("data"))
            .context("Vault metadata response has no data.data")?;
        let metadata = parse_metadata(data)?;

        // Only non-secret fields are logged; CA blobs, the TLS crypt key and
        // all tokens stay out of the logs.
        tracing::debug!(
            hostname = %metadata.hostname,
            port = %metadata.port,
            protocol = %metadata.protocol,
            cipher = %metadata.cipher,
            digest = %metadata.digest,
            server_dn = %metadata.server_dn,
            "Vault metadata loaded"
        );

        Ok(metadata)
    }

    /// Issues a client certificate under the mapping's PKI mount. The common
    /// name is the only app-supplied field; the TTL comes from the Vault role.
    pub async fn issue_certificate(
        &self,
        token: &str,
        mapping: &Mapping,
        common_name: &str,
    ) -> Result<Certificate> {
        let url = self.endpoint(&format!("v1/{}/issue/client", mapping.vault_pki_mountpoint))?;
        let response = self
            .client
            .post(url)
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({ "common_name": common_name }))
            .send()
            .await
            .context("Vault certificate issuance request failed")?;
        let body = success_body(response, "Vault certificate issuance").await?;
        let data = body
            .get("data")
            .context("Vault certificate response has no data")?;
        let certificate = string_field(data, "certificate", "Vault certificate")?;
        let private_key = string_field(data, "private_key", "Vault certificate")?;

        Ok(Certificate {
            certificate: certificate.to_owned(),
            private_key: private_key.to_owned(),
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path)
            .with_context(|| format!("invalid Vault endpoint path `{path}`"))
    }
}

async fn success_body(response: reqwest::Response, operation: &str) -> Result<Value> {
    let status = response.status();
    if !status.is_success() {
        // Upstream responses can echo request material, so log only the
        // status, never the body.
        bail!("{operation} returned HTTP {status}");
    }
    response
        .json::<Value>()
        .await
        .with_context(|| format!("{operation} returned a non-JSON body"))
}

fn string_field<'a>(object: &'a Value, key: &str, operation: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{operation} response has no string `{key}`"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;
    use url::Url;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn mapping() -> Mapping {
        Mapping {
            vpn_server: "myserver".to_owned(),
            idp_group: "/example".to_owned(),
            vault_metadata_mountpoint: "vpnmeta".to_owned(),
            vault_metadata_path: "develmeta".to_owned(),
            vault_pki_mountpoint: "vpn/devel".to_owned(),
            vault_jwt_role: "test-role".to_owned(),
            vault_jwt_path: "jwt".to_owned(),
        }
    }

    fn client(server: &MockServer) -> VaultClient {
        VaultClient::new(
            Url::parse(&server.uri()).expect("mock server URL"),
            None,
            true,
        )
        .expect("Vault client builds")
    }

    #[tokio::test]
    async fn jwt_login_posts_role_and_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/jwt/login"))
            .and(body_json(
                json!({ "role": "test-role", "jwt": "jwt-value" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "client_token": "client-token-123" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        // The token returned by login must be used on the following call.
        Mock::given(method("GET"))
            .and(path("/v1/vpnmeta/data/develmeta"))
            .and(header("X-Vault-Token", "client-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": crate::ovpn::test_support::reference_metadata_json() }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client(&server);
        let token = client
            .jwt_login("jwt-value", &mapping())
            .await
            .expect("login succeeds");
        assert_eq!(token, "client-token-123");
        let metadata = client
            .read_metadata(&token, &mapping())
            .await
            .expect("metadata reads with the login token");
        assert_eq!(metadata.hostname, "myvpn.example.com");
        server.verify().await;
    }

    #[tokio::test]
    async fn read_metadata_uses_data_data() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/vpnmeta/data/develmeta"))
            .and(header("X-Vault-Token", "client-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "request_id": "request-id",
                "data": {
                    "metadata": { "version": 1 },
                    "data": crate::ovpn::test_support::reference_metadata_json()
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let metadata = client(&server)
            .read_metadata("client-token-123", &mapping())
            .await
            .expect("metadata is read from data.data");

        assert_eq!(metadata.port, "1194");
        assert_eq!(metadata.cipher, "AES-256-CBC");
        assert_eq!(metadata.digest, "SHA1");
        server.verify().await;
    }

    #[tokio::test]
    async fn issue_certificate_uses_common_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/vpn/devel/issue/client"))
            .and(header("X-Vault-Token", "client-token-123"))
            .and(body_json(json!({ "common_name": "testuser" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "certificate": "-----BEGIN CERTIFICATE-----\nissued\n-----END CERTIFICATE-----",
                    "private_key": "-----BEGIN PRIVATE KEY-----\nissued-key\n-----END PRIVATE KEY-----"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let certificate = client(&server)
            .issue_certificate("client-token-123", &mapping(), "testuser")
            .await
            .expect("certificate is issued");

        assert!(certificate.certificate.contains("issued"));
        assert!(certificate.private_key.contains("issued-key"));
        server.verify().await;
    }

    /// A 307/308 login response must fail locally. Following it would replay
    /// the JWT body to whatever origin the redirect names.
    #[tokio::test]
    async fn jwt_login_does_not_follow_redirect() {
        for status in [307, 308] {
            let origin = MockServer::start().await;
            let destination = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/auth/jwt/login"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("Location", format!("{}/received", destination.uri())),
                )
                .expect(1)
                .mount(&origin)
                .await;
            // The cross-origin destination must never see a follow-up request
            // carrying the login body.
            Mock::given(method("POST"))
                .and(path("/received"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "auth": { "client_token": "stolen-token" }
                })))
                .expect(0)
                .mount(&destination)
                .await;

            let error = client(&origin)
                .jwt_login("jwt-value", &mapping())
                .await
                .expect_err("a Vault redirect is treated as an upstream failure");
            assert!(
                format!("{error:#}").contains("JWT login returned HTTP"),
                "unexpected error: {error:#}"
            );
            origin.verify().await;
            destination.verify().await;
        }
    }

    /// A redirected metadata read must fail locally, so X-Vault-Token cannot
    /// be replayed to the redirect target.
    #[tokio::test]
    async fn read_metadata_does_not_follow_redirect() {
        for status in [307, 308] {
            let origin = MockServer::start().await;
            let destination = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v1/vpnmeta/data/develmeta"))
                .and(header("X-Vault-Token", "client-token-123"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("Location", format!("{}/received", destination.uri())),
                )
                .expect(1)
                .mount(&origin)
                .await;
            Mock::given(method("GET"))
                .and(path("/received"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "data": { "data": crate::ovpn::test_support::reference_metadata_json() }
                })))
                .expect(0)
                .mount(&destination)
                .await;

            let error = client(&origin)
                .read_metadata("client-token-123", &mapping())
                .await
                .expect_err("a Vault redirect is treated as an upstream failure");
            assert!(
                format!("{error:#}").contains("Vault metadata read returned HTTP"),
                "unexpected error: {error:#}"
            );
            origin.verify().await;
            destination.verify().await;
        }
    }

    #[test]
    fn verification_can_be_disabled_for_development() {
        let url = Url::parse("https://vault.example.com").expect("valid url");

        VaultClient::new(url.clone(), None, true).expect("verified client builds");
        VaultClient::new(url, None, false).expect("development client builds");
    }

    /// A small self-signed CA certificate (EC P-256, CA:TRUE), used to prove
    /// that both the inline-PEM and file branches add a real trust anchor.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBbDCCARKgAwIBAgIUO023fiG5B/sykfylcl6sqJaDTlQwCgYIKoZIzj0EAwIw\n\
        HDEaMBgGA1UEAwwRVlNNIFRlc3QgVmF1bHQgQ0EwHhcNMjYxMTI2MTU0MzE4WhcN\n\
        MzYxMTIzMTU0MzE4WjAcMRowGAYDVQQDDBFWU00gVGVzdCBWYXVsdCBDQTBZMBMG\n\
        ByqGSM49AgEGCCqGSM49AwEHA0IABGjn4UydI9FBnMo2zivVY5603xAboskGzZ4Z\n\
        sjpppDXQDOn8/gLxJYMvbjV/TZ5fF/+Po9yjHcjcimX3JIiLqeujMjAwMB0GA1Ud\n\
        DgQWBBQpp0ak7u0xmCWSbuo7bCof1cKi2DAPBgNVHRMBAf8EBTADAQH/MAoGCCqG\n\
        SM49BAMCA0gAMEUCIGM5RTycZnwu2q7Pnu6BKY1MZGTefoBjBqdkqT52ojotAiEA\n\
        w/c6vpMjMgW1newC6V20GvazQXNZbrs0aEhWhyVElcM=\n\
        -----END CERTIFICATE-----\n";

    /// Well-formed PEM whose block is a public key, not a certificate.
    const NO_CERTIFICATE_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaOfhTJ0j0UGcyjbOK9VjnrTfEBui\n\
        yQbNnhmyOmmkNdAM6fz+AvElgy9uNX9Nnl8X/4+j3KMdyNyKZfckiIup6w==\n\
        -----END PUBLIC KEY-----\n";

    fn test_url() -> Url {
        Url::parse("https://vault.example.com").expect("valid url")
    }

    fn temp_ca_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vsm-vault-ca-{label}-{}-{nanos}.pem",
            std::process::id()
        ))
    }

    /// A uniquely named temp PEM file removed on drop, even on panic.
    struct TempCaFile(PathBuf);

    impl TempCaFile {
        fn new(label: &str, contents: &str) -> Self {
            let path = temp_ca_path(label);
            std::fs::write(&path, contents).expect("test CA file written");
            Self(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().expect("UTF-8 temp path")
        }
    }

    impl Drop for TempCaFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn inline_pem_custom_ca_builds_verified_client() {
        VaultClient::new(test_url(), Some(TEST_CA_PEM), true)
            .expect("an inline PEM containing BEGIN is treated as PEM, not a path");
    }

    #[test]
    fn custom_ca_file_with_valid_pem_builds_verified_client() {
        let file = TempCaFile::new("valid", TEST_CA_PEM);
        VaultClient::new(test_url(), Some(file.path()), true)
            .expect("a mounted PEM file is added to the root store");
    }

    #[test]
    fn missing_custom_ca_file_is_rejected() {
        let path = temp_ca_path("missing");
        let path = path.to_str().expect("UTF-8 temp path");
        let error = VaultClient::new(test_url(), Some(path), true)
            .err()
            .expect("a nonexistent CA path is rejected");
        assert!(
            format!("{error:#}").contains("failed to read the custom Vault CA file"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn invalid_custom_ca_pem_is_rejected() {
        let file = TempCaFile::new("invalid", "this is not a PEM certificate\n");
        let error = VaultClient::new(test_url(), Some(file.path()), true)
            .err()
            .expect("an invalid PEM file is rejected");
        assert!(
            format!("{error:#}").contains("custom Vault CA"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn custom_ca_pem_without_certificates_is_rejected() {
        let file = TempCaFile::new("no-certs", NO_CERTIFICATE_PEM);
        let error = VaultClient::new(test_url(), Some(file.path()), true)
            .err()
            .expect("a PEM file with no certificates is rejected");
        assert!(
            format!("{error:#}").contains("contains no PEM certificates"),
            "unexpected error: {error:#}"
        );
    }
}
