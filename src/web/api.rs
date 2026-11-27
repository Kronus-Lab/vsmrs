//! API handlers.

use axum::body::Body;
use axum::extract::{Form, Json, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tracing::debug;

use crate::authz::{authorized, authorized_servers};
use crate::config::Mapping;
use crate::error::{ApiError, AppError, PageError};
use crate::session::is_expired;
use crate::state::AppState;

/// Identity endpoint: the username and the authorized VPN server list.
pub async fn whoami(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Json<Value>, ApiError> {
    let jar_cookie = jar.get("session");
    let Some(session_cookie) = jar_cookie else {
        return Err(ApiError(AppError::Unauthenticated));
    };
    let uuid = session_cookie.value().to_owned();
    let Some(record) = state.store.get(&uuid).await else {
        return Err(ApiError(AppError::Unauthenticated));
    };

    if is_expired(&record, unix_now()) {
        return Err(ApiError(AppError::Unauthenticated));
    }

    let username = record
        .userinfo
        .get(&state.config.auth_username_field)
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or(AppError::MissingGroups)?;
    let groups = record
        .userinfo
        .get(&state.config.auth_groups_field)
        .and_then(Value::as_array)
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| group.as_str().map(str::to_owned))
                .collect::<Vec<String>>()
        })
        .ok_or(AppError::MissingGroups)?;

    let vpn_servers = authorized_servers(&groups, &state.mappings);

    debug!(username = %username, vpn_servers = ?vpn_servers, "whoami payload");

    Ok(Json(json!({
        "username": username,
        "vpn_servers": vpn_servers,
    })))
}

/// Hidden field submitted by every download form on the portal.
#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

/// `POST /api/servers/{server}`: validates the session, CSRF token and group
/// authorization before touching Vault, then streams the rendered profile.
// `Form` consumes the request body, so axum requires it as the final
// extractor; the remaining arguments all implement `FromRequestParts`.
pub async fn download(
    Path(server): Path<String>,
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some(cookie) = jar.get("session") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let uuid = cookie.value().to_owned();
    let Some(record) = state.store.get(&uuid).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if is_expired(&record, unix_now()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !bool::from(
        form.csrf_token
            .as_bytes()
            .ct_eq(record.csrf_token.as_bytes()),
    ) {
        return PageError(AppError::BadCsrf).into_response();
    }

    let Some(username) = record
        .userinfo
        .get(&state.config.auth_username_field)
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return ApiError(AppError::MissingGroups).into_response();
    };
    let Some(groups) = record
        .userinfo
        .get(&state.config.auth_groups_field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect::<Vec<String>>()
        })
    else {
        return ApiError(AppError::MissingGroups).into_response();
    };
    // Authorization is the last gate before any network call to Vault;
    // unknown and denied servers are indistinguishable to the caller.
    let Some(mapping) = authorized(&groups, &server, &state.mappings) else {
        return PageError(AppError::Forbidden).into_response();
    };

    let profile =
        match assemble_profile(&state, &record.access_token, mapping, &username, &server).await {
            Ok(profile) => profile,
            Err(error) => {
                // Details go to the log only; the client gets a generic 502.
                tracing::warn!(%error, "failed to assemble the VPN profile");
                return PageError(AppError::Upstream).into_response();
            }
        };

    // Escape quotes and backslashes so a configured server name cannot break
    // out of the quoted filename. `HeaderValue` still rejects control bytes.
    let escaped = server.replace('\\', "\\\\").replace('"', "\\\"");
    let disposition = format!("attachment; filename=\"{escaped}.ovpn\"");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(Body::from(profile))
        .expect("a static download response is always valid")
}

/// Runs the three Vault calls in order and renders the profile. Any failure,
/// including invalid metadata, is surfaced as an upstream failure by the caller.
async fn assemble_profile(
    state: &AppState,
    access_token: &str,
    mapping: &Mapping,
    username: &str,
    server: &str,
) -> anyhow::Result<String> {
    let client_token = state.vault.jwt_login(access_token, mapping).await?;
    let metadata = state.vault.read_metadata(&client_token, mapping).await?;
    let certificate = state
        .vault
        .issue_certificate(&client_token, mapping, username)
        .await?;
    tracing::info!(username, server, "issued VPN profile");
    crate::ovpn::render(&metadata, &certificate)
}

fn unix_now() -> f64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as f64
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Method, Request, StatusCode};
    use axum::response::Response;
    use axum::Router;
    use serde_json::{json, Value};
    use subtle::ConstantTimeEq;
    use tower::ServiceExt;
    use wiremock::matchers::{
        body_json as wm_body_json, header as wm_header, method as wm_method, path as wm_path,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::{AppConfig, Mapping};
    use crate::oidc::OidcClient;
    use crate::session::{new_uuid, MemoryStore, SessionStore, TokenRecord};
    use crate::state::AppState;

    const TEST_SESSION_SECRET: &str = "itsasecret";
    const TEST_HOSTNAME: &str = "localhost";
    const TEST_VAULT_URL: &str = "http://hcv.local.kronus.network";

    fn mapping(vpn_server: &str, idp_group: &str) -> Mapping {
        Mapping {
            vpn_server: vpn_server.to_owned(),
            idp_group: idp_group.to_owned(),
            vault_metadata_mountpoint: "vpnmeta".to_owned(),
            vault_metadata_path: "develmeta".to_owned(),
            vault_pki_mountpoint: "vpn/devel".to_owned(),
            vault_jwt_role: "test-role".to_owned(),
            vault_jwt_path: "jwt".to_owned(),
        }
    }

    fn reference_mappings() -> Vec<Mapping> {
        vec![
            mapping("myserver", "/example"),
            mapping("myserver2", "/example"),
            mapping("myserver3", "/example"),
            mapping("myserver4", "/example2"),
        ]
    }

    fn test_config(vault_url: &str) -> AppConfig {
        AppConfig {
            session_secret: TEST_SESSION_SECRET.to_owned(),
            env: "development".to_owned(),
            hostname: TEST_HOSTNAME.to_owned(),
            redis_host: "localhost".to_owned(),
            redis_port: 6379,
            vault_url: url::Url::parse(vault_url).expect("valid url"),
            custom_vault_ca: None,
            auth_issuer: url::Url::parse("http://kc.local.kronus.network/realms/devel")
                .expect("valid url"),
            auth_client_id: "vsm".to_owned(),
            auth_client_secret: "devel1234".to_owned(),
            auth_username_field: "preferred_username".to_owned(),
            auth_groups_field: "groups".to_owned(),
        }
    }

    fn token_record(userinfo: Value, expires_at: f64) -> TokenRecord {
        TokenRecord {
            access_token: "access-token-value".to_owned(),
            expires_at,
            userinfo,
            csrf_token: "csrf-token-value".to_owned(),
        }
    }

    fn app(store: Arc<dyn SessionStore>, vault_url: &str) -> Router {
        let config = test_config(vault_url);
        let state = AppState {
            config: Arc::new(config.clone()),
            mappings: Arc::new(reference_mappings()),
            store,
            oidc: Arc::new(OidcClient::from_parts(
                url::Url::parse(
                    "http://kc.local.kronus.network/realms/devel/protocol/openid-connect/auth",
                )
                .expect("valid authorize URL"),
                "vsm".to_owned(),
                url::Url::parse("http://localhost/auth/callback").expect("valid callback URL"),
            )),
            vault: Arc::new(
                crate::vault::VaultClient::new(config.vault_url, None, true)
                    .expect("Vault client builds"),
            ),
        };

        crate::web::router(state)
    }

    fn signed_value(uuid: &str) -> String {
        signed_value_with_secret(uuid, TEST_SESSION_SECRET)
    }

    /// Signs a cookie with a secret other than the app's, so the jar sees a
    /// well-formed signed cookie whose MAC cannot validate.
    fn signed_value_with_secret(value: &str, secret: &str) -> String {
        let mut jar = cookie::CookieJar::new();
        let mut signed_jar = jar.signed_mut(&crate::session::signing_key(secret));
        signed_jar.add((String::from("session"), value.to_owned()));

        jar.get("session")
            .expect("signed session cookie is present")
            .value()
            .to_owned()
    }

    async fn send(router: Router, cookie: Option<String>) -> Response {
        let mut request = Request::builder().uri("/api/whoami");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, format!("session={cookie}"));
        }

        let request = request.body(Body::empty()).expect("valid request");
        router.oneshot(request).await.expect("handler responds")
    }

    async fn response_body(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body is readable");
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[tokio::test]
    async fn whoami_requires_session() {
        let response = send(app(Arc::new(MemoryStore::new()), TEST_VAULT_URL), None).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            response_body(response).await,
            r#"{"error-message":"Not Authenticated"}"#
        );
    }

    #[tokio::test]
    async fn whoami_rejects_expired_token() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let uuid = new_uuid();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        store
            .put(
                &uuid,
                &token_record(
                    json!({ "preferred_username": "testuser", "groups": ["/example"] }),
                    now - 3600.0,
                ),
                60,
            )
            .await
            .expect("token is stored");

        let response = send(app(store, TEST_VAULT_URL), Some(signed_value(&uuid))).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn whoami_missing_groups_is_well_formed_500() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let uuid = new_uuid();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        store
            .put(
                &uuid,
                &token_record(json!({ "preferred_username": "testuser" }), now + 3600.0),
                60,
            )
            .await
            .expect("token is stored");

        let response = send(app(store, TEST_VAULT_URL), Some(signed_value(&uuid))).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_body(response).await;
        let value: Value = serde_json::from_str(&body).expect("error body is well-formed JSON");
        assert!(
            value.get("error-message").is_some(),
            "error body must carry an error-message field: {body}"
        );
    }

    #[tokio::test]
    async fn whoami_returns_reference_servers() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let uuid = new_uuid();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        store
            .put(
                &uuid,
                &token_record(
                    json!({ "preferred_username": "testuser", "groups": ["/example"] }),
                    now + 3600.0,
                ),
                60,
            )
            .await
            .expect("token is stored");

        let response = send(app(store, TEST_VAULT_URL), Some(signed_value(&uuid))).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        let value: Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(value["username"], json!("testuser"));
        assert_eq!(
            value["vpn_servers"],
            json!(["myserver", "myserver2", "myserver3"])
        );
    }

    const CSRF_TOKEN: &str = "csrf-token-value";

    #[test]
    fn csrf_comparison_accepts_only_exact_tokens() {
        assert!(bool::from(
            CSRF_TOKEN.as_bytes().ct_eq("csrf-token-value".as_bytes())
        ));
        assert!(!bool::from(
            "wrong-token".as_bytes().ct_eq(CSRF_TOKEN.as_bytes())
        ));
        assert!(!bool::from("".as_bytes().ct_eq(CSRF_TOKEN.as_bytes())));
    }

    #[derive(serde::Serialize)]
    struct DownloadForm<'a> {
        csrf_token: &'a str,
    }

    async fn seed_download_session(store: &Arc<dyn SessionStore>, userinfo: Value) -> String {
        let uuid = new_uuid();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        store
            .put(
                &uuid,
                &TokenRecord {
                    access_token: "jwt-value".to_owned(),
                    expires_at: now + 3600.0,
                    userinfo,
                    csrf_token: CSRF_TOKEN.to_owned(),
                },
                60,
            )
            .await
            .expect("token is stored");
        signed_value(&uuid)
    }

    async fn send_download(
        router: Router,
        cookie: Option<&str>,
        server: &str,
        csrf: &str,
    ) -> Response {
        let body = serde_urlencoded::to_string(DownloadForm { csrf_token: csrf })
            .expect("form body encodes");
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/servers/{server}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, format!("session={cookie}"));
        }
        router
            .oneshot(request.body(Body::from(body)).expect("valid request"))
            .await
            .expect("handler responds")
    }

    /// Mounts the three Vault calls a successful download makes, all bound to
    /// the same mock server the router's `VaultClient` points at.
    async fn mount_vault_mock(server: &MockServer) {
        Mock::given(wm_method("POST"))
            .and(wm_path("/v1/auth/jwt/login"))
            .and(wm_body_json(
                json!({ "role": "test-role", "jwt": "jwt-value" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "client_token": "client-token-123" }
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(wm_method("GET"))
            .and(wm_path("/v1/vpnmeta/data/develmeta"))
            .and(wm_header("X-Vault-Token", "client-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": crate::ovpn::test_support::reference_metadata_json() }
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(wm_method("POST"))
            .and(wm_path("/v1/vpn/devel/issue/client"))
            .and(wm_header("X-Vault-Token", "client-token-123"))
            .and(wm_body_json(json!({ "common_name": "testuser" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "certificate": "-----BEGIN CERTIFICATE-----\nstub-cert\n-----END CERTIFICATE-----",
                    "private_key": "-----BEGIN PRIVATE KEY-----\nstub-key\n-----END PRIVATE KEY-----"
                }
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn download_without_session_is_401_empty() {
        let vault = MockServer::start().await;
        let response = send_download(
            app(Arc::new(MemoryStore::new()), &vault.uri()),
            None,
            "myserver",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response_body(response).await.is_empty());
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "an unauthenticated download must not reach Vault"
        );
    }

    #[tokio::test]
    async fn download_bad_csrf_is_403() {
        let vault = MockServer::start().await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed_download_session(
            &store,
            json!({ "preferred_username": "testuser", "groups": ["/example"] }),
        )
        .await;

        let response = send_download(
            app(store, &vault.uri()),
            Some(&cookie),
            "myserver",
            "wrong-token",
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "a bad CSRF token must not reach Vault"
        );
    }

    #[tokio::test]
    async fn download_denied_server_never_calls_vault() {
        let vault = MockServer::start().await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed_download_session(
            &store,
            json!({ "preferred_username": "testuser", "groups": ["/example"] }),
        )
        .await;

        let response = send_download(
            app(store, &vault.uri()),
            Some(&cookie),
            "myserver4",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .starts_with("text/html"),
            "a denied download must render the HTML error page"
        );
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "authorization must run before any Vault call"
        );
    }

    #[tokio::test]
    async fn download_unknown_server_never_calls_vault() {
        let vault = MockServer::start().await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed_download_session(
            &store,
            json!({ "preferred_username": "testuser", "groups": ["/example"] }),
        )
        .await;

        let response = send_download(
            app(store, &vault.uri()),
            Some(&cookie),
            "nosuch",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "an unknown server must not reach Vault"
        );
    }

    #[tokio::test]
    async fn download_missing_groups_is_500() {
        let vault = MockServer::start().await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie =
            seed_download_session(&store, json!({ "preferred_username": "testuser" })).await;

        let response = send_download(
            app(store, &vault.uri()),
            Some(&cookie),
            "myserver",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = response_body(response).await;
        let value: Value = serde_json::from_str(&body).expect("error body is well-formed JSON");
        assert!(
            value.get("error-message").is_some(),
            "error body must carry an error-message field: {body}"
        );
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "a missing groups claim must not reach Vault"
        );
    }

    #[tokio::test]
    async fn download_missing_username_is_500_json() {
        let vault = MockServer::start().await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed_download_session(&store, json!({ "groups": ["/example"] })).await;

        let response = send_download(
            app(store, &vault.uri()),
            Some(&cookie),
            "myserver",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = response_body(response).await;
        let value: Value = serde_json::from_str(&body).expect("error body is well-formed JSON");
        assert!(
            value.get("error-message").is_some(),
            "error body must carry an error-message field: {body}"
        );
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "a missing username claim must not reach Vault"
        );
    }

    #[tokio::test]
    async fn download_vault_failure_is_502_html() {
        let vault = MockServer::start().await;
        Mock::given(wm_method("POST"))
            .and(wm_path("/v1/auth/jwt/login"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&vault)
            .await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed_download_session(
            &store,
            json!({ "preferred_username": "testuser", "groups": ["/example"] }),
        )
        .await;

        let response = send_download(
            app(store, &vault.uri()),
            Some(&cookie),
            "myserver",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .starts_with("text/html"),
            "Vault failures must render the generic HTML error page"
        );
        let body = response_body(response).await;
        assert!(
            !body.contains("jwt-value") && !body.contains("client-token"),
            "the error body must not echo upstream details: {body}"
        );
        vault.verify().await;
    }

    #[tokio::test]
    async fn download_success_has_contract_headers() {
        let vault = MockServer::start().await;
        mount_vault_mock(&vault).await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed_download_session(
            &store,
            json!({ "preferred_username": "testuser", "groups": ["/example"] }),
        )
        .await;

        let response = send_download(
            app(store, &vault.uri()),
            Some(&cookie),
            "myserver",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain")
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|value| value.to_str().ok()),
            Some("attachment; filename=\"myserver.ovpn\"")
        );
        let body = response_body(response).await;
        assert!(
            body.contains("dev tun"),
            "body must be a rendered profile: {body}"
        );
        vault.verify().await;
    }

    /// A record exists under the cookie's UUID, but the cookie was signed with
    /// a different secret, so the signed jar must drop it before the handler.
    #[tokio::test]
    async fn whoami_tampered_signature_is_401() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let uuid = new_uuid();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        store
            .put(
                &uuid,
                &token_record(
                    json!({ "preferred_username": "testuser", "groups": ["/example"] }),
                    now + 3600.0,
                ),
                60,
            )
            .await
            .expect("token is stored");

        let cookie = signed_value_with_secret(&uuid, "a-different-secret");
        let response = send(app(store, TEST_VAULT_URL), Some(cookie)).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_body(response).await,
            r#"{"error-message":"Not Authenticated"}"#
        );
    }

    #[tokio::test]
    async fn download_tampered_signature_is_401_empty() {
        let vault = MockServer::start().await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let uuid = new_uuid();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        store
            .put(
                &uuid,
                &token_record(
                    json!({ "preferred_username": "testuser", "groups": ["/example"] }),
                    now + 3600.0,
                ),
                60,
            )
            .await
            .expect("token is stored");

        let cookie = signed_value_with_secret(&uuid, "a-different-secret");
        let response = send_download(
            app(store, &vault.uri()),
            Some(&cookie),
            "myserver",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response_body(response).await.is_empty());
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "a tampered cookie must not reach Vault"
        );
    }

    #[tokio::test]
    async fn whoami_malformed_session_values_are_401() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        for value in ["not-a-uuid", "../../etc/passwd", ""] {
            let response = send(
                app(store.clone(), TEST_VAULT_URL),
                Some(signed_value(value)),
            )
            .await;

            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "malformed cookie value {value:?} must be anonymous"
            );
            assert_eq!(
                response_body(response).await,
                r#"{"error-message":"Not Authenticated"}"#
            );
        }
    }

    #[tokio::test]
    async fn download_malformed_session_values_are_401_empty() {
        let vault = MockServer::start().await;
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        for value in ["not-a-uuid", "../../etc/passwd", ""] {
            let cookie = signed_value(value);
            let response = send_download(
                app(store.clone(), &vault.uri()),
                Some(&cookie),
                "myserver",
                CSRF_TOKEN,
            )
            .await;

            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "malformed cookie value {value:?} must be anonymous"
            );
            assert!(response_body(response).await.is_empty());
        }
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "malformed cookies must not reach Vault"
        );
    }

    #[tokio::test]
    async fn whoami_unknown_session_uuid_is_401() {
        let response = send(
            app(Arc::new(MemoryStore::new()), TEST_VAULT_URL),
            Some(signed_value(&new_uuid())),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_body(response).await,
            r#"{"error-message":"Not Authenticated"}"#
        );
    }

    #[tokio::test]
    async fn download_unknown_session_uuid_is_401_empty() {
        let vault = MockServer::start().await;
        let response = send_download(
            app(Arc::new(MemoryStore::new()), &vault.uri()),
            Some(&signed_value(&new_uuid())),
            "myserver",
            CSRF_TOKEN,
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response_body(response).await.is_empty());
        assert!(
            vault
                .received_requests()
                .await
                .expect("requests are readable")
                .is_empty(),
            "an unknown session UUID must not reach Vault"
        );
    }
}
