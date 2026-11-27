//! Portal rendering: authenticated index page and its CSRF-protected forms.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::SignedCookieJar;
use minijinja::context;
use serde_json::Value;
use time::OffsetDateTime;
use tracing::{debug, info};

use crate::authz::authorized_servers;
use crate::error::{AppError, PageError};
use crate::session::is_expired;
use crate::state::AppState;
use crate::web::templates;

/// A 302 response. Axum 0.8 only exposes 303/307/308 `Redirect` constructors,
/// so the status is overridden on a redirect carrying the `Location` header.
fn found(uri: &str) -> Response {
    let mut response = Redirect::temporary(uri).into_response();
    *response.status_mut() = StatusCode::FOUND;
    response
}

/// The value placed in the hidden `csrf_token` field of every mutating form.
pub fn csrf_field(token: &str) -> String {
    token.to_owned()
}

/// `GET /`: render the portal for a valid session, otherwise redirect to login.
pub async fn index(State(state): State<AppState>, jar: SignedCookieJar) -> Response {
    let Some(cookie) = jar.get("session") else {
        return found("/auth/login");
    };
    let uuid = cookie.value().to_owned();
    let Some(record) = state.store.get(&uuid).await else {
        return found("/auth/login");
    };
    if is_expired(&record, OffsetDateTime::now_utc().unix_timestamp() as f64) {
        return found("/auth/login");
    }

    let Some(username) = record
        .userinfo
        .get(&state.config.auth_username_field)
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return PageError(AppError::MissingGroups).into_response();
    };
    let Some(groups) = record
        .userinfo
        .get(&state.config.auth_groups_field)
        .and_then(Value::as_array)
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| group.as_str().map(str::to_owned))
                .collect::<Vec<String>>()
        })
    else {
        return PageError(AppError::MissingGroups).into_response();
    };
    let vpn_servers = authorized_servers(&groups, &state.mappings);

    // Neither tokens nor the CSRF value are logged: only identity fields.
    info!(username = %username, groups = ?groups, "rendering portal");
    let csrf_token = csrf_field(&record.csrf_token);
    match templates::render(
        "index.html",
        context! {
            username,
            vpn_servers,
            csrf_token,
        },
    ) {
        Ok(body) => Html(body).into_response(),
        Err(_) => {
            // Render errors can quote template values, so log no details.
            debug!("failed to render the portal template");
            PageError(AppError::Internal).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Method, Request, StatusCode};
    use axum::response::Response;
    use axum::Router;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use crate::config::{AppConfig, Mapping};
    use crate::oidc::OidcClient;
    use crate::session::{new_uuid, MemoryStore, SessionStore, TokenRecord};
    use crate::state::AppState;

    const TEST_SESSION_SECRET: &str = "itsasecret";
    const CSRF_TOKEN: &str = "csrf-token-value";

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

    fn test_config() -> AppConfig {
        AppConfig {
            session_secret: TEST_SESSION_SECRET.to_owned(),
            env: "development".to_owned(),
            hostname: "localhost".to_owned(),
            redis_host: "localhost".to_owned(),
            redis_port: 6379,
            vault_url: url::Url::parse("http://hcv.local.kronus.network").expect("valid url"),
            custom_vault_ca: None,
            auth_issuer: url::Url::parse("http://kc.local.kronus.network/realms/devel")
                .expect("valid url"),
            auth_client_id: "vsm".to_owned(),
            auth_client_secret: "devel1234".to_owned(),
            auth_username_field: "preferred_username".to_owned(),
            auth_groups_field: "groups".to_owned(),
        }
    }

    fn app(store: Arc<dyn SessionStore>) -> Router {
        let state = AppState {
            config: Arc::new(test_config()),
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
                crate::vault::VaultClient::new(
                    url::Url::parse("http://hcv.local.kronus.network").expect("valid url"),
                    None,
                    true,
                )
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

    async fn seed(store: &Arc<dyn SessionStore>, userinfo: Value) -> String {
        let uuid = new_uuid();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        store
            .put(
                &uuid,
                &TokenRecord {
                    access_token: "access-token-value".to_owned(),
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

    async fn send_uri(router: Router, method: Method, uri: &str, cookie: Option<&str>) -> Response {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, format!("session={cookie}"));
        }

        router
            .oneshot(request.body(Body::empty()).expect("valid request"))
            .await
            .expect("handler responds")
    }

    async fn send(router: Router, cookie: Option<&str>) -> Response {
        send_uri(router, Method::GET, "/", cookie).await
    }

    async fn response_body(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body is readable");
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// Extracts the complete `<form>…</form>` containing `action`.
    fn form_for<'a>(body: &'a str, action: &str) -> &'a str {
        let marker = body
            .find(action)
            .unwrap_or_else(|| panic!("no form with {action} in body"));
        let start = body[..marker]
            .rfind("<form")
            .expect("form starts before action");
        let end = marker
            + body[marker..]
                .find("</form>")
                .expect("form ends after action")
            + "</form>".len();
        &body[start..end]
    }

    #[tokio::test]
    async fn index_lists_only_authorized_servers() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed(
            &store,
            json!({ "preferred_username": "testuser", "groups": ["/example"] }),
        )
        .await;

        let response = send(app(store), Some(&cookie)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        for expected in [
            "Logged in as: testuser",
            "Download VPN Server Configuration",
            "myserver",
            "myserver2",
            "myserver3",
        ] {
            assert!(
                body.contains(expected),
                "body must contain {expected}: {body}"
            );
        }
        assert!(
            !body.contains("myserver4"),
            "unauthorized server must not be listed: {body}"
        );
    }

    #[tokio::test]
    async fn index_forms_carry_csrf() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed(
            &store,
            json!({ "preferred_username": "testuser", "groups": ["/example"] }),
        )
        .await;

        let response = send(app(store), Some(&cookie)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        let hidden = format!(r#"<input type="hidden" name="csrf_token" value="{CSRF_TOKEN}">"#);
        let form = form_for(&body, r#"action="/api/servers/myserver""#);
        assert!(
            form.contains(r#"method="post""#),
            "download form must POST: {form}"
        );
        assert!(
            form.contains(&hidden),
            "download form must carry the seeded CSRF token: {form}"
        );
    }

    #[tokio::test]
    async fn index_logout_form_is_post() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed(
            &store,
            json!({ "preferred_username": "testuser", "groups": ["/example"] }),
        )
        .await;

        let response = send(app(store), Some(&cookie)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        let form = form_for(&body, r#"action="/auth/logout""#);
        assert!(
            form.contains(r#"method="post""#),
            "logout form must POST: {form}"
        );

        let hidden = format!(r#"<input type="hidden" name="csrf_token" value="{CSRF_TOKEN}">"#);
        assert!(
            form.contains(&hidden),
            "logout form must carry the seeded CSRF token: {form}"
        );
    }

    #[tokio::test]
    async fn index_missing_groups_is_500_html() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let cookie = seed(&store, json!({ "preferred_username": "testuser" })).await;

        let response = send(app(store), Some(&cookie)).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("text/html"),
            "error page must be HTML: {content_type}"
        );
    }

    #[tokio::test]
    async fn unauthenticated_index_redirects() {
        let response = send(app(Arc::new(MemoryStore::new())), None).await;

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/auth/login")
        );
    }

    #[tokio::test]
    async fn static_logo_is_served() {
        let response = send_uri(
            app(Arc::new(MemoryStore::new())),
            Method::GET,
            "/static/logo.png",
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("image/png")
        );
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body is readable");
        // The checkout keeps `logo.png` as a Git LFS pointer, so assert the
        // asset bytes are served rather than decoding them here.
        assert!(!bytes.is_empty(), "logo asset must not be empty");
    }

    /// A record exists under the cookie's UUID, but the cookie was signed with
    /// a different secret, so the signed jar must drop it before the handler.
    #[tokio::test]
    async fn index_tampered_signature_redirects() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        let uuid = new_uuid();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        store
            .put(
                &uuid,
                &TokenRecord {
                    access_token: "access-token-value".to_owned(),
                    expires_at: now + 3600.0,
                    userinfo: json!({ "preferred_username": "testuser", "groups": ["/example"] }),
                    csrf_token: CSRF_TOKEN.to_owned(),
                },
                60,
            )
            .await
            .expect("token is stored");

        let cookie = signed_value_with_secret(&uuid, "a-different-secret");
        let response = send(app(store), Some(&cookie)).await;

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/auth/login")
        );
    }

    #[tokio::test]
    async fn index_malformed_session_values_redirect() {
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
        for value in ["not-a-uuid", "../../etc/passwd", ""] {
            let cookie = signed_value(value);
            let response = send(app(store.clone()), Some(&cookie)).await;

            assert_eq!(
                response.status(),
                StatusCode::FOUND,
                "malformed cookie value {value:?} must be anonymous"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|value| value.to_str().ok()),
                Some("/auth/login")
            );
        }
    }

    #[tokio::test]
    async fn index_unknown_session_uuid_redirects() {
        let response = send(
            app(Arc::new(MemoryStore::new())),
            Some(&signed_value(&new_uuid())),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/auth/login")
        );
    }
}
