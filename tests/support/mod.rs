//! Black-box HTTP helpers used by the integration tests.
//!
//! These mirror the Python `test/fixtures` clients: no redirects are followed
//! automatically, cookies are kept in a small manual jar, and the authentication
//! flow is driven through the same three hops as the historical pytest suite.

use std::collections::BTreeMap;

use redis::AsyncCommands;
use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Client, Response, StatusCode};

const DEFAULT_BASE: &str = "http://localhost:3000";

/// A minimal cookie-aware HTTP client for talking to the running binary.
pub struct TestSession {
    base: url::Url,
    client: Client,
    cookies: BTreeMap<String, String>,
    /// Token captured at login so logout still works with an expired session.
    pub csrf_token: Option<String>,
}

impl TestSession {
    pub fn new(base: Option<&str>) -> Self {
        Self {
            base: url::Url::parse(base.unwrap_or(DEFAULT_BASE)).expect("invalid base URL"),
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("build HTTP client"),
            cookies: BTreeMap::new(),
            csrf_token: None,
        }
    }

    pub fn base_url(&self) -> &url::Url {
        &self.base
    }

    /// Re-host an absolute callback URL onto this session's VSM base URL.
    ///
    /// The identity provider redirects to `vsm.local.kronus.network`; the test
    /// binary listens on `localhost`, so only scheme and authority are swapped.
    pub fn rewrite_base(&self, absolute: &str) -> String {
        let mut url = url::Url::parse(absolute).expect("callback URL must be absolute");
        url.set_scheme(self.base.scheme())
            .expect("cannot change callback scheme");
        url.set_host(self.base.host_str())
            .expect("cannot change callback host");
        url.set_port(self.base.port())
            .expect("cannot change callback port");
        url.to_string()
    }

    fn resolve(&self, path_or_url: &str) -> url::Url {
        if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
            url::Url::parse(path_or_url).expect("invalid absolute URL")
        } else {
            self.base.join(path_or_url).expect("invalid relative URL")
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn store_cookies(&mut self, response: &Response) {
        for header in response.headers().get_all(SET_COOKIE) {
            let raw = header.to_str().expect("invalid Set-Cookie header");
            let mut segments = raw.split(';');
            let pair = segments.next().unwrap_or("").trim();
            let mut pair = pair.splitn(2, '=');
            let name = pair.next().unwrap_or("").trim();
            let value = pair.next().unwrap_or("").trim();
            let max_age_zero =
                segments.any(|attribute| attribute.trim().eq_ignore_ascii_case("Max-Age=0"));
            if name.is_empty() || value.is_empty() || max_age_zero {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    async fn send(&mut self, request: reqwest::RequestBuilder) -> Response {
        let cookies = self.cookie_header();
        let request = if cookies.is_empty() {
            request
        } else {
            request.header(COOKIE, cookies)
        };
        let response = request.send().await.expect("HTTP request failed");
        self.store_cookies(&response);
        response
    }

    pub async fn get(&mut self, path_or_url: &str) -> Response {
        let url = self.resolve(path_or_url);
        self.send(self.client.get(url)).await
    }

    pub async fn post_form(&mut self, path_or_url: &str, form: &[(&str, &str)]) -> Response {
        let url = self.resolve(path_or_url);
        let body = serde_urlencoded::to_string(form).expect("serialize form");
        let request = self
            .client
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body);
        self.send(request).await
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(String::as_str)
    }
}

fn location(response: &Response) -> Option<&str> {
    response.headers().get(LOCATION)?.to_str().ok()
}

/// Read the session-scoped CSRF token out of a rendered portal page.
pub fn csrf_token(html: &str) -> String {
    let document = scraper::Html::parse_document(html);
    let selector = scraper::Selector::parse("input[name=csrf_token]").expect("csrf selector");
    document
        .select(&selector)
        .next()
        .and_then(|field| field.value().attr("value").map(str::to_owned))
        .expect("portal page has no csrf_token field")
}

/// Read the action of the identity provider's authentication form.
pub fn form_action(html: &str) -> String {
    let document = scraper::Html::parse_document(html);
    let selector = scraper::Selector::parse("form").expect("form selector");
    document
        .select(&selector)
        .next()
        .and_then(|form| form.value().attr("action").map(str::to_owned))
        .expect("identity provider page has no form action")
}

/// Drive the login flow against the running VSM and its identity provider.
pub async fn login(session: &mut TestSession, idp: &mut TestSession) {
    let response = session.get("/").await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), Some("/auth/login"));

    let response = session.get("/auth/login").await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let auth_url = location(&response).expect("login has no Location header");
    assert!(
        auth_url.starts_with(
            "http://kc.local.kronus.network/realms/devel/protocol/openid-connect/auth?"
        ),
        "unexpected authorization URL: {auth_url}"
    );

    let auth_url = auth_url.to_owned();
    let html = idp
        .get(&auth_url)
        .await
        .text()
        .await
        .expect("read auth form");
    let action = form_action(&html);

    let response = idp.post_form(&action, &[("username", "testuser")]).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let callback = location(&response).expect("authentication has no Location header");
    assert!(
        callback.starts_with("http://vsm.local.kronus.network/auth/callback?"),
        "unexpected callback URL: {callback}"
    );

    let callback = session.rewrite_base(callback);
    let response = session.get(&callback).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), Some("/"));

    let response = session.get("/").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("read portal page");
    session.csrf_token = Some(csrf_token(&body));
}

/// Log out, falling back to the token captured at login for expired sessions.
pub async fn logout(session: &mut TestSession) {
    let token = {
        let response = session.get("/").await;
        if response.status() == StatusCode::OK {
            let body = response.text().await.expect("read portal page");
            let token = csrf_token(&body);
            session.csrf_token = Some(token.clone());
            token
        } else {
            session.csrf_token.clone().unwrap_or_default()
        }
    };

    let response = session
        .post_form("/auth/logout", &[("csrf_token", token.as_str())])
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), Some("/"));
}

/// Force the current Redis record into the expired state without waiting.
pub async fn expire_session(session: &mut TestSession) {
    let raw = session.cookie("session").expect("no session cookie");
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .expect("session cookie is not UTF-8");
    let signed = decoded.split('.').next().unwrap_or("");
    assert!(signed.len() >= 44, "signed session cookie is too short");
    let uuid = &signed[44..];
    assert_eq!(uuid.len(), 32, "session id must be 32 characters: {uuid}");
    assert!(
        uuid.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "session id must be lowercase hex: {uuid}"
    );

    let client = redis::Client::open("redis://127.0.0.1:6379/0").expect("invalid Redis URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect to Redis");
    let mut token: serde_json::Value = connection
        .get(uuid)
        .await
        .map_err(|error| format!("failed to read session record: {error}"))
        .and_then(|payload: String| {
            serde_json::from_str(&payload)
                .map_err(|error| format!("failed to parse session record: {error}"))
        })
        .expect("read session record");
    token["expires_at"] = serde_json::json!(chrono::Utc::now().timestamp());
    let payload = serde_json::to_string(&token).expect("serialize session record");
    let _: () = connection
        .set(uuid, payload)
        .await
        .expect("write session record");
}
