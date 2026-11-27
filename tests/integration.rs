mod support;

use support::TestSession;

fn base_url() -> String {
    std::env::var("VSM_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn harness_login_and_logout() {
    let mut session = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut session, &mut idp).await;
    assert_eq!(session.get("/").await.status(), reqwest::StatusCode::OK);
    support::logout(&mut session).await;
    assert!(session.cookie("session").is_none());
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn index_lists_allowed_servers() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    let response = s.get("/").await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("Logged in as: testuser"));
    assert!(body.contains("Download VPN Server Configuration"));
    for server in ["myserver", "myserver2", "myserver3"] {
        assert!(body.contains(server), "missing {server}");
    }
    assert!(!body.contains("myserver4"));
    support::logout(&mut s).await;
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn index_expired_redirects_to_login() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    support::expire_session(&mut s).await;
    let r = s.get("/").await;
    assert_eq!(r.status(), reqwest::StatusCode::FOUND);
    assert_eq!(r.headers()[reqwest::header::LOCATION], "/auth/login");
    support::logout(&mut s).await;
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn logout_when_anonymous_is_idempotent() {
    let mut s = TestSession::new(Some(&base_url()));
    assert!(s.cookie("session").is_none());
    let r = s.post_form("/auth/logout", &[("csrf_token", "")]).await;
    assert_eq!(r.status(), reqwest::StatusCode::FOUND);
    assert_eq!(r.headers()[reqwest::header::LOCATION], "/");
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn whoami_requires_login() {
    let mut s = TestSession::new(Some(&base_url()));
    assert_eq!(
        s.get("/api/whoami").await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn whoami_returns_user_and_servers() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    let response = s.get("/api/whoami").await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("testuser"));
    for server in ["myserver", "myserver2", "myserver3"] {
        assert!(body.contains(server), "missing {server}");
    }
    assert!(!body.contains("myserver4"));
    support::logout(&mut s).await;
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn whoami_expired_is_unauthorized() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    support::expire_session(&mut s).await;
    assert_eq!(
        s.get("/api/whoami").await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    support::logout(&mut s).await;
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn download_returns_ovpn() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    let token = s.csrf_token.clone().unwrap();
    let r = s
        .post_form("/api/servers/myserver", &[("csrf_token", &token)])
        .await;
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let disposition = r.headers()[reqwest::header::CONTENT_DISPOSITION].clone();
    assert!(r.text().await.unwrap().contains("dev tun"));
    assert_eq!(disposition, "attachment; filename=\"myserver.ovpn\"");
    support::logout(&mut s).await;
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn download_expired_is_unauthorized() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    support::expire_session(&mut s).await;
    let token = s.csrf_token.clone().unwrap();
    let r = s
        .post_form("/api/servers/myserver", &[("csrf_token", &token)])
        .await;
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);
    support::logout(&mut s).await;
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn download_anonymous_is_unauthorized() {
    let mut s = TestSession::new(Some(&base_url()));
    let r = s
        .post_form("/api/servers/myserver", &[("csrf_token", "")])
        .await;
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn download_unknown_server_is_forbidden() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    let token = s.csrf_token.clone().unwrap();
    let r = s
        .post_form("/api/servers/mybadserver", &[("csrf_token", &token)])
        .await;
    assert_eq!(r.status(), reqwest::StatusCode::FORBIDDEN);
    let content_type = r.headers()[reqwest::header::CONTENT_TYPE].clone();
    assert!(content_type.to_str().unwrap().starts_with("text/html"));
    assert!(r.text().await.unwrap().contains("Forbidden"));
    support::logout(&mut s).await;
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn download_denied_server_is_forbidden() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    let token = s.csrf_token.clone().unwrap();
    let r = s
        .post_form("/api/servers/myserver4", &[("csrf_token", &token)])
        .await;
    assert_eq!(r.status(), reqwest::StatusCode::FORBIDDEN);
    let content_type = r.headers()[reqwest::header::CONTENT_TYPE].clone();
    assert!(content_type.to_str().unwrap().starts_with("text/html"));
    assert!(r.text().await.unwrap().contains("Forbidden"));
    support::logout(&mut s).await;
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn keycloak_enforces_pkce() {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let auth_url = "http://kc.local.kronus.network/realms/devel/protocol/openid-connect/auth";
    let redirect_uri = "http://vsm.local.kronus.network/auth/callback";
    let base_params = [
        ("client_id", "vsm"),
        ("response_type", "code"),
        ("scope", "openid email profile"),
        ("redirect_uri", redirect_uri),
        ("state", "pkce-enforcement-probe"),
        ("nonce", "pkce-enforcement-probe"),
    ];

    async fn assert_rejected(client: &reqwest::Client, url: reqwest::Url) {
        let resp = client.get(url).send().await.unwrap();
        assert_eq!(
            resp.status(),
            302,
            "invalid-PKCE probe must not reach the login form"
        );
        let location = resp.headers()["location"].to_str().unwrap();
        assert!(location.starts_with("http://vsm.local.kronus.network/auth/callback"));
        assert!(
            location.contains("error="),
            "expected OAuth error redirect, got {location}"
        );
        assert!(
            !location.contains("code="),
            "no authorization code may be issued"
        );
    }

    // Probe 1: no code_challenge at all.
    let url = reqwest::Url::parse_with_params(auth_url, base_params).unwrap();
    assert_rejected(&client, url).await;

    // Probe 2: downgrade to plain — S256 is the only permitted method.
    let mut plain = base_params.to_vec();
    plain.push((
        "code_challenge",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    ));
    plain.push(("code_challenge_method", "plain"));
    let url = reqwest::Url::parse_with_params(auth_url, plain).unwrap();
    assert_rejected(&client, url).await;

    // Positive control: valid S256 challenge reaches the login form.
    // Challenge = S256 of RFC 7636 App. B verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".
    let mut s256 = base_params.to_vec();
    s256.push((
        "code_challenge",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    ));
    s256.push(("code_challenge_method", "S256"));
    let url = reqwest::Url::parse_with_params(auth_url, s256).unwrap();
    let resp = client.get(url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("kc-login"));
}
