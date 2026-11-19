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
    let body = s.get("/").await.text().await.unwrap();
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
