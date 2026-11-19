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
