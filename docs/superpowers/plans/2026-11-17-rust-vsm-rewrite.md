# VPN Server Manager Rust Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python/Flask VSM with a statically linked Rust service behind the existing HAProxy/Keycloak/Redis/Vault stack, shipping as a `FROM scratch` image and implementing the full-clean-up contract.

**Architecture:** In-place rewrite of the upstream tree checked out at `upstream/` (pinned SHA `8ea0424…`): thin axum handlers over explicit config, session, OIDC, authorization, Vault, and OVPN modules. Config loads once at startup from mounted JSON; sessions are signed UUID cookies plus Redis token records; authorization is one pure function; OIDC state/PKCE verifiers and CSRF tokens live in Redis with TTLs.

**Tech Stack:** Rust (MSRV 1.88+), axum 0.8 / tokio 1, `openidconnect` 4, `reqwest` with rustls + `ring`, `redis`, `minijinja`, `rust-embed`, `tower`, `wiremock`; Python 3.12 + pytest/requests/BeautifulSoup for HTTP integration tests; Cypress in Chrome and Firefox.

**Spec:** `../specs/2026-11-17-rust-rewrite-design.md`, `../../CONTRACT.MD`, and `../../functional-spec.md` (as-built baseline). Read all three before starting.

## Global Constraints

- Runtime target `x86_64-unknown-linux-musl`; runtime image `FROM scratch`; no dynamic libraries, shell, `/etc/passwd`, or `ca-certificates` in the image.
- Listen on `0.0.0.0:3000`.
- All commands run from `upstream/` unless a step says otherwise; config paths stay relative (`config/vsm/app.json`, `config/vsm/vpn_group_mapping.json`).
- Reference config: `ENV=development`, `FLASK_SECRET=itsasecret`, `HOSTNAME=vsm.local.kronus.network`, Redis `localhost:6379` DB 0, Vault `http://hcv.local.kronus.network`, issuer `http://kc.local.kronus.network/realms/devel`, client `vsm`, username field `preferred_username`, groups field `groups`.
- Cookie: name `session`, payload only a 32-char lowercase hex UUID; `HttpOnly`, `SameSite=Strict`, `Path=/`; `Secure` and `Domain=HOSTNAME` only when `ENV != "development"`.
- OIDC: scopes `openid email profile`; PKCE `S256`; `state` and `nonce` validated; redirect URI is the absolute callback URL with `http` in development and `https` otherwise. Registered redirect URIs are `http://vsm.local.kronus.network/*` and `http://localhost/*`.
- Certificate CN = `userinfo[preferred_username]`; TTL 8 h comes from the Vault role, not the app.
- API error key is `error-message`; unauthenticated `whoami` body is exactly `{"error-message":"Not Authenticated"}`.
- In development, Vault TLS verification is disabled and CUSTOM_VAULT_CA value is printed; production never takes that branch.
- Never log access tokens, JWTs, Vault client tokens, CA blobs, `server_tls_key`, issued keys/certificates, or CSRF tokens.
- Test tooling: Python 3.12; Cypress runs in Chrome and Firefox; delete `cypress/screenshots` and `cypress/downloads` between browser runs.

## Review Focus

These are the inputs the spec implies but no single task's happy-path test covers. Each has a pinning test in the owning task.

1. **Multi-line PEM metadata** — `certificate_authority` and `server_tls_key` are legitimate multi-line blobs, so a blanket CR/LF ban breaks every real download; scalars must still reject newlines and OVPN tags. Pinned in Task 6, Step 2.
2. **Expired but still-present Redis token** — expiry is read-time and strict (`expires_at > now`); a lingering key must not authenticate. Pinned in Task 2, Step 2 and Task 3, Step 2.
3. **Denied or unknown server must never reach Vault** — authorization runs before any Vault call, including token exchange. Pinned in Task 6, Step 6.
4. **Missing `groups` claim** — `500` with well-formed JSON on APIs and an HTML page on `/`, never a silent denial. Pinned in Task 3, Step 2 and Task 5, Step 2.
5. **Replay/CSRF inputs** — bad OIDC `state`, bad CSRF token, and one-time pending login records must not create sessions or issue profiles. Pinned in Task 4, Step 2 and Task 6, Step 6.

---

## File Structure

**Create in `upstream/`:** `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml` (if needed for musl), `rust-toolchain.toml`, `src/main.rs`, `src/config.rs`, `src/session.rs`, `src/authz.rs`, `src/oidc.rs`, `src/vault.rs`, `src/ovpn.rs`, `src/error.rs`, `src/state.rs`, `src/web/mod.rs`, `src/web/auth.rs`, `src/web/portal.rs`, `src/web/api.rs`, `src/web/static_files.rs`, `templates/error.html`, `deny.toml`, `tests/` (Rust integration helpers if needed).

**Modify in `upstream/`:** `templates/index.html` (download/logout forms + CSRF), `templates/template.ovpn` (unchanged directive set, new renderer), `Dockerfile`, `docker-compose-e2e.yml`, `.github/workflows/test-suite.yml`, `requirements.txt`, `requirements-dev.txt`, `test/conftest.py`, `test/fixtures/*.py`, `test/test_*.py`, `cypress/e2e/vsm.cy.js`, `README.md`.

**Delete in `upstream/`:** `vsm.py`, `templates/logout.html`, `liccheck.ini`, `.coveragerc` once the Python app is gone.

**Already created outside `upstream/`:** `CONTRACT.MD`, `docs/superpowers/specs/2026-11-17-rust-rewrite-design.md`, and this plan. Do not move them.

---

### Task 1: Rust workspace, config loading and startup validation

**Files:**
- Create: `upstream/Cargo.toml`, `upstream/src/config.rs`, `upstream/src/main.rs`, `upstream/rust-toolchain.toml`
- Modify: `upstream/Cargo.toml`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub struct AppConfig` (fields `flask_secret: String`, `env: String`, `hostname: String`, `redis_host: String`, `redis_port: u16`, `vault_url: url::Url`, `custom_vault_ca: Option<String>`, `auth_issuer: url::Url`, `auth_client_id: String`, `auth_client_secret: String`, `auth_username_field: String`, `auth_groups_field: String`); `pub struct Mapping` (seven fields named after the JSON keys); `pub fn load(app_path: &Path, mappings_path: &Path) -> anyhow::Result<(AppConfig, Vec<Mapping>)>`; `impl AppConfig { pub fn is_development(&self) -> bool }`.

- [ ] **Step 1: Create `upstream/Cargo.toml`** with package name `vsm`, edition 2021, and dependencies: `axum` (features `macros`), `tokio` (`macros`, `rt-multi-thread`), `tower` (`util`), `serde` (`derive`), `serde_json`, `anyhow`, `thiserror`, `tracing`, `tracing-subscriber`, `url`, `cookie`, `hex`, `rand`. Set `rust-toolchain.toml` to a channel of 1.88 or newer.

- [ ] **Step 2: Write failing tests in `upstream/src/config.rs`** in a `#[cfg(test)] mod tests` using inline JSON strings:
  - `accepts_reference_config`: `load` from two temp files with the reference `app.json` and two distinct mappings returns port `6379` and two mappings.
  - `rejects_duplicate_vpn_server`: two mappings with `vpn_server: "myserver"` returns an error containing `duplicate`.
  - `rejects_missing_groups_field`: app JSON without `AUTH_GROUPS_FIELD` returns an error.
  - `rejects_bad_port`: `"REDIS_PORT": "not-a-port"` returns an error.
  Use `std::env::temp_dir()` plus a unique filename per test; no external crates for fixtures.

- [ ] **Step 3: Run the failing tests**

Run: `cd upstream && cargo test config::tests`
Expected: compile failure because `config` module and its types do not exist yet.

- [ ] **Step 4: Implement `config.rs` and a bootstrap `main.rs`**

Implement `load` with `serde_json::from_str` for both files, validate: every required key present and non-empty, port parses, issuer and Vault URL parse as absolute URLs, mapping fields present, `vpn_server` values unique (error message contains `duplicate`), secret non-empty and at least 32 bytes when not development. Log each mapping at info level. `main.rs` initializes `tracing_subscriber`, calls `load("config/vsm/app.json", "config/vsm/vpn_group_mapping.json")`, logs the trust source line, and exits with a clear error on failure.

- [ ] **Step 5: Run tests**

Run: `cd upstream && cargo test config::tests && cargo build`
Expected: all four tests PASS; binary builds.

- [ ] **Step 6: Commit**

```bash
git -C upstream add Cargo.toml rust-toolchain.toml src/config.rs src/main.rs
git -C upstream commit -m "feat: add Rust workspace and validated config loading"
```

---

### Task 2: Session store, signed cookie and expiry

**Files:**
- Create: `upstream/src/session.rs`
- Modify: `upstream/Cargo.toml`, `upstream/src/main.rs`

**Interfaces:**
- Consumes: `AppConfig` (Task 1).
- Produces: `#[derive(Clone, Serialize, Deserialize)] pub struct TokenRecord { pub access_token: String, pub expires_at: f64, pub userinfo: serde_json::Value, pub csrf_token: String }`; `pub struct PendingLogin { pub state: String, pub nonce: String, pub pkce_verifier: String }`; `#[async_trait] pub trait SessionStore: Send + Sync { async fn get(&self, uuid: &str) -> Option<TokenRecord>; async fn put(&self, uuid: &str, record: &TokenRecord, ttl_secs: u64) -> anyhow::Result<()>; async fn delete(&self, uuid: &str); async fn put_pending(&self, id: &str, pending: &PendingLogin, ttl_secs: u64); async fn take_pending(&self, id: &str) -> Option<PendingLogin>; }`; `pub struct RedisStore`, `pub struct MemoryStore` (test use); `pub fn new_uuid() -> String`; `pub fn is_expired(record: &TokenRecord, now: f64) -> bool`; `pub fn signing_key(secret: &str) -> cookie::Key`; `pub fn build_session_cookie(development: bool, hostname: &str, value: &str) -> cookie::Cookie<'static>`.

- [ ] **Step 1: Add dependencies** `redis` (features `tokio-comp`), `axum-extra` (feature `cookie`), `async-trait`, `sha2`, `hkdf`, `time`.

- [ ] **Step 2: Write failing tests in `upstream/src/session.rs`**
  - `cookie_has_hardened_attributes_in_production`: `build_session_cookie(false, "vsm.local.kronus.network", "abc")` has `HttpOnly`, `SameSite::Strict`, `Path="/"`, `secure() == true`, `domain() == Some("vsm.local.kronus.network")`.
  - `cookie_is_host_only_in_development`: development cookie has `secure() == false` and `domain() == None`.
  - `expiry_is_strict`: `is_expired` is `false` at `expires_at - 0.01`, `true` at `expires_at` and `expires_at + 0.01`.
  - `memory_store_roundtrip_and_pending_is_one_shot`: put/get/delete a `TokenRecord`; `take_pending` returns the value once and `None` the second time.

- [ ] **Step 3: Run failing tests**

Run: `cd upstream && cargo test session::tests`
Expected: compile failure, missing module and symbols.

- [ ] **Step 4: Implement `session.rs`**

`new_uuid` uses `rand` bytes formatted by `hex::encode` to 32 lowercase chars. `signing_key` derives 64 bytes from `secret` with HKDF-SHA256 and builds `cookie::Key`. `build_session_cookie` sets the attributes listed in Step 2 only. `RedisStore` connects to DB 0 and uses `SET … EX` for both token and pending records; `get` deletes the key when the decoded record is already expired and returns `None`. `MemoryStore` is an in-memory `HashMap` for tests. Implement `SessionStore` for both with `async_trait`.

- [ ] **Step 5: Run tests**

Run: `cd upstream && cargo test session::tests`
Expected: all four PASS.

- [ ] **Step 6: Commit**

```bash
git -C upstream add Cargo.toml src/session.rs
git -C upstream commit -m "feat: add session store, signed cookies and read-time expiry"
```

---

### Task 3: Authorization rule, error mapping and `whoami`

**Files:**
- Create: `upstream/src/authz.rs`, `upstream/src/error.rs`, `upstream/src/state.rs`, `upstream/src/web/mod.rs`, `upstream/src/web/api.rs`
- Modify: `upstream/src/main.rs`

**Interfaces:**
- Consumes: `AppConfig`, `Mapping` (Task 1); `SessionStore`, `TokenRecord`, `is_expired` (Task 2).
- Produces: `pub fn authorized<'a>(groups: &[String], server: &str, mappings: &'a [Mapping]) -> Option<&'a Mapping>`; `pub fn authorized_servers(groups: &[String], mappings: &[Mapping]) -> Vec<String>`; `pub enum AppError { Unauthenticated, Forbidden, MissingGroups, BadCsrf, BadState, Upstream, Internal }`; two wrappers `pub struct ApiError(pub AppError)` and `pub struct PageError(pub AppError)` implementing `IntoResponse` (JSON `{"error-message":"…"}` / HTML error page respectively); `pub struct AppState { pub config: Arc<AppConfig>, pub mappings: Arc<Vec<Mapping>>, pub store: Arc<dyn SessionStore> }` (extend in Tasks 4 and 6); `pub fn router(state: AppState) -> axum::Router`; `pub async fn whoami(State(state): State<AppState>, jar: SignedCookieJar) -> Result<Json<Value>, ApiError>` wired at `GET /api/whoami`.

- [ ] **Step 1: Write failing tests in `upstream/src/authz.rs`**
  - `exact_case_sensitive_match`: `/example` grants `myserver` but `/Example` and `other` do not.
  - `any_mapping_grants`: one matching mapping in a list is enough.
  - `authorized_servers_preserves_mapping_order`: groups `/example` produce `["myserver", "myserver2", "myserver3"]` from the reference mapping and exclude `myserver4`.

- [ ] **Step 2: Write failing handler tests in `upstream/src/web/api.rs`** using `tower::ServiceExt::oneshot` and `MemoryStore`:
  - `whoami_requires_session`: no cookie → `401` and body exactly `{"error-message":"Not Authenticated"}` with `application/json`.
  - `whoami_rejects_expired_token`: cookie UUID with a `TokenRecord` whose `expires_at` is in the past → `401`.
  - `whoami_missing_groups_is_well_formed_500`: `userinfo` without `groups` → `500` and `serde_json::from_slice::<Value>(body)` succeeds with an `error-message` field.
  - `whoami_returns_reference_servers`: reference mapping + groups `/example` → `200`, `username == "testuser"`, `vpn_servers == ["myserver","myserver2","myserver3"]`.

- [ ] **Step 3: Run failing tests**

Run: `cd upstream && cargo test authz::tests && cargo test web::api::tests`
Expected: compile failure, missing modules and handlers.

- [ ] **Step 4: Implement `authz.rs`, `error.rs`, `state.rs`, `web/mod.rs`, `web/api.rs`**

`authorized` returns the first matching mapping (startup validation already forbids duplicate `vpn_server`). `whoami` resolves the session from the signed cookie via the shared `store`, checks `is_expired`, reads the configured group/username fields from `userinfo`, and returns `ApiError(AppError::MissingGroups)` when absent. Emit the debug-level `whoami` payload log (identity and server list only, no tokens). Wire `GET /api/whoami` into `router`; `main.rs` builds `AppState`, adds `SignedCookieJarLayer` with `signing_key(&config.flask_secret)` and serves the router with `axum::serve`.

- [ ] **Step 5: Run tests**

Run: `cd upstream && cargo test authz::tests && cargo test web::api::tests`
Expected: all seven tests PASS.

- [ ] **Step 6: Commit**

```bash
git -C upstream add src/authz.rs src/error.rs src/state.rs src/web/mod.rs src/web/api.rs src/main.rs
git -C upstream commit -m "feat: add authorization rule, error mapping and whoami"
```

---

### Task 4: OIDC login, callback and pending state

**Files:**
- Create: `upstream/src/oidc.rs`, `upstream/src/web/auth.rs`
- Modify: `upstream/Cargo.toml`, `upstream/src/state.rs`, `upstream/src/web/mod.rs`, `upstream/src/main.rs`

**Interfaces:**
- Consumes: `AppConfig`, `SessionStore`, `PendingLogin`, `TokenRecord`, `signing_key`.
- Produces: `pub struct OidcClient`; `impl OidcClient { pub async fn new(config: &AppConfig) -> anyhow::Result<Self>; #[cfg(test)] pub fn from_parts(authorize_url: url::Url, client_id: String, redirect_uri: url::Url) -> Self; pub fn authorization_request(&self) -> anyhow::Result<(url::Url, PendingLogin)>; pub async fn complete(&self, code: &str, nonce: &str, verifier: &str) -> anyhow::Result<UserInfo> }`; `pub struct UserInfo { pub username: String, pub groups: Vec<String> }`; `AppState` gains `pub oidc: Arc<OidcClient>`; handlers `pub async fn login(...) -> Redirect`, `pub async fn callback(...) -> Response`, `pub async fn logout(...) -> Response`, `pub async fn logout_get() -> Response` wired at `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`, `GET /auth/logout`.

- [ ] **Step 1: Add dependencies** `openidconnect` version 4 with the `reqwest` feature, and a separately configured `reqwest` client with no default TLS features plus `rustls` and `webpki-roots` for the custom root store. Confirm with `cargo tree -e features` that no `aws-lc-rs` is pulled in; if it is, switch to `rustls-no-provider` and install the `ring` provider explicitly.

- [ ] **Step 2: Write failing tests in `upstream/src/oidc.rs` and `upstream/src/web/auth.rs`**
  - `authorize_url_uses_contract_parameters`: build `OidcClient` with the test-only `from_parts` constructor (no network needed for URL construction) and assert the returned URL has `client_id=vsm`, `redirect_uri` equal to the configured absolute callback URL, `scope` containing `openid email profile`, `code_challenge_method=S256`, a non-empty `state` and `nonce`, and a `code_challenge` different from the verifier.
  - `pending_login_is_single_use`: `put_pending` then `take_pending` twice returns the record then `None`.
  - `callback_rejects_bad_state`: a callback request with a mismatched `state` returns `401` and leaves no session cookie or token record in `MemoryStore`.
  - `logout_get_is_405`: `GET /auth/logout` returns `405` with `Allow: POST`.
  - `anonymous_logout_is_idempotent`: `POST /auth/logout` with no cookie returns `302` with `Location: /`.

  Stub discovery/userinfo with `wiremock` only for tests that call `OidcClient::new` or `complete`; do not call real Keycloak in these unit tests. Update all `AppState` test constructors built in Tasks 3–5 to include the new `oidc` field.

- [ ] **Step 3: Run failing tests**

Run: `cd upstream && cargo test oidc::tests && cargo test web::auth::tests`
Expected: compile failure, missing symbols.

- [ ] **Step 4: Implement `oidc.rs` and `web/auth.rs`**

`OidcClient::new` performs discovery with `CoreProviderMetadata::discover_async` using a `reqwest` client with redirects disabled and the explicit root store. `authorization_request` uses `PkceCodeChallenge::new_random_sha256()`, `CsrfToken::new_random`, `Nonce::new_random`, and the configured scopes; the caller stores `PendingLogin` under `oidc:<random>` with a 600-second TTL. `complete` exchanges the code with the verifier, verifies the ID token nonce, fetches userinfo, and reads `AUTH_USERNAME_FIELD`/`AUTH_GROUPS_FIELD`. Callback maps invalid state, exchange failure, nonce mismatch, and userinfo failure to `401`; "no token" to `302 /`. Logout deletes the token and clears the cookie, checking the session before CSRF.

- [ ] **Step 5: Run tests**

Run: `cd upstream && cargo test oidc::tests && cargo test web::auth::tests`
Expected: all five PASS.

- [ ] **Step 6: Commit**

```bash
git -C upstream add Cargo.toml src/oidc.rs src/web/auth.rs src/state.rs src/web/mod.rs src/main.rs
git -C upstream commit -m "feat: add OIDC login, callback and idempotent logout"
```

---

### Task 5: Portal rendering, CSRF forms and static assets

**Files:**
- Create: `upstream/templates/error.html`, `upstream/src/web/portal.rs`, `upstream/src/web/static_files.rs`
- Modify: `upstream/templates/index.html`, `upstream/src/web/mod.rs`

**Interfaces:**
- Consumes: `authorized_servers` (Task 3), `AppState`, `TokenRecord`.
- Produces: `pub async fn index(State(state): State<AppState>, jar: SignedCookieJar) -> Response` at `GET /`; a static handler at `/static/*path` serving the embedded logo; `pub fn csrf_field(token: &str) -> String` helper used by templates via minijinja context.

- [ ] **Step 1: Add dependencies** `minijinja` and `rust-embed` (embed `templates/` and `static/` at compile time; at startup prefer a mounted `templates/`/`static/` directory when present).

- [ ] **Step 2: Write failing handler tests in `upstream/src/web/portal.rs`**
  - `index_lists_only_authorized_servers`: seeded session with groups `/example` → body contains `Logged in as: testuser`, `Download VPN Server Configuration`, `myserver`, `myserver2`, `myserver3`, and not `myserver4`.
  - `index_forms_carry_csrf`: body contains `action="/api/servers/myserver"`, `method="post"`, and a hidden `csrf_token` input matching the seeded record.
  - `index_logout_form_is_post`: body contains `action="/auth/logout"` and `method="post"`.
  - `index_missing_groups_is_500_html`: `userinfo` without groups → `500` and `Content-Type` starts with `text/html`.
  - `unauthenticated_index_redirects`: no cookie → `302` `Location: /auth/login`.
  - `static_logo_is_served`: `GET /static/logo.png` → `200`.

- [ ] **Step 3: Run failing tests**

Run: `cd upstream && cargo test web::portal::tests`
Expected: compile failure, missing module and handler.

- [ ] **Step 4: Update `templates/index.html` and implement `web/portal.rs` and `web/static_files.rs`**

Keep `base.html` and the visible text unchanged. Emit the info-level log containing username and groups on successful rendering. Replace each server `<a>` with a `<form method="post" action="/api/servers/{{vpn_server}}">` containing `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` and a submit button. Replace the logout form with `method="post"` and the same hidden field. Add `templates/error.html` with a short message. Render with minijinja using `auto_escape` for HTML; `web/static_files.rs` serves embedded `static/logo.png` with `image/png`.

- [ ] **Step 5: Run tests**

Run: `cd upstream && cargo test web::portal::tests`
Expected: all six PASS.

- [ ] **Step 6: Commit**

```bash
git -C upstream add templates/index.html templates/error.html src/web/portal.rs src/web/static_files.rs src/web/mod.rs Cargo.toml
git -C upstream commit -m "feat: render portal with CSRF-protected forms"
```

---

### Task 6: Vault client, metadata validation, OVPN rendering and download

**Files:**
- Create: `upstream/src/vault.rs`, `upstream/src/ovpn.rs`
- Modify: `upstream/src/state.rs`, `upstream/src/web/api.rs`, `upstream/src/web/mod.rs`, `upstream/Cargo.toml`, `upstream/templates/template.ovpn`

**Interfaces:**
- Consumes: `Mapping`, `AppConfig`, `authorized`, `SessionStore`, `ApiError`/`PageError`.
- Produces: `pub struct Metadata { pub hostname: String, pub port: String, pub protocol: String, pub server_dn: String, pub cipher: String, pub digest: String, pub certificate_authority: String, pub server_tls_key: String }`; `pub struct Certificate { pub certificate: String, pub private_key: String }`; `pub struct VaultClient`; `impl VaultClient { pub fn new(base_url: url::Url, custom_ca: Option<&str>, verify: bool) -> anyhow::Result<Self>; pub async fn jwt_login(&self, jwt: &str, mapping: &Mapping) -> anyhow::Result<String>; pub async fn read_metadata(&self, token: &str, mapping: &Mapping) -> anyhow::Result<Metadata>; pub async fn issue_certificate(&self, token: &str, mapping: &Mapping, common_name: &str) -> anyhow::Result<Certificate> }`; `pub fn parse_metadata(value: &serde_json::Value) -> anyhow::Result<Metadata>`; `pub fn render(metadata: &Metadata, cert: &Certificate) -> anyhow::Result<String>`; handler `pub async fn download(Path(server): Path<String>, Form(form): Form<CsrfForm>, State(state): State<AppState>, jar: SignedCookieJar) -> Response` at `POST /api/servers/{server}` (returns an empty-body `401` directly, and uses `PageError(...).into_response()` for other failures).

- [ ] **Step 1: Add dependencies** `reqwest` (rustls/no-provider per Task 4), `rustls`, `rustls-pemfile`, `webpki-roots`, `serde_urlencoded`, `axum` `form` feature. Extend `AppState` with `pub vault: Arc<VaultClient>` and update every `AppState` test constructor from Tasks 3–5 to include it.

- [ ] **Step 2: Write failing tests in `upstream/src/ovpn.rs`**
  - `accepts_reference_metadata`: the Terraform `develmeta` payload (including numeric `port: 1194`, multi-line CA and `server_tls_key`) parses; `port` becomes `"1194"`.
  - `rejects_newline_in_scalar`: `hostname` containing `\n` is rejected.
  - `rejects_ovpn_tag_in_pem`: `certificate_authority` containing `</ca>` is rejected.
  - `accepts_multiline_pem`: CA PEM with `\n` and CRLF variants parses after normalization.
  - `render_matches_directives`: rendering the reference metadata and a stub certificate yields `dev tun`, `cipher AES-256-CBC`, `auth SHA1`, `remote myvpn.example.com 1194 udp`, the `verify-x509-name` line, and `<ca>`, `<cert>`, `<key>`, `<tls-crypt>` blocks.

- [ ] **Step 3: Write failing Vault tests in `upstream/src/vault.rs`** using `wiremock`:
  - `jwt_login_posts_role_and_token`: request body contains the mapping's role and the supplied JWT; returned client token is used in the next request's `X-Vault-Token` header.
  - `read_metadata_uses_data_data`: KV v2 response is read from `data.data`.
  - `issue_certificate_uses_common_name`: request body contains only `common_name` equal to `testuser` and the path ends in `/issue/client`.

- [ ] **Step 4: Run failing tests**

Run: `cd upstream && cargo test ovpn::tests && cargo test vault::tests`
Expected: compile failure, missing modules.

- [ ] **Step 5: Implement `ovpn.rs` and `vault.rs`**

`parse_metadata` requires all eight keys, coerces `port` from string or number to string, rejects CR/LF on scalars, requires matching PEM BEGIN/END markers on the two PEM keys, rejects OVPN closing tags and directive-looking lines in them, and normalizes CRLF to LF. `render` uses the embedded `template.ovpn` with no auto-escaping and no conditional blocks. `VaultClient::new` builds the explicit root store from embedded roots plus `CUSTOM_VAULT_CA` (inline PEM or a path when the value is not PEM), and disables verification only in development. Emit the debug-level metadata log with non-secret fields only (hostname, port, protocol, cipher, digest, server_dn); never log CA blobs, `server_tls_key`, issued keys, or client tokens.

- [ ] **Step 6: Write and run download handler tests in `upstream/src/web/api.rs`**
  - `download_without_session_is_401_empty`: no cookie → `401`, empty body.
  - `download_bad_csrf_is_403`: valid session, wrong token → `403`.
  - `download_denied_server_never_calls_vault`: groups `/example`, server `myserver4` → `403` and `wiremock` reports zero requests.
  - `download_unknown_server_never_calls_vault`: server `nosuch` → `403` and zero requests.
  - `download_success_has_contract_headers`: authorized server, valid CSRF → `200`, `Content-Type: text/plain`, `Content-Disposition: attachment; filename="myserver.ovpn"`, body contains `dev tun`.
  Run: `cd upstream && cargo test web::api::tests`
  Expected: all five PASS.

- [ ] **Step 7: Commit**

```bash
git -C upstream add Cargo.toml src/vault.rs src/ovpn.rs src/state.rs src/web/api.rs src/web/mod.rs templates/template.ovpn
git -C upstream commit -m "feat: add Vault orchestration and OVPN download"
```

---

### Task 7: Scratch container, compose and CI wiring

**Files:**
- Modify: `upstream/Dockerfile`, `upstream/docker-compose-e2e.yml`, `upstream/.github/workflows/test-suite.yml`, `upstream/requirements.txt`, `upstream/requirements-dev.txt`, `upstream/deny.toml` (create)

**Interfaces:**
- Consumes: the compiled binary from Tasks 1–6.
- Produces: image tag `kr0nus/vsm:devel`; CI jobs `rust`, `integrationtests`, `e2etests`.

- [ ] **Step 1: Rewrite `upstream/Dockerfile`**

Builder stage `FROM rust:1-alpine AS builder`, `RUN apk add --no-cache build-base musl-dev`, `WORKDIR /src`, `COPY . .`, `RUN cargo build --release --target x86_64-unknown-linux-musl`. Runtime stage `FROM scratch`, `COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/vsm /vsm`, `WORKDIR /app`, `USER 65532:65532`, `EXPOSE 3000`, `ENTRYPOINT ["/vsm"]`. Keep the config/template/static volume mounts in compose; do not copy them into the image.

- [ ] **Step 2: Update `docker-compose-e2e.yml`** so the `vsm` service builds this Dockerfile and is tagged `kr0nus/vsm:devel` (keeping the existing `config/vsm-e2e:/app/config/vsm:ro` mount and all depends_on entries). Leave `docker-compose-common.yml`, `docker-compose-integration.yml`, HAProxy configs, and Terraform untouched.

- [ ] **Step 3: Update `.github/workflows/test-suite.yml`**

Add a `rust` job running `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo audit`, and `cargo deny check licenses` from the repo root. Replace the Python `lint` and `license` jobs. In `integrationtests`, add a step that runs `cargo build --release` and starts the resulting binary on `localhost:3000` with CWD the repo root before pytest; keep the existing compose/wait/terraform steps. Leave the e2e job's image build, SBOM, browser runs, and screenshot cleanup intact.

- [ ] **Step 4: Trim Python dependencies**

`requirements.txt` keeps only test-time packages actually used by the converted suite (`pytest`, `requests`, `beautifulsoup4`, `redis`); remove Flask, Authlib, hvac, certifi. `requirements-dev.txt` keeps pylint/autopep8 only if still used on remaining Python test files; otherwise reduce to the Cypress setup. Create `deny.toml` with an allowlist of the project's licenses and `cargo deny check licenses` passing.

- [ ] **Step 5: Verify container and static build**

Run: `cd upstream && docker build -t kr0nus/vsm:devel . && docker run --rm --entrypoint /bin/sh kr0nus/vsm:devel -c 'echo should-not-exist' || true && docker image inspect kr0nus/vsm:devel --format '{{.Config}}'`
Expected: build succeeds; no shell exists in the image; image config shows `FROM scratch`-style layers with no package manager. Also run `cd upstream && cargo build --release --target x86_64-unknown-linux-musl && file target/x86_64-unknown-linux-musl/release/vsm` and confirm `statically linked`.

- [ ] **Step 6: Commit**

```bash
git -C upstream add Dockerfile docker-compose-e2e.yml .github/workflows/test-suite.yml requirements.txt requirements-dev.txt deny.toml
git -C upstream commit -m "build: static musl binary and scratch container with CI wiring"
```

---

### Task 8: Convert pytest integration suite to HTTP tests

**Files:**
- Modify: `upstream/test/conftest.py`, `upstream/test/fixtures/application.py`, `upstream/test/fixtures/client.py`, `upstream/test/fixtures/login.py`, `upstream/test/fixtures/logout.py`, `upstream/test/fixtures/expire_session.py`, `upstream/test/test_index.py`, `upstream/test/test_server.py`, `upstream/test/test_whoami.py`

**Interfaces:**
- Consumes: `kr0nus/vsm:devel` binary served at `http://localhost:3000` by the CI step from Task 7 (or a manually started binary during local runs); Keycloak, Redis and Vault from `docker-compose-common.yml` + Terraform.
- Produces: `client` fixture returning a `requests.Session` for `http://localhost:3000`; fixtures `login(client)`, `logout(client)`, `expire_session(client)` with their existing signatures.

- [ ] **Step 1: Replace the in-process fixtures**

`application.py` and `client.py` stop importing `vsm`; `client` creates `requests.Session` with base URL from env `VSM_BASE_URL` default `http://localhost:3000`. Remove the `application` fixture from `conftest.py` plugin list and file.

- [ ] **Step 2: Rewrite `login` for the HTTP flow**

Follow: `GET /` → `302 /auth/login`; `GET /auth/login` → `302` to the IdP; assert the URL starts with `http://kc.local.kronus.network/realms/devel/protocol/openid-connect/auth?`; use a separate `requests.Session` for Keycloak; parse the form action with BeautifulSoup; POST `{"username": "testuser"}` with redirects disabled; assert the callback URL starts with `http://localhost:3000/auth/callback?`; GET it with the VSM session; assert `302 /`; GET `/`; assert `200`.

- [ ] **Step 3: Rewrite `logout` and `expire_session`**

`logout(client)` parses `csrf_token` from the portal HTML, POSTs it to `/auth/logout`, and asserts `302 /`. `expire_session(client)` reads the `session` cookie value, base64-decodes the first dot-separated segment to get `{"user": "<uuid>"}`, connects to Redis at `localhost:6379` DB 0, rewrites `expires_at` to `int(time.time())`, and stores it again with `SET` (no EX) so read-time expiry is exercised.

- [ ] **Step 4: Update assertions in the three test files**

Change download calls to `client.post('/api/servers/myserver', data={'csrf_token': <token from portal>})`; change invalid/denied server assertions from `302` + `Location: /` to `403`; keep the `200` profile assertion (`dev tun`), all whoami assertions, expiry `401` assertions, and unauthenticated index redirect. Add `test_logout_when_anonymous_is_idempotent` asserting `302 /` with no cookie.

- [ ] **Step 5: Run integration tests against the live stack**

Run with common compose + Terraform applied and the Rust binary running:

```bash
cd upstream && pytest -q
```

Expected: all tests PASS, including new CSRF, `403` and idempotent-logout cases.

- [ ] **Step 6: Commit**

```bash
git -C upstream add test/
git -C upstream commit -m "test: convert integration suite to HTTP contract"
```

---

### Task 9: Update Cypress E2E suite

**Files:**
- Modify: `upstream/cypress/e2e/vsm.cy.js`

**Interfaces:**
- Consumes: portal forms from Task 5 and `403` error page from Task 6.
- Produces: same five `it(...)` cases with updated selectors/assertions.

- [ ] **Step 1: Update the success case**

Inside `cy.origin('http://vsm.local.kronus.network', ...)`, replace `cy.get('a[href="/api/servers/myserver"]').click()` with `cy.get('form[action="/api/servers/myserver"] button').click()`. Keep every golden assertion on the downloaded `myserver.ovpn` unchanged (lines asserting `cipher AES-256-CBC`, `auth SHA1`, `remote myvpn.example.com 1194 udp`, `verify-x509-name`, and all four PEM blocks).

- [ ] **Step 2: Update the unknown-server case**

Use a POST request carrying the CSRF token scraped from the portal form: `cy.get('form[action="/api/servers/badserver"] input[name="csrf_token"]')` may not exist for a denied server, so instead POST to `/api/servers/badserver` with a token taken from a visible allowed-server form and assert `expect(resp.status).to.eq(403)`. Drop the `redirectedToUrl` assertion and keep the navbar-brand assertion.

- [ ] **Step 3: Keep the remaining cases**

`Bad username`, `Not logged in` (still `401` on GET `/api/servers/myserver`), and `Who Am I endpoint test` stay as-is. Add one assertion that `GET /auth/logout` returns `405`.

- [ ] **Step 4: Run both browsers**

Run:

```bash
cd upstream && npx cypress run --browser chrome --spec cypress/e2e/vsm.cy.js
rm -rf cypress/screenshots cypress/downloads
npx cypress run --browser firefox --spec cypress/e2e/vsm.cy.js
```

Expected: all five cases PASS in both browsers.

- [ ] **Step 5: Commit**

```bash
git -C upstream add cypress/e2e/vsm.cy.js
git -C upstream commit -m "test: update Cypress for CSRF forms and 403 responses"
```

---

### Task 10: Cutover and full acceptance

**Files:**
- Delete: `upstream/vsm.py`, `upstream/templates/logout.html`, `upstream/liccheck.ini`, `upstream/.coveragerc`
- Modify: `upstream/README.md`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: a repository whose only application runtime is the Rust binary.

- [ ] **Step 1: Remove the Python application**

Delete `vsm.py`, `templates/logout.html`, `liccheck.ini`, `.coveragerc`. Confirm no remaining file imports `vsm` or references `python vsm.py`:

Run: `cd upstream && grep -R "vsm.py\|python vsm\|from vsm" --exclude-dir=.git . || true`
Expected: no application references (docs may mention history; update any that do).

- [ ] **Step 2: Update `README.md`** to describe the Rust build, `FROM scratch` image, mounted config/templates/static, the changed contract (POST download/logout, `403`, CSRF, hardened cookies), and the local test commands.

- [ ] **Step 3: Run the complete verification suite**

Run in order:

```bash
cd upstream
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
cargo deny check licenses
docker build -t kr0nus/vsm:devel .
pytest -q
```

Expected: every command exits 0 with the live stack up for pytest.

- [ ] **Step 4: Walk the CONTRACT acceptance list**

Verify: unauthenticated `/` → `302 /auth/login`; APIs → `401`; expiry rejects all protected routes; portal/whoami list exactly the three servers; download yields a valid profile with a fresh 8-hour cert whose CN is `testuser`; denied/unknown servers → `403` with zero Vault calls; logout removes Redis key and cookie; all config keys consumed from files; Cypress passes in both browsers; image is scratch with no dynamic libs.

- [ ] **Step 5: Commit**

```bash
git -C upstream add -A
git -C upstream commit -m "chore: remove Python application and document Rust contract"
```
