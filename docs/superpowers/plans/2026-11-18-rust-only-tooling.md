# Rust-only Tooling and De-Python-ification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python lint/test/tooling stack with Rust equivalents, port the 11 pytest black-box tests to Rust, remove every Python artifact, and bring the active docs in line.

**Architecture:** A `tests/integration.rs` binary drives the running VSM over HTTP with `reqwest`, a hand-rolled cookie jar, `scraper` for CSRF/form extraction, and the `redis` crate for session expiry. The tests are `#[ignore]`d so the stack-free CI `rust` job only compiles them; the CI integration job runs them with `--ignored`. `package.json`, CI, editor config, and docs switch to `cargo` commands, and `FLASK_SECRET` is renamed to `SESSION_SECRET`.

**Tech Stack:** Rust 1.88, axum 0.8, reqwest 0.12, tokio, scraper, percent-encoding, serde_json, redis 0.32, Cargo deny/audit, Cypress (unchanged).

**Spec:** `docs/superpowers/specs/2026-11-18-rust-only-tooling-design.md`

## Global Constraints

- Rust toolchain 1.88 (`rust-toolchain.toml`); do not raise the MSRV.
- Add only **dev-dependencies**: `scraper`, `percent-encoding`. No new runtime dependencies.
- Do not change routes, status codes, redirects, cookie attributes, templates, OIDC, Vault, or Redis behavior.
- `FLASK_SECRET` → `SESSION_SECRET` is a deliberate breaking config rename; remove `FLASK_APP` entirely.
- Every ported integration test is `#[ignore = "requires the integration stack"]`.
- `VSM_BASE_URL` defaults to `http://localhost:3000`.
- Historical docs `docs/superpowers/{specs,plans}/2026-11-17-*` and `2026-11-18-dead-code-cleanup*` are left untouched.
- Redis for the expiry helper: `redis://127.0.0.1:6379/0`.

## Review Focus

1. **Redirects must not auto-follow.** `reqwest` follows up to 10 by default; the harness must use `Policy::none()`, or every `302`/`Location` assertion becomes meaningless. Every ported test asserts `302` + `Location`.
2. **The session cookie is signed on the wire.** `SignedCookieJar` prefixes the 32-hex UUID with a 44-char base64 HMAC; the expiry helper must percent-decode, split at `.`, and slice `[44..]`. Task 1 asserts the 32-lowercase-hex shape; the expired tests in Tasks 2–4 depend on it.
3. **The Keycloak `idp` session needs its own cookie jar.** Sharing the VSM jar sends the wrong cookies to Keycloak and loses the auth session. Task 1's `login` takes two distinct `TestSession`s.
4. **Logout clears the cookie with `Max-Age=0`.** The jar must delete a cookie when the response sends an empty value or `Max-Age=0`, or `logout_when_anonymous_is_idempotent` sees a stale `session`. Task 1 implements deletion; Task 2 asserts it.
5. **`--ignored` must fail loudly, not skip.** With no stack, `cargo test --test integration -- --ignored` must produce connection errors, not "0 tests". Task 9 checks this explicitly.

---

### Task 1: Integration-test harness and auth helpers

**Files:**
- Modify: `Cargo.toml` (`[dev-dependencies]`)
- Create: `tests/support/mod.rs`
- Create: `tests/integration.rs`

**Interfaces:**
- Produces:
  - `TestSession::new(base: Option<&str>) -> TestSession`
  - `TestSession::base_url(&self) -> &url::Url`
  - `TestSession::rewrite_base(&self, absolute: &str) -> String`
  - `TestSession::get(&mut self, path_or_url: &str) -> reqwest::Response`
  - `TestSession::post_form(&mut self, path_or_url: &str, form: &[(&str, &str)]) -> reqwest::Response`
  - `TestSession::cookie(&self, name: &str) -> Option<&str>`
  - `TestSession.csrf_token: Option<String>` (public field)
  - `csrf_token(html: &str) -> String`
  - `form_action(html: &str) -> String`
  - `login(session: &mut TestSession, idp: &mut TestSession)` (async)
  - `logout(session: &mut TestSession)` (async)
  - `expire_session(session: &mut TestSession)` (async)

- [ ] **Step 1: Add the dev-dependencies**

```toml
[dev-dependencies]
chrono = "0.4"
wiremock = "0.6"
scraper = "0.20"
percent-encoding = "2"
```

Run: `cargo check --all-targets`
Expected: builds (network may be needed to fetch the new crates).

- [ ] **Step 2: Write `tests/support/mod.rs`**

Implement `TestSession` with `reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())`. Resolve a request target as follows: if it starts with `http://` or `https://`, parse it as-is; otherwise `base.join(path)`. Before each request add a `COOKIE` header built from `name=value` pairs; after each response iterate `get_all(SET_COOKIE)`, take the text before the first `;`, split at the first `=`, and either insert the value or delete the entry when the value is empty or a `Max-Age=0` attribute is present.

`post_form` serializes with the already-present `serde_urlencoded` and sets `Content-Type: application/x-www-form-urlencoded` (do not rely on a `reqwest` `form` feature).

`csrf_token` parses with `scraper::Html::parse_document` and returns the `value` of `input[name=csrf_token]`; `form_action` returns the `action` of the first `form`.

`login` ports `test/fixtures/login.py` exactly: GET `/` → 302 `/auth/login`; GET `/auth/login` → 302 with `Location` starting `http://kc.local.kronus.network/realms/devel/protocol/openid-connect/auth?`; GET that URL on `idp`; POST `form_action(html)` on `idp` with `[("username", "testuser")]` → 302 with `Location` starting `http://vsm.local.kronus.network/auth/callback?`; rewrite the callback host to the VSM base with `rewrite_base`; GET it on `session` → 302 `/`; GET `/` → 200 and store `csrf_token` from the body.

`logout` ports `test/fixtures/logout.py`: GET `/` (no redirects); if 200 read the CSRF token from the body, otherwise use `session.csrf_token.clone().unwrap_or_default()`; POST `/auth/logout` with `csrf_token` → assert 302 and `Location: /`.

`expire_session` ports `test/fixtures/expire_session.py`: percent-decode `session.cookie("session")`, split at `.`, take the first part, slice `[44..]`, assert the result is 32 lowercase hex chars, connect with `redis::Client::open("redis://127.0.0.1:6379/0")`, `GET` the JSON, set `expires_at` to the current Unix time, and `SET` it back.

- [ ] **Step 3: Write the ignored harness test in `tests/integration.rs`**

```rust
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
```

- [ ] **Step 4: Compile the integration target**

Run: `cargo test --test integration --no-run`
Expected: compiles with no errors.

- [ ] **Step 5: Run the unit suite**

Run: `cargo test`
Expected: all existing unit tests pass; the ignored integration test is not run.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock tests/support/mod.rs tests/integration.rs
git commit -m "test: add Rust integration harness and auth helpers"
```

---

### Task 2: Port the index suite

**Files:**
- Modify: `tests/integration.rs`

**Interfaces:**
- Consumes: `TestSession`, `login`, `logout`, `expire_session`, `base_url` from Task 1.

- [ ] **Step 1: Add the three tests**

```rust
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
```

- [ ] **Step 2: Compile**

Run: `cargo test --test integration --no-run`
Expected: compiles.

- [ ] **Step 3: Run the unit suite and lint**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add tests/integration.rs
git commit -m "test: port index and anonymous-logout integration tests"
```

---

### Task 3: Port the whoami suite

**Files:**
- Modify: `tests/integration.rs`

**Interfaces:**
- Consumes: `TestSession`, `login`, `logout`, `expire_session`, `base_url`.

- [ ] **Step 1: Add the three tests**

```rust
#[tokio::test]
#[ignore = "requires the integration stack"]
async fn whoami_requires_login() {
    let mut s = TestSession::new(Some(&base_url()));
    assert_eq!(s.get("/api/whoami").await.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires the integration stack"]
async fn whoami_returns_user_and_servers() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    let body = s.get("/api/whoami").await.text().await.unwrap();
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
    assert_eq!(s.get("/api/whoami").await.status(), reqwest::StatusCode::UNAUTHORIZED);
    support::logout(&mut s).await;
}
```

- [ ] **Step 2: Compile**

Run: `cargo test --test integration --no-run`
Expected: compiles.

- [ ] **Step 3: Run the unit suite and lint**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add tests/integration.rs
git commit -m "test: port whoami integration tests"
```

---

### Task 4: Port the server-download suite

**Files:**
- Modify: `tests/integration.rs`

**Interfaces:**
- Consumes: `TestSession`, `login`, `logout`, `expire_session`, `base_url`, `TestSession.csrf_token`.

- [ ] **Step 1: Add the five tests**

```rust
#[tokio::test]
#[ignore = "requires the integration stack"]
async fn download_returns_ovpn() {
    let mut s = TestSession::new(Some(&base_url()));
    let mut idp = TestSession::new(None);
    support::login(&mut s, &mut idp).await;
    let token = s.csrf_token.clone().unwrap();
    let r = s.post_form("/api/servers/myserver", &[("csrf_token", &token)]).await;
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    assert!(r.text().await.unwrap().contains("dev tun"));
    assert_eq!(
        r.headers()[reqwest::header::CONTENT_DISPOSITION],
        "attachment; filename=\"myserver.ovpn\""
    );
    support::logout(&mut s).await;
}
```

Add `download_expired_is_unauthorized` (login → expire → POST with `csrf_token` → 401 → logout), `download_anonymous_is_unauthorized` (new session → POST with `csrf_token=""` → 401), `download_unknown_server_is_forbidden` (login → POST `/api/servers/mybadserver` → 403, `Content-Type` starts with `text/html`, body contains `Forbidden` → logout), and `download_denied_server_is_forbidden` (same for `myserver4`).

- [ ] **Step 2: Compile**

Run: `cargo test --test integration --no-run`
Expected: compiles.

- [ ] **Step 3: Run the unit suite and lint**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add tests/integration.rs
git commit -m "test: port server download integration tests"
```

---

### Task 5: Rename the config key and drop `FLASK_APP`

**Files:**
- Modify: `src/config.rs`, `src/state.rs`, `src/oidc.rs`, `src/session.rs`, `src/web/api.rs`, `src/web/portal.rs`, `src/web/auth.rs`
- Modify: `config/vsm/app.json`, `config/vsm-e2e/app.json`

**Interfaces:**
- Produces: `AppConfig.session_secret: String` (replaces `flask_secret`); config files read `SESSION_SECRET`.

- [ ] **Step 1: Rename the field and parse key**

In `src/config.rs`: rename `pub flask_secret: String` to `pub session_secret: String`; rename the local and struct-literal occurrences; change `required_string(raw, "FLASK_SECRET")` to `"SESSION_SECRET"`; update the length error strings; in the `REFERENCE_APP` fixture remove `"FLASK_APP": "vsm.py"` and rename `"FLASK_SECRET"` to `"SESSION_SECRET"`.

- [ ] **Step 2: Update every consumer**

`src/state.rs`: `signing_key(&state.config.session_secret)`.
`src/oidc.rs` (~319 and ~511): `session_secret:` in the `AppConfig` literals.
`src/web/api.rs`, `src/web/portal.rs`, `src/web/auth.rs`: rename `TEST_FLASK_SECRET` → `TEST_SESSION_SECRET` and `flask_secret:` → `session_secret:`.
`src/session.rs` (~42, ~297) and `src/web/auth.rs` (~349): replace `FLASK_SECRET` with `SESSION_SECRET` in comments.

- [ ] **Step 3: Update both config files**

Remove `"FLASK_APP": "vsm.py"` and rename `"FLASK_SECRET"` to `"SESSION_SECRET"` in `config/vsm/app.json` and `config/vsm-e2e/app.json`.

- [ ] **Step 4: Verify**

Run: `cargo test`
Expected: passes (including `accepts_reference_config`).

Run: `grep -rniE 'flask_secret|FLASK_SECRET|FLASK_APP' src config`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add src config
git commit -m "refactor: rename FLASK_SECRET to SESSION_SECRET and drop FLASK_APP"
```

---

### Task 6: Replace npm scripts, delete Python artifacts, clean editor config

**Files:**
- Modify: `package.json`, `.vscode/settings.json`, `.gitignore`
- Delete: `test/conftest.py`, `test/test_*.py`, `test/fixtures/*.py`, `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `coverage-badge.svg`, `tests-badge.svg`, `all.lst`

**Interfaces:**
- Produces: npm scripts that call only Cargo/Docker/npm/Cypress/shell.

- [ ] **Step 1: Rewrite `package.json` scripts**

Use exactly the table in the spec §7.1: `build`, `lint` (`cargo fmt --check && cargo clippy --all-targets -- -D warnings`), `license`, `audit`, `test` (`cargo test --test integration -- --ignored`), `test:unit` (`cargo test`), `coverage` (`cargo llvm-cov --html`), `setup`, `teardown`, `pretest`, `posttest` (drop `genbadge`), `pree2e`, `e2e`, `poste2e`.

- [ ] **Step 2: Delete the Python tree and stray artifacts**

```bash
git rm test/conftest.py test/test_index.py test/test_server.py test/test_whoami.py \
  test/fixtures/__init__.py test/fixtures/client.py test/fixtures/expire_session.py \
  test/fixtures/login.py test/fixtures/logout.py \
  coverage-badge.svg tests-badge.svg
rm -f requirements.txt requirements-dev.txt pyproject.toml all.lst
rm -rf test/__pycache__ test/fixtures/__pycache__
```

- [ ] **Step 3: Replace `.vscode/settings.json`**

```json
{
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.cargo.allTargets": true
}
```

- [ ] **Step 4: Update `.gitignore`**

Remove Python/Flask entries (`__pycache__/`, `*.py[cod]`, `.venv/`, `venv/`, `coverage.xml`, `htmlcov/`, `.pytest_cache/`, etc.). Keep/add: `target/`, `vsm.log`, `coverage/`, `*.tfstate`, `.terraform/`, `cypress/screenshots/`, `cypress/downloads/`.

- [ ] **Step 5: Verify**

Run: `npm run lint && npm run test:unit`
Expected: fmt/clippy clean and unit tests pass.

Run: `find . -path ./target -prune -o \( -name '*.py' -o -name 'requirements*.txt' -o -name 'pyproject.toml' -o -name '__pycache__' \) -print`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add -A package.json .vscode .gitignore test
git commit -m "chore: replace Python tooling with Rust equivalents and remove Python files"
```

---

### Task 7: Update CI

**Files:**
- Modify: `.github/workflows/test-suite.yml`

**Interfaces:**
- Consumes: `cargo test --test integration -- --ignored` from Task 1.

- [ ] **Step 1: Tighten the `rust` job**

Change the clippy step to `cargo clippy --all-targets -- -D warnings`. Leave fmt, test, audit, and deny as they are.

- [ ] **Step 2: Replace the Python steps in `integrationtests`**

Delete the `pyenv-action`, `pip install`, and `pytest-action` steps. After the existing build/start/readiness steps, add:

```yaml
      - name: Run Rust integration tests
        env:
          VSM_BASE_URL: http://localhost:3000
        run: cargo test --test integration -- --ignored
```

- [ ] **Step 3: Verify**

Run: `grep -nEi 'python|pytest|pip |pyenv|requirements|pytest-action' .github/workflows/test-suite.yml`
Expected: no output.

Read the job order and confirm: compose → wait → terraform → build release → start VSM → readiness → run Rust tests.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/test-suite.yml
git commit -m "ci: run Rust integration tests and drop Python steps"
```

---

### Task 8: Update active documentation

**Files:**
- Modify: `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `functional-spec.md`

- [ ] **Step 1: README**

Remove the "Legacy notes" paragraph about Python/Flask. Document `npm run lint|license|audit|test|test:unit|coverage`, the `FLASK_SECRET` → `SESSION_SECRET` rename (breaking), and that `npm test` needs a running VSM at `VSM_BASE_URL`.

- [ ] **Step 2: CONTRIBUTING**

Replace the pylint/autopep8/pipenv guidance with `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and the integration command.

- [ ] **Step 3: AGENTS.md**

Replace the "Verification targets" Python list with the Cargo commands and Cypress. Update runtime traps to say `SESSION_SECRET`; state that the 2026-11-17 rewrite docs and 2026-11-18 cleanup docs are historical.

- [ ] **Step 4: functional-spec.md**

Rewrite it as an as-built description of the Rust system:
- Source map: `src/*.rs`, `src/web/*.rs`, `tests/integration.rs`, `test/presetup/*`, `cypress/e2e/vsm.cy.js`.
- Config table: `SESSION_SECRET` (remove `FLASK_APP`).
- Session: signed cookie whose value is a 32-hex UUID; read-time expiry.
- Routes: 403 for unknown/denied downloads, 401 for unauthenticated API calls, 302 for expired-page redirects.
- Dependencies/CI: Cargo, fmt/clippy/test/audit/deny, Cypress.
- Verification targets: the Cargo commands.
- Remove Flask-era defect notes that no longer describe the binary.

- [ ] **Step 5: Verify the grep gate**

Run:

```bash
grep -rniE 'python|pytest|pylint|autopep8|liccheck|pip |requirements\.txt|pyproject|genbadge|flask' \
  --exclude-dir=.git --exclude-dir=target .
```

Expected: matches only in `docs/superpowers/specs/2026-11-17-*`, `docs/superpowers/plans/2026-11-17-*`, `docs/superpowers/specs/2026-11-18-dead-code-cleanup*`, `docs/superpowers/plans/2026-11-18-dead-code-cleanup*`, this plan, and the design doc.

- [ ] **Step 6: Commit**

```bash
git add README.md CONTRIBUTING.md AGENTS.md functional-spec.md
git commit -m "docs: describe the Rust system and remove Python instructions"
```

---

### Task 9: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Format and lint**

Run: `cargo fmt --check`
Expected: exit 0.

Run: `cargo clippy --all-targets -- -D warnings`
Expected: exit 0.

- [ ] **Step 2: Unit tests and integration compile**

Run: `cargo test`
Expected: all unit tests pass; ignored integration tests are not run.

Run: `cargo test --test integration --no-run`
Expected: compiles.

- [ ] **Step 3: Prove `--ignored` fails loudly without the stack**

Run: `cargo test --test integration -- --ignored`
Expected: fails with a connection-refused/transport error (not "0 tests"). This is expected in this workspace.

- [ ] **Step 4: Prove no Python artifacts remain**

Run: `find . -path ./target -prune -o -path ./.git -prune -o \( -name '*.py' -o -name '*.pyc' -o -name 'requirements*.txt' -o -name 'pyproject.toml' -o -name '__pycache__' \) -print`
Expected: no output.

- [ ] **Step 5: Run the license/audit scripts where installed**

Run: `npm run license && npm run audit`
Expected: pass if `cargo-deny`/`cargo-audit` are installed; note any missing tool rather than changing the script.

- [ ] **Step 6: Commit any verification-only formatting fixes**

```bash
git add -A
git commit -m "chore: final Rust-only verification"
```

---

## Self-Review Notes

- **Spec coverage:** §7.1 → Task 6; §7.2 → Tasks 1–4; §7.3 → Task 7; §7.4 → Task 5; §7.5 → Task 6; §7.6 → Task 8; §7.7 → Task 6; §9 → Task 9.
- **Step scan:** every step has one checkable result; helper bodies are specified by signature plus the exact ported fixture they mirror, not transcribed.
- **Type consistency:** `session_secret`, `TestSession`, `csrf_token`, `login`, `logout`, `expire_session` are used identically across tasks.
- **Review Focus:** each of the five items maps to a test named in Tasks 1–4 and a check in Task 9.
