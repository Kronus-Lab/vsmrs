# Rust-only tooling and de-Python-ification — Design

- **Date:** 2026-11-18
- **Status:** Proposed (awaiting approval)
- **Scope chosen by product owner:** "Code + active docs, keep history"
- **Supersedes:** the "Python is a test-only dependency" decision in
  `docs/superpowers/specs/2026-11-17-rust-rewrite-design.md` §2/§9/§10 and
  `docs/superpowers/plans/2026-11-17-rust-vsm-rewrite.md` Task 8.

## 1. Intent and why

The application is already a Rust binary, but the repository still requires a
Python 3.12 toolchain (pytest, requests, BeautifulSoup, redis, pylint,
autopep8, genbadge, `requirements*.txt`, `pyproject.toml`) to lint and to run
the black-box integration suite. The product owner wants the npm scripts to
use Rust equivalents and wants no Python references left in the code and
active documentation. Historical migration documents from 2026-11-17 are
deliberately preserved as history.

The runtime contract must not change. This is a tooling, test-harness, config
key, and documentation change only.

## 2. Goals

1. `package.json` scripts invoke Cargo/Docker/npm/Cypress only — no Python tool.
2. Reimplement the 11 pytest black-box HTTP tests as Rust integration tests
   that exercise the real stack (Redis, Keycloak, Vault, VSM).
3. Delete every Python executable, test, requirements, and project file.
4. Remove Python steps from CI and Python settings from the editor config.
5. Rename the `FLASK_SECRET` config key to `SESSION_SECRET` and drop the
   informational `FLASK_APP` key.
6. Bring `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, and `functional-spec.md`
   in line with the Rust system.

## 3. Non-goals

- Changing routes, status codes, cookies, redirects, templates, or Vault/OIDC
  behavior.
- Rewriting the Cypress E2E suite.
- Rewriting the historical 2026-11-17 design/plan documents (they keep their
  Python references and are marked historical).
- Adding coverage or JUnit reporting to CI gates.

## 4. Anti-goals

- A test harness that silently skips when the stack is absent. Integration
  tests are `#[ignore]`d and only run when explicitly requested; when run, a
  missing stack must fail loudly.
- Leaking test-only dependencies into the release binary.
- Breaking the config contract without documenting the rename.

## 5. Constraints

- Rust 1.88, axum 0.8, reqwest 0.12 (`default-features = false`, `json`,
  rustls). `reqwest`'s cookie-store feature is not enabled.
- The CI `rust` job has no service stack; the `integrationtests` job starts
  compose + terraform + the release binary.
- Keycloak uses the `development-always-good` flow (`auth-username-form` +
  `allow-access-authenticator`), so posting only `username=testuser` succeeds.
- The OIDC callback is issued for `http://vsm.local.kronus.network/...`; the
  test rewrites its scheme/host to `VSM_BASE_URL` before following it.
- Sessions expire by read-time comparison (`expires_at > now`). The server
  writes tokens with `SETEX` using the provider's remaining lifetime, but the
  test helper overwrites the key with a plain `SET`, clearing the outer TTL, so
  only read-time expiry can reject the session.

## 6. Approaches considered

### 6.1 Scope

- **A — `package.json` only:** replace Python commands, leave pytest suite and
  Python files. Rejected: the user chose repo-wide removal (B).
- **B — repo-wide Rust test harness + cleanup:** chosen.

### 6.2 Integration-test strategy

- **B1 — `tests/integration.rs` driving a running VSM over HTTP** (chosen):
  true black-box parity with the pytest suite, uses the real Keycloak/Vault/
  Redis/HAProxy topology, and fits the existing CI bootstrap.
- **B2 — in-process `tower::ServiceExt::oneshot`:** rejected. It would bypass
  Keycloak, Vault, and Redis and stop being a contract test.
- **B3 — shell/curl harness:** rejected. CSRF extraction, cookie handling, and
  JSON assertions become brittle.

### 6.3 Cookie handling inside the Rust tests

- **Manual cookie jar** (chosen): a small `TestSession` stores `Set-Cookie`
  name/value pairs and attaches a `Cookie` header per request. This can read
  the `session` value needed by the expiry helper and keeps the release binary
  unchanged.
- **`reqwest` `cookies` feature:** rejected. Its jar cannot be read back, so the
  expiry helper could not obtain the raw `session` value; a manual jar keeps the
  cookie visible. (Dev-dependency features do not affect `cargo build
  --release`, so that was not the reason.)

## 7. Design

### 7.1 Target `package.json` scripts

| Script | New command | Notes |
|---|---|---|
| `build` | `docker buildx build -t kr0nus/vsm:devel .` | unchanged (Rust image) |
| `lint` | `cargo fmt --check && cargo clippy --all-targets -- -D warnings` | replaces pylint/autopep8 |
| `license` | `cargo deny check licenses` | Rust equivalent of liccheck |
| `audit` | `cargo audit` | matches CI |
| `test` | `cargo test --test integration -- --ignored` | replaces pytest (integration semantics) |
| `test:unit` | `cargo test` | new; unit/doc tests |
| `coverage` | `cargo llvm-cov --html` | optional; requires `cargo install cargo-llvm-cov` + `llvm-tools-preview` |
| `setup` | `./test/presetup/setup.sh` | unchanged |
| `teardown` | `./test/presetup/cleanup.sh` | unchanged |
| `pretest` | `npm run teardown && npm run setup -- integration` | unchanged |
| `posttest` | `npm run teardown` | drops `genbadge` |
| `pree2e` | `npm run build && npm run teardown && npm run setup -- e2e` | unchanged |
| `e2e` | `cypress run --e2e --browser firefox` | unchanged |
| `poste2e` | `npm run teardown` | unchanged |

`npm test` keeps its old meaning (integration suite). Like the pytest era, it
expects VSM to be running at `VSM_BASE_URL` (default `http://localhost:3000`);
the stack is set up by `pretest`, the binary is started by the operator/CI.

### 7.2 Rust integration suite

New files:

```
tests/integration.rs        # all #[ignore]d black-box tests
tests/support/mod.rs        # TestSession, csrf_token, login/logout/expire helpers
```

New dev-dependencies in `Cargo.toml`:

- `scraper = "0.20"` — CSRF input and Keycloak form-action extraction.
- `percent-encoding = "2"` — decode the signed cookie before slicing the UUID.

Already available to tests: `reqwest`, `redis` (`tokio-comp`), `serde_json`,
`tokio`, `url`, `serde_urlencoded`, `tower`.

`TestSession` contract:

- `new(base: Option<Url>)`, `get(path)`, `post_form(path, &[(k, v)])`.
- `reqwest::redirect::Policy::none()` to mirror `allow_redirects=False`.
- `HashMap<String, String>` cookie jar; `cookie(name)` exposes the raw value.
  Parse `Set-Cookie` up to the first `;`, delete on `Max-Age=0` or an empty
  value (logout clears `session`), and keep a separate jar for the Keycloak
  `idp` session so its cookies survive the credential POST.
- Absolute URLs are used as-is; relative paths join against the base.
- Send form bodies with `serde_urlencoded` (already a dependency) and set
  `Content-Type: application/x-www-form-urlencoded`, avoiding any reqwest
  `form`-feature question.

Helpers ported 1:1 from the fixtures:

- `csrf_token(html)` → value of `<input name="csrf_token">`.
- `login(&mut session, &mut idp)` → the six-step flow in
  `test/fixtures/login.py`, including rewriting the callback host to the base.
- `logout(&mut session)` → POST `/auth/logout` with the remembered CSRF token.
- `expire_session(&mut session)` → percent-decode the raw `session` cookie,
  split at `.`, take chars 44..76 as the 32-hex UUID. `SignedCookieJar` prefixes
  the UUID with a 44-char base64 HMAC signature on the wire; server-side
  `cookie.value()` masks it, but the HTTP client sees the signed form. Then
  `GET` the JSON from `redis://127.0.0.1:6379/0`, set `expires_at` to now, and
  `SET` it back.

Tests to port (each `#[ignore = "requires the integration stack"]`):

| Test | Assertions |
|---|---|
| `index_lists_allowed_servers` | 200; `Logged in as: testuser`; download text; `myserver`/`2`/`3` present, `myserver4` absent |
| `index_expired_redirects_to_login` | GET `/` → 302, `Location: /auth/login` |
| `logout_when_anonymous_is_idempotent` | no `session` cookie; POST `/auth/logout` → 302, `Location: /` |
| `whoami_requires_login` | GET `/api/whoami` → 401 |
| `whoami_returns_user_and_servers` | 200; `testuser`, three servers present, `myserver4` absent |
| `whoami_expired_is_unauthorized` | 401 |
| `download_returns_ovpn` | 200; body contains `dev tun`; `Content-Disposition: attachment; filename="myserver.ovpn"` |
| `download_expired_is_unauthorized` | 401 |
| `download_anonymous_is_unauthorized` | 401 |
| `download_unknown_server_is_forbidden` | 403; `Content-Type: text/html…`; body contains `Forbidden` |
| `download_denied_server_is_forbidden` | 403; `Content-Type: text/html…`; body contains `Forbidden` |

### 7.3 CI changes (`.github/workflows/test-suite.yml`)

- `rust` job: keep steps; change clippy to `cargo clippy --all-targets -- -D
  warnings`; `cargo test` now compiles (and skips) the ignored integration
  target.
- `integrationtests` job: delete the `pyenv-action`, `pip install`, and
  `pytest-action` steps. After the existing build/start/readiness steps, run:
  `VSM_BASE_URL=http://localhost:3000 cargo test --test integration -- --ignored`.
- `e2etests` job: unchanged (Cypress only; no Python references).

### 7.4 Config key rename

Rename `FLASK_SECRET` → `SESSION_SECRET` and remove `FLASK_APP` in:

- `src/config.rs` — field `flask_secret` → `session_secret`, `required_string`
  key, length error text, and the `REFERENCE_APP` test fixture (also drop its
  `FLASK_APP` entry).
- `src/state.rs` — `signing_key(&state.config.session_secret)`.
- Every `AppConfig` literal in tests: `src/oidc.rs` (~319 and ~511),
  `src/web/api.rs`, `src/web/portal.rs`, `src/web/auth.rs` (including the
  `TEST_FLASK_SECRET` constants).
- Comments that name the key: `src/session.rs` (~42, ~297) and
  `src/web/auth.rs` (~349).
- `config/vsm/app.json`, `config/vsm-e2e/app.json` (drop `FLASK_APP`).
- `README.md`, `AGENTS.md`, `functional-spec.md` where the key is documented.

This is a deliberate breaking config change: deployed configs must rename the
key. A follow-up note will be added to `README.md`.

### 7.5 Files to delete

```
test/conftest.py
test/test_index.py
test/test_server.py
test/test_whoami.py
test/fixtures/__init__.py
test/fixtures/client.py
test/fixtures/expire_session.py
test/fixtures/login.py
test/fixtures/logout.py
test/__pycache__/           (untracked)
test/fixtures/__pycache__/  (untracked)
requirements.txt
requirements-dev.txt
pyproject.toml
coverage-badge.svg          (already deleted in worktree; confirm)
tests-badge.svg             (already deleted in worktree; confirm)
all.lst                     (stray untracked command output)
```

`.coveragerc` and `liccheck.ini` do not exist at this revision; nothing to do.

`test/presetup/` (shell + Terraform), `cypress/`, compose files, Dockerfile,
and `vault_create_role.sh` stay.

### 7.6 Active documentation

- **README.md** — remove the "Legacy notes" Python paragraph; document
  `npm run lint|license|audit|test|test:unit|coverage`; document the
  `FLASK_SECRET` → `SESSION_SECRET` rename; state that integration tests need a
  running VSM at `VSM_BASE_URL`.
- **CONTRIBUTING.md** — replace pylint/autopep8/pipenv guidance with
  `cargo fmt` / `cargo clippy` / `cargo test`.
- **AGENTS.md** — replace the Python verification targets with Rust commands;
  update runtime traps for `SESSION_SECRET`; state that the 2026-11-17
  documents are historical.
- **functional-spec.md** — rewrite it as an as-built description of the Rust
  system: source map (`src/*.rs`, `tests/integration.rs`), config table
  (`SESSION_SECRET`, no `FLASK_APP`), cookie/session behavior (signed 32-hex
  UUID), route behavior as implemented (e.g. 403 for unknown/denied downloads),
  dependency/CI section (Cargo, fmt/clippy/test/audit/deny), and verification
  targets (cargo + Cypress). Remove the Flask-era defect notes that no longer
  describe the binary.

The 2026-11-17 rewrite spec/plan and the 2026-11-18 cleanup docs are untouched
history.

### 7.7 Editor and ignore config

- `.vscode/settings.json` — replace Python linting/testing keys with
  `rust-analyzer` settings (e.g. `rust-analyzer.check.command: "clippy"`).
- `.gitignore` — drop Python artifact entries; ensure `vsm.log`, `target/`,
  `coverage/`, `*.tfstate`, `.terraform/`, `cypress/screenshots`, and
  `cypress/downloads` are ignored.

## 8. Risks and trade-offs

- **Config break:** renaming `FLASK_SECRET` will break an un-migrated deployment
  until its config is updated. Accepted by the product owner; documented in the
  README.
- **Test parity:** the Rust port must reproduce cookie parsing, CSRF
  extraction, and the callback rewrite exactly. Mitigation: helpers are ported
  line-for-line from the fixtures and reviewed against the originals.
- **CI-only coverage:** the integration suite cannot run in this workspace (no
  Keycloak/Vault/Redis stack), so local verification is limited to formatting,
  clippy, unit tests, compilation of the ignored target, and grep gates. The CI
  integration job is the real acceptance run.
- **Optional coverage script:** `cargo llvm-cov` is not installed by CI; the
  script is documented as optional and is not a gate.

## 9. Verification

1. `cargo fmt --check` passes.
2. `cargo clippy --all-targets -- -D warnings` passes.
3. `cargo test` passes (unit tests; integration tests compile and are ignored).
4. Plain `cargo test` compiles the integration target and skips its
   `#[ignore]`d tests. `cargo test --test integration -- --ignored` runs all 11
   tests and must fail loudly if the stack is absent.
5. `grep -riE 'python|pytest|pylint|autopep8|liccheck|pip |requirements\\.txt|pyproject|genbadge|flask'`
   over the repo returns only the historical 2026-11-17 design/plan docs and
   this design doc (both necessarily name the retired tools).
6. `npm run lint`, `npm run license`, `npm run audit` succeed where the tools
   are installed.
7. No `*.py`, `requirements*.txt`, `pyproject.toml`, `__pycache__`, or badge
   artifacts remain in the tree.

## 10. Decisions left to the builder

- Exact `scraper`/`percent-encoding` versions and any MSRV-compatible pinning;
  run `cargo deny check licenses` after they land and extend `deny.toml` if
  their licenses are not already allowed.
- Whether `coverage` stays in `package.json` (recommended: yes, optional).
- Whether `test` is aliased to `test:unit` instead of integration (recommended:
  keep integration semantics).
- Minor wording of the rewritten doc sections.
