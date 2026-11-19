# Design — Rust rewrite of VPN Server Manager (VSM)

- **Date:** 2026-11-17
- **Status:** Draft for owner approval
- **Supersedes for the rewrite:** none — `functional-spec.md` remains the as-built record of the Python app. Where this document changes behavior, the change is listed in §9.
- **External contract:** `CONTRACT.MD` at the repo root is normative for observable behavior; §9 mirrors its delta table.
- **Owner decisions:** Rust rewrite; statically linked binary in a `FROM scratch` image; memory safety; **full clean-up** of §8–9 defects (not byte-for-byte compatibility); implementation modifies the upstream VSM tree at SHA `8ea0424d5e0b95e9e4f693582e7e84900dba4de3` in place rather than starting greenfield.

## 1. Intent and why

Replace the Python/Flask VSM with a single statically linked Rust binary that can run in a `FROM scratch` container containing only the binary and the mounted runtime files. The product behavior stays: an authenticated user sees the VPN servers their IdP groups allow, and downloads a short-lived `.ovpn` profile backed by Vault-issued PKI.

The rewrite is the moment to fix the defects the as-built spec documents, because the current Python app ships known-correctness and cookie-hardening bugs and the owner has chosen correctness over drop-in compatibility.

Success looks like: the same login → portal → download journey works against the existing Keycloak/Redis/Vault/HAProxy stack; `docker history` shows a scratch image; the binary has no dynamic library dependencies; and the §11 acceptance checklist passes with the updated contract in §10.

**Working base:** the upstream repository at tree SHA `8ea0424d5e0b95e9e4f693582e7e84900dba4de3` is brought into the workspace first and edited in place. The Compose files, HAProxy configs, Terraform presetup, templates, `static/logo.png`, pytest suite and Cypress golden assertions therefore exist as real files; no reconstruction from prose is needed.

## 2. Goals

1. One static `x86_64-unknown-linux-musl` binary, no libc, OpenSSL, Python, or shell in the runtime image.
2. Preserve the product contract: OIDC Authorization Code + PKCE `S256` login, Redis-backed opaque session, group→server authorization, Vault JWT/KV/PKI orchestration, portal, `whoami`, `.ovpn` download.
3. Fix the §8–9 defects: well-formed JSON errors, idempotent logout, applied cookie flags, `403` for denied downloads, duplicate-mapping rejection, CSRF protection, metadata validation.
4. Keep the reference stack (Keycloak, Vault, Redis, HAProxy, Compose, Terraform) and keep the existing black-box verification suites usable.
5. Fail fast at startup on bad configuration; make every authorization and Vault call auditable in code.

## 3. Non-goals

- §13 roadmap: PGP/S-MIME profile encryption (#3), event windows (#53), mapping restructure for performance (#2), release-tag image builds (#6), dependency CVEs (#61–65). Treat these as separate change requests.
- Replacing or reconfiguring Keycloak, Vault, HAProxy, or Terraform.
- A metrics endpoint, distributed tracing backend, request IDs, or an audit trail (still absent, still out of scope).
- Horizontal scale-out design beyond "shared Redis + same cookie-signing key", which the current app already requires.
- Rewriting the test harness in Rust. See §9.

## 4. Anti-goals

These are failure modes, even if the app "works":

- A dynamically linked binary, or an image that needs `ca-certificates`, a shell, or `libgcc`/`libssl`.
- Silently reproducing the old bugs while claiming compatibility.
- A second service or sidecar to make the container work.
- Secrets, tokens, private keys, CA blobs, `server_tls_key`, or issued certificates in logs.
- Authorization decisions made anywhere except the single rule in §7.4.
- Any route that reaches Vault before the user is authorized.

## 5. Constraints

- **Static musl build.** Build natively on Alpine (`rust:1-alpine` + `build-base`/`musl-dev`) rather than cross-compiling; `ring` needs a C toolchain. Target `x86_64-unknown-linux-musl`. No `.cargo/config.toml` linker tricks needed on Alpine.
- **No system trust store in scratch.** TLS roots must be embedded at build time (`webpki-roots`) and optionally extended by a custom PEM. `CUSTOM_VAULT_CA` keeps the upstream inline-PEM form; a value that is not PEM is treated as a path to a mounted PEM file. If the issuer also needs custom trust, add a separate key. Do **not** rely on reqwest 0.13 defaults: it uses `rustls-platform-verifier`, which reads the system store and will fail in scratch. Build the client with an explicit root store (`tls_certs_only`).
- **Crypto provider.** Use rustls with the `ring` provider, not `aws-lc-rs`, to avoid cmake and keep musl builds simple. Cargo feature unification with `openidconnect`'s built-in reqwest client must be checked; fallback is to implement `AsyncHttpClient` over our configured client.
- **Config from files, at startup.** `config/vsm/app.json` and `config/vsm/vpn_group_mapping.json`, relative to CWD (app root, `/app` in the image). Missing/invalid config must abort with a clear error, never start half-configured.
- **Redis and Vault stay network dependencies.** Redis DB 0; token expiry is authoritative from the IdP `expires_at`.
- **No new required config keys.** Existing `app.json` keys keep their meaning. Binding stays `0.0.0.0:3000`.

## 6. Approaches considered

### A. Framework-heavy composition (rejected)

`axum` + `tower-sessions` + `axum-oidc` + off-the-shelf session middleware. Fastest to a login page, but session-cookie attributes become the framework's defaults, `axum-oidc` hides state/PKCE handling, and matching the cookie semantics in §7.2 means fighting the abstraction. Rejected: the contract is the product here.

### B. Thin explicit modules (chosen)

`axum` for routing only; `openidconnect` for OIDC; explicit `session`, `authz`, `vault`, `ovpn`, and `config` modules; `minijinja` for the existing Jinja-style templates. More first-party code, but every behavior in §7 is visible and unit-testable, and the static-binary constraints are easy to enforce.

### C. Keep Flask, compile with a wrapper (rejected)

Contradicts the owner's goal and cannot produce a scratch image.

**Chosen: B.** Owner picked the *behavior* stance (full clean-up); the technical shape follows from the static-binary constraint.

## 7. Design

### 7.1 Module layout

```
src/main.rs        bootstrap, tracing, router, serve
src/config.rs      AppConfig + Mapping, serde, startup validation
src/session.rs     cookie jar, Redis token store, expiry, TTL
src/oidc.rs        discovery, PKCE login, callback, userinfo
src/authz.rs       the single authorization rule
src/vault.rs       JWT login, KV v2 read, PKI issue
src/ovpn.rs        metadata validation + template rendering
src/web/           handlers: portal, auth, whoami, download
src/error.rs       error types and response mapping
templates/         base.html, index.html, template.ovpn, error.html
static/logo.png
```

Defaults for templates and the logo are embedded with `rust-embed` and overridden at startup if `templates/` or `static/` exist in the mounted directory. This keeps the scratch image at "binary + config" and preserves the operator override behavior in FR-11.

### 7.2 Configuration and startup

- Parse both JSON files with `serde`, then validate:
  - every required key present and non-empty;
  - `REDIS_PORT` parses as a port;
  - every mapping has all seven fields;
  - **no two mappings share a `vpn_server`** (full clean-up; the last-wins rule is removed);
  - `AUTH_ISSUER` parses as an absolute URL;
  - `FLASK_SECRET` is non-empty and at least 32 bytes (warn below, hard error in non-development).
- Log the trust-store source (embedded roots, plus custom CA path if configured), not a `certifi` path.
- Log every mapping at startup, as today.
- Build one `reqwest::Client` for Keycloak and one for Vault, both with the explicit root store and redirect policy disabled for the OIDC client (SSRF guidance from the crate).
- If `ENV == "development"`: enable debug-level tracing, use `http` redirect URIs, disable Vault TLS verification. Production never sees this branch.

### 7.3 Session and cookies

- Cookie name `session` (kept), containing a signed, opaque UUID only.
- Signing: HMAC-SHA256 via `axum-extra`'s signed cookie jar, key derived from `FLASK_SECRET`.
- Applied attributes:
  - `HttpOnly`;
  - `SameSite=Strict`;
  - `Secure` unless `ENV == "development"`;
  - `Path=/`;
  - `Domain=HOSTNAME` **only outside development** (so `localhost`/`127.0.0.1` tests keep working).
- Redis key `<uuid>` → JSON token record: `access_token`, `expires_at`, `userinfo`, `csrf_token`.
- **TTL added:** `SET <uuid> <json> EX <expires_at - now>`; read-time `expires_at` check remains. Expired keys are deleted on read.
- A session is valid only if the cookie carries a UUID, the Redis key exists, and `expires_at > now`.
- `GET /auth/login` stores pending state in Redis at `oidc:<random>` with a 10-minute TTL: `state`, `nonce`, PKCE verifier, and a post-login redirect target (`/`). A short-lived signed cookie carries the random id. This fixes the missing state/nonce validation.
- Callback verifies `state` in constant time, removes the pending record, exchanges the code with the PKCE verifier, verifies the ID token nonce, fetches userinfo, and creates or reuses the session UUID.
- Logout is idempotent: absent session is a no-op that still redirects; the session check runs before the CSRF check.

### 7.4 Authorization (single rule)

```rust
fn authorize<'a>(groups: &[String], server: &str, mappings: &'a [Mapping])
    -> Option<&'a Mapping>
```

A mapping matches when `mapping.vpn_server == server` and `groups.contains(&mapping.idp_group)` (case-sensitive, exact). Duplicate `vpn_server` values cannot exist after startup validation, so "last wins" is gone. All three call sites (portal list, `whoami`, download) use this function. Unknown and denied servers are indistinguishable to the caller.

### 7.5 OIDC

- `openidconnect` 4 `CoreClient`, discovery from `<AUTH_ISSUER>/.well-known/openid-configuration`.
- Scopes `openid email profile`; PKCE `S256`; nonce; state.
- Redirect URI is the absolute URL of the `auth` route: `http` in development, `https` otherwise.
- After token exchange, call the userinfo endpoint with the access token. Read `AUTH_USERNAME_FIELD` and `AUTH_GROUPS_FIELD` from the userinfo claims map. Missing groups claim is a configuration error (`500`), not an authorization denial.
- Discovery failure on `/auth/login` → `502`. Token-exchange failure, nonce mismatch, or userinfo failure on the callback → `401` login error page with no session created; details logged. "Provider returned no token" keeps `302 /`.
- Token record stores the access token (needed for Vault JWT login), `expires_at`, userinfo, and the CSRF token.

### 7.6 Vault

- Client: explicit root store = embedded webpki roots, merged with `CUSTOM_VAULT_CA` PEM when configured; TLS verification disabled only in development.
- `POST /v1/auth/{vault_jwt_path}/login` with `{ "role": ..., "jwt": <access_token> }`; use the returned `auth.client_token` for the next two calls.
- `GET /v1/{metadata_mountpoint}/data/{metadata_path}` (KV v2); accept `data.data` only.
- `POST /v1/{pki_mountpoint}/issue/client` with `{ "common_name": <username> }`; role name `client` comes from the path, as upstream.
- Validate the KV payload: all eight required keys present and non-empty. Reject CR/LF on scalar keys and unbalanced quotes in `server_dn`. `certificate_authority` and `server_tls_key` are legitimate multi-line PEM blobs: normalize CRLF→LF, require matching PEM markers, reject closing OVPN tags and directive-looking lines. This is the full-clean-up replacement for "inserted verbatim".
- Vault errors map to `502` with a generic body; details go to the log only.

### 7.7 Portal, `whoami`, download

- `GET /` renders `Logged in as: <username>`, heading `Download VPN Server Configuration`, and one form per authorized server.
- Download becomes `POST /api/servers/{server}` with a hidden CSRF token. A successful response is `200`, `Content-Type: text/plain`, `Content-Disposition: attachment; filename="<server>.ovpn"` (quoted, space removed).
- `GET /api/whoami` returns `{"username": "...", "vpn_servers": [...]}` as today.
- `POST /auth/logout` takes a CSRF token; `GET /auth/logout` returns `405`.
- Denied/unknown download is `403` with a small HTML error page; no Vault call, no redirect.
- Missing groups claim is `500` with a single well-formed JSON object on APIs and the error page on `/`.
- `templates/logout.html` is retired (it was never rendered).

### 7.8 Errors

One error enum maps deterministically to the matrix in §10. No handler builds JSON by string concatenation. `error-message` stays the key name for compatibility.

### 7.9 Observability

- `tracing` to stdout; human-readable in development, JSON outside.
- Info: startup config summary (no secrets), loaded mappings, successful portal render (username + groups), certificate issuance (username, server, not the key).
- Debug: `whoami` payload and non-secret Vault metadata only (`hostname`, `port`, `protocol`, `cipher`, `digest`, `server_dn`). Never CA blobs, `server_tls_key`, issued certificates/keys, tokens, or client tokens.
- Never log access tokens, JWTs, client tokens, private keys, or CSRF tokens.

### 7.10 Container and deployment

- Builder stage: `rust:1-alpine`, `apk add --no-cache build-base musl-dev`, `cargo build --release --target x86_64-unknown-linux-musl`.
- Runtime: `FROM scratch`; `COPY --from=build /app/target/x86_64-unknown-linux-musl/release/vsm /vsm`; `WORKDIR /app`; `USER 65532:65532`; `EXPOSE 3000`; `ENTRYPOINT ["/vsm"]`.
- No `/etc/passwd`, no CA bundle, no shell.
- Config, templates, and static overrides are mounted at runtime, exactly as today.
- Compose files keep Keycloak, Vault, Redis, and HAProxy; only the `vsm` service image and build change.
- A reproducible-build check (`docker history`, `ldd` on the binary) is part of acceptance.

## 8. Testing and verification

- **Rust unit tests:** config validation (including duplicate rejection), authorization truth table, OVPN rendering and metadata rejection, cookie attribute selection, error mapping.
- **Integration (kept Python/pytest, updated):** the existing suite is black-box HTTP, so it stays; assertions change for `403`, POST download with CSRF, POST logout, and quoted filenames. Python is a test-only dependency and is not in the runtime image.
- **E2E (Cypress):** update selectors to submit the portal forms and assert the `403` page; run in Chrome and Firefox as today.
- **Static checks:** `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo audit`, `cargo deny check licenses` (replaces `liccheck`).
- **Acceptance:** the functional-spec §11 checklist, with §10's contract changes applied.

## 9. Contract changes from the as-built app

| Area | As-built | Rewrite |
|---|---|---|
| Denied/unknown download | `302 /` | `403` error page |
| Logout | `GET`, errors when unauthenticated | `POST` + CSRF, idempotent; `GET` → `405` |
| Download | `GET` link | `POST` form + CSRF |
| Cookie flags | constants unused; Flask defaults | `HttpOnly`, `SameSite=Strict`, `Secure` outside dev, `Domain=HOSTNAME` outside dev |
| Missing groups error | doubled-quote, invalid JSON | single well-formed JSON object, same `500` |
| Duplicate mappings | last wins | startup rejection |
| Filename | `filename= <server>.ovpn` | `filename="<server>.ovpn"` |
| Vault metadata | inserted verbatim | required keys + CR/LF and quote validation |
| Redis expiry | no TTL, expired keys linger | TTL + delete on read |
| Vault/KV/PKI failure | unhandled exception → `500` | `502` generic, details logged |
| OIDC state/nonce | not validated | validated; pending state in Redis |
| Startup trust log | `certifi` path | embedded roots source (+ custom CA path) |

## 10. What is left to the builder

Obtaining the upstream tree at the pinned SHA, exact crate versions and lockfile, module-internal naming, error message wording, template markup, CI workflow structure, Terraform/compose edits, and the precise pytest/Cypress assertion updates. The builder may choose a custom `AsyncHttpClient` adapter if `openidconnect`'s reqwest feature fights the `ring`/root-store configuration. If `CUSTOM_VAULT_CA` needs to also cover the OIDC issuer, add a single `CUSTOM_CA` key rather than two mechanisms.

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Embedded roots go stale in a scratch image | Document rebuild cadence; allow a mounted CA to extend trust; log the trust source at startup |
| reqwest/openidconnect feature unification pulls `aws-lc-rs` | Pin features, verify with `cargo tree`; fall back to a custom `AsyncHttpClient` |
| CSRF/POST changes break scripted clients | Documented contract change; update tests in the same change |
| Static musl build fails on `ring` C/asm | Build natively on Alpine with `build-base`; no cross-compilation |
| Lost Python-era behavior not covered by tests | Port the §11 checklist into explicit acceptance tests before deleting compatibility shims |
