# Functional Specification — VPN Server Manager (`Kronus-Lab/vsm`)

## 0. Document control

| Field | Value |
|---|---|
| System | VPN Server Manager (VSM) — self-service short-lived OpenVPN configuration portal |
| Source of truth | This repository's Rust implementation; `CONTRACT.MD` is normative for observable behavior. |
| Spec type | As-built behavior of the compiled binary. Statements describe current source unless labeled "roadmap" or "open question". |
| Primary sources | `src/*.rs`, `src/web/*.rs`, `config/vsm/*`, `templates/*`, `static/*`, `tests/integration.rs`, `tests/support/mod.rs`, `cypress/e2e/vsm.cy.js`, `test/presetup/main.tf`, `Dockerfile`, `Cargo.toml`, `package.json`, compose files, `.github/workflows/test-suite.yml` |
| License | Apache-2.0 |

## 1. Purpose and scope

**Goal:** let an authenticated user visit a web portal, see only the VPN servers their IdP group membership permits, and download a freshly generated, short-lived `.ovpn` profile containing their own client certificate/private key.

**In scope:** web portal UI, OIDC login/session lifecycle, group→server authorization, Vault-backed config metadata and PKI certificate issuance, profile rendering and download, configuration file contracts, deployment topology, and the verification suite.

**Out of scope (current system):** managing VPN servers themselves, revocation UI, user administration, IdP administration, long-lived credentials, PGP/S-MIME protection, time-bounded event windows, rate limiting, download auditing, and profile encryption beyond TLS. CSRF protection is implemented (§8). These are recorded as roadmap items in §13.

## 2. System context and runtime topology

```
Browser ──HTTP(S)──> HAProxy (Host-header routing)
                       ├─ vsm.local.kronus.network ──> VSM Rust binary :3000
                       ├─ kc.local.kronus.network  ──> Keycloak :8080
                       └─ hcv.local.kronus.network ──> HashiCorp Vault :8200
VSM ──OIDC discovery/auth/code exchange + userinfo──> Keycloak
VSM ──token records + one-time pending logins──> Redis :6379 (DB 0)
VSM ──JWT auth + KV v2 read + PKI issue──> Vault
```

**End-to-end flow:**

1. User requests `/`; VSM redirects to `/auth/login` when there is no valid session.
2. `GET /auth/login` discovers the provider, creates a one-time pending login in Redis (`oidc:<state>`, 10-minute TTL) with `state`, `nonce`, and the PKCE verifier, sets a short-lived signed `oidc_pending` cookie, and redirects to the IdP with `state`, `nonce`, and the PKCE `S256` challenge.
3. IdP authenticates the user and redirects to `/auth/callback` with an authorization code and state.
4. The callback checks the signed `oidc_pending` cookie against `state` in constant time, atomically consumes the Redis record, exchanges the code with the PKCE verifier, verifies the ID token signature and nonce, reads userinfo, stores the token record in Redis under a 32-hex UUID with a TTL, sets the signed `session` cookie, and redirects to `/`.
5. On `/`, VSM reads the token from Redis, checks `expires_at`, extracts username and groups, resolves allowed servers, and renders one CSRF-protected POST form per allowed server.
6. On `POST /api/servers/<server>`, VSM validates the session and CSRF token, re-checks authorization, authenticates to Vault with the user's access token, reads server metadata from KV v2, issues a client certificate from the PKI mount, renders `template.ovpn`, and streams it as an attachment.
7. Logout deletes the Redis token and clears the cookie; no IdP end-session call is made.

## 3. Actors

| Actor | Responsibilities |
|---|---|
| End user | Authenticate via IdP, view allowed servers, submit download forms, log out. |
| VSM service | Session brokering, authorization decisions, Vault orchestration, profile rendering. |
| OIDC provider (Keycloak in reference stack) | Authenticate user, expose discovery document and userinfo, emit `groups` claim, sign ID tokens. |
| Redis | Hold token records keyed by opaque session UUID and one-time pending-login records. |
| Vault | Validate user JWT via configured JWT auth role; serve KV metadata; issue short-lived client certificates under a constrained policy. |
| Operator / deployer | Supply `app.json`, `vpn_group_mapping.json`, templates, TLS/routing, and IdP/Vault configuration. |

## 4. Configuration contracts

### 4.1 `config/vsm/app.json` (loaded at process start from a relative path)

| Key | Type | Purpose | Reference value |
|---|---|---|---|
| `SESSION_SECRET` | string | Secret expanded with HKDF-SHA256 into the cookie-signing key. Must be secret, stable across replicas, and at least 32 bytes outside development. | `itsasecret` (dev only) |
| `ENV` | `"development"` or other | Controls debug tracing, redirect URI scheme, Vault TLS verification, cookie `Secure`/`Domain`, and the minimum secret length. | `development` |
| `HOSTNAME` | string | Public hostname; callback URL host and cookie `Domain` outside development. | `vsm.local.kronus.network` |
| `REDIS_HOST`, `REDIS_PORT` | string, string | Redis endpoint (DB 0 hard-coded); the port must parse as `u16`. | `localhost`/`vsm-redis-1`, `6379` |
| `VAULT_URL` | string | Absolute Vault base URL with a host. | `http://hcv.local.kronus.network` |
| `CUSTOM_VAULT_CA` | optional string | Inline PEM certificate or path to a mounted PEM file; merged into the embedded root store for Vault only. | absent |
| `AUTH_ISSUER` | string | Absolute OIDC issuer URL; discovery at `<issuer>/.well-known/openid-configuration`. | `http://kc.local.kronus.network/realms/devel` |
| `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET` | string | Confidential OIDC client credentials. | `vsm`, `devel1234` |
| `AUTH_USERNAME_FIELD` | string | Key in token `userinfo` used as display name and certificate CN. | `preferred_username` |
| `AUTH_GROUPS_FIELD` | string | Key in token `userinfo` holding the groups list used for authorization. | `groups` |

Every key is required and non-empty except `CUSTOM_VAULT_CA`; a missing, empty, or wrong-typed value aborts startup. A short `SESSION_SECRET` is only a warning in development and a startup error otherwise.

### 4.2 `config/vsm/vpn_group_mapping.json` (list of objects)

| Field | Meaning |
|---|---|
| `vpn_server` | Server identifier used in URL `/api/servers/<vpn_server>` and in the UI. Must be unique. |
| `idp_group` | Exact group string from the `userinfo` groups claim that grants access. |
| `vault_metadata_mountpoint` | KV v2 mount holding connection metadata. |
| `vault_metadata_path` | Secret path inside that mount. |
| `vault_pki_mountpoint` | PKI mount; certificate is issued at `<mount>/issue/client`. |
| `vault_jwt_role` | Vault JWT auth role used with the user's access token. |
| `vault_jwt_path` | JWT auth backend mount path. |

All seven fields are required and non-empty; duplicate `vpn_server` values abort startup. Each accepted mapping is logged without secrets. Reference data maps `/example` → `myserver`, `myserver2`, `myserver3`; `/example2` → `myserver4`. The reference test user belongs only to `/example`.

### 4.3 Vault KV metadata payload (`data.data`)

Required keys: `hostname`, `port`, `protocol`, `server_dn`, `cipher`, `digest`, `certificate_authority`, `server_tls_key`. `port` may be a JSON number (reference value `1194`) and is normalized to a string; all other keys are strings.

Scalar keys (`hostname`, `port`, `protocol`, `server_dn`, `cipher`, `digest`) must be non-empty, free of CR/LF and OVPN tag strings, and `server_dn` must not contain unbalanced quotes. `certificate_authority` and `server_tls_key` are multi-line PEM blobs: CRLF is normalized to LF, matching PEM BEGIN/END markers are required, closing OVPN tags and directive-looking lines are rejected. Invalid metadata aborts the download as an upstream failure before rendering.

### 4.4 Vault reference configuration (Terraform in `test/presetup/main.tf`)

- Keycloak realm `devel` with a development "always good" browser flow, user `testuser` in group `example`, confidential client `vsm` with redirect URIs `http://vsm.local.kronus.network/*` and `http://localhost/*`, group-membership mapper emitting claim `groups`, and audience mapper for `vsm` in ID and access tokens.
- Vault JWT backend at `jwt`, role `test-role`, `user_claim=preferred_username`, `groups_claim=groups`, `bound_audiences=["vsm"]`, `bound_claims.groups` bound to the `example` group path, policy `develvpn`, default policy disabled.
- KV v2 mount `vpnmeta` with secret `develmeta` (max 2 versions).
- PKI mount `vpn/devel`, root CA 10 years, role `client` with `ttl=max_ttl=28800` (8 h), RSA 4096, client-only.
- Policy `develvpn` grants `create/update` on `vpn/devel/issue/client` and `read/list` on the metadata secret path.

## 5. Functional requirements

Each requirement carries implementation-independent acceptance criteria.

### FR-01 — Unauthenticated access control

- **Given** no valid session, **when** `GET /` is requested, **then** respond `302` with `Location: /auth/login`.
- **Given** no valid session, **when** `GET /api/whoami` is requested, **then** respond `401` with `{"error-message":"Not Authenticated"}`; **when** `POST /api/servers/<server>` is requested, **then** respond `401` with an empty body.
- A session is valid only if the signed `session` cookie carries a 32-hex UUID, Redis holds a token record under that UUID, and the record's `expires_at` is strictly greater than the current Unix time.

### FR-02 — Login initiation

- `GET /auth/login` must obtain provider metadata from `<AUTH_ISSUER>/.well-known/openid-configuration` (discovery failure is retained and answered as `502`); a local authorization request failure redirects `302 /`.
- The authorization request uses `AUTH_CLIENT_ID`, scopes `openid email profile`, PKCE challenge method `S256`, and a redirect URI equal to the absolute callback URL `<scheme>://<HOSTNAME>/auth/callback` — `http` when `ENV == "development"`, otherwise `https`.
- The random `state` doubles as the Redis key id: a pending record with `state`, `nonce`, and the PKCE verifier is stored at `oidc:<state>` with a 600-second TTL, and the same value is signed into a short-lived `oidc_pending` cookie.
- Acceptance: `Location` points at `<issuer>/protocol/openid-connect/auth?...` with the expected client, redirect, `state`, `nonce`, and PKCE parameters, and both the pending record and cookie exist.

### FR-03 — Callback and session establishment

- `GET /auth/callback` reads `state` and `code`. It requires the signed `oidc_pending` cookie to match `state` in constant time and atomically consumes the one-time Redis record (`GETDEL`); a missing or mismatched value is a `401` error page with no session created.
- With a valid pending record and code, it exchanges the code using the PKCE verifier, requires an ID token, verifies its signature and nonce, and reads userinfo. Missing username/groups fields in userinfo or any upstream failure is a `401` error page with no session created.
- On success: generate a fresh 32-character lowercase hex UUID, store the token record (`access_token`, `expires_at`, `userinfo`, `csrf_token`) in Redis at key `<uuid>` with TTL `ceil(expires_at - now)` (minimum 1 second), set the signed `session` cookie, clear the `oidc_pending` cookie and Redis record, and redirect `302` to `/`.
- If the provider returns no authorization code, do not create session state, but still redirect to `/` (which will then redirect to login).
- Acceptance: after callback, a signed `session` cookie exists, Redis contains the token, and `GET /` returns `200`.

### FR-04 — Session validation and expiry

- Every protected route resolves the session through the same rules: signed cookie → UUID → Redis record → strict `expires_at > now`.
- Redis token records are written with a TTL derived from the provider lifetime, and a record whose `expires_at` has passed is rejected and deleted on read. Pending logins are one-time records with a 10-minute TTL.
- Acceptance: rewriting the stored record's `expires_at` to the current time causes `/` to redirect to `/auth/login`, and both APIs to return `401` (covered by the `expire_session` integration helper).

### FR-05 — Logout

- `GET /auth/logout` responds `405` with `Allow: POST` and performs no state change.
- `POST /auth/logout` reads a form-encoded `csrf_token`. With a valid session it compares the token in constant time, deletes the Redis token, clears the cookie, and redirects `302` to `/`.
- An anonymous POST (or one with no Redis record) is idempotent: it skips the CSRF check and returns `302 /`. An invalid CSRF token on an authenticated session is `403`. No IdP end-session call is made.
- Acceptance: after logout, `GET /` redirects to login and both APIs return `401`; logging out twice still returns `302 /`.

### FR-06 — Authenticated portal view

- `GET /` when authenticated must:
  1. Extract the username from `userinfo[AUTH_USERNAME_FIELD]`.
  2. Extract the groups list from `userinfo[AUTH_GROUPS_FIELD]`; if either is missing, return a `500` error page.
  3. Compute the authorized server list (FR-08).
  4. Render the portal template showing `Logged in as: <username>`, the heading `Download VPN Server Configuration`, a logout form, and one `<form method="post" action="/api/servers/<server>">` per authorized server with a hidden `csrf_token` field.
  5. Log an info-level event containing username and groups; never log the CSRF value or token material.
- Acceptance: with the reference mapping, `myserver`, `myserver2`, `myserver3` appear and `myserver4` does not.

### FR-07 — Identity API

- `GET /api/whoami` on a valid session returns `200`, `Content-Type: application/json`, body `{"username": "<username>", "vpn_servers": ["...", ...]}`.
- Missing username or groups claim → `500` with a well-formed `{"error-message": ...}` body; unauthenticated → `401` with `{"error-message":"Not Authenticated"}`.
- Acceptance: both the integration suite and Cypress assert `username == "testuser"` and the three allowed servers, excluding `myserver4`.

### FR-08 — Group-to-server authorization

- A server is authorized if **any** mapping has both `idp_group` present in the user's groups list and `vpn_server` equal to the requested server. Group comparison is case-sensitive exact string match.
- The same rule drives the UI list, `whoami`, and downloads. Duplicate `vpn_server` values are rejected at startup, so at most one mapping can match; there is no last-match resolution.
- Unknown server or server outside the user's groups returns `403` with the HTML error page, indistinguishable from a denied server, and never touches Vault.
- Acceptance: `myserver4` and an arbitrary unknown name both return `403` for a `/example` user with no Vault request.

### FR-09 — VPN configuration download

- `POST /api/servers/<server>` with a valid session, matching form `csrf_token`, and an authorized server must, in order:
  1. Authenticate to Vault via JWT auth at `v1/auth/<vault_jwt_path>/login` with `{"role": <vault_jwt_role>, "jwt": <access_token>}`.
  2. Read KV v2 metadata at `v1/<metadata_mountpoint>/data/<metadata_path>` using `data.data` and validate it (§4.3).
  3. Issue a certificate at `v1/<pki_mountpoint>/issue/client` with `common_name = username` (from `AUTH_USERNAME_FIELD`); the TTL comes from the Vault role.
  4. Render `template.ovpn` with validated metadata plus the issued `certificate` and `private_key`.
  5. Return `200`, `Content-Type: text/plain`, and `Content-Disposition: attachment; filename="<server>.ovpn"` with quotes/backslashes escaped.
- Vault TLS verification is enabled unless `ENV == "development"`; optional `CUSTOM_VAULT_CA` is merged into the embedded root store, and the CA value is never logged.
- Failure statuses: `401` (empty body) unauthenticated, `403` bad CSRF or denied/unknown server (HTML), `500` missing username/groups claim (well-formed JSON), `502` Vault/metadata failure (generic HTML, details only in logs). Authorization and CSRF run before any Vault call.
- Acceptance: downloaded file contains `dev tun`, correct `remote`, `cipher`, `auth`, `verify-x509-name`, CA/cert/key/tls-crypt blocks with a real issued certificate and private key, and the quoted attachment filename header.

### FR-10 — OVPN profile rendering

Template `templates/template.ovpn` is a fixed directive set:

```
dev tun
persist-tun
persist-key
cipher {{cipher}}
auth {{digest}}
client
resolv-retry infinite
remote {{hostname}} {{port}} {{protocol}}
lport 0
verify-x509-name "{{server_dn}}" subject
remote-cert-tls server
<ca> … certificate_authority … </ca>
<cert> … certificate … </cert>
<key> … certificate_key … </key>
<tls-crypt> … server_tls_key … </tls-crypt>
```

- `.ovpn` templates are not HTML-escaped; metadata is validated (§4.3) before insertion, and `common_name` is the only request-derived certificate input.
- Acceptance: Cypress golden assertions on the downloaded `myserver.ovpn` must pass in both Chrome and Firefox.

### FR-11 — Configuration loading and operator extensibility

- Both JSON files are read from relative paths (`config/vsm/app.json`, `config/vsm/vpn_group_mapping.json`) at process start; the working directory must be the application root (`/app` in the container).
- Startup logs the trust-source status, a config summary without secrets, and every mapping.
- Templates and static assets are embedded in the binary at compile time; a mounted `templates/` or `static/` directory at the application root takes precedence. Config is mounted at `/app/config/vsm` in the image; nothing is baked into the runtime image.
- Adding a server requires one mapping entry plus matching Vault metadata/PKI setup; no code change.

### FR-12 — Deployment and environment behavior

- Container: `npm run build` (`scripts/build-image.sh`) compiles a static musl binary in a pinned `rust:1-alpine` builder container into `dist/vsm`; the image is `FROM scratch` packaging only (context: just `dist/vsm`), numeric user `65532:65532`, `WORKDIR /app`, `EXPOSE 3000`, `ENTRYPOINT ["/vsm"]`, listening on `0.0.0.0:3000`. No shell, CA bundle, or `/etc/passwd` in the runtime image.
- Compose layers: `docker-compose-common.yml` (Vault dev mode with root token `admin`, Keycloak `start-dev` admin/admin, Redis published on 6379) plus either `docker-compose-e2e.yml` (VSM + HAProxy with port 80 published) or `docker-compose-integration.yml` (HAProxy only; the release binary runs on the host).
- HAProxy routes by `Host` header; development aliases are the three `*.local.kronus.network` names. Only the e2e config includes a `vsm` backend.
- `ENV == "development"` enables debug tracing, HTTP redirect URIs, and disabled Vault TLS verification, and omits cookie `Secure`/`Domain`; never use it in production.

### FR-13 — Observability

- Startup: logs the TLS trust source (embedded roots, optionally plus a custom CA) without ever printing the CA value, a config summary of non-secret fields, and each loaded mapping.
- Runtime: info log on successful portal rendering (username + groups), debug log of the `whoami` payload, debug log of non-secret Vault metadata fields, info log after issuing a profile, and debug-level OIDC/Vault failure markers.
- Tokens, JWTs, state, nonces, PKCE verifiers, CSRF values, CA blobs, TLS crypt keys, and private keys are not logged. No structured log schema, request IDs, metrics endpoint, or audit trail exists.

### FR-14 — Verification

The implementation must satisfy three automated layers:

1. **Static** (`.github/workflows/test-suite.yml`, also `npm run lint`): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo audit`, `cargo deny check licenses`. `cargo audit` ignores only `RUSTSEC-2023-0071` per `.cargo/audit.toml`; `deny.toml` holds the license allowlist.
2. **Integration** (`tests/integration.rs` + `tests/support/mod.rs`): 12 black-box HTTP tests marked `#[ignore = "requires the integration stack"]`, driven by `cargo test --test integration -- --ignored` with `VSM_BASE_URL` (default `http://localhost:3000`). They cover login/logout, portal contents, `whoami`, valid `.ovpn` download, expiry (by rewriting Redis `expires_at`), `401` without a session, and `403` for unknown/denied servers.
3. **E2E** (`cypress/e2e/vsm.cy.js`): login success with downloaded-file assertions, bad username, unauthenticated API, unknown server, whoami; executed in Chrome and Firefox with an SBOM generated for the image. Delete `cypress/screenshots` and `cypress/downloads` between runs.
- Test infrastructure is provisioned by `terraform apply --auto-approve` in `test/presetup`; helper scripts `wait.sh`, `setup.sh`, and `cleanup.sh` orchestrate readiness and teardown, and `package.json` wires them into `pretest`/`posttest` and `pree2e`/`poste2e`.

## 6. External interface summary

| Method | Path | Auth | Success | Failure |
|---|---|---|---|---|
| GET | `/` | Session | `200` HTML portal | `302 /auth/login` |
| GET | `/auth/login` | none | `302` IdP authorize URL | `502` on discovery failure |
| GET | `/auth/callback` | `code`+`state`+pending cookie | stores token, `302 /` | `401` error page on invalid state/code/token/userinfo; `302 /` without code |
| GET | `/auth/logout` | none | — | `405`, `Allow: POST` |
| POST | `/auth/logout` | Session + CSRF | deletes token, `302 /`; anonymous is idempotent | `403` bad CSRF |
| GET | `/api/whoami` | Session | `200` JSON identity | `401`, or `500` well-formed JSON |
| POST | `/api/servers/<server>` | Session + CSRF + group | `200` `.ovpn` attachment | `401`, `403`, `500`, or `502` |
| GET | `/static/{*path}` | none | `200` asset bytes | `404` for missing or traversal paths |

## 7. State and data model

- **Browser cookies:** `session`, signed and containing only the 32-char lowercase hex UUID; `oidc_pending`, signed and short-lived, containing the random pending-login id.
- **Redis DB 0:** key `<uuid>` → JSON token record with `access_token`, `expires_at`, `userinfo`, and `csrf_token`, written with a TTL derived from the provider lifetime; key `oidc:<state>` → JSON record with `state`, `nonce`, and `pkce_verifier`, TTL 600 seconds, consumed once via `GETDEL`.
- **Derived state:** authorized server list (group ∩ mapping), validated Vault metadata, issued certificate, and rendered OVPN (metadata ∪ issued certificate).
- **Session lifetime:** bounded by the provider token's `expires_at` and checked at read time; there is no sliding renewal or refresh-token use. Expired records are deleted on read, and logout deletes the record explicitly.

## 8. Security requirements (as-built and intended)

| Requirement | Status |
|---|---|
| Authorization Code flow with PKCE `S256`, `state`, and `nonce` | Implemented; state and nonce verified |
| Confidential client with secret from config | Implemented |
| Signed `session` and `oidc_pending` cookies; opaque UUID only, no token in browser | Implemented |
| Cookie flags `HttpOnly`, `SameSite=Strict`, `Path=/`, plus `Secure` and `Domain=HOSTNAME` outside development | Implemented |
| CSRF protection on state-changing POSTs using a per-session token stored in Redis and compared in constant time | Implemented |
| Duplicate `vpn_server` rejection and fail-fast config validation | Implemented |
| Vault least privilege (JWT role bound to audience/groups; policy limited to one issue path + one secret path) | Implemented in reference Terraform |
| Vault metadata validation before template insertion | Implemented |
| TLS verification toward Vault outside development; embedded roots plus optional mounted CA | Implemented |
| Development bypasses TLS verification, uses HTTP redirect URIs, enables debug | Implemented — must never be enabled in production |
| Rate limiting, download auditing, profile encryption at rest/in transit beyond TLS | Not implemented (see §13) |

## 9. Error handling matrix (normative for compatibility)

| Condition | Route | Response |
|---|---|---|
| No/expired/missing session | `/` | `302 /auth/login` |
| No/expired/missing session | `/api/whoami` | `401 {"error-message":"Not Authenticated"}` |
| No/expired/missing session | `POST /api/servers/<s>` | `401` empty body |
| No session | `POST /auth/logout` | `302 /` (idempotent, no CSRF check) |
| Any method other than POST | `/auth/logout` | `405` with `Allow: POST` |
| Bad/expired OIDC `state`, token exchange, nonce, or userinfo failure | `/auth/callback` | `401` HTML error page, no session |
| Provider returned no code | `/auth/callback` | `302 /`, no session |
| Discovery failure | `/auth/login` | `502` HTML error page |
| Missing username or groups claim | `/`, APIs | `500` (HTML page on `/`, single well-formed JSON object on APIs) |
| Unknown/denied server | `POST /api/servers/<s>` | `403` HTML error page, no Vault call |
| Bad CSRF token | state-changing POST | `403`, route-appropriate error representation |
| Vault/KV/PKI failure or invalid metadata | `POST /api/servers/<s>` | `502` generic HTML error page; details only in logs |

## 10. Nonfunctional requirements

- Rust `1.88` per `rust-toolchain.toml`, edition 2021; tokio + axum HTTP stack, openidconnect 4 with reqwest/rustls (ring, embedded webpki roots), minijinja templates, rust-embed for compile-time assets, redis async client.
- Static `x86_64-unknown-linux-musl` binary in a `FROM scratch` image; no dynamic dependencies and no CA bundle at runtime. Config and overrides are mounted, never baked in.
- Single process; horizontal replicas need only shared Redis and a shared `SESSION_SECRET`.
- Bootstrap dependency order: Redis, Keycloak, Vault → Terraform provisioning → VSM readiness → tests.
- Templates and static assets are overridable by volume mount; license allowlist in `deny.toml`, advisory exception in `.cargo/audit.toml`.

## 11. Acceptance checklist for an agent team

- [ ] Unauthenticated user cannot see server names or obtain a profile (`401`/`302` as specified).
- [ ] Login uses discovery, PKCE, state, and nonce; callback creates signed cookies, a one-time pending record, and a Redis token record.
- [ ] Expiring the Redis record makes all protected routes reject the user.
- [ ] Portal and `whoami` list exactly the servers implied by group mappings.
- [ ] Downloading a mapped server requires a CSRF token and yields a valid OpenVPN profile with a freshly issued, short-lived client cert whose CN is the username.
- [ ] Unknown and unauthorized servers return `403`, never touch Vault, and are indistinguishable.
- [ ] Logout removes the Redis entry and the cookie; re-login works; anonymous logout is idempotent.
- [ ] All config keys and mapping fields are consumed from files, not hard-coded; duplicates and invalid values abort startup.
- [ ] Rust static checks, the Rust integration suite, and Cypress in both browsers pass in CI.

## 12. Open questions for the product owner

1. **Spec baseline — open:** this file is descriptive; `CONTRACT.MD` is normative for observable behavior and §12 there is the complete change list. Confirm that split remains intended.
2. **Cookie hardening — resolved:** hardened cookie attributes are implemented (§8); no decision pending.
3. **Mapping conflicts — resolved:** duplicate `vpn_server` values are rejected at startup (§4.2); no last-wins behavior remains.
4. **Unauthorized download status — resolved:** `403` with an HTML error page and no Vault call (§9); the old redirect is gone.
5. **File location — open:** where this spec and `CONTRACT.MD` should live long-term (repository docs, wiki, or another location).

## 13. Explicitly out of scope / roadmap (from open GitHub issues)

- **#3** PGP/S-MIME encryption of the downloaded profile to protect against TLS-inspecting proxies/MitM.
- **#53** Event start/end/config-availability windows with certificate TTL capped to event end and Vault `max_ttl`.
- **#2** Restructure mappings into `server → config` dictionaries to avoid the linear scan (performance/clarity).
- **#6** Release-tag-based container builds in addition to the daily `devel` build.

These are **not** requirements of the as-built system; treat them as separate change requests with their own acceptance criteria. Dependency advisories and licenses are handled by `cargo audit` and `cargo deny check licenses` in CI.

## 14. Suggested agent work packages (ordered)

| WP | Scope | Depends on |
|---|---|---|
| WP1 | Config contracts, environment switching, secure session cookie setup, startup validation | — |
| WP2 | OIDC login/callback/logout + Redis session layer, including one-time pending logins | WP1 |
| WP3 | Authorization mapping and identity API (`whoami`) | WP2 |
| WP4 | Portal UI templates and static assets with CSRF forms | WP3 |
| WP5 | Vault JWT/KV/PKI integration, metadata validation, and OVPN rendering | WP1, WP3 |
| WP6 | Docker/Compose/HAProxy/Terraform reference stack | WP1–WP5 |
| WP7 | Rust integration suite + Cypress E2E + CI | WP2–WP6 |
| WP8 | Roadmap items (§13) after owner decisions | All |

## 15. Source map for the implementing agents

| Concern | Files |
|---|---|
| Application logic | `src/main.rs`, `src/config.rs`, `src/authz.rs`, `src/oidc.rs`, `src/session.rs`, `src/state.rs`, `src/error.rs`, `src/vault.rs`, `src/ovpn.rs` |
| Web handlers | `src/web/mod.rs`, `src/web/auth.rs`, `src/web/portal.rs`, `src/web/api.rs`, `src/web/static_files.rs` |
| Configuration | `config/vsm/app.json`, `config/vsm/vpn_group_mapping.json`, `config/vsm-e2e/*` |
| UI/profile templates | `templates/base.html`, `templates/index.html`, `templates/error.html`, `templates/template.ovpn`, `static/logo.png` |
| Tests | `tests/integration.rs`, `tests/support/mod.rs`, `cypress/e2e/vsm.cy.js` |
| Reference infrastructure | `test/presetup/main.tf`, `test/presetup/{setup,cleanup,wait}.sh`, `vault_create_role.sh`, `docker-compose-*.yml`, `config/haproxy-*/haproxy.cfg`, `automation/vault.tf` |
| Build/CI | `Dockerfile`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `.cargo/audit.toml`, `package.json`, `.github/workflows/test-suite.yml`, `.github/workflows/docker-daily.yml` |
| Product docs | `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `CONTRACT.MD`, `diagram.drawio` |
