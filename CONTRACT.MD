# CONTRACT — VPN Server Manager (Rust rewrite)

- **Status:** Normative for observable behavior of the Rust implementation.
- **Baseline:** `functional-spec.md`, the as-built description of `Kronus-Lab/vsm` at tree `8ea0424d5e0b95e9e4f693582e7e84900dba4de3`.
- **Architecture:** `docs/superpowers/specs/2026-11-17-rust-rewrite-design.md`.
- **Precedence:** where these documents disagree, this file wins for observable behavior. The delta in §12 is the complete list of intentional behavior changes from the baseline.
- **Owner decisions:** rewrite in Rust; one statically linked binary in a `FROM scratch` image; rely on Rust memory safety; **full clean-up** of the §8–9 defects rather than byte-for-byte compatibility; implement by editing the upstream tree at SHA `8ea0424d5e0b95e9e4f693582e7e84900dba4de3` in place.

## 1. System contract

```
Browser ──HTTP(S)──> HAProxy (Host routing)
                       ├─ vsm.local.kronus.network ──> VSM :3000
                       ├─ kc.local.kronus.network  ──> Keycloak :8080
                       └─ hcv.local.kronus.network ──> Vault :8200
VSM ──OIDC discovery / auth / token / userinfo──> Keycloak
VSM ──session + pending-login state──> Redis :6379 (DB 0)
VSM ──JWT auth + KV v2 read + PKI issue──> Vault
```

End-to-end flow:

1. `GET /` without a valid session → `302 /auth/login`.
2. `GET /auth/login` discovers the provider and creates a pending login record in Redis; redirects to the IdP with `state`, `nonce`, and PKCE `S256` challenge.
3. IdP authenticates and returns to `/auth/callback?code=...&state=...`.
4. Callback verifies `state`, exchanges the code with the PKCE verifier, verifies the ID token nonce, fetches userinfo, stores the token record in Redis under a fresh 32-hex UUID, and sets the signed session cookie.
5. `GET /` reads the token, evaluates authorization, renders the portal with one download form per allowed server, and embeds a per-session CSRF token.
6. `POST /api/servers/{server}` re-checks the session and CSRF token, evaluates authorization, authenticates to Vault with the access token, reads metadata, issues a certificate, renders the profile, and streams it as an attachment.
7. `POST /auth/logout` deletes the Redis token and clears the cookie. No IdP end-session call is made.

## 2. Configuration contract

### 2.1 `config/vsm/app.json`

Loaded once at process start from a path relative to the working directory (`/app` in the image). No baked-in defaults for secrets.

| Key | Type | Meaning |
|---|---|---|
| `SESSION_SECRET` | string | Cookie-signing secret; stable across replicas. >= 32 bytes outside development. |
| `ENV` | `"development"` or other | Selects debug logging, HTTP redirect URI, Vault TLS verification, cookie `Secure`/`Domain`. Never use `development` in production. |
| `HOSTNAME` | string | Public hostname; used as cookie `Domain` outside development. |
| `REDIS_HOST`, `REDIS_PORT` | string, string/int | Redis endpoint, DB 0 hard-coded. |
| `VAULT_URL` | string | Vault base URL. |
| `CUSTOM_VAULT_CA` | optional string/path | Extra PEM CA merged into the embedded root store for Vault. |
| `AUTH_ISSUER` | string | OIDC issuer; discovery at `<issuer>/.well-known/openid-configuration`. |
| `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET` | string | Confidential OIDC client credentials. |
| `AUTH_USERNAME_FIELD` | string | Userinfo claim used as display name and certificate CN. |
| `AUTH_GROUPS_FIELD` | string | Userinfo claim holding the groups list. |

### 2.2 `config/vsm/vpn_group_mapping.json`

List of objects; each field is required.

| Field | Meaning |
|---|---|
| `vpn_server` | Identifier in `/api/servers/{vpn_server}` and the portal. Must be unique. |
| `idp_group` | Exact group string from the userinfo claim that grants access. |
| `vault_metadata_mountpoint` | KV v2 mount holding connection metadata. |
| `vault_metadata_path` | Secret path in that mount. |
| `vault_pki_mountpoint` | PKI mount; issue at `<mount>/issue/client`. |
| `vault_jwt_role` | Vault JWT auth role. |
| `vault_jwt_path` | JWT auth mount path. |

### 2.3 Startup validation (fail fast)

- every required key present and non-empty; `REDIS_PORT` parses as a port; `AUTH_ISSUER` is an absolute URL;
- every mapping has all seven fields;
- **no two mappings share a `vpn_server`** — startup aborts on a duplicate;
- `SESSION_SECRET` non-empty; >= 32 bytes outside development;
- every loaded mapping is logged (without secrets).

Adding a VPN server requires one mapping plus matching Vault metadata/PKI; no code change.

### 2.4 Environment behavior

| Aspect | `ENV == "development"` | Otherwise |
|---|---|---|
| Tracing | debug level, human readable | info level, JSON |
| Redirect URI scheme | `http` | `https` |
| Vault TLS verification | disabled | enabled |
| Cookie `Secure` | absent | present |
| Cookie `Domain` | absent (host-only) | `HOSTNAME` |

### 2.5 Vault KV metadata payload (`data.data`)

Required, non-empty keys: `hostname`, `port`, `protocol`, `server_dn`, `cipher`, `digest`, `certificate_authority`, `server_tls_key`. `port` may be a JSON number (the reference OpenTofu configuration sets `1194`); all others are strings and `port` is normalized to a string for rendering.

- Scalar keys (`hostname`, `port`, `protocol`, `server_dn`, `cipher`, `digest`) must not contain CR/LF; `server_dn` must not contain unbalanced quotes.
- `certificate_authority` and `server_tls_key` are multi-line PEM blobs: CRLF is normalized to LF, matching PEM BEGIN/END markers are required, and closing OVPN tags (`</ca>`, `</cert>`, `</key>`, `</tls-crypt>`) or lines starting with an OVPN directive are rejected.

Invalid metadata is rejected before rendering. The multi-line exemption applies only to those two PEM keys.

## 3. HTTP contract

### 3.1 General conventions

- Error bodies for API routes: a single JSON object `{"error-message":"<text>"}`, `Content-Type: application/json`. No string-built/doubled-quote JSON.
- Error bodies for browser routes (`/`, POST download, POST logout): small HTML page, `Content-Type: text/html; charset=utf-8`.
- CSRF failure on a state-changing POST: `403` using that route's error representation.
- An anonymous `POST /auth/logout` is not an error: it returns `302 /` and skips the CSRF check.
- Unauthenticated download keeps the empty-body `401` for compatibility.
- No route returns a redirect for an authorization denial.

### 3.2 Endpoint summary

| Method | Path | Auth | Success | Failure |
|---|---|---|---|---|
| GET | `/` | Session | `200` HTML portal | `302 /auth/login` |
| GET | `/auth/login` | none | `302` IdP authorize URL | `502` on discovery failure |
| GET | `/auth/callback` | `code`+`state` | stores token, `302 /` | `401` invalid state/exchange/nonce/userinfo; `302 /` if provider returned no token |
| GET | `/auth/logout` | none | — | `405`, `Allow: POST` |
| POST | `/auth/logout` | Session + CSRF | deletes token, `302 /`; idempotent | `403` bad CSRF; no session → `302 /` |
| GET | `/api/whoami` | Session | `200` JSON identity | `401`; `500` missing groups claim |
| POST | `/api/servers/{server}` | Session + CSRF + group | `200` `.ovpn` attachment | `401`; `403` denied/unknown; `403` bad CSRF; `500` missing groups; `502` Vault failure |

### 3.3 Endpoint details

**`GET /`** — Valid session: `200`, renders `Logged in as: <username>`, heading `Download VPN Server Configuration`, and one `<form method="post" action="/api/servers/{server}">` per authorized server, each with a hidden `csrf_token` field. Also renders a logout form. Info-log username and groups. Missing groups claim → `500` error page.

**`GET /auth/login`** — Discovers `<AUTH_ISSUER>/.well-known/openid-configuration`; creates a Redis pending-login record with a 10-minute TTL containing `state`, `nonce`, PKCE verifier, and return target; sets a short-lived signed cookie carrying the record id; redirects to `<issuer>/protocol/openid-connect/auth?...`. Authorization request uses `AUTH_CLIENT_ID`, scopes `openid email profile`, `code_verifier`/PKCE `S256`, and redirect URI equal to the absolute URL of the callback route (`http` in development, else `https`).

**`GET /auth/callback`** — Reads `code` and `state`. Verify `state` against the pending record in constant time; mismatch/expiry → `401` login error page, no session created. Token-exchange failure, nonce mismatch, or userinfo failure → the same `401` error page, no session created, details logged. If the provider returns no token at all → `302 /` with no session state. On success, exchange code with PKCE verifier; verify ID token nonce; fetch userinfo. Store token record in Redis under `uuid4`-equivalent 32-char lowercase hex UUID (reuse an existing UUID if the session already has one), set `session["user"]`, redirect `302 /`.

**`GET /auth/logout`** — `405` with `Allow: POST`. No state change.

**`POST /auth/logout`** — Form-encoded `csrf_token`. Valid session + CSRF: delete the Redis token, clear the cookie, `302 /`. No session: still `302 /` (idempotent). Invalid CSRF: `403`. Does not call the IdP end-session endpoint.

**`GET /api/whoami`** — Valid session: `200 application/json`, body `{"username":"<username>","vpn_servers":["..."]}`, listing exactly the authorized servers. Unauthenticated: `401 {"error-message":"Not Authenticated"}`. Missing groups claim: `500` well-formed JSON with the misconfiguration message.

**`POST /api/servers/{server}`** — Form-encoded `csrf_token`. Valid session + CSRF + authorization: `200`, `Content-Type: text/plain`, `Content-Disposition: attachment; filename="<server>.ovpn"`. Unauthenticated: `401`, empty body. Denied or unknown server: `403` error page, and **no Vault call**. Missing groups claim: `500`. Vault failure: `502` generic error page, details logged only.

## 4. Session and state contract

- **Cookie:** name `session`; signed with HMAC-SHA256 keyed by a key derived from `SESSION_SECRET` (HKDF-SHA256); contains only a 32-char lowercase hex UUID. Attributes: `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` outside development, `Domain=HOSTNAME` outside development. No token material in the browser.
- **Token record:** Redis key `<uuid>` → JSON with `access_token`, `expires_at`, `userinfo`, `csrf_token`. No long-lived token in the cookie.
- **Expiry:** a session is valid only if the cookie has a UUID, Redis holds the key, and `expires_at > now` (strict). The record is stored with `EX = expires_at - now` and also checked at read time; expired keys are deleted on read. No sliding renewal and no refresh-token use.
- **Pending login:** Redis key `oidc:<random>` with a 10-minute TTL; one-time use; removed on callback. The random id is carried in a short-lived signed cookie.
- **CSRF:** random token issued at login and stored in the token record; embedded in portal forms; compared in constant time. SameSite=Strict is defense in depth, not the primary control.

## 5. Authorization contract

A single rule drives the portal list, `whoami`, and downloads:

```
authorized(server, groups, mappings) =
    any(mapping.vpn_server == server && groups.contains(mapping.idp_group))
```

- Exact, case-sensitive string comparison.
- Duplicate `vpn_server` values are rejected at startup, so no last-wins resolution exists.
- Unknown and unauthorized servers are indistinguishable to the caller: both `403`, both without touching Vault.
- Missing `groups` claim is a misconfiguration (`500`), never a silent denial.

## 6. Identity provider contract

- OIDC Authorization Code flow with PKCE `S256`, `state`, and `nonce`; discovery-driven endpoints; confidential client with secret from config.
- Scopes: `openid email profile`.
- Username and groups come from the **userinfo endpoint**, using the configured claim field names.
- Discovery redirect policy is disabled (no following redirects) to avoid SSRF.
- Trust: embedded webpki roots plus optional mounted CA; no system store.

## 7. Vault contract

- Authenticate with `POST /v1/auth/{vault_jwt_path}/login`, body `{"role":"<vault_jwt_role>","jwt":"<access_token>"}`; use `auth.client_token` on subsequent calls.
- Read KV v2 metadata with `GET /v1/{vault_metadata_mountpoint}/data/{vault_metadata_path}`; use `data.data`.
- Issue certificate with `POST /v1/{vault_pki_mountpoint}/issue/client`, body `{"common_name":"<username>"}`; role `client` is implicit in the path.
- Certificate TTL is governed by the Vault role (`max_ttl` 8 h in the reference stack), not the app.
- TLS verification enabled outside development; `CUSTOM_VAULT_CA` merged into the embedded root store.
- Vault least privilege (reference OpenTofu configuration): JWT role bound to audience `vsm` and group `/example`; policy grants issue on `vpn/devel/issue/client` and read/list on `vpnmeta/data/develmeta`.
- Vault is contacted **only after authorization succeeds**.

## 8. Profile rendering contract

`templates/template.ovpn` keeps the fixed directive set:

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
<ca>…certificate_authority…</ca>
<cert>…certificate…</cert>
<key>…certificate_key…</key>
<tls-crypt>…server_tls_key…</tls-crypt>
```

- Metadata is validated (§2.5) before insertion; the only request-derived certificate input is `common_name`.
- Templates and static assets are embedded in the binary and overridable by mounting `templates/` and `static/` at startup.
- Cypress golden assertions on `myserver.ovpn` must pass in Chrome and Firefox, with the updated filename header.

## 9. Error matrix (normative)

| Condition | Route | Status | Body |
|---|---|---|---|
| No/expired/missing session | `/` | `302` | `Location: /auth/login` |
| No/expired/missing session | `/api/whoami` | `401` | `{"error-message":"Not Authenticated"}` |
| No/expired/missing session | `POST /api/servers/{s}` | `401` | empty |
| No/expired/missing session | `POST /auth/logout` | `302` | `Location: /` (idempotent, no CSRF check) |
| No session | `GET /auth/logout` | `405` | `Allow: POST` |
| Discovery failure | `GET /auth/login` | `502` | login error page |
| Bad/expired OIDC `state`, token exchange, nonce, or userinfo failure | `/auth/callback` | `401` | login error page, no session |
| Provider returned no token | `/auth/callback` | `302` | `Location: /`, no session |
| Missing groups claim | `/` | `500` | HTML error page |
| Missing groups claim | APIs | `500` | well-formed JSON error |
| Denied or unknown server | `POST /api/servers/{s}` | `403` | HTML error page |
| Invalid CSRF token | state-changing POST | `403` | route-appropriate error |
| Vault/KV/PKI failure | `POST /api/servers/{s}` | `502` | generic HTML error; details in log |

## 10. Deployment and runtime contract

- Single static binary, target `x86_64-unknown-linux-musl`, built natively on Alpine; no dynamic dependencies (`ldd` reports "not a dynamic executable").
- Runtime image `FROM scratch`: binary, numeric user `65532:65532`, `WORKDIR /app`, `EXPOSE 3000`, `ENTRYPOINT ["/vsm"]`. No shell, no `/etc/passwd`, no `ca-certificates`.
- Config is mounted at `/app/config/vsm`; template/static overrides at `/app/templates` and `/app/static`.
- Compose layering unchanged: `docker-compose-common.yml` plus either `docker-compose-e2e.yml` (VSM + HAProxy) or `docker-compose-integration.yml` (HAProxy only, tests on host). HAProxy routes by `Host`; only e2e has a `vsm` backend.
- Bootstrap order unchanged: Redis → Keycloak → Vault → OpenTofu → VSM → tests.
- Working base is the upstream tree at SHA `8ea0424d5e0b95e9e4f693582e7e84900dba4de3`; Compose/HAProxy/OpenTofu/templates/test suites are edited in place, not recreated from prose.

## 11. Verification contract

1. **Static:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo audit`, `cargo deny check licenses`.
2. **Integration:** the Rust integration suite in `tests/integration.rs` with helpers in `tests/support/mod.rs` — the historical black-box HTTP scenarios, updated for §12 and run with `cargo test --test integration -- --ignored` against the real stack; asserts portal, `whoami`, valid download, `401` on expiry/no session, `403` for denied/unknown servers, `302` on unauthenticated `/`.
3. **E2E:** Cypress `cypress/e2e/vsm.cy.js` in Chrome and Firefox; updated to submit portal forms with CSRF and assert the `403` page; delete screenshots/downloads between runs.
4. **Image:** confirm `FROM scratch`, no shell, no dynamic linking, no CA bundle, and config not baked in.

## 12. Delta from the as-built application

| # | Area | As-built Python app | Rust contract | Why | Test impact |
|---|---|---|---|---|---|
| 1 | Download method | `GET /api/servers/{s}` link | `POST` form + CSRF token | CSRF protection | Update Cypress and the Rust integration suite |
| 2 | Logout method | `GET /auth/logout` | `POST` + CSRF; `GET` → `405` | CSRF protection | Update all logout helpers |
| 3 | Logout when anonymous | unhandled error | idempotent `302 /` | Defect fix | New test |
| 4 | Denied/unknown server | `302 /` | `403` error page | Correct semantics | Update status assertions |
| 5 | Cookie flags | constants unused; Flask defaults | applied `HttpOnly`, `SameSite=Strict`, `Secure`+`Domain` outside dev | Defect fix / hardening | Assert `Set-Cookie` |
| 6 | Missing groups error | doubled-quote, invalid JSON | single well-formed JSON object | Defect fix | Assert parseable JSON |
| 7 | Duplicate mappings | last wins | startup rejection | Deterministic config | New config test |
| 8 | Download filename | `filename= <s>.ovpn` | `filename="<s>.ovpn"` | Valid header | Update golden assertions |
| 9 | Vault metadata | inserted verbatim | required keys; CR/LF rejected on scalars, PEM blobs validated and exempted | Injection defense | Add rejection tests |
| 10 | Redis expiry | no TTL, expired keys linger | TTL + delete on read | Bounded state | Adapt `expire_session` fixture |
| 11 | OIDC state/nonce | not validated | validated; pending record in Redis | CSRF/replay defense | New negative test |
| 12 | Vault failure | unhandled exception → `500` | `502` generic, details logged | Controlled failure | New test |
| 13 | Startup trust log | `certifi` path | embedded roots (+ inline or mounted custom CA) | Scratch has no CA bundle | Update log assertion |
| 14 | Templates/logo | loaded from disk | embedded defaults with mount override | Minimal image | New override test |
| 15 | Stack/language | Python/Flask, Chainguard image | static Rust binary, scratch | Owner goal | New image checks |

## 13. Decisions recorded and deferred

**Owner decisions:** Rust; static scratch image; memory safety; full clean-up (§12 is authoritative); modify the upstream tree at SHA `8ea0424d5e0b95e9e4f693582e7e84900dba4de3` in place.

**Implementation calls (not owner approvals):**

- axum + tokio with thin explicit modules; `openidconnect` 4; rustls with `ring` and embedded roots.
- Per-session CSRF token in Redis; session check before CSRF check on logout.
- `502` for Vault and IdP discovery failures; `401` for all callback verification failures; "no token" keeps `302 /`.
- `CUSTOM_VAULT_CA` keeps the upstream inline-PEM form; a value that is not PEM is treated as a path to a mounted PEM file. If the issuer also needs custom trust, add a separate key.
- Debug logs include only non-secret metadata fields (`hostname`, `port`, `protocol`, `cipher`, `digest`, `server_dn`); CA blobs, `server_tls_key`, issued keys, and tokens are never logged.
- Keep the black-box HTTP scenarios and Cypress as the verification suites; the HTTP scenarios are now implemented as the Rust integration suite in `tests/integration.rs`.

**Deferred, not in scope:** PGP/S-MIME profile encryption (#3), event windows (#53), mapping restructure for performance (#2), release-tag builds (#6), dependency CVE backlog (#61–65), rate limiting, download auditing, and profile encryption beyond TLS.
