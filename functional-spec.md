# Functional Specification — VPN Server Manager (`Kronus-Lab/vsm`)

## 0. Document control

| Field | Value |
|---|---|
| System | VPN Server Manager (VSM) — self-service short-lived OpenVPN configuration portal |
| Source of truth | `https://github.com/Kronus-Lab/vsm`, branch `main`, tree SHA `8ea0424d5e0b95e9e4f693582e7e84900dba4de3` |
| Spec type | As-built behavior + explicit gaps. Normative statements describe current code unless labeled "intended" or "proposed". |
| Primary sources | `vsm.py`, `config/vsm/*`, `templates/*`, `test/*`, `cypress/e2e/vsm.cy.js`, `test/presetup/main.tf`, `Dockerfile`, compose files, CI workflow |
| License | Apache-2.0 |

## 1. Purpose and scope

**Goal:** let an authenticated user visit a web portal, see only the VPN servers their IdP group membership permits, and download a freshly generated, short-lived `.ovpn` profile containing their own client certificate/private key.

**In scope:** web portal UI, OIDC login/session lifecycle, group→server authorization, Vault-backed config metadata and PKI certificate issuance, profile rendering and download, configuration file contracts, deployment topology, and the verification suite.

**Out of scope (current system):** managing VPN servers themselves, revocation UI, user administration, IdP administration, long-lived credentials, PGP/S-MIME protection, time-bounded event windows, rate limiting, CSRF protection. These are recorded as roadmap items in §13.

## 2. System context and runtime topology

```
Browser ──HTTP(S)──> HAProxy (Host-header routing)
                       ├─ vsm.local.kronus.network ──> VSM Flask app :3000
                       ├─ kc.local.kronus.network  ──> Keycloak :8080
                       └─ hcv.local.kronus.network ──> HashiCorp Vault :8200
VSM ──OIDC discovery/auth/code exchange + userinfo──> Keycloak
VSM ──token blob keyed by session UUID──> Redis :6379
VSM ──JWT auth + KV v2 read + PKI issue──> Vault
```

**End-to-end flow:**

1. User requests `/`; VSM redirects to `/auth/login` when unauthenticated.
2. VSM builds an OIDC authorization request (Authorization Code + PKCE `S256`, scopes `openid email profile`) and redirects to the IdP.
3. IdP authenticates the user and redirects to `/auth/callback` with an authorization code.
4. VSM exchanges the code for a token set, stores the full token dict in Redis under a random session UUID, and puts that UUID in a Flask signed session cookie.
5. On `/`, VSM reads the token from Redis, checks `expires_at`, extracts username and groups, resolves allowed servers, and renders links.
6. On `/api/servers/<server>`, VSM re-checks authorization, authenticates to Vault with the user's JWT, reads server metadata from KV v2, issues a client certificate from the PKI mount, renders `template.ovpn`, and streams it as an attachment.
7. Logout deletes the Redis token and clears the cookie; no IdP end-session call is made.

## 3. Actors

| Actor | Responsibilities |
|---|---|
| End user | Authenticate via IdP, view allowed servers, download one or more profiles, log out. |
| VSM service | Session brokering, authorization decisions, Vault orchestration, profile rendering. |
| OIDC provider (Keycloak in reference stack) | Authenticate user, expose discovery document and userinfo, emit `groups` claim. |
| Redis | Hold raw token sets keyed by opaque session UUID. |
| Vault | Validate user JWT via configured JWT auth role; serve KV metadata; issue short-lived client certificates under a constrained policy. |
| Operator / deployer | Supply `app.json`, `vpn_group_mapping.json`, templates, TLS/routing, and IdP/Vault configuration. |

## 4. Configuration contracts

### 4.1 `config/vsm/app.json` (loaded at process start from a relative path)

| Key | Type | Purpose | Reference value |
|---|---|---|---|
| `FLASK_SECRET` | string | Flask cookie-signing secret. Must be secret and stable across replicas. | `itsasecret` (dev only) |
| `ENV` | `"development"` or other | Controls debug mode, redirect URI scheme, Vault TLS verification, cookie-secure intent. | `development` |
| `HOSTNAME` | string | Intended public hostname; named as session cookie domain in code. | `vsm.local.kronus.network` |
| `REDIS_HOST`, `REDIS_PORT` | string, string/int | Redis connection (DB 0 hard-coded). | `localhost`/`vsm-redis-1`, `6379` |
| `VAULT_URL` | string | Vault base URL. | `http://hcv.local.kronus.network` |
| `CUSTOM_VAULT_CA` | optional string | PEM CA bundle passed to `hvac` as `cert` when present. | absent |
| `AUTH_ISSUER` | string | OIDC issuer; discovery URL is `<issuer>/.well-known/openid-configuration`. | `http://kc.local.kronus.network/realms/devel` |
| `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET` | string | Confidential OIDC client credentials. | `vsm`, `devel1234` |
| `AUTH_USERNAME_FIELD` | string | Key in token `userinfo` used as display name and certificate CN. | `preferred_username` |
| `AUTH_GROUPS_FIELD` | string | Key in token `userinfo` holding the groups list used for authorization. | `groups` |
| `FLASK_APP` | string | Informational; entrypoint is `python vsm.py`. | `vsm.py` |

### 4.2 `config/vsm/vpn_group_mapping.json` (list of objects)

| Field | Meaning |
|---|---|
| `vpn_server` | Server identifier used in URL `/api/servers/<vpn_server>` and in the UI. |
| `idp_group` | Exact group string from the `userinfo` groups claim that grants access. |
| `vault_metadata_mountpoint` | KV v2 mount holding connection metadata. |
| `vault_metadata_path` | Secret path inside that mount. |
| `vault_pki_mountpoint` | PKI mount; certificate is issued at `<mount>/issue/client`. |
| `vault_jwt_role` | Vault JWT auth role used with the user's access token. |
| `vault_jwt_path` | JWT auth backend mount path. |

Reference data maps `/example` → `myserver`, `myserver2`, `myserver3`; `/example2` → `myserver4`. Test user belongs only to `/example`.

### 4.3 Vault KV metadata payload (`data.data`)

Required keys: `hostname`, `port`, `protocol`, `server_dn`, `cipher`, `digest`, `certificate_authority`, `server_tls_key`. Values are inserted verbatim into the OVPN template; no escaping or validation is performed.

### 4.4 Vault reference configuration (Terraform in `test/presetup/main.tf`)

- Keycloak realm `devel` with a development "always good" browser flow, user `testuser`, group `example`, confidential client `vsm` with redirect URIs `http://vsm.local.kronus.network/*` and `http://localhost/*`, group-membership mapper emitting claim `groups`, and audience mapper for `vsm` in ID and access tokens.
- Vault JWT backend at `jwt`, role `test-role`, `user_claim=preferred_username`, `groups_claim=groups`, `bound_audiences=["vsm"]`, `bound_claims.groups="/example"`, policy `develvpn`, default policy disabled.
- KV v2 mount `vpnmeta` with secret `develmeta`.
- PKI mount `vpn/devel`, root CA 10 years, role `client` with `ttl=max_ttl=28800` (8 h), RSA 4096, client-only.
- Policy `develvpn` grants `create/update` on `vpn/devel/issue/client` and `read/list` on the metadata secret path.

## 5. Functional requirements

Each requirement carries implementation-independent acceptance criteria.

### FR-01 — Unauthenticated access control

- **Given** no valid session, **when** `GET /` is requested, **then** respond `302` with `Location: /auth/login`.
- **Given** no valid session, **when** `GET /api/whoami` or `GET /api/servers/<server>` is requested, **then** respond `401` (no redirect).
- A session is valid only if the cookie carries a UUID, Redis holds a token under that UUID, and the token's `expires_at` is strictly greater than the current Unix time.

### FR-02 — Login initiation

- `GET /auth/login` must obtain the provider's discovery metadata from `<AUTH_ISSUER>/.well-known/openid-configuration` and redirect to the authorization endpoint.
- Authorization request must use the configured client ID, scopes `openid email profile`, PKCE challenge method `S256`, and a redirect URI equal to the absolute URL of the `auth` route: `http` scheme when `ENV == "development"`, otherwise `https`.
- Acceptance: `Location` points at `<issuer>/protocol/openid-connect/auth?...` and contains the expected client and redirect parameters.

### FR-03 — Callback and session establishment

- `GET /auth/callback` exchanges the authorization code for a token set via the OIDC client.
- On success: reuse the existing session UUID if present, otherwise generate a 32-character lowercase hex UUID (`uuid4().hex`); store the JSON-serialized token set in Redis at key `<uuid>`; set `session["user"] = <uuid>`; redirect `302` to `/`.
- If no token is returned, do not create session state, but still redirect to `/` (which will then redirect to login).
- Acceptance: after callback, a signed `session` cookie exists, Redis contains the token, and `GET /` returns `200`.

### FR-04 — Session validation and expiry

- Every protected route resolves the session through one shared validation routine.
- Redis entries have **no TTL**; expiry is enforced at read time using the token's `expires_at` timestamp. An expired token is treated as no session and is not eagerly deleted.
- Acceptance: rewriting the stored token's `expires_at` to the current time causes `/` to redirect to `/auth/login`, and both API routes to return `401` (covered by `expire_session` fixture).

### FR-05 — Logout

- `GET /auth/logout` deletes the Redis key for the current session UUID, removes `session["user"]`, and redirects `302` to `/`.
- Acceptance: after logout, `GET /` redirects to login and both API routes return `401`. A `templates/logout.html` file exists but is not rendered.
- **Known defect:** the route accesses `session['user']` without a guard, so logging out while unauthenticated raises an error. A robust implementation should treat "already logged out" as idempotent while preserving the redirect.

### FR-06 — Authenticated portal view

- `GET /` when authenticated must:
  1. Extract the username from `userinfo[AUTH_USERNAME_FIELD]`.
  2. Extract the groups list from `userinfo[AUTH_GROUPS_FIELD]`; if missing, return the configured misconfiguration error (HTTP `500`).
  3. Compute the authorized server list (FR-08).
  4. Render the portal template showing `Logged in as: <username>`, the heading `Download VPN Server Configuration`, and one `<a href="/api/servers/<server>">` link per authorized server.
  5. Log an info-level event containing username and groups.
- Acceptance: with the reference mapping, `myserver`, `myserver2`, `myserver3` appear and `myserver4` does not.

### FR-07 — Identity API

- `GET /api/whoami` on a valid session returns `200`, `Content-Type: application/json`, body `{"username": "<username>", "vpn_servers": ["...", ...]}`.
- Missing groups claim → `500` with the configured error message; unauthenticated → `401` with body `{"error-message":"Not Authenticated"}`.
- Acceptance: matches the pytest and Cypress assertions (`username == "testuser"`, `vpn_servers` is an array containing exactly the three allowed servers).

### FR-08 — Group-to-server authorization

- A server is authorized if **any** mapping has both `idp_group` present in the user's groups list and `vpn_server` equal to the requested server. Group comparison is case-sensitive exact string match.
- The same function drives the UI list and both APIs; there must be a single authoritative source of this rule.
- For config downloads, the mapping also supplies all five Vault parameters. If several mappings match the same server, the **last matching mapping** in file order wins (current behavior; see §12 open question Q3).
- Unknown server or server outside the user's groups → `302` to `/` for the download endpoint, not `404`/`403` (current observable behavior).

### FR-09 — VPN configuration download

- `GET /api/servers/<server>` on a valid, authorized session must, in order:
  1. Authenticate to Vault via JWT auth: `jwt_login(role=<mapping.vault_jwt_role>, jwt=<token.access_token>, path=<mapping.vault_jwt_path>)`.
  2. Read KV v2 secret at `<metadata_mountpoint>` / `<metadata_path>` with `raise_on_deleted_version=True`.
  3. Issue a certificate at `<pki_mountpoint>/issue/client` with `common_name = username` (from `AUTH_USERNAME_FIELD`) and role name `client`.
  4. Render the OVPN template with metadata + issued `certificate` and `private_key`.
  5. Return `200`, `Content-Type: text/plain`, and `Content-Disposition: attachment; filename= <server>.ovpn`.
- Vault TLS verification is enabled unless `ENV == "development"`; optional `CUSTOM_VAULT_CA` is supplied when configured.
- Failure statuses: `401` unauthenticated, `500` missing groups claim, `302` to `/` unauthorized/unknown server. Vault/backend exceptions are currently unhandled (propagate as server errors).
- Acceptance: downloaded file contains `dev tun`, correct `remote`, `cipher`, `auth`, `verify-x509-name`, CA/cert/key/tls-crypt blocks with a real issued certificate and private key.

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

- No conditional blocks, escaping, or user-controlled free text beyond configured metadata; `common_name` is the only request-derived certificate input.
- Acceptance: Cypress golden assertions on the downloaded `myserver.ovpn` must pass in both Chrome and Firefox.

### FR-11 — Configuration loading and operator extensibility

- Both JSON files are read from relative paths (`config/vsm/app.json`, `config/vsm/vpn_group_mapping.json`) at import time; the process working directory must be the application root (`/app` in the container).
- Every mapping is logged at startup.
- Operators can override config, templates, and static logo by mounting files into `/home/vsm/config/vsm`, `/home/vsm/templates`, `/home/vsm/static` (README); the reference container mounts `./config/vsm-e2e:/app/config/vsm:ro`.
- Adding a server requires one mapping entry plus matching Vault metadata/PKI setup; no code change.

### FR-12 — Deployment and environment behavior

- Container: Chainguard Python base, non-root, `WORKDIR /app`, entrypoint `python vsm.py`, listening on `0.0.0.0:3000`. Runtime image contains `vsm.py`, `templates/`, `static/`, `LICENSE`, and pinned dependencies; config directory is expected at runtime.
- Compose layers: `docker-compose-common.yml` (Vault dev mode with root token `admin`, Keycloak `start-dev` admin/admin, Redis published on 6379) plus either `docker-compose-e2e.yml` (VSM + HAProxy with `/` published on 80) or `docker-compose-integration.yml` (HAProxy only; tests run on the host against localhost Redis).
- HAProxy routes by `Host` header; development aliases are the three `*.local.kronus.network` names. Only the e2e config includes a `vsm` backend.
- `ENV == "development"` also enables Flask debug mode and prints the custom-CA value.

### FR-13 — Observability

- Startup: prints the `certifi` CA bundle path; logs each loaded mapping.
- Runtime: info log on successful portal rendering (username + groups), debug log of `whoami` payload, info log of VPN metadata.
- No structured log schema, request IDs, metrics endpoint, or audit trail exists. Sensitive fields (token, private key) are not logged by current code.

### FR-14 — Verification

The implementation must satisfy three automated layers:
1. **Lint/license** (`test-suite.yml`): `pylint vsm`, `pylint -d duplicate-code vsm test/*.py`, `autopep8 -aad --exit-code`, `liccheck -r requirements.txt`.
2. **Integration** (`test/test_*.py`, pytest): login/logout/expiry fixtures drive a real Keycloak, Redis, and Vault stack; asserts portal contents, `whoami`, valid config download, `401` on expiry/no session, and `302` for invalid/denied servers.
3. **E2E** (`cypress/e2e/vsm.cy.js`): login success with downloaded-file assertions, bad username, unauthenticated API, unknown server, whoami; executed in Chrome and Firefox; SBOM generated for the image.
- Test infrastructure is provisioned by `terraform apply --auto-approve` in `test/presetup`; helper scripts `wait.sh`, `setup.sh`, `cleanup.sh` orchestrate readiness and teardown.

## 6. External interface summary

| Method | Path | Auth | Success | Failure |
|---|---|---|---|---|
| GET | `/` | Session | `200` HTML portal | `302 /auth/login` |
| GET | `/auth/login` | None | `302` to IdP authorize URL | — |
| GET | `/auth/callback` | Code + PKCE | stores token, `302 /` | `302 /` without token |
| GET | `/auth/logout` | Session (currently required) | deletes token, `302 /` | error if no session (defect) |
| GET | `/api/whoami` | Session | `200` JSON identity | `401`, or `500` claim missing |
| GET | `/api/servers/<server>` | Session + group | `200` `.ovpn` attachment | `401`, `500`, or `302 /` |

## 7. State and data model

- **Browser cookie:** Flask signed session containing only `{"user": "<32-hex-uuid>"}`.
- **Redis DB 0:** key `<uuid>` → JSON token set from the OIDC provider, containing at least `access_token`, `expires_at`, and `userinfo` with configurable username and groups fields. No TTL; deleted on logout.
- **Derived state:** authorized server list (group ∩ mapping), Vault parameters (from the winning mapping), rendered OVPN (metadata ∪ issued certificate).
- **Session lifetime:** bounded by the IdP token's `expires_at`; there is no sliding renewal, refresh-token use, or Redis TTL.

## 8. Security requirements (as-built and intended)

| Requirement | Status |
|---|---|
| Authorization Code flow with PKCE `S256` | Implemented |
| Confidential client with secret from config | Implemented |
| Signed Flask session cookie; opaque UUID, no token in browser | Implemented |
| Cookie flags **intended** by module constants: `HttpOnly`, `SameSite=Strict`, `Secure` outside development, domain `HOSTNAME` | **Not effective**: constants are never applied to `app.config`; Flask defaults apply (`HttpOnly=True`, no `Secure`, no `SameSite`, no domain). Must be fixed in any target implementation. |
| Vault least privilege (JWT role bound to audience/groups; policy limited to one issue path + one secret path) | Implemented in reference Terraform |
| TLS verification toward Vault outside development; optional custom CA | Implemented |
| Development bypasses TLS verification, uses HTTP redirect URIs, enables debug | Implemented — must never be enabled in production |
| CSRF protection on state-changing routes | Not implemented (`GET` logout, `GET` download); Flask-WTF is a dependency but unused |
| Rate limiting, download auditing, profile encryption at rest/in transit beyond TLS | Not implemented (see §13) |

## 9. Error handling matrix (normative for compatibility)

| Condition | Route | Response |
|---|---|---|
| No/expired Redis token | `/` | `302 /auth/login` |
| No/expired Redis token | `/api/whoami` | `401 {"error-message":"Not Authenticated"}` |
| No/expired Redis token | `/api/servers/<s>` | `401` empty body |
| `AUTH_GROUPS_FIELD` absent in `userinfo` | `/`, APIs | `500` with misconfiguration message |
| Unknown/denied server | `/api/servers/<s>` | `302 /` |
| Vault or PKI failure | `/api/servers/<s>` | unhandled exception → HTTP 500 at server level |

**Defect to note:** the constructed misconfiguration body wraps an already-quoted string, producing doubled quotes around the message (invalid JSON). A target implementation should emit a single well-formed JSON object while keeping the same status code.

## 10. Nonfunctional requirements

- Python 3.12 is used in CI; container runtime is based on Chainguard Python (3.13 site-packages path in Dockerfile).
- Pinned runtime dependencies include Flask 3.0.0, Authlib 1.6.4, hvac 1.2.1, redis 5.0.1, certifi, requests; dev dependencies include pytest, pylint, autopep8, liccheck, Cypress.
- Single-process Flask app; no horizontal-state concerns beyond shared Redis and shared `FLASK_SECRET`.
- Bootstrap dependency order: Redis, Keycloak, Vault → Terraform provisioning → VSM readiness → tests.
- Templates and static assets are overridable by volume mount; config is not baked into the runtime image.

## 11. Acceptance checklist for an agent team

- [ ] Unauthenticated user cannot see server names or obtain a profile (`401`/`302` as specified).
- [ ] Login uses PKCE and the configured discovery URL; callback creates cookie + Redis entry.
- [ ] Expiring the Redis token makes all protected routes reject the user.
- [ ] Portal and `whoami` list exactly the servers implied by group mappings.
- [ ] Downloading a mapped server yields a valid OpenVPN profile with a freshly issued, short-lived client cert whose CN is the username.
- [ ] Unknown and unauthorized servers redirect to `/` and never touch Vault.
- [ ] Logout removes the Redis entry and the cookie; re-login works.
- [ ] All config keys and mapping fields are consumed from files, not hard-coded.
- [ ] Pytest integration suite, Cypress suite (both browsers), lint, and license checks pass in CI.

## 12. Open questions for the product owner

1. **Spec baseline:** this document describes current behavior. Should the agent team treat the security/correctness defects in §8–9 as required fixes in scope, or preserve byte-for-byte compatibility?
2. **Cookie hardening:** should `SESSION_COOKIE_*` be applied to `app.config` (fixing the ineffective constants), and should the session cookie domain be the full public hostname?
3. **Mapping conflicts:** when two mappings match the same server with different Vault parameters, should the last-win behavior be kept, or should configuration validation reject duplicates?
4. **Unauthorized download status:** keep `302` to `/` for compatibility, or move to `403` with an error page?
5. **File location:** where should the team store this spec (repo docs, wiki, or local plan directory)?

## 13. Explicitly out of scope / roadmap (from open GitHub issues)

- **#3** PGP/S-MIME encryption of the downloaded profile to protect against TLS-inspecting proxies/MitM.
- **#53** Event start/end/config-availability windows with certificate TTL capped to event end and Vault `max_ttl`.
- **#2** Restructure mappings into `server → config` dictionaries to avoid the linear scan (performance/clarity).
- **#6** Release-tag-based container builds in addition to the daily `devel` build.
- **#61–65** Dependency security upgrades (Authlib, Werkzeug, urllib3, cryptography) — pending PRs.

These are **not** requirements of the as-built system; treat them as separate change requests with their own acceptance criteria.

## 14. Suggested agent work packages (ordered)

| WP | Scope | Depends on |
|---|---|---|
| WP1 | Config contracts, environment switching, secure session cookie setup, startup validation | — |
| WP2 | OIDC login/callback/logout + Redis session layer | WP1 |
| WP3 | Authorization mapping and identity API (`whoami`) | WP2 |
| WP4 | Portal UI templates and static assets | WP3 |
| WP5 | Vault JWT/KV/PKI integration and OVPN rendering | WP1, WP3 |
| WP6 | Docker/Compose/HAProxy/Terraform reference stack | WP1–WP5 |
| WP7 | Pytest integration + Cypress E2E + CI | WP2–WP6 |
| WP8 | Hardening backlog (§8–9) and roadmap items (§13) after PO decisions | All |

## 15. Source map for the implementing agents

| Concern | Files |
|---|---|
| Application logic | `vsm.py` |
| Configuration | `config/vsm/app.json`, `config/vsm/vpn_group_mapping.json`, `config/vsm-e2e/*` |
| UI/profile templates | `templates/base.html`, `index.html`, `logout.html`, `template.ovpn`, `static/logo.png` |
| Tests | `test/test_index.py`, `test/test_server.py`, `test/test_whoami.py`, `test/fixtures/*`, `cypress/e2e/vsm.cy.js` |
| Reference infrastructure | `test/presetup/main.tf`, `vault_create_role.sh`, `docker-compose-*.yml`, `config/haproxy-*/haproxy.cfg` |
| Build/CI | `Dockerfile`, `.github/workflows/test-suite.yml`, `requirements*.txt`, `liccheck.ini` |
| Product docs | `README.md`, `CONTRIBUTING.md`, `diagram.drawio` |
