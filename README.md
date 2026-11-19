# VPN Server Manager (VSM)

## What is this?

VSM provides self-service, short-lived VPN access. Users sign in through an OIDC
identity provider, pick an authorized VPN endpoint, and download a generated
OpenVPN profile whose certificate is issued on demand by HashiCorp Vault.

![img](diagram.png)

1. A user reaches the VSM portal.
2. The login redirect starts an OIDC Authorization Code flow (PKCE `S256`,
   `state`, and `nonce`) against the configured identity provider.
3. After authentication, the portal lists only the VPN servers allowed by the
   user's groups.
4. A POST request downloads a `.ovpn` profile: VSM authenticates to Vault with
   the user's access token, reads connection metadata, issues a short-lived
   client certificate whose CN is the username, and renders the profile.
5. Denied or unknown servers return `403` without any Vault call.

## Implementation

The application is a single Rust binary built on **tokio** and **axum**. It is
compiled for `x86_64-unknown-linux-musl` on Alpine and is **statically linked**;
the runtime image is `FROM scratch` and contains only `/vsm` plus an entrypoint:

- `WORKDIR /app`, `EXPOSE 3000`, `ENTRYPOINT ["/vsm"]`
- numeric user `65532:65532` (no shell, no `/etc/passwd`, no CA bundle)
- TLS trust comes from roots embedded in the binary; no system certificate
  store is required at runtime

Configuration, templates, and static assets are **never baked into the image**.
The JSON configuration must be mounted at `/app/config/vsm`:

```sh
docker run --rm -p 3000:3000 \
  -v "$PWD/config/vsm:/app/config/vsm:ro" \
  kr0nus/vsm:devel
```

`templates/` and `static/` are embedded as defaults at compile time and may be
overridden by mounting them read-only at `/app/templates` and `/app/static`.
The same applies to `docker-compose-e2e.yml`, which mounts
`./config/vsm-e2e:/app/config/vsm:ro`. Every mounted path must be readable by
UID `65532`. `static/logo.png` is a Git LFS asset; check out with LFS enabled
(`actions/checkout` uses `lfs: true`) so the image/test run gets the real PNG.

The binary reads `config/vsm/app.json` and
`config/vsm/vpn_group_mapping.json` **relative to the working directory** at
startup, so start it from the repository root (or from `/app` in the image):

```sh
cargo build --release
./target/release/vsm
```

`FLASK_SECRET`, `ENV`, `HOSTNAME`, `REDIS_HOST`, `REDIS_PORT`, `VAULT_URL`,
`CUSTOM_VAULT_CA` (optional), `AUTH_ISSUER`, `AUTH_CLIENT_ID`,
`AUTH_CLIENT_SECRET`, `AUTH_USERNAME_FIELD`, and `AUTH_GROUPS_FIELD` are loaded
from `app.json`; each mapping in `vpn_group_mapping.json` supplies
`vpn_server`, `idp_group`, `vault_metadata_mountpoint`, `vault_metadata_path`,
`vault_pki_mountpoint`, `vault_jwt_role`, and `vault_jwt_path`. Duplicate
`vpn_server` values or missing/invalid keys abort startup. `ENV=development`
changes tracing, the callback scheme, Vault TLS verification, and cookie
`Secure`/`Domain` behavior; never use it in production. The `FLASK_APP` key in
the JSON is retained only as upstream compatibility data and is informational.

### Vault CA trust

`CUSTOM_VAULT_CA` accepts either an inline PEM certificate or a path to a PEM
file (a value that is not PEM is treated as a path). The CA is merged into the
embedded root store for Vault requests only. Mount the PEM file read-only into
the container (for example `-v "$PWD/vault-ca.pem:/app/vault-ca.pem:ro"`), set
`CUSTOM_VAULT_CA` to the path, and ensure UID `65532` can read it. Never add the
CA file to the image, and never print the config or CA contents in logs,
scripts, or CI output: the application deliberately logs only a trust-source
status line, not the CA value.

## HTTP and security contract

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/` | `200` portal with one CSRF-protected POST form per authorized server, or `302 /auth/login` without a session |
| `GET` | `/auth/login` | `302` to the OIDC provider; `502` on discovery failure |
| `GET` | `/auth/callback` | validates `state`, ID-token `nonce`, exchange, and userinfo; `401` on failure, `302 /` when the provider returns no token |
| `GET` | `/auth/logout` | `405` with `Allow: POST` |
| `POST` | `/auth/logout` | form-encoded `csrf_token`; deletes the Redis token, clears the cookie, `302 /`; no session is also `302 /` (idempotent) |
| `GET` | `/api/whoami` | `200` JSON identity/server list, or `401 {"error-message":"Not Authenticated"}` |
| `POST` | `/api/servers/{server}` | form-encoded `csrf_token`; `200` `.ovpn` attachment, `401` (empty body) without a session, `403` for denied/unknown server or bad CSRF, `502` on Vault failure |

Both the download and logout forms are POSTs carrying the per-session CSRF
token rendered into the portal; `SameSite=Strict` is only defense in depth.
Denied and unknown servers are indistinguishable (`403`, HTML error page) and
never reach Vault. Session cookies are signed opaque UUIDs, never tokens, and
carry `HttpOnly`, `SameSite=Strict`, `Path=/`, plus `Secure` and
`Domain=HOSTNAME` outside development. Sessions expire at the stored
`expires_at` (strictly greater than now), with a Redis TTL and deletion on
read. API errors are single, well-formed JSON objects with an `error-message`
field; browser-route errors are small HTML pages. A missing groups claim is a
`500` (JSON on APIs), not a silent denial.

## Build and verification

Static checks (from the repository root):

```sh
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
cargo deny check licenses
```

`cargo audit` uses `.cargo/audit.toml` to ignore only `RUSTSEC-2023-0071`
(unreachable RSA private-key path; see the comment in that file). All other
advisories are enforced. To build the statically linked binary and the scratch
image:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/vsm   # statically linked
docker build -t kr0nus/vsm:devel .
```

Integration tests are black-box HTTP tests against the real stack. Bootstrap
order is Redis → Keycloak → Vault → Terraform → VSM → tests. For local runs,
bring up the common compose file plus the integration overlay, apply the
Terraform fixtures, start the release binary **from the repository root** (the
config paths are relative), then run pytest:

```sh
PATH="/tmp/opencode/bin:$PATH"   # only if terraform is not already on PATH
docker compose -f docker-compose-common.yml -f docker-compose-integration.yml up -d
./test/presetup/wait.sh
(cd test/presetup && terraform init --upgrade && terraform apply --auto-approve)
cargo build --release
./target/release/vsm &
pytest -q
```

End-to-end tests use the e2e overlay (which supplies the VSM backend and
HAProxy host routing) and the `kr0nus/vsm:devel` image. With the LFS-resolved
logo and Terraform state applied, run both browsers and clean generated files
between runs:

```sh
npx cypress run --browser chrome --spec cypress/e2e/vsm.cy.js
rm -rf cypress/screenshots cypress/downloads
npx cypress run --browser firefox --spec cypress/e2e/vsm.cy.js
rm -rf cypress/screenshots cypress/downloads
```

CI runs the Rust checks, the integration suite, and both Cypress browser jobs
on every pull request.

## Legacy notes

The former Python/Flask application runtime has been removed. The Python files
that remain belong to the black-box test suite only (see `requirements.txt`);
they are not part of the deployed application.
