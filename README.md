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

The application is a single Rust binary built on **tokio** and **axum**.
`npm run build` (`./scripts/build-image.sh`) compiles it for
`x86_64-unknown-linux-musl` in a pinned `rust:1-alpine` builder container
(**statically linked**) into `dist/vsm`; no host musl toolchain is needed. The
toolchain, crate registry and target dir are cached in `vsm-rustup`,
`vsm-cargo` and `vsm-build-cache` (or under `VSM_CACHE_DIR`); Cargo and rustup
invalidate each layer per dependency or toolchain change, and `--locked` makes
a stale lockfile fail the build instead of silently re-resolving. The image
itself is `FROM scratch` packaging only and contains just `/vsm` plus an
entrypoint:

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

`SESSION_SECRET`, `ENV`, `HOSTNAME`, `REDIS_HOST`, `REDIS_PORT`, `VAULT_URL`,
`CUSTOM_VAULT_CA` (optional), `AUTH_ISSUER`, `AUTH_CLIENT_ID`,
`AUTH_CLIENT_SECRET`, `AUTH_USERNAME_FIELD`, and `AUTH_GROUPS_FIELD` are loaded
from `app.json`; each mapping in `vpn_group_mapping.json` supplies
`vpn_server`, `idp_group`, `vault_metadata_mountpoint`, `vault_metadata_path`,
`vault_pki_mountpoint`, `vault_jwt_role`, and `vault_jwt_path`. Duplicate
`vpn_server` values or missing/invalid keys abort startup. `SESSION_SECRET`
must be at least 32 bytes unless `ENV=development`; `ENV=development` changes
tracing, the callback scheme, Vault TLS verification, and cookie
`Secure`/`Domain` behavior — never use it in production.

**Breaking configuration change:** `FLASK_SECRET` was renamed to
`SESSION_SECRET`. Update deployed `app.json` files before upgrading: startup
now fails when `SESSION_SECRET` is absent (or too short outside development).
The former application-entrypoint key is no longer read.

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
| `GET` | `/auth/callback` | validates pending state, ID-token `nonce`, exchange, and userinfo; `401` on failure, `302 /` when the provider returns no token |
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

Only Cypress is installed from npm; all application checks are Cargo or shell
commands. From the repository root:

```sh
npm install                # installs the Cypress devDependency
npm run lint               # cargo fmt --check && cargo clippy --all-targets -- -D warnings
npm run test:unit          # cargo test
npm run coverage           # cargo llvm-cov --html
npm run license            # cargo deny check licenses
npm run audit              # cargo audit
```

`cargo audit` uses `.cargo/audit.toml` to ignore only `RUSTSEC-2023-0071`
(unreachable RSA private-key path; see the comment in that file). All other
advisories are enforced. To build the statically linked binary and the scratch
image (the binary is compiled in a pinned builder container into `dist/vsm`,
then packaged into a `FROM scratch` image):

```sh
npm run build                 # or: ./scripts/build-image.sh
file dist/vsm                 # statically linked
```

Integration tests are black-box HTTP tests against the real stack. Bootstrap
order is Redis → Keycloak → Vault → OpenTofu → VSM → tests. `npm test` runs
`cargo test --test integration -- --ignored`; its `pretest`/`posttest` hooks
bring the compose stack and OpenTofu fixtures up and down
(`./test/presetup/setup.sh integration` and `./test/presetup/cleanup.sh`). The
tests expect a **running VSM** reachable at `VSM_BASE_URL` (default
`http://localhost:3000`) — they never start the binary themselves. For a local
run with the binary already started from the repository root:

```sh
VSM_BASE_URL=http://localhost:3000 npm test
```

Or drive each step explicitly:

```sh
docker compose -f docker-compose-common.yml -f docker-compose-integration.yml up -d
./test/presetup/wait.sh
(cd test/presetup && tofu init --upgrade && tofu apply --auto-approve)
cargo build --release
./target/release/vsm &
VSM_BASE_URL=http://localhost:3000 cargo test --test integration -- --ignored
```

End-to-end tests use the e2e overlay (which supplies the VSM backend and
HAProxy host routing) and the `kr0nus/vsm:devel` image. With the LFS-resolved
logo and OpenTofu state applied, run both browsers and clean generated files
between runs:

```sh
npx cypress run --browser chrome --spec cypress/e2e/vsm.cy.js
rm -rf cypress/screenshots cypress/downloads
npx cypress run --browser firefox --spec cypress/e2e/vsm.cy.js
rm -rf cypress/screenshots cypress/downloads
```

CI runs the Rust checks, the integration suite, and both Cypress browser jobs
on every pull request.
