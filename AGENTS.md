# AGENTS.md

## Start here
- This repository is the Rust implementation of `Kronus-Lab/vsm`: one statically linked tokio/axum binary, JSON configuration mounted at runtime, and Cypress for end-to-end checks.
- `functional-spec.md` is the as-built behavior description; `CONTRACT.MD` is normative for observable behavior and wins on disagreement. Where prose and executable files (`src/`, `config/`, `Dockerfile`, `Cargo.toml`, `.github/workflows/`) disagree, the files win.
- The 2026-11-17 rewrite docs (`docs/superpowers/specs/2026-11-17-*`, `docs/superpowers/plans/2026-11-17-*`) and the 2026-11-18 dead-code-cleanup docs (`docs/superpowers/specs/2026-11-18-dead-code-cleanup*`, `docs/superpowers/plans/2026-11-18-dead-code-cleanup*`) are historical records, not requirements. The 2026-11-18 Rust-only-tooling plan, design document, and `.superpowers/` artifacts are also historical.

## Treat spec labels as decision points
- `functional-spec.md` §8–9 "defects", §12 open questions, and §13 roadmap describe the old baseline or deferred work, not current requirements. The hardened behavior (403 denials, CSRF, validated metadata) is what the binary implements and is recorded in `CONTRACT.MD` §12.
- `CONTRACT.MD` §12 is the complete list of intentional behavior changes from that baseline; §13 records owner decisions and implementation calls. Neither is a backlog to execute without a new decision.
- Do not reintroduce old behavior (unauthenticated logout errors, redirects on denied downloads, unverified OIDC state/nonce, verbatim metadata insertion) from historical documents.

## Runtime traps
- Both JSON configs load from relative paths at startup (`config/vsm/app.json`, `config/vsm/vpn_group_mapping.json`); CWD must be the app root (`/app` in the container). Duplicate `vpn_server` values and missing/invalid keys abort startup.
- `SESSION_SECRET` is expanded with HKDF-SHA256 into the cookie-signing key; it must be at least 32 bytes outside `ENV=development`, and changing it invalidates existing cookies.
- `ENV=development` flips tracing to debug, HTTP redirect URIs, Vault TLS verification, and cookie `Secure`/`Domain` at once — never in production.
- Redis DB 0 holds token records keyed by a 32-hex session UUID with a TTL, plus one-time `oidc:<state>` pending logins (10-minute TTL). Expiry is read-time (`expires_at > now`) and expired keys are deleted on read.
- Missing username or groups claim → `500`; unknown/denied server → `403` and no Vault call; unauthenticated API call → `401`.
- Vault metadata is validated before insertion into the OVPN template; cert CN is the username, TTL from the Vault role (8 h in the reference Terraform).
- Bootstrap order: Redis → Keycloak → Vault → `terraform apply` → VSM → tests. `*.local.kronus.network` hosts resolve to the stack; HAProxy routes by `Host`; only the e2e compose has a VSM backend.

## Verification targets
- Static (`npm run lint`): `cargo fmt --check`, then `cargo clippy --all-targets -- -D warnings`.
- Unit and analysis: `npm run test:unit` (`cargo test`), `npm run audit` (`cargo audit`), `npm run license` (`cargo deny check licenses`), `npm run coverage` (`cargo llvm-cov --html`).
- Integration: bring up `docker-compose-common.yml` + `docker-compose-integration.yml`, run `./test/presetup/wait.sh`, then `terraform init --upgrade && terraform apply --auto-approve` in `test/presetup`, start the release binary, and run `VSM_BASE_URL=http://localhost:3000 npm test` (`cargo test --test integration -- --ignored`). The 12 black-box HTTP tests are marked `#[ignore = "requires the integration stack"]`.
- E2E: `docker-compose-common.yml` + `docker-compose-e2e.yml`, image `kr0nus/vsm:devel`, Cypress `cypress/e2e/vsm.cy.js` in Chrome and Firefox; delete `cypress/screenshots` and `cypress/downloads` between runs.
- Image build: `npm run build` (`scripts/build-image.sh`) compiles the static musl binary in a pinned `rust:1-alpine` builder container into `dist/vsm`; the `FROM scratch` image only packages that file and the context contains only `dist/vsm`. No host musl toolchain is needed.
