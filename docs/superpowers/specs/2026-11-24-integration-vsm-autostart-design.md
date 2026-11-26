# Integration VSM autostart — design

Date: 2026-11-24
Status: proposed (approach A approved in conversation)

## Intent

`npm run test` fails with `ConnectionRefused` on `localhost:3000` because nothing in the
local flow starts VSM: `test/presetup/setup.sh integration` brings up only
Redis/Keycloak/Vault/HAProxy and applies OpenTofu. CI already bridges this gap
(`.github/workflows/test-suite.yml`: build release binary → `nohup` start → wait for
HTTP 302). Make the local flow match CI so `npm run test` works end-to-end.

## Goals

- `npm run test` passes end-to-end from a clean machine state (stack + VSM + 12 tests).
- Local startup/readiness logic is identical to the CI steps (no drift).
- Failed runs leave a diagnosable `vsm.log`; the next `pretest` teardown kills any
  leftover VSM process.

## Non-goals / anti-goals

- No changes to the e2e flow (`setup.sh e2e` keeps using the `kr0nus/vsm:devel` container).
- No compose-file, config, test-harness, or CI-workflow changes.
- No fix to the `docker ps | grep -q vsm` guard (matches `vsmrs-*` names; harmless in the
  `pretest` flow because teardown runs first).
- Must not test stale code: always build from the working tree, never reuse `dist/vsm`.

## Approaches considered

- **A (chosen): mirror CI in `setup.sh`.** Host `cargo build --release`, `nohup` start
  with PID file, 60 s HTTP-302 readiness loop. Cheap after first build, proven in CI.
- B: `vsm` service in `docker-compose-integration.yml` publishing 3000. Rejected:
  expensive musl image build per setup, needs container-specific config (current
  `app.json` uses `localhost`/`*.local.kronus.network` hosts), diverges from CI.
- C: start prebuilt `dist/vsm`. Rejected as default: binary can be stale relative to
  HEAD (currently Nov 19 vs Nov 24 commits); misleading test results.

## Design (approach A)

Two files change; everything else stays as-is.

### `test/presetup/setup.sh`

After the existing `tofu init`/`tofu apply` (VSM must start after apply — it needs the
Keycloak client and Vault roles), add an integration-only branch:

1. `cd` back to the repo root (binary loads `config/vsm/*.json` from relative paths;
   CWD must be the app root). Resolve root from the script location, not `$PWD`.
2. `cargo build --release` (fail fast if the build fails).
3. `nohup ./target/release/vsm > vsm.log 2>&1 &` then `echo $! > vsm.pid`
   (both at repo root, same names/locations as CI).
4. Readiness loop copied verbatim in behavior from CI: up to 60 × 1 s polls of
   `curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/`, success on `302`;
   on timeout print `vsm.log` and `exit 1`.

`MODE=e2e` skips all of the above.

### `test/presetup/cleanup.sh`

Before/alongside the existing compose down + tfstate removal:

- If `vsm.pid` exists at repo root: kill that PID (ignore "no such process"), then
  `rm -f vsm.pid vsm.log`.
- Keep everything else unchanged (including the existing e2e-file compose down).

### Constraints

- `config/vsm/app.json` is used unchanged (`ENV=development`, short `SESSION_SECRET`
  passes with a warning in development).
- Shell stays POSIX `sh` compatible where the existing scripts are; the CI wait loop
  uses `seq`/`$(...)` — keep the same constructs CI uses.
- Uncommitted `terraform` → `tofu` change in `setup.sh` stays (user's in-flight work).

## Verification

- `npm run test` from clean state: pretest brings up stack, applies tofu, builds and
  starts VSM, readiness loop sees 302, all 12 integration tests pass, posttest tears
  down and no `vsm` process remains.
- Failure path: with a broken config, setup exits non-zero and prints `vsm.log`.
- `npm run lint` unaffected (shell-only change); `cargo fmt --check` / clippy still clean.

## Left to the builder

- Exact placement/wording of the integration branch and PID-kill guard in the two
  scripts, consistent with their existing style.