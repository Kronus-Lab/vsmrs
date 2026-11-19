# AGENTS.md

## Start here
- This workspace contains only `functional-spec.md` — no source, manifests, CI config, git history, or other instruction files. Don't hunt for them; the spec is all local context.
- The spec is an **as-built** description of `Kronus-Lab/vsm`, pinned to upstream tree `8ea0424d5e0b95e9e4f693582e7e84900dba4de3`. Where prose and upstream executable files disagree, the upstream files at that SHA win.
- No toolchain files exist yet, so don't infer a language or stack from the directory name. Confirm the target stack before scaffolding.

## Treat spec labels as decision points
- The spec documents current behavior, not the desired system. `intended`, `proposed`, §8–9 "defects", §12 open questions, and §13 roadmap are not requirements by default.
- §12 is unresolved by the product owner: preserve-vs-fix defects, cookie hardening, duplicate-mapping conflicts, `302` vs `403` for denied downloads, spec location. Ask rather than silently choosing.
- The defects are still current observable behavior (ineffective cookie constants, doubled-quote JSON 500, unauthenticated-logout error). Fixing them changes compatibility.

## Runtime traps
- Both JSON configs load from relative paths at import time; CWD must be the app root (`/app` in the container).
- `ENV=development` flips debug mode, HTTP redirect URIs, Vault TLS verification, and secure-cookie intent at once — never in production.
- Redis tokens have no TTL; expiry is read-time (`expires_at > now`) and expired keys are not deleted.
- Missing groups claim → 500; unknown/denied server → `302 /` (not 403/404) and must never touch Vault.
- Vault metadata is inserted into the OVPN template verbatim (no escaping/validation); cert CN is the username, TTL 8h.
- Bootstrap order: Redis → Keycloak → Vault → `terraform apply` → VSM → tests. `*.local.kronus.network` → 127.0.0.1; HAProxy routes by `Host`; only the e2e compose has a VSM backend.

## Verification targets (from upstream CI at the pinned SHA; not runnable here yet)
- Python 3.12; `pip install -r requirements.txt -r requirements-dev.txt`.
- Lint/license in order: `pylint vsm`, `pylint -d duplicate-code vsm test/*.py`, `autopep8 -aad --exit-code $(git ls-files '*.py')`, `liccheck -r requirements.txt`.
- Integration: `docker-compose-common.yml` + `docker-compose-integration.yml`, `./test/presetup/wait.sh`, `cd test/presetup && terraform init --upgrade && terraform apply --auto-approve`, then `pytest -q`.
- E2E: common + `docker-compose-e2e.yml`, image `kr0nus/vsm:devel`, same wait/terraform, Cypress `cypress/e2e/vsm.cy.js` in Chrome and Firefox; delete `cypress/screenshots` and `cypress/downloads` between runs.
