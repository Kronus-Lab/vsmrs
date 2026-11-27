# PKCE Enforcement in the Test Stack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the test stack's Keycloak client require PKCE `S256` and prove it with a black-box integration test.

**Architecture:** One Terraform attribute on `keycloak_openid_client.vsm` (`test/presetup/main.tf`), plus one ignored integration test that probes Keycloak's authorization endpoint directly (bypassing VSM) without a valid PKCE challenge and asserts rejection. Red/green cycle runs against the live integration stack: the test fails before the attribute is applied and passes after.

**Tech Stack:** OpenTofu locally (`tofu`; CI uses `terraform`), provider `mrparkers/keycloak` v4.4.0, Rust/reqwest/tokio integration tests, Docker Compose stack.

**Spec:** `docs/superpowers/specs/2026-11-26-pkce-enforcement-design.md`

## Global Constraints

- Provider stays `mrparkers/keycloak` v4.4.0 — do not touch `required_providers` or `.terraform.lock.hcl`.
- No changes to `src/`, `config/`, or `CONTRACT.MD` — VSM behavior is unchanged.
- New test follows the existing pattern: `#[tokio::test]` + `#[ignore = "requires the integration stack"]` in `tests/integration.rs`.
- Local IaC binary is `tofu` (no `terraform` on this machine); commands below use `tofu`.
- `npm run lint` (`cargo fmt --check` + `cargo clippy --all-targets -- -D warnings`) must pass.
- Commit only the files listed per step — never `test/presetup/vsmdevel.tfstate`, `vsm.log`, `vsm.pid`, `.terraform/`.
- Any git commit: load the `agent-commit-attribution` skill first.

## Review Focus

- No-PKCE authorization request must never yield an authorization code → asserted (`!location.contains("code=")`) in Task 1's test.
- Downgrade to `code_challenge_method=plain` must be rejected → second probe in Task 1's test.
- A valid `S256` request must still reach the login form (enforcement isn't breakage) → positive control in Task 1's test.
- The attribute must actually be applied, not just written → red/green cycle plus `tofu apply` output showing `1 to change` (Task 1, steps 4–7).
- Existing VSM login flows must be unaffected → full 13-test suite run (Task 1, step 8).

---

### Task 1: Enforce PKCE on the Keycloak client + enforcement-proof test

**Files:**
- Modify: `test/presetup/main.tf:100-108` (the `keycloak_openid_client.vsm` resource)
- Modify: `tests/integration.rs` (append one test after the existing 12)
- Commit also: `docs/superpowers/specs/2026-11-26-pkce-enforcement-design.md`, `docs/superpowers/plans/2026-11-26-pkce-enforcement.md`

**Interfaces:**
- Consumes: existing stack scripts `test/presetup/setup.sh integration` (compose up → `wait.sh` → `tofu init --upgrade && tofu apply` → `cargo build --release` → starts VSM, writes `vsm.pid`/`vsm.log`, waits for HTTP 302 on `localhost:3000`). Keycloak realm `devel`, client `vsm`, registered redirect `http://vsm.local.kronus.network/auth/callback`. `reqwest`, `tokio`, `url` are crate dependencies, usable from integration tests.
- Produces: test `keycloak_enforces_pkce` (13th ignored test); no public API changes.

- [ ] **Step 1: Bring up the integration stack (pre-attribute)**

Run from repo root: `./test/presetup/setup.sh integration`
Expected: ends with `VSM ready on localhost:3000 (HTTP 302)`. If it aborts with "Development environment up or broken", a `vsm` container is running — stop it first (`docker ps`, then `docker stop <name>`) and rerun. If `wait.sh` cannot resolve `kc.local.kronus.network`, the host needs `127.0.0.1 kc.local.kronus.network vsm.local.kronus.network hcv.local.kronus.network` in `/etc/hosts` (stack publishes HAProxy on 80/443).

- [ ] **Step 2: Write the failing test**

Append to `tests/integration.rs`:

```rust
#[tokio::test]
#[ignore = "requires the integration stack"]
async fn keycloak_enforces_pkce() {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let auth_url = "http://kc.local.kronus.network/realms/devel/protocol/openid-connect/auth";
    let redirect_uri = "http://vsm.local.kronus.network/auth/callback";
    let base_params = [
        ("client_id", "vsm"),
        ("response_type", "code"),
        ("scope", "openid email profile"),
        ("redirect_uri", redirect_uri),
        ("state", "pkce-enforcement-probe"),
        ("nonce", "pkce-enforcement-probe"),
    ];

    async fn assert_rejected(client: &reqwest::Client, url: reqwest::Url) {
        let resp = client.get(url).send().await.unwrap();
        assert_eq!(resp.status(), 302, "invalid-PKCE probe must not reach the login form");
        let location = resp.headers()["location"].to_str().unwrap();
        assert!(location.starts_with("http://vsm.local.kronus.network/auth/callback"));
        assert!(location.contains("error="), "expected OAuth error redirect, got {location}");
        assert!(!location.contains("code="), "no authorization code may be issued");
    }

    // Probe 1: no code_challenge at all.
    let url = reqwest::Url::parse_with_params(auth_url, base_params).unwrap();
    assert_rejected(&client, url).await;

    // Probe 2: downgrade to plain — S256 is the only permitted method.
    let mut plain = base_params.to_vec();
    plain.push(("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    plain.push(("code_challenge_method", "plain"));
    let url = reqwest::Url::parse_with_params(auth_url, plain).unwrap();
    assert_rejected(&client, url).await;

    // Positive control: valid S256 challenge reaches the login form.
    // Challenge = S256 of RFC 7636 App. B verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".
    let mut s256 = base_params.to_vec();
    s256.push(("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    s256.push(("code_challenge_method", "S256"));
    let url = reqwest::Url::parse_with_params(auth_url, s256).unwrap();
    let resp = client.get(url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("kc-login"));
}
```

**Rejection-shape fallback (spec leaves this to the builder):** the assertions above expect Keycloak's error-redirect behavior (302 to the registered redirect URI with `error=`, no `code=`). If after Step 5 the enforced stack instead returns a 4xx error page, observe the actual response (status + body), change `assert_rejected` to pin that observed rejection (status and a `code_challenge` mention in the body), and note the observed shape in a comment. Do not weaken the positive control.

- [ ] **Step 3: Run the test — verify it FAILS (red)**

Run: `VSM_BASE_URL=http://localhost:3000 cargo test --test integration keycloak_enforces_pkce -- --ignored`
Expected: FAIL on probe 1 — without enforcement Keycloak returns the 200 login form, so `assert_eq!(resp.status(), 302)` fails. This failure is the point: it proves the test detects missing enforcement.

- [ ] **Step 4: Add the Terraform attribute**

In `test/presetup/main.tf`, inside `resource "keycloak_openid_client" "vsm"` (lines 100–108), add one line:

```hcl
  pkce_code_challenge_method = "S256"
```

Then run `tofu fmt` in `test/presetup/` to fix `=` alignment. No other Terraform changes.

- [ ] **Step 5: Apply to the running stack**

Run in `test/presetup/`: `tofu apply --auto-approve`
Expected: `Apply complete! Resources: ... 1 changed ...` — the change is `keycloak_openid_client.vsm` (in-place update). No provider re-init needed.

- [ ] **Step 6: Run the test — verify it PASSES (green)**

Run: `VSM_BASE_URL=http://localhost:3000 cargo test --test integration keycloak_enforces_pkce -- --ignored`
Expected: PASS. If it fails on rejection shape, apply the Step 2 fallback rule and rerun.

- [ ] **Step 7: Run the full integration suite**

Run: `VSM_BASE_URL=http://localhost:3000 npm test`
Expected: 13 passed, 0 failed (the 12 existing tests plus the new one). Any existing-test failure means enforcement broke a flow — stop and investigate; do not weaken existing tests.

- [ ] **Step 8: Static checks**

Run: `npm run lint`
Expected: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` both clean.

- [ ] **Step 9: Commit**

Load `agent-commit-attribution` skill, then:

```bash
git add test/presetup/main.tf tests/integration.rs
git commit -m "test: enforce PKCE S256 on the integration Keycloak client"
git add docs/superpowers/specs/2026-11-26-pkce-enforcement-design.md docs/superpowers/plans/2026-11-26-pkce-enforcement.md
git commit -m "docs: PKCE enforcement design and plan"
```

- [ ] **Step 10: Tear down the stack**

```bash
kill "$(cat vsm.pid)" 2>/dev/null; rm -f vsm.pid vsm.log
docker compose -f docker-compose-common.yml -f docker-compose-integration.yml down
rm -f test/presetup/vsmdevel.tfstate
```

(Note: `cleanup.sh` downs the *e2e* compose file, so use the explicit commands above for the integration stack.)