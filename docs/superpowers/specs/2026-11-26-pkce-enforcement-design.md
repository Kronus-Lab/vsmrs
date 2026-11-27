# PKCE enforcement in the test stack — short design

Date: 2026-11-26 · Status: approved by owner (conversation)

## Intent

Make the test stack's Keycloak client *require* PKCE (`S256`) instead of merely
tolerating it, and prove the enforcement with a test. Today VSM always sends
PKCE (`src/oidc.rs`), but the Terraform client sets no
`pkce_code_challenge_method`, so Keycloak would also accept a no-PKCE login —
nothing in the stack tests enforcement.

## Goals

- `keycloak_openid_client.vsm` in `test/presetup/main.tf` sets
  `pkce_code_challenge_method = "S256"`.
- One black-box integration test proves Keycloak rejects an authorization
  request that omits `code_challenge`.
- All existing integration tests and Cypress flows keep passing (they log in
  through VSM, which always sends PKCE).

## Non-goals / anti-goals

- No change to VSM application behavior or `CONTRACT.MD` observable behavior.
- No pinning of the `keycloak:latest` image (separate concern).
- No realm-wide policy work; the client attribute is the mechanism.

## Constraints

- Provider `mrparkers/keycloak` v4.4.0 (pinned in `main.tf` and
  `.terraform.lock.hcl`) supports `pkce_code_challenge_method` (added v4.2.0).
- Integration tests are black-box HTTP tests marked
  `#[ignore = "requires the integration stack"]`; the new test follows the same
  pattern and lives in `tests/integration.rs` with helpers in
  `tests/support/mod.rs`.
- Verification needs the integration stack: compose up, `wait.sh`,
  `terraform init --upgrade && terraform apply --auto-approve` (CI; `tofu` locally), release binary,
  `VSM_BASE_URL=http://localhost:3000 npm test`.

## Approaches

1. **Client attribute + enforcement-proof integration test (chosen).** One-line
   Terraform change; a direct no-PKCE request to Keycloak's authorization
   endpoint must be rejected. Owner approved.
2. Terraform flip only — rejected: nothing would prove enforcement; every
   existing test passes either way.
3. App-side test only — rejected: cannot prove server-side enforcement.

## Decided

- Attribute value `S256` (matches VSM's challenge method).
- The proof test talks to Keycloak directly (bypassing VSM) without
  `code_challenge`, asserting rejection; it must not create a VSM session.

## Left to the builder

- Exact rejection assertion shape (Keycloak error redirect vs error page) —
  observe actual behavior on the stack and assert the stable part.
- Test naming/placement consistent with the existing 12 black-box tests.
