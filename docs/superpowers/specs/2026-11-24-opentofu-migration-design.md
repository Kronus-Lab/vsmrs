# OpenTofu migration for the VSM test fixtures — design (2026-11-24)

Status: proposed, awaiting approval.

## Intent

Replace Terraform CLI usage with OpenTofu across the repo's test provisioning, and use the
currently maintained Keycloak provider. Terraform is only used for test infrastructure
(`test/presetup/main.tf`, `automation/vault.tf`); the Rust app has no Terraform dependency.
The fixture still pins `mrparkers/keycloak` 4.4.0, but the Keycloak project adopted that
provider in Dec 2024 and now publishes it as `keycloak/keycloak` (Apache-2.0), with version
5.x the supported line for current Keycloak 26.x.

## Goals

- All provisioning commands use `tofu`, including local npm/script hooks and both CI jobs.
- `test/presetup/main.tf` uses `keycloak/keycloak` provider version `5.11.0` (official docs
  recommend `>= 5.11.0`; the repo pins exact versions, so exact pin it).
- Keep `hashicorp/vault` 4.3.0 in presetup and 4.2.0 in `automation/vault.tf`; both resolve
  from the OpenTofu registry with the exact pinned versions.
- No change to the resources the fixture creates, and no change to application behavior.

## Non-goals

- No extraction into registry or local modules: there are **no `module` blocks** today, and
  generic community modules do not cover this fixture's custom auth flow, protocol mappers,
  and cross-provider JWT bindings. The "appropriate modules" check is therefore a provider
  source/version audit, which is covered by the goals above.
- No changes to app runtime, compose topology, or the `quay.io/keycloak/keycloak:latest` tag.
- No edits to the 2026-11-17 and 2026-11-18 historical docs under `docs/superpowers/`
  (AGENTS.md classifies them as historical records).

## Constraints

- Local state (`test/presetup/vsmdevel.tfstate`), `.terraform/`, and `.terraform.lock.hcl`
  are gitignored (`.gitignore` lines 21-24); `cleanup.sh` deletes the state file, so the
  fixture is disposable and does not need state surgery.
- The Keycloak provider officially supports the latest three Keycloak minor versions.
- CI currently uses `hashicorp/setup-terraform@v3` in two jobs of
  `.github/workflows/test-suite.yml` (lines 77-84 and 149-156).
- Latest OpenTofu CLI release at design time: 1.13.10.

## Approaches considered

1. **Swap CLI and align providers (chosen).** Mechanical CLI/script/CI/doc replacement plus
   the official Keycloak provider address and version bump. Small, reviewable diff; the
   official provider's own docs confirm the flow/execution/bindings resources used here are
   present with the same arguments, so no HCL rewrite is expected. Risk: 4.4.0 → 5.x behavior
   drift, caught by `tofu validate` and the integration stack.
2. **CLI swap only.** Keep `mrparkers/keycloak` 4.4.0 (it is mirrored on the OpenTofu
   registry). Lowest risk but leaves the fixture on the superseded provider, so it does not
   answer the upstream-support concern.
3. **Refactor into registry modules.** Large churn for disposable test infrastructure, with
   no module covering the fixture's exact configuration. Rejected.

## Implementation outline

1. `test/presetup/main.tf`: change `source = "mrparkers/keycloak"` to
   `source = "keycloak/keycloak"` and `version = "4.4.0"` to `version = "5.11.0"`.
   Leave all resource blocks unchanged.
2. `test/presetup/setup.sh` lines 21-22: `terraform init --upgrade` → `tofu init --upgrade`;
   `terraform apply --auto-approve` → `tofu apply --auto-approve`.
   `cleanup.sh` and `wait.sh` need no change.
3. `.github/workflows/test-suite.yml` (both jobs): replace `hashicorp/setup-terraform@v3`
   with `opentofu/setup-opentofu@v1` and set `with: tofu_version: "1.13.10"`; replace the
   two `terraform ...` invocations with `tofu ...`.
4. Documentation: update Terraform wording/commands in `README.md` (lines 140, 142, 157,
   165), `AGENTS.md` (lines 19-20, 25), `functional-spec.md` (lines 93, 226, 258, 286,
   327), and `CONTRIBUTING.md` (line 28). Historical design/plan docs are left alone.
5. Generated artifacts: do not commit `.terraform/`, `.terraform.lock.hcl`, or state. On a
   working copy with stale Terraform state, delete the state and let `setup.sh` rebuild it;
   if preserving state is ever required, use
   `tofu state replace-provider mrparkers/keycloak keycloak/keycloak`.
6. If `tofu validate` or integration reveals a 5.x schema change in one of the ten Keycloak
   resource types, make the smallest HCL adjustment needed and record it here.

## Verification

- `tofu init --upgrade` and `tofu validate` in `test/presetup` succeed with the new provider.
- Full integration stack: compose common + integration, `wait.sh`, `tofu apply`, release
  binary, `VSM_BASE_URL=http://localhost:3000 npm test`.
- E2E stack smoke run with the new provisioning step.
- Existing static checks (`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`)
  remain green; no Rust code changes are expected.
