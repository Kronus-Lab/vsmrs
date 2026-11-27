# OpenTofu Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Terraform CLI usage with OpenTofu in the VSM test stack and move the Keycloak provider to the officially maintained `keycloak/keycloak` source.

**Architecture:** Terraform is used only to provision disposable test infrastructure (`test/presetup/main.tf` and `automation/vault.tf`); the Rust application is untouched. The migration is a CLI/source swap: `tofu` replaces `terraform` in local scripts, CI, and current docs, while the fixture's provider address changes from `mrparkers/keycloak` 4.4.0 to `keycloak/keycloak` 5.11.0. All HCL resources stay as they are; the official provider has the same resource types and arguments. Local state and lock files are gitignored and regenerated, so no state migration is needed.

**Tech Stack:** OpenTofu 1.x (`tofu`), OpenTofu registry providers `keycloak/keycloak` 5.11.0 and `hashicorp/vault` 4.3.0 (presetup) / 4.2.0 (automation), GitHub Actions, npm scripts, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-11-24-opentofu-migration-design.md`

## Global Constraints

- Provider source in `test/presetup/main.tf` becomes exactly `keycloak/keycloak`, version exactly `5.11.0`.
- Vault providers stay pinned: `hashicorp/vault` `4.3.0` in presetup, `4.2.0` in `automation/vault.tf`.
- CI installs OpenTofu with `opentofu/setup-opentofu@v1` and `tofu_version: "1.13.10"`.
- Provisioning commands are exactly `tofu init --upgrade` and `tofu apply --auto-approve`.
- `.terraform/`, `.terraform.lock.hcl`, and `*.tfstate` stay gitignored and uncommitted; local state is disposable (`cleanup.sh` removes `test/presetup/vsmdevel.tfstate`).
- No `module` blocks are introduced; no resource HCL is rewritten unless `tofu validate` or integration proves a 5.x schema change.
- Current docs only: `README.md`, `AGENTS.md`, `functional-spec.md`, `CONTRIBUTING.md`. Historical design/plan docs under `docs/superpowers/` (2026-11-17 and 2026-11-18) are not edited.
- No application runtime, compose topology, or Keycloak image tag changes.

## Review Focus

- Stale local Terraform state with old provider addresses: if `test/presetup/vsmdevel.tfstate` exists before the first `tofu apply`, delete it (disposable) — pinned in Task 1 step 6.
- 5.x Keycloak schema drift in the ten resource types (especially auth flow/execution/bindings): expect no HCL changes, but `tofu validate` and a real integration apply must pass — pinned in Task 1 step 7 and Task 4 step 2.
- CI left with `hashicorp/setup-terraform@v3` or a `terraform` command after the action swap: both occurrences must be gone, with exactly two `tofu apply` calls — pinned in Task 2 step 3.
- Current docs still instructing users to run `terraform`: no `terraform` matches may remain in the four live docs — pinned in Task 3 step 3.
- Generated artifacts accidentally committed after `tofu init`: `git status --short` must show no new state/lock files — pinned in Task 1 step 6 and Task 4 step 4.

---

### Task 1: Switch presetup provisioning to OpenTofu and the official Keycloak provider

**Files:**
- Modify: `test/presetup/main.tf:5-14`
- Modify: `test/presetup/setup.sh:20-22`

**Interfaces:**
- Consumes: nothing; this is the first task.
- Produces: `tofu init --upgrade` / `tofu apply --auto-approve` in `setup.sh`, and `keycloak/keycloak` 5.11.0 in the fixture's `required_providers`. Tasks 2-4 rely on these exact commands.

- [ ] **Step 1: Confirm the local CLI and baseline repository state**

Run: `tofu version && git status --short test/presetup`
Expected: an OpenTofu 1.x version string; no unexpected tracked modifications under `test/presetup`.

- [ ] **Step 2: Run the check that fails before the change**

Run: `grep -F 'source = "keycloak/keycloak"' test/presetup/main.tf && grep -F 'version = "5.11.0"' test/presetup/main.tf && grep -F 'tofu apply --auto-approve' test/presetup/setup.sh`
Expected: FAIL (no matches).

- [ ] **Step 3: Change the provider source and version in `test/presetup/main.tf`**

Replace the `keycloak` entry inside `required_providers` verbatim:
```hcl
  keycloak = {
    source = "keycloak/keycloak"
    version = "5.11.0"
  }
```
Leave the `hashicorp/vault` 4.3.0 entry and every resource block untouched.

- [ ] **Step 4: Swap the commands in `test/presetup/setup.sh`**

Replace lines 20-22 verbatim:
```sh
# Configure using OpenTofu
tofu init --upgrade
tofu apply --auto-approve
```
Leave `docker compose`, `cd test/presetup`, and `./wait.sh` as they are.

- [ ] **Step 5: Re-run the check from Step 2**

Expected: PASS (all three strings found).

- [ ] **Step 6: Clear disposable state and confirm no generated artifacts are tracked**

Run: `rm -f test/presetup/vsmdevel.tfstate; git status --short`
Expected: no `vsmdevel.tfstate`, `.terraform.lock.hcl`, or `.terraform/` entries in the status output (all are gitignored); only the two intended file modifications are shown.

- [ ] **Step 7: Initialise and validate the fixture with OpenTofu**

Run: `cd test/presetup && tofu init --upgrade && tofu validate`
Expected: providers resolved from `registry.opentofu.org` (`keycloak/keycloak` 5.11.0, `hashicorp/vault` 4.3.0); `tofu validate` reports "Success! The configuration is valid." If a 5.x schema error appears, make the smallest HCL adjustment it names, re-run validation, and record the adjustment in the design doc.

- [ ] **Step 8: Commit**

```bash
git add test/presetup/main.tf test/presetup/setup.sh
git commit -m "build: provision test fixtures with OpenTofu and official Keycloak provider"
```

---

### Task 2: Replace Terraform setup and commands in CI

**Files:**
- Modify: `.github/workflows/test-suite.yml:77-84`
- Modify: `.github/workflows/test-suite.yml:149-156`

**Interfaces:**
- Consumes: the `tofu init --upgrade` / `tofu apply --auto-approve` conventions from Task 1.
- Produces: both CI jobs installing OpenTofu 1.13.10 and invoking `tofu`; Task 4 verifies the stack built by these jobs locally.

- [ ] **Step 1: Run the check that fails before the change**

Run: `! grep -F 'hashicorp/setup-terraform@v3' .github/workflows/test-suite.yml && grep -F 'tofu apply --auto-approve' .github/workflows/test-suite.yml`
Expected: FAIL (`hashicorp/setup-terraform@v3` is still present).

- [ ] **Step 2: Replace both setup steps and both provisioning steps**

In each of the two blocks (around lines 77-84 and 149-156), replace:
```yaml
    - name: Setup terraform in execution
      uses: hashicorp/setup-terraform@v3
```
with:
```yaml
    - name: Setup OpenTofu in execution
      uses: opentofu/setup-opentofu@v1
      with:
        tofu_version: "1.13.10"
```
In the following step, rename `Configure test intrastructure` to `Configure test infrastructure` and replace `terraform init --upgrade` with `tofu init --upgrade` and `terraform apply --auto-approve` with `tofu apply --auto-approve`. Do both blocks identically; leave all other workflow steps untouched.

- [ ] **Step 3: Verify the workflow has no Terraform remnants**

Run:
```sh
! grep -F 'hashicorp/setup-terraform@v3' .github/workflows/test-suite.yml &&
! grep -E '^\s+terraform ' .github/workflows/test-suite.yml &&
test "$(grep -cF 'opentofu/setup-opentofu@v1' .github/workflows/test-suite.yml)" -eq 2 &&
test "$(grep -cF 'tofu apply --auto-approve' .github/workflows/test-suite.yml)" -eq 2
```
Expected: PASS, with no output.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/test-suite.yml
git commit -m "ci: install OpenTofu and provision fixtures with tofu"
```

---

### Task 3: Update live documentation

**Files:**
- Modify: `README.md:140,142,157,165`
- Modify: `AGENTS.md:19-20,25`
- Modify: `functional-spec.md:93,226,258,286,327`
- Modify: `CONTRIBUTING.md:28`

**Interfaces:**
- Consumes: the OpenTofu commands and provider names established in Tasks 1-2.
- Produces: documentation that no longer instructs anyone to run `terraform`; Task 4 checks the docs again as part of final verification.

- [ ] **Step 1: Run the check that fails before the change**

Run: `grep -Rni 'terraform' README.md AGENTS.md functional-spec.md CONTRIBUTING.md`
Expected: matches in all four files (the old commands and descriptions).

- [ ] **Step 2: Update the four live docs**

In those files only, change Terraform references to OpenTofu and commands to `tofu`: `terraform init --upgrade && terraform apply --auto-approve` → `tofu init --upgrade && tofu apply --auto-approve`; `terraform apply` → `tofu apply`; "Terraform fixtures/state/provisioning" → "OpenTofu fixtures/state/provisioning". Keep the bootstrap order and all other wording intact. Do not touch anything under `docs/superpowers/`.

- [ ] **Step 3: Verify no stale Terraform references remain in live docs**

Run:
```sh
! grep -Rni 'terraform' README.md AGENTS.md functional-spec.md CONTRIBUTING.md &&
grep -Rqi 'opentofu' README.md AGENTS.md functional-spec.md CONTRIBUTING.md &&
test -z "$(git diff --name-only -- docs/superpowers | grep -v '2026-11-24')"
```
Expected: PASS, with no output (the two new 2026-11-24 docs are the only intended files there).

- [ ] **Step 4: Commit**

```bash
git add README.md AGENTS.md functional-spec.md CONTRIBUTING.md
git commit -m "docs: describe OpenTofu provisioning instead of Terraform"
```

---

### Task 4: Verify the migrated stack end to end

**Files:** none expected; modify only if verification exposes a problem (then commit that fix with a descriptive message).

**Interfaces:**
- Consumes: all artifacts produced by Tasks 1-3.
- Produces: a verified migration; no interfaces for later work.

- [ ] **Step 1: Confirm the local static checks still pass**

Run: `npm run lint`
Expected: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` succeed.

- [ ] **Step 2: Run the integration stack through the updated hooks**

Run: `VSM_BASE_URL=http://localhost:3000 npm test`
Expected: `pretest` runs `cleanup.sh` then `setup.sh`, which prints `tofu init --upgrade` / `tofu apply --auto-approve` output; the 12 black-box HTTP integration tests pass with no `terraform` binary present locally.

- [ ] **Step 3: Smoke-test the e2e provisioning path**

Run: `npm run teardown && npm run setup -- e2e && npm run teardown`
Expected: e2e compose starts, the OpenTofu apply configures Keycloak and Vault successfully, and teardown removes the stack and local state without errors.

- [ ] **Step 4: Confirm no generated artifacts or stale commands remain**

Run:
```sh
git status --short &&
! grep -RniE '\bterraform\b' README.md AGENTS.md functional-spec.md CONTRIBUTING.md .github/workflows/test-suite.yml test/presetup/setup.sh test/presetup/main.tf
```
Expected: clean working tree apart from the two new 2026-11-24 design/plan docs, no state or lock files listed, and no `terraform` references in the migrated surfaces.
