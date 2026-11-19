# Dead-Code Suppression Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every `#[allow(dead_code)]` from the Rust rewrite and prove with the compiler that no dead code remains.

**Architecture:** Attribute-only edits in three source files inside the existing worktree; no runtime behavior changes. Verification is a warning-free `cargo check --all-targets` plus a source grep showing zero remaining suppressions.

**Tech Stack:** Rust (pinned by `rust-toolchain.toml`), Cargo; worktree at `upstream/.worktrees/rust-rewrite/`

**Spec:** `docs/superpowers/specs/2026-11-18-dead-code-cleanup-design.md`

## Global Constraints

- Work only in `upstream/.worktrees/rust-rewrite/`.
- No runtime behavior changes: this is a lint-attribute-only edit.
- Never re-add a `dead_code` suppression to silence a warning — wire the item in or delete it.
- Only `dead_code` diagnostics are in scope. Note unrelated warnings; do not fix them.
- Commit only the three files you changed; leave pre-existing user changes untouched.
- The `#![deny(dead_code)]` gate is explicitly deferred and out of scope.

## Review Focus

- An item believed live is actually dead once its attribute is gone → zero `dead_code` diagnostics in the Step 3 check. (Task 1 Step 3)
- Test-only usage is invisible to a plain `cargo check` → `--all-targets` is mandatory in the Step 3 command. (Task 1 Step 3)
- A suppression is quietly re-added to make a warning disappear → Step 4 grep must find zero `allow(dead_code)` occurrences. (Task 1 Step 4)
- Scope creep into unrelated warnings or pre-existing edits → Step 1 baseline and Step 5 scoped `git add`. (Task 1 Steps 1, 5)

---

### Task 1: Remove all `dead_code` suppressions and verify with the compiler

**Files:**
- Modify: `upstream/.worktrees/rust-rewrite/src/main.rs:10`
- Modify: `upstream/.worktrees/rust-rewrite/src/config.rs:20-21,31-32,49`
- Modify: `upstream/.worktrees/rust-rewrite/src/authz.rs:20`
- Test: compiler sweep via `cargo check --all-targets` (no new test file)

**Interfaces:**
- Consumes: the five live items already wired into the crate — `session` module (imported across `web/*.rs`), `flask_secret` (`state.rs:25`), `auth_client_secret` (`oidc.rs:108`), `Mapping` (config/authz/web/state), `authorized` (`web/api.rs:122`).
- Produces: a crate that compiles with zero `dead_code` diagnostics and zero `allow(dead_code)` attributes. Public API unchanged.

- [ ] **Step 1: Record the baseline warning set**

Run in `upstream/.worktrees/rust-rewrite`:

```bash
cargo check --all-targets
```

Expected: exits 0. Write down any non-`dead_code` warnings so later output can be compared.

- [ ] **Step 2: Remove the five attributes and two stale comments**

- In `src/main.rs`: delete the `#[allow(dead_code)]` line directly above `mod session;`.
- In `src/authz.rs`: delete the `#[allow(dead_code)]` line directly above `pub fn authorized`.
- In `src/config.rs`: delete the `// Consumed by the session and OIDC modules added in later tasks.` comment and the `#[allow(dead_code)]` line above `flask_secret`; delete the `// Consumed by the OIDC module added in a later task.` comment and the `#[allow(dead_code)]` line above `auth_client_secret`; delete the `#[allow(dead_code)]` line above `#[derive(Debug, Clone, PartialEq, Eq)]` on `Mapping`.

Expected: the diff contains only those seven deleted lines — no added lines, no other edits.

- [ ] **Step 3: Run the compiler sweep**

Run: `cargo check --all-targets`

Expected: exits 0 with zero `dead_code` warnings. If a `dead_code` warning appears, wire that item into its real call site or delete it, then re-run this step until clean. Do not re-add the attribute. Non-`dead_code` warnings noted in Step 1 are out of scope.

- [ ] **Step 4: Confirm no suppressions remain**

Run in the worktree root:

```bash
grep -rn "allow(dead_code)" src/
```

Expected: no output (grep exits 1).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/config.rs src/authz.rs
git commit -m "chore: remove stale dead_code suppressions"
```

Expected: one commit containing only those three source files.
