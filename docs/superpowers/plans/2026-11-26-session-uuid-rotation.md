# Session UUID Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Amend CONTRACT.MD §3.3 to require session-ID rotation on every login, and make the callback delete the previous session record after the new one is stored (Tier 2 finding #8, option B).

**Architecture:** The callback already mints a fresh UUID (`src/web/auth.rs:133`); keep that. After the new record is successfully stored, read the old UUID from the signed `session` cookie and delete its Redis record. Contract §3.3/§12/§13 are amended to make rotation normative; the ignored reuse test is replaced by rotation tests.

**Tech Stack:** Rust, axum, axum-extra SignedCookieJar, wiremock unit tests. Verify with `npm run lint` and `npm run test:unit`.

**Spec:** `docs/superpowers/specs/2026-11-26-session-uuid-rotation-design.md`

## Global Constraints

- Work in the current tree, NOT a worktree: the test fixtures this plan uses (`send_with_cookies_and_body`, `set_cookies`, `token_record`, `unix_now`, the ignored test) are uncommitted WIP in `src/web/auth.rs`; HEAD lacks them.
- Do NOT commit by default: the tree carries unrelated uncommitted audit WIP (`src/oidc.rs`, `src/vault.rs`, `src/web/*`, `.github/workflows/test-suite.yml`). Leave changes uncommitted unless the owner says otherwise. Do not touch, stage, stash, or revert any pre-existing modification.
- Delete strictly AFTER successful put; a failed put must leave the old session untouched.
- Never reintroduce UUID reuse. Deleting a missing/expired old record is a no-op, not an error.
- No changes to login, logout, cookie format/signing, or the pending-login flow.
- `npm run lint` (cargo fmt --check + clippy -D warnings) and `npm run test:unit` must pass.

## Review Focus

- Redis put failure during relogin → old session must survive (test in Task 2).
- Session cookie whose record is already gone/expired → callback still succeeds, delete is a no-op (test in Task 2).
- First-ever login (no session cookie) → unchanged behavior; existing callback tests already pin this — run them.
- Tampered/unsigned session cookie → `SignedCookieJar::get` returns None, so nothing is deleted; pinned by jar semantics, no new test.
- Old UUID equal to new UUID (astronomically unlikely) → guard `old != new` prevents self-deletion (code step in Task 2).

---

### Task 1: Contract amendment

**Files:**
- Modify: `CONTRACT.MD` (§3.3 line ~122; §12 table ends at entry 15, ~line 251; §13 "Owner decisions" list, ~lines 252-265)

**Interfaces:**
- Consumes: nothing.
- Produces: normative wording Task 2's test doc-comment cites ("§3.3: fresh UUID per callback; previous session deleted after the new record is stored").

- [ ] **Step 1: Amend §3.3.** In the `GET /auth/callback` paragraph, replace only the parenthetical `(reuse an existing UUID if the session already has one)` with `(always a fresh UUID; never reuse an existing session UUID)`, and append to that sentence: `If the request carried a live session cookie, delete its Redis record after the new record is stored; a failed store leaves the old session untouched.` Keep the rest of the line byte-identical.

- [ ] **Step 2: Add §12 entry 16**, matching the table's `# | Area | As-built Python app | Rust contract | Why | Test impact` column style:
  - Area: `Session UUID on relogin`
  - As-built column: `original §3.3 reused a live session's UUID`
  - Rust contract: `fresh UUID every callback; previous session record deleted after the new one is stored`
  - Why: `session-fixation defense (OWASP ASVS V3.2.1); owner decision 2026-11-26, Tier 2 finding #8`
  - Test impact: `ignored reuse test replaced by rotation tests`

- [ ] **Step 3: Add §13 "Owner decisions" bullet**, matching surrounding bullet style: `2026-11-26: §3.3 amended — the session UUID rotates on every successful login and the previous session is invalidated (Tier 2 audit finding #8). UUID reuse is prohibited.`

- [ ] **Step 4: Verify.** Run: `grep -n "never reuse" CONTRACT.MD` and `grep -n "2026-11-26" CONTRACT.MD`. Expected: one §3.3 hit, one §13 hit, plus the §12 row. Confirm no other line changed: `git diff CONTRACT.MD` shows only these three edits.

### Task 2: Rotate-and-delete in the callback (TDD)

**Files:**
- Modify: `src/web/auth.rs` (callback handler ~lines 133-146; imports line ~14; tests module: replace ignored test at ~lines 1090-1144)
- Test: same file, `mod tests`

**Interfaces:**
- Consumes: existing helpers `signed_cookie_value(name, value) -> String`, `set_cookies(&Response) -> Vec<String>`, `seed_pending(&CountingStore)`, `token_record(f64) -> TokenRecord`, `unix_now() -> f64`, `send_with_cookies_and_body(router, method, uri, &[(&str,&str)], body) -> Response`, `app_with_provider(store, &MockServer) -> Router`, `crate::oidc::test_support::{mount_provider, signed_id_token}`; `SESSION_COOKIE_NAME` from `crate::session` (session.rs:28).
- Produces: callback behavior — fresh UUID always; old session record deleted after successful put.

- [ ] **Step 1: Replace the ignored test with the failing rotation test.** Delete `callback_reuses_existing_session_uuid_on_relogin` (including its `#[ignore]` and doc comment) and write `callback_rotates_session_uuid_and_deletes_old_session` with the same setup (mock provider via `mount_provider` + `signed_id_token(&base, "some-nonce")`, `seed_pending`, seed record at `"existing-session-uuid"` with `token_record(unix_now() + 3600.0)`, both signed cookies, GET `/auth/callback?state=good-state&code=some-code`). Doc comment: `/// CONTRACT.MD §3.3: every callback mints a fresh session UUID and invalidates the session named by the incoming cookie (Tier 2 #8).` Assertions:
  - status 302;
  - issued `session=` cookie exists; extract the new UUID as the last 32 chars of the cookie pair (split the Set-Cookie value at `';'` first, strip `session=`); the signed format puts the raw value last, as the old test's `ends_with` assertion shows;
  - `new_uuid != "existing-session-uuid"`;
  - `store.get(new_uuid).await.is_some()`;
  - `store.get("existing-session-uuid").await.is_none()`;
  - puts delta: capture `store.puts.load(Ordering::SeqCst)` BEFORE the request and assert it grew by exactly 1 (do NOT copy the old test's absolute `== 1` — the seed put also counts);
  - `server.verify().await`.

- [ ] **Step 2: Run it, verify it fails.** Run: `cargo test callback_rotates_session_uuid -- --nocapture`. Expected: FAIL on `store.get("existing-session-uuid").is_none()` (current code never deletes).

- [ ] **Step 3: Implement.** Add `SESSION_COOKIE_NAME` to the `crate::session` import list. In `callback`, immediately after the successful `state.store.put(...)` block and before `build_session_cookie`, insert:

```rust
// Rotate: invalidate the previous session only after the new record is
// safely stored, so a failed put cannot destroy a live session.
if let Some(old) = jar.get(SESSION_COOKIE_NAME) {
    if old.value() != uuid {
        state.store.delete(old.value()).await;
    }
}
```

  Ignore the delete result (matches the logout handler's pattern at auth.rs:169). `jar.get` verifies the HMAC, so a tampered cookie deletes nothing.

- [ ] **Step 4: Run the test, verify it passes.** Run: `cargo test callback_rotates_session_uuid`. Expected: PASS.

- [ ] **Step 5: Edge test — stale cookie is a no-op.** Add `callback_with_stale_session_cookie_still_succeeds`: same provider/pending setup, session cookie signed for `"gone-session-uuid"` with NO seeded record. Assert 302, a `session=` cookie is issued whose last-32-chars UUID has a live record, and puts grew by 1. Run: `cargo test callback_with_stale_session_cookie`. Expected: PASS (no implementation change needed).

- [ ] **Step 6: Failure-ordering test — failed put preserves the old session.** Add a test-local wrapper `struct FailPutStore(CountingStore)` implementing `SessionStore` by delegating everything to `.0` except `put`, which returns an error (match the trait's error type as used by `MemoryStore`). Test `callback_put_failure_preserves_existing_session`: seed record at `"existing-session-uuid"`, send the callback with both cookies through a router built with `FailPutStore`. Assert status 500 and `store.get("existing-session-uuid").await.is_some()`. Run: `cargo test callback_put_failure_preserves`. Expected: PASS with the Step-3 ordering; if it fails, the delete is before the put — fix the ordering, not the test.

- [ ] **Step 7: Full verification.** Run: `npm run lint` then `npm run test:unit`. Expected: fmt/clippy clean; all tests pass, zero ignored tests remaining in `src/web/auth.rs` (`grep -c "#\[ignore" src/web/auth.rs` → 0).

- [ ] **Step 8: No commit** (Global Constraints). Report the diff summary instead: `git diff --stat CONTRACT.MD src/web/auth.rs`.
