# Integration VSM Autostart Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `npm run test` work end-to-end by starting the VSM release binary in `setup.sh` (integration mode) and stopping it in `cleanup.sh`, mirroring CI.

**Architecture:** After `tofu apply`, `setup.sh` builds and `nohup`-starts `target/release/vsm` from the repo root with `vsm.pid`/`vsm.log`, then runs CI's 60 s HTTP-302 readiness loop. `cleanup.sh` kills the recorded PID and removes the files. E2e mode and all other files are untouched.

**Tech Stack:** POSIX sh, docker compose, OpenTofu, cargo (host release build), curl.

**Spec:** `docs/superpowers/specs/2026-11-24-integration-vsm-autostart-design.md`

## Global Constraints

- Work in place (no worktree): the docker stack binds host ports 80/443/6379/3000 globally; a second checkout cannot run it in parallel.
- Integration mode only: the new setup code runs iff `MODE` = `integration`; e2e keeps the `kr0nus/vsm:devel` container.
- VSM starts AFTER `tofu apply` and with CWD = repo root (config loads from relative `config/vsm/*.json`).
- Readiness loop behavior copied from `.github/workflows/test-suite.yml` ("Wait for VSM to be ready"): 60 × 1 s, success only on HTTP `302` at `http://localhost:3000/`, on timeout print `vsm.log` and exit 1.
- PID/log files: `vsm.pid`, `vsm.log` at repo root (same names/locations as CI).
- Never reuse `dist/vsm`; always `cargo build --release` from the working tree.
- Do not touch: compose files, `config/`, `tests/`, CI workflows, the `docker ps | grep -q vsm` guard, the user's uncommitted `terraform` → `tofu` hunk in `setup.sh` (keep it in the file).
- Before ANY commit: load the `agent-commit-attribution` skill and follow it.
- Each full stack cycle (teardown → setup → tofu → tests) takes a few minutes; that is expected, do not shortcut it.

## Review Focus

- Leftover VSM from a failed run holds port 3000 → next run's binary cannot bind; `pretest` teardown must kill it (Task 2 steps 1–4).
- Stale `vsm.pid` pointing at a dead process → cleanup must still succeed and remove the files (Task 2 step 5).
- Startup failure (port taken / bad config) → setup exits non-zero and prints `vsm.log`, never silently continues (Task 2 step 7, run from repo root). `ROOT_DIR` resolution is verified by inspection (`cd "$ROOT_DIR"` before build/start) plus successful config loads in normal runs — the pre-existing compose/tofu lines assume repo-root CWD, so a full foreign-CWD run is out of scope (controller ruling, see SDD ledger).
- E2e mode must not start a host binary or create `vsm.pid` → verified by inspection of the `MODE` gate + `sh -n` (Task 1 step 3); no e2e stack run needed.

---

### Task 1: `setup.sh` integration autostart

**Files:**
- Modify: `test/presetup/setup.sh` (append after the `tofu apply` line; add root-dir resolution near the top)
- Docs (commit together): `docs/superpowers/specs/2026-11-24-integration-vsm-autostart-design.md`, `docs/superpowers/plans/2026-11-24-integration-vsm-autostart.md`

**Interfaces:**
- Produces: `vsm.pid` (single line, background PID) and `vsm.log` at repo root; a listening VSM on `localhost:3000` answering `/` with 302 when setup exits 0. Task 2's cleanup consumes exactly these two files.

- [ ] **Step 1: Confirm the failing baseline**

Run: `npm run test` (repo root, timeout ≥ 300 s).
Expected: setup succeeds, then `test result: FAILED. 0 passed; 12 failed` with `ConnectionRefused` on `127.0.0.1:3000` (panics at `tests/support/mod.rs:103`). This is the failing test the change must flip.

- [ ] **Step 2: Implement the integration branch in `test/presetup/setup.sh`**

Near the top (after `MODE=$1`), resolve the repo root from the script location:

```sh
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
```

After the existing `tofu apply --auto-approve` line, append (exact readiness-loop copy from CI; `exit 0` is fine — nothing follows):

```sh
if [ "$MODE" = "integration" ]; then
    cd "$ROOT_DIR"
    cargo build --release || exit 1
    nohup ./target/release/vsm > vsm.log 2>&1 &
    echo $! > vsm.pid
    for _ in $(seq 1 60); do
        status=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/ || true)
        if [ "$status" = "302" ]; then
            echo "VSM ready on localhost:3000 (HTTP $status)"
            exit 0
        fi
        echo "Waiting for VSM on localhost:3000 (HTTP ${status:-none})"
        sleep 1
    done
    echo "VSM did not become ready; log follows:"
    cat vsm.log
    exit 1
fi
```

Keep the user's `tofu` lines and everything else byte-identical.

- [ ] **Step 3: Syntax + gate check**

Run: `sh -n test/presetup/setup.sh` → no output, exit 0.
Inspect: the whole new block is inside `[ "$MODE" = "integration" ]`; e2e path creates no `vsm.pid` and starts no host process.

- [ ] **Step 4: Run the suite — must pass now**

Run: `npm run test` (timeout ≥ 600 s; first release build may take minutes).
Expected: readiness line `VSM ready on localhost:3000 (HTTP 302)`, then `test result: ok. 12 passed; 0 failed`. Note: `posttest` teardown does NOT yet kill VSM — a running `target/release/vsm` process afterwards is expected at this stage (Task 2 fixes it).

- [ ] **Step 5: Commit**

Load `agent-commit-attribution` first. Stage the two docs and `test/presetup/setup.sh`.
RULING (user approved "commit it all" at handoff): commit `setup.sh` as-is, INCLUDING the user's `terraform` → `tofu` hunk. Do NOT stage the unrelated untracked `2026-11-24-opentofu-migration*` docs.
Message: `test: start VSM automatically for local integration runs`

### Task 2: `cleanup.sh` stops VSM

**Files:**
- Modify: `test/presetup/cleanup.sh` (add PID kill + file removal before the compose down)

**Interfaces:**
- Consumes: `vsm.pid` / `vsm.log` at repo root (Task 1).
- Produces: after `npm run teardown`, no `target/release/vsm` process, no `vsm.pid`/`vsm.log`; exit 0 even when the PID is stale or absent.

- [ ] **Step 1: Observe the failing condition**

With the stack/VSM left from Task 1 step 4, run: `pgrep -af 'target/release/vsm'`.
Expected: a live process — teardown currently leaks it. That is the defect this task fixes.

- [ ] **Step 2: Implement the kill in `test/presetup/cleanup.sh`**

At the top (script already assumes repo-root CWD, matching its existing relative `test/presetup/...` path):

```sh
# Stop a locally started VSM (integration mode)
if [ -f vsm.pid ]; then
    kill "$(cat vsm.pid)" 2>/dev/null || true
fi
rm -f vsm.pid vsm.log
```

Leave the existing compose down and tfstate removal unchanged.

- [ ] **Step 3: Syntax check**

Run: `sh -n test/presetup/cleanup.sh` → exit 0.

- [ ] **Step 4: Teardown kills the leftover**

Run: `npm run teardown`, then `pgrep -af 'target/release/vsm'` and `ls vsm.pid vsm.log`.
Expected: pgrep finds nothing (exit 1), both files gone, teardown exit 0.

- [ ] **Step 5: Stale-PID tolerance**

Run: `echo 999999 > vsm.pid && npm run teardown`.
Expected: exit 0, `vsm.pid` removed, no error output from kill.

- [ ] **Step 6: Full end-to-end run**

Run: `npm run test` (timeout ≥ 600 s).
Expected: `12 passed; 0 failed`, and afterwards `pgrep -af 'target/release/vsm'` finds nothing (posttest now cleans up).

- [ ] **Step 7: Failure path (port 3000 occupied)**

Occupy port 3000: `python3 -m http.server 3000` in background (note its PID).
Run from the REPO ROOT: `./test/presetup/setup.sh integration` (timeout ≥ 300 s).
Expected: exit 1 after ~60 s of waiting, output ends with `VSM did not become ready; log follows:` and `vsm.log` content showing an address-in-use bind error (NOT a missing-config error — that would mean root resolution is broken).
Then: kill the python listener, `npm run teardown` (also removes the failed run's `vsm.pid`/`vsm.log`).

- [ ] **Step 8: Commit**

Load `agent-commit-attribution` first. Stage `test/presetup/cleanup.sh` (and `setup.sh` too if it was left unstaged in Task 1 and the user has since approved).
Message: `test: stop the local VSM process during teardown`
