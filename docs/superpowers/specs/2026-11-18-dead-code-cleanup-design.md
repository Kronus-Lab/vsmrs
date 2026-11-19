# Dead-code suppression cleanup — design

Date: 2026-11-18
Scope: Rust rewrite worktree at `upstream/.worktrees/rust-rewrite/`

## Intent

Remove every `#[allow(dead_code)]` from the rewrite and use the compiler to prove there is no dead code left, rather than assuming the suppressions are stale.

## What we found

All five attributes are vestigial — every item they cover is live:

| Attribute | Item | Live use |
|---|---|---|
| `src/main.rs:10` | `mod session;` | imported across web handlers |
| `src/config.rs:21` | `flask_secret` | `state.rs:25` cookie signing key |
| `src/config.rs:32` | `auth_client_secret` | `oidc.rs:108` confidential-client auth |
| `src/config.rs:49` | `Mapping` | config, authz, web, state |
| `src/authz.rs:20` | `authorized` | `web/api.rs:122` |

The comments at `config.rs:20,31` ("Consumed by the ... modules added in later tasks") are stale: those modules now exist.

## Goals / non-goals

- Goal: zero `dead_code` suppressions in the crate; compiler confirms no dead code.
- Goal: any genuinely dead item found is either wired up or deleted, not re-suppressed.
- Non-goal: adding a `#![deny(dead_code)]` lint gate (deferred; only if the sweep is clean).
- Non-goal: changing runtime behavior.

## Approaches

1. Compiler-led sweep (chosen) — remove all five, run `cargo check --all-targets`, triage warnings. Proves the claim; may surface fresh warnings to resolve.
2. Manual audit only — rejected: cannot rule out unsuppressed dead code.
3. Strict gate — deferred: build-policy change, evaluate after (1) is clean.

## What's left to the builder

- Remove the five attributes (and the two stale "added in later tasks" comments if they no longer describe anything).
- Run `cargo check --all-targets` in the worktree.
- For each warning: wire the item into its real call site or delete it. Do not re-add a suppression.
- Re-run the check until clean; report the final warning count.
