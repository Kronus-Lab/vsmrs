# Session UUID rotation on login — design (Tier 2 issue #8)

Date: 2026-11-26
Status: approved by owner (option B)

## Intent and why

Tier 2 audit finding #8 records that `GET /auth/callback` mints a fresh session
UUID (`src/web/auth.rs:133`) while CONTRACT.MD §3.3 requires reusing the UUID of
a live session cookie. Security analysis concluded the **implementation is the
more secure behavior**: regenerating the session identifier at every
authentication is the standard session-fixation defense (OWASP ASVS V3.2.1).
The contract's reuse rule is exploitable even with HMAC-signed cookies: an
attacker can legitimately obtain a signed cookie for their own session UUID,
plant it in a victim's browser (cookie tossing / sibling-subdomain XSS / shared
machine), and — under the reuse rule — inherit the victim's authenticated
session when the victim logs in.

The contract is amended to match the secure behavior, and the behavior is
strengthened one step further: the old session is invalidated on relogin.

## Approaches considered

- **A — Contract-only amendment.** Rewrite §3.3 to match today's code (always
  fresh UUID, old sessions live out their TTL). Cheapest, but a stolen old
  cookie stays valid up to the token TTL (~8 h) after relogin.
- **B — Rotate-and-delete (chosen).** Fresh UUID on every callback *and*
  deletion of the session record named by the incoming session cookie, after
  the new record is stored. Strictly more secure than both the old contract
  and the current code; small code change.

Owner picked B.

## Goals

- CONTRACT.MD §3.3 normatively requires session-ID rotation on every
  successful login and invalidation of the previous session.
- `callback` deletes the old session record (from the incoming signed
  `session` cookie) only **after** the new record is successfully stored, so a
  Redis failure cannot destroy a live session.
- The ignored test `callback_reuses_existing_session_uuid_on_relogin` is
  replaced by a test asserting rotation: new UUID ≠ old UUID, old record
  deleted, new record present.
- §12 records the intentional behavior change; §13 records the owner decision
  (2026-11-26).

## Non-goals / anti-goals

- No multi-session management or "logout everywhere" feature.
- No changes to cookie format, signing, login, logout, or the pending-login
  flow.
- Do not reintroduce UUID reuse anywhere.
- Deleting a nonexistent/expired old record is a no-op, not an error.

## Constraints

- CONTRACT.MD is normative; amendment entries must match existing §12/§13
  style.
- Static checks must pass: `npm run lint` (fmt + clippy -D warnings);
  unit tests: `npm run test:unit`.
- Delete-after-put ordering is a security property, not an optimization.

## What's left to the builder

- Exact amendment wording consistent with surrounding contract prose.
- Whether the old-UUID read happens before or after the put (read anytime;
  delete strictly after successful put).
- Checking integration tests / Cypress for relogin assumptions.
