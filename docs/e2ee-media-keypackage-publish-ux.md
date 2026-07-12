# E2EE media — KeyPackage publish UX (drop call-join MFA) + cap fix

Status: PLAN (queued behind the 6.4 rejoin affordance) — for media-e2ee-reviewer
audit before implementation.

## 1. Problems

1. **Account-password prompt on first E2EE call join (DAVE-parity UX gap).**
   The FIRST `PUT /mls/key_packages` per device is MFA-gated server-side
   (mirrors the text-E2EE first key publish), so a device's first E2EE call
   join pops the `mfa_flow` modal for the account password. Discord DAVE
   never prompts account credentials at call join. One-time per device, but
   the wrong moment to interrupt (mid join), and repeated in any fresh
   profile/store.
2. **KeyPackage cap-exceeded 400 (step-9 secondary finding).** Fresh app
   start → client `#serverKeyPackages` begins at 0 → native regenerates a
   full batch → publish pushes the directory past `MAX_KEY_PACKAGES = 100` →
   `FailedValidation`, and the device can't replenish until packages are
   consumed/expire.

## 2. Trust analysis (why the MFA gate is droppable)

- The directory is UNTRUSTED by design: every claimed KeyPackage's
  `binding_signature` is re-verified CLIENT-SIDE against the admitter's own
  pinned identity for the target device (`verify_leaf_credential` in
  `mls_call_admit`). Forged directory entries are never admitted.
- The device identity itself was already MFA-gated at its own enrollment,
  and the publish route already requires the registered identity + a
  device-bound session (`assert_bound_session`). The MLS-publish MFA is a
  second gate on an already-MFA-enrolled identity.
- Removing it therefore costs NO confidentiality/integrity — only the
  defense-in-depth against directory pollution by a stolen session token
  (availability nuisance). §3.1 replaces that defense with something
  STRICTLY STRONGER (a token thief can pollute today's replenish path,
  which has no MFA; after §3.1 they cannot publish at all).

## 3. Changes

### 3.1 Server: signature-verified publish replaces the MFA gate

`PUT /mls/key_packages` (first publish AND replenish): verify EVERY included
package's `binding_signature` server-side against the registered device
identity Ed25519 for the bound (user, device) — the server already stores
that public key (`e2ee_identities`) and the binding payload is canonical.
Valid → accept with no MFA ticket. Invalid → 400. Drop the 401-MFA arm.

Effect: possession of the device identity key (which never leaves the native
store) becomes the publish credential. Strictly stronger than both today's
paths (first publish: MFA + token; replenish: token only).

### 3.2 Enrollment pre-publish (UX belt-and-braces)

Publish the first KeyPackage batch during E2EE device enrollment (the flow
where the user is already authenticating), so the first call join finds the
directory populated and never blocks on any publish at all. Frontend/native
only; rides §3.1's route.

### 3.3 Client MFA plumbing

Keep the `mfa_required` handling in `#apiMls`/`#ensureKeyPackages` as a
harmless fallback (a pre-§3.1 server still works); it should never fire
against an upgraded server. Remove in a later cleanup once deployed.

### 3.4 Cap fix (same route, folded in)

Server-side self-healing on publish: when accepting a batch would exceed
`MAX_KEY_PACKAGES`, prune the same device's OLDEST unclaimed packages to
make room instead of 400-ing. Safe: pruned entries just stop being claimable
(the Welcome-acceptance gate keys on group_id, not a specific ref — native
comment in `mls_call_join_intent`); the joiner keeps all init keys locally.
Client-side: pass the publish response's resulting count back into
`#serverKeyPackages` so the client's watermark tracks server truth (no more
regenerate-from-zero blowups).

## 4. Failure modes / notes

- Invalid-signature publish (attacker with stolen token, no identity key):
  400, nothing stored — better than today.
- Legacy devices enrolled before §3.2: first join publishes silently via
  §3.1 (no prompt) — the modal simply disappears.
- Mixed versions: old client + new server = old client offers an MFA ticket
  that the server no longer demands (accepted, ignored); new client + old
  server = `mfa_required` fallback still prompts (acceptable during rollout).
- REFERENCE + Mongo driver tests: valid-sig publish accepted without MFA;
  invalid sig rejected; cap-prune keeps newest, count returned; replenish
  after prune consistent.
