# E2EE media slice 6.4 — joiner leaf-verify (TOFU-on-Welcome) fix plan

Status: PLAN (for `media-e2ee-reviewer` audit before coding). 2026-07-12.
Companion to `e2ee-media-slice-6.4-breakdown.md`. Scope: the joiner-never-enables
gap surfaced by the step-9 live proof.

## 1. Problem (root-caused from a live instrumented rejoin + store inspection)

Two-desktop call, JeffS (admitter, device `25c9e4c4`) + b2 (joiner, device `a47b51ac`).
The joiner **receives and processes** the `MlsWelcome` (receive/drain path is 100%
healthy — verified with baked-in logs across the join-time reload). Native then
**rejects the admitter's leaf** and the Welcome is dropped:

```
processEnvelope-disp mls_welcome ep1
  {kind:"drop", reason:"mls_leaf_rejected", loud:true, successorNeeded:false, ack:true}
→ welcome_joined never fires → joinPath retries → gives up (RE-SECURING)
```

Cause (confirmed against the live SQLite stores, `peer_identities`):

- Processing a Welcome, native runs `verify_leaf_credential` (e2ee-core
  `mls/credential.rs`) on the admitter's leaf. b2 has JeffS's **call device
  `25c9e4c4`** only as a **curve-only stub**: `binding_verified=0, ed25519=NULL`
  (b2 saw a text pre-key from it but never fetched its signed device listing).
  It DOES have JeffS's *other* devices (`b592e4d0`, `f66512b3`) fully pinned.
- `verify_leaf_credential` (credential.rs:281-289): `get_peer` finds the row
  (status=active ⇒ not `UnknownIdentity`), then `if !peer.binding_verified` ⇒
  **`LeafRejection::BindingUnverified`** ⇒ whole group rejected (no partial trust).
- Asymmetry: JeffS's admit runs `verify_join_intent`, which needs b2's call device
  pinned in **JeffS's** store — and it IS (`a47b51ac binding_verified=1`) — so the
  admit succeeds and the Welcome is sent. Only the joiner→admitter direction is
  unverified.
- The disposition mapping `classifyEnvelopeError` (frontend `components/client/e2ee.ts`
  ~L549-557) collapses **every** `LeafRejection` — recoverable (`UnknownIdentity`,
  `BindingUnverified`) and hostile (`IdentityKeyMismatch`, …) alike — into one
  terminal `mls_leaf_rejected → drop + ack + loud`. The credential.rs doc-comment
  promises a "TOFU-fetch-then-pin-then-retry for unpinned identities" but it is
  **not wired into the MLS drain**.

The consequence, verified live via LiveKit room state: JeffS `isE2EEEnabled:true`
(mic+cam `encrypted:1`); b2 `isE2EEEnabled:false`, sends plaintext AND cannot decrypt
JeffS's encrypted tracks (keyless).

## 2. Key facts that shape the fix (already true in the code — no new primitives)

- The native error crosses IPC fully typed: `Error` is `#[serde(tag="type",
  rename_all="snake_case")]` and `LeafRejection` is `#[serde(rename_all="snake_case")]`
  (e2ee-core `error.rs`). So the frontend ALREADY receives:
  `{ type:"mls_leaf_rejected", user_id, device_id, reason:"binding_unverified" }`
  (or `"unknown_identity"`, `"identity_key_mismatch"`, …). **The classification info
  is present; it is simply ignored today.**
- `LeafRejection` variants (error.rs): `malformed_credential`, `signature_key_mismatch`,
  `unknown_identity`, `binding_unverified`, `identity_changed`, `identity_key_mismatch`,
  `bad_binding_signature`.
- The verified TOFU-pin primitive already exists: `E2EE.#reconcileDevices(userId)`
  (e2ee.ts:1386) → `GET /e2ee/devices/{userId}` → native `e2ee_reconcile_devices`,
  which verifies the SIGNED device listing and upgrades genuine devices to
  `binding_verified=1` (the same trust step text E2EE uses; slice-5 hardened). This is
  exactly what turns b2's `25c9e4c4` stub into a verified pin.
- The poison-on-`MlsLeafRejected` at `mls/mod.rs:980` is in `try_apply_commit`
  (COMMIT path on an existing group), NOT the Welcome/join path — so a joiner retry is
  not blocked by a poisoned group. (Native atomicity of the Welcome path on rejection
  is an OPEN item to confirm — see §6.)

## 3. Design

Reactive TOFU-on-reject: when native rejects a leaf ONLY because the peer device is
not yet verifiably pinned, fetch that peer's signed device listing (verified),
re-pin, and reprocess the SAME Welcome. Fail closed everywhere else.

Recoverable ⇔ `reason ∈ { unknown_identity, binding_unverified }`.
Everything else stays terminal/hostile, INCLUDING `identity_changed` (a pinned identity
that changed is a security event; it must surface for user re-confirmation via the
slice-5 flow — never auto-repin).

### 3.1 Frontend — classify (components/client/e2ee.ts)

- Extend `EnvelopeDisposition` with a new recoverable kind:
  `{ kind: "needs_identity"; userId: string; deviceId: string; ack: false }`.
- In `classifyEnvelopeError`, split the `mls_leaf_rejected` case: read
  `error.reason` (+ `error.user_id`, `error.device_id`). If recoverable ⇒
  `needs_identity` (ack:false — do NOT drop, do NOT ack). Else ⇒ the existing
  `drop + ack + loud`. Keep `mls_welcome_context_mismatch` terminal as-is.

### 3.2 Frontend — drain action (components/rtc/mlsCallSession.ts)

- Add `DrainAction` variant `{ do: "fetch_identity"; userId; deviceId }`.
- In `drainAction`, map `needs_identity` bounded by a retry counter: under the cap ⇒
  `fetch_identity`; at the cap ⇒ terminal loud drop (ack) — fail closed, never spin.
- In `#consume`, handle `fetch_identity`: (a) do NOT ack; (b) `await` the bridge
  device-reconcile for `userId`; (c) bump the per-envelope retry counter; (d)
  re-enqueue the SAME envelope (model on the existing `gap_refetch` re-feed) so the
  pump reprocesses it. On the re-pass native re-runs the FULL leaf check → success ⇒
  `welcome_joined` ⇒ resolves `#waitForWelcome`. If still rejected after a verified
  reconcile (device genuinely absent from the signed listing, or binding still
  unverifiable) ⇒ terminal loud drop.
- Bridge surface: expose the existing `#reconcileDevices` via the `MlsCallSessionDeps`
  bridge (e.g. `reconcileDevices(userId): Promise<void>`), reusing the verified path —
  do NOT add a second, weaker pin path.

### 3.3 Optional proactive pre-fetch (reviewer to weigh)

Before/at join, reconcile device listings for the call roster's user-ids so leaves
validate on the first Welcome pass (avoids the reject→fetch→reprocess round-trip and a
retry-window key gap). Reactive (§3.1/3.2) is the correctness guarantee; proactive is a
latency optimisation. Could gate on roster size.

### 3.4 Native (e2ee-core) — expected NO functional change

Reason is already surfaced; the Welcome path does not poison. The ONLY native work, if
§6 finds it necessary, is to guarantee the Welcome/join processing is atomic on
`MlsLeafRejected` (no half-created group / no consumed-KeyPackage side effect that would
make the reprocess fail). To confirm before coding.

## 4. Independent issue (NOT the join blocker) — KeyPackage publish 400 FailedValidation

Both devices' enrol publish fails `FailedValidation` = **cap exceeded**
(`MAX_KEY_PACKAGES=100`; mongo `revolt.mls_key_packages`: JeffS=101, b2=98). On a fresh
app start the client's `#serverKeyPackages` counter begins at 0, native regenerates a
full batch, and `current(~100)+new(~100)-already_stored(0) > 100` ⇒ reject. It did NOT
block the join (last session's dir was empty and the join still failed), but it errors
every session. Fix (separable, lower priority): sync `#serverKeyPackages` to the real
server count before replenish (e.g. seed from `mlsReplenish`/a count fetch), and/or
prune expired packages. Out of scope for the leaf-verify correctness fix; listed so it
isn't lost.

## 5. Security invariants (must hold)

1. Auto-pin goes ONLY through the verified signed-device-listing path
   (`e2ee_reconcile_devices`); never trust the leaf's self-asserted identity.
2. `identity_changed` / revoked is NEVER auto-repinned — stays loud, user re-confirms.
3. Bounded retries; on exhaustion or a still-unverifiable device ⇒ loud drop, never
   plaintext, never a weak/partial-trust admit.
4. Never ack until the Welcome is actually processed (don't lose it mid-retry).
5. No partial trust: any genuinely-hostile leaf still rejects the WHOLE group.
6. Reprocess re-runs the full native verification (no cached "already checked" bypass).

## 6. Open questions for the reviewer

- Is the Welcome/join native path atomic on `MlsLeafRejected` (no half state, no
  KeyPackage consumption) so reprocessing the same Welcome after a reconcile succeeds?
  If not, what native change makes it so?
- Retry cap + backoff: reuse `MAX_ENVELOPE_RETRIES`, or a dedicated smaller cap? The
  reconcile is a network round-trip; the joiner also has its own `JOINER_RETRY_MS`
  outer loop — avoid compounding retries.
- Reactive-only vs proactive pre-fetch (§3.3) — worth the roster fan-out?
- Does `#reconcileDevices` need call-context care (it also calls `#refreshMode` /
  `#syncRecent`, text-conversation side effects) when invoked from the call drain?
- KeyPackage cap fix (§4): fix now alongside, or separate change?

## 7. Audit-folded revision (v2 — media-e2ee-reviewer, APPROVE-WITH-FIXES 2026-07-12)

The reviewer confirmed the core mechanism and the native atomicity assumption
(§3.4 holds — `process_welcome` runs under one `BEGIN IMMEDIATE`; a
`MlsLeafRejected` rolls back the group insert AND any KeyPackage consumption, so the
same Welcome is reprocessable, NO native change). But it found the reactive-only,
`unknown_identity`-inclusive design under-recovers. Superseding changes:

- **[HIGH-1] Recoverable set = `binding_unverified` ONLY.** `reconcile_devices`
  (session.rs:2528-2548) upgrades an EXISTING curve-only stub but does NOT pin a
  brand-new device (it only reports `new_devices`). So `unknown_identity` is NOT
  recovered by a reconcile — make it terminal (or a separate bundle-fetch path,
  deferred). The root-caused bug is `binding_unverified`, which reconcile DOES fix.
- **[HIGH-2] Proactive whole-roster reconcile is REQUIRED, not optional (§3.3).**
  `verify_roster` (mls/mod.rs:268-304) rejects on the FIRST bad leaf, so a per-envelope
  retry cap can't converge a roster with N unpinned users. Reconcile all distinct
  roster user-ids at join BEFORE the first Welcome pass; keep reactive as a per-user
  safety net bounded by **distinct-users-with-progress-detection** (each round must
  newly pin a user, else fail closed) — not a flat count.
- **[HIGH-3] Cover the admitter + existing-member paths.** Reconcile the joiner's
  devices in `#onJoinRequest` (mlsCallSession.ts:1133) — fires before `callAdmit`
  (which else throws loud, sending no Welcome) and before existing members process the
  Add commit (a `binding_unverified` leaf in `try_apply_commit` hits the poison arm →
  `mls_poisoned_epoch`, which the leaf-classify never sees). Pre-fetch is the only
  no-native-change fix for the commit-poison path.
- **[MED-1] Cap-exhaustion ⇒ rejoin-fresh, not ack-drop.** A bare ack-drop wedges the
  joiner (admitter already has it in-roster ⇒ never re-sends a Welcome). Escalate to
  `#rejoinFresh` (leave-clean + fresh intent forces ghost-remove + re-add). Never plaintext.
- **[MED-2] `classifyEnvelopeError` is an ALLOW-LIST.** Recoverable branch fires ONLY
  for `binding_unverified`; every other/unknown/future reason defaults terminal. Keep
  `mls_welcome_context_mismatch` terminal when splitting the shared case arm.
- **[MED-3] `fetch_identity` action: model on `retry`, NOT `ack`.** Do not ack, do not
  add to `#seen` (dedup at #consume:1357 would drop the reprocess), bump `#retries`,
  reprocess inline bounded by the counter; wrap the reconcile so a network failure is a
  bounded transient no-ack retry; run the reconcile OFF the per-group lock (LOW-1).
- **[LOW-2] §4 numbers corrected:** native `KEY_PACKAGE_TARGET=50` (not ~100); the
  unconditional first-publish adds ~51 without reconciling the server count; stale
  packages never pruned. Still separable/later.
- **[LOW-3] Adversarial tests required:** native welcome-rollback+reprocess; frontend
  classify allow-list (unknown/future → terminal); `needs_identity→fetch_identity→cap→
  rejoin-fresh`; no-`#seen`/no-ack during retries; multi-unpinned-roster convergence.

Net: the fix is **proactive whole-roster reconcile at join + at `#onJoinRequest`**
(the real correctness mechanism, covers joiner/admitter/existing-members, no native
change) **plus** a reactive `binding_unverified`-only safety net (allow-list classify →
off-lock reconcile → inline reprocess → rejoin-fresh at cap). Still frontend-only.
