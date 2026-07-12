# E2EE media slice 6.4 — rejoin affordance (leaf-verify gate HIGH-1 re-plan)

Status: PLAN — AUDITED (media-e2ee-reviewer, 2026-07-12): APPROVE-WITH-FIXES.
All audit findings folded below (§7); implement per this amended version.
Supersedes the frontend-only HIGH-1 fix attempted in
`e2ee-media-slice-6.4-leaf-verify-fix.md` (gate re-verify proved it
inoperative: native `mls_call_remove` commits `remove_members(&[own_index])`
and OpenMLS forbids self-removal — `CreateCommitError::CannotRemoveSelf`,
RFC 9420). Corollary discovered: `#teardownGroup`'s self-remove has been dead
code since step 6; call-end roster cleanup actually rides peers'
SFU-disconnect leave-grace `#removeMember`.

## 1. Problem

A device that escalates `rejoin_fresh` (desync park-exceeded, submit timeout,
leaf unverifiable after reconcile) wipes local group state, but its stale leaf
stays in the DS roster and the MLS tree:

- `POST /mls/groups/<id>/join_intent` 400s an already-member device
  (`join_intent.rs:84-93`), so the fresh intent is refused;
- admitters skip already-members (`#tryAdmit` membership re-check), so no
  Welcome is ever sent;
- peers' ghost-remove (`#removeMember`) never fires — it requires the
  identity to be ABSENT from the SFU, and the rejoiner is still connected.

Nobody can remove the stale leaf: the rejoiner may not (CannotRemoveSelf),
and peers have no signal to. Result: bounded-loud RE-SECURING with manual
hang-up/re-call as the only recovery.

## 2. Design (one line)

An already-member device's signed join intent is accepted by the DS and
fanned out flagged `rejoin: true`; verifying members REMOVE the stale leaf
(peers CAN remove others — the existing arbitrated `callRemove` path); the
joiner's next 10 s intent retry then rides the existing normal
join → admit → Welcome flow unchanged.

Rejected alternative (atomic Remove+Add in one commit inside
`mls_call_admit`): converges in one epoch, but a second racing admitter
cannot distinguish the stale leaf from the freshly replaced one — the roster
entry is identical (user_id, device_id) before and after, `mls_call_admit`
does not ref-match the claimed KeyPackage to the intent's `key_package_ref`,
and leaf nodes retain no KP hash-ref — so a staggered second admitter would
replace the fresh leaf, kicking the joiner it just admitted (replace loop).
Remove-only is naturally idempotent: the second admitter's fresh
`callState` check finds the member gone → no-op. It also reuses the two
already-gated flows (admit, remove-other) byte-identical.

Rejected alternative (native `leave_group()` self-remove proposal): requires
peer-side commit-of-pending-proposals machinery that does not exist in the
lifecycle engine, a new envelope kind through the DS, and reopens the gated
OpenMLS surface — strictly more new mechanism for the same outcome.

## 3. Changes

### 3.1 Server (stoatchat, `crates/delta/src/routes/mls/join_intent.rs`)

Replace the already-member 400 arm:

- **Same device already a member** (`existing.device_id == data.device_id`):
  - If `group.members.len() == 1` (the sole member IS the stale self):
    close the group (`db.close_mls_group(&group.id)` — already exists on
    BOTH drivers, used by the supersede flow) and return 204 with no fan-out.
    Nobody can serve this rejoin (no other leaf-holder exists) and the sole
    member's group secrets are wiped by definition of rejoin-fresh — closing
    lets the joiner's next `#establish` take the CREATE path.
  - Else: continue exactly as a normal intent (signature defense-in-depth
    verify, slowmode upsert, fan-out) but with `rejoin: true` in the event.
- **Different device of the same user already a member**: 400 unchanged
  (one-device-per-user, plan §1.5).

`EventV1::MlsJoinRequested` gains `rejoin: bool` (`events/client.rs:434`).
Normal joins fan out `rejoin: false`. bonfire relays the variant untouched
(rebuild only). Update the two destructures in `routes/mls/tests.rs`.

### 3.2 Native (acutest-desktop, e2ee-core + shell) — one thin READ-ONLY IPC

`e2ee_call_verify_join_intent(request) -> Result<()>`: a wrapper over the
existing internal `credential::verify_join_intent` (credential.rs:375, already
used inside `mls_call_admit`). No OpenMLS interaction, no state mutation, no
new crypto. Registered in e2ee.rs / build.rs / lib.rs; bridge method
`callVerifyJoinIntent`.

Why required: the rejoin event triggers a REMOVE of a current member. The
server relay must never be the trust decision (invariant §1.4) — a member
only acts on a rejoin whose signature verifies against its own pinned
identity for the claimed device. Without it, a hostile DS could fabricate
`rejoin: true` events with garbage signatures to kick arbitrary members.

### 3.3 Frontend joiner side (`mlsCallSession.ts`, `e2ee.ts`)

- `mlsJoinIntent` gains a typed `not_found` outcome (`#apiMls` opt-in 404
  mapping, mirroring the existing `mfaRetryable` opt-in): the solo-stale
  close (§3.1) surfaces as `not_found` on the joiner's NEXT intent attempt →
  `#scheduleReestablish("group closed")` → `#establish` →
  `routeCreateOrJoin` → the closed group no longer conflicts → CREATE path →
  solo epoch-0. Bounded by the existing `MAX_REESTABLISH = 3`.
- Delete `#removeSelfBestEffort` and its `#rejoinFresh` call entirely;
  `#teardownGroup` reverts to `#safeLeave` only, with an honest comment that
  call-end roster cleanup is the peers' leave-grace removal. (The mechanism
  is provably inoperative; keeping it masks the gap.)
- The existing `#joinPath` intent try/catch (gate-fix round) stays — it
  covers transient errors and the different-device 400.

### 3.4 Frontend admitter side (`mlsCallSession.ts`, `e2ee.ts`)

`MlsJoinRequest` type += `rejoin: boolean`; `onEvent` passes
`rejoin: event.rejoin ?? false` through the sink.

`#onJoinRequest`: when `request.rejoin` is set, route to a new
`#serveRejoin(request)` instead of admit scheduling:

1. Same guards as today (state `active`, group matches).
2. Dedup via `#scheduledAdmits` under a DISTINCT key
   (`rejoin:${user}:${device}`) so the timer cannot collide with the
   subsequent real admit's key; reserve the key BEFORE any await (also
   fixes gate LOW-1's check-then-await race for this new arm).
3. `await bridge.callVerifyJoinIntent(request)` — refuse (return, no
   removal) on any failure. Also `await #reconcileRoster([user])` first so
   an unpinned-but-honest rejoiner verifies (same reason as the admit path;
   fail-closed per user).
4. Fresh `callState`: proceed only if (user_id, device_id) IS a current
   member — absent means another member already served it (idempotence).
5. Stagger by own leaf index (`leafStaggerDelayMs`, same liveness heuristic
   as admits), re-check state + membership after the delay, then
   `#stageAndSubmit(() => callRemove(user, device), "remove")` — the
   `#removeMember` pattern MINUS its SFU-absence precondition (the rejoiner
   is present in the SFU by construction).
6. No Add is staged here. The joiner's next intent (≤10 s) is a normal join
   served by the unchanged admit flow.

### 3.5 Convergence + bounds

t=0 intent#1 → 204, rejoin fan-out; stagger ≤ ~3 s; Remove commit ≈1 s
round-trip → roster clean by ≈t+5 s; t=10 s intent#2 → normal join → admit +
Welcome ≈2 s → joined by ≈t+15 s. Joiner window is 4 attempts × 10 s = 40 s
(`MAX_JOINER_RETRIES = 3`), slowmode 5 s < 10 s retry — comfortable margin.
If NO member serves the rejoin (all offline / none active): intents exhaust →
loud RE-SECURING exactly as today (strictly better in every served case,
never worse). Each rejoin consumes one claimed KeyPackage on the eventual
admit — same cost as any join (cap accounting is the separate tracked issue).

## 4. Security analysis

- **Server can never GROW a roster** — unchanged. The rejoin affordance only
  triggers removals; Adds still require a member's native
  intent-verify + claim + `callAdmit`.
- **New power introduced**: a validly-signed join intent from a device that
  is CURRENTLY a member causes members to remove that device's own leaf
  (self-eviction by proxy — exactly the self-remove MLS forbids, effected by
  peers with client-side signature verification as the trust gate).
- **Replay**: a hostile DS replaying a captured intent (every member except
  the creator produced one) can trigger removal of a healthy member. The
  victim's session sees `removed_self` → ack → RE-SECURING; its own
  rejoin-fresh then converges back through this very affordance (kick →
  auto-recover churn). Availability-only: rekey excludes the removed leaf,
  no confidentiality or integrity impact, and a hostile DS can already deny
  service outright (drop envelopes, refuse routes) — within the accepted
  threat model (untrusted DS degrades availability, never secrecy).
  Slowmode (5 s per group/user/device) bounds the churn rate.
  - The kp_ref-based replay hardening considered here was VERIFIED UNSOUND
    and is dropped: the intent's `key_package_ref` is ADVISORY by design
    (native `mls_call_join_intent` nominates a deterministic pick that may
    already be server-side-claimed; the DS claim route serves a
    server-chosen package; the Welcome-acceptance gate keys on group_id,
    not the ref) — so "ref must exist unclaimed" would 400 legitimate
    rejoins. Replay stays availability-only, slowmode-bounded.
- **Malicious rejoiner**: can only evict ITSELF (signature binds user+device;
  the removal target is exactly the signer). A member spamming rejoin
  intents costs the group rekeys at ≥5 s intervals — equivalent to the
  already-possible join/leave churn; cap unchanged.
- **Welcome acceptance gating** on the joiner (native `mls_join_intents`
  TTL table) is untouched — a rejoin-triggered Welcome is accepted only
  because the joiner itself recorded a fresh intent.
- **Solo-stale group close**: the DS already owns group lifecycle rows
  (create/supersede); closing a group whose only leaf-holder has provably
  lost its state has no confidentiality impact and unblocks the CREATE path.
  A racing other-user join_intent on the just-closed group gets 404 →
  its own re-establish converges via create-or-conflict.
- **Removed-self on the victim**: existing `ack_removed_self` →
  `#onRemovedSelf` → RE-SECURING path, unchanged.

## 5. Failure modes

| Scenario | Outcome |
|---|---|
| No admitter online/active | Intents exhaust → loud RE-SECURING (= today) |
| Remove loses arbitration | Loser rebases (existing `#stageAndSubmit` Lost path); membership re-check on any later rejoin event → converges |
| Target vanished between check and stage | Pre-checked at step 4/5; residual race → native remove errors → `#onLoud` on that admitter (pre-existing `#stageAndSubmit` semantics, same as ghost-remove) |
| Rejoin event to old clients (mixed versions) | Unknown field ignored → treated as normal join → `#tryAdmit` membership check → skip (harmless no-op; one wasted claim avoided by the check ordering) |
| Joiner crashes mid-rejoin | Stale leaf removed anyway; on restart, fresh create-or-join proceeds normally |
| Replayed rejoin intent | Availability churn only (§4); optional kp_ref hardening shrinks it |

## 6. Tests

- Server (REFERENCE driver): same-device member intent → 204 + fan-out with
  `rejoin: true`; solo-stale → group closed + 204 + no fan-out; different
  device → 400 unchanged; non-member → normal `rejoin: false`.
- Frontend: extract the `#onJoinRequest` routing decision (normal admit vs
  serve-rejoin vs ignore) into a pure `joinRequestAction()` policy module +
  `node --test` spec (mirrors `mlsDrainPolicy` precedent): rejoin+member →
  remove; rejoin+absent → ignore; rejoin+self → ignore; normal+member →
  ignore; normal+absent → admit.
- Live two-desktop re-proof of the reactive path is now possible: force a
  desync (park-exceeded) on one side and observe rejoin_fresh → Remove →
  re-admit → keys re-installed, both sides encrypted.

## 7. Audit findings folded (media-e2ee-reviewer, APPROVE-WITH-FIXES)

- **AUD-HIGH-1 — auto-recovery on `removed_self` (REQUIRED).** The §4 replay
  analysis assumed a kicked member converges back; in current code
  `#onRemovedSelf` only sets RE-SECURING (no re-establish anywhere:
  reconcile/heartbeat early-return off-active, no onStateChange rejoin). Fold:
  `#onRemovedSelf` schedules a re-establish IFF this device is still an SFU
  participant (`media.sfuParticipants()` includes `media.localIdentity()`),
  bounded by the existing `MAX_REESTABLISH`; not-in-SFU (genuine call end /
  our own leave) stays RE-SECURING as today. This makes BOTH the replay-kick
  and a false-positive ghost removal genuinely self-heal through this very
  affordance, and makes §4's acceptance argument true. Sustained replay at
  the 5 s slowmode rate = rekey churn (availability-only; each successful
  rejoin resets the re-establish budget, so the loop is per-cycle bounded,
  never wedged, never plaintext).
- **AUD-MED-1 — target-absent Remove must be a benign no-op (REQUIRED).**
  The stagger design makes concurrent same-target Removes LIKELY; the loser
  reaching `callRemove` after the target is gone gets native
  `mls_group_not_found` (the missing-target error) and `#stageAndSubmit`'s
  build-catch would `#onLoud` a healthy admitter into terminal `failed`.
  Fold: for `kind === "remove"`, a `mls_group_not_found` build error is a
  quiet return (covers `#serveRejoin` AND the pre-existing `#removeMember`
  ghost path, which had the same latent bug).
- **AUD-MED-2 — kp_ref anti-replay hardening stays DROPPED.** Verified: the
  nominated ref is deterministic and STABLE across retries of one join
  (`ORDER BY last_resort ASC, created_at DESC, ref ASC`), and the joiner is
  not told when the server consumes it — an "unclaimed" gate would 400 the
  joiner's own attempt #2. Real anti-replay = a signed freshness token
  (nonce/timestamp inside `mls_join_intent_payload`) — DEFERRED, tracked;
  present posture = slowmode + availability-only + AUD-HIGH-1 self-heal.
- **AUD-LOW-1 — solo-stale arm verifies the signature FIRST.** Move the
  defense-in-depth `verify_payload` ahead of the member/solo branch so both
  arms verify (closes the asymmetry/refactor hazard; the close is then only
  reachable by the authenticated signing device).
- **AUD-LOW-2 — Android surface: deliberately none.** Android media E2EE is
  fail-closed (no key push → non-E2EE shell → no `MlsCallSession` → never
  calls `callVerifyJoinIntent`). The command registers in the desktop shell
  only; the Capacitor plugin is untouched (the bridge method is unreachable
  on Android, so no allowlist change is needed).
- **AUD-LOW-3 — solo recovery consumes ~2 of `MAX_REESTABLISH = 3`**
  (rejoin_fresh → join → close, then not_found → re-establish → create);
  acceptable margin, do not shrink the budget without revisiting.
