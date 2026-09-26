# E2EE media slice 6.4 — rejoin affordance (leaf-verify gate HIGH-1 re-plan)

Status: PLAN — AUDITED (media-e2ee-reviewer, 2026-07-12): APPROVE-WITH-FIXES.
All audit findings folded below (§7); implement per this amended version.
Amended 2026-09-26: §8 (resume — a device returning inside the leave-grace
keeps its group and sends no intent, so §3 becomes the fallback) and §9
(serve-then-admit: tried and parked, and the epoch-keyed guard that closed
the ≥ 7-member kick).
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

## 8. Resume: a returning device keeps its group

Status: DESIGNED, landing. Ships with the frontend branch
`fix/mls-rejoin-resume-w2` (wave 2, the foundations, committed `918c246e`;
wave 3, the resume itself, in progress). Not on frontend `main` yet: until
that branch merges, every return takes §3's path. This section describes
the designed behavior (join-latency "resume" plan, operator-approved
2026-09-25). **No server, native or protocol change** — the resume uses two
existing DS read routes.

### 8.1 Why

§3's path costs ~11 s of dead air: measured 11.0–11.2 s on 3/3 rejoins
(two-seat legs, 2026-09-08), against 0.7–1.0 s for a clean join. The cost
exists because the returning client DELETES its own MLS state (the startup
wipe on reload, `#teardownGroup` on hang-up), so its leaf is stale and two
commits by OTHER members must re-seat it: the Remove (§3.4), then the Add
after the joiner's blind 10 s retry (`JOINER_RETRY_MS`). Three attempts to
make that Add sooner failed audit (§9). The resume removes the reason for
the dance instead: a device whose leaf is still current keeps the state
that leaf belongs to.

### 8.2 Who resumes

Only a device that returns while its leaf is still in the roster, i.e.
inside the peers' leave-grace (`LEAVE_GRACE_MS = 10_000`):

- **Ctrl+R / crash:** the native rows are still on disk (page death runs no
  MLS teardown).
- **Hang-up → rejoin:** `dispose()` no longer tears the group down. It
  clears the channel's downgrade grant first (`callClearDowngrade`, so a
  kept row cannot carry a confirmed-downgrade grant into the next call),
  then KEEPS the group for `LOCAL_GROUP_KEEP_MS = 10_000` and deletes it
  when that expires.

Either way a resume REQUIRES a recency record,
`sessionStorage["mls-resume:<channelId>"] = { groupId, epoch, at }`,
naming the same group and no older than 10 s. It is refreshed on every key
install, every reconcile tick while active, and on an accepted keep, and
deleted on every immediate-delete reason. It stops a hostile DS steering a
device into an older group it still holds, and it guarantees a dead page's
leftover rows are never resumed.

Not resumed (today's path): a full app restart (`sessionStorage` is gone);
a network-blip auto-rejoin (it fires only after ~12 s of state mismatch
plus a backoff, past the grace, when peers have already removed the leaf →
a clean join); any return after 10 s. Never kept, deleted at once:
sign-out, E2EE disable/wipe, account mismatch, `removed_self`,
poisoned/desync.

### 8.3 The path

1. **Prefetch, read-only, overlapping the SFU connect.** Started before
   `room.connect`, so it runs while ICE/DTLS does. Candidate = the
   channel's kept group (claimed, its expiry timer suspended) or the
   recency record's group. In parallel: the open-group GET
   (`/mls/channels/<channel_id>/open_group`, `group_open.rs`), native
   `callState(candidate)`, the native pending-commit probe; then ONE
   commits fetch (`/mls/groups/<id>/commits?from_epoch=<local + 1>`,
   `commits_fetch.rs`), whose `current_epoch` is the DS's current epoch.
   Nothing is applied. A superseded connect aborts it and hands the claim
   back.
2. **Decision** (pure `resumeDecision`, `mlsRejoinPolicy.ts`). Resume only
   if ALL hold: the open-group GET was for the intended channel and names
   the held group, and native's channel for it matches; native state
   `active` with self in the roster; no pending own commit; no fetched
   commit was committed by this device; `0 ≤ current − local < 12`; the
   fetched list is exactly `current − local` commits, contiguous from
   `local + 1`; the prefetch is ≤ 10 s old; this is the session's startup
   establish (a re-establish never resumes). Anything else → join.
3. **DS verdict.** The open-group GET is a DS answer exactly as the
   create-409 is on the ladder, so it is this route's verdict; no epoch-0
   group is minted.
4. **Catch up.** Under the session lock, each fetched commit goes through
   the same inbound path a live commit takes. Native apply is strictly
   consecutive; a `duplicate` (a drained copy already applied) is clean;
   the first commit that does not apply cleanly ends the catch-up. Then
   native `callState` must show self present at `epoch == current_epoch`.
   A `removed_self` arriving during establish is recorded and acted on only
   if native confirms self absent — never replayed blindly.
5. **Adopt.** Release the keep entry (only if the group is not already
   being deleted), clear the downgrade grant, install every member's keys
   at the current epoch, then the UNCHANGED fail-closed path: roster
   consistency → enable → gate release.

**Sent: nothing.** No join intent, no KeyPackage, no Welcome, no commit,
and no self-Update (membership did not change; post-compromise security
still comes from the lowest leaf's 10-minute heartbeat).

### 8.4 What the DS and peers see; effect on §3

- Two existing read routes, both already gated: `open_group` needs channel
  access; the commits fetch needs a device-bound session AND current group
  membership (NotFound otherwise) and returns at most
  `MAX_COMMITS_PER_FETCH` (100) commits, far above the lag bound of 12.
- **No join intent, so the DS never fans out `rejoin: true`**, no member
  runs `#serveRejoin`, and no Remove or Add is committed. The `rejoin` flag
  (§3.1) now fires only on the fallback.
- **Solo reload:** the sole member resumes without an intent, so §3.1's
  solo-stale close is not reached on this route; the group stays open.
- **Peers need nothing new.** The return clears their pending leave-grace
  Remove, and the returning device installs every member's keys exactly as
  a join does.

### 8.5 Fallback: §3, unchanged

On a `join` decision, a null prefetch, a prefetch that outlives its bound,
or ANY catch-up outcome other than caught up, the device, in order: aborts
the prefetch; deletes the kept group for the channel (awaited and bounded —
a timeout fails LOUD, never falls through into the ladder); ensures its
KeyPackages are published; runs today's create-or-join ladder from the
top. It therefore arrives with wiped state, and §3 applies exactly as
written — including §3.4's `rejoin` serve when its old leaf is still
rostered. The two-commit ladder, `#serveRejoin`, `#removeStaleLeaf`,
`JOINER_RETRY_MS` and `REJOIN_SERVE_SUPPRESS_MS` are not modified.

### 8.6 Security

- **Fail closed, no speculative release.** Publishing on the held keys
  before any DS answer was designed and REJECTED: if a member left while we
  were away, releasing under the held epoch lets that removed member read
  our media, silently. The gate releases only through the unchanged path,
  after the verdict and the catch-up.
- **Server can never grow a roster** — unchanged; the resume adds nobody.
- **Hostile DS:** steering into an old group is blocked by the recency
  record and the channel binding; a padded or reordered commit list fails
  the count and contiguity checks; a device resumed at epoch N while a peer
  publishes at N+1 goes loud within the re-securing escalation bound.
- **Frame keys:** a resumed FrameCryptor reuses the epoch's frame key, so
  IV uniqueness rests on the random SSRC (recorded, accepted).
- **Residuals / follow-ups:** a page that dies inside the 10 s leaves rows
  on disk until the next establish on that channel sweeps them (never
  resumed: no valid record); a background keep-expiry delete can race an
  `e2ee_wipe` (fix is native). Follow-ups: a device-level + `group.open`
  gate on the commits fetch; a client-requestable re-drain; a native
  `GroupAlreadyExists` test; a boot-time kept-group sweep.

### 8.7 Target

MLS-attributable time ≤ 0.1 s (the resume run's `connect.add` →
`resumeGate emptied`, minus the same seat's fresh-join `room.connect` +
enable republish, same sitting); advisory total ≤ 0.5 s; zero Remove/Add
commits in any admitter log; a solo reload resumes with no DS close. What
remains between that and a literal 0 is the SFU connect and the enable-time
republish, not MLS. Live legs are owed; none has run.

## 9. Serve-then-admit: tried and parked

A record, so nobody re-derives it. **None of this is in the product**;
§3.4 step 6 ("No Add is staged here") stands.

### 9.1 What it was

Lever 1 of the join-latency plan (2026-09-20): the member whose stale-leaf
Remove WINS arbitration chains the admit (`#tryAdmit`) on the SAME rejoin
intent at once, instead of waiting for the joiner's intent #2. `"won"` was
pinned narrowly (only after the DS accepted and `callCommitWon` resolved).
Aim: 11 s → ~1.5–2 s with no DS or joiner change.

### 9.2 The stagger-window mechanism

Every verifying member schedules its own serve at `leafIndex × 2 s`
(§3.4 step 5). Today the Add lands ~11 s after the Remove — outside a
higher-leaf member's stagger window in a small call. Chaining moves the Add
to ~1.5–2 s, INSIDE it. A higher-leaf member's already-scheduled serve then
fires after the re-add; its fresh `callState` finds (user_id, device_id)
present — the fresh leaf is indistinguishable from the stale one (§2) — and
it removes the live, just-readmitted participant and chains its own Add:
kicked and re-admitted once per higher-leaf member, the replace loop §2
rejected the atomic variant for. §3.4 step 4's idempotence ("absent means
another member already served it") holds only while the Add lands after
every scheduled serve.

### 9.3 Three rounds

1. **Audit FAIL (2026-09-20), blocker W2-1:** the above, reproduced with a
   third-seat probe. Fix: retire a scheduled serve when an inbound commit
   removes its target (a `#removedSince[id] = epoch` memo), reconcile on
   every applied commit, a fire-time memo belt.
2. **Re-audit (2026-09-21), PASS WITH FIXES, two MAJORs of the same
   class:** W2R-2 — the recent-add re-check and the memo both ran BEFORE
   `await callState` and were not re-checked after it, so a Remove + Add
   applied during that IPC defeated both; W2R-1 — the retire skipped a
   serve held on a bare `null` reservation, and the scheduling epoch was
   read after the removal (Remove at N+1, chained Add at N+2: the memo
   compared N+1 ≥ N+2 and was off). Fix: a snapshot before the window plus
   after-read re-checks.
3. **Audit FAIL (2026-09-21), blocker W2F-1:** the W2R-1 guard was a
   change detector over a map that can be deleted INSIDE its own window.
   `#removedSince` was deleted by `onParticipantLeft` and by a won own
   admit; undefined → set → deleted reads "no change", and the serve went
   ahead onto the live leaf. A rejoin IS a participant leaving and
   returning, so this is the common case, not a corner. Also: W2F-2, the
   two new after-read re-checks masked each other (delete either alone and
   every case stayed green); W2F-3, the reconcile-on-commit mutant was
   killed only at a plumbing assertion, not a behavior.

### 9.4 Why every guard was deletable

Three of the four belts were difference- or freshness-based over MUTABLE,
DELETABLE state: the `#removedSince` memo (cleared by `onParticipantLeft`
and by a won own admit) and `#recentAdds` (the recent-add check, §4.8 of
the frontend rejoin-after-reload design, maintained by the roster diff).
None was a fact about the leaf that could not revert inside its own
window, and a spec can only ever show that SOME belt held. Each fix pass
closed one interleaving and a new one appeared — and the gate stayed green
while it did. What a future attempt needs: a guard that is monotonic and
cannot be deleted inside its own window, e.g. an epoch-keyed fact about
the leaf carried by the commit stream itself, so "this identity was
removed at or after the epoch my serve was scheduled against" can never
revert to "no change".

### 9.5 Ruling (operator, 2026-09-23)

Asked to choose between an 11 s delay and a possible kick of a live
participant: **park serve-then-admit; ship the instrumentation** (the join
timeline, merged to frontend `main` as `fb29b21e`). The parked tree is the
frontend tag `snapshot/joinlat-w2-parked` = `e1f7aab6` (local to the build
box, not pushed). An earlier amendment of THIS document that described
serve-then-admit as the behavior (backend branch `docs/join-latency`:
`7df11359`, `d57edd9a`, `a6e0ebc7`; local, never pushed) must not be
merged; this section replaces it.

### 9.6 The ≥ 7-member kick and the epoch-keyed guard

The multi-member harness built for the resume found the same class on
TODAY's path, with no chaining at all. In an E2EE call of ≥ 7 members, a
rejoin inside the grace got the freshly re-seated participant removed
again by the member at leaf ≥ 6: its serve fires at `leaf × 2 s` ≥ 12 s,
after the Add (~10.5 s). On a non-admitting member `#recentAdds` is
written only by the roster diff of the 5 s reconcile, so the fire-time
check was blind, `callState` showed the fresh leaf, and the serve removed
a live member. At 7 seats (real constants): Remove won 0.5 s, re-intent
10.25 s, Add won 10.5 s, leaf-6 serve 12.25 s → Remove at epoch 9 → the
victim wipes and re-enrolls again; 14/20 phase offsets. At 8–9 seats
leaf 7 removed it a second time in 10/20; leaf 8 (16 s) never. Damage per
hit: one extra re-enrollment cycle.

Fix (wave 1.5 of the resume plan; merged to frontend `main` as `9139682a`,
shipped in v0.63.0), in the ruling's shape:

- `#removedAtEpoch`: identity → the HIGHEST epoch at which a commit removed
  it. Written from every inbound commit for our group and from this
  member's own won Removes; max-merge only; cleared only on a group change,
  together with every scheduled serve. Never deleted by a leave, an admit,
  a reconcile or a roster diff — that is the whole point.
- A serve records `scheduledAtEpoch` from the `callState` that confirmed
  the stale leaf. The deciding check runs inside the commit build UNDER the
  session lock, immediately before `callRemove`: if the target was removed
  at an epoch after `scheduledAtEpoch` (`serveTargetStillStale` false), the
  serve refuses with `mls_serve_target_fresh`, a benign no-op like
  AUD-MED-1's `mls_group_not_found`. It also refuses if the session's
  generation or group changed since scheduling.
- **Why it is complete:** under the lock no commit applies concurrently.
  `callRemove` can find the target present only if no Remove of it was
  applied (the leaf is stale; serving is correct) or a later Add was —
  which implies its Remove, at an earlier epoch, was applied first and
  recorded, so `removedAtEpoch > scheduledAtEpoch` and the serve refuses.
- **No lockout:** a refusal retires only that one serve; the rejoiner's
  next re-broadcast anchors afresh, so a genuinely stale leaf is still
  served.
- **Out of scope, recorded:** a stale rejoin re-broadcast arriving AFTER
  the re-add schedules a new serve anchored after the Remove, and a slow or
  ledger-re-driven serve can anchor after the Add; both are still guarded
  only by the recent-add check. Closing them needs intent freshness (a DS
  or native change; cf. the deferred signed freshness token, AUD-MED-2).

The wave-1.5 audit judged this guard to close the parked serve-then-admit
class as well (a chained Add at 1.5–2 s: the victim's Remove at epoch + 1
postdates a higher-leaf member's anchor). Serve-then-admit has NOT been
re-attempted; the resume plan does not retry it, and §8 takes the serve
out of returns inside the grace altogether.
