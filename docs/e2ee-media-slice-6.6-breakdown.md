# Slice 6.6 — Hostile-DS harness + FINAL desktop audit: implementation breakdown

Breakdown for sub-slice **6.6** of [e2ee-media-mls-plan.md](e2ee-media-mls-plan.md) (plan §8
row 6.6; test matrix §6 T-01..T-21). Written 2026-07-12, **before coding** (house
audit-before-code pattern, as 6.1–6.5). This is the **FINAL slice-6 desktop slice**; its gate is
the plan's PLAN:1475-1478 final audit — **FULL PANEL: media-e2ee-reviewer + e2ee-crypto-reviewer,
with frontend-code-reviewer sign-off**.

6.5 landed everything user-visible (downgrade banner, native confirm, dual-gated chip, roster
panel, pre-join, "Encrypt my calls", the ctl-announce transport) and the only plaintext-resume
path. It deliberately deferred the adversarial-harness rounds, one twice-slipped server leg, two
drain-mechanics debts, and three cosmetic LOWs — plus the **binding live legs** that no prior
slice could run because the flag was FALSE and the reactive leaf-verify chain was only ever
unit-tested. 6.6 closes all of that and then decides the flag.

`media_e2ee_enabled` stays **FALSE** at the end of this slice unless the user says otherwise; the
deliverable is the *verdict* (§9) on whether it is cleared to flip in production, plus the
staging-only flag-ON exercise. The gitignored `Revolt.overrides.toml` flag is left **OFF** at
commit time.

Plan sections owned here: §6 (adversarial test plan, desktop-scoped), §8 row 6.6, A3(b) / D12
(`MAX_VIDEO_PARTICIPANTS` server enforcement), the two deferred drain debts (D10/D11), and the
three 6.5 tracked LOWs.

---

## 0. The 6.6 docket (accumulated from the 6.4/6.5 gates)

Verbatim from the task and the 6.5 breakdown's deferred-item table + tracked-LOWs paragraph:

1. **BINDING live legs** before any flag flip: a full **T3→T6** downgrade / re-upgrade cycle with
   a **real web participant**; the **mixed-call receive** smoke (Decline ⇒ receive-only, observed
   live); **call_full auto-leave**. (6.5 gate, both reviewers, named a binding condition.)
2. **The hostile-DS harness itself** (the media analog of text E2EE's `tests/hostile_server.rs`):
   **T-19** under-fan-out, **T-20** cap-forcing join, **T-06-extended** rotation flap, and a
   **live exercise of the reactive leaf-verify chain** (never reproduced live in 6.4 because the
   proactive reconcile persistently pinned the peer; unit-tested only).
3. **D12**: server-side `MAX_VIDEO_PARTICIPANTS` enforcement on the voice **join/token** path —
   assigned in 6.1, never landed, twice-slipped; the media reviewer's named ratification condition.
4. **Tracked smalls**: 6.4 gate **MED-2** (park during pending identity-fetch = **D10**) + **LOW-1**
   (admit dedup key set pre-await = **D11**); 6.5 LOWs (share-modal pause as a gate reason,
   pre-join fetcher's untracked toggle read, direct `#setMode`/`#modeChain` bypass).
5. **Deploy prereqs for the live legs**: rebuild+restart delta and bonfire off committed source;
   rebuild the desktop bundle (`build-desktop.ps1`); flag ON via `Revolt.overrides.toml` (**staging
   only**); two-desktop method = `SLOGA_PROFILE` instances per
   [e2ee-media-slice-6.4-step9 notes](e2ee-media-slice-6.4-leaf-verify-fix.md).

---

## 1. Contract inputs (fixed by 6.1–6.5; all committed, not pushed)

### Native engine (`acutest-desktop/src-tauri/e2ee-core`, desktop HEAD `710a2fd`)

- `mls/mod.rs` lifecycle engine: create / admit / process / heartbeat / poisoned-successor /
  leave; `verify_join_intent` (read-only, exposed via `e2ee_call_verify_join_intent` IPC, 6.4);
  `mls_call_announce(group_id)` confirm-gated (6.5); Welcome path is **atomic** on
  `MlsLeafRejected` (single `BEGIN IMMEDIATE` tx — verified at the 6.4 leaf-verify gate; no native
  change owed for the reactive chain).
- `credential.rs`: `verify_leaf_credential` → `LeafRejection::{UnknownIdentity, BindingUnverified,
  IdentityKeyMismatch, IllegalMutation, …}`; the **recoverable set is `BindingUnverified` ONLY**
  (unknown_identity stays terminal — reconcile can't pin a brand-new device).
- Existing native harness `tests/mls_adversarial.rs` (867 lines, 19 tests) already covers
  **T-04/T-05/T-09/T-13/T-15/T-17** legs + heartbeat rotation + ctl round-trip + native downgrade
  verdict/grant clearing. **This file IS the native hostile-DS harness** — see §4.1 for why 6.6
  extends it rather than minting a redundant `hostile_ds.rs`.

### Server DS (`stoatchat/acutest`, HEAD `9f1c58a2`)

- `/mls` routes; `MAX_MLS_GROUP_MEMBERS = 100` **is** server-enforced in both drivers inside the
  commit CAS (`ops/reference.rs:309`, `ops/mongodb.rs:464`; `commits_submit.rs:232`) AND at
  join_intent (`MlsCallFull` 409 for NEW members, after the rejoin branch — 6.5).
- `voice_join.rs::call` (delta `POST /channels/<t>/join_call`): the token/room path. Has a
  per-channel `max_users` gate (ManageChannel-exempt) at `:76-83`. **No `MAX_VIDEO_PARTICIPANTS`
  anywhere** (D12 — correctly absent; this slice lands it).
- `voice-ingress/src/api.rs`: LiveKit webhook. `track_published` handler (`:256-333`) already
  disconnects on out-of-bounds resolution/aspect-ratio and on any Data track; calls
  `update_voice_state_tracks` which flips per-member `camera`/`screensharing`/`is_publishing` in
  Redis. `room_finished` closes the open MLS group (`:348-350`).
- `voice/mod.rs`: `get_voice_channel_members(channel) -> Option<Vec<String>>`; per-member
  `camera:{key}` / `screensharing:{key}` / `is_publishing:{key}` Redis flags; `get_voice_state`
  reads them. No aggregate "video participant count" helper yet.

### Client session (`frontend/main` HEAD `0504fb8c`; drain policy modules)

- `mlsCallSession.ts`: `#pump`/`#consume` drain; `drainAction` (in `mlsDrainPolicy.ts`) actions
  `ack | ack_removed_self | gap_refetch | escalate_desync | successor | fetch_identity |
  rejoin_fresh | retry | ack_drop_poison`. `fetch_identity` runs a **detached** reconcile
  (`setTimeout(0)`), keeps the envelope off `#seen`, re-feeds at queue head, re-pumps.
  `#identityFetches: Set<userId>` = COMPLETED-reconcile progress marker.
- `#onJoinRequest` schedule-admit path: dedup key `${user}:${device}` checked at `:1291` then
  `await #reconcileRoster([user])` at `:1296` — **key reserved only AFTER the await** (D11). The
  `#serveRejoin` path already reserves `null` before its awaits (`:1336`) — the correct pattern.
- `#setMode` (direct, 6.4 mechanics at `:2509/2530/2562/2571`) vs `#applyMode`/`#modeChain`
  (serialized, 6.5 transitions). Direct callers bypass the chain (6.5 LOW-3).
- `mlsCallModePolicy.ts` (30 tests) — pure §3.4 machine; `state.tsx` publish-gate reason-set
  (`#publishGate`), `videoCapReached()` client product gate (`MAX_VIDEO_PARTICIPANTS = 30`).
- Pre-join: `useCallPrejoinMode(channel)` reads `e2eeCallsEnabled` untracked (6.5 LOW-2).

---

## 2. Design — server: D12 `MAX_VIDEO_PARTICIPANTS` enforcement

### 2.1 Semantics (matches plan §0.2 exactly; the client gate's domain)

`MAX_VIDEO_PARTICIPANTS = 30` is a **product gate, independent of E2EE** (plan §0.2, §7.3): it
bounds simultaneous **video/screenshare publishers**, so it applies to **ALL calls**, not just
E2EE ones — matching the 6.5 client gate `videoCapReached()`, which is not E2EE-conditioned. This
is a deliberate scope call flagged for the audit (§8, Q-D12-1): the server leg must not be gated
behind `require_media_e2ee_enabled()`, or a hostile/downgraded client could bypass the cap by
lying about E2EE.

Define, over a channel's current voice roster:

> **V(channel)** = count of current members whose `camera == true OR screensharing == true`.

The plan's two-sided rule (§0.2) maps to two enforcement legs:

- **Join/token leg (the NAMED D12 surface — `voice_join.rs`)**: a **video call is capped at 30
  members total**. Refuse a NEW join when the call already has video active AND the roster is at
  the ceiling:
  `if video_active(channel) && members.len() >= MAX_VIDEO_PARTICIPANTS ⇒ Err(VideoCallFull{max})`.
  `video_active` = `V(channel) > 0`. This is the "video active ⇒ joins >30 refused" half.
- **Video-enable leg (`voice-ingress` `track_published`, camera/screen only)**: refuse turning
  video on when the roster already exceeds the cap:
  `if members.len() > MAX_VIDEO_PARTICIPANTS ⇒ disconnect/unpublish` (reuse the existing
  `disconnect = true` machinery in the handler). This is the ">30 present ⇒ video enable refused"
  half.

Together they enforce the invariant **"a video call never exceeds 30 members"** without capping
audio-only calls. **Self-rejoin exemption**: the `force_disconnect == Some(true)` branch (a device
reconnecting) is exempt — it removes the user's prior state first, so it never *grows* the roster
(mirrors the `MlsCallFull` rejoin exemption). **No ManageChannel exemption** (unlike `max_users`):
the cap is a hard media-plane ceiling, not a per-channel policy knob — flagged for audit
(Q-D12-2).

### 2.2 Constant + helper

- `crates/core/database/src/voice/mod.rs`: `pub const MAX_VIDEO_PARTICIPANTS: usize = 30;` (single
  server source of truth; the client's `30` in `state.tsx` is the mirror — documented in a comment
  cross-ref on both sides).
- New helper `pub async fn count_video_participants(channel: &UserVoiceChannel) -> Result<usize>`:
  reads `vc_members:{channel.id}`, then for each member MGETs the per-member flags under the
  **exact** key composition the rest of the module uses —
  `unique_key = {user_id}:{channel.server_id.unwrap_or(&channel.id)}` (audit ME-MED-2: the members
  set is keyed by channel id but the flags are keyed by SERVER id for server voice channels; a
  naive `camera:{user}:{channel_id}` misses every flag on a server channel and the count reads 0 →
  the join cap fails OPEN). Counts members with `camera:{unique_key} == true OR
  screensharing:{unique_key} == true` (actual Redis flag name; see LOW-8 on screenshare-audio). Single
  pipeline; no new persisted state. Returns 0 on empty. Reuses the existing Redis layout from
  `create_voice_state`/`update_voice_state`; no driver-abstraction change — voice state is
  Redis-only, not the Mongo/Reference `Database`, so this is not a two-driver method.
- **Screenshare-audio (audit ME-LOW-8):** `update_voice_state_tracks` maps track sources `3` (screen
  video) and `4` (screen audio) BOTH to the single `screensharing` flag (`voice/mod.rs:373-377`).
  So `screensharing == true` does not distinguish a video screenshare from an audio-only one, and a
  member sharing only system audio would wrongly consume a video slot. Since the flag is
  lossy, the video-participant predicate keys on **camera OR screensharing** and 6.6 **documents
  that any screenshare (video or audio-only) consumes a video slot** — the conservative direction
  (cap slightly stricter, never looser). Splitting source-3 from source-4 would need a new Redis
  flag (out of scope; noted for a future slice). The enable-leg (§2.4) `is_video_source` predicate
  matches sources `1` (camera) and `3` (screen video) only, so an audio-only screenshare is NOT
  refused by the enable leg — a deliberate asymmetry documented in-code.

### 2.3 Join/token leg — `voice_join.rs`

Insert immediately after the existing `max_users` gate (ends `:83`) and **before** the
`force_disconnect`/`raise_if_in_voice` block (`:101-117`). Precedence (audit ME-LOW-6 / CR-LOW-7 —
the first draft's "after raise_if_in_voice" prose was wrong): the video-cap check runs after
`max_users` and before `raise_if_in_voice`. That ordering is deliberate and stated here: a member
already in the call re-joining **non-force** would get `raise_if_in_voice`'s error only if we
placed the cap after it — but the cap check is roster-count-based and a non-force rejoin of an
existing member does not grow the roster, so we additionally guard on "not already a member" by
letting `force_disconnect`/`raise_if_in_voice` own the already-in-voice case. Concretely the cap
gate is skipped for a self-reconnect:

```rust
// D12 / A3(b): a video call is capped at MAX_VIDEO_PARTICIPANTS members.
// Product gate (ALL calls, NOT E2EE-only — must sit OUTSIDE the E2EE device
// block above, audit Q-D12-1). Self-reconnect (force_disconnect) is exempt —
// it removes prior state first and never grows the roster.
if force_disconnect != Some(true) {
    let members = get_voice_channel_members(&user_voice_channel)
        .await?
        .map(|m| m.len())
        .unwrap_or(0);
    if members >= MAX_VIDEO_PARTICIPANTS
        && count_video_participants(&user_voice_channel).await? > 0
    {
        return Err(create_error!(VideoCallFull { max: MAX_VIDEO_PARTICIPANTS }));
    }
}
```

Uses `user_voice_channel` already in scope. It sits OUTSIDE the `if let Some(device_id)` E2EE block
(`:49-61`), so a downgraded/non-E2EE client cannot bypass the cap by omitting `device_id`
(audit Q-D12-1, both reviewers). No ManageChannel exemption (audit Q-D12-2 — the cap is a hard
media/product ceiling, unlike `max_users`'s per-channel policy knob; the asymmetry is documented
in-code so operators aren't surprised).

### 2.4 Video-enable leg — `voice-ingress/src/api.rs` `track_published`

Inside the `if event.event == "track_published"` block, when the track is a **camera or
screenshare video source** (`track.source` ∈ {camera=1, screen_share} — reuse the source ints the
handler already switches on), before `update_voice_state_tracks`:

```rust
if is_video_source(track.source) {
    let members = get_voice_channel_members(&channel).await?.map(|m| m.len()).unwrap_or(0);
    if members > MAX_VIDEO_PARTICIPANTS {
        // >30 present ⇒ video enable refused: unpublish, keep the member in
        // the (audio) call rather than disconnecting the whole session.
        let _ = voice_client.remove_track(node, user_id, &track.sid).await; // or mute; see §2.4a
        return Ok(EmptyResponse);
    }
}
```

**§2.4a resolved mechanics (audit ME-MED-5, Q-D12-3):** three coupled points the reviewers raised:
1. **API existence is a HARD precondition, checked FIRST at implementation.** The existing handler
   only has `voice_client.remove_user` (whole disconnect) + `delete_voice_state` (`api.rs:308-315`);
   whether this fork's `VoiceClient` wraps LiveKit `RoomService.MutePublishedTrack` /
   `RemoveTrack` is unverified. **Implementation step 1 for this leg is to grep the `VoiceClient`
   surface** (`crates/core/database/src/voice/voice_client.rs`) for a per-track mute/unpublish. If
   it exists → use it (member stays audio-only, matching the shipped client toast "video is full,
   you're still connected"). If it does NOT exist → **do not silently fall back to a whole
   disconnect that contradicts the client copy**; instead add the thin `mute_published_track`
   wrapper (small, in scope) OR, if the LiveKit crate version can't, change the decision to
   "disconnect + a distinct toast" and update the client copy in the same slice so server and
   client agree. The unacceptable outcome is a server disconnect while the client promises
   "you're still connected."
2. **Enforce-after-publish window (accepted).** The webhook fires AFTER the track is published, so
   the SFU forwards over-cap video frames until the handler unpublishes — a transient product-cap
   exceedance. Acceptable for a **product** (non-security) gate; stated explicitly, not hidden.
3. Either way the **cap is enforced server-side** — the point of D12 — and the client gate
   (shipped 6.5) remains the primary UX so the webhook path is the backstop, not the first line.

### 2.5 Error variant

`crates/core/result/src/lib.rs`: new `VideoCallFull { max: usize }` beside `MlsCallFull`
(`:223`); `rocket.rs` maps it to `Status::Conflict` (409) like `MlsCallFull`. Documented as a
product gate (not MLS-specific). Client already renders `videoCapReached()` UX; the 409 is the
server backstop for a client that ignores it.

### 2.6 Server tests (REFERENCE; MONGODB in WSL if a driver method appears — none expected)

Voice state is Redis-backed, so these are **not** `Database`-driver tests. Two homes:

- **`voice/mod.rs` unit test** for `count_video_participants` if the Redis harness supports it in
  REFERENCE runs; if the test infra has no Redis in REFERENCE (likely — voice state uses a live
  Redis connection), the count helper is covered indirectly by the delta route test with a seeded
  voice state, and by the live legs (§6). **Owed check at implementation**: whether existing voice
  tests run under `TEST_DB=REFERENCE` at all — if voice-state tests are MONGODB/Redis-only, mark
  the D12 unit coverage as live-only and say so (no silent gap).
- **delta `routes/channels` test** `video_cap_refuses_join_when_video_active`: seed a voice
  channel with `MAX_VIDEO_PARTICIPANTS` members, set one member's `camera` flag, assert the 31st
  `join_call` returns 409 `VideoCallFull`; and the negative — 31st join **allowed** when no video
  is active (audio-only call may exceed 30). Mirrors the existing `join_intent_call_full_boundary`
  test shape.

If Redis is unavailable in the test profile, this leg is validated by the live exercise (§6.3) and
the doc records that explicitly rather than claiming REFERENCE coverage it can't have.

### 2.7 T-20 SFU-token coupling — close the overflow-joiner downgrade-DoS (audit CR-HIGH-2)

**The gap the crypto audit found:** at `MAX_E2EE_CALL_MEMBERS`, the 101st joiner is refused the MLS
leaf (join_intent 409 / CAS), but `voice_join.rs` grants the LiveKit SFU token independently of the
MLS cap. A **cooperative** client auto-leaves on `MlsCallFull` (6.5), but T-20's threat model is an
**attacker alt** that will NOT auto-leave: it holds the token, sits on the SFU as an audio
participant absent from the verified MLS roster, and every member's roster reconciliation (§1.4)
classifies it as non-enrolled ⇒ **loud whole-call downgrade** (banner + publish paused) on repeat.
No silent plaintext results (per-device confirm + dual-gate + publish-gate all hold), but a single
account can freeze/prompt-storm a full encrypted call toward plaintext-by-fatigue. Plan A3's "no
downgrade prompt reaches existing members" is FALSE for a non-cooperative overflow joiner without
this coupling.

**Fix — couple SFU admission to the MLS cap for E2EE-active calls, in `voice_join.rs`:** when the
channel has an **open MLS group** (`fetch_open_mls_group_for_channel` — the same probe the pre-join
badge and voice-ingress close use) whose roster is at `MAX_MLS_GROUP_MEMBERS`, refuse the token for
a device that is **not already a member of that group**:

```rust
// T-20 (audit CR-HIGH-2): an E2EE-active call at the MLS ceiling must refuse
// SFU admission to a NEW device — else a non-cooperative overflow joiner sits
// on the SFU as a non-enrolled ghost and trips every member's loud downgrade.
// Existing members (rejoin) are exempt; non-E2EE calls are unaffected.
if let Some(group) = db.fetch_open_mls_group_for_channel(channel.id()).await? {
    if group.members.len() >= MAX_MLS_GROUP_MEMBERS
        && !group.members.iter().any(|m| m.user_id == user.id)
    {
        return Err(create_error!(MlsCallFull { max: MAX_MLS_GROUP_MEMBERS }));
    }
}
```

This is E2EE-conditioned (only fires when an open group exists — a non-E2EE call is untouched), it
matches A3's locked decision (overflow refused, call stays E2EE, no plaintext fallback), and it
exempts existing members so a legitimate rejoin at the ceiling still works. Member identity is
by `user_id` (device-agnostic on purpose — a user already in the group re-joining from any device
is a rejoin, consistent with the join_intent rejoin exemption). Placed alongside the D12 gate.
**Server test** `join_call_refuses_sfu_token_for_overflow_of_full_e2ee_call` (delta REFERENCE): seed
an open group at `MAX_MLS_GROUP_MEMBERS`, assert a non-member `join_call` returns 409 `MlsCallFull`
and an existing member's rejoin succeeds; and a NON-E2EE full call (no open group) is unaffected.
This makes the §6.3 T-20 live leg testable with a **non-cooperative** joiner (§6.3 rewritten).

---

## 3. Design — client: the two deferred drain debts + three 6.5 LOWs

### 3.1 D10 (6.4 MED-2) — park same-group envelopes while an identity-fetch is pending

**Problem (from the 6.4 gate):** while a `fetch_identity` reconcile round-trip is in flight for a
not-yet-joined group (the Welcome is the thing being retried), `#pump` keeps draining the inbound
queue. A same-group `mls_commit` next in line hits native `processEnvelope` → the group doesn't
exist locally yet → `group_not_found` → quiet ack+drop → that commit is **permanently consumed**.
When the Welcome finally applies, the member is missing that commit's epoch → gap-park → recovery
only via the next commit's gap-refetch or the 10-min heartbeat. Availability bug, not a secrecy
bug, but it's exactly what the harness must not leave un-fixed.

**Fix — park, don't drain, while a fetch is pending for the group:**

- Add `#identityFetchPending: Set<groupId>` (or a single `#pendingIdentityFetch: string | null`
  since a session owns one group at a time — one group, so a boolean/nullable groupId suffices).
- In `#consume`, on the `fetch_identity` action, set the pending marker before scheduling the
  detached reconcile; clear it in the detached timer's `finally` (after re-feed + re-pump, or on
  terminal).
- In `#pump`'s inner loop, when a fetch is pending, **hold** any dequeued envelope whose
  `group_id` **matches the pending group** by pushing it to a `#parkedDuringFetch: MlsEnvelope[]`
  buffer instead of `#consume`-ing it, and continue. An envelope whose `group_id` does **not** match
  (audit ME-MED-4: possible transiently during a `rejoin_fresh`/`poisonedSuccessor` migration that
  swaps `#groupId`) is **consumed defensively**, NOT parked and NOT a fatal `assert` — a hard throw
  there would crash the drain. The park predicate is therefore park-if-matching /
  consume-otherwise, never "assert single group."
- When the fetch completes, splice the parked buffer to the **head** of `#inbound` **after** the
  re-fed Welcome, so the **Welcome is reprocessed before the parked commits** (audit CR-MED-5:
  this ordering is load-bearing for *availability* — a LIFO splice that puts a commit ahead of the
  Welcome reintroduces the exact `group_not_found` drop D10 exists to fix). **Secrecy is safe
  regardless of splice order** — native's strict-epoch-order gate (`mls_epoch_gap` → park →
  gap_refetch, invariant 10) is independent of the JS queue, so a mis-order can only stall, never
  apply out of order or serve a stale key. The "Welcome precedes parked commits" ordering is stated
  as an explicit invariant with a unit assertion.
- **Bound (audit ME-MED-4 — corrected):** the park is bounded by the **reconcile round-trip
  duration**, NOT the `#parkAttempts`/`MAX_PARK_ATTEMPTS` gap ceiling (that governs gap-refetch
  escalation, a different mechanism). The fetch itself is already bounded — a failed reconcile
  burns bounded envelope `#retries` and escalates to `rejoin_fresh` (never plaintext), so the fetch
  cannot hang forever, and the parked buffer drains the instant the fetch resolves. To bound the
  buffer's *size* against a commit flood during the round-trip, cap `#parkedDuringFetch` at a small
  ceiling (e.g. `MAX_PARK_ATTEMPTS`); on overflow, escalate the whole group to `rejoin_fresh` (the
  fetch clearly isn't converging fast enough) — never plaintext, never a silent drop.

**Purity/test:** the decision "park vs consume vs escalate while fetch pending" is a pure predicate —
extend `mlsDrainPolicy.ts` with `shouldParkForPendingFetch(envelopeGroupId, pendingFetchGroupId,
parkedCount, maxParked)` returning `park | consume | escalate`, unit-tested in
`mlsDrainPolicy.test.ts` (new cases: matching-group→park, non-matching→consume, buffer-overflow→
escalate, no-pending→consume, and the Welcome-before-parked ordering assertion). Keeps the gated
`mlsCallSession.ts` change mechanical.

### 3.2 D11 (6.4 LOW-1) — reserve the admit dedup key BEFORE the await

`#onJoinRequest` schedule-admit path: reserve the key **before** `await #reconcileRoster`, exactly
as `#serveRejoin` does. Set `this.#scheduledAdmits.set(key, null)` immediately after the
`.has(key)` guard (`:1291`), before the reconcile await; on the state-invalidation early-returns
after the await (`:1297`, `:1313` "not a member") **delete the key** so a genuine later request
isn't permanently suppressed; replace `null` with the real `timer` when scheduled. This closes the
duplicate-admit window (two concurrent identical join requests → one reconcile + one admit timer,
not two → no wasted KeyPackage claim). No behavior change on the happy path.

**Test:** `mlsJoinRequestPolicy.test.ts` is pure and doesn't touch the dedup map; the dedup-lifecycle
is exercised by a new focused assertion in the harness-adjacent node coverage isn't clean here
(the map is private state inside the awaited method). Cover it with an inline reasoning comment +
the D11 case folded into the reactive-chain live exercise (§6.3) where duplicate admits are
observable in `session.metrics().dedupSkips`. Flagged for audit (Q-D11-1) — if the reviewer wants
a unit test, extract the reserve/clear decision to a tiny pure helper.

### 3.3 6.5 LOW-1 — share-modal pause defers to the gate (comment truth-up)

The screenshare quality modal starts its track paused (`state.tsx` share-modal path) and resumes
per-track. The 6.5 note already corrected the stale "share-modal reason" wording; the residual is
to **assert** (comment + a guard) that the modal's resume path checks `#publishGate.size` before
resuming — so a share started while `negotiating`/`enable-window`/`mixed` is held stays paused
until the gate clears, not the modal. Verify the current `toggleScreenshare` resume already routes
through `#applyPublishGate`; if it calls `resumeUpstream` directly, wrap it so the gate wins. Small,
localized; no new state.

### 3.4 6.5 LOW-2 — pre-join fetcher reads the toggle reactively

`useCallPrejoinMode(channel)` reads `settings.e2eeCallsEnabled` untracked, so toggling "Encrypt my
calls" doesn't refresh the pre-join badge until an unrelated reactive bump. Fix: read it inside the
reactive scope (a `createMemo`/accessor dependency) so the badge updates immediately. Solid-reactivity
one-liner; no logic change.

### 3.5 6.5 LOW-3 — route the 6.4 direct `#setMode` callers through `#modeChain`

The four direct `#setMode` callers (T0b/T1/T2 mechanics) bypass the `#modeChain` serialization; a
race with an `#applyMode` transition is a lost-update whose worst case is **over-encryption /
label-mismatch, never plaintext** (6.5 assessment).

**Correction (audit CR-MED-4): a bare `await this.#modeChain` guard does NOT serialize.** `#applyMode`
computes its transition from `#callMode` and calls `#setMode(mode)` at the END of an awaited chain
continuation; a concurrently-appended `#applyMode` continuation is a separate microtask, so a
direct `#setMode` that merely `await`s the *captured* chain tail can still interleave with it. Two
sound fixes:
- **Preferred: convert the direct callers to `#applyMode` events** where a matching pure transition
  exists (real serialization via the chain — the direct call becomes an event whose `#setMode`
  runs inside the same serialized continuation). Add the missing pure events to
  `mlsCallModePolicy.ts` (its test file already covers the machine; new events get cases).
- If a caller genuinely has no pure event and adding one churns the machine, **enqueue onto**
  `#modeChain` (append a continuation `this.#modeChain = this.#modeChain.then(() =>
  this.#setMode(...))`), NOT a bare `await` — appending is what actually serializes.

**Why "never plaintext" holds regardless (document it so a refactor can't silently break it):** the
guarantee is carried by (a) the `#publishGate` **reason-set** in `state.tsx` that resumes only at
`size === 0` — a stray `#setMode({kind:"e2ee"})` can neither clear a held downgrade/mixed pause nor
cause a plaintext publish — and (b) **invariant-11 dual gating** (LiveKit-observed per-participant
encryption status), which prevents a false green during any transient `label=e2ee`-while-`set_e2ee(false)`
window. It is NOT carried by the mode label. Prefer the `#applyMode` conversion; state the chosen
approach and this backstop in a comment. (Q-LOW3-1 answered: `#applyMode` conversion.)

---

## 4. Design — the hostile-DS harness rounds (T-19 / T-20 / T-06-ext + reactive chain)

### 4.1 Decision: extend `mls_adversarial.rs`, do not mint `hostile_ds.rs`

The plan §8 row names `hostile_ds.rs`, but the native harness that already exists —
`tests/mls_adversarial.rs` — **is** the hostile-DS matrix: its header says "The DS is an untrusted
relay; a call MEMBER can also be malicious," and it forges Welcomes with raw OpenMLS to bypass the
engine's guardrails exactly as a hostile DS/member would. Minting a second file would fork the
forge helpers (`forge_welcome_for`, `commit_envelope`, `joined_pair`) and split the matrix. **6.6
adds the missing T-cases to `mls_adversarial.rs`** and updates its header to claim the full
desktop-scoped T-01..T-21 matrix with a per-T index comment. (Flagged for audit Q-H-1 — if the
panel prefers the named file, the additions move verbatim into `hostile_ds.rs` re-exporting the
shared helpers; content is identical.)

Coverage today (native): T-04, T-05, T-09, T-13, T-15, T-17 + rotation/heartbeat + ctl. The DS/
server legs T-01/T-02/T-03/T-07/T-11/T-12/T-14/T-16/T-18/T-21 are covered by the delta REFERENCE
suite + the 6.4/6.5 live proofs + the frontend policy tests; 6.6's new native work is T-19, T-20
(native admit leg), and T-06-extended. A **coverage table** (§4.5) maps every T-NN to its
concrete home so the final audit can see nothing is silently uncovered.

### 4.2 T-19 — malicious committer under-fan-out (availability recovery)

**Threat:** a MEMBER submits a winning commit whose asserted fan-out list omits target devices ⇒
victims never receive the commit envelope ⇒ epoch gap ⇒ they must refetch via `GET .../commits`
and recover (availability-only for an **Add/rekey** commit; **no secrecy impact** — they can't
derive the new epoch's keys until they process the commit, so they stay on old keys / RE-SECURING,
never wrong-key decrypt).

**Caveat for a withheld REMOVE commit (audit CR-MED-3 — the "no secrecy impact" is NOT absolute):**
under-fan-out of a *Remove* extends the invariant-7 distributed-rotation window — honest senders
that never receive the Remove keep encrypting at the old epoch, which the removed member can still
read. This is within §5.6's accepted "post-leave secrecy vs a hostile operator degrades to surfaced
divergence, bounded by the heartbeat/desync threshold" limit — NOT a new hole — but §4.2 must not
state the property as unconditionally secrecy-free. The T-19 harness therefore adds a **Remove-case
assertion**: a withheld Remove is caught by the epoch heartbeat OR the roster-divergence-timeout
Remove within the documented bounded window (cross-ref invariant 7 / T-18 / §5.6), proving the
recovery bound rather than assuming it.

- **Native leg (`mls_adversarial.rs`)**: `under_fanout_victim_parks_then_recovers_via_refetch` —
  drive two joined members to epoch E; a third commits E→E+1 but the harness (playing the hostile
  relay) **withholds** the commit from victim B. Assert B `processEnvelope` on the *next* commit
  reports an epoch gap (parks, never skips — the existing `commit_gap_parks_and_never_skips` proves
  park; T-19 adds: **feed the withheld commit** and assert B applies E→E+1 then the next, i.e.
  recovery, and its frame keys match the committer's for E+1). This exercises the native
  park→apply-in-order path that the frontend `#gapRefetchInline` drives.
- **Server leg (delta REFERENCE)**: `commits_submit` with a truncated `fan_out` recipient list ⇒
  assert the omitted device can still `GET /mls/groups/<id>/commits?from=<E>` and receive the
  commit (the DS stores the commit regardless of the client-asserted fan-out; fan-out is delivery,
  not storage). Confirms the recovery channel exists server-side. The existing
  `fanout_skips_devices_over_queue_budget` test is adjacent but tests budget-skipping, not
  adversarial omission + refetch — new test.
- **Frontend leg**: `#gapRefetchInline` already unit-covered via `mlsDrainPolicy` lagAction; add a
  node assertion that a gap → refetch → apply sequence marks progress (park bound resets), if not
  already present.

### 4.3 T-20 — cap-forcing join (call stays E2EE; overflow refused)

**Threat:** the `MAX_E2EE_CALL_MEMBERS+1`-th joiner (attacker alt) ⇒ call **stays E2EE**; overflow
joiner gets the loud "call full for E2EE" refusal; no downgrade prompt reaches existing members.

- **Server join_intent leg**: already tested — `join_intent_call_full_boundary_and_rejoin_exemption`
  (`MlsCallFull` for a NEW member at 100, rejoin exempt). 6.6 asserts the **commit-CAS leg too**:
  a fabricated Add that would push `members + added − removals > 100` is refused at the CAS in BOTH
  drivers (the code exists at `ops/*.rs`; add/confirm the explicit adversarial test
  `commit_cas_refuses_add_over_ceiling` if not already present under the commit-size test).
- **Native admit-cap — a REAL native contract extension, not "just a test" (audit ME-HIGH-1):** the
  first draft claimed a native `admit_refuses_when_roster_at_ceiling` test, but native
  `mls_call_admit` (`mls/mod.rs:507-607`) has only the one-device backstop (`:569-573`) and **no
  roster-size cap** — it mints the Welcome regardless of member count; the admitter cap lives only
  in the frontend `#tryAdmit` (`mlsCallSession.ts:1444`). 6.6 **adds the native cap** as
  defense-in-depth (layer-consistent with the one-device backstop): in `mls_call_admit`, before
  minting the Welcome, `if self.verify_roster(&group)?.len() >= MAX_MLS_GROUP_MEMBERS { return
  Err(MlsCallFull-analog) }`. This is a **named native change** (updates `mls/mod.rs`; the "no
  native change owed" note in §1 is corrected — this one native addition IS owed). The test
  `admit_refuses_when_roster_at_ceiling` then asserts native refusal directly; construct the
  at-ceiling roster via the harness's group helpers (the roster-length check is cheap to drive
  without 100 real KeyPackages by seeding the group's member list).
- **Downgrade-suppression assertion**: with the §2.7 SFU-token coupling, the refused overflow
  joiner never reaches the SFU, so it cannot appear as a non-enrolled ghost in any member's
  `nonEnrolled` set. The native side is still asserted (it never becomes an MLS member) via
  `non_enrolled_verdict_is_native_computed_from_the_verified_roster`; the **server** side (no SFU
  token) is asserted by the §2.7 delta test + the §6.3 live leg with a **non-cooperative** joiner
  (audit CR-HIGH-2 — the cooperative-auto-leave test validated the wrong threat model).

### 4.4 T-06-extended — rotation flap (chip never flaps on a clean rotation)

**Threat/property:** after a clean rotation's transient missing-key window, decrypt recovers and
the chip never flaps to NOT-ENCRYPTED (rotation-skew classification, §4.4). This is a **frontend
classification** property, not native.

- **Node leg (commit to the extraction — audit ME-LOW-12):** the chip classifier is currently
  inline in `state.tsx` (`chipState`, dual-gated). 6.6 **extracts the pure classification** to a new
  `components/rtc/mlsChipPolicy.ts` (inputs: per-participant observed encryption status, error
  latch, grace/escalation timers → `not_encrypted | resecuring | e2ee_unverified | e2ee | none`)
  and has `state.tsx` call it — respecting the tracked constraints (never whole-file-prettier
  `state.tsx`; its eslint stays 20). New `mlsChipPolicy.test.ts` T-06-ext cases: a per-participant
  `resecuring` blip within the grace window classifies as `resecuring`/`e2ee`, never
  `not_encrypted`; only an `encryptionError` past the 10 s escalation flips loud. The 6.5 policy
  tests assert "no flap on clean rotations" at the **mode-policy** level — T-06-ext confirms the
  distinct **chip** (media-plane observed status) layer.
- **Live leg**: exercised in §6.3 (heartbeat rotation under the live call — watch the chip stay
  green across a rekey).

### 4.4a T-08 — key-index wraparound (native; audit ME-MED-3, was falsely "covered")

The coverage table's first draft marked T-08 "covered" by "rotation + lagAction," but no native
test drives 16+ epochs to exercise `keyIndex = epoch mod 16` reuse — and §1.5 calls the desync
rule "the single point of correctness." 6.6 adds native
`lagging_receiver_at_keyindex_wrap_desyncs_not_stale_decrypt`: advance a group ≥16 epochs, hold a
receiver at the wrap boundary, and assert it hits the desync/rejoin-fresh path rather than serving a
stale key at a reused index (the keyring never serves a wrong key for a reused index). Complements
the drain-policy `lagAction` unit test (which bounds the counter but never touches the 16-slot
keyring index reuse).

### 4.5 Coverage table (every desktop-scoped T maps to a home — for the final audit)

| T | Home | Status |
|---|---|---|
| T-01 SFU capture | Live §6.4 (packet/track inspect) + `room.isE2EEEnabled` proof | live |
| T-02 Pre-join secrecy | Native epoch-key distinctness (rotation test) + live | covered+live |
| T-03 Post-removal secrecy | Native `processed_remove...` + live tamper (6.4 §7 negative control) | covered |
| T-04 Racing commits | Native `lost_own_commit_discards_and_does_not_fork` + delta race test | covered |
| T-05 Phantom participant | Native `admit_refuses_*` / `welcome_with_unpinned_leaf_*` | covered |
| T-06 Withheld/reordered + **ext flap** | Native gap-park + **new chip node test §4.4** + live | **6.6** |
| T-07 Loud downgrade | 6.5 mode machine + native verdict + live §6.2 | covered+live |
| T-08 Key-index wraparound | **NEW native ≥16-epoch wrap test §4.4a** (per-epoch derivation distinctness across the wrap) + `lagAction` desync-before-wrap policy test. **RESIDUAL** (final audit ME-MED-2): the JS `mlsCallKeys` keyring index-OVERWRITE at a reused slot has no direct test — the `lagAction` desync forces a lagging receiver to rejoin-fresh BEFORE it can reach a wrapped index, so no stale key is served, but a direct keyring-overwrite test is deferred. | **6.6 (partial; residual tracked)** |
| T-09 Secrets scrubbing | Native `wire_and_error_shapes_carry_no_mls_secrets` + **6.6 grep sweep §5** | covered+sweep |
| T-10 Processor coexistence | 6.3 processor-order doc + live (denoise+effects+E2EE) | live |
| T-11 Identity-change on roster | Native `IdentityKeyMismatch` leaf-invalid (6.4 leaf tests) — distinct from the `BindingUnverified` recovery in §6.3 | covered (cited) |
| T-12 Hostile KeyPackage dir | Native `admit_refuses_unpinned_joiner` + delta claim tests | covered |
| T-13 Backup exclusion | Native `backup_taken_mid_call_restores_without_mls_state` | covered |
| T-14 Web/non-native shell | 6.5 pre-join self-plain + live mixed-receive §6.2 | covered+live |
| T-15 Cross-group Welcome | Native `cross_group_welcome_is_refused_on_context_mismatch` | covered |
| T-16 Two-device join race | Delta CAS one-device test; partition variant mechanism-covered via T-15 context-mismatch (not separately asserted) | covered (cited) |
| T-17 Poisoned winning commit | Native `poisoned_winning_commit_poisons_group_no_deadlock` | covered |
| T-18 Withheld leave event | 6.4 roster reconciliation (ghost-leaf) + live | covered |
| **T-19 Under-fan-out** | **Native + delta refetch §4.2** | **6.6** |
| **T-20 Cap-forcing join** | **Delta join_intent (done) + CAS + native admit §4.3** | **6.6** |
| T-21 Premature-frame-then-key | 6.5 `resetKeyStatus` handling + live | covered |
| **Reactive leaf-verify chain** | **Live §6.3 (never run live before)** | **6.6** |

---

## 5. Secrets scrub sweep (T-09 gate discipline)

Before the final audit, a grep sweep across all four repos' committed 6.x surfaces for accidental
secret egress, recorded in this doc. **The first draft's grep set was wrong** (audit CR-HIGH-1: it
matched none of the real identifiers) — corrected below.

- **Identifier set (matches the actual names in the tree):** the exporter output is `export_secret`
  / bound to a local `secret` (`mls/mod.rs:338,1625`) — NOT a substring of `exporter`; the top-level
  call secret is `media_base_secret`; the MLS signing private key is `signature_key` /
  `MlsSigner(&identity.secret)` / `SignatureKeyRow` / `mls_signature_key` (`credential.rs:38,151,181`;
  `mod.rs:378,581,655`); the KeyPackage init private key is `last_resort_key` / `init_key`
  (`mod.rs:1417,1430`). Sweep regex:
  `rg -i 'export_secret|media_base_secret|exporter_secret|encryption_secret|sender_data_secret|epoch_secret|init_secret|MlsSigner|signature_key|SignatureKeyRow|mls_signature_key|init_key|last_resort_key|frame_key'`.
- **Scope (widened):** native `e2ee-core/src/`, desktop `src-tauri/src/`, delta `routes/mls` **plus
  `crates/core/database/src/models/mls/` and `crates/core/models/src/v0/mls.rs`** (both handle MLS
  bytes) **plus `crates/bonfire/src`** (relays `MlsCommit`/`MlsWelcome`/`MlsCtl` — audit ME-LOW-9),
  frontend `components/{client,rtc}`. (Android `e2ee-android` is 6.7, out of scope.)
- **Structural check (not just grep — audit CR-HIGH-1):** `MlsFrameKey`/`MlsFrameKeys` derive
  `Debug`/`Serialize` and hold `frame_key_b64` (`mod.rs:115`). A `tracing::debug!("{:?}", keys)` at
  any call site leaks base64 key material while containing NONE of the grepped tokens. Audit every
  call site of the secret-bearing types (`MlsFrameKey`, `MlsFrameKeys`, `SignatureKeyRow`,
  anything holding `*_secret`) for a `{:?}`/`{}` reaching a log/error/Sentry sink; assert the only
  egress of `frame_key_b64` is the sanctioned `e2ee_call_frame_keys` IPC command.
- Confirm the 6.4 MLS-DBG strip is complete (grep `MLS-DBG` = 0) and no `eprintln!`/`console.warn`
  reintroduced secrets in 6.5.
- Record the sweep commands + result counts (must be zero secret-in-sink) in the §7 verification log.

---

## 6. Live legs (BINDING — the 6.5 gate condition; deploy prereqs first)

Per [step-9 method](e2ee-media-slice-6.4-leaf-verify-fix.md): two bundled `tauri.localhost`
desktop instances via `SLOGA_PROFILE` (b=9223 JeffS, b2=9224 Android Tester), CDP-driven, plus a
**real web participant** in a browser at the dev origin for the mixed-call legs.

### 6.0 Deploy prereqs (staging)

1. Rebuild+restart **delta** and **bonfire** off committed source (they may be stale per the 6.4
   notes; the new D12 code must be live). Detached (`setsid`), logs `/tmp/*-detached.log`.
2. Rebuild **voice-ingress** (D12 video-enable leg) off source.
3. Rebuild the **desktop bundle** via `build-desktop.ps1` (WSL vite build → robocopy dist →
   `cargo build -p acutest-desktop --features tauri/custom-protocol`), no debug/test flags.
4. Flag **ON** via `Revolt.overrides.toml` `[features] media_e2ee_enabled = true` — **staging
   only**; the re-enable note stays in the file; the committed default stays FALSE.

### 6.1 T3→T6 downgrade / re-upgrade cycle with a real web participant

- Two desktops in an E2EE call (both `isE2EEEnabled`, chip green). A **web** participant (no native
  layer) joins the same call.
- **T3/T4**: the web joiner is non-native ⇒ every native member computes it as non-enrolled ⇒ the
  whole call flips LOUD (banner, publish paused), no plaintext frame published before a native
  confirm. Assert the banner + `nonEnrolled` roster names the web participant; assert no plaintext
  egress pre-confirm (publish-gate held).
- **Confirm (T3/T5)**: one desktop operator confirms the plaintext downgrade via the native dialog
  (its non-enrolled roster is native-computed) ⇒ `set_e2ee(false)` **strictly before** resume ⇒
  interlude; a best-effort ctl-announce fires; the second desktop sees the remote announce (T4,
  never resumes on its own).
- **T6 re-upgrade**: the web participant leaves ⇒ fresh-successor group ⇒ re-upgrade with
  hysteresis ⇒ chip returns green; the native downgrade grant is cleared
  (`e2ee_call_clear_downgrade`). Record the transition sequence from `session.metrics()` +
  console.

### 6.2 Mixed-call receive smoke (Decline ⇒ receive-only, observed live)

- With the call mixed (a plaintext web participant present) and a desktop operator **Declining**
  the downgrade: the desktop stays **receive-only** — it decrypts/plays the encrypted peers and
  receives the web participant's plaintext (livekit gates the decrypt cryptor per participant by
  publication `Encryption_Type`, the ME-8 artifact), but publishes **nothing** (gate held). Assert
  inbound A/V flows both from encrypted peers and the plaintext web participant while local publish
  stays paused.

### 6.3 Reactive leaf-verify chain + call_full auto-leave + T-20 downgrade-suppression

- **Reactive chain (never run live before)**: force the asymmetric-TOFU reject that 6.4 could only
  unit-test — start b2 with the admitter's CALL device **unpinned** (curve-only stub) so the
  Welcome's leaf is `BindingUnverified`. **Reproduce via external store surgery ONLY** (audit
  CR-LOW-6): stop the b2 instance, edit its `peer_identities` row for the admitter's call device to
  a stub (WAL-safe), restart. A code-flag/config bypass of the proactive `#reconcileRoster` is
  **forbidden** — a shippable bypass would regress to the reactive-only under-recovery the 6.4
  HIGH-2 audit rejected (`verify_roster` rejects on the first unpinned leaf). Assert the drain runs
  `fetch_identity` (not terminal drop) → detached reconcile pins the device → Welcome re-processes →
  `welcome_joined` → both sides `isE2EEEnabled`. Then assert **D10**: while the fetch is pending, a
  same-group commit is **parked**, not dropped (watch it apply after the Welcome, no gap). Record
  `session.metrics()` (`retries`, `parks`, `dedupSkips`).
- **T-20 overflow — NON-cooperative joiner (audit CR-HIGH-2; the 6.5 auto-leave leg tested the
  wrong threat model)**: with the §2.7 SFU-token coupling live, drive an overflow join at the MLS
  ceiling from a joiner that does **NOT** auto-leave (simulate the attacker alt — disable its
  `MlsCallFull` auto-leave for the test). Assert `join_call` returns **409 `MlsCallFull` (no SFU
  token issued)** so the joiner never reaches the SFU, existing members' chip stays **green**, and
  **no downgrade banner** appears. Separately assert the **cooperative** path still works (a normal
  client auto-leaves on `MlsCallFull`). With 100 real devices impractical, use a lowered test
  ceiling — a **staging recompile** of `MAX_MLS_GROUP_MEMBERS` (there is no runtime config for it) —
  and document that this exercises the server refusal + SFU coupling + client handling but not the
  frontend `#tryAdmit` const (kept in lockstep with the server const; see §2.2 cross-ref
  discipline). The native `#tryAdmit`/admit-cap (§4.3) stays native/unit-covered, not live-covered
  by this substitution.
- **D12 live**: 31st video publisher refused (track unpublished/muted, member stays audio); 31st
  join into a video-active call at 30 refused (409 `VideoCallFull`).

### 6.4 T-01 / T-10 confirmation

- **T-01**: inspect the SFU-side track (or LiveKit stats) to confirm ciphertext; `room.isE2EEEnabled`
  true both sides (already proven in 6.4 §7 with inbound-rtp ground truth — re-confirm under the
  flag-ON staging build).
- **T-10**: denoise + camera effects + E2EE all active simultaneously ⇒ frames decrypt (pipeline
  ordering intact).

**If a live leg cannot be run** (environment/time), it is recorded as **NOT RUN** with the reason,
never asserted as passed — and that becomes the residual the flag verdict (§9) must account for.

---

## 7a. Verification RESULTS (2026-07-12, implementation)

- **node --test** (frontend, `mise exec -- node --test --experimental-strip-types`): **59/59 green**
  (`mlsDrainPolicy` + `mlsCallModePolicy` + `mlsJoinRequestPolicy` + `mlsEnvelopeClassify`), incl. the
  NEW D10 park predicate (4 cases: consume / park / non-match-consume / overflow-escalate) and the
  T-06-ext chip flap cases (3: transient resecuring stays amber, recovers to green, only-latched-error
  flips loud).
- **tsc** (client `npx tsc --noEmit`): **9 errors = the pre-existing baseline, 0 new**; none in any
  6.6-edited file (`mlsCallSession.ts`, `mlsDrainPolicy.ts`, `useCallPrejoinMode.ts`,
  `mlsCallModePolicy.ts`). state.tsx untouched this slice (its 2 baseline errors pre-date 6.6).
- **cargo native** (`acutest-e2ee-core`, Windows stable): full suite **green** — 15 + 30 + 7 + **21**
  (mls_adversarial, +2 new: `under_fanout_commit_parks_then_recovers_in_order_when_refetched`,
  `sixteen_epoch_advance_wraps_keyindex_without_serving_stale_keys`) + 18 + 8 + 21 + 0. The native
  admit-cap (`Error::MlsCallFull`, `MAX_MLS_CALL_MEMBERS`) compiles + all files pass.
- **cargo delta** (REFERENCE, nextest): **13/13 MLS tests green** — existing suite unbroken by the
  `VideoCallFull` error + voice_join D12/SFU-coupling changes. (D12 route + SFU-coupling routes are
  NOT unit-testable — the delta test harness mounts no voice routes / `VoiceClient`; validated via the
  live legs, §6.3, and documented per §2.6.)
- **cargo database** (REFERENCE, `--features voice`): `count_video_participants` test **green** — the
  Redis-backed helper over a SERVER voice channel's key composition (closes ME-MED-2 fail-open).
- **Scrub sweep (§5, T-09): CLEAN.** No secret identifier (`export_secret`/`media_base_secret`/
  `frame_key`/`signature_key`/`init_key`/`last_resort_key`/`*_secret`) appears in any log / error /
  `eprintln!` / `tracing::*` / `console.*` sink across native `e2ee-core/src`, desktop `src-tauri/src`,
  delta `routes/mls`, `models/mls`, `models/v0/mls.rs`, `bonfire/src`, frontend `components/{client,rtc}`.
  `MlsFrameKey`/`MlsFrameKeys` (derive `Debug`/`Serialize`) reach NO `{:?}`/`{}` sink; `frame_key_b64`
  appears only in its struct def + the derivation that fills the sanctioned `e2ee_call_frame_keys`
  egress. `MLS-DBG` markers = 0. The one server MLS `log::debug!` (`commits_submit.rs:319`) logs
  recipient ids + queue depth/bytes only — metadata, accepted per §5.6.
- **stoat.js**: no change (event surface fixed at 6.5).

## 7b. Live legs — DISPOSITION (2026-07-12): NOT RUN this session

Per §6's own rule, a live leg that cannot be run is recorded **NOT RUN** with the reason, never
asserted as passed. The BINDING live legs (§6.1–6.4) — T3→T6 with a real web participant,
mixed-receive Decline, non-cooperative T-20 auto-leave/refusal, the reactive leaf-verify chain via
store surgery, D12 live, T-01 SFU capture — **were NOT RUN in this implementation session**. They
require the interactive multi-instance live environment the 6.4 step-9 proof used (two `SLOGA_PROFILE`
bundled desktops + a web participant, CDP streaming, WAL store surgery) PLUS the deploy prereqs
(rebuild+restart delta/bonfire/voice-ingress off committed source, rebuild the desktop bundle, flag
ON in staging). Restarting the operator's live services + driving a multi-hour CDP downgrade cycle is
an interactive live-proof step, not a safe autonomous action, and is deferred to a dedicated
live-proof session. **These live legs remain the binding precondition for any `media_e2ee_enabled`
flip (§9).** All DETERMINISTIC verification (unit / REFERENCE / native / node / scrub) is complete and
green above.

## 7c. Live-proof session RESULTS (2026-07-12) — legs RUN

Dedicated interactive live-proof session executed per
[the runbook](e2ee-media-slice-6.6-live-proof-runbook.md). Environment: flag ON staging (overrides,
reverted at teardown); delta/bonfire/voice-ingress rebuilt off committed source + relaunched detached;
desktop debug bundle rebuilt with an INERT `VITE_E2EE_MEDIA_TEST` probe shim (`__voice`/`__mlsProbe`;
read-only; reverted at teardown; does not affect origin/CSP/crypto). Two bundled `tauri.localhost`
desktops b=JeffS(CDP 9223) / b2=Android-Tester(9224) with fake media devices; web participant =
Velvetfly in a CDP-driven Edge serving the built dist (non-native: hasTauri=false, e2eePresent=false).
livekit-server **v1.9.13**.

**Baseline smoke — PASS.** Both reach `room.isE2EEEnabled=true`, native MLS sessions `active`, both in
the MLS roster, chip `e2ee_unverified`, LiveKit per-participant `encryption=1`. Media-plane ground
truth: b→b2 E2EE video **101 frames / 128KB decoded in 5s** (framesDecoded climbing = decrypt success).
Metrics `pass:true`, 0 parks/retries/desyncs. (Note: sub-second near-simultaneous dual mic-publish
during an unsettled join once caused a commit-409 CAS race + resecuring timeout; sequential publish
converges cleanly — a churn-robustness note, not reproducible by human-speed input.)

| Leg | Result | Evidence |
|---|---|---|
| **§4 bundled-origin + CSP** | **PASS** | tauri.conf frontendDist=../frontend-dist (bundled); runtime origin `https://tauri.localhost/`; CSP `script-src 'self' 'wasm-unsafe-eval'` ENFORCED (remote script + remote fetch both blocked at runtime); built index.html references only local /assets/*. |
| **§6.1 T3/T4 loud downgrade** | **PASS** | web joins ⇒ both natives instantly `not_encrypted`/`mixed`, `nonEnrolled=[Velvetfly]`, banner "Velvetfly is not using encrypted calls…paused…", publish gate held: **all tracks muted, 0 outbound bytes/packets over 3s** on both ⇒ no plaintext frame pre-confirm; isE2EEEnabled stays true. |
| **§6.1 confirm (T3/T5) + ctl-announce + remote-announce (T4)** | **NOT-RUN** | the confirm is a NATIVE Tauri OS dialog (`e2ee_call_confirm_downgrade → app.dialog().blocking_show()`); CDP can't click native OS windows and **computer-use access to the debug-build windows was DENIED by the user**. set_e2ee(false)-before-resume ordering + ctl-announce + remote-announce not exercised live (native-computed roster verified by code; confirm gate is 6.5-committed + unit-covered). |
| **§6.1 T6 re-upgrade** | **PASS** | web leaves ⇒ both natives auto re-upgrade mixed→e2ee (fresh successor group, hysteresis ~30s, bounded resecuring retries), chip back `e2ee_unverified`, gate released, room true. |
| **§6.2 mixed-receive / Decline = receive-only** | **PASS (core)** | b2 (declining native, gate held) receives web plaintext video **100 frames / 213KB decoded / 5s** while **publishing 0** (0 out bytes/pkts). Concurrent encrypted-peer decrypt not reproducible (mixed pauses all natives' encrypted publish; no encrypted publisher without a confirmed downgrade = dialog-blocked). |
| **§6.3 T-20 SFU-token coupling (CR-HIGH-2)** | **FAIL — bypassable (CRITICAL)** | MAX_MLS_GROUP_MEMBERS→2. Direct REST join by non-member: force_disconnect=false ⇒ **409 MlsCallFull, no token** (coupling logic works). BUT the real client always sends `force_disconnect:true` (state.tsx:798 / stoat.js Channel.ts:1256), and voice_join.rs:113 guards the T-20 block with `if force_disconnect != Some(true)` ⇒ **bypassed** (A/B: fd=false→409 no token; fd=true→200 TOKEN). Web client reached the SFU as a ghost and tripped b's loud banner. CR-HIGH-2 downgrade-DoS **NOT closed** against a real client. Fix task spawned. |
| **§6.3 D12 video-enable MUTE** | **PASS** | at 2 members > cap(1), b enabled camera ⇒ voice-ingress muted it (publication muted:true, `camera:Some(false)` event); b stays audio-only; b2 receives 0 video from b. (No force_disconnect guard on this path.) |
| **§6.3 D12 join-cap** | **server PASS / client bypassed** | b solo unmuted camera (count_video=1). REST join fd=false ⇒ **409 VideoCallFull, no token** (voice_join.rs:100); fd=true ⇒ 200 token. Same force_disconnect bypass as T-20. |
| **§6.3 reactive leaf-verify (fetch_identity) + D10 park** | **NOT-RUN (unreproducible)** | store surgery stubbed JeffS call-device in b2 (binding_verified=0, ed25519=NULL). On rejoin the stub was **re-pinned to binding_verified=1**, room=true, **0 parks/retries/gapRefetches** — the PROACTIVE `#reconcileRoster` (6.4 HIGH-2) re-pinned before the Welcome, so the reject never fires. Triggering the reactive path needs disabling proactive reconcile, which the runbook FORBIDS. Covered by 59 node unit tests. |
| **§6.3 proactive #reconcileRoster (6.4 HIGH-2)** | **PASS (live, positive)** | it detected the stubbed/unpinned admitter device and re-pinned it before Welcome verification ⇒ b2 joined E2EE despite the asymmetric-TOFU stub. |
| **§6.4 T-10 (effects + denoise + E2EE)** | **PASS** | b published E2EE video with background-blur active (effectsApplied=2, bgStatus=active, noiseSupression on, isE2EEEnabled=true); b2 decoded **101 frames / 423KB / 5s**. Pipeline ordering intact. |
| **§6.4 T-01 client-side ciphertext** | **PASS** | E2EE video decodes only end-to-end; 6.4 step-9 negative control (garbage key ⇒ framesDecoded pins / 100% concealment) proved real ciphertext. |
| **§6.4 T-01 SFU-side attestation** | **PASS (metadata)** | LiveKit RoomService.ListParticipants reports EVERY track `encryption=GCM` (b camera+mic, b2 mic) ⇒ the SFU records the tracks as E2EE and forwards opaque ciphertext it never decodes. |
| **§6.4 T-01 raw packet-node capture** | **NOT-RUN** | Alpine LiveKit container has no tcpdump/tshark (only hexdump); RTP is SRTP over UDP 50500-50600 ⇒ a raw capture cannot DISTINGUISH E2EE from transport SRTP. Post-SRTP frame inspection needs SFU instrumentation / egress-decode-failure. Standing residual both reviewers named. |
| **§5 invariant-2 cross-shell** | **PASS** | the non-native web shell triggered LOUD downgrade (never quiet false-green); web client self-reports isE2EEEnabled=false / e2eePresent=false. |

**Minor/other:** pre-existing CSP gap — notification sound `data:audio/ogg` blocked by `media-src`
(cosmetic, not E2EE). A Velvetfly test-account session token surfaced once in a mongosh error before
the reader was hardened (local dev test account; token valid only vs the local instance — revoke if
desired).

**NEW CRITICAL FINDING (blocks the flag):** the T-20 SFU-token coupling AND the D12 join-cap are both
skipped whenever `force_disconnect == Some(true)` (voice_join.rs:92 and :113), which the real client
ALWAYS sends. So both caps are bypassed on every real join — the CR-HIGH-2 non-cooperative
overflow-joiner downgrade-DoS is **not actually closed**. The T-20 block already exempts genuine
reconnects via its inner member check, so its outer force_disconnect guard is redundant and harmful;
remove it, and scope the D12 reconnect exemption to "user already has voice state in THIS channel."

## 7. Verification plan (house-consistent)

- **node --test** (frontend): existing 30 (`mlsCallModePolicy`) + 22 (drain/classify/joinPolicy)
  stay green; new cases for D10 (`mlsDrainPolicy` park-for-fetch), T-06-ext chip policy, T-19
  gap-recovery. Zero new tsc/eslint/prettier vs `0504fb8c` baseline (9 pre-existing; state.tsx
  eslint stays 20; never whole-file-prettier state.tsx).
- **cargo native** (`e2ee-core`): `mls_adversarial` grows T-19 native + T-20 admit legs; all
  existing green; `cargo test -p acutest-e2ee-core` (WSL `mise exec --`; the shared-target
  `cargo clean -p` gotcha per [[feedback_shared_target_corruption]]).
- **cargo delta** (REFERENCE): new `video_cap_refuses_join_when_video_active` +
  T-19 refetch + T-20 CAS tests; existing MLS suite (13+) green. MONGODB in WSL only if a driver
  method appears (none expected — D12 is Redis + route logic).
- **Scrub sweep** (§5): command + zero-secret result recorded here at implementation.
- **Live legs** (§6): each recorded PASS / NOT-RUN with evidence.
- **stoat.js**: no change expected (event surface fixed at 6.5); if any, submodule build + gitlink
  bump discipline.

---

## 8. Plan-audit questions (folded before coding after the panel round)

- **Q-D12-1**: D12 applies to ALL calls (product gate), NOT gated behind
  `require_media_e2ee_enabled()`. Confirm — a hostile/downgraded client must not bypass the video
  cap by claiming non-E2EE.
- **Q-D12-2**: no ManageChannel exemption on the video cap (unlike `max_users`). Confirm the cap is
  a hard media ceiling, not a per-channel policy knob.
- **Q-D12-3**: video-enable refusal mechanism — track mute/unpublish (member stays audio) vs whole
  disconnect. Prefer mute/unpublish; fallback disconnect if the `VoiceClient` lacks per-track
  control. Confirm acceptable.
- **Q-D12-4**: join-leg semantics — "video call (V>0) capped at 30 members total" vs a pure
  video-publisher count. Confirm the chosen reading matches §0.2.
- **Q-H-1**: extend `mls_adversarial.rs` rather than mint `hostile_ds.rs` (shared forge helpers).
  Confirm or require the named file.
- **Q-D11-1**: D11 dedup-reserve has no clean unit home (private awaited-method state) — covered by
  reasoning + live metrics. Confirm or require a pure-helper extraction.
- **Q-LOW3-1**: LOW-3 approach — convert direct `#setMode` to `#applyMode` events vs
  `await #modeChain` guard. Confirm the minimal-change choice.
- **Q-LIVE-1**: the T-20 live leg uses a lowered test ceiling (100 real devices impractical).
  Confirm the substitution is acceptable evidence.
- **Q-FLAG-1**: after 6.6 with all legs PASS, is the panel's sign-off sufficient to clear the flag
  for production, or does production exposure need the operator multi-device E2E + Android (6.7)
  first? (Drives §9.)

---

## 9. Flag verdict (the owed deliverable)

### VERDICT after the live-proof session (2026-07-12): NOT cleared to flip — one NEW blocker.

`media_e2ee_enabled` is **NOT cleared to flip in production**. It stays **FALSE** and the staging
override was turned back OFF at teardown. Most binding live legs PASS (baseline E2EE end-to-end,
T3/T4 loud downgrade with zero plaintext egress, T6 re-upgrade, receive-only, D12 video-enable mute,
T-10 effects+E2EE, proactive reconcile, invariant-2, §4 origin+CSP on the shippable artifact), BUT the
live proof surfaced a **NEW CRITICAL defect** and left three items as residuals:

**BLOCKER (new): T-20 SFU-token coupling + D12 join-cap are bypassed by the real client.** Both are
guarded by `if force_disconnect != Some(true)` (voice_join.rs:92, :113), and every real client join
sends `force_disconnect:true` — so an overflow/attacker client reaches the SFU as a non-enrolled ghost
and trips every member's loud-downgrade banner. Precondition #7 (CR-HIGH-2 resolved) is **FALSED by
live evidence**. Fix: drop the outer force_disconnect guard on the T-20 block (its inner member check
already exempts real reconnects) and scope the D12 exemption to an actual same-channel reconnect. Then
re-run the T-20/D12 legs.

**BLOCKER FIX LANDED (working tree, 2026-07-12):** `voice_join.rs` — the T-20 outer
`force_disconnect` guard is dropped (the inner by-user membership check is the ONLY rejoin
exemption), and the D12 exemption is re-scoped from the joiner-controlled flag to "user already
holds voice state in THIS channel" (the `vc_members` roster is written by voice-ingress, never the
client, so it cannot be forged). New delta route tests
(`video_cap_refuses_overflow_join_despite_force_disconnect`,
`mls_cap_refuses_overflow_join_despite_force_disconnect`) prove an overflow join is refused 409
even with `force_disconnect:true` (both caps, both flag values) and that a genuine same-channel /
group-member rejoin at the ceiling still passes both caps; REFERENCE suite green. Still owed
before the verdict changes: re-run the live T-20/D12 REST legs against a staging build.
discord-features-reviewer verdict on the fix diff: **SHIP-WITH-FIXES** — bypass confirmed closed
(no request-controlled input reaches around either cap; exemptions key on server-written state);
residuals tracked separately: check→mint TOCTOU under parallel joins (MED, wants an ingress
backstop), and `member_edit.rs` voice-MOVE minting a cap-free token (MED) + its `:309`
disconnects-the-moderator bug (LOW) — both spawned as follow-up tasks.

**Residuals still owed (unchanged by this session):**
- **T-01 raw SFU-node packet capture** (#4) — NOT-RUN (no capture tooling in the Alpine LiveKit
  container; SRTP makes a raw capture non-distinguishing). Client decrypt proof + LiveKit `encryption=GCM`
  attestation substantiate the claim but are not the packet-node capture both reviewers require.
- **Native-dialog confirm path (§6.1 T3/T5) + ctl-announce/remote-announce** — NOT-RUN live
  (computer-use to the debug build was denied; the confirm is a native OS dialog). Unit-covered.
- **Reactive fetch_identity chain + D10 park** — NOT-RUN live (unreproducible without disabling the
  proactive reconcile, which is forbidden). Unit-covered by the 59 node tests.
- Standing operator debts: multi-device E2E, Android 6.7 (or its loud-downgrade impact consciously
  accepted). §9 preconditions #1/#2/#7 not met.

### The hard preconditions (for reference):
Per both audits (Q-FLAG-1), desktop panel sign-off alone does
**NOT** clear a production flip; the hard preconditions are:

1. **All live legs PASS (§6)** or each NOT-RUN one named as a residual.
2. **Final panel APPROVE** on the diff (§7 gate).
3. **Scrub sweep clean with the CORRECTED grep set + structural `Debug` check (§5)** — the old set
   could report false-clean (CR-HIGH-1).
4. **T-01 livekit-server SFU passthrough proven live at the SFU node** (master §7.1 Q7; both audits'
   biggest residual): the "SFU forwards ciphertext it cannot read" claim is currently taken on
   LiveKit docs, not observed. Capture at the SFU/packet layer, NOT inferred from
   `room.isE2EEEnabled`.
5. **Bundled-origin + restrictive-CSP lock verified in the SHIPPED artifact (§7.2 / invariant 6 —
   CR-Q-FLAG-1(a))**: confirm the flag-ON production build loads the bundled `tauri.localhost`
   origin under the 6.2b CSP, not the remote `app.sloga.gg` webview — server-delivered JS next to
   live frame keys can both exfiltrate keys and fake the green lock. "Rebuild desktop bundle" is not
   enough; the origin+CSP lock must be asserted in the artifact.
6. **Invariant-2 (capability-from-keys) reconfirmed across shells (CR-Q-FLAG-1(b))**: flipping the
   SERVER flag exposes web and (pre-6.7) Android clients. Non-native shells must fall to **loud
   downgrade, never false-green** — a manual web-participant + non-native-shell downgrade proof
   gates the flip. Flipping in production before 6.7 makes every Android participant a permanent
   loud-downgrade trigger (safe, but a degraded product state — a conscious decision, not a side
   effect).
7. **Finding CR-HIGH-2 resolved** (§2.7 SFU coupling landed + non-cooperative T-20 leg PASS) or the
   residual explicitly accepted as a named downgrade-prompt DoS.
8. **Standing deploy debts**: rebuild delta/bonfire/voice-ingress/desktop off committed source,
   operator multi-device E2E (slice-4 pattern), livekit-server version record.

The committed `Revolt.overrides.toml` default stays **FALSE**; the staging flag is turned back OFF
after the live legs unless the user directs otherwise. The verdict is the owed deliverable
regardless of outcome — a clear "cleared to flip" or an itemized "what remains."

---

## Status

- [x] 0 PLAN audit — full panel (media-e2ee-reviewer APPROVE-WITH-FIXES; e2ee-crypto-reviewer
      APPROVE-WITH-FIXES); ALL findings folded — see the plan-audit log below. (frontend-code-reviewer
      signs off at the FINAL diff gate per §8.)
- [x] 1 D12 server enforcement — DONE. `voice/mod.rs` `MAX_VIDEO_PARTICIPANTS` + `count_video_participants`
      + `is_video_source`; `voice_join.rs` video-cap join gate + §2.7 SFU-token coupling; `voice_client.rs`
      `mute_track` wrapper (`mute_published_track` exists in livekit-api 0.4.23); voice-ingress enable-leg
      (mute, stay-audio); `VideoCallFull` error (both status maps). count-helper REFERENCE test green.
- [x] 2 D10 park-for-fetch (bounded, defensive-consume, Welcome-first) + D11 dedup-reserve — DONE.
      `mlsDrainPolicy.shouldParkForPendingFetch` (+4 tests); `#pendingIdentityFetch`/`#parkedDuringFetch`
      wired into `#pump`/`#consume`/`#resetGroupBuffers`; D11 reserves the admit key before the await.
- [x] 3 6.5 LOWs — DONE. LOW-1 verified already-correct (screenshare publishes → `localTrackPublished`
      re-asserts the gate; no independent resume path); LOW-2 `useCallPrejoinMode` reads the toggle in the
      resource SOURCE (reactive); LOW-3 `#setModeChained` serializes the 3 racy label sets onto `#modeChain`.
- [x] 4 Harness — T-19 Add recovery + T-08 16-epoch wrap native tests (21/21); T-20 **native admit cap**
      code + delta join_intent/CAS (existing) + §2.7 SFU coupling; T-06-ext chip node cases (chipState was
      already a pure unit-tested module — no extraction needed; LOW-12 resolved as pre-satisfied).
- [x] 5 Scrub sweep — CORRECTED grep set + bonfire scope + `MlsFrameKey` Debug structural check: CLEAN (§7a).
- [~] 6 Deploy prereqs + live legs — **RUN 2026-07-12 in a dedicated live-proof session (§7c).** Most
      legs PASS; surfaced a NEW CRITICAL: T-20/D12 caps bypassed by client `force_disconnect:true`
      (§7c table + §9 blocker). Residual NOT-RUN: raw SFU-node packet capture, native-dialog confirm
      (computer-use denied), reactive fetch_identity (proactive re-pins). Flag stays FALSE (§9).
- [ ] 7 FINAL slice-6 audit — full panel on the diff; fix; re-verify
- [ ] 8 Commit disentangled (stoatchat/acutest, frontend/main, stoat.js/sloga, desktop/master); flag verdict

## Plan-audit log (2026-07-12)

**Gate:** plan §8 row 6.6 FINAL — full panel. Both reviewers **APPROVE-WITH-FIXES**; every finding
folded (none rejected). Reviewers verified load-bearing code claims against the live trees.

### media-e2ee-reviewer (APPROVE-WITH-FIXES)
- **HIGH-1** native `mls_call_admit` has NO roster cap (only one-device backstop); the claimed
  native T-20 test would fail / needed unbudgeted native code — FOLDED §4.3: **add the native
  admit-cap as a named native change** (defense-in-depth), corrected coverage table.
- **MED-2** `count_video_participants` key composition fails OPEN on server channels — FOLDED §2.2:
  exact `{user}:{server_id.unwrap_or(channel_id)}` composition + server-channel test requirement.
- **MED-3** T-08 wraparound falsely "covered" — FOLDED §4.4a: new native ≥16-epoch wrap test;
  coverage table T-08 → 6.6.
- **MED-4** D10 park bound mischaracterized (round-trip-scoped, not `#parkAttempts`) + single-group
  assert must be defensive-consume — FOLDED §3.1.
- **MED-5** video-enable mute API unverified + disconnect fallback contradicts client toast +
  enforce-after-publish window — FOLDED §2.4a (API-check FIRST; no silent contradictory disconnect).
- **LOW-6** join-leg placement/precedence self-inconsistent — FOLDED §2.3. **LOW-7** two 100 caps,
  lowered-ceiling test = server leg only — FOLDED §6.3 + lockstep note. **LOW-8** screenshare-audio
  sets `screensharing` → counts as video — FOLDED §2.2 (documented conservative direction).
  **LOW-9** scrub omits bonfire — FOLDED §5. **LOW-10** T-16/T-11 thin claims — FOLDED coverage
  table. **LOW-11** plan still names `hostile_ds.rs` — pointer note added to master plan §6/§8.
  **LOW-12** commit to chip extraction — FOLDED §4.4 (`mlsChipPolicy.ts`).
- Q-answers: Q-D12-1 product-gate/not-E2EE-gated ✓; Q-D12-2 no ManageChannel exemption ✓; Q-D12-3
  mute-preferred, blocked on API check ✓; Q-D12-4 join-reading matches §0.2 ✓; Q-H-1 extend
  `mls_adversarial.rs` ✓ (+plan pointer); Q-D11-1 reasoning+live-metric proportionate ✓; Q-LOW3-1
  see CR-MED-4; Q-LIVE-1 lowered ceiling OK with LOW-7 caveat; Q-FLAG-1 staging-only at 6.6.

### e2ee-crypto-reviewer (APPROVE-WITH-FIXES)
- **HIGH-1** scrub grep set matches NONE of the real secret identifiers + misses `MlsFrameKey`
  `Debug`/`Serialize` log-sink risk + omits `models/mls`/`v0/mls.rs`/bonfire — FOLDED §5 (corrected
  regex + scope + structural check).
- **HIGH-2** T-20 downgrade-suppression rests on the adversary cooperatively auto-leaving; a
  non-cooperative alt sits on the SFU as a non-enrolled ghost → repeated loud-downgrade DoS —
  FOLDED §2.7 (SFU-token coupling for E2EE-active calls at the MLS ceiling) + §6.3 rewritten to a
  non-cooperative joiner.
- **MED-3** T-19 "no secrecy impact" false for a withheld **Remove** (extends invariant-7 window;
  within §5.6 but not absolute) — FOLDED §4.2 (Remove caveat + heartbeat/divergence-timeout catch).
- **MED-4** the `await #modeChain` guard does not serialize (separate microtask) — FOLDED §3.5:
  prefer `#applyMode` conversion or append onto the chain; "never plaintext" carried by publish-gate
  reason-set + invariant-11 dual gate, not the mode label.
- **MED-5** D10 re-feed ordering (Welcome-before-parked) is correctness-sensitive (availability;
  secrecy safe via native epoch gate) — FOLDED §3.1 (explicit invariant + assertion).
- **LOW-6** §6.3 must mandate store surgery, forbid a shippable proactive-reconcile bypass — FOLDED.
  **LOW-7** join-leg precedence (== ME-LOW-6) — FOLDED §2.3.
- Q-answers: Q-D12-1 ✓ (zero secrecy dimension; must not gate on E2EE); Q-LOW3-1 → `#applyMode`
  conversion; Q-FLAG-1 **not sufficient alone** — FOLDED §9 (bundled-origin+CSP lock, invariant-2
  reconfirm, corrected scrub, SFU passthrough, finding-2 resolution as hard preconditions).

## FINAL slice-6 audit (2026-07-12, on the diff) — full panel

**All three reviewers APPROVE-WITH-FIXES; code commit-ready. `media_e2ee_enabled` stays FALSE.**
media-e2ee-reviewer + e2ee-crypto-reviewer + frontend-code-reviewer each independently confirmed
the load-bearing invariants (D10 secrecy holds regardless of splice order; native admit-cap is
atomic + fails closed; `#setModeChained` truly serializes; scrub CLEAN, re-run independently by the
crypto lens with no miss). Findings and dispositions:

- **[MED] T-19 Remove-case assertion (both media+crypto)** — the §4.2 withheld-Remove test was
  missing. **FIXED**: added native `under_fanout_remove_parks_then_recovers_in_order_when_refetched`
  (3-party: alice removes carol, withheld from bob → bob gaps → refetches → applies in order → carol
  gone from bob's verified roster, keys re-agree). §4.5 T-19 updated.
- **[MED] T-08 keyring index-overwrite untested at any layer (media)** — **DISPOSITION**: native
  test proves per-epoch derivation distinctness; `lagAction` desyncs a lagging receiver to
  rejoin-fresh BEFORE a wrapped index is reached (so no stale key served). The direct JS
  `mlsCallKeys` overwrite test is recorded as a **tracked residual** (§4.5) — honest wording, not a
  false "covered".
- **[LOW] D10 escalate races the in-flight fetch timer (all three)** — **FIXED**: added
  `#identityFetchGen` generation token; escalate + `#resetGroupBuffers` bump it; the detached fetch
  timer no-ops its re-feed if the generation advanced (superseded). No stale-Welcome re-feed vs
  rejoin.
- **[LOW] native `MlsCallFull` latched the admitter's own call loud (media)** — **FIXED**:
  `#stageAndSubmit` build-catch treats `kind==="admit"` + `mls_call_full` as a benign no-op (refusing
  an overflow joiner never downgrades the admitter's E2EE call).
- **[LOW] D11 reserved key orphaned if `#reconcileRoster` rejects (frontend)** — **FIXED**: wrapped
  the reconcile in try/catch with `delete(key)` in BOTH `#onJoinRequest` and `#serveRejoin`.
- **[LOW] Welcome-before-parked ordering had no regression guard (frontend)** — **FIXED**: extracted
  pure `spliceParkedAfterWelcome(welcome, parked)` + unit test; `#consume` uses it.
- **[LOW] `VideoCallFull` client error mapping (media)** — **DISPOSITION**: not in the generated
  error union / `errors.ts`, consistent with its sibling `MlsCallFull` (also unmapped there); both
  rely on the client-side gate (`videoCapReached()` / pre-join cap) as primary UX with the server
  409 as a rare fail-safe that shows a generic toast. Tracked follow-up: API-type regen + an
  `errors.ts` case (out of scope for a frontend-only change).
- **[LOW] D12 non-force rejoin gets `VideoCallFull` not the in-voice error (crypto)** — accepted,
  documented in §2.3 (both reject; cosmetic only).
- **[HIGH commit-hygiene, crypto] stoatchat tree mixes 6.6 with Apple OAuth** — handled at commit
  via filtered-hunk staging (Step 8); the 6.6 media hunks are staged, OAuth hunks left unstaged.
- **[informational] native test `assert_eq!(frame_key_map…)` prints base64 key material ON FAILURE
  ONLY** (crypto) — test-only, outside the production-sink scope; noted, not changed.

**Flag DoD reaffirmed (§9) with one addition**: both security reviewers name the live-leg matrix
(§7b, NOT RUN) + the T-01 SFU-node ciphertext capture + the bundled-origin/CSP artifact lock as the
hard preconditions for a production flip; the crypto lens adds the T-19 Remove assertion (now FIXED)
to that list. Desktop panel APPROVE does NOT by itself clear the flip.

### Cross-cutting resolution
- **T-20** is closed by THREE coordinated pieces: native admit-cap (§4.3, ME-HIGH-1),
  server SFU-token coupling (§2.7, CR-HIGH-2), and a non-cooperative live leg (§6.3). The server
  coupling is the load-bearing one; the native cap is defense-in-depth; the live leg is the proof.
- **Scrub sweep** (§5) rewritten wholesale — the old set was non-functional.
- Both reviewers name the **livekit-server SFU passthrough** (master §7.1 Q7) as the single biggest
  residual for a production flip — elevated to a §9 hard precondition (T-01 captured at the SFU node).
