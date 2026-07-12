# Slice 6.5 — Downgrade UX + verification: implementation breakdown

Breakdown for sub-slice 6.5 of [e2ee-media-mls-plan.md](e2ee-media-mls-plan.md) (plan §8 row
6.5). Written 2026-07-12, **before coding** (house audit-before-code pattern, as 6.1–6.4).
Gate at the end: **frontend-code-reviewer + media-e2ee-reviewer — BOTH** (plan §8).
**REVISED 2026-07-12 after the dual plan audit** (media-e2ee-reviewer APPROVE-WITH-FIXES,
frontend-code-reviewer NEEDS_REVISION); ALL 31 findings folded — see the plan-audit log at
the end. `media_e2ee_enabled` stays **FALSE** through 6.5 (flip belongs with 6.6).

6.4 landed the control plane and the ratchet-toward-encrypted direction: create/join/admit,
rotation, roster reconciliation DETECTION, the enable gate, and the fail-closed pause on any
mix. 6.5 is the layer the user actually sees — and the ONLY path that ever resumes publishing
as plaintext (explicit, per-device, native-confirmed).

Plan sections owned here: §3.4 (downgrade machinery + mode-transition state machine), §4.4
(corrected indicator surfaces), §0.2 #9 ("Encrypt my calls" toggle + attribution + consent
fine print), A3 (cap-refusal UX), safety-number roster entry point (§1.3).

## Contract inputs (fixed by 6.1–6.4 + the KeyPackage-UX slice; all committed, not pushed)

### Session (`packages/client/components/rtc/mlsCallSession.ts`, frontend `115cab07`)

- `MlsSessionState = "starting"|"active"|"plaintext"|"resecuring"|"failed"|"closed"`;
  `deps.onStateChange` observer.
- Enable state machine (step 6): `#evaluateEnable` off every FRESH `reconcileNow()` —
  **NB (audit FE-1): the mix-pause branch fires only when `#e2eeEnabled` is already true**
  (`:2306-2322`); a never-enabled session (joiner pre-Welcome, mixed-from-start) today
  pauses NOTHING. `#enable()` = pause → `setEncryptionEnabled(true)` → resume;
  `#onMixDetected()` = PAUSE; `#scheduleReupgrade()` = 15 s hysteresis → warm-group resume.
- `MlsMediaBinding`: `installer`, `localIdentity()`, `sfuParticipants()`,
  `onEncryptionState?("clear"|"resecuring"|"loud", error?)` — **NB (audit FE-2): the 10 s
  RE-SECURING→loud escalation arms only on an `encryptionError`** (`:2001-2014`), not on a
  merely-missing status. `onRosterReconciled?`, `setEncryptionEnabled?`,
  `pausePublishing?`/`resumePublishing?`.
- `rosterConsistent()`, `nonEnrolled()`, leave-grace(10 s)/ghost(30 s) timers, heartbeat,
  `#tryAdmit` refusal at 100 (admitter-side), successor/rejoin machinery (`#rejoinFresh`,
  `supersedes`), bounded re-establish, metrics.
- Policy modules + tests: `mlsDrainPolicy.ts`, `mlsEnvelopeClassify.ts`,
  `mlsJoinRequestPolicy.ts` — 22/22 `node --test` green at 6.4 HEAD.

### RTC store (`packages/client/components/rtc/state.tsx`, frontend `115cab07`)

- `callEncryption: ReactiveMap<identity, boolean>`, `callEncryptionError` (latched
  structured), `callNonEnrolled`.
- `#buildMediaBinding(room, provider)`; `#setUpstreamPaused` — **NB (audit FE-3): iterates
  only EXISTING publications (`:808-815`); `toggleCamera` (`:864`), `toggleScreenshare`
  (`:1250`), PTT/VAD mic re-enable (`:1484`, `:1527`) publish NEW tracks that bypass any
  asserted pause; `toggleScreenshare` also drives `pauseUpstream`/`resumeUpstream` itself
  for its quality modal (`:1328-1352`) — a second uncoordinated pause owner.**
- **NB (audit FE-1): local publishing starts at the `connected` handler (`:447-498`),
  BEFORE the session is constructed (`:666-676`).**
- **NB (audit FE-9c, pre-existing bug in this seam): the supersession bail paths
  (`:569-573`, `:613-616`, `:621-623`) call `room.disconnect()` WITHOUT
  `removeAllListeners()` — the abandoned room's async `disconnected` event later fires
  `#setState("DISCONNECTED")` + `nativeCallServiceStop()` (`:500-503`), clobbering the
  newer call's state / killing the Android foreground service.** 6.5 fixes this in
  passing (Step 5).
- Session constructed after `room.connect` + identity assertion; several no-session arms
  (null bridge / missing provider/worker) skip construction WITHOUT latching an error
  (audit ME-7); disposed in `disconnect()`/failed-connect/supersession.

### Bridge (`packages/client/components/client/e2ee.ts`, frontend `115cab07` + `3d604dab`)

- 17 `e2ee_call_*`/`e2ee_mls_*` wrappers incl. `callConfirmDowngrade(channelId,
  nonEnrolled?)` — the 6.3 dialog gate, roster webview-supplied (the tracked LOW).
- DS couriers over `#apiMls`; `registerMlsSink`; `onEvent` normalizes `MlsJoinRequested`/
  `MlsCommit`/`MlsWelcome`; `ackEnvelopes`; `callStates` ReactiveMap;
  `#prepublishMlsKeyPackages()` UNGATED at `enable()` (:2665) / `finishReenroll()` (:2865);
  `nativeKeyPushAvailable()`.

### Native (`acutest-desktop/src-tauri/e2ee-core`, desktop `f106a94`)

- `mls_call_state → MlsCallState { …, members: [{user_id, device_id, user_verified}] }` —
  `user_verified` = slice-5 pin state (the per-participant lock input).
- Envelope dispatch (`mls/mod.rs:817-821`): `mls_welcome` | `mls_commit` only — NO
  application-message primitive. Envelope dedup at `mls/mod.rs:794-815`. Group configs
  (`:210-223`) leave OpenMLS `max_past_epochs` at 0 — **an application message from a
  prior epoch is undecryptable (audit ME-4)**.
- `e2ee_call_confirm_downgrade(channel_id, non_enrolled)` (`src/e2ee.rs:1453`): blocking
  native dialog, names webview-supplied.
- IPC has FOUR sync points.

### Server DS (`stoatchat/acutest`, `b9f6e05a` + `e740c2cb`)

- `/mls` routes: key_packages publish/claim, groups create (channel-arbitrated 409),
  join_intent (sig-verify-first + rejoin affordance + solo-close — **the rejoin arm at
  `join_intent.rs:101-117` serves devices ALREADY in the roster**), commits (arbitrated,
  fan-out with per-recipient queue budgets 512/32 MiB), commits fetch.
- **CORRECTED ground truth (audit ME-2 — the first draft of this doc was wrong):** the
  E2EE roster ceiling IS server-enforced, in both drivers: `MAX_MLS_GROUP_MEMBERS = 100`
  (`models/mls/model.rs:19-23`), enforced inside the commit CAS
  (`ops/reference.rs:302-311`, `ops/mongodb.rs:464-466` — `members + added − real_removals
  > 100` ⇒ refused; `commits_submit.rs:232-234`). What is missing is (a) a
  join_intent-time check (today an overflow joiner burns the full intent→claim→admit
  round-trip and the ADMIT fails at the CAS) and (b) any enforcement of
  `MAX_VIDEO_PARTICIPANTS` (correctly absent everywhere — the A3(b) 6.1 assignment never
  landed).
- `E2EEContentType { Olm, MlsCommit, MlsWelcome }`; MLS types minted server-side only.
- Bonfire: `MlsJoinRequested{…, rejoin}`, `MlsCommit(E2EEMessage)`, `MlsWelcome(E2EEMessage)`.
- `fetch_open_mls_group_for_channel` in both drivers (ops.rs:98); voice-ingress closes the
  open group on `room_finished` (`api.rs:345-350`) — the pre-join probe's 404 is live truth.

### UI + state stores (frontend `115cab07`)

- `VoiceCallCardStatus.tsx` (connection chip only), `ParticipantTile.tsx` (no lock),
  `VoiceCallCardActiveRoom.tsx` — **all chrome hidden behind `<Show when={!voice.
  immersive()}>` (`:27`; audit FE-12)**; fullscreen is per-element.
- Pre-join surfaces: `src/interface/channels/ChannelHeader.tsx:165/177`,
  `VoiceCallCardPreview.tsx`, `VoiceChannelPreview.tsx`. (Master-plan citation
  re-corrected: this fork's join controls are in `ChannelHeader.tsx`, which exists.)
- `settings/user/SecurityAndPrivacy.tsx` (`EncryptionCard`); `modals/E2EEVerify.tsx`
  (`e2ee_verify`, `peerUserId`) — **NB (audit FE-10): it renders from
  `conversationState(peerUserId)` with DM-centric fallback copy, and its `turnOff()`
  silently no-ops without a DM channel.**
- State stores: **`Voice.ts` is a persisted LOCAL store — NOT synced**
  (`Sync.ts:14-20` syncs only `ordering`/`notifications`/`release-notes`; audit FE-5/ME-1).
  New fields go through `default()` + `clean()`.

## Deferred-item sweep (the explicit 6.3/6.4 debts this slice owes)

| # | Source | Item | Disposition in 6.5 |
|---|---|---|---|
| D1 | 6.3 [6.5, crypto LOW] | Dialog roster from the NATIVE verdict | **In scope** — Step 2 |
| D2 | 6.3 notes | `callEncryption`+`callEncryptionError` consumed by the §4.4 chip | **In scope** — Step 5 |
| D3 | 6.3 judgment call 1 | ctl-announce + mode-transition machine | **In scope** — Steps 1/2/4 |
| D4 | 6.4 scope boundary | Banner, confirm-to-plaintext, native confirm, dual chip, cap polish, safety-number entry | **In scope** — Steps 2–9 |
| D5 | 6.4 step 5 | Divergent-leaf roster panel from `ghosts` | **In scope** — Step 6 |
| D6 | 6.4 step 6 | Joiner-side "call full for E2EE" UX | **In scope** — Steps 1/4/5 (join_intent check + auto-leave) |
| D7 | 6.4 gate MED-3 | `disp.loud` has no consumer | **In scope** — Step 4 |
| D8 | 6.4 gate LOW-2 + rejoin LOW-3 | Silent security-telemetry catches | **In scope** — Step 4 |
| D9 | 6.4 rejoin LOW-2 | Replay-kick churn telemetry | **In scope** — Step 4 |
| D10 | 6.4 gate MED-2 | Drain vs pending identity-fetch | **Deferred to 6.6** (harness-exercised) |
| D11 | 6.4 gate LOW-1 | Admit dedup key post-await | **Deferred to 6.6** |
| D12 | A3(b) | `MAX_VIDEO_PARTICIPANTS` server enforcement (assigned 6.1, never landed, now twice-slipped) | **Named, tracked 6.6 GATE ITEM** (media reviewer's ratification condition); 6.5 lands the client product gate + UX (Step 8) |
| D13 | KeyPackage-UX | Client `mfa_required` fallback removal | Not 6.5 (post-rollout) |

## Approved judgment calls (revised 2026-07-12 per the dual audit)

1. **Ctl-announce = an MLS application message, `content_type: "mls_ctl"`, member-gated
   fan-out route — and the announce primitive is NATIVE-GATED on a prior confirm (ME-12).**
   Native gains `mls_call_announce(group_id)` which mints the group-encrypted announce
   ciphertext **only for a group whose `downgrade_confirmed` flag is set** — the flag is
   set exclusively by the native confirm dialog (`e2ee_call_confirm_downgrade` → Ok) and
   cleared on group close / successor / re-upgrade. A compromised webview therefore cannot
   originate announces at will (no announce-oracle); the command exists so the session can
   RE-ANNOUNCE after epoch changes (see state machine) without re-prompting the user.
   Envelope dispatch gains `"mls_ctl"` → `process_message` → `ApplicationMessage` →
   `MlsProcessOutcome { kind:"ctl_received", epoch, sender_user_id, sender_device_id,
   ctl_payload }` — sender from the VERIFIED leaf (§1.3 one-primitive rule; realizes the
   slice-5 ctl authority rule). Stale/undecryptable ⇒ `Error::MlsStaleCtl` → quiet
   ack+drop; **a ctl can NEVER park the drain, advance an epoch, or poison a group.**
   Forward-compat (ME-15): unknown `v`/`kind`, malformed JSON, or any mode other than
   exactly `"plaintext"` ⇒ quiet drop — there is NO `mode:"e2ee"` trigger (re-upgrade is
   automatic-only). Server: `E2EEContentType::MlsCtl` + `MAX_MLS_CTL_RAW_SIZE = 4 KiB` +
   `POST /mls/groups/<id>/messages` — session-USER-level membership gate (sufficient:
   only a member can mint decryptable group ciphertext — stated per FE-15), server stamps
   sender (invariant 5), fan-out to roster minus sender via the commits queue-budget
   machinery, live push as new bonfire `MlsCtl(E2EEMessage)`. **Rate limit (ME-5):
   per-(sender, group) — v1: min 5 s interval, burst 2** (a legitimate announce is ~once
   per interlude + epoch-change re-announces), so a ctl flood cannot crowd commit
   envelopes out of the 512/32 MiB per-recipient budgets. §5.6 gains a one-line
   accepted-metadata amendment for the ctl event ("a member announced a mode change at
   time T") in the same diff (ME-13). *Why not the commits pipe:* commits are
   epoch-arbitrated + consecutive-epoch-ordered; a ctl neither arbitrates nor advances.
   **IPC allowlist growth, honestly flagged:** one changed signature
   (`e2ee_call_confirm_downgrade`) + one NEW but confirm-inert command
   (`e2ee_call_announce`) vs 6.3's "allowlist complete" promise — surfaced at the gate.
2. **The confirm dialog's roster is computed NATIVELY (closes D1).**
   `e2ee_call_confirm_downgrade(group_id, sfu_participants: Vec<String>, display_names:
   Map<user_id, String>)`: native computes `non_enrolled = sfu_participants ∖
   verified-roster-identities` from ITS `mls_call_state` roster and renders the dialog
   from that set; on Ok it sets the group's `downgrade_confirmed` flag and returns the
   first announce ciphertext. Display names label natively-selected IDs only, and the
   dialog **renders the raw user_id alongside each supplied name** (ME-11's residual
   blunted). Trust wording (corrected per ME-11): `sfu_participants` is
   webview-controlled, so the webview CAN shrink (omit) or grow (fabricate) the computed
   set — this is safe only because the dialog's authorization semantics ("turn off
   encryption for this whole call?") do not depend on the set's contents, shrinkage
   cannot suppress the dialog (it shows even when the computed set is empty, with a
   generic "participants could not be verified" line — fail toward prompting), and the
   set never feeds anything but display.
3. **"Encrypt my calls" toggle is LOCAL PER-DEVICE (Voice store field, NOT added to the
   sync set), default OFF (FE-5/ME-1).** Syncing it would hand the server a write path
   (`UserSettingsUpdate`) into the E2EE-attempt gate — a hostile server flipping a
   creator's toggle to OFF yields silent plaintext calls with a `none` chip. Per-device
   also matches reality (capability IS per-device) and §0.2 #9's per-device attribution.
   The settings card copy states "on this device". If cross-device sync is ever wanted, a
   remote OFF must surface and require local re-ack — out of scope. Field rides
   `default()` + `clean()` (`typeof input.e2eeCallsEnabled === "boolean"`). Gates:
   (a) session construction in `state.tsx`; (b) `#prepublishMlsKeyPackages` — via a
   **REQUIRED** `callsEnabled: () => boolean` bridge dep at the real construction site
   (FE-14/ME-14: no fail-open default; the test factory may default it). Toggle ON
   requires enrollment (routes through `e2ee_enable` first); the confirm carries the
   media fine print. Toggle OFF takes effect on the NEXT call. Stale published
   KeyPackages remain harmless (nothing claims agency: unsolicited-Welcome refusal is
   native, intents are group-scoped + signature-bound; worst case a member-forged
   phantom Add = ghost leaf → 30 s sweep — verified by the media audit).
4. **Pre-join mode = one cheap read-only probe + local capability, with a process-wide
   cache and a bridge-independent transport (FE-11).** `GET /mls/groups/open/<channel_id>`
   (channel-access-gated + feature-gated) → 200 `{ group_id, member_count }` | 404.
   A single shared `useCallPrejoinMode` hook backed by a module-level cache keyed by
   channel (TTL ~10 s; refresh on `voiceParticipants` change): three mounted surfaces
   share ONE in-flight request. A `feature_disabled` verdict is cached PROCESS-WIDE and
   stops all probing (with the flag FALSE all slice, zero steady-state traffic).
   Transport: plain authenticated raw fetch (the stoat-api generated tables won't carry
   this route — known body-drop gotcha), NOT `#apiMls`, so the **web shell probes too**:
   web sees "This call is end-to-end encrypted — you'll join unencrypted and the call
   will show a warning" (the honest §0.2 #9 self-attribution; FE-11). Badge logic:
   open group ⇒ "End-to-end encrypted call" (+ cap pre-warning at
   `member_count ≥ MAX_MLS_GROUP_MEMBERS`; + self-attribution when the local device
   won't join it: web / toggle-off / not enrolled); no open group ⇒ own-eligibility
   "Will be end-to-end encrypted" vs no badge. Metadata: nothing beyond §5.6's existing
   concessions, to channel-access holders only.
5. **A3 cap refusal: join_intent-time check + joiner auto-leave + mix-classification
   grace (revised per ME-2/ME-3/FE-4/ME-10).** Server: `join_intent` refuses a
   **NEW-member** intent when `group.members.len() >= MAX_MLS_GROUP_MEMBERS` (REUSE the
   existing constant — no second 100) with new error `MlsCallFull` — **ordered AFTER the
   membership/rejoin branch** so a stale-leaf member's rejoin at exactly-100 still
   succeeds (ME-3; test pinned). This is the polite third layer; the commit-CAS ceiling
   remains the hard guarantee. Client: `MlsCallFull` ⇒ terminal `call_full` mode, loud
   chip, and **auto-leave the SFU call** (deferred via `queueMicrotask` — never
   `disconnect()` synchronously from inside a session callback; FE-9b) with an
   explanatory dialog. *Why auto-leave:* a lingering refused joiner is, by the §3.4
   trusted enumeration, a non-enrolled participant — the one-account downgrade-prompt
   lever A3 rejects. **Generalized (ME-10):** ANY terminal loud failure of an E2EE-known
   call (retry-exhaustion RE-SECURING → failed, not just call_full) surfaces a blocking
   choice — "Leave call" (primary) / "Stay unencrypted" (native confirm, T3) — so no
   failure mode leaves a keyless participant silently parked in the SFU. Residual: a
   malicious client ignores all of this; prompt-never-suppress remains the actual
   invariant. **Mix-classification grace (FE-4):** a freshly-joined SFU identity does
   not count as non-enrolled until it has been present `MIX_CLASSIFY_GRACE_MS = 3 s`
   (one reconcile generation) — during the grace we keep publishing ENCRYPTED (the
   safe direction: a non-enrolled participant cannot decrypt those frames), so a
   cap-refused joiner's ~1–2 s in/out never pauses the call, never flips the chip, and
   never arms the 15 s re-upgrade hysteresis. The grace delays CLASSIFICATION (pause +
   banner + chip together), not any plaintext decision.
6. **Two re-upgrade paths, kept separate — and the enable branch is MODE-GATED (ME-6).**
   (a) Mix cleared with no interlude: warm-group resume after 15 s hysteresis (6.4,
   unchanged — deviation from §3.4's blanket fresh-group re-upgrade RATIFIED as
   amendment; crypto-sound: E2EE was never disabled and the group never keyed a
   non-member). (b) Mix cleared after a confirmed interlude: T6 ONLY — 15 s hysteresis →
   FRESH successor group (`supersedes` flow) → normal enable. Normative rule: the
   `#evaluateEnable` enable branch requires `CallMode === "e2ee" || "negotiating"`; in
   `interlude` the sole exit is T6 (policy-tested), so a mix-clear can never
   warm-enable the old group under a confirmed interlude.
7. **The interlude keeps the group warm and the control plane running** (§3.4):
   heartbeat, admits, removes, rotations continue; frame keys keep installing while Room
   E2EE is off. **Because `max_past_epochs = 0`, every epoch change makes the previous
   announce undecryptable to late processors — so the session RE-ANNOUNCES after each
   epoch change while `interlude && localConfirmed` (ME-4; bounded by the ctl rate
   limit; native-gated by the `downgrade_confirmed` flag).** Members who still miss
   every announce converge anyway via their own mix detection (policy test: "announce
   lost ⇒ member still reaches `mixed`, publishing paused" — the loss is
   availability-of-attribution only, accepted and documented; FE-15's early-ctl loss
   note folded here).
8. **Native `mls_call_send_mode` verdict is DROPPED for v1 — ratified deviation
   (ME-9a).** Ongoing mix detection stays a webview-side SFU∖MLS computation. Defense:
   the direction is safe-loud (webview can over-warn, never suppress a prompt that
   matters, because the PLAINTEXT decision is native-gated); native cannot see the SFU
   roster without the webview feeding it anyway (§4.4 amendment A1's honest-limitation
   logic). The confirm-dialog set (judgment call 2) is the one place the §3.4
   "computed natively" stance is load-bearing, and there it IS native.

## The §3.4 mode-transition state machine (normative spec, revised)

```
CallMode = "negotiating"  — INITIAL (session exists, no verdict yet); local publishing
                            GATED (see publish gate below)
         | "off"          — not an E2EE call (feature/toggle off ⇒ session "plaintext");
                            publishing normal, no chrome (6.3 L4)
         | "e2ee"         — enabled, roster consistent, publishing encrypted
         | "mixed"        — non-enrolled present (post-grace); publishing PAUSED; banner
         | "interlude"    — confirmed plaintext window; substate localConfirmed: boolean
         | "call_full"    — terminal joiner-side A3 refusal (auto-leave)
```

**The publish gate (FE-1 + FE-3 + round-2 R2-1/R2-5/R2-7/R2-8 — the single pause
owner):** `state.tsx` owns ONE reason-set `publishGate:
Set<"negotiating"|"mixed"|"enable-window"|"resecure"|"share-modal">`; publishing is
allowed iff the set is empty. Asserted with `"negotiating"` **BEFORE `room.connect`**
(R2-5 — not merely at session construction; the `connected` handler's mic publish races
construction otherwise), and every empty→non-empty transition SWEEPS existing
publications. Every LiveKit `LocalTrackPublished` event immediately `pauseUpstream()`s
the new publication while the set is non-empty. **Hardening against livekit-client
2.15.13's unconditional resume paths (R2-1 — verified in the pinned source):**
(a) `setMediaStreamTrack` ends in an unconditional `resumeUpstream()` (fires on device
switch / `restartTrack` / unmute-with-restart / reconnect), and (b) `setProcessor`
replaces the sender track directly WITHOUT flipping `_isUpstreamPaused`, so a naive
re-assert no-ops on `pauseUpstream()`'s idempotency early-return. The gate owner
therefore (i) listens to `TrackEvent.UpstreamResumed` and `TrackEvent.
TrackProcessorUpdate` on every local track and RE-ASSERTS while the set is non-empty —
for the processor path via resume-then-pause (defeating the idempotency trap); and
(ii) DEFERS effect attachment while gated: the `connected` handler's denoise/gain attach
(state.tsx:469-484) and camera-effects attach (:883) run only once the gate clears
(they attach in-window today — the in-repo day-one leak). The screenshare quality-modal
pause becomes the `"share-modal"` reason — its direct `pauseUpstream()`/
`resumeUpstream()` calls (:1328-1352) are REPLACED by gate-owner calls (R2-8; a leftover
direct resume is another bypass). The session drives its reasons via the binding:
`pausePublishing(reason)`/`resumePublishing(reason)` gain a reason parameter (R2-7) so
mixed/enable-window/resecure pauses can't collapse or double-count. Policy/acceptance
lines: "publish attempted while gated stays paused" AND "processor attach / device
switch / unmute while gated does not resume flow".

Entry/exit transitions:

- **T0a `negotiating → off`**: session settles `"plaintext"` (feature off / toggle off /
  legacy server) ⇒ clear gate. With the flag FALSE this resolves in one round-trip —
  flag-off calls never stay muted.
- **T0b `negotiating → e2ee`**: enable completes (existing pause→enable→resume order).
- **T0c `negotiating → mixed`**: mix classified (post-grace) before enable ⇒ gate swaps
  `negotiating`→`mixed`; banner. (Closes FE-1's mixed-from-start plaintext hole: the
  never-enabled session STILL pauses.)
- **T0d fail-safe resume (FE-1, bounded availability escape):** if after
  `NEGOTIATING_FAILSAFE_MS = 5 s` the session has produced NO verdict (DS unreachable)
  **AND the channel's open-group probe has completed with 404/feature-off — or errored
  (R2-6: the probe and the DS share an origin, so they fail together; probe-error ⇒
  resume is RATIFIED as part of this availability escape)** — clear the `negotiating`
  reason and keep negotiating in the background — documented plaintext-availability
  tradeoff, policy-tested. If a completed probe says an open group EXISTS, the gate
  stays asserted and the state goes loud RE-SECURING (bounded → the ME-10
  Leave/Stay-unencrypted choice) — an E2EE-known call never auto-resumes plaintext.
- **T1 `e2ee → mixed`**: reconcile classifies a non-enrolled identity present ≥ the 3 s
  grace ⇒ pause + banner + chip together (grace per judgment call 5; publishing during
  the grace stays ENCRYPTED).
- **T2 `mixed → e2ee`**: mix clears, nobody confirmed ⇒ 15 s hysteresis ⇒ warm resume
  (ratified amendment, judgment call 6a).
- **T3 `mixed → interlude(localConfirmed=true)`**: user action →
  `session.confirmPlaintext()`: (1) native dialog (judgment call 2) — Declined ⇒ stay
  `mixed`; (2) Ok ⇒ native sets `downgrade_confirmed` + returns announce ciphertext;
  courier it (best-effort — announce failure never blocks the local transition);
  (3) `setEncryptionEnabled(false)`; (4) resume (clear gate); (5) mode = interlude.
  **Order invariant: E2EE-off strictly before resume.**
- **T4 `mixed → interlude(localConfirmed=false)`** (remote announce): verified
  `ctl_received` with `mode:"plaintext"`, matching group+channel ⇒ re-word banner
  ("<user> turned off encryption…", "Resume unencrypted" / "Leave"); **publishing stays
  PAUSED — an announce can never open the local plaintext path.**
- **T5 `interlude(false) → interlude(true)`**: local confirm = T3 steps 1,2,3,4,5; the
  native flag-set + announce still run (idempotent; racing double-announces harmless).
- **T6 `interlude → e2ee`**: last non-enrolled leaves ⇒ 15 s hysteresis ⇒ successor
  group ⇒ enable. `localConfirmed` resets — per-interlude stickiness. **Documented
  (ME-16): `localConfirmed` persists across non-enrolled TURNOVER within one interlude**
  (Alice-web leaves, Bob-web joins inside the hysteresis ⇒ interlude continues; the
  banner's names update live) — intended, pinned by a policy test.
- **T7 `negotiating|e2ee|mixed → call_full`** (JOINER-side only — members never receive
  `MlsCallFull`; FE-15) ⇒ loud chip + deferred auto-leave (judgment call 5).
- **Re-secure interactions**: group re-establish keeps CallMode; `#resetEnableState`'s
  pause-through-re-secure applies EXCEPT in `interlude(localConfirmed=true)` — a
  locally-confirmed member keeps publishing plaintext through a control-plane re-secure
  (their authorization came from the user; Room E2EE is off, no key dependency).
- **Session-state map for the chip:** `starting` ⇒ chip `none` (FE-13 — no chrome flash
  on plain calls); `plaintext` ⇒ `off`.

Mixed-window semantics (§3.4, for tests): confirmed members publish plaintext;
unconfirmed members publish NOTHING; all members may receive plaintext with the loud
indicator visible; the group stays warm.

**Platform assumption, named as an OPEN QUESTION (ME-8):** "members may receive
plaintext while their Room has E2EE enabled" (mixed / interlude-unconfirmed receive
path) is unproven on livekit-client 2.15.13. Step 4 includes a SOURCE VERIFICATION
against the pinned package (the worker's handling of unencrypted inbound tracks /
per-track encryption signaling). If source-inconclusive, a live web-participant receive
smoke is pulled forward from 6.6 into this slice's acceptance — "Decline = receive-only"
must not ship as dead air.

## The §4.4 chip state machine (dual-gated, revised)

`callEncryptionChip()` inputs: session mode+state, `callEncryption`, `callNonEnrolled`,
`callEncryptionError`, MLS roster, **`callChannelHasOpenGroup`** (the probe result,
fetched at connect too — FE-7), and a `participantsVersion` signal bumped by the
existing `participantConnected`/`participantDisconnected` listeners **AND the
`trackPublished`/`trackUnpublished`/`LocalTrackPublished` listeners (R2-3 — gate (b)'s
quantification domain changes on publication, not just presence; a trackless-then-
publishing participant must drop the chip from green immediately)** (FE-8 —
`room.remoteParticipants` is not Solid-reactive; the derivation must not go stale).
Binding callbacks that set multiple signals wrap them in `batch()` (FE-8).

```
"none"           — no session AND no open group known (plain call, quiet); or session
                   "starting" (FE-13); or mode "off" with no open group.
"e2ee"           — GREEN. ALL of:
                   (a) mode "e2ee" + enabled + first local key + not resecuring + no
                       latched error;
                   (b) LiveKit-observed encrypted === true for every SFU participant
                       **WITH ≥1 PUBLISHED TRACK** (FE-2 — trackless listeners never
                       emit a status; they are covered by (a)/(c), i.e. MLS membership
                       + verification). Local counts when publishing. A participant
                       with published tracks and a missing/false entry ⇒ NOT green.
                   (c) every MLS roster member user_verified === true.
"e2ee_unverified"— (a)+(b) hold, (c) fails. Tooltip names unverified peers.
"resecuring"     — session "resecuring"; or rotation-window MediaEncryptionState
                   "resecuring"; or (a) holds but (b) not yet satisfied for a
                   TRACK-PUBLISHING participant — this last arm is BOUNDED: the session
                   arms the existing 10 s escalation for it (extended beyond
                   encryptionError-only; FE-2's unbounded-amber fix) → loud. **The
                   escalation bookkeeping is PER-PARTICIPANT (R2-2):
                   `noteEncryptionRecovered` must not globally clear it — before
                   cancelling, re-check that no publishing participant still lacks an
                   encrypted status (participant A's missing status must not be defused
                   by participant B's events).**
"not_encrypted"  — LOUD: mode "mixed"/"interlude"/"call_full"; session "failed";
                   MediaEncryptionState "loud"; latched callEncryptionError; OR
                   (ME-7/FE-7) toggle-on + capable shell + session missing/failed
                   construction (every no-session arm in state.tsx now LATCHES a
                   structured error — **and when `callChannelHasOpenGroup` says the
                   call is E2EE, those arms ALSO assert the publish gate and surface
                   the ME-10 Leave/Stay choice (R2-4): a capable-but-failed client in
                   an E2EE-known call must not publish plaintext behind a mere loud
                   chip**); OR toggle-OFF self in a channel whose open-group probe
                   says the call is E2EE (§0.2 #9 self-attribution).
```

Precedence: `not_encrypted` > `resecuring` > `e2ee_unverified` > `e2ee` > `none`.
Neither gate alone produces green; server flags never promote; clean rotations never
flap (session debounce is the sole rotation `resecuring` source).

## Steps (numbered — repo · plan §)

1. **Ctl transport + probe + cap (server + stoat.js).** `E2EEContentType::MlsCtl` (+ v0)
   + `MAX_MLS_CTL_RAW_SIZE = 4 KiB`; `POST /mls/groups/<id>/messages` — feature-gated,
   member-USER-gated, size-capped, per-(sender,group) rate limit (5 s / burst 2),
   fan-out minus sender through the queue budgets, bonfire `MlsCtl(E2EEMessage)`;
   REFERENCE tests: member gate, sender excluded, size cap, rate limit, feature-off,
   budget skip. `GET /mls/groups/open/<channel_id>` over
   `fetch_open_mls_group_for_channel` — tests: 200 shape / 404 / access / feature-off.
   `join_intent`: `MlsCallFull` for NEW-member intents at
   `members.len() >= MAX_MLS_GROUP_MEMBERS`, placed AFTER the membership/rejoin branch —
   tests: 101st NEW intent refused; **rejoin at exactly-100 succeeds** (ME-3). §5.6
   one-line MlsCtl metadata amendment in the plan doc (ME-13). stoat.js: `MlsCtl` event
   + v1 dispatch (rebuild). · §2.3/§2.4/A3.
2. **Native announce + verdict (desktop).** Per-group `downgrade_confirmed` flag
   (in-memory on the engine's group row — cleared on close/successor/re-upgrade;
   NOT persisted secrets); `e2ee_call_confirm_downgrade(group_id, sfu_participants,
   display_names)` — native-computed set, raw-id rendering, empty-set still prompts,
   sets the flag, returns first announce ciphertext; `mls_call_announce(group_id)` —
   refuses (`Error::MlsNotConfirmed`) without the flag; dispatch `"mls_ctl"` →
   `ctl_received` outcome (verified sender leaf); `MlsStaleCtl` quiet; forward-compat
   drops (ME-15). New command through all 4 IPC sync points. e2ee-core tests:
   announce/process round-trip, announce-refused-without-confirm, sender verification,
   stale quiet, ctl-never-poisons, set-computation pure fn. · §3.4/§3.5/§7.2.
3. **Bridge plumbing (frontend `e2ee.ts` + classify).** `mlsSendCtl` courier; `onEvent`
   accepts `MlsCtl`; `callAnnounce` + re-signed `callConfirmDowngrade` wrappers;
   `classifyEnvelopeError` gains `MlsStaleCtl` → quiet ack+drop (+ test, default-closed
   intact); REQUIRED `callsEnabled` dep gating `#prepublishMlsKeyPackages` (test factory
   may default). Bridge-independent probe helper (raw authenticated fetch + module cache
   + process-wide feature_disabled latch). · §4.2.
4. **Session mode machine (frontend `mlsCallSession.ts` + `mlsCallModePolicy.ts`).**
   CallMode + T0a–T7 per the revised spec; publish-gate reasons via the binding;
   3 s mix-classification grace; enable branch mode-gated (ME-6); interlude re-announce
   on epoch change (ME-4); `confirmPlaintext()`; `#onCtlReceived` (T4/T5, dedupe,
   forward-compat); terminal-loud Leave/Stay choice (ME-10); `call_full` +
   deferred auto-leave signal; extended 10 s escalation to cover missing-status-on-
   publishing-participant (FE-2); D7 (`drop{loud}` → `#surfaceError`), D8/D9 telemetry.
   Binding gains `onCallModeChanged?`, `onRosterState?(members, ghosts)`. **ME-8 source
   verification of the unencrypted-receive path in livekit-client 2.15.13 recorded in
   the doc; if inconclusive → live receive smoke this slice.** Policy tests: every
   numbered transition incl. T0a–T0d, grace, confirm order, T6-sole-exit, no-warm-enable-
   after-interlude, announce-lost-converges, turnover persistence (ME-16), publish-
   attempted-while-gated, fail-safe-resume-only-without-open-group. · §3.4.
5. **Signals + publish gate + lifecycle (frontend `state.tsx`).** `callMode`/`callRoster`/
   `callChannelHasOpenGroup`/`participantsVersion` signals; `callEncryptionChip` derived
   per the revised spec; publish-gate owner + `LocalTrackPublished` hook + screenshare-
   modal refcount coexistence (FE-3); every no-session arm latches a structured error
   (ME-7); `confirmCallPlaintext()` action; deferred auto-leave (queueMicrotask +
   dispose idempotency; FE-9b); `disconnect()` resets ALL new signals (FE-9a);
   **fix the pre-existing supersession-bail listener leak — `removeAllListeners()`
   before `room.disconnect()` on the three bail paths (FE-9c)**; toggle gate on session
   construction; `batch()` in multi-signal callbacks. · §4.4.
6. **Call-card UX (frontend UI).** (a) Encryption chip in `VoiceCallCardStatus.tsx`
   (+ PiP variant — PiP shows the chip; the banner re-appears on un-PiP); click → (b)
   ROSTER PANEL overlay in `VoiceCallCardActiveRoom.tsx` — MLS-roster-driven (members +
   device count + `user_verified` badge; ghosts flagged "divergent"; SFU-only
   identities flagged "not encrypted"); each row →
   `openModal({type:"e2ee_verify", peerUserId, context:"call"})` — **E2EEVerify gains a
   `context` prop (FE-10): call-context fallback copy (no "send a message first"), the
   DM turn-off button HIDDEN in call context; Step verifies call-pinned devices
   (reconcileCallRoster pins) actually surface in `conversationState` and fixes the
   query if not.** (c) DOWNGRADE BANNER — blocking strip; `mixed`: names + attribution
   copy, "Turn off encryption for everyone" / "Leave call"; `interlude(false)`:
   "<user> turned off encryption" + "Resume unencrypted" / "Leave"; terminal-loud:
   "Leave" / "Stay unencrypted" (ME-10). Collapsible to the loud chip only. **The
   banner AND the loud chip render inside the immersive/fullscreen container too
   (`ImmersiveExit` overlay precedent — FE-12); never hidden by theater mode.**
   (d) Per-participant lock in `ParticipantTile.tsx` (MLS member: filled/outline by
   `user_verified`; non-enrolled: loud slashed lock — slice-5 iconography family).
   All new copy through lingui. · §4.4.
7. **Pre-join mode + cap pre-warning (frontend UI).** Shared cached
   `useCallPrejoinMode(channel)` (judgment call 4) feeding `ChannelHeader.tsx`,
   `VoiceCallCardPreview.tsx`, `VoiceChannelPreview.tsx`; badges: "End-to-end encrypted
   call" / "Will be end-to-end encrypted" / "Call full for E2EE (100)" /
   self-attribution (incl. WEB shell). Also feeds `callChannelHasOpenGroup` at
   connect. · §3.4/A3.
8. **Video-cap product gate UX (frontend).** Client gate: camera/screenshare toggles
   refuse (lingui toast) at SFU participants > `MAX_VIDEO_PARTICIPANTS = 30`;
   **documented in-code:** >30-after-video-on is NOT enforced until the 6.6 server leg
   (D12 — named 6.6 gate item); join-side refusal likewise 6.6. · A3(b).
9. **"Encrypt my calls" settings card (frontend).** `Voice` store `e2eeCallsEnabled`
   (default false, `clean()` handled, LOCAL — never added to `SynchronisedStores`);
   card in `SecurityAndPrivacy.tsx` **gated on media capability
   (`nativeKeyPushAvailable()`), not just `useE2EE()` — Android renders it DISABLED
   with "not yet available on Android" copy (FE-6)**; enrollment-shared flow; per-device
   copy ("on this device"); fine print. Wires the two judgment-call-3 gates. · §0.2 #9.
10. **Gate — BOTH reviewers on the full diff.** Checklist below.

## Tests + verification (house-consistent)

- **node --test:** `mlsCallModePolicy.test.ts` — every transition T0a–T7, grace,
  precedence table + each fail-closed degradation, confirm-order, T6-sole-exit /
  no-warm-enable-after-interlude, announce-lost-converges, ME-16 turnover, publish-gate,
  fail-safe-resume guard, `starting`→`none`, ctl forward-compat drops.
  `mlsEnvelopeClassify.test.ts` + `MlsStaleCtl` arm. Existing 22 stay green.
- **cargo (server, REFERENCE):** per Step 1. `TEST_DB=MONGODB` in WSL if any new driver
  method appears (none expected — probe + cap reuse existing ones; messages reuses
  envelope insert).
- **cargo (native):** per Step 2.
- **tsc/eslint/prettier:** zero NEW vs `115cab07` baseline (9 pre-existing; state.tsx
  eslint stays 20; never whole-file-prettier state.tsx). stoat.js build clean. WSL
  `vite build` green.
- **ME-8 verification artifact:** source citation (or smoke result) for the
  unencrypted-receive-while-E2EE-enabled path, recorded in this doc before the gate.
- **Live proof:** not owed in 6.5 (flag FALSE; mode machine pure-tested) — **BINDING
  condition (both reviewers): the 6.6 harness MUST include live T3/T4/T5/T6, call_full
  auto-leave, and the mixed-call receive path with a real web participant, before any
  flag flip.**

## Scope boundary vs 6.6/6.7

6.5 = everything user-visible + the only plaintext-resume path + ctl transport. NOT 6.5:
hostile-DS harness (T-19/T-20/T-06-extended + the live downgrade legs above — 6.6);
`MAX_VIDEO_PARTICIPANTS` server enforcement (D12 — NAMED 6.6 gate item); D10/D11 drain
mechanics; Android (6.7 — confirm dialog, Capacitor key-push, announce uniffi export;
fail-closed non-capable until then, and the settings card renders disabled there).

## Flag recommendation (owed answer)

`media_e2ee_enabled` stays **FALSE at the end of 6.5**. The flip belongs with **6.6**:
§0.3's definition of done requires the hostile-DS harness + final audit before exposure;
the binding live-downgrade legs above are 6.6 items; and the deploy-time debts (rebuild
delta/bonfire, desktop bundle, operator smoke) are queued at that boundary. After 6.5
the indicator/consent surfaces exist, so 6.6 can run flag-ON in staging without
shipping it.

## Gate checklist (both reviewers)

- Invariant 1: T3/T5 native confirm is the only plaintext-resume; T4 never resumes;
  Decline holds the pause; the publish gate covers LATE publications; the never-enabled
  paths (T0c/T0d) pause; fail-safe resume only with no open group known.
- Confirm order: E2EE-off strictly before resume.
- D1 closed: dialog roster native-computed, raw ids rendered, empty-set still prompts.
- Announce: native-gated on `downgrade_confirmed`; re-announce bounded by the server
  rate limit; ctl never parks/advances/poisons; forward-compat drops; 4 KiB both sides.
- Chip: dual-gated green quantified over track-publishing participants; bounded amber
  (10 s escalation covers missing-status); `starting`→`none`; no-session-capable-shell
  latches; toggle-off self-attribution reachable; no flap on clean rotations; server
  never promotes.
- A3: `MlsCallFull` new-members-only AFTER the rejoin branch (rejoin-at-100 test);
  auto-leave deferred; 3 s classification grace delays paint+pause but publishing stays
  ENCRYPTED during it; terminal-loud Leave/Stay choice.
- §0.2 #9: toggle LOCAL per-device default-off; prepublish gated by a REQUIRED dep;
  Android card disabled; fine print; per-device copy.
- IPC allowlist growth (one re-signature + one confirm-inert command) reviewed at the
  §7.2 boundary; `e2ee_call_frame_keys` sole secret egress, untouched.
- FE-9c supersession-bail fix in; disconnect() resets new signals; auto-leave never
  reenters dispose synchronously.
- ME-8 receive-path verification recorded; `media_e2ee_enabled` FALSE; all tests green.

## Plan-audit log (2026-07-12)

**Round 1 — media-e2ee-reviewer: APPROVE-WITH-FIXES (16 findings); frontend-code-reviewer:
NEEDS_REVISION (15 findings). ALL folded; the spec above is the post-fold normative text.**

media-e2ee-reviewer (ME-):
1. HIGH toggle "synced" false + hostile-server flip lever → LOCAL per-device, never synced
   (judgment call 3). 2. MED false ground truth: server cap EXISTS
   (`MAX_MLS_GROUP_MEMBERS`, both drivers, commit CAS) → contract inputs corrected; reuse
   the constant. 3. MED join_intent cap would lock out rejoiners at cap → new-members-only,
   after the rejoin branch, rejoin-at-100 test. 4. MED T4 lossy (`max_past_epochs=0`) →
   interlude re-announce per epoch + converge-anyway test. 5. MED ctl route unratelimited
   → per-(sender,group) 5 s/burst-2. 6. MED mix-clear during interlude warm-enables old
   group → enable branch mode-gated; T6 sole exit. 7. MED chip `none` conflates
   capable-but-failed → every no-session arm latches; not_encrypted. 8. MED mixed-window
   receive is an unverified platform assumption → named open question + source
   verification, smoke fallback. 9. MED two silent §3.4 deviations → RATIFIED here:
   (a) native send_mode verdict dropped v1 (judgment call 8); (b) T2 warm resume
   (judgment call 6a). 10. MED call_full auto-leave honest-path-only → generalized
   terminal-loud Leave/Stay choice. 11. LOW judgment-call-2 wording false → corrected +
   raw-id rendering. 12. LOW announce oracle → native-gated on `downgrade_confirmed`
   (adopted hybrid: command kept for re-announce, inert without confirm). 13. LOW §5.6
   amendment → Step 1. 14. LOW fail-open callsEnabled default → REQUIRED dep. 15. LOW ctl
   forward-compat unspecified → judgment call 1 + tests. 16. LOW interlude turnover →
   documented + test (T6 note).

frontend-code-reviewer (FE-):
1. HIGH no initial mode + never-enabled plaintext windows → `negotiating` + publish gate
   asserted at construction + T0a–T0d + fail-safe rule. 2. HIGH chip gate (b)
   unsatisfiable for trackless listeners + unbounded amber → quantified over
   track-publishing participants + extended 10 s escalation. 3. HIGH two pause owners +
   late publications bypass → single reason-set gate + `LocalTrackPublished` hook +
   modal refcount. 4. MED cap-bounce mute lever + chip flash → 3 s mix-classification
   grace (paint AND pause; encrypted during grace). 5. MED Voice store not synced →
   folded with ME-1 (local per-device; `clean()`). 6. MED Android inert toggle → card
   gated on `nativeKeyPushAvailable()`, disabled + copy. 7. MED `none` exception
   unreachable → `callChannelHasOpenGroup` chip input (probe at connect). 8. MED no
   reactive participants source + glitch → `participantsVersion` + `batch()`. 9. MED
   disconnect resets / auto-leave reentrancy / pre-existing supersession-bail listener
   leak → Step 5 (incl. the pre-existing fix). 10. MED E2EEVerify reuse unproven →
   `context:"call"` prop, fallback copy, hide DM turn-off, verify call-pins surface.
   11. MED probe hygiene → shared cache + feature_disabled latch + raw-fetch transport +
   web badge. 12. MED banner invisible in immersive/fullscreen → render inside the
   container; PiP treatment specified. 13. LOW `starting` chip mapping → `none`.
   14. LOW fail-open callsEnabled → folded with ME-14. 15. LOW nits (T7 joiner-only;
   early-ctl accepted loss; user-level route gating stated; >30-after-video documented;
   two extra policy tests) → all folded.

**Round 2 (frontend-code-reviewer, on the revised doc): NEEDS_REVISION-narrow — 12 of
13 folds verified correct (incl. against the PINNED livekit-client 2.15.13 source);
8 residuals, ALL folded above:**
- R2-1 HIGH: publish gate bypassable via livekit-client's unconditional
  `resumeUpstream()` in `setMediaStreamTrack` (device switch/unmute/reconnect) and
  `setProcessor`'s direct `replaceTrack` that skips `_isUpstreamPaused` (making naive
  re-asserts no-op on the idempotency guard); in-repo day-one trigger = denoise/gain
  attach inside the negotiating window (state.tsx:469-484) and camera effects (:883).
  → Gate hardening paragraph: `UpstreamResumed`/`TrackProcessorUpdate` re-assert
  (resume-then-pause), effect attach deferred while gated, new acceptance line.
- R2-2 MED: global `noteEncryptionRecovered` defuses the missing-status escalation →
  per-participant bookkeeping (chip spec).
- R2-3 MED: `participantsVersion` must also bump on track publication events (chip
  inputs).
- R2-4 MED: capable-but-failed construction in an E2EE-known call must gate + offer
  Leave/Stay, not just latch a chip (chip spec).
- R2-5 LOW: assert `negotiating` before `room.connect` + sweep on empty→non-empty.
- R2-6 LOW: T0d requires a COMPLETED probe verdict; probe-error ⇒ resume ratified.
- R2-7 LOW: `pausePublishing`/`resumePublishing` gain a reason parameter.
- R2-8 LOW: share-modal direct pause/resume REPLACED by gate-owner calls.
Round-2 verdict on the folds themselves: architecture right, interleavings compose
cleanly, no new contradictions. With R2-1..8 folded, the next reviewer touchpoint is
the diff gate (Step 10).

**DIFF GATE (2026-07-12) — media-e2ee-reviewer: APPROVE-WITH-FIXES (4 LOW, no
CRIT/HIGH); frontend-code-reviewer: NEEDS_REVISION (1 CRIT, 5 MED, 2 LOW). ALL
findings fixed same day (fix record below); focused re-verify run on the fix delta.**

media-e2ee gate findings (all fixed):
- G-M1 LOW: downgrade grant not cleared on T6 re-upgrade (announce-oracle window
  wider than promised) → NEW confirm-inert `e2ee_call_clear_downgrade` command
  (native `mls_call_clear_downgrade_confirmed`, 4 sync points); the session clears
  the grant in the T6 viaSuccessor branch before migrating; new adversarial test
  `downgrade_grant_clears_explicitly_on_reupgrade` (19/19 green).
- G-M2 LOW: T0d fail-safe conflated pending/completed probe → tri-state
  (`"open"|"none"|"pending"`) `channelHasOpenGroup` dep; PENDING holds the gate and
  re-arms the fail-safe (bounded, `MAX_FAILSAFE_REARMS=2`); "none" is a COMPLETED
  verdict (error arm ratified, same origin).
- G-M3 LOW (informational): confirm returns Ok(()) and the announce is a separate
  confirm-gated command — RATIFIED as an intentional simplification of the plan's
  "returns announce ciphertext" wording (single responsibility; announce still
  native-gated; re-announce needs the command anyway).
- G-M4 LOW: ME-8 artifact → RECORDED: livekit-client 2.15.13 gates the DECRYPT
  cryptor per participant by the publication's server-signaled encryption type
  (`RoomEvent.TrackPublished → setParticipantCryptorEnabled(pub.trackInfo.encryption
  !== Encryption_Type.NONE, identity)`, esm.mjs:14122) — a plaintext publication
  from a non-enrolled/confirmed participant bypasses decryption entirely, so
  mixed-call receive works while the local Room has E2EE enabled. "Decline =
  receive-only" is real. The 6.6 live web-participant smoke remains binding.

frontend gate findings (all fixed):
- G-F1 CRIT: `setProcessor` publish-gate bypass NOT closed (only the
  `UpstreamResumed` half was; `setProcessor` replaces the sender track without
  touching `_isUpstreamPaused` and emits only `TrackProcessorUpdate`, so a bare
  re-pause no-ops on the idempotency guard while the denoised/gain mic streams
  plaintext) → per-track `TrackProcessorUpdate` handler added: while the gate is
  held, RESUME-then-PAUSE (the resume resets the stale flag; its nested
  `UpstreamResumed` triggers the bare-pause arm, which serializes behind livekit's
  per-track lock and early-returns — bounded, no loop; early-return semantics
  verified against the pinned source).
- G-F2 MED: remote `trackPublished` didn't bump `callParticipantsVersion` (chip
  stayed green for a trackless-then-publishing peer) → bump added.
- G-F3 MED: screenshare quality-modal direct `resumeUpstream` could resume into a
  held gate (brief plaintext screenshare on a mixed call) → the modal callback
  resumes only when `#publishGate` is empty (the gate owner resumes everything when
  the set empties).
- G-F4 MED: pre-join/in-call self-attribution ignored the toggle and was
  desktop-only → `wouldEncrypt` now includes `e2eeCallsEnabled`; the probe is a raw
  authenticated fetch (bridge-independent) in BOTH `useCallPrejoinMode` and
  `connect()` (runs for EVERY call incl. web), so toggle-off desktop shows
  `self-plain` and web gets the badge + in-call attribution.
- G-F5 MED: loud chip hidden in theater mode → an `ImmersiveChipOverlay` copy
  renders when immersive (banner already outside the chrome Show).
- G-F6 MED: no terminal-loud Leave/Stay surface (ME-10 partial) → new
  `callTerminalLoud()` (mode negotiating + chip not_encrypted); the banner gains a
  terminal arm ("This call could not be secured…", Stay unencrypted / Leave);
  `confirmPlaintext` accepts the negotiating+failed/resecuring terminal escape; the
  policy gains `local_confirm` from `negotiating` (E2EE-off first, NO explicit
  resume — the mode lockstep releases the `negotiating` gate AFTER effects; new
  policy test).
- G-F7 LOW: `disconnect()` now resets `callRosterPanelOpen` + the probe tri-state.
- G-F8 LOW: `#applyMode` now SERIALIZES transitions on a promise chain and AWAITS
  media effects in order, setting the mode (whose lockstep may resume) only after
  they complete — `set_e2ee(false)` precedes any resume in COMPLETION order.

Post-fix verification: 51/51 node tests (28 policy), tsc = 9 pre-existing baseline
(0 new), 19/19 native adversarial tests, delta/db REFERENCE suites green, WSL vite
build green.

**GATE FIX RE-VERIFY (frontend-code-reviewer, same day): the CRITICAL is CONFIRMED
CLOSED against the pinned livekit source (idempotency defeat + bounded nested-emit
trace + attach-coverage all verified); 6/8 fixes + both media LOWs verify clean.
Two NEW MEDs found INSIDE the fix delta — both fixed immediately (+2 policy tests,
52/52):**
- MED-A: the TrackProcessorUpdate re-assert's trailing pause was unconditional —
  the gate could empty mid-sequence (session settles plaintext during the resume)
  leaving a healthy call silently muted forever → gate re-checked before the
  trailing pause.
- MED-B: the "Stay unencrypted" terminal button was dead for the latched-loud-
  while-active population (`#enable` threw; `#latchLoud` doesn't fail the session)
  and even when reachable would leave `enable-window` held (paused forever after
  confirming) → `terminalEscape` also accepts `#loudLatched`; BOTH `local_confirm`
  policy arms now release `enable-window` (E2EE-off still strictly first;
  policy-tested).
Tracked non-blocking LOWs (6.6): share-modal pause is per-track, resume defers to
the gate (comment corrected — the "share-modal reason" wording was stale); the
pre-join fetcher reads the toggle untracked (badge refreshes on the next version
bump); the 6.4 direct `#setMode` callers bypass the `#modeChain` (lost-update
window is over-encryption/label-mismatch only, never plaintext).
The MED-A/MED-B fixes landed after the re-verify with test coverage; the 6.6 final
audit re-checks them alongside its live legs.

## Status

- [x] 0 PLAN audit — both reviewers round 1 (31 findings) + frontend round 2 on the
      revision (8 residuals incl. the livekit-client publish-gate bypass); ALL folded
- [x] 1 ctl transport + probe + cap (server + stoat.js) — DONE. 13/13 delta mls +
      11/11 db mls + 29/29 e2ee REFERENCE green; §5.6 amendment added.
- [x] 2 native announce + verdict (desktop) — DONE. 18/18 e2ee-core tests; cargo clean.
- [x] 3 bridge plumbing (frontend e2ee.ts) — DONE. `MlsStaleCtl` classify (+test).
- [x] 4 session mode machine + policy module — DONE. `mlsCallModePolicy.ts` 27 tests.
- [x] 5 signals + publish gate + lifecycle (state.tsx) — DONE. Reason-set gate +
      R2-1 hardening + FE-9a/9c fixes.
- [x] 6 call-card UX — DONE. Chip + banner + roster panel + tile locks + E2EEVerify
      `context:"call"` (banner/chip render outside immersive Show, FE-12).
- [x] 7 pre-join mode + cap pre-warning — DONE. `useCallPrejoinMode` + preview badge.
- [x] 8 video-cap product gate UX — DONE. `videoCapReached()`; server leg = D12 → 6.6.
- [x] 9 "Encrypt my calls" settings card — DONE. Voice store (LOCAL) + gated card.
      VERIFY: tsc = 9 pre-existing baseline (0 new); 50/50 node tests; WSL vite
      build green.
- [x] 10 gate — BOTH reviewers on the diff. media-e2ee-reviewer:
      APPROVE-WITH-FIXES (4 LOW, all fixed incl. a new confirm-inert
      `e2ee_call_clear_downgrade` command + the tri-state fail-safe).
      frontend-code-reviewer: NEEDS_REVISION (1 CRIT + 5 MED + 2 LOW, all
      fixed) → focused re-verify CONFIRMED the CRITICAL closed; its 2 new MEDs
      fixed with policy tests; 3 LOWs tracked to 6.6. Final: 52/52 node tests,
      19/19 native, tsc 9-baseline, vite green. See the gate record in the
      plan-audit log above.
