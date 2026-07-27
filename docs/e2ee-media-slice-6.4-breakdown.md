# Slice 6.4 — Epoch lifecycle + churn: implementation breakdown

Breakdown for sub-slice 6.4 of [e2ee-media-mls-plan.md](e2ee-media-mls-plan.md) (plan §8
row 6.4). Written 2026-07-11, **before coding**, so a follow-on session can resume from this
file and so the plan itself can be audited before implementation (house "audit-before-code"
pattern, as 6.1/6.2/6.3). Gate at the end: **media-e2ee-reviewer** (plan §8). This doc is
also submitted to media-e2ee-reviewer as a PLAN audit before the diff exists.

6.3 landed the plumbing only — the IPC surface, `MlsKeyProvider`, the always-E2EE-capable
Room, the `e2ee:call-keys-changed` loop, and the caller-policy guards — and deliberately did
**not** drive the control plane. 6.4 wires it and proves it live. `media_e2ee_enabled` stays
**FALSE** until 6.5 (downgrade UX).

## Contract inputs (fixed by 6.1/6.2/6.3, already committed — not pushed)

### Native engine (`e2ee-core/src/mls/mod.rs`, desktop `5cbb167`)

All on `&mut E2ee` except `mls_call_pending_commit_epoch` (`&self`). Returns re-exported from
the crate root; wire shapes under `acutest_e2ee_core::wire`.

| Native method | Signature (args → return) |
|---|---|
| `mls_call_create` | `(channel_id, user_id, supersedes: Option<&str>) → MlsCallCreated` |
| `mls_call_join_intent` | `(group_id, channel_id, user_id) → wire::MlsJoinIntentPayload` |
| `mls_call_admit` | `(&MlsJoinRequest, &MlsClaimedKeyPackage) → wire::SubmitMlsCommitPayload` |
| `mls_call_process` | `(&MlsEnvelope, user_id) → MlsProcessOutcome` |
| `mls_call_commit_won` | `(group_id, won_epoch) → MlsProcessOutcome` (cross-checks `won_epoch == current+1`) |
| `mls_call_commit_lost` | `(group_id) → ()` |
| `mls_call_pending_commit_epoch` | `(group_id) → Option<i64>` |
| `mls_call_leave_cleanup` | `(group_id) → ()` |
| `mls_call_heartbeat` | `(group_id) → wire::SubmitMlsCommitPayload` |
| `mls_call_remove` | `(group_id, target_user_id, target_device_id) → wire::SubmitMlsCommitPayload` |
| `mls_call_state` | `(group_id) → MlsCallState` |
| `mls_call_frame_keys` | `(group_id) → MlsFrameKeys` — **the §7.2 egress** |
| `mls_publish_key_packages` / `mls_replenish_check` / `mls_expire_key_packages` | KeyPackage directory |

**No `mls_call_send_mode` primitive exists** — the native downgrade *verdict* is 6.5. 6.4's
"non-enrolled participant" detection is therefore a **client-layer** computation over the SFU
participant set and the `mls_call_state` roster (plan §3.4 trusted enumeration = the union;
the client can only cause a *spurious* loud prompt, never suppress a real one).

Key return shapes (confirmed in source):
- `MlsProcessOutcome { group_id, kind: "welcome_joined"|"commit_applied"|"duplicate", epoch,
  removed_self: bool, removed: Vec<MlsMemberDevice> }`. **`removed` non-empty ⇒ Remove-driven
  epoch ⇒ switch own send-key IMMEDIATELY** (§1.5). `removed_self` ⇒ group is over for us.
  **CAVEAT (audit C1):** `removed` is populated only on the *inbound* `mls_call_process` path
  (from the StagedCommit, mod.rs:1051-1062). `mls_call_commit_won` returns `removed: vec![]`,
  `removed_self: false` **unconditionally** (mod.rs:741-747) — so for the member that ISSUED a
  Remove and won arbitration, the outcome looks Add-driven. The rotation classifier therefore
  MUST NOT trust `MlsProcessOutcome.removed` alone for own-won commits; it must remember what it
  staged (see C1 fix).
- `MlsCallState { group_id, channel_id, epoch, state: "active"|"poisoned", members[] }`.
- `MlsFrameKeys { group_id, epoch, keys[], previous[] }` — native ALREADY returns old+new for
  the rotation overlap; the client only times the local-last `applyKeys`.
- `MlsCallCreated { group_id, payload: CreateMlsGroupPayload{ group_id, channel_id, device_id,
  supersedes } }`.

### IPC (`src-tauri/src/e2ee.rs`, desktop `4f81a07`)

One `e2ee_call_*` / `e2ee_mls_*` command per native method (session `user_id` is a param).
`emit_keys_changed(app, group_id, epoch)` fires `e2ee:call-keys-changed {group_id, epoch}`
after every LOCAL epoch advance: `create` (epoch 0), `process` (welcome_joined/commit_applied,
never duplicate), `commit_won`. `e2ee_call_confirm_downgrade` is the **dialog gate only** in
6.3 (returns `Ok` on confirm / `Error::Declined` on cancel); the ctl-announce transition is 6.5.

### Frontend (`packages/client`, main `b43c755d`)

- `MlsKeyProvider` (`rtc/mlsCallKeys.ts`): `applyKeys(frameKeys, localIdentity)` installs
  previous-first, remotes, then the LOCAL entry LAST (`orderForInstall`), HKDF-material import.
  `appliedIdentities()`. **`localIdentity` MUST be `"{user_id}:{device_id}"`** or local-last
  never matches (carried item 3).
- `E2EEBridge` (`components/client/e2ee.ts`): native wrappers `callCreate`, `callJoinIntent`
  (**T-15 guard**: refuses unless `dsResponseChannelId === intendedChannelId`, signs the
  user-intended channel), `callAdmit`, `processEnvelope`→`classifyEnvelopeError`
  (ack/park/drop/error; poison-pill terminal already folded), `callProcess`, `callCommitWon`,
  `callCommitLost`, `callPendingCommitEpoch`, `reconcilePendingCommit`, `callLeaveCleanup`,
  `callHeartbeat`, `callRemove`, `callState`, `callFrameKeys`, `callConfirmDowngrade`,
  `mlsPublishKeyPackages`, `mlsReplenish`, `mlsExpireKeyPackages`, `onCallKeysChanged` (Tauri
  listen; **Android returns a no-op** — carried item 6), `callStates: ReactiveMap`.
- `state.tsx` (`rtc/state.tsx`): always-E2EE-capable Room (`#connectGen` supersession guard,
  worker try/catch degrade), keys-changed loop `onCallKeysChanged → callFrameKeys → applyKeys`,
  `callEncryption: ReactiveMap<identity, bool>` (from `participantEncryptionStatusChanged`),
  `callEncryptionError` signal (latches first STRUCTURED error), processor-ordering doc (§4.3).
  `connect(channel, auth?)` calls `channel.joinCall("worldwide")` (today **without**
  `device_id`) then `room.connect`.

### Server DS (`stoatchat/acutest`, `c1e313e7`)

Routes under `/mls`: `PUT /key_packages`, `POST /key_packages/claim`, `POST /groups`
(`Arbitrated` 200/409 — 409 body carries the open `group_id`), `POST /groups/<id>/join_intent`
(fans out `MlsJoinRequested`), `POST /groups/<id>/commits` (`Arbitrated` 200 Won / 409 Lost —
409 body carries the winning commit to rebase), `GET /groups/<id>/commits?from_epoch=` (gap
refetch, requires GROUP membership). Caps: `MAX_MLS_COMMIT_RAW_SIZE=64 KiB`,
`MAX_MLS_WELCOME_RAW_SIZE=256 KiB`, `MAX_KEY_PACKAGES=100`, `MAX_COMMITS_PER_FETCH=100`,
`MIN_JOIN_INTENT_INTERVAL_SECONDS=5`, `MAX_CLAIMS_PER_TARGET_PER_MINUTE=5`. Product caps:
**`MAX_E2EE_CALL_MEMBERS=100`**, **`MAX_VIDEO_PARTICIPANTS=30`**.

Bonfire (all on `{user_id}!` private topic, ULID-dedup like `E2EEMessage`):
- `MlsJoinRequested { group_id, channel_id, user_id, device_id, key_package_ref, signature }`
  — a **distinct** event (the admit trigger).
- `MlsCommit(E2EEMessage)` / `MlsWelcome(E2EEMessage)` — wrap an envelope
  `{ id, content_type, group_id, epoch, ciphertext, … }`; **queue-first**, so the drain and the
  live push race and must dedup by envelope ULID and order per group by consecutive epoch.

### Transport seam (the seam 6.4 rides, §4.2)

- Inbound events reach the bridge via `client.e2ee?.onEvent(event)` (`stoat.js/events/v1.ts`).
  **Today only `E2EEMessage`/device/claim are parsed — the `Mls*` events are NOT** (must add).
- Outbound HTTP: `E2EEBridge.#api(method, path, body)` — raw `fetch` to `baseURL+path` with the
  auth header, **throws on any non-2xx** (so a 409 currently throws — needs an arbitration-aware
  variant).
- Acks: `client.events.send({ type: "E2EEAck", ids: [...] })` after durable processing.

## What 6.3 deliberately did NOT do (the 6.4 gap — explicit)

No code calls any `/mls` route; the `Mls*` bonfire events are unparsed; there is no MLS mailbox
drain; nobody creates/joins/admits a group; no commit is submitted or arbitrated; membership
never maps to an epoch; `setE2EEEnabled(true)` is never called; `joinCall` sends no `device_id`
(so the LiveKit identity is bare `user_id` and `orderForInstall`'s local-last match is
currently a no-op — **carried item 3 is presently broken**). 6.4 closes all of the above.

## Approved judgment calls (2026-07-11)

1. **Downgrade boundary split (user-confirmed).** 6.4 lands the ratchet-**toward**-encrypted
   direction and reconciliation DETECTION: create/join/rejoin/desync/re-upgrade + the loud
   *state signal* (non-enrolled detected, ghost-leaf flagged, RE-SECURING/NOT-ENCRYPTED fed to
   `callStates`/`callEncryptionError`) + refuse-to-publish-encrypted-into-a-mixed-call. 6.5 owns
   the downgrade **UX**: blocking banner, pause-publish-until-confirm, the native OS confirm
   dialog wiring, the epoch-anchored MLS ctl-announce mode-transition state machine, and the
   dual-gated chip. The two meet at the state signal. Because `media_e2ee_enabled` stays FALSE,
   6.4's re-upgrade path is exercised via a forced/simulated non-enrolled detection in the
   harness, not a live downgraded call.
2. **`MlsCallSession` is a NEW module (`rtc/mlsCallSession.ts`); DS-HTTP methods go on
   `E2EEBridge`.** Extends the 6.3 deviation-with-rationale (§4.2 literal file citation is
   `e2ee.ts`): the orchestration loop (churn/rotation/reconciliation timers) lives near the Room
   in the RTC layer, keeping the 3230-line text/DM bridge and the RTC store thin; the DS-HTTP
   couriering rides `E2EEBridge.#api` (same transport seam as text). Surfaced at the gate.
3. **409 is arbitration, not error.** `create` and `commits` return `Arbitrated<T>`. A new
   `#apiArbitrated` returns `{ conflict: bool, body }` instead of throwing, so create-race and
   commit-Lost are normal control flow, never exceptions.
4. **This breakdown is audited by media-e2ee-reviewer BEFORE coding** (user-chosen), findings
   folded here, then implemented; the diff is gated again at the end.

## Architecture (three pieces)

1. **`E2EEBridge` DS-HTTP + bonfire (`components/client/e2ee.ts`, `stoat.js`).**
   `mlsCreateGroup`, `mlsJoinIntent`, `mlsClaimKeyPackage`, `mlsSubmitCommit`, `mlsFetchCommits`,
   `mlsPutKeyPackages` — thin couriers over `#api`/`#apiArbitrated`. Add `MlsJoinRequested` /
   `MlsCommit` / `MlsWelcome` to stoat.js `EventV1`, `E2EEServerEvent`, and the `v1.ts`
   dispatch; `onEvent` routes them to the **active `MlsCallSession`'s sink** (a registered
   callback; no session ⇒ envelope stays queued server-side, unacked — never ack what no call
   consumes).
2. **`MlsCallSession` (`rtc/mlsCallSession.ts`, NEW).** One per active call. Owns the control
   loop + all timers (admit stagger, heartbeat, leave grace, divergence timeout, re-upgrade
   hysteresis, Add-grace, joiner-retry), the per-group epoch cursor + park buffer, the
   arbitration/rebase logic, roster reconciliation, and the metrics counters. Emits state into
   `Voice.callStates` / `callEncryptionError` and calls `room.setE2EEEnabled(...)`. Pure decision
   helpers are exported for unit audit (house test split — no vitest in this repo).
3. **`state.tsx` wiring.** `connect()`: plumb `device_id` into `joinCall`, **assert the token
   identity** equals `"{user_id}:{device_id}"` (loud fail), construct the `MlsCallSession` when
   `e2eeCapable`, hand it the Room + the existing keys-changed loop (the loop's `applyKeys` call
   is now driven under the session's Add-grace/Remove-immediate timing). `disconnect()`: leave
   grace → `callRemove` best-effort → `callLeaveCleanup` → clear timers, superseded by
   `#connectGen`.

## Control-plane state machine (detail)

Per group, driven from `MlsCallSession.start(channel, room, {userId, deviceId})`:

- **Enrol.** `mlsReplenish(userId, serverRemaining)` / `mlsPublishKeyPackages` if the directory
  is low (idempotent; rides existing enrollment). Needed so admitters can claim our KeyPackage.
- **Create-or-join.** `POST /mls/groups {channel_id: channel.id}`. **200** ⇒ we are the epoch-0
  creator (`emit_keys_changed` epoch 0 already fired native-side). **409** ⇒ take the open
  `group_id` from the body, **`callLeaveCleanup` our orphan epoch-0 group first** (create already
  fired `emit_keys_changed(group_id,0)` + minted a local group, mod.rs:328-331 / e2ee.rs:1246 —
  L1), then run the **join path**:
  - `callJoinIntent({ groupId, intendedChannelId: channel.id /* ROUTE/UI truth */,
    dsResponseChannelId: <the group's channel_id AS ASSERTED BY THE DS>, userId })`.
    **T-15 honest framing (audit H2 — the guard as I first wired it was VACUOUS).** There is
    **no client-verifiable group↔channel binding in the protocol**: MLS `GroupContext` carries
    `group_id`, not `channel_id`, and native's Welcome gate only checks `group_id` equality
    (mod.rs:875-878). The create-409 body is `Conflict { open_group_id }` with **NO channel_id**
    (groups_create.rs:126) and there is **no `GET /mls/groups/<id>`** route (mls/mod.rs:175-184),
    so `dsResponseChannelId` had no independent source — the guard compared `channel.id` to
    `channel.id` and never fired. 6.4 therefore does BOTH:
    1. **Honest-DS leg (defense-in-depth):** add `channel_id` to `ResponseCreateMlsGroup::Conflict`
       (a 6.1-model change 6.4 budgets) so the guard compares route-truth `channel.id` against the
       DS-asserted binding and refuses a *misbinding* loudly. A hostile DS that simply lies here
       just makes us refuse to join (safe-loud) — it CANNOT be the real cross-group defense.
    2. **Hostile-DS leg (the load-bearing one, carried item 2):** **roster reconciliation is the
       true T-15 backstop.** The LiveKit room is keyed by the channel, so a hostile DS steering us
       into `G_evil` (a real group in another channel, all leaves legit) produces an MLS roster
       that diverges from THIS channel's SFU participant set. Reconciliation (step 5) must
       therefore **gate `setE2EEEnabled(true)` / publishing** on the MLS roster being consistent
       with the SFU set for `channel.id` — a cross-group redirect is caught loudly *before* the
       joiner trusts the group. Carried item 2 lands at BOTH sites, not the guard alone.
  - `POST /mls/groups/<id>/join_intent` → wait for `MlsWelcome`. **Joiner retry (§1.4):** 10 s
    timeout, re-broadcast intent, ≤3 retries, then **loud failure state (`RE-SECURING`→loud),
    never plaintext.**
- **Admit (existing member).** On `MlsJoinRequested` for our group: schedule at `leafIndex·2 s`
  (our leaf index from `mls_call_state.members` order). On fire, if the join is still
  outstanding (no winning Add yet): `POST /mls/key_packages/claim` → `callAdmit(request, claimed)`
  → submit (below). Higher leaves provide **liveness failover** if the low leaf is wedged;
  correctness never depends on the heuristic (DS arbitration is total).
- **Submit + arbitrate — ONE serialized per-group domain with the drain (audit H1).** Outbound
  submit and inbound drain are NOT independent flows: the winner's commit is fanned out
  queue-first-then-live-push (commits_submit.rs:330-341), so the live push of the *winning*
  epoch-E commit can reach a loser **before** its own 409 arrives. If the drain feeds that commit
  to `mls_call_process` while the loser's own commit for E is still staged, native's
  `process_message` errors and native maps **any** such error to `mls_err("commit-process")` →
  the group is **poisoned** (mod.rs:1034-1036 → 980-990) → a routine lost race forces a successor
  migration for the whole call, firing constantly at the R-1 stress rate. Fix: a **per-group
  mutex spanning the submit HTTP round-trip** — inbound envelopes for that group QUEUE until it
  releases; and whenever an inbound commit arrives at the epoch a local commit is staged for,
  call `callCommitLost` (clear pending) **before** `process`. Any staged commit (admit / heartbeat
  / remove) → `POST /mls/groups/<id>/commits` **under the lock, with a bounded submit timeout**
  (v1: 10 s) so a hung POST cannot wedge the drain: **200 (Won)** ⇒ `callCommitWon(wonEpoch)`
  (native re-checks `won == staged+1`); **409 (Lost)** ⇒ `callCommitLost` then **rebase**.
  **Rebase and its gap-refetch run INLINE within the current lock hold (a direct `processEnvelope`
  loop) — NEVER re-dispatched through the mutex-guarded queue (audit NEW-2), else the rebase awaits
  a queue that awaits the mutex the rebase still holds → self-deadlock (non-reentrant async mutex).
  Bound the ENTIRE locked critical section (not just the initial POST); on timeout release + loud
  desync, never an indefinite wedge.**
  The 409-Lost body is `MlsCommitInfo`, not an `MlsEnvelope` — **synthesize** an envelope
  (`content_type: "mls_commit"`, `group_id`, `epoch`, `ciphertext = commit`, synthetic `id`;
  native dedups by epoch not id, mod.rs:938-961 — L2) and feed through `processEnvelope`. Reconnect
  uses `reconcilePendingCommit`; its `dsWonEpoch` is derived from `GET …/commits?from_epoch=` by
  checking whether the committer at `pending` is self (no direct "my current epoch" query — L3),
  never a guessed win. **The drain-test MUST verify OpenMLS 0.8's actual process-while-pending
  behavior** (if 0.8 does NOT error on that path the poison risk downgrades, but the plan
  serializes regardless — you never process an inbound commit holding a conflicting pending one).
- **Mailbox drain.** `MlsCommit`/`MlsWelcome` envelopes → a per-group serialized queue ordered
  by consecutive epoch, ULID-deduped, **sharing the per-group mutex with submit (H1)**. Each →
  `processEnvelope(envelope, userId)`:
  - `processed` ⇒ **E2EEAck** the envelope id (durable per §3.3); if
    `outcome.removed.length` ⇒ mark Remove-driven (immediate send-key switch this rotation).
    **If `outcome.removed_self`** ⇒ run leave teardown (`callLeaveCleanup`) and **suppress the
    keys-changed handling for this group** — `emit_keys_changed` still fires on a `commit_applied`
    that removed us (e2ee.rs:1305), and calling `callFrameKeys` on a group we just left throws a
    transient loud error (L5).
  - `park {expected, got}` ⇒ **do NOT ack**; `GET /mls/groups/<id>/commits?from_epoch=<expected>`,
    feed the gap back through the drain. Invariant 10 (never skip-ahead). **BOUNDED (audit M4):**
    park/gap-refetch is capped (v1: N attempts) then **escalates to desync → rejoin-fresh (loud)**
    — a DS that withholds epoch E+1 produces no lag signal, so the total-withhold case is *also*
    caught by roster reconciliation (an SFU participant with no advancing MLS roster → loud).
  - `drop {successorNeeded}` ⇒ **ack + drop**; if `successorNeeded` enter the poisoned→successor
    flow; loud vs quiet per the classification.
  - `error` ⇒ **do NOT ack**, surface loud — **BOUNDED retry (carried item 4):** a per-envelope
    retry counter (v1: 5) then ack+drop-as-poison so an unrecognised terminal error can't spin
    the drain forever (the `classifyEnvelopeError` no-ack default must not be unbounded).
- **Rotation seam (§1.5) — the session drives `applyKeys`, NOT the blind auto-loop (audit
  C1 + M1).** The classifier for Add-grace-vs-Remove-immediate must know whether the epoch was
  Remove-driven, and **that fact is not in the keys-changed event nor reliably in the outcome**:
  `mls_call_commit_won` returns `removed: []` for an own-won Remove (mod.rs:741-747), and the
  6.3 auto-loop (state.tsx:499-515) calls `applyKeys` on the bare `{group_id, epoch}` push with
  no access to the drain's `MlsProcessOutcome`. Two coupled changes:
  1. **Per-staged-commit kind memory.** When the session stages a commit it records its kind:
     `remove` (from the non-empty `SubmitMlsCommitPayload.removed` returned by `mls_call_remove`),
     `admit`, or `heartbeat`. On an **own-won** epoch the session classifies from THIS memory
     (a won `remove` ⇒ Remove-immediate), never from the empty `commit_won.removed`. On an
     **inbound** epoch it classifies from `MlsProcessOutcome.removed` (trustworthy there).
  2. **Provider hook for the grace, EPOCH-FENCED (audit NEW-1 — the timer, not just the
     classifier, must be safe).** `MlsKeyProvider.applyKeys` currently installs previous → remotes
     → local **synchronously** (mlsCallKeys.ts:79-102) with no way to hold the local entry. Add an
     install-mode: **Remove-driven / first-key ⇒ install all incl. local now; Add-driven ⇒ install
     previous+remotes now, schedule the local-last `onSetEncryptionKey` after Add-grace ≤ 2 s** (or
     on commit-delivery ack). **The scheduled local-last install is tagged with its epoch and fires
     only if the group is STILL at that epoch; ANY newer epoch application — and every
     Remove-immediate — CANCELS outstanding Add-grace timers for the group.** Without this fence,
     an Add at E schedules the local key for +2 s; a Remove at E+1 within that window applies
     Remove-immediate; then E's stale timer fires and regresses the send index back to E — the
     remover publishes on E's key (which the just-removed member holds) for up to 2 s, silently
     re-opening the invariant-7 hole C1 closed (invisible to R-1: receivers hold E as `previous[]`,
     no gap flags it). Test: Add-then-Remove-within-grace must NOT regress the send key.
  3. **Single-source the driver (audit NEW-3).** The session is the **SOLE** `applyKeys` driver for
     epoch changes: the `e2ee:call-keys-changed` event routes **into** the session, which correlates
     it with the recorded staged-commit kind and times the install. The state.tsx auto-loop's
     "install immediately" mode is reserved for **reconnect re-assert ONLY**, never per-epoch — if
     both fired for the same epoch the auto-loop's immediate local install would cancel the
     Add-grace and make R-1's Add-driven p95 < 250 ms unmeetable (safe for secrecy, but defeats the
     feature). The `removed` classification is recorded before any local send-key is delayed
     (closes the event-vs-outcome order hazard, M1). **Fail-safe: unknown kind ⇒ Remove-immediate**
     (a spurious immediate switch costs one receiver gap; a wrong grace breaks invariant 7).
  Receivers always hold old+new (native `previous[]` + 16-slot keyring).
- **Loud-state debounce (§4.4).** A missing-key `encryptionError` inside a KNOWN rotation window
  (an epoch change the session is mid-processing, or within the Add-grace) ⇒ `RE-SECURING` with a
  10 s timer escalating to loud; the same error outside a known window ⇒ immediately loud. Clean
  rotations must never flap the chip (extended T-06). Latches the first STRUCTURED error
  (already wired in 6.3 `callEncryptionError`).
- **Lag / wraparound (§1.5).** Track receive-epoch lag; **warn at 8**, **desync at
  `LAG_DESYNC_THRESHOLD = 12`** (pinned to the native constant, keys.rs:44 — 12 < 16 keeps the
  keyIndex wrap safe; GCM already prevents wrong-key *silent* decrypt at wrap, so the worst case
  is dropped frames, I1) ⇒ discard local state, rejoin fresh.
- **Poisoned epoch (§1.4).** `drop` with `successorNeeded` (or a rejoin discovering admission
  can't proceed) ⇒ `POST /mls/groups {supersedes: old_group_id}` (channel-scoped atomic
  close+create), migrate via the join path; UI stays `RE-SECURING` throughout, never plaintext.
- **Heartbeat (§1.4).** Lowest-online-leaf (staggered failover like admission) stages an empty
  self-update `callHeartbeat` every **10 min** on a stable roster; submitted + arbitrated like
  any commit. Bounds stable-roster exposure + exercises the desync machinery.
- **Leave + roster reconciliation (§1.4/§3.4, carried item 5).** On `participantDisconnected`,
  start a **10 s leave-grace** timer (a reconnect within it cancels the pending Remove —
  transient blips must not churn remove+rejoin). Still gone ⇒ `callRemove`. Continuously
  reconcile `room` participants vs `mls_call_state.members` both directions:
  - **SFU participant absent from the MLS roster** ⇒ **non-enrolled → loud** state (this is the
    trusted downgrade-trigger enumeration; the client can only over-warn, never suppress).
  - **MLS leaf with no SFU participant (and no tracks)** ⇒ render from the MLS roster (crypto
    truth), flag divergence, and after a **30 s divergence timeout** any member `callRemove`s the
    ghost leaf.
- **Enable + plaintext-until-first-key window (carried item 4, §3.4/§1.5).** Enable only once
  (a) the group is established, (b) **roster reconciliation says the MLS roster is consistent with
  this channel's SFU set** — a HARD SYNCHRONOUS precondition evaluated AT enable-time from
  `mls_call_state` vs `room.remoteParticipants` (not merely on a periodic tick), the hostile-DS
  T-15 backstop, H2; even if it slipped through, a redirected joiner cannot decrypt the real room's
  media (frame keys are per-group-exporter, so G_evil's keys never match this channel's group's
  frames — the playback backstop) — (c) the first *local* send-key is
  installed, and (d) LiveKit reports encrypted. Then `room.setE2EEEnabled(true)`. **Between
  `setE2EEEnabled(true)` and the first local `setKey` there is a plaintext window** — guard it:
  **pause local publishing** (fail-closed) until the first local send-key is installed (§1.5
  sender-grace + invariant-11 dual-gating), so no plaintext frame is published under an
  "encrypted" flag. Unpause only after the local-last `applyKeys`. **Feature-off is NOT a
  failure (L4):** with `media_e2ee_enabled=false` every `/mls` route returns `FeatureDisabled`
  (mls/mod.rs:75-84); the session must classify that as **"not an E2EE call" (quiet plaintext,
  no chip)** — never latch a loud `NOT ENCRYPTED` / `callEncryptionError`. Distinguish
  `FeatureDisabled` from a genuine E2EE failure in `#apiArbitrated`.
- **Re-upgrade + hysteresis (§3.4).** When the last non-enrolled participant leaves, wait a
  **15 s hysteresis** (a bouncing non-enrolled participant must not alternate downgrade/re-key
  storms), then re-establish E2EE via a fresh successor group + `setE2EEEnabled(true)` on the
  existing Room (NOT a reconnect). Sticky direction: re-upgrade needs no confirm.
- **Caps (A3).** At `MAX_E2EE_CALL_MEMBERS=100` the call stays E2EE and an overflow joiner is
  refused media-key admission with a loud "call full for E2EE" state (the cap-refusal UX polish
  is 6.5; 6.4 lands the refusal). Respect `MAX_VIDEO_PARTICIPANTS=30`.
- **End of call.** `disconnect()` best-effort `callRemove` self (within grace), `callLeaveCleanup`,
  clear timers, terminate worker (6.3 already does the worker/listener teardown). **The leave-time
  `callRemove` is best-effort and MUST NOT block `callLeaveCleanup`/timer-clear on the per-group
  mutex (audit NEW-6)** — with the H1 mutex held across a ≤10 s submit round-trip, a blocking
  teardown could stall disconnect for up to 10 s; try-lock or skip.

## Steps (numbered — repo · carried item · plan §)

1. **Token identity + create-409 channel_id (frontend + stoat.js + 1 server model field).** Thread
   the E2EE `device_id` (from `E2EEBridge.status.state.device_id`) into `Channel.joinCall` →
   `join_call` route body → token mint, so the LiveKit identity is `"{user_id}:{device_id}"` (the
   server already accepts + validates the body `device_id` and mints the qualified identity —
   voice_join.rs:38/49-53, voice_client.rs:86-93; only the client plumb + assert remain). In
   `connect()`, after `room.connect`, **assert** `room.localParticipant.identity ===
   "${userId}:${deviceId}"`; mismatch ⇒ loud fail, never enable E2EE (else local-last silently
   breaks). **Also (H2 defense-in-depth):** add `channel_id` to `ResponseCreateMlsGroup::Conflict`
   (`crates/core/models/src/v0/e2ee.rs` + groups_create.rs:124-127) so the T-15 guard has a real
   DS assertion to compare route-truth against. **Size honestly (audit NEW-5):** this is NOT one
   field — it ripples to `MlsGroupCreateOutcome::Conflict` (carries only `open_group_id` today) and
   **both** driver impls of `create_mls_group` (each must return the open group's `channel_id` on
   the conflict branch) + both-driver tests (workspace BOTH-drivers rule); the `Arbitrated`
   responder + okapi schema auto-derive. · **items 2/3** · §1.5.
2. **DS-HTTP + bonfire (frontend + stoat.js).** `E2EEBridge` DS methods over `#api` /
   `#apiArbitrated`; add `Mls*` events to stoat.js `EventV1`/`E2EEServerEvent`/`v1.ts` and route
   them to the active session sink via `onEvent`. · §2.3/§1.2.
3. **`MlsCallSession` core (frontend).** Create-or-join (409-arbitrated), admit scheduler (leaf
   stagger + failover), submit/arbitrate Won/Lost + rebase, per-group serialized mailbox drain +
   **bounded retry** + gap-refetch + park buffer, joiner-retry timeout. · **item 4** · §1.4/§3.3.
4. **Rotation transition window (frontend).** Session is the SOLE `applyKeys` driver (NEW-3); own-won
   epochs classified from the staged-commit-kind memory, inbound from `MlsProcessOutcome.removed`,
   fail-safe Remove-immediate on unknown (C1); **epoch-fenced Add-grace timer cancelled by any newer
   epoch / Remove-immediate (NEW-1)**; old+new overlap install order, lag warn/desync at
   `LAG_DESYNC_THRESHOLD=12`, **§4.4 loud-state debounce** so clean rotations never flap. · §1.5/§4.4.
5. **Roster reconciliation (frontend).** SFU∪MLS union both directions; non-enrolled detection →
   loud state; ghost-leaf 30 s divergence-timeout Remove; leave-grace 10 s. The loud backstop the
   6.2/6.3 phantom-defense LOWs lean on. · **item 5** · §1.4/§3.4.
6. **Enable + lifecycle timers (frontend).** `setE2EEEnabled(true)` driving + plaintext-until-
   first-key guard (pause-publish); heartbeat 10 min; re-upgrade + 15 s hysteresis; cap refusal.
   · **item 4** · §3.4.
7. **Android / no-key-push shell → fail-CLOSED, not just "don't enable" (frontend, audit H3).**
   Not-enabling is INSUFFICIENT: a Room built with the `e2ee` option but never
   `setE2EEEnabled(true)` still publishes **cleartext transport** (state.tsx:347-351) — so an
   Android shell that is `e2eeCapable` but blocks the enable-gate forever would publish plaintext
   to the SFU *believing it is encrypted* (invariant 1). And the gate has no signal to read:
   `onCallKeysChanged` returns `() => {}` on BOTH the real-Tauri and Android-no-op paths
   (e2ee.ts:3220-3229), so "subscription live" is undecidable. Fix: the probe must be **SYNCHRONOUS
   at Room-construction time (audit NEW-4)** — `e2eeCapable` + the `e2ee:` option are decided
   synchronously at state.tsx:333-351, but `onCallKeysChanged` is async/awaited later (state.tsx:499),
   so relying on its return leaves the Room already built E2EE-capable and (since Android never calls
   `setE2EEEnabled(true)`) the pause-publish window never opens → plaintext publish. Add a
   **synchronous predicate** `bridge.nativeKeyPushAvailable()` (= `!!window.__TAURI__?.event`) and
   fold it into `e2eeCapable` at :333 so a no-key-push shell is constructed **WITHOUT** the `e2ee`
   option (loud non-enrolled path, same as an unsupported web shell) — never an E2EE-capable Room
   stuck publishing plaintext. Do NOT gate this on the async `onCallKeysChanged` return. · **item 6**.
8. **Metrics R-1/R-2 (frontend).** Instrument per-rotation receive-gap (R-1: time from
   `keys-changed` to first successful decrypt at the new index, and the sender-side Add-grace
   effectiveness) and mailbox pressure (R-2: per-device queue depth + bytes vs the 512/32 MiB
   budgets). Emit a session summary; assert against the thresholds below. · §7.3.
9. **LIVE two-desktop proof (operator/desktop) — BLOCKING.** Two bundled `tauri.localhost`+CSP
   desktop instances (the 6.0 `SLOGA_PROFILE` two-instance method): real audio+video decrypts
   both ways under native-derived keys; **wrong-key negative control** (tamper one instance's
   installed key) proves frames are ciphertext, not plaintext-with-a-flag. Join/leave/rejoin/
   rotation observed live. · **item 1**.

## Metrics + acceptance thresholds (proposed; reviewer-confirmable)

- **R-1 per-rotation receive-gap (numeric, and NOT a substitute for the C1 correctness test —
  M3).** Measure two distributions, not vibes: **(i) commit-propagation** `submit→peer keys-changed`
  and **(ii) receive-gap** `keys-changed→first successful decrypt at the new index`. Pass criteria:
  commit-propagation **p95 < 2 s** (if it routinely exceeds the Add-grace, the grace can't hide the
  gap — tune the grace or fail); Add-driven receive-gap p50 ≈ 0 and **p95 < 250 ms**; Remove-driven
  receive-gap **p95 < 1 s** (accepted + documented dropout). **FAIL** if, at a realistic churn rate,
  sustained audio dropout **> 1 s/rotation** or cascading desync. Churn = 1 join/leave per **10 s**
  in a 10-party call; stress = 1 per **2 s**. **Note:** the C1 mis-classification would *shrink* the
  measured Remove gap (the remover wrongly holds the old key longer), so **R-1 can show green while
  invariant 7 is broken** — keep a SEPARATE correctness assertion (T-03-at-the-remover, below) that
  R-1 does not stand in for.
- **R-2 mailbox pressure (measure the skip rate + recovery, not "zero drops" — M2).** The server
  **silently skips** any recipient over `MAX_QUEUE_DEPTH=512` / `MAX_QUEUE_BYTES=32 MiB` with a
  `log::debug!` + `continue` (commits_submit.rs:316-325) — availability-only, recovered by
  gap-refetch. So under cap-adjacent rosters with a **backgrounded / doze member** (the exact
  §1.4 scenario) drops WILL happen. Measure: peak per-device queue depth + bytes vs the budgets,
  the **skip rate**, and that **gap-refetch recovers every skip** (no permanent desync). Include the
  backgrounded-member-queue-fill case explicitly. Either raise the server skip log above `debug`
  or drop the "log loudly" claim — do not assert a guarantee the committed server does not make.

## Carried must-cover items → landing site

| # | 6.3-gate carried item | Where it lands in 6.4 |
|---|---|---|
| 1 | LIVE two-desktop MLS-keyed media proof + wrong-key negative control (BLOCKING) | Step 9 (operator/desktop, bundled origin+CSP) |
| 2 | T-15 client-leg non-vacuous (audit H2: no client-verifiable group↔channel binding exists) | **Two sites**: honest-DS leg = `channel_id` added to create-409 body + guard (Steps 1/3); hostile-DS leg = **roster reconciliation gates enablement** (Step 5) — the load-bearing one |
| 3 | Assert LiveKit token identity is exactly `{user_id}:{device_id}` | Step 1 (plumb + runtime assert) |
| 4 | Bound mailbox-drain retries; cover the `setE2EEEnabled(true)`→first-local-`setKey` plaintext window | Steps 3 (bounded retry + park bound) + 6 (pause-publish guard) |
| 5 | Roster reconciliation (SFU∪MLS union) — the loud backstop | Step 5 |
| 6 | Fail-CLOSED on any shell with no native key-push channel (Android pre-6.7) — never an E2EE Room publishing plaintext | Step 7 (real capability probe + `e2eeCapable=false`) |

## Tests + verification (house-consistent)

The client has no unit-test runner (Playwright e2e only); prior slices validated the client via
typecheck + browser/manual E2E and put unit tests on the Rust side. 6.4 keeps that split:

- **Pure exported decision helpers** (session-independent, auditable in isolation): create-vs-join
  routing from a 200/409 response; the T-15 provenance guard; arbitration Won/Lost→won/lost/rebase;
  drain disposition→action incl. the **bounded-retry** cutoff **and the park/gap-refetch bound**;
  **Add-grace vs Remove-immediate selection from the SESSION's staged-commit kind for own-won
  epochs and `MlsProcessOutcome.removed` for inbound epochs, with the fail-safe = Remove-immediate
  on unknown (C1)**; roster-reconciliation diff (SFU∪MLS → non-enrolled / ghost sets); re-upgrade
  hysteresis gating; leaf-stagger schedule.
- **T-03-at-the-REMOVER (new, audit C1/M3) — a correctness assertion R-1 cannot substitute for:**
  the member that issues + wins a Remove switches its own send-key on the SAME rotation as the
  Remove (no Add-grace), so no frame it publishes after the won Remove is decryptable by the
  removed member. Assert at the remover, not only at bystanders.
- **H1 serialization test:** an inbound winning commit that arrives (live-push) while an own commit
  is staged for the same epoch does not poison the group — verify the per-group lock + clear-pending
  ordering, and **record OpenMLS 0.8's actual process-while-pending behavior**.
- **Native legs already green in 6.2** (won-epoch cross-check, poisoned→successor, unsolicited-
  Welcome refusal, epoch-gap park, secrets-never-in-wire scrub).
- **Live plane = the blocking two-desktop proof (Step 9)** — the runtime evidence T-10/media-plane
  was deferred to here.
- `tsc -p packages/client/tsconfig.json` introduces **zero** new errors vs the `b43c755d`
  baseline (stash/compare, the 6.3 method); `cargo check` clean if the token-identity change
  touches the desktop/`join_call` server. `vite build` (the real gate) green.

## Scope boundary vs 6.5 (user-confirmed)

6.4 = ratchet-toward-encrypted + reconciliation DETECTION + the loud state signal + re-upgrade/
hysteresis. **On mix-detection, 6.4 PAUSES local publishing (fail-closed) — it never opens a
plaintext path (I2).** 6.5 = downgrade UX (banner, the confirm-to-resume-as-plaintext flow, native
confirm dialog wiring, ctl-announce transition state machine, dual-gated chip, cap-refusal polish,
safety-number roster entry). So: 6.4 pauses on a non-enrolled participant; 6.5 adds the only path
that resumes as plaintext (explicit per-device confirm). `media_e2ee_enabled` stays **FALSE**
through 6.4.

## Gate

**media-e2ee-reviewer** on the full diff (plan §8). Checklist: the 6 carried items covered; live
two-desktop proof + wrong-key negative control done; token identity asserted; T-15 provenance
independent; bounded drain retries; plaintext-until-first-key window closed; roster reconciliation
both directions; Add-grace/Remove-immediate correct off `removed`; loud-state debounce; R-1/R-2 vs
thresholds; caps respected; Android enablement gated; `frame_keys` still the sole secret egress
(untouched); `media_e2ee_enabled` still FALSE.

## Plan-audit fold (media-e2ee-reviewer, 2026-07-11)

Verdict **NEEDS_REVISION** (1 CRITICAL, 3 HIGH, 4 MEDIUM, 5 LOW/INFO); all folded into the body
above, each verified against source before folding.

- **[CRITICAL C1] Own-won Remove mis-classified as Add-driven → remover keeps encrypting on the
  removed-member-readable epoch for 2 s (invariant-7 hole 6.4's own Add-grace introduces).**
  `mls_call_commit_won` returns `removed: []` (mod.rs:741-747). FOLDED: session classifies own-won
  epochs from its **staged-commit kind** memory, not the outcome; provider gains an install-mode
  so only Add-driven epochs delay the local-last key; **fail-safe = Remove-immediate on unknown**;
  new **T-03-at-the-remover** correctness test (Rotation seam bullet, C1 caveat in Contract inputs,
  Tests).
- **[HIGH H1] Submit/live-push race poisons the group on a benign lost arbitration → successor
  migration every contested epoch.** FOLDED: outbound-submit + inbound-drain share **one per-group
  mutex** spanning the submit round-trip; clear-pending before rebase; bounded submit timeout;
  drain-test records OpenMLS 0.8 process-while-pending behavior (Submit + arbitrate bullet).
- **[HIGH H2] T-15 client-leg vacuous — no client-verifiable group↔channel binding; create-409
  carries no channel_id and there's no group-fetch route.** FOLDED: honest-DS leg adds `channel_id`
  to the create-409 body (Step 1); **hostile-DS leg = roster reconciliation gates
  `setE2EEEnabled`/publish** as the real backstop (Create-or-join bullet, Enable bullet,
  carried-items table).
- **[HIGH H3] Android/no-key-push shell: an E2EE-capable-but-not-enabled Room publishes plaintext,
  and the no-op subscription is indistinguishable from a live one.** FOLDED: **fail-closed** — real
  capability probe (`onCallKeysChanged` returns null/throws when unavailable) + treat such shells as
  NOT E2EE-capable (loud downgrade path), never a plaintext-publishing E2EE Room (Step 7).
- **[MEDIUM M1] No provider hook for the Add-grace; classifier had no access to `removed`.** FOLDED
  into C1 (provider install-mode; session drives `applyKeys` from the drain; event-vs-outcome order
  fixed).
- **[MEDIUM M2] R-2 "no drops" contradicts the server's silent over-budget skip.** FOLDED: measure
  skip-rate + gap-refetch recovery + the backgrounded-member case; drop the false guarantee.
- **[MEDIUM M3] R-1 soft + structurally blind to C1.** FOLDED: numeric commit-propagation p95 vs
  the 2 s grace + separate T-03-at-remover assertion.
- **[MEDIUM M4] Park/gap-refetch + submit unbounded.** FOLDED: park bound → desync/rejoin escalation;
  submit timeout; total-withhold caught by roster reconciliation.
- **[LOW/INFO L1-L5, I1-I2]** create-race loser `callLeaveCleanup` (L1); rebase synthesizes an
  `MlsEnvelope` from `MlsCommitInfo` (L2); reconnect `dsWonEpoch` derived from gap-fetch (L3);
  `FeatureDisabled` = quiet plaintext, not loud (L4); `removed_self` teardown suppresses the
  keys-changed handler (L5); desync pinned to `LAG_DESYNC_THRESHOLD=12` (I1); mix-detection PAUSES,
  never opens plaintext (I2). All folded at their bullets.

**Confirmed clean by the audit (no change):** token-identity landing; `frame_keys` sole secret
egress untouched; per-sender/per-epoch derivation KAT; credential-binding / phantom / unsolicited-
Welcome refusal (6.2 primitives reused); `reconcilePendingCommit` no guessed-win; roster-recon
safe-loud direction; leave-grace(10 s) < divergence(30 s); `media_e2ee_enabled` FALSE + gate
checklist.

### Re-audit fold (media-e2ee-reviewer round 2, 2026-07-11)

Re-audit of the revised plan: **NEEDS_REVISION (close)** — **C1, H1, H2 CLOSED**; H3
PARTIALLY-CLOSED → NEW-4. The reviewer stress-tested the fixes' *mechanisms* and found two HIGH
residuals the folds themselves created/left, plus a deadlock and a feature-defeat. All folded:

- **[NEW-1 HIGH — C1 mechanism regression]** A stale Add-grace timer firing after a newer Remove
  epoch regresses the send key to the stale epoch → re-opens the 2 s post-removal window C1 closed,
  invisible to R-1. FOLDED: **epoch-fence the scheduled local-last install** (fire only if still at
  that epoch) + **any newer epoch / Remove-immediate CANCELS outstanding Add-grace timers**; churn
  test Add-then-Remove-within-grace must not regress (Rotation seam bullet, Step 4).
- **[NEW-4 HIGH — H3 residual]** The capability probe (`onCallKeysChanged` async return) resolves
  AFTER Room construction → Android E2EE-capable Room publishes plaintext (pause-window never opens).
  FOLDED: **synchronous `bridge.nativeKeyPushAvailable()` = `!!window.__TAURI__?.event` folded into
  `e2eeCapable` at state.tsx:333**; no-key-push shells constructed without the `e2ee` option (Step 7).
- **[NEW-2 MED/HIGH]** Self-deadlock between the H1 per-group mutex and the M4 gap-refetch-through-
  drain. FOLDED: rebase + gap-refetch run **inline within the current lock hold** (direct
  `processEnvelope` loop), never re-dispatched through the mutex-guarded queue; bound the ENTIRE
  locked section (Submit + arbitrate bullet).
- **[NEW-3 MED]** The auto-loop's "always install immediately" cancels the Add-grace + fails R-1.
  FOLDED: **session is the SOLE `applyKeys` driver for epoch changes**; the keys-changed event routes
  INTO the session; immediate-install reserved for reconnect re-assert only (Rotation seam point 3).
- **[NEW-5 LOW]** The create-409 `channel_id` add is not "1 field" — ripples to
  `MlsGroupCreateOutcome::Conflict` + both drivers + tests. FOLDED (Step 1 sizing).
- **[NEW-6 LOW]** `disconnect()`'s `callRemove` must not block teardown on the per-group mutex.
  FOLDED (End-of-call bullet).

Reviewer clarifications folded: H2 reconciliation is a **hard synchronous precondition at
enable-time** (not only a periodic tick) + per-group-key mismatch is the playback backstop (Enable
bullet); H1 no-deadlock-on-submit-await confirmed; the v1 commit kinds are disjoint (admit/heartbeat
hard-set `removed: []`, mod.rs:558-563/668-675) so "a heartbeat that also removes" is unreachable.
Reviewer bottom line: with NEW-1/NEW-4 folded and NEW-2/NEW-3 tightened, **ready to code** — the
diff gate is the next reviewer touchpoint.

## Status

- [x] 0 PLAN audit by media-e2ee-reviewer (this doc), 2 rounds — round 1 NEEDS_REVISION (C1/H1/H2/H3),
      round 2 NEEDS_REVISION-close (C1/H1/H2 CLOSED, NEW-1..6); ALL folded; reviewer verdict "ready to code"
- [x] 1 token identity plumb + assert + create-409 `channel_id` — DONE 2026-07-11. Server:
      `MlsGroupCreateOutcome::Conflict` + `ResponseCreateMlsGroup::Conflict` carry `channel_id`
      sourced from the group record (both drivers + route + 4 tests); `cargo check -p revolt-delta`
      and `-p revolt-database --features mongodb` clean. Frontend: `Channel.joinCall(node, force,
      recipients, deviceId?)` sends `device_id` (verified the stoat-api generic body mapper carries
      it for the known route); `state.tsx` sources the E2EE device id, passes it, and asserts the
      minted `{user_id}:{device_id}` identity (loud `callEncryptionError` latch on mismatch — the
      6.4-step-6 enable gate refuses to encrypt while it's set). `tsc` clean (client + stoat.js,
      zero new errors). NOT committed (commit at slice end, post-gate).
- [x] 2 DS-HTTP + `Mls*` bonfire events — DONE 2026-07-11. **stoat.js** (`sloga`):
      `E2EEEnvelope` gains optional `content_type`/`group_id`/`epoch`; `E2EEServerEvent`
      gains `MlsJoinRequested` + `MlsCommit`/`MlsWelcome` (`& E2EEEnvelope`), auto-joining
      the `EventV1` union via the existing `| E2EEServerEvent`; the `v1.ts` dispatch forwards
      all three to `client.e2ee?.onEvent` (web/no-session = no-op, envelopes stay queued).
      **Frontend** (`E2EEBridge`, main): six DS couriers `mlsPutKeyPackages` (MFA-ticket arg) /
      `mlsClaimKeyPackage` / `mlsCreateGroup` / `mlsJoinIntent` / `mlsSubmitCommit` /
      `mlsFetchCommits` over a new `#apiMls` — arbitration-aware (`{kind:"ok"|"conflict"|
      "feature_disabled"}`, judgment-call-3 + L4: 409 = create-race/commit-Lost normal control
      flow, 400 `FeatureDisabled` = quiet "not an E2EE call", any other non-2xx throws);
      request bodies reuse the 6.3 native-payload types, response types mirror v0/mls.rs.
      `registerMlsSink(sink)` + `#mlsSink`; `onEvent` normalizes the three `Mls*` events to
      `MlsSinkEvent` (`join_request` | `envelope` w/ `recipientDeviceId`), dropping malformed
      envelopes and NOT acking (the Step-3 session acks after durable processing, §3.3).
      stoat.js `tsc` (build) clean; client `tsc -p tsconfig.json` = SAME 9 pre-existing errors
      as the `cf432122` baseline (stash/compare), zero in e2ee.ts. Vite build owed to the
      slice-end gate. NOT committed (commit at slice end, post-gate).
- [x] 3 `MlsCallSession` core — DONE 2026-07-11. NEW `packages/client/components/rtc/mlsCallSession.ts`
      (frontend main): a PURE DS-control-plane orchestrator over `E2EEBridge` (NO Room dependency —
      Room-facing pieces are steps 4/5/6). Owns: enrol (best-effort low-water KeyPackage publish,
      tolerates feature-off + first-publish-MFA); create-or-join via the arbitrated `mlsCreateGroup`
      (200 Created / 409→leave-clean orphan L1 + join path); join path with the native T-15-guarded
      `callJoinIntent` + joiner retry (10 s ×3 → loud RE-SECURING, never plaintext); admit scheduler
      (leaf-stagger `leafIndex·2 s`, re-checks outstanding, claim→`callAdmit`→submit); **H1** submit +
      drain share ONE per-group async `Mutex` spanning the bounded (10 s) submit round-trip, staged →
      Won(`callCommitWon`)/Lost(`callCommitLost` + **NEW-2 inline rebase**: synth-envelope L2 +
      gap-refetch INLINE under the same hold, never re-queued); per-group serialized mailbox drain
      (single-flight pump, ULID dedup, `drainAction` policy: bounded park→desync/rejoin M4, bounded
      per-envelope retry→ack+drop-poison item 4, gap-refetch inline, removed_self teardown L5,
      poisoned→successor via `supersedes`); group-level transitions (rejoin/successor/removed) run
      DETACHED outside the lock (avoids NEW-2 deadlock), one-at-a-time + bounded re-establish; **C1**
      records own-won staged-commit KIND (`#lastOwnWon`) + inbound `removed` (`#lastInboundRemoved`)
      for step 4; **NEW-6** dispose self-`callRemove` via `tryAcquire` (never blocks teardown).
      Exported PURE helpers for audit: `leafStaggerDelayMs`, `routeCreateOrJoin`, `classifyArbitration`,
      `drainAction`, `claimedFromResult`. Added `E2EEBridge.ackEnvelopes(ids)` (the session acks, §3.3)
      + client-index re-exports. NOT wired into `state.tsx` yet (deferred to step 6 alongside enable —
      keeps each step's diff focused; the session has no Room dep so nothing is exercised at runtime
      until then). client `tsc -p tsconfig.json` = SAME 9 baseline errors, 0 in the new module
      (positive-control-confirmed the file IS typechecked); prettier-clean. Vite build + live proof
      owed to steps 9/10 (the module isn't imported by an entry point until step 6, so vite tree-shakes
      it today). NOT committed.
- [x] 4 rotation transition window + loud-state debounce — DONE 2026-07-11 (frontend `main`,
      UNCOMMITTED). Two files:
      - **`rtc/mlsCallKeys.ts` (provider install-mode).** `applyKeys` split into `applyRemoteKeys`
        (previous+remotes, send index untouched) + `applyLocalKey` (the send-index switch);
        `applyKeys` = both (immediate / reconnect). **Correctness fix beyond the plan:** native
        derives `previous[]` over the CURRENT roster (mod.rs:1394-1399) so it INCLUDES the local
        device's own previous-epoch key — installing it would transiently regress our send index
        onto an epoch a just-removed member still reads. `orderForInstall`/`remoteInstallEntries`
        now EXCLUDE the local identity from `previous[]` (we never decrypt ourselves), so the local
        key is only ever installed at the CURRENT epoch, last. New exported `remoteInstallEntries` /
        `localInstallEntries` for audit.
      - **`rtc/mlsCallSession.ts` (rotation seam).** Optional `bindMedia({installer, localIdentity,
        onEncryptionState?})` (narrow `KeyInstaller` structural iface the `MlsKeyProvider`
        satisfies — auditable without a Room). `onLocalKeysChanged(groupId, epoch)` = the **SOLE
        applyKeys driver (NEW-3)**: classifies via `classifyLocalKeyInstall` (own-won from
        `#lastOwnWon` KIND / inbound from epoch-keyed `#lastInbound.removed` / first-key /
        **fail-safe Remove-immediate on unknown, C1**) and installs immediate vs `applyRemoteKeys`
        + **epoch-fenced ≤2 s Add-grace** local install. **NEW-1:** any newer epoch OR
        Remove-immediate `#cancelGrace`s the pending timer, and the deferred install double-guards
        `#installEpoch !== epoch` so a stale timer can never regress the send key. `#lastInbound`
        set synchronously in `#onEpochAdvanced` BEFORE the async keys-changed reaches the classifier
        (closes the M1 event-vs-outcome order). **§4.4 loud-state debounce:** `classifyEncryptionError`
        + `#surfaceError` (rotation-window ⇒ RE-SECURING + 10 s escalation to loud; outside ⇒
        immediately loud; latched) shared by `noteEncryptionError` (LiveKit) and `#onMediaError`
        (native frame-key path), `noteEncryptionRecovered` clears a transient RE-SECURING; the
        rotation window opens BEFORE the frame-key fetch so a transient native blip self-heals.
        **Lag (§1.5):** `lagAction` warn@8 / desync@12 (pinned to native keys.rs:42/44) applied in
        `#gapRefetchInline` against `ResponseFetchMlsCommits.current_epoch` → detached rejoin-fresh.
        `#resetRotationState` (folded into `#resetGroupBuffers`) drops all rotation memos/timers on
        every group re-establish. Exported pure helpers: `classifyLocalKeyInstall`, `lagAction`,
        `classifyEncryptionError` (+ types `OwnWonMemo`/`InboundMemo`/`LocalKeyInstall`/`LagAction`/
        `KeyInstaller`/`MlsMediaBinding`/`MediaEncryptionState`).
      - **NOT wired into `state.tsx`** — per this breakdown's Architecture §3 + step 6, the session
        construction, the `bindMedia` call, and REPLACING the 6.3 auto-loop's direct
        `provider.applyKeys` (state.tsx:509-536) with `onLocalKeysChanged` all land in step 6
        alongside `setE2EEEnabled`. So at step-4 HEAD the runtime is unchanged (session unconstructed,
        auto-loop still direct — no NEW-3 double-fire); the machinery to flip it is complete.
      - `tsc -p tsconfig.json` = SAME 9 baseline errors (0 in either file); eslint + prettier clean.
- [x] 5 roster reconciliation + leave grace — DONE 2026-07-11 (frontend `main`, UNCOMMITTED;
      `rtc/mlsCallSession.ts` only). SFU∪MLS union both directions:
      - **Pure `reconcileRoster(sfu, mls, local)` → `{nonEnrolled, ghosts}`** (exported for audit):
        `nonEnrolled` = SFU∖MLS (the trusted downgrade-trigger enumeration + hostile-DS T-15
        backstop, carried item 2 — a live participant we cannot encrypt to ⇒ mixed ⇒ loud/pause);
        `ghosts` = MLS∖SFU (crypto-truth leaves with no SFU presence). **Local excluded from BOTH**
        so a transient self-asymmetry never reads as divergence.
      - **Binding extended:** `MlsMediaBinding` gains `sfuParticipants(): string[]` (device-qualified
        Room identities, local+remote) + `onRosterReconciled?(result)`. Step 6 renders the mixed-call
        loud state + drives pause-publish off `nonEnrolled`, and the divergent-leaf roster panel (6.5)
        off `ghosts`. The non-enrolled loud state is a DISTINCT chip signal from the rotation
        `onEncryptionState` (mixed "NOT ENCRYPTED" vs "RE-SECURING") — kept separate.
      - **Leave-grace (10 s):** `onParticipantLeft` arms a per-identity timer → `#removeMember`;
        `onParticipantJoined` cancels it (+ any ghost timer) so a reconnect within grace never churns
        remove+rejoin. Never self.
      - **Ghost-divergence (30 s > leave-grace 10 s):** `reconcileNow` arms a per-ghost timer (unless
        a faster leave-grace already covers it), clears timers for leaves no longer ghosts →
        `#removeMember`. Any member removes; arbitration dedups the herd; `#removeMember` re-checks
        (still a member AND still SFU-absent, never self) before the staged `callRemove`.
      - **`rosterConsistent(): Promise<boolean>`** = the hard enable-gate precondition (H2): fresh
        reconcile, true iff `nonEnrolled` empty. `nonEnrolled(): readonly string[]` = sync snapshot
        for step 6's pause-publish. Periodic `reconcileNow` tick (5 s safety net) started in `#toActive`,
        gated by `#reconcileEnabled` so an in-flight reconcile's `finally` can't re-arm after
        `#stopReconcile` (folded into `#resetRotationState` + `dispose`).
      - **NOT wired into `state.tsx`** — step 6 wires `participantConnected/Disconnected` →
        `onParticipantJoined/Left`, calls `reconcileNow` on epoch changes, awaits `rosterConsistent`
        at enable-time, and consumes `onRosterReconciled` / `nonEnrolled()`.
      - `tsc` = SAME 9 baseline errors (0 in the file); eslint + prettier clean.
- [x] 6 enable + plaintext-window guard + heartbeat + re-upgrade hysteresis + caps — DONE
      2026-07-11 (frontend `main`, UNCOMMITTED). The big step: the session finally drives the Room.
      - **Session (`rtc/mlsCallSession.ts`) — enable state machine.** `MlsMediaBinding` gains
        `setEncryptionEnabled?`/`pausePublishing?`/`resumePublishing?`. `#evaluateEnable(result)` runs
        off every FRESH `reconcileNow`: consistent roster + first local key + not-enabled ⇒ `#enable`
        (**plaintext-until-first-key guard**: pause → `setEncryptionEnabled(true)` → resume, the local
        key already installed so no plaintext frame ever publishes under the encrypted flag); a
        non-enrolled participant while enabled ⇒ `#onMixDetected` (PAUSE, fail-closed — 6.4 never opens
        a plaintext path); mix cleared ⇒ `#scheduleReupgrade` (15 s hysteresis, re-check consistent,
        resume on the still-valid warm group). `#resetEnableState` keeps publishing PAUSED through a
        re-secure (successor keys not installed yet) and leaves E2EE mode ON (never disables into
        plaintext). `onLocalKeysChanged` kicks `reconcileNow` on the first key so enable fires promptly.
      - **Heartbeat (§1.4):** self-rescheduling 10-min tick (`#startHeartbeat` in `#toActive`,
        `#reconcileEnabled`-style gate); `#maybeHeartbeat` stages `callHeartbeat` iff we are the LOWEST
        online leaf (deterministic single committer; fails over as leaves depart).
      - **Caps (A3):** `#tryAdmit` refuses admission when the roster is at `MAX_E2EE_CALL_MEMBERS=100`
        (the "call full for E2EE" refusal; the joiner-side UX is 6.5).
      - **First-key race fix:** `#establish` now adopts `#groupId` RIGHT AFTER `callCreate` (before the
        `mlsCreateGroup` round-trip) so the keys-changed(0) that callCreate already fired installs our
        first local key even if it arrives before arbitration resolves — a solo creator would otherwise
        never encrypt. 409-join re-points to the winner + resets rotation state (winner's first key is
        first-key-immediate); plaintext/failed clear `#groupId`.
      - **`state.tsx` wiring (the delicate live-path change).** Constructs `MlsCallSession` after
        `room.connect` + the identity assertion passes (gated on `e2eeIdentityOk` — never encrypt with a
        wrong identity), `bindMedia`s a `#buildMediaBinding(room, provider)` (live Room closures:
        `sfuParticipants`, `setEncryptionEnabled`→`room.setE2EEEnabled`, pause/resume→`#setUpstreamPaused`
        over `localParticipant.trackPublications.pauseUpstream/resumeUpstream`, `onEncryptionState`→latch
        `callEncryptionError`, `onRosterReconciled`→new `callNonEnrolled` signal), and `void session.start()`.
        The 6.3 keys-changed auto-loop (was direct `provider.applyKeys`) now routes into
        `session.onLocalKeysChanged` — **closes NEW-3** (the session is the sole applyKeys driver).
        `participantConnected/Disconnected`→`onParticipantJoined/Left`; `encryptionError`→
        `noteEncryptionError`; `participantEncryptionStatusChanged(encrypted)`→`noteEncryptionRecovered`.
        `disconnect()` + the failed-connect + supersession paths dispose the session (before
        room.disconnect so its best-effort self-`callRemove` reaches the DS). New `callNonEnrolled`
        reactive signal = the 6.4-detection↔6.5-UX meeting point.
      - **Flag-off safety (verified by trace):** with `media_e2ee_enabled` off, `start()` enrols → the
        first `/mls` call returns FeatureDisabled → the session settles to "plaintext" (terminal) and
        NEVER calls `setEncryptionEnabled(true)`; the Room's `e2ee` option stays inert (cleartext
        transport, the 6.3 behavior) → a normal voice call, unchanged. Only overhead: 1-2 failed
        `/mls` calls + one transient native group (leave-cleaned) per call start.
      - **Diff hygiene:** the committed `state.tsx` (cf432122) was NOT prettier-clean; a whole-file
        prettier pass would churn unrelated imports, so I restored the committed file and re-applied ONLY
        the semantic edits (no whole-file reformat). `state.tsx` eslint = **20 problems, IDENTICAL to
        cf432122** (0 net new — 1 pre-existing `#ctx` error + 19 pre-existing prettier warnings, none on
        my lines). `mlsCallSession.ts`/`mlsCallKeys.ts` prettier + eslint clean. `tsc` = SAME 9 baseline
        errors (state.tsx's 2 are the pre-existing GainTrackProcessor + joinCall-null, shifted line #s).
- [x] 7 Android enablement gate (fail-CLOSED, audit H3/NEW-4) — DONE 2026-07-11 (frontend `main` only:
      `e2ee.ts` + `state.tsx`, UNCOMMITTED). `nativeE2EEAvailable()` is TRUE on the Capacitor Android shell but that
      shell can't yet RECEIVE `e2ee:call-keys-changed` (its listener is 6.7), so an E2EE-capable Room
      there would never install a first local key → the pause-publish window would stay open forever and
      publish plaintext under an "encrypted" Room (invariant 1). Fix:
      - **`E2EEBridge.nativeKeyPushAvailable(): boolean`** (`components/client/e2ee.ts`, next to
        `onCallKeysChanged`) = `!!window.__TAURI__?.event` — the EXACT precondition `onCallKeysChanged`
        checks before subscribing, co-located so 6.7's Capacitor key-push updates both together. The
        desktop shell's `__TAURI__.event` presence is already relied on by `onCallKeysChanged`, so the
        probe is true on desktop, false on Android/web.
      - **`state.tsx`:** folded into the capability check — `e2eeCapable = isE2EESupported() &&
        nativeE2EEAvailable() && !!bridge?.nativeKeyPushAvailable()`. It is **SYNCHRONOUS at
        Room-construction time** (NEW-4 — never gated on the async `onCallKeysChanged` return, which
        resolves too late). A no-key-push shell is built WITHOUT the `e2ee` option → the loud
        non-enrolled path, same as web, never a plaintext-publishing E2EE Room. Also hoisted the bridge
        into a single `const bridge` at the top of `connect()` and reused it (capability check +
        `e2eeDeviceId` + keys-changed loop + session construction) — 4 redundant `this.getClient()?.e2ee`
        fetches collapsed to 1.
      - `tsc` = SAME 9 baseline; `state.tsx` eslint = 20 problems IDENTICAL to cf432122 (0 net new);
        `e2ee.ts` eslint = 12 pre-existing prettier warnings (all < line 2653; my `nativeKeyPushAvailable`
        at 3578 is clean). Carried item 6 CLOSED.
- [x] 8 R-1/R-2 metrics + thresholds — DONE 2026-07-11 (frontend `main`, `rtc/mlsCallSession.ts` only,
      UNCOMMITTED). Off-the-correctness-path recorder (`MlsMetrics`) + pure `percentile`/`summarize`
      helpers (exported for audit) + thresholds.
      - **R-1 receive-gap** = `keys-changed → REMOTE keys installed` (the client-observable moment it can
        decrypt peers' new-epoch frames), classified add/remove from the same signal the rotation
        classifier uses. Recorded in `onLocalKeysChanged` around `applyKeys`/`applyRemoteKeys`. Asserts
        add p95 < 250 ms, remove p95 < 1 s.
      - **R-1 commit-propagation** = own `submit → Won` round-trip, recorded in `#stageAndSubmit`. Asserts
        p95 < 2 s (if a commit routinely exceeds the Add-grace, the grace can't hide the gap).
      - **R-2 mailbox** = peak receive-queue depth + bytes (`#enqueue`, `envelopeBytes` = base64→bytes)
        vs the server's 512 / 32 MiB budgets, plus dedup-skip / park / gap-refetch / retry /
        desync-escalation counters (in `#consume`). Measures pressure + recovery, NOT "zero drops" (M2).
      - `metrics(): MlsMetricsSummary` accessor + a summary logged on `dispose` (console.info if pass,
        console.warn on any threshold breach). Cumulative per-CALL (survives group re-establish).
      - **M3 honesty:** the summary comment + `metrics()` doc state R-1 is NOT a substitute for the
        T-03-at-the-remover correctness assertion — a C1 mis-classification would SHRINK the measured
        Remove gap, so R-1 can show green while invariant 7 is broken. That correctness leg is a native
        6.2 test (green) + the step-9 wrong-key negative control.
      - `tsc` = SAME 9 baseline (0 in file); prettier + eslint clean. `performance.now()` for timing.
- [ ] 9 LIVE two-desktop proof + wrong-key negative control (BLOCKING)
- [ ] 10 gate — media-e2ee-reviewer on the diff
