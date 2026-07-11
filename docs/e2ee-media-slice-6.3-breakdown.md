# Slice 6.3 — Desktop IPC + client key plumbing: implementation breakdown

Breakdown for sub-slice 6.3 of [e2ee-media-mls-plan.md](e2ee-media-mls-plan.md) (plan §8
row 6.3). Written 2026-07-11, before coding, so a follow-on session can resume from this
file. IPC lives in `acutest-desktop/src-tauri/src/e2ee.rs`; native crypto in
`e2ee-core` (already committed, master 5cbb167); client media plumbing in the `frontend`
repo (`packages/client`). Gate at the end: **e2ee-crypto-reviewer (boundary §7.2) +
frontend-code-reviewer**. The 6.3 gate is allowed to open ONLY because 6.2b is merged
(bundled `tauri.localhost` origin + restrictive CSP + capability re-lock — the hard
precondition of §7.1 Q3 / amendment A2).

## Contract inputs (fixed by 6.2, already committed)

Native engine surface (`e2ee-core/src/mls/mod.rs`), all on `&mut E2ee` except
`mls_call_pending_commit_epoch` (`&self`). Returns are `Serialize` structs re-exported
from the crate root (`MlsCallCreated`, `MlsCallState`, `MlsFrameKeys`, `MlsFrameKey`,
`MlsProcessOutcome`, `MlsRosterEntry`); wire shapes under `acutest_e2ee_core::wire`.

| Native method | Signature (args → return) |
|---|---|
| `mls_call_create` | `(channel_id, user_id, supersedes: Option<&str>) → MlsCallCreated` |
| `mls_call_join_intent` | `(group_id, channel_id, user_id) → wire::MlsJoinIntentPayload` |
| `mls_call_admit` | `(&wire::MlsJoinRequest, &wire::MlsClaimedKeyPackage) → wire::SubmitMlsCommitPayload` |
| `mls_call_process` | `(&wire::MlsEnvelope, user_id) → MlsProcessOutcome` |
| `mls_call_commit_won` | `(group_id, won_epoch) → MlsProcessOutcome` (cross-checks `won_epoch == current+1`, refuses on mismatch / no pending) |
| `mls_call_commit_lost` | `(group_id) → ()` |
| `mls_call_pending_commit_epoch` | `(group_id) → Option<i64>` (the epoch a staged commit would establish) |
| `mls_call_leave_cleanup` | `(group_id) → ()` |
| `mls_call_heartbeat` | `(group_id) → wire::SubmitMlsCommitPayload` |
| `mls_call_remove` | `(group_id, target_user_id, target_device_id) → wire::SubmitMlsCommitPayload` |
| `mls_call_state` | `(group_id) → MlsCallState` |
| `mls_call_frame_keys` | `(group_id) → MlsFrameKeys` — **the §7.2 egress** |
| `mls_publish_key_packages` | `(user_id) → wire::PublishMlsKeyPackagesPayload` |
| `mls_replenish_check` | `(user_id, server_remaining) → Option<wire::PublishMlsKeyPackagesPayload>` |
| `mls_expire_key_packages` | `() → ()` |

Native error variants the caller policy keys on (`e2ee-core/src/error.rs`):
`MlsEpochGap{expected,got}` (park + gap-refetch, never ack), `MlsPoisonedEpoch{epoch}`
(successor-needed), `MlsGroupNotFound` (wiped), `MlsUnsolicitedWelcome` /
`MlsWelcomeContextMismatch` (refuse-loud), `MlsNotPublished`, `MlsLeafRejected`.

**Session user is a command parameter** (the shell supplies it; every existing `e2ee_*`
command already threads `self_user_id`/`user_id` this way — 6.2 breakdown "Deferred to
6.3+" note).

**IPC has FOUR sync points, not three** (the task text says three): `APP_COMMANDS`
(`build.rs`), `generate_handler!` (`lib.rs`), `capabilities/default.json` (bundled/local
origin — the shipped surface, `"local": true`), and the debug-only `e2ee-dev-origins`
`CapabilityBuilder` in `lib.rs` (localhost Vite origin). Keep all four in lockstep; only
`default.json` reaches shipped binaries.

**6.0 proved the exact provider/worker path** (`e2eeMediaSpike.ts`, deleted in this
slice): `BaseKeyProvider({sharedKey:false, ratchetWindowSize:0, failureTolerance:0})`,
`importKey('raw', buf, 'HKDF', false, ['deriveBits','deriveKey'])` → `onSetEncryptionKey`,
`import E2EEWorker from "livekit-client/e2ee-worker?worker"`, remote-first/local-last,
mid-call `setE2EEEnabled` toggling. `state.tsx` wired it at the import, the `new Room`
`e2ee:` option (:265), `attach` (:395), and `detach` (:413) — the replacement points.

## Approved judgment calls (2026-07-11)

1. **`e2ee_call_confirm_downgrade` = dialog gate only in 6.3.** Native 6.2 has no
   call-downgrade primitive (the MLS ctl-announce + mode-transition state machine is
   §3.4 / row 6.5). 6.3 lands the blocking native OS dialog (confirmed/declined) + its
   capability grant, so the release-locked allowlist the crypto reviewer signs off at the
   §7.2 boundary is COMPLETE and untouched by 6.5. The ctl-announce/sticky-plaintext
   record is 6.5.
2. **Delete the 6.0 spike in 6.3** (`e2eeMediaSpike.ts`, the `state.tsx` hooks, the
   `vite.config.ts` `/__e2ee_spike_report` sink). 6.3 supersedes its only consumer; closes
   pre-deploy blocker task_83f673d2.
3. **Live two-desktop media-plane proof is 6.4**, after the create/join/admit/commit DS
   drive loop exists. 6.3 lands plumbing + unit/adversarial tests; the live proof is the
   6.3/6.4 must-carry, discharged in 6.4.
4. **`MlsKeyProvider` in `components/rtc/mlsCallKeys.ts`** (LiveKit-facing, near the
   Room); the native invoke methods + `callStates` map stay on `E2EEBridge`
   (`components/client/e2ee.ts`) — honoring §4.2 "ride the existing transport seam."
   Deviation-with-rationale from §4.2's literal file citation (keeps the media pipeline
   out of the 2741-line text/DM bridge); surfaced at the gate.

## Steps

1. **Desktop IPC (`src-tauri/src/e2ee.rs`) + 4 sync points.** One command per native
   method via `with_engine`, mirroring existing param/error conventions. Names:
   `e2ee_call_create`, `e2ee_call_join_intent`, `e2ee_call_admit`, `e2ee_call_process`,
   `e2ee_call_commit_won`, `e2ee_call_commit_lost`, `e2ee_call_pending_commit_epoch`,
   `e2ee_call_leave_cleanup`, `e2ee_call_heartbeat`, `e2ee_call_remove`,
   `e2ee_call_state`, `e2ee_call_frame_keys`, `e2ee_call_confirm_downgrade`,
   `e2ee_mls_publish_key_packages`, `e2ee_mls_replenish`, `e2ee_mls_expire_key_packages`.
   `e2ee_call_frame_keys` carries a §7.2 doc-comment (SOLE secret egress; never logged).
   `e2ee_call_confirm_downgrade` is `async` + `spawn_blocking` native dialog (the
   `e2ee_downgrade` pattern), returns `Error::Declined` on cancel.

2. **Epoch-change event (`e2ee:call-keys-changed`).** The core crate cannot emit Tauri
   events, so the IPC layer emits `{group_id, epoch}` after any epoch-advancing command
   (`e2ee_call_process` → `commit_applied`/`welcome_joined`, `e2ee_call_commit_won`,
   `e2ee_call_heartbeat` win). This is the decoupling seam between the mailbox-drain code
   (E2EEBridge) and the Room/provider owner (RTC layer).

3. **`MlsKeyProvider` (`packages/client/components/rtc/mlsCallKeys.ts`).**
   `extends BaseKeyProvider({sharedKey:false, ratchetWindowSize:0, failureTolerance:0})`.
   `applyKeys(MlsFrameKeys)`: for `previous` then `keys` (so current wins in the keyring),
   remote senders first and the local participant LAST, `importKey('raw', b64→buf,
   'HKDF', …)` → `onSetEncryptionKey(material, livekit_identity, key_index)`. Hygiene
   (§4.2): retain only current(+previous) epoch per participant, clear removed leaves,
   re-push from native on reconnect (do not trust LiveKit's stale `getKeys()` replay),
   `worker.terminate()` on call end.

4. **`E2EEBridge` call methods + event subscription + the 3 carried items
   (`packages/client/components/client/e2ee.ts`).** Thin `#invoke` wrappers for every
   command; `onCallKeysChanged(cb)` via the `tauri.event.listen` pattern
   (`#ensureBackupCourier`); `callStates: ReactiveMap<channelId, CallE2EEState>`
   (sendModes pattern; minimally populated — 6.4/6.5 drive it). Carried items land here
   (the caller boundary):
   - **① T-15 client-leg** — `callJoinIntent` asserts the **DS-returned `channel_id`
     equals the UI-intended channel** BEFORE invoking native (native binds `channel_id`
     into the signed intent but cannot check it against user intent — this is the only
     place that can). Loud throw on mismatch.
   - **② commit_won reconnect check** — `callCommitWon` is only ever called with an epoch
     from an authoritative DS `Won` response; `reconcilePendingCommit(groupId,
     dsCurrentEpoch, dsWinnerIsSelf)` uses `pending_commit_epoch` to route a dangling
     stage to `commit_lost` + rebase, never a guessed `won`.
   - **③ ack-and-drop** — `classifyProcessError(err)`:
     `MlsPoisonedEpoch`/`MlsGroupNotFound` → ack+drop (poisoned also surfaces
     successor-needed); `MlsEpochGap` → park + gap-refetch (NO ack);
     `MlsUnsolicitedWelcome`/`MlsWelcomeContextMismatch` → refuse-loud + ack+drop.

5. **Always-E2EE-capable Room + keys loop + processor doc (`state.tsx`).** Replace the
   spike wiring at `:265`: `e2ee: (isE2EESupported() && nativeE2EEAvailable()) ? {
   keyProvider, worker: new E2EEWorker() } : undefined` (unsupported shells → no option,
   treated as non-enrolled). Post-connect: subscribe `e2ee:call-keys-changed` →
   `callFrameKeys` → `applyKeys`; wire `ParticipantEncryptionStatusChanged` +
   `EncryptionError` as required green-gating input (consumed by 6.5). Add the §4.3
   processor-ordering doc comment (pre-encode processor → encoder → post-encode E2EE →
   SFU; nothing may reorder). The eligibility decision + `setE2EEEnabled(true)` driving is
   6.4/6.5; 6.3 makes it possible.

6. **Productionize worker bundling + pins.** Confirm the emitted `?worker` asset against
   the 4 MB PWA precache cap (`vite.config.ts`; add to `globIgnores` if it threatens it);
   pin `livekit-client` exactly (`^2.13.0` → `=2.15.13`, Q7).

7. **Remove the 6.0 throwaway.** Delete `e2eeMediaSpike.ts`, the `state.tsx` spike hooks,
   and the `vite.config.ts` `/__e2ee_spike_report` sink.

8. **Tests.** T-10 processor-ordering coexistence (denoise pre-encode + E2EE post-encode);
   T-15 client-leg mismatch refusal; commit_won-never-on-guess + reconcile; ack/drop/park
   classification; `MlsKeyProvider` HKDF-material (not AES-GCM) + remote-first/local-last +
   hygiene; IPC-boundary scrub (only `frame_keys` returns secret material).

9. **Gate.** e2ee-crypto-reviewer (§7.2 boundary) + frontend-code-reviewer on the full
   diff. Checklist: the 3 carried items covered; `frame_keys` is the SOLE secret egress;
   capability allowlist re-locked across all 4 sync points, bundled-origin only, no remote
   grant; `MlsKeyProvider` HKDF-material import + hygiene; always-E2EE Room construction;
   keys-changed loop; processor ordering; livekit pin; spike removed.

## Verification & test coverage

- **Rust IPC** (`src-tauri`): `cargo check` clean (16 s incremental), no warnings.
- **Client**: `tsc -p packages/client/tsconfig.json` — my files (`e2ee.ts`,
  `mlsCallKeys.ts`, `client/index.tsx`, `state.tsx`) introduce **zero** new
  errors (verified by stash/compare: 27 errors at baseline `258bc515`, 27 with
  my changes; the one match in `state.tsx` is the pre-existing
  `GainTrackProcessor` type error, present in baseline). The repo carries 27
  pre-existing `tsc` errors across 14 unrelated files; the project's actual
  gate is `vite build` (esbuild, no full-program typecheck), which this slice
  also runs.
- **livekit-client** pinned exact `2.15.13` (Q7); lockfile specifier synced.
  The `?worker` asset (`livekit-client.e2ee.worker.mjs`, ~95 KB) is far under
  the 4 MB PWA precache cap — no `globIgnores` entry needed.

**Test approach (house-consistent).** The client has NO unit-test framework
(only Playwright e2e); prior E2EE slices validated the client via typecheck +
browser/manual E2E and put the unit tests on the Rust/server side. 6.3 keeps
that split:

- **Native legs of all three carried items are already unit-tested (green) in
  6.2**: cross-group Welcome (T-15 native leg), `commit_won` refuses wrong
  epoch / no-pending, poisoned→successor (T-17), unsolicited-Welcome refusal,
  epoch-gap park (inv 10), secrets-never-in-wire scrub (T-09).
- **6.3 client-leg logic is pure + exported for audit**: `classifyEnvelopeError`
  (ack/drop/park policy), `orderForInstall` (§1.5 previous-first /
  remote-before-local ordering). The T-15 pre-sign channel guard
  (`callJoinIntent`) and the `reconcilePendingCommit` decision are small,
  pure-branching methods.
- **T-10 (denoise + E2EE coexistence) & the live media plane**: documented as
  the §4.3 ordering invariant in `state.tsx`; its runtime proof rides the 6.4
  two-desktop live E2E (approved judgment call #3 — the live media-plane proof
  lands in 6.4, after the DS create/join/admit/commit drive loop exists).
- **No vitest was added** — introducing a unit-test runner to a repo that has
  none is a maintainer decision, out of 6.3 scope. Flag at the gate if client
  unit coverage is wanted.

## Status

- [x] 1 desktop IPC + 4 sync points (build.rs / lib.rs handler / default.json /
      dev-origins cap) — `cargo check` clean
- [x] 2 epoch-change event (`e2ee:call-keys-changed`, emitted from the IPC
      layer after create / applied-commit / joined-Welcome / commit_won)
- [x] 3 MlsKeyProvider (`rtc/mlsCallKeys.ts`: HKDF-material import,
      previous-first/remote-before-local ordering, worker-terminate hygiene)
- [x] 4 E2EEBridge call methods + 3 carried items (T-15 `callJoinIntent`
      guard, `reconcilePendingCommit`, `classifyEnvelopeError`)
- [x] 5 always-E2EE Room + keys loop + processor doc (`state.tsx`)
- [x] 6 worker bundling confirmed + livekit-client pinned `2.15.13`
- [x] 7 remove 6.0 spike — done by parallel commit `258bc515`
- [x] 8 tests — native legs (6.2, green) + pure exported client-leg logic;
      T-10/live plane → 6.4 (see coverage note)
- [x] 9 gate — **BOTH SHIP-WITH-FIXES**; blocking fixes folded (below)

## Gate outcome (2026-07-11)

**e2ee-crypto-reviewer (§7.2 boundary): SHIP-WITH-FIXES, no CRITICAL/HIGH.** The
boundary is intact — `e2ee_call_frame_keys` is the sole secret egress, keys
import as non-extractable HKDF material, the error surface is scrubbed, the
capability allowlist is re-locked local-only across all four sync points
(`default.json` `"local": true`, dev cap `#[cfg(debug_assertions)]`), and the
core crate is untouched. **frontend-code-reviewer (media pipeline):
SHIP-WITH-FIXES**; the 2 HIGH were availability/lifecycle, not confidentiality.

**Folded before landing (2026-07-11):**
- **[crypto MEDIUM — top residual risk]** `classifyEnvelopeError` had no terminal
  disposition for structurally-malformed envelopes (`mls` / `invalid_argument`
  / `mls_not_published` fell to no-ack) → an untrusted DS could wedge one bad
  envelope at a victim's queue head and block a legitimate Remove behind it
  (invariant-7 degradation). Now ack+drop as a POISON PILL, distinct from the
  transient no-ack retries.
- **[frontend HIGH]** Unguarded `new E2EEWorker()` on the connect critical path
  → a worker that can't construct (CSP/asset) broke EVERY call. Now wrapped in
  try/catch that degrades to a non-E2EE-capable Room (loud non-enrolled path,
  never silent plaintext). *(Verified `tauri.conf.json` already grants
  `worker-src 'self' blob:`, so the shipped CSP is fine; the guard is defense.)*
- **[frontend HIGH]** Async-listener registration race — `#unlistenCallKeys`
  stored after an `await` let a fast re-connect orphan the listener + revive an
  abandoned Room. Now a `#connectGen` supersession token guards every post-await
  step (drop-and-bail if superseded).
- **[frontend MEDIUM]** Failed `connect()` leaked the worker + native listener.
  Now a try/catch around the join/connect awaits tears down this invocation's
  E2EE resources on failure.
- **[frontend MEDIUM]** `reconcilePendingCommit` was over-strict
  (`dsCurrentEpoch === pending`) — it discarded a genuinely-won commit whenever
  the DS had advanced past it. Now wins on `dsWonEpoch === pending` (merge, then
  the caller gap-refetches forward).
- **[frontend LOW]** `callEncryptionError` stored `String(error)`, losing the
  structure 6.5's dual-gating needs. Now latches the STRUCTURED error.

**Deferred to 6.4/6.5 (documented, non-blocking — 6.3 doesn't drive the loop):**
- **[6.4, crypto MEDIUM + INFO]** T-15 client-leg is vacuous unless the 6.4
  caller sources `intendedChannelId` from route/UI truth with provenance
  INDEPENDENT of the DS create/join response — explicit 6.4 wiring-audit item.
- **[6.4, crypto INFO]** `orderForInstall` local-last correctness depends on the
  LiveKit token identity being exactly `"{user_id}:{device_id}"` (6.1
  device-qualified) — add a 6.4 runtime assertion.
- **[6.4]** The 6.4 mailbox drain MUST bound retries so an unrecognised terminal
  error (the no-ack default) can't spin forever; and cover the
  `setE2EEEnabled(true)`→first-`setKey` plaintext-until-first-key window
  (§1.5 sender-grace + pause-publish + invariant-11 dual-gating).
- **[6.4/6.7]** Android builds an E2EE-capable Room but `onCallKeysChanged` is a
  Tauri-only no-op until 6.7 — gate call-encryption ENABLEMENT on a real
  keys-changed subscription so Android can't publish undecryptable media.
- **[6.5, crypto LOW]** The downgrade dialog's non-enrolled roster must be driven
  from the native `mls_call_send_mode` verdict, not the webview-supplied arg.
- **[deploy]** Keep `media_e2ee_enabled` FALSE until 6.5 (a 6.3-only build would
  otherwise run calls with an inert E2EE manager + no indicator).

## Notes for the gate + follow-on (6.4/6.5)

- **4 sync points, not 3**: the debug-only `e2ee-dev-origins` `CapabilityBuilder`
  in `lib.rs` is a fourth grant (localhost Vite origin); kept in lockstep.
  Only `capabilities/default.json` (`"local": true`) reaches shipped binaries.
- **6.3 deliberately does NOT drive** create/join/admit/commit HTTP, the
  mailbox drain, membership→epoch, `setE2EEEnabled(true)`, or the downgrade
  state machine — those are 6.4 (lifecycle/churn) and 6.5 (downgrade UX). 6.3
  lands the IPC surface, the provider, the always-E2EE Room, the key loop, and
  the caller-policy guards the loop will use.
- `e2ee_call_confirm_downgrade` is the dialog gate only (approved call #1);
  6.5 adds the MLS ctl-announce + transition state machine behind it.
- `callEncryption` (ReactiveMap) + `callEncryptionError` (signal) on the Voice
  store are the §4.4 dual-gating inputs 6.5's chip consumes.
- The provider's Add-grace send-key *timing* (continue on old epoch 2 s) is 6.4;
  6.3 installs current+previous immediately (correct for Remove-immediate).
