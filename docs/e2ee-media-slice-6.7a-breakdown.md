# Media E2EE slice 6.7a — Android probe + uniffi surface

Sub-slice of the slice-6 master plan (`e2ee-media-mls-plan.md` §3.6, sub-slice
table row 6.7a). Desktop slices 6.0–6.6 are COMPLETE and committed;
`media_e2ee_enabled` remains FALSE. 6.7a brings the Android shell to command
parity so the platform-independent client lifecycle (6.4/6.5, all in shared
frontend code above the `NativeTransport` seam) can drive calls on Android.
6.7b (separate session) is on-device integration, APK, and the Android gate.

## 0. Scope

IN: (1) uniffi `mls_call_*`/`mls_*` exports on `E2eeEngine` (e2ee-android),
1:1 with the desktop Tauri surface; (2) Kotlin `E2eePlugin` allowlist arms +
the `callKeysChanged` plugin event (the desktop `e2ee:call-keys-changed`
analog); (3) the native BLOCKING confirm-downgrade dialog method; (4) the
frontend seam updates that let the shared RTC layer see Android as a
key-push-capable shell; (5) bindings regen + host binding tests; (6) the Q2
on-device probe procedure (staged; the run itself needs a physical device).

OUT (6.7b): APK build, on-device call vs desktop peer, downgrade/rotation on
device, Android-scoped adversarial re-runs, the media-e2ee + crypto dual gate
for the integrated result, **and the main-document CSP** (audit MED-1 — must
be authored + validated on device against hCaptcha/Stripe/Sentry/translate/
embeds, else it white-screens the shared Android build). OUT (unchanged):
server, e2ee-core, desktop.

## 1. Q2 probe — GO/NO-GO precondition (staged here, run on device)

Master-plan open question #2: Android System WebView support for the LiveKit
E2EE data path is UNVERIFIED. The probe must confirm, in the REAL Capacitor
WebView (not Chrome-the-app):

- P1 `RTCRtpSender.prototype.createEncodedStreams` exists (Chromium path
  livekit-client 2.15.13 uses; `RTCRtpScriptTransform` is the Safari path) —
  i.e. `isE2EESupported()` returns true.
- P2 The bundled `livekit-client/e2ee-worker?worker` asset constructs from the
  Capacitor asset server origin (`https://localhost`) — no CSP/scheme refusal.
- P3 `crypto.subtle.importKey('raw', …, 'HKDF', …)` + `deriveKey(AES-GCM 128)`
  succeed in the worker (secure-context WebCrypto).
- P4 Field-version floor: record the device WebView version; the client
  already treats `isE2EESupported() === false` as an unsupported shell (loud
  non-enrolled path, invariant 2), so old WebViews degrade safely — the probe
  informs UX messaging, not a hard gate.

Procedure (5 min, staged in §8): install the debug APK, `chrome://inspect` or
`adb forward` CDP into the app WebView, run the probe snippet from the
console. NO-GO on P1–P3 ⇒ 6.7 stops (Android stays a permanent loud-downgrade
platform); the code built in this slice remains inert behind
`isE2EESupported()` and ships no risk.

## 2. uniffi surface (e2ee-android/src/lib.rs)

One new section on `E2eeEngine`, mirroring `src-tauri/src/e2ee.rs` lines
1189–1612 exactly — THIN ADAPTER rule unchanged: JSON strings in/out using
the core serde shapes, `err()`-scrubbed typed errors, no logic. 20 methods:

| uniffi export | core call | notes |
|---|---|---|
| `mls_call_create(channel_id, user_id, supersedes: Option<String>) -> String` | `mls_call_create` | returns `MlsCallCreated` JSON; Kotlin emits keys-changed (epoch 0) |
| `mls_call_join_intent(group_id, channel_id, user_id) -> String` | `mls_call_join_intent` | T-15 client-leg stays in shared JS (`callJoinIntent`) — unchanged |
| `mls_call_verify_join_intent(request_json) -> ()` | `mls_call_verify_join_intent` | read-only trust gate |
| `mls_call_admit(request_json, claimed_json) -> String` | `mls_call_admit` | `SubmitMlsCommitPayload` JSON |
| `mls_call_process(envelope_json, user_id) -> String` | `mls_call_process` | `MlsProcessOutcome` JSON; Kotlin emits keys-changed iff kind ∈ {welcome_joined, commit_applied} |
| `mls_call_commit_won(group_id, won_epoch: i64) -> String` | `mls_call_commit_won` | Kotlin emits keys-changed |
| `mls_call_commit_lost(group_id) -> ()` | `mls_call_commit_lost` | |
| `mls_call_pending_commit_epoch(group_id) -> String` | `mls_call_pending_commit_epoch` | JSON `null` or number |
| `mls_call_leave_cleanup(group_id) -> ()` | `mls_call_leave_cleanup` | |
| `mls_call_heartbeat(group_id) -> String` | `mls_call_heartbeat` | |
| `mls_call_remove(group_id, target_user_id, target_device_id) -> String` | `mls_call_remove` | |
| `mls_call_state(group_id) -> String` | `mls_call_state` | display data only |
| `mls_call_frame_keys(group_id) -> String` | `mls_call_frame_keys` | THE §7.2 egress — see §5 |
| `mls_call_non_enrolled(group_id, sfu_participants: Vec<String>) -> String` | `mls_call_non_enrolled` | JSON string array |
| `mls_call_mark_downgrade_confirmed(group_id) -> ()` | `mls_call_mark_downgrade_confirmed` | DIALOG-ONLY — see §3.3; export carries the wipe-style doc comment ("reachable ONLY from the plugin's confirm-dialog click; must never be wired to any path that skips that dialog") [audit LOW-8] |
| `mls_call_clear_downgrade_confirmed(group_id) -> ()` | `mls_call_clear_downgrade_confirmed` | safe direction; generic allowlist OK |
| `mls_call_announce(group_id, user_id) -> String` | `mls_call_announce` | confirm-gated in CORE (`MlsNotConfirmed`) — gate holds regardless of caller |
| `mls_publish_key_packages(user_id) -> String` | `mls_publish_key_packages` | |
| `mls_replenish(user_id, server_remaining: u64) -> String` | `mls_replenish_check` | JSON payload or `null` |
| `mls_expire_key_packages() -> ()` | `mls_expire_key_packages` | |

Doc-comment rule: no `/*` sequences inside exported-item docs (slice-4
bindgen gotcha — nested block comments break generated Kotlin).

## 3. Kotlin plugin (E2eePlugin.kt)

### 3.1 Generic `call()` arms

New arms, same requireString/objectJson/arrayJson idioms, same arg keys the
JS bridge already sends the desktop (camelCase): `e2ee_call_create`
(channelId, userId, supersedes?), `e2ee_call_join_intent` (groupId,
channelId, userId), `e2ee_call_verify_join_intent` (request),
`e2ee_call_admit` (request, claimed), `e2ee_call_process` (envelope, userId),
`e2ee_call_commit_won` (groupId, wonEpoch), `e2ee_call_commit_lost`,
`e2ee_call_pending_commit_epoch`, `e2ee_call_leave_cleanup`,
`e2ee_call_heartbeat`, `e2ee_call_remove` (groupId, targetUserId,
targetDeviceId), `e2ee_call_state`, `e2ee_call_frame_keys`,
`e2ee_call_non_enrolled` (groupId, sfuParticipants),
`e2ee_call_clear_downgrade` → `mlsCallClearDowngradeConfirmed`,
`e2ee_call_announce` (groupId, userId), `e2ee_mls_publish_key_packages`
(userId), `e2ee_mls_replenish` (userId, serverRemaining),
`e2ee_mls_expire_key_packages`.

NOT in the generic allowlist by design (comment updated in the else-arm
block): `e2ee_call_confirm_downgrade` (native dialog method §3.3) and the
raw `mls_call_mark_downgrade_confirmed` (reachable ONLY from that dialog's
confirm click — wipe parity; a webview that could arm the announce gate
directly would reduce the §3.4 dialog to decoration).

`wonEpoch` note: `call.getInt` would truncate; epochs are i64. Use
`call.getLong`-equivalent (Capacitor `JSObject` carries numbers as
Int/Long/Double — read via `call.data.optLong("wonEpoch", -1)` with a
missing-key check) so a >2^31 epoch cannot silently wrap.

Required-arg rule [audit LOW-5]: trust-adjacent array/object args —
`sfuParticipants` (BOTH the `e2ee_call_non_enrolled` arm and the
`callConfirmDowngrade` dialog method) and `displayNames` — reject
`invalid_argument` when ABSENT via the throwing `arrayJson`/`objectJson`
idiom. Do NOT copy the slice-5 `?: emptyList()` defaulting idiom for these:
a silent empty default would compute `non_enrolled = []` off a key typo.
Desktop Tauri hard-errors on a missing arg; the arms match.

### 3.2 `callKeysChanged` plugin event (the desktop emit analog)

Desktop emits `e2ee:call-keys-changed` from the IPC layer (e2ee.rs
`emit_keys_changed`) — the SHELL layer, not core. The Android shell layer is
this plugin, so the emit lives here, with the identical trigger set:

- after `e2ee_call_create` resolves → `{group_id, epoch: 0}` (parse
  `group_id` from the `MlsCallCreated` JSON);
- after `e2ee_call_process` resolves with `kind` ∈ {`welcome_joined`,
  `commit_applied`} → `{group_id, epoch}` from the outcome JSON;
- after `e2ee_call_commit_won` resolves → `{group_id, epoch}` from the
  outcome JSON.

Emit = `notifyListeners("callKeysChanged", JSObject{group_id, epoch})`.
Payload is group id + epoch ONLY — public data (same rule as desktop's
`CallKeysChanged` struct: never key material).

**snake_case is deliberate** [audit LOW-6]: the payload keys are `group_id`
/ `epoch` — the plugin's camelCase argument convention does NOT apply here.
The listener callback type in `e2ee.ts` (`{group_id: string; epoch: number}`)
and desktop's `CallKeysChanged` serde shape are the contract; a
"normalized" camelCase payload would make `onLocalKeysChanged` no-op forever
(fields undefined) — an H3-shaped first-key failure. The §4 seam type
declares the literal shape.

**Parse-drift hazard + honest failure mode** [audit MED-2]: unlike desktop
(which reads the typed struct — the emit cannot fail), Kotlin re-parses core
serde JSON as a second, compile-unchecked consumer. A core field rename
would kill Android key rotation with `assembleDebug` still green. Controls:
(a) binding tests pin the exact extraction contract (§6); (b) the core wire
structs (`MlsCallCreated`, `MlsProcessOutcome`) carry a comment that the
Android plugin parses `group_id`/`kind`/`epoch` by name; (c) failure mode
stated honestly: emit-skip is NOT equivalent to a dropped Tauri event for a
Remove-won epoch — the local send key would stay on the removed-member-
readable epoch until the next epoch event (heartbeat bounds this at ≤10
min), an invariant-7 erosion window. The parse is therefore structured so
skipping requires the resolve JSON to be malformed (which would equally
break the JS caller), not merely unexpected-extra-fields.

### 3.3 `callConfirmDowngrade` dialog method (desktop `e2ee_call_confirm_downgrade` parity)

Dedicated `@PluginMethod`, wipe/downgrade/backup pattern:

1. Args: `groupId`, `sfuParticipants` (string array), `displayNames`
   (object user_id → name). Reject invalid_argument on missing groupId.
2. On the executor: `non_enrolled = engine.mlsCallNonEnrolled(groupId,
   sfuParticipants)` — the NATIVE-computed set (trust-load-bearing; a lying
   webview can distort the DISPLAYED names, never suppress the dialog).
3. Render `"name (user_id)"` per identity (user_id = identity prefix before
   `:`), empty set → `" (participants could not be verified)"` — the exact
   desktop strings, including the dialog body copy ("Someone in this call …
   Turn off encryption for this call?"), title "Turn off call encryption",
   buttons "Turn off"/"Cancel".
4. UI thread: BLOCKING `AlertDialog`, `setCancelable(false)` is NOT set —
   cancel/back = decline (reject `{"type":"declined"}`), matching desktop
   Cancel semantics.
5. Confirm click → executor → `engine.mlsCallMarkDowngradeConfirmed(groupId)`
   → resolve `null`. Only this path arms the announce gate.

No FLAG_SECURE needed (no secret displayed). Dialog copy is fixed English
for now — matches desktop (also unlocalized); i18n is a tracked follow-up
for both shells.

### 3.4 Threading

All engine calls stay on the plugin executor (never the UI thread); dialogs
on the UI thread; confirm-click handlers hop back to the executor. Decrypt
ordering unaffected (MLS envelope processing is serialized by the JS-side
drain in `mlsCallSession.ts`, which awaits each `callProcess` — same
contract as the text `#decryptQueue`).

## 4. Frontend seam (packages/client/components/client/e2ee.ts)

The ONLY frontend changes are at the transport seam — zero changes to
`mlsCallSession.ts` / `mlsCallKeys.ts` / `state.tsx` (that's the point of
the seam; the 6.4 H3/NEW-4 comments already say "when 6.7 adds the Android
channel BOTH update together"):

1. `E2eeCapacitorPlugin` type gains `callConfirmDowngrade(options)` and
   `addListener(eventName: "callKeysChanged", cb)` (Capacitor's PluginListenerHandle).
2. `CapacitorTransport.invoke`: route `e2ee_call_confirm_downgrade` to the
   dedicated dialog method (like `e2ee_downgrade`); everything else in the
   table above flows through the existing generic `call()` path untouched.
3. `nativeKeyPushAvailable()`: `true` also when
   `Capacitor.isNativePlatform() && getPlatform() === "android"` — the
   plugin event channel ships in the same APK as the JS bundle (bundled
   asset server), so no version skew: if the JS can ask, the shell can push.
   The Android branch carries a comment naming the bundled-dist dependency
   [audit Q3]: this truth rests on `capacitor.config.ts` `webDir: "dist"`
   with NO `server.url` remote override — a remote-webview config would
   reintroduce skew (new JS asserting the probe against an old shell).
4. `onCallKeysChanged()`: on the Capacitor shell, subscribe via
   `plugin.addListener("callKeysChanged", …)`; return
   `handle.remove`-wrapping unsubscribe. Tauri branch unchanged. The
   listener event type declares the LITERAL snake_case payload
   `{group_id: string; epoch: number}` [audit LOW-6].

Net effect: on a WebView where `isE2EESupported()` is true and "Encrypt my
calls" is ON, Android constructs the E2EE-capable Room and the shared
6.4/6.5 lifecycle drives it. All of that stays inert until the server flag
flips (no MLS groups exist ⇒ plain calls), so landing this is exactly as
safe as the desktop slices were under the same flag.

## 5. Trust-boundary disposition (what the plan audit should check)

- **Frame keys over the JS bridge**: `e2ee_call_frame_keys` returns HKDF key
  MATERIAL through `resolveJson` — the master plan §3.6 explicitly relaxes
  the Android no-keys-over-the-JS-bridge invariant for THIS one command,
  same documented invariant-6 exception + narrowest-exposure rule as
  desktop (§7.2). No interceptor route (keys are small). Everything else on
  the new surface is public wire material / opaque ciphertext / scrubbed
  errors — identical to desktop.
- **Dialog authority**: the §3.4 plaintext direction requires a physical tap
  on an OS dialog owned by installer-signed native code on BOTH shells; the
  announce gate (`MlsNotConfirmed`) is enforced in the CORE, so even a
  Kotlin bug cannot let the webview originate an announce unconfirmed.
- **Event channel**: `callKeysChanged` carries `{group_id, epoch}` only.
- **No new persistence, no new key handling**: all MLS state/crypto stays in
  the audited e2ee-core; this slice adds carriers.
- **Main-document CSP for the Capacitor origin** [audit MED-1 — disposition
  REVISED to defer to 6.7b, on-device]: §7.2's bundle+CSP control is only
  half-present on Android (bundled `dist`: yes — the load-bearing half, so
  no remote webview and no MITM-injectable remote page; CSP: none — only the
  `/_e2ee-att` responses carry `sandbox`). The remaining gap is a
  main-document CSP so an XSS foothold in the bundled app cannot pull remote
  script to exfil frame keys. **This does NOT land in 6.7a**, deliberately:
  `build:android` is the SHARED Android build (not E2EE-specific), and the
  app loads remote scripts that a naive `script-src 'self'` would break —
  hCaptcha (`solid-hcaptcha`, login), Stripe.js (`@stripe/stripe-js`),
  Sentry ingest (`@sentry/browser`), plus the media-translation and embed
  origins. An unvalidated CSP shipped here would white-screen ordinary
  Android builds with E2EE OFF (the MED-3 "compiles-green, breaks-on-device"
  class). The CSP MUST be authored AND validated against the real app on a
  device — the exact 6.7b context — enumerating every legitimate remote
  origin (hCaptcha/Stripe/Sentry/translate/embeds/app.sloga.gg + `wss`) with
  `script-src` carrying NO attacker-reachable origin, `worker-src 'self'
  blob:`, and no `connect-src` an XSS could retarget. Tracked as a BLOCKING
  6.7b gate item (§9 residuals). Interim posture = desktop's own pre-6.2b
  posture, gated behind `media_e2ee_enabled` FALSE + no APK shipped from
  6.7a. The frame-key resolve payload is still kept out of logs by the
  logging controls below.
- **Logging controls are now §7.2-load-bearing** [audit LOW-7]:
  `capacitor.config.ts` `loggingBehavior: "none"` +
  `webContentsDebuggingEnabled: false` keep `frame_key_b64` resolve payloads
  out of logcat/devtools; the config comment is updated to name frame keys
  so nobody flips them "temporarily" while debugging 6.7b.
- **Fail-closed inheritance**: unsupported WebView ⇒ `isE2EESupported()`
  false ⇒ non-E2EE Room ⇒ loud non-enrolled path (invariant 2); key-push
  probe now true on Android but the Room is still only E2EE-capable when
  the full 6.4 predicate holds (enrollment, toggle, worker construction).

## 6. Tests

- **Host binding tests** (`e2ee-android/tests/binding.rs`, slice-4 pattern):
  - `mls_publish → create → frame_keys` JSON roundtrip: shapes are the
    desktop serde shapes (group_id/epoch/keys[].frame_key_b64 present,
    32-byte material b64), epoch 0 self-key present.
  - **Kotlin extraction contract** [audit MED-2]: serialize
    `MlsCallCreated` + `MlsProcessOutcome` values (constructed directly —
    the structs are pub) and assert, via the SAME extraction shape the
    plugin uses, every field Kotlin reads by name: `MlsCallCreated.group_id`;
    `MlsProcessOutcome.kind`/`group_id`/`epoch` for `welcome_joined`,
    `commit_applied`, and the commit-won outcome. A core field rename now
    fails a test instead of silently killing Android key rotation.
  - `mls_call_announce` without confirm → typed `mls_not_confirmed` error
    JSON through the FFI (the gate survives the boundary).
  - `mls_call_pending_commit_epoch` none → JSON `null` (not `"null"` string
    mangling, not an error).
  - `mls_call_verify_join_intent` with garbage JSON → `invalid_argument`
    (scrubbed, field-tagged) not a panic.
  - frame-keys error path (`group_not_found`) → scrubbed typed JSON.
- **Kotlin compile check**: `gradlew assembleDebug` after bindings regen
  (also proves generated Kotlin is valid — the doc-comment gotcha).
- **Frontend**: `tsc` no new errors over baseline; `npx vite build` green.
- On-device legs (FFI lift, dialogs, real WebView) are 6.7b by design —
  slice-4 LESSON acknowledged: host tests cannot catch FFI-lift/Keystore
  issues; that is exactly why 6.7b's on-device smoke is a REQUIRED step.

## 7. Deliverables / commit plan

- `acutest-desktop` (master): e2ee-android/src/lib.rs + tests/binding.rs +
  the MED-2 comments on the core wire structs (docs only, core logic
  untouched).
- frontend (main): e2ee.ts seam + E2eePlugin.kt + capacitor.config.ts
  comment + CSP injection (script + build:android wiring) + regenerated
  `uniffi/acutest_e2ee/acutest_e2ee.kt` **and rebuilt jniLibs, atomically**
  [audit MED-3]: a regenerated `.kt` against a stale `.so` fails uniffi's
  library-wide checksum verification at runtime — every E2EE call on such
  an APK throws, including slices 1–5.5, invisible to `assembleDebug`.
  Either both land in this commit or both defer to 6.7b; never split.
- stoatchat (acutest): this doc.
- `media_e2ee_enabled` untouched (FALSE).

## 8. Q2 probe snippet (run via CDP against the app WebView)

Scope note [audit MED-4]: a THROWAWAY debug APK for probing is IN scope
(release/integration APK stays 6.7b). The 6.7a outcome is a **provisional
GO on P1/P3**; P2 (worker construction in-app) is a named, BLOCKING
precondition of the 6.7b gate. P3 runs in the page context as a proxy for
the worker property (secure-context WebCrypto inheritance makes the delta
low-risk; 6.7b's in-app leg is the real measurement). The probe also
records `location.origin`, with a STOP condition if it is not the bundled
Capacitor origin (`https://localhost`) — master-plan Q2's own
origin-confirmation item; the stale "remote (`app.sloga.gg`) WebView"
comment in `E2eePlugin.kt` is corrected in this slice.

```js
(async () => {
  const out = { ua: navigator.userAgent, origin: location.origin };
  out.p1_createEncodedStreams =
    typeof RTCRtpSender !== "undefined" &&
    !!RTCRtpSender.prototype.createEncodedStreams;
  out.p1_scriptTransform = typeof RTCRtpScriptTransform !== "undefined";
  try {
    const mat = await crypto.subtle.importKey(
      "raw", new Uint8Array(32), "HKDF", false, ["deriveBits", "deriveKey"]);
    await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(8), info: new Uint8Array(8) },
      mat, { name: "AES-GCM", length: 128 }, false, ["encrypt", "decrypt"]);
    out.p3_hkdf = true;
  } catch (e) { out.p3_hkdf = String(e); }
  // P2 (worker asset) is observed in-app: with the seam landed, joining any
  // call logs worker-construction success/failure via the existing 6.3
  // graceful-degrade path (state.tsx catch → onErr). For the standalone
  // probe: new Worker on a same-origin blob is NOT representative; rely on
  // the in-app check.
  return JSON.stringify(out);
})();
```

Provisional GO = (p1_createEncodedStreams || p1_scriptTransform) &&
p3_hkdf === true && origin === "https://localhost". Record the WebView
version. Full GO additionally needs the 6.7b in-app worker-construction
leg (P2) to not degrade.

## 9. Audit log

### Plan audit (2026-07-13, e2ee-crypto-reviewer, boundary-parity lens)

**Verdict: APPROVE-WITH-FIXES** — surface mapping 1:1; trust-load-bearing
decisions (dialog-only arming, core-enforced announce gate, event payload
discipline) confirmed correct desktop analogs. 8 findings, ALL FOLDED into
this doc before implementation:

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | MED | Android main document had NO CSP next to the frame-key egress (§7.2 bundle+CSP control only half-present) | PARTIALLY FOLDED → **deferred to 6.7b (on-device)**: §5 revised. Shipping an unvalidated CSP into the SHARED build:android would white-screen ordinary builds (hCaptcha/Stripe/Sentry load remote script) — the MED-3 hazard. Load-bearing half (bundled dist, no remote webview) already holds; CSP authored+validated on device at 6.7b, tracked as a BLOCKING 6.7b gate item. Interim = desktop's own pre-6.2b posture, gated behind flag FALSE + no 6.7a APK |
| 2 | MED | Kotlin emit re-parses core serde JSON — compile-unchecked; drift silently kills Android rotation; Remove-won skip = invariant-7 erosion (≤10 min heartbeat bound) | FOLDED §3.2 (honest failure mode) + §6 (extraction-contract tests) + core struct comments |
| 3 | MED | ".kt now, .so later" option = compiles-green, breaks-on-device (uniffi library-wide checksum) | FOLDED §7: atomic or defer both — option removed |
| 4 | MED | Probe omitted origin confirmation; P2 deferral mislabeled as GO; P3 context mismatch; APK scope contradiction | FOLDED §8: origin + STOP condition, provisional-GO labeling, P3 proxy note, throwaway debug APK in scope, stale plugin comment fixed |
| 5 | LOW | sfuParticipants/displayNames must be REQUIRED (no slice-5 empty-default idiom) | FOLDED §3.1 |
| 6 | LOW | Pin snake_case event payload against camelCase "normalization" | FOLDED §3.2 + §4 (literal type) |
| 7 | LOW | loggingBehavior/webContentsDebuggingEnabled now §7.2-load-bearing (frame keys in resolve payloads) | FOLDED §5 + config comment update |
| 8 | LOW | mark_downgrade_confirmed export needs the wipe-style doc comment | FOLDED §2 table |

Q1 (Kotlin-layer emit): acceptable analog — same trust class, same trigger
set, spoof-safe (fake event only re-pulls native truth). Q2 (uniffi export
containment): acceptable — @PluginMethod is the only webview reach; core
MlsNotConfirmed backstops even an arming bug. Q3 (key-push flip): no
permanent first-key window — subscription awaited before session
construction; rests on the bundled-dist config line (comment demanded,
folded). Q4 (arg audit): no mismatches beyond the plan's own notes. Q5
(probe): adequate for provisional GO; slice-4 lift lesson does not bite
(no new FFI shapes — all param/return types already exercised on-device by
slices 1–5.5).

### Diff gate (2026-07-13, e2ee-crypto-reviewer, boundary-parity lens)

**Verdict: APPROVE-WITH-FIXES** — boundary parity 1:1 with desktop
`e2ee.rs:1189-1612`; all 20 uniffi methods present with correct signatures;
all 8 plan-audit findings confirmed folded; no CRITICAL/HIGH/MEDIUM. All four
trust properties verified against real code: (1) `mls_call_frame_keys` is the
SOLE secret-bearing egress (logging controls documented as required); (2) the
confirm-downgrade dialog computes non-enrolled NATIVELY (webview arg distorts
only DISPLAY); (3) `mls_call_mark_downgrade_confirmed` is unreachable from the
generic `call()` allowlist (only the dialog's confirm click); (4)
`mls_call_announce` stays core-confirm-gated (`MlsNotConfirmed` survives the
FFI, proven by a binding test). callKeysChanged emit correct
(process=conditional-on-kind, commit_won=unconditional, snake_case payload,
spoof/suppress-safe). keyPushAvailable creates no new invariant-1 first-key
window. Error scrubbing clean. MED-1 CSP deferral to 6.7b: **reviewer AGREES**
(interim exposure nil — flag FALSE ⇒ no MLS groups ⇒ no frame-key material;
no 6.7a APK), with the condition that the 6.7b gate MUST author + on-device-
validate the CSP before any `media_e2ee_enabled=TRUE` APK ships.

Findings — 2 LOW folded, 2 informational:

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | LOW | `requireLong` coerced a present-but-non-numeric `wonEpoch` to 0 (desktop rejects) | FOLDED: `requireLong` now type-checks JSON `Number` (rejects missing/null/non-numeric as invalid_argument) |
| 2 | LOW | `serverRemaining` truncated to 32-bit + sign-wrapped via `getInt().toULong()` (both the new MLS arm AND pre-existing `e2ee_replenish`) | FOLDED: new `requireCount` helper (full-width, rejects negative); applied to BOTH replenish arms |
| 3 | INFO | `emitFromOutcome` doc overstated "skips" — a missing `epoch` DEFAULTS to 0, not skip (benign) | FOLDED: comment tightened |
| 4 | INFO | `MlsFrameKey`/`MlsFrameKeys` derive `Debug` (pre-existing 6.2/6.3 core, out of 6.7a scope; nothing `{:?}`-prints them) | TRACKED as a 6.7b hardening follow-up (drop `Debug`); already covered by the 6.6 scrub-sweep structural check |

Re-verified after fold: `gradle :app:compileDebugKotlin` BUILD SUCCESSFUL;
host binding tests unchanged (Rust untouched by the fold). No CRIT/HIGH/MED
survive.

### Verification summary (deterministic)

- Rust host binding tests: **25/25** green (`cargo test -p acutest-e2ee-android`;
  was 18 pre-6.7a, +7 MLS tests).
- `acutest-e2ee-core` builds clean (doc-comment-only change).
- uniffi bindgen regenerated valid Kotlin (20 new methods, `wonEpoch: Long`,
  `sfuParticipants: List<String>`); doc-comment gotcha avoided.
- `cargo-ndk` built `libacutest_e2ee.so` for arm64-v8a / armeabi-v7a / x86_64.
- `gradle :app:compileDebugKotlin` BUILD SUCCESSFUL (the plugin + generated
  bindings compile).
- `tsc`: 9-error pre-existing baseline unchanged; edited FE files contribute 0.

### Q2 probe result (2026-07-13, Retroid Pocket 5, Android 13, WebView 109)

**PROVISIONAL GO.** Run via CDP (`adb forward` → `Runtime.evaluate`) against
the installed debuggable build's live WebView:

```json
{ "origin": "https://localhost", "webview_version": "109",
  "p1_createEncodedStreams": true, "p1_scriptTransform": false,
  "p3_hkdf": true, "provisional_go": true }
```

- Origin = the bundled Capacitor origin (the MED-4 stop condition PASSES;
  master-plan Q2's origin-confirmation item closed).
- P1: `RTCRtpSender.createEncodedStreams` present — the exact Chromium path
  livekit-client 2.15.13 uses. P3: HKDF import + AES-GCM-128 `deriveKey` OK.
- Field-floor note: WebView 109 is the OLDEST device in the fleet (the
  slice-4 polyfill device) and it passes — the support floor is comfortably
  below the field.
- P2 (worker construction in-app) remains the named BLOCKING 6.7b gate leg
  (needs an APK carrying the 6.7a seam).

**Same-session follow-through (2026-07-13, same device): the platform
question is closed end-to-end.**

1. **On-device load smoke (the slice-4 LESSON leg) — PASS.** Debug APK
   carrying the 6.7a bindings built (`build:android` → `assembleDebug`) and
   installed **in place** (`adb install -r`, signature-matched — the
   provisioned E2EE store was PRESERVED; never uninstall this device). Clean
   launch: no FATAL, no "Can't lift flat errors", no UnsatisfiedLinkError, no
   checksum failure in logcat. Real uniffi roundtrips via CDP through the NEW
   `.so` + regenerated `.kt`:
   - `e2ee_is_provisioned` → `true` (bindings init = **library-wide uniffi
     checksum PASSED on device** — the MED-3 atomic-commit contract proven);
   - `e2ee_status` → `{enabled:true, published:true, device_id}` (store
     OPENED = a real Android Keystore protector unwrap through the new
     library);
   - NEW surface: `e2ee_call_frame_keys` (bogus group) → typed
     `mls_group_not_found`; `e2ee_call_verify_join_intent` (garbage) →
     `invalid_argument{field:"request"}` — the 6.7a export block lifts/lowers
     and scrubs on device.
2. **P2-standalone — PASS.** The REAL emitted worker asset
   (`/assets/livekit-client.e2ee.worker-*.js`, present in the synced APK
   payload) fetches 200 `application/javascript` from the Capacitor asset
   server and constructs as a same-origin module worker in the real WebView
   (2s, no error event) — byte-for-byte what the Vite `?worker` wrapper does
   at Room construction. The Capacitor-asset-server worker-loading question
   (master-plan Q2's second half) is answered.

With P1 + P3 + origin + P2-standalone + the FFI-lift smoke all green on the
fleet's OLDEST WebView (109), Q2 is a **platform GO**. What 6.7b retains is
the INTEGRATED leg (worker via the in-app wrapper during a real E2EE call vs
a desktop peer, downgrade/rotation on device) — integration proof, no longer
a platform risk.

### Owed (on-device / 6.7b)

- ~~Q2 probe run on a physical device (§8)~~ — **DONE, PROVISIONAL GO** (above).
- Everything in §0 OUT: APK build, on-device call vs desktop peer,
  downgrade/rotation on device, Android adversarial re-runs, the main-document
  CSP (MED-1), and the media-e2ee + crypto dual gate for the integrated result.
