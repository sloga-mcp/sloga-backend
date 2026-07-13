# Media E2EE slice 6.7b — Android integration + APK + gate

Final sub-slice of the slice-6 master plan (`e2ee-media-mls-plan.md` §3.6, row
6.7b). 6.7a brought the Android shell to command parity (20 uniffi exports +
Kotlin plugin + native confirm dialog + frontend seam), gated APPROVE and
committed; Q2 was a PLATFORM GO on device. 6.7b is the on-device INTEGRATION
proof + the deferred main-document CSP (audit MED-1) + Android-scoped
adversarial re-runs + the final dual gate.

Device: Retroid Pocket 5 (adb `c07e0440`), Android 13, System WebView 109 —
the fleet's OLDEST WebView (slice-4 polyfill device). Peer: bundled Sloga
desktop (Tauri/WebView2), profiles `b` (JeffS) and `b2` (Android Tester), CDP
9223/9224. `media_e2ee_enabled` flipped ON in `Revolt.overrides.toml` for this
session ONLY (6.6 live-proof method) — reverts to FALSE at teardown.

## 0. Scope

IN: (1) main-document CSP for the Capacitor origin, injected `build:android`-
only, validated on device; (2) on-device E2EE call Android↔desktop (keys via
`callKeysChanged`, video both ways, in-app worker P2, loud downgrade + native
confirm dialog, T6 re-upgrade, epoch rotation); (3) Android-scoped adversarial
re-runs; (4) final media-e2ee + crypto dual gate.

OUT (unchanged): server, e2ee-core (crypto untouched), desktop.

## 1. Main-document CSP (audit MED-1, BLOCKING gate item — CLOSED)

**Author:** `packages/client/scripts/injectAndroidCsp.mjs`, wired as the
`capacitor:copy:after` npm hook (package.json) so EVERY `cap copy`/`cap sync`
(build:android included) injects the policy into
`android/app/src/main/assets/public/index.html` — never into `dist/` (the web
deploy stays unpoliced; desktop keeps its own tauri.conf CSP).

**Policy** (modeled on desktop 6.2b, Android deltas — see the script's header
for full provenance):

```
default-src 'none';
script-src 'self' 'wasm-unsafe-eval' https://hcaptcha.com https://*.hcaptcha.com https://js.stripe.com;
style-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com;
img-src 'self' data: blob: https://app.sloga.gg;
media-src 'self' blob: https://app.sloga.gg;
font-src 'self' data:;
connect-src 'self' blob: https://app.sloga.gg wss://app.sloga.gg https://translate.googleapis.com https://hcaptcha.com https://*.hcaptcha.com https://api.stripe.com;
worker-src 'self' blob:;
manifest-src 'self';
frame-src <hcaptcha/stripe> <youtube/twitch/spotify/soundcloud/bandcamp/lightspeed embeds>;
object-src 'none'; base-uri 'none'; form-action 'none'
```

Design decisions:
- `worker-src 'self' blob:` present (the required gate item — livekit e2ee
  worker + PWA SW ride 'self'; vendored blob workers ride blob:).
- `script-src` carries NO attacker-reachable origin — only 'self', wasm, and
  the FIXED hCaptcha/Stripe vendor hosts (both load remote script by design:
  login captcha / subscriptions). NO `'unsafe-inline'`.
- **Sentry ingest DELIBERATELY absent from `connect-src`** — a `*.ingest`
  allowance is a data-exfil channel for an XSS foothold sitting next to frame
  keys. If Sentry is enabled on Android, route it through `VITE_SENTRY_TUNNEL`
  (same-origin, already supported in `src/sentry.ts`) which rides `'self'`.
- Placement (load-bearing): the `<meta>` is inserted immediately after the
  literal `<head>`. Capacitor's JSInjector inserts its native-bridge inline
  `<script>` at `indexOf("<head>")+6` — i.e. BEFORE this meta — so the ONE
  inline script the meta-CSP can't police is installer-signed native content
  (same trust class as the shell). Everything after (app bundle, any
  DOM-injected XSS script, all runtime fetches) is policed. This is why no
  `'unsafe-inline'` is needed for the app.

**On-device validation (WebView 109, live):**
- App boots clean under the CSP (`document.readyState=complete`, root
  rendered, Capacitor bridge live, SW-served path carries the meta, len 866).
- POSITIVE (all pass): `translate.googleapis.com` fetch → "hello world";
  hCaptcha api.js loads + `newassets.hcaptcha.com` widget iframe renders;
  Stripe v3 loads + `js.stripe.com` controller frames; youtube-nocookie embed
  iframe loads; **livekit e2ee worker constructs same-origin ('self')**;
  3/3 `app.sloga.gg` avatars load.
- NEGATIVE (all blocked, with `securitypolicyviolation` events): arbitrary
  `example.com` fetch; `*.ingest.sentry.io` POST; DOM-injected inline script;
  external `example.com/x.js` script.
- Full cold boot: ZERO CSP violations for legitimate flows in logcat.
- Interim exposure before this landed: nil — the flag was FALSE and no 6.7a
  APK shipped, so no frame-key material ever existed next to the unpoliced
  document (the 6.7a diff-gate condition).

## 2. On-device E2EE call (integration proof)

All legs on the Retroid (WebView 109) vs a bundled desktop peer, "Encrypt my
calls" ON both devices, flag ON in staging:

| Leg | Result | Evidence |
|---|---|---|
| Keys flow via `callKeysChanged` → green | **PASS** | both peers reach `End-to-end encrypted` / `Encrypted · unverified` chip; native frame keys installed |
| Video decodes both ways | **PASS** | phone `<video>` 320×180 & 640×360 from desktop; desktop decodes phone — both directions |
| **P2 in-app worker construction (BLOCKING gate leg)** | **PASS** | `initializing worker` + `initialize encoded streams` + frames encrypt/decrypt during a real call (the in-app `?worker` wrapper, not the standalone probe) — Q2's last open leg closed |
| Loud downgrade (plaintext participant joins) | **PASS** | phone shows red banner "JeffS is not using encrypted calls. Your audio and video stay paused until you turn off encryption", chip `Not encrypted`, publishing paused |
| **Native confirm dialog on the phone** | **PASS** | tapping "Turn off encryption" shows the OS `AlertDialog` (greyed webview behind): title "Turn off call encryption", body names the NATIVE-computed non-enrolled set "JeffS (01KWFKG47HBFTEEN6XPPS8H3HN)", buttons CANCEL / TURN OFF |
| Confirm (TURN OFF) → announce | **PASS** | after TURN OFF, `POST /mls/groups/<id>/messages` (ctl-announce) fires — succeeds only because `mls_call_mark_downgrade_confirmed` armed the gate; mode → interlude, publishing resumes plaintext |
| Decline (BACK = cancel) → stay paused | **PASS** | after BACK the phone stays MIXED (red banner, chip `Not encrypted`, "Turn off encryption" retry button returns); NO announce fired; gate NOT armed |
| T6 re-upgrade | **PASS** | plaintext participant leaves → phone returns to green `End-to-end encrypted` (fresh successor group) |
| Epoch rotation on churn | **PASS** | store `last_epoch` advanced 0→7 across join/leave cycles; `MlsWelcome`/`MlsCommit` relays observed with monotonic epochs |

### 2a. Integration bug FOUND + FIXED on device (the value of the on-device leg)

**Symptom:** a mid-call joiner (desktop rejoining a phone-admitted group, or
either peer joining while the other already published encrypted frames) latched
the session terminally LOUD — chip stuck `Not encrypted` despite a successful
MLS join.

**Root cause:** a joiner connects to the SFU and receives the existing members'
already-encrypted frames BEFORE its Welcome resolves and its first key
installs. LiveKit raises missing-key `encryptionError`s — EXPECTED
join-in-progress noise — which the §4.4 debounce classified `loud` (outside any
rotation window). `#latchLoud` is by design not cleared by a later successful
join, so the chip wedged. Desktop↔desktop on one machine admits sub-second, so
the 6.4–6.6 desktop proofs never hit it; a real Android admitter takes seconds,
so it reproduced on every device join.

**Fix** (frontend only, no crypto touched):
- `classifyEncryptionError(inRotationWindow, awaitingFirstKey)` (moved to the
  unit-tested `mlsCallModePolicy.ts`): a missing-key error while
  `!#hasLocalKey` classifies `resecuring` instead of `loud`. BOUNDED by the
  SAME `RESECURE_ESCALATE_MS` escalation the caller already arms — a join that
  never completes still goes loud. The chip stays AMBER throughout (never green
  — chip gate (a) requires the first local key) and the publish gate holds (no
  plaintext escapes while re-securing).
- `state.tsx`: the `encryptionError` listener no longer directly latches
  `callEncryptionError`; latching happens ONLY via the session's
  `onEncryptionState("loud")` verdict (so the joiner-window softening actually
  takes effect). A session-less error can't latch — but session-less means the
  Room is torn down / never constructed, where the ME-7 chipState arm
  (`channelHasOpenGroup` + capable, no session → `not_encrypted`) already keeps
  an E2EE-known call loud.
- 4 new unit tests in `mlsCallModePolicy.test.ts` (36/36 green).

**Re-verified on device:** the formerly-wedged rejoin now converges to
encrypted within seconds; full downgrade/re-upgrade/epoch-rotation cycle passes
on the fixed build.

## 3. Android-scoped adversarial re-runs

The hostile-DS class (T-08/T-19/T-20, downgrade-DoS, caps) is platform-
independent core — unchanged by 6.7b, covered by the 6.6 harness + 25/25
binding tests. The Android-SHELL adversarial surface, verified ON DEVICE:

| Property | Result | Evidence |
|---|---|---|
| Webview cannot originate a downgrade announce | **PASS** | direct `plugin.call({__cmd:"e2ee_call_announce", …})` bypassing the dialog → `{"type":"mls_not_confirmed"}` scrubbed error; the core `MlsNotConfirmed` gate refuses across the FFI |
| Gate-arm command unreachable from generic allowlist | **PASS** | all 4 spellings of `*mark_downgrade_confirmed` via generic `call()` → rejected `invalid_argument{field:"name"}`; announce STILL `mls_not_confirmed` after |
| Frame-key egress discipline (audit LOW-7) | **PASS** | 4067 logcat lines during an active E2EE call: 0 `frame_key`, 0 `e2ee_call_frame_keys`, 0 plugin-data hits (loggingBehavior:"none" holds) |
| Native-computed non-enrolled set | **PASS** | the confirm dialog names the native-resolved "JeffS (user_id)" — a lying webview arg distorts DISPLAY only, never suppresses the dialog or the native set |
| Fail-closed joiner window | **PASS** | the §2a fix keeps the chip amber + publish gate held during the join window, never green/plaintext; bounded escalation to loud if the join never completes |
| SFU-coupling on rejoin (§2.7) | **OBSERVED** | when the phone's LiveKit transport dropped mid-churn, its MLS rejoin got `400 NotConnected` (voice-ingress refuses group ops without an SFU seat) — the coupling working, fail-closed |

## 4. Deliverables / commit plan

- frontend (main): `scripts/injectAndroidCsp.mjs` (new) + `package.json`
  (`capacitor:copy:after` hook) + `components/rtc/mlsCallModePolicy.ts`
  (`classifyEncryptionError` + `awaitingFirstKey`) +
  `components/rtc/mlsCallModePolicy.test.ts` (4 tests) +
  `components/rtc/mlsCallSession.ts` (import + `!#hasLocalKey` arg; inline
  classifier removed) + `components/rtc/state.tsx` (latch-via-session-verdict).
  The synced `android/.../assets/public/index.html` CSP + APK artifacts are
  build outputs (regenerated by build:android).
- stoatchat (acutest): this doc.
- `media_e2ee_enabled`: reverted to FALSE at teardown (staging-only flip).
- Constraint honored: NEVER `adb uninstall` (install -r, signature-matched,
  provisioned store preserved); .kt/.so untouched this slice (6.7a already
  landed them atomically — 6.7b is integration + CSP + a frontend fix, no
  bindgen).

## 5. Audit log

### Final dual gate (2026-07-13)

**e2ee-crypto-reviewer — APPROVE-WITH-FIXES.** Verified "no crypto/core/native
code changed" directly (e2ee-core/e2ee-android `.rs` untouched; `MlsNotConfirmed`
backstop intact). No confidentiality break — no plaintext egress, no false lock,
no downgrade-without-confirm. Findings:
- **MED-1 (`api.stripe.com` in connect-src = attacker-readable frame-key exfil
  sink)** — FIXED. Subscriptions are `hidden: true` on every platform (desktop
  6.2b CSP omits Stripe too), so all Stripe origins dropped from
  script-src/connect-src/frame-src. Rebuilt + re-validated on device: legit
  origins still load, `js.stripe.com` now blocked with a violation event.
- MED-2 (commit hygiene) — HANDLED: the 6.7b hunks were committed in isolation
  via filtered `git apply --cached`; the parallel voice-pipeline refactor in the
  shared tree was excluded (frontend `c85ab1dc`, exactly 6 files).
- LOW-3/4/5/6 (regression/adversarial tests, supply-chain residuals) — tracked.

**media-e2ee-reviewer — SHIP-WITH-FIXES.** CSP correct + enforced on WebView 109
(proper superset of desktop 6.2b; script-src carries no attacker origin;
`worker-src 'self' blob:` present; Sentry/connect-src reasoning denies a usable
exfil channel). Joiner-window fix is fail-closed (chip can't reach green,
publish gate holds, no plaintext-as-encrypted). Findings:
- **MEDIUM-1 (joiner-window escalation not reliably bounded)** — FIXED.
  `noteEncryptionRecovered()` cleared the escalation timer on ANY participant's
  `encrypted=true` (incl. a remote's, which does not witness OUR first key), so
  a joiner whose local key never installs could strand in amber. Fix:
  `noteEncryptionRecovered` early-returns while `!#hasLocalKey` (a remote's
  status can't clear the awaiting-first-key bound), and `#onLocalKeyInstalled`
  clears the timer on the genuine local recovery (so a successful join never
  false-latches loud). Fail-closed — the reviewer confirmed it does NOT block
  the staging flip.
- MEDIUM-2 (raw SFU on-wire ciphertext capture NOT-RUN) — carried 6.6 residual,
  not introduced by 6.7b; a production-flip precondition, not a 6.7b blocker.
- MEDIUM-3 (scope hygiene) — same as crypto MED-2, handled by the isolated commit.
- LOW-1..4 — Capacitor-anchor pinning, extra on-device flow spot-checks, the
  session-level escalation test, and a real-web-client cross-shell smoke; tracked.

### Verification summary

- Policy unit tests: **36/36** green (`node --test mlsCallModePolicy.test.ts`;
  +4 for `classifyEncryptionError`).
- `tsc`: pre-existing baseline unchanged; the 6.7b files contribute 0 errors.
- CSP re-validated on device after the MED-1 Stripe removal (cspLen 774): legit
  origins load, Stripe + all attack-shaped negatives blocked, 0 violations
  cold-boot.
- MEDIUM-1 fix: type-clean, policy-tests pass, reviewer-endorsed direction,
  fail-closed. The successful-join→green path was live-proven earlier this
  session on a build carrying these changes; the fix only makes the timer-clear
  MORE deterministic (local trigger) so it cannot regress that path. A fresh
  live re-verify was blocked by an UNRELATED parallel-session TDZ regression in
  the shared working tree (`voiceAudioPipeline.ts` refactor — excluded from the
  6.7b commit), an environment issue, not a 6.7b code issue.

### Flag verdict

`media_e2ee_enabled` stays **FALSE** (committed default; the staging flip was
reverted at teardown). 6.7b closes the Android integration + the MED-1 CSP gate
item. Remaining **production-flip** preconditions (unchanged, cross-slice):
raw SFU-node ciphertext capture (§3.6 / media MED-2), a real web-client
cross-shell smoke (media LOW-4), plus the standing operator debts. 6.7b is
committed (not pushed): frontend/main `c85ab1dc`, stoatchat/acutest (this doc).

### Commit plan (executed)

- frontend (main) `c85ab1dc`: the 6 files in §4, isolated via filtered
  `git apply --cached` (the shared tree's parallel voice-pipeline refactor left
  uncommitted for its own session/review).
- The synced `android/.../index.html` CSP is gitignored (a build artifact the
  hook regenerates) — the injector + hook are the committed source of truth.
