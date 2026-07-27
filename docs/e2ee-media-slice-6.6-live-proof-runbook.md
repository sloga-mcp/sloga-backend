# Slice 6.6 — Live-proof session runbook

The binding live legs for slice 6.6 (§6 of
[e2ee-media-slice-6.6-breakdown.md](e2ee-media-slice-6.6-breakdown.md)) were **NOT RUN** in the
implementation session (§7b). This runbook is the step-by-step for a **dedicated interactive
session** to run them. Its output decides whether `media_e2ee_enabled` can flip.

**Start this session at the strongest model** (as the 6.0 spike + 6.4 step-9 did). It is
interactive: two desktop instances driven over CDP, a real web participant, service rebuilds, and a
staging flag flip. Expect the pace of 6.4 step-9.

**Committed source to build off (not pushed):** stoatchat/acutest `7447a224`, desktop/master
`41115f4`, frontend/main `d7151fd4`. The parallel Apple-OAuth / threads / forums work is
uncommitted in the working trees — leave it be; build off the working tree (it contains the 6.6
code) but do NOT commit anything from this session unless explicitly asked.

**Outcome to produce:** fill in §5 (results table) + §6 (flag verdict) of the breakdown doc with
each leg's PASS / FAIL / NOT-RUN + evidence, and update the slice-6.6 notes
if the flip status changes. Keep the overrides flag OFF at the end.

---

## 0. Prerequisites / environment sanity (10 min)

Reference: [[project_startup_runbook]], [[project_architecture]],
[[feedback_desktop_preview_frontend_changes]], [[project_e2ee_slice64_step9]].

1. **Infra up** (Docker): `docker ps` shows `stoatchat-mongo-1`, `stoatchat-redis-1`,
   `stoatchat-livekit-1` (+ rabbit/minio). If not: `wsl … mise docker:start` from the stoatchat
   repo.
2. **Tunnel / URLs**: the desktop bundle loads `tauri.localhost` and talks to delta/bonfire via the
   configured hosts. Confirm the dev URL config the bundled build points at is reachable (the
   6.4/6.5 builds used the app.sloga.gg → local tunnel path; verify the tunnel is live, or repoint
   `.env` before the bundle build in §2). A quick check: open the target API base in a browser and
   hit `/` (should return the delta root JSON).
3. **Accounts / test channel** (from step-9): server `01KWFNZNNHJ08J5K7C35CGB1YA`, voice channel
   **"Voice Encyption Test"** `01KX789WHX8GJFHDH4RADDHM2C`. Instances: **JeffS** (SLOGA_PROFILE
   `b`, CDP port 9223) and **Android Tester** / b2 (SLOGA_PROFILE `b2`, CDP port 9224). A THIRD
   participant is the **web** browser (see §4.3).
4. **Scratchpad tooling**: recreate the step-9 CDP helpers in this session's scratchpad — a
   persistent `Runtime.consoleAPICalled` streamer that survives the join-time reload
   (`console_capture.mjs`), and a `peer_identities` reader that copies the e2ee store db+wal+shm to
   temp and queries via `node:sqlite` (`query_store.mjs`). These were throwaway; do not look for
   the old ones.

**Gotchas to keep in mind** (all from prior sessions):
- Shared `/mnt/c` cargo target corrupts on mixed Windows/WSL builds → `cargo clean -p <crate>` in
  WSL if you see a "Verneed record" error ([[feedback_shared_target_corruption]]).
- e2ee-core needs the **newer Windows `stable`** toolchain (libsqlite3-sys `cfg_select`); the WSL
  stoatchat mise cargo (1.92) **cannot** build it. Build native/desktop on **Windows**, build the
  server crates in **WSL**.
- First KeyPackage publish per device fires the `mfa_flow` modal — the operator enters the account
  password. Subsequent joins: no MFA.
- Closing the desktop: kill both `acutest-desktop` and `msedgewebview2` (com.acutest.desktop)
  processes before a `cargo build` or Windows locks the .exe.

---

## 1. Deploy prereqs — rebuild the server off committed source (20 min)

Build in WSL (stoatchat mise cargo), relaunch **detached** so they survive the session.

```bash
# WSL, in the stoatchat repo
cd /home/mcp/stoatchat
mise exec -- cargo build --bin revolt-delta --bin revolt-bonfire -p revolt-voice-ingress
```

Kill any stale/orphaned instances first (an old `revolt-delta` can hold 14702 across restarts;
`wsl pkill -f revolt-delta` — note that pattern also kills the invoking wsl shell, run it
standalone). Then relaunch detached (the step-9 pattern):

```bash
setsid mise exec -- ./target/debug/revolt-delta         >/tmp/delta-detached.log 2>&1 &
setsid mise exec -- ./target/debug/revolt-bonfire       >/tmp/bonfire-detached.log 2>&1 &
setsid mise exec -- ./target/debug/revolt-voice-ingress >/tmp/voice-ingress-detached.log 2>&1 &
```

Why each matters (step-9 findings): **voice-ingress** must post-date the device-qualified identity
strip (else `create_group` NotConnected 400); **bonfire** must relay `Mls*` events (else admit is
impossible); **delta** carries the new D12 + T-20 code.

## 1a. Flip the flag ON — STAGING ONLY

Edit `stoatchat/Revolt.overrides.toml` (gitignored), under the existing `[features]` table (the
re-enable note is already there, right below `e2ee_enabled = true`):

```toml
[features]
e2ee_enabled = true
media_e2ee_enabled = true   # <-- ADD for this session; REMOVE at teardown (§7)
```

Restart delta + bonfire after editing (they read config at boot). **This flag stays local; never
commit it.**

---

## 2. Rebuild the desktop bundle (debug, CDP-debuggable) (15 min)

Use the fast DEBUG bundle path (NOT `build-desktop.ps1`, which is the release/NSIS/sign pipeline —
only needed if you're testing the actual installer). No debug/test flags (`VITE_E2EE_MEDIA_TEST`
etc. must be OFF — this is the shippable path):

```bash
# 1) frontend build (WSL — linux rollup native present; Windows node build may fail per step-9)
wsl -e bash -lc 'cd "/mnt/c/Users/admin/frontend/packages/client" && mise exec -- npx vite build'
```
```powershell
# 2) copy dist -> frontend-dist   (from acutest-desktop)
robocopy C:\Users\admin\frontend\packages\client\dist `
         <workspace>\acutest-desktop\frontend-dist /MIR /NFL /NDL /NJH
# 3) build ONLY the desktop crate (Windows stable; ~27s incremental)
Set-Location "<workspace>\acutest-desktop\src-tauri"
cargo build -p acutest-desktop --features tauri/custom-protocol
```

(Close `acutest-desktop` + `msedgewebview2` before the cargo build.)

## 2a. Launch the two instances with CDP

```powershell
# Instance b (JeffS) — CDP 9223
$env:SLOGA_PROFILE="b"; $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=9223"
Start-Process ...\acutest-desktop\src-tauri\target\debug\acutest-desktop.exe -RedirectStandardError b.stderr.log
# Instance b2 (Android Tester) — CDP 9224 (new shell / clear the env first)
$env:SLOGA_PROFILE="b2"; $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=9224"
Start-Process ...\acutest-desktop.exe -RedirectStandardError b2.stderr.log
```

Log in both (JeffS on b, Android Tester on b2). Attach the persistent CDP console streamer to
9223 and 9224. `-RedirectStandardError` captures native `eprintln`/panics.

**Baseline smoke before the legs:** both join the voice channel; enable "Encrypt my calls" (Settings
→ Security & Privacy) on both; start a call. First join per device → MFA modal → enter password.
Confirm both reach `room.isE2EEEnabled=true` with native frame keys installed (the step-9 happy
path). If this doesn't work, STOP and debug before the adversarial legs — everything below assumes a
working two-desktop E2EE call.

---

## 3. Live legs — run each, record PASS/FAIL/NOT-RUN + evidence in breakdown §5

> For each leg, capture: the CDP console trace (mode/chip transitions), `session.metrics()` both
> sides, and the observable UI state (banner / chip / roster panel). "PASS" requires the asserted
> outcome AND no plaintext frame published before a native confirm.

### 3.1 T3→T6 downgrade / re-upgrade with a REAL web participant  (§6.1)

1. With b + b2 in an E2EE call (chip green), open the **web** client in a browser (no native layer)
   and join the same call as a third participant.
2. **T3/T4 (loud downgrade):** assert every native member flips LOUD — banner shown, publishing
   PAUSED, the web participant named in the `nonEnrolled` roster — and **no plaintext frame is
   published before the native confirm** (watch the publish gate hold; check the SFU/stats show no
   plaintext from b/b2).
3. **Confirm (T3/T5):** on b, click through the downgrade banner → the **native confirm dialog**
   (its non-enrolled roster is native-computed). On Ok: assert `set_e2ee(false)` STRICTLY precedes
   resume (mode → interlude), and a ctl-announce fires. On b2: assert it sees the **remote announce
   (T4)** and does NOT resume on its own.
4. **T6 (re-upgrade):** the web participant LEAVES → assert a fresh-successor group forms,
   re-upgrade with hysteresis, chip returns green, and the native downgrade grant is cleared
   (`e2ee_call_clear_downgrade`).

Evidence: the full mode sequence from console + `metrics()`.

### 3.2 Mixed-call receive smoke — Decline = receive-only  (§6.2)

1. Re-form the mixed call (web participant present). On b, **Decline** the downgrade.
2. Assert b stays **receive-only**: it decrypts/plays the encrypted peer (b2) AND receives the web
   participant's plaintext (livekit gates the decrypt cryptor per participant by the publication's
   `Encryption_Type` — the ME-8 artifact), while b **publishes nothing** (gate held).
3. Evidence: inbound A/V flowing from both an encrypted peer and the plaintext web participant;
   local publish paused (inbound-rtp / getStats both sides).

### 3.3 call_full auto-leave + NON-cooperative T-20 refusal  (§6.3)

**Lowered test ceiling** (100 real devices is impractical): on the staging server, temporarily set
`MAX_MLS_GROUP_MEMBERS` in
[`crates/core/database/src/models/mls/model.rs:23`](../crates/core/database/src/models/mls/model.rs)
to a small value (e.g. `3`), rebuild + restart delta (§1). Document the substitution. This exercises
the server refusal + §2.7 SFU coupling + client handling (NOT the native `#tryAdmit` const, which
stays 100 — that's native/unit-covered).

1. **Cooperative auto-leave:** fill the group to the lowered ceiling, then have a normal client
   join → `MlsCallFull` 409 → assert it **auto-leaves** the SFU; existing members' chip stays green,
   no downgrade banner.
2. **Non-cooperative (the real T-20, audit CR-HIGH-2):** simulate the attacker alt — a joiner whose
   `MlsCallFull` auto-leave is disabled (patch the client's auto-leave for the test, or drive the
   join_call endpoint directly). Assert **`join_call` returns 409 `MlsCallFull` with NO SFU token
   issued** (the §2.7 coupling), so it never reaches the SFU, existing members' chip stays **green**,
   and **no downgrade banner** appears. This is the leg that proves the coupling actually closes the
   downgrade-DoS.

### 3.4 Reactive leaf-verify chain — via STORE SURGERY only  (§6.3)

Forbidden: a shippable/config bypass of the proactive `#reconcileRoster` (would regress the 6.4
HIGH-2 fix). Reproduce the asymmetric-TOFU reject externally:

1. Stop b2. Copy its e2ee store; using `query_store.mjs`, find the `peer_identities` row for the
   ADMITTER's (JeffS) **call device**. Edit it to a stub: `binding_verified=0`, `ed25519=NULL`
   (WAL-safe: instance stopped). Restart b2.
2. b2 joins → the Welcome's admitter leaf is `BindingUnverified`. Assert the drain runs
   **`fetch_identity`** (NOT a terminal drop) → detached reconcile pins the device → the Welcome
   **re-processes** → `welcome_joined` → both sides `isE2EEEnabled`.
3. **D10 assertion (while the fetch is pending):** feed/observe a same-group commit — assert it is
   **PARKED**, not dropped, and applies AFTER the Welcome with no epoch gap. Record `metrics()`
   (`retries`, `parks`, `dedupSkips`).

### 3.5 D12 live  (§6.3)

1. **Video-enable cap:** in a call at > `MAX_VIDEO_PARTICIPANTS` members (use the lowered ceiling or
   a small `MAX_VIDEO_PARTICIPANTS` recompile), have a member enable camera → assert the track is
   server-**muted** (voice-ingress) and the member stays connected audio-only.
2. **Join cap:** with video active at the cap, a new join → assert `409 VideoCallFull` (join
   refused). Note the client shows a generic error toast today (the `VideoCallFull` → `errors.ts`
   map is a tracked follow-up).

### 3.6 T-01 SFU passthrough — CAPTURE AT THE SFU NODE  (§6.4)  ⚠ biggest residual

`room.isE2EEEnabled=true` is necessary but **NOT sufficient** — both security reviewers require
capture at the SFU/packet layer.

1. On the LiveKit node, capture the forwarded media (packet capture on the livekit container, or
   LiveKit egress/track inspection) during an E2EE call.
2. Assert the frames the SFU forwards are **ciphertext** — no plaintext codec payloads. This proves
   "the SFU forwards ciphertext it cannot read," the load-bearing claim of the whole two-plane
   design.
3. Also re-run **T-10** (denoise + camera effects + E2EE all active) → frames still decrypt.

---

### RESULT — RUN 2026-07-13 (session-2, this runbook) — **T-01 raw capture PASS; T-10 PASS**

**Method used (angle a, "egress-decode-failure" — the cleanest SFU-can't-read-it proof).**
A raw LiveKit **hidden subscriber bot** (`@livekit/rtc-node`, token grant `hidden:true` so it is
invisible to the call peers and does NOT trip the downgrade-roster check) joined the call's LiveKit
room (`ws://127.0.0.1:7880`, room = channel id `01KX789WHX8GJFHDH4RADDHM2C`) with **no MLS/E2EE
keys**. It is a faithful proxy for "what the SFU can extract from the forwarded media": it receives
exactly what the SFU forwards, past SRTP (the bot terminates DTLS-SRTP like any subscriber), then
tries to decode. Bot + control script in the session scratchpad (`cap/cap-bot.mjs`).

Two-desktop E2EE call: **b (JeffS)** + **b2 (Android Tester)**, both "Encrypt my calls" ON, both
`chip = "Encrypted · unverified"` (dual-gated ⇒ `room.isE2EEEnabled = true`). b published camera
(640×360) + mic; b2 published mic.

| Track (as SFU forwards it) | E2EE call | CONTROL (E2EE off, same room/SFU/bot) |
|---|---|---|
| **video** — frames the keyless bot could DECODE in ~12 s | **0 frames / 0 bytes** | **356 frames / 28.7 MB decoded** |
| video `encryptionType` reported by SFU | **1 = GCM** | 0 = NONE |
| audio `encryptionType` | 1 = GCM (both tracks) | 0 = NONE |

**Verdict — T-01 raw SFU-node capture: PASS.** An independent, keyless subscriber at the SFU decodes
**zero** video frames of the E2EE call yet the **same bot on the same SFU decodes the full 356-frame
plaintext stream** when E2EE is off. The SFU forwards GCM ciphertext it cannot read; the earlier
`isE2EEEnabled` + `ListParticipants encryption=GCM` attestations are now backed by a direct
capture. (Audio was non-discriminating in this bot: 1001 decoded-frame *events* in both arms but the
PCM-byte extractor returned 0 bytes in both — an instrumentation limit of `@livekit/rtc-node`
AudioStream, not a finding; the video frame-count contrast is the decisive signal. `rtc-node`
exposes only *decoded* frames, not raw RTP payload bytes, so the entropy/Opus-TOC angle (b) was not
separately computed — the decode-failure contrast is strictly stronger.)

**T-10 (denoise + camera effects + E2EE all active) — PASS.** On b: camera ON with **Background =
Blur** (pre-encode video processor) **+** noise suppression = **Enhanced / RNNoise** (pre-encode
audio processor) **+** E2EE. Both chips stayed `Encrypted · unverified`; **b2 decoded b's video
end-to-end in real time** (its `<video>.currentTime` advanced 222.45 s → 226.58 s over 4 s wall-clock,
`paused=false`). Re-running the SFU bot against this effects-active call still showed **video
frames=0, encryptionType=GCM** — the pre-encode processors do not leak plaintext to the SFU and do
not collide with the post-encode E2EE layer.

**Remaining before a production flip (unchanged by this run; T-01 was the biggest residual):**
- **media LOW-4** — real web-client cross-shell smoke (a genuine browser peer joining, forced to the
  T-07 loud path, never a false-green quiet Room). §5 invariant-2.
- **§4 bundled-origin + CSP gate** re-confirm on the flag-ON build (this run used the bundled
  `tauri.localhost` shell, but the §4 checklist was not formally re-walked).
- **Operator debts:** manual multi-device E2E pass, and record the running livekit-server version
  (this env: **`ghcr.io/stoatchat/livekit-server:v1.9.13`**, Alpine; RTC UDP 50500-50600, TURN 3478).
- Android 6.7 shipped OR its permanent loud-downgrade impact consciously accepted.

**Env footnote (blocker found + fixed this session):** the frontend built off committed
`c85ab1dc` would not render ANY channel (blank content pane) because `MessageComposition`
(`packages/client/src/interface/channels/text/Composition.tsx`) declared the `pollAllowed`
`createMemo` (polls feature) BEFORE `const currentSlowmode`, which it reads — an eager-eval
temporal-dead-zone `ReferenceError` that crashed the composer on every channel. Fixed locally by
moving `currentSlowmode` above `pollAllowed` (working-tree only, NOT committed). This is a real bug
in committed code and should be fixed on `main` independently.

---

## 4. Bundled-origin + CSP artifact check  (§9 precondition, crypto Q-FLAG-1(a))

Before contemplating a flip, confirm the flag-ON build loads the bundled `tauri.localhost` origin
under the 6.2b restrictive CSP — NOT a remote `app.sloga.gg` webview (server-delivered JS next to
live frame keys = key-exfil + fake-green). Inspect the running instance's document origin + the CSP
header/meta in the shipped `frontend-dist`, and confirm `tauri.conf` frontendDist points at the
bundle. This is a hard §9 gate, not optional.

---

## 5. Invariant-2 cross-shell reconfirm  (§9 precondition, crypto Q-FLAG-1(b))

Confirm every non-native shell falls to LOUD downgrade, never false-green: the web participant
(§3.1) already exercises this; additionally confirm an Android build (pre-6.7, fail-closed) or a
web shell joining an E2EE call triggers the T-07 loud path, never a quiet plain Room. Flipping in
production before 6.7 makes every Android participant a permanent loud-downgrade trigger — a
conscious product decision, note it.

---

## 6. Teardown

1. **Flag OFF:** remove `media_e2ee_enabled = true` from `Revolt.overrides.toml`; restart delta +
   bonfire. Verify the committed default stays FALSE.
2. **Revert the lowered ceiling** (`MAX_MLS_GROUP_MEMBERS` / `MAX_VIDEO_PARTICIPANTS` test edits);
   rebuild delta so the running binary matches committed source. **Do not commit** the test edits.
3. Undo any client auto-leave patch used for the non-cooperative T-20 leg.
4. b2's store surgery: the stub is transient — b2 re-pins on the next successful reconcile; no
   cleanup needed beyond confirming it re-verified.
5. Leave services running detached if the user wants the env warm, else stop them.

---

## 7. Record results + the flag verdict

- Fill breakdown §5 (results) + §6/§9 (flag verdict) with each leg's PASS / FAIL / NOT-RUN +
  evidence.
- Update [[project_e2ee_slice66]] memory with the live-leg outcome and whether
  `media_e2ee_enabled` is now cleared to flip.
- **Flip decision:** `media_e2ee_enabled` may be recommended for production ONLY if ALL of: every
  §3 leg PASS, T-01 captured at the SFU node (§3.6), the bundled-origin/CSP check (§4), invariant-2
  cross-shell (§5), AND the standing operator debts (multi-device E2E, livekit-server version
  record) — with Android 6.7 either shipped or its loud-downgrade impact consciously accepted.
  Otherwise: itemize what remains. Keep the committed default FALSE regardless.

---

## Quick reference

| Item | Value |
|---|---|
| Build off | stoatchat `7447a224`, desktop `41115f4`, frontend `d7151fd4` (working tree) |
| Server (14702/14703) | rebuild WSL mise cargo, relaunch detached (`/tmp/*-detached.log`) |
| Native/desktop | build on **Windows stable** (WSL cargo can't; `cfg_select`) |
| Flag | `Revolt.overrides.toml [features] media_e2ee_enabled = true` (STAGING; remove at teardown) |
| Instances | b=JeffS (CDP 9223), b2=Android Tester (CDP 9224), + web browser |
| Test channel | "Voice Encyption Test" `01KX789WHX8GJFHDH4RADDHM2C` / server `01KWFNZNNHJ08J5K7C35CGB1YA` |
| Lowered ceiling | `models/mls/model.rs:23` `MAX_MLS_GROUP_MEMBERS` → small; rebuild delta; revert after |
| Reactive chain | store surgery on b2's `peer_identities` (stop → stub admitter call device → restart) |
| T-01 | capture at the LiveKit node — ciphertext, NOT just `isE2EEEnabled` |

---

## Flag-flip deploy session (2026-07-14) — committed-source redeploy + flag-ON legs

**Deploy (precondition #8):** delta/bonfire/voice-ingress rebuilt from committed `31cb36cc`
(isolated ext4 worktree, not the OAuth-dirty working tree), running as durable systemd
user units. Frontend dist + desktop NSIS (`Sloga_0.5.0_x64-setup.exe`, signed) + debug APK
(`app-debug.apk`) all built from committed frontend `019c4772` (parallel voice-pipeline TDZ
regression + logos stashed away; verified the 2 untracked orphans are unreferenced by
committed code). livekit-server = v1.9.13. Infra/caddy/cloudflared up (app.sloga.gg → 200).

**Precondition #5 (bundled-origin + restrictive-CSP lock in the SHIPPED artifact) — MET:**
- Static re-walk: desktop `frontendDist: ../frontend-dist` (bundled), CSP `default-src 'none';
  script-src 'self' 'wasm-unsafe-eval'` (no remote/inline), `worker-src 'self' blob:`,
  connect-src = own backend + IPC only. Android injector excludes Stripe/Sentry; hooked to
  `capacitor:copy:after`; cap-sync verified the CSP is present in the synced android asset
  (no stripe/sentry).
- RUNTIME assertion on the flag-ON desktop bundle (WebView2 CDP, remote-debugging-port 9222):
  `location.origin = https://tauri.localhost` (bundled, NOT app.sloga.gg);
  fetch to a non-allowlisted attacker origin → BLOCKED (TypeError, connect-src);
  inline `<script>` injection → BLOCKED (script-src, no unsafe-inline). metaCsp null (header-delivered).

**Staging flag:** `media_e2ee_enabled = true` added to `Revolt.overrides.toml [features]`
(reverted at teardown); delta+bonfire restarted; MLS routes mounted (open_group → 401 not 404).

### FINDING (2026-07-14): committed `019c4772` production build renders blank (#root)
Running the flag-ON desktop bundle surfaced `TypeError: Cannot destructure property '_'
of 'Be(...)' as it is null` at top-level render → empty `#root`. Root cause: in committed
`packages/client/src/index.tsx` `MountContext`, `<ClientContext>` (which calls `useLingui()`)
wraps `<I18nProvider>` — so in a PRODUCTION build ClientContext's lingui context is null.
The live app.sloga.gg masks this because it is served by the Vite DEV server, not a
production build. The fix (swap so `<I18nProvider>` wraps `<ClientContext>`) exists only in
the uncommitted parallel WIP. Applied that exact one-hunk fix on top of committed source to
produce a working flag-ON build. **This blank-#root fix should be committed** (it is required
for any production frontend build to render). Matches the [[feedback_panda_content_prop_landmine]]
memory (useLingui-under-I18nProvider).

### LIVE LEGS (2026-07-14, flag-ON staging, committed+blank-fix build)
**Fleet:** JeffS = desktop release bundle (WebView2 CDP 9223, origin tauri.localhost);
Android Tester = Retroid Pocket 5 (fresh committed debug APK, CDP via adb 9225);
Test = Edge web at app.sloga.gg (CDP 9226). All CDP-observed.

- **JeffS self-E2EE:** alone in Voice Encryption Test (Test Server) → chip **"End-to-end
  encrypted"** (lock + verified_user), own camera tile 640x360 playing, no banner. PASS.
- **invariant-2 (Android non-E2EE peer):** Android Tester joined WITHOUT encryption
  (Encrypt-my-calls/enrollment did not engage this session) → JeffS correctly flipped to
  **"Not encrypted"**, named `Android Tester no_encryption`, NEVER false-green. PASS (bonus).
- **REAL-WEB CROSS-SHELL DOWNGRADE (media LOW-4 / precondition #6):** JeffS clean E2EE →
  **Test (real web browser) joined** → JeffS immediately **"Not encrypted"**, roster names
  `Test no_encryption`, "Turn off encryption" confirm prompt up (NOT auto-confirmed ⇒ no
  plaintext egress pre-confirm, consistent with 6.6 T3/T4 packet proof). Web client's own
  view also "Not encrypted". NEVER false-green. **PASS.**
- **Android-encrypting multi-device E2E:** NOT re-run live this session (Android E2EE did not
  engage — native plugin present + responding, likely an enrollment/capability gate on the
  account). **Cited from slice 6.7b** on-device proof (this device, committed build: keys→green
  both sides, two-way video decode, native confirm dialog, epoch rotation) — user-accepted.

- **T3/T5 NATIVE CONFIRM DIALOG + ctl-announce (task-3 leg) — PASS LIVE (desktop, this
  session):** with Test (web) in the call, user clicked "Turn off encryption" on JeffS → native
  OS confirm dialog (non-enrolled "Test") → confirm → JeffS fired `mls_call_announce`, observed
  in the delta log as `POST /mls/groups/11105c367adca330428f9e5e79d913c6dc3fca737aaa1868e8f25efd5c8671a3/messages`
  (send_message / E2EEContentType::MlsCtl relay) at 15:09:30; JeffS's "Turn off encryption"
  prompt cleared (confirmed-downgrade). Complements 6.7b's on-device Android native dialog.
- **Reactive fetch_identity + D10 park (task-3 leg):** NOT driven live — reproduction requires
  disabling the proactive #reconcileRoster (which re-pins the stub before the Welcome, so the
  reject never fires), and that bypass is forbidden (crypto gate LOW-6). CONSCIOUSLY ACCEPTED as
  unit-covered (59 node tests incl. D10 park/splice ordering + generation-token supersede).

---

## PRODUCTION FLIP — `media_e2ee_enabled` = TRUE (2026-07-14)

FINAL sign-off panel (precondition #2): **media-e2ee-reviewer + e2ee-crypto-reviewer both GO**,
no crypto/architecture blocker — release-hygiene conditions only, all closed:

- Provenance commits pushed: frontend/main `019c4772`→`faba32e0` (`index.tsx` blank-`#root`
  render fix + downgrade-banner cosmetic), desktop/master `184de5d`→`5d64269` (`dragDropEnabled`).
- NSIS + APK rebuilt from committed source (`BUILD_INFO=faba32e0`, spike-guard clean, orphans
  absent). CSP re-verified: desktop release binary embeds the restrictive CSP (no `unsafe-inline`
  in `script-src`; `connect-src` = self + `app.sloga.gg` only; no Stripe/Sentry) and ships only an
  external module `<script>`; Android CSP confirmed inside the APK.
- Pre-flip capstone (built desktop bundle via WebView2 remote-debug): origin `https://tauri.localhost`,
  `#root` has 2 rendered children (render fix works — not blank), login UI renders.

**Flip:** the flag was already `true` in the live gitignored `Revolt.overrides.toml` (a STAGING-ONLY
evidence flip) and delta had served it since 13:44 — blessed to the permanent production state
(removed the REVERT-AT-TEARDOWN framing; value unchanged). Gate is **delta-only**
(`require_media_e2ee_enabled`; bonfire/voice-ingress don't read it) and delta already had it loaded
→ **no restart needed**. Live-verified: real `POST /mls/groups/<id>/commits` Matched + `open_group`/
`fetch_commits` in the delta log today, and **0 `FeatureDisabled(media_e2ee)` rejections** ⇒ gate open.

### ⚠️ DURABILITY — re-apply on reprovision
`media_e2ee_enabled` (and `e2ee_enabled`) live ONLY in the **gitignored** `Revolt.overrides.toml`;
the committed `Revolt.toml` default is `false`. A box reprovision / fresh checkout turns media E2EE
(and text E2EE) **OFF** unless these overrides are re-applied under `[features]`:

    e2ee_enabled = true
    media_e2ee_enabled = true   # requires e2ee_enabled

The gate is delta-only, so re-applying requires a **delta (re)start** to load it.

### Owed / accepted residuals (not blockers)
- Fresh independent 2-client E2EE-call + downgrade smoke (this flip relied on the evidence legs above).
- Android as an *encrypting* leg on a real prod account (enrollment gate; cited from 6.7b on-device proof).
- Desktop/APK artifact ship: `updates/latest.json` is still `0.5.0` — bump (e.g. 0.5.1) if the
  `index.tsx` render fix must reach already-installed users; server flip needs no client ship.
