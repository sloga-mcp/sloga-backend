# Sub-slice 6.2b — Desktop shell bundling + restrictive CSP

Status: IMPLEMENTATION BREAKDOWN (authored before coding, per session charter)
Plan: `docs/e2ee-media-mls-plan.md` §8 row 6.2b, §7.1 Q3 (amendment A2), §7.2.
Hard precondition of 6.3 (frame-key egress). Independent of 6.1/6.2 (MLS work).

## 1. Why (threat model recap)

The desktop shell is currently a thin webview loading `https://app.sloga.gg`
live with `csp: null`, and the E2EE IPC surface was explicitly granted to that
remote origin (commit `acdbf5d`). That means server-delivered JS sits directly
on the IPC boundary. For text E2EE this was carried risk #1 (displayed
plaintext); media E2EE puts **live frame keys** next to that JS — a hostile or
swapped server bundle could exfiltrate every call's keys AND fake the green
lock. All three plan audits converged: resolve as work, not acceptance.

After 6.2b: the desktop executes only installer-shipped, updater-signed
frontend code; the server can no longer swap the JS under the desktop app.
The IPC capability is granted only to bundled (local) content.

## 2. Current state (recon, 2026-07-10)

- `tauri.conf.json`: `windows[0].url = https://app.sloga.gg`, `csp: null`,
  `frontendDist: ../src` (a placeholder page, never shipped as the app).
- `capabilities/default.json`: full E2EE command allowlist granted to
  `remote.urls = ["https://app.sloga.gg"]`. Debug builds additionally grant
  the same surface to `http://localhost:5174` at runtime (lib.rs, compiled out
  of release).
- Frontend (`C:\Users\admin\frontend`, packages/client): Vite + PWA plugin.
  `.env.production` (and `.env`) already use **absolute** URLs
  (`https://app.sloga.gg/api|/ws|/media|/proxy|/livekit`) — the Android
  Capacitor build already runs this bundle from a non-sloga origin, so
  cross-origin API/WS/media is proven (delta CORS = all origins; Autumn/January
  exercised by Android).
- Production "site" today is actually the Vite dev server proxied by Caddy —
  there is no production web build in service; the desktop bundle will be the
  first `vite build` consumer besides Android.
- Service worker registers unconditionally (`src/serviceWorkerInterface.ts`
  via `virtual:pwa-register`; plus a web-push registration path in
  `NotificationsController.ts`).
- `livekit-rnnoise-processor` defaults its worklet URL to **jsdelivr** when
  `VITE_RNNOISE_WORKLET_CDN_URL` is blank (plan §7.1 Q8 confirmed) — the new
  CSP would silently break noise suppression.
- Shell reads the window origin to fetch `{origin}/games.json` (lib.rs game
  detector) — breaks under a bundled origin.
- Encrypted attachments render from `https://e2ee-att.localhost/...`
  (custom-protocol origin on Windows) — must be CSP-allowed.
- Special embeds are `<iframe src={server-provided embedURL}>` (YouTube,
  Twitch, Spotify, Soundcloud, Bandcamp, Lightspeed) — need `frame-src`.
- Updater artifacts are static files under `stoatchat/updates/` served at
  `app.sloga.gg/updates/*` by Caddy.

## 3. Decisions

1. **Bundled origin = `https://tauri.localhost`** (Windows WebView2 with
   `useHttpsScheme: true`, unchanged). Secure context (crypto.subtle,
   getUserMedia, workers all available). Chosen once; changing the scheme
   later would change the origin again and re-trigger the logout cost below.
2. **One-time logout on update is accepted.** localforage session + client
   settings live under the `app.sloga.gg` origin and do not carry over to
   `tauri.localhost`. Native E2EE state (DPAPI store) is origin-independent;
   re-login on a provisioned device takes the existing `is_provisioned`
   restore path — no key loss, no re-enroll. Must be smoke-tested (task C).
3. **Dev workflow keeps the remote dev server.** `build.devUrl =
   http://localhost:5174` so `tauri dev` (and debug-build iteration) keeps
   Vite hot-reload; the debug-only runtime capability for localhost origins
   stays (compiled out of release). Release grants IPC **only** to bundled
   content.
4. **Service worker is not registered under Tauri.** The updater is the
   version authority for desktop; a SW adds a second, stale-prone cache layer
   and web-push is unused there (native notifications exist). Gate, don't
   delete — web/Android keep it.
5. **rnnoise worklet self-hosted** under `public/rnnoise/` and
   `VITE_RNNOISE_WORKLET_CDN_URL` pointed at it for BOTH web and desktop —
   fixes the standing Q8 no-CDN violation in passing (it becomes mandatory
   here: CSP would break it).
6. **MediaPipe segmentation assets stay bundled** (`public/mediapipe/` is in
   dist; `SEGMENTATION_ASSETS_URL` blank ⇒ `${BASE_URL}mediapipe` ⇒ 'self').
   Installer grows (~19 MB uncompressed wasm); acceptable, self-contained.
7. **games.json**: shell fetches `https://app.sloga.gg/games.json` explicitly
   (keeps the "update game list without desktop release" property; native
   reqwest fetch, not subject to CSP). Falls back to the compiled-in list.
8. **build.rs AppManifest permission generation stays** — the allow-*
   permissions are still what the capability grants, and the debug dev-origin
   capability still needs them. Only the *grant target* changes (local
   instead of remote).

## 4. Restrictive CSP (draft; final text validated by the re-probe + smoke)

```
default-src 'none';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' data: blob: https://app.sloga.gg https://e2ee-att.localhost;
media-src 'self' blob: https://app.sloga.gg https://e2ee-att.localhost;
font-src 'self' data:;
connect-src 'self' blob: https://app.sloga.gg wss://app.sloga.gg ipc: http://ipc.localhost https://ipc.localhost;
worker-src 'self' blob:;
frame-src https://www.youtube.com https://www.youtube-nocookie.com https://player.twitch.tv https://open.spotify.com https://w.soundcloud.com https://bandcamp.com https://new.lightspeed.tv;
object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

Rationale / notes:
- `script-src 'self' 'wasm-unsafe-eval'`: no inline scripts (Vite emits
  modules; Tauri nonces its own injected init scripts via the default
  asset-CSP modification). `'wasm-unsafe-eval'` is required for MediaPipe
  (and any future wasm) under a CSP that omits `'unsafe-eval'`.
- **No remote script source at all** — this is the trust-surface point.
- `worker-src 'self' blob:`: the LiveKit e2ee worker (6.3) is a Vite
  `?worker` self-hosted asset ('self'); `blob:` is a provisional allowance
  for track-processors/worklet internals — the re-probe decides whether it
  can be dropped.
- `connect-src`: API/WS/LiveKit-ws all ride `app.sloga.gg` (wss listed
  explicitly; don't rely on CSP3 https→wss equivalence). ipc origins are the
  Tauri invoke transport (same set the recovery window CSP uses).
- `img/media-src`: `e2ee-att.localhost` is the encrypted-attachment
  decrypt-and-serve protocol; `app.sloga.gg` covers Autumn/January;
  remote embed images ride January (`/proxy`) so no wildcard needed.
- `frame-src`: enumerated January special-embed providers. A blocked iframe
  fails visibly and safely; remote frames get no IPC (capability is
  local-only) — this is containment, not trust.
- WebRTC media itself (UDP/TURN) is not CSP-governed.

## 5. Work breakdown

**A. Frontend repo (packages/client) — desktop-bundle build mode**
1. Gate `registerSW` (serviceWorkerInterface.ts) and the
   NotificationsController web-push SW path behind "not Tauri".
2. Vendor `livekit-rnnoise-processor` worklet assets → `public/rnnoise/`;
   set `VITE_RNNOISE_WORKLET_CDN_URL=/rnnoise/` in `.env` +
   `.env.production` (verify the lib accepts a root-relative base).
3. `vite build` (WSL) and sanity-check dist (absolute URLs, mediapipe
   present, worker assets emitted).

**B. Desktop shell (acutest-desktop/src-tauri)**
1. `tauri.conf.json`: remove remote `url` (window loads bundled
   `index.html`); `frontendDist` → `../frontend-dist` (gitignored copy of the
   client dist); `devUrl` → `http://localhost:5174`; `csp` → §4 string.
2. `capabilities/default.json`: **delete the `remote` block** (grant becomes
   local-content-only), update the description; keep the permission list.
3. `lib.rs`: games.json fetch → explicit `https://app.sloga.gg`.
4. `build-desktop.ps1`: frontend build in WSL → copy dist →
   `frontend-dist/` → `tauri build` → separate `tauri signer sign
   --password ""` step (known hang gotcha).
5. `.gitignore`: `frontend-dist/`.

**C. Re-probe + smoke (6.0 must-carry #2)**
1. Debug bundled build with the 6.0 spike harness temporarily re-attached;
   two `SLOGA_PROFILE` instances + CDP (`--remote-debugging-port`), re-run
   P1+P2: `isE2EESupported`, `RTCRtpScriptTransform`, `createEncodedStreams`,
   module worker + `?worker` asset load, `BaseKeyProvider→onSetEncryptionKey`
   with HKDF key material — all under `https://tauri.localhost` + final CSP.
2. Smoke: login (fresh origin), text-E2EE IPC round-trip from the bundled
   origin (proves the re-locked capability), encrypted attachment render
   (e2ee-att under CSP), avatars/embeds/GIF picker, a voice call, SPA
   reload on a nested route (Tauri asset-resolver fallback), zero unexpected
   CSP violations in console.
3. Evidence recorded in §7 of this doc.

**D. Release build + pipeline doc**
- Signed 0.4.0 release; update flow documented (below) — NOT deployed to
  `updates/latest.json` until the gate passes.

**E. Gate** — e2ee-crypto-reviewer + frontend-code-reviewer (trust-surface
sign-off), findings folded.

## 6. Updater / asset-pipeline implications (plan §8 row asks these be worked out)

- **Frontend changes no longer reach the desktop automatically.** That is the
  point (the server losing the ability to change desktop code is the security
  property). New flow for shipping client changes to desktop:
  1. `vite build` the client (WSL) with production env,
  2. copy dist → `acutest-desktop/frontend-dist`,
  3. bump `version` in tauri.conf.json, `npx tauri build`,
  4. sign the installer separately (`tauri signer sign --password ""`),
  5. drop installer + `.sig` into `stoatchat/updates/` and update
     `latest.json` — clients update via the existing dialog.
  (`build-desktop.ps1` automates 1–4.)
- Web (`app.sloga.gg` in a browser) and Android pipelines are unchanged.
  Desktop can lag web; API compatibility is the same contract Android already
  relies on.
- Installer size grows by the client dist (~mediapipe wasm dominates); NSIS
  compresses; measured in task D.
- The updater endpoint/pubkey/signing are unchanged — the updater itself is
  the existing trusted channel, now covering the JS too.
- One-time logout for existing desktop users on the first bundled update
  (origin change, decision 2); release notes should say so.
- **Key custody (crypto gate finding #3).** After 6.2b the updater signing key
  (`C:\Users\admin\.sloga\sloga-updater.key`, currently EMPTY passphrase)
  authorizes *all desktop-executed JS*, not just the native binary — its
  compromise silently replaces every line that will sit next to live call
  frame keys from 6.3 on. It lives on the same host as the internet-reachable
  dev server. Owed hardening: passphrase-protect the key (the build hang is the
  empty-string *env var*, not passphrases — the explicit `--password` flag path
  works with a real passphrase) or move signing to an offline/DPAPI step. This
  is the single biggest residual risk of the slice.

## 7. Re-probe evidence (6.0 must-carry #2 — CLOSED 2026-07-10)

Method: probe-variant dist (`VITE_E2EE_SPIKE=1 vite build` — production build
with the 6.0 spike's CDP global force-enabled) copied to `frontend-dist`,
shell built as `cargo build -p acutest-desktop --features tauri/custom-protocol`
(debug profile ⇒ SLOGA_PROFILE isolation + dev capability still available,
`custom-protocol` ⇒ bundled assets + conf CSP served, devUrl ignored).
Instance: `SLOGA_PROFILE=b`, CDP via
`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9223`, driven
by scratchpad `cdp62b.mjs` (6.0 pattern, `Runtime.evaluate`).

Environment: real WebView2 `Edg/150`, `window.__TAURI__` present, page origin
**`https://tauri.localhost`** (bundled), final §4 CSP active (delivered as a
header — no meta tag — and observed enforcing).

| Probe | Result |
|---|---|
| `isE2EESupported()` | **true** |
| `RTCRtpScriptTransform` in window | **true** |
| `RTCRtpSender.createEncodedStreams` | **true** |
| `MediaStreamTrackProcessor` | **true** |
| P2 module worker (`livekit-client/e2ee-worker?worker` bundled asset) | **loaded, no error** (asset `livekit-client.e2ee.worker-*.js` emitted + served under CSP `worker-src 'self'`) |
| P3 HKDF key-MATERIAL importKey→deriveKey (exact LiveKit worker params) | **ok** |
| P3 negative: AES-GCM CryptoKey as HKDF material | **throws InvalidAccessError (expected)** |
| Service-worker registrations under Tauri | **0** (gating works) |
| IPC `greet` + `e2ee_status` from bundled origin | **works** — `e2ee_status` returned the provisioned profile-b device (capability re-lock to local context proven live) |
| CSP connect-src negative (`fetch https://example.com`) | **blocked** with exactly the §4 connect-src directive; the only violation recorded in the whole session |
| CSP connect-src positive (`https://app.sloga.gg`) | reachable (404 on `/api` is the no-trailing-slash artifact; `/api/` = 200) |
| SPA hard navigation to `/friends` (unknown asset path) | **index.html fallback served, app booted fully**, client router redirected to /login |

Bonus negative result: a navigation to a MALFORMED host under the tauri
protocol (`https://tauri.localhostc/...`, produced by a driver bug) still got
bundled content + CSP but was **DENIED all IPC** — the ACL matches the exact
local context only ("allowed on: URL: local" did not match). Defense-in-depth
confirmation that near-miss origins get no command surface.

**Conclusion: the 6.0 GO transfers to the bundled origin + restrictive CSP.**
The `[BLOCKER for 6.3]` re-probe condition is closed; 6.3 still owes the
connected-room `setE2EEEnabled(true)` exercise (6.0 must-carry #3).

Operator-owed smoke (needs credentials; same pattern as prior slices) — run
with the console open, expect ZERO CSP violations; any violation is a §4
allow-list gap to reconcile before deploying `latest.json`:
- log in on the bundled build (exercises the origin-migration path: existing
  native E2EE store + fresh webview origin → `is_provisioned` restore),
- one voice call **with enhanced denoise + a camera background effect active**
  — exercises the rnnoise worklet under `script-src 'self'` and confirms
  whether `worker-src blob:` is actually needed (gate finding #4): if no
  blob-worker violation appears, drop `blob:` from `worker-src`,
- one encrypted attachment render (e2ee-att under CSP), embeds, GIF picker,
- **emoji, both paths** (findings #6 + #9): open a channel with standard
  (unicode) emoji AND open the emoji picker — finding #9 predicts EVERY
  unicode emoji is a broken glyph from hardcoded `https://static.stoat.chat/
  emoji/…` (`UnicodeEmoji.tsx:70`), plus type a custom emoji in the composer
  (finding #6, `cdn.revoltusercontent.com`). Both are `img-src` blocks; fix by
  self-hosting / routing through configured media, NOT by widening CSP.
- **watch for a lone `manifest-src` boot violation** (finding #10) — harmless
  (Tauri window isn't an installable PWA) but strip it or add `manifest-src
  'self'` to keep the smoke clean,
- **confirm login does NOT require a captcha** (finding #11) — hCaptcha is
  unconfigured + not CSP-allowed; latent today.

## 8. Gate disposition (2026-07-11)

**e2ee-crypto-reviewer: SHIP-WITH-FIXES.** The load-bearing trust-surface
change is confirmed correct and the re-probe genuinely closes must-carry #2.
Reviewer-verified CLEAN: capability re-lock (local-only; dev-origins
capability is `#[cfg(debug_assertions)]`; recovery capability untouched), CSP
as an anti-injection control (no remote/inline/eval script source), updater
trust chain preserved, games.json origin fix, re-probe evidence. Findings and
disposition:

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | HIGH | Pipeline could sign/ship the throwaway spike; `SPIKE_MEDIA_E2EE` arming path is un-gated so it survives even a clean build (empirically: 3 hits in the 0.4.0 dist) | **FIXED — both halves.** Pipeline: `build-desktop.ps1` scans the *staged bytes* and hard-fails on `SPIKE_MEDIA_E2EE`/`__E2EE_SPIKE__`/`__e2ee_spike_report` (kept as a regression backstop). Spike: **fully removed 2026-07-11, frontend `258bc515`** (e2eeMediaSpike.ts deleted; state.tsx hunks + vite.config.ts sink dropped). Verified: fresh `vite build` dist has ZERO spike markers → the guard PASSES; 0.4.0 rebuild unblocked. |
| 2 | MED | Prod (= Vite dev server) exposes `window.__E2EE_SPIKE__`, the ARM chip, and an unauthenticated disk-writing report sink `/__e2ee_spike_report` on the signing-key host (confirmed live: GET → 405) | **FIXED.** First gated on `VITE_E2EE_SPIKE=1` (frontend `ed3fd429`, live after a `mise dev` restart), then the whole sink+global+chip were **deleted** with the spike (`258bc515`). |
| 3 | MED | Passwordless updater key now authorizes all desktop JS | **DOCUMENTED** (§6 key custody) as the slice's biggest residual; owed hardening. |
| 4 | LOW | `worker-src blob:` provisional, undecided | **OWED to smoke** (§7) — drop if clean. |
| 5 | LOW | No top-level navigation lock on the main window | **ACCEPTED residual.** Capability re-lock is the primary control (a navigated-away page gets zero IPC — §7 malformed-host negative proves it). A nav-allowlist needs moving the window from config to a Rust builder (`on_navigation`), risking exactly the origin regressions 6.2b exists to prevent; deferred to 6.3 where the window/Room wiring is touched anyway. |
| 6 | LOW | Composer emoji hardcodes `cdn.revoltusercontent.com` (violates `img-src`) | **OWED to smoke + frontend fix** (§7) — route through the configured media host; do NOT widen CSP. |
| 7 | LOW | SW/push desktop gate is a runtime `"__TAURI__" in window` sniff, coupled to `withGlobalTauri` | **NOTED.** Correct today (`withGlobalTauri: true`); if that's ever disabled, revisit with a build-time desktop define. |
| 8 | LOW | Vendored rnnoise wasm provenance was claim-only | **FIXED:** `public/rnnoise/PROVENANCE` records upstream URLs + SHA-256 of both files. |

**frontend-code-reviewer: SHIP-WITH-FIXES (2026-07-11), concurs with the
crypto disposition.** Confirmed CLEAN (traced end-to-end): rnnoise URL correct
across web/desktop/Android (the base-relative fallback is *safer* than the
plan's A2 "set the env var" — an absolute app.sloga.gg value would have broken
the worklet under desktop `script-src 'self'`); SW gating breaks nothing
(`pendingUpdate` stays undefined → Titlebar hides the web-update button; push
toggle fails into the snackbar; no offline/badge/share-target path depends on
the SW on desktop); no media-track lifecycle regression; **`worker-src blob:`
is genuinely droppable** — it verified MediaPipe does not spawn a blob worker
(`new Worker(` absent; camera background works without it). One NET-NEW
blocker + two LOWs:

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 9 | HIGH | **Unicode emoji** render from hardcoded `https://static.stoat.chat/emoji/…` (`UnicodeEmoji.tsx:70`) on the message-**render** path (messages, reactions, statuses, picker) — a SECOND external host, distinct from #6's composer-only `cdn.revoltusercontent.com`, and BROADER: every standard emoji is a broken glyph on desktop under `img-src`. | **FIXED, frontend `fd95b4d3` + Caddyfile.** Emoji + the #6 composer-custom pair now route through the app origin: `unicodeEmojiUrl` uses a configurable `DEFAULT_EMOJI_URL` (`VITE_EMOJI_URL=https://app.sloga.gg/emoji`), and a new Caddy `handle /emoji/*` proxies to the upstream pack host (stoatchat/Caddyfile) — so the client only ever requests emoji from `app.sloga.gg` (allowed by `img-src`), CDN-independent. Composer custom emoji now use `DEFAULT_MEDIA_URL` (Sloga Autumn) instead of Revolt's CDN. **Verified:** tunnel serves `/emoji/*` (200 SVG); an `<img>` from `app.sloga.gg/emoji` loads under the CSP at `https://tauri.localhost` with ZERO img-src violations; tsc clean. Full server-side vendoring (drop the upstream proxy) can follow with no client change. |
| 10 | LOW | Injected PWA `<link rel="manifest">` blocked (no `manifest-src` → `default-src 'none'`) — one boot-time violation, no functional break (Tauri window isn't an installable PWA) | **OWED to smoke** — strip the manifest link for the desktop build (preferred, keeps CSP minimal) or add `manifest-src 'self'`. |
| 11 | LOW | hCaptcha unconfigured + not CSP-allowed; the origin-change re-login (decision 2) would break twice if a captcha is ever server-required | **SMOKE PRECONDITION** — confirm captcha is not server-required on `app.sloga.gg` during the login smoke; decide self-host-vs-allowlist only if it's ever enabled. Latent today (empty sitekey). |

## 9. Blocking-for-6.3 handoff

- **Delete the 6.0 media spike — DONE** (frontend `258bc515`): e2eeMediaSpike.ts
  removed, state.tsx Room wiring restored to pre-spike form, vite.config.ts sink
  gone. 6.3 adds the real `MlsKeyProvider` (the parallel session's new
  `components/rtc/mlsCallKeys.ts`) in its place — no latent `localStorage`-armed
  path inherited.
- **must-carry #3:** exercise `setE2EEEnabled(true)` on a *connected* Room.
- **Emoji (findings #9 + #6): DONE** — routed through `app.sloga.gg/emoji`
  (Caddy proxy) + configurable `DEFAULT_EMOJI_URL`; composer custom emoji moved
  to Sloga Autumn. Optional follow-up: fully vendor the emoji SVGs to the
  server (drop the upstream proxy) — no client change needed. NOTE: the live
  WEB dev server keeps serving emoji from `static.stoat.chat` until the next
  `mise dev` restart picks up the new `.env` (harmless; the fallback keeps web
  working meanwhile). Desktop uses `.env.production`, baked at build.
- Reconcile the remaining operator-smoke CSP items (findings #4 drop-blob,
  #10 manifest, #11 captcha) before deploying `latest.json`.
