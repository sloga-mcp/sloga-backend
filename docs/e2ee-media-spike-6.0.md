# E2EE Media (Slice 6) — Sub-slice 6.0 Platform Spike: probe evidence & GO/NO-GO

**Date:** 2026-07-10
**Author:** implementation session (desktop track)
**Gate:** frontend-code-reviewer (probe-evidence review; GO/NO-GO)
**Plan:** [`e2ee-media-mls-plan.md`](./e2ee-media-mls-plan.md) §8 (sub-slice 6.0), §7.1 Q1 (the
`[BLOCKER for 6.3]`), §4.1–§4.2, §3.4.

## 1. Purpose

Sub-slice 6.0 is a runtime probe gate. It answers the one platform unknown that gates the whole
media-E2EE slice (plan §7.1 Q1, marked **[BLOCKER for 6.3]**): does the **actual desktop WebView2
shell** support the encoded-frame-transform + module-worker + WebCrypto surface that LiveKit's
client-side E2EE requires, and does the **real** `BaseKeyProvider → worker` key path (with the
exact HKDF-material import parameters — §4.2) work there without the documented
`InvalidAccessError` failure? If NO-GO, the whole slice re-plans.

**Nothing here is the real implementation.** The spike code (`e2eeMediaSpike.ts`, the Room-site
hooks in `state.tsx`, the Vite dev sink, and the `__E2EE_SPIKE__` global) is **throwaway**, marked
for deletion at the end of 6.0. Keys are static SHA-256 dev constants and provide **no security**.
The real work is 6.2 (native OpenMLS + exporter→frame-key derivation) and 6.3
(`MlsKeyProvider` + native-derived keys over IPC).

## 2. Environment under test

| Property | Value |
|---|---|
| Shell | Sloga desktop (Tauri 2), **debug** build, two isolated instances via `SLOGA_PROFILE=b` / `b2` |
| Webview | **WebView2 (Evergreen)** — `Edg/150.0.4078.48`, Chromium 150 |
| Origin | `https://app.sloga.gg` (remote webview — the pre-6.2b state; see §5 caveat 1) |
| `window.__TAURI__` | present (native bridge live) |
| Frontend | Vite **dev** server (`mise dev`) over the `app.sloga.gg` tunnel; HMR on |
| livekit-client | **2.15.13** (pinned `^2.13.0` in `packages/client`, installed 2.15.13) |
| livekit-server | **v1.9.13** (`ghcr.io/stoatchat/livekit-server:v1.9.13`) — records plan Q7 |
| Evidence transport | CDP `Runtime.evaluate` on `--remote-debugging-port=9223`/`9224`, driving the page directly in the real WebView2 (not the Electron/Chrome Browser pane) |

Both instances (b and b2) produced **identical** results — this demonstrates **determinism** of the
probe on this WebView2 build, not cross-version/cross-shell corroboration (both are the same
`Edg/150` build on the same machine). Field-WebView-version variance is a separate concern the
Android sub-slice (6.7a) probes for; on desktop the WebView2 Evergreen runtime is auto-updated.

## 3. Probe results

### P1 — Encoded-transform + WebCrypto API surface (the blocker)

Run directly in WebView2 via CDP:

| Probe | Result |
|---|---|
| `isE2EESupported()` (the real livekit-client export) | **`true`** |
| `'RTCRtpScriptTransform' in window` | **`true`** |
| `'createEncodedStreams' in RTCRtpSender.prototype` | **`true`** |
| `'MediaStreamTrackProcessor' in window` | **`true`** |
| `crossOriginIsolated` | `false` (not required — LiveKit E2EE uses `RTCRtpScriptTransform`, not SharedArrayBuffer) |

**⇒ The [BLOCKER for 6.3] is resolved: WebView2 exposes the encoded-frame-transform surface
LiveKit's E2EE requires, and `isE2EESupported()` returns true in the real shell.**

### P2 — Module-worker load (Vite `?worker`-bundled LiveKit E2EE worker)

- `new E2EEWorker()` from `import E2EEWorker from "livekit-client/e2ee-worker?worker"` loaded with
  **no `error` event** (module worker instantiated + parsed in the webview origin).
- Production `vite build` emits it as a **self-hosted first-party asset**
  (`dist/assets/livekit-client.e2ee.worker-DjoLe7BK.js`, ~35 KB) — **no CDN**, matching the plan's
  no-CDN requirement (§4.1). The service-worker precache references it.

### P3 — Real `BaseKeyProvider → worker` setKey path with HKDF material (§4.2)

A `SpikeKeyProvider extends BaseKeyProvider` (`{ sharedKey:false, ratchetWindowSize:0,
failureTolerance:0 }` — the planned `MlsKeyProvider` shape) imported each frame key as **raw HKDF
key MATERIAL** (`crypto.subtle.importKey('raw', buf, 'HKDF', false, ['deriveBits','deriveKey'])`)
and called the protected `onSetEncryptionKey(material, identity, keyIndex)`:

| Probe | Result |
|---|---|
| `importKey('raw', …, 'HKDF', …)` + `onSetEncryptionKey(material)` | **ok — no `InvalidAccessError`** |
| The exact op the worker runs internally: `deriveKey(HKDF → {AES-GCM,128})` on the material | **ok** |
| **Negative control:** pass an **AES-GCM `CryptoKey`** where material is expected | **throws `InvalidAccessError`** (as the §4.2 audit-HIGH note predicted) — archived through the sink (`probes.aesGcmAsMaterial`) |

**⇒ The §4.2 audit-HIGH fix is empirically validated:** frame keys MUST be imported as HKDF
material, not as an AES-GCM `CryptoKey`; the wrong form throws `InvalidAccessError` on every
setKey (total media loss), the right form works.

### P4 — Room construction + mid-lifecycle `setE2EEEnabled` toggle (§4.1/A4, §3.4)

A real `new Room({ e2ee: { keyProvider, worker } })` constructed in WebView2, then toggled:

| Probe | Result |
|---|---|
| `new Room({ e2ee: {...} })` | **ok** (no throw) |
| `room.setE2EEEnabled(true)` | **ok** (no throw) |
| `room.setE2EEEnabled(false)` then `(true)` again | **ok, ok** (no throw) |
| `provider.getKeys().length` after setKey | `1` |
| `encryptionError` events | none |

**Verified against the livekit-client 2.15.13 source:** `Room.setE2EEEnabled()` **throws
`Error('e2ee not configured, please set e2ee settings within the room options')` when the `e2ee`
option was omitted at construction** — the exact amendment-A4 failure mode. Our call did **not**
throw ⇒ the E2EEManager attached at construction ⇒ the plan's "always construct the Room
E2EE-capable on supported shells" (§4.1) is both necessary and achievable in WebView2.

**Nuance (accurately recorded — do not over-read P4).** `room.isE2EEEnabled` read `false` after
`setE2EEEnabled(true)` in this **disconnected** probe. This is expected: `Room.setE2EEEnabled` only
runs `e2eeManager.setParticipantCryptorEnabled(...)` — the half that actually arms the cryptor and
wires the provider into the worker transform — when `localParticipant.identity !== ''`, which is
assigned **at connect**. So P4 soundly proves "no-throw ⇒ the A4 E2EEManager attached at
construction," but it does **not** prove the toggle *functionally engages* frame encryption
(`setParticipantCryptorEnabled` never executed; `providerKeyCount:1` is only a `keyInfoMap` insert,
not worker installation). The functional toggle is part of the §5 caveat-2 live-call checkpoint. It
also confirms the plan's §4.1 ordering requirement — **call `setE2EEEnabled(true)` after connect**,
when the identity exists.

## 4. Build / typecheck

- `tsc --noEmit`: the spike files add **no** new errors (the only errors on this branch are
  pre-existing `TrackProcessor.restart` / catalog-typing issues unrelated to this work).
- `vite build`: **clean** (exit 0). PWA `injectManifest`: **383 precache entries / 8707 KiB**,
  under the 4 MB **per-file** cap (`maximumFileSizeToCacheInBytes`); the ~35 KB e2ee worker asset
  is nowhere near the per-file limit and does **not** require a `globIgnores` entry (unlike the
  ~9 MB MediaPipe WASM). **No `globIgnores` change needed for the worker.**

## 5. What was NOT proven here (honest scope + caveats)

1. **Remote-origin only, not the bundled `tauri://` origin — a real residual risk.** All probes ran
   with the webview loading `https://app.sloga.gg` (today's remote-webview state). Module workers +
   WebCrypto + ScriptTransform in the **bundled first-party origin** under a **restrictive CSP** are
   a *distinct* question: a restrictive CSP can genuinely block module-worker instantiation
   (`worker-src`), inline module loading, or WASM. The plan already makes bundle+CSP a **hard
   precondition of 6.3** (amendment A2) and §7.1 Q1 flags "module workers inside the Tauri
   custom-protocol origin" as *still unverified* precisely because the `app.sloga.gg` engine-
   capability result does **not** transfer to the CSP'd origin. 6.0 proves the *Chromium/WebView2
   engine* is capable; **6.2b/6.3 must re-run P1+P2 (worker instantiation especially) under the
   bundled origin + final CSP** and treat a failure there as a 6.2b/6.3 blocker.
2. **No live two-peer media decrypt / wrong-key negative control / SFU-ciphertext capture — this
   is a real gap, promoted to a BLOCKING checkpoint (gate-review HIGH, folded).** 6.0's charter
   row (plan §8) named a "throwaway static-key two-desktop E2EE call to prove the media plane
   end-to-end"; it was **not** delivered here. P1 proves the transform API is *present*
   (`'RTCRtpScriptTransform' in window`), which is **not** the same as proving WebView2's WebRTC
   pipeline actually *routes encoded frames through the script transform and encrypts them*
   (`framesEncoded`/`framesDecoded` advancing, SFU capture = ciphertext, wrong-key decrypt
   failing). A present-but-inert insertable-streams implementation in an embedded webview is
   exactly the class of surprise a spike should catch. The blocker to running it here was that a
   second logged-in account needs a password, which the assistant will not enter.

   **Disposition (supersedes the earlier "risk retired / operator-owned after 6.7b" framing):**
   this functional media-plane proof is a **blocking checkpoint no later than 6.3/6.4**, NOT
   slice-end operator cleanup. The harness already contains the exact instrumentation — `#sampleStats`
   captures `framesEncoded`/`framesDecoded`, and `ARM A`/`ARM B` is a shared-key/wrong-key control —
   so the only missing ingredient is a second connected peer. The GO below rests on the *engine
   capability* unknowns (P1–P4), which are genuinely retired; it does **not** claim the functional
   media plane is proven. If the transform is present-but-inert, that must surface at 6.3/6.4, not
   after the whole slice is built.
3. **`setE2EEEnabled` was exercised disconnected** (see §3 P4 nuance). The connected-room flip and
   `ParticipantEncryptionStatusChanged` firing are part of the 6.3/6.4 live-call work (and the
   operator manual E2E), where a real track and identity exist.

## 6. Recommendation & gate verdict

**GO** — issued, and **confirmed by the frontend-code-reviewer gate (2026-07-10)**, which traced
every load-bearing claim (P1–P4, the negative control, the worker export, the A4 throw-branch) to
the livekit-client 2.15.13 source and found the evidence faithful. The GO rests specifically on the
**engine-capability** unknowns that could have re-planned the whole slice:

- encoded-frame transform + module worker + HKDF WebCrypto: **present and working**;
- the real `BaseKeyProvider → worker` HKDF-material setKey path: **works, no `InvalidAccessError`**,
  and the wrong (AES-GCM `CryptoKey`) form fails exactly as the §4.2 audit predicted;
- an E2EE-capable Room constructs and `setE2EEEnabled` toggles without throwing, with the source
  confirming the A4 throw-if-omitted behavior the plan designed around;
- the worker self-hosts cleanly (no CDN) and does not threaten the precache cap.

The GO does **not** claim the functional media plane is proven (see §5 caveat 2).

**Must-carry conditions into 6.1 / 6.2b / 6.3 (blocking, not advisory — from the gate):**

1. **Live media-plane functional proof is a blocking checkpoint no later than 6.3/6.4** (NOT
   after-6.7b operator cleanup): a two-instance static-key (or real-key) encrypted call showing
   `framesEncoded`/`framesDecoded` advancing, an SFU packet capture = ciphertext, and the `ARM B`
   wrong-key control failing to decrypt. The harness instrumentation already exists; it needs a
   second logged-in peer.
2. **Re-run P1 + P2 (worker instantiation especially) under the bundled `tauri://` origin + the
   final restrictive CSP** in 6.2b/6.3 — the remote-origin result does not transfer.
3. When 6.3 wires the real `MlsKeyProvider`, **exercise `setE2EEEnabled(true)` on a *connected*
   room** so `setParticipantCryptorEnabled` actually runs (the 6.0 probe was disconnected and never
   reached it).
4. **Single biggest residual risk to watch:** `RTCRtpScriptTransform` is *present* in WebView2 but
   its *functional execution on real encoded frames* (and later under the bundled-origin CSP) is
   unproven; condition 1 is what retires it — do not let that proof slip to slice-end.

Proceed to **6.1 (server DS + KeyPackage directory)** and **6.2 (native OpenMLS core)**.

## 7. Throwaway inventory (delete at end of 6.0)

- `packages/client/components/rtc/e2eeMediaSpike.ts` (new file)
- `packages/client/components/rtc/state.tsx` — the four `// THROWAWAY (spike 6.0)` hunks (import,
  `roomE2EEOptions()` at the Room site, `attach()`, `detach()`)
- `packages/client/vite.config.ts` — the `e2eeSpikeReportSink()` plugin + its registration
- `packages/client/.spike-reports/` (gitignored evidence dumps)
- scratchpad `cdp.mjs` driver + `spike-evidence-webview2.json`
