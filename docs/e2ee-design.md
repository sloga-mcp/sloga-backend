# Sloga E2EE Design — Opt-in Signal-Protocol DMs

Status: **DRAFT** (design accepted 2026-07-06, implementation not scheduled — post-launch flagship feature)
Prerequisite: message reporting must ship first, designed around reporter-side reports (see §9).

## 1. Goal and non-goals

**Goal:** users who opt in get end-to-end encrypted DMs and group DMs. The server
only ever relays ciphertext it cannot read, and deletes it after delivery. The
operator (us) is cryptographically unable to read these conversations.

**Non-goals (deliberately out of scope):**
- E2EE for server channels — they are semi-public spaces; E2EE there costs
  search, embeds, and moderation while buying little. Channels stay plaintext.
- E2EE in the web client — the server serves the JS, so a compromised server
  could exfiltrate keys; browser E2EE is security theater. Native apps only
  (Tauri desktop, Android).
- Rolling our own crypto. We wrap an audited library.

## 2. User model (the decisions already made)

- **Opt-in per account** via an explicit consent flow that states plainly:
  - DMs become E2EE *when the other party has also opted in*.
  - No DM history on new devices; server-side DM history ends.
  - E2EE DMs are unreadable in the web client (shown as "🔒 available on your
    desktop and mobile apps"). Web login itself still works for servers/channels.
  - We cannot recover encrypted messages. Ever.
- **Mixed pairs fall back:** a DM is encrypted iff both sides are opted in and
  have published keys; otherwise plaintext, with a per-conversation lock/unlock
  indicator. (Matrix-style, not Signal-strict.)
- **Disabling** only affects *new* conversations (revert to plaintext). Existing
  ciphertext history stays encrypted forever; the server never gains the
  ability to read it retroactively.

## 3. Crypto layer

Use an audited Rust implementation, evaluated at implementation time:
- `libsignal` (Signal's own; Rust core, official TS/Java bindings) — PQXDH +
  Double Ratchet, sealed sender. License: AGPLv3 — check compatibility.
- `vodozemac` (Matrix; Apache-2.0) — Olm/Megolm, vetted, friendlier license,
  Megolm gives group sessions for free.

Client-side crypto runs **in the native layer** (Rust in Tauri via commands;
libsignal-android on Android), *not* in webview JS, so keys never enter the
DOM/JS heap. The webview asks the native shell to encrypt/decrypt via IPC.

Key storage: Windows DPAPI / Android Keystore-wrapped SQLite (libsignal
provides stores; vodozemac needs a thin one).

## 4. Server changes (delta + core/database)

New collections:
- `e2ee_identity` — per device: user_id, device_id, identity key, signed
  prekey (+ signature), registration metadata.
- `e2ee_prekeys` — one-time prekeys, consumed atomically on fetch.
- `e2ee_queue` — encrypted envelopes awaiting delivery:
  `{recipient_user, recipient_device, sender info, ciphertext, timestamp}`.
  **Deleted on acknowledged delivery**; TTL fallback (e.g. 30 days) for dead
  devices.

New routes (plain REST on delta; remember the stoat-api OpenAPI gotcha — routes
not in the schema drop POST bodies, register them properly):
- `PUT  /e2ee/keys` — publish identity + signed prekey + one-time prekey batch
- `GET  /e2ee/keys/{user}` — fetch a key bundle (consumes a one-time prekey)
- `POST /e2ee/messages` — submit envelopes (fan-out: one ciphertext per
  recipient *device*)
- `PATCH /users/@me` gains `e2ee_enabled` flag (drives the lock indicator and
  mixed-pair fallback)

Bonfire: new `E2EEMessage` event pushing envelopes to connected devices; ack
deletes from `e2ee_queue`. Push notifications carry no preview for E2EE
messages ("New message" only) — FCM data values must be strings (known gotcha).

The existing `messages` collection is untouched; E2EE DMs simply never write
to it.

## 5. Client changes (frontend + native shells)

- Device registration: on enabling E2EE (or first login on a new device),
  generate identity/prekeys in the native layer, publish bundle.
- Session establishment: X3DH (or Olm handshake) on first message to each of
  the peer's devices; per-device sessions thereafter (phone and desktop are
  separate cryptographic recipients).
- Group DMs: pairwise fan-out first (fine at friends-scale group sizes);
  sender-keys/Megolm optimization later if needed.
- Local message store: encrypted SQLite in the native layer is the *only*
  history for E2EE DMs. The webview renders via IPC queries.
- UI: lock icon per conversation, consent flow, safety-number verification
  screen (phase 2), "history starts here" divider.

## 6. Phasing (~8 sessions total)

1. Server: key collections + routes + envelope queue/relay (1–2 sessions)
2. Desktop native crypto layer + key storage + IPC bridge (2 sessions)
3. 1:1 E2EE DMs desktop↔desktop E2E working (1–2 sessions)
4. Android parity (1–2 sessions)
5. Group DMs, verification UI, web lock-screen states, consent flow polish
   (1–2 sessions)

Later/optional: passphrase-encrypted key backup (restores history to new
devices), sealed sender, sender-keys for large groups.

## 7. What breaks inside E2EE DMs (accepted)

- Server-side search, link-embed generation (January can't see URLs — embeds
  generate client-side or not at all), notification previews, server-side
  history for new devices.

## 8. Enforcement notes

- Web "cannot use E2EE" is enforced by *key absence*, not policy — nothing to
  bypass. Optionally also refuse web session tokens for E2EE DM routes.
- Server cannot verify clients actually encrypt (mixed-pair plaintext fallback
  is client-honored); the lock indicator must be derived from *message type*,
  not conversation state, so a downgrade is visible.

## 9. Moderation interaction (why reporting ships first)

We cannot scan ciphertext. Reporting must therefore be **reporter-side**: the
report payload includes the offending plaintext + context from the reporter's
device, signed request over authenticated session. Incident procedure
(ban + NCMEC report + preservation) still works on reported content. Design
the report API now so the payload shape already supports client-supplied
plaintext for E2EE conversations later.
