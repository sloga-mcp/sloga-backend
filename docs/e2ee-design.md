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

## 9a. Slice-0 decision record (2026-07-07)

### Library: vodozemac (decided)

| Criterion | libsignal | vodozemac 0.10 |
|---|---|---|
| License | AGPLv3 | Apache-2.0 |
| Third-party use | README: "Use outside of Signal is unsupported"; APIs "subject to change without notice" | Built for reuse; semver on crates.io |
| Distribution | git dependency, Rust crates unpublished | crates.io, MSRV 1.85 (ours: 1.92) |
| Audit | Signal's own pedigree | Least Authority audit, no significant findings |
| Handshake | PQXDH (post-quantum) | Olm (classical X25519 triple-DH) |
| Groups | sender keys (more work) | Megolm included (aligns with slice 5) |
| Android | libsignal-android (Java, Signal-internal) | pure Rust → our own uniffi bindings, same core as desktop |

Decision: **vodozemac**. The clinchers: libsignal explicitly disclaims
third-party support with no API stability, which is untenable for a
security-critical dependency we must track for years; vodozemac is audited,
semver'd, Apache-2.0, and lets ONE Rust crypto core serve both Tauri desktop
(commands) and Android (uniffi) — exactly the architecture in §3.

Accepted cost: **no post-quantum handshake in v1** (harvest-now-decrypt-later
exposure). Mitigation: `protocol_version` on bundles/envelopes/identities (per
implementation-plan invariants) gives a migration path when vodozemac or the
Matrix ecosystem ships PQ; revisit at slice 5.

Terminology mapping for the plan: "signed prekey" → Olm **fallback key**;
one-time prekeys → Olm one-time keys; X3DH session establishment → Olm
`create_outbound_session` / `create_inbound_session`.

**Signed bundle format (REQUIRED — reviewer F1/F8).** Unlike libsignal,
vodozemac does NOT sign or verify prekeys internally — Olm one-time/fallback
keys are bare Curve25519 keys. Signature handling is therefore application-
layer and mandatory:
- Bundle = Ed25519 identity key + **Ed25519 signature over the canonical
  serialization of {Curve25519 identity key, fallback key, one-time key
  batch, protocol_version, device_id}** (via `Account::sign`).
- `protocol_version` lives INSIDE the signed payload — a server cannot strip
  PQ capability during the future migration.
- Clients MUST verify the signature before `create_outbound_session`; an
  invalid signature rejects the bundle (hard error, fail closed).
- The phase-2 safety number covers BOTH identity keys (Ed25519 + Curve25519),
  so a server-side Curve25519 swap cannot survive user verification.
- Slice-1 schemas (`e2ee_identity`, `e2ee_prekeys`) carry the signature
  fields from day one; the slice-3 hostile-server harness permanently
  includes key-substitution and signature-stripping cases.

**Device claim authentication (REQUIRED — reviewer F2).** `last_session_id`
may NOT be updated by mere assertion. A bonfire connection claiming a
device_id must prove possession of the device identity key (Ed25519-signed
challenge on connect). Queue drain and E2EEAck are restricted to the
currently-proven session; an unproven claim gets no drain, no ack rights.
This closes the stolen-token attack (drain-and-ack = silent message
destruction; logout-cascade = destroying the victim's device).

**Logout semantics (reviewer F3/F4).** The local E2EE wipe hangs ONLY off the
deliberate user-logout action with a blocking confirmation ("logging out
destroys this device's encrypted history — type LOGOUT to confirm" style);
programmatic session teardown (InvalidSession, token expiry, route-change
dispose — see the historical dispose()/logout() footgun) must NEVER trigger
it (slice-3 adversarial test). Consent copy explicitly states logout = local
history destruction. Authz decision: the token-only logout cascade revoking
the device server-side is accepted (own-session, availability-only impact,
bounded by the device-claim proof above); `DELETE /e2ee/keys/{device}` stays
MFA-gated for revoking OTHER devices.

**Further reviewer-driven decisions (F5–F13):** fallback key rotates on a
cadence (Matrix-style), previous fallback retained to decrypt in-flight
prekey messages; `POST /e2ee/messages` returns per-device status so senders
tear down sessions to unknown/revoked devices (events alone can't reach
offline peers), and clients reconcile peer device lists on connect; device
revocation is server-side only — UI copy must not imply remote wipe, and a
revoked device that reconnects performs a mandatory local wipe; new-device
warnings distinguish "safety number changed" from unchanged to limit warning
fatigue (fresh-device-per-login makes these common); device_id is a random
128-bit value, NOT a ULID (avoids leaking creation time); per-DEVICE queue
depth caps so a dead device can't block live ones; the Android uniffi surface
stays at encrypt/decrypt/persist granularity — no key-export across FFI
(reference matrix-sdk-crypto's bindings before hand-rolling). Correction:
Megolm is NOT a v1 group argument — slice 5 uses pairwise fan-out; Megolm
stays deferred.

### Device model (decided)

- **device_id**: random ULID generated in the NATIVE layer when E2EE is
  enabled on a device; stored in the platform keystore alongside the identity
  key. NOT derived from session id (sessions churn per login).
- **Binding**: first `PUT /e2ee/keys` binds (session's user_id, device_id)
  under MFA; `e2ee_identity` unique index on (user_id, device_id); user_id
  always from the authenticated session.
- **Session mapping**: `e2ee_identity.last_session_id` updated on each key
  publish/connect. Revoking that session (or logout) revokes the device:
  server deletes identity+prekeys+queued envelopes, emits device-removed.
- **Logout wipes local E2EE state** (keys + encrypted history) and calls
  `DELETE /e2ee/keys/{device}`. Each enable cycle = fresh device identity.
  This is the v1 simplicity/safety tradeoff — consistent with the consent
  screen's "no recovery" promise; persistent-device-across-logins is a later
  optimization, NOT v1.
- **Device list UI**: settings page lists a user's own E2EE devices
  (created-at, last-seen) with revoke buttons (MFA-gated).

## 9. Moderation interaction (why reporting ships first)

We cannot scan ciphertext. Reporting must therefore be **reporter-side**: the
report payload includes the offending plaintext + context from the reporter's
device, signed request over authenticated session. Incident procedure
(ban + NCMEC report + preservation) still works on reported content. Design
the report API now so the payload shape already supports client-supplied
plaintext for E2EE conversations later.
