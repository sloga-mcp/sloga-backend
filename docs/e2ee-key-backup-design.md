# Sloga E2EE — Key Backup & Recovery (design)

Status: draft, pending user approval. Promotes "passphrase-encrypted key
backup" out of the implementation plan's **Explicitly deferred** list.
Parent design: `docs/e2ee-design.md`; plan: `docs/e2ee-implementation-plan.md`
(this lands as slice 5.5). Sequenced AFTER the slice-5 FINAL FULL AUDIT —
this feature adds a key-egress surface and must not land before the audited
baseline exists.

## 1. Problem

Today (slices 2–3.5) the desktop identity key is generated at opt-in and
stored DPAPI-wrapped, bound to the Windows user on that machine. The local
SQLite store is the ONLY history for E2EE DMs. Consequences:

- Reinstall / new machine / OS reinstall / lost disk ⇒ identity gone,
  history gone, peers see an "identity key changed" warning (correct but
  scary), all sessions re-handshake as a stranger.
- Logout is survivable only because we deliberately do NOT wipe on logout
  (wipe requires the native confirm dialog) — but that is machine-bound
  luck, not a recovery mechanism.

Users coming from Signal expect: a recovery secret shown once; restore it
and you pick up where you left off; lose it and the history is gone forever.
That "gone forever" property is the point — it proves the server can't help,
because the server can't read anything.

## 2. What is (and is NOT) recoverable — the crypto constraint

**Never restore live Olm ratchet session state from a backup.** A ratchet
pickle captured at time T and restored at time T+n rewinds the ratchet:
message keys already consumed are re-derivable and send chains resume from
a stale position (key/nonce reuse). Signal does not restore sessions;
Matrix's key backup stores *history message keys*, never live sessions.
Same rule here (it is the backup-flavored twin of slice 2's
write-after-ratchet invariant).

So the backup restores, in v1:

| Restored | How |
|---|---|
| Device identity (Ed25519 + Curve25519 keys, device_id) | in the backup blob |
| ⇒ no "identity changed" warning; pins/verifications stay valid | follows from identity |
| ⇒ server-side device row, queue, blobs still addressed to you | device_id unchanged |
| Message history | in the backup blob (history snapshot section) |

Not restored (by design): live Olm sessions (re-established fresh via the
existing pre-key handshake on next send/receive — automatic, no user
action); one-time-key private halves (server-published OTKs for the device
are revoked-and-republished on restore, see §6); unfetched attachment blobs
older than their TTL (honest `expired`, existing behavior).

## 3. Recovery code

- 256-bit CSPRNG secret, displayed once at creation as 12 groups of 5
  Crockford-base32 chars (`XXXXX-XXXXX-…`), with copy + "I stored it"
  confirm. Re-viewable never; re-generatable anytime while logged in with
  keys present (new code ⇒ new backup blob; old blob + code invalidated).
- KDF: Argon2id (m=256 MiB, t=3, p=4 — desktop-class; parameters stored in
  the blob header for forward evolution), random 16-byte salt, domain-
  separated context `"sloga-e2ee-backup-v1"`.
- The derived key AEAD-encrypts the backup blob (ChaCha20-Poly1305, same
  primitives already in e2ee-core). The recovery code and derived key exist
  ONLY in native memory, zeroized after use; they never cross IPC, never
  appear in errors/logs (same invariant-6 test pattern as everything else).
- The server sees: an opaque ciphertext blob + KDF salt/params. A malicious
  server can delete the backup (availability) but never read it. Brute-force
  is bounded by 256-bit entropy, not by the KDF — the KDF is defense in
  depth for users who transcribe a shorter code in some future variant.

## 4. Backup blob

Versioned, single blob per (user_id, device_id), created/refreshed natively:

```
header  { v: 1, kdf: argon2id{m,t,p}, salt }               // plaintext
payload { identity pickle (vodozemac, re-encrypted under the  // AEAD
          backup key — NOT the DPAPI-wrapped local form),
          device_id, created_at,
          history: encrypted-store export (messages, attachment
          metadata + per-file keys, conversation state, pins/
          verified-bindings) }
```

- Pins and verified bindings ride along: restore keeps not just *your*
  identity but your *view of peers'* identities — TOFU state survives.
- Attachment per-file keys are in the history rows already; local
  ciphertext files are NOT in the blob (size). Restored rows whose local
  file is absent render as re-fetchable if the server blob still exists,
  else `expired`. Honest-about-loss, existing UI states.
- Refresh cadence: on a timer (daily) + after N new messages, debounced;
  refresh re-uses the same backup key (code unchanged), bumps a monotonic
  `generation` echoed by the server so a hostile server rolling you back to
  an older blob is DETECTED at restore ("backup is older than expected" —
  loud, not blocking).
- Size: history-dominated. Cap at Autumn-style limits; if a store outgrows
  the cap, back up identity + pins + most-recent window and say so in the
  UI (no silent truncation).

## 5. Server surface (stoatchat)

New routes under the existing `/e2ee` mount, feature-flagged with the rest:

- `PUT /e2ee/backup` — upsert own blob. Device-bound session required
  (int-H3 parity — only a device that has proven its identity key can write
  its backup). Size cap, dedicated ratelimit bucket.
- `GET /e2ee/backup` — the restore path. This device has NO keys yet, so a
  device-bound session is impossible by construction; gate with a fresh MFA
  `ValidatedTicket` (exactly the pattern of first key publication) +
  dedicated tight ratelimit. Response: blob + generation. 404 for no-backup
  is fine (own-account only — no cross-user oracle exists on this route).
- `DELETE /e2ee/backup` — MFA-gated (explicit "delete my backup" in
  settings); also cascaded from `User::delete`.
- Storage: `e2ee_backups` model, both drivers, migration rev 53; fields:
  user_id, device_id, header, ciphertext, generation, updated_at. Unique
  index (user_id, device_id).

The device-revocation cascade (`DELETE /e2ee/keys/{device}`, session
revoke, account deletion) does NOT delete the backup — revoking a lost
device must not destroy the recovery path for it. Backup deletion is only
ever the explicit MFA-gated route.

## 6. Restore flow (native-driven end to end)

1. Fresh install, user logs in, opts into E2EE. If `GET /e2ee/backup`
   (MFA-ticketed) finds a blob: offer "Restore from recovery code" vs
   "Start fresh" (fresh = today's behavior, new identity, peers warned).
2. Code entered in a NATIVE dialog (tauri_plugin_dialog, same pattern as
   the wipe confirm) — the code never enters the webview. Webview couriers
   the ciphertext blob to native; native derives, decrypts, verifies.
3. Wrong code ⇒ AEAD failure ⇒ typed error, retry; no partial state.
4. Success ⇒ native rebuilds the local store atomically (temp dir + rename;
   crash-safe), re-wraps the identity under LOCAL DPAPI, then:
   - revokes the device's server-side one-time keys and republishes a fresh
     batch + fallback key (their private halves died with the old machine;
     leaving them consumable would wedge new inbound sessions);
   - marks all restored conversations' sessions stale ⇒ existing teardown/
     re-handshake machinery runs on next traffic;
   - drains the envelope queue normally (anything sent while offline that
     targeted the old sessions surfaces via the existing `undecryptable`
     marker — honest, bounded loss).
5. Peers see NO identity-change warning (same key). Device-list events:
   none needed (same device_id); last-seen just resumes.

Same-machine logout/login remains what it is today: DPAPI store persists,
nothing to restore. The backup only enters the picture when the local
store is gone.

## 7. UX

- Opt-in flow gains a step: after key publish, "Create your recovery code"
  (skippable, with an explicit "no backup = unrecoverable" warning; nag
  banner in Sessions settings while no backup exists).
- Sessions settings card: backup status (exists / generation date), rotate
  code, delete backup (MFA), the one-time code display.
  - Placement (operator decision 2026-07-08): put this card under
    **Security & Privacy**, directly beneath the E2EE opt-in toggle (where
    slice 4 landed it), not Sessions — backup is only meaningful once the
    toggle is on, and co-locating keeps the mental model "encryption and
    its recovery live together". The no-backup nag banner moves with it.
  - Rotate/delete stay behind an identity re-auth (password / MFA ticket,
    same pattern as the wipe flow). There is deliberately NO
    "reveal stored code" affordance: the code is never persisted anywhere
    (device or server), so the only password-gated action is minting a
    NEW code — which invalidates the old blob+code (see §3). Considered
    and rejected: keystore-persisted reveal-in-settings (widens stolen
    device+password blast radius from "live keys on this device" to
    "portable identity+history restore anywhere").
- Copy must say the true thing: "Anyone with this code and your account
  password can read your message history. Sloga cannot recover it for you."

## 8. Threat model deltas

- **New egress surface**: the backup blob is the first artifact containing
  private key material that leaves the device. Mitigation: AEAD under a
  256-bit code the server never sees; creation/restore paths native-only;
  invariant-6 tests extended to the backup path.
- **Compromised webview** (the standing remote-webview-trust risk): the
  webview couriers only ciphertext; the code is entered natively. A hostile
  webview can trigger backup refresh (no gain — same ciphertext channel it
  already can't read) or request restore (native dialog = user in the loop).
- **Hostile server**: can withhold (availability), delete (availability),
  or roll back the blob (detected via generation, loud). Cannot read,
  forge (AEAD), or swap another user's blob into the response usefully
  (AEAD key is user-code-derived; decryption fails).
- **Rubber-hose / stolen code**: code + a session on the account = full
  history. Documented; matches Signal's model. MFA on the GET narrows
  "stolen code alone".

## 9. Explicitly out of scope (v1)

- Cross-device backup merge (each device backs up its own store; Android
  gets parity in a follow-up half-slice after slice 4's store exists).
- Continuous per-message-key backup (Matrix-style incremental) — the
  snapshot model is simpler and the blob is small at Sloga's scale.
- Changing the logout story: logout still never wipes; wipe stays behind
  the native confirm.

## 10. Adversarial tests (definition of done)

Wrong code fails clean (no partial store); tampered blob (bit-flip, header
swap, generation tamper) rejected; rollback detected and surfaced; restore
is atomic under crash at every step boundary; restored identity
byte-identical (peers' pins still verify); OTK revoke-republish on restore
(old OTKs unclaimable); no code/derived-key/key material in IPC, errors,
logs, or the server-visible blob header; `GET /e2ee/backup` refuses without
MFA ticket; `PUT` refuses unbound sessions; ratelimits enforced; backup
survives device revocation but not account deletion; second restore with a
rotated-away old code fails.

**Gate: e2ee-crypto-reviewer audit (key-egress surface — heaviest scrutiny
on the blob construction, KDF/AEAD use, restore atomicity, and the
MFA-gated GET).**
