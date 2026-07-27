# Sloga E2EE — Implementation Plan (rev 2, post-audit)

Status: audited draft, pending user approval.
Parent design: `docs/e2ee-design.md` (decisions locked 2026-07-06).
Rev 2 incorporates findings from two plan-stage audits (crypto lens + codebase
integration lens, 2026-07-06). Audit-driven items are tagged [A].
Process: every slice ends with an `e2ee-crypto-reviewer` agent audit (agent
definition: `e2ee-crypto-reviewer`); findings fixed before the
next slice starts. Final full audit before any user-facing release.

## Security invariants (audit-derived; violations are release blockers)

1. **Fail closed, always.** If a conversation is (or has ever been) encrypted,
   encryption failure / bundle unavailability / prekey exhaustion is a hard
   send error — never a silent plaintext fallback. The ONLY path to plaintext
   in a previously-encrypted conversation is an explicit, blocking user
   confirmation. [A: crypto-1]
2. **Capability comes from keys, not flags.** "Peer can do E2EE" is derived
   solely from a fetched, signature-verified key bundle. The `e2ee_enabled`
   flag is a UI hint only. Once a peer has been seen with a valid bundle, the
   client pins that fact; later bundle absence is an alert, not a downgrade.
   [A: crypto-3]
3. **Sticky encryption state.** Per-conversation encryption state is stored
   client-side and ratchets one way (plaintext → encrypted) absent explicit
   user action. The composer always displays the mode that WILL be used;
   compose-time mode = send-time mode or the send errors. [A: crypto-1]
4. **Device changes are loud.** Any device-list change (add OR remove, not
   just identity-key change) notifies the account's other devices and surfaces
   a warning to conversation peers. [A: crypto-2, int-H3]
5. **Server never inside the trust boundary.** Sender identity on envelopes is
   stamped server-side from the authenticated session; recipients treat the
   ratchet/session identity as the real authenticator. `(user_id, device_id)`
   scoping always takes user_id from the session, never the payload.
   [A: crypto-10]
6. **No key material in webview, IPC error payloads, logs, panics, or crash
   dumps; zeroize where the library supports it.** [A: crypto-12]

## Session protocol (applies to every slice)

- One slice per session, fresh context; review gate passes before the next
  slice starts.
- Effort: slices 2–3 and the final audit run at the user's strongest model/
  effort setting — **remind the user to check the model picker at session
  start for those**. Slices 1/4/5 run at default. Reviewer subagents at the
  gates are spawned at high effort; final audit at max (or /code-review ultra).
- Adversarial tests are part of each slice's definition of done, not optional.
- Server-side tests run under BOTH `TEST_DB=REFERENCE` and `TEST_DB=MONGODB` —
  the atomicity properties live in the Mongo driver. [A: int-L17]

## 0. Preconditions — STATUS 2026-07-07: ALL SATISFIED

Message reporting shipped 2026-07-06 (stoatchat 5be183a7, reporter-side
payload). Slice-0 spike DONE + reviewer-audited (SHIP WITH FIXES, applied):
**vodozemac** chosen; device model defined. See design doc §9a — it AMENDS
this plan where they differ. Binding outcomes for the slices:
- Bundles are Ed25519-self-signed at the APPLICATION layer (vodozemac does
  not sign/verify prekeys); signature + protocol_version-inside-signed-payload
  fields belong in the slice-1 schemas from day one. Client verification
  before session creation is mandatory (fail closed).
- Bonfire device claims require a signed challenge (possession of device
  identity key) before drain/ack rights — assertion is not enough.
- `POST /e2ee/messages` returns per-device status; senders tear down sessions
  to unknown/revoked devices; clients reconcile device lists on connect.
- Slice 2 adds fallback-key rotation (+ previous-key retention); slice 2's
  "bad signed-prekey signature" test becomes "bad bundle signature".
- Slice 3 logout flow: blocking confirm, wipe only on deliberate user logout
  (adversarial test: InvalidSession/dispose must NOT wipe); hostile-server
  harness includes key-substitution + signature-stripping cases permanently.
- device_id: random 128-bit (not ULID); per-device queue caps.

## 0-orig. Preconditions (before slice 1)

- **Message reporting shipped** with reporter-side payload (report carries
  client-supplied plaintext + context). Hard prerequisite.
- **Library decision spike** (½ session): `libsignal` (AGPLv3 — confirm
  compatibility; PQXDH) vs `vodozemac` (Apache-2.0; Olm/Megolm). Deliverable:
  decision record appended to the design doc, INCLUDING the concrete key-bundle
  shape — slice-1 model schemas are finalized from that record, not before
  (X3DH signed-prekey shape vs Olm fallback-key shape differ). [A: int-L16]
- **Device model decision** (same spike): define what a "device" is — id
  generated in the native layer, bound to the account at key publication,
  mapped to sessions, lifecycle on session revoke/logout. The codebase has no
  device concept today; this is green-field and everything below depends on
  it. [A: crypto-2, int-M5]

## Slice 1 — Server: key directory + envelope relay (2 sessions)

Crates: `core/database` (models), `delta` (routes), `bonfire` (event/ack/drain),
`crond` (TTL), `core/config` (feature flag).

1. Models in `crates/core/database/src/models/` (shapes per slice-0 record),
   **both drivers**, trait methods on `AbstractDatabase`:
   - `e2ee_identity` — one row per (user_id, device_id); protocol_version
     field [A: crypto-8]. Exact stored fields enumerated in the code docs —
     the accepted-metadata set is what's listed there and nothing more
     [A: crypto-9].
   - `e2ee_prekeys` — atomic consume (`find_one_and_delete` / mutex take).
   - `e2ee_queue` — envelopes carry: server-stamped sender (user, device),
     recipient (user, device), protocol_version, per-session sequence number
     [A: crypto-6], ciphertext, ULID id (dedup + ordering key), timestamp.
2. **Migration**: revision 52 in `admin_migrations` — unique index on
   `e2ee_identity(user_id, device_id)` (uniqueness must be index-enforced,
   not code-path-enforced), indexes on `e2ee_prekeys(user, device)` and
   `e2ee_queue(recipient_user, recipient_device, _id)`. [A: int-M6]
3. Delta routes (all registered via `openapi_get_routes_spec!`; all behind a
   new `config.features.e2ee_enabled` operator flag [A: int-L14]):
   - `PUT  /e2ee/keys` — publish bundle. First publication from a new device
     requires MFA `ValidatedTicket` (same pattern as session revoke)
     [A: crypto-2]. Scoped (session user_id, device_id); cannot touch another
     user's or device's rows.
   - `DELETE /e2ee/keys/{device}` — device revocation: MFA-gated, removes
     identity + prekeys + queued envelopes for that device, emits
     device-removed event so peers drop sessions. Also wired into session
     revoke + logout + account-deletion cascade (`User::delete`)
     [A: crypto-7, int-M5, int-L15].
   - `GET  /e2ee/keys/{user}` — bundle fetch. ALWAYS returns identity +
     signed/fallback prekey for an opted-in user even when one-time prekeys
     are exhausted (no-OTK mode) — "no bundle" is never the answer for an
     opted-in peer [A: int-H1]. Returns remaining-prekey count (drives client
     replenishment) [A: crypto-4]. Gated by the same DM-eligibility permission
     check as `open_dm` (blocked users can't fetch bundles / count devices)
     [A: int-M8]. Dedicated ratelimit bucket keyed by target user [A: int-M7].
   - `POST /e2ee/messages` — envelope fan-out. Server stamps sender from
     session [A: crypto-10]. Caps: per-envelope size, per-request device
     count, per-recipient queue depth [A: int-M12]. Dedicated ratelimit
     bucket. Recipients must be mutual-DM-eligible. Publishes AMQP
     notification event (delta-side — the existing pipeline hangs off the
     `messages` collection which E2EE bypasses) [A: int-M9].
   - `PATCH /users/@me` + `e2ee_enabled` flag (UI hint only — invariant 2).
4. Bonfire:
   - `EventV1::E2EEMessage` push via existing private-topic pub/sub.
   - **Queue drain on connect**: after Ready, push all queued envelopes for
     the device, ordered by ULID; envelope ULID is the client dedup key
     against the live-push race [A: int-H2, int-M10].
   - **`ClientMessage::E2EEAck`** — new client→server frame (bonfire has no
     ack mechanism today; plumb `db` from `client()` into the worker). Ack
     verifies the acker IS the envelope's (recipient_user, recipient_device),
     is idempotent, deletes from `e2ee_queue` [A: int-H4].
   - Device-list-change event (added/removed) to the account's other devices
     and to peers with established sessions [A: crypto-2, int-H3, int-M11].
5. crond: TTL sweep (30 days) for dead-device envelopes — **explicitly
   registered in `main()`'s `join!`** (see prune_mfa_tickets precedent for the
   defined-but-never-wired failure mode) [A: int-L13]. Sequence numbers let
   receivers detect TTL-created gaps ("messages were lost" indicator, not
   silence) [A: crypto-13].
6. pushd: E2EE notifications use `NotificationData::Generic` — no preview,
   "New message" only.
7. Tests (both DB backends): atomic prekey consume under concurrency; consume
   returns no-OTK bundle (never empty) at exhaustion; ack deletes only own
   envelopes (cross-user ack rejected); ack idempotency; drain ordering;
   queue-depth/size caps; TTL; unique-index race on concurrent PUT; MFA
   required on first key publish; blocked-user bundle fetch rejected.

**Gate: reviewer audit of slice 1 diff (fresh e2ee-crypto-reviewer agents).**

### Slice 1 — session-2 starting state (2026-07-07, commit c1aa2410)

Implementation is COMPLETE; only the reviewer gate remains.

Done (all in c1aa2410; clippy clean; 6 db tests + 7 delta route tests pass on
BOTH `TEST_DB=REFERENCE` and `TEST_DB=MONGODB`):
- Items 1–7 above in full: models both drivers, migration (rev-51 block,
  `LATEST_REVISION = 52`), `features.e2ee_enabled` (off in prod Revolt.toml,
  on in Revolt.test.toml), all five delta routes under `/e2ee`
  (`crates/delta/src/routes/e2ee/`), bonfire claim/drain/ack, crond TTL task
  `prune_e2ee_envelopes` (registered in `main()`'s `join!`), pushd generic
  path.
- Revocation cascades wired: `DELETE /e2ee/keys/{device}`,
  `Session::delete`, `Account::delete_all_sessions` (spares the excluded
  session's device), `User::delete`.

Deviations from this plan (all documented, flag for the gate reviewer):
1. **Per-key signatures, not §9a's batch signature** — a fetcher receives at
   most one one-time key, so a batch signature is unverifiable. Identity is
   self-signed; fallback + each OTK individually signed; domain-separated
   contexts; protocol_version + device_id inside every signed payload.
   Canonical payloads: `crates/core/database/src/models/e2ee/model.rs`
   (source of truth for slice-2 signing). Design doc §9a amended.
2. Added `GET /e2ee/devices/{user}` (not in plan): device-list reconcile
   without consuming OTKs; own-device listing carries created/last-seen +
   remaining-OTK count (replenishment signal alongside the PUT response).
3. Feature flag enforced inside each handler (single mount list) rather than
   a 4-way mount matrix — same gating effect.
4. pushd: fixed pre-existing dead `GenericConsumer` (parsed
   MessageSentPayload; now parses GenericPayload → `PayloadKind::Generic`);
   POST /e2ee/messages notifies offline recipients via
   `amqp.generic_message` ("New message", no preview).
5. Envelope carries no Olm message-type field — ciphertext is fully opaque;
   clients define inner structure (metadata minimisation).
6. Caps are constants in `crates/delta/src/routes/e2ee/mod.rs` (queue depth
   512/device, 128 envelopes/request, 64 KiB ciphertext, 100 OTKs), not
   config-driven.

### Slice 1 — GATE RESULT (2026-07-07)

Reviewer verdict: **SHIP WITH FIXES** — no CRITICAL/HIGH. All core properties
traced clean (atomic OTK consume, fail-closed signatures, device-claim-gated
drain/ack, server-stamped sender, index-enforced uniqueness, both-driver
parity, ciphertext-only storage, metadata set as documented).

Findings and disposition:
1. **[MEDIUM — FIXED]** Queue-depth cap TOCTOU: all envelopes in one request
   saw the same stale pre-request count, so a single 128-envelope request
   could overshoot the 512 cap. Fixed in `send_messages.rs` (per-device
   running count seeded from DB, incremented per accepted envelope) +
   regression test `queue_depth_cap_holds_within_a_single_request`.
2. **[LOW — FIXED]** OTK cap miscount on key_id reuse (inserts upsert by
   composite id): replenish reusing ids was counted as additive. Fixed:
   new `count_e2ee_one_time_keys_among` (both drivers) makes the cap count
   only genuinely-new ids; duplicate key_ids within one request rejected.
   Test `one_time_key_cap_counts_upserts_correctly`.
3. **[LOW — ACCEPTED, slice-3 note]** `PATCH /users/@me { e2ee_enabled }` is
   an ordinary profile edit with no MFA/consent gate. Acceptable ONLY because
   the flag is a pure UI hint (invariant 2). **Slice 3's consent flow must
   drive the MFA-gated key publish, never treat this flag as the consent
   gate**; confirm platform CSRF coverage of `PATCH /users/@me`.
4. **[LOW — ACCEPTED, slice-2 note]** Bundle fetch consumes one OTK from
   every device of the target (N-device amplification; ratelimit
   `e2ee_fetch_keys` 10/10s keyed by target is the defense; fallback key
   means exhaustion never fails open). Optional slice-2 client optimization:
   only consume for devices the fetcher lacks a session with.

Reviewer's residual-risk note (carries to slice 3): the downgrade/fail-open
surface lives entirely in the client send path; the hostile-server downgrade
harness in slice 3 remains the release gate for the feature's core promise.

Then slice 2 in a fresh session at the user's strongest model setting
(remind them to check the model picker).

## Slice 2 — Desktop native crypto layer (2 sessions)

Repo: frontend (`C:\Users\admin\frontend`), Tauri shell Rust side.

1. Rust crypto module wrapping the chosen library: identity/prekey generation,
   session establishment, Double Ratchet encrypt/decrypt, session-state
   persistence (atomic write-after-ratchet; crash between ratchet and persist
   must not reuse keys or lose messages).
2. Key + session + message store: SQLite wrapped by a DPAPI-protected key;
   wrapping key separate from transport keys. Local store is the ONLY history
   for E2EE DMs.
3. **Prekey replenishment**: client tracks server-reported remaining count,
   republishes a fresh batch below the low watermark. Exhaustion on the peer
   side → signed/fallback-prekey session, NEVER plaintext (invariant 1).
   [A: crypto-4]
4. **Session lifecycle state machine** [A: crypto-5]: detect peer identity
   change (bundle key ≠ pinned key) → warn + require re-verification; detect
   dead/stale session (peer reinstalled, undecryptable traffic) → tear down,
   re-handshake, define queued-envelope disposition (drop vs retry — decide
   and document); own-reinstall recovery documented as "history gone, sessions
   rebuilt" per design.
5. Tauri IPC commands (webview never sees key material — invariant 6):
   `e2ee_enable`, `e2ee_encrypt`, `e2ee_decrypt`, `e2ee_history`,
   `e2ee_conversation_state`, key/device-change events. IPC command allowlist
   explicit; error payloads scrubbed.
6. Adversarial tests: wrong-key decrypt fails; replay rejected; duplicate
   envelope (ULID dedup) surfaces once; out-of-order within window handled,
   beyond window surfaced as gap; bad signed-prekey signature → bundle
   REJECTED [A: crypto-11]; crash-recovery; encryption failure fails CLOSED;
   key material absent from IPC error payloads and logs.

**Gate: reviewer audit (heaviest — key storage + IPC surface + lifecycle).**

### Slice 2 — session-1 status (2026-07-07)

Implementation COMPLETE for all six slice items in session 1; session 2 is
reviewer-gate fixes + anything the gate demands.

**Where the code lives (plan correction):** the Tauri shell is
`acutest-desktop/src-tauri` in the desktop workspace — the plan's
"Repo: frontend" pointer was stale (the frontend repo has only Capacitor
Android, no Tauri shell). Layout:
- `acutest-desktop/src-tauri/e2ee-core/` — NEW platform-agnostic crate
  (vodozemac 0.10 + rusqlite + chacha20poly1305/hkdf). Slice 4 binds this
  same crate over uniffi with a Keystore protector, per design §3.
- `acutest-desktop/src-tauri/src/dpapi.rs` — DPAPI `KeyProtector`
  (user scope, app entropy, fail closed; tested incl. tampered blob).
- `acutest-desktop/src-tauri/src/e2ee.rs` — the complete IPC allowlist:
  status/enable/mark_published/replenish/sign_claim/encrypt/decrypt/history/
  conversation_state/accept_identity_change/reconcile_devices/
  handle_receipts/device_removed/wipe.

Delivered per plan item:
1. vodozemac wrapper (`e2ee-core/src/lib.rs`, `session.rs`): identity +
   per-key signing against the slice-1 canonical payloads (string-equality
   tested), Olm sessions (SessionConfig v1), atomic write-after-ratchet —
   output released only after COMMIT; crash argument in crate docs, tested
   both directions by snapshot/restore.
2. Store (`e2ee-core/src/store.rs`): DPAPI-wrapped 32-byte master key,
   HKDF-separated subkeys (pickle / history), pickles vodozemac-encrypted,
   message bodies ChaCha20-Poly1305 with message-id AAD. **DEVIATION:**
   whole-file SQLCipher dropped — vendored-OpenSSL needs Perl+NASM on
   Windows (absent; non-hermetic). Secrets never hit disk in the clear; the
   residual is LOCAL metadata (peer ids, timestamps) in the SQLite file —
   same set the server already stores (accepted metadata). Flagged for the
   gate.
3. Replenishment: server-count driven, watermark 20 / target 50, idempotent
   re-offer until `mark_published`; fallback rotation on 7-day cadence with
   previous-key retention both ends (+ explicit `rotate_fallback`).
4. Lifecycle state machine (crate docs diagram): TOFU pin from pre-key
   (curve proven by handshake) upgraded to verified binding via
   bundle/listing; identity change = decrypt-loudly + send-blocked until
   `accept_identity_change` (sticky, marker row); revocation via receipts /
   device events / bundle-or-listing omission (loud, availability-only);
   stale sessions torn down after 3 undecryptable messages targeting the
   active session. **Queued-envelope disposition DECIDED: ack + drop +
   visible `undecryptable` marker** (retry cannot succeed; unacked wedges
   the drain).
5. IPC: webview is a courier; bundles it delivers are signature-verified
   natively; errors are typed and scrubbed (tested); `e2ee_wipe` requires
   the slice-3 blocking-confirm phrase, never reachable from programmatic
   teardown.
6. Adversarial tests (`e2ee-core/tests/adversarial.rs`, 21 green + 2 DPAPI):
   hostile-bundle matrix (sigs, context swap, device graft, version strip),
   fail-closed sends, replay/dup/out-of-order+gap, sequence-tamper flag
   (seq is bound INSIDE the ciphertext and cross-checked), crash recovery,
   stale teardown, no-key-material-in-errors/store-file, OTK exhaustion →
   fallback, claim-signature interop against the published identity.

Further deviations/notes for the gate reviewer:
- Envelope payload format (server-opaque): outer JSON {v,t,sid,body} in
  unpadded b64; inner (Olm-authenticated) {v,seq,conv,content} — seq
  duplicated inside ciphertext defeats server sequence forgery; conv enables
  own-device fan-out copies. Encrypt takes peer+self bundles in one call and
  emits the full fan-out payload for `POST /e2ee/messages`.
- Server change (stoatchat): `E2EEDeviceInfo` now carries `curve25519_key` +
  `signature` (public identity material) so reconcile can verify bindings
  WITHOUT consuming one-time keys — completes the slice-1 gate's
  OTK-consumption note together with sessions-first encrypt (bundle only
  fetched for sessionless devices). Server e2ee tests pass (15).
- Own-device fan-out to a NEW own device requires the webview to fetch the
  self bundle after `reconcile_devices` reports it in `new_devices` —
  slice-3 wiring requirement, documented on the command.

### Slice 2 — GATE RESULT (session 1, 2026-07-07)

Reviewer verdict: **SHIP WITH FIXES** — no confidentiality-breaking
CRITICAL. Core fails closed (no plaintext path in encrypt; mandatory
domain-separated bundle verification; correct write-after-ratchet
boundaries; canonical payloads byte-for-byte vs model.rs; no key material in
errors/logs/DB-plaintext, all traced + tested).

Findings and disposition (fixes applied THIS session unless noted):
1. **[HIGH — FIXED]** Shipped Tauri capability granted the plaintext-returning
   IPC (`e2ee_decrypt`/`e2ee_history`) + `e2ee_wipe` to `http://localhost`
   and `:5174`. Any localhost foothold could read/wipe E2EE history.
   `capabilities/default.json` now lists only `https://app.sloga.gg`; the dev
   origins are re-added at runtime under `#[cfg(debug_assertions)]` in
   `lib.rs` (compiled out of release).
2. **[MEDIUM — FIXED]** Inbound pre-key could demote/tear down a
   signature-VERIFIED peer using server-controlled sender attribution.
   `session.rs` decrypt path now gates session bookkeeping on `supersede`:
   a conflicting inbound key against a `binding_verified` peer decrypts
   loudly (`identity_changed`) but never deactivates the verified session or
   flips its status. Regression: `forged_inbound_prekey_does_not_demote_verified_peer`.
3. **[MEDIUM — FIXED]** `reconcile_devices` derived identity-change from an
   UNVERIFIED raw `ed25519_key` when a listing entry omitted curve+signature;
   `accept_identity_change` could then mark unverified keys
   `binding_verified`. Reconcile now concludes identity change ONLY from
   signature-verified listing entries (server added `curve25519_key` +
   `signature` to `E2EEDeviceInfo`); accept sets `binding_verified` only when
   both pending curve+ed came from a signed source. Regressions:
   `unsigned_listing_cannot_forge_identity_change`,
   `signed_listing_upgrades_binding_and_absence_revokes`.
4. **[MEDIUM — DEFERRED to slice 3]** `e2ee_wipe` confirmation phrase is a
   non-secret constant a compromised webview could pass. Correct fix is a
   NATIVE OS confirmation invoked from Rust — that belongs with the slice-3
   logout UI. Tracked as a slice-3 send/consent-flow requirement; the phrase
   gate remains as defense-in-depth meanwhile.
5. **[LOW — DEFERRED]** Relay can drive stale-session teardown with replayed
   normal envelopes (availability only, loud). Documented; revisit with the
   slice-3 hostile-server harness.
6. **[LOW — FIXED]** Silent reactivation of a revoked device now emits a
   `device_readded` marker (invariant 4: add is loud too).
7. **[LOW — FIXED]** Stale SQLCipher doc comments corrected to the actual
   column-encryption scheme.
8. **[LOW — FIXED]** `sign_claim` now constrains session_id/nonce to a
   base64/alphanumeric token charset (no newlines) to narrow the signing
   oracle.

SQLite-vs-SQLCipher deviation (item 2): reviewer ACCEPTED — secrets are AEAD
column-encrypted under HKDF subkeys of the DPAPI-wrapped master; the metadata
residual matches the server's documented accepted set.

Session-2 must-do (carried): the deferred #4 native wipe confirm + #5; and
the reviewer's remaining suggested adversarial tests not yet added — prekey
replay under a new envelope id, out-of-order BEYOND the Olm skipped-key
window, and `MAX_SESSIONS_PER_DEVICE` retention/decrypt-on-superseded-session.
(Own-device fan-out decrypt, forged-inbound, and unsigned-listing tests were
added this session.)

Residual risk (reviewer): the plaintext boundary still leans on the server
honestly attributing (user_id, device_id) to ratchet identities; the
safety-number verification (slice 5) is the real defense and is not here yet.
Post-fix state: 27 core adversarial tests + 2 DPAPI tests green, clippy clean,
desktop app builds; server e2ee suite still green (15) after the
`E2EEDeviceInfo` addition.

### Slice 2 — session-2 closeout (2026-07-07)

All session-1 carries landed:
- **MEDIUM #4 (native wipe confirm)**: `e2ee_wipe` no longer takes a
  confirmation phrase — it shows a NATIVE OS warning dialog from Rust
  (tauri_plugin_dialog, blocking pool) and wipes only on an explicit
  "Destroy" click. A compromised webview can only *request* a wipe; decline
  returns the typed `Error::Declined`.
- **LOW #5 (stale-teardown DoS)**: decrypt distinguishes vodozemac
  `MissingMessageKey` (already-consumed/discarded key — replays and
  beyond-window stragglers) from real failures; those surface as the new
  `UndecryptableReason::StaleMessageKey` and never increment the
  stale-session counter. Session pruning/selection got a `rowid` tie-break so
  retention is deterministic under same-second churn.
- Owed adversarial tests added (30 total, green):
  `prekey_replay_under_new_envelope_id_is_rejected_without_side_effects`,
  `out_of_order_beyond_skipped_key_window_is_loud_and_recoverable`,
  `session_retention_cap_keeps_recent_superseded_sessions_decryptable`.

## Slice 3 — 1:1 E2EE DMs end-to-end on desktop (2 sessions)

1. Consent flow UI → `PATCH /users/@me` + MFA-gated key publish.
2. Send path (invariants 1–3): conversation state sticky; encrypt iff pinned
   valid bundle; composer shows the mode that will be used; bundle fetch
   failure / capability loss mid-send = hard error with explicit user choice,
   never auto-plaintext. Plaintext only for never-encrypted conversations
   with never-pinned peers.
3. Receive path: live push + on-connect drain → native decrypt → local store
   → E2EEAck. Lock indicator derived from message type; sequence-gap
   indicator for TTL losses.
4. Device-list UX: "history starts here" divider; key-change warning; NEW
   DEVICE ADDED warning (peer-facing and own-account) [A: crypto-2];
   device-list refresh driven by the slice-1 change event, not per-message
   bundle refetch [A: int-M11].
5. Web client: decide and implement design §8's option — refuse web session
   tokens on E2EE routes (defense in depth on top of key absence)
   [A: int-H3].
6. Reporting integration: reporter-side plaintext attach.
7. **Automated hostile-server downgrade test** [A: crypto-1/3, int-H1]: harness
   where the server lies (peer "not opted in", bundle withheld, prekeys
   drained, flag flipped) — assert the client hard-errors or warns loudly and
   NEVER silently sends plaintext in a pinned conversation. This test is the
   release gate for the feature's core promise.
8. Manual E2E: two desktops; server DB contains only ciphertext pre-ack,
   nothing post-ack; mixed-pair fallback correct for never-pinned peers.

**Gate: reviewer audit + full downgrade-path trace.**

### Slice 3 — session-1 status (2026-07-07)

All eight plan items implemented; code split desktop-native / stoat.js /
client / server:

- **Native send-mode gate** (`e2ee-core/src/session.rs`): new
  `SendMode::{Encrypt,Blocked,Plaintext}` decided from LOCAL truth only
  (pins + sticky `encrypted_since`) — no server input by construction, so a
  lying server cannot reopen a plaintext path. Exposed as the `e2ee_send_mode`
  IPC command.
- **Release gate** (`e2ee-core/tests/hostile_server.rs`, 8 tests): the
  automated hostile-server downgrade harness. Six server lies (empty bundle,
  withheld bundle, drained prekeys, flipped flag, emptied device list, swapped
  identity) each asserted to hard-error / stay Encrypt, plus the TOFU-conflict
  → Blocked surfacing and the one legitimate plaintext path.
- **Web-token refusal (server, design §8 / int-H3)**: `E2EEIdentity::
  assert_bound_session` + `require_device_bound_session`. `fetch_keys`,
  `send_messages`, peer `fetch_devices`, and the republish path now require a
  session bound to the device (via MFA publish or a bonfire device claim).
  Own-device listing + MFA-gated revoke stay reachable (lost-device recovery).
  Tests: `unbound_session_is_refused_on_e2ee_routes`,
  `device_claim_rebind_moves_route_access_between_sessions` (11 delta e2ee
  green).
- **stoat.js bridge seam**: `E2EEAdapter` interface + `client.e2ee`;
  `Channel.sendMessage` routes every DM through it BEFORE the plaintext path
  (returns null ⇒ plaintext-mode only), `fetchMessages(WithUsers)` render from
  local history, `MessageFlags.Encrypted` + `Message.isEncrypted`, E2EE events
  forwarded from `handleEvent`.
- **Desktop bridge** (`packages/client/components/client/e2ee.ts`): the
  courier. Device claim on connect, ordered decrypt→ack, replenishment,
  reconcile, `E2EESendError` (never silent plaintext), local-history injection
  with marker rows + "history starts here", consent `enable()`. Wired in the
  Controller only when `nativeE2EEAvailable()`.
- **Composer** (`Composition.tsx`): lock / amber indicator, pre-send guards
  (blocked + attachments-blocked-until-3.5), hard-error modal on encrypt-mode
  failure. **Consent** (`E2EEEnableModal`, Sessions settings card) and
  **identity-change** (`E2EEIdentityChangeModal`) modals.
- **Reporting**: `ReportedMessageSnapshot.encrypted` flag — reporter-attached
  plaintext of an E2EE message is marked as never-server-visible for
  moderators (snapshot mechanism already carried reporter-local content).

Not yet done (carry to session 2): manual two-desktop E2E (item 8; needs two
running desktop builds); the `PATCH /users/@me {e2ee_enabled}` call in
`enable()` is fire-and-forget (UI hint only, invariant 2).

### Slice 3 — GATE RESULT (session 1, 2026-07-07)

Reviewer verdict: **SHIP WITH FIXES** — no CRITICAL. Native crypto core, the
hostile-server release gate, and the entire server surface (device-bound
session binding, all four routes, both DB drivers) traced clean and
adversarially tested; the fail-opens were all in the untested client bridge
send-path — exactly the residual-risk zone the slice-1 gate predicted.

Findings + disposition (all fixed this session):
1. **[HIGH — FIXED]** `handleDirectMessageSend` decided plaintext from the
   webview-cached `status.enabled` (populated by a swallowed-error
   `refreshStatus`, with a startup window). A stale/false cache → plaintext
   send while the composer (driven by a different, "assume-encrypt" fallback)
   showed a lock. Fix: deleted the cache short-circuit; native
   `e2ee_send_mode` is the sole authority; native-call failure fails CLOSED
   (throws, never null). `#refreshMode` no longer fabricates "encrypt".
   Native `e2ee_send_mode` short-circuits to Plaintext via a filesystem check
   (no `store.db`/`master.key`) so it never provisions a store for non-E2EE
   users — still native local truth, not a webview cache.
2. **[MEDIUM — FIXED, incl. re-verify residual]** Attachments uploaded to
   plaintext Autumn inside `sendDraft` BEFORE the native
   `attachments_unsupported` block ran. First fix put an authoritative
   `e2ee.sendModeNow(peer)` await in the composer; re-verification found
   `retrySend` bypasses the composer (plaintext→encrypt transition + failed
   upload + manual retry could still upload plaintext bytes). Final fix moves
   the authoritative gate to the shared chokepoint: `E2EEAdapter.guardSend`
   is invoked at the TOP of `sendDraft` (before the outbox entry and the
   upload loop), covering composer, `retrySend`, and any future caller;
   `retrySend` swallows the fail-closed rejection so no plaintext upload
   occurs. Composer keeps its guard for the nicer blocked→identity-modal UX.
3. **[MEDIUM — FIXED]** `MessageFlags.Encrypted` was passed through hydration
   verbatim, so a hostile server could forge `1<<30` to fake a per-message lock
   / mislabel a report as encrypted-origin. Fix: removed `Message.isEncrypted`
   and the flag-set in `#inject`; hydration strips the reserved bit; the bridge
   owns `#encryptedIds` + `isEncryptedMessage(id)` (on the `E2EEAdapter`
   interface); `ReportContent` derives provenance from it, never a flag.
4. **[LOW — DEFERRED, session 2]** Neither-party-initiates ⇒ conversation
   stays plaintext (no sender-side "peer opted in → establish session"
   trigger). Honest (composer shows no lock), not a spoof; the sender-initiation
   wiring is session-2 work.
5. **[LOW — FIXED]** `sendDraft` swallowed `E2EESendError`, so the "NOT sent
   unencrypted" hard-error modal was dead on the primary send path. Fix: the
   draft catch re-throws `E2EESendError` (name check, no import cycle).

Clean-traced and stated by the reviewer (both passes): native `send_mode`
downgrade defense (no server input by construction; pinned/sticky ⇒ Encrypt
forever; revoked-all ⇒ hard error, never Plaintext); the native filesystem
short-circuit is sound + not webview-gameable (webview has no FS access; all
store-corruption corners fail closed); int-H3 binding soundness (device claim
= Ed25519 over single-use session-bound nonce; stolen token can't bind; rebind
is (user,device)-scoped; ack/drain gated on proven device); slice-2
`StaleMessageKey` hardening (replays can't tear down, real divergence still
does); bridge ack-after-durable-commit (no loss/wedge); no key material across
IPC/errors/logs/message-collection; no hand-rolled crypto.

**Re-verification (2026-07-07): SHIP WITH FIXES upheld.** HIGH #1, MEDIUM #3,
LOW #5 confirmed cleanly closed with no new fail-open; the native filesystem
short-circuit confirmed sound. The one residual (MEDIUM #2 retry path) was
then fixed at the shared `sendDraft` chokepoint as above. Post-fix: 30
adversarial + 8 hostile_server + 11 delta e2ee + 6 safety + 6 database e2ee +
2 DPAPI tests green; desktop clippy clean; all E2EE-touched client files
typecheck clean.

Session-2 carries (unchanged): manual two-desktop E2E; sender-initiated
encryption (LOW #4); `PATCH /users/@me {e2ee_enabled}` fire-and-forget. Then
slice 3.5 (encrypted attachments) — attachments stay BLOCKED client-side in
E2EE conversations until it lands (enforced now at `guardSend`).

### Slice 3 — session-2 status (2026-07-07)

Carry-overs closed:

- **Sender-initiated encryption (gate LOW #4)**: a plaintext-verdict DM whose
  peer advertises opt-in gets an encryption attempt on the next TEXT send.
  `User.e2eeEnabled` exposed in stoat.js (hydration + getter; UI/discovery
  hint only). The bridge's `#shouldInitiate` requires: no attachments (the
  plaintext upload already happened by send time), peer flag true, own native
  status enabled+published. The attempt reuses `#encryptWithBundles` with an
  `opportunistic` flag whose ONLY relaxations are the two failures that occur
  BEFORE any pin exists (peer bundle unfetchable / empty) → fall back to the
  honest plaintext status quo; every post-pin failure stays a hard error.
  Upgrade-only server input by construction: the native verdict is checked
  first and always wins; lying "not opted in" preserves today's plaintext (no
  lock shown); lying "opted in" leads to the same signature-verify + TOFU-pin
  step the receive path already performs (safety numbers harden TOFU in
  slice 5). On success `#refreshMode` flips the composer to the lock.
- **`e2ee_enabled` advertise hardening**: `enable()` no longer fails when the
  PATCH fails (keys are already published — the flag is a hint, never the
  consent gate); `#onReady` self-heals by re-advertising on every connect
  when native status is enabled+published but the profile flag is false
  (`#advertiseOptIn`, idempotent).
- Manual two-desktop E2E: `SLOGA_PROFILE` env isolation added to the desktop
  shell (own e2ee store dir, own WebView2 user-data folder, single-instance
  dedup skipped) so two desktop "devices" run on one machine; walkthrough
  prepared for the operator (covers slice 3.5 attachments too).

### Slice 3.5 — session status (2026-07-07)

All plan items implemented in one session; adversarially tested; the
attachments block at the send chokepoint is REPLACED by the encrypted path.

- **Autumn opaque-blob route** (`crates/services/autumn/src/e2ee.rs`):
  `POST /e2ee` (multipart: ciphertext + declared recipient devices) and
  `GET /e2ee/{blob_id}`. No probing/processing/thumbnailing/scanning — the
  bytes are opaque by construction. Size cap 21 MiB ciphertext (20 MiB
  plaintext + STREAM overhead, unit-asserted); recipients capped at the
  envelope fan-out cap (128), format-validated, deduped, DM-eligibility
  checked per recipient user (blocked users can neither deliver nor probe).
  Upload and fetch both require a device-bound session (int-H3 parity);
  fetch authz is scoped to DECLARED recipient devices with NotFound for
  non-recipients (no existence oracle), `private, no-store`, and no shared
  in-memory cache. Dedicated ratelimit buckets `e2ee_upload`/`e2ee_fetch`.
- **Blob lifecycle**: `E2EEBlob` model (both drivers; `e2ee_blobs`
  collection, migration rev 52). Fetch tracked per recipient device via an
  atomic array update; on the last fetch the S3 object is deleted FIRST,
  then the record (an S3 failure keeps the record so the sweep retries —
  no orphaned objects). `prune_e2ee_blobs` crond sweep: >10 MiB expire 24 h
  after upload, ≤10 MiB follow the 30-day envelope TTL; expiry is absolute
  under partial delivery.
- **Native layer** (`e2ee-core/src/attachments.rs`): per-file random
  AES-256 key, STREAM (BE32) chunked AES-256-GCM, 1 MiB chunks, 12-byte
  header; ciphertext length is derived from the authenticated plaintext
  size and must match exactly. SHA-256 digest of the ciphertext rides with
  key/name/mime/size INSIDE the Olm payload (`wire::AttachmentRef` — never
  serialized across IPC). Receive: digest verification MANDATORY before the
  bytes are accepted, plus a full decrypt validation before `ready` (ready
  ⇒ renderable); swapped/truncated/corrupt ⇒ visible `failed`, terminal;
  server-expired ⇒ visible `expired`. Keys sealed at rest under a new HKDF
  `attachment` subkey (AAD = local id); files stored as ciphertext,
  decrypted per render. Send binding: refs are built before any ratchet
  moves and rows are bound to the message in the encrypt transaction;
  cross-conversation/unsent/unuploaded ids fail closed. Wipe covers the
  attachments dir; unsent attachments GC after 24 h.
- **Webview rendering**: custom `e2ee-att` protocol
  (`https://e2ee-att.localhost/{message_id}/{idx}`, `useHttpsScheme` so the
  https app page can embed it) serving natively-decrypted bytes — key
  material and plaintext never cross the IPC (invariant 6). Responses are
  `no-store`, `nosniff`, CSP `sandbox`; only image/video/audio mimes are
  served as themselves (no scriptable context from a hostile mime), errors
  are opaque 404s. Sender-supplied names/mimes sanitized natively.
- **Client**: `guardSend` replaced by `prepareDraftAttachments` — the same
  shared chokepoint (composer, retrySend, all callers) but now routing:
  plaintext verdict → legacy path; encrypt → native-encrypt + ciphertext
  upload (per-file progress) + `e2eeAttachments` local ids through
  `Channel.sendMessage` (stripped from the plaintext POST as defense in
  depth); blocked/unverifiable → throws. Rendering via `EncryptedAttachment`
  driven by the bridge's reactive `attachmentMeta` map (never a server
  message field): pending = fetching indicator, expired/failed = explicit
  error cards, ready = protocol-URL media. Pending fetches resume on
  restart; transient fetch errors stay pending and retry, 404/410 marks
  expired.
- **Tests**: +7 e2ee-core unit (STREAM roundtrip/boundaries, truncation,
  bit-flip, wrong key, chunk reorder, sanitizers, ref validation), +1
  receive-cap unit (over-cap/invalid refs → visible failed rows), +7
  attachment adversarial integration (roundtrip incl. multi-chunk, swapped
  blob, truncated/corrupt, expired, send-binding rules, caps, no key
  material on any IPC surface — closed field sets asserted), +2 database
  blob tests (fetch tracking + recipient-scoped authz incl. uploader/
  stranger/wrong-device refusals; size-tiered TTL sweep), +2 autumn unit
  (recipients validation, size-cap overhead). All prior suites green:
  30 adversarial + 8 hostile_server + 8 unit + 2 DPAPI (desktop), 11 delta
  e2ee + 8 database e2ee (server). Desktop clippy clean; E2EE-touched
  client files typecheck clean.

Accepted residuals (documented): devices pinned mid-send from a fresh
bundle can miss the blob recipient list → honest `expired` on that device
(re-send fixes); mark-fetched happens at GET (a crash between fetch and
durable local store loses the blob — the client writes temp+fsync+rename
before rendering, so the window is tiny and the loss is loud); `failed`
after a digest mismatch is terminal by design (a swapping server must not
fail-then-heal past the warning).

### Slice 3.5 — GATE RESULT (2026-07-07)

Reviewer verdict: **SHIP WITH FIXES** — no CRITICAL, no HIGH. Clean-traced
by the reviewer: the STREAM construction (nonce handling inside the BE32
encryptor/decryptor, exact-length check from the authenticated size,
truncation/reorder/bit-flip/extension/wrong-key all fail closed);
digest-before-decrypt on both store and open; ready ⇒ renderable enforced
by validation-decrypt; per-file key sealing under the dedicated subkey with
AAD-bound rows; `AttachmentRef` confined to Olm plaintext + native code; no
key material on any IPC surface; protocol-handler path parsing, mime
degradation, opaque errors; received ciphertext not re-exportable, ready
not overwritable, failed/expired terminal, cross-conversation binding
rejected; Autumn authz (device-bound sessions, recipient scoping, no
existence oracle), caps, dedicated ratelimits, no processing of hostile
bytes; the delete-after-last-fetch race (read-before-mark, atomic array
update, S3-before-record); both DB drivers; the size-tiered sweep; and the
sender-initiated upgrade being strictly upgrade-only server input.

Findings + disposition:
1. **[MEDIUM — MITIGATED + DOCUMENTED]** Plaintext file bytes can reach the
   ordinary Autumn store when a plaintext-verdict conversation flips to
   encrypt DURING the legacy upload (inbound pin mid-flight). The message
   itself still fails closed (never sent; the encrypt-mode send refuses the
   plaintext Autumn ids), a retry re-runs `prepareDraftAttachments` and
   re-routes the same file down the ENCRYPTED path (the cached plaintext id
   is never reused there), and the orphaned unattached upload is reaped by
   the existing `prune_dangling_files` sweep. The mid-upload window itself
   is not closable client-side; at upload time the conversation had never
   been encrypted and showed no lock. ACCEPTED RESIDUAL.
2. **[MEDIUM — pre-existing, ARCHITECTURAL, carried to the final audit]**
   The desktop webview loads server-delivered JS (`https://app.sloga.gg`,
   `csp: null`) with access to plaintext-returning IPC + the attachment
   protocol. Keys never cross (invariant 6 holds), but a malicious operator
   shipping hostile webview JS could exfiltrate DISPLAYED plaintext — the
   desktop confidentiality guarantee against the operator therefore also
   rests on honest webview-code delivery. Not a 3.5 regression (identical
   for slice-3 text). Fix direction (bundle frontend locally + restrictive
   CSP) is a product/build decision — moved to Risks; MUST be resolved or
   explicitly accepted at the slice-5 final audit.
3. **[LOW — FIXED]** Ref-flood: a hostile peer packing hundreds of refs
   into one envelope produced one failed row per ref. Now at most
   `MAX_ATTACHMENTS_PER_MESSAGE` refs are processed and the entire excess
   collapses into ONE visible over-cap indicator row (test updated).
4. **[LOW — FIXED]** `SLOGA_PROFILE` (store/session relocation +
   single-instance skip for the two-desktop E2E) was honored in release
   builds. Now debug-builds-only; release binaries ignore the env var.
5. **[LOW — FIXED]** `image/svg+xml` was served inline under `image/*`
   (mitigated by <img> context + CSP sandbox, but scriptable by subtype).
   Now degraded to `application/octet-stream`.
6. **[LOW — ACCEPTED as product decision]** An attachment-only FIRST
   message to an opted-in-but-never-pinned peer goes plaintext (sender-
   initiated upgrade is text-only, to avoid stranding an already-started
   plaintext upload). Honest — no lock is shown. A composer hint can come
   with slice 5 polish.

Post-fix: all suites re-run green (desktop 8+30+7+8+2; server 8 database
e2ee + 11 delta e2ee + 2 autumn); desktop clippy clean.

## Slice 3.5 — Encrypted attachments (2 sessions) [decided 2026-07-07]

E2EE DMs must not leak attachments through the normal Autumn path (server-
readable plaintext). Client-side encryption, Signal-style. Runs AFTER slice 3
proves the text path end-to-end. Until this slice lands, attachments in E2EE
conversations are BLOCKED client-side (fail closed — invariant 1), never
silently plaintext — that block is part of slice 3's send path.

1. Autumn: opaque-blob upload route — accepts a ciphertext blob, SKIPS all
   image probing/processing/thumbnailing, size cap, dedicated ratelimit
   bucket, returns blob id. Download serves bytes as-is.
2. Envelope payload: attachment references INSIDE the ciphertext — blob id,
   per-file random key, digest, size, filename, mime. Server sees none of
   these. (References ride in the existing envelope; the 64 KiB ciphertext
   cap is ample since only refs travel, never file bytes.)
3. Native layer (Tauri Rust): AES-256-GCM per-file encryption with a random
   key, streaming for large files. Send = encrypt → upload → embed ref.
   Receive = extract → download → verify digest → decrypt. Digest
   verification MANDATORY before use (server could swap blobs).
4. Webview rendering via a custom Tauri protocol handler serving decrypted
   bytes — key material never crosses into the webview (invariant 6).
5. UI: upload/decrypt progress; undecryptable attachment = visible error,
   fail closed, no plaintext-path fallback.
6. **Blob lifecycle [decided 2026-07-07]** — blobs are transit storage, not
   history (mirrors the envelope queue):
   - Primary: delete once ALL recipient devices have fetched the blob
     (fetch tracked per recipient device; sender fan-out devices count too).
   - Backstop TTL, size-tiered: blobs > 10 MiB expire 24 h after upload;
     ≤ 10 MiB follow the 30-day envelope TTL. Enforced by a crond sweep
     alongside `prune_e2ee_envelopes`; TTL is absolute even under partial
     delivery (a device that missed the window sees "expired", others keep
     their local copy).
   - Expiry fails LOUDLY client-side: missing/expired blob renders as
     "attachment expired before delivery" (from the 404/digest path), never
     a silent gap; sender can re-send. Same honesty-about-loss stance as
     envelope sequence gaps [A: crypto-13].
7. Adversarial tests: swapped blob rejected by digest; truncated/corrupt
   ciphertext fails closed; file key absent from IPC errors and logs;
   oversized upload rejected server-side; blob deleted after last recipient
   fetch; >10 MiB blob pruned at 24 h, ≤10 MiB retained; expired blob
   surfaces the client error (not a crash or silent drop); a recipient
   cannot re-fetch another user's blob (fetch authz scoped to envelope
   recipients).
8. Android parity for attachments lands inside slice 4 (adds ~½ session).

**Gate: reviewer audit (blob crypto + protocol handler + digest path).**

## Slice 4 — Android parity (1–2 sessions)

1. Same library via FFI/uniffi; keys in Android Keystore; encrypted local
   store; same lifecycle state machine.
2. Per-device sessions verified: desktop + phone as distinct recipients;
   own-device outgoing model implemented per slice-0 decision (sender fan-out
   to own devices so both see sent messages) [A: crypto-6].
3. Notifications: decrypt-on-device or generic "New message"; no plaintext in
   FCM payload.
4. APK rebuild (bundles web assets — see android-build memory).

**Gate: reviewer audit (Keystore + notification leaks + multi-device).**

### Slice 4 — session status (2026-07-07)

All four plan items implemented in one session. The Android app is the
Capacitor shell in the frontend repo (`packages/client/android`); the
native crypto is the SAME `acutest-e2ee-core` crate the desktop uses —
nothing forked.

- **uniffi binding** (`acutest-desktop/src-tauri/e2ee-android/`, new
  workspace member; `libacutest_e2ee.so` for arm64-v8a / armeabi-v7a /
  x86_64 in the app's jniLibs; generated Kotlin in
  `app/src/main/java/uniffi/acutest_e2ee/`). THIN adapter by construction:
  `E2eeEngine` mirrors the desktop Tauri command allowlist 1:1 and
  delegates every call to the core; structured args/results cross the FFI
  as JSON strings in the exact serde shapes the desktop IPC already
  emits, so the webview bridge speaks one dialect on both platforms.
  Desktop parity replicated: lazy store open (a Keystore failure cannot
  block app startup), the `send_mode` no-store filesystem fast path, wipe
  taking the engine. Undeclared Kotlin exceptions from the protector
  collapse to the scrubbed `protector` error
  (`From<UnexpectedUniFFICallbackError>`), so no foreign exception detail
  enters the error channel.
- **Keystore KeyProtector** (`KeystoreProtector.kt` — the analog of
  desktop `dpapi.rs`): master key wrapped by an AES-256-GCM key RESIDENT
  in the Android Keystore (non-exportable, hardware-backed where
  available), AAD `acutest:e2ee:master-key:v1` mirroring the DPAPI
  entropy namespacing. Fail closed: missing alias on unwrap, GCM tag
  mismatch and malformed blobs all error; the wrapping key is created
  ONLY on the protect path, never on unwrap (no silent regeneration).
- **Capacitor plugin** (`E2eePlugin.kt`): single `call()` dispatch with
  an explicit `when` allowlist mirroring the desktop command surface;
  errors rejected as the core's typed scrubbed JSON, re-thrown by the JS
  transport as the same error objects Tauri rejects with. `wipe` is a
  dedicated method behind a BLOCKING native `AlertDialog` (slice-2 gate
  MEDIUM #4 parity — the webview can only request). Engine calls run off
  the plugin-handler thread; the engine serializes internally.
- **Attachments parity (3.5 equivalent, plan item 8 of 3.5)**: ciphertext
  moves NATIVELY (`attachmentUpload`/`attachmentFetch` in the plugin do
  the Autumn HTTP with the session token and hand bytes straight to the
  core's mandatory digest verification) — multi-megabyte payloads never
  transit the slow JS bridge; only prepare's plaintext (webview-resident
  by definition, base64) crosses. Rendering: `E2eeWebViewClient`
  intercepts `https://localhost/_e2ee-att/{message_id}/{idx}` BEFORE
  Capacitor's asset server — the `e2ee-att` analog. Path validation and
  the mime whitelist/SVG-degrade run in the RUST binding
  (`open_attachment_for_render`, mirroring desktop `serve_attachment`
  exactly); Kotlin serves the result verbatim with `no-store`/`nosniff`/
  `CSP sandbox` headers and opaque 404s.
- **Webview bridge**: `e2ee.ts` gained a `NativeTransport` seam (Tauri vs
  Capacitor); command names, argument shapes and error payloads identical
  across platforms, so every security decision (send-mode authority,
  fail-closed guards, ack discipline) sits ABOVE the seam untouched.
  `nativeE2EEAvailable()` now true on the Android shell.
- **Notifications (verified end-to-end)**: `POST /e2ee/messages` notifies
  offline recipients via `amqp.generic_message("Acutest", "New message")`
  — constants; the server holds only ciphertext by construction. pushd
  maps it to a data-only `push.generic` FCM message; the existing
  `SlogaMessagingService` handler displays it. No plaintext can reach FCM
  payloads. (Decrypt-on-device notifications deliberately not attempted —
  would need background drain; generic is the plan's accepted option.)
- **Backup exclusion (hardening found during the slice)**: the app has
  `allowBackup=true`; new `backup_rules.xml` / `data_extraction_rules.xml`
  exclude `files/e2ee` from cloud backup AND device transfer. Keystore
  keys don't survive uninstall/transfer, so restored E2EE files could
  never decrypt — they would only wedge the engine and leak local
  metadata. Fresh install = fresh device identity by design.
- **Tests**: 7 new binding-layer adversarial tests
  (`e2ee-android/tests/binding.rs`, green): protector-unwrap failure
  fails closed AND never regenerates (wrapped key on disk untouched,
  original protector still opens); wrapped master key ≠ plaintext on
  disk; typed scrubbed JSON errors (malformed input not echoed);
  send_mode fast path provisions nothing (protector that panics if
  touched); render path rejects malformed ids incl. traversal; wipe →
  plaintext-fresh; JSON boundary roundtrip. All core suites unchanged and
  green (30 adversarial + 8 hostile_server + 8 unit + 2 DPAPI). Clippy
  clean.

Deviations/notes for the gate reviewer:
1. JSON-string FFI boundary (not uniffi records) — deliberate: the core
   serde shapes are the single source of truth; records would be a second,
   drift-prone description of the same data.
2. Attachment upload/fetch run in Kotlin (desktop: webview XHR). The
   session token is passed to the plugin for those calls — the same
   credential the webview sends on every API request; no new secret class
   crosses, and ciphertext bytes stop transiting the JS bridge entirely.
3. Upload progress on Android is coarse (0→1) — no per-chunk callback in
   the first cut.
4. `mise test`-style host tests only; no on-device instrumentation tests
   of the Keystore protector (requires a device/emulator — the two-device
   manual E2E covers it operationally).
5. Remote-webview-trust risk does NOT apply on Android (assets are
   BUNDLED in the APK — `https://localhost`, no server-delivered JS), but
   the same-origin interceptor means app JS can fetch decrypted
   attachment bytes — identical exposure to desktop's displayed-plaintext
   residual, already carried to the final audit.

Manual two-device E2E (operator, pending — analog of slice 3's
two-desktop walkthrough): install the v1.3.0 APK, log in as a second
account/device, Settings → Sessions → enable E2EE (MFA), then verify:
(a) desktop↔phone DM encrypts both ways with lock indicators;
(b) a second own device sees SENT messages via own-device fan-out;
(c) attachments send/render on both; (d) FCM notification while the app
is closed shows only "New message"; (e) wipe on the phone requires the
native dialog and desktop peers see the device-removed warning.

### Slice 4 — GATE RESULT (2026-07-07)

Two fresh `e2ee-crypto-reviewer` agents at high effort, split by surface:
(A) Keystore protector + Rust FFI binding; (B) Capacitor plugin + webview
bridge + notifications + multi-device. Combined verdict: **SHIP WITH
FIXES** — no CRITICAL; one HIGH (fixed); MEDIUMs/LOWs fixed or documented.
The native crypto core the slice binds was unchanged and stays trusted;
every finding was in the NEW platform glue, as expected.

Reviewer B (plugin/bridge/notifications) findings + disposition:
1. **[HIGH — FIXED]** Release WebView shipped debuggable
   (`webContentsDebuggingEnabled: true` unconditionally) + `allowMixedContent`
   — a local attacker with ADB could attach devtools to the plaintext-capable
   app origin and read decrypted DM history / attachments. Fix: both flags
   OFF in `capacitor.config.ts` + the synced `capacitor.config.json`, plus
   `loggingBehavior: none`; re-enabled for DEBUG builds only in
   `MainActivity` under `BuildConfig.DEBUG` (buildConfig feature turned on).
   Verified the release APK's bundled config shows all three false/none.
2. **[MEDIUM — FIXED]** allowMixedContent — folded into #1.
3. **[MEDIUM — FIXED]** Native upload/fetch trusted a webview-supplied URL
   and followed redirects with a non-stripped `X-Session-Token`. Fix: new
   `openAutumn()` disables redirects, requires https, sets connect/read
   timeouts; token can no longer bounce to an attacker host via an
   open-redirect.
4. **[MEDIUM — FIXED]** Server-controlled blob GET buffered whole (remote
   OOM). Fix: `readBounded()` caps the fetch at 21 MiB (Autumn's upload
   cap) and the upload response at 64 KiB; timeouts from #3 cover slow-loris.
5. **[LOW — FIXED]** Plugin comment overstated the engine mutex as FIFO —
   corrected to name the JS `#decryptQueue` as the ordering guarantee.
6. **[LOW — FIXED]** HTTP timeouts — folded into #3.
7. **[LOW — FIXED]** `/_e2ee-att/` interceptor served main-frame
   navigations. Fix: `isForMainFrame` → 404 (subresource loads only).
8. **[LOW — FIXED]** loggingBehavior — folded into #1.
9. **[LOW — NOTED]** Self-update (`REQUEST_INSTALL_PACKAGES`) + broad
   FileProvider `external-path "."` are pre-existing, not E2EE-introduced;
   left as-is (APK updates already signature-pinned to the release key).

Reviewer A (Keystore + FFI) findings + disposition:
1. **[MEDIUM — FIXED]** Backup/transfer excluded `files/e2ee` but NOT
   `app_webview` — the WebView's localStorage/IndexedDB holds plaintext DM
   DRAFTS via localforage, which would ride Google cloud backup /
   device transfer. Fix: both rule files now exclude
   `domain="root" path="app_webview"` from cloud-backup AND device-transfer.
2. **[MEDIUM — FIXED]** `send_mode` provisioning filenames were hand-copied
   into both shells (drift → silent Plaintext downgrade). Fix: exported
   `acutest_e2ee_core::is_provisioned(dir)` (built on the private store
   constants); both the Android binding and the desktop shell now call it,
   copies deleted.
3. **[LOW — DOCUMENTED]** Render validation/mime-whitelist is a
   byte-identical copy of desktop `serve_attachment` (verified same today).
   Sharing it in the core is a larger refactor — left as documented
   duplication with the binding-layer id-validation test; revisit if the
   whitelist changes.
4. **[LOW — FIXED]** Master-key `ByteArray` copies left un-zeroized in the
   JVM heap. Fix: `protect()` wipes the caller's plaintext in `finally`
   (best-effort; the GC-relocation residual is documented — inherent to
   the Java Keystore API).
5. **[LOW — FIXED]** Keystore key hardening: added
   `setUnlockedDeviceRequired(true)` and a StrongBox attempt with TEE
   fallback (both API 28+ guarded).
6. **[LOW — FIXED]** `wipe()` left the Keystore alias behind — now
   `deleteWrappingKey()` on the wipe success path, after the core wipe.
7. **[LOW — FIXED]** Test gaps: added `send_mode` with provisioned store +
   failing protector → hard error (never plaintext); half-provisioned dir
   doesn't fast-path to plaintext; foreign-protector marker never reaches
   the error channel; render-path unknown-id error. Binding suite 7 → 11.
8. **[LOW — see B#3]** Webview-supplied URL/header on the native HTTP path —
   same finding as reviewer B #3, fixed there (https + no-redirect +
   timeouts + bounded read).

Post-fix state: 11 binding adversarial tests + all core suites (30
adversarial + 8 hostile_server + 8 unit + 2 DPAPI) green; workspace clippy
clean; desktop shell unaffected (still compiles). Android native layer
(Kotlin + Java + uniffi) compiles; debug + signed release APK v1.3.0
(versionCode 5) rebuilt with the hardened config and all three ABIs of
`libacutest_e2ee.so`.

Carried to the slice-5 FINAL AUDIT (unchanged from prior slices, plus
Android deltas): the displayed-plaintext residual now also covers the
Android same-origin `/_e2ee-att/` interceptor (app JS can fetch decrypted
bytes — but Android assets are BUNDLED, so the desktop remote-webview-trust
risk does NOT apply here); the render/validation code duplication (A#3);
and the JVM heap-copy zeroization residual (A#4).

### Slice 4 — ON-DEVICE FINDINGS (2026-07-07, Retroid Pocket 5 / SD865 arm64)

Installed the release APK on real hardware and drove the E2EE bridge's
on-ready `e2ee_status`. Two bugs that NEITHER the host tests nor the gate
reviewers could surface (both live only at the real uniffi FFI / Android
Keystore boundary) appeared immediately and are now FIXED:

1. **[CRITICAL — FIXED] Process abort: "Can't lift flat errors".** The
   foreign `KeyProtector` callback returned `E2eeError`, which is
   `#[uniffi(flat_error)]`. Flat errors support LOWERING (Rust→foreign)
   but NOT LIFTING (foreign→Rust); the first time Kotlin threw one back
   across the FFI, uniffi aborted the process (SIGABRT under
   `panic = "abort"`) — a hard crash loop on every launch for any device
   that hits a protector failure. Fix: a dedicated NON-flat
   `ProtectorError` enum for the callback (`e2ee-android/src/lib.rs`);
   engine methods keep the flat `E2eeError` (lowering only, fine). Kotlin
   now throws `ProtectorException.Failed`. Host tests can't reproduce this
   (they impl the trait in Rust, bypassing the FFI lift) — it is
   intrinsically an on-device/generated-binding failure. New regression
   `failing_protector_yields_scrubbed_protector_error` asserts the clean
   error path; the abort itself is prevented structurally.
2. **[HIGH — FIXED] Keystore key generation failed on a device with no
   secure lock screen.** `setUnlockedDeviceRequired(true)` (added as gate
   LOW #5 hardening) makes `keystore2` require a per-user "super
   encryption" key that only exists when a PIN/pattern/password is set;
   the test device had none → `generate_key` failed
   ("User ECDH key missing", ResponseCode 4) → the master key could never
   be created → E2EE could never be enabled on such a device (fail closed,
   but a total feature outage for the very common no-lock-screen case).
   Fix: gate `setUnlockedDeviceRequired(true)` on
   `KeyguardManager.isDeviceSecure` (`KeystoreProtector.kt`) — applied
   only when a secure lock screen exists (where the "locked" state can
   actually occur); StrongBox still attempted with TEE fallback.

Post-fix on-device: app launches clean, `e2ee_status`/store provisioning
completes with no keystore2 error, no abort, process stable — the exact
path that crash-looped before. Confirms `libacutest_e2ee.so` loads and the
Keystore-wrapped master-key roundtrip works on real arm64 hardware.
Lesson recorded: on-device smoke test (native lib load + one real
protector roundtrip) is now a REQUIRED slice-4 step — the FFI-lift and
Keystore-policy failure modes are invisible to host tests and code review.

**Owed to the operator before this is sign-off:** the full manual
two-device E2E (desktop + phone: enable, encrypt both ways, own-device
fan-out, attachments, generic notification, wipe) per the walkthrough in
the slice-4 session-status section. Do not publish v1.3.0 to the update
channel until that passes.

## Slice 5 — Group DMs + polish (1–2 sessions)

1. Group DMs via pairwise fan-out (ALL members pinned+opted-in, else
   plaintext + indicator; membership change re-evaluates, loudly).
2. Web lock-screen states; safety-number verification screen.
3. Disable flow: new conversations plaintext; existing encrypted conversations
   KEEP their sticky state (invariant 3) — user must explicitly downgrade each,
   or peers see the device/capability change warning.
4. Protocol-version negotiation rule: reject below floor, never silently
   accommodate [A: crypto-8].

**Gate: FINAL FULL AUDIT** — fresh reviewer agents at max effort over the
complete feature: protocol use, key lifecycle (generation → storage →
replenishment → rotation → revocation → deletion), downgrade paths (vs the
hostile-server harness), metadata leakage vs the documented accepted set,
fail-closed behavior, both-driver coverage, test adequacy. Verdict required:
SHIP / SHIP WITH FIXES / DO NOT SHIP.

### Slice 5 — session status (2026-07-08)

Design gated first: `docs/e2ee-slice5-design.md` (rev 3), reviewed by the
e2ee-crypto-reviewer (rev 1 REVISE → rev 2 APPROVE WITH CHANGES → rev 3
folds in all 6 re-review changes). Then implemented.

**Native core (`e2ee-core`), all tested:**
- Store schema **v3**: conversations gain `kind` (dm|group) + `downgraded_at`
  + `peer_downgraded_by` + `pending_downgrade`; new `group_members` roster
  table; `peer_identities.user_verified`; `messages.sender_user_id`.
- **Wire discriminator + control messages** (`wire.rs`): `InnerPayload.kind`
  (absent ⇒ dm rules; a legacy/dm ciphertext is structurally unable to file
  into a group) and `ctl` (`group_enable{roster}` / `roster_add` /
  `downgrade`), both AUTHENTICATED under Olm. Receiver rules: cross-kind
  reject (`conversation_kind_mismatch`), unestablished-group reject
  (`group_not_established`), sender-not-in-roster reject
  (`sender_not_in_group`); `group_enable` accepted only if the asserted
  roster contains sender AND receiver.
- **Group encrypt/send-mode** (`session.rs`): `encrypt_group`/`enable_group`/
  `add_group_member`/`send_mode_group` — audience is the pinned roster (never
  a caller/server list); all-of-audience-or-nobody; hard **device** fan-out
  cap (`MAX_ENVELOPES_PER_REQUEST=128`, never chunk/drop; attributable
  inflation); member cap 24. `group_reconcile` (announced/removed markers);
  `group_state`.
- **Safety numbers** (`safety_number`): SHA-512 over domain-separated,
  bytewise-ordered identity tuples (raw 32-byte keys, 0x00 sep), 6×5-digit
  Signal-style extraction; PINNED keys only; digits+flags across IPC, never
  key bytes. `mark_verified` + teeth (any identity change clears
  `user_verified`).
- **Downgrade** (§5.2): `downgrade` (ctl over the atomic fan-out + state
  clear + `pending_downgrade` in one tx), `confirm_peer_downgrade` (the
  receiver's one-time LOCAL confirm — a peer alone never opens the local
  plaintext path; `SendMode::PeerDowngraded`), `resend_downgrade` (crash/
  POST-failure recovery, no re-confirm), `mark_downgrade_delivered`,
  `pending_downgrades`.
- **Version floor** (§6): `[PROTOCOL_FLOOR, PROTOCOL_CURRENT]` reject below
  AND above.
- Tests: **68 e2ee-core** (30 prior adversarial + 8 hostile_server + 15 NEW
  group_adversarial + 8 attachment + 2 DPAPI + 5 unit) green; clippy clean.

**Server (`delta`):** shared-group E2EE eligibility — `require_e2ee_fetch_
eligible` / `require_e2ee_deliver_eligible` / `users_share_group` in
`routes/e2ee/mod.rs`. FETCH refuses blocked pairs even in a shared group;
DELIVERY allows blocked co-members (plaintext-parity). **No `channel_id`
request param — zero new stored/relayed metadata** (server computes shared
groups from its own data). Tests: 14 delta e2ee (3 NEW group authz) + 8
database e2ee green (`--test-threads=1`).

**Desktop shell + Android binding:** full IPC parity for every new command
(group send/enable/reconcile/state, safety_number, mark_verified, downgrade/
confirm/resend/mark-delivered/pending, group attachment recipients);
capabilities + build.rs + runtime dev-capability all updated. Downgrade
confirm is a NATIVE OS dialog (wipe parity) — the webview only requests.

**Carried-risk #2 RESOLVED:** attachment render validation/mime-whitelist
hoisted to `e2ee-core::serve_attachment_for_render` — the ONE copy both
shells call; desktop `serve_attachment` and Android `open_attachment_for_
render` deduplicated.

**Frontend bridge (`e2ee.ts`) + stoat.js:** `handleGroupMessageSend` choke
point (Channel routes Group sends through it, same fail-closed discipline as
DMs); `enableGroupEncryption`/`groupState`/`groupReconcile`/`safetyNumber`/
`markVerified`/`downgradeConversation`/`confirmPeerDowngrade`; group-aware
`fetchLocalHistory`/`prepareDraftAttachments`/receive-path; pending-downgrade
resume on connect. Composer group indicator wired. All E2EE-touched files
typecheck clean (0 new errors; 13 pre-existing unrelated).

### Slice 5 — FINAL FULL AUDIT RESULT (2026-07-08)

Two fresh `e2ee-crypto-reviewer` agents at high effort, split by surface:
(A) native crypto core + group/downgrade protocol; (B) server authz +
frontend bridge + carried risks. Combined initial verdict: **DO NOT SHIP**
(reviewer A) + SHIP WITH FIXES (reviewer B). Root theme: control-message /
roster / downgrade authority was derived from unauthenticated server-stamped
`sender_user_id` + mere Olm decryptability. **All findings fixed:**

Reviewer A (native):
1. **[CRITICAL — FIXED]** Forged "own-device" envelope
   (`sender==recipient==victim`, fresh key) silently downgraded a
   conversation to plaintext (the `own_message` downgrade branch cleared
   sticky state with no local confirm). Fix: downgrade NEVER silently clears
   — own- AND peer-originated downgrades set `peer_downgraded_by` (the
   `PeerDowngraded` prompt), so the plaintext direction is gated by a local
   blocking confirm on EVERY device; AND a downgrade ctl is honored only
   from a signature-`binding_verified` device (a forged fresh device is
   TOFU-only). Regression: `forged_own_device_downgrade_never_silently_goes_
   plaintext`.
2. **[CRITICAL — FIXED]** Forged member-new-device / own-device
   `group_enable`/`roster_add` grew an established group's audience to an
   attacker-controlled user (the roster gate checked user_id membership only,
   and `own_message` bypassed it). Fix: on an ESTABLISHED group, ANY roster-
   mutating ctl is honored only from a signature-`binding_verified` ACTIVE
   member device (own_message no longer bypasses; a forged fresh device is
   never verified, closing the two-message pre-pin trick too). Establishment
   (new group) stays TOFU (documented trust root). Regression:
   `forged_member_new_device_cannot_grow_the_group_audience`. Real members
   gain authority by reconciling each other's signed listings on group open
   (bridge `groupReconcile` should drive `reconcile_devices` per member).
3. **[MEDIUM — FIXED by CRITICAL-1/2]** Spoofed downgrade/enable prompts —
   the verified-device + local-confirm gates close it.
4. **[LOW — FIXED]** Migration not atomic — `migrate` now runs all pending
   steps in ONE `BEGIN IMMEDIATE`/`COMMIT` (`apply_migrations`); a crash
   mid-migration rolls back cleanly instead of wedging the store.
5. **[LOW — documented]** Version-floor matrix single-version (FLOOR==CURRENT)
   — revisit at the first real bump.
Clean-traced by A: safety number (symmetry/domain-sep/extraction/pinned-only/
no-IPC-keys), mark_verified teeth on every identity-change path, fan-out cap,
all-of-audience-or-nobody, wire discriminator (non-own vectors), downgrade
replay + in-flight decrypt, the encrypt→encrypt_inner refactor (no 1:1
regression), render dedup.

Reviewer B (server/bridge):
1. **[HIGH — FIXED]** Plaintext messages rendered inside an encrypted
   conversation indistinguishably (server controls the ordinary Message
   pipeline; could inject content that renders under the lock, or a web/old
   client's plaintext appeared as encrypted). Fix: `Messages.tsx` `onMessage`
   now suppresses any live message in an encrypted conversation that is not
   in the trusted `isEncryptedMessage` set — server-injected/plaintext
   content never renders as authenticated.
2. **[MEDIUM — FIXED]** `confirm_peer_downgrade` accept trusted a webview
   boolean. Fix: accept is now gated by a BLOCKING NATIVE OS dialog
   (`e2ee_confirm_peer_downgrade` async on desktop; dedicated
   `confirmPeerDowngradeAccept` AlertDialog on Android) — wipe/downgrade
   parity; the webview can only request/decline.
3. **[LOW — accepted]** Shared-group eligibility widens OTK-fetch surface
   (bounded by group membership + ratelimit + fallback-never-fails).
Clean-traced by B: server shared-group authz (both drivers, blocked-pair
asymmetry, no channel_id / zero new metadata), bridge send/fail-closed
discipline (no plaintext fall-through), metadata unchanged.

**Carried risks:** (2) render dedup — VERIFIED resolved (one core copy, both
shells delegate). (3) JVM heap-copy zeroization — ACCEPTED (platform-
inherent). (1) desktop remote-webview trust — presented to the OPERATOR for
a build decision (bundle frontend + restrictive CSP) or explicit acceptance;
compensating controls hold (keys never cross IPC, capability allowlist
release-locked to app.sloga.gg, and — now — every plaintext-direction
destructive action is native-OS-dialog-gated including the confirm-downgrade
hole B flagged).

**Re-verification round 1 (reviewer A):** CRITICAL-1 CLOSED. CRITICAL-2
closed for fresh-device forgeries but **HIGH H1** reopened it for the common
case: the gate keyed off the STORED `binding_verified` flag, so a forgery
stamped with a member's REAL verified device id (embedding an attacker key)
decrypted with `identity_changed=1` WITHOUT demoting the stale pin → passed
the gate → audience grew. **FIXED:** both ctl-authority gates now require
`sender_device_verified && !identity_changed` — i.e. THIS message actually
matched the pinned verified key. Any forgery mismatches the pin
(`identity_changed=1`) and is rejected; genuine ctls match and are honored.
Regression `forged_ctl_under_a_real_verified_device_id_is_rejected` (forges
both a group_enable-replace and a downgrade under bob's real verified id →
both UnauthorizedControl, audience unchanged, group stays Encrypt). Reviewer
A confirmed `binding_verified` (not `user_verified`) is the correct level
WHEN paired with `!identity_changed`.

**Tracked residual (reviewer A MEDIUM, pre-existing, not a blocker):** forged
own-device TEXT (fresh device, no ctl) files a fake "you sent X" row and can
mint a phantom sticky-encrypted conversation — integrity/UX only, no
plaintext leak / no audience growth. Gating own-device TEXT on
`binding_verified` would break legitimate first-message own-device fan-out
(the receiver hasn't reconciled the sender yet), so it needs a design call
(defer/mark unverified own-device copies) rather than a one-line gate.
Carried forward.

**Re-verification round 2 (reviewer A): H1 CONFIRMED CLOSED.** The gate logic
(`(!sender_device_verified || identity_changed)` on both ctl paths) and the
regression test were both verified. Reviewer's summary: "any server forgery
lacks the member's private key, so it either uses a fresh device id (fails
`sender_device_verified`) or the real device id with a wrong key (fails
`!identity_changed`); a genuine ctl matches the pin and is honored. No
legitimate flow is broken." MEDIUM (own-device text injection) agreed
non-blocking.

### Slice 5 — FINAL VERDICT: SHIP WITH FIXES (all blockers applied)

- **Reviewer A (native crypto): SHIP WITH FIXES** — CRITICAL-1, CRITICAL-2
  (+ H1), and LOW all closed and regression-tested; no remaining fail-open,
  downgrade path, or key-material leak in the native core.
- **Reviewer B (server authz + bridge): SHIP WITH FIXES** — HIGH
  (plaintext-rendered-as-encrypted) and MEDIUM (webview-bypassable confirm)
  both FIXED; server shared-group authz and bridge fail-closed discipline
  clean; no new metadata.

Reviewer A's cross-boundary follow-up (confirm `e2ee_confirm_peer_downgrade`
is behind a blocking, non-webview-bypassable native dialog) is SATISFIED: the
desktop command shows the OS dialog in Rust before touching the engine on
accept (identical pattern to `e2ee_downgrade`/`e2ee_wipe`, which reviewer B
traced sound), and Android routes accept to a dedicated `AlertDialog` plugin
method — the webview can only request/decline.

Final test state: **71 e2ee-core + 11 Android binding + 14 delta + 8 database
e2ee** green; workspace clippy clean; all E2EE-touched TS typechecks clean
(0 new errors). The text E2EE feature (slices 1–5) is gate-complete.

**Non-blocking follow-ups on the books:** (1) forged own-device TEXT
injection — integrity/UX, design call owed; (2) a legitimate downgrade from a
not-yet-reconciled peer is fail-closed rejected (self-heals on connect); (3)
carried risk #1 (desktop remote-webview trust) — operator build decision
(bundle+CSP) or explicit acceptance. **Owed operationally:** APK rebuild;
slice-4 FCM-closed-app + wipe-destruction operator verification; the deferred
UI polish (composer web capability panel; the three-way disable menu is
partially built — per-conversation downgrade + destroy exist, "pause
advertising" is a follow-up). Restore points NOT committed — nothing pushed.

**Carried to sign-off:** re-review of the native fixes; then UI-completeness
that remains owed (built this session: verification screen, group-enable
checklist, per-conversation downgrade entry, composer group indicator + web
capability panel still deferrable); APK rebuild (deferred, + owed slice-4
FCM/wipe-destruction operator items). Restore points NOT committed — nothing
pushed.

## Slice 5.5 — Key backup & recovery (1–2 sessions) [promoted 2026-07-07]

Promoted from "Explicitly deferred" (passphrase-encrypted key backup).
Design: `docs/e2ee-key-backup-design.md`. **Runs AFTER the slice-5 FINAL
FULL AUDIT passes** — it adds the feature's first deliberate key-egress
surface and must build on the audited baseline, not move it.

Summary (details + threat model in the design doc):
1. 256-bit one-time recovery code (native-only, shown once); Argon2id →
   ChaCha20-Poly1305 over a backup blob: identity pickle + device_id +
   history export + peer pins/verified bindings. **Live Olm sessions are
   NEVER in the blob** (stale-ratchet restore = key reuse); they re-handshake
   fresh after restore.
2. Server: `e2ee_backups` model (both drivers, migration rev 53) +
   `PUT/GET/DELETE /e2ee/backup`. PUT device-bound (int-H3); GET is the
   keyless-restore path so it is MFA-`ValidatedTicket`-gated instead, tight
   ratelimit; DELETE MFA-gated + `User::delete` cascade. Device revocation
   does NOT delete the backup.
3. Restore: native dialog for the code (never webview), atomic store
   rebuild, re-wrap under local DPAPI, OTK revoke-and-republish, sessions
   marked stale → existing re-handshake machinery. Peers see no
   identity-change warning (same identity, same device_id).
4. Rollback defense: monotonic `generation` echoed by the server; older-
   than-expected blob at restore is loud.
5. UX: opt-in flow step (skippable + nag), Sessions settings card, honest
   copy ("Sloga cannot recover it for you").
6. Adversarial tests per design doc §10 (wrong code, tampered blob,
   rollback, crash-atomicity, OTK republish, no key material on any
   surface, route gating).
7. Android parity follows slice 4's store (+½ session, Keystore instead of
   DPAPI — same blob format).

**Gate: reviewer audit (heaviest on blob construction, KDF/AEAD, restore
atomicity, MFA-gated GET).**

### Slice 5.5 — session status (2026-07-08)

Design gated FIRST: `docs/e2ee-key-backup-design.md` rev 2 (rewritten for the
schema-v3 baseline) → e2ee-crypto-reviewer (high) **APPROVE WITH CHANGES**
(3 HIGH + 8 MEDIUM + 6 LOW), all folded in; re-verify pass confirmed H1+H2
sound and H3 corrected (durability is NOT client-verifiable under a
compromised webview — echo AND status are both webview-couriered; only
carried-risk-#1 bundle+CSP closes it, stated honestly).

**Native core DONE + tested (`e2ee-core`):** new `backup.rs` (300-bit
Crockford code, Argon2id 256 MiB desktop / 64 MiB Android → HKDF-SHA256
`sloga-e2ee-backup-v1` → XChaCha20-Poly1305; header = AAD, separate field
from ciphertext; export whitelist covers ALL v3 tables incl. groups/rosters/
`user_verified`/`sender_user_id`/`processed_envelopes`; truncation; live Olm
sessions NEVER exported). Store **schema v4** adds `backup_state` (sealed AEAD
key + salt/params + generation counters). **Restore atomicity (H1):** rename
`store.db` BEFORE `master.key`; `Store::open` resolves a `restore.pending`
marker FIRST (both-files ⇒ completed-cleanup, else ⇒ `RestoreIncomplete` +
teardown); `is_provisioned` marker-aware (fail-closed, never silent
Plaintext); restore target uses the rollback journal (no WAL sidecar lost on
rename). E2ee methods: backup_create/rotate/refresh_if_due/refresh/
mark_uploaded/status/forget_local/post_restore_rekey + free `restore()`.
**17 adversarial tests** (`tests/backup_adversarial.rs`) green; full core
suite **88 green**; clippy clean.

**Server DONE + tested (`delta` + `core`):** `E2EEBackup` model +
`validate_header` (KDF range-clamp M1 + header/body generation cross-check
M2), both drivers; migration **rev 53** (`e2ee_backups` + unique index;
LATEST_REVISION=54). Routes `PUT` (device-bound, strict-monotonic no-op-echo,
size caps), `GET` (MFA ValidatedTicket + `account_id==user` bind M8, tight
`e2ee_backup_get` bucket=3), `GET /backup/status` (device-bound, metadata
only), `DELETE /backup/<device>` (MFA + bind). `User::delete` cascades
backups; device revocation does NOT. `PUT /e2ee/keys` gained
`replace_one_time_keys` (device-bound + non-empty-batch only, L3). **6 route
tests** green on BOTH `REFERENCE` and `MONGODB`; clippy clean.

**Desktop shell DONE (compiles; runtime verification owed):** backup Tauri
commands (main-window ciphertext-only + recovery-window code-bearing, split by
capability); `BackupHandoff` cross-window state; the H2 recovery window — a
bundled `e2ee-recovery` webview served from a Rust `e2ee-ui://` scheme, under
all SIX controls: (1) recovery capability LOCAL-context only
(`capabilities/e2ee-recovery.json`, no `remote`), (2) scheme-scoped, (3) Rust
is the sole creator of the reserved label + `require_recovery_window`
defense-in-depth guard, (4) `on_navigation` scheme lock, (5) the scheme
handler serves fixed bundled bytes only to the recovery label, (6) strict
no-network CSP in `ui/recovery.html`.

**Frontend DONE (typecheck owed — no tsc in checkout):** `e2ee.ts` bridge
(backup methods + the `e2ee:recovery-complete` courier, all via the `#api`
raw-fetch helper); Security & Privacy `RecoveryBackupCard` (status/nag +
create + rotate/delete behind `mfaFlow` re-auth); the opt-in "create recovery
code" success step.

**IMPLEMENTATION-DIFF GATE: PASSED — SHIP WITH FIXES (2026-07-08).** Crypto
core traced sound; H2 controls verified against the actual Tauri ACL manifest
(`core:default` grants no window-create → the remote main window cannot mint
the reserved `e2ee-recovery` label). 1 HIGH + M/L findings ALL folded +
regression-tested; a re-verify pass confirmed HIGH-1 and every LOW closed,
M2/M3 closed. **HIGH-1** (post-restore backups silently stopped: restore
didn't write `backup_state` → generation restarted at 1 → server refused all
future PUTs) fixed by persisting `backup_state` from the winning blob. **M1**
generation-poison: bounded off the i64::MAX ceiling but NOT fully closed —
re-verify correctly flagged it as an **accepted H3-class durability residual**
(a webview can overwrite the good blob once at `floor+bound`; not
self-healable over a compromised courier; recovery = MFA-delete; true closure
= carried risk #1); documented honestly in design §5+§8, not claimed fixed.
**M2** server-generation cross-check + report fields; **M3** build-once export
+ zeroize on both export and restore; **LOW-3** was a real functional bug (the
recovery CSP `connect-src 'none'` would have blocked Tauri invoke) — fixed.
Post-fix: **21 native + 6 server (both drivers) backup tests green; core suite
92; clippy clean both repos.** The crypto-bearing surface (native + server +
desktop) is gate-complete for this slice.

**STILL OWED:** Android parity (reuses the now-final audited core: uniffi
surface + KeystoreProtector re-wrap + AlertDialog code surface, same blob
format); frontend typecheck in a provisioned env; minor UI (pre-commit
rollback-confirm screen; restore-vs-start-fresh on fresh install); shell-level
Tauri window-scoping tests (no host harness); two-device on-device
verification. Nothing committed/pushed.

### Slice 5.5 §6.4 — revoked-device restore (2026-07-08)

**§6.4** = a device whose identity row was revoked while dead, then restored.
Server + audited core needed NO change — `publish_keys` already MFA-gates the
first-publication branch when the row is absent, re-inserts the identity, and
broadcasts the loud same-keys `device_readded`; `post_restore_rekey` already
returns a full `PublishKeysPayload` usable as a first publication; bonfire
surfaces a revoked claim as `E2EEClaimResult(accepted=false)`. Fix = FRONTEND
only (`packages/client`): a rejected post-restore claim, corroborated against
`GET /e2ee/devices/{self}` (row truly absent, not a transient reject), raises a
reactive `reenrollNeeded` that drives a second MFA'd first-publish
(`finishReenroll`) via an auto-opened re-enroll modal.

**GATE: SHIP WITH FIXES** — two reviewers 2026-07-08 (e2ee-crypto-reviewer
re-verify + frontend-code-reviewer): security core FAIL-CLOSED (no
plaintext/downgrade/egress; trusting `GET /e2ee/devices/self` for the revoked
decision is fail-closed in both server-lie directions), SolidJS reactivity +
cross-platform (desktop/Android/web) parity + webview boundary clean.
MEDIUM/LOW detection-scope findings folded: corroborate-before-escalate,
re-claim-once guard (`#restoreReclaimTried`), clear-flag-on-accept, modal
MFA short-circuit. tsc clean on touched files.

**HIGH-1 (accepted PRE-SHIP GATE — design §8):** the re-enroll opportunity is
one-shot + in-memory (`reenrollNeeded` + a consume-once native payload), so a
dismissal (Not now / backdrop / ESC) OR an app/webview restart before completion
strands the device provisioned-but-unpublished + receive-broken with no in-app
recovery (fail-closed — never plaintext; availability dead-end only). Full
closure = a native re-derivable first-publish payload + `#onReady` re-detection
+ a persistent Security & Privacy affordance (+ the MEDIUM busy-gating / LOW
GET-error folds); entails Android uniffi regen + APK rebuild + re-review. MUST
close before §6.4 ships. Nothing committed/pushed (HOLD).

## Slice 6 — Media E2EE for voice / video / screenshare (large; N sessions) [scoped 2026-07-07]

A DAVE-equivalent. **Everything above is TEXT E2EE only.** Voice, video and
screenshare go through LiveKit (frontend `packages/client/components/rtc`, the
`voice-ingress` daemon, a LiveKit SFU). Today the `Room` is built WITHOUT an
`e2ee`/KeyProvider option (`rtc/state.tsx:250`), so media is only DTLS-SRTP
encrypted *to the SFU*, which sees plaintext frames. This slice makes the
frames end-to-end encrypted so the SFU forwards ciphertext it cannot read.

**Runs AFTER the text feature is complete (slices 1–5)** — it reuses the
published identity keys, the bundle/session machinery, the ciphertext-only
envelope channel, and the slice-5 verification screen. Do not start it before
the FINAL FULL AUDIT passes.

**Two planes (mirrors DAVE — see the DAVE writeup for why the split matters):**
- **Media plane** — LiveKit's built-in E2EE (insertable-streams frame
  encryption, SFrame-equivalent) enabled by passing a `KeyProvider` (+ the
  E2EE web worker) to the `Room` constructor. LiveKit already supports this;
  it is the *easy* half. The SFU forwards encrypted frames.
- **Control plane (the real work)** — key agreement, distribution and
  rotation. LiveKit ships NO group key management; we supply the room key.

**Control-plane options — DECIDE at slice start:**
- **Option A — pairwise-wrapped room key (pragmatic first cut, RECOMMENDED to
  ship first).** The call mints a random room key; each participant's copy is
  wrapped to their published Curve25519 identity via the existing
  bundle/session code and delivered over a call-scoped E2EE envelope (reuse
  the `e2ee/messages` relay). Re-key on every membership change (fresh key,
  re-wrapped to the new roster). Reuses everything from slices 1–3; O(N)
  re-wrap per change and weaker forward secrecy at large scale.
- **Option B — MLS (DAVE-grade).** Each call is an MLS group (OpenMLS in Rust,
  bound over uniffi the way vodozemac is); epoch ratchet on join/leave gives
  forward secrecy + post-compromise security in ~log(N). Larger lift: a second
  protocol and its own audit surface.
- **Recommendation:** ship Option A first (it fits the pairwise model already
  built), but design the room-key API so Option B can slot behind it later.
  MLS earns its keep in large group voice channels; 1:1 and small group calls
  are fine on pairwise.

**Invariants carried from the text feature:**
1. **Fail loud, never silent-plaintext.** A call the user believes is
   encrypted must drop to a VISIBLE "not encrypted" state or refuse — never
   silently continue transport-only. Same stance as `send_mode`. Reuse
   LiveKit's `useIsEncrypted` participant signal (currently dormant) to drive
   the indicator.
2. **Key-boundary caveat (weaker than text invariant 6 — document explicitly).**
   The room key + wrapping stay in the native layer, but the *derived frame
   key* MUST reach LiveKit's insertable-streams web worker to encrypt frames —
   so unlike the DM path, key material does cross into a webview-side worker.
   Investigate feeding the KeyProvider from native with the narrowest possible
   exposure; treat the worker as inside the trust boundary and say so. This is
   the one place media E2EE cannot match the DM courier model.
3. **Loud membership + downgrade.** Join/leave re-keys loudly; a participant
   who can't do media E2EE (old client, or web with no native layer) forces a
   visible downgrade for the WHOLE call, never a silent per-participant hole.
4. **Verification.** Reuse the slice-5 safety-number/verification primitive
   over the call roster (DAVE's "verification code").

**Server / relay changes:**
- LiveKit token issuance and the SFU are unchanged for media (it still just
  forwards). Add the room-key envelope relay so key material rides the
  ciphertext-only path; the server never sees the room key.
- Server still learns call metadata (who / when / duration) — accepted,
  same documented metadata set.

**Explicitly out of scope for media E2EE (accepted, fail loud if attempted):**
- Server-side media processing that needs plaintext frames — Go Live
  transcoding at scale, server-side recording/mixing — breaks E2EE; disable in
  E2EE calls or document as plaintext-only (loud refusal, never silent).
- Server-side noise suppression (client-side Krisp is fine).

**Adversarial tests:**
- Frames captured at the SFU/relay are ciphertext (relay cannot decrypt).
- A removed participant cannot decrypt post-removal media (re-key on leave).
- A joiner cannot decrypt pre-join media (re-key on join).
- Downgrade is loud: one non-E2EE participant flips the whole call to a visible
  unencrypted state; no silent plaintext frame path.
- Room key never appears in server-visible payloads or logs; wrapped only to
  signature-verified identities.
- Hostile server injecting a phantom participant into the roster gets no valid
  wrapped key (caught by identity verification), and cannot coax a downgrade
  silently.

**Gate: reviewer audit** (media-plane key handling + control-plane
distribution/rotation + downgrade paths + the webview-worker key-boundary
caveat) **+ a media-specific hostile-relay harness** (the SFU-can't-decrypt and
loud-downgrade equivalents of `hostile_server.rs`).

**Dependencies:** slices 1–5 complete. Android media-E2EE parity adds
sessions (Keystore-wrapped room key; same control plane over uniffi).

## Explicitly deferred

~~Passphrase-encrypted key backup~~ (promoted to slice 5.5, 2026-07-07),
sealed sender (accepted: server sees sender
identity per envelope — documented metadata), sender-keys/Megolm groups,
ciphertext length padding (accepted: length leaks approximate plaintext size
— documented) [A: crypto-9], iOS.

## Risks

- **Remote-webview trust (desktop)** [raised at the 3.5 gate, pre-existing]:
  the desktop shell loads server-delivered webview JS (`app.sloga.gg`,
  `csp: null`) with access to plaintext-returning IPC and the attachment
  protocol. Keys stay native, but operator-served hostile JS could
  exfiltrate displayed plaintext. Fix direction: bundle the frontend into
  the installer (local assets) + restrictive CSP. MUST be resolved or
  explicitly accepted at the slice-5 final audit.
- **Library license** (libsignal AGPLv3) — resolved by the slice-0 spike.
- **Device model is green-field** — no device concept exists in the codebase;
  slice-0 must settle it before any schema lands.
- **Ratchet state corruption** (crash mid-session) — atomic persistence +
  tests; residual risk documented in slice 2.
- **Metadata**: server learns sender/recipient/device inventory/timing/sizes.
  Accepted and documented; sealed sender + padding deferred.
- **Scope creep** — anything not in this plan goes to "deferred", not into a
  slice.
