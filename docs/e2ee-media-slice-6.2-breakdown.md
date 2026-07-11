# Slice 6.2 — Native OpenMLS core: implementation breakdown

Breakdown for sub-slice 6.2 of [e2ee-media-mls-plan.md](e2ee-media-mls-plan.md) (plan §8
row 6.2). Written 2026-07-10, before coding, so a follow-on session can resume from this
file. Code lives in `acutest-desktop/src-tauri/e2ee-core` (NOT the frontend repo).
Gate at the end: **e2ee-crypto-reviewer (primary) + media-e2ee-reviewer**.

**Carried from the 6.1 gate (MUST be on the 6.2 gate checklist):** the client rejects an
unsolicited Welcome — one whose join it did not initiate — because the DS cannot bind an
Add to a stored join intent (6.1 gate, media finding 4). The server structurally cannot
enforce this; the native layer is the only defense.

## Contract inputs (fixed by 6.1, already committed)

- Canonical mirrors in `stoatchat/crates/core/database/src/models/mls/model.rs`:
  - `CONTEXT_MLS_CREDENTIAL = "acutest:e2ee:mls-credential:v1"`, payload
    `{ctx}\n{user_id}\n{device_id}\n{mls_signature_key}\n{identity_ed25519_key}` (model.rs:41)
  - `CONTEXT_MLS_JOIN = "acutest:e2ee:mls-join:v1"`, payload
    `{ctx}\n{user_id}\n{device_id}\n{group_id}\n{key_package_ref}` (model.rs:52)
  - group_id = 64 lowercase hex; key_package_ref = unpadded std base64, ≤64 chars;
    mls_signature_key validated server-side as exactly-32-byte unpadded base64.
- API shapes in `crates/core/models/src/v0/mls.rs` (publish/claim/create/join_intent/
  commit-submit/gap-fetch); native `wire.rs` additions must mirror these field-for-field.
- Envelope `content_type`: `olm` / `mls_commit` / `mls_welcome`, plus `group_id`, `epoch`.
- LiveKit participant identity is `{user_id}:{device_id}` (6.1 device-qualified identities).
- Group order = DS epoch counter, NOT mailbox ULIDs: apply commits strictly by consecutive
  epoch; park/refetch on gaps (plan invariant 10).

## Steps

1. **OpenMLS pinning + feasibility spike (plan-named FIRST task; §2.2.1, Q6, R-3).**
   Pin exact versions in `e2ee-core/Cargo.toml`: `openmls = "=0.8.1"`,
   `openmls_rust_crypto = "=0.5.1"`, `openmls_traits = "=0.5.0"` (verified current on
   crates.io 2026-07-10). Then confirm against vendored source, and RECORD the verdicts here:
   - **(a) Last-resort init-key retention (§2.2.1):** OpenMLS ships a `last_resort`
     KeyPackage extension (`KeyPackageBuilder::mark_as_last_resort()`); confirm Welcome
     processing skips deleting the KeyPackageBundle (incl. the HPKE init private key) for
     last-resort packages — i.e. the retention carve-out is UPSTREAM-SUPPORTED, not a hack
     on single-use accounting. If the pinned version does not do this cleanly, v1 falls
     back to **no-last-resort + loud "KeyPackages exhausted, retry shortly"** (fail-loud
     beats fail-weak-FS) and the server's `last_resort` fields go unused by native.
   - **(b) Ambient-transaction storage (Q6):** `StorageProvider<CURRENT_VERSION>` is a sync
     `&self` trait → a provider holding the store's `rusqlite::Connection` inside an open
     `TxGuard` (store.rs `begin()`) participates in the ambient transaction by construction.
     Confirm no interior spawning/async in the pinned version; else fall back to
     snapshot-pickle-per-commit (one sealed row write per epoch).
   - **(c) Dependency friction (R-3):** record the `rand`/`zeroize`/`getrandom` versions the
     pinned stack pulls; ours is rand 0.8 — coexisting majors are fine, unification not
     required. Watch Android .so growth (6.7 concern, note only).

2. **Sealed storage provider + schema v5 + backup ruling (R-5: SAME sub-slice, or the
   workspace doesn't build).**
   - New `e2ee-core/src/mls/storage.rs`: `StorageProvider` impl over the sealed SQLite
     store. Rows `(label, key) → sealed value` in `mls_state`; seal with the new 5th HKDF
     subkey (`b"mls"`, both derivation sites: `open_with_master` AND the fresh-master
     restore path), AAD = `label || 0x00 || key` so a row cannot be swapped across
     labels/keys. Group-scoped rows carry a `group_id` column so per-group wipe is one
     DELETE (plus OpenMLS's own `delete()` walk).
   - Schema migration v5 in the existing single-transaction ladder: `mls_state` (KV for the
     storage trait), `mls_signature_key` (sealed long-lived MLS signature keypair +
     published-KeyPackage bookkeeping), `mls_groups` (local call bookkeeping: group_id,
     channel_id, lifecycle state, last processed epoch, poisoned flag, created_at),
     `mls_join_intents` (own outstanding signed join intents — the durable record that
     makes unsolicited-Welcome rejection possible across a crash).
   - **Backup ruling (§5.5):** ALL `mls_*` tables EXCLUDED from backup — whitelist no-op,
     no reader added; `EXPORT_SCHEMA_VERSION` 4→5 with a comment citing §5.5;
     `BACKUP_PAYLOAD_VERSION` unchanged (exported set does not grow). MLS signature keypair
     is also excluded v1 (regenerated + rebound at restore). T-13-shaped test: store with
     live MLS state → backup → restore ⇒ zero MLS rows, engine treats calls as fresh.
   - `E2ee::wipe()` needs no change (everything lives in `store.db`).

3. **Credential binding + canonical contexts (§1.3; byte-for-byte 6.1 parity).**
   - `canonical.rs`: add `CONTEXT_MLS_CREDENTIAL`, `CONTEXT_MLS_JOIN` + payload builders
     mirroring model.rs exactly; parity unit tests assert the full expected strings (same
     fixed vectors as the server-side tests).
   - `mls/credential.rs`: generate/load the device's MLS Ed25519 signature keypair (sealed
     at rest). Leaf credential = BasicCredential whose identity bytes are a serialized
     `{payload, binding_signature}` envelope (JSON, like wire.rs) — the canonical payload
     signed by the vodozemac identity key (`ctx.account.sign`).
   - **Acceptance rule** (the real trust decision, all three legs): (a) MLS-structural
     signature validity (OpenMLS verifies), (b) embedded binding signature verifies under
     the LOCALLY PINNED slice-5 identity for (user_id, device_id), (c) ctl-authority:
     `binding_verified && !identity_changed` (H1). Unpinned identity → same TOFU-then-pin
     flow as text; identity-changed pin → leaf INVALID until user re-confirms.
   - **Leaf-mutation rule:** every processed leaf mutation re-runs (a)+(b)+(c). Any change
     to credential bytes or MLS signature key ⇒ INVALID, loud reject, group treated as
     hostile (v1 permits only HPKE-rotation self-updates — the heartbeat shape).

4. **KeyPackage lifecycle (`mls_publish_key_packages`, `mls_replenish_check`).**
   - Targets mirror OTK machinery: KP_TARGET = 50, low-water 20 (server cap 100).
     One-time lifetime 30 d; last-resort 7 d (regenerated on each publish, old init key
     zeroized/deleted per the §2.2.1 ruling).
   - Output = `DataPublishMlsKeyPackages` wire shape (device_id, mls_signature_key b64,
     binding_signature, key_packages[], last_resort) — refs computed as unpadded std
     base64 of the OpenMLS KeyPackageRef, matching server charset validation.

5. **Group lifecycle engine (`mls/mod.rs`, surface on `E2ee`, all `&mut self`).**
   Ciphersuite fixed: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; exactly one accepted
   ciphersuite + protocol version, reject outside loudly (invariant 9).
   - `mls_call_create(channel_id)` → group_id = sha256(channel_id || call_start_ulid) hex;
     epoch-0 group; returns `DataCreateMlsGroup` shape. Conflict handling is the CALLER's
     (409 → join path with the returned open group_id).
   - `mls_call_join_intent(group_id, channel_id)` → mint fresh KP if needed, sign
     CONTEXT_MLS_JOIN payload, persist the outstanding intent (group_id, key_package_ref,
     channel_id, created_at) BEFORE returning the wire body.
   - `mls_call_admit(group_id, intent)` → verify intent signature against pinned identity
     (acceptance rule legs b+c), verify the claimed KeyPackage's credential binding +
     leaf validity, `add_members` → staged pending commit + Welcome; returns
     `DataSubmitMlsCommit` shape. NEVER applies before the DS confirms the win (§3.3).
   - `mls_call_process(envelope)` — commit or Welcome from the mailbox:
     - **Welcome:** REJECT unless an outstanding own join intent matches
       (group_id, key_package_ref) — the carried 6.1 gate item; then §1.4 step-4
       group-context assertion (Welcome's group_id == intent's group_id, channel binding
       intact) BEFORE key derivation; then verify EVERY leaf credential against pins
       (reject the whole group on any invalid leaf); then join. Consume the intent record.
     - **Commit:** strict epoch order (park/gap-refetch signal on gaps, never skip-ahead);
       full leaf re-verification on every Add/Update; merge inside the §3.3 transaction.
       Unprocessable WINNING commit ⇒ mark group poisoned, surface successor-needed state
       (§1.4 poisoned-epoch flow; the caller drives `POST /mls/groups` w/ `supersedes`).
   - `mls_call_leave_cleanup(group_id)` → wipe local group state (one DELETE + OpenMLS
     delete walk).
   - `mls_call_heartbeat(group_id)` → HPKE-only self-update commit (the §1.3-legal shape),
     staged pending like any outbound commit. Cadence/stagger policy is client-layer (6.4);
     native just provides the primitive.
   - `mls_call_state(group_id)` → roster with per-member verification status, epoch,
     lifecycle/poisoned/desynced flags — display data only, no key material.
6. **Exporter → frame keys (`mls/keys.rs`, §1.5 byte-exact).**
   - `media_base_secret = MLS-Exporter("acutest-media-frame:v1", group_id_bytes, 32)`;
     `frame_key(sender) = HKDF-SHA256(ikm=base, salt="", info="acutest:media:sender:v1" ||
     0x00 || user_id || 0x00 || device_id || 0x00 || epoch_be64, L=32)`.
   - `mls_call_frame_keys(group_id)` → `[{livekit_identity: "{user}:{device}", user_id,
     device_id, key_index: epoch mod 16, frame_key_b64}]` for the current epoch (+ previous
     during the Add-grace rotation overlap). The SINGLE sanctioned egress (§7.2);
     exporter/epoch secrets never leave `keys.rs`.
   - Lag telemetry: warn at receiver lag 8, desync threshold well before 16 (§1.5 wrap rule).

7. **Crash-safe commit transaction (§3.3).**
   - Inbound: ONE `TxGuard` wraps OpenMLS storage writes (ambient via step 1b) + epoch
     bookkeeping + processed-envelope replay horizon; caller acks the envelope only after
     commit returns Ok.
   - Outbound: OpenMLS pending-commit staged locally; `merge_pending_commit` on DS Won;
     `clear_pending_commit` + rebase on Lost (never apply an unconfirmed own commit).

8. **Tests (unit + first adversarial wave — `e2ee-core/tests/mls_adversarial.rs`).**
   - Unit: canonical parity vectors; storage roundtrip + AAD-swap rejection; v4→v5
     migration (fresh + upgrade); backup exclusion (T-13 shape); frame-key derivation
     fixed vectors; keyIndex mapping + wrap warn; KP replenish accounting; last-resort
     retention behavior per the step-1 ruling.
   - Adversarial (fail-closed asserts, `hostile_server.rs` structure):
     **unsolicited Welcome (no matching intent) rejected — gate headline**;
     cross-group Welcome (T-15 native leg); phantom join intent w/ unverifiable signature
     (T-05 leg); tampered credential binding rejected; identity-changed pin invalidates
     leaf (T-11 leg); epoch gap parks, never skips (invariant 10); poisoned winning commit
     → successor-needed state, no deadlock (T-17 native leg); racing own-commit Lost →
     rebase without forking (T-04 native leg); secrets never in returned wire
     payloads/errors (T-09 grep-shape).

9. **Gate.** e2ee-crypto-reviewer (primary) + media-e2ee-reviewer on the full diff.
   Checklist must include: unsolicited-Welcome rejection (carried), §1.3 leaf-mutation
   rule, §1.5 derivation exactness, §3.3 tx atomicity, §5.5 backup exclusion, canonical
   byte-parity vs model.rs, and the step-1 last-resort ruling.

## Step-1 feasibility verdicts (recorded 2026-07-10, against vendored 0.8.1 source)

- **(a) Last-resort: CONFIRMED, upstream-supported.** `KeyPackageBuilder::mark_as_last_resort()`
  attaches the RFC `last_resort` extension (key_packages/mod.rs:479); Welcome processing
  explicitly skips `delete_key_package` for last-resort bundles
  (group/mls_group/creation.rs:605 — `if !key_package_bundle.key_package().last_resort()`).
  The init private key is retained by OpenMLS itself; no carve-out hack needed, single-use
  accounting uncorrupted. v1 keeps the last-resort package with the planned 7-day lifetime.
- **(b) Ambient tx: CONFIRMED.** `StorageProvider<CURRENT_VERSION>` is a fully synchronous
  `&self` trait (openmls_traits 0.5 storage.rs); a provider over the store's `Connection`
  inside a `TxGuard` participates in the ambient transaction by construction. The
  snapshot-pickle fallback is NOT needed. `OpenMlsProvider` composes crypto/rand
  (openmls_rust_crypto::RustCrypto) with our storage — a per-call composed struct.
- **(c) R-3 record:** openmls_rust_crypto 0.5.1 pulls `rand 0.8.6` (same major as ours),
  `sha2 0.10.9`, `hkdf 0.12.4`, `chacha20poly1305 0.10` (ours is 0.11 — coexists),
  `ed25519-dalek 2.2`, `tls_codec 0.4.2`. rand 0.9/0.10 appear elsewhere in the workspace
  tree but not on this path. No unification friction.
- Serialization contract mirrored from `openmls_memory_storage` 0.5: storage key =
  `label || serde_json(key) || u16_be(version)`, values = serde_json entities, list
  semantics (append/remove_item) for proposal refs + own leaf nodes.

## Judgment calls to surface at the gate

- Credential identity-bytes encoding: JSON envelope `{payload, binding_signature}` inside
  BasicCredential (self-describing, mirrors wire.rs conventions) rather than concatenated
  raw bytes. The canonical PAYLOAD is byte-exact per model.rs; the envelope is local
  framing that never crosses to the server unparsed by us.
- `mls_groups`/`mls_join_intents` as dedicated bookkeeping tables (not stuffed into the
  `mls_state` KV): the plan's §3.2 DDL sketch names only `mls_state` + `mls_signature_key`,
  but durable join intents are REQUIRED for the carried unsolicited-Welcome defense, and
  lifecycle bookkeeping needs queryable columns. All are backup-excluded alike.
- Heartbeat/admit scheduling (stagger timers, 10-min cadence, grace windows) lives in the
  client layer (6.3/6.4); native exposes primitives only. Matches the §3.1 surface list.
- Native does not consume `ResponseFetchMlsCommits` pagination policy — gap-refetch is
  caller-driven; native only signals `epoch_gap` with the range needed.

## Status

- [x] 1 pinning + feasibility spike (last-resort CONFIRMED upstream, ambient-tx CONFIRMED,
      R-3 recorded) — `openmls =0.8.1` / `openmls_rust_crypto =0.5.1` /
      `openmls_traits =0.5.0` / `tls_codec =0.4.2` pinned exact
- [x] 2 storage provider (`mls/storage.rs`, sealed under the new `mls` HKDF subkey) +
      schema v5 (`mls_state`/`mls_signature_key`/`mls_groups`/`mls_join_intents`/
      `mls_key_packages`) + `EXPORT_SCHEMA_VERSION` 4→5 + backup exclusion (§5.5)
- [x] 3 credential binding (`mls/credential.rs`) + canonical contexts (`canonical.rs`,
      pinned parity vectors matching model.rs byte-for-byte)
- [x] 4 KeyPackage lifecycle (`mls_publish_key_packages` / `mls_replenish_check` /
      `mls_expire_key_packages`, last-resort zeroize-on-replacement)
- [x] 5 group lifecycle engine (`mls/mod.rs`: create/join_intent/admit/process/
      leave_cleanup/heartbeat/remove; poisoned-epoch → successor; commit_won/lost)
- [x] 6 exporter → frame keys (`mls/keys.rs`, byte-exact §1.5, pinned derivation vector)
- [x] 7 crash-safe commit tx (single `TxGuard` around OpenMLS storage + epoch bookkeeping
      + replay horizon; outbound staged-until-DS-win)
- [x] 8 unit + adversarial tests — 11 in `tests/mls_adversarial.rs` (incl. UNSOLICITED
      WELCOME refusal, cross-group T-15, poisoned T-17, gap inv-10, lost-commit T-04,
      backup-exclusion T-13, scrub T-09, happy-path key agreement + heartbeat rotation)
      + 4 canonical/keys unit tests. All green (`cargo test`: 46 across the crate).
- [x] 9 gate (e2ee-crypto-reviewer primary + media-e2ee-reviewer) — BOTH **SHIP-WITH-FIXES**,
      no CRITICAL/HIGH. All 7 mandatory checklist items verified to the pinned OpenMLS source
      + server canonical mirror. Fixes folded (below); 14 adversarial + parity tests green.

## Gate outcome (2026-07-11)

Both reviewers **SHIP-WITH-FIXES (PASS)**, no CRITICAL/HIGH. Unsolicited-Welcome refusal
(carried 6.1 item), §1.3 leaf-mutation rule, §1.5 derivation exactness, §3.3 tx atomicity,
§5.5 backup exclusion, canonical byte-parity, and the last-resort ruling all confirmed clean.

**Folded before landing (folded 2026-07-11):**
- **[code bug caught by a new test]** `mls_call_remove` pin-verified EVERY leaf incl. our own
  → `UnknownIdentity` on self (a device never pins itself). Now locates the target by
  `credential_identity_unverified` (locating a leaf to remove needs no trust; the Remove is
  MLS-authenticated). New 3-party `processed_remove_*` test.
- **[media MEDIUM]** Staged-commit crash/reconnect could silently fork: `mls_call_commit_won`
  now REQUIRES the DS-authoritative `won_epoch` and cross-checks it against the pending
  commit (`current_epoch+1`), refusing on mismatch or when no commit is staged. Added
  `mls_call_pending_commit_epoch` so 6.3 can reconcile a dangling stage after a crash.
  New `commit_won_refuses_wrong_epoch_and_without_pending` test. (Enforced reconnect check
  is a 6.3 gate item.)
- **[both LOW]** `MlsProcessOutcome.removed` now exposes the removed (user,device) set from
  the StagedCommit (MLS truth) so 6.4 drives the §1.5 Remove-immediate send-key switch.
- **[crypto LOW]** `process_welcome` now asserts the MLS protocol version (`Mls10`) alongside
  the ciphersuite floor.
- **[crypto LOW]** storage AAD gains a `0x00` label/key separator (breakdown step 2).
- **[crypto LOW]** T-05 Welcome-path leaf rejection now has a dedicated test
  (`welcome_with_unpinned_leaf_is_rejected_wholesale`).
- **[media LOW]** old-epoch "duplicate" no longer persists a processed-envelope marker (the
  epoch comparison is the idempotency guard; avoids a DS-relabel withholding-marker).
- **[media LOW]** deterministic KeyPackage nomination tiebreak (`key_package_ref ASC`) +
  documented that the nominated ref is advisory (admitter may seal to a different package),
  which is why the Welcome gate keys on group_id, not the ref.
- **[crypto INFORMATIONAL]** derivation test now pins a HARDCODED KAT byte vector (catches an
  HKDF/HMAC library swap, not just info-construction).

**Carried to 6.3/6.4 (documented, non-blocking):**
- **[MEDIUM, 6.3]** `group_id ↔ channel_id` has no cryptographic anchor the joiner can check
  (rests on DS honesty + loud roster-reconciliation backstop). 6.3 must verify the DS
  create/join response `channel_id` against the intended channel before signing the intent —
  named T-15 client-leg gate item so it doesn't evaporate at the IPC boundary.
- **[6.3]** Enforce the `commit_won`-only-on-authoritative-`Won` reconnect check (native
  primitive now exists).
- **[6.3]** Ack-and-drop envelopes for poisoned/wiped groups (caller policy; native returns
  the error).
- **[6.4]** Roster reconciliation (SFU∪MLS) is the loud backstop several LOW trust-boundary
  items lean on — must land in 6.4 for invariant 7 / phantom defense to be end-to-end.

## Deferred to 6.3+ (out of 6.2 scope, tracked here)

- IPC wiring of `e2ee_call_*` commands (3 sync points + capability grant) — sub-slice 6.3.
- `mls/mod.rs` exposes primitives only; admitter stagger / heartbeat cadence / leave
  grace / retry timers are the client layer's (6.3/6.4).
- The engine surface takes `user_id` as a parameter (the shell supplies the session
  user); 6.3 threads it from the Tauri session.
