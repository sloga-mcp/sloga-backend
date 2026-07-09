# Sloga E2EE — Key Backup & Recovery (design, rev 2)

Status: rev 2, updated 2026-07-08 for the slice-5 baseline (store schema v3:
group conversations + pinned rosters, `user_verified` safety-number bindings,
`sender_user_id` attribution) and concretized for implementation. Rev 1 was
drafted 2026-07-07 before slice 5 landed. Promotes "passphrase-encrypted key
backup" out of the implementation plan's **Explicitly deferred** list.
Parent design: `docs/e2ee-design.md`; plan: `docs/e2ee-implementation-plan.md`
(this lands as slice 5.5). Sequenced AFTER the slice-5 FINAL FULL AUDIT —
this feature adds a key-egress surface and must not land before the audited
baseline exists. **That gate is satisfied: the slice-5 final audit passed
(SHIP WITH FIXES, all blockers applied) on 2026-07-08.**

## 1. Problem

Today (slices 2–5) the desktop identity key is generated at opt-in and
stored DPAPI-wrapped, bound to the Windows user on that machine (Keystore on
Android). The local SQLite store is the ONLY history for E2EE DMs and group
DMs. Consequences:

- Reinstall / new machine / OS reinstall / lost disk ⇒ identity gone,
  history gone, peers see an "identity key changed" warning (correct but
  scary), all sessions re-handshake as a stranger, every safety-number
  verification is void.
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
| Device identity (Ed25519 + Curve25519 keys, device_id) | in the backup blob (account pickle) |
| ⇒ no "identity changed" warning; peers' pins of US stay valid | follows from identity |
| ⇒ server-side device row, queue, blobs still addressed to you | device_id unchanged (see §6.4 for the revoked-row case) |
| Message history — text, markers, sender attribution (`sender_user_id`) | in the blob (history section) |
| DM **and group** conversation state (kind, sticky-encryption timestamps, downgrade state) | in the blob |
| Pinned group rosters (`group_members`, incl. active/announced/removed status) | in the blob — a restored group re-encrypts to the same pinned audience |
| Our pins of peers (`peer_identities`) incl. `binding_verified` AND `user_verified` | in the blob — TOFU state and in-person safety-number verifications survive |
| Encrypted-attachment metadata + per-file content keys | in the blob (rows only; ciphertext files are not — §4.4) |
| Replay horizon (`processed_envelopes`) | in the blob — a replayed old envelope stays deduplicated after restore |

Not restored (by design): live Olm sessions (re-established fresh via the
existing pre-key handshake on next send/receive — automatic, no user
action); one-time-key and fallback private halves as *served* material
(server-published OTKs and the fallback for the device are
replaced-and-republished on restore, see §6.3 — stale private halves inside
the restored account pickle are inert); local attachment ciphertext files
(restored rows whose server blob still exists degrade to re-fetchable,
else `expired` — honest about loss, existing UI states); the local
DPAPI/Keystore master key and its HKDF subkeys (a **fresh master is minted
at restore**; local wrapping keys never leave the machine they were minted
on — §4.3).

Slice-5 delta note (why rev 2 exists): the rev-1 table predates schema v3.
The blob now MUST carry `conversations.kind/downgraded_at/
peer_downgraded_by/pending_downgrade`, the `group_members` roster,
`peer_identities.user_verified`, and `messages.sender_user_id` — otherwise a
restore silently demotes groups to broken DMs, loses in-person verification
state, and strips group attribution. The export whitelist in §4.2 is the
authoritative field list.

## 3. Recovery code

- One-time secret displayed at creation as **12 groups of 5 Crockford
  base32 symbols** (`XXXXX-XXXXX-…`, 60 symbols = 300 bits sampled directly
  from OS CSPRNG via rejection sampling — comfortably above the 256-bit
  target; the code IS the secret, no byte-decoding round trip). Canonical
  form for KDF input: uppercase, separators stripped, Crockford ambiguity
  folding applied (`I`,`L`→`1`, `O`→`0`). Copy button + "I stored it"
  confirm. Re-viewable never; re-generatable anytime while logged in with
  keys present (new code ⇒ new salt ⇒ new key ⇒ new blob; the old blob is
  replaced server-side and the old code becomes useless). No check digit in
  v1 — a mistyped code fails the AEAD cleanly; considered and deferred.
- KDF: **Argon2id** over the canonical code string, random 16-byte salt.
  Parameter profiles: desktop `m=256 MiB, t=3, p=4`; Android
  `m=64 MiB, t=3, p=4` (low-RAM devices; the blob header carries the actual
  parameters, so any device can restore any blob). The Argon2id output is
  fed through **HKDF-SHA256 with info = `"sloga-e2ee-backup-v1"`** (domain
  separation lives in HKDF, since Argon2 has no context input) to produce
  the 32-byte AEAD key.
- The derived key AEAD-encrypts the backup blob (**XChaCha20-Poly1305** —
  24-byte random nonce; chosen over the 12-byte variant because refresh
  re-uses the backup key across many encryptions, §4.5). Primitives already
  in e2ee-core's dependency set.
- The recovery code and the moment-of-derivation key exist ONLY in native
  memory (zeroized after use) and in the dedicated native-owned UI surface
  (§7.2); they never enter the REMOTE webview, never appear in
  errors/logs (invariant-6 test pattern). A **code-equivalent derived key**
  is additionally persisted locally, sealed under the store master key
  (§4.5), so refresh works without re-entering the code. To be precise
  (L6): this IS a decryption-equivalent of the code at rest, but it gains a
  device-local attacker nothing — the full store is already readable with
  local DPAPI/Keystore there — and the *code itself* (the portable,
  restore-anywhere secret) is never persisted on device or server.
- **Zeroization scope (M4):** the largest secret concentration is not the
  code but the serialized plaintext PAYLOAD (§4.2) — it holds the raw
  account pickle, every decrypted message body, and every unsealed
  attachment key. On BOTH export and restore, the plaintext payload buffer,
  every raw-secret field inside the payload struct, and all re-seal
  intermediates are held in `Zeroizing`/zeroized after use, alongside the
  code and derived key. The §10 "no key material lingers" test asserts the
  payload buffer is zeroized, not just the code.
- The server sees: an opaque header (KDF salt/params + binding fields, §4.1)
  + ciphertext. A malicious server can delete the backup (availability) but
  never read it. Brute-force is bounded by ≥256-bit code entropy, not by
  the KDF — the KDF is defense in depth for any future shorter-code
  variant.

## 4. Backup blob

Versioned, single blob per (user_id, device_id), created/refreshed natively.

### 4.1 Format

The header and ciphertext are stored and transmitted as **two separate
fields** (server columns `header` + `ciphertext`; API fields likewise), NOT
one concatenated blob — so there is no in-band delimiter to get wrong (M6 is
resolved by separation rather than a length prefix). The restorer uses the
exact received `header` bytes verbatim as AAD.

```
header = canonical serialization (single-line JSON, fixed field order) of {
           v: 1,
           kdf: { alg: "argon2id", m_kib, t, p },
           salt: base64(16 bytes),
           nonce: base64(24 bytes),
           user_id, device_id,
           generation: u64,
           created_at: unix seconds
         }                                   // plaintext, server-visible
ciphertext = XChaCha20-Poly1305(key, nonce, payload, AAD = header_bytes)
```

- **Separate fields, verbatim AAD (M6):** header and ciphertext travel as
  distinct fields, so there is no concatenation to mis-parse. The restorer
  MUST use the **exact received `header` bytes** as AAD — never a
  re-serialized copy. Any canonicalization drift on re-serialize would break
  legitimate blobs; the round-trip test in §10 pins byte-identical AAD (and
  proves a semantically-equal-but-re-serialized header fails).
- **The header is the AAD.** Any tamper — bit-flip, KDF-parameter swap
  (downgrade-the-KDF attack), salt swap, generation rewrite, user/device
  rebinding, header swap onto another ciphertext — fails authentication.
  `generation`/`user_id`/`device_id` are deliberately duplicated between the
  header and the server's own columns: the server needs them as data, and the
  header binding makes the server-held copies tamper-evident at restore
  (§6.2, §8). The PUT handler cross-checks the body generation against the
  header's parsed generation (§5, M2) so the two copies can never diverge.
- **KDF-parameter clamp at restore (M1):** the header's `m_kib/t/p` are
  attacker-tamperable (server-visible, unsigned by anything the restoring
  device trusts a priori). Argon2id runs on these params BEFORE the AEAD
  check, so an unclamped restore is a resource-exhaustion DoS (a hostile
  header sets `m=4 GiB` and OOMs a low-RAM device — multiplied by device
  count, since GET returns every device blob). Native MUST validate params
  against `[BACKUP_KDF_M_MIN=8 MiB, BACKUP_KDF_M_MAX=512 MiB]`,
  `[t: 1..=10]`, `[p: 1..=4]` and reject out-of-range as a typed
  `BackupKdfParamsRejected` BEFORE deriving. The server also range-checks the
  header on PUT as defense in depth.

### 4.2 Payload (the export whitelist)

The payload is a versioned serde struct (`payload_v: 1`), serialized as
JSON inside the AEAD. Export is an **explicit whitelist** — a raw store-file
copy was considered and rejected: deny-by-default means a future schema
table can never ride into the key-egress surface unreviewed, at the cost of
bumping `payload_v` when the schema grows (enforced by a test pinned to
`SCHEMA_VERSION`, §10).

Included (complete against store schema v3):

| Section | Fields |
|---|---|
| `account` | vodozemac account pickle (RAW `AccountPickle`, not the locally-encrypted form — the AEAD is the encryption), `device_id`, `identity_signature`, `created_at` |
| `peer_identities` | user_id, device_id, curve25519, ed25519, **binding_verified**, **user_verified**, status, pending_curve25519, pending_ed25519, first_seen, updated_at |
| `conversations` | conversation_id, **kind**, encrypted_since, **downgraded_at**, **peer_downgraded_by**, **pending_downgrade** |
| `group_members` | conversation_id, user_id, **status** (active/announced/removed), added_at, removed_at |
| `messages` | id, conversation_id, direction, **sender_user_id**, sender_device_id, kind, content (PLAINTEXT — see §4.3), sequence, detail, created_at |
| `attachments` | local_id, message_id, idx, conversation, direction, blob_id, **file key RAW** (unsealed — see §4.3), digest, size, name, mime, state, created_at. Only attachments already bound to a message row (`message_id IS NOT NULL`) are exported — abandoned/unsent outbound drafts are deliberately not backed up (L1); their GC (`stale_unsent_attachments`) is unaffected because restored rows all carry a real `created_at`. |
| `processed_envelopes` | id, processed_at |
| `meta` | truncated: bool, earliest_kept_message_at (when truncated, §4.4) |

Excluded, deliberately: `sessions` (live ratchets — the §2 rule; their
absence after restore IS the "mark stale" mechanism: zero sessions ⇒ the
existing bundle-handshake machinery runs on next traffic in both
directions); the local master key and every HKDF subkey; the sealed forms
of anything (no DPAPI/Keystore-wrapped bytes in the blob); `backup_state`
(§4.5 — re-derived from the entered code at restore); signed fallback/OTK
public rows (regenerated and republished at restore, §6.3).

### 4.3 Key hygiene: fresh master at restore, raw secrets inside the AEAD

Message bodies and attachment file keys are stored locally encrypted under
HKDF subkeys of the DPAPI/Keystore-wrapped master. The export decrypts them
and places PLAINTEXT/RAW values inside the AEAD payload; restore mints a
**fresh master key** on the new machine and re-seals everything under its
new subkeys. Rationale: the local wrapping hierarchy never leaves the
machine it was minted on, a compromise of the old machine's wrapped
`master.key` file is worthless against the new install, and the blob is
self-contained (restorable with the code alone). The alternative — shipping
the master key in the blob so sealed rows copy verbatim — was rejected for
coupling every future machine to the oldest machine's master.

No compression, v1. Compress-then-encrypt leaks plaintext redundancy
through ciphertext length, and group peers author part of this plaintext
(a chosen-prefix side channel, CRIME-family). Sloga-scale text history fits
uncompressed (§4.4). Considered and rejected; revisit only with a
padding/bucketing scheme.

### 4.4 Size

History-dominated. Hard cap: **8 MiB ciphertext** (`E2EE_MAX_BACKUP_SIZE`,
server-enforced on PUT; fits MongoDB's 16 MB document limit with headroom —
S3 offload à la `e2ee_blobs` is the escape hatch if ever needed, not v1).
If a store outgrows the cap, the export keeps the account, all pins, all
conversations, all rosters — and the most-recent message/attachment rows
that fit; `meta.truncated` is set and the UI says so (no silent
truncation). Attachment ciphertext FILES are never in the blob; restored
rows whose local file is absent are remapped `ready → pending` when
`blob_id` is present (re-fetchable while the server blob lives), else
`expired`.

`processed_envelopes` is pruned to the server-TTL replay horizon (L2):
only ids newer than `now - 30d` (the envelope TTL) are exported. Older
envelopes are server-deleted and can never be replayed, so retaining their
ids wastes cap space (they could dominate an 8 MiB budget on a chatty
account) and crowd out real history.

### 4.5 Refresh cadence and local state (store schema v4)

New `backup_state` row (singleton, like `account`), added by e2ee-core
migration v3→v4:

```
backup_state (
  id = 1,
  key_sealed BLOB,        -- 32-byte backup AEAD key, sealed under a new
  key_nonce  BLOB,        --   HKDF subkey "backup" (AAD = "backup_state")
  salt       BLOB,        -- the KDF salt (goes into every header)
  kdf_params TEXT,        -- the profile used at creation
  generation INTEGER,     -- last generation BUILT locally
  uploaded_generation INTEGER,  -- last generation CONFIRMED stored by server
  created_at INTEGER,     -- when the CODE was minted
  refreshed_at INTEGER,   -- when the blob was last built
  messages_at_refresh INTEGER   -- messages-table count at last build
)
```

- Refresh triggers (computed natively; the webview can only ask): engine
  open with `now - refreshed_at > 24h`, or ≥ 50 new message rows since
  `messages_at_refresh`, debounced. `backup_refresh_if_due()` returns
  `None` or the upload bundle `{header, ciphertext_b64, generation}` —
  ciphertext only, so it may cross IPC like any envelope.
- Refresh re-uses the sealed backup key (code unchanged), same salt, fresh
  24-byte nonce (hence XChaCha20: random-nonce collision margin stays
  comfortable under one key across years of daily refreshes), and bumps
  `generation` monotonically — **the generation sequence never resets, not
  even on code rotation** (rotation swaps key+salt but continues the
  counter; a reset would let a hostile server serve a stale pre-rotation
  count without contradiction... the counter is also inside the AAD-bound
  header, see §6.2).
- After a successful PUT, the bridge reports the server's echoed generation
  back to native (`backup_mark_uploaded`); native advances
  `uploaded_generation` and drives the local optimistic nag state.
- **Durability under a compromised webview is NOT client-verifiable by any
  signal (H3 — honest statement).** Native has no network; the webview
  couriers EVERY server interaction. Two consequences, both accepted:
  1. The `backup_mark_uploaded` echo is only an optimistic local hint — the
     webview knows the built generation (it holds the upload bundle) and can
     report a correct echo WITHOUT performing the PUT.
  2. `GET /e2ee/backup/status` does NOT rescue this. Its response is
     unauthenticated plaintext metadata that the webview itself couriers, so
     a hostile webview fabricates a healthy status just as easily as it
     fakes the echo. Displaying it in the native surface does not
     authenticate bytes that arrived through the compromised courier.
  Therefore, under a fully compromised webview, backup durability cannot be
  proven client-side. Confidentiality and INTEGRITY are untouched (the
  webview can neither read nor forge the AEAD blob — a stolen/forged blob
  fails restore); this is purely a DURABILITY/availability gap. The status
  endpoint remains useful against a HONEST server (surfacing genuine
  "never stored / behind" states and driving the nag) — it is simply not a
  defense against a hostile webview. The ONLY true closure is carried risk
  #1 (bundle the frontend into the installer + restrictive CSP, removing
  server-delivered JS from the loop); §8 documents this residual honestly.
  A nonce-signed status endpoint (server signs `{nonce, device_id,
  generation, exists}` under a native-pinned key) was considered as a real
  mechanism and deferred: it adds a server signing identity + pinned-key
  distribution for a durability-only property that carried risk #1 already
  subsumes.

## 5. Server surface (stoatchat)

New `e2ee_backups` model, both drivers, migration **rev 53** (bump
`LATEST_REVISION` to 54):

```
e2ee_backups {
  _id: "{user_id}:{device_id}",
  user_id, device_id,
  header: String,          // opaque canonical header bytes (server never parses beyond size checks)
  ciphertext: String,      // base64, ≤ 8 MiB decoded
  generation: u64,
  created_at, updated_at: Timestamp,
}
```

Unique index (user_id, device_id). Routes under the existing `/e2ee` mount,
behind `features.e2ee_enabled`, bots refused, all following the existing
route-module pattern. **All four routes MUST be registered in
`openapi_get_routes_spec!` (`routes/e2ee/mod.rs`) and the client MUST use
raw `fetch` for them, not the generated typed client** (M7 — the stoat-api
typed client silently drops bodies for routes missing from its generated
tables; a dropped `PUT /e2ee/backup` body stores nothing, a dropped
`replace_one_time_keys` defaults it to false and silently skips the OTK
replacement §6.3 depends on):

- **`PUT /e2ee/backup`** — upsert own blob. Requires a session **bound to
  the asserted `device_id`** (`assert_bound_session`, int-H3 parity — only
  a device that has proven its identity key can write its backup). The
  server **parses the (canonical single-line JSON) header, extracts its
  `generation`, and rejects any PUT where `body.generation !=
  header.generation`** (M2) — the two deliberately-duplicated copies can
  never diverge, so a compromised webview cannot poison the column with
  `u64::MAX` in the body to permanently wedge future PUTs while the
  AAD-bound header says otherwise. Also range-checks the header KDF params
  (M1 defense-in-depth). `generation` must be **strictly greater** than the
  stored row's (first write: any value ≥ 1); a stale-or-equal generation is
  a **no-op 200 that echoes the STORED generation** — the stale/replayed
  bundle never overwrites the newer stored blob (replay refused), PUT is
  idempotency-safe, and a live client whose built generation disagrees with
  the echo detects a server-side wedge (§4.5). The generation increment is
  also magnitude-bounded (`MAX_BACKUP_GENERATION_JUMP`): a PUT more than that
  far above the previously-stored value (0 for a first write) is refused.
  This bounds the counter well away from `i64::MAX` (so it can never be
  pinned at the ceiling where no increment is possible) — but note it does
  NOT fully close the compromised-webview backup-WEDGE: a hostile webview can
  still send ONE PUT at `floor + bound` (header and body agreeing on the big
  value) that overwrites the good blob and sets a generation the honest local
  counter (which steps by 1) will never reach, no-op-ing all future
  legitimate PUTs. This is an H3-class durability residual under active
  compromise, recoverable only via the MFA-gated DELETE (§8). It is NOT
  self-healable client-side, because under a fully compromised webview the
  client cannot distinguish a real server-ahead from a faked one — the same
  reason H3 holds. Size caps on header (≤ 1 KiB) and ciphertext (≤ 8 MiB
  decoded). Ratelimit: existing `e2ee` bucket (10).
- **`GET /e2ee/backup`** — the restore path. The restoring device has NO
  keys yet, so a device-bound session is impossible by construction; gate
  with a fresh MFA **`ValidatedTicket`** (single-use, 5-minute TTL,
  consumed on match — the first-key-publication pattern) **with an explicit
  `ticket.account_id == user.id` bind** (M8 — the `ValidatedTicket` guard
  proves *some* account did MFA, not that it is THIS user; a key-egress
  route must bind them) + a NEW tight ratelimit bucket `e2ee_backup_get`
  (limit 3, added to `util/ratelimits.rs` via
  `("e2ee", Some("backup"), Method::Get) => ("e2ee_backup_get", None)`,
  L5). Returns ALL of the authenticated user's backups (`[{device_id,
  generation, header, ciphertext, updated_at}]` — a user restores with one
  code but may hold one blob per device; native tries the entered code
  against each, §6.1). Own-account only; empty list is an honest 200.
- **`GET /e2ee/backup/status`** — settings-card/nag support: metadata ONLY
  (`[{device_id, generation, updated_at, size}]`, no header, no
  ciphertext). Device-bound session required (any of the user's devices),
  no MFA — zero key egress. Existing `e2ee` bucket. Drives the nag against
  an HONEST server; it is NOT a defense against a hostile webview (its
  response is webview-couriered and unauthenticated — §4.5 H3).
- **`DELETE /e2ee/backup/<device_id>`** — MFA-`ValidatedTicket`-gated (same
  `account_id == user.id` bind, M8); own-user scope. Also cascaded from
  `User::delete`.

The device-revocation cascade (`DELETE /e2ee/keys/{device}`, session
revoke, account-deletion path for sessions) does **NOT** delete the backup
— revoking a lost device must not destroy the recovery path for it. Backup
deletion is only ever the explicit MFA-gated route or account deletion.

**`PUT /e2ee/keys` gains `replace_one_time_keys: bool` (default false).**
When set the server deletes ALL stored one-time keys for the device before
inserting the new batch. Constraints (L3): device-bound sessions only (same
as republish), and the flag is **honored only with a NON-EMPTY new batch**
— so a compromised webview cannot append `replace_one_time_keys:true` to a
live-device publish to strip a device's OTKs (which would silently degrade
peers to the reused fallback key). Restore needs this (§6.3): OTKs
published after the backup snapshot have private halves the restored
account never had; leaving them consumable wedges new inbound sessions. A
test asserts it deletes exactly the target device's OTKs — not another
device's, not another user's. Fallback replacement already works via the
existing fallback-rotation semantics.

**Durable server-visible metadata (M5).** Unlike envelopes (deleted on
ack), an `e2ee_backups` row PERSISTS and exposes, per device: that an E2EE
backup exists, the `device_id`, the ciphertext `size` (≈ total history
volume, ≤ 8 MiB), `created_at`, `updated_at` (≈ last-active), and a
monotonic `generation` that never resets even across code rotation (≈ a
durable refresh counter accumulating over the account's life). This exceeds
the transient envelope-metadata set and is documented as an accepted
extension in §8. `generation` is server-visible because the server needs it
for the monotonicity/replay check; `size`/`updated_at` exposure is accepted
(bucketing deferred).

## 6. Restore flow (native-driven end to end)

### 6.1 Happy path

1. Fresh install, user logs in, starts the E2EE opt-in flow. Before minting
   a fresh identity, the client asks (one MFA prompt → ValidatedTicket →
   `GET /e2ee/backup`): blobs exist ⇒ offer **"Restore from recovery
   code"** vs **"Start fresh"** (fresh = today's behavior: new identity,
   peers warned). No blobs ⇒ straight to today's enable flow.
2. The code is entered in the **native-owned recovery surface** (§7.2) —
   it never enters the remote webview. The webview couriers only the
   ciphertext blobs (it already fetched them; they're opaque). Native
   canonicalizes the code, derives the key per blob header (each blob's own
   salt/params), and attempts AEAD open per blob — typically one or two;
   a few seconds of Argon2id each is fine for a rare flow.
3. Wrong code ⇒ every AEAD fails ⇒ typed error, retry; no partial state.
   Header/AAD checks (§6.2) run before any row is written.
4. Success ⇒ atomic store rebuild (§6.2), then re-keying (§6.3), then
   normal engine open. Peers see NO identity-change warning (same keys,
   same device_id) and every safety-number verification (`user_verified`)
   they or we recorded still stands.

### 6.2 Verification and crash-atomicity

Before writing anything, native verifies on the opened payload:
- header AAD authenticated (implicit in AEAD open) — covers KDF-param,
  salt, generation, and user/device binding tamper;
- `header.user_id == authenticated user` (a foreign blob can't decrypt
  anyway — different code — but check-and-say-so beats a generic failure);
- `payload.account.device_id == header.device_id`;
- server-echoed generation == header generation. A mismatch means the
  server's column lies about the blob it served — LOUD error, restore
  refused (tampering, not loss).
- Rollback honesty: the restoring device has no local expectation to
  compare against, so true rollback detection at restore is impossible;
  instead the confirm screen shows `created_at` + generation prominently
  ("Backup from 2026-07-08, version 41 — continue?") so a months-stale
  serve is human-visible. Alive devices DO have the expectation and verify
  every PUT echo (§4.5). Documented limit (§8).
- **Stale-restore downgrade consequence (M3):** the whitelist captures
  `downgraded_at`/`encrypted_since`, so restoring a snapshot taken while a
  conversation was DOWNGRADED (before a later re-enable that the snapshot
  predates) brings back the downgraded state → `ConversationRow::encrypted()`
  is false → `send_mode` returns `Plaintext` for a conversation the peer now
  holds as encrypted. To keep restore fail-closed, **restore promotes every
  restored conversation whose snapshot state is plaintext-eligible into a
  local `peer_downgraded_by = "restore"` prompt state** — i.e. the FIRST
  post-restore send is gated by the existing local downgrade-confirm dialog
  (slice-5 machinery) rather than silently going plaintext. Re-encrypting is
  one tap; the user is never silently dropped to plaintext by a stale blob.
  §10 tests a stale `downgraded_at`.

Rebuild sequence — **crash-safe at every boundary**; `restore.pending` is
the write-ahead journal. The rename order is deliberate (H1): `store.db`
lands BEFORE `master.key`, so any mid-rename crash leaves the fail-CLOSED
"db present, master absent" state, which `load_or_create_master` already
rejects as `StoreCorrupt` (it refuses to mint a fresh master over an
existing db — store.rs). The reverse order would leave "master present, db
absent" → an empty db minted under a valid fresh master → a
silently-empty-but-provisioned store sending plaintext. That inversion is
the bug this ordering closes.

```
1. write  dir/restore.pending           (marker: restore in progress)
2. build  dir/store.db.restore          (fresh SQLite, v4 schema, fresh
                                         master key; all rows re-sealed
                                         under the new subkeys)
3. write  dir/master.key.restore        (protector-wrapped fresh master)
4. fsync  both files + the directory
5. rename store.db.restore   → store.db     (DB first — see H1 above)
6. rename master.key.restore → master.key
7. fsync  the directory
8. delete restore.pending
```

**`Store::open` performs the marker check as its UNCONDITIONAL FIRST
operation** — before `load_or_create_master`, before any
`Connection::open` (which would otherwise CREATE an empty db). Marker
present ⇒ classify by what else is on disk:
- both `store.db` and `master.key` present (crash between 6 and 8 — restore
  actually COMPLETED, only the marker delete was lost, L4): treat as
  SUCCESS — delete the marker and any `*.restore` remnants, open normally.
  The completed store is kept, not discarded.
- otherwise (crash between 1 and 6 — genuinely incomplete): delete
  `store.db*`, `master.key`, and every `*.restore` remnant, surface a typed
  loud `RestoreIncomplete`, and the user re-runs restore with their code.
  Safe because a mid-restore store holds nothing that exists only locally —
  the server blob is still the source.

**`is_provisioned()` is made marker-aware (H1):** a directory containing
`restore.pending` is treated as NOT cleanly provisioned, and the
`send_mode` fast path in both shells routes such a directory to a
FAIL-CLOSED verdict (engine open, which hits `RestoreIncomplete`) rather
than returning `Plaintext`. A half-restored install must never answer
"no store ⇒ Plaintext"; it must refuse to send until the restore is
completed or abandoned. (This tightens the existing filesystem-only
`is_provisioned`; the security-critical direction is that a
partially-restored directory can never silently downgrade.)

Restore refuses to run over a cleanly-provisioned store (existing
`store.db`/`master.key`, no marker) — wiping live state is the wipe flow's
job, with its own native confirm.

### 6.3 Post-restore re-keying (before first use)

In the restored store, sessions are absent by construction (§4.2) — every
conversation re-handshakes via the existing bundle machinery on next
traffic, exactly like the established stale-session path. Then:

- **Reconstruct `backup_state`** (gate HIGH-1): restore seals the
  code-derived key under the FRESH master and writes a `backup_state` row
  with `generation = uploaded_generation = the restored blob's generation`
  (salt/params from the header). Without this the generation counter would
  restart at 1, the server (already holding the blob at generation N>1)
  would refuse every subsequent PUT as stale while returning a misleading
  200-echo, and the user could be led to trust a freshly-minted code that
  matches no stored blob — a silent recovery-integrity loss precisely after
  the feature's main use. With it, the next refresh builds `N+1 > N` and
  uploads normally.

- **Rebind the device to the new session** via the existing bonfire
  device-claim challenge (the restored identity key signs the
  session-bound nonce) — after which device-bound routes accept us.
- **Replace served key material**: generate a fresh fallback key and a
  fresh OTK batch; `PUT /e2ee/keys` with `replace_one_time_keys: true`.
  Stale server-side OTKs (published post-snapshot, private halves lost)
  become unclaimable; in-flight prekey messages that already consumed them
  surface as the existing honest `undecryptable` marker on drain. The
  stale OTK/fallback private halves INSIDE the restored pickle are inert
  (never again served, so never again targeted).
- **Drain the queue normally** — anything sent to the old install's live
  sessions while we were dead decrypts nowhere and files the
  `undecryptable` marker (honest, bounded loss; identical to today's
  stale-session behavior).

### 6.4 Edge cases

- **Device row revoked while dead** (the lost machine's session was
  remotely logged out ⇒ `revoke_devices_for_session` deleted the identity
  row): restore proceeds; the republish is a FIRST publication for the
  server (same device_id, same identity keys) and needs a second
  MFA-ValidatedTicket — up to two MFA prompts total in this path,
  accepted. Peers who pinned us hold status `revoked` and observe the
  re-publish as the existing loud `device_readded` marker (same keys ⇒ NO
  identity-change warning, sends unblock on reconcile).
  **Client (2026-07-08):** a rejected post-restore claim, once corroborated
  against `GET /e2ee/devices/{self}` (a truly ABSENT row, not a transient
  reject), raises a reactive `reenrollNeeded` that drives the second MFA'd
  first-publish (`finishReenroll`) via an auto-opened re-enroll modal. Gated
  SHIP WITH FIXES by two reviewers (crypto + frontend) 2026-07-08; the security
  core is fail-closed (no plaintext/downgrade/egress). This recovery is now
  DURABLE across dismissal and restart — **see the HIGH-1 closure in §8**
  (re-derivable native payload + `#onClaimResult` re-detection on every
  reconnect + a persistent Security & Privacy affordance).
- **The old install is still alive** (restore was used as "copy", not
  "recover"): two installs now hold the same device identity. They fight
  over the device binding (each bonfire claim rebinds
  `last_session_id`), and whichever consumes an inbound prekey message
  first wins that session while the other files `undecryptable` markers.
  No key-reuse hazard arises (the two installs never share ratchet state —
  sessions were never in the blob), but the UX is degraded and confusing.
  Restore copy says plainly: "Only restore if that computer no longer runs
  Sloga." Documented; matches Signal's re-registration semantics.
- **Same machine, store intact**: nothing changes — DPAPI store persists
  across logout by design; the backup only enters the picture when the
  local store is gone.

## 7. UX

### 7.1 Placement and states

- Opt-in flow gains a step: after key publish, "Create your recovery code"
  (skippable, with an explicit "no backup = unrecoverable" warning).
- Settings card (operator decision 2026-07-08): under **Security &
  Privacy**, directly beneath the E2EE opt-in toggle (not Sessions) —
  backup is only meaningful once the toggle is on; encryption and its
  recovery live together. Card shows backup status from
  `GET /e2ee/backup/status` + local `backup_state`: exists/never-created,
  last-stored date, truncated flag, and a LOUD warning state when
  `uploaded_generation < generation` (built but never stored) or the last
  PUT echo mismatched. The no-backup nag banner lives here and on the
  E2EE toggle confirmation.
- Rotate code / delete backup sit behind an identity re-auth (password /
  MFA ticket, same pattern as the wipe flow). There is deliberately NO
  "reveal stored code" affordance: the code is never persisted anywhere
  (device or server), so the only re-auth-gated action is minting a NEW
  code — which replaces the old blob and invalidates the old code (§3).
  Considered and rejected: keystore-persisted reveal-in-settings (widens
  stolen device+password blast radius from "live keys on this device" to
  "portable identity+history restore anywhere").
- Copy must say the true thing: "Anyone with this code and access to your
  account can read your message history. Sloga cannot recover it for
  you."

### 7.2 The native-owned recovery surface (code display + entry)

`tauri_plugin_dialog` has no text input, so the wipe-confirm pattern can't
carry code entry. Desktop uses a **dedicated recovery window whose content
ships in the installer**: a separate `WebviewWindow` (label
`e2ee-recovery`) served from a Rust-registered custom URI scheme
(`e2ee-ui://`, embedded HTML via `include_str!` — the same in-process
custom-protocol machinery as `e2ee-att`). The remote `app.sloga.gg` window
(the standing remote-webview-trust risk) can REQUEST that the window open,
and nothing else — it never sees the code in either direction.

**Window-label scoping ALONE is not a sufficient boundary (H2).** In Tauri
v2 a capability binds to a window LABEL, so "grant the recovery capability
to the window labelled `e2ee-recovery`" is only safe if the remote window
cannot create or navigate a window into that capability. The design
REQUIRES all of the following, each pinned by an adversarial test (§10);
an implementer must satisfy every one, not just the label check:

1. **The recovery capability is `local` context only** — no `remote` /
   URL-remote grant. Even a window that somehow loads remote content cannot
   invoke the recovery commands.
2. **It is ALSO scheme/URL-scoped to the `e2ee-ui://` origin**, not just to
   the label — belt and suspenders over (1).
3. **The main (`app.sloga.gg`) window has NO window-creation permission**
   (`core:webview:allow-create-webview-window` etc. are absent from its
   capability), and cannot mint a window carrying the reserved
   `e2ee-recovery` label. Opening the recovery window is done from RUST
   (a plain, argument-free IPC command the remote window may call), which
   is the only creator of that label.
4. **The recovery `WebviewWindow` is navigation-locked to `e2ee-ui://`** —
   an `on_navigation` handler rejects any navigation off the scheme, so the
   window can never be steered to remote content post-open.
5. **The `e2ee-ui://` protocol handler serves the fixed bundled bytes for
   ALL paths and queries** (ignores/normalizes the request path), and
   refuses to serve any window whose label ≠ `e2ee-recovery` — no
   path-traversal or query-driven content injection.
6. **The bundled recovery HTML carries a strict CSP** (`default-src 'none'`;
   `script-src 'self'`/inline-hash only; no `connect-src` to anything —
   zero remote resources, no network), so even a content bug in the bundled
   page cannot exfiltrate over the network.

This is a deliberate, narrow amendment to invariant 6 ("key material never
crosses IPC"): the recovery code crosses between Rust and the
installer-bundled recovery window ONLY, under the six controls above. That
surface is in the same trust class as native code (shipped, signed, not
server-delivered); the invariant's intent — no key material reachable by
REMOTE content or any webview the server can influence — holds. §10 tests:
a remote-content or attacker-labelled window cannot obtain the recovery
capability nor invoke either recovery command; the code never appears in
any event/IPC payload addressed to another window.

Rejected alternatives: raw Win32 input dialog (strongest isolation, but
unreviewable-quality UI code and no copy affordance — did not clear the
beats-vs-risk bar, though it remains the fallback if the six controls prove
fragile in review); entry in the main remote webview (violates the
invariant outright). Because this is the single most dangerous surface in
the slice, the implementation diff's reviewer pass scrutinizes these six
controls specifically.

Android: the code surface is a native `AlertDialog` (display: TextView +
copy; entry: EditText) from `E2eePlugin`, wipe-dialog parity — no webview
involvement at all.

Clipboard: the copy button places the code in the OS clipboard at the
user's explicit request — readable by other local apps (desktop) or
clipboard-access apps (Android; mitigated with
`ClipDescription.EXTRA_IS_SENSITIVE`). Same exposure Signal accepts;
documented, not mitigated further in v1.

## 8. Threat model deltas

- **New egress surface**: the backup blob is the first artifact containing
  private key material that deliberately leaves the device. Mitigation:
  AEAD under a ≥256-bit code the server never sees; creation/restore paths
  native-only; invariant-6 tests extended to the backup path and the
  recovery window (§7.2).
- **Compromised webview** (the standing remote-webview-trust risk): the
  webview couriers only ciphertext in both directions; the code lives in
  native UI. A hostile webview can trigger a backup refresh (no gain —
  same ciphertext channel it can't read); **silently defeat backup
  durability** by suppressing the PUT while faking BOTH the
  `backup_mark_uploaded` echo AND a healthy `GET /e2ee/backup/status`
  response (both are webview-couriered plaintext — §4.5 H3). This is a
  DURABILITY/availability gap only: confidentiality and integrity hold (the
  webview can neither read nor forge the AEAD blob). It is NOT closed
  client-side by any signal; the only true closure is carried risk #1
  (bundle the frontend + CSP), and it is documented as such rather than
  papered over. Attacks that the webview CANNOT mount: read/forge the blob
  (AEAD); replay an OLD upload bundle to roll back a live device's backup
  (refused — server-side strict generation monotonicity + header/body
  generation cross-check, §5 M2); strip a live device's OTKs via
  `replace_one_time_keys` (refused — flag honored only with a non-empty
  batch, §5 L3); or extract the recovery code by requesting the restore
  window (native surface = user in the loop, and the §7.2 H2 controls keep
  the code off any window the webview can reach).
  - **Durable backup wedge (accepted H3-class residual, NOT claimed fixed):**
    a hostile webview CAN overwrite the good blob with one PUT at
    `floor + MAX_BACKUP_GENERATION_JUMP` (§5) and set a stored generation the
    honest local counter never reaches, no-op-ing future legitimate PUTs. The
    magnitude bound keeps this off the `i64::MAX` ceiling but does not remove
    it, and it is not client-self-healable for the SAME reason H3 holds (the
    client cannot tell a real server-ahead from a faked one over the
    compromised courier — a "sync local up to the server" heal just relocates
    the wedge). Confidentiality/integrity untouched; recovery is the explicit
    MFA-gated DELETE + re-create, and the true closure is carried risk #1.
- **Hostile server**: can withhold or delete the blob (availability); can
  attempt rollback — detected by alive devices on every PUT echo, and at
  restore made human-visible (created-at/generation on the confirm screen)
  though not machine-detectable there (§6.2, documented limit); cannot
  read, forge, or graft (AEAD + header-as-AAD binds kdf-params, salt,
  generation, user, device); cannot usefully swap another user's blob into
  the response (different code ⇒ derivation fails; plus explicit user_id
  check).
- **KDF-downgrade via header tamper**: header is AAD — weakened `m/t/p` or
  a chosen salt breaks authentication. (The derived key depends on the
  header's salt/params, so a tampered header ALSO derives a different key;
  either way: clean failure.)
- **KDF resource-exhaustion at restore (M1)**: a hostile header sets huge
  `m/t` to OOM/hang the restoring device BEFORE the AEAD check runs. Closed
  by clamping header params to `[BACKUP_KDF_*_MIN, MAX]` before deriving
  (both native and, defensively, server-side on PUT).
- **Durable backup metadata (M5)**: the persistent `e2ee_backups` row leaks
  to the server, per device: backup existence, `device_id`, ciphertext
  `size` (≈ history volume), `created_at`, `updated_at` (≈ last-active), and
  a monotonic `generation` (≈ lifetime refresh counter). This EXCEEDS the
  transient envelope-metadata set and is an ACCEPTED extension of the
  documented metadata surface (bucketing deferred).
- **Stale-restore plaintext downgrade (M3)**: a stale snapshot could carry a
  since-reversed `downgraded_at` and drop a conversation to plaintext.
  Closed by routing every plaintext-eligible restored conversation through
  the local downgrade-confirm prompt on first post-restore send (§6.2) —
  never a silent plaintext drop.
- **Compression oracle**: none — no compression (§4.3).
- **Rubber-hose / stolen code**: code + account access = full history.
  Documented; matches Signal's model. MFA on the GET narrows "stolen code
  alone" — the code without the account's second factor retrieves nothing.
- **Stolen unlocked device**: the sealed backup key (§4.5) adds nothing —
  the same attacker already reads the whole local store via local DPAPI.
- **Clipboard**: §7.2, documented residual.
- **Revoked-device restore recovery IS NOW DURABLE (HIGH-1, CLOSED 2026-07-09;
  two-reviewer gate SHIP WITH FIXES).** Was: the §6.4 re-enroll opportunity
  lived only in the in-memory `reenrollNeeded` flag + a CONSUME-ONCE native
  republish payload, so a single dismissal (Not now / backdrop / ESC) OR an
  app/webview restart before `finishReenroll` stranded the device
  provisioned-but-receive-broken with no in-app recovery and no way to re-run
  restore (`StoreAlreadyProvisioned`). Confidentiality/integrity were never at
  risk and the state was FAIL-CLOSED (`send_mode` keys off local store state,
  never server publish state ⇒ `Encrypt`/hard-error, never plaintext) — an
  availability dead-end only. **Closed by three parts:**
  1. a NATIVE re-derivable first-publish payload — `e2ee_backup_rederive_republish`
     (desktop Tauri command / Android Capacitor `call()` arm) re-runs the
     re-callable `post_restore_rekey` (public-key-only export; the audited
     AEAD/KDF/pickle crypto is untouched);
  2. DURABLE re-detection in `#onClaimResult` — when a device claim is rejected
     and this device's row is a CONFIRMED-absent (`#ownDevicePresence`
     tri-state: present/missing/**unknown**, folding the old GET-error-as-present
     LOW) it re-derives the payload and re-raises `reenrollNeeded`, on EVERY
     reconnect until re-enrolled. **Placement note (corrected during
     implementation):** a restored store carries `published = true` (restore
     imports the source device's published flag), so a stranded restored device
     is NOT provisioned-**un**published — it re-challenges on reconnect and the
     server rejects it (revoked row), which is why the durable re-detection
     lives in the claim-rejection path, not a `!published` branch;
  3. a PERSISTENT Security & Privacy affordance ("Finish restoring on this
     device") driven by `reenrollNeeded`, plus the original auto-modal kept only
     as a backstop.
  Folded sub-findings: MEDIUM (modal backdrop/ESC not gated by `busy()`) closed
  via a `guardedClose` backdrop guard + an id-scoped controller dismiss-lock for
  ESC; a root-cause MFA-flow fix (dismissing the `mfa_flow` modal now settles its
  callback as a cancel, so ESC during the second MFA prompt can no longer strand
  `reauth()` in a permanent busy state — HIGH, frontend gate); LOW
  present-vs-unknown distinction (above).
- **Post-restore re-derive is a webview-reachable local key-churn primitive
  (accepted webview-availability residual, 2026-07-09).** `e2ee_backup_rederive_republish`
  is a `with_engine` command, so the standing remote-webview-trust actor can call
  it on demand. On a healthy device this rotates the served fallback +
  regenerates OTKs locally; two calls WITHOUT a republish discard the fallback
  secret the server still advertises, so peers that establish a session against
  it produce `undecryptable` prekey messages until the next legitimate republish.
  This is AVAILABILITY-only (no confidentiality/integrity loss; AEAD + identity
  intact) and in the SAME trust class as the already-accepted "webview suppresses
  the courier" / "durable backup wedge" residuals — a compromised webview can
  already `enable`/`wipe`-request to grief. It is NOT closable by the reviewer's
  suggested `!published` guard: a stranded (legitimately re-deriving) device is
  `published = true` (see the placement note above), so that guard would reject
  the real recovery path AND the restore-time rekey (it breaks
  `post_restore_rekey_yields_a_fresh_one_time_key_batch`). True closure = carried
  risk #1 (bundle the frontend + CSP); a cheaper future hardening would be a
  non-fallback-rotating re-derive (top up OTKs + rebuild the payload from the
  current fallback), deferred.

## 9. Explicitly out of scope (v1)

- Cross-device backup merge (each device backs up its own store; restore
  takes exactly one device's blob). Android *parity* — same blob format,
  Keystore-sealed `backup_state`, AlertDialog surfaces — IS in scope for
  this slice (slice 4's store exists).
- Continuous per-message-key backup (Matrix-style incremental) — the
  snapshot model is simpler and the blob is small at Sloga's scale.
- S3 offload of blobs (8 MiB cap suffices; §4.4).
- Changing the logout story: logout still never wipes; wipe stays behind
  the native confirm.
- Check digit in the code; compression; reveal-stored-code (§3, §4.3,
  §7.1 — considered and rejected).

## 10. Adversarial tests (definition of done)

Native (e2ee-core, + shell-level for the window scoping):
- wrong code fails clean — no partial store, typed error, retry works;
- tampered blob rejected: ciphertext bit-flip; header bit-flip; header
  swapped onto another ciphertext; KDF params weakened; salt swapped;
  generation rewritten; user_id/device_id rebound — every one a clean
  AEAD/verification failure;
- byte-identical legitimate blob round-trips; a re-serialized but
  semantically-equal header FAILS (proves verbatim-received-bytes AAD, M6);
- header KDF params out of `[MIN,MAX]` rejected BEFORE derivation
  (`BackupKdfParamsRejected`) — no OOM/hang path (M1);
- stale snapshot with an old `downgraded_at` restores into the local
  downgrade-confirm state, NOT a silent plaintext send-mode (M3);
- cross-user swap: another user's (validly encrypted) blob under MY code
  fails; under THEIR code fails the user_id check loudly;
- restore is atomic under crash at EVERY step boundary of §6.2 (kill
  between each numbered step; reopen either finds the old state absent +
  `RestoreIncomplete`, or the fully-restored store — never empty-but-
  provisioned, never half-sealed);
- restored identity byte-identical (same Ed25519/Curve25519/device_id;
  peers' pins verify); restored store carries: group conversations with
  kind+roster (re-encrypt targets the pinned audience), `user_verified`
  flags, `sender_user_id` attribution, downgrade state, attachment rows
  remapped ready→pending/expired correctly, processed_envelopes (a
  replayed pre-restore envelope is still deduplicated);
- sessions table empty after restore; next send establishes a FRESH
  session (and the old install's ratchet, if somehow replayed, never
  matches);
- OTK replace-republish: after restore the publish payload carries a fresh
  fallback + fresh OTKs; with `replace_one_time_keys` the server holds
  ONLY the new batch (old ids gone);
- second restore with a rotated-away old code fails (new salt/key);
- export whitelist is pinned to `SCHEMA_VERSION` — bumping the store
  schema without touching the export module fails a test;
- truncation: an over-cap store exports with `truncated: true`, identity/
  pins/conversations/rosters complete, newest messages kept;
- no code / derived key / master key / any key material in: IPC payloads
  (except the recovery-window channel), errors, logs, the upload bundle,
  or the server-visible header; recovery IPC commands refuse every window
  label except `e2ee-recovery`; a remote-content or attacker-labelled
  window cannot obtain the recovery capability nor invoke either recovery
  command (§7.2 H2 controls 1–6); zeroization on the code, derived-key AND
  the serialized plaintext-payload buffers (M4).

Server (both drivers, `--test-threads=1` parity with the existing e2ee
suites):
- `GET /e2ee/backup` refuses without a ValidatedTicket, refuses a ticket
  whose `account_id != user.id` (M8), consumes the ticket on success; tight
  `e2ee_backup_get` bucket enforced;
- `PUT` refuses unbound sessions, web-token sessions, wrong-device
  bindings, bots; refuses generation ≤ stored (echoes stored); refuses a
  body generation ≠ the header's parsed generation (M2); refuses out-of-
  range header KDF params (M1); refuses over-cap header/ciphertext; accepts
  and echoes strictly-increasing generations;
- `DELETE` refuses a ticket whose `account_id != user.id` (M8);
- `replace_one_time_keys:true` with an EMPTY batch does NOT strip OTKs
  (L3);
- `GET /e2ee/backup/status` refuses non-device-bound sessions; returns
  metadata only (response shape contains no header/ciphertext);
- `DELETE` refuses without ValidatedTicket; deletes own row only;
- device revocation (`DELETE /e2ee/keys/{device}`, session revoke) leaves
  the backup row intact; `User::delete` cascades it away;
- `replace_one_time_keys` deletes exactly the device's OTKs (not another
  device's, not another user's);
- feature-flag off ⇒ every backup route 400s (existing pattern).

**Gate: e2ee-crypto-reviewer audit (key-egress surface — heaviest scrutiny
on the blob construction, KDF/AEAD use, restore atomicity, and the
MFA-gated GET) BEFORE implementation; a second reviewer pass on the
implementation diff.**
