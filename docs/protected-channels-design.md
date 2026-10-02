# Protected Channels: Design Contract (Slice 1, Foundation)

Status: **W0 CONTRACT** (written 2026-10-01 against `origin/acutest` 781122d9, desktop
`origin/master` f566be7, frontend `origin/main` 49ac438d).
Source of truth for scope: the approved plan `cozy-cooking-pretzel.md` ("Protected Channels:
Roadmap + Slice 1"). This document pins every format, rule and surface that the later waves
(W1 backend data, W2 backend routes, W3 native, W4 SDK + frontend) implement. Where this
document and the plan disagree, the plan wins on scope and this document wins on formats;
report the disagreement.

How to read it:

- **MUST / MUST NOT / SHOULD** are normative.
- Every choice the plan did not fix is marked **DECISION (W0):** so the wave audit can check
  it. Section 12 indexes them.
- "Server" means the delta/database backend; "native" means `e2ee-core` (+ the Tauri command
  layer in `src-tauri/src/e2ee.rs`); "bridge" means `components/client/e2ee.ts`; "SDK" means
  stoat.js.
- Related documents: `docs/e2ee-design.md` (device model, section 8 enforcement notes),
  `docs/e2ee-media-mls-plan.md` (MLS stack this reuses: section 1.2 to 1.5, 2, 3, 5.6).

---

## 0. Conventions used by every format below

### 0.1 Identifier charsets

| Name | Format | Length | Notes |
|---|---|---|---|
| user id, channel id, server id, message id | ULID, Crockford base32, UPPERCASE, `[0-9A-HJKMNP-TV-Z]` | 26 | as minted by the server today |
| client message id (`cid`) | ULID, same charset, minted by the SENDER's native layer | 26 | see 3.6 |
| device id | lowercase hex `[0-9a-f]` | 32 | `is_valid_device_id` (existing) |
| group id | lowercase hex `[0-9a-f]` | 64 | `is_valid_group_id` (existing); text derivation in 3.1 |
| Ed25519 public key | b64 of 32 bytes | 43 | the vodozemac identity key, as already published |
| Ed25519 signature | b64 of 64 bytes | 86 | |

**b64** everywhere in this document means the standard alphabet (`A-Z a-z 0-9 + /`),
**unpadded**, canonical (`base64::engine::general_purpose::STANDARD_NO_PAD`, the house
encoding of the existing E2EE and MLS models). Decoders MUST reject padding, whitespace,
the URL-safe alphabet and non-canonical trailing bits.

### 0.2 Integers and times

Integers in canonical text are ASCII decimal, no sign, no leading zeros (`0` itself is `0`),
no separators. Timestamps are milliseconds since the Unix epoch, UTC. Epochs are MLS epochs
(`u64` natively, `i64` server-side, always `0 <= epoch <= 2^53 - 1` so JSON numbers survive
JavaScript).

### 0.3 Newline-canonical payloads

Every signed text payload in this document follows the house pattern of
`models/mls/model.rs` and `e2ee-core/src/canonical.rs`:

- UTF-8; lines joined by a single LF (`0x0A`); **no trailing LF**; no CR; nothing trimmed.
- The first line is a versioned domain-separation context string.
- Every field is charset-constrained so it can never contain LF, `,` or `:` where those are
  separators. Builders MUST **reject** an out-of-charset input; nothing is ever escaped.
- Labeled lines are `label:value` with no space after the colon.
  **DECISION (W0):** the new formats use labeled lines (the `identity_payload` style) rather
  than the bare positional lines of the MLS builders, because two of them carry lists that
  can be empty and an empty labeled line (`replies:`) is unambiguous on sight.

### 0.4 Context strings (WIRE FORMAT, never rename)

| Literal | Used for | Section |
|---|---|---|
| `sloga/text/v1` | MLS exporter label for the epoch key | 3.3 |
| `sloga-text-v1` | AAD context field | 3.5 |
| `sloga-text-sig-v1` | message signature payload | 3.7 |
| `sloga-text-group-v1` | text group id derivation | 3.1 |
| `sloga-seat-list-v1` | seat list body | 4.1 |
| `sloga-owner-handover-v1` | owner handover statement | 4.6 |

The first three are fixed by the plan. The last three are **DECISION (W0)**. Like the
existing `acutest:e2ee:*` literals, each is a protocol constant: changing one is a protocol
migration with a compatibility matrix, never a find-and-replace. Native and server each
carry their own copy and the section 5 vectors pin them byte-for-byte.

---

## 1. Scope and threat model

### 1.1 Slice 1 scope

**In:** the `protected` channel flag and an admin-granted entitlement; the owner protects a
channel and seats members explicitly with an owner-signed seat list; one MLS **text** group
per protected channel; encrypted text send, receive and history on Tauri desktop
(Windows/macOS); fail-closed refusals on server and client; a static shield and a "Not
available on this device" state; flag `[features.protected_channels]`, OFF by default.

**Out (refused or absent in S1):** attachments (refused), message edits (refused), history
for new members or new devices, billing, Android/Linux/Electron/iOS/web composers, franking,
animation, the permission-loss reconciler, admin delegation of signing, whole-server mode,
protecting a channel that already has messages.

**HOLD (plan finding 12):** no production flag-on and no non-admin grant until S2 ships. S1
does not react to a seated member losing ViewChannel (see 6.4); the owner sees "seated without
access" and must unseat by hand.

### 1.2 Trust model

The server is a **Delivery Service plus directory**: it stores ciphertext, arbitrates one
commit per epoch, keeps the seat registry and relays the owner-signed seat list. It holds no
group secret, epoch secret, exporter output, epoch key or message key, ever (locked decision
4 of the media plan, unchanged).

The trust anchor is the **owner-signed seat list** plus the owner identity **pinned on each
member's device** (section 4). Membership growth requires the signed list; membership
shrinkage needs no signature.

A hostile or compromised server (or an operator with database access):

| Can | Cannot |
|---|---|
| Read all metadata: who is seated, who sends, when, to which channel, ciphertext length, and reactions (plaintext emoji metadata, 7.4) | Read message text or reply targets (both inside the ciphertext) |
| Withhold, delay, reorder or drop messages, commits and Welcomes (availability) | Make a member accept a message under a forged sender: the Ed25519 signature is checked against the identity key bound in the sender's MLS leaf at that epoch (3.9) |
| Strip the `protected` flag in API responses | Make a pinned client send plaintext or upload a file: the local protected pin (9.4) refuses |
| Withhold a server-forced removal (kick/ban/leave) or falsely clear `pending_removals` | Make a member re-admit the removed user without a newer signed list (6.2 forced-removal memory) |
| Suppress an owner unseat from MEMBERS: refuse to sequence every commit from the owner's device and keep serving the old list to every other member. Members stay green; the owner's own shield goes `unverified` (residual R11) | Do so once ANY commit carrying the newer list is sequenced: every text commit embeds the committer's full signed seat list in MLS `authenticated_data` (3.12), and every member verifies and adopts it under its owner pin before decrypting |
| Make a member decrypt a commit whose embedded seat list is forged or signed by an unpinned key, or use an older embedded list to re-admit someone a newer list dropped | Every receiver verifies the embedded list BEFORE decrypting, and a failure is a poisoned epoch, loud (3.12.3). An older valid list is never adopted, and Adds are always checked against the newest held list (3.12.3 steps 3 and 6) |
| Serve an older seat list to a client that has seen a newer one | Make that client accept it: anti-rollback (4.4) |
| Claim a different owner (`server.owner`) | Make a client accept a seat list from a non-pinned signer without a pinned-key handover or a blocking native confirmation (4.5) |
| Inject plaintext messages into a protected channel's history | Make them render as normal messages: they render as a loud marker (9.3) |
| Relay a Welcome for a different channel's group | Make the joiner accept it: the text group id is derived from the channel id (3.1) and checked before any key derivation |
| Register an extra device for a seated user (directory control) | Do so invisibly: a "new device joined" marker is shown; see residual R1 |

### 1.3 Documented residuals (accepted for S1)

- **R1. Injected extra device of a seated user.** The server controls the device directory. A
  device it registers for a seated user U will be TOFU-pinned and admitted by members (U is on
  the signed list and within `device_cap`), and can then read the channel. This is the same
  risk as E2EE DMs. Mitigation: a visible "new device joined" marker (9.3) and slice-5 safety
  numbers. Not closed in S1.
- **R2. Non-repudiation.** Messages are signed with the long-term vodozemac identity key, so
  authorship is provable to third parties (unlike deniable Olm). This is deliberate (it is
  what S9 franking and reporter-side reports build on) and must be stated in the consent copy.
- **R3. Megolm-like epoch-key retention.** Native keeps every epoch key it ever derived
  (`mls_text_epoch_keys`) so history stays readable. Compromise of a device's store reveals
  all history that device could read; there is no forward secrecy at rest. MLS forward
  secrecy still covers the in-transit handshake.
- **R4. History lost on logout or a new device until S4.** Text tables are excluded from key
  backup in S1. A new device of a seated user reads only messages from its join epoch on.
- **R5. Welcome stranded by the queue budget until S2.** A Welcome dropped by the per-device
  E2EE queue depth cap leaves the joiner without group state. The joiner's join-intent retry
  (3 retries, media plan 1.4 step 5) then ends in the loud failure state; catch-up is S2.
- **R6. Length and timing metadata.** Ciphertext length tracks plaintext length (no padding in
  S1, **DECISION (W0)**); send times, sender ids and reactions are visible to the server
  (reply targets are not: they are inside the ciphertext).
- **R7. Colluding removed member + server.** A removed member keeps the epoch keys of the
  epochs it was a member of and can sign valid messages at those epochs. A colluding server
  can insert them into history at any position. Live injection is caught (3.9 step 9); a
  forged backdated history entry is not, beyond the timestamp-skew marker (3.9 step 11).
- **R8. Server-forced removal is availability-trust.** Kick, ban, leave and account deletion
  remove the user from the group only if the server reports them (6.3). The security-bearing
  removal is the owner's signed unseat, itself subject to R11.
- **R9. Commit retention.** Text commits older than `commit_retention_days` (default 30) are
  pruned. A device offline longer than that cannot catch up and must rejoin (history for the
  gap is lost until S2/S4).
- **R10. Send-time check races.** The server's epoch and membership checks on send (7.3) are
  not atomic with commit arbitration; a send can land at epoch `e` while a commit to `e+1`
  wins. Receivers handle this (3.9 step 9).
- **R11. A hostile server can suppress an owner's unseat (rewritten in W0 fix round 2).** The
  server chooses which commits it sequences and serves `GET .../seats`. It can refuse to
  sequence the owner's Remove commit and keep serving the old list. It cannot forge or
  rewrite a seat list, and every text commit embeds the committer's full signed list in its
  `authenticated_data` (3.12). So the moment ANY commit that carries the newer list is
  sequenced (the owner's Remove, any later owner Update, or a commit by any member that
  fetched the new list), every member verifies and adopts it before decrypting, and its
  `_encrypt` refuses until the unseated user's leaves are removed.
  **Precise extent:** an honest delivery service refuses any commit whose embedded list is
  not its newest (6.1), so with an honest server a stale committer cannot commit at all
  until it holds the newest list. A HOSTILE server can still sequence commits from members it
  keeps on the old list, so to suppress the unseat it must (a) refuse every commit from the
  owner's device and (b) keep every other member on the old list, indefinitely. That is
  narrower than the round-1 position, but it is not "the whole group must stall". The owner
  detects it: its own commits never win, and its own `_encrypt` refuses (the unseated user
  is off its list), so its shield goes `unverified`. Members detect nothing until an owner
  commit is sequenced. Closing this fully (owner-signed epoch attestations, S2) is deferred.
- **R12. Owner device loss freezes seat changes.** If the owner's pinned device is lost
  (logout, wipe, dead hardware), nothing can sign a new seat list, create a successor group
  or sign a handover. **DECISION (W0-fix):** in S1, seat changes FREEZE. Existing members keep
  chatting, and server-forced removals and member-committed Removes of pending-removal users
  still work. But no one can be seated or unseated by list, and a poisoned group cannot be
  replaced (the channel then stays `resecuring`). Recovery (succession, handover from a lost
  device) is S2.
  **W0-fix3, corrected in W0-fix4:** the lost owner device's leaf stays in the group. The DS
  refuses every Remove of the current list signer's device except the rejoin case (6.1), and
  receivers accept such a Remove only with a verified rejoin intent from that device
  (3.12.3 step 6). A lost device sends no rejoin intent, so its leaf is never removed, even
  if the device was revoked. That is deliberate. (A device can never remove itself: OpenMLS
  `CannotRemoveSelf`.) The current list stays valid because the signer-leaf check runs only
  when a NEWER list is adopted (4.4), so every later commit, which still embeds that
  owner-signed list, keeps being accepted and members keep chatting. Removing the owner's
  device would instead have made every later commit unverifiable and killed the channel. A
  device that merely WIPED its state (not lost) recovers through the rejoin case (6.3).
- **R13. Inactive devices keep their compromise.** The Update cadence (3.11) is per device
  and triggered on open or send. A device that is never opened and never sends never issues
  an Update, so a past compromise of that device's leaf stays exploitable until it updates
  or is removed. Accepted for S1; S2 may add owner-driven Removes of long-idle devices.
- **R14. Denial of service (restated in W0-fix3).**
  - *Hostile server:* it can always deny service. It can refuse every commit or send, or
    sequence a commit whose embedded list fails verification so receivers take the
    poisoned-epoch path. The 3.12 checks make each of these a loud failure, never a silent
    acceptance; they cannot keep the channel available.
  - *Repeated eviction (W0-fix5; qualified in W0-fix6):* **against an HONEST DS**, a member
    cannot repeatedly evict a device (including the owner's) by reusing that device's
    rejoin intent. Every intent is consumed by the commit that uses it, and the intents of
    added devices are consumed at admission (2.5 step 5). Rule 6 also only counts an intent
    created after the device's latest (re-)Add (`member_added`). Each eviction therefore
    needs a fresh rejoin intent signed by the device itself, which only a device that really
    wiped its state sends.
    A HOSTILE DS can replay an old signed intent in `rejoin_intents`. Receivers partly catch
    that (corrected in W0-fix7). Native records every consumed rejoin-intent signature per
    group and refuses a replay (`ReplayedRejoinIntent`, poisoned path, 3.12.3 step 6), but
    that record is each device's OWN history. A device that processed the original eviction
    refuses the replay. A device that joined later has no record and merges it. So a replay
    can produce SPLIT verdicts across members: older devices take the poisoned path, newer
    joiners merge.
    This is hostile-DS-only (an honest DS consumed the intent, 2.5 step 5), and the split
    surfaces LOUDLY on the older devices (`ReplayedRejoinIntent`, `unverified`). It is
    therefore a loud fork plus a DoS, never a silent eviction seen by everyone.
  - *Malicious seated member, honest server (restated in W0-fix4):* the member cannot embed a
    fake, old or tampered list (the AD check sits inside the commit transaction, 3.12.2).
    It also cannot get a Remove of the owner's device or of arbitrary users MERGED. The DS
    checks only the declared `removed` list (6.1). A commit whose actual removes differ from
    its declaration (under-declared) or whose declaration lists a device it does not really
    remove (over-declared) passes the DS but fails every receiver's declaration binding
    (3.12.3 step 6). That includes the undeclared same-commit replacement: Remove(X) plus
    Add(X's claimed KeyPackage) with empty declarations has an empty CREDENTIAL diff, but
    every receiver refuses it twice over (W0-fix8):
    - the proposal-level rule, because an Add credential equals a Remove target;
    - the leaf-identity diff, because X's replaced leaf counts as remove plus add against
      empty declarations.

    The precise claim is therefore not "cannot remove" but "any attempt, declared or not,
    becomes a poisoned epoch at every honest receiver, never a silent removal, a silent
    replacement, or a silently cleared pending removal".
    Exactly as in calls, the member CAN force a successor group: it submits a commit the DS
    accepts (the DS cannot see inside the ciphertext) but members cannot process, such as a
    mis-declared commit, a bad leaf credential, an over-cap Add, an off-list Add or malformed
    MLS content (3.12.3 step 6, poisoned path).
    Successor creation is owner-device-only (6.1). While the owner's device is available this
    is a liveness cost (members show `resecuring` until the owner's device recreates the
    group, and history before the successor stays readable locally). With the owner's device
    lost it is a freeze (R12). The offending member stays identifiable as the committer; S2
    may add owner-driven expulsion.

---

## 2. Data model (W1)

### 2.1 The `protected` channel flag

- `protected: bool` on `Channel::TextChannel` (`#[serde(default, skip_serializing_if = "crate::if_false")]`
  or the local equivalent), on `PartialChannel` (`Option<bool>`), on the v0 `Channel::TextChannel`
  and in `util/bridge/v0.rs` both directions.
- NOT in `FieldsChannel`, `DataEditChannel` or `DataCreateServerChannel`: no client route can
  set or clear it except `PUT /channels/:id/protect` (7.2).
- **One-way invariant.** Once true it is never false. `Channel::update` MUST refuse a partial
  with `protected: Some(false)` on a protected channel (`ChannelProtected`); setting it true is
  only done by the protect route. No migration ever writes false.
- Only server `TextChannel`s can be protected (not DMs, groups, voice-only or forum channels).

### 2.2 `channel_entitlements` (new collection, both drivers)

Type name `ChannelEntitlement`.

| Field | Type | Notes |
|---|---|---|
| `_id` | String | ULID |
| `channel_id` | String | **unique index** |
| `server_id` | String | |
| `source` | enum `ChannelEntitlementSource` | S1: `AdminGrant` only. Reserved for S5: `Prot`, `Crowdfund` |
| `slot_cap` | u32 | `1..=100` (**DECISION (W0)**: capped at the S1 group leaf cap) |
| `device_cap` | `Option<u32>` | `None` = use `default_device_cap`; `0` = unlimited (still bounded by 100 leaves) |
| `state` | enum `ChannelEntitlementState` | S1: `Active`. Reserved: `Grace`, `Frozen`, `Deleted` (S5) |
| `granted_by` | String | privileged user id |
| `created_at` | Timestamp | |

Effective device cap = `entitlement.device_cap.unwrap_or(config.default_device_cap)`.

### 2.3 `channel_seats` (new collection, both drivers)

Type name `ChannelSeat`.

| Field | Type | Notes |
|---|---|---|
| `_id` | String | `{channel_id}:{user_id}` |
| `channel_id` | String | index (**DECISION (W0)**: explicit fields beside the composite id, for queries) |
| `user_id` | String | index |
| `seated_at` | Timestamp | last time the seat became active |
| `released_at` | `Option<Timestamp>` | set on release |
| `cooldown_until` | `Option<Timestamp>` | `released_at + 14 days` |

- A seat is **active** when `released_at` is `None`; it is **cooling** when released and
  `now < cooldown_until`. Seats used = active + cooling. `SEAT_COOLDOWN_DAYS = 14`.
- Seat claims are **atomic**: the conditional count (`seats used + newly seated <= slot_cap`)
  and the writes happen under the driver's atomicity primitive (Mongo transaction or a
  conditional update on a per-channel counter; Reference driver under its single Mutex).
  Racing claims MUST NOT exceed `slot_cap` (W1/W2 test: concurrent claims).
- **DECISION (W0):** re-seating a user whose own seat is still cooling reactivates that row and
  consumes no additional slot.
- **Bots and staff can never be seated.** Bot = `user.bot.is_some()` (refused `IsBot`).
  **DECISION (W0):** staff = `user.privileged == true` (refused `InvalidOperation`).
- The server owner occupies a seat like anyone else (**DECISION (W0)**, confirmed by the main
  session in the W0 fix round).
- **Consequence (W0-fix):** because the signer must be seated (4.1) and a privileged account
  can never be seated, **a privileged (staff) account cannot own a protected channel**: the
  protect route refuses a privileged owner (`InvalidOperation`). The live leg therefore needs a
  NON-privileged account as the server owner; the privileged account is only the one that
  grants the entitlement.

### 2.4 `channel_seat_lists` (new collection, both drivers)

Type name `SeatList`. Newest only: `_id = channel_id`.

| Field | Type | Notes |
|---|---|---|
| `_id` | String | channel id |
| `version` | i64 | from the body; `>= 1` |
| `body` | String | the exact canonical body of 4.1, byte-for-byte as signed |
| `signer_user_id` | String | equals the body's `signer_user_id` |
| `signer_device_id` | String | equals the body's `signer_device_id` |
| `signature` | String | b64, 64 bytes |
| `handovers` | `Vec<SignedHandover>` | **DECISION (W0)**: append-only chain, max 16 (4.6) |
| `updated_at` | Timestamp | |

`SignedHandover { body: String, signature: String }`.

### 2.5 `MlsGroup` changes

- `kind: MlsGroupKind` with `enum MlsGroupKind { Call, Text }`, `#[serde(default)]`,
  `impl Default` = `Call`. Serialized as `"Call"` / `"Text"`.
- `pending_removals: Vec<MlsPendingRemoval>`, `#[serde(default, skip_serializing_if = "Vec::is_empty")]`.
  `MlsPendingRemoval { user_id: String, created_at: Timestamp }`. Only meaningful on Text groups.
- `generation: Option<u32>`, `#[serde(default, skip_serializing_if = "Option::is_none")]`
  (**DECISION (W0-fix)**): `Some(g)` on every Text group (3.1), `None` on Call groups. Stored
  from the create request after the server checks it (6.1) and returned by the text-group
  state route so joiners check exactly that generation.
- `seat_list_ad_sha256: Option<String>` (**DECISION (W0-fix3)**): `Some` on every open Text
  group. It is the lowercase hex SHA-256 of the `commit_ad` (3.12.1) built from the channel's
  newest stored seat-list row. It is written in the SAME transaction as every seat-list row
  change (see "Seat-list writes" below). It exists so the commit transaction can test the AD
  with a field filter on the group document (3.12.2).
- `MlsCommit` gains `rejoin_intents: Vec<MlsJoinIntent>` (**DECISION (W0-fix4)**,
  `#[serde(default, skip_serializing_if = "Vec::is_empty")]`). These are copies of the stored
  signed join intents that justified a rejoin-case Remove (6.1). They are copied into the
  commit row inside the commit transaction, so they survive the intent row's deletion and
  reach every receiver through the envelope and the commit fetch (3.12.3 step 6).

**Commit transaction (DECISION (W0-fix4)).** This replaces every earlier "inside the CAS"
wording for Text groups. Transactions are available: the deployment runs a replica set
(`rs0`), and the driver already uses them (`channels/ops/mongodb.rs`,
`server_members/ops/mongodb.rs`). Today's Mongo `insert_mls_commit` reads the group outside
any transaction, decides the winner by `insert_one` on the unique commit `_id`, applies effects
by `replace_one` of a stale clone, and has a repair loop. That shape CANNOT host the new checks:
a hash check there either wedges the repair loop or silently reverts concurrent writes of
`seat_list_ad_sha256` / `pending_removals`. Pinned shape:

- **(a) Text `insert_mls_commit` = ONE multi-document Mongo transaction**, retried as a whole
  on `TransientTransactionError` (and `UnknownTransactionCommitResult` for the commit step),
  at most 5 attempts. After that, the existing database error. The committer then runs the
  outcome-recovery procedure below (W0-fix5); it does NOT blindly treat the error as lost.
  Inside the transaction, in order:
  0. **existing-row check (DECISION (W0-fix7); position pinned in W0-fix8):** if a commit row
     already exists at `{group}:{epoch}`, return `Lost { winning: <that row> }` immediately.
     **Exact order (route and driver):**
     1. ACCESS checks first: the caller is not a bot; the session is bound to the
        submitting device (`assert_bound_session`); and the caller passes the commit-fetch
        authorization (seated AND ViewChannel, 6.1 "Commit fetch"). The returned winning row
        is commit data, so without these first any account that derives a `group_id` could
        read commit rows.
     2. THEN the existing-row check.
     3. THEN every VALIDITY check: committer membership, the AD compare, the Remove/Add
        rules, the growth gate and `pending_removal`.

     This is what makes "resubmit the identical bytes" idempotent: a resubmit of a commit that
     already won always gets its own row back, even when the group's state has since moved
     on so far that the validity checks would now refuse it. A committer that was removed in
     between still passes the access checks while it remains seated with ViewChannel; if it
     no longer does, it gets the access refusal, which the bridge handles as desync
     (wipe-and-rejoin). Inside the driver transaction, this check is the first statement;
     the route's access checks have already run;
  1. read the group;
  2. check `open`, `current_epoch == e - 1`, `seat_list_ad_sha256 == SHA-256(AD)` (else
     `stale_seat_list`), `pending_removals` (Adds refused while non-empty), the Remove rule
     (6.1), the enforced device cap and the 100-leaf cap, and the revoked-identity lookups the
     Remove rule needs (see "Revoked-identity lookup" below);
  3. `insert_one` the commit row (its unique `_id` still arbitrates a racing same-epoch insert:
     a duplicate-key abort returns `Lost` with the winning row);
  4. a field-level `update_one` filtered on
     `{ _id, open: true, current_epoch: e - 1, seat_list_ad_sha256: h }` with
     `$set { current_epoch: e, members: <roster computed from the group read in step 1> }`
     and `$pull { pending_removals: { user_id: { $in: <users with no remaining device> } } }`.
     The same `$set` also maintains `member_added` (W0-fix5, below): each added device gets
     an entry `{ user_id, device_id, epoch: e, at: now }`, and each removed device's entry is
     dropped. `matched_count == 0` aborts the transaction (a concurrent writer won);
  5. **consume join intents (DECISION (W0-fix5))**: `delete_many` on `mls_join_intents` for
     the composite ids of (i) every ADDED device, mirroring the Call path's admission
     consumption, and (ii) every intent consumed by a rule-6 (rejoin) Remove in this commit.
     It is inside the transaction, so it cannot be lost or applied without the commit.

  Then commit the transaction. A Text commit needs no repair loop: the insert, the effects and
  the intent consumption are atomic.

**`member_added` (DECISION (W0-fix5))**: a new Text-only `MlsGroup` field
`member_added: Vec<MlsMemberAdded { user_id, device_id, epoch: i64, at: Timestamp }>`
(`#[serde(default, skip_serializing_if = "Vec::is_empty")]`). The creator's entry is written at
group create (epoch 0). It is how the server knows when each member device was last added,
which rule 6 needs (3.12.2): a rejoin intent counts only if its `created_at` is AFTER that
device's `member_added.at`. An intent left over from before the device's latest (re-)Add can
therefore never justify evicting it again.

Maintenance rules (**DECISION (W0-fix6)**):
- ~~drop, then add~~ (W0-fix6) is **UNREACHABLE** (**DECISION (W0-fix7)**, made receiver-true in
  W0-fix8): a Text commit may NOT remove and re-add the same device. This holds at BOTH
  layers:
  - the DS, on the DECLARATIONS: `commits_submit.rs` already refuses a device that appears in
    both `added` and `removed`, and the driver refuses "added device already a member" (6.1
    Add row);
  - every RECEIVER, on the ACTUAL commit (3.12.3 step 6): an Add whose credential equals a
    Remove target, or any replaced leaf identity not matched by the declarations, is
    `CommitDeclarationMismatch`, poisoned path. So an UNDECLARED same-commit replacement,
    which the DS cannot see, is never merged by an honest member, and `member_added` never
    has to represent it.

  A re-Add is always a later commit. So removed entries are dropped and added entries are
  inserted without overlap.
- **missing entry means refused:** a current member device with NO `member_added` entry
  (for example a group created before this field existed, or a bug) can NEVER be evicted
  under rule 6. Rule 6 is refused for it rather than treating "no entry" as "added at time
  zero". (Such a device can still be removed by the other cases.)

**Commit outcome recovery (DECISION (W0-fix5)).** A transaction can commit while its response
is lost (`UnknownTransactionCommitResult`, or a network error after commit), and a resubmit
after a lost response returns `Lost { winning: <the committer's own commit> }`. Treating either
as lost would discard a commit that actually won. So on (i) any database or transport error
from the submit, or (ii) a `Lost` whose `winning.committer` is this device, the bridge fetches
the stored commit for `{group}:{epoch}` (`GET /mls/groups/:id/commits?from_epoch=epoch`).
**Rewritten in W0-fix6 (DECISION (W0-fix6)).** The comparison is an exact comparison of the
stored base64 `commit` STRING (stored verbatim by `commits_submit.rs`) against the base64 of
the bytes native persisted with the pending stage (below):

- **present, committer is this `(user, device)`, string identical**: call `_commit_won`.
- **present, another committer**: call `_commit_lost` and rebase.
- **present, committer is this device, string DIFFERENT from our persisted stage** (for
  example we re-staged after a crash, and an earlier stage won): this device's MLS state can
  no longer follow the group. Take the **wipe-and-rejoin path**: discard this group's local
  MLS state (epoch keys for history are kept), send a rejoin intent, and let another member
  remove the stale leaf (rule 6). This is NOT poisoned: the group is fine, only this device
  is out of step.
- **absent**: this does NOT mean lost. Resubmit the IDENTICAL bytes. The existing-row check
  that runs first (step 0 above, route and driver) makes this idempotent: a duplicate
  returns `Lost` with the stored winner, which is then classified by the rules above. Repeat
  (with backoff) until the result is definitive: `Won`, a classified `Lost`, or a definitive
  refusal (`stale_seat_list`, `FailedValidation`, ...).
- **After any definitive refusal (DECISION (W0-fix7)),** the bridge re-fetches `{group}:{epoch}`
  ONCE before calling `_commit_lost`. If the row now exists, it is classified by the rules
  above instead; this covers a refusal that raced the original winning insert.
- **A 404 on resubmit or refetch** (the group or the commit row is gone, for example pruned past
  retention, or we were removed) counts as desync and goes to **wipe-and-rejoin**, never
  `_commit_won`.
- If a fetch fails, retry it with backoff; never guess.

**Native contract (W3).** Native persists the serialized commit bytes together with the pending
stage, in a `mls_text_pending_commits (group_id, epoch, commit_b64)` row written in the same
SQLite transaction as the stage. Then:

- after a crash, `e2ee_text_pending_commit(group_id)` returns `{ epoch, commit_b64 }`, so the
  bridge can resubmit identical bytes or compare;
- `e2ee_text_commit_won(group_id, won_epoch, stored_commit_b64)` merges ONLY if
  `stored_commit_b64` equals the persisted string, else `OwnCommitMismatch`, which means
  wipe-and-rejoin;
- when `_process` meets a commit from this device (an echo or a refetch), it does not try to
  decrypt it (OpenMLS refuses with `CannotDecryptOwnMessage`). It compares with the persisted
  stage instead: equal means merge as won, otherwise `OwnCommitMismatch` and wipe-and-rejoin.
  If a `CannotDecryptOwnMessage` reaches the error path anyway (**DECISION (W0-fix7)**), native
  FIRST compares the commit bytes with the persisted stage. If they are equal, it merges
  (the `_commit_won` path). Only a mismatch, or no persisted stage at all, gives
  `OwnCommitMismatch` and wipe-and-rejoin. It is never poisoned.

**Wipe-and-rejoin, and "holds a leaf" (DECISION (W0-fix7)).**
- *Holds a leaf* means the OpenMLS group is loaded and operational AND this device's own leaf
  is present in its current epoch. Only then is the native group state `active`.
- *Every path that leaves this device without a leaf* moves the group to the new native state
  `left` and wipes the group's MLS state BEFORE any `_join`. Those paths are:
  - `removed_self` from `_process`;
  - the server's `not_member` refusal (`ProtectedChannelResecuring { reason: "not_member" }`);
  - an R9 catch-up failure (commits pruned past retention);
  - `OwnCommitMismatch`;
  - a 404 on resubmit or refetch.
- *Wiped:* the OpenMLS group, its pending stage (`mls_text_pending_commits`) and its
  `mls_text_self` row. *Kept:* every CHANNEL-scoped table, namely `mls_text_seat_lists`,
  `mls_text_owner_pins`, `mls_text_forced_removals`, `mls_text_seen`,
  `mls_text_consumed_rejoin_intents`, plus `mls_text_epoch_keys` for history (R3).
- `_join` is refused (`AlreadyMember`) only in `active`; from `left` (and `none`) it is
  allowed. So a removed or desynced device can never be wedged by the eviction-loop guard
  (6.3).

This is the same rule the native code documents for dangling stages
(`mls_call_pending_commit_epoch`, `mls/mod.rs`): never "won" unless the DS shows our own
commit at that epoch.

**Scope:** S1 applies this recovery to TEXT commits only. Changing the Call path would touch
`mlsCallSession.ts` and require an `rtc-mutations.py` run; it is an S2 follow-up (10).
- **(b) Never `replace_one` of a clone. Field-level writes for BOTH kinds** (recommended
  option, adopted). The Call path keeps its insert-then-apply structure and repair loop, but
  its apply step becomes a field-level `update_one` (`$set { current_epoch, members }`,
  filtered on `{ _id, open: true, current_epoch: e - 1 }`) instead of `replace_one`. So it can
  never clobber `kind`, `generation`, `pending_removals` or `seat_list_ad_sha256`. W1
  obligation: a test that a Call commit applied over a group document carrying the new fields
  leaves them byte-identical.
- **(c) Seat-list writes are one transaction each.** Protect, a seat PUT, a handover append
  and Text group create each write the `channel_seat_lists` row, the `channel_seats` rows, and
  the open Text group's `seat_list_ad_sha256` / `pending_removals` in ONE Mongo transaction,
  with the same retry rule. A seat PUT and a commit transaction both write the group document,
  so Mongo's write-conflict detection serializes them: the loser retries and then sees the
  other's result. This is what makes "embedded list versions never decrease along epochs"
  (3.12.2) true.
- **(d) Reference driver: lock order** (extended in W0-fix5) `channel_seat_lists ->
  channel_seats -> mls_groups -> mls_commits -> mls_join_intents -> e2ee_identities` (the
  per-collection mutexes in `drivers/reference.rs`). Every path that holds more than one of
  these takes them in this order and holds them for the whole operation.
  - The Text commit path takes `channel_seat_lists` (read), `mls_groups`, `mls_commits`,
    `mls_join_intents` (rule-6 lookup and consumption) and `e2ee_identities` (revoked
    lookup).
  - Seat-list writes take `channel_seat_lists`, `channel_seats` and `mls_groups`.
  - The existing Call path's "groups -> commits -> intents" order is a suffix of this order,
    so it stays valid.

  No path takes them in another order.
- **Mongo Call repair loop and Text groups (W0-fix5).** The existing Call-path repair loop
  (the loser-side re-application of a winner's effects) MUST never apply effects to a Text
  group: it filters on `kind: "Call"`, or checks the kind of the group it re-reads, and skips
  a Text group. Text effects are only ever applied inside the Text commit transaction.
- **Revoked-identity lookup (DECISION (W0-fix4)).** The Remove rule's "revoked device" case is evaluated
  by looking up the device's E2EE identity INSIDE the transaction. If the identity exists at
  that moment (for example it re-registered, or the revocation has not landed), that case does
  not apply. The Remove is then refused (`FailedValidation`) unless another case covers it.
  The committer does `_commit_lost` and does NOT retry on that ground; the leaf is removed
  later by another case or stays. There is no retry loop.
- Per-kind constants: `MAX_MLS_GROUP_MEMBERS = 100` stays the Call ceiling; new
  `MAX_MLS_TEXT_GROUP_MEMBERS = 100` (leaves, counting every device). Both derive from
  `MAX_MLS_WELCOME_RAW_SIZE` (256 KiB); raising the text one is S10.
- Every `MlsGroup` struct literal (`groups_create.rs`, `voice_join.rs` x2, `member_edit.rs`,
  `mls/tests.rs`) sets `kind: MlsGroupKind::Call`. Every `fetch_open_mls_group_for_channel`
  caller passes a kind (`voice/mod.rs`, `voice-ingress/src/api.rs`, `reconcile.rs`,
  `routes/mls/group_open.rs`, the Mongo conflict path, tests).
- Per-user device rule inside `insert_mls_commit` (both drivers) becomes per-kind: Call = 1
  device per user (unchanged, existing structure); Text = the **enforced device cap**, checked
  inside the Text commit transaction (below). **DECISION (W0):** the limit is passed into the
  driver, so it is enforced there and not only in the route. **DECISION (W0-fix3):** enforced device cap = `min(signed-list
  device_cap, effective entitlement cap)`, where `0` means unlimited in either operand
  (so `min(0, x) = x` and only `min(0, 0) = 0` = unlimited). It is still bounded by 100
  leaves. It is never looser than the limit clients enforce (the signed value, 6.2), so an
  honest DS never sequences an Add that members must refuse as over-cap. Since W0-fix4 the
  signed value may be below the entitlement cap (4.1), so the min is usually the signed value.
- `sweep_mls_groups` (both drivers) never closes or deletes Text groups. New driver method
  `prune_mls_text_commits(older_than: Timestamp) -> Result<u64>` deletes `mls_commits` rows of
  Text groups with `created_at < older_than` (crond, daily, cutoff `now - commit_retention_days`).
- Close paths (`room_finished`, reconcile, `join_intent.rs` closes) touch Call groups only.

### 2.6 `Message.encrypted`

`encrypted: Option<EncryptedPayload>` on the database `Message` and the v0 `Message`
(`#[serde(skip_serializing_if = "Option::is_none")]`), mirrored in the bridge.

`EncryptedPayload` (type name pinned; v0 and database shapes identical):

| Field | JSON | Rust | Encoding and limit |
|---|---|---|---|
| `v` | number | u8 | exactly `1` |
| `group_id` | string | String | 64 lowercase hex |
| `epoch` | number | i64 | `0..=2^53-1` |
| `sender_device_id` | string | String | 32 lowercase hex |
| `nonce` | string | String | b64 of exactly 24 bytes (32 chars). The **AEAD nonce**, not the message `nonce` |
| `ciphertext` | string | String | b64; decoded length `17..=16384` bytes (plaintext + 16-byte tag); encoded length `<= 21846` chars |
| `sig` | string | String | b64 of exactly 64 bytes (86 chars) |
| `franking` | absent or `null` | `Option<String>` | reserved for S9. **DECISION (W0):** the S1 server refuses a non-null value (`ProtectedFieldRefused { field: "encrypted.franking" }`) |

- **DECISION (W0):** unknown fields inside `encrypted` are refused (`deny_unknown_fields`), so a
  future field can never be silently dropped by an old server.
- Ciphertext cap 16 KiB is enforced on the decoded length; the encoded length is checked first
  so oversized input is rejected before decoding (house pattern, `encoded_len`).
- **The message-level `nonce` is the client message id.** `Message.nonce` (already present,
  `Option<String>`) carries the `cid` (3.6). **DECISION (W0):** for protected messages it is
  REQUIRED, MUST be a ULID, and MUST be persisted and returned unchanged by every read path
  (single fetch, history fetch, the `Message` websocket event). W2 tests assert the round trip.
- Fix the empty check (`messages/model.rs` "Check the message is not empty"): a message with
  `encrypted: Some(_)` is not empty.
- **Stored-shape invariant for a protected channel** (enforced in `create_from_api_with_id`
  and `insert_message` as defense in depth): `encrypted` is `Some`; `content`, `embeds`,
  `attachments`, `masquerade`, `replies`, `mentions`, `role_mentions`, `sticker_ids`,
  `system`, `components`, `poll`, `command_context`, `webhook`, `thread_id` are all
  `None`/empty and `interactions` is default. Anything else is refused.

### 2.7 Migration (revision 73, `LATEST_REVISION` 74)

Confirm with the merge steward that no unmerged branch has claimed revision 73 before W1
lands. Revision 73 runs, in this order, so there is never a window without a uniqueness
guarantee:

1. **Backfill:** `mls_groups.updateMany({ kind: { $exists: false } }, { $set: { kind: "Call" } })`.
2. **Create** the new index on `mls_groups`:
   `{ key: { channel_id: 1, kind: 1 }, name: "open_channel_kind_group", unique: true, partialFilterExpression: { open: true } }`.
3. **Drop** the old index `open_channel_group`.

Then `LATEST_REVISION = 74`. `init.rs` (fresh databases) creates `open_channel_kind_group`
only, plus: `channel_entitlements` unique index on `channel_id`; `channel_seats` index on
`channel_id` and on `user_id`; `channel_seat_lists` needs only `_id`. The Reference driver
registers the three new collections and keys its open-group check by `(channel_id, kind)`.
Update the revision asserts in `scripts.rs` (the `LATEST_REVISION` assert and the
"last migration" asserts) in the same lane.

---

## 3. Crypto formats (W3 implements; server mirrors 3.1 and 2.6 validation)

### 3.1 Text group id derivation

**DECISION (W0).** A text group id is deterministic in the channel id:

```
group_id(channel_id, g) = lowercase_hex( SHA-256( UTF-8( "sloga-text-group-v1" LF channel_id LF decimal(g) ) ) )
```

where `g` is the **generation** (a `u32`), `0` for the first group of a channel and
`previous + 1` for each poisoned-epoch successor (`supersedes`). `g` is capped at `63`.

Why: it binds the group to the channel cryptographically. **DECISION (W0-fix):** the server
stores `generation` on the group record (2.5) and returns it with the group state; a joiner
checks `group_id == group_id(intended_channel_id, generation)` for **exactly that stated
generation** (no scan), and `generation <= 63`, **before deriving any key**. The server checks
the same equation at create. A hostile server relaying a different channel's group or Welcome
fails loudly (`ChannelMismatch`): it cannot find a generation that makes another channel's id
derive from this channel. No MLS GroupContext extension is used (an extension would require
every existing KeyPackage to advertise a new capability). A reused id is refused by the `_id`
uniqueness of `mls_groups`. Reaching `g = 64` is a loud failure; more successors are S2.

Only the device that signed the channel's CURRENT seat list (the owner's pinned device) may
create a text group or a successor (**DECISION (W0-fix)**, 6.1).

### 3.2 MLS configuration

Text groups reuse the call stack unchanged unless stated: ciphersuite
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (single accepted value), the same leaf
credential (`acutest:e2ee:mls-credential:v1`) and the same leaf acceptance rule (media plan
1.3: MLS signature verifies, binding signature verifies under the locally pinned slice-5
identity, pin is `binding_verified && !identity_changed`), the same Welcome-based join with a
signed join intent (`acutest:e2ee:mls-join:v1`) and the same allowed Update shape
(HPKE-only self-update, credential and MLS signature key unchanged). MLS application messages
are NOT used for text: messages are encrypted under the exported epoch key (3.3, 3.4).

### 3.3 Epoch key

For every epoch a device holds (on Welcome join and after every merged commit):

```
epoch_key = MlsGroup::export_secret(crypto,
                                    label   = "sloga/text/v1",
                                    context = raw_group_id (32 bytes) || u64_be(epoch) (8 bytes),
                                    length  = 32)
```

- `raw_group_id` is the 32 bytes the hex group id encodes (the media exporter's convention).
  The context is exactly 40 bytes. Including the epoch is belt and braces: the exporter is
  already per-epoch.
- Stored sealed (the store's existing secret sealing) in `mls_text_epoch_keys`
  `(group_id, epoch, key_sealed, roster, first_seen_at)`, where `roster` is the verified leaf
  list at that epoch: `(user_id, device_id, identity_ed25519_b64)` per leaf, from the leaf
  credentials. Never returned over IPC, never in an error.
- **Retention (R3):** epoch keys are kept for the lifetime of the local channel state.

### 3.4 AEAD

- Algorithm: **XChaCha20-Poly1305** (`chacha20poly1305::XChaCha20Poly1305`, already a
  dependency at 0.11). Key = `epoch_key` (32 bytes). Tag 16 bytes, appended to the ciphertext.
- Nonce: **24 bytes from the OS CSPRNG, fresh per message**, never derived, never reused.
- Plaintext: the UTF-8 bytes of the envelope JSON (3.6).
- AAD: 3.5.

### 3.5 AAD (byte layout)

The AAD is the concatenation of seven fields, each encoded as `u16_be(len) || bytes`.
**DECISION (W0):** the length prefix is a 2-byte unsigned big-endian integer.
**DECISION (W0-fix), the one length rule:** each field MUST be at most 255 bytes; builders and
parsers refuse anything longer. (The fields defined below are 8 to 64 bytes.)

| # | Field | Bytes | Length |
|---|---|---|---|
| 1 | context | ASCII `sloga-text-v1` | 13 |
| 2 | channel id | ASCII of the message's channel id | 26 |
| 3 | group id | ASCII of the **64-char hex** group id (not the raw 32 bytes, **DECISION (W0)**) | 64 |
| 4 | epoch | `u64_be(epoch)` | 8 |
| 5 | author user id | ASCII of the message author (server-stamped `Message.author`) | 26 |
| 6 | sender device id | ASCII of `encrypted.sender_device_id` | 32 |
| 7 | client message id | ASCII of the `cid` (= `Message.nonce`) | 26 |

Every AAD field is reconstructible by a receiver from server-visible data before decryption,
which is why the `cid` travels in the clear in `Message.nonce`. The fixed field lengths give a
209-byte AAD; implementations MUST still build it from the length-prefixed rule, not a fixed
offset table. Section 5.6 has the field-by-field vector.

### 3.6 Plaintext envelope (inside the ciphertext)

Compact JSON object, UTF-8:

| Key | Type | Rule |
|---|---|---|
| `v` | number | exactly `1` |
| `cid` | string | the client message id, a ULID; MUST equal `Message.nonce` |
| `ts` | number | sender clock, ms since epoch |
| `text` | string | non-empty; at most `limits.message_length` characters (the existing per-account limit) |
| `replies` | array of string | message ids (ULID), at most `limits.message_replies` (5 today), no duplicates; `[]` when not a reply |

- Senders serialize keys in the order `v, cid, ts, text, replies` with no insignificant
  whitespace (serde_json compact of a struct in that declaration order). The envelope is not
  itself signed (the ciphertext is), so receivers parse it strictly but not canonically:
  unknown keys, duplicate keys, missing keys or wrong types are `MalformedTextPayload`.
- The envelope MUST fit the 16 KiB ciphertext cap: `len(envelope) <= 16368` bytes.
- Reply targets live ONLY here; the server never sees `replies` for a protected message.
  Mentions are not parsed server-side, so in S1 a mention inside protected text never pings
  (documented UX limitation).

### 3.7 Signature

Ed25519 by the sender device's **vodozemac identity key** (`account.sign`, the same key that
signs the leaf credential), over the UTF-8 bytes of this newline-canonical string:

```
sloga-text-sig-v1
nonce:{b64(aead_nonce)}
aad:{b64(aad)}
ciphertext:{b64(ciphertext_with_tag)}
cid:{cid}
ts:{decimal(ts)}
replies:{reply ids joined by ","; empty when none}
```

- The plan's "nonce || AAD || ciphertext || client message id || timestamp || reply targets"
  is realized as these labeled lines. **DECISION (W0):** binary fields are b64 inside a text
  payload, because the vodozemac signing API and every existing signed payload in this
  codebase sign UTF-8 text.
- `ts` and `replies` are taken from the decrypted envelope; the reply order is the envelope
  order (not sorted).
- `sig` in the payload is `b64(signature)`.
- Verification key: the `identity_ed25519` carried in the sender leaf's credential **at the
  message's epoch** (from the `mls_text_epoch_keys` roster), never the server directory.

### 3.8 Sender procedure (`e2ee_text_encrypt`)

1. Resolve the channel's local text group by native table lookup (never from a server kind).
   None, or not active: `MlsGroupNotFound` (the existing variant).
2. Refuse `OwnerChanged` if the owner pin is in the changed state; refuse `NotSeated` if this
   user is not on the newest verified seat list.
3. **Roster check:** refuse `RosterMismatch` if any leaf's user is absent from the newest
   verified seat list or is locally known to be removed (4.4, 6.2).
4. Refuse `UpdateRequired` if the hard Update ceiling (3.11) is reached.
5. Mint `cid` (ULID) and `ts` (local clock); build the envelope; refuse oversize.
6. Build the AAD with `author = user_id` (the caller's own id), random 24-byte nonce, encrypt,
   build and sign the signature payload.
7. Record `cid` as pending-own in `mls_text_seen` (3.10).
8. Return `{ nonce: cid, encrypted: EncryptedPayload }` (the REST body minus the optional
   silent flag).

### 3.9 Receiver procedure (`e2ee_text_decrypt`), in order

Each failure is a typed, loud result (section 8.4); nothing is silently dropped.

1. `Message.encrypted` absent on a protected or locally pinned channel: not a native call; the
   bridge renders the **plaintext-in-protected** loud marker (9.3).
2. Structural validation of the payload (2.6) and of `Message.nonce` (ULID):
   `MalformedTextPayload`.
3. Group lookup by `encrypted.group_id` in the native text table; it MUST map to
   `Message.channel` (`ChannelMismatch`). The table row was admitted only after the exact
   generation check of 3.1, so a group id never maps to a channel it does not derive from.
   No local row at all: `MlsGroupNotFound` (gray marker, 9.2).
4. Epoch key for `encrypted.epoch`: absent means `UnknownEpoch { epoch, oldest_held, current }`.
   The bridge distinguishes "before this device joined" (`epoch < oldest_held`, gray history
   marker) from "ahead of us" (`epoch > current`: catch up commits, then retry once).
5. Sender leaf `(Message.author, sender_device_id)` in the stored roster of that epoch:
   absent means `UnknownSender`.
6. Rebuild the AAD (3.5) and AEAD-open: failure is `BadSig` (**DECISION (W0)**: an AEAD failure
   and a signature failure are reported identically, so the UI has one "could not verify"
   marker).
7. Parse the envelope strictly; `envelope.cid != Message.nonce` is `MalformedTextPayload`.
8. Build the signature payload (3.7) and verify against the leaf-bound identity key:
   `BadSig`.
9. **Removed-sender rule** (plan, audit finding 3): if the message arrived **live** (websocket
   push, `live = true`) at `epoch < local current epoch` and the sender has no leaf at the
   current epoch: `RemovedSender`. Also `RemovedSender` (live or history) when this device
   observed the sender's removal locally and the signed `ts` is later than that observation
   plus 5 minutes.
10. **Replay** (3.10): `Replay` if this `cid` is already bound to a different message id.
11. Success returns the plaintext plus `ts_skew = |ts - ulid_time(Message.id)| > 10 minutes`
    (**DECISION (W0)**; rendered as an informational marker, not red).

### 3.10 Replay dedupe

Native table `mls_text_seen (channel_id, cid, message_id NULL)`, unique on
`(channel_id, cid)`. Own sends insert `(cid, NULL)` at encrypt time; the first decrypt of a
message binds `message_id`. Decrypting the same `(cid, message_id)` again (history refetch)
is idempotent. The same `cid` under a different message id is `Replay`; the first-seen
binding wins. The server additionally refuses a repeated `nonce` within its idempotency cache:
today `consume_nonce` maps that duplicate to **`InvalidOperation`** (`messages/model.rs`
"consume_nonce ... map_err"), not `DuplicateNonce`. A bridge that retries a send after a lost
response and gets `InvalidOperation` MUST treat the message as possibly delivered and refetch
the channel to confirm, never re-encrypt under a new `cid` blindly.

**Protected sends MUST NOT send an `Idempotency-Key` header (DECISION (W0-fix)).** stoat.js
always sends one today (W0 audit: `Channel.ts` send path). The request guard
(`util/idempotency.rs`) caches the header key, and `consume_nonce(data.nonce)` refuses any
`nonce` already in that same cache with `InvalidOperation`; a header and body carrying the
same token would refuse every send, and differing tokens would double-book the cache. The
`nonce` body field is the only idempotency token on a protected send.

### 3.11 Update-commit cadence (post-compromise security)

**DECISION (W0):** each device issues an HPKE-only **self-Update** commit (3.2) when its own
leaf was last refreshed by itself (join or own Update) **7 days** ago or it has **sent 500
messages** since then, whichever comes first. The check runs when the channel is opened and
before each send (`e2ee_text_state.update_due`). Hard ceiling: at **14 days or 2000 sent
messages** `_encrypt` refuses `UpdateRequired`; the bridge then commits the Update and
retries. The sender can always clear this itself, so it cannot wedge a channel.

Why these values: PCS for a compromised device is restored only when that device updates
its own leaf (another member's Update does not re-key a path the attacker still holds), so
the trigger is per device, not per group. Text is low-rate, so the call heartbeat (10
minutes) would be pure commit churn; 7 days matches the existing 7-day call backstop and the
last-resort KeyPackage lifetime, and keeps the commit backlog a returning device must replay
small relative to the 30-day commit retention (R9). 500 messages bounds the volume exposed by
one compromise in busy channels. With 100 devices the time trigger alone yields about 14
Update commits per day per channel, each a few KiB; busy channels add message-triggered ones.

### 3.12 Seat-list binding in commit `authenticated_data` (R11 mitigation)

Redesigned in W0 fix round 2 (**DECISION (W0-fix2)**, main-session decision). The round-1
form (a version and a hash, with a fetch-and-defer receiver) is withdrawn for two reasons.
First, OpenMLS 0.8.1 persists the advanced secret tree when it decrypts a PrivateMessage, so
a decrypted-then-deferred commit can never be decrypted again (`SecretReuseError`); deferral
desynced every member on the older list. Second, an insider could name a fake version and
wedge every receiver. The AD is now **self-proving**: it carries the whole signed list, so a
receiver verifies it before decrypting and never needs to fetch.

#### 3.12.1 Format

EVERY text-group commit (Add, Remove, Update) carries, as its MLS `authenticated_data`, the
committer's current seat list exactly as the server stores it. Every field is
`u16_be(len) || bytes` (the 3.5 encoding, but the 255-byte AAD limit does NOT apply here):

```
commit_ad = field( ASCII "sloga-text-commit-ad-v1" )                  23 bytes
         || field( seat-list body, exact signed bytes, 4.1 )           <= 4096 bytes
         || field( seat-list signature, RAW 64 bytes )                 64 bytes
         || u16_be( handover_count )                                    0..=16
         || handover_count x ( field( handover body, exact bytes, 4.6 )  <= 1024 bytes
                            || field( handover signature, RAW 64 bytes ) )
```

- The signer ids are not separate fields: they are lines 7 and 8 of the signed body (4.1),
  so they are covered by the signature and cannot disagree with it.
- The handovers are the channel's full stored chain in stored (append) order (2.4), so a
  member pinned to any earlier owner key can walk to the signer (4.6) without fetching.
- Parsers refuse trailing bytes, a count above 16 and any field over its limit; the whole AD
  MUST be at most **16383 bytes** (**DECISION (W0-fix3)**, was 16384), the largest length a
  2-byte MLS varint can carry. Its framing length is therefore always a 1- or 2-byte varint,
  and the 3.12.2 parser refuses a 4-byte one.
- **Worst case: 10291 bytes** (100 seats; `version`, `issued_at` at `2^53 - 1`; `device_cap`
  at `2^32 - 1`; 16 handovers of 386-byte bodies). The body is at most 2932 bytes, each
  handover entry 454 bytes. That is 15.7% of `MAX_MLS_COMMIT_RAW_SIZE` (65536, backend
  `routes/mls/mod.rs`), which still leaves at least 55245 bytes for the rest of the serialized
  commit (framing and ciphertext). It fits a 2-byte MLS varint. A typical channel (10 seats,
  no handover) is 570 bytes.
- Committer (native): call `MlsGroup::set_aad(commit_ad)` IMMEDIATELY before each
  `add_members` / `remove_members` / `self_update` (OpenMLS resets the AAD after every
  message, `reset_aad`), including every re-stage after a lost race. The embedded list is the
  device's newest verified list together with the chain it received with it, so native
  stores the chain with the list (8.2).
- Vector: 5.7.

#### 3.12.2 Server enforcement (W2, `routes/mls/commits_submit.rs`)

For a Text group the delivery service accepts a commit only if its AD is **byte-identical**
to `commit_ad` built from the newest seat-list row it holds for the channel (body, decoded
signature, stored handovers in order). Mismatch: **`ProtectedChannelResecuring { reason:
"stale_seat_list" }`** (409; existing variant, new reason value, **DECISION (W0-fix2)**). The
committer then calls `_commit_lost`, catches up, fetches and verifies `GET .../seats`
(4.4, catch-up first), and re-stages. Call groups are unchanged.

**Inside the commit transaction (DECISION (W0-fix3), mechanics rewritten in W0-fix4).** The
comparison is part of the Text commit transaction (2.5 "Commit transaction"). In it, the
group read gives `seat_list_ad_sha256`, and the effects `update_one` is filtered on
`{ _id, open: true, current_epoch: e - 1, seat_list_ad_sha256: SHA-256(received AD) }`. The
Reference driver does the same under its lock order. The route also byte-compares the AD
against the row it read, as a pre-check. Equality of SHA-256 over the full AD bytes is the
in-transaction form of "byte-identical". Every seat-list row change updates
`seat_list_ad_sha256` in its own transaction on the same group document, so the two
serialize: no seat PUT can land between check and insert. Consequence: along the epoch
sequence, embedded list versions never decrease, and a commit accepted after a seat PUT
always embeds that PUT's list or a newer one.

**Remove rule (DECISION (W0-fix3), main-session decision; amended W0-fix4).** The DS checks a
Text commit's declared `removed` list inside the commit transaction:

1. **The CURRENT list signer's device** (the owner's signing device) may be removed ONLY in
   the rejoin case (item 6 below), regardless of the other cases (W0-fix4). That includes
   by another device of the owner user, when it is pending removal, and when it is revoked.
2. devices of the **committer's own user**, other than the committing device itself (OpenMLS
   refuses self-removal, `CannotRemoveSelf`), are allowed; or
3. devices of users in the group's **`pending_removals`** are allowed, by ANY committer, whether
   or not the user is still on the signed list. A server-forced removal (kick, ban, leave)
   leaves the user ON the list, so this case must not require "off-list" or "owner"
   (W0-fix6 clarification); or
4. devices whose E2EE identity was **revoked** (no longer exists, `E2EEIdentity::revoke_device`;
   looked up inside the transaction, 2.5) are allowed; or
5. devices of users **absent from the newest signed seat list** are allowed, ONLY when the
   committer is the current list signer's device; or
6. **rejoin case (DECISION (W0-fix4)):** a device that has an **outstanding rejoin intent
   signed by that device** is allowed. That is a stored `MlsJoinIntent` for this group whose
   `(user_id, device_id)` is the removed device, whose device is currently a member, whose
   signature verified at the join-intent route, which is no older than
   `REJOIN_OUTSTANDING_WINDOW_SECONDS` (30 s), and (**W0-fix5**) whose `created_at` is AFTER
   that device's `member_added.at` (2.5). The intent is copied into the commit row's
   `rejoin_intents` and then CONSUMED (deleted) in the same transaction (2.5 step 5). One
   signed rejoin intent therefore justifies exactly one eviction, and an intent older than
   the device's latest (re-)Add can never evict it again. This is the only way a stale leaf of a device that wiped its
   state (including the owner's signing device) can be removed, because a device can never
   remove itself.

Anything else is `FailedValidation` (removal not permitted).

**This rule is enforceable only together with the receiver binding (DECISION (W0-fix4)).**
The DS sees only the committer-DECLARED `added` / `removed` lists (availability-trust,
media plan T-19), never the encrypted proposals. A committer could under-declare (really
remove someone without listing them) or over-declare (list a kicked user's device so the DS
clears `pending_removals` while the leaf stays). The server-side rule binds only what is
declared. 3.12.3 step 6 makes every receiver compare the commit's ACTUAL adds and removes
with the server-recorded declarations and refuse any mismatch, which is what turns the
declarations into the truth. Without that receiver check the server-side Remove rule would be
decorative.

The server reads the AD in cleartext: a PrivateMessage's framing fields are plaintext (RFC
9420 section 6.3). Today the route only length-checks the base64 `commit`. W2 decodes it and parses
this prefix of the serialized `MLSMessage`, stopping after the AD (the rest is opaque):

| Field | Encoding | Required value |
|---|---|---|
| `version` | u16 big-endian | `0x0001` (mls10) |
| `wire_format` | u16 big-endian | `0x0002` (mls_private_message) |
| `group_id` | `<V>` varint length, then bytes | length 32; bytes = the raw 32-byte route group id |
| `epoch` | u64 big-endian | `DataSubmitMlsCommit.epoch - 1` (a commit is framed in the epoch it was created in) |
| `content_type` | u8 | `0x03` (commit) |
| `authenticated_data` | `<V>` varint length (1 or 2 bytes ONLY; a 4-byte varint is refused, W0-fix3), then bytes | length `<= 16383`; then the byte-identical check above |

`<V>` is the RFC 9420 section 2.1.2 variable-length integer: the top two bits of the first byte
give the size (`00` 1 byte, 6-bit value; `01` 2 bytes, 14-bit; `10` 4 bytes, 30-bit; `11`
invalid), and the encoding MUST be minimal. Any prefix failure (truncation, wrong constant,
non-minimal varint, length past the end) is `FailedValidation`. The 5.7 vector pins the prefix
bytes.

(W0-fix3: the round-2 note that a seat PUT could land between check and insert is withdrawn.
The compare is now inside the Text commit transaction, see above and 2.5.)

#### 3.12.3 Receiver (native `_process`), checks BEFORE decrypting

1. Deserialize the envelope as `MlsMessageIn`, `extract()` it, and require
   `MlsMessageBodyIn::PrivateMessage`. Read `PrivateMessageIn::aad()`
   (openmls 0.8.1 `framing/private_message_in.rs:52`). It is unverified at this point, which
   is why step 2 verifies it independently.
   **Non-commit content refused (DECISION (W0-fix6)).** The Text commit path accepts only
   `content_type == commit` (the framing field is readable before decryption). A standalone
   proposal or an application message arriving on it is refused with `UnexpectedMlsContent`
   BEFORE anything is decrypted or stored. Nothing ever enters OpenMLS's proposal store from
   outside. This device's own `add_members` / `remove_members` / `self_update` consume the
   proposal store by default, so a commit can never pick up a queued foreign proposal.
   A commit sent by THIS device is not decrypted (OpenMLS cannot decrypt its own message): it
   is matched against the persisted pending stage (2.5 "Commit outcome recovery").
2. Parse `commit_ad` strictly (3.12.1). On failure, do NOT decrypt: return
   `SeatListInvalid { reason: malformed }`, and the group takes the poisoned-epoch path
   (successor flow). This is loud, because an honest server refuses such a commit (6.1).
3. Check the embedded list with the 4.4 rules, **anti-rollback FIRST** (**DECISION
   (W0-fix3)**), using the embedded handovers as the chain:
   - `version < held`: NOT adopted. Signer acceptance, signature and signer-leaf checks are
     all skipped (an old list can move nothing), and processing continues. With an honest
     server this cannot happen, because embedded versions never decrease along epochs and a
     `GET` list is adopted only after catching up (4.4); it can only come from a hostile
     server. Step 6 keeps it harmless: Adds are checked against the newest held list, so an
     old list re-admits no one. It never raises `OwnerChanged`.
   - `version == held`: the body and signature must be byte-identical to the held ones,
     then continue (no other check; never `OwnerChanged`). A different body or signature at
     the same version is `SeatListEquivocation`: do NOT decrypt; poisoned path.
   - `version > held` (or nothing held): run the full newer-list checks of 4.4. That is the
     signature under the signer device's slice-5 pin, signer acceptance under the OWNER PIN
     (pin, or forward along the handover chain), and **the signer-leaf check (ONLY here,
     W0-fix3)**: the signer holds a verified leaf at the current epoch. If all pass,
     **adopt** it (persist list and chain, advance the stored version and the pin if the
     chain moved it, mark off-list leaves) and continue. A signature, structure or leaf
     failure (`BadSig`, `SeatListInvalid`) means do NOT decrypt; poisoned path.
   - `OwnerChanged` (only possible on a NEWER list) with `same_user`: do NOT decrypt; leave
     the envelope unacknowledged and show the 4.7 confirmation. On confirm, re-run `_process`.
     That is safe because nothing was decrypted and no secret-tree state advanced. Later
     envelopes wait behind it while the channel shows `unverified`.
   - `OwnerChanged` with a different user: refused outright in S1 (4.7). Do NOT decrypt;
     poisoned path; `unverified`.
4. Decrypt and stage (`process_message`).
5. Assert `ProcessedMessage::aad()` equals the bytes checked in steps 2 and 3. A mismatch can
   only be a library defect; it is the poisoned path.
6. **Membership checks, in this order** (the order is the point). The list was already
   adopted in step 3, and only then are the commit's changes checked.
   - **Adds.** Each added leaf passes the 3.2 leaf acceptance rule; its user is on the
     **newest held list** (after step 3, with an honest server, that IS the embedded list);
     it is not in forced-removal memory (6.2); per-user `device_cap` of the newest held list;
     total leaves at most 100.
   - **Proposal allowlist (DECISION (W0-fix5)).** A Text commit's
     `StagedCommit::queued_proposals()` may contain ONLY `Add` and `Remove` proposals. A
     commit with no proposals and an update path (`update_path_leaf_node()` present) is the
     3.11 self-Update, and is allowed. Any other proposal type is refused with
     `CommitDeclarationMismatch`: `Update` (by reference), `PreSharedKey`, `ReInit`,
     `ExternalInit`, `GroupContextExtensions`, OpenMLS 0.8.1's `SelfRemove` (which
     `remove_proposals()` does NOT report), `Custom`, or any extension proposal.
   - **No same-commit replacement (DECISION (W0-fix8), the round-8 HIGH).** A Text commit in
     which ANY Add proposal's KeyPackage credential `(user_id, device_id)` equals ANY Remove
     proposal target's leaf credential `(user_id, device_id)` is refused
     (`CommitDeclarationMismatch`, poisoned path).
     *The attack this closes:* a member claims victim X's KeyPackage and commits
     Remove(X's leaf) + Add(X's KeyPackage) with EMPTY declarations. The credential diff is
     then empty, the DS sees an Update-shaped commit, and the owner-device check never fires.
     Yet X's real device is evicted (`removed_self`, so `left`). Applied to the owner's
     signing device, that would silently block all signing (4.3 step 5b, 8.3).
     **This rule is REQUIRED, not redundant (DECISION (W0-fix9)). Implementers must not drop
     it.** The leaf-identity diff below does NOT catch every variant: see the
     original-KeyPackage case under "Declared vs actual".
   - **No Add of a known signature key (DECISION (W0-fix9)).** A Text commit is refused
     (`CommitDeclarationMismatch`, poisoned path) if ANY Add proposal's leaf has an MLS
     signature key equal to the signature key of ANY leaf in the PRE-commit tree. MLS
     signature keys are constant per device in v1 (3.2), so a legitimate Add always brings a
     device whose key is not yet in the tree; a match can only be a re-Add of an existing (or
     just-removed) device. This rule is independent of the credential rule above: it holds
     even if a credential were somehow mis-mapped, because it compares raw keys.
   - **Declared vs actual (DECISION (W0-fix4); "actual" redefined in W0-fix5, and over LEAF
     IDENTITY in W0-fix8).** The receiver compares the commit's ACTUAL membership change with
     the server-recorded declarations for this epoch. "Actual" is the difference between the
     group's leaves BEFORE the commit (current epoch) and AFTER it (the staged epoch's
     leaves). It is not the proposal iterators, which can miss changes (for example
     `SelfRemove`). Leaves are compared by **leaf identity**, not by credential alone:
     - for every leaf except the committer's: `(leaf_index, MLS signature key, HPKE
       encryption key)`;
     - for the committer's own leaf: `(leaf_index, MLS signature key)`, because its
       encryption key legitimately changes with the commit's update path.

     Why the encryption key is included: RFC 9420 applies Removes before Adds, and an Add
     fills the leftmost blank leaf (`free_leaf_index`). That may be the just-removed device's
     own index, or a LOWER index that was already blank (corrected in W0-fix9). A device's
     MLS signature key is constant across its KeyPackages (v1), so `(leaf_index, signature
     key)` alone does not see a re-Add that lands on the removed leaf's index. A non-committer
     leaf's encryption key never changes in a legitimate Text commit (`Update` proposals are
     refused by the allowlist), so a re-Add with a FRESH KeyPackage changes the identity and
     counts as one remove plus one add.

     **Limit of the identity diff (DECISION (W0-fix9)).** It does NOT catch re-use of the
     ORIGINAL KeyPackage. If victim X never updated since joining, X's leaf is still byte for
     byte the LeafNode from its admitting KeyPackage, which every member saw.
     Remove(X) + Add(that same KeyPackage) passes OpenMLS validation (removed indices are
     skipped by the duplicate-key checks) and refills X's own index, the leftmost blank, with
     byte-identical keys. The leaf-identity diff then sees NO change. That variant is caught
     ONLY by the proposal-level rules above: the credential rule (Add credential equals
     Remove target) and the signature-key rule (the Add's signature key is already in the
     pre-commit tree). Each catches it independently. Hence both are required.

     Each removed and added leaf is then mapped to its credential `(user_id, device_id)`:
     - actual added (after-identities absent before) must equal the declared `added`;
     - actual removed (before-identities absent after) must equal the declared `removed`;
     - the committer (the sender leaf's credential) must equal the server-stamped
       `committer`.

     **Multiset, and roster uniqueness (DECISION (W0-fix6)).** The credential comparisons
     above are MULTISET comparisons over `(user_id, device_id)`, so a duplicate leaf is
     never hidden by set semantics. Independently, a Text group refuses any epoch whose
     leaves contain two entries with the same `(user_id, device_id)`: checked at Welcome
     verification and on the staged epoch of every commit, before merge (`DuplicateLeaf`,
     poisoned path). (W0-fix8: the round-6 sentence describing a same-commit Remove + re-Add
     as a valid shape is deleted. That shape is refused, by the DS on the declarations, 6.1,
     and by every receiver on the actual proposals and leaf identities, above.)
     The Call `verify_roster` rule "at most one leaf per USER" does NOT apply to Text groups
     (multi-device is allowed up to `device_cap`). The per-`(user, device)` uniqueness rule
     replaces it for Text.
   - **Replayed rejoin intents (DECISION (W0-fix6)).** Native records the signature of every
     rejoin intent it has seen consumed by a processed commit, per group, in
     `mls_text_consumed_rejoin_intents (group_id, signature)`. A later commit citing an
     already-recorded intent is refused (`ReplayedRejoinIntent`, poisoned path). This catches
     a HOSTILE DS replaying an old intent to evict a device again (R14), which the
     server-side consumption (2.5 step 5) can only prevent on an honest DS. **Limit
     (W0-fix7):** the record is per-device history, so a device that joined after the
     original eviction cannot recognize the replay and merges it. A replay can therefore split
     verdicts (older devices poisoned and loud, later joiners merged). That is hostile-DS-only
     and loud on the older devices (R14). Unlike every other step-6 check, this one is not
     guaranteed to be deterministic across members.
     **Making "loud on the older devices" true (DECISION (W0-fix8)):**
     - the consumed set is filled on EVERY path that merges a commit carrying
       `rejoin_intents`: `_process` of others' commits AND `_commit_won` of this device's own
       commits (an own commit is never decrypted, so without this the committer would never
       record the intents it consumed);
     - `e2ee_text_remove` refuses (`ReplayedRejoinIntent`) a `rejoin_intent` whose signature
       is already in the consumed set, so an honest device never builds a replay;
     - **clock-free own-intent rule (DECISION (W0-fix9), replacing the W0-fix8 wall-clock
       check):** a device REFUSES (poisoned, loud, `ReplayedRejoinIntent`) any commit whose
       `rejoin_intents` contains an intent for ITS OWN `(user, device)` while its group is
       `active`.
       An honest `active` device never issues a join or rejoin intent: the eviction-loop
       guard refuses `_join` in `active` (6.3, 8.3). A device sends a rejoin intent only from
       `left`, and while `left` it holds no group state and processes no commits. So any
       commit citing its own intent that reaches it while `active` is necessarily a replay of
       an old intent. No timestamps, `key_package_ref` matching or `own_leaf_since_at` are
       involved. (The W0-fix8 `own_leaf_since_at` field is dropped.)

       So the victim device itself always sees a replayed eviction of ITSELF as loud, even
       when it is the newest member. It is the one device guaranteed to notice.

     The declarations travel with the commit (pinned, W2 and W3). The delivered `mls_commit`
     envelope gains `committer`, `added`, `removed` and `rejoin_intents`, copied from the
     stored commit row. They are `#[serde(default)]` in native `wire::MlsEnvelope` and absent
     on `mls_welcome` / `mls_ctl`. The commit fetch (`MlsCommitInfo`) already carries
     `committer`, `added` and `removed`, and gains `rejoin_intents`. A Text commit envelope
     missing these fields is treated as a mismatch.

     Today native takes removals from the `StagedCommit` without comparing them (e2ee-core
     `mls/mod.rs`); the text path MUST compare. Any mismatch takes the poisoned path:
     `CommitDeclarationMismatch { group_id, epoch }`, loud. This is the half of the 6.1 Remove
     rule that makes it enforceable.
   - **Removes of the owner's pinned signing device (W0-fix3, amended W0-fix4).** A commit
     whose actual removes include the owner's pinned signing device is accepted ONLY if
     `rejoin_intents` contains a join intent from exactly that `(user_id, device_id)`, for
     this group, whose signature (`acutest:e2ee:mls-join:v1`) verifies under this device's
     pinned slice-5 identity for that device. Otherwise it is refused (`NotOwner`, poisoned
     path). Receivers cannot see `pending_removals` or revocations; the declaration binding
     above covers those.
   - A failure here comes after decryption, so the commit cannot be merged by anyone honest.
     **DECISION (W0-fix3):** it takes the **poisoned-epoch / successor path** (loud, typed:
     `CommitDeclarationMismatch`, `RosterMismatch`, `MlsLeafRejected`, `TextGroupFull`,
     `NotOwner` for the forbidden Remove), NOT a per-device rejoin.
   - Every honest member holds exactly the embedded list at this point, receives the same
     declarations, and runs the same deterministic checks, so all honest members reach the
     same verdict. A failure means the committer (or a hostile server) misbehaved (R14), not
     a routine race. The catch-up-first rule (4.4) and the in-transaction AD check (3.12.2)
     removed the round-2 race in which a device holding `v+1` refused an Add sequenced under
     `v`.
7. Merge.

There is no fetch, no post-decrypt deferral and no "named but not held" state. A Welcome
carries no commit AD; a joiner verifies the list via `GET .../seats` before it signs its join
intent (6.3), as before.

**Welcome during a pending unseat (DECISION (W0-fix3)).** The DS refuses every Add commit
while the group's `pending_removals` is non-empty
(`ProtectedChannelResecuring { reason: "pending_removal" }`, 6.1), so an honest server never
delivers a Welcome whose roster still contains a user the newest list dropped. As defense in
depth the joiner still checks every leaf user against its newest held list. An off-list
leaf in a Welcome does NOT refuse the Welcome. The joiner keeps the group state, its verdict
is `roster_mismatch` (`_encrypt` refuses), and the shield shows `resecuring` for the first
60 s, then `unverified` (9.1 step 6). That is not a hostile red at first sight. Meanwhile the
pending Remove (by the owner, or by any member for a pending-removal user) clears it.

---

## 4. Seat list, owner pin and handover

### 4.1 Seat list body (newline-canonical)

```
sloga-seat-list-v1
v:1
channel_id:{channel_id}
version:{decimal, 1 ..= 2^53 - 1}
device_cap:{decimal u32; 0 = unlimited}
issued_at:{decimal ms, 0 ..= 2^53 - 1}
signer_user_id:{user id}
signer_device_id:{device id}
seats:{user ids, sorted ascending by byte value, unique, joined by ","}
```

- Exactly 9 lines, in this order, no trailing LF.
- **Bounds (DECISION (W0-fix3)):** `version` is `1 ..= 2^53 - 1` (9007199254740991, JSON-safe,
  like epochs, 0.2) and `issued_at` is `0 ..= 2^53 - 1`. Builders refuse to produce anything
  outside that, and the server (4.3) and native (4.4) parsers refuse it as
  `FailedValidation` / `SeatListInvalid { reason: malformed }`. The 3.12.1 worst case
  already assumes these bounds.
- `seats` is never empty: it MUST contain `signer_user_id` (the signer is always seated).
  Count `<= slot_cap` (server) and `<= 100` (both sides).
- Builders sort and de-duplicate; verifiers REJECT an unsorted or duplicated line rather than
  normalizing it (`SeatListInvalid`), so one body has exactly one valid byte string.
- The plan's field set is `{v, channel_id, version, seats, device_cap, issued_at}`.
  **DECISION (W0):** `signer_user_id` and `signer_device_id` are added inside the signed body so
  the stored signer metadata cannot be re-attributed.
- `device_cap` MUST be **at most** the effective entitlement device cap at signing time
  (**DECISION (W0-fix4)**, replacing W0's "MUST equal"; the server refuses a larger value).
  `0` (unlimited) is allowed ONLY when the effective entitlement cap is itself `0`; when the
  entitlement cap is `0`, any value is allowed. `GET .../seats` returns
  `entitlement_device_cap` so the owner always knows the ceiling (7.2). Clients enforce the
  signed value; the server enforces `min(signed, entitlement)` (2.5). Why: with "MUST
  equal", raising the entitlement cap made every PUT fail until the owner somehow learned the
  new value.

### 4.2 Seat list signature

Ed25519 by the signer device's vodozemac identity key over the UTF-8 bytes of the body
exactly (the first line is the domain separation). Stored and transported as b64.

### 4.3 Server validation on `PUT /channels/:id/seats` (and the genesis list on protect)

The server is not the trust anchor, but it validates so garbage never reaches clients:

1. Parse the body strictly (4.1, including the W0-fix3 bounds on `version` and `issued_at`);
   `channel_id` equals the route channel.
2. `signer_user_id == caller == server.owner` (authorization), and `signer_device_id` is a
   registered E2EE device of the caller whose `last_session_id` is this session
   (`assert_bound_session`, the existing device-bound-session rule).
3. The signature verifies under that device's directory identity key (`verify_payload`).
4. `version == stored_version + 1` (genesis: `1`). **DECISION (W0):** strictly +1, so the
   server's compare-and-set is the equivocation guard; clients accept any higher version.
   **DECISION (W0-fix):** a PUT with `version == stored_version` whose body and signature are
   byte-identical to the stored row is an idempotent success with no side effects (the
   lost-response retry of 4.9); any other version is `FailedValidation`.
   **(DECISION (W0-fix8))** That byte-identical re-PUT returns the stored success
   IMMEDIATELY at this step, before steps 5 to 8, including 5b. A retry of a PUT that
   already landed must not be refused because the state moved on afterwards (for example
   the signer device lost its leaf in the meantime, or a seat claim would now exceed the
   cap). Steps 1 to 3 (parse, authorization, signature) still run first.
5. Every seated user is a member of the server, not a bot, not staff; the signer is seated.
5b. **Signer holds a leaf (DECISION (W0-fix7)).** When the channel has an open Text group, the
   signer device `(signer_user_id, signer_device_id)` must be in that group's `members`,
   else `FailedValidation`. Exempt: genesis (no group yet). An owner device without a leaf
   could otherwise publish a newer list whose signer-leaf check (4.4 step 5) fails on every
   member, which would poison the whole group.
6. `device_cap <= entitlement cap`, with `0` only if the entitlement cap is `0` (4.1,
   W0-fix4); else `FailedValidation`.
7. Atomically: seats newly listed are claimed (2.3), seats dropped are released (cooldown
   starts) and each dropped user that has at least one device in the open text group is added
   to `pending_removals`. Count check `active + cooling <= slot_cap` or `SeatCapReached`.
8. If a `handover` statement is supplied (**rule rewritten, DECISION (W0-fix3)**, so the 6.3
   handover flow can run), it is published by the CURRENT owner device, the `from` side:
   - its `channel_id` is this channel;
   - its `from_device_id` / `from_identity_key` are this PUT's signer device and that
     device's directory key;
   - its signature verifies under `from_identity_key`;
   - `to_user_id == from_user_id` (S1);
   - `to_device_id` is a registered E2EE device of that user, and `to_identity_key` is its
     directory key.

   It is appended (chain length `<= 16`, else `FailedValidation`). The successor device then
   signs the NEXT list itself. The server does NOT decide trust; clients do (4.5, 4.6).

### 4.4 Client verification and anti-rollback (`e2ee_text_seat_list_verify`)

**Order rewritten in W0-fix3** (anti-rollback FIRST, signer acceptance and the signer-leaf
check only for a NEWER list):

0. **Catch up first (DECISION (W0-fix3), aligned with the 7.2 snapshot in W0-fix5).**
   `GET .../seats` returns the list together with `as_of_epoch` and `as_of_group_id`. All
   three are read in ONE snapshot transaction (7.2), so they describe the same instant; there
   is no "list first, then epoch" ordering. A device that holds group state processes every
   commit in `as_of_group_id` up to `as_of_epoch` (gap refetch) BEFORE it verifies and adopts
   the `GET` list. If `as_of_group_id` is not its group, it takes the join path instead. Combined with the in-transaction AD
   check (3.12.2), this means every commit
   it processes afterwards embeds this list or a newer one, so a later-unseated user's
   earlier Add is processed while the older list is still held and never fails the 3.12.3
   step 6 check. If catch-up fails (commits pruned past retention, R9), the device is
   desynced and rejoins. A device without group state (a joiner) adopts directly.
1. Parse strictly (4.1, including the bounds); `channel_id` matches; 9 lines; sorted,
   unique, signer seated, at most 100.
2. **Anti-rollback FIRST.** Native stores the highest accepted `(version, sha256(body))` per
   channel in `mls_text_seat_lists`.
   - `version < stored`: `SeatListRollback`, stop.
   - `version == stored`: byte-identical body and signature give `unchanged`, stop; anything
     else is `SeatListEquivocation`, stop.

   A list at or below the held version therefore NEVER reaches signer acceptance and NEVER
   raises `OwnerChanged`. A hostile server replaying an older list signed by a previous owner
   key `K0` cannot get the pin moved back to `K0`.
3. **Signature (newer lists only, W0-fix).** Resolve the signer's identity key from this
   device's EXISTING slice-5 pin for `(signer_user_id, signer_device_id)` (no pin: the normal
   TOFU pin flow for that device; a pin in identity-changed state: `BadSig`, nothing
   persisted). The signature MUST verify under that key, else `BadSig`. `OwnerChanged` is
   never raised for a list that does not verify, so a forged list can never reach the owner
   confirmation dialog.
4. **Signer acceptance** (4.5; newer lists only). With no owner pin yet, the first-sight rule
   of 4.5 applies. Otherwise the verified signer key must be the pinned owner key, or reached
   FORWARD from it along the stored handover chain (4.6), or (same user only) the key the
   user confirmed natively for THIS newer list (4.7). Otherwise `OwnerChanged`: native records
   the pending signer as `(user_id, device_id, identity_key, same_user = (user_id == pinned
   owner_user_id), verified = slice-5 safety-number state of that device)` and persists
   nothing else. **The pin only ever moves forward:** along the chain, or by a same-user
   confirmation on a list newer than the held one.
5. **Signer-leaf check (newer lists only, DECISION (W0-fix3)).** If this device holds group
   state, the signer `(user, device)` holds a verified leaf whose credential identity key
   equals the signing key. It is NEVER run for an equal or older list. Otherwise removing
   the owner's device would invalidate the list every later commit must embed (the round-3
   BLOCKER). Exception (genesis): a version-1 list signed before the group exists (4.9); for a
   joiner the check runs at Welcome time. A Welcome whose roster lacks the newest list's
   signer is refused with **`SignerLeafMissing { channel_id }`** (**DECISION (W0-fix4)**: a
   distinct, non-owner-change error, mapped to `resecuring` in 9.2; it never opens the
   owner-change dialog). The usual cause is benign: the owner's signing device is mid-rejoin
   (its stale leaf was removed by the rejoin case and it has not been re-added). The joiner
   discards the Welcome and retries its join intent on the normal join-retry schedule.
6. Accept: store the list (with its chain), advance the version (and the pin, if the chain
   moved it), and mark every leaf whose user is not on the new list as off-list; `_encrypt`
   refuses until a Remove lands (3.8 step 3).

The same rules apply to a list that arrives embedded in a commit's `authenticated_data`
(3.12.3 step 3), with the embedded handovers as the chain, with two differences. Step 0 does
not apply, because the commit itself is the catch-up. And an embedded OLDER list is not an
error: it is simply not adopted (3.12.3 step 3). That check runs BEFORE the commit is
decrypted, and a failure there is a poisoned epoch instead of a refused fetch. A list is
stored together with the handover chain it arrived with (from `GET` or from the AD), because
the device's own commits must embed exactly that chain (3.12.1).

### 4.5 Owner pinning

Native stores per channel `mls_text_owner_pins (channel_id, owner_user_id, owner_device_id,
owner_identity_key, source, pinned_at, pending_signer)`, where `pending_signer` holds the
pending signer's `user_id`, `device_id` and **identity key** (not just user/device;
**DECISION (W0-fix)**), plus `same_user` and `verified` (4.4 step 4). The key never crosses IPC.

- **At protect (genesis):** the owner's own device signs the genesis list (`_seat_list_sign`,
  version 1). **DECISION (W0-fix):** genesis is allowed only when **the server holds no seat
  list for this channel** (the bridge passes the `GET .../seats` result, whose `list` is
  `null`; the server independently refuses version 1 when it holds a list and refuses protect
  on a protected channel). The absence of a local pin is NOT the criterion: a member device or
  an owner's replacement device also has no pin. The owner device pins itself
  (`source = protect`) only when it verifies the genesis list it reads back (4.9).
- **At first sight:** a member's device that has no pin for the channel pins the signer of the
  first list it verifies (`source = first_sight`), provided the signer's identity is the
  slice-5 pinned identity for `(signer_user_id, signer_device_id)` (TOFU through the existing
  pin flow; a pin in identity-changed state refuses). **DECISION (W0):** at first sight only,
  `signer_user_id` MUST also equal the server-reported owner; otherwise the list is refused
  with `OwnerChanged { same_user: false }`, and in S1 no confirmation is offered (4.7,
  **DECISION (W0-fix2)**). This is a consistency
  check only: the pin is never derived from `server.owner`, and after first sight
  `server.owner` is ignored.
- **The owner is never taken from `server.owner`.**
- The pin's trust level is the slice-5 verification state of that device; an unverified
  (TOFU) owner pin still allows the green shield (**DECISION (W0)**, consistent with DMs and
  calls; the roster panel shows per-member verification).

### 4.6 Handover statement

```
sloga-owner-handover-v1
v:1
channel_id:{channel_id}
from_user_id:{user id}
from_device_id:{device id}
from_identity_key:{b64 Ed25519 public key}
to_user_id:{user id}
to_device_id:{device id}
to_identity_key:{b64 Ed25519 public key}
issued_at:{decimal ms, 0 ..= 2^53 - 1}
```

Exactly 10 lines, no trailing LF, signed by the `from` device's identity key (b64 signature).
`issued_at` is bounded to `2^53 - 1` like the seat list's (**DECISION (W0-fix4)**); builders
refuse to produce anything larger, and the server and native parsers refuse it. The 3.12.1
worst case already assumes this bound.
S1 uses it for the owner moving to a new device (`to_user_id == from_user_id`). A different
`to_user_id` is format-valid, but **in S1 such a link is refused** (the chain walk stops
there, and `_owner_handover_sign` refuses to create one). Server ownership transfer is
refused in S1 (7.4), and cross-user succession is S2 (**DECISION (W0-fix2)**).

Chain walk (client): starting from the pinned key `K`, repeatedly find a stored statement
with `from_identity_key == K` whose signature verifies under `K` and whose `channel_id`
matches; set `K = to_identity_key` (and the pinned user/device to `to_*`). Stop when `K`
equals the list signer's key (accept, `source = handover`, persist the new pin) or when no
statement matches (`OwnerChanged`). Cycles are impossible to exploit (each step is signed) but
the walk is bounded by the chain length (16). The walk only moves FORWARD from the current
pin; it never re-pins a key earlier in the chain (W0-fix3).

**Self-qualification of the successor device (DECISION (W0-fix3)).** A device `K1` of the
owner user, whose own key is reached from its pinned owner key `K0` by this walk over the
chain it holds, qualifies as the owner device for signing. `_seat_list_sign` accepts "this
device is the pinned key OR a chain-verified successor of it" (8.3). The flow is in 6.3.

### 4.7 Blocking owner-change confirmation

When `OwnerChanged` is raised, the bridge calls `e2ee_text_owner_confirm_change`, which shows
a **native** blocking dialog (like `e2ee_call_confirm_downgrade`, so a compromised webview
cannot accept on the user's behalf) naming the channel and the new signer.
**DECISION (W0-fix):** the dialog states which case it is, from the stored pending signer.

- **Same user, new device** (confirmable): "The owner of #channel is now signing from a
  different device". It shows the verification state of the new signer's device ("You
  verified this device" / "This device is not verified; compare safety numbers first").
  Confirm re-pins to exactly the stored pending key (`source = confirmed`); a different key
  arriving later raises a fresh `OwnerChanged`. Cancel (`Declined`, the existing variant)
  leaves the channel in the `unverified` shield state with the composer disabled.
- **Different user** (**DECISION (W0-fix2)**: refused outright in S1, with NO confirm button):
  server ownership transfer is refused server-side in S1 (7.4), so a seat list signed by a
  different person can only come from a hostile or broken server. The native dialog is
  informational only ("#channel's member list is now signed by a different person: {name}.
  This is not allowed and the channel has been locked."). `e2ee_text_owner_confirm_change`
  returns `OwnerChanged { same_user: false }` without changing anything. The channel stays
  `unverified` with no composer until S2 succession exists.

No other path changes the pin.

### 4.8 Signer rules (summary)

A seat list is ADOPTED only if all hold, checked in this order (W0-fix3):

1. the version is newer than the held one (anti-rollback first; an equal byte-identical list
   is a no-op, an older or equivocating one never reaches the later checks);
2. the signature verifies under the signer device's slice-5 pin;
3. the signer key is the pin, chain-reached forward from it, or same-user-confirmed for this
   newer list;
4. the signer is on its own list;
5. the signer holds a verified leaf (newer lists only; genesis exception, 4.4 step 5).

### 4.9 Signing and publishing a seat list (no wedge, no equivocation)

**DECISION (W0-fix).**

- `e2ee_text_seat_list_sign` **persists nothing**: no stored version, no pin, no list. It
  returns signed bytes only.
- **Native confirmation on growth.** When the new list ADDS users relative to the base list
  (the device's stored verified list; at genesis, every seat other than the signer), `_sign`
  shows a native blocking dialog listing every added user (display name and user id) and the
  channel; cancel is `Declined` and nothing is signed. **Any INCREASE of `device_cap` is also
  growth** and gets the same dialog, stating the old and new cap (**DECISION (W0-fix2)**).
  Changing it to `0` (unlimited) from any non-zero value counts as an increase. Only a list
  that removes seats and/or lowers `device_cap` (a non-zero value below the old one, or any
  non-zero value when the old one was `0`) needs no dialog. `e2ee_text_owner_handover_sign`
  ALWAYS shows a native dialog naming the target device; in S1 it refuses a target of a
  different user (4.6).
- The bridge keeps the returned signed bytes until the publish resolves, and PUTs them. On a
  lost response or a transport error it **re-PUTs the SAME bytes**. The server treats a PUT
  whose `version` equals the stored version and whose body and signature are byte-identical
  to the stored row as an idempotent success (no seat changes, no new pending removals).
- The owner device's stored version (and, at genesis, its self-pin) advance only when it
  reads the list back with `GET .../seats` and `_seat_list_verify` accepts it. The owner's
  following Remove commits embed that read-back list (3.12).
- If the signed bytes are lost (crash) before a confirmed publish, the bridge first GETs: a
  list it signed at the new version means the earlier PUT landed (verify it); otherwise it
  signs again from the server's current list as the base. A second, different body at an
  already-stored version is refused by the server (`FailedValidation`, version not
  stored + 1 and not byte-identical), so the owner can never equivocate by retrying.
- `_sign` refuses (`SeatListBehind`) when the server's current list, as passed by the
  bridge, is not byte-identical to the device's stored verified list. The owner must verify
  the newest list first (`_seat_list_verify`), so it never signs a successor to a list it
  has not verified. This is the only remaining use of `SeatListBehind` (3.12 no longer uses
  it).

---

## 5. Test vectors (server and native parity)

Reading rule: each vector is the fenced block right after an HTML comment `tv:NAME`. A text
block's exact bytes are its lines joined by LF with **no trailing LF**. A `*_hex` block's
bytes are the concatenation of its lines (line breaks are for reading only). Every value was
recomputed by an independent checker before this document was committed (section 13).

**Where each side tests them.** Server (W1/W2): the seat list builder and parser (body bytes,
signature verify), the handover parser and signature verify, the text group id derivation,
the payload JSON structural validation, the 5.7 `commit_ad` built from a stored seat-list row,
and the 5.7 MLS framing-prefix parser. Native (W3): all of them, plus the exporter
context, AAD, envelope, XChaCha20-Poly1305 output, signature payload and signature. The
Ed25519 secret keys below are RFC 8032 32-byte seeds; Ed25519 is deterministic, so the
signatures are fixed and both sides can check them exactly (sign with the seed using
`ed25519-dalek`, and verify).

### 5.1 Inputs

<!-- tv:inputs -->
```text
channel_id = 01J9Z3K4M5N6P7Q8R9S0T1V2W3
owner_user_id = 01HZXAAAAAAAAAAAAAAAAAAAAA
owner_device_id = 00112233445566778899aabbccddeeff
owner_seed_hex = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
member_user_id = 01HZXBBBBBBBBBBBBBBBBBBBBB
member_device_id = ffeeddccbbaa99887766554433221100
member_seed_hex = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
new_owner_device_id = 0123456789abcdef0123456789abcdef
new_owner_seed_hex = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
seats_unsorted = 01HZXCCCCCCCCCCCCCCCCCCCCC,01HZXAAAAAAAAAAAAAAAAAAAAA,01HZXBBBBBBBBBBBBBBBBBBBBB
seat_version = 3
seat_device_cap = 5
issued_at = 1790812800000
epoch = 7
epoch_key_hex = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
aead_nonce_hex = 606162636465666768696a6b6c6d6e6f7071727374757677
cid = 01JA0000000000000000000MSG
ts = 1790812800000
text = hello, protected world
replies = 01J9Z3K4M5N6P7Q8R9S0T1V2W0
```

The member (`01HZXB...`, device `ffee...`) is the message author. The epoch key is a fixed
input (the MLS exporter itself needs live group state and is covered by native round-trip
tests, not by this vector).

### 5.2 Identity public keys (b64 of the Ed25519 public key for each seed)

<!-- tv:owner_identity_key -->
```text
A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
```

<!-- tv:member_identity_key -->
```text
Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc
```

<!-- tv:new_owner_identity_key -->
```text
zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o
```

### 5.3 Seat list (signed by the owner device)

Built from `seats_unsorted` (the builder sorts), `seat_version`, `seat_device_cap`,
`issued_at`, signer = owner user and owner device.

<!-- tv:seat_list_body -->
```text
sloga-seat-list-v1
v:1
channel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3
version:3
device_cap:5
issued_at:1790812800000
signer_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA
signer_device_id:00112233445566778899aabbccddeeff
seats:01HZXAAAAAAAAAAAAAAAAAAAAA,01HZXBBBBBBBBBBBBBBBBBBBBB,01HZXCCCCCCCCCCCCCCCCCCCCC
```

Same bytes as hex, one body line per row (each row but the last ends in `0a`):

<!-- tv:seat_list_body_hex -->
```text
736c6f67612d736561742d6c6973742d76310a
763a310a
6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a
76657273696f6e3a330a
6465766963655f6361703a350a
6973737565645f61743a313739303831323830303030300a
7369676e65725f757365725f69643a3031485a584141414141414141414141414141414141414141410a
7369676e65725f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a
73656174733a3031485a584141414141414141414141414141414141414141412c3031485a584242424242424242424242424242424242424242422c3031485a58434343434343434343434343434343434343434343
```

<!-- tv:seat_list_body_sha256 -->
```text
1d4a02cc0065715b926db563902ca4a6bc7961cb6bd832a9f03544ab59bf7b48
```

The signature input is the body bytes above, exactly. Signature (owner seed):

<!-- tv:seat_list_signature -->
```text
HtbS6jbLvwSZxAe4i2a4lwmKhv4hM+3NkMY1EuwRaPyv9kI3x/3t1SsalteuxoxmG4YFczXUA77134HTJwLRCA
```

### 5.4 Handover (owner device to the owner's new device, signed by the owner device)

<!-- tv:handover_body -->
```text
sloga-owner-handover-v1
v:1
channel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3
from_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA
from_device_id:00112233445566778899aabbccddeeff
from_identity_key:A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
to_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA
to_device_id:0123456789abcdef0123456789abcdef
to_identity_key:zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o
issued_at:1790812800000
```

<!-- tv:handover_signature -->
```text
JKnYtaiK/i3tYSxV71XoXyz9l0XaDsWIhzoCu8s9IuTdmFmWX5BNtoEhpt+v9gSvhE+nqS2/kZEA0CX6giR6BA
```

### 5.5 Text group ids (3.1)

Generation 0 (used by 5.6) and generation 1:

<!-- tv:group_id_g0 -->
```text
4a4ba4afc6e6ea1c9f4a271f7eded44ea860fdb814e4e1377121e02635a715b5
```

<!-- tv:group_id_g1 -->
```text
b4989a8d9b082e1668a726aa3303d3eb8b52688d340ca4dc1e0184f61fc67000
```

### 5.6 Message (author = member, group = generation 0, epoch 7)

Exporter context (raw group id, then `u64_be(7)`), 40 bytes:

<!-- tv:exporter_context_hex -->
```text
4a4ba4afc6e6ea1c9f4a271f7eded44ea860fdb814e4e1377121e02635a715b5
0000000000000007
```

AAD, one length-prefixed field per row (context, channel id, group id, epoch, author, sender
device, cid), 209 bytes:

<!-- tv:aad_hex -->
```text
000d736c6f67612d746578742d7631
001a30314a395a334b344d354e365037513852395330543156325733
004034613462613461666336653665613163396634613237316637656465643434656138363066646238313465346531333737313231653032363335613731356235
00080000000000000007
001a3031485a58424242424242424242424242424242424242424242
00206666656564646363626261613939383837373636353534343333323231313030
001a30314a41303030303030303030303030303030303030304d5347
```

Envelope (the AEAD plaintext, 134 bytes):

<!-- tv:envelope_json -->
```text
{"v":1,"cid":"01JA0000000000000000000MSG","ts":1790812800000,"text":"hello, protected world","replies":["01J9Z3K4M5N6P7Q8R9S0T1V2W0"]}
```

XChaCha20-Poly1305(key = `epoch_key_hex`, nonce = `aead_nonce_hex`, plaintext = envelope,
aad = AAD), ciphertext with the 16-byte tag appended (150 bytes), b64:

<!-- tv:ciphertext_b64 -->
```text
7lyFR0kjzwme2lNYYODt2rZmmYbNUdZ30V/L+qdgbzKONjAeYv8uelDf4K/WcWB+eZH5NVTNV+9i0rW+AGfyD6wMllEfcDpoWSemybsLAnUd2vkx5tmdCrhnWkKmIt4AYuiW2wJroVo6I6KRe9NVyjAYMDwcOtyPnYobI5CPNwg3O7QjdMMjhdkjNGEVh4oGVS+nI04P
```

Signature payload (3.7), exact bytes:

<!-- tv:sig_input -->
```text
sloga-text-sig-v1
nonce:YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3
aad:AA1zbG9nYS10ZXh0LXYxABowMUo5WjNLNE01TjZQN1E4UjlTMFQxVjJXMwBANGE0YmE0YWZjNmU2ZWExYzlmNGEyNzFmN2VkZWQ0NGVhODYwZmRiODE0ZTRlMTM3NzEyMWUwMjYzNWE3MTViNQAIAAAAAAAAAAcAGjAxSFpYQkJCQkJCQkJCQkJCQkJCQkJCQkJCACBmZmVlZGRjY2JiYWE5OTg4Nzc2NjU1NDQzMzIyMTEwMAAaMDFKQTAwMDAwMDAwMDAwMDAwMDAwMDBNU0c
ciphertext:7lyFR0kjzwme2lNYYODt2rZmmYbNUdZ30V/L+qdgbzKONjAeYv8uelDf4K/WcWB+eZH5NVTNV+9i0rW+AGfyD6wMllEfcDpoWSemybsLAnUd2vkx5tmdCrhnWkKmIt4AYuiW2wJroVo6I6KRe9NVyjAYMDwcOtyPnYobI5CPNwg3O7QjdMMjhdkjNGEVh4oGVS+nI04P
cid:01JA0000000000000000000MSG
ts:1790812800000
replies:01J9Z3K4M5N6P7Q8R9S0T1V2W0
```

<!-- tv:sig_input_sha256 -->
```text
5665222b571fdfa2c8974a570ee2d15dda0db4164c97f0d1da813ef4bab08d03
```

Signature (member seed):

<!-- tv:message_signature -->
```text
Ylo7oNHshb/EPJ67afoJrw2H0t6FKRiM3dDOUbHGchXCtq3AqxJLv0GuR87KNu8msVg2nKn3iVs4OCDOu15MAA
```

The resulting `encrypted` JSON (compact, `franking` absent); the REST body adds
`"nonce":"01JA0000000000000000000MSG"`:

<!-- tv:payload_json -->
```text
{"v":1,"group_id":"4a4ba4afc6e6ea1c9f4a271f7eded44ea860fdb814e4e1377121e02635a715b5","epoch":7,"sender_device_id":"ffeeddccbbaa99887766554433221100","nonce":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3","ciphertext":"7lyFR0kjzwme2lNYYODt2rZmmYbNUdZ30V/L+qdgbzKONjAeYv8uelDf4K/WcWB+eZH5NVTNV+9i0rW+AGfyD6wMllEfcDpoWSemybsLAnUd2vkx5tmdCrhnWkKmIt4AYuiW2wJroVo6I6KRe9NVyjAYMDwcOtyPnYobI5CPNwg3O7QjdMMjhdkjNGEVh4oGVS+nI04P","sig":"Ylo7oNHshb/EPJ67afoJrw2H0t6FKRiM3dDOUbHGchXCtq3AqxJLv0GuR87KNu8msVg2nKn3iVs4OCDOu15MAA"}
```

XChaCha20 here is HChaCha20(key, nonce[0..16]) as the subkey with IETF ChaCha20-Poly1305 over
the 12-byte nonce `00000000 || nonce[16..24]` (draft-irtf-cfrg-xchacha-03); the checker
validated that construction against the draft's own section 2.2.1 and A.3.1 vectors.

### 5.7 Commit `authenticated_data` (3.12) and its MLS framing prefix

Replaced in W0 fix round 2 (the round-1 version/hash form is withdrawn); the 5.1 to 5.6
vectors are unchanged. The AD embeds the 5.3 seat list (body and signature) and a one-entry
handover chain (the 5.4 statement), 832 bytes. One row per element, in order: context field,
seat-list body field, seat-list signature field (raw 64 bytes), handover count (`u16_be`),
handover body field, handover signature field (raw 64 bytes):

<!-- tv:commit_ad_hex -->
```text
0017736c6f67612d746578742d636f6d6d69742d61642d7631
011e736c6f67612d736561742d6c6973742d76310a763a310a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a76657273696f6e3a330a6465766963655f6361703a350a6973737565645f61743a313739303831323830303030300a7369676e65725f757365725f69643a3031485a584141414141414141414141414141414141414141410a7369676e65725f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a73656174733a3031485a584141414141414141414141414141414141414141412c3031485a584242424242424242424242424242424242424242422c3031485a58434343434343434343434343434343434343434343
00401ed6d2ea36cbbf0499c407b88b66b897098a86fe2133edcd90c63512ec1168fcaff64237c7fdedd52b1a96d7aec68c661b86057335d403bef5df81d32702d108
0001
017f736c6f67612d6f776e65722d68616e646f7665722d76310a763a310a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a66726f6d5f757365725f69643a3031485a584141414141414141414141414141414141414141410a66726f6d5f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a66726f6d5f6964656e746974795f6b65793a41364548762f504f454c3464634e3059353076416d57666b316a436270513166486479475a424a564d62670a746f5f757365725f69643a3031485a584141414141414141414141414141414141414141410a746f5f6465766963655f69643a30313233343536373839616263646566303132333435363738396162636465660a746f5f6964656e746974795f6b65793a7a52537a663556756c5447552f332b334f7a3242334d5668316870314f416c4c664434615a44376c38366f0a6973737565645f61743a31373930383132383030303030
004024a9d8b5a88afe2ded612c55ef55e85f2cfd9745da0ec588873a02bbcb3d22e4dd9859965f904db68121a6dfaff604af844fa7a92dbf919100d025fa82247a04
```

<!-- tv:commit_ad_sha256 -->
```text
9cc01bfe85923de2a68126c90f891806c0ced23191dc1b44c0d02edb0a4b0ea4
```

The serialized commit (`MLSMessage`) a server receives for this AD, a commit created in epoch 7
of the generation-0 group, begins with these bytes, one element per row: `version` = mls10,
`wire_format` = mls_private_message, `group_id` length (varint) and bytes, `epoch` (u64),
`content_type` = commit, `authenticated_data` length (varint `0x4000 | 832`). The 832 AD bytes
above follow immediately, then the opaque `encrypted_sender_data<V>` and `ciphertext<V>`:

<!-- tv:commit_prefix_head_hex -->
```text
0001
0002
20
4a4ba4afc6e6ea1c9f4a271f7eded44ea860fdb814e4e1377121e02635a715b5
0000000000000007
03
4340
```

---

## 6. Admission and removal rules

### 6.1 Server side (Delivery Service, defense in depth; W2)

| Operation (Text group) | Rule |
|---|---|
| Create or successor (`POST /mls/groups`, `kind: Text`) | Channel protected; entitlement `Active`; **the caller is the CURRENT seat list's `signer_user_id` and the session is bound to its `signer_device_id`** (the owner's pinned device; not "any seated member", **DECISION (W0-fix)**); `generation` present, `<= 63`, and `group_id == group_id(channel, generation)` (3.1); without `supersedes` the generation is `0`, with `supersedes` it is the superseded Text group's generation + 1 and the superseded group belongs to this channel; growth gate (7.1). Skips the voice/presence checks of call create |
| Join intent | Caller **seated**; device session-bound; growth gate. Rejoin = this `(user, device)` is already a member (device-aware lookup, replacing `member_device_of`). A new device is refused when the user's member devices already equal the **enforced** device cap, `min(signed-list cap, entitlement cap)` (2.5; W0-fix5, was "effective") |
| KeyPackage claim (group is Text) | Claimer is a current member device AND seated (else `NotSeated`); growth gate. Each target must be seated and hold ViewChannel, else that target's status is `NotFound` |
| Every Text commit: existing-row check (W0-fix7; position pinned W0-fix8) | In BOTH the route and the driver: AFTER the access checks (not a bot; `assert_bound_session` for the submitting device; seated AND ViewChannel, the commit-fetch authorization) and BEFORE every validity check (membership, AD, Remove/Add rules, growth gate, `pending_removal`), a commit row already at `{group}:{epoch}` returns `Lost { winning: <that row> }` (409). This makes an identical-bytes resubmit idempotent without letting an unauthorized caller read commit rows (2.5 step 0) |
| Every Text commit (W0-fix2, W0-fix3) | The MLS framing prefix parses (3.12.2, else `FailedValidation`), and its `authenticated_data` is byte-identical to the `commit_ad` of the newest stored seat list (else `ProtectedChannelResecuring { reason: "stale_seat_list" }`). The route pre-checks; the binding check is **inside the Text commit transaction** (Mongo multi-document transaction; Reference lock order), via `seat_list_ad_sha256` (2.5, 3.12.2; W0-fix4). Applies to Add, Remove and Update commits alike, including with the flag off |
| Commit with `added` | Committer is a current member device. **Refused while `pending_removals` is non-empty** (`ProtectedChannelResecuring { reason: "pending_removal" }`, **DECISION (W0-fix3)**, so a joiner never receives a roster with an unseated user). Every added device: **not already a member, and not also listed in `removed`** (no same-commit Remove + re-Add of one device in S1, **DECISION (W0-fix7)**; matches today's `commits_submit.rs` refusal and the driver's "added device already a member"); registered E2EE device; its user **seated AND has ViewChannel** (the friend/DM-eligibility OR is dropped for Text); per-user device count within the **enforced device cap = min(signed-list cap, effective entitlement cap)** (inside the commit transaction, 2.5); total leaves `<= 100`. Growth gate |
| Commit `removed` list (any Text commit; W0-fix3 main-session decision, amended W0-fix4) | The exact rule is 3.12.2 "Remove rule". **The current list signer's device can be removed ONLY in the rejoin case** (a stored, verified, outstanding rejoin intent from that device, copied into the commit's `rejoin_intents`), regardless of every other case. Every other removed device must be one of: a device of the committer's own user other than the committing device; a device of a `pending_removals` user; a device whose E2EE identity was revoked (looked up inside the transaction); ONLY when the committer is the current list signer's device, a device of a user absent from the newest signed list; or a device with an outstanding rejoin intent. Anything else is `FailedValidation`. Checked in the route and inside the commit transaction. **Enforceable only together with the receiver declaration binding (3.12.3 step 6)** |
| Commit with only `removed` or an Update | Committer is a current member device. No seat-list signature is needed for a removal, but the Remove rule above applies. Allowed with the flag off |
| `pending_removals` clearing | After a won commit, every pending entry whose user has no remaining member device is removed from the list |
| Commit fetch | Caller seated and has ViewChannel |
| Ctl pipe (`POST /mls/groups/:id/messages`) | Refused for Text groups (`InvalidOperation`) |
| Encrypted send | 7.3 |

### 6.2 Client side (native; W3). The real trust decisions.

| Operation | Rule |
|---|---|
| Admit a device (`_admit`) | The join intent verifies under the pinned slice-5 identity of `(user, device)`; the user is on the **newest verified seat list** (and the bridge has seen them seated per the server); not forced-removed since that list (below); the user's leaf count stays `<= device_cap` of the signed list; total leaves `<= 100` (`TextGroupFull`) |
| Process any commit (W0-fix2) | 3.12.3, in order: read and parse the AD BEFORE decrypting; verify the embedded list under the owner pin; adopt it if newer; only then decrypt; assert the authenticated AD equals the pre-checked bytes. Any failure before decryption is a poisoned epoch and nothing is decrypted |
| Process a commit that adds or removes | Runs AFTER the embedded list has been adopted (3.12.3 step 6). Every added leaf passes the leaf acceptance rule (3.2), its user is on the newest held list, it is not in forced-removal memory, and the per-user `device_cap` and 100-leaf cap hold. The actual adds, removes and committer equal the server-recorded declarations (W0-fix4). A Remove of the owner's pinned signing device is accepted only with a verified rejoin intent from that device in `rejoin_intents` (W0-fix4). A failure takes the **poisoned-epoch / successor path** (loud), NOT a per-device rejoin (**DECISION (W0-fix3)**) |
| Process a Welcome (`_process`) | Outstanding join intent for this group (else `MlsUnsolicitedWelcome`); group id equals `group_id(intended channel, generation)` for the generation recorded with the join intent (`ChannelMismatch`); every leaf verified; the newest list's signer holds a leaf (4.4 step 5; else `SignerLeafMissing`, resecuring, retry the join, W0-fix4). A leaf user absent from the newest held list does NOT refuse the Welcome (W0-fix3): verdict `roster_mismatch`, shield `resecuring` for 60 s, then `unverified` (3.12.3 "Welcome during a pending unseat") |
| Remove (`_remove`) | No seat-list signature needed. The bridge only stages Removes the 6.1 Remove rule allows from this device: its own user's OTHER devices (never itself; OpenMLS refuses self-removal), `pending_removals` users, revoked devices, (owner device only) off-list users, and devices with a verified outstanding rejoin intent. **It never stages a Remove of the owner's pinned signing device except in the rejoin case** (W0-fix4). Native refuses a forbidden target with `NotOwner` |
| Forced-removal memory | When a Remove takes out a user who is still on the newest verified list (a server-forced removal), native records `(channel, user, list_version)` in `mls_text_forced_removals`; that user is not re-admitted until a list with a **higher** version includes them. A visible marker is shown (9.3) |
| Encrypt | 3.8: refused on any roster member off the newest list or locally removed (`RosterMismatch`), owner pin changed, not seated, Update ceiling |
| Decrypt | 3.9 |
| Call commands | `mls_call_*` / `e2ee_call_*` refuse text group ids (`WrongGroupKind`); text commands refuse call ids |

### 6.3 Flows

**Protect (owner).** Admin grants the entitlement (7.2). Owner device: `GET .../seats`
(`list: null`); `_seat_list_sign` (version 1, seats = owner plus any initial members; native
dialog if it seats anyone besides the owner); `PUT /channels/:id/protect` with that list;
`GET .../seats` and `_seat_list_verify`, which is when the owner device pins itself (4.9);
`_group_create` (generation 0); `POST /mls/groups` (`kind: Text`, `generation: 0`). Then seat
and admit as below.

**Seat a member.** Owner: `_seat_list_sign` (version n+1, native dialog listing the added
users); `PUT /channels/:id/seats` (re-PUT the same bytes on a lost response); `GET .../seats`,
catch up to its `as_of_epoch`, then `_seat_list_verify` (the owner's stored version advances
here; 4.4 step 0). The member's device: `GET /channels/:id/seats`; `_seat_list_verify` (pins
the owner on first sight; a joiner has no group state, so no catch-up);
`GET /mls/channels/:id/text_group`; `_join` (with the stated `generation`) and
`POST .../join_intent`. An online member device admits (leaf-index stagger as for calls):
`_admit`, claim, commit Add + Welcome. The commit's `authenticated_data` embeds the
admitter's newest verified list (3.12.1), and the server accepts it only if that is its newest
list (inside the commit transaction). On `ProtectedChannelResecuring { reason: "stale_seat_list" }` the
admitter calls `_commit_lost`, catches up, verifies `GET .../seats` and re-admits. On
`reason: "pending_removal"` it waits for the pending Remove to land (Adds are refused while
any removal is pending, 6.1). Every other member processes the Add in the 3.12.3 order: adopt
the embedded list, then check the added user against it. The member processes the Welcome.

**Owner unseat.** Owner device: `_seat_list_sign` without the user (no dialog: removal only);
`PUT .../seats` (server releases the seat and adds the pending removal, so sends are refused);
`GET .../seats`, catch up to `as_of_epoch`, `_seat_list_verify`; `_remove` for every leaf of
that user (permitted: the user is in `pending_removals`, and also off the newest list with
the owner device committing), embedding the new list (3.12.1); submit the commit; on win the server clears the pending entry. This is one
UI action. Every member adopts the new list from that commit's AD before decrypting it. If the
owner's commit never wins, the owner's shield goes `unverified` (its own `_encrypt` refuses:
the user is off its list). Members learn the new list from the next sequenced commit that
carries it (an honest server only accepts commits carrying its newest list, 6.1) or from the
periodic `GET .../seats` refresh (7.5). From then on their `_encrypt` refuses too, and any
member may commit the Remove. Against a hostile server, see R11.

**Server-forced removal (kick, ban, leave, account deletion).** `Member::remove` and
`clear_memberships` release the user's seat in every protected channel of the affected
server(s) and add a pending removal on each open text group where the user has a device.
These writes are not best-effort: a failure fails the operation. Member clients learn of it
from `ProtectedChannelResecuring { reason: "pending_removal" }` on send or from the text-group
state refresh, and any member device commits the Remove (leaf-index stagger, 2 s; permitted
because the user is in `pending_removals`, 6.1 Remove rule).

The owner is never a server-forced-removal target (W0-fix4 correction; the round-3 "owner
account deletion" exception is deleted because it cannot happen). The owner cannot be kicked
from their own server, and `User::delete` deletes every server the user owns BEFORE it calls
`clear_memberships` (`users/model.rs`). Deleting the owner's account therefore cascades as a
SERVER deletion: every protected channel of that server is deleted with its entitlement,
seats, seat list, Text group and commits (7.5 "Delete cascades"). No pending removal of the
owner is ever created.

**Update.** 3.11.

**Successor (poisoned epoch).** As calls (media plan 1.4), with `kind: Text`, generation
`g + 1` (3.1), created only by the current seat-list signer's device (6.1). Members that detect
the poisoned epoch stay `resecuring` until the owner's device creates the successor; with the
owner's device lost, the channel stays there (R12).

**Every member wiped its state (DECISION (W0-fix5)).** If the group's only member, or every
member, has wiped its local group state, no leaf-holder remains to serve a rejoin (no one can
commit the Remove of a stale leaf, and a device cannot remove itself). The Call path closes
such a group at the join-intent route (`join_intent.rs`, sole-member case). For Text:

- the join-intent route does NOT close the group;
- the owner's signing device, or a chain-verified successor that has signed the current list
  (4.6), creates a SUCCESSOR group (`supersedes` the old one, generation `g + 1`, 6.1), and
  every seated member's device joins it through the normal join path;
- history stays readable from local epoch keys only where a device kept them (R4).

A bridge detects this case when its join intent goes unanswered past the join-retry budget
while `GET .../text_group` shows only stale members. It surfaces `resecuring`, and on the
owner's device it offers "Re-create the protected group". Under R12 (the owner's device lost
and no successor qualified) this is a **freeze**: no successor can be created in S1.

**Owner moves to a new device (handover; DECISION (W0-fix3)).** Old owner device `K0` (pinned
everywhere), new device `K1` of the SAME user:

1. **K1 joins as an owner-user device.** The owner user is seated, so K1 joins like any
   member device of a seated user (`_join`, join intent, admitted by any member) within the
   enforced `device_cap`. K1 verifies the current list on the way in and pins `K0` on first
   sight. K1 now holds a leaf, which it will need for the signer-leaf check (4.4 step 5).
2. **K0 signs the handover.** `e2ee_text_owner_handover_sign(to = K1)` always shows K0's
   native confirmation naming the target device (4.9). K0 then publishes it: it signs the
   next list `v+1` (same seats; removal-or-equal, so no growth dialog) and PUTs it with
   `handover` attached. The server checks the 4.3 step 8 rules and appends the statement. K0
   reads it back and verifies it.
3. **K1 verifies the chain locally and qualifies.** K1 fetches `GET .../seats`, catches up
   and verifies `v+1` (signed by its pin `K0`; the chain `K0 -> K1` is now stored). Its
   chain walk from `K0` reaches its own key, so it is a chain-verified successor (4.6).
4. **K1 signs the next list.** `_seat_list_sign` accepts "pinned key OR chain-verified
   successor" (8.3). K1 signs `v+2` and PUTs it (the server's `signer == server.owner` holds;
   same user). K1 reads it back.
5. **Members re-pin.** Every member learns `v+2` (from the next commit's AD or `GET`). It is
   newer, signed by K1, and reached forward from the pin `K0` along the stored chain, and K1
   holds a leaf. So the member adopts it and re-pins to `K1` (`source = handover`). No dialog
   is shown to members.
6. **K1 removes K0 (own-user case; DECISION (W0-fix4)).** Once `v+2` is the server's list,
   K0 is no longer the current list signer's device. K1, the committer, then Removes K0 as a
   device of its own user (6.1 Remove rule case 2), embedding `v+2`. A device can never
   remove itself (OpenMLS `CannotRemoveSelf`), so K0 does not. Alternatively K0 simply stays
   a member device. From then on K1 is the owner device: it creates successors and commits
   owner Removes.

**Owner signing device rejoin (DECISION (W0-fix4)).** If the owner's signing device `K0` wipes
its local group state (crash, rejoin-fresh), its stale leaf can only be removed by ANOTHER
member, because self-removal is impossible:

1. K0 signs a rejoin intent (the normal join intent; `join_intent.rs` flags it `rejoin`
   because `(user, K0)` is already a member).

   **Eviction-loop guard (DECISION (W0-fix6), liveness only):**
   - a device NEVER sends a join (or rejoin) intent while native says it holds a leaf in
     the group's current epoch (`e2ee_text_state.state == "active"`); `_join` refuses in
     that state;
   - the bridge CANCELS all pending join retries the moment a Welcome for that group is
     processed.

   Otherwise a retry fired just after a re-Add could hand some member a fresh rule-6 intent
   and evict the device again.
2. A member device verifies the intent against its pinned identity for K0, then commits the
   Remove of K0's stale leaf. That is allowed by 6.1 Remove rule case 6, and the DS copies
   the intent into the commit's `rejoin_intents`.
3. Every receiver accepts that Remove of the owner's pinned device only because it verifies
   the copied intent (3.12.3 step 6).
4. K0's next intent is admitted normally (the owner user is seated), and K0 holds a fresh
   leaf.

The current list, signed by K0, stays valid throughout: equal-version lists are never
leaf-checked (4.4 step 5). A joiner whose Welcome lands while K0 is out sees
`SignerLeafMissing` and retries (4.4 step 5).

**Owner device loss.** Seat changes freeze (R12). Nothing in S1 can re-pin members to a new
owner device unless the old device ran steps 2 to 3 of the handover above before it was
lost. The lost device's leaf is never removed: the DS refuses every Remove of the current
list signer's device except the rejoin case (6.1), and a lost device never sends a rejoin
intent.

**Server ownership transfer.** Refused while the server has any protected channel (7.4), so
`server.owner` and the pinned owner cannot drift apart in S1.

### 6.4 Permission loss (not handled in S1)

A seated member who loses ViewChannel keeps their seat and their leaves and still receives
new epochs. S1 mitigation only: `GET /channels/:id/seats` returns `seated_without_access: true`
for them (owner caller) and the owner's seat UI highlights them for unseating. The reconciler
is S2. This is why the HOLD in 1.1 exists.

---

## 7. API (W2)

### 7.1 Feature flag and gates

```toml
[features.protected_channels]
enabled = false              # master switch for growth (grants, protect, seating, adds)
default_device_cap = 5       # 0 = unlimited (still bounded by 100 leaves)
commit_retention_days = 30   # crond prunes Text commits older than this
```

Config struct `ProtectedChannelsFeatures` (copy the `BoostFeatures` pattern: `#[serde(default)]`
fields, `impl Default`, documented block in `Revolt.toml`). Advertised in `routes/root.rs` as
`protected_channels: { enabled, default_device_cap }`.

Gates (**kind-aware**; the media gate body is unchanged and stays pinned by `flag_delegation`):

- Call-kind MLS routes: `require_media_e2ee_enabled()` (unchanged).
- Text **growth** operations: `require_protected_growth()` =
  `e2ee_enabled && protected_channels.enabled`.
- Text **maintenance** operations: `require_protected_available()` = `e2ee_enabled`. This
  includes the encrypted send: **an encrypted send while `e2ee_enabled = false` is refused
  with `FeatureDisabled { feature: "e2ee" }`** (**DECISION (W0-fix)**). It is **the first
  check inside the handler, after the request guards and JSON parsing** (Rocket's `Json`
  guard parses the body before the handler runs). That includes the existing channel
  permission checks it follows, and it comes before any protected-send validation of the
  parsed body (7.3 step 0; **DECISION (W0-fix3)**, reworded from round 2's "before any body
  processing", which Rocket cannot do; one order for both sections). Plaintext stays refused
  on the protected channel either way.
  **DECISION (W0):** the text plane needs the E2EE identity directory, so `e2ee_enabled = false`
  stops it entirely (the global E2EE kill switch); `protected_channels.enabled = false` only
  stops growth.
- KeyPackage publish (shared directory): `e2ee_enabled && (media_e2ee_enabled || protected_channels.enabled)`.

**Flag-off semantics** (flag off never unprotects; the plan's rule, made concrete):

| Operation | Flag off |
|---|---|
| Admin grant, `PUT .../protect` | Refused `FeatureDisabled { feature: "protected_channels" }` |
| `PUT .../seats` adding anyone | Refused `FeatureDisabled` |
| `PUT .../seats` that only removes | Allowed (removal must always be possible) |
| Text group create, join intent, KeyPackage claim, commits with `added` | Refused `FeatureDisabled` |
| Remove/Update commits, commit fetch, text group state, `GET .../seats` | Allowed |
| Encrypted send, history, receive | Allowed (**DECISION (W0)**: existing protected channels keep working) |
| Plaintext send, attachments, every 7.4 refusal | Still refused: the channel is still protected |

Consequence, stated so nobody mistakes it for a bug: with the flag off, every Add is refused,
including the re-admission of a member device that desynced and must rejoin. Such a device
stays in `resecuring` until the flag is back on. Growth is frozen; nothing is unprotected and
nothing falls back to plaintext.

### 7.2 Routes

All bodies are JSON. Unless stated, errors include `NotFound` / `MissingPermission` from the
existing channel resolution.

**Admin grant.** `PUT /channels/:channel_id/protected_entitlement` (**DECISION (W0)** path;
pattern copied from `users/boost_grant.rs`).
Request `DataGrantChannelEntitlement { slot_cap: u32 (1..=100), device_cap: Option<u32> }`.
Response `ChannelEntitlement` (v0). Caller `privileged` (`NotPrivileged`); channel is a server
`TextChannel`; growth gate. Upsert: an existing entitlement's caps are updated; lowering
`slot_cap` below the seats in use is `SeatCapReached { max }`. Logs an `AUDIT` line.

**Protect.** `PUT /channels/:channel_id/protect`. Request
`DataProtectChannel { seat_list: DataSeatList }`. Response: the v0 `Channel` with
`protected: true`. Rules: caller is the server owner (a hard check, not the permission
calculus, because `calculate_channel_permissions` grants all to privileged accounts first);
growth gate; `Active` entitlement (else `InvalidOperation`); channel is a server `TextChannel`
with no `voice` and not an announcement channel (else `InvalidOperation`); channel has no
messages, `last_message_id == None` (**DECISION (W0)**: protecting a channel with history is
S4; else `InvalidOperation`); already protected is `InvalidOperation`; a privileged (staff)
owner is `InvalidOperation` (2.3, **DECISION (W0-fix)**). The seat list is the
genesis list (`version: 1`), validated per 4.3, stored, seats claimed, all atomically with
setting the flag.

On success the server emits the existing `ChannelUpdate { id, data: PartialChannel { protected: Some(true), .. }, clear: [] }`
event (**DECISION (W0-fix)**), so every connected client sets its local protected pin (9.4)
immediately rather than on its next channel fetch.

`DataSeatList { body: String, signature: String, signer_device_id: String, handover: Option<SignedHandover> }`.

**Seats.** `PUT /channels/:channel_id/seats`, request `DataSeatList`, response
`ResponseChannelSeats` (below). Validation 4.3. Errors: `NotOwner`, `FeatureDisabled` (adds
with the flag off), `SeatCapReached { max }`, `FailedValidation` (body, version, cap,
signature), `IsBot`, `InvalidOperation` (staff), `NotAuthenticated` (session not bound to the
signer device).

`GET /channels/:channel_id/seats`, any user with ViewChannel. Response:

```json
{
  "list": {
    "version": 3,
    "body": "sloga-seat-list-v1\nv:1\n...",
    "signature": "<b64>",
    "signer_user_id": "<ULID>",
    "signer_device_id": "<hex32>",
    "handovers": [{ "body": "sloga-owner-handover-v1\n...", "signature": "<b64>" }]
  },
  "as_of_epoch": 7,
  "as_of_group_id": "<hex64>",
  "entitlement_device_cap": 5,
  "slot_cap": 10,
  "device_cap": 5,
  "seats_used": 4,
  "seats": [
    { "user_id": "<ULID>", "seated_at": "<ISO 8601>", "seated_without_access": false }
  ],
  "cooling": [
    { "user_id": "<ULID>", "released_at": "<ISO 8601>", "cooldown_until": "<ISO 8601>" }
  ]
}
```

`as_of_epoch` (**DECISION (W0-fix3)**) is the open Text group's `current_epoch`, and
`as_of_group_id` (**DECISION (W0-fix4)**) is that group's id. Both are `null` when there is no
open Text group. **Snapshot read (DECISION (W0-fix4)):** the seat-list row and the group
document are read in ONE Mongo transaction with read concern `snapshot` (Reference: under
the 2.5 lock order, holding `channel_seat_lists` and `mls_groups` together). The round-3 rule
"list first, then epoch" read two documents at different moments, so a racing seat PUT
could return a newer epoch with an older list, or the reverse, and produce a false
`SeatListRollback` red.

Devices with group state catch up to `as_of_epoch` in `as_of_group_id` before adopting `list`
(4.4 step 0). If `as_of_group_id` is not the device's group, it is out of date (a successor
exists) and takes the join path instead. Because the in-transaction AD check (3.12.2) ties
every later commit to this list or a newer one, a consistent snapshot makes the catch-up
sufficient. `device_cap` here is the enforced cap (2.5); `entitlement_device_cap` is the
ceiling a newly signed list may use (4.1, W0-fix4).

`list` is `null` only for a channel that is not protected. `seated_without_access` is computed
(ViewChannel for that user) and present **only when the caller is the server owner**; omitted
otherwise (**DECISION (W0)**: other members' permission state is not disclosed).

**Text group create.** `POST /mls/groups` with `DataCreateMlsGroup` gaining
`kind: MlsGroupKind` (`#[serde(default)]` = `Call`, so existing callers are unchanged) and
`generation: Option<u32>` (required for `Text`, refused for `Call`; **DECISION (W0-fix)**).
Response unchanged (`Created` / 409 `Conflict { open_group_id, channel_id }`). Rules 6.1:
only the current seat-list signer's device may create; `supersedes` must name a Text group of
the same channel and `generation` must be its generation + 1.

**Text group state.** `GET /mls/channels/:channel_id/text_group` (**DECISION (W0)**: a new
route; the existing `open_group` route becomes Call-scoped). ViewChannel; maintenance gate.
Response:

```json
{
  "group_id": "<hex64>",
  "channel_id": "<ULID>",
  "generation": 0,
  "current_epoch": 7,
  "members": [{ "user_id": "<ULID>", "device_id": "<hex32>" }],
  "pending_removals": [{ "user_id": "<ULID>", "created_at": "<ISO 8601>" }],
  "member_added": [{ "user_id": "<ULID>", "device_id": "<hex32>", "epoch": 5, "at": "<ISO 8601>" }]
}
```

`NotFound` when the channel has no open Text group. `member_added` (**DECISION (W0-fix7)**)
exposes each member device's latest Add epoch and time (2.5). The bridge uses its own
device's entry to suppress join retries once it has been re-Added: if an entry for this
device exists with `epoch` at or after the rejoin it requested, it stops retrying and waits
for or refetches the Welcome. This is only a liveness aid; the native eviction-loop guard
(6.3) does not depend on it.

**Existing MLS routes**, behavior by the stored group's kind: join intent, KeyPackage claim,
commit submit and commit fetch per 6.1; the ctl pipe refuses Text.

### 7.3 Protected-channel send (`POST /channels/:id/messages`)

**Allowlist: only `nonce`, `encrypted` and `flags` (silent only).**

```json
{ "nonce": "01JA0000000000000000000MSG", "encrypted": { ...EncryptedPayload... }, "flags": 1 }
```

- `nonce`: REQUIRED, ULID (the `cid`).
- `encrypted`: REQUIRED.
- `flags`: absent, `0` or `1` (SuppressNotifications). Any other bit is refused.
- Any other `DataMessageSend` field that is present and non-null (even an empty string or
  empty array) is refused with `ProtectedFieldRefused { field }`: `content`, `attachments`,
  `replies`, `embeds`, `masquerade`, `interactions`, `components`, `sticker_ids`. Server-side
  mention parsing never runs.
- Conversely, `encrypted` on a non-protected channel is refused
  (`ProtectedFieldRefused { field: "encrypted" }`, **DECISION (W0)**).

The request MUST NOT carry an `Idempotency-Key` header (3.10, **DECISION (W0-fix)**); the
server refuses one on a protected send (`ProtectedFieldRefused { field: "idempotency-key" }`)
so a client that still sends it fails loudly instead of intermittently.
**W2 note (DECISION (W0-fix2)):** the refusal MUST test the RAW request header, e.g. a small
request guard or a `&Request` read that records whether `Idempotency-Key` was present.
`IdempotencyKey::from_request` (`util/idempotency.rs`) mints a ULID key when the header is
absent, so its `key` cannot tell "absent" from "present". The existing guard also runs first:
a header whose value is already in its cache is refused by the guard with `DuplicateNonce`
(409) before the route body runs (9.2).

Server checks, in this one order (the same order 7.1 states):

- (before the handler) authentication and the request guards, including the
  `Idempotency-Key` guard and Rocket's `Json` body parsing;
- (handler) the existing channel permission checks (ViewChannel, SendMessage);
0. `e2ee_enabled` is on, else `FeatureDisabled { feature: "e2ee" }` (7.1). This is the first
   protected-send check inside the handler (W0-fix3 wording). The body has been parsed as
   JSON by the guard but not yet validated.
1. Raw `Idempotency-Key` header absent; allowlist and structural validation (2.6).
2. Caller seated (`NotSeated`).
3. Session bound to `encrypted.sender_device_id` (`NotAuthenticated`).
4. The channel's open Text group exists and `group_id` matches, else
   `ProtectedChannelResecuring { reason: "stale_group" }`.
5. `pending_removals` empty, else `ProtectedChannelResecuring { reason: "pending_removal" }`.
6. `epoch == current_epoch`, else `ProtectedChannelResecuring { reason: "stale_epoch" }`.
7. `(caller, sender_device_id)` is a current member, else
   `ProtectedChannelResecuring { reason: "not_member" }`.

The server never verifies `sig` (it cannot rebuild the payload: `ts` and `replies` are inside
the ciphertext).

### 7.4 Routes that refuse on protected channels (`ChannelProtected`)

- Message edit (all edits, S1).
- Forward from a protected channel, and forward into one.
- Crosspost from or to a protected channel.
- Scheduled messages (create).
- Webhooks: create on, and execute into, a protected channel.
- Forum posts (if the target is protected).
- `message_roll.rs`, `poll_create.rs`.
- System messages: none are written into a protected channel (join/leave/pin/rename notices
  are suppressed, not errors). **DECISION (W0):** pin and unpin themselves stay allowed; only
  their system message is suppressed.
- `thread_create.rs`, `follow_create.rs`.
- Voice join, and any edit adding `voice` or the announcement flag.
- `Channel::update` with `protected: Some(false)`.
- **Server ownership transfer** (**DECISION (W0-fix)**): every path that changes
  `Server.owner` (`DataEditServer.owner` in `server_edit.rs`, and the privileged/staff
  transfer path; W2 must enumerate every writer of `Server.owner`) is refused with
  `ChannelProtected` while the server has ANY protected channel. Pinned choice: reuse
  `ChannelProtected` (no new variant, no field); the client knows the context is a transfer
  and shows "Ownership can't be transferred while this server has protected channels."
  Deleting the protected channels first lifts the refusal. Succession is S2.
- Search: protected messages are never indexed; a search scoped to a protected channel
  returns no results.

Allowed: fetch, delete, bulk delete, reactions (plaintext emoji metadata, residual R6),
pins, typing indicators, acks.

### 7.5 Other server behavior

- **pushd**: a protected message produces a generic notification (body "New message", no
  content, no preview); `SuppressNotifications` is honored.
- **Delete cascades**: `channel_delete.rs` and the bulk server delete remove the channel's
  entitlement, seats and seat list, close the open Text group and delete its commits.
- **Events**: **DECISION (W0):** S1 adds no new websocket events. Clients refresh
  `GET .../seats` and `GET .../text_group` on channel open, on every processed commit, on every
  `ProtectedChannelResecuring` error and every 60 s while the channel is open. S2 adds push
  events.

### 7.6 New errors (`revolt_result`, all status-mapping files)

| Variant | Fields | HTTP |
|---|---|---|
| `ProtectedChannelResecuring` | `reason: String` (`pending_removal` on a send, and from W0-fix3 also on an Add commit while removals are pending, 6.1; `stale_epoch`, `stale_group`, `not_member`; and from W0-fix2 `stale_seat_list` on a Text commit, 3.12.2) | 409 |
| `NotSeated` | none | 403 |
| `SeatCapReached` | `max: usize` | 400 |
| `ChannelProtected` | none | 400 |
| `ProtectedFieldRefused` | `field: String` | 400 |

**DECISION (W0):** the `reason` and `field` / `max` fields. The frontend needs the usual cast
for new `ErrorType`s (the `stoat-api` types are upstream).

---

## 8. Native command surface (W3)

### 8.1 Separation and routing

- New module `e2ee-core/src/mls/text.rs` with its own tables (8.2). Routing of any MLS
  envelope, commit or Welcome is decided by **native table lookup**, never by a server-supplied
  kind: `e2ee_mls_group_kind(group_id)` returns `"call"`, `"text"` or `null` (for a Welcome:
  the table of the outstanding join intent).
- `mls_call_*` / `e2ee_call_*` refuse text group ids with `WrongGroupKind`; text commands
  refuse call ids the same way.
- `e2ee_call_local_groups` (`mls_call_local_groups`) returns **call groups only**: the
  frontend startup wipe in `mlsCallSession.ts` relies on it.
- `leave_cleanup` and the downgrade grant never touch text groups.
- **Envelope declarations (DECISION (W0-fix4)).** `wire::MlsEnvelope` gains
  `committer: Option<MlsMemberDevice>`, `added: Vec<MlsMemberDevice>`,
  `removed: Vec<MlsMemberDevice>` and `rejoin_intents: Vec<MlsJoinRequest>`, all
  `#[serde(default)]`. **Wire element for `rejoin_intents` (DECISION (W0-fix5)), identical on
  the envelope AND on `MlsCommitInfo` (the v0 type W2 adds is `MlsRejoinIntentInfo`):**
  `{ "group_id", "channel_id", "user_id", "device_id", "key_package_ref", "signature" }`, all
  strings. This is exactly native `wire::MlsJoinRequest`, which requires `channel_id`. The
  stored row (`MlsCommit.rejoin_intents: Vec<MlsJoinIntent>`) has no `channel_id`, so the
  server fills it from the group's `channel_id` when it serializes. `_id` and `created_at` are
  not sent. Native verifies the signature over `mls_join_intent_payload(user_id, device_id,
  group_id, key_package_ref)`, which does not cover `channel_id`. Native therefore also checks
  that `channel_id` and `group_id` equal the commit's own group and channel, and refuses a
  mismatch as `CommitDeclarationMismatch`. The server fills them from the stored commit row on every `mls_commit`
  envelope. `_process` on a Text commit uses them for the 3.12.3 step 6 declaration binding.
  Call processing ignores them (unchanged behavior). Commit gap-refetch uses `MlsCommitInfo`,
  which carries the same fields (`rejoin_intents` added).

### 8.2 Native storage (excluded from key backup in S1)

| Table | Contents |
|---|---|
| `mls_text_groups` | `group_id` (PK), `channel_id`, `generation`, `state` (`joining`/`active`/`poisoned`/`left`; `left` added in W0-fix7: no leaf, MLS state wiped, rejoin allowed, 2.5 "Wipe-and-rejoin"), `last_epoch`, `superseded_by`, `created_at` |
| `mls_text_epoch_keys` | `(group_id, epoch)` PK, `key_sealed`, `roster` (JSON leaf list incl. identity keys), `first_seen_at` |
| `mls_text_seat_lists` | `channel_id` PK, `version`, `body`, `body_sha256`, `signature`, `signer_user_id`, `signer_device_id`, `handovers` (the chain it arrived with, in order; embedded verbatim in this device's commits, 3.12.1) |
| `mls_text_owner_pins` | 4.5 |
| `mls_text_forced_removals` | `(channel_id, user_id)`, `list_version`, `removed_at` |
| `mls_text_seen` | 3.10 |
| `mls_text_join_intents` | intents this device issued `(group_id, channel_id, generation, key_package_ref, created_at)`, where `created_at` is the local time of issue (the single field name, unified in W0-fix9). Used for Welcome routing and the outstanding-intent check; the own-intent replay rule is clock-free and does not read it (3.12.3 step 6) |
| `mls_text_self` | per group: `last_self_update_at`, `sent_since_update` (3.11). (The W0-fix8 `own_leaf_since_at` column is dropped in W0-fix9.) |
| `mls_text_pending_commits` (W0-fix6) | `group_id` PK, `epoch`, `commit_b64`: the serialized own commit written in the same SQLite transaction as the OpenMLS pending stage; deleted on won/lost (2.5 "Commit outcome recovery") |
| `mls_text_consumed_rejoin_intents` (W0-fix6) | `(group_id, signature)` PK: signatures of rejoin intents consumed by commits this device merged, both others' commits (`_process`) and its own (`_commit_won`, W0-fix8); a replay is `ReplayedRejoinIntent` (3.12.3 step 6), and `e2ee_text_remove` refuses a consumed intent |

Table names other than `mls_text_epoch_keys` (plan-pinned) are **DECISION (W0)** and may be
renamed by W3 with a note in its report.

### 8.3 Commands

Each command needs its autogenerated permission TOML and a `capabilities/default.json` allow;
`generate_handler!` has a single owner lane. Argument names below are the Rust parameter
names; from JavaScript, Tauri's default mapping takes them in camelCase (`channelId`). Struct
payloads serialize snake_case. Errors are the typed `Error` (8.4).

**DECISION (W0):** prefix `e2ee_text_`, parallel to `e2ee_call_`. The plan's ten names are kept
(`group_create`, `join`, `process`, `encrypt`, `decrypt`, `seat_list_sign`, `seat_list_verify`,
`owner_pin_state`, `remove`, `state`); seven are added because the flows in 6.3 need them:
`admit`, `commit_won`, `commit_lost`, `update`, `owner_confirm_change`, `owner_handover_sign`,
and the routing query `e2ee_mls_group_kind`.

| Command | Arguments | Returns |
|---|---|---|
| `e2ee_text_group_create` | `channel_id, user_id, supersedes: Option<String>` | `TextGroupCreated { group_id, generation, payload: CreateMlsGroupPayload }` (payload carries `kind: "Text"` and `generation`). Refuses `NotOwner` unless this device signed the newest verified seat list (6.1) |
| `e2ee_text_join` | `group_id, channel_id, generation: u32, user_id` | `MlsJoinIntentPayload` (existing wire type). Refuses `ChannelMismatch` unless `generation <= 63` and `group_id == group_id(channel_id, generation)` for exactly that generation (3.1). Refuses `AlreadyMember { group_id }` only while the group is `active`, i.e. this device holds a leaf (2.5 definition: the OpenMLS group is operational AND its own leaf is present). From `left`, `none` or `joining` it proceeds (the eviction-loop guard, 6.3; W0-fix6, pinned in W0-fix7) |
| `e2ee_text_admit` | `request: MlsJoinRequest, claimed: MlsClaimedKeyPackage` | `SubmitMlsCommitPayload` |
| `e2ee_text_process` | `envelope: MlsEnvelope, user_id` | `TextProcessOutcome` |
| `e2ee_text_commit_won` | `group_id, won_epoch: i64, stored_commit_b64: String` (W0-fix6) | `TextProcessOutcome`. Merges only if `stored_commit_b64` (the DS's stored string) equals the b64 persisted with the pending stage; otherwise `OwnCommitMismatch` (wipe-and-rejoin, 2.5). On merge it also records the commit's `rejoin_intents` signatures in `mls_text_consumed_rejoin_intents` (W0-fix8) |
| `e2ee_text_commit_lost` | `group_id` | `()`; also deletes the persisted pending-commit bytes |
| `e2ee_text_pending_commit` (W0-fix6) | `group_id` | `Option<{ epoch: i64, commit_b64: String }>`: the persisted bytes of the staged own commit, so after a crash the bridge can resubmit IDENTICAL bytes or compare (2.5 "Commit outcome recovery") |
| `e2ee_text_encrypt` | `channel_id, user_id, text: String, replies: Vec<String>` | `TextEncrypted { nonce, encrypted: EncryptedPayload }` |
| `e2ee_text_decrypt` | `channel_id, message_id, author_user_id, nonce, encrypted: EncryptedPayload, live: bool` | `TextDecrypted` |
| `e2ee_text_seat_list_sign` (async; native dialog when the list adds users or raises `device_cap`, 4.9) | `channel_id, user_id, seats: Vec<String>, device_cap: u32, server_list: Option<{ version, body }>` (the bridge's latest `GET .../seats` `list`) | `SignedSeatList { version, body, signature, signer_user_id, signer_device_id }`. **Persists nothing** (4.9). Genesis (version 1) only when `server_list` is `null` (the server holds no list) and this device holds no list for the channel. Otherwise version = the stored verified version + 1, and `server_list` must equal the stored verified list (else `SeatListBehind`). Refuses `NotOwner` unless this device is **the pinned owner key OR a chain-verified successor of it** (the held chain walks forward from the pin to this device's key, 4.6; **DECISION (W0-fix3)**) (except genesis). Refuses a version above `2^53 - 1` (4.1). **Refuses (`SignerLeafMissing`) unless this device's text group for the channel is `active` and holds a leaf (2.5 "holds a leaf"); genesis is exempt** (DECISION (W0-fix7); mirrored server-side by 4.3 step 5b). Shows the native growth dialog listing added users and any `device_cap` increase (4.9); cancel is `Declined` |
| `e2ee_text_seat_list_verify` | `channel_id, list: { body, signature, signer_user_id, signer_device_id }, handovers: Vec<SignedHandover>, server_owner_id` | `SeatListVerdict { status: "accepted" \| "unchanged", version, seats, device_cap, signer_user_id, signer_device_id, pinned_now: bool }` |
| `e2ee_text_owner_pin_state` | `channel_id` | `OwnerPinState { channel_id, status: "unpinned" \| "pinned" \| "changed", owner_user_id, owner_device_id, owner_verified: bool, source, pending_signer: Option<{ user_id, device_id, same_user: bool, verified: bool }> }` (the pending identity key is stored natively, never returned) |
| `e2ee_text_owner_confirm_change` | `channel_id` (async; native dialog, 4.7) | `()`; cancel is `Declined`. For a different-user pending signer there is no confirm button; it returns `OwnerChanged { same_user: false }` and changes nothing (S1) |
| `e2ee_text_owner_handover_sign` (async; ALWAYS a native dialog naming the target) | `channel_id, user_id, to_user_id, to_device_id` | `SignedHandover { body, signature }`. The `to` identity key comes from this device's slice-5 pin of `(to_user_id, to_device_id)`; refuses `NotOwner` unless this device is the pinned owner; cancel is `Declined`; persists nothing |
| `e2ee_text_remove` | `group_id, targets: Vec<MlsMemberDevice>, rejoin_intent: Option<MlsJoinRequest>` (W0-fix5) | `SubmitMlsCommitPayload`. **Target rules (DECISION (W0-fix5), consistent with 3.12.2 rule 1, the 6.2 `_remove` row and the 6.3 owner rejoin flow):** (1) a target that is THIS device itself is always refused (OpenMLS `CannotRemoveSelf`); (2) a target that is the owner's pinned signing device is staged ONLY when `rejoin_intent` is supplied for exactly that `(user_id, device_id)` and this `group_id`, and its signature (`acutest:e2ee:mls-join:v1`) verifies under this device's slice-5 pin for that device; otherwise `NotOwner`; (3) another device of this device's own user (the own-user case, e.g. 6.3 handover step 6) is allowed; (4a) **any device of a user the bridge marks as pending removal** (from `GET .../text_group` `pending_removals`) is allowed for ANY member device, whether or not the user is still on the signed list. A kicked, banned or departed user IS still on the list, and any member must be able to remove them, or one kick freezes all sends (7.3 step 5) (**DECISION (W0-fix6)**; this mirrors 3.12.2 rule 3); (4b) devices of users **absent from the newest signed list** are allowed ONLY when this device is the owner's signing device (mirrors 3.12.2 rule 5); (5) a device the bridge marks as revoked, or as having a verified outstanding rejoin intent whose signature is NOT already in `mls_text_consumed_rejoin_intents` (a consumed one is refused, `ReplayedRejoinIntent`, W0-fix8) (passed as `rejoin_intent`), is allowed. Anything else is `NotOwner`. A single `rejoin_intent` covers one target, so a commit removing the owner device carries only that target. The DS enforces the full rule |
| `e2ee_text_update` | `group_id` | `SubmitMlsCommitPayload` (HPKE-only self-update) |
| `e2ee_text_state` | `channel_id` | `TextChannelState` |
| `e2ee_mls_group_kind` | `group_id` | `Option<"call" \| "text">` |

Result shapes:

- `TextProcessOutcome { group_id, channel_id, kind: "welcome_joined" | "commit_applied" | "duplicate", epoch, removed_self: bool, added: Vec<MlsMemberDevice>, removed: Vec<MlsMemberDevice>, new_devices: Vec<MlsMemberDevice>, off_list: Vec<String> }`.
  `new_devices` = added devices whose user already had a leaf (the "new device joined" marker).
  `off_list` = leaf users absent from the newest verified list after this epoch. Plus
  `seat_list_adopted: Option<i64>`, the version adopted from the commit's embedded list
  before decryption (3.12.3 step 3), or `None` when it was not newer. Any failure of the
  pre-decryption checks returns the typed error and decrypts nothing (poisoned path); an
  owner-change pending confirmation returns `OwnerChanged` and decrypts nothing.
- `TextDecrypted { message_id, channel_id, group_id, epoch, author_user_id, sender_device_id, cid, ts, text, replies, sender_verified: bool, ts_skew: bool }`.
- `TextChannelState { channel_id, group_id: Option, generation: Option, epoch: Option<i64>, state: "none" | "joining" | "active" | "poisoned" | "left", members: Vec<{ user_id, device_id, user_verified, on_signed_list, removed_locally }>, seat_list: Option<{ version, signer_user_id, signer_device_id, seats, device_cap, issued_at }>, owner_pin: OwnerPinState, self_seated: bool, roster_matches_list: bool, update_due: bool, update_required: bool, verdict: "ok" | "no_group" | "joining" | "not_seated" | "no_seat_list" | "roster_mismatch" | "owner_changed" | "poisoned" }`.
  `verdict == "ok"` iff: group active, a verified seat list exists, this user is on it, every
  leaf user is on it and none is locally removed, and the owner pin is not in the changed state.
  Otherwise the verdict is the FIRST that applies, in this order: `owner_changed`,
  `no_seat_list`, `not_seated`, `no_group`, `joining`, `poisoned`, `roster_mismatch`.
  (W0-fix2: the round-1 `seat_list_behind` verdict is removed. A newer embedded list is
  adopted before decryption, so a "named but not held" state cannot exist.) State `left`
  (W0-fix7) yields verdict `no_group`, so the shield shows `resecuring` while the device
  rejoins.

### 8.4 Typed errors (added to `e2ee-core` `Error`, serde tag `type`, snake_case)

No variant carries key material (invariant 6). Plan-pinned: `UnknownEpoch`, `BadSig`,
`NotSeated`, `RosterMismatch`, `OwnerChanged`. Added (**DECISION (W0)**): the rest.

| Variant | Fields | Raised by |
|---|---|---|
| `UnknownEpoch` | `group_id, epoch, oldest_held: Option<i64>, current: i64` | decrypt step 4 |
| `UnknownSender` | `user_id, device_id, epoch` | decrypt step 5 |
| `BadSig` | `user_id, device_id` | decrypt steps 6 and 8; seat list or handover signature, including a list embedded in a commit AD (3.12.3 step 3: nothing decrypted, poisoned path) |
| `NotSeated` | `channel_id` | encrypt; seat list not including self |
| `RosterMismatch` | `group_id, users: Vec<String>` | encrypt (off-list leaves, transient); processing an Add that fails 3.12.3 step 6 (poisoned path). A Welcome with off-list leaves is NOT an error (verdict `roster_mismatch`, W0-fix3) |
| `OwnerChanged` | `channel_id, signer_user_id, signer_device_id, same_user: bool, verified: bool` | seat list verify and the commit-AD pre-check (only after the signature verified, and only for a NEWER list, 4.4; nothing decrypted). `same_user: false` is final in S1 (4.7). NOT used for a Welcome lacking the signer's leaf (that is `SignerLeafMissing`, W0-fix4) |
| `SignerLeafMissing` | `channel_id` | Welcome whose roster lacks the newest list's signer (4.4 step 5; **DECISION (W0-fix4)**). Benign cause: the owner device is mid-rejoin. Never opens the owner-change dialog |
| `CommitDeclarationMismatch` | `group_id, epoch: i64` | a commit's actual adds, removes or committer differ from the server-recorded declarations, or the declarations are missing from a Text commit envelope (3.12.3 step 6; **DECISION (W0-fix4)**); poisoned path |
| `NotOwner` | `channel_id` | seat list sign, handover sign, text group create; `_remove` of a forbidden target; processing a commit that Removes the owner's pinned device by another sender (poisoned path, 3.12.3 step 6) |
| `SeatListRollback` | `channel_id, have: i64, got: i64` | seat list verify |
| `SeatListEquivocation` | `channel_id, version: i64` | seat list verify; commit-AD pre-check (nothing decrypted, poisoned path) |
| `SeatListBehind` | `channel_id, have: i64, need: i64` | `_seat_list_sign` only: the server's current list (passed by the bridge) is not the stored verified one (4.9). W0-fix2 removed its `_process` and `_encrypt` uses |
| `SeatListInvalid` | `channel_id, reason: SeatListRejection` (closed: `malformed`, `wrong_channel`, `unsorted`, `duplicate`, `signer_not_seated`, `signer_mismatch`, `too_many_seats`) | seat list verify; commit-AD pre-check (nothing decrypted, poisoned path). An AD that does not parse at all is `SeatListInvalid { reason: malformed }` (3.12.3 step 2) |
| `RemovedSender` | `user_id, device_id, epoch` | decrypt step 9 |
| `Replay` | `cid, first_message_id` | decrypt step 10 |
| `ChannelMismatch` | `group_id` | join, Welcome, decrypt step 3 |
| `AlreadyMember` | `group_id` | `_join` while the group is `active` (holds a leaf, 2.5) (6.3 eviction-loop guard; **DECISION (W0-fix6)**). Never raised from `left`; every leaf-losing path moves the group to `left` first (W0-fix7) |
| `OwnCommitMismatch` | `group_id, epoch: i64` | the DS shows an own commit at an epoch whose bytes differ from the persisted stage, or an own commit (including one that hit `CannotDecryptOwnMessage`) whose bytes do not match the persisted stage, or for which no stage is persisted. A `CannotDecryptOwnMessage` with MATCHING bytes merges as won instead (W0-fix7). **Wipe-and-rejoin (state `left`), NOT poisoned** (2.5; **DECISION (W0-fix6)**) |
| `DuplicateLeaf` | `group_id, user_id, device_id` | a Welcome or a staged epoch with two leaves for the same `(user, device)` (3.12.3; **DECISION (W0-fix6)**); poisoned path |
| `ReplayedRejoinIntent` | `group_id, user_id, device_id` | a rule-6 Remove citing a rejoin intent whose signature this device already saw consumed (3.12.3 step 6; **DECISION (W0-fix6)**); or (W0-fix8) a commit citing an intent for this device's OWN `(user, device)` that it did not issue since its current leaf; poisoned path. Also returned by `e2ee_text_remove` for an already-consumed `rejoin_intent` (nothing staged) |
| `UnexpectedMlsContent` | `group_id` | the Text commit path received a standalone proposal or an application message (3.12.3 step 1; **DECISION (W0-fix6)**); refused before anything is stored |
| `UpdateRequired` | `group_id` | encrypt (3.11) |
| `TextGroupFull` | `max: usize` | admit; processing an Add that exceeds 100 leaves (poisoned path) |
| `MalformedTextPayload` | `reason` (closed: `structure`, `envelope`, `cid_mismatch`, `too_large`) | encrypt and decrypt |
| `WrongGroupKind` | `group_id` | call commands given a text id and vice versa |

Existing `MlsGroupNotFound`, `MlsUnsolicitedWelcome`, `MlsLeafRejected`, `MlsEpochGap`,
`MlsPoisonedEpoch` and `Declined` (a cancelled native dialog) apply to text groups with their
current meaning. None of the text errors
is ever a quiet drop (unlike `MlsStaleCtl`).

---

## 9. Client: shield state and error to UI mapping (W4)

### 9.1 Shield state

Enum (in a `node --test`-loadable module with no Solid or livekit imports):

```ts
type ProtectedShieldState =
  | "protected"      // green: verified local state only
  | "resecuring"     // joining, catching up, pending removal, removal in flight
  | "not_seated"     // read-only; "Ask the owner for a seat"
  | "not_available"  // no native E2EE on this device; read-only, no composer
  | "unverified"     // LOUD: verification failed or the server contradicted a pin
  | "grace"          // reserved (S5); never produced in S1
  | "frozen";        // reserved (S5); never produced in S1
```

It is computed only for channels that are server-protected **or locally pinned**; other
channels have no shield. Inputs:

- `serverProtected`, `locallyPinned`: booleans;
- `capable`: `nativeE2EEAvailable()` AND the Tauri transport;
- `seatListError`: the error tag of the last `e2ee_text_seat_list_verify`, or `null`;
- `groupError`: the error tag of the last text-group join/process call, or `null`;
- `native`: the latest `TextChannelState`, or `null` while loading;
- `serverGroup`: the latest `GET .../text_group` body, or `null`;
- `rosterMismatchAgeMs`: how long `verdict` has been `roster_mismatch` (0 otherwise);
- `signerLeafMissingRetries` (**W0-fix5**): how many consecutive join attempts ended in
  `SignerLeafMissing` (0 otherwise; reset on a successful join);
- `welcomeRetriesExhausted` (**W0-fix6**): true once this device's join-intent retries (3,
  media plan 1.4 step 5) have run out with no Welcome processed. That is the R5 "stranded
  Welcome" shape.

Message-level errors (`bad_sig` on a message, `replay`, ...) never change the channel shield;
they produce markers (9.3). First match wins:

1. `locallyPinned && !serverProtected`: `unverified` (the flag was stripped).
2. `!capable`: `not_available`.
3. `seatListError` in {`bad_sig`, `owner_changed`, `seat_list_rollback`,
   `seat_list_equivocation`, `seat_list_invalid`}, or `groupError` in {`channel_mismatch`,
   `roster_mismatch`, `mls_leaf_rejected`, `owner_changed`, `seat_list_equivocation`,
   `wrong_group_kind`, `bad_sig`, `seat_list_invalid`, `text_group_full`, `not_owner`,
   `commit_declaration_mismatch`, `duplicate_leaf`, `replayed_rejoin_intent`}, or
   `native.verdict == "owner_changed"`: `unverified`. (`bad_sig` and `seat_list_invalid` as
   a `groupError` come from the 3.12.3 commit-AD pre-check; `roster_mismatch`,
   `mls_leaf_rejected`, `text_group_full` and `not_owner` as a `groupError` come from the
   3.12.3 step 6 commit checks, poisoned path, W0-fix3. A Welcome with off-list leaves is
   NOT a `groupError`; it surfaces as `native.verdict == "roster_mismatch"`, step 6. An honest
   server or an honest committer never produces these, so they are loud, not just
   `resecuring`.)
4. `native == null`: `resecuring`.
5. `native.verdict == "not_seated"`: `not_seated`.
6. `native.verdict == "roster_mismatch"`: `resecuring` while `rosterMismatchAgeMs < 60000`, then
   `unverified` (**DECISION (W0)**: a legitimate unseat briefly leaves an off-list leaf until
   the Remove lands; a mismatch that persists past 60 s is treated as hostile).
6c. `signerLeafMissingRetries >= 3` (the join-retry budget): `unverified` (**DECISION
   (W0-fix5)**). Fewer retries fall through to step 7 as `resecuring` (the joiner's verdict
   is `joining`).
6d. `welcomeRetriesExhausted`: `unverified`, loud (**DECISION (W0-fix6)**). The R5 stranded
   Welcome is never shown as an endless `resecuring`. Catch-up is S2; until then the user
   sees the loud state and can retry manually.
6e. (**DECISION (W0-fix7)**) `groupError` in {`own_commit_mismatch`, `already_member`,
   `unexpected_mls_content`} NEVER makes the shield `unverified` by itself:
   - `own_commit_mismatch` is this device's own desync. It goes through wipe-and-rejoin, so
     the state is `left` and the verdict `no_group`, which step 7 shows as `resecuring`.
   - `already_member` is a benign refused duplicate join.
   - `unexpected_mls_content` is a dropped envelope (9.2).

   These fall through to the following steps.
7. `native.verdict` in {`no_group`, `joining`, `poisoned`, `no_seat_list`},
   `serverGroup.pending_removals` non-empty, or `native.epoch` behind
   `serverGroup.current_epoch`: `resecuring`.
8. `native.verdict == "ok"`: `protected`.
9. Anything else: `unverified` (fail closed).

**Rule:** `protected` is produced only by step 8, which requires the native verdict `ok`.
Green is never derived from a server field, and never shown while the local roster has anyone
off the signed list or locally removed (`verdict` is then `roster_mismatch`). The spec must
assert exhaustiveness (`const exhaustive: never = state`) and every precedence step.

The composer exists only in `protected`. `resecuring` shows a disabled composer with the
re-securing notice; `not_seated` shows "Ask the owner for a seat"; `not_available` shows
"Not available on this device"; `unverified` shows the loud banner and no composer.

### 9.2 Error to UI mapping

| Source | Error | Shield / state | User-facing (suggested copy, final strings via lingui) |
|---|---|---|---|
| Server | `ProtectedChannelResecuring { reason }` | `resecuring` | "Re-securing this channel..." The draft stays in the composer; the bridge refreshes state, catches up or commits the pending Remove, then retries the send once |
| Server | `ProtectedChannelResecuring { reason: "stale_seat_list" }` on a commit submit | unchanged (transparent) | the committer calls `_commit_lost`, verifies the current `GET .../seats` list, re-stages and resubmits (3.12.2) |
| Server | `DuplicateNonce` (409), from the `Idempotency-Key` request guard (W0-fix2) | unchanged | On a protected send it means the client sent the forbidden header (7.3): a client defect, reported to Sentry, never retried with plaintext. Elsewhere it keeps its existing meaning (duplicate retry: possibly delivered, refetch) |
| Server | `NotSeated` | `not_seated` | "You don't have a seat in this protected channel. Ask the owner for a seat." |
| Server | `SeatCapReached { max }` | owner seat UI | "All {max} seats are in use. Released seats count for 14 days." |
| Server | `ChannelProtected` | unchanged | "Not available in protected channels." (the UI should hide these actions on protected channels). On an ownership-transfer request: "Ownership can't be transferred while this server has protected channels." (7.4) |
| Server | `FeatureDisabled { feature: "e2ee" }` on a protected send | unchanged; composer notice | "Encrypted messaging is unavailable right now." The draft stays; never sent as plaintext |
| Server | `InvalidOperation` on a protected send retry | unchanged | treated as "possibly delivered": the bridge refetches the channel to confirm (3.10) |
| Server | `ProtectedFieldRefused { field }` | unchanged | "This message couldn't be sent securely." Never retried, never downgraded to plaintext; reported to Sentry as a client defect |
| Server | `FeatureDisabled { feature: "protected_channels" }` | unchanged | Owner controls hidden; growth actions: "Protected channels are unavailable right now." |
| Native | `UnknownEpoch` (`epoch < oldest_held`) | message marker (gray) | "Sent before this device joined." |
| Native | `UnknownEpoch` (`epoch > current`) | `resecuring` | catch up commits, retry once; if still unknown, red marker "Couldn't decrypt this message." |
| Native | `UnknownSender`, `BadSig` (message) | message marker (red) | "Couldn't verify the sender. This message may be forged." |
| Native | `BadSig` (seat list), `SeatListRollback`, `SeatListEquivocation`, `SeatListInvalid` | `unverified` | "This channel's member list failed verification." |
| Native | `NotSeated` | `not_seated` | as above |
| Native | `RosterMismatch` from `_encrypt` | `resecuring`, then `unverified` (9.1 step 6) | "Re-securing this channel..." then "Someone in this channel isn't on the owner's member list." The bridge commits the Remove |
| Native | `RosterMismatch` / `MlsLeafRejected` / `TextGroupFull` / `NotOwner` from processing a commit (3.12.3 step 6) | `unverified` (9.1 step 3) until the successor group is joined | "A member made an invalid change to this channel. Re-securing with a new group..." The group takes the successor path (W0-fix3), not a per-device rejoin |
| Native | off-list leaf in a Welcome (verdict `roster_mismatch`, not an error) | `resecuring` for 60 s, then `unverified` (9.1 step 6) | "Re-securing this channel..." The pending Remove clears it (W0-fix3) |
| Native | `OwnerChanged { same_user: true }` | `unverified` + native blocking dialog with Confirm/Cancel (4.7) | "The owner of this channel is now signing from a different device." plus that device's verification state |
| Native | `OwnerChanged { same_user: false }` | `unverified`, final in S1; informational native dialog with NO confirm button (4.7) | "This channel's member list is now signed by a different person. This is not allowed and the channel has been locked." |
| Native | `SignerLeafMissing` (W0-fix4) | `resecuring`; after the join-retry budget (3 retries) is exhausted, `unverified` | "Re-securing this channel..." The joiner discards the Welcome and retries its join intent. No owner-change dialog |
| Native | `CommitDeclarationMismatch` (W0-fix4) | `unverified` (9.1 step 3) until the successor group is joined | "A member made an invalid change to this channel. Re-securing with a new group..." Poisoned/successor path |
| Native | `OwnCommitMismatch` (W0-fix7 mapping) | `resecuring`, NEVER `unverified` (9.1 step 6e) | "Re-securing this channel..." This device wipes its group state (`left`) and rejoins; the group itself is fine |
| Native | `AlreadyMember` (W0-fix7 mapping) | unchanged | none; the bridge cancels the duplicate join attempt (the device already holds a leaf) |
| Native | `DuplicateLeaf` (W0-fix7 mapping) | `unverified` (9.1 step 3) until the successor group is joined | "A member made an invalid change to this channel. Re-securing with a new group..." Poisoned/successor path |
| Native | `ReplayedRejoinIntent` (W0-fix7 mapping) | `unverified` (9.1 step 3) | "This channel received a replayed membership change. Re-securing with a new group..." Hostile-server signal; may differ from later joiners' view (R14) |
| Native | `UnexpectedMlsContent` (W0-fix7 mapping) | unchanged | No user-facing marker. **Envelope handling pinned:** the bridge ACKs and DROPS the envelope (it is never retried and never blocks the mailbox queue) and logs it loudly (console error plus Sentry breadcrumb with group id and envelope id, no content) |
| Native | `NotOwner` | owner UI | "Only the channel owner's device can change seats." |
| Native | `RemovedSender` | message marker (red) | "Sent by someone who was removed from this channel." |
| Native | `Replay` | message marker (red) | "Duplicate message (replayed)." |
| Native | `ChannelMismatch` | `unverified` | "This channel's security check failed." |
| Native | `UpdateRequired` | transparent | bridge commits `_update`, retries |
| Native | `TextGroupFull` | admitting member: none; joiner stays `resecuring` | "This protected channel is full." |
| Native | `MalformedTextPayload` | message marker (red) | "Unreadable message." |
| Native | `SeatListBehind` (only from `_seat_list_sign`, W0-fix2) | owner seat UI, unchanged shield | "The member list changed since you last loaded it. Reloading..." The bridge verifies the current `GET .../seats` list and lets the owner redo the change |
| Native | `BadSig` / `SeatListInvalid` / `SeatListEquivocation` from the commit-AD pre-check (3.12.3) | `unverified` (9.1 step 3) | "This channel's member list failed verification." Nothing was decrypted; the group takes the successor path |
| Native | `MlsGroupNotFound` on decrypt (the message names a group this device holds no state for) | message marker (gray) | "Sent with a key this device never had." |
| Native | `MlsGroupNotFound` on encrypt or state | `resecuring` | the bridge enters the join flow |
| Native | `MlsEpochGap` | `resecuring` | the bridge gap-refetches commits (`GET .../commits?from_epoch`) and reprocesses; never skips ahead |
| Native | `MlsPoisonedEpoch` | `resecuring` | "Re-securing this channel..." Waits for the owner's device to create the successor group (6.3); with the owner device lost it stays here (R12) |
| Native | `MlsUnsolicitedWelcome` | unchanged; red toast, logged | "Blocked an unexpected invitation to a protected channel." The Welcome is never processed |
| Native | `WrongGroupKind` | `unverified` for the channel concerned | "This channel's security check failed." Indicates a client routing defect or a hostile relay; reported to Sentry |
| Native | `Declined` | unchanged | the user cancelled a native dialog; nothing was signed or re-pinned |
| Native | **any other or unknown error type** (catch-all, fail closed) | message marker (red) for a message; `unverified` for channel-level calls | "Something went wrong verifying this channel." Never rendered as a normal message, never a silent drop |
| Client | no `encrypted` on a protected or pinned channel | message marker (red) | "Unencrypted message in a protected channel. It did not come from a member's protected app." |
| Client | `ts_skew` | message marker (informational) | "Sent time doesn't match." |
| Client | `new_devices` / forced removal | timeline marker | "{name} added a new device." / "{name} was removed by the server and can't rejoin until the owner re-seats them." |

### 9.3 Message markers

Markers render in place of the message body (`Messages.tsx`) and are never mistaken for a
normal message. Red markers are loud; gray and informational markers are not alarms. Every
string goes through lingui.

### 9.4 Never-plaintext client rules

- **SDK** (`Channel.ts`): a protected `TextChannel` send goes to `handleProtectedSend`; it
  **throws** when `client.e2ee` is null or the bridge fails; it never falls back to a plaintext
  POST.
- **Local protected pin:** the client persists "channel id seen protected" (one-way). A pinned
  channel refuses plaintext sends and attachments even if the server later strips the flag
  (shield `unverified`).
- **`Draft.ts`:** files in protected or pinned channels are refused **before any upload**.
- **Bridge:** a text-group manager separate from the call session with a multi-group sink;
  routing by `e2ee_mls_group_kind`; decrypt on live receive (`live: true`) and history fetch
  (`live: false`); inject via `#inject`.

---

## 10. Deferred to later slices

- **S2:** the commit-outcome recovery of 2.5 applied to the CALL path too (needs an
  `mlsCallSession.ts` change and an `rtc-mutations.py` run; W0-fix6); permission-loss
  reconciler; every removal path; signing delegated to admins;
  device-cap UI; owner handover/succession UX and server-ownership transfer; catch-up and
  rejoin (incl. stranded Welcomes, R5, and devices offline past retention, R9); full
  re-securing UX; push events for seat and removal changes; more than 64 successor
  generations; owner device-loss recovery and succession (R12); lifting the S1 refusal of
  server ownership transfer (7.4); Removes or forced Updates for long-idle devices (R13);
  stronger member-side detection of a suppressed unseat (R11).
- **S3:** attachments (persistent ciphertext blobs, storage allowance, large files).
- **S4:** history sharing (owner setting), the "protected from here" divider, opt-in wipe,
  protecting an existing channel, text tables in key backup.
- **S5:** Prot coin, ledger, Stripe, fuel tank, expiry stages; entitlement states `Grace`,
  `Frozen`, `Deleted` and the matching shield states.
- **S6:** in-app purchase.
- **S7:** Android and Linux/Electron parity.
- **S8:** iOS native E2EE.
- **S9:** franking (`encrypted.franking`), in-app reports, NCMEC process, termination policy.
- **S10:** animated shield, whole-server plan, raising the 100-leaf cap after measurement.
- Unscheduled: ciphertext padding (R6), mention notifications inside protected text.

---

## 11. Verification obligations carried by this contract

Each wave's tests MUST include the plan's verification list. This document adds:

- Server: the 5.3, 5.4 and 5.5 vectors through the server builders and parsers, and the 5.6
  `payload_json` accepted by the structural validator while each single-field corruption is
  refused.
- Native: every section 5 vector byte-exact, including ciphertext, both signatures and the
  5.7 commit `authenticated_data`.
- W0 fix-round obligations: server tests that a protected send with an `Idempotency-Key`
  header is refused, that a byte-identical seat-list re-PUT is a no-op, that a Text create by
  anyone but the current list signer's device is refused, that ownership transfer is refused
  while a protected channel exists, and that protect emits `ChannelUpdate`; native tests that
  `_seat_list_sign` persists nothing, and that `OwnerChanged` is never raised for a list
  whose signature fails.
- W0 fix-round-2 obligations. Server:
  - a Text commit whose AD is not byte-identical to the newest stored list is refused with
    `stale_seat_list`;
  - each single-byte corruption of the 5.7 framing prefix is `FailedValidation`, including a
    non-minimal varint;
  - Call commits are unaffected;
  - the protected-send header refusal tests the raw header (a request without the header is
    accepted even though the guard minted a key).

  Native:
  - a commit whose embedded list fails verification is refused WITHOUT calling
    `process_message` (assert the secret tree did not advance by successfully processing the
    next valid commit);
  - a newer embedded list is adopted before the Add check;
  - an older valid embedded list is not adopted and cannot re-admit a user the held list
    dropped;
  - a same-user owner change parks the commit undecrypted and processes it after confirm;
  - a different-user owner change cannot be confirmed;
  - `ProcessedMessage::aad()` equals the pre-checked bytes;
  - a `device_cap` increase triggers the growth dialog.
- W0 fix-round-3 obligations. Server (both drivers where noted):
  - **a Remove of the current list signer's (owner's) device is refused** (`FailedValidation`)
    in every case except the rejoin case: by another member, by another device of the owner
    user, while the owner is pending, and while the device is revoked (W0-fix4 wording);
  - each Remove-rule branch is accepted (own user's OTHER devices, `pending_removals` user,
    revoked identity, owner-committed off-list user, rejoin intent), and an off-list user
    removed by a non-owner who is not pending is refused;
  - an Add commit is refused with `pending_removal` while `pending_removals` is non-empty;
  - an Add exceeding `min(signed cap, entitlement cap)` is refused inside the commit
    transaction;
  - a race test in both drivers: a seat PUT interleaved with a commit carrying the old AD
    never yields an accepted commit whose AD differs from the group's `seat_list_ad_sha256`
    at win time;
  - a 4-byte AD varint is refused;
  - a list with `version > 2^53 - 1` is refused;
  - `GET .../seats` returns `as_of_epoch`;
  - the handover append rules of 4.3 step 8.

  Native:
  - a held list `v+1` plus a replayed `v` signed by an older owner key yields
    `SeatListRollback` (GET path) or "not adopted" (AD path), never `OwnerChanged`;
  - after the owner's device leaf is gone (removed in the rejoin case, before its re-add),
    commits embedding the current (equal-version) list are still accepted;
  - a commit Removing the owner's pinned device by another sender takes the poisoned path;
  - a step-6 failure takes the successor path, not a rejoin;
  - the GET path catches up to `as_of_epoch` before adopting;
  - a Welcome with an off-list leaf is accepted with verdict `roster_mismatch`;
  - the full 6.3 handover flow (K1 joins, K0 signs, K1 qualifies and signs, members
    re-pin);
  - `_seat_list_sign` accepts a chain-verified successor.
- W0 fix-round-4 obligations. Server:
  - **transaction rewrite:** the Text `insert_mls_commit` is one multi-document transaction
    (group read, checks, commit insert, field-level `update_one` filtered on
    `{_id, open, current_epoch: e-1, seat_list_ad_sha256: h}`), retried on
    `TransientTransactionError`, with no `replace_one` and no repair loop on the Text path;
  - **concurrent seat PUT vs commit race** (both drivers, many iterations): no accepted
    commit's AD hash ever differs from the group's `seat_list_ad_sha256` at its commit time;
    the seat PUT's `pending_removals` and hash writes are never lost;
  - **Call-path field preservation:** a Call commit applied to a group document carrying
    `kind`, `generation`, `pending_removals` and `seat_list_ad_sha256` leaves them
    byte-identical (no `replace_one` on either kind);
  - **rejoin-Remove case:** a Remove of the owner's signing device is accepted only with an
    outstanding signed rejoin intent from that device, and the intent is copied into the
    commit's `rejoin_intents`; with no intent, or a stale one (> 30 s), it is refused;
  - the revoked-identity case is refused when the identity re-exists at transaction time,
    and is not retried;
  - **GET snapshot:** `GET .../seats` reads the list and group in one snapshot transaction,
    so under a racing seat PUT the returned `(list.version, as_of_epoch, as_of_group_id)`
    is always a consistent pair; it returns `entitlement_device_cap`;
  - a signed `device_cap` below the entitlement cap is accepted, above it is refused, and
    `0` is refused unless the entitlement cap is `0`;
  - a handover `issued_at > 2^53 - 1` is refused;
  - the `mls_commit` envelope and the commit fetch carry `committer`, `added`, `removed` and
    `rejoin_intents`.

  Native:
  - **declared-vs-actual mismatch takes the poisoned path:** under-declared remove,
    over-declared remove, an undeclared add, a wrong committer, and a missing declaration;
    each gives `CommitDeclarationMismatch`;
  - a Remove of the owner's pinned device is accepted with a verified rejoin intent and
    refused without one or with one signed by another key;
  - a Welcome lacking the signer's leaf gives `SignerLeafMissing` (never `OwnerChanged`);
  - the 6.3 owner-device rejoin flow end to end;
  - the 6.3 handover step 6 (K1 removes K0 after `v+2`);
  - no test anywhere relies on a device removing itself.
- W0 fix-round-5 obligations:
  - **intent consumption** (server, both drivers): a Text commit deletes the join-intent rows
    of every added device and of every rule-6-consumed intent inside the commit transaction;
    an aborted transaction deletes nothing;
  - **repeated-evict prevention** (server): after K0's rejoin re-Add, a second Remove of K0
    citing the same (now deleted) intent, or any intent created before K0's
    `member_added.at`, is refused; a fresh post-re-Add intent is accepted exactly once;
  - **won-but-errored commit recovery** (bridge + native): with a fault injected after the
    transaction commits (lost response / `UnknownTransactionCommitResult`), and on a resubmit
    that returns `Lost { winning: self }`, the bridge fetches `{group}:{epoch}` and calls
    `_commit_won` (same committer, identical bytes), never `_commit_lost`; with a different
    stored committer it calls `_commit_lost`;
  - **non-Add/Remove proposal refusal** (native): a Text commit carrying `Update` by
    reference, `PreSharedKey`, `ReInit`, `ExternalInit`, `GroupContextExtensions`,
    `SelfRemove` or `Custom` is `CommitDeclarationMismatch` (poisoned path); a path-only
    self-Update is accepted; a `SelfRemove` hidden from `remove_proposals()` is still caught
    by the leaf-set difference;
  - **wire-shape parity for `rejoin_intents`**: the v0 `MlsRejoinIntentInfo` serialization on
    the envelope and on `MlsCommitInfo` deserializes into native `wire::MlsJoinRequest`
    (all six fields, `channel_id` filled from the group), and a `channel_id` / `group_id`
    differing from the commit's own is refused;
  - `e2ee_text_remove` stages a Remove of the owner's pinned device only with a verified
    `rejoin_intent` for that exact device and group, refuses targeting itself, and accepts
    the own-user case;
  - the Mongo Call repair loop never touches a Text group;
  - the join-intent route checks the enforced (min) cap;
  - the all-members-wiped case leads to an owner-created successor.
- W0 fix-round-6 obligations:
  - **a non-owner member removes a still-listed pending user** (both drivers + native): a
    kicked user still on the signed list, in `pending_removals`, is removed by a NON-owner
    member's commit; the DS accepts it (rule 3), native `_remove` stages it (4a), every
    receiver merges it, and sends resume once `pending_removals` clears. The same commit
    from a non-owner for an off-list user who is NOT pending is refused (rule 5 / 4b);
  - **repeated-evict prevention runs on BOTH drivers** (the round-5 test, now explicitly
    Mongo and Reference); a current member with no `member_added` entry is refused under
    rule 6; a same-commit remove + re-add of one device is REFUSED (W0-fix8 correction of the
    round-6 "drop-then-add" obligation; see the round-7 N4 obligation and the round-8
    adversarial test);
  - **commit outcome recovery:** "absent" leads to a resubmit of identical bytes (idempotent)
    until definitive; an own commit with different bytes, and a refetched own commit
    raising `CannotDecryptOwnMessage` with bytes NOT equal to the persisted stage, both lead
    to wipe-and-rejoin, never poisoned (equal bytes merge as won, W0-fix7);
    `e2ee_text_pending_commit` survives a native restart; `_commit_won` refuses
    mismatching bytes;
  - **roster uniqueness:** a Welcome or a staged epoch with two leaves for one
    `(user, device)` gives `DuplicateLeaf`; the multiset difference catches a duplicated
    add that a set difference would hide; a user with two DIFFERENT devices is accepted
    (no Call `verify_roster` per-user rule on Text);
  - **replayed rejoin intent:** a commit citing an already-consumed intent signature gives
    `ReplayedRejoinIntent`;
  - **non-commit content:** a standalone proposal or an application message on the Text
    commit path gives `UnexpectedMlsContent`, and nothing is stored;
  - **eviction-loop guard:** `_join` refuses with `AlreadyMember` while active, and the
    bridge cancels join retries when a Welcome is processed;
  - frontend step 6d: `welcomeRetriesExhausted` leads to `unverified`.
- W0 fix-round-7 obligations:
  - **existing-row check before validity** (route AND both drivers): a resubmit of a commit
    that already won returns `Lost { winning: self }` even when the committer has since been
    removed from the group (still seated with ViewChannel), the seat list has advanced (AD
    now stale), `pending_removals` is non-empty, or the flag is off, i.e. even when every
    later validity check would refuse it;
  - **(W0-fix8) access checks before the existing-row check:** a bot, an unbound session, or
    a caller without seat plus ViewChannel gets its access refusal and NEVER a
    `Lost { winning }` body, even for an existing `{group}:{epoch}`;
  - the bridge re-fetches once after a definitive refusal and classifies a now-present own
    row as won; a 404 on resubmit leads to wipe-and-rejoin;
  - **N2:** `_seat_list_sign` refuses (`SignerLeafMissing`) when this device's group is not
    `active` (genesis exempt); the server refuses a seat PUT whose signer device is not in
    the open Text group's `members` (genesis exempt); wipe-and-rejoin keeps the
    channel-scoped tables (seat list, owner pin, forced removals, seen ids, consumed
    rejoin intents) and still verifies the next commit's embedded list without a refetch;
  - **N3:** each leaf-losing path (`removed_self`, `not_member`, R9 catch-up failure,
    `OwnCommitMismatch`, 404 on resubmit) moves the group to `left`, wipes the MLS state, and
    lets `_join` proceed (no `AlreadyMember` wedge);
  - **N4:** a Text commit listing one device in both `added` and `removed`, or adding a
    current member, is refused;
  - **N5:** `GET .../text_group` returns `member_added`; replay of a consumed rejoin intent to a
    later joiner merges on the joiner and poisons older devices (documented split, loud on
    the older devices);
  - **N6:** a refetched own commit hitting `CannotDecryptOwnMessage` with bytes equal to the
    persisted stage merges as won; with different bytes it gives `OwnCommitMismatch`;
  - **N7:** an `UnexpectedMlsContent` envelope is acked and dropped (the queue keeps
    draining) and logged; `OwnCommitMismatch` never yields `unverified`.
- W0 fix-round-8 obligations:
  - **ADVERSARIAL undeclared same-commit replacement** (native, with a real OpenMLS group of
    at least 3 members). Member M claims victim X's KeyPackage and commits
    Remove(X's leaf) + Add(X's KeyPackage) with EMPTY `added`/`removed` declarations.
    - Every honest receiver refuses it with `CommitDeclarationMismatch` (poisoned path) and
      does NOT merge.
    - Run it once with X = an ordinary member and once with X = the owner's signing device.
    - FRESH-KeyPackage variant: assert it is caught independently by EACH of:
      - the credential rule;
      - the signature-key rule (W0-fix9);
      - with both proposal rules disabled in a test build, the leaf-identity diff on its own
        (the re-Add has a new HPKE encryption key).
    - **ORIGINAL-KeyPackage variant (W0-fix9):** X has not updated since joining, and M
      re-Adds X's ORIGINAL admitting KeyPackage. The re-Add refills X's index with
      byte-identical keys. Assert:
      - the leaf-identity diff alone does NOT flag it (documenting the limit);
      - the credential rule alone (signature-key rule disabled) catches it;
      - the signature-key rule alone (credential rule disabled) catches it.
    - Also cover an Add that lands on a LOWER pre-existing blank index (the leftmost free
      leaf), not X's own.
    - Assert that a legitimate path-only self-Update (the committer's encryption key changes)
      is NOT flagged as a replacement, and that a legitimate Add of a new device (signature
      key not in the tree) passes.
  - **N1 order:** a bot, an unbound session, or a caller without seat plus ViewChannel
    submitting to an existing `{group}:{epoch}` gets its access refusal and never a
    `Lost { winning }` body; the flag-off resubmit case above still returns
    `Lost { winning: self }`;
  - **byte-identical seat re-PUT** returns success before step 5b, even after the signer
    device lost its leaf;
  - **consumed set:** `_commit_won` of an own rule-6 Remove records the intent; a later
    `e2ee_text_remove` with that intent is refused (`ReplayedRejoinIntent`); a commit citing
    an intent for this device's own `(user, device)` that it did not issue since its current
    leaf is refused loudly on that device, even when it is the newest member.

**Lane ownership for the new wire fields (DECISION (W0-fix6)).** The `mls_commit` envelope
declarations (`committer`, `added`, `removed`, `rejoin_intents`; 8.1) touch the database
`E2EEEnvelope` model and the v0 `E2EEMessage` event DTO. Owners: **W2 L2i (v0 DTOs)** for
`E2EEMessage` and the new `MlsRejoinIntentInfo` / `MlsCommitInfo` fields, together with
**the owner of the e2ee model file** (`crates/core/database/src/models/e2ee/model.rs`) for
`E2EEEnvelope`. These are a single atomic cross-file change, so they form one lane per the
plan's lane rules. Native `wire::MlsEnvelope` is W3 L3b.
- Frontend: the 9.1 precedence table, step by step, in the shield-state spec (including steps
  6c and 6d).

---

## 12. DECISION (W0) index

1. Labeled newline-canonical lines for the new formats (0.3).
2. Context strings `sloga-text-group-v1`, `sloga-seat-list-v1`, `sloga-owner-handover-v1` (0.4).
3. No ciphertext padding in S1 (R6).
4. Entitlement `slot_cap` capped at 100 (2.2).
5. `channel_seats` carries explicit `channel_id` / `user_id` fields (2.3).
6. Re-seating a cooling user reuses their slot (2.3).
7. Staff = `privileged`; refused with `InvalidOperation` (2.3).
8. The owner occupies a seat (2.3).
9. Append-only handover chain on the seat-list row, max 16 (2.4, 4.3).
10. Per-user device limit passed into the driver's commit path (2.5); for Text it is checked
    inside the commit transaction (W0-fix4, see 74).
11. `franking` non-null refused in S1 (2.6).
12. Unknown fields in `encrypted` refused (2.6).
13. `Message.nonce` is the client message id: required, ULID, persisted and returned (2.6).
14. Deterministic text group id; generation capped at 63. CHANGED in the fix round, see 41
    (3.1).
15. AAD length prefix is u16 big-endian; group id as its hex ASCII (3.5). The field-length
    rule CHANGED in the fix round, see 46.
16. Signature payload as labeled text with b64 binary fields (3.7).
17. AEAD failure reported as `BadSig` (3.9).
18. Timestamp-skew marker at 10 minutes; removed-sender check via local removal time plus 5
    minutes (3.9).
19. Update cadence: per device, 7 days or 500 sent; hard ceiling 14 days or 2000 (3.11).
20. Signer ids inside the seat list body (4.1).
21. SUPERSEDED by 81 (W0-fix4). Was: signed `device_cap` equals the server's effective cap
    (4.1). Now: at most the entitlement cap.
22. Server requires version exactly +1 (4.3); a byte-identical re-PUT is the one exception,
    see 45.
23. First-sight consistency check against the server-reported owner (4.5).
24. TOFU owner pin allows green (4.5).
25. Kind-aware gates: growth vs maintenance; `e2ee_enabled` stops the text plane (7.1).
26. Flag off keeps encrypted send and receive working for existing protected channels (7.1).
27. Admin grant route path `PUT /channels/:id/protected_entitlement` (7.2).
28. Protect only channels with no messages; genesis seat list required in the protect body (7.2).
29. `seated_without_access` shown to the owner only (7.2).
30. New `GET /mls/channels/:id/text_group` route (7.2).
31. `encrypted` refused on non-protected channels (7.3).
32. Pin/unpin allowed, their system message suppressed (7.4).
33. No new websocket events in S1; polling refresh rules (7.5).
34. Error fields: `reason`, `field`, `max`; status codes (7.6).
35. Command prefix `e2ee_text_` and seven added commands (8.3).
36. Additional native error variants (8.4).
37. Native table names other than `mls_text_epoch_keys` (8.2).
38. Roster mismatch shown as re-securing for 60 s, then unverified (9.1).

Added or changed in the W0 fix round (audit FAILED; items numbered as in the fix request):

39. SUPERSEDED by 54 to 57 (W0 fix round 2). Was: the commit AD carried only a seat-list
    `(version, sha256)`, with a fetch-and-defer receiver and a `seat_list_behind` verdict.
    That was withdrawn because of the OpenMLS `SecretReuseError` on re-decrypt and the
    insider wedge. What survives: residual R11 exists, and the 1.2 "cannot hide an owner
    unseat" claim stays withdrawn.
40. DECISION (W0-fix), item 2: seat-list signature verified under the signer's slice-5 device
    pin BEFORE `OwnerChanged`; the pending signer stored with its identity key, `same_user`
    and `verified`; the dialog distinguishes same user/new device vs different user and shows
    verification state (4.4, 4.5, 4.7, 8.3, 8.4).
41. DECISION (W0-fix), item 5: only the current seat-list signer's device creates a Text group
    or successor; `generation: Option<u32>` stored on `MlsGroup`, sent on create, returned by
    the state route; joiners check exactly that generation (cap 63) (2.5, 3.1, 6.1, 6.3, 7.2,
    8.3).
42. DECISION (W0-fix), item 3: server ownership transfer refused while any protected channel
    exists, reusing `ChannelProtected` (no new variant) (6.3, 7.4, 9.2).
43. DECISION (W0-fix), item 3: owner device loss freezes seat changes and successor creation
    until S2 (R12, 6.3, 10).
44. DECISION (W0-fix), item 3: genesis allowed only when the server holds no seat list for the
    channel, not "this device has no pin" (4.5, 8.3).
45. DECISION (W0-fix), item 7: `_seat_list_sign` persists nothing; the stored version and the
    genesis self-pin advance only on verified read-back; lost-response retry re-PUTs the same
    bytes, and the server treats a byte-identical re-PUT as an idempotent no-op (4.3, 4.9,
    8.3).
46. DECISION (W0-fix), item 8: each AAD field at most 255 bytes, refused above (3.5).
47. DECISION (W0-fix), item 6: native confirmation when a signed list adds users (lists them);
    the handover signature always confirms natively, naming the target; cancel is the existing
    `Declined` (4.9, 8.3).
48. DECISION (W0-fix), item 4: protected sends omit `Idempotency-Key`; the server refuses one
    (`ProtectedFieldRefused { field: "idempotency-key" }`); a duplicate `nonce` is
    `InvalidOperation` (today's behavior), handled by refetching (3.10, 7.3, 9.2).
49. DECISION (W0-fix), item 10: protect emits `ChannelUpdate { protected: true }` (7.2).
50. DECISION (W0-fix), item 11: a privileged account cannot be seated and therefore cannot own
    a protected channel; the live leg needs a non-privileged owner. #8 (the owner occupies a
    slot) confirmed by the main session (2.3, 7.2).
51. DECISION (W0-fix), item 12: residual R13, inactive devices never Update (1.3).
52. DECISION (W0-fix), item 13: an encrypted send with `e2ee_enabled = false` is
    `FeatureDisabled { feature: "e2ee" }` (7.1, 7.3, 9.2).
53. DECISION (W0-fix), item 9: error-to-UI rows for `MlsGroupNotFound`, `MlsEpochGap`,
    `MlsPoisonedEpoch`, `MlsUnsolicitedWelcome`, `WrongGroupKind`, `Declined`,
    `SeatListBehind` and a red catch-all (9.2).

Added or changed in W0 fix round 2 (re-audit FAILED on 3.12; main-session redesign):

54. DECISION (W0-fix2), N1/N2/(a): the commit AD is SELF-PROVING. It carries the full stored
    seat list (body, raw signature) and the full handover chain, as `u16_be` fields under
    context `sloga-text-commit-ad-v1`, at most 16384 bytes (16383 since W0-fix3, see 71).
    The worst case is 10291 bytes,
    15.7% of the 64 KiB commit cap. The signer ids are not separate fields because they are
    inside the signed body. Native calls `set_aad` immediately before every commit (3.12.1,
    5.7).
55. DECISION (W0-fix2), (b): the delivery service accepts a Text commit only if its AD is
    byte-identical to the `commit_ad` of its newest stored list, else
    `ProtectedChannelResecuring { reason: "stale_seat_list" }` (existing variant, new reason).
    W2 parses the pinned MLSMessage/PrivateMessage framing prefix (RFC 9420 varints, minimal),
    and a malformed prefix is `FailedValidation` (3.12.2, 6.1, 7.6, 9.2).
56. DECISION (W0-fix2), (c)/N4: receivers read `PrivateMessageIn::aad()`, parse it, and verify
    the embedded list under the owner pin BEFORE decrypting. A newer list is adopted, then
    processing continues. A verification failure means nothing is decrypted and the group is
    poisoned, loud. After processing, `ProcessedMessage::aad()` must equal the pre-checked
    bytes. The Add checks run AFTER adoption, against the newest held list (3.12.3, 4.4, 6.2).
    The `mls_text_seat_list_named` table, the `seat_list_behind` verdict and shield step 6b
    are removed. `SeatListBehind` survives only for `_seat_list_sign` (4.9, 8.2 to 8.4,
    9.1, 9.2).
57. DECISION (W0-fix2), deviation from the request's "version >= held": a verified embedded
    list with `version < held` is NOT an error. It is not adopted, and processing continues.
    It arises legitimately when a device reads a newer list via `GET` before processing a
    commit sequenced earlier; rejecting it would poison the group on a routine race. Safety
    comes from the Add check, which uses the newest held list, so an old list can never
    re-admit anyone (3.12.3 steps 3 and 6).
58. DECISION (W0-fix2), (d): R11 rewritten. A hostile server can suppress an unseat only by
    refusing every owner commit AND keeping every other member on the old list; the owner
    detects it. This is narrower than before but not "the whole group stalls" (see R11 for
    why). New residual R14: a hostile server can always deny service (1.2, 1.3).
59. DECISION (W0-fix2), N5: any `device_cap` increase, including to `0`, gets the native growth
    dialog (4.9, 8.3).
60. DECISION (W0-fix2), N6: a different-user owner change is refused outright in S1, with no
    confirm button. That covers a cross-user handover link and a first-sight signer who is
    not the server owner. Same user, new device stays confirmable (4.5, 4.6, 4.7, 8.3, 8.4,
    9.2).
61. DECISION (W0-fix2), N7: the protected-send header refusal tests the RAW header, because
    `IdempotencyKey::from_request` mints a key when the header is absent. A 9.2 row was added
    for the guard's `DuplicateNonce` (409) (7.3, 9.2).
62. DECISION (W0-fix2), clash: the `e2ee_enabled` send check runs after authentication and
    the existing permission checks, and before any body processing; 7.1 and 7.3 now state
    the same order. WORDING CHANGED in W0-fix3, see 72.

Added or changed in W0 fix round 3 (re-audit #3 FAILED: 1 BLOCKER, 2 HIGH). Numbering follows
the fix request. #54 is amended by 71 (cap 16383) and #55 by 65 (in-CAS); #57 still holds, but
with an honest server the "older embedded list" case can no longer occur (65, 66).

63. DECISION (W0-fix3), item 1(a) [BLOCKER]: the signer-leaf check runs ONLY when adopting a
    list NEWER than the held one; never for an equal or older list (4.4 step 5, 3.12.3
    step 3, 4.8).
64. DECISION (W0-fix3), item 1(b) (main-session decision): the DS accepts a Text commit's
    Removes only for the committer's own user's devices, `pending_removals` users, revoked
    identities, or (owner device only) users absent from the newest signed list, else
    `FailedValidation`. Receivers refuse a Remove of the owner's pinned signing device by any
    other sender (poisoned path, `NotOwner`). Bridges never stage it. R12 and R14 updated
    (1.3, 3.12.2, 3.12.3 step 6, 6.1, 6.2, 6.3, 8.3, 8.4, 9.1, 9.2).
65. DECISION (W0-fix3), item 2(c): the AD byte-compare is INSIDE the commit compare-and-set in
    both drivers. A new `MlsGroup.seat_list_ad_sha256` is updated atomically with every
    seat-list row change, and the winning condition includes it (2.5, 3.12.2, 6.1).
66. DECISION (W0-fix3), item 2(a): catch-up-first. `GET .../seats` returns `as_of_epoch`
    (read after the list), and a device with group state processes commits up to it before
    adopting a `GET` list (4.4 step 0, 6.3, 7.2). Amended by #80 (single snapshot read with
    `as_of_group_id`; no "read after" ordering).
67. DECISION (W0-fix3), item 2(b): the DS enforces device cap = `min(signed-list cap,
    entitlement cap)`, with 0 meaning unlimited in either (2.5, 6.1, 7.2).
68. DECISION (W0-fix3), item 2(d)(e): a 3.12.3 step-6 failure takes the poisoned/successor
    path, not a per-device rejoin. R14 restated: a malicious seated member can force a
    successor group as in calls, which is a liveness cost while the owner device is available
    and a freeze under R12 (1.3, 3.12.3, 6.2, 8.4, 9.1, 9.2).
69. DECISION (W0-fix3), item 3 [HIGH]: anti-rollback FIRST. A list at or below the held
    version never raises `OwnerChanged`; an embedded older list skips signer acceptance
    entirely. The pin moves only forward, along the stored chain or by a same-user confirm on
    a NEWER list (3.12.3 step 3, 4.4 steps 2 to 4, 4.6, 4.8).
70. DECISION (W0-fix3), item 4: the handover flow (K1 joins as an owner-user device, K0 signs
    and publishes the handover with its next list, K1 qualifies by chain and signs the
    following list, members re-pin). The 4.3 step 8 server rule is rewritten (the `from`
    device publishes), and `_seat_list_sign` accepts "pinned key OR chain-verified successor"
    (4.3, 4.6, 6.3, 8.3).
71. DECISION (W0-fix3), item 6: `version` and `issued_at` bounded to `2^53 - 1` (4.1, 4.3,
    4.4, 8.3); the AD is capped at 16383 bytes so its length is always a 1- or 2-byte varint,
    and the prefix parser refuses a 4-byte varint (3.12.1, 3.12.2). Vectors unchanged (the
    832-byte 5.7 AD already uses a 2-byte varint).
72. DECISION (W0-fix3), item 7: the `e2ee_enabled` check is "the first check inside the
    handler, after request guards and JSON parsing" (7.1, 7.3).
73. DECISION (W0-fix3), item 5: the DS refuses Add commits while `pending_removals` is
    non-empty (`pending_removal`). A Welcome with an off-list leaf is accepted with verdict
    `roster_mismatch` and shield `resecuring` for 60 s, not a hostile red (3.12.3, 6.1, 6.2,
    8.4, 9.1, 9.2).

Added or changed in W0 fix round 4 (re-audit #4 FAILED: 3 HIGH). Earlier "CAS" wording for
Text commits (#10, #55, #65) now means the commit transaction of #74.

74. DECISION (W0-fix4), N1(a): the Text `insert_mls_commit` is ONE multi-document Mongo
    transaction, retried on `TransientTransactionError` (5 attempts). It reads the group,
    checks epoch / hash / Remove rule / `pending_removals` / caps / revoked identities,
    inserts the commit row, then runs a field-level `update_one` filtered on
    `{_id, open, current_epoch: e-1, seat_list_ad_sha256: h}`. There is no repair loop on the
    Text path (2.5, 3.12.2, 6.1).
75. DECISION (W0-fix4), N1(b): never `replace_one` of a clone. Effects writes are field-level
    for BOTH kinds. The Call path keeps its insert-then-apply structure and repair loop, but
    `$set`s only `current_epoch` and `members`. W1 test: Call commits preserve the new fields
    (2.5, 11).
76. DECISION (W0-fix4), N1(c)(d): protect, seat PUT, handover append and Text create each
    write the seat-list row, seats and group hash/pending fields in ONE transaction. The
    Reference lock order is `channel_seat_lists -> channel_seats -> mls_groups ->
    mls_commits` (2.5).
77. DECISION (W0-fix4), N2: a new Remove-rule case for a device with an outstanding signed
    rejoin intent (copied into `MlsCommit.rejoin_intents`). Receivers accept a Remove of the
    owner's pinned device only with a verified rejoin intent from it. Every "self-remove"
    flow and test is deleted (OpenMLS `CannotRemoveSelf`). Handover step 6 is now "K1 removes
    K0". There is a new owner-device rejoin flow (2.5, 3.12.2, 3.12.3, 6.2, 6.3, 11, R12).
78. DECISION (W0-fix4), N3: receivers compare the `StagedCommit`'s actual adds, removes and
    committer with the server-recorded `committer` / `added` / `removed`. These are carried on
    the `mls_commit` envelope (new fields) and on the commit fetch. A mismatch or missing
    declaration is `CommitDeclarationMismatch`, poisoned path. The server-side Remove rule is
    stated to be enforceable only together with this binding. The R14 overclaim is corrected
    (1.3, 3.12.2, 3.12.3, 6.2, 8.4, 9.1, 9.2).
79. DECISION (W0-fix4), N4: the DS refuses ANY Remove of the current list signer's device
    except the rejoin case, regardless of the other cases (6.1, 3.12.2, 11). The round-3
    owner-account-deletion case is deleted: `User::delete` deletes owned servers first, so it
    cascades as a server deletion (6.3).
80. DECISION (W0-fix4), N5: `GET .../seats` reads the list and the group in one snapshot
    transaction and returns `as_of_group_id` with `as_of_epoch` (7.2, 4.4).
81. DECISION (W0-fix4), N6: a signed `device_cap` may be at most the entitlement cap (0 only if
    the entitlement cap is 0); `GET` returns `entitlement_device_cap` (4.1, 4.3, 7.2).
82. DECISION (W0-fix4), N7: a Welcome lacking the signer's leaf gives a distinct
    `SignerLeafMissing` (resecuring), never `OwnerChanged` (4.4, 8.4, 9.2).
83. DECISION (W0-fix4), N8: handover `issued_at` is bounded to `2^53 - 1` (4.6).
84. DECISION (W0-fix4), N9: the revoked-identity lookup runs inside the commit transaction. If
    the identity re-exists, that case does not apply, the Remove is refused and is not
    retried (2.5).

Added or changed in W0 fix round 5 (re-audit #5 FAILED: 1 HIGH):

85. DECISION (W0-fix5), H1: `e2ee_text_remove` gains `rejoin_intent: Option<MlsJoinRequest>`.
    A Remove of the owner's pinned device is staged only with a rejoin intent for exactly
    that device and group, verified under this device's slice-5 pin. A target equal to this
    device is always refused (`CannotRemoveSelf`). The own-user case is explicit. The stale
    "unless this device IS that device" clause is deleted (8.3; consistent with 3.12.2, 6.2,
    6.3).
86. DECISION (W0-fix5), M1: the Text commit transaction consumes the join-intent rows of
    every added device and of every rule-6-consumed intent. New `MlsGroup.member_added`
    (per-device last-Add epoch and time). Rule 6 needs an intent created after that time.
    R14 is updated (2.5, 3.12.2, 1.3).
87. SUPERSEDED by #96 and #101 (and refined by #106/#111). Was (W0-fix5, M2): commit outcome
    recovery where "otherwise `_commit_lost`" included "absent" and the recovery applied to
    both kinds. Now: "absent" resubmits identical bytes, a mismatching own commit goes to
    wipe-and-rejoin, and the scope is Text only in S1.
88. DECISION (W0-fix5), M3: the `rejoin_intents` wire element on the envelope and on
    `MlsCommitInfo` is `{group_id, channel_id, user_id, device_id, key_package_ref,
    signature}` (= native `wire::MlsJoinRequest`), with `channel_id` filled from the group.
    Native checks that `channel_id` and `group_id` match the commit (8.1).
89. DECISION (W0-fix5), M4: Text commits may carry only `Add` / `Remove` proposals, or none
    with an update path; anything else (including `SelfRemove`) is
    `CommitDeclarationMismatch`. "Actual added/removed" is the pre/post leaf-set
    difference, not the proposal iterators (3.12.3 step 6).
90. DECISION (W0-fix5), L1: the Reference lock order is extended to `... -> mls_commits ->
    mls_join_intents -> e2ee_identities`. The Mongo Call repair loop never applies effects
    to a Text group (2.5).
91. DECISION (W0-fix5), L2: #21 is marked superseded by #81.
92. DECISION (W0-fix5), L3: 4.4 step 0 is aligned with the 7.2 single-snapshot read
    (`as_of_epoch` + `as_of_group_id`).
93. DECISION (W0-fix5), L4: a new 9.1 input `signerLeafMissingRetries` and step 6c (`>= 3`
    gives `unverified`).
94. DECISION (W0-fix5), L5: the join-intent row checks the ENFORCED cap. Every member wiped
    their state: the owner device (or a chain-verified successor) creates a successor group,
    and under R12 it is a freeze (6.1, 6.3).

Added or changed in W0 fix round 6 (re-audit #6 FAILED: 1 HIGH introduced in round 5):

95. DECISION (W0-fix6), HIGH: `e2ee_text_remove` rule 4 is split. (4a) any member may remove
    any device of a user marked pending removal, whether or not they are still on the signed
    list. (4b) off-list users' devices are removable by the owner's signing device only. One
    kick no longer freezes the channel. 3.12.2 rule 3 is clarified ("by ANY committer, listed
    or not"); 6.2 and 6.3 were already split (8.3, 3.12.2).
96. DECISION (W0-fix6), M2: commit outcome recovery rewritten. "Absent" means resubmit the
    identical bytes until definitive (idempotent by `_id`). The comparison is an exact b64
    string comparison. Native persists the commit bytes with the stage
    (`mls_text_pending_commits`, `e2ee_text_pending_commit`, `stored_commit_b64` on
    `_commit_won`). An own commit with different bytes, or `CannotDecryptOwnMessage` (refined by
    #111: only when the bytes mismatch), gives
    `OwnCommitMismatch` and the wipe-and-rejoin path, not poisoned. Text only in S1; the Call
    path is an S2 follow-up (2.5, 3.12.3, 8.2, 8.3, 8.4, 10).
97. DECISION (W0-fix6), roster uniqueness: Text groups refuse any epoch with two leaves for one
    `(user, device)` (`DuplicateLeaf`, at Welcome and on every staged epoch). Actual
    added/removed are MULTISET differences (computed over leaf identity since #114, W0-fix8). The Call `verify_roster` one-leaf-per-user rule
    does not apply to Text (3.12.3 step 6, 8.4).
98. DECISION (W0-fix6) (the "drop, then add" half is superseded by #109 and unreachable): `member_added` maintenance is "drop, then add". A current member with
    no entry is never evictable under rule 6 (2.5).
99. DECISION (W0-fix6): R14 "cannot repeatedly evict" is qualified as honest-DS only. Native
    `mls_text_consumed_rejoin_intents` and `ReplayedRejoinIntent` catch a hostile DS's
    replays (1.3, 3.12.3, 8.2, 8.4).
100. DECISION (W0-fix6): the Text `_process` refuses non-commit MLS content
     (`UnexpectedMlsContent`) before storing anything; own add/remove/self_update consume the
     proposal store (3.12.3 step 1).
101. DECISION (W0-fix6): the "applies to Call commits as well" line is dropped; the Call-path
     recovery is an S2 follow-up (2.5, 10).
102. DECISION (W0-fix6): lane owners for the new envelope fields: W2 L2i (v0 DTOs) plus the e2ee
     model file owner, as one atomic lane; native `wire::MlsEnvelope` is W3 L3b (11).
103. DECISION (W0-fix6): Welcome-retry exhaustion (R5) gives `unverified`, loud (9.1 step 6d).
104. DECISION (W0-fix6): eviction-loop guard. `_join` refuses (`AlreadyMember`) while the
     device holds a leaf in the current epoch, and the bridge cancels join retries on a
     Welcome (6.3, 8.3, 8.4).
105. DECISION (W0-fix6): index #66 annotated "amended by #80".

Added or changed in W0 fix round 7 (re-audit #7 PASSED; folded before the W0 commit):

106. DECISION (W0-fix7), N1: the FIRST check on a Text commit, in the route and in the
     driver, is "row exists at `{group}:{epoch}` gives `Lost { winning }`", before every
     validation. The bridge re-fetches once after a definitive refusal; a 404 on resubmit
     leads to wipe-and-rejoin (2.5 step 0 and recovery, 6.1). Amended by #115 (the check
     runs AFTER the access checks and before every VALIDITY check, not before everything).
107. DECISION (W0-fix7), N2: `_seat_list_sign` requires an `active` group with a leaf, and the
     server refuses a seat PUT whose signer device is not a member of the open Text group
     (genesis exempt both sides). Wipe-and-rejoin keeps the channel-scoped tables (2.5, 4.3
     step 5b, 8.3).
108. DECISION (W0-fix7), N3: "holds a leaf" = operational OpenMLS group AND own leaf present
     (= `active`). New native state `left`: every leaf-losing path moves there and wipes the
     MLS state before `_join`; `AlreadyMember` only in `active` (2.5, 8.2, 8.3, 8.4).
109. DECISION (W0-fix7), N4: no same-commit Remove + re-Add of one device in S1; the
     "drop, then add" clause is unreachable; the 6.1 Add row requires "not already a
     member, not also removed" (2.5, 6.1). Supersedes the "drop, then add" half of #98.
110. DECISION (W0-fix7), N5: `ReplayedRejoinIntent` is per-device history, so a replay can
     split verdicts (older devices poisoned and loud, later joiners merged). It is
     hostile-DS-only. `GET .../text_group` exposes `member_added` (1.3 R14, 3.12.3, 7.2).
111. DECISION (W0-fix7), N6: on `CannotDecryptOwnMessage`, compare with the persisted stage
     first; equal means merge, mismatch means `OwnCommitMismatch` (2.5).
112. DECISION (W0-fix7), N7: 9.1 step 6e and 9.2 rows for `OwnCommitMismatch` (`resecuring`,
     never `unverified`), `AlreadyMember`, `DuplicateLeaf`, `ReplayedRejoinIntent`,
     `UnexpectedMlsContent`; an `UnexpectedMlsContent` envelope is acked and dropped, loudly
     logged.
113. DECISION (W0-fix7), N8: #87 marked superseded by #96/#101.

Added or changed in W0 fix round 8 (targeted re-check: N1 to N8 confirmed except N4 partial;
1 new HIGH):

114. DECISION (W0-fix8), HIGH: receivers refuse any Text commit in which an Add credential
     equals a Remove target's credential. Actual adds and removes are computed over LEAF
     IDENTITY: `(leaf_index, signature key, encryption key)`, or for the committer's own leaf
     `(leaf_index, signature key)`. A leaf replaced by a FRESH KeyPackage counts as remove
     plus add; a re-Add of the ORIGINAL KeyPackage is not visible to the identity diff and is
     caught only by the proposal-level rules (corrected by #119). The encryption key is
     included because an Add fills the leftmost blank (`free_leaf_index`), possibly the
     removed leaf's own index, with the same constant signature key. The stale round-6
     sentence is deleted; R14 and the "UNREACHABLE" note now hold at the receiver (1.3, 2.5,
     3.12.3 step 6, 11).
115. DECISION (W0-fix8): the existing-row check runs AFTER the access checks (bot,
     `assert_bound_session`, seated plus ViewChannel) and BEFORE every validity check
     (2.5 step 0, 6.1, 11).
116. DECISION (W0-fix8): the section-11 "drop-then-add leaves exactly one entry" obligation is
     replaced by "refused", with cross-references to the N4 and adversarial tests (11).
117. DECISION (W0-fix8): the consumed rejoin-intent set is also filled by `_commit_won`;
     `e2ee_text_remove` refuses an already-consumed intent; a device refuses (loud) a commit
     citing an own-device intent. That last check was originally wall-clock based; it is
     REPLACED by the clock-free rule of #121 ("refuse any own-device intent while
     `active`"), and `own_leaf_since_at` is dropped (3.12.3 step 6, 8.2, 8.3).
118. DECISION (W0-fix8): a byte-identical seat re-PUT returns the stored success at 4.3 step
     4, before steps 5 to 8 (including 5b) (4.3).

Added or changed in W0 fix round 9 (final W0 fold-in; targeted re-check PASSED):

119. DECISION (W0-fix9): the leaf-identity diff does NOT catch re-use of a never-updated
     victim's ORIGINAL KeyPackage (byte-identical leaf at its own index). The proposal-level
     credential rule is REQUIRED, and implementers must not drop it. A second required rule:
     refuse any Add whose leaf signature key equals the signature key of any pre-commit
     leaf. "Refills the SAME leaf index" is corrected to "fills the leftmost blank
     (`free_leaf_index`), possibly a lower index" (3.12.3 step 6).
120. DECISION (W0-fix9): the 11 adversarial test adds the original-KeyPackage variant, with
     the credential rule and the signature-key rule each shown to catch it alone, and a
     lower-blank-index Add (11).
121. DECISION (W0-fix9): the clock-free own-intent rule. A device refuses (loud,
     `ReplayedRejoinIntent`) any commit citing a rejoin intent for its own `(user, device)`
     while its group is `active`. It replaces the W0-fix8 wall-clock check, and
     `own_leaf_since_at` is dropped (3.12.3 step 6, 8.2; #117 amended).
122. DECISION (W0-fix9): one field name, `created_at`, for the native intent row's local time
     of issue (8.2; the 3.12.3 text no longer references a separate `issued_at` for intents).
123. DECISION (W0-fix9): #106 annotated "amended by #115".

---

## 13. How the vectors in section 5 were checked

The values were generated by one script and then recomputed by a second, independent
implementation that parses this document (the `tv:inputs` block and every `tv:*` block) and
rebuilds each value from the prose rules above: canonical builders, SHA-256, the AAD layout,
HChaCha20 + ChaCha20-Poly1305 (itself first validated against draft-irtf-cfrg-xchacha-03
sections 2.2.1 and A.3.1), and Ed25519 sign and verify. The checker was shown to fail on a copy
of this document with a single altered byte before it was run on the real file. W1 and W3
must reproduce the vectors in Rust; they are the parity test, not this checker.
