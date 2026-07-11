# Slice 6.1 — Server MLS Delivery Service + KeyPackage directory: implementation breakdown

Approved breakdown for sub-slice 6.1 of [e2ee-media-mls-plan.md](e2ee-media-mls-plan.md)
(plan §8 row 6.1). Written 2026-07-10 so a follow-on session can resume from this file.
Gate at the end: **media-e2ee-reviewer + e2ee-crypto-reviewer** (lenses: DS arbitration,
accepted-metadata set §5.6).

## Steps

1. **Feature flag + `/mls` scaffold.** `Features.media_e2ee_enabled` (`#[serde(default)]`,
   false in `Revolt.toml`, true under test) next to `e2ee_enabled`
   (`crates/core/config/src/lib.rs:471`). New `crates/delta/src/routes/mls/mod.rs` with
   `require_media_e2ee_enabled()` (also requires `e2ee_enabled`), constants
   (`MAX_KEY_PACKAGES=100`, commit cap 64 KiB, Welcome cap 256 KiB **raw** with explicit
   encoded-vs-raw accounting, `MAX_E2EE_CALL_MEMBERS=100`), mounted in `routes/mod.rs`.

2. **`can_publish_data` regrant fix (plan §0.4).** `voice/mod.rs:537`: permission sync must
   preserve `can_publish_data: false` (currently re-grants `can_speak` on every sync). With test.

3. **Device-qualified LiveKit identities (plan Q4, decided for 6.1).** Ripple map (bigger than
   the plan's "small server change" — `update_participant`/`remove_participant` address by
   identity):
   - Token mint (`voice_client.rs:82`): `DataJoinCall` gains optional `device_id`; validated as
     a registered E2EE device of the session user with `assert_bound_session`; identity becomes
     `{user_id}:{device_id}` when present, else plain `user_id` (web/non-E2EE unchanged).
   - voice-ingress (`api.rs:54`): `user_id = identity.split(':').next()` (ULIDs contain no `:`).
   - New Redis key `voice_identity:{channel}:{user}` = full participant identity, written by
     voice-ingress on `participant_joined`, cleared on leave. `update_permissions` /
     `remove_user` resolve through it, falling back to `user.id`. Deliberately NOT a
     voice-state field — device ids must not broadcast to channel co-members.
   - Server-initiated move (`member_edit.rs:251`) reuses the stored identity's device suffix
     when minting the move token.

4. **DB models `crates/core/database/src/models/mls/`, BOTH drivers.**
   - `MlsKeyPackage` (`_id = user:device:ref`, opaque bytes, `last_resort: bool`, `expires_at`:
     7d last-resort / 30d one-time).
   - `MlsGroup` (`_id = group_id`, `channel_id`, creator `(user,device)`, `current_epoch`,
     `closed_at`, `superseded_by`, committer-asserted `(user,device)` roster mirror — for
     fan-out, one-device rule, envelope eligibility; availability-trust only per T-19).
   - `MlsCommit` (`_id = {group_id}:{epoch}`, opaque ciphertext, server-stamped committer, size,
     created_at).
   - `AbstractMls` trait + mongodb/reference ops, ReferenceDb fields, indexes in
     `admin_migrations/.../init.rs` + numbered migration **rev 55** in `scripts.rs`.
   - Concurrency primitives: **partial unique index `channel_id WHERE closed_at IS NULL`**
     (create arbitration §1.2; 409 body carries open group_id; `supersedes` closes+creates
     atomically §1.4); **unique-insert CAS on `{group_id}:{epoch}`** (409 body carries winning
     commit); **one-device-per-user check inside commit CAS + at join_intent** (§1.5).

5. **Envelope extension (plan §2.2.4).** `E2EEEnvelope` + `E2EEMessage` event model gain
   `content_type` (`olm` default / `mls_commit` / `mls_welcome`), `group_id`, `epoch` — the
   existing bonfire drain/ack path then carries MLS envelopes unchanged. Per-content_type size
   caps (olm stays 64 KiB). **Queue-budget re-derivation:** keep depth 512, add per-device
   queue BYTE budget 32 MiB (= existing implicit worst case 512×64 KiB) enforced on the MLS
   fan-out path; derivation documented in code. Verify bonfire live-push frame handles
   ~341 KiB frames (tungstenite limits).

6. **Routes (plan §2.3), `crates/delta/src/routes/mls/`.**
   - `PUT /mls/key_packages` — MFA ticket on first publish, device-bound session on republish,
     binding-signature verification, dedupe-by-ref, cap accounting, returns remaining count.
   - `POST /mls/key_packages/claim` — atomic consume, last-resort at exhaustion flagged
     `reused`, rate limit per (claimer, target) pair; body carries `group_id` for the
     co-presence eligibility class.
   - `POST /mls/groups` — channel-access + in-call check; channel-scoped arbitration; accepts
     `supersedes` (poisoned-epoch successor §1.4).
   - `POST /mls/groups/<id>/join_intent` — server-side signature verification
     (defense-in-depth; clients re-verify), one-device refusal, `MlsJoinRequested` fan-out.
   - `POST /mls/groups/<id>/commits` — CAS insert, one-device rule in the CAS tx, epoch bump,
     queue-first-then-live-push commit fan-out to roster devices + welcome to added devices;
     epoch monotonicity bound (cannot submit N+5).
   - `GET /mls/groups/<id>/commits?from_epoch=` — gap refetch.
   - **New eligibility class:** claim + MLS-envelope delivery admit **call co-presence** (both
     parties can access the `channel_id` of an open group), falling back to text-E2EE gates;
     blocked-pair semantics mirror slice-5 deliver-vs-fetch asymmetry.
   - **Canonical-payload mirrors (6.1∥6.2 parity contract, plan §1.3)** centralized in the
     model layer: `CONTEXT_MLS_CREDENTIAL` (`acutest:e2ee:mls-credential:v1`), join-intent
     payload (`acutest:e2ee:mls-join:v1`, group_id + KeyPackage ref), KeyPackage publish
     payload binding ref + hash of opaque bytes to the identity key. Native must sign these
     byte-for-byte in 6.2 — flag parity at the gate.

7. **Bonfire events.** `MlsJoinRequested`, `MlsCommit`, `MlsWelcome` on `{user_id}!` private
   topic, envelope-ULID dedup like `E2EEMessage`. No new topic machinery (plan §2.4).

8. **crond sweeps (plan §2.5).** `prune_mls_groups.rs` (closed >24h, or created >7d),
   `prune_mls_key_packages.rs` (hourly `expires_at`); voice-ingress `room_finished` sets
   `closed_at` on the channel's open group. Existing envelope TTL covers MLS envelopes.

9. **Tests (plan §2.6), both drivers.** Commit-race one-winner; epoch monotonicity; claim
   atomicity; last-resort at exhaustion; cap accounting; stranger-co-member + blocked-pair
   eligibility; simultaneous-create ⇒ one open group + 409 carries group_id; per-content_type
   caps; one-device CAS refusal; `supersedes` atomicity; flag-off ⇒ 4xx; join-intent signature
   rejection; fan-out set correctness; sweeps; regrant fix; byte-budget cap. Mongo runs in WSL
   (Windows-native cargo breaks `database_test!`).

10. **Gate.** media-e2ee-reviewer + e2ee-crypto-reviewer on the full diff.

## Judgment calls to surface at the gate

- The Redis identity-resolution mechanism (step 3) — the plan did not anticipate
  `update_participant` addressing participants by identity. Implemented as a per-channel Redis
  hash (`voice_identity:{channel}`) maintained by voice-ingress; resolution centralized inside
  `VoiceClient::update_permissions`/`remove_user` so no kick/ban/move call site changed.
- The 32 MiB per-device queue BYTE budget (step 5) — derivation: 512 × 64 KiB = the
  pre-slice-6 implicit worst case; enforced only on the MLS fan-out path (client submission
  stays olm-only). Accounted in ENCODED bytes via `$strLenBytes` / string length.
- KeyPackage publish binding signature covers the plan's §1.3 credential payload EXACTLY
  (context/user/device/mls-sig-key/identity-key) — a considered-and-rejected alternative was
  also hashing the opaque bytes into the payload; rejected for plan fidelity (self-DoS only,
  clients verify the real credential at Welcome time).
- Commit fan-out recipient set: pre-commit roster minus the committer's device (added devices
  get the Welcome instead; removed devices still get the commit that removes them — MLS lets a
  removed member process its own Remove).
- Added-device eligibility on commits is REJECT (not skip): closes the welcome-spam/queue-fill
  vector a committer-asserted `added` list would otherwise open.
- MFA is required on FIRST MLS KeyPackage publish per device (mirrors publish_keys); a device
  offline long enough for all packages to expire re-enrolls through MFA — deliberate.
- Join-intent rate limit: minimum 5 s between intents per (group,user,device), enforced via
  the stored intent's timestamp; claim rate limit: 5/min per (claimer, target device) via a
  new `RatelimitEventType::MlsKeyPackageClaim`.
- Mongo has no multi-doc transactions here (standalone deploy): commit effects (epoch bump +
  roster delta) are an epoch-CAS'd separate update with winner-side apply + loser-side/reader
  lazy repair (`fetch_mls_group_repaired`). The Reference driver is atomic under its Mutex.
- `mls_groups.open: bool` mirrors `closed_at == None` because Mongo partial unique indexes
  cannot express `$exists: false`.

## Known limitations / owed

- The stranger-with-no-shared-channel claim refusal test asserts on MONGODB only: the
  REFERENCE driver's `fetch_mutual_server_ids` is `todo!()` (pre-existing driver gap that the
  eligibility fallback reaches for true strangers).
- `flag_off_rejects_every_route` mutates global config (once-per-process `overwrite_config`,
  the create_account.rs convention) — fine under nextest; under plain `cargo test` run it
  filtered alone.
- The group-create "is in the call" check is enforced only when LiveKit nodes are configured
  (voice presence lives in Redis and is written by voice-ingress); tests seed the voice state.
- Bonfire live-push frame path verified by inspection: tungstenite defaults (64 MiB message /
  16 MiB frame, inbound-only) far exceed the ~341 KiB encoded Welcome; no config change.
- The regrant-fix invariant test lives behind the `voice` cargo feature
  (`cargo test -p revolt-database --features voice regrants`) because the voice module is
  feature-gated out of the default database test build.
- Mongo BSON encoding trap (found via failing Mongo sweeps): typed collection writes serialize
  `Timestamp` as Int64 unix-ms, while `bson::to_bson`/`to_document` emit ISO strings — a `$lt`
  across BSON types silently matches nothing. All hand-built MLS timestamps now use an
  Int64 `timestamp_bson` helper and the KeyPackage upsert uses the typed replace path. The
  same latent mix exists in e2ee code (`last_seen_at`) but is never range-queried there.

## Status

- [x] 1 flag + scaffold (`media_e2ee_enabled`, `/mls` mounted)
- [x] 2 regrant fix (voice/mod.rs permission sync keeps `can_publish_data: false`)
- [x] 3 device-qualified identities (token, ingress parse, Redis mapping, move suffix)
- [x] 4 models both drivers (+ indexes, migration rev 55, LATEST_REVISION 56)
- [x] 5 envelope extension (content_type/group_id/epoch, caps, byte budget op)
- [x] 6 routes (publish/claim/create/join_intent/commits/gap-fetch, 409 arbitration bodies)
- [x] 7 bonfire events (MlsJoinRequested/MlsCommit/MlsWelcome)
- [x] 8 crond sweeps + room_finished closes the open group
- [x] 9 tests: 8 driver-level + 8 route-level; REFERENCE green on Windows; MONGODB run in WSL
- [x] 10 gate (media-e2ee-reviewer + e2ee-crypto-reviewer) — both **SHIP WITH FIXES**

## Gate outcome (2026-07-10)

Both reviewers verdict **SHIP WITH FIXES**, no CRITICAL/HIGH. Arbitration totality, consume
atomicity, epoch monotonicity, web-token refusal, device-identity injectivity, and the §5.6
metadata boundary all confirmed clean by both.

**Folded before landing:**
- **[crypto MEDIUM]** `mls_signature_key` now validated as exactly 32-byte unpadded base64
  before interpolation into the canonical binding payload (closes the newline-injection /
  wrong-length parity gap; `key_packages_publish.rs`). Test keys updated to real 32-byte values.
- **[media MEDIUM, finding 1]** `GET /mls/groups/<id>/commits` now requires GROUP MEMBERSHIP,
  not just channel ViewChannel — a channel viewer could otherwise read the per-device
  join/leave history the plan keeps off co-members (§3.5). Non-member → NotFound. Route test
  asserts a removed member is refused.
- **[media MEDIUM, finding 3]** Device-identity coverage added: `user_id_from_participant_identity`
  parse unit test + a `voice_participant_identity_mapping_round_trips` test (set-on-join /
  clear-on-leave / DEL-on-room_finished / bare fallback).
- **[crypto LOW, finding 5]** Reference driver's `fetch_mutual_user_ids`/`_channel_ids`/`_server_ids`
  were `todo!()` panics reachable via the claim eligibility fallback — now implemented (mirror
  the Mongo semantics), so the stranger-claim refusal test asserts on BOTH drivers.
- **[crypto LOW, finding 4]** Expired last-resort KeyPackages are no longer served (both drivers
  now filter `expires_at > now`), closing the pre-sweep window.
- **[media MEDIUM, finding 2]** voice_identity fallback made observable (debug log) and the
  per-user keying documented as correct under the one-device-per-user rule; full SFU
  reconciliation for the Redis-eviction/missed-webhook case is 6.4 roster-reconciliation scope.

**Deferred to 6.2/6.4 (LOW, documented, non-blocking):**
- **[media finding 4]** DS does not bind an `Add` to a stored join intent — a member can force a
  Welcome + KeyPackage burn onto an eligible co-member device. Availability-only; the real
  defense is the 6.2 client rejecting an unsolicited Welcome. **Add to the 6.2 gate checklist.**
- **[media finding 5 / crypto finding 2]** claim/join/create eligibility uses ViewChannel, not
  Connect/live-call-presence — a view-only user can still burn call participants' one-time
  KeyPackages (rate-limited, last-resort backstop). Accepted per plan §2.3; tighten to Connect +
  presence if the drain surface matters (6.4).
- **[media finding 6]** commit fan-out does N sequential depth+byte queries per recipient; batch
  into one aggregation for throughput under churn (measured in 6.4 R-1/R-2).
- **[crypto finding 3]** breakdown's "device ids never reach co-members" rationale should note
  SFU-level participant-identity visibility (device_id is within the §5.6 accepted (user,device)
  set; the surfacing to *non-E2EE* co-members in a downgraded call is the overshoot).
- Spawned a separate task for the pre-existing e2ee `last_seen_at` BSON type inconsistency.
