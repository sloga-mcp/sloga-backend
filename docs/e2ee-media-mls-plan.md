# Slice 6 — Media E2EE (voice / video / screenshare) via MLS

**Status:** PLAN (approved decisions locked 2026-07-09; supersedes the Option-A/Option-B guidance in
`e2ee-implementation-plan.md` lines ~1414–1429 — see §0.2).
**Prerequisites:** text-E2EE slices 1–5 gate-complete, slice 5.5 gate-passed (both true as of 2026-07-09).
**Scope discipline:** anything not in this plan goes to *Deferred*, not into a sub-slice.

---

## 0. Overview

### 0.1 Goal

End-to-end encrypt the media plane (voice, video, screenshare) for **1:1/group DM calls and server
voice channels**, such that the LiveKit SFU and the Sloga server forward only ciphertext frames and
never possess the keys. Key agreement uses **MLS (RFC 9420) via OpenMLS** in the existing native
Rust layer (`e2ee-core`); per-sender media keys are derived from the MLS exporter each epoch and fed
to LiveKit's insertable-streams E2EE worker. The design is deliberately DAVE-shaped (Discord's
audited two-plane architecture): MLS is the **control plane only** — media is never carried inside
MLS messages.

### 0.2 Locked decisions (2026-07-09) — this section supersedes prior guidance

The existing Slice 6 sketch in `e2ee-implementation-plan.md` (PLAN:1414–1429) recommended
"Option A — pairwise-wrapped room key, ship first; Option B (MLS) later." **That recommendation is
SUPERSEDED.** Decision of record:

1. **MLS directly, no pairwise interim.** Server voice channels have many participants with heavy
   join/leave churn. Pairwise wrapping is O(n) envelopes per membership change and gives neither
   forward secrecy nor post-compromise security without extra machinery; TreeKEM is O(log n) per
   change with FS+PCS built in. Building Option A first would mean shipping, auditing, and then
   ripping out a second key-distribution protocol. The doc-stated costs of Option B carry as
   obligations of this plan: it is a second protocol with its own audit surface, and OpenMLS is
   bound over uniffi the same way vodozemac is.
2. **Two-plane split (DAVE-shaped):** MLS for group key agreement ONLY; per-sender media keys
   derived from the MLS exporter per epoch; frames encrypted client-side via the LiveKit
   KeyProvider / insertable-streams worker; the SFU forwards ciphertext unchanged.
3. **Our server becomes the MLS Delivery Service (DS):** ordered relay of MLS handshake messages
   with one winning commit per epoch, plus a KeyPackage directory mirroring the existing
   one-time-prekey machinery. The server never sees group secrets.
4. **MLS leaf credentials are bound to (signed by) the existing vodozemac Ed25519 identity keys**,
   so slice-5 safety numbers / verification extend to call rosters — one verification primitive,
   never a second MLS-only code.
5. **Non-enrolled participant joins ⇒ LOUD whole-call downgrade.** The both-sides rule generalizes
   to N parties. Fail loud, never silent-plaintext.
6. **Webview-worker key boundary caveat carries:** derived per-sender FRAME keys cross into
   LiveKit's E2EE worker — the narrowest possible exposure; the worker is inside the trust
   boundary and this doc says so explicitly (§7.2). MLS signature keys, epoch secrets, and
   exporter secrets NEVER leave the native layer.
7. **MLS group state is call-scoped and ephemeral-ish:** persisted for crash recovery within a
   call, but EXCLUDED from key backup, exactly like live Olm sessions (§5.5).
8. **Android parity is a later sub-slice within slice 6** (OpenMLS rides the same uniffi crate).
9. **Opt-in UX (user-decided 2026-07-09, after initial authoring): SEPARATE "Encrypt my calls"
   toggle** under Security & Privacy, independent of the text-E2EE toggle. Enrollment (identity
   keys, native requirement, consent screen) is SHARED infrastructure: the calls toggle requires
   E2EE enrollment and triggers the same enrollment flow if absent — there is no second key
   system. New state this creates: *text-E2EE on + calls off* → the user's calls always negotiate
   plaintext and cause a loud downgrade in otherwise-capable rosters; the downgrade indicator
   must ATTRIBUTE the cause per participant ("not encrypted — <user> has call encryption off"),
   exactly as the composer attributes mixed-pair text state. Capability advertisement (§2/§3.4)
   therefore keys off *calls-toggle + enrollment + native shell*, not text opt-in alone. The
   media consent screen carries call-specific fine print: web clients can't join encrypted calls
   at full E2EE, and server-side features needing plaintext frames (recording/transcode) are off
   in encrypted calls. Owned by sub-slice 6.5 (UX) with the settings surface in the existing
   Security & Privacy page; per-user "strict mode" (refuse downgraded calls) stays Deferred.

Any deviation from these in implementation needs explicit justification flagged as OPEN QUESTION.

**Post-audit amendments (plan-stage audit, 2026-07-09)** — the following supersede any
conflicting text elsewhere in this doc; each is folded into its home section:

- **A1 — Media-plane indicator is dual-gated.** Native cannot observe whether frames were
  actually encrypted (encryption runs in the webview/worker); "keys pushed" ≠ "encryption
  happened". The green whole-call state requires BOTH native control-plane health AND the
  observed media-plane encryption status (§4.4, new invariant 11). Text invariant 2 does NOT
  carry unmodified to the media plane, and this doc says so.
- **A2 — Q3 is resolved as work, not as a checkpoint.** Bundling the desktop frontend into the
  installer + a restrictive CSP is a **budgeted sub-slice (6.2b)** and a **hard precondition of
  6.3** (the sub-slice that lands frame-key egress). The "recorded operator acceptance" escape
  hatch is removed for the live-frame-key surface unless the user explicitly re-opens it BEFORE
  6.1 starts — never at the 6.3 checkpoint where schedule pressure biases toward acceptance.
- **A3 — Q5 overflow rule + USER-DECIDED cap values (2026-07-09).** At the cap the CALL
  remains encrypted and the overflow joiner is refused media-key admission with a loud "call
  full for E2EE" state. Overflow never prompts the call toward plaintext (that would be a
  one-account downgrade attack against invariant 3). **Cap values (user decision, superseding
  the earlier 24):** the user's intent is "unlimited voice, cap 30 once a webcam is on" — encoded
  honestly as TWO independent constants, because MLS control-plane cost (Welcome size, commit
  fan-out, KeyPackage churn) scales with ROSTER SIZE regardless of media type, so truly
  unlimited *encrypted* voice is structurally impossible:
  (a) `MAX_E2EE_CALL_MEMBERS = 100` — the Welcome envelope-budget ceiling (§2.2(4): 256 KiB raw
  fits ≈100 leaves), media-independent; 6.4's churn measurements validate at this size and may
  force it down. The 101st joiner gets the loud "call full for E2EE" refusal (call stays E2EE).
  (b) `MAX_VIDEO_PARTICIPANTS = 30` — a PRODUCT gate at the LiveKit/product layer, independent
  of MLS, two-sided: while any video/screenshare is active, joins beyond 30 are refused; while
  participants > 30, enabling video/screenshare is refused. Server-side enforcement rides the
  voice join/token path (6.1); UX surfaces in 6.5.
  Changeability (user asked): the video gate is a trivial config-constant change at any time;
  raising the E2EE cap past ~100 requires the Deferred large-channel work (Welcome budget,
  external-commit revisit, fan-out scaling) — a measured project, not a constant flip.
  **DAVE-parity note (verified 2026-07-09):** Discord's DAVE never handles groups larger than
  this either — Discord voice channels hard-cap at 99 concurrent users (group DMs at 10), and
  stage channels (the 10,000-listener surface) are explicitly EXCLUDED from DAVE E2EE as public
  broadcasts. MAX_E2EE_CALL_MEMBERS=100 is therefore Discord-parity +1; MLS itself (RFC 9420)
  scales to tens of thousands, so the ceiling is our v1 transport budget, not the protocol.
- **A4 — Room is always constructed E2EE-capable on supported shells** (§4.1): livekit-client's
  `setE2EEEnabled` throws if the `e2ee` option was omitted at construction, so re-upgrade is
  impossible otherwise.
- **A5 — Create-race arbitration is channel-scoped**, not group_id-scoped (§1.2/§1.4): racing
  creators mint different hash-derived group_ids, so unique-insert-on-group_id can never
  arbitrate. Partial unique index on `mls_groups.channel_id WHERE closed_at IS NULL`.
- **A6 — Epoch-rotation transition window** (§1.5): senders grace-period on Adds, immediate
  switch on Removes; loud-state machine latches and debounces (§4.4).

### 0.3 Goals

- E2EE media for DM calls (1:1 and group) and **server voice channels up to
  MAX_E2EE_CALL_MEMBERS = 100 in v1** (the Welcome envelope-budget ceiling; user-decided
  2026-07-09, amendment A3 / §7.1 Q5) where **all** participants are E2EE-enrolled native
  clients. A separate product gate `MAX_VIDEO_PARTICIPANTS = 30` bounds video/screenshare
  (A3(b)). Beyond-100 scale is Deferred — the MLS choice is justified by the *trajectory*
  (O(log n) churn cost), and 6.4's measurements gate the delivered ceiling.
- Epoch hygiene: a joiner cannot decrypt pre-join media; a removed/left participant cannot decrypt
  media encrypted after each sender applies the Remove commit (re-key on every membership change —
  TreeKEM gives this natively; see invariant 7 for the precise per-sender boundary).
- Per-participant encryption indicator + whole-call state chip + loud downgrade banner. The green
  state is dual-gated: **verified native control-plane state AND observed media-plane encryption
  status** (§4.4, invariant 11) — never server flags. Text invariant 2 carries for the control
  plane only; native structurally cannot attest that frames were encrypted (§7.2, amendment A1).
- Safety-number verification (slice 5) extends unchanged to call rosters via credential binding.
- Hostile-DS adversarial harness (media equivalent of `hostile_server.rs`) as part of definition
  of done, per the standing gate contract (PLAN:1475–1478).

### 0.4 Non-goals / explicitly out of scope

- **Server-side media processing that needs plaintext frames** — server-side recording, mixing,
  Go-Live-style transcoding at scale: **disabled in E2EE calls or documented plaintext-only with a
  loud refusal**, never silent (carries PLAN:1457–1462 verbatim).
- **Server-side noise suppression** — out; client-side rnnoise/Krisp-style processing is fine and
  already exists (DenoiseTrackProcessor).
- Web-client media E2EE. Web has no native layer; a web participant is a non-enrolled participant
  and triggers the loud whole-call downgrade. (Same stance as text: web-token refusal since 3.5.)
- E2EE for LiveKit data channels. Key distribution rides our DS / envelope relay, never LiveKit
  data channels — that is a design commitment, not a reliance on platform enforcement. **Audit
  correction:** the previous claim that the data plane is "already locked off" was half-false.
  The token grant does set `can_publish_data: false` (`voice_client.rs:90`), BUT
  `crates/core/database/src/voice/mod.rs:537` re-grants `can_publish_data: can_speak` on every
  permission sync, silently re-enabling data publishing for any speaker; and the voice-ingress
  kick (`api.rs:269-272`) fires on `track_published` with `TrackType::Data` — LiveKit
  `publishData()` sends data *packets*, which never publish a track, so the kick never covers
  the actual data-channel path. **Slice-6 prerequisite (lands in 6.1):** fix `voice/mod.rs:537`
  to preserve `can_publish_data: false`. **Client rule (tested):** no E2EE or call-state
  machinery may ever consume LiveKit data-channel input (`DataReceived` and friends) — the data
  channel is treated as an untrusted injection surface. Encrypting the data channel
  (`dcEncryptionEnabled` exists in 2.15.13) stays Deferred with this risk documented.
- **AMENDMENT (2026-07-28, remote-control plan §2 rev 9) — one narrow, named carve-out to the
  client no-consume rule above, plus the cardinality of the `can_publish_data` regrant.**
  The rule as written is "no E2EE or call-state machinery may ever consume LiveKit data-channel
  input". Remote control is call-state machinery doing exactly that, so it needs saying out loud
  rather than being quietly excepted:
  - **What may be consumed:** opaque **sealed bytes on topic `"rc"`**, and nothing else. The
    design commitment that MLS/DS key distribution never rides the data channel is
    **unchanged** — remote control carries no key material on this path; its key agreement runs
    over the REST/`EventV1` control routes.
  - **JS parses nothing.** The renderer may read `topic` and `participant.identity` **from the
    server-attested LiveKit event object** — that is a *filter*, not a state mutation, and
    `liveCaptions.ts:83-95` is the precedent for taking identity from the participant object
    rather than the payload — and then forwards the payload bytes to native unexamined. It may
    not read a single byte of the payload, **including the header**: not the version, not the
    direction, not `rc_session_id`. Everything a receiver reads before authenticating is covered
    by the AEAD's AAD, and reading it in JS would put an unauthenticated parser in front of the
    one that is authenticated.
  - **Unauthenticated bytes may not mutate any client state.** A packet that fails to open is
    dropped silently, with no user-visible and no metric effect — a counter a hostile SFU can
    drive is an oracle. The only permitted defence against a flood is a bounded, silent drop
    queue in native. Note the consequence, which is deliberate: because that bound is checked
    before the session lookup, a saturating flood also drops legitimate packets, producing a
    reliable-stream gap and a LOUD teardown. That is fail-closed and correct — a hostile SFU can
    drop packets anyway — and it must not be "fixed" by making gaps quiet.
  - **🔴 CARDINALITY of the regrant, stated explicitly because it is the real dependency.**
    `voice_participant_permissions` hardcodes `can_publish_data: false` and this section leans on
    that. Remote control reopens it for one identity per grant, and with one grant per sharer
    permitted (remote-control plan §0.7) that is **up to ~30 granted identities in a 30-person
    room**. `ParticipantPermission` has **no per-topic scoping**, so each of those identities may
    publish on **any** topic — including `"captions"`, which `liveCaptions.ts:83-95` ingests with
    the topic string as its only gate — and to any `destinationIdentities`. So the flood surface
    is reachable by an ordinary **co-participant holding a grant**, not only by the SFU.
  - **The compensating control is ACTIVE revocation only.** Do not describe the voice-ingress
    data kick as a backstop anywhere: it fires on `track_published` with `TrackType::Data`, and
    datagrams publish no track (already recorded above, and independently measured 2026-07-27 —
    0 of 100 packets delivered on a default token, with `publishData()` resolving cleanly). What
    bounds the surface is that a grant exists only while the sharer is heartbeating an
    **authenticated** native session, and that every teardown path either pushes
    `voice_participant_permissions` (data false) or ejects the participant.
  - **The invariant test is RE-EXPRESSED, not weakened — and it is currently weakened by
    omission.** `permission_sync_never_regrants_data_publishing` (`voice/mod.rs`) still asserts
    `voice_participant_permissions(..).can_publish_data == false` and still passes — **because
    remote control added a second function, `remote_control_participant_permissions`, that the
    test cannot see.** The property it stood for ("no participant in any room holds
    `can_publish_data`") is therefore untested today. Four tests replace the one:
    1. **Keep `permission_sync_never_regrants_data_publishing` verbatim.** Rename nothing. It
       still means "the sync path never grants".
    2. **`remote_control_permissions_flip_exactly_one_field`** — over the full cross-product of
       `can_listen` × `allowed_sources`, the RC variant must equal `voice_participant_permissions`
       field for field **except** `can_publish_data == true`. Catches the `..Default::default()`
       mute-and-deafen regression and any future field drift.
    3. **`remote_control_permissions_have_exactly_one_caller`** — a source-level assertion (the
       desktop shell's `build.rs` is the precedent for this style) that
       `remote_control_participant_permissions` has exactly one non-test caller in the workspace,
       in `control_respond`. **This is the test that actually preserves the original invariant's
       meaning:** no code path other than an accepted control grant can grant data publishing.
    4. **`remote_control_teardown_restores_the_sync_permission_set`** — every teardown path calls
       `update_permissions` with `voice_participant_permissions`, never with the RC variant.

    **Status: all four tests are in CI as of 2026-07-28** (`voice/mod.rs`, `permission_tests`).
    Test 2 subsumed slice 1's `remote_control_grant_carries_full_set_and_flips_only_data`
    (renamed to the name above, widened to the full source cross-product). Tests 3 and 4 are
    source-level scans over the workspace in the desktop `build.rs` style; each of their
    assertions was negative-tested (probe caller / probe RC push / variable-arg push /
    caller moved out of `control_respond` all fail the run). Scan discipline the scans
    impose: permission pushes pass their constructor INLINE, and test-code strings/comments
    keep braces balanced (the cfg(test) stripper matches braces textually).
- Federation/multi-node MLS DS coordination beyond what the single logical DB already provides.
- Restoring any call state from key backup (calls are ephemeral; §5.5).

---

## 1. Architecture

### 1.1 Two planes

```
CONTROL PLANE (key agreement)                      MEDIA PLANE (frames)
=============================                      ====================

 native e2ee-core (Rust)                            webview JS + E2EE worker
 ┌──────────────────────────────┐                  ┌──────────────────────────────┐
 │ OpenMLS group (per call)     │                  │ LiveKit Room                 │
 │  - leaf credential bound to  │  derived         │  MlsKeyProvider (subclass of │
 │    vodozemac Ed25519 identity│  per-sender      │  BaseKeyProvider)            │
 │  - epoch secrets, exporter   │  FRAME KEYS ────►│    onSetEncryptionKey(key,   │
 │  - commit/welcome processing │  (only these     │      participantIdentity,    │
 │  - sealed SQLite state (mls  │   cross IPC)     │      keyIndex=epoch mod 16)  │
 │    HKDF subkey, schema v5)   │                  │         │                    │
 └──────────┬───────────────────┘                  │         ▼                    │
            │ MLS handshake msgs                   │  e2ee worker (bundled,       │
            │ (opaque ciphertext                   │  self-hosted): AES-GCM frame │
            │  + epoch counter)                    │  encrypt/decrypt via         │
            ▼                                      │  RTCRtpScriptTransform /     │
 ┌──────────────────────────────┐                  │  createEncodedStreams        │
 │ Sloga server = MLS DS        │                  └──────────┬───────────────────┘
 │  - KeyPackage directory      │                             │ ciphertext frames
 │    (mirrors OTK machinery)   │                             ▼
 │  - commit arbitration:       │                  ┌──────────────────────────────┐
 │    ONE winner per epoch      │                  │ LiveKit SFU                  │
 │    (unique-index insert CAS) │                  │  forwards opaque payloads    │
 │  - per-device mailbox relay  │                  │  UNCHANGED (no server change)│
 │    (ULID-ordered, acked)     │                  └──────────────────────────────┘
 │  - sees: membership metadata │
 │    NEVER group secrets       │
 └──────────────────────────────┘
```

Rules of the split:

- Media is **never** carried in MLS messages. MLS messages are **never** carried over LiveKit.
- The DS relays opaque MLS ciphertext (commits/proposals as MLS *PrivateMessage*, Welcomes
  encrypted to the joiner's KeyPackage init key). The **only** plaintext the DS needs is a
  client-asserted `(group_id, epoch)` pair for arbitration, carried as envelope metadata beside
  the ciphertext — the server never parses MLS framing.
- MLS signature private keys, epoch secrets, exporter secrets: native layer only, forever.
  Per-sender derived frame keys: the single sanctioned egress (§7.2).

### 1.2 Group identity and call binding

- One MLS group per **call instance**: `group_id = blake2b/sha256(channel_id || call_start_ulid)`
  minted by the creator; the DS record stores `(group_id, channel_id)` so authorization can reuse
  existing channel-permission checks (can this session's user see this channel?).
- **Create-race arbitration is channel-scoped (audit CRITICAL fix, amendment A5).** A ULID is
  minted locally, so two enrolled participants joining an empty call simultaneously derive
  DIFFERENT group_ids — a unique index on `group_id` can never arbitrate that race (both inserts
  succeed → split-brain: two parallel MLS groups that loudly cannot decrypt each other, with no
  merge path; verified: LiveKit rooms are keyed by channel id only and there is no
  server-authoritative call-instance id). Arbitration: **partial unique index on
  `mls_groups.channel_id WHERE closed_at IS NULL`** (both DB drivers — Mongo partial index;
  Reference driver open-group contains-check under the single Mutex). The racing loser's insert
  gets 409 **with the existing open `group_id` in the response body** and falls into the join
  path for that group. Consequence: at most one OPEN group per channel at any time; the
  successor-group flow (§1.4 poisoned-epoch recovery, §3.4 re-upgrade) closes the old group in
  the same transaction that admits the new one. Because the winning group_id is
  server-relayed to losers, a hostile DS partitioning joiners across fabricated group_ids is
  in-scope for the harness (T-16): joiners only trust a group after Welcome-time leaf
  verification AND the §1.4 group-context check, so a partition yields loud failure, not two
  silently working half-calls.
- Ciphersuite v1: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (curve alignment with the
  existing vodozemac stack). Single-entry accepted set; anything else rejected loudly — the
  slice-5 version-floor rule (reject outside `[FLOOR, CURRENT]`, below AND above, never
  best-effort parse) applies to ciphersuite and MLS protocol version alike. First future
  ciphersuite bump inherits the two-version-matrix test obligation (DESIGN5 [G:11]).

### 1.3 Credential binding (invariant: one verification primitive)

MLS leaves need a signature keypair used constantly on MLS structures (raw bytes, not UTF-8), so
we do **not** reuse the vodozemac account key as the MLS signing key (vodozemac's `sign(&str)` API
and cross-protocol signature-confusion hygiene both argue against it). Instead:

- Each device generates a dedicated **MLS Ed25519 signature keypair**, stored sealed in the store.
- Leaf credential = BasicCredential whose identity bytes are a canonical, domain-separated
  payload: new `CONTEXT_MLS_CREDENTIAL` in `e2ee-core/src/canonical.rs` (newline-delimited
  builder, charset-constrained inputs, mirroring the `sign_claim` pattern at `lib.rs:429-457`):

  ```
  acutest:e2ee:mls-credential:v1
  {user_id}
  {device_id}
  {mls_sig_pubkey_b64}
  {identity_ed25519_pubkey_b64}
  ```

  signed by the **vodozemac identity Ed25519 key** (`ctx.account.sign`), signature embedded in the
  credential bytes. The server-side canonical mirror in
  `stoatchat/crates/core/database/src/models/e2ee/model.rs` gets the same builder so KeyPackage
  publish can be signature-verified server-side exactly like OTK publish (model.rs:602-637
  precedent). *(Open item: scout marked the server mirror file as unverified-read; confirm builder
  parity byte-for-byte during 6.2/6.1.)*
- **Acceptance rule (client-side, the real trust decision):** a leaf is valid iff (a) the MLS
  structure verifies under the leaf's MLS signature key, AND (b) the embedded binding signature
  verifies under the **locally pinned** slice-5 identity key for `(user_id, device_id)`, AND
  (c) the pin's ctl-authority condition holds: `binding_verified && !identity_changed` (the H1
  rule, PLAN:1174-1187, applied to call rosters). A leaf whose identity key is not pinned yet
  follows the same TOFU-then-pin flow as text; an identity-changed pin makes the leaf INVALID
  until the user re-confirms via the existing slice-5 flow.
- **Leaf mutation / Update-proposal rule (audit fix — previously unaddressed):** v1 DOES include
  Update commits, but only in one shape: a **self-update that rotates the leaf HPKE (encryption)
  key while keeping the MLS signature key and credential bytes identical**. This is what the
  epoch heartbeat (§1.4) issues. Every processed leaf mutation — Add, Update, Welcome-carried —
  re-runs the FULL acceptance rule (a)+(b)+(c) above against the pinned identity. A leaf
  mutation that changes the credential bytes or the MLS signature key is **INVALID in v1**
  (loud reject, group treated as hostile): rotating the MLS signature key would require a fresh
  binding signature by the vodozemac identity key and a re-verification flow, which is Deferred.
  Consequence for PCS honesty: with heartbeat self-updates, PCS holds on membership change AND
  on the heartbeat period for leaf HPKE compromise; compromise of the (never-rotated-in-call)
  MLS signature key or the vodozemac identity key is outside in-call PCS, same as text.
- **Consequence:** the slice-5 safety number (computed over pinned identity keys, DESIGN5 §3) is
  automatically the verification code for the call roster. No new code format. The verification
  screen gains a "participants in this call" entry point only (UI, 6.5).

### 1.4 Epoch lifecycle

State machine per call group (all transitions are commits; every commit = new epoch = new frame
keys for everyone):

- **Create.** First E2EE-enrolled participant to join the call creates the group (epoch 0, self
  only) and registers it with the DS (`POST /mls/groups` — **channel-scoped arbitration, §1.2**:
  partial unique index on `channel_id WHERE closed_at IS NULL`; a racing second creator gets 409
  carrying the existing open `group_id` and falls into the join path for THAT group). Both-driver
  concurrency test for the simultaneous-create race is definition-of-done (§2.6).
- **Join (Welcome-based — chosen for v1, see §1.6).**
  1. Joiner claims call membership by sending the DS a **signed join intent**: canonical payload
     (`CONTEXT_MLS_JOIN:v1`, includes group_id + a fresh KeyPackage reference) signed by the
     identity key. The DS stores it and fans out an `MlsJoinRequested` event to member devices.
  2. Admitters self-schedule with **timers staggered by leaf index** (leaf *k* waits `k·Δ`,
     Δ ≈ 2 s, before acting) — the lowest-leaf heuristic gives fast joins when that member is
     healthy, and the stagger gives **liveness failover** when it is suspended/backgrounded/
     wedged (laptop lid, mobile doze — common in long calls). Correctness never depends on the
     heuristic. The acting admitter verifies the intent signature against its pinned identity
     for that user/device, claims one of the joiner's KeyPackages from the directory (atomic
     consume), and issues Add proposal + commit + Welcome. KeyPackage consumption accounting:
     each RACING admitter consumes one claim (up to roster-size claims per contested join, NOT
     one) — the DS rate-limits claims per `(claimer, target)` pair and the stagger keeps races
     rare; replenish low-water math in R-1 uses the corrected per-race cost.
  3. DS arbitration picks one winning commit for the epoch; the Welcome of the winner is relayed
     to the joiner's device mailbox; losers rebase and retry (their consumed KeyPackage claim is
     wasted — acceptable; KeyPackages are one-time like OTKs).
  4. Joiner processes Welcome. **Before deriving any keys** it asserts
     `Welcome.GroupContext.group_id == the group_id from its own signed join intent` and that
     the DS's group record binds that group_id to the channel it intended to join — a hostile
     DS relaying a *different* group's Welcome (all leaves legitimate, so leaf verification
     alone cannot catch it) must produce a loud failure, never a silent join into the wrong
     call context (T-15). Then it verifies **every** leaf credential binding against its own
     pins (rejects the whole group on any invalid leaf — no partial trust), derives keys,
     starts decrypting.
  5. **Joiner-side retry:** if no Welcome arrives within timeout T (v1: 10 s), the joiner
     re-broadcasts the join intent, up to N (v1: 3) retries, then enters the **loud failure
     state**, never plaintext.
  - *Server can never grow the roster:* an Add is only ever issued in response to an
    identity-signed join intent verified client-side — the generalization of the slice-5
    audience-expansion rule (DESIGN5:123-130). A hostile DS injecting a phantom join gets no Add
    because no member can verify a binding signature for it.
- **Leave.** Leaver just disconnects (or crashes). Remaining members observe
  `VoiceChannelLeave`/participant_left and any member commits a Remove — **after a grace window**
  (v1: 10 s, strictly shorter than the desync threshold): transient network blips cause full
  LiveKit reconnects (`Restarting → SignalRestarted`), and an undebounced Remove races the
  member's reconnection, converting every blip into remove+rejoin churn. A member that
  reconnects to the SFU within the window re-asserts liveness (its presence cancels the pending
  Remove). Post-removal media is unreadable to the removed member per invariant 7's per-sender
  boundary. The leaver ALSO wipes its local group state.
  **Audit correction on the shrink-rule citation:** the slice-5 rule justified trusting
  server-derived signals because wrongly *shrinking* is safe. For calls, the dangerous direction
  is **failure to shrink** — exactly what a hostile operator controls (withhold the leave event
  for a colluding member and no Remove ever happens). Server leave signals are therefore only a
  *liveness optimization*; the security backstop is roster reconciliation (below) plus the
  heartbeat, and the honest statement of what invariant 7 guarantees against a hostile server
  lives in §5.6.
- **Roster reconciliation (audit fix — MLS roster vs SFU participant set were unbound).** Each
  member continuously reconciles the LiveKit participant list against the verified MLS roster,
  both directions:
  - **SFU participant absent from the MLS group** ⇒ treated as a **non-enrolled participant**:
    trips the loud whole-call downgrade machinery (§3.4). This is also the trusted-enumeration
    answer for the downgrade trigger: "every current call participant" = the UNION of the SFU
    participant set and the MLS roster; a participant that only the SFU reports still counts.
    (They receive only ciphertext they cannot decrypt — but their presence must be LOUD.)
  - **MLS leaf with no SFU participant** (and no tracks — so LiveKit-track-driven tiles would
    render nothing: a silent-eavesdropper shape) ⇒ the roster UI renders from the **MLS roster
    (the cryptographic truth)**, loudly flagging the divergence; after a divergence timeout
    (v1: 30 s, > the leave grace window) any member commits a Remove for the ghost leaf.
  T-18 covers the withheld-leave-event case.
- **Epoch heartbeat (audit fix — no time-based re-key existed).** The acting member (lowest-leaf
  online, with the same staggered failover as admission) issues an **empty self-update commit
  every 10 minutes** on a stable roster. This (a) bounds the stable-roster exposure window — a
  point-in-time worker/webview compromise no longer yields the whole call's media, only ≤ one
  heartbeat period per sender going forward; (b) exercises the desync machinery continuously;
  (c) doubles as the liveness probe for roster reconciliation. Cheap at the 24-member cap. The
  heartbeat is the §1.3 self-update shape (leaf HPKE rotation only).
- **Rejoin.** Same as join with a fresh KeyPackage — a rejoiner is a new leaf; no state reuse.
- **Desync recovery.** A member whose epoch falls behind (missed commits beyond the mailbox, crash
  with unrecoverable state, storage failure) treats itself as out: local state for the group is
  discarded and it re-enters via the join path. v1 has **no external commit** (§1.6). While
  desynced, the member's UI shows a loud "re-securing call" state; it publishes nothing (its old
  frame keys are stale) and renders nothing it cannot decrypt.
- **Poisoned-epoch recovery (audit HIGH fix — previously the group deadlocked).** The DS accepts
  commits as opaque ciphertext, so a malformed / MLS-invalid commit from any authenticated member
  can WIN epoch N: every honest member's OpenMLS rejects it, but the `{group_id}:{epoch}` slot is
  occupied, `current_epoch` is bumped, and — since invariant 10 forbids skip-ahead and admission
  requires committing on top of N — the group would be permanently bricked by one member (a
  one-member DoS cheaper than any hostile-DS attack). Recovery = **group abandonment via the
  channel-scoped successor flow (§1.2):** a member that fails to process the winning commit for
  epoch N enters desync; when its rejoin attempt discovers that admission cannot proceed (the
  group is unprocessable for admitters too), any member issues
  `POST /mls/groups` with `supersedes: old_group_id` — the DS atomically marks the old group
  `closed_at` and creates the successor (the partial unique index makes this race-safe; losers
  join the successor). Members migrate via the normal join path; the UI stays in "re-securing"
  throughout — never plaintext. Adversarial test T-17 (member submits syntactically-accepted,
  semantically-invalid winning commit) asserts the group converges on a successor, not a
  deadlock.
- **End of call.** `room_finished` webhook ⇒ crond-swept DS group record; members wipe local MLS
  state for the group (call-scoped; nothing outlives the call except crash-recovery persistence
  during it).

**Crash recovery within a call:** all OpenMLS state mutations for a commit are applied in ONE
SQLite transaction together with our epoch bookkeeping (§5.4), so a crash mid-commit resumes at
the previous epoch and reprocesses from the mailbox (envelopes stay queued until acked — the
existing ack contract).

### 1.5 Exporter → per-sender frame keys → LiveKit key index

Per epoch, in native code only:

```
media_base_secret = MLS-Exporter(label = "acutest-media-frame:v1",
                                 context = group_id,        # 32 bytes
                                 length  = 32)

frame_key(sender) = HKDF-SHA256(ikm  = media_base_secret,
                                salt = "",
                                info = "acutest:media:sender:v1" || 0x00
                                       || utf8(user_id)  || 0x00
                                       || utf8(device_id)|| 0x00
                                       || epoch_be64,
                                L = 32)
```

- Every member derives every sender's key locally (all inputs are roster-public within the
  group); no key ever transits any channel. Only the derived `frame_key` values cross IPC to the
  webview KeyProvider (§7.2).
- **Full chain honesty (audit fix):** `frame_key` is 32 bytes of **key MATERIAL**, not the frame
  encryption key. LiveKit's worker runs its own HKDF over it (fixed, PUBLIC salt
  `"LKFrameEncryptionKey"`, `constants.ts:32`) and derives an **AES-128-GCM** key
  (`deriveKeys` uses `length: 128` — consistent with the AES128GCM ciphersuite in §1.2). The
  effective media key is `HKDF_LK(frame_key)`; the fixed salt adds no secrecy — all secrecy comes
  from `frame_key`. Per-sender/per-epoch uniqueness is preserved (frame_key is already unique).
  Every "AES-256 frame key" phrasing elsewhere in earlier drafts was wrong and is corrected
  (§7.2). Note also the `epoch_be64` field in the HKDF info is belt-and-suspenders: the exporter
  secret is already per-epoch, so exporter epoch-binding is the PRIMARY separation and the info
  field is defensive redundancy — stated so a future reader doesn't misread the schedule.
- **LiveKit mapping:** `keyIndex = epoch mod 16` (keyring size 16, the 2.15.13 default).
  `MlsKeyProvider` (subclass of `BaseKeyProvider` — required because 2.15.13's
  `ExternalE2EEKeyProvider.setKey` takes neither participantIdentity nor keyIndex and hard-codes
  `sharedKey: true`) calls the protected `onSetEncryptionKey(keyMaterial, participantIdentity,
  keyIndex)` per sender, with options `{ sharedKey: false, ratchetWindowSize: 0,
  failureTolerance: 0 }` — **MLS epochs are the only rotation mechanism**; LiveKit's sframe-style
  self-ratchet is disabled so a "ratcheted" key can never diverge from MLS-derived truth.
  **failureTolerance: 0 semantics, stated honestly (audit fix):** the FIRST missing-key decrypt
  failure at an index emits one error event, then the worker **silently drops** all subsequent
  frames at that index (no further events) until a `setKey` resets the failure count. So
  failures do NOT "surface immediately as loud state" per frame — the loud-state machine must
  **latch on the first `encryptionError`** and classify it (§4.4).
- **Rotation seam (restated in terms of the real mechanism — there is no separate "switch"
  API; the local participant's `setKey` IS the send-index switch):** on epoch change,
  `applyKeys` installs remote senders' keys FIRST and the **local participant's key LAST**.
- **Transition window (audit HIGH fix — control plane races the media plane on every epoch
  change).** The committer switches its send key on win, while every other member learns the new
  epoch via mailbox → native tx → IPC → worker; new-epoch frames routinely arrive before that
  pipeline completes, and with failureTolerance: 0 each receiver eats a silent media gap per
  rotation. Rule: **for Add-driven epochs, senders continue on the OLD epoch key for a bounded
  grace period (v1: 2 s, or until commit-delivery acks if sooner); receivers hold old+new (the
  16-slot keyring already allows this). For Remove-driven epochs, senders switch IMMEDIATELY —
  epoch hygiene beats continuity — and the dropout is accepted and documented.** The loud-state
  trigger is debounced past the grace window (§4.4) so clean rotations never flash
  NOT-ENCRYPTED. The per-rotation gap under churn is measured in 6.4 with an acceptance
  threshold (R-1). This is the same tradeoff DAVE resolves with protocol-defined transitions;
  ours is client-local because the DS must stay untrusted.
- **Wraparound:** receivers that lag ≤15 epochs still hold the old key at the old index. Lag >15
  epochs within one call ⇒ desync (§1.4). Key-index wraparound (epoch 16 reuses index 0) is safe
  iff a member never lags 16 epochs — the desync rule is the SINGLE point of correctness here,
  so native emits telemetry + an assertion when any receiver's lag approaches the boundary
  (v1: warn at lag 8, desync at the threshold, well before 16); adversarial test T-08 covers it.
- **Participant identity mapping:** LiveKit token identity today is the user id
  (`voice_client.rs:72` token creation). Frame keys are per `(user, device)`. v1 constraint:
  **one device per user per call**, and the enforcement point is the **DS, not "native"** (audit
  fix — two native layers on two devices share no state; only the DS sees both): the DS
  atomically **refuses a join_intent / winning Add for a `(group, user)` that already has a live
  leaf from a different device** (unique check inside the commit-CAS transaction). Client-side,
  the second device's join UI checks `mls_call_state` before touching LiveKit. Known residue:
  with user-scoped token identities, the SFU kicks the FIRST device's media session the moment
  the second connects — unavoidable at the SFU level and it strengthens the case for
  device-qualified identities (OPEN QUESTION #4); the first device then sees itself SFU-less and
  leaves cleanly. Without DS enforcement a two-device race would put two same-user leaves in the
  group, both mapping to one participantIdentity, and LiveKit's `keyInfoMap` (keyed by
  `identity-keyIndex`) would let the second key silently OVERWRITE the first — wrong-key silent
  decrypt, the exact opposite of the promised refusal. T-16 is the two-device-race adversarial
  test asserting refusal, not last-writer-wins. The LiveKit participantIdentity →
  `(user_id, device_id)` mapping is then injective. Lifting this is Deferred (Q4).

### 1.6 Join mechanism analysis: Welcome-based vs external commit — DECISION: Welcome-based for v1

| | Welcome-based (chosen) | External commit |
|---|---|---|
| Server must store | Nothing beyond KeyPackages + opaque relayed ciphertext | **GroupInfo (with external pub) per epoch** — includes tree hash / confirmed transcript, and practically the ratchet tree extension ⇒ roster structure visible to the server |
| Trust direction | Existing member (with pinned identities) verifies and admits the joiner | Joiner inserts itself; existing members validate after the fact |
| Fits existing machinery | Exactly the OTK-claim + envelope-mailbox shape we already run | New "fetch GroupInfo" surface, new hostile-DS forgery class (forged GroupInfo) |
| Metadata cost | Zero new server-readable group structure | Significant, violates the zero-new-metadata precedent (DESIGN5 §2.6) without buying required function |
| Churn cost | One losing committer wastes a KeyPackage claim per race | Slightly fewer round trips for the joiner |

Welcome-based join keeps the server maximally blind, reuses the audience-expansion trust rule
(member-verified admission), and maps 1:1 onto proven machinery. External commit is **rejected for
v1** including for desync recovery (rejoin-fresh is simpler and calls are short-lived). Revisit
only if join latency at scale proves unacceptable (Deferred; would require deciding whether
server-held GroupInfo is an acceptable, documented metadata extension).

---

## 2. Server: the MLS Delivery Service

All new code follows the `/e2ee` precedent (`crates/delta/src/routes/e2ee/`,
`crates/core/database/src/models/e2ee/`). Everything ships behind a new feature flag and lands in
BOTH DB drivers with tests under both `TEST_DB=REFERENCE` and `TEST_DB=MONGODB` (Mongo runs are
WSL-only on Windows).

### 2.1 Feature flag

`Features.media_e2ee_enabled: bool` (`#[serde(default)]`, `crates/core/config/src/lib.rs:462-479`
pattern), default `false` in `Revolt.toml`, `true` in `Revolt.test.toml`, operator override in
`Revolt.overrides.toml`. Per-request `require_media_e2ee_enabled()` clone of
`routes/e2ee/mod.rs:51-59`, called first in every handler and per-frame in bonfire. Additionally
gated on `e2ee_enabled` (media E2EE requires text E2EE).

### 2.2 New collections / models (`crates/core/database/src/models/mls/`)

`model.rs` + `ops.rs` trait (`AbstractMls`) + `ops/mongodb.rs` + `ops/reference.rs`; trait added
to `AbstractDatabase` (models/mod.rs:60-90); `Arc<Mutex<HashMap>>` fields added to ReferenceDb
(drivers/reference.rs:43-47); collections + indexes in `admin_migrations/ops/mongodb/init.rs` AND
a numbered migration in `ops/mongodb/scripts.rs` (e2ee precedent at 1496-1582).

1. **`mls_key_packages`** — mirrors `e2ee_prekeys` exactly:
   `_id = {user_id}:{device_id}:{key_package_ref}`, opaque KeyPackage bytes, server-verified
   binding signature at publish (same per-key Ed25519 verification pattern as
   `publish_keys.rs:126-128`), `MAX_KEY_PACKAGES = 100` cap with upsert-aware count
   (`count_..._among` pattern), atomic claim via `find_one_and_delete` / single-Mutex
   check-and-remove, **last-resort KeyPackage**, `expires_at` from the KeyPackage lifetime for
   the crond sweep.
   **Last-resort KeyPackage — analyzed as an MLS-specific FS tradeoff, NOT a fallback-key
   analogy (audit HIGH fix).** The Olm analogy breaks in two ways. (a) *Forward secrecy:* an MLS
   KeyPackage carries a one-time HPKE init private key and the Welcome is HPKE-sealed to it;
   reusing one init key across joins means a single later compromise of that key decrypts EVERY
   Welcome sealed to it — handing over the initial group/epoch secrets of each of those calls.
   (An Olm fallback key only exposes a pairwise session that immediately ratchets away.) The
   Welcome-FS reduction is documented in §5.6 and bounded: last-resort packages get a SHORT
   lifetime (v1: 7 days vs 30 for one-time packages), replenish is aggressive (same low-water
   trigger; exhaustion should be rare), the claim response flags reusability so clients prefer
   re-claiming a one-time package later, and the retained init key is zeroized on replacement.
   (b) *Storage model:* OpenMLS's StorageProvider deletes the init private key after a Welcome
   is processed — single-use by construction. A reusable last-resort package requires an
   **explicit storage carve-out** retaining that one init key across joins without corrupting
   OpenMLS's single-use accounting. **Confirming OpenMLS actually permits this is a named first
   task of 6.2**; if it cannot be done cleanly, v1 falls back to no-last-resort + a loud
   "joiner's KeyPackages exhausted, retry shortly" state (fail-loud beats fail-weak-FS).
2. **`mls_groups`** — `_id = group_id`, `channel_id`, `created_by (user,device)`, `created_at`,
   `current_epoch: u64`, `closed_at: Option`, `superseded_by: Option<group_id>`. **Create-race
   arbitration: partial unique index on `channel_id WHERE closed_at IS NULL`** (Mongo partial
   index; Reference driver contains-check for an open group per channel under the Mutex) — NOT
   a unique insert on group_id, which can never collide for racing creators (§1.2, amendment
   A5). 409 responses carry the open group_id. Authorization: every route checks the session
   user can access `channel_id` (existing channel-permission machinery). NOTE: this collection
   is a **documented metadata extension** — see §5.6.
3. **`mls_commits`** — `_id = {group_id}:{epoch}`, opaque commit ciphertext, committer
   `(user_id, device_id)` stamped **server-side from the session** (text invariant 5), size,
   created_at. **Unique-index insert IS the epoch arbitration**: Mongo duplicate-key 11000 →
   `InvalidOperation`/409 (exact `insert_e2ee_identity` pattern, ops/mongodb.rs:42-57); Reference
   driver single-Mutex contains-check-then-insert. Loser receives the winning commit in the same
   409 response body and rebases. This is the one-winner-per-epoch primitive, already proven in
   this codebase.
4. **Handshake mailbox — reuse `e2ee_queue` (`E2EEEnvelope`) with a size-cap extension** (the
   word "unchanged" was wrong — audit fix: the existing `MAX_CIPHERTEXT_LENGTH = 65536`
   (`routes/e2ee/mod.rs:44`, enforced `send_messages.rs:59`) would reject the first ~10-member
   Welcome and brick every join). Commits (fan-out copies) and Welcomes ride the existing
   per-recipient-device mailbox: server ULID ordering per mailbox, bonfire
   drain-after-device-proof, `E2EEAck` deletion, 30-day crond TTL — all already built and
   audited. New envelope `content_type` discriminator field (`olm` default / `mls_commit` /
   `mls_welcome`) + `group_id` + `epoch` metadata columns (opaque to routing; used by clients to
   order per-group). **Per-content_type size caps in envelope validation:** `olm` 64 KiB
   (unchanged — the text-E2EE abuse budget is NOT quadrupled), `mls_commit` 64 KiB,
   `mls_welcome` 256 KiB **raw** (≈341 KiB base64-encoded — the validation accounts encoded vs
   raw explicitly). Consequences budgeted in 6.1: re-derive the per-device queue-depth/bandwidth
   budget (512/device was sized for ≤64 KiB envelopes) for welcome-sized envelopes at the
   24-member cap, and verify bonfire's live-push frame path handles the larger frame. Per-
   recipient-device mailbox order is sufficient because **group order is established by the DS
   arbitration (epoch counter), not mailbox ULIDs** — a client applies commits strictly by
   consecutive epoch number and parks/refetches on gaps.

### 2.3 Routes (mounted at `/mls` in delta, `routes/mod.rs:42` pattern)

| Route | Behavior |
|---|---|
| `PUT /mls/key_packages` | Publish/replenish KeyPackages + last-resort package. MFA ticket on first publish, device-bound session on republish, binding-signature verification, dedupe-by-ref rejection, cap accounting, returns remaining count (all mirroring `publish_keys.rs`). |
| `POST /mls/key_packages/claim` | Body: target `(user_id, device_id)` list (bounded). Atomic consume per device; last-resort at exhaustion; rate-limited per `(claimer, target)` pair (§1.4 racing-admitter accounting). **Eligibility (audit HIGH fix):** the text-E2EE gates (`require_e2ee_fetch_eligible` admits only friend/mutual pairs or shared *Group-DM* members) structurally exclude strangers who are co-members of a server voice channel — the headline use case. New eligibility class for BOTH claim and MLS-envelope delivery: **shared channel access on the target group's `channel_id`** (session user and target both able to access the channel of an open `mls_groups` record, i.e. co-presence in the target call). Blocked-pair semantics mirror slice-5's deliver-vs-fetch asymmetry — and note blocked pairs in the same server channel already see each other's plaintext today, so channel-scoped eligibility leaks nothing new. Stranger-co-member tests in §2.6. |
| `POST /mls/groups` | Create group for a channel the session user can access + is in the call of. **Channel-scoped arbitration (§1.2):** partial-unique on open channel groups; 409 returns the existing open `group_id` → join path. Accepts `supersedes: group_id` for poisoned-epoch/successor flow (§1.4): atomically closes the old group and creates the new one. |
| `POST /mls/groups/<id>/join_intent` | Store signed join intent (server verifies the identity signature — defense in depth; clients re-verify, which is the real check), fan out `MlsJoinRequested` to member-user private topics. |
| `POST /mls/groups/<id>/commits` | Body: `{ epoch, commit_ciphertext, welcome_ciphertext?, added/removed device list for fan-out }`. CAS insert on `{group_id}:{epoch}` (the CAS transaction also enforces the one-device-per-user rule, §1.5); on win: bump `mls_groups.current_epoch`, enqueue commit envelope per member device + welcome envelope per added device (queue-first-then-live-push, `send_messages.rs:179-187` pattern), respond 200. On lose: 409 + winning commit bytes. Caps per §2.2(4): commit 64 KiB, Welcome 256 KiB raw (Welcome is O(n); the roster cap is A3/Q5). **Trust note (audit fix):** the fan-out device list is committer-asserted and the DS cannot validate it against the ciphertext — a malicious MEMBER can under-fan-out to silently desync targeted members. This is **availability-only** (victims gap-refetch via `GET .../commits` or rejoin; no secrecy impact) and is tested as T-19. |
| `GET /mls/groups/<id>/commits?from_epoch=` | Gap refetch for desynced members (returns the stored winning commits — they are ciphertext; only members can read them). |

Rate limits: reuse delta's existing per-route rate-limit machinery; commits additionally bounded
by epoch monotonicity (you cannot submit epoch N+5), join intents per user per group per minute.

### 2.4 Bonfire

Zero new topic machinery for v1 (the deliberate slice-5 choice): all events fan out one per member
user on the `{user_id}!` private topic (`EventV1::private`), devices filter by device_id. New
events: `MlsJoinRequested`, `MlsCommit` (live push of the enqueued envelope, dedup by envelope
ULID exactly like `E2EEMessage`), `MlsWelcome`. Drain/ack path is untouched — MLS envelopes are
just envelopes. Topic-per-group is Deferred (topic == authorization boundary; not needed at
≤ the v1 roster cap).

### 2.5 crond sweeps (`crates/daemons/crond/src/tasks/`)

- `prune_mls_groups.rs` — delete group + its `mls_commits` rows when `closed_at` older than 24 h,
  or `created_at` older than 7 d regardless (call groups are ephemeral; nothing to keep).
  `room_finished` webhook (voice-ingress) sets `closed_at`.
- `prune_mls_key_packages.rs` — hourly delete of `expires_at < now` (KeyPackage lifetime v1:
  30 days, matching envelope TTL; clients replenish on the same low-water trigger as OTKs).
- Envelope TTL: existing `prune_e2ee_envelopes.rs` covers MLS envelopes for free.

### 2.6 Server tests

In-crate Rocket tests over ReferenceDb (`routes/e2ee/tests.rs` precedent), both drivers:
commit-race exactly-one-winner under concurrency, epoch monotonicity, claim atomicity (two
concurrent claimers never get the same KeyPackage), last-resort at exhaustion, cap accounting,
eligibility gates **including the stranger-co-member case (two non-friends sharing only a server
voice channel can claim/deliver; §2.3 audit fix) and the blocked-pair semantics**,
**simultaneous-create race on one channel ⇒ exactly one open group, loser 409 carries the open
group_id (both drivers; audit CRITICAL)**, per-content_type envelope size caps (welcome-sized
accepted, oversized olm rejected), one-device-per-user CAS refusal, successor/`supersedes`
atomicity, flag-off ⇒ every route 4xx, join-intent signature rejection, fan-out set
correctness, sweep behavior, and the `voice/mod.rs:537` `can_publish_data` regrant fix (§0.4).

---

## 3. Native: OpenMLS in `e2ee-core`

### 3.1 Crate / module layout

- `openmls` + `openmls_rust_crypto` (crypto provider — RustCrypto stack, next to the existing
  `aes-gcm`/`hkdf`/`sha2`) added to `e2ee-core/Cargo.toml`, **pinned to exact versions** (`=x.y.z`)
  given pre-1.0 churn. Watch items (carried as risk R-3): `rand` 0.8 (ours) vs 0.9 in newer
  openmls stacks, `zeroize` unification, `getrandom` 0.3.
- New modules: `e2ee-core/src/mls/` — `mod.rs` (engine surface), `credential.rs` (binding,
  canonical payload, verification), `storage.rs` (OpenMLS `StorageProvider` over our SQLite),
  `keys.rs` (exporter → frame-key derivation, LiveKit index mapping), `wire.rs` additions for the
  DS shapes. `canonical.rs` gains `CONTEXT_MLS_CREDENTIAL` + `CONTEXT_MLS_JOIN`.
- Engine surface on `E2ee` (same `&mut self` + embedder-Mutex model): `mls_call_create`,
  `mls_call_join_intent`, `mls_call_admit` (verify intent → Add+commit+Welcome),
  `mls_call_process` (commit/welcome from mailbox), `mls_call_leave_cleanup`,
  `mls_call_frame_keys` (the sanctioned derived-key egress), `mls_call_state` (roster +
  per-member verification status + epoch + encrypted/downgraded — flags and display data only),
  `mls_publish_key_packages`, `mls_replenish_check`.

### 3.2 Storage + schema migration

- 5th HKDF domain-separated subkey from the master: expand `b"mls"` alongside
  pickle/history/attachment/backup (store.rs:517-524). All OpenMLS-persisted values are sealed
  with it (AAD = group_id || storage-key-label) before touching SQLite — same
  column-encryption pattern as vodozemac pickles.
- Schema migration `if version < 5 { CREATE TABLE mls_state (…); CREATE TABLE
  mls_signature_key (…); PRAGMA user_version = 5; }` in the existing single-transaction ladder
  (store.rs:646-809). `mls_state` is a sealed KV table shaped for the OpenMLS storage trait
  (group_id-scoped rows so per-group wipe is one DELETE); `mls_signature_key` holds the sealed
  long-lived MLS signature keypair + published-KeyPackage bookkeeping.
- **Backup tripwire (this is budgeted, not incidental):** bumping `SCHEMA_VERSION` to 5 breaks the
  `EXPORT_SCHEMA_VERSION == store::SCHEMA_VERSION` compile-time assert (backup.rs:60-66) until
  backup.rs is revisited — see §5.5 for the ruling.
- `E2ee::wipe()` needs no change for MLS state living inside `store.db` (wiped for free); the
  KeyPackage private init keys live there too — no new files.

### 3.3 Crash-safe commit processing

Processing an inbound commit = one SQLite transaction containing: OpenMLS storage writes (the
storage provider participates in the ambient transaction), our epoch bookkeeping row, and the
processed-envelope replay-horizon update. Ack to the server is sent only after the transaction
commits (existing ack discipline: envelopes stay queued until acked). Outbound commit = stage
locally as *pending*, submit to DS, then apply-on-win / discard-and-rebase-on-409 — never apply an
unconfirmed own-commit (the DS is the orderer; applying early would fork us from the group on a
lost race).

### 3.4 Downgrade machinery (generalized both-sides rule)

- Call encryption eligibility is computed **natively** (`mls_call_send_mode` verdict, same
  sole-authority stance as `e2ee_send_mode`): E2EE iff every current call participant presents a
  claimable KeyPackage whose binding verifies against a pinned (or TOFU-pinnable) identity.
- **Trusted enumeration of "every current call participant" (audit fix — this input was
  attacker-controlled and unspecified):** the participant set is the **UNION of the
  LiveKit/SFU participant list and the verified MLS roster**, reconciled per §1.4. The SFU list
  arrives via the untrusted server, but for the downgrade decision that direction is safe-loud:
  an SFU participant absent from the verified MLS group counts as a **non-enrolled participant
  and trips the loud whole-call downgrade** — the server can at most cause a *spurious* loud
  prompt (annoying, safe), never suppress a real one, because suppression requires hiding the
  participant from BOTH the SFU list (which would also stop their media) and the MLS roster
  (which is cryptographically verified).
- **Non-enrolled participant joins an E2EE call ⇒ whole-call LOUD downgrade:** native emits
  `downgraded` state; each enrolled client (a) immediately STOPS publishing encrypted frames,
  (b) **pauses local media publishing entirely** and shows the blocking downgrade banner,
  (c) resumes as plaintext only after a **local, per-device confirmation** (the slice-5 [G2:1]
  rule generalized: a peer or server can at most cause a prompt, never open the plaintext path
  itself). Desktop: native OS dialog via the `e2ee_downgrade` pattern; the webview can only
  request. Declining = leave the call or stay receive-only-plaintext-indicated.
- **Mode-transition state machine (audit fix — N members previously transitioned independently
  with no convergence protocol).** The downgrade DECISION stays per-device (native verdict +
  local confirm — correct trust direction, unchanged). The transition MECHANICS converge as
  follows: the first member whose user confirms plaintext announces the mode change **inside the
  MLS group** (a ctl-style application message, epoch-anchored — same authority rule as slice-5
  ctl: `binding_verified && !identity_changed`); this is a coordination signal only, it cannot
  open anyone's plaintext path (each device still requires its own local confirm — the
  announcement at most timestamps the interlude). Mixed-window semantics, enumerated: members
  that confirmed publish plaintext; members that have not confirmed have publishing PAUSED
  (never plaintext-without-confirm, never encrypted-into-a-mixed-call); all members may receive
  plaintext with the loud indicator; the MLS group is kept warm (not retired) during the
  interlude so re-upgrade is cheap and the ctl channel survives. Mid-call
  `Room.setE2EEEnabled(true/false)` toggling is on the 6.0 platform-probe list — the §4.1
  wiring (Room always constructed E2EE-capable) makes it *possible*; 6.0 proves it *works*.
- **Re-upgrade:** when the last non-enrolled participant leaves, the call re-establishes E2EE
  automatically (fresh group via the §1.2 successor flow, fresh epoch — the sticky-encryption
  ratchet direction is toward encrypted, so auto-re-upgrade needs no confirm), via
  `setE2EEEnabled(true)` on the existing Room (§4.1) — **not** a disconnect/reconnect.
  **Flap damping (audit fix):** re-upgrade fires only after the call has been
  non-enrolled-free for a hysteresis window (v1: 15 s), so a bouncing non-enrolled participant
  cannot alternate downgrade prompts with re-key storms.
- **Roster cap (amendment A3, resolves the two audits' disagreement in the same direction):** at
  `MAX_E2EE_CALL_MEMBERS` the call **stays E2EE** and the overflow joiner is refused media-key
  admission with a loud "call full for E2EE" state on their device. The earlier draft's
  overflow-to-plaintext-with-confirm is REJECTED: it hands any single account (or an alt) a
  whole-call downgrade trigger, violating invariant 3, and creates 24↔25 boundary flapping.
  Cap-forcing join is adversarial test T-20.
- The composer-adjacent surface (join button) shows the mode the call WILL use before joining
  (text invariant 3's compose-time = send-time rule, translated).

### 3.5 IPC surface (desktop, `src-tauri/src/e2ee.rs`)

New commands (three sync points each: `APP_COMMANDS` in build.rs, `generate_handler!` in lib.rs,
`capabilities/default.json` grant): `e2ee_call_create`, `e2ee_call_join`, `e2ee_call_admit_poll`
(or event-driven via the existing Tauri event bus like `e2ee:recovery-complete`),
`e2ee_call_process`, `e2ee_call_state`, `e2ee_call_leave`, `e2ee_call_frame_keys`,
`e2ee_call_confirm_downgrade` (native-dialog-gated), `e2ee_mls_replenish`.

**`e2ee_call_frame_keys` is the documented invariant-6 exception** (§7.2): returns
`[{ livekit_identity, user_id, device_id, key_index, frame_key_b64 }]` for the current epoch (and
the previous epoch during rotation overlap). Native pushes a `e2ee:call-keys-changed` Tauri event
on every epoch change; the webview re-invokes and feeds `MlsKeyProvider`. Nothing else secret ever
crosses: not exporter secrets, not epoch secrets, not MLS signature keys.

### 3.6 Android (later sub-slice, 6.7)

- `e2ee-android/src/lib.rs`: thin `#[uniffi::export]` methods 1:1 with the desktop commands, JSON
  strings in/out (existing boundary encoding), frame keys crossing as the same JSON shape.
  Regenerate bindings via `build-android.ps1` (debug-dylib bindgen gotcha unchanged).
- `E2eePlugin.kt`: new `__cmd` allowlist entries in the generic `call()`;
  `e2ee_call_confirm_downgrade` becomes a dedicated method with a BLOCKING native `AlertDialog`
  (wipe/downgrade precedent). Epoch-change push: plugin exposes a listener/callback event to JS
  (Capacitor plugin events) mirroring the Tauri event bus.
- **This relaxes the Android no-keys-over-the-JS-bridge invariant** the same way as desktop —
  same documented exception, same narrowest-exposure rule (§7.2). No interceptor route is needed
  (frame keys are small; the `resolveJson` path carries them).
- OpenMLS is already in e2ee-core, so the .so grows but no new crate.

---

## 4. Client (frontend repo)

### 4.1 Room wiring (`packages/client/components/rtc/state.tsx`)

At the exact `new Room({...})` site (state.tsx:243-256): **on ANY shell where
`isE2EESupported()` is true and the native layer is present, ALWAYS construct the Room with**

```ts
e2ee: { keyProvider: mlsKeyProvider, worker: new E2EEWorker() }
```

**regardless of whether THIS call is currently E2EE-eligible** (audit HIGH fix, amendment A4:
verified in livekit-client Room.ts, `setE2EEEnabled()` THROWS if the `e2ee` option was omitted
at construction — the E2EEManager can only attach in the constructor. Constructing the Room
without the option whenever a non-enrolled participant happens to be present would make the
§3.4 auto-re-upgrade *impossible* without a full disconnect/reconnect). The option is inert
while disabled; the actual mode is controlled via `setE2EEEnabled(true/false)`. The no-e2ee
Room construction is reserved for **unsupported shells only** (which are non-enrolled and can
never re-upgrade anyway).

Worker import: `import E2EEWorker from "livekit-client/e2ee-worker?worker"` — the worker ships
inside the npm package (`dist/livekit-client.e2ee.worker.mjs`), so Vite `?worker` bundling makes
it fully self-hosted, **no CDN** (unlike the rnnoise runtime-URL pattern; like the mediapipe
self-hosting precedent). Add the emitted worker asset to the PWA `globIgnores` if it threatens
the 4 MB precache cap (vite.config.ts:43-48). Unsupported shell ⇒ treated as non-enrolled (loud
downgrade path), never a silent plain Room.

`Room.setE2EEEnabled(true)` after connect when the call is E2EE;
`RoomEvent.ParticipantEncryptionStatusChanged` + `encryptionError` wired into the
downgrade/indicator state **as a REQUIRED gating input for the green state, not merely
telemetry** (§4.4, invariant 11).

### 4.2 `MlsKeyProvider` + bridge plumbing (`components/client/e2ee.ts`)

- `class MlsKeyProvider extends BaseKeyProvider` (constructed
  `{ sharedKey: false, ratchetWindowSize: 0, failureTolerance: 0 }`), with an
  `applyKeys(entries)` method that imports each `frame_key` as **raw HKDF key MATERIAL** —
  `crypto.subtle.importKey('raw', buf, 'HKDF', false, ['deriveBits','deriveKey'])`, the
  `createKeyMaterialFromBuffer` pattern (utils.ts:58) — and calls the protected
  `onSetEncryptionKey(keyMaterial, participantIdentity, keyIndex)`, **remote senders first,
  local participant LAST** (§1.5: the local setKey IS the send-index switch).
  **Audit HIGH fix — the earlier draft said "AES-GCM CryptoKey", which is wrong and
  non-functional:** the 2.15.13 worker's `setKeyFromMaterial → deriveKeys` calls
  `crypto.subtle.deriveKey(HKDF, material, {name:'AES-GCM', length:128}, …)` on the provided
  key; an AES-GCM `CryptoKey` (usages encrypt/decrypt) throws `InvalidAccessError` on EVERY
  setKey — no key ever installs, all frames drop. The 6.0 spike explicitly exercises the real
  `BaseKeyProvider → worker` path with these exact import parameters.
- **Provider/worker hygiene (audit fix — LiveKit never destroys ParticipantKeyHandlers and
  `keyInfoMap` grows for the call's duration; `getKeys()` is replayed to the worker on
  reconnect in stale insertion order):** `MlsKeyProvider` keeps only the CURRENT (+ previous,
  during rotation overlap) epoch entries per participant; clears entries for removed leaves; on
  any LiveKit reconnect, native re-pushes the current epoch key set (local last) rather than
  trusting LiveKit's replay — a stale replay could momentarily resume sending on an old epoch
  key still held by since-removed members (invariant 7 edge). The worker is terminated/replaced
  on call end. Residual worker-side key retention until call end is documented in §7.2.
- New `NativeTransport` usage: the `e2ee_call_*` commands ride the existing transport seam
  (TauriTransport / CapacitorTransport) — no new transport machinery. New reactive map
  `callStates: ReactiveMap<channelId, CallE2EEState>` (the `sendModes` pattern) drives all UI.
- Tauri event `e2ee:call-keys-changed` (and the Capacitor listener on Android) triggers
  re-invoke of `e2ee_call_frame_keys` → `applyKeys`. The webview never derives, stores, or
  persists keys — memory-only, handed straight to the provider.
- Fail-closed: every native error in the call-key path surfaces as the loud "not encrypted /
  re-securing" state; there is no code path that silently constructs an unencrypted Room for a
  call natively judged E2EE (the `E2EESendError` never-fall-back stance, translated).

### 4.3 Track processor interaction

Denoise (`setProcessor(DenoiseTrackProcessor)`, state.tsx:292-299) and camera effects
(cameraEffects.ts) are **pre-encode** track processors (AudioWorklet / video frame processing on
the raw track). LiveKit E2EE runs **post-encode** on encoded frames (RTCRtpScriptTransform /
createEncodedStreams). Pipeline: processor → encoder → E2EE encrypt → SFU. No slot conflict; the
plan's only rule is nothing may re-order this (document in state.tsx comments; test T-10 asserts
denoise+E2EE coexist).

### 4.4 Indicator + downgrade UX (verified state only)

- **Whole-call chip:** `VoiceCallCardStatus.tsx` — states: `E2EE` (green lock), `E2EE
  (unverified peers)` (lock, neutral), `NOT ENCRYPTED` (loud, persistent), `RE-SECURING`
  (desync/rotation).
  **Green gating is DUAL (audit HIGH fix, amendment A1 — supersedes the earlier
  "cross-check/telemetry" demotion):** green requires (a) native `mls_call_state` = encrypted +
  all leaf bindings verified + keys pushed, **AND (b) LiveKit's observed per-participant
  encryption status (`ParticipantEncryptionStatusChanged` / `useIsEncrypted`) reporting
  encrypted for every participant.** Rationale: for media, native only derives and pushes keys —
  the encryption toggle and the frame-encrypt worker live in the webview, so "keys pushed" is
  NOT "encryption happened"; the LiveKit signal is the only one that observes the media plane.
  Neither signal alone can produce green; either's absence/failure drops to
  RE-SECURING/NOT ENCRYPTED (fail-closed). Server flags still can never promote. **Honest
  limitation, stated:** native cannot unilaterally attest media-plane encryption, and signal (b)
  is computed by webview code — the indicator is only as trustworthy as the code that owns
  `setE2EEEnabled`, which is exactly why bundle-frontend+CSP is a hard precondition of 6.3
  (amendment A2), not a nice-to-have.
- **Error classification + latching (audit fix — LiveKit emits ONE error then drops frames
  silently, §1.5):** the state machine LATCHES on the first `encryptionError`.
  Missing-key failures during a KNOWN rotation window (an epoch change native is currently
  processing, § 1.5 transition window) classify as `RE-SECURING` with a bounded timer (v1: 10 s)
  escalating to `NOT ENCRYPTED`/loud failure; the same failure outside a known rotation is
  immediately loud. Clean rotations must never flap the chip (extended T-06).
- **Per-participant lock:** `ParticipantTile.tsx` — pinned-identity verification status per tile
  (same iconography as slice-5 chat verification). Tiles are LiveKit-track-driven, so the roster
  panel itself renders from the MLS roster with divergence flags (§1.4 reconciliation) — a
  trackless MLS leaf must be visible, not absent.
- **Downgrade banner:** inside `VoiceCallCard.tsx` (`VoiceChannelCallCardMount`) — blocking,
  names the non-enrolled participant(s), publishing paused until native confirm (§3.4).
- **Pre-join mode surface (citation audit fix — `ChannelHeader.tsx` does not exist):** the join
  controls in `components/ui/components/layout/Header.tsx` and the join/preview surfaces
  `VoiceChannelPreview.tsx` / `VoiceCallCardPreview.tsx` show the pre-join mode (will-be-E2EE
  vs plaintext).
- **Safety numbers:** call roster panel links each participant to the existing slice-5
  verification screen; the number shown IS the slice-5 number (§1.3).

---

## 5. Security invariants (carried + new; violations are release blockers)

The six text invariants (PLAN:11-37) carry as follows:

1. **Fail loud, never silent-plaintext.** An E2EE-eligible call that cannot establish or maintain
   E2EE shows a blocking visible state or refuses; the ONLY path to publishing plaintext media in
   an E2EE-eligible call is an explicit, blocking, per-device native confirmation. No silent
   per-participant plaintext hole, ever — downgrade is whole-call and visible.
2. **Capability from keys, not flags.** Call E2EE eligibility derives solely from
   signature-verified KeyPackages bound to pinned identities. `media_e2ee_enabled` is a UI/route
   hint. A peer once seen enrolled is pinned as enrolled; later KeyPackage absence is an alert
   (and a downgrade PROMPT), never a silent downgrade.
3. **Sticky direction.** Per-channel call encryption ratchets toward encrypted: auto-re-upgrade
   when non-enrolled members leave; plaintext requires per-device local confirm each call.
   Pre-join UI shows the mode that WILL be used.
4. **Membership changes are loud.** Every join/leave is an epoch change (visible in the roster
   UI); identity-changed pins invalidate leaves until re-confirmed; device-list changes surface
   exactly as in text.
5. **Server never inside the trust boundary.** The DS orders and relays; it can never grow a
   roster (member-verified signed join intents), never forge a commit (MLS signatures + binding
   verification), never read group secrets. Committer identity on DS records is stamped from the
   session, but clients trust only MLS-cryptographic identity.
6. **No key material in webview/IPC/logs — with ONE documented exception (§7.2):** derived
   per-sender frame keys cross to the LiveKit E2EE worker. MLS signature keys, epoch secrets,
   exporter secrets, and `media_base_secret` never leave native. Zeroize where supported.

New media-specific invariants:

7. **Epoch hygiene (stated with the precise per-sender boundary — the unconditional form was
   falsifiable on timing, audit fix).** A joiner cannot decrypt media from before its Add
   commit. Post-removal secrecy is guaranteed for frames encrypted **after each sender applies
   the Remove commit**; a sender whose commit delivery lags keeps encrypting at the old epoch
   for a window bounded by commit delivery + the Remove-immediate switch rule (§1.5 — no grace
   period on Removes) + the desync threshold, and frames in that window are decryptable by the
   removed member if a compromised SFU/relay hands them over (the standard distributed-rotation
   window; DAVE has it too — documented in §5.6). Every membership change re-keys. T-03 asserts
   exactly the per-sender post-commit boundary. **Hostile-operator scope:** removal depends on
   observing leave signals the operator controls; against a hostile operator invariant 7
   degrades to *surfaced divergence* via roster reconciliation + heartbeat (§1.4) — written
   honestly in §5.6, not claimed as prevention.
8. **One verification primitive.** Call-roster verification is the slice-5 safety number via
   credential binding; no second code format may be introduced.
9. **Version/ciphersuite floor.** Exactly one accepted ciphersuite + MLS protocol version in v1;
   reject outside the set loudly, below AND above.
10. **DS arbitration is total.** Exactly one commit per (group, epoch) can ever be accepted by
    any client; clients apply commits in strict epoch order and treat gaps as desync, never
    skip-ahead. (An unprocessable winning commit routes to the §1.4 poisoned-epoch successor
    flow — strict order never means deadlock.)
11. **Green requires both planes (new — audit HIGH).** The encrypted indicator asserts control-
    plane health (native: MLS group healthy, bindings verified, keys pushed) AND observed
    media-plane encryption (LiveKit per-participant encryption status). Native alone cannot
    attest that frames were encrypted; keys-pushed is not encryption-happened. Either signal
    failing ⇒ fail-closed to RE-SECURING / NOT ENCRYPTED.

### 5.5 Key-backup ruling (budgeted decision for the §3.2 tripwire)

Live MLS group state (epoch secrets, secret tree, pending proposals/commits, KeyPackage private
init keys as *served* material) is the same hazard class as live Olm ratchets: restoring stale
epoch state = key/nonce reuse and breaks PCS. **Ruling: ALL `mls_state` rows are EXCLUDED from
backup** (whitelist no-op — no reader added; `EXPORT_SCHEMA_VERSION` bumped to 5 with a comment;
`BACKUP_PAYLOAD_VERSION` unchanged since the exported set does not grow). The long-lived MLS
signature keypair is ALSO excluded v1: it is cheap to regenerate at restore (fresh keypair, fresh
binding signature by the restored identity key, republish KeyPackages during the existing
`post_restore_rekey` step) and excluding it avoids any stale-credential edge. Post-restore
behavior: rejoin calls fresh — the analog of "zero sessions ⇒ re-handshake". Calls are ephemeral;
nothing about a call needs restoring.

### 5.6 Accepted-metadata statement (extends PLAN:1454-1456; documented per the BACKUP §5 M5 pattern)

The server already learns call metadata (who/when/duration). Slice 6 adds to the accepted set:
per-call MLS group existence bound to a channel id; the (user, device) membership/delivery sets
for fan-out (equivalent to what envelope recipients already reveal); the epoch counter and
commit/Welcome sizes and timing; each device's KeyPackage inventory and claim events (equivalent
to existing OTK inventory/consume). **Amendment (6.5, ctl-announce):** the existence and timing
of MLS application-message envelopes (`mls_ctl`) — i.e. "a member announced a call mode change
at time T" — join the accepted set; the announce CONTENT stays group-encrypted and opaque. The
server does NOT learn: group secrets, frame keys, roster
*cryptographic* structure (no GroupInfo/ratchet tree stored — a consequence of the Welcome-based
join decision, §1.6), or media content. Any future feature requiring server-held GroupInfo must
re-open this section explicitly.

**Accepted limitations (audit-mandated honesty; each is documented, bounded, and tested — none
may be silently narrowed further):**

- **Media authenticity is group-level, not sender-level.** Frame keys are derived from
  roster-public inputs, so every member can derive every sender's key; LiveKit's frame format
  carries no signature. A malicious CALL MEMBER can forge frames attributed to another member.
  The §4.4 verification lock authenticates roster identity, never frame origin. (Same accepted
  property as DAVE / SFrame-with-shared-derivation.)
- **Post-leave secrecy vs a hostile operator degrades to surfaced divergence.** Remove commits
  are triggered by operator-controlled signals; a withheld leave event delays removal. The
  backstops are roster reconciliation (a ghost MLS leaf is loudly flagged, then Removed after
  the divergence timeout) and the epoch heartbeat — the guarantee is *divergence becomes loud
  within a bounded window*, not instantaneous eviction (invariant 7, T-18).
- **Distributed-rotation window.** Frames a lagging sender encrypts at the old epoch remain
  decryptable by a removed member until that sender applies the Remove commit; bounded by
  commit delivery + desync threshold (invariant 7).
- **Last-resort KeyPackage Welcome-FS reduction.** Joins served at KeyPackage exhaustion reuse
  an init key; later compromise of that key decrypts every Welcome sealed to it (initial group
  secrets at join time for those calls). Bounded per §2.2(1): short lifetime, aggressive
  replenish, zeroize-on-replacement, client preference for re-claiming one-time packages.
- **Stable-roster exposure is bounded by the heartbeat, not per-frame.** A point-in-time
  webview/worker compromise yields at most the current call's media from the last heartbeat
  epoch onward (§1.4, §7.2) — not per-generation ratcheting (DAVE ratchets generations; we
  deliberately disabled LiveKit's self-ratchet to keep MLS the single source of key truth).

---

## 6. Adversarial test plan

Client-side: new `hostile_ds.rs` (+ `mls_adversarial.rs`) in `e2ee-core/tests/`, same structure
as `hostile_server.rs` (hand-crafted DS lies fed to `E2ee`, asserting fail-closed). Server-side:
`routes/mls/tests.rs` over ReferenceDb + Mongo. Media-plane: scripted two-desktop probe + SFU
capture.

> **6.6 consolidation note (2026-07-12):** the native hostile-DS matrix was implemented in
> `tests/mls_adversarial.rs` (which already forges Welcomes/commits + owns the shared helpers)
> rather than a separate `hostile_ds.rs` — a second file would fork the forge helpers. The full
> desktop-scoped T-01..T-21 coverage map lives in `e2ee-media-slice-6.6-breakdown.md` §4.5.

| # | Test | Asserts |
|---|---|---|
| T-01 | SFU/relay capture | Frames captured at the SFU (packet capture on the LiveKit node) are ciphertext; no plaintext codec payloads. |
| T-02 | Pre-join secrecy | A joiner given recorded pre-join ciphertext + its post-join state cannot decrypt it (epoch keys differ). |
| T-03 | Post-removal secrecy | A removed member holding full pre-removal state cannot decrypt frames encrypted **after each sender applies the Remove commit** (the precise invariant-7 boundary — the unconditional form flakes on the distributed-rotation window). |
| T-04 | Racing commits converge | N concurrent committers for epoch E ⇒ exactly one winner server-side (both drivers, concurrency test) AND all clients converge on the winner; losers rebase without forking. |
| T-05 | Phantom participant | Hostile DS injects a fabricated join intent / adds an unverifiable leaf via forged Welcome ⇒ rejected at credential-binding verification; no member ever derives keys for it; group rejected wholesale on invalid leaf. |
| T-06 | Withheld/reordered commits | DS withholds commits, delivers out of order, or serves epoch gaps ⇒ client parks, refetches, and on failure enters LOUD desync/re-securing state; never applies out of order, never silently continues on stale keys. **Extended:** after a clean rotation's transient missing-key window, decrypt recovers and the chip never flaps to NOT-ENCRYPTED (rotation-skew classification, §4.4). |
| T-07 | Loud downgrade | One non-enrolled participant ⇒ whole call flips to visible unencrypted state; no frame is published plaintext before the per-device native confirm; hostile server cannot suppress the banner (state is native-computed). |
| T-08 | Key-index wraparound | 16+ rapid epochs: lagging receiver at wrap boundary hits desync path, not wrong-key silent decrypt; keyring never serves a stale key for a reused index. |
| T-09 | Secrets scrubbing | Exporter/epoch/signature secrets never in IPC payloads, DS payloads, logs, error strings (grep + typed-error assertions, existing scrub pattern); frame keys appear ONLY in `e2ee_call_frame_keys` responses. |
| T-10 | Processor coexistence | Denoise + camera effects + E2EE all active: frames decrypt correctly (pipeline ordering intact). |
| T-11 | Identity-change on roster | Pinned identity change for a call member ⇒ leaf invalid, loud re-verify flow, no key derivation for that member until confirmed (H1 rule on calls). |
| T-12 | Hostile KeyPackage directory | DS serves stale/expired/binding-invalid/foreign-device KeyPackages at claim ⇒ admitter refuses the Add; drained directory serves last-resort, never "no package ⇒ plaintext". |
| T-13 | Backup exclusion | Backup taken mid-call restores with zero MLS state; restored device rejoins fresh; schema-pin test forces the export decision (compile-time assert). |
| T-14 | Web/non-native shell | `isE2EESupported()` false or no native layer ⇒ shell treated as non-enrolled; joining an E2EE call triggers T-07 behavior, never a quiet plain Room. |
| T-15 | Cross-group Welcome | Hostile DS relays a Welcome for a DIFFERENT group/channel whose leaves are all legitimate pinned members ⇒ joiner's group-context assertion (§1.4 step 4) fails LOUDLY before any key derivation; never a silent join into the wrong call. |
| T-16 | Two-device join race | Same account joins from two devices near-simultaneously ⇒ DS CAS refuses the second `(group, user)` leaf; asserted outcome is REFUSAL with a clear error, never last-writer-wins key overwrite at the KeyProvider. Includes the hostile-DS partition variant (different group_ids handed to different joiners ⇒ loud failure, not two half-calls). |
| T-17 | Poisoned winning commit | A member submits a syntactically-accepted, semantically-invalid commit that WINS an epoch slot ⇒ group converges on a successor group via the abandon flow (§1.4), never a permanent deadlock; UI stays re-securing throughout. |
| T-18 | Withheld leave event | Hostile server suppresses `VoiceChannelLeave`/participant_left for a departed member ⇒ roster reconciliation flags the ghost MLS leaf loudly; a Remove commits after the divergence timeout (surfaced divergence, §5.6). |
| T-19 | Malicious committer under-fan-out | A MEMBER submits a winning commit whose asserted fan-out list omits target devices ⇒ victims detect the epoch gap, refetch via `GET .../commits`, and recover (availability-only; no secrecy impact). |
| T-20 | Cap-forcing join | The `MAX_E2EE_CALL_MEMBERS+1`-th joiner (attacker alt) ⇒ call STAYS E2EE; overflow joiner gets the loud "call full for E2EE" refusal; no downgrade prompt reaches existing members (amendment A3). |
| T-21 | Premature-frame-then-key | Frames at a new keyIndex arrive before the key ⇒ one error event, silent drops, then full recovery after `setKey` (pins LiveKit's `resetKeyStatus` behavior against library upgrades); loud-state stays RE-SECURING within the bounded window. |

---

## 7. Risks, open questions, and the trust-boundary record

### 7.1 OPEN QUESTIONS (top of list; blockers marked)

1. **[BLOCKER for 6.3] WebView2 encoded-transform support — UNVERIFIED.** Nothing in either repo
   confirms `RTCRtpScriptTransform` or `createEncodedStreams` in the installed WebView2 Evergreen
   runtime (Chromium-based, expected present, unproven). Also unverified: module workers inside
   the Tauri custom-protocol origin. Sub-slice 6.0 is a runtime probe gate; `isE2EESupported()`
   exists precisely for this. **Probe list additions (audit):** the real
   `BaseKeyProvider → worker` setKey path with the exact HKDF-material import parameters
   (§4.2), and mid-call `Room.setE2EEEnabled(true/false)` toggling on an E2EE-constructed Room
   (§3.4 mode transitions depend on it).
2. **[BLOCKER for 6.7] Android System WebView support — UNVERIFIED.** Same APIs, plus worker/WASM
   loading through the Capacitor asset server, across field WebView versions. Probed in 6.7a
   before any Android build work. Also: the stale `E2eePlugin.kt:517` "remote webview" comment
   vs the bundled-`dist` config — confirm the production APK origin while probing.
3. **Remote-webview-trust risk — RESOLVED AS WORK (amendment A2; all three audits converged
   here).** Carried risk #1 (desktop loads server-delivered JS from `app.sloga.gg` with
   `csp: null`) previously had no recorded resolution, and media E2EE puts live frame keys (not
   just displayed plaintext) next to server-delivered JS — a hostile/refreshed webview could
   both exfiltrate every call's keys AND fake the green lock (the indicator is only as
   trustworthy as the code owning `setE2EEEnabled`). Resolution: **bundle-frontend +
   restrictive-CSP is budgeted as sub-slice 6.2b and is a HARD precondition of 6.3** (the
   sub-slice landing key egress) — not a 6.6-gate item, not a "decide before" checkpoint. The
   "recorded operator acceptance" escape hatch is removed for this surface; re-opening it is a
   USER decision that must happen before 6.1 starts, never under 6.3 schedule pressure (the
   architecture audit's predicted failure mode).
4. **Multi-device same-user in one call.** v1 enforces one device per user per call, enforced at
   the **DS** (§1.5). The audits strengthened the case for device-qualified LiveKit identities
   (token change in `voice_client.rs`): with user-scoped identities the SFU kicks the first
   device's media session before any MLS-level refusal can happen, and the injectivity of the
   identity→(user,device) mapping rests on the DS rule alone. Small server change; decide by
   6.1 — **recommendation: adopt device-qualified identities in 6.1** and keep the one-device
   rule as v1 policy on top.
5. **Roster scale cap for v1 — USER-DECIDED 2026-07-09 (amendment A3).** User intent:
   "unlimited voice; cap 30 once a webcam turns on; may change later." Encoded as two
   constants because MLS control-plane cost is roster-driven, not media-driven:
   `MAX_E2EE_CALL_MEMBERS = 100` (Welcome envelope-budget ceiling; 6.4 churn measurements
   validate and may lower it) and `MAX_VIDEO_PARTICIPANTS = 30` (product gate, two-sided,
   trivially changeable). At the E2EE cap the CALL STAYS E2EE and the overflow joiner is
   refused media-key admission (loud "call full for E2EE") — the earlier
   overflow-to-plaintext-with-confirm proposal is rejected as a one-account downgrade attack
   (§3.4, T-20). The two audits that flagged Q5 disagreed in emphasis (crypto: get the user
   OK + honest scope claim; architecture: never downgrade on overflow) — both folded. Raising
   the E2EE cap past ~100 (Welcome-size budget, commit fan-out cost, mailbox pressure) stays
   a named Deferred item with measurement first; the video gate is a config one-liner.
6. **OpenMLS maturity/version.** Pre-1.0; storage-trait and provider APIs have churned. Pin exact
   versions; carry `rand`/`zeroize`/`getrandom` unification friction (scout-flagged, unverified
   against actual current openmls) into 6.2's first task. If the storage trait can't participate
   in an ambient SQLite transaction cleanly, fall back to snapshot-pickle-per-commit
   (serialize whole group state, one sealed row write per epoch) — decide in 6.2.
7. **LiveKit pin.** Client is `^2.13.0` (installed 2.15.13) — the subclass-BaseKeyProvider
   approach relies on the protected `onSetEncryptionKey` signature; pin livekit-client exactly in
   package.json for the slice, and record the deployed livekit-server version (nothing pins it —
   scout UNVERIFIED item; SFU passthrough of encrypted frames is LiveKit-documented, not verified
   in-repo).
8. **`VITE_RNNOISE_WORKLET_CDN_URL` production value unknown** — if production still hits
   jsdelivr, that's a standing no-CDN-policy violation worth fixing in passing (not slice-6 scope;
   flag to operator).

### 7.2 The webview-worker key boundary (the documented invariant-6 exception)

- **What crosses:** per-sender, per-epoch derived 32-byte frame-key MATERIAL (LiveKit's worker
  HKDFs it into the effective **AES-128-GCM** frame key — §1.5; "AES-256" in earlier drafts was
  wrong), from native → `e2ee_call_frame_keys` IPC → JS `MlsKeyProvider` → LiveKit E2EE worker.
  Nothing else.
- **Why it must:** frame encryption happens in the webview's media pipeline
  (RTCRtpScriptTransform worker); LiveKit's KeyProvider is JS-side. This is the one place media
  E2EE cannot match the DM courier model (PLAN:1437-1443, acknowledged there). **Structural
  consequence (amendment A1):** because encryption executes outside native, native can never
  attest it — hence invariant 11's dual gating and the 6.2b bundling precondition.
- **Blast radius bound (worded precisely — audit fix):** compromise of the webview/worker leaks
  *current-call frame keys* — media of the ongoing call — but NOT identity keys, MLS signature
  keys, epoch/exporter secrets, or any text-E2EE material. Keys rotate every epoch (heartbeat-
  bounded on stable rosters, §1.4), but the 2.15.13 worker retains prior ParticipantKeyHandler
  key sets until the call ends (no destruction API) — so worker compromise exposes the WHOLE
  current call's keys, not just the current epoch; all of it dies with the call (worker
  terminated at call end, §4.2).
- **Controls (the recovery-window precedent, BACKUP:647-655, is the pattern for narrow, tested,
  documented exceptions):** keys memory-only in JS, never persisted/logged; worker code is
  bundled first-party (no CDN); command in the release-locked capability allowlist; the T-09
  scrub test; provider/worker hygiene + worker termination at call end (§4.2); and the 6.2b
  bundle+CSP hard precondition (§7.1 Q3, amendment A2) because server-delivered JS sitting next
  to frame keys is the widened exposure. Android relaxes its no-keys-over-the-JS-bridge
  invariant identically and cites this section.

### 7.3 Other risks

- **R-1 Epoch churn under heavy join/leave:** commit storms in busy voice channels, AND (audit
  fix) **every rotation costs each receiver a media gap** proportional to commit-propagation
  latency (mailbox → native tx → IPC → worker) — under churn this is continuous stutter.
  Mitigations: DS arbitration serializes, staggered admitter timers reduce races, the leave
  grace window absorbs reconnect blips, the Add-side sender grace period (§1.5) hides most of
  the gap, roster cap (Q5). 6.4 measures BOTH commit rate and per-rotation receive-gap with an
  explicit churn-rate acceptance threshold (fail the gate if a realistic join/leave rate makes
  calls unusable). KeyPackage consumption under races uses the corrected accounting (one claim
  per RACING admitter per race — §1.4), with the claim rate limit per (claimer, target).
- **R-2 Mailbox pressure:** every epoch fans a commit to every member device through `e2ee_queue`
  (depth cap 512/device), and Welcomes are up to 256 KiB raw (§2.2.4 — budget re-derived in
  6.1). At cap-24 rosters this is fine; revisit with Q5.
- **R-3 Dependency friction:** openmls rand/zeroize/uniffi interplay; the Android .so size growth.
- **R-4 Desync UX:** rejoin-fresh recovery is visible-to-user by design; if telemetry shows it
  frequent, external commit gets re-evaluated (with its metadata cost, §1.6).
- **R-5 Schema/backup coupling:** the v5 migration + EXPORT_SCHEMA_VERSION bump must land in the
  same sub-slice (6.2) or the workspace doesn't build — sequencing constraint, not optional.

---

## 8. Sub-slice breakdown, sessions, and gates

Evidence for the estimate: slice 5 (comparable protocol surface, one repo fewer) ran ~6 sessions
+ audit; slice 6 spans four surfaces (server DS, native OpenMLS, client media plumbing, UX) plus
a platform unknown (6.0) — hence the target of ~8 desktop + 2 Android sessions, at the top of the
tasked 7–9 range because OpenMLS integration is a new-dependency risk (Q6) and the media plane
has a hardware/runtime verification loop no text slice had.

Reviewer roles: **media-e2ee-reviewer** (protocol/architecture: MLS usage, epoch lifecycle, DS
design), **e2ee-crypto-reviewer** (crypto invariants: derivation, binding, storage, boundaries),
**frontend-code-reviewer** (client/media: Room wiring, worker, UX states). Every sub-slice ends
with its named gate; adversarial tests are definition-of-done, not optional.

| Sub-slice | Content | Sessions | Gate (reviewers) |
|---|---|---|---|
| **6.0 Platform spike** | Runtime probes: WebView2 `isE2EESupported()`/ScriptTransform/module-worker in Tauri origin (Q1); real `BaseKeyProvider→worker` setKey path with HKDF-material import params (§4.2); mid-call `setE2EEEnabled` toggling (§3.4); Vite `?worker` bundling of the LiveKit e2ee worker + PWA precache; throwaway static-key two-desktop E2EE call to prove the media plane end-to-end. GO/NO-GO output; if NO-GO the whole slice re-plans. | 1 | frontend-code-reviewer (probe evidence review; go/no-go) |
| **6.1 Server DS + KeyPackage directory** | Feature flag; `mls_*` models BOTH drivers (channel-scoped create arbitration §1.2, one-device CAS §1.5, successor flow §1.4); routes (publish/claim/create/join_intent/commits/gap-fetch) incl. the call-co-presence eligibility class (§2.3); per-content_type envelope caps + queue-budget re-derivation (§2.2.4); `can_publish_data` regrant fix (§0.4); bonfire events; crond sweeps; commit-race + claim-atomicity + create-race + stranger-co-member tests both DBs. | 2 | media-e2ee-reviewer + e2ee-crypto-reviewer (DS arbitration, metadata set §5.6) |
| **6.2 Native OpenMLS core** | openmls pinning + provider (FIRST task: confirm last-resort init-key retention is possible without corrupting single-use accounting, §2.2.1); storage provider over sealed SQLite; schema v5 + backup exclusion ruling (§5.5, EXPORT_SCHEMA_VERSION bump); credential binding + canonical contexts + the §1.3 leaf-mutation rule (client AND server mirror parity); group lifecycle engine (create/admit/process/leave/heartbeat/poisoned-epoch successor); exporter→frame-key derivation; crash-safe commit tx; unit + first adversarial tests. | 2 | e2ee-crypto-reviewer (primary) + media-e2ee-reviewer |
| **6.2b Desktop shell bundling + CSP** | Bundle the frontend into the installer (replace `app.sloga.gg` remote webview); restrictive CSP replacing `csp: null`; updater/asset-pipeline implications; capability allowlist re-lock to the bundled origin. **HARD precondition of 6.3 (amendment A2)** — previously unbudgeted despite being on 6.3's critical path. | 1.5 | e2ee-crypto-reviewer + frontend-code-reviewer (trust-surface sign-off) |
| **6.3 Desktop IPC + client key plumbing** | `e2ee_call_*` commands (3 sync points + capability); `MlsKeyProvider` (HKDF-material import, hygiene rules §4.2); always-E2EE-capable Room construction at state.tsx:243 (§4.1); worker bundling productionized; keys-changed event loop; processor-ordering doc + T-10. **Gate refuses to open unless 6.2b is merged.** | 1.5 | e2ee-crypto-reviewer (boundary §7.2) + frontend-code-reviewer |
| **6.4 Epoch lifecycle + churn** | Join/leave/rejoin/desync end-to-end; DS race convergence with real clients; rotation + keyIndex mapping under churn incl. transition-window behavior and loud-state debounce (§1.5/§4.4); heartbeat; roster reconciliation + leave grace window; gap refetch; re-upgrade with hysteresis; measure R-1/R-2 against the churn acceptance threshold. | 1.5 | media-e2ee-reviewer |
| **6.5 Downgrade UX + verification** | Loud downgrade banner + pause-publish + native confirm; mode-transition state machine (§3.4); dual-gated whole-call chip + per-participant locks + MLS-roster-driven roster panel + pre-join mode (corrected surfaces, §4.4); safety-number roster entry point; sticky/re-upgrade UX; cap-refusal UX (A3). | 1 | frontend-code-reviewer + media-e2ee-reviewer |
| **6.6 Hostile-DS harness + FINAL desktop audit** | `hostile_ds.rs` full matrix (T-01..T-21 desktop-scoped); SFU capture check; scrub sweep; **final audit: media-plane key handling + control-plane distribution/rotation + downgrade paths + the §7.2 boundary** (the PLAN:1475-1478 gate). | 1 | FULL PANEL: media-e2ee-reviewer + e2ee-crypto-reviewer (+ frontend-code-reviewer sign-off) |
| **6.7a Android probe + uniffi surface** | Q2 runtime probes on-device; uniffi `mls_call_*` exports; bindings regen; Kotlin plugin allowlist + keys-changed listener; native downgrade dialog. | 1 | e2ee-crypto-reviewer (boundary parity) |
| **6.7b Android integration + APK** | End-to-end on-device call vs desktop peer; downgrade + rotation on device; APK build; Android-scoped adversarial re-runs; Android gate. | 1 | media-e2ee-reviewer + e2ee-crypto-reviewer |

**Total: ~10.5 desktop-track sessions + 2 Android** (was ~8.5; +1.5 for 6.2b — previously
unbudgeted critical-path work — and +0.5 for the enlarged 6.4 churn/transition scope).
Operator-owed after 6.7b: manual multi-device E2E (the slice-4 pattern), livekit-server version
recording (Q7).

Dependencies: 6.0 → 6.3/6.4 (platform go); 6.1 ∥ 6.2 (can interleave; share canonical-mirror
work); 6.2b ∥ 6.1/6.2 (independent of MLS work; must merge before 6.3); 6.3 needs 6.1+6.2+6.2b;
6.4 needs 6.3; 6.5 needs 6.4; 6.6 gates desktop; 6.7 after 6.6.

## 9. Deferred (explicitly NOT in slice 6)

External-commit join / server-held GroupInfo; roster cap raise beyond 24 + large-channel scale
work (Q5); topic-per-group bonfire fan-out; multi-device-per-user calls (Q4); mid-call MLS
signature-key rotation (requires fresh binding + re-verification flow — §1.3 leaf-mutation
rule); E2EE for any server-side media feature (recording/mixing/transcode); web-client media
E2EE; data-channel encryption (LiveKit 2.15.13 has `dcEncryptionEnabled`; the channel is
treated as an untrusted injection surface until then, §0.4); per-sender frame authenticity
(signed frames — §5.6 accepts group-level authenticity, as DAVE does); rnnoise CDN cleanup
(Q8, operator).

---

## Plan-audit log (2026-07-09)

Adversarial plan-stage audit: three reviewers (crypto, frontend, architecture), all verdicts
SHIP_WITH_FIXES. Every finding folded; none rejected. Where audits disagreed (Q5 overflow
behavior; the weight given to LiveKit's encryption-status signal), the resolution is recorded in
the cited section.

**Crypto audit**

- [HIGH] Native green lock vouches for encryption it cannot observe — FOLDED §0.2 A1, §4.4, invariant 11 (dual-gated green: native control plane AND observed media-plane status; Q3 bundling made hard precondition of 6.3).
- [HIGH] Reusable last-resort KeyPackage degrades Welcome FS / conflicts with OpenMLS single-use semantics — FOLDED §2.2(1), §5.6 (FS tradeoff analyzed, short expiry, storage carve-out, zeroize, OpenMLS-feasibility as 6.2 first task with fail-loud fallback).
- [MEDIUM] MLS Update proposals unaddressed (PCS overstated or re-binding unspecified) — FOLDED §1.3 leaf-mutation rule (self-update HPKE-only allowed, signature/credential change invalid in v1) + §1.4 heartbeat (periodic PCS).
- [MEDIUM] Downgrade trigger lacks trusted participant enumeration — FOLDED §3.4 (union of SFU list and MLS roster; SFU-only participant = non-enrolled → loud downgrade) + §1.4 reconciliation.
- [MEDIUM] One-device-per-call enforced by unspecified mechanism; race collides at KeyProvider — FOLDED §1.5 (DS-side CAS refusal), §2.3, T-16; Q4 recommendation strengthened.
- [MEDIUM] Joiner never checks Welcome group context vs join intent — FOLDED §1.4 join step 4 + T-15.
- [LOW] KeyProvider import type / AES-256 wording wrong — FOLDED §4.2 (HKDF material), §1.5 full-chain, §7.2 (AES-128-GCM).
- [LOW] keyIndex wrap safety rests solely on desync rule; epoch-in-HKDF redundancy unstated — FOLDED §1.5 (lag telemetry warn-at-8; belt-and-suspenders note).
- [LOW] Roster cap 24 contradicts "server voice channels" goal; needs user OK — FOLDED §0.3 (scope softened to small channels), §7.1 Q5 (user OK still required on value). **RESOLVED 2026-07-09: user decided MAX_E2EE_CALL_MEMBERS=100 (envelope ceiling) + MAX_VIDEO_PARTICIPANTS=30 product gate (A3).**

**Frontend audit**

- [HIGH] AES-GCM CryptoKey import would throw in 2.15.13 worker; keys must be HKDF material — FOLDED §4.2, §1.5, §7.2, 6.0 probe list (same fix as crypto LOW above; frontend audit verified the failure mode is total media loss).
- [HIGH] Auto-re-upgrade impossible: setE2EEEnabled throws if e2ee omitted at Room construction — FOLDED §4.1 / A4 (always construct E2EE-capable on supported shells; mode via setE2EEEnabled; no-e2ee Room only for unsupported shells).
- [MEDIUM] Rotation-skew semantics under failureTolerance:0 unspecified (blackout, one-shot error, flap) — FOLDED §1.5 (honest failureTolerance semantics, local-setKey-last restatement, transition window), §4.4 (latch + classify + debounce), T-06 ext, T-21, R-1 threshold.
- [MEDIUM] §0.4 data-channel claim contradicted by codebase (regrant at voice/mod.rs:537; kick misses publishData) — FOLDED §0.4 (claim corrected; regrant fix in 6.1; client no-consume rule; encryption Deferred).
- [MEDIUM] Welcome 256 KiB vs "reuse e2ee_queue unchanged" (64 KiB cap) inconsistent — FOLDED §2.2(4) (per-content_type caps, encoded-vs-raw accounting, budget re-derivation, bonfire frame check; "unchanged" removed).
- [MEDIUM] LiveKit duplicate-identity kick + transient reconnects force roster/presence apart; refusal point unspecified — FOLDED §1.5 (DS enforcement point + SFU-kick residue), §1.4 (leave grace window, liveness re-assertion), Q4.
- [LOW] Worker key residue: handlers never destroyed, keyInfoMap grows, stale replay on reconnect — FOLDED §4.2 hygiene rules + §7.2 blast-radius wording + worker termination at call end.
- [LOW] Invariant 7 falsifiable on timing (lagging senders on old epoch) — FOLDED invariant 7 restated per-sender post-commit, T-03 restated, §5.6 window documented.
- [LOW] Citation nits (ChannelHeader.tsx nonexistent; AES-256; vite line) — FOLDED §4.4 (Header.tsx / VoiceChannelPreview.tsx / VoiceCallCardPreview.tsx), §4.1 (vite.config.ts:43-48), AES wording global.

**Architecture audit**

- [CRITICAL] Split-brain group creation: racing creators mint different group_ids so the 409 arbitration never fires — FOLDED §1.2 / A5 (channel-scoped partial unique index WHERE closed_at IS NULL, 409 carries open group_id), §2.2(2), §2.6 both-driver race test, hostile-DS partition variant in T-16.
- [HIGH] Eligibility gates exclude stranger co-members of server voice channels — FOLDED §2.3 (call-co-presence / shared-channel-access eligibility class for claim AND delivery, blocked-pair semantics), §2.6 tests.
- [HIGH] Poisoned epoch slot deadlocks the group with no recovery — FOLDED §1.4 poisoned-epoch recovery (successor group via `supersedes`, channel-scoped atomic close+create), invariant 10 note, T-17.
- [HIGH] No media-key transition window; failureTolerance:0 mischaracterized — FOLDED §1.5 / A6 (Add grace period, Remove immediate, honest silent-drop description), §4.4 debounce, T-21 (same family as frontend rotation-skew finding; resolved with one mechanism).
- [HIGH] Post-leave secrecy unenforceable vs hostile DS (withheld leave signals; invisible MLS-only members) — FOLDED §1.4 roster reconciliation (MLS roster is UI truth, ghost-leaf flag + timeout Remove), invariant 7 hostile-operator scoping, §5.6 accepted limitation, T-18.
- [MEDIUM] Whole-call downgrade/re-upgrade has no convergence protocol — FOLDED §3.4 mode-transition state machine (epoch-anchored ctl-style announcement, enumerated mixed-window semantics, group kept warm, hysteresis), 6.0 probe for mid-call toggling.
- [MEDIUM] Roster cap becomes a one-account downgrade trigger — FOLDED §3.4 / A3 / Q5 (call stays E2EE, overflow joiner refused; overflow-to-plaintext rejected), T-20. Resolves the disagreement with the crypto audit's Q5 finding in the stricter direction.
- [MEDIUM] Admitter liveness: single-heuristic actor, no failover; KeyPackage race cost understated — FOLDED §1.4 (staggered timers k·Δ, joiner retry protocol with T/N, per-(claimer,target) claim rate limit, corrected per-racing-admitter accounting), R-1.
- [MEDIUM] Q3 bundling on 6.3's critical path with zero sessions budgeted — FOLDED §8 sub-slice 6.2b (1.5 sessions) + §7.1 Q3 / A2 (hard precondition; acceptance escape hatch removed unless user re-opens before 6.1).
- [MEDIUM] Data-channel "locked off" claim half-false — FOLDED §0.4 (duplicate of frontend MEDIUM; single fix).
- [LOW] No time-based re-key on stable rosters — FOLDED §1.4 epoch heartbeat (10 min self-update, staggered failover), §5.6, §7.2.
- [LOW] Intra-group frame forgery possible and unstated — FOLDED §5.6 accepted limitation (group-level authenticity; UI authenticates roster, not frames); signed frames Deferred (§9).
- [LOW] Client-asserted fan-out lists + last-resort reuse: quiet trust edges — FOLDED §2.3 commits-route trust note + T-19 (availability-only under-fan-out); last-resort FS documented §2.2(1)/§5.6.
