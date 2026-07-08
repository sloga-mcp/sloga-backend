# E2EE Slice 5 — Group DMs, verification, web states, disable polish (design)

Status: rev 3 — GATE PASSED (rev 1 REVISE → rev 2 APPROVE WITH CHANGES,
2026-07-08); rev 3 folds in the six re-review changes, tagged [G2: n].
Rev-2 changes are tagged [G: n] with the original gate finding they answer.
Parent: `docs/e2ee-design.md`, `docs/e2ee-implementation-plan.md` (slice 5).
Builds on slices 1–4 (all gate-passed). The slice ENDS with the FINAL FULL
AUDIT (plan §Slice 5 gate); the three carried risks are dispositioned in §8.

Security invariants 1–6 from the implementation plan apply unchanged. The
design rule for everything below: **every new decision input that a lying
server could influence must be either (a) derived from local pinned truth,
(b) carried inside authenticated ciphertext, or (c) explicitly documented
as a loud, availability-only, or honest-plaintext surface.** [G: rule
tightened — (b) added; the roster now lives there.]

## 1. Scope

1. Group DM E2EE via **pairwise fan-out** (no group ratchet / sender keys —
   explicitly deferred, unchanged).
2. **Safety-number verification screen** — upgrades TOFU pins to
   user-verified bindings against key substitution on known peers.
3. **Web lock-screen states** — the web client self-excludes visibly
   instead of silently degrading.
4. **Disable / turn-off flow polish** — separate "stop using E2EE" from
   "destroy local data"; sticky per-conversation state preserved
   (invariant 3).
5. **Protocol-version floor** — verify + test the reject-below-floor rule
   end-to-end (plan item 4, [A: crypto-8]).

Out of scope: sender keys/Megolm, sealed sender, padding, iOS, key backup
(slice 5.5, after the final audit).

## 2. Group DM E2EE — model

### 2.1 Conversation identity and the wire discriminator [G: 1]

- A conversation is keyed by a **conversation id**: for 1:1 DMs it remains
  the peer user id (no store migration of meaning, no history rekeying);
  for group DMs it is the **group channel ULID**.
- **The dm/group discriminator is a WIRE property, authenticated under
  Olm — not merely a store column.** `wire::InnerPayload` gains a
  mandatory-for-groups field:

  ```
  InnerPayload { v, seq, conv, kind?: "dm" | "group", ctl?: Control,
                 content, att }
  ```

  Rules (receiver side, all inside the native layer):
  - `kind` absent ⇒ the message is a 1:1 DM. Two cases, by authenticated
    sender [G2: 3] (note: a dm sender writes `conv` = ITS peer, per the
    slice-3 wire semantics — so on the receive side):
    - sender is a PEER device ⇒ `conv` MUST equal the RECIPIENT's own user
      id (what every honest slice-3/4 sender writes); the message files
      under the authenticated sender, as always;
    - sender is a pinned OWN device (own-device fan-out copy) ⇒ `conv`
      may name any dm conversation (it is the conversation the sending
      own device recorded).
    In neither case can it be filed into a group conversation. This is
    exactly the slice-3/4 traffic shape — full backward compatibility,
    and legacy ciphertext is structurally unable to land in a group
    transcript.
  - `kind: "group"` ⇒ `conv` MUST name a PINNED group conversation; if
    the local store has it pinned as `dm` (or vice-versa), the message is
    rejected as a loud `Undecryptable`-class marker
    (`conversation_kind_mismatch`), acked and dropped.
  - `kind: "group"` for a conversation with NO pinned group (e.g.
    ordinary group traffic arriving before the `group_enable` that would
    create the pin, or after a wipe): loud marker
    (`group_not_established`), acked, dropped — NEVER auto-create the
    group pin and never buffer into a provisional transcript. Only a
    valid `group_enable` ctl creates a group conversation. [G2: 4]
  - A group message is accepted into the transcript only if the
    authenticated sender (Olm session → pinned device → user) is in the
    **locally pinned roster** for `conv`. Otherwise: loud
    `sender_not_in_group` marker, acked, dropped — the relay cannot
    inject a stranger's messages into a group transcript.
- Store schema v3:
  - `conversations(conversation_id PK, kind, encrypted_since,
    downgraded_at)` (renamed from `peer_user_id`; existing rows migrate
    with `kind='dm'`). Lookups always specify kind.
  - New `group_members(conversation_id, user_id, status
    ['active'|'removed'|'announced'], added_at, removed_at)` — the pinned
    roster (see 2.3).
  - `messages.peer_user_id` → `conversation_id` (rename);
    `messages.sender_user_id` added (group attribution; backfilled for DM
    rows from direction + conversation id).
  - `attachments.conversation` unchanged in meaning.

### 2.2 Control messages (authenticated group state) [G: 2, 3]

Group lifecycle state travels INSIDE the pairwise ciphertext as a `ctl`
payload — never as server metadata:

```
Control =
  | { type: "group_enable",  roster: [user_id, ...] }   // full roster
  | { type: "roster_add",    user_id }
  | { type: "group_downgrade" }
```

- `group_enable` is sent by the member who turns encryption on (§2.5) and
  carries **the enabler's asserted roster**. Receivers pin THAT roster —
  the server's channel state is a display/diff input only and never seeds
  the pin.
- `roster_add` is sent by the member who performs an add (their client
  knows it initiated the add). Existing members' devices extend their pin
  only on receiving it from a **pinned, active member device**. The added
  member receives a fresh `group_enable` (full roster) from the adder —
  their TOFU baseline is an authenticated message from the adder, the
  same first-contact trust shape as a 1:1.
  **Implementation note (core, slice-5 build):** the reference client
  sends a single full-roster `group_enable` for an add instead of
  `roster_add` + a separate enable to the new member — one atomic fan-out
  extends existing pins (loud `member_added` diff) AND establishes the
  new member, with no split-delivery window between the two ctls.
  `roster_add` remains a valid inbound ctl.
- `group_downgrade` — see §5.
- `ctl` messages are ordinary messages in every mechanical respect: same
  encrypt path (atomicity, §2.4), same per-session sequence, same replay
  protection, same local-history row (rendered as a system-style marker).
- **The encrypt audience only ever EXPANDS via (a) an authenticated
  `group_enable`/`roster_add` from a pinned member device, or (b) an
  explicit local user action (§2.3 fallback). The server alone — channel
  state, events, member lists — can never grow the set of devices a
  message is encrypted to.** This is the group analog of the 1:1
  no-server-input send_mode property. Roster SHRINKS may additionally
  follow server state (loud marker) because wrongly shrinking is
  availability-only, in the safe direction (§2.3).

### 2.3 Roster changes (loud, locally pinned)

On every send and membership event the webview passes current channel
recipients; the native layer diffs against the pinned roster:

- **Server-state member appears who is not pinned**: loud marker + banner
  ("X was added but is not yet part of the encrypted conversation — they
  cannot read new messages"). The member becomes part of the encrypt
  audience ONLY via a `roster_add` from the adder (§2.2) or the explicit
  local action "Include X" (blocking confirm; covers adds performed from
  web/old clients that cannot send `roster_add`). Until then the pin is
  `announced` — displayed, never encrypted to. Sends CONTINUE to the
  pinned roster (an unpinned announced member does not wedge the group;
  the banner is the honesty mechanism). [G: 2 — no silent expansion; G: 8
  — the checklist gap closes because the pin, not the server list, is the
  audience.]
- **Pinned member added to audience** (`roster_add` received or local
  Include): marker `member_added`; bundle fetched, signature-verified,
  pinned; if they have no valid keys the group send mode becomes
  **Blocked** with the explicit choice: downgrade the group (explicit
  blocking confirm, §5 semantics) or remove/wait. Never silent plaintext
  (invariant 1).
- **Member removed** (server state OR their own departure): loud
  `member_removed` marker; devices dropped from the fan-out from the next
  message on. Pairwise fan-out gives post-removal secrecy for free.
  Availability note: a lying server "removing" a member only stops NEW
  messages reaching them — visible in the member list, safe direction.
- **Phantom-member honesty boundary (narrowed) [G: 2]**: after rev 2 the
  server cannot silently place anyone in the encrypted audience. What
  remains server-origin is the *displayed* channel member list and the
  *availability* of members (dropping `roster_add` envelopes, hiding
  members from display). A malicious server colluding with a malicious
  MEMBER still learns plaintext — members are inside the trust boundary
  by definition. State this in user-facing copy.

### 2.4 Send mode + encrypt path

`send_mode_group(conversation_id)` (1:1 `send_mode(peer)` keeps its exact
contract; the existing hostile-server harness is untouched):

- **Sticky Encrypt is local-only truth**: once `encrypted_since` is set,
  the verdict is Encrypt (or Blocked) regardless of any webview/server
  input — supplied member lists can never flip the verdict to Plaintext.
- **Blocked** when: any audience member device is `identity_changed`
  (accept flow identical to 1:1), or an audience member has zero usable
  devices, or the fan-out would exceed the envelope cap (below).
- **Plaintext → Encrypt happens only via §2.5's explicit enable.** No
  opportunistic auto-upgrade for groups in v1 (flappy under the
  all-members condition and turns server-influenced state into an upgrade
  trigger).

`encrypt_group(conversation_id, content, attachment_ids, bundles)`:

- Targets = every ACTIVE pinned device of every **audience** roster
  member (pinned roster with status beyond `announced`) + own other
  devices. Any audience member with zero usable devices → hard error
  naming them — a group message goes to ALL of the audience or NOBODY; no
  partial-audience sends; aborts happen before any ratchet moves (same
  crash-safety envelope as 1:1).
- The client NEVER emits an envelope to a user absent from the pinned
  roster — client-side subset rule, independent of any server authz
  looseness. [G: 4a]
- Per-session `seq` unchanged (gap detection per sender-device as in 1:1).
- Attachments: unchanged mechanics; blob recipient list = the device
  target set; refs ride inside each pairwise ciphertext.

**Fan-out cap [G: 5]**: the hard rule is on DEVICES, not members: if the
total envelope count for one message exceeds
`MAX_ENVELOPES_PER_REQUEST = 128`, the send is a HARD, loud error — never
chunked (chunking would reintroduce the partial-delivery window the
all-or-nobody rule exists to prevent), never a silent device drop.
`MAX_E2EE_GROUP_MEMBERS = 24` is the product-facing cap enforced at
enable/add time (24 members × a few devices each fits comfortably), but
the envelope-count check at encrypt time is the invariant; a
device-inflation attack by a member (publishing dozens of devices) wedges
the group loudly at the cap instead of splitting delivery — and is
attributable in the blocked-send explanation ("X has 40 devices").

### 2.5 Enable flow (group)

"Encrypt this group" (group settings / lock menu), visible when the local
device is enabled+published and the group is within the member cap. Flow:

1. Fetch every displayed member's device list + bundles → verify + pin.
2. Show the checklist: each member ✓/✗, **with the full name list and
   count the user is asserting** — the confirm copy says "you are
   encrypting to exactly these N people; check this list against the
   member list you expect" [G: 8 — the roster assertion is the security
   decision and it is the ENABLER's, made visible].
3. On all-✓ + blocking confirm: single store transaction sets
   `encrypted_since`, pins the roster as the audience, records the
   `encryption_enabled` marker; then the `group_enable` control message
   (carrying that roster) is sent through the normal atomic encrypt path.
4. Receivers: decrypt `group_enable` from an authenticated (TOFU-pinned)
   sender → pin conversation as `kind=group`, sticky `encrypted_since`,
   roster = the ASSERTED roster [G: 2], with three acceptance conditions
   [G2: 2]:
   - the asserted roster MUST contain both the sender AND the receiver
     (a `group_enable` excluding either is rejected loudly — a sender
     cannot assert a group it claims not to be in, and a receiver never
     pins a group it is excluded from);
   - the §2.3 diff against displayed channel state runs AT PIN TIME, not
     just on later sends/events — displayed-but-excluded members produce
     `announced` banners immediately, so a co-member asserting a roster
     that omits genuine members is visible the moment the pin lands;
   - the enable renders as a PROMINENT attributed event ("X enabled
     encryption for this group with these N members: …"), not a subtle
     marker row — the receiver sees who asserted what.
   Server channel state is then only a diff/display input (§2.3). A
   receiver that never gets `group_enable` simply keeps treating the
   group as plaintext — safe direction, visible (no lock).

### 2.6 Server changes (group scope) [G: 4]

Rev 2 drops the `channel_id` request parameter entirely — it was both an
authz-loosening server-trusted input and a NEW metadata channel (linking
sends to a specific group). Instead:

- The e2ee route authz predicate becomes: target/recipient user is
  DM-eligible (`UserPermission::SendMessage`, as today) **OR shares at
  least one Group channel with the caller** (server-side query over the
  caller's groups; the client names nothing). Applied to
  `POST /e2ee/messages` recipients, `GET /e2ee/keys/{user}`, and
  `GET /e2ee/devices/{user}`.
- Metadata: the server learns NOTHING new per-request — no channel id is
  sent or stored; envelopes remain conversation-blind (`conv` inside
  ciphertext). The server can already enumerate shared groups from its
  own data; running the check reveals nothing it did not have. The
  accepted-metadata set is unchanged. [G: 4b resolved by construction.]
- Blocked pairs inside a group: envelope DELIVERY between co-members is
  allowed even when blocked (plaintext groups already deliver blocked
  members' messages — E2EE must not be weaker or stronger here), but
  bundle/device FETCH between blocked pairs stays refused. A blocked
  member without an established session therefore surfaces as Blocked to
  the sender — and the blocked-send explanation MUST name the block as
  the cause ("you have blocked X / X has blocked you"), never "X has no
  keys" [G: 10]. Resolution: removal or unblock.
- Ratelimits: existing buckets; the shared-group query is bounded by the
  caller's group count.
- Tests: co-member non-friends can send/fetch; non-member/departed
  refused; blocked-pair fetch refused while co-member delivery works;
  envelope cap; both drivers.

## 3. Safety-number verification screen

### 3.1 What is verified

Per (peer **user**, peer **device**) — identities are per-device, so the
honest object to verify is the device identity. One safety number per
peer device; unverified ones flagged. (No per-user roll-up number — it
would churn on every device add and train users to ignore changes.)

**Explicit non-goal [G: 7]: safety-number verification does NOT mitigate
group roster manipulation.** It defends against key substitution on a
known peer (the server swapping keys under a user id). Who is IN a group
is governed by §2.2/§2.3's authenticated-roster machinery; a genuinely
malicious member verifies fine and still reads plaintext — members are
inside the trust boundary. The screen's copy must not imply otherwise.

### 3.2 Derivation (native only) [G: 6 — extraction fully specified]

Inputs, per side x: the PINNED keys (never a fresh server fetch — a
server swapping bundles cannot change the displayed number):

```
t_x = utf8(user_id_x) || 0x00 || utf8(device_id_x) || 0x00
      || ed25519_pub_x (raw 32 bytes) || 0x00
      || curve25519_pub_x (raw 32 bytes)

input = utf8("acutest-e2ee-safety-number:v1") || 0x00
        || min(t_a, t_b) || 0x00 || max(t_a, t_b)     // bytewise ordering

h = SHA-512(input)
```

Digit extraction (Signal-style, platform-deterministic):

```
for i in 0..6:
    chunk = h[5*i .. 5*i+5]                  // 5 bytes, big-endian
    group_i = (u64::from_be_bytes(chunk) ) % 100000
    render as zero-padded 5 digits
safety number = 6 groups of 5 digits (30 digits total)
```

- Symmetric by construction; identical across desktop and Android because
  every byte of the layout (UTF-8 ids, raw 32-byte keys, BE chunking) is
  pinned above — a cross-platform test vector is part of the DoD.
- Entropy: 6 × log2(10^5) ≈ 99.7 bits; per-group modulo bias from 2^40 →
  10^5 is < 2^-23, negligible.
- Exposed as `e2ee_safety_number(peer_user_id, device_id)` IPC returning
  ONLY the digit string + verified flag + first-seen; key bytes never
  cross IPC (invariant 6).
- QR compare deferred (manual digit comparison only in v1).

### 3.3 Verified state + its teeth

- `e2ee_mark_verified(peer_user_id, device_id)` sets `user_verified` on
  the pin (new column, above `binding_verified`); timeline marker.
- **Teeth**: an identity change on a `user_verified` device is a heavier
  event than the standard `identity_changed`: the accept dialog states
  verification is being discarded, requires re-typing the peer's name,
  and clears `user_verified`. Send mode stays Blocked until accepted
  (existing machinery).
- Screen: conversation header lock → "Verify security numbers"; shows
  per-device number, verified badge, first-seen, honest scope copy (§3.1
  non-goal included). Native-only; web shows the §4 state.

## 4. Web lock-screen states [G: 9 — no encryption claims from flags]

The web client has no native layer; today it silently falls through to
plaintext. New behavior is a UI-honesty layer that makes NO encryption
claims — the flags driving it are server-controlled hints (invariant 2):

- **State W1 — capability panel**: for a DM where BOTH own profile and
  the peer advertise `e2ee_enabled`, the composer is replaced by a
  capability-oriented panel: **"This conversation may be end-to-end
  encrypted. To read and reply, open Acutest on your desktop or mobile
  app."** — "may", never "is": a never-pinned pair would in fact be
  plaintext on native, and the web client cannot know. The panel is a
  routing aid, not a lock claim; it deliberately does not render a lock
  glyph styled like the native encrypted indicator.
- **State W2 — history hint**: same conditions + zero server-visible
  history: the panel adds "message history for this conversation lives on
  your other devices."
- **Residual (documented)**: a lying server can hide the panel and let
  web send plaintext — the native recipient renders it as what it is
  (plaintext, no shield); no encrypted-looking forgery results. It can
  also SHOW the panel spuriously (deny web composing) — availability
  -only, bounded by the user's own opt-in, and the honest copy means
  nothing false is asserted. Both directions are honesty/availability
  surfaces; the hard boundary remains the server-side web-token refusal
  on all `/e2ee` routes (slice 3).
- Groups: no reliable web-side signal exists (no flags on channels) —
  groups get no W1 in v1; documented gap, revisit if a safe signal
  appears.
- Web Security & Privacy settings: passive card — "Manage end-to-end
  encryption from a desktop or mobile app."

## 5. Disable / turn-off flow polish

Three clearly separated actions:

1. **Stop advertising ("Pause E2EE for new conversations")**: PATCH
   `e2ee_enabled=false` only. Keys stay published, sessions keep working,
   every sticky conversation keeps encrypting (invariant 3). Reversible,
   no confirm friction.
2. **Per-conversation downgrade** [G: 3 — fully specified]:
   - Entry: conversation lock menu → explicit warning ("new messages will
     be readable by the server") → NATIVE OS blocking confirm (the
     webview can only request, wipe-dialog parity).
   - Mechanics: the downgrade is a `group_downgrade` / dm-downgrade `ctl`
     message sent through the NORMAL atomic encrypt path — all-or-nobody
     fan-out to every audience device, same as any message [G: 3a]. In
     the SAME local store transaction that releases the envelopes:
     `encryption_disabled` marker row + `encrypted_since` cleared +
     `downgraded_at` set (crash-safe ordering preserved).
   - Delivery visibility [G: 3b]: `POST /e2ee/messages` returns per-device
     receipts (slice-1 machinery). Any device that could not be enqueued
     surfaces a persistent loud state on the initiator: "the downgrade
     notice may not have reached all of X's devices — they may still show
     this conversation as encrypted." The server dropping a QUEUED
     downgrade envelope later is the existing TTL-loss surface: the
     victim device sees the per-session sequence gap indicator on the
     next message ("messages were lost"), and any subsequent plaintext
     arriving in a still-sticky conversation is rendered with an explicit
     "unencrypted message in an encrypted conversation" warning row
     (fail-honest; this rendering rule is part of this slice).
   - Ordering [G: 3c]: a receiver applies the downgrade when it DECRYPTS
     the ctl message (per-session sequence makes it totally ordered
     against the same sender-device's messages). Encrypted messages
     already in flight from OTHER devices/senders still decrypt and
     display as encrypted history afterwards — decryption never depends
     on sticky state; only the SEND verdict does. Replay of the downgrade
     ctl is rejected by Olm replay protection like any envelope (explicit
     test).
   - **Receiver-side local confirm [G2: 1]**: receiving a downgrade ctl
     records the marker and shows the unlocked composer state, but it
     does NOT by itself open the local plaintext send path. The FIRST
     subsequent send from each receiving device requires a one-time
     explicit blocking confirm ("X turned off encryption for this
     conversation — send unencrypted?"); native state machine:
     `encrypted_since` transitions to `peer_downgraded` (send verdict =
     Blocked-with-downgrade-prompt), and only the local confirm clears it
     to plaintext. The plaintext direction is therefore gated by a LOCAL
     user action on every device (invariant 1's blocking confirmation is
     the local user's, never only the remote party's), and a
     malicious/compromised peer can at worst cause a prompt, not a silent
     server-readable send. Applies identically to `group_downgrade` on
     every member device.
   - **Crash/POST-failure window [G2: 5]**: the committing transaction
     also persists a `pending_downgrade` flag, cleared only when the
     `POST /e2ee/messages` receipts are processed. On restart (or total
     POST failure) with the flag set, the client re-sends the downgrade
     ctl (idempotent for receivers — already-downgraded state absorbs a
     duplicate loudly-but-harmlessly) or, if re-send keeps failing,
     surfaces the persistent "the downgrade notice may not have reached
     everyone" state. No silent window where the initiator is downgraded
     and peers have no path to learning it.
   - **Group downgrade authority [G2: 6]**: ANY audience member device
     can send `group_downgrade` for the whole group — deliberate symmetry
     with any-member-can-enable, and consistent with members being inside
     the trust boundary. It is loud (attributed event, like enable) and
     every OTHER member device gets the first-send confirm above; no
     member's device drops to plaintext sends without its own user's
     confirmation.
   - Split-brain bound: sticky state is per-device by construction; the
     defined convergence mechanism is the ctl message; devices that miss
     it FAIL SAFE (keep encrypting — confidentiality preserved) and the
     honesty gap is covered by the loud states above. There is no silent
     path from encrypted to plaintext on any device.
   - Local history is KEPT (downgrade, not wipe).
3. **Turn off & destroy (existing wipe flow)**: mechanics unchanged
   (native dialog + password/MFA-gated server device revocation); copy
   now explains the difference from 1/2 via a summary screen listing what
   dies (local history, this device's identity) and what persists
   (peers' copies, other own devices' sticky states).

Invariant-3 note: (2) is the first plaintext-direction transition since
slice 3 — explicit + native-confirmed + marker-before-clear in one
transaction + peer-side clear rides ONLY the authenticated channel; the
server cannot forge, replay, or selectively apply it beyond the
availability effects documented above.

## 6. Protocol-version floor

Already largely enforced (envelope `protocol_version`, inner `v`, bundle
`protocol_version` inside every signed payload; `UnsupportedVersion`
decrypt outcome). Slice-5 work:

- Single source of truth: `PROTOCOL_FLOOR = 1`, `PROTOCOL_CURRENT = 1` in
  e2ee-core; every accept path (bundle verify, outer payload, inner
  payload, envelope field) rejects outside `[FLOOR, CURRENT]` loudly —
  below floor AND above current (never best-effort parse a future
  format); no silent accommodation in either direction [A: crypto-8].
- The `kind`/`ctl` InnerPayload additions (§2.1/2.2) are backward-
  compatible OPTIONAL fields under `v=1` for 1:1 traffic; group traffic
  requires them semantically (absence ⇒ dm rules apply). No version bump
  needed; the discriminator rules, not the version number, prevent
  cross-filing. A future incompatible change bumps `v`.
- Known limitation [G: 11]: with FLOOR == CURRENT the multi-version
  accept-set machinery is exercised only by the v=0/v=2 reject tests; the
  first real version bump (e.g. PQ migration) must add a genuine
  two-version matrix. Noted for the final audit.

## 7. Test plan (adversarial, per slice DoD) [G: 12 — findings' cases named]

Native (e2ee-core):
- Group encrypt: all-of-audience-or-nobody (one bundle-less audience
  member aborts, no ratchet movement, no envelopes); envelope-cap
  hard-error (never chunk/drop) incl. device-inflation by one member;
  sticky group verdict immune to shrunk/grown/empty webview member input
  (hostile-server harness extension — group analog of the six 1:1 lies).
- Roster authentication: **first-decrypt roster seeding comes ONLY from
  the authenticated `group_enable` roster — a server-supplied channel
  state naming a phantom member never enters the audience and never
  receives an envelope, with the loud announced-banner marker** [G: 2];
  `roster_add` accepted only from a pinned active member device
  (stranger/removed-member/unpinned-device `roster_add` rejected loudly);
  sends continue to pinned audience while an announced member is pending.
- Wire discriminator: **1:1 ciphertext replayed with a group conversation
  id (and vice-versa) is rejected — `kind` mismatch / missing-kind rules**
  [G: 1]; sender-not-in-roster inbound → loud marker, acked, no
  transcript entry; conversation_kind_mismatch marker; kind-absent peer
  message with `conv` ≠ sender user id rejected while own-device fan-out
  copies still file correctly [G2: 3]; `kind:"group"` with no pinned
  group → `group_not_established` marker, acked, dropped, NO pin created
  [G2: 4].
- group_enable acceptance: asserted roster missing the sender OR the
  receiver → rejected loudly, no pin; pin-time diff against displayed
  channel state produces immediate `announced` banners for
  displayed-but-excluded members [G2: 2].
- Downgrade: ctl rides the atomic fan-out (partial assembly aborts all);
  **per-device receipt failure surfaces the "may not have reached
  everyone" state; a device that misses the downgrade keeps encrypting
  and later plaintext in a sticky conversation renders the explicit
  warning row** [G: 3]; replayed downgrade ctl rejected by Olm replay
  protection; marker+state single-transaction crash test; decrypt of
  in-flight encrypted traffic after downgrade still succeeds; receiving
  a downgrade ctl yields `peer_downgraded` send verdict (Blocked until
  the one-time local confirm — a peer alone can never open the local
  plaintext path) [G2: 1]; `pending_downgrade` survives crash-before-POST
  and drives re-send / the not-everyone-notified state; duplicate
  downgrade ctl absorbed harmlessly [G2: 5].
- Safety number: cross-platform test vector (fixed keys → exact 30
  digits); symmetric (a,b) == (b,a); pinned-keys-only (changing the
  server bundle does not change the number); mark-verified → identity
  change takes the heavy path and clears the flag.
- Version floor matrix (§6): v=0 below floor, v=2 above current, inner/
  outer mismatch.

Server (both drivers):
- Shared-group authz: co-member non-friends can send/fetch; non-member/
  departed-member refused; blocked-pair fetch refused while co-member
  delivery works; no channel identifier accepted or stored anywhere on
  the e2ee surface (schema assertion); caps.

Client: typecheck + reviewer-trace of the bridge changes (no frontend
harness — same caveat and treatment as slice 3).

## 8. Carried risks — disposition at the final audit

1. **Desktop remote-webview trust** (app.sloga.gg JS, csp null): slice 5
   proposes RESOLVING via the known fix direction — bundle the frontend
   into the installer + restrictive CSP — as its own work item IF the
   operator green-lights the build change; otherwise it is presented to
   the final audit for explicit acceptance with compensating controls
   listed (keys never in webview, IPC allowlist, native confirms on
   destructive actions). Decision owner: operator, at implementation
   start (build-pipeline change, not crypto).
2. **Attachment render-code duplication** (desktop `serve_attachment` vs
   Android binding): slice 5 RESOLVES it — hoist the shared
   validation/mime-whitelist/SVG-degrade into e2ee-core, both shells call
   it, both copies deleted.
3. **JVM heap-copy zeroization**: ACCEPT — inherent to the Java Keystore
   API (documented since slice 4; best-effort wipe in `finally` already
   in place). Presented to the final audit as an accepted platform
   residual.

## 9. Implementation order (1 session target, 2 max)

1. Store v3 migration + conversation-id/kind generalization (+ tests).
2. Wire `kind`/`ctl` + group send_mode/encrypt/roster pinning +
   hostile-group tests.
3. Server shared-group authz + tests.
4. Bridge + UI: group enable flow (roster assertion checklist), markers,
   announced-member banner, indicator.
5. Safety numbers (core + IPC + screen + cross-platform vector) +
   verified-state teeth.
6. Disable-flow polish (3 actions) + downgrade ctl path + the
   plaintext-in-sticky warning row.
7. Web lock states (capability copy).
8. Version-floor audit + tests; render-code dedup (risk #2).
9. Android parity for the new IPC surface (uniffi mirrors; APK rebuild
   deferred to after the final audit alongside the owed FCM/wipe operator
   items).

Then: **FINAL FULL AUDIT** (fresh reviewers, max effort) per the plan.
