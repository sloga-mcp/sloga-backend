# Server Calendar & Events — Design / Implementation Plan

Status: **DRAFT rev 2 — audited** by `calendar-events-reviewer` (verdict: SHIP WITH FIXES).
Findings **C1, H1–H6, M1–M6, L1–L3** are incorporated below and marked inline as `[fixes Cx/Hx]`.
This document is the contract the reviewer audits against. Deviations during implementation are findings.

## 1. Goal

Turn the current client-only calendar into a real, server-backed events feature:

- Events scheduled for a specific **date + time** (with end time), server-scoped.
- **Recurring** events (daily / weekly / monthly, bounded).
- **Invitations**: an organizer invites server members; each invitee can **accept** or **decline**.
- **Cancel-after-accept**: an attendee who accepted can later withdraw ("can't attend anymore").
- Real-time updates + notifications (invite received, event changed/cancelled, reminders).

## 2. Current state (what we are replacing)

Today the calendar is a **client-only hack** (frontend repo):

- `packages/client/src/lib/serverEvents.ts` — an event is a normal chat message whose content
  is `"[ACUTEST_EVENT]:" + JSON.stringify({...})`, posted to a channel literally named `events`.
- `packages/client/src/interface/ServerEvents.tsx` — fetches the last 100 messages of that
  channel, parses the tagged ones, renders a month grid.

**Why it can't grow into this feature:** nowhere to store per-user RSVP state, no authorization
(anyone who can post can fabricate any event/author), no way to notify invitees, no consistency
(100-message window silently drops older events), no server truth for attendee counts. This plan
adds authoritative server state and retires the message-tag path.

## 3. Architecture fit

Standard feature shape for this workspace:

| Layer | Location | What we add |
|-------|----------|-------------|
| DB model | `crates/core/database/src/models/calendar_events/` | `CalendarEvent`, `EventRsvp` + ops for **both** drivers |
| Wire model | `crates/core/models/src/v0/calendar_events.rs` | `DataCreateEvent`, `Event`, `EventRsvp`, … |
| REST | server-scoped routes in `routes/servers/`; event-scoped in new `routes/events/` | see §5 (**M6:** mount prefix split) |
| Permissions | `crates/core/permissions/` | authz via existing `ChannelPermission` (§6) — **no new bit v1** |
| Real-time | `EventV1` (`events/client.rs`) + bonfire fan-out | event/invite/rsvp push (§8) |
| Timed | `crates/daemons/crond` | reminders + retention |
| Push | `crates/daemons/pushd` | invite / cancel / reminder notifications |
| Client | `frontend/packages/stoat.js` + `packages/client/src/interface/ServerEvents.tsx` | bindings + new UI |

**[fixes M4]** Gated behind a new `config.features.events_enabled` flag, appended via a **single
conditional** to the route mount — *not* by duplicating the whole mount block the way
`webhooks_enabled` does in `routes/mod.rs` (duplication risks unmounting a route → the
"unregistered route silently drops POST bodies" gotcha).

## 4. Data model (Rust, `auto_derived!`)

### 4.1 `CalendarEvent`  (collection: `calendar_events`)

```
id: String            // Ulid, "_id"
server: String        // owning server (indexed)
channel: Option<String> // optional associated channel (e.g. voice channel to meet in)
creator: String
title: String         // validated 1..=100
description: Option<String> // 0..=2000
location: Option<String>    // 0..=200
start: i64            // ms epoch; UTC instant of the FIRST occurrence
end: Option<i64>      // ms epoch; must be > start when present
duration_ms: i64      // derived (end-start, or 0); applied to every recurring occurrence
series_end: i64       // [fixes H4] denormalized UTC upper bound of the whole series (see §4.2)
all_day: bool         // [fixes M3] date-only semantics, see below
timezone: String      // IANA tz id; validated against chrono-tz zone set [fixes L2]
recurrence: Option<RecurrenceRule>
color: Option<String>
cancelled: bool       // soft-cancel of the whole series (terminal); rows retained [fixes H6]
source_message_id: Option<String> // [fixes M5] set by migration import; dedup key
created_at: i64
edited_at: Option<i64>
```

**[fixes M3] `all_day`**: anchored to the event `timezone` as a wall-clock **date** (stored as the
UTC instant of local midnight for sorting) and **rendered date-only**; recurrence of an all-day
event steps by whole calendar days with **no** DST offset applied, so it never shifts a day for a
viewer in another timezone.

### 4.2 `RecurrenceRule` (embedded, bounded subset of RFC-5545)

```
freq: Frequency          // Daily | Weekly | Monthly
interval: u16            // every N (1..=52), validated
by_weekday: Vec<Weekday> // Weekly only; empty ⇒ same weekday as `start`
end: RecurrenceEnd       // Count(u16, 1..=MAX_OCCURRENCES) | Until(i64) — REQUIRED, no infinite series
exceptions: Vec<i64>     // occurrence-start UTC instants that are skipped (single-occurrence cancel)
```

- Hard cap `MAX_OCCURRENCES` (e.g. 730) enforced at validation and expansion.
- **[fixes H4] `series_end`** is computed on create and on every time-affecting edit:
  non-recurring ⇒ `end.unwrap_or(start)`; recurring ⇒ **last actual occurrence start + duration**
  (for both `Until` and `Count` terminators — tighter than the earlier "`t + duration_ms`" sketch,
  since the last occurrence may fall well before an `Until` instant). It exists so the window query
  (§5) and reminder scan (§9) can find a series whose **first** occurrence precedes the query window.
- **Expansion is on-read within a bounded window**, never materialized as rows. Occurrences are
  computed in `timezone` wall-clock then converted to UTC (`chrono-tz`): a weekly 18:00 stays 18:00
  local across DST.
- **[fixes H2] DST edge policy** (no `.unwrap()` on `LocalResult`): a **nonexistent** wall-clock time
  (spring-forward gap) shifts **forward** by the gap offset; an **ambiguous** time (fall-back) takes
  the **earliest** instant.
- **[fixes M2] Monthly on day 29–31**: **clamp to the last day** of shorter months (Jan 31 → Feb 28/29).
- **[fixes M1] Exceptions & edits**: any time-affecting edit (`start`/`timezone`/`freq`/`interval`/
  `by_weekday`) **clears `exceptions`** (documented behavior — old instants no longer map to
  occurrences). Reminders (§9) and RSVP rendering **skip** excepted occurrences.

### 4.3 `EventRsvp`  (collection: `event_rsvps`)

Composite key mirrors `server_members` (`MemberCompositeKey`):

```
id: EventRsvpKey { event: String, user: String }  // "_id"
status: RsvpStatus       // Pending | Going | NotGoing
invited_by: String
had_accepted: bool       // [fixes L1] set true on EVERY transition into Going; never reset.
                         //   Lets organizer distinguish "declined" from "accepted then cancelled".
created_at: i64
responded_at: Option<i64>
```

Per-**series** RSVP in v1 (no `occurrence` field). **[fixes M1]** documented consequence: cancelling
a single occurrence does not change attendee state for that occurrence (attendees stay `Going` to the
series); it only suppresses that occurrence's reminders. Per-occurrence RSVP is a future extension.

### 4.4 Dual-driver requirement

Every new `Database` method (`insert_event`, `fetch_event`, `fetch_events_in_window`, `update_event`,
`soft_cancel_event`, `insert_rsvp_if_absent`, `fetch_rsvp`, `fetch_rsvps_for_event`, `update_rsvp`,
`delete_rsvp`, …) implemented for **both** `Reference` and `MongoDb` via `query!`. A `todo!()`/missing
method on either driver is a blocking defect.

**[fixes H4] Indexes** (Mongo): `calendar_events` on `(server, series_end)` **and** `(server, start)`;
`event_rsvps` on `id.event` and `id.user`.

## 5. REST routes

Acting user is **always** the `User` auth guard, never the body. All bodies `validator::Validate`d;
all mutations authorized server-side (§6); all rate-limited.

**[fixes M6 — as built in slice B] Static-first paths under one `/events` mount.** To keep the
feature self-contained (one module, one feature-gated mount) AND collision-free, every route uses a
static first segment: server-scoped under `/events/server/<server>`, event-scoped under
`/events/event/<event>`. This supersedes the earlier "split across `/servers` and `/events`" wording —
it resolves the same Rocket mount-prefix hazard (no dynamic-first segment can collide with a literal)
and is what stoat.js + the frontend (slice E) bind against. Concrete paths:
`POST|GET /events/server/<server>`; `GET|PATCH|DELETE /events/event/<event>`;
`POST /events/event/<event>/invites`; `DELETE /events/event/<event>/invites/<user>`;
`PUT /events/event/<event>/rsvp`; `GET /events/event/<event>/attendees?limit=&before=`.

Original (superseded) sketch:

| Method / path | Purpose | AuthZ |
|---|---|---|
| `POST /servers/<server>/events` | create event (+ optional recurrence) | §6 create |
| `GET /servers/<server>/events?from=&to=` | list events overlapping window | member + **per-event ViewChannel** |
| `GET /events/<event>` | event + caller RSVP + attendee summary | can-view |
| `PATCH /events/<event>` | edit event (recomputes `series_end`, may clear exceptions) | creator OR manage |
| `DELETE /events/<event>` | **soft-cancel** event (notify, then `cancelled=true`) | creator OR manage |
| `POST /events/<event>/invites` | invite `{ users:[id] }` — **insert-if-absent** [fixes H5] | creator OR manage |
| `DELETE /events/<event>/invites/<user>` | uninvite (delete RSVP row) | creator OR manage |
| `PUT /events/<event>/rsvp` | set caller RSVP `{ status }` — target ∈ {Going,NotGoing} [fixes L1] | invited member |
| `GET /events/<event>/attendees?limit=&before=` | paginated RSVP list [fixes L3] | can-view |

- **[fixes H4] Window query**: `from`/`to` required, span clamped (≤ 1 year). Selects events where
  `series_end ≥ from AND start ≤ to`, then expands occurrences in memory and keeps those overlapping
  `[from,to]`. This returns recurring series anchored **before** the window. **[as built, slice F
  0.2-A]** Cancelled series are **included** (clients render them struck-through with a `Cancelled`
  pill; they age out as the window passes `series_end`) — the reminder scan uses a separate op that
  keeps excluding them. There is no purge/hard-delete route yet (known roadmap item).
- **[slice F] Invites accept roles**: `POST /events/event/<event>/invites` takes
  `{users?: [id] (≤100), roles?: [id] (≤25)}` (at least one non-empty); each role's **current**
  holders are expanded server-side and fed through the same per-user gates (membership incl.
  pending-deletion filter, ViewChannel for channel-scoped events, insert-if-absent). Unknown role ⇒
  `NotFound` before any insert. Returns `{invited, skipped}` (200) instead of 204.
- **[slice F] Legacy import**: `POST /events/server/<server>/import {channel}` — see §11.
- **[fixes C1] Per-event view filter**: `GET /servers/<server>/events` must filter each event whose
  `channel` the caller cannot `ViewChannel` — server membership alone is insufficient.
- **[fixes L3]** GET list caps returned events + expanded occurrences; heavy daily×1yr case is bounded.
- Every route registered in the router **and** `#[openapi]`-annotated.

## 6. Authorization

Reuse existing permissions — **no new bitfield v1**. `DatabasePermissionQuery` +
`calculate_*_permissions(...).throw_if_lacking_channel_permission(...)`, as `ban_create.rs`.

- **[fixes H1] Create**: there is no "events channel" anymore, so the create anchor is defined as:
  **any server member may create** an event (rate-limited); if `channel=Some`, additionally require
  `ViewChannel` on that channel (evaluated with `calculate_channel_permissions`, not the server-default
  baseline). Deployments wanting stricter behavior flip open-decision §12.3 to manager-only. (The old
  "SendMessage parity" framing was dropped — it silently diverged from per-channel reality.)
- **Edit / delete / invite / uninvite**: event `creator` **OR** `ChannelPermission::ManageChannel`.
  **[as built, slice F]** the creator branch additionally requires **live membership**
  (`fetch_member`): a banned/departed creator with a still-valid session must not edit, cancel, or
  fan out invite pushes. (Imported events' creators — original message authors — rely on this gate.)
- **RSVP**: caller must be a server member **and** already have an RSVP row for the event (was invited).
  Non-invited users cannot RSVP. IDOR-safe (acting user from session).
- **View**: server member with `ViewChannel` on the event's channel (or server-wide if `channel=None`).

## 7. RSVP state machine (server-enforced)

States: `Pending` (invited, no answer) · `Going` (accepted) · `NotGoing` (declined or withdrawn).

```
Pending  --accept-->  Going       (had_accepted=true)
Pending  --decline--> NotGoing
Going    --cancel-->  NotGoing    // "cancel after accepting"
NotGoing --accept-->  Going       (had_accepted stays true)
Going    --(re)accept--> Going    // idempotent; count unchanged
```

- **[fixes L1]** `Pending` is **not** a client-settable target (only the invite flow creates it).
- **[fixes H5] Invite is insert-if-absent**: re-inviting a user who already has any RSVP row is a
  no-op for that user — it never resets `Going`→`Pending` (which would corrupt the attendee count).
- Illegal/absent transitions rejected server-side (RSVP with no invite → `Forbidden`; RSVP to a
  `cancelled` event → error). `cancelled` is terminal.
- **Attendee counts are computed authoritatively** by aggregating `event_rsvps` by status — never
  client-supplied, never unguarded increments (no race under concurrent RSVPs).

## 8. Real-time (bonfire `EventV1`) — **[fixes C1]**

New `#[serde(tag="type")]` variants, published on a topic that matches who may see the event:

- If `channel = Some`: publish on the **channel topic** (`.p(channel_id)`) — bonfire only subscribes a
  client to channel topics it can `ViewChannel`, so this is the enforcement point.
- If `channel = None`: publish on the **server topic** (all members).

**As built (slice C)** — four full-payload variants (a full object is safe to rebroadcast because the
topic audience is already authorized to see it; the client treats an update as a full replace):
- `CalendarEventCreate { event }` and `CalendarEventUpdate { event }` — to the event audience.
  **Soft-cancel is a `CalendarEventUpdate` with `event.cancelled = true`** (no separate Delete variant;
  edits can only widen scope today, so no eviction/removal signal is needed — if a future slice lets an
  edit *narrow* scope or hard-deletes, a removal event to the now-excluded audience becomes required).
- `CalendarEventInvite { event }` — to the invited user's private topic, only for genuinely-new invitees.
- `CalendarEventRsvp { rsvp }` — to the event audience (same audience the attendees endpoint serves).

Clients reconcile local cache from these. **Adversarial test (done, slice C):**
`channel_scoped_event_hidden_from_non_viewer` — a member without `ViewChannel` gets an empty REST
listing and is skipped on invite. Note (carried to slice D): an attendee who *later* loses ViewChannel
is unsubscribed from the channel topic, so the WS cancel/update never reaches them — pushd must be the
authoritative cancel/reminder delivery for `Going` rows, keyed by user id independent of channel perms.

## 9. Notifications (pushd) & timed jobs (crond)

- **On invite** (`pushd`): push each genuinely-new invitee (insert-if-absent → true) — "You're
  invited to *<title>*". Best-effort; the invitee already passed the `ViewChannel` invite gate.
- **[fixes H6] On cancel**: because cancel is a *soft*-cancel the RSVP rows are **retained**, so the
  `Going` notify-list is intact regardless of ordering. **As built (slice D):** the DELETE sets
  `cancelled=true` first, then gathers `Going` and enqueues the cancel push — notifying only after the
  write commits avoids announcing a cancellation that failed to persist (H6's "don't destroy the
  notify-list first" is satisfied by soft-cancel row retention, not by pre-commit ordering). The route
  is **idempotent**: a re-issued DELETE on an already-cancelled event is a no-op, so a retry/double
  DELETE never re-fans-out the cancel (there is no per-send marker on the cancel path).
- **[fixes H3] Reminders** (`crond`): a periodic (60s) job scans non-cancelled events with an
  occurrence near now (`start ≤ now+lead AND series_end ≥ now−grace`), expands those occurrences
  (skipping `exceptions`), and for each `Going` RSVP sends one push per reminder trigger.
  - **As built (slice D):** the idempotency marker key is the **quad** `(event, user, occurrence,
    offset)` in the `event_reminders_sent` collection — the `occurrence` component keeps a recurring
    series from collapsing to one reminder (the actual H3 requirement: **not** a per-RSVP flag), and
    the `offset` component lets the two default leads (**30 min before** + **at-start**, `offset ∈
    {30m, 0}`) each fire exactly once. **Mark-then-send**: the marker is written first and only a
    newly-written marker sends, so a crond re-run/reconnect never double-fires (at-most-once: a marked
    reminder whose AMQP publish fails is not retried).
  - A trigger (`occurrence − offset`) fires only when it lands in the half-open window `(now−grace,
    now]` (`grace = 5 min`), so a trigger missed by more than the grace window is dropped rather than
    fired late — bounding a notification flood after crond downtime.
  - **All-day events** remind only at-start (the local-midnight instant); the 30-min lead is
    suppressed so it does not fire at 23:30 the prior night.
  - Markers are swept once their occurrence is a day past (`RETENTION_MS ≫ grace`, so a swept marker
    can never resurrect a due trigger).
- **Authoritative for `Going` rows, by user id** (the §8 "carried to slice D" note): reminder and
  cancel delivery is keyed on the `event_rsvps` `Going` rows by **user id**, *not* re-gated on
  `ViewChannel` — an attendee who accepted and later lost `ViewChannel` is off the channel WS topic but
  is still notified. A user who has fully **left / been banned** from the server is filtered out
  (live `fetch_member` check). **[as built, slice F]** RSVP rows ARE now cascaded on member removal
  (best-effort in `Member::remove`), plus on server deletion and account deletion; the live
  `fetch_member` filter remains as defense-in-depth for a missed best-effort cascade.
- **Transport:** a dedicated `PayloadKind::CalendarEvent` (recipient user id + `event_id` + `server_id`
  + `title` + `kind ∈ {invited,cancelled,reminder}` + optional `occurrence_start`), on its own
  `notifications.ingest.calendar_event` queue/consumer, with structured data on all three outbound
  platforms (FCM data, APN custom payload, VAPID JSON) for client deep-linking. Delivery is
  offline-agnostic (no online filtering — reminders/cancels must reach disconnected devices).
- Notification payloads carry only what the recipient may see — ids + the event title the recipient
  already saw when invited/RSVPing, never channel contents.

## 10. Frontend (`frontend/`)

- **stoat.js**: typed bindings/collections for events + RSVP; a live `Event` object updated by the WS
  events. Where the generated client lacks a route, use **raw fetch** (avoids the empty-`{}`-body bug —
  see [[stoat-api-body-drop]]).
- **`ServerEvents.tsx`** rewrite (keep the month-grid look, drop message-tag parsing):
  - Create form gains **recurrence** controls (freq / interval / weekdays / ends-after|on) + an
    **invite picker** (server-member multi-select).
  - Event detail: attendee list grouped by status + caller RSVP control — **Accept / Decline**, and
    when `Going` a **Cancel (can't attend)** action → `NotGoing`.
  - Optimistic RSVP reconciled against the authoritative response/WS; failures surface (no
    permanently-wrong "you're going").
  - All strings via lingui `Trans`/`t`; works across web / Tauri / Capacitor.
- Remove `serverEvents.ts` tag encode/parse once migration (§11) lands. **[done, slice F]** —
  the file is deleted; the invite pickers also match server **role** names (client-side name match
  against the cached role map; expansion is server-side, §5), and the manager-only "Import legacy
  events" panel drives §11.

## 11. Migration / back-compat — **[fixes M5]** **[as built, slice F]**

One-time, manager-triggered **optional** import, re-runnable safely (dedup):

- **Route**: `POST /events/server/<server>/import { channel }` — the manager picks the source
  channel explicitly (the client's panel defaults the select to the channel literally named
  "events"; with no such channel an explicit choice is required).
- **Gates**: `events_enabled`; not a bot; member; server-wide `ManageChannel`; the channel must
  belong to the server **and be viewable by the caller** (no private-channel exfiltration into
  server-visible events). Lands in the `events_create` ratelimit bucket.
- **Scan**: paginates newest→oldest, 100/page, capped at `MAX_IMPORT_SCAN = 2000` messages
  (`truncated` reported when hit). Messages starting `"[ACUTEST_EVENT]:"` parse as the legacy JSON
  `{title, start, end?, desc?, voiceId?, color?}`.
- **Mapping**: rows go through the **same model validation as create** (title/desc/color lengths,
  end > start — invalid rows rejected and counted, never stored). `start` parses as RFC3339 (the
  legacy writer used `Date.toISOString()`); a bare `YYYY-MM-DD` imports as **all-day** at UTC
  midnight. `timezone = "UTC"` (imports are non-recurring). `creator` = the tagged **message's
  author** (server truth — the payload's `authorId` is ignored, so content cannot spoof a creator;
  §6's live-membership manage gate bounds a departed author's authority). `voiceId` is kept as the
  event channel only if it exists, belongs to the server, and the **importer** can view it — else
  it degrades to `None` (a dead auxiliary channel must not block the import).
- **Dedup**: `source_message_id` recorded per import; one up-front `fetch_imported_source_ids`
  set + within-run tracking means a re-run (or duplicate tag) imports nothing twice.
- **Response**: `{imported, skipped_duplicates, skipped_invalid, scanned, truncated}`. Each
  imported event fans out `CalendarEventCreate` (bounded by the scan cap).
- **Prod indexes**: existing deployments get the calendar collections + 6 indexes via
  **migration revision 54** (`admin_migrations/ops/mongodb/scripts.rs`, idempotent;
  `LATEST_REVISION = 55`) — init.rs only covers fresh DBs; delta migrates on boot.

The legacy tag path is retired: `packages/client/src/lib/serverEvents.ts` is **deleted** (nothing
referenced it after the slice-E rewrite). Old tagged messages remain as harmless chat history.

## 12. Open decisions (need your sign-off)

1. **RSVP granularity for recurring events** — *Recommend:* per **series** in v1. Alt: per-occurrence now.
2. **Distinct "Cancelled" vs "Declined"** — *Recommend:* collapse to `NotGoing`, keep `had_accepted`.
3. **Who can create events** — *Recommend:* any server member (rate-limited); if `channel` set, needs
   `ViewChannel`. Alt: managers-only, or a dedicated `ManageEvents` permission bit (bigger scope).
4. **Recurrence scope** — *Recommend:* bounded subset (Daily/Weekly/Monthly + interval + weekdays +
   count/until). Alt: full RFC-5545 RRULE.
5. **Reminder lead time** — *Recommend:* default 30 min + at-start; configurable later.
6. **Tentative/"Maybe" RSVP** — *Recommend:* out of scope v1.
7. **Event scope** — *Recommend:* server-only v1. Alt: also group/DM (interacts with the [[e2ee]]
   boundary — encrypted conversations must not carry plaintext event payloads; server-only side-steps it).
8. **Migration** — *Recommend:* optional manager-triggered import; stop writing tags.

## 13. Testing (adversarial — required)

- Non-invited RSVP rejected; IDOR (A cannot set B's RSVP).
- Cancel-after-accept transitions + count correctness; **re-invite of a Going user is a no-op** (H5);
  double-accept idempotent.
- Illegal transitions (RSVP to cancelled/deleted event) rejected; `Pending` not client-settable.
- **Recurrence**: keeps wall-clock across DST; **DST gap/ambiguous policy** (H2); `count`/`until` bound
  the series; window clamp; **monthly day-31 clamp** (M2); all-day renders same date cross-tz (M3);
  exceptions cleared on time-affecting edit (M1).
- **[fixes H4]** window query returns a recurring series anchored before the window.
- **[fixes C1]** member without `ViewChannel` receives neither the WS event nor the REST listing.
- **[fixes H6]** cancel notifies `Going` attendees (notify-list intact through soft-cancel).
- **[fixes H3]** reminder fires exactly once per occurrence for a recurring series; excepted
  occurrences don't remind; crond re-run doesn't double-fire.
- Permission checks on every mutating route; rate limits; **migration import** validates + dedups (M5).
- Both DB drivers exercised (`TEST_DB=REFERENCE` and `MONGODB`).

## 14. Implementation slices (each gets a reviewer audit)

- **A — Data layer**: `CalendarEvent` + `EventRsvp` models (incl. `series_end`), recurrence expansion
  util (DST/monthly-clamp/exception-aware), both drivers, unit tests. No routes.
- **B — REST**: routes (CRUD + invite insert-if-absent + rsvp state machine), authz (incl. per-event
  ViewChannel), validation, OpenAPI, mount-prefix split, route tests.
- **C — Real-time**: `EventV1` variants + **channel-topic-aware** bonfire fan-out + client cache.
- **D — Notifications**: pushd invite/cancel + crond per-occurrence reminders (idempotent). *Done +
  audited + fixed 2026-07-09 — see audit trail.*
- **E — Frontend**: stoat.js bindings + `ServerEvents.tsx` rewrite (recurrence, invite picker, RSVP
  accept/decline/cancel, attendee list).
- **F — Recurrence polish + migration**: edge hardening, validated/dedup import, remove tag path;
  final audit. *Implemented 2026-07-09 (plan: `calendar-events-slice-f-plan.md`, rev 2 audited) —
  see audit trail; final A–F audit pending.*

Each slice is implemented; the calendar/events reviewer audits it (with `frontend-code-reviewer`
as a lens on E, `e2ee-crypto-reviewer` if §12.7 expands events into encrypted conversations).

---

### Audit trail
- **FINAL AUDIT (A–F) — `calendar-events-reviewer`, 2026-07-10: PASS.** Full §13 walkthrough
  (every adversarial item has a live enforcement point + named test, four LOW gaps noted below);
  cross-slice seams traced clean (cancelled-in-list × WS × cache; cascades cover every
  RSVP-creation path — import creates zero RSVP rows; import fan-out respects C1 via
  `event_topic`; banned-creator gate consistent with the create anchor and the RSVP
  live-recheck); authorization chain verified on all 10 routes (fail-closed, nothing trusts the
  body); state-machine/notification invariants unregressed; docs-vs-code claims spot-checked.
  Applied from the audit: stale "not cascaded" comments/doc reconciled (crond + §9), §4.2
  `series_end` formula tightened to as-built. **Non-blocking follow-ups (roadmap):**
  LOW-1 error-code oracle (cancelled check before authz on 3 routes; 403/404 split in
  `authorize_view` — fold cancelled into post-authz and map view failures to NotFound);
  LOW-2 cancel double-notify TOCTOU under concurrent DELETEs (make the cancel a conditional
  update, fan out on modified_count==1); LOW-3 four small missing tests (window clamp, DST
  fall-back branch, route-level cancel-after-accept/double-accept, uninvite authz);
  INFO items: `had_accepted` visible to all viewers (social nit), unsorted MAX_EVENTS
  truncation, no uninvite WS fan-out, creator-sans-ViewChannel keeps manage (as designed).
  Residual-risk register accepted (purge route, per-occurrence RSVP, exceptions UI,
  interval-only Until caveat, untested one-line guards, kick-cascade via automated tests,
  Reference `Relative` FIXME, O(holders) role-invite cost). **Feature A–F complete.**
- **Slice F (polish + migration) — implemented 2026-07-09; plan audited rev 2 (both reviewers,
  SHIP WITH FIXES, findings folded pre-implementation); diff audit + final A–F audit pending.**
  Backend: migration revision 54 (collections + 6 indexes, idempotent, LATEST_REVISION 55);
  cancelled-in-list (0.2-A, both drivers); bounded occurrence expansion
  (`series_occurrence_starts_bounded`, non-decreasing invariant incl. date-line caveat; callers
  `occurrences_in_window`/`reminders_due_for_event`; `compute_series_end`/validate stay unbounded);
  lifecycle hardening — RSVP cascade on `Member::remove` (best-effort), **live-membership gate on
  the creator manage branch**, server-delete calendar cascade (`delete_calendar_for_server`),
  account-delete RSVP cascade (`delete_rsvps_for_user`); legacy import route (§11 as-built,
  Reference `fetch_messages` `Absolute` path completed so import pagination tests are honest);
  role invites (`{users?, roles?}` + `InviteResult`, server-side expansion, per-user gates kept —
  the loop's `fetch_member` re-check is the only pending-deletion filter). Frontend: stoat.js
  `invite(users, roles?)` + `importLegacy` + result types; ServerEvents edit form (keyed remount,
  prefill-string dirty detection, atomic schedule group re-anchored to the editor's tz,
  `remove:[…]` for cleared optionals, cancelled-mid-edit close), role rows/chips in both invite
  pickers, import panel (explicit channel choice, in-flight disable, counts + truncation note),
  `lib/serverEvents.ts` deleted. **Diff audit: both reviewers SHIP WITH FIXES, all applied**
  (end-less-import edit no longer fabricates an end; import pagination/truncation +
  pending-deletion tests added; migration test hardened per-revision; server-delete cascade
  before the broadcast; Plural counts) — see the slice-F plan's audit trail. Tests: 22 calendar
  DB (4 new: bounded-equivalence, Pacific/Apia hostile anchor, lifecycle ops + dedup set,
  Mongo-gated migration idempotency) + 15 events route tests (8 new: role invite
  expansion/dedup/unknown-role/kick, per-server cascade, banned-creator manage rejection,
  cancelled-in-list, import end-to-end incl. spoof/dedup/all-day, import authz incl.
  unviewable-source-channel, import pagination/truncation, Mongo-gated pending-deletion
  invite skip) green REFERENCE + MONGODB (WSL); no new failures in the full delta suite
  (pre-existing account-route flakes verified identical on baseline).
- **Slice D (notifications) — implemented + audited + fixed, 2026-07-09.** pushd invite/cancel pushes +
  crond per-occurrence reminders. Dedicated `PayloadKind::CalendarEvent` (+ `calendar_event` queue,
  inbound consumer, FCM/APN/VAPID outbound arms); `event_reminders_sent` marker model + 3 ops (both
  drivers) + indexes; pure `reminders_due_for_event` (quad-key idempotency, grace window, all-day
  at-start-only). Reviewer verdict **SHIP WITH FIXES**; all applied: cancel is now idempotent
  (already-cancelled guard — stops retried/double-DELETE re-notification, the HIGH) and notifies
  *after* the commit; APN carries structured `event_id`/`server_id`/`kind`/`occurrence_start` (parity
  with FCM/VAPID); reminder + cancel delivery filters `Going` rows by a live `fetch_member` check
  (ex-member/banned attendees stop receiving pushes); doc §9 reconciled to as-built (quad key +
  grace + notify-after-commit + all-day). Deferred (LOW): windowed occurrence expansion in the
  reminder scan (currently full-series expansion each tick, bounded by `MAX_OCCURRENCES`) and RSVP
  cascade on member removal — slice F. 18 calendar-events DB unit tests (6 new: reminder
  per-occurrence/exception/cancelled/stale/all-day, marker insert-if-absent + prune, window scan) +
  7 delta events route tests (1 new: `cancel_retains_going_rows_for_notify`, also asserting
  double-cancel idempotency) green; clippy clean; pushd/crond build+clippy verified under WSL.
  Uncommitted.
- **Slice C (real-time WS) — implemented + audited + fixed, 2026-07-09.** 4 `EventV1` variants,
  emitted from delta routes on the channel topic (C1 boundary) / server topic / invitee private topic;
  no bonfire change needed. Reviewer verdict SHIP WITH FIXES; all applied (C1 integration test added:
  non-viewer gets empty list + invite skipped; doc §8 reconciled to as-built shapes). 6 route tests
  green, clippy clean. Uncommitted.
- **Slice B (REST API) — implemented + audited + fixed, 2026-07-09.** 9 routes under `/events`
  (static-first), feature-gated; v0 DTOs; authz (per-event ViewChannel C1, manage, live-membership
  RSVP recheck); soft-cancel; insert-if-absent invites. Reviewer verdict SHIP WITH FIXES; all applied
  (rsvp live-view recheck, hermetic `events_enabled` test flag, checked window span, attendee
  pagination + list cap, dedicated ratelimit buckets, invite ViewChannel gate, +3 adversarial tests).
  5 route tests green, clippy clean. Uncommitted.
- **Slice A (data layer) — implemented + audited + fixed, 2026-07-09.** `calendar_events` models,
  recurrence engine, both DB drivers, indexes. Reviewer verdict SHIP WITH FIXES; all findings applied
  (HIGH edit-recompute helper `CalendarEvent::edit`/`replace_event`; validate-before-compute;
  `Until`-truncation guard; driver parity on missing rows; atomic RSVP upsert; Mongo indexes;
  DST shift-by-offset). 12 unit tests green. Uncommitted. Slices B–F not started.
- **rev 1 → rev 2**: incorporated calendar-events-reviewer findings. Must-fixes resolved in-doc: C1
  (channel-topic/per-event view filter), H1 (create anchor), H2 (DST policy), H3 (per-occurrence
  reminder idempotency), H4 (`series_end` + window query + index), H5 (invite insert-if-absent), H6
  (soft-cancel + notify-before-cascade). Mediums M1–M6 and lows L1–L3 folded in. Verdict on rev 1 was
  **SHIP WITH FIXES**; rev 2 targets those fixes for a re-review before/at slice A.
