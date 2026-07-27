# Calendar/Events — Slice F (Polish + Migration + Final Audit) Implementation Plan

Status: **rev 2 — audited + IMPLEMENTED 2026-07-09** (decisions 0.1 = A, 0.2 = A; operator
sign-off). Plan audit: `calendar-events-reviewer` (full-stack): SHIP WITH FIXES;
`frontend-code-reviewer` (lens on §3/§4): SHIP WITH FIXES. All findings folded in below and
marked inline `[fixes cal-…/fe-…]`. This is the contract for the slice-F diff; deviations during
implementation are findings. Diff audit + browser verification + final A–F audit in progress.
Known deviation from §6: no route test for the import `IsBot` guard (it mirrors create's
untested one-line guard) and no `FeatureDisabled` route test (gate untestable without a config
override harness, same as slices B–E). Design doc = `calendar-events-design.md` (§5 REST, §9 notifications,
§11 migration, §13 testing, §14 slices). Slice-E plan's "Carried to slice F" section + audit
trail enumerate the debts this slice retires.

State: slices A–E done/audited/committed (stoatchat `acutest`: 9489fb2c A–C, 4b717499 D,
a14dba6a E-backend; frontend repo: stoat.js/sloga e6bcd67c, frontend/main 644f1eb3). Nothing
pushed. Slice E browser-verified live 2026-07-09.

Frontend repo: `C:\Users\admin\frontend` — `packages/stoat.js` + `packages/client`.

---

## 0. DECISIONS — RESOLVED (operator sign-off 2026-07-09)

> **0.1 = A** (server-side `roles[]` expansion). **0.2 = A** (cancelled series returned by the
> list route, rendered struck-through). Both cost notes acknowledged; the cancelled-purge route
> is a known future roadmap item, not slice F. Details of each option retained below for the
> record.

### 0.1 Role-based group invites: server-side expansion vs client-side (blocking)

Operator request: the invite picker matches server **role** names alongside members; picking
"Raid group 1" invites everyone currently holding that role. Roles are the grouping primitive —
no new backend model either way. Two mechanisms:

| | Approach | Cost | Properties |
|---|---|---|---|
| **A ✅** | **Server-side**: extend `DataInviteToEvent` to `{users?: [id] (≤100), roles?: [id] (≤25)}` (at least one non-empty; the current `min = 1` on `users` is dropped — v0/calendar_events.rs:231 `[fixes cal nit]`). Handler resolves roles → member ids via the **existing** `fetch_all_members_with_roles` op (`server_members/ops.rs:90`, both drivers), merges with `users`, dedups, and feeds the **existing** per-user loop (rsvp.rs:55–93) — fetch_member + per-user ViewChannel gate + insert-if-absent + WS/push fan-out all unchanged. Response changes `EmptyResponse` (204) → `Json<InviteResult>{invited, skipped}` so the client can toast "Invited N members" (stoat.js `apiReq` already handles both 200/204; stoat.js is the only consumer). | DTO change + handler branch + ~5 route tests; stoat.js signature + types. | One request; no roster download; expansion reflects **live** role holders at execution; dedup and authz stay server-authoritative; wire back-compat (`users` required→optional is serde-compatible). |
| B | **Client-side**: picker expands the role locally (`server().syncMembers()` roster, filter `member.roles.includes(roleId)`), batches into the existing `users:[]` route ≤100 at a time, dedups vs loaded attendees. | Pure frontend (~40 lines). | Downloads the roster (heavy on big servers); expansion is as stale as the roster sync; N batched requests race the `events_invite` 5/event rate bucket; dedup only best-effort client-side (server insert-if-absent still guards). |

**Recommendation: A.** The backend loop and both gates already exist; A is a thin DTO/plumbing
change that stays correct at any server size, and B's batching fights our own rate limit. The
UI work (§4.2) is identical under either.

**Cost note `[fixes cal-LOW-3]`:** one role invite runs O(holders) sequential per-user
permission calcs and enqueues O(holders) pushes in a single request — the `events_invite`
bucket (ratelimits.rs:77,:105 — 5/window, keyed by event) limits *requests*, not per-request
fan-out. Acceptable at self-hosted scale; a 500-holder role means a visibly slow request, not a
broken one.

### 0.2 Cancelled events on the month grid (blocking)

Today `fetch_events_for_server_in_window` **excludes cancelled series** (slice A/B as audited),
so a cancelled event vanishes from the grid on the next refetch; the struck-through +
`Cancelled`-pill rendering only covers the transient WS state and the open detail
(slice-E plan §4.1, deferred decision). Pick one and make code + design §5 agree:

| | Approach | Cost | Properties |
|---|---|---|---|
| **A ✅** | **Return cancelled series** from the list route: drop the `cancelled` filter in `fetch_events_for_server_in_window` (both drivers). The grid renders them struck-through with the pill — that rendering **already exists** (`ServerEvents.tsx:641–650`, detail `:742–748`), so frontend cost ≈ 0. Cancelled series age out of the grid as the queried window moves past `series_end`. The reminder scan is untouched (`fetch_events_in_reminder_window` is a **separate op** that keeps excluding cancelled, and `reminders_due_for_event` guards `cancelled` again — model.rs:422); RSVP/edit/invite on a cancelled event stay rejected. | ~6 lines in 2 drivers + 1 route test + doc §5 line. | Everyone who can see the grid learns of the cancellation (today only `Going` attendees get the push; Pending invitees and other viewers get silent disappearance). |
| B | **Status quo**: keep excluding; reconcile design §5 wording ("list = non-cancelled") and remove the now-dead transient claim from the slice-E plan. | Doc-only. | Cancellations stay invisible to non-Going viewers; simplest. |

**Recommendation: A** — it closes a real information gap for Pending invitees, and the
rendering already shipped in E.

**Cost note `[fixes cal-LOW-1]`:** a long recurring series cancelled early (e.g. weekly ×
`Count: 730`) keeps `series_end` ~2 years out, so its struck-through entries render on every
month view until then — and there is **no removal affordance** (the `delete_event` DB op exists
but is unrouted; hard-cancel is soft by design, finding H6). If you pick A, a future
"purge/hard-delete cancelled event" route goes on the roadmap as a known item; it is NOT in
slice F.

---

## 1. Scope / non-goals

**In:** F1 prod index migration · F2 cancelled-on-grid decision · F3 bounded occurrence
expansion (slice-D LOW) · F4 lifecycle cascades + manage-authority hardening (slice-D LOW,
widened by audit) · F5 legacy tag import (design §11) + delete `lib/serverEvents.ts` · F6 role
invites (per 0.1) · F7 stoat.js bindings · F8 client UI (edit form, role picker, import) · doc
reconcile · **final audit A–F**.

**Out:** per-occurrence RSVP; UI for *creating* recurrence exceptions ("skip this occurrence" —
the model supports exceptions but nothing sets them yet); full RRULE; hard-delete/purge route
for cancelled events (0.2 cost note); report notifications; `events_enabled` in `RevoltFeatures`
(0.2-ii from slice E stands).

---

## 2. Backend

### F1 — Prod migration (incremental indexes for existing deployments)

`init.rs` only runs on **fresh** DBs; an existing deployment restarting on this branch has none
of the calendar collections/indexes. Add **revision 54** to
`admin_migrations/ops/mongodb/scripts.rs` (pattern of revisions 51–53; guard `if revision <= 54`
— the deployed DB's stored revision is already 54 because this branch shipped with
`LATEST_REVISION = 54`, and the `<=` guard covers both a 53- and 54-state DB):

- `create_collection` × 3 with `.ok()` (idempotent): `calendar_events`, `event_rsvps`,
  `event_reminders_sent` — mirroring init.rs:51–61.
- `createIndexes` (idempotent when key+name match) exactly mirroring init.rs:433–496:
  `calendar_events` → `server_series_end (server,series_end)`, `server_start (server,start)`,
  `series_end_global (series_end)`; `event_rsvps` → `event_id (_id.event)`, `user_id (_id.user)`;
  `event_reminders_sent` → `occurrence (_id.occurrence)`.
- Bump `LATEST_REVISION` 54 → **55** (scripts.rs:29 — "MUST BE +1 to last migration").

No standalone script needed: delta runs `migrate_database` on boot ("auto-connects +
migrates"), so the existing deployment picks this up on the next `start-sloga.sh` restart.
Verify in WSL against MONGODB test DBs seeded at revision **53 and at 54** `[fixes cal nit]`;
re-run must be a no-op.

### F2 — Cancelled events in the list route (if 0.2 = A)

- Remove the `cancelled` filter from `fetch_events_for_server_in_window` in
  `calendar_events/ops/mongodb.rs` and `ops/reference.rs`; update the trait doc comment
  (ops.rs:19–27) — it currently promises "non-cancelled". Audit confirmed the op has exactly one
  production consumer (`list_events`, events_crud.rs:134) and no existing test asserts
  cancelled-exclusion.
- Everything else already behaves: list handler expands occurrences for cancelled series the
  same way; `EventCollection.listForServer` upserts them (refreshing `cancelled` in cache);
  EventCard/Detail render struck-through; RSVP (rsvp.rs:133), edit (events_crud.rs:211) and
  invite (rsvp.rs:41) still reject cancelled; the reminder path is a different op + double guard.
- Route test: a cancelled series is returned by list (with occurrences) and still C1-filtered
  for a non-viewer; RSVP to it still rejected.
- Design §5 window-query bullet: "non-cancelled" → "including cancelled (rendered
  struck-through; reminder scan unaffected)".

### F3 — Bounded occurrence expansion (resolves slice-D LOW #1)

`series_occurrence_starts` always expands the full series (≤ `MAX_OCCURRENCES` = 730) even when
the caller only needs a 42-day window or a 35-minute reminder horizon. Add an **upper bound**:

- New internal `series_occurrence_starts_bounded(event, stop_after: Option<i64>)`; public
  `series_occurrence_starts(event)` becomes the `None` wrapper (call sites unchanged).
- Each frequency loop breaks (without pushing) once a computed occurrence start exceeds
  `stop_after`. Safety `[fixes cal-LOW-2]`: UTC occurrence starts are **non-decreasing** — the
  minimum local step is one calendar day (daily interval 1 / weekly by-day adjacent days /
  monthly clamp is monotone) and no tzdb offset delta exceeds 24h. Strict increase can fail for
  historical date-line jumps (e.g. Pacific/Apia 2011: a 24h offset shift makes two consecutive
  daily starts *equal*), but non-decreasing suffices: the first start `> stop_after` proves all
  later ones are `> stop_after`. State the invariant as non-decreasing in the doc comment.
  Occurrences *before* the bound still count toward a `Count` terminator (we never skip early
  ones), so terminator semantics are unchanged.
- Callers (audit-verified complete set): `occurrences_in_window` passes `Some(to)`;
  `reminders_due_for_event` passes `Some(now + max(REMINDER_OFFSETS_MS))` (a trigger
  `occ − offset ≤ now` implies `occ ≤ now + offset`). `compute_series_end` and `validate` (the
  `Until`-cap probe, model.rs:565) stay **unbounded** — they need the true series tail.
- **Explicitly NOT doing** analytic skip-ahead to the window's lower bound: it would introduce
  new DST-sensitive arithmetic (the exact class of bug the engine centralizes away) to save at
  most 730 cheap date ops per candidate series per 60s tick. This bound + the 730 cap is the
  documented resolution of the deferred LOW.
- Unit tests: bounded == unbounded-then-filter equivalence for daily / weekly-multi-day /
  monthly-day-31 series across a DST-transition week **plus one hostile anchor in a date-line
  zone (Pacific/Apia across 2011-12-30)** `[fixes cal-LOW-2]`; `Count`/`Until` results unchanged.

### F4 — Lifecycle cascades + manage-authority hardening (resolves slice-D LOW #2, widened)

**F4a — RSVP cascade on member removal.** New op `delete_rsvps_for_member(server_id, user_id)`
on `AbstractCalendarEvents`, both drivers. Mongo: fetch the server's event ids
(`calendar_events {server}` — prefix of the `server_series_end` index; projection `_id`), then
`event_rsvps.delete_many({"_id.user": uid, "_id.event": {$in: ids}})`. Reference: iterate.
Call site: `Member::remove` (`server_members/model.rs:274–315`), right after
`soft_delete_member` — **best-effort** (`.ok()` + `capture_error`), matching the system-message
send in the same function: a leave/kick/ban must never fail on calendar cleanup, and the live
`fetch_member` filters in crond (event_reminders.rs:77) and cancel (events_crud.rs:293) remain
as defense-in-depth. Audit confirmed Leave / Kick / Ban all route through `Member::remove`
(ban_create.rs:63, member_remove.rs:49, server_delete.rs:57). Effect: ex-members disappear from
attendee lists and counts; a rejoining member has lost their invites (same semantics as
uninvite — documented). No WS fan-out, matching the existing uninvite route.

**F4b — Manage authority requires live membership `[fixes cal-HIGH-2]`.** `authorize_manage`'s
creator short-circuit (mod.rs:50–53) has **no membership check**: a banned/kicked creator with a
still-valid session can PATCH (edit route never calls `authorize_view` — events_crud.rs:210–214),
cancel, or invite (fanning out pushes to server members) — a concrete harassment vector, amplified
by F5 (imported events' creators may have left long ago). Fix: the creator branch also requires
live membership (`db.fetch_member(&event.server, &user.id).await.is_ok()`); otherwise fall
through to the ManageChannel path (which fails for a non-member via the permission query).
Route test: banned creator's edit/cancel/invite all rejected.

**F4c — Server-deletion cascade `[fixes cal-MED-1]`.** `delete_associated_server_objects`
(servers/ops/mongodb.rs:192–263 + Reference equivalent) cascades channels/messages/members/bans
but not calendar rows: a deleted server's events remain candidates in crond's **cross-server**
reminder scan (the op has no server-existence check) every 60s until `series_end` — up to ~2
years of dead scans plus a permanent storage leak. Fix: delete `calendar_events`, `event_rsvps`
(by the server's event ids), and `event_reminders_sent` (by the same ids) in the server-delete
cascade, both drivers. Test: server delete removes all three.

**F4d — Account-deletion cascade `[fixes cal-MED-2]`.** `User::delete` →
`clear_memberships` (users/model.rs:899–911) bypasses `Member::remove`, so a deleted account's
`Going`/`Pending` rows persist as ghost users in attendee lists and counts (the REST attendees
route has no `fetch_member` filter). Fix: at the account-deletion cascade, delete `event_rsvps`
by user id (`{"_id.user": uid}` — the existing `user_id` index), both drivers. Test included.

### F5 — Legacy tag import (design §11)

**Route:** `POST /events/server/<server>/import`, body `DataImportLegacyEvents { channel: String }`
(manager picks the source channel — no name-guessing server-side). Registered in `routes()` +
`#[openapi]`. Ratelimit: the path shape `("events", Some("server"), Post)` already lands in the
`events_create` bucket (ratelimits.rs:76, 10/window) — no fairing change.

**Gates:** `require_events_enabled`; `IsBot` guard (as create); member of the server; server-wide
`ManageChannel` via `calculate_server_permissions` (same as `authorize_manage`'s channel-less
branch, mod.rs:60–66 — "manager-triggered", §11); the channel must belong to the server (as
create's cross-server block, events_crud.rs:62–65); **and the caller must hold `ViewChannel` on
the source channel** `[fixes cal-MED-3]` — otherwise a server-wide manager denied ViewChannel on
a private channel could exfiltrate its tagged titles/descriptions into server-visible events.
Same `calculate_channel_permissions` pattern as create.

**Reference-driver pagination `[fixes cal-HIGH-1]`:** the scan below paginates
`db.fetch_messages` — but `ReferenceDb::fetch_messages` currently ignores `limit`, `before`,
and sorting entirely (messages/ops/reference.rs:37–78, literal `FIXME: sorting`), so the
REFERENCE route tests would go green while never exercising real pagination (cursor never
narrows; `truncated` untestable). **F5 therefore completes the Reference `Absolute` path**:
sort by `_id` (ulid = chronological), apply `before`/`after` filters and `limit`, matching the
Mongo semantics (ops/mongodb.rs:113–169). This is a test-infrastructure fix with its own tiny
driver-parity test (same query against both drivers where feasible under WSL).

**Scan:** paginate `fetch_messages` (`MessageQuery` Absolute, `before` cursor, limit 100/page,
filter channel) newest→oldest up to `MAX_IMPORT_SCAN = 2000` messages; set `truncated` if the cap
was hit before exhausting history. Parse messages whose content starts with `"[ACUTEST_EVENT]:"`
(the `EVENT_PREFIX` from `lib/serverEvents.ts`) as JSON `{title, start, end?, desc?, voiceId?,
color?}` (legacy `ServerEvent` minus client-only fields). Fan-out note `[fixes cal-LOW-3]`: one
import can emit up to ~cap `CalendarEventCreate` broadcasts — bounded, and the client's 150ms
debounced grid refetch absorbs the burst.

**Mapping** (one row per tagged message, through the same validation as create — §11):

| legacy | CalendarEvent | notes |
|---|---|---|
| `title` | `title` | model `validate()` enforces 1..=100 — invalid ⇒ rejected, counted |
| `start` (ISO string) | `start` (ms) | RFC3339 datetime parse (the legacy writer used `Date.toISOString()` — audit-verified in git `31c450c7`); a **date-only** `YYYY-MM-DD` value imports as `all_day = true` at UTC midnight; unparseable ⇒ invalid |
| `end` | `end` | must be a datetime > start (validate) else the row is rejected, counted (§11: invalid rows rejected, not stored). **[as built]** an `end` on a *date-only* (all-day) row is **ignored** rather than rejecting the row — all-day events have no end, and the legacy writer could not produce this shape anyway |
| `desc` | `description` | >2000 ⇒ rejected |
| `voiceId` | `channel` | kept **only if** the channel exists, belongs to this server, **and the importer holds `ViewChannel` on it** `[fixes cal-MED-3]`; else `None` (degrade, don't reject — a deleted/hidden voice channel must not block the import; the channel is auxiliary and, when kept, becomes the event's C1 topic/visibility boundary) |
| `color` | `color` | >32 ⇒ rejected |
| message author | `creator` | **server truth** (`message.author`), never the payload's `authorId` — no creator spoofing via message content. F4b bounds the authority this grants an since-departed author. |
| — | `timezone` | `"UTC"` (imports are non-recurring; timed events render viewer-local anyway) |
| — | `recurrence` | `None` |
| message id | `source_message_id` | dedup key (§11) |

**Dedup:** new op `fetch_imported_source_ids(server_id) -> Result<HashSet<String>>` (both
drivers; Mongo: find `{server, source_message_id: {$exists: true}}`, projection — uses the
`server_series_end` index prefix). One query up front; skip any message whose id is present, and
track within-run inserts so a duplicate tag in the same scan imports once.

**Creation:** thread a `source_message_id: Option<String>` parameter through
`CalendarEvent::create` (model.rs:581 — currently hardcodes `None` at :613). Call sites that
update: the create route (events_crud.rs, passes `None`) **and the 4 model unit-test
constructors** (model.rs:972, :1036, :1214, :1238) `[fixes cal nit]`. Import passes the message
id. Each imported event fans out `CalendarEventCreate` on `event_topic`.

**Response:** `Json<ImportResult> { imported, skipped_duplicates, skipped_invalid, scanned,
truncated }`.

**Retiring the tag path:** delete `packages/client/src/lib/serverEvents.ts` — both audits
confirmed zero references outside the file itself (incl. stoat.js; the Rust import hardcodes the
prefix literal). Old tagged messages remain as harmless chat history (§11).

### F6 — Role invites (if 0.1 = A)

- `DataInviteToEvent` → `{ users: Option<Vec<String>> (validate ≤100, **min dropped**), roles:
  Option<Vec<String>> (validate ≤25) }`; handler rejects when both are empty/absent
  (`FailedValidation`).
- Each role id must exist in the server's `roles` map (fetch server, check) — unknown role ⇒
  `NotFound` **before any insert** (fail the request rather than silently skipping; no partial
  application).
- Expand: `db.fetch_all_members_with_roles(&server_id, &roles)` → member ids; merge with
  `data.users`, dedup (HashSet). Feed the **existing** loop unchanged. `[fixes cal-MED-5]` The
  per-user `fetch_member` re-check in that loop is **REQUIRED, not redundant**:
  `fetch_all_members_with_roles` does not filter `pending_deletion_at`
  (server_members/ops/mongodb.rs:122–144) while `fetch_member` does — without the re-check, a
  soft-deleted (kicked-while-in-timeout) member could be re-invited. Do not "optimize" it away;
  the plan pins a test for exactly this.
- Response: `Json<InviteResult> { invited: usize, skipped: usize }` (replaces `EmptyResponse`;
  `skipped` = non-members + pending-deletion + non-viewers + already-had-a-row). No hard cap on
  role size (see 0.1 cost note): truncating an invite silently would be worse; the request is
  merely slow for a huge role.
- Tests: role expands to exactly current holders; **expansion skips a pending-deletion member**
  `[fixes cal-MED-5]`; users∩roles dedup (one row, one push); unknown role 404; both-empty 400;
  role invitee without ViewChannel on a channel-scoped event skipped (counted); re-invite via
  role is a no-op (insert-if-absent); `InviteResult` counts correct.

---

## 3. stoat.js (F7)

- Wire types (`classes/CalendarEvent.ts`): `ImportResultData`, `InviteResultData`; update
  `DataInviteToEvent` (`users?`, `roles?`).
- `CalendarEvent.invite(users: string[], roles?: string[])` — backward-compatible signature;
  body includes only non-empty arrays; returns `InviteResultData`.
- `EventCollection.importLegacy(serverId: string, channelId: string): Promise<ImportResultData>`
  → `apiReq("POST", "/events/server/<id>/import", {body: {channel}})`. (Raw fetch as everything
  else here — typed-client body/query drop, `feedback_stoat_api_body_drop`.)
- Rebuild: `npx tsc` in `packages/stoat.js` (client consumes built `lib/`).

## 4. Client (F8) — `ServerEvents.tsx`

### 4.1 Edit form

Generalize `CreateForm` (`:933`) with an optional `event?: CalendarEvent` prop (edit mode)
rather than a parallel component — every needed signal already exists (`:944–957`).

**Dirty detection `[fixes fe-HIGH-1]` — the load-bearing rule:** a field is dirty iff its
current form value differs from its **prefilled initial value** (string/primitive comparison of
the form's own representation, captured once at prefill). NEVER decide "changed" by recomputing
an instant from the form and comparing to the stored ms — that round-trip is lossy in at least
three real cases (all-day events anchored in a foreign tz, where recomputed viewer-local
midnight ≠ stored creator-tz midnight; imported events with seconds precision, which a
minute-resolution `<input type="time">` can never reproduce; `Until` terminators resubmitted as
`23:59` local). Any of those would turn a title-only edit into a silent schedule rewrite.

**Atomic schedule group `[fixes fe-HIGH-2]`:** `start`, `end` / `remove:["End"]`, `all_day`,
`timezone` travel **together or not at all**. If *any* schedule field is dirty, submit the full
tuple recomputed from the form (new local instants + `timezone: LOCAL_TZ`); if none is dirty,
omit all of them. `timezone` must never appear without `start` — an end-only diff that shipped
`{end, timezone: LOCAL_TZ}` would make the server re-derive the recurrence wall-clock from the
old UTC start in the new zone, shifting every occurrence of a cross-tz series by the DST
divergence.

- **Prefill:** title/description/location verbatim; `allDay`; date + times from `start`/`end` —
  timed events in **viewer-local** (display only); an **all-day** event's date via the en-CA
  `Intl.DateTimeFormat(…, {timeZone: event.timezone})` trick (same bucketing as the grid, slice-E
  HIGH-1 — never `new Date(ms)` viewer-tz for all-day); recurrence freq/interval/weekdays/end
  from `event.recurrence`. Hide the invite picker in edit mode (invites live in the detail).
  Mechanics `[fixes fe-LOW-7]`: time inputs need 24h `"HH:mm"` (`pad(getHours())+":"+
  pad(getMinutes())` — the locale-formatted `time()` helper at `:1367` is unusable for
  `<input type="time">`); the form is **keyed on the event id** (`<Show keyed>` / remount) so
  switching targets re-runs the once-per-mount signal initializers; an `Until` date prefills
  viewer-local (acceptable under the re-anchor doctrine *because* untouched recurrence is never
  resubmitted).
- **Recurrence diff `[fixes fe-MED-4]`:** compare only the form-editable subfields — freq,
  interval, **sorted** `by_weekday`, end (mode + count/date) — against the prefilled initial
  values; click-order array differences must not read as dirty. When recurrence IS dirty, submit
  the rebuilt rule without `exceptions` — the server clears exceptions on any time-affecting
  edit anyway (model.rs:653–657), and that server-side clear is the documented intended
  semantics. When not dirty, omit `recurrence` entirely. Clearing recurrence (freq → "None") ⇒
  `remove: ["Recurrence"]`.
- **Time-edit semantics:** when the user changes the schedule, submit the new local instants
  (`new Date(y,m,d,h,mm)` ms) **and** `timezone: LOCAL_TZ` — editing the schedule re-anchors the
  series in the **editor's** timezone, exactly like create. Zero tz/recurrence math in TS.
  Documented in the form's info text.
- **End semantics `[fixes fe-MED-5, widened by diff-audit MED]`:** the end *input* may be EMPTY —
  it prefills empty for an all-day event **and for an end-less imported timed event** (legacy
  `end?` was optional; the create form always sends an end, so only imports produce these). When
  the schedule group is dirty, an empty end maps to `remove:["End"]` and a non-empty one to
  `diff.end` — the group **never fabricates an end** the event didn't have (a date-only edit of
  an end-less import must not attach 19:00, nor fail `end > start` validation). This supersedes
  rev 2's "toggling all-day is the only `remove:["End"]` path": clearing the end input is now a
  supported way to remove an end. Create mode: an emptied end input simply omits `end`.
- **Accepted caveat `[diff-audit LOW]`:** an *interval-only* (or count/weekday-only) edit of an
  `Until`-terminated series rebuilds the rule from the viewer-local until-date prefill without
  touching the schedule group, so a cross-tz editor can shift the until instant by the tz delta
  (at most one boundary occurrence). This sits inside the re-anchor doctrine (recurrence WAS
  touched) and is accepted for v1.
- **Concurrent updates `[fixes fe-MED-6]`:** WS updates upsert the store while the form holds
  prefill snapshots — the diff is computed against the *prefill*, so a save applies
  **dirty-fields-win last-write-wins** over a concurrent edit (acceptable, stated). If
  `event.cancelled` flips while the form is open (getters are store-backed/reactive), close the
  form or show the cancelled state; an in-flight save rejected by the server
  (events_crud.rs:211) surfaces via `showError` and must not strand the form.
- **Exceptions note:** when `event.recurrence` exists, show an inline note that changing the
  schedule resets any skipped occurrences (server clears `exceptions`). Label built in component
  scope (lingui macro-`t` helper-fn gotcha).
- **Wiring:** Edit button in `EventDetail` beside Cancel (`canManage` gate, same as slice E);
  on save `event.edit(diff)` (binding ships since E; upsert refreshes the store) →
  `refreshDetail()` + grid `refetch()`. Edit button hidden/disabled when `event.cancelled`.

### 4.2 Role invite picker (if 0.1 = A)

In **both** pickers: match `server().orderedRoles` by case-insensitive substring **client-side**
(roles are already cached on the server object — no fetch; an untracked read inside the
debounced search callback is fine, audit-verified), render matching roles above member results
with a distinct "role" badge.

- **Create form** (`:960–998`) `[fixes fe-MED-3]`: chips state gains a second collection for
  roles (e.g. `invitedRoles: Map<string, ServerRole>` beside the existing
  `invited: Map<string, ServerMember>` — the member map cannot hold roles). Widen the submit
  path to `onSubmit(data, userIds, roleIds)` (`:937`, `:1038`) and the gate at
  `createEvent` (`:334–352`) from `if (invites.length)` to `if (userIds.length ||
  roleIds.length)` — otherwise a **role-only** selection would create the event and silently
  invite nobody. Create-flow partial-failure surfacing (slice-E MED-4) unchanged.
- **Detail picker** (`:702–731`) `[fixes fe-MED-3]`: keeps its existing interaction — a row
  click invites **immediately** (no chips there today); a role row likewise invites its holders
  immediately via `invite([], [roleId])`. Consistent with the member rows; no new chip state in
  the detail.
- **Toasts `[fixes fe-LOW-8]`:** success toast uses the returned `invited` count as a single
  lingui `plural`/`Trans` expression built in component scope (no concatenated fragments);
  `invited: 0` gets its own wording ("Everyone in that role was already invited or can't view
  this event") rather than a confusing "Invited 0 members".

### 4.3 Import UI

"Import legacy events" action in the page header, shown only to `canManage` users (same gate
expression as slice E). Opens a small confirm modal: channel `<select>` of the server's text
channels defaulting to the one literally named "events" (case-insensitive — the legacy
convention); `[fixes fe-LOW-9]` when no such channel exists the select starts **unset** with a
"select a channel" placeholder (explicit choice required — never silently default to #general).
The Import button **disables while the request is in flight** (the scan can take a moment at the
2000-message cap; double-submit is dedup-safe server-side but burns the `events_create` bucket).
On success: result toast as a single component-scope `plural`/`Trans` expression ("Imported N
events, skipped D duplicates, I invalid" + truncation note when `truncated`) `[fixes fe-LOW-8]`
→ `refetch()`. Errors surface via `showError`. Re-running is safe (dedup), so no client-side
"already imported" state.

### 4.4 Cancelled on grid (if 0.2 = A)

No new rendering — the struck-through card + `Cancelled` pill already handle it (card
`:641–650`, detail `:742–748`; the upcoming-list entry strikes through without a pill `:604` —
cosmetic, judged during browser verification). Verify the day-dot for a day whose only
occurrences are cancelled looks intentional (mute it if jarring).

### 4.5 Legacy file removal

Delete `src/lib/serverEvents.ts`. Typecheck confirms nothing references it (its `isSameDay`
helper is already duplicated at `ServerEvents.tsx:1270`).

---

## 5. Docs reconcile (same diff)

- design §5: cancelled-in-list wording per 0.2 decision.
- design §6: `authorize_manage` creator branch now requires live membership (F4b).
- design §11: replace the sketch with the as-built import contract (route, gates incl.
  source-channel ViewChannel, mapping table, caps, dedup op) — mark `[as built, slice F]`.
- design §10: note `serverEvents.ts` removed (tag path retired).
- design §14: slice F marked done; audit-trail entry appended after the final audit.
- slice-e-plan: leave historical; the Carried-to-F section gets a one-line "resolved in slice F"
  pointer.

---

## 6. Testing / verification

Backend (REFERENCE; route tests `cargo test -- --test-threads=1` on Windows; repeat calendar DB
tests under MONGODB in WSL — `feedback_mongo_tests_wsl_only`):

1. **Import**: happy path maps every field (creator = message author, tz UTC, timed);
   date-only start → all-day; bad JSON / long title / end ≤ start / long desc → counted
   invalid, not stored; second run imports 0 (dedup); duplicate tag within one run imports 1;
   dead `voiceId` → `channel: None`; **importer-unviewable `voiceId` → `channel: None`**;
   **import from a channel the caller cannot view → 403** `[fixes cal-MED-3]`; cross-server
   channel rejected; non-manager 403; bot 403; feature-gate; `truncated` when the cap hits —
   **pagination tests are honest**: they rely on the completed Reference `Absolute` path
   (sort + `before` + `limit`), with a driver-parity spot-check under WSL `[fixes cal-HIGH-1]`.
2. **Role invites**: per F6 list, incl. **pending-deletion member skipped** `[fixes cal-MED-5]`.
3. **Cancelled-in-list** (0.2-A): returned with occurrences; C1 non-viewer filter still applies;
   RSVP still rejected.
4. **Cascades + authority**: leave/kick/ban delete that server's rows only (another server's
   RSVPs survive); **server delete removes calendar_events + event_rsvps + event_reminders_sent**
   `[fixes cal-MED-1]`; **account deletion removes the user's RSVP rows** `[fixes cal-MED-2]`;
   **banned/kicked creator can no longer edit/cancel/invite** `[fixes cal-HIGH-2]`.
5. **Bounded expansion**: equivalence tests incl. the Pacific/Apia hostile anchor (F3); existing
   18 calendar DB + 7 route tests stay green; clippy clean; crond/pushd build in WSL.
6. Migration: run `migrate_database` in WSL against MONGODB DBs pinned at revision **53 and 54**
   → collections + 6 indexes exist; re-run is a no-op (idempotent).

Frontend: `npx tsc` (stoat.js) + client typecheck green. Browser (app.sloga.gg via `mise dev`,
Vite/WSL restart gotcha):

7. Edit: open detail → Edit prefilled; **title-only edit of (a) a cross-tz all-day event and
   (b) an imported seconds-precision event leaves `start`/`timezone` byte-identical**
   `[fixes fe-HIGH-1]` (verify via refetch: `edited_at` changed, `start` didn't); **end-only
   edit of a recurring cross-tz series does not shift the other occurrences' wall-clock**
   `[fixes fe-HIGH-2]`; time edit moves occurrences on the grid; recurrence change re-expands;
   all-day toggle on/off round-trips (`remove:["End"]` path); form remounts cleanly when
   switching events; cancel-over-WS mid-edit surfaces, doesn't strand the form.
8. Role invite: role "Raid group 1" with 2 holders → both get Pending rows + live WS invite +
   push; toast count matches; re-invite no-op; **role-only selection in the CREATE form invites
   the holders** `[fixes fe-MED-3]`; detail role row invites immediately.
9. Import: hand-craft an `[ACUTEST_EVENT]:` message (and one invalid one) in a channel → import
   → event on grid with correct date/title/creator; counts in toast; second import = 0; button
   disabled in flight; no-"events"-channel case requires explicit selection.
10. Cancelled (0.2-A): cancel from a second session → struck-through entry survives a month
    nav round-trip (refetch).
11. Cascade: kick the invited member → they disappear from attendees after refresh.

Then: **FINAL AUDIT of A–F** by `calendar-events-reviewer` against design §13's full adversarial
matrix — explicitly including the new §13 items: banned-creator manage, lifecycle cascades,
import authz/dedup — (with `frontend-code-reviewer` as a lens on stoat.js + ServerEvents.tsx),
fixes applied, suite re-run, restore-point commits in both repos.

---

## 7. Risks & reviewer focus (post-audit)

- **Edit-form diff mechanism (fe-HIGH-1/2)** — the one place this slice can silently corrupt
  data: dirty = initial-value comparison, schedule fields atomic, `timezone` never travels
  without `start`. Reviewers verify no instant-recompute comparison survives into the diff.
- **Import**: Reference pagination completed (cal-HIGH-1) so the tests test reality; creator
  from `message.author`; source-channel + voiceId ViewChannel gates (cal-MED-3); scan capped.
- **Authority**: creator-manage now membership-gated (cal-HIGH-2) — check every `authorize_manage`
  consumer still behaves (edit/cancel/invite/uninvite).
- **Cascades**: three lifecycle paths (member removal, server delete, account delete) each hit
  the right rows, both drivers; best-effort at `Member::remove` keeps the live-filter safety net.
- **F3 early-break**: non-decreasing (not strictly increasing) invariant; hostile-anchor test.
- **DTO back-compat**: `users` required→optional (min dropped) and 204→200 on invite are
  consumed only by stoat.js, updated in the same slice.
- **No recurrence math in TS** — unchanged invariant; the import parses dates in **Rust**;
  re-anchor uses viewer-local `Date` construction + Intl formatting only.

---

## 8. File-by-file change list

**stoatchat (backend)**
- `admin_migrations/ops/mongodb/scripts.rs` — revision 54 (collections + 6 indexes), LATEST_REVISION 55.
- `calendar_events/ops.rs` + `ops/mongodb.rs` + `ops/reference.rs` — window-query cancelled
  filter (F2); `delete_rsvps_for_member` (F4a); `fetch_imported_source_ids` (F5); rows for the
  server-delete / account-delete cascades as needed (F4c/F4d).
- `calendar_events/model.rs` — `series_occurrence_starts_bounded` (F3); `create(...,
  source_message_id)` (F5; + 4 unit-test call sites); unit tests.
- `server_members/model.rs` — cascade call in `Member::remove` (F4a).
- `servers/ops/mongodb.rs` + Reference equivalent — calendar rows in
  `delete_associated_server_objects` (F4c).
- `users/model.rs` (account-deletion cascade path) — RSVP rows by user id (F4d).
- `messages/ops/reference.rs` — complete the `Absolute` fetch path (sort/before/limit) (F5,
  cal-HIGH-1).
- `models/src/v0/calendar_events.rs` — `DataImportLegacyEvents`, `ImportResult`,
  `DataInviteToEvent{users?,roles?}` (min dropped), `InviteResult`.
- `delta/src/routes/events/mod.rs` — `authorize_manage` membership gate (F4b); register import.
- `delta/src/routes/events/events_crud.rs` — pass-through `source_message_id: None`.
- `delta/src/routes/events/import.rs` — new: import route (F5).
- `delta/src/routes/events/rsvp.rs` — role expansion + `InviteResult` (F6).
- `delta/src/routes/events/tests.rs` — new tests per §6.
- `docs/calendar-events-design.md` — §5/§6/§10/§11/§14 + audit trail.

**frontend**
- `stoat.js/src/classes/CalendarEvent.ts` — types + `invite(users, roles?)`.
- `stoat.js/src/collections/EventCollection.ts` — `importLegacy`.
- `client/src/interface/ServerEvents.tsx` — edit mode on CreateForm (keyed remount, dirty-flag
  diff, atomic schedule group), Edit button, role chips (create) / immediate role rows (detail),
  import modal + header action, widened `onSubmit`/`createEvent` signatures.
- `client/src/lib/serverEvents.ts` — **deleted**.

---

## Audit trail

- **Browser verification (§6.7–11) — PASSED live on app.sloga.gg, 2026-07-10.**
  Deployed via full-stack restart; **migration revision 54 ran against the live DB**
  (stored revision 55; all 6 calendar indexes present — this pre-calendar DB never ran the
  fresh-DB init path, so they could only come from the migration; re-run no-op).
  - **§6.7 edit** (verified at STORAGE level via mongosh snapshots): title-only edit of the
    live weekly series left `start`/`end`/`series_end`/`timezone`/`recurrence` **byte-identical**
    (only `title` + `edited_at` changed — the fe-HIGH-1 guarantee on the real wire); a
    start-time-only edit re-anchored the full atomic group (`start` −30min exactly, `end`
    untouched, `duration_ms` recomputed 60→90min by the sanctioned edit path, recurrence
    preserved, occurrences stayed on Thursdays). Prefill exact (title/date/times/freq/
    interval/ends-after; weekday chips correctly un-toggled for empty `by_weekday`); edit
    mode hides the invite picker; re-anchor info note shown.
  - **§6.8 role invite**: "raid" search surfaced the "Raid group 1" role row (ROLE badge);
    clicking it invited exactly the role's holders — 1 new Pending row (Velvetfly), the
    already-invited holder deduped — with the Plural-rendered "Invited 1 member" feedback;
    DB shows exactly 3 rows, no duplicates.
  - **§6.9 import**: panel defaulted to the channel literally named #Events; scanning 3
    tagged messages (one GENUINE legacy "Kara Raid Team 1" from 2026-02, one crafted with a
    spoofed `authorId`, one broken JSON) yielded "Imported: 2 · Duplicates skipped: 0 ·
    Invalid: 1"; DB confirms both events have `creator` = the message AUTHOR (spoofed payload
    id ignored), `timezone: UTC`, `source_message_id` set; the imported event rendered on the
    correct local day/time with its description; **re-run: "Imported: 0 · Duplicates
    skipped: 2 · Invalid: 1"** (dedup).
  - **§6.10 cancelled (0.2-A)**: cancelling the imported event set `cancelled: true` (DB
    verified); after a month-nav round trip (full list refetch) the event **stayed on the
    grid** struck-through with the red Cancelled pill in both the day card and Upcoming list.
  - **§6.11 kick-cascade**: covered by the two automated route tests + DB ops test
    (`member_removal_cascades_rsvps_per_server`, `role_invite_expands_and_dedups`,
    `lifecycle_ops_and_import_dedup`) rather than a live kick — kicking and re-adding a real
    member requires that member's session to rejoin.
  - Ops notes from the deploy: crond's shared-`/mnt/c` binary had been corrupted by
    Windows/WSL toolchains sharing one `target/` (loader "Verneed record" error) — clean
    rebuild fixed it, exactly one instance now running; a transient WS outage during the
    verification traced to cloudflared restarts (tunnel healthy after; NOTE: an
    `Upgrade:`-header probe over HTTP/2 is invalid by spec and 502s — always probe WS with
    `--http1.1`).
- **Diff audit (implemented slice F) — both reviewers, SHIP WITH FIXES ×2; all fixes applied.**
  - *calendar-events-reviewer*: no live correctness/authz bugs; both plan HIGHs verified landed
    (Reference `Absolute` pagination real + import loop traced correct; membership-gated
    `authorize_manage` safe across all four consumers). Findings applied: **MED** missing
    plan-pinned import pagination/truncation tests → `import_paginates_and_truncates` (120-msg
    two-page scan + 2000-cap truncation; a cursor regression now hangs the test); **MED**
    missing pending-deletion test (unwritable under REFERENCE — `pending_deletion_at` is a
    DB-layer-only field the Reference driver cannot represent) → Mongo-gated
    `pending_deletion_member_not_invitable` (explicit-users AND role-expansion paths, exercising
    the fetch_member re-check as the only filter); **LOW** migration test blind spot → drops the
    calendar collections per pinned iteration (53 AND 54 independently prove creation) + a
    no-drop idempotent re-run; **LOW** server-delete cascade moved BEFORE the ServerDelete
    broadcast (fail before announcing); **LOW** mapping-table wording reconciled (end on
    date-only row is ignored); **INFO** mid-loop `?` on invite acknowledged (pre-existing
    pattern, re-run safe). Route tests now 15.
  - *frontend-code-reviewer*: fe-HIGH-1/2 verified landed exactly (no instant-recompute
    comparison exists; timezone can never travel without start; keyed remount + snapshot
    semantics traced). Findings applied: **MED** schedule edit of an end-less imported timed
    event fabricated an end (or failed validation) → end input prefills EMPTY for end-less
    events; empty end ⇒ `remove:["End"]`, never a fabricated 19:00 (see End semantics above);
    **LOW** count strings → `Plural` macro component (invited count) and a label-colon layout
    for the import result (no "(s)" hacks); **LOW** create-flow role invite discarded the
    result → `invited: 0` now lands the organizer on the detail (real attendee state visible);
    **LOW** Save disabled when the date input is empty; **LOW** interval-only `Until`
    reinterpretation documented as an accepted caveat (above).
- **rev 2 (this doc) — plan audited by both reviewers, SHIP WITH FIXES ×2; all findings folded.**
  - *calendar-events-reviewer* (full-stack) — confirmed factual accuracy of nearly all code
    anchors (migration pattern incl. revision numbering, ratelimit bucket resolution, F3 caller
    set completeness, F5 mapping vs the legacy writer in git `31c450c7`, F2 single-consumer
    claim, F4 op/index design, decision recommendations 0.1-A/0.2-A). Findings folded:
    **HIGH-1** Reference `fetch_messages` ignores limit/before/sort → import pagination tests
    would validate nothing (→ F5 completes the Reference Absolute path); **HIGH-2** banned/kicked
    creator retains manage authority (creator short-circuit lacks membership check → F4b);
    **MED-1** server deletion doesn't cascade calendar rows (crond scans dead series for up to
    ~2y → F4c); **MED-2** account deletion leaves ghost RSVP rows (→ F4d); **MED-3** import
    lacked ViewChannel on the source channel (+ voiceId view gate); **MED-5** F6's "redundant"
    fetch_member wording inverted — it is the only pending-deletion filter (reworded + test);
    **LOW** 0.2-A ~2-year clutter cost note + unrouted purge as future item; **LOW** F3
    invariant is non-decreasing not strictly-increasing (date-line zones) + hostile-anchor test;
    **LOW** fan-out burst costs stated; nits (4 test call sites of `create`, ratelimit line
    numbers, `users` min dropped explicitly, migration verified against rev-53 AND rev-54 DBs).
  - *frontend-code-reviewer* (SolidJS/stoat.js lens) — confirmed the re-anchor doctrine, en-CA
    all-day prefill, deletion safety (no references incl. stoat.js), binding shapes vs `apiReq`
    (204→200 compat), role matching via untracked `orderedRoles` read, and the no-TS-tz-math
    invariant. Findings folded: **HIGH-1** dirty detection must compare prefilled initial values,
    never recomputed instants (three concrete corruption cases: cross-tz all-day, imported
    seconds precision, `Until` round-trip); **HIGH-2** schedule fields are an atomic group —
    `timezone` never ships without `start` (end-only edit would shift a cross-tz series);
    **MED-3** create-flow `onSubmit`/gate must admit role-only invites + chips state shape +
    detail picker stays immediate-invite; **MED-4** recurrence diff on sorted editable subfields,
    server-side exceptions-clear documented as intended; **MED-5** all-day toggle transitions
    define the only `remove:["End"]` paths; **MED-6** WS-mid-edit = dirty-fields-win LWW +
    cancelled-mid-edit surfaces; **LOW** prefill mechanics (HH:mm 24h, keyed remount, `Until`
    caveat); **LOW** toast plurals in component scope + `invited: 0` wording; **LOW** import
    modal fallback (explicit choice) + in-flight disable.
- **rev 1 → rev 2**: two open decisions (0.1 role-invite mechanism, 0.2 cancelled-on-grid)
  remain for operator sign-off, now with the audit-added cost notes attached.
