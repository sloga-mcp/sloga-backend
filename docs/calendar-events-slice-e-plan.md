# Calendar/Events — Slice E (Frontend) Implementation Plan

Status: **rev 2 — audited** by `calendar-events-reviewer` (SHIP WITH FIXES) + `frontend-code-reviewer`
(SHIP WITH FIXES, REWORK on the binding section). All findings folded in below and marked inline
`[fixes …]`. This is the contract for the slice-E diff; deviations during implementation are findings.
Design doc = `calendar-events-design.md` (§5 REST, §6 authz, §7 RSVP, §8 WS, §10 frontend, §14 slices).
Backend slices A–D done/audited/committed on `acutest` (9489fb2c = A–C, 4b717499 = D), not pushed.

Frontend repo: `C:\Users\admin\frontend` — `packages/stoat.js` (bindings) and
`packages/client/src/interface/ServerEvents.tsx` + `.../lib/serverEvents.ts` (legacy tag calendar).

---

## 0. DECISIONS — RESOLVED (operator sign-off 2026-07-09)

> **0.1 = A** (backend returns `EventWithOccurrences`). **0.2 = ii** (no root-config change; the page
> degrades on a `FeatureDisabled` error). Net: slice E carries **one** small backend edit (0.1-A) plus
> the pure-frontend work; `RevoltFeatures` is untouched. Details of each option retained below for the
> record.

### 0.1 How the month grid gets per-occurrence instances (blocking)

`GET /events/server/<server>?from=&to=` returns **series** — `Vec<v0::Event>` with the recurrence
*rule* (events_crud.rs `list_events`). The grid needs one instance **per occurrence**. Constraint:
**do not re-fork the DST-aware recurrence math**.

| | Approach | Cost | Divergence | Verdict |
|---|---|---|---|---|
| **A ✅** | **Backend returns the occurrences it already computes.** `list_events` *already* calls the pure `occurrences_in_window(&event, from, to)` (events_crud.rs:141) — solely to drop all-excepted series — then discards the `Vec<i64>`. Change the response `Vec<v0::Event>` → `Vec<v0::EventWithOccurrences { event, occurrences: Vec<i64> }>`. **Reviewer-confirmed:** the engine already applies exceptions (model.rs:395), DST local→UTC, monthly day-clamp (model.rs:361-375) and all-day stepping, and no other consumer reads the list route. | ~10 backend lines + 1 route-test tweak; reuses the pure fn. | None (one engine, server-authoritative). | **Recommended** |
| B | New `GET /events/server/<s>/occurrences?from=&to=` → flat `[{event_id,start}]`; list keeps series. | New route + openapi + test. | None. | Heavier, same result |
| C | Expand in TS (Luxon/Temporal/rrule.js). | Big TS surface. | **High** — re-forks the *policy*; grid can place an occurrence on a different instant than the server serves/reminds. | **Rejected by constraint** |
| D | Compile the Rust engine to WASM. | Build-pipeline weight web/Tauri/Capacitor. | None. | Overkill v1 |

**Recommendation: A** — literally "expose a shared occurrences path"; the server already produced the
array, we stop discarding it. This is the **one backend edit** slice E strictly requires (a slice-B
contract change, so calendar-events-reviewer re-audits the list route + its test).

> **Note — occurrences don't eliminate ALL client date logic** `[fixes calendar HIGH-1]`. A is
> zero recurrence *expansion*, not zero date logic. The **bucketing timezone** still matters:
> - **All-day** occurrences are stored as the UTC instant of *local midnight in the event's
>   timezone* (design §4.1), so they must be bucketed to a calendar day using **wall-clock date in
>   `event.timezone`**, NOT `new Date(ms)` in the viewer's tz — else a viewer west of the creator
>   sees the event a day early. §4.1 pins this.
> - **Timed** occurrences bucket to the **viewer's local day** (stated decision, so day-detail and
>   any future reminder copy stay consistent).

### 0.2 Feature-flag surfacing (minor)

`events_enabled` is **not** in `GET /` (`RevoltFeatures`, **`crates/delta/src/routes/root.rs:45-64`**
— corrected path). `[fixes calendar LOW-3]` Honest precedent: `webhooks` is likewise **not** in
`RevoltFeatures` (webhooks are gated purely server-side), so that precedent actually argues for (ii).
Choose:
- **(i)** add `events: bool` to `RevoltFeatures` (2 lines) → UI hides the nav entry/page when off.
  Client reads `client.configuration?.features.events`, treating `undefined` (older servers) as
  **disabled** `[fixes frontend L4]`.
- **(ii, matches webhooks)** no backend change — the page attempts to load and renders a graceful
  "Events aren't enabled here" empty-state on a `FeatureDisabled` error.

Recommend **(ii)** for consistency with webhooks, *and* keep the defensive error path regardless. (If
you'd rather the nav entry vanish cleanly, pick (i).)

*Decisions needed: 0.1 (A / B / defer) and 0.2 (i / ii).*

---

## 1. Scope / non-goals

**In:** stoat.js bindings (`CalendarEvent` class + `EventCollection` + hydration + RSVP), live
reconciliation from the four slice-C WS variants, and the `ServerEvents.tsx` rewrite (month grid kept;
tag parsing dropped) — create form with recurrence controls + member invite picker; event detail with
status-grouped attendee list + caller RSVP control (Accept / Decline, and when Going a
"Cancel (can't attend)" → NotGoing); optimistic RSVP reconciled against the authoritative response/WS,
failures surfaced.

**Out (slice F):** deleting `serverEvents.ts` / the tag path (kept & coexisting); legacy import;
per-occurrence RSVP; recurrence edge polish.

---

## 2. stoat.js bindings

New files mirror the `ChannelWebhook` triple (class + collection + hydration), wired like the other
collections in `Client.ts`. **`[fixes frontend L3]` the class is named `CalendarEvent`** (not `Event`,
which shadows the DOM global in the JSX-heavy page); the collection is `client.calendarEvents`.

### 2.1 Wire types (`classes/CalendarEvent.ts`, exported)
`stoat-api` (upstream-generated) has no calendar types, so we declare them to match the Rust wire:
`RsvpStatus = "Pending"|"Going"|"NotGoing"`, `Frequency`, `Weekday`, `RecurrenceEnd`
(`{type:"Count",count}` | `{type:"Until",timestamp}`), `RecurrenceRuleData`, `EventData` (serialized
`v0::Event`: `_id`, snake_case, `all_day`, `created_at`, `edited_at`), `EventRsvpData`
(`{user,event,status,invited_by,had_accepted,responded_at?}` — no `created_at` on the wire),
`AttendeeCounts` (`{going,pending,not_going}`), `EventWithContext` (`{event,my_rsvp?,counts}`),
**`AttendeesResponse` (`{attendees: EventRsvpData[]}`)** `[fixes calendar HIGH-2]` — the attendees
route wraps the array, so the binding unwraps `.attendees`; and `EventWithOccurrences`
(`{event: EventData, occurrences: number[]}`, per 0.1-A).

### 2.2 Hydration (`hydration/event.ts` + register in `hydration/index.ts`)
`[fixes frontend H1]` `hydrateInternal` runs a `functions[key]` for **every input key** and **drops**
any key without one (there is NO passthrough — `channelWebhookHydration` defines a function per field).
So `eventHydration` must define a `functions` entry for **every** `EventData` field and a `keyMapping`
covering the renames:
- keyMapping: `_id→id, server→serverId, channel→channelId, creator→creatorId, all_day→allDay,
  created_at→createdAt, edited_at→editedAt`; the remaining fields map to themselves.
- functions: one closure per hydrated key (`id,serverId,channelId,creatorId,title,description,
  location,start,end,allDay,timezone,recurrence,color,cancelled,createdAt,editedAt`) reading the wire
  field. `start/end` stored as raw ms numbers (class exposes `Date`); `recurrence` stored as the
  `RecurrenceRuleData` object; `cancelled` bool.
- `HydratedEvent` also carries `myRsvp?: RsvpStatus` and `counts?: AttendeeCounts`, **not hydrated**
  (no wire key, no `functions` entry) — set only via `updateUnderlyingObject`. The store is a Solid
  merge (`ObjectStorage.set` = `setStore`), so these survive an event-field merge.
- `[fixes calendar MED-3 / frontend H3]` **clearing optionals:** the wire omits `None` optionals
  (`skip_serializing_if=Option::is_none`), and `hydrateInternal` only visits present keys, so a merge
  can't clear a removed field. The collection's upsert (2.4) therefore **normalizes to a complete
  object** — after hydrating, it fills every absent optional (`description,location,end,recurrence,
  color,channelId,editedAt`) with explicit `undefined` before `updateUnderlyingObject`, so the merge
  overwrites a removed field. (Equivalent: `updateUnderlyingObject(id, reconcile(complete))`.)
- Register `event: eventHydration` in the `hydrators` map.
- **Occurrences are NOT on the Event** — window-dependent; returned per query by `listForServer` (2.4).

### 2.3 `CalendarEvent` class (`classes/CalendarEvent.ts`)
Getters over `getUnderlyingObject(id)`: `id, serverId, channelId?, creatorId, title, description?,
location?, start:Date, end?:Date, allDay, timezone, recurrence?, color?, cancelled, createdAt,
editedAt?`, plus `server`/`channel` lookups, and `myRsvp`/`counts`.
Methods (all via the collection's raw-fetch helper — 2.5):
- `edit(data)` → `PATCH /events/event/<id>`; upsert store from the returned `EventData` (2.4 upsert).
- `cancel()` → `DELETE /events/event/<id>`. `[fixes frontend M1]` **optimistic + revert:** snapshot
  `cancelled`, set `true` optimistically, revert + `showError` on rejection; the WS
  `CalendarEventUpdate{cancelled:true}` is the authoritative confirm.
- `invite(userIds[])` → `POST /events/event/<id>/invites`.
- `uninvite(userId)` → `DELETE /events/event/<id>/invites/<userId>`.
- `rsvp(status)` → `PUT /events/event/<id>/rsvp`; returns the reconciled `EventRsvpData`.
- `fetchAttendees({limit?, before?})` → `GET /events/event/<id>/attendees`; **unwraps
  `AttendeesResponse.attendees`** → `EventRsvpData[]` `[fixes calendar HIGH-2]`. `[fixes calendar
  MED-2]` cursor semantics: `before` is a **forward/"after"** cursor — rows are sorted ascending by
  user id and filtered `user > cursor` (rsvp.rs:179-184). To page, pass the **last returned** row's
  `user` id; name the param accordingly in docs to avoid a reverse-paging bug.

### 2.4 `EventCollection` (`collections/EventCollection.ts`, `client.calendarEvents`)
`ClassCollection<CalendarEvent, HydratedEvent>`. `[fixes frontend H2]` because `getOrCreate` is
**create-if-absent** (returns the cached instance untouched), every "upsert" path must, for an
already-present id, call `updateUnderlyingObject(id, complete)` (2.2 normalize) — a **real upsert**,
not bare `getOrCreate`:
- `upsert(data: EventData)` — private helper: `getOrCreate` then `updateUnderlyingObject` with the
  normalized complete `HydratedEvent`; preserves `myRsvp`/`counts` (merge).
- `fetchWithContext(id)` → `GET /events/event/<id>` (`EventWithContext`); upserts the event AND sets
  `myRsvp`+`counts`; returns the CalendarEvent.
- `createForServer(serverId, DataCreateEvent)` → `POST /events/server/<serverId>`; upsert + return.
- `listForServer(serverId, from, to)` → `GET /events/server/<serverId>?from=&to=`
  (`EventWithOccurrences[]`, 0.1-A); **upserts every event** (fresh field values, not create-only) and
  returns `{ event: CalendarEvent, occurrences: number[] }[]` — the window projection, not stored.
  `[fixes calendar LOW-4]` the list is server-capped at `MAX_EVENTS=500`; note it (harmless for the
  ~42-day grid window).

### 2.5 Raw fetch (body-drop + query-drop gotcha)
Per `feedback_stoat_api_body_drop`: `stoat-api`'s typed client only maps params for routes in its
generated tables. For our routes `getPathName` is undefined, so `req()` sends an empty `{}` body AND
drops query params. So **every** calendar route uses raw `fetch`. A collection method (`[fixes
frontend L1]` an **internal** method, not `#private`, so `CalendarEvent` can reach it via
`this.#collection`) reads from the `API` object stoat.js holds (`this.client.api.baseURL`,
`this.client.api.auth` getter — verified `stoat-api/lib/index.js`; `auth` recomputes
`X-Session-Token`/`X-Bot-Token` after the `#updateHeaders` swap):
```
async apiReq(method, path, { body?, query? } = {}) {
  const api = this.client.api as unknown as { baseURL: string; auth: Record<string,string> };
  // [fixes frontend M3] drop undefined/null so we never emit ?before=undefined
  const qs = query
    ? "?" + new URLSearchParams(
        Object.entries(query).filter(([,v]) => v != null).map(([k,v]) => [k, String(v)]))
    : "";
  const res = await fetch(api.baseURL + path + qs, {
    method,
    headers: { ...api.auth, ...(body ? {"Content-Type":"application/json"} : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {                                   // [fixes frontend L2] parse typed error if JSON
    const text = await res.text();
    try { throw JSON.parse(text); } catch { throw text; }
  }
  return res.status === 204 ? null : res.json();
}
```
Query built into the URL ourselves (never through the typed client, which double-`?`s). Absolute
`baseURL` + header auth work identically web/Tauri/Capacitor.

### 2.6 Exports & Client wiring
- `Client.ts`: `readonly calendarEvents = new EventCollection(this)` (beside `channelWebhooks`).
- `classes/index.ts`, `collections/index.ts`: export the class/collection + wire types.
- `Events` map (Client.ts): `calendarEventCreate/Update/Invite: [event: CalendarEvent]` and
  `calendarEventRsvp: [event: CalendarEvent, rsvp: EventRsvpData]`, emitted from v1.ts.

---

## 3. WS reconciliation (`events/v1.ts`)

Add the four slice-C variants to `ServerMessage` + `handleEvent`. Shapes match the serialized backend
enum (client.rs:433-452): `{type:"CalendarEventCreate",event}`, `{type:"CalendarEventUpdate",event}`,
`{type:"CalendarEventInvite",event}` (each `event` = serialized `v0::Event`, `_id`+snake_case);
`{type:"CalendarEventRsvp",rsvp}` (serialized `v0::EventRsvp`, `rsvp.user` top-level).

- **Create / Update / Invite**: `client.calendarEvents.upsert(event)` (2.4 — `getOrCreate` **then**
  normalize+`updateUnderlyingObject`, so removed optionals clear and existing events refresh).
  `[fixes calendar MED-3/frontend H3]` the plan's earlier "full replace" wording is corrected: it is a
  merge over a **complete** normalized object. Update covers soft-cancel (`cancelled===true`). Emit the
  matching client event.
- **Rsvp**: look up the event; if cached and `rsvp.user === client.user?.id`, set `myRsvp`; always emit
  `calendarEventRsvp(event, rsvp)`. `[fixes calendar MED-1]` counts are **not** delta-summed from the
  delta (no prior status, and the attendee page is capped) — the open detail refetches authoritative
  `counts` via `fetchWithContext` (§4.3). If the event isn't cached, ignore.

No bonfire/protocol change; the client trusts topic delivery (design §8 — ViewChannel/`private(uid)` is
the server's boundary) and does not re-authorize.

---

## 4. `ServerEvents.tsx` rewrite

Keep the visual shell (month grid + right panel + styled-components) and `useParams<{server}>()`;
replace the data layer. Legacy `serverEvents.ts` + the `events`-channel tag path are **untouched**
(slice F) — the new page just stops using them.

### 4.1 Data
- `events = createResource(() => [server().id, viewYear(), viewMonth()] as const, ([sid,y,m]) =>
  client.calendarEvents.listForServer(sid, gridStartMs, gridEndMs))`, window = the visible grid's
  first→last cell (includes the spill days already in `calendarDays`). `[fixes frontend M4]` after
  `createForServer` resolves, call `refetch()` explicitly (idempotent with the WS echo, keyed by id) —
  don't depend on the author receiving their own fan-out.
- `[fixes frontend M8]` Subscribe **once** (component scope) to the four calendar client events with
  **named, stored handlers**; each filters by `server().id`; remove them by reference in `onCleanup`
  via `client().removeListener(evt, handler)`. Grid-affecting events (`create/update/invite`) →
  `refetch()`; `rsvp` → the open-detail refresh (§4.3). Debounced so a burst doesn't storm.
- Day dots / per-day lists come from the **occurrences** arrays flattened to `{event, start}`.
  `[fixes calendar HIGH-1]` **bucketing:** all-day occurrences → wall-clock date in `event.timezone`
  (`Intl.DateTimeFormat('en-CA',{timeZone:event.timezone}).format` → `YYYY-MM-DD` key); timed
  occurrences → viewer-local day. No client recurrence expansion.
- **Cancelled events** `[as-built, diff-audit MED]`: the authoritative list
  (`fetch_events_for_server_in_window`) **excludes cancelled series** (backend slice A/B, audited), so a
  cancelled event is *removed* from the grid on the next refetch. The struck-through / `Cancelled`-pill
  rendering still covers (a) the transient live WS-cancel state before the debounced refetch and (b) the
  **open detail** (which holds the instance). Attendees are told via the pushd cancel notification (slice
  D), not a persistent grid marker. Keeping cancelled events visible on the grid would require the list
  route to return them (out-of-scope, audited backend) — deferred; revisit in F if desired.

### 4.2 Create form (gated by create permission)
Existing title/date/time/desc plus:
- **Recurrence**: `None|Daily|Weekly|Monthly`; `interval` (1–52); Weekly → weekday multi-select
  (`by_weekday`); **ends**: `After <count>` **or** `On <date>` (`Until` ms) — a recurring series must
  pick one terminator (design §4.2); default `After 10`.
- **all_day** toggle (hides time inputs; `all_day:true`).
- **timezone** = `Intl.DateTimeFormat().resolvedOptions().timeZone`; `start`/`end` as ms epoch from the
  local date+time. Optional `color`, `location`.
- **Invite picker**: `[fixes frontend M6]` do NOT eager-fetch the whole roster — use
  `server().queryMembersExperimental(query)` (search endpoint, Server.ts:754), lazy on the filter
  input; exclude self. Chosen ids passed to `event.invite([...])` after create.
- Submit → `createForServer` → `[fixes calendar MED-4]` if invitees were chosen, `await event.invite`
  and **surface a partial failure** (don't close the form until invite resolves; on invite error keep
  the form open / toast a retry) so an "event created, nobody invited" state is visible and
  recoverable. Then `refetch()` (§4.1).
- Gate: create UI shown to any member (design §6/H1 = any member may create). `[fixes calendar LOW-1]`
  v1 events are always **server-scoped** (the form has no channel picker → `channel=None`); state this
  invariant. Server remains authoritative; UI gate is UX only.

### 4.3 Event detail
- On open: `event.fetchWithContext()` (fills `myRsvp`+`counts`) and `event.fetchAttendees()` (grouped
  list). `[fixes frontend M5 / calendar MED-1]` on a `calendarEventRsvp` for this event, **debounce**
  then refetch **both** `fetchWithContext` (authoritative `counts`) and the attendee page — never
  derive counts from the capped attendee page.
- **Attendee list grouped by status** (Going / Pending / Not going). `[fixes frontend M5]` resolve
  member display via a **batched** roster (`server().syncMembers()` once) rather than per-row
  fetch-through; row = `displayName` + `avatarURL` (`serverMembers.getByKey({server,user})`).
  `[fixes calendar MED-2]` if `counts.going+pending+not_going > loaded rows`, show a **"load more"**
  that pages with the last row's `user` id (2.3 cursor); reconcile the (possibly truncated) list
  against authoritative `counts`.
- **Caller RSVP control** (only when `myRsvp !== undefined` — the caller was invited; `[fixes calendar
  LOW-4]` the creator has **no** RSVP row unless self-invited, so the organizer won't see this control
  or appear "Going" by default — acknowledged; v1 shows the organizer separately as "Organizer"):
  - `Pending`/`NotGoing` → **Accept**(→Going) / **Decline**(→NotGoing); `Going` → **Cancel (can't
    attend)**(→NotGoing).
  - `[fixes calendar LOW-2]` disable the control entirely when `event.cancelled` (server rejects RSVP
    to a cancelled event — no guaranteed-fail clicks).
  - `[fixes frontend M2]` **optimistic, two-bucket:** snapshot prior `myRsvp` + `counts`; on click move
    BOTH buckets (e.g. Going→NotGoing = `going-1, not_going+1`) and set `myRsvp`; call
    `event.rsvp(status)`; reconcile on the authoritative response/WS echo (idempotent for own row);
    **on failure revert both** and `showError`. No permanently-wrong "you're going".
- **Manage** (creator or ManageChannel): Cancel, invite (reusing the search picker), uninvite
  from a row. **Edit is deferred to slice F** `[diff-audit MED]` — the `CalendarEvent.edit()` binding
  ships in this slice, but the edit *form* (prefill + recurrence-change semantics: clearing exceptions,
  `remove` fields) belongs with F's "recurrence edge hardening". Rest of this line as originally:
  from a row. `[fixes calendar LOW-1]` gate = `event.creatorId === client.user?.id ||
  server().havePermission("ManageChannel")` (valid while events are server-scoped; if a channel is ever
  attached, evaluate `ManageChannel` on that channel). UI gate is UX only.

### 4.4 Empty / disabled states
- Feature off (0.2): (i) hide entry / show "not enabled"; (ii) catch `FeatureDisabled` → same
  empty-state. Either way keep the defensive catch.
- No events in month → existing copy.

---

## 5. Cross-cutting

- **i18n** `[fixes frontend M7]`: every user-facing string via lingui `Trans`/`t`. **Do not carry the
  current hardcoded English `MONTH_NAMES`/`DAY_NAMES` arrays** (ServerEvents.tsx:30-34) or raw
  `placeholder=` strings (`:227,:255`) — render month/weekday/date/time via locale-aware
  `Intl.DateTimeFormat` (correct names + start-of-week per locale); freq/weekday/RSVP-status/button/
  error strings via `t`/`Trans`.
- **Platforms**: raw fetch + `auth` header + absolute `baseURL` + `Intl…timeZone` behave identically on
  web / Tauri / Capacitor (all Chromium/WebView2). No native bridge (server-plaintext, not E2EE). No
  bundled assets / CDN / CSP concerns.
- **Reactivity**: getters read `getUnderlyingObject` (tracked); the month resource keyed on
  `[server.id, year, month]` re-runs only on explicit `refetch`, not on store mutation; WS handlers
  mutate through the store (`upsert`) so the grid updates without manual refresh.
- **Lifecycle**: the only listeners are the four `client.on(...)`; stored by reference and removed in
  `onCleanup` — no leak/double-subscribe across server navigation.

---

## 6. Testing / verification

- `pnpm -F stoat.js build` + client typecheck green.
- **Browser** via `mise dev` (Vite in WSL — `feedback_vite_wsl_filewatcher`; edits need the dev
  restart):
  1. one-off event → dot on the day; detail shows it.
  2. weekly recurring (ends after N) → occurrences on the right weekdays this month AND next
     (series anchored before the window) — validates 0.1-A end-to-end.
  3. two sessions: invite member B; B Accepts → Pending→Going live; B "Cancel (can't attend)" →
     Going→NotGoing, `had_accepted` retained.
  4. optimistic failure: RSVP to a just-cancelled event → UI reverts both buckets, error shown, no
     stuck "going".
  5. cancel the event → other session's grid marks it cancelled live.
  6. `[fixes calendar HIGH-1]` all-day event created in a **different tz** renders on the **same
     calendar day** for a viewer in another tz (west-of-creator regression); pick a spring-forward week
     and confirm a timed occurrence lands on the intended local day.
  7. `[fixes calendar MED-2]` an event with >100 RSVPs → attendee "load more" pages correctly; header
     count matches authoritative `counts`, not the loaded page size.
- Legacy tag calendar still parses (coexistence) on a server that used the old path.

---

## 7. Risks & reviewer focus (post-audit)

- **All-day cross-tz off-by-one (calendar HIGH-1)** — the one correctness defect that survives 0.1-A;
  bucket all-day by `event.timezone`. Reviewer confirms no `new Date(ms)`-in-viewer-tz for all-day.
- **Binding correctness (frontend H1/H2/H3)** — hydration defines a function per field + full
  keyMapping; list/create/fetch do a **real upsert**; optionals normalized so a removed field clears.
- **Counts authoritative** — refetch via `fetchWithContext`, never delta-summed or derived from the
  capped attendee page.
- **Optimistic RSVP/cancel** — two-bucket move + revert-on-failure + idempotent WS echo.
- **Wire shapes** — `AttendeesResponse.attendees` unwrap; `before` = forward cursor.
- **Raw fetch** — undefined query params filtered; body+query bypass the typed client;
  `X-Session-Token` present; absolute URL.
- **Gating** — UI gates are UX only; server (`authorize_view`/`authorize_manage`, live-membership RSVP
  recheck rsvp.rs:139) is the authority. v1 events server-scoped.
- **Coexistence** — legacy `serverEvents.ts` untouched.

---

## 8. File-by-file change list

**stoat.js**
- `src/classes/CalendarEvent.ts` — new: wire types + `CalendarEvent` class + methods.
- `src/collections/EventCollection.ts` — new: collection + `upsert` + raw-fetch `apiReq`.
- `src/hydration/event.ts` — new: `HydratedEvent` + `eventHydration` (function per field).
- `src/hydration/index.ts` — register `event`.
- `src/classes/index.ts`, `src/collections/index.ts` — export new class/collection + types.
- `src/Client.ts` — add `calendarEvents`; extend `Events` map + emit.
- `src/events/v1.ts` — 4 new `ServerMessage` variants + `handleEvent` cases (upsert).

**client**
- `src/interface/ServerEvents.tsx` — rewrite onto `client.calendarEvents` (grid kept, i18n via `Intl`).
- `src/lib/serverEvents.ts` — **untouched** (slice F).

**backend (the single resolved edit — 0.1-A)**
- `crates/core/models/src/v0/calendar_events.rs` add `EventWithOccurrences`;
  `crates/delta/src/routes/events/events_crud.rs` `list_events` returns `Vec<EventWithOccurrences>`
  (reuse the already-computed `occurrences_in_window` result); update the list route test.
- *(0.2 resolved as ii — no `RevoltFeatures` change; the page catches `FeatureDisabled`.)*

---

## Carried to slice F (from browser verification, 2026-07-09)

> **Resolved in slice F** (2026-07-09, `calendar-events-slice-f-plan.md`): role-based group
> invites landed as the server-side `{users?, roles?}` expansion (decision 0.1-A); the edit form,
> legacy import, cancelled-on-grid (0.2-A) and the deferred slice-D LOWs all shipped there.

- **Role-based group invites** (operator request): the invite search should match server *role* names
  alongside member names — picking "Raid group 1" invites everyone currently holding that role
  (client-side expansion → existing `users:[]` invite route, ≤100/batch, dedup vs attendees; consider a
  server-side `POST /invites {role}` variant for large servers). Roles are the grouping primitive — no
  new backend model.
- **Live-verification fixes applied during E** (for the record): `queryMembersExperimental` raw-fetch
  (typed client appended a literal `?` to the embedded query — server searched `"simtendo?"`);
  case-insensitive member-name matching in `member_experimental_query.rs` (upstream matcher was
  case-sensitive `contains`); lingui macro-`t` cannot be passed into helper fns (weekday/freq/all-day
  labels were blank — weekdays now via `Intl`, freq/all-day labels built in component scope);
  `person_add` affordance on search-result rows.

## Audit trail

- **Diff audit (implemented slice E) — both reviewers, SHIP WITH FIXES; fixes applied.**
  Both confirmed all 13 rev-2 plan-fixes landed correctly (hydration function-per-field, real upsert +
  clear-optionals, optimistic two-bucket RSVP + revert, all-day cross-tz bucketing, forward attendee
  cursor, wire shapes incl. `AttendeesResponse.attendees`, raw-fetch undefined-query filtering,
  listener-by-reference cleanup, i18n via `Intl`, invite via `queryMembersExperimental`) and that the
  0.1-A backend edit expands occurrences once and regresses nothing. **Applied fixes:** debounced the
  WS→detail refresh (storm/race); generic load-error state + Retry (distinct from empty/feature-off);
  reset open-detail/create on server-nav (`createEffect(on(params.server))`); post-uninvite refresh via
  `fetchContext` (counts, not just the page); locale start-of-week (`Intl.Locale` week info) for the
  grid + headers; ±1-day window pad for all-day edge occurrences; capture the client once for
  subscribe/unsubscribe; removed dead `useClientId`; **added invite-from-detail** picker. **Deferred to
  F (plan-amended):** cancelled events drop from the grid on refetch (list excludes cancelled — struck-
  through remains for the transient/open-detail state); the **edit form** (binding ships now, form +
  recurrence-change semantics land with F's recurrence hardening). Client typecheck + stoat.js build
  green.
- **rev 2 (this doc) — audited by both reviewers, SHIP WITH FIXES.**
  - *calendar-events-reviewer* (full-stack): confirmed 0.1-A accurate (list_events discards the
    `occurrences_in_window` result; engine applies exceptions/DST/monthly-clamp/all-day; no other list
    consumer) and the wire/WS shape catalogue correct except HIGH-2. Findings folded: HIGH-1 all-day
    cross-tz bucketing; HIGH-2 `AttendeesResponse.attendees` unwrap; MED-1 counts via `fetchWithContext`
    not attendee page; MED-2 `before` forward-cursor + wire load-more; MED-3 merge-not-replace / clear
    optionals; MED-4 create→invite partial-failure; LOW-1 manage gate/server-scoped invariant; LOW-2
    disable RSVP on cancelled; LOW-3 root.rs path + webhooks precedent (→ recommend 0.2-ii); LOW-4
    MAX_EVENTS cap + creator-has-no-RSVP-row.
  - *frontend-code-reviewer* (SolidJS/stoat.js): REWORK on the binding section. Folded: H1 hydration
    has no passthrough (function per field + keyMapping server/channel/creator); H2 `getOrCreate`
    doesn't refresh (real upsert); H3 store is a merge (normalize+clear optionals); M1 cancel
    revert-on-failure; M2 two-bucket optimistic counts; M3 `URLSearchParams` drops undefined; M4 explicit
    refetch after create; M5 debounce refetch + batched member sync; M6 invite picker via
    `queryMembersExperimental`; M7 i18n via `Intl` not English arrays; M8 listeners removed by stored
    reference; L1 helper internal not `#private`; L2 parse error body; L3 class named `CalendarEvent`;
    L4 client reads `features.events`, undefined→disabled.
- **rev 1 → rev 2**: incorporated all reviewer findings above; two open decisions (0.1 occurrence path,
  0.2 flag surfacing) remain for operator sign-off before implementation.
</content>
