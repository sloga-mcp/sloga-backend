# Calendar Events — Slice G: Event Attachments

**Status:** IMPLEMENTED + REVIEWER-AUDITED + FIXED 2026-07-15 (uncommitted) — awaiting
live browser-verify + commit. `calendar-events-reviewer` verdict = SHIP WITH FIXES;
**all findings addressed** (see below). Backend clippy-clean (no new warnings); stoat.js
builds (tsc); frontend type-clean (8 pre-existing client TS errors unrelated).

**Tests (post-fix):** 24 calendar DB + 19 events route green under BOTH
`TEST_DB=REFERENCE` and `TEST_DB=MONGODB` (WSL). Full delta REFERENCE suite: 218 passed,
0 new failures (14 pre-existing env failures = account SMTP/captcha + 1 mls flag, modules
untouched). 76 revolt-database tests green (confirms the Reference-mock change is safe).

**Audit findings & resolutions:**
- **[HIGH] edit mutated files before validating the event** → FIXED: `edit_event` now
  checks the cap, then runs `event.edit` (full validator: tz/time/recurrence) and
  PERSISTS, and only THEN claims/detaches files. New regression test
  `edit_validation_failure_leaves_attachments_untouched` (bad tz + attachment change →
  rejected, f1 not deleted, f2 not claimed).
- **[MED] Reference mock didn't enforce claim-once** → FIXED: Reference
  `find_and_use_attachment` now requires `used_for.is_none()` (mirrors Mongo's
  `{$exists:false}`); the reuse-reject test is un-gated and runs on both drivers. Verified
  no regression across 76 DB + 218 delta tests.
- **[LOW] create-path partial-claim orphan** → FIXED: new `claim_event_attachments`
  helper marks already-claimed ids deleted on a mid-list failure; create also deletes the
  just-created event on ANY attachment failure (no empty event, no orphaned files).
- **[LOW] cap literal decoupled from constant** → FIXED: create re-checks `ids.len()`
  against `MAX_EVENT_ATTACHMENTS` (the DTO literal stays as belt-and-suspenders/OpenAPI).
- **[LOW] frontend filename fallback not localized** → FIXED: `t\`file\`` in `AttachmentItem`.
- Reviewer's clean-bill items (authz inherits view/manage, fan-out audience, opt_some_priority
  handling, cascades/no-hard-delete, frontend store consistency) unchanged.

**As-built notes / findings for the reviewer:**
- The Reference driver's `find_and_use_attachment` does NOT enforce claim-once (it
  overwrites `used_for` unconditionally); only the Mongo driver filters on
  `used_for: {$exists:false}`. Pre-existing driver-parity gap affecting ALL attachment
  claiming (messages included), so the reuse-rejection assertion is Mongo-gated
  (`create_with_attachments_visible_to_members`). Consider a follow-up to make the
  Reference mock faithful.
- Create claims attachments via a second write (`create` insert → claim → `update_event`)
  to keep `CalendarEvent::create`'s signature stable; a failed claim leaves the event
  without attachments (surfaced to the caller). Edit claims-before-detach so a bad add id
  fails with no side effects; cap is checked before any mutation.
- Frontend clears attachments by detaching each id (`remove_attachments`), not via
  `remove:["Attachments"]`; the server unsets the field when the resulting set is empty.

---

**Original plan (rev 1) below.**

## Goal

Let an event carry file attachments (agendas, slide decks, maps, images) that anyone
who can already view the event can see and download. Files are uploadable at create time
and add/removable afterwards via the edit path.

## Decisions (operator-approved 2026-07-15)

- **0.1 Visibility = inherit the event's existing view rule.** Attachments are visible to
  exactly the audience that can already see the event: server members, plus `ViewChannel`
  on the event's channel when it is channel-scoped (`authorize_view`, design §6/§8,
  finding C1). We deliberately do **not** add an invitee-only gate — title/description/
  location are already viewer-visible, so gating only the files would be inconsistent and
  would need a brand-new authz path. Attachments therefore add **no** new authorization
  surface; they ride the existing view/manage split.
- **0.2 Editable after creation.** The existing edit route (creator OR `ManageChannel`,
  `authorize_manage`) may add new files and remove existing ones. Add and remove are
  expressed in the same PATCH.
- **0.3 Reuse the generic `attachments` Autumn bucket** (the same one message uploads use),
  distinguished only by a new `FileUsedForType::CalendarEvent`. No new bucket/tag config,
  no Autumn change. The bucket already enforces per-file size/type limits.
- **0.4 Cap = `MAX_EVENT_ATTACHMENTS` = 10 per event** (constant in the models crate;
  small, bounded, not operator-configurable in v1). Enforced on both create and the
  post-edit total.

## Data model — `crates/core/database/src/models/calendar_events/model.rs`

- Add to `CalendarEvent` (and thus `PartialCalendarEvent`):
  ```rust
  /// Files attached to the event; visible to anyone who can view the event.
  /// Freshly-minted `File` docs owned by this event (claimed via
  /// `File::use_calendar_event_attachment`).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub attachments: Option<Vec<File>>,
  ```
  (`File` is already re-exported from the database crate; messages embed `Option<Vec<File>>`
  the same way — `messages/model.rs:51`.)
- Add `FieldsCalendarEvent::Attachments` and handle it in `remove_field` (`self.attachments = None`).
- `create(...)` gains no attachment logic itself — claiming happens at the route (mirrors
  messages, where `Message::create_no_web_push` claims). `create` keeps `attachments: None`;
  the route sets it after claiming so the derived-field / validate flow is untouched.
- `edit(...)`: attachments are **not** a time-affecting field — adding/removing a file must
  not clear recurrence exceptions. Claiming/unclaiming happens at the route (see below); the
  edit path only persists the resulting `attachments` vec. Keep the claim work out of the
  pure `edit` recompute so `series_end`/`duration_ms` logic is unaffected.

## File claim helper — `crates/core/database/src/models/files/model.rs`

- New `FileUsedForType::CalendarEvent` variant (`files/model.rs:63`).
- New helper:
  ```rust
  pub async fn use_calendar_event_attachment(
      db: &Database, id: &str, parent: &str, uploader_id: &str,
  ) -> Result<File> {
      db.find_and_use_attachment(
          id, "attachments",
          FileUsedFor { id: parent.to_owned(), object_type: FileUsedForType::CalendarEvent },
          uploader_id.to_owned(),
      ).await
  }
  ```
  `find_and_use_attachment` already enforces claim-once (`used_for` must be absent) and
  tag match, so a re-used or foreign file id fails with `NotFound` — same guarantee messages
  get.

## Wire / DTO — `crates/core/models/src/v0/calendar_events.rs`

- `Event`: add `#[serde(skip_serializing_if = "Option::is_none")] pub attachments: Option<Vec<File>>`
  (`v0::File`, already used across the models crate).
- `DataCreateEvent`: add `#[serde(default)] pub attachments: Option<Vec<String>>` (file ids),
  validated `length(max = 10)`.
- `DataEditEvent`: add `#[serde(default)] pub attachments: Option<Vec<String>>` — file ids to
  **add** — plus `remove: Vec<FieldsEvent>` gains a variant for wholesale clearing, and a new
  `#[serde(default)] pub remove_attachments: Option<Vec<String>>` (file ids to detach).
  Rationale: attachments are a set; "add these, drop those" is clearer and more idempotent
  than a full replace, and avoids re-claiming already-attached files.
- `FieldsEvent`: add `Attachments` (unset all).
- Update `field_from_wire` (`events_crud.rs`) and `event_to_wire` (`mod.rs:160`) for the new
  field. `event_to_wire` maps `Option<Vec<File>>` → `Option<Vec<v0::File>>` via `.into()`.

## Routes — `crates/delta/src/routes/events/events_crud.rs`

- **create_event**: after `CalendarEvent::create(...)`, if `data.attachments` is non-empty:
  claim each id via `File::use_calendar_event_attachment(db, id, &event.id, &user.id)`, cap at
  `MAX_EVENT_ATTACHMENTS`, set `event.attachments`, and persist with a `PartialCalendarEvent`
  update. (A failed claim → `NotFound`; the event already exists, so surface the error — the
  organizer can retry the file. Matches message behaviour where a bad attachment id fails the
  send.)
- **edit_event**: gate on `authorize_manage` as today. Compute the resulting set:
  start from `event.attachments`, drop ids in `remove_attachments` (and mark those files
  deleted via `mark_attachments_as_deleted`), claim ids in `attachments`, enforce the total
  ≤ `MAX_EVENT_ATTACHMENTS`, then persist. `FieldsEvent::Attachments` in `remove` clears all
  (and deletes the files). Do this **outside** the pure `edit` recompute (attachments aren't
  time-affecting).
- Both already fan out `CalendarEventCreate` / `CalendarEventUpdate` carrying the full
  `event_to_wire` — attachments ride along automatically to ViewChannel/server subscribers.

## Lifecycle / cascades — `crates/core/database/src/models/calendar_events/ops*`

The files crate keeps orphaned files until marked deleted (crond sweeps deleted files).
Add attachment cleanup to the existing cascades so event files don't leak (mirrors the
slice-F F4 cascades and the message-delete attachment cleanup):

- **cancel_event**: soft-cancel keeps the event + RSVPs; **keep** attachments too (attendees
  may still want the agenda for a just-cancelled meeting). No file deletion on cancel.
- **server delete cascade** (`delete_calendar_for_server`): collect attachment file ids from
  the server's events and `mark_attachments_as_deleted` before/with dropping the events.
- **account delete**: events are keyed by server, not deleted per-user; no change (the
  creator leaving doesn't delete their events — consistent with existing behaviour).
- There is no hard event-delete route today (only soft-cancel), so no per-event file GC is
  needed beyond the server cascade. Note this explicitly for the reviewer.

## stoat.js — `packages/stoat.js`

- `classes/CalendarEvent.ts`: add `attachments?: File[]` to wire types + class, hydrate it
  (`hydration/event.ts`, function-per-field, normalise absent→`undefined`), and expose a
  `get attachments()` returning `File` model instances (there is an existing `File` class in
  stoat.js for message attachments — reuse it for URL/metadata rendering).
- `createForServer` / `edit` already pass the data object through raw `apiReq` (body bypasses
  the typed client — see slice-E notes / `feedback_stoat_api_body_drop`); just include the new
  fields.
- Rebuild (`pnpm --filter stoat.js build`) — the client consumes built `lib/`.

## Frontend — `packages/client/src/interface/ServerEvents.tsx`

- **CreateForm**: a file picker (`<input type="file" multiple>`), each selected file uploaded
  immediately via `client().uploadFile("attachments", file)` (`Client.ts:684`) → collect ids;
  show pending/uploaded chips with a remove-before-submit affordance; pass ids in
  `data.attachments`. Enforce the 10-file cap client-side too.
- **Edit mode**: show existing attachments with remove buttons (→ `remove_attachments`) and the
  same picker for new uploads (→ `attachments`). Diff builder adds only the changed sets.
- **Detail view**: render the attachment list — image previews inline, other types as a
  download row (filename + size), linking to the Autumn URL the `File` model already exposes.
  Reuse the message-attachment rendering component if one is exported; otherwise a minimal list.
- Lingui: build any labels in component scope (slice-E landmine: macro-`t` passed into helpers
  compiles to nothing).

## Tests

- **DB (models)**: round-trip an event with attachments; `remove_field(Attachments)` clears;
  edit that adds/removes attachments does **not** clear recurrence exceptions; server cascade
  marks attachment files deleted.
- **Claim**: `use_calendar_event_attachment` claims once; a second claim of the same id fails;
  a wrong-tag id fails.
- **Route** (`events/tests.rs`): create-with-attachments; edit add/remove; cap enforcement
  (11th rejected); non-manager cannot edit attachments; a non-viewer's list omits the event
  (unchanged authz, but assert attachments don't leak).
- Run `TEST_DB=REFERENCE cargo nextest run` + the Mongo-gated subset in WSL
  (`feedback_mongo_tests_wsl_only`).

## Open questions for the reviewer

1. **remove_attachments vs. full replace** on edit — plan proposes add-set + remove-set. Confirm
   this over a replace-the-whole-list PATCH (idempotency + avoiding re-claim was the driver).
2. **Cancel keeps files** — confirm we don't GC attachments on soft-cancel (attendee access to a
   just-cancelled meeting's materials vs. storage). Server-delete still GCs.
3. **Cap of 10** and reusing the `attachments` bucket size limits (no event-specific size cap).
4. Whether the reviewer wants an event-attachment **size** budget separate from the per-file
   bucket limit (e.g. total-bytes cap), or the count cap suffices for v1.

## Files touched (summary)

- `crates/core/database/src/models/calendar_events/model.rs` — field, `FieldsCalendarEvent`, remove_field
- `crates/core/database/src/models/calendar_events/ops*.rs` — server-cascade file cleanup
- `crates/core/database/src/models/files/model.rs` — `FileUsedForType::CalendarEvent` + claim helper
- `crates/core/models/src/v0/calendar_events.rs` — wire `Event`, DTOs, `FieldsEvent`
- `crates/delta/src/routes/events/events_crud.rs` — claim/unclaim in create + edit, `field_from_wire`
- `crates/delta/src/routes/events/mod.rs` — `event_to_wire`
- `packages/stoat.js/src/classes/CalendarEvent.ts`, `hydration/event.ts`, types
- `packages/client/src/interface/ServerEvents.tsx` — picker, detail render, edit
