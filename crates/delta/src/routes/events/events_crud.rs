use revolt_database::{
    events::client::EventV1,
    events::rabbit::{CalendarEventNotification, CalendarEventPayload},
    occurrences_in_window,
    util::permissions::DatabasePermissionQuery,
    util::reference::Reference,
    CalendarEvent, Database, FieldsCalendarEvent, File, PartialCalendarEvent, RsvpStatus, User,
    AMQP, MAX_EVENT_ATTACHMENTS,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;
use validator::Validate;

/// Max window span for a list query: one year, to bound recurrence expansion.
const MAX_WINDOW_MS: i64 = 366 * 24 * 60 * 60 * 1000;

/// Max number of events returned by a single list query.
const MAX_EVENTS: usize = 500;

fn field_from_wire(f: v0::FieldsEvent) -> FieldsCalendarEvent {
    match f {
        v0::FieldsEvent::Channel => FieldsCalendarEvent::Channel,
        v0::FieldsEvent::Description => FieldsCalendarEvent::Description,
        v0::FieldsEvent::Location => FieldsCalendarEvent::Location,
        v0::FieldsEvent::End => FieldsCalendarEvent::End,
        v0::FieldsEvent::Recurrence => FieldsCalendarEvent::Recurrence,
        v0::FieldsEvent::Color => FieldsCalendarEvent::Color,
        v0::FieldsEvent::Attachments => FieldsCalendarEvent::Attachments,
    }
}

/// Claim every file id as an attachment of `event_id` (slice G). Claim-once + tag
/// match are enforced by `find_and_use_attachment`, so a bad/foreign/already-claimed
/// id fails with `NotFound`. On a mid-list failure the ids already claimed in THIS
/// call are marked deleted (best-effort) so a partial claim never leaks orphaned
/// files, then the error is surfaced. Returns the claimed `File`s on full success.
async fn claim_event_attachments(
    db: &Database,
    ids: &[String],
    event_id: &str,
    uploader_id: &str,
) -> Result<Vec<File>> {
    let mut files: Vec<File> = Vec::with_capacity(ids.len());
    for id in ids {
        match File::use_calendar_event_attachment(db, id, event_id, uploader_id).await {
            Ok(file) => files.push(file),
            Err(error) => {
                let claimed: Vec<String> = files.iter().map(|f| f.id.clone()).collect();
                if !claimed.is_empty() {
                    db.mark_attachments_as_deleted(&claimed).await.ok();
                }
                return Err(error);
            }
        }
    }
    Ok(files)
}

/// # Create Event
///
/// Create a calendar event in a server. Any server member may create; if a channel
/// is named, the caller must be able to view it and it must belong to the server.
#[openapi(tag = "Calendar")]
#[post("/server/<server>", data = "<data>")]
pub async fn create_event(
    db: &State<Database>,
    user: User,
    server: Reference<'_>,
    data: Json<v0::DataCreateEvent>,
) -> Result<Json<v0::Event>> {
    super::require_events_enabled().await?;
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let server = server.as_server(db).await?;
    db.fetch_member(&server.id, &user.id)
        .await
        .map_err(|_| create_error!(NotFound))?;

    if let Some(channel_id) = &data.channel {
        let channel = db.fetch_channel(channel_id).await?;
        if channel.server() != Some(server.id.as_str()) {
            return Err(create_error!(InvalidOperation));
        }
        let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
        calculate_channel_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    }

    let mut event = CalendarEvent::create(
        db,
        server.id.clone(),
        user.id.clone(),
        data.title,
        data.description,
        data.location,
        data.start,
        data.end,
        data.all_day,
        data.timezone,
        data.recurrence.map(super::recurrence_from_wire),
        data.color,
        data.channel,
        None,
    )
    .await?;

    // Claim attachment files (slice G): reuse the generic `attachments` bucket, tagged
    // CalendarEvent and claimed against the freshly-created event id. On ANY attachment
    // failure (over-cap, or a bad/foreign/re-used id) the just-created event is deleted
    // and the partially-claimed files released (`claim_event_attachments`) so a failed
    // create leaves neither an empty event nor orphaned files.
    if let Some(ids) = data.attachments {
        if !ids.is_empty() {
            // Enforce the cap against the constant (the DTO literal must agree, but the
            // constant is the real gate).
            if ids.len() > MAX_EVENT_ATTACHMENTS {
                db.delete_event(&event.id).await.ok();
                return Err(create_error!(FailedValidation {
                    error: "attachments".to_string()
                }));
            }
            match claim_event_attachments(db, &ids, &event.id, &user.id).await {
                Ok(files) => {
                    db.update_event(
                        &event.id,
                        &PartialCalendarEvent {
                            attachments: Some(files.clone()),
                            ..Default::default()
                        },
                        vec![],
                    )
                    .await?;
                    event.attachments = Some(files);
                }
                Err(error) => {
                    db.delete_event(&event.id).await.ok();
                    return Err(error);
                }
            }
        }
    }

    let topic = super::event_topic(&event);
    let wire = super::event_to_wire(event);
    EventV1::CalendarEventCreate {
        event: wire.clone(),
    }
    .p(topic)
    .await;

    Ok(Json(wire))
}

/// # List Events
///
/// List events in a server whose series overlaps the `[from, to]` window (ms epoch).
/// Events whose channel the caller cannot view are filtered out. Each returned series
/// carries its per-occurrence starts within the window (expanded by the server's single
/// DST-aware engine) so the client renders one grid entry per occurrence without
/// re-implementing recurrence math.
#[openapi(tag = "Calendar")]
#[get("/server/<server>?<from>&<to>")]
pub async fn list_events(
    db: &State<Database>,
    user: User,
    server: Reference<'_>,
    from: i64,
    to: i64,
) -> Result<Json<Vec<v0::EventWithOccurrences>>> {
    super::require_events_enabled().await?;

    let server = server.as_server(db).await?;
    db.fetch_member(&server.id, &user.id)
        .await
        .map_err(|_| create_error!(NotFound))?;

    // Checked span: reject inverted or over-cap windows without integer overflow.
    match to.checked_sub(from) {
        Some(span) if (0..=MAX_WINDOW_MS).contains(&span) => {}
        _ => {
            return Err(create_error!(FailedValidation {
                error: "window".to_string()
            }))
        }
    }

    let candidates = db
        .fetch_events_for_server_in_window(&server.id, from, to)
        .await?;

    let mut out = Vec::new();
    for event in candidates {
        // Per-event view filter (finding C1).
        if super::authorize_view(db, &user, &event).await.is_err() {
            continue;
        }
        // Expand occurrences once: drop series with none in the window (e.g. all excepted)
        // and return the same array to the client (0.1-A — no client-side recurrence math).
        let occurrences = occurrences_in_window(&event, from, to);
        if occurrences.is_empty() {
            continue;
        }
        out.push(v0::EventWithOccurrences {
            event: super::event_to_wire(event),
            occurrences,
        });
        if out.len() >= MAX_EVENTS {
            break;
        }
    }

    Ok(Json(out))
}

/// # Fetch Event
///
/// Fetch a single event, the caller's own RSVP, and attendee tallies.
#[openapi(tag = "Calendar")]
#[get("/event/<target>")]
pub async fn fetch_event(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::EventWithContext>> {
    super::require_events_enabled().await?;

    let event = db.fetch_event(target.id).await?;
    super::authorize_view(db, &user, &event).await?;

    let rsvps = db.fetch_rsvps_for_event(&event.id).await?;
    let counts = super::tally(&rsvps);
    let my_rsvp = rsvps
        .into_iter()
        .find(|r| r.id.user == user.id)
        .map(super::rsvp_to_wire);

    Ok(Json(v0::EventWithContext {
        event: super::event_to_wire(event),
        my_rsvp,
        counts,
    }))
}

/// # Edit Event
///
/// Edit an event. Time/recurrence changes recompute derived fields and clear
/// single-occurrence exceptions. Requires creator or `ManageChannel`.
#[openapi(tag = "Calendar")]
#[patch("/event/<target>", data = "<data>")]
pub async fn edit_event(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataEditEvent>,
) -> Result<Json<v0::Event>> {
    super::require_events_enabled().await?;
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut event = db.fetch_event(target.id).await?;
    if event.cancelled {
        return Err(create_error!(InvalidOperation));
    }
    super::authorize_manage(db, &user, &event).await?;

    // ----- validate a channel move up front (before ANY mutation) --------------
    // Same gate as create: the target channel must belong to the event's server
    // and the caller must be able to view it. The fetched channel is reused for
    // the RSVP prune after the edit persists.
    let new_channel = match &data.channel {
        Some(channel_id) => {
            let channel = db.fetch_channel(channel_id).await?;
            if channel.server() != Some(event.server.as_str()) {
                return Err(create_error!(InvalidOperation));
            }
            let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
            calculate_channel_permissions(&mut query)
                .await
                .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
            Some(channel)
        }
        None => None,
    };
    let old_channel = event.channel.clone();
    let pre_edit = event.clone();

    // ----- resolve the attachment plan (slice G) -------------------------------
    // Attachments are NOT time-affecting and must never clear recurrence exceptions,
    // so they are handled separately from the event-field edit below. The cap is
    // checked up front — before ANY mutation (event fields OR files) — so an over-cap
    // request has no side effects.
    let clear_all = data
        .remove
        .iter()
        .any(|f| matches!(f, v0::FieldsEvent::Attachments));
    let add_ids = data.attachments.unwrap_or_default();
    let detach_ids = data.remove_attachments.unwrap_or_default();
    let attachments_changed = clear_all || !add_ids.is_empty() || !detach_ids.is_empty();

    let existing = event.attachments.clone().unwrap_or_default();
    let detach: std::collections::HashSet<&str> = detach_ids.iter().map(|s| s.as_str()).collect();
    // Existing files kept after removals (unchanged when nothing about attachments changed).
    let kept: Vec<File> = if clear_all {
        Vec::new()
    } else {
        existing
            .iter()
            .filter(|f| !detach.contains(f.id.as_str()))
            .cloned()
            .collect()
    };
    if attachments_changed && kept.len() + add_ids.len() > MAX_EVENT_ATTACHMENTS {
        return Err(create_error!(FailedValidation {
            error: "attachments".to_string()
        }));
    }

    // Apply the event-field edit FIRST. `event.edit` runs the full validator (timezone,
    // start/end ordering, recurrence bounds) that the DTO validation does NOT — so it
    // must succeed and PERSIST before any file is claimed or deleted. Were files mutated
    // first, a rejected edit (bad tz/time/recurrence) would leave a detached file marked
    // deleted while the event still referenced it (broken link) and orphan any added
    // files. Attachments are excluded from this partial (resolved below); the wire
    // `Attachments` unset is filtered out of `remove`.
    let partial = PartialCalendarEvent {
        title: data.title,
        description: data.description,
        location: data.location,
        start: data.start,
        end: data.end,
        all_day: data.all_day,
        timezone: data.timezone,
        recurrence: data.recurrence.map(super::recurrence_from_wire),
        color: data.color,
        channel: data.channel,
        ..Default::default()
    };
    let remove: Vec<FieldsCalendarEvent> = data
        .remove
        .into_iter()
        .filter(|f| !matches!(f, v0::FieldsEvent::Attachments))
        .map(field_from_wire)
        .collect();
    event.edit(db, partial, remove).await?;

    // The event is now validated and persisted — safe to mutate files. Claim the new
    // ids (orphan-safe), mark the detached/cleared ones deleted, and persist the
    // resulting set: non-empty via the partial, emptied via the `Attachments` unset
    // (an Option field cannot be set to None via the partial under opt_some_priority).
    if attachments_changed {
        let added = claim_event_attachments(db, &add_ids, &event.id, &user.id).await?;

        let to_delete: Vec<String> = if clear_all {
            existing.iter().map(|f| f.id.clone()).collect()
        } else {
            existing
                .iter()
                .filter(|f| detach.contains(f.id.as_str()))
                .map(|f| f.id.clone())
                .collect()
        };
        if !to_delete.is_empty() {
            db.mark_attachments_as_deleted(&to_delete).await?;
        }

        let mut resolved = kept;
        resolved.extend(added);
        if resolved.is_empty() {
            db.update_event(
                &event.id,
                &PartialCalendarEvent::default(),
                vec![FieldsCalendarEvent::Attachments],
            )
            .await?;
            event.attachments = None;
        } else {
            db.update_event(
                &event.id,
                &PartialCalendarEvent {
                    attachments: Some(resolved.clone()),
                    ..Default::default()
                },
                vec![],
            )
            .await?;
            event.attachments = Some(resolved);
        }
    }

    // ----- fan-out ---------------------------------------------------------------
    // A channel change moves the event between real-time topics (the topic IS the
    // authorization boundary). The OLD audience is told the event moved — but with
    // the pre-edit content plus only the new channel pointer, so a same-PATCH
    // title/description edit never reaches users who just lost visibility. Clients
    // drop events whose channel they cannot resolve.
    let channel_changed = old_channel != event.channel;
    if channel_changed {
        let mut moved = pre_edit;
        moved.channel = event.channel.clone();
        let old_topic = old_channel.unwrap_or_else(|| moved.server.clone());
        EventV1::CalendarEventUpdate {
            event: super::event_to_wire(moved),
        }
        .p(old_topic)
        .await;
    }

    let topic = super::event_topic(&event);
    let wire = super::event_to_wire(event.clone());
    EventV1::CalendarEventUpdate {
        event: wire.clone(),
    }
    .p(topic)
    .await;

    // ----- RSVP prune on a narrowing move ---------------------------------------
    // Users who cannot view the new channel would otherwise be stranded: still
    // `Going`, still reminded every occurrence, unable to open the event. Drop
    // their rows (same semantics as uninvite; the reminder daemon then skips
    // them). A widening move (channel cleared) strands nobody — skip.
    if channel_changed {
        if let Some(channel) = &new_channel {
            if let Ok(rsvps) = db.fetch_rsvps_for_event(&event.id).await {
                for rsvp in rsvps {
                    let uid = rsvp.id.user;
                    let visible = match db.fetch_user(&uid).await {
                        Ok(target) => {
                            let mut query =
                                DatabasePermissionQuery::new(db, &target).channel(channel);
                            calculate_channel_permissions(&mut query)
                                .await
                                .has_channel_permission(ChannelPermission::ViewChannel)
                        }
                        Err(_) => false,
                    };
                    if !visible {
                        db.delete_rsvp(&event.id, &uid).await.ok();
                    }
                }
            }
        }
    }

    Ok(Json(wire))
}

/// Lock the soft-res sheet linked to a cancelled event, if any — a
/// cancelled raid freezes its sheet. Best-effort (a sheet-side failure
/// must never fail a cancel), exactly-once via the atomic lock flip (it
/// may lose to a concurrent manual lock; the sheet ends up locked either
/// way), and only the winner fans out the update.
async fn lock_linked_softres_sheet(db: &Database, event_id: &str) {
    if let Ok(Some(sheet)) = db.fetch_sheet_by_event(event_id).await {
        if let Ok(true) = db.set_sheet_locked_if_unlocked(&sheet.id).await {
            if let Ok(fresh) = db.fetch_sheet(&sheet.id).await {
                let _ = crate::util::softres::publish_sheet_update(db, fresh).await;
            }
        }
    }
}

/// # Cancel Event
///
/// Soft-cancel an event (terminal). RSVP rows are retained so attendees can still
/// be notified. Requires creator or `ManageChannel`.
#[openapi(tag = "Calendar")]
#[delete("/event/<target>")]
pub async fn cancel_event(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    super::require_events_enabled().await?;

    let mut event = db.fetch_event(target.id).await?;
    super::authorize_manage(db, &user, &event).await?;

    // Idempotent: a re-issued DELETE on an already-cancelled event is a no-op. Without
    // this, each retry/double-cancel would re-notify every attendee (cancel is terminal,
    // design §7); the cancel path has no per-send marker like reminders do.
    if event.cancelled {
        // Still heal the linked soft-res sheet: a sheet created in the
        // cancel's fetch→insert race window can exist unlocked against an
        // already-cancelled event, and only a retried cancel passes here.
        // The lock arbitration is exactly-once, so repeats are free.
        lock_linked_softres_sheet(db, &event.id).await;
        return Ok(EmptyResponse);
    }

    let partial = PartialCalendarEvent {
        cancelled: Some(true),
        ..Default::default()
    };
    db.update_event(&event.id, &partial, vec![]).await?;
    event.cancelled = true;

    // Reflect the soft-cancel in the fan-out payload so clients mark it cancelled.
    let topic = super::event_topic(&event);
    EventV1::CalendarEventUpdate {
        event: super::event_to_wire(event.clone()),
    }
    .p(topic)
    .await;

    // A cancelled raid freezes its soft-res sheet: lock the linked sheet
    // (if any) exactly once and fan the update out. This is the only
    // events→softres coupling and it runs AFTER the cancel commits.
    lock_linked_softres_sheet(db, &event.id).await;

    // Notify Going attendees AFTER the cancel commits (finding H6). The soft-cancel keeps
    // the RSVP rows, so the notify-list is intact when gathered here — and notifying only
    // after a successful write avoids announcing a cancellation that did not persist.
    // Delivery is by user id (pushd is authoritative for Going rows), so an attendee who
    // lost ViewChannel — and is thus off the channel WS topic above — is still told;
    // a user who fully left / was banned is filtered out (their Going row is stale).
    if let Ok(rsvps) = db.fetch_rsvps_for_event(&event.id).await {
        for rsvp in rsvps {
            if !matches!(rsvp.status, RsvpStatus::Going) {
                continue;
            }
            if db.fetch_member(&event.server, &rsvp.id.user).await.is_err() {
                continue;
            }
            // Best-effort: a push failure must not fail the cancel.
            amqp.calendar_event_notify(&CalendarEventPayload {
                user: rsvp.id.user,
                event_id: event.id.clone(),
                server_id: event.server.clone(),
                title: event.title.clone(),
                kind: CalendarEventNotification::Cancelled,
                occurrence_start: None,
                channel_id: event.channel.clone(),
                offset_ms: None,
            })
            .await
            .ok();
        }
    }

    Ok(EmptyResponse)
}
