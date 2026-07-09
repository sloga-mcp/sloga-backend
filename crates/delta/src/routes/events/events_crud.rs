use revolt_database::{
    events::client::EventV1, occurrences_in_window, util::permissions::DatabasePermissionQuery,
    util::reference::Reference, CalendarEvent, Database, FieldsCalendarEvent, PartialCalendarEvent,
    User,
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
    }
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

    let event = CalendarEvent::create(
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
    )
    .await?;

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
/// Events whose channel the caller cannot view are filtered out.
#[openapi(tag = "Calendar")]
#[get("/server/<server>?<from>&<to>")]
pub async fn list_events(
    db: &State<Database>,
    user: User,
    server: Reference<'_>,
    from: i64,
    to: i64,
) -> Result<Json<Vec<v0::Event>>> {
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
        // Drop series with no real occurrence in the window (e.g. all excepted).
        if occurrences_in_window(&event, from, to).is_empty() {
            continue;
        }
        out.push(super::event_to_wire(event));
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
        ..Default::default()
    };
    let remove = data.remove.into_iter().map(field_from_wire).collect();

    event.edit(db, partial, remove).await?;

    let topic = super::event_topic(&event);
    let wire = super::event_to_wire(event);
    EventV1::CalendarEventUpdate {
        event: wire.clone(),
    }
    .p(topic)
    .await;

    Ok(Json(wire))
}

/// # Cancel Event
///
/// Soft-cancel an event (terminal). RSVP rows are retained so attendees can still
/// be notified. Requires creator or `ManageChannel`.
#[openapi(tag = "Calendar")]
#[delete("/event/<target>")]
pub async fn cancel_event(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    super::require_events_enabled().await?;

    let event = db.fetch_event(target.id).await?;
    super::authorize_manage(db, &user, &event).await?;

    let partial = PartialCalendarEvent {
        cancelled: Some(true),
        ..Default::default()
    };
    db.update_event(&event.id, &partial, vec![]).await?;

    // Reflect the soft-cancel in the fan-out payload so clients mark it cancelled.
    let mut event = event;
    event.cancelled = true;
    let topic = super::event_topic(&event);
    EventV1::CalendarEventUpdate {
        event: super::event_to_wire(event),
    }
    .p(topic)
    .await;

    Ok(EmptyResponse)
}
