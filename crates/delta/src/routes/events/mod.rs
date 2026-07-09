use revolt_database::{
    util::permissions::DatabasePermissionQuery, CalendarEvent, Database, EventRsvp, Frequency,
    RecurrenceEnd, RecurrenceRule, RsvpStatus, Weekday,
};
use revolt_models::v0;
use revolt_permissions::{
    calculate_channel_permissions, calculate_server_permissions, ChannelPermission,
};
use revolt_result::{create_error, Result};
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod events_crud;
mod rsvp;
#[cfg(test)]
mod tests;

/// All calendar/events routes sit behind the operator feature flag.
pub async fn require_events_enabled() -> Result<()> {
    if !revolt_config::config().await.features.events_enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "events".to_string()
        }));
    }
    Ok(())
}

// ----- Authorization helpers ---------------------------------------------------

/// The caller may VIEW an event iff they are a member of its server and, when the
/// event names a channel, hold `ViewChannel` there (design §6/§8, finding C1).
pub async fn authorize_view(db: &Database, user: &revolt_database::User, event: &CalendarEvent) -> Result<()> {
    if let Some(channel_id) = &event.channel {
        let channel = db.fetch_channel(channel_id).await?;
        let mut query = DatabasePermissionQuery::new(db, user).channel(&channel);
        calculate_channel_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    } else {
        // Server-wide event: membership is sufficient.
        db.fetch_member(&event.server, &user.id)
            .await
            .map_err(|_| create_error!(NotFound))?;
    }
    Ok(())
}

/// The caller may MANAGE an event iff they created it OR hold `ManageChannel`
/// (evaluated on the event's channel, or server-wide when it has none) (design §6).
pub async fn authorize_manage(db: &Database, user: &revolt_database::User, event: &CalendarEvent) -> Result<()> {
    if user.id == event.creator {
        return Ok(());
    }
    if let Some(channel_id) = &event.channel {
        let channel = db.fetch_channel(channel_id).await?;
        let mut query = DatabasePermissionQuery::new(db, user).channel(&channel);
        calculate_channel_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
    } else {
        let server = db.fetch_server(&event.server).await?;
        let mut query = DatabasePermissionQuery::new(db, user).server(&server);
        calculate_server_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
    }
    Ok(())
}

// ----- db <-> wire conversion --------------------------------------------------

pub fn freq_to_wire(f: Frequency) -> v0::Frequency {
    match f {
        Frequency::Daily => v0::Frequency::Daily,
        Frequency::Weekly => v0::Frequency::Weekly,
        Frequency::Monthly => v0::Frequency::Monthly,
    }
}

pub fn freq_from_wire(f: v0::Frequency) -> Frequency {
    match f {
        v0::Frequency::Daily => Frequency::Daily,
        v0::Frequency::Weekly => Frequency::Weekly,
        v0::Frequency::Monthly => Frequency::Monthly,
    }
}

pub fn weekday_to_wire(w: Weekday) -> v0::Weekday {
    match w {
        Weekday::Monday => v0::Weekday::Monday,
        Weekday::Tuesday => v0::Weekday::Tuesday,
        Weekday::Wednesday => v0::Weekday::Wednesday,
        Weekday::Thursday => v0::Weekday::Thursday,
        Weekday::Friday => v0::Weekday::Friday,
        Weekday::Saturday => v0::Weekday::Saturday,
        Weekday::Sunday => v0::Weekday::Sunday,
    }
}

pub fn weekday_from_wire(w: v0::Weekday) -> Weekday {
    match w {
        v0::Weekday::Monday => Weekday::Monday,
        v0::Weekday::Tuesday => Weekday::Tuesday,
        v0::Weekday::Wednesday => Weekday::Wednesday,
        v0::Weekday::Thursday => Weekday::Thursday,
        v0::Weekday::Friday => Weekday::Friday,
        v0::Weekday::Saturday => Weekday::Saturday,
        v0::Weekday::Sunday => Weekday::Sunday,
    }
}

pub fn recurrence_to_wire(r: RecurrenceRule) -> v0::RecurrenceRule {
    v0::RecurrenceRule {
        freq: freq_to_wire(r.freq),
        interval: r.interval,
        by_weekday: r.by_weekday.into_iter().map(weekday_to_wire).collect(),
        end: match r.end {
            RecurrenceEnd::Count { count } => v0::RecurrenceEnd::Count { count },
            RecurrenceEnd::Until { timestamp } => v0::RecurrenceEnd::Until { timestamp },
        },
        exceptions: r.exceptions,
    }
}

pub fn recurrence_from_wire(r: v0::RecurrenceRule) -> RecurrenceRule {
    RecurrenceRule {
        freq: freq_from_wire(r.freq),
        interval: r.interval,
        by_weekday: r.by_weekday.into_iter().map(weekday_from_wire).collect(),
        end: match r.end {
            v0::RecurrenceEnd::Count { count } => RecurrenceEnd::Count { count },
            v0::RecurrenceEnd::Until { timestamp } => RecurrenceEnd::Until { timestamp },
        },
        exceptions: r.exceptions,
    }
}

pub fn status_to_wire(s: RsvpStatus) -> v0::RsvpStatus {
    match s {
        RsvpStatus::Pending => v0::RsvpStatus::Pending,
        RsvpStatus::Going => v0::RsvpStatus::Going,
        RsvpStatus::NotGoing => v0::RsvpStatus::NotGoing,
    }
}

pub fn status_from_wire(s: v0::RsvpStatus) -> RsvpStatus {
    match s {
        v0::RsvpStatus::Pending => RsvpStatus::Pending,
        v0::RsvpStatus::Going => RsvpStatus::Going,
        v0::RsvpStatus::NotGoing => RsvpStatus::NotGoing,
    }
}

pub fn event_to_wire(e: CalendarEvent) -> v0::Event {
    v0::Event {
        id: e.id,
        server: e.server,
        channel: e.channel,
        creator: e.creator,
        title: e.title,
        description: e.description,
        location: e.location,
        start: e.start,
        end: e.end,
        all_day: e.all_day,
        timezone: e.timezone,
        recurrence: e.recurrence.map(recurrence_to_wire),
        color: e.color,
        cancelled: e.cancelled,
        created_at: e.created_at,
        edited_at: e.edited_at,
    }
}

pub fn rsvp_to_wire(r: EventRsvp) -> v0::EventRsvp {
    v0::EventRsvp {
        user: r.id.user,
        event: r.id.event,
        status: status_to_wire(r.status),
        invited_by: r.invited_by,
        had_accepted: r.had_accepted,
        responded_at: r.responded_at,
    }
}

/// The real-time topic an event publishes to: its channel (only ViewChannel
/// subscribers receive it — finding C1) when channel-scoped, else the server
/// (all members). The topic is the authorization boundary.
pub fn event_topic(event: &CalendarEvent) -> String {
    event
        .channel
        .clone()
        .unwrap_or_else(|| event.server.clone())
}

/// Tally RSVP rows by status.
pub fn tally(rsvps: &[EventRsvp]) -> v0::AttendeeCounts {
    let mut counts = v0::AttendeeCounts {
        going: 0,
        pending: 0,
        not_going: 0,
    };
    for r in rsvps {
        match r.status {
            RsvpStatus::Going => counts.going += 1,
            RsvpStatus::Pending => counts.pending += 1,
            RsvpStatus::NotGoing => counts.not_going += 1,
        }
    }
    counts
}

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        events_crud::create_event,
        events_crud::list_events,
        events_crud::fetch_event,
        events_crud::edit_event,
        events_crud::cancel_event,
        rsvp::invite_to_event,
        rsvp::uninvite_from_event,
        rsvp::set_rsvp,
        rsvp::fetch_attendees,
    ]
}
