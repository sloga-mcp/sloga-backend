use revolt_database::{
    events::client::EventV1,
    events::rabbit::{CalendarEventNotification, CalendarEventPayload},
    util::permissions::DatabasePermissionQuery,
    util::reference::Reference,
    Database, EventRsvp, RsvpStatus, User, AMQP,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;
use validator::Validate;

/// Max attendees returned per page.
const MAX_ATTENDEES_PAGE: usize = 100;

/// # Invite Users
///
/// Invite server members to an event, by user id and/or by role (each named role's
/// CURRENT holders are expanded server-side — slice F, decision 0.1-A; an unknown
/// role fails the whole request before any insert). Insert-if-absent: re-inviting a
/// user who already answered is a no-op. Non-members — and, for a channel-scoped
/// event, members who cannot view that channel — are skipped and counted. Requires
/// manage.
#[openapi(tag = "Calendar")]
#[post("/event/<target>/invites", data = "<data>")]
pub async fn invite_to_event(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataInviteToEvent>,
) -> Result<Json<v0::InviteResult>> {
    super::require_events_enabled().await?;
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let users = data.users.unwrap_or_default();
    let roles = data.roles.unwrap_or_default();
    if users.is_empty() && roles.is_empty() {
        return Err(create_error!(FailedValidation {
            error: "users_or_roles".to_string()
        }));
    }

    let event = db.fetch_event(target.id).await?;
    if event.cancelled {
        return Err(create_error!(InvalidOperation));
    }
    super::authorize_manage(db, &user, &event).await?;

    // Role expansion: every role must exist on the server (a typo'd/deleted role is
    // a hard error, not a silent no-op), then its current holders join the invite
    // set. Dedup across users∩roles and role∩role via the set.
    let mut invitees: std::collections::HashSet<String> = users.into_iter().collect();
    if !roles.is_empty() {
        let server = db.fetch_server(&event.server).await?;
        for role_id in &roles {
            if !server.roles.contains_key(role_id) {
                return Err(create_error!(NotFound));
            }
        }
        for member in db
            .fetch_all_members_with_roles(&event.server, &roles)
            .await?
        {
            invitees.insert(member.id.user);
        }
    }

    // For a channel-scoped event, an invitee must be able to view that channel —
    // otherwise they would be "invited but cannot open" (keeps invite/view/RSVP
    // consistent, and avoids an invite push for an event they can never see).
    let channel = match &event.channel {
        Some(channel_id) => Some(db.fetch_channel(channel_id).await?),
        None => None,
    };

    let mut invited = 0usize;
    let mut skipped = 0usize;
    let wire = super::event_to_wire(event.clone());
    for uid in &invitees {
        // REQUIRED even for role-expanded members: `fetch_all_members_with_roles`
        // does not filter `pending_deletion_at`, so this re-check is the only thing
        // keeping a soft-deleted member from being re-invited (slice-F audit).
        if db.fetch_member(&event.server, uid).await.is_err() {
            skipped += 1;
            continue;
        }
        if let Some(channel) = &channel {
            let target_user = match db.fetch_user(uid).await {
                Ok(u) => u,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            let mut query = DatabasePermissionQuery::new(db, &target_user).channel(channel);
            if !calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::ViewChannel)
            {
                skipped += 1;
                continue;
            }
        }
        // Only fan out an invite for a genuinely new invitee (insert-if-absent → true).
        if EventRsvp::invite(db, &event.id, uid, &user.id).await? {
            invited += 1;
            EventV1::CalendarEventInvite {
                event: wire.clone(),
            }
            .private(uid.clone())
            .await;

            // Push the invite (offline-agnostic); best-effort — a push failure must not
            // fail the invite. The invitee just passed the ViewChannel gate above.
            amqp.calendar_event_notify(&CalendarEventPayload {
                user: uid.clone(),
                event_id: event.id.clone(),
                server_id: event.server.clone(),
                title: event.title.clone(),
                kind: CalendarEventNotification::Invited,
                occurrence_start: None,
                channel_id: event.channel.clone(),
                offset_ms: None,
            })
            .await
            .ok();
        } else {
            // Already had an RSVP row — re-invites never reset an answer (finding H5).
            skipped += 1;
        }
    }

    Ok(Json(v0::InviteResult { invited, skipped }))
}

/// # Uninvite User
///
/// Remove a user's invite/RSVP from an event. Requires manage.
#[openapi(tag = "Calendar")]
#[delete("/event/<target>/invites/<member>")]
pub async fn uninvite_from_event(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    member: Reference<'_>,
) -> Result<EmptyResponse> {
    super::require_events_enabled().await?;

    let event = db.fetch_event(target.id).await?;
    super::authorize_manage(db, &user, &event).await?;

    db.delete_rsvp(&event.id, member.id).await?;
    Ok(EmptyResponse)
}

/// # Set RSVP
///
/// Set the caller's RSVP (`Going` or `NotGoing`). Only currently-eligible invited
/// users may respond; `Pending` is not a settable target.
#[openapi(tag = "Calendar")]
#[put("/event/<target>/rsvp", data = "<data>")]
pub async fn set_rsvp(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataSetRsvp>,
) -> Result<Json<v0::EventRsvp>> {
    super::require_events_enabled().await?;

    let event = db.fetch_event(target.id).await?;
    if event.cancelled {
        return Err(create_error!(InvalidOperation));
    }

    // RSVP authority must track LIVE membership/permission, not a stale invite row
    // (a removed/banned user, or one who lost ViewChannel, must not keep attending).
    // EXCEPTION: the withdraw transition (`NotGoing`) needs only live membership — a
    // user who lost view (e.g. the event moved to a channel they cannot see) must
    // always be able to escape `Going` and its reminder pushes.
    let target_status = super::status_from_wire(data.into_inner().status);
    if matches!(target_status, RsvpStatus::NotGoing) {
        db.fetch_member(&event.server, &user.id)
            .await
            .map_err(|_| create_error!(NotFound))?;
    } else {
        super::authorize_view(db, &user, &event).await?;
    }

    // Only invited users may RSVP: they must already have a row (design §6/§7).
    let mut rsvp = db
        .fetch_rsvp(&event.id, &user.id)
        .await
        .map_err(|_| create_error!(NotFound))?;

    rsvp.apply_response(target_status)?; // rejects a `Pending` target (finding L1)
    db.update_rsvp(&rsvp).await?;

    // Fan out the RSVP change to the event audience (same topic as the event).
    let wire = super::rsvp_to_wire(rsvp);
    EventV1::CalendarEventRsvp { rsvp: wire.clone() }
        .p(super::event_topic(&event))
        .await;

    Ok(Json(wire))
}

/// # Fetch Attendees
///
/// List RSVP rows for an event, ordered by user id and paginated with an optional
/// `before` cursor (a user id) and `limit`. Requires view permission.
#[openapi(tag = "Calendar")]
#[get("/event/<target>/attendees?<limit>&<before>")]
pub async fn fetch_attendees(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    limit: Option<u32>,
    before: Option<String>,
) -> Result<Json<v0::AttendeesResponse>> {
    super::require_events_enabled().await?;

    let event = db.fetch_event(target.id).await?;
    super::authorize_view(db, &user, &event).await?;

    let mut rsvps = db.fetch_rsvps_for_event(&event.id).await?;
    rsvps.sort_by(|a, b| a.id.user.cmp(&b.id.user));

    let limit = (limit.unwrap_or(MAX_ATTENDEES_PAGE as u32) as usize).min(MAX_ATTENDEES_PAGE);
    let attendees = rsvps
        .into_iter()
        .filter(|r| before.as_ref().is_none_or(|cursor| &r.id.user > cursor))
        .take(limit)
        .map(super::rsvp_to_wire)
        .collect();

    Ok(Json(v0::AttendeesResponse { attendees }))
}
