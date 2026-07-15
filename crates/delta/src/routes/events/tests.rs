use crate::{rocket, util::test::TestHarness};
use revolt_database::{File, Member, Metadata, Server, User};
use revolt_models::v0::{self, DataCreateServer};
use rocket::http::{ContentType, Header, Status};
use serde_json::json;

/// Create a server owned by `owner` and add them as a member.
async fn make_server(harness: &TestHarness, owner: &User) -> Server {
    let server = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Test Server".to_string(),
            description: None,
            nsfw: None,
        },
        owner,
        false,
    )
    .await
    .expect("server")
    .0;
    Member::create(&harness.db, &server, owner, None)
        .await
        .expect("owner member");
    server
}

/// Slice G: seed an UNCLAIMED file in the `attachments` bucket, exactly as Autumn
/// leaves one after an upload (no `used_for`), so a route can claim it. Returns the id.
async fn upload_attachment(harness: &TestHarness, filename: &str, uploader: &User) -> String {
    use iso8601_timestamp::Timestamp;
    let id = ulid::Ulid::new().to_string();
    harness
        .db
        .insert_attachment(&File {
            id: id.clone(),
            tag: "attachments".to_string(),
            filename: filename.to_string(),
            hash: None,
            uploaded_at: Some(Timestamp::now_utc()),
            uploader_id: Some(uploader.id.clone()),
            used_for: None,
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "application/octet-stream".to_string(),
            size: 10,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        })
        .await
        .expect("insert attachment");
    id
}

#[rocket::async_test]
async fn create_and_fetch_event() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    // Create.
    let response = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({
                "title": "Launch Party",
                "start": 1_900_000_000_000_i64,
                "end": 1_900_003_600_000_i64,
                "timezone": "UTC"
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let event = response.into_json::<v0::Event>().await.expect("event");
    assert_eq!(event.title, "Launch Party");
    assert_eq!(event.creator, owner.id);

    // Fetch with context.
    let response = harness
        .client
        .get(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let ctx = response
        .into_json::<v0::EventWithContext>()
        .await
        .expect("context");
    assert_eq!(ctx.event.id, event.id);
    assert_eq!(ctx.counts.going, 0);
    assert!(ctx.my_rsvp.is_none());
}

#[rocket::async_test]
async fn invite_accept_and_non_invited_rejected() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let (_, outsider_session, outsider) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");
    Member::create(&harness.db, &server, &outsider, None)
        .await
        .expect("outsider member");

    // Owner creates an event.
    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Standup", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    // Owner invites the guest. The route reports counts (slice F, decision 0.1-A).
    let response = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "users": [guest.id] }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let result = response
        .into_json::<v0::InviteResult>()
        .await
        .expect("invite result");
    assert_eq!(result.invited, 1);
    assert_eq!(result.skipped, 0);

    // Guest accepts.
    let response = harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new("x-session-token", guest_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "status": "Going" }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let rsvp = response.into_json::<v0::EventRsvp>().await.expect("rsvp");
    assert!(matches!(rsvp.status, v0::RsvpStatus::Going));
    assert!(rsvp.had_accepted);

    // A member who was never invited cannot RSVP.
    let response = harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new("x-session-token", outsider_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "status": "Going" }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok);

    // Counts reflect exactly one attendee going.
    let ctx = harness
        .client
        .get(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::EventWithContext>()
        .await
        .expect("context");
    assert_eq!(ctx.counts.going, 1);
}

/// Cancelling an event is terminal: RSVPs are then rejected, and the event reports cancelled.
#[rocket::async_test]
async fn cancel_is_terminal() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Party", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    // Invite + accept, then cancel.
    harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "users": [guest.id] }).to_string())
        .dispatch()
        .await;
    let response = harness
        .client
        .delete(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);

    // RSVP to a cancelled event is rejected.
    let response = harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new("x-session-token", guest_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "status": "Going" }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok);

    // The event now reports cancelled (rows retained for notifications).
    let ctx = harness
        .client
        .get(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::EventWithContext>()
        .await
        .expect("context");
    assert!(ctx.event.cancelled);
}

/// A plain member who is neither creator nor a manager cannot edit an event.
#[rocket::async_test]
async fn non_manager_cannot_edit() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Owned", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", guest_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Hijacked" }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok);
}

/// Re-inviting a user who already accepted is a no-op — it must not reset their status
/// (finding H5) or double-count them.
#[rocket::async_test]
async fn reinvite_is_noop() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Sync", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    let invite = |token: String| {
        harness
            .client
            .post(format!("/events/event/{}/invites", event.id))
            .header(Header::new("x-session-token", token))
            .header(ContentType::JSON)
            .body(json!({ "users": [guest.id] }).to_string())
    };
    invite(owner_session.token.to_string()).dispatch().await;

    // Guest accepts.
    harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new("x-session-token", guest_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "status": "Going" }).to_string())
        .dispatch()
        .await;

    // Owner re-invites the (already Going) guest.
    invite(owner_session.token.to_string()).dispatch().await;

    // Guest is still Going; count unchanged.
    let ctx = harness
        .client
        .get(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", guest_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::EventWithContext>()
        .await
        .expect("context");
    assert_eq!(ctx.counts.going, 1);
    assert!(matches!(
        ctx.my_rsvp.map(|r| r.status),
        Some(v0::RsvpStatus::Going)
    ));
}

/// Finding H6: soft-cancel must retain the `Going` RSVP rows so the cancel-notify
/// list is intact (pushd delivers the cancel to those attendees by user id). After a
/// cancel, an attendee who accepted is still counted `Going`.
#[rocket::async_test]
async fn cancel_retains_going_rows_for_notify() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Offsite", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    // Invite + accept so there is a Going attendee to notify.
    harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "users": [guest.id] }).to_string())
        .dispatch()
        .await;
    harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new("x-session-token", guest_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "status": "Going" }).to_string())
        .dispatch()
        .await;

    // Cancel.
    let response = harness
        .client
        .delete(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);

    // The Going row survived the soft-cancel: the notify-list was never destroyed.
    let attendees = harness
        .client
        .get(format!("/events/event/{}/attendees", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::AttendeesResponse>()
        .await
        .expect("attendees");
    assert_eq!(attendees.attendees.len(), 1);
    assert!(matches!(
        attendees.attendees[0].status,
        v0::RsvpStatus::Going
    ));

    // A second cancel is an idempotent no-op (it must not re-run the notify fan-out).
    let response = harness
        .client
        .delete(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);
}

/// Finding C1: an event scoped to a channel the caller cannot view must be invisible
/// to them in the list, and inviting such a member must be skipped.
#[rocket::async_test]
async fn channel_scoped_event_hidden_from_non_viewer() {
    use revolt_database::{Channel, PartialChannel};
    use revolt_permissions::{ChannelPermission, OverrideField};

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;

    let (server, channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Scoped".to_string(),
            description: None,
            nsfw: None,
        },
        &owner,
        true, // create the default "General" text channel
    )
    .await
    .expect("server");
    Member::create(&harness.db, &server, &owner, None)
        .await
        .expect("owner member");
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");

    // Deny ViewChannel by default on the first text channel. The owner still sees it
    // (server-owner bypass); a plain member (guest) cannot.
    let mut channel = channels
        .into_iter()
        .find(|c| matches!(c, Channel::TextChannel { .. }))
        .expect("text channel");
    let channel_id = channel.id().to_string();
    channel
        .update(
            &harness.db,
            PartialChannel {
                default_permissions: Some(OverrideField {
                    a: 0,
                    d: ChannelPermission::ViewChannel as i64,
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("deny view");

    // Owner creates an event scoped to that channel.
    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({
                "title": "Private",
                "start": 1_900_000_000_000_i64,
                "timezone": "UTC",
                "channel": channel_id
            })
            .to_string(),
        )
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    let list_url = format!(
        "/events/server/{}?from=1899000000000&to=1901000000000",
        server.id
    );

    // Owner (can view) sees the event, with its occurrence expanded in-window (0.1-A).
    let owner_list = harness
        .client
        .get(&list_url)
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<Vec<v0::EventWithOccurrences>>()
        .await
        .expect("owner list");
    assert_eq!(owner_list.len(), 1);
    assert_eq!(
        owner_list[0].occurrences,
        vec![1_900_000_000_000_i64],
        "the list must carry the series' in-window occurrence starts"
    );

    // Guest (cannot view the channel) does NOT see the event (finding C1).
    let guest_list = harness
        .client
        .get(&list_url)
        .header(Header::new("x-session-token", guest_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<Vec<v0::EventWithOccurrences>>()
        .await
        .expect("guest list");
    assert!(
        guest_list.is_empty(),
        "a non-viewer must not see a channel-scoped event"
    );

    // Inviting the non-viewer is skipped — no attendee row is created.
    harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "users": [guest.id] }).to_string())
        .dispatch()
        .await;
    let attendees = harness
        .client
        .get(format!("/events/event/{}/attendees", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::AttendeesResponse>()
        .await
        .expect("attendees");
    assert!(
        attendees.attendees.is_empty(),
        "invite must skip a member who cannot view the channel"
    );
}

/// Slice F (0.1-A): a role invite expands to the role's CURRENT holders server-side,
/// dedups against explicit user ids, hard-fails on an unknown role, and rejects an
/// empty request. A removed holder is not re-invited (their cascaded row stays gone).
#[rocket::async_test]
async fn role_invite_expands_and_dedups() {
    use revolt_database::{PartialMember, RemovalIntention, Role};
    use revolt_permissions::OverrideField;
    use ulid::Ulid;

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, _a_session, member_a) = harness.new_user().await;
    let (_, _b_session, member_b) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    let ma = Member::create(&harness.db, &server, &member_a, None)
        .await
        .expect("member a")
        .0;
    let mb = Member::create(&harness.db, &server, &member_b, None)
        .await
        .expect("member b")
        .0;

    // A role held by both members.
    let role = Role {
        id: Ulid::new().to_string(),
        name: "Raid group 1".to_string(),
        permissions: OverrideField { a: 0, d: 0 },
        colour: None,
        hoist: false,
        rank: 5,
        icon: None,
    };
    harness
        .db
        .insert_role(&server.id, &role)
        .await
        .expect("role");
    for member in [&ma, &mb] {
        harness
            .db
            .update_member(
                &member.id,
                &PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("assign role");
    }

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Raid", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    // users ∩ roles dedups: member_a is named explicitly AND holds the role.
    let response = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "users": [member_a.id], "roles": [role.id] }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let result = response
        .into_json::<v0::InviteResult>()
        .await
        .expect("invite result");
    assert_eq!(result.invited, 2, "role expands to both holders, deduped");

    // Unknown role is a hard error before any insert.
    let response = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "roles": [Ulid::new().to_string()] }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok);

    // Neither users nor roles is a validation error.
    let response = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({}).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok);

    // Kick member_b: the cascade removes their row, and a role re-invite must not
    // resurrect them (they are no longer a member/holder).
    harness
        .db
        .fetch_member(&server.id, &member_b.id)
        .await
        .expect("member b row")
        .remove(&harness.db, &server, RemovalIntention::Kick, true)
        .await
        .expect("kick");
    let result = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "roles": [role.id] }).to_string())
        .dispatch()
        .await
        .into_json::<v0::InviteResult>()
        .await
        .expect("re-invite result");
    assert_eq!(result.invited, 0, "no new invitees after the kick");

    let attendees = harness
        .client
        .get(format!("/events/event/{}/attendees", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::AttendeesResponse>()
        .await
        .expect("attendees");
    assert_eq!(
        attendees.attendees.len(),
        1,
        "the kicked member's RSVP row was cascaded and never re-created"
    );
    assert_eq!(attendees.attendees[0].user, member_a.id);
}

/// Slice F (F4a): removing a member cascades their RSVP rows for THAT server only —
/// their rows on another server survive.
#[rocket::async_test]
async fn member_removal_cascades_rsvps_per_server() {
    use revolt_database::RemovalIntention;

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, _guest_session, guest) = harness.new_user().await;
    let server_a = make_server(&harness, &owner).await;
    let server_b = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server_a, &guest, None)
        .await
        .expect("guest in a");
    Member::create(&harness.db, &server_b, &guest, None)
        .await
        .expect("guest in b");

    let mut events = Vec::new();
    for server in [&server_a, &server_b] {
        let event = harness
            .client
            .post(format!("/events/server/{}", server.id))
            .header(Header::new("x-session-token", owner_session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "title": "Meet", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
            .dispatch()
            .await
            .into_json::<v0::Event>()
            .await
            .expect("event");
        harness
            .client
            .post(format!("/events/event/{}/invites", event.id))
            .header(Header::new("x-session-token", owner_session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "users": [guest.id] }).to_string())
            .dispatch()
            .await;
        events.push(event);
    }

    // Kick the guest from server A only.
    harness
        .db
        .fetch_member(&server_a.id, &guest.id)
        .await
        .expect("member row")
        .remove(&harness.db, &server_a, RemovalIntention::Kick, true)
        .await
        .expect("kick");

    assert!(
        harness
            .db
            .fetch_rsvp(&events[0].id, &guest.id)
            .await
            .is_err(),
        "server A row cascaded"
    );
    assert!(
        harness
            .db
            .fetch_rsvp(&events[1].id, &guest.id)
            .await
            .is_ok(),
        "server B row untouched"
    );
}

/// Slice F (F4b): a creator who is no longer a member (kicked/banned) loses manage
/// authority — edit, cancel and invite are all rejected for their still-valid session.
#[rocket::async_test]
async fn removed_creator_loses_manage() {
    use revolt_database::RemovalIntention;

    let harness = TestHarness::new().await;
    let (_, _owner_session, owner) = harness.new_user().await;
    let (_, creator_session, creator) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &creator, None)
        .await
        .expect("creator member");

    // Any member may create an event.
    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", creator_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Mine", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    // While a member, the creator can edit.
    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", creator_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Renamed" }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // Kick the creator; their session stays valid but manage authority must not.
    harness
        .db
        .fetch_member(&server.id, &creator.id)
        .await
        .expect("member row")
        .remove(&harness.db, &server, RemovalIntention::Kick, true)
        .await
        .expect("kick");

    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", creator_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Hijacked" }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "edit must be rejected");

    let response = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", creator_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "users": [owner.id] }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "invite must be rejected");

    let response = harness
        .client
        .delete(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", creator_session.token.to_string()))
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::NoContent, "cancel must be rejected");
}

/// Slice F (0.2-A): a cancelled series stays in the list (clients render it
/// struck-through) with its occurrences expanded; RSVPing it stays rejected.
#[rocket::async_test]
async fn cancelled_event_still_listed() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Gone", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    harness
        .client
        .delete(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await;

    let list = harness
        .client
        .get(format!(
            "/events/server/{}?from=1899000000000&to=1901000000000",
            server.id
        ))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<Vec<v0::EventWithOccurrences>>()
        .await
        .expect("list");
    assert_eq!(list.len(), 1, "cancelled series must stay listed (0.2-A)");
    assert!(list[0].event.cancelled);
    assert_eq!(list[0].occurrences, vec![1_900_000_000_000_i64]);
}

/// Slice F (F5): the legacy import maps tagged messages through create's validation,
/// takes the creator from the message author (spoof-proof), imports date-only starts
/// as all-day, degrades a dead voiceId to no channel, counts invalid rows without
/// storing them, and dedups by source message id so a re-run imports nothing.
#[rocket::async_test]
async fn import_legacy_events_end_to_end() {
    use revolt_database::Message;
    use ulid::Ulid;

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, author_session, author) = harness.new_user().await;

    let (server, channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Legacy".to_string(),
            description: None,
            nsfw: None,
        },
        &owner,
        true,
    )
    .await
    .expect("server");
    Member::create(&harness.db, &server, &owner, None)
        .await
        .expect("owner member");
    Member::create(&harness.db, &server, &author, None)
        .await
        .expect("author member");
    let channel_id = channels[0].id().to_string();

    let tag = |json: &str| format!("[ACUTEST_EVENT]:{json}");
    let contents = [
        // Valid timed event with extras (authorId must be IGNORED — creator is the
        // message author, not the payload).
        tag(r##"{"title":"Old Party","start":"2030-03-01T18:00:00.000Z","end":"2030-03-01T19:00:00.000Z","desc":"bring snacks","color":"#ff8800","authorId":"01SPOOFED"}"##),
        // Date-only start imports as all-day.
        tag(r##"{"title":"Fair","start":"2030-04-05"}"##),
        // Dead voiceId degrades to no channel, still imports.
        tag(r##"{"title":"Voice hang","start":"2030-05-01T10:00:00.000Z","voiceId":"01DEADCHANNEL0000000000000"}"##),
        // Invalid: end before start.
        tag(r##"{"title":"Backwards","start":"2030-06-01T10:00:00.000Z","end":"2030-06-01T09:00:00.000Z"}"##),
        // Invalid: not JSON.
        "[ACUTEST_EVENT]:{definitely not json".to_string(),
        // Plain chat message: scanned, not an event.
        "hello world".to_string(),
    ];
    for content in &contents {
        harness
            .db
            .insert_message(&Message {
                id: Ulid::new().to_string(),
                channel: channel_id.clone(),
                author: author.id.clone(),
                content: Some(content.clone()),
                ..Default::default()
            })
            .await
            .expect("message");
    }

    // A plain member (the author) is not a manager: import rejected.
    let response = harness
        .client
        .post(format!("/events/server/{}/import", server.id))
        .header(Header::new("x-session-token", author_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "channel": channel_id }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok);

    // The owner imports.
    let response = harness
        .client
        .post(format!("/events/server/{}/import", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "channel": channel_id }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let result = response
        .into_json::<v0::ImportResult>()
        .await
        .expect("import result");
    assert_eq!(result.imported, 3);
    assert_eq!(result.skipped_invalid, 2);
    assert_eq!(result.skipped_duplicates, 0);
    assert_eq!(result.scanned, 6);
    assert!(!result.truncated);

    // The imported events are real: correct mapping, creator = message author.
    let list = harness
        .client
        .get(format!(
            "/events/server/{}?from=1890000000000&to=1920000000000",
            server.id
        ))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<Vec<v0::EventWithOccurrences>>()
        .await
        .expect("list");
    assert_eq!(list.len(), 3);
    for row in &list {
        assert_eq!(row.event.creator, author.id, "creator is the message author");
        assert!(row.event.channel.is_none(), "dead voiceId degraded to None");
    }
    let party = list
        .iter()
        .find(|r| r.event.title == "Old Party")
        .expect("party");
    assert_eq!(party.event.description.as_deref(), Some("bring snacks"));
    assert_eq!(party.event.color.as_deref(), Some("#ff8800"));
    assert!(!party.event.all_day);
    let fair = list.iter().find(|r| r.event.title == "Fair").expect("fair");
    assert!(fair.event.all_day, "date-only start imports as all-day");

    // Re-running imports nothing (source_message_id dedup).
    let result = harness
        .client
        .post(format!("/events/server/{}/import", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "channel": channel_id }).to_string())
        .dispatch()
        .await
        .into_json::<v0::ImportResult>()
        .await
        .expect("re-import result");
    assert_eq!(result.imported, 0);
    assert_eq!(result.skipped_duplicates, 3);
}

/// Slice F (F5 gates): the import source channel must belong to the server, and a
/// manager without ViewChannel on it must be rejected (no private-channel exfil).
#[rocket::async_test]
async fn import_requires_viewable_in_server_channel() {
    use revolt_database::{Channel, PartialChannel, PartialMember, Role};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use ulid::Ulid;

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, manager_session, manager) = harness.new_user().await;

    let (server, channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Gated".to_string(),
            description: None,
            nsfw: None,
        },
        &owner,
        true,
    )
    .await
    .expect("server");
    Member::create(&harness.db, &server, &owner, None)
        .await
        .expect("owner member");
    let manager_member = Member::create(&harness.db, &server, &manager, None)
        .await
        .expect("manager member")
        .0;

    // Cross-server channel is rejected outright.
    let other_server = make_server(&harness, &owner).await;
    let response = harness
        .client
        .post(format!("/events/server/{}/import", other_server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "channel": channels[0].id() }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok);

    // Grant the manager server-wide ManageChannel via a role, then deny ViewChannel
    // on the channel itself: manager authority without readability.
    let role = Role {
        id: Ulid::new().to_string(),
        name: "Mgr".to_string(),
        permissions: OverrideField {
            a: ChannelPermission::ManageChannel as i64,
            d: 0,
        },
        colour: None,
        hoist: false,
        rank: 1,
        icon: None,
    };
    harness
        .db
        .insert_role(&server.id, &role)
        .await
        .expect("role");
    harness
        .db
        .update_member(
            &manager_member.id,
            &PartialMember {
                roles: Some(vec![role.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("assign role");

    let mut channel = channels
        .into_iter()
        .find(|c| matches!(c, Channel::TextChannel { .. }))
        .expect("text channel");
    let channel_id = channel.id().to_string();
    channel
        .update(
            &harness.db,
            PartialChannel {
                default_permissions: Some(OverrideField {
                    a: 0,
                    d: ChannelPermission::ViewChannel as i64,
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("deny view");

    let response = harness
        .client
        .post(format!("/events/server/{}/import", server.id))
        .header(Header::new("x-session-token", manager_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "channel": channel_id }).to_string())
        .dispatch()
        .await;
    assert_ne!(
        response.status(),
        Status::Ok,
        "a manager denied ViewChannel must not import from that channel"
    );
}

/// Slice F (F5, cal-HIGH-1 follow-through): the import's cursor pagination is
/// exercised for real — a multi-page channel is scanned to exhaustion with tagged
/// messages on different pages, and a channel larger than `MAX_IMPORT_SCAN` stops
/// at the cap with `truncated` set. A cursor regression (no progress) would hang
/// this test rather than pass it.
#[rocket::async_test]
async fn import_paginates_and_truncates() {
    use revolt_database::Message;
    use ulid::Ulid;

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (server, channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Paged".to_string(),
            description: None,
            nsfw: None,
        },
        &owner,
        true,
    )
    .await
    .expect("server");
    Member::create(&harness.db, &server, &owner, None)
        .await
        .expect("owner member");
    let channel_id = channels[0].id().to_string();

    let insert = |content: String| {
        let db = harness.db.clone();
        let channel = channel_id.clone();
        let author = owner.id.clone();
        async move {
            db.insert_message(&Message {
                id: Ulid::new().to_string(),
                channel,
                author,
                content: Some(content),
                ..Default::default()
            })
            .await
            .expect("message");
        }
    };

    // 120 messages spanning two scan pages (page size 100, newest-first): a tagged
    // message among the OLDEST (first inserted → only reachable via the second
    // page / cursor advance) and one among the newest.
    insert(r##"[ACUTEST_EVENT]:{"title":"Oldest","start":"2030-01-01T10:00:00.000Z"}"##.to_string())
        .await;
    for i in 0..118 {
        insert(format!("filler {i}")).await;
    }
    insert(r##"[ACUTEST_EVENT]:{"title":"Newest","start":"2030-02-01T10:00:00.000Z"}"##.to_string())
        .await;

    let result = harness
        .client
        .post(format!("/events/server/{}/import", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "channel": channel_id }).to_string())
        .dispatch()
        .await
        .into_json::<v0::ImportResult>()
        .await
        .expect("import result");
    assert_eq!(result.scanned, 120, "both pages scanned to exhaustion");
    assert_eq!(result.imported, 2, "tagged messages found on both pages");
    assert!(!result.truncated);

    // Bury the history under more messages than the scan cap: the re-run stops at
    // the cap (newest-first), reports truncation, and never reaches the two
    // already-imported tags at the oldest end.
    for i in 0..2000 {
        insert(format!("burying filler {i}")).await;
    }
    let result = harness
        .client
        .post(format!("/events/server/{}/import", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "channel": channel_id }).to_string())
        .dispatch()
        .await
        .into_json::<v0::ImportResult>()
        .await
        .expect("re-import result");
    assert_eq!(result.scanned, 2000, "scan stops at MAX_IMPORT_SCAN");
    assert!(result.truncated, "cap hit before exhausting history");
    assert_eq!(result.imported, 0);
    assert_eq!(result.skipped_duplicates, 0, "tags lie beyond the cap");
}

/// Slice F (F6, cal-MED-5): a member slated for deletion (`pending_deletion_at`
/// set — the state a kicked-while-in-timeout member has) must not be invitable,
/// neither named explicitly nor via role expansion. `pending_deletion_at` is a
/// database-layer-only field the Reference driver cannot represent (its
/// soft-delete of an in-timeout member is unimplemented), so this test is
/// Mongo-gated and runs in the WSL MONGODB pass; the invite loop's `fetch_member`
/// re-check is the only filter (`fetch_all_members_with_roles` does not apply it).
#[rocket::async_test]
async fn pending_deletion_member_not_invitable() {
    use revolt_database::mongodb::bson::{doc, Document};
    use revolt_database::{Database, PartialMember, Role};
    use revolt_permissions::OverrideField;
    use ulid::Ulid;

    let harness = TestHarness::new().await;
    let Database::MongoDb(mongo) = &harness.db else {
        return; // REFERENCE cannot represent pending_deletion_at
    };

    let (_, owner_session, owner) = harness.new_user().await;
    let (_, _ghost_session, ghost) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    let ghost_member = Member::create(&harness.db, &server, &ghost, None)
        .await
        .expect("ghost member")
        .0;

    // The ghost holds a role…
    let role = Role {
        id: Ulid::new().to_string(),
        name: "Raiders".to_string(),
        permissions: OverrideField { a: 0, d: 0 },
        colour: None,
        hoist: false,
        rank: 5,
        icon: None,
    };
    harness
        .db
        .insert_role(&server.id, &role)
        .await
        .expect("role");
    harness
        .db
        .update_member(
            &ghost_member.id,
            &PartialMember {
                roles: Some(vec![role.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("assign role");

    // …and is then slated for deletion. Roles stay set in this synthetic state,
    // so role expansion WILL surface them — the fetch_member re-check must not.
    mongo
        .col::<Document>("server_members")
        .update_one(
            doc! { "_id.server": &server.id, "_id.user": &ghost.id },
            doc! { "$set": { "pending_deletion_at": "2100-01-01T00:00:00Z" } },
        )
        .await
        .expect("mark pending deletion");

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "title": "Raid", "start": 1_900_000_000_000_i64, "timezone": "UTC" }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    // Named explicitly: skipped.
    let result = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "users": [ghost.id] }).to_string())
        .dispatch()
        .await
        .into_json::<v0::InviteResult>()
        .await
        .expect("invite result");
    assert_eq!(result.invited, 0, "pending-deletion member must be skipped");
    assert_eq!(result.skipped, 1);

    // Via role expansion: skipped too.
    let result = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "roles": [role.id] }).to_string())
        .dispatch()
        .await
        .into_json::<v0::InviteResult>()
        .await
        .expect("role invite result");
    assert_eq!(result.invited, 0, "role expansion must not resurrect them");

    let attendees = harness
        .client
        .get(format!("/events/event/{}/attendees", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::AttendeesResponse>()
        .await
        .expect("attendees");
    assert!(attendees.attendees.is_empty());
}

/// Slice G: an event created with attachment file ids claims those files (bad ids
/// fail), carries them on the wire, and — because attachments inherit the event's
/// view rule — is visible to any other member who can see the event.
#[rocket::async_test]
async fn create_with_attachments_visible_to_members() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, member_session, member) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &member, None)
        .await
        .expect("member");

    let f1 = upload_attachment(&harness, "agenda.pdf", &owner).await;
    let f2 = upload_attachment(&harness, "map.png", &owner).await;

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({
                "title": "Kickoff",
                "start": 1_900_000_000_000_i64,
                "timezone": "UTC",
                "attachments": [f1, f2]
            })
            .to_string(),
        )
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");
    let attachments = event.attachments.expect("attachments present");
    assert_eq!(attachments.len(), 2);
    let names: Vec<&str> = attachments.iter().map(|f| f.filename.as_str()).collect();
    assert!(names.contains(&"agenda.pdf") && names.contains(&"map.png"));

    // Another member who can view the event sees its attachments (visibility inherits
    // the event's view rule).
    let ctx = harness
        .client
        .get(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", member_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::EventWithContext>()
        .await
        .expect("context");
    assert_eq!(ctx.event.attachments.map(|a| a.len()), Some(2));

    // The files are now claimed: a second event re-using the same id fails (claim-once,
    // enforced by both drivers — Mongo via `used_for: {$exists:false}`, Reference via the
    // matching unclaimed check).
    let response = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({
                "title": "Dup",
                "start": 1_900_000_000_000_i64,
                "timezone": "UTC",
                "attachments": [f1]
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "a claimed file cannot be reused");
}

/// Slice G (audit HIGH): an edit that changes attachments but fails the event's OWN
/// validator (bad timezone — which the DTO length checks do not catch) must be rejected
/// with NO file side effects: the detached file stays referenced and undeleted, and the
/// would-be new file stays unclaimed (re-usable). Guards the "validate/persist the event
/// before mutating any files" ordering.
#[rocket::async_test]
async fn edit_validation_failure_leaves_attachments_untouched() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    let f1 = upload_attachment(&harness, "keep.pdf", &owner).await;
    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({ "title": "Docs", "start": 1_900_000_000_000_i64, "timezone": "UTC", "attachments": [f1] })
                .to_string(),
        )
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    // Edit that detaches f1, adds f2, AND sets an invalid timezone → event.validate() fails.
    let f2 = upload_attachment(&harness, "new.pdf", &owner).await;
    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({ "timezone": "Not/AZone", "attachments": [f2], "remove_attachments": [f1] })
                .to_string(),
        )
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "invalid timezone must reject the edit");

    // f1 was NOT deleted and is still the event's only attachment.
    let f1_doc = harness
        .db
        .fetch_attachment("attachments", &f1)
        .await
        .expect("f1 present");
    assert_ne!(
        f1_doc.deleted,
        Some(true),
        "a rejected edit must not delete the detached file"
    );
    let ctx = harness
        .client
        .get(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<v0::EventWithContext>()
        .await
        .expect("context");
    assert_eq!(ctx.event.attachments.map(|a| a.len()), Some(1), "attachments unchanged");

    // f2 was never claimed, so a valid edit can still add it.
    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "attachments": [f2] }).to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Ok,
        "the rejected edit left f2 unclaimed and re-usable"
    );
}

/// Slice G: the edit path adds and detaches files (detached files are marked deleted),
/// and `remove: ["Attachments"]` clears the whole set — all without disturbing the
/// rest of the event.
#[rocket::async_test]
async fn edit_add_remove_and_clear_attachments() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    let f1 = upload_attachment(&harness, "one.pdf", &owner).await;
    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({ "title": "Docs", "start": 1_900_000_000_000_i64, "timezone": "UTC", "attachments": [f1] })
                .to_string(),
        )
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    // Add f2, detach f1 in a single PATCH.
    let f2 = upload_attachment(&harness, "two.pdf", &owner).await;
    let edited = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "attachments": [f2], "remove_attachments": [f1] }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("edited");
    let attachments = edited.attachments.expect("attachments");
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].filename, "two.pdf");

    // The detached file was marked deleted (crond will sweep it).
    let f1_doc = harness
        .db
        .fetch_attachment("attachments", &f1)
        .await
        .expect("f1 still present");
    assert_eq!(f1_doc.deleted, Some(true), "detached file is marked deleted");

    // Clearing the whole set unsets attachments.
    let cleared = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "remove": ["Attachments"] }).to_string())
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("cleared");
    assert!(
        cleared.attachments.is_none() || cleared.attachments.as_ref().unwrap().is_empty(),
        "attachments cleared"
    );
    let f2_doc = harness
        .db
        .fetch_attachment("attachments", &f2)
        .await
        .expect("f2 present");
    assert_eq!(f2_doc.deleted, Some(true), "cleared file is marked deleted");
}

/// Slice G: the attachment count is capped at `MAX_EVENT_ATTACHMENTS` (10) on create
/// (DTO validation) and on the post-edit total — and an over-cap edit has NO side
/// effects (its would-be new file is left unclaimed and re-usable).
#[rocket::async_test]
async fn attachment_cap_enforced() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    // 11 ids on create → rejected before any claim (DTO length cap).
    let too_many: Vec<String> = (0..11).map(|i| format!("id{i}")).collect();
    let response = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({ "title": "Too many", "start": 1_900_000_000_000_i64, "timezone": "UTC", "attachments": too_many })
                .to_string(),
        )
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "11 attachments rejected on create");

    // Create with 8 real files, then try to add 3 more (total 11) — rejected, with the
    // new file left unclaimed.
    let mut ids = Vec::new();
    for i in 0..8 {
        ids.push(upload_attachment(&harness, &format!("f{i}.bin"), &owner).await);
    }
    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({ "title": "Eight", "start": 1_900_000_000_000_i64, "timezone": "UTC", "attachments": ids })
                .to_string(),
        )
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");
    assert_eq!(event.attachments.map(|a| a.len()), Some(8));

    let add = [
        upload_attachment(&harness, "a.bin", &owner).await,
        upload_attachment(&harness, "b.bin", &owner).await,
        upload_attachment(&harness, "c.bin", &owner).await,
    ];
    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "attachments": add }).to_string())
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "8 + 3 exceeds the cap");

    // No side effects: the first would-be file was never claimed, so it can still be
    // claimed by a valid single-file edit.
    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "remove_attachments": ids, "attachments": [add[0]] }).to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Ok,
        "the over-cap edit left its file unclaimed and re-usable"
    );
}
