use crate::{rocket, util::test::TestHarness};
use revolt_database::{Member, Server, User};
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

    // Owner invites the guest.
    let response = harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "users": [guest.id] }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);

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

    // Owner (can view) sees the event.
    let owner_list = harness
        .client
        .get(&list_url)
        .header(Header::new("x-session-token", owner_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<Vec<v0::Event>>()
        .await
        .expect("owner list");
    assert_eq!(owner_list.len(), 1);

    // Guest (cannot view the channel) does NOT see the event (finding C1).
    let guest_list = harness
        .client
        .get(&list_url)
        .header(Header::new("x-session-token", guest_session.token.to_string()))
        .dispatch()
        .await
        .into_json::<Vec<v0::Event>>()
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
