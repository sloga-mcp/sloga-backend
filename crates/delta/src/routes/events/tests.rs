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

#[test]
fn create_and_fetch_event() {
    crate::util::test::rt().block_on(create_and_fetch_event_case())
}

async fn create_and_fetch_event_case() {
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

#[test]
fn invite_accept_and_non_invited_rejected() {
    crate::util::test::rt().block_on(invite_accept_and_non_invited_rejected_case())
}

async fn invite_accept_and_non_invited_rejected_case() {
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
#[test]
fn cancel_is_terminal() {
    crate::util::test::rt().block_on(cancel_is_terminal_case())
}

async fn cancel_is_terminal_case() {
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
#[test]
fn non_manager_cannot_edit() {
    crate::util::test::rt().block_on(non_manager_cannot_edit_case())
}

async fn non_manager_cannot_edit_case() {
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
#[test]
fn reinvite_is_noop() {
    crate::util::test::rt().block_on(reinvite_is_noop_case())
}

async fn reinvite_is_noop_case() {
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
#[test]
fn cancel_retains_going_rows_for_notify() {
    crate::util::test::rt().block_on(cancel_retains_going_rows_for_notify_case())
}

async fn cancel_retains_going_rows_for_notify_case() {
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
#[test]
fn channel_scoped_event_hidden_from_non_viewer() {
    crate::util::test::rt().block_on(channel_scoped_event_hidden_from_non_viewer_case())
}

async fn channel_scoped_event_hidden_from_non_viewer_case() {
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
#[test]
fn role_invite_expands_and_dedups() {
    crate::util::test::rt().block_on(role_invite_expands_and_dedups_case())
}

async fn role_invite_expands_and_dedups_case() {
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
#[test]
fn member_removal_cascades_rsvps_per_server() {
    crate::util::test::rt().block_on(member_removal_cascades_rsvps_per_server_case())
}

async fn member_removal_cascades_rsvps_per_server_case() {
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
#[test]
fn removed_creator_loses_manage() {
    crate::util::test::rt().block_on(removed_creator_loses_manage_case())
}

async fn removed_creator_loses_manage_case() {
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
#[test]
fn cancelled_event_still_listed() {
    crate::util::test::rt().block_on(cancelled_event_still_listed_case())
}

async fn cancelled_event_still_listed_case() {
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
#[test]
fn import_legacy_events_end_to_end() {
    crate::util::test::rt().block_on(import_legacy_events_end_to_end_case())
}

async fn import_legacy_events_end_to_end_case() {
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
#[test]
fn import_requires_viewable_in_server_channel() {
    crate::util::test::rt().block_on(import_requires_viewable_in_server_channel_case())
}

async fn import_requires_viewable_in_server_channel_case() {
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
    assert_eq!(response.status(), Status::BadRequest);

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
#[test]
fn import_paginates_and_truncates() {
    crate::util::test::rt().block_on(import_paginates_and_truncates_case())
}

async fn import_paginates_and_truncates_case() {
    use futures::StreamExt;
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

    // 2120 sequentially-awaited inserts made this test's wall time scale with
    // per-op mongod latency: ~30s alone, >300s (killed) while the rest of the
    // suite loads the box. Inserts here fan out 16-at-a-time instead — but the
    // scan-order assertions below depend on ID order, and `Ulid::new()` only
    // sorts correctly when sequential awaits space the timestamps (same-ms
    // ULIDs order randomly). So every message gets an explicit ULID minted
    // from a per-message millisecond: `seq` IS the order, independent of
    // insert completion order.
    let base_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        - 3_600_000;
    let mk_id = |seq: u64| Ulid::from_parts(base_ms + seq, seq as u128).to_string();

    let insert = |id: String, content: String| {
        let db = harness.db.clone();
        let channel = channel_id.clone();
        let author = owner.id.clone();
        async move {
            db.insert_message(&Message {
                id,
                channel,
                author,
                content: Some(content),
                ..Default::default()
            })
            .await
            .expect("message");
        }
    };
    let insert_batch = |batch: Vec<(String, String)>| async {
        futures::stream::iter(batch.into_iter().map(|(id, content)| insert(id, content)))
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await;
    };

    // 120 messages spanning two scan pages (page size 100, newest-first): a tagged
    // message with the OLDEST id (only reachable via the second page / cursor
    // advance) and one with the newest.
    insert(
        mk_id(0),
        r##"[ACUTEST_EVENT]:{"title":"Oldest","start":"2030-01-01T10:00:00.000Z"}"##.to_string(),
    )
    .await;
    insert_batch(
        (0..118)
            .map(|i| (mk_id(1 + i), format!("filler {i}")))
            .collect(),
    )
    .await;
    insert(
        mk_id(119),
        r##"[ACUTEST_EVENT]:{"title":"Newest","start":"2030-02-01T10:00:00.000Z"}"##.to_string(),
    )
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
    // already-imported tags at the oldest end. Every burying id sorts strictly
    // after `mk_id(119)` — the 2000-message scan must cover exactly this batch
    // and nothing older, or `skipped_duplicates` picks up the "Newest" tag.
    insert_batch(
        (0..2000)
            .map(|i| (mk_id(120 + i), format!("burying filler {i}")))
            .collect(),
    )
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
#[test]
fn pending_deletion_member_not_invitable() {
    crate::util::test::rt().block_on(pending_deletion_member_not_invitable_case())
}

async fn pending_deletion_member_not_invitable_case() {
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
#[test]
fn create_with_attachments_visible_to_members() {
    crate::util::test::rt().block_on(create_with_attachments_visible_to_members_case())
}

async fn create_with_attachments_visible_to_members_case() {
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
#[test]
fn edit_validation_failure_leaves_attachments_untouched() {
    crate::util::test::rt().block_on(edit_validation_failure_leaves_attachments_untouched_case())
}

async fn edit_validation_failure_leaves_attachments_untouched_case() {
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
#[test]
fn edit_add_remove_and_clear_attachments() {
    crate::util::test::rt().block_on(edit_add_remove_and_clear_attachments_case())
}

async fn edit_add_remove_and_clear_attachments_case() {
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
#[test]
fn attachment_cap_enforced() {
    crate::util::test::rt().block_on(attachment_cap_enforced_case())
}

async fn attachment_cap_enforced_case() {
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

// ---------------------------------------------------------------------------
// Soft-reserve sheet ↔ event linkage (softres slice 2)
// ---------------------------------------------------------------------------

/// Create a server-wide event through the API and return it.
async fn make_event(
    harness: &TestHarness,
    session_token: &str,
    server_id: &str,
    body: serde_json::Value,
) -> v0::Event {
    let response = harness
        .client
        .post(format!("/events/server/{server_id}"))
        .header(Header::new("x-session-token", session_token.to_string()))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    response.into_json::<v0::Event>().await.expect("event")
}

#[test]
fn softres_link_requires_event_manage_and_one_sheet_per_event() {
    crate::util::test::rt().block_on(softres_link_requires_event_manage_and_one_sheet_per_event_case())
}

async fn softres_link_requires_event_manage_and_one_sheet_per_event_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let (_, member_session, member) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &member, None)
        .await
        .expect("member");
    let channel = harness.new_channel(&server).await;

    let start = 1_900_000_000_000_i64;
    let event = make_event(
        &harness,
        &session.token,
        &server.id,
        json!({ "title": "Raid Night", "start": start, "timezone": "UTC" }),
    )
    .await;

    let sheet_body = json!({
        "title": "MC softres",
        "edition": "classic",
        "raids": ["mc"],
        "event_id": event.id,
        "lock_at_event_start": true
    });

    // A plain member (no event-manage rights) cannot claim the event's
    // sheet slot.
    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new(
            "x-session-token",
            member_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(sheet_body.to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Forbidden,
        "view-level linking must be rejected"
    );

    // The event creator links fine; locks_at snapshots the event start.
    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(sheet_body.to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let message: v0::Message = response.into_json().await.expect("`Message`");
    let sheet_id = message.softres.expect("softres").id;

    // The events-side lookup resolves for a plain member and carries the
    // snapshot.
    let response = harness
        .client
        .get(format!("/events/event/{}/softres", event.id))
        .header(Header::new(
            "x-session-token",
            member_session.token.to_string(),
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
    assert_eq!(state.id, sheet_id);
    assert_eq!(state.event_id.as_deref(), Some(event.id.as_str()));
    assert_eq!(state.locks_at, Some(start));
    assert!(!state.locked, "future start must not pre-lock");

    // One sheet per event: a second create 409s.
    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(sheet_body.to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Conflict,
        "the event's sheet slot is unique"
    );
}

#[test]
fn softres_link_rejects_recurring_cancelled_and_born_locked() {
    crate::util::test::rt().block_on(softres_link_rejects_recurring_cancelled_and_born_locked_case())
}

async fn softres_link_rejects_recurring_cancelled_and_born_locked_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    let channel = harness.new_channel(&server).await;

    // Recurring event → SoftResRecurringEvent.
    let recurring = make_event(
        &harness,
        &session.token,
        &server.id,
        json!({
            "title": "Weekly Raid",
            "start": 1_900_000_000_000_i64,
            "timezone": "UTC",
            "recurrence": {
                "freq": "Weekly",
                "interval": 1,
                "end": { "type": "Count", "count": 4 }
            }
        }),
    )
    .await;

    let body = |event_id: &str, lock: bool| {
        json!({
            "title": "sheet",
            "edition": "classic",
            "raids": ["mc"],
            "event_id": event_id,
            "lock_at_event_start": lock
        })
    };

    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(body(&recurring.id, false).to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::BadRequest,
        "recurring events cannot be linked in v1"
    );

    // Cancelled event → rejected.
    let cancelled = make_event(
        &harness,
        &session.token,
        &server.id,
        json!({ "title": "Called off", "start": 1_900_000_000_000_i64, "timezone": "UTC" }),
    )
    .await;
    let response = harness
        .client
        .delete(format!("/events/event/{}", cancelled.id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .dispatch()
        .await;
    assert!(response.status().code < 300, "cancel should succeed");
    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(body(&cancelled.id, false).to_string())
        .dispatch()
        .await;
    assert_ne!(
        response.status(),
        Status::Ok,
        "cancelled events cannot be linked"
    );

    // Past-start event: linking is fine, but lock_at_event_start would be
    // born-locked and is rejected.
    let past = make_event(
        &harness,
        &session.token,
        &server.id,
        json!({ "title": "Yesterday", "start": 1_000_000_000_000_i64, "timezone": "UTC" }),
    )
    .await;
    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(body(&past.id, true).to_string())
        .dispatch()
        .await;
    assert_ne!(
        response.status(),
        Status::Ok,
        "a born-locked sheet is useless and must be rejected"
    );
    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(body(&past.id, false).to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Ok,
        "linking a past event without auto-lock is allowed"
    );
    let message: v0::Message = response.into_json().await.expect("`Message`");
    assert!(message.softres.is_some());
}

#[test]
fn cancelling_an_event_locks_its_sheet_idempotently() {
    crate::util::test::rt().block_on(cancelling_an_event_locks_its_sheet_idempotently_case())
}

async fn cancelling_an_event_locks_its_sheet_idempotently_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    let channel = harness.new_channel(&server).await;

    let event = make_event(
        &harness,
        &session.token,
        &server.id,
        json!({ "title": "Raid Night", "start": 1_900_000_000_000_i64, "timezone": "UTC" }),
    )
    .await;

    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({
                "title": "sheet",
                "edition": "classic",
                "raids": ["mc"],
                "event_id": event.id
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let message: v0::Message = response.into_json().await.expect("`Message`");
    let sheet_id = message.softres.expect("softres").id;

    // Cancel the event → the hook locks the sheet.
    let response = harness
        .client
        .delete(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .dispatch()
        .await;
    assert!(response.status().code < 300);

    let response = harness
        .client
        .get(format!("/channels/{}/softres/{}", channel.id(), sheet_id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
    assert!(state.locked, "cancel hook must lock the sheet");

    // A re-issued cancel stays 2xx and the sheet (not deleted!) stays
    // locked and still resolves through the events-side lookup.
    let response = harness
        .client
        .delete(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .dispatch()
        .await;
    assert!(response.status().code < 300, "cancel is idempotent");

    let response = harness
        .client
        .get(format!("/events/event/{}/softres", event.id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Ok,
        "a cancelled event's sheet still resolves"
    );
}

#[test]
fn event_softres_lookup_is_gated_and_oracle_free() {
    crate::util::test::rt().block_on(event_softres_lookup_is_gated_and_oracle_free_case())
}

async fn event_softres_lookup_is_gated_and_oracle_free_case() {
    use revolt_permissions::ChannelPermission;

    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let (_, member_session, member) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &member, None)
        .await
        .expect("member");
    let channel = harness.new_channel(&server).await;

    let event = make_event(
        &harness,
        &session.token,
        &server.id,
        json!({ "title": "Raid Night", "start": 1_900_000_000_000_i64, "timezone": "UTC" }),
    )
    .await;

    // No sheet yet → 404.
    let response = harness
        .client
        .get(format!("/events/event/{}/softres", event.id))
        .header(Header::new(
            "x-session-token",
            member_session.token.to_string(),
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NotFound);

    // Owner links a sheet in the channel.
    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({
                "title": "sheet",
                "edition": "classic",
                "raids": ["mc"],
                "event_id": event.id
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // Member can see it while the channel is visible…
    let response = harness
        .client
        .get(format!("/events/event/{}/softres", event.id))
        .header(Header::new(
            "x-session-token",
            member_session.token.to_string(),
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // …then the channel denies ViewChannel to default members: the
    // event stays visible (server-wide) but the sheet must 404 exactly
    // like "no sheet" — event visibility never overrides sheet-channel
    // visibility, and the two cases must be indistinguishable.
    let response = harness
        .client
        .put(format!("/channels/{}/permissions/default", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({
                "permissions": {
                    "allow": 0,
                    "deny": ChannelPermission::ViewChannel as u64
                }
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok, "perm update failed");

    let response = harness
        .client
        .get(format!("/events/event/{}/softres", event.id))
        .header(Header::new(
            "x-session-token",
            member_session.token.to_string(),
        ))
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::NotFound,
        "hidden channel must read as no-sheet (no existence oracle)"
    );

    // A non-member cannot resolve anything through the event route.
    let (_, outsider_session, _) = harness.new_user().await;
    let response = harness
        .client
        .get(format!("/events/event/{}/softres", event.id))
        .header(Header::new(
            "x-session-token",
            outsider_session.token.to_string(),
        ))
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok);
}

#[test]
fn lock_at_event_start_toggle_rearms_and_clears() {
    crate::util::test::rt().block_on(lock_at_event_start_toggle_rearms_and_clears_case())
}

async fn lock_at_event_start_toggle_rearms_and_clears_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    let channel = harness.new_channel(&server).await;

    let start = 1_900_000_000_000_i64;
    let event = make_event(
        &harness,
        &session.token,
        &server.id,
        json!({ "title": "Raid Night", "start": start, "timezone": "UTC" }),
    )
    .await;

    // Sheet linked WITHOUT auto-lock.
    let response = harness
        .client
        .post(format!("/channels/{}/softres", channel.id()))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(
            json!({
                "title": "sheet",
                "edition": "classic",
                "raids": ["mc"],
                "event_id": event.id
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let message: v0::Message = response.into_json().await.expect("`Message`");
    let sheet_id = message.softres.expect("softres").id;

    // Toggle ON → snapshots locks_at from the event.
    let response = harness
        .client
        .patch(format!("/channels/{}/softres/{}", channel.id(), sheet_id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "lock_at_event_start": true }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
    assert_eq!(state.locks_at, Some(start));

    // Unlock clears the auto-lock state entirely…
    let response = harness
        .client
        .delete(format!(
            "/channels/{}/softres/{}/lock",
            channel.id(),
            sheet_id
        ))
        .header(Header::new("x-session-token", session.token.to_string()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
    assert_eq!(state.locks_at, None, "unlock clears the snapshot");

    // …and toggling ON again re-arms rather than silently no-opping.
    let response = harness
        .client
        .patch(format!("/channels/{}/softres/{}", channel.id(), sheet_id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "lock_at_event_start": true }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
    assert_eq!(state.locks_at, Some(start), "re-arming must re-snapshot");

    // Toggle OFF clears the snapshot.
    let response = harness
        .client
        .patch(format!("/channels/{}/softres/{}", channel.id(), sheet_id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "lock_at_event_start": false }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
    assert_eq!(state.locks_at, None);

    // After the event is cancelled, re-arming is rejected.
    let response = harness
        .client
        .delete(format!("/events/event/{}", event.id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .dispatch()
        .await;
    assert!(response.status().code < 300);
    let response = harness
        .client
        .patch(format!("/channels/{}/softres/{}", channel.id(), sheet_id))
        .header(Header::new("x-session-token", session.token.to_string()))
        .header(ContentType::JSON)
        .body(json!({ "lock_at_event_start": true }).to_string())
        .dispatch()
        .await;
    assert_ne!(
        response.status(),
        Status::Ok,
        "re-arming against a cancelled event must fail"
    );
}

/// A PATCH may move an event into a channel (validated like create), and a
/// narrowing move prunes the RSVP rows of users who cannot view the new channel —
/// otherwise they would stay `Going` (and reminded) for an event they cannot open.
#[test]
fn edit_moves_event_into_channel_and_prunes_blind_rsvps() {
    crate::util::test::rt().block_on(edit_moves_event_into_channel_and_prunes_blind_rsvps_case())
}

async fn edit_moves_event_into_channel_and_prunes_blind_rsvps_case() {
    use revolt_database::{Channel, PartialChannel};
    use revolt_permissions::{ChannelPermission, OverrideField};

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;

    let (server, channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Movable".to_string(),
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

    // Deny ViewChannel by default on the channel; the owner bypasses, the guest can't see it.
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

    // Server-wide event; guest is invited and Going.
    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(
            json!({ "title": "Raid", "start": 1_900_000_000_000_i64, "timezone": "UTC" })
                .to_string(),
        )
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");
    harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "users": [guest.id] }).to_string())
        .dispatch()
        .await;
    let response = harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new(
            "x-session-token",
            guest_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "status": "Going" }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // The guest (a plain member, not the creator) cannot move the event into a
    // channel they cannot view — same gate as create.
    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new(
            "x-session-token",
            guest_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "channel": channel_id }).to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Forbidden,
        "a non-manager must not move the event at all"
    );

    // The owner moves the event into the restricted channel.
    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "channel": channel_id }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let moved = response.into_json::<v0::Event>().await.expect("moved");
    assert_eq!(moved.channel.as_deref(), Some(channel_id.as_str()));

    // The guest's Going row was pruned by the narrowing move.
    let attendees = harness
        .client
        .get(format!("/events/event/{}/attendees", event.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .dispatch()
        .await
        .into_json::<v0::AttendeesResponse>()
        .await
        .expect("attendees");
    assert!(
        attendees.attendees.is_empty(),
        "a Going row must not survive a move to a channel its user cannot view"
    );

    // And the guest can no longer fetch the event.
    let response = harness
        .client
        .get(format!("/events/event/{}", event.id))
        .header(Header::new(
            "x-session-token",
            guest_session.token.to_string(),
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NotFound);
}

/// A cross-server channel is rejected as an edit target.
#[test]
fn edit_rejects_cross_server_channel() {
    crate::util::test::rt().block_on(edit_rejects_cross_server_channel_case())
}

async fn edit_rejects_cross_server_channel_case() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;

    let server = make_server(&harness, &owner).await;
    let (_, foreign_channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Elsewhere".to_string(),
            description: None,
            nsfw: None,
        },
        &owner,
        true,
    )
    .await
    .expect("foreign server");
    let foreign_channel = foreign_channels
        .first()
        .expect("foreign channel")
        .id()
        .to_string();

    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(
            json!({ "title": "Local", "start": 1_900_000_000_000_i64, "timezone": "UTC" })
                .to_string(),
        )
        .dispatch()
        .await
        .into_json::<v0::Event>()
        .await
        .expect("event");

    let response = harness
        .client
        .patch(format!("/events/event/{}", event.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "channel": foreign_channel }).to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::BadRequest,
        "a channel from another server must be rejected"
    );

    // The event is untouched.
    let ctx = harness
        .client
        .get(format!("/events/event/{}", event.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .dispatch()
        .await
        .into_json::<v0::EventWithContext>()
        .await
        .expect("context");
    assert_eq!(ctx.event.channel, None);
}

/// A `Going` attendee who loses ViewChannel (permission change, not a move — so the
/// prune never ran) can still withdraw: `NotGoing` needs only live membership.
/// Re-accepting (`Going`) stays behind the view gate.
#[test]
fn notgoing_escape_survives_lost_view() {
    crate::util::test::rt().block_on(notgoing_escape_survives_lost_view_case())
}

async fn notgoing_escape_survives_lost_view_case() {
    use revolt_database::{Channel, PartialChannel};
    use revolt_permissions::{ChannelPermission, OverrideField};

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;

    let (server, channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Escape".to_string(),
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
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");

    let mut channel = channels
        .into_iter()
        .find(|c| matches!(c, Channel::TextChannel { .. }))
        .expect("text channel");
    let channel_id = channel.id().to_string();

    // Channel-scoped event while the channel is still visible to everyone.
    let event = harness
        .client
        .post(format!("/events/server/{}", server.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(
            json!({
                "title": "Sync",
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
    harness
        .client
        .post(format!("/events/event/{}/invites", event.id))
        .header(Header::new(
            "x-session-token",
            owner_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "users": [guest.id] }).to_string())
        .dispatch()
        .await;
    let response = harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new(
            "x-session-token",
            guest_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "status": "Going" }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // Now deny ViewChannel — a permission change, not an event edit.
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

    // Withdrawing still works…
    let response = harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new(
            "x-session-token",
            guest_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "status": "NotGoing" }).to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Ok,
        "NotGoing must not require ViewChannel"
    );
    let rsvp = response.into_json::<v0::EventRsvp>().await.expect("rsvp");
    assert!(matches!(rsvp.status, v0::RsvpStatus::NotGoing));

    // …but re-accepting is still gated on view.
    let response = harness
        .client
        .put(format!("/events/event/{}/rsvp", event.id))
        .header(Header::new(
            "x-session-token",
            guest_session.token.to_string(),
        ))
        .header(ContentType::JSON)
        .body(json!({ "status": "Going" }).to_string())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::NotFound,
        "Going must stay behind the view gate"
    );
}

// ---------------------------------------------------------------------------
// Cross-server upcoming list: GET /events/@me/upcoming. The caller's soonest
// visible events across every server they are in, ranked by each event's first
// occurrence at or after `from`. The route has its own rate bucket
// (`events_me`, 10 per 10 s per session), so no test spends more than nine
// upcoming calls on one session. Events are seeded through
// `CalendarEvent::create`, which derives `duration_ms` and `series_end`. The
// helpers below are used only by the tests in this block.
// ---------------------------------------------------------------------------

const UPCOMING_MINUTE: i64 = 60 * 1000;
const UPCOMING_HOUR: i64 = 60 * UPCOMING_MINUTE;
const UPCOMING_DAY: i64 = 24 * UPCOMING_HOUR;
const UPCOMING_T0: i64 = 1_900_000_000_000;
/// The route's window cap: 62 days.
const UPCOMING_MAX_WINDOW: i64 = 62 * UPCOMING_DAY;

/// The shape of a seeded event; `timezone` defaults to UTC.
#[derive(Default)]
struct UpcomingSeed<'a> {
    start: i64,
    end: Option<i64>,
    timezone: Option<&'a str>,
    recurrence: Option<revolt_database::RecurrenceRule>,
    channel: Option<&'a str>,
}

/// A server-wide one-off starting at `start`, with no end.
fn upcoming_at<'a>(start: i64) -> UpcomingSeed<'a> {
    UpcomingSeed {
        start,
        ..Default::default()
    }
}

/// A weekly rule that ends after `count` occurrences and skips `exceptions`.
fn upcoming_weekly(count: u16, exceptions: Vec<i64>) -> revolt_database::RecurrenceRule {
    revolt_database::RecurrenceRule {
        freq: revolt_database::Frequency::Weekly,
        interval: 1,
        by_weekday: vec![],
        end: revolt_database::RecurrenceEnd::Count { count },
        exceptions,
    }
}

/// Store an event through the model's create path. It runs no membership or
/// channel checks, so a test can also plant a corrupted row with it.
async fn upcoming_seed(
    harness: &TestHarness,
    server_id: &str,
    creator: &User,
    title: &str,
    seed: UpcomingSeed<'_>,
) -> revolt_database::CalendarEvent {
    revolt_database::CalendarEvent::create(
        &harness.db,
        server_id.to_string(),
        creator.id.clone(),
        title.to_string(),
        None,
        None,
        seed.start,
        seed.end,
        false,
        seed.timezone.unwrap_or("UTC").to_string(),
        seed.recurrence,
        None,
        seed.channel.map(str::to_string),
        None,
    )
    .await
    .expect("seed event")
}

/// Deny ViewChannel to everyone below the owner on `channel`.
async fn upcoming_hide_channel(harness: &TestHarness, channel: &mut revolt_database::Channel) {
    use revolt_database::PartialChannel;
    use revolt_permissions::{ChannelPermission, OverrideField};

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
}

/// A thread under `parent`, created by `creator`.
async fn upcoming_thread(
    harness: &TestHarness,
    parent: &revolt_database::Channel,
    creator: &User,
    name: &str,
) -> revolt_database::Channel {
    revolt_database::Channel::create_thread(
        &harness.db,
        parent,
        creator,
        None,
        v0::DataCreateThread {
            name: name.to_string(),
            auto_archive_minutes: None,
        },
    )
    .await
    .expect("thread")
}

/// `?from=<from>&to=<to>`, plus `&limit=<limit>` when given.
fn upcoming_query(from: i64, to: i64, limit: Option<i64>) -> String {
    match limit {
        Some(limit) => format!("?from={from}&to={to}&limit={limit}"),
        None => format!("?from={from}&to={to}"),
    }
}

/// One `GET /events/@me/upcoming{query}`. `auth` is a header name and its
/// token; None sends no credentials. Returns the status and the body parsed as
/// JSON (Null when it is not JSON).
async fn upcoming_get(
    harness: &TestHarness,
    auth: Option<(&str, &str)>,
    query: &str,
) -> (Status, serde_json::Value) {
    let mut request = harness.client.get(format!("/events/@me/upcoming{query}"));
    if let Some((name, token)) = auth {
        request = request.header(Header::new(name.to_string(), token.to_string()));
    }
    let response = request.dispatch().await;
    let status = response.status();
    let text = response.into_string().await.unwrap_or_default();
    let value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, value)
}

/// A session call that must answer 200, parsed as the route's response type.
async fn upcoming_ok(
    harness: &TestHarness,
    token: &str,
    query: &str,
) -> Vec<v0::EventWithOccurrences> {
    let (status, body) = upcoming_get(harness, Some(("x-session-token", token)), query).await;
    assert_eq!(
        status,
        Status::Ok,
        "GET /events/@me/upcoming{query}: {body}"
    );
    serde_json::from_value(body).expect("upcoming list")
}

/// A session call that must answer 400 `FailedValidation` naming `field`.
async fn upcoming_rejects(harness: &TestHarness, token: &str, query: &str, field: &str) {
    let (status, body) = upcoming_get(harness, Some(("x-session-token", token)), query).await;
    assert_eq!(
        status,
        Status::BadRequest,
        "GET /events/@me/upcoming{query}: {body}"
    );
    assert_eq!(body["type"], "FailedValidation", "{query}: {body}");
    assert_eq!(body["error"], field, "{query}: {body}");
}

/// The titles of a response, in order.
fn upcoming_titles(rows: &[v0::EventWithOccurrences]) -> Vec<&str> {
    rows.iter().map(|row| row.event.title.as_str()).collect()
}

/// The event ids of a response, in order.
fn upcoming_ids(rows: &[v0::EventWithOccurrences]) -> Vec<&str> {
    rows.iter().map(|row| row.event.id.as_str()).collect()
}

/// The ids of seeded one-offs in the route's order: (start, id) ascending.
fn upcoming_expected_order(events: &[revolt_database::CalendarEvent]) -> Vec<&str> {
    let mut keyed: Vec<(i64, &str)> = events
        .iter()
        .map(|event| (event.start, event.id.as_str()))
        .collect();
    keyed.sort();
    keyed.into_iter().map(|(_, id)| id).collect()
}

/// `GET /events/server/<server>` over the same window: the occurrence oracle.
/// It spends the shared `events` bucket, not `events_me`.
async fn upcoming_list_oracle(
    harness: &TestHarness,
    token: &str,
    server_id: &str,
    from: i64,
    to: i64,
) -> Vec<v0::EventWithOccurrences> {
    let response = harness
        .client
        .get(format!("/events/server/{server_id}?from={from}&to={to}"))
        .header(Header::new("x-session-token", token.to_string()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    response
        .into_json::<Vec<v0::EventWithOccurrences>>()
        .await
        .expect("list")
}

/// Two member servers come back as one list ordered by first occurrence, and a
/// server the caller is not in contributes nothing, not even its soonest event.
#[test]
fn upcoming_merges_member_servers_by_first_occurrence() {
    crate::util::test::rt().block_on(upcoming_merges_member_servers_by_first_occurrence_case())
}

async fn upcoming_merges_member_servers_by_first_occurrence_case() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server_a = make_server(&harness, &owner).await;
    let server_b = make_server(&harness, &owner).await;
    let outside = make_server(&harness, &owner).await;
    for server in [&server_a, &server_b] {
        Member::create(&harness.db, server, &guest, None)
            .await
            .expect("guest member");
    }

    // Created out of order, interleaved across the two servers.
    let hour = |n: i64| upcoming_at(UPCOMING_T0 + n * UPCOMING_HOUR);
    upcoming_seed(&harness, &server_a.id, &owner, "a3", hour(3)).await;
    upcoming_seed(&harness, &server_b.id, &owner, "b4", hour(4)).await;
    upcoming_seed(&harness, &server_a.id, &owner, "a1", hour(1)).await;
    upcoming_seed(&harness, &server_b.id, &owner, "b2", hour(2)).await;
    // The soonest event of all, in a server the guest is not in.
    let soonest = upcoming_at(UPCOMING_T0 + 30 * UPCOMING_MINUTE);
    upcoming_seed(&harness, &outside.id, &owner, "outside", soonest).await;

    let query = upcoming_query(UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY, None);
    let rows = upcoming_ok(&harness, &guest_session.token, &query).await;
    assert_eq!(upcoming_titles(&rows), ["a1", "b2", "a3", "b4"]);
    let servers: Vec<&str> = rows.iter().map(|row| row.event.server.as_str()).collect();
    assert_eq!(
        servers,
        [
            server_a.id.as_str(),
            server_b.id.as_str(),
            server_a.id.as_str(),
            server_b.id.as_str()
        ]
    );
    for row in &rows {
        assert_eq!(
            row.occurrences,
            vec![row.event.start],
            "a one-off's only occurrence is its start"
        );
    }

    // Control: the owner is in all three servers and does get the outside event.
    let rows = upcoming_ok(&harness, &owner_session.token, &query).await;
    assert_eq!(upcoming_titles(&rows), ["outside", "a1", "b2", "a3", "b4"]);
}

/// A kicked member stops getting that server's events on the next call; their
/// other server's events stay.
#[test]
fn upcoming_drops_a_server_after_a_kick() {
    crate::util::test::rt().block_on(upcoming_drops_a_server_after_a_kick_case())
}

async fn upcoming_drops_a_server_after_a_kick_case() {
    use revolt_database::RemovalIntention;

    let harness = TestHarness::new().await;
    let (_, _owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server_a = make_server(&harness, &owner).await;
    let server_b = make_server(&harness, &owner).await;
    for server in [&server_a, &server_b] {
        Member::create(&harness.db, server, &guest, None)
            .await
            .expect("guest member");
    }
    upcoming_seed(
        &harness,
        &server_a.id,
        &owner,
        "a",
        upcoming_at(UPCOMING_T0 + UPCOMING_HOUR),
    )
    .await;
    upcoming_seed(
        &harness,
        &server_b.id,
        &owner,
        "b",
        upcoming_at(UPCOMING_T0 + 2 * UPCOMING_HOUR),
    )
    .await;

    let query = upcoming_query(UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY, None);
    let rows = upcoming_ok(&harness, &guest_session.token, &query).await;
    assert_eq!(upcoming_titles(&rows), ["a", "b"]);

    for (server, expected) in [(&server_a, vec!["b"]), (&server_b, vec![])] {
        harness
            .db
            .fetch_member(&server.id, &guest.id)
            .await
            .expect("member row")
            .remove(&harness.db, server, RemovalIntention::Kick, true)
            .await
            .expect("kick");
        let rows = upcoming_ok(&harness, &guest_session.token, &query).await;
        assert_eq!(
            upcoming_titles(&rows),
            expected,
            "after the kick from {}",
            server.id
        );
    }
}

/// An event in a channel the caller cannot view, or in a thread under such a
/// channel, is left out for a plain member and kept for the owner. Events in a
/// visible channel and in a thread under it stay for both.
#[test]
fn upcoming_hides_denied_channel_and_its_threads() {
    crate::util::test::rt().block_on(upcoming_hides_denied_channel_and_its_threads_case())
}

async fn upcoming_hides_denied_channel_and_its_threads_case() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");

    let mut hidden = harness.new_channel(&server).await;
    upcoming_hide_channel(&harness, &mut hidden).await;
    let open = harness.new_channel(&server).await;
    let hidden_thread = upcoming_thread(&harness, &hidden, &owner, "hidden thread").await;
    let open_thread = upcoming_thread(&harness, &open, &owner, "open thread").await;

    let seeds = [
        ("wide", None),
        ("hidden", Some(hidden.id())),
        ("hidden thread", Some(hidden_thread.id())),
        ("open thread", Some(open_thread.id())),
        ("open", Some(open.id())),
    ];
    for (n, (title, channel)) in (1..).zip(seeds) {
        let seed = UpcomingSeed {
            channel,
            ..upcoming_at(UPCOMING_T0 + n * UPCOMING_HOUR)
        };
        upcoming_seed(&harness, &server.id, &owner, title, seed).await;
    }

    let query = upcoming_query(UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY, None);
    let rows = upcoming_ok(&harness, &guest_session.token, &query).await;
    assert_eq!(
        upcoming_titles(&rows),
        ["wide", "open thread", "open"],
        "a plain member must not get events in a hidden channel or its threads"
    );

    let rows = upcoming_ok(&harness, &owner_session.token, &query).await;
    assert_eq!(
        upcoming_titles(&rows),
        ["wide", "hidden", "hidden thread", "open thread", "open"],
        "the owner views every channel"
    );
}

/// A corrupted row that claims server A but names a channel of server B is
/// left out, even for a member of both who can view that channel, and even
/// though a valid event in the same channel (in its real server) is listed
/// first.
#[test]
fn upcoming_skips_event_naming_another_servers_channel() {
    crate::util::test::rt().block_on(upcoming_skips_event_naming_another_servers_channel_case())
}

async fn upcoming_skips_event_naming_another_servers_channel_case() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    // The assertion below holds whichever server is processed first: each server
    // is checked with its own viewer, and the event's server is compared with the
    // channel's on every check.
    let server_b = make_server(&harness, &owner).await;
    let server_a = make_server(&harness, &owner).await;
    for server in [&server_a, &server_b] {
        Member::create(&harness.db, server, &guest, None)
            .await
            .expect("guest member");
    }
    let channel_b = harness.new_channel(&server_b).await;

    let at = |n: i64, channel| UpcomingSeed {
        channel,
        ..upcoming_at(UPCOMING_T0 + n * UPCOMING_HOUR)
    };
    upcoming_seed(
        &harness,
        &server_b.id,
        &owner,
        "valid",
        at(1, Some(channel_b.id())),
    )
    .await;
    let corrupt = upcoming_seed(
        &harness,
        &server_a.id,
        &owner,
        "corrupt",
        at(2, Some(channel_b.id())),
    )
    .await;
    upcoming_seed(&harness, &server_a.id, &owner, "a wide", at(3, None)).await;
    assert_eq!(corrupt.server, server_a.id);

    let query = upcoming_query(UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY, None);
    for token in [&guest_session.token, &owner_session.token] {
        let rows = upcoming_ok(&harness, token, &query).await;
        assert_eq!(
            upcoming_titles(&rows),
            ["valid", "a wide"],
            "an event whose channel lives in another server is never listed"
        );
    }
}

/// A weekly series anchored weeks before the window, in America/New_York across
/// the November DST change, is listed with the same occurrences `list_events`
/// returns for that server minus the one already in progress at `from`. It is
/// ranked by its first occurrence at or after `from`, not by its anchor.
#[test]
fn upcoming_series_before_window_matches_list_oracle() {
    crate::util::test::rt().block_on(upcoming_series_before_window_matches_list_oracle_case())
}

async fn upcoming_series_before_window_matches_list_oracle_case() {
    // Tuesday 2030-10-01 18:00 EDT.
    const ANCHOR: i64 = 1_917_122_400_000;
    // 2030-10-29 22:30 UTC: 30 minutes into the 18:00 EDT occurrence.
    const FROM: i64 = 1_919_543_400_000;
    // 2030-11-20 00:00 UTC.
    const TO: i64 = 1_921_363_200_000;
    // 2030-10-29 18:00 EDT, then 2030-11-05, -12 and -19 18:00 EST.
    const IN_PROGRESS: i64 = 1_919_541_600_000;
    const AFTER_FROM: [i64; 3] = [1_920_150_000_000, 1_920_754_800_000, 1_921_359_600_000];

    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    let weekly = upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "weekly",
        UpcomingSeed {
            start: ANCHOR,
            end: Some(ANCHOR + 2 * UPCOMING_HOUR),
            timezone: Some("America/New_York"),
            recurrence: Some(upcoming_weekly(12, vec![])),
            channel: None,
        },
    )
    .await;
    // Starts after the anchor but before the series' first occurrence >= FROM.
    upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "between",
        upcoming_at(FROM + 3 * UPCOMING_DAY),
    )
    .await;

    let oracle = upcoming_list_oracle(&harness, &session.token, &server.id, FROM, TO).await;
    let oracle = oracle
        .into_iter()
        .find(|row| row.event.id == weekly.id)
        .expect("list_events returns the series")
        .occurrences;
    let mut expected_oracle = vec![IN_PROGRESS];
    expected_oracle.extend(AFTER_FROM);
    assert_eq!(
        oracle, expected_oracle,
        "the oracle includes the occurrence in progress at `from`"
    );
    let expected: Vec<i64> = oracle.into_iter().filter(|start| *start >= FROM).collect();

    let rows = upcoming_ok(&harness, &session.token, &upcoming_query(FROM, TO, None)).await;
    assert_eq!(upcoming_titles(&rows), ["between", "weekly"]);
    assert_eq!(rows[1].occurrences, expected);
    assert_eq!(rows[1].occurrences, AFTER_FROM);
    assert_eq!(
        rows[1].occurrences[0] - IN_PROGRESS,
        7 * UPCOMING_DAY + UPCOMING_HOUR,
        "the wall-clock time holds across the DST change"
    );
    assert_eq!(rows[1].event.start, ANCHOR, "the row carries the series");
}

/// A series whose next occurrence is excepted is keyed on the occurrence after
/// it, and the excepted start is not in its occurrences. An identical series
/// without the exception is keyed on the excepted start, as a control.
#[test]
fn upcoming_excepted_next_occurrence_keys_on_the_following_one() {
    crate::util::test::rt()
        .block_on(upcoming_excepted_next_occurrence_keys_on_the_following_one_case())
}

async fn upcoming_excepted_next_occurrence_keys_on_the_following_one_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    // Weekly from two weeks before T0, so T0 is the third occurrence.
    let series = |exceptions| UpcomingSeed {
        start: UPCOMING_T0 - 14 * UPCOMING_DAY,
        end: Some(UPCOMING_T0 - 14 * UPCOMING_DAY + UPCOMING_HOUR),
        recurrence: Some(upcoming_weekly(10, exceptions)),
        ..Default::default()
    };
    upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "excepted",
        series(vec![UPCOMING_T0]),
    )
    .await;
    upcoming_seed(&harness, &server.id, &owner, "plain", series(vec![])).await;
    upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "midweek",
        upcoming_at(UPCOMING_T0 + 3 * UPCOMING_DAY),
    )
    .await;

    let (from, to) = (UPCOMING_T0 - UPCOMING_HOUR, UPCOMING_T0 + 30 * UPCOMING_DAY);
    let weeks = |from_week: i64| -> Vec<i64> {
        (from_week..=4)
            .map(|week| UPCOMING_T0 + week * 7 * UPCOMING_DAY)
            .collect()
    };

    let rows = upcoming_ok(&harness, &session.token, &upcoming_query(from, to, None)).await;
    assert_eq!(upcoming_titles(&rows), ["plain", "midweek", "excepted"]);
    assert_eq!(rows[0].occurrences, weeks(0));
    assert_eq!(
        rows[2].occurrences,
        weeks(1),
        "the excepted start never appears"
    );

    let rows = upcoming_ok(&harness, &session.token, &upcoming_query(from, to, Some(2))).await;
    assert_eq!(upcoming_titles(&rows), ["plain", "midweek"]);
}

/// Cancelled series and cancelled one-offs are left out, and so is anything
/// whose only in-window occurrence started before `from`: a one-off in
/// progress at `from`, and a series whose last occurrence is in progress. An
/// event starting exactly at `from` is kept. `list_events` still returns all of
/// them, so the exclusions are this route's own.
#[test]
fn upcoming_excludes_cancelled_and_already_started() {
    crate::util::test::rt().block_on(upcoming_excludes_cancelled_and_already_started_case())
}

async fn upcoming_excludes_cancelled_and_already_started_case() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");

    let (from, to) = (UPCOMING_T0, UPCOMING_T0 + 7 * UPCOMING_DAY);
    let cancelled_series = upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "cancelled series",
        UpcomingSeed {
            recurrence: Some(upcoming_weekly(4, vec![])),
            ..upcoming_at(from + UPCOMING_HOUR)
        },
    )
    .await;
    let cancelled_oneoff = upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "cancelled one-off",
        upcoming_at(from + 2 * UPCOMING_HOUR),
    )
    .await;
    for event in [&cancelled_series, &cancelled_oneoff] {
        let response = harness
            .client
            .delete(format!("/events/event/{}", event.id))
            .header(Header::new(
                "x-session-token",
                owner_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
    }
    upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "in progress",
        UpcomingSeed {
            end: Some(from + UPCOMING_HOUR),
            ..upcoming_at(from - UPCOMING_HOUR)
        },
    )
    .await;
    // Two weekly occurrences; the second runs from 30 minutes before `from`
    // until 90 minutes after it.
    let last_start = from - 30 * UPCOMING_MINUTE;
    upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "series in progress",
        UpcomingSeed {
            start: last_start - 7 * UPCOMING_DAY,
            end: Some(last_start - 7 * UPCOMING_DAY + 2 * UPCOMING_HOUR),
            recurrence: Some(upcoming_weekly(2, vec![])),
            ..Default::default()
        },
    )
    .await;
    upcoming_seed(&harness, &server.id, &owner, "at from", upcoming_at(from)).await;
    upcoming_seed(
        &harness,
        &server.id,
        &owner,
        "later",
        upcoming_at(from + 3 * UPCOMING_HOUR),
    )
    .await;

    // Oracle: the per-server list returns every one of them.
    let listed = upcoming_list_oracle(&harness, &guest_session.token, &server.id, from, to).await;
    let mut listed = upcoming_titles(&listed)
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    listed.sort();
    assert_eq!(
        listed,
        [
            "at from",
            "cancelled one-off",
            "cancelled series",
            "in progress",
            "later",
            "series in progress"
        ]
    );

    let rows = upcoming_ok(
        &harness,
        &guest_session.token,
        &upcoming_query(from, to, None),
    )
    .await;
    assert_eq!(upcoming_titles(&rows), ["at from", "later"]);
    assert_eq!(rows[0].occurrences, vec![from]);
}

/// Bad windows are 400 `FailedValidation{window}`, never a 404 forward or a
/// panic: inverted, longer than 62 days, i64 extremes, and missing or
/// unparseable bounds. Exactly 62 days and a zero-length window are accepted
/// and both ends are inclusive.
#[test]
fn upcoming_rejects_bad_windows() {
    crate::util::test::rt().block_on(upcoming_rejects_bad_windows_case())
}

async fn upcoming_rejects_bad_windows_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let (_, other_session, _) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    let start = UPCOMING_T0 + UPCOMING_HOUR;
    upcoming_seed(&harness, &server.id, &owner, "event", upcoming_at(start)).await;

    // Seven calls on the first session.
    let token = &session.token;
    let t0 = UPCOMING_T0;
    upcoming_rejects(&harness, token, &upcoming_query(t0 + 1, t0, None), "window").await;
    let over = t0 + UPCOMING_MAX_WINDOW + 1;
    upcoming_rejects(&harness, token, &upcoming_query(t0, over, None), "window").await;
    let rows = upcoming_ok(
        &harness,
        token,
        &upcoming_query(t0, t0 + UPCOMING_MAX_WINDOW, None),
    )
    .await;
    assert_eq!(
        upcoming_titles(&rows),
        ["event"],
        "exactly 62 days is accepted"
    );
    let rows = upcoming_ok(&harness, token, &upcoming_query(start, start, None)).await;
    assert_eq!(
        upcoming_titles(&rows),
        ["event"],
        "from == to == start is kept"
    );
    for (from, to) in [(i64::MIN, i64::MAX), (i64::MAX, i64::MIN), (i64::MIN, 0)] {
        upcoming_rejects(&harness, token, &upcoming_query(from, to, None), "window").await;
    }

    // Six calls on a second session.
    let token = &other_session.token;
    for query in [
        format!("?to={t0}"),
        format!("?from={t0}"),
        String::new(),
        format!("?from=abc&to={t0}"),
        format!("?from=9223372036854775808&to={t0}"),
        upcoming_query(0, i64::MAX, None),
    ] {
        upcoming_rejects(&harness, token, &query, "window").await;
    }
}

/// `limit` defaults to 20 and accepts 1..=100; 0, 101 and -1 are 400
/// `FailedValidation{limit}`. The rows are the soonest ones, in order.
#[test]
fn upcoming_limit_default_and_bounds() {
    crate::util::test::rt().block_on(upcoming_limit_default_and_bounds_case())
}

async fn upcoming_limit_default_and_bounds_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    // 25 hourly one-offs, created in a shuffled order (7 is coprime to 25).
    for i in 0..25 {
        let n = (i * 7) % 25;
        let seed = upcoming_at(UPCOMING_T0 + n * UPCOMING_HOUR);
        upcoming_seed(&harness, &server.id, &owner, &format!("e{n:02}"), seed).await;
    }
    let titles = |count: i64| -> Vec<String> { (0..count).map(|n| format!("e{n:02}")).collect() };

    let (from, to) = (UPCOMING_T0, UPCOMING_T0 + 7 * UPCOMING_DAY);
    let token = &session.token;
    let rows = upcoming_ok(&harness, token, &upcoming_query(from, to, None)).await;
    assert_eq!(
        upcoming_titles(&rows),
        titles(20),
        "the default limit is 20"
    );
    let rows = upcoming_ok(&harness, token, &upcoming_query(from, to, Some(100))).await;
    assert_eq!(upcoming_titles(&rows), titles(25));
    let rows = upcoming_ok(&harness, token, &upcoming_query(from, to, Some(1))).await;
    assert_eq!(upcoming_titles(&rows), titles(1));
    for limit in [0, 101, -1] {
        upcoming_rejects(
            &harness,
            token,
            &upcoming_query(from, to, Some(limit)),
            "limit",
        )
        .await;
    }
}

/// With rows from two servers created in a shuffled order, `limit` keeps the
/// soonest N overall in (first occurrence, id) order, not each server's first
/// rows in server order.
#[test]
fn upcoming_returns_the_soonest_n_across_servers() {
    crate::util::test::rt().block_on(upcoming_returns_the_soonest_n_across_servers_case())
}

async fn upcoming_returns_the_soonest_n_across_servers_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server_a = make_server(&harness, &owner).await;
    let server_b = make_server(&harness, &owner).await;

    let mut seeded = Vec::new();
    for (server, hours, title) in [
        (&server_b, 5, "b5"),
        (&server_a, 2, "a2"),
        (&server_b, 1, "b1"),
        (&server_a, 6, "a6"),
        (&server_a, 4, "a4"),
        (&server_b, 3, "b3"),
        (&server_b, 7, "b7 tie"),
        (&server_a, 7, "a7 tie"),
    ] {
        let seed = upcoming_at(UPCOMING_T0 + hours * UPCOMING_HOUR);
        seeded.push(upcoming_seed(&harness, &server.id, &owner, title, seed).await);
    }

    let (from, to) = (UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY);
    let rows = upcoming_ok(&harness, &session.token, &upcoming_query(from, to, Some(3))).await;
    assert_eq!(upcoming_titles(&rows), ["b1", "a2", "b3"]);

    // The 7-hour tie is broken by event id.
    let rows = upcoming_ok(
        &harness,
        &session.token,
        &upcoming_query(from, to, Some(100)),
    )
    .await;
    assert_eq!(upcoming_ids(&rows), upcoming_expected_order(&seeded));
    assert_eq!(rows.len(), 8);
}

/// A server with more than a page of near events cannot push another server's
/// sooner-or-equal events out of the top `limit`, whatever the server order.
#[test]
fn upcoming_busy_server_cannot_crowd_out_another() {
    crate::util::test::rt().block_on(upcoming_busy_server_cannot_crowd_out_another_case())
}

async fn upcoming_busy_server_cannot_crowd_out_another_case() {
    let harness = TestHarness::new().await;
    let (_, _owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    // The busy server is created first, so it has the lower id.
    let busy = make_server(&harness, &owner).await;
    let quiet = make_server(&harness, &owner).await;
    for server in [&busy, &quiet] {
        Member::create(&harness.db, server, &guest, None)
            .await
            .expect("guest member");
    }

    // 150 one-offs a minute apart starting at T0.
    let mut seeded = Vec::new();
    for n in 0..150 {
        let seed = upcoming_at(UPCOMING_T0 + n * UPCOMING_MINUTE);
        seeded.push(upcoming_seed(&harness, &busy.id, &owner, &format!("busy {n}"), seed).await);
    }
    // Same keys as the busy server's first and third events.
    let quiet_first = upcoming_seed(
        &harness,
        &quiet.id,
        &owner,
        "quiet first",
        upcoming_at(UPCOMING_T0),
    )
    .await;
    let third = upcoming_at(UPCOMING_T0 + 2 * UPCOMING_MINUTE);
    let quiet_third = upcoming_seed(&harness, &quiet.id, &owner, "quiet third", third).await;
    seeded.push(quiet_first.clone());
    seeded.push(quiet_third.clone());
    let expected = upcoming_expected_order(&seeded);

    let (from, to) = (UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY);
    for limit in [5, 100] {
        let rows = upcoming_ok(
            &harness,
            &guest_session.token,
            &upcoming_query(from, to, Some(limit)),
        )
        .await;
        let ids = upcoming_ids(&rows);
        assert_eq!(ids, expected[..limit as usize], "limit {limit}");
        for quiet_event in [&quiet_first, &quiet_third] {
            assert!(
                ids.contains(&quiet_event.id.as_str()),
                "limit {limit}: {} was crowded out",
                quiet_event.title
            );
        }
    }
}

/// More than a page of events in a hidden channel, all sooner than a visible
/// event in the same server, cannot hide the visible one from a plain member.
#[test]
fn upcoming_hidden_rows_cannot_hide_a_visible_event() {
    crate::util::test::rt().block_on(upcoming_hidden_rows_cannot_hide_a_visible_event_case())
}

async fn upcoming_hidden_rows_cannot_hide_a_visible_event_case() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, guest_session, guest) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    Member::create(&harness.db, &server, &guest, None)
        .await
        .expect("guest member");
    let mut hidden = harness.new_channel(&server).await;
    upcoming_hide_channel(&harness, &mut hidden).await;

    for n in 0..120 {
        let seed = UpcomingSeed {
            channel: Some(hidden.id()),
            ..upcoming_at(UPCOMING_T0 + n * UPCOMING_MINUTE)
        };
        upcoming_seed(
            &harness,
            &server.id,
            &owner,
            &format!("hidden {n:03}"),
            seed,
        )
        .await;
    }
    let later = upcoming_at(UPCOMING_T0 + 3 * UPCOMING_HOUR);
    upcoming_seed(&harness, &server.id, &owner, "visible", later).await;

    let (from, to) = (UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY);
    for limit in [Some(1), None] {
        let rows = upcoming_ok(
            &harness,
            &guest_session.token,
            &upcoming_query(from, to, limit),
        )
        .await;
        assert_eq!(upcoming_titles(&rows), ["visible"], "limit {limit:?}");
    }

    // Control: the hidden rows are real and sooner.
    let rows = upcoming_ok(
        &harness,
        &owner_session.token,
        &upcoming_query(from, to, Some(3)),
    )
    .await;
    assert_eq!(
        upcoming_titles(&rows),
        ["hidden 000", "hidden 001", "hidden 002"]
    );
}

/// The one-off scan stops once `limit` one-offs are visible, but series do not
/// count toward that stop: a series keyed between those one-offs still takes its
/// place in the cut, and one keyed after all of them is cut, as is the last
/// one-off.
#[test]
fn upcoming_series_do_not_count_toward_the_oneoff_stop() {
    crate::util::test::rt().block_on(upcoming_series_do_not_count_toward_the_oneoff_stop_case())
}

async fn upcoming_series_do_not_count_toward_the_oneoff_stop_case() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    // Weekly series anchored a week before T0, so the anchor is outside the window
    // and the key is the second occurrence.
    let weekly_at = |hours: i64| UpcomingSeed {
        start: UPCOMING_T0 - 7 * UPCOMING_DAY + hours * UPCOMING_HOUR,
        end: Some(UPCOMING_T0 - 7 * UPCOMING_DAY + hours * UPCOMING_HOUR + UPCOMING_MINUTE),
        recurrence: Some(upcoming_weekly(4, vec![])),
        ..Default::default()
    };
    let early = upcoming_seed(&harness, &server.id, &owner, "early series", weekly_at(2)).await;
    upcoming_seed(&harness, &server.id, &owner, "late series", weekly_at(6)).await;
    for hours in [1, 3, 5] {
        let seed = upcoming_at(UPCOMING_T0 + hours * UPCOMING_HOUR);
        upcoming_seed(
            &harness,
            &server.id,
            &owner,
            &format!("one-off {hours}"),
            seed,
        )
        .await;
    }

    let (from, to) = (UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY);
    let rows = upcoming_ok(&harness, &session.token, &upcoming_query(from, to, Some(3))).await;
    assert_eq!(
        upcoming_titles(&rows),
        ["one-off 1", "early series", "one-off 3"],
        "the early series sits between the one-offs; the late series and the last one-off are cut"
    );
    assert_eq!(rows[1].event.id, early.id);
    assert_eq!(rows[1].occurrences, vec![UPCOMING_T0 + 2 * UPCOMING_HOUR]);

    // Control: with room for everything, the late series and the last one-off are listed.
    let rows = upcoming_ok(
        &harness,
        &session.token,
        &upcoming_query(from, to, Some(100)),
    )
    .await;
    assert_eq!(
        upcoming_titles(&rows),
        [
            "one-off 1",
            "early series",
            "one-off 3",
            "one-off 5",
            "late series"
        ]
    );
}

/// A bot is refused with 400 `IsBot`, even as a member of a server with events.
#[test]
fn upcoming_rejects_bots() {
    crate::util::test::rt().block_on(upcoming_rejects_bots_case())
}

async fn upcoming_rejects_bots_case() {
    use revolt_database::Bot;

    let harness = TestHarness::new().await;
    let (_, _session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;
    let (bot, bot_user) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
        .await
        .expect("bot");
    Member::create(&harness.db, &server, &bot_user, None)
        .await
        .expect("bot member");
    let seed = upcoming_at(UPCOMING_T0 + UPCOMING_HOUR);
    upcoming_seed(&harness, &server.id, &owner, "event", seed).await;

    let query = upcoming_query(UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY, None);
    let (status, body) =
        upcoming_get(&harness, Some(("x-bot-token", bot.token.as_str())), &query).await;
    assert_eq!(status, Status::BadRequest, "{body}");
    assert_eq!(body["type"], "IsBot", "{body}");
}

/// The route never answers NotFound, which the client reads as "this server
/// predates the route": a caller with no servers, and one whose only server
/// holds nothing in the window but an event naming a channel that does not
/// exist, both get 200 with an empty list. No session is 401.
#[test]
fn upcoming_never_answers_not_found() {
    crate::util::test::rt().block_on(upcoming_never_answers_not_found_case())
}

async fn upcoming_never_answers_not_found_case() {
    let harness = TestHarness::new().await;
    let (_, lonely_session, _) = harness.new_user().await;
    let (_, session, owner) = harness.new_user().await;
    let server = make_server(&harness, &owner).await;

    let query = upcoming_query(UPCOMING_T0, UPCOMING_T0 + UPCOMING_DAY, None);

    // Zero memberships.
    let rows = upcoming_ok(&harness, &lonely_session.token, &query).await;
    assert!(rows.is_empty());

    // Outside the window, and a dangling channel id inside it.
    let past = upcoming_at(UPCOMING_T0 - UPCOMING_DAY);
    upcoming_seed(&harness, &server.id, &owner, "past", past).await;
    let missing_channel = ulid::Ulid::new().to_string();
    let dangling = UpcomingSeed {
        channel: Some(missing_channel.as_str()),
        ..upcoming_at(UPCOMING_T0 + UPCOMING_HOUR)
    };
    upcoming_seed(&harness, &server.id, &owner, "dangling", dangling).await;
    let rows = upcoming_ok(&harness, &session.token, &query).await;
    assert!(rows.is_empty(), "{:?}", upcoming_titles(&rows));

    // No credentials at all.
    let (status, _) = upcoming_get(&harness, None, &query).await;
    assert_eq!(status, Status::Unauthorized);
}

// ---------------------------------------------------------------------------
// Thread and forum-post event scope: events in a thread or forum post take the
// parent channel's permissions. The helpers below are used only by the tests
// in this block.
// ---------------------------------------------------------------------------

/// A server whose default text channel is hidden from plain members, with a
/// thread under that channel created by the owner.
struct ThreadScopeFixture {
    server: Server,
    owner: User,
    owner_token: String,
    member: User,
    member_token: String,
    thread: revolt_database::Channel,
}

async fn thread_scope_fixture(harness: &TestHarness) -> ThreadScopeFixture {
    use revolt_database::{Channel, PartialChannel};
    use revolt_permissions::{ChannelPermission, OverrideField};

    let (_, owner_session, owner) = harness.new_user().await;
    let (_, member_session, member) = harness.new_user().await;
    let (server, channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Thread scope".to_string(),
            description: None,
            nsfw: None,
        },
        &owner,
        true,
    )
    .await
    .expect("server");
    for user in [&owner, &member] {
        Member::create(&harness.db, &server, user, None)
            .await
            .expect("member");
    }

    let mut parent = channels
        .into_iter()
        .find(|c| matches!(c, Channel::TextChannel { .. }))
        .expect("text channel");
    parent
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
    let thread = Channel::create_thread(
        &harness.db,
        &parent,
        &owner,
        None,
        v0::DataCreateThread {
            name: "hidden thread".to_string(),
            auto_archive_minutes: None,
        },
    )
    .await
    .expect("thread");

    ThreadScopeFixture {
        server,
        owner,
        owner_token: owner_session.token.to_string(),
        member,
        member_token: member_session.token.to_string(),
        thread,
    }
}

/// Add a member holding a role with server-wide `ManageChannel`.
async fn thread_scope_manager(harness: &TestHarness, server: &Server) -> String {
    use revolt_database::{PartialMember, Role};
    use revolt_permissions::{ChannelPermission, OverrideField};

    let (_, session, manager) = harness.new_user().await;
    let member = Member::create(&harness.db, server, &manager, None)
        .await
        .expect("manager member")
        .0;
    let role = Role {
        id: ulid::Ulid::new().to_string(),
        name: "Event managers".to_string(),
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
            &member.id,
            &PartialMember {
                roles: Some(vec![role.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("assign role");
    session.token.to_string()
}

/// Send a request; returns the status and the body parsed as JSON (Null if empty).
async fn thread_scope_call(
    harness: &TestHarness,
    method: rocket::http::Method,
    url: String,
    token: &str,
    body: Option<serde_json::Value>,
) -> (Status, serde_json::Value) {
    let mut request = harness
        .client
        .req(method, url)
        .header(Header::new("x-session-token", token.to_string()));
    if let Some(body) = body {
        request = request.header(ContentType::JSON).body(body.to_string());
    }
    let response = request.dispatch().await;
    let status = response.status();
    let text = response.into_string().await.unwrap_or_default();
    let value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, value)
}

fn thread_scope_event_body(title: &str, channel: Option<&str>) -> serde_json::Value {
    let mut body = json!({
        "title": title,
        "start": 1_900_000_000_000_i64,
        "timezone": "UTC"
    });
    if let Some(channel) = channel {
        body["channel"] = json!(channel);
    }
    body
}

fn thread_scope_list_url(server: &Server) -> String {
    format!(
        "/events/server/{}?from=1899000000000&to=1901000000000",
        server.id
    )
}

/// A thread under a visible text channel and a post in a visible forum work like
/// any other channel for a plain member: create, list, fetch, invite, RSVP and
/// attendees all succeed, and a server-wide manager can edit events there.
#[test]
fn thread_scope_visible_thread_and_forum_post_events_work() {
    crate::util::test::rt().block_on(thread_scope_visible_thread_and_forum_post_events_work_case())
}

async fn thread_scope_visible_thread_and_forum_post_events_work_case() {
    use revolt_database::{Channel, PartialMember, Role};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, member_session, member) = harness.new_user().await;
    let (_, manager_session, manager) = harness.new_user().await;
    let (owner_token, member_token, manager_token) = (
        owner_session.token.to_string(),
        member_session.token.to_string(),
        manager_session.token.to_string(),
    );

    let (mut server, channels) = Server::create(
        &harness.db,
        DataCreateServer {
            name: "Open threads".to_string(),
            description: None,
            nsfw: None,
        },
        &owner,
        true,
    )
    .await
    .expect("server");
    for user in [&owner, &member] {
        Member::create(&harness.db, &server, user, None)
            .await
            .expect("member");
    }
    let manager_member = Member::create(&harness.db, &server, &manager, None)
        .await
        .expect("manager member")
        .0;
    let role = Role {
        id: ulid::Ulid::new().to_string(),
        name: "Event managers".to_string(),
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

    let parent = channels
        .into_iter()
        .find(|c| matches!(c, Channel::TextChannel { .. }))
        .expect("text channel");
    let thread = Channel::create_thread(
        &harness.db,
        &parent,
        &owner,
        None,
        v0::DataCreateThread {
            name: "open thread".to_string(),
            auto_archive_minutes: None,
        },
    )
    .await
    .expect("thread");
    let forum = Channel::create_server_channel(
        &harness.db,
        &mut server,
        v0::DataCreateServerChannel {
            channel_type: v0::LegacyServerChannelType::Forum,
            name: "open forum".to_string(),
            ..Default::default()
        },
        false,
    )
    .await
    .expect("forum");
    let post = Channel::create_forum_post(
        &harness.db,
        &forum,
        &owner,
        "open post".to_string(),
        vec![],
        None,
    )
    .await
    .expect("post");

    let create_url = format!("/events/server/{}", server.id);
    for target in [thread.id(), post.id()] {
        let body = json!({
            "title": "Member event",
            "start": 1_900_000_000_000_i64,
            "timezone": "UTC",
            "channel": target
        });
        let (status, created) = thread_scope_call(
            &harness,
            Method::Post,
            create_url.clone(),
            &member_token,
            Some(body),
        )
        .await;
        assert_eq!(status, Status::Ok, "member creates in {target}");
        let created: v0::Event = serde_json::from_value(created).expect("event");
        assert_eq!(created.channel.as_deref(), Some(target));

        let body = json!({
            "title": "Owner event",
            "start": 1_900_000_000_000_i64,
            "timezone": "UTC",
            "channel": target
        });
        let (status, event) = thread_scope_call(
            &harness,
            Method::Post,
            create_url.clone(),
            &owner_token,
            Some(body),
        )
        .await;
        assert_eq!(status, Status::Ok, "owner creates in {target}");
        let event: v0::Event = serde_json::from_value(event).expect("event");

        let (status, result) = thread_scope_call(
            &harness,
            Method::Post,
            format!("/events/event/{}/invites", event.id),
            &owner_token,
            Some(json!({ "users": [member.id] })),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let result: v0::InviteResult = serde_json::from_value(result).expect("invite result");
        assert_eq!(result.invited, 1, "member invited in {target}");
        assert_eq!(result.skipped, 0);

        let (status, _) = thread_scope_call(
            &harness,
            Method::Put,
            format!("/events/event/{}/rsvp", event.id),
            &member_token,
            Some(json!({ "status": "Going" })),
        )
        .await;
        assert_eq!(status, Status::Ok, "member RSVPs Going in {target}");

        let (status, _) = thread_scope_call(
            &harness,
            Method::Get,
            format!("/events/event/{}", event.id),
            &member_token,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "member fetches in {target}");

        let (status, attendees) = thread_scope_call(
            &harness,
            Method::Get,
            format!("/events/event/{}/attendees", event.id),
            &member_token,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "member reads attendees in {target}");
        let attendees: v0::AttendeesResponse =
            serde_json::from_value(attendees).expect("attendees");
        assert_eq!(attendees.attendees.len(), 1);
        assert_eq!(attendees.attendees[0].user, member.id);
        assert!(matches!(
            attendees.attendees[0].status,
            v0::RsvpStatus::Going
        ));

        let (status, _) = thread_scope_call(
            &harness,
            Method::Patch,
            format!("/events/event/{}", event.id),
            &manager_token,
            Some(json!({ "title": "Renamed" })),
        )
        .await;
        assert_eq!(status, Status::Ok, "manager edits in {target}");
    }

    let (status, list) = thread_scope_call(
        &harness,
        Method::Get,
        format!(
            "/events/server/{}?from=1899000000000&to=1901000000000",
            server.id
        ),
        &member_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    let list: Vec<v0::EventWithOccurrences> = serde_json::from_value(list).expect("list");
    assert_eq!(list.len(), 4, "member lists every thread and post event");
}

/// An event in a thread under a channel hidden from plain members is absent from
/// their list and reads as missing on fetch and attendees; the owner still sees it.
#[test]
fn thread_scope_hidden_parent_event_not_readable() {
    crate::util::test::rt().block_on(thread_scope_hidden_parent_event_not_readable_case())
}

async fn thread_scope_hidden_parent_event_not_readable_case() {
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;

    let (status, event) = thread_scope_call(
        &harness,
        Method::Post,
        format!("/events/server/{}", fx.server.id),
        &fx.owner_token,
        Some(thread_scope_event_body("Hidden", Some(fx.thread.id()))),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let event: v0::Event = serde_json::from_value(event).expect("event");

    // The owner reads it on every path.
    let (status, list) = thread_scope_call(
        &harness,
        Method::Get,
        thread_scope_list_url(&fx.server),
        &fx.owner_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    let list: Vec<v0::EventWithOccurrences> = serde_json::from_value(list).expect("list");
    assert_eq!(list.len(), 1, "owner lists the thread event");
    let (status, _) = thread_scope_call(
        &harness,
        Method::Get,
        format!("/events/event/{}", event.id),
        &fx.owner_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);

    // A plain member does not. All three reads are taken before asserting, so a
    // failure reports every path at once: (list status, events listed, fetch,
    // attendees).
    let (list_status, list) = thread_scope_call(
        &harness,
        Method::Get,
        thread_scope_list_url(&fx.server),
        &fx.member_token,
        None,
    )
    .await;
    let listed = serde_json::from_value::<Vec<v0::EventWithOccurrences>>(list)
        .map(|list| list.len())
        .unwrap_or(usize::MAX);
    let (fetch_status, _) = thread_scope_call(
        &harness,
        Method::Get,
        format!("/events/event/{}", event.id),
        &fx.member_token,
        None,
    )
    .await;
    let (attendees_status, _) = thread_scope_call(
        &harness,
        Method::Get,
        format!("/events/event/{}/attendees", event.id),
        &fx.member_token,
        None,
    )
    .await;
    assert_eq!(
        (list_status, listed, fetch_status, attendees_status),
        (Status::Ok, 0, Status::NotFound, Status::NotFound),
        "(list status, events listed, fetch, attendees) for a member who cannot \
         view the parent channel"
    );
}

/// A plain member can neither create an event in, nor move their own event into,
/// a thread or forum post whose parent they cannot view.
#[test]
fn thread_scope_hidden_parent_rejects_create_and_move() {
    crate::util::test::rt().block_on(thread_scope_hidden_parent_rejects_create_and_move_case())
}

async fn thread_scope_hidden_parent_rejects_create_and_move_case() {
    use revolt_database::{Channel, PartialChannel};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;

    // A forum hidden from plain members, with a post in it.
    let mut server = fx.server.clone();
    let mut forum = Channel::create_server_channel(
        &harness.db,
        &mut server,
        v0::DataCreateServerChannel {
            channel_type: v0::LegacyServerChannelType::Forum,
            name: "hidden forum".to_string(),
            ..Default::default()
        },
        false,
    )
    .await
    .expect("forum");
    forum
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
    let post = Channel::create_forum_post(
        &harness.db,
        &forum,
        &fx.owner,
        "hidden post".to_string(),
        vec![],
        None,
    )
    .await
    .expect("post");

    let create_url = format!("/events/server/{}", fx.server.id);
    for target in [fx.thread.id(), post.id()] {
        let (status, _) = thread_scope_call(
            &harness,
            Method::Post,
            create_url.clone(),
            &fx.member_token,
            Some(thread_scope_event_body("Planning", Some(target))),
        )
        .await;
        assert_eq!(status, Status::NotFound, "create in {target}");
    }

    // The member's own server-wide event cannot be moved there either.
    let (status, event) = thread_scope_call(
        &harness,
        Method::Post,
        create_url.clone(),
        &fx.member_token,
        Some(thread_scope_event_body("Mine", None)),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let event: v0::Event = serde_json::from_value(event).expect("event");
    for target in [fx.thread.id(), post.id()] {
        let (status, _) = thread_scope_call(
            &harness,
            Method::Patch,
            format!("/events/event/{}", event.id),
            &fx.member_token,
            Some(json!({ "channel": target })),
        )
        .await;
        assert_eq!(status, Status::NotFound, "move into {target}");
    }
    let (status, event) = thread_scope_call(
        &harness,
        Method::Get,
        format!("/events/event/{}", event.id),
        &fx.member_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    let event: v0::EventWithContext = serde_json::from_value(event).expect("event");
    assert_eq!(event.event.channel, None, "the event stayed server-wide");
}

/// Moving an event into a thread whose parent a Going attendee cannot view prunes
/// their RSVP row; an attendee whose role the parent allows keeps theirs.
#[test]
fn thread_scope_move_into_hidden_thread_prunes_rsvp() {
    crate::util::test::rt().block_on(thread_scope_move_into_hidden_thread_prunes_rsvp_case())
}

async fn thread_scope_move_into_hidden_thread_prunes_rsvp_case() {
    use revolt_database::{Channel, PartialChannel, PartialMember, Role};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::Method;
    use std::collections::HashMap;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;

    // A second member whose role the hidden parent channel allows to view it.
    let (_, viewer_session, viewer) = harness.new_user().await;
    let viewer_token = viewer_session.token.to_string();
    let viewer_member = Member::create(&harness.db, &fx.server, &viewer, None)
        .await
        .expect("viewer member")
        .0;
    let role = Role {
        id: ulid::Ulid::new().to_string(),
        name: "Parent viewers".to_string(),
        permissions: OverrideField { a: 0, d: 0 },
        colour: None,
        hoist: false,
        rank: 1,
        icon: None,
    };
    harness
        .db
        .insert_role(&fx.server.id, &role)
        .await
        .expect("role");
    harness
        .db
        .update_member(
            &viewer_member.id,
            &PartialMember {
                roles: Some(vec![role.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("assign role");
    let Channel::Thread { parent_channel, .. } = &fx.thread else {
        panic!("fixture thread is not a thread");
    };
    let mut parent = harness
        .db
        .fetch_channel(parent_channel)
        .await
        .expect("parent");
    parent
        .update(
            &harness.db,
            PartialChannel {
                role_permissions: Some(HashMap::from([(
                    role.id.clone(),
                    OverrideField {
                        a: ChannelPermission::ViewChannel as i64,
                        d: 0,
                    },
                )])),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("allow the role on the parent");

    let (status, event) = thread_scope_call(
        &harness,
        Method::Post,
        format!("/events/server/{}", fx.server.id),
        &fx.owner_token,
        Some(thread_scope_event_body("Movable", None)),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let event: v0::Event = serde_json::from_value(event).expect("event");

    let (status, result) = thread_scope_call(
        &harness,
        Method::Post,
        format!("/events/event/{}/invites", event.id),
        &fx.owner_token,
        Some(json!({ "users": [fx.member.id, viewer.id] })),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let result: v0::InviteResult = serde_json::from_value(result).expect("invite result");
    assert_eq!(result.invited, 2);
    for token in [&fx.member_token, &viewer_token] {
        let (status, _) = thread_scope_call(
            &harness,
            Method::Put,
            format!("/events/event/{}/rsvp", event.id),
            token,
            Some(json!({ "status": "Going" })),
        )
        .await;
        assert_eq!(status, Status::Ok);
    }

    let (status, _) = thread_scope_call(
        &harness,
        Method::Patch,
        format!("/events/event/{}", event.id),
        &fx.owner_token,
        Some(json!({ "channel": fx.thread.id() })),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let (status, attendees) = thread_scope_call(
        &harness,
        Method::Get,
        format!("/events/event/{}/attendees", event.id),
        &fx.owner_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    let attendees: v0::AttendeesResponse = serde_json::from_value(attendees).expect("attendees");
    let kept: Vec<&str> = attendees
        .attendees
        .iter()
        .map(|row| row.user.as_str())
        .collect();
    assert!(
        !kept.contains(&fx.member.id.as_str()),
        "Going row kept after a move into a thread its user cannot view"
    );
    assert_eq!(
        kept,
        vec![viewer.id.as_str()],
        "the Going row of a user the parent allows must survive the move"
    );
    assert!(matches!(
        attendees.attendees[0].status,
        v0::RsvpStatus::Going
    ));
}

/// Inviting a member to an event in a thread whose parent they cannot view is
/// skipped, the same as for the hidden channel itself.
#[test]
fn thread_scope_invite_to_hidden_thread_event_skipped() {
    crate::util::test::rt().block_on(thread_scope_invite_to_hidden_thread_event_skipped_case())
}

async fn thread_scope_invite_to_hidden_thread_event_skipped_case() {
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;

    let (status, event) = thread_scope_call(
        &harness,
        Method::Post,
        format!("/events/server/{}", fx.server.id),
        &fx.owner_token,
        Some(thread_scope_event_body("Hidden", Some(fx.thread.id()))),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let event: v0::Event = serde_json::from_value(event).expect("event");

    let (status, result) = thread_scope_call(
        &harness,
        Method::Post,
        format!("/events/event/{}/invites", event.id),
        &fx.owner_token,
        Some(json!({ "users": [fx.member.id] })),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let result: v0::InviteResult = serde_json::from_value(result).expect("invite result");
    assert_eq!(
        result.invited, 0,
        "member invited to a thread event they cannot view"
    );
    assert_eq!(result.skipped, 1);

    let (status, attendees) = thread_scope_call(
        &harness,
        Method::Get,
        format!("/events/event/{}/attendees", event.id),
        &fx.owner_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    let attendees: v0::AttendeesResponse = serde_json::from_value(attendees).expect("attendees");
    assert!(attendees.attendees.is_empty());
}

/// An imported row whose `voiceId` names a thread under a channel the importer
/// cannot view imports with no channel; one naming a visible thread keeps it.
#[test]
fn thread_scope_import_voice_id_in_hidden_thread_degrades() {
    crate::util::test::rt().block_on(thread_scope_import_voice_id_in_hidden_thread_degrades_case())
}

async fn thread_scope_import_voice_id_in_hidden_thread_degrades_case() {
    use revolt_database::{Channel, Message};
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;
    let manager_token = thread_scope_manager(&harness, &fx.server).await;

    // A visible source channel with a visible thread of its own.
    let source = harness.new_channel(&fx.server).await;
    let open_thread = Channel::create_thread(
        &harness.db,
        &source,
        &fx.owner,
        None,
        v0::DataCreateThread {
            name: "open thread".to_string(),
            auto_archive_minutes: None,
        },
    )
    .await
    .expect("thread");

    for (title, voice) in [
        ("Hidden voice", fx.thread.id()),
        ("Open voice", open_thread.id()),
    ] {
        harness
            .db
            .insert_message(&Message {
                id: ulid::Ulid::new().to_string(),
                channel: source.id().to_string(),
                author: fx.owner.id.clone(),
                content: Some(format!(
                    "[ACUTEST_EVENT]:{}",
                    json!({ "title": title, "start": "2030-05-01T10:00:00.000Z", "voiceId": voice })
                )),
                ..Default::default()
            })
            .await
            .expect("message");
    }

    let (status, result) = thread_scope_call(
        &harness,
        Method::Post,
        format!("/events/server/{}/import", fx.server.id),
        &manager_token,
        Some(json!({ "channel": source.id() })),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let result: v0::ImportResult = serde_json::from_value(result).expect("import result");
    assert_eq!(result.imported, 2);

    let (status, list) = thread_scope_call(
        &harness,
        Method::Get,
        format!(
            "/events/server/{}?from=1890000000000&to=1920000000000",
            fx.server.id
        ),
        &fx.owner_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    let list: Vec<v0::EventWithOccurrences> = serde_json::from_value(list).expect("list");
    let channel_of = |title: &str| {
        list.iter()
            .find(|row| row.event.title == title)
            .unwrap_or_else(|| panic!("{} not imported", title))
            .event
            .channel
            .clone()
    };
    assert_eq!(
        channel_of("Open voice").as_deref(),
        Some(open_thread.id()),
        "a visible thread is kept"
    );
    assert_eq!(
        channel_of("Hidden voice"),
        None,
        "a thread under a channel the importer cannot view must not be attached"
    );
}

/// A member with server-wide `ManageChannel` that the parent channel takes away
/// cannot edit or cancel an event in a thread under it.
#[test]
fn thread_scope_manage_is_judged_on_the_parent() {
    crate::util::test::rt().block_on(thread_scope_manage_is_judged_on_the_parent_case())
}

async fn thread_scope_manage_is_judged_on_the_parent_case() {
    use revolt_database::{Channel, PartialChannel};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;
    let manager_token = thread_scope_manager(&harness, &fx.server).await;

    // A visible channel that takes ManageChannel away from everyone but the owner.
    let mut parent = harness.new_channel(&fx.server).await;
    parent
        .update(
            &harness.db,
            PartialChannel {
                default_permissions: Some(OverrideField {
                    a: 0,
                    d: ChannelPermission::ManageChannel as i64,
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("deny manage");
    let thread = Channel::create_thread(
        &harness.db,
        &parent,
        &fx.owner,
        None,
        v0::DataCreateThread {
            name: "managed thread".to_string(),
            auto_archive_minutes: None,
        },
    )
    .await
    .expect("thread");

    let create_url = format!("/events/server/{}", fx.server.id);
    let (status, server_wide) = thread_scope_call(
        &harness,
        Method::Post,
        create_url.clone(),
        &fx.owner_token,
        Some(thread_scope_event_body("Server-wide", None)),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let server_wide: v0::Event = serde_json::from_value(server_wide).expect("event");
    let (status, in_thread) = thread_scope_call(
        &harness,
        Method::Post,
        create_url,
        &fx.owner_token,
        Some(thread_scope_event_body("In thread", Some(thread.id()))),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let in_thread: v0::Event = serde_json::from_value(in_thread).expect("event");

    // The manager can see the thread event and manage server-wide events.
    let (status, _) = thread_scope_call(
        &harness,
        Method::Get,
        format!("/events/event/{}", in_thread.id),
        &manager_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    let (status, _) = thread_scope_call(
        &harness,
        Method::Patch,
        format!("/events/event/{}", server_wide.id),
        &manager_token,
        Some(json!({ "title": "Renamed" })),
    )
    .await;
    assert_eq!(status, Status::Ok);

    // But not the thread event.
    let (status, _) = thread_scope_call(
        &harness,
        Method::Patch,
        format!("/events/event/{}", in_thread.id),
        &manager_token,
        Some(json!({ "title": "Renamed" })),
    )
    .await;
    assert_eq!(status, Status::Forbidden, "edit");
    let (status, _) = thread_scope_call(
        &harness,
        Method::Delete,
        format!("/events/event/{}", in_thread.id),
        &manager_token,
        None,
    )
    .await;
    assert_eq!(status, Status::Forbidden, "cancel");
}

/// Create two owner events, one in a channel and one in a thread, then delete the
/// channel and the thread's parent. Returns the event ids.
async fn thread_scope_events_in_deleted_channels(
    harness: &TestHarness,
    fx: &ThreadScopeFixture,
) -> Vec<String> {
    use revolt_database::Channel;
    use rocket::http::Method;

    let doomed = harness.new_channel(&fx.server).await;
    let doomed_parent = harness.new_channel(&fx.server).await;
    let orphan = Channel::create_thread(
        &harness.db,
        &doomed_parent,
        &fx.owner,
        None,
        v0::DataCreateThread {
            name: "orphaned thread".to_string(),
            auto_archive_minutes: None,
        },
    )
    .await
    .expect("thread");

    let mut events = Vec::new();
    for target in [doomed.id(), orphan.id()] {
        let (status, event) = thread_scope_call(
            harness,
            Method::Post,
            format!("/events/server/{}", fx.server.id),
            &fx.owner_token,
            Some(thread_scope_event_body("Doomed", Some(target))),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let event: v0::Event = serde_json::from_value(event).expect("event");
        events.push(event.id);
    }
    harness
        .db
        .delete_channel(&doomed)
        .await
        .expect("delete channel");
    harness
        .db
        .delete_channel(&doomed_parent)
        .await
        .expect("delete parent");
    events
}

/// An event whose channel (or thread parent) was deleted can still be cancelled by
/// a server-wide manager, and still not by a plain member.
#[test]
fn thread_scope_deleted_channel_event_cancellable_by_manager() {
    crate::util::test::rt()
        .block_on(thread_scope_deleted_channel_event_cancellable_by_manager_case())
}

async fn thread_scope_deleted_channel_event_cancellable_by_manager_case() {
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;
    let manager_token = thread_scope_manager(&harness, &fx.server).await;
    let events = thread_scope_events_in_deleted_channels(&harness, &fx).await;

    for event_id in &events {
        let (status, _) = thread_scope_call(
            &harness,
            Method::Delete,
            format!("/events/event/{event_id}"),
            &fx.member_token,
            None,
        )
        .await;
        assert_eq!(status, Status::Forbidden, "plain member cancels {event_id}");

        let (status, _) = thread_scope_call(
            &harness,
            Method::Delete,
            format!("/events/event/{event_id}"),
            &manager_token,
            None,
        )
        .await;
        assert_eq!(status, Status::NoContent, "manager cancels {event_id}");
        let stored = harness.db.fetch_event(event_id).await.expect("event row");
        assert!(stored.cancelled);
    }
}

/// A server-wide manager cannot edit, or invite to, an event whose channel (or
/// thread parent) was deleted; only cancelling falls back to server-wide rights.
#[test]
fn thread_scope_deleted_channel_event_not_editable_by_manager() {
    crate::util::test::rt()
        .block_on(thread_scope_deleted_channel_event_not_editable_by_manager_case())
}

async fn thread_scope_deleted_channel_event_not_editable_by_manager_case() {
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;
    let manager_token = thread_scope_manager(&harness, &fx.server).await;
    let events = thread_scope_events_in_deleted_channels(&harness, &fx).await;

    for event_id in &events {
        let (status, _) = thread_scope_call(
            &harness,
            Method::Patch,
            format!("/events/event/{event_id}"),
            &manager_token,
            Some(json!({ "title": "Renamed" })),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "manager edits {event_id}");

        let (status, _) = thread_scope_call(
            &harness,
            Method::Post,
            format!("/events/event/{event_id}/invites"),
            &manager_token,
            Some(json!({ "users": [fx.member.id] })),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "manager invites to {event_id}");

        let stored = harness.db.fetch_event(event_id).await.expect("event row");
        assert_eq!(stored.title, "Doomed");
        assert!(harness
            .db
            .fetch_rsvps_for_event(event_id)
            .await
            .expect("rsvps")
            .is_empty());

        let (status, _) = thread_scope_call(
            &harness,
            Method::Delete,
            format!("/events/event/{event_id}"),
            &manager_token,
            None,
        )
        .await;
        assert_eq!(status, Status::NoContent, "manager cancels {event_id}");
    }
}

/// A user outside the server gets `NotFound` from the RSVP route whether the event
/// is live or cancelled; a member who can view the event still gets the cancelled
/// error.
#[test]
fn thread_scope_rsvp_by_non_member_reads_as_missing() {
    crate::util::test::rt().block_on(thread_scope_rsvp_by_non_member_reads_as_missing_case())
}

async fn thread_scope_rsvp_by_non_member_reads_as_missing_case() {
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;
    let (_, outsider_session, _) = harness.new_user().await;
    let outsider_token = outsider_session.token.to_string();

    let mut events = Vec::new();
    for title in ["Live", "Called off"] {
        let (status, event) = thread_scope_call(
            &harness,
            Method::Post,
            format!("/events/server/{}", fx.server.id),
            &fx.owner_token,
            Some(thread_scope_event_body(title, None)),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let event: v0::Event = serde_json::from_value(event).expect("event");
        events.push(event.id);
    }
    let (status, _) = thread_scope_call(
        &harness,
        Method::Delete,
        format!("/events/event/{}", events[1]),
        &fx.owner_token,
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);

    for event_id in &events {
        for answer in ["Going", "NotGoing"] {
            let (status, _) = thread_scope_call(
                &harness,
                Method::Put,
                format!("/events/event/{event_id}/rsvp"),
                &outsider_token,
                Some(json!({ "status": answer })),
            )
            .await;
            assert_eq!(status, Status::NotFound, "{answer} on {event_id}");
        }
    }

    let (status, _) = thread_scope_call(
        &harness,
        Method::Put,
        format!("/events/event/{}/rsvp", events[1]),
        &fx.member_token,
        Some(json!({ "status": "Going" })),
    )
    .await;
    assert_eq!(
        status,
        Status::BadRequest,
        "member answers a cancelled event"
    );
}

/// A member who cannot view a cancelled event's thread gets `NotFound` from the
/// RSVP route, the same as for a missing event; the owner, who can view it, gets
/// the cancelled error.
#[test]
fn thread_scope_rsvp_on_hidden_cancelled_event_reads_as_missing() {
    crate::util::test::rt()
        .block_on(thread_scope_rsvp_on_hidden_cancelled_event_reads_as_missing_case())
}

async fn thread_scope_rsvp_on_hidden_cancelled_event_reads_as_missing_case() {
    use rocket::http::Method;

    let harness = TestHarness::new().await;
    let fx = thread_scope_fixture(&harness).await;

    let (status, event) = thread_scope_call(
        &harness,
        Method::Post,
        format!("/events/server/{}", fx.server.id),
        &fx.owner_token,
        Some(thread_scope_event_body("Hidden", Some(fx.thread.id()))),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let event: v0::Event = serde_json::from_value(event).expect("event");
    let (status, _) = thread_scope_call(
        &harness,
        Method::Delete,
        format!("/events/event/{}", event.id),
        &fx.owner_token,
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);

    for answer in ["Going", "NotGoing"] {
        let (status, _) = thread_scope_call(
            &harness,
            Method::Put,
            format!("/events/event/{}/rsvp", event.id),
            &fx.member_token,
            Some(json!({ "status": answer })),
        )
        .await;
        assert_eq!(status, Status::NotFound, "member answers {answer}");
    }

    let (status, _) = thread_scope_call(
        &harness,
        Method::Put,
        format!("/events/event/{}/rsvp", event.id),
        &fx.owner_token,
        Some(json!({ "status": "Going" })),
    )
    .await;
    assert_eq!(
        status,
        Status::BadRequest,
        "owner answers a cancelled event"
    );
}
