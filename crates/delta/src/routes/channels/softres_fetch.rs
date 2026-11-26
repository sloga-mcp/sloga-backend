use std::collections::HashSet;

use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, ProtectedReadView, SoftResSheet, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::util::polls::now_ms;
use crate::util::softres::can_see_full;
// `softres_export` imports the helper from here
pub(super) use crate::util::softres::sheet_is_servable;

/// [`sheet_is_servable`] for a page of sheets, in one read: drops every
/// sheet the read may not serve
async fn retain_servable_sheets(
    db: &Database,
    channel: &Channel,
    permission_channel: &Channel,
    sheets: &mut Vec<SoftResSheet>,
) -> Result<()> {
    let view = ProtectedReadView::of_read_target(channel, permission_channel);
    if !view.protected || sheets.is_empty() {
        return Ok(());
    }

    let ids: Vec<String> = sheets.iter().map(|sheet| sheet.message.clone()).collect();
    let servable: HashSet<String> = db
        .fetch_messages_by_id(&ids)
        .await?
        .into_iter()
        .filter(|message| message.is_servable(&view))
        .map(|message| message.id)
        .collect();
    sheets.retain(|sheet| servable.contains(&sheet.message));
    Ok(())
}

/// # Fetch Soft-Reserve Sheet
///
/// Fetches a sheet's dynamic state. On hidden sheets, reserve rows and
/// per-item counts are included only for the creator / ManageMessages —
/// enforced here, server-side. The caller's own row is always included.
#[openapi(tag = "Soft Reserves")]
#[get("/<target>/softres/<sheet_id>")]
pub async fn softres_fetch(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sheet_id: String,
) -> Result<Json<v0::SoftRes>> {
    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let sheet = db.fetch_sheet(&sheet_id).await?;
    if sheet.channel != channel.id()
        || !sheet_is_servable(db, &channel, &permission_channel, &sheet).await?
    {
        return Err(create_error!(NotFound));
    }

    let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;
    let include_full = can_see_full(&sheet, &user.id, &permissions);
    Ok(Json(sheet.into_model(include_full, rows, &user.id, now_ms())))
}

/// # Bulk Fetch Soft-Reserve Sheets
///
/// Fetches sheet state for the sheets on a page of messages in one
/// request (avoids one fetch per sheet message on scroll). The same
/// per-sheet visibility gating as the single fetch applies.
#[openapi(tag = "Soft Reserves")]
#[post("/<target>/softres/fetch", data = "<data>")]
pub async fn softres_fetch_bulk(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataSoftResFetchBulk>,
) -> Result<Json<Vec<v0::SoftRes>>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Dedup ids: Mongo's `$in` dedupes while the Reference driver yields
    // one entry per requested id — without this the drivers disagree on
    // the response shape for a repeated id.
    let mut ids = data.ids;
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(id.clone()));

    let mut sheets = db.fetch_sheets(&ids).await?;

    // The channel topic is the authorization boundary: only sheets that
    // actually live in this channel are returned.
    sheets.retain(|sheet| sheet.channel == channel.id());
    // ...and whose carrying message the channel still serves (design 7.4
    // "S4")
    retain_servable_sheets(db, &channel, &permission_channel, &mut sheets).await?;

    // One row-fetch per sheet — bounded by the ≤25-id request cap and
    // raid-size row counts; still one HTTP round-trip for the page.
    let now = now_ms();
    let mut out = Vec::with_capacity(sheets.len());
    for sheet in sheets {
        let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;
        let include_full = can_see_full(&sheet, &user.id, &permissions);
        out.push(sheet.into_model(include_full, rows, &user.id, now));
    }

    Ok(Json(out))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    use super::super::softres_reserve::test::create_sheet;

    #[test]
    fn fetch_is_channel_scoped_and_bulk_returns_page() {
        crate::util::test::rt().block_on(fetch_is_channel_scoped_and_bulk_returns_page_case())
    }

    async fn fetch_is_channel_scoped_and_bulk_returns_page_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        // NOT a member of the server below
        let (_, outsider_session, _) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let other_channel = harness.new_channel(&server).await;

        let mut sheet_ids = Vec::new();
        for title in ["one", "two"] {
            let message = create_sheet(
                &harness,
                &session.token,
                channel.id(),
                json!({ "title": title, "edition": "classic", "raids": ["mc"] }),
            )
            .await;
            sheet_ids.push(message.softres.expect("softres").id);
        }

        // Single fetch works for a member
        let response = harness
            .client
            .get(format!(
                "/channels/{}/softres/{}",
                channel.id(),
                sheet_ids[0]
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
        assert_eq!(state.creator_id, user.id);
        assert!(!state.locked);

        // An outsider can't fetch
        let response = harness
            .client
            .get(format!(
                "/channels/{}/softres/{}",
                channel.id(),
                sheet_ids[0]
            ))
            .header(Header::new(
                "x-session-token",
                outsider_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok, "outsider must not fetch");

        // The wrong channel is scoped out
        let response = harness
            .client
            .get(format!(
                "/channels/{}/softres/{}",
                other_channel.id(),
                sheet_ids[0]
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::NotFound,
            "sheet lookups are channel-scoped"
        );

        // Bulk returns both, scoped to the channel
        let response = harness
            .client
            .post(format!("/channels/{}/softres/fetch", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "ids": sheet_ids }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let sheets: Vec<v0::SoftRes> = response.into_json().await.expect("`Vec<SoftRes>`");
        assert_eq!(sheets.len(), 2);
    }
}

/// Protected channels (S4): the world the softres routes' protected tests
/// share
#[cfg(test)]
pub(super) mod protected_fixture {
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        Channel, HistoryWipe, Message, PartialChannel, Session, SoftResReserveRow, SoftResSheet,
        User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Method, Status};
    use serde_json::Value;
    use ulid::Ulid;

    use crate::util::polls::now_ms;
    use crate::util::test::{ProtectedChannel, TestHarness};

    /// The items of the reserve row [`new_sheet`] seeds
    pub const SEEDED_ITEMS: [u32; 1] = [17204];

    /// What [`world`] built
    pub struct World {
        pub harness: TestHarness,
        /// Protected with its history kept: the boundary B is `sheet`'s row
        pub protected: ProtectedChannel,
        /// An unprotected channel of the same server
        pub ordinary: Channel,
        pub owner: User,
        pub owner_session: Session,
        /// Seated in the protected channel
        pub member: User,
        pub member_session: Session,
        /// An open sheet by the owner in the protected channel, carried by
        /// the pre-protect row B; the member holds a reserve row on it
        pub sheet: SoftResSheet,
        /// The same in the ordinary channel
        pub ordinary_sheet: SoftResSheet,
    }

    /// An open sheet by `creator` carried by the plaintext row `message_id`
    /// of `channel`, both stored raw (as pre-protect history leaves them),
    /// with `raider`'s reserve row on [`SEEDED_ITEMS`]
    pub async fn new_sheet(
        harness: &TestHarness,
        channel: &Channel,
        server_id: &str,
        creator: &User,
        raider: &User,
        message_id: &str,
    ) -> SoftResSheet {
        new_event_sheet(
            harness, channel, server_id, creator, raider, message_id, None,
        )
        .await
    }

    /// [`new_sheet`], linked to the calendar event `event` when given
    pub async fn new_event_sheet(
        harness: &TestHarness,
        channel: &Channel,
        server_id: &str,
        creator: &User,
        raider: &User,
        message_id: &str,
        event: Option<&str>,
    ) -> SoftResSheet {
        harness
            .insert_raw_message(&Message {
                id: message_id.to_string(),
                channel: channel.id().to_string(),
                author: creator.id.clone(),
                content: Some("Sunday MC".to_string()),
                ..Default::default()
            })
            .await;

        let sheet = SoftResSheet {
            id: Ulid::new().to_string(),
            message: message_id.to_string(),
            channel: channel.id().to_string(),
            server: Some(server_id.to_string()),
            event: event.map(str::to_string),
            creator: creator.id.clone(),
            title: "Sunday MC".to_string(),
            edition: "classic".to_string(),
            raids: vec!["mc".to_string()],
            reserves_per_user: 2,
            per_item_cap: None,
            allow_duplicates: false,
            class_restriction: false,
            hidden: false,
            lock_at_event_start: false,
            locks_at: None,
            note: None,
            hard_reserves: vec![],
            locked: false,
            created_at: now_ms(),
            edited_at: None,
        };
        harness
            .db
            .insert_sheet(&sheet)
            .await
            .expect("`SoftResSheet`");
        harness
            .db
            .upsert_reserve(&SoftResReserveRow {
                id: SoftResSheet::reserve_key(&sheet.id, &raider.id),
                sheet: sheet.id.clone(),
                user: raider.id.clone(),
                channel: sheet.channel.clone(),
                character_name: "Leeroy".to_string(),
                class: v0::WowClass::Paladin,
                items: SEEDED_ITEMS.to_vec(),
                note: None,
                plus_ones: 0,
                edited_at: now_ms(),
            })
            .await
            .expect("`SoftResReserveRow`");
        sheet
    }

    /// A protected channel whose kept history holds an open sheet (left
    /// open as a failed best-effort lock would leave it), and an ordinary
    /// channel of the same server holding another
    pub async fn world() -> World {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let ordinary = harness.new_channel(&protected.server).await;
        let server_id = protected.server.id.clone();

        // Ten minutes ago: the sheet's row is the newest pre-protect row, B
        let boundary = Ulid::from_parts(Ulid::new().timestamp_ms() - 600_000, 0).to_string();
        let sheet = new_sheet(
            &harness,
            &protected.channel,
            &server_id,
            &owner,
            &member,
            &boundary,
        )
        .await;
        let ordinary_sheet = new_sheet(
            &harness,
            &ordinary,
            &server_id,
            &owner,
            &member,
            &Ulid::new().to_string(),
        )
        .await;
        let channel = harness
            .protect_with_history_raw(protected.channel.id(), &boundary, HistoryWipe::None)
            .await;

        World {
            harness,
            protected: ProtectedChannel {
                channel,
                ..protected
            },
            ordinary,
            owner,
            owner_session,
            member,
            member_session,
            sheet,
            ordinary_sheet,
        }
    }

    /// Move the protected channel's wipe to `Requested`: from here on its
    /// pre-boundary rows are wipe-pending (S4-D21)
    pub async fn request_the_wipe(world: &World) {
        world
            .harness
            .protect_with_history_raw(
                world.protected.channel.id(),
                &world.sheet.message,
                HistoryWipe::Requested {
                    at: Timestamp::now_utc(),
                    by: world.owner.id.clone(),
                },
            )
            .await;
    }

    /// The items of `user`'s stored reserve row on `sheet_id`
    pub async fn reserved_items(world: &World, sheet_id: &str, user_id: &str) -> Option<Vec<u32>> {
        world
            .harness
            .db
            .fetch_reserve(sheet_id, user_id)
            .await
            .expect("the reserve row")
            .map(|row| row.items)
    }

    /// The route's answer: status and JSON body (`Null` when there is none)
    pub async fn request(
        harness: &TestHarness,
        session: &Session,
        method: Method,
        path: String,
        body: Option<Value>,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .req(method, path)
            .header(Header::new("x-session-token", session.token.to_string()));
        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    #[track_caller]
    pub fn assert_refused(answer: &(Status, Value), status: Status, error: &str, case: &str) {
        assert_eq!(answer.0, status, "{case}: {}", answer.1);
        assert_eq!(answer.1["type"], error, "{case}: {}", answer.1);
    }

    /// A thread under `parent`, for a raw insert (2.5 "Race closure": no
    /// route creates one under a protected parent)
    pub fn thread_under(parent: &Channel, server_id: &str, creator: &User) -> Channel {
        Channel::Thread {
            id: Ulid::new().to_string(),
            server: server_id.to_string(),
            parent_channel: parent.id().to_string(),
            name: "Thread".to_string(),
            creator: creator.id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        }
    }

    pub async fn deny_view(harness: &TestHarness, channel_id: &str) {
        harness
            .db
            .fetch_channel(channel_id)
            .await
            .expect("the channel")
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
}

/// Protected channels (S4): the sheet of a wipe-pending row is not served
#[cfg(test)]
mod protected_test {
    use revolt_database::events::client::EventV1;
    use revolt_models::v0;
    use rocket::http::{Method, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use super::protected_fixture::{
        assert_refused, deny_view, new_event_sheet, new_sheet, request, request_the_wipe,
        thread_under, world, World,
    };
    use crate::util::softres::publish_sheet_update;

    async fn fetch(world: &World, channel_id: &str, sheet_id: &str) -> (Status, Value) {
        request(
            &world.harness,
            &world.member_session,
            Method::Get,
            format!("/channels/{channel_id}/softres/{sheet_id}"),
            None,
        )
        .await
    }

    async fn fetch_bulk(world: &World, channel_id: &str, sheet_id: &str) -> (Status, Value) {
        request(
            &world.harness,
            &world.member_session,
            Method::Post,
            format!("/channels/{channel_id}/softres/fetch"),
            Some(json!({ "ids": [sheet_id] })),
        )
        .await
    }

    /// Design 7.4 "S4": while the history is kept, the sheet of the
    /// pre-boundary row B is served by the single and the bulk fetch; from
    /// `Requested` on, the single fetch answers exactly as for a sheet of
    /// another channel and the bulk fetch drops it. The ordinary channel's
    /// sheet is served throughout.
    #[test]
    fn a_wipe_pending_sheet_answers_not_found() {
        crate::util::test::rt().block_on(Box::pin(a_wipe_pending_sheet_answers_not_found_case()))
    }

    async fn a_wipe_pending_sheet_answers_not_found_case() {
        let w = world().await;
        let channel_id = w.protected.channel.id();

        let kept = fetch(&w, channel_id, &w.sheet.id).await;
        assert_eq!(kept.0, Status::Ok, "kept: {}", kept.1);
        assert_eq!(kept.1["_id"], w.sheet.id.as_str(), "kept: {}", kept.1);
        assert_eq!(kept.1["total_reserves"], 1, "kept: {}", kept.1);
        let kept = fetch_bulk(&w, channel_id, &w.sheet.id).await;
        assert_eq!(kept.0, Status::Ok, "kept bulk: {}", kept.1);
        assert_eq!(
            kept.1.as_array().map(Vec::len),
            Some(1),
            "kept bulk: {}",
            kept.1
        );

        request_the_wipe(&w).await;

        let foreign = fetch(&w, channel_id, &w.ordinary_sheet.id).await;
        assert_refused(&foreign, Status::NotFound, "NotFound", "a foreign sheet");
        assert_eq!(
            fetch(&w, channel_id, &w.sheet.id).await,
            foreign,
            "wipe pending"
        );
        assert_eq!(
            fetch_bulk(&w, channel_id, &w.sheet.id).await,
            (Status::Ok, json!([])),
            "wipe pending bulk"
        );

        // Only the answer changed: the job deletes the sheet, not the read
        w.harness
            .db
            .fetch_sheet(&w.sheet.id)
            .await
            .expect("the read deleted the sheet");

        let ordinary = fetch(&w, w.ordinary.id(), &w.ordinary_sheet.id).await;
        assert_eq!(ordinary.0, Status::Ok, "ordinary: {}", ordinary.1);
        let ordinary = fetch_bulk(&w, w.ordinary.id(), &w.ordinary_sheet.id).await;
        assert_eq!(
            ordinary.1.as_array().map(Vec::len),
            Some(1),
            "{}",
            ordinary.1
        );
    }

    /// A server-wide calendar event by the owner
    async fn new_event(world: &World) -> String {
        let (status, body) = request(
            &world.harness,
            &world.owner_session,
            Method::Post,
            format!("/events/server/{}", world.protected.server.id),
            Some(json!({
                "title": "Raid Night",
                "start": 1_900_000_000_000_i64,
                "timezone": "UTC"
            })),
        )
        .await;
        assert_eq!(status, Status::Ok, "event: {body}");
        serde_json::from_value::<v0::Event>(body)
            .expect("`Event`")
            .id
    }

    async fn lookup(world: &World, event_id: &str) -> (Status, Value) {
        request(
            &world.harness,
            &world.member_session,
            Method::Get,
            format!("/events/event/{event_id}/softres"),
            None,
        )
        .await
    }

    /// Design 7.4 "S4": the events-side lookup serves the sheet of a
    /// pre-boundary row while the history is kept; from `Requested` on it
    /// answers exactly as for an event with no sheet. The ordinary channel's
    /// sheet is served throughout.
    #[test]
    fn a_wipe_pending_sheet_has_no_event_lookup() {
        crate::util::test::rt().block_on(Box::pin(a_wipe_pending_sheet_has_no_event_lookup_case()))
    }

    async fn a_wipe_pending_sheet_has_no_event_lookup_case() {
        let w = world().await;
        let server_id = &w.protected.server.id;
        let (protected_event, ordinary_event, bare_event) = (
            new_event(&w).await,
            new_event(&w).await,
            new_event(&w).await,
        );

        // A minute before the boundary B: a pre-boundary row
        let boundary = Ulid::from_string(&w.sheet.message).expect("B");
        let row = Ulid::from_parts(boundary.timestamp_ms() - 60_000, 0).to_string();
        let sheet = new_event_sheet(
            &w.harness,
            &w.protected.channel,
            server_id,
            &w.owner,
            &w.member,
            &row,
            Some(&protected_event),
        )
        .await;
        let ordinary_sheet = new_event_sheet(
            &w.harness,
            &w.ordinary,
            server_id,
            &w.owner,
            &w.member,
            &Ulid::new().to_string(),
            Some(&ordinary_event),
        )
        .await;

        let kept = lookup(&w, &protected_event).await;
        assert_eq!(kept.0, Status::Ok, "kept: {}", kept.1);
        assert_eq!(kept.1["_id"], sheet.id.as_str(), "kept: {}", kept.1);

        request_the_wipe(&w).await;

        let no_sheet = lookup(&w, &bare_event).await;
        assert_refused(
            &no_sheet,
            Status::NotFound,
            "NotFound",
            "an event with no sheet",
        );
        assert_eq!(lookup(&w, &protected_event).await, no_sheet, "wipe pending");

        let ordinary = lookup(&w, &ordinary_event).await;
        assert_eq!(ordinary.0, Status::Ok, "ordinary: {}", ordinary.1);
        assert_eq!(
            ordinary.1["_id"],
            ordinary_sheet.id.as_str(),
            "ordinary: {}",
            ordinary.1
        );
    }

    /// The sheet update of `sheet_id`
    fn sheet_update(sheet_id: String) -> impl Fn(&EventV1) -> bool {
        move |event| matches!(event, EventV1::SoftresSheetUpdate { id, .. } if *id == sheet_id)
    }

    /// The owner (the events' creator) cancels an event
    async fn cancel(world: &World, event_id: &str) {
        let (status, body) = request(
            &world.harness,
            &world.owner_session,
            Method::Delete,
            format!("/events/event/{event_id}"),
            None,
        )
        .await;
        assert!(status.class().is_success(), "cancel: {} {}", status, body);
    }

    /// S4-D21: cancelling an event locks its linked sheet, and the sheet
    /// update goes out while the sheet's carrying row is servable (a
    /// protected channel's kept history, an ordinary channel) but not once
    /// the row is wipe-pending. A later published update is the marker that
    /// proves the negative (one FIFO subscription).
    #[test]
    fn cancelling_an_event_publishes_no_wipe_pending_sheet() {
        crate::util::test::rt().block_on(Box::pin(
            cancelling_an_event_publishes_no_wipe_pending_sheet_case(),
        ))
    }

    async fn cancelling_an_event_publishes_no_wipe_pending_sheet_case() {
        let mut w = world().await;
        let server_id = w.protected.server.id.clone();
        let protected_id = w.protected.channel.id().to_string();
        let ordinary_id = w.ordinary.id().to_string();
        let (kept_event, pending_event, ordinary_event) = (
            new_event(&w).await,
            new_event(&w).await,
            new_event(&w).await,
        );

        // One and two minutes before the boundary B: pre-boundary rows
        let boundary = Ulid::from_string(&w.sheet.message).expect("B");
        let row = |before: u64| Ulid::from_parts(boundary.timestamp_ms() - before, 0).to_string();
        let mut sheets = Vec::new();
        for (channel, message_id, event) in [
            (&w.protected.channel, row(60_000), &kept_event),
            (&w.protected.channel, row(120_000), &pending_event),
            (&w.ordinary, Ulid::new().to_string(), &ordinary_event),
        ] {
            let sheet = new_event_sheet(
                &w.harness,
                channel,
                &server_id,
                &w.owner,
                &w.member,
                &message_id,
                Some(event),
            )
            .await;
            sheets.push(sheet.id);
        }

        cancel(&w, &kept_event).await;
        w.harness
            .wait_for_event(&protected_id, sheet_update(sheets[0].clone()))
            .await;

        request_the_wipe(&w).await;
        cancel(&w, &pending_event).await;
        cancel(&w, &ordinary_event).await;
        w.harness
            .wait_for_event(&ordinary_id, sheet_update(sheets[2].clone()))
            .await;
        w.harness
            .assert_no_buffered_event(&protected_id, sheet_update(sheets[1].clone()));

        // The lock stands either way
        for sheet_id in &sheets {
            let sheet = w.harness.db.fetch_sheet(sheet_id).await.expect("sheet");
            assert!(sheet.locked, "{} was not locked", sheet_id);
        }
    }

    /// S4-D21 through a thread, judged by its parent (#182): a sheet in a
    /// thread under the protected channel is published while its row is
    /// servable (the kept history), and not once the parent's wipe is
    /// `Requested`, neither on an event cancel nor on a direct publish of
    /// the locked sheet (protect's lock path). A thread under the ordinary
    /// channel publishes: the later marker.
    #[test]
    fn a_thread_under_a_wipe_pending_parent_publishes_no_sheet() {
        crate::util::test::rt().block_on(Box::pin(
            a_thread_under_a_wipe_pending_parent_publishes_no_sheet_case(),
        ))
    }

    async fn a_thread_under_a_wipe_pending_parent_publishes_no_sheet_case() {
        let mut w = world().await;
        let server_id = w.protected.server.id.clone();
        let protected_thread = thread_under(&w.protected.channel, &server_id, &w.owner);
        let ordinary_thread = thread_under(&w.ordinary, &server_id, &w.owner);
        for thread in [&protected_thread, &ordinary_thread] {
            w.harness.db.insert_channel(thread).await.expect("thread");
        }
        let protected_id = protected_thread.id().to_string();
        let ordinary_id = ordinary_thread.id().to_string();
        let (kept_event, pending_event, ordinary_event) = (
            new_event(&w).await,
            new_event(&w).await,
            new_event(&w).await,
        );

        // One and two minutes before the parent's boundary B
        let boundary = Ulid::from_string(&w.sheet.message).expect("B");
        let row = |before: u64| Ulid::from_parts(boundary.timestamp_ms() - before, 0).to_string();
        let mut sheets = Vec::new();
        for (thread, message_id, event) in [
            (&protected_thread, row(60_000), &kept_event),
            (&protected_thread, row(120_000), &pending_event),
            (&ordinary_thread, Ulid::new().to_string(), &ordinary_event),
        ] {
            let sheet = new_event_sheet(
                &w.harness,
                thread,
                &server_id,
                &w.owner,
                &w.member,
                &message_id,
                Some(event),
            )
            .await;
            sheets.push(sheet.id);
        }

        cancel(&w, &kept_event).await;
        w.harness
            .wait_for_event(&protected_id, sheet_update(sheets[0].clone()))
            .await;

        request_the_wipe(&w).await;
        cancel(&w, &pending_event).await;
        let pending = w.harness.db.fetch_sheet(&sheets[1]).await.expect("sheet");
        assert!(pending.locked, "the cancel did not lock the sheet");
        publish_sheet_update(&w.harness.db, pending)
            .await
            .expect("a withheld update answers Ok");
        cancel(&w, &ordinary_event).await;
        w.harness
            .wait_for_event(&ordinary_id, sheet_update(sheets[2].clone()))
            .await;
        w.harness
            .assert_no_buffered_event(&protected_id, sheet_update(sheets[1].clone()));
    }

    /// F5: the publish gate's reads run after the caller's write has
    /// landed, so a failed one answers `Ok` and publishes nothing (fail
    /// closed): a sheet whose channel row is missing, and one in a thread
    /// whose parent row is missing. The ordinary sheet's update is the
    /// later marker.
    #[test]
    fn a_failed_publish_gate_answers_ok_and_publishes_nothing() {
        crate::util::test::rt().block_on(Box::pin(
            a_failed_publish_gate_answers_ok_and_publishes_nothing_case(),
        ))
    }

    async fn a_failed_publish_gate_answers_ok_and_publishes_nothing_case() {
        let mut w = world().await;
        let server_id = w.protected.server.id.clone();

        // Never stored: the channel read fails
        let missing = thread_under(&w.ordinary, &server_id, &w.owner);
        // Stored under the missing one: the parent read fails
        let orphan = thread_under(&missing, &server_id, &w.owner);
        w.harness.db.insert_channel(&orphan).await.expect("thread");

        let mut sheets = Vec::new();
        for channel in [&missing, &orphan] {
            let sheet = new_sheet(
                &w.harness,
                channel,
                &server_id,
                &w.owner,
                &w.member,
                &Ulid::new().to_string(),
            )
            .await;
            publish_sheet_update(&w.harness.db, sheet.clone())
                .await
                .expect("a failed gate answers Ok");
            sheets.push(sheet);
        }

        publish_sheet_update(&w.harness.db, w.ordinary_sheet.clone())
            .await
            .expect("the marker");
        w.harness
            .wait_for_event(w.ordinary.id(), sheet_update(w.ordinary_sheet.id.clone()))
            .await;
        for sheet in sheets {
            w.harness
                .assert_no_buffered_event(&sheet.channel, sheet_update(sheet.id.clone()));
        }
    }

    /// Decision 18: every softres sheet route answers a caller who cannot
    /// view the channel byte-identically for a protected (wipe-pending) and
    /// an ordinary channel, and a missing channel as before
    #[test]
    fn every_softres_route_answers_a_non_viewer_as_before() {
        crate::util::test::rt().block_on(Box::pin(
            every_softres_route_answers_a_non_viewer_as_before_case(),
        ))
    }

    async fn every_softres_route_answers_a_non_viewer_as_before_case() {
        let w = world().await;
        request_the_wipe(&w).await;
        deny_view(&w.harness, w.protected.channel.id()).await;
        deny_view(&w.harness, w.ordinary.id()).await;
        let missing = ulid::Ulid::new().to_string();

        let routes = [
            (Method::Put, "/reserve"),
            (Method::Delete, "/reserve"),
            (Method::Patch, ""),
            (Method::Post, "/lock"),
            (Method::Delete, "/lock"),
            (Method::Get, ""),
            (Method::Get, "/export"),
            (Method::Post, "/fetch"),
        ];
        for (method, suffix) in routes {
            let case = format!("{method} {suffix}");
            let mut answers = Vec::new();
            for (channel_id, sheet) in [
                (w.ordinary.id(), &w.ordinary_sheet),
                (w.protected.channel.id(), &w.sheet),
                (missing.as_str(), &w.sheet),
            ] {
                let (path, body) = match (method, suffix) {
                    (Method::Post, "/fetch") => (
                        format!("/channels/{channel_id}/softres/fetch"),
                        Some(json!({ "ids": [sheet.id] })),
                    ),
                    (Method::Put, _) => (
                        format!("/channels/{channel_id}/softres/{}{suffix}", sheet.id),
                        Some(json!({
                            "character_name": "Jenkins",
                            "class": "paladin",
                            "items": [18563]
                        })),
                    ),
                    (Method::Patch, _) => (
                        format!("/channels/{channel_id}/softres/{}", sheet.id),
                        Some(json!({ "title": "Moved" })),
                    ),
                    _ => (
                        format!("/channels/{channel_id}/softres/{}{suffix}", sheet.id),
                        None,
                    ),
                };
                answers.push(request(&w.harness, &w.member_session, method, path, body).await);
            }

            assert_refused(&answers[0], Status::Forbidden, "MissingPermission", &case);
            assert_eq!(answers[1], answers[0], "{case}: protected vs ordinary");
            assert_refused(&answers[2], Status::NotFound, "NotFound", &case);
        }
    }
}
