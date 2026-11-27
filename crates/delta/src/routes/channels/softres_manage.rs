use revolt_config::config;
use revolt_database::util::e2ee_only;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, SoftResSheet, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::util::polls::now_ms;
use crate::util::softres::{authorize_manage_sheet, can_see_full, publish_sheet_update};
use crate::util::softres_catalog;

/// Channel gate + sheet fetch + manage authorization (creator or
/// ManageMessages). The channel is handed back for the checks that depend
/// on it.
async fn resolve_managed_sheet(
    db: &Database,
    target: &Reference<'_>,
    sheet_id: &str,
    user: &User,
) -> Result<(SoftResSheet, PermissionValue, Channel)> {
    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // A protected channel (or a thread under one) takes no sheet edit, lock
    // or unlock (design 7.4 "S4"): protect locks the open sheets itself, and
    // an unlock would reopen one. After the ViewChannel check, so a
    // non-viewer gets the pre-S4 answer (decision 18), and before the sheet
    // is read or the manage check runs.
    if channel.is_protected() || permission_channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    let sheet = db.fetch_sheet(sheet_id).await?;
    if sheet.channel != channel.id() {
        return Err(create_error!(NotFound));
    }

    authorize_manage_sheet(&sheet, &user.id, &permissions)?;

    Ok((sheet, permissions, channel))
}

/// # Edit Soft-Reserve Sheet
///
/// Edits a sheet's settings. Raids are immutable post-create (reserves
/// reference them). A per-item-cap decrease does NOT evict existing
/// over-cap reserves, and a hard-reserve swap that now conflicts with
/// existing reserves does NOT evict them either — the documented
/// non-eviction rule, matching softres.it edit semantics.
#[openapi(tag = "Soft Reserves")]
#[patch("/<target>/softres/<sheet_id>", data = "<data>")]
pub async fn softres_edit(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sheet_id: String,
    data: Json<v0::DataSoftResEdit>,
) -> Result<Json<v0::SoftRes>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let (mut sheet, permissions, channel) =
        resolve_managed_sheet(db, &target, &sheet_id, &user).await?;

    // An edit rewrites the sheet's title, note and hard reserves, plain text
    // that an encrypted-only account or group never takes. Refused right
    // after the channel, permission and manage checks, before the event
    // read and the write. Locking, unlocking and the export write no text
    // and stay allowed.
    let e2ee_config = config().await.features.e2ee.clone();
    e2ee_only::plain_write_allowed(db, &e2ee_config, &user, &channel, None).await?;

    if let Some(title) = data.title {
        sheet.title = title;
    }
    if let Some(reserves_per_user) = data.reserves_per_user {
        sheet.reserves_per_user = reserves_per_user;
    }
    if let Some(per_item_cap) = data.per_item_cap {
        sheet.per_item_cap = Some(per_item_cap);
    }
    if let Some(allow_duplicates) = data.allow_duplicates {
        sheet.allow_duplicates = allow_duplicates;
    }
    if let Some(class_restriction) = data.class_restriction {
        sheet.class_restriction = class_restriction;
    }
    if let Some(hidden) = data.hidden {
        sheet.hidden = hidden;
    }
    if let Some(note) = data.note {
        sheet.note = Some(note);
    }
    if let Some(hard_reserves) = data.hard_reserves {
        // A replacement list is validated like create: per-row fields and
        // membership in the sheet's (immutable) raids.
        for hard_reserve in &hard_reserves {
            hard_reserve.validate().map_err(|error| {
                create_error!(FailedValidation {
                    error: error.to_string()
                })
            })?;
            if softres_catalog::item_in_raids(hard_reserve.item_id, &sheet.raids).is_none() {
                return Err(create_error!(SoftResInvalidItems));
            }
        }
        sheet.hard_reserves = hard_reserves;
    }

    if let Some(lock_at_event_start) = data.lock_at_event_start {
        if lock_at_event_start && (!sheet.lock_at_event_start || sheet.locks_at.is_none()) {
            // Toggling ON re-snapshots from the linked event — the only
            // place besides create that reads the event, and under the
            // same rules (events feature on, non-cancelled, future start).
            // Also re-snapshots when the flag is set but `locks_at` is
            // missing (a stranded state must not make re-arming a silent
            // no-op).
            let Some(event_id) = &sheet.event else {
                return Err(create_error!(InvalidOperation));
            };
            crate::routes::events::require_events_enabled().await?;
            let event = db.fetch_event(event_id).await?;
            if event.cancelled || event.start <= now_ms() {
                return Err(create_error!(InvalidOperation));
            }
            sheet.lock_at_event_start = true;
            sheet.locks_at = Some(event.start);
        } else if !lock_at_event_start {
            sheet.lock_at_event_start = false;
            sheet.locks_at = None;
        }
    }

    for field in &data.remove {
        match field {
            v0::FieldsSoftRes::PerItemCap => sheet.per_item_cap = None,
            v0::FieldsSoftRes::Note => sheet.note = None,
        }
    }

    sheet.edited_at = Some(now_ms());

    db.update_sheet_settings(&sheet).await?;

    // Re-read so the response and the fan-out reflect what actually
    // persisted (`locked` in particular is never written by an edit and a
    // concurrent lock must not be masked).
    let sheet = db.fetch_sheet(&sheet.id).await?;
    publish_sheet_update(db, sheet.clone()).await?;

    let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;
    let include_full = can_see_full(&sheet, &user.id, &permissions);
    Ok(Json(sheet.into_model(include_full, rows, &user.id, now_ms())))
}

/// # Lock Soft-Reserve Sheet
///
/// Locks a sheet immediately: reserves can no longer be set or
/// retracted. Idempotent — locking a locked sheet is a no-op.
#[openapi(tag = "Soft Reserves")]
#[post("/<target>/softres/<sheet_id>/lock")]
pub async fn softres_lock(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sheet_id: String,
) -> Result<Json<v0::SoftRes>> {
    let (sheet, permissions, _) = resolve_managed_sheet(db, &target, &sheet_id, &user).await?;

    // Exactly-once arbitration (may race the event-cancel hook); losers
    // simply return the already-locked state without a duplicate fan-out.
    if db.set_sheet_locked_if_unlocked(&sheet.id).await? {
        let fresh = db.fetch_sheet(&sheet.id).await?;
        publish_sheet_update(db, fresh).await?;
    }

    let sheet = db.fetch_sheet(&sheet.id).await?;
    let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;
    let include_full = can_see_full(&sheet, &user.id, &permissions);
    Ok(Json(sheet.into_model(include_full, rows, &user.id, now_ms())))
}

/// # Unlock Soft-Reserve Sheet
///
/// Unlocks a sheet. This clears BOTH the manual lock and the
/// `locks_at` auto-lock snapshot — past the event start, clearing only
/// the flag would leave the sheet locked forever by the timestamp.
#[openapi(tag = "Soft Reserves")]
#[delete("/<target>/softres/<sheet_id>/lock")]
pub async fn softres_unlock(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sheet_id: String,
) -> Result<Json<v0::SoftRes>> {
    let (sheet, permissions, _) = resolve_managed_sheet(db, &target, &sheet_id, &user).await?;

    db.set_sheet_unlocked(&sheet.id).await?;

    let sheet = db.fetch_sheet(&sheet.id).await?;
    publish_sheet_update(db, sheet.clone()).await?;

    let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;
    let include_full = can_see_full(&sheet, &user.id, &permissions);
    Ok(Json(sheet.into_model(include_full, rows, &user.id, now_ms())))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::Member;
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Method, Status};
    use serde_json::json;

    use super::super::message_send::test::{
        assert_accepted, assert_encryption_required, e2ee_dm, e2ee_request, set_e2ee_only,
    };
    use super::super::softres_reserve::test::create_sheet;

    #[test]
    fn edit_lock_and_unlock_flow() {
        crate::util::test::rt().block_on(edit_lock_and_unlock_flow_case())
    }

    async fn edit_lock_and_unlock_flow_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, other_session, other_user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        Member::create(&harness.db, &server, &other_user, None)
            .await
            .expect("member");
        let channel = harness.new_channel(&server).await;

        let message = create_sheet(
            &harness,
            &session.token,
            channel.id(),
            json!({ "title": "Sunday MC", "edition": "classic", "raids": ["mc"] }),
        )
        .await;
        let sheet_id = message.softres.expect("softres").id;

        // A non-manager can neither edit nor lock
        for (method, path) in [
            ("patch", format!("/channels/{}/softres/{}", channel.id(), sheet_id)),
            (
                "post",
                format!("/channels/{}/softres/{}/lock", channel.id(), sheet_id),
            ),
        ] {
            let request = match method {
                "patch" => harness
                    .client
                    .patch(path)
                    .header(ContentType::JSON)
                    .body(json!({ "title": "hijack" }).to_string()),
                _ => harness.client.post(path),
            };
            let response = request
                .header(Header::new(
                    "x-session-token",
                    other_session.token.to_string(),
                ))
                .dispatch()
                .await;
            assert_ne!(response.status(), Status::Ok, "non-manager must be rejected");
        }

        // Creator edits settings
        let response = harness
            .client
            .patch(format!("/channels/{}/softres/{}", channel.id(), sheet_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "title": "Sunday MC (moved)",
                    "per_item_cap": 2,
                    "hidden": true
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
        assert!(!state.locked);

        // Creator locks — reserves are rejected with 410
        let response = harness
            .client
            .post(format!(
                "/channels/{}/softres/{}/lock",
                channel.id(),
                sheet_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
        assert!(state.locked);

        let response = harness
            .client
            .put(format!(
                "/channels/{}/softres/{}/reserve",
                channel.id(),
                sheet_id
            ))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(
                json!({ "character_name": "Jenkins", "class": "mage", "items": [17204] })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Gone, "locked sheet must 410");

        // Unlock re-opens reserving
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
        assert!(!state.locked);

        let response = harness
            .client
            .put(format!(
                "/channels/{}/softres/{}/reserve",
                channel.id(),
                sheet_id
            ))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(
                json!({ "character_name": "Jenkins", "class": "mage", "items": [17204] })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    /// Editing a sheet in a direct message with an encrypted-only side is
    /// refused and changes nothing; locking and unlocking stay allowed.
    /// Control: with the flags lifted the same edit is applied.
    #[test]
    fn e2ee_only_softres_edit_refused_without_side_effects() {
        crate::util::test::rt().block_on(Box::pin(
            e2ee_only_softres_edit_refused_without_side_effects_case(),
        ))
    }

    async fn e2ee_only_softres_edit_refused_without_side_effects_case() {
        let harness = TestHarness::new().await;
        let (author_session, mut author, _, mut peer, dm) = e2ee_dm(&harness).await;
        let message = create_sheet(
            &harness,
            &author_session.token,
            dm.id(),
            json!({ "title": "Sunday MC", "edition": "classic", "raids": ["mc"] }),
        )
        .await;
        let sheet_id = message.softres.expect("softres").id;
        let path = format!("/channels/{}/softres/{}", dm.id(), sheet_id);
        let lock_path = format!("{path}/lock");
        let edit = json!({ "title": "Moved", "note": "bring flasks" });

        set_e2ee_only(&harness, &mut author, true).await;
        let answer =
            e2ee_request(&harness, Method::Patch, &path, &author_session, Some(&edit)).await;
        assert_encryption_required(&answer, "sender", "an encrypted-only author");

        // Locking and unlocking write no text
        let answer = e2ee_request(&harness, Method::Post, &lock_path, &author_session, None).await;
        assert_accepted(&answer, "a lock");
        assert_eq!(answer.1["locked"], true, "{}", answer.1);
        let answer =
            e2ee_request(&harness, Method::Delete, &lock_path, &author_session, None).await;
        assert_accepted(&answer, "an unlock");
        // `locked` is omitted from the body when false
        assert!(!answer.1["locked"].as_bool().unwrap_or(false), "{}", answer.1);

        set_e2ee_only(&harness, &mut author, false).await;
        set_e2ee_only(&harness, &mut peer, true).await;
        let answer =
            e2ee_request(&harness, Method::Patch, &path, &author_session, Some(&edit)).await;
        assert_encryption_required(&answer, "recipient", "an encrypted-only peer");

        let sheet = harness.db.fetch_sheet(&sheet_id).await.expect("sheet");
        assert_eq!(sheet.title, "Sunday MC", "a refused edit changed the title");
        assert_eq!(sheet.note, None, "a refused edit changed the note");
        assert_eq!(sheet.edited_at, None, "a refused edit was recorded");

        // Control: no flags, the same edit
        set_e2ee_only(&harness, &mut peer, false).await;
        let answer =
            e2ee_request(&harness, Method::Patch, &path, &author_session, Some(&edit)).await;
        assert_accepted(&answer, "no flags");
        assert_eq!(
            harness
                .db
                .fetch_sheet(&sheet_id)
                .await
                .expect("sheet")
                .title,
            "Moved"
        );
    }

    /// With `only_enforced = false` the same edit is applied
    #[test]
    fn e2ee_only_softres_edit_allowed_when_not_enforced() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee.only_enforced = false;
            })
            .await;
            Box::pin(e2ee_only_softres_edit_allowed_when_not_enforced_case()).await
        })
    }

    async fn e2ee_only_softres_edit_allowed_when_not_enforced_case() {
        assert!(
            !revolt_config::config().await.features.e2ee.only_enforced,
            "precondition: the refusals are switched off"
        );

        let harness = TestHarness::new().await;
        let (author_session, mut author, _, mut peer, dm) = e2ee_dm(&harness).await;
        let message = create_sheet(
            &harness,
            &author_session.token,
            dm.id(),
            json!({ "title": "Sunday MC", "edition": "classic", "raids": ["mc"] }),
        )
        .await;
        let sheet_id = message.softres.expect("softres").id;
        set_e2ee_only(&harness, &mut author, true).await;
        set_e2ee_only(&harness, &mut peer, true).await;

        let answer = e2ee_request(
            &harness,
            Method::Patch,
            &format!("/channels/{}/softres/{}", dm.id(), sheet_id),
            &author_session,
            Some(&json!({ "title": "Moved" })),
        )
        .await;
        assert_accepted(&answer, "an encrypted-only author and peer");
        assert_eq!(
            harness
                .db
                .fetch_sheet(&sheet_id)
                .await
                .expect("sheet")
                .title,
            "Moved"
        );
    }
}

/// Protected channels (S4): a protected channel's sheet cannot be edited,
/// locked or unlocked
#[cfg(test)]
mod protected_test {
    use rocket::http::{Method, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use crate::routes::channels::softres_fetch::protected_fixture::{
        assert_refused, new_sheet, request, thread_under, world, World,
    };

    /// The sheets' creator (the server owner) edits (`PATCH`), locks
    /// (`POST /lock`) or unlocks (`DELETE /lock`) one
    async fn manage(
        world: &World,
        method: Method,
        channel_id: &str,
        sheet_id: &str,
        suffix: &str,
    ) -> (Status, Value) {
        let body = match method {
            Method::Patch => Some(json!({ "title": "Moved" })),
            _ => None,
        };
        request(
            &world.harness,
            &world.owner_session,
            method,
            format!("/channels/{channel_id}/softres/{sheet_id}{suffix}"),
            body,
        )
        .await
    }

    /// Design 7.4 "S4": the creator's edit, lock and unlock of a sheet of a
    /// protected channel answer `ChannelProtected` and change nothing (an
    /// unlock would reopen a sheet protect locked); the same three on the
    /// ordinary channel's sheet still land. A thread under the protected
    /// channel is judged by its parent (#182).
    #[test]
    fn a_protected_channel_refuses_to_edit_lock_or_unlock_a_sheet() {
        crate::util::test::rt().block_on(Box::pin(
            a_protected_channel_refuses_to_edit_lock_or_unlock_a_sheet_case(),
        ))
    }

    async fn a_protected_channel_refuses_to_edit_lock_or_unlock_a_sheet_case() {
        let w = world().await;
        let channel_id = w.protected.channel.id();

        for (method, suffix, case) in [
            (Method::Patch, "", "an edit"),
            (Method::Post, "/lock", "a lock"),
        ] {
            assert_refused(
                &manage(&w, method, channel_id, &w.sheet.id, suffix).await,
                Status::BadRequest,
                "ChannelProtected",
                case,
            );
        }
        let stored = w.harness.db.fetch_sheet(&w.sheet.id).await.expect("sheet");
        assert_eq!(stored.title, w.sheet.title, "the refusal edited the sheet");
        assert!(!stored.locked, "the refusal locked the sheet");

        // As protect leaves it: locked
        assert!(w
            .harness
            .db
            .set_sheet_locked_if_unlocked(&w.sheet.id)
            .await
            .expect("lock"));
        assert_refused(
            &manage(&w, Method::Delete, channel_id, &w.sheet.id, "/lock").await,
            Status::BadRequest,
            "ChannelProtected",
            "an unlock",
        );
        let stored = w.harness.db.fetch_sheet(&w.sheet.id).await.expect("sheet");
        assert!(stored.locked, "the refusal unlocked the sheet");

        for (method, suffix, case) in [
            (Method::Patch, "", "an edit"),
            (Method::Post, "/lock", "a lock"),
            (Method::Delete, "/lock", "an unlock"),
        ] {
            let ordinary = manage(&w, method, w.ordinary.id(), &w.ordinary_sheet.id, suffix).await;
            assert_eq!(ordinary.0, Status::Ok, "ordinary {case}: {}", ordinary.1);
        }
        let stored = w
            .harness
            .db
            .fetch_sheet(&w.ordinary_sheet.id)
            .await
            .expect("sheet");
        assert_eq!(stored.title, "Moved");
        assert!(!stored.locked);

        // A thread is judged by its parent (#182)
        let server_id = &w.protected.server.id;
        let thread = thread_under(&w.protected.channel, server_id, &w.owner);
        w.harness.db.insert_channel(&thread).await.expect("thread");
        let sheet = new_sheet(
            &w.harness,
            &thread,
            server_id,
            &w.owner,
            &w.owner,
            &Ulid::new().to_string(),
        )
        .await;
        assert_refused(
            &manage(&w, Method::Post, thread.id(), &sheet.id, "/lock").await,
            Status::BadRequest,
            "ChannelProtected",
            "a lock in a thread under a protected parent",
        );
    }
}
