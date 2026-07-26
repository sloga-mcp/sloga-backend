use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, SoftResSheet, User};
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
/// ManageMessages).
async fn resolve_managed_sheet(
    db: &Database,
    target: &Reference<'_>,
    sheet_id: &str,
    user: &User,
) -> Result<(SoftResSheet, PermissionValue)> {
    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let sheet = db.fetch_sheet(sheet_id).await?;
    if sheet.channel != channel.id() {
        return Err(create_error!(NotFound));
    }

    authorize_manage_sheet(&sheet, &user.id, &permissions)?;

    Ok((sheet, permissions))
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

    let (mut sheet, permissions) = resolve_managed_sheet(db, &target, &sheet_id, &user).await?;

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
    let (sheet, permissions) = resolve_managed_sheet(db, &target, &sheet_id, &user).await?;

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
    let (sheet, permissions) = resolve_managed_sheet(db, &target, &sheet_id, &user).await?;

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
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    use super::super::softres_reserve::test::create_sheet;

    #[rocket::async_test]
    async fn edit_lock_and_unlock_flow() {
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
}
