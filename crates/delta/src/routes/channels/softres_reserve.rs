use std::collections::HashMap;

use revolt_database::events::client::EventV1;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, SoftResReserveRow, SoftResSheet, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::util::polls::now_ms;
use crate::util::softres::{can_see_full, validate_reserve_items};

/// Resolve the sheet after the usual channel permission gate, rejecting
/// locked sheets (manual lock, event-cancel lock, or the snapshotted
/// `locks_at` instant having passed — a pure compare, no event fetch).
async fn resolve_open_sheet(
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

    if sheet.is_locked_now(now_ms()) {
        return Err(create_error!(SoftResLocked));
    }

    Ok((sheet, permissions))
}

/// Publish `SoftresReserveUpdate` for a row change. For hidden sheets the
/// row AND the per-item count deltas are omitted — aggregate item counts
/// are exactly the signal `hidden` hides, and the channel topic has one
/// audience; leaders refetch over REST. For visible sheets only the
/// CHANGED items' new absolute counts are sent (the client merges).
async fn publish_reserve_update(
    db: &Database,
    sheet: &SoftResSheet,
    changed_items: &[u32],
    reserve: Option<v0::SoftResReserve>,
    removed_user: Option<String>,
) -> Result<Vec<SoftResReserveRow>> {
    let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;

    let (changed_item_counts, reserve, removed_user) = if sheet.hidden {
        // Hidden sheets broadcast the total ONLY — the row, the per-item
        // deltas, and even the retracting user's id are all part of the
        // reserve set `hidden` conceals.
        (HashMap::new(), None, None)
    } else {
        let counts = SoftResSheet::item_counts_of(&rows);
        let mut changed: HashMap<String, u32> = HashMap::new();
        for item in changed_items {
            let key = item.to_string();
            changed.insert(key.clone(), counts.get(&key).copied().unwrap_or(0));
        }
        (changed, reserve, removed_user)
    };

    EventV1::SoftresReserveUpdate {
        id: sheet.id.clone(),
        channel_id: sheet.channel.clone(),
        message_id: sheet.message.clone(),
        total_reserves: rows.len() as i64,
        changed_item_counts,
        reserve,
        removed_user,
    }
    .p(sheet.channel.clone())
    .await;

    Ok(rows)
}

/// Restore a reserve row to its pre-request state (compensation for the
/// check-then-write races: per-item cap overflow and a lock landing
/// between the open check and the write).
///
/// If the restore itself errors, the over-cap/post-lock row persists
/// while the client sees the rejection — an accepted residual (plan
/// Risks): storage self-heals on the raider's next write and the leader
/// can evict by lock+export inspection; there is no compensation for the
/// compensator.
async fn restore_previous(
    db: &Database,
    sheet: &SoftResSheet,
    user_id: &str,
    previous: &Option<SoftResReserveRow>,
) -> Result<()> {
    match previous {
        Some(row) => {
            db.upsert_reserve(row).await?;
        }
        None => {
            db.remove_reserve(&sheet.id, user_id).await?;
        }
    }
    Ok(())
}

/// # Set Soft Reserve
///
/// Sets (or replaces) the calling user's reservation row on a sheet.
#[openapi(tag = "Soft Reserves")]
#[put("/<target>/softres/<sheet_id>/reserve", data = "<data>")]
pub async fn softres_reserve(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sheet_id: String,
    data: Json<v0::DataSoftResReserve>,
) -> Result<Json<v0::SoftRes>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let (sheet, permissions) = resolve_open_sheet(db, &target, &sheet_id, &user).await?;

    // Character names are letters-only (WoW name rules — a free charset
    // buys nothing and hurts addon-import robustness).
    if !data.character_name.chars().all(char::is_alphabetic) {
        return Err(create_error!(InvalidProperty));
    }

    // The class must exist in the sheet's edition (Death Knights are
    // Wrath-only).
    if !data.class.valid_in_edition(&sheet.edition) {
        return Err(create_error!(InvalidProperty));
    }

    // Item count against the per-sheet setting (the DTO only enforces the
    // global ceiling).
    if data.items.is_empty() || data.items.len() > sheet.reserves_per_user as usize {
        return Err(create_error!(InvalidProperty));
    }

    validate_reserve_items(&sheet, &data.items, &data.class)?;

    // Per-item cap: copies held by others + the incoming row's own copies
    // must fit. Check-then-write with post-write recount compensation —
    // the check and the write are not atomic.
    if let Some(cap) = sheet.per_item_cap {
        let mut distinct: Vec<u32> = data.items.clone();
        distinct.sort_unstable();
        distinct.dedup();
        for item in &distinct {
            let own = data.items.iter().filter(|i| **i == *item).count() as u32;
            let others = db
                .count_item_reservations(&sheet.id, *item, &user.id)
                .await?;
            if others + own > cap as u32 {
                return Err(create_error!(SoftResItemCapReached));
            }
        }
    }

    let row = SoftResReserveRow {
        id: SoftResSheet::reserve_key(&sheet.id, &user.id),
        sheet: sheet.id.clone(),
        user: user.id.clone(),
        channel: sheet.channel.clone(),
        character_name: data.character_name,
        class: data.class,
        items: data.items.clone(),
        note: data.note,
        plus_ones: 0,
        edited_at: now_ms(),
    };

    let previous = db.upsert_reserve(&row).await?;

    // Post-write cap recount: concurrent writes can all pass the eager
    // check. If this write pushed an item over the cap, restore the
    // previous row and reject (storage self-heals; the poll
    // after-close-compensation precedent).
    if let Some(cap) = sheet.per_item_cap {
        let mut distinct: Vec<u32> = data.items.clone();
        distinct.sort_unstable();
        distinct.dedup();
        for item in &distinct {
            let own = data.items.iter().filter(|i| **i == *item).count() as u32;
            let others = db
                .count_item_reservations(&sheet.id, *item, &user.id)
                .await?;
            if others + own > cap as u32 {
                restore_previous(db, &sheet, &user.id, &previous).await?;
                return Err(create_error!(SoftResItemCapReached));
            }
        }
    }

    // Post-write lock re-check: a lock (manual or event-cancel) can land
    // between the open check and the write. A row slipping in after the
    // lock would silently change what the leader exports — restore and
    // reject instead.
    let fresh = match db.fetch_sheet(&sheet.id).await {
        Ok(fresh) => fresh,
        Err(error) => {
            // The sheet was cascade-deleted between the open check and
            // this re-read (message/channel deletion) — the row just
            // written is permanent garbage nothing else will sweep, so
            // remove it before failing.
            let _ = db.remove_reserve(&sheet.id, &user.id).await;
            return Err(error);
        }
    };
    if fresh.is_locked_now(now_ms()) {
        restore_previous(db, &sheet, &user.id, &previous).await?;
        return Err(create_error!(SoftResLocked));
    }

    // Changed items: everything in the previous row plus everything in
    // the new one (overlaps collapse — absolute counts are sent).
    let mut changed: Vec<u32> = previous
        .as_ref()
        .map(|row| row.items.clone())
        .unwrap_or_default();
    changed.extend(&data.items);
    changed.sort_unstable();
    changed.dedup();

    let rows = publish_reserve_update(
        db,
        &sheet,
        &changed,
        Some(row.clone().into_model()),
        None,
    )
    .await?;

    let include_full = can_see_full(&sheet, &user.id, &permissions);
    Ok(Json(sheet.into_model(include_full, rows, &user.id, now_ms())))
}

/// # Retract Soft Reserve
///
/// Removes the calling user's reservation row from a sheet.
#[openapi(tag = "Soft Reserves")]
#[delete("/<target>/softres/<sheet_id>/reserve")]
pub async fn softres_unreserve(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sheet_id: String,
) -> Result<Json<v0::SoftRes>> {
    let (sheet, permissions) = resolve_open_sheet(db, &target, &sheet_id, &user).await?;

    let previous = db.remove_reserve(&sheet.id, &user.id).await?;

    let rows = if let Some(removed) = &previous {
        // Post-write lock re-check, mirroring the set path: a retraction
        // racing the lock would change what the leader exports.
        let fresh = db.fetch_sheet(&sheet.id).await?;
        if fresh.is_locked_now(now_ms()) {
            db.upsert_reserve(removed).await?;
            return Err(create_error!(SoftResLocked));
        }

        let mut changed = removed.items.clone();
        changed.sort_unstable();
        changed.dedup();

        publish_reserve_update(db, &sheet, &changed, None, Some(user.id.clone())).await?
    } else {
        db.fetch_reserves_for_sheet(&sheet.id).await?
    };

    let include_full = can_see_full(&sheet, &user.id, &permissions);
    Ok(Json(sheet.into_model(include_full, rows, &user.id, now_ms())))
}

#[cfg(test)]
pub mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::Member;
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    pub async fn create_sheet(
        harness: &TestHarness,
        session_token: &str,
        channel_id: &str,
        body: serde_json::Value,
    ) -> v0::Message {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/softres"))
            .header(Header::new("x-session-token", session_token.to_string()))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        response.into_json().await.expect("`Message`")
    }

    #[rocket::async_test]
    async fn reserve_replace_and_retract() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let message = create_sheet(
            &harness,
            &session.token,
            channel.id(),
            json!({
                "title": "Sunday MC",
                "edition": "classic",
                "raids": ["mc"],
                "reserves_per_user": 2
            }),
        )
        .await;
        let sheet_id = message.softres.expect("softres").id;

        // Reserve two items (Eye of Sulfuras + a Garr binding)
        let response = harness
            .client
            .put(format!(
                "/channels/{}/softres/{}/reserve",
                channel.id(),
                sheet_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "character_name": "Leeroy",
                    "class": "paladin",
                    "items": [17204, 18563]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
        assert_eq!(state.total_reserves, 1);
        let mine = state.my_reserve.expect("own row");
        assert_eq!(mine.items, vec![17204, 18563]);
        assert_eq!(mine.character_name, "Leeroy");
        let counts = state.item_counts.expect("visible sheet");
        assert_eq!(counts.get("17204"), Some(&1));

        // Replace with a single different item — the row is replaced, not
        // appended.
        let response = harness
            .client
            .put(format!(
                "/channels/{}/softres/{}/reserve",
                channel.id(),
                sheet_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "character_name": "Leeroy",
                    "class": "paladin",
                    "items": [18564]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
        assert_eq!(state.total_reserves, 1);
        let counts = state.item_counts.expect("visible sheet");
        assert_eq!(counts.get("17204"), None);
        assert_eq!(counts.get("18564"), Some(&1));

        // Retract
        let response = harness
            .client
            .delete(format!(
                "/channels/{}/softres/{}/reserve",
                channel.id(),
                sheet_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
        assert_eq!(state.total_reserves, 0);
        assert!(state.my_reserve.is_none());
    }

    #[rocket::async_test]
    async fn reserve_validation_rejects_bad_rows() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let message = create_sheet(
            &harness,
            &session.token,
            channel.id(),
            json!({
                "title": "Sunday MC",
                "edition": "classic",
                "raids": ["mc"],
                "reserves_per_user": 1,
                "class_restriction": true,
                "hard_reserves": [
                    { "item_id": 17204, "reserved_for": "Guild bank" }
                ]
            }),
        )
        .await;
        let sheet_id = message.softres.expect("softres").id;

        for body in [
            // Item not in the raid (Warglaive in MC)
            json!({ "character_name": "Leeroy", "class": "paladin", "items": [32837] }),
            // Hard-reserved item
            json!({ "character_name": "Leeroy", "class": "paladin", "items": [17204] }),
            // Death Knight on a classic sheet
            json!({ "character_name": "Arthas", "class": "deathknight", "items": [18563] }),
            // Too many items for the sheet setting
            json!({ "character_name": "Leeroy", "class": "paladin", "items": [18563, 18564] }),
            // Empty items
            json!({ "character_name": "Leeroy", "class": "paladin", "items": [] }),
            // Non-letter character name
            json!({ "character_name": "L33roy", "class": "paladin", "items": [18563] }),
            // Name too short
            json!({ "character_name": "L", "class": "paladin", "items": [18563] }),
        ] {
            let response = harness
                .client
                .put(format!(
                    "/channels/{}/softres/{}/reserve",
                    channel.id(),
                    sheet_id
                ))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await;
            assert_ne!(response.status(), Status::Ok, "row should be rejected: {body}");
        }
    }

    #[rocket::async_test]
    async fn per_item_cap_blocks_the_overflowing_reserve() {
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
            json!({
                "title": "Capped",
                "edition": "classic",
                "raids": ["mc"],
                "per_item_cap": 1
            }),
        )
        .await;
        let sheet_id = message.softres.expect("softres").id;

        // First reserve takes the only slot for the item
        let response = harness
            .client
            .put(format!(
                "/channels/{}/softres/{}/reserve",
                channel.id(),
                sheet_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({ "character_name": "Leeroy", "class": "paladin", "items": [17204] })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Second raider hits the cap
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
        assert_eq!(response.status(), Status::Conflict);

        // A different item is fine
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
                json!({ "character_name": "Jenkins", "class": "mage", "items": [18563] })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Replacing one's own row does not collide with one's own copies
        let response = harness
            .client
            .put(format!(
                "/channels/{}/softres/{}/reserve",
                channel.id(),
                sheet_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({ "character_name": "Leeroy", "class": "paladin", "items": [17204] })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn hidden_sheet_gates_reserves_but_not_own_row() {
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
            json!({
                "title": "Hidden",
                "edition": "classic",
                "raids": ["mc"],
                "hidden": true
            }),
        )
        .await;
        let sheet_id = message.softres.expect("softres").id;

        // The non-creator reserves — response must not leak the sheet's
        // rows or aggregates, but must include their own row.
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
        let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
        assert!(state.reserves.is_none(), "hidden sheet leaked rows");
        assert!(state.item_counts.is_none(), "hidden sheet leaked counts");
        assert_eq!(state.total_reserves, 1);
        assert!(state.my_reserve.is_some(), "own row must always be visible");

        // The creator sees everything
        let response = harness
            .client
            .get(format!("/channels/{}/softres/{}", channel.id(), sheet_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let state: v0::SoftRes = response.into_json().await.expect("`SoftRes`");
        assert!(state.reserves.is_some(), "creator sees rows");
        assert!(state.item_counts.is_some(), "creator sees counts");
        assert_eq!(user.id, user.id);
    }
}
