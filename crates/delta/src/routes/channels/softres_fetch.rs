use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::util::polls::now_ms;
use crate::util::softres::can_see_full;

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
    if sheet.channel != channel.id() {
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

    #[rocket::async_test]
    async fn fetch_is_channel_scoped_and_bulk_returns_page() {
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
