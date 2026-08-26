use iso8601_timestamp::Timestamp;
use revolt_database::FieldsUser;
use revolt_database::{
    util::{name_filter::contains_blocked_slur, reference::Reference},
    Database, File, PartialUser, User, UserActivity,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

/// # Edit User
///
/// Edit currently authenticated user.
#[openapi(tag = "User Information")]
#[patch("/<target>", data = "<data>")]
pub async fn edit(
    db: &State<Database>,
    mut user: User,
    target: Reference<'_>,
    data: Json<v0::DataEditUser>,
) -> Result<Json<v0::User>> {
    let mut data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Filter out invalid edit fields
    if !user.privileged && (data.badges.is_some() || data.flags.is_some()) {
        return Err(create_error!(NotPrivileged));
    }

    // Display names get the same slur filter as usernames — they are what
    // everyone actually reads.
    if let Some(display_name) = &data.display_name {
        if contains_blocked_slur(display_name) {
            return Err(create_error!(DisallowedName));
        }
    }

    // Game-account links: cap, hygiene, slur filter. Handles are read by
    // strangers on the profile card, so they get the display-name treatment.
    // (Per-handle length is the nested derive's job; validator 0.16 cannot
    // carry a list-length rule alongside it, hence the explicit cap here.)
    if let Some(links) = data.profile.as_mut().and_then(|profile| profile.links.as_mut()) {
        if links.len() > 12 {
            return Err(create_error!(FailedValidation {
                error: "links: at most 12 entries".to_string()
            }));
        }

        for link in links.iter_mut() {
            link.handle = link
                .handle
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_string();

            if link.handle.is_empty() {
                return Err(create_error!(FailedValidation {
                    error: "links: handle must not be empty".to_string()
                }));
            }

            if contains_blocked_slur(&link.handle) {
                return Err(create_error!(DisallowedName));
            }
        }
    }

    // If we want to edit a different user than self, ensure we have
    // permissions and subsequently replace the user in question
    if target.id != "@me" && target.id != user.id {
        let target_user = target.as_user(db).await?;
        let is_bot_owner = target_user
            .bot
            .as_ref()
            .map(|bot| bot.owner == user.id)
            .unwrap_or_default();

        if !is_bot_owner && !user.privileged {
            return Err(create_error!(NotPrivileged));
        }

        user = target_user;
    }

    // Exit out early if nothing is changed
    if data.display_name.is_none()
        && data.pronouns.is_none()
        && data.status.is_none()
        && data.profile.is_none()
        && data.avatar.is_none()
        && data.badges.is_none()
        && data.flags.is_none()
        && data.e2ee_enabled.is_none()
        && data.profile_visibility.is_none()
        && data.remove.is_empty()
    {
        return Ok(Json(user.into_self(false).await));
    }

    // `connections` is denormalized from user_stream_connections and only
    // the link/unlink/poller paths may rewrite it — removing it here would
    // silently desync until the next live-flip. Unlink is the real API.
    if data.remove.contains(&v0::FieldsUser::Connections) {
        return Err(create_error!(InvalidOperation));
    }

    // 1. Remove fields from object
    if data.remove.contains(&v0::FieldsUser::Avatar) {
        if let Some(avatar) = &user.avatar {
            db.mark_attachment_as_deleted(&avatar.id).await?;
        }
    }

    if data.remove.contains(&v0::FieldsUser::ProfileBackground) {
        if let Some(profile) = &user.profile {
            if let Some(background) = &profile.background {
                db.mark_attachment_as_deleted(&background.id).await?;
            }
        }
    }

    for field in &data.remove {
        let field: FieldsUser = field.clone().into();
        user.remove_field(&field);
    }

    let mut partial: PartialUser = PartialUser {
        display_name: data.display_name,
        pronouns: data.pronouns,
        badges: data.badges,
        flags: data.flags,
        // UI hint only: E2EE capability is always derived from published,
        // signature-verified key bundles, never from this flag
        e2ee_enabled: data.e2ee_enabled,
        profile_visibility: data.profile_visibility.map(Into::into),
        ..Default::default()
    };

    // 2. Apply new avatar
    if let Some(avatar) = data.avatar {
        partial.avatar = Some(File::use_user_avatar(db, &avatar, &user.id, &user.id).await?);
    }

    // 3. Apply new status
    if let Some(status) = data.status {
        let mut new_status = user.status.take().unwrap_or_default();
        if let Some(text) = status.text {
            new_status.text = Some(text);
        }

        if let Some(presence) = status.presence {
            new_status.presence = Some(presence.into());
        }

        if let Some(activity) = status.activity {
            // Server-authoritative timer: keep it running if they're still playing
            // the same game, otherwise stamp the moment this one started.
            let started_at = match &new_status.activity {
                Some(current) if current.name == activity.name => current.started_at,
                _ => Some(Timestamp::now_utc()),
            };

            new_status.activity = Some(UserActivity {
                name: activity.name,
                started_at,
            });
        }

        partial.status = Some(new_status);
    }

    // 4. Apply new profile
    if let Some(profile) = data.profile {
        let mut new_profile = user.profile.take().unwrap_or_default();
        if let Some(content) = profile.content {
            new_profile.content = Some(content);
        }

        if let Some(background) = profile.background {
            new_profile.background =
                Some(File::use_background(db, &background, &user.id, &user.id).await?);
        }

        // Links replace wholesale (an empty list clears) — a partial merge
        // of a list has no sane semantics.
        if let Some(links) = profile.links {
            new_profile.links = links.into_iter().map(Into::into).collect();
        }

        partial.profile = Some(new_profile);
    }

    user.update(
        db,
        partial,
        data.remove.into_iter().map(Into::into).collect(),
    )
    .await?;

    Ok(Json(user.into_self(false).await))
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};

    #[test]
    fn set_game_activity() {
        crate::util::test::rt().block_on(set_game_activity_case())
    }

    async fn set_game_activity_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        // Set the "playing a game" activity via the status object.
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "status": {
                            "activity": { "name": "Celeste" }
                        }
                    })
                    .to_string(),
                ),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);

        // The returned user should advertise the game to anyone who can see them,
        // with a server-stamped start time.
        let user = response.into_json::<v0::User>().await.expect("`User`");
        let activity = user
            .status
            .and_then(|status| status.activity)
            .expect("`activity`");
        assert_eq!(activity.name, "Celeste".to_string());
        assert!(activity.started_at.is_some());
    }

    #[test]
    fn reject_slur_in_display_name() {
        crate::util::test::rt().block_on(reject_slur_in_display_name_case())
    }

    async fn reject_slur_in_display_name_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        // Leetspeak and separator padding are folded before matching, so this
        // is rejected the same way the plain spelling is.
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "display_name": "n1gg3r" }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn allow_display_name_that_merely_looks_like_one() {
        crate::util::test::rt().block_on(allow_display_name_that_merely_looks_like_one_case())
    }

    async fn allow_display_name_that_merely_looks_like_one_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        // "Spicy" contains a blocked whole word and "Nigerian" is one `g` short
        // of one — neither may cost somebody their name.
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "display_name": "Spicy Nigerian Chef" }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);

        let user = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(user.display_name, Some("Spicy Nigerian Chef".to_string()));
    }

    #[test]
    fn clear_game_activity() {
        crate::util::test::rt().block_on(clear_game_activity_case())
    }

    async fn clear_game_activity_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        // Set it first.
        TestHarness::with_session(
            session.clone(),
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "status": { "activity": { "name": "Celeste" } } }).to_string()),
        )
        .await;

        // Then clear it via the remove field.
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "remove": ["StatusActivity"] }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);

        let user = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(user.status.and_then(|status| status.activity), None);
    }
}
