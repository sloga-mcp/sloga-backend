use iso8601_timestamp::Timestamp;
use revolt_database::FieldsUser;
use revolt_database::{
    now_ms,
    util::{name_filter::contains_blocked_slur, reference::Reference},
    Database, File, PartialUser, User, UserActivity,
};
use revolt_models::v0::{self, UserPerks, USER_BADGES_DYNAMIC_MASK};
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
    if let Some(links) = data
        .profile
        .as_mut()
        .and_then(|profile| profile.links.as_mut())
    {
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

    // Custom badges are staff-set and staff-cleared (that route also retires
    // the image), so a request to drop one here is ignored
    data.remove
        .retain(|field| field != &v0::FieldsUser::CustomBadge);

    // Each part of a name style needs its own perk. The request decides the
    // parts the user holds the perk for; a locked part keeps its stored value
    // so it comes back if the perk returns. A style left with no parts is
    // cleared instead.
    if let Some(style) = data.name_style.take() {
        let perks = user.perks(now_ms());
        let held = |perk: UserPerks| perks & perk as u32 != 0;

        // Clearing the style in the same request leaves nothing to keep
        let stored = if data.remove.contains(&v0::FieldsUser::NameStyle) {
            None
        } else {
            user.name_style.clone()
        };
        let (stored_colour, stored_font, stored_effect) = match stored {
            Some(stored) => (stored.colour, stored.font, stored.effect),
            None => (None, None, None),
        };

        let merged = v0::NameStyle {
            colour: merge_name_style_part(
                held(UserPerks::NameColour),
                style.colour,
                stored_colour,
            )?,
            font: merge_name_style_part(held(UserPerks::NameFont), style.font, stored_font)?,
            effect: merge_name_style_part(
                held(UserPerks::NameEffect),
                style.effect,
                stored_effect,
            )?,
        };

        if merged.colour.is_none() && merged.font.is_none() && merged.effect.is_none() {
            if !data.remove.contains(&v0::FieldsUser::NameStyle) {
                data.remove.push(v0::FieldsUser::NameStyle);
            }
        } else {
            // The merged style replaces the stored one whole, and clearing
            // the same field in one write conflicts on Mongo
            data.remove
                .retain(|field| field != &v0::FieldsUser::NameStyle);
            data.name_style = Some(merged);
        }
    }

    // Exit out early if nothing is changed
    if data.display_name.is_none()
        && data.pronouns.is_none()
        && data.status.is_none()
        && data.profile.is_none()
        && data.name_style.is_none()
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
        // Referral and supporter badges are computed on read, never stored
        badges: data
            .badges
            .map(|badges| ((badges as u32) & !USER_BADGES_DYNAMIC_MASK) as i32),
        flags: data.flags,
        name_style: data.name_style,
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

/// One part of a requested name style merged with the stored one
///
/// With the perk the request wins, including clearing the part. Without it
/// the stored value stays, and a request to change it is refused.
fn merge_name_style_part<T: PartialEq>(
    held: bool,
    requested: Option<T>,
    stored: Option<T>,
) -> Result<Option<T>> {
    if held {
        Ok(requested)
    } else if requested.is_none() || requested == stored {
        Ok(stored)
    } else {
        Err(create_error!(PerkRequired))
    }
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_database::{
        now_ms, CustomBadge, File, Metadata, PartialUser, User, DAY_MS, WELCOME_TRIAL_DAYS,
    };
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

    #[test]
    fn name_style_requires_perk() {
        crate::util::test::rt().block_on(name_style_requires_perk_case())
    }

    async fn name_style_requires_perk_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": { "colour": "#ff0000" } }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Forbidden);
    }

    #[test]
    fn name_style_rejects_non_colour_values() {
        crate::util::test::rt().block_on(name_style_rejects_non_colour_values_case())
    }

    async fn name_style_rejects_non_colour_values_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;

        // Even with the perk, anything that is not a plain colour (here a
        // remote fetch every viewer's client would make) is refused.
        user.update(
            &harness.db,
            PartialUser {
                welcomed_at: Some(now_ms()),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("welcomed user");

        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": { "colour": "url(https://x)" } }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn set_and_clear_name_style() {
        crate::util::test::rt().block_on(set_and_clear_name_style_case())
    }

    async fn set_and_clear_name_style_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;

        // The welcome trial unlocks the name colour and nothing else.
        user.update(
            &harness.db,
            PartialUser {
                welcomed_at: Some(now_ms()),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("welcomed user");

        // A request carrying only a name style must still be applied.
        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": { "colour": "#ff0000" } }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        let edited = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(
            edited.name_style,
            Some(v0::NameStyle {
                colour: Some("#ff0000".to_string()),
                font: None,
                effect: None,
            })
        );

        // An empty style clears it.
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": {} }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        let cleared = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(cleared.name_style, None);

        let stored = harness.db.fetch_user(&user.id).await.expect("`User`");
        assert_eq!(stored.name_style, None);
    }

    #[test]
    fn name_style_font_needs_its_own_perk() {
        crate::util::test::rt().block_on(name_style_font_needs_its_own_perk_case())
    }

    async fn name_style_font_needs_its_own_perk_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;

        // The welcome trial covers the colour but not the font.
        user.update(
            &harness.db,
            PartialUser {
                welcomed_at: Some(now_ms()),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("welcomed user");

        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(
                    json!({ "name_style": { "colour": "#ff0000", "font": "Serif" } }).to_string(),
                ),
        )
        .await;

        assert_eq!(response.status(), Status::Forbidden);
    }

    fn style(colour: Option<&str>, font: Option<v0::NameFont>) -> Option<v0::NameStyle> {
        Some(v0::NameStyle {
            colour: colour.map(str::to_string),
            font,
            effect: None,
        })
    }

    /// Give `user` the welcome trial's name color and a stored font whose
    /// perk they no longer hold
    async fn lock_stored_font(harness: &TestHarness, user: &mut User) {
        user.update(
            &harness.db,
            PartialUser {
                welcomed_at: Some(now_ms()),
                name_style: style(None, Some(v0::NameFont::Serif)),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("styled user");
    }

    async fn stored_name_style(harness: &TestHarness, user: &User) -> Option<v0::NameStyle> {
        harness
            .db
            .fetch_user(&user.id)
            .await
            .expect("`User`")
            .name_style
    }

    #[test]
    fn name_style_save_keeps_locked_part() {
        crate::util::test::rt().block_on(name_style_save_keeps_locked_part_case())
    }

    async fn name_style_save_keeps_locked_part_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        lock_stored_font(&harness, &mut user).await;

        // Setting the color leaves the locked font in place, hidden from
        // everyone until the perk returns
        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": { "colour": "#00ff00" } }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        let edited = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(edited.name_style, style(Some("#00ff00"), None));
        assert_eq!(
            stored_name_style(&harness, &user).await,
            style(Some("#00ff00"), Some(v0::NameFont::Serif))
        );

        // An empty style resets only what the user can still change
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": {} }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        let cleared = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(cleared.name_style, None);
        assert_eq!(
            stored_name_style(&harness, &user).await,
            style(None, Some(v0::NameFont::Serif))
        );
    }

    #[test]
    fn name_style_locked_part_cannot_change() {
        crate::util::test::rt().block_on(name_style_locked_part_cannot_change_case())
    }

    async fn name_style_locked_part_cannot_change_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        lock_stored_font(&harness, &mut user).await;

        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": { "colour": "#00ff00", "font": "Mono" } }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            stored_name_style(&harness, &user).await,
            style(None, Some(v0::NameFont::Serif))
        );

        // Sending the locked font back unchanged is fine
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(
                    json!({ "name_style": { "colour": "#00ff00", "font": "Serif" } }).to_string(),
                ),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            stored_name_style(&harness, &user).await,
            style(Some("#00ff00"), Some(v0::NameFont::Serif))
        );
    }

    #[test]
    fn remove_name_style_clears_locked_part() {
        crate::util::test::rt().block_on(remove_name_style_clears_locked_part_case())
    }

    async fn remove_name_style_clears_locked_part_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        lock_stored_font(&harness, &mut user).await;

        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": { "colour": "#00ff00" } }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            stored_name_style(&harness, &user).await,
            style(Some("#00ff00"), Some(v0::NameFont::Serif))
        );

        // Removing the field outright still takes every part with it
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "remove": ["NameStyle"] }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        let cleared = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(cleared.name_style, None);
        assert_eq!(stored_name_style(&harness, &user).await, None);
    }

    /// Store a color on `user` whose welcome trial has run out
    async fn lapse_stored_colour(harness: &TestHarness, user: &mut User) {
        user.update(
            &harness.db,
            PartialUser {
                welcomed_at: Some(now_ms() - WELCOME_TRIAL_DAYS * DAY_MS - 1),
                name_style: style(Some("#ff0000"), None),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("lapsed user");
    }

    #[test]
    fn name_style_keeps_lapsed_colour() {
        crate::util::test::rt().block_on(name_style_keeps_lapsed_colour_case())
    }

    async fn name_style_keeps_lapsed_colour_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        lapse_stored_colour(&harness, &mut user).await;

        // Resetting with no perks left touches nothing
        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": {} }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            stored_name_style(&harness, &user).await,
            style(Some("#ff0000"), None)
        );

        // Sending the locked color back unchanged is fine
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": { "colour": "#ff0000" } }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            stored_name_style(&harness, &user).await,
            style(Some("#ff0000"), None)
        );
    }

    #[test]
    fn name_style_lapsed_colour_cannot_change() {
        crate::util::test::rt().block_on(name_style_lapsed_colour_cannot_change_case())
    }

    async fn name_style_lapsed_colour_cannot_change_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        lapse_stored_colour(&harness, &mut user).await;

        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "name_style": { "colour": "#00ff00" } }).to_string()),
        )
        .await;

        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            stored_name_style(&harness, &user).await,
            style(Some("#ff0000"), None)
        );
    }

    #[test]
    fn remove_custom_badge_is_ignored() {
        crate::util::test::rt().block_on(remove_custom_badge_is_ignored_case())
    }

    async fn remove_custom_badge_is_ignored_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;

        user.update(
            &harness.db,
            PartialUser {
                custom_badge: Some(CustomBadge {
                    image: File {
                        id: ulid::Ulid::new().to_string(),
                        tag: "custom_badges".to_string(),
                        filename: "badge.png".to_string(),
                        hash: None,
                        uploaded_at: None,
                        uploader_id: None,
                        used_for: None,
                        deleted: None,
                        reported: None,
                        metadata: Metadata::File,
                        content_type: "image/png".to_string(),
                        size: 10,
                        message_id: None,
                        user_id: None,
                        server_id: None,
                        object_id: None,
                    },
                    label: "Founder".to_string(),
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("badged user");

        // Only staff may take the badge away; the rest of the edit still lands.
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(
                    json!({ "display_name": "Badge Keeper", "remove": ["CustomBadge"] })
                        .to_string(),
                ),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
        let edited = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(edited.display_name, Some("Badge Keeper".to_string()));
        assert!(edited.custom_badge.is_some());

        let stored = harness.db.fetch_user(&user.id).await.expect("`User`");
        assert!(stored.custom_badge.is_some());
    }
}
