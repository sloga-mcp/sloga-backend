//! Draw-consent management for screen-share annotation (tech-support-mode
//! plan §2.4).
//!
//! The sharer — and only the sharer — decides who may draw on their shared
//! screen: OFF by default, granted per NAMED participant, revoked in ONE
//! action. This state is the enforcement input for `annotations_send` and
//! lives server-side precisely so a hostile annotator client has nothing to
//! skip. The GET exists so a late joiner learns standing consent from a
//! roster read instead of a missed event (the pass-the-controller slice-0
//! backfill lesson).

use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{
        annotations::{
            add_allowed_annotator, clear_allowed_annotators, count_allowed_annotators,
            get_allowed_annotators, MAX_ALLOWED_ANNOTATORS,
        },
        get_voice_channel_members, get_voice_state, is_in_voice_channel, UserVoiceChannel,
    },
    Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// Shared guard: voice channel, `Connect`, caller currently in the call.
async fn require_call_participant(
    db: &Database,
    user: &User,
    channel: &revolt_database::Channel,
) -> Result<UserVoiceChannel> {
    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    let mut query = perms(db, user).channel(channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    let voice_channel = UserVoiceChannel::from_channel(channel);
    if !is_in_voice_channel(&user.id, &voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }
    Ok(voice_channel)
}

/// Fan the sharer's COMPLETE new allowlist to the call's members (private
/// topics, sender included — the sharer's other sessions need the update
/// too, and unlike strokes there is no local echo to duplicate).
async fn fan_consent(channel_id: &str, sharer_id: &str, voice_channel: &UserVoiceChannel) {
    let allowed = get_allowed_annotators(channel_id, sharer_id)
        .await
        .unwrap_or_default();
    if let Ok(Some(members)) = get_voice_channel_members(voice_channel).await {
        for member_id in members {
            EventV1::CallAnnotationConsent {
                channel_id: channel_id.to_string(),
                sharer_id: sharer_id.to_string(),
                allowed: allowed.clone(),
            }
            .private(member_id)
            .await;
        }
    }
}

/// # Allow An Annotator
///
/// Let one named call participant draw on the caller's shared screen. The
/// caller must be publishing screen video right now — consent is granted on
/// a live surface, not stockpiled — and the named user must be a current
/// call participant. Off by default; each grant names exactly one person,
/// never "anyone in the call".
#[openapi(tag = "Voice")]
#[put("/<target>/annotations/allow", data = "<data>")]
pub async fn annotation_allow(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataAnnotationAllow>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    let channel = target.as_channel(db).await?;
    let voice_channel = require_call_participant(db, &user, &channel).await?;

    // Allowing yourself is a confused client, and must not seed a
    // "self-consent" precedent the send route would then have to reason
    // about.
    if data.user == user.id {
        return Err(create_error!(InvalidOperation));
    }

    if !is_in_voice_channel(&data.user, &voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    // Consent is granted ON a live shared surface: the caller must be
    // publishing screen video (source 3 only, the offer-predicate rule).
    let sharing = get_voice_state(&voice_channel, &user.id)
        .await?
        .is_some_and(|state| state.screen_video);
    if !sharing {
        return Err(create_error!(FailedValidation {
            error: "caller is not publishing screen video".to_string()
        }));
    }

    // The allowlist is capped (rev-3 review): its size is the only
    // server-side bound on aggregate stroke fan-out, so it must not scale
    // with channel population. §2.4's model is a helper or two, not an
    // audience. (SCARD-then-SADD races at worst one entry past the cap —
    // the caller is a single ratelimited sharer, not an adversary against
    // their own list.)
    if count_allowed_annotators(channel.id(), &user.id).await? >= MAX_ALLOWED_ANNOTATORS {
        return Err(create_error!(FailedValidation {
            error: "annotator allowlist is full".to_string()
        }));
    }

    add_allowed_annotator(channel.id(), &user.id, &data.user).await?;
    fan_consent(channel.id(), &user.id, &voice_channel).await;

    Ok(EmptyResponse)
}

/// # Revoke All Annotators
///
/// The ONE-ACTION revoke (plan §2.4): clear the caller's entire draw
/// allowlist at once. This — not the stroke fade — is the backstop against
/// a live phishing overlay, so it deliberately does NOT require an active
/// share: a sharer who just stopped streaming (or whose share state is in
/// any doubt) can always clear consent.
#[openapi(tag = "Voice")]
#[delete("/<target>/annotations/allow")]
pub async fn annotation_revoke(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;
    let voice_channel = require_call_participant(db, &user, &channel).await?;

    clear_allowed_annotators(channel.id(), &user.id).await?;
    fan_consent(channel.id(), &user.id, &voice_channel).await;

    Ok(EmptyResponse)
}

/// # Fetch Draw-Consent State
///
/// Current draw allowlists for this call's active screen-sharers (entries
/// with at least one allowed annotator). Lets a client joining mid-call
/// render the draw affordance without having seen the consent events.
#[openapi(tag = "Voice")]
#[get("/<target>/annotations/allow")]
pub async fn annotation_consent_fetch(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::AnnotationConsentResponse>> {
    let channel = target.as_channel(db).await?;
    let voice_channel = require_call_participant(db, &user, &channel).await?;

    let mut sharers = Vec::new();
    if let Some(members) = get_voice_channel_members(&voice_channel).await? {
        for member_id in members {
            let is_sharing = get_voice_state(&voice_channel, &member_id)
                .await?
                .is_some_and(|state| state.screen_video);
            if !is_sharing {
                continue;
            }
            let allowed = get_allowed_annotators(channel.id(), &member_id).await?;
            if !allowed.is_empty() {
                sharers.push(v0::AnnotationConsentEntry {
                    sharer_id: member_id,
                    allowed,
                });
            }
        }
    }

    Ok(Json(v0::AnnotationConsentResponse { sharers }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            annotations::is_annotator_allowed, create_voice_state, delete_channel_voice_state,
            update_voice_state, UserVoiceChannel,
        },
        Channel, Member, User,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    async fn voice_channel(
        harness: &TestHarness,
        server: &revolt_database::Server,
        name: &str,
    ) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: name.to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: Some(v0::VoiceInformation {
                    max_users: None,
                    disabled: false,
                }),
                announcement: None,
            },
            true,
        )
        .await
        .expect("voice channel")
    }

    /// Sharer A (owner) + annotator B, both with voice states; A streaming.
    async fn setup() -> (TestHarness, Channel, UserVoiceChannel, User, String, User) {
        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await; // sharer
        let (_, _session_b, user_b) = harness.new_user().await; // annotator
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        create_voice_state(&uvc, &user_a.id, Timestamp::now_utc())
            .await
            .expect("voice state a");
        create_voice_state(&uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state b");
        update_voice_state(
            &uvc,
            &user_a.id,
            &v0::PartialUserVoiceState {
                screen_video: Some(true),
                screensharing: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("screen video flag");
        (harness, channel, uvc, user_a, session_a.token, user_b)
    }

    /// Grant → visible in GET → one-action revoke clears it, and the revoke
    /// works even after the share has stopped.
    #[rocket::async_test]
    async fn consent_grant_fetch_and_revoke_lifecycle() {
        let (harness, channel, uvc, user_a, token_a, user_b) = setup().await;

        // Grant B.
        let response = harness
            .client
            .put(format!("/channels/{}/annotations/allow", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(serde_json::json!({ "user": user_b.id }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        assert!(
            is_annotator_allowed(channel.id(), &user_a.id, &user_b.id)
                .await
                .expect("allowlist read")
        );

        // GET shows the sharer with B allowed.
        let response = harness
            .client
            .get(format!("/channels/{}/annotations/allow", channel.id()))
            .header(Header::new("x-session-token", token_a.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let body: v0::AnnotationConsentResponse =
            response.into_json().await.expect("consent response");
        assert_eq!(body.sharers.len(), 1);
        assert_eq!(body.sharers[0].sharer_id, user_a.id);
        assert_eq!(body.sharers[0].allowed, vec![user_b.id.clone()]);

        // Share stops — consent is scoped to the share it was granted on,
        // so the allowlist AUTO-clears right here (rev-3 review: without
        // this, re-sharing hours later silently resurrects old grants).
        update_voice_state(
            &uvc,
            &user_a.id,
            &v0::PartialUserVoiceState {
                screen_video: Some(false),
                screensharing: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect("share stop");
        assert!(
            !is_annotator_allowed(channel.id(), &user_a.id, &user_b.id)
                .await
                .expect("allowlist read"),
            "share stop must clear draw consent"
        );

        // The explicit revoke must STILL work after the share ended (the
        // backstop never depends on a live share) — here it is a no-op on
        // an already-cleared list, and still 204.
        let response = harness
            .client
            .delete(format!("/channels/{}/annotations/allow", channel.id()))
            .header(Header::new("x-session-token", token_a.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        assert!(
            !is_annotator_allowed(channel.id(), &user_a.id, &user_b.id)
                .await
                .expect("allowlist read")
        );

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }

    /// The grant guards: no self-allow, no allowing an absent user, and no
    /// granting while not streaming.
    #[rocket::async_test]
    async fn consent_grant_guards() {
        let (harness, channel, uvc, user_a, token_a, user_b) = setup().await;

        // Self-allow: refused.
        let response = harness
            .client
            .put(format!("/channels/{}/annotations/allow", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(serde_json::json!({ "user": user_a.id }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Allowing someone who is not in the call: refused.
        let (_, _, user_c) = harness.new_user().await;
        let response = harness
            .client
            .put(format!("/channels/{}/annotations/allow", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(serde_json::json!({ "user": user_c.id }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Not streaming: refused — consent is granted on a live surface.
        update_voice_state(
            &uvc,
            &user_a.id,
            &v0::PartialUserVoiceState {
                screen_video: Some(false),
                screensharing: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect("share stop");
        let response = harness
            .client
            .put(format!("/channels/{}/annotations/allow", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(serde_json::json!({ "user": user_b.id }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }
}
