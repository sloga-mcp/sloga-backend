//! Screen-share annotation — server relay (tech-support-mode plan §2).
//!
//! A call participant draws translucent ink on a screen-sharer's surface:
//! "circle the button" instead of (or before) taking control. Strokes take
//! the captions TRANSPORT — REST validates, the server fans an `EventV1` to
//! the call's members — because no other authenticated path exists before a
//! remote-control session arms (no pairwise key, and the voice token forbids
//! `publishData`). But NOT the captions ADDRESSING MODEL: a caption is
//! SELF-addressed (the sender's own speech on the sender's own tile), so
//! stamping the sender sufficed there. An annotation is OTHER-addressed —
//! the helper draws on someone ELSE's surface — so this route additionally
//! validates the TARGET (a live screen-sharer here) and enforces the
//! target's draw-consent allowlist server-side. Without that, plan §2.4's
//! consent gate would be a client toggle a hostile client skips.
//!
//! A stroke is a PICTURE, never an input event (plan §0.3): nothing here
//! touches, imports, or shares state with the remote-control seal/open/
//! inject surface, and it must stay that way.

use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{
        annotations::{
            is_annotator_allowed, ANNOTATION_COORD_SCALE, ANNOTATION_PALETTE_SIZE,
            ANNOTATION_WIDTH_CLASSES,
        },
        get_voice_channel_members, get_voice_participant_identity, get_voice_state,
        is_in_voice_channel, UserVoiceChannel,
    },
    Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use validator::Validate;

use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// Most points one stroke may carry (128 f32 values as flattened x,y pairs).
/// With ≤8 strokes per batch and ≤10 Hz client coalescing this bounds the
/// fan-out payload regardless of what the sender claims.
const MAX_STROKE_VALUES: usize = 128;

/// # Send Annotation Strokes
///
/// Relay a batch of drawn strokes onto a screen-sharing participant's
/// surface. The caller must be a current call participant holding `Connect`
/// (deliberately NOT `Speak` — a listen-only helper may legitimately point
/// at things), the named target must be publishing screen video right now,
/// and the target must have allowlisted the caller ("let people draw on my
/// shared screen" is off by default and server-enforced). Nothing is stored:
/// the server validates, fans a `CallAnnotation` event to the call's
/// members, and forgets it.
#[openapi(tag = "Voice")]
#[post("/<target>/annotations", data = "<data>")]
pub async fn send_annotation(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataSendAnnotation>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Geometry/palette bounds the derive can't express: pairs of in-range
    // coordinates, palette + width class indexes. Rejected, not clamped —
    // out-of-range here is a hostile or broken client, not an over-length
    // utterance.
    for stroke in &data.strokes {
        if stroke.points.len() < 2
            || stroke.points.len() > MAX_STROKE_VALUES
            || stroke.points.len() % 2 != 0
            || stroke.points.iter().any(|v| *v > ANNOTATION_COORD_SCALE)
            || stroke.color >= ANNOTATION_PALETTE_SIZE
            || stroke.width >= ANNOTATION_WIDTH_CLASSES
        {
            return Err(create_error!(FailedValidation {
                error: "malformed stroke".to_string()
            }));
        }
    }

    let channel = target.as_channel(db).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // A self-annotation is a confused client: the sharer's own client can
    // render locally without a round trip, and "drawing on yourself" must
    // not create a consent bypass precedent.
    if data.target == user.id {
        return Err(create_error!(InvalidOperation));
    }

    let mut query = perms(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    // Connect only, deliberately not Speak (captions' extra gate): drawing
    // is not speech, and a listen-only participant pointing at the right
    // button is exactly the use case.
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    let voice_channel = UserVoiceChannel::from_channel(&channel);
    if !is_in_voice_channel(&user.id, &voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }
    if !is_in_voice_channel(&data.target, &voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    // The target must be streaming RIGHT NOW — there is no surface to draw
    // on otherwise. Gate on `screen_video` (source 3 only), not the
    // conflated `screensharing` flag, for the same reason the offer and
    // control-request predicates do.
    let publishing_screen_video = get_voice_state(&voice_channel, &data.target)
        .await?
        .is_some_and(|state| state.screen_video);
    if !publishing_screen_video {
        return Err(create_error!(FailedValidation {
            error: "target is not publishing screen video".to_string()
        }));
    }

    // THE §2.4 GATE, server-side: the target must have allowlisted this
    // caller. Checked on every batch — the one-action revoke (DELETE on the
    // consent route) takes effect on the very next send.
    if !is_annotator_allowed(channel.id(), &data.target, &user.id).await? {
        return Err(create_error!(MissingPermission {
            permission: "AnnotateScreenShare".to_string(),
        }));
    }

    // Both identities resolved SERVER-side, never taken from the request
    // (the captions rule, doubly load-bearing here because the event is
    // other-addressed): receivers key the overlay by `target_identity` and
    // the attribution banner by `annotator_identity`.
    let annotator_identity = get_voice_participant_identity(channel.id(), &user.id).await?;
    let target_identity = get_voice_participant_identity(channel.id(), &data.target).await?;

    let Some(members) = get_voice_channel_members(&voice_channel).await? else {
        return Ok(EmptyResponse);
    };

    // Private topics per call member, sender skipped — the captions
    // boundary decision: `.p(channel_id)` authorizes on ViewChannel and
    // would hand the overlay to text-channel lurkers who never joined.
    // Every viewer receives it (not just the target): all tiles showing the
    // shared screen render the same ink.
    for member_id in members {
        if member_id == user.id {
            continue;
        }

        EventV1::CallAnnotation {
            channel_id: channel.id().to_string(),
            annotator_identity: annotator_identity.clone(),
            annotator_id: user.id.clone(),
            target_identity: target_identity.clone(),
            target_id: data.target.clone(),
            strokes: data.strokes.clone(),
            seq: data.seq,
        }
        .private(member_id)
        .await;
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            annotations::add_allowed_annotator, create_voice_state, delete_channel_voice_state,
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

    fn stroke_body(target_id: &str) -> String {
        serde_json::json!({
            "target": target_id,
            "strokes": [{ "points": [1000, 1000, 5000, 5000], "color": 0, "width": 0 }],
            "seq": 1
        })
        .to_string()
    }

    async fn draw<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
        body: String,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .post(format!("/channels/{channel_id}/annotations"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(body)
            .dispatch()
            .await
    }

    /// Fresh server + voice channel + sharer (A, owner) + annotator (B,
    /// member). The `annotations` bucket is generous (180/10s) so scenarios
    /// can share a harness, but they are still split by CONCERN so a failure
    /// names the gate that broke.
    async fn setup() -> (TestHarness, Channel, UserVoiceChannel, User, String, User) {
        let harness = TestHarness::new().await;
        let (_, _session_a, user_a) = harness.new_user().await; // sharer
        let (_, session_b, user_b) = harness.new_user().await; // annotator
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        (harness, channel, uvc, user_a, session_b.token, user_b)
    }

    /// Membership, live-stream and CONSENT refusals, in gate order. The
    /// consent refusal is the §2.4 enforcement point: everything else about
    /// the request is valid, only the allowlist entry is missing.
    #[rocket::async_test]
    async fn annotation_gates_membership_share_and_consent() {
        let (harness, channel, uvc, user_a, token_b, user_b) = setup().await;

        // Annotator not in the call: refused.
        let response = draw(&harness, &token_b, channel.id(), stroke_body(&user_a.id)).await;
        assert_eq!(response.status(), Status::BadRequest);

        create_voice_state(&uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state b");

        // Target not in the call: refused.
        let response = draw(&harness, &token_b, channel.id(), stroke_body(&user_a.id)).await;
        assert_eq!(response.status(), Status::BadRequest);

        create_voice_state(&uvc, &user_a.id, Timestamp::now_utc())
            .await
            .expect("voice state a");

        // Target present but not publishing screen video: refused — there is
        // no surface to draw on.
        let response = draw(&harness, &token_b, channel.id(), stroke_body(&user_a.id)).await;
        assert_eq!(response.status(), Status::BadRequest);

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

        // Live stream, valid request — but NO CONSENT: refused. A hostile
        // client that skips its local toggle lands exactly here.
        let response = draw(&harness, &token_b, channel.id(), stroke_body(&user_a.id)).await;
        assert_eq!(response.status(), Status::Forbidden);

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }

    /// The allowed path relays; self-annotation and malformed strokes are
    /// refused even WITH consent (validation is not a consent question).
    #[rocket::async_test]
    async fn annotation_relays_when_allowed_and_validates_strokes() {
        let (harness, channel, uvc, user_a, token_b, user_b) = setup().await;

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
        add_allowed_annotator(channel.id(), &user_a.id, &user_b.id)
            .await
            .expect("allowlist");

        // Consent in place: the honest path relays.
        let response = draw(&harness, &token_b, channel.id(), stroke_body(&user_a.id)).await;
        assert_eq!(response.status(), Status::NoContent);

        // Self-annotation: refused regardless of consent state.
        let response = draw(&harness, &token_b, channel.id(), stroke_body(&user_b.id)).await;
        assert_eq!(response.status(), Status::BadRequest);

        // Out-of-range coordinate: refused, not clamped.
        let bad = serde_json::json!({
            "target": user_a.id,
            "strokes": [{ "points": [1000, 15000], "color": 0, "width": 0 }],
            "seq": 2
        })
        .to_string();
        let response = draw(&harness, &token_b, channel.id(), bad).await;
        assert_eq!(response.status(), Status::BadRequest);

        // Palette index past the fixed palette: refused — raw colors must
        // never cross the wire disguised as indexes.
        let bad = serde_json::json!({
            "target": user_a.id,
            "strokes": [{ "points": [1000, 1000, 2000, 2000], "color": 99, "width": 0 }],
            "seq": 3
        })
        .to_string();
        let response = draw(&harness, &token_b, channel.id(), bad).await;
        assert_eq!(response.status(), Status::BadRequest);

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }
}
