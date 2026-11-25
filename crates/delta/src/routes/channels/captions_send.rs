//! Live call captions — server relay.
//!
//! Replaces the original design, in which a speaker broadcast captions over a
//! LiveKit data channel. That never worked and could not: the voice join token
//! is minted with `can_publish_data: false` (`voice/voice_client.rs`), so the
//! SFU silently discarded every caption packet — `publishData()` resolves
//! without error on the sender and nothing arrives at the peer. Only the
//! speaker's own local self-mirror rendered, which is why one-person tests
//! looked green for months.
//!
//! Flipping that grant was the wrong fix: `can_publish_data` is what stops any
//! speaker injecting arbitrary data packets at every other participant, and
//! E2EE slice 6.1 already closed a regrant-on-permission-sync hole in it
//! (`permission_sync_never_regrants_data_publishing`). So captions take the
//! soundboard shape instead — REST validates, the server fans an event — with
//! one deliberate divergence noted on the fan-out below.

use revolt_config::config;
use revolt_database::{
    events::client::EventV1,
    util::{e2ee_only, permissions::perms, reference::Reference},
    voice::{
        get_voice_channel_members, get_voice_participant_identity, is_in_voice_channel,
        UserVoiceChannel,
    },
    Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use validator::Validate;

use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// Display cap the client renders captions at (`liveCaptions.ts`
/// MAX_CAPTION_CHARS). Clamped here too so an over-length line is truncated
/// rather than dropped, and so the fan-out payload is bounded regardless of
/// what the sender claims.
const MAX_CAPTION_CHARS: usize = 240;

/// Truncate on a character boundary — `text` is arbitrary UTF-8 and a byte
/// slice would panic mid-codepoint on the first non-ASCII caption.
fn clamp_caption(text: &str) -> String {
    text.chars().take(MAX_CAPTION_CHARS).collect()
}

/// # Send Live Caption
///
/// Relay one finalized caption line to the other participants of a voice call.
/// The caller must be a current participant holding `Connect` + `Speak`.
/// Nothing is stored: the server validates, fans a `CallCaption` event to the
/// call's members, and forgets it.
#[openapi(tag = "Voice")]
#[post("/<target>/captions", data = "<data>")]
pub async fn send_caption(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataSendCaption>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    let mut query = perms(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;
    // Speak, not just Connect: a caption is a transcript of speech, so anyone
    // barred from speaking has nothing legitimate to caption. This also stops
    // a listen-only participant putting words on a tile.
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Speak)?;

    // A caption is readable text relayed through the server, so a direct
    // message or group that takes encrypted messages only takes none.
    // Refused after the permission checks, before any fan-out.
    let e2ee_config = config().await.features.e2ee.clone();
    e2ee_only::plain_write_allowed(db, &e2ee_config, &user, &channel, None).await?;

    let voice_channel = UserVoiceChannel::from_channel(&channel);
    if !is_in_voice_channel(&user.id, &voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    let text = clamp_caption(&data.text);
    // `min = 1` validation passes on whitespace; an all-blank line would clear
    // nothing and cost a fan-out.
    if text.trim().is_empty() {
        return Ok(EmptyResponse);
    }

    // The identity the SFU knows this speaker by — device-qualified on an
    // E2EE-capable call. Resolved SERVER-side, never taken from the request:
    // the client keys caption overlays by identity, so a caller-supplied one
    // would let anyone paint a caption onto another participant's tile.
    let identity = get_voice_participant_identity(channel.id(), &user.id).await?;

    let Some(members) = get_voice_channel_members(&voice_channel).await? else {
        return Ok(EmptyResponse);
    };

    // DIVERGENCE FROM THE SOUNDBOARD PATTERN, deliberate: soundboard uses
    // `.p(channel_id)`, whose authorization boundary is ViewChannel. A caption
    // is speech, so that would hand a live transcript of the call to every
    // text-channel lurker who never joined it. Fan to the CALL's members over
    // their private topics instead (the remote-control offer/decline shape).
    //
    // The speaker is skipped: their own client already renders its recognizer
    // output locally the moment it finalizes, so echoing it back would only
    // re-set an identical entry and reset its linger timer.
    for member_id in members {
        if member_id == user.id {
            continue;
        }

        EventV1::CallCaption {
            channel_id: channel.id().to_string(),
            identity: identity.clone(),
            user_id: user.id.clone(),
            text: text.clone(),
            lang: data.lang.clone(),
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
        events::client::EventV1,
        voice::{create_voice_state, delete_channel_voice_state, UserVoiceChannel},
        Channel, Database, PartialUser, User,
    };
    use rocket::http::{ContentType, Header, Status};

    /// A group of `owner` and `member`, stored directly and unmarked, with
    /// both in its call
    async fn group_call(
        harness: &TestHarness,
        owner: &User,
        member: &User,
    ) -> (Channel, UserVoiceChannel) {
        let group = Channel::Group {
            id: ulid::Ulid::new().to_string(),
            name: "Group".to_string(),
            owner: owner.id.clone(),
            description: None,
            recipients: vec![owner.id.clone(), member.id.clone()],
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            spoiler: false,
            // Groups are call-capable by default
            voice: None,
            e2ee_only: false,
        };
        harness.db.insert_channel(&group).await.expect("group");

        let uvc = UserVoiceChannel::from_channel(&group);
        for user in [owner, member] {
            create_voice_state(&uvc, &user.id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
        (group, uvc)
    }

    /// Set or clear a stored group's encrypted-only mark, raw: no route
    /// writes it after creation
    async fn mark_group_raw(db: &Database, channel_id: &str, marked: bool) {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::Group { e2ee_only, .. }) => *e2ee_only = marked,
                    other => panic!("expected a group, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "e2ee_only": marked } },
                    )
                    .await
                    .expect("raw mark");
                assert_eq!(result.matched_count, 1);
            }
        }
    }

    async fn set_e2ee_only(db: &Database, user: &User, e2ee_only: bool) {
        let mut user = user.clone();
        user.update(
            db,
            PartialUser {
                e2ee_only: Some(e2ee_only),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("e2ee_only");
    }

    /// POST one caption line; the status and the raw body
    async fn caption(
        harness: &TestHarness,
        token: &str,
        channel_id: &str,
        text: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/captions"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(serde_json::json!({ "text": text, "lang": "en-US" }).to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    fn assert_encryption_required(answer: &(Status, String), side: &str) {
        assert_eq!(answer.0, Status::Forbidden, "{}", answer.1);
        let error: serde_json::Value = serde_json::from_str(&answer.1).expect("error body");
        assert_eq!(error["type"], "EncryptionRequired", "{}", answer.1);
        assert_eq!(error["side"], side, "{}", answer.1);
    }

    /// Encrypted-only: a caption is readable text relayed through the
    /// server, so a marked group refuses it (`group`) and an unmarked one
    /// refuses an encrypted-only speaker (`sender`); neither reaches the
    /// other member. With the mark and the flag lifted a caption is relayed
    /// (the control, and the marker for the negatives: it is published after
    /// them on the same FIFO subscription).
    ///
    /// Control: the `plain_write_allowed` call removed → the first caption
    /// is relayed.
    // Shared runtime: live Redis voice state through the global pool (see
    // `util::test::rt`).
    #[test]
    fn caption_in_an_encrypted_only_group_is_refused() {
        crate::util::test::rt().block_on(caption_in_an_encrypted_only_group_is_refused_case())
    }

    async fn caption_in_an_encrypted_only_group_is_refused_case() {
        let mut harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, _, user_b) = harness.new_user().await;
        let (group, uvc) = group_call(&harness, &user_a, &user_b).await;

        mark_group_raw(&harness.db, group.id(), true).await;
        let marked = caption(&harness, &session_a.token, group.id(), "refused group").await;
        mark_group_raw(&harness.db, group.id(), false).await;

        set_e2ee_only(&harness.db, &user_a, true).await;
        let sender = caption(&harness, &session_a.token, group.id(), "refused sender").await;
        set_e2ee_only(&harness.db, &user_a, false).await;

        let allowed = caption(&harness, &session_a.token, group.id(), "relayed").await;

        assert_encryption_required(&marked, "group");
        assert_encryption_required(&sender, "sender");
        assert_eq!(allowed.0, Status::NoContent, "{}", allowed.1);

        let topic = format!("{}!", user_b.id);
        harness
            .wait_for_event(&topic, |event| match event {
                EventV1::CallCaption { text, .. } => text == "relayed",
                _ => false,
            })
            .await;
        harness.assert_no_buffered_event(&topic, |event| match event {
            EventV1::CallCaption { text, .. } => text != "relayed",
            _ => false,
        });

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }

    /// `only_enforced = false` lifts both refusals. Process-wide config, so
    /// nextest only (one process per test).
    #[test]
    fn caption_in_an_encrypted_only_group_is_relayed_when_not_enforced() {
        crate::util::test::rt()
            .block_on(caption_in_an_encrypted_only_group_is_relayed_when_not_enforced_case())
    }

    async fn caption_in_an_encrypted_only_group_is_relayed_when_not_enforced_case() {
        // Must run before the harness primes the config cache
        revolt_config::overwrite_config(|settings| {
            settings.features.e2ee.only_enforced = false;
        })
        .await;

        let mut harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, _, user_b) = harness.new_user().await;
        let (group, uvc) = group_call(&harness, &user_a, &user_b).await;
        mark_group_raw(&harness.db, group.id(), true).await;
        set_e2ee_only(&harness.db, &user_a, true).await;

        let allowed = caption(&harness, &session_a.token, group.id(), "relayed").await;
        assert_eq!(allowed.0, Status::NoContent, "{}", allowed.1);
        harness
            .wait_for_event(&format!("{}!", user_b.id), |event| match event {
                EventV1::CallCaption { text, .. } => text == "relayed",
                _ => false,
            })
            .await;

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }
}
