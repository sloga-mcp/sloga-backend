use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    voice::{remove_user_from_server_voice, VoiceClient},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Database, Message,
    RemovalIntention, ServerBan, User,
};
use revolt_models::v0;
use std::time::{Duration, SystemTime};

use revolt_database::events::client::EventV1;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};
use ulid::Ulid;
use validator::Validate;

/// # Ban User
///
/// Ban a user by their id.
#[openapi(tag = "Server Members")]
#[put("/<server>/bans/<target>", data = "<data>")]
pub async fn ban(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    server: Reference<'_>,
    target: Reference<'_>,
    data: Json<v0::DataBanCreate>,
) -> Result<Json<v0::ServerBan>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let server = server.as_server(db).await?;

    if target.id == user.id {
        return Err(create_error!(CannotRemoveYourself));
    }

    if target.id == server.owner {
        return Err(create_error!(InvalidOperation));
    }

    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::BanMembers)?;

    // The ban runs in this exact order (AFK S-3 D-2, P2-2):
    //
    // 1. The rank check, before anything is written, so a moderator who does
    //    not outrank a member target is refused with nothing persisted. The
    //    member read fails closed: only NotFound means "not a member". Any
    //    other read error refuses the ban before anything is written, so it
    //    can be retried, instead of skipping the rank check, persisting the
    //    ban and leaving the membership in place.
    // 2. The ban is persisted, BEFORE the membership is removed and before the
    //    eviction: an eviction error then answers an error with the ban
    //    already durable, instead of leaving a kick behind (S-3 F-4).
    // 3. The membership is removed, if the target is a member. A ban this
    //    request created is then recorded in the audit log, before the
    //    eviction, so an eviction error cannot lose the entry.
    // 4. The target is evicted from every call in the server, member or not.
    // 5. Their recent messages are deleted, if asked.
    //
    // A retried ban re-runs steps 3 to 5, which is how an eviction that failed
    // is completed: step 2 answers "already banned" as a success for that.
    // The retry writes no second audit entry: only a ban this request
    // created is recorded.
    let member = match target.as_member(db, &server.id).await {
        Ok(member) => Some(member),
        Err(error) if !matches!(error.error_type, ErrorType::NotFound) => return Err(error),
        Err(_) => None,
    };
    if let Some(member) = &member {
        if member.get_ranking(query.server_ref().as_ref().unwrap())
            <= query.get_member_rank().unwrap_or(i64::MIN)
        {
            return Err(create_error!(NotElevated));
        }
    }

    // "Already banned" is a success (P2-2): a duplicate insert errors on both
    // drivers, so a plain create would answer a retry with an error before it
    // could re-evict. The existing ban is returned as it is, with its original
    // reason. A create that fails because a concurrent ban won the insert
    // finds that ban on the second read; any other create failure finds
    // nothing there and is answered.
    //
    // The audit entry takes the BODY reason (plan audit M4: a ban reason may
    // run to 1024 characters, past the 512 the reason header allows), so no
    // reason header is read here. It is copied before the create consumes
    // it: trimmed, and blank means none. `newly_banned` is set only when this
    // request's create succeeded; an existing ban, or one a concurrent
    // request won the insert for (that request records its own), is not.
    let audit_reason = data
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(str::to_string);
    let mut newly_banned = false;
    let ban = match db.fetch_ban(&server.id, target.id).await {
        Ok(existing) => existing,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            match ServerBan::create(db, &server, target.id, data.reason).await {
                Ok(ban) => {
                    newly_banned = true;
                    ban
                }
                Err(error) => db
                    .fetch_ban(&server.id, target.id)
                    .await
                    .map_err(|_| error)?,
            }
        }
        Err(error) => return Err(error),
    };

    if let Some(member) = member {
        member
            .remove(db, &server, RemovalIntention::Ban, false)
            .await?;
    }

    // After the ban is durable and the member removed, before the eviction,
    // whose error is answered with the ban already standing. The purge
    // window is recorded only when a purge was asked for.
    if newly_banned {
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: server.id.clone(),
                actor: Some(user.id.clone()),
                action: AuditLogAction::MemberBanAdd,
                target: Some(target.id.to_string()),
                changes: data
                    .delete_message_seconds
                    .filter(|seconds| *seconds > 0)
                    .map(|seconds| {
                        AuditLogChange::new(
                            "delete_message_seconds",
                            None,
                            Some(AuditValue::Int(seconds)),
                        )
                    })
                    .into_iter()
                    .collect(),
                reason: audit_reason,
                ..Default::default()
            },
        )
        .await;
    }

    // Outside the member check (S-3 F-4): a hit-and-run spammer who already
    // left can still hold a connection. Every call in the server is reached,
    // not only the one the per-server pointer names (S-3 F-3).
    remove_user_from_server_voice(db, voice_client, &server, target.id).await?;

    // We do this outside the member check so we can sweep hit-and-run spammers who already left.
    if let Some(seconds) = data.delete_message_seconds {
        if seconds > 0 {
            let threshold_time = SystemTime::now() - Duration::from_secs(seconds as u64);

            // Threads and forum posts are never listed in `server.channels`.
            let channels = server.message_channel_ids(db).await?;
            Message::bulk_delete_by_author_since(db, &channels, target.id, threshold_time).await?;
        }
    }

    Ok(Json(ban.into()))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_node, delete_channel_voice_state,
            get_user_voice_channel_in_server, get_voice_channel_members, is_in_voice_channel,
            record_voice_connection, recorded_voice_connections, set_channel_node,
            UserVoiceChannel,
        },
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Channel, Member, Message,
        PartialMember, Server,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};

    // ---- behavior (needs RabbitMQ and Redis) ------------------------------
    //
    // Compile-only on a box without those services, like every other route
    // test: `TestHarness::new` connects to RabbitMQ and the voice state lives
    // in Redis. The eviction is observed through the ghost of an ended call:
    // a channel with NO node pinned, which `remove_user_from_server_voice`
    // reaches through the per-server pointer and tears down from the recorded
    // connections, with no SFU involved.

    /// A node name deliberately absent from `Revolt.toml`: an eviction
    /// addressed to it fails with `UnknownNode` before any network.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

    async fn voice_channel(harness: &TestHarness, server: &Server, name: &str) -> Channel {
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
                ..Default::default()
            },
            true,
        )
        .await
        .expect("voice channel")
    }

    /// A join as voice-ingress records it: the connection first, then the
    /// state, created only for the user's first connection.
    async fn join_recorded(uvc: &UserVoiceChannel, user_id: &str, sid: &str, identity: &str) {
        if record_voice_connection(uvc, user_id, sid, identity)
            .await
            .expect("record")
        {
            create_voice_state(uvc, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
    }

    /// Every trace of `user_id` in `uvc`: the recorded connections, `vc:`
    /// membership, `vc_members:` membership, and the per-server pointer when
    /// it names this channel.
    async fn voice_traces(
        uvc: &UserVoiceChannel,
        user_id: &str,
    ) -> (Vec<(String, String)>, bool, bool, bool) {
        let recorded = recorded_voice_connections(uvc, user_id)
            .await
            .expect("recorded read");
        let listed = is_in_voice_channel(user_id, uvc).await.expect("vc read");
        let member = get_voice_channel_members(uvc)
            .await
            .expect("members read")
            .is_some_and(|members| members.iter().any(|id| id == user_id));
        let pointer = get_user_voice_channel_in_server(
            user_id,
            uvc.server_id.as_deref().expect("a server channel"),
        )
        .await
        .expect("pointer read")
        .as_deref()
            == Some(uvc.id.as_str());
        (recorded, listed, member, pointer)
    }

    async fn assert_ghost_present(uvc: &UserVoiceChannel, user_id: &str, sids: usize) {
        let (recorded, listed, member, pointer) = voice_traces(uvc, user_id).await;
        assert!(
            recorded.len() == sids && listed && member && pointer,
            "the ghost of {} must be in place: recorded {:?}, vc {}, vc_members {}, pointer {}",
            user_id,
            recorded,
            listed,
            member,
            pointer
        );
    }

    async fn assert_ghost_cleared(uvc: &UserVoiceChannel, user_id: &str) {
        let (recorded, listed, member, pointer) = voice_traces(uvc, user_id).await;
        assert!(
            recorded.is_empty() && !listed && !member && !pointer,
            "the ghost of {} must be torn down, left: recorded {:?}, vc {}, vc_members {}, \
             pointer {}",
            user_id,
            recorded,
            listed,
            member,
            pointer
        );
    }

    async fn ban_user<'a>(
        harness: &'a TestHarness,
        token: &str,
        server_id: &str,
        target_id: &str,
        reason: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .put(format!("/servers/{server_id}/bans/{target_id}"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(serde_json::json!({ "reason": reason }).to_string())
            .dispatch()
            .await
    }

    async fn ban_answered(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        what: &str,
    ) -> v0::ServerBan {
        assert_eq!(response.status(), Status::Ok, "{what} must succeed");
        serde_json::from_str(&response.into_string().await.expect("a body"))
            .expect("the ban is returned")
    }

    async fn assert_rejected(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        status: Status,
        error_type: &str,
    ) {
        assert_eq!(response.status(), status);
        let body = response.into_string().await.unwrap_or_default();
        assert!(
            body.contains(error_type),
            "expected a {} error, got: {}",
            error_type,
            body
        );
    }

    /// Every audit log entry in the server, newest first. Unfiltered on
    /// purpose: a ban must write its one entry and nothing else.
    async fn audit_entries(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server_id, None, 50, None, None)
            .await
            .expect("the audit log reads")
    }

    /// A ban with the given JSON body.
    async fn ban_with<'a>(
        harness: &'a TestHarness,
        token: &str,
        server_id: &str,
        target_id: &str,
        body: serde_json::Value,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .put(format!("/servers/{server_id}/bans/{target_id}"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await
    }

    /// The one `member_ban_add` entry of `target_id`, asserting there is
    /// exactly one and that it names `actor_id` and no channel or count.
    fn ban_entry<'e>(
        entries: &'e [AuditLogEntry],
        actor_id: &str,
        target_id: &str,
    ) -> &'e AuditLogEntry {
        let matching: Vec<&AuditLogEntry> = entries
            .iter()
            .filter(|entry| entry.target.as_deref() == Some(target_id))
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "one audit entry per ban of {}: {:?}",
            target_id,
            entries
        );
        let entry = matching[0];
        assert_eq!(entry.action, AuditLogAction::MemberBanAdd, "{entry:?}");
        assert_eq!(entry.actor.as_deref(), Some(actor_id), "{entry:?}");
        assert_eq!(entry.channel, None, "{entry:?}");
        assert_eq!(entry.count, None, "{entry:?}");
        entry
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_repeated_ban_succeeds_and_evicts_again() {
        crate::util::test::rt().block_on(a_repeated_ban_succeeds_and_evicts_again_case())
    }

    /// AFK S-3 P2-2: banning a user who is already banned is a success that
    /// re-runs the eviction, so a ban whose eviction failed can be completed
    /// by retrying it. The duplicate insert errors on both drivers, which
    /// used to answer the retry with an error before it reached the eviction.
    /// The target is no longer a member on the second ban, so this also needs
    /// the eviction outside the member check. The existing ban is returned,
    /// its reason unchanged. Mutations: the create's error propagated with
    /// `?`; the eviction moved back inside the member check; the eviction
    /// removed.
    async fn a_repeated_ban_succeeds_and_evicts_again_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Ended").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_ban_first", &user_b.id).await;
        assert_ghost_present(&uvc, &user_b.id, 1).await;

        let response = ban_user(&harness, &session_a.token, &server.id, &user_b.id, "first").await;
        let ban = ban_answered(response, "the first ban").await;
        assert_eq!(ban.id.user, user_b.id);
        assert_eq!(ban.reason.as_deref(), Some("first"));
        assert_ghost_cleared(&uvc, &user_b.id).await;
        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(
            entries.len(),
            1,
            "the first ban is recorded once: {entries:?}"
        );
        assert_eq!(
            ban_entry(&entries, &user_a.id, &user_b.id)
                .reason
                .as_deref(),
            Some("first")
        );
        assert!(
            harness
                .db
                .fetch_member(&server.id, &user_b.id)
                .await
                .is_err(),
            "the banned target is no longer a member"
        );

        // The target reappears in the channel: a connection the first
        // eviction did not reach, as after an eviction that failed.
        join_recorded(
            &uvc,
            &user_b.id,
            "PA_ban_again",
            &format!("{}:DEV", user_b.id),
        )
        .await;
        assert_ghost_present(&uvc, &user_b.id, 1).await;

        let response = ban_user(&harness, &session_a.token, &server.id, &user_b.id, "second").await;
        let ban = ban_answered(response, "banning an already banned user").await;
        assert_eq!(ban.id.user, user_b.id);
        assert_eq!(
            ban.reason.as_deref(),
            Some("first"),
            "the existing ban is returned, not replaced"
        );
        assert_ghost_cleared(&uvc, &user_b.id).await;
        assert_eq!(
            harness
                .db
                .fetch_ban(&server.id, &user_b.id)
                .await
                .expect("the ban stands")
                .reason
                .as_deref(),
            Some("first")
        );
        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(
            entries.len(),
            1,
            "an already-banned retry must write no second audit entry: {entries:?}"
        );
        assert_eq!(
            ban_entry(&entries, &user_a.id, &user_b.id)
                .reason
                .as_deref(),
            Some("first"),
            "the one entry is the first ban's"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_moderator_not_above_the_target_cannot_ban_them() {
        crate::util::test::rt().block_on(a_moderator_not_above_the_target_cannot_ban_them_case())
    }

    /// AFK S-3 P2-2, step 1: the rank check precedes every write. A moderator
    /// holding BanMembers whose rank is not above the target's (the same
    /// role here) is refused with NotElevated, and nothing happened: no ban,
    /// the target still a member, their voice state untouched. Mutation: the
    /// rank check moved below the ban persist.
    async fn a_moderator_not_above_the_target_cannot_ban_them_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_m, session_m, user_m) = harness.new_user().await; // moderator
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;

        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::BanMembers as i64,
                    d: 0,
                }),
            )
            .await;
        for user in [&user_m, &user_b] {
            let (mut member, _) = Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
            member
                .update(
                    &harness.db,
                    PartialMember {
                        roles: Some(vec![role.id.clone()]),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("role");
        }

        let channel = voice_channel(&harness, &server, "Ended").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_rank", &user_b.id).await;

        let response = ban_user(&harness, &session_m.token, &server.id, &user_b.id, "rank").await;
        assert_rejected(response, Status::Forbidden, "NotElevated").await;

        let ban = harness.db.fetch_ban(&server.id, &user_b.id).await;
        assert!(
            matches!(&ban, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
            "a refused ban must persist nothing: {:?}",
            ban
        );
        assert!(
            harness
                .db
                .fetch_member(&server.id, &user_b.id)
                .await
                .is_ok(),
            "a refused ban must leave the target a member"
        );
        assert_ghost_present(&uvc, &user_b.id, 1).await;
        let entries = audit_entries(&harness, &server.id).await;
        assert!(
            entries.is_empty(),
            "a ban refused for rank must record nothing: {entries:?}"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_non_member_is_banned_and_evicted() {
        crate::util::test::rt().block_on(a_non_member_is_banned_and_evicted_case())
    }

    /// AFK S-3 F-4: a hit-and-run user who is not a member but still holds a
    /// connection in one of the server's calls is banned AND evicted. The
    /// eviction used to sit inside the member check. Mutations: the eviction
    /// moved back inside the member check; the eviction removed.
    async fn a_non_member_is_banned_and_evicted_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // never a member
        let (server, _channels) = harness.new_server(&user_a).await;

        let channel = voice_channel(&harness, &server, "Ended").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_hit_and_run", &user_b.id).await;
        assert_ghost_present(&uvc, &user_b.id, 1).await;
        assert!(harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .is_err());

        let response = ban_user(&harness, &session_a.token, &server.id, &user_b.id, "spam").await;
        let ban = ban_answered(response, "banning a non-member").await;
        assert_eq!(ban.id.user, user_b.id);
        assert_ghost_cleared(&uvc, &user_b.id).await;
        assert!(harness.db.fetch_ban(&server.id, &user_b.id).await.is_ok());

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_failed_eviction_leaves_the_ban_durable_and_a_retry_evicts() {
        crate::util::test::rt()
            .block_on(a_failed_eviction_leaves_the_ban_durable_and_a_retry_evicts_case())
    }

    /// AFK S-3 F-4 + P2-2: the ban is persisted before the eviction, so an
    /// eviction that fails answers an error with the ban already standing,
    /// never a kick. The failed eviction tears nothing down. Once the cause
    /// is gone, retrying the ban evicts. ABSENT_NODE makes the eviction fail
    /// with UnknownNode before any network. Mutation: the ban persist moved
    /// back below the eviction.
    async fn a_failed_eviction_leaves_the_ban_durable_and_a_retry_evicts_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Live").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_live", &user_b.id).await;
        set_channel_node(channel.id(), ABSENT_NODE)
            .await
            .expect("node");

        let response = ban_user(&harness, &session_a.token, &server.id, &user_b.id, "live").await;
        assert_rejected(response, Status::BadRequest, "UnknownNode").await;

        assert!(
            harness.db.fetch_ban(&server.id, &user_b.id).await.is_ok(),
            "the ban must be durable before the eviction runs"
        );
        assert!(
            harness
                .db
                .fetch_member(&server.id, &user_b.id)
                .await
                .is_err(),
            "the membership is removed before the eviction runs"
        );
        assert_ghost_present(&uvc, &user_b.id, 1).await;
        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(
            entries.len(),
            1,
            "the audit entry is written before the eviction that failed: {entries:?}"
        );
        assert_eq!(
            ban_entry(&entries, &user_a.id, &user_b.id)
                .reason
                .as_deref(),
            Some("live")
        );

        // The call ended: the retry reaches the ghost with no SFU involved.
        delete_channel_node(channel.id()).await.expect("node gone");
        let response = ban_user(&harness, &session_a.token, &server.id, &user_b.id, "retry").await;
        ban_answered(response, "retrying the ban").await;
        assert_ghost_cleared(&uvc, &user_b.id).await;
        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(
            entries.len(),
            1,
            "the retry that completes the eviction records no second ban: {entries:?}"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // ---- the message purge reaches threads and forum posts -----------------
    //
    // Threads and forum posts hold messages but are never listed in
    // `server.channels`, so a purge scoped to that list left everything the
    // target wrote in them behind, a forum post's starter included.

    async fn ban_user_deleting<'a>(
        harness: &'a TestHarness,
        token: &str,
        server_id: &str,
        target_id: &str,
        delete_message_seconds: i64,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .put(format!("/servers/{server_id}/bans/{target_id}"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(
                serde_json::json!({
                    "reason": "purge",
                    "delete_message_seconds": delete_message_seconds,
                })
                .to_string(),
            )
            .dispatch()
            .await
    }

    /// A message stored as it is, with no send path and no events.
    #[allow(clippy::disallowed_methods)] // a test fixture, stored directly like test_fixtures does
    async fn stored_message(harness: &TestHarness, id: &str, channel: &str, author: &str) {
        harness
            .db
            .insert_message(&Message {
                id: id.to_string(),
                channel: channel.to_string(),
                author: author.to_string(),
                content: Some("purge check".to_string()),
                ..Default::default()
            })
            .await
            .expect("message");
    }

    struct PurgeFixture {
        owner_token: String,
        server_id: String,
        target_id: String,
        thread_id: String,
        post_id: String,
        /// The target's messages, each with where it was written.
        target_messages: Vec<(&'static str, String)>,
        /// The owner's message in the thread, never the target's to lose.
        owner_message: String,
    }

    /// An owner and a member target. The server holds a text channel with a
    /// thread under it, and a forum with a post, both opened by the target.
    /// The target wrote in the text channel, the thread and the post (the
    /// post's starter, whose id is the post's id, as `forum_post_create`
    /// stores it, and a reply); the owner wrote in the thread. All of it is
    /// recent. Only the target's messages are counted: `create_thread` also
    /// posts a system message into the text channel.
    async fn purge_fixture(harness: &TestHarness) -> PurgeFixture {
        let (_a, session_a, owner) = harness.new_user().await;
        let (_b, _session_b, target) = harness.new_user().await;
        let (mut server, _channels) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &target, None)
            .await
            .expect("member");

        // `&mut server` for both: a second create from a stale copy would
        // write the server's channel list without the first channel.
        let text = Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: "purge-text".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("text channel");
        let forum = Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "purge-forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum");
        let thread = Channel::create_thread(
            &harness.db,
            &text,
            &target,
            None,
            v0::DataCreateThread {
                name: "purge-thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("thread");
        let post = Channel::create_forum_post(
            &harness.db,
            &forum,
            &target,
            "purge-post".to_string(),
            vec![],
            None,
        )
        .await
        .expect("post");

        let stored = harness.db.fetch_server(&server.id).await.expect("`Server`");
        for listed in [text.id(), forum.id()] {
            assert!(
                stored.channels.iter().any(|id| id == listed),
                "the fixture's channels are the server's: {:?}",
                stored.channels
            );
        }
        for unlisted in [thread.id(), post.id()] {
            assert!(
                !stored.channels.iter().any(|id| id == unlisted),
                "a thread or post is never in `server.channels`: {:?}",
                stored.channels
            );
        }

        let mut target_messages = vec![];
        for (place, id, channel) in [
            ("the text channel", ulid::Ulid::new().to_string(), text.id()),
            ("the thread", ulid::Ulid::new().to_string(), thread.id()),
            ("the post's starter", post.id().to_string(), post.id()),
            ("the post", ulid::Ulid::new().to_string(), post.id()),
        ] {
            stored_message(harness, &id, channel, &target.id).await;
            target_messages.push((place, id));
        }
        let owner_message = ulid::Ulid::new().to_string();
        stored_message(harness, &owner_message, thread.id(), &owner.id).await;

        PurgeFixture {
            owner_token: session_a.token,
            server_id: server.id,
            target_id: target.id,
            thread_id: thread.id().to_string(),
            post_id: post.id().to_string(),
            target_messages,
            owner_message,
        }
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_ban_that_deletes_messages_reaches_threads_and_forum_posts() {
        crate::util::test::rt()
            .block_on(a_ban_that_deletes_messages_reaches_threads_and_forum_posts_case())
    }

    /// A ban with `delete_message_seconds` deletes the target's recent
    /// messages in the text channel, in a thread under it, and in a forum
    /// post, the post's starter included. The owner's message in the thread
    /// stays, and so do the thread and the post themselves. Mutation: the
    /// purge scoped back to `&server.channels`, which deletes only the
    /// message in the text channel.
    async fn a_ban_that_deletes_messages_reaches_threads_and_forum_posts_case() {
        let harness = TestHarness::new().await;
        let fixture = purge_fixture(&harness).await;

        let response = ban_user_deleting(
            &harness,
            &fixture.owner_token,
            &fixture.server_id,
            &fixture.target_id,
            3600,
        )
        .await;
        ban_answered(response, "a ban that deletes messages").await;

        for (place, id) in &fixture.target_messages {
            let read = harness.db.fetch_message(id).await;
            assert!(
                matches!(&read, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
                "W3A: the ban must delete the target's message in {}, found {:?}",
                place,
                read
            );
        }
        harness
            .db
            .fetch_message(&fixture.owner_message)
            .await
            .expect("the owner's message in the thread survives the target's ban");
        for (what, id) in [("thread", &fixture.thread_id), ("post", &fixture.post_id)] {
            // Explicit arguments: in this edition-2018 crate a lone literal
            // panic message is printed as it is, braces and all.
            harness.db.fetch_channel(id).await.unwrap_or_else(|error| {
                panic!(
                    "the purge deletes messages only, the {} stays: {:?}",
                    what, error
                )
            });
        }
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_ban_without_delete_message_seconds_keeps_every_message() {
        crate::util::test::rt()
            .block_on(a_ban_without_delete_message_seconds_keeps_every_message_case())
    }

    /// A ban that does not ask for a purge deletes nothing, in a thread or a
    /// forum post as anywhere else. Mutation: the purge run unconditionally.
    async fn a_ban_without_delete_message_seconds_keeps_every_message_case() {
        let harness = TestHarness::new().await;
        let fixture = purge_fixture(&harness).await;

        let response = ban_user(
            &harness,
            &fixture.owner_token,
            &fixture.server_id,
            &fixture.target_id,
            "no purge",
        )
        .await;
        ban_answered(response, "a ban without a purge").await;

        for (place, id) in &fixture.target_messages {
            let read = harness.db.fetch_message(id).await;
            assert!(
                read.is_ok(),
                "a ban without delete_message_seconds must keep the target's message in {}: \
                 {:?}",
                place,
                read
            );
        }
        harness
            .db
            .fetch_message(&fixture.owner_message)
            .await
            .expect("the owner's message in the thread");
    }

    // ---- the audit log entry (moderation slice 1) ---------------------------
    //
    // A ban this request created writes one `member_ban_add` entry: the
    // banned user as the target, the BODY reason (bans read no reason header,
    // plan audit M4), and the purge window when one was asked for. An
    // already-banned retry and every refusal write nothing; the retry is
    // covered in the voice tests above.

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_ban_records_its_reason_and_purge_window() {
        crate::util::test::rt().block_on(a_ban_records_its_reason_and_purge_window_case())
    }

    /// The entry names the moderator, the target and the body reason, and
    /// carries the purge window as an Int. Mutations: the record removed;
    /// the purge window dropped from the changes or recorded as a String.
    async fn a_ban_records_its_reason_and_purge_window_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let response =
            ban_user_deleting(&harness, &session_a.token, &server.id, &user_b.id, 3600).await;
        ban_answered(response, "a ban that deletes messages").await;

        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "one ban, one audit entry: {entries:?}");
        let entry = ban_entry(&entries, &user_a.id, &user_b.id);
        assert_eq!(entry.reason.as_deref(), Some("purge"));
        assert_eq!(
            entry.changes,
            vec![AuditLogChange::new(
                "delete_message_seconds",
                None,
                Some(AuditValue::Int(3600))
            )]
        );
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_blank_reason_and_no_purge_record_neither() {
        crate::util::test::rt().block_on(a_blank_reason_and_no_purge_record_neither_case())
    }

    /// The reason is trimmed and a blank one is recorded as none; a purge
    /// window that is absent or zero adds no change. Mutations: the trim
    /// dropped; the blank filter dropped; the `> 0` filter dropped.
    async fn a_blank_reason_and_no_purge_record_neither_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (server, _channels) = harness.new_server(&user_a).await;

        let mut cases = vec![];
        for (body, expected) in [
            (serde_json::json!({ "reason": "" }), None),
            (
                serde_json::json!({ "reason": " \t\n ", "delete_message_seconds": 0 }),
                None,
            ),
            (serde_json::json!({}), None),
            (serde_json::json!({ "reason": "  spam  " }), Some("spam")),
        ] {
            let (_t, _session_t, target) = harness.new_user().await;
            let response = ban_with(&harness, &session_a.token, &server.id, &target.id, body).await;
            ban_answered(response, "a ban with a blank or padded reason").await;
            cases.push((target.id, expected));
        }

        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), cases.len(), "one entry per ban: {entries:?}");
        for (target_id, expected) in &cases {
            let entry = ban_entry(&entries, &user_a.id, target_id);
            assert_eq!(entry.reason.as_deref(), *expected, "{entry:?}");
            assert!(
                entry.changes.is_empty(),
                "no purge window was asked for: {entry:?}"
            );
        }
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_ban_records_the_body_reason_up_to_1024_characters() {
        crate::util::test::rt().block_on(a_ban_records_the_body_reason_up_to_1024_characters_case())
    }

    /// Plan audit M4: the ban's reason comes from its body, which allows
    /// 1024 characters. A 1024-character reason is banned and recorded in
    /// full, and a reason header sent alongside is not read. A 1025-character
    /// reason fails the body validation with nothing written. Mutations: the
    /// reason header guard added to the route (its 512 cap answers 400); the
    /// reason taken from the header.
    async fn a_ban_records_the_body_reason_up_to_1024_characters_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;

        let response = ban_with(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "reason": "x".repeat(1025) }),
        )
        .await;
        assert_rejected(response, Status::BadRequest, "FailedValidation").await;
        let ban = harness.db.fetch_ban(&server.id, &user_b.id).await;
        assert!(
            matches!(&ban, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
            "an over-long reason must persist nothing: {:?}",
            ban
        );
        let entries = audit_entries(&harness, &server.id).await;
        assert!(
            entries.is_empty(),
            "an invalid ban records nothing: {entries:?}"
        );

        let reason = "x".repeat(1024);
        let response = harness
            .client
            .put(format!("/servers/{}/bans/{}", server.id, user_b.id))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session_a.token.to_string()))
            .header(Header::new("X-Audit-Log-Reason", "header%20reason"))
            .body(serde_json::json!({ "reason": reason }).to_string())
            .dispatch()
            .await;
        ban_answered(response, "a ban with a 1024-character reason").await;

        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "one ban, one audit entry: {entries:?}");
        assert_eq!(
            ban_entry(&entries, &user_a.id, &user_b.id)
                .reason
                .as_deref(),
            Some(reason.as_str()),
            "the body reason is recorded in full and the header is not read"
        );
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn banning_the_owner_is_refused_and_records_nothing() {
        crate::util::test::rt().block_on(banning_the_owner_is_refused_and_records_nothing_case())
    }

    /// The owner guard: a moderator holding BanMembers who tries to ban the
    /// server owner is refused with InvalidOperation, no ban is persisted
    /// and nothing is recorded. Mutation: the owner guard removed.
    async fn banning_the_owner_is_refused_and_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_m, session_m, user_m) = harness.new_user().await; // moderator
        let (server, _channels) = harness.new_server(&user_a).await;

        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::BanMembers as i64,
                    d: 0,
                }),
            )
            .await;
        let (mut member, _) = Member::create(&harness.db, &server, &user_m, None)
            .await
            .expect("member");
        member
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("role");

        let response = ban_user(&harness, &session_m.token, &server.id, &user_a.id, "coup").await;
        assert_rejected(response, Status::BadRequest, "InvalidOperation").await;

        let ban = harness.db.fetch_ban(&server.id, &user_a.id).await;
        assert!(
            matches!(&ban, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
            "the owner must never be banned: {:?}",
            ban
        );
        let entries = audit_entries(&harness, &server.id).await;
        assert!(
            entries.is_empty(),
            "a refused ban of the owner records nothing: {entries:?}"
        );
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_ban_refused_for_permission_or_self_records_nothing() {
        crate::util::test::rt()
            .block_on(a_ban_refused_for_permission_or_self_records_nothing_case())
    }

    /// A member without BanMembers is refused with MissingPermission, and a
    /// ban of oneself with CannotRemoveYourself; neither persists a ban or
    /// records anything. Mutation: the record moved above the permission
    /// check.
    async fn a_ban_refused_for_permission_or_self_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_p, session_p, user_p) = harness.new_user().await; // no BanMembers
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        for user in [&user_p, &user_b] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }

        let response = ban_user(&harness, &session_p.token, &server.id, &user_b.id, "no").await;
        assert_rejected(response, Status::Forbidden, "MissingPermission").await;
        let response = ban_user(&harness, &session_a.token, &server.id, &user_a.id, "me").await;
        assert_rejected(response, Status::BadRequest, "CannotRemoveYourself").await;

        for banned in [&user_b.id, &user_a.id] {
            let ban = harness.db.fetch_ban(&server.id, banned).await;
            assert!(
                matches!(&ban, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
                "a refused ban must persist nothing: {:?}",
                ban
            );
        }
        let entries = audit_entries(&harness, &server.id).await;
        assert!(
            entries.is_empty(),
            "a refused ban records nothing: {entries:?}"
        );
    }

    // ---- the ban's order, pinned on its text (AFK S-3 P2-2) ----------------

    /// `ban`'s body, comment lines dropped and whitespace collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("ban_create.rs");
        let at = SOURCE
            .find("pub async fn ban(")
            .expect("the route is defined");
        let open = at + SOURCE[at..].find('\u{7b}').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        SOURCE[open..=close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// How many blocks enclose `at` in `body`, the body's own braces
    /// included: 1 is a statement of the route itself, under no condition.
    fn depth_at(body: &str, at: usize) -> usize {
        body[..at].chars().fold(0usize, |depth, ch| match ch {
            '\u{7b}' => depth + 1,
            '\u{7d}' => depth - 1,
            _ => depth,
        })
    }

    const RANK: &str = "return Err(create_error!(NotElevated));";
    const FETCH: &str = "let ban = match db.fetch_ban(&server.id, target.id).await \u{7b}";
    const CREATE: &str = "ServerBan::create(db, &server, target.id, data.reason).await";
    const REMOVE: &str = ".remove(db, &server, RemovalIntention::Ban, false) .await?;";
    const EVICT: &str =
        "remove_user_from_server_voice(db, voice_client, &server, target.id).await?;";
    const PURGE: &str = "Message::bulk_delete_by_author_since(";

    /// AFK S-3 D-2 / P2-2: rank check, ban persisted, membership removed,
    /// eviction, message delete, in that order, each exactly once, and the
    /// single-pointer removal gone. Mutations: the rank check moved below the
    /// persist; the persist moved back to the end; the eviction moved before
    /// the membership removal or removed.
    #[test]
    fn the_ban_runs_its_steps_in_order() {
        let body = route_body();
        let mut last = 0;
        for needle in [RANK, FETCH, CREATE, REMOVE, EVICT, PURGE] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the ban must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        for banned in [
            "get_user_voice_channel_in_server(",
            "remove_user_from_voice_channel(",
        ] {
            assert!(
                !body.contains(banned),
                "the ban must not call `{}`: {}",
                banned,
                body
            );
        }
    }

    /// AFK S-3 F-4: the eviction is a statement of the route itself, under no
    /// condition, so a target who is not a member is evicted too. The rank
    /// check and the membership removal are the ones under the member check.
    /// Mutation: the eviction moved back inside the member check.
    #[test]
    fn the_ban_evicts_members_and_non_members_alike() {
        let body = route_body();
        let at = body.find(EVICT).expect("the ban evicts");
        assert_eq!(
            depth_at(&body, at),
            1,
            "the eviction must not sit inside any block: {body}"
        );
        assert!(
            depth_at(&body, body.find(REMOVE).expect("the ban removes")) > 1,
            "the membership removal is conditional on a member: {}",
            body
        );
    }

    /// AFK S-3 P2-2: an existing ban is the answer, not an error, and a
    /// create that loses the insert race to a concurrent ban answers that
    /// ban. The race arm cannot be driven deterministically through the
    /// route, so it is held here on its text. Mutations: the create's error
    /// returned without the second read; the existing ban's arm removed.
    /// The create's `Ok` arm also sets `newly_banned` (moderation slice 1),
    /// which only that arm may do: see
    /// `the_ban_is_recorded_once_between_the_removal_and_the_eviction`.
    #[test]
    fn an_existing_ban_is_the_answer() {
        const EXISTING: &str = "Ok(existing) => existing,";
        const ABSENT: &str =
            "Err(error) if matches!(error.error_type, ErrorType::NotFound) => \u{7b}";
        const RACE: &str = "match ServerBan::create(db, &server, target.id, data.reason).await \
             \u{7b} Ok(ban) => \u{7b} newly_banned = true; ban \u{7d} Err(error) => db \
             .fetch_ban(&server.id, target.id) .await .map_err(|_| error)?, \u{7d}";
        const OTHER: &str = "Err(error) => return Err(error), \u{7d};";
        const ANSWER: &str = "Ok(Json(ban.into()))";

        let body = route_body();
        let mut last = 0;
        for needle in [FETCH, EXISTING, ABSENT, RACE, OTHER, ANSWER] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the ban must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        assert_eq!(
            body.matches("ServerBan::create(").count(),
            1,
            "one create, inside the not-found arm: {body}"
        );
    }

    /// Moderation slice 1: the `member_ban_add` entry is written once, and
    /// only for a ban this request created: `newly_banned` is declared false
    /// before the ban is read and set only in the create's `Ok` arm, so an
    /// already-banned retry and a create that lost the insert race to a
    /// concurrent ban (which records its own) write nothing. It is written
    /// after the membership removal and before the eviction, whose error is
    /// answered with the ban already durable. The route reads no reason
    /// header: the reason is the body's (plan audit M4). Mutations: the
    /// record moved below the eviction; the `newly_banned` guard dropped; the
    /// flag set in the not-found arm before the create; an `AuditLogReason`
    /// guard added to the route.
    #[test]
    fn the_ban_is_recorded_once_between_the_removal_and_the_eviction() {
        const FLAG: &str = "let mut newly_banned = false;";
        const SET: &str = "Ok(ban) => \u{7b} newly_banned = true; ban \u{7d}";
        const GUARD: &str = "if newly_banned \u{7b} AuditLogEntry::record(";
        const ACTION: &str = "action: AuditLogAction::MemberBanAdd,";

        let body = route_body();
        for needle in [
            FLAG,
            SET,
            GUARD,
            ACTION,
            "newly_banned = true;",
            "AuditLogEntry::record(",
        ] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the ban must carry `{needle}` exactly once: {body}"
            );
        }
        let mut last = 0;
        for needle in [FLAG, FETCH, CREATE, SET, REMOVE, GUARD, EVICT] {
            let at = body.find(needle).expect("counted above or by the step pin");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        assert_eq!(
            depth_at(&body, body.find(GUARD).expect("counted above")),
            1,
            "the record's guard is a statement of the route itself: {body}"
        );

        const SOURCE: &str = include_str!("ban_create.rs");
        let route = &SOURCE[SOURCE
            .find("pub async fn ban(")
            .expect("the route is defined")
            ..SOURCE
                .find("#[cfg(test)]")
                .expect("the tests follow the route")];
        assert!(
            !route.contains("AuditLogReason"),
            "a ban's reason is its body's; no reason header is read (plan audit M4)"
        );
    }

    /// AFK S-3 P2-2, step 1 fails closed: only a NotFound member read means
    /// "not a member". Any other read error returns before the ban is
    /// persisted, so a database failure can no longer skip the rank check,
    /// persist the ban and leave the membership in place. A member read that
    /// fails for any other reason cannot be forced through the route on
    /// either driver without touching the database crate, so this is held on
    /// its text. Mutations: the read turned back into `.ok()` or an
    /// `if let Ok(`; the non-NotFound arm mapped to `None`; the guard dropped.
    #[test]
    fn a_failed_member_read_refuses_the_ban() {
        const READ: &str = "let member = match target.as_member(db, &server.id).await \u{7b} \
             Ok(member) => Some(member), Err(error) if !matches!(error.error_type, \
             ErrorType::NotFound) => return Err(error), Err(_) => None, \u{7d};";

        let body = route_body();
        assert_eq!(
            body.matches("as_member(").count(),
            1,
            "the ban reads the member once: {body}"
        );
        assert_eq!(
            body.matches(READ).count(),
            1,
            "the member read must map only NotFound to None and return any \
             other error: {}",
            body
        );
        for banned in [".ok()", "if let Ok("] {
            assert!(
                !body.contains(banned),
                "the ban must not swallow an error with `{}`: {}",
                banned,
                body
            );
        }
        assert_eq!(
            body.matches("=> None").count(),
            1,
            "only the not-found arm maps to None: {body}"
        );

        let read = body.find(READ).expect("counted above");
        assert_eq!(
            depth_at(&body, read),
            1,
            "the member read must not sit inside any block: {body}"
        );
        for later in [RANK, FETCH, CREATE] {
            let at = body.find(later).expect("pinned by the_ban_runs_its_steps_in_order");
            assert!(
                read < at,
                "the member read must return its error before `{}`: {}",
                later,
                body
            );
        }
    }

    /// The purge is scoped to every channel that holds the server's
    /// messages, threads and forum posts included, read once, after the
    /// eviction, inside the same block as the purge, so a ban that asks for
    /// no purge reads nothing more. The purge is passed exactly those
    /// channels, and `channels` is bound once, so neither an empty list nor
    /// a shadowing binding can stand in for them. `server.channels` lists
    /// top-level channels only and must not scope it. Mutations: the purge
    /// scoped back to `&server.channels`, with or without the
    /// `message_channel_ids` read; the purge passed `&[]`; a shadowing
    /// `let channels = vec![];`; the read moved out of the `seconds > 0`
    /// block.
    #[test]
    fn the_purge_is_scoped_to_threads_and_posts_too() {
        const SCOPE: &str = "let channels = server.message_channel_ids(db).await?;";
        const SCOPED_PURGE: &str = "Message::bulk_delete_by_author_since(db, &channels, \
             target.id, threshold_time).await?;";

        let body = route_body();
        assert_eq!(
            body.matches(SCOPE).count(),
            1,
            "W3A: the purge must read its channels with `{SCOPE}` exactly once: {body}"
        );
        assert_eq!(
            body.matches("let channels =").count(),
            1,
            "W3A: `channels` must be bound once, by the read, never shadowed: {body}"
        );
        assert_eq!(
            body.matches(SCOPED_PURGE).count(),
            1,
            "W3A: the purge must be passed the channels it read: `{SCOPED_PURGE}`: {body}"
        );
        let at = body.find(SCOPE).expect("counted above");
        let evict = body.find(EVICT).expect("the ban evicts");
        let purge = body.find(PURGE).expect("the ban purges");
        assert!(
            evict < at && at < purge,
            "W3A: the purge's channels are read after the eviction and before the purge: {}",
            body
        );
        assert!(
            depth_at(&body, at) > 1,
            "W3A: the purge's channels are read only when a purge is asked for: {}",
            body
        );
        assert_eq!(
            depth_at(&body, at),
            depth_at(&body, purge),
            "W3A: the purge's channels are read in the purge's own block: {body}"
        );
        assert!(
            !body.contains("server.channels"),
            "W3A: `server.channels` misses threads and forum posts and must not scope \
             the purge: {}",
            body
        );
    }
}
