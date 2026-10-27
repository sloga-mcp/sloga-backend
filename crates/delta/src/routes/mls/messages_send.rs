use std::collections::HashMap;
use std::sync::Mutex;

use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, is_valid_device_id, Database, E2EEContentType, E2EEEnvelope, MlsGroup,
    Session, User, E2EE_PROTOCOL_VERSION,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;
use ulid::Ulid;

use crate::routes::e2ee::{MAX_QUEUE_BYTES, MAX_QUEUE_DEPTH};

use super::{encoded_len, GroupDispatch, CTL_BURST, CTL_INTERVAL_SECONDS, MAX_MLS_CTL_RAW_SIZE};

/// In-memory per-(group, sender-user) ctl rate limiter (plan §3.4 fold
/// ME-5): a legitimate announce is ~once per interlude plus one re-announce
/// per epoch change, so a small burst budget suffices. A ctl flood must
/// never crowd commit envelopes out of the per-recipient mailbox budgets.
/// Process-local state is sufficient — delta is a single logical process
/// and the limit is an abuse bound, not an accounting guarantee.
static CTL_SENDS: Mutex<Option<HashMap<String, Vec<Timestamp>>>> = Mutex::new(None);

/// Returns `Err(InSlowmode)` when the (group, user) pair exceeded
/// `CTL_BURST` sends within the trailing `CTL_INTERVAL_SECONDS` window.
fn ctl_rate_limit(group_id: &str, user_id: &str) -> Result<()> {
    let now = Timestamp::now_utc();
    let key = format!("{group_id}:{user_id}");
    let mut guard = CTL_SENDS.lock().expect("ctl rate limiter poisoned");
    let map = guard.get_or_insert_with(HashMap::new);

    // Drop expired windows globally so the map cannot grow unbounded across
    // many groups/users (calls are ephemeral).
    map.retain(|_, sends| {
        sends.retain(|sent| {
            now.duration_since(*sent).whole_seconds() < CTL_INTERVAL_SECONDS
        });
        !sends.is_empty()
    });

    let sends = map.entry(key).or_default();
    if sends.len() >= CTL_BURST {
        let oldest = sends[0];
        let retry_after =
            CTL_INTERVAL_SECONDS - now.duration_since(oldest).whole_seconds();
        return Err(create_error!(InSlowmode {
            retry_after: retry_after.max(1) as u64
        }));
    }
    sends.push(now);
    Ok(())
}

/// # Send MLS Application Message
///
/// Relay an opaque MLS application message (the §3.4 downgrade
/// ctl-announce) to every member device of the group except the sender's.
/// The ciphertext is group-encrypted and group-authenticated — the trust
/// decision is each receiver's native verification of the sender leaf; the
/// server only enforces membership, size, and rate.
///
/// Never advances an epoch, never arbitrates: this is NOT the commits pipe.
/// Sender identity is stamped server-side from the session (invariant 5).
///
/// Call groups only: a protected channel's Text group is refused with
/// `InvalidOperation` (design §7.2), so nothing of a Text group ever goes
/// out through this pipe.
#[openapi(tag = "MLS")]
#[post("/groups/<group_id>/messages", data = "<data>")]
pub async fn send_message(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    data: Json<v0::DataSendMlsMessage>,
) -> Result<EmptyResponse> {
    // Kind dispatch comes first (decision 1 (W2)); a Call group goes on
    // through the checks below, unchanged
    match super::dispatch_group(db, &group_id).await? {
        GroupDispatch::CallOrUnknown(None) => {
            return super::as_unknown_group(db, &user, Some(&session)).await;
        }
        GroupDispatch::Text(group) => {
            return refuse_text_group(db, &user, &session, &group).await;
        }
        GroupDispatch::CallOrUnknown(Some(_)) => {}
    }

    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();

    if !is_valid_device_id(&data.device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    if data.ciphertext.is_empty() || data.ciphertext.len() > encoded_len(MAX_MLS_CTL_RAW_SIZE) {
        return Err(create_error!(FailedValidation {
            error: "ctl ciphertext empty or over size cap".to_string()
        }));
    }

    // The sending session must be bound to the registered device
    let identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "sending device is not registered".to_string()
            })
        })?;
    identity.assert_bound_session(&session.id)?;

    // Group must exist, be open, its channel accessible — and the sending
    // DEVICE must be a member (user-level auth + device membership: only a
    // member can mint decryptable group ciphertext anyway; this check just
    // refuses obvious garbage early).
    let (group, _channel) = super::fetch_authorized_group(db, &user, &group_id).await?;
    if !group.open {
        return Err(create_error!(NotFound));
    }
    let is_member_device = group
        .members
        .iter()
        .any(|member| member.user_id == user.id && member.device_id == data.device_id);
    if !is_member_device {
        return Err(create_error!(FailedValidation {
            error: "sending device is not a member of this group".to_string()
        }));
    }

    ctl_rate_limit(&group.id, &user.id)?;

    // Fan out to every member device except the sender's, through the same
    // per-recipient mailbox budgets as commits (an over-budget recipient is
    // skipped — availability-only; a lost ctl converges via mix detection).
    let mut accepted: Vec<E2EEEnvelope> = Vec::new();
    for member in &group.members {
        if member.user_id == user.id && member.device_id == data.device_id {
            continue;
        }

        let depth = db
            .count_e2ee_envelopes(&member.user_id, &member.device_id)
            .await?;
        let bytes = db
            .sum_e2ee_envelope_bytes(&member.user_id, &member.device_id)
            .await?;
        if depth >= MAX_QUEUE_DEPTH
            || bytes + data.ciphertext.len() as u64 > MAX_QUEUE_BYTES
        {
            log::debug!(
                "mls ctl fan-out skipped for {}:{} (queue depth {depth}, bytes {bytes})",
                member.user_id,
                member.device_id
            );
            continue;
        }

        accepted.push(E2EEEnvelope {
            id: Ulid::new().to_string(),
            recipient_user_id: member.user_id.clone(),
            recipient_device_id: member.device_id.clone(),
            // Sender stamped from the session, never from the payload
            sender_user_id: user.id.clone(),
            sender_device_id: data.device_id.clone(),
            protocol_version: E2EE_PROTOCOL_VERSION,
            // Ctl messages carry no per-group ordering: sequence stays 0 and
            // epoch is None — receivers must never park on them
            sequence: 0,
            ciphertext: data.ciphertext.clone(),
            timestamp: Timestamp::now_utc(),
            content_type: E2EEContentType::MlsCtl,
            group_id: Some(group.id.clone()),
            epoch: None,
            committer: None,
            added: vec![],
            removed: vec![],
            rejoin_intents: vec![],
            removed_reasons: vec![],
        });
    }

    // Queue first, then push live (clients dedup by envelope ULID)
    db.insert_e2ee_envelopes(&accepted).await?;
    for envelope in accepted {
        let recipient_user_id = envelope.recipient_user_id.clone();
        EventV1::MlsCtl(envelope.into())
            .private(recipient_user_id)
            .await;
    }

    Ok(EmptyResponse)
}

/// The ctl pipe's answer for a Text group (design §7.2): `InvalidOperation`,
/// whatever the body, the flags or the caller's seat. It comes only after
/// the channel fetch, ViewChannel and the shared caller checks, so a caller
/// who cannot view the channel, or whose channel is gone, gets the
/// unknown-group answer instead and cannot tell a protected channel's group
/// id from no group at all (decision 1 (W2)).
///
/// No Text gate, seat check or body validation runs first: each would only
/// swap this refusal for another one, and a refusal never depends on a flag
/// (decision 5 (W2)).
async fn refuse_text_group(
    db: &Database,
    user: &User,
    session: &Session,
    group: &MlsGroup,
) -> Result<EmptyResponse> {
    let Ok(channel) = db.fetch_channel(&group.channel_id).await else {
        return super::as_unknown_group(db, user, Some(session)).await;
    };
    if super::require_channel_access(db, user, &channel)
        .await
        .is_err()
    {
        return super::as_unknown_group(db, user, Some(session)).await;
    }
    super::require_mls_caller(db, user, Some(session)).await?;

    Err(create_error!(InvalidOperation))
}

/// The ctl pipe on Text groups (decision 1 (W2), design §7.2), through the
/// real route. Every flag case is its own `#[test]`: `overwrite_config` runs
/// once per process, BEFORE the harness primes the config cache, so these
/// need nextest (one process per test). The test config has every flag on.
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        events::client::EventV1, BotInformation, E2EEContentType, MlsCommit, MlsCommitOutcome,
        MlsGroup, MlsMemberDevice, PartialChannel, PartialUser, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use ulid::Ulid;

    use crate::routes::mls::{
        dispatch_group, require_channel_access, require_seated, GroupDispatch,
    };
    use crate::util::test::{TestE2EEDevice, TestHarness, MEMBER_DEVICE_SEED};

    /// A body that deserializes but fails the Call path's request validation
    /// (device id and ciphertext)
    const MALFORMED: &str = r#"{"device_id":"not a device id","ciphertext":""}"#;

    /// A well-formed ctl body from `device_id`
    fn ctl_body(device_id: &str) -> String {
        serde_json::to_string(&v0::DataSendMlsMessage {
            device_id: device_id.to_string(),
            ciphertext: STANDARD_NO_PAD.encode(b"opaque ctl announce"),
        })
        .expect("a ctl body")
    }

    /// The route's answer: the status and the full response body
    async fn send(
        harness: &TestHarness,
        session: &Session,
        group_id: &str,
        body: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .post(format!("/mls/groups/{group_id}/messages"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// An error response body, parsed
    #[track_caller]
    fn error_body(body: &str) -> serde_json::Value {
        serde_json::from_str(body).unwrap_or_else(|_| panic!("an error body: {}", body))
    }

    #[track_caller]
    fn assert_invalid_operation(answer: &(Status, String), case: &str) {
        assert_eq!(answer.0, Status::BadRequest, "{}: {}", case, answer.1);
        assert_eq!(
            error_body(&answer.1)["type"],
            "InvalidOperation",
            "{}: {}",
            case,
            answer.1
        );
    }

    fn random_group_id() -> String {
        format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0)
    }

    /// `group` after an epoch-1 Add of `device` committed by `committer`,
    /// through the database primitive (a Text group starts with its creator
    /// only)
    async fn add_device(
        harness: &TestHarness,
        group: &MlsGroup,
        committer: &TestE2EEDevice,
        device: &TestE2EEDevice,
    ) -> MlsGroup {
        let db = &harness.db;
        let hash = db
            .fetch_seat_list(&group.channel_id)
            .await
            .expect("the seat list")
            .expect("a stored seat list")
            .commit_ad_sha256()
            .expect("its AD hash");
        let commit = MlsCommit {
            id: MlsCommit::composite_id(&group.id, 1),
            group_id: group.id.clone(),
            epoch: 1,
            committer: MlsMemberDevice {
                user_id: committer.user_id.clone(),
                device_id: committer.device_id.clone(),
            },
            commit: STANDARD_NO_PAD.encode(b"add"),
            size: 3,
            added: vec![MlsMemberDevice {
                user_id: device.user_id.clone(),
                device_id: device.device_id.clone(),
            }],
            removed: vec![],
            created_at: Timestamp::now_utc(),
            rejoin_intents: vec![],
            removed_reasons: vec![],
        };
        let outcome = db
            .insert_mls_text_commit(&commit, &hash, 0)
            .await
            .expect("the add");
        assert!(matches!(outcome, MlsCommitOutcome::Won), "{:?}", outcome);
        db.fetch_mls_group(&group.id)
            .await
            .expect("the grown group")
    }

    /// Publish a marker on `user_id`'s private topic and wait for it. The
    /// harness reads every topic through ONE subscription and redis pub/sub
    /// is FIFO on it, and the route awaits its publishes, so once the marker
    /// is seen everything the route published is in the event buffer, where
    /// `assert_no_buffered_event` sees it
    async fn flush_with_marker(harness: &mut TestHarness, user_id: &str) {
        let marker = Ulid::new().to_string();
        EventV1::ChannelAck {
            id: marker.clone(),
            user: user_id.to_string(),
            message_id: marker.clone(),
        }
        .private(user_id.to_string())
        .await;
        harness
            .wait_for_event(&format!("{user_id}!"), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;
    }

    /// Design §7.2: a seated viewer of a Text group, sending from one of its
    /// member devices with a bound session, gets `InvalidOperation`; no
    /// envelope is queued and no `MlsCtl` event is published for any member
    /// device. Control: the refusal dropped (the route at `cce2f2b6`) relays
    /// each ctl to the other member device.
    #[test]
    fn a_seated_member_is_refused_and_nothing_is_relayed() {
        crate::util::test::rt().block_on(a_seated_member_is_refused_and_nothing_is_relayed_case())
    }

    async fn a_seated_member_is_refused_and_nothing_is_relayed_case() {
        let mut harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let group = add_device(&harness, &group, &protected.owner_device, &member_device).await;

        // Non-vacuity: each sender is a viewer, seated, and one of the two
        // member devices, so each ctl has a recipient the old route would
        // have relayed it to
        let senders = [
            (&owner, &owner_session, &protected.owner_device),
            (&member, &member_session, &member_device),
        ];
        assert_eq!(group.members.len(), 2, "{:?}", group.members);
        for (user, _, device) in senders {
            assert!(group
                .members
                .iter()
                .any(|leaf| leaf.user_id == user.id && leaf.device_id == device.device_id));
            assert!(
                require_channel_access(&harness.db, user, &protected.channel)
                    .await
                    .is_ok()
            );
            require_seated(&harness.db, protected.channel.id(), &user.id)
                .await
                .expect("seated");
        }

        let mut answers = vec![];
        for (user, session, device) in senders {
            let answer = send(&harness, session, &group.id, &ctl_body(&device.device_id)).await;
            answers.push((user.id.clone(), answer));
        }
        flush_with_marker(&mut harness, &owner.id).await;

        // Nothing relayed: no queued ctl and no ctl event for either device
        for (user, _, device) in senders {
            let queued = harness
                .db
                .fetch_e2ee_envelopes(&user.id, &device.device_id, 100)
                .await
                .expect("the mailbox");
            assert!(
                !queued
                    .iter()
                    .any(|envelope| matches!(envelope.content_type, E2EEContentType::MlsCtl)),
                "a Text ctl was relayed to {}: {:?}",
                user.id,
                queued
            );
            harness.assert_no_buffered_event(&format!("{}!", user.id), |event| {
                matches!(event, EventV1::MlsCtl(_))
            });
        }
        for (sender, answer) in &answers {
            assert_invalid_operation(answer, sender);
        }
    }

    /// One caller class of the oracle
    struct Caller {
        class: &'static str,
        /// As stored, the bot flag included
        user: User,
        session: Session,
        /// The device its well-formed body names
        device_id: String,
    }

    struct Oracle {
        harness: TestHarness,
        owner: User,
        owner_session: Session,
        owner_device_id: String,
        callers: Vec<Caller>,
        hidden_group_id: String,
        deleted_group_id: String,
        unknown_group_id: String,
    }

    /// A protected channel whose Text group exists but which members cannot
    /// view (`@everyone` denied ViewChannel), a second protected channel
    /// deleted under its Text group, and one server member of each caller
    /// class: a member with a bound session, a bot (flagged on the stored
    /// user, so the session guard still lets the request reach the route)
    /// and a member whose session is bound to none of its devices
    async fn oracle_fixture() -> Oracle {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        let hidden = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        for user in [&member, &bot, &unbound] {
            harness.join_server(&hidden.server, user).await;
        }
        db.update_user(
            &bot.id,
            &PartialUser {
                bot: Some(BotInformation {
                    owner: owner.id.clone(),
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("flag the bot");
        let bot = db.fetch_user(&bot.id).await.expect("the bot");
        assert!(bot.bot.is_some());
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, 0x41)
            .await;
        let unbound_device = harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), 0x42)
            .await;
        let mut hidden_channel = hidden.channel.clone();
        hidden_channel
            .update(
                db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view");
        let hidden_group = harness
            .new_text_group(&hidden.channel, &hidden.owner_device, 0, None)
            .await;

        let (_, other_owner_session, other_owner) = harness.new_user().await;
        let deleted = harness
            .new_protected_channel(&other_owner, &other_owner_session, &[])
            .await;
        let deleted_group = harness
            .new_text_group(&deleted.channel, &deleted.owner_device, 0, None)
            .await;
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted.channel.id()).await.is_err());

        Oracle {
            owner,
            owner_session,
            owner_device_id: hidden.owner_device.device_id.clone(),
            callers: vec![
                Caller {
                    class: "member",
                    user: member,
                    session: member_session,
                    device_id: member_device.device_id,
                },
                Caller {
                    class: "bot",
                    user: bot,
                    session: bot_session,
                    device_id: "ab".repeat(16),
                },
                Caller {
                    class: "unbound",
                    user: unbound,
                    session: unbound_session,
                    device_id: unbound_device.device_id,
                },
            ],
            hidden_group_id: hidden_group.id,
            deleted_group_id: deleted_group.id,
            unknown_group_id: random_group_id(),
            harness,
        }
    }

    /// Decision 1 (W2): for every caller class and every request, a Text
    /// group whose channel the caller cannot view, and one whose channel was
    /// deleted, answer EXACTLY as a group id the server does not know: the
    /// same status and response body (which carries no `location`). A
    /// viewer gets the refusal under every flag set, so the Text path is
    /// really reached.
    /// Controls: the refusal before the channel fetch; request validation
    /// between the kind dispatch and the branch.
    async fn hidden_and_deleted_text_groups_answer_as_unknown() {
        let oracle = oracle_fixture().await;
        let harness = &oracle.harness;
        let db = &harness.db;
        let media = revolt_database::voice::media_e2ee_enabled().await;

        // Both are stored Text groups, so the oracle compares the route's
        // real Text path with its unknown path
        for group_id in [&oracle.hidden_group_id, &oracle.deleted_group_id] {
            assert!(
                matches!(
                    dispatch_group(db, group_id).await,
                    Ok(GroupDispatch::Text(_))
                ),
                "{}",
                group_id
            );
        }
        let hidden = db
            .fetch_mls_group(&oracle.hidden_group_id)
            .await
            .expect("the hidden group");
        let channel = db
            .fetch_channel(&hidden.channel_id)
            .await
            .expect("the hidden channel");

        // The owner views the channel, holds a seat and a bound session: it
        // reaches the refusal, whatever the flags and the body
        assert!(require_channel_access(db, &oracle.owner, &channel)
            .await
            .is_ok());
        for body in [ctl_body(&oracle.owner_device_id), MALFORMED.to_string()] {
            let answer = send(
                harness,
                &oracle.owner_session,
                &oracle.hidden_group_id,
                &body,
            )
            .await;
            assert_invalid_operation(&answer, &format!("owner {}", body));
        }

        for caller in &oracle.callers {
            assert!(
                require_channel_access(db, &caller.user, &channel)
                    .await
                    .is_err(),
                "{} views the hidden channel",
                caller.class
            );
            for (request, body) in [
                ("valid", ctl_body(&caller.device_id)),
                ("malformed", MALFORMED.to_string()),
            ] {
                let case = format!("{} {}", caller.class, request);
                let unknown = send(harness, &caller.session, &oracle.unknown_group_id, &body).await;

                // Each class gets its own answer, so the classes are real
                let value = error_body(&unknown.1);
                let expected = match (media, caller.class) {
                    (false, _) => "FeatureDisabled",
                    (true, "bot") => "IsBot",
                    (true, "unbound") => "NotAuthenticated",
                    (true, _) => "NotFound",
                };
                assert_eq!(value["type"], expected, "unknown {}: {}", case, unknown.1);
                if !media {
                    assert_eq!(value["feature"], "media_e2ee", "{}: {}", case, unknown.1);
                }

                for (target, group_id) in [
                    ("hidden", &oracle.hidden_group_id),
                    ("deleted", &oracle.deleted_group_id),
                ] {
                    let answer = send(harness, &caller.session, group_id, &body).await;
                    assert_eq!(answer, unknown, "{} {}", target, case);
                }
            }
        }
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_every_flag_on() {
        crate::util::test::rt().block_on(hidden_and_deleted_text_groups_answer_as_unknown())
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_growth_and_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }
}
