use revolt_database::{Database, E2EEIdentity, MlsGroup, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::{GroupDispatch, TextGate, MAX_COMMITS_PER_FETCH};

/// # Fetch MLS Commits
///
/// Gap refetch for desynced members (plan §2.3): the stored winning commits
/// from `from_epoch` upward, ascending. The commits are opaque ciphertext,
/// but their metadata (`committer` / `added` / `removed` `(user, device)`
/// lists) is the per-device join/leave history of the call — which the plan
/// keeps OFF channel co-members (§3.5). So access requires actual GROUP
/// MEMBERSHIP, not merely channel view: only a participant already in the
/// roster (a desynced member re-securing) may read it (media-e2ee gate
/// finding, slice 6.1).
///
/// A protected channel's Text group (protected-channels design §6.1 "Commit
/// fetch") needs ViewChannel and an ACTIVE seat instead, behind the
/// maintenance gate only (decision 5 (W2): the growth flag never stops a
/// fetch). Its commits carry `rejoin_intents` (§8.1).
#[openapi(tag = "MLS")]
#[get("/groups/<group_id>/commits?<from_epoch>")]
pub async fn fetch_commits(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    from_epoch: i64,
) -> Result<Json<v0::ResponseFetchMlsCommits>> {
    // Kind dispatch on the stored group comes first (decision 1 (W2)). No
    // request validation may run before the branch: with the media flag off
    // an unknown id stops in here while a Text group passes ungated
    match super::dispatch_group(db, &group_id).await? {
        GroupDispatch::CallOrUnknown(None) => {
            super::as_unknown_group(db, &user, Some(&session)).await
        }
        GroupDispatch::CallOrUnknown(Some(_)) => {
            fetch_call_commits(db, user, session, group_id, from_epoch).await
        }
        GroupDispatch::Text(group) => {
            fetch_text_commits(db, &user, &session, group, from_epoch).await
        }
    }
}

/// The Call group path: the checks this route ran before Text groups
/// existed, in their order, unchanged (decision 1 (W2))
async fn fetch_call_commits(
    db: &Database,
    user: User,
    session: Session,
    group_id: String,
    from_epoch: i64,
) -> Result<Json<v0::ResponseFetchMlsCommits>> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    if from_epoch < 0 {
        return Err(create_error!(FailedValidation {
            error: "from_epoch must be non-negative".to_string()
        }));
    }

    // Any of the caller's registered devices qualifies (the desynced device
    // is re-fetching; it is device-bound like every E2EE surface)
    E2EEIdentity::require_device_bound_session(db, &user.id, &session.id).await?;

    let (group, _channel) = super::fetch_authorized_group(db, &user, &group_id).await?;

    // Channel access is necessary but NOT sufficient: the caller must be a
    // current member of the group, else the per-device roster history would
    // leak to any channel viewer (device ids stay off co-members, §3.5).
    // NotFound (not Forbidden) so a non-member cannot even probe existence.
    if group.member_device_of(&user.id).is_none() {
        return Err(create_error!(NotFound));
    }

    let commits = db
        .fetch_mls_commits_from(&group.id, from_epoch, MAX_COMMITS_PER_FETCH)
        .await?;

    Ok(Json(v0::ResponseFetchMlsCommits {
        commits: commits
            .into_iter()
            .map(|commit| commit.into_commit_info(&group.channel_id))
            .collect(),
        current_epoch: group.current_epoch,
    }))
}

/// The Text group path (design §6.1 steps 2 to 8). A caller who cannot see
/// the group's channel, or whose channel is gone, gets exactly the unknown
/// group answer, so a hidden protected channel cannot be told apart from no
/// group at all.
///
/// The rule is seated AND ViewChannel (§6.1), not the Call path's group
/// membership: the same authorization already guards the commit row submit
/// returns as `Lost` (§2.5 step 0), and device ids are not kept from
/// viewers on the Text plane (the text group state lists them, §7.2).
async fn fetch_text_commits(
    db: &Database,
    user: &User,
    session: &Session,
    group: MlsGroup,
    from_epoch: i64,
) -> Result<Json<v0::ResponseFetchMlsCommits>> {
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

    if from_epoch < 0 {
        return Err(create_error!(FailedValidation {
            error: "from_epoch must be non-negative".to_string()
        }));
    }

    super::require_text_gate(TextGate::Available).await?;
    super::require_seated(db, &group.channel_id, &user.id).await?;

    let commits = db
        .fetch_mls_commits_from(&group.id, from_epoch, MAX_COMMITS_PER_FETCH)
        .await?;

    // `into_commit_info` fills each rejoin intent's `channel_id` from the
    // group's channel (§8.1); the stored row does not carry it
    Ok(Json(v0::ResponseFetchMlsCommits {
        commits: commits
            .into_iter()
            .map(|commit| commit.into_commit_info(&group.channel_id))
            .collect(),
        current_epoch: group.current_epoch,
    }))
}

/// Commit fetch on Text and Call groups (W2 decisions 1 and 5, design §6.1
/// "Commit fetch", §8.1). Every flag case is its own `#[test]`:
/// `overwrite_config` runs once per process, BEFORE the harness primes the
/// config cache, so these need nextest. The test config has every flag on.
/// The route is called directly, as Rocket calls it, so a bot caller (which
/// has no session over HTTP) reaches it too.
#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        BotInformation, Database, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome,
        MlsGroupKind, MlsJoinIntent, MlsMemberDevice, MlsRemovalReason, MlsRemovedReason,
        PartialChannel, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::{Error, Result};
    use rocket::State;
    use ulid::Ulid;

    use super::super::{dispatch_group, require_channel_access, GroupDispatch};
    use super::fetch_commits;
    use crate::util::test::{TestE2EEDevice, TestHarness, MEMBER_DEVICE_SEED};

    const VIEWER_DEVICE_SEED: u8 = 0x40;
    const UNBOUND_DEVICE_SEED: u8 = 0x60;

    /// The route, called as Rocket calls it
    async fn fetch(
        db: &Database,
        user: &User,
        session: &Session,
        group_id: &str,
        from_epoch: i64,
    ) -> Result<v0::ResponseFetchMlsCommits> {
        fetch_commits(
            State::from(db),
            user.clone(),
            session.clone(),
            group_id.to_string(),
            from_epoch,
        )
        .await
        .map(|json| json.into_inner())
    }

    fn random_group_id() -> String {
        format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0)
    }

    fn leaf(device: &TestE2EEDevice) -> MlsMemberDevice {
        MlsMemberDevice {
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
        }
    }

    fn seconds_ago(seconds: i64) -> Timestamp {
        Timestamp::now_utc()
            .checked_sub(Duration::seconds(seconds))
            .expect("a past time")
    }

    fn commit(
        group: &MlsGroup,
        epoch: i64,
        committer: &MlsMemberDevice,
        added: Vec<MlsMemberDevice>,
        removed: Vec<MlsMemberDevice>,
        at: Timestamp,
    ) -> MlsCommit {
        MlsCommit {
            id: MlsCommit::composite_id(&group.id, epoch),
            group_id: group.id.clone(),
            epoch,
            committer: committer.clone(),
            commit: format!("Y29tbWl0{epoch}"),
            size: 8,
            added,
            removed,
            created_at: at,
            rejoin_intents: vec![],
            removed_reasons: vec![],
        }
    }

    #[track_caller]
    fn assert_won(outcome: Result<MlsCommitOutcome>, what: &str) {
        match outcome {
            Ok(MlsCommitOutcome::Won) => {}
            other => panic!("{}: expected Won, got {:?}", what, other),
        }
    }

    /// The refusal's serialized `type` is `expected`; returns the error
    #[track_caller]
    fn assert_refused(
        result: Result<v0::ResponseFetchMlsCommits>,
        expected: &str,
        case: &str,
    ) -> Error {
        match result {
            Err(error) => {
                let body = serde_json::to_value(&error).expect("an error body");
                assert_eq!(body["type"], expected, "{}: {}", case, body);
                error
            }
            Ok(served) => panic!(
                "{}: expected {}, served {} commits",
                case,
                expected,
                served.commits.len()
            ),
        }
    }

    #[track_caller]
    fn assert_disabled(result: Result<v0::ResponseFetchMlsCommits>, feature: &str, case: &str) {
        let error = assert_refused(result, "FeatureDisabled", case);
        let body = serde_json::to_value(&error).expect("an error body");
        assert_eq!(body["feature"], feature, "{}: {}", case, body);
    }

    struct Fixture {
        harness: TestHarness,
        owner: User,
        owner_session: Session,
        /// Seated; its device was Added at epoch 1 and Removed at epoch 2 on
        /// its own rejoin intent, so it is no longer a group member
        member: User,
        member_session: Session,
        /// A server member who views the channel; no seat, bound session
        viewer: User,
        viewer_session: Session,
        /// Views the channel, no seat; its device is bound to another session
        unbound: User,
        unbound_session: Session,
        channel_id: String,
        text_group_id: String,
        /// The intent the epoch 2 Remove consumed
        intent: MlsJoinIntent,
        /// A Call group on another channel of the server: the owner's device
        /// is its only member; one commit (epoch 1)
        call_group_id: String,
    }

    /// A protected channel seating the owner and the member, its Text group
    /// with two commits through the real Text commit transaction (epoch 1
    /// Adds the member's device, epoch 2 Removes it in the rejoin case, so
    /// the stored row carries `rejoin_intents`), and a Call group
    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, viewer_session, viewer) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        for user in [&viewer, &unbound] {
            harness.join_server(&protected.server, user).await;
        }
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&viewer, &viewer_session.id, VIEWER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), UNBOUND_DEVICE_SEED)
            .await;

        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let hash = group
            .seat_list_ad_sha256
            .clone()
            .expect("the group binds the genesis list");
        let owner_leaf = leaf(&protected.owner_device);
        let member_leaf = leaf(&member_device);

        assert_won(
            db.insert_mls_text_commit(
                &commit(
                    &group,
                    1,
                    &owner_leaf,
                    vec![member_leaf.clone()],
                    vec![],
                    seconds_ago(20),
                ),
                &hash,
                0,
            )
            .await,
            "the Add",
        );
        let intent = MlsJoinIntent {
            id: MlsJoinIntent::composite_id(&group.id, &member.id, &member_device.device_id),
            group_id: group.id.clone(),
            user_id: member.id.clone(),
            device_id: member_device.device_id.clone(),
            key_package_ref: "rejoin-ref".to_string(),
            signature: member_device.sign("rejoin intent"),
            created_at: seconds_ago(5),
        };
        db.upsert_mls_join_intent(&intent)
            .await
            .expect("the rejoin intent");
        // The advisory reason the submit route stamps for this Remove (B48)
        assert_won(
            db.insert_mls_text_commit(
                &MlsCommit {
                    removed_reasons: vec![MlsRemovedReason {
                        user_id: member.id.clone(),
                        device_id: member_device.device_id.clone(),
                        reason: MlsRemovalReason::Rejoin,
                    }],
                    ..commit(
                        &group,
                        2,
                        &owner_leaf,
                        vec![],
                        vec![member_leaf],
                        Timestamp::now_utc(),
                    )
                },
                &hash,
                0,
            )
            .await,
            "the rejoin Remove",
        );

        let call_channel = harness.new_channel(&protected.server).await;
        let call_group = MlsGroup {
            id: random_group_id(),
            channel_id: call_channel.id().to_string(),
            open: true,
            created_by: owner_leaf.clone(),
            created_at: Timestamp::now_utc(),
            current_epoch: 0,
            members: vec![owner_leaf.clone()],
            closed_at: None,
            superseded_by: None,
            kind: MlsGroupKind::Call,
            generation: None,
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
        };
        assert!(matches!(
            db.create_mls_group(&call_group, None)
                .await
                .expect("the call group"),
            MlsGroupCreateOutcome::Created
        ));
        assert_won(
            db.insert_mls_commit(&commit(
                &call_group,
                1,
                &owner_leaf,
                vec![],
                vec![],
                Timestamp::now_utc(),
            ))
            .await,
            "the call Update",
        );

        Fixture {
            harness,
            owner,
            owner_session,
            member,
            member_session,
            viewer,
            viewer_session,
            unbound,
            unbound_session,
            channel_id: protected.channel.id().to_string(),
            text_group_id: group.id,
            intent,
            call_group_id: call_group.id,
        }
    }

    /// Design §6.1 "Commit fetch" and §8.1, every flag on: a seated viewer
    /// is served with the rejoin intents; group membership is not needed;
    /// an unseated viewer is refused; the checks run in decision 1 order
    #[test]
    fn text_fetch_serves_seated_viewers_with_rejoin_intents() {
        crate::util::test::rt().block_on(text_fetch_serves_seated_viewers_case())
    }

    async fn text_fetch_serves_seated_viewers_case() {
        let fixture = fixture().await;
        let db = &fixture.harness.db;
        let group_id = &fixture.text_group_id;

        let served = fetch(db, &fixture.owner, &fixture.owner_session, group_id, 0)
            .await
            .expect("the owner is served");
        assert_eq!(served.current_epoch, 2);
        assert_eq!(
            served
                .commits
                .iter()
                .map(|commit| commit.epoch)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(served.commits[0].rejoin_intents.is_empty());
        let intent = &fixture.intent;
        assert_eq!(
            served.commits[1].rejoin_intents,
            vec![v0::MlsRejoinIntentInfo {
                group_id: intent.group_id.clone(),
                channel_id: fixture.channel_id.clone(),
                user_id: intent.user_id.clone(),
                device_id: intent.device_id.clone(),
                key_package_ref: intent.key_package_ref.clone(),
                signature: intent.signature.clone(),
            }]
        );

        // On the wire: exactly the §8.1 element, its channel filled in
        let wire = serde_json::to_value(&served).expect("JSON");
        let element = &wire["commits"][1]["rejoin_intents"][0];
        let mut keys: Vec<&str> = element
            .as_object()
            .expect("an intent object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "channel_id",
                "device_id",
                "group_id",
                "key_package_ref",
                "signature",
                "user_id"
            ]
        );
        assert_eq!(element["channel_id"], fixture.channel_id.as_str());

        // B48: the stored advisory reasons round-trip, snake_case; a commit
        // without any omits the key
        assert_eq!(
            served.commits[1].removed_reasons,
            vec![v0::MlsRemovedReasonInfo {
                user_id: intent.user_id.clone(),
                device_id: intent.device_id.clone(),
                reason: v0::MlsRemovalReason::Rejoin,
            }]
        );
        assert_eq!(
            wire["commits"][1]["removed_reasons"],
            serde_json::json!([{
                "user_id": intent.user_id,
                "device_id": intent.device_id,
                "reason": "rejoin"
            }])
        );
        assert!(
            wire["commits"][0].get("removed_reasons").is_none(),
            "{}",
            wire
        );

        // The member's device left the roster at epoch 2; its seat and the
        // channel are what count on Text
        let served = fetch(db, &fixture.member, &fixture.member_session, group_id, 2)
            .await
            .expect("the seated member is served");
        assert_eq!(served.commits.len(), 1);
        assert_eq!(served.commits[0].rejoin_intents.len(), 1);

        assert_refused(
            fetch(db, &fixture.viewer, &fixture.viewer_session, group_id, 0).await,
            "NotSeated",
            "an unseated viewer",
        );
        // Request validation runs before the seat check...
        assert_refused(
            fetch(db, &fixture.viewer, &fixture.viewer_session, group_id, -1).await,
            "FailedValidation",
            "an unseated viewer, malformed",
        );
        // ...and after the caller checks
        for from_epoch in [0, -1] {
            assert_refused(
                fetch(
                    db,
                    &fixture.unbound,
                    &fixture.unbound_session,
                    group_id,
                    from_epoch,
                )
                .await,
                "NotAuthenticated",
                &format!("an unbound viewer, from_epoch {from_epoch}"),
            );
            let mut bot = fixture.owner.clone();
            bot.bot = Some(BotInformation {
                owner: fixture.viewer.id.clone(),
            });
            assert_refused(
                fetch(db, &bot, &fixture.owner_session, group_id, from_epoch).await,
                "IsBot",
                &format!("a bot, from_epoch {from_epoch}"),
            );
        }
    }

    /// Decision 5 (W2): fetch is maintenance, so growth off still serves a
    /// seated member. The seat check still runs, and a Call group never
    /// reads the growth flag.
    #[test]
    fn text_fetch_is_served_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            text_fetch_is_served_with_growth_off_case().await
        })
    }

    async fn text_fetch_is_served_with_growth_off_case() {
        let fixture = fixture().await;
        let db = &fixture.harness.db;
        let group_id = &fixture.text_group_id;

        let served = fetch(db, &fixture.owner, &fixture.owner_session, group_id, 0)
            .await
            .expect("the owner is served with growth off");
        assert_eq!(served.commits.len(), 2);
        assert_eq!(served.commits[1].rejoin_intents.len(), 1);
        fetch(db, &fixture.member, &fixture.member_session, group_id, 1)
            .await
            .expect("the seated member is served with growth off");
        assert_refused(
            fetch(db, &fixture.viewer, &fixture.viewer_session, group_id, 0).await,
            "NotSeated",
            "an unseated viewer, growth off",
        );

        let served = fetch(
            db,
            &fixture.owner,
            &fixture.owner_session,
            &fixture.call_group_id,
            0,
        )
        .await
        .expect("the call member is served with growth off");
        assert_eq!(served.commits.len(), 1);
    }

    /// A Text group ignores the media flag; Call and unknown groups keep
    /// today's answer
    #[test]
    fn text_fetch_is_served_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            text_fetch_is_served_with_media_off_case().await
        })
    }

    async fn text_fetch_is_served_with_media_off_case() {
        let fixture = fixture().await;
        let db = &fixture.harness.db;

        let served = fetch(
            db,
            &fixture.owner,
            &fixture.owner_session,
            &fixture.text_group_id,
            0,
        )
        .await
        .expect("the owner is served with media off");
        assert_eq!(served.commits.len(), 2);
        for group_id in [&fixture.call_group_id, &random_group_id()] {
            assert_disabled(
                fetch(db, &fixture.owner, &fixture.owner_session, group_id, 0).await,
                "media_e2ee",
                group_id,
            );
        }
    }

    /// E2EE off closes the Text plane: the maintenance gate answers, after
    /// request validation and before the seat check (§6.1 steps 5 to 7)
    #[test]
    fn text_fetch_is_refused_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            text_fetch_is_refused_with_e2ee_off_case().await
        })
    }

    async fn text_fetch_is_refused_with_e2ee_off_case() {
        let fixture = fixture().await;
        let db = &fixture.harness.db;
        let group_id = &fixture.text_group_id;

        assert_disabled(
            fetch(db, &fixture.owner, &fixture.owner_session, group_id, 0).await,
            "e2ee",
            "the owner",
        );
        assert_disabled(
            fetch(db, &fixture.viewer, &fixture.viewer_session, group_id, 0).await,
            "e2ee",
            "an unseated viewer",
        );
        assert_refused(
            fetch(db, &fixture.owner, &fixture.owner_session, group_id, -1).await,
            "FailedValidation",
            "the owner, malformed",
        );
        assert_disabled(
            fetch(
                db,
                &fixture.owner,
                &fixture.owner_session,
                &fixture.call_group_id,
                0,
            )
            .await,
            "media_e2ee",
            "the call group",
        );
    }

    /// Decision 1 (W2): the Call branch keeps its checks and their order
    /// (bot, request validation, bound session, ViewChannel, group
    /// membership) and its response; `rejoin_intents` is always empty on a
    /// Call commit. An unknown id answers the unknown-group answer for any
    /// request (the accepted exception (d)).
    #[test]
    fn call_fetch_keeps_its_checks_and_response() {
        crate::util::test::rt().block_on(call_fetch_keeps_its_checks_and_response_case())
    }

    async fn call_fetch_keeps_its_checks_and_response_case() {
        let fixture = fixture().await;
        let db = &fixture.harness.db;
        let group_id = &fixture.call_group_id;
        assert!(matches!(
            dispatch_group(db, group_id).await,
            Ok(GroupDispatch::CallOrUnknown(Some(_)))
        ));

        let served = fetch(db, &fixture.owner, &fixture.owner_session, group_id, 0)
            .await
            .expect("the call member is served");
        assert_eq!(served.current_epoch, 1);
        assert_eq!(served.commits.len(), 1);
        assert_eq!(served.commits[0].committer.device_id.len(), 32);
        assert!(served.commits[0].rejoin_intents.is_empty());
        assert!(served.commits[0].removed_reasons.is_empty());
        let wire = serde_json::to_value(&served).expect("JSON");
        assert_eq!(wire["commits"][0]["rejoin_intents"], serde_json::json!([]));
        assert!(
            wire["commits"][0].get("removed_reasons").is_none(),
            "{}",
            wire
        );

        // A channel viewer who is not a group member: the route's own
        // membership check answers, not the unknown-group answer
        let error = assert_refused(
            fetch(db, &fixture.viewer, &fixture.viewer_session, group_id, 0).await,
            "NotFound",
            "a viewer who is not a member",
        );
        assert!(
            error.location.contains("commits_fetch.rs"),
            "{}",
            error.location
        );
        // Validation before the bound-session check (the Text order is the
        // reverse)
        assert_refused(
            fetch(db, &fixture.unbound, &fixture.unbound_session, group_id, -1).await,
            "FailedValidation",
            "an unbound caller, malformed",
        );
        assert_refused(
            fetch(db, &fixture.unbound, &fixture.unbound_session, group_id, 0).await,
            "NotAuthenticated",
            "an unbound caller",
        );
        let mut bot = fixture.owner.clone();
        bot.bot = Some(BotInformation {
            owner: fixture.viewer.id.clone(),
        });
        assert_refused(
            fetch(db, &bot, &fixture.owner_session, group_id, -1).await,
            "IsBot",
            "a bot, malformed",
        );

        let error = assert_refused(
            fetch(
                db,
                &fixture.owner,
                &fixture.owner_session,
                &random_group_id(),
                -1,
            )
            .await,
            "NotFound",
            "an unknown id, malformed",
        );
        assert!(error.location.contains("mls/mod.rs"), "{}", error.location);
    }

    /// One caller class of the oracle
    struct Caller {
        class: &'static str,
        user: User,
        session: Session,
    }

    struct Oracle {
        harness: TestHarness,
        owner: User,
        owner_session: Session,
        callers: Vec<Caller>,
        hidden_group_id: String,
        deleted_group_id: String,
        unknown_group_id: String,
    }

    /// A protected channel whose Text group exists but which members cannot
    /// view (`@everyone` denied ViewChannel; the member caller even holds a
    /// seat), a second protected channel deleted under its Text group, and
    /// one caller of each class: a member with a bound session, a bot (a
    /// member, no device) and a member whose session is bound to none of
    /// its devices
    async fn oracle_fixture() -> Oracle {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, mut bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        let hidden = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        for user in [&bot, &unbound] {
            harness.join_server(&hidden.server, user).await;
        }
        bot.bot = Some(BotInformation {
            owner: owner.id.clone(),
        });
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), UNBOUND_DEVICE_SEED)
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
            harness,
            owner,
            owner_session,
            callers: vec![
                Caller {
                    class: "member",
                    user: member,
                    session: member_session,
                },
                Caller {
                    class: "bot",
                    user: bot,
                    session: bot_session,
                },
                Caller {
                    class: "unbound",
                    user: unbound,
                    session: unbound_session,
                },
            ],
            hidden_group_id: hidden_group.id,
            deleted_group_id: deleted_group.id,
            unknown_group_id: random_group_id(),
        }
    }

    /// The response body a refusal serializes to
    #[track_caller]
    fn refusal_body(result: Result<v0::ResponseFetchMlsCommits>, case: &str) -> String {
        match result {
            Err(error) => serde_json::to_string(&error).expect("an error body"),
            Ok(served) => panic!("{}: served {} commits", case, served.commits.len()),
        }
    }

    /// Decision 1 (W2) invariant on this route: for every caller class and
    /// for a valid and a MALFORMED request, a Text group whose channel the
    /// caller cannot view, and one whose channel was deleted, answer EXACTLY
    /// as a group id the server does not know (the full body, `location`
    /// included)
    async fn hidden_and_deleted_text_groups_answer_as_unknown() {
        let oracle = oracle_fixture().await;
        let db = &oracle.harness.db;
        let media = revolt_database::voice::media_e2ee_enabled().await;
        let e2ee = revolt_config::config().await.features.e2ee_enabled;

        // Both groups are stored Text groups, so the oracle compares a real
        // Text path with the unknown path
        for group_id in [&oracle.hidden_group_id, &oracle.deleted_group_id] {
            assert!(matches!(
                dispatch_group(db, group_id).await,
                Ok(GroupDispatch::Text(_))
            ));
        }
        let hidden = db
            .fetch_mls_group(&oracle.hidden_group_id)
            .await
            .expect("the hidden group");
        let channel = db
            .fetch_channel(&hidden.channel_id)
            .await
            .expect("the hidden channel");
        assert!(require_channel_access(db, &oracle.owner, &channel)
            .await
            .is_ok());
        // The owner (a viewer, seated, bound) gets past the access checks:
        // served while E2EE is on, the maintenance gate's answer otherwise
        let owner = fetch(
            db,
            &oracle.owner,
            &oracle.owner_session,
            &oracle.hidden_group_id,
            0,
        )
        .await;
        if e2ee {
            owner.expect("the owner is served");
        } else {
            assert_disabled(owner, "e2ee", "the owner, e2ee off");
        }

        for caller in &oracle.callers {
            assert!(
                require_channel_access(db, &caller.user, &channel)
                    .await
                    .is_err(),
                "{} views the hidden channel",
                caller.class
            );
            for from_epoch in [0, -1] {
                let case = format!("{} from_epoch {}", caller.class, from_epoch);
                let unknown = refusal_body(
                    fetch(
                        db,
                        &caller.user,
                        &caller.session,
                        &oracle.unknown_group_id,
                        from_epoch,
                    )
                    .await,
                    &format!("unknown {case}"),
                );

                // Each class gets its own answer, so the classes are real
                let value: serde_json::Value = serde_json::from_str(&unknown).expect("JSON");
                let expected = match (media, caller.class) {
                    (false, _) => "FeatureDisabled",
                    (true, "bot") => "IsBot",
                    (true, "unbound") => "NotAuthenticated",
                    (true, _) => "NotFound",
                };
                assert_eq!(value["type"], expected, "{}: {}", case, unknown);
                if !media {
                    assert_eq!(value["feature"], "media_e2ee", "{}: {}", case, unknown);
                }

                for (target, group_id) in [
                    ("hidden", &oracle.hidden_group_id),
                    ("deleted", &oracle.deleted_group_id),
                ] {
                    let answer = refusal_body(
                        fetch(db, &caller.user, &caller.session, group_id, from_epoch).await,
                        &format!("{target} {case}"),
                    );
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

    /// B48: a Text commit row stored before `removed_reasons` existed (no
    /// key) reads as empty and is served without the key; its other
    /// declarations are unchanged. Mongo: the key is unset on the stored
    /// document. Reference (no serialization): the row is replaced by the
    /// BSON round trip of the keyless document.
    #[test]
    fn a_text_row_without_removed_reasons_reads_as_empty() {
        crate::util::test::rt().block_on(a_text_row_without_removed_reasons_reads_as_empty_case())
    }

    async fn a_text_row_without_removed_reasons_reads_as_empty_case() {
        use revolt_database::mongodb::bson::{doc, from_document, to_document, Document};

        let fixture = fixture().await;
        let db = &fixture.harness.db;
        let group_id = &fixture.text_group_id;
        let row_id = MlsCommit::composite_id(group_id, 2);

        let stored = db
            .fetch_mls_commits_from(group_id, 2, 1)
            .await
            .expect("commit read")
            .remove(0);
        assert_eq!(stored.removed_reasons.len(), 1);
        let mut document = to_document(&stored).expect("BSON");
        assert!(document.remove("removed_reasons").is_some());
        let old: MlsCommit = from_document(document).expect("a keyless row deserializes");
        assert!(old.removed_reasons.is_empty());
        // Field by field: BSON keeps milliseconds, the Reference row
        // nanoseconds, so `created_at` is not compared
        assert_eq!(old.id, stored.id);
        assert_eq!(old.committer, stored.committer);
        assert_eq!(old.commit, stored.commit);
        assert_eq!(old.added, stored.added);
        assert_eq!(old.removed, stored.removed);
        assert_eq!(
            old.rejoin_intents
                .iter()
                .map(|intent| &intent.id)
                .collect::<Vec<_>>(),
            stored
                .rejoin_intents
                .iter()
                .map(|intent| &intent.id)
                .collect::<Vec<_>>()
        );

        match db {
            Database::Reference(reference) => {
                reference
                    .mls_commits
                    .lock()
                    .await
                    .insert(row_id.clone(), old);
            }
            Database::MongoDb(mongo) => {
                let result = mongo
                    .col::<Document>("mls_commits")
                    .update_one(
                        doc! { "_id": &row_id },
                        doc! { "$unset": { "removed_reasons": "" } },
                    )
                    .await
                    .expect("unset the key");
                assert_eq!(result.modified_count, 1);
                let raw = mongo
                    .col::<Document>("mls_commits")
                    .find_one(doc! { "_id": &row_id })
                    .await
                    .expect("raw read")
                    .expect("the row");
                assert!(!raw.contains_key("removed_reasons"));
            }
        }

        let served = fetch(db, &fixture.owner, &fixture.owner_session, group_id, 2)
            .await
            .expect("the owner is served");
        assert_eq!(served.commits.len(), 1);
        assert!(served.commits[0].removed_reasons.is_empty());
        assert_eq!(served.commits[0].removed.len(), 1);
        assert_eq!(served.commits[0].rejoin_intents.len(), 1);
        let wire = serde_json::to_value(&served).expect("JSON");
        assert!(
            wire["commits"][0].get("removed_reasons").is_none(),
            "{}",
            wire
        );
    }
}
