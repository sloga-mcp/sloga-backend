use revolt_database::{Database, MlsGroup, Session, User};
use revolt_models::v0;
use revolt_result::{ErrorType, Result};
use rocket::{serde::json::Json, State};

use super::{GroupDispatch, TextGate};

/// # Fetch MLS Text Welcome
///
/// The stored Welcome of one of the caller's own devices (protected-channels
/// design §6.3 "Stored Welcome and refetch", §7.2, S2-D29): a device that
/// `member_added` lists but that saw no `mls_welcome` envelope fetches it
/// here (R5). This is the only surface that serves `MlsCommit.welcome`.
///
/// Text groups only: the route has no Call path. An unknown id, a Call
/// group, a missing channel and a channel the caller cannot view answer
/// exactly like a group id the server does not know; then the caller
/// checks, the available gate (a Welcome completes an Add already made, so
/// the growth flag never stops it), the caller's seat. Every case with no
/// Welcome to serve gives that same unknown-group answer: `device_id` is
/// not a registered device of the caller bound to this session (another
/// user's device included), no stored Text commit added it (or its row was
/// pruned, or stored no Welcome), or it is no longer a member whose
/// `member_added.epoch` is that commit's epoch (evicted, or re-added
/// since).
#[openapi(tag = "MLS")]
#[get("/groups/<group_id>/welcome?<device_id>")]
pub async fn fetch_welcome(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    device_id: String,
) -> Result<Json<v0::ResponseTextWelcome>> {
    // Kind dispatch on the stored group comes first (decision 1 (W2)), and
    // nothing about the request is checked before it
    match super::dispatch_group(db, &group_id).await? {
        GroupDispatch::CallOrUnknown(_) => super::as_unknown_group(db, &user, Some(&session)).await,
        GroupDispatch::Text(group) => {
            fetch_text_welcome(db, &user, &session, group, &device_id).await
        }
    }
}

/// The Text group path, in the design §7.2 order. A caller who cannot see
/// the group's channel, or whose channel is gone, gets exactly the unknown
/// group answer, before any check of its own.
async fn fetch_text_welcome(
    db: &Database,
    user: &User,
    session: &Session,
    group: MlsGroup,
    device_id: &str,
) -> Result<Json<v0::ResponseTextWelcome>> {
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
    super::require_text_gate(TextGate::Available).await?;
    super::require_seated(db, &group.channel_id, &user.id).await?;

    match stored_welcome(db, user, session, &group.id, device_id).await? {
        Some(welcome) => Ok(Json(welcome)),
        None => super::as_unknown_group(db, user, Some(session)).await,
    }
}

/// The Welcome the route may serve, or `None` for the unknown-group answer
async fn stored_welcome(
    db: &Database,
    user: &User,
    session: &Session,
    group_id: &str,
    device_id: &str,
) -> Result<Option<v0::ResponseTextWelcome>> {
    // The caller's OWN registered device, bound to this session. Another
    // user's device id is never one of the caller's, so it ends here too
    let bound = match db.fetch_e2ee_identity(&user.id, device_id).await {
        Ok(identity) => identity.assert_bound_session(&session.id).is_ok(),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => false,
        Err(error) => return Err(error),
    };
    if !bound {
        return Ok(None);
    }

    // The newest Text-marked commit that added this device
    let Some(commit) = db
        .fetch_mls_text_welcome(group_id, &user.id, device_id)
        .await?
    else {
        return Ok(None);
    };
    let Some(welcome) = commit.welcome else {
        return Ok(None);
    };

    // The group is read AFTER the commit, so an eviction or a re-Add that
    // lands before this read withholds the Welcome
    let group = match db.fetch_mls_group(group_id).await {
        Ok(group) => group,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    if !last_added_at(&group, &user.id, device_id, commit.epoch) {
        return Ok(None);
    }

    Ok(Some(v0::ResponseTextWelcome {
        group_id: group.id,
        epoch: commit.epoch,
        welcome,
    }))
}

/// Whether the device is still a member of `group` and `epoch` is its
/// latest Add (`member_added`, design §2.5): an evicted device is no
/// member, a re-added one has a later epoch
fn last_added_at(group: &MlsGroup, user_id: &str, device_id: &str, epoch: i64) -> bool {
    group.has_member(user_id, device_id)
        && group.member_added.iter().any(|entry| {
            entry.user_id == user_id && entry.device_id == device_id && entry.epoch == epoch
        })
}

/// The Welcome route (design §6.3 "Stored Welcome and refetch", §7.2,
/// S2-D29). Every flag case is its own `#[test]`: `overwrite_config` runs
/// once per process, BEFORE the harness primes the config cache, so these
/// need nextest. The test config has every flag on. The route is called
/// directly, as Rocket calls it, so a bot caller (which has no session over
/// HTTP) reaches it too.
#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        BotInformation, Database, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome,
        MlsGroupKind, MlsJoinIntent, MlsMemberDevice, PartialChannel, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::Result;
    use rocket::State;
    use ulid::Ulid;

    use super::fetch_welcome;
    use crate::util::test::{TestE2EEDevice, TestHarness, MEMBER_DEVICE_SEED};

    const MEMBER_SECOND_DEVICE_SEED: u8 = 0x30;
    const PEER_DEVICE_SEED: u8 = 0x40;
    const JOINER_DEVICE_SEED: u8 = 0x50;
    const EVICTED_DEVICE_SEED: u8 = 0x60;
    const READDED_DEVICE_SEED: u8 = 0x70;
    const UNBOUND_DEVICE_SEED: u8 = 0x90;

    /// The epoch 1 Add's Welcome (b64 of `welcome-1`)
    const WELCOME_1: &str = "d2VsY29tZS0x";
    /// The epoch 3 re-Add's Welcome (b64 of `welcome-3`)
    const WELCOME_3: &str = "d2VsY29tZS0z";

    /// The route, called as Rocket calls it
    async fn fetch(
        db: &Database,
        user: &User,
        session: &Session,
        group_id: &str,
        device_id: &str,
    ) -> Result<v0::ResponseTextWelcome> {
        Box::pin(fetch_welcome(
            State::from(db),
            user.clone(),
            session.clone(),
            group_id.to_string(),
            device_id.to_string(),
        ))
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
        welcome: Option<&str>,
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
            welcome: welcome.map(str::to_string),
        }
    }

    fn rejoin_intent(group: &MlsGroup, device: &TestE2EEDevice, at: Timestamp) -> MlsJoinIntent {
        MlsJoinIntent {
            id: MlsJoinIntent::composite_id(&group.id, &device.user_id, &device.device_id),
            group_id: group.id.clone(),
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
            key_package_ref: format!("rejoin-{}", device.device_id),
            signature: device.sign("rejoin intent"),
            created_at: at,
            generation: None,
            issued_at: None,
        }
    }

    #[track_caller]
    fn assert_won(outcome: Result<MlsCommitOutcome>, what: &str) {
        match outcome {
            Ok(MlsCommitOutcome::Won) => {}
            other => panic!("{}: expected Won, got {:?}", what, other),
        }
    }

    /// The response body a refusal serializes to (it carries no `location`)
    #[track_caller]
    fn refusal_body(result: Result<v0::ResponseTextWelcome>, case: &str) -> String {
        match result {
            Err(error) => serde_json::to_string(&error).expect("an error body"),
            Ok(served) => panic!(
                "{}: served the epoch {} Welcome of {}",
                case, served.epoch, served.group_id
            ),
        }
    }

    /// The serialized `type` of a refusal body
    fn refusal_type(body: &str) -> serde_json::Value {
        let value: serde_json::Value = serde_json::from_str(body).expect("JSON");
        value["type"].clone()
    }

    /// A user, its harness session, and its device: bound to that session
    /// unless built by [`unbound_caller`]
    struct Caller {
        user: User,
        session: Session,
        device: TestE2EEDevice,
    }

    async fn caller(harness: &TestHarness, seed: u8) -> Caller {
        let (_, session, user) = harness.new_user().await;
        let device = harness.new_e2ee_device(&user, &session.id, seed).await;
        Caller {
            user,
            session,
            device,
        }
    }

    /// A caller whose session is bound to none of its devices
    async fn unbound_caller(harness: &TestHarness, seed: u8) -> Caller {
        let (_, session, user) = harness.new_user().await;
        let device = harness
            .new_e2ee_device(&user, &Ulid::new().to_string(), seed)
            .await;
        Caller {
            user,
            session,
            device,
        }
    }

    /// The unknown-group answer `caller` gets: a group id the server does
    /// not know, same session and device id
    async fn unknown_answer(
        db: &Database,
        user: &User,
        session: &Session,
        device_id: &str,
    ) -> String {
        refusal_body(
            fetch(db, user, session, &random_group_id(), device_id).await,
            "an unknown group id",
        )
    }

    struct Fixture {
        harness: TestHarness,
        server_id: String,
        channel_id: String,
        text_group_id: String,
        /// The owner's device is its only member; on another channel
        call_group_id: String,
        /// The member is seated there and Added with a Welcome, but
        /// `@everyone` is denied ViewChannel
        hidden_group_id: String,
        /// The member was Added there with a Welcome; the channel is deleted
        deleted_group_id: String,
        /// Seated, the creator (epoch 0): no commit added its device
        owner: Caller,
        /// Seated; its device and [`Fixture::member_second`] were Added at
        /// epoch 1
        member: Caller,
        /// The member's second device, Added at epoch 1, bound to ANOTHER
        /// session than the member's
        member_second: TestE2EEDevice,
        /// Seated; Added at epoch 1
        peer: Caller,
        /// Seated; its bound device was never Added
        joiner: Caller,
        /// Seated; Added at epoch 1, evicted at epoch 2 on its own rejoin
        /// intent (rule 6)
        evicted: Caller,
        /// Seated; Added at epoch 1, evicted at epoch 2, re-Added at epoch 3
        readded: Caller,
        /// Seated; its device was Added at epoch 1, but its session is bound
        /// to none of its devices
        unbound: Caller,
    }

    /// A protected channel seating everyone above, its Text group with
    /// three commits through the real Text commit transaction (epoch 1 Adds
    /// six devices with [`WELCOME_1`], epoch 2 evicts two on their rejoin
    /// intents, epoch 3 re-Adds one with [`WELCOME_3`]), a Call group, and a
    /// hidden and a deleted protected channel where the member was Added
    /// with a Welcome
    async fn fixture() -> Fixture {
        let harness = Box::pin(TestHarness::new()).await;
        let db = &harness.db;
        let (_, owner_session, owner_user) = harness.new_user().await;
        let member = caller(&harness, MEMBER_DEVICE_SEED).await;
        let member_second = harness
            .new_e2ee_device(
                &member.user,
                &Ulid::new().to_string(),
                MEMBER_SECOND_DEVICE_SEED,
            )
            .await;
        let peer = caller(&harness, PEER_DEVICE_SEED).await;
        let joiner = caller(&harness, JOINER_DEVICE_SEED).await;
        let evicted = caller(&harness, EVICTED_DEVICE_SEED).await;
        let readded = caller(&harness, READDED_DEVICE_SEED).await;
        let unbound = unbound_caller(&harness, UNBOUND_DEVICE_SEED).await;

        let protected = Box::pin(harness.new_protected_channel(
            &owner_user,
            &owner_session,
            &[
                &member.user,
                &peer.user,
                &joiner.user,
                &evicted.user,
                &readded.user,
                &unbound.user,
            ],
        ))
        .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let hash = group
            .seat_list_ad_sha256
            .clone()
            .expect("the group binds the genesis list");
        let owner_leaf = leaf(&protected.owner_device);

        assert_won(
            db.insert_mls_text_commit(
                &commit(
                    &group,
                    1,
                    &owner_leaf,
                    vec![
                        leaf(&member.device),
                        leaf(&member_second),
                        leaf(&peer.device),
                        leaf(&evicted.device),
                        leaf(&readded.device),
                        leaf(&unbound.device),
                    ],
                    vec![],
                    Some(WELCOME_1),
                    seconds_ago(30),
                ),
                &hash,
                0,
            )
            .await,
            "the epoch 1 Add",
        );
        for device in [&evicted.device, &readded.device] {
            db.upsert_mls_join_intent(&rejoin_intent(&group, device, seconds_ago(10)))
                .await
                .expect("the rejoin intent");
        }
        assert_won(
            db.insert_mls_text_commit(
                &commit(
                    &group,
                    2,
                    &owner_leaf,
                    vec![],
                    vec![leaf(&evicted.device), leaf(&readded.device)],
                    None,
                    seconds_ago(5),
                ),
                &hash,
                0,
            )
            .await,
            "the epoch 2 rejoin Removes",
        );
        assert_won(
            db.insert_mls_text_commit(
                &commit(
                    &group,
                    3,
                    &owner_leaf,
                    vec![leaf(&readded.device)],
                    vec![],
                    Some(WELCOME_3),
                    Timestamp::now_utc(),
                ),
                &hash,
                0,
            )
            .await,
            "the epoch 3 re-Add",
        );

        let call_channel = harness.new_channel(&protected.server).await;
        let call_group = MlsGroup {
            id: random_group_id(),
            channel_id: call_channel.id().to_string(),
            open: true,
            created_by: owner_leaf.clone(),
            created_at: Timestamp::now_utc(),
            current_epoch: 0,
            members: vec![owner_leaf],
            closed_at: None,
            superseded_by: None,
            kind: MlsGroupKind::Call,
            generation: None,
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
            pending_device_removals: vec![],
            signer_lost: None,
            rejoin_readd: vec![],
        };
        assert!(matches!(
            db.create_mls_group(&call_group, None)
                .await
                .expect("the call group"),
            MlsGroupCreateOutcome::Created
        ));

        // The member is Added with a Welcome while it can still view the
        // channel; then `@everyone` loses ViewChannel
        let (_, hidden_owner_session, hidden_owner) = harness.new_user().await;
        let hidden = Box::pin(harness.new_protected_channel(
            &hidden_owner,
            &hidden_owner_session,
            &[&member.user],
        ))
        .await;
        let hidden_group = harness
            .new_text_group(&hidden.channel, &hidden.owner_device, 0, None)
            .await;
        assert_won(
            db.insert_mls_text_commit(
                &commit(
                    &hidden_group,
                    1,
                    &leaf(&hidden.owner_device),
                    vec![leaf(&member.device)],
                    vec![],
                    Some(WELCOME_1),
                    seconds_ago(30),
                ),
                hidden_group
                    .seat_list_ad_sha256
                    .as_deref()
                    .expect("the hidden group binds its list"),
                0,
            )
            .await,
            "the hidden Add",
        );
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

        let (_, deleted_owner_session, deleted_owner) = harness.new_user().await;
        let deleted = Box::pin(harness.new_protected_channel(
            &deleted_owner,
            &deleted_owner_session,
            &[&member.user],
        ))
        .await;
        let deleted_group = harness
            .new_text_group(&deleted.channel, &deleted.owner_device, 0, None)
            .await;
        assert_won(
            db.insert_mls_text_commit(
                &commit(
                    &deleted_group,
                    1,
                    &leaf(&deleted.owner_device),
                    vec![leaf(&member.device)],
                    vec![],
                    Some(WELCOME_1),
                    seconds_ago(30),
                ),
                deleted_group
                    .seat_list_ad_sha256
                    .as_deref()
                    .expect("the deleted group binds its list"),
                0,
            )
            .await,
            "the deleted channel's Add",
        );
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted.channel.id()).await.is_err());

        Fixture {
            server_id: protected.server.id.clone(),
            channel_id: protected.channel.id().to_string(),
            text_group_id: group.id,
            call_group_id: call_group.id,
            hidden_group_id: hidden_group.id,
            deleted_group_id: deleted_group.id,
            owner: Caller {
                user: owner_user,
                session: owner_session,
                device: protected.owner_device,
            },
            member,
            member_second,
            peer,
            joiner,
            evicted,
            readded,
            unbound,
            harness,
        }
    }

    /// The caller's own bound device is served the Welcome of the newest
    /// commit that added it, exactly `{ group_id, epoch, welcome }`
    async fn own_devices_are_served(fixture: &Fixture) {
        let db = &fixture.harness.db;
        let group_id = &fixture.text_group_id;

        for (class, caller, epoch, welcome) in [
            ("member", &fixture.member, 1, WELCOME_1),
            ("peer", &fixture.peer, 1, WELCOME_1),
            // Re-added at epoch 3: that Add's Welcome, never the epoch 1 one
            ("readded", &fixture.readded, 3, WELCOME_3),
        ] {
            let served = fetch(
                db,
                &caller.user,
                &caller.session,
                group_id,
                &caller.device.device_id,
            )
            .await
            .unwrap_or_else(|error| panic!("{}: refused {:?}", class, error));
            assert_eq!(
                serde_json::to_value(&served).expect("JSON"),
                serde_json::json!({
                    "group_id": group_id,
                    "epoch": epoch,
                    "welcome": welcome
                }),
                "{}",
                class
            );
        }
    }

    /// Decision 1 (W2) on this route: every case that may not be served
    /// answers EXACTLY like a group id the server does not know (the full
    /// serialized body), for the same caller
    async fn refusals_answer_as_unknown(fixture: &Fixture) {
        let db = &fixture.harness.db;
        let media = revolt_database::voice::media_e2ee_enabled().await;
        let text = &fixture.text_group_id;
        let member = &fixture.member;
        let unregistered = format!("{:032x}", Ulid::new().0);

        // A bound, seated viewer each: only the Welcome rules refuse
        for (case, caller, group_id, device_id) in [
            (
                "another user's device",
                member,
                text,
                &fixture.peer.device.device_id,
            ),
            (
                "an own device bound to another session",
                member,
                text,
                &fixture.member_second.device_id,
            ),
            ("an unregistered device", member, text, &unregistered),
            (
                "a device no commit added",
                &fixture.joiner,
                text,
                &fixture.joiner.device.device_id,
            ),
            (
                "an evicted device",
                &fixture.evicted,
                text,
                &fixture.evicted.device.device_id,
            ),
            (
                "the creator's device",
                &fixture.owner,
                text,
                &fixture.owner.device.device_id,
            ),
            (
                "a channel the caller cannot view",
                member,
                &fixture.hidden_group_id,
                &member.device.device_id,
            ),
            (
                "a deleted channel",
                member,
                &fixture.deleted_group_id,
                &member.device.device_id,
            ),
            (
                "a Call group",
                &fixture.owner,
                &fixture.call_group_id,
                &fixture.owner.device.device_id,
            ),
        ] {
            let unknown = unknown_answer(db, &caller.user, &caller.session, device_id).await;
            let expected = if media { "NotFound" } else { "FeatureDisabled" };
            assert_eq!(refusal_type(&unknown), expected, "{}: {}", case, unknown);
            let answer = refusal_body(
                fetch(db, &caller.user, &caller.session, group_id, device_id).await,
                case,
            );
            assert_eq!(answer, unknown, "{}", case);
        }

        // The other caller classes. A bot (the member, flagged; its session
        // and device are bound, and the member holds a Welcome everywhere)
        // and an unbound session (its device holds the epoch 1 Welcome)
        let mut bot = member.user.clone();
        bot.bot = Some(BotInformation {
            owner: fixture.owner.user.id.clone(),
        });
        let unbound = &fixture.unbound;
        for (class, user, session, device_id) in [
            ("bot", &bot, &member.session, &member.device.device_id),
            (
                "unbound",
                &unbound.user,
                &unbound.session,
                &unbound.device.device_id,
            ),
        ] {
            let unknown = unknown_answer(db, user, session, device_id).await;
            // Each class gets its own answer, so the classes are real
            let expected = match (media, class) {
                (false, _) => "FeatureDisabled",
                (true, "bot") => "IsBot",
                (true, _) => "NotAuthenticated",
            };
            assert_eq!(refusal_type(&unknown), expected, "{}: {}", class, unknown);

            for (target, group_id) in [
                ("hidden", &fixture.hidden_group_id),
                ("deleted", &fixture.deleted_group_id),
                ("call", &fixture.call_group_id),
            ] {
                let answer = refusal_body(
                    fetch(db, user, session, group_id, device_id).await,
                    &format!("{class} {target}"),
                );
                assert_eq!(answer, unknown, "{} {}", class, target);
            }

            // On a channel it views, the shared caller checks answer (§7.2
            // order): with the media flag on that is the unknown-group
            // answer itself; with it off the unknown answer is the media
            // gate's, which only a viewer can tell apart (decision 17 (W2))
            let viewer = refusal_body(
                fetch(db, user, session, text, device_id).await,
                &format!("{class} viewer"),
            );
            if media {
                assert_eq!(viewer, unknown, "{} viewer", class);
            } else {
                let caller_check = if class == "bot" {
                    "IsBot"
                } else {
                    "NotAuthenticated"
                };
                assert_eq!(refusal_type(&viewer), caller_check, "{}: {}", class, viewer);
            }
        }
    }

    #[test]
    fn the_welcome_is_served_with_every_flag_on() {
        crate::util::test::rt().block_on(async {
            let fixture = Box::pin(fixture()).await;
            Box::pin(own_devices_are_served(&fixture)).await;
            Box::pin(refusals_answer_as_unknown(&fixture)).await;
        })
    }

    /// A Welcome finishes an Add already made: maintenance, not growth
    /// (§7.2 "the available gate"; decision 5 (W2))
    #[test]
    fn the_welcome_is_served_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            let fixture = Box::pin(fixture()).await;
            Box::pin(own_devices_are_served(&fixture)).await;
            Box::pin(refusals_answer_as_unknown(&fixture)).await;
        })
    }

    /// A Text group ignores the media flag; the unknown-group answer is
    /// then the media gate's, and every refusal still gives it
    #[test]
    fn the_welcome_is_served_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            let fixture = Box::pin(fixture()).await;
            Box::pin(own_devices_are_served(&fixture)).await;
            Box::pin(refusals_answer_as_unknown(&fixture)).await;
        })
    }

    #[test]
    fn the_welcome_is_served_with_growth_and_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            let fixture = Box::pin(fixture()).await;
            Box::pin(own_devices_are_served(&fixture)).await;
            Box::pin(refusals_answer_as_unknown(&fixture)).await;
        })
    }

    /// E2EE off closes the Text plane: a viewer past the caller checks meets
    /// the available gate, before the seat and every Welcome rule; a
    /// non-viewer still gets the unknown-group answer
    #[test]
    fn the_welcome_is_refused_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            the_welcome_is_refused_with_e2ee_off_case().await
        })
    }

    async fn the_welcome_is_refused_with_e2ee_off_case() {
        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let text = &fixture.text_group_id;
        let member = &fixture.member;

        for (case, caller, device_id) in [
            ("the member's own device", member, &member.device.device_id),
            (
                "an evicted device",
                &fixture.evicted,
                &fixture.evicted.device.device_id,
            ),
            (
                "another user's device",
                member,
                &fixture.peer.device.device_id,
            ),
        ] {
            let answer = refusal_body(
                fetch(db, &caller.user, &caller.session, text, device_id).await,
                case,
            );
            let value: serde_json::Value = serde_json::from_str(&answer).expect("JSON");
            assert_eq!(value["type"], "FeatureDisabled", "{}: {}", case, answer);
            assert_eq!(value["feature"], "e2ee", "{}: {}", case, answer);
        }

        let device_id = &member.device.device_id;
        let unknown = unknown_answer(db, &member.user, &member.session, device_id).await;
        let value: serde_json::Value = serde_json::from_str(&unknown).expect("JSON");
        assert_eq!(value["feature"], "media_e2ee", "{}", unknown);
        for group_id in [
            &fixture.hidden_group_id,
            &fixture.deleted_group_id,
            &fixture.call_group_id,
        ] {
            let answer = refusal_body(
                fetch(db, &member.user, &member.session, group_id, device_id).await,
                group_id,
            );
            assert_eq!(answer, unknown, "{}", group_id);
        }
    }

    /// The seat is checked after the available gate (§7.2): a member device
    /// whose user lost the seat is refused `NotSeated`, its Welcome kept
    #[test]
    fn an_unseated_caller_is_refused() {
        crate::util::test::rt().block_on(an_unseated_caller_is_refused_case())
    }

    async fn an_unseated_caller_is_refused_case() {
        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let member = &fixture.member;

        let released = db
            .release_channel_seats_for_user(
                &member.user.id,
                Some(&fixture.server_id),
                Timestamp::now_utc(),
            )
            .await
            .expect("release");
        assert_eq!(released, vec![fixture.channel_id.clone()]);
        let answer = refusal_body(
            fetch(
                db,
                &member.user,
                &member.session,
                &fixture.text_group_id,
                &member.device.device_id,
            )
            .await,
            "an unseated member",
        );
        assert_eq!(refusal_type(&answer), "NotSeated", "{}", answer);
    }

    /// A commit that added the device but stored no Welcome, and a re-Add
    /// whose row was pruned (R9) while the older Add's row is kept, both
    /// give the unknown-group answer: the kept row's epoch is not the
    /// device's `member_added.epoch`
    #[test]
    fn a_missing_or_pruned_welcome_answers_as_unknown() {
        crate::util::test::rt().block_on(a_missing_or_pruned_welcome_answers_as_unknown_case())
    }

    async fn a_missing_or_pruned_welcome_answers_as_unknown_case() {
        use revolt_database::mongodb::bson::{doc, Document};

        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let text = &fixture.text_group_id;

        // Epoch 4 Adds the joiner's device without a Welcome
        let group = db.fetch_mls_group(text).await.expect("the text group");
        assert_eq!(group.current_epoch, 3);
        assert_won(
            db.insert_mls_text_commit(
                &commit(
                    &group,
                    4,
                    &leaf(&fixture.owner.device),
                    vec![leaf(&fixture.joiner.device)],
                    vec![],
                    None,
                    Timestamp::now_utc(),
                ),
                group
                    .seat_list_ad_sha256
                    .as_deref()
                    .expect("the group binds its list"),
                0,
            )
            .await,
            "an Add without a Welcome",
        );
        let joiner = &fixture.joiner;
        let unknown =
            unknown_answer(db, &joiner.user, &joiner.session, &joiner.device.device_id).await;
        let answer = refusal_body(
            fetch(
                db,
                &joiner.user,
                &joiner.session,
                text,
                &joiner.device.device_id,
            )
            .await,
            "an Add without a Welcome",
        );
        assert_eq!(answer, unknown, "an Add without a Welcome");

        // The epoch 3 re-Add's row is pruned; the epoch 1 row still adds
        // the device, with a Welcome
        let row_id = MlsCommit::composite_id(text, 3);
        match db {
            Database::Reference(reference) => {
                let mut commits = reference.mls_commits.lock().await;
                let before = commits.len();
                commits.retain(|_, row| row.id != row_id);
                assert_eq!(commits.len() + 1, before, "one row at the id");
            }
            Database::MongoDb(mongo) => {
                let result = mongo
                    .col::<Document>("mls_commits")
                    .delete_one(doc! { "_id": &row_id })
                    .await
                    .expect("prune the row");
                assert_eq!(result.deleted_count, 1);
            }
        }
        let readded = &fixture.readded;
        let kept = db
            .fetch_mls_text_welcome(text, &readded.user.id, &readded.device.device_id)
            .await
            .expect("the Welcome read")
            .expect("the epoch 1 row");
        assert_eq!(kept.epoch, 1);
        assert_eq!(kept.welcome.as_deref(), Some(WELCOME_1));

        let unknown = unknown_answer(
            db,
            &readded.user,
            &readded.session,
            &readded.device.device_id,
        )
        .await;
        let answer = refusal_body(
            fetch(
                db,
                &readded.user,
                &readded.session,
                text,
                &readded.device.device_id,
            )
            .await,
            "a pruned re-Add",
        );
        assert_eq!(answer, unknown, "a pruned re-Add");
    }

    /// The route is mounted and in the OpenAPI spec under its path, method
    /// and tag (a route left out of `openapi_get_routes_spec!` is neither)
    #[test]
    fn the_welcome_route_is_mounted_and_documented() {
        let (routes, spec) = super::super::routes();
        let item = spec
            .paths
            .get("/groups/{group_id}/welcome")
            .unwrap_or_else(|| {
                panic!(
                    "the Welcome route is missing from the spec: {:?}",
                    spec.paths.keys().collect::<Vec<_>>()
                )
            });
        let operation = item.get.as_ref().expect("a GET operation");
        assert!(
            operation.tags.iter().any(|tag| tag == "MLS"),
            "{:?}",
            operation.tags
        );
        let route = routes
            .iter()
            .find(|route| route.name.as_deref() == Some("fetch_welcome"))
            .expect("the handler is mounted");
        assert_eq!(route.method, rocket::http::Method::Get);
    }
}
