use revolt_database::{Database, MlsAddedProtocol, MlsGroup, Session, User, MIN_TEXT_PROTOCOL_V2};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
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
/// since). On a channel whose stored list is v2, a Welcome the route would
/// serve is refused `ProtectedClientOutdated` unless that commit recorded
/// the device at text protocol 2 or above (S4 plan appendix (2) item 4).
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

    // Minimum text protocol (S4 plan appendix (2) item 4, ruling
    // R-WELCOME): on a channel whose stored list is v2, an S1-only device
    // must never join a group whose v2 commits it cannot read. The Add
    // consumed its intent, so the protocol is the one the commit recorded.
    // Last, after every access check and every rule above, so it only ever
    // replaces a Welcome that would be served and each earlier answer is
    // unchanged. The route writes nothing, so the rows stay as they were.
    // No stored list (the channel went away meanwhile) is no Welcome
    let Some(list) = db.fetch_seat_list(&group.channel_id).await? else {
        return Ok(None);
    };
    if list.is_v2() && !recorded_protocol_meets_floor(&commit.added_protocols, &user.id, device_id)
    {
        return Err(create_error!(ProtectedClientOutdated {
            min: MIN_TEXT_PROTOCOL_V2
        }));
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

/// Whether a commit's `added_protocols` (ruling R-WELCOME) record the
/// device at a text protocol of at least [`MIN_TEXT_PROTOCOL_V2`]. Only the
/// entry of this user AND this device counts: none, or one without a
/// protocol, fails, and so does any entry for it below the floor (fail
/// closed). The protocol is CLIENT-CLAIMED: it turns an honest S1 client
/// away cleanly and protects nothing against a dishonest one.
fn recorded_protocol_meets_floor(
    added_protocols: &[MlsAddedProtocol],
    user_id: &str,
    device_id: &str,
) -> bool {
    let mut entries = added_protocols
        .iter()
        .filter(|entry| entry.user_id == user_id && entry.device_id == device_id)
        .peekable();
    entries.peek().is_some()
        && entries.all(|entry| {
            entry
                .protocol
                .is_some_and(|protocol| protocol >= MIN_TEXT_PROTOCOL_V2)
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
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        BotInformation, Channel, Database, MlsAddedProtocol, MlsCommit, MlsCommitOutcome, MlsGroup,
        MlsGroupCreateOutcome, MlsGroupKind, MlsJoinIntent, MlsMemberDevice, PartialChannel,
        SeatListBody, SeatListHistory, SeatListPreHistory, SeatListV2Lines, Server, Session,
        TextJoinPayload, User, MIN_TEXT_PROTOCOL_V2,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::Result;
    use rocket::{
        http::{Header, Status},
        serde::json::Json,
        State,
    };
    use ulid::Ulid;

    use super::super::Arbitrated;
    use super::fetch_welcome;
    use crate::util::test::{
        ProtectedChannel, TestE2EEDevice, TestHarness, FIXTURE_DEVICE_CAP, FIXTURE_ISSUED_AT,
        FIXTURE_SLOT_CAP, MEMBER_DEVICE_SEED, OWNER_DEVICE_SEED,
    };

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

    /// The `added_protocols` entry a Text commit records for `device`
    fn added_protocol(device: &TestE2EEDevice, protocol: Option<u32>) -> MlsAddedProtocol {
        MlsAddedProtocol {
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
            protocol,
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
            history_visible: None,
            added_protocols: vec![],
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
            protocol: None,
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

    /// `@everyone` loses ViewChannel on `channel`
    async fn deny_view(db: &Database, channel: &Channel) {
        let mut channel = channel.clone();
        channel
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
    }

    /// A Call group on a new channel of `server`, `creator`'s device its
    /// only member; returns its id
    async fn new_call_group(
        harness: &TestHarness,
        server: &Server,
        creator: &TestE2EEDevice,
    ) -> String {
        let call_channel = harness.new_channel(server).await;
        let creator = leaf(creator);
        let call_group = MlsGroup {
            id: random_group_id(),
            channel_id: call_channel.id().to_string(),
            open: true,
            created_by: creator.clone(),
            created_at: Timestamp::now_utc(),
            current_epoch: 0,
            members: vec![creator],
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
            history_visible_at_create: None,
        };
        assert!(matches!(
            harness
                .db
                .create_mls_group(&call_group, None)
                .await
                .expect("the call group"),
            MlsGroupCreateOutcome::Created
        ));
        call_group.id
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
        // A v1 list never reads the recorded protocol: the epoch 1 Add
        // records none, this one records 1, and both are served
        assert_won(
            db.insert_mls_text_commit(
                &MlsCommit {
                    added_protocols: vec![added_protocol(&readded.device, Some(1))],
                    ..commit(
                        &group,
                        3,
                        &owner_leaf,
                        vec![leaf(&readded.device)],
                        vec![],
                        Some(WELCOME_3),
                        Timestamp::now_utc(),
                    )
                },
                &hash,
                0,
            )
            .await,
            "the epoch 3 re-Add",
        );

        let call_group_id =
            new_call_group(&harness, &protected.server, &protected.owner_device).await;

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
        deny_view(db, &hidden.channel).await;

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
            call_group_id,
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
    /// commit that added it, exactly `{ group_id, epoch, welcome }`. The
    /// list is v1, so no recorded protocol (none, or 1) refuses it
    async fn own_devices_are_served(fixture: &Fixture) {
        let db = &fixture.harness.db;
        let group_id = &fixture.text_group_id;
        assert!(!db
            .fetch_seat_list(&fixture.channel_id)
            .await
            .expect("seat list read")
            .expect("a seat list")
            .is_v2());

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

    /// The route over HTTP, as the caller's session: status and body
    async fn fetch_http(
        harness: &TestHarness,
        session: &Session,
        group_id: &str,
        device_id: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .get(format!(
                "/mls/groups/{group_id}/welcome?device_id={device_id}"
            ))
            .header(Header::new("x-session-token", session.token.clone()))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// The refusal is exactly `ProtectedClientOutdated { min: 2 }`
    #[track_caller]
    fn outdated(result: Result<v0::ResponseTextWelcome>, case: &str) {
        let body = refusal_body(result, case);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("JSON"),
            serde_json::json!({ "type": "ProtectedClientOutdated", "min": 2 }),
            "{}",
            case
        );
    }

    /// `owner` protects a new channel through the database with a v2
    /// genesis list (4.1.1, no authority, `history: hidden`, `pre_history:
    /// kept`) seating the owner and `members`, as
    /// [`TestHarness::new_protected_channel`] does with a v1 list. Needs
    /// `formats_v2` on: protect takes a v2 genesis only then (#218).
    async fn new_v2_protected_channel(
        harness: &TestHarness,
        owner: &User,
        owner_session: &Session,
        members: &[&User],
    ) -> ProtectedChannel {
        let (server, channel) = harness.new_protectable_channel(owner).await;
        let entitlement = harness
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = harness
            .new_e2ee_device(owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        let mut seats = vec![owner.id.clone()];
        for member in members {
            harness.join_server(&server, member).await;
            seats.push(member.id.clone());
        }

        let body = SeatListBody {
            channel_id: channel.id().to_string(),
            version: 1,
            device_cap: FIXTURE_DEVICE_CAP,
            issued_at: FIXTURE_ISSUED_AT,
            signer_user_id: owner.id.clone(),
            signer_device_id: owner_device.device_id.clone(),
            seats,
            v2: Some(SeatListV2Lines {
                authority_sha256: None,
                history: SeatListHistory::Hidden,
                history_boundary: None,
                pre_history: SeatListPreHistory::Kept,
                group_salt: "ab".repeat(32),
            }),
        }
        .build()
        .expect("a canonical v2 seat list body");
        let protect = v0::DataProtectChannel {
            seat_list: v0::DataSeatList {
                signature: owner_device.sign(&body),
                body,
                signer_device_id: owner_device.device_id.clone(),
                handover: None,
                authority: None,
            },
            wipe_history: None,
        };
        harness.protect_with_db(&channel, &protect).await;
        let channel = harness
            .db
            .fetch_channel(channel.id())
            .await
            .expect("the protected channel");
        assert!(harness
            .db
            .fetch_seat_list(channel.id())
            .await
            .expect("seat list read")
            .expect("a seat list")
            .is_v2());

        ProtectedChannel {
            server,
            channel,
            entitlement,
            owner_device,
            seat_list: protect.seat_list,
        }
    }

    /// `group`'s epoch 1 commit by its creator, through the real Text
    /// commit transaction: it Adds `devices` with [`WELCOME_1`] and records
    /// `protocols` as `added_protocols`, as the commit route would
    async fn add_at_epoch_1(
        db: &Database,
        group: &MlsGroup,
        devices: &[&TestE2EEDevice],
        protocols: Vec<MlsAddedProtocol>,
        what: &str,
    ) {
        assert_won(
            db.insert_mls_text_commit(
                &MlsCommit {
                    added_protocols: protocols,
                    ..commit(
                        group,
                        1,
                        &group.created_by,
                        devices.iter().map(|device| leaf(device)).collect(),
                        vec![],
                        Some(WELCOME_1),
                        seconds_ago(30),
                    )
                },
                group
                    .seat_list_ad_sha256
                    .as_deref()
                    .expect("the group binds its list"),
                0,
            )
            .await,
            what,
        );
    }

    const AT_TWO_SEED: u8 = 0xa0;
    const AT_THREE_SEED: u8 = 0xa1;
    const AT_ONE_SEED: u8 = 0xa2;
    const WITHOUT_SEED: u8 = 0xa3;
    const ABSENT_SEED: u8 = 0xa4;

    struct V2Fixture {
        harness: TestHarness,
        /// Its owner's device ([`ProtectedChannel::owner_device`]) is the
        /// group's creator (epoch 0): no commit added it
        protected: ProtectedChannel,
        text_group_id: String,
        owner: User,
        owner_session: Session,
        /// Seated, Added at epoch 1, recorded at protocol 2: the commit's
        /// FIRST `added_protocols` entry
        at_two: Caller,
        /// Seated, Added at epoch 1, recorded at protocol 3
        at_three: Caller,
        /// Seated, Added at epoch 1, recorded at protocol 1
        at_one: Caller,
        /// Seated, Added at epoch 1, recorded with no protocol
        without: Caller,
        /// Seated, Added at epoch 1 with no entry of its own: the commit
        /// records protocol 2 for another device of its user, and for its
        /// device id under another user
        absent: Caller,
    }

    /// A channel whose stored list is v2 seating everyone above, and its
    /// Text group, whose epoch 1 Add stores [`WELCOME_1`] for five devices
    /// and records each one's protocol as the fixture names it
    async fn v2_fixture() -> V2Fixture {
        let harness = Box::pin(TestHarness::new()).await;
        let db = &harness.db;
        let (_, owner_session, owner_user) = harness.new_user().await;
        let at_two = caller(&harness, AT_TWO_SEED).await;
        let at_three = caller(&harness, AT_THREE_SEED).await;
        let at_one = caller(&harness, AT_ONE_SEED).await;
        let without = caller(&harness, WITHOUT_SEED).await;
        let absent = caller(&harness, ABSENT_SEED).await;

        let protected = Box::pin(new_v2_protected_channel(
            &harness,
            &owner_user,
            &owner_session,
            &[
                &at_two.user,
                &at_three.user,
                &at_one.user,
                &without.user,
                &absent.user,
            ],
        ))
        .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        add_at_epoch_1(
            db,
            &group,
            &[
                &at_two.device,
                &at_three.device,
                &at_one.device,
                &without.device,
                &absent.device,
            ],
            vec![
                added_protocol(&at_two.device, Some(MIN_TEXT_PROTOCOL_V2)),
                added_protocol(&at_one.device, Some(1)),
                added_protocol(&without.device, None),
                added_protocol(&at_three.device, Some(MIN_TEXT_PROTOCOL_V2 + 1)),
                MlsAddedProtocol {
                    user_id: absent.user.id.clone(),
                    device_id: format!("{:032x}", Ulid::new().0),
                    protocol: Some(MIN_TEXT_PROTOCOL_V2),
                },
                MlsAddedProtocol {
                    user_id: at_two.user.id.clone(),
                    device_id: absent.device.device_id.clone(),
                    protocol: Some(MIN_TEXT_PROTOCOL_V2),
                },
            ],
            "the v2 epoch 1 Add",
        )
        .await;

        V2Fixture {
            text_group_id: group.id,
            owner: owner_user,
            owner_session,
            protected,
            at_two,
            at_three,
            at_one,
            without,
            absent,
            harness,
        }
    }

    #[test]
    fn a_v2_welcome_needs_a_recorded_protocol_of_2() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.formats_v2 = true;
            })
            .await;
            Box::pin(a_v2_welcome_needs_a_recorded_protocol_of_2_case()).await
        })
    }

    /// S4 plan appendix (2) item 4, ruling R-WELCOME: on a channel whose
    /// stored list is v2, the Welcome is served only to a device its commit
    /// recorded at protocol 2 or above. Protocol 1, no protocol and no entry
    /// for this user AND device are `ProtectedClientOutdated { min: 2 }`
    /// (over HTTP a 400), and the refusal consumes nothing. Every earlier
    /// answer still comes first: no Welcome to serve, the seat; and a
    /// channel with no stored list serves nothing.
    async fn a_v2_welcome_needs_a_recorded_protocol_of_2_case() {
        let fixture = Box::pin(v2_fixture()).await;
        let harness = &fixture.harness;
        let db = &harness.db;
        let group_id = &fixture.text_group_id;
        let before = db.fetch_mls_group(group_id).await.expect("the text group");

        for (class, caller) in [
            ("protocol 2", &fixture.at_two),
            ("protocol 3", &fixture.at_three),
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
                    "epoch": 1,
                    "welcome": WELCOME_1
                }),
                "{}",
                class
            );
        }

        for (class, caller) in [
            ("protocol 1", &fixture.at_one),
            ("no protocol", &fixture.without),
            ("no entry for this device", &fixture.absent),
        ] {
            let device_id = &caller.device.device_id;
            for attempt in ["first", "second"] {
                outdated(
                    fetch(db, &caller.user, &caller.session, group_id, device_id).await,
                    &format!("{class}, {attempt} fetch"),
                );
            }
            let kept = db
                .fetch_mls_text_welcome(group_id, &caller.user.id, device_id)
                .await
                .expect("the Welcome read")
                .unwrap_or_else(|| panic!("{}: the row is gone", class));
            assert_eq!(kept.epoch, 1, "{}", class);
            assert_eq!(kept.welcome.as_deref(), Some(WELCOME_1), "{}", class);
        }
        assert_eq!(
            db.fetch_mls_group(group_id).await.expect("the text group"),
            before,
            "a refusal changes no group state"
        );

        let at_one = &fixture.at_one;
        let (status, body) =
            fetch_http(harness, &at_one.session, group_id, &at_one.device.device_id).await;
        assert_eq!(status, Status::BadRequest, "over HTTP: {}", body);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("JSON"),
            serde_json::json!({ "type": "ProtectedClientOutdated", "min": 2 }),
            "over HTTP"
        );

        // No Welcome to serve: the unknown-group answer, as on a v1 list
        let (owner, owner_session) = (&fixture.owner, &fixture.owner_session);
        let device_id = &fixture.protected.owner_device.device_id;
        let unknown = unknown_answer(db, owner, owner_session, device_id).await;
        let answer = refusal_body(
            fetch(db, owner, owner_session, group_id, device_id).await,
            "the creator's device",
        );
        assert_eq!(answer, unknown, "the creator's device");

        // The seat is checked first
        let released = db
            .release_channel_seats_for_user(
                &at_one.user.id,
                Some(&fixture.protected.server.id),
                Timestamp::now_utc(),
            )
            .await
            .expect("release");
        assert_eq!(released, vec![fixture.protected.channel.id().to_string()]);
        let answer = refusal_body(
            fetch(
                db,
                &at_one.user,
                &at_one.session,
                group_id,
                &at_one.device.device_id,
            )
            .await,
            "an unseated caller recorded at protocol 1",
        );
        assert_eq!(refusal_type(&answer), "NotSeated", "{}", answer);

        // No stored list: nothing is served, not even at protocol 2
        let channel_id = fixture.protected.channel.id().to_string();
        match db {
            Database::Reference(reference) => {
                let removed = reference
                    .channel_seat_lists
                    .lock()
                    .await
                    .remove(&channel_id);
                assert!(removed.is_some(), "the stored list");
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channel_seat_lists")
                    .delete_one(doc! { "_id": &channel_id })
                    .await
                    .expect("delete the stored list");
                assert_eq!(result.deleted_count, 1);
            }
        }
        let at_two = &fixture.at_two;
        let device_id = &at_two.device.device_id;
        let unknown = unknown_answer(db, &at_two.user, &at_two.session, device_id).await;
        let answer = refusal_body(
            fetch(db, &at_two.user, &at_two.session, group_id, device_id).await,
            "no stored list",
        );
        assert_eq!(answer, unknown, "no stored list");
    }

    #[test]
    fn a_v2_non_viewer_gets_the_unknown_answer_before_the_protocol_floor() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.formats_v2 = true;
            })
            .await;
            Box::pin(a_v2_non_viewer_gets_the_unknown_answer_before_the_protocol_floor_case()).await
        })
    }

    /// Oracle parity before the floor (6.1 order): a device recorded with
    /// no protocol is refused `ProtectedClientOutdated` on each v2 channel
    /// it views, and once the channel is hidden or deleted it gets EXACTLY
    /// the unknown-group answer, as for a Call group. A bot meets the
    /// caller checks first, never the floor.
    async fn a_v2_non_viewer_gets_the_unknown_answer_before_the_protocol_floor_case() {
        let fixture = Box::pin(v2_fixture()).await;
        let harness = &fixture.harness;
        let db = &harness.db;
        let media = revolt_database::voice::media_e2ee_enabled().await;
        let caller = &fixture.without;
        let device_id = &caller.device.device_id;

        let mut groups = vec![];
        for what in ["hidden", "deleted"] {
            let (_, other_session, other_owner) = harness.new_user().await;
            let protected = Box::pin(new_v2_protected_channel(
                harness,
                &other_owner,
                &other_session,
                &[&caller.user],
            ))
            .await;
            let group = harness
                .new_text_group(&protected.channel, &protected.owner_device, 0, None)
                .await;
            add_at_epoch_1(
                db,
                &group,
                &[&caller.device],
                vec![added_protocol(&caller.device, None)],
                what,
            )
            .await;
            // While the caller views it, the floor is live there
            outdated(
                fetch(db, &caller.user, &caller.session, &group.id, device_id).await,
                &format!("{what}, still viewed"),
            );
            groups.push((what, protected.channel, group.id));
        }
        let (_, hidden_channel, hidden_group_id) = &groups[0];
        deny_view(db, hidden_channel).await;
        let (_, deleted_channel, deleted_group_id) = &groups[1];
        db.delete_channel(deleted_channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted_channel.id()).await.is_err());
        let call_group_id = new_call_group(
            harness,
            &fixture.protected.server,
            &fixture.protected.owner_device,
        )
        .await;

        let mut bot = caller.user.clone();
        bot.bot = Some(BotInformation {
            owner: fixture.owner.id.clone(),
        });
        for (class, user) in [("member", &caller.user), ("bot", &bot)] {
            let unknown = unknown_answer(db, user, &caller.session, device_id).await;
            let expected = match (media, class) {
                (false, _) => "FeatureDisabled",
                (true, "bot") => "IsBot",
                (true, _) => "NotFound",
            };
            assert_eq!(refusal_type(&unknown), expected, "{}: {}", class, unknown);
            for (target, group_id) in [
                ("hidden", hidden_group_id),
                ("deleted", deleted_group_id),
                ("call", &call_group_id),
            ] {
                let answer = refusal_body(
                    fetch(db, user, &caller.session, group_id, device_id).await,
                    &format!("{class} {target}"),
                );
                assert_eq!(answer, unknown, "{} {}", class, target);
            }
        }

        // On the channel it still views: the floor for the member, the
        // caller check for the bot
        let text = &fixture.text_group_id;
        outdated(
            fetch(db, &caller.user, &caller.session, text, device_id).await,
            "the member on the viewed channel",
        );
        let answer = refusal_body(
            fetch(db, &bot, &caller.session, text, device_id).await,
            "the bot on the viewed channel",
        );
        assert_eq!(refusal_type(&answer), "IsBot", "{}", answer);
    }

    /// `caller`'s Text join intent for `group` through the real route (W2-JI),
    /// signed over the Text join payload and claiming `protocol`
    async fn send_join_intent(
        db: &Database,
        caller: &Caller,
        group: &MlsGroup,
        key_package_ref: &str,
        protocol: Option<u32>,
    ) {
        let device = &caller.device;
        let generation = group.generation.expect("a Text group generation");
        let payload = TextJoinPayload {
            user_id: caller.user.id.clone(),
            device_id: device.device_id.clone(),
            channel_id: group.channel_id.clone(),
            generation,
            group_id: group.id.clone(),
            key_package_ref: key_package_ref.to_string(),
            issued_at: FIXTURE_ISSUED_AT,
        }
        .build()
        .expect("a text join payload");
        // No SFU nodes: the Text path never lists
        let voice_client =
            revolt_database::voice::VoiceClient::new(std::collections::HashMap::new());
        Box::pin(super::super::join_intent::join_intent(
            State::from(db),
            State::from(&voice_client),
            caller.user.clone(),
            caller.session.clone(),
            group.id.clone(),
            Json(v0::DataMlsJoinIntent {
                device_id: device.device_id.clone(),
                key_package_ref: key_package_ref.to_string(),
                signature: device.sign(&payload),
                generation: Some(generation),
                issued_at: Some(FIXTURE_ISSUED_AT),
                protocol,
            }),
        ))
        .await
        .unwrap_or_else(|error| panic!("the join intent ({key_package_ref}): {:?}", error));
    }

    /// The opaque Welcome every routed Add below carries, as stored (b64)
    fn routed_welcome() -> String {
        STANDARD_NO_PAD.encode(b"opaque welcome")
    }

    /// `committer`'s commit for `group_id`'s next epoch through the real
    /// commit route (W2-CS), framed as a client frames it (design 3.12.2:
    /// the MLS prefix at `epoch - 1`, the stored list's AD, opaque bytes),
    /// with [`routed_welcome`] when it Adds; it must win
    async fn submit_next(
        db: &Database,
        committer: &Caller,
        group_id: &str,
        added: &[&TestE2EEDevice],
        removed: &[&TestE2EEDevice],
        what: &str,
    ) {
        let group = db.fetch_mls_group(group_id).await.expect("the group");
        let epoch = group.current_epoch + 1;
        let ad = db
            .fetch_seat_list(&group.channel_id)
            .await
            .expect("seat list read")
            .expect("a seat list")
            .commit_ad()
            .expect("commit ad");
        let mut bytes = vec![0x00, 0x01, 0x00, 0x02, 0x20];
        for index in 0..32 {
            bytes.push(u8::from_str_radix(&group_id[index * 2..index * 2 + 2], 16).expect("hex"));
        }
        bytes.extend_from_slice(&((epoch - 1) as u64).to_be_bytes());
        bytes.push(0x03);
        if ad.len() < 0x40 {
            bytes.push(ad.len() as u8);
        } else {
            bytes.push(0x40 | (ad.len() >> 8) as u8);
            bytes.push((ad.len() & 0xff) as u8);
        }
        bytes.extend_from_slice(&ad);
        bytes.extend_from_slice(b"opaque private message content");
        let device = |device: &&TestE2EEDevice| v0::MlsMemberDevice {
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
        };

        let outcome = Box::pin(super::super::commits_submit::submit_commit(
            State::from(db),
            committer.user.clone(),
            committer.session.clone(),
            group_id.to_string(),
            Json(v0::DataSubmitMlsCommit {
                device_id: committer.device.device_id.clone(),
                epoch,
                commit: STANDARD_NO_PAD.encode(bytes),
                welcome: (!added.is_empty()).then(routed_welcome),
                added: added.iter().map(device).collect(),
                removed: removed.iter().map(device).collect(),
            }),
        ))
        .await;
        match outcome {
            Ok(Arbitrated {
                conflict: false,
                body,
            }) => assert!(
                matches!(body.into_inner(), v0::ResponseSubmitMlsCommit::Won),
                "{}",
                what
            ),
            Ok(Arbitrated { body, .. }) => panic!("{}: lost {:?}", what, body.into_inner()),
            Err(error) => panic!("{}: refused {:?}", what, error),
        }
    }

    #[test]
    fn a_v2_welcome_is_served_after_the_routed_join_and_add() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.formats_v2 = true;
            })
            .await;
            Box::pin(a_v2_welcome_is_served_after_the_routed_join_and_add_case()).await
        })
    }

    /// End to end on a v2 channel (rulings R-WELCOME, R-REJOIN), every step
    /// through its real route: the join intent stores protocol 2, the Add
    /// records it on the commit row, and that device's Welcome is served.
    /// The contrast: the device's routed rejoin intent at protocol 2, the
    /// rule-6 eviction that consumes it into `rejoin_readd`, and the re-Add
    /// with no intent left, which records the entry's 2: the re-Add's
    /// Welcome is served too.
    async fn a_v2_welcome_is_served_after_the_routed_join_and_add_case() {
        let harness = Box::pin(TestHarness::new()).await;
        let db = &harness.db;
        let (_, owner_session, owner_user) = harness.new_user().await;
        let joiner = caller(&harness, JOINER_DEVICE_SEED).await;
        let protected = Box::pin(new_v2_protected_channel(
            &harness,
            &owner_user,
            &owner_session,
            &[&joiner.user],
        ))
        .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let owner = Caller {
            user: owner_user,
            session: owner_session,
            device: protected.owner_device,
        };
        let device_id = &joiner.device.device_id;
        let recorded = vec![added_protocol(&joiner.device, Some(MIN_TEXT_PROTOCOL_V2))];

        send_join_intent(db, &joiner, &group, "kp", Some(MIN_TEXT_PROTOCOL_V2)).await;
        submit_next(db, &owner, &group.id, &[&joiner.device], &[], "the Add").await;
        let served = fetch(db, &joiner.user, &joiner.session, &group.id, device_id)
            .await
            .unwrap_or_else(|error| panic!("the routed Add: refused {:?}", error));
        assert_eq!(
            serde_json::to_value(&served).expect("JSON"),
            serde_json::json!({
                "group_id": group.id,
                "epoch": 1,
                "welcome": routed_welcome()
            }),
            "the routed Add"
        );
        let row = db
            .fetch_mls_text_welcome(&group.id, &joiner.user.id, device_id)
            .await
            .expect("the Welcome read")
            .expect("the epoch 1 row");
        assert_eq!(row.epoch, 1);
        assert_eq!(
            row.added_protocols, recorded,
            "the Add records the intent's 2"
        );

        // The rejoin intent must be newer than the Add for rule 6
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        send_join_intent(db, &joiner, &group, "kprejoin", Some(MIN_TEXT_PROTOCOL_V2)).await;
        submit_next(
            db,
            &owner,
            &group.id,
            &[],
            &[&joiner.device],
            "the rule-6 eviction",
        )
        .await;
        let evicted = db.fetch_mls_group(&group.id).await.expect("the group");
        assert!(!evicted.has_member(&joiner.user.id, device_id));
        assert!(
            evicted
                .rejoin_readd
                .iter()
                .any(|entry| entry.user_id == joiner.user.id
                    && entry.device_id == *device_id
                    && entry.protocol == Some(MIN_TEXT_PROTOCOL_V2)),
            "the eviction records the re-Add with protocol 2: {:?}",
            evicted.rejoin_readd
        );
        assert!(db
            .fetch_mls_join_intents_for_group(&group.id)
            .await
            .expect("intents")
            .is_empty());

        submit_next(db, &owner, &group.id, &[&joiner.device], &[], "the re-Add").await;
        let served = fetch(db, &joiner.user, &joiner.session, &group.id, device_id)
            .await
            .unwrap_or_else(|error| panic!("the routed re-Add: refused {:?}", error));
        assert_eq!(
            serde_json::to_value(&served).expect("JSON"),
            serde_json::json!({
                "group_id": group.id,
                "epoch": 3,
                "welcome": routed_welcome()
            }),
            "the routed re-Add"
        );
        let row = db
            .fetch_mls_text_welcome(&group.id, &joiner.user.id, device_id)
            .await
            .expect("the Welcome read")
            .expect("the epoch 3 row");
        assert_eq!(row.epoch, 3);
        assert_eq!(
            row.added_protocols, recorded,
            "the re-Add records the entry's 2"
        );
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
