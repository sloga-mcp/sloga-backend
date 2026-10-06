use iso8601_timestamp::Timestamp;
use revolt_database::{
    is_valid_device_id, is_valid_group_id,
    util::reference::Reference,
    voice::{get_voice_state, UserVoiceChannel},
    Channel, ChannelEntitlementState, Database, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind,
    MlsMemberDevice, Session, User, MAX_TEXT_GROUP_GENERATION,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};

use super::text::text_group_id;
use super::{Arbitrated, TextGate};

/// # Create MLS Group
///
/// Register a per-call MLS group (epoch 0, creator only) for a channel the
/// caller can access and whose call they are in.
///
/// **Create-race arbitration is channel-scoped (plan §1.2):** at most one
/// OPEN group exists per channel; a racing second creator receives **409**
/// with the existing open group id and falls into the join path for THAT
/// group. `supersedes` runs the poisoned-epoch successor flow (plan §1.4):
/// the named group is atomically closed and this one registered in its
/// place.
///
/// With `kind: Text` it registers a protected channel's Text group, or its
/// successor, instead (protected channels design 6.1, 7.2): only the device
/// that signed the channel's current seat list may create one, and the call
/// checks (media flag, voice channel, call presence) do not apply.
#[openapi(tag = "MLS")]
#[post("/groups", data = "<data>")]
pub async fn create_group(
    db: &State<Database>,
    user: User,
    session: Session,
    data: Json<v0::DataCreateMlsGroup>,
) -> Result<Arbitrated<v0::ResponseCreateMlsGroup>> {
    // Kind dispatch on the request (decision 1 (W2)). An absent kind is a
    // Call group: everything below this branch is the Call path, unchanged.
    if matches!(data.kind, Some(v0::MlsGroupKind::Text)) {
        return create_text_group(db, user, session, data.into_inner()).await;
    }

    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();

    if !is_valid_group_id(&data.group_id) {
        return Err(create_error!(FailedValidation {
            error: "invalid group id".to_string()
        }));
    }

    if let Some(supersedes) = &data.supersedes {
        if !is_valid_group_id(supersedes) {
            return Err(create_error!(FailedValidation {
                error: "invalid superseded group id".to_string()
            }));
        }
        if supersedes == &data.group_id {
            return Err(create_error!(FailedValidation {
                error: "a group cannot supersede itself".to_string()
            }));
        }
    }

    if !is_valid_device_id(&data.device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    // The creating session must be bound to a registered device
    let identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "creating device is not registered".to_string()
            })
        })?;
    identity.assert_bound_session(&session.id)?;

    // Channel authorization: existing permission machinery (plan §1.2)
    let channel = Reference::from_unchecked(&data.channel_id)
        .as_channel(db)
        .await?;
    super::require_channel_access(db, &user, &channel).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // The creator must actually be in the channel's call. Voice presence
    // lives in Redis and is only populated when a LiveKit backend is
    // configured — without one (unit tests / voice-less deployments) there
    // is no call to be in, so the check is vacuous and skipped.
    if !revolt_config::config().await.api.livekit.nodes.is_empty() {
        let user_voice_channel = UserVoiceChannel::from_channel(&channel);
        if get_voice_state(&user_voice_channel, &user.id)
            .await?
            .is_none()
        {
            return Err(create_error!(NotConnected));
        }
    }

    let group = MlsGroup {
        id: data.group_id,
        channel_id: channel.id().to_string(),
        open: true,
        created_by: MlsMemberDevice {
            user_id: user.id.clone(),
            device_id: data.device_id.clone(),
        },
        created_at: Timestamp::now_utc(),
        current_epoch: 0,
        members: vec![MlsMemberDevice {
            user_id: user.id.clone(),
            device_id: data.device_id,
        }],
        closed_at: None,
        superseded_by: None,
        kind: MlsGroupKind::Call,
        generation: None,
        seat_list_ad_sha256: None,
        pending_removals: vec![],
        member_added: vec![],
    };

    match db.create_mls_group(&group, data.supersedes.as_deref()).await? {
        MlsGroupCreateOutcome::Created => Ok(Arbitrated {
            conflict: false,
            body: Json(v0::ResponseCreateMlsGroup::Created),
        }),
        MlsGroupCreateOutcome::Conflict {
            open_group_id,
            channel_id,
        } => Ok(Arbitrated {
            conflict: true,
            body: Json(v0::ResponseCreateMlsGroup::Conflict {
                open_group_id,
                channel_id,
            }),
        }),
    }
}

/// Text group create or successor (protected channels design 6.1, 7.2),
/// in the decision 1 (W2) order, adapted to a route that names a channel
/// rather than a group:
///
/// 1. the channel and ViewChannel: a channel the caller cannot view, and a
///    channel that does not exist, both answer [`as_missing_channel`],
///    BEFORE any protected-specific check, so a non-viewer cannot tell a
///    hidden protected channel from an unprotected or a missing one
///    (decisions 17 and 18 (W2));
/// 2. the shared caller checks ([`super::require_mls_caller`]);
/// 3. request validation, the checks on the body alone;
/// 4. the growth gate (Text create is growth, decision 5 (W2));
/// 5. the 6.1 create rules: the channel is protected, its entitlement is
///    `Active`, the caller is seated, the caller is the current seat list's
///    signer creating from its signer device with this session bound to that
///    device, and the successor rule.
///
/// The media flag, the voice channel and call presence play no part. Only
/// `create_text_mls_group` is called, which re-checks the signer, the
/// generation and the successor rule inside its transaction and binds the
/// newest list's AD hash.
async fn create_text_group(
    db: &Database,
    user: User,
    session: Session,
    data: v0::DataCreateMlsGroup,
) -> Result<Arbitrated<v0::ResponseCreateMlsGroup>> {
    let Some(channel) = viewable_channel(db, &user, &data.channel_id).await else {
        return as_missing_channel(db, &user, &session).await;
    };

    super::require_mls_caller(db, &user, Some(&session)).await?;

    let generation = validate_text_request(&data, channel.id())?;

    super::require_text_gate(TextGate::Growth).await?;

    if !channel.is_protected() {
        return Err(create_error!(InvalidOperation));
    }
    match db.fetch_channel_entitlement(channel.id()).await? {
        Some(entitlement) if entitlement.state == ChannelEntitlementState::Active => {}
        _ => return Err(create_error!(InvalidOperation)),
    }
    super::require_seated(db, channel.id(), &user.id).await?;

    // Only the device that signed the CURRENT seat list creates (6.1,
    // DECISION (W0-fix)): its user, that device, and a session bound to
    // that device, not merely to one of the user's devices
    let list = db
        .fetch_seat_list(channel.id())
        .await?
        .ok_or_else(|| create_error!(InvalidOperation))?;
    if list.signer_user_id != user.id || list.signer_device_id != data.device_id {
        return Err(create_error!(NotOwner));
    }
    let signer = db
        .fetch_e2ee_identity(&user.id, &list.signer_device_id)
        .await
        .map_err(|error| match error.error_type {
            ErrorType::NotFound => invalid("creating device is not registered"),
            _ => error,
        })?;
    signer.assert_bound_session(&session.id)?;

    if let Some(superseded_id) = &data.supersedes {
        check_superseded(db, channel.id(), superseded_id, generation).await?;
    }

    let creator = MlsMemberDevice {
        user_id: user.id.clone(),
        device_id: data.device_id.clone(),
    };
    let group = MlsGroup {
        id: data.group_id,
        channel_id: channel.id().to_string(),
        open: true,
        created_by: creator.clone(),
        created_at: Timestamp::now_utc(),
        current_epoch: 0,
        members: vec![creator],
        closed_at: None,
        superseded_by: None,
        kind: MlsGroupKind::Text,
        generation: Some(generation),
        // Server-owned: the driver sets them inside its transaction
        seat_list_ad_sha256: None,
        pending_removals: vec![],
        member_added: vec![],
    };

    match db
        .create_text_mls_group(&group, data.supersedes.as_deref())
        .await?
    {
        MlsGroupCreateOutcome::Created => Ok(Arbitrated {
            conflict: false,
            body: Json(v0::ResponseCreateMlsGroup::Created),
        }),
        MlsGroupCreateOutcome::Conflict {
            open_group_id,
            channel_id,
        } => Ok(Arbitrated {
            conflict: true,
            body: Json(v0::ResponseCreateMlsGroup::Conflict {
                open_group_id,
                channel_id,
            }),
        }),
    }
}

/// The channel, when it exists and `user` can view it; `None` on ANY
/// failure, a read error included
async fn viewable_channel(db: &Database, user: &User, channel_id: &str) -> Option<Channel> {
    let channel = Reference::from_unchecked(channel_id)
        .as_channel(db)
        .await
        .ok()?;
    super::require_channel_access(db, user, &channel)
        .await
        .ok()?;
    Some(channel)
}

/// The answer a Text create gets for a channel the caller cannot view or
/// that does not exist: the shared caller checks, then `NotFound`, from this
/// one site, so the two cases carry the same body, `location` included,
/// for every caller class and under every flag
async fn as_missing_channel<T>(db: &Database, user: &User, session: &Session) -> Result<T> {
    super::require_mls_caller(db, user, Some(session)).await?;
    Err(create_error!(NotFound))
}

fn invalid(error: &str) -> revolt_result::Error {
    create_error!(FailedValidation {
        error: error.to_string()
    })
}

/// Request validation of a Text create (6.1 step 5): the checks that read
/// the body alone. Returns the generation.
fn validate_text_request(data: &v0::DataCreateMlsGroup, channel_id: &str) -> Result<u32> {
    if !is_valid_group_id(&data.group_id) {
        return Err(invalid("invalid group id"));
    }
    if let Some(supersedes) = &data.supersedes {
        if !is_valid_group_id(supersedes) {
            return Err(invalid("invalid superseded group id"));
        }
        if supersedes == &data.group_id {
            return Err(invalid("a group cannot supersede itself"));
        }
    }
    if !is_valid_device_id(&data.device_id) {
        return Err(invalid("device_id must be 128 bits of lowercase hex"));
    }

    // 3.1: the generation is stated, capped, and the id derives from it
    let generation = data
        .generation
        .ok_or_else(|| invalid("a text group needs a generation"))?;
    if generation > MAX_TEXT_GROUP_GENERATION {
        return Err(invalid("text group generation is capped at 63"));
    }
    if data.group_id != text_group_id(channel_id, generation) {
        return Err(invalid(
            "group id does not derive from the channel and generation",
        ));
    }
    if data.supersedes.is_none() && generation != 0 {
        return Err(invalid("a first text group is generation 0"));
    }

    Ok(generation)
}

/// The successor rule (6.1): `supersedes` names a Text group of this channel
/// and `generation` is its generation + 1. An unknown id, a Call group and
/// another channel's group get one answer, so the check tells the caller
/// nothing about groups outside this channel.
async fn check_superseded(
    db: &Database,
    channel_id: &str,
    superseded_id: &str,
    generation: u32,
) -> Result<()> {
    let superseded = match db.fetch_mls_group(superseded_id).await {
        Ok(group) => Some(group),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => None,
        Err(error) => return Err(error),
    };
    let Some(superseded) = superseded
        .filter(|group| group.kind == MlsGroupKind::Text && group.channel_id == channel_id)
    else {
        return Err(invalid(
            "superseded group is not a text group of this channel",
        ));
    };
    if superseded
        .generation
        .and_then(|previous| previous.checked_add(1))
        != Some(generation)
    {
        return Err(invalid(
            "successor generation must be the superseded generation + 1",
        ));
    }

    Ok(())
}

/// Text create (W2 lane B5). Flag cases are their own `#[test]`s:
/// `overwrite_config` runs once per process, so these need nextest (one
/// process per test). The test config has every flag on.
#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{create_voice_state, UserVoiceChannel},
        Account, BotInformation, Channel, ChannelEntitlementState, Database, MlsGroupCreateOutcome,
        MlsMemberDevice, PartialChannel, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::Result;
    use rocket::http::{ContentType, Header, Status};
    use rocket::serde::json::Json;
    use rocket::State;
    use ulid::Ulid;

    use super::create_group;
    use crate::routes::mls::require_channel_access;
    use crate::routes::mls::text::text_group_id;
    use crate::util::test::{
        ProtectedChannel, TestHarness, MEMBER_DEVICE_SEED, NEW_OWNER_DEVICE_SEED,
    };

    fn random_group_id() -> String {
        format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0)
    }

    /// The route, called as Rocket calls it: `(conflict, body)` or the error
    async fn create(
        harness: &TestHarness,
        user: &User,
        session: &Session,
        data: v0::DataCreateMlsGroup,
    ) -> Result<(bool, v0::ResponseCreateMlsGroup)> {
        let db = State::<Database>::get(harness.client.rocket()).expect("`Database`");
        create_group(db, user.clone(), session.clone(), Json(data))
            .await
            .map(|answer| (answer.conflict, answer.body.into_inner()))
    }

    /// The route over HTTP: the status and the raw response body
    async fn post(
        harness: &TestHarness,
        session: &Session,
        data: &v0::DataCreateMlsGroup,
    ) -> (Status, String) {
        let response = harness
            .client
            .post("/mls/groups")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(serde_json::to_string(data).expect("a JSON body"))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// A Text create of `channel_id`'s group for `generation` (the id of
    /// generation 0 when `None`)
    fn text_request(
        channel_id: &str,
        device_id: &str,
        generation: Option<u32>,
        supersedes: Option<&str>,
    ) -> v0::DataCreateMlsGroup {
        v0::DataCreateMlsGroup {
            group_id: text_group_id(channel_id, generation.unwrap_or(0)),
            channel_id: channel_id.to_string(),
            device_id: device_id.to_string(),
            supersedes: supersedes.map(str::to_string),
            kind: Some(v0::MlsGroupKind::Text),
            generation,
        }
    }

    /// The response body a refusal serializes to
    #[track_caller]
    fn refusal<T: std::fmt::Debug>(result: Result<T>, case: &str) -> String {
        match result {
            Err(error) => serde_json::to_string(&error).expect("an error body"),
            Ok(answer) => panic!("{}: served {:?}", case, answer),
        }
    }

    #[track_caller]
    fn assert_refused<T: std::fmt::Debug>(
        result: Result<T>,
        error_type: &str,
        case: &str,
    ) -> serde_json::Value {
        let body: serde_json::Value =
            serde_json::from_str(&refusal(result, case)).expect("a JSON error");
        assert_eq!(body["type"], error_type, "{}: {}", case, body);
        body
    }

    #[track_caller]
    fn assert_invalid<T: std::fmt::Debug>(result: Result<T>, message: &str, case: &str) {
        let body = assert_refused(result, "FailedValidation", case);
        assert_eq!(body["error"], message, "{}: {}", case, body);
    }

    #[track_caller]
    fn assert_disabled<T: std::fmt::Debug>(result: Result<T>, feature: &str, case: &str) {
        let body = assert_refused(result, "FeatureDisabled", case);
        assert_eq!(body["feature"], feature, "{}: {}", case, body);
    }

    #[track_caller]
    fn assert_created(result: Result<(bool, v0::ResponseCreateMlsGroup)>, case: &str) {
        match result {
            Ok((false, v0::ResponseCreateMlsGroup::Created)) => {}
            other => panic!("{}: expected Created, got {:?}", case, other),
        }
    }

    async fn assert_no_group(db: &Database, group_id: &str, case: &str) {
        assert!(
            db.fetch_mls_group(group_id).await.is_err(),
            "{}: group {} was stored",
            case,
            group_id
        );
    }

    /// A voice channel on `server` with `user` in its call (the dev config
    /// defines LiveKit nodes, so call create checks presence)
    async fn voice_channel(
        harness: &TestHarness,
        protected: &ProtectedChannel,
        user: &User,
    ) -> Channel {
        let channel = Channel::create_server_channel(
            &harness.db,
            &mut protected.server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: "Voice".to_string(),
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
        .expect("voice channel");
        create_voice_state(
            &UserVoiceChannel::from_channel(&channel),
            &user.id,
            Timestamp::now_utc(),
        )
        .await
        .expect("voice state");
        channel
    }

    /// Deny ViewChannel to `@everyone` on `channel` (the server owner keeps it)
    async fn hide(db: &Database, channel: &Channel) {
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

    /// Set the state of `channel_id`'s entitlement, or delete it (`None`),
    /// raw: no route or driver method changes it in S1
    async fn set_entitlement(
        db: &Database,
        channel_id: &str,
        state: Option<ChannelEntitlementState>,
    ) {
        let expected = state.clone();
        match db {
            Database::Reference(reference) => {
                let mut entitlements = reference.channel_entitlements.lock().await;
                let id = entitlements
                    .values()
                    .find(|entitlement| entitlement.channel_id == channel_id)
                    .map(|entitlement| entitlement.id.clone())
                    .expect("an entitlement");
                match state {
                    Some(state) => {
                        entitlements.get_mut(&id).expect("an entitlement").state = state;
                    }
                    None => {
                        entitlements.remove(&id);
                    }
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, to_bson, Document};

                let collection = mongo.col::<Document>("channel_entitlements");
                let matched = match state {
                    Some(state) => {
                        collection
                            .update_one(
                                doc! { "channel_id": channel_id },
                                doc! { "$set": { "state": to_bson(&state).expect("a state") } },
                            )
                            .await
                            .expect("raw state write")
                            .matched_count
                    }
                    None => {
                        collection
                            .delete_one(doc! { "channel_id": channel_id })
                            .await
                            .expect("raw delete")
                            .deleted_count
                    }
                };
                assert_eq!(matched, 1);
            }
        }

        let stored = db
            .fetch_channel_entitlement(channel_id)
            .await
            .expect("entitlement read");
        assert_eq!(stored.map(|entitlement| entitlement.state), expected);
    }

    struct Fixture {
        harness: TestHarness,
        owner_account: Account,
        owner: User,
        owner_session: Session,
        protected: ProtectedChannel,
    }

    /// A protected channel whose genesis list seats `members` and its owner,
    /// signed by the owner's device bound to `owner_session`. No Text group.
    async fn fixture_with(members: usize) -> (Fixture, Vec<(User, Session)>) {
        let harness = TestHarness::new().await;
        let (owner_account, owner_session, owner) = harness.new_user().await;
        let mut seated = vec![];
        for _ in 0..members {
            let (_, session, user) = harness.new_user().await;
            seated.push((user, session));
        }
        let users: Vec<&User> = seated.iter().map(|(user, _)| user).collect();
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &users)
            .await;
        assert!(protected.channel.is_protected());

        (
            Fixture {
                harness,
                owner_account,
                owner,
                owner_session,
                protected,
            },
            seated,
        )
    }

    async fn fixture() -> Fixture {
        fixture_with(0).await.0
    }

    impl Fixture {
        fn db(&self) -> &Database {
            &self.harness.db
        }

        fn channel_id(&self) -> &str {
            self.protected.channel.id()
        }

        /// The owner's (signer device's) create on the protected channel
        fn owner_request(
            &self,
            generation: Option<u32>,
            supersedes: Option<&str>,
        ) -> v0::DataCreateMlsGroup {
            text_request(
                self.channel_id(),
                &self.protected.owner_device.device_id,
                generation,
                supersedes,
            )
        }

        async fn create_as_owner(
            &self,
            data: v0::DataCreateMlsGroup,
        ) -> Result<(bool, v0::ResponseCreateMlsGroup)> {
            create(&self.harness, &self.owner, &self.owner_session, data).await
        }
    }

    #[test]
    fn the_signer_device_creates_the_first_text_group() {
        crate::util::test::rt().block_on(the_signer_device_creates_the_first_text_group_case())
    }

    async fn the_signer_device_creates_the_first_text_group_case() {
        let fixture = fixture().await;
        let db = fixture.db();
        let request = fixture.owner_request(Some(0), None);

        // Over HTTP, so the `kind` and `generation` keys reach the route
        let (status, body) = post(&fixture.harness, &fixture.owner_session, &request).await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(
            serde_json::from_str::<v0::ResponseCreateMlsGroup>(&body).expect("a response"),
            v0::ResponseCreateMlsGroup::Created
        );

        let creator = MlsMemberDevice {
            user_id: fixture.owner.id.clone(),
            device_id: fixture.protected.owner_device.device_id.clone(),
        };
        let group = db
            .fetch_mls_group(&request.group_id)
            .await
            .expect("the text group");
        assert_eq!(group.kind, revolt_database::MlsGroupKind::Text);
        assert_eq!(group.generation, Some(0));
        assert_eq!(group.channel_id, fixture.channel_id());
        assert!(group.open);
        assert_eq!(group.current_epoch, 0);
        assert_eq!(group.created_by, creator);
        assert_eq!(group.members, vec![creator]);
        let list = db
            .fetch_seat_list(fixture.channel_id())
            .await
            .expect("list read")
            .expect("the stored list");
        assert_eq!(
            group.seat_list_ad_sha256,
            Some(list.commit_ad_sha256().expect("the AD hash"))
        );

        // The same create again (a retry, or a racing creator): 409 naming
        // the open Text group
        match fixture.create_as_owner(request.clone()).await {
            Ok((
                true,
                v0::ResponseCreateMlsGroup::Conflict {
                    open_group_id,
                    channel_id,
                },
            )) => {
                assert_eq!(open_group_id, request.group_id);
                assert_eq!(channel_id, fixture.channel_id());
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    #[test]
    fn a_successor_supersedes_the_previous_generation() {
        crate::util::test::rt().block_on(a_successor_supersedes_the_previous_generation_case())
    }

    async fn a_successor_supersedes_the_previous_generation_case() {
        let fixture = fixture().await;
        let db = fixture.db();
        let first = fixture
            .harness
            .new_text_group(
                &fixture.protected.channel,
                &fixture.protected.owner_device,
                0,
                None,
            )
            .await;

        let request = fixture.owner_request(Some(1), Some(first.id.as_str()));
        assert_created(fixture.create_as_owner(request.clone()).await, "successor");

        let successor = db
            .fetch_mls_group(&request.group_id)
            .await
            .expect("the successor");
        assert_eq!(successor.kind, revolt_database::MlsGroupKind::Text);
        assert_eq!(successor.generation, Some(1));
        assert!(successor.open);
        let first = db
            .fetch_mls_group(&first.id)
            .await
            .expect("the first group");
        assert!(!first.open);
        assert_eq!(first.superseded_by, Some(request.group_id));
    }

    #[test]
    fn the_successor_rules_are_enforced() {
        crate::util::test::rt().block_on(the_successor_rules_are_enforced_case())
    }

    async fn the_successor_rules_are_enforced_case() {
        let fixture = fixture().await;
        let db = fixture.db();
        let harness = &fixture.harness;
        let first = harness
            .new_text_group(
                &fixture.protected.channel,
                &fixture.protected.owner_device,
                0,
                None,
            )
            .await;

        // Another protected channel's Text group, and a Call group stored on
        // this very channel
        let (_, other_session, other_owner) = harness.new_user().await;
        let other = harness
            .new_protected_channel(&other_owner, &other_session, &[])
            .await;
        let other_group = harness
            .new_text_group(&other.channel, &other.owner_device, 0, None)
            .await;
        let call_group = revolt_database::MlsGroup {
            id: random_group_id(),
            kind: revolt_database::MlsGroupKind::Call,
            generation: None,
            seat_list_ad_sha256: None,
            member_added: vec![],
            ..first.clone()
        };
        assert!(matches!(
            db.create_mls_group(&call_group, None)
                .await
                .expect("call group"),
            MlsGroupCreateOutcome::Created
        ));

        let unknown = random_group_id();
        let not_ours = "superseded group is not a text group of this channel";
        for (case, superseded) in [
            ("another channel's text group", other_group.id.as_str()),
            ("a call group", call_group.id.as_str()),
            ("an unknown group", unknown.as_str()),
        ] {
            assert_invalid(
                fixture
                    .create_as_owner(fixture.owner_request(Some(1), Some(superseded)))
                    .await,
                not_ours,
                case,
            );
        }

        let plus_one = "successor generation must be the superseded generation + 1";
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(2), Some(first.id.as_str())))
                .await,
            plus_one,
            "generation + 2",
        );
        // Generation 0 derives generation 0's own id, so it names itself
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(0), Some(first.id.as_str())))
                .await,
            "a group cannot supersede itself",
            "generation 0 as a successor",
        );
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(1), None))
                .await,
            "a first text group is generation 0",
            "generation 1 without supersedes",
        );

        // Nothing moved
        let first = db
            .fetch_mls_group(&first.id)
            .await
            .expect("the first group");
        assert!(first.open);
        assert_eq!(first.superseded_by, None);
        for generation in [1, 2] {
            assert_no_group(
                db,
                &text_group_id(fixture.channel_id(), generation),
                "refused successor",
            )
            .await;
        }
    }

    #[test]
    fn a_non_signer_is_refused() {
        crate::util::test::rt().block_on(a_non_signer_is_refused_case())
    }

    async fn a_non_signer_is_refused_case() {
        let (fixture, seated) = fixture_with(1).await;
        let (member, member_session) = &seated[0];
        let member_device = fixture
            .harness
            .new_e2ee_device(member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        crate::routes::mls::require_seated(fixture.db(), fixture.channel_id(), &member.id)
            .await
            .expect("the member is seated");

        for (case, device_id) in [
            ("own device", member_device.device_id.as_str()),
            (
                "the signer's device id",
                fixture.protected.owner_device.device_id.as_str(),
            ),
        ] {
            assert_refused(
                create(
                    &fixture.harness,
                    member,
                    member_session,
                    text_request(fixture.channel_id(), device_id, Some(0), None),
                )
                .await,
                "NotOwner",
                case,
            );
        }
        assert_no_group(
            fixture.db(),
            &text_group_id(fixture.channel_id(), 0),
            "non-signer",
        )
        .await;
    }

    #[test]
    fn the_signer_on_another_device_is_refused() {
        crate::util::test::rt().block_on(the_signer_on_another_device_is_refused_case())
    }

    async fn the_signer_on_another_device_is_refused_case() {
        let fixture = fixture().await;
        let db = fixture.db();
        // A second device of the owner, bound to a second session of theirs
        let second_session = fixture
            .owner_account
            .create_session(db, String::new())
            .await
            .expect("a second session");
        let second_device = fixture
            .harness
            .new_e2ee_device(&fixture.owner, &second_session.id, NEW_OWNER_DEVICE_SEED)
            .await;
        let signer_device = fixture.protected.owner_device.device_id.clone();
        let channel_id = fixture.channel_id();

        // Creating from the other device
        assert_refused(
            create(
                &fixture.harness,
                &fixture.owner,
                &second_session,
                text_request(channel_id, &second_device.device_id, Some(0), None),
            )
            .await,
            "NotOwner",
            "the other device",
        );
        // Naming the signer device from a session bound to the other device
        assert_refused(
            create(
                &fixture.harness,
                &fixture.owner,
                &second_session,
                text_request(channel_id, &signer_device, Some(0), None),
            )
            .await,
            "NotAuthenticated",
            "the signer device id, the other device's session",
        );
        // Naming the other device from the signer device's session
        assert_refused(
            fixture
                .create_as_owner(text_request(
                    channel_id,
                    &second_device.device_id,
                    Some(0),
                    None,
                ))
                .await,
            "NotOwner",
            "the other device id, the signer device's session",
        );
        assert_no_group(db, &text_group_id(channel_id, 0), "other device").await;
    }

    #[test]
    fn the_group_id_must_derive_from_the_channel_and_generation() {
        crate::util::test::rt()
            .block_on(the_group_id_must_derive_from_the_channel_and_generation_case())
    }

    async fn the_group_id_must_derive_from_the_channel_and_generation_case() {
        let fixture = fixture().await;
        let message = "group id does not derive from the channel and generation";

        for (case, group_id) in [
            (
                "another channel's id",
                text_group_id(&Ulid::new().to_string(), 0),
            ),
            ("a random id", random_group_id()),
            ("generation 1's id", text_group_id(fixture.channel_id(), 1)),
        ] {
            let request = v0::DataCreateMlsGroup {
                group_id: group_id.clone(),
                ..fixture.owner_request(Some(0), None)
            };
            assert_invalid(fixture.create_as_owner(request).await, message, case);
            assert_no_group(fixture.db(), &group_id, case).await;
        }
        assert_no_group(
            fixture.db(),
            &text_group_id(fixture.channel_id(), 0),
            "wrong id",
        )
        .await;
    }

    #[test]
    fn the_generation_is_required_and_capped() {
        crate::util::test::rt().block_on(the_generation_is_required_and_capped_case())
    }

    async fn the_generation_is_required_and_capped_case() {
        let fixture = fixture().await;
        let first = fixture
            .harness
            .new_text_group(
                &fixture.protected.channel,
                &fixture.protected.owner_device,
                0,
                None,
            )
            .await;

        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(None, None))
                .await,
            "a text group needs a generation",
            "no generation",
        );
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(None, Some(random_group_id().as_str())))
                .await,
            "a text group needs a generation",
            "no generation, a successor",
        );
        let capped = "text group generation is capped at 63";
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(64), None))
                .await,
            capped,
            "generation 64",
        );
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(64), Some(first.id.as_str())))
                .await,
            capped,
            "generation 64, a successor",
        );
        // 63 is within the cap: it is refused by the first-group rule instead
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(63), None))
                .await,
            "a first text group is generation 0",
            "generation 63",
        );
        for generation in [63, 64] {
            assert_no_group(
                fixture.db(),
                &text_group_id(fixture.channel_id(), generation),
                "capped",
            )
            .await;
        }
    }

    #[test]
    fn an_unprotected_channel_is_refused() {
        crate::util::test::rt().block_on(an_unprotected_channel_is_refused_case())
    }

    async fn an_unprotected_channel_is_refused_case() {
        let fixture = fixture().await;
        let harness = &fixture.harness;
        let device = fixture.protected.owner_device.device_id.clone();

        // An entitled, unprotected text channel
        let unprotected = harness.new_channel(&fixture.protected.server).await;
        harness.grant_entitlement(&unprotected, 10, None).await;
        // A voice channel the owner's call create would succeed on, so a Text
        // request that reached the Call create would store a group
        let voice = voice_channel(harness, &fixture.protected, &fixture.owner).await;

        for (case, channel) in [("unprotected", &unprotected), ("voice", &voice)] {
            assert!(!channel.is_protected());
            let request = text_request(channel.id(), &device, Some(0), None);
            assert_refused(
                fixture.create_as_owner(request.clone()).await,
                "InvalidOperation",
                case,
            );
            assert_no_group(fixture.db(), &request.group_id, case).await;
        }
    }

    #[test]
    fn an_inactive_or_missing_entitlement_is_refused() {
        crate::util::test::rt().block_on(an_inactive_or_missing_entitlement_is_refused_case())
    }

    async fn an_inactive_or_missing_entitlement_is_refused_case() {
        let fixture = fixture().await;
        let db = fixture.db();
        let channel_id = fixture.channel_id();
        let request = fixture.owner_request(Some(0), None);

        set_entitlement(db, channel_id, None).await;
        assert_refused(
            fixture.create_as_owner(request.clone()).await,
            "InvalidOperation",
            "no entitlement",
        );
        db.upsert_channel_entitlement(&fixture.protected.entitlement, Timestamp::now_utc())
            .await
            .expect("re-grant");

        for state in [
            ChannelEntitlementState::Grace,
            ChannelEntitlementState::Frozen,
            ChannelEntitlementState::Deleted,
        ] {
            set_entitlement(db, channel_id, Some(state.clone())).await;
            assert_refused(
                fixture.create_as_owner(request.clone()).await,
                "InvalidOperation",
                &format!("{state:?}"),
            );
        }
        assert_no_group(db, &request.group_id, "inactive").await;

        // The entitlement was the only thing in the way
        set_entitlement(db, channel_id, Some(ChannelEntitlementState::Active)).await;
        assert_created(fixture.create_as_owner(request).await, "active again");
    }

    #[test]
    fn a_signer_without_an_active_seat_is_refused() {
        crate::util::test::rt().block_on(a_signer_without_an_active_seat_is_refused_case())
    }

    async fn a_signer_without_an_active_seat_is_refused_case() {
        let fixture = fixture().await;
        let db = fixture.db();
        let released = db
            .release_channel_seats_for_user(
                &fixture.owner.id,
                Some(&fixture.protected.server.id),
                Timestamp::now_utc(),
            )
            .await
            .expect("release");
        assert_eq!(released, vec![fixture.channel_id().to_string()]);

        let request = fixture.owner_request(Some(0), None);
        assert_refused(
            fixture.create_as_owner(request.clone()).await,
            "NotSeated",
            "released",
        );
        assert_no_group(db, &request.group_id, "released").await;
    }

    #[test]
    fn call_create_is_unchanged() {
        crate::util::test::rt().block_on(call_create_is_unchanged_case())
    }

    async fn call_create_is_unchanged_case() {
        let fixture = fixture().await;
        let harness = &fixture.harness;
        let device = fixture.protected.owner_device.device_id.clone();

        // An absent kind and an explicit Call kind both create a Call group
        for kind in [None, Some(v0::MlsGroupKind::Call)] {
            let voice = voice_channel(harness, &fixture.protected, &fixture.owner).await;
            let request = v0::DataCreateMlsGroup {
                group_id: random_group_id(),
                channel_id: voice.id().to_string(),
                device_id: device.clone(),
                supersedes: None,
                kind: kind.clone(),
                generation: None,
            };
            assert_created(
                fixture.create_as_owner(request.clone()).await,
                &format!("{kind:?}"),
            );
            let group = fixture
                .db()
                .fetch_mls_group(&request.group_id)
                .await
                .expect("the call group");
            assert_eq!(group.kind, revolt_database::MlsGroupKind::Call, "{kind:?}");
            assert_eq!(group.generation, None, "{kind:?}");
            assert_eq!(group.seat_list_ad_sha256, None, "{kind:?}");
        }

        // The dispatch reads the request's kind, never the channel: a Call
        // request on the protected channel runs the Call checks
        let request = v0::DataCreateMlsGroup {
            group_id: text_group_id(fixture.channel_id(), 0),
            channel_id: fixture.channel_id().to_string(),
            device_id: device,
            supersedes: None,
            kind: None,
            generation: None,
        };
        assert_refused(
            fixture.create_as_owner(request.clone()).await,
            "NotAVoiceChannel",
            "call kind on the protected channel",
        );
        assert_no_group(fixture.db(), &request.group_id, "call kind").await;
    }

    /// One caller class of the oracle
    struct Caller {
        class: &'static str,
        user: User,
        session: Session,
        device_id: String,
        /// The answer every non-viewer request of this class gets
        expected: &'static str,
    }

    struct Oracle {
        fixture: Fixture,
        callers: Vec<Caller>,
        /// Every channel id a non-viewer must not tell apart: a hidden
        /// protected channel, a hidden unprotected one, a deleted protected
        /// one, and one that never existed
        targets: Vec<(&'static str, String)>,
    }

    async fn oracle_fixture() -> Oracle {
        let fixture = fixture().await;
        let harness = &fixture.harness;
        let db = &harness.db;
        let server = &fixture.protected.server;

        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, mut bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;
        for user in [&member, &bot, &unbound] {
            harness.join_server(server, user).await;
        }
        bot.bot = Some(BotInformation {
            owner: fixture.owner.id.clone(),
        });
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, 0x41)
            .await;
        let unbound_device = harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), 0x42)
            .await;

        hide(db, &fixture.protected.channel).await;
        let unprotected = harness.new_channel(server).await;
        hide(db, &unprotected).await;

        let (_, other_session, other_owner) = harness.new_user().await;
        let deleted = harness
            .new_protected_channel(&other_owner, &other_session, &[])
            .await;
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");

        let targets = vec![
            ("hidden protected", fixture.channel_id().to_string()),
            ("hidden unprotected", unprotected.id().to_string()),
            ("deleted protected", deleted.channel.id().to_string()),
            ("never existed", Ulid::new().to_string()),
        ];

        Oracle {
            fixture,
            callers: vec![
                Caller {
                    class: "member",
                    user: member,
                    session: member_session,
                    device_id: member_device.device_id,
                    expected: "NotFound",
                },
                Caller {
                    class: "bot",
                    user: bot,
                    session: bot_session,
                    device_id: "ab".repeat(16),
                    expected: "IsBot",
                },
                Caller {
                    class: "unbound",
                    user: unbound,
                    session: unbound_session,
                    device_id: unbound_device.device_id,
                    expected: "NotAuthenticated",
                },
            ],
            targets,
        }
    }

    /// Decisions 1, 17 and 18 (W2): for every caller class, a Text create
    /// naming a channel the caller cannot view (protected or not) or one
    /// that does not exist (deleted or never created) gets ONE answer, the
    /// same body (`location` included) and status, for a valid and a
    /// malformed request, under every flag set
    async fn hidden_and_missing_channels_answer_alike() {
        let config = revolt_config::config().await;
        let e2ee = config.features.e2ee_enabled;
        let growth = config.features.protected_channels.enabled;
        let media = revolt_database::voice::media_e2ee_enabled().await;
        let oracle = oracle_fixture().await;
        let fixture = &oracle.fixture;
        let harness = &fixture.harness;
        let db = &harness.db;

        // The targets really are what they claim to be
        let hidden = db
            .fetch_channel(fixture.channel_id())
            .await
            .expect("the hidden channel");
        let unprotected = db
            .fetch_channel(&oracle.targets[1].1)
            .await
            .expect("the hidden unprotected channel");
        assert!(hidden.is_protected());
        assert!(!unprotected.is_protected());
        for (_, channel_id) in &oracle.targets[2..] {
            assert!(db.fetch_channel(channel_id).await.is_err());
        }
        assert!(require_channel_access(db, &fixture.owner, &hidden)
            .await
            .is_ok());

        for caller in &oracle.callers {
            for channel in [&hidden, &unprotected] {
                assert!(
                    require_channel_access(db, &caller.user, channel)
                        .await
                        .is_err(),
                    "{} views {}",
                    caller.class,
                    channel.id()
                );
            }

            for malformed in [false, true] {
                let case = format!(
                    "{} {}",
                    caller.class,
                    if malformed { "malformed" } else { "valid" }
                );
                let mut answers = vec![];
                let mut http = vec![];
                for (target, channel_id) in &oracle.targets {
                    let mut request = text_request(channel_id, &caller.device_id, Some(0), None);
                    if malformed {
                        request.group_id = "zz".to_string();
                    }
                    let answer = refusal(
                        create(harness, &caller.user, &caller.session, request.clone()).await,
                        &format!("{case} {target}"),
                    );
                    answers.push((*target, answer));
                    // A bot's session cannot authenticate it as a bot over
                    // HTTP; the other classes are also compared on the wire
                    if caller.class != "bot" {
                        http.push((*target, post(harness, &caller.session, &request).await));
                    }
                }

                let (_, first) = &answers[0];
                let value: serde_json::Value = serde_json::from_str(first).expect("JSON");
                assert_eq!(value["type"], caller.expected, "{}: {}", case, first);
                for (target, answer) in &answers[1..] {
                    assert_eq!(answer, first, "{} {}", case, target);
                }
                if let Some((_, first_http)) = http.first() {
                    assert_ne!(first_http.0, Status::Ok, "{}", case);
                    for (target, answer) in &http[1..] {
                        assert_eq!(answer, first_http, "{} {} over HTTP", case, target);
                    }
                }
            }
        }

        // The owner, a viewer, is answered past the channel check: a
        // malformed request fails validation under every flag, and a valid
        // one meets the growth gate, never the media flag
        let mut malformed = fixture.owner_request(Some(0), None);
        malformed.group_id = "zz".to_string();
        assert_invalid(
            fixture.create_as_owner(malformed).await,
            "invalid group id",
            "owner malformed",
        );
        if !media {
            let call = v0::DataCreateMlsGroup {
                kind: None,
                generation: None,
                ..fixture.owner_request(Some(0), None)
            };
            assert_disabled(
                fixture.create_as_owner(call).await,
                "media_e2ee",
                "owner call create, media off",
            );
        }
        let request = fixture.owner_request(Some(0), None);
        let served = fixture.create_as_owner(request.clone()).await;
        match (e2ee, growth) {
            (false, _) => assert_disabled(served, "e2ee", "owner, e2ee off"),
            (true, false) => assert_disabled(served, "protected_channels", "owner, growth off"),
            (true, true) => {
                assert_created(served, "owner");
                let group = db
                    .fetch_mls_group(&request.group_id)
                    .await
                    .expect("the owner's group");
                assert_eq!(group.kind, revolt_database::MlsGroupKind::Text);
            }
        }
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_every_flag_on() {
        crate::util::test::rt().block_on(Box::pin(hidden_and_missing_channels_answer_alike()))
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            Box::pin(hidden_and_missing_channels_answer_alike()).await
        })
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            Box::pin(hidden_and_missing_channels_answer_alike()).await
        })
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            Box::pin(hidden_and_missing_channels_answer_alike()).await
        })
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_growth_and_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            Box::pin(hidden_and_missing_channels_answer_alike()).await
        })
    }
}
