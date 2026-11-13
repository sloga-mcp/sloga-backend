use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::{
    is_valid_device_id, is_valid_group_id, text_group_id_v2,
    util::reference::Reference,
    voice::{get_voice_state, UserVoiceChannel},
    Channel, ChannelEntitlement, Database, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind,
    MlsMemberDevice, SeatList, SeatListBody, Session, TextGroupCreator, User,
    MAX_TEXT_GROUP_GENERATION,
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
/// that signed the channel's current seat list may create one (another
/// device of its user only for a recovery successor, S2-D17d), and the call
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
        pending_device_removals: vec![],
        signer_lost: None,
        rejoin_readd: vec![],
        history_visible_at_create: None,
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
/// 4. the gate: a first create is growth (decision 5 (W2)); a successor of
///    the channel's existing Text group is recovery, the available gate
///    without the growth flag (S2-D32, #220);
/// 5. the 6.1 create rules: the channel is protected, its entitlement
///    allows Text traffic, the caller is seated, the group id derives from
///    the channel, the generation and (on a v2 channel) the stored salt,
///    the caller is the current seat list's signer user, the successor
///    rule, the creator rule ([`text_group_creator`]: the signer device, or
///    the S2-D17d recovery exception) and the successor rate limit.
///
/// The media flag, the voice channel and call presence play no part. Only
/// `create_text_mls_group_as` is called, which re-checks the creator rule,
/// the generation and the successor rule inside its transaction and binds
/// the newest list's AD hash.
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

    let generation = validate_text_request(&data)?;

    // The operation picks the gate, never a client flag: with `supersedes`
    // the successor rule below and the driver both require a Text group of
    // this channel to supersede, so the weaker gate never admits a first
    // create
    let gate = if data.supersedes.is_some() {
        TextGate::Available
    } else {
        TextGate::Growth
    };
    super::require_text_gate(gate).await?;

    if !channel.is_protected() {
        return Err(create_error!(InvalidOperation));
    }
    // Both tiers need `allows_text_traffic()` (#220)
    match db.fetch_channel_entitlement(channel.id()).await? {
        Some(entitlement) if allows_text_traffic(&entitlement) => {}
        _ => return Err(create_error!(InvalidOperation)),
    }
    super::require_seated(db, channel.id(), &user.id).await?;

    let list = db
        .fetch_seat_list(channel.id())
        .await?
        .ok_or_else(|| create_error!(InvalidOperation))?;
    let salt = group_salt(&list)?;
    check_group_id(&data.group_id, channel.id(), generation, salt.as_deref())?;

    // Only the signer USER creates; which of its devices is the creator rule
    if list.signer_user_id != user.id {
        return Err(create_error!(NotOwner));
    }
    let superseded = match &data.supersedes {
        Some(superseded_id) => {
            Some(check_superseded(db, channel.id(), superseded_id, generation).await?)
        }
        None => None,
    };
    let creator_rule = text_group_creator(
        db,
        &user,
        &session,
        &data.device_id,
        &list,
        superseded.as_ref(),
    )
    .await?;
    if let Some(superseded) = &superseded {
        check_successor_rate(db, channel.id(), superseded, salt.as_deref()).await?;
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
        pending_device_removals: vec![],
        signer_lost: None,
        rejoin_readd: vec![],
        history_visible_at_create: None,
    };

    match db
        .create_text_mls_group_as(&group, data.supersedes.as_deref(), &creator_rule)
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
/// one site, so the two cases give the same answer (status and body; the
/// body carries no `location`) for every caller class and under every flag
async fn as_missing_channel<T>(db: &Database, user: &User, session: &Session) -> Result<T> {
    super::require_mls_caller(db, user, Some(session)).await?;
    Err(create_error!(NotFound))
}

/// The entitlement predicate both Text create tiers need (6.3 "Recovery
/// gates", #220): before S5 lands it is `Active` only. S5b's
/// `ChannelEntitlement::allows_text_traffic()` (`Active` or `Grace`)
/// replaces this helper at the merge.
fn allows_text_traffic(entitlement: &ChannelEntitlement) -> bool {
    entitlement.is_active()
}

fn invalid(error: &str) -> revolt_result::Error {
    create_error!(FailedValidation {
        error: error.to_string()
    })
}

/// Request validation of a Text create (6.1 step 5): the checks that read
/// the body alone. Returns the generation. The id derivation needs the
/// stored list on a v2 channel, so it is [`check_group_id`], later.
fn validate_text_request(data: &v0::DataCreateMlsGroup) -> Result<u32> {
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

    // 3.1: the generation is stated and capped (S2-D33: 65535)
    let generation = data
        .generation
        .ok_or_else(|| invalid("a text group needs a generation"))?;
    if generation > MAX_TEXT_GROUP_GENERATION {
        return Err(invalid(&format!(
            "text group generation is capped at {MAX_TEXT_GROUP_GENERATION}"
        )));
    }
    if data.supersedes.is_none() && generation != 0 {
        return Err(invalid("a first text group is generation 0"));
    }

    Ok(generation)
}

/// The 3.1.1 salt of a v2 list (its `group_salt` line); `None` for a v1
/// list. A stored v2 body that does not parse fails the create closed.
fn group_salt(list: &SeatList) -> Result<Option<String>> {
    if !list.is_v2() {
        return Ok(None);
    }
    let lines = SeatListBody::parse(&list.body)?
        .v2
        .ok_or_else(|| invalid("stored seat list has no group salt"))?;
    Ok(Some(lines.group_salt))
}

/// The channel's derived Text group id for `generation`: v2 (3.1.1) with
/// the stored list's salt on a v2 channel, never a salt from the request
/// (#217); v1 (3.1) otherwise
fn derived_group_id(channel_id: &str, generation: u32, salt: Option<&str>) -> Result<String> {
    match salt {
        Some(salt) => text_group_id_v2(channel_id, generation, salt),
        None => Ok(text_group_id(channel_id, generation)),
    }
}

/// 3.1, 3.1.1: the group id derives from the channel and the generation
fn check_group_id(
    group_id: &str,
    channel_id: &str,
    generation: u32,
    salt: Option<&str>,
) -> Result<()> {
    if group_id != derived_group_id(channel_id, generation, salt)? {
        return Err(invalid(
            "group id does not derive from the channel and generation",
        ));
    }
    Ok(())
}

/// The 6.1 creator rule, for a caller who is the stored list's signer user,
/// with this session bound to the creating device:
///
/// - the list's signer device creates (DECISION (W0-fix));
/// - any other registered device of the signer user creates generation
///   `g + 1` (a successor) only under the S2-D17d recovery exception
///   (#213): the open group it supersedes carries `signer_lost`, OR the
///   signer device has no registered identity (the server's own directory,
///   so recovery never depends on `signer_lost` having been written).
///
/// Anything else is `NotOwner`. Both conditions are this route's reads; the
/// driver re-checks that the list it binds still names the lost device.
async fn text_group_creator(
    db: &Database,
    user: &User,
    session: &Session,
    device_id: &str,
    list: &SeatList,
    superseded: Option<&MlsGroup>,
) -> Result<TextGroupCreator> {
    let signer = match db
        .fetch_e2ee_identity(&user.id, &list.signer_device_id)
        .await
    {
        Ok(identity) => Some(identity),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => None,
        Err(error) => return Err(error),
    };

    if device_id == list.signer_device_id {
        let signer = signer.ok_or_else(|| invalid("creating device is not registered"))?;
        signer.assert_bound_session(&session.id)?;
        return Ok(TextGroupCreator::SignerDevice);
    }

    let Some(superseded) = superseded else {
        return Err(create_error!(NotOwner));
    };
    let signer_lost = superseded.open && superseded.signer_lost.is_some();
    if signer.is_some() && !signer_lost {
        return Err(create_error!(NotOwner));
    }
    let identity = db
        .fetch_e2ee_identity(&user.id, device_id)
        .await
        .map_err(|error| match error.error_type {
            ErrorType::NotFound => invalid("creating device is not registered"),
            _ => error,
        })?;
    identity.assert_bound_session(&session.id)?;

    Ok(TextGroupCreator::SignerUserRecovery {
        lost_device_id: list.signer_device_id.clone(),
    })
}

/// The successor rate window (6.1, S2-D33)
const SUCCESSOR_RATE_WINDOW_SECONDS: i64 = 24 * 60 * 60;

/// The successor rate limit (6.1, S2-D33): at most `successor_rate_per_day`
/// successors per channel per 24 h (`0`: no limit), else `InSlowmode` with
/// the seconds until the oldest counted one leaves the window.
///
/// Counted from the stored groups: a successor is a Text group of
/// generation >= 1 (only a `supersedes` create makes one), and the count
/// walks back from the group this create supersedes through each
/// generation's predecessor ([`predecessor`]) while the group is a
/// successor created within the window. Successors are created in
/// generation order, so a group outside the window ends the walk. It reads
/// at most `limit` links of two reads each.
///
/// Race: the count is read outside the create transaction, but a successor
/// supersedes the channel's OPEN group and the driver lands one create per
/// open group (a racing one gets `Conflict`), so a race cannot add more
/// than one successor beyond the limit.
async fn check_successor_rate(
    db: &Database,
    channel_id: &str,
    superseded: &MlsGroup,
    salt: Option<&str>,
) -> Result<()> {
    let limit = revolt_config::config()
        .await
        .features
        .protected_channels
        .successor_rate_per_day;
    if limit == 0 {
        return Ok(());
    }

    let now = Timestamp::now_utc();
    let window = Duration::seconds(SUCCESSOR_RATE_WINDOW_SECONDS);
    let mut counted: u32 = 0;
    let mut link = superseded.clone();
    loop {
        let Some(generation) = link.generation.filter(|generation| *generation > 0) else {
            return Ok(());
        };
        let age = now.duration_since(link.created_at);
        if age >= window {
            return Ok(());
        }
        counted += 1;
        if counted >= limit {
            let retry_after = (window - age).whole_seconds().max(1) as u64;
            return Err(create_error!(InSlowmode { retry_after }));
        }
        match predecessor(db, channel_id, &link, generation - 1, salt).await? {
            Some(previous) => link = previous,
            None => return Ok(()),
        }
    }
}

/// The Text group of `channel_id` at `generation` that `successor`
/// superseded: found at its derived id, the v2 one (with the stored salt)
/// first and then the v1 one, since a channel that moved to v2 keeps its
/// earlier v1 generations (#223). It counts only when its `superseded_by`
/// names `successor`.
async fn predecessor(
    db: &Database,
    channel_id: &str,
    successor: &MlsGroup,
    generation: u32,
    salt: Option<&str>,
) -> Result<Option<MlsGroup>> {
    let mut ids = Vec::with_capacity(2);
    if let Some(salt) = salt {
        ids.push(text_group_id_v2(channel_id, generation, salt)?);
    }
    ids.push(text_group_id(channel_id, generation));

    for id in ids {
        let group = match db.fetch_mls_group(&id).await {
            Ok(group) => group,
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => continue,
            Err(error) => return Err(error),
        };
        if group.kind == MlsGroupKind::Text
            && group.channel_id == channel_id
            && group.generation == Some(generation)
            && group.superseded_by.as_deref() == Some(successor.id.as_str())
        {
            return Ok(Some(group));
        }
    }
    Ok(None)
}

/// The successor rule (6.1): `supersedes` names a Text group of this channel
/// and `generation` is its generation + 1. An unknown id, a Call group and
/// another channel's group get one answer, so the check tells the caller
/// nothing about groups outside this channel. Returns the superseded group.
async fn check_superseded(
    db: &Database,
    channel_id: &str,
    superseded_id: &str,
    generation: u32,
) -> Result<MlsGroup> {
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

    Ok(superseded)
}

/// Text create (W2 lane B5). Flag cases are their own `#[test]`s:
/// `overwrite_config` runs once per process, so these need nextest (one
/// process per test). The test config has every flag on.
#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        text_group_id_v2,
        voice::{create_voice_state, UserVoiceChannel},
        Account, BotInformation, Channel, ChannelEntitlementState, Database, MlsGroup,
        MlsGroupCreateOutcome, MlsMemberDevice, MlsSignerLost, MlsSignerLostCause, PartialChannel,
        SeatList, SeatListBody, SeatListHistory, SeatListPreHistory, SeatListV2Lines, Session, User,
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
        ProtectedChannel, TestHarness, FIXTURE_ISSUED_AT, MEMBER_DEVICE_SEED, NEW_OWNER_DEVICE_SEED,
    };

    fn random_group_id() -> String {
        format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0)
    }

    /// A 3.1.1 group salt: 32 bytes of `byte`, as 64 lowercase hex
    fn salt_of(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn v2_group_id(channel_id: &str, generation: u32, salt: &str) -> String {
        text_group_id_v2(channel_id, generation, salt).expect("a v2 group id")
    }

    /// A whole-millisecond time: Mongo stores Int64 milliseconds, so a
    /// stored `now_utc()` would not compare equal after a round trip
    fn fixture_time() -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(Duration::milliseconds(FIXTURE_ISSUED_AT))
            .expect("a time")
    }

    /// Test-only edit of a stored group, written straight to the store on
    /// both drivers
    async fn edit_group(db: &Database, group_id: &str, edit: impl FnOnce(&mut MlsGroup)) {
        match db {
            Database::Reference(reference) => {
                edit(
                    reference
                        .mls_groups
                        .lock()
                        .await
                        .get_mut(group_id)
                        .expect("the group"),
                );
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::doc;

                let collection = mongo.col::<MlsGroup>("mls_groups");
                let mut group = collection
                    .find_one(doc! { "_id": group_id })
                    .await
                    .expect("the group read")
                    .expect("the group");
                edit(&mut group);
                let result = collection
                    .replace_one(doc! { "_id": group_id }, &group)
                    .await
                    .expect("the group write");
                assert_eq!(result.matched_count, 1, "the group");
            }
        }
    }

    /// Turn `channel_id`'s stored list into a v2 list carrying `salt`,
    /// written straight to the store: the test config keeps `formats_v2`
    /// off, and a stored v2 list keeps v2 whatever the flag says (7.1, #218)
    async fn make_v2(db: &Database, channel_id: &str, salt: &str) {
        let mut list = db
            .fetch_seat_list(channel_id)
            .await
            .expect("list read")
            .expect("the stored list");
        let mut body = SeatListBody::parse(&list.body).expect("the stored body");
        body.v2 = Some(SeatListV2Lines {
            authority_sha256: None,
            history: SeatListHistory::Visible,
            history_boundary: None,
            pre_history: SeatListPreHistory::Kept,
            group_salt: salt.to_string(),
        });
        list.body = body.build().expect("a v2 body");

        match db {
            Database::Reference(reference) => {
                reference
                    .channel_seat_lists
                    .lock()
                    .await
                    .insert(list.id.clone(), list.clone());
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::doc;

                let result = mongo
                    .col::<SeatList>("channel_seat_lists")
                    .replace_one(doc! { "_id": &list.id }, &list)
                    .await
                    .expect("the list write");
                assert_eq!(result.matched_count, 1, "the list");
            }
        }

        let stored = db
            .fetch_seat_list(channel_id)
            .await
            .expect("list read")
            .expect("the stored list");
        assert!(stored.is_v2());
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
            protocol: None,
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
            (
                "a v2 id on a v1 channel",
                v2_group_id(fixture.channel_id(), 0, &salt_of(0x5a)),
            ),
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
        // S2-D33 (#204): the cap is 65535
        let capped = "text group generation is capped at 65535";
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(65_536), None))
                .await,
            capped,
            "generation 65536",
        );
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(65_536), Some(first.id.as_str())))
                .await,
            capped,
            "generation 65536, a successor",
        );
        // 64 (the S1 cap + 1) and 65535 are within the cap: they are refused
        // by the first-group rule instead
        for generation in [64, 65_535] {
            assert_invalid(
                fixture
                    .create_as_owner(fixture.owner_request(Some(generation), None))
                    .await,
                "a first text group is generation 0",
                &format!("generation {generation}"),
            );
        }
        for generation in [64, 65_535, 65_536] {
            assert_no_group(
                fixture.db(),
                &text_group_id(fixture.channel_id(), generation),
                "capped",
            )
            .await;
        }
    }

    #[test]
    fn generations_up_to_65535_are_created() {
        crate::util::test::rt().block_on(generations_up_to_65535_are_created_case())
    }

    /// S2-D33 (#204): a successor at 64 (refused under S1's cap of 63) and
    /// at 65535 lands; 65535 has no successor. The predecessor's generation
    /// is written straight to the store: 64 route successors would meet the
    /// rate limit.
    async fn generations_up_to_65535_are_created_case() {
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

        let mut superseded = first.id.clone();
        for (previous, generation) in [(63, 64), (65_534, 65_535)] {
            edit_group(db, &superseded, |group| group.generation = Some(previous)).await;
            let request = fixture.owner_request(Some(generation), Some(superseded.as_str()));
            assert_created(
                fixture.create_as_owner(request.clone()).await,
                &format!("generation {generation}"),
            );
            let group = db
                .fetch_mls_group(&request.group_id)
                .await
                .expect("the successor");
            assert_eq!(group.generation, Some(generation));
            assert_eq!(group.kind, revolt_database::MlsGroupKind::Text);
            assert!(group.open);
            superseded = request.group_id;
        }

        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(65_536), Some(superseded.as_str())))
                .await,
            "text group generation is capped at 65535",
            "a successor of 65535",
        );
        assert!(
            db.fetch_mls_group(&superseded)
                .await
                .expect("generation 65535")
                .open
        );
    }

    #[test]
    fn a_v2_group_id_derives_from_the_stored_salt() {
        crate::util::test::rt().block_on(a_v2_group_id_derives_from_the_stored_salt_case())
    }

    /// 3.1.1 (S2-D1b, #217): on a v2 channel the id derives with the STORED
    /// list's salt, for a first group and a successor; the v1 id, another
    /// salt, another channel and another generation are refused
    async fn a_v2_group_id_derives_from_the_stored_salt_case() {
        let fixture = fixture().await;
        let db = fixture.db();
        let channel_id = fixture.channel_id();
        let salt = salt_of(0x5a);
        make_v2(db, channel_id, &salt).await;

        let message = "group id does not derive from the channel and generation";
        for (case, group_id) in [
            ("the v1 id", text_group_id(channel_id, 0)),
            ("another salt", v2_group_id(channel_id, 0, &salt_of(0xa5))),
            (
                "another channel's id",
                v2_group_id(&Ulid::new().to_string(), 0, &salt),
            ),
            ("generation 1's id", v2_group_id(channel_id, 1, &salt)),
        ] {
            let request = v0::DataCreateMlsGroup {
                group_id: group_id.clone(),
                ..fixture.owner_request(Some(0), None)
            };
            assert_invalid(fixture.create_as_owner(request).await, message, case);
            assert_no_group(db, &group_id, case).await;
        }

        let first = v0::DataCreateMlsGroup {
            group_id: v2_group_id(channel_id, 0, &salt),
            ..fixture.owner_request(Some(0), None)
        };
        assert_created(fixture.create_as_owner(first.clone()).await, "v2 first");
        let successor = v0::DataCreateMlsGroup {
            group_id: v2_group_id(channel_id, 1, &salt),
            ..fixture.owner_request(Some(1), Some(first.group_id.as_str()))
        };
        // A v1 successor id is refused on the v2 channel
        assert_invalid(
            fixture
                .create_as_owner(fixture.owner_request(Some(1), Some(first.group_id.as_str())))
                .await,
            message,
            "the v1 successor id",
        );
        assert_created(
            fixture.create_as_owner(successor.clone()).await,
            "v2 successor",
        );

        let stored = db
            .fetch_mls_group(&successor.group_id)
            .await
            .expect("the v2 successor");
        assert_eq!(stored.generation, Some(1));
        assert!(stored.open);
        let first = db
            .fetch_mls_group(&first.group_id)
            .await
            .expect("the v2 first group");
        assert_eq!(first.superseded_by, Some(successor.group_id));
    }

    /// A condition of the S2-D17d recovery exception (6.1, #213)
    #[derive(Debug, Clone, Copy)]
    enum Lost {
        /// The open group carries `signer_lost`; the signer device is still
        /// registered
        SignerLost,
        /// The signer device has no registered identity; no `signer_lost`
        /// was written
        Unregistered,
    }

    /// 6.1 recovery exception (S2-D17d, #213): once `lost` holds, another
    /// session-bound, registered device of the signer USER creates the
    /// successor `g + 1`, which carries `signer_lost` over; before it holds
    /// that device is refused, and it never creates a first group, another
    /// user's device never qualifies and an unbound device is refused. A
    /// successor is recovery-gated (S2-D32): the growth flag plays no part.
    async fn recovery_case(lost: Lost) {
        let growth = revolt_config::config()
            .await
            .features
            .protected_channels
            .enabled;
        let (fixture, seated) = fixture_with(1).await;
        let (member, member_session) = &seated[0];
        let harness = &fixture.harness;
        let db = fixture.db();
        let owner = &fixture.owner;
        let channel_id = fixture.channel_id();
        let signer_device = fixture.protected.owner_device.device_id.clone();
        let first = harness
            .new_text_group(
                &fixture.protected.channel,
                &fixture.protected.owner_device,
                0,
                None,
            )
            .await;

        let second_session = fixture
            .owner_account
            .create_session(db, String::new())
            .await
            .expect("a second session");
        let second = harness
            .new_e2ee_device(owner, &second_session.id, NEW_OWNER_DEVICE_SEED)
            .await;
        let unbound = harness
            .new_e2ee_device(owner, &Ulid::new().to_string(), 0x81)
            .await;
        let member_device = harness
            .new_e2ee_device(member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let recovery = text_request(
            channel_id,
            &second.device_id,
            Some(1),
            Some(first.id.as_str()),
        );

        // Neither condition holds yet
        assert_refused(
            create(harness, owner, &second_session, recovery.clone()).await,
            "NotOwner",
            "no recovery condition",
        );

        let signer_lost = MlsSignerLost {
            user_id: owner.id.clone(),
            device_id: signer_device.clone(),
            cause: MlsSignerLostCause::DeviceRevoked,
            at: fixture_time(),
        };
        match lost {
            Lost::SignerLost => {
                let recorded = signer_lost.clone();
                edit_group(db, &first.id, |group| group.signer_lost = Some(recorded)).await;
            }
            Lost::Unregistered => {
                assert!(db
                    .delete_e2ee_device(&owner.id, &signer_device)
                    .await
                    .expect("the identity delete"));
            }
        }

        // Never a first group (with the growth flag off, the growth gate
        // answers first)
        let answer = create(
            harness,
            owner,
            &second_session,
            text_request(channel_id, &second.device_id, Some(0), None),
        )
        .await;
        if growth {
            assert_refused(answer, "NotOwner", "a first group");
        } else {
            assert_disabled(answer, "protected_channels", "a first group, growth off");
        }
        // Never another user's device, though seated with a bound device
        assert_refused(
            create(
                harness,
                member,
                member_session,
                text_request(
                    channel_id,
                    &member_device.device_id,
                    Some(1),
                    Some(first.id.as_str()),
                ),
            )
            .await,
            "NotOwner",
            "another user's device",
        );
        // Never a device of the owner that this session is not bound to
        assert_refused(
            create(
                harness,
                owner,
                &second_session,
                text_request(
                    channel_id,
                    &unbound.device_id,
                    Some(1),
                    Some(first.id.as_str()),
                ),
            )
            .await,
            "NotAuthenticated",
            "an unbound device",
        );
        assert_no_group(db, &recovery.group_id, "refused").await;

        assert_created(
            create(harness, owner, &second_session, recovery.clone()).await,
            &format!("{lost:?}"),
        );
        let successor = db
            .fetch_mls_group(&recovery.group_id)
            .await
            .expect("the recovery successor");
        let creator = MlsMemberDevice {
            user_id: owner.id.clone(),
            device_id: second.device_id.clone(),
        };
        assert_eq!(successor.created_by, creator);
        assert_eq!(successor.members, vec![creator]);
        assert_eq!(successor.generation, Some(1));
        // #213: a successor carries `signer_lost` over; a create never sets it
        let expected = match lost {
            Lost::SignerLost => Some(signer_lost),
            Lost::Unregistered => None,
        };
        assert_eq!(successor.signer_lost, expected, "{lost:?}");
        assert!(successor.pending_removals.is_empty());
        assert!(successor.pending_device_removals.is_empty());
        let first = db
            .fetch_mls_group(&first.id)
            .await
            .expect("the first group");
        assert!(!first.open);
        assert_eq!(first.superseded_by, Some(recovery.group_id));
    }

    #[test]
    fn recovery_while_the_signer_is_lost() {
        crate::util::test::rt().block_on(recovery_case(Lost::SignerLost))
    }

    #[test]
    fn recovery_while_the_signer_device_is_unregistered() {
        crate::util::test::rt().block_on(recovery_case(Lost::Unregistered))
    }

    #[test]
    fn recovery_while_the_signer_is_lost_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            recovery_case(Lost::SignerLost).await
        })
    }

    #[test]
    fn recovery_while_the_signer_device_is_unregistered_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            recovery_case(Lost::Unregistered).await
        })
    }

    /// S2-D32 (#220): a successor of the channel's existing Text group is
    /// recovery-gated, so it needs the available gate (`e2ee_enabled`) and
    /// not the growth flag
    async fn a_successor_is_recovery_gated() {
        let e2ee = revolt_config::config().await.features.e2ee_enabled;
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
        let request = fixture.owner_request(Some(1), Some(first.id.as_str()));
        let served = fixture.create_as_owner(request.clone()).await;
        if e2ee {
            assert_created(served, "a successor");
        } else {
            assert_disabled(served, "e2ee", "a successor, e2ee off");
            assert_no_group(fixture.db(), &request.group_id, "e2ee off").await;
        }
    }

    #[test]
    fn a_successor_passes_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            a_successor_is_recovery_gated().await
        })
    }

    #[test]
    fn a_successor_is_refused_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            a_successor_is_recovery_gated().await
        })
    }

    /// The configured `successor_rate_per_day`
    async fn successor_rate() -> u32 {
        revolt_config::config()
            .await
            .features
            .protected_channels
            .successor_rate_per_day
    }

    /// Create the owner's successors `from..=to` of `previous` on the
    /// fixture channel through the route, ids from `salt` (v2) or v1;
    /// returns the last group id
    async fn successors(
        fixture: &Fixture,
        mut previous: String,
        from: u32,
        to: u32,
        salt: Option<&str>,
    ) -> String {
        for generation in from..=to {
            let mut request = fixture.owner_request(Some(generation), Some(previous.as_str()));
            if let Some(salt) = salt {
                request.group_id = v2_group_id(fixture.channel_id(), generation, salt);
            }
            assert_created(
                fixture.create_as_owner(request.clone()).await,
                &format!("successor {generation}"),
            );
            previous = request.group_id;
        }
        previous
    }

    #[test]
    fn successors_are_rate_limited_per_channel_per_day() {
        crate::util::test::rt().block_on(successors_are_rate_limited_per_channel_per_day_case())
    }

    /// 6.1 (S2-D33): `successor_rate_per_day` (10, the default) successors
    /// of one channel within 24 h land; one more is `InSlowmode` and writes
    /// nothing; another channel is not counted; once the oldest leaves the
    /// window, one more lands
    async fn successors_are_rate_limited_per_channel_per_day_case() {
        let limit = successor_rate().await;
        assert_eq!(limit, 10, "the default rate");
        let fixture = fixture().await;
        let harness = &fixture.harness;
        let db = fixture.db();
        let channel_id = fixture.channel_id();
        let first = harness
            .new_text_group(
                &fixture.protected.channel,
                &fixture.protected.owner_device,
                0,
                None,
            )
            .await;
        let last = successors(&fixture, first.id.clone(), 1, limit, None).await;

        let over = fixture.owner_request(Some(limit + 1), Some(last.as_str()));
        let body = assert_refused(
            fixture.create_as_owner(over.clone()).await,
            "InSlowmode",
            "successor N + 1",
        );
        let retry_after = body["retry_after"].as_u64().expect("retry_after");
        assert!((1..=86_400).contains(&retry_after), "{}", body);
        assert_no_group(db, &over.group_id, "over the rate").await;
        assert!(db.fetch_mls_group(&last).await.expect("the open group").open);

        // Per channel
        let (_, other_session, other_owner) = harness.new_user().await;
        let other = harness
            .new_protected_channel(&other_owner, &other_session, &[])
            .await;
        let other_first = harness
            .new_text_group(&other.channel, &other.owner_device, 0, None)
            .await;
        assert_created(
            create(
                harness,
                &other_owner,
                &other_session,
                text_request(
                    other.channel.id(),
                    &other.owner_device.device_id,
                    Some(1),
                    Some(other_first.id.as_str()),
                ),
            )
            .await,
            "another channel",
        );

        // The oldest successor leaves the 24 h window
        let aged = Timestamp::now_utc()
            .checked_sub(Duration::hours(25))
            .expect("a time");
        let oldest = text_group_id(channel_id, 1);
        edit_group(db, &oldest, |group| group.created_at = aged).await;
        assert_created(fixture.create_as_owner(over).await, "after the window");
    }

    #[test]
    fn a_zero_successor_rate_is_unlimited() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.successor_rate_per_day = 0;
            })
            .await;
            assert_eq!(successor_rate().await, 0);
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
            // More than the default rate of 10
            successors(&fixture, first.id, 1, 12, None).await;
        })
    }

    /// The rate limit counts a v2 chain (v2 ids, the stored salt) and a
    /// chain that moved from v1 to v2 (#223: its earlier generations keep
    /// their v1 ids), at a rate of 2
    #[test]
    fn the_successor_rate_follows_v2_chains() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.successor_rate_per_day = 2;
            })
            .await;
            assert_eq!(successor_rate().await, 2);
            let salt = salt_of(0x5a);

            // v2 from genesis
            let fixture = fixture().await;
            let channel_id = fixture.channel_id();
            make_v2(fixture.db(), channel_id, &salt).await;
            let first = v0::DataCreateMlsGroup {
                group_id: v2_group_id(channel_id, 0, &salt),
                ..fixture.owner_request(Some(0), None)
            };
            assert_created(fixture.create_as_owner(first.clone()).await, "v2 first");
            let last = successors(&fixture, first.group_id, 1, 2, Some(&salt)).await;
            let over = v0::DataCreateMlsGroup {
                group_id: v2_group_id(channel_id, 3, &salt),
                ..fixture.owner_request(Some(3), Some(last.as_str()))
            };
            assert_refused(
                fixture.create_as_owner(over).await,
                "InSlowmode",
                "v2 successor N + 1",
            );

            // v1 generations 0 and 1, then v2
            let fixture = self::fixture().await;
            let channel_id = fixture.channel_id();
            let first = fixture
                .harness
                .new_text_group(
                    &fixture.protected.channel,
                    &fixture.protected.owner_device,
                    0,
                    None,
                )
                .await;
            let last = successors(&fixture, first.id, 1, 1, None).await;
            make_v2(fixture.db(), channel_id, &salt).await;
            let last = successors(&fixture, last, 2, 2, Some(&salt)).await;
            let over = v0::DataCreateMlsGroup {
                group_id: v2_group_id(channel_id, 3, &salt),
                ..fixture.owner_request(Some(3), Some(last.as_str()))
            };
            assert_refused(
                fixture.create_as_owner(over).await,
                "InSlowmode",
                "mixed successor N + 1",
            );
        })
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
                protocol: None,
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
            protocol: None,
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
    /// same body (which carries no `location`) and status, for a valid, a
    /// malformed and a successor request (S2: a successor picks a different
    /// gate, after the channel check), under every flag set
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

            for variant in ["valid", "malformed", "successor"] {
                let case = format!("{} {}", caller.class, variant);
                let mut answers = vec![];
                let mut http = vec![];
                for (target, channel_id) in &oracle.targets {
                    let mut request = text_request(channel_id, &caller.device_id, Some(0), None);
                    if variant == "malformed" {
                        request.group_id = "zz".to_string();
                    }
                    if variant == "successor" {
                        let previous = text_group_id(channel_id, 0);
                        request = text_request(
                            channel_id,
                            &caller.device_id,
                            Some(1),
                            Some(previous.as_str()),
                        );
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

    /// The oracle case polled straight from the test thread overflows the
    /// default 2 MiB test stack in a debug build: measured 2026-11-12, base
    /// 12cfa219 needs 2,093,056 to 2,099,200 bytes and S4-W1 2,097,152 to
    /// 2,105,344. Run it on a thread with room, as `payments/webhook.rs`
    /// does. A panic in the case still fails the test.
    fn on_a_big_stack(case: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(case)
            .expect("test thread")
            .join()
            .expect("the case passes")
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_every_flag_on() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(Box::pin(hidden_and_missing_channels_answer_alike()))
        })
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_e2ee_off() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                revolt_config::overwrite_config(|settings| {
                    settings.features.e2ee_enabled = false;
                })
                .await;
                Box::pin(hidden_and_missing_channels_answer_alike()).await
            })
        })
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_growth_off() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                revolt_config::overwrite_config(|settings| {
                    settings.features.protected_channels.enabled = false;
                })
                .await;
                Box::pin(hidden_and_missing_channels_answer_alike()).await
            })
        })
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_media_off() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                revolt_config::overwrite_config(|settings| {
                    settings.features.media_e2ee_enabled = false;
                })
                .await;
                Box::pin(hidden_and_missing_channels_answer_alike()).await
            })
        })
    }

    #[test]
    fn hidden_and_missing_channels_answer_alike_with_growth_and_media_off() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                revolt_config::overwrite_config(|settings| {
                    settings.features.protected_channels.enabled = false;
                    settings.features.media_e2ee_enabled = false;
                })
                .await;
                Box::pin(hidden_and_missing_channels_answer_alike()).await
            })
        })
    }
}
