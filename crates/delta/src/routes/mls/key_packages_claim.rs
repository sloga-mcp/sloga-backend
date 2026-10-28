use std::time::Duration;

use revolt_database::{
    is_valid_device_id, is_valid_group_id, util::reference::Reference, Channel, Database, MlsGroup,
    RatelimitEvent, RatelimitEventType, Session, User, MAX_MLS_GROUP_MEMBERS,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};

use crate::routes::e2ee::require_e2ee_fetch_eligible;

use super::{GroupDispatch, TextGate, MAX_CLAIMS_PER_TARGET_PER_MINUTE};

/// # Claim MLS KeyPackages
///
/// Atomically consume one KeyPackage per target device (admission, plan
/// §1.4 step 2). At one-time exhaustion the reusable last-resort package is
/// served, flagged `reused`; a device with no packages at all reports
/// `exhausted` and admission fails LOUDLY — never weakly.
///
/// Eligibility per target: own devices always; otherwise the pair must not
/// be blocked AND either share access to the claimed group's channel
/// (call co-presence — the class that admits strangers in a server voice
/// channel) or satisfy the text-E2EE fetch gates (friends / mutual /
/// shared group DM).
///
/// For a Text group (protected channels design 6.1) the claimer must be a
/// current member device of the group and seated, the growth flag must be
/// on, and every target must be seated, hold ViewChannel, be a server
/// member and be neither a bot nor staff; any other target reports
/// `NotFound`. Blocked pairs and the friend/DM eligibility play no part.
///
/// The claimer MUST verify each returned binding signature against its own
/// pinned identity for the target — the server relay is never the trust
/// decision.
#[openapi(tag = "MLS")]
#[post("/key_packages/claim", data = "<data>")]
pub async fn claim_key_packages(
    db: &State<Database>,
    user: User,
    session: Session,
    data: Json<v0::DataClaimMlsKeyPackages>,
) -> Result<Json<v0::ResponseClaimMlsKeyPackages>> {
    // Kind dispatch is the first check (decision 1 (W2)), and no request
    // validation runs before the branch: with the media flag off an unknown
    // id stops inside the dispatch while a Text group passes it, so a
    // validation error here would tell a hidden Text group from no group
    match super::dispatch_group(db, &data.group_id).await? {
        GroupDispatch::CallOrUnknown(None) => {
            super::as_unknown_group(db, &user, Some(&session)).await
        }
        GroupDispatch::CallOrUnknown(Some(_)) => {
            claim_for_call_group(db, user, session, data).await
        }
        GroupDispatch::Text(group) => {
            claim_for_text_group(db, user, session, data.into_inner(), group).await
        }
    }
}

/// A Call group: the route as it was before Text groups existed, unchanged
/// (decision 1 (W2)). It reads the group again itself.
async fn claim_for_call_group(
    db: &State<Database>,
    user: User,
    session: Session,
    data: Json<v0::DataClaimMlsKeyPackages>,
) -> Result<Json<v0::ResponseClaimMlsKeyPackages>> {
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

    if data.targets.is_empty() || data.targets.len() > MAX_MLS_GROUP_MEMBERS {
        return Err(create_error!(FailedValidation {
            error: format!("between 1 and {MAX_MLS_GROUP_MEMBERS} targets per request")
        }));
    }

    if data
        .targets
        .iter()
        .any(|target| !is_valid_device_id(&target.device_id))
    {
        return Err(create_error!(FailedValidation {
            error: "invalid target device id".to_string()
        }));
    }

    // The claiming session must be bound to a registered device of the
    // caller (web/stolen tokens cannot claim key material)
    let claimer_identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "claiming device is not registered".to_string()
            })
        })?;
    claimer_identity.assert_bound_session(&session.id)?;

    // The claim is scoped to an OPEN group whose channel the claimer can
    // access — this anchors the co-presence eligibility class
    let group = db.fetch_mls_group(&data.group_id).await?;
    if !group.open {
        return Err(create_error!(NotFound));
    }
    let channel = Reference::from_unchecked(&group.channel_id)
        .as_channel(db)
        .await?;
    super::require_channel_access(db, &user, &channel).await?;

    let mut results = Vec::with_capacity(data.targets.len());

    for target in data.targets {
        // Per-pair rate limit (plan §1.4 racing-admitter accounting): a
        // contested join costs one claim per RACING admitter, so the budget
        // is small but non-unit
        let pair = format!("{}:{}:{}", user.id, target.user_id, target.device_id);
        if db
            .has_ratelimited(
                &pair,
                RatelimitEventType::MlsKeyPackageClaim,
                Duration::from_secs(60),
                MAX_CLAIMS_PER_TARGET_PER_MINUTE,
            )
            .await?
        {
            return Err(create_error!(InSlowmode { retry_after: 60 }));
        }
        RatelimitEvent::create(db, pair, RatelimitEventType::MlsKeyPackageClaim).await?;

        // Eligibility. NotFound deliberately covers unknown device AND
        // ineligible pair — a claim must not become a probe for device
        // inventories the caller couldn't otherwise see.
        let eligible = if target.user_id == user.id {
            true
        } else {
            match db.fetch_user(&target.user_id).await {
                Ok(target_user) => {
                    // Call co-presence: the target can access the group's
                    // channel too. Blocked pairs are refused (claim is
                    // fetch-like, slice-5 asymmetry) — require_e2ee_fetch_
                    // eligible rejects them on the fallback path, and the
                    // co-presence path checks explicitly below.
                    let blocked = matches!(
                        user.relationship_with(&target.user_id),
                        revolt_database::RelationshipStatus::Blocked
                            | revolt_database::RelationshipStatus::BlockedOther
                    );

                    if blocked {
                        false
                    } else {
                        super::require_channel_access(db, &target_user, &channel)
                            .await
                            .is_ok()
                            || require_e2ee_fetch_eligible(db, &user, &target_user)
                                .await
                                .is_ok()
                    }
                }
                Err(_) => false,
            }
        };

        if !eligible {
            results.push(v0::MlsClaimResult {
                user_id: target.user_id,
                device_id: target.device_id,
                status: v0::MlsClaimStatus::NotFound,
            });
            continue;
        }

        // Unknown/revoked devices report NotFound (device changes are loud)
        if db
            .fetch_e2ee_identity(&target.user_id, &target.device_id)
            .await
            .is_err()
        {
            results.push(v0::MlsClaimResult {
                user_id: target.user_id,
                device_id: target.device_id,
                status: v0::MlsClaimStatus::NotFound,
            });
            continue;
        }

        // Atomic consume; last-resort at exhaustion (flagged so the client
        // can prefer re-claiming a one-time package later — plan §2.2.1)
        let status = match db
            .consume_mls_key_package(&target.user_id, &target.device_id)
            .await?
        {
            Some(package) => v0::MlsClaimStatus::Claimed {
                key_package_ref: package.key_package_ref,
                key_package: package.key_package,
                mls_signature_key: package.mls_signature_key,
                binding_signature: package.binding_signature,
                reused: false,
            },
            None => match db
                .fetch_mls_last_resort_key_package(&target.user_id, &target.device_id)
                .await?
            {
                Some(package) => v0::MlsClaimStatus::Claimed {
                    key_package_ref: package.key_package_ref,
                    key_package: package.key_package,
                    mls_signature_key: package.mls_signature_key,
                    binding_signature: package.binding_signature,
                    reused: true,
                },
                None => v0::MlsClaimStatus::Exhausted,
            },
        };

        results.push(v0::MlsClaimResult {
            user_id: target.user_id,
            device_id: target.device_id,
            status,
        });
    }

    Ok(Json(v0::ResponseClaimMlsKeyPackages { results }))
}

/// A Text group, in the design 6.1 order: the group's channel and
/// ViewChannel (a missing channel, or one the caller cannot view, answers
/// exactly like a group id the server does not know) -> the caller checks
/// -> request validation -> the growth gate (decision 5 (W2): a claim is
/// growth) -> seated -> the claim rules.
async fn claim_for_text_group(
    db: &Database,
    user: User,
    session: Session,
    data: v0::DataClaimMlsKeyPackages,
    group: MlsGroup,
) -> Result<Json<v0::ResponseClaimMlsKeyPackages>> {
    let Ok(channel) = db.fetch_channel(&group.channel_id).await else {
        return super::as_unknown_group(db, &user, Some(&session)).await;
    };
    if super::require_channel_access(db, &user, &channel)
        .await
        .is_err()
    {
        return super::as_unknown_group(db, &user, Some(&session)).await;
    }

    super::require_mls_caller(db, &user, Some(&session)).await?;

    validate_claim_request(&data)?;
    // The claiming device is a registered device of the caller, bound to
    // this session (web or stolen tokens cannot claim key material)
    let claimer_identity = match db.fetch_e2ee_identity(&user.id, &data.device_id).await {
        Ok(identity) => identity,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return Err(create_error!(FailedValidation {
                error: "claiming device is not registered".to_string()
            }));
        }
        Err(error) => return Err(error),
    };
    claimer_identity.assert_bound_session(&session.id)?;

    super::require_text_gate(TextGate::Growth).await?;
    super::require_seated(db, &group.channel_id, &user.id).await?;

    // A claim admits a device into an OPEN group, and only a current member
    // device admits (decision 7 (W2))
    if !group.open {
        return Err(create_error!(NotFound));
    }
    if !group
        .members
        .iter()
        .any(|member| member.user_id == user.id && member.device_id == data.device_id)
    {
        return Err(create_error!(NotSeated));
    }

    let mut results = Vec::with_capacity(data.targets.len());

    for target in data.targets {
        // The Call route's per-pair rate limit, counted before eligibility
        // as there
        let pair = format!("{}:{}:{}", user.id, target.user_id, target.device_id);
        if db
            .has_ratelimited(
                &pair,
                RatelimitEventType::MlsKeyPackageClaim,
                Duration::from_secs(60),
                MAX_CLAIMS_PER_TARGET_PER_MINUTE,
            )
            .await?
        {
            return Err(create_error!(InSlowmode { retry_after: 60 }));
        }
        RatelimitEvent::create(db, pair, RatelimitEventType::MlsKeyPackageClaim).await?;

        // NotFound covers an ineligible target AND an unknown device, so a
        // claim is no probe for who is seated or which devices exist
        let status = if text_target_eligible(db, &channel, &target.user_id).await? {
            claim_text_target(db, &target).await?
        } else {
            v0::MlsClaimStatus::NotFound
        };

        results.push(v0::MlsClaimResult {
            user_id: target.user_id,
            device_id: target.device_id,
            status,
        });
    }

    Ok(Json(v0::ResponseClaimMlsKeyPackages { results }))
}

/// The claim request's own shape: the Call route's checks, for the Text
/// branch (design 6.1 step 5)
fn validate_claim_request(data: &v0::DataClaimMlsKeyPackages) -> Result<()> {
    if !is_valid_group_id(&data.group_id) {
        return Err(create_error!(FailedValidation {
            error: "invalid group id".to_string()
        }));
    }

    if data.targets.is_empty() || data.targets.len() > MAX_MLS_GROUP_MEMBERS {
        return Err(create_error!(FailedValidation {
            error: format!("between 1 and {MAX_MLS_GROUP_MEMBERS} targets per request")
        }));
    }

    if data
        .targets
        .iter()
        .any(|target| !is_valid_device_id(&target.device_id))
    {
        return Err(create_error!(FailedValidation {
            error: "invalid target device id".to_string()
        }));
    }

    Ok(())
}

/// Whether a Text group of `channel` may admit `target_user_id`: seated and
/// ViewChannel (design 6.1), a server member, neither a bot nor `privileged`
/// (decision 7 (W2)). The claimer's own devices take the same rule. A read
/// that fails for any reason other than "not found" is an error, never an
/// eligible target.
async fn text_target_eligible(
    db: &Database,
    channel: &Channel,
    target_user_id: &str,
) -> Result<bool> {
    let Some(server_id) = channel.server() else {
        return Ok(false);
    };

    let target = match db.fetch_user(target_user_id).await {
        Ok(target) => target,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    };
    if target.bot.is_some() || target.privileged {
        return Ok(false);
    }

    match db.fetch_member(server_id, &target.id).await {
        Ok(_) => {}
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    }

    if super::require_channel_access(db, &target, channel)
        .await
        .is_err()
    {
        return Ok(false);
    }

    match super::require_seated(db, channel.id(), &target.id).await {
        Ok(()) => Ok(true),
        Err(error) if matches!(error.error_type, ErrorType::NotSeated) => Ok(false),
        Err(error) => Err(error),
    }
}

/// One eligible target's package for a Text claim: an unknown or revoked
/// device reports `NotFound`; otherwise a one-time package, the last-resort
/// one at exhaustion (`reused`), or `Exhausted`
async fn claim_text_target(
    db: &Database,
    target: &v0::MlsMemberDevice,
) -> Result<v0::MlsClaimStatus> {
    match db
        .fetch_e2ee_identity(&target.user_id, &target.device_id)
        .await
    {
        Ok(_) => {}
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return Ok(v0::MlsClaimStatus::NotFound);
        }
        Err(error) => return Err(error),
    }

    if let Some(package) = db
        .consume_mls_key_package(&target.user_id, &target.device_id)
        .await?
    {
        return Ok(v0::MlsClaimStatus::Claimed {
            key_package_ref: package.key_package_ref,
            key_package: package.key_package,
            mls_signature_key: package.mls_signature_key,
            binding_signature: package.binding_signature,
            reused: false,
        });
    }

    Ok(
        match db
            .fetch_mls_last_resort_key_package(&target.user_id, &target.device_id)
            .await?
        {
            Some(package) => v0::MlsClaimStatus::Claimed {
                key_package_ref: package.key_package_ref,
                key_package: package.key_package,
                mls_signature_key: package.mls_signature_key,
                binding_signature: package.binding_signature,
                reused: true,
            },
            None => v0::MlsClaimStatus::Exhausted,
        },
    )
}

/// Text-group claims (protected channels design 6.1). Each flag case is its
/// own `#[test]`: `overwrite_config` runs once per process, BEFORE the
/// harness primes the config cache, so these need nextest (one process per
/// test). The test config has every flag on.
#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        BotInformation, Database, MemberCompositeKey, MlsKeyPackage, PartialChannel, PartialUser,
        RelationshipStatus, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::Result;
    use rocket::{
        http::{ContentType, Header, Status},
        serde::json::Json,
        State,
    };
    use ulid::Ulid;

    use super::claim_key_packages;
    use crate::routes::mls::{
        dispatch_group, require_channel_access, require_seated, GroupDispatch,
    };
    use crate::util::test::{TestE2EEDevice, TestHarness, MEMBER_DEVICE_SEED};

    /// A device id no device has
    const UNREGISTERED_DEVICE: &str = "abababababababababababababababab";

    /// Store one KeyPackage for `device`: a one-time package, or its
    /// last-resort one
    async fn publish(db: &Database, device: &TestE2EEDevice, reference: &str, last_resort: bool) {
        let now = Timestamp::now_utc();
        db.insert_mls_key_packages(&[MlsKeyPackage {
            id: MlsKeyPackage::composite_id(&device.user_id, &device.device_id, reference),
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
            key_package_ref: reference.to_string(),
            key_package: format!("package {reference}"),
            mls_signature_key: "signature key".to_string(),
            binding_signature: "binding signature".to_string(),
            last_resort,
            expires_at: now.checked_add(Duration::days(1)).expect("an expiry"),
            created_at: now,
        }])
        .await
        .expect("`MlsKeyPackage`");
    }

    /// The one-time packages `device` has left
    async fn packages_left(db: &Database, device: &TestE2EEDevice) -> u64 {
        db.count_mls_key_packages(&device.user_id, &device.device_id)
            .await
            .expect("a package count")
    }

    fn claim_body(
        device_id: &str,
        group_id: &str,
        targets: &[(&str, &str)],
    ) -> v0::DataClaimMlsKeyPackages {
        v0::DataClaimMlsKeyPackages {
            device_id: device_id.to_string(),
            group_id: group_id.to_string(),
            targets: targets
                .iter()
                .map(|(user_id, device_id)| v0::MlsMemberDevice {
                    user_id: user_id.to_string(),
                    device_id: device_id.to_string(),
                })
                .collect(),
        }
    }

    /// The handler, called directly. A bot holds no session, so the bot
    /// caller class can only reach the handler's own bot check this way.
    async fn claim(
        db: &Database,
        user: &User,
        session: &Session,
        body: &v0::DataClaimMlsKeyPackages,
    ) -> Result<v0::ResponseClaimMlsKeyPackages> {
        claim_key_packages(
            State::from(db),
            user.clone(),
            session.clone(),
            Json(body.clone()),
        )
        .await
        .map(Json::into_inner)
    }

    /// The same request over HTTP: the status and the full response body
    async fn claim_http(
        harness: &TestHarness,
        session: &Session,
        body: &v0::DataClaimMlsKeyPackages,
    ) -> (Status, String) {
        let response = harness
            .client
            .post("/mls/key_packages/claim")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(serde_json::to_string(body).expect("a request body"))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// A served claim's result statuses, in request order
    #[track_caller]
    fn served(status: Status, body: &str, case: &str) -> Vec<v0::MlsClaimStatus> {
        assert_eq!(status, Status::Ok, "{}: {}", case, body);
        let response: v0::ResponseClaimMlsKeyPackages =
            serde_json::from_str(body).expect("a claim response");
        response
            .results
            .into_iter()
            .map(|result| result.status)
            .collect()
    }

    /// The `status` tag of each result (`Claimed`, `Exhausted`, `NotFound`)
    fn tags(statuses: &[v0::MlsClaimStatus]) -> Vec<String> {
        statuses
            .iter()
            .map(|status| {
                serde_json::to_value(status).expect("a status")["status"]
                    .as_str()
                    .expect("a status tag")
                    .to_string()
            })
            .collect()
    }

    /// The body a refusal serializes to
    #[track_caller]
    fn refusal(result: Result<v0::ResponseClaimMlsKeyPackages>, case: &str) -> String {
        match result {
            Err(error) => serde_json::to_string(&error).expect("an error body"),
            Ok(response) => panic!("{}: served {:?}", case, response),
        }
    }

    /// A refusal over HTTP: its status and its error `type`
    #[track_caller]
    fn refused(answer: &(Status, String), status: Status, error_type: &str, case: &str) {
        assert_eq!(answer.0, status, "{}: {}", case, answer.1);
        let body: serde_json::Value = serde_json::from_str(&answer.1).expect("an error body");
        assert_eq!(body["type"], error_type, "{}: {}", case, answer.1);
    }

    /// One caller class of the oracle: the caller, its session and the
    /// device it claims with
    struct Caller {
        class: &'static str,
        user: User,
        session: Session,
        device_id: String,
    }

    struct Oracle {
        harness: TestHarness,
        owner: User,
        owner_session: Session,
        owner_device: TestE2EEDevice,
        callers: Vec<Caller>,
        hidden_group_id: String,
        deleted_group_id: String,
        unknown_group_id: String,
    }

    /// A protected channel whose Text group exists but which members cannot
    /// view (`@everyone` denied ViewChannel; the member caller is SEATED, a
    /// seat that lost access), a second protected channel deleted under its
    /// Text group, and one caller of each class: a member with a bound
    /// session, a bot (a member, no device) and a member whose session is
    /// bound to none of its devices
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
        publish(db, &hidden.owner_device, "owner-0", false).await;

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
            owner_device: hidden.owner_device,
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
                    device_id: UNREGISTERED_DEVICE.to_string(),
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
            unknown_group_id: format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0),
        }
    }

    /// The oracle's request shapes for `group_id`: a valid claim of the
    /// owner's device, and two malformed ones
    fn oracle_requests(
        oracle: &Oracle,
        device_id: &str,
        group_id: &str,
    ) -> Vec<(&'static str, v0::DataClaimMlsKeyPackages)> {
        let owner = (
            oracle.owner.id.as_str(),
            oracle.owner_device.device_id.as_str(),
        );
        vec![
            ("valid", claim_body(device_id, group_id, &[owner])),
            ("no targets", claim_body(device_id, group_id, &[])),
            (
                "bad target device",
                claim_body(device_id, group_id, &[(owner.0, "not a device")]),
            ),
        ]
    }

    /// Decision 1 (W2), design 6.1 invariant: for every caller class, a Text
    /// group whose channel the caller cannot view, and one whose channel was
    /// deleted, answer a claim EXACTLY as a group id the server does not
    /// know (status and full body; the body carries no `location`), for a
    /// valid and a malformed request, under the current flags
    async fn hidden_and_deleted_text_groups_claim_as_unknown() {
        let oracle = oracle_fixture().await;
        let db = &oracle.harness.db;
        let features = revolt_config::config().await.features;
        let media = revolt_database::voice::media_e2ee_enabled().await;

        // Both groups are stored Text groups, so the oracle compares a real
        // Text path with the unknown path
        for group_id in [&oracle.hidden_group_id, &oracle.deleted_group_id] {
            assert!(
                matches!(
                    dispatch_group(db, group_id).await,
                    Ok(GroupDispatch::Text(_))
                ),
                "{} is not dispatched as Text",
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

        // The owner (a viewer, seated, a member device, bound) reaches the
        // claim: served when both Text flags are on, else refused by the
        // Text gate (which ignores the media flag)
        let owner_claim = claim(
            db,
            &oracle.owner,
            &oracle.owner_session,
            &claim_body(
                &oracle.owner_device.device_id,
                &oracle.hidden_group_id,
                &[(&oracle.owner.id, &oracle.owner_device.device_id)],
            ),
        )
        .await;
        match (features.e2ee_enabled, features.protected_channels.enabled) {
            (true, true) => {
                let response = owner_claim.expect("the owner is served");
                assert_eq!(tags(&[response.results[0].status.clone()]), ["Claimed"]);
            }
            (e2ee, _) => {
                let body: serde_json::Value =
                    serde_json::from_str(&refusal(owner_claim, "owner")).expect("JSON");
                assert_eq!(body["type"], "FeatureDisabled", "owner: {}", body);
                let feature = if e2ee { "protected_channels" } else { "e2ee" };
                assert_eq!(body["feature"], feature, "owner: {}", body);
            }
        }

        for caller in &oracle.callers {
            assert!(
                require_channel_access(db, &caller.user, &channel)
                    .await
                    .is_err(),
                "{} views the hidden channel",
                caller.class
            );

            let unknown_requests =
                oracle_requests(&oracle, &caller.device_id, &oracle.unknown_group_id);
            let hidden_requests =
                oracle_requests(&oracle, &caller.device_id, &oracle.hidden_group_id);
            let deleted_requests =
                oracle_requests(&oracle, &caller.device_id, &oracle.deleted_group_id);
            let unknown_valid = refusal(
                claim(db, &caller.user, &caller.session, &unknown_requests[0].1).await,
                &format!("unknown valid {}", caller.class),
            );
            // Each class gets its own answer, so the classes are real
            let value: serde_json::Value = serde_json::from_str(&unknown_valid).expect("JSON");
            let expected = match (media, caller.class) {
                (false, _) => "FeatureDisabled",
                (true, "bot") => "IsBot",
                (true, "unbound") => "NotAuthenticated",
                (true, _) => "NotFound",
            };
            assert_eq!(
                value["type"], expected,
                "{}: {}",
                caller.class, unknown_valid
            );
            if !media {
                assert_eq!(value["feature"], "media_e2ee", "{}", unknown_valid);
            }

            for (index, (shape, unknown_request)) in unknown_requests.iter().enumerate() {
                let case = format!("{} {}", caller.class, shape);
                let unknown = refusal(
                    claim(db, &caller.user, &caller.session, unknown_request).await,
                    &format!("unknown {case}"),
                );
                // An unknown id never validates the request (6.1)
                assert_eq!(unknown, unknown_valid, "unknown {}", case);
                let unknown_http = if caller.class == "bot" {
                    None
                } else {
                    let answer =
                        claim_http(&oracle.harness, &caller.session, unknown_request).await;
                    assert_ne!(answer.0, Status::Ok, "unknown {}: {}", case, answer.1);
                    Some(answer)
                };

                for (target, requests) in
                    [("hidden", &hidden_requests), ("deleted", &deleted_requests)]
                {
                    let request = &requests[index].1;
                    let answer = refusal(
                        claim(db, &caller.user, &caller.session, request).await,
                        &format!("{target} {case}"),
                    );
                    assert_eq!(answer, unknown, "{} {}", target, case);
                    if let Some(unknown_http) = &unknown_http {
                        assert_eq!(
                            &claim_http(&oracle.harness, &caller.session, request).await,
                            unknown_http,
                            "{} {} over HTTP",
                            target,
                            case
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn hidden_and_deleted_text_groups_claim_as_unknown_with_every_flag_on() {
        crate::util::test::rt().block_on(hidden_and_deleted_text_groups_claim_as_unknown())
    }

    #[test]
    fn hidden_and_deleted_text_groups_claim_as_unknown_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_claim_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_claim_as_unknown_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_claim_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_claim_as_unknown_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_claim_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_claim_as_unknown_with_growth_and_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_claim_as_unknown().await
        })
    }

    #[test]
    fn a_member_device_claims_seated_viewers() {
        crate::util::test::rt().block_on(a_member_device_claims_seated_viewers_case())
    }

    async fn a_member_device_claims_seated_viewers_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let empty_device = harness
            .new_e2ee_device(&member, &Ulid::new().to_string(), 0x60)
            .await;
        publish(db, &member_device, "member-0", false).await;
        publish(db, &member_device, "member-last", true).await;

        let owner_device = &protected.owner_device.device_id;
        let (status, body) = claim_http(
            &harness,
            &owner_session,
            &claim_body(
                owner_device,
                &group.id,
                &[
                    (&member.id, &member_device.device_id),
                    (&member.id, &empty_device.device_id),
                ],
            ),
        )
        .await;
        let statuses = served(status, &body, "first claim");
        assert!(
            matches!(
                &statuses[..],
                [
                    v0::MlsClaimStatus::Claimed {
                        key_package_ref,
                        reused: false,
                        ..
                    },
                    v0::MlsClaimStatus::Exhausted,
                ] if key_package_ref == "member-0"
            ),
            "{:?}",
            statuses
        );

        // Blocked pairs are not checked on Text (decision 7 (W2)): the owner
        // blocks the member and still claims, now the last-resort package
        owner
            .clone()
            .apply_relationship(
                db,
                &mut member.clone(),
                RelationshipStatus::Blocked,
                RelationshipStatus::BlockedOther,
                None,
            )
            .await
            .expect("block");
        let (status, body) = claim_http(
            &harness,
            &owner_session,
            &claim_body(
                owner_device,
                &group.id,
                &[(&member.id, &member_device.device_id)],
            ),
        )
        .await;
        let statuses = served(status, &body, "blocked claim");
        assert!(
            matches!(
                &statuses[..],
                [v0::MlsClaimStatus::Claimed {
                    key_package_ref,
                    reused: true,
                    ..
                }] if key_package_ref == "member-last"
            ),
            "{:?}",
            statuses
        );
    }

    #[test]
    fn ineligible_targets_report_not_found() {
        crate::util::test::rt().block_on(ineligible_targets_report_not_found_case())
    }

    async fn ineligible_targets_report_not_found_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, eligible) = harness.new_user().await;
        let (_, _, unseated) = harness.new_user().await;
        let (_, _, bot) = harness.new_user().await;
        let (_, _, staff) = harness.new_user().await;
        let (_, _, leaver) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&eligible, &bot, &staff, &leaver])
            .await;
        harness.join_server(&protected.server, &unseated).await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;

        let mut devices = Vec::new();
        for (seed, user) in [
            (0x40, &eligible),
            (0x50, &unseated),
            (0x60, &bot),
            (0x70, &staff),
            (0x90, &leaver),
        ] {
            let device = harness
                .new_e2ee_device(user, &Ulid::new().to_string(), seed)
                .await;
            publish(db, &device, "one", false).await;
            publish(db, &device, "two", false).await;
            devices.push(device);
        }

        // Seated, then made a bot and staff, as no route could seat them
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
        .expect("make a bot");
        db.update_user(
            &staff.id,
            &PartialUser {
                privileged: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("make staff");
        // A member gone while its seat stays active (a failed second
        // release, design 6.3)
        db.force_delete_member(&MemberCompositeKey {
            server: protected.server.id.clone(),
            user: leaver.id.clone(),
        })
        .await
        .expect("remove the membership");
        require_seated(db, protected.channel.id(), &leaver.id)
            .await
            .expect("the leaver is still seated");

        let unknown_user = Ulid::new().to_string();
        let mut targets: Vec<(&str, &str)> = devices
            .iter()
            .map(|device| (device.user_id.as_str(), device.device_id.as_str()))
            .collect();
        targets.push((&eligible.id, UNREGISTERED_DEVICE));
        targets.push((&unknown_user, UNREGISTERED_DEVICE));

        let owner_device = &protected.owner_device.device_id;
        let (status, body) = claim_http(
            &harness,
            &owner_session,
            &claim_body(owner_device, &group.id, &targets),
        )
        .await;
        assert_eq!(
            tags(&served(status, &body, "targets")),
            [
                "Claimed",  // seated, a viewer, a member
                "NotFound", // a viewer and a member, not seated
                "NotFound", // a bot
                "NotFound", // staff
                "NotFound", // seated, no longer a member
                "NotFound", // an eligible user's unregistered device
                "NotFound", // no such user
            ]
        );
        // Nothing was consumed for a refused target
        assert_eq!(packages_left(db, &devices[0]).await, 1);
        for device in &devices[1..] {
            assert_eq!(packages_left(db, device).await, 2, "{}", device.user_id);
        }

        // ViewChannel: denied to everyone but the owner, the same seated
        // member turns NotFound while it still has a package
        let mut channel = protected.channel.clone();
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
        let (status, body) = claim_http(
            &harness,
            &owner_session,
            &claim_body(
                owner_device,
                &group.id,
                &[(&eligible.id, &devices[0].device_id)],
            ),
        )
        .await;
        assert_eq!(tags(&served(status, &body, "no view")), ["NotFound"]);
        assert_eq!(packages_left(db, &devices[0]).await, 1);
    }

    #[test]
    fn the_claimer_must_be_a_seated_member_device() {
        crate::util::test::rt().block_on(the_claimer_must_be_a_seated_member_device_case())
    }

    async fn the_claimer_must_be_a_seated_member_device_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, viewer_session, viewer) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        harness.join_server(&protected.server, &viewer).await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let viewer_device = harness
            .new_e2ee_device(&viewer, &viewer_session.id, 0x40)
            .await;
        let owner_device = &protected.owner_device;
        publish(db, owner_device, "owner-0", false).await;
        let target = [(owner.id.as_str(), owner_device.device_id.as_str())];

        // Seated, but its device is not in the group
        let answer = claim_http(
            &harness,
            &member_session,
            &claim_body(&member_device.device_id, &group.id, &target),
        )
        .await;
        refused(
            &answer,
            Status::Forbidden,
            "NotSeated",
            "not a member device",
        );

        // A viewer and a server member, not seated
        let answer = claim_http(
            &harness,
            &viewer_session,
            &claim_body(&viewer_device.device_id, &group.id, &target),
        )
        .await;
        refused(&answer, Status::Forbidden, "NotSeated", "not seated");

        // A member device whose seat was released (it is still in the
        // roster until a commit removes it)
        db.release_channel_seats_for_user(
            &owner.id,
            Some(&protected.server.id),
            Timestamp::now_utc(),
        )
        .await
        .expect("release");
        let answer = claim_http(
            &harness,
            &owner_session,
            &claim_body(&owner_device.device_id, &group.id, &target),
        )
        .await;
        refused(&answer, Status::Forbidden, "NotSeated", "released seat");

        assert_eq!(packages_left(db, owner_device).await, 1);
    }

    #[test]
    fn the_claim_request_and_claiming_device_are_checked() {
        crate::util::test::rt().block_on(the_claim_request_and_claiming_device_are_checked_case())
    }

    async fn the_claim_request_and_claiming_device_are_checked_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let owner_device = &protected.owner_device;
        let owner_second_device = harness
            .new_e2ee_device(&owner, &Ulid::new().to_string(), 0x40)
            .await;
        // The member's only device is bound to another session
        harness
            .new_e2ee_device(&member, &Ulid::new().to_string(), MEMBER_DEVICE_SEED)
            .await;
        publish(db, owner_device, "owner-0", false).await;
        let target = (owner.id.as_str(), owner_device.device_id.as_str());

        let too_many: Vec<(&str, &str)> = std::iter::repeat(target)
            .take(revolt_database::MAX_MLS_GROUP_MEMBERS + 1)
            .collect();
        for (case, body) in [
            (
                "no targets",
                claim_body(&owner_device.device_id, &group.id, &[]),
            ),
            (
                "too many targets",
                claim_body(&owner_device.device_id, &group.id, &too_many),
            ),
            (
                "bad target device",
                claim_body(&owner_device.device_id, &group.id, &[(target.0, "nope")]),
            ),
            (
                "unregistered claiming device",
                claim_body(UNREGISTERED_DEVICE, &group.id, &[target]),
            ),
        ] {
            let answer = claim_http(&harness, &owner_session, &body).await;
            refused(&answer, Status::BadRequest, "FailedValidation", case);
        }

        // The session is bound to the owner's first device, not this one
        let answer = claim_http(
            &harness,
            &owner_session,
            &claim_body(&owner_second_device.device_id, &group.id, &[target]),
        )
        .await;
        refused(
            &answer,
            Status::Unauthorized,
            "NotAuthenticated",
            "claiming device bound elsewhere",
        );

        // A seated viewer whose session is bound to none of its devices
        let answer = claim_http(
            &harness,
            &member_session,
            &claim_body(UNREGISTERED_DEVICE, &group.id, &[target]),
        )
        .await;
        refused(
            &answer,
            Status::Unauthorized,
            "NotAuthenticated",
            "unbound session",
        );

        // A superseded (closed) group admits nobody; its successor does
        let successor = harness
            .new_text_group(&protected.channel, owner_device, 1, Some(&group.id))
            .await;
        let answer = claim_http(
            &harness,
            &owner_session,
            &claim_body(&owner_device.device_id, &group.id, &[target]),
        )
        .await;
        refused(&answer, Status::NotFound, "NotFound", "closed group");
        assert_eq!(packages_left(db, owner_device).await, 1);

        let (status, body) = claim_http(
            &harness,
            &owner_session,
            &claim_body(&owner_device.device_id, &successor.id, &[target]),
        )
        .await;
        assert_eq!(tags(&served(status, &body, "successor")), ["Claimed"]);
    }

    #[test]
    fn growth_off_refuses_a_text_claim() {
        crate::util::test::rt().block_on(growth_off_refuses_a_text_claim_case())
    }

    async fn growth_off_refuses_a_text_claim_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.enabled = false;
        })
        .await;
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        publish(db, &member_device, "member-0", false).await;

        // Decision 5 (W2): a claim is growth, refused with the flag off
        let answer = claim_http(
            &harness,
            &owner_session,
            &claim_body(
                &protected.owner_device.device_id,
                &group.id,
                &[(&member.id, &member_device.device_id)],
            ),
        )
        .await;
        refused(&answer, Status::BadRequest, "FeatureDisabled", "growth off");
        let body: serde_json::Value = serde_json::from_str(&answer.1).expect("JSON");
        assert_eq!(body["feature"], "protected_channels", "{}", answer.1);
        assert_eq!(packages_left(db, &member_device).await, 1);
    }
}
