//! Route-side seat-list validation for `PUT /channels/:id/protect` (the
//! genesis list) and `PUT /channels/:id/seats` (design 4.3, decision 6
//! (W2)).
//!
//! The server is not the trust anchor; it validates so garbage never reaches
//! clients. This module owns the 4.3 steps the database layer does not:
//! 1 (parse, route channel), 2 (authorization, bound session), 3 (signature),
//! 5 (seating eligibility), 6 (`device_cap` ceiling) and 8 (the handover
//! statement itself). The driver re-parses the body and owns step 4 (the
//! version rule and the byte-identical retry), 5b (signer leaf), 7 (claims,
//! releases, slot cap, the membership claim of newly claimed users) and the
//! step 8 append and chain bound. The removed-users refusal (C1,
//! `SeatListNamesRemovedUsers`) is the driver's, read here first only so a
//! removed user who has not rejoined gets the same answer.
//!
//! S2 (4.3 "S2 additions"): the route runs the planner's pure checks for
//! step 1 (format), 3b (authority) and 4c (immutable v2 lines) against the
//! stored list it read, and owns the half of 3b the planner cannot: a
//! CHANGED authority's signer key must be the signer device's directory key
//! and its signature must verify under it, BEFORE the driver is called (see
//! `validate`). 4d (the removal reason) is the planner's alone: it needs the
//! planned releases. [`after_seat_list_write`] is the post-claim step both
//! routes share (reconcile, event, audit).

use std::collections::BTreeSet;

use revolt_database::{
    check_seat_list_authority, check_seat_list_format, check_seat_list_v2_lines,
    events::client::EventV1,
    is_genesis_reprotect, seat_list_channel_server, seat_list_removed_users,
    util::protected_access::{reconcile_channel, seat_holder_lacks_access},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Channel,
    ChannelAuthorityChange, Database, E2EEIdentity, HandoverBody, SeatListBody, SeatListSubmission,
    SeatListWriteKind, SeatListWriteOutcome, Server, Session, SignedAuthority, User,
    PROTECTED_SCOPE_SEATS,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};

use crate::routes::mls::effective_device_cap;

/// A seat list that passed every route-side check, ready for
/// `protect_channel` / `put_seat_list`
#[derive(Debug, Clone)]
pub(crate) struct ValidatedSeatList {
    /// What the route passes to the driver
    pub(crate) submission: SeatListSubmission,
    /// The parsed body
    pub(crate) body: SeatListBody,
    /// Byte-identical to the stored list (the 4.9 retry, N3 on protect):
    /// steps 5, 6 and 8 were skipped and the driver answers `unchanged`
    pub(crate) retry: bool,
}

fn invalid(error: &str) -> revolt_result::Error {
    create_error!(FailedValidation {
        error: error.to_string()
    })
}

/// Validate the genesis list of `PUT /channels/:id/protect`
pub(crate) async fn validate_protect(
    db: &Database,
    channel: &Channel,
    server: &Server,
    user: &User,
    session: &Session,
    data: &v0::DataProtectChannel,
) -> Result<ValidatedSeatList> {
    validate(
        db,
        channel,
        server,
        user,
        session,
        &data.seat_list,
        SeatListWriteKind::Protect,
    )
    .await
}

/// Validate the list of `PUT /channels/:id/seats`
pub(crate) async fn validate_seat_list_put(
    db: &Database,
    channel: &Channel,
    server: &Server,
    user: &User,
    session: &Session,
    data: &v0::DataSeatList,
) -> Result<ValidatedSeatList> {
    validate(
        db,
        channel,
        server,
        user,
        session,
        data,
        SeatListWriteKind::Put,
    )
    .await
}

async fn validate(
    db: &Database,
    channel: &Channel,
    server: &Server,
    user: &User,
    session: &Session,
    data: &v0::DataSeatList,
    kind: SeatListWriteKind,
) -> Result<ValidatedSeatList> {
    if seat_list_channel_server(channel) != Some(server.id.as_str()) {
        return Err(create_error!(InvalidOperation));
    }

    // Step 1: strict parse; the route channel and the declared signer device
    // must match the signed body
    let body = SeatListBody::parse(&data.body)?;
    if body.channel_id != channel.id() {
        return Err(invalid("seat list channel_id does not match the channel"));
    }
    if body.signer_device_id != data.signer_device_id {
        return Err(invalid(
            "signer_device_id does not match the seat list body",
        ));
    }

    // Step 2: the signer is the caller and the server owner (a hard check,
    // not the permission calculus), signing from a registered device this
    // session is bound to
    if user.id != server.owner || body.signer_user_id != user.id {
        return Err(create_error!(NotOwner));
    }
    let signer = registered_device(db, &user.id, &body.signer_device_id, "signer device").await?;
    signer.assert_bound_session(&session.id)?;

    // Step 3: the signature verifies under the directory identity key
    if !signer.verify_payload(&data.body, &data.signature) {
        return Err(invalid("seat list signature"));
    }

    // Decision 6 (W2): the genesis list carries no handover
    if kind == SeatListWriteKind::Protect && data.handover.is_some() {
        return Err(invalid("the genesis seat list carries no handover"));
    }

    let submission: SeatListSubmission = data.clone().into();

    // Step 4 (W0-fix8) and N3: a byte-identical retry of a list that landed
    // returns before steps 5 to 8, so it is not refused because state moved
    // on. Skipping them is safe: the driver decides the same compare again
    // inside its transaction, and a stored version never decreases, so a
    // submission identical to a stored row can only ever be answered
    // `unchanged`, never applied.
    let stored = db.fetch_seat_list(channel.id()).await?;
    let retry = match (kind, &stored) {
        (SeatListWriteKind::Put | SeatListWriteKind::Wipe, Some(stored)) => {
            stored.body == submission.body && stored.signature == submission.signature
        }
        (SeatListWriteKind::Protect, Some(stored)) => is_genesis_reprotect(&submission, stored),
        (_, None) => false,
    };
    if retry {
        return Ok(ValidatedSeatList {
            submission,
            body,
            retry,
        });
    }

    // S2 steps 1, 3b and 4c: the planner's own checks, against the stored
    // list read above (protect: none; a genesis lands only over no list).
    // 3b is finished here, before anything is persisted: a CHANGED
    // authority must name the signer device with its directory key and
    // verify under it. The planner re-runs the structural half inside its
    // transaction against the list it reads there, and that cannot turn
    // this verdict into an unverified change: a stored authority only moves
    // forward (`version + 1`, `prev` = the stored hash, never dropped), so
    // an authority that equals the one read here can only meet the same
    // row or a newer one, where it is no change or is refused as stale.
    let config = revolt_config::config().await;
    let stored_before = match kind {
        SeatListWriteKind::Put | SeatListWriteKind::Wipe => stored.as_ref(),
        SeatListWriteKind::Protect => None,
    };
    check_seat_list_format(
        kind,
        &body,
        stored_before,
        config.features.protected_channels.formats_v2,
    )?;
    if let Some(change) =
        check_seat_list_authority(&body, submission.authority.as_ref(), stored_before)?
    {
        verify_authority_change(&signer, &change, submission.authority.as_ref())?;
    }
    check_seat_list_v2_lines(&body, stored_before)?;

    // C1 (W2 audit, decision 2): a list still naming a user the server
    // removed since the stored list is refused before the step 5 rules, so
    // the owner gets the same typed answer whether that user has rejoined or
    // not (not rejoined, step 5 would answer a bare `FailedValidation`). The
    // driver decides it again inside its transaction; this read only picks
    // the answer. A genesis list has no stored list to check against.
    if kind == SeatListWriteKind::Put {
        let seats = db.fetch_channel_seats(channel.id()).await?;
        let removed = seat_list_removed_users(&body, stored.as_ref(), &seats)?;
        if !removed.is_empty() {
            return Err(create_error!(SeatListNamesRemovedUsers { users: removed }));
        }
    }

    // Step 5 and decision 6 (W2)
    check_seat_eligibility(db, channel, server, &body.seats).await?;

    // Step 6 (W0-fix4): at most the effective entitlement cap; `0`
    // (unlimited) only when that cap is itself `0`
    let entitlement = db
        .fetch_channel_entitlement(channel.id())
        .await?
        .ok_or_else(|| create_error!(InvalidOperation))?;
    let ceiling = effective_device_cap(&entitlement, &config.features.protected_channels);
    if ceiling != 0 && (body.device_cap == 0 || body.device_cap > ceiling) {
        return Err(invalid("seat list device_cap exceeds the entitlement"));
    }

    // Step 8: the statement itself (the driver appends it and bounds the
    // chain)
    if let Some(handover) = &data.handover {
        check_handover(db, channel, &body, &signer, handover).await?;
    }

    Ok(ValidatedSeatList {
        submission,
        body,
        retry,
    })
}

/// 4.3 step 3b, the route's half (#215, #225): a CHANGED authority (the
/// planner's `ChannelAuthorityChange`) lists the PUT's signer device under
/// that device's DIRECTORY identity key, and its signature verifies under
/// that key (`verify_payload`, as for the list in step 3). An unchanged,
/// byte-identical authority never reaches here: it may carry another owner
/// device's signature (4.4.1 rule 6).
fn verify_authority_change(
    signer: &E2EEIdentity,
    change: &ChannelAuthorityChange,
    authority: Option<&SignedAuthority>,
) -> Result<()> {
    if change.signer_identity_key != signer.ed25519_key {
        return Err(invalid("authority signer key is not the signer device key"));
    }
    let authority = authority.ok_or_else(|| create_error!(InternalError))?;
    if !signer.verify_payload(&authority.body, &authority.signature) {
        return Err(invalid("authority signature"));
    }
    Ok(())
}

/// A registered E2EE device; an unknown one is `FailedValidation`, any other
/// error (a database failure) propagates unchanged so the client retries
async fn registered_device(
    db: &Database,
    user_id: &str,
    device_id: &str,
    what: &str,
) -> Result<E2EEIdentity> {
    db.fetch_e2ee_identity(user_id, device_id)
        .await
        .map_err(|error| match error.error_type {
            ErrorType::NotFound => invalid(&format!("{what} is not registered")),
            _ => error,
        })
}

/// 4.3 step 5 with decision 6 (W2): every listed user exists, is not a bot,
/// is not staff and is a member of the server; a NEWLY claimed user (no
/// active seat yet) must also have access by the shared predicate
/// `seat_holder_lacks_access` (S2, 6.4), so this rule and the reconciler
/// never disagree. An existing seat that lost access is not refused here;
/// the post-claim reconcile releases it (S2-D12).
///
/// Each rule runs over the whole list before the next, so the answer does
/// not depend on the order of the seats.
async fn check_seat_eligibility(
    db: &Database,
    channel: &Channel,
    server: &Server,
    seats: &[String],
) -> Result<()> {
    let requested: BTreeSet<&str> = seats.iter().map(String::as_str).collect();

    // [R#10] Both drivers skip unknown ids, so existence is the returned id
    // set equal to the requested one, never a NotFound
    let users = db.fetch_users(seats).await?;
    let found: BTreeSet<&str> = users.iter().map(|user| user.id.as_str()).collect();
    if found != requested {
        return Err(invalid("seat list names an unknown user"));
    }

    if users.iter().any(|user| user.bot.is_some()) {
        return Err(create_error!(IsBot));
    }
    if users.iter().any(|user| user.privileged) {
        return Err(create_error!(InvalidOperation));
    }

    let members = db.fetch_members(&server.id, seats).await?;
    let member_ids: BTreeSet<&str> = members
        .iter()
        .filter(|member| member.id.server == server.id)
        .map(|member| member.id.user.as_str())
        .collect();
    if member_ids != requested {
        return Err(invalid("seat list names a user who is not a server member"));
    }

    let seated: BTreeSet<String> = db
        .fetch_channel_seats(channel.id())
        .await?
        .into_iter()
        .filter(|seat| seat.is_active())
        .map(|seat| seat.user_id)
        .collect();

    for user in &users {
        if seated.contains(&user.id) {
            continue;
        }

        let member = members
            .iter()
            .find(|member| member.id.user == user.id)
            .ok_or_else(|| invalid("seat list names a user who is not a server member"))?;
        if seat_holder_lacks_access(db, Some(user), Some(member), channel, server).await {
            return Err(invalid(
                "seat list claims a user who cannot view the channel",
            ));
        }
    }

    Ok(())
}

/// 4.3 step 8 with decision 6 (W2): the statement is published by the
/// CURRENT owner device (the list's signer device), names this channel, is
/// signed under the signer's directory key, and hands over to a registered
/// device of the same user (S1) whose directory key it names
async fn check_handover(
    db: &Database,
    channel: &Channel,
    body: &SeatListBody,
    signer: &E2EEIdentity,
    handover: &v0::SignedHandover,
) -> Result<()> {
    let statement = HandoverBody::parse(&handover.body)?;

    if statement.channel_id != channel.id() {
        return Err(invalid("handover channel_id does not match the channel"));
    }
    if statement.from_user_id != body.signer_user_id {
        return Err(invalid("handover is not from the seat list signer"));
    }
    if statement.from_device_id != body.signer_device_id {
        return Err(invalid("handover is not from the seat list signer device"));
    }
    if statement.from_identity_key != signer.ed25519_key {
        return Err(invalid(
            "handover from_identity_key is not the signer device key",
        ));
    }
    if !signer.verify_payload(&handover.body, &handover.signature) {
        return Err(invalid("handover signature"));
    }
    if statement.to_user_id != statement.from_user_id {
        return Err(invalid("handover to another user"));
    }

    let successor = registered_device(
        db,
        &statement.to_user_id,
        &statement.to_device_id,
        "handover target device",
    )
    .await?;
    if statement.to_identity_key != successor.ed25519_key {
        return Err(invalid(
            "handover to_identity_key is not the target device key",
        ));
    }

    Ok(())
}

/// 4.3 "After the claim commits" (S2-D12) and 7.5, shared by protect and
/// the seat PUT once the driver answered: `reconcile_channel` with fresh
/// reads (it records and announces its own releases), then, only when the
/// write changed the list (not the `unchanged` retry),
/// `ProtectedChannelChanged { scope: ["seats"] }` on the channel topic and
/// the `ProtectedSeatsUpdate` entry. The reconcile also runs on the retry,
/// so retrying a request whose recheck failed repairs it (6.3 "Hooks").
///
/// The write is never undone: a failed reconcile is kept and returned after
/// the event and the entry, and the route answers it (500).
pub(crate) async fn after_seat_list_write(
    db: &Database,
    server: &Server,
    channel: &Channel,
    actor: &User,
    outcome: &SeatListWriteOutcome,
    reason: Option<String>,
) -> Result<()> {
    let reconciled = reconcile_channel(db, channel.id()).await;

    if !outcome.unchanged {
        EventV1::ProtectedChannelChanged {
            id: channel.id().to_string(),
            scope: vec![PROTECTED_SCOPE_SEATS.to_string()],
        }
        .p(channel.id().to_string())
        .await;
        AuditLogEntry::record(
            db,
            seats_update_audit(&server.id, channel.id(), &actor.id, outcome, reason),
        )
        .await;
    }

    reconciled.map(|_| ())
}

/// The `ProtectedSeatsUpdate` entry of a list write (7.5, the mapping on
/// `AuditLogAction::ProtectedSeatsUpdate`): the owner as the actor, the
/// channel, the users the write released and seated (sorted), and the
/// `X-Audit-Log-Reason`
pub(crate) fn seats_update_audit(
    server_id: &str,
    channel_id: &str,
    actor_id: &str,
    outcome: &SeatListWriteOutcome,
    reason: Option<String>,
) -> AuditLogDraft {
    AuditLogDraft {
        server: server_id.to_string(),
        actor: Some(actor_id.to_string()),
        action: AuditLogAction::ProtectedSeatsUpdate,
        target: None,
        channel: Some(channel_id.to_string()),
        changes: vec![
            AuditLogChange::new(
                "released",
                None,
                Some(AuditValue::StringList(outcome.released.clone())),
            ),
            AuditLogChange::new(
                "seated",
                None,
                Some(AuditValue::StringList(outcome.claimed.clone())),
            ),
        ],
        count: None,
        reason,
    }
}

#[cfg(test)]
pub(crate) mod v2_fixtures {
    //! v2 seat lists and channel authorities (4.1.1, 4.10) for the tests of
    //! this validator, protect and the seat PUT

    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use revolt_database::{
        AuthorityOwnerDevice, ChannelAuthority, ChannelAuthorityBody, SeatListBody,
        SeatListHistory, SeatListPreHistory, SeatListV2Lines,
    };
    use revolt_models::v0;

    /// A group salt (3.1.1: 64 lowercase hex)
    pub(crate) const SALT: &str =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    /// Another salt, for the 4.3 step 4c refusal
    pub(crate) const OTHER_SALT: &str =
        "5555555555555555555555555555555555555555555555555555555555555555";

    const ISSUED_AT: i64 = 1_790_812_800_000;

    /// b64 of `key`'s public half, the directory `ed25519_key` form
    pub(crate) fn identity_key(key: &SigningKey) -> String {
        STANDARD_NO_PAD.encode(key.verifying_key().as_bytes())
    }

    fn sign(key: &SigningKey, payload: &str) -> String {
        STANDARD_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes())
    }

    /// A channel authority (4.10) of `channel_id` owned by `owner_user_id`:
    /// `signer_device_id`, `owner_devices` as (device id, the key whose
    /// public half the entry lists), the successor of `previous` (version
    /// 1 without one), signed with `signing_key`
    pub(crate) fn authority(
        channel_id: &str,
        owner_user_id: &str,
        signer_device_id: &str,
        owner_devices: &[(&str, &SigningKey)],
        previous: Option<&v0::SignedAuthority>,
        signing_key: &SigningKey,
    ) -> v0::SignedAuthority {
        let version = previous.map_or(1, |previous| {
            ChannelAuthority::parse(&previous.body)
                .expect("the previous authority")
                .version
                + 1
        });
        let body = ChannelAuthority::build(&ChannelAuthorityBody {
            channel_id: channel_id.to_string(),
            version,
            owner_user_id: owner_user_id.to_string(),
            signer_device_id: signer_device_id.to_string(),
            issued_at: ISSUED_AT,
            owner_devices: owner_devices
                .iter()
                .map(|(device_id, key)| AuthorityOwnerDevice {
                    device_id: device_id.to_string(),
                    identity_key: identity_key(key),
                })
                .collect(),
            delegates: vec![],
            delegate_max_device_cap: 0,
            successors: vec![],
            prev: previous.map(|previous| ChannelAuthority::sha256(&previous.body)),
        })
        .expect("a canonical authority body");
        v0::SignedAuthority {
            signature: sign(signing_key, &body),
            body,
        }
    }

    /// A v2 seat list (device cap 5, history hidden, no boundary, `kept`)
    /// naming `authority`
    pub(crate) struct V2List<'a> {
        pub(crate) channel_id: &'a str,
        pub(crate) version: i64,
        pub(crate) signer_user_id: &'a str,
        pub(crate) signer_device_id: &'a str,
        pub(crate) key: &'a SigningKey,
        pub(crate) seats: &'a [&'a str],
        pub(crate) salt: &'a str,
        pub(crate) authority: &'a v0::SignedAuthority,
    }

    impl V2List<'_> {
        /// The body, signed with `key`, carrying `authority`
        pub(crate) fn signed(&self) -> v0::DataSeatList {
            let body = SeatListBody {
                channel_id: self.channel_id.to_string(),
                version: self.version,
                device_cap: 5,
                issued_at: ISSUED_AT,
                signer_user_id: self.signer_user_id.to_string(),
                signer_device_id: self.signer_device_id.to_string(),
                seats: self.seats.iter().map(|seat| seat.to_string()).collect(),
                v2: Some(SeatListV2Lines {
                    authority_sha256: Some(ChannelAuthority::sha256(&self.authority.body)),
                    history: SeatListHistory::Hidden,
                    history_boundary: None,
                    pre_history: SeatListPreHistory::Kept,
                    group_salt: self.salt.to_string(),
                }),
            }
            .build()
            .expect("a canonical v2 seat list body");
            v0::DataSeatList {
                signature: sign(self.key, &body),
                body,
                signer_device_id: self.signer_device_id.to_string(),
                handover: None,
                authority: Some(self.authority.clone()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Run under nextest (one process per test). Every refusal test builds
    //! a list that breaks exactly ONE rule, so with that rule's check
    //! removed the list is accepted and the test fails.

    use std::collections::HashMap;

    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        BotInformation, Channel, ChannelEntitlement, ChannelEntitlementSource,
        ChannelEntitlementState, E2EEIdentity, E2EESignedKey, Member, MemberCompositeKey,
        SeatListBody, SeatListSubmission, Server, Session, User, E2EE_PROTOCOL_VERSION,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField, DEFAULT_PERMISSION_SERVER};
    use revolt_result::ErrorType;

    use super::v2_fixtures::{authority, V2List, OTHER_SALT, SALT};
    use super::{validate_protect, validate_seat_list_put, ValidatedSeatList};
    use crate::util::test::TestHarness;

    // Section 5.1 inputs
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";
    const OWNER: &str = "01HZXAAAAAAAAAAAAAAAAAAAAA";
    const MEMBER: &str = "01HZXBBBBBBBBBBBBBBBBBBBBB";
    const OTHER: &str = "01HZXCCCCCCCCCCCCCCCCCCCCC";
    const OWNER_DEVICE: &str = "00112233445566778899aabbccddeeff";
    const NEW_OWNER_DEVICE: &str = "0123456789abcdef0123456789abcdef";
    const MEMBER_DEVICE: &str = "ffeeddccbbaa99887766554433221100";

    // Section 5.2 keys and the 5.4 handover (owner device to the owner's
    // new device, signed by the owner device)
    const OWNER_IDENTITY_KEY: &str = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
    const NEW_OWNER_IDENTITY_KEY: &str = "zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o";
    const VECTOR_HANDOVER_BODY: &str = "sloga-owner-handover-v1\nv:1\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\nfrom_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nfrom_device_id:00112233445566778899aabbccddeeff\nfrom_identity_key:A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg\nto_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nto_device_id:0123456789abcdef0123456789abcdef\nto_identity_key:zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o\nissued_at:1790812800000";
    const VECTOR_HANDOVER_SIGNATURE: &str =
        "JKnYtaiK/i3tYSxV71XoXyz9l0XaDsWIhzoCu8s9IuTdmFmWX5BNtoEhpt+v9gSvhE+nqS2/kZEA0CX6giR6BA";

    const SERVER: &str = "01HZXSERVERSERVERSERVERSER";
    const UNKNOWN: &str = "01HZXDDDDDDDDDDDDDDDDDDDDD";
    const BOT: &str = "01HZXEEEEEEEEEEEEEEEEEEEEE";
    const STAFF: &str = "01HZXFFFFFFFFFFFFFFFFFFFFF";
    const BLIND: &str = "01HZXGGGGGGGGGGGGGGGGGGGGG";
    /// A role whose channel override denies ViewChannel
    const BLIND_ROLE: &str = "blind";

    fn owner_key() -> SigningKey {
        SigningKey::from_bytes(&std::array::from_fn(|i| i as u8))
    }

    fn member_key() -> SigningKey {
        SigningKey::from_bytes(&std::array::from_fn(|i| 0x20 + i as u8))
    }

    fn new_owner_key() -> SigningKey {
        SigningKey::from_bytes(&std::array::from_fn(|i| 0x80 + i as u8))
    }

    /// A second owner device, registered by the S2 tests that need one
    const SECOND_OWNER_DEVICE: &str = "abcdef0123456789abcdef0123456789";

    fn second_owner_key() -> SigningKey {
        SigningKey::from_bytes(&std::array::from_fn(|i| 0x40 + i as u8))
    }

    fn b64(bytes: &[u8]) -> String {
        STANDARD_NO_PAD.encode(bytes)
    }

    fn sign(key: &SigningKey, payload: &str) -> String {
        b64(&key.sign(payload.as_bytes()).to_bytes())
    }

    struct World {
        harness: TestHarness,
        server: Server,
        channel: Channel,
        owner: User,
        owner_session: Session,
        member: User,
        member_session: Session,
    }

    /// A user with a fixed id; `User::create` fills the required fields
    async fn user(harness: &TestHarness, id: &str, edit: impl FnOnce(&mut User)) -> User {
        let mut user = User::create(&harness.db, TestHarness::rand_string(), None, None)
            .await
            .expect("user");
        user.id = id.to_string();
        user.username = TestHarness::rand_string();
        edit(&mut user);
        harness.db.insert_user(&user).await.expect("insert user");
        user
    }

    async fn join(harness: &TestHarness, user_id: &str, roles: &[&str]) {
        harness
            .db
            .insert_or_merge_member(&Member {
                id: MemberCompositeKey {
                    server: SERVER.to_string(),
                    user: user_id.to_string(),
                },
                roles: roles.iter().map(|role| role.to_string()).collect(),
                ..Default::default()
            })
            .await
            .expect("member");
    }

    async fn leave(harness: &TestHarness, user_id: &str) {
        harness
            .db
            .force_delete_member(&MemberCompositeKey {
                server: SERVER.to_string(),
                user: user_id.to_string(),
            })
            .await
            .expect("remove member");
    }

    async fn device(
        harness: &TestHarness,
        user_id: &str,
        device_id: &str,
        key: &SigningKey,
        session_id: &str,
    ) {
        harness
            .db
            .insert_e2ee_identity(&E2EEIdentity {
                id: E2EEIdentity::composite_id(user_id, device_id),
                user_id: user_id.to_string(),
                device_id: device_id.to_string(),
                protocol_version: E2EE_PROTOCOL_VERSION,
                ed25519_key: b64(key.verifying_key().as_bytes()),
                curve25519_key: b64(&[9u8; 32]),
                signature: b64(&[0u8; 64]),
                fallback_key: E2EESignedKey {
                    key_id: "fallback0".to_string(),
                    key: b64(&[8u8; 32]),
                    signature: b64(&[0u8; 64]),
                },
                previous_fallback_key: None,
                created_at: Timestamp::now_utc(),
                last_seen_at: Timestamp::now_utc(),
                last_session_id: session_id.to_string(),
            })
            .await
            .expect("identity");
    }

    /// `SERVER` owned by `OWNER`, with `CHANNEL` (a server TextChannel whose
    /// override denies ViewChannel to `BLIND_ROLE`) and an active
    /// entitlement (slot cap 10, the default device cap 5). `OWNER`,
    /// `MEMBER` and `OTHER` are members who can view it. `OWNER` has the
    /// owner device (bound to `owner_session`) and the new owner device;
    /// `MEMBER` has the member device (bound to `member_session`).
    async fn world() -> World {
        let harness = TestHarness::new().await;
        let owner = user(&harness, OWNER, |_| {}).await;
        let member = user(&harness, MEMBER, |_| {}).await;
        user(&harness, OTHER, |_| {}).await;

        let server: Server = serde_json::from_value(serde_json::json!({
            "_id": SERVER,
            "owner": OWNER,
            "name": "protected",
            "channels": [CHANNEL],
            "default_permissions": *DEFAULT_PERMISSION_SERVER as i64,
            "roles": {
                BLIND_ROLE: {
                    "_id": BLIND_ROLE,
                    "name": "blind",
                    "permissions": { "a": 0, "d": 0 },
                    "rank": 1,
                }
            },
        }))
        .expect("server");
        harness
            .db
            .insert_server(&server)
            .await
            .expect("insert server");

        let channel = Channel::TextChannel {
            id: CHANNEL.to_string(),
            server: SERVER.to_string(),
            name: "protected".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::from([(
                BLIND_ROLE.to_string(),
                OverrideField {
                    a: 0,
                    d: ChannelPermission::ViewChannel as i64,
                },
            )]),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
            protected_history: None,
        };
        harness.db.insert_channel(&channel).await.expect("channel");

        for user_id in [OWNER, MEMBER, OTHER] {
            join(&harness, user_id, &[]).await;
        }

        harness
            .db
            .upsert_channel_entitlement(
                &ChannelEntitlement {
                    id: ulid::Ulid::new().to_string(),
                    channel_id: CHANNEL.to_string(),
                    server_id: SERVER.to_string(),
                    source: ChannelEntitlementSource::AdminGrant,
                    slot_cap: 10,
                    device_cap: None,
                    state: ChannelEntitlementState::Active,
                    granted_by: "admin".to_string(),
                    created_at: Timestamp::now_utc(),
                },
                Timestamp::now_utc(),
            )
            .await
            .expect("entitlement");

        let (_, owner_session) = harness.account_from_user(OWNER.to_string()).await;
        let (_, member_session) = harness.account_from_user(MEMBER.to_string()).await;
        device(
            &harness,
            OWNER,
            OWNER_DEVICE,
            &owner_key(),
            &owner_session.id,
        )
        .await;
        device(
            &harness,
            OWNER,
            NEW_OWNER_DEVICE,
            &new_owner_key(),
            "elsewhere",
        )
        .await;
        device(
            &harness,
            MEMBER,
            MEMBER_DEVICE,
            &member_key(),
            &member_session.id,
        )
        .await;

        World {
            harness,
            server,
            channel,
            owner,
            owner_session,
            member,
            member_session,
        }
    }

    struct ListSpec<'a> {
        version: i64,
        device_cap: u32,
        signer_user: &'a str,
        signer_device: &'a str,
        key: SigningKey,
        seats: &'a [&'a str],
    }

    impl<'a> ListSpec<'a> {
        /// The owner device signing `seats` at `version` with device cap 5
        fn owner(version: i64, seats: &'a [&'a str]) -> ListSpec<'a> {
            ListSpec {
                version,
                device_cap: 5,
                signer_user: OWNER,
                signer_device: OWNER_DEVICE,
                key: owner_key(),
                seats,
            }
        }

        fn signed(&self) -> v0::DataSeatList {
            let body = SeatListBody {
                channel_id: CHANNEL.to_string(),
                version: self.version,
                device_cap: self.device_cap,
                issued_at: 1_790_812_800_000,
                signer_user_id: self.signer_user.to_string(),
                signer_device_id: self.signer_device.to_string(),
                seats: self.seats.iter().map(|seat| seat.to_string()).collect(),
                v2: None,
            }
            .build()
            .expect("body");
            v0::DataSeatList {
                signature: sign(&self.key, &body),
                body,
                signer_device_id: self.signer_device.to_string(),
                handover: None,
                authority: None,
            }
        }
    }

    /// The fields of a 4.6 statement
    struct Statement<'a> {
        channel: &'a str,
        from_user: &'a str,
        from_device: &'a str,
        from_key: &'a str,
        to_user: &'a str,
        to_device: &'a str,
        to_key: &'a str,
    }

    impl<'a> Statement<'a> {
        /// The 5.4 vector's fields
        fn vector() -> Statement<'static> {
            Statement {
                channel: CHANNEL,
                from_user: OWNER,
                from_device: OWNER_DEVICE,
                from_key: OWNER_IDENTITY_KEY,
                to_user: OWNER,
                to_device: NEW_OWNER_DEVICE,
                to_key: NEW_OWNER_IDENTITY_KEY,
            }
        }

        fn signed_by(&self, key: &SigningKey) -> v0::SignedHandover {
            let body = format!(
                "sloga-owner-handover-v1\nv:1\nchannel_id:{}\nfrom_user_id:{}\nfrom_device_id:{}\nfrom_identity_key:{}\nto_user_id:{}\nto_device_id:{}\nto_identity_key:{}\nissued_at:1790812800000",
                self.channel,
                self.from_user,
                self.from_device,
                self.from_key,
                self.to_user,
                self.to_device,
                self.to_key
            );
            v0::SignedHandover {
                signature: sign(key, &body),
                body,
            }
        }
    }

    fn vector_handover() -> v0::SignedHandover {
        v0::SignedHandover {
            body: VECTOR_HANDOVER_BODY.to_string(),
            signature: VECTOR_HANDOVER_SIGNATURE.to_string(),
        }
    }

    /// Protect `CHANNEL` through the driver (no route checks) with a genesis
    /// list seating `seats`, so they hold active seats
    async fn seat(world: &World, seats: &[&str]) -> v0::DataSeatList {
        let genesis = ListSpec::owner(1, seats).signed();
        world
            .harness
            .db
            .protect_channel(
                CHANNEL,
                &SeatListSubmission::from(genesis.clone()),
                Timestamp::now_utc(),
            )
            .await
            .expect("protect");
        genesis
    }

    async fn put(
        world: &World,
        data: &v0::DataSeatList,
    ) -> revolt_result::Result<ValidatedSeatList> {
        validate_seat_list_put(
            &world.harness.db,
            &world.channel,
            &world.server,
            &world.owner,
            &world.owner_session,
            data,
        )
        .await
    }

    async fn protect(
        world: &World,
        data: &v0::DataSeatList,
    ) -> revolt_result::Result<ValidatedSeatList> {
        validate_protect(
            &world.harness.db,
            &world.channel,
            &world.server,
            &world.owner,
            &world.owner_session,
            &v0::DataProtectChannel {
                seat_list: data.clone(),
                wipe_history: None,
            },
        )
        .await
    }

    fn is_failed_validation(error: &ErrorType, message: &str) -> bool {
        matches!(error, ErrorType::FailedValidation { error } if error == message)
    }

    #[track_caller]
    fn assert_refused(
        result: revolt_result::Result<ValidatedSeatList>,
        expected: impl Fn(&ErrorType) -> bool,
        rule: &str,
    ) {
        match result {
            Err(error) if expected(&error.error_type) => {}
            other => panic!("{}: expected the rule's refusal, got {:?}", rule, other),
        }
    }

    #[track_caller]
    fn assert_failed_validation(result: revolt_result::Result<ValidatedSeatList>, message: &str) {
        assert_refused(
            result,
            |error| is_failed_validation(error, message),
            message,
        )
    }

    #[test]
    fn a_nonexistent_user_is_refused() {
        crate::util::test::rt().block_on(a_nonexistent_user_is_refused_case())
    }

    async fn a_nonexistent_user_is_refused_case() {
        let world = world().await;
        // A membership row without a user row: only the [R#10] id-set
        // compare can catch the unknown id
        join(&world.harness, UNKNOWN, &[]).await;

        let data = ListSpec::owner(1, &[OWNER, UNKNOWN]).signed();
        assert_failed_validation(put(&world, &data).await, "seat list names an unknown user");
        assert_failed_validation(
            protect(&world, &data).await,
            "seat list names an unknown user",
        );
    }

    #[test]
    fn a_bot_is_refused() {
        crate::util::test::rt().block_on(a_bot_is_refused_case())
    }

    async fn a_bot_is_refused_case() {
        let world = world().await;
        user(&world.harness, BOT, |user| {
            user.bot = Some(BotInformation {
                owner: OWNER.to_string(),
            })
        })
        .await;
        join(&world.harness, BOT, &[]).await;

        let data = ListSpec::owner(1, &[OWNER, BOT]).signed();
        assert_refused(
            put(&world, &data).await,
            |error| matches!(error, ErrorType::IsBot),
            "bot",
        );
    }

    #[test]
    fn a_privileged_user_is_refused() {
        crate::util::test::rt().block_on(a_privileged_user_is_refused_case())
    }

    async fn a_privileged_user_is_refused_case() {
        let world = world().await;
        user(&world.harness, STAFF, |user| user.privileged = true).await;
        join(&world.harness, STAFF, &[]).await;

        let data = ListSpec::owner(1, &[OWNER, STAFF]).signed();
        assert_refused(
            put(&world, &data).await,
            |error| matches!(error, ErrorType::InvalidOperation),
            "privileged",
        );
    }

    #[test]
    fn a_non_member_is_refused() {
        crate::util::test::rt().block_on(a_non_member_is_refused_case())
    }

    async fn a_non_member_is_refused_case() {
        let world = world().await;
        // `MEMBER` holds an active seat, then loses the membership without a
        // release (the decision-11 failed second release). A kept seat skips
        // the ViewChannel rule and the driver claims only NEW members, so
        // the route's membership rule is the only guard.
        seat(&world, &[OWNER, MEMBER]).await;
        leave(&world.harness, MEMBER).await;

        let data = ListSpec::owner(2, &[OWNER, MEMBER]).signed();
        assert_failed_validation(
            put(&world, &data).await,
            "seat list names a user who is not a server member",
        );
    }

    #[test]
    fn a_newly_claimed_user_without_view_channel_is_refused() {
        crate::util::test::rt()
            .block_on(a_newly_claimed_user_without_view_channel_is_refused_case())
    }

    async fn a_newly_claimed_user_without_view_channel_is_refused_case() {
        let world = world().await;
        user(&world.harness, BLIND, |_| {}).await;
        join(&world.harness, BLIND, &[BLIND_ROLE]).await;
        seat(&world, &[OWNER]).await;

        let data = ListSpec::owner(2, &[OWNER, BLIND]).signed();
        assert_failed_validation(
            put(&world, &data).await,
            "seat list claims a user who cannot view the channel",
        );
    }

    #[test]
    fn an_existing_seat_without_view_channel_is_accepted() {
        crate::util::test::rt().block_on(an_existing_seat_without_view_channel_is_accepted_case())
    }

    async fn an_existing_seat_without_view_channel_is_accepted_case() {
        let world = world().await;
        user(&world.harness, BLIND, |_| {}).await;
        join(&world.harness, BLIND, &[BLIND_ROLE]).await;
        // Seated through the driver, which does not check access: the same
        // state as a seat whose holder lost ViewChannel later (6.4)
        seat(&world, &[OWNER, BLIND]).await;

        let data = ListSpec::owner(2, &[BLIND, OWNER, MEMBER]).signed();
        let validated = put(&world, &data)
            .await
            .expect("an existing seat keeps its place");
        assert!(!validated.retry);
        assert_eq!(validated.submission, SeatListSubmission::from(data));
    }

    #[test]
    fn a_handover_on_the_genesis_list_is_refused() {
        crate::util::test::rt().block_on(a_handover_on_the_genesis_list_is_refused_case())
    }

    async fn a_handover_on_the_genesis_list_is_refused_case() {
        let world = world().await;
        let mut data = ListSpec::owner(1, &[OWNER]).signed();
        data.handover = Some(vector_handover());
        assert_failed_validation(
            protect(&world, &data).await,
            "the genesis seat list carries no handover",
        );
    }

    #[test]
    fn a_handover_not_from_the_signer_user_is_refused() {
        crate::util::test::rt().block_on(a_handover_not_from_the_signer_user_is_refused_case())
    }

    async fn a_handover_not_from_the_signer_user_is_refused_case() {
        let world = world().await;
        seat(&world, &[OWNER, MEMBER]).await;

        // The owner device signs a statement naming `MEMBER` as the `from`
        // user and handing over to `MEMBER`'s own device; everything else
        // holds
        let member_identity = b64(member_key().verifying_key().as_bytes());
        let mut data = ListSpec::owner(2, &[OWNER, MEMBER]).signed();
        data.handover = Some(
            Statement {
                from_user: MEMBER,
                to_user: MEMBER,
                to_device: MEMBER_DEVICE,
                to_key: &member_identity,
                ..Statement::vector()
            }
            .signed_by(&owner_key()),
        );
        assert_failed_validation(
            put(&world, &data).await,
            "handover is not from the seat list signer",
        );
    }

    #[test]
    fn a_list_signed_as_another_user_is_refused() {
        crate::util::test::rt().block_on(a_list_signed_as_another_user_is_refused_case())
    }

    async fn a_list_signed_as_another_user_is_refused_case() {
        let world = world().await;
        // The owner, from the owner device, signs a body naming `MEMBER` as
        // the signer
        let data = ListSpec {
            signer_user: MEMBER,
            ..ListSpec::owner(1, &[OWNER, MEMBER])
        }
        .signed();
        assert_refused(
            put(&world, &data).await,
            |error| matches!(error, ErrorType::NotOwner),
            "signer is not the caller",
        );
    }

    #[test]
    fn a_caller_who_is_not_the_owner_is_refused() {
        crate::util::test::rt().block_on(a_caller_who_is_not_the_owner_is_refused_case())
    }

    async fn a_caller_who_is_not_the_owner_is_refused_case() {
        let world = world().await;
        // `MEMBER` signs a list as itself from its own bound device
        let data = ListSpec {
            signer_user: MEMBER,
            signer_device: MEMBER_DEVICE,
            key: member_key(),
            ..ListSpec::owner(1, &[OWNER, MEMBER])
        }
        .signed();
        let result = validate_seat_list_put(
            &world.harness.db,
            &world.channel,
            &world.server,
            &world.member,
            &world.member_session,
            &data,
        )
        .await;
        assert_refused(
            result,
            |error| matches!(error, ErrorType::NotOwner),
            "caller is not the owner",
        );
    }

    #[test]
    fn an_unbound_session_is_refused() {
        crate::util::test::rt().block_on(an_unbound_session_is_refused_case())
    }

    async fn an_unbound_session_is_refused_case() {
        let world = world().await;
        // The new owner device is registered but bound to another session
        let data = ListSpec {
            signer_device: NEW_OWNER_DEVICE,
            key: new_owner_key(),
            ..ListSpec::owner(1, &[OWNER])
        }
        .signed();
        assert_refused(
            put(&world, &data).await,
            |error| matches!(error, ErrorType::NotAuthenticated),
            "session not bound to the signer device",
        );
    }

    #[test]
    fn a_bad_seat_list_signature_is_refused() {
        crate::util::test::rt().block_on(a_bad_seat_list_signature_is_refused_case())
    }

    async fn a_bad_seat_list_signature_is_refused_case() {
        let world = world().await;
        // Signed by a key that is not the owner device's
        let data = ListSpec {
            key: member_key(),
            ..ListSpec::owner(1, &[OWNER])
        }
        .signed();
        assert_failed_validation(put(&world, &data).await, "seat list signature");
    }

    #[test]
    fn a_device_cap_above_the_entitlement_is_refused() {
        crate::util::test::rt().block_on(a_device_cap_above_the_entitlement_is_refused_case())
    }

    async fn a_device_cap_above_the_entitlement_is_refused_case() {
        let world = world().await;
        // The entitlement has no cap of its own: the configured default 5
        for device_cap in [6, 0] {
            let data = ListSpec {
                device_cap,
                ..ListSpec::owner(1, &[OWNER])
            }
            .signed();
            assert_failed_validation(
                put(&world, &data).await,
                "seat list device_cap exceeds the entitlement",
            );
        }
        for device_cap in [5, 1] {
            let data = ListSpec {
                device_cap,
                ..ListSpec::owner(1, &[OWNER])
            }
            .signed();
            put(&world, &data)
                .await
                .expect("at most the entitlement cap");
        }
    }

    #[test]
    fn a_byte_identical_retry_skips_eligibility() {
        crate::util::test::rt().block_on(a_byte_identical_retry_skips_eligibility_case())
    }

    async fn a_byte_identical_retry_skips_eligibility_case() {
        let world = world().await;
        let genesis = seat(&world, &[OWNER, MEMBER]).await;
        leave(&world.harness, MEMBER).await;

        // The retry of a list that landed is not refused because `MEMBER`
        // left since (W0-fix8; N3 for protect)
        let retried = put(&world, &genesis).await.expect("seat re-PUT");
        assert!(retried.retry, "seat re-PUT is a retry");
        let retried = protect(&world, &genesis).await.expect("re-protect");
        assert!(retried.retry, "re-protect is a retry");

        // A new list keeping the non-member is refused
        let next = ListSpec::owner(2, &[OWNER, MEMBER]).signed();
        assert_failed_validation(
            put(&world, &next).await,
            "seat list names a user who is not a server member",
        );
    }

    #[test]
    fn the_5_4_handover_vector_is_accepted() {
        crate::util::test::rt().block_on(the_5_4_handover_vector_is_accepted_case())
    }

    async fn the_5_4_handover_vector_is_accepted_case() {
        let world = world().await;
        assert_eq!(
            b64(owner_key().verifying_key().as_bytes()),
            OWNER_IDENTITY_KEY
        );
        assert_eq!(
            b64(new_owner_key().verifying_key().as_bytes()),
            NEW_OWNER_IDENTITY_KEY
        );
        // The fixture builds the vector's exact bytes; only the signature
        // below comes from the document
        assert_eq!(
            Statement::vector().signed_by(&owner_key()).body,
            VECTOR_HANDOVER_BODY
        );
        seat(&world, &[OWNER, MEMBER]).await;

        let mut data = ListSpec::owner(2, &[OWNER, MEMBER]).signed();
        data.handover = Some(vector_handover());

        let validated = put(&world, &data).await.expect("the 5.4 handover");
        assert!(!validated.retry);
        assert_eq!(validated.body.version, 2);
        let handover = validated.submission.handover.expect("handover kept");
        assert_eq!(handover.body, VECTOR_HANDOVER_BODY);
        assert_eq!(handover.signature, VECTOR_HANDOVER_SIGNATURE);
    }

    #[test]
    fn every_other_handover_mismatch_is_refused() {
        crate::util::test::rt().block_on(every_other_handover_mismatch_is_refused_case())
    }

    async fn every_other_handover_mismatch_is_refused_case() {
        let world = world().await;
        seat(&world, &[OWNER]).await;

        let member_identity = b64(member_key().verifying_key().as_bytes());
        let cases = [
            (
                "handover channel_id does not match the channel",
                Statement {
                    channel: "01J9Z3K4M5N6P7Q8R9S0T1V2W4",
                    ..Statement::vector()
                }
                .signed_by(&owner_key()),
            ),
            (
                "handover is not from the seat list signer device",
                Statement {
                    from_device: NEW_OWNER_DEVICE,
                    ..Statement::vector()
                }
                .signed_by(&owner_key()),
            ),
            (
                "handover from_identity_key is not the signer device key",
                Statement {
                    from_key: NEW_OWNER_IDENTITY_KEY,
                    ..Statement::vector()
                }
                .signed_by(&owner_key()),
            ),
            (
                "handover signature",
                Statement::vector().signed_by(&new_owner_key()),
            ),
            (
                "handover to another user",
                Statement {
                    to_user: MEMBER,
                    to_device: MEMBER_DEVICE,
                    to_key: &member_identity,
                    ..Statement::vector()
                }
                .signed_by(&owner_key()),
            ),
            (
                "handover target device is not registered",
                Statement {
                    to_device: "abcdefabcdefabcdefabcdefabcdefab",
                    ..Statement::vector()
                }
                .signed_by(&owner_key()),
            ),
            (
                "handover to_identity_key is not the target device key",
                Statement {
                    to_key: &member_identity,
                    ..Statement::vector()
                }
                .signed_by(&owner_key()),
            ),
        ];

        // Every case runs and every miss is named, so one control run shows
        // each removed check on a line of its own
        let mut misses = Vec::new();
        for (message, statement) in cases {
            let mut data = ListSpec::owner(2, &[OWNER]).signed();
            data.handover = Some(statement);
            let result = put(&world, &data).await;
            if !matches!(&result, Err(error) if is_failed_validation(&error.error_type, message)) {
                misses.push(format!("{message}: got {result:?}"));
            }
        }
        assert!(
            misses.is_empty(),
            "not refused as expected:\n{}",
            misses.join("\n")
        );
    }

    // S2 (4.3 "S2 additions"): steps 1, 3b and 4c, decided by the route
    // before the driver is called

    async fn formats_v2_on() {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.formats_v2 = true;
        })
        .await;
    }

    /// An authority of `CHANNEL` owned by `OWNER` naming the owner device as
    /// its signer
    fn owner_authority(
        owner_devices: &[(&str, &SigningKey)],
        previous: Option<&v0::SignedAuthority>,
        signing_key: &SigningKey,
    ) -> v0::SignedAuthority {
        authority(
            CHANNEL,
            OWNER,
            OWNER_DEVICE,
            owner_devices,
            previous,
            signing_key,
        )
    }

    /// Protect `CHANNEL` through the driver (no route checks) with the owner
    /// device's v2 genesis, salt `SALT`, seating `seats` and carrying
    /// `authority` (needs `formats_v2`)
    async fn seat_v2(world: &World, seats: &[&str], authority: &v0::SignedAuthority) {
        let key = owner_key();
        let genesis = V2List {
            channel_id: CHANNEL,
            version: 1,
            signer_user_id: OWNER,
            signer_device_id: OWNER_DEVICE,
            key: &key,
            seats,
            salt: SALT,
            authority,
        }
        .signed();
        world
            .harness
            .db
            .protect_channel(
                CHANNEL,
                &SeatListSubmission::from(genesis),
                Timestamp::now_utc(),
            )
            .await
            .expect("protect with a v2 genesis");
    }

    /// 4.3 step 1 (#218) with `formats_v2` off (the test config): a v2
    /// genesis, and a v2 list over a stored v1 list, are refused by the
    /// route. Control: the route's `check_seat_list_format` call removed.
    #[test]
    fn v2_lists_need_formats_v2() {
        crate::util::test::rt().block_on(v2_lists_need_formats_v2_case())
    }

    async fn v2_lists_need_formats_v2_case() {
        let world = world().await;
        assert!(
            !revolt_config::config()
                .await
                .features
                .protected_channels
                .formats_v2
        );
        let key = owner_key();
        let first = owner_authority(&[(OWNER_DEVICE, &key)], None, &key);
        let v2 = |version| {
            V2List {
                channel_id: CHANNEL,
                version,
                signer_user_id: OWNER,
                signer_device_id: OWNER_DEVICE,
                key: &key,
                seats: &[OWNER],
                salt: SALT,
                authority: &first,
            }
            .signed()
        };

        assert_failed_validation(
            protect(&world, &v2(1)).await,
            "a v2 genesis list needs formats_v2",
        );
        seat(&world, &[OWNER]).await;
        assert_failed_validation(
            put(&world, &v2(2)).await,
            "a v2 seat list over a v1 list needs formats_v2",
        );
    }

    /// 4.3 step 1 (#218) with `formats_v2` on: the route refuses a v1
    /// genesis and passes a v2 one. Control: the route's format check
    /// removed.
    #[test]
    fn a_v1_genesis_is_refused_while_formats_v2_is_on() {
        crate::util::test::rt().block_on(async {
            formats_v2_on().await;
            a_v1_genesis_is_refused_while_formats_v2_is_on_case().await
        })
    }

    async fn a_v1_genesis_is_refused_while_formats_v2_is_on_case() {
        let world = world().await;
        assert_failed_validation(
            protect(&world, &ListSpec::owner(1, &[OWNER]).signed()).await,
            "a genesis list must be v2 while formats_v2 is on",
        );

        let key = owner_key();
        let first = owner_authority(&[(OWNER_DEVICE, &key)], None, &key);
        let genesis = V2List {
            channel_id: CHANNEL,
            version: 1,
            signer_user_id: OWNER,
            signer_device_id: OWNER_DEVICE,
            key: &key,
            seats: &[OWNER, MEMBER],
            salt: SALT,
            authority: &first,
        }
        .signed();
        let validated = protect(&world, &genesis).await.expect("a v2 genesis");
        assert!(!validated.retry);
        assert!(validated.body.v2.is_some());
    }

    /// 4.3 step 3b, the route's half, on the first authority (a v2 genesis).
    /// Refused: (a) the signer device listed under a key that is not its
    /// directory key, signed with that key (a forgery that verifies under
    /// the key it names); (b) the directory key listed, signed by another
    /// key; (c) a key other than the directory key listed, signed by the
    /// directory key. The honest one passes. (b) and (c) each break exactly
    /// one rule. Controls: the directory-key compare removed ((c) passes);
    /// the signature check removed ((b) passes).
    #[test]
    fn a_forged_genesis_authority_is_refused() {
        crate::util::test::rt().block_on(async {
            formats_v2_on().await;
            a_forged_genesis_authority_is_refused_case().await
        })
    }

    async fn a_forged_genesis_authority_is_refused_case() {
        let world = world().await;
        let owner = owner_key();
        let other = new_owner_key();
        let cases = [
            (
                "(a) another key, signed by it",
                "authority signer key is not the signer device key",
                owner_authority(&[(OWNER_DEVICE, &other)], None, &other),
            ),
            (
                "(b) the directory key, signed by another",
                "authority signature",
                owner_authority(&[(OWNER_DEVICE, &owner)], None, &member_key()),
            ),
            (
                "(c) another key, signed by the directory key",
                "authority signer key is not the signer device key",
                owner_authority(&[(OWNER_DEVICE, &other)], None, &owner),
            ),
        ];

        let mut misses = Vec::new();
        for (case, message, forged) in &cases {
            let genesis = V2List {
                channel_id: CHANNEL,
                version: 1,
                signer_user_id: OWNER,
                signer_device_id: OWNER_DEVICE,
                key: &owner,
                seats: &[OWNER],
                salt: SALT,
                authority: forged,
            }
            .signed();
            let result = protect(&world, &genesis).await;
            if !matches!(&result, Err(error) if is_failed_validation(&error.error_type, message)) {
                misses.push(format!("{case}: expected {message}, got {result:?}"));
            }
        }
        assert!(
            misses.is_empty(),
            "not refused as expected:\n{}",
            misses.join("\n")
        );

        let honest = owner_authority(&[(OWNER_DEVICE, &owner)], None, &owner);
        let genesis = V2List {
            channel_id: CHANNEL,
            version: 1,
            signer_user_id: OWNER,
            signer_device_id: OWNER_DEVICE,
            key: &owner,
            seats: &[OWNER],
            salt: SALT,
            authority: &honest,
        }
        .signed();
        protect(&world, &genesis)
            .await
            .expect("the honest genesis authority");
    }

    /// 4.3 step 3b (#225): a list signed by ANOTHER listed owner device that
    /// carries the stored authority unchanged (signed by the owner device)
    /// passes without the authority being verified again; when that device
    /// changes the authority, the change must verify under ITS directory
    /// key. Control: an unchanged authority re-verified under the PUT
    /// signer's key (the first list is then refused).
    #[test]
    fn an_unchanged_authority_is_not_re_verified() {
        crate::util::test::rt().block_on(async {
            formats_v2_on().await;
            an_unchanged_authority_is_not_re_verified_case().await
        })
    }

    async fn an_unchanged_authority_is_not_re_verified_case() {
        let world = world().await;
        let owner = owner_key();
        let second = second_owner_key();
        device(
            &world.harness,
            OWNER,
            SECOND_OWNER_DEVICE,
            &second,
            &world.owner_session.id,
        )
        .await;
        let owners = [(OWNER_DEVICE, &owner), (SECOND_OWNER_DEVICE, &second)];
        let first = owner_authority(&owners, None, &owner);
        seat_v2(&world, &[OWNER], &first).await;

        let from_second = |authority: &v0::SignedAuthority| {
            V2List {
                channel_id: CHANNEL,
                version: 2,
                signer_user_id: OWNER,
                signer_device_id: SECOND_OWNER_DEVICE,
                key: &second,
                seats: &[OWNER, MEMBER],
                salt: SALT,
                authority,
            }
            .signed()
        };

        let validated = put(&world, &from_second(&first))
            .await
            .expect("the stored authority, unchanged, from another owner device");
        assert!(!validated.retry);

        let changed = |signing_key: &SigningKey| {
            authority(
                CHANNEL,
                OWNER,
                SECOND_OWNER_DEVICE,
                &owners,
                Some(&first),
                signing_key,
            )
        };
        assert_failed_validation(
            put(&world, &from_second(&changed(&owner))).await,
            "authority signature",
        );
        put(&world, &from_second(&changed(&second)))
            .await
            .expect("a change signed by the PUT's own device");
    }

    /// 4.3 step 4c: a v2 list changing the stored `group_salt` is refused by
    /// the route, before the driver. Control: the route's
    /// `check_seat_list_v2_lines` call removed.
    #[test]
    fn a_changed_group_salt_is_refused() {
        crate::util::test::rt().block_on(async {
            formats_v2_on().await;
            a_changed_group_salt_is_refused_case().await
        })
    }

    async fn a_changed_group_salt_is_refused_case() {
        let world = world().await;
        let owner = owner_key();
        let first = owner_authority(&[(OWNER_DEVICE, &owner)], None, &owner);
        seat_v2(&world, &[OWNER], &first).await;

        let next = |salt| {
            V2List {
                channel_id: CHANNEL,
                version: 2,
                signer_user_id: OWNER,
                signer_device_id: OWNER_DEVICE,
                key: &owner,
                seats: &[OWNER, MEMBER],
                salt,
                authority: &first,
            }
            .signed()
        };
        assert_failed_validation(
            put(&world, &next(OTHER_SALT)).await,
            "group_salt is immutable",
        );
        put(&world, &next(SALT)).await.expect("the stored salt");
    }
}
