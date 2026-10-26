//! MLS Delivery Service + KeyPackage directory (media E2EE, slice 6).
//!
//! The server acts as a blind delivery service for per-call MLS groups: it
//! stores opaque KeyPackages, arbitrates exactly one winning commit per
//! epoch, and relays opaque handshake ciphertext through the existing E2EE
//! envelope mailbox. It never parses MLS framing and never learns group
//! secrets — the accepted server-visible metadata set is documented in the
//! slice-6 plan (§5.6) and must not grow silently.

use revolt_config::ProtectedChannelFeatures;
use revolt_database::{
    util::permissions::perms, Channel, ChannelEntitlement, Database, E2EEIdentity, MlsGroup,
    MlsGroupKind, Session, User,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionValue};
use revolt_result::{create_error, ErrorType, Result};
use revolt_rocket_okapi::revolt_okapi::openapi3::{self, MediaType, RefOr};
use rocket::http::Status;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::{Request, Response, Route};

mod commits_fetch;
mod commits_submit;
mod group_open;
mod groups_create;
mod join_intent;
mod key_packages_claim;
mod key_packages_publish;
mod messages_send;
#[cfg(test)]
mod tests;
pub(crate) mod text;
mod text_group;

/// Maximum stored one-time KeyPackages per device (mirrors
/// `MAX_ONE_TIME_KEYS`)
pub const MAX_KEY_PACKAGES: usize = 100;

/// Maximum RAW (decoded) size of a single KeyPackage
pub const MAX_KEY_PACKAGE_RAW_SIZE: usize = 8 * 1024;

/// Maximum RAW (decoded) size of an MLS commit ciphertext: 64 KiB — the same
/// abuse budget as an olm envelope (plan §2.2.4; the text-E2EE budget is NOT
/// quadrupled)
pub const MAX_MLS_COMMIT_RAW_SIZE: usize = 64 * 1024;

/// Maximum RAW (decoded) size of an MLS Welcome: 256 KiB. A Welcome is O(n)
/// in roster size; `MAX_MLS_GROUP_MEMBERS` is derived from this budget.
pub const MAX_MLS_WELCOME_RAW_SIZE: usize = 256 * 1024;

/// Maximum RAW (decoded) size of an MLS application message (the §3.4
/// downgrade ctl-announce) — a mode-change record is tiny; the cap exists
/// so the ctl pipe can never carry meaningful payload volume
pub const MAX_MLS_CTL_RAW_SIZE: usize = 4 * 1024;

/// Ctl application-message sends allowed per (group, sender user) within
/// the trailing window — a legitimate announce is ~once per interlude plus
/// one re-announce per epoch change (plan §3.4 fold ME-4/ME-5)
pub const CTL_BURST: usize = 2;

/// Trailing window for `CTL_BURST`
pub const CTL_INTERVAL_SECONDS: i64 = 5;

/// Maximum commits returned per gap-refetch request
pub const MAX_COMMITS_PER_FETCH: i64 = 100;

/// Minimum interval between join intents per (group, user, device) — the
/// joiner-side retry runs at 10 s (plan §1.4), so half that is generous
pub const MIN_JOIN_INTENT_INTERVAL_SECONDS: i64 = 5;

/// How recently a member device's join intent must have been (re)broadcast
/// to count as an OUTSTANDING rejoin for the dual-reload close (rejoin
/// plan §5): an actively rejoining device re-broadcasts every 10 s, so
/// three missed beats means it is not actively rejoining. Admission
/// consumes intent rows (`insert_mls_commit` deletes intents for added
/// devices), so this window only ever measures rejoin re-broadcasts — or a
/// post-add straggler, which goes stale within one window.
///
/// 🔴 The aging is LOAD-BEARING beyond convenience (implementation audit):
/// the Mongo driver's group-update and intent-delete are not atomic (a
/// crash between them, or a loser-side repair that skips the delete, can
/// leave a consumed row behind), and a joiner re-broadcasting between its
/// Add and its Welcome briefly re-creates its row — in both shapes it is
/// this window expiring, not the delete, that keeps the row from feeding a
/// false close. Do not shrink it below the client's re-broadcast beat, and
/// do not remove the aging check.
pub const REJOIN_OUTSTANDING_WINDOW_SECONDS: i64 = 30;

/// KeyPackage claims allowed per (claimer, target device) per minute. Racing
/// admitters cost one claim each per contested join (plan §1.4) and the
/// admitter stagger keeps races rare, so a small budget suffices.
pub const MAX_CLAIMS_PER_TARGET_PER_MINUTE: usize = 5;

/// KeyPackage lifetime for one-time packages (matches envelope TTL)
pub const KEY_PACKAGE_LIFETIME_DAYS: i64 = 30;

/// KeyPackage lifetime for the last-resort package — deliberately SHORT: a
/// reused init key weakens Welcome forward secrecy, so the exposure window
/// is bounded tightly (plan §2.2.1 / §5.6)
pub const LAST_RESORT_LIFETIME_DAYS: i64 = 7;

/// Unpadded-base64 length for a given raw byte length (envelopes carry
/// base64 text; caps are stated raw, enforced on the encoded field —
/// encoded-vs-raw is accounted explicitly, plan §2.2.4)
pub const fn encoded_len(raw: usize) -> usize {
    raw.div_ceil(3) * 4
}

/// All MLS routes sit behind the media-E2EE operator flag, which itself
/// requires the text-E2EE flag (media E2EE builds on slice-1..5 machinery).
/// The rule itself is the database crate's `voice::media_e2ee_enabled`, the
/// one a voice move reads too (merge slice P2A-9, F9), so a device-qualified
/// join and a move can never disagree about it.
pub async fn require_media_e2ee_enabled() -> Result<()> {
    if !revolt_database::voice::media_e2ee_enabled().await {
        return Err(create_error!(FeatureDisabled {
            feature: "media_e2ee".to_string()
        }));
    }

    Ok(())
}

/// Text maintenance gate (protected-channels design §7.1): the text plane
/// needs the E2EE identity directory, so `e2ee_enabled` is its kill switch.
/// Commit fetch, Remove/Update commits, the text group state, `GET
/// .../seats` and the encrypted send sit behind this gate alone: the growth
/// flag never stops them (decision 5 (W2)). The media flag plays no part.
pub(crate) async fn require_protected_available() -> Result<()> {
    if !revolt_config::config().await.features.e2ee_enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "e2ee".to_string()
        }));
    }

    Ok(())
}

/// Text growth gate (§7.1): available AND `protected_channels.enabled`, for
/// grants, protect, seat claims, Text group create, join intents, KeyPackage
/// claims and Adds. Availability is checked first, so with E2EE off the
/// answer is `e2ee` whatever the growth flag says.
pub(crate) async fn require_protected_growth() -> Result<()> {
    require_protected_available().await?;
    let features = revolt_config::config().await.features;
    if !features.protected_channels.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "protected_channels".to_string()
        }));
    }

    Ok(())
}

/// `NotSeated` unless `user_id` holds an ACTIVE seat in `channel_id`
/// (§2.3: a seat is active until released; a cooling seat is not a seat).
/// This is the Delivery Service's view only; members trust the owner-signed
/// list (§1.2).
pub(crate) async fn require_seated(db: &Database, channel_id: &str, user_id: &str) -> Result<()> {
    let seated = db
        .fetch_channel_seats_for_user(user_id)
        .await?
        .iter()
        .any(|seat| seat.channel_id == channel_id && seat.user_id == user_id && seat.is_active());
    if !seated {
        return Err(create_error!(NotSeated));
    }

    Ok(())
}

/// The channel's effective entitlement device cap (§2.2): the entitlement's
/// own `device_cap` when set, an explicit `0` included, else the configured
/// `default_device_cap`. `0` = unlimited (still bounded by the 100-leaf cap).
///
/// This is ONE operand of the cap the Delivery Service enforces on Adds and
/// join intents, `min(signed-list device_cap, effective cap)` with `0` =
/// unlimited in either operand (§2.5, W0-fix3). The signed-list operand is
/// not known here, so that min is the caller's.
pub(crate) fn effective_device_cap(
    entitlement: &ChannelEntitlement,
    config: &ProtectedChannelFeatures,
) -> u32 {
    entitlement.device_cap.unwrap_or(config.default_device_cap)
}

/// Which gate a group-scoped route applies when the group is a Text group
/// (§7.1, §7.2 "Existing MLS routes")
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextGate {
    /// Maintenance: [`require_protected_available`]
    Available,
    /// Growth: [`require_protected_growth`]
    Growth,
}

/// What [`dispatch_group`] found for a group id
#[derive(Debug)]
pub(crate) enum GroupDispatch {
    /// A Text group. NO gate and no caller check has run. The route goes on
    /// in this order: fetch the group's channel (ANY failure answers
    /// [`as_unknown_group`]) → ViewChannel (missing answers
    /// [`as_unknown_group`]) → [`require_mls_caller`] →
    /// [`require_text_gate`] → seated → the route's own rules.
    Text(MlsGroup),
    /// A Call group, or `None` for a group id the server does not know.
    /// [`require_media_e2ee_enabled`] has passed. `None` answers
    /// [`as_unknown_group`]; a Call group goes on to the route's existing
    /// checks, unchanged.
    CallOrUnknown(Option<MlsGroup>),
}

/// Kind dispatch for the group-scoped MLS routes (decision 1 (W2)), the
/// FIRST check of every such route: the STORED group's kind picks the path
/// (see [`GroupDispatch`] for what each path does next). A Call group, and a
/// group id the server does not know, get [`require_media_e2ee_enabled`]
/// here, so with the media flag off they answer `FeatureDisabled
/// { media_e2ee }` as they did before Text groups existed.
///
/// A Text group gets NO gate here. Gating it before the access check let a
/// non-viewer of a hidden channel, who can compute `text_group_id`, tell a
/// protected channel from an unprotected one by which error answered (W2a
/// audit WA#1). Its gate is [`require_text_gate`], after ViewChannel.
///
/// A read error other than `NotFound` runs the media gate FIRST, so with the
/// media flag off it answers 400 like an unknown group (WA#3); with the flag
/// on it is returned as is: the kind is not known, so nothing passes.
pub(crate) async fn dispatch_group(db: &Database, group_id: &str) -> Result<GroupDispatch> {
    let group = match db.fetch_mls_group(group_id).await {
        Ok(group) => Some(group),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => None,
        Err(error) => {
            require_media_e2ee_enabled().await?;
            return Err(error);
        }
    };

    match group {
        Some(group) => match group.kind {
            MlsGroupKind::Text => Ok(GroupDispatch::Text(group)),
            MlsGroupKind::Call => {
                require_media_e2ee_enabled().await?;
                Ok(GroupDispatch::CallOrUnknown(Some(group)))
            }
        },
        None => {
            require_media_e2ee_enabled().await?;
            Ok(GroupDispatch::CallOrUnknown(None))
        }
    }
}

/// The caller checks every MLS route shares (decision 1 (W2)): not a bot,
/// then, when the route takes a session, a session bound to one of the
/// caller's E2EE devices. The SINGLE source of these errors for an unknown
/// group id ([`as_unknown_group`]) and for a Text group's viewer, so the two
/// answers are the same error by construction (fix re-review RR#1). The
/// response body carries no `location` (upstream 2e8bf9d7); the one site
/// keeps the server-log location of the two the same as well.
///
/// `None` is for a route that takes no session at all; it skips the bound
/// session check only, never the bot check.
pub(crate) async fn require_mls_caller(
    db: &Database,
    user: &User,
    session: Option<&Session>,
) -> Result<()> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    if let Some(session) = session {
        E2EEIdentity::require_device_bound_session(db, &user.id, &session.id).await?;
    }

    Ok(())
}

/// The Text plane's gate for a group-scoped route (§7.1), applied after
/// ViewChannel and [`require_mls_caller`] (decision 1 (W2)), so which gate
/// answers is visible only to a caller who can see the channel (decision 17
/// (W2)).
pub(crate) async fn require_text_gate(text_gate: TextGate) -> Result<()> {
    match text_gate {
        TextGate::Available => require_protected_available().await,
        TextGate::Growth => require_protected_growth().await,
    }
}

/// The answer a group id the server does not know gets:
/// [`require_media_e2ee_enabled`], then [`require_mls_caller`], then
/// `NotFound`. A Text route gives the same answer when the group's channel
/// cannot be fetched or the caller cannot view it, so for every caller (a
/// member, a bot, an unbound session) a hidden or deleted channel's Text
/// group is indistinguishable from no group at all (WA#1, RR#1).
///
/// A route answers `GroupDispatch::CallOrUnknown(None)` and those Text cases
/// through this function, never through a later fetch's `NotFound` or its
/// own caller checks. The response body carries no `location` (upstream
/// 2e8bf9d7), so this is not about the body's bytes: a second site can
/// drift from this one in its gate order or its errors, and the oracle
/// tests would then see different answers.
pub(crate) async fn as_unknown_group<T>(
    db: &Database,
    user: &User,
    session: Option<&Session>,
) -> Result<T> {
    require_media_e2ee_enabled().await?;
    require_mls_caller(db, user, session).await?;
    Err(create_error!(NotFound))
}

/// Whether `user` can access (view) `channel` — the authorization primitive
/// for every group-scoped route (plan §1.2: reuse the existing
/// channel-permission machinery). Returns the computed permissions so
/// callers can layer further checks.
pub async fn require_channel_access(
    db: &Database,
    user: &User,
    channel: &Channel,
) -> Result<PermissionValue> {
    let mut query = perms(db, user).channel(channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    Ok(permissions)
}

/// Resolve a group and authorize the calling user against its channel.
/// Returns (group, channel).
pub async fn fetch_authorized_group(
    db: &Database,
    user: &User,
    group_id: &str,
) -> Result<(MlsGroup, Channel)> {
    let group = db.fetch_mls_group(group_id).await?;
    let channel = revolt_database::util::reference::Reference::from_unchecked(&group.channel_id)
        .as_channel(db)
        .await?;
    require_channel_access(db, user, &channel).await?;
    Ok((group, channel))
}

/// A JSON response that is either 200 (arbitration settled in the caller's
/// favor) or 409 Conflict (the body carries what the loser needs — the open
/// group id, or the winning commit to rebase onto). Plan §1.2 / §2.2.3.
pub struct Arbitrated<T> {
    pub conflict: bool,
    pub body: Json<T>,
}

impl<'r, T: serde::Serialize> Responder<'r, 'static> for Arbitrated<T> {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        let mut builder = Response::build_from(self.body.respond_to(req)?);
        if self.conflict {
            builder.status(Status::Conflict);
        }
        builder.ok()
    }
}

impl<T: schemars::JsonSchema> revolt_rocket_okapi::response::OpenApiResponderInner
    for Arbitrated<T>
{
    fn responses(
        gen: &mut revolt_rocket_okapi::gen::OpenApiGenerator,
    ) -> std::result::Result<openapi3::Responses, revolt_rocket_okapi::OpenApiError> {
        let schema = gen.json_schema::<T>();
        let mut content = schemars::Map::new();
        content.insert(
            "application/json".to_owned(),
            MediaType {
                schema: Some(schema),
                ..Default::default()
            },
        );

        let mut responses = schemars::Map::new();
        responses.insert(
            "200".to_string(),
            RefOr::Object(openapi3::Response {
                description: "Arbitration won".to_string(),
                content: content.clone(),
                ..Default::default()
            }),
        );
        responses.insert(
            "409".to_string(),
            RefOr::Object(openapi3::Response {
                description: "Arbitration lost — the body carries the winner".to_string(),
                content,
                ..Default::default()
            }),
        );

        Ok(openapi3::Responses {
            responses,
            ..Default::default()
        })
    }
}

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        key_packages_publish::publish_key_packages,
        key_packages_claim::claim_key_packages,
        groups_create::create_group,
        join_intent::join_intent,
        commits_submit::submit_commit,
        commits_fetch::fetch_commits,
        messages_send::send_message,
        group_open::open_group,
        text_group::fetch_text_group,
    ]
}

use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;

#[cfg(test)]
mod flag_delegation {
    const SOURCE: &str = include_str!("mod.rs");

    /// The body of `require_media_e2ee_enabled`, comment lines dropped and
    /// whitespace collapsed.
    fn gate_body() -> String {
        flat_body("pub async fn require_media_e2ee_enabled(")
    }

    /// The body of the function `signature` opens, comment lines dropped and
    /// whitespace collapsed.
    fn flat_body(signature: &str) -> String {
        const OPEN: char = '\u{7b}';
        const CLOSE: char = '\u{7d}';
        let at = SOURCE
            .find(signature)
            .unwrap_or_else(|| panic!("mod.rs defines `{}`", signature));
        let open = at + SOURCE[at..].find(OPEN).expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in SOURCE[open..].char_indices() {
            if ch == OPEN {
                depth += 1;
            } else if ch == CLOSE {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
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

    /// Merge slice P2A-9 (F9): the MLS gate decides through the database
    /// crate's `media_e2ee_enabled` alone, with the polarity exact, and
    /// reads no flag of its own that could drift from the rule a voice move
    /// applies. Control GATE-INLINE (the old inline body restored).
    #[test]
    fn the_gate_delegates_to_the_database_crate() {
        let body = gate_body();

        assert!(
            body.contains(
                "if !revolt_database::voice::media_e2ee_enabled().await \u{7b} \
                 return Err(create_error!(FeatureDisabled \u{7b} feature: \
                 \"media_e2ee\".to_string() \u{7d}));"
            ),
            "{}",
            body
        );
        assert_eq!(body.matches("media_e2ee_enabled(").count(), 1, "{}", body);
        for banned in ["features", "config(", "e2ee_enabled &&", "e2ee_enabled ||"] {
            assert!(
                !body.contains(banned),
                "the gate reads `{}` itself: {}",
                banned,
                body
            );
        }
    }

    /// WA#3: a group read error other than `NotFound` runs the media gate
    /// BEFORE it is returned, so media-off answers 400 rather than the read
    /// error. A source-order check because a delta test cannot inject the
    /// error: the Reference driver only ever answers `NotFound`, and in a
    /// debug build the Mongo driver's `query!` unwraps (panics) instead of
    /// returning one. Control READ-ERROR-FIRST (the error returned before the
    /// gate).
    #[test]
    fn a_read_error_meets_the_media_gate_first() {
        let body = flat_body("pub(crate) async fn dispatch_group(");

        assert!(
            body.contains(
                "Err(error) if matches!(error.error_type, ErrorType::NotFound) => None, \
                 Err(error) => \u{7b} require_media_e2ee_enabled().await?; \
                 return Err(error); \u{7d}"
            ),
            "{}",
            body
        );
        assert_eq!(body.matches("return Err(error)").count(), 1, "{}", body);
    }
}

/// Protected-channel gates and helpers (W2 decisions 1, 3 and 5, design
/// §7.1). Every flag case is its own `#[test]`: `overwrite_config` runs once
/// per process, BEFORE the harness primes the config cache, so these need
/// nextest (one process per test). The test config has every flag on.
#[cfg(test)]
mod protected_gates {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::Timestamp;
    use revolt_config::ProtectedChannelFeatures;
    use revolt_database::{
        BotInformation, ChannelEntitlement, ChannelEntitlementSource, ChannelEntitlementState,
        Database, Member, MemberCompositeKey, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind,
        MlsMemberDevice, PartialChannel, SeatListBody, SeatListSubmission, Session, User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::{Error, ErrorType, Result};
    use ulid::Ulid;

    use super::text::text_group_id;
    use super::{
        as_unknown_group, dispatch_group, effective_device_cap, require_channel_access,
        require_mls_caller, require_protected_available, require_protected_growth, require_seated,
        require_text_gate, GroupDispatch, TextGate,
    };
    use crate::util::test::TestHarness;

    const OWNER_DEVICE: &str = "00112233445566778899aabbccddeeff";
    const GATES: [TextGate; 2] = [TextGate::Available, TextGate::Growth];

    struct Fixture {
        harness: TestHarness,
        server_id: String,
        owner_id: String,
        other_user_id: String,
        channel_id: String,
        call_channel_id: String,
        text_group_id: String,
        call_group_id: String,
        unknown_group_id: String,
    }

    fn random_group_id() -> String {
        format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0)
    }

    /// A protected channel (genesis list seats the owner only) with its
    /// generation-0 Text group, and an open Call group on another channel.
    /// Built through the database layer, which verifies no signatures.
    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, _, other) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let channel_id = harness.new_channel(&server).await.id().to_string();
        let call_channel_id = harness.new_channel(&server).await.id().to_string();
        let now = Timestamp::now_utc();

        harness
            .db
            .insert_or_merge_member(&Member {
                id: MemberCompositeKey {
                    server: server.id.clone(),
                    user: owner.id.clone(),
                },
                ..Default::default()
            })
            .await
            .expect("owner membership");
        harness
            .db
            .upsert_channel_entitlement(
                &ChannelEntitlement {
                    id: Ulid::new().to_string(),
                    channel_id: channel_id.clone(),
                    server_id: server.id.clone(),
                    source: ChannelEntitlementSource::AdminGrant,
                    slot_cap: 10,
                    device_cap: None,
                    state: ChannelEntitlementState::Active,
                    granted_by: owner.id.clone(),
                    created_at: now,
                },
                now,
            )
            .await
            .expect("entitlement");
        let body = SeatListBody {
            channel_id: channel_id.clone(),
            version: 1,
            device_cap: 5,
            issued_at: 1_790_812_800_000,
            signer_user_id: owner.id.clone(),
            signer_device_id: OWNER_DEVICE.to_string(),
            seats: vec![owner.id.clone()],
        }
        .build()
        .expect("seat list body");
        harness
            .db
            .protect_channel(
                &channel_id,
                &SeatListSubmission {
                    body,
                    signature: STANDARD_NO_PAD.encode([7u8; 64]),
                    signer_device_id: OWNER_DEVICE.to_string(),
                    handover: None,
                },
                now,
            )
            .await
            .expect("protect");

        let creator = MlsMemberDevice {
            user_id: owner.id.clone(),
            device_id: OWNER_DEVICE.to_string(),
        };
        let text_group = MlsGroup {
            id: text_group_id(&channel_id, 0),
            channel_id: channel_id.clone(),
            open: true,
            created_by: creator.clone(),
            created_at: now,
            current_epoch: 0,
            members: vec![creator.clone()],
            closed_at: None,
            superseded_by: None,
            kind: MlsGroupKind::Text,
            generation: Some(0),
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
        };
        assert!(matches!(
            harness
                .db
                .create_text_mls_group(&text_group, None)
                .await
                .expect("text group"),
            MlsGroupCreateOutcome::Created
        ));

        let call_group = MlsGroup {
            id: random_group_id(),
            channel_id: call_channel_id.clone(),
            kind: MlsGroupKind::Call,
            generation: None,
            ..text_group.clone()
        };
        assert!(matches!(
            harness
                .db
                .create_mls_group(&call_group, None)
                .await
                .expect("call group"),
            MlsGroupCreateOutcome::Created
        ));

        Fixture {
            harness,
            server_id: server.id,
            owner_id: owner.id,
            other_user_id: other.id,
            channel_id,
            call_channel_id,
            text_group_id: text_group.id,
            call_group_id: call_group.id,
            unknown_group_id: random_group_id(),
        }
    }

    #[track_caller]
    fn assert_disabled<T: std::fmt::Debug>(result: Result<T>, feature: &str, case: &str) {
        match result {
            Err(Error {
                error_type: ErrorType::FeatureDisabled { feature: actual },
                ..
            }) => assert_eq!(actual, feature, "{}", case),
            other => panic!(
                "{}: expected FeatureDisabled {{ {} }}, got {:?}",
                case, feature, other
            ),
        }
    }

    #[track_caller]
    fn assert_not_seated(result: Result<()>, case: &str) {
        assert!(
            matches!(
                result,
                Err(Error {
                    error_type: ErrorType::NotSeated,
                    ..
                })
            ),
            "{}: expected NotSeated, got {:?}",
            case,
            result
        );
    }

    #[track_caller]
    fn assert_not_found<T: std::fmt::Debug>(result: Result<T>, case: &str) {
        assert!(
            matches!(
                result,
                Err(Error {
                    error_type: ErrorType::NotFound,
                    ..
                })
            ),
            "{}: expected NotFound, got {:?}",
            case,
            result
        );
    }

    /// [`as_unknown_group`] for the fixture's owner on a route without a
    /// session
    async fn unknown_answer(fixture: &Fixture) -> Result<()> {
        let db = &fixture.harness.db;
        let owner = db.fetch_user(&fixture.owner_id).await.expect("owner");
        as_unknown_group(db, &owner, None).await
    }

    /// What `dispatch_group` let through
    #[derive(Debug, PartialEq, Eq)]
    enum Dispatched {
        Text,
        Call,
        Unknown,
    }

    /// Where `dispatch_group` sent `group_id`; panics when it refuses
    async fn dispatched(fixture: &Fixture, group_id: &str) -> Dispatched {
        let dispatch = dispatch_group(&fixture.harness.db, group_id)
            .await
            .unwrap_or_else(|error| panic!("{}: refused {:?}", group_id, error));
        let (group, dispatched) = match dispatch {
            GroupDispatch::Text(group) => (group, Dispatched::Text),
            GroupDispatch::CallOrUnknown(Some(group)) => (group, Dispatched::Call),
            GroupDispatch::CallOrUnknown(None) => return Dispatched::Unknown,
        };
        assert_eq!(group.id, group_id);
        let kind = match dispatched {
            Dispatched::Text => MlsGroupKind::Text,
            _ => MlsGroupKind::Call,
        };
        assert_eq!(group.kind, kind, "{}", group_id);
        dispatched
    }

    #[test]
    fn gates_with_every_flag_on() {
        crate::util::test::rt().block_on(gates_with_every_flag_on_case())
    }

    async fn gates_with_every_flag_on_case() {
        let fixture = fixture().await;

        require_protected_available().await.expect("available");
        require_protected_growth().await.expect("growth");
        for gate in GATES {
            require_text_gate(gate).await.expect("the text gate");
        }
        assert_eq!(
            dispatched(&fixture, &fixture.text_group_id).await,
            Dispatched::Text
        );
        assert_eq!(
            dispatched(&fixture, &fixture.call_group_id).await,
            Dispatched::Call
        );
        assert_eq!(
            dispatched(&fixture, &fixture.unknown_group_id).await,
            Dispatched::Unknown
        );
        assert_not_found(unknown_answer(&fixture).await, "unknown");
    }

    #[test]
    fn gates_with_e2ee_off() {
        crate::util::test::rt().block_on(gates_with_e2ee_off_case())
    }

    async fn gates_with_e2ee_off_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.e2ee_enabled = false;
        })
        .await;
        let fixture = fixture().await;
        let db = &fixture.harness.db;

        // Availability answers first, whatever the growth flag says
        assert_disabled(require_protected_available().await, "e2ee", "available");
        assert_disabled(require_protected_growth().await, "e2ee", "growth");
        for gate in GATES {
            assert_disabled(require_text_gate(gate).await, "e2ee", &format!("{gate:?}"));
        }
        // The dispatch gates no Text group; the route does, after ViewChannel
        assert_eq!(
            dispatched(&fixture, &fixture.text_group_id).await,
            Dispatched::Text
        );
        // The media gate needs e2ee too
        assert_disabled(
            dispatch_group(db, &fixture.call_group_id).await,
            "media_e2ee",
            "call",
        );
        assert_disabled(
            dispatch_group(db, &fixture.unknown_group_id).await,
            "media_e2ee",
            "unknown",
        );
        assert_disabled(unknown_answer(&fixture).await, "media_e2ee", "as unknown");
    }

    #[test]
    fn gates_with_growth_off() {
        crate::util::test::rt().block_on(gates_with_growth_off_case())
    }

    async fn gates_with_growth_off_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.enabled = false;
        })
        .await;
        let fixture = fixture().await;

        // Growth off freezes growth only (decision 5 (W2))
        require_protected_available().await.expect("available");
        assert_disabled(
            require_protected_growth().await,
            "protected_channels",
            "growth",
        );
        require_text_gate(TextGate::Available)
            .await
            .expect("the maintenance gate");
        assert_disabled(
            require_text_gate(TextGate::Growth).await,
            "protected_channels",
            "Growth",
        );
        assert_eq!(
            dispatched(&fixture, &fixture.text_group_id).await,
            Dispatched::Text
        );
        // Call paths never read the growth flag
        assert_eq!(
            dispatched(&fixture, &fixture.call_group_id).await,
            Dispatched::Call
        );
        assert_eq!(
            dispatched(&fixture, &fixture.unknown_group_id).await,
            Dispatched::Unknown
        );
        assert_not_found(unknown_answer(&fixture).await, "unknown");
    }

    #[test]
    fn gates_with_media_off() {
        crate::util::test::rt().block_on(gates_with_media_off_case())
    }

    async fn gates_with_media_off_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.media_e2ee_enabled = false;
        })
        .await;
        let fixture = fixture().await;
        let db = &fixture.harness.db;

        // Text groups ignore the media flag (W2 plan verification: "text_group
        // ignores the media flag"); Call and unknown groups keep today's answer
        require_protected_available().await.expect("available");
        require_protected_growth().await.expect("growth");
        for gate in GATES {
            require_text_gate(gate).await.expect("the text gate");
        }
        assert_eq!(
            dispatched(&fixture, &fixture.text_group_id).await,
            Dispatched::Text
        );
        assert_disabled(
            dispatch_group(db, &fixture.call_group_id).await,
            "media_e2ee",
            "call",
        );
        assert_disabled(
            dispatch_group(db, &fixture.unknown_group_id).await,
            "media_e2ee",
            "unknown",
        );
        assert_disabled(unknown_answer(&fixture).await, "media_e2ee", "as unknown");
    }

    /// A Text-capable route's checks in decision 1 (W2) order: kind dispatch;
    /// an unknown id answers [`as_unknown_group`]; for a Text group, the
    /// channel fetch and ViewChannel (any failure answers
    /// [`as_unknown_group`]), then the shared caller checks, the Text gate
    /// and the seat.
    async fn text_route(
        db: &Database,
        user: &User,
        session: Option<&Session>,
        group_id: &str,
        gate: TextGate,
    ) -> Result<MlsGroup> {
        match dispatch_group(db, group_id).await? {
            GroupDispatch::CallOrUnknown(None) => as_unknown_group(db, user, session).await,
            GroupDispatch::CallOrUnknown(Some(group)) => {
                panic!("{}: a Call group on a Text route", group.id)
            }
            GroupDispatch::Text(group) => {
                let Ok(channel) = db.fetch_channel(&group.channel_id).await else {
                    return as_unknown_group(db, user, session).await;
                };
                if require_channel_access(db, user, &channel).await.is_err() {
                    return as_unknown_group(db, user, session).await;
                }
                require_mls_caller(db, user, session).await?;
                require_text_gate(gate).await?;
                require_seated(db, &group.channel_id, &user.id).await?;
                Ok(group)
            }
        }
    }

    /// The response body a refusal serializes to
    #[track_caller]
    fn refusal_body(result: Result<MlsGroup>, case: &str) -> String {
        match result {
            Err(error) => serde_json::to_string(&error).expect("an error body"),
            Ok(group) => panic!("{}: served {}", case, group.id),
        }
    }

    /// One caller class of the oracle: the caller and its session
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
    /// view (`@everyone` denied ViewChannel), a second protected channel
    /// deleted under its Text group, and one caller of each class: a member
    /// with a bound session, a bot (a member, no device) and a member whose
    /// session is bound to none of its devices
    async fn oracle_fixture() -> Oracle {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, mut bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        let hidden = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        for user in [&member, &bot, &unbound] {
            harness.join_server(&hidden.server, user).await;
        }
        bot.bot = Some(BotInformation {
            owner: owner.id.clone(),
        });
        harness
            .new_e2ee_device(&member, &member_session.id, 41)
            .await;
        harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), 42)
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

    /// WA#1, RR#1: for every caller class, a Text group whose channel the
    /// caller cannot view, and one whose channel was deleted, answer EXACTLY
    /// as a group id the server does not know: the same response body
    /// (which carries no `location`), under every flag combination
    async fn hidden_and_deleted_text_groups_answer_as_unknown() {
        let oracle = oracle_fixture().await;
        let db = &oracle.harness.db;
        let media = revolt_database::voice::media_e2ee_enabled().await;

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
        if revolt_config::config().await.features.e2ee_enabled {
            // The owner (a viewer, seated, bound) passes the maintenance gate
            text_route(
                db,
                &oracle.owner,
                Some(&oracle.owner_session),
                &oracle.hidden_group_id,
                TextGate::Available,
            )
            .await
            .expect("the owner is served");
        }

        for caller in &oracle.callers {
            assert!(
                require_channel_access(db, &caller.user, &channel)
                    .await
                    .is_err(),
                "{} views the hidden channel",
                caller.class
            );
            let session = Some(&caller.session);
            for gate in GATES {
                let case = format!("{} {gate:?}", caller.class);
                let unknown = refusal_body(
                    text_route(db, &caller.user, session, &oracle.unknown_group_id, gate).await,
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
                        text_route(db, &caller.user, session, group_id, gate).await,
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

    #[test]
    fn require_seated_needs_an_active_seat() {
        crate::util::test::rt().block_on(require_seated_needs_an_active_seat_case())
    }

    async fn require_seated_needs_an_active_seat_case() {
        let fixture = fixture().await;
        let db = &fixture.harness.db;

        require_seated(db, &fixture.channel_id, &fixture.owner_id)
            .await
            .expect("the genesis list seats the owner");
        assert_not_seated(
            require_seated(db, &fixture.channel_id, &fixture.other_user_id).await,
            "never seated",
        );
        assert_not_seated(
            require_seated(db, &fixture.call_channel_id, &fixture.owner_id).await,
            "seated in another channel only",
        );

        // A released seat is not a seat, even while it cools down
        let released = db
            .release_channel_seats_for_user(
                &fixture.owner_id,
                Some(&fixture.server_id),
                Timestamp::now_utc(),
            )
            .await
            .expect("release");
        assert_eq!(released, vec![fixture.channel_id.clone()]);
        assert_not_seated(
            require_seated(db, &fixture.channel_id, &fixture.owner_id).await,
            "released",
        );
    }

    fn entitlement_with(device_cap: Option<u32>) -> ChannelEntitlement {
        ChannelEntitlement {
            id: Ulid::new().to_string(),
            channel_id: Ulid::new().to_string(),
            server_id: Ulid::new().to_string(),
            source: ChannelEntitlementSource::AdminGrant,
            slot_cap: 10,
            device_cap,
            state: ChannelEntitlementState::Active,
            granted_by: Ulid::new().to_string(),
            created_at: Timestamp::now_utc(),
        }
    }

    fn config_with(default_device_cap: u32) -> ProtectedChannelFeatures {
        ProtectedChannelFeatures {
            default_device_cap,
            ..Default::default()
        }
    }

    #[test]
    fn effective_device_cap_prefers_the_entitlement() {
        // The entitlement's own cap wins, below or above the default
        assert_eq!(
            effective_device_cap(&entitlement_with(Some(3)), &config_with(5)),
            3
        );
        assert_eq!(
            effective_device_cap(&entitlement_with(Some(7)), &config_with(5)),
            7
        );
        assert_eq!(
            effective_device_cap(&entitlement_with(Some(2)), &config_with(0)),
            2
        );
        // An explicit 0 is unlimited, not "unset"
        assert_eq!(
            effective_device_cap(&entitlement_with(Some(0)), &config_with(5)),
            0
        );
        // Unset takes the configured default, 0 = unlimited included
        assert_eq!(
            effective_device_cap(&entitlement_with(None), &config_with(5)),
            5
        );
        assert_eq!(
            effective_device_cap(&entitlement_with(None), &config_with(0)),
            0
        );
    }
}
