//! MLS Delivery Service + KeyPackage directory (media E2EE, slice 6).
//!
//! The server acts as a blind delivery service for per-call MLS groups: it
//! stores opaque KeyPackages, arbitrates exactly one winning commit per
//! epoch, and relays opaque handshake ciphertext through the existing E2EE
//! envelope mailbox. It never parses MLS framing and never learns group
//! secrets — the accepted server-visible metadata set is documented in the
//! slice-6 plan (§5.6) and must not grow silently.

use revolt_database::{
    util::permissions::perms, Channel, Database, MlsGroup, User,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};
use revolt_rocket_okapi::revolt_okapi::openapi3::{self, MediaType, RefOr};
use rocket::http::Status;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::{Request, Response, Route};

mod commits_fetch;
mod commits_submit;
mod groups_create;
mod join_intent;
mod key_packages_claim;
mod key_packages_publish;
#[cfg(test)]
mod tests;

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

/// Maximum commits returned per gap-refetch request
pub const MAX_COMMITS_PER_FETCH: i64 = 100;

/// Minimum interval between join intents per (group, user, device) — the
/// joiner-side retry runs at 10 s (plan §1.4), so half that is generous
pub const MIN_JOIN_INTENT_INTERVAL_SECONDS: i64 = 5;

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
/// requires the text-E2EE flag (media E2EE builds on slice-1..5 machinery)
pub async fn require_media_e2ee_enabled() -> Result<()> {
    let features = &revolt_config::config().await.features;
    if !features.e2ee_enabled || !features.media_e2ee_enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "media_e2ee".to_string()
        }));
    }

    Ok(())
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
    ]
}

use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
