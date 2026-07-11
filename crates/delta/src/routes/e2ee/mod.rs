use revolt_database::{Channel, Database, RelationshipStatus, User};
use revolt_permissions::{calculate_user_permissions, UserPermission};
use revolt_result::{create_error, Result};
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod delete_backup;
mod fetch_devices;
mod fetch_keys;
mod get_backup;
mod get_backup_status;
mod publish_keys;
mod put_backup;
mod revoke_device;
mod send_messages;
#[cfg(test)]
pub(crate) mod tests;

/// Maximum length of a key-backup header (the plaintext, server-visible AAD)
pub const MAX_BACKUP_HEADER_LENGTH: usize = 1024;

/// Maximum a backup `generation` may exceed the previously-stored value on a
/// single PUT. Legitimate refreshes step by 1, so this generous bound only
/// blocks a compromised webview from jumping the stored generation to a huge
/// value to permanently wedge future PUTs (M2 defence-in-depth).
pub const MAX_BACKUP_GENERATION_JUMP: i64 = 1_000_000;

/// Maximum one-time keys stored per device
pub const MAX_ONE_TIME_KEYS: usize = 100;

/// Maximum length of a key id
pub const MAX_KEY_ID_LENGTH: usize = 32;

/// Maximum length of an encoded public key (32 bytes ≈ 43 chars base64)
pub const MAX_KEY_LENGTH: usize = 64;

/// Maximum length of an encoded signature (64 bytes ≈ 86 chars base64)
pub const MAX_SIGNATURE_LENGTH: usize = 96;

/// Maximum envelopes per submission (recipient devices per message)
pub const MAX_ENVELOPES_PER_REQUEST: usize = 128;

/// Maximum encoded ciphertext length per envelope
pub const MAX_CIPHERTEXT_LENGTH: usize = 65536;

/// Maximum queued envelopes per recipient device: a dead device's queue
/// fills up and TTLs out without blocking live devices (per-device cap)
pub const MAX_QUEUE_DEPTH: u64 = 512;

/// Maximum queued ENCODED ciphertext bytes per recipient device (media-E2EE
/// plan §2.2.4 queue-budget re-derivation). The depth cap was sized when
/// every envelope was ≤ 64 KiB — an implicit worst case of 512 × 64 KiB =
/// 32 MiB per device. MLS Welcomes raise the per-envelope cap to 256 KiB
/// raw (≈ 341 KiB encoded), so without a byte budget the same depth cap
/// would mean a ~5× larger abuse ceiling. This budget pins the ceiling at
/// the pre-slice-6 value; it is enforced on the MLS fan-out path (the only
/// source of over-64-KiB envelopes — client submission stays olm-only).
pub const MAX_QUEUE_BYTES: u64 = 32 * 1024 * 1024;

/// All E2EE routes sit behind the operator feature flag
pub async fn require_e2ee_enabled() -> Result<()> {
    if !revolt_config::config().await.features.e2ee_enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "e2ee".to_string()
        }));
    }

    Ok(())
}

/// Whether `caller` and `target` share at least one Group channel (both are
/// current recipients). Group DM E2EE (slice 5): group co-members must be
/// able to fetch each other's bundles and exchange envelopes even when they
/// are not friends, mirroring the plaintext group behaviour. Computed
/// entirely from the SERVER's own channel data — the client names no
/// channel, so this reveals nothing the server did not already know and adds
/// nothing to the stored/relayed metadata set.
pub async fn users_share_group(db: &Database, caller: &str, target: &str) -> Result<bool> {
    let mut generator = db.find_group_message_channels(caller).await?;
    while let Some(groups) = generator.next_n(100).await? {
        for channel in groups {
            if let Channel::Group { recipients, .. } = channel {
                if recipients.iter().any(|id| id == caller)
                    && recipients.iter().any(|id| id == target)
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Whether the caller is blocked-paired with the target (either direction).
fn is_blocked_pair(caller: &User, target: &str) -> bool {
    matches!(
        caller.relationship_with(target),
        RelationshipStatus::Blocked | RelationshipStatus::BlockedOther
    )
}

/// The pre-slice-5 friend/mutual-connection DM-eligibility check
/// (`UserPermission::SendMessage`): friends, or a mutual server/channel.
async fn friend_or_mutual_eligible(db: &Database, caller: &User, target: &User) -> bool {
    let mut query = revolt_database::util::permissions::DatabasePermissionQuery::new(db, caller)
        .user(target);
    calculate_user_permissions(&mut query)
        .await
        .has_user_permission(UserPermission::SendMessage)
}

/// E2EE bundle/device-FETCH eligibility (slice 5, design §2.6): the caller
/// may fetch `target`'s bundle/devices iff they share a Group channel AND
/// are not a blocked pair, OR they are friend/mutual-eligible as before.
/// Fetching your own material is always allowed (own-device fan-out).
/// Blocked members of a shared group are refused here so a blocked member
/// surfaces to the sender as Blocked; the honest resolution is
/// removal/unblock. (The shared-group check comes first because it is
/// portable across both DB drivers; the friend/mutual check is only reached
/// for non-group pairs.)
pub async fn require_e2ee_fetch_eligible(
    db: &Database,
    caller: &User,
    target: &User,
) -> Result<()> {
    if caller.id == target.id {
        return Ok(());
    }

    if is_blocked_pair(caller, &target.id) {
        return Err(create_error!(NotFound));
    }

    if users_share_group(db, &caller.id, &target.id).await?
        || friend_or_mutual_eligible(db, caller, target).await
    {
        return Ok(());
    }

    Err(create_error!(NotFound))
}

/// E2EE envelope-DELIVERY eligibility (slice 5, design §2.6): the caller may
/// deliver an envelope to `target` iff they share a Group channel OR they
/// are friend/mutual-eligible. Unlike FETCH, a blocked pair inside a shared
/// group may still exchange envelopes — E2EE delivery must be neither weaker
/// nor stronger than the plaintext group behaviour (blocked members already
/// see each other's plaintext group messages). The shared-group check comes
/// first (portable across drivers).
pub async fn require_e2ee_deliver_eligible(
    db: &Database,
    caller: &User,
    target: &User,
) -> Result<()> {
    if caller.id == target.id {
        return Ok(());
    }

    if users_share_group(db, &caller.id, &target.id).await?
        || friend_or_mutual_eligible(db, caller, target).await
    {
        return Ok(());
    }

    Err(create_error!(NotFound))
}

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        publish_keys::publish_keys,
        revoke_device::revoke_device,
        fetch_keys::fetch_keys,
        fetch_devices::fetch_devices,
        send_messages::send_messages,
        put_backup::put_backup,
        get_backup::get_backup,
        get_backup_status::get_backup_status,
        delete_backup::delete_backup,
    ]
}
