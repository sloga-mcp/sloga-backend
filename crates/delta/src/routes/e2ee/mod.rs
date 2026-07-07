use revolt_result::{create_error, Result};
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod fetch_devices;
mod fetch_keys;
mod publish_keys;
mod revoke_device;
mod send_messages;
#[cfg(test)]
mod tests;

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

/// All E2EE routes sit behind the operator feature flag
pub async fn require_e2ee_enabled() -> Result<()> {
    if !revolt_config::config().await.features.e2ee_enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "e2ee".to_string()
        }));
    }

    Ok(())
}

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        publish_keys::publish_keys,
        revoke_device::revoke_device,
        fetch_keys::fetch_keys,
        fetch_devices::fetch_devices,
        send_messages::send_messages,
    ]
}
