use std::collections::HashMap;

use revolt_database::{util::reference::Reference, Database, E2EEIdentity, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # List E2EE Devices
///
/// List a user's registered E2EE devices without consuming any key material.
/// Used for device-list reconciliation on connect and for the own-device
/// management UI.
///
/// For your own devices the listing includes registration/last-seen times,
/// the remaining one-time key count (drives replenishment) and the session
/// the device is bound to with that session's name (protected channels
/// design §7.2, S2-D38); for peers only the device id, protocol version and
/// identity key are returned.
///
/// Peer listings require a device-bound session (design §8) — only an
/// E2EE-capable device has any use for them. Listing your OWN devices is
/// allowed from any session: the web device-management UI needs it (e.g. to
/// revoke a lost desktop, which stays MFA-gated).
#[openapi(tag = "E2EE")]
#[get("/devices/<target>")]
pub async fn fetch_devices(
    db: &State<Database>,
    user: User,
    session: Session,
    target: Reference<'_>,
) -> Result<Json<Vec<v0::E2EEDeviceInfo>>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let target = target.as_user(db).await?;
    let own = target.id == user.id;

    if !own {
        E2EEIdentity::require_device_bound_session(db, &user.id, &session.id).await?;

        // Friend-eligible OR shared-group co-member; blocked pairs refused
        // on the FETCH path even inside a shared group (design §2.6)
        super::require_e2ee_fetch_eligible(db, &user, &target).await?;
    }

    // Names of the caller's own sessions only: a device bound to a session
    // that is gone (or is not the caller's) lists no name
    let session_names: HashMap<String, String> = if own {
        db.fetch_sessions(&user.id)
            .await?
            .into_iter()
            .map(|session| (session.id, session.name))
            .collect()
    } else {
        HashMap::new()
    };

    let mut devices = vec![];
    for identity in db.fetch_e2ee_identities(&target.id).await? {
        let one_time_key_count = if own {
            Some(
                db.count_e2ee_one_time_keys(&target.id, &identity.device_id)
                    .await?,
            )
        } else {
            None
        };

        let (session_id, session_name) = if own {
            (
                Some(identity.last_session_id.clone()),
                session_names.get(&identity.last_session_id).cloned(),
            )
        } else {
            (None, None)
        };

        devices.push(v0::E2EEDeviceInfo {
            created_at: own.then(|| identity.created_at.to_string()),
            last_seen_at: own.then(|| identity.last_seen_at.to_string()),
            device_id: identity.device_id,
            protocol_version: identity.protocol_version,
            ed25519_key: identity.ed25519_key,
            curve25519_key: identity.curve25519_key,
            signature: identity.signature,
            one_time_key_count,
            session_id,
            session_name,
        });
    }

    Ok(Json(devices))
}

/// The session fields of the own-device listing (design 7.2, S2-D38)
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use revolt_database::{RelationshipStatus, Session, User};
    use rocket::http::Status;
    use serde_json::Value;

    use crate::util::test::{TestHarness, MEMBER_DEVICE_SEED, OWNER_DEVICE_SEED};

    /// A session id no session has
    const UNKNOWN_SESSION: &str = "01NOSUCHSESSION00000000000";

    /// The raw JSON entries of `GET /e2ee/devices/{target}` as `session`,
    /// by device id
    async fn listing(
        harness: &TestHarness,
        session: &Session,
        target: &User,
    ) -> HashMap<String, Value> {
        let response = TestHarness::with_session(
            session.clone(),
            harness.client.get(format!("/e2ee/devices/{}", target.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let body: Value =
            serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
        body.as_array()
            .expect("a listing")
            .iter()
            .map(|entry| {
                (
                    entry["device_id"].as_str().expect("device_id").to_string(),
                    entry.clone(),
                )
            })
            .collect()
    }

    /// Each own device lists its bound session id; the name only when that
    /// session exists and is the caller's
    #[test]
    fn own_listing_names_each_devices_session() {
        crate::util::test::rt().block_on(own_listing_names_each_devices_session_case())
    }

    async fn own_listing_names_each_devices_session_case() {
        let harness = TestHarness::new().await;
        let (account, _, user) = harness.new_user().await;
        let (other_account, _, _) = harness.new_user().await;
        let desktop = account
            .create_session(&harness.db, "Desktop".to_string())
            .await
            .expect("session");
        let phone = account
            .create_session(&harness.db, "Phone".to_string())
            .await
            .expect("session");
        let theirs = other_account
            .create_session(&harness.db, "Their laptop".to_string())
            .await
            .expect("session");

        let bound = harness
            .new_e2ee_device(&user, &desktop.id, OWNER_DEVICE_SEED)
            .await;
        // The session row goes without the revocation `Session::delete` runs
        let deleted = harness
            .new_e2ee_device(&user, &phone.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .db
            .delete_session(&phone.id)
            .await
            .expect("delete session");
        let unknown = harness.new_e2ee_device(&user, UNKNOWN_SESSION, 0x30).await;
        let foreign = harness.new_e2ee_device(&user, &theirs.id, 0x40).await;

        let entries = listing(&harness, &desktop, &user).await;
        assert_eq!(entries.len(), 4, "{:?}", entries);

        let entry = &entries[&bound.device_id];
        assert_eq!(entry["session_id"], desktop.id.as_str(), "{}", entry);
        assert_eq!(entry["session_name"], "Desktop", "{}", entry);

        for (device, session_id, case) in [
            (&deleted, phone.id.as_str(), "a deleted session"),
            (&unknown, UNKNOWN_SESSION, "an unknown session"),
            (&foreign, theirs.id.as_str(), "another user's session"),
        ] {
            let entry = &entries[&device.device_id];
            assert_eq!(entry["session_id"], session_id, "{}: {}", case, entry);
            assert!(
                entry.get("session_name").is_none(),
                "{}: the name must be absent: {}",
                case,
                entry
            );
        }
    }

    /// Another user's listing never carries either session field
    #[test]
    fn peer_listing_has_no_session_fields() {
        crate::util::test::rt().block_on(peer_listing_has_no_session_fields_case())
    }

    async fn peer_listing_has_no_session_fields_case() {
        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (account_b, _, user_b) = harness.new_user().await;
        user_a
            .clone()
            .apply_relationship(
                &harness.db,
                &mut user_b.clone(),
                RelationshipStatus::Friend,
                RelationshipStatus::Friend,
                None,
            )
            .await
            .expect("friendship");
        // A peer listing needs a device-bound session
        harness
            .new_e2ee_device(&user_a, &session_a.id, OWNER_DEVICE_SEED)
            .await;
        let laptop = account_b
            .create_session(&harness.db, "Laptop".to_string())
            .await
            .expect("session");
        let device_b = harness
            .new_e2ee_device(&user_b, &laptop.id, MEMBER_DEVICE_SEED)
            .await;

        // B's own listing carries both fields, so the peer case has
        // something to leak
        let own = listing(&harness, &laptop, &user_b).await;
        assert_eq!(own[&device_b.device_id]["session_id"], laptop.id.as_str());
        assert_eq!(own[&device_b.device_id]["session_name"], "Laptop");

        let peer = listing(&harness, &session_a, &user_b).await;
        assert_eq!(peer.len(), 1, "{:?}", peer);
        let entry = &peer[&device_b.device_id];
        for field in ["session_id", "session_name"] {
            assert!(
                entry.get(field).is_none(),
                "{} in a peer listing: {}",
                field,
                entry
            );
        }
    }
}
