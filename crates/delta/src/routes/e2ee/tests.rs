use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use revolt_database::{
    E2EEIdentity, MFATicket, User, E2EE_PROTOCOL_VERSION, E2EE_SIGN_CONTEXT_FALLBACK,
    E2EE_SIGN_CONTEXT_ONE_TIME,
};
use revolt_models::v0;
use rocket::http::{ContentType, Header, Status};

use crate::util::test::TestHarness;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

pub struct TestDevice {
    pub signing_key: SigningKey,
    pub device_id: String,
    pub curve25519_key: String,
}

impl TestDevice {
    pub fn new() -> TestDevice {
        TestDevice {
            signing_key: SigningKey::from_bytes(&random_bytes::<32>()),
            device_id: random_bytes::<16>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            // Identity keys are immutable per device: cache so republishes
            // carry the same identity
            curve25519_key: STANDARD_NO_PAD.encode(random_bytes::<32>()),
        }
    }

    fn signed_key(&self, context: &str, key_id: &str) -> v0::E2EESignedKey {
        let key = STANDARD_NO_PAD.encode(random_bytes::<32>());
        let payload = format!(
            "{context}\nprotocol_version:{E2EE_PROTOCOL_VERSION}\ndevice_id:{}\nkey_id:{key_id}\nkey:{key}",
            self.device_id
        );

        v0::E2EESignedKey {
            key_id: key_id.to_string(),
            key,
            signature: STANDARD_NO_PAD.encode(self.signing_key.sign(payload.as_bytes()).to_bytes()),
        }
    }

    pub fn bundle(&self, one_time_keys: usize) -> v0::DataPublishE2EEKeys {
        let ed25519_key = STANDARD_NO_PAD.encode(self.signing_key.verifying_key().as_bytes());
        let curve25519_key = self.curve25519_key.clone();

        let payload = E2EEIdentity::signed_payload(
            E2EE_PROTOCOL_VERSION,
            &self.device_id,
            &ed25519_key,
            &curve25519_key,
        );

        v0::DataPublishE2EEKeys {
            device_id: self.device_id.clone(),
            protocol_version: E2EE_PROTOCOL_VERSION,
            ed25519_key,
            curve25519_key,
            signature: STANDARD_NO_PAD
                .encode(self.signing_key.sign(payload.as_bytes()).to_bytes()),
            fallback_key: self.signed_key(E2EE_SIGN_CONTEXT_FALLBACK, "fallback0"),
            one_time_keys: (0..one_time_keys)
                .map(|i| self.signed_key(E2EE_SIGN_CONTEXT_ONE_TIME, &format!("otk{i}")))
                .collect(),
            replace_one_time_keys: false,
        }
    }
}

pub(crate) async fn mfa_ticket(harness: &TestHarness, account_id: &str) -> String {
    let ticket = MFATicket::new(account_id.to_string(), true);
    ticket.save(&harness.db).await.unwrap();
    ticket.token
}

/// Publish a device for the user and return it
pub(crate) async fn publish_device(
    harness: &TestHarness,
    account_id: &str,
    session_token: &str,
    one_time_keys: usize,
) -> TestDevice {
    let device = TestDevice::new();
    let ticket = mfa_ticket(harness, account_id).await;

    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session_token.to_string()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .body(serde_json::to_string(&device.bundle(one_time_keys)).unwrap())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    device
}

/// Make the pair DM-eligible by befriending them (the REFERENCE driver has
/// no mutual-server query, so friendship is the portable eligibility path)
async fn make_dm_eligible(harness: &TestHarness, user_a: &User, user_b: &User) {
    user_a
        .clone()
        .apply_relationship(
            &harness.db,
            &mut user_b.clone(),
            revolt_database::RelationshipStatus::Friend,
            revolt_database::RelationshipStatus::Friend,
        )
        .await
        .expect("friendship");
}

#[rocket::async_test]
async fn publish_requires_mfa_for_new_device_only() {
    let harness = TestHarness::new().await;
    let (account, session, _) = harness.new_user().await;

    let device = TestDevice::new();

    // First publication without a validated MFA ticket is rejected
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&device.bundle(2)).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // With MFA it binds the device
    let ticket = mfa_ticket(&harness, &account.id).await;
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .body(serde_json::to_string(&device.bundle(2)).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponsePublishE2EEKeys = response.into_json().await.unwrap();
    assert_eq!(body.one_time_key_count, 2);

    // Replenishing the SAME device needs no MFA
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&device.bundle(3)).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // Identity keys are immutable: same device id with a fresh identity is
    // a substitution attempt and is rejected even with MFA
    let mut impostor = TestDevice::new();
    impostor.device_id = device.device_id.clone();
    let ticket = mfa_ticket(&harness, &account.id).await;
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .body(serde_json::to_string(&impostor.bundle(1)).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
}

#[rocket::async_test]
async fn publish_rejects_bad_signatures() {
    let harness = TestHarness::new().await;
    let (account, session, _) = harness.new_user().await;

    let device = TestDevice::new();

    // Tampered identity signature (signature-stripping / substitution)
    let mut bundle = device.bundle(1);
    bundle.signature = STANDARD_NO_PAD.encode(random_bytes::<64>());
    let ticket = mfa_ticket(&harness, &account.id).await;
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .body(serde_json::to_string(&bundle).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);

    // One-time key signed by the wrong key
    let mut bundle = device.bundle(0);
    let mallory = TestDevice::new();
    bundle.one_time_keys = vec![{
        let mut key = mallory.signed_key(E2EE_SIGN_CONTEXT_ONE_TIME, "otk0");
        key.key_id = "otk0".to_string();
        key
    }];
    let ticket = mfa_ticket(&harness, &account.id).await;
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .body(serde_json::to_string(&bundle).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
}

#[rocket::async_test]
async fn fetch_consumes_one_time_keys_and_never_returns_empty() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    make_dm_eligible(&harness, &user_a, &user_b).await;

    let device = publish_device(&harness, &account_a.id, &session_a.token, 1).await;
    // Fetching key material requires a device-bound session (design §8)
    publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    // First fetch consumes the only one-time key
    let response = TestHarness::with_session(
        session_b.clone(),
        harness.client.get(format!("/e2ee/keys/{}", user_a.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let bundle: v0::E2EEKeyBundle = response.into_json().await.unwrap();
    assert_eq!(bundle.devices.len(), 1);
    assert_eq!(bundle.devices[0].device_id, device.device_id);
    assert!(bundle.devices[0].one_time_key.is_some());
    assert_eq!(bundle.devices[0].one_time_keys_remaining, 0);

    // Exhausted: fallback key still served — a registered device always
    // yields a usable bundle
    let response = TestHarness::with_session(
        session_b,
        harness.client.get(format!("/e2ee/keys/{}", user_a.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let bundle: v0::E2EEKeyBundle = response.into_json().await.unwrap();
    assert_eq!(bundle.devices.len(), 1);
    assert!(bundle.devices[0].one_time_key.is_none());
    assert_eq!(bundle.devices[0].fallback_key.key_id, "fallback0");
}

#[rocket::async_test]
async fn blocked_user_cannot_fetch_keys_or_devices() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    make_dm_eligible(&harness, &user_a, &user_b).await;
    publish_device(&harness, &account_a.id, &session_a.token, 1).await;
    // B gets a bound device so the BLOCK is the gate under test, not the
    // device-bound-session requirement
    publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    // A blocks B
    let response = TestHarness::with_session(
        session_a,
        harness.client.put(format!("/users/{}/block", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // B can no longer fetch A's bundle (or probe A's device inventory)
    let response = TestHarness::with_session(
        session_b.clone(),
        harness.client.get(format!("/e2ee/keys/{}", user_a.id)),
    )
    .await;
    assert_ne!(response.status(), Status::Ok);

    let response = TestHarness::with_session(
        session_b,
        harness.client.get(format!("/e2ee/devices/{}", user_a.id)),
    )
    .await;
    assert_ne!(response.status(), Status::Ok);
}

/// Create a Group channel owned by `owner` also containing `member` (no
/// friendship — exercises the shared-group eligibility path).
async fn make_group(harness: &TestHarness, owner: &User, member: &User) -> String {
    let channel = revolt_database::Channel::create_group(
        &harness.db,
        v0::DataCreateGroup {
            name: "g".to_string(),
            description: None,
            icon: None,
            users: std::iter::once(member.id.clone()).collect(),
            nsfw: None,
        },
        owner.id.clone(),
    )
    .await
    .expect("create group");
    channel.id().to_string()
}

#[rocket::async_test]
async fn group_comembers_can_fetch_and_send_without_friendship() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    // NOT friends — only a shared group
    make_group(&harness, &user_a, &user_b).await;

    let device_a = publish_device(&harness, &account_a.id, &session_a.token, 1).await;
    let device_b = publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    // A can fetch B's bundle (shared-group co-member)
    let response = TestHarness::with_session(
        session_a.clone(),
        harness.client.get(format!("/e2ee/keys/{}", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // A can fetch B's device listing
    let response = TestHarness::with_session(
        session_a.clone(),
        harness.client.get(format!("/e2ee/devices/{}", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // A can deliver an envelope to B
    let body = v0::DataSendE2EEMessages {
        device_id: device_a.device_id.clone(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        envelopes: vec![v0::DataE2EEEnvelope {
            recipient_user_id: user_b.id.clone(),
            recipient_device_id: device_b.device_id.clone(),
            sequence: 1,
            ciphertext: STANDARD_NO_PAD.encode(b"group"),
        }],
    };
    let response = TestHarness::with_session(
        session_a,
        harness
            .client
            .post("/e2ee/messages")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&body).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let result: v0::ResponseSendE2EEMessages = response.into_json().await.unwrap();
    assert!(matches!(
        result.receipts[0].status,
        v0::E2EEDeliveryStatus::Queued { .. }
    ));
}

#[rocket::async_test]
async fn non_member_stranger_is_refused() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    // No friendship, no shared group. (The REFERENCE driver's
    // has_mutual_connection is unimplemented, so the friend/mutual fallback
    // 500s here where MongoDB cleanly returns NotFound — both are refusals,
    // asserted as "not Ok". The friend/group positive paths are covered by
    // the other tests, which never reach the mutual fallback.)
    publish_device(&harness, &account_a.id, &session_a.token, 1).await;
    publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    let response = TestHarness::with_session(
        session_a,
        harness.client.get(format!("/e2ee/keys/{}", user_b.id)),
    )
    .await;
    assert_ne!(response.status(), Status::Ok);
    let _ = user_a;
}

#[rocket::async_test]
async fn blocked_pair_in_a_group_can_deliver_but_not_fetch() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    make_group(&harness, &user_a, &user_b).await;
    let device_a = publish_device(&harness, &account_a.id, &session_a.token, 1).await;
    let device_b = publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    // A blocks B
    let response = TestHarness::with_session(
        session_a.clone(),
        harness.client.put(format!("/users/{}/block", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // FETCH between the blocked pair is refused even though they share a
    // group (design §2.6) — the blocked member surfaces as Blocked
    let response = TestHarness::with_session(
        session_b.clone(),
        harness.client.get(format!("/e2ee/keys/{}", user_a.id)),
    )
    .await;
    assert_ne!(response.status(), Status::Ok);

    // DELIVERY still works (E2EE must not be weaker OR stronger than
    // plaintext group behaviour — blocked co-members see plaintext today)
    let body = v0::DataSendE2EEMessages {
        device_id: device_b.device_id.clone(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        envelopes: vec![v0::DataE2EEEnvelope {
            recipient_user_id: user_a.id.clone(),
            recipient_device_id: device_a.device_id.clone(),
            sequence: 1,
            ciphertext: STANDARD_NO_PAD.encode(b"still-delivers"),
        }],
    };
    let response = TestHarness::with_session(
        session_b,
        harness
            .client
            .post("/e2ee/messages")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&body).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let result: v0::ResponseSendE2EEMessages = response.into_json().await.unwrap();
    assert!(matches!(
        result.receipts[0].status,
        v0::E2EEDeliveryStatus::Queued { .. }
    ));
}

#[rocket::async_test]
async fn send_stamps_sender_and_reports_per_device_status() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    make_dm_eligible(&harness, &user_a, &user_b).await;

    let device_a = publish_device(&harness, &account_a.id, &session_a.token, 1).await;
    let device_b = publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    let body = v0::DataSendE2EEMessages {
        device_id: device_a.device_id.clone(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        envelopes: vec![
            v0::DataE2EEEnvelope {
                recipient_user_id: user_b.id.clone(),
                recipient_device_id: device_b.device_id.clone(),
                sequence: 1,
                ciphertext: STANDARD_NO_PAD.encode(b"hello"),
            },
            // Unknown device: sender must be told to tear down the session
            v0::DataE2EEEnvelope {
                recipient_user_id: user_b.id.clone(),
                recipient_device_id: "00000000000000000000000000000000".to_string(),
                sequence: 1,
                ciphertext: STANDARD_NO_PAD.encode(b"hello"),
            },
        ],
    };

    let response = TestHarness::with_session(
        session_a.clone(),
        harness
            .client
            .post("/e2ee/messages")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&body).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let result: v0::ResponseSendE2EEMessages = response.into_json().await.unwrap();
    assert_eq!(result.receipts.len(), 2);
    assert!(matches!(
        result.receipts[0].status,
        v0::E2EEDeliveryStatus::Queued { .. }
    ));
    assert!(matches!(
        result.receipts[1].status,
        v0::E2EEDeliveryStatus::UnknownDevice
    ));

    // The queued envelope's sender was stamped from the session, and the
    // ciphertext is stored verbatim (the server never interprets it)
    let queued = harness
        .db
        .fetch_e2ee_envelopes(&user_b.id, &device_b.device_id, 10)
        .await
        .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].sender_user_id, user_a.id);
    assert_eq!(queued[0].sender_device_id, device_a.device_id);
    assert_eq!(queued[0].ciphertext, STANDARD_NO_PAD.encode(b"hello"));

    // Sending from a device that is not registered to the sender fails
    let mut forged = v0::DataSendE2EEMessages {
        device_id: device_b.device_id.clone(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        envelopes: vec![v0::DataE2EEEnvelope {
            recipient_user_id: user_b.id.clone(),
            recipient_device_id: device_b.device_id.clone(),
            sequence: 2,
            ciphertext: STANDARD_NO_PAD.encode(b"forged"),
        }],
    };
    forged.device_id = device_b.device_id.clone();

    let response = TestHarness::with_session(
        session_a,
        harness
            .client
            .post("/e2ee/messages")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&forged).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::BadRequest);
}

#[rocket::async_test]
async fn queue_depth_cap_reports_queue_full() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    make_dm_eligible(&harness, &user_a, &user_b).await;

    let device_a = publish_device(&harness, &account_a.id, &session_a.token, 1).await;
    let device_b = publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    // Fill the recipient device's queue to the cap directly
    let envelopes: Vec<_> = (0..super::MAX_QUEUE_DEPTH)
        .map(|i| revolt_database::E2EEEnvelope {
            id: ulid::Ulid::new().to_string(),
            recipient_user_id: user_b.id.clone(),
            recipient_device_id: device_b.device_id.clone(),
            sender_user_id: user_a.id.clone(),
            sender_device_id: device_a.device_id.clone(),
            protocol_version: E2EE_PROTOCOL_VERSION,
            sequence: i,
            ciphertext: "AAAA".to_string(),
            timestamp: iso8601_timestamp::Timestamp::now_utc(),
            content_type: revolt_database::E2EEContentType::Olm,
            group_id: None,
            epoch: None,
        })
        .collect();
    harness.db.insert_e2ee_envelopes(&envelopes).await.unwrap();

    let body = v0::DataSendE2EEMessages {
        device_id: device_a.device_id.clone(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        envelopes: vec![v0::DataE2EEEnvelope {
            recipient_user_id: user_b.id.clone(),
            recipient_device_id: device_b.device_id.clone(),
            sequence: 9999,
            ciphertext: STANDARD_NO_PAD.encode(b"overflow"),
        }],
    };

    let response = TestHarness::with_session(
        session_a.clone(),
        harness
            .client
            .post("/e2ee/messages")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&body).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let result: v0::ResponseSendE2EEMessages = response.into_json().await.unwrap();
    assert!(matches!(
        result.receipts[0].status,
        v0::E2EEDeliveryStatus::QueueFull
    ));

    // A dead device's full queue must not affect the user's live devices:
    // the same message to a fresh device of B still queues
    let device_b2 = publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    let body = v0::DataSendE2EEMessages {
        device_id: device_a.device_id,
        protocol_version: E2EE_PROTOCOL_VERSION,
        envelopes: vec![v0::DataE2EEEnvelope {
            recipient_user_id: user_b.id.clone(),
            recipient_device_id: device_b2.device_id,
            sequence: 1,
            ciphertext: STANDARD_NO_PAD.encode(b"alive"),
        }],
    };

    let response = TestHarness::with_session(
        session_a,
        harness
            .client
            .post("/e2ee/messages")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&body).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let result: v0::ResponseSendE2EEMessages = response.into_json().await.unwrap();
    assert!(matches!(
        result.receipts[0].status,
        v0::E2EEDeliveryStatus::Queued { .. }
    ));
}

#[rocket::async_test]
async fn revoke_device_is_mfa_gated_and_cascades() {
    let harness = TestHarness::new().await;
    let (account, session, user) = harness.new_user().await;

    let device = publish_device(&harness, &account.id, &session.token, 2).await;

    // Without MFA: rejected
    let response = TestHarness::with_session(
        session.clone(),
        harness
            .client
            .delete(format!("/e2ee/keys/{}", device.device_id)),
    )
    .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // With MFA: identity, prekeys and queue are gone
    let ticket = mfa_ticket(&harness, &account.id).await;
    let response = harness
        .client
        .delete(format!("/e2ee/keys/{}", device.device_id))
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);

    assert!(harness
        .db
        .fetch_e2ee_identity(&user.id, &device.device_id)
        .await
        .is_err());
    assert_eq!(
        harness
            .db
            .count_e2ee_one_time_keys(&user.id, &device.device_id)
            .await
            .unwrap(),
        0
    );
}

#[rocket::async_test]
async fn queue_depth_cap_holds_within_a_single_request() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    make_dm_eligible(&harness, &user_a, &user_b).await;

    let device_a = publish_device(&harness, &account_a.id, &session_a.token, 1).await;
    let device_b = publish_device(&harness, &account_b.id, &session_b.token, 1).await;

    // Fill the recipient device's queue to one below the cap
    let envelopes: Vec<_> = (0..super::MAX_QUEUE_DEPTH - 1)
        .map(|i| revolt_database::E2EEEnvelope {
            id: ulid::Ulid::new().to_string(),
            recipient_user_id: user_b.id.clone(),
            recipient_device_id: device_b.device_id.clone(),
            sender_user_id: user_a.id.clone(),
            sender_device_id: device_a.device_id.clone(),
            protocol_version: E2EE_PROTOCOL_VERSION,
            sequence: i,
            ciphertext: "AAAA".to_string(),
            timestamp: iso8601_timestamp::Timestamp::now_utc(),
            content_type: revolt_database::E2EEContentType::Olm,
            group_id: None,
            epoch: None,
        })
        .collect();
    harness.db.insert_e2ee_envelopes(&envelopes).await.unwrap();

    // A burst of envelopes to the same device in ONE request must not blow
    // through the cap on the stale pre-request count: exactly one fits
    let body = v0::DataSendE2EEMessages {
        device_id: device_a.device_id.clone(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        envelopes: (0..4u64)
            .map(|i| v0::DataE2EEEnvelope {
                recipient_user_id: user_b.id.clone(),
                recipient_device_id: device_b.device_id.clone(),
                sequence: 1000 + i,
                ciphertext: STANDARD_NO_PAD.encode(b"burst"),
            })
            .collect(),
    };

    let response = TestHarness::with_session(
        session_a,
        harness
            .client
            .post("/e2ee/messages")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&body).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let result: v0::ResponseSendE2EEMessages = response.into_json().await.unwrap();

    let queued = result
        .receipts
        .iter()
        .filter(|receipt| matches!(receipt.status, v0::E2EEDeliveryStatus::Queued { .. }))
        .count();
    let full = result
        .receipts
        .iter()
        .filter(|receipt| matches!(receipt.status, v0::E2EEDeliveryStatus::QueueFull))
        .count();
    assert_eq!(queued, 1);
    assert_eq!(full, 3);

    assert_eq!(
        harness
            .db
            .count_e2ee_envelopes(&user_b.id, &device_b.device_id)
            .await
            .unwrap(),
        super::MAX_QUEUE_DEPTH
    );
}

#[rocket::async_test]
async fn one_time_key_cap_counts_upserts_correctly() {
    let harness = TestHarness::new().await;
    let (account, session, _user) = harness.new_user().await;

    let device = publish_device(
        &harness,
        &account.id,
        &session.token,
        super::MAX_ONE_TIME_KEYS,
    )
    .await;

    // Replenishing with the SAME key ids upserts in place: the cap must not
    // treat the batch as additive and spuriously reject it
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&device.bundle(super::MAX_ONE_TIME_KEYS)).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponsePublishE2EEKeys = response.into_json().await.unwrap();
    assert_eq!(body.one_time_key_count, super::MAX_ONE_TIME_KEYS as u64);

    // A genuinely new key id past the cap is still rejected
    let mut bundle = device.bundle(0);
    bundle.one_time_keys = vec![device.signed_key(E2EE_SIGN_CONTEXT_ONE_TIME, "fresh0")];
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&bundle).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);

    // Duplicate key ids within one request are rejected outright
    let mut bundle = device.bundle(0);
    bundle.one_time_keys = vec![
        device.signed_key(E2EE_SIGN_CONTEXT_ONE_TIME, "dup"),
        device.signed_key(E2EE_SIGN_CONTEXT_ONE_TIME, "dup"),
    ];
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&bundle).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
}

/// Design §8 / int-H3: a session that never proved possession of a device
/// identity key (a web login, or any stolen token) is refused on E2EE
/// routes that consume key material or act as a device. Own-device listing
/// and MFA-gated revocation stay reachable — that's the lost-device
/// recovery path.
#[rocket::async_test]
async fn unbound_session_is_refused_on_e2ee_routes() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    make_dm_eligible(&harness, &user_a, &user_b).await;

    let device_a = publish_device(&harness, &account_a.id, &session_a.token, 2).await;
    let device_b = publish_device(&harness, &account_b.id, &session_b.token, 2).await;

    // A second session for account A — the "web login". It never publishes
    // or proves a device claim, so it is not device-bound.
    let web = account_a
        .create_session(&harness.db, "web".to_string())
        .await
        .unwrap();

    // Bundle fetch: refused (would consume B's one-time keys)
    let response = TestHarness::with_session(
        web.clone(),
        harness.client.get(format!("/e2ee/keys/{}", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // Peer device listing: refused
    let response = TestHarness::with_session(
        web.clone(),
        harness.client.get(format!("/e2ee/devices/{}", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // OWN device listing: allowed (web device management)
    let response = TestHarness::with_session(
        web.clone(),
        harness.client.get(format!("/e2ee/devices/{}", user_a.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // Sending as the account's device: refused (session not bound to it)
    let body = v0::DataSendE2EEMessages {
        device_id: device_a.device_id.clone(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        envelopes: vec![v0::DataE2EEEnvelope {
            recipient_user_id: user_b.id.clone(),
            recipient_device_id: device_b.device_id.clone(),
            sequence: 1,
            ciphertext: STANDARD_NO_PAD.encode(b"stolen token"),
        }],
    };
    let response = TestHarness::with_session(
        web.clone(),
        harness
            .client
            .post("/e2ee/messages")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&body).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // Republish (replenish / fallback rotation) for the device: refused —
    // a token thief cannot re-upload stale public keys
    let response = TestHarness::with_session(
        web.clone(),
        harness
            .client
            .put("/e2ee/keys")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&device_a.bundle(2)).unwrap()),
    )
    .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // The bound session still works for all of the above
    let response = TestHarness::with_session(
        session_a.clone(),
        harness.client.get(format!("/e2ee/keys/{}", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // MFA-gated revocation from the unbound session: allowed (recovery
    // path for a lost or stolen device)
    let ticket = mfa_ticket(&harness, &account_a.id).await;
    let response = harness
        .client
        .delete(format!("/e2ee/keys/{}", device_a.device_id))
        .header(Header::new("x-session-token", web.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);
}

/// A device claim proven over the events connection (bonfire) rebinds the
/// device to the proving session: the new session gains E2EE-route access
/// and the old session loses it. (The claim verification itself is
/// signature-tested in the database crate; here we exercise the rebind's
/// effect on the route gates.)
#[rocket::async_test]
async fn device_claim_rebind_moves_route_access_between_sessions() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    make_dm_eligible(&harness, &user_a, &user_b).await;

    let device_a = publish_device(&harness, &account_a.id, &session_a.token, 2).await;
    publish_device(&harness, &account_b.id, &session_b.token, 2).await;

    // Fresh login on the same physical device: new session, then the client
    // proves the device claim on connect (bonfire calls this exact update)
    let relogin = account_a
        .create_session(&harness.db, "relogin".to_string())
        .await
        .unwrap();

    harness
        .db
        .update_e2ee_identity_session(
            &user_a.id,
            &device_a.device_id,
            &relogin.id,
            iso8601_timestamp::Timestamp::now_utc(),
        )
        .await
        .unwrap();

    // The new session is now the bound one...
    let response = TestHarness::with_session(
        relogin,
        harness.client.get(format!("/e2ee/keys/{}", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // ...and the original session lost its binding
    let response = TestHarness::with_session(
        session_a,
        harness.client.get(format!("/e2ee/keys/{}", user_b.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Unauthorized);
}

// ========================================================================
// Key backup & recovery (slice 5.5)
// ========================================================================

/// A minimal valid backup header bound to (user, device, generation) with
/// in-range Argon2id params. The server parses it only to range-check the
/// KDF and cross-check the generation binding; salt/nonce are opaque to it.
fn backup_header(user_id: &str, device_id: &str, generation: i64) -> String {
    format!(
        "{{\"v\":1,\"kdf\":{{\"alg\":\"argon2id\",\"m_kib\":262144,\"t\":3,\"p\":4}},\
         \"salt\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\
         \"user_id\":\"{user_id}\",\"device_id\":\"{device_id}\",\
         \"generation\":{generation},\"created_at\":0}}"
    )
}

async fn put_backup(
    harness: &TestHarness,
    session_token: &str,
    device_id: &str,
    header: String,
    generation: i64,
) -> Status {
    let body = v0::DataPutE2EEBackup {
        device_id: device_id.to_string(),
        header,
        ciphertext: "AAAAAAAAAAAAAAAA".to_string(),
        generation,
    };
    harness
        .client
        .put("/e2ee/backup")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session_token.to_string()))
        .body(serde_json::to_string(&body).unwrap())
        .dispatch()
        .await
        .status()
}

#[rocket::async_test]
async fn backup_roundtrip_and_generation_monotonic() {
    let harness = TestHarness::new().await;
    let (account, session, user) = harness.new_user().await;
    let device = publish_device(&harness, &account.id, &session.token, 2).await;

    // First upload (generation 1) from the device-bound session
    assert_eq!(
        put_backup(
            &harness,
            &session.token,
            &device.device_id,
            backup_header(&user.id, &device.device_id, 1),
            1,
        )
        .await,
        Status::Ok
    );

    // A stale-or-equal generation is a no-op that echoes the stored value
    assert_eq!(
        put_backup(
            &harness,
            &session.token,
            &device.device_id,
            backup_header(&user.id, &device.device_id, 1),
            1,
        )
        .await,
        Status::Ok
    );
    assert_eq!(
        harness
            .db
            .fetch_e2ee_backup(&user.id, &device.device_id)
            .await
            .unwrap()
            .unwrap()
            .generation,
        1
    );

    // A strictly greater generation advances the stored blob
    assert_eq!(
        put_backup(
            &harness,
            &session.token,
            &device.device_id,
            backup_header(&user.id, &device.device_id, 2),
            2,
        )
        .await,
        Status::Ok
    );

    // GET restore (MFA-gated) returns the blob
    let ticket = mfa_ticket(&harness, &account.id).await;
    let response = harness
        .client
        .get("/e2ee/backup")
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponseFetchE2EEBackups = response.into_json().await.unwrap();
    assert_eq!(body.backups.len(), 1);
    assert_eq!(body.backups[0].generation, 2);
    assert_eq!(body.backups[0].device_id, device.device_id);
}

#[rocket::async_test]
async fn backup_get_requires_mfa_and_binds_to_user() {
    let harness = TestHarness::new().await;
    let (account, session, user) = harness.new_user().await;
    let device = publish_device(&harness, &account.id, &session.token, 1).await;
    put_backup(
        &harness,
        &session.token,
        &device.device_id,
        backup_header(&user.id, &device.device_id, 1),
        1,
    )
    .await;

    // No MFA ticket -> refused
    let response = harness
        .client
        .get("/e2ee/backup")
        .header(Header::new("x-session-token", session.token.clone()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // A ticket belonging to ANOTHER account is refused (M8)
    let (other_account, _, _) = harness.new_user().await;
    let foreign = mfa_ticket(&harness, &other_account.id).await;
    let response = harness
        .client
        .get("/e2ee/backup")
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", foreign))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn backup_put_rejects_generation_and_kdf_and_binding_tampering() {
    let harness = TestHarness::new().await;
    let (account, session, user) = harness.new_user().await;
    let device = publish_device(&harness, &account.id, &session.token, 1).await;

    // Body generation disagrees with the header's bound generation (M2)
    assert_eq!(
        put_backup(
            &harness,
            &session.token,
            &device.device_id,
            backup_header(&user.id, &device.device_id, 5),
            2,
        )
        .await,
        Status::BadRequest
    );

    // KDF memory cost out of range (M1 DoS guard)
    let huge = backup_header(&user.id, &device.device_id, 1)
        .replace("\"m_kib\":262144", "\"m_kib\":4294967295");
    assert_eq!(
        put_backup(&harness, &session.token, &device.device_id, huge, 1).await,
        Status::BadRequest
    );

    // A generation far beyond the previous value (here: from a floor of 0) is
    // refused, so a compromised webview cannot poison the stored generation to
    // a huge value to permanently wedge future PUTs (M2 defence-in-depth).
    assert_eq!(
        put_backup(
            &harness,
            &session.token,
            &device.device_id,
            backup_header(&user.id, &device.device_id, i64::MAX),
            i64::MAX,
        )
        .await,
        Status::BadRequest
    );

    // Header bound to a different user than the authenticated session
    let wrong_user = backup_header("01SOMEONEELSE0000000000000", &device.device_id, 1);
    assert_eq!(
        put_backup(&harness, &session.token, &device.device_id, wrong_user, 1).await,
        Status::BadRequest
    );
}

#[rocket::async_test]
async fn backup_put_requires_a_device_bound_session() {
    let harness = TestHarness::new().await;
    let (account, session, user) = harness.new_user().await;
    let device = publish_device(&harness, &account.id, &session.token, 1).await;

    // A second session of the SAME user that never proved the device is not
    // bound -> cannot write the device's backup
    let other = account
        .create_session(&harness.db, "web".to_string())
        .await
        .unwrap();
    assert_eq!(
        put_backup(
            &harness,
            &other.token,
            &device.device_id,
            backup_header(&user.id, &device.device_id, 1),
            1,
        )
        .await,
        Status::Unauthorized
    );
}

#[rocket::async_test]
async fn backup_survives_device_revocation_but_dies_with_account() {
    let harness = TestHarness::new().await;
    let (account, session, mut user) = harness.new_user().await;
    let device = publish_device(&harness, &account.id, &session.token, 1).await;
    put_backup(
        &harness,
        &session.token,
        &device.device_id,
        backup_header(&user.id, &device.device_id, 1),
        1,
    )
    .await;

    // Revoke the device (MFA-gated) — the backup must SURVIVE (a lost device
    // keeps its recovery path)
    let ticket = mfa_ticket(&harness, &account.id).await;
    let response = harness
        .client
        .delete(format!("/e2ee/keys/{}", device.device_id))
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);
    assert!(harness
        .db
        .fetch_e2ee_backup(&user.id, &device.device_id)
        .await
        .unwrap()
        .is_some());

    // Account deletion cascades the backup away
    user.delete(&harness.db).await.unwrap();
    assert!(harness
        .db
        .fetch_e2ee_backup(&user.id, &device.device_id)
        .await
        .unwrap()
        .is_none());
}

#[rocket::async_test]
async fn backup_delete_requires_mfa_and_scopes_to_user() {
    let harness = TestHarness::new().await;
    let (account, session, user) = harness.new_user().await;
    let device = publish_device(&harness, &account.id, &session.token, 1).await;
    put_backup(
        &harness,
        &session.token,
        &device.device_id,
        backup_header(&user.id, &device.device_id, 1),
        1,
    )
    .await;

    // No MFA -> refused
    let response = harness
        .client
        .delete(format!("/e2ee/backup/{}", device.device_id))
        .header(Header::new("x-session-token", session.token.clone()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(harness
        .db
        .fetch_e2ee_backup(&user.id, &device.device_id)
        .await
        .unwrap()
        .is_some());

    // With a valid own ticket -> deleted
    let ticket = mfa_ticket(&harness, &account.id).await;
    let response = harness
        .client
        .delete(format!("/e2ee/backup/{}", device.device_id))
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", ticket))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);
    assert!(harness
        .db
        .fetch_e2ee_backup(&user.id, &device.device_id)
        .await
        .unwrap()
        .is_none());
}

#[rocket::async_test]
async fn replace_one_time_keys_replaces_only_with_a_nonempty_batch() {
    let harness = TestHarness::new().await;
    let (account, session, _user) = harness.new_user().await;
    let device = publish_device(&harness, &account.id, &session.token, 3).await;
    assert_eq!(
        harness
            .db
            .count_e2ee_one_time_keys(&account.id, &device.device_id)
            .await
            .unwrap(),
        3
    );

    // replace_one_time_keys with an EMPTY batch must NOT strip keys (L3)
    let mut bundle = device.bundle(0);
    bundle.replace_one_time_keys = true;
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&bundle).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        harness
            .db
            .count_e2ee_one_time_keys(&account.id, &device.device_id)
            .await
            .unwrap(),
        3
    );

    // With a non-empty batch it replaces: the stored set becomes exactly the
    // new keys (restore's stale-OTK eviction, section 6.3)
    let mut bundle = device.bundle(2);
    bundle.replace_one_time_keys = true;
    let response = harness
        .client
        .put("/e2ee/keys")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&bundle).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        harness
            .db
            .count_e2ee_one_time_keys(&account.id, &device.device_id)
            .await
            .unwrap(),
        2
    );
}

#[rocket::async_test]
async fn second_publish_same_session_revokes_predecessor() {
    // Device-lifecycle fixes §2: a first publication from a session sweeps
    // any OTHER identity row bound to the SAME session — the wipe→re-enable
    // flow's stale predecessor is provably a dead store. A fresh session
    // publishing does NOT touch other sessions' devices.
    let harness = TestHarness::new().await;
    let (account, session, user) = harness.new_user().await;

    let first = publish_device(&harness, &account.id, &session.token, 2).await;
    let second = publish_device(&harness, &account.id, &session.token, 2).await;

    // Predecessor bound to the same session is gone; successor remains
    assert!(
        harness
            .db
            .fetch_e2ee_identity(&user.id, &first.device_id)
            .await
            .is_err(),
        "same-session predecessor must be revoked"
    );
    assert!(harness
        .db
        .fetch_e2ee_identity(&user.id, &second.device_id)
        .await
        .is_ok());

    // A DIFFERENT session's device is untouched by a sweep: publish from a
    // second session, then re-publish a third device on the first session —
    // only the first session's predecessor (second device) is swept.
    let session_b = account
        .create_session(&harness.db, String::new())
        .await
        .expect("second session");
    let other = publish_device(&harness, &account.id, &session_b.token, 2).await;
    let third = publish_device(&harness, &account.id, &session.token, 2).await;

    assert!(harness
        .db
        .fetch_e2ee_identity(&user.id, &other.device_id)
        .await
        .is_ok(),
    );
    assert!(harness
        .db
        .fetch_e2ee_identity(&user.id, &second.device_id)
        .await
        .is_err());
    assert!(harness
        .db
        .fetch_e2ee_identity(&user.id, &third.device_id)
        .await
        .is_ok());
}
