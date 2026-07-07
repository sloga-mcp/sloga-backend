use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iso8601_timestamp::Timestamp;
use rand::RngCore;
use revolt_result::ErrorType;
use ulid::Ulid;

use crate::{E2EEEnvelope, E2EEIdentity, E2EEOneTimeKey, E2EESignedKey, E2EE_PROTOCOL_VERSION};

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn random_device_id() -> String {
    random_bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Build a fully-signed test identity the way the native layer will
pub(crate) struct TestDevice {
    pub signing_key: SigningKey,
    pub identity: E2EEIdentity,
}

pub(crate) fn make_device(user_id: &str) -> TestDevice {
    let signing_key = SigningKey::from_bytes(&random_bytes::<32>());
    let device_id = random_device_id();

    let ed25519_key = STANDARD_NO_PAD.encode(signing_key.verifying_key().as_bytes());
    let curve25519_key = STANDARD_NO_PAD.encode(random_bytes::<32>());

    let payload = E2EEIdentity::signed_payload(
        E2EE_PROTOCOL_VERSION,
        &device_id,
        &ed25519_key,
        &curve25519_key,
    );
    let signature = STANDARD_NO_PAD.encode(signing_key.sign(payload.as_bytes()).to_bytes());

    let fallback_key = make_signed_key(
        &signing_key,
        super::model::E2EE_SIGN_CONTEXT_FALLBACK,
        &device_id,
        "fallback0",
    );

    TestDevice {
        identity: E2EEIdentity {
            id: E2EEIdentity::composite_id(user_id, &device_id),
            user_id: user_id.to_string(),
            device_id,
            protocol_version: E2EE_PROTOCOL_VERSION,
            ed25519_key,
            curve25519_key,
            signature,
            fallback_key,
            previous_fallback_key: None,
            created_at: Timestamp::now_utc(),
            last_seen_at: Timestamp::now_utc(),
            last_session_id: "session0".to_string(),
        },
        signing_key,
    }
}

pub(crate) fn make_signed_key(
    signing_key: &SigningKey,
    context: &str,
    device_id: &str,
    key_id: &str,
) -> E2EESignedKey {
    let key = STANDARD_NO_PAD.encode(random_bytes::<32>());
    let payload = format!(
        "{context}\nprotocol_version:{E2EE_PROTOCOL_VERSION}\ndevice_id:{device_id}\nkey_id:{key_id}\nkey:{key}"
    );

    E2EESignedKey {
        key_id: key_id.to_string(),
        key,
        signature: STANDARD_NO_PAD.encode(signing_key.sign(payload.as_bytes()).to_bytes()),
    }
}

pub(crate) fn make_one_time_key(device: &TestDevice, key_id: &str) -> E2EEOneTimeKey {
    let signed = make_signed_key(
        &device.signing_key,
        super::model::E2EE_SIGN_CONTEXT_ONE_TIME,
        &device.identity.device_id,
        key_id,
    );

    E2EEOneTimeKey {
        id: E2EEOneTimeKey::composite_id(
            &device.identity.user_id,
            &device.identity.device_id,
            key_id,
        ),
        user_id: device.identity.user_id.clone(),
        device_id: device.identity.device_id.clone(),
        key_id: signed.key_id,
        key: signed.key,
        signature: signed.signature,
    }
}

fn make_envelope(recipient_user: &str, recipient_device: &str) -> E2EEEnvelope {
    E2EEEnvelope {
        id: Ulid::new().to_string(),
        recipient_user_id: recipient_user.to_string(),
        recipient_device_id: recipient_device.to_string(),
        sender_user_id: "sender".to_string(),
        sender_device_id: random_device_id(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        sequence: 0,
        ciphertext: STANDARD_NO_PAD.encode(b"ciphertext"),
        timestamp: Timestamp::now_utc(),
    }
}

#[test]
fn signature_verification_fails_closed() {
    let device = make_device("user");

    // A correctly-signed bundle verifies
    device.identity.verify().expect("valid identity");

    // Substituted Curve25519 identity key: signature no longer covers it
    let mut tampered = device.identity.clone();
    tampered.curve25519_key = STANDARD_NO_PAD.encode(random_bytes::<32>());
    assert!(tampered.verify().is_err());

    // Stripped protocol version (downgrade attempt): inside signed payload
    let mut tampered = device.identity.clone();
    tampered.protocol_version = 0;
    assert!(tampered.verify().is_err());

    // Stripped or garbage signature
    let mut tampered = device.identity.clone();
    tampered.signature = String::new();
    assert!(tampered.verify().is_err());

    // Tampered fallback key
    let mut tampered = device.identity.clone();
    tampered.fallback_key.key = STANDARD_NO_PAD.encode(random_bytes::<32>());
    assert!(tampered.verify().is_err());

    // A fallback key cannot be replayed as a one-time key (domain
    // separation): re-labelling the fallback as an OTK must fail
    let fallback = device.identity.fallback_key.clone();
    let cross_context = E2EEOneTimeKey {
        id: "user:device:fallback0".to_string(),
        user_id: "user".to_string(),
        device_id: device.identity.device_id.clone(),
        key_id: fallback.key_id,
        key: fallback.key,
        signature: fallback.signature,
    };
    assert!(cross_context.verify(&device.identity).is_err());

    // Valid one-time key verifies; tampered fails
    let otk = make_one_time_key(&device, "otk0");
    otk.verify(&device.identity).expect("valid one-time key");

    let mut tampered = otk.clone();
    tampered.key = STANDARD_NO_PAD.encode(random_bytes::<32>());
    assert!(tampered.verify(&device.identity).is_err());
}

#[test]
fn device_claim_verification() {
    let device = make_device("user");
    let nonce = STANDARD_NO_PAD.encode(random_bytes::<32>());

    let payload = E2EEIdentity::claim_payload(&device.identity.device_id, "session1", &nonce);
    let signature = STANDARD_NO_PAD.encode(device.signing_key.sign(payload.as_bytes()).to_bytes());

    // Valid proof accepted
    assert!(device.identity.verify_claim(&nonce, "session1", &signature));

    // Proof bound to another session rejected (no cross-connection replay)
    assert!(!device.identity.verify_claim(&nonce, "session2", &signature));

    // Wrong nonce rejected
    let other_nonce = STANDARD_NO_PAD.encode(random_bytes::<32>());
    assert!(!device.identity.verify_claim(&other_nonce, "session1", &signature));

    // Signature by a different key rejected
    let mallory = SigningKey::from_bytes(&random_bytes::<32>());
    let forged = STANDARD_NO_PAD.encode(mallory.sign(payload.as_bytes()).to_bytes());
    assert!(!device.identity.verify_claim(&nonce, "session1", &forged));
}

#[tokio::test]
async fn identity_unique_and_crud() {
    database_test!(|db| async move {
        let device = make_device("user_a");

        db.insert_e2ee_identity(&device.identity).await.unwrap();

        // Duplicate insert for the same (user, device) loses the race —
        // uniqueness is index-enforced
        assert!(matches!(
            db.insert_e2ee_identity(&device.identity)
                .await
                .unwrap_err()
                .error_type,
            ErrorType::InvalidOperation | ErrorType::DatabaseError { .. }
        ));

        // Compare everything except timestamps (BSON truncates to millis)
        let fetched = db
            .fetch_e2ee_identity("user_a", &device.identity.device_id)
            .await
            .unwrap();
        assert_eq!(fetched.id, device.identity.id);
        assert_eq!(fetched.ed25519_key, device.identity.ed25519_key);
        assert_eq!(fetched.curve25519_key, device.identity.curve25519_key);
        assert_eq!(fetched.signature, device.identity.signature);
        assert_eq!(fetched.fallback_key, device.identity.fallback_key);
        assert_eq!(fetched.protocol_version, device.identity.protocol_version);

        // Fetch-all only returns this user's devices
        let other = make_device("user_b");
        db.insert_e2ee_identity(&other.identity).await.unwrap();
        let list = db.fetch_e2ee_identities("user_a").await.unwrap();
        assert_eq!(list.len(), 1);

        // Session bookkeeping update
        db.update_e2ee_identity_session(
            "user_a",
            &device.identity.device_id,
            "session_new",
            Timestamp::now_utc(),
        )
        .await
        .unwrap();

        let fetched = db
            .fetch_e2ee_identity("user_a", &device.identity.device_id)
            .await
            .unwrap();
        assert_eq!(fetched.last_session_id, "session_new");
    });
}

#[tokio::test]
async fn atomic_one_time_key_consume() {
    database_test!(|db| async move {
        let device = make_device("user_consume");
        db.insert_e2ee_identity(&device.identity).await.unwrap();

        let keys: Vec<_> = (0..20)
            .map(|i| make_one_time_key(&device, &format!("otk{i}")))
            .collect();
        db.insert_e2ee_one_time_keys(&keys).await.unwrap();

        assert_eq!(
            db.count_e2ee_one_time_keys("user_consume", &device.identity.device_id)
                .await
                .unwrap(),
            20
        );

        // 40 concurrent consumers race for 20 keys: exactly 20 succeed and
        // no key is handed out twice
        let mut handles = vec![];
        for _ in 0..40 {
            let db = db.clone();
            let device_id = device.identity.device_id.clone();
            handles.push(tokio::spawn(async move {
                db.consume_e2ee_one_time_key("user_consume", &device_id)
                    .await
                    .unwrap()
            }));
        }

        let mut consumed = vec![];
        for handle in handles {
            if let Some(key) = handle.await.unwrap() {
                consumed.push(key.key_id);
            }
        }

        consumed.sort();
        let unique: std::collections::HashSet<_> = consumed.iter().collect();
        assert_eq!(consumed.len(), 20, "exactly the stored keys are consumed");
        assert_eq!(unique.len(), 20, "no key was consumed twice");

        // Exhaustion: consume returns None, never an error
        assert!(db
            .consume_e2ee_one_time_key("user_consume", &device.identity.device_id)
            .await
            .unwrap()
            .is_none());
    });
}

#[tokio::test]
async fn envelope_queue_ordering_ack_scoping_and_ttl() {
    database_test!(|db| async move {
        let recipient = ("user_r", "deviceaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let envelopes: Vec<_> = (0..5).map(|_| make_envelope(recipient.0, recipient.1)).collect();
        db.insert_e2ee_envelopes(&envelopes).await.unwrap();

        // Also queue mail for someone else: never visible to this recipient
        let stranger = make_envelope("user_s", "devicebbbbbbbbbbbbbbbbbbbbbbbbbb");
        db.insert_e2ee_envelopes(std::slice::from_ref(&stranger))
            .await
            .unwrap();

        assert_eq!(
            db.count_e2ee_envelopes(recipient.0, recipient.1).await.unwrap(),
            5
        );

        // Drain order is strictly ULID-ascending
        let fetched = db
            .fetch_e2ee_envelopes(recipient.0, recipient.1, 100)
            .await
            .unwrap();
        assert_eq!(fetched.len(), 5);
        let mut sorted = fetched.clone();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(fetched, sorted);

        // Cross-user ack rejected: deleting someone else's envelope is a
        // silent no-op, not a deletion
        assert!(!db
            .delete_e2ee_envelope(&stranger.id, recipient.0, recipient.1)
            .await
            .unwrap());
        assert_eq!(db.count_e2ee_envelopes("user_s", stranger.recipient_device_id.as_str()).await.unwrap(), 1);

        // Own ack deletes; repeat ack is idempotent
        assert!(db
            .delete_e2ee_envelope(&fetched[0].id, recipient.0, recipient.1)
            .await
            .unwrap());
        assert!(!db
            .delete_e2ee_envelope(&fetched[0].id, recipient.0, recipient.1)
            .await
            .unwrap());
        assert_eq!(
            db.count_e2ee_envelopes(recipient.0, recipient.1).await.unwrap(),
            4
        );

        // TTL sweep: everything older than the threshold goes, newer stays
        let future_threshold =
            Ulid::from_datetime(SystemTime::now() + Duration::from_secs(60)).to_string();
        let swept = db
            .delete_e2ee_envelopes_before(&future_threshold)
            .await
            .unwrap();
        assert_eq!(swept, 5); // 4 remaining + the stranger's

        assert_eq!(
            db.count_e2ee_envelopes(recipient.0, recipient.1).await.unwrap(),
            0
        );
    });
}

#[tokio::test]
async fn device_deletion_cascades() {
    database_test!(|db| async move {
        let device = make_device("user_del");
        db.insert_e2ee_identity(&device.identity).await.unwrap();

        let keys: Vec<_> = (0..3)
            .map(|i| make_one_time_key(&device, &format!("otk{i}")))
            .collect();
        db.insert_e2ee_one_time_keys(&keys).await.unwrap();

        let envelope = make_envelope("user_del", &device.identity.device_id);
        db.insert_e2ee_envelopes(std::slice::from_ref(&envelope))
            .await
            .unwrap();

        // Deleting the device removes identity, prekeys and queued envelopes
        assert!(db
            .delete_e2ee_device("user_del", &device.identity.device_id)
            .await
            .unwrap());

        assert!(db
            .fetch_e2ee_identity("user_del", &device.identity.device_id)
            .await
            .is_err());
        assert_eq!(
            db.count_e2ee_one_time_keys("user_del", &device.identity.device_id)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            db.count_e2ee_envelopes("user_del", &device.identity.device_id)
                .await
                .unwrap(),
            0
        );

        // Idempotent
        assert!(!db
            .delete_e2ee_device("user_del", &device.identity.device_id)
            .await
            .unwrap());

        // delete_all returns the removed device ids
        let device_a = make_device("user_del2");
        let device_b = make_device("user_del2");
        db.insert_e2ee_identity(&device_a.identity).await.unwrap();
        db.insert_e2ee_identity(&device_b.identity).await.unwrap();

        let mut removed = db.delete_all_e2ee_devices("user_del2").await.unwrap();
        removed.sort();
        let mut expected = vec![
            device_a.identity.device_id.clone(),
            device_b.identity.device_id.clone(),
        ];
        expected.sort();
        assert_eq!(removed, expected);
    });
}
