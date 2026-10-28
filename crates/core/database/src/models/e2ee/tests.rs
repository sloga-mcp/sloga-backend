use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iso8601_timestamp::Timestamp;
use rand::RngCore;
use revolt_result::ErrorType;
use ulid::Ulid;

use crate::{
    events::client::EventV1, Channel, ChannelEntitlement, ChannelEntitlementSource,
    ChannelEntitlementState, Database, E2EEBlob, E2EEBlobRecipient, E2EEEnvelope, E2EEIdentity,
    E2EEOneTimeKey, E2EESignedKey, Member, MemberCompositeKey, MlsGroup, MlsGroupKind,
    MlsKeyPackage, MlsMemberDevice, MlsSignerLostCause, SeatListBody, SeatListHistory,
    SeatListPreHistory, SeatListSubmission, SeatListV2Lines, Server, E2EE_LARGE_BLOB_SIZE,
    E2EE_PROTOCOL_VERSION,
};

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
        content_type: crate::E2EEContentType::Olm,
        group_id: None,
        epoch: None,
        committer: None,
        added: vec![],
        removed: vec![],
        rejoin_intents: vec![],
        removed_reasons: vec![],
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

fn make_blob(at: SystemTime, size: isize, recipients: Vec<E2EEBlobRecipient>) -> E2EEBlob {
    E2EEBlob {
        id: Ulid::from_datetime(at).to_string(),
        uploader_user_id: "alice".to_string(),
        uploader_device_id: "dev_alice".to_string(),
        size,
        bucket_id: "bucket".to_string(),
        iv: "iv".to_string(),
        key_id: None,
        recipients,
    }
}

fn recipient(user_id: &str, device_id: &str) -> E2EEBlobRecipient {
    E2EEBlobRecipient {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        fetched: false,
    }
}

#[tokio::test]
async fn blob_fetch_tracking_and_recipient_scoped_authz() {
    database_test!(|db| async move {
        let blob = make_blob(
            SystemTime::now(),
            1000,
            vec![
                recipient("bob", "dev_b1"),
                recipient("bob", "dev_b2"),
                recipient("alice", "dev_alice2"),
            ],
        );
        db.insert_e2ee_blob(&blob).await.unwrap();

        // Fetch authz is scoped to DECLARED recipient devices only — the
        // uploading device, a stranger, and a wrong device of a legitimate
        // recipient are all refused
        let fetched = db.fetch_e2ee_blob(&blob.id).await.unwrap();
        assert!(fetched.authorizes_fetch("bob", "dev_b1"));
        assert!(!fetched.authorizes_fetch("alice", "dev_alice"));
        assert!(!fetched.authorizes_fetch("mallory", "dev_m"));
        assert!(!fetched.authorizes_fetch("bob", "dev_b3"));

        // Marking a non-recipient fetched matches nothing (atomic filter)
        assert!(db
            .mark_e2ee_blob_fetched(&blob.id, "mallory", "dev_m")
            .await
            .is_err());

        // Per-device fetch tracking: fully_fetched flips only when EVERY
        // declared device has fetched
        let after = db
            .mark_e2ee_blob_fetched(&blob.id, "bob", "dev_b1")
            .await
            .unwrap();
        assert!(!after.fully_fetched());

        let after = db
            .mark_e2ee_blob_fetched(&blob.id, "bob", "dev_b2")
            .await
            .unwrap();
        assert!(!after.fully_fetched());

        let after = db
            .mark_e2ee_blob_fetched(&blob.id, "alice", "dev_alice2")
            .await
            .unwrap();
        assert!(after.fully_fetched());

        // Deletion (post-full-fetch or by the sweep) is idempotent
        assert!(db.delete_e2ee_blob(&blob.id).await.unwrap());
        assert!(!db.delete_e2ee_blob(&blob.id).await.unwrap());
        assert!(db.fetch_e2ee_blob(&blob.id).await.is_err());
    });
}

#[tokio::test]
async fn blob_key_id_round_trips() {
    database_test!(|db| async move {
        // A blob stored under a rotated file key fetches back with its key id
        let mut rotated = make_blob(SystemTime::now(), 1000, vec![recipient("bob", "dev_b")]);
        rotated.key_id = Some("k1".to_string());
        db.insert_e2ee_blob(&rotated).await.unwrap();
        let fetched = db.fetch_e2ee_blob(&rotated.id).await.unwrap();
        assert_eq!(fetched.key_id.as_deref(), Some("k1"));

        // A legacy blob (no key id) fetches back as None
        let legacy = make_blob(SystemTime::now(), 1000, vec![recipient("bob", "dev_b")]);
        db.insert_e2ee_blob(&legacy).await.unwrap();
        let fetched = db.fetch_e2ee_blob(&legacy.id).await.unwrap();
        assert_eq!(fetched.key_id, None);
    });
}

#[tokio::test]
async fn blob_ttl_sweep_is_size_tiered() {
    database_test!(|db| async move {
        let day_old = SystemTime::now() - Duration::from_secs(25 * 60 * 60);
        let month_old = SystemTime::now() - Duration::from_secs(31 * 24 * 60 * 60);

        let large_old = make_blob(
            day_old,
            E2EE_LARGE_BLOB_SIZE + 1,
            vec![recipient("bob", "dev_b")],
        );
        let small_old = make_blob(day_old, 1000, vec![recipient("bob", "dev_b")]);
        let small_ancient = make_blob(month_old, 1000, vec![recipient("bob", "dev_b")]);
        let large_fresh = make_blob(
            SystemTime::now(),
            E2EE_LARGE_BLOB_SIZE + 1,
            vec![recipient("bob", "dev_b")],
        );

        for blob in [&large_old, &small_old, &small_ancient, &large_fresh] {
            db.insert_e2ee_blob(blob).await.unwrap();
        }

        // The 24h sweep uses the large-size floor: it must catch ONLY the
        // day-old large blob — a small day-old blob is retained (30-day
        // tier) and a fresh large blob is untouched
        let threshold_24h =
            Ulid::from_datetime(SystemTime::now() - Duration::from_secs(24 * 60 * 60))
                .to_string();
        let expired = db
            .fetch_expired_e2ee_blobs(&threshold_24h, E2EE_LARGE_BLOB_SIZE)
            .await
            .unwrap();
        assert_eq!(
            expired.iter().map(|b| b.id.as_str()).collect::<Vec<_>>(),
            vec![large_old.id.as_str()]
        );

        // The 30-day sweep (no size floor) catches only the ancient blob
        // (the large day-old one is handled by the tier above)
        let threshold_30d = Ulid::from_datetime(
            SystemTime::now() - Duration::from_secs(30 * 24 * 60 * 60),
        )
        .to_string();
        let expired = db
            .fetch_expired_e2ee_blobs(&threshold_30d, 0)
            .await
            .unwrap();
        assert_eq!(
            expired.iter().map(|b| b.id.as_str()).collect::<Vec<_>>(),
            vec![small_ancient.id.as_str()]
        );
    });
}

// ---------------------------------------------------------------------------
// 6.3 "Device revocation" (S2-D17a, #202, #219): the pending passes around
// the delete while `formats_v2` is on, and the S1 revocation while it is off
// ---------------------------------------------------------------------------

const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";
const SERVER: &str = "01HZXSERVERSERVERSERVERSER";
const OWNER: &str = "01HZXAAAAAAAAAAAAAAAAAAAAA";
const MEMBER: &str = "01HZXBBBBBBBBBBBBBBBBBBBBB";
/// The device that signs the channel's stored list
const SIGNER_DEVICE: &str = "00112233445566778899aabbccddeeff";
const OWNER_DEVICE_2: &str = "0123456789abcdef0123456789abcdef";
const MEMBER_DEVICE: &str = "ffeeddccbbaa99887766554433221100";
const MEMBER_DEVICE_2: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";

fn member_device(user_id: &str, device_id: &str) -> MlsMemberDevice {
    MlsMemberDevice {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
    }
}

/// A stored identity for a fixed device id (the delete only needs the row)
fn identity_of(user_id: &str, device_id: &str) -> E2EEIdentity {
    let mut identity = make_device(user_id).identity;
    identity.id = E2EEIdentity::composite_id(user_id, device_id);
    identity.device_id = device_id.to_string();
    identity
}

fn key_package(user_id: &str, device_id: &str) -> MlsKeyPackage {
    MlsKeyPackage {
        id: MlsKeyPackage::composite_id(user_id, device_id, "kp0"),
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        key_package_ref: "kp0".to_string(),
        key_package: "b3BhcXVl".to_string(),
        mls_signature_key: "c2lna2V5".to_string(),
        binding_signature: "c2ln".to_string(),
        last_resort: false,
        expires_at: Timestamp::now_utc()
            .checked_add(iso8601_timestamp::Duration::days(30))
            .unwrap(),
        created_at: Timestamp::now_utc(),
    }
}

/// The genesis list (seats only the owner, signed on `SIGNER_DEVICE`) in
/// the format the configured `formats_v2` lets protect take (7.1, #218)
async fn genesis_list() -> SeatListSubmission {
    let formats_v2 = revolt_config::config()
        .await
        .features
        .protected_channels
        .formats_v2;
    let body = SeatListBody {
        channel_id: CHANNEL.to_string(),
        version: 1,
        device_cap: 5,
        issued_at: 1_790_812_800_000,
        signer_user_id: OWNER.to_string(),
        signer_device_id: SIGNER_DEVICE.to_string(),
        seats: vec![OWNER.to_string()],
        v2: formats_v2.then(|| SeatListV2Lines {
            authority_sha256: None,
            history: SeatListHistory::Visible,
            history_boundary: None,
            pre_history: SeatListPreHistory::Kept,
            group_salt: "a0".repeat(32),
        }),
    };
    SeatListSubmission {
        body: body.build().unwrap(),
        // The DB layer checks the encoding only; the route verifies it
        signature: format!("B{}", "A".repeat(85)),
        signer_device_id: SIGNER_DEVICE.to_string(),
        handover: None,
        authority: None,
    }
}

const GROUP_ID_BYTE: &str = "a1";

/// `CHANNEL` protected (seats: the owner) with an open Text group created
/// by `SIGNER_DEVICE` holding `members`
async fn protected_channel_with_group(db: &Database, members: Vec<MlsMemberDevice>) {
    let server: Server = serde_json::from_value(serde_json::json!({
        "_id": SERVER,
        "owner": OWNER,
        "name": "protected",
        "channels": [],
        "default_permissions": 0,
    }))
    .unwrap();
    db.insert_server(&server).await.unwrap();
    for user in [OWNER, MEMBER] {
        db.insert_or_merge_member(&Member {
            id: MemberCompositeKey {
                server: SERVER.to_string(),
                user: user.to_string(),
            },
            ..Default::default()
        })
        .await
        .unwrap();
    }
    db.insert_channel(&Channel::TextChannel {
        id: CHANNEL.to_string(),
        server: SERVER.to_string(),
        name: "protected".to_string(),
        description: None,
        icon: None,
        last_message_id: None,
        default_permissions: None,
        role_permissions: HashMap::new(),
        nsfw: false,
        spoiler: false,
        voice: None,
        slowmode: None,
        announcement: None,
        protected: false,
    })
    .await
    .unwrap();
    db.upsert_channel_entitlement(
        &ChannelEntitlement {
            id: Ulid::new().to_string(),
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
    .unwrap();
    db.protect_channel(CHANNEL, &genesis_list().await, Timestamp::now_utc())
        .await
        .unwrap();

    let creator = member_device(OWNER, SIGNER_DEVICE);
    let group = MlsGroup {
        id: GROUP_ID_BYTE.repeat(32),
        channel_id: CHANNEL.to_string(),
        open: true,
        created_by: creator.clone(),
        created_at: Timestamp::now_utc(),
        current_epoch: 0,
        members: vec![creator],
        closed_at: None,
        superseded_by: None,
        // Server-owned Text fields: create_text_mls_group sets them
        kind: MlsGroupKind::Call,
        generation: Some(0),
        seat_list_ad_sha256: None,
        pending_removals: vec![],
        member_added: vec![],
        pending_device_removals: vec![],
        signer_lost: None,
        rejoin_readd: vec![],
    };
    db.create_text_mls_group(&group, None).await.unwrap();
    set_group_members(db, members).await;
}

/// Test-only roster edit of the open Text group on both drivers (the Text
/// commit path that really changes `members` belongs to the mls models)
async fn set_group_members(db: &Database, members: Vec<MlsMemberDevice>) {
    let group_id = GROUP_ID_BYTE.repeat(32);
    match db {
        Database::Reference(reference) => {
            reference
                .mls_groups
                .lock()
                .await
                .get_mut(&group_id)
                .expect("group")
                .members = members;
        }
        #[cfg(feature = "mongodb")]
        Database::MongoDb(mongo) => {
            let members: Vec<bson::Document> = members
                .iter()
                .map(|member| doc! { "user_id": &member.user_id, "device_id": &member.device_id })
                .collect();
            let result = mongo
                .col::<bson::Document>("mls_groups")
                .update_one(
                    doc! { "_id": &group_id },
                    doc! { "$set": { "members": members } },
                )
                .await
                .unwrap();
            assert_eq!(result.matched_count, 1);
        }
    }
}

async fn open_text_group(db: &Database) -> MlsGroup {
    db.fetch_seat_list_snapshot(CHANNEL)
        .await
        .unwrap()
        .text_group
        .expect("an open Text group")
}

/// The `(user, device)` pairs queued on the open Text group
async fn pending_devices(db: &Database) -> Vec<(String, String)> {
    open_text_group(db)
        .await
        .pending_device_removals
        .into_iter()
        .map(|entry| (entry.user_id, entry.device_id))
        .collect()
}

fn pending(user_id: &str, device_id: &str) -> (String, String) {
    (user_id.to_string(), device_id.to_string())
}

/// Revoke with `formats_v2` as given, recording what would be published as
/// `(topic, event JSON)`
async fn revoke_recording(
    db: &Database,
    user_id: &str,
    device_id: &str,
    formats_v2: bool,
) -> (revolt_result::Result<bool>, Vec<(String, String)>) {
    let mut sent = Vec::new();
    let result = E2EEIdentity::revoke_device_publishing(
        db,
        user_id,
        device_id,
        formats_v2,
        |topic, event: EventV1| {
            sent.push((topic, serde_json::to_string(&event).unwrap()));
            std::future::ready(())
        },
    )
    .await;
    (result, sent)
}

/// `ProtectedChannelChanged { scope: [text_group] }` for `CHANNEL` on the
/// CHANNEL topic (7.5: viewers only). The exact topic rules out the user's
/// own topics (`{user}`, `{user}!`) and the server topic (`{server}u`), and
/// the exact JSON rules out any user or device id in the payload.
fn text_group_changed() -> (String, String) {
    (
        CHANNEL.to_string(),
        format!(r#"{{"type":"ProtectedChannelChanged","id":"{CHANNEL}","scope":["text_group"]}}"#),
    )
}

async fn identity_exists(db: &Database, user_id: &str, device_id: &str) -> bool {
    db.fetch_e2ee_identity(user_id, device_id).await.is_ok()
}

/// A member device of an open Text group: queued (never `signer_lost`),
/// deleted, and the channel announced once on its own topic; a repeat
/// revocation queues and announces nothing more. Controls: publish on the
/// user topic; skip the first pass.
#[tokio::test]
async fn revoking_a_member_device_queues_it_and_announces_the_channel() {
    database_test!(|db| async move {
        protected_channel_with_group(
            &db,
            vec![
                member_device(OWNER, SIGNER_DEVICE),
                member_device(MEMBER, MEMBER_DEVICE),
            ],
        )
        .await;
        db.insert_e2ee_identity(&identity_of(MEMBER, MEMBER_DEVICE))
            .await
            .unwrap();
        db.insert_mls_key_packages(&[key_package(MEMBER, MEMBER_DEVICE)])
            .await
            .unwrap();

        let (result, sent) = revoke_recording(&db, MEMBER, MEMBER_DEVICE, true).await;
        assert!(result.unwrap(), "the device existed");
        assert_eq!(sent, vec![text_group_changed()]);
        assert_eq!(
            pending_devices(&db).await,
            vec![pending(MEMBER, MEMBER_DEVICE)]
        );
        assert_eq!(open_text_group(&db).await.signer_lost, None);
        assert!(!identity_exists(&db, MEMBER, MEMBER_DEVICE).await);
        assert_eq!(
            db.count_mls_key_packages(MEMBER, MEMBER_DEVICE)
                .await
                .unwrap(),
            0
        );

        // Idempotent: nothing left to delete, nothing new to queue or say
        let before = open_text_group(&db).await.pending_device_removals;
        let (result, sent) = revoke_recording(&db, MEMBER, MEMBER_DEVICE, true).await;
        assert!(!result.unwrap());
        assert!(sent.is_empty(), "{sent:?}");
        assert_eq!(open_text_group(&db).await.pending_device_removals, before);
    });
}

/// S2-D15: revoking the device that signed the stored list sets the open
/// group's `signer_lost` and never queues it; the channel is announced.
#[tokio::test]
async fn revoking_the_list_signer_device_sets_signer_lost_never_an_entry() {
    database_test!(|db| async move {
        protected_channel_with_group(
            &db,
            vec![
                member_device(OWNER, SIGNER_DEVICE),
                member_device(OWNER, OWNER_DEVICE_2),
            ],
        )
        .await;
        db.insert_e2ee_identity(&identity_of(OWNER, SIGNER_DEVICE))
            .await
            .unwrap();

        let (result, sent) = revoke_recording(&db, OWNER, SIGNER_DEVICE, true).await;
        assert!(result.unwrap());
        assert_eq!(sent, vec![text_group_changed()]);
        let group = open_text_group(&db).await;
        assert!(group.pending_device_removals.is_empty());
        let lost = group.signer_lost.expect("signer_lost");
        assert_eq!(
            (lost.user_id.as_str(), lost.device_id.as_str(), lost.cause),
            (OWNER, SIGNER_DEVICE, MlsSignerLostCause::DeviceRevoked)
        );
        assert!(!identity_exists(&db, OWNER, SIGNER_DEVICE).await);
    });
}

/// No Text group holds the device: the S1 result, no event
#[tokio::test]
async fn revoking_a_device_in_no_text_group_is_the_s1_revocation() {
    database_test!(|db| async move {
        db.insert_e2ee_identity(&identity_of(MEMBER, MEMBER_DEVICE))
            .await
            .unwrap();
        db.insert_mls_key_packages(&[key_package(MEMBER, MEMBER_DEVICE)])
            .await
            .unwrap();

        let (result, sent) = revoke_recording(&db, MEMBER, MEMBER_DEVICE, true).await;
        assert!(result.unwrap());
        assert!(sent.is_empty(), "{sent:?}");
        assert!(!identity_exists(&db, MEMBER, MEMBER_DEVICE).await);
        assert_eq!(
            db.count_mls_key_packages(MEMBER, MEMBER_DEVICE)
                .await
                .unwrap(),
            0
        );

        let (result, sent) = revoke_recording(&db, MEMBER, MEMBER_DEVICE, true).await;
        assert!(!result.unwrap());
        assert!(sent.is_empty(), "{sent:?}");
    });
}

/// Pass (3): a Text commit that added the device after pass (1) (nothing
/// to queue then) and before the delete is caught after the delete, and
/// its channel is collected for the announcement. With the flag off the
/// same sequence queues nothing. Control: drop the second pass.
#[tokio::test]
async fn the_second_pass_catches_a_device_added_after_the_first() {
    database_test!(|db| async move {
        protected_channel_with_group(&db, vec![member_device(OWNER, SIGNER_DEVICE)]).await;
        for device_id in [MEMBER_DEVICE, MEMBER_DEVICE_2] {
            db.insert_e2ee_identity(&identity_of(MEMBER, device_id))
                .await
                .unwrap();
        }

        let mut changed = BTreeSet::new();
        for device_id in [MEMBER_DEVICE, MEMBER_DEVICE_2] {
            E2EEIdentity::pending_device_pass(&db, MEMBER, device_id, &mut changed)
                .await
                .unwrap();
        }
        assert!(changed.is_empty(), "not members yet: {changed:?}");

        // The Adds land between the first pass and the delete
        set_group_members(
            &db,
            vec![
                member_device(OWNER, SIGNER_DEVICE),
                member_device(MEMBER, MEMBER_DEVICE),
                member_device(MEMBER, MEMBER_DEVICE_2),
            ],
        )
        .await;

        // Flag off: the S1 delete only
        assert!(E2EEIdentity::delete_revoked_device(
            &db,
            MEMBER,
            MEMBER_DEVICE_2,
            false,
            &mut changed
        )
        .await
        .unwrap());
        assert!(changed.is_empty(), "{changed:?}");
        assert!(pending_devices(&db).await.is_empty());

        // Flag on: the second pass queues it
        assert!(E2EEIdentity::delete_revoked_device(
            &db,
            MEMBER,
            MEMBER_DEVICE,
            true,
            &mut changed
        )
        .await
        .unwrap());
        assert_eq!(changed, BTreeSet::from([CHANNEL.to_string()]));
        assert_eq!(
            pending_devices(&db).await,
            vec![pending(MEMBER, MEMBER_DEVICE)]
        );
        assert!(!identity_exists(&db, MEMBER, MEMBER_DEVICE).await);
    });
}

/// #219: with `formats_v2` off a revocation is the S1 one: no entry, no
/// `signer_lost` (even for the list signer), no event; the device and its
/// KeyPackages are deleted as before. Control: drop the flag check.
#[tokio::test]
async fn with_formats_v2_off_a_revocation_writes_nothing_protected() {
    database_test!(|db| async move {
        protected_channel_with_group(
            &db,
            vec![
                member_device(OWNER, SIGNER_DEVICE),
                member_device(MEMBER, MEMBER_DEVICE),
            ],
        )
        .await;
        for (user_id, device_id) in [(MEMBER, MEMBER_DEVICE), (OWNER, SIGNER_DEVICE)] {
            db.insert_e2ee_identity(&identity_of(user_id, device_id))
                .await
                .unwrap();
            db.insert_mls_key_packages(&[key_package(user_id, device_id)])
                .await
                .unwrap();

            let (result, sent) = revoke_recording(&db, user_id, device_id, false).await;
            assert!(result.unwrap(), "{device_id}");
            assert!(sent.is_empty(), "{device_id}: {sent:?}");
            assert!(!identity_exists(&db, user_id, device_id).await);
            assert_eq!(
                db.count_mls_key_packages(user_id, device_id).await.unwrap(),
                0
            );
        }
        let group = open_text_group(&db).await;
        assert!(group.pending_device_removals.is_empty());
        assert_eq!(group.signer_lost, None);
    });
}

/// 7.1 (#219): `revoke_device` reads `formats_v2` from the config. The
/// suite runs it with the test config (off); run it once more with
/// `REVOLT__FEATURES__PROTECTED_CHANNELS__FORMATS_V2=true` for the on side.
#[tokio::test]
async fn revoke_device_reads_formats_v2_from_the_config() {
    database_test!(|db| async move {
        let formats_v2 = revolt_config::config()
            .await
            .features
            .protected_channels
            .formats_v2;
        protected_channel_with_group(
            &db,
            vec![
                member_device(OWNER, SIGNER_DEVICE),
                member_device(MEMBER, MEMBER_DEVICE),
            ],
        )
        .await;
        db.insert_e2ee_identity(&identity_of(MEMBER, MEMBER_DEVICE))
            .await
            .unwrap();

        assert!(E2EEIdentity::revoke_device(&db, MEMBER, MEMBER_DEVICE)
            .await
            .unwrap());
        let expected = if formats_v2 {
            vec![pending(MEMBER, MEMBER_DEVICE)]
        } else {
            vec![]
        };
        assert_eq!(pending_devices(&db).await, expected);
        assert!(!identity_exists(&db, MEMBER, MEMBER_DEVICE).await);
    });
}

/// A failed pending pass fails the revocation closed. Pass (1): nothing is
/// deleted and nothing announced. Pass (3) (the device is already gone):
/// the error is still returned. Only Mongo can fail the pass (a stored list
/// row whose id is not a string fails the signer read); the Reference
/// driver's pass cannot fail, so this test checks nothing there.
#[tokio::test]
async fn a_failed_pending_pass_fails_the_revocation_closed() {
    database_test!(|db| async move {
        #[cfg(feature = "mongodb")]
        if let Database::MongoDb(mongo) = &db {
            mongo
                .col::<bson::Document>("channel_seat_lists")
                .insert_one(doc! {
                    "_id": 7_i64,
                    "signer_user_id": MEMBER,
                    "signer_device_id": MEMBER_DEVICE,
                })
                .await
                .unwrap();
            db.insert_e2ee_identity(&identity_of(MEMBER, MEMBER_DEVICE))
                .await
                .unwrap();
            db.insert_mls_key_packages(&[key_package(MEMBER, MEMBER_DEVICE)])
                .await
                .unwrap();

            // Pass (1) fails: the device and its KeyPackages stay
            let (result, sent) = revoke_recording(&db, MEMBER, MEMBER_DEVICE, true).await;
            assert!(result.is_err());
            assert!(sent.is_empty(), "{sent:?}");
            assert!(identity_exists(&db, MEMBER, MEMBER_DEVICE).await);
            assert_eq!(
                db.count_mls_key_packages(MEMBER, MEMBER_DEVICE)
                    .await
                    .unwrap(),
                1
            );

            // Pass (3) fails after the delete: still an error
            let mut changed = BTreeSet::new();
            assert!(E2EEIdentity::delete_revoked_device(
                &db,
                MEMBER,
                MEMBER_DEVICE,
                true,
                &mut changed
            )
            .await
            .is_err());
            assert!(!identity_exists(&db, MEMBER, MEMBER_DEVICE).await);

            // With the flag off the pass never runs
            db.insert_e2ee_identity(&identity_of(MEMBER, MEMBER_DEVICE))
                .await
                .unwrap();
            let (result, _) = revoke_recording(&db, MEMBER, MEMBER_DEVICE, false).await;
            assert!(result.unwrap());
        }
    });
}
