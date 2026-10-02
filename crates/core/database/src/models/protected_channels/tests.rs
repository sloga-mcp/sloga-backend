//! Protected-channel data-layer tests (design section 11, the data-layer
//! obligations on `channel_entitlements`, `channel_seats`,
//! `channel_seat_lists` and the seat-list writes to `mls_groups`).
//!
//! The pure tests pin the 4.1 body and the 3.12.1 commit AD to the section 5
//! vectors. The `database_test!` tests must pass under BOTH
//! `TEST_DB=REFERENCE` and `TEST_DB=MONGODB` (never run without `TEST_DB`:
//! that is production).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering::SeqCst};

use iso8601_timestamp::{Duration, Timestamp};
use revolt_result::ErrorType;
use sha2::{Digest, Sha256};

use crate::{
    channel_seats_used, Channel, ChannelEntitlement, ChannelEntitlementSource,
    ChannelEntitlementState, Database, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind,
    MlsMemberDevice, SeatList, SeatListBody, SeatListSubmission, SignedHandover,
    MAX_SEAT_LIST_HANDOVERS, SEAT_COOLDOWN_DAYS,
};

// Section 5.1 inputs
const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";
const USER_A: &str = "01HZXAAAAAAAAAAAAAAAAAAAAA";
const USER_B: &str = "01HZXBBBBBBBBBBBBBBBBBBBBB";
const USER_C: &str = "01HZXCCCCCCCCCCCCCCCCCCCCC";
const DEVICE_A: &str = "00112233445566778899aabbccddeeff";
const DEVICE_A2: &str = "0123456789abcdef0123456789abcdef";
const DEVICE_B: &str = "ffeeddccbbaa99887766554433221100";
const SERVER: &str = "01HZXSERVERSERVERSERVERSER";

// Section 5.3 / 5.4 / 5.7 vectors
const VECTOR_BODY: &str = "sloga-seat-list-v1\nv:1\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\nversion:3\ndevice_cap:5\nissued_at:1790812800000\nsigner_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nsigner_device_id:00112233445566778899aabbccddeeff\nseats:01HZXAAAAAAAAAAAAAAAAAAAAA,01HZXBBBBBBBBBBBBBBBBBBBBB,01HZXCCCCCCCCCCCCCCCCCCCCC";
const VECTOR_BODY_SHA256: &str = "1d4a02cc0065715b926db563902ca4a6bc7961cb6bd832a9f03544ab59bf7b48";
const VECTOR_SIGNATURE: &str =
    "HtbS6jbLvwSZxAe4i2a4lwmKhv4hM+3NkMY1EuwRaPyv9kI3x/3t1SsalteuxoxmG4YFczXUA77134HTJwLRCA";
const VECTOR_HANDOVER_BODY: &str = "sloga-owner-handover-v1\nv:1\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\nfrom_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nfrom_device_id:00112233445566778899aabbccddeeff\nfrom_identity_key:A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg\nto_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nto_device_id:0123456789abcdef0123456789abcdef\nto_identity_key:zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o\nissued_at:1790812800000";
const VECTOR_HANDOVER_SIGNATURE: &str =
    "JKnYtaiK/i3tYSxV71XoXyz9l0XaDsWIhzoCu8s9IuTdmFmWX5BNtoEhpt+v9gSvhE+nqS2/kZEA0CX6giR6BA";
const VECTOR_COMMIT_AD_HEX: [&str; 6] = [
    "0017736c6f67612d746578742d636f6d6d69742d61642d7631",
    "011e736c6f67612d736561742d6c6973742d76310a763a310a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a76657273696f6e3a330a6465766963655f6361703a350a6973737565645f61743a313739303831323830303030300a7369676e65725f757365725f69643a3031485a584141414141414141414141414141414141414141410a7369676e65725f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a73656174733a3031485a584141414141414141414141414141414141414141412c3031485a584242424242424242424242424242424242424242422c3031485a58434343434343434343434343434343434343434343",
    "00401ed6d2ea36cbbf0499c407b88b66b897098a86fe2133edcd90c63512ec1168fcaff64237c7fdedd52b1a96d7aec68c661b86057335d403bef5df81d32702d108",
    "0001",
    "017f736c6f67612d6f776e65722d68616e646f7665722d76310a763a310a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a66726f6d5f757365725f69643a3031485a584141414141414141414141414141414141414141410a66726f6d5f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a66726f6d5f6964656e746974795f6b65793a41364548762f504f454c3464634e3059353076416d57666b316a436270513166486479475a424a564d62670a746f5f757365725f69643a3031485a584141414141414141414141414141414141414141410a746f5f6465766963655f69643a30313233343536373839616263646566303132333435363738396162636465660a746f5f6964656e746974795f6b65793a7a52537a663556756c5447552f332b334f7a3242334d5668316870314f416c4c664434615a44376c38366f0a6973737565645f61743a31373930383132383030303030",
    "004024a9d8b5a88afe2ded612c55ef55e85f2cfd9745da0ec588873a02bbcb3d22e4dd9859965f904db68121a6dfaff604af844fa7a92dbf919100d025fa82247a04",
];
const VECTOR_COMMIT_AD_SHA256: &str =
    "9cc01bfe85923de2a68126c90f891806c0ced23191dc1b44c0d02edb0a4b0ea4";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Fixed, whole-millisecond base time: Mongo stores Int64 milliseconds, so
/// sub-millisecond `now_utc()` values would not round-trip
fn at(days: i64) -> Timestamp {
    Timestamp::UNIX_EPOCH
        .checked_add(Duration::milliseconds(1_790_812_800_000))
        .and_then(|base| base.checked_add(Duration::days(days)))
        .unwrap()
}

fn numbered_user(n: u32) -> String {
    format!("01HZX{n:021}")
}

/// A canonical unpadded b64 encoding of 64 bytes (the DB layer only checks
/// the encoding; signatures are verified by the route)
fn signature(n: i64) -> String {
    let alphabet = b"BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    format!(
        "{}{}",
        alphabet[n as usize % alphabet.len()] as char,
        "A".repeat(85)
    )
}

fn body_with(version: i64, issued_at: i64, seats: &[&str]) -> String {
    SeatListBody {
        channel_id: CHANNEL.to_string(),
        version,
        device_cap: 5,
        issued_at,
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        seats: seats.iter().map(|seat| seat.to_string()).collect(),
    }
    .build()
    .unwrap()
}

fn submit(version: i64, seats: &[&str]) -> SeatListSubmission {
    SeatListSubmission {
        body: body_with(version, 1_790_812_800_000, seats),
        signature: signature(version),
        signer_device_id: DEVICE_A.to_string(),
        handover: None,
    }
}

fn device(user_id: &str, device_id: &str) -> MlsMemberDevice {
    MlsMemberDevice {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
    }
}

fn text_group(id_byte: u8, creator: &MlsMemberDevice, generation: u32) -> MlsGroup {
    MlsGroup {
        id: format!("{id_byte:02x}").repeat(32),
        channel_id: CHANNEL.to_string(),
        open: true,
        created_by: creator.clone(),
        created_at: at(0),
        current_epoch: 0,
        members: vec![creator.clone()],
        closed_at: None,
        superseded_by: None,
        // Server-owned Text fields: create_text_mls_group sets them
        kind: MlsGroupKind::Call,
        generation: Some(generation),
        seat_list_ad_sha256: None,
        pending_removals: vec![],
        member_added: vec![],
    }
}

fn text_channel(last_message_id: Option<String>) -> Channel {
    Channel::TextChannel {
        id: CHANNEL.to_string(),
        server: SERVER.to_string(),
        name: "protected".to_string(),
        description: None,
        icon: None,
        last_message_id,
        default_permissions: None,
        role_permissions: HashMap::new(),
        nsfw: false,
        spoiler: false,
        voice: None,
        slowmode: None,
        announcement: None,
        protected: false,
    }
}

fn entitlement(slot_cap: u32) -> ChannelEntitlement {
    ChannelEntitlement {
        id: ulid::Ulid::new().to_string(),
        channel_id: CHANNEL.to_string(),
        server_id: SERVER.to_string(),
        source: ChannelEntitlementSource::AdminGrant,
        slot_cap,
        device_cap: None,
        state: ChannelEntitlementState::Active,
        granted_by: "admin".to_string(),
        created_at: at(0),
    }
}

async fn setup(db: &Database, slot_cap: u32) {
    db.insert_channel(&text_channel(None)).await.unwrap();
    db.upsert_channel_entitlement(&entitlement(slot_cap), at(0))
        .await
        .unwrap();
}

/// A distinct, valid channel id per race iteration
fn race_channel(n: u32) -> String {
    format!("01J9Z3K4M5N6P7Q8R9S0T{n:05}")
}

fn submit_in(channel_id: &str, version: i64, seats: &[&str]) -> SeatListSubmission {
    SeatListSubmission {
        body: SeatListBody {
            channel_id: channel_id.to_string(),
            version,
            device_cap: 5,
            issued_at: 1_790_812_800_000,
            signer_user_id: USER_A.to_string(),
            signer_device_id: DEVICE_A.to_string(),
            seats: seats.iter().map(|seat| seat.to_string()).collect(),
        }
        .build()
        .unwrap(),
        signature: signature(version),
        signer_device_id: DEVICE_A.to_string(),
        handover: None,
    }
}

/// Protect `channel_id` (genesis list seats only A) under a fresh entitlement
async fn protected_in(db: &Database, channel_id: &str, slot_cap: u32) {
    let mut channel = text_channel(None);
    if let Channel::TextChannel { id, .. } = &mut channel {
        *id = channel_id.to_string();
    }
    db.insert_channel(&channel).await.unwrap();
    let mut grant = entitlement(slot_cap);
    grant.channel_id = channel_id.to_string();
    db.upsert_channel_entitlement(&grant, at(0)).await.unwrap();
    db.protect_channel(channel_id, &submit_in(channel_id, 1, &[USER_A]), at(0))
        .await
        .unwrap();
}

/// Test-only roster edit on both drivers (the Text commit path that really
/// changes `members` belongs to another lane)
async fn set_group_members(db: &Database, group_id: &str, members: Vec<MlsMemberDevice>) {
    match db {
        Database::Reference(reference) => {
            reference
                .mls_groups
                .lock()
                .await
                .get_mut(group_id)
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
                    doc! { "_id": group_id },
                    doc! { "$set": { "members": members } },
                )
                .await
                .unwrap();
            assert_eq!(result.matched_count, 1);
        }
    }
}

fn is_failed_validation(error: &revolt_result::Error) -> bool {
    matches!(error.error_type, ErrorType::FailedValidation { .. })
}

fn is_seat_cap(error: &revolt_result::Error, expected: usize) -> bool {
    matches!(error.error_type, ErrorType::SeatCapReached { max } if max == expected)
}

// ---------------------------------------------------------------------------
// Pure: section 5 vectors and canonical parsing
// ---------------------------------------------------------------------------

#[test]
fn seat_list_body_matches_the_5_3_vector() {
    let built = SeatListBody {
        channel_id: CHANNEL.to_string(),
        version: 3,
        device_cap: 5,
        issued_at: 1_790_812_800_000,
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        // the builder sorts (5.3 is built from `seats_unsorted`)
        seats: vec![USER_C.to_string(), USER_A.to_string(), USER_B.to_string()],
    }
    .build()
    .unwrap();
    assert_eq!(built, VECTOR_BODY);
    assert_eq!(hex(&Sha256::digest(built.as_bytes())), VECTOR_BODY_SHA256);

    let parsed = SeatListBody::parse(VECTOR_BODY).unwrap();
    assert_eq!(parsed.channel_id, CHANNEL);
    assert_eq!(parsed.version, 3);
    assert_eq!(parsed.device_cap, 5);
    assert_eq!(parsed.issued_at, 1_790_812_800_000);
    assert_eq!(parsed.signer_user_id, USER_A);
    assert_eq!(parsed.signer_device_id, DEVICE_A);
    assert_eq!(parsed.seats, vec![USER_A, USER_B, USER_C]);
}

#[test]
fn seat_list_body_refuses_every_non_canonical_form() {
    let seats_line = format!("seats:{USER_A},{USER_B},{USER_C}");
    let too_many: Vec<String> = (0..100).map(numbered_user).collect();

    let corrupt = [
        format!("{VECTOR_BODY}\n"),
        VECTOR_BODY.replacen('\n', "\r\n", 1),
        VECTOR_BODY.replace("sloga-seat-list-v1", "sloga-seat-list-v2"),
        VECTOR_BODY.replace("\nv:1\n", "\nv:2\n"),
        VECTOR_BODY.replace("version:3", "version:03"),
        VECTOR_BODY.replace("version:3", "version:0"),
        VECTOR_BODY.replace("version:3", "version:+3"),
        VECTOR_BODY.replace("version:3", "version:9007199254740992"),
        VECTOR_BODY.replace("issued_at:1790812800000", "issued_at:9007199254740992"),
        VECTOR_BODY.replace("device_cap:5", "device_cap:4294967296"),
        VECTOR_BODY.replace("device_cap:5", "device_cap: 5"),
        VECTOR_BODY.replace(CHANNEL, &CHANNEL.to_lowercase()),
        VECTOR_BODY.replace(DEVICE_A, &DEVICE_A.to_uppercase()),
        VECTOR_BODY.replace(&seats_line, &format!("seats:{USER_B},{USER_A},{USER_C}")),
        VECTOR_BODY.replace(&seats_line, &format!("seats:{USER_A},{USER_A},{USER_B}")),
        VECTOR_BODY.replace(&seats_line, &format!("seats:{USER_B},{USER_C}")),
        VECTOR_BODY.replace(&seats_line, "seats:"),
        VECTOR_BODY.replace(&seats_line, &format!("seats:{USER_A},")),
        VECTOR_BODY.replace(
            &seats_line,
            &format!("seats:{},{USER_A}", too_many.join(",")),
        ),
        VECTOR_BODY.replace("signer_user_id:", "signer_user:"),
        VECTOR_BODY.replace("\nseats:", "\nseats:\n"),
    ];

    for (index, body) in corrupt.iter().enumerate() {
        assert_ne!(body, VECTOR_BODY, "corruption {index} changed nothing");
        let result = SeatListBody::parse(body);
        assert!(
            result.as_ref().is_err_and(is_failed_validation),
            "corruption {index} was accepted: {body:?}"
        );
    }

    // The bounds are inclusive
    assert!(
        SeatListBody::parse(&VECTOR_BODY.replace("version:3", "version:9007199254740991")).is_ok()
    );
    assert!(SeatListBody::parse(&VECTOR_BODY.replace("device_cap:5", "device_cap:0")).is_ok());
    let hundred: Vec<String> = (0..99).map(numbered_user).collect();
    assert!(SeatListBody::parse(&VECTOR_BODY.replace(
        &seats_line,
        &format!("seats:{},{USER_A}", hundred.join(","))
    ))
    .is_ok());
}

#[test]
fn commit_ad_matches_the_5_7_vector() {
    let row = SeatList {
        id: CHANNEL.to_string(),
        version: 3,
        body: VECTOR_BODY.to_string(),
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        signature: VECTOR_SIGNATURE.to_string(),
        handovers: vec![SignedHandover {
            body: VECTOR_HANDOVER_BODY.to_string(),
            signature: VECTOR_HANDOVER_SIGNATURE.to_string(),
        }],
        updated_at: at(0),
    };

    let ad = row.commit_ad().unwrap();
    assert_eq!(ad.len(), 832);
    assert_eq!(hex(&ad), VECTOR_COMMIT_AD_HEX.concat());
    assert_eq!(row.commit_ad_sha256().unwrap(), VECTOR_COMMIT_AD_SHA256);

    // Any change to the stored row changes the hash the commit path tests
    let mut without_chain = row.clone();
    without_chain.handovers.clear();
    assert_ne!(
        without_chain.commit_ad_sha256().unwrap(),
        VECTOR_COMMIT_AD_SHA256
    );
}

#[test]
fn signatures_must_be_canonical_unpadded_b64_of_64_bytes() {
    let good = VECTOR_SIGNATURE.to_string();
    assert!(crate::decode_signature_b64(&good).is_ok());

    let bad = [
        format!("{good}=="),
        good.replacen('+', "-", 1),
        good.replacen('/', "_", 1),
        format!(" {}", &good[1..]),
        // non-zero trailing bits in the last character
        format!("{}B", &good[..85]),
        good[..84].to_string(),
    ];
    for (index, signature) in bad.iter().enumerate() {
        assert!(
            crate::decode_signature_b64(signature).is_err(),
            "signature corruption {index} was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Database: both drivers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn protect_and_put_follow_the_version_rule() {
    database_test!(|db| async move {
        setup(&db, 10).await;

        // Genesis must be version 1
        let error = db
            .protect_channel(CHANNEL, &submit(2, &[USER_A]), at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        let outcome = db
            .protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();
        assert!(!outcome.unchanged);
        assert_eq!(outcome.claimed, vec![USER_A]);
        assert_eq!(outcome.list.version, 1);
        assert!(db.fetch_channel(CHANNEL).await.unwrap().is_protected());

        // Protect is one-shot
        let error = db
            .protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::InvalidOperation));

        // Strictly stored + 1
        for version in [3, 4, 1_000] {
            let error = db
                .put_seat_list(CHANNEL, &submit(version, &[USER_A, USER_B]), at(0))
                .await
                .unwrap_err();
            assert!(is_failed_validation(&error), "version {version}");
        }

        // A different body at the stored version is equivocation
        let mut other_v1 = submit(1, &[USER_A]);
        other_v1.body = body_with(1, 1_790_812_800_001, &[USER_A]);
        let error = db
            .put_seat_list(CHANNEL, &other_v1, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        // ... and so is the same body under a different signature
        let mut resigned_v1 = submit(1, &[USER_A]);
        resigned_v1.signature = signature(40);
        let error = db
            .put_seat_list(CHANNEL, &resigned_v1, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        let outcome = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), at(0))
            .await
            .unwrap();
        assert!(!outcome.unchanged);
        assert_eq!(outcome.claimed, vec![USER_B]);
        assert_eq!(outcome.list.version, 2);

        // Byte-identical re-PUT: stored success, no side effects
        let seats_before = db.fetch_channel_seats(CHANNEL).await.unwrap();
        let again = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), at(1))
            .await
            .unwrap();
        assert!(again.unchanged);
        assert!(again.claimed.is_empty() && again.released.is_empty());
        assert_eq!(again.list, outcome.list);
        assert_eq!(db.fetch_channel_seats(CHANNEL).await.unwrap(), seats_before);

        // A different list at version 2 is refused
        let error = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_C]), at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        // The route channel and the declared signer device must match the body
        let mut wrong_device = submit(3, &[USER_A]);
        wrong_device.signer_device_id = DEVICE_A2.to_string();
        let error = db
            .put_seat_list(CHANNEL, &wrong_device, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));
        let error = db
            .put_seat_list("01J9Z3K4M5N6P7Q8R9S0T1V2W4", &submit(3, &[USER_A]), at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        let stored = db.fetch_seat_list(CHANNEL).await.unwrap().unwrap();
        assert_eq!(stored, outcome.list);
    });
}

#[tokio::test]
async fn protect_refuses_a_channel_with_messages_or_without_an_active_entitlement() {
    database_test!(|db| async move {
        // No entitlement
        db.insert_channel(&text_channel(None)).await.unwrap();
        let error = db
            .protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::InvalidOperation));
        assert!(db.fetch_seat_list(CHANNEL).await.unwrap().is_none());
        assert!(db.fetch_channel_seats(CHANNEL).await.unwrap().is_empty());
    });

    database_test!(|db| async move {
        // Has history
        db.insert_channel(&text_channel(Some(
            "01J9Z3K4M5N6P7Q8R9S0T1V2W0".to_string(),
        )))
        .await
        .unwrap();
        db.upsert_channel_entitlement(&entitlement(10), at(0))
            .await
            .unwrap();
        let error = db
            .protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::InvalidOperation));
        assert!(db.fetch_seat_list(CHANNEL).await.unwrap().is_none());
        assert!(!db.fetch_channel(CHANNEL).await.unwrap().is_protected());
    });
}

#[tokio::test]
async fn released_seats_count_against_the_cap_until_the_cooldown_ends() {
    database_test!(|db| async move {
        setup(&db, 2).await;

        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();
        db.put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), at(0))
            .await
            .unwrap();

        let outcome = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A]), at(0))
            .await
            .unwrap();
        assert_eq!(outcome.released, vec![USER_B]);

        let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
        let seat_b = seats.iter().find(|seat| seat.user_id == USER_B).unwrap();
        assert_eq!(seat_b.released_at, Some(at(0)));
        assert_eq!(seat_b.cooldown_until, Some(at(SEAT_COOLDOWN_DAYS)));
        assert_eq!(channel_seats_used(&seats, at(1)), 2, "cooling seat counts");

        // A new user does not fit while B cools
        let error = db
            .put_seat_list(CHANNEL, &submit(4, &[USER_A, USER_C]), at(1))
            .await
            .unwrap_err();
        assert!(is_seat_cap(&error, 2));

        // Re-seating the cooling user reactivates the row, no new slot
        let outcome = db
            .put_seat_list(CHANNEL, &submit(4, &[USER_A, USER_B]), at(1))
            .await
            .unwrap();
        assert_eq!(outcome.claimed, vec![USER_B]);
        let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
        let seat_b = seats.iter().find(|seat| seat.user_id == USER_B).unwrap();
        assert!(seat_b.is_active());
        assert_eq!(seat_b.seated_at, at(1));
        assert_eq!(seats.len(), 2);

        // Release again at day 1: cooling until day 15
        db.put_seat_list(CHANNEL, &submit(5, &[USER_A]), at(1))
            .await
            .unwrap();

        // Day 14 is still inside the cooldown
        let error = db
            .put_seat_list(CHANNEL, &submit(6, &[USER_A, USER_C]), at(14))
            .await
            .unwrap_err();
        assert!(is_seat_cap(&error, 2));

        // A removal-only list is never refused by the cap (7.1)
        // (here: the same seats, so nothing is claimed)
        db.put_seat_list(CHANNEL, &submit(6, &[USER_A]), at(14))
            .await
            .unwrap();

        // Day 16: B's cooldown is over and its slot is free
        let outcome = db
            .put_seat_list(CHANNEL, &submit(7, &[USER_A, USER_C]), at(16))
            .await
            .unwrap();
        assert_eq!(outcome.claimed, vec![USER_C]);
        let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
        assert_eq!(channel_seats_used(&seats, at(16)), 2);
    });
}

#[tokio::test]
async fn racing_seat_claims_never_exceed_the_cap() {
    database_test!(|db| async move {
        setup(&db, 3).await;

        // Racing genesis lists: exactly one protect lands
        let mut handles = Vec::new();
        for task in 0..8u32 {
            let db = db.clone();
            let mine = numbered_user(100 + task);
            handles.push(tokio::spawn(async move {
                db.protect_channel(CHANNEL, &submit(1, &[USER_A, mine.as_str()]), at(0))
                    .await
            }));
        }
        let mut protected = 0;
        for handle in handles {
            match handle.await.expect("join") {
                Ok(_) => protected += 1,
                Err(error) => assert!(
                    matches!(error.error_type, ErrorType::InvalidOperation)
                        || is_failed_validation(&error),
                    "unexpected protect error {error:?}"
                ),
            }
        }
        assert_eq!(protected, 1, "exactly one genesis list is stored");
        let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
        assert_eq!(channel_seats_used(&seats, at(0)), 2);
        let genesis = db.fetch_seat_list(CHANNEL).await.unwrap().unwrap();
        assert_eq!(genesis.version, 1);
        // The genesis winner's second seat (a released seat keeps counting
        // while it cools, so each racing PUT below keeps it seated)
        let winner = SeatListBody::parse(&genesis.body)
            .unwrap()
            .seats
            .into_iter()
            .find(|seat| seat != USER_A)
            .unwrap();

        // Racing PUTs, each of which fits the cap on its own (A + winner +
        // one new = 3): one lands, the others lose the version
        // compare-and-set and claim nothing. Two landing would need 4 seats.
        let mut handles = Vec::new();
        for task in 0..8u32 {
            let db = db.clone();
            let winner = winner.clone();
            let new = numbered_user(200 + task);
            handles.push(tokio::spawn(async move {
                db.put_seat_list(
                    CHANNEL,
                    &submit(2, &[USER_A, winner.as_str(), new.as_str()]),
                    at(0),
                )
                .await
            }));
        }
        let mut landed = Vec::new();
        for handle in handles {
            match handle.await.expect("join") {
                Ok(outcome) => landed.push(outcome),
                Err(error) => assert!(
                    is_failed_validation(&error),
                    "a racing PUT must lose on the version, got {error:?}"
                ),
            }
        }
        assert_eq!(landed.len(), 1, "exactly one racing PUT lands");
        assert_eq!(landed[0].claimed.len(), 1);
        let stored_row = db.fetch_seat_list(CHANNEL).await.unwrap().unwrap();
        assert_eq!(stored_row.version, 2, "the version advances by exactly one");
        assert_eq!(stored_row, landed[0].list, "the stored row is the winner's");

        let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
        let used = channel_seats_used(&seats, at(0));
        assert!(used <= 3, "seats used {used} exceeds the cap");
        assert_eq!(used, 3);
        let active: Vec<&str> = seats
            .iter()
            .filter(|seat| seat.is_active())
            .map(|seat| seat.user_id.as_str())
            .collect();
        let stored =
            SeatListBody::parse(&db.fetch_seat_list(CHANNEL).await.unwrap().unwrap().body).unwrap();
        let mut expected: Vec<&str> = stored.seats.iter().map(String::as_str).collect();
        expected.sort();
        let mut active_sorted = active.clone();
        active_sorted.sort();
        assert_eq!(
            active_sorted, expected,
            "active seats are exactly the stored list"
        );

        // Equivocation race the cap cannot catch: 8 DIFFERENT version-3
        // bodies (same seats, distinct issued_at, so nothing is claimed).
        // Only the version compare-and-set can keep all but one out.
        let seats_v2: Vec<String> = expected.iter().map(|seat| seat.to_string()).collect();
        let mut handles = Vec::new();
        for task in 0..8i64 {
            let db = db.clone();
            let seats_v2 = seats_v2.clone();
            handles.push(tokio::spawn(async move {
                let seats: Vec<&str> = seats_v2.iter().map(String::as_str).collect();
                let submission = SeatListSubmission {
                    body: body_with(3, 1_790_812_800_000 + task, &seats),
                    signature: signature(task),
                    signer_device_id: DEVICE_A.to_string(),
                    handover: None,
                };
                db.put_seat_list(CHANNEL, &submission, at(0)).await
            }));
        }
        let mut landed = Vec::new();
        for handle in handles {
            match handle.await.expect("join") {
                Ok(outcome) => landed.push(outcome),
                Err(error) => assert!(
                    is_failed_validation(&error),
                    "an equivocating PUT must lose on the version, got {error:?}"
                ),
            }
        }
        assert_eq!(landed.len(), 1, "exactly one version-3 body lands");
        assert!(!landed[0].unchanged);
        let stored_row = db.fetch_seat_list(CHANNEL).await.unwrap().unwrap();
        assert_eq!(stored_row.version, 3, "the version advances by exactly one");
        assert_eq!(stored_row, landed[0].list, "the stored row is the winner's");
    });
}

#[tokio::test]
async fn seat_put_writes_the_group_hash_and_pending_removals_with_the_list() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);

        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B]), at(0))
            .await
            .unwrap();
        let group = text_group(0xaa, &owner, 0);
        assert_eq!(
            db.create_text_mls_group(&group, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        );

        let snapshot = db.fetch_seat_list_snapshot(CHANNEL).await.unwrap();
        let list = snapshot.list.unwrap();
        let stored = snapshot.text_group.unwrap();
        assert_eq!(stored.kind, MlsGroupKind::Text);
        assert_eq!(stored.generation, Some(0));
        assert_eq!(
            stored.seat_list_ad_sha256,
            Some(list.commit_ad_sha256().unwrap())
        );
        assert_eq!(stored.member_added.len(), 1);
        assert_eq!(stored.member_added[0].user_id, USER_A);
        assert_eq!(stored.member_added[0].device_id, DEVICE_A);
        assert_eq!(stored.member_added[0].epoch, 0);

        set_group_members(
            &db,
            &group.id,
            vec![owner.clone(), device(USER_B, DEVICE_B)],
        )
        .await;

        // Unseat B: released, pending removal, and the new hash, together
        let outcome = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A]), at(1))
            .await
            .unwrap();
        assert_eq!(outcome.released, vec![USER_B]);
        assert_eq!(outcome.pending_removals_added, vec![USER_B]);

        let snapshot = db.fetch_seat_list_snapshot(CHANNEL).await.unwrap();
        let list = snapshot.list.unwrap();
        let stored = snapshot.text_group.unwrap();
        assert_eq!(list.version, 2);
        assert_eq!(
            stored.seat_list_ad_sha256,
            Some(list.commit_ad_sha256().unwrap())
        );
        assert_eq!(stored.pending_removals.len(), 1);
        assert_eq!(stored.pending_removals[0].user_id, USER_B);
        assert_eq!(stored.pending_removals[0].created_at, at(1));
        // Fields the seat PUT does not own are untouched
        assert_eq!(stored.current_epoch, 0);
        assert_eq!(stored.members.len(), 2);
        assert_eq!(stored.member_added.len(), 1);
        assert_eq!(stored.generation, Some(0));

        // An identical re-PUT adds nothing
        let again = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A]), at(2))
            .await
            .unwrap();
        assert!(again.unchanged);
        let stored = db
            .fetch_seat_list_snapshot(CHANNEL)
            .await
            .unwrap()
            .text_group
            .unwrap();
        assert_eq!(stored.pending_removals.len(), 1);

        // A later list never duplicates the pending entry, but moves the hash
        let outcome = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A]), at(2))
            .await
            .unwrap();
        assert!(outcome.pending_removals_added.is_empty());
        let snapshot = db.fetch_seat_list_snapshot(CHANNEL).await.unwrap();
        let stored = snapshot.text_group.unwrap();
        assert_eq!(stored.pending_removals.len(), 1);
        assert_eq!(
            stored.seat_list_ad_sha256,
            Some(snapshot.list.unwrap().commit_ad_sha256().unwrap())
        );
    });
}

#[tokio::test]
async fn byte_identical_reput_succeeds_after_the_signer_lost_its_leaf() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);

        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B]), at(0))
            .await
            .unwrap();
        let group = text_group(0xbb, &owner, 0);
        db.create_text_mls_group(&group, None).await.unwrap();
        db.put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), at(0))
            .await
            .unwrap();

        // The signer device's leaf is gone (rejoin case)
        set_group_members(&db, &group.id, vec![device(USER_B, DEVICE_B)]).await;

        // 5b refuses a NEW list from a signer without a leaf
        let error = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A]), at(1))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        // ... but the lost-response retry of the stored list still succeeds
        let again = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), at(1))
            .await
            .unwrap();
        assert!(again.unchanged);
        assert_eq!(again.list.version, 2);
    });
}

#[tokio::test]
async fn text_group_create_follows_the_signer_and_generation_rules() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);

        // No seat list yet
        let error = db
            .create_text_mls_group(&text_group(0x01, &owner, 0), None)
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();

        // Another device of the owner user is not the signer device
        let error = db
            .create_text_mls_group(&text_group(0x02, &device(USER_A, DEVICE_A2), 0), None)
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        // A first group is generation 0; a generation is required
        let error = db
            .create_text_mls_group(&text_group(0x03, &owner, 1), None)
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));
        let mut no_generation = text_group(0x04, &owner, 0);
        no_generation.generation = None;
        let error = db
            .create_text_mls_group(&no_generation, None)
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        let first = text_group(0x05, &owner, 0);
        assert_eq!(
            db.create_text_mls_group(&first, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        );

        // One open Text group per channel
        assert_eq!(
            db.create_text_mls_group(&text_group(0x06, &owner, 0), None)
                .await
                .unwrap(),
            MlsGroupCreateOutcome::Conflict {
                open_group_id: first.id.clone(),
                channel_id: CHANNEL.to_string(),
            }
        );

        // A successor must be the superseded generation + 1
        let error = db
            .create_text_mls_group(&text_group(0x07, &owner, 2), Some(&first.id))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        let successor = text_group(0x08, &owner, 1);
        assert_eq!(
            db.create_text_mls_group(&successor, Some(&first.id))
                .await
                .unwrap(),
            MlsGroupCreateOutcome::Created
        );
        let open = db
            .fetch_seat_list_snapshot(CHANNEL)
            .await
            .unwrap()
            .text_group
            .unwrap();
        assert_eq!(open.id, successor.id);
        assert_eq!(open.generation, Some(1));
        assert!(open.seat_list_ad_sha256.is_some());

        // The superseded group was closed with a back-pointer
        let old = db.fetch_mls_group(&first.id).await.unwrap();
        assert!(!old.open);
        assert_eq!(old.superseded_by, Some(successor.id.clone()));
    });
}

#[tokio::test]
async fn handover_chain_is_append_only_and_capped() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();

        for version in 2..(2 + MAX_SEAT_LIST_HANDOVERS as i64) {
            let mut submission = submit(version, &[USER_A]);
            submission.handover = Some(SignedHandover {
                body: format!("handover {version}"),
                signature: signature(version),
            });
            let outcome = db.put_seat_list(CHANNEL, &submission, at(0)).await.unwrap();
            assert_eq!(outcome.list.handovers.len() as i64, version - 1);
            assert_eq!(
                outcome.list.handovers.last().unwrap().body,
                format!("handover {version}")
            );
        }

        let next = 2 + MAX_SEAT_LIST_HANDOVERS as i64;
        let mut over = submit(next, &[USER_A]);
        over.handover = Some(SignedHandover {
            body: "one too many".to_string(),
            signature: signature(next),
        });
        let error = db.put_seat_list(CHANNEL, &over, at(0)).await.unwrap_err();
        assert!(is_failed_validation(&error));

        // Without a handover the list still advances; the chain is kept
        let outcome = db
            .put_seat_list(CHANNEL, &submit(next, &[USER_A]), at(0))
            .await
            .unwrap();
        assert_eq!(outcome.list.handovers.len(), MAX_SEAT_LIST_HANDOVERS);
        assert_eq!(outcome.list.handovers[0].body, "handover 2");
    });
}

#[tokio::test]
async fn forced_release_releases_the_seat_and_adds_one_pending_removal() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);

        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B]), at(0))
            .await
            .unwrap();
        let group = text_group(0xcc, &owner, 0);
        db.create_text_mls_group(&group, None).await.unwrap();
        set_group_members(
            &db,
            &group.id,
            vec![owner.clone(), device(USER_B, DEVICE_B)],
        )
        .await;
        let hash_before = db
            .fetch_seat_list_snapshot(CHANNEL)
            .await
            .unwrap()
            .text_group
            .unwrap()
            .seat_list_ad_sha256;

        // Another server's removal touches nothing here
        assert!(db
            .release_channel_seats_for_user(USER_B, Some("01HZXOTHERSERVEROTHERSERVE"), at(1))
            .await
            .unwrap()
            .is_empty());

        assert_eq!(
            db.release_channel_seats_for_user(USER_B, Some(SERVER), at(1))
                .await
                .unwrap(),
            vec![CHANNEL]
        );
        let seats = db.fetch_channel_seats_for_user(USER_B).await.unwrap();
        assert_eq!(seats.len(), 1);
        assert_eq!(seats[0].released_at, Some(at(1)));
        assert!(seats[0].is_cooling(at(2)));

        let stored = db
            .fetch_seat_list_snapshot(CHANNEL)
            .await
            .unwrap()
            .text_group
            .unwrap();
        assert_eq!(stored.pending_removals.len(), 1);
        assert_eq!(stored.pending_removals[0].user_id, USER_B);
        // The signed list did not change, so neither did the AD hash
        assert_eq!(stored.seat_list_ad_sha256, hash_before);

        // Idempotent
        assert!(db
            .release_channel_seats_for_user(USER_B, None, at(2))
            .await
            .unwrap()
            .is_empty());
        let stored = db
            .fetch_seat_list_snapshot(CHANNEL)
            .await
            .unwrap()
            .text_group
            .unwrap();
        assert_eq!(stored.pending_removals.len(), 1);

        // The owner's later unseat neither re-releases nor duplicates
        let outcome = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A]), at(3))
            .await
            .unwrap();
        assert!(outcome.released.is_empty());
        assert!(outcome.pending_removals_added.is_empty());
    });
}

#[tokio::test]
async fn entitlement_upsert_refuses_a_cap_below_the_seats_in_use() {
    database_test!(|db| async move {
        setup(&db, 3).await;
        let original = db
            .fetch_channel_entitlement(CHANNEL)
            .await
            .unwrap()
            .unwrap();

        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B, USER_C]), at(0))
            .await
            .unwrap();

        let error = db
            .upsert_channel_entitlement(&entitlement(2), at(0))
            .await
            .unwrap_err();
        assert!(is_seat_cap(&error, 2));

        for slot_cap in [0, 101] {
            let error = db
                .upsert_channel_entitlement(&entitlement(slot_cap), at(0))
                .await
                .unwrap_err();
            assert!(is_failed_validation(&error));
        }

        let mut update = entitlement(5);
        update.device_cap = Some(2);
        let stored = db.upsert_channel_entitlement(&update, at(0)).await.unwrap();
        assert_eq!(stored.id, original.id);
        assert_eq!(stored.created_at, original.created_at);
        assert_eq!(stored.slot_cap, 5);
        assert_eq!(stored.device_cap, Some(2));
        assert_eq!(
            db.fetch_channel_entitlement(CHANNEL).await.unwrap(),
            Some(stored)
        );
    });
}

#[tokio::test]
async fn delete_cascade_removes_the_protected_channel_data() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);
        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();
        let group = text_group(0xdd, &owner, 0);
        db.create_text_mls_group(&group, None).await.unwrap();

        db.delete_protected_channel_data(CHANNEL).await.unwrap();

        assert!(db
            .fetch_channel_entitlement(CHANNEL)
            .await
            .unwrap()
            .is_none());
        assert!(db.fetch_channel_seats(CHANNEL).await.unwrap().is_empty());
        let snapshot = db.fetch_seat_list_snapshot(CHANNEL).await.unwrap();
        assert!(snapshot.list.is_none());
        assert!(snapshot.text_group.is_none());
        assert!(!db.fetch_mls_group(&group.id).await.unwrap().open);
    });
}

#[tokio::test]
async fn protect_refuses_a_channel_whose_message_is_not_yet_in_last_message_id() {
    database_test!(|db| async move {
        // last_message_id is written by a batched queue, so a stored message
        // can exist while the channel still reports none
        setup(&db, 10).await;
        db.insert_message(&crate::Message {
            id: ulid::Ulid::new().to_string(),
            channel: CHANNEL.to_string(),
            author: USER_B.to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(matches!(
            db.fetch_channel(CHANNEL).await.unwrap(),
            Channel::TextChannel {
                last_message_id: None,
                ..
            }
        ));

        let error = db
            .protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::InvalidOperation));
        assert!(db.fetch_seat_list(CHANNEL).await.unwrap().is_none());
        assert!(db.fetch_channel_seats(CHANNEL).await.unwrap().is_empty());
        assert!(!db.fetch_channel(CHANNEL).await.unwrap().is_protected());
    });
}

/// Racing iterations for the write-skew tests: each one is a fresh channel
const RACE_ITERATIONS: u32 = 25;

#[tokio::test]
async fn text_group_create_never_binds_a_stale_seat_list() {
    database_test!(|db| async move {
        let owner = device(USER_A, DEVICE_A);
        for iteration in 0..RACE_ITERATIONS {
            let channel_id = race_channel(iteration);
            protected_in(&db, &channel_id, 10).await;

            let mut group = text_group(0, &owner, 0);
            group.id = format!("{:064x}", 0x00c0_0000 + iteration);
            group.channel_id = channel_id.clone();

            // Real create racing a real seat PUT on the same channel
            let next = submit_in(&channel_id, 2, &[USER_A, USER_B]);
            let (created, put) = tokio::join!(
                db.create_text_mls_group(&group, None),
                db.put_seat_list(&channel_id, &next, at(0))
            );
            assert_eq!(
                created.expect("create must not error"),
                MlsGroupCreateOutcome::Created
            );
            assert!(!put.expect("seat PUT must not error").unchanged);

            // Whatever the order, the group binds the NEWEST list
            let snapshot = db.fetch_seat_list_snapshot(&channel_id).await.unwrap();
            let list = snapshot.list.unwrap();
            assert_eq!(list.version, 2);
            assert_eq!(
                snapshot.text_group.unwrap().seat_list_ad_sha256,
                Some(list.commit_ad_sha256().unwrap()),
                "iteration {iteration}: the group is bound to a stale seat list"
            );
        }
    });
}

#[tokio::test]
async fn lowering_the_slot_cap_never_skews_against_a_seat_claim() {
    database_test!(|db| async move {
        for iteration in 0..RACE_ITERATIONS {
            let channel_id = race_channel(1_000 + iteration);
            protected_in(&db, &channel_id, 3).await;

            // Lower the cap to the 1 seat in use while a PUT claims a 2nd
            let mut lowered = entitlement(1);
            lowered.channel_id = channel_id.clone();
            let claim = submit_in(&channel_id, 2, &[USER_A, USER_B]);
            let (granted, put) = tokio::join!(
                db.upsert_channel_entitlement(&lowered, at(0)),
                db.put_seat_list(&channel_id, &claim, at(0))
            );

            // Exactly one lands; the other sees it and hits the cap
            match (&granted, &put) {
                (Ok(_), Err(error)) | (Err(error), Ok(_)) => assert!(
                    is_seat_cap(error, 1),
                    "iteration {iteration}: unexpected error {error:?}"
                ),
                _ => panic!(
                    "iteration {iteration}: expected exactly one to land, got {granted:?} / {put:?}"
                ),
            }

            let cap = db
                .fetch_channel_entitlement(&channel_id)
                .await
                .unwrap()
                .unwrap()
                .slot_cap as usize;
            let seats = db.fetch_channel_seats(&channel_id).await.unwrap();
            let used = channel_seats_used(&seats, at(0));
            assert!(
                used <= cap,
                "iteration {iteration}: {used} seats used under a slot cap of {cap}"
            );
        }
    });
}

/// A tight stream of REAL Text Update commits (`insert_mls_text_commit`)
/// with a 1 ms gap. It tracks the epoch and seat-list hash locally and
/// refetches them only after a loss (a racing writer, or a stale hash once a
/// seat PUT lands), so the group document is written as often as the commit
/// path allows. Runs until `stop`, counting wins in `won`; returns the
/// last commit error, for diagnosis.
async fn text_commit_stream(
    db: &Database,
    channel_id: &str,
    committer: &MlsMemberDevice,
    stop: &AtomicBool,
    won: &AtomicI64,
) -> Option<String> {
    let mut last_error = None;
    let mut state: Option<(String, i64, String)> = None;
    while !stop.load(SeqCst) {
        let (group_id, current_epoch, hash) = match state.take() {
            Some(state) => state,
            None => {
                let group = db
                    .fetch_seat_list_snapshot(channel_id)
                    .await
                    .unwrap()
                    .text_group
                    .unwrap();
                (
                    group.id,
                    group.current_epoch,
                    group.seat_list_ad_sha256.unwrap(),
                )
            }
        };
        let epoch = current_epoch + 1;
        let commit = crate::MlsCommit {
            id: crate::MlsCommit::composite_id(&group_id, epoch),
            group_id: group_id.clone(),
            epoch,
            committer: committer.clone(),
            commit: "b3BhcXVl".to_string(),
            size: 8,
            added: vec![],
            removed: vec![],
            created_at: Timestamp::now_utc(),
            rejoin_intents: vec![],
        };
        match db.insert_mls_text_commit(&commit, &hash, 0).await {
            Ok(crate::MlsCommitOutcome::Won) => {
                won.fetch_add(1, SeqCst);
                state = Some((group_id, epoch, hash));
            }
            // Losing a race is expected: refetch and go again
            Ok(other) => last_error = Some(format!("{other:?}")),
            Err(error) => last_error = Some(format!("{error:?}")),
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    last_error
}

/// Poll `done` every 2 ms for up to 5 s; whether it became true
async fn wait_until(done: impl Fn() -> bool) -> bool {
    for _ in 0..2_500 {
        if done() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    done()
}

/// Rounds of the seat-PUT starvation test (each a fresh channel)
const STARVATION_ROUNDS: u32 = 12;

/// Sequential seat PUTs per starvation round, from version 2
const PUTS_PER_ROUND: i64 = 5;
const FIRST_PUT_VERSION: i64 = 2;

#[tokio::test]
async fn seat_put_lands_while_text_commits_stream_in() {
    database_test!(|db| async move {
        let owner = device(USER_A, DEVICE_A);
        for round in 0..STARVATION_ROUNDS {
            let channel_id = race_channel(2_000 + round);
            protected_in(&db, &channel_id, 10).await;
            let mut group = text_group(0, &owner, 0);
            group.id = format!("{:064x}", 0x00d0_0000 + round);
            group.channel_id = channel_id.clone();
            assert_eq!(
                db.create_text_mls_group(&group, None).await.unwrap(),
                MlsGroupCreateOutcome::Created
            );

            let stop = AtomicBool::new(false);
            let won = AtomicI64::new(0);
            let puts = async {
                // Fire the PUTs only once the commit stream is live
                let live = wait_until(|| won.load(SeqCst) >= 1).await;
                let before = won.load(SeqCst);
                // Several PUTs in a row (alternately seating and unseating
                // B), each racing the stream; every one must land
                let mut results = Vec::new();
                for version in FIRST_PUT_VERSION..FIRST_PUT_VERSION + PUTS_PER_ROUND {
                    let seats: &[&str] = if version % 2 == 0 {
                        &[USER_A, USER_B]
                    } else {
                        &[USER_A]
                    };
                    let submission = submit_in(&channel_id, version, seats);
                    results.push(db.put_seat_list(&channel_id, &submission, at(0)).await);
                }
                // Keep streaming until a commit lands on the newest hash
                let after = won.load(SeqCst);
                let adopted = wait_until(|| won.load(SeqCst) > after).await;
                stop.store(true, SeqCst);
                (results, live, before, adopted)
            };
            let (last_error, (results, live, before, adopted)) = tokio::join!(
                text_commit_stream(&db, &channel_id, &owner, &stop, &won),
                puts
            );

            assert!(
                live && before >= 1,
                "round {round}: the commit stream never went live (last error {last_error:?})"
            );
            for (offset, result) in results.into_iter().enumerate() {
                let outcome = result.unwrap_or_else(|error| {
                    panic!("round {round}, PUT {offset}: never landed (starved): {error:?}")
                });
                assert_eq!(outcome.list.version, FIRST_PUT_VERSION + offset as i64);
            }
            assert!(
                adopted,
                "round {round}: no commit landed on the new hash (last error {last_error:?})"
            );

            // The commits really landed on the group, and it carries the
            // PUT's hash (no write was lost on either side)
            let snapshot = db.fetch_seat_list_snapshot(&channel_id).await.unwrap();
            let list = snapshot.list.unwrap();
            let stored = snapshot.text_group.unwrap();
            assert_eq!(list.version, FIRST_PUT_VERSION + PUTS_PER_ROUND - 1);
            assert_eq!(stored.current_epoch, won.load(SeqCst), "round {round}");
            assert_eq!(
                stored.seat_list_ad_sha256,
                Some(list.commit_ad_sha256().unwrap()),
                "round {round}"
            );
        }
    });
}
