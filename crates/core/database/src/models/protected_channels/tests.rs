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
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use iso8601_timestamp::{Duration, Timestamp};
use revolt_result::ErrorType;
use sha2::{Digest, Sha256};

use crate::{
    channel_seats_used, check_removal_reason, check_seat_list_authority, check_seat_list_v2_lines,
    plan_seat_list_write, resolve_signer_lost, seat_list_removed_users, text_group_id_v2,
    text_group_id_v2_input, AuthorityOwnerDevice, AuthorityUserDevice, Channel, ChannelAuthority,
    ChannelAuthorityBody, ChannelEntitlement, ChannelEntitlementSource, ChannelEntitlementState,
    ChannelSeat, Database, E2EEContentType, E2EEEnvelope, HandoverBody, Member, MemberCompositeKey,
    MlsGroup, MlsGroupCreateOutcome, MlsGroupKind, MlsMemberDevice, MlsPendingDeviceRemoval,
    MlsSignerLost, MlsSignerLostCause, SeatList, SeatListBody, SeatListHistory, SeatListPreHistory,
    SeatListSubmission, SeatListV2Lines, SeatListWriteDecision, SeatListWriteInput,
    SeatListWriteKind, SeatListWritePlan, SeatReleaseCause, Server, SignedAuthority,
    SignedHandover, SignerLostResolution, SuccessionStatement, TextJoinPayload,
    E2EE_PROTOCOL_VERSION, MAX_COMMIT_AD_LEN, MAX_SEAT_LIST_HANDOVERS, PROTECTED_SCOPE_SEATS,
    PROTECTED_SCOPE_TEXT_GROUP, SEAT_COOLDOWN_DAYS,
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

// Section 5.2 identity keys (owner seed, new owner seed)
const OWNER_IDENTITY_KEY: &str = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
const NEW_OWNER_IDENTITY_KEY: &str = "zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o";

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
        v2: None,
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
        authority: None,
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
        pending_device_removals: vec![],
        signer_lost: None,
        rejoin_readd: vec![],
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

/// A server owned by `owner` (protect claims it, decision 13 (W2))
async fn insert_server(db: &Database, server_id: &str, owner: &str) {
    let server: Server = serde_json::from_value(serde_json::json!({
        "_id": server_id,
        "owner": owner,
        "name": "protected",
        "channels": [],
        "default_permissions": 0,
    }))
    .unwrap();
    db.insert_server(&server).await.unwrap();
}

/// Memberships of `users` in `server_id` (protect and the seat PUT claim
/// the membership of every user they seat, decision 13 (W2))
async fn insert_members(db: &Database, server_id: &str, users: &[&str]) {
    for user in users {
        db.insert_or_merge_member(&Member {
            id: MemberCompositeKey {
                server: server_id.to_string(),
                user: user.to_string(),
            },
            ..Default::default()
        })
        .await
        .unwrap();
    }
}

/// `SERVER`, owned by `USER_A`, with `USER_A`, `USER_B` and `USER_C` as
/// members
async fn server_ready(db: &Database) {
    insert_server(db, SERVER, USER_A).await;
    insert_members(db, SERVER, &[USER_A, USER_B, USER_C]).await;
}

async fn setup(db: &Database, slot_cap: u32) {
    server_ready(db).await;
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
            v2: None,
        }
        .build()
        .unwrap(),
        signature: signature(version),
        signer_device_id: DEVICE_A.to_string(),
        handover: None,
        authority: None,
    }
}

/// Protect `channel_id` (genesis list seats only A) under a fresh
/// entitlement, in `SERVER` (call `server_ready` once first)
async fn protected_in(db: &Database, channel_id: &str, slot_cap: u32) {
    protectable_in(db, channel_id, SERVER, slot_cap).await;
    db.protect_channel(channel_id, &submit_in(channel_id, 1, &[USER_A]), at(0))
        .await
        .unwrap();
}

/// An unprotected channel `channel_id` of `server_id` with a fresh
/// entitlement
async fn protectable_in(db: &Database, channel_id: &str, server_id: &str, slot_cap: u32) {
    let mut channel = text_channel(None);
    if let Channel::TextChannel { id, server, .. } = &mut channel {
        *id = channel_id.to_string();
        *server = server_id.to_string();
    }
    db.insert_channel(&channel).await.unwrap();
    let mut grant = entitlement(slot_cap);
    grant.channel_id = channel_id.to_string();
    grant.server_id = server_id.to_string();
    db.upsert_channel_entitlement(&grant, at(0)).await.unwrap();
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

fn is_growth_disabled(error: &revolt_result::Error) -> bool {
    matches!(&error.error_type, ErrorType::FeatureDisabled { feature } if feature == "protected_channels")
}

fn is_invalid_operation(error: &revolt_result::Error) -> bool {
    matches!(error.error_type, ErrorType::InvalidOperation)
}

/// `SeatListNamesRemovedUsers` naming exactly `expected` (C1)
fn is_removed_users(error: &revolt_result::Error, expected: &[&str]) -> bool {
    matches!(&error.error_type, ErrorType::SeatListNamesRemovedUsers { users } if users == expected)
}

/// A thread hanging off `parent`
fn thread(id: &str, parent: &str) -> Channel {
    serde_json::from_value(serde_json::json!({
        "channel_type": "Thread",
        "_id": id,
        "server": SERVER,
        "parent_channel": parent,
        "name": "thread",
        "creator": USER_B,
    }))
    .unwrap()
}

/// Server ownership transfer at the database level: `server_edit`'s
/// unconditional owner write (decision 14 (W2)), raw on Mongo
async fn transfer_owner(db: &Database, server_id: &str, owner: &str) {
    match db {
        Database::Reference(reference) => {
            reference
                .servers
                .lock()
                .await
                .get_mut(server_id)
                .expect("server")
                .owner = owner.to_string();
        }
        #[cfg(feature = "mongodb")]
        Database::MongoDb(mongo) => {
            let result = mongo
                .col::<bson::Document>("servers")
                .update_one(
                    doc! { "_id": server_id },
                    doc! { "$set": { "owner": owner } },
                )
                .await
                .unwrap();
            assert_eq!(result.matched_count, 1);
        }
    }
}

/// Mongo's `txn_serial` of every document a protect or seat PUT of
/// `CHANNEL` can write (`None`: never claimed); empty under REFERENCE,
/// which has no such counter
async fn write_counters(db: &Database, group_id: &str) -> Vec<Option<i64>> {
    match db {
        Database::Reference(_) => vec![],
        #[cfg(feature = "mongodb")]
        Database::MongoDb(mongo) => {
            let documents = [
                ("mls_groups", doc! { "_id": group_id }),
                ("servers", doc! { "_id": SERVER }),
                (
                    "server_members",
                    doc! { "_id.server": SERVER, "_id.user": USER_A },
                ),
                (
                    "server_members",
                    doc! { "_id.server": SERVER, "_id.user": USER_B },
                ),
                ("channel_entitlements", doc! { "channel_id": CHANNEL }),
                ("channel_seat_lists", doc! { "_id": CHANNEL }),
                ("channels", doc! { "_id": CHANNEL }),
            ];
            let mut counters = Vec::new();
            for (collection, filter) in documents {
                let row = mongo
                    .col::<bson::Document>(collection)
                    .find_one(filter)
                    .await
                    .unwrap()
                    .expect("document");
                counters.push(row.get_i64("txn_serial").ok());
            }
            counters
        }
    }
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
        v2: None,
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
        authority: None,
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

#[test]
fn handover_body_parses_the_5_4_vector() {
    let parsed = HandoverBody::parse(VECTOR_HANDOVER_BODY).unwrap();
    assert_eq!(
        parsed,
        HandoverBody {
            channel_id: CHANNEL.to_string(),
            from_user_id: USER_A.to_string(),
            from_device_id: DEVICE_A.to_string(),
            from_identity_key: OWNER_IDENTITY_KEY.to_string(),
            to_user_id: USER_A.to_string(),
            to_device_id: DEVICE_A2.to_string(),
            to_identity_key: NEW_OWNER_IDENTITY_KEY.to_string(),
            issued_at: 1_790_812_800_000,
        }
    );
}

#[test]
fn handover_body_refuses_every_single_field_corruption() {
    let issued = "issued_at:1790812800000";
    let from_device = format!("from_device_id:{DEVICE_A}");
    let to_device = format!("to_device_id:{DEVICE_A2}");
    // Last b64 char of a 32-byte key carries 2 padding bits; `g` has them 0
    let non_canonical_key = format!("{}h", &OWNER_IDENTITY_KEY[..42]);

    let corrupt = [
        // Line count: a trailing LF, an extra line, a missing line
        format!("{VECTOR_HANDOVER_BODY}\n"),
        format!("{VECTOR_HANDOVER_BODY}\nextra:1"),
        VECTOR_HANDOVER_BODY.replace("\nv:1", ""),
        // Context and format version
        VECTOR_HANDOVER_BODY.replace("sloga-owner-handover-v1", "sloga-owner-handover-v2"),
        VECTOR_HANDOVER_BODY.replace("sloga-owner-handover-v1", "sloga-seat-list-v1"),
        VECTOR_HANDOVER_BODY.replace("\nv:1\n", "\nv:2\n"),
        // issued_at: above 2^53 - 1, and non-canonical decimals
        VECTOR_HANDOVER_BODY.replace(issued, "issued_at:9007199254740992"),
        VECTOR_HANDOVER_BODY.replace(issued, "issued_at:01790812800000"),
        VECTOR_HANDOVER_BODY.replace(issued, "issued_at:+1790812800000"),
        VECTOR_HANDOVER_BODY.replace(issued, "issued_at:"),
        // CR
        VECTOR_HANDOVER_BODY.replacen('\n', "\r\n", 1),
        // Ids out of charset
        VECTOR_HANDOVER_BODY.replace(CHANNEL, &CHANNEL.to_lowercase()),
        VECTOR_HANDOVER_BODY.replace(
            &from_device,
            &format!("from_device_id:{}", DEVICE_A.to_uppercase()),
        ),
        VECTOR_HANDOVER_BODY.replace(&to_device, &format!("{to_device}0")),
        // Keys: padding, the URL-safe alphabet, non-canonical trailing bits
        VECTOR_HANDOVER_BODY.replace(OWNER_IDENTITY_KEY, &format!("{OWNER_IDENTITY_KEY}=")),
        VECTOR_HANDOVER_BODY.replace(
            NEW_OWNER_IDENTITY_KEY,
            &NEW_OWNER_IDENTITY_KEY.replace('/', "_"),
        ),
        VECTOR_HANDOVER_BODY.replace(OWNER_IDENTITY_KEY, &non_canonical_key),
        // Labels and field order
        VECTOR_HANDOVER_BODY.replace("to_user_id:", "to_user:"),
        VECTOR_HANDOVER_BODY.replace("from_user_id:", "from_user_id: "),
        VECTOR_HANDOVER_BODY
            .replace(&from_device, "SWAP")
            .replace(&to_device, &from_device)
            .replace("SWAP", &to_device),
    ];

    for (index, body) in corrupt.iter().enumerate() {
        assert_ne!(
            body, VECTOR_HANDOVER_BODY,
            "corruption {index} changed nothing"
        );
        let result = HandoverBody::parse(body);
        assert!(
            result.as_ref().is_err_and(is_failed_validation),
            "corruption {index} was accepted: {body:?}"
        );
    }

    // The bound is inclusive
    let at_bound =
        HandoverBody::parse(&VECTOR_HANDOVER_BODY.replace(issued, "issued_at:9007199254740991"))
            .unwrap();
    assert_eq!(at_bound.issued_at, 9_007_199_254_740_991);
    assert!(HandoverBody::parse(&VECTOR_HANDOVER_BODY.replace(issued, "issued_at:0")).is_ok());

    // A cross-user link is format-valid; refusing it is an S1 trust rule
    // (4.6), not a parse rule
    let cross_user = HandoverBody::parse(&VECTOR_HANDOVER_BODY.replace(
        &format!("to_user_id:{USER_A}"),
        &format!("to_user_id:{USER_B}"),
    ))
    .unwrap();
    assert_eq!(cross_user.to_user_id, USER_B);
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

        // Protect is one-shot: another genesis list is refused. (The
        // byte-identical retry is the N3 stored success, covered by
        // `genesis_reprotect_is_the_stored_success_and_writes_nothing`.)
        let mut other_genesis = submit(1, &[USER_A]);
        other_genesis.body = body_with(1, 1_790_812_800_001, &[USER_A]);
        let error = db
            .protect_channel(CHANNEL, &other_genesis, at(0))
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::InvalidOperation));

        // Strictly stored + 1
        for version in [3, 4, 1_000] {
            let error = db
                .put_seat_list(CHANNEL, &submit(version, &[USER_A, USER_B]), true, at(0))
                .await
                .unwrap_err();
            assert!(is_failed_validation(&error), "version {version}");
        }

        // A different body at the stored version is equivocation
        let mut other_v1 = submit(1, &[USER_A]);
        other_v1.body = body_with(1, 1_790_812_800_001, &[USER_A]);
        let error = db
            .put_seat_list(CHANNEL, &other_v1, true, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        // ... and so is the same body under a different signature
        let mut resigned_v1 = submit(1, &[USER_A]);
        resigned_v1.signature = signature(40);
        let error = db
            .put_seat_list(CHANNEL, &resigned_v1, true, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        let outcome = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), true, at(0))
            .await
            .unwrap();
        assert!(!outcome.unchanged);
        assert_eq!(outcome.claimed, vec![USER_B]);
        assert_eq!(outcome.list.version, 2);

        // Byte-identical re-PUT: stored success, no side effects
        let seats_before = db.fetch_channel_seats(CHANNEL).await.unwrap();
        let again = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), true, at(1))
            .await
            .unwrap();
        assert!(again.unchanged);
        assert!(again.claimed.is_empty() && again.released.is_empty());
        assert_eq!(again.list, outcome.list);
        assert_eq!(db.fetch_channel_seats(CHANNEL).await.unwrap(), seats_before);

        // A different list at version 2 is refused
        let error = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_C]), true, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        // The route channel and the declared signer device must match the body
        let mut wrong_device = submit(3, &[USER_A]);
        wrong_device.signer_device_id = DEVICE_A2.to_string();
        let error = db
            .put_seat_list(CHANNEL, &wrong_device, true, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));
        let error = db
            .put_seat_list(
                "01J9Z3K4M5N6P7Q8R9S0T1V2W4",
                &submit(3, &[USER_A]),
                true,
                at(0),
            )
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
        server_ready(&db).await;
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
        server_ready(&db).await;
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
        db.put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), true, at(0))
            .await
            .unwrap();

        let outcome = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A]), true, at(0))
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
            .put_seat_list(CHANNEL, &submit(4, &[USER_A, USER_C]), true, at(1))
            .await
            .unwrap_err();
        assert!(is_seat_cap(&error, 2));

        // Re-seating the cooling user reactivates the row, no new slot
        let outcome = db
            .put_seat_list(CHANNEL, &submit(4, &[USER_A, USER_B]), true, at(1))
            .await
            .unwrap();
        assert_eq!(outcome.claimed, vec![USER_B]);
        let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
        let seat_b = seats.iter().find(|seat| seat.user_id == USER_B).unwrap();
        assert!(seat_b.is_active());
        assert_eq!(seat_b.seated_at, at(1));
        assert_eq!(seats.len(), 2);

        // Release again at day 1: cooling until day 15
        db.put_seat_list(CHANNEL, &submit(5, &[USER_A]), true, at(1))
            .await
            .unwrap();

        // Day 14 is still inside the cooldown
        let error = db
            .put_seat_list(CHANNEL, &submit(6, &[USER_A, USER_C]), true, at(14))
            .await
            .unwrap_err();
        assert!(is_seat_cap(&error, 2));

        // A removal-only list is never refused by the cap (7.1)
        // (here: the same seats, so nothing is claimed)
        db.put_seat_list(CHANNEL, &submit(6, &[USER_A]), true, at(14))
            .await
            .unwrap();

        // Day 16: B's cooldown is over and its slot is free
        let outcome = db
            .put_seat_list(CHANNEL, &submit(7, &[USER_A, USER_C]), true, at(16))
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
        let racers: Vec<String> = (100..108).chain(200..208).map(numbered_user).collect();
        let racers: Vec<&str> = racers.iter().map(String::as_str).collect();
        insert_members(&db, SERVER, &racers).await;

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
                    true,
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
                    authority: None,
                };
                db.put_seat_list(CHANNEL, &submission, true, at(0)).await
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
            .put_seat_list(CHANNEL, &submit(2, &[USER_A]), true, at(1))
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
            .put_seat_list(CHANNEL, &submit(2, &[USER_A]), true, at(2))
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
            .put_seat_list(CHANNEL, &submit(3, &[USER_A]), true, at(2))
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
        db.put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), true, at(0))
            .await
            .unwrap();

        // The signer device's leaf is gone (rejoin case)
        set_group_members(&db, &group.id, vec![device(USER_B, DEVICE_B)]).await;

        // 5b refuses a NEW list from a signer without a leaf
        let error = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A]), true, at(1))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        // ... but the lost-response retry of the stored list still succeeds
        let again = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), true, at(1))
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
            let outcome = db
                .put_seat_list(CHANNEL, &submission, true, at(0))
                .await
                .unwrap();
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
        let error = db
            .put_seat_list(CHANNEL, &over, true, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error));

        // Without a handover the list still advances; the chain is kept
        let outcome = db
            .put_seat_list(CHANNEL, &submit(next, &[USER_A]), true, at(0))
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
            .put_seat_list(CHANNEL, &submit(2, &[USER_A]), true, at(3))
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

/// Design 7.5 with C7 (W2 audit): the cascade deletes the channel's Text
/// group rows, the closed one as well as the open one, with their join
/// intents; another channel's group is untouched. Control: today's close
/// instead of the delete (the rows are still found).
#[tokio::test]
async fn delete_cascade_removes_the_protected_channel_data() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);
        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();
        let first = text_group(0xdd, &owner, 0);
        db.create_text_mls_group(&first, None).await.unwrap();
        let successor = text_group(0xde, &owner, 1);
        db.create_text_mls_group(&successor, Some(&first.id))
            .await
            .unwrap();
        assert!(!db.fetch_mls_group(&first.id).await.unwrap().open);
        let joiner = device(USER_B, DEVICE_B);
        db.upsert_mls_join_intent(&crate::MlsJoinIntent {
            id: crate::MlsJoinIntent::composite_id(
                &successor.id,
                &joiner.user_id,
                &joiner.device_id,
            ),
            group_id: successor.id.clone(),
            user_id: joiner.user_id,
            device_id: joiner.device_id,
            key_package_ref: "cmVm".to_string(),
            signature: signature(1),
            created_at: at(0),
            generation: None,
            issued_at: None,
        })
        .await
        .unwrap();
        let bystander = call_group(&"df".repeat(32), &call_channel(400));
        db.create_mls_group(&bystander, None).await.unwrap();

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
        for (case, group_id) in [("closed", &first.id), ("open", &successor.id)] {
            let result = db.fetch_mls_group(group_id).await;
            assert!(
                matches!(&result, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
                "the {case} Text group row survived: {result:?}"
            );
        }
        assert!(db
            .fetch_mls_join_intents_for_group(&successor.id)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            db.fetch_mls_group(&bystander.id).await.unwrap().kind,
            MlsGroupKind::Call
        );
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
        server_ready(&db).await;
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
                db.put_seat_list(&channel_id, &next, true, at(0))
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
        server_ready(&db).await;
        for iteration in 0..RACE_ITERATIONS {
            let channel_id = race_channel(1_000 + iteration);
            protected_in(&db, &channel_id, 3).await;

            // Lower the cap to the 1 seat in use while a PUT claims a 2nd
            let mut lowered = entitlement(1);
            lowered.channel_id = channel_id.clone();
            let claim = submit_in(&channel_id, 2, &[USER_A, USER_B]);
            let (granted, put) = tokio::join!(
                db.upsert_channel_entitlement(&lowered, at(0)),
                db.put_seat_list(&channel_id, &claim, true, at(0))
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
            removed_reasons: vec![],
            welcome: None,
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
        server_ready(&db).await;
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
                    results.push(
                        db.put_seat_list(&channel_id, &submission, true, at(0))
                            .await,
                    );
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

// ---------------------------------------------------------------------------
// W2: N3, the growth flag, threads, and the decision 13 claims
// ---------------------------------------------------------------------------

#[tokio::test]
async fn genesis_reprotect_is_the_stored_success_and_writes_nothing() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let genesis = submit(1, &[USER_A, USER_B]);
        let landed = db.protect_channel(CHANNEL, &genesis, at(0)).await.unwrap();
        assert!(!landed.unchanged);

        // The owner's device opens the Text group right after protect (6.3),
        // so a retry that wrote anything would touch it too
        let group = text_group(0xee, &device(USER_A, DEVICE_A), 0);
        db.create_text_mls_group(&group, None).await.unwrap();

        let list_before = db.fetch_seat_list(CHANNEL).await.unwrap();
        let seats_before = db.fetch_channel_seats(CHANNEL).await.unwrap();
        let group_before = db.fetch_mls_group(&group.id).await.unwrap();
        let counters_before = write_counters(&db, &group.id).await;

        // The landed protect made its own preconditions false (the channel
        // is protected); the identical retry is still the stored success
        let again = db.protect_channel(CHANNEL, &genesis, at(5)).await.unwrap();
        assert!(again.unchanged);
        assert_eq!(again.list, landed.list);
        assert!(again.claimed.is_empty());
        assert!(again.released.is_empty());
        assert!(again.pending_removals_added.is_empty());

        // ... and it wrote nothing at all
        assert_eq!(db.fetch_seat_list(CHANNEL).await.unwrap(), list_before);
        assert_eq!(db.fetch_channel_seats(CHANNEL).await.unwrap(), seats_before);
        assert_eq!(db.fetch_mls_group(&group.id).await.unwrap(), group_before);
        assert_eq!(
            write_counters(&db, &group.id).await,
            counters_before,
            "the retry wrote a document"
        );
        assert!(db.fetch_channel(CHANNEL).await.unwrap().is_protected());

        // A different genesis body, or the same body re-signed, is refused
        let mut other = genesis.clone();
        other.body = body_with(1, 1_790_812_800_001, &[USER_A, USER_B]);
        let error = db
            .protect_channel(CHANNEL, &other, at(5))
            .await
            .unwrap_err();
        assert!(is_invalid_operation(&error), "{error:?}");
        let mut resigned = genesis.clone();
        resigned.signature = signature(41);
        let error = db
            .protect_channel(CHANNEL, &resigned, at(5))
            .await
            .unwrap_err();
        assert!(is_invalid_operation(&error), "{error:?}");

        // Once the stored list is past version 1, the genesis retry is refused
        db.put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), true, at(1))
            .await
            .unwrap();
        let error = db
            .protect_channel(CHANNEL, &genesis, at(5))
            .await
            .unwrap_err();
        assert!(is_invalid_operation(&error), "{error:?}");
    });
}

#[tokio::test]
async fn genesis_reprotect_is_not_answered_once_the_signer_lost_the_server() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let genesis = submit(1, &[USER_A]);
        db.protect_channel(CHANNEL, &genesis, at(0)).await.unwrap();

        transfer_owner(&db, SERVER, USER_B).await;
        let error = db
            .protect_channel(CHANNEL, &genesis, at(1))
            .await
            .unwrap_err();
        assert!(is_invalid_operation(&error), "{error:?}");
    });
}

#[tokio::test]
async fn seat_claims_need_the_growth_flag_but_retries_and_removals_do_not() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();

        // Flag off: a new claim is refused and nothing is written
        let error = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B]), false, at(0))
            .await
            .unwrap_err();
        assert!(is_growth_disabled(&error), "{error:?}");
        assert_eq!(
            db.fetch_seat_list(CHANNEL).await.unwrap().unwrap().version,
            1
        );
        assert_eq!(db.fetch_channel_seats(CHANNEL).await.unwrap().len(), 1);

        // Flag on: B and C are seated
        let seated = submit(2, &[USER_A, USER_B, USER_C]);
        let outcome = db
            .put_seat_list(CHANNEL, &seated, true, at(0))
            .await
            .unwrap();
        assert_eq!(outcome.claimed, vec![USER_B, USER_C]);

        // C is removed from the server: its seat is released and cools
        db.release_channel_seats_for_user(USER_C, Some(SERVER), at(1))
            .await
            .unwrap();

        // Flag off: the byte-identical retry of the list that landed still
        // succeeds, although applying it again would reactivate C's seat
        let again = db
            .put_seat_list(CHANNEL, &seated, false, at(1))
            .await
            .unwrap();
        assert!(again.unchanged, "{again:?}");

        // C1 (W2 audit): a list that still names C, whom the server removed
        // since v2, is refused before the flag is even looked at
        let error = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A, USER_B, USER_C]), false, at(1))
            .await
            .unwrap_err();
        assert!(is_removed_users(&error, &[USER_C]), "{error:?}");

        // Flag off: a removal-only list lands
        let outcome = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A]), false, at(2))
            .await
            .unwrap();
        assert_eq!(outcome.released, vec![USER_B]);
        assert!(outcome.claimed.is_empty());

        // Flag off: reactivating a cooling seat is a claim (B's, which the
        // owner's v3 released)
        let error = db
            .put_seat_list(CHANNEL, &submit(4, &[USER_A, USER_B]), false, at(2))
            .await
            .unwrap_err();
        assert!(is_growth_disabled(&error), "{error:?}");

        // Flag off: a `device_cap`-only list lands
        let capped = SeatListSubmission {
            body: SeatListBody {
                channel_id: CHANNEL.to_string(),
                version: 4,
                device_cap: 2,
                issued_at: 1_790_812_800_000,
                signer_user_id: USER_A.to_string(),
                signer_device_id: DEVICE_A.to_string(),
                seats: vec![USER_A.to_string()],
                v2: None,
            }
            .build()
            .unwrap(),
            signature: signature(4),
            signer_device_id: DEVICE_A.to_string(),
            handover: None,
            authority: None,
        };
        let outcome = db
            .put_seat_list(CHANNEL, &capped, false, at(2))
            .await
            .unwrap();
        assert!(!outcome.unchanged);
        assert!(outcome.claimed.is_empty() && outcome.released.is_empty());
        assert_eq!(outcome.list.version, 4);

        let active: Vec<String> = db
            .fetch_channel_seats(CHANNEL)
            .await
            .unwrap()
            .into_iter()
            .filter(|seat| seat.is_active())
            .map(|seat| seat.user_id)
            .collect();
        assert_eq!(active, vec![USER_A]);
    });
}

#[tokio::test]
async fn protect_refuses_a_channel_with_threads() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        db.insert_channel(&thread("01J9Z3K4M5N6P7Q8R9S0T1V2X1", CHANNEL))
            .await
            .unwrap();

        let error = db
            .protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap_err();
        assert!(is_invalid_operation(&error), "{error:?}");
        assert!(db.fetch_seat_list(CHANNEL).await.unwrap().is_none());
        assert!(db.fetch_channel_seats(CHANNEL).await.unwrap().is_empty());
        assert!(!db.fetch_channel(CHANNEL).await.unwrap().is_protected());

        // A thread of ANOTHER channel does not count
        protected_in(&db, &race_channel(3_000), 10).await;
        assert!(db
            .fetch_channel(&race_channel(3_000))
            .await
            .unwrap()
            .is_protected());
    });
}

#[tokio::test]
async fn protect_needs_the_owner_and_every_claim_needs_a_member() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let stranger = numbered_user(900);

        // A list signed by a member who does not own the server
        let by_member = SeatListSubmission {
            body: SeatListBody {
                channel_id: CHANNEL.to_string(),
                version: 1,
                device_cap: 5,
                issued_at: 1_790_812_800_000,
                signer_user_id: USER_B.to_string(),
                signer_device_id: DEVICE_B.to_string(),
                seats: vec![USER_B.to_string()],
                v2: None,
            }
            .build()
            .unwrap(),
            signature: signature(1),
            signer_device_id: DEVICE_B.to_string(),
            handover: None,
            authority: None,
        };
        let error = db
            .protect_channel(CHANNEL, &by_member, at(0))
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::NotOwner), "{error:?}");

        // A genesis list seating a non-member
        let error = db
            .protect_channel(CHANNEL, &submit(1, &[USER_A, stranger.as_str()]), at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error), "{error:?}");
        assert!(db.fetch_seat_list(CHANNEL).await.unwrap().is_none());
        assert!(db.fetch_channel_seats(CHANNEL).await.unwrap().is_empty());
        assert!(!db.fetch_channel(CHANNEL).await.unwrap().is_protected());

        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_C]), at(0))
            .await
            .unwrap();

        // A PUT seating a non-member, or a member who has since left
        let error = db
            .put_seat_list(
                CHANNEL,
                &submit(2, &[USER_A, USER_C, stranger.as_str()]),
                true,
                at(0),
            )
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error), "{error:?}");
        db.soft_delete_member(&MemberCompositeKey {
            server: SERVER.to_string(),
            user: USER_B.to_string(),
        })
        .await
        .unwrap();
        let error = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B, USER_C]), true, at(0))
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error), "{error:?}");
        assert_eq!(
            db.fetch_seat_list(CHANNEL).await.unwrap().unwrap().version,
            1
        );

        // Only NEW claims are checked: C leaves while still seated, and a
        // list that keeps C seated still lands
        db.soft_delete_member(&MemberCompositeKey {
            server: SERVER.to_string(),
            user: USER_C.to_string(),
        })
        .await
        .unwrap();
        db.put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_C]), true, at(0))
            .await
            .unwrap();
    });
}

// ---------------------------------------------------------------------------
// C1 (W2 audit): a list still naming a user the server removed is refused
// ---------------------------------------------------------------------------

/// C1 (W2 audit; decision 2, confirmed by the user 2026-10-04: a removed or
/// re-invited member is not re-seated until the owner re-seats them). B is
/// kicked and rejoins; the owner's client still names B, so its next list
/// (adding C) would reactivate B's cooling seat with no dialog. That list
/// is refused with B's id and nothing is written, with the growth flag on or
/// off. The list without B lands; only then does a list naming B again
/// land, as an ordinary claim, and only with the flag on. The stored list's
/// byte-identical retry is unaffected. Control: the planner's
/// `seat_list_removed_users` check removed (the first PUT lands and B is
/// seated again).
#[tokio::test]
async fn a_list_still_naming_a_removed_user_is_refused_until_one_without_them_lands() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B]), at(0))
            .await
            .unwrap();
        let genesis = db.fetch_seat_list(CHANNEL).await.unwrap().unwrap();

        // B is kicked, then rejoins by invite
        kick(&db, USER_B).await;
        insert_members(&db, SERVER, &[USER_B]).await;

        // The stored list's retry is still the stored success
        let again = db
            .put_seat_list(CHANNEL, &submit(1, &[USER_A, USER_B]), true, at(1))
            .await
            .unwrap();
        assert!(again.unchanged, "{again:?}");

        for allow_claims in [true, false] {
            let error = db
                .put_seat_list(
                    CHANNEL,
                    &submit(2, &[USER_A, USER_B, USER_C]),
                    allow_claims,
                    at(1),
                )
                .await
                .unwrap_err();
            assert!(
                is_removed_users(&error, &[USER_B]),
                "growth {allow_claims}: {error:?}"
            );
        }
        assert_eq!(
            db.fetch_seat_list(CHANNEL).await.unwrap(),
            Some(genesis),
            "a refused list writes nothing"
        );
        let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
        assert!(
            seats.iter().all(|seat| seat.user_id != USER_C),
            "C was claimed: {seats:?}"
        );
        assert!(
            seats
                .iter()
                .any(|seat| seat.user_id == USER_B && !seat.is_active()),
            "B was seated again: {seats:?}"
        );

        // The list without B lands
        let outcome = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_C]), true, at(2))
            .await
            .unwrap();
        assert_eq!(outcome.claimed, vec![USER_C]);
        assert!(outcome.released.is_empty(), "{outcome:?}");

        // Only now is B's re-seat an ordinary claim: refused with the
        // growth flag off, landed with it on
        let error = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A, USER_B, USER_C]), false, at(3))
            .await
            .unwrap_err();
        assert!(is_growth_disabled(&error), "{error:?}");
        let outcome = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A, USER_B, USER_C]), true, at(3))
            .await
            .unwrap();
        assert_eq!(outcome.claimed, vec![USER_B]);

        let active: Vec<String> = db
            .fetch_channel_seats(CHANNEL)
            .await
            .unwrap()
            .into_iter()
            .filter(|seat| seat.is_active())
            .map(|seat| seat.user_id)
            .collect();
        assert_eq!(active, vec![USER_A, USER_B, USER_C]);
    });
}

/// C1: which removals refuse a later list naming the user. The owner's own
/// unseat does not: the list that released B no longer names B, so a list
/// naming B again is an ordinary claim. A release by the server-forced
/// primitive does, whatever drove it: kick, ban, leaving the server of
/// one's own accord and account deletion all run
/// `release_channel_seats_for_user` (6.3), which carries no reason, so a
/// user who LEFT and rejoined is refused like a kicked one (fail closed:
/// their devices are pending removal exactly as after a kick, and the
/// owner's client still lists them). An expired cooldown changes nothing.
/// The signer is never reported, or a forced release of the owner's own
/// seat would wedge every later list.
#[tokio::test]
async fn only_a_server_removal_refuses_a_list_naming_the_user_again() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B, USER_C]), at(0))
            .await
            .unwrap();

        // The owner unseats B, then seats B again
        let outcome = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_C]), true, at(1))
            .await
            .unwrap();
        assert_eq!(outcome.released, vec![USER_B]);
        let outcome = db
            .put_seat_list(CHANNEL, &submit(3, &[USER_A, USER_B, USER_C]), true, at(2))
            .await
            .unwrap();
        assert_eq!(outcome.claimed, vec![USER_B]);

        // C leaves the server (the leave runs the forced release) and is a
        // member again by the next list, whose time is past C's cooldown
        db.release_channel_seats_for_user(USER_C, Some(SERVER), at(3))
            .await
            .unwrap();
        let expired = at(3 + SEAT_COOLDOWN_DAYS + 1);
        let error = db
            .put_seat_list(
                CHANNEL,
                &submit(4, &[USER_A, USER_B, USER_C]),
                true,
                expired,
            )
            .await
            .unwrap_err();
        assert!(is_removed_users(&error, &[USER_C]), "{error:?}");

        // A forced release of the signer's own seat never refuses its lists
        db.release_channel_seats_for_user(USER_A, Some(SERVER), expired)
            .await
            .unwrap();
        let outcome = db
            .put_seat_list(CHANNEL, &submit(4, &[USER_A, USER_B]), true, expired)
            .await
            .unwrap();
        assert_eq!(outcome.claimed, vec![USER_A]);
    });
}

/// C1, pure: the rule reads the rows, never a release time. A seat released
/// BEFORE the stored list's `updated_at` while that list names its user is
/// still reported: that is a removal that committed between a seat PUT's
/// snapshot and its commit (the PUT writes no row of a user it keeps). A
/// released seat whose user the stored list does not name (the owner's own
/// unseat), an active seat and the signer are not. With no stored list
/// (genesis) nothing is; a stored body that no longer parses fails closed.
#[test]
fn removed_users_are_read_from_the_rows_not_from_release_times() {
    let row = |user_id: &str, released: Option<i64>| ChannelSeat {
        id: ChannelSeat::composite_id(CHANNEL, user_id),
        channel_id: CHANNEL.to_string(),
        user_id: user_id.to_string(),
        seated_at: at(0),
        released_at: released.map(at),
        cooldown_until: released.map(|days| at(days + SEAT_COOLDOWN_DAYS)),
        release_cause: None,
        keys_received_at: None,
    };
    let unseated = numbered_user(901);
    let stored = SeatList {
        id: CHANNEL.to_string(),
        version: 2,
        body: body_with(2, 1_790_812_800_000, &[USER_A, USER_B, USER_C]),
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        signature: signature(2),
        handovers: vec![],
        updated_at: at(5),
        authority: None,
    };
    let seats = vec![
        row(USER_A, Some(1)),
        row(USER_B, Some(1)),
        row(USER_C, None),
        row(&unseated, Some(1)),
    ];
    let next = SeatListBody::parse(&body_with(
        3,
        1_790_812_800_000,
        &[USER_A, USER_B, USER_C, unseated.as_str()],
    ))
    .unwrap();

    assert_eq!(
        seat_list_removed_users(&next, Some(&stored), &seats).unwrap(),
        vec![USER_B]
    );
    assert!(seat_list_removed_users(&next, None, &seats)
        .unwrap()
        .is_empty());

    let mut corrupt = stored.clone();
    corrupt.body = "garbage".to_string();
    assert!(seat_list_removed_users(&next, Some(&corrupt), &seats).is_err());
}

/// C1 with re-review L3, pure: a user the stored list still names who has
/// NO seat row is reported (a landed list has an active row for every user
/// it names, so a missing one was removed); only an active row clears a
/// listed user. Control: the earlier `any(!is_active)` filter.
#[test]
fn a_listed_user_with_no_seat_row_is_reported_as_removed() {
    let rowless = numbered_user(902);
    let stored = SeatList {
        id: CHANNEL.to_string(),
        version: 2,
        body: body_with(2, 1_790_812_800_000, &[USER_A, USER_B, rowless.as_str()]),
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        signature: signature(2),
        handovers: vec![],
        updated_at: at(5),
        authority: None,
    };
    let active = |user_id: &str| ChannelSeat {
        id: ChannelSeat::composite_id(CHANNEL, user_id),
        channel_id: CHANNEL.to_string(),
        user_id: user_id.to_string(),
        seated_at: at(0),
        released_at: None,
        cooldown_until: None,
        release_cause: None,
        keys_received_at: None,
    };
    // The signer has no row either: still never reported
    let seats = vec![active(USER_B)];
    let next = SeatListBody::parse(&body_with(
        3,
        1_790_812_800_000,
        &[USER_A, USER_B, rowless.as_str()],
    ))
    .unwrap();

    assert_eq!(
        seat_list_removed_users(&next, Some(&stored), &seats).unwrap(),
        vec![rowless]
    );
}

/// C1 with re-review L3: B is kicked and B's seat row is then deleted
/// outright (what a future released-seat sweep would do); B rejoins. The
/// owner's list still naming B is refused, not answered as a fresh claim of
/// a user with no row. Raw delete on both drivers. Control: the earlier
/// `any(!is_active)` filter (the list lands and seats B again).
#[tokio::test]
async fn a_removed_user_whose_seat_row_is_gone_is_still_refused() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B]), at(0))
            .await
            .unwrap();
        kick(&db, USER_B).await;

        let seat_id = ChannelSeat::composite_id(CHANNEL, USER_B);
        match &db {
            Database::Reference(reference) => {
                assert!(reference
                    .channel_seats
                    .lock()
                    .await
                    .remove(&seat_id)
                    .is_some());
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                let result = mongo
                    .col::<bson::Document>("channel_seats")
                    .delete_one(doc! { "_id": &seat_id })
                    .await
                    .unwrap();
                assert_eq!(result.deleted_count, 1);
            }
        }
        insert_members(&db, SERVER, &[USER_B]).await;
        assert!(db
            .fetch_channel_seats(CHANNEL)
            .await
            .unwrap()
            .iter()
            .all(|seat| seat.user_id != USER_B));

        let error = db
            .put_seat_list(CHANNEL, &submit(2, &[USER_A, USER_B, USER_C]), true, at(1))
            .await
            .unwrap_err();
        assert!(is_removed_users(&error, &[USER_B]), "{error:?}");
        assert_eq!(
            db.fetch_seat_list(CHANNEL).await.unwrap().unwrap().version,
            1
        );
        assert!(db
            .fetch_channel_seats(CHANNEL)
            .await
            .unwrap()
            .iter()
            .all(|seat| seat.user_id != USER_B && seat.user_id != USER_C));
    });
}

/// Rounds of each claim race below (every round uses fresh channels, and a
/// fresh user or server)
const CLAIM_RACE_ROUNDS: u32 = 10;

/// Back-to-back operations per round in the claim races. Each round's
/// stream straddles the one racing kick or transfer, so both of its
/// outcomes (landed before, refused after) occur without any pacing.
const CLAIM_RACE_STREAM: u32 = 8;

/// A kick at the database level, in the decision 11 (W2) order without the
/// thread loop and the events: the first release, the membership delete,
/// then the second release. Every step must succeed. Returns its window,
/// from the start of the first release to the end of the second.
async fn kick(db: &Database, user: &str) -> (Instant, Instant) {
    let started = Instant::now();
    db.release_channel_seats_for_user(user, Some(SERVER), at(0))
        .await
        .expect("first release");
    db.soft_delete_member(&MemberCompositeKey {
        server: SERVER.to_string(),
        user: user.to_string(),
    })
    .await
    .expect("membership delete");
    db.release_channel_seats_for_user(user, Some(SERVER), at(0))
        .await
        .expect("second release");
    (started, Instant::now())
}

/// Once a race with a kick has settled: `user` is not a member and holds no
/// active seat anywhere
async fn assert_kicked_and_unseated(db: &Database, user: &str, round: u32) {
    assert!(
        db.fetch_member(SERVER, user).await.is_err(),
        "round {round}: the kick did not remove the member"
    );
    let active = db
        .fetch_channel_seats_for_user(user)
        .await
        .unwrap()
        .into_iter()
        .filter(|seat| seat.is_active())
        .count();
    assert_eq!(
        active, 0,
        "round {round}: a non-member holds an active seat"
    );
}

/// Tally of a race's outcomes and timing (W2a audit WA#4, fix re-review
/// RR#3). Both outcomes occurring is not enough on its own: the round
/// alternation and the even-round start make it hold even when no claim
/// ever ran while the kick did. So under MONGODB the kick races also assert
/// that at least one claim operation OVERLAPPED the kick window (started
/// before the kick ended and ended after it started). REFERENCE keeps only
/// the outcome guard: its in-memory store does not yield inside an
/// operation and its locks serialize, so nothing there overlaps in time.
#[derive(Default)]
struct RaceTally {
    landed: u32,
    refused: u32,
    /// Rounds whose own stream saw both outcomes, i.e. the kick landed
    /// mid-stream (printed; REFERENCE never yields mid-stream)
    straddled: u32,
    /// Claim operations that overlapped their round's kick window
    overlapped: u32,
    /// Rounds with at least one such claim
    overlap_rounds: u32,
    /// (start, end) of each claim operation of one round's stream
    claims: Vec<(Instant, Instant)>,
}

impl RaceTally {
    /// Fold one round's stream into the run's tally, given that round's
    /// kick window
    fn add_round(&mut self, stream: RaceTally, kick: (Instant, Instant)) {
        let (kick_started, kick_ended) = kick;
        self.landed += stream.landed;
        self.refused += stream.refused;
        if stream.landed > 0 && stream.refused > 0 {
            self.straddled += 1;
        }
        let overlapped = stream
            .claims
            .iter()
            .filter(|(started, ended)| *started < kick_ended && *ended > kick_started)
            .count() as u32;
        self.overlapped += overlapped;
        if overlapped > 0 {
            self.overlap_rounds += 1;
        }
    }

    /// The guards, once every round ran (see the type docs). The overlap
    /// guard is checked first, so a run that never overlapped fails on it.
    fn assert_raced(&self, db: &Database, race: &str) {
        eprintln!(
            "{race}: {} claims landed, {} refused, {} of {CLAIM_RACE_ROUNDS} rounds saw both; \
             {} claims overlapped the kick, in {} of {CLAIM_RACE_ROUNDS} rounds",
            self.landed, self.refused, self.straddled, self.overlapped, self.overlap_rounds
        );
        if !matches!(db, Database::Reference(_)) {
            assert!(
                self.overlapped > 0,
                "{race}: no claim overlapped the kick in any round"
            );
        }
        assert!(
            self.landed > 0 && self.refused > 0,
            "{race}: one-sided race: {} claims landed, {} refused",
            self.landed,
            self.refused
        );
    }
}

#[tokio::test]
async fn seat_puts_racing_a_kick_never_seat_a_non_member() {
    database_test!(|db| async move {
        server_ready(&db).await;
        let mut tally = RaceTally::default();
        for round in 0..CLAIM_RACE_ROUNDS {
            let channel_id = race_channel(4_000 + round);
            let user = numbered_user(4_000 + round);
            insert_members(&db, SERVER, &[user.as_str()]).await;
            protected_in(&db, &channel_id, 10).await;

            // Back to back: seat the user, unseat, seat again ..., ending on
            // a seat attempt, while the kick runs once. No pacing.
            let stream = async {
                let mut tally = RaceTally::default();
                let mut version = 2;
                for step in 0..=CLAIM_RACE_STREAM {
                    let seats: &[&str] = if step % 2 == 0 {
                        &[USER_A, user.as_str()]
                    } else {
                        &[USER_A]
                    };
                    let list = submit_in(&channel_id, version, seats);
                    let started = Instant::now();
                    let put = db.put_seat_list(&channel_id, &list, true, at(0)).await;
                    if step % 2 == 0 {
                        tally.claims.push((started, Instant::now()));
                    }
                    match put {
                        Ok(_) => {
                            version += 1;
                            if step % 2 == 0 {
                                tally.landed += 1;
                            }
                        }
                        Err(error) => {
                            assert!(
                                step % 2 == 0 && is_failed_validation(&error),
                                "round {round} step {step}: {error:?}"
                            );
                            tally.refused += 1;
                        }
                    }
                }
                tally
            };
            let kicked = kick(&db, &user);
            let (stream, window) = if round % 2 == 0 {
                tokio::join!(stream, kicked)
            } else {
                let (window, stream) = tokio::join!(kicked, stream);
                (stream, window)
            };

            tally.add_round(stream, window);
            assert_kicked_and_unseated(&db, &user, round).await;
        }
        tally.assert_raced(&db, "seat PUT vs kick");
    });
}

#[tokio::test]
async fn protects_racing_a_kick_never_seat_a_non_member() {
    database_test!(|db| async move {
        server_ready(&db).await;
        let mut tally = RaceTally::default();
        for round in 0..CLAIM_RACE_ROUNDS {
            let user = numbered_user(5_000 + round);
            insert_members(&db, SERVER, &[user.as_str()]).await;
            let channels: Vec<String> = (0..CLAIM_RACE_STREAM)
                .map(|index| race_channel(10_000 + round * 100 + index))
                .collect();
            for channel_id in &channels {
                protectable_in(&db, channel_id, SERVER, 10).await;
            }

            // Back to back: protect each channel seating the user, while
            // the kick runs once. No pacing: the kick (three short writes)
            // beats most protects under MONGODB, so on even rounds it starts
            // once the first protect has returned (an event, not a timer)
            // and races the rest; on odd rounds it starts at once and is
            // polled first. That start alone makes both outcomes certain, so
            // the overlap guard (`RaceTally`) is what shows a race happened.
            let first_returned = tokio::sync::Notify::new();
            let stream = async {
                let mut tally = RaceTally::default();
                for channel_id in &channels {
                    let genesis = submit_in(channel_id, 1, &[USER_A, user.as_str()]);
                    let started = Instant::now();
                    let protected = db.protect_channel(channel_id, &genesis, at(0)).await;
                    tally.claims.push((started, Instant::now()));
                    first_returned.notify_one();
                    let flag = db.fetch_channel(channel_id).await.unwrap().is_protected();
                    match protected {
                        Ok(outcome) => {
                            assert!(outcome.claimed.contains(&user), "round {round}");
                            assert!(flag, "round {round}");
                            tally.landed += 1;
                        }
                        Err(error) => {
                            assert!(is_failed_validation(&error), "round {round}: {error:?}");
                            assert!(!flag, "round {round}");
                            tally.refused += 1;
                        }
                    }
                }
                tally
            };
            let kicked = async {
                if round % 2 == 0 {
                    first_returned.notified().await;
                }
                kick(&db, &user).await
            };
            let (stream, window) = if round % 2 == 0 {
                tokio::join!(stream, kicked)
            } else {
                let (window, stream) = tokio::join!(kicked, stream);
                (stream, window)
            };

            tally.add_round(stream, window);
            assert_kicked_and_unseated(&db, &user, round).await;
        }
        tally.assert_raced(&db, "protect vs kick");
    });
}

#[tokio::test]
async fn protects_racing_an_ownership_transfer_never_commit_for_a_non_owner() {
    database_test!(|db| async move {
        let mut tally = RaceTally::default();
        for round in 0..CLAIM_RACE_ROUNDS {
            let server_id = format!("01HZXSERVER{round:015}");
            insert_server(&db, &server_id, USER_A).await;
            insert_members(&db, &server_id, &[USER_A]).await;
            let channels: Vec<String> = (0..CLAIM_RACE_STREAM)
                .map(|index| race_channel(20_000 + round * 100 + index))
                .collect();
            for channel_id in &channels {
                protectable_in(&db, channel_id, &server_id, 10).await;
            }

            // Back to back: protect each channel, while the owner is
            // transferred once. Right after the transfer lands, read every
            // channel: a protect that commits later committed for a
            // non-owner. No pacing: the transfer (one write) would otherwise
            // always beat the first protect, so on even rounds it starts
            // once the first protect has returned (an event, not a timer)
            // and races the rest; on odd rounds it starts at once and is
            // polled first (REFERENCE never yields mid-stream, so the poll
            // order is what decides it there).
            let first_returned = tokio::sync::Notify::new();
            let stream = async {
                let mut outcomes = Vec::new();
                for channel_id in &channels {
                    let genesis = submit_in(channel_id, 1, &[USER_A]);
                    outcomes.push(db.protect_channel(channel_id, &genesis, at(0)).await);
                    first_returned.notify_one();
                }
                outcomes
            };
            let transfer = async {
                if round % 2 == 0 {
                    first_returned.notified().await;
                }
                transfer_owner(&db, &server_id, USER_B).await;
                let mut protected = Vec::new();
                for channel_id in &channels {
                    protected.push(db.fetch_channel(channel_id).await.unwrap().is_protected());
                }
                protected
            };
            let (outcomes, protected_after_transfer) = if round % 2 == 0 {
                tokio::join!(stream, transfer)
            } else {
                let (after, outcomes) = tokio::join!(transfer, stream);
                (outcomes, after)
            };

            for (index, outcome) in outcomes.into_iter().enumerate() {
                let channel_id = &channels[index];
                match outcome {
                    Ok(outcome) => {
                        assert!(!outcome.unchanged, "round {round} channel {index}");
                        // Protect may only commit while the signer owns the
                        // server, i.e. before the transfer landed
                        assert!(
                            protected_after_transfer[index],
                            "round {round} channel {index}: protect committed after the owner changed"
                        );
                        tally.landed += 1;
                    }
                    Err(error) => {
                        assert!(
                            matches!(error.error_type, ErrorType::NotOwner),
                            "round {round} channel {index}: {error:?}"
                        );
                        assert!(!db.fetch_channel(channel_id).await.unwrap().is_protected());
                        tally.refused += 1;
                    }
                }
            }
        }
        eprintln!(
            "protect vs transfer: {} protects landed, {} refused",
            tally.landed, tally.refused
        );
    });
}

/// A scoped release reads only the `channel_id` of the server's
/// entitlements (W2a audit WA#6), so an undecodable entitlement of ANOTHER
/// channel cannot fail it (and with it every join, kick, leave and ban in
/// the server). A row whose `channel_id` is unusable still fails it, with
/// nothing released. MONGODB only: the reference store cannot hold an
/// undecodable row. Mutation: the full `ChannelEntitlement` decode.
#[cfg(feature = "mongodb")]
#[tokio::test]
async fn a_corrupt_entitlement_of_another_channel_does_not_block_a_release() {
    database_test!(|db| async move {
        let Database::MongoDb(mongo) = &db else {
            return;
        };
        setup(&db, 10).await;
        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B, USER_C]), at(0))
            .await
            .unwrap();

        // `slot_cap` is not a number and most fields are missing, so every
        // typed read of the row fails
        let other = race_channel(6_000);
        mongo
            .col::<bson::Document>("channel_entitlements")
            .insert_one(doc! {
                "_id": "01HZXCORRUPTENTITLEMENT000",
                "channel_id": &other,
                "server_id": SERVER,
                "slot_cap": "ten",
            })
            .await
            .unwrap();
        assert!(
            mongo
                .col::<ChannelEntitlement>("channel_entitlements")
                .find_one(doc! { "channel_id": &other })
                .await
                .is_err(),
            "precondition: the corrupt entitlement does not decode"
        );

        assert_eq!(
            db.release_channel_seats_for_user(USER_B, Some(SERVER), at(1))
                .await
                .unwrap(),
            vec![CHANNEL]
        );
        let seats = db.fetch_channel_seats_for_user(USER_B).await.unwrap();
        assert_eq!(seats.len(), 1);
        assert_eq!(seats[0].released_at, Some(at(1)));

        // A row of the server without a usable `channel_id` cannot be
        // scoped, so it fails the release closed
        mongo
            .col::<bson::Document>("channel_entitlements")
            .insert_one(doc! {
                "_id": "01HZXCORRUPTENTITLEMENT001",
                "channel_id": 7,
                "server_id": SERVER,
            })
            .await
            .unwrap();
        let error = db
            .release_channel_seats_for_user(USER_C, Some(SERVER), at(1))
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error.error_type,
                ErrorType::DatabaseError { collection, .. } if collection == "channel_entitlements"
            ),
            "{error:?}"
        );
        let seats = db.fetch_channel_seats_for_user(USER_C).await.unwrap();
        assert_eq!(seats.len(), 1);
        assert!(seats[0].is_active(), "a failed release released nothing");
    });
}

/// C9 (W2 audit): the release decodes neither the seat nor the group
/// document (a `channel_id` projection, then `update_many` on the same
/// filter), so a seat row and a Text group carrying a field added later
/// (unknown) and a field no typed read decodes still release: the user can
/// still be kicked, banned and can join. The extra field alone would prove
/// nothing (serde skips unknown fields), so each row also carries an
/// undecodable `seated_at` / `member_added`. MONGODB only: the reference
/// store cannot hold such a row. Control: today's typed `find_all` of
/// `ChannelSeat` and `MlsGroup`.
#[cfg(feature = "mongodb")]
#[tokio::test]
async fn a_release_never_decodes_the_seat_or_group_rows() {
    database_test!(|db| async move {
        let Database::MongoDb(mongo) = &db else {
            return;
        };
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

        let seat_id = ChannelSeat::composite_id(CHANNEL, USER_B);
        for (collection, id, corrupt) in [
            ("channel_seats", seat_id.as_str(), "seated_at"),
            ("mls_groups", group.id.as_str(), "member_added"),
        ] {
            let mut set = doc! { "added_by_a_later_release": { "nested": true } };
            set.insert(corrupt, "not decodable");
            let result = mongo
                .col::<bson::Document>(collection)
                .update_one(doc! { "_id": id }, doc! { "$set": set })
                .await
                .unwrap();
            assert_eq!(result.modified_count, 1, "{collection}");
        }
        assert!(
            mongo
                .col::<ChannelSeat>("channel_seats")
                .find_one(doc! { "_id": &seat_id })
                .await
                .is_err(),
            "precondition: the seat row does not decode"
        );
        assert!(
            mongo
                .col::<MlsGroup>("mls_groups")
                .find_one(doc! { "_id": &group.id })
                .await
                .is_err(),
            "precondition: the group does not decode"
        );

        assert_eq!(
            db.release_channel_seats_for_user(USER_B, Some(SERVER), at(1))
                .await
                .unwrap(),
            vec![CHANNEL]
        );
        let millis = |time: Timestamp| {
            time.duration_since(Timestamp::UNIX_EPOCH)
                .whole_milliseconds() as i64
        };
        let seat = mongo
            .col::<bson::Document>("channel_seats")
            .find_one(doc! { "_id": &seat_id })
            .await
            .unwrap()
            .expect("the seat row");
        assert_eq!(seat.get_i64("released_at").ok(), Some(millis(at(1))));
        assert_eq!(
            seat.get_i64("cooldown_until").ok(),
            Some(millis(at(1 + SEAT_COOLDOWN_DAYS)))
        );
        let pending = |row: &bson::Document| -> Vec<String> {
            row.get_array("pending_removals")
                .unwrap()
                .iter()
                .map(|entry| {
                    entry
                        .as_document()
                        .and_then(|entry| entry.get_str("user_id").ok())
                        .unwrap()
                        .to_string()
                })
                .collect()
        };
        let stored = mongo
            .col::<bson::Document>("mls_groups")
            .find_one(doc! { "_id": &group.id })
            .await
            .unwrap()
            .expect("the group");
        assert_eq!(pending(&stored), vec![USER_B]);

        // Still idempotent: nothing left to release, no second entry
        assert!(db
            .release_channel_seats_for_user(USER_B, None, at(2))
            .await
            .unwrap()
            .is_empty());
        let stored = mongo
            .col::<bson::Document>("mls_groups")
            .find_one(doc! { "_id": &group.id })
            .await
            .unwrap()
            .expect("the group");
        assert_eq!(pending(&stored), vec![USER_B]);
    });
}

/// C9 (W2 audit), the closed side: with no row decoded, what still fails a
/// release (fail closed, in one transaction, so nothing is released) is a
/// write the database refuses, or a matched row whose `channel_id` is not a
/// string. Scoped (kick, ban, leave, join): a Text group of the server that
/// lists the user and whose `pending_removals` is not an array refuses the
/// `$push`. Unscoped (account deletion): a seat row of the user with an
/// Int32 `channel_id`. These are the triggers a test that needs a failing
/// release can use now that an undecodable `seated_at` releases. MONGODB
/// only.
#[cfg(feature = "mongodb")]
#[tokio::test]
async fn a_release_that_cannot_be_written_fails_closed_and_releases_nothing() {
    database_test!(|db| async move {
        let Database::MongoDb(mongo) = &db else {
            return;
        };
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);
        db.protect_channel(CHANNEL, &submit(1, &[USER_A, USER_B, USER_C]), at(0))
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
        let result = mongo
            .col::<bson::Document>("mls_groups")
            .update_one(
                doc! { "_id": &group.id },
                doc! { "$set": { "pending_removals": "not an array" } },
            )
            .await
            .unwrap();
        assert_eq!(result.modified_count, 1);

        let error = db
            .release_channel_seats_for_user(USER_B, Some(SERVER), at(1))
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error.error_type,
                ErrorType::DatabaseError { operation, collection }
                    if operation == "update_many" && collection == "mls_groups"
            ),
            "{error:?}"
        );
        let seats = db.fetch_channel_seats_for_user(USER_B).await.unwrap();
        assert!(seats[0].is_active(), "a failed release released nothing");

        // Unscoped: a seat row whose `channel_id` is an Int32
        mongo
            .col::<bson::Document>("channel_seats")
            .insert_one(doc! {
                "_id": "corrupt",
                "channel_id": 5_i32,
                "user_id": USER_C,
                "seated_at": 0_i64,
            })
            .await
            .unwrap();
        let error = db
            .release_channel_seats_for_user(USER_C, None, at(1))
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error.error_type,
                ErrorType::DatabaseError { operation, collection }
                    if operation == "find" && collection == "channel_seats"
            ),
            "{error:?}"
        );
        let seat = db
            .fetch_channel_seats(CHANNEL)
            .await
            .unwrap()
            .into_iter()
            .find(|seat| seat.user_id == USER_C)
            .expect("C's seat");
        assert!(seat.is_active(), "a failed release released nothing");
    });
}

/// C4 (W2 audit): the channel ids of a server's entitlements, sorted, and
/// only that server's. Under MONGODB they are read through a projection: an
/// entitlement row nothing else decodes still answers its `channel_id`, and
/// a row whose `channel_id` is not a string fails the read closed.
#[tokio::test]
async fn entitled_channel_ids_list_every_entitlement_of_the_server() {
    database_test!(|db| async move {
        server_ready(&db).await;
        let (second, first) = (race_channel(6_101), race_channel(6_100));
        protectable_in(&db, &second, SERVER, 10).await;
        protectable_in(&db, &first, SERVER, 10).await;
        protectable_in(&db, &race_channel(6_102), "01HZXOTHERSERVEROTHERSERVE", 10).await;

        assert_eq!(
            db.fetch_entitled_channel_ids(SERVER).await.unwrap(),
            vec![first.clone(), second.clone()]
        );
        assert!(db
            .fetch_entitled_channel_ids("01HZXNOSERVERNOSERVERNOSER")
            .await
            .unwrap()
            .is_empty());

        #[cfg(feature = "mongodb")]
        if let Database::MongoDb(mongo) = &db {
            let corrupt = race_channel(6_103);
            mongo
                .col::<bson::Document>("channel_entitlements")
                .insert_one(doc! {
                    "_id": "01HZXCORRUPTENTITLEMENT100",
                    "channel_id": &corrupt,
                    "server_id": SERVER,
                    "slot_cap": "ten",
                })
                .await
                .unwrap();
            assert_eq!(
                db.fetch_entitled_channel_ids(SERVER).await.unwrap(),
                vec![first.clone(), second.clone(), corrupt]
            );

            mongo
                .col::<bson::Document>("channel_entitlements")
                .insert_one(doc! {
                    "_id": "01HZXCORRUPTENTITLEMENT101",
                    "channel_id": 7,
                    "server_id": SERVER,
                })
                .await
                .unwrap();
            let error = db.fetch_entitled_channel_ids(SERVER).await.unwrap_err();
            assert!(
                matches!(
                    &error.error_type,
                    ErrorType::DatabaseError { collection, .. } if collection == "channel_entitlements"
                ),
                "{error:?}"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// M9 (b6 B47): a Call squat at a Text group's derived id is evicted
// ---------------------------------------------------------------------------

/// Section 5.5: the Text group ids of the 5.1 channel (`CHANNEL`)
const GROUP_ID_G0: &str = "4a4ba4afc6e6ea1c9f4a271f7eded44ea860fdb814e4e1377121e02635a715b5";
const GROUP_ID_G1: &str = "b4989a8d9b082e1668a726aa3303d3eb8b52688d340ca4dc1e0184f61fc67000";

/// Design 3.1, computed here independently of the drivers
fn derived_group_id(channel_id: &str, generation: u32) -> String {
    hex(&Sha256::digest(format!(
        "sloga-text-group-v1\n{channel_id}\n{generation}"
    )))
}

/// A distinct voice channel per squat (the database does not check it;
/// the Call route needs only call access there)
fn call_channel(n: u32) -> String {
    format!("01HZXVOICE{n:016}")
}

fn squatter() -> MlsMemberDevice {
    device(USER_C, DEVICE_B)
}

/// A Call group the squatter registers at `group_id`
fn call_group(group_id: &str, call_channel: &str) -> MlsGroup {
    let squatter = squatter();
    MlsGroup {
        id: group_id.to_string(),
        channel_id: call_channel.to_string(),
        open: true,
        created_by: squatter.clone(),
        created_at: Timestamp::now_utc(),
        current_epoch: 0,
        members: vec![squatter],
        closed_at: None,
        superseded_by: None,
        kind: MlsGroupKind::Call,
        generation: None,
        seat_list_ad_sha256: None,
        pending_removals: vec![],
        member_added: vec![],
        pending_device_removals: vec![],
        signer_lost: None,
        rejoin_readd: vec![],
    }
}

fn call_commit(group_id: &str, epoch: i64) -> crate::MlsCommit {
    crate::MlsCommit {
        id: crate::MlsCommit::composite_id(group_id, epoch),
        group_id: group_id.to_string(),
        epoch,
        committer: squatter(),
        commit: "b3BhcXVl".to_string(),
        size: 6,
        added: vec![],
        removed: vec![],
        created_at: Timestamp::now_utc(),
        rejoin_intents: vec![],
        removed_reasons: vec![],
        welcome: None,
    }
}

/// The device the squat's queued envelope is addressed to: its own per
/// group id, so counting that device's queue counts this squat's envelope
/// only (A6)
fn squat_recipient(group_id: &str) -> (&'static str, String) {
    (USER_B, group_id[..32].to_string())
}

/// Queued envelopes of the squat at `group_id` (A6)
async fn squat_envelopes(db: &Database, group_id: &str) -> usize {
    let (user_id, device_id) = squat_recipient(group_id);
    db.count_e2ee_envelopes(user_id, &device_id).await.unwrap() as usize
}

/// The squat through the REAL Call paths: the group, a won Call commit at
/// epoch 1, a join intent and the commit's queued envelope, i.e. every
/// Call-plane row keyed by the id
async fn squat(db: &Database, group_id: &str, call_channel: &str) {
    assert_eq!(
        db.create_mls_group(&call_group(group_id, call_channel), None)
            .await
            .unwrap(),
        MlsGroupCreateOutcome::Created
    );
    assert!(matches!(
        db.insert_mls_commit(&call_commit(group_id, 1))
            .await
            .unwrap(),
        crate::MlsCommitOutcome::Won
    ));
    let joiner = device(USER_B, DEVICE_A2);
    db.upsert_mls_join_intent(&crate::MlsJoinIntent {
        id: crate::MlsJoinIntent::composite_id(group_id, &joiner.user_id, &joiner.device_id),
        group_id: group_id.to_string(),
        user_id: joiner.user_id,
        device_id: joiner.device_id,
        key_package_ref: "cmVm".to_string(),
        signature: signature(1),
        created_at: at(0),
        generation: None,
        issued_at: None,
    })
    .await
    .unwrap();
    let (recipient_user_id, recipient_device_id) = squat_recipient(group_id);
    db.insert_e2ee_envelopes(&[E2EEEnvelope {
        id: ulid::Ulid::new().to_string(),
        recipient_user_id: recipient_user_id.to_string(),
        recipient_device_id,
        sender_user_id: squatter().user_id,
        sender_device_id: squatter().device_id,
        protocol_version: E2EE_PROTOCOL_VERSION,
        sequence: 0,
        ciphertext: "b3BhcXVl".to_string(),
        timestamp: Timestamp::now_utc(),
        content_type: E2EEContentType::MlsCommit,
        group_id: Some(group_id.to_string()),
        epoch: Some(1),
        committer: None,
        added: vec![],
        removed: vec![],
        rejoin_intents: vec![],
        removed_reasons: vec![],
    }])
    .await
    .unwrap();
}

/// The squat and its Call-plane rows are all still there
async fn assert_squat_intact(db: &Database, group_id: &str, call_channel: &str, case: &str) {
    let group = db
        .fetch_mls_group(group_id)
        .await
        .unwrap_or_else(|error| panic!("{case}: the squat is gone: {error:?}"));
    assert_eq!(group.kind, MlsGroupKind::Call, "{case}");
    assert_eq!(group.channel_id, call_channel, "{case}");
    assert_eq!(
        db.fetch_mls_commits_from(group_id, 0, 10)
            .await
            .unwrap()
            .len(),
        1,
        "{case}: the squat's commit"
    );
    assert_eq!(
        db.fetch_mls_join_intents_for_group(group_id)
            .await
            .unwrap()
            .len(),
        1,
        "{case}: the squat's join intent"
    );
    assert_eq!(
        squat_envelopes(db, group_id).await,
        1,
        "{case}: the squat's queued envelope"
    );
}

/// The Text group stands at `group_id`, and nothing of the squat is left
async fn assert_text_group_replaced_the_squat(
    db: &Database,
    group_id: &str,
    channel_id: &str,
    generation: u32,
    creator: &MlsMemberDevice,
) {
    let group = db.fetch_mls_group(group_id).await.unwrap();
    assert_eq!(group.kind, MlsGroupKind::Text);
    assert_eq!(group.channel_id, channel_id);
    assert_eq!(group.generation, Some(generation));
    assert!(group.open);
    assert_eq!(group.members, vec![creator.clone()]);
    assert!(group.seat_list_ad_sha256.is_some());
    assert!(
        db.fetch_mls_commits_from(group_id, 0, 10)
            .await
            .unwrap()
            .is_empty(),
        "the squat's commits went with it"
    );
    assert!(
        db.fetch_mls_join_intents_for_group(group_id)
            .await
            .unwrap()
            .is_empty(),
        "the squat's join intents went with it"
    );
    // A6 (W2 audit): no envelope queued for the squat is left to reach the
    // Text group's members as that group's
    assert_eq!(
        squat_envelopes(db, group_id).await,
        0,
        "the squat's queued envelopes went with it"
    );
}

/// A REAL Text Update commit at the next epoch of the channel's open Text
/// group must win: no Call commit is left at that `{group}:{epoch}`
async fn assert_text_commit_wins(db: &Database, channel_id: &str, committer: &MlsMemberDevice) {
    let group = db
        .fetch_seat_list_snapshot(channel_id)
        .await
        .unwrap()
        .text_group
        .expect("open Text group");
    let epoch = group.current_epoch + 1;
    let commit = crate::MlsCommit {
        id: crate::MlsCommit::composite_id(&group.id, epoch),
        group_id: group.id.clone(),
        epoch,
        committer: committer.clone(),
        commit: "b3BhcXVl".to_string(),
        size: 6,
        added: vec![],
        removed: vec![],
        created_at: Timestamp::now_utc(),
        rejoin_intents: vec![],
        removed_reasons: vec![],
        welcome: None,
    };
    let outcome = db
        .insert_mls_text_commit(&commit, &group.seat_list_ad_sha256.unwrap(), 0)
        .await
        .unwrap();
    assert!(
        matches!(outcome, crate::MlsCommitOutcome::Won),
        "the Text commit at epoch {epoch} lost to a leftover row: {outcome:?}"
    );
}

#[tokio::test]
async fn a_call_squat_at_the_text_group_id_no_longer_blocks_protect() {
    database_test!(|db| async move {
        // The squats name the 5.5 vector ids: the drivers' derivation must
        // be the design's, or nothing is evicted
        assert_eq!(derived_group_id(CHANNEL, 0), GROUP_ID_G0);
        assert_eq!(derived_group_id(CHANNEL, 1), GROUP_ID_G1);
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);

        // Pre-registered before the channel is even protected
        squat(&db, GROUP_ID_G0, &call_channel(0)).await;
        squat(&db, GROUP_ID_G1, &call_channel(1)).await;

        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();
        let mut first = text_group(0, &owner, 0);
        first.id = GROUP_ID_G0.to_string();
        assert_eq!(
            db.create_text_mls_group(&first, None)
                .await
                .expect("a Call squat must not block the Text create"),
            MlsGroupCreateOutcome::Created
        );

        assert_text_group_replaced_the_squat(&db, GROUP_ID_G0, CHANNEL, 0, &owner).await;
        assert_text_commit_wins(&db, CHANNEL, &owner).await;
        // A squat at another generation's id is untouched
        assert_squat_intact(&db, GROUP_ID_G1, &call_channel(1), "generation 1").await;
    });
}

#[tokio::test]
async fn a_call_squat_at_a_successor_id_no_longer_blocks_supersession() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);
        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();
        let mut first = text_group(0, &owner, 0);
        first.id = GROUP_ID_G0.to_string();
        assert_eq!(
            db.create_text_mls_group(&first, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        );

        squat(&db, GROUP_ID_G1, &call_channel(1)).await;
        let generation_2 = derived_group_id(CHANNEL, 2);
        squat(&db, &generation_2, &call_channel(2)).await;

        // A row written before `kind` existed is a Call group too (Mongo
        // only: a Reference row always has its kind)
        if let Database::MongoDb(mongo) = &db {
            let result = mongo
                .col::<bson::Document>("mls_groups")
                .update_one(
                    doc! { "_id": GROUP_ID_G1 },
                    doc! { "$unset": { "kind": "" } },
                )
                .await
                .unwrap();
            assert_eq!(result.modified_count, 1, "precondition: kind removed");
        }

        let mut successor = text_group(0, &owner, 1);
        successor.id = GROUP_ID_G1.to_string();
        assert_eq!(
            db.create_text_mls_group(&successor, Some(GROUP_ID_G0))
                .await
                .expect("a Call squat must not block the successor"),
            MlsGroupCreateOutcome::Created
        );

        assert_text_group_replaced_the_squat(&db, GROUP_ID_G1, CHANNEL, 1, &owner).await;
        let old = db.fetch_mls_group(GROUP_ID_G0).await.unwrap();
        assert!(!old.open);
        assert_eq!(old.superseded_by.as_deref(), Some(GROUP_ID_G1));
        assert_text_commit_wins(&db, CHANNEL, &owner).await;
        assert_squat_intact(&db, &generation_2, &call_channel(2), "generation 2").await;
    });
}

#[tokio::test]
async fn a_text_group_at_the_id_still_answers_as_before() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);
        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();
        let mut first = text_group(0, &owner, 0);
        first.id = GROUP_ID_G0.to_string();
        assert_eq!(
            db.create_text_mls_group(&first, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        );

        // The channel's own open Text group: `Conflict`, as before
        assert_eq!(
            db.create_text_mls_group(&first, None).await.unwrap(),
            MlsGroupCreateOutcome::Conflict {
                open_group_id: GROUP_ID_G0.to_string(),
                channel_id: CHANNEL.to_string(),
            }
        );

        // Another channel's Text group at the id (the database does not
        // derive Text ids, the route does): refused, and left as it was
        let other = race_channel(7_000);
        let holder = race_channel(7_001);
        protected_in(&db, &other, 10).await;
        protected_in(&db, &holder, 10).await;
        let taken_id = derived_group_id(&other, 0);
        let mut holding = text_group(0, &owner, 0);
        holding.id = taken_id.clone();
        holding.channel_id = holder.clone();
        assert_eq!(
            db.create_text_mls_group(&holding, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        );

        let mut wanted = text_group(0, &owner, 0);
        wanted.id = taken_id.clone();
        wanted.channel_id = other.clone();
        let error = db.create_text_mls_group(&wanted, None).await.unwrap_err();
        assert!(is_invalid_operation(&error), "{error:?}");
        let kept = db.fetch_mls_group(&taken_id).await.unwrap();
        assert_eq!(kept.kind, MlsGroupKind::Text);
        assert_eq!(kept.channel_id, holder);
        assert!(kept.open);
        assert!(db
            .fetch_seat_list_snapshot(&other)
            .await
            .unwrap()
            .text_group
            .is_none());
    });
}

#[tokio::test]
async fn a_refused_text_create_leaves_a_call_squat_untouched() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);
        squat(&db, GROUP_ID_G0, &call_channel(0)).await;
        let mut first = text_group(0, &owner, 0);
        first.id = GROUP_ID_G0.to_string();

        // No seat list yet
        let error = db.create_text_mls_group(&first, None).await.unwrap_err();
        assert!(is_failed_validation(&error), "{error:?}");
        assert_squat_intact(&db, GROUP_ID_G0, &call_channel(0), "no seat list").await;

        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();

        // Not the signer device
        let mut other_device = text_group(0, &device(USER_A, DEVICE_A2), 0);
        other_device.id = GROUP_ID_G0.to_string();
        let error = db
            .create_text_mls_group(&other_device, None)
            .await
            .unwrap_err();
        assert!(is_failed_validation(&error), "{error:?}");
        assert_squat_intact(&db, GROUP_ID_G0, &call_channel(0), "not the signer").await;

        // The signer's create then lands
        assert_eq!(
            db.create_text_mls_group(&first, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        );
        assert_text_group_replaced_the_squat(&db, GROUP_ID_G0, CHANNEL, 0, &owner).await;
    });
}

#[tokio::test]
async fn a_call_group_at_an_id_the_create_does_not_derive_is_never_evicted() {
    database_test!(|db| async move {
        setup(&db, 10).await;
        let owner = device(USER_A, DEVICE_A);
        db.protect_channel(CHANNEL, &submit(1, &[USER_A]), at(0))
            .await
            .unwrap();

        // A random id, another generation's id, another channel's id: none
        // is this generation-0 create's own id, so another call's group
        // there is never deleted
        let cases = [
            ("a random id", "ab".repeat(32)),
            ("generation 1's id", GROUP_ID_G1.to_string()),
            (
                "another channel's id",
                derived_group_id(&race_channel(7_100), 0),
            ),
        ];
        for (n, (case, group_id)) in cases.iter().enumerate() {
            squat(&db, group_id, &call_channel(n as u32)).await;
            let mut naming = text_group(0, &owner, 0);
            naming.id = group_id.clone();
            let error = db.create_text_mls_group(&naming, None).await.unwrap_err();
            assert!(is_invalid_operation(&error), "{case}: {error:?}");
            assert_squat_intact(&db, group_id, &call_channel(n as u32), case).await;
        }
    });
}

/// The squatter re-registering its Call group at `group_id` as fast as it
/// can until `stop`, counting its attempts
async fn resquat_loop(
    db: &Database,
    group_id: &str,
    call_channel: &str,
    stop: &AtomicBool,
    attempts: &AtomicI64,
) {
    while !stop.load(SeqCst) {
        let _ = db
            .create_mls_group(&call_group(group_id, call_channel), None)
            .await;
        attempts.fetch_add(1, SeqCst);
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn a_text_create_racing_a_resquat_still_lands() {
    database_test!(|db| async move {
        // Under REFERENCE the create holds every lock it needs at once, so
        // this is structural; the eviction's atomicity against a squatter
        // that re-registers in between is exercised under MONGODB
        server_ready(&db).await;
        let owner = device(USER_A, DEVICE_A);
        for iteration in 0..RACE_ITERATIONS {
            let channel_id = race_channel(8_000 + iteration);
            protected_in(&db, &channel_id, 10).await;
            let group_id = derived_group_id(&channel_id, 0);
            let call_channel = call_channel(100 + iteration);
            squat(&db, &group_id, &call_channel).await;

            let mut group = text_group(0, &owner, 0);
            group.id = group_id.clone();
            group.channel_id = channel_id.clone();
            let stop = AtomicBool::new(false);
            let attempts = AtomicI64::new(0);
            let create = async {
                // Fire the create only once the squatter is live
                let live = wait_until(|| attempts.load(SeqCst) >= 1).await;
                let created = db.create_text_mls_group(&group, None).await;
                stop.store(true, SeqCst);
                (live, created)
            };
            let ((live, created), ()) = tokio::join!(
                create,
                resquat_loop(&db, &group_id, &call_channel, &stop, &attempts)
            );

            assert!(live, "iteration {iteration}: the squatter never went live");
            assert_eq!(
                created.unwrap_or_else(|error| panic!(
                    "iteration {iteration}: the Text create was refused: {error:?}"
                )),
                MlsGroupCreateOutcome::Created
            );
            let stored = db.fetch_mls_group(&group_id).await.unwrap();
            assert_eq!(stored.kind, MlsGroupKind::Text, "iteration {iteration}");
            assert_eq!(stored.channel_id, channel_id, "iteration {iteration}");
        }
    });
}

/// The squatter streaming REAL Call commits on its squat, one epoch after
/// the other, until `stop`; counts the wins
async fn call_commit_stream(db: &Database, group_id: &str, stop: &AtomicBool, won: &AtomicI64) {
    while !stop.load(SeqCst) {
        if let Ok(group) = db.fetch_mls_group(group_id).await {
            if group.kind == MlsGroupKind::Call {
                let commit = call_commit(group_id, group.current_epoch + 1);
                if let Ok(crate::MlsCommitOutcome::Won) = db.insert_mls_commit(&commit).await {
                    won.fetch_add(1, SeqCst);
                }
            }
        }
        tokio::task::yield_now().await;
    }
}

/// Rounds of the commit-stream test (each a fresh channel)
const SQUAT_STREAM_ROUNDS: u32 = 8;

#[tokio::test]
async fn a_text_create_lands_while_the_squat_streams_call_commits() {
    database_test!(|db| async move {
        server_ready(&db).await;
        let owner = device(USER_A, DEVICE_A);
        for round in 0..SQUAT_STREAM_ROUNDS {
            let channel_id = race_channel(9_000 + round);
            protected_in(&db, &channel_id, 10).await;
            let group_id = derived_group_id(&channel_id, 0);
            squat(&db, &group_id, &call_channel(200 + round)).await;

            let mut group = text_group(0, &owner, 0);
            group.id = group_id.clone();
            group.channel_id = channel_id.clone();
            let stop = AtomicBool::new(false);
            let won = AtomicI64::new(0);
            let create = async {
                let live = wait_until(|| won.load(SeqCst) >= 2).await;
                let created = db.create_text_mls_group(&group, None).await;
                stop.store(true, SeqCst);
                (live, created)
            };
            let ((live, created), ()) =
                tokio::join!(create, call_commit_stream(&db, &group_id, &stop, &won));

            assert!(live, "round {round}: the commit stream never went live");
            assert_eq!(
                created.unwrap_or_else(|error| panic!(
                    "round {round}: the Text create never landed: {error:?}"
                )),
                MlsGroupCreateOutcome::Created
            );
            let stored = db.fetch_mls_group(&group_id).await.unwrap();
            assert_eq!(stored.kind, MlsGroupKind::Text, "round {round}");

            // Not asserted (a residual outside this driver): a Call commit
            // that read its group before the eviction committed is still
            // inserted after it, since the Call commit path is not one
            // transaction
            let left = db
                .fetch_mls_commits_from(&group_id, 0, 1_000)
                .await
                .unwrap()
                .len();
            if left > 0 {
                eprintln!(
                    "NOTE round {round}: {left} Call commit row(s) landed at the evicted id after the eviction"
                );
            }
        }
    });
}

/// What the Mongo Text create runs mid-transaction (test-only, see
/// `run_text_create_hook`)
type TextCreateHook =
    std::sync::Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

/// The group id the hook fires for, and the hook. Keyed by id, so the
/// tests running beside the one that sets it are never affected.
static TEXT_CREATE_HOOK: std::sync::Mutex<Option<(String, TextCreateHook)>> =
    std::sync::Mutex::new(None);

/// Called by the Mongo Text create (`ops/mongodb.rs`, `#[cfg(test)]` only)
/// inside every transaction attempt, once the attempt's snapshot is fixed
/// and before it reads and evicts the row at its id
pub(super) async fn run_text_create_hook(group_id: &str) {
    let hook = TEXT_CREATE_HOOK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(id, _)| id == group_id)
        .map(|(_, hook)| hook.clone());
    if let Some(hook) = hook {
        hook().await;
    }
}

/// How long the squatter's mid-transaction write may wait before the
/// create goes on without it
const SQUAT_WRITE_WAIT_MS: u64 = 300;

#[tokio::test]
async fn a_text_create_claims_the_squat_row_before_the_squatter_can_starve_it() {
    database_test!(|db| async move {
        // MONGODB only (under REFERENCE the create holds every lock it
        // needs at once). The create's FIRST operation writes the squat's
        // row (`claim_groups_first`), so a squatter writing that row while
        // the create is in flight (a won Call commit's effects update) waits
        // for the create's transaction. Without the claim the row is first
        // written by the eviction's delete, after the snapshot, so a write
        // landing in between write-conflicts the attempt, and a squatter
        // that does it on every attempt starves the create until the retry
        // budget runs out. The hook is that squatter, made deterministic.
        let Database::MongoDb(mongo) = &db else {
            return;
        };
        server_ready(&db).await;
        let owner = device(USER_A, DEVICE_A);
        let channel_id = race_channel(9_500);
        protected_in(&db, &channel_id, 10).await;
        let group_id = derived_group_id(&channel_id, 0);
        squat(&db, &group_id, &call_channel(300)).await;

        let fired = std::sync::Arc::new(AtomicI64::new(0));
        let landed = std::sync::Arc::new(AtomicI64::new(0));
        let hook: TextCreateHook = {
            let (mongo, group_id) = (mongo.clone(), group_id.clone());
            let (fired, landed) = (fired.clone(), landed.clone());
            std::sync::Arc::new(move || {
                let (mongo, group_id) = (mongo.clone(), group_id.clone());
                let (fired, landed) = (fired.clone(), landed.clone());
                Box::pin(async move {
                    fired.fetch_add(1, SeqCst);
                    // Outside any transaction, filtered on the Call kind (a
                    // Call commit never writes a Text group)
                    let write = async {
                        mongo
                            .col::<bson::Document>("mls_groups")
                            .update_one(
                                doc! { "_id": &group_id, "kind": "Call" },
                                doc! { "$inc": { "squat_writes": 1_i64 } },
                            )
                            .await
                    };
                    let waited = std::time::Duration::from_millis(SQUAT_WRITE_WAIT_MS);
                    if let Ok(Ok(result)) = tokio::time::timeout(waited, write).await {
                        if result.modified_count == 1 {
                            landed.fetch_add(1, SeqCst);
                        }
                    }
                })
            })
        };
        *TEXT_CREATE_HOOK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((group_id.clone(), hook));

        let mut group = text_group(0, &owner, 0);
        group.id = group_id.clone();
        group.channel_id = channel_id.clone();
        let created = db.create_text_mls_group(&group, None).await;
        *TEXT_CREATE_HOOK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;

        let (fired, landed) = (fired.load(SeqCst), landed.load(SeqCst));
        assert_eq!(
            created.unwrap_or_else(|error| panic!(
                "the squatter starved the Text create ({fired} attempts, its write \
                 landed mid-transaction {landed} times): {error:?}"
            )),
            MlsGroupCreateOutcome::Created
        );
        assert!(fired >= 1, "the hook never ran: the test proves nothing");
        assert_eq!(
            landed, 0,
            "the squatter's write landed while the create's transaction was open"
        );
        assert_text_group_replaced_the_squat(&db, &group_id, &channel_id, 0, &owner).await;
    });
}

/// A cooling seat row exactly as an S1 build (dafb3433) stores it
const SEAT_S1: &str = r#"{"_id":"01J9Z3K4M5N6P7Q8R9S0T1V2W3:01HZXBBBBBBBBBBBBBBBBBBBBB","channel_id":"01J9Z3K4M5N6P7Q8R9S0T1V2W3","user_id":"01HZXBBBBBBBBBBBBBBBBBBBBB","seated_at":"2026-10-04T12:00:00.000Z","released_at":"2026-10-05T12:00:00.000Z","cooldown_until":"2026-10-19T12:00:00.000Z"}"#;

/// A seat list row exactly as an S1 build (dafb3433) stores it
const SEAT_LIST_S1: &str = r#"{"_id":"01J9Z3K4M5N6P7Q8R9S0T1V2W3","version":3,"body":"body","signer_user_id":"01HZXAAAAAAAAAAAAAAAAAAAAA","signer_device_id":"00112233445566778899aabbccddeeff","signature":"c2ln","handovers":[{"body":"handover","signature":"aG8"}],"updated_at":"2026-10-04T12:00:00.000Z"}"#;

/// Decodes `s1`, checks it is byte-identical on re-encode (JSON) and has
/// the same keys as a BSON document, and returns it
fn s1_round_trip<T>(s1: &str) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let parsed: T = serde_json::from_str(s1).expect("an S1 row decodes");
    assert_eq!(serde_json::to_string(&parsed).unwrap(), s1);

    let expected: serde_json::Map<String, serde_json::Value> = serde_json::from_str(s1).unwrap();
    let document = bson::to_document(&parsed).unwrap();
    assert_eq!(
        document.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "the stored BSON keys are the S1 keys"
    );
    assert_eq!(bson::from_document::<T>(document).unwrap(), parsed);
    parsed
}

/// S2 (2.3): `release_cause` and `keys_received_at` are absent when `None`,
/// so an S1 seat row decodes and re-encodes byte-identical; set values are
/// stored snake_case under their exact keys
#[test]
fn seat_s2_fields_are_absent_when_empty() {
    let seat: ChannelSeat = s1_round_trip(SEAT_S1);
    assert_eq!(seat.release_cause, None);
    assert_eq!(seat.keys_received_at, None);

    for (cause, wire) in [
        (SeatReleaseCause::OwnerUnseat, "owner_unseat"),
        (SeatReleaseCause::ServerRemoval, "server_removal"),
        (SeatReleaseCause::AccessLost, "access_lost"),
        (SeatReleaseCause::DeviceNeverJoined, "device_never_joined"),
    ] {
        let s2 = ChannelSeat {
            release_cause: Some(cause),
            keys_received_at: Some(seat.seated_at),
            ..seat.clone()
        };
        let value = serde_json::to_value(&s2).unwrap();
        assert_eq!(value["release_cause"], wire);
        assert_eq!(value["keys_received_at"], value["seated_at"]);
        assert_eq!(serde_json::from_value::<ChannelSeat>(value).unwrap(), s2);
        let document = bson::to_document(&s2).unwrap();
        assert_eq!(document.get_str("release_cause").unwrap(), wire);
        assert_eq!(bson::from_document::<ChannelSeat>(document).unwrap(), s2);
    }
}

/// S2 (2.4): `authority` is absent when `None`, so an S1 seat list row
/// decodes and re-encodes byte-identical; a set authority round-trips
#[test]
fn seat_list_authority_is_absent_when_empty() {
    let list: SeatList = s1_round_trip(SEAT_LIST_S1);
    assert_eq!(list.authority, None);

    let s2 = SeatList {
        authority: Some(SignedAuthority {
            body: "authority".to_string(),
            signature: "YXV0aA".to_string(),
        }),
        ..list
    };
    let value = serde_json::to_value(&s2).unwrap();
    assert_eq!(value["authority"]["body"], "authority");
    assert_eq!(value["authority"]["signature"], "YXV0aA");
    let document = bson::to_document(&s2).unwrap();
    assert!(document.contains_key("authority"));
    assert_eq!(bson::from_document::<SeatList>(document).unwrap(), s2);
}

/// `ProtectedChannelChanged.scope` items (7.5): the exact wire strings
#[test]
fn protected_scopes_are_the_wire_strings() {
    assert_eq!(PROTECTED_SCOPE_SEATS, "seats");
    assert_eq!(PROTECTED_SCOPE_TEXT_GROUP, "text_group");
}

// ---------------------------------------------------------------------------
// S2 (W1-1b): the 5.8 `tv2:` vectors and the 4.3 "S2 additions" rules
// ---------------------------------------------------------------------------

// `tv:inputs` seeds (5.1) and `tv2:inputs` (5.8)
const OWNER_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const MEMBER_SEED: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const NEW_OWNER_SEED: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const CID: &str = "01JA0000000000000000000MSG";
const GROUP_SALT: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const SEAT_V2_VERSION: i64 = 4;
const SEAT_V2_DEVICE_CAP: u32 = 5;
const SEAT_V2_ISSUED_AT: i64 = 1_790_812_860_000;
const AUTHORITY_VERSION: i64 = 1;
const AUTHORITY_ISSUED_AT: i64 = 1_790_812_860_000;
const AUTHORITY_DELEGATE_MAX_DEVICE_CAP: u32 = 5;
const JOIN_GENERATION: u32 = 0;
const JOIN_KEY_PACKAGE_REF: &str = "S2JvaW5LZXlQYWNrYWdlUmVmVjE+/0123456789";
const JOIN_ISSUED_AT: i64 = 1_790_812_870_000;
const SUCCESSION_RANK: u8 = 1;
const SUCCESSION_ISSUED_AT: i64 = 1_790_812_880_000;
const EXTRA1_SEED: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
const EXTRA2_SEED: &str = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

// Section 5.2 member key; `MAX` of the 5.8 worst case
const MEMBER_IDENTITY_KEY: &str = "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc";
const MAX_INT: i64 = 9_007_199_254_740_991;

// The `tv2:` expected values, copied verbatim from 5.8. Each test rebuilds
// the value from the inputs above and compares.
const TV2_AUTHORITY_BODY: &str = "sloga-channel-authority-v1\nv:1\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\nversion:1\nowner_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nsigner_device_id:00112233445566778899aabbccddeeff\nissued_at:1790812860000\nowner_devices:00112233445566778899aabbccddeeff.A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg,0123456789abcdef0123456789abcdef.zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o\ndelegates:01HZXBBBBBBBBBBBBBBBBBBBBB.ffeeddccbbaa99887766554433221100.Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc\ndelegate_scope:seat\ndelegate_max_device_cap:5\nsuccessors:01HZXBBBBBBBBBBBBBBBBBBBBB.ffeeddccbbaa99887766554433221100.Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc\nprev:";
const TV2_AUTHORITY_BODY_SHA256: &str =
    "0277b8d50e6322568380e1fede0ee1a7a03ae70444420445e86d10e99dc7cd71";
const TV2_AUTHORITY_SIGNATURE: &str =
    "xRMnLtvVVtb5tra2OK01NOd+gCbkWfTqnQSYJThQ1Wlc5Cv2XObDdLXviQH/kji2qjWDRj7PMWDTfqkQusupAA";
const TV2_SEAT_LIST_V2_BODY: &str = "sloga-seat-list-v2\nv:2\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\nversion:4\ndevice_cap:5\nissued_at:1790812860000\nsigner_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nsigner_device_id:00112233445566778899aabbccddeeff\nseats:01HZXAAAAAAAAAAAAAAAAAAAAA,01HZXBBBBBBBBBBBBBBBBBBBBB,01HZXCCCCCCCCCCCCCCCCCCCCC\nauthority:0277b8d50e6322568380e1fede0ee1a7a03ae70444420445e86d10e99dc7cd71\nhistory:visible\nhistory_boundary:\npre_history:kept\ngroup_salt:a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const TV2_SEAT_LIST_V2_BODY_SHA256: &str =
    "6822d2c987006383581ee0cf0c5fd758dd3785bb2c214d514332dd7eed336806";
const TV2_SEAT_LIST_V2_SIGNATURE: &str =
    "2fpKyQ7i80lUPxe8a4K8CjJAeoRR1xH4s3owXpN4L92AeR2ot0pcaRD/qLR8bbH97vLzYNNQ/5jP+M6GXybwAg";
const TV2_GROUP_ID_V2_INPUT_G0_HEX: [&str; 4] = [
    "0013736c6f67612d746578742d67726f75702d7632",
    "001a30314a395a334b344d354e365037513852395330543156325733",
    "0000000000000000",
    "0020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
];
const TV2_GROUP_ID_V2_G0: &str = "6036022873e9088d763291333fd3aad4eed2efa4ad97edc74349494d0fa24ac3";
const TV2_GROUP_ID_V2_G1: &str = "f5d67f0df1e16b362c46ede8a927a8cb63b95ddca63822da6d691475b56fe81f";
const TV2_GROUP_ID_V2_G64: &str =
    "787025fd12b11b64a85630a1fa261c420d919691633a6ab349a51173c671eb95";
const TV2_GROUP_ID_V2_G65535: &str =
    "c6e859ede61183b2d91d57c50484667f004a96e931dc5cbc38d614674ae5e4c3";
const TV2_COMMIT_AD_V2_HEX: [&str; 8] = [
    "0017736c6f67612d746578742d636f6d6d69742d61642d7632",
    "01e8736c6f67612d736561742d6c6973742d76320a763a320a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a76657273696f6e3a340a6465766963655f6361703a350a6973737565645f61743a313739303831323836303030300a7369676e65725f757365725f69643a3031485a584141414141414141414141414141414141414141410a7369676e65725f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a73656174733a3031485a584141414141414141414141414141414141414141412c3031485a584242424242424242424242424242424242424242422c3031485a584343434343434343434343434343434343434343430a617574686f726974793a303237376238643530653633323235363833383065316665646530656531613761303361653730343434343230343435653836643130653939646337636437310a686973746f72793a76697369626c650a686973746f72795f626f756e646172793a0a7072655f686973746f72793a6b6570740a67726f75705f73616c743a61306131613261336134613561366137613861396161616261636164616561666230623162326233623462356236623762386239626162626263626462656266",
    "0040d9fa4ac90ee2f349543f17bc6b82bc0a32407a8451d711f8b37a305e93782fdd80791da8b74a5c6910ffa8b47c6db1fdeef2f360d350ff98cff8ce865f26f002",
    "0001",
    "017f736c6f67612d6f776e65722d68616e646f7665722d76310a763a310a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a66726f6d5f757365725f69643a3031485a584141414141414141414141414141414141414141410a66726f6d5f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a66726f6d5f6964656e746974795f6b65793a41364548762f504f454c3464634e3059353076416d57666b316a436270513166486479475a424a564d62670a746f5f757365725f69643a3031485a584141414141414141414141414141414141414141410a746f5f6465766963655f69643a30313233343536373839616263646566303132333435363738396162636465660a746f5f6964656e746974795f6b65793a7a52537a663556756c5447552f332b334f7a3242334d5668316870314f416c4c664434615a44376c38366f0a6973737565645f61743a31373930383132383030303030",
    "004024a9d8b5a88afe2ded612c55ef55e85f2cfd9745da0ec588873a02bbcb3d22e4dd9859965f904db68121a6dfaff604af844fa7a92dbf919100d025fa82247a04",
    "0282736c6f67612d6368616e6e656c2d617574686f726974792d76310a763a310a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a76657273696f6e3a310a6f776e65725f757365725f69643a3031485a584141414141414141414141414141414141414141410a7369676e65725f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a6973737565645f61743a313739303831323836303030300a6f776e65725f646576696365733a30303131323233333434353536363737383839396161626263636464656566662e41364548762f504f454c3464634e3059353076416d57666b316a436270513166486479475a424a564d62672c30313233343536373839616263646566303132333435363738396162636465662e7a52537a663556756c5447552f332b334f7a3242334d5668316870314f416c4c664434615a44376c38366f0a64656c6567617465733a3031485a584242424242424242424242424242424242424242422e66666565646463636262616139393838373736363535343433333232313130302e4b61793634554738797643794c6871553030304c787a5965556d304c2f684c496c3553386b794b576264630a64656c65676174655f73636f70653a736561740a64656c65676174655f6d61785f6465766963655f6361703a350a737563636573736f72733a3031485a584242424242424242424242424242424242424242422e66666565646463636262616139393838373736363535343433333232313130302e4b61793634554738797643794c6871553030304c787a5965556d304c2f684c496c3553386b794b576264630a707265763a",
    "0040c513272edbd556d6f9b6b6b638ad3534e77e8026e459f4ea9d0498253850d5695ce42bf65ce6c374b5ef8901ff9238b6aa3583463ecf3160d37ea910bacba900",
];
const TV2_COMMIT_AD_V2_SHA256: &str =
    "38495363a9d10a817ed464523a1d17852f6c634008124118d6ff814397299d46";
const TV2_TEXT_JOIN_BODY: &str = "sloga-text-join-v1\nv:1\nuser_id:01HZXBBBBBBBBBBBBBBBBBBBBB\ndevice_id:ffeeddccbbaa99887766554433221100\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\ngeneration:0\ngroup_id:6036022873e9088d763291333fd3aad4eed2efa4ad97edc74349494d0fa24ac3\nkey_package_ref:S2JvaW5LZXlQYWNrYWdlUmVmVjE+/0123456789\nissued_at:1790812870000";
const TV2_TEXT_JOIN_SIGNATURE: &str =
    "l6DoK5goYia40tveyilADPFzJ46y8uVz/IUGtdn3DuybteG/t0xU1Hfur8G0siBGCbEVQNxzNiGKayHnCjKABw";
const TV2_SUCCESSION_BODY: &str = "sloga-owner-succession-v1\nv:1\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\nfrom_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nfrom_identity_key:A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg\nto_user_id:01HZXBBBBBBBBBBBBBBBBBBBBB\nto_device_id:ffeeddccbbaa99887766554433221100\nto_identity_key:Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc\nauthority_sha256:0277b8d50e6322568380e1fede0ee1a7a03ae70444420445e86d10e99dc7cd71\nrank:1\nissued_at:1790812880000";
const TV2_SUCCESSION_SIGNATURE: &str =
    "FTQqMwVpolS3sn+iveaRPZwuthYIbGn1P99OBmLp1OpCrcOYSG8C3o90XFn1LsqMt3yxRBiJqtHkW+6mOEZhCw";
const TV2_WORST_COMMIT_AD_V2_LEN: &str = "14112";
const TV2_WORST_COMMIT_AD_V2_SHA256: &str =
    "745d6adff648976eb588bab96cb005001819f66858b6556bba5f59bf3dcd68c1";

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn signing_key(seed_hex: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&unhex(seed_hex).try_into().unwrap())
}

/// b64 of the Ed25519 public key of a seed (5.2)
fn identity_key_of(seed_hex: &str) -> String {
    STANDARD_NO_PAD.encode(signing_key(seed_hex).verifying_key().as_bytes())
}

/// b64 Ed25519 signature by a seed (deterministic, so the 5.8 signatures
/// are reproducible)
fn sign_b64(seed_hex: &str, message: &str) -> String {
    use ed25519_dalek::Signer;
    STANDARD_NO_PAD.encode(signing_key(seed_hex).sign(message.as_bytes()).to_bytes())
}

fn hex32(n: u32) -> String {
    format!("{n:032x}")
}

/// Refused with `FailedValidation` by the rule whose message contains
/// `needle`, so a rule's test fails when that rule is gone even if another
/// rule refuses the input. Every failure names `case`.
fn assert_refused<T: std::fmt::Debug>(result: revolt_result::Result<T>, needle: &str, case: &str) {
    match result {
        Err(error) => match error.error_type {
            ErrorType::FailedValidation { error } => assert!(
                error.contains(needle),
                "{case}: refused with {error:?}, expected {needle:?}"
            ),
            other => panic!("{case}: expected FailedValidation, got {other:?}"),
        },
        Ok(value) => panic!("{case}: expected a refusal, got {value:?}"),
    }
}

fn is_resecuring(error: &revolt_result::Error) -> bool {
    matches!(&error.error_type, ErrorType::ProtectedChannelResecuring { reason } if reason == "owner_device_lost")
}

/// `body` with the value of its one `label:` line replaced
fn with_line(body: &str, label: &str, value: &str) -> String {
    let prefix = format!("{label}:");
    let mut found = 0;
    let lines: Vec<String> = body
        .split('\n')
        .map(|line| {
            if line.starts_with(&prefix) {
                found += 1;
                format!("{prefix}{value}")
            } else {
                line.to_string()
            }
        })
        .collect();
    assert_eq!(found, 1, "{label}");
    lines.join("\n")
}

fn owner_device(device_id: &str, identity_key: &str) -> AuthorityOwnerDevice {
    AuthorityOwnerDevice {
        device_id: device_id.to_string(),
        identity_key: identity_key.to_string(),
    }
}

fn user_device(user_id: &str, device_id: &str, identity_key: &str) -> AuthorityUserDevice {
    AuthorityUserDevice {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        identity_key: identity_key.to_string(),
    }
}

/// The 5.8 authority from its inputs; the owner devices are given out of
/// order (the builder sorts)
fn vector_authority() -> ChannelAuthorityBody {
    ChannelAuthorityBody {
        channel_id: CHANNEL.to_string(),
        version: AUTHORITY_VERSION,
        owner_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        issued_at: AUTHORITY_ISSUED_AT,
        owner_devices: vec![
            owner_device(DEVICE_A2, &identity_key_of(NEW_OWNER_SEED)),
            owner_device(DEVICE_A, &identity_key_of(OWNER_SEED)),
        ],
        delegates: vec![user_device(USER_B, DEVICE_B, &identity_key_of(MEMBER_SEED))],
        delegate_max_device_cap: AUTHORITY_DELEGATE_MAX_DEVICE_CAP,
        successors: vec![user_device(USER_B, DEVICE_B, &identity_key_of(MEMBER_SEED))],
        prev: None,
    }
}

/// The 5.8 seat list v2 (5.3's seats, unsorted: the builder sorts)
fn vector_seat_list_v2(authority_sha256: &str) -> SeatListBody {
    SeatListBody {
        channel_id: CHANNEL.to_string(),
        version: SEAT_V2_VERSION,
        device_cap: SEAT_V2_DEVICE_CAP,
        issued_at: SEAT_V2_ISSUED_AT,
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        seats: vec![USER_C.to_string(), USER_A.to_string(), USER_B.to_string()],
        v2: Some(SeatListV2Lines {
            authority_sha256: Some(authority_sha256.to_string()),
            // `seat_v2_history`, `seat_v2_pre_history`
            history: SeatListHistory::Visible,
            history_boundary: None,
            pre_history: SeatListPreHistory::Kept,
            group_salt: GROUP_SALT.to_string(),
        }),
    }
}

/// The 5.8 AD v2 row: the v2 list, the 5.4 handover and the 5.8 authority,
/// every signature computed from its seed
fn vector_v2_row() -> SeatList {
    let authority = ChannelAuthority::build(&vector_authority()).unwrap();
    let body = vector_seat_list_v2(&ChannelAuthority::sha256(&authority))
        .build()
        .unwrap();
    SeatList {
        id: CHANNEL.to_string(),
        version: SEAT_V2_VERSION,
        signature: sign_b64(OWNER_SEED, &body),
        body,
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        handovers: vec![SignedHandover {
            body: VECTOR_HANDOVER_BODY.to_string(),
            signature: sign_b64(OWNER_SEED, VECTOR_HANDOVER_BODY),
        }],
        updated_at: at(0),
        authority: Some(SignedAuthority {
            signature: sign_b64(OWNER_SEED, &authority),
            body: authority,
        }),
    }
}

/// Chain entries of filler bodies (the AD builder never parses chain
/// entries, as in S1) that bring an AD of `base_len` bytes to `target`
fn filler_chain(base_len: usize, target: usize) -> Vec<SignedHandover> {
    let mut remaining = target - base_len;
    let mut chain = Vec::new();
    while remaining > 0 {
        assert!(remaining > 68, "filler chain cannot hit {target} exactly");
        let len = (remaining - 68).min(1024);
        chain.push(SignedHandover {
            body: "x".repeat(len),
            signature: signature(chain.len() as i64),
        });
        remaining -= 68 + len;
    }
    assert!(chain.len() <= MAX_SEAT_LIST_HANDOVERS);
    chain
}

#[test]
fn s2_seeds_give_the_5_2_identity_keys() {
    assert_eq!(identity_key_of(OWNER_SEED), OWNER_IDENTITY_KEY);
    assert_eq!(identity_key_of(NEW_OWNER_SEED), NEW_OWNER_IDENTITY_KEY);
    assert_eq!(identity_key_of(MEMBER_SEED), MEMBER_IDENTITY_KEY);
}

#[test]
fn authority_matches_the_5_8_vector() {
    let body = ChannelAuthority::build(&vector_authority()).unwrap();
    assert_eq!(body, TV2_AUTHORITY_BODY);
    assert_eq!(ChannelAuthority::sha256(&body), TV2_AUTHORITY_BODY_SHA256);
    assert_eq!(sign_b64(OWNER_SEED, &body), TV2_AUTHORITY_SIGNATURE);

    let mut sorted = vector_authority();
    sorted.owner_devices.reverse();
    assert_eq!(ChannelAuthority::parse(TV2_AUTHORITY_BODY).unwrap(), sorted);
}

#[test]
fn seat_list_v2_matches_the_5_8_vector() {
    let authority = ChannelAuthority::build(&vector_authority()).unwrap();
    let authority_sha256 = ChannelAuthority::sha256(&authority);
    let unsorted = vector_seat_list_v2(&authority_sha256);
    let body = unsorted.build().unwrap();
    assert_eq!(body, TV2_SEAT_LIST_V2_BODY);
    assert_eq!(unsorted.build_v2().unwrap(), TV2_SEAT_LIST_V2_BODY);
    assert_eq!(
        hex(&Sha256::digest(body.as_bytes())),
        TV2_SEAT_LIST_V2_BODY_SHA256
    );
    assert_eq!(sign_b64(OWNER_SEED, &body), TV2_SEAT_LIST_V2_SIGNATURE);

    // `parse` dispatches on the context line; `parse_v1` refuses v2 bytes
    let parsed = SeatListBody::parse(TV2_SEAT_LIST_V2_BODY).unwrap();
    assert_eq!(
        parsed,
        SeatListBody {
            seats: vec![USER_A.to_string(), USER_B.to_string(), USER_C.to_string()],
            ..unsorted
        }
    );
    assert_eq!(
        SeatListBody::parse_v2(TV2_SEAT_LIST_V2_BODY).unwrap(),
        parsed
    );
    assert_refused(
        SeatListBody::parse_v1(TV2_SEAT_LIST_V2_BODY),
        "exactly 9 lines",
        "v2 bytes through parse_v1",
    );
}

/// v1 byte identity: an S1 body still parses as v1 (no v2 lines) and builds
/// back to the same bytes; `build_v2` refuses it
#[test]
fn s1_bodies_still_parse_as_v1_and_rebuild_byte_identical() {
    let parsed = SeatListBody::parse(VECTOR_BODY).unwrap();
    assert_eq!(parsed.v2, None);
    assert_eq!(SeatListBody::parse_v1(VECTOR_BODY).unwrap(), parsed);
    assert_eq!(parsed.build().unwrap(), VECTOR_BODY);
    assert_refused(
        SeatListBody::parse_v2(VECTOR_BODY),
        "exactly 14 lines",
        "v1 bytes through parse_v2",
    );
    assert_refused(
        parsed.build_v2(),
        "v2 lines missing",
        "build_v2 of a v1 body",
    );
}

#[test]
fn seat_list_v2_body_refuses_every_non_canonical_form() {
    let base = TV2_SEAT_LIST_V2_BODY;
    let mut swapped: Vec<&str> = base.split('\n').collect();
    swapped.swap(10, 12);
    let swapped = swapped.join("\n");

    let cases: Vec<(&str, String, &str)> = vec![
        ("trailing LF", format!("{base}\n"), "exactly 14 lines"),
        ("CR", base.replacen('\n', "\r\n", 1), "contains CR"),
        (
            "13 lines",
            base.rsplit_once('\n').unwrap().0.to_string(),
            "exactly 14 lines",
        ),
        (
            "v2 context, v:1",
            base.replace("\nv:2\n", "\nv:1\n"),
            "context or format version",
        ),
        (
            "v1 context, v:2, 14 lines",
            base.replace("sloga-seat-list-v2", "sloga-seat-list-v1"),
            "exactly 9 lines",
        ),
        (
            "v1 context, v:2, 9 lines",
            VECTOR_BODY.replace("\nv:1\n", "\nv:2\n"),
            "context or format version",
        ),
        (
            "authority charset",
            with_line(base, "authority", &TV2_AUTHORITY_BODY_SHA256.to_uppercase()),
            "seat list authority",
        ),
        (
            "authority length",
            with_line(base, "authority", &TV2_AUTHORITY_BODY_SHA256[..63]),
            "seat list authority",
        ),
        (
            "history value",
            with_line(base, "history", "shown"),
            "seat list history",
        ),
        (
            "boundary charset",
            with_line(base, "history_boundary", &CID.to_lowercase()),
            "seat list history_boundary",
        ),
        (
            "pre_history value",
            with_line(base, "pre_history", "gone"),
            "seat list pre_history",
        ),
        (
            "wiped without a boundary",
            with_line(base, "pre_history", "wiped"),
            "wiped without a boundary",
        ),
        (
            "empty salt",
            with_line(base, "group_salt", ""),
            "seat list group_salt",
        ),
        (
            "salt charset",
            with_line(base, "group_salt", &GROUP_SALT.to_uppercase()),
            "seat list group_salt",
        ),
        ("lines out of order", swapped, "seat list label"),
        (
            "seats unsorted",
            with_line(base, "seats", &format!("{USER_B},{USER_A},{USER_C}")),
            "not sorted and unique",
        ),
    ];
    for (case, body, needle) in &cases {
        assert_ne!(body, base, "{case} changed nothing");
        assert_refused(SeatListBody::parse(body), needle, case);
    }

    // Format-valid: an empty authority line, `hidden`, a boundary with `wiped`
    for valid in [
        with_line(base, "authority", ""),
        with_line(base, "history", "hidden"),
        with_line(
            &with_line(base, "history_boundary", CID),
            "pre_history",
            "wiped",
        ),
    ] {
        assert!(SeatListBody::parse(&valid).is_ok(), "{valid}");
    }
}

#[test]
fn channel_authority_refuses_every_format_violation() {
    let base = TV2_AUTHORITY_BODY;
    let a = format!("{DEVICE_A}.{OWNER_IDENTITY_KEY}");
    let a2 = format!("{DEVICE_A2}.{NEW_OWNER_IDENTITY_KEY}");
    let entry = |user: &str, n: u32| format!("{user}.{}.{MEMBER_IDENTITY_KEY}", hex32(n));
    let joined = |entries: Vec<String>| entries.join(",");
    let hash = "ab".repeat(32);

    let cases: Vec<(&str, String, &str)> = vec![
        ("trailing LF", format!("{base}\n"), "exactly 13 lines"),
        ("CR", base.replacen('\n', "\r\n", 1), "contains CR"),
        (
            "12 lines",
            base.rsplit_once('\n').unwrap().0.to_string(),
            "exactly 13 lines",
        ),
        (
            "context",
            base.replace("sloga-channel-authority-v1", "sloga-channel-authority-v2"),
            "context or format version",
        ),
        (
            "format version",
            base.replace("\nv:1\n", "\nv:2\n"),
            "context or format version",
        ),
        (
            "over 3072 bytes",
            with_line(base, "delegates", &"x".repeat(3100)),
            "too long",
        ),
        (
            "label",
            base.replace("owner_user_id:", "owner_user:"),
            "authority label",
        ),
        (
            "channel charset",
            with_line(base, "channel_id", &CHANNEL.to_lowercase()),
            "authority channel_id",
        ),
        (
            "version 0",
            with_line(base, "version", "0"),
            "authority version",
        ),
        (
            "version leading zero",
            with_line(base, "version", "01"),
            "authority version",
        ),
        (
            "version above 2^53 - 1",
            with_line(base, "version", "9007199254740992"),
            "authority version",
        ),
        (
            "owner charset",
            with_line(base, "owner_user_id", &USER_A.to_lowercase()),
            "authority owner_user_id",
        ),
        (
            "signer device charset",
            with_line(base, "signer_device_id", &DEVICE_A.to_uppercase()),
            "authority signer_device_id",
        ),
        (
            "issued_at above 2^53 - 1",
            with_line(base, "issued_at", "9007199254740992"),
            "authority issued_at",
        ),
        (
            "no owner device",
            with_line(base, "owner_devices", ""),
            "owner_devices count",
        ),
        (
            "six owner devices",
            with_line(
                base,
                "owner_devices",
                &joined(
                    (0..6)
                        .map(|n| format!("{}.{OWNER_IDENTITY_KEY}", hex32(n)))
                        .collect(),
                ),
            ),
            "owner_devices count",
        ),
        (
            "owner devices unsorted",
            with_line(base, "owner_devices", &format!("{a2},{a}")),
            "owner_devices not sorted",
        ),
        (
            "owner device twice",
            with_line(
                base,
                "owner_devices",
                &format!("{a},{DEVICE_A}.{NEW_OWNER_IDENTITY_KEY}"),
            ),
            "device id twice",
        ),
        (
            "owner identity key twice",
            with_line(
                base,
                "owner_devices",
                &format!("{a},{DEVICE_A2}.{OWNER_IDENTITY_KEY}"),
            ),
            "owner identity key twice",
        ),
        (
            "signer device not an owner device",
            with_line(base, "signer_device_id", DEVICE_B),
            "no owner_devices entry",
        ),
        (
            "owner entry shape",
            with_line(base, "owner_devices", &format!("{USER_A}.{a}")),
            "entry shape",
        ),
        (
            "owner entry key",
            with_line(
                base,
                "owner_devices",
                &format!("{DEVICE_A}.{}", &OWNER_IDENTITY_KEY[..42]),
            ),
            "entry charset",
        ),
        (
            "empty entry",
            with_line(base, "owner_devices", &format!("{a},,{a2}")),
            "empty entry",
        ),
        (
            "owner as delegate",
            with_line(base, "delegates", &entry(USER_A, 1)),
            "names the owner",
        ),
        (
            "delegates unsorted",
            with_line(
                base,
                "delegates",
                &format!("{},{}", entry(USER_C, 2), entry(USER_B, 1)),
            ),
            "delegates not sorted",
        ),
        (
            "delegate device twice",
            with_line(
                base,
                "delegates",
                &format!("{},{}", entry(USER_B, 1), entry(USER_C, 1)),
            ),
            "device id twice",
        ),
        (
            "eleven delegates",
            with_line(
                base,
                "delegates",
                &joined((0..11).map(|n| entry(&numbered_user(n), n)).collect()),
            ),
            "too many entries",
        ),
        (
            "delegate entry shape",
            with_line(base, "delegates", &format!("{USER_B}.{DEVICE_B}")),
            "entry shape",
        ),
        (
            "delegate scope",
            with_line(base, "delegate_scope", "all"),
            "authority delegate_scope",
        ),
        (
            "empty delegate scope",
            with_line(base, "delegate_scope", ""),
            "authority delegate_scope",
        ),
        (
            "delegate cap above u32",
            with_line(base, "delegate_max_device_cap", "4294967296"),
            "delegate_max_device_cap",
        ),
        (
            "owner as successor",
            with_line(base, "successors", &entry(USER_A, 1)),
            "names the owner",
        ),
        (
            "six successor users",
            with_line(
                base,
                "successors",
                &joined((0..6).map(|n| entry(&numbered_user(n), n)).collect()),
            ),
            "more than 5 successor users",
        ),
        (
            "successors not contiguous",
            with_line(
                base,
                "successors",
                &format!(
                    "{},{},{}",
                    entry(USER_B, 1),
                    entry(USER_C, 2),
                    entry(USER_B, 3)
                ),
            ),
            "not contiguous",
        ),
        (
            "successor devices unsorted",
            with_line(
                base,
                "successors",
                &format!("{},{}", entry(USER_B, 2), entry(USER_B, 1)),
            ),
            "successor devices not sorted",
        ),
        (
            "eleven successors",
            with_line(
                base,
                "successors",
                &joined((0..11).map(|n| entry(&numbered_user(n / 3), n)).collect()),
            ),
            "too many entries",
        ),
        (
            "prev at version 1",
            with_line(base, "prev", &hash),
            "exactly at version 1",
        ),
        (
            "no prev at version 2",
            with_line(base, "version", "2"),
            "exactly at version 1",
        ),
        (
            "prev charset",
            with_line(
                &with_line(base, "version", "2"),
                "prev",
                &hash.to_uppercase(),
            ),
            "authority prev",
        ),
    ];
    for (case, body, needle) in &cases {
        assert_ne!(body, base, "{case} changed nothing");
        assert_refused(ChannelAuthority::parse(body), needle, case);
    }

    // The bounds are inclusive: 5 owner devices, 10 delegates, 5 successor
    // users with 2 devices each, the u32 cap, empty lists
    let five_owner_devices = joined(
        [
            (hex32(1), MEMBER_IDENTITY_KEY.to_string()),
            (hex32(2), identity_key_of(EXTRA1_SEED)),
            (hex32(3), identity_key_of(EXTRA2_SEED)),
            (DEVICE_A.to_string(), OWNER_IDENTITY_KEY.to_string()),
            (DEVICE_A2.to_string(), NEW_OWNER_IDENTITY_KEY.to_string()),
        ]
        .iter()
        .map(|(device, key)| format!("{device}.{key}"))
        .collect(),
    );
    let valid = [
        with_line(base, "owner_devices", &five_owner_devices),
        with_line(
            base,
            "delegates",
            &joined((0..10).map(|n| entry(&numbered_user(n), n)).collect()),
        ),
        with_line(
            base,
            "successors",
            &joined((0..10).map(|n| entry(&numbered_user(n / 2), n)).collect()),
        ),
        with_line(base, "delegate_max_device_cap", "4294967295"),
        with_line(&with_line(base, "delegates", ""), "successors", ""),
        with_line(
            &with_line(base, "version", "9007199254740991"),
            "prev",
            &hash,
        ),
    ];
    for body in &valid {
        assert!(ChannelAuthority::parse(body).is_ok(), "{body}");
    }
}

#[test]
fn text_group_id_v2_matches_the_5_8_vectors() {
    let input = text_group_id_v2_input(CHANNEL, 0, GROUP_SALT).unwrap();
    assert_eq!(input.len(), 91);
    assert_eq!(hex(&input), TV2_GROUP_ID_V2_INPUT_G0_HEX.concat());
    for (generation, expected) in [
        (0, TV2_GROUP_ID_V2_G0),
        (1, TV2_GROUP_ID_V2_G1),
        (64, TV2_GROUP_ID_V2_G64),
        (65_535, TV2_GROUP_ID_V2_G65535),
    ] {
        assert_eq!(
            text_group_id_v2(CHANNEL, generation, GROUP_SALT).unwrap(),
            expected,
            "g = {generation}"
        );
    }

    // The v1 derivation never stands in for a v2 id (3.1.1 control)
    assert_ne!(derived_group_id(CHANNEL, 0), TV2_GROUP_ID_V2_G0);

    assert_refused(
        text_group_id_v2(CHANNEL, 65_536, GROUP_SALT),
        "text group generation",
        "g = 65536",
    );
    assert_refused(
        text_group_id_v2(CHANNEL, 0, &GROUP_SALT.to_uppercase()),
        "text group salt",
        "uppercase salt",
    );
    assert_refused(
        text_group_id_v2(CHANNEL, 0, &GROUP_SALT[..62]),
        "text group salt",
        "short salt",
    );
    assert_refused(
        text_group_id_v2(&CHANNEL.to_lowercase(), 0, GROUP_SALT),
        "text group channel id",
        "lowercase channel",
    );
}

#[test]
fn commit_ad_v2_matches_the_5_8_vector() {
    let row = vector_v2_row();
    assert_eq!(row.handovers[0].signature, VECTOR_HANDOVER_SIGNATURE);

    let ad = row.commit_ad_v2().unwrap();
    assert_eq!(ad.len(), 1744);
    assert_eq!(hex(&ad), TV2_COMMIT_AD_V2_HEX.concat());
    assert_eq!(hex(&Sha256::digest(&ad)), TV2_COMMIT_AD_V2_SHA256);

    // `commit_ad` dispatches a v2 row to the v2 AD, and the group hash
    // follows it (3.12.1: `seat_list_ad_sha256` hashes the v2 bytes)
    assert!(row.is_v2());
    assert_eq!(row.commit_ad().unwrap(), ad);
    assert_eq!(row.commit_ad_sha256().unwrap(), TV2_COMMIT_AD_V2_SHA256);
}

/// v1 byte identity of the AD: an S1 row stays on the v1 AD (5.7), and a v1
/// row never carries an authority
#[test]
fn commit_ad_v1_rows_keep_the_s1_bytes_and_carry_no_authority() {
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
        authority: None,
    };
    assert!(!row.is_v2());
    assert_eq!(
        hex(&row.commit_ad().unwrap()),
        VECTOR_COMMIT_AD_HEX.concat()
    );
    assert_refused(
        row.commit_ad_v2(),
        "exactly 14 lines",
        "v1 row through the v2 AD",
    );

    let with_authority = SeatList {
        authority: vector_v2_row().authority,
        ..row
    };
    assert_refused(
        with_authority.commit_ad(),
        "carries no authority",
        "v1 row with an authority",
    );
}

#[test]
fn commit_ad_v2_refuses_an_authority_that_does_not_match_its_line() {
    let row = vector_v2_row();
    let no_line = SeatListBody {
        v2: Some(SeatListV2Lines {
            authority_sha256: None,
            ..vector_seat_list_v2("").v2.unwrap()
        }),
        ..vector_seat_list_v2("")
    }
    .build()
    .unwrap();

    let missing = SeatList {
        authority: None,
        ..row.clone()
    };
    assert_refused(missing.commit_ad_v2(), "disagree", "a line, no authority");

    let extra = SeatList {
        body: no_line.clone(),
        ..row.clone()
    };
    assert_refused(extra.commit_ad_v2(), "disagree", "an authority, no line");

    let mut other = row.clone();
    other.authority.as_mut().unwrap().body = ChannelAuthority::build(&ChannelAuthorityBody {
        issued_at: AUTHORITY_ISSUED_AT + 1,
        ..vector_authority()
    })
    .unwrap();
    assert_refused(
        other.commit_ad_v2(),
        "does not match the seat list",
        "authority hash differs from the line",
    );

    let mut short = row.clone();
    short.authority.as_mut().unwrap().signature = "AAAA".to_string();
    assert_refused(short.commit_ad_v2(), "signature length", "short signature");

    // Neither: two empty fields close the AD
    let neither = SeatList {
        body: no_line,
        authority: None,
        ..row
    };
    let ad = neither.commit_ad_v2().unwrap();
    assert_eq!(&ad[ad.len() - 4..], &[0, 0, 0, 0]);
}

/// 3.12.1: an AD of exactly 16383 bytes passes and one of 16384 is refused
#[test]
fn commit_ad_v2_is_refused_above_16383_bytes() {
    let mut row = vector_v2_row();
    row.handovers.clear();
    let base = row.commit_ad_v2().unwrap().len();

    row.handovers = filler_chain(base, MAX_COMMIT_AD_LEN);
    assert_eq!(row.commit_ad_v2().unwrap().len(), MAX_COMMIT_AD_LEN);

    row.handovers = filler_chain(base, MAX_COMMIT_AD_LEN + 1);
    assert_refused(row.commit_ad_v2(), "commit ad too long", "16384 bytes");
}

/// 3.12.1 / 5.8 worst case: authority 2836 bytes, list 3161, 16 succession
/// statements of 429, AD 14112 bytes and its SHA-256
#[test]
fn worst_case_commit_ad_v2_matches_the_5_8_vector() {
    let member_key = identity_key_of(MEMBER_SEED);
    let vector_authority_sha256 =
        ChannelAuthority::sha256(&ChannelAuthority::build(&vector_authority()).unwrap());

    let authority = ChannelAuthorityBody {
        channel_id: CHANNEL.to_string(),
        version: MAX_INT,
        owner_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        issued_at: MAX_INT,
        owner_devices: vec![
            owner_device(DEVICE_A, &identity_key_of(OWNER_SEED)),
            owner_device(DEVICE_A2, &identity_key_of(NEW_OWNER_SEED)),
            owner_device(&hex32(1), &member_key),
            owner_device(&hex32(2), &identity_key_of(EXTRA1_SEED)),
            owner_device(&hex32(3), &identity_key_of(EXTRA2_SEED)),
        ],
        delegates: (0..=9)
            .map(|i| user_device(&format!("01HZXD{i:020}"), &hex32(16 + i), &member_key))
            .collect(),
        delegate_max_device_cap: u32::MAX,
        successors: (0..=4)
            .flat_map(|u| {
                let user = format!("01HZXW{u:020}");
                [
                    user_device(&user, &hex32(32 + 2 * u), &member_key),
                    user_device(&user, &hex32(33 + 2 * u), &member_key),
                ]
            })
            .collect(),
        prev: Some(vector_authority_sha256),
    };
    let authority_body = ChannelAuthority::build(&authority).unwrap();
    assert_eq!(authority_body.len(), 2836);
    let authority_sha256 = ChannelAuthority::sha256(&authority_body);

    let mut seats = vec![USER_A.to_string()];
    seats.extend((0..=98).map(|i| format!("01HZXS{i:020}")));
    let list = SeatListBody {
        channel_id: CHANNEL.to_string(),
        version: MAX_INT,
        device_cap: u32::MAX,
        issued_at: MAX_INT,
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        seats,
        v2: Some(SeatListV2Lines {
            authority_sha256: Some(authority_sha256.clone()),
            history: SeatListHistory::Visible,
            history_boundary: Some(CID.to_string()),
            pre_history: SeatListPreHistory::Wiped,
            group_salt: GROUP_SALT.to_string(),
        }),
    };
    let list_body = list.build().unwrap();
    assert_eq!(list_body.len(), 3161);

    let chain: Vec<SignedHandover> = (0..=15)
        .map(|i| {
            let body = SuccessionStatement {
                channel_id: CHANNEL.to_string(),
                from_user_id: USER_A.to_string(),
                from_identity_key: identity_key_of(OWNER_SEED),
                to_user_id: format!("01HZXT{i:020}"),
                to_device_id: hex32(i),
                to_identity_key: member_key.clone(),
                authority_sha256: authority_sha256.clone(),
                rank: 5,
                issued_at: MAX_INT,
            }
            .build()
            .unwrap();
            assert_eq!(body.len(), 429);
            SignedHandover {
                signature: sign_b64(MEMBER_SEED, &body),
                body,
            }
        })
        .collect();

    let row = SeatList {
        id: CHANNEL.to_string(),
        version: MAX_INT,
        signature: sign_b64(OWNER_SEED, &list_body),
        body: list_body,
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        handovers: chain,
        updated_at: at(0),
        authority: Some(SignedAuthority {
            signature: sign_b64(OWNER_SEED, &authority_body),
            body: authority_body,
        }),
    };
    let ad = row.commit_ad_v2().unwrap();
    assert_eq!(ad.len().to_string(), TV2_WORST_COMMIT_AD_V2_LEN);
    assert_eq!(hex(&Sha256::digest(&ad)), TV2_WORST_COMMIT_AD_V2_SHA256);

    // Format-valid, but S2 refuses its boundary and `wiped` (4.3 step 4c)
    assert!(check_seat_list_v2_lines(&list, None).is_err());
}

fn vector_text_join() -> TextJoinPayload {
    TextJoinPayload {
        user_id: USER_B.to_string(),
        device_id: DEVICE_B.to_string(),
        channel_id: CHANNEL.to_string(),
        generation: JOIN_GENERATION,
        group_id: text_group_id_v2(CHANNEL, JOIN_GENERATION, GROUP_SALT).unwrap(),
        key_package_ref: JOIN_KEY_PACKAGE_REF.to_string(),
        issued_at: JOIN_ISSUED_AT,
    }
}

#[test]
fn text_join_payload_matches_the_5_8_vector() {
    let body = vector_text_join().build().unwrap();
    assert_eq!(body, TV2_TEXT_JOIN_BODY);
    assert_eq!(sign_b64(MEMBER_SEED, &body), TV2_TEXT_JOIN_SIGNATURE);
}

#[test]
fn text_join_payload_refuses_out_of_charset_inputs() {
    let good = vector_text_join();
    let cases: Vec<(&str, TextJoinPayload, &str)> = vec![
        (
            "generation 65536",
            TextJoinPayload {
                generation: 65_536,
                ..good.clone()
            },
            "text join generation",
        ),
        (
            "user charset",
            TextJoinPayload {
                user_id: USER_B.to_lowercase(),
                ..good.clone()
            },
            "text join user or channel id",
        ),
        (
            "channel charset",
            TextJoinPayload {
                channel_id: CHANNEL[..25].to_string(),
                ..good.clone()
            },
            "text join user or channel id",
        ),
        (
            "device charset",
            TextJoinPayload {
                device_id: DEVICE_B.to_uppercase(),
                ..good.clone()
            },
            "text join device id",
        ),
        (
            "group id charset",
            TextJoinPayload {
                group_id: good.group_id.to_uppercase(),
                ..good.clone()
            },
            "text join group id",
        ),
        (
            "empty key_package_ref",
            TextJoinPayload {
                key_package_ref: String::new(),
                ..good.clone()
            },
            "text join key_package_ref",
        ),
        (
            "key_package_ref separator",
            TextJoinPayload {
                key_package_ref: "a.b".to_string(),
                ..good.clone()
            },
            "text join key_package_ref",
        ),
        (
            "key_package_ref of 65 chars",
            TextJoinPayload {
                key_package_ref: "A".repeat(65),
                ..good.clone()
            },
            "text join key_package_ref",
        ),
        (
            "negative issued_at",
            TextJoinPayload {
                issued_at: -1,
                ..good.clone()
            },
            "text join issued_at",
        ),
        (
            "issued_at above 2^53 - 1",
            TextJoinPayload {
                issued_at: MAX_INT + 1,
                ..good.clone()
            },
            "text join issued_at",
        ),
    ];
    for (case, payload, needle) in cases {
        assert_refused(payload.build(), needle, case);
    }

    // The bounds are inclusive
    assert!(TextJoinPayload {
        generation: 65_535,
        issued_at: MAX_INT,
        key_package_ref: "A".repeat(64),
        ..good
    }
    .build()
    .is_ok());
}

fn vector_succession() -> SuccessionStatement {
    SuccessionStatement {
        channel_id: CHANNEL.to_string(),
        from_user_id: USER_A.to_string(),
        from_identity_key: identity_key_of(OWNER_SEED),
        to_user_id: USER_B.to_string(),
        to_device_id: DEVICE_B.to_string(),
        to_identity_key: identity_key_of(MEMBER_SEED),
        authority_sha256: ChannelAuthority::sha256(
            &ChannelAuthority::build(&vector_authority()).unwrap(),
        ),
        rank: SUCCESSION_RANK,
        issued_at: SUCCESSION_ISSUED_AT,
    }
}

#[test]
fn succession_statement_matches_the_5_8_vector() {
    let body = vector_succession().build().unwrap();
    assert_eq!(body, TV2_SUCCESSION_BODY);
    assert_eq!(sign_b64(MEMBER_SEED, &body), TV2_SUCCESSION_SIGNATURE);
    assert_eq!(
        SuccessionStatement::parse(TV2_SUCCESSION_BODY).unwrap(),
        vector_succession()
    );
}

#[test]
fn succession_statement_refuses_every_format_violation() {
    let base = TV2_SUCCESSION_BODY;
    let cases: Vec<(&str, String, &str)> = vec![
        ("trailing LF", format!("{base}\n"), "exactly 11 lines"),
        ("CR", base.replacen('\n', "\r\n", 1), "contains CR"),
        (
            "context",
            base.replace("sloga-owner-succession-v1", "sloga-owner-handover-v1"),
            "context or format version",
        ),
        (
            "format version",
            base.replace("\nv:1\n", "\nv:2\n"),
            "context or format version",
        ),
        (
            "over 1024 bytes",
            with_line(base, "to_identity_key", &"x".repeat(1100)),
            "too long",
        ),
        (
            "label",
            base.replace("\nrank:", "\nrnk:"),
            "succession label",
        ),
        ("rank 0", with_line(base, "rank", "0"), "succession rank"),
        ("rank 6", with_line(base, "rank", "6"), "succession rank"),
        (
            "rank leading zero",
            with_line(base, "rank", "01"),
            "succession rank",
        ),
        (
            "authority hash charset",
            with_line(
                base,
                "authority_sha256",
                &TV2_AUTHORITY_BODY_SHA256.to_uppercase(),
            ),
            "succession authority_sha256",
        ),
        (
            "device charset",
            with_line(base, "to_device_id", &DEVICE_B.to_uppercase()),
            "succession device id",
        ),
        (
            "key charset",
            with_line(base, "from_identity_key", &OWNER_IDENTITY_KEY[..42]),
            "succession identity key",
        ),
        (
            "user charset",
            with_line(base, "to_user_id", &USER_B.to_lowercase()),
            "succession user or channel id",
        ),
        (
            "issued_at above 2^53 - 1",
            with_line(base, "issued_at", "9007199254740992"),
            "succession issued_at",
        ),
    ];
    for (case, body, needle) in &cases {
        assert_ne!(body, base, "{case} changed nothing");
        assert_refused(SuccessionStatement::parse(body), needle, case);
    }
    assert!(SuccessionStatement::parse(&with_line(base, "rank", "5")).is_ok());
}

// --- 4.3 S2 rules: helpers ---------------------------------------------------

fn v2_lines(salt: &str) -> SeatListV2Lines {
    SeatListV2Lines {
        authority_sha256: None,
        history: SeatListHistory::Visible,
        history_boundary: None,
        pre_history: SeatListPreHistory::Kept,
        group_salt: salt.to_string(),
    }
}

/// A v2 body (signer A on `signer_device`)
fn v2_body_by(signer_device: &str, version: i64, seats: &[&str], lines: SeatListV2Lines) -> String {
    SeatListBody {
        channel_id: CHANNEL.to_string(),
        version,
        device_cap: 5,
        issued_at: 1_790_812_800_000,
        signer_user_id: USER_A.to_string(),
        signer_device_id: signer_device.to_string(),
        seats: seats.iter().map(|seat| seat.to_string()).collect(),
        v2: Some(lines),
    }
    .build()
    .unwrap()
}

fn v2_body(version: i64, seats: &[&str], lines: SeatListV2Lines) -> String {
    v2_body_by(DEVICE_A, version, seats, lines)
}

fn submit_v2(
    version: i64,
    seats: &[&str],
    lines: SeatListV2Lines,
    authority: Option<SignedAuthority>,
) -> SeatListSubmission {
    SeatListSubmission {
        body: v2_body(version, seats, lines),
        signature: signature(version),
        signer_device_id: DEVICE_A.to_string(),
        handover: None,
        authority,
    }
}

/// The stored row a submission would become (no chain)
fn stored_row(submission: &SeatListSubmission) -> SeatList {
    let body = SeatListBody::parse(&submission.body).unwrap();
    SeatList {
        id: CHANNEL.to_string(),
        version: body.version,
        body: submission.body.clone(),
        signer_user_id: body.signer_user_id,
        signer_device_id: body.signer_device_id,
        signature: submission.signature.clone(),
        handovers: vec![],
        updated_at: at(0),
        authority: submission.authority.clone(),
    }
}

fn active_seats(users: &[&str]) -> Vec<ChannelSeat> {
    users
        .iter()
        .map(|user| ChannelSeat {
            id: ChannelSeat::composite_id(CHANNEL, user),
            channel_id: CHANNEL.to_string(),
            user_id: user.to_string(),
            seated_at: at(0),
            released_at: None,
            cooldown_until: None,
            release_cause: None,
            keys_received_at: None,
        })
        .collect()
}

/// The planner as a driver calls it (no open Text group, claims allowed)
fn plan(
    kind: SeatListWriteKind,
    submission: &SeatListSubmission,
    stored: Option<&SeatList>,
    seats: &[ChannelSeat],
    formats_v2: bool,
) -> revolt_result::Result<SeatListWriteDecision> {
    let entitlement = entitlement(100);
    plan_seat_list_write(&SeatListWriteInput {
        kind,
        channel_id: CHANNEL,
        submission,
        stored,
        entitlement: Some(&entitlement),
        seats,
        text_group: None,
        allow_claims: true,
        formats_v2,
        now: at(1),
    })
}

fn applied(decision: SeatListWriteDecision) -> SeatListWritePlan {
    match decision {
        SeatListWriteDecision::Apply(plan) => plan,
        other => panic!("expected a write, got {other:?}"),
    }
}

// --- 4.3 step 1 (format; #218) -----------------------------------------------

#[test]
fn step1_protect_takes_a_v2_genesis_only_with_formats_v2_on() {
    let genesis = submit_v2(1, &[USER_A], v2_lines(GROUP_SALT), None);
    let landed = applied(plan(SeatListWriteKind::Protect, &genesis, None, &[], true).unwrap());
    assert!(landed.row.is_v2());
    assert_refused(
        plan(SeatListWriteKind::Protect, &genesis, None, &[], false),
        "a v2 genesis list needs formats_v2",
        "v2 genesis, flag off",
    );
}

#[test]
fn step1_protect_takes_a_v1_genesis_only_with_formats_v2_off() {
    let genesis = submit(1, &[USER_A]);
    let landed = applied(plan(SeatListWriteKind::Protect, &genesis, None, &[], false).unwrap());
    assert!(!landed.row.is_v2());
    assert_refused(
        plan(SeatListWriteKind::Protect, &genesis, None, &[], true),
        "must be v2 while formats_v2 is on",
        "v1 genesis, flag on",
    );
}

#[test]
fn step1_a_v1_list_never_replaces_a_v2_list() {
    let stored = stored_row(&submit_v2(1, &[USER_A, USER_B], v2_lines(GROUP_SALT), None));
    let seats = active_seats(&[USER_A, USER_B]);
    for formats_v2 in [false, true] {
        assert_refused(
            plan(
                SeatListWriteKind::Put,
                &submit(2, &[USER_A, USER_B]),
                Some(&stored),
                &seats,
                formats_v2,
            ),
            "a v1 seat list cannot replace a v2 list",
            &format!("v1 over v2, formats_v2 = {formats_v2}"),
        );
    }
}

/// #218: a channel already on v2 keeps v2 with the flag off: a removal-only
/// PUT lands and a byte-identical re-PUT answers its stored success
#[test]
fn step1_a_v2_channel_keeps_working_with_formats_v2_off() {
    let genesis = submit_v2(1, &[USER_A, USER_B], v2_lines(GROUP_SALT), None);
    let stored = stored_row(&genesis);
    let seats = active_seats(&[USER_A, USER_B]);

    let removal = submit_v2(2, &[USER_A], v2_lines(GROUP_SALT), None);
    let landed = applied(
        plan(
            SeatListWriteKind::Put,
            &removal,
            Some(&stored),
            &seats,
            false,
        )
        .unwrap(),
    );
    assert_eq!(landed.released, vec![USER_B.to_string()]);
    assert!(landed.row.is_v2());
    assert_eq!(
        landed.seat_list_ad_sha256,
        hex(&Sha256::digest(landed.row.commit_ad_v2().unwrap()))
    );

    assert!(matches!(
        plan(
            SeatListWriteKind::Put,
            &genesis,
            Some(&stored),
            &seats,
            false
        ),
        Ok(SeatListWriteDecision::Unchanged(_))
    ));
}

#[test]
fn step1_a_v1_to_v2_upgrade_needs_formats_v2() {
    let stored = stored_row(&submit(1, &[USER_A, USER_B]));
    let seats = active_seats(&[USER_A, USER_B]);
    let upgrade = submit_v2(2, &[USER_A, USER_B], v2_lines(GROUP_SALT), None);

    assert_refused(
        plan(
            SeatListWriteKind::Put,
            &upgrade,
            Some(&stored),
            &seats,
            false,
        ),
        "a v2 seat list over a v1 list needs formats_v2",
        "upgrade, flag off",
    );
    let landed = applied(
        plan(
            SeatListWriteKind::Put,
            &upgrade,
            Some(&stored),
            &seats,
            true,
        )
        .unwrap(),
    );
    assert!(landed.row.is_v2());

    // A v1 channel may stay on v1 with the flag on (#232)
    assert!(matches!(
        plan(
            SeatListWriteKind::Put,
            &submit(2, &[USER_A, USER_B]),
            Some(&stored),
            &seats,
            true
        ),
        Ok(SeatListWriteDecision::Apply(_))
    ));
}

// --- 4.3 step 3b (authority; #215, #225) -------------------------------------

/// An authority over the owner devices A and A2, signed by `signer_device_id`
fn test_authority(
    version: i64,
    signer_device_id: &str,
    prev: Option<String>,
) -> ChannelAuthorityBody {
    ChannelAuthorityBody {
        channel_id: CHANNEL.to_string(),
        version,
        owner_user_id: USER_A.to_string(),
        signer_device_id: signer_device_id.to_string(),
        issued_at: AUTHORITY_ISSUED_AT,
        owner_devices: vec![
            owner_device(DEVICE_A, OWNER_IDENTITY_KEY),
            owner_device(DEVICE_A2, NEW_OWNER_IDENTITY_KEY),
        ],
        delegates: vec![],
        delegate_max_device_cap: 0,
        successors: vec![],
        prev,
    }
}

fn signed_authority(authority: &ChannelAuthorityBody) -> SignedAuthority {
    SignedAuthority {
        body: ChannelAuthority::build(authority).unwrap(),
        signature: signature(authority.version),
    }
}

fn lines_naming(authority: &SignedAuthority) -> SeatListV2Lines {
    SeatListV2Lines {
        authority_sha256: Some(ChannelAuthority::sha256(&authority.body)),
        ..v2_lines(GROUP_SALT)
    }
}

/// A parsed v2 body signed by A's `signer_device`, naming `authority`
fn body_naming(
    version: i64,
    signer_device: &str,
    authority: Option<&SignedAuthority>,
) -> SeatListBody {
    let lines = authority
        .map(lines_naming)
        .unwrap_or_else(|| v2_lines(GROUP_SALT));
    SeatListBody::parse(&v2_body_by(signer_device, version, &[USER_A], lines)).unwrap()
}

/// A stored v2 row (version 1, by A's first device) carrying `authority`
fn stored_with(authority: Option<&SignedAuthority>) -> SeatList {
    SeatList {
        id: CHANNEL.to_string(),
        version: 1,
        body: body_naming(1, DEVICE_A, authority).build().unwrap(),
        signer_user_id: USER_A.to_string(),
        signer_device_id: DEVICE_A.to_string(),
        signature: signature(1),
        handovers: vec![],
        updated_at: at(0),
        authority: authority.cloned(),
    }
}

#[test]
fn step3b_a_first_authority_is_version_1_and_returns_the_signer_entry_key() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    let change = check_seat_list_authority(&body_naming(1, DEVICE_A, Some(&a1)), Some(&a1), None)
        .unwrap()
        .expect("a first authority is a change");
    assert_eq!(change.authority.version, 1);
    assert_eq!(change.signer_identity_key, OWNER_IDENTITY_KEY);

    // Over a stored v1 list (no authority) too; by the other owner device,
    // its entry's key is the one the route must check
    let v1 = stored_row(&submit(1, &[USER_A]));
    let by_a2 = signed_authority(&test_authority(1, DEVICE_A2, None));
    let change = check_seat_list_authority(
        &body_naming(2, DEVICE_A2, Some(&by_a2)),
        Some(&by_a2),
        Some(&v1),
    )
    .unwrap()
    .expect("a change");
    assert_eq!(change.signer_identity_key, NEW_OWNER_IDENTITY_KEY);

    // No line, no authority, nothing stored: nothing to check
    assert_eq!(
        check_seat_list_authority(&body_naming(1, DEVICE_A, None), None, None).unwrap(),
        None
    );
}

#[test]
fn step3b_a_non_empty_line_needs_its_authority() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    assert_refused(
        check_seat_list_authority(&body_naming(1, DEVICE_A, Some(&a1)), None, None),
        "line without an authority",
        "line, no authority",
    );
}

#[test]
fn step3b_an_authority_needs_its_line() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    assert_refused(
        check_seat_list_authority(&body_naming(1, DEVICE_A, None), Some(&a1), None),
        "authority without a seat list authority line",
        "v2 body with an empty line",
    );
    let v1 = SeatListBody::parse(&body_with(1, 1_790_812_800_000, &[USER_A])).unwrap();
    assert_refused(
        check_seat_list_authority(&v1, Some(&a1), None),
        "authority without a seat list authority line",
        "v1 body",
    );
}

#[test]
fn step3b_the_line_never_empties_over_a_stored_authority() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    assert_refused(
        check_seat_list_authority(
            &body_naming(2, DEVICE_A, None),
            None,
            Some(&stored_with(Some(&a1))),
        ),
        "drops the stored authority",
        "empty line over a stored authority",
    );
}

#[test]
fn step3b_the_authority_hashes_to_the_line() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    let other = signed_authority(&ChannelAuthorityBody {
        issued_at: AUTHORITY_ISSUED_AT + 1,
        ..test_authority(1, DEVICE_A, None)
    });
    assert_refused(
        check_seat_list_authority(&body_naming(1, DEVICE_A, Some(&a1)), Some(&other), None),
        "does not match the seat list authority line",
        "hash differs",
    );
}

#[test]
fn step3b_the_authority_names_the_route_channel() {
    let elsewhere = signed_authority(&ChannelAuthorityBody {
        channel_id: "01J9Z3K4M5N6P7Q8R9S0T1V2W4".to_string(),
        ..test_authority(1, DEVICE_A, None)
    });
    assert_refused(
        check_seat_list_authority(
            &body_naming(1, DEVICE_A, Some(&elsewhere)),
            Some(&elsewhere),
            None,
        ),
        "channel_id does not match",
        "another channel",
    );
}

#[test]
fn step3b_the_authority_owner_is_the_list_signer() {
    let foreign = signed_authority(&ChannelAuthorityBody {
        owner_user_id: USER_B.to_string(),
        ..test_authority(1, DEVICE_A, None)
    });
    assert_refused(
        check_seat_list_authority(
            &body_naming(1, DEVICE_A, Some(&foreign)),
            Some(&foreign),
            None,
        ),
        "owner is not the seat list signer",
        "another owner",
    );
}

#[test]
fn step3b_a_changed_authority_is_signed_by_the_list_signer_device() {
    let by_a2 = signed_authority(&test_authority(1, DEVICE_A2, None));
    assert_refused(
        check_seat_list_authority(&body_naming(1, DEVICE_A, Some(&by_a2)), Some(&by_a2), None),
        "signed by the list's signer device",
        "authority by A2 on a list by A",
    );
}

/// #225: a list from another listed owner device may carry the stored
/// authority unchanged; it is not a change and is not re-verified
#[test]
fn step3b_an_unchanged_authority_rides_on_another_owner_devices_list() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    let stored = stored_with(Some(&a1));
    assert_eq!(
        check_seat_list_authority(
            &body_naming(2, DEVICE_A2, Some(&a1)),
            Some(&a1),
            Some(&stored)
        )
        .unwrap(),
        None
    );

    // Same body, another signature: a change, refused (same version)
    let resigned = SignedAuthority {
        signature: signature(9),
        ..a1.clone()
    };
    assert_refused(
        check_seat_list_authority(
            &body_naming(2, DEVICE_A, Some(&resigned)),
            Some(&resigned),
            Some(&stored),
        ),
        "version must be the stored version + 1",
        "re-signed authority",
    );
}

#[test]
fn step3b_a_change_is_the_stored_version_plus_1() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    let stored = stored_with(Some(&a1));
    let after_a1 = Some(ChannelAuthority::sha256(&a1.body));

    let skipped = signed_authority(&test_authority(3, DEVICE_A, after_a1.clone()));
    let same_version = signed_authority(&ChannelAuthorityBody {
        issued_at: AUTHORITY_ISSUED_AT + 1,
        ..test_authority(1, DEVICE_A, None)
    });
    for (case, authority, stored) in [
        ("a skipped version", &skipped, Some(&stored)),
        (
            "the same version, another body",
            &same_version,
            Some(&stored),
        ),
        (
            "a first authority above version 1",
            &signed_authority(&test_authority(2, DEVICE_A, after_a1.clone())),
            None,
        ),
    ] {
        assert_refused(
            check_seat_list_authority(
                &body_naming(2, DEVICE_A, Some(authority)),
                Some(authority),
                stored,
            ),
            "version must be the stored version + 1",
            case,
        );
    }

    // Never lower: a stored version 3 refuses a version 2
    let a3 = signed_authority(&test_authority(3, DEVICE_A, Some("ab".repeat(32))));
    let lower = signed_authority(&test_authority(
        2,
        DEVICE_A,
        Some(ChannelAuthority::sha256(&a3.body)),
    ));
    assert_refused(
        check_seat_list_authority(
            &body_naming(2, DEVICE_A, Some(&lower)),
            Some(&lower),
            Some(&stored_with(Some(&a3))),
        ),
        "version must be the stored version + 1",
        "a lower version",
    );

    // The next version naming the stored body is accepted
    let a2 = signed_authority(&test_authority(2, DEVICE_A, after_a1));
    assert!(check_seat_list_authority(
        &body_naming(2, DEVICE_A, Some(&a2)),
        Some(&a2),
        Some(&stored)
    )
    .unwrap()
    .is_some());
}

#[test]
fn step3b_a_change_names_the_stored_authority_as_prev() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    let wrong_prev = signed_authority(&test_authority(2, DEVICE_A, Some("ab".repeat(32))));
    assert_refused(
        check_seat_list_authority(
            &body_naming(2, DEVICE_A, Some(&wrong_prev)),
            Some(&wrong_prev),
            Some(&stored_with(Some(&a1))),
        ),
        "prev must name the stored authority",
        "prev names another body",
    );
}

#[test]
fn step3b_the_authority_signature_is_64_bytes_of_b64() {
    let short = SignedAuthority {
        signature: "AAAA".to_string(),
        ..signed_authority(&test_authority(1, DEVICE_A, None))
    };
    assert_refused(
        check_seat_list_authority(&body_naming(1, DEVICE_A, Some(&short)), Some(&short), None),
        "signature length",
        "short signature",
    );
}

/// Step 3b runs in the planner, and the landed row carries the authority
/// its AD v2 binds
#[test]
fn step3b_runs_in_the_planner_and_the_row_carries_the_authority() {
    let a1 = signed_authority(&test_authority(1, DEVICE_A, None));
    let genesis = submit_v2(1, &[USER_A], lines_naming(&a1), Some(a1.clone()));
    let landed = applied(plan(SeatListWriteKind::Protect, &genesis, None, &[], true).unwrap());
    assert_eq!(landed.row.authority, Some(a1.clone()));
    let ad = landed.row.commit_ad_v2().unwrap();
    assert_eq!(landed.seat_list_ad_sha256, hex(&Sha256::digest(&ad)));
    assert!(ad.ends_with(&crate::decode_signature_b64(&a1.signature).unwrap()));

    let without = SeatListSubmission {
        authority: None,
        ..genesis
    };
    assert_refused(
        plan(SeatListWriteKind::Protect, &without, None, &[], true),
        "line without an authority",
        "planner, line without an authority",
    );
}

// --- 4.3 step 4c (immutable and one-way lines) -------------------------------

/// A stored v2 row with the given lines (a boundary or `wiped` row stands
/// for S4 data; S2 never writes one)
fn stored_v2(lines: SeatListV2Lines) -> SeatList {
    stored_row(&submit_v2(1, &[USER_A], lines, None))
}

fn next_v2(lines: SeatListV2Lines) -> SeatListBody {
    SeatListBody::parse(&v2_body(2, &[USER_A], lines)).unwrap()
}

fn with_boundary(lines: SeatListV2Lines, pre_history: SeatListPreHistory) -> SeatListV2Lines {
    SeatListV2Lines {
        history_boundary: Some(CID.to_string()),
        pre_history,
        ..lines
    }
}

#[test]
fn step4c_group_salt_is_immutable() {
    let stored = stored_v2(v2_lines(GROUP_SALT));
    assert_refused(
        check_seat_list_v2_lines(&next_v2(v2_lines(&"5".repeat(64))), Some(&stored)),
        "group_salt is immutable",
        "another salt",
    );
    assert!(check_seat_list_v2_lines(&next_v2(v2_lines(GROUP_SALT)), Some(&stored)).is_ok());
}

#[test]
fn step4c_history_boundary_is_immutable() {
    let stored = stored_v2(with_boundary(
        v2_lines(GROUP_SALT),
        SeatListPreHistory::Kept,
    ));
    assert_refused(
        check_seat_list_v2_lines(&next_v2(v2_lines(GROUP_SALT)), Some(&stored)),
        "history_boundary is immutable",
        "boundary dropped",
    );
}

#[test]
fn step4c_pre_history_never_goes_from_wiped_to_kept() {
    let stored = stored_v2(with_boundary(
        v2_lines(GROUP_SALT),
        SeatListPreHistory::Wiped,
    ));
    assert_refused(
        check_seat_list_v2_lines(&next_v2(v2_lines(GROUP_SALT)), Some(&stored)),
        "cannot go from wiped to kept",
        "wiped to kept",
    );
}

/// Until S4: `wiped` is refused on every path (genesis included), so `kept`
/// to `wiped` is refused on the PUT
#[test]
fn step4c_pre_history_wiped_is_refused_until_s4() {
    let wiped = next_v2(with_boundary(
        v2_lines(GROUP_SALT),
        SeatListPreHistory::Wiped,
    ));
    assert_refused(
        check_seat_list_v2_lines(&wiped, None),
        "pre_history wiped is refused until S4",
        "wiped genesis",
    );
    let stored = stored_v2(with_boundary(
        v2_lines(GROUP_SALT),
        SeatListPreHistory::Kept,
    ));
    assert_refused(
        check_seat_list_v2_lines(&wiped, Some(&stored)),
        "pre_history wiped is refused until S4",
        "kept to wiped",
    );
}

#[test]
fn step4c_history_boundary_is_refused_until_s4() {
    let boundary = next_v2(with_boundary(
        v2_lines(GROUP_SALT),
        SeatListPreHistory::Kept,
    ));
    assert_refused(
        check_seat_list_v2_lines(&boundary, None),
        "history_boundary is refused until S4",
        "boundary genesis",
    );
    let stored = stored_v2(with_boundary(
        v2_lines(GROUP_SALT),
        SeatListPreHistory::Kept,
    ));
    assert_refused(
        check_seat_list_v2_lines(&boundary, Some(&stored)),
        "history_boundary is refused until S4",
        "same boundary as stored",
    );
}

/// 4.1.1 / PA-18: a stored v1 list is the predecessor `{ authority: empty,
/// history: hidden, history_boundary: empty, pre_history: kept }`: any salt
/// and any `history` (#222), but no boundary
#[test]
fn step4c_a_stored_v1_list_is_the_v2_predecessor() {
    let stored = stored_row(&submit(1, &[USER_A]));
    for history in [SeatListHistory::Visible, SeatListHistory::Hidden] {
        let lines = SeatListV2Lines {
            history,
            ..v2_lines(&"5".repeat(64))
        };
        assert!(check_seat_list_v2_lines(&next_v2(lines), Some(&stored)).is_ok());
    }
    assert_refused(
        check_seat_list_v2_lines(
            &next_v2(with_boundary(
                v2_lines(GROUP_SALT),
                SeatListPreHistory::Kept,
            )),
            Some(&stored),
        ),
        "history_boundary is refused until S4",
        "a boundary over v1",
    );
}

#[test]
fn step4c_history_may_change_either_way() {
    for (from, to) in [
        (SeatListHistory::Visible, SeatListHistory::Hidden),
        (SeatListHistory::Hidden, SeatListHistory::Visible),
    ] {
        let stored = stored_v2(SeatListV2Lines {
            history: from,
            ..v2_lines(GROUP_SALT)
        });
        let next = next_v2(SeatListV2Lines {
            history: to,
            ..v2_lines(GROUP_SALT)
        });
        assert!(check_seat_list_v2_lines(&next, Some(&stored)).is_ok());
    }
}

/// 4c runs in the planner AFTER the byte-identical return of step 4
#[test]
fn step4c_runs_in_the_planner_after_the_retry_return() {
    let stored_submission = submit_v2(
        1,
        &[USER_A],
        with_boundary(v2_lines(GROUP_SALT), SeatListPreHistory::Kept),
        None,
    );
    let stored = stored_row(&stored_submission);
    let seats = active_seats(&[USER_A]);
    assert!(matches!(
        plan(
            SeatListWriteKind::Put,
            &stored_submission,
            Some(&stored),
            &seats,
            true
        ),
        Ok(SeatListWriteDecision::Unchanged(_))
    ));
    assert_refused(
        plan(
            SeatListWriteKind::Put,
            &submit_v2(2, &[USER_A], v2_lines(&"5".repeat(64)), None),
            Some(&stored),
            &seats,
            true,
        ),
        "group_salt is immutable",
        "planner, new salt",
    );
}

// --- 4.3 step 4d (removal reason) --------------------------------------------

#[test]
fn step4d_a_release_needs_a_non_empty_reason() {
    let released = vec![USER_B.to_string()];
    for reason in [None, Some(""), Some("  \t")] {
        let error = check_removal_reason(&released, reason).unwrap_err();
        assert!(
            matches!(error.error_type, ErrorType::RemovalReasonRequired),
            "{reason:?}"
        );
    }
    assert!(check_removal_reason(&released, Some("left the team")).is_ok());

    // Nothing released (a retry, a growth-only list): no reason needed
    assert!(check_removal_reason(&[], None).is_ok());
}

// --- 4.3 step 7 (`signer_lost`; #222, #224) ----------------------------------

/// An open Text group whose `signer_lost` names A's first device
fn signer_lost_group(members: &[&str]) -> MlsGroup {
    let mut group = text_group(0x07, &device(USER_A, DEVICE_A2), 1);
    group.members = members.iter().map(|id| device(USER_A, id)).collect();
    group.signer_lost = Some(MlsSignerLost {
        user_id: USER_A.to_string(),
        device_id: DEVICE_A.to_string(),
        cause: MlsSignerLostCause::DeviceRevoked,
        at: at(0),
    });
    group
}

/// An authority change by A2 whose `owner_devices` drops or keeps A
fn recovery_authority(keeps_lost: bool) -> ChannelAuthorityBody {
    let mut authority = test_authority(2, DEVICE_A2, Some("ab".repeat(32)));
    if !keeps_lost {
        authority
            .owner_devices
            .retain(|device| device.device_id != DEVICE_A);
    }
    authority
}

#[test]
fn step7_nothing_to_resolve_without_signer_lost() {
    let list = body_naming(2, DEVICE_A2, None);
    assert_eq!(
        resolve_signer_lost(None, &list, None, at(1)).unwrap(),
        SignerLostResolution::NotLost
    );
    let group = text_group(0x07, &device(USER_A, DEVICE_A), 1);
    assert_eq!(
        resolve_signer_lost(Some(&group), &list, None, at(1)).unwrap(),
        SignerLostResolution::NotLost
    );
}

#[test]
fn step7_another_device_without_an_authority_change_is_refused() {
    let group = signer_lost_group(&[DEVICE_A, DEVICE_A2]);
    let error = resolve_signer_lost(Some(&group), &body_naming(2, DEVICE_A2, None), None, at(1))
        .unwrap_err();
    assert!(is_resecuring(&error), "{error:?}");
}

#[test]
fn step7_an_authority_still_listing_the_lost_device_is_refused() {
    let group = signer_lost_group(&[DEVICE_A, DEVICE_A2]);
    let error = resolve_signer_lost(
        Some(&group),
        &body_naming(2, DEVICE_A2, None),
        Some(&recovery_authority(true)),
        at(1),
    )
    .unwrap_err();
    assert!(is_resecuring(&error), "{error:?}");
}

#[test]
fn step7_a_list_by_the_lost_device_itself_is_refused() {
    let group = signer_lost_group(&[DEVICE_A, DEVICE_A2]);
    let error = resolve_signer_lost(
        Some(&group),
        &body_naming(2, DEVICE_A, None),
        Some(&recovery_authority(false)),
        at(1),
    )
    .unwrap_err();
    assert!(is_resecuring(&error), "{error:?}");
}

#[test]
fn step7_a_qualifying_list_clears_and_queues_the_lost_leaf() {
    let group = signer_lost_group(&[DEVICE_A, DEVICE_A2]);
    assert_eq!(
        resolve_signer_lost(
            Some(&group),
            &body_naming(2, DEVICE_A2, None),
            Some(&recovery_authority(false)),
            at(1),
        )
        .unwrap(),
        SignerLostResolution::Clear {
            pending_device: Some(MlsPendingDeviceRemoval {
                user_id: USER_A.to_string(),
                device_id: DEVICE_A.to_string(),
                created_at: at(1),
            })
        }
    );
}

/// #224: a lost device that holds no leaf (a recovery successor) is only
/// cleared; an entry nobody can remove would freeze every send
#[test]
fn step7_a_lost_device_without_a_leaf_is_only_cleared() {
    let group = signer_lost_group(&[DEVICE_A2]);
    assert_eq!(
        resolve_signer_lost(
            Some(&group),
            &body_naming(2, DEVICE_A2, None),
            Some(&recovery_authority(false)),
            at(1),
        )
        .unwrap(),
        SignerLostResolution::Clear {
            pending_device: None
        }
    );
}

#[test]
fn step7_an_already_pending_lost_device_is_not_queued_twice() {
    let mut group = signer_lost_group(&[DEVICE_A, DEVICE_A2]);
    group.pending_device_removals = vec![MlsPendingDeviceRemoval {
        user_id: USER_A.to_string(),
        device_id: DEVICE_A.to_string(),
        created_at: at(0),
    }];
    assert_eq!(
        resolve_signer_lost(
            Some(&group),
            &body_naming(2, DEVICE_A2, None),
            Some(&recovery_authority(false)),
            at(1),
        )
        .unwrap(),
        SignerLostResolution::Clear {
            pending_device: None
        }
    );
}

// --- AD size in the planner (3.12.1) -----------------------------------------

#[test]
fn the_planner_refuses_a_row_whose_ad_v2_exceeds_16383_bytes() {
    let mut stored = stored_row(&submit_v2(1, &[USER_A], v2_lines(GROUP_SALT), None));
    let next = submit_v2(2, &[USER_A], v2_lines(GROUP_SALT), None);
    let base = stored_row(&next).commit_ad_v2().unwrap().len();
    let seats = active_seats(&[USER_A]);

    stored.handovers = filler_chain(base, MAX_COMMIT_AD_LEN);
    let landed =
        applied(plan(SeatListWriteKind::Put, &next, Some(&stored), &seats, false).unwrap());
    assert_eq!(landed.row.commit_ad().unwrap().len(), MAX_COMMIT_AD_LEN);

    stored.handovers = filler_chain(base, MAX_COMMIT_AD_LEN + 1);
    assert_refused(
        plan(SeatListWriteKind::Put, &next, Some(&stored), &seats, false),
        "commit ad too long",
        "16384-byte AD",
    );
}
