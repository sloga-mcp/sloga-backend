//! In-crate Rocket tests for the MLS delivery service (plan §2.6). Run
//! under both `TEST_DB=REFERENCE` and `TEST_DB=MONGODB`; the driver-level
//! concurrency matrix (create race, commit race, claim atomicity,
//! one-device CAS, supersedes, sweeps) lives in
//! `revolt-database::models::mls::tests`.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::Signer;
use revolt_database::{
    mls_credential_binding_payload, mls_join_intent_payload, Channel, E2EEContentType,
    E2EEEnvelope, Member, Session, User, E2EE_PROTOCOL_VERSION,
};
use revolt_models::v0;
use rocket::http::{ContentType, Header, Status};
use ulid::Ulid;

use crate::routes::e2ee::tests::{publish_device, TestDevice};
use crate::util::test::TestHarness;

/// A user's E2EE device plus its MLS signing material
pub struct MlsTestDevice {
    pub device: TestDevice,
    pub mls_signature_key: String,
}

impl MlsTestDevice {
    fn binding_signature(&self, user_id: &str) -> String {
        let identity_key =
            STANDARD_NO_PAD.encode(self.device.signing_key.verifying_key().as_bytes());
        let payload = mls_credential_binding_payload(
            user_id,
            &self.device.device_id,
            &self.mls_signature_key,
            &identity_key,
        );
        STANDARD_NO_PAD.encode(self.device.signing_key.sign(payload.as_bytes()).to_bytes())
    }

    fn join_signature(&self, user_id: &str, group_id: &str, key_package_ref: &str) -> String {
        let payload = mls_join_intent_payload(
            user_id,
            &self.device.device_id,
            group_id,
            key_package_ref,
        );
        STANDARD_NO_PAD.encode(self.device.signing_key.sign(payload.as_bytes()).to_bytes())
    }

    fn publish_body(
        &self,
        user_id: &str,
        refs: &[&str],
        last_resort: Option<&str>,
    ) -> v0::DataPublishMlsKeyPackages {
        v0::DataPublishMlsKeyPackages {
            device_id: self.device.device_id.clone(),
            mls_signature_key: self.mls_signature_key.clone(),
            binding_signature: self.binding_signature(user_id),
            key_packages: refs
                .iter()
                .map(|reference| v0::MlsKeyPackageUpload {
                    key_package_ref: reference.to_string(),
                    key_package: STANDARD_NO_PAD.encode(b"opaque key package bytes"),
                })
                .collect(),
            last_resort: last_resort.map(|reference| v0::MlsKeyPackageUpload {
                key_package_ref: reference.to_string(),
                key_package: STANDARD_NO_PAD.encode(b"opaque last resort bytes"),
            }),
        }
    }
}

fn group_id(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

/// Enroll an E2EE device for the user and publish MLS packages for it
async fn enroll_mls_device(
    harness: &TestHarness,
    account_id: &str,
    user_id: &str,
    session_token: &str,
    refs: &[&str],
    last_resort: Option<&str>,
) -> MlsTestDevice {
    let device = publish_device(harness, account_id, session_token, 1).await;
    let mls_device = MlsTestDevice {
        device,
        mls_signature_key: STANDARD_NO_PAD.encode([7u8; 32]),
    };

    // No MFA ticket: the device-bound session + verified credential binding
    // is the publish credential (publish-UX plan §3.1)
    let response = harness
        .client
        .put("/mls/key_packages")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session_token.to_string()))
        .body(serde_json::to_string(&mls_device.publish_body(user_id, refs, last_resort)).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok, "mls publish must succeed");

    mls_device
}

/// A server with a voice channel, owned by `owner`, with `member` added —
/// the stranger-co-member topology (plan §2.3): the two users share ONLY
/// this channel
async fn voice_channel_with_members(
    harness: &TestHarness,
    owner: &User,
    members: &[&User],
) -> Channel {
    let (server, _channels) = harness.new_server(owner).await;

    let channel = Channel::create_server_channel(
        &harness.db,
        &mut server.clone(),
        v0::DataCreateServerChannel {
            channel_type: v0::LegacyServerChannelType::Text,
            name: "Voice".to_string(),
            description: None,
            nsfw: Some(false),
            voice: Some(v0::VoiceInformation {
                max_users: None,
                disabled: false,
            }),
        },
        true,
    )
    .await
    .expect("voice channel");

    for member in members {
        Member::create(&harness.db, &server, member, None)
            .await
            .expect("member");
    }

    // Group creation requires call presence (plan §2.3 "is in the call
    // of"); the dev config defines LiveKit nodes, so the check is live in
    // tests — seed the Redis voice state the ingress would have written
    let voice_channel = revolt_database::voice::UserVoiceChannel::from_channel(&channel);
    for user in std::iter::once(owner).chain(members.iter().copied()) {
        revolt_database::voice::create_voice_state(
            &voice_channel,
            &user.id,
            iso8601_timestamp::Timestamp::now_utc(),
        )
        .await
        .expect("voice state");
    }

    channel
}

async fn post_json<'a>(
    harness: &'a TestHarness,
    session: &Session,
    uri: String,
    body: String,
) -> rocket::local::asynchronous::LocalResponse<'a> {
    harness
        .client
        .post(uri)
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(body)
        .dispatch()
        .await
}

#[rocket::async_test]
async fn full_flow_create_join_commit_fanout() {
    let mut harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    // A and B are STRANGERS sharing only a server voice channel — the
    // co-presence eligibility class is what admits them (plan §2.3)
    let channel = voice_channel_with_members(&harness, &user_a, &[&user_b]).await;

    let device_a = enroll_mls_device(
        &harness,
        &account_a.id,
        &user_a.id,
        &session_a.token,
        &["a0", "a1"],
        Some("alast"),
    )
    .await;
    let device_b = enroll_mls_device(
        &harness,
        &account_b.id,
        &user_b.id,
        &session_b.token,
        &["b0", "b1"],
        Some("blast"),
    )
    .await;

    // A registers the group. (Responses borrow the harness, so each request
    // is scoped — wait_for_event below needs &mut harness.)
    let gid = group_id(1);
    {
        let response = post_json(
            &harness,
            &session_a,
            "/mls/groups".to_string(),
            serde_json::to_string(&v0::DataCreateMlsGroup {
                group_id: gid.clone(),
                channel_id: channel.id().to_string(),
                device_id: device_a.device.device_id.clone(),
                supersedes: None,
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
    }

    // B racing with a DIFFERENT group id gets 409 carrying A's group id
    {
        let response = post_json(
            &harness,
            &session_b,
            "/mls/groups".to_string(),
            serde_json::to_string(&v0::DataCreateMlsGroup {
                group_id: group_id(2),
                channel_id: channel.id().to_string(),
                device_id: device_b.device.device_id.clone(),
                supersedes: None,
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::Conflict);
        match response.into_json::<v0::ResponseCreateMlsGroup>().await {
            Some(v0::ResponseCreateMlsGroup::Conflict {
                open_group_id,
                channel_id,
            }) => {
                assert_eq!(open_group_id, gid);
                // The DS asserts the open group's channel — the client's T-15
                // guard compares this against its route-truth channel (H2)
                assert_eq!(channel_id, channel.id().to_string());
            }
            other => panic!("expected conflict body, got {other:?}"),
        }
    }

    // B signals join intent (signed) — members receive MlsJoinRequested
    {
        let response = post_json(
            &harness,
            &session_b,
            format!("/mls/groups/{gid}/join_intent"),
            serde_json::to_string(&v0::DataMlsJoinIntent {
                device_id: device_b.device.device_id.clone(),
                key_package_ref: "b0".to_string(),
                signature: device_b.join_signature(&user_b.id, &gid, "b0"),
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
    }

    let event = harness
        .wait_for_event(&format!("{}!", user_a.id), |event| {
            matches!(
                event,
                revolt_database::events::client::EventV1::MlsJoinRequested { .. }
            )
        })
        .await;
    if let revolt_database::events::client::EventV1::MlsJoinRequested {
        group_id: event_group,
        user_id: event_user,
        key_package_ref,
        rejoin,
        ..
    } = event
    {
        assert_eq!(event_group, gid);
        assert_eq!(event_user, user_b.id);
        assert_eq!(key_package_ref, "b0");
        assert!(!rejoin, "a non-member's intent is a normal join");
    }

    // A (stranger co-member) claims B's KeyPackage — the co-presence class
    let response = post_json(
        &harness,
        &session_a,
        "/mls/key_packages/claim".to_string(),
        serde_json::to_string(&v0::DataClaimMlsKeyPackages {
            device_id: device_a.device.device_id.clone(),
            group_id: gid.clone(),
            targets: vec![v0::MlsMemberDevice {
                user_id: user_b.id.clone(),
                device_id: device_b.device.device_id.clone(),
            }],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponseClaimMlsKeyPackages = response.into_json().await.unwrap();
    assert_eq!(body.results.len(), 1);
    match &body.results[0].status {
        v0::MlsClaimStatus::Claimed { reused, .. } => assert!(!*reused),
        other => panic!("expected claim, got {other:?}"),
    }

    // A commits epoch 1 adding B, with a Welcome
    let commit_body = |payload: &str| {
        serde_json::to_string(&v0::DataSubmitMlsCommit {
            device_id: device_a.device.device_id.clone(),
            epoch: 1,
            commit: STANDARD_NO_PAD.encode(payload.as_bytes()),
            welcome: Some(STANDARD_NO_PAD.encode(b"welcome bytes")),
            added: vec![v0::MlsMemberDevice {
                user_id: user_b.id.clone(),
                device_id: device_b.device.device_id.clone(),
            }],
            removed: vec![],
        })
        .unwrap()
    };

    let response = post_json(
        &harness,
        &session_a,
        format!("/mls/groups/{gid}/commits"),
        commit_body("commit one"),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // Fan-out set correctness: B's device got the WELCOME (a joiner cannot
    // read a commit for a group it is not in yet); A, the committer, got
    // nothing
    let envelopes_b = harness
        .db
        .fetch_e2ee_envelopes(&user_b.id, &device_b.device.device_id, 10)
        .await
        .unwrap();
    assert_eq!(envelopes_b.len(), 1);
    assert!(matches!(
        envelopes_b[0].content_type,
        E2EEContentType::MlsWelcome
    ));
    assert_eq!(envelopes_b[0].group_id.as_deref(), Some(gid.as_str()));
    assert_eq!(envelopes_b[0].epoch, Some(1));

    let envelopes_a = harness
        .db
        .fetch_e2ee_envelopes(&user_a.id, &device_a.device.device_id, 10)
        .await
        .unwrap();
    assert!(envelopes_a.is_empty());

    // A re-submitting epoch 1 loses: 409 + the winning commit bytes
    let response = post_json(
        &harness,
        &session_a,
        format!("/mls/groups/{gid}/commits"),
        commit_body("commit one prime"),
    )
    .await;
    assert_eq!(response.status(), Status::Conflict);
    match response.into_json::<v0::ResponseSubmitMlsCommit>().await {
        Some(v0::ResponseSubmitMlsCommit::Lost { winning }) => {
            assert_eq!(winning.epoch, 1);
            assert_eq!(
                winning.commit,
                STANDARD_NO_PAD.encode(b"commit one".as_slice())
            );
        }
        other => panic!("expected lost body, got {other:?}"),
    }

    // B (now a member) commits epoch 2 removing itself — commit envelope
    // goes to A's device
    let response = post_json(
        &harness,
        &session_b,
        format!("/mls/groups/{gid}/commits"),
        serde_json::to_string(&v0::DataSubmitMlsCommit {
            device_id: device_b.device.device_id.clone(),
            epoch: 2,
            commit: STANDARD_NO_PAD.encode(b"commit two"),
            welcome: None,
            added: vec![],
            removed: vec![v0::MlsMemberDevice {
                user_id: user_b.id.clone(),
                device_id: device_b.device.device_id.clone(),
            }],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    let envelopes_a = harness
        .db
        .fetch_e2ee_envelopes(&user_a.id, &device_a.device.device_id, 10)
        .await
        .unwrap();
    assert_eq!(envelopes_a.len(), 1);
    assert!(matches!(
        envelopes_a[0].content_type,
        E2EEContentType::MlsCommit
    ));
    assert_eq!(envelopes_a[0].epoch, Some(2));

    // Gap refetch returns both commits ascending, with the current epoch —
    // for A, who is still a group member
    let response = harness
        .client
        .get(format!("/mls/groups/{gid}/commits?from_epoch=1"))
        .header(Header::new("x-session-token", session_a.token.clone()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponseFetchMlsCommits = response.into_json().await.unwrap();
    assert_eq!(body.current_epoch, 2);
    assert_eq!(body.commits.len(), 2);
    assert_eq!(body.commits[0].epoch, 1);
    assert_eq!(body.commits[1].epoch, 2);
    assert_eq!(body.commits[1].committer.user_id, user_b.id);

    // B was removed at epoch 2: though B still has channel access, B is no
    // longer a group MEMBER and must NOT be able to read the per-device
    // roster history — NotFound, not the commit metadata (gate finding 1,
    // device ids stay off channel co-members §3.5)
    let response = harness
        .client
        .get(format!("/mls/groups/{gid}/commits?from_epoch=0"))
        .header(Header::new("x-session-token", session_b.token.clone()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NotFound);
}

#[rocket::async_test]
async fn rejoin_affordance_flags_and_solo_close() {
    let mut harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    let channel = voice_channel_with_members(&harness, &user_a, &[&user_b]).await;
    let device_a = enroll_mls_device(
        &harness,
        &account_a.id,
        &user_a.id,
        &session_a.token,
        &["a0"],
        Some("alast"),
    )
    .await;
    let device_b = enroll_mls_device(
        &harness,
        &account_b.id,
        &user_b.id,
        &session_b.token,
        &["b0"],
        Some("blast"),
    )
    .await;

    // A registers the group and commits epoch 1 adding B (the DS commit
    // route does not require a prior intent — B being a MEMBER is the
    // precondition the rejoin arm keys on, and skipping the HTTP intent
    // keeps B's rejoin below outside the per-device intent slowmode).
    let gid = group_id(3);
    {
        let response = post_json(
            &harness,
            &session_a,
            "/mls/groups".to_string(),
            serde_json::to_string(&v0::DataCreateMlsGroup {
                group_id: gid.clone(),
                channel_id: channel.id().to_string(),
                device_id: device_a.device.device_id.clone(),
                supersedes: None,
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
    }
    {
        let response = post_json(
            &harness,
            &session_a,
            format!("/mls/groups/{gid}/commits"),
            serde_json::to_string(&v0::DataSubmitMlsCommit {
                device_id: device_a.device.device_id.clone(),
                epoch: 1,
                commit: STANDARD_NO_PAD.encode(b"add b"),
                welcome: Some(STANDARD_NO_PAD.encode(b"welcome b")),
                added: vec![v0::MlsMemberDevice {
                    user_id: user_b.id.clone(),
                    device_id: device_b.device.device_id.clone(),
                }],
                removed: vec![],
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
    }

    // B — already a member (stale leaf after a local rejoin-fresh) —
    // signals join intent again: accepted (204, NOT the old 400) and fanned
    // out flagged `rejoin` so verifying members remove the stale leaf.
    {
        let response = post_json(
            &harness,
            &session_b,
            format!("/mls/groups/{gid}/join_intent"),
            serde_json::to_string(&v0::DataMlsJoinIntent {
                device_id: device_b.device.device_id.clone(),
                key_package_ref: "b0".to_string(),
                signature: device_b.join_signature(&user_b.id, &gid, "b0"),
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
    }
    let event = harness
        .wait_for_event(&format!("{}!", user_a.id), |event| {
            matches!(
                event,
                revolt_database::events::client::EventV1::MlsJoinRequested { .. }
            )
        })
        .await;
    if let revolt_database::events::client::EventV1::MlsJoinRequested {
        user_id: event_user,
        device_id: event_device,
        rejoin,
        ..
    } = event
    {
        assert_eq!(event_user, user_b.id);
        assert_eq!(event_device, device_b.device.device_id);
        assert!(rejoin, "an already-member device's intent is a rejoin");
    }

    // Solo-stale: A is the SOLE member of a fresh group on a second channel
    // and rejoins it — nobody can serve the rejoin (no other leaf-holder),
    // so the DS closes the group instead of fanning out.
    let solo_channel = voice_channel_with_members(&harness, &user_a, &[]).await;
    let solo_gid = group_id(4);
    {
        let response = post_json(
            &harness,
            &session_a,
            "/mls/groups".to_string(),
            serde_json::to_string(&v0::DataCreateMlsGroup {
                group_id: solo_gid.clone(),
                channel_id: solo_channel.id().to_string(),
                device_id: device_a.device.device_id.clone(),
                supersedes: None,
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
    }
    {
        let response = post_json(
            &harness,
            &session_a,
            format!("/mls/groups/{solo_gid}/join_intent"),
            serde_json::to_string(&v0::DataMlsJoinIntent {
                device_id: device_a.device.device_id.clone(),
                key_package_ref: "a0".to_string(),
                signature: device_a.join_signature(&user_a.id, &solo_gid, "a0"),
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
    }
    // The group is now CLOSED: a further intent 404s (open == false), which
    // the joiner surfaces as `not_found` → re-establish → CREATE path.
    {
        let response = post_json(
            &harness,
            &session_a,
            format!("/mls/groups/{solo_gid}/join_intent"),
            serde_json::to_string(&v0::DataMlsJoinIntent {
                device_id: device_a.device.device_id.clone(),
                key_package_ref: "a0".to_string(),
                signature: device_a.join_signature(&user_a.id, &solo_gid, "a0"),
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), Status::NotFound);
    }
}

#[rocket::async_test]
async fn voice_participant_identity_mapping_round_trips() {
    use revolt_database::voice::{
        clear_voice_participant_identities, delete_voice_participant_identity,
        get_voice_participant_identity, set_voice_participant_identity,
    };

    let _harness = TestHarness::new().await;
    let channel = format!("channel_{}", TestHarness::rand_string());
    let user = "01KX7HASD9FHBYA3XGKA5YACYX";
    let device = "4208aa7e9ff58761b2d7a5d6c45f7383";
    let identity = format!("{user}:{device}");

    // Absent mapping → bare user id (correct for non-E2EE participants;
    // logged for device-qualified ones)
    assert_eq!(
        get_voice_participant_identity(&channel, user).await.unwrap(),
        user
    );

    // Ingress records the device-qualified identity on join
    set_voice_participant_identity(&channel, user, &identity)
        .await
        .unwrap();
    assert_eq!(
        get_voice_participant_identity(&channel, user).await.unwrap(),
        identity
    );

    // Cleared on leave → back to the bare fallback
    delete_voice_participant_identity(&channel, user)
        .await
        .unwrap();
    assert_eq!(
        get_voice_participant_identity(&channel, user).await.unwrap(),
        user
    );

    // room_finished wipes the whole channel map (backstop for missed leaves)
    set_voice_participant_identity(&channel, user, &identity)
        .await
        .unwrap();
    clear_voice_participant_identities(&channel).await.unwrap();
    assert_eq!(
        get_voice_participant_identity(&channel, user).await.unwrap(),
        user
    );
}

#[rocket::async_test]
async fn strangers_without_shared_channel_cannot_claim_or_create() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;
    let (account_c, session_c, user_c) = harness.new_user().await;

    // A and B share a voice channel; C is a total stranger
    let channel = voice_channel_with_members(&harness, &user_a, &[&user_b]).await;

    let device_a = enroll_mls_device(
        &harness,
        &account_a.id,
        &user_a.id,
        &session_a.token,
        &["a0"],
        None,
    )
    .await;
    let device_b = enroll_mls_device(
        &harness,
        &account_b.id,
        &user_b.id,
        &session_b.token,
        &["b0"],
        None,
    )
    .await;
    let device_c = enroll_mls_device(
        &harness,
        &account_c.id,
        &user_c.id,
        &session_c.token,
        &["c0"],
        None,
    )
    .await;

    let gid = group_id(1);
    let response = post_json(
        &harness,
        &session_a,
        "/mls/groups".to_string(),
        serde_json::to_string(&v0::DataCreateMlsGroup {
            group_id: gid.clone(),
            channel_id: channel.id().to_string(),
            device_id: device_a.device.device_id.clone(),
            supersedes: None,
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // C cannot create a group in a channel it cannot see
    let response = post_json(
        &harness,
        &session_c,
        "/mls/groups".to_string(),
        serde_json::to_string(&v0::DataCreateMlsGroup {
            group_id: group_id(3),
            channel_id: channel.id().to_string(),
            device_id: device_c.device.device_id.clone(),
            supersedes: None,
        })
        .unwrap(),
    )
    .await;
    assert_ne!(response.status(), Status::Ok);
    assert_ne!(response.status(), Status::Conflict);

    // C cannot claim against the group either (no channel access)
    let response = post_json(
        &harness,
        &session_c,
        "/mls/key_packages/claim".to_string(),
        serde_json::to_string(&v0::DataClaimMlsKeyPackages {
            device_id: device_c.device.device_id.clone(),
            group_id: gid.clone(),
            targets: vec![v0::MlsMemberDevice {
                user_id: user_b.id.clone(),
                device_id: device_b.device.device_id.clone(),
            }],
        })
        .unwrap(),
    )
    .await;
    assert_ne!(response.status(), Status::Ok);

    // B claiming C (co-member claiming a NON-member stranger with no shared
    // channel/DM eligibility) is refused per target — NotFound, not a probe.
    // (The Reference driver's mutual queries were `todo!()` panics until the
    // 6.1 crypto gate; both drivers now fail closed here.)
    let response = post_json(
        &harness,
        &session_b,
        "/mls/key_packages/claim".to_string(),
        serde_json::to_string(&v0::DataClaimMlsKeyPackages {
            device_id: device_b.device.device_id.clone(),
            group_id: gid.clone(),
            targets: vec![v0::MlsMemberDevice {
                user_id: user_c.id.clone(),
                device_id: device_c.device.device_id.clone(),
            }],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponseClaimMlsKeyPackages = response.into_json().await.unwrap();
    assert!(matches!(
        body.results[0].status,
        v0::MlsClaimStatus::NotFound
    ));
}

#[rocket::async_test]
async fn blocked_pair_in_shared_channel_cannot_claim() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    let channel = voice_channel_with_members(&harness, &user_a, &[&user_b]).await;

    let device_a = enroll_mls_device(
        &harness,
        &account_a.id,
        &user_a.id,
        &session_a.token,
        &["a0"],
        None,
    )
    .await;
    let device_b = enroll_mls_device(
        &harness,
        &account_b.id,
        &user_b.id,
        &session_b.token,
        &["b0"],
        None,
    )
    .await;

    let gid = group_id(1);
    let response = post_json(
        &harness,
        &session_a,
        "/mls/groups".to_string(),
        serde_json::to_string(&v0::DataCreateMlsGroup {
            group_id: gid.clone(),
            channel_id: channel.id().to_string(),
            device_id: device_a.device.device_id.clone(),
            supersedes: None,
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // A blocks B — claim is FETCH-like, so the blocked pair is refused even
    // though they share the channel (slice-5 deliver-vs-fetch asymmetry)
    user_a
        .clone()
        .apply_relationship(
            &harness.db,
            &mut user_b.clone(),
            revolt_database::RelationshipStatus::Blocked,
            revolt_database::RelationshipStatus::BlockedOther,
        )
        .await
        .expect("block");

    let response = post_json(
        &harness,
        &session_a,
        "/mls/key_packages/claim".to_string(),
        serde_json::to_string(&v0::DataClaimMlsKeyPackages {
            device_id: device_a.device.device_id.clone(),
            group_id: gid.clone(),
            targets: vec![v0::MlsMemberDevice {
                user_id: user_b.id.clone(),
                device_id: device_b.device.device_id.clone(),
            }],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponseClaimMlsKeyPackages = response.into_json().await.unwrap();
    assert!(matches!(
        body.results[0].status,
        v0::MlsClaimStatus::NotFound
    ));
}

#[rocket::async_test]
async fn publish_validates_binding_caps_and_immutability() {
    let harness = TestHarness::new().await;
    let (account, session, user) = harness.new_user().await;

    let e2ee_device = publish_device(&harness, &account.id, &session.token, 1).await;
    let mls_device = MlsTestDevice {
        device: e2ee_device,
        mls_signature_key: STANDARD_NO_PAD.encode([7u8; 32]),
    };

    // Tampered binding signature is refused
    let mut body = mls_device.publish_body(&user.id, &["k0"], None);
    body.binding_signature = STANDARD_NO_PAD.encode([0u8; 64]);
    let response = harness
        .client
        .put("/mls/key_packages")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&body).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);

    // Valid FIRST publish needs no MFA ticket (publish-UX plan §3.1): the
    // device-bound session + verified credential binding is the credential.
    // A stray X-MFA-Ticket header from an older client is simply ignored —
    // it must never fail the request.
    let response = harness
        .client
        .put("/mls/key_packages")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-MFA-Ticket", "stray-legacy-ticket"))
        .body(
            serde_json::to_string(&mls_device.publish_body(&user.id, &["k0", "k1"], Some("lr")))
                .unwrap(),
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // Replenish; upsert-aware accounting: same refs don't double-count
    let response = post_put_publish(&harness, &session, &mls_device, &user.id, &["k0", "k2"], None)
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponsePublishMlsKeyPackages = response.into_json().await.unwrap();
    assert_eq!(body.key_package_count, 3, "k0 replaced in place, k2 added");

    // The MLS signature key is immutable while packages are stored
    let impostor = MlsTestDevice {
        device: TestDevice {
            signing_key: mls_device.device.signing_key.clone(),
            device_id: mls_device.device.device_id.clone(),
            curve25519_key: mls_device.device.curve25519_key.clone(),
        },
        mls_signature_key: STANDARD_NO_PAD.encode([9u8; 32]),
    };
    let response = post_put_publish(&harness, &session, &impostor, &user.id, &["k9"], None).await;
    assert_eq!(response.status(), Status::BadRequest);

    // Cap self-heal (publish-UX plan §3.4): pushing past MAX_KEY_PACKAGES
    // prunes the device's oldest packages instead of refusing — the fresh
    // batch survives intact and the count converges on the cap
    let too_many: Vec<String> = (0..99).map(|i| format!("bulk{i}")).collect();
    let refs: Vec<&str> = too_many.iter().map(String::as_str).collect();
    let response = post_put_publish(&harness, &session, &mls_device, &user.id, &refs, None).await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponsePublishMlsKeyPackages = response.into_json().await.unwrap();
    assert_eq!(
        body.key_package_count, 100,
        "prune converges on MAX_KEY_PACKAGES"
    );

    // A single batch that ALONE exceeds the cap is still structurally refused
    // (no amount of pruning makes room for it)
    let way_too_many: Vec<String> = (0..101).map(|i| format!("flood{i}")).collect();
    let refs: Vec<&str> = way_too_many.iter().map(String::as_str).collect();
    let response = post_put_publish(&harness, &session, &mls_device, &user.id, &refs, None).await;
    assert_eq!(response.status(), Status::BadRequest);
}

async fn post_put_publish<'a>(
    harness: &'a TestHarness,
    session: &Session,
    device: &MlsTestDevice,
    user_id: &str,
    refs: &[&str],
    last_resort: Option<&str>,
) -> rocket::local::asynchronous::LocalResponse<'a> {
    harness
        .client
        .put("/mls/key_packages")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&device.publish_body(user_id, refs, last_resort)).unwrap())
        .dispatch()
        .await
}

#[rocket::async_test]
async fn join_intent_signature_one_device_and_rate_limit() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    let channel = voice_channel_with_members(&harness, &user_a, &[&user_b]).await;

    let device_a = enroll_mls_device(
        &harness,
        &account_a.id,
        &user_a.id,
        &session_a.token,
        &["a0"],
        None,
    )
    .await;
    let device_b = enroll_mls_device(
        &harness,
        &account_b.id,
        &user_b.id,
        &session_b.token,
        &["b0"],
        None,
    )
    .await;

    let gid = group_id(1);
    let response = post_json(
        &harness,
        &session_a,
        "/mls/groups".to_string(),
        serde_json::to_string(&v0::DataCreateMlsGroup {
            group_id: gid.clone(),
            channel_id: channel.id().to_string(),
            device_id: device_a.device.device_id.clone(),
            supersedes: None,
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // Forged signature is refused (defense in depth)
    let response = post_json(
        &harness,
        &session_b,
        format!("/mls/groups/{gid}/join_intent"),
        serde_json::to_string(&v0::DataMlsJoinIntent {
            device_id: device_b.device.device_id.clone(),
            key_package_ref: "b0".to_string(),
            signature: STANDARD_NO_PAD.encode([0u8; 64]),
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::BadRequest);

    // A member's OWN device signalling intent is refused (one-device rule:
    // the creator's user already has a live leaf)
    let second_device = enroll_mls_device(
        &harness,
        &account_a.id,
        &user_a.id,
        &session_a.token,
        &["a20"],
        None,
    )
    .await;
    let response = post_json(
        &harness,
        &session_a,
        format!("/mls/groups/{gid}/join_intent"),
        serde_json::to_string(&v0::DataMlsJoinIntent {
            device_id: second_device.device.device_id.clone(),
            key_package_ref: "a20".to_string(),
            signature: second_device.join_signature(&user_a.id, &gid, "a20"),
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::BadRequest);

    // Valid intent works once, then rapid re-broadcast is rate-limited
    let intent = serde_json::to_string(&v0::DataMlsJoinIntent {
        device_id: device_b.device.device_id.clone(),
        key_package_ref: "b0".to_string(),
        signature: device_b.join_signature(&user_b.id, &gid, "b0"),
    })
    .unwrap();

    let response = post_json(
        &harness,
        &session_b,
        format!("/mls/groups/{gid}/join_intent"),
        intent.clone(),
    )
    .await;
    assert_eq!(response.status(), Status::NoContent);

    let response = post_json(
        &harness,
        &session_b,
        format!("/mls/groups/{gid}/join_intent"),
        intent,
    )
    .await;
    assert_eq!(response.status(), Status::TooManyRequests);
}

#[rocket::async_test]
async fn commit_size_caps_and_welcome_pairing() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    let channel = voice_channel_with_members(&harness, &user_a, &[&user_b]).await;

    let device_a = enroll_mls_device(
        &harness,
        &account_a.id,
        &user_a.id,
        &session_a.token,
        &["a0"],
        None,
    )
    .await;
    let device_b = enroll_mls_device(
        &harness,
        &account_b.id,
        &user_b.id,
        &session_b.token,
        &["b0"],
        None,
    )
    .await;

    let gid = group_id(1);
    let response = post_json(
        &harness,
        &session_a,
        "/mls/groups".to_string(),
        serde_json::to_string(&v0::DataCreateMlsGroup {
            group_id: gid.clone(),
            channel_id: channel.id().to_string(),
            device_id: device_a.device.device_id.clone(),
            supersedes: None,
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    let added_b = vec![v0::MlsMemberDevice {
        user_id: user_b.id.clone(),
        device_id: device_b.device.device_id.clone(),
    }];

    // Oversized commit (over the 64 KiB raw budget) is refused
    let response = post_json(
        &harness,
        &session_a,
        format!("/mls/groups/{gid}/commits"),
        serde_json::to_string(&v0::DataSubmitMlsCommit {
            device_id: device_a.device.device_id.clone(),
            epoch: 1,
            commit: "A".repeat(super::encoded_len(super::MAX_MLS_COMMIT_RAW_SIZE) + 4),
            welcome: None,
            added: vec![],
            removed: vec![],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::UnprocessableEntity);

    // Oversized welcome (over the 256 KiB raw budget) is refused
    let response = post_json(
        &harness,
        &session_a,
        format!("/mls/groups/{gid}/commits"),
        serde_json::to_string(&v0::DataSubmitMlsCommit {
            device_id: device_a.device.device_id.clone(),
            epoch: 1,
            commit: STANDARD_NO_PAD.encode(b"small"),
            welcome: Some("A".repeat(super::encoded_len(super::MAX_MLS_WELCOME_RAW_SIZE) + 4)),
            added: added_b.clone(),
            removed: vec![],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::UnprocessableEntity);

    // A welcome-SIZED welcome (just under the cap) is accepted — the size
    // class the old 64 KiB olm cap would have rejected (plan §2.2.4)
    let response = post_json(
        &harness,
        &session_a,
        format!("/mls/groups/{gid}/commits"),
        serde_json::to_string(&v0::DataSubmitMlsCommit {
            device_id: device_a.device.device_id.clone(),
            epoch: 1,
            commit: STANDARD_NO_PAD.encode(b"real commit"),
            welcome: Some("A".repeat(super::encoded_len(super::MAX_MLS_WELCOME_RAW_SIZE) - 4)),
            added: added_b.clone(),
            removed: vec![],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // Welcome/added pairing violations are refused
    let response = post_json(
        &harness,
        &session_a,
        format!("/mls/groups/{gid}/commits"),
        serde_json::to_string(&v0::DataSubmitMlsCommit {
            device_id: device_a.device.device_id.clone(),
            epoch: 2,
            commit: STANDARD_NO_PAD.encode(b"commit"),
            welcome: Some(STANDARD_NO_PAD.encode(b"welcome")),
            added: vec![],
            removed: vec![],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::BadRequest);

    // Oversized OLM envelope stays refused: the text-E2EE abuse budget is
    // NOT widened by the MLS caps (plan §2.2.4)
    let response = post_json(
        &harness,
        &session_a,
        "/e2ee/messages".to_string(),
        serde_json::to_string(&v0::DataSendE2EEMessages {
            device_id: device_a.device.device_id.clone(),
            protocol_version: E2EE_PROTOCOL_VERSION,
            envelopes: vec![v0::DataE2EEEnvelope {
                recipient_user_id: user_b.id.clone(),
                recipient_device_id: device_b.device.device_id.clone(),
                sequence: 0,
                ciphertext: "A".repeat(crate::routes::e2ee::MAX_CIPHERTEXT_LENGTH + 1),
            }],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::UnprocessableEntity);
}

#[rocket::async_test]
async fn fanout_skips_devices_over_queue_budget() {
    let harness = TestHarness::new().await;
    let (account_a, session_a, user_a) = harness.new_user().await;
    let (account_b, session_b, user_b) = harness.new_user().await;

    let channel = voice_channel_with_members(&harness, &user_a, &[&user_b]).await;

    let device_a = enroll_mls_device(
        &harness,
        &account_a.id,
        &user_a.id,
        &session_a.token,
        &["a0"],
        None,
    )
    .await;
    let device_b = enroll_mls_device(
        &harness,
        &account_b.id,
        &user_b.id,
        &session_b.token,
        &["b0"],
        None,
    )
    .await;

    let gid = group_id(1);
    let response = post_json(
        &harness,
        &session_a,
        "/mls/groups".to_string(),
        serde_json::to_string(&v0::DataCreateMlsGroup {
            group_id: gid.clone(),
            channel_id: channel.id().to_string(),
            device_id: device_a.device.device_id.clone(),
            supersedes: None,
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    // Pre-fill B's queue past the BYTE budget (three 11 MiB envelopes >
    // 32 MiB — inserted at the DB layer; route caps do not apply to the
    // budget seed, that is the point of the budget)
    let envelopes: Vec<E2EEEnvelope> = (0..3)
        .map(|_| E2EEEnvelope {
            id: Ulid::new().to_string(),
            recipient_user_id: user_b.id.clone(),
            recipient_device_id: device_b.device.device_id.clone(),
            sender_user_id: user_a.id.clone(),
            sender_device_id: device_a.device.device_id.clone(),
            protocol_version: E2EE_PROTOCOL_VERSION,
            sequence: 0,
            ciphertext: "A".repeat(11 * 1024 * 1024),
            timestamp: iso8601_timestamp::Timestamp::now_utc(),
            content_type: E2EEContentType::Olm,
            group_id: None,
            epoch: None,
        })
        .collect();
    harness.db.insert_e2ee_envelopes(&envelopes).await.unwrap();

    // A's commit adding B: the Welcome for B is SKIPPED (budget), loudly
    // recoverable via gap refetch — availability-only (T-19 shape)
    let response = post_json(
        &harness,
        &session_a,
        format!("/mls/groups/{gid}/commits"),
        serde_json::to_string(&v0::DataSubmitMlsCommit {
            device_id: device_a.device.device_id.clone(),
            epoch: 1,
            commit: STANDARD_NO_PAD.encode(b"commit"),
            welcome: Some(STANDARD_NO_PAD.encode(b"welcome")),
            added: vec![v0::MlsMemberDevice {
                user_id: user_b.id.clone(),
                device_id: device_b.device.device_id.clone(),
            }],
            removed: vec![],
        })
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    let queued = harness
        .db
        .fetch_e2ee_envelopes(&user_b.id, &device_b.device.device_id, 10)
        .await
        .unwrap();
    assert_eq!(queued.len(), 3, "the welcome was skipped, not queued");

    // The commit itself is still arbitrated and gap-fetchable
    let response = harness
        .client
        .get(format!("/mls/groups/{gid}/commits?from_epoch=1"))
        .header(Header::new("x-session-token", session_b.token.clone()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body: v0::ResponseFetchMlsCommits = response.into_json().await.unwrap();
    assert_eq!(body.commits.len(), 1);
}

#[rocket::async_test]
async fn flag_off_rejects_every_route() {
    // overwrite_config is once-per-process and must run BEFORE the harness
    // primes the config cache (the create_account.rs test convention) —
    // process isolation comes from nextest; under plain `cargo test` this
    // test must run in its own process (e.g. filtered alone)
    revolt_config::overwrite_config(|settings| {
        settings.features.media_e2ee_enabled = false;
    })
    .await;

    let harness = TestHarness::new().await;
    let (_account, session, _user) = harness.new_user().await;

    // Bodies must deserialize (a malformed body is 422 before the handler
    // runs); the flag check must then fire FIRST in every handler
    let gid = group_id(1);
    let device = "aa".repeat(16);

    let response = harness
        .client
        .put("/mls/key_packages")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(format!(
            r#"{{"device_id":"{device}","mls_signature_key":"a","binding_signature":"a"}}"#
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);

    for (uri, body) in [
        (
            "/mls/key_packages/claim".to_string(),
            format!(r#"{{"device_id":"{device}","group_id":"{gid}","targets":[]}}"#),
        ),
        (
            "/mls/groups".to_string(),
            format!(
                r#"{{"group_id":"{gid}","channel_id":"channel","device_id":"{device}"}}"#
            ),
        ),
        (
            format!("/mls/groups/{gid}/join_intent"),
            format!(r#"{{"device_id":"{device}","key_package_ref":"a","signature":"a"}}"#),
        ),
        (
            format!("/mls/groups/{gid}/commits"),
            format!(r#"{{"device_id":"{device}","epoch":1,"commit":"a"}}"#),
        ),
    ] {
        let response = post_json(&harness, &session, uri, body).await;
        assert_eq!(response.status(), Status::BadRequest);
    }

    let response = harness
        .client
        .get(format!("/mls/groups/{gid}/commits?from_epoch=0"))
        .header(Header::new("x-session-token", session.token.clone()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
}
