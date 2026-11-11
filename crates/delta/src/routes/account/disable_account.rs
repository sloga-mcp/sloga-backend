//! Disable an account.
//! POST /account/disable
use revolt_result::Result;
use revolt_database::{Database, Account, ValidatedTicket};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Disable Account
///
/// Disable an account.
#[openapi(tag = "Account")]
#[post("/disable")]
pub async fn disable_account(
    db: &State<Database>,
    mut account: Account,
    _ticket: ValidatedTicket,
) -> Result<EmptyResponse> {
    account.disable(db).await.map(|_| EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{MFATicket, events::client::EventV1};
    use revolt_result::ErrorType;
    use rocket::http::{Header, Status};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let mut harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/account/disable")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
        drop(res);
        assert!(
            harness.db
                .fetch_account(&account.id)
                .await
                .unwrap()
                .disabled
        );

        assert!(matches!(
            harness.db
                .fetch_session(&session.id)
                .await
                .unwrap_err().error_type,
            ErrorType::UnknownUser
        ));

        harness.wait_for_event(&format!("{}!", &account.id), |e| if let EventV1::DeleteAllSessions { user_id, .. } = e {
            user_id == &account.id
        } else {
            false
        }).await;
    }
}

/// S2-D13 as amended (design R17 replaced, 6.3 "Device revocation"): a
/// disabled account keeps its seats while `Account::disable` revokes every
/// one of its devices, and while `formats_v2` is on each revocation queues a
/// pending device removal. Every flag case is its own `#[test]`:
/// `overwrite_config` runs once per process (nextest).
#[cfg(test)]
mod protected_tests {
    use std::collections::BTreeSet;

    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        events::client::EventV1,
        mongodb::bson::{doc, Document},
        Account, Channel, Database, MFATicket, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupKind,
        MlsMemberDevice, Session, User, PROTECTED_SCOPE_TEXT_GROUP,
    };
    use revolt_models::v0;
    use rocket::http::{Header, Status};

    use crate::routes::channels::protected_seat_validation::v2_fixtures::{
        authority, V2List, SALT,
    };
    use crate::util::test::{
        TestE2EEDevice, TestHarness, FIXTURE_SLOT_CAP, MEMBER_DEVICE_SEED, OWNER_DEVICE_SEED,
    };

    /// Key seed of the member's second device, bound to its second session
    const SECOND_MEMBER_DEVICE_SEED: u8 = 0x30;

    async fn formats_v2(on: bool) {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.formats_v2 = on;
        })
        .await;
    }

    struct World {
        harness: TestHarness,
        channel: Channel,
        /// Epoch 1: the owner's device and both member devices
        group: MlsGroup,
        member_account: Account,
        member_session: Session,
        member: User,
        /// One per member session
        member_devices: Vec<TestE2EEDevice>,
    }

    /// A protected channel seating the owner and the member, whose open Text
    /// group holds the owner's device and the member's two devices (one per
    /// member session). Protect takes a v2 genesis while `formats_v2` is on
    /// and a v1 genesis while it is off (7.1, #218), so the genesis follows
    /// the flag.
    async fn world(formats_v2: bool) -> World {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (member_account, member_session, member) = harness.new_user().await;

        let (channel, owner_device) = if formats_v2 {
            let (server, channel) = harness.new_protectable_channel(&owner).await;
            harness
                .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
                .await;
            let owner_device = harness
                .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
                .await;
            harness.join_server(&server, &member).await;
            let first = authority(
                channel.id(),
                &owner.id,
                &owner_device.device_id,
                &[(owner_device.device_id.as_str(), &owner_device.signing_key)],
                None,
                &owner_device.signing_key,
            );
            let genesis = V2List {
                channel_id: channel.id(),
                version: 1,
                signer_user_id: &owner.id,
                signer_device_id: &owner_device.device_id,
                key: &owner_device.signing_key,
                seats: &[owner.id.as_str(), member.id.as_str()],
                salt: SALT,
                authority: &first,
            }
            .signed();
            harness
                .protect_with_db(&channel, &v0::DataProtectChannel { seat_list: genesis })
                .await;
            let channel = harness
                .db
                .fetch_channel(channel.id())
                .await
                .expect("the protected channel");
            (channel, owner_device)
        } else {
            let protected = harness
                .new_protected_channel(&owner, &owner_session, &[&member])
                .await;
            (protected.channel, protected.owner_device)
        };

        let phone = member_account
            .create_session(&harness.db, "Phone".to_string())
            .await
            .expect("the member's second session");
        let member_devices = vec![
            harness
                .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
                .await,
            harness
                .new_e2ee_device(&member, &phone.id, SECOND_MEMBER_DEVICE_SEED)
                .await,
        ];

        let group = harness
            .new_text_group(&channel, &owner_device, 0, None)
            .await;
        let group = add_devices(&harness, &group, &owner_device, &member_devices).await;
        assert_eq!(group.current_epoch, 1);
        for device in &member_devices {
            assert!(
                group.has_member(&device.user_id, &device.device_id),
                "{} is not in the group",
                device.device_id
            );
        }
        assert!(group.pending_device_removals.is_empty());

        World {
            harness,
            channel,
            group,
            member_account,
            member_session,
            member,
            member_devices,
        }
    }

    /// `group` after one Add of `devices` at the next epoch, committed by
    /// `committer`, through the database primitive
    async fn add_devices(
        harness: &TestHarness,
        group: &MlsGroup,
        committer: &TestE2EEDevice,
        devices: &[TestE2EEDevice],
    ) -> MlsGroup {
        let db = &harness.db;
        let hash = db
            .fetch_seat_list(&group.channel_id)
            .await
            .expect("the seat list")
            .expect("a stored seat list")
            .commit_ad_sha256()
            .expect("its AD hash");
        let epoch = group.current_epoch + 1;
        let commit = MlsCommit {
            id: MlsCommit::composite_id(&group.id, epoch),
            group_id: group.id.clone(),
            epoch,
            committer: MlsMemberDevice {
                user_id: committer.user_id.clone(),
                device_id: committer.device_id.clone(),
            },
            commit: STANDARD_NO_PAD.encode(b"add"),
            size: 3,
            added: devices
                .iter()
                .map(|device| MlsMemberDevice {
                    user_id: device.user_id.clone(),
                    device_id: device.device_id.clone(),
                })
                .collect(),
            removed: vec![],
            created_at: Timestamp::now_utc(),
            rejoin_intents: vec![],
            removed_reasons: vec![],
            welcome: None,
        };
        let outcome = db
            .insert_mls_text_commit(&commit, &hash, 0)
            .await
            .expect("the add");
        assert!(matches!(outcome, MlsCommitOutcome::Won), "{:?}", outcome);
        db.fetch_mls_group(&group.id)
            .await
            .expect("the grown group")
    }

    /// The member disables their account through the route
    async fn disable(w: &World) {
        let ticket = MFATicket::new(w.member_account.id.to_string(), true);
        ticket.save(&w.harness.db).await.unwrap();

        let response = w
            .harness
            .client
            .post("/auth/account/disable")
            .header(Header::new(
                "X-Session-Token",
                w.member_session.token.clone(),
            ))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
    }

    /// Every member device is revoked, the member's seat row is still
    /// active and the stored list is still the genesis (nothing re-signed)
    async fn assert_devices_gone_and_seat_kept(w: &World) {
        let db = &w.harness.db;
        assert!(db
            .fetch_e2ee_identities(&w.member.id)
            .await
            .expect("identities")
            .is_empty());

        let seat = db
            .fetch_channel_seats(w.channel.id())
            .await
            .expect("the seats")
            .into_iter()
            .find(|seat| seat.user_id == w.member.id)
            .expect("the member's seat row");
        assert!(seat.is_active(), "the seat was released: {:?}", seat);
        assert_eq!(seat.release_cause, None);

        let list = db
            .fetch_seat_list(w.channel.id())
            .await
            .expect("list read")
            .expect("the stored list");
        assert_eq!(list.version, 1);
    }

    /// Flag on: one pending device entry per member device, in the open Text
    /// group; the seat stays, so there is no user-level pending removal and
    /// the leaves stay until a commit removes them (rule 3a)
    #[test]
    fn disabling_keeps_the_seat_and_queues_every_device() {
        crate::util::test::rt().block_on(Box::pin(async {
            formats_v2(true).await;
            disabling_keeps_the_seat_and_queues_every_device_case().await
        }))
    }

    async fn disabling_keeps_the_seat_and_queues_every_device_case() {
        let mut w = world(true).await;
        disable(&w).await;

        let group = w
            .harness
            .db
            .fetch_mls_group(&w.group.id)
            .await
            .expect("the group");
        let pending: BTreeSet<(String, String)> = group
            .pending_device_removals
            .iter()
            .map(|pending| (pending.user_id.clone(), pending.device_id.clone()))
            .collect();
        let expected: BTreeSet<(String, String)> = w
            .member_devices
            .iter()
            .map(|device| (device.user_id.clone(), device.device_id.clone()))
            .collect();
        assert_eq!(pending, expected, "one pending entry per member device");
        assert_eq!(group.pending_device_removals.len(), expected.len());
        assert!(group.pending_removals.is_empty());
        assert_eq!(group.signer_lost, None);
        assert_eq!(group.members, w.group.members);
        assert_devices_gone_and_seat_kept(&w).await;

        let channel_id = w.channel.id().to_string();
        w.harness
            .wait_for_event(&channel_id, |event| {
                matches!(event, EventV1::ProtectedChannelChanged { id, scope }
                    if id == &channel_id
                        && *scope == vec![PROTECTED_SCOPE_TEXT_GROUP.to_string()])
            })
            .await;
    }

    /// Flag off: the S1 revocation (#219; R23 stays open). The devices go
    /// and the seat stays, but nothing is queued and nothing is announced on
    /// the channel
    #[test]
    fn with_formats_v2_off_disabling_stays_s1() {
        crate::util::test::rt().block_on(Box::pin(async {
            formats_v2(false).await;
            with_formats_v2_off_disabling_stays_s1_case().await
        }))
    }

    async fn with_formats_v2_off_disabling_stays_s1_case() {
        let mut w = world(false).await;
        disable(&w).await;

        let group = w
            .harness
            .db
            .fetch_mls_group(&w.group.id)
            .await
            .expect("the group");
        assert!(group.pending_device_removals.is_empty());
        assert!(group.pending_removals.is_empty());
        assert_eq!(group.signer_lost, None);
        assert_eq!(group.members, w.group.members);
        assert_devices_gone_and_seat_kept(&w).await;

        // `DeleteAllSessions` follows every revocation, so once it is seen
        // anything the revocations published on the channel is buffered
        let member_topic = format!("{}!", w.member.id);
        let member_id = w.member.id.clone();
        w.harness
            .wait_for_event(&member_topic, |event| {
                matches!(event, EventV1::DeleteAllSessions { user_id, .. } if user_id == &member_id)
            })
            .await;
        w.harness.assert_no_buffered_event(w.channel.id(), |event| {
            matches!(event, EventV1::ProtectedChannelChanged { .. })
        });
    }

    const FAILING_GROUP: &str = "01DISFAILINGGROUP";
    const PASSING_GROUP: &str = "01DISPASSINGGROUP";

    /// A failing revocation (audit MAJOR-2), flag on: the member's two
    /// devices each sit alone in an open Text group, and an `mls_groups`
    /// validator refuses every write to the first, so that device's pending
    /// pass fails and leaves it intact while the other's goes through. The
    /// failing device gets the lower device id and is stored first, so the
    /// listing returns it first in id and in insertion order: a loop that
    /// stops at the first error never reaches the other. Lift the validator
    /// with [`group_validator`] and `{}`.
    struct Fault {
        harness: TestHarness,
        account: Account,
        session: Session,
        member: User,
        failing: TestE2EEDevice,
        passing: TestE2EEDevice,
    }

    /// [`Fault`], armed. `None` on the reference store, which cannot fail a
    /// write.
    async fn fault() -> Option<Fault> {
        let harness = TestHarness::new().await;
        let Database::MongoDb(mongo) = &harness.db else {
            return None;
        };
        let (account, session, member) = harness.new_user().await;
        let phone = account
            .create_session(&harness.db, "Phone".to_string())
            .await
            .expect("the member's second session");
        let device_id_for = |seed: u8| -> String {
            TestE2EEDevice::signing_key_for(seed)
                .verifying_key()
                .as_bytes()[..16]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        };
        let (failing_seed, passing_seed) =
            if device_id_for(MEMBER_DEVICE_SEED) < device_id_for(SECOND_MEMBER_DEVICE_SEED) {
                (MEMBER_DEVICE_SEED, SECOND_MEMBER_DEVICE_SEED)
            } else {
                (SECOND_MEMBER_DEVICE_SEED, MEMBER_DEVICE_SEED)
            };
        let failing = harness
            .new_e2ee_device(&member, &session.id, failing_seed)
            .await;
        let passing = harness
            .new_e2ee_device(&member, &phone.id, passing_seed)
            .await;
        assert!(failing.device_id < passing.device_id);

        for (group_id, device) in [(FAILING_GROUP, &failing), (PASSING_GROUP, &passing)] {
            let member_device = MlsMemberDevice {
                user_id: device.user_id.clone(),
                device_id: device.device_id.clone(),
            };
            let group = MlsGroup {
                id: group_id.to_string(),
                channel_id: format!("{group_id}CHANNEL"),
                open: true,
                created_by: member_device.clone(),
                created_at: Timestamp::now_utc(),
                current_epoch: 0,
                members: vec![member_device],
                closed_at: None,
                superseded_by: None,
                kind: MlsGroupKind::Text,
                generation: Some(0),
                seat_list_ad_sha256: None,
                pending_removals: vec![],
                member_added: vec![],
                pending_device_removals: vec![],
                signer_lost: None,
                rejoin_readd: vec![],
            };
            mongo
                .col::<MlsGroup>("mls_groups")
                .insert_one(&group)
                .await
                .expect("raw text group");
        }

        group_validator(&harness, doc! { "_id": { "$ne": FAILING_GROUP } }).await;
        assert!(
            harness
                .db
                .add_pending_device_removal(&member.id, &failing.device_id, Timestamp::now_utc())
                .await
                .is_err(),
            "precondition: the refused group write fails the pending pass"
        );

        Some(Fault {
            harness,
            account,
            session,
            member,
            failing,
            passing,
        })
    }

    /// Set the `mls_groups` collection validator (`{}` lifts it)
    async fn group_validator(harness: &TestHarness, validator: Document) {
        let Database::MongoDb(mongo) = &harness.db else {
            panic!("the group validator is MONGODB only");
        };
        mongo
            .db()
            .run_command(doc! {
                "collMod": "mls_groups",
                "validator": validator,
                "validationLevel": "strict",
                "validationAction": "error",
            })
            .await
            .expect("collMod mls_groups");
    }

    /// The member's devices left in the directory
    async fn devices_left(harness: &TestHarness, member: &User) -> BTreeSet<String> {
        harness
            .db
            .fetch_e2ee_identities(&member.id)
            .await
            .expect("identities")
            .into_iter()
            .map(|identity| identity.device_id)
            .collect()
    }

    /// [`Fault`] through the route: disable answers 500 with `disabled`
    /// already stored, every session gone, the other device revoked and
    /// `DeleteAllSessions` sent. MONGODB only. Controls: the loop's `?`
    /// restored; the save moved back after the revocations; the first
    /// error dropped.
    #[test]
    fn a_failed_device_revocation_still_disables_and_revokes_the_rest() {
        crate::util::test::rt().block_on(Box::pin(async {
            formats_v2(true).await;
            a_failed_device_revocation_still_disables_and_revokes_the_rest_case().await
        }))
    }

    async fn a_failed_device_revocation_still_disables_and_revokes_the_rest_case() {
        let Some(Fault {
            mut harness,
            account,
            session,
            member,
            failing,
            passing,
        }) = fault().await
        else {
            return;
        };

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();
        let response = harness
            .client
            .post("/auth/account/disable")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();

        // Lifted before any assertion can fail
        group_validator(&harness, doc! {}).await;

        assert_eq!(
            status,
            Status::InternalServerError,
            "the failed revocation is answered: {body}"
        );
        assert!(body.contains("DatabaseError"), "{}", body);
        assert!(
            harness
                .db
                .fetch_account(&account.id)
                .await
                .expect("the account")
                .disabled,
            "disabled is stored although a revocation failed"
        );
        assert!(
            harness
                .db
                .fetch_sessions(&member.id)
                .await
                .expect("the sessions")
                .is_empty(),
            "every session is deleted"
        );

        let left = devices_left(&harness, &member).await;
        assert!(
            !left.contains(&passing.device_id),
            "the device whose pass went through is revoked: {left:?}"
        );
        assert_eq!(
            left,
            BTreeSet::from([failing.device_id.clone()]),
            "the failed pass leaves its device intact"
        );
        let queued = |group: &MlsGroup| {
            group
                .pending_device_removals
                .iter()
                .map(|pending| (pending.user_id.clone(), pending.device_id.clone()))
                .collect::<Vec<_>>()
        };
        let passed = harness
            .db
            .fetch_mls_group(PASSING_GROUP)
            .await
            .expect("the passing group");
        assert_eq!(
            queued(&passed),
            vec![(member.id.clone(), passing.device_id.clone())]
        );
        let failed = harness
            .db
            .fetch_mls_group(FAILING_GROUP)
            .await
            .expect("the failing group");
        assert!(queued(&failed).is_empty(), "{:?}", queued(&failed));

        let member_id = member.id.clone();
        harness
            .wait_for_event(&format!("{}!", member.id), |event| {
                matches!(event, EventV1::DeleteAllSessions { user_id, .. } if user_id == &member_id)
            })
            .await;
    }

    /// [`Fault`] under a suspension: `User::suspend` (the model method the
    /// staff suspend route calls) answers the revocation's error with the
    /// suspension (`SuspendedUntil`, `suspended_until`) and `disabled`
    /// already stored, and the other device revoked. MONGODB only.
    /// Control: the suspension write moved back after
    /// `account.disable(db).await?`.
    #[test]
    fn a_failed_device_revocation_still_stores_the_suspension() {
        crate::util::test::rt().block_on(Box::pin(async {
            formats_v2(true).await;
            a_failed_device_revocation_still_stores_the_suspension_case().await
        }))
    }

    async fn a_failed_device_revocation_still_stores_the_suspension_case() {
        let Some(Fault {
            harness,
            account,
            member,
            failing,
            ..
        }) = fault().await
        else {
            return;
        };

        let mut user = member.clone();
        let result = user.suspend(&harness.db, Some(7), None).await;

        // Lifted before any assertion can fail
        group_validator(&harness, doc! {}).await;

        assert!(
            result.is_err(),
            "the failed revocation fails the suspension: {result:?}"
        );
        let stored = harness.db.fetch_user(&member.id).await.expect("the user");
        assert_eq!(
            stored.flags,
            Some(v0::UserFlags::SuspendedUntil as i32),
            "the suspension flag is stored although a revocation failed"
        );
        assert!(
            stored.suspended_until.is_some(),
            "the suspension's end is stored although a revocation failed"
        );
        assert!(
            harness
                .db
                .fetch_account(&account.id)
                .await
                .expect("the account")
                .disabled,
            "the suspended account is stored disabled"
        );
        assert_eq!(
            devices_left(&harness, &member).await,
            BTreeSet::from([failing.device_id.clone()]),
            "only the device whose pass failed is left"
        );
    }
}
