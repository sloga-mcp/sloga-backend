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
        events::client::EventV1, Account, Channel, MFATicket, MlsCommit, MlsCommitOutcome,
        MlsGroup, MlsMemberDevice, Session, User, PROTECTED_SCOPE_TEXT_GROUP,
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
}
