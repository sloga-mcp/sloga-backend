//! Driver-level tests for the MLS delivery service (media E2EE, plan §2.6).
//! The concurrency tests are the definition-of-done for the arbitration
//! primitives: they must pass under BOTH `TEST_DB=REFERENCE` and
//! `TEST_DB=MONGODB` (Mongo runs are WSL-only on Windows).

use iso8601_timestamp::{Duration, Timestamp};
use ulid::Ulid;

use crate::{
    E2EEContentType, E2EEEnvelope, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome,
    MlsJoinIntent, MlsKeyPackage, MlsMemberDevice, E2EE_PROTOCOL_VERSION,
};

fn group_id(seed: u8) -> String {
    format!("{:02x}", seed).repeat(32)
}

fn device(user: &str, n: u8) -> MlsMemberDevice {
    MlsMemberDevice {
        user_id: user.to_string(),
        device_id: format!("{n:02x}").repeat(16),
    }
}

fn make_group(id: &str, channel_id: &str, creator: &MlsMemberDevice) -> MlsGroup {
    MlsGroup {
        id: id.to_string(),
        channel_id: channel_id.to_string(),
        open: true,
        created_by: creator.clone(),
        created_at: Timestamp::now_utc(),
        current_epoch: 0,
        members: vec![creator.clone()],
        closed_at: None,
        superseded_by: None,
    }
}

fn make_commit(
    group: &str,
    epoch: i64,
    committer: &MlsMemberDevice,
    added: Vec<MlsMemberDevice>,
    removed: Vec<MlsMemberDevice>,
    payload: &str,
) -> MlsCommit {
    MlsCommit {
        id: MlsCommit::composite_id(group, epoch),
        group_id: group.to_string(),
        epoch,
        committer: committer.clone(),
        commit: payload.to_string(),
        size: payload.len() as i64,
        added,
        removed,
        created_at: Timestamp::now_utc(),
    }
}

fn make_key_package(member: &MlsMemberDevice, reference: &str, last_resort: bool) -> MlsKeyPackage {
    MlsKeyPackage {
        id: MlsKeyPackage::composite_id(&member.user_id, &member.device_id, reference),
        user_id: member.user_id.clone(),
        device_id: member.device_id.clone(),
        key_package_ref: reference.to_string(),
        key_package: "b3BhcXVl".to_string(),
        mls_signature_key: "c2lna2V5".to_string(),
        binding_signature: "c2ln".to_string(),
        last_resort,
        expires_at: Timestamp::now_utc()
            .checked_add(Duration::days(30))
            .unwrap(),
        created_at: Timestamp::now_utc(),
    }
}

#[tokio::test]
async fn create_race_yields_exactly_one_open_group_per_channel() {
    database_test!(|db| async move {
        // The channel-scoped arbitration IS the partial unique index — the
        // schema must exist (database_test! drops it; a Reference migrate
        // is a no-op)
        db.migrate_database().await.expect("schema");

        let creator_a = device("alice", 1);
        let creator_b = device("bob", 2);

        // Racing creators derive DIFFERENT group ids (plan §1.2/A5) — fire
        // them concurrently; the channel-scoped arbitration must admit
        // exactly one
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let db = db.clone();
            let creator = if i % 2 == 0 {
                creator_a.clone()
            } else {
                creator_b.clone()
            };
            handles.push(tokio::spawn(async move {
                let group = make_group(&group_id(i + 1), "channel_race", &creator);
                db.create_mls_group(&group, None).await
            }));
        }

        let mut created = 0;
        let mut conflicts = Vec::new();
        for handle in handles {
            match handle.await.expect("join").expect("create must not error") {
                MlsGroupCreateOutcome::Created => created += 1,
                MlsGroupCreateOutcome::Conflict {
                    open_group_id,
                    channel_id,
                } => {
                    assert_eq!(channel_id, "channel_race");
                    conflicts.push(open_group_id)
                }
            }
        }

        assert_eq!(created, 1, "exactly one creator wins");
        assert_eq!(conflicts.len(), 7);

        // Every loser was pointed at the SAME open group — the winner's
        let open = db
            .fetch_open_mls_group_for_channel("channel_race")
            .await
            .unwrap()
            .expect("open group");
        assert!(conflicts.iter().all(|id| id == &open.id));

        // A late creator still conflicts with the open group
        let late = make_group(&group_id(99), "channel_race", &creator_a);
        match db.create_mls_group(&late, None).await.unwrap() {
            MlsGroupCreateOutcome::Conflict {
                open_group_id,
                channel_id,
            } => {
                assert_eq!(open_group_id, open.id);
                assert_eq!(channel_id, open.channel_id);
            }
            _ => panic!("late creator must conflict"),
        }
    });
}

#[tokio::test]
async fn supersedes_closes_old_group_atomically() {
    database_test!(|db| async move {
        // Arbitration depends on the partial unique index (see above)
        db.migrate_database().await.expect("schema");

        let creator = device("alice", 1);

        let old = make_group(&group_id(1), "channel_super", &creator);
        assert!(matches!(
            db.create_mls_group(&old, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        ));

        // Successor closes the poisoned group and takes its place
        let successor = make_group(&group_id(2), "channel_super", &creator);
        assert!(matches!(
            db.create_mls_group(&successor, Some(&old.id)).await.unwrap(),
            MlsGroupCreateOutcome::Created
        ));

        let old_now = db.fetch_mls_group(&old.id).await.unwrap();
        assert!(!old_now.open);
        assert!(old_now.closed_at.is_some());
        assert_eq!(old_now.superseded_by.as_deref(), Some(successor.id.as_str()));

        let open = db
            .fetch_open_mls_group_for_channel("channel_super")
            .await
            .unwrap()
            .expect("successor open");
        assert_eq!(open.id, successor.id);

        // A racing second successor targeting the ALREADY-CLOSED group
        // conflicts with the live successor instead of forking the channel
        let stale = make_group(&group_id(3), "channel_super", &creator);
        match db.create_mls_group(&stale, Some(&old.id)).await.unwrap() {
            MlsGroupCreateOutcome::Conflict {
                open_group_id,
                channel_id,
            } => {
                assert_eq!(open_group_id, successor.id);
                assert_eq!(channel_id, successor.channel_id);
            }
            _ => panic!("stale successor must conflict"),
        }

        // Superseding a group from ANOTHER channel is refused
        let other = make_group(&group_id(4), "channel_other", &creator);
        assert!(matches!(
            db.create_mls_group(&other, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        ));
        let cross = make_group(&group_id(5), "channel_super", &creator);
        assert!(db.create_mls_group(&cross, Some(&other.id)).await.is_err());

        // Superseding an unknown group is refused
        let orphan = make_group(&group_id(6), "channel_orphan", &creator);
        assert!(db
            .create_mls_group(&orphan, Some(&group_id(42)))
            .await
            .is_err());
    });
}

#[tokio::test]
async fn commit_race_has_exactly_one_winner_per_epoch() {
    database_test!(|db| async move {
        let creator = device("alice", 1);
        let group = make_group(&group_id(1), "channel_commit", &creator);
        db.create_mls_group(&group, None).await.unwrap();

        // Concurrent epoch-1 commits from the creator device: the CAS must
        // admit exactly one, and every loser must receive the SAME winner
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let db = db.clone();
            let commit = make_commit(
                &group.id,
                1,
                &creator,
                vec![],
                vec![],
                &format!("commit_payload_{i}"),
            );
            handles.push(tokio::spawn(async move {
                db.insert_mls_commit(&commit).await
            }));
        }

        let mut won = 0;
        let mut winners = Vec::new();
        for handle in handles {
            match handle.await.expect("join").expect("commit must not error") {
                MlsCommitOutcome::Won => won += 1,
                MlsCommitOutcome::Lost { winning } => winners.push(winning.commit),
            }
        }

        assert_eq!(won, 1, "exactly one committer wins the epoch");
        assert_eq!(winners.len(), 7);
        let stored = db.fetch_mls_commits_from(&group.id, 1, 10).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(winners.iter().all(|commit| commit == &stored[0].commit));

        // The group advanced exactly one epoch
        let group_now = db.fetch_mls_group(&group.id).await.unwrap();
        assert_eq!(group_now.current_epoch, 1);

        // Epoch monotonicity: skip-ahead is refused (invariant 10)
        let skip = make_commit(&group.id, 5, &creator, vec![], vec![], "skip");
        assert!(db.insert_mls_commit(&skip).await.is_err());

        // A stale (already-arbitrated) epoch returns the winner to rebase on
        let stale = make_commit(&group.id, 1, &creator, vec![], vec![], "stale");
        match db.insert_mls_commit(&stale).await.unwrap() {
            MlsCommitOutcome::Lost { winning } => {
                assert_eq!(winning.commit, stored[0].commit)
            }
            _ => panic!("stale epoch must lose"),
        }

        // Non-members cannot commit
        let stranger = device("mallory", 9);
        let intruder = make_commit(&group.id, 2, &stranger, vec![], vec![], "intruder");
        assert!(db.insert_mls_commit(&intruder).await.is_err());
    });
}

#[tokio::test]
async fn one_device_per_user_is_refused_in_the_commit_cas() {
    database_test!(|db| async move {
        let creator = device("alice", 1);
        let group = make_group(&group_id(1), "channel_onedev", &creator);
        db.create_mls_group(&group, None).await.unwrap();

        // Admit bob's first device
        let bob1 = device("bob", 2);
        let add_bob = make_commit(&group.id, 1, &creator, vec![bob1.clone()], vec![], "add_bob");
        assert!(matches!(
            db.insert_mls_commit(&add_bob).await.unwrap(),
            MlsCommitOutcome::Won
        ));

        // A second bob device while the first leaf is live: refused — with
        // user-scoped identities this would silently overwrite frame keys
        // (plan §1.5, T-16 refusal-not-last-writer-wins)
        let bob2 = device("bob", 3);
        let add_bob2 = make_commit(&group.id, 2, &creator, vec![bob2.clone()], vec![], "add_bob2");
        assert!(db.insert_mls_commit(&add_bob2).await.is_err());

        // Adding an already-present device is refused too
        let dup = make_commit(&group.id, 2, &creator, vec![bob1.clone()], vec![], "dup");
        assert!(db.insert_mls_commit(&dup).await.is_err());

        // After bob's leaf is removed, a different device may join
        let remove = make_commit(&group.id, 2, &creator, vec![], vec![bob1.clone()], "rm");
        assert!(matches!(
            db.insert_mls_commit(&remove).await.unwrap(),
            MlsCommitOutcome::Won
        ));
        let rejoin = make_commit(&group.id, 3, &creator, vec![bob2], vec![], "rejoin");
        assert!(matches!(
            db.insert_mls_commit(&rejoin).await.unwrap(),
            MlsCommitOutcome::Won
        ));

        let group_now = db.fetch_mls_group(&group.id).await.unwrap();
        assert_eq!(group_now.current_epoch, 3);
        assert_eq!(group_now.members.len(), 2);
        assert!(group_now.has_member("bob", &device("bob", 3).device_id));
        assert!(!group_now.has_member("bob", &device("bob", 2).device_id));
    });
}

#[tokio::test]
async fn key_package_claims_are_atomic() {
    database_test!(|db| async move {
        let target = device("bob", 2);

        // Five one-time packages + a last-resort
        let packages: Vec<MlsKeyPackage> = (0..5)
            .map(|i| make_key_package(&target, &format!("ref{i}"), false))
            .collect();
        db.insert_mls_key_packages(&packages).await.unwrap();
        db.replace_mls_last_resort_key_package(&make_key_package(&target, "last", true))
            .await
            .unwrap();

        // Ten concurrent claimers: exactly five get distinct one-time
        // packages, never the same one twice
        let mut handles = Vec::new();
        for _ in 0..10 {
            let db = db.clone();
            let target = target.clone();
            handles.push(tokio::spawn(async move {
                db.consume_mls_key_package(&target.user_id, &target.device_id)
                    .await
            }));
        }

        let mut claimed = Vec::new();
        let mut exhausted = 0;
        for handle in handles {
            match handle.await.expect("join").expect("claim must not error") {
                Some(package) => claimed.push(package.key_package_ref),
                None => exhausted += 1,
            }
        }

        claimed.sort();
        claimed.dedup();
        assert_eq!(claimed.len(), 5, "each one-time package claimed exactly once");
        assert_eq!(exhausted, 5);

        // At exhaustion the last-resort package remains, un-consumed
        let last = db
            .fetch_mls_last_resort_key_package(&target.user_id, &target.device_id)
            .await
            .unwrap()
            .expect("last resort survives");
        assert!(last.last_resort);
        assert!(db
            .fetch_mls_last_resort_key_package(&target.user_id, &target.device_id)
            .await
            .unwrap()
            .is_some());

        // Cap accounting counts one-time packages only
        assert_eq!(
            db.count_mls_key_packages(&target.user_id, &target.device_id)
                .await
                .unwrap(),
            0
        );
    });
}

#[tokio::test]
async fn expired_key_packages_are_swept() {
    database_test!(|db| async move {
        let target = device("bob", 2);

        let mut fresh = make_key_package(&target, "fresh", false);
        fresh.expires_at = Timestamp::now_utc()
            .checked_add(Duration::days(10))
            .unwrap();

        let mut stale = make_key_package(&target, "stale", false);
        stale.expires_at = Timestamp::now_utc()
            .checked_sub(Duration::days(1))
            .unwrap();

        db.insert_mls_key_packages(&[fresh, stale]).await.unwrap();

        let swept = db
            .delete_expired_mls_key_packages(Timestamp::now_utc())
            .await
            .unwrap();
        assert_eq!(swept, 1);
        assert_eq!(
            db.count_mls_key_packages(&target.user_id, &target.device_id)
                .await
                .unwrap(),
            1
        );
    });
}

#[tokio::test]
async fn group_sweep_cascades_to_commits_and_intents() {
    database_test!(|db| async move {
        let creator = device("alice", 1);

        // An old closed group with a commit and an intent
        let mut old = make_group(&group_id(1), "channel_sweep_a", &creator);
        old.created_at = Timestamp::now_utc()
            .checked_sub(Duration::days(2))
            .unwrap();
        db.create_mls_group(&old, None).await.unwrap();
        db.insert_mls_commit(&make_commit(&old.id, 1, &creator, vec![], vec![], "c1"))
            .await
            .unwrap();
        db.upsert_mls_join_intent(&MlsJoinIntent {
            id: MlsJoinIntent::composite_id(&old.id, "bob", &device("bob", 2).device_id),
            group_id: old.id.clone(),
            user_id: "bob".to_string(),
            device_id: device("bob", 2).device_id,
            key_package_ref: "ref0".to_string(),
            signature: "c2ln".to_string(),
            created_at: Timestamp::now_utc(),
        })
        .await
        .unwrap();
        db.close_mls_group(&old.id).await.unwrap();

        // A live group on another channel survives
        let live = make_group(&group_id(2), "channel_sweep_b", &creator);
        db.create_mls_group(&live, None).await.unwrap();

        // Sweep: closed-before-now catches the old group (closed_at is set
        // to now, so use a future threshold to simulate 24h passing)
        let swept = db
            .sweep_mls_groups(
                Timestamp::now_utc().checked_add(Duration::hours(1)).unwrap(),
                Timestamp::now_utc().checked_sub(Duration::days(7)).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(swept, 1);

        assert!(db.fetch_mls_group(&old.id).await.is_err());
        assert!(db.fetch_mls_group(&live.id).await.is_ok());
        assert!(db
            .fetch_mls_commits_from(&old.id, 0, 10)
            .await
            .unwrap()
            .is_empty());

        // Backstop: ANY group older than the created threshold goes, even
        // if still open (missed room_finished)
        let mut ancient = make_group(&group_id(3), "channel_sweep_c", &creator);
        ancient.created_at = Timestamp::now_utc()
            .checked_sub(Duration::days(8))
            .unwrap();
        db.create_mls_group(&ancient, None).await.unwrap();

        let swept = db
            .sweep_mls_groups(
                Timestamp::now_utc().checked_sub(Duration::hours(24)).unwrap(),
                Timestamp::now_utc().checked_sub(Duration::days(7)).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(swept, 1);
        assert!(db.fetch_mls_group(&ancient.id).await.is_err());
    });
}

#[tokio::test]
async fn envelope_byte_budget_is_summed_per_device() {
    database_test!(|db| async move {
        let make_envelope = |size: usize| E2EEEnvelope {
            id: Ulid::new().to_string(),
            recipient_user_id: "bob".to_string(),
            recipient_device_id: device("bob", 2).device_id,
            sender_user_id: "alice".to_string(),
            sender_device_id: device("alice", 1).device_id,
            protocol_version: E2EE_PROTOCOL_VERSION,
            sequence: 0,
            ciphertext: "A".repeat(size),
            timestamp: Timestamp::now_utc(),
            content_type: E2EEContentType::MlsCommit,
            group_id: Some(group_id(1)),
            epoch: Some(1),
        };

        db.insert_e2ee_envelopes(&[make_envelope(1000), make_envelope(500)])
            .await
            .unwrap();

        // Another device's queue must not count toward this budget
        let mut other = make_envelope(4096);
        other.recipient_device_id = device("bob", 3).device_id;
        db.insert_e2ee_envelopes(&[other]).await.unwrap();

        assert_eq!(
            db.sum_e2ee_envelope_bytes("bob", &device("bob", 2).device_id)
                .await
                .unwrap(),
            1500
        );
        assert_eq!(
            db.sum_e2ee_envelope_bytes("bob", &device("bob", 9).device_id)
                .await
                .unwrap(),
            0
        );
    });
}
