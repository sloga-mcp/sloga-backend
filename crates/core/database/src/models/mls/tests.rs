//! Driver-level tests for the MLS delivery service (media E2EE, plan §2.6).
//! The concurrency tests are the definition-of-done for the arbitration
//! primitives: they must pass under BOTH `TEST_DB=REFERENCE` and
//! `TEST_DB=MONGODB` (Mongo runs are WSL-only on Windows).

use iso8601_timestamp::{Duration, Timestamp};
use revolt_result::ErrorType;
use ulid::Ulid;

use crate::{
    mls_text_enforced_device_cap, ChannelEntitlement, ChannelEntitlementSource,
    ChannelEntitlementState, ChannelSeat, Database, E2EEContentType, E2EEEnvelope, E2EEIdentity,
    E2EESignedKey, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind,
    MlsJoinIntent, MlsKeyPackage, MlsMemberAdded, MlsMemberDevice, MlsPendingRemoval, SeatList,
    SeatListBody, SeatListSubmission, E2EE_PROTOCOL_VERSION,
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
        kind: MlsGroupKind::Call,
        generation: None,
        seat_list_ad_sha256: None,
        pending_removals: vec![],
        member_added: vec![],
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
        rejoin_intents: vec![],
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
            .fetch_open_mls_group_for_channel("channel_race", MlsGroupKind::Call)
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
            .fetch_open_mls_group_for_channel("channel_super", MlsGroupKind::Call)
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
async fn capped_insert_prunes_oldest_and_spares_batch_and_last_resort() {
    database_test!(|db| async move {
        let target = device("bob", 2);

        // Three aged packages (old0 the oldest) + a last-resort
        let aged: Vec<MlsKeyPackage> = (0..3)
            .map(|i| {
                let mut package = make_key_package(&target, &format!("old{i}"), false);
                package.created_at = Timestamp::now_utc()
                    .checked_sub(Duration::days(3 - i as i64))
                    .unwrap();
                package
            })
            .collect();
        db.insert_mls_key_packages(&aged).await.unwrap();
        db.replace_mls_last_resort_key_package(&make_key_package(&target, "last", true))
            .await
            .unwrap();

        // A fresh batch of three against cap 4: 6 stored → the TWO oldest
        // (old0, old1) go; the fresh batch survives intact
        let fresh: Vec<MlsKeyPackage> = (0..3)
            .map(|i| make_key_package(&target, &format!("new{i}"), false))
            .collect();
        let count = db
            .insert_mls_key_packages_capped(&target.user_id, &target.device_id, &fresh, 4)
            .await
            .unwrap();
        assert_eq!(count, 4, "prune converges on the cap");

        // Republishing the SAME refs is upsert-idempotent — nothing to prune
        let count = db
            .insert_mls_key_packages_capped(&target.user_id, &target.device_id, &fresh, 4)
            .await
            .unwrap();
        assert_eq!(count, 4);

        // The last-resort row lives outside the cap and is never pruned
        assert!(db
            .fetch_mls_last_resort_key_package(&target.user_id, &target.device_id)
            .await
            .unwrap()
            .is_some());

        // Exactly {old2, new0, new1, new2} survived (consume order is
        // driver-specific; set equality is not)
        let mut survivors = Vec::new();
        while let Some(package) = db
            .consume_mls_key_package(&target.user_id, &target.device_id)
            .await
            .unwrap()
        {
            survivors.push(package.key_package_ref);
        }
        survivors.sort();
        assert_eq!(survivors, vec!["new0", "new1", "new2", "old2"]);
    });
}

#[tokio::test]
async fn capped_insert_tie_breaks_equal_created_at_by_id() {
    database_test!(|db| async move {
        let target = device("bob", 2);

        // Two packages sharing ONE created_at (an intra-batch publish, or
        // two publishes within the same millisecond): the prune victim must
        // be the id-ascending one, identically in both drivers (re-audit
        // LOW-3 — Mongo sorts Int64 unix-ms, Reference full precision;
        // equal stamps must fall through to the id tie-break)
        let stamp = Timestamp::now_utc().checked_sub(Duration::days(1)).unwrap();
        let tied: Vec<MlsKeyPackage> = ["tie_a", "tie_b"]
            .iter()
            .map(|reference| {
                let mut package = make_key_package(&target, reference, false);
                package.created_at = stamp;
                package
            })
            .collect();
        db.insert_mls_key_packages(&tied).await.unwrap();

        let fresh = vec![make_key_package(&target, "fresh", false)];
        let count = db
            .insert_mls_key_packages_capped(&target.user_id, &target.device_id, &fresh, 2)
            .await
            .unwrap();
        assert_eq!(count, 2);

        let mut survivors = Vec::new();
        while let Some(package) = db
            .consume_mls_key_package(&target.user_id, &target.device_id)
            .await
            .unwrap()
        {
            survivors.push(package.key_package_ref);
        }
        survivors.sort();
        assert_eq!(survivors, vec!["fresh", "tie_b"], "tie_a (id-ascending) is the victim");
    });
}

#[tokio::test]
async fn capped_insert_converges_under_concurrent_claims() {
    database_test!(|db| async move {
        let target = device("bob", 2);

        // Ten aged packages fill the cap exactly
        let aged: Vec<MlsKeyPackage> = (0..10)
            .map(|i| {
                let mut package = make_key_package(&target, &format!("seed{i:02}"), false);
                package.created_at = Timestamp::now_utc()
                    .checked_sub(Duration::days(1))
                    .unwrap();
                package
            })
            .collect();
        db.insert_mls_key_packages(&aged).await.unwrap();

        // A full replenish (8 fresh, cap 10) racing five concurrent claims:
        // claims must never serve the same package twice, and the directory
        // must converge at (or under — claims shrink it) the cap
        let mut claim_handles = Vec::new();
        for _ in 0..5 {
            let db = db.clone();
            let target = target.clone();
            claim_handles.push(tokio::spawn(async move {
                db.consume_mls_key_package(&target.user_id, &target.device_id)
                    .await
            }));
        }
        let fresh: Vec<MlsKeyPackage> = (0..8)
            .map(|i| make_key_package(&target, &format!("fresh{i}"), false))
            .collect();
        let insert_handle = {
            let db = db.clone();
            let target = target.clone();
            tokio::spawn(async move {
                db.insert_mls_key_packages_capped(&target.user_id, &target.device_id, &fresh, 10)
                    .await
            })
        };

        let mut claimed = Vec::new();
        for handle in claim_handles {
            if let Some(package) = handle.await.expect("join").expect("claim must not error") {
                claimed.push(package.key_package_ref);
            }
        }
        let reported = insert_handle
            .await
            .expect("join")
            .expect("capped insert must not error");

        let mut distinct = claimed.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), claimed.len(), "no package served twice");

        assert!(reported <= 10, "reported count converges on the cap");
        let count = db
            .count_mls_key_packages(&target.user_id, &target.device_id)
            .await
            .unwrap();
        assert!(count <= 10, "stored count converges on the cap");
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
async fn admission_consumes_the_added_devices_join_intent() {
    database_test!(|db| async move {
        let creator = device("alice", 1);
        let joiner = device("bob", 2);

        let make_intent = |group_id: &str| MlsJoinIntent {
            id: MlsJoinIntent::composite_id(group_id, &joiner.user_id, &joiner.device_id),
            group_id: group_id.to_string(),
            user_id: joiner.user_id.clone(),
            device_id: joiner.device_id.clone(),
            key_package_ref: "ref0".to_string(),
            signature: "c2ln".to_string(),
            created_at: Timestamp::now_utc(),
        };

        let group = make_group(&group_id(1), "channel_consume_a", &creator);
        db.create_mls_group(&group, None).await.unwrap();
        db.upsert_mls_join_intent(&make_intent(&group.id)).await.unwrap();

        // The same device's intent on ANOTHER group must survive the Add
        let other = make_group(&group_id(2), "channel_consume_b", &creator);
        db.create_mls_group(&other, None).await.unwrap();
        db.upsert_mls_join_intent(&make_intent(&other.id)).await.unwrap();

        assert_eq!(
            db.fetch_mls_join_intents_for_group(&group.id)
                .await
                .unwrap()
                .len(),
            1
        );

        // The commit that ADDS the joiner consumes its intent row —
        // afterwards, an intent held by a member can only mean a rejoin
        let outcome = db
            .insert_mls_commit(&make_commit(
                &group.id,
                1,
                &creator,
                vec![joiner.clone()],
                vec![],
                "add bob",
            ))
            .await
            .unwrap();
        assert!(matches!(outcome, MlsCommitOutcome::Won));

        assert!(db
            .fetch_mls_join_intents_for_group(&group.id)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            db.fetch_mls_join_intents_for_group(&other.id)
                .await
                .unwrap()
                .len(),
            1
        );
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

// ---------------------------------------------------------------------------
// Protected-channel Text groups (protected channels design §2.5, §3.12.2,
// §6.1, §11). Every test below runs under BOTH drivers. Text user and
// channel ids are ULID-shaped because the stored seat-list body goes through
// the strict §4.1 parser.
// ---------------------------------------------------------------------------

/// A ULID-shaped id (26 Crockford digits) for Text-path users and channels
fn ulid(n: u32) -> String {
    format!("{n:0>26}")
}

const ALICE: u32 = 1;
const BOB: u32 = 2;
const CAROL: u32 = 3;
const DAVE: u32 = 4;
const EVE: u32 = 5;

fn text_device(user: u32, n: u8) -> MlsMemberDevice {
    device(&ulid(user), n)
}

fn identity_row(member: &MlsMemberDevice) -> E2EEIdentity {
    E2EEIdentity {
        id: E2EEIdentity::composite_id(&member.user_id, &member.device_id),
        user_id: member.user_id.clone(),
        device_id: member.device_id.clone(),
        protocol_version: 1,
        ed25519_key: "ed25519".to_string(),
        curve25519_key: "curve25519".to_string(),
        signature: "signature".to_string(),
        fallback_key: E2EESignedKey {
            key_id: "fallback0".to_string(),
            key: "key".to_string(),
            signature: "signature".to_string(),
        },
        previous_fallback_key: None,
        created_at: Timestamp::now_utc(),
        last_seen_at: Timestamp::now_utc(),
        last_session_id: "session".to_string(),
    }
}

fn seconds_from_now(seconds: i64) -> Timestamp {
    if seconds >= 0 {
        Timestamp::now_utc()
            .checked_add(Duration::seconds(seconds))
            .unwrap()
    } else {
        Timestamp::now_utc()
            .checked_sub(Duration::seconds(-seconds))
            .unwrap()
    }
}

/// A Text group to seed: `members` hold leaves (each added an hour ago,
/// except `no_added_entry`), the newest stored seat list is signed by
/// `signer` and seats `seats`, every member device has a live E2EE identity
/// except `revoked`
struct TextSeed {
    seed: u8,
    signer: MlsMemberDevice,
    members: Vec<MlsMemberDevice>,
    seats: Vec<u32>,
    device_cap: u32,
    pending: Vec<u32>,
    revoked: Vec<MlsMemberDevice>,
    no_added_entry: Vec<MlsMemberDevice>,
    created_at: Timestamp,
}

fn text_seed(
    seed: u8,
    signer: &MlsMemberDevice,
    members: &[MlsMemberDevice],
    seats: &[u32],
) -> TextSeed {
    TextSeed {
        seed,
        signer: signer.clone(),
        members: members.to_vec(),
        seats: seats.to_vec(),
        device_cap: 0,
        pending: vec![],
        revoked: vec![],
        no_added_entry: vec![],
        created_at: Timestamp::now_utc(),
    }
}

struct TextFixture {
    channel_id: String,
    group: MlsGroup,
    hash: String,
}

fn seat_list_row(
    channel_id: &str,
    version: i64,
    device_cap: u32,
    signer: &MlsMemberDevice,
    seats: &[u32],
) -> SeatList {
    let mut seats: Vec<String> = seats.iter().map(|user| ulid(*user)).collect();
    seats.sort();
    seats.dedup();
    let body = format!(
        "sloga-seat-list-v1\nv:1\nchannel_id:{channel_id}\nversion:{version}\ndevice_cap:{device_cap}\nissued_at:0\nsigner_user_id:{}\nsigner_device_id:{}\nseats:{}",
        signer.user_id,
        signer.device_id,
        seats.join(",")
    );

    SeatList {
        id: channel_id.to_string(),
        version,
        body,
        signer_user_id: signer.user_id.clone(),
        signer_device_id: signer.device_id.clone(),
        signature: "A".repeat(86),
        handovers: vec![],
        updated_at: Timestamp::now_utc(),
    }
}

/// Store a GENESIS seat-list row directly, with the ACTIVE `channel_seats`
/// rows protect would claim for its seats. Fixture-only: the genesis path
/// (`protect_channel`) also needs a real channel document, which these
/// data-layer tests do not have. Every LATER list in these tests goes
/// through the real seat PUT ([`put_next_seat_list`]).
async fn store_genesis_seat_list(db: &Database, row: &SeatList) {
    let seats: Vec<ChannelSeat> = SeatListBody::parse(&row.body)
        .expect("genesis body")
        .seats
        .iter()
        .map(|user_id| ChannelSeat {
            id: ChannelSeat::composite_id(&row.id, user_id),
            channel_id: row.id.clone(),
            user_id: user_id.clone(),
            seated_at: Timestamp::now_utc(),
            released_at: None,
            cooldown_until: None,
        })
        .collect();

    match db {
        Database::Reference(reference) => {
            reference
                .channel_seat_lists
                .lock()
                .await
                .insert(row.id.clone(), row.clone());
            let mut stored = reference.channel_seats.lock().await;
            for seat in seats {
                stored.insert(seat.id.clone(), seat);
            }
        }
        #[cfg(feature = "mongodb")]
        Database::MongoDb(mongo) => {
            mongo
                .col::<SeatList>("channel_seat_lists")
                .replace_one(bson::doc! { "_id": &row.id }, row)
                .with_options(
                    mongodb::options::ReplaceOptions::builder()
                        .upsert(true)
                        .build(),
                )
                .await
                .expect("seat list row");
            for seat in &seats {
                mongo
                    .col::<ChannelSeat>("channel_seats")
                    .insert_one(seat)
                    .await
                    .expect("seat row");
            }
        }
    }
}

/// The REAL seat PUT (`AbstractProtectedChannels::put_seat_list`): stores
/// list `version` (seats `seats`, signed by `signer`), claims and releases
/// the seats, and writes the open Text group's new `seat_list_ad_sha256`
/// and pending removals, all in ONE transaction. Returns the new AD hash.
async fn put_next_seat_list(
    db: &Database,
    channel_id: &str,
    version: i64,
    signer: &MlsMemberDevice,
    seats: &[u32],
) -> String {
    try_put_next_seat_list(db, channel_id, version, signer, seats)
        .await
        .expect("seat PUT")
}

/// [`put_next_seat_list`] without the unwrap: a racing PUT may exhaust its
/// transaction attempts and return the database error (design §2.5 (a))
async fn try_put_next_seat_list(
    db: &Database,
    channel_id: &str,
    version: i64,
    signer: &MlsMemberDevice,
    seats: &[u32],
) -> revolt_result::Result<String> {
    let row = seat_list_row(channel_id, version, 0, signer, seats);
    let outcome = db
        .put_seat_list(
            channel_id,
            &SeatListSubmission {
                body: row.body.clone(),
                signature: row.signature.clone(),
                signer_device_id: signer.device_id.clone(),
                handover: None,
            },
            Timestamp::now_utc(),
        )
        .await?;
    // `unchanged` = a re-PUT of bytes an earlier (errored-but-committed)
    // attempt already stored: the idempotent success of 4.3 step 4
    Ok(outcome.list.commit_ad_sha256().expect("stored list hash"))
}

/// Insert a Text group document directly. Fixture-only: the real create
/// path (`create_text_mls_group`) only makes a creator-only group at epoch
/// 0, while these tests need rosters, `member_added` entries and pending
/// removals that only a sequence of commits and seat PUTs could otherwise
/// build. `create_mls_group` refuses Text groups (tested below).
async fn insert_raw_group(db: &Database, group: &MlsGroup) {
    match db {
        Database::Reference(reference) => {
            reference
                .mls_groups
                .lock()
                .await
                .insert(group.id.clone(), group.clone());
        }
        #[cfg(feature = "mongodb")]
        Database::MongoDb(mongo) => {
            mongo
                .col::<MlsGroup>("mls_groups")
                .insert_one(group)
                .await
                .expect("raw group");
        }
    }
}

/// Whether the test runs against MongoDB. Concurrency properties (write
/// conflicts, transaction retries, field-level vs whole-document writes) are
/// only REALLY exercised there: the Reference driver serializes every
/// operation under its mutexes. Tests that depend on this say so, still
/// assert what is meaningful under Reference, and print a note.
fn is_mongo(db: &Database) -> bool {
    match db {
        Database::Reference(_) => false,
        #[cfg(feature = "mongodb")]
        Database::MongoDb(_) => true,
    }
}

fn reference_note(db: &Database, test: &str, what: &str) {
    if !is_mongo(db) {
        eprintln!(
            "NOTE {test}: under TEST_DB=REFERENCE {what} is structural (mutex-serialized, \
             in-place); the race / field-level property is exercised under TEST_DB=MONGODB"
        );
    }
}

/// An Active entitlement for a fixture channel (the real seat PUT claims
/// seats against it)
async fn grant_entitlement(db: &Database, channel_id: &str) {
    db.upsert_channel_entitlement(
        &ChannelEntitlement {
            id: Ulid::new().to_string(),
            channel_id: channel_id.to_string(),
            server_id: "server".to_string(),
            source: ChannelEntitlementSource::AdminGrant,
            slot_cap: 100,
            device_cap: None,
            state: ChannelEntitlementState::Active,
            granted_by: "admin".to_string(),
            created_at: Timestamp::now_utc(),
        },
        Timestamp::now_utc(),
    )
    .await
    .expect("entitlement");
}

/// Store a commit row directly, bypassing every rule (a crashed or foreign
/// writer)
async fn insert_raw_commit(db: &Database, commit: &MlsCommit) {
    match db {
        Database::Reference(reference) => {
            reference
                .mls_commits
                .lock()
                .await
                .insert(commit.id.clone(), commit.clone());
        }
        #[cfg(feature = "mongodb")]
        Database::MongoDb(mongo) => {
            mongo
                .col::<MlsCommit>("mls_commits")
                .insert_one(commit)
                .await
                .expect("raw commit");
        }
    }
}

async fn seed_text_group(db: &Database, seed: &TextSeed) -> TextFixture {
    let channel_id = ulid(1000 + seed.seed as u32);
    let genesis = seat_list_row(&channel_id, 1, seed.device_cap, &seed.signer, &seed.seats);
    // The one source of truth for the AD hash (shared with the seat PUT)
    let hash = genesis.commit_ad_sha256().expect("genesis hash");
    let an_hour_ago = seconds_from_now(-3600);

    let group = MlsGroup {
        id: group_id(seed.seed),
        channel_id: channel_id.clone(),
        open: true,
        created_by: seed.signer.clone(),
        created_at: seed.created_at,
        current_epoch: 0,
        members: seed.members.clone(),
        closed_at: None,
        superseded_by: None,
        kind: MlsGroupKind::Text,
        generation: Some(0),
        seat_list_ad_sha256: Some(hash.clone()),
        pending_removals: seed
            .pending
            .iter()
            .map(|user| MlsPendingRemoval {
                user_id: ulid(*user),
                created_at: an_hour_ago,
            })
            .collect(),
        member_added: seed
            .members
            .iter()
            .filter(|member| !seed.no_added_entry.contains(member))
            .map(|member| MlsMemberAdded {
                user_id: member.user_id.clone(),
                device_id: member.device_id.clone(),
                epoch: 0,
                at: an_hour_ago,
            })
            .collect(),
    };

    insert_raw_group(db, &group).await;
    store_genesis_seat_list(db, &genesis).await;
    grant_entitlement(db, &channel_id).await;
    // Identities are per (user, device), not per group, and one test seeds
    // several fixtures with the same devices: bring the directory to THIS
    // fixture's state (live unless `revoked`) rather than blindly inserting
    for member in &seed.members {
        let exists = db
            .fetch_e2ee_identity(&member.user_id, &member.device_id)
            .await
            .is_ok();
        if seed.revoked.contains(member) {
            if exists {
                db.delete_e2ee_device(&member.user_id, &member.device_id)
                    .await
                    .expect("revoke identity");
            }
        } else if !exists {
            db.insert_e2ee_identity(&identity_row(member))
                .await
                .expect("identity");
        }
    }

    // The stored form (Mongo truncates timestamps to milliseconds)
    let group = db.fetch_mls_group(&group.id).await.expect("seeded group");
    TextFixture {
        channel_id,
        group,
        hash,
    }
}

fn text_commit(
    fixture: &TextFixture,
    epoch: i64,
    committer: &MlsMemberDevice,
    added: Vec<MlsMemberDevice>,
    removed: Vec<MlsMemberDevice>,
    at: Timestamp,
) -> MlsCommit {
    let mut commit = make_commit(
        &fixture.group.id,
        epoch,
        committer,
        added,
        removed,
        &format!("text_commit_{epoch}_{}", committer.device_id),
    );
    commit.created_at = at;
    commit
}

fn rejoin_intent(group: &str, member: &MlsMemberDevice, at: Timestamp) -> MlsJoinIntent {
    MlsJoinIntent {
        id: MlsJoinIntent::composite_id(group, &member.user_id, &member.device_id),
        group_id: group.to_string(),
        user_id: member.user_id.clone(),
        device_id: member.device_id.clone(),
        key_package_ref: "ref0".to_string(),
        signature: format!(
            "sig_{}",
            at.duration_since(Timestamp::UNIX_EPOCH).whole_seconds()
        ),
        created_at: at,
    }
}

fn assert_won(result: revolt_result::Result<MlsCommitOutcome>, what: &str) {
    match result {
        Ok(MlsCommitOutcome::Won) => {}
        other => panic!("{what}: expected Won, got {other:?}"),
    }
}

fn assert_failed_validation(result: revolt_result::Result<MlsCommitOutcome>, what: &str) {
    match result {
        Err(error) => match error.error_type {
            ErrorType::FailedValidation { .. } => {}
            other => panic!("{what}: expected FailedValidation, got {other:?}"),
        },
        Ok(outcome) => panic!("{what}: expected FailedValidation, got {outcome:?}"),
    }
}

fn assert_not_seated(result: revolt_result::Result<MlsCommitOutcome>, what: &str) {
    match result {
        Err(error) => match error.error_type {
            ErrorType::NotSeated => {}
            other => panic!("{what}: expected NotSeated, got {other:?}"),
        },
        Ok(outcome) => panic!("{what}: expected NotSeated, got {outcome:?}"),
    }
}

fn assert_resecuring(result: revolt_result::Result<MlsCommitOutcome>, reason: &str, what: &str) {
    match result {
        Err(error) => match error.error_type {
            ErrorType::ProtectedChannelResecuring { reason: actual } => {
                assert_eq!(actual, reason, "{what}")
            }
            other => panic!("{what}: expected ProtectedChannelResecuring({reason}), got {other:?}"),
        },
        Ok(outcome) => {
            panic!("{what}: expected ProtectedChannelResecuring({reason}), got {outcome:?}")
        }
    }
}

/// A refused Text commit stored nothing and moved nothing
async fn assert_untouched(db: &Database, fixture: &TextFixture, epoch: i64) {
    let group = db.fetch_mls_group(&fixture.group.id).await.unwrap();
    assert_eq!(
        group.current_epoch, epoch,
        "a refused commit never advances the epoch"
    );
    assert!(db
        .fetch_mls_commits_from(&fixture.group.id, epoch + 1, 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn call_and_text_groups_coexist_per_channel() {
    database_test!(|db| async move {
        // The (channel_id, kind) partial unique index is the arbitration
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);
        let channel = ulid(1001);
        // The newest seat list, which the real Text create reads
        store_genesis_seat_list(&db, &seat_list_row(&channel, 1, 0, &alice, &[ALICE])).await;

        let call = make_group(&group_id(1), &channel, &alice);
        assert!(matches!(
            db.create_mls_group(&call, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        ));

        let text_group = |seed: u8, generation: u32| {
            let mut group = make_group(&group_id(seed), &channel, &alice);
            group.kind = MlsGroupKind::Text;
            group.generation = Some(generation);
            group
        };

        // The Call create path refuses a Text group outright
        match db.create_mls_group(&text_group(2, 0), None).await {
            Err(error) => assert!(matches!(error.error_type, ErrorType::InvalidOperation)),
            Ok(outcome) => panic!("create_mls_group accepted a Text group: {outcome:?}"),
        }
        assert!(db
            .fetch_open_mls_group_for_channel(&channel, MlsGroupKind::Text)
            .await
            .unwrap()
            .is_none());

        // The real Text create coexists with the channel's open Call group
        let text = text_group(2, 0);
        assert!(matches!(
            db.create_text_mls_group(&text, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        ));

        // A second creator of each kind conflicts with ITS kind's group
        match db
            .create_text_mls_group(&text_group(3, 0), None)
            .await
            .unwrap()
        {
            MlsGroupCreateOutcome::Conflict { open_group_id, .. } => {
                assert_eq!(open_group_id, text.id)
            }
            _ => panic!("second Text group must conflict"),
        }
        match db
            .create_mls_group(&make_group(&group_id(4), &channel, &alice), None)
            .await
            .unwrap()
        {
            MlsGroupCreateOutcome::Conflict { open_group_id, .. } => {
                assert_eq!(open_group_id, call.id)
            }
            _ => panic!("second Call group must conflict"),
        }

        let open_call = db
            .fetch_open_mls_group_for_channel(&channel, MlsGroupKind::Call)
            .await
            .unwrap()
            .expect("open call group");
        assert_eq!(open_call.id, call.id);
        let open_text = db
            .fetch_open_mls_group_for_channel(&channel, MlsGroupKind::Text)
            .await
            .unwrap()
            .expect("open text group");
        assert_eq!(open_text.id, text.id);

        // Superseding across kinds is refused and closes nothing
        let call_successor = make_group(&group_id(5), &channel, &alice);
        assert!(db
            .create_mls_group(&call_successor, Some(&text.id))
            .await
            .is_err());
        assert!(db.fetch_mls_group(&text.id).await.unwrap().open);

        // A Text successor closes the Text group and leaves the Call group
        // open
        let text_successor = text_group(6, 1);
        assert!(matches!(
            db.create_text_mls_group(&text_successor, Some(&text.id))
                .await
                .unwrap(),
            MlsGroupCreateOutcome::Created
        ));
        assert!(!db.fetch_mls_group(&text.id).await.unwrap().open);
        assert_eq!(
            db.fetch_open_mls_group_for_channel(&channel, MlsGroupKind::Call)
                .await
                .unwrap()
                .expect("call group survives")
                .id,
            call.id
        );
        assert_eq!(
            db.fetch_open_mls_group_for_channel(&channel, MlsGroupKind::Text)
                .await
                .unwrap()
                .expect("text successor")
                .id,
            text_successor.id
        );
    });
}

#[tokio::test]
async fn text_groups_are_never_swept_and_text_commits_age_out() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);

        // An 8-day-old Text group and an 8-day-old Call group
        let mut seed = text_seed(10, &alice, &[alice.clone()], &[ALICE]);
        seed.created_at = seconds_from_now(-8 * 86400);
        let old_text = seed_text_group(&db, &seed).await;

        let mut old_call = make_group(&group_id(11), &ulid(1011), &alice);
        old_call.created_at = seconds_from_now(-8 * 86400);
        db.create_mls_group(&old_call, None).await.unwrap();

        let swept = db
            .sweep_mls_groups(seconds_from_now(-86400), seconds_from_now(-7 * 86400))
            .await
            .unwrap();
        assert_eq!(swept, 1, "only the Call group is swept");
        assert!(db.fetch_mls_group(&old_call.id).await.is_err());
        assert!(db.fetch_mls_group(&old_text.group.id).await.is_ok());

        // Even a CLOSED Text group is never swept. Text groups close only by
        // supersession (close_mls_group refuses them), so supersede it
        let mut successor = make_group(&group_id(14), &old_text.channel_id, &alice);
        successor.kind = MlsGroupKind::Text;
        successor.generation = Some(1);
        assert!(matches!(
            db.create_text_mls_group(&successor, Some(&old_text.group.id))
                .await
                .unwrap(),
            MlsGroupCreateOutcome::Created
        ));
        assert!(!db.fetch_mls_group(&old_text.group.id).await.unwrap().open);
        let swept = db
            .sweep_mls_groups(seconds_from_now(3600), seconds_from_now(-7 * 86400))
            .await
            .unwrap();
        assert_eq!(swept, 0);
        assert!(db.fetch_mls_group(&old_text.group.id).await.is_ok());

        // Retention: a 40-day-old and a 1-day-old Text commit, and a
        // 40-day-old Call commit
        let text = seed_text_group(&db, &text_seed(12, &alice, &[alice.clone()], &[ALICE])).await;
        assert_won(
            db.insert_mls_text_commit(
                &text_commit(
                    &text,
                    1,
                    &alice,
                    vec![],
                    vec![],
                    seconds_from_now(-40 * 86400),
                ),
                &text.hash,
                0,
            )
            .await,
            "old text commit",
        );
        assert_won(
            db.insert_mls_text_commit(
                &text_commit(&text, 2, &alice, vec![], vec![], seconds_from_now(-86400)),
                &text.hash,
                0,
            )
            .await,
            "recent text commit",
        );

        let call = make_group(&group_id(13), &ulid(1013), &alice);
        db.create_mls_group(&call, None).await.unwrap();
        let mut old_call_commit = make_commit(&call.id, 1, &alice, vec![], vec![], "old call");
        old_call_commit.created_at = seconds_from_now(-40 * 86400);
        assert!(matches!(
            db.insert_mls_commit(&old_call_commit).await.unwrap(),
            MlsCommitOutcome::Won
        ));

        let pruned = db
            .prune_mls_text_commits(seconds_from_now(-30 * 86400))
            .await
            .unwrap();
        assert_eq!(pruned, 1, "only the old TEXT commit is pruned");

        let kept: Vec<i64> = db
            .fetch_mls_commits_from(&text.group.id, 0, 10)
            .await
            .unwrap()
            .iter()
            .map(|commit| commit.epoch)
            .collect();
        assert_eq!(kept, vec![2]);
        assert_eq!(
            db.fetch_mls_commits_from(&call.id, 0, 10)
                .await
                .unwrap()
                .len(),
            1,
            "Call commits are never pruned by Text retention"
        );
        assert_eq!(
            db.prune_mls_text_commits(seconds_from_now(-30 * 86400))
                .await
                .unwrap(),
            0
        );
    });
}

#[tokio::test]
async fn text_commit_existing_row_returns_lost_before_any_validity_check() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);
        let bob = text_device(BOB, 1);
        let fixture = seed_text_group(
            &db,
            &text_seed(20, &alice, &[alice.clone(), bob.clone()], &[ALICE, BOB]),
        )
        .await;

        let bobs = text_commit(&fixture, 1, &bob, vec![], vec![], Timestamp::now_utc());
        assert_won(
            db.insert_mls_text_commit(&bobs, &fixture.hash, 0).await,
            "bob's epoch 1",
        );

        // An identical resubmit is idempotent: it gets its own row back
        match db
            .insert_mls_text_commit(&bobs, &fixture.hash, 0)
            .await
            .unwrap()
        {
            MlsCommitOutcome::Lost { winning } => {
                assert_eq!(winning.commit, bobs.commit);
                assert_eq!(winning.committer, bob);
            }
            _ => panic!("identical resubmit must return the stored row"),
        }

        // The owner unseats bob through the real seat PUT (bob pending),
        // then alice removes bob
        let new_hash = put_next_seat_list(&db, &fixture.channel_id, 2, &alice, &[ALICE]).await;
        assert!(db
            .fetch_mls_group(&fixture.group.id)
            .await
            .unwrap()
            .has_pending_removal(&bob.user_id));
        assert_won(
            db.insert_mls_text_commit(
                &text_commit(
                    &fixture,
                    2,
                    &alice,
                    vec![],
                    vec![bob.clone()],
                    Timestamp::now_utc(),
                ),
                &new_hash,
                0,
            )
            .await,
            "alice removes pending bob",
        );

        // Bob's resubmit STILL returns his own row: removed, a stale AD and
        // an old epoch would each refuse it, but the existing row comes first
        match db
            .insert_mls_text_commit(&bobs, &fixture.hash, 0)
            .await
            .unwrap()
        {
            MlsCommitOutcome::Lost { winning } => {
                assert_eq!(winning.commit, bobs.commit);
                assert_eq!(winning.committer, bob);
            }
            _ => panic!("resubmit after removal must return the stored row"),
        }

        // A NEW epoch from the removed device is refused as not_member
        assert_resecuring(
            db.insert_mls_text_commit(
                &text_commit(&fixture, 3, &bob, vec![], vec![], Timestamp::now_utc()),
                &new_hash,
                0,
            )
            .await,
            "not_member",
            "removed device commits",
        );
        assert_untouched(&db, &fixture, 2).await;
    });
}

#[tokio::test]
async fn text_commit_with_a_stale_ad_is_refused_and_writes_nothing() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);
        let bob = text_device(BOB, 1);
        let fixture =
            seed_text_group(&db, &text_seed(21, &alice, &[alice.clone()], &[ALICE, BOB])).await;

        // The joiner's intent must survive an aborted Add
        db.upsert_mls_join_intent(&rejoin_intent(
            &fixture.group.id,
            &bob,
            Timestamp::now_utc(),
        ))
        .await
        .unwrap();

        // A well-formed hash of some other list
        let stale = "0".repeat(64);
        assert_resecuring(
            db.insert_mls_text_commit(
                &text_commit(
                    &fixture,
                    1,
                    &alice,
                    vec![bob.clone()],
                    vec![],
                    Timestamp::now_utc(),
                ),
                &stale,
                0,
            )
            .await,
            "stale_seat_list",
            "stale AD",
        );
        assert_untouched(&db, &fixture, 0).await;
        assert_eq!(
            db.fetch_mls_join_intents_for_group(&fixture.group.id)
                .await
                .unwrap()
                .len(),
            1,
            "an aborted commit consumes no intent"
        );

        // The same Add with the current AD wins and consumes the intent
        assert_won(
            db.insert_mls_text_commit(
                &text_commit(
                    &fixture,
                    1,
                    &alice,
                    vec![bob.clone()],
                    vec![],
                    Timestamp::now_utc(),
                ),
                &fixture.hash,
                0,
            )
            .await,
            "add bob",
        );
        assert!(db
            .fetch_mls_join_intents_for_group(&fixture.group.id)
            .await
            .unwrap()
            .is_empty());

        let group = db.fetch_mls_group(&fixture.group.id).await.unwrap();
        assert!(group.has_member(&bob.user_id, &bob.device_id));
        let entry = group
            .member_added
            .iter()
            .find(|entry| entry.user_id == bob.user_id && entry.device_id == bob.device_id)
            .expect("member_added entry for the added device");
        assert_eq!(entry.epoch, 1);
    });
}

/// §11 W0-fix3/fix4: the REAL seat PUT (`put_seat_list`, one transaction
/// writing the list row, the seat rows, the group's `seat_list_ad_sha256` and
/// its pending removals) racing Text commits that carry the OLD list's AD.
/// MONGODB is where this is a real race (write-conflict detection between
/// two multi-document transactions); under REFERENCE both sides run under
/// the same collection mutexes, so it checks the same invariants against a
/// serialized interleaving.
#[tokio::test]
async fn seat_list_write_racing_text_commits_never_lets_a_stale_ad_win() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");
        reference_note(
            &db,
            "seat_list_write_racing_text_commits_never_lets_a_stale_ad_win",
            "the commit/PUT interleaving",
        );

        let alice = text_device(ALICE, 1);
        let bob = text_device(BOB, 1);
        let carol = text_device(CAROL, 1);

        for round in 0..8u8 {
            let fixture = seed_text_group(
                &db,
                &text_seed(
                    40 + round,
                    &alice,
                    &[alice.clone(), bob.clone(), carol.clone()],
                    &[ALICE, BOB, CAROL],
                ),
            )
            .await;

            // Bob keeps committing Updates with the OLD list's AD until the
            // DS refuses it. A DS that ignored the AD would never refuse.
            // No pacing: commits go back to back. The seat PUT claims the
            // group document first (protected-channels `claim_groups_first`);
            // measured in isolation against this exact back-to-back committer
            // its first write conflicted 1 in 40 and the real PUT landed 8 of
            // 8. Under heavy parallel load on the same mongod (the rest of
            // this suite), a PUT can still exhaust its 5 attempts; per design
            // 4.9 the owner then re-PUTs the same bytes, which the writer
            // does (bounded) and reports. Safety is asserted below either way.
            let committer = {
                let db = db.clone();
                let bob = bob.clone();
                let old_hash = fixture.hash.clone();
                let group = fixture.group.id.clone();
                tokio::spawn(async move {
                    let mut epoch = 1;
                    for _ in 0..2_000 {
                        let commit = make_commit(&group, epoch, &bob, vec![], vec![], "update");
                        match db.insert_mls_text_commit(&commit, &old_hash, 0).await {
                            Ok(MlsCommitOutcome::Won) => epoch += 1,
                            Ok(MlsCommitOutcome::Lost { .. }) => panic!("single committer lost"),
                            Err(error) => match error.error_type {
                                ErrorType::ProtectedChannelResecuring { reason }
                                    if reason == "stale_seat_list" =>
                                {
                                    return epoch - 1
                                }
                                other => panic!("unexpected refusal {other:?}"),
                            },
                        }
                        tokio::task::yield_now().await;
                    }
                    panic!("a commit with the old AD was never refused");
                })
            };

            // The owner's real seat PUT (unseating carol) lands once the
            // group reaches a round-dependent epoch, mid-stream
            let writer = {
                let db = db.clone();
                let alice = alice.clone();
                let group = fixture.group.id.clone();
                let channel = fixture.channel_id.clone();
                let target = (round % 4) as i64;
                tokio::spawn(async move {
                    loop {
                        let group_now = db.fetch_mls_group(&group).await.unwrap();
                        if group_now.current_epoch >= target {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    // A PUT that loses every transaction attempt returns the
                    // database error; the owner re-PUTs the same bytes
                    // (design 4.9). Bounded, and counted.
                    let mut failed_puts = 0u32;
                    loop {
                        match try_put_next_seat_list(&db, &channel, 2, &alice, &[ALICE, BOB]).await
                        {
                            Ok(hash) => break (hash, failed_puts),
                            Err(error)
                                if matches!(error.error_type, ErrorType::DatabaseError { .. })
                                    && failed_puts < 20 =>
                            {
                                failed_puts += 1
                            }
                            Err(error) => panic!("seat PUT: {error:?}"),
                        }
                    }
                })
            };

            let (new_hash, failed_puts) = writer.await.expect("writer");
            let last_won = committer.await.expect("committer");
            if failed_puts > 0 {
                eprintln!("NOTE round {round}: the racing seat PUT exhausted its transaction attempts {failed_puts} time(s) before landing");
            }

            // No commit landed after the committer was refused: every
            // accepted old-AD commit was sequenced BEFORE the PUT
            let group = db.fetch_mls_group(&fixture.group.id).await.unwrap();
            assert_eq!(group.current_epoch, last_won, "round {round}");
            assert!(db
                .fetch_mls_commits_from(&fixture.group.id, last_won + 1, 10)
                .await
                .unwrap()
                .is_empty());

            // The PUT's writes were never lost or reverted by a commit
            assert_eq!(
                group.seat_list_ad_sha256.as_deref(),
                Some(new_hash.as_str()),
                "round {round}"
            );
            assert!(group.has_pending_removal(&carol.user_id), "round {round}");

            // ... and the new list's AD is now the binding one
            assert_won(
                db.insert_mls_text_commit(
                    &make_commit(&fixture.group.id, last_won + 1, &bob, vec![], vec![], "new"),
                    &new_hash,
                    0,
                )
                .await,
                "commit embedding the new list",
            );
        }
    });
}

/// Racing Text commits at the SAME epoch: exactly one wins and every other
/// committer gets `Lost` with that winner. Under MONGODB the losers' inserts
/// hit write conflicts (`TransientTransactionError`), so this exercises the
/// whole-transaction retry branch (with backoff), which then returns `Lost`
/// from the existing-row check; the retry counter proves the branch ran.
/// Under REFERENCE the commits are serialized by the mutexes (no retries)
/// and the one-winner property is what is checked.
#[tokio::test]
async fn racing_text_commits_retry_and_lose_cleanly() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");
        reference_note(
            &db,
            "racing_text_commits_retry_and_lose_cleanly",
            "the retry branch",
        );

        let alice = text_device(ALICE, 1);
        let roster: Vec<MlsMemberDevice> = std::iter::once(alice.clone())
            .chain((1..=7u8).map(|n| text_device(BOB, n)))
            .collect();

        #[cfg(feature = "mongodb")]
        let retries_before =
            super::ops::TEXT_COMMIT_RETRIES.load(std::sync::atomic::Ordering::SeqCst);

        for round in 0..6u8 {
            let fixture =
                seed_text_group(&db, &text_seed(60 + round, &alice, &roster, &[ALICE, BOB])).await;

            let mut handles = Vec::new();
            for committer in roster.clone() {
                let db = db.clone();
                let commit = text_commit(
                    &fixture,
                    1,
                    &committer,
                    vec![],
                    vec![],
                    Timestamp::now_utc(),
                );
                let hash = fixture.hash.clone();
                handles.push(tokio::spawn(async move {
                    db.insert_mls_text_commit(&commit, &hash, 0).await
                }));
            }

            let mut won = 0;
            let mut winners = Vec::new();
            for handle in handles {
                match handle
                    .await
                    .expect("join")
                    .expect("a racing commit must not error")
                {
                    MlsCommitOutcome::Won => won += 1,
                    MlsCommitOutcome::Lost { winning } => winners.push(winning),
                }
            }
            assert_eq!(won, 1, "round {round}: exactly one winner");
            let stored = db
                .fetch_mls_commits_from(&fixture.group.id, 1, 10)
                .await
                .unwrap();
            assert_eq!(stored.len(), 1);
            assert!(winners
                .iter()
                .all(|winning| winning.commit == stored[0].commit
                    && winning.committer == stored[0].committer));
            assert_eq!(
                db.fetch_mls_group(&fixture.group.id)
                    .await
                    .unwrap()
                    .current_epoch,
                1
            );
        }

        #[cfg(feature = "mongodb")]
        if is_mongo(&db) {
            let retries = super::ops::TEXT_COMMIT_RETRIES.load(std::sync::atomic::Ordering::SeqCst)
                - retries_before;
            assert!(
                retries > 0,
                "racing same-epoch Text commits never took the retry branch"
            );
        }
    });
}

/// N1 (re-audit): a forced seat release (kick, ban, leave) racing a Text Add
/// of that user's device must never end with the user a member while their
/// seat is released and no pending removal exists. The release leaves the
/// user ON the signed list and, for a not-yet-member, writes no document the
/// Add writes except the seat row, so the Add's in-transaction seat check
/// is what closes it.
///
/// Even rounds: the release lands strictly BEFORE the Add, the exact hole
/// (must be `NotSeated`). Odd rounds: the two run concurrently; either order
/// is fine, but an Add that wins must leave a pending removal behind it.
/// The concurrent rounds are a real race only under MONGODB (write conflict
/// on the seat row); under REFERENCE the mutexes serialize them.
#[tokio::test]
async fn seat_release_racing_a_text_add_never_admits_a_released_user() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");
        reference_note(
            &db,
            "seat_release_racing_a_text_add_never_admits_a_released_user",
            "the concurrent release/Add interleaving",
        );

        let alice = text_device(ALICE, 1);
        let carol = text_device(CAROL, 1);
        let mut won_rounds = 0;
        let mut refused_rounds = 0;

        for round in 0..24u8 {
            let fixture = seed_text_group(
                &db,
                &text_seed(120 + round, &alice, &[alice.clone()], &[ALICE, CAROL]),
            )
            .await;
            let add = text_commit(
                &fixture,
                1,
                &alice,
                vec![carol.clone()],
                vec![],
                Timestamp::now_utc(),
            );

            let outcome = if round % 2 == 0 {
                db.release_channel_seats_for_user(&carol.user_id, None, Timestamp::now_utc())
                    .await
                    .expect("release");
                db.insert_mls_text_commit(&add, &fixture.hash, 0).await
            } else {
                let adder = {
                    let db = db.clone();
                    let hash = fixture.hash.clone();
                    tokio::spawn(async move { db.insert_mls_text_commit(&add, &hash, 0).await })
                };
                let releaser = {
                    let db = db.clone();
                    let user = carol.user_id.clone();
                    tokio::spawn(async move {
                        db.release_channel_seats_for_user(&user, None, Timestamp::now_utc())
                            .await
                    })
                };
                releaser.await.expect("join").expect("release");
                adder.await.expect("join")
            };

            let group = db.fetch_mls_group(&fixture.group.id).await.unwrap();
            let seat = db
                .fetch_channel_seats(&fixture.channel_id)
                .await
                .unwrap()
                .into_iter()
                .find(|seat| seat.user_id == carol.user_id)
                .expect("carol's seat row");
            assert!(seat.released_at.is_some(), "round {round}: release ran");

            match outcome {
                Ok(MlsCommitOutcome::Won) => {
                    won_rounds += 1;
                    assert!(round % 2 == 1, "round {round}: Add after the release WON");
                    assert!(group.has_member(&carol.user_id, &carol.device_id));
                }
                Err(error) if matches!(error.error_type, ErrorType::NotSeated) => {
                    refused_rounds += 1;
                    assert!(!group.has_member(&carol.user_id, &carol.device_id));
                }
                other => panic!("round {round}: unexpected outcome {other:?}"),
            }

            // The invariant: a released user is never a member without a
            // pending removal that makes the group evict them
            assert!(
                group.member_devices_of(&carol.user_id).next().is_none()
                    || group.has_pending_removal(&carol.user_id),
                "round {round}: carol is a member, seat released, no pending removal"
            );
        }

        eprintln!("seat release vs Add: {won_rounds} Add-first, {refused_rounds} refused");
    });
}

/// Close paths touch Call groups only (design §2.5): `close_mls_group`
/// keeps its Call semantics and REFUSES a Text group (`InvalidOperation`),
/// leaving it open, on both drivers.
#[tokio::test]
async fn close_mls_group_refuses_text_groups_and_keeps_call_semantics() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);

        // Call: unchanged (true, then idempotent false; unknown = NotFound)
        let call = make_group(&group_id(110), &ulid(1110), &alice);
        db.create_mls_group(&call, None).await.unwrap();
        assert!(db.close_mls_group(&call.id).await.unwrap());
        assert!(!db.close_mls_group(&call.id).await.unwrap());
        let closed = db.fetch_mls_group(&call.id).await.unwrap();
        assert!(!closed.open);
        assert!(closed.closed_at.is_some());
        match db.close_mls_group(&group_id(119)).await {
            Err(error) => assert!(matches!(error.error_type, ErrorType::NotFound)),
            Ok(result) => panic!("closing an unknown group returned {result}"),
        }

        // Text: refused loudly and left exactly as it was
        let fixture =
            seed_text_group(&db, &text_seed(111, &alice, &[alice.clone()], &[ALICE])).await;
        match db.close_mls_group(&fixture.group.id).await {
            Err(error) => assert!(matches!(error.error_type, ErrorType::InvalidOperation)),
            Ok(result) => panic!("close_mls_group touched a Text group (returned {result})"),
        }
        assert_eq!(
            db.fetch_mls_group(&fixture.group.id).await.unwrap(),
            fixture.group
        );
        assert_eq!(
            db.fetch_open_mls_group_for_channel(&fixture.channel_id, MlsGroupKind::Text)
                .await
                .unwrap()
                .expect("still open")
                .id,
            fixture.group.id
        );
    });
}

#[tokio::test]
async fn text_remove_rule_accepts_each_permitted_case() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);
        let bob = text_device(BOB, 1);
        let bob2 = text_device(BOB, 2);
        let carol = text_device(CAROL, 1);
        let dave = text_device(DAVE, 1);
        let eve = text_device(EVE, 1);
        let roster = vec![
            alice.clone(),
            bob.clone(),
            bob2.clone(),
            carol.clone(),
            dave.clone(),
            eve.clone(),
        ];
        // EVE holds a leaf but is OFF the newest list
        let seats = [ALICE, BOB, CAROL, DAVE];
        let remove = |fixture: &TextFixture, by: &MlsMemberDevice, target: &MlsMemberDevice| {
            text_commit(
                fixture,
                1,
                by,
                vec![],
                vec![target.clone()],
                Timestamp::now_utc(),
            )
        };

        // Rule 2: a device of the committer's own user
        let fixture = seed_text_group(&db, &text_seed(50, &alice, &roster, &seats)).await;
        assert_won(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &bob2), &fixture.hash, 0)
                .await,
            "own-user device",
        );
        let group = db.fetch_mls_group(&fixture.group.id).await.unwrap();
        assert!(!group.has_member(&bob2.user_id, &bob2.device_id));
        assert!(!group
            .member_added
            .iter()
            .any(|entry| entry.user_id == bob2.user_id && entry.device_id == bob2.device_id));

        // Rule 3: a pending user, still on the list, by a NON-owner member
        let mut seed = text_seed(51, &alice, &roster, &seats);
        seed.pending = vec![CAROL];
        let fixture = seed_text_group(&db, &seed).await;
        assert_won(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &carol), &fixture.hash, 0)
                .await,
            "pending user",
        );
        let group = db.fetch_mls_group(&fixture.group.id).await.unwrap();
        assert!(
            group.pending_removals.is_empty(),
            "the pending entry clears once the user has no device left"
        );

        // Rule 4: a revoked device (no identity row)
        let mut seed = text_seed(52, &alice, &roster, &seats);
        seed.revoked = vec![dave.clone()];
        let fixture = seed_text_group(&db, &seed).await;
        assert_won(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &dave), &fixture.hash, 0)
                .await,
            "revoked device",
        );

        // Rule 5: an off-list user, by the current list signer's device
        let fixture = seed_text_group(&db, &text_seed(53, &alice, &roster, &seats)).await;
        assert_won(
            db.insert_mls_text_commit(&remove(&fixture, &alice, &eve), &fixture.hash, 0)
                .await,
            "owner removes an off-list user",
        );

        // Rule 6 for an ordinary member: a fresh rejoin intent from it
        let fixture = seed_text_group(&db, &text_seed(54, &alice, &roster, &seats)).await;
        let intent = rejoin_intent(&fixture.group.id, &carol, seconds_from_now(-5));
        db.upsert_mls_join_intent(&intent).await.unwrap();
        assert_won(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &carol), &fixture.hash, 0)
                .await,
            "rejoin intent for an ordinary member",
        );
        let stored = db
            .fetch_mls_commits_from(&fixture.group.id, 1, 1)
            .await
            .unwrap();
        assert_eq!(stored[0].rejoin_intents.len(), 1);
        assert_eq!(stored[0].rejoin_intents[0].id, intent.id);
    });
}

#[tokio::test]
async fn text_remove_rule_refuses_everything_else() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);
        let alice2 = text_device(ALICE, 2);
        let bob = text_device(BOB, 1);
        let carol = text_device(CAROL, 1);
        let dave = text_device(DAVE, 1);
        let eve = text_device(EVE, 1);
        let roster = vec![
            alice.clone(),
            alice2.clone(),
            bob.clone(),
            carol.clone(),
            dave.clone(),
            eve.clone(),
        ];
        let seats = [ALICE, BOB, CAROL, DAVE];
        let remove = |fixture: &TextFixture, by: &MlsMemberDevice, target: &MlsMemberDevice| {
            text_commit(
                fixture,
                1,
                by,
                vec![],
                vec![target.clone()],
                Timestamp::now_utc(),
            )
        };

        let fixture = seed_text_group(&db, &text_seed(60, &alice, &roster, &seats)).await;

        // Off-list, not pending, live identity, by a NON-owner: refused
        assert_failed_validation(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &eve), &fixture.hash, 0)
                .await,
            "non-owner removes an off-list user",
        );
        // On the list, not pending, live identity: refused
        assert_failed_validation(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &carol), &fixture.hash, 0)
                .await,
            "plain member",
        );
        // A device never removes itself
        assert_failed_validation(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &bob), &fixture.hash, 0)
                .await,
            "self-removal",
        );
        // A non-member
        assert_failed_validation(
            db.insert_mls_text_commit(
                &remove(&fixture, &bob, &text_device(BOB, 9)),
                &fixture.hash,
                0,
            )
            .await,
            "non-member",
        );
        // The signer's device by another device of the owner user
        assert_failed_validation(
            db.insert_mls_text_commit(&remove(&fixture, &alice2, &alice), &fixture.hash, 0)
                .await,
            "signer device by own user",
        );
        assert_untouched(&db, &fixture, 0).await;

        // The signer's device while the owner is pending
        let mut seed = text_seed(61, &alice, &roster, &seats);
        seed.pending = vec![ALICE];
        let fixture = seed_text_group(&db, &seed).await;
        assert_failed_validation(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &alice), &fixture.hash, 0)
                .await,
            "signer device while pending",
        );

        // The signer's device while revoked
        let mut seed = text_seed(62, &alice, &roster, &seats);
        seed.revoked = vec![alice.clone()];
        let fixture = seed_text_group(&db, &seed).await;
        assert_failed_validation(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &alice), &fixture.hash, 0)
                .await,
            "signer device while revoked",
        );

        // Revoked case: the identity RE-EXISTS at transaction time
        let mut seed = text_seed(63, &alice, &roster, &seats);
        seed.revoked = vec![dave.clone()];
        let fixture = seed_text_group(&db, &seed).await;
        db.insert_e2ee_identity(&identity_row(&dave)).await.unwrap();
        assert_failed_validation(
            db.insert_mls_text_commit(&remove(&fixture, &bob, &dave), &fixture.hash, 0)
                .await,
            "re-registered identity",
        );
        assert_untouched(&db, &fixture, 0).await;
    });
}

#[tokio::test]
async fn rejoin_remove_of_the_signer_device_is_one_shot_per_add() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);
        let bob = text_device(BOB, 1);
        let fixture = seed_text_group(
            &db,
            &text_seed(70, &alice, &[alice.clone(), bob.clone()], &[ALICE, BOB]),
        )
        .await;
        let group = fixture.group.id.clone();
        let remove_alice = |epoch: i64, at: Timestamp| {
            text_commit(&fixture, epoch, &bob, vec![], vec![alice.clone()], at)
        };
        let readd_alice = |epoch: i64, at: Timestamp| {
            text_commit(&fixture, epoch, &bob, vec![alice.clone()], vec![], at)
        };

        // No intent: refused
        assert_failed_validation(
            db.insert_mls_text_commit(&remove_alice(1, Timestamp::now_utc()), &fixture.hash, 0)
                .await,
            "no intent",
        );

        // A stale intent (> 30 s): refused
        db.upsert_mls_join_intent(&rejoin_intent(&group, &alice, seconds_from_now(-60)))
            .await
            .unwrap();
        assert_failed_validation(
            db.insert_mls_text_commit(&remove_alice(1, Timestamp::now_utc()), &fixture.hash, 0)
                .await,
            "stale intent",
        );

        // A fresh intent: accepted, copied into the row, consumed
        let intent = rejoin_intent(&group, &alice, seconds_from_now(-5));
        db.upsert_mls_join_intent(&intent).await.unwrap();
        assert_won(
            db.insert_mls_text_commit(&remove_alice(1, Timestamp::now_utc()), &fixture.hash, 0)
                .await,
            "fresh rejoin intent",
        );
        let row = db.fetch_mls_commits_from(&group, 1, 1).await.unwrap();
        assert_eq!(row[0].rejoin_intents.len(), 1);
        assert_eq!(row[0].rejoin_intents[0].id, intent.id);
        assert_eq!(row[0].rejoin_intents[0].signature, intent.signature);
        assert!(db
            .fetch_mls_join_intents_for_group(&group)
            .await
            .unwrap()
            .is_empty());

        // Re-Add one second from now
        assert_won(
            db.insert_mls_text_commit(&readd_alice(2, seconds_from_now(1)), &fixture.hash, 0)
                .await,
            "re-add",
        );

        // The consumed intent cannot evict again
        assert_failed_validation(
            db.insert_mls_text_commit(&remove_alice(3, seconds_from_now(3)), &fixture.hash, 0)
                .await,
            "consumed intent",
        );

        // An intent created BEFORE the re-Add cannot evict either
        db.upsert_mls_join_intent(&rejoin_intent(&group, &alice, seconds_from_now(-1)))
            .await
            .unwrap();
        assert_failed_validation(
            db.insert_mls_text_commit(&remove_alice(3, seconds_from_now(3)), &fixture.hash, 0)
                .await,
            "intent older than member_added.at",
        );

        // A fresh post-re-Add intent evicts exactly once
        db.upsert_mls_join_intent(&rejoin_intent(&group, &alice, seconds_from_now(2)))
            .await
            .unwrap();
        assert_won(
            db.insert_mls_text_commit(&remove_alice(3, seconds_from_now(3)), &fixture.hash, 0)
                .await,
            "fresh post-re-add intent",
        );
        assert_won(
            db.insert_mls_text_commit(&readd_alice(4, seconds_from_now(4)), &fixture.hash, 0)
                .await,
            "second re-add",
        );
        assert_failed_validation(
            db.insert_mls_text_commit(&remove_alice(5, seconds_from_now(5)), &fixture.hash, 0)
                .await,
            "the same intent twice",
        );

        // A current member with NO member_added entry is never evicted by
        // rule 6
        let mut seed = text_seed(71, &alice, &[alice.clone(), bob.clone()], &[ALICE, BOB]);
        seed.no_added_entry = vec![alice.clone()];
        let fixture = seed_text_group(&db, &seed).await;
        db.upsert_mls_join_intent(&rejoin_intent(
            &fixture.group.id,
            &alice,
            seconds_from_now(-5),
        ))
        .await
        .unwrap();
        assert_failed_validation(
            db.insert_mls_text_commit(
                &text_commit(
                    &fixture,
                    1,
                    &bob,
                    vec![],
                    vec![alice.clone()],
                    Timestamp::now_utc(),
                ),
                &fixture.hash,
                0,
            )
            .await,
            "missing member_added entry",
        );
    });
}

#[tokio::test]
async fn text_add_rules_refuse_readd_members_unseated_and_pending() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);
        let bob = text_device(BOB, 1);
        let bob2 = text_device(BOB, 2);
        let carol = text_device(CAROL, 1);
        let commit = |fixture: &TextFixture,
                      epoch: i64,
                      by: &MlsMemberDevice,
                      added: &[&MlsMemberDevice],
                      removed: &[&MlsMemberDevice]| {
            text_commit(
                fixture,
                epoch,
                by,
                added.iter().map(|device| (*device).clone()).collect(),
                removed.iter().map(|device| (*device).clone()).collect(),
                Timestamp::now_utc(),
            )
        };

        let fixture = seed_text_group(
            &db,
            &text_seed(80, &alice, &[alice.clone(), bob.clone()], &[ALICE, BOB]),
        )
        .await;

        // Same-commit Remove + re-Add of one device
        assert_failed_validation(
            db.insert_mls_text_commit(
                &commit(&fixture, 1, &alice, &[&bob], &[&bob]),
                &fixture.hash,
                0,
            )
            .await,
            "remove and re-add in one commit",
        );
        // Adding a current member
        assert_failed_validation(
            db.insert_mls_text_commit(&commit(&fixture, 1, &alice, &[&bob], &[]), &fixture.hash, 0)
                .await,
            "add a current member",
        );
        // Adding an unseated user (no active seat row, off the list)
        assert_not_seated(
            db.insert_mls_text_commit(
                &commit(&fixture, 1, &alice, &[&carol], &[]),
                &fixture.hash,
                0,
            )
            .await,
            "add an unseated user",
        );
        assert_untouched(&db, &fixture, 0).await;

        // Adds are refused while a removal is pending; removals still run
        let mut seed = text_seed(
            81,
            &alice,
            &[alice.clone(), bob.clone(), carol.clone()],
            &[ALICE, BOB, CAROL],
        );
        seed.pending = vec![CAROL];
        let fixture = seed_text_group(&db, &seed).await;
        assert_resecuring(
            db.insert_mls_text_commit(
                &commit(&fixture, 1, &alice, &[&bob2], &[]),
                &fixture.hash,
                0,
            )
            .await,
            "pending_removal",
            "add while pending",
        );
        assert_won(
            db.insert_mls_text_commit(&commit(&fixture, 1, &bob, &[], &[&carol]), &fixture.hash, 0)
                .await,
            "remove the pending user",
        );
        assert_won(
            db.insert_mls_text_commit(
                &commit(&fixture, 2, &alice, &[&bob2], &[]),
                &fixture.hash,
                0,
            )
            .await,
            "add once nothing is pending",
        );
    });
}

#[test]
fn text_enforced_device_cap_is_the_min_with_zero_as_unlimited() {
    assert_eq!(mls_text_enforced_device_cap(0, 0), 0);
    assert_eq!(mls_text_enforced_device_cap(0, 5), 5);
    assert_eq!(mls_text_enforced_device_cap(5, 0), 5);
    assert_eq!(mls_text_enforced_device_cap(2, 3), 2);
    assert_eq!(mls_text_enforced_device_cap(3, 2), 2);
}

#[tokio::test]
async fn text_device_cap_is_enforced_inside_the_commit() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");

        let alice = text_device(ALICE, 1);
        let bob = |n: u8| text_device(BOB, n);
        let add_bob = |fixture: &TextFixture, epoch: i64, n: u8| {
            text_commit(
                fixture,
                epoch,
                &alice,
                vec![bob(n)],
                vec![],
                Timestamp::now_utc(),
            )
        };

        // Signed 2, entitlement unlimited: the signed cap binds
        let mut seed = text_seed(90, &alice, &[alice.clone(), bob(1)], &[ALICE, BOB]);
        seed.device_cap = 2;
        let fixture = seed_text_group(&db, &seed).await;
        assert_won(
            db.insert_mls_text_commit(&add_bob(&fixture, 1, 2), &fixture.hash, 0)
                .await,
            "second device within the signed cap",
        );
        assert_failed_validation(
            db.insert_mls_text_commit(&add_bob(&fixture, 2, 3), &fixture.hash, 0)
                .await,
            "third device over the signed cap",
        );

        // Signed 3, entitlement 1: the entitlement binds
        let mut seed = text_seed(91, &alice, &[alice.clone(), bob(1)], &[ALICE, BOB]);
        seed.device_cap = 3;
        let fixture = seed_text_group(&db, &seed).await;
        assert_failed_validation(
            db.insert_mls_text_commit(&add_bob(&fixture, 1, 2), &fixture.hash, 1)
                .await,
            "over the entitlement cap",
        );

        // Both unlimited: bounded only by the leaf cap
        let fixture = seed_text_group(
            &db,
            &text_seed(92, &alice, &[alice.clone(), bob(1)], &[ALICE, BOB]),
        )
        .await;
        assert_won(
            db.insert_mls_text_commit(&add_bob(&fixture, 1, 2), &fixture.hash, 0)
                .await,
            "unlimited 2",
        );
        assert_won(
            db.insert_mls_text_commit(&add_bob(&fixture, 2, 3), &fixture.hash, 0)
                .await,
            "unlimited 3",
        );

        // The 100-leaf ceiling counts every device
        let mut roster: Vec<MlsMemberDevice> = (1..=99u8).map(|n| text_device(ALICE, n)).collect();
        roster.push(bob(1));
        let fixture = seed_text_group(&db, &text_seed(93, &alice, &roster, &[ALICE, BOB])).await;
        assert_failed_validation(
            db.insert_mls_text_commit(&add_bob(&fixture, 1, 2), &fixture.hash, 0)
                .await,
            "101st leaf",
        );
    });
}

#[tokio::test]
async fn call_path_preserves_text_fields_and_never_touches_text_groups() {
    database_test!(|db| async move {
        db.migrate_database().await.expect("schema");
        // The byte-identical field check guards against a whole-document
        // `replace_one`, which only the Mongo driver could do; the Text
        // refusal and the no-repair checks below are meaningful on both
        reference_note(
            &db,
            "call_path_preserves_text_fields_and_never_touches_text_groups",
            "field preservation",
        );

        let alice = text_device(ALICE, 1);
        let bob = text_device(BOB, 1);

        // A Call group document carrying every new field
        let mut call = make_group(&group_id(100), &ulid(1100), &alice);
        call.generation = Some(7);
        call.seat_list_ad_sha256 = Some("ab".repeat(32));
        call.pending_removals = vec![MlsPendingRemoval {
            user_id: ulid(CAROL),
            created_at: seconds_from_now(-60),
        }];
        call.member_added = vec![MlsMemberAdded {
            user_id: alice.user_id.clone(),
            device_id: alice.device_id.clone(),
            epoch: 0,
            at: seconds_from_now(-60),
        }];
        db.create_mls_group(&call, None).await.unwrap();
        let before = db.fetch_mls_group(&call.id).await.unwrap();

        assert!(matches!(
            db.insert_mls_commit(&make_commit(
                &call.id,
                1,
                &alice,
                vec![bob.clone()],
                vec![],
                "add"
            ))
            .await
            .unwrap(),
            MlsCommitOutcome::Won
        ));

        // Only current_epoch and members changed; every other field is
        // byte-identical (no replace_one of a clone on either kind)
        let after = db.fetch_mls_group(&call.id).await.unwrap();
        assert_eq!(after.current_epoch, 1);
        assert!(after.has_member(&bob.user_id, &bob.device_id));
        let mut expected = before.clone();
        expected.current_epoch = after.current_epoch;
        expected.members = after.members.clone();
        assert_eq!(after, expected);

        // The Call path refuses a Text group outright
        let fixture = seed_text_group(
            &db,
            &text_seed(101, &alice, &[alice.clone()], &[ALICE, BOB]),
        )
        .await;
        let add_bob = text_commit(
            &fixture,
            1,
            &alice,
            vec![bob.clone()],
            vec![],
            Timestamp::now_utc(),
        );
        match db.insert_mls_commit(&add_bob).await {
            Err(error) => assert!(matches!(error.error_type, ErrorType::InvalidOperation)),
            Ok(outcome) => panic!("Call path accepted a Text commit: {outcome:?}"),
        }
        assert_untouched(&db, &fixture, 0).await;

        // A stored-but-unapplied row on a Text group is NEVER absorbed by
        // the Call repair loop (it would skip every Text rule)
        insert_raw_commit(&db, &add_bob).await;
        let group = db.fetch_mls_group(&fixture.group.id).await.unwrap();
        assert_eq!(group.current_epoch, 0);
        assert!(!group.has_member(&bob.user_id, &bob.device_id));
        assert_eq!(group, fixture.group);
    });
}
