use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{Channel, DmGuard, FieldsUser, PartialUser, RelationshipStatus, Supporter, User};
use crate::{ReferenceDb, Relationship};

/// Empty supporter record written when a user gains one for the first time
fn empty_supporter() -> Supporter {
    Supporter {
        lifetime_usd_cents: 0,
        monthly_until: None,
        payer_hmacs: vec![],
        show_badges: true,
    }
}

use super::AbstractUsers;

#[async_trait]
impl AbstractUsers for ReferenceDb {
    /// Insert a new user into the database
    async fn insert_user(&self, user: &User) -> Result<()> {
        let mut users = self.users.lock().await;
        if users.contains_key(&user.id) {
            Err(create_database_error!("insert", "user"))
        } else {
            users.insert(user.id.to_string(), user.clone());
            Ok(())
        }
    }

    /// Fetch a user from the database
    async fn fetch_user(&self, id: &str) -> Result<User> {
        let users = self.users.lock().await;
        users
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch a user from the database by their username
    async fn fetch_user_by_username(&self, username: &str, discriminator: &str) -> Result<User> {
        let users = self.users.lock().await;
        let lowercase = username.to_lowercase();
        users
            .values()
            .find(|user| {
                user.username.to_lowercase() == lowercase && user.discriminator == discriminator
            })
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch multiple users by their ids
    ///
    /// Mirrors the MongoDB `$in` query: unknown ids are skipped instead of
    /// failing the whole call, and each user is returned at most once.
    async fn fetch_users<'a>(&self, ids: &'a [String]) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        let mut seen = std::collections::HashSet::new();
        Ok(ids
            .iter()
            .filter(|id| seen.insert(id.as_str()))
            .filter_map(|id| users.get(id).cloned())
            .collect())
    }

    /// Fetch every user with at least one stored badge bit, positive bitfield only
    async fn fetch_badged_users(&self) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        // `> 0`, not `!= 0`: a negative bitfield sign-extends to 0xFFFFFFFF in
        // a caller's `as u32` bit test (every badge bit set), so it is excluded
        // here rather than at each call site. Matches the Mongo `$gt: 0`.
        let mut matches: Vec<User> = users
            .values()
            .filter(|user| user.badges.is_some_and(|badges| badges > 0))
            .cloned()
            .collect();

        // Newest first (ulid ids sort chronologically), matching the Mongo sort
        matches.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(matches)
    }

    /// Fetch all discriminators in use for a username
    async fn fetch_discriminators_in_use(&self, username: &str) -> Result<Vec<String>> {
        let users = self.users.lock().await;
        let lowercase = username.to_lowercase();
        Ok(users
            .values()
            .filter(|user| user.username.to_lowercase() == lowercase)
            .map(|user| &user.discriminator)
            .cloned()
            .collect())
    }

    /// Fetch ids of users that both users are friends with
    ///
    /// (Was `todo!()` — a latent panic on any request path reaching the
    /// friend/mutual eligibility fallback for strangers, e.g. the MLS
    /// KeyPackage claim route. Mirrors the Mongo query semantics.)
    async fn fetch_mutual_user_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let users = self.users.lock().await;

        let friends_of = |target: &str| -> std::collections::HashSet<String> {
            users
                .values()
                .filter(|user| {
                    user.relations.iter().flatten().any(|relation| {
                        relation.id == target
                            && matches!(relation.status, RelationshipStatus::Friend)
                    })
                })
                .map(|user| user.id.clone())
                .collect()
        };

        let of_a = friends_of(user_a);
        let of_b = friends_of(user_b);
        let mut mutual: Vec<String> = of_a.intersection(&of_b).cloned().collect();
        mutual.sort();
        Ok(mutual)
    }

    /// Fetch ids of channels that both users are in
    async fn fetch_mutual_channel_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let channels = self.channels.lock().await;
        let mut mutual: Vec<String> = channels
            .values()
            .filter_map(|channel| match channel {
                Channel::Group { id, recipients, .. }
                | Channel::DirectMessage { id, recipients, .. }
                    if recipients.iter().any(|r| r == user_a)
                        && recipients.iter().any(|r| r == user_b) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect();
        mutual.sort();
        Ok(mutual)
    }

    /// Fetch ids of servers that both users share
    async fn fetch_mutual_server_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let members = self.server_members.lock().await;
        let of_a: std::collections::HashSet<&str> = members
            .keys()
            .filter(|key| key.user == user_a)
            .map(|key| key.server.as_str())
            .collect();

        let mut mutual: Vec<String> = members
            .keys()
            .filter(|key| key.user == user_b && of_a.contains(key.server.as_str()))
            .map(|key| key.server.clone())
            .collect();
        mutual.sort();
        Ok(mutual)
    }

    /// Update a user by their id given some data
    async fn update_user(
        &self,
        id: &str,
        partial: &PartialUser,
        remove: Vec<FieldsUser>,
    ) -> Result<()> {
        let mut users = self.users.lock().await;
        if let Some(user) = users.get_mut(id) {
            for field in remove {
                #[allow(clippy::disallowed_methods)]
                user.remove_field(&field);
            }

            user.apply_options(partial.clone());
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Set relationship with another user
    ///
    /// This should use pull_relationship if relationship is None or User.
    async fn set_relationship(
        &self,
        user_id: &str,
        target_id: &str,
        relationship: &RelationshipStatus,
        note: Option<&str>,
    ) -> Result<()> {
        if let RelationshipStatus::User | RelationshipStatus::None = &relationship {
            self.pull_relationship(user_id, target_id).await
        } else {
            let mut users = self.users.lock().await;
            let user = users
                .get_mut(user_id)
                .ok_or_else(|| create_error!(NotFound))?;

            let relation = Relationship {
                id: target_id.to_string(),
                status: relationship.clone(),
                note: note.map(str::to_string),
            };

            if let Some(relations) = &mut user.relations {
                relations.retain(|relation| relation.id != target_id);
                relations.push(relation);
            } else {
                user.relations = Some(vec![relation]);
            }

            Ok(())
        }
    }

    /// Remove relationship with another user
    async fn pull_relationship(&self, user_id: &str, target_id: &str) -> Result<()> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;

        if let Some(relations) = &mut user.relations {
            relations.retain(|relation| relation.id != target_id);
        }

        Ok(())
    }

    /// Delete a user by their id
    async fn delete_user(&self, id: &str) -> Result<()> {
        let mut users = self.users.lock().await;
        if users.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Removes all relationships with the user from the list of users
    async fn clear_user_relationships(
        &self,
        target_id: &str,
        user_ids: Vec<String>,
    ) -> Result<()> {
        let mut users = self.users.lock().await;

        for user_id in user_ids {
            if let Some(user) = users.get_mut(&user_id) {
                if let Some(relations) = &mut user.relations {
                    relations.retain(|relation| relation.id != target_id);
                }
            }
        }

        Ok(())
    }

    /// Fetch the user whose supporter record lists this payer HMAC
    async fn fetch_user_by_payer_hmac(&self, hmac: &str) -> Result<Option<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .find(|u| {
                u.supporter
                    .as_ref()
                    .is_some_and(|s| s.payer_hmacs.iter().any(|h| h == hmac))
            })
            .cloned())
    }

    /// Fetch users with at least `n` qualified referrals
    async fn fetch_users_with_referral_count_at_least(&self, n: i32) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| u.referral_count.is_some_and(|count| count >= n))
            .cloned()
            .collect())
    }

    /// Fetch users whose `welcomed_at` falls in [from_ms, to_ms)
    async fn fetch_users_welcomed_between(&self, from_ms: i64, to_ms: i64) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| u.welcomed_at.is_some_and(|at| at >= from_ms && at < to_ms))
            .cloned()
            .collect())
    }

    /// Fetch users whose `supporter.monthly_until` falls in [from_ms, to_ms)
    async fn fetch_users_monthly_until_between(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| {
                u.supporter
                    .as_ref()
                    .and_then(|s| s.monthly_until)
                    .is_some_and(|until| until >= from_ms && until < to_ms)
            })
            .cloned()
            .collect())
    }

    /// Fetch users with a referral still awaiting attribution
    async fn fetch_users_with_referral_pending(&self) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| u.referral_pending == Some(true))
            .cloned()
            .collect())
    }

    /// Claim a payer hash for a user
    async fn claim_payer_hmac(&self, user_id: &str, hmac: &str) -> Result<Vec<String>> {
        let mut users = self.users.lock().await;
        if !users.contains_key(user_id) {
            return Err(create_error!(NotFound));
        }

        let mut lost: Vec<String> = Vec::new();
        for user in users.values_mut() {
            if user.id == user_id {
                continue;
            }

            if let Some(supporter) = &mut user.supporter {
                let before = supporter.payer_hmacs.len();
                supporter.payer_hmacs.retain(|h| h != hmac);
                if supporter.payer_hmacs.len() != before {
                    lost.push(user.id.clone());
                }
            }
        }
        lost.sort();

        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;
        let supporter = user.supporter.get_or_insert_with(empty_supporter);
        if !supporter.payer_hmacs.iter().any(|h| h == hmac) {
            supporter.payer_hmacs.push(hmac.to_string());
        }

        Ok(lost)
    }

    /// Set a user's supporter totals
    async fn set_supporter_totals(
        &self,
        user_id: &str,
        lifetime_usd_cents: i64,
        monthly_until: Option<i64>,
    ) -> Result<()> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;
        let supporter = user.supporter.get_or_insert_with(empty_supporter);
        supporter.lifetime_usd_cents = lifetime_usd_cents;
        supporter.monthly_until = monthly_until;
        Ok(())
    }

    /// Set whether a user's supporter badges are shown
    async fn set_supporter_show_badges(&self, user_id: &str, show: bool) -> Result<()> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;
        let supporter = user.supporter.get_or_insert_with(empty_supporter);
        supporter.show_badges = show;
        Ok(())
    }

    /// Set a user's DM guard
    async fn claim_dm_guard(
        &self,
        user_id: &str,
        guard: &DmGuard,
        rearm_before: Timestamp,
    ) -> Result<bool> {
        let mut users = self.users.lock().await;
        let Some(user) = users.get_mut(user_id) else {
            return Ok(false);
        };

        let claimable = match &user.dm_guard {
            None => true,
            Some(existing) => existing
                .cleared_at
                .is_some_and(|cleared_at| cleared_at < rearm_before),
        };

        if claimable {
            user.dm_guard = Some(guard.clone());
        }

        Ok(claimable)
    }

    /// Lift the DM pause of the guard filed under `report_id`
    async fn clear_dm_guard_pause(
        &self,
        user_id: &str,
        report_id: &str,
        at: Timestamp,
    ) -> Result<bool> {
        let mut users = self.users.lock().await;
        let guard = users
            .get_mut(user_id)
            .and_then(|user| user.dm_guard.as_mut())
            .filter(|guard| guard.report_id == report_id);

        if let Some(guard) = guard {
            guard.paused = false;
            guard.cleared_at = Some(at);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remove the DM guard filed under `report_id`
    async fn release_dm_guard(&self, user_id: &str, report_id: &str) -> Result<bool> {
        let mut users = self.users.lock().await;
        let Some(user) = users.get_mut(user_id) else {
            return Ok(false);
        };

        if user
            .dm_guard
            .as_ref()
            .is_some_and(|guard| guard.report_id == report_id)
        {
            user.dm_guard = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Fetch unguarded, unflagged human users created since `cutoff_id`
    async fn fetch_users_created_since(&self, cutoff_id: &str) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| {
                u.id.as_str() >= cutoff_id
                    && u.bot.is_none()
                    && !u.privileged
                    && u.flags.unwrap_or(0) == 0
                    && u.dm_guard.is_none()
            })
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};

    use crate::{BotInformation, DmGuard, PartialUser, User};

    fn ids(users: &[User]) -> Vec<&str> {
        users.iter().map(|user| user.id.as_str()).collect()
    }

    fn guard(report_id: &str) -> DmGuard {
        DmGuard {
            report_id: report_id.to_string(),
            flagged_at: Timestamp::now_utc(),
            paused: true,
            cleared_at: None,
            recipients: 5,
            fingerprint: "fingerprint".to_string(),
        }
    }

    fn hours_from_now(hours: i64) -> Timestamp {
        Timestamp::now_utc()
            .checked_add(Duration::hours(hours))
            .unwrap()
    }

    /// Both drivers: only one claim wins, and a cleared guard re-arms only
    /// once its clear is older than the cutoff
    #[tokio::test]
    async fn dm_guard_claim_is_exclusive_and_rearms_after_clear() {
        database_test!(|db| async move {
            let user = User::create(&db, "Spammer".to_string(), None, None)
                .await
                .unwrap();

            assert!(db
                .claim_dm_guard(&user.id, &guard("r1"), Timestamp::now_utc())
                .await
                .unwrap());
            // A live guard is never replaced, whatever the cutoff
            assert!(!db
                .claim_dm_guard(&user.id, &guard("r2"), hours_from_now(1))
                .await
                .unwrap());

            let fetched = db.fetch_user(&user.id).await.unwrap();
            assert_eq!(fetched.dm_guard.as_ref().unwrap().report_id, "r1");
            assert!(fetched.is_dm_paused());

            assert!(db
                .clear_dm_guard_pause(&user.id, "r1", Timestamp::now_utc())
                .await
                .unwrap());
            let fetched = db.fetch_user(&user.id).await.unwrap();
            assert!(!fetched.is_dm_paused());
            let cleared = fetched.dm_guard.unwrap();
            assert_eq!(cleared.report_id, "r1");
            assert!(!cleared.paused);
            assert!(cleared.cleared_at.is_some());

            // Cleared after the cutoff: still shielded from a re-flag
            assert!(!db
                .claim_dm_guard(&user.id, &guard("r2"), hours_from_now(-1))
                .await
                .unwrap());
            assert_eq!(
                db.fetch_user(&user.id)
                    .await
                    .unwrap()
                    .dm_guard
                    .unwrap()
                    .report_id,
                "r1"
            );

            // Cleared before the cutoff: re-arms
            assert!(db
                .claim_dm_guard(&user.id, &guard("r3"), hours_from_now(1))
                .await
                .unwrap());
            let fetched = db.fetch_user(&user.id).await.unwrap();
            assert_eq!(fetched.dm_guard.as_ref().unwrap().report_id, "r3");
            assert!(fetched.is_dm_paused());

            // An unknown user claims nothing
            assert!(!db
                .claim_dm_guard(
                    &ulid::Ulid::new().to_string(),
                    &guard("r4"),
                    hours_from_now(1)
                )
                .await
                .unwrap());
        });
    }

    /// Both drivers: clear and release act only on the matching report id
    #[tokio::test]
    async fn dm_guard_clear_and_release_need_matching_report() {
        database_test!(|db| async move {
            let user = User::create(&db, "Spammer".to_string(), None, None)
                .await
                .unwrap();

            // No guard: nothing to clear or release
            assert!(!db
                .clear_dm_guard_pause(&user.id, "r1", Timestamp::now_utc())
                .await
                .unwrap());
            assert!(!db.release_dm_guard(&user.id, "r1").await.unwrap());
            assert!(db.fetch_user(&user.id).await.unwrap().dm_guard.is_none());

            assert!(db
                .claim_dm_guard(&user.id, &guard("r1"), Timestamp::now_utc())
                .await
                .unwrap());
            let before = db.fetch_user(&user.id).await.unwrap();
            assert!(before.is_dm_paused());

            assert!(!db
                .clear_dm_guard_pause(&user.id, "other", Timestamp::now_utc())
                .await
                .unwrap());
            assert!(!db.release_dm_guard(&user.id, "other").await.unwrap());
            assert_eq!(db.fetch_user(&user.id).await.unwrap(), before);

            assert!(db.release_dm_guard(&user.id, "r1").await.unwrap());
            let released = db.fetch_user(&user.id).await.unwrap();
            assert!(released.dm_guard.is_none());
            assert!(!released.is_dm_paused());

            // Released: the next detection can claim again
            assert!(db
                .claim_dm_guard(&user.id, &guard("r2"), Timestamp::now_utc())
                .await
                .unwrap());
        });
    }

    /// Both drivers: re-arming reads `cleared_at` however it was stored
    /// (a typed insert writes Int64 milliseconds, `update_user` an ISO string)
    #[tokio::test]
    async fn dm_guard_rearm_matches_any_cleared_at_encoding() {
        database_test!(|db| async move {
            let cleared = DmGuard {
                paused: false,
                cleared_at: Some(hours_from_now(-2)),
                ..guard("old")
            };

            let inserted = User::create(
                &db,
                "Inserted".to_string(),
                None,
                PartialUser {
                    dm_guard: Some(cleared.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

            let updated = User::create(&db, "Updated".to_string(), None, None)
                .await
                .unwrap();
            db.update_user(
                &updated.id,
                &PartialUser {
                    dm_guard: Some(cleared.clone()),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();

            for id in [&inserted.id, &updated.id] {
                assert!(!db
                    .claim_dm_guard(id, &guard("new"), hours_from_now(-3))
                    .await
                    .unwrap());
                assert!(db
                    .claim_dm_guard(id, &guard("new"), hours_from_now(-1))
                    .await
                    .unwrap());
                assert!(db.fetch_user(id).await.unwrap().is_dm_paused());
            }
        });
    }

    /// Both drivers: only unguarded, unflagged, non-bot, non-privileged users
    /// created at or after the cutoff are returned
    #[tokio::test]
    async fn fetch_users_created_since_filters_candidates() {
        database_test!(|db| async move {
            let now_ms = ulid::Ulid::new().timestamp_ms();
            let cutoff = ulid::Ulid::from_parts(now_ms - 60_000, 0).to_string();

            let old = User::create(
                &db,
                "Old".to_string(),
                ulid::Ulid::from_parts(now_ms - 3_600_000, 1).to_string(),
                None,
            )
            .await
            .unwrap();
            let boundary = User::create(&db, "Boundary".to_string(), cutoff.clone(), None)
                .await
                .unwrap();
            let fresh = User::create(&db, "Fresh".to_string(), None, None)
                .await
                .unwrap();
            let zero_flags = User::create(
                &db,
                "ZeroFlags".to_string(),
                None,
                PartialUser {
                    flags: Some(0),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let bot = User::create(
                &db,
                "Robot".to_string(),
                None,
                PartialUser {
                    bot: Some(BotInformation {
                        owner: fresh.id.clone(),
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let privileged = User::create(
                &db,
                "Staff".to_string(),
                None,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let flagged = User::create(
                &db,
                "Flagged".to_string(),
                None,
                PartialUser {
                    flags: Some(1),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let guarded = User::create(&db, "Guarded".to_string(), None, None)
                .await
                .unwrap();
            assert!(db
                .claim_dm_guard(&guarded.id, &guard("r1"), Timestamp::now_utc())
                .await
                .unwrap());

            let found = db.fetch_users_created_since(&cutoff).await.unwrap();
            let mut found = ids(&found);
            found.sort();

            let mut expected = vec![
                boundary.id.as_str(),
                fresh.id.as_str(),
                zero_flags.id.as_str(),
            ];
            expected.sort();
            assert_eq!(found, expected);

            for excluded in [&old, &bot, &privileged, &flagged, &guarded] {
                assert!(!found.contains(&excluded.id.as_str()));
            }
        });
    }

    /// Both drivers: an unknown id is skipped, never an error (Mongo `$in`)
    #[tokio::test]
    async fn fetch_users_skips_unknown_ids() {
        database_test!(|db| async move {
            let known = User::create(&db, "Known".to_string(), None, None)
                .await
                .unwrap();
            let unknown = ulid::Ulid::new().to_string();

            let users = db
                .fetch_users(&[known.id.clone(), unknown.clone()])
                .await
                .unwrap();
            assert_eq!(ids(&users), vec![known.id.as_str()]);

            // A repeated id comes back once, as with `$in`
            let users = db
                .fetch_users(&[unknown.clone(), known.id.clone(), known.id.clone()])
                .await
                .unwrap();
            assert_eq!(ids(&users), vec![known.id.as_str()]);

            assert!(db.fetch_users(&[unknown]).await.unwrap().is_empty());
            assert!(db.fetch_users(&[]).await.unwrap().is_empty());
        });
    }
}
