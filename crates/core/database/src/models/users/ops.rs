use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{DmGuard, FieldsUser, PartialUser, RelationshipStatus, User};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// The only stored fields `fetch_badged_users` returns, by their stored
/// (serde) names; every other field comes back as its default.
///
/// The anonymous streamer directory is the caller, and it reads nothing
/// else: the card fields, plus what it filters on. Without this a cache miss
/// pulled every badged user's full document, relations and all, into delta.
///
/// The four non-optional fields of `User` (`_id`, `username`,
/// `discriminator`, `last_acknowledged_policy_change`) must stay listed or
/// the projected document no longer deserializes.
pub(crate) const BADGED_USER_FIELDS: &[&str] = &[
    "_id",
    "username",
    "discriminator",
    "last_acknowledged_policy_change",
    "display_name",
    "avatar",
    "badges",
    "flags",
    "suspended_until",
    "bot",
    "profile_visibility",
    "connections",
    // Filter-only: the directory hides users whose DMs the anti-spam guard
    // has paused. Dropping this would silently publish them again.
    "dm_guard",
];

#[async_trait]
pub trait AbstractUsers: Sync + Send {
    /// Insert a new user into the database
    async fn insert_user(&self, user: &User) -> Result<()>;

    /// Fetch a user from the database
    async fn fetch_user(&self, id: &str) -> Result<User>;

    /// Fetch a user from the database by their username
    async fn fetch_user_by_username(&self, username: &str, discriminator: &str) -> Result<User>;

    /// Fetch multiple users by their ids
    async fn fetch_users<'a>(&self, ids: &'a [String]) -> Result<Vec<User>>;

    /// Fetch every user with at least one *stored* badge bit, positive
    /// bitfield only.
    ///
    /// Dynamic badges (early adopter) are computed per-user in
    /// `User::get_badges` and are not visible to this query.
    ///
    /// `badges` is sparse: users with no badges have no `badges` field at all, and some
    /// carry an explicit 0. Callers bitmask-test the result themselves, because Mongo's
    /// `$bits*` operators cannot use an index.
    ///
    /// A NEGATIVE `badges` value is never returned. It is reachable only by a
    /// direct database write, but it would sign-extend in a caller's `as u32`
    /// bit test (-1 becomes 0xFFFFFFFF, every bit set), so both drivers
    /// exclude it at the source rather than trusting each call site.
    ///
    /// Newest first (ulid ids sort chronologically), so a caller that caps the
    /// list sees the same page under either driver.
    ///
    /// The users are PROJECTED to `BADGED_USER_FIELDS`: relations, status,
    /// profile, supporter data and every other unlisted field come back empty.
    /// Never write one of these users back or treat it as the whole record.
    ///
    /// NOTE (Mongo): `badges` is `Option<i32>` with `skip_serializing_if =
    /// Option::is_none`, so "no badges" is an ABSENT field — filters must
    /// exclude missing/null as well as 0, never a bare `{"badges": {"$ne": 0}}`.
    async fn fetch_badged_users(&self) -> Result<Vec<User>>;

    /// Fetch all discriminators in use for a username
    async fn fetch_discriminators_in_use(&self, username: &str) -> Result<Vec<String>>;

    /// Fetch ids of users that both users are friends with
    async fn fetch_mutual_user_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>>;

    /// Fetch ids of channels that both users are in
    async fn fetch_mutual_channel_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>>;

    /// Fetch ids of servers that both users share
    async fn fetch_mutual_server_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>>;

    /// Update a user by their id given some data
    async fn update_user(
        &self,
        id: &str,
        user: &PartialUser,
        remove: Vec<FieldsUser>,
    ) -> Result<()>;

    /// Set relationship with another user
    ///
    /// This should use pull_relationship if relationship is None.
    async fn set_relationship(
        &self,
        user_id: &str,
        target_id: &str,
        relationship: &RelationshipStatus,
        note: Option<&str>,
    ) -> Result<()>;

    /// Remove relationship with another user
    async fn pull_relationship(&self, user_id: &str, target_id: &str) -> Result<()>;

    /// Delete a user by their id
    async fn delete_user(&self, id: &str) -> Result<()>;

    /// Removes all relationships with the user from the list of users
    async fn clear_user_relationships(&self, target_id: &str, user_ids: Vec<String>) -> Result<()>;

    /// Fetch the user whose supporter payer hashes contain the given hash
    async fn fetch_user_by_payer_hmac(&self, hmac: &str) -> Result<Option<User>>;

    /// Fetch all users with a referral count of at least `n`
    async fn fetch_users_with_referral_count_at_least(&self, n: i32) -> Result<Vec<User>>;

    /// Fetch all users welcomed between the given timestamps (in milliseconds)
    ///
    /// The window applies to the raw `welcomed_at` value; the caller is
    /// responsible for offsetting it by the trial length.
    async fn fetch_users_welcomed_between(&self, from_ms: i64, to_ms: i64) -> Result<Vec<User>>;

    /// Fetch all users whose monthly supporter status ends between the given
    /// timestamps (in milliseconds)
    async fn fetch_users_monthly_until_between(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<User>>;

    /// Fetch all users with a pending referral
    async fn fetch_users_with_referral_pending(&self) -> Result<Vec<User>>;

    /// Claim a payer hash for a user
    ///
    /// Ensures `supporter` exists (lifetime 0, no hashes, badges shown),
    /// removes the hash from every other user's `supporter.payer_hmacs` and
    /// adds it to this user's. Returns the ids of the users that lost it.
    async fn claim_payer_hmac(&self, user_id: &str, hmac: &str) -> Result<Vec<String>>;

    /// Set a user's supporter totals
    ///
    /// Ensures `supporter` exists, sets `lifetime_usd_cents` and sets or
    /// unsets `monthly_until`.
    async fn set_supporter_totals(
        &self,
        user_id: &str,
        lifetime_usd_cents: i64,
        monthly_until: Option<i64>,
    ) -> Result<()>;

    /// Set whether a user's supporter badges are shown
    ///
    /// Ensures `supporter` exists, then sets `show_badges`.
    async fn set_supporter_show_badges(&self, user_id: &str, show: bool) -> Result<()>;

    /// Set a user's DM guard
    ///
    /// Atomic: only succeeds if the user has no guard, or their guard was
    /// cleared before `rearm_before`. Returns whether the guard was set.
    async fn claim_dm_guard(
        &self,
        user_id: &str,
        guard: &DmGuard,
        rearm_before: Timestamp,
    ) -> Result<bool>;

    /// Lift the DM pause of the guard filed under `report_id`
    ///
    /// Returns whether a guard with that report id matched.
    async fn clear_dm_guard_pause(
        &self,
        user_id: &str,
        report_id: &str,
        at: Timestamp,
    ) -> Result<bool>;

    /// Remove the DM guard filed under `report_id`
    ///
    /// Returns whether a guard with that report id matched.
    async fn release_dm_guard(&self, user_id: &str, report_id: &str) -> Result<bool>;

    /// Fetch users with an id of at least `cutoff_id` that are not bots, not
    /// privileged, carry no flags and have no DM guard
    async fn fetch_users_created_since(&self, cutoff_id: &str) -> Result<Vec<User>>;
}

#[cfg(test)]
mod tests {
    // NOTE: `AbstractUsers` is deliberately NOT imported -- `Database` derefs
    // to `dyn AbstractDatabase`, which has this trait as a supertrait, so the
    // import would be dead code (and a warning).
    use crate::User;
    use revolt_models::v0::UserBadges;
    use ulid::Ulid;

    fn user(id: &str, badges: Option<i32>) -> User {
        // Fixture ids must be decodable ULIDs -- the Crockford alphabet
        // excludes I, L, O and U.
        //
        // Id-derived logic fails CLOSED on an unparseable id rather than
        // announcing itself: `User::get_badges` gates the early-adopter bit on
        // `Ulid::from_string(&self.id).is_ok_and(...)` (`model.rs:1005`), so a
        // malformed fixture id just silently skips that branch and the user
        // quietly never earns the badge. A test built on such an id would pass
        // for the wrong reason. Assert here so the fixture is rejected loudly
        // instead.
        assert!(
            Ulid::from_string(id).is_ok(),
            "fixture id is not a decodable ULID: {id}"
        );

        User {
            id: id.to_string(),
            username: format!("u{id}"),
            discriminator: "0001".to_string(),
            badges,
            ..Default::default()
        }
    }

    /// Regression guard for the sparse-field trap: `badges` is skip-serialized
    /// when `None`, so an unbadged user has NO `badges` field on Mongo and a
    /// naive `{"badges": {"$ne": 0}}` returns them. The reference driver
    /// iterates a `HashMap` and passes either way — run under
    /// `TEST_DB=MONGODB` for this assertion to mean anything.
    #[tokio::test]
    async fn fetch_badged_users_skips_zero_and_absent_badges() {
        database_test!(|db| async move {
            // carries the FoundingStreamer bit
            db.insert_user(&user(
                "01TEST00000000000000BADGED",
                Some(UserBadges::FoundingStreamer as i32),
            ))
            .await
            .unwrap();
            // carries some OTHER badge: the driver must NOT filter by bit
            db.insert_user(&user("01TEST00000000000000BADGE1", Some(1)))
                .await
                .unwrap();
            // stored field, but no badges set
            db.insert_user(&user("01TEST0000000000000000ZER0", Some(0)))
                .await
                .unwrap();
            // no `badges` field on the stored document at all
            db.insert_user(&user("01TEST00000000000000NBADGE", None))
                .await
                .unwrap();
            // negative bitfield: only reachable by a direct DB write, but the
            // route's `as u32` bit test sign-extends -1 to 0xFFFFFFFF, which
            // has EVERY bit set -- including FoundingStreamer. Must not be
            // returned; excluding it at the source is the fail-closed choice.
            db.insert_user(&user("01TEST00000000000000NEGATV", Some(-1)))
                .await
                .unwrap();

            let mut ids: Vec<String> = db
                .fetch_badged_users()
                .await
                .unwrap()
                .into_iter()
                .map(|user| user.id)
                .collect();
            ids.sort();

            // Sort both sides: this assertion is about set membership, the
            // ordering contract has its own test below.
            let mut expected = vec![
                "01TEST00000000000000BADGED".to_string(),
                "01TEST00000000000000BADGE1".to_string(),
            ];
            expected.sort();

            assert_eq!(
                ids, expected,
                "expected exactly the two users carrying a non-zero badge bitfield"
            );
        });
    }

    /// Both drivers promise newest-first, so a caller that caps the list keeps
    /// the same page whichever driver is behind it.
    #[tokio::test]
    async fn fetch_badged_users_orders_newest_first() {
        database_test!(|db| async move {
            db.insert_user(&user(
                "01TEST00000000000000BADGED",
                Some(UserBadges::FoundingStreamer as i32),
            ))
            .await
            .unwrap();
            db.insert_user(&user(
                "01TEST00000000000000BADGE1",
                Some(UserBadges::FoundingStreamer as i32),
            ))
            .await
            .unwrap();

            let ids: Vec<String> = db
                .fetch_badged_users()
                .await
                .unwrap()
                .into_iter()
                .map(|user| user.id)
                .collect();

            // "01TEST00000000000000BADGED" > "01TEST00000000000000BADGE1" lexicographically
            assert_eq!(
                ids,
                vec![
                    "01TEST00000000000000BADGED".to_string(),
                    "01TEST00000000000000BADGE1".to_string()
                ]
            );
        });
    }

    /// Only `BADGED_USER_FIELDS` come back: the fields the directory reads
    /// survive, and private ones it never needs are not loaded at all.
    #[tokio::test]
    async fn fetch_badged_users_projects_to_the_listed_fields() {
        use crate::{
            ConnectionPlatform, DmGuard, ProfileVisibility, Relationship, RelationshipStatus,
            UserConnection, UserProfile, UserStatus,
        };
        use iso8601_timestamp::Timestamp;

        database_test!(|db| async move {
            let mut full = user(
                "01TEST00000000000000BADGED",
                Some(UserBadges::FoundingStreamer as i32),
            );
            // Kept
            full.display_name = Some("Streamer".to_string());
            full.flags = Some(0);
            full.profile_visibility = Some(ProfileVisibility::Everyone);
            full.connections = Some(vec![UserConnection {
                platform: ConnectionPlatform::Twitch,
                handle: "streamer".to_string(),
                display_name: "Streamer".to_string(),
                live: true,
                live_title: Some("live now".to_string()),
                live_since: None,
            }]);
            full.dm_guard = Some(DmGuard {
                report_id: "01TEST00000000000000REPRT1".to_string(),
                flagged_at: Timestamp::now_utc(),
                paused: true,
                cleared_at: None,
                recipients: 5,
                fingerprint: "fp".to_string(),
            });
            // Dropped
            full.relations = Some(vec![Relationship {
                id: "01TEST00000000000000FR1END".to_string(),
                status: RelationshipStatus::Friend,
                note: Some("private note".to_string()),
            }]);
            full.status = Some(UserStatus {
                text: Some("status".to_string()),
                ..Default::default()
            });
            full.profile = Some(UserProfile {
                content: Some("bio".to_string()),
                ..Default::default()
            });
            full.pronouns = Some("they/them".to_string());
            full.privileged = true;
            full.referral_count = Some(3);
            db.insert_user(&full).await.unwrap();

            let fetched = db.fetch_badged_users().await.unwrap();
            assert_eq!(fetched.len(), 1);
            let fetched = &fetched[0];

            assert_eq!(fetched.id, full.id);
            assert_eq!(fetched.username, full.username);
            assert_eq!(fetched.discriminator, full.discriminator);
            assert_eq!(fetched.display_name, full.display_name);
            assert_eq!(fetched.badges, full.badges);
            assert_eq!(fetched.flags, full.flags);
            assert_eq!(fetched.profile_visibility, full.profile_visibility);
            assert_eq!(fetched.connections, full.connections);
            // Timestamps left out: their round trip is not what this pins
            let guard = |user: &User| {
                user.dm_guard
                    .as_ref()
                    .map(|g| (g.report_id.clone(), g.paused, g.cleared_at.is_some()))
            };
            assert_eq!(
                guard(fetched),
                guard(&full),
                "dm_guard was projected away; the directory's pause filter would never fire"
            );

            assert_eq!(fetched.relations, None, "relations were loaded");
            assert_eq!(fetched.status, None, "status was loaded");
            assert_eq!(fetched.profile, None, "profile was loaded");
            assert_eq!(fetched.pronouns, None, "pronouns were loaded");
            assert!(!fetched.privileged, "privileged was loaded");
            assert_eq!(fetched.referral_count, None, "referral_count was loaded");
        });
    }
}
