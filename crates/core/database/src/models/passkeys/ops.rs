use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::Passkey;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractPasskeys: Sync + Send {
    /// Insert a new passkey.
    ///
    /// A `credential_id` that is already stored (on any account) is an
    /// error, as is a duplicate id.
    async fn insert_passkey(&self, passkey: &Passkey) -> Result<()>;

    /// Fetch one of a user's passkeys by id.
    ///
    /// NotFound when the id does not exist or belongs to another user.
    async fn fetch_passkey(&self, user_id: &str, id: &str) -> Result<Passkey>;

    /// Fetch every passkey of a user, oldest first (by `created_at`, then id)
    async fn fetch_passkeys(&self, user_id: &str) -> Result<Vec<Passkey>>;

    /// Fetch a passkey by its WebAuthn credential id, whoever owns it
    /// (discoverable login resolves the account this way)
    async fn fetch_passkey_by_credential_id(&self, credential_id: &str)
        -> Result<Option<Passkey>>;

    /// Count a user's passkeys
    async fn count_passkeys(&self, user_id: &str) -> Result<u64>;

    /// Store the verifier state after a successful assertion.
    ///
    /// Compare-and-swap on the stored credential text: the write happens only
    /// while the row still holds `expected_credential`, so of two concurrent
    /// assertions that both read one signature counter, only one advances
    /// it. Ok(true) if this call wrote; Ok(false) if the row is missing or
    /// its credential has changed since it was read.
    ///
    /// When `credential` equals `expected_credential` (a synced passkey whose
    /// counter stays 0) the call still matches and records `last_used_at`.
    async fn update_passkey_after_use(
        &self,
        id: &str,
        expected_credential: &str,
        credential: &str,
        last_used_at: Timestamp,
    ) -> Result<bool>;

    /// Rename one of a user's passkeys.
    ///
    /// NotFound when the id does not exist or belongs to another user.
    async fn rename_passkey(&self, user_id: &str, id: &str, name: &str) -> Result<()>;

    /// Delete one of a user's passkeys.
    ///
    /// NotFound when the id does not exist or belongs to another user.
    async fn delete_passkey(&self, user_id: &str, id: &str) -> Result<()>;

    /// Account-deletion cascade: delete every passkey of a user (no-op if
    /// there are none)
    async fn delete_passkeys_for_user(&self, user_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_result::ErrorType;

    use crate::Passkey;

    /// A whole-second timestamp, so it round-trips through Mongo's
    /// millisecond encoding unchanged
    fn at(seconds: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(Duration::seconds(1_800_000_000 + seconds))
            .unwrap()
    }

    /// A 26-character ULID-shaped id that sorts by `n`
    fn id(n: u32) -> String {
        format!("01PK00000000000000000{n:05}")
    }

    /// Passkey `n` of `user`, registered `n` seconds in, with its own
    /// credential id
    fn passkey(n: u32, user: &str) -> Passkey {
        Passkey {
            id: id(n),
            user_id: user.to_string(),
            credential_id: format!("credential-{n}"),
            user_handle: format!("handle-of-{user}"),
            credential: format!("state-{n}-counter-0"),
            name: format!("Passkey {n}"),
            created_at: at(n as i64),
            last_used_at: None,
        }
    }

    fn ids(rows: &[Passkey]) -> Vec<String> {
        rows.iter().map(|row| row.id.clone()).collect()
    }

    fn is_not_found<T>(result: revolt_result::Result<T>) -> bool {
        matches!(result, Err(error) if matches!(error.error_type, ErrorType::NotFound))
    }

    #[tokio::test]
    async fn insert_and_fetch_round_trip() {
        database_test!(|db| async move {
            let mut used = passkey(1, "user_a");
            used.last_used_at = Some(at(500));
            let unused = passkey(2, "user_a");

            db.insert_passkey(&used).await.unwrap();
            db.insert_passkey(&unused).await.unwrap();

            assert_eq!(db.fetch_passkey("user_a", &id(1)).await.unwrap(), used);
            assert_eq!(db.fetch_passkey("user_a", &id(2)).await.unwrap(), unused);
            assert_eq!(
                db.fetch_passkey_by_credential_id("credential-2")
                    .await
                    .unwrap(),
                Some(unused)
            );
            assert_eq!(
                db.fetch_passkey_by_credential_id("credential-unknown")
                    .await
                    .unwrap(),
                None
            );
            assert!(is_not_found(db.fetch_passkey("user_a", &id(9)).await));

            assert_eq!(db.count_passkeys("user_a").await.unwrap(), 2);
            assert_eq!(db.count_passkeys("user_b").await.unwrap(), 0);
            assert!(db.fetch_passkeys("user_b").await.unwrap().is_empty());
        });
    }

    #[tokio::test]
    async fn a_duplicate_credential_id_is_refused() {
        database_test!(|db| async move {
            // On MongoDB the refusal IS the unique index, so the schema must
            // exist (database_test! drops it; a Reference migrate is a no-op)
            db.migrate_database().await.expect("schema");

            let first = passkey(1, "user_a");
            db.insert_passkey(&first).await.unwrap();

            // Another row, another account, the same credential id
            let mut clash = passkey(2, "user_b");
            clash.credential_id = first.credential_id.clone();
            assert!(db.insert_passkey(&clash).await.is_err());

            // The same account is refused as well
            let mut same_account = passkey(3, "user_a");
            same_account.credential_id = first.credential_id.clone();
            assert!(db.insert_passkey(&same_account).await.is_err());

            // The first row stands and nothing else was stored
            assert_eq!(
                db.fetch_passkey_by_credential_id(&first.credential_id)
                    .await
                    .unwrap(),
                Some(first)
            );
            assert_eq!(db.count_passkeys("user_a").await.unwrap(), 1);
            assert_eq!(db.count_passkeys("user_b").await.unwrap(), 0);

            // The control: a different credential id is accepted
            db.insert_passkey(&passkey(4, "user_b")).await.unwrap();
            assert_eq!(db.count_passkeys("user_b").await.unwrap(), 1);
        });
    }

    #[tokio::test]
    async fn a_duplicate_id_is_refused() {
        database_test!(|db| async move {
            let first = passkey(1, "user_a");
            db.insert_passkey(&first).await.unwrap();

            let mut clash = passkey(1, "user_b");
            clash.credential_id = "credential-other".to_string();
            assert!(db.insert_passkey(&clash).await.is_err());

            assert_eq!(db.fetch_passkey("user_a", &id(1)).await.unwrap(), first);
            assert_eq!(db.count_passkeys("user_b").await.unwrap(), 0);
        });
    }

    #[tokio::test]
    async fn another_users_passkey_cannot_be_fetched_renamed_or_deleted() {
        database_test!(|db| async move {
            let owned = passkey(1, "user_a");
            db.insert_passkey(&owned).await.unwrap();

            assert!(is_not_found(db.fetch_passkey("user_b", &id(1)).await));
            assert!(is_not_found(
                db.rename_passkey("user_b", &id(1), "Stolen").await
            ));
            assert!(is_not_found(db.delete_passkey("user_b", &id(1)).await));

            // Nothing moved
            assert_eq!(db.fetch_passkey("user_a", &id(1)).await.unwrap(), owned);
            assert_eq!(db.count_passkeys("user_a").await.unwrap(), 1);

            // The control: the owner can do all three
            db.rename_passkey("user_a", &id(1), "Renamed").await.unwrap();
            let renamed = db.fetch_passkey("user_a", &id(1)).await.unwrap();
            assert_eq!(renamed.name, "Renamed");
            assert_eq!(
                Passkey {
                    name: owned.name.clone(),
                    ..renamed
                },
                owned,
                "a rename changes the name only"
            );

            db.delete_passkey("user_a", &id(1)).await.unwrap();
            assert!(is_not_found(db.fetch_passkey("user_a", &id(1)).await));
            assert_eq!(db.count_passkeys("user_a").await.unwrap(), 0);

            // Gone means NotFound for the owner too
            assert!(is_not_found(db.delete_passkey("user_a", &id(1)).await));
            assert!(is_not_found(
                db.rename_passkey("user_a", &id(1), "Again").await
            ));
        });
    }

    #[tokio::test]
    async fn update_after_use_is_a_compare_and_swap() {
        database_test!(|db| async move {
            let stored = passkey(1, "user_a");
            db.insert_passkey(&stored).await.unwrap();

            // Two assertions both read "state-1-counter-0". The first wins.
            assert!(db
                .update_passkey_after_use(
                    &id(1),
                    "state-1-counter-0",
                    "state-1-counter-5",
                    at(100),
                )
                .await
                .unwrap());

            // The second still expects what it read, and loses
            assert!(!db
                .update_passkey_after_use(
                    &id(1),
                    "state-1-counter-0",
                    "state-1-counter-6",
                    at(200),
                )
                .await
                .unwrap());

            let after = db.fetch_passkey("user_a", &id(1)).await.unwrap();
            assert_eq!(after.credential, "state-1-counter-5");
            assert_eq!(after.last_used_at, Some(at(100)));
            assert_eq!(
                Passkey {
                    credential: stored.credential.clone(),
                    last_used_at: None,
                    ..after
                },
                stored,
                "only the credential and last_used_at change"
            );

            // A synced passkey keeps its counter at 0: unchanged state still
            // matches and records the use
            assert!(db
                .update_passkey_after_use(
                    &id(1),
                    "state-1-counter-5",
                    "state-1-counter-5",
                    at(300),
                )
                .await
                .unwrap());
            let after = db.fetch_passkey("user_a", &id(1)).await.unwrap();
            assert_eq!(after.credential, "state-1-counter-5");
            assert_eq!(after.last_used_at, Some(at(300)));

            // A missing row writes nothing and creates nothing
            assert!(!db
                .update_passkey_after_use(
                    &id(9),
                    "state-1-counter-5",
                    "state-9",
                    at(400),
                )
                .await
                .unwrap());
            assert_eq!(db.count_passkeys("user_a").await.unwrap(), 1);
        });
    }

    #[tokio::test]
    async fn delete_for_user_removes_only_that_users_passkeys() {
        database_test!(|db| async move {
            for (n, user) in [(1, "user_a"), (2, "user_b"), (3, "user_a"), (4, "user_c")] {
                db.insert_passkey(&passkey(n, user)).await.unwrap();
            }

            db.delete_passkeys_for_user("user_a").await.unwrap();

            assert_eq!(db.count_passkeys("user_a").await.unwrap(), 0);
            assert!(db.fetch_passkeys("user_a").await.unwrap().is_empty());
            assert!(db
                .fetch_passkey_by_credential_id("credential-1")
                .await
                .unwrap()
                .is_none());

            assert_eq!(ids(&db.fetch_passkeys("user_b").await.unwrap()), [id(2)]);
            assert_eq!(ids(&db.fetch_passkeys("user_c").await.unwrap()), [id(4)]);

            // Again, and for a user with none: a no-op, not an error
            db.delete_passkeys_for_user("user_a").await.unwrap();
            db.delete_passkeys_for_user("user_nobody").await.unwrap();
            assert_eq!(db.count_passkeys("user_b").await.unwrap(), 1);
            assert_eq!(db.count_passkeys("user_c").await.unwrap(), 1);
        });
    }

    #[tokio::test]
    async fn fetch_passkeys_is_oldest_first() {
        database_test!(|db| async move {
            // Ids are given against the registration order, and the rows are
            // inserted in a third order, so neither id order nor insertion
            // order can pass for "oldest first"
            let mut oldest = passkey(30, "user_a");
            oldest.created_at = at(10);
            let mut middle = passkey(10, "user_a");
            middle.created_at = at(20);
            let mut newest = passkey(20, "user_a");
            newest.created_at = at(30);

            // Same instant as `newest`: the id breaks the tie
            let mut tied = passkey(25, "user_a");
            tied.created_at = at(30);

            // Another user's row, older than all of them
            let mut other = passkey(5, "user_b");
            other.created_at = at(1);

            for row in [&newest, &other, &tied, &oldest, &middle] {
                db.insert_passkey(row).await.unwrap();
            }

            assert_eq!(
                ids(&db.fetch_passkeys("user_a").await.unwrap()),
                [id(30), id(10), id(20), id(25)]
            );
            assert_eq!(ids(&db.fetch_passkeys("user_b").await.unwrap()), [id(5)]);
        });
    }
}
