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

    /// Delete one of a user's passkeys, unless it is the last way in.
    ///
    /// Another way in is a usable password, a linked Google or Apple sign-in
    /// (`Account::can_sign_in_without_passkey`), or another passkey of this
    /// user. The account is read inside the op, never taken from the caller.
    ///
    /// NotFound when the id does not exist or belongs to another user;
    /// UnknownUser when the user has no account; InvalidOperation when the
    /// passkey is the only way left to sign in. Nothing is deleted in any of
    /// the three.
    ///
    /// The Reference driver decides and deletes under one lock. MongoDB has
    /// no single statement across the two collections: see the comments in
    /// its implementation for what it does instead and what race is left.
    async fn delete_passkey_unless_last_way_in(&self, user_id: &str, id: &str) -> Result<()>;

    /// Account-deletion cascade: delete every passkey of a user (no-op if
    /// there are none)
    async fn delete_passkeys_for_user(&self, user_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_result::ErrorType;

    use crate::{Account, EmailVerification, Passkey};

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

    fn is_invalid_operation<T>(result: revolt_result::Result<T>) -> bool {
        matches!(result, Err(error) if matches!(error.error_type, ErrorType::InvalidOperation))
    }

    /// An account with a usable password and no linked sign-in
    fn account(id: &str) -> Account {
        Account {
            id: id.to_string(),
            email: format!("{id}@example.test"),
            email_normalised: format!("{id}@example.test"),
            password: "hash-original".to_string(),
            disabled: false,
            verification: EmailVerification::Verified,
            password_reset: None,
            deletion: None,
            lockout: None,
            mfa: Default::default(),
            google_id: None,
            apple_id: None,
            password_absent: false,
            email_absent: false,
        }
    }

    /// An account whose only way in can be a passkey
    fn passkey_only_account(id: &str) -> Account {
        Account {
            password_absent: true,
            ..account(id)
        }
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

    /// Fails if: a password, a Google link, an Apple link or another passkey
    /// stops counting as another way in.
    #[tokio::test]
    async fn the_last_passkey_goes_when_another_way_in_remains() {
        database_test!(|db| async move {
            let with_password = account("01PKACCOUNTPASSWORD0000000");
            let with_google = Account {
                google_id: Some("google-sub-way-in".to_string()),
                ..passkey_only_account("01PKACCOUNTGOOGLE000000000")
            };
            let with_apple = Account {
                apple_id: Some("apple-sub-way-in".to_string()),
                ..passkey_only_account("01PKACCOUNTAPPLE0000000000")
            };

            for (n, acct) in [(1, &with_password), (2, &with_google), (3, &with_apple)] {
                db.save_account(acct).await.unwrap();
                db.insert_passkey(&passkey(n, &acct.id)).await.unwrap();
                assert_eq!(db.count_passkeys(&acct.id).await.unwrap(), 1);

                db.delete_passkey_unless_last_way_in(&acct.id, &id(n))
                    .await
                    .unwrap_or_else(|error| panic!("{}: {error:?}", acct.id));
                assert_eq!(db.count_passkeys(&acct.id).await.unwrap(), 0, "{}", acct.id);
            }

            // Nothing but passkeys: one of two may go
            let only_passkeys = passkey_only_account("01PKACCOUNTTWOPASSKEYS0000");
            db.save_account(&only_passkeys).await.unwrap();
            db.insert_passkey(&passkey(10, &only_passkeys.id))
                .await
                .unwrap();
            db.insert_passkey(&passkey(11, &only_passkeys.id))
                .await
                .unwrap();

            db.delete_passkey_unless_last_way_in(&only_passkeys.id, &id(10))
                .await
                .unwrap();
            assert_eq!(
                ids(&db.fetch_passkeys(&only_passkeys.id).await.unwrap()),
                [id(11)]
            );
        });
    }

    /// Fails if: the only way left to sign in can be removed, another user's
    /// passkeys are counted as this user's, or a refusal alters the row.
    #[tokio::test]
    async fn the_last_way_in_cannot_be_removed() {
        database_test!(|db| async move {
            let acct = passkey_only_account("01PKACCOUNTLASTWAYIN000000");
            db.save_account(&acct).await.unwrap();
            let last = passkey(1, &acct.id);
            db.insert_passkey(&last).await.unwrap();

            // Somebody else has plenty of ways in; none of them are this
            // account's
            let other = account("01PKACCOUNTLASTWAYINOTHER0");
            db.save_account(&other).await.unwrap();
            db.insert_passkey(&passkey(2, &other.id)).await.unwrap();
            db.insert_passkey(&passkey(3, &other.id)).await.unwrap();

            assert!(is_invalid_operation(
                db.delete_passkey_unless_last_way_in(&acct.id, &id(1)).await
            ));
            assert_eq!(db.fetch_passkey(&acct.id, &id(1)).await.unwrap(), last);
            assert_eq!(db.count_passkeys(&acct.id).await.unwrap(), 1);
            assert_eq!(db.count_passkeys(&other.id).await.unwrap(), 2);

            // The control: a second passkey makes the first removable, and
            // then the second is the last
            let second = passkey(4, &acct.id);
            db.insert_passkey(&second).await.unwrap();
            db.delete_passkey_unless_last_way_in(&acct.id, &id(1))
                .await
                .unwrap();
            assert!(is_invalid_operation(
                db.delete_passkey_unless_last_way_in(&acct.id, &id(4)).await
            ));
            assert_eq!(db.fetch_passkey(&acct.id, &id(4)).await.unwrap(), second);
        });
    }

    /// Fails if: the op trusts anything but the stored account. The account
    /// loses its password and its Google link between two removals, and the
    /// second removal must see that.
    #[tokio::test]
    async fn the_account_is_read_when_the_passkey_is_removed() {
        database_test!(|db| async move {
            let mut acct = Account {
                google_id: Some("google-sub-fresh-read".to_string()),
                ..account("01PKACCOUNTFRESHREAD000000")
            };
            db.save_account(&acct).await.unwrap();
            db.insert_passkey(&passkey(1, &acct.id)).await.unwrap();
            db.insert_passkey(&passkey(2, &acct.id)).await.unwrap();
            db.insert_passkey(&passkey(3, &acct.id)).await.unwrap();

            // The password goes: the Google link still counts
            acct.password_absent = true;
            db.save_account(&acct).await.unwrap();
            db.delete_passkey_unless_last_way_in(&acct.id, &id(1))
                .await
                .unwrap();
            db.delete_passkey_unless_last_way_in(&acct.id, &id(2))
                .await
                .unwrap();

            // The link goes too: the one passkey left is the last way in
            db.unlink_account_oauth(&acct.id).await.unwrap();
            assert!(is_invalid_operation(
                db.delete_passkey_unless_last_way_in(&acct.id, &id(3)).await
            ));
            assert_eq!(ids(&db.fetch_passkeys(&acct.id).await.unwrap()), [id(3)]);
        });
    }

    /// Fails if: an unknown id or another user's passkey is anything but
    /// NotFound, a user with no account can remove a passkey, or any of
    /// these deletes a row.
    #[tokio::test]
    async fn conditional_removal_of_a_missing_or_foreign_passkey_is_refused() {
        database_test!(|db| async move {
            let owner = account("01PKACCOUNTFOREIGNOWNER000");
            let thief = account("01PKACCOUNTFOREIGNTHIEF000");
            db.save_account(&owner).await.unwrap();
            db.save_account(&thief).await.unwrap();
            db.insert_passkey(&passkey(1, &owner.id)).await.unwrap();
            db.insert_passkey(&passkey(2, &owner.id)).await.unwrap();

            assert!(is_not_found(
                db.delete_passkey_unless_last_way_in(&thief.id, &id(1)).await
            ));
            assert!(is_not_found(
                db.delete_passkey_unless_last_way_in(&owner.id, &id(9)).await
            ));
            assert_eq!(db.count_passkeys(&owner.id).await.unwrap(), 2);

            // A passkey whose user has no account row is left alone
            db.insert_passkey(&passkey(5, "01PKACCOUNTNOSUCHACCOUNT00"))
                .await
                .unwrap();
            let error = db
                .delete_passkey_unless_last_way_in("01PKACCOUNTNOSUCHACCOUNT00", &id(5))
                .await
                .expect_err("no account, no removal");
            assert!(
                matches!(error.error_type, ErrorType::UnknownUser),
                "expected UnknownUser, got {:?}",
                error.error_type
            );
            assert_eq!(
                db.count_passkeys("01PKACCOUNTNOSUCHACCOUNT00").await.unwrap(),
                1
            );

            // The control: the owner removes one, and it is gone for good
            db.delete_passkey_unless_last_way_in(&owner.id, &id(1))
                .await
                .unwrap();
            assert!(is_not_found(
                db.delete_passkey_unless_last_way_in(&owner.id, &id(1)).await
            ));
            assert_eq!(ids(&db.fetch_passkeys(&owner.id).await.unwrap()), [id(2)]);
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
