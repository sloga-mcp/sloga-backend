use revolt_result::Result;

use crate::{Account, EmailVerification, Lockout, PasswordReset};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractAccounts: Sync + Send {
    /// Find account by id
    async fn fetch_account(&self, id: &str) -> Result<Account>;

    /// Find account by normalised email
    async fn fetch_account_by_normalised_email(
        &self,
        normalised_email: &str,
    ) -> Result<Option<Account>>;

    /// Find account by linked Google account id
    async fn fetch_account_by_google_id(&self, google_id: &str) -> Result<Option<Account>>;

    /// Find account by linked Apple user id
    async fn fetch_account_by_apple_id(&self, apple_id: &str) -> Result<Option<Account>>;

    /// Find account with active pending email verification
    async fn fetch_account_with_email_verification(&self, token: &str) -> Result<Account>;

    /// Find account with active password reset
    async fn fetch_account_with_password_reset(&self, token: &str) -> Result<Account>;

    /// Find account with active deletion token
    async fn fetch_account_with_deletion_token(&self, token: &str) -> Result<Account>;

    /// Find accounts which are due to be deleted
    async fn fetch_accounts_due_for_deletion(&self) -> Result<Vec<Account>>;

    // Save account
    //
    // Never writes `lockout`: an update keeps the stored value and an insert
    // stores none. Lockout is written only through the lockout ops below.
    async fn save_account(&self, account: &Account) -> Result<()>;

    /// Atomically count one failed attempt, with no lock check
    ///
    /// The expiry follows the new count `n`: `n >= 5` locks for 1 hour,
    /// `n == 4` for 5 minutes, `n == 3` for 1 minute, and any other count
    /// leaves the expiry unchanged. Returns the updated account, or
    /// `UnknownUser` if there is none.
    async fn bump_lockout_count(&self, id: &str) -> Result<Account>;

    /// Atomically reserve one attempt on an account that is not locked
    ///
    /// `LockedOut` if the lockout expiry is in the future, and then nothing
    /// changes (the lockout is not extended). Otherwise exactly like
    /// `bump_lockout_count`.
    async fn reserve_lockout_attempt(&self, id: &str) -> Result<Account>;

    /// Overwrite the lockout, and nothing else
    async fn set_lockout(&self, id: &str, lockout: Option<Lockout>) -> Result<()>;

    /// Atomically remove one recovery code
    ///
    /// `InvalidToken` if the account does not hold that code, so a code can
    /// be spent once however many requests race for it.
    async fn consume_recovery_code(&self, id: &str, code: &str) -> Result<()>;

    /// Overwrite the password reset, and nothing else
    async fn set_password_reset(&self, id: &str, reset: Option<PasswordReset>) -> Result<()>;

    /// Overwrite the email verification, and nothing else
    async fn set_email_verification(
        &self,
        id: &str,
        verification: &EmailVerification,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractAccounts;
    use crate::{Account, EmailVerification, Lockout, PasswordReset};
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_result::ErrorType;

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
        }
    }

    /// Assert an expiry of `offset` from a moment between `before` and
    /// `after`. The slack covers the millisecond truncation of the stored
    /// ISO string.
    fn assert_expiry_near(
        expiry: Option<Timestamp>,
        before: Timestamp,
        after: Timestamp,
        offset: Duration,
    ) {
        let expiry = expiry.expect("the lockout must have an expiry");
        let slack = Duration::seconds(1);
        assert!(
            expiry >= before + offset - slack && expiry <= after + offset + slack,
            "expiry {expiry:?} is not {offset:?} after [{before:?}, {after:?}]"
        );
    }

    /// MongoDB only: the stored expiry must be an ISO string, the type the
    /// lock filter compares against. A BSON date never compares to a string
    /// and would lock the account forever.
    async fn assert_stored_expiry_is_string(db: &crate::Database, id: &str) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                let raw = mongo
                    .col::<bson::Document>("accounts")
                    .find_one(bson::doc! { "_id": id })
                    .await
                    .unwrap()
                    .expect("account exists");
                let lockout = raw.get_document("lockout").expect("lockout is a document");
                assert!(
                    matches!(lockout.get("expiry"), Some(bson::Bson::String(_))),
                    "stored expiry must be a string, got {:?}",
                    lockout.get("expiry")
                );
            }
        }
    }

    #[tokio::test]
    async fn bump_from_missing() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTBUMP0000000000000");
            db.save_account(&acct).await.unwrap();

            // Prove the starting state: the key is absent, not null
            #[cfg(feature = "mongodb")]
            {
                if let crate::Database::MongoDb(mongo) = &db {
                    let raw = mongo
                        .col::<bson::Document>("accounts")
                        .find_one(bson::doc! { "_id": &acct.id })
                        .await
                        .unwrap()
                        .expect("account exists");
                    assert!(raw.get("lockout").is_none(), "lockout key must be absent");
                }
            }

            let bumped = db.bump_lockout_count(&acct.id).await.unwrap();
            assert_eq!(
                bumped.lockout,
                Some(Lockout {
                    attempts: 1,
                    expiry: None
                })
            );

            db.bump_lockout_count(&acct.id).await.unwrap();
            let before = Timestamp::now_utc();
            let bumped = db.bump_lockout_count(&acct.id).await.unwrap();
            let after = Timestamp::now_utc();
            let lockout = bumped.lockout.expect("lockout set");
            assert_eq!(lockout.attempts, 3);
            assert_expiry_near(lockout.expiry, before, after, Duration::minutes(1));

            // The returned document is the stored one
            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.lockout, Some(lockout));
            assert_stored_expiry_is_string(&db, &acct.id).await;

            let missing = db
                .bump_lockout_count("01ACCOUNTMISSING0000000000")
                .await
                .expect_err("a missing account must fail");
            assert!(
                matches!(missing.error_type, ErrorType::UnknownUser),
                "expected UnknownUser, got {:?}",
                missing.error_type
            );
        });
    }

    /// MongoDB only: the reference driver has no raw document to hold a null.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn reserve_from_null() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };

            let acct = account("01ACCOUNTNULL0000000000000");
            db.save_account(&acct).await.unwrap();

            let accounts = mongo.col::<bson::Document>("accounts");
            accounts
                .update_one(
                    bson::doc! { "_id": &acct.id },
                    bson::doc! { "$set": { "lockout": bson::Bson::Null } },
                )
                .await
                .unwrap();

            // Prove the control: the field is stored as an explicit null
            let raw = accounts
                .find_one(bson::doc! { "_id": &acct.id })
                .await
                .unwrap()
                .expect("account exists");
            assert_eq!(raw.get("lockout"), Some(&bson::Bson::Null));

            let reserved = db.reserve_lockout_attempt(&acct.id).await.unwrap();
            assert_eq!(
                reserved.lockout,
                Some(Lockout {
                    attempts: 1,
                    expiry: None
                })
            );

            let bumped = db.bump_lockout_count(&acct.id).await.unwrap();
            assert_eq!(bumped.lockout.map(|lockout| lockout.attempts), Some(2));
        });
    }

    #[tokio::test]
    async fn reserve_then_locked() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTLOCK0000000000000");
            db.save_account(&acct).await.unwrap();
            db.set_lockout(
                &acct.id,
                Some(Lockout {
                    attempts: 2,
                    expiry: None,
                }),
            )
            .await
            .unwrap();

            let before = Timestamp::now_utc();
            let reserved = db.reserve_lockout_attempt(&acct.id).await.unwrap();
            let after = Timestamp::now_utc();
            let lockout = reserved.lockout.expect("lockout set");
            assert_eq!(lockout.attempts, 3);
            assert_expiry_near(lockout.expiry, before, after, Duration::minutes(1));
            assert_stored_expiry_is_string(&db, &acct.id).await;

            let locked = db
                .reserve_lockout_attempt(&acct.id)
                .await
                .expect_err("a locked account must refuse the reserve");
            assert!(
                matches!(locked.error_type, ErrorType::LockedOut),
                "expected LockedOut, got {:?}",
                locked.error_type
            );

            // Refused, so nothing changed: no count, no extension
            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.lockout, Some(lockout));
        });
    }

    #[tokio::test]
    async fn reserve_expired() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTEXPIRED00000000000");
            db.save_account(&acct).await.unwrap();
            db.set_lockout(
                &acct.id,
                Some(Lockout {
                    attempts: 5,
                    expiry: Some(Timestamp::now_utc() - Duration::minutes(1)),
                }),
            )
            .await
            .unwrap();

            let reserved = db.reserve_lockout_attempt(&acct.id).await.unwrap();
            let lockout = reserved.lockout.expect("lockout set");
            assert_eq!(lockout.attempts, 6);
            assert!(
                lockout.expiry.expect("expiry set") > Timestamp::now_utc() + Duration::minutes(59),
                "the sixth attempt must lock for an hour"
            );
            assert_stored_expiry_is_string(&db, &acct.id).await;
        });
    }

    #[tokio::test]
    async fn reserve_concurrent() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTRACE0000000000000");
            db.save_account(&acct).await.unwrap();

            // All twenty are in flight at once on one task
            let attempts = (0..20).map(|_| db.reserve_lockout_attempt(&acct.id));
            let results = futures::future::join_all(attempts).await;

            let ok = results.iter().filter(|result| result.is_ok()).count();
            assert_eq!(ok, 3, "exactly three reserves may pass before the lock");
            for result in &results {
                if let Err(error) = result {
                    assert!(
                        matches!(error.error_type, ErrorType::LockedOut),
                        "expected LockedOut, got {:?}",
                        error.error_type
                    );
                }
            }

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.lockout.map(|lockout| lockout.attempts), Some(3));
        });
    }

    #[tokio::test]
    async fn stale_save() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTSTALE000000000000");
            db.save_account(&acct).await.unwrap();

            let mut stale = db.fetch_account(&acct.id).await.unwrap();
            db.bump_lockout_count(&acct.id).await.unwrap();
            db.bump_lockout_count(&acct.id).await.unwrap();

            stale.password = "hash-changed".to_string();
            db.save_account(&stale).await.unwrap();

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(
                fetched.lockout.map(|lockout| lockout.attempts),
                Some(2),
                "a stale save must not reset the lockout"
            );
            assert_eq!(
                fetched.password, "hash-changed",
                "the save still writes every other field"
            );
        });
    }

    #[tokio::test]
    async fn insert_no_lockout() {
        database_test!(|db| async move {
            let mut acct = account("01ACCOUNTINSERT00000000000");
            acct.lockout = Some(Lockout {
                attempts: 4,
                expiry: Some(Timestamp::now_utc() + Duration::hours(1)),
            });
            db.save_account(&acct).await.unwrap();

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.lockout, None, "an insert must not store a lockout");
        });
    }

    #[tokio::test]
    async fn recovery_consume() {
        database_test!(|db| async move {
            let mut acct = account("01ACCOUNTRECOVERY000000000");
            acct.mfa.recovery_codes = vec!["aaaa".to_string(), "bbbb".to_string()];
            db.save_account(&acct).await.unwrap();

            db.consume_recovery_code(&acct.id, "aaaa").await.unwrap();

            let again = db
                .consume_recovery_code(&acct.id, "aaaa")
                .await
                .expect_err("a spent code must be refused");
            assert!(
                matches!(again.error_type, ErrorType::InvalidToken),
                "expected InvalidToken, got {:?}",
                again.error_type
            );

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.mfa.recovery_codes, vec!["bbbb".to_string()]);

            assert!(db
                .consume_recovery_code("01ACCOUNTMISSING0000000000", "bbbb")
                .await
                .is_err());
        });
    }

    #[tokio::test]
    async fn recovery_race() {
        database_test!(|db| async move {
            let mut acct = account("01ACCOUNTRECRACE0000000000");
            acct.mfa.recovery_codes = vec!["cccc".to_string(), "dddd".to_string()];
            db.save_account(&acct).await.unwrap();

            let attempts = (0..5).map(|_| db.consume_recovery_code(&acct.id, "cccc"));
            let results = futures::future::join_all(attempts).await;
            let ok = results.iter().filter(|result| result.is_ok()).count();
            assert_eq!(ok, 1, "a recovery code may be spent once");

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.mfa.recovery_codes, vec!["dddd".to_string()]);
        });
    }

    #[tokio::test]
    async fn targeted_writes() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTTARGET00000000000");
            db.save_account(&acct).await.unwrap();

            // A copy taken before any of the changes below
            let mut stale = db.fetch_account(&acct.id).await.unwrap();

            let mut fresh = db.fetch_account(&acct.id).await.unwrap();
            fresh.password = "hash-rotated".to_string();
            fresh.mfa.recovery_codes = vec!["eeee".to_string()];
            db.save_account(&fresh).await.unwrap();
            let lockout = db.bump_lockout_count(&acct.id).await.unwrap().lockout;
            assert!(lockout.is_some());

            // Millisecond-exact, so it survives the ISO string round trip
            // and the equality checks below hold on MongoDB too
            let expiry = Timestamp::parse("2099-01-01T00:00:00.000Z").expect("valid timestamp");
            stale.password_reset = Some(PasswordReset {
                token: "reset-token".to_string(),
                expiry,
            });
            db.set_password_reset(&stale.id, stale.password_reset.clone())
                .await
                .unwrap();

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.password_reset, stale.password_reset);
            assert_eq!(fetched.lockout, lockout);
            assert_eq!(fetched.mfa, fresh.mfa);
            assert_eq!(fetched.password, "hash-rotated");
            assert_eq!(fetched.verification, EmailVerification::Verified);

            stale.verification = EmailVerification::Pending {
                token: "verify-token".to_string(),
                expiry,
            };
            db.set_email_verification(&stale.id, &stale.verification)
                .await
                .unwrap();

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.verification, stale.verification);
            assert_eq!(fetched.password_reset, stale.password_reset);
            assert_eq!(fetched.lockout, lockout);
            assert_eq!(fetched.mfa, fresh.mfa);
            assert_eq!(fetched.password, "hash-rotated");

            // None clears only its own field
            db.set_password_reset(&acct.id, None).await.unwrap();
            db.set_lockout(&acct.id, None).await.unwrap();
            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.password_reset, None);
            assert_eq!(fetched.lockout, None);
            assert_eq!(fetched.verification, stale.verification);
            assert_eq!(fetched.mfa, fresh.mfa);

            // A missing account is an error, never a silent no-op
            assert!(db
                .set_lockout("01ACCOUNTMISSING0000000000", None)
                .await
                .is_err());
            assert!(db
                .set_password_reset("01ACCOUNTMISSING0000000000", None)
                .await
                .is_err());
            assert!(db
                .set_email_verification(
                    "01ACCOUNTMISSING0000000000",
                    &EmailVerification::Verified
                )
                .await
                .is_err());
        });
    }
}
