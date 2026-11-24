use revolt_result::Result;

use crate::{Account, DeletionInfo, EmailVerification, Lockout, PasswordReset};

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
    ///
    /// The token must be pending and unexpired, else `InvalidToken`.
    async fn fetch_account_with_deletion_token(&self, token: &str) -> Result<Account>;

    /// Find accounts which are due to be deleted
    async fn fetch_accounts_due_for_deletion(&self) -> Result<Vec<Account>>;

    // Save account
    //
    // Never writes `lockout` or `deletion`: an update keeps the stored values
    // and an insert stores none. Lockout is written only through the lockout
    // ops below, and deletion only through the deletion ops, so a stale
    // whole-document save can neither reset a lockout nor cancel, revive or
    // un-schedule a deletion. Every other field, `disabled` included, is
    // still written.
    //
    // A copy with `email_absent` set never writes `email`,
    // `email_normalised` or `email_absent` of a row that exists (an insert
    // stores them): the address of such an account arrives only through
    // `set_account_email_if_absent`, and a copy loaded before that write
    // must not put the stand-in back. So a save can clear `email_absent`
    // but never set it on a stored row.
    //
    // A save that would leave two accounts with one address, in `email` or
    // in `email_normalised` and without regard to letter case, fails with a
    // database error and stores nothing: the unique indexes on MongoDB, the
    // same check in the reference driver.
    async fn save_account(&self, account: &Account) -> Result<()>;

    /// Overwrite the deletion state, and nothing else
    ///
    /// `None` removes it. `UnknownUser` if there is no such account.
    async fn set_account_deletion(&self, id: &str, deletion: Option<DeletionInfo>) -> Result<()>;

    /// Atomically store a new deletion request
    ///
    /// Writes `deletion` only if the account is not disabled and has no
    /// deletion or a `WaitingForVerification` one (which it replaces). A
    /// `Scheduled` or `Deleted` account, a disabled one, or no such account
    /// is `InvalidOperation` and changes nothing, so a request racing a
    /// confirm can never turn a claimed deletion back into a pending one
    /// that could then be neither confirmed nor purged.
    async fn request_account_deletion(&self, id: &str, deletion: DeletionInfo) -> Result<()>;

    /// Atomically confirm a pending deletion
    ///
    /// Matches only an account that is not disabled and whose deletion is
    /// `WaitingForVerification` with this token and an expiry not yet
    /// passed. It becomes `Scheduled { after: now }` and disabled in the same
    /// write, and the updated account is returned. Anything else is
    /// `InvalidToken` and changes nothing, so of any number of racing claims
    /// (or a claim racing `cancel_account_deletion`) exactly one wins.
    async fn claim_account_deletion(&self, token: &str) -> Result<Account>;

    /// Atomically cancel a pending deletion
    ///
    /// If the account's deletion is `WaitingForVerification`, expired or
    /// not, it is removed and the previous value returned. Otherwise
    /// (`Scheduled`, `Deleted`, none, or no such account) nothing changes
    /// and the result is `None`.
    async fn cancel_account_deletion(&self, account_id: &str) -> Result<Option<DeletionInfo>>;

    /// Remove the linked Google and Apple ids, and nothing else
    ///
    /// Both are removed from storage, so neither `fetch_account_by_google_id`
    /// nor `fetch_account_by_apple_id` finds the account afterwards.
    /// `save_account` cannot do this: it leaves a `None` id out of its
    /// write. An account with neither id is `Ok`. `UnknownUser` if there is
    /// no such account.
    async fn unlink_account_oauth(&self, id: &str) -> Result<()>;

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

    /// Atomically give an account that has no email its first address
    ///
    /// Sets `email` and `email_normalised` and clears `email_absent`, only
    /// if the account still has `email_absent` set, was not deleted, and no
    /// other account holds the address in either field (compared without
    /// regard to case, as the unique indexes do). `Ok(true)` if it applied.
    /// Otherwise `Ok(false)` and nothing changed; a missing account is
    /// `Ok(false)` too. The caller normalises: use
    /// `Account::set_first_email`.
    async fn set_account_email_if_absent(
        &self,
        id: &str,
        email: &str,
        email_normalised: &str,
    ) -> Result<bool>;

    /// Undo a failed sign-up: remove the account row it just inserted
    ///
    /// This is NOT how a user's account is deleted (that is
    /// `Account::schedule_deletion`, then the purge). It removes one row and
    /// nothing that hangs off it, and exists only so a sign-up that failed
    /// after its first write leaves no half-made account behind. It only
    /// removes a row that has no usable password (`password_absent`), which
    /// every passkey sign-up row has. `Ok(true)` if a row was removed.
    async fn rollback_signup_account(&self, id: &str) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::AbstractAccounts;
    use crate::{Account, DeletionInfo, EmailVerification, Lockout, PasswordReset};
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
            password_absent: false,
            email_absent: false,
        }
    }

    /// An account with no email: the flag, and a stand-in in both fields
    fn no_email_account(id: &str) -> Account {
        let placeholder = crate::util::email::generate_placeholder_email();
        Account {
            email: placeholder.clone(),
            email_normalised: placeholder,
            password_absent: true,
            email_absent: true,
            ..account(id)
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

    /// Fails if: a copy loaded while the account had no email, saved after
    /// the first-email op landed, puts the stand-in or the flag back; or
    /// that save stops writing the other fields.
    #[tokio::test]
    async fn stale_save_keeps_an_added_email() {
        database_test!(|db| async move {
            let acct = no_email_account("01ACCOUNTSTALEEMAIL0000000");
            db.save_account(&acct).await.unwrap();

            let mut stale = db.fetch_account(&acct.id).await.unwrap();
            assert!(stale.email_absent, "the control: loaded with no email");

            assert!(db
                .set_account_email_if_absent(&acct.id, "Ad.ded@example.test", "added@example.test")
                .await
                .unwrap());

            stale.password = "hash-changed".to_string();
            db.save_account(&stale).await.unwrap();

            let stored = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(
                stored,
                Account {
                    email: "Ad.ded@example.test".to_string(),
                    email_normalised: "added@example.test".to_string(),
                    email_absent: false,
                    password: "hash-changed".to_string(),
                    ..acct.clone()
                },
                "the added email stays, and the save still writes the rest"
            );
            assert_eq!(stored.real_email(), Some("Ad.ded@example.test"));

            // The same copy saved again changes nothing either
            db.save_account(&stale).await.unwrap();
            assert_eq!(db.fetch_account(&acct.id).await.unwrap(), stored);
        });
    }

    /// Fails if: the first save of an account with no email stops storing
    /// the stand-in and the flag; a later save of such a copy rewrites the
    /// email fields of the stored row; or a copy that has an email stops
    /// writing them.
    #[tokio::test]
    async fn save_writes_email_fields_on_insert_and_for_a_copy_with_an_email() {
        database_test!(|db| async move {
            // Insert: all three are stored
            let absent = no_email_account("01ACCOUNTSAVEEMAILABSENT00");
            db.save_account(&absent).await.unwrap();
            let stored = db.fetch_account(&absent.id).await.unwrap();
            assert_eq!(stored, absent);
            assert!(stored.email_absent);

            // A copy that says "no email" cannot change the stored fields
            let mut edited = absent.clone();
            edited.email = "typed@example.test".to_string();
            edited.email_normalised = "typed@example.test".to_string();
            edited.disabled = true;
            db.save_account(&edited).await.unwrap();
            assert_eq!(
                db.fetch_account(&absent.id).await.unwrap(),
                Account {
                    disabled: true,
                    ..absent.clone()
                }
            );

            // Nor can it set the flag on a row that has an email
            let with_email = account("01ACCOUNTSAVEEMAILHASONE00");
            db.save_account(&with_email).await.unwrap();
            let mut flagged = with_email.clone();
            flagged.email_absent = true;
            flagged.email = "other@example.test".to_string();
            db.save_account(&flagged).await.unwrap();
            assert_eq!(db.fetch_account(&with_email.id).await.unwrap(), with_email);

            // The control: a copy that has an email saves as before
            let mut moved = with_email.clone();
            moved.email = "Mo.ved@example.test".to_string();
            moved.email_normalised = "moved@example.test".to_string();
            db.save_account(&moved).await.unwrap();
            assert_eq!(db.fetch_account(&with_email.id).await.unwrap(), moved);
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

    /// Millisecond-exact, so it survives the ISO string round trip
    fn far_future() -> Timestamp {
        Timestamp::parse("2099-01-01T00:00:00.000Z").expect("valid timestamp")
    }

    fn waiting(token: &str, expiry: Timestamp) -> Option<DeletionInfo> {
        Some(DeletionInfo::WaitingForVerification {
            token: token.to_string(),
            expiry,
        })
    }

    /// Insert an account and give it a pending deletion through the
    /// targeted write, never through `save_account`
    async fn request_deletion(
        db: &crate::Database,
        mut acct: Account,
        token: &str,
        expiry: Timestamp,
    ) -> Account {
        acct.deletion = None;
        db.save_account(&acct).await.unwrap();
        db.set_account_deletion(&acct.id, waiting(token, expiry))
            .await
            .unwrap();
        db.fetch_account(&acct.id).await.unwrap()
    }

    fn assert_invalid_token(result: revolt_result::Result<Account>, why: &str) {
        let error = result.expect_err(why);
        assert!(
            matches!(error.error_type, ErrorType::InvalidToken),
            "{why}: expected InvalidToken, got {:?}",
            error.error_type
        );
    }

    #[tokio::test]
    async fn deletion_claim() {
        database_test!(|db| async move {
            let acct = request_deletion(
                &db,
                account("01ACCOUNTDELCLAIM000000000"),
                "claim-token",
                far_future(),
            )
            .await;
            assert!(db
                .fetch_account_with_deletion_token("claim-token")
                .await
                .is_ok());

            let claimed = db.claim_account_deletion("claim-token").await.unwrap();
            assert_eq!(claimed.id, acct.id);
            assert!(claimed.disabled, "a claim must disable the account");
            assert!(
                matches!(claimed.deletion, Some(DeletionInfo::Scheduled { .. })),
                "a claim must schedule the deletion, got {:?}",
                claimed.deletion
            );

            // The returned document is the stored one
            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert!(fetched.disabled);
            assert_eq!(fetched.deletion, claimed.deletion);

            // A token is spent once
            assert_invalid_token(
                db.claim_account_deletion("claim-token").await,
                "a second claim must be refused",
            );
            assert_invalid_token(
                db.fetch_account_with_deletion_token("claim-token").await,
                "a claimed token no longer finds the account",
            );

            // A claimed deletion cannot be cancelled
            assert_eq!(db.cancel_account_deletion(&acct.id).await.unwrap(), None);
            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, claimed.deletion);
            assert!(fetched.disabled);

            // `after` is now, so the purge picks it up at once
            let due = db.fetch_accounts_due_for_deletion().await.unwrap();
            assert_eq!(
                due.iter().map(|due| due.id.as_str()).collect::<Vec<_>>(),
                vec![acct.id.as_str()]
            );
        });
    }

    #[tokio::test]
    async fn deletion_claim_expired() {
        database_test!(|db| async move {
            let acct = request_deletion(
                &db,
                account("01ACCOUNTDELEXPIRED0000000"),
                "expired-token",
                Timestamp::now_utc() - Duration::minutes(1),
            )
            .await;

            assert_invalid_token(
                db.claim_account_deletion("expired-token").await,
                "an expired token must be refused",
            );
            assert_invalid_token(
                db.fetch_account_with_deletion_token("expired-token").await,
                "an expired token must not find the account",
            );

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, acct.deletion, "a refused claim changes nothing");
            assert!(!fetched.disabled);
        });
    }

    #[tokio::test]
    async fn deletion_claim_wrong_token() {
        database_test!(|db| async move {
            let acct = request_deletion(
                &db,
                account("01ACCOUNTDELWRONG000000000"),
                "right-token",
                far_future(),
            )
            .await;

            assert_invalid_token(
                db.claim_account_deletion("wrong-token").await,
                "a wrong token must be refused",
            );

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, waiting("right-token", far_future()));
            assert!(!fetched.disabled);
        });
    }

    #[tokio::test]
    async fn deletion_claim_disabled() {
        database_test!(|db| async move {
            let mut acct = account("01ACCOUNTDELDISABLED000000");
            acct.disabled = true;
            let acct = request_deletion(&db, acct, "disabled-token", far_future()).await;
            assert!(acct.disabled, "the control: the account is stored disabled");

            assert_invalid_token(
                db.claim_account_deletion("disabled-token").await,
                "a disabled account must be refused",
            );

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, waiting("disabled-token", far_future()));
        });
    }

    #[tokio::test]
    async fn deletion_cancel() {
        database_test!(|db| async move {
            let acct = request_deletion(
                &db,
                account("01ACCOUNTDELCANCEL00000000"),
                "cancel-token",
                far_future(),
            )
            .await;

            let previous = db.cancel_account_deletion(&acct.id).await.unwrap();
            assert_eq!(previous, waiting("cancel-token", far_future()));

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, None);
            assert!(!fetched.disabled);

            assert_invalid_token(
                db.claim_account_deletion("cancel-token").await,
                "a cancelled token must be refused",
            );
            assert_eq!(db.cancel_account_deletion(&acct.id).await.unwrap(), None);
            assert_eq!(
                db.cancel_account_deletion("01ACCOUNTMISSING0000000000")
                    .await
                    .unwrap(),
                None
            );
        });
    }

    #[tokio::test]
    async fn deletion_cancel_expired() {
        database_test!(|db| async move {
            let expiry = Timestamp::parse("2000-01-01T00:00:00.000Z").expect("valid timestamp");
            let acct = request_deletion(
                &db,
                account("01ACCOUNTDELCANCELEXP00000"),
                "old-token",
                expiry,
            )
            .await;

            // An expired request is still cleared, and the caller sees it
            // was expired
            let previous = db.cancel_account_deletion(&acct.id).await.unwrap();
            assert_eq!(previous, waiting("old-token", expiry));
            assert_eq!(db.fetch_account(&acct.id).await.unwrap().deletion, None);
        });
    }

    #[tokio::test]
    async fn deletion_cancel_scheduled() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTDELSCHEDULED00000");
            db.save_account(&acct).await.unwrap();

            let scheduled = Some(DeletionInfo::Scheduled {
                after: far_future(),
            });
            db.set_account_deletion(&acct.id, scheduled.clone())
                .await
                .unwrap();
            assert_eq!(db.cancel_account_deletion(&acct.id).await.unwrap(), None);
            assert_eq!(db.fetch_account(&acct.id).await.unwrap().deletion, scheduled);

            db.set_account_deletion(&acct.id, Some(DeletionInfo::Deleted))
                .await
                .unwrap();
            assert_eq!(db.cancel_account_deletion(&acct.id).await.unwrap(), None);
            assert_eq!(
                db.fetch_account(&acct.id).await.unwrap().deletion,
                Some(DeletionInfo::Deleted)
            );
        });
    }

    #[tokio::test]
    async fn deletion_race() {
        database_test!(|db| async move {
            // Racing claims: exactly one wins
            let acct = request_deletion(
                &db,
                account("01ACCOUNTDELRACE0000000000"),
                "race-token",
                far_future(),
            )
            .await;
            let claims = (0..5).map(|_| db.claim_account_deletion("race-token"));
            let results = futures::future::join_all(claims).await;
            assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
            for result in results.into_iter().filter(|result| result.is_err()) {
                assert_invalid_token(result, "a losing claim");
            }
            assert!(matches!(
                db.fetch_account(&acct.id).await.unwrap().deletion,
                Some(DeletionInfo::Scheduled { .. })
            ));

            // A claim racing a cancel: exactly one of them takes effect
            let other = request_deletion(
                &db,
                account("01ACCOUNTDELRACE2000000000"),
                "race-token-2",
                far_future(),
            )
            .await;
            let (claim, cancel) = futures::join!(
                db.claim_account_deletion("race-token-2"),
                db.cancel_account_deletion(&other.id)
            );
            let cancel = cancel.unwrap();
            let fetched = db.fetch_account(&other.id).await.unwrap();
            match claim {
                Ok(_) => {
                    assert_eq!(cancel, None, "both the claim and the cancel won");
                    assert!(matches!(
                        fetched.deletion,
                        Some(DeletionInfo::Scheduled { .. })
                    ));
                    assert!(fetched.disabled);
                }
                Err(error) => {
                    assert!(matches!(error.error_type, ErrorType::InvalidToken));
                    assert_eq!(cancel, waiting("race-token-2", far_future()));
                    assert_eq!(fetched.deletion, None);
                    assert!(!fetched.disabled);
                }
            }
        });
    }

    #[tokio::test]
    async fn deletion_stale_save() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTDELSTALE000000000");
            db.save_account(&acct).await.unwrap();

            // A copy taken before the deletion was requested and claimed
            let mut stale = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(stale.deletion, None);
            assert!(!stale.disabled);

            db.set_account_deletion(&acct.id, waiting("stale-token", far_future()))
                .await
                .unwrap();
            let claimed = db.claim_account_deletion("stale-token").await.unwrap();

            stale.password = "hash-changed".to_string();
            db.save_account(&stale).await.unwrap();

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(
                fetched.deletion, claimed.deletion,
                "a stale save must not clear a scheduled deletion"
            );
            assert_eq!(
                fetched.password, "hash-changed",
                "the save still writes every other field"
            );
            // `disabled` is NOT protected: the stale save wrote it back
            assert!(!fetched.disabled);
            assert_eq!(
                db.fetch_accounts_due_for_deletion().await.unwrap().len(),
                1,
                "the purge still finds the account"
            );

            // A save never writes a deletion of its own either
            stale.deletion = Some(DeletionInfo::Deleted);
            db.save_account(&stale).await.unwrap();
            assert_eq!(
                db.fetch_account(&acct.id).await.unwrap().deletion,
                claimed.deletion
            );

            // Nor does an insert
            let mut fresh = account("01ACCOUNTDELINSERT00000000");
            fresh.deletion = waiting("insert-token", far_future());
            db.save_account(&fresh).await.unwrap();
            assert_eq!(
                db.fetch_account(&fresh.id).await.unwrap().deletion,
                None,
                "an insert must not store a deletion"
            );
        });
    }

    #[tokio::test]
    async fn deletion_set() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTDELSET00000000000");
            db.save_account(&acct).await.unwrap();

            let scheduled = Some(DeletionInfo::Scheduled {
                after: far_future(),
            });
            db.set_account_deletion(&acct.id, scheduled.clone())
                .await
                .unwrap();
            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, scheduled);
            assert_eq!(fetched.password, acct.password, "nothing else changes");

            db.set_account_deletion(&acct.id, None).await.unwrap();
            assert_eq!(db.fetch_account(&acct.id).await.unwrap().deletion, None);

            // MongoDB: `None` removes the key, it does not store a null
            #[cfg(feature = "mongodb")]
            {
                if let crate::Database::MongoDb(mongo) = &db {
                    let raw = mongo
                        .col::<bson::Document>("accounts")
                        .find_one(bson::doc! { "_id": &acct.id })
                        .await
                        .unwrap()
                        .expect("account exists");
                    assert!(raw.get("deletion").is_none(), "deletion key must be absent");
                }
            }

            let missing = db
                .set_account_deletion("01ACCOUNTMISSING0000000000", None)
                .await
                .expect_err("a missing account must fail");
            assert!(
                matches!(missing.error_type, ErrorType::UnknownUser),
                "expected UnknownUser, got {:?}",
                missing.error_type
            );
        });
    }

    /// The pending state a deletion request stores
    fn pending(token: &str) -> DeletionInfo {
        DeletionInfo::WaitingForVerification {
            token: token.to_string(),
            expiry: far_future(),
        }
    }

    fn assert_invalid_operation(result: revolt_result::Result<()>, why: &str) {
        let error = result.expect_err(why);
        assert!(
            matches!(error.error_type, ErrorType::InvalidOperation),
            "{why}: expected InvalidOperation, got {:?}",
            error.error_type
        );
    }

    /// Store `deletion` on a fresh account, then show a request is refused
    /// and leaves it as it was
    async fn assert_request_refused(db: &crate::Database, id: &str, deletion: DeletionInfo) {
        db.save_account(&account(id)).await.unwrap();
        db.set_account_deletion(id, Some(deletion.clone()))
            .await
            .unwrap();

        assert_invalid_operation(
            db.request_account_deletion(id, pending("refused-token"))
                .await,
            &format!("{id}: a request over {deletion:?} must be refused"),
        );

        let fetched = db.fetch_account(id).await.unwrap();
        assert_eq!(
            fetched.deletion,
            Some(deletion),
            "{id}: a refused request changes nothing"
        );
        assert!(!fetched.disabled);
        assert_invalid_token(
            db.fetch_account_with_deletion_token("refused-token").await,
            "a refused request must not store its token",
        );
    }

    #[tokio::test]
    async fn deletion_request_stores() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTDELREQUEST0000000");
            db.save_account(&acct).await.unwrap();

            db.request_account_deletion(&acct.id, pending("request-token"))
                .await
                .unwrap();

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, Some(pending("request-token")));
            assert!(!fetched.disabled, "a request does not disable");
            assert_eq!(fetched.password, acct.password, "nothing else changes");
            assert_eq!(
                db.fetch_account_with_deletion_token("request-token")
                    .await
                    .unwrap()
                    .id,
                acct.id
            );

            // A missing account is refused, never a silent no-op
            assert_invalid_operation(
                db.request_account_deletion("01ACCOUNTMISSING0000000000", pending("missing-token"))
                    .await,
                "a missing account must be refused",
            );
        });
    }

    #[tokio::test]
    async fn deletion_request_replaces_pending() {
        database_test!(|db| async move {
            let acct = request_deletion(
                &db,
                account("01ACCOUNTDELREQREPLACE0000"),
                "first-token",
                far_future(),
            )
            .await;

            db.request_account_deletion(&acct.id, pending("second-token"))
                .await
                .unwrap();
            assert_eq!(
                db.fetch_account(&acct.id).await.unwrap().deletion,
                Some(pending("second-token"))
            );
            assert_invalid_token(
                db.claim_account_deletion("first-token").await,
                "a replaced token must be refused",
            );

            // An expired pending request is replaced the same way
            let expired = Timestamp::parse("2000-01-01T00:00:00.000Z").expect("valid timestamp");
            db.set_account_deletion(&acct.id, waiting("expired-token", expired))
                .await
                .unwrap();
            db.request_account_deletion(&acct.id, pending("third-token"))
                .await
                .unwrap();

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, Some(pending("third-token")));
            assert!(!fetched.disabled);
        });
    }

    #[tokio::test]
    async fn deletion_request_refuses_scheduled() {
        database_test!(|db| async move {
            assert_request_refused(
                &db,
                "01ACCOUNTDELREQSCHEDULED00",
                DeletionInfo::Scheduled {
                    after: far_future(),
                },
            )
            .await;
        });
    }

    #[tokio::test]
    async fn deletion_request_refuses_deleted() {
        database_test!(|db| async move {
            assert_request_refused(&db, "01ACCOUNTDELREQDELETED0000", DeletionInfo::Deleted).await;
        });
    }

    #[tokio::test]
    async fn deletion_request_refuses_disabled() {
        database_test!(|db| async move {
            let mut acct = account("01ACCOUNTDELREQDISABLED000");
            acct.disabled = true;
            db.save_account(&acct).await.unwrap();
            assert!(
                db.fetch_account(&acct.id).await.unwrap().disabled,
                "the control: the account is stored disabled"
            );

            assert_invalid_operation(
                db.request_account_deletion(&acct.id, pending("disabled-token"))
                    .await,
                "a disabled account with no deletion must be refused",
            );
            assert_eq!(db.fetch_account(&acct.id).await.unwrap().deletion, None);

            // Disabled with a pending deletion: still refused, still unchanged
            db.set_account_deletion(&acct.id, waiting("old-token", far_future()))
                .await
                .unwrap();
            assert_invalid_operation(
                db.request_account_deletion(&acct.id, pending("disabled-token"))
                    .await,
                "a disabled account with a pending deletion must be refused",
            );

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.deletion, waiting("old-token", far_future()));
            assert!(fetched.disabled);
        });
    }

    /// Wave-2 audit MINOR 1: a request landing after a confirm's claim must
    /// not turn Scheduled back into a pending deletion on a disabled
    /// account, which could then be neither confirmed nor purged
    #[tokio::test]
    async fn deletion_request_after_claim() {
        database_test!(|db| async move {
            let acct = request_deletion(
                &db,
                account("01ACCOUNTDELREQCLAIM000000"),
                "claim-token",
                far_future(),
            )
            .await;
            let claimed = db.claim_account_deletion("claim-token").await.unwrap();

            assert_invalid_operation(
                db.request_account_deletion(&acct.id, pending("late-token"))
                    .await,
                "a request after a claim must be refused",
            );

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert!(
                matches!(fetched.deletion, Some(DeletionInfo::Scheduled { .. })),
                "the account must stay Scheduled, got {:?}",
                fetched.deletion
            );
            assert_eq!(fetched.deletion, claimed.deletion);
            assert!(fetched.disabled, "the account must stay disabled");
            assert_invalid_token(
                db.fetch_account_with_deletion_token("late-token").await,
                "the refused request must not store its token",
            );

            // The purge still finds it
            let due = db.fetch_accounts_due_for_deletion().await.unwrap();
            assert_eq!(
                due.iter().map(|due| due.id.as_str()).collect::<Vec<_>>(),
                vec![acct.id.as_str()]
            );

            // A request racing a claim: exactly one takes effect, and the
            // account is never left pending and disabled at once
            let other = request_deletion(
                &db,
                account("01ACCOUNTDELREQCLAIM200000"),
                "race-token",
                far_future(),
            )
            .await;
            let (claim, request) = futures::join!(
                db.claim_account_deletion("race-token"),
                db.request_account_deletion(&other.id, pending("racing-token"))
            );
            let fetched = db.fetch_account(&other.id).await.unwrap();
            match claim {
                Ok(_) => {
                    assert_invalid_operation(request, "both the claim and the request won");
                    assert!(matches!(
                        fetched.deletion,
                        Some(DeletionInfo::Scheduled { .. })
                    ));
                    assert!(fetched.disabled);
                }
                Err(error) => {
                    assert!(matches!(error.error_type, ErrorType::InvalidToken));
                    request.expect("the claim lost, so the request must have won");
                    assert_eq!(fetched.deletion, Some(pending("racing-token")));
                    assert!(!fetched.disabled);
                }
            }
        });
    }

    /// MongoDB only: whole-document saves stored `deletion: null` before
    /// `save_account` stopped writing it, and such an account must still be
    /// able to ask. The reference driver has no raw document to hold a null.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn deletion_request_over_null() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };

            let acct = account("01ACCOUNTDELREQNULL0000000");
            db.save_account(&acct).await.unwrap();

            let accounts = mongo.col::<bson::Document>("accounts");
            accounts
                .update_one(
                    bson::doc! { "_id": &acct.id },
                    bson::doc! { "$set": { "deletion": bson::Bson::Null } },
                )
                .await
                .unwrap();

            // Prove the control: the field is stored as an explicit null
            let raw = accounts
                .find_one(bson::doc! { "_id": &acct.id })
                .await
                .unwrap()
                .expect("account exists");
            assert_eq!(raw.get("deletion"), Some(&bson::Bson::Null));

            db.request_account_deletion(&acct.id, pending("null-token"))
                .await
                .unwrap();
            assert_eq!(
                db.fetch_account(&acct.id).await.unwrap().deletion,
                Some(pending("null-token"))
            );
        });
    }

    /// Amendment 9: a purged account must not keep its OAuth ids, so the
    /// unlink removes both and leaves every other field as it was
    #[tokio::test]
    async fn oauth_unlink() {
        database_test!(|db| async move {
            let mut acct = account("01ACCOUNTOAUTHUNLINK000000");
            acct.google_id = Some("google-sub-unlink".to_string());
            acct.apple_id = Some("apple-sub-unlink".to_string());
            acct.password_reset = Some(PasswordReset {
                token: "reset-token".to_string(),
                expiry: far_future(),
            });
            db.save_account(&acct).await.unwrap();
            let scheduled = Some(DeletionInfo::Scheduled {
                after: far_future(),
            });
            db.set_account_deletion(&acct.id, scheduled.clone())
                .await
                .unwrap();
            let lockout = db.bump_lockout_count(&acct.id).await.unwrap().lockout;

            // The control: both lookups find the account before the unlink
            assert_eq!(
                db.fetch_account_by_google_id("google-sub-unlink")
                    .await
                    .unwrap()
                    .expect("the control: the Google id is stored")
                    .id,
                acct.id
            );
            assert_eq!(
                db.fetch_account_by_apple_id("apple-sub-unlink")
                    .await
                    .unwrap()
                    .expect("the control: the Apple id is stored")
                    .id,
                acct.id
            );

            db.unlink_account_oauth(&acct.id).await.unwrap();

            assert!(db
                .fetch_account_by_google_id("google-sub-unlink")
                .await
                .unwrap()
                .is_none());
            assert!(db
                .fetch_account_by_apple_id("apple-sub-unlink")
                .await
                .unwrap()
                .is_none());

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.google_id, None);
            assert_eq!(fetched.apple_id, None);

            // Nothing else changes
            assert_eq!(fetched.email, acct.email);
            assert_eq!(fetched.email_normalised, acct.email_normalised);
            assert_eq!(fetched.password, acct.password);
            assert_eq!(fetched.disabled, acct.disabled);
            assert_eq!(fetched.verification, acct.verification);
            assert_eq!(fetched.password_reset, acct.password_reset);
            assert_eq!(fetched.mfa, acct.mfa);
            assert_eq!(fetched.deletion, scheduled);
            assert_eq!(fetched.lockout, lockout);

            // MongoDB: both keys are removed, not stored as nulls
            #[cfg(feature = "mongodb")]
            {
                if let crate::Database::MongoDb(mongo) = &db {
                    let raw = mongo
                        .col::<bson::Document>("accounts")
                        .find_one(bson::doc! { "_id": &acct.id })
                        .await
                        .unwrap()
                        .expect("account exists");
                    assert!(
                        raw.get("google_id").is_none(),
                        "google_id key must be absent"
                    );
                    assert!(raw.get("apple_id").is_none(), "apple_id key must be absent");
                }
            }
        });
    }

    /// Only one id linked: the unlink still clears it
    #[tokio::test]
    async fn oauth_unlink_one_id() {
        database_test!(|db| async move {
            let mut acct = account("01ACCOUNTOAUTHUNLINKONE000");
            acct.apple_id = Some("apple-sub-only".to_string());
            db.save_account(&acct).await.unwrap();

            db.unlink_account_oauth(&acct.id).await.unwrap();

            assert!(db
                .fetch_account_by_apple_id("apple-sub-only")
                .await
                .unwrap()
                .is_none());
            assert_eq!(db.fetch_account(&acct.id).await.unwrap().apple_id, None);
        });
    }

    /// An account with no ids (and a second unlink, as a retried purge
    /// runs) is `Ok` and changes nothing
    #[tokio::test]
    async fn oauth_unlink_none() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTOAUTHUNLINKNONE00");
            db.save_account(&acct).await.unwrap();

            db.unlink_account_oauth(&acct.id).await.unwrap();
            db.unlink_account_oauth(&acct.id).await.unwrap();

            let fetched = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(fetched.google_id, None);
            assert_eq!(fetched.apple_id, None);
            assert_eq!(fetched.email, acct.email);
            assert_eq!(fetched.password, acct.password);
        });
    }

    #[tokio::test]
    async fn oauth_unlink_missing() {
        database_test!(|db| async move {
            let missing = db
                .unlink_account_oauth("01ACCOUNTMISSING0000000000")
                .await
                .expect_err("a missing account must fail");
            assert!(
                matches!(missing.error_type, ErrorType::UnknownUser),
                "expected UnknownUser, got {:?}",
                missing.error_type
            );
        });
    }

    /// Fails if: the first-email write does not store both fields and clear
    /// the flag, touches anything else, or applies a second time.
    #[tokio::test]
    async fn first_email_applies_once() {
        database_test!(|db| async move {
            db.migrate_database().await.expect("schema");

            let acct = no_email_account("01ACCOUNTFIRSTEMAILONCE000");
            db.save_account(&acct).await.unwrap();

            assert!(db
                .set_account_email_if_absent(&acct.id, "Fi.rst@example.test", "first@example.test")
                .await
                .unwrap());

            let stored = db.fetch_account(&acct.id).await.unwrap();
            assert_eq!(
                stored,
                Account {
                    email: "Fi.rst@example.test".to_string(),
                    email_normalised: "first@example.test".to_string(),
                    email_absent: false,
                    ..acct.clone()
                },
                "only the two email fields and the flag change"
            );

            // The account has an email now, so the write is spent
            assert!(!db
                .set_account_email_if_absent(&acct.id, "second@example.test", "second@example.test")
                .await
                .unwrap());
            assert_eq!(db.fetch_account(&acct.id).await.unwrap(), stored);
        });
    }

    /// Fails if: an address another account holds, in either field or in
    /// another letter case, can be written; or a refusal changes anything.
    #[tokio::test]
    async fn first_email_is_refused_when_another_account_holds_it() {
        database_test!(|db| async move {
            // On MongoDB the unique indexes are what settle a race
            db.migrate_database().await.expect("schema");

            let holder = Account {
                email: "Ta.ken@example.test".to_string(),
                email_normalised: "taken@example.test".to_string(),
                ..account("01ACCOUNTFIRSTEMAILHOLDER0")
            };
            db.save_account(&holder).await.unwrap();

            let acct = no_email_account("01ACCOUNTFIRSTEMAILDUP0000");
            db.save_account(&acct).await.unwrap();

            for (email, email_normalised) in [
                // The same normalised address behind another spelling
                ("taken+alias@example.test", "taken@example.test"),
                ("T.aken@example.test", "TAKEN@EXAMPLE.TEST"),
                // The same typed address
                ("Ta.ken@example.test", "other@example.test"),
                ("ta.KEN@example.test", "other@example.test"),
            ] {
                assert!(
                    !db.set_account_email_if_absent(&acct.id, email, email_normalised)
                        .await
                        .unwrap(),
                    "{email} / {email_normalised}"
                );
                assert_eq!(
                    db.fetch_account(&acct.id).await.unwrap(),
                    acct,
                    "{email} / {email_normalised}: a refusal changes nothing"
                );
            }
            assert_eq!(db.fetch_account(&holder.id).await.unwrap(), holder);

            // The control: an address nobody holds is written
            assert!(db
                .set_account_email_if_absent(&acct.id, "free@example.test", "free@example.test")
                .await
                .unwrap());
            assert!(!db.fetch_account(&acct.id).await.unwrap().email_absent);
        });
    }

    /// Fails if: a save stores a second account under an address another
    /// account holds, in either field or in another letter case (the
    /// reference driver without its check, or MongoDB without its unique
    /// indexes); or the refused save changes the holder or an account that
    /// tried to move onto the address.
    #[tokio::test]
    async fn save_refuses_an_address_another_account_holds() {
        database_test!(|db| async move {
            // On MongoDB the unique indexes are what refuse
            db.migrate_database().await.expect("schema");

            let holder = Account {
                email: "Ta.ken@example.test".to_string(),
                email_normalised: "taken@example.test".to_string(),
                ..account("01ACCOUNTSAVEDUPHOLDER0000")
            };
            db.save_account(&holder).await.unwrap();

            for (row, (email, email_normalised)) in [
                // The same address in both fields
                ("Ta.ken@example.test", "taken@example.test"),
                // The same normalised address behind another spelling
                ("taken+alias@example.test", "taken@example.test"),
                ("T.aken@example.test", "TAKEN@EXAMPLE.TEST"),
                // The same typed address, in the same and in another case
                ("Ta.ken@example.test", "other@example.test"),
                ("ta.KEN@example.test", "other@example.test"),
            ]
            .into_iter()
            .enumerate()
            {
                let id = format!("01ACCOUNTSAVEDUPSECOND000{row}");
                let second = Account {
                    email: email.to_string(),
                    email_normalised: email_normalised.to_string(),
                    ..account(&id)
                };

                let error = db
                    .save_account(&second)
                    .await
                    .expect_err("a second account under one address");
                assert!(
                    matches!(error.error_type, ErrorType::DatabaseError { .. }),
                    "{email} / {email_normalised}: {:?}",
                    error.error_type
                );
                assert!(
                    db.fetch_account(&id).await.is_err(),
                    "{email} / {email_normalised}: the refused account is stored"
                );
            }

            // An account that exists cannot be moved onto the address either,
            // and keeps what it had
            let mover = account("01ACCOUNTSAVEDUPMOVER00000");
            db.save_account(&mover).await.unwrap();
            let mut moved = mover.clone();
            moved.email = "TA.KEN@example.test".to_string();
            moved.password = "hash-changed".to_string();
            db.save_account(&moved)
                .await
                .expect_err("a move onto a held address");
            assert_eq!(db.fetch_account(&mover.id).await.unwrap(), mover);

            assert_eq!(db.fetch_account(&holder.id).await.unwrap(), holder);
            assert_eq!(
                db.fetch_account_by_normalised_email("taken@example.test")
                    .await
                    .unwrap()
                    .map(|found| found.id),
                Some(holder.id.clone())
            );
        });
    }

    /// Fails if: the duplicate check refuses an account its own address
    /// when it is saved again, refuses two accounts with no email (each has
    /// its own stand-in), or refuses a stale no-email copy whose address
    /// fields are not written anyway.
    #[tokio::test]
    async fn save_accepts_a_resave_and_accounts_with_no_email() {
        database_test!(|db| async move {
            db.migrate_database().await.expect("schema");

            let mut acct = Account {
                email: "Re.Save@example.test".to_string(),
                email_normalised: "resave@example.test".to_string(),
                ..account("01ACCOUNTSAVEDUPRESAVE0000")
            };
            db.save_account(&acct).await.unwrap();

            // Unchanged, then with another field changed, then with its own
            // address in another letter case
            db.save_account(&acct).await.unwrap();
            acct.password = "hash-changed".to_string();
            db.save_account(&acct).await.unwrap();
            acct.email = "RE.SAVE@example.test".to_string();
            db.save_account(&acct).await.unwrap();
            assert_eq!(db.fetch_account(&acct.id).await.unwrap(), acct);

            let first = no_email_account("01ACCOUNTSAVEDUPNOEMAIL001");
            let second = no_email_account("01ACCOUNTSAVEDUPNOEMAIL002");
            assert_ne!(first.email, second.email, "the control: two stand-ins");
            db.save_account(&first).await.unwrap();
            db.save_account(&second).await.unwrap();
            assert_eq!(db.fetch_account(&first.id).await.unwrap(), first);
            assert_eq!(db.fetch_account(&second.id).await.unwrap(), second);

            // A no-email copy that carries a held address in its fields: the
            // fields of a stored row are not written, so nothing clashes
            let mut stale = second.clone();
            stale.email = acct.email.clone();
            stale.email_normalised = acct.email_normalised.clone();
            stale.disabled = true;
            db.save_account(&stale).await.unwrap();
            assert_eq!(
                db.fetch_account(&second.id).await.unwrap(),
                Account {
                    disabled: true,
                    ..second.clone()
                }
            );
        });
    }

    /// Fails if: the write applies to an account that already has an email,
    /// to a deleted one, or reports success for an account that is not there.
    #[tokio::test]
    async fn first_email_is_refused_unless_the_account_has_none() {
        database_test!(|db| async move {
            db.migrate_database().await.expect("schema");

            let with_email = account("01ACCOUNTFIRSTEMAILHASONE0");
            db.save_account(&with_email).await.unwrap();

            let deleted = no_email_account("01ACCOUNTFIRSTEMAILDELETED");
            db.save_account(&deleted).await.unwrap();
            db.set_account_deletion(&deleted.id, Some(DeletionInfo::Deleted))
                .await
                .unwrap();
            let deleted = db.fetch_account(&deleted.id).await.unwrap();

            for acct in [&with_email, &deleted] {
                let applied = db
                    .set_account_email_if_absent(&acct.id, "new@example.test", "new@example.test")
                    .await
                    .unwrap();
                assert!(!applied, "{}", acct.id);
                assert_eq!(&db.fetch_account(&acct.id).await.unwrap(), acct);
            }

            assert!(!db
                .set_account_email_if_absent(
                    "01ACCOUNTMISSING0000000000",
                    "new@example.test",
                    "new@example.test"
                )
                .await
                .unwrap());
            assert!(db
                .fetch_account_by_normalised_email("new@example.test")
                .await
                .unwrap()
                .is_none());

            // The control: the same address goes to an account with none
            let absent = no_email_account("01ACCOUNTFIRSTEMAILABSENT0");
            db.save_account(&absent).await.unwrap();
            assert!(db
                .set_account_email_if_absent(&absent.id, "new@example.test", "new@example.test")
                .await
                .unwrap());
        });
    }

    /// Fails if: the sign-up rollback leaves the row, removes another
    /// account, or removes an account that has a password.
    #[tokio::test]
    async fn signup_rollback_removes_only_the_passkey_signup_row() {
        database_test!(|db| async move {
            let fresh = no_email_account("01ACCOUNTROLLBACKFRESH0000");
            let other = no_email_account("01ACCOUNTROLLBACKOTHER0000");
            let with_password = account("01ACCOUNTROLLBACKPASSWORD0");
            for acct in [&fresh, &other, &with_password] {
                db.save_account(acct).await.unwrap();
            }

            assert!(db.rollback_signup_account(&fresh.id).await.unwrap());
            let gone = db
                .fetch_account(&fresh.id)
                .await
                .expect_err("the row must be gone");
            assert!(
                matches!(gone.error_type, ErrorType::UnknownUser),
                "expected UnknownUser, got {:?}",
                gone.error_type
            );
            assert!(db
                .fetch_account_by_normalised_email(&fresh.email_normalised)
                .await
                .unwrap()
                .is_none());

            // Again, and for an id that never existed: nothing to remove
            assert!(!db.rollback_signup_account(&fresh.id).await.unwrap());
            assert!(!db
                .rollback_signup_account("01ACCOUNTMISSING0000000000")
                .await
                .unwrap());

            // An account with a password is never a sign-up to roll back
            assert!(!db.rollback_signup_account(&with_password.id).await.unwrap());
            assert_eq!(
                db.fetch_account(&with_password.id).await.unwrap(),
                with_password
            );
            assert_eq!(db.fetch_account(&other.id).await.unwrap(), other);
        });
    }
}
