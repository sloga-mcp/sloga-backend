use crate::{
    AbstractAccounts, Account, DeletionInfo, EmailVerification, Lockout, MongoDb, PasswordReset,
};
use bson::{to_bson, to_document, Bson, Document};
use iso8601_timestamp::{Duration, Timestamp};
use mongodb::options::{
    Collation, CollationStrength, FindOneAndUpdateOptions, FindOneOptions, ReturnDocument,
    UpdateOptions,
};
use revolt_result::Result;

const COL: &str = "accounts";

/// Serialise a timestamp the way `to_document` stores it: an ISO string,
/// which is the type the lockout filter compares against
fn timestamp_bson(at: Timestamp) -> Result<Bson> {
    to_bson(&at).map_err(|_| create_database_error!("to_bson", COL))
}

/// Update pipeline that counts one failed attempt
///
/// Stage 1 adds one to the count; a missing or null lockout counts as 0.
/// Stage 2 sets the expiry from the new count and keeps the stored expiry
/// when that count does not lock. The times are computed here, never with
/// `$$NOW`: a BSON date never compares to the stored strings, so the account
/// would stay locked forever.
fn lockout_attempt_pipeline(now: Timestamp) -> Result<Vec<Document>> {
    let one_minute = timestamp_bson(now + Duration::minutes(1))?;
    let five_minutes = timestamp_bson(now + Duration::minutes(5))?;
    let one_hour = timestamp_bson(now + Duration::hours(1))?;

    Ok(vec![
        doc! {
            "$set": {
                "lockout.attempts": {
                    "$add": [{ "$ifNull": ["$lockout.attempts", 0_i32] }, 1_i32]
                }
            }
        },
        doc! {
            "$set": {
                "lockout.expiry": {
                    "$switch": {
                        "branches": [
                            {
                                "case": { "$gte": ["$lockout.attempts", 5_i32] },
                                "then": one_hour
                            },
                            {
                                "case": { "$eq": ["$lockout.attempts", 4_i32] },
                                "then": five_minutes
                            },
                            {
                                "case": { "$eq": ["$lockout.attempts", 3_i32] },
                                "then": one_minute
                            }
                        ],
                        "default": { "$ifNull": ["$lockout.expiry", null] }
                    }
                }
            }
        },
    ])
}

fn return_after() -> FindOneAndUpdateOptions {
    FindOneAndUpdateOptions::builder()
        .return_document(ReturnDocument::After)
        .build()
}

/// Whether a write was refused by a unique index
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(
        *error.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) if write_error.code == 11000
    )
}

/// The collation of the unique `email` and `email_normalised` indexes
fn email_collation() -> Collation {
    Collation::builder()
        .locale("en")
        .strength(CollationStrength::Secondary)
        .build()
}

/// `$set` the given fields of one account, and nothing else
async fn set_account_fields(db: &MongoDb, id: &str, fields: Document) -> Result<()> {
    update_account(db, id, doc! { "$set": fields }).await
}

/// Apply one update to one account; `UnknownUser` if it does not exist
async fn update_account(db: &MongoDb, id: &str, update: Document) -> Result<()> {
    let result = db
        .col::<Account>(COL)
        .update_one(doc! { "_id": id }, update)
        .await
        .map_err(|_| create_database_error!("update_one", COL))?;

    if result.matched_count == 0 {
        Err(create_error!(UnknownUser))
    } else {
        Ok(())
    }
}

#[async_trait]
impl AbstractAccounts for MongoDb {
    /// Find account by id
    async fn fetch_account(&self, id: &str) -> Result<Account> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(UnknownUser))
    }

    /// Find account by normalised email
    async fn fetch_account_by_normalised_email(
        &self,
        normalised_email: &str,
    ) -> Result<Option<Account>> {
        query!(
            self,
            find_one_with_options,
            COL,
            doc! {
                "email_normalised": normalised_email
            },
            FindOneOptions::builder()
                .collation(
                    Collation::builder()
                        .locale("en")
                        .strength(CollationStrength::Secondary)
                        .build(),
                )
                .build()
        )
    }

    /// Find account by linked Google account id
    async fn fetch_account_by_google_id(&self, google_id: &str) -> Result<Option<Account>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "google_id": google_id
            }
        )
    }

    /// Find account by linked Apple user id
    async fn fetch_account_by_apple_id(&self, apple_id: &str) -> Result<Option<Account>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "apple_id": apple_id
            }
        )
    }

    /// Find account with active pending email verification
    async fn fetch_account_with_email_verification(&self, token: &str) -> Result<Account> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "verification.token": token,
                "verification.expiry": {
                    "$gte": to_bson(&Timestamp::now_utc()).unwrap()
                }
            }
        )?
        .ok_or_else(|| create_error!(InvalidToken))
    }

    /// Find account with active password reset
    async fn fetch_account_with_password_reset(&self, token: &str) -> Result<Account> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "password_reset.token": token,
                "password_reset.expiry": {
                    "$gte": to_bson(&Timestamp::now_utc()).unwrap()
                }
            }
        )?
        .ok_or_else(|| create_error!(InvalidToken))
    }

    /// Find account with active deletion token
    async fn fetch_account_with_deletion_token(&self, token: &str) -> Result<Account> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "deletion.token": token,
                "deletion.expiry": {
                    "$gte": to_bson(&Timestamp::now_utc()).unwrap()
                }
            }
        )?
        .ok_or_else(|| create_error!(InvalidToken))
    }

    /// Find accounts which are due to be deleted
    async fn fetch_accounts_due_for_deletion(&self) -> Result<Vec<Account>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "deletion.status": "Scheduled",
                "deletion.after": {
                    "$lte": to_bson(&Timestamp::now_utc()).unwrap()
                }
            }
        )
    }

    // Save account
    async fn save_account(&self, account: &Account) -> Result<()> {
        let mut document =
            to_document(account).map_err(|_| create_database_error!("to_document", COL))?;

        // Lockout is written only through the lockout ops, so a stale
        // whole-document save cannot reset the counter
        document.remove("lockout");

        // Deletion is written only through the deletion ops, so a stale
        // whole-document save cannot cancel or revive a deletion. An insert
        // stores none.
        document.remove("deletion");

        // A copy that says "no email" never writes the email fields of a row
        // that exists: it may have been loaded before the first-email op
        // gave the account its address, and would put the stand-in back. An
        // insert still stores them.
        let mut update = Document::new();
        if account.email_absent {
            let mut on_insert = Document::new();
            for key in ["email", "email_normalised", "email_absent"] {
                if let Some(value) = document.remove(key) {
                    on_insert.insert(key, value);
                }
            }
            update.insert("$setOnInsert", on_insert);
        }
        update.insert("$set", document);

        self.col::<Account>(COL)
            .update_one(
                doc! {
                    "_id": &account.id
                },
                update,
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await
            .map_err(|_| create_database_error!("find_one", COL))
            .map(|_| ())
    }

    /// Overwrite the deletion state, and nothing else
    async fn set_account_deletion(&self, id: &str, deletion: Option<DeletionInfo>) -> Result<()> {
        let update = match deletion {
            Some(deletion) => {
                let deletion =
                    to_bson(&deletion).map_err(|_| create_database_error!("to_bson", COL))?;
                doc! { "$set": { "deletion": deletion } }
            }
            None => doc! { "$unset": { "deletion": "" } },
        };

        update_account(self, id, update).await
    }

    /// Atomically store a new deletion request
    async fn request_account_deletion(&self, id: &str, deletion: DeletionInfo) -> Result<()> {
        let deletion = to_bson(&deletion).map_err(|_| create_database_error!("to_bson", COL))?;

        // Every condition is in the filter, so a request landing after a
        // confirm's claim (Scheduled and disabled in one write) matches
        // nothing. The null arm also matches a key stored as an explicit
        // null, which whole-document saves wrote before `save_account`
        // stopped writing `deletion`.
        let result = self
            .col::<Account>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "disabled": {
                        "$ne": true
                    },
                    "$or": [
                        { "deletion": { "$exists": false } },
                        { "deletion": null },
                        { "deletion.status": "WaitingForVerification" }
                    ]
                },
                doc! {
                    "$set": {
                        "deletion": deletion
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))?;

        // A missing account cannot be told apart from a refused one here
        if result.matched_count == 0 {
            Err(create_error!(InvalidOperation))
        } else {
            Ok(())
        }
    }

    /// Atomically confirm a pending deletion
    async fn claim_account_deletion(&self, token: &str) -> Result<Account> {
        let now = Timestamp::now_utc();
        let scheduled = to_bson(&DeletionInfo::Scheduled { after: now })
            .map_err(|_| create_database_error!("to_bson", COL))?;

        // Every condition is in the filter, so a second claim, a racing
        // cancel or an expired token matches nothing. The expiry compares
        // ISO strings, as `fetch_account_with_deletion_token` does.
        self.col::<Account>(COL)
            .find_one_and_update(
                doc! {
                    "deletion.status": "WaitingForVerification",
                    "deletion.token": token,
                    "deletion.expiry": {
                        "$gte": timestamp_bson(now)?
                    },
                    "disabled": {
                        "$ne": true
                    }
                },
                doc! {
                    "$set": {
                        "deletion": scheduled,
                        "disabled": true
                    }
                },
            )
            .with_options(return_after())
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))?
            .ok_or_else(|| create_error!(InvalidToken))
    }

    /// Atomically cancel a pending deletion
    async fn cancel_account_deletion(&self, account_id: &str) -> Result<Option<DeletionInfo>> {
        // Conditional on the status, so a claimed (Scheduled) or Deleted
        // account is never touched
        let previous = self
            .col::<Account>(COL)
            .find_one_and_update(
                doc! {
                    "_id": account_id,
                    "deletion.status": "WaitingForVerification"
                },
                doc! {
                    "$unset": {
                        "deletion": ""
                    }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .return_document(ReturnDocument::Before)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))?;

        Ok(previous.and_then(|account| account.deletion))
    }

    /// Remove the linked Google and Apple ids, and nothing else
    async fn unlink_account_oauth(&self, id: &str) -> Result<()> {
        // `$unset`: `save_account` leaves a `None` id out of its `$set`
        // (`skip_serializing_if`), so it can never clear one. Matching (not
        // modifying) is the success test, so an account with neither id is
        // `Ok` and a retry is harmless.
        update_account(
            self,
            id,
            doc! {
                "$unset": {
                    "google_id": "",
                    "apple_id": ""
                }
            },
        )
        .await
    }

    /// Atomically count one failed attempt, with no lock check
    async fn bump_lockout_count(&self, id: &str) -> Result<Account> {
        self.col::<Account>(COL)
            .find_one_and_update(
                doc! {
                    "_id": id
                },
                lockout_attempt_pipeline(Timestamp::now_utc())?,
            )
            .with_options(return_after())
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))?
            .ok_or_else(|| create_error!(UnknownUser))
    }

    /// Atomically reserve one attempt on an account that is not locked
    async fn reserve_lockout_attempt(&self, id: &str) -> Result<Account> {
        let now = Timestamp::now_utc();
        let now_bson = timestamp_bson(now)?;

        // The null arm matches a missing lockout, `lockout: null` and
        // `expiry: null`. A locked account matches nothing and is left as it
        // is, so a refused attempt never extends the lockout.
        self.col::<Account>(COL)
            .find_one_and_update(
                doc! {
                    "_id": id,
                    "$or": [
                        { "lockout.expiry": null },
                        { "lockout.expiry": { "$lte": now_bson } }
                    ]
                },
                lockout_attempt_pipeline(now)?,
            )
            .with_options(return_after())
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))?
            .ok_or_else(|| create_error!(LockedOut))
    }

    /// Overwrite the lockout, and nothing else
    async fn set_lockout(&self, id: &str, lockout: Option<Lockout>) -> Result<()> {
        let lockout = to_bson(&lockout).map_err(|_| create_database_error!("to_bson", COL))?;
        set_account_fields(self, id, doc! { "lockout": lockout }).await
    }

    /// Atomically remove one recovery code
    async fn consume_recovery_code(&self, id: &str, code: &str) -> Result<()> {
        // The code is in the filter, so of two racing requests only one can
        // match and modify the document
        let result = self
            .col::<Account>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "mfa.recovery_codes": code
                },
                doc! {
                    "$pull": {
                        "mfa.recovery_codes": code
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))?;

        if result.modified_count == 1 {
            Ok(())
        } else {
            Err(create_error!(InvalidToken))
        }
    }

    /// Overwrite the password reset, and nothing else
    async fn set_password_reset(&self, id: &str, reset: Option<PasswordReset>) -> Result<()> {
        let reset = to_bson(&reset).map_err(|_| create_database_error!("to_bson", COL))?;
        set_account_fields(self, id, doc! { "password_reset": reset }).await
    }

    /// Overwrite the email verification, and nothing else
    async fn set_email_verification(
        &self,
        id: &str,
        verification: &EmailVerification,
    ) -> Result<()> {
        let verification =
            to_bson(verification).map_err(|_| create_database_error!("to_bson", COL))?;
        set_account_fields(self, id, doc! { "verification": verification }).await
    }

    /// Atomically give an account that has no email its first address
    async fn set_account_email_if_absent(
        &self,
        id: &str,
        email: &str,
        email_normalised: &str,
    ) -> Result<bool> {
        // Looked up first so the common refusal is not a failed write, and
        // so a database without the indexes still refuses. It is the unique
        // indexes, in the write below, that settle two requests racing for
        // one address.
        let holder = self
            .col::<Document>(COL)
            .find_one(doc! {
                "_id": { "$ne": id },
                "$or": [
                    { "email": email },
                    { "email_normalised": email_normalised }
                ]
            })
            .with_options(
                FindOneOptions::builder()
                    .collation(email_collation())
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one", COL))?;

        if holder.is_some() {
            return Ok(false);
        }

        // Every condition is in the filter: an account that gained an email
        // or was deleted since it was read matches nothing. `$ne` also
        // matches an account with no `deletion` key.
        let result = self
            .col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "email_absent": true,
                    "deletion.status": { "$ne": "Deleted" }
                },
                doc! {
                    "$set": {
                        "email": email,
                        "email_normalised": email_normalised,
                        "email_absent": false
                    }
                },
            )
            .await;

        match result {
            Ok(result) => Ok(result.matched_count == 1),
            // Another account took the address between the lookup and here
            Err(error) if is_duplicate_key(&error) => Ok(false),
            Err(_) => Err(create_database_error!("update_one", COL)),
        }
    }

    /// Undo a failed sign-up: remove the account row it just inserted
    async fn rollback_signup_account(&self, id: &str) -> Result<bool> {
        // `password_absent` is in the filter, so this can never remove an
        // account that has a password
        self.col::<Document>(COL)
            .delete_one(doc! {
                "_id": id,
                "password_absent": true
            })
            .await
            .map(|result| result.deleted_count == 1)
            .map_err(|_| create_database_error!("delete_one", COL))
    }
}
