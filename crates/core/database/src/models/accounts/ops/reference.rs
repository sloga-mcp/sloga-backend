use crate::{
    AbstractAccounts, Account, DeletionInfo, EmailVerification, Lockout, PasswordReset,
    ReferenceDb,
};
use iso8601_timestamp::{Duration, Timestamp};
use revolt_result::Result;

#[async_trait]
impl AbstractAccounts for ReferenceDb {
    /// Find account by id
    async fn fetch_account(&self, id: &str) -> Result<Account> {
        let accounts = self.accounts.lock().await;
        accounts
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(UnknownUser))
    }

    /// Find account by normalised email
    async fn fetch_account_by_normalised_email(
        &self,
        normalised_email: &str,
    ) -> Result<Option<Account>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts
            .values()
            .find(|account| account.email_normalised == normalised_email)
            .cloned())
    }

    /// Find account by linked Google account id
    async fn fetch_account_by_google_id(&self, google_id: &str) -> Result<Option<Account>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts
            .values()
            .find(|account| account.google_id.as_deref() == Some(google_id))
            .cloned())
    }

    /// Find account by linked Apple user id
    async fn fetch_account_by_apple_id(&self, apple_id: &str) -> Result<Option<Account>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts
            .values()
            .find(|account| account.apple_id.as_deref() == Some(apple_id))
            .cloned())
    }

    /// Find account with active pending email verification
    async fn fetch_account_with_email_verification(&self, token_to_match: &str) -> Result<Account> {
        let accounts = self.accounts.lock().await;
        accounts
            .values()
            .find(|account| match &account.verification {
                EmailVerification::Pending { token, .. }
                | EmailVerification::Moving { token, .. } => token == token_to_match,
                _ => false,
            })
            .cloned()
            .ok_or_else(|| create_error!(InvalidToken))
    }

    /// Find account with active password reset
    async fn fetch_account_with_password_reset(&self, token: &str) -> Result<Account> {
        let accounts = self.accounts.lock().await;
        accounts
            .values()
            .find(|account| {
                if let Some(reset) = &account.password_reset {
                    reset.token == token
                } else {
                    false
                }
            })
            .cloned()
            .ok_or_else(|| create_error!(InvalidToken))
    }

    /// Find account with active deletion token
    async fn fetch_account_with_deletion_token(&self, token_to_match: &str) -> Result<Account> {
        let now = Timestamp::now_utc();
        let accounts = self.accounts.lock().await;
        accounts
            .values()
            .find(|account| pending_deletion_matches(account, token_to_match, now))
            .cloned()
            .ok_or_else(|| create_error!(InvalidToken))
    }

    /// Find accounts which are due to be deleted
    async fn fetch_accounts_due_for_deletion(&self) -> Result<Vec<Account>> {
        let now = Timestamp::now_utc();
        let accounts = self.accounts.lock().await;

        Ok(accounts
            .values()
            .filter(|account| {
                if let Some(DeletionInfo::Scheduled { after }) = &account.deletion {
                    after <= &now
                } else {
                    false
                }
            })
            .cloned()
            .collect())
    }

    // Save account
    async fn save_account(&self, account: &Account) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        let mut account = account.clone();

        // Lockout and deletion are written only through their own ops, so a
        // stale whole-document save can neither reset the counter nor
        // cancel or revive a deletion. An update keeps the stored values; an
        // insert stores none, as the MongoDB driver (which leaves both out of
        // its upsert `$set`) does.
        let stored = accounts.get(&account.id);
        account.lockout = stored.and_then(|stored| stored.lockout.clone());
        account.deletion = stored.and_then(|stored| stored.deletion.clone());

        // A copy that says "no email" never writes the email fields of a row
        // that exists: it may have been loaded before the first-email op
        // gave the account its address, and would put the stand-in back. An
        // insert still stores them, as the MongoDB driver's `$setOnInsert`
        // does.
        if account.email_absent {
            if let Some(stored) = stored {
                account.email = stored.email.clone();
                account.email_normalised = stored.email_normalised.clone();
                account.email_absent = stored.email_absent;
            }
        }

        // The MongoDB driver's two unique email indexes: a save that would
        // give this account an address another account holds, in either
        // field, fails with the error that driver's write gives, and stores
        // nothing.
        let taken = accounts.values().any(|other| {
            other.id != account.id
                && (same_address(&other.email, &account.email)
                    || same_address(&other.email_normalised, &account.email_normalised))
        });
        if taken {
            return Err(create_database_error!("find_one", "accounts"));
        }

        accounts.insert(account.id.to_string(), account);
        Ok(())
    }

    /// Overwrite the deletion state, and nothing else
    async fn set_account_deletion(&self, id: &str, deletion: Option<DeletionInfo>) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(UnknownUser))?;

        account.deletion = deletion;
        Ok(())
    }

    /// Atomically store a new deletion request
    async fn request_account_deletion(&self, id: &str, deletion: DeletionInfo) -> Result<()> {
        let mut accounts = self.accounts.lock().await;

        // A missing account is `InvalidOperation` too, not `UnknownUser`: the
        // MongoDB filter cannot tell it apart from a refused one, and the
        // drivers must agree. The caller has loaded the account already.
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(InvalidOperation))?;

        // The same conditions as the MongoDB filter, checked and applied
        // under one lock
        let open = matches!(
            account.deletion,
            None | Some(DeletionInfo::WaitingForVerification { .. })
        );

        if account.disabled || !open {
            return Err(create_error!(InvalidOperation));
        }

        account.deletion = Some(deletion);
        Ok(())
    }

    /// Atomically confirm a pending deletion
    async fn claim_account_deletion(&self, token: &str) -> Result<Account> {
        let now = Timestamp::now_utc();
        let mut accounts = self.accounts.lock().await;

        // The same conditions as the MongoDB filter, checked and applied
        // under one lock
        let account = accounts
            .values_mut()
            .find(|account| !account.disabled && pending_deletion_matches(account, token, now))
            .ok_or_else(|| create_error!(InvalidToken))?;

        account.deletion = Some(DeletionInfo::Scheduled { after: now });
        account.disabled = true;
        Ok(account.clone())
    }

    /// Atomically cancel a pending deletion
    async fn cancel_account_deletion(&self, account_id: &str) -> Result<Option<DeletionInfo>> {
        let mut accounts = self.accounts.lock().await;
        let Some(account) = accounts.get_mut(account_id) else {
            return Ok(None);
        };

        // Only a pending deletion is cancelled; Scheduled and Deleted stay
        if matches!(
            account.deletion,
            Some(DeletionInfo::WaitingForVerification { .. })
        ) {
            Ok(account.deletion.take())
        } else {
            Ok(None)
        }
    }

    /// Remove the linked Google and Apple ids, and nothing else
    async fn unlink_account_oauth(&self, id: &str) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(UnknownUser))?;

        account.google_id = None;
        account.apple_id = None;
        Ok(())
    }

    /// Atomically count one failed attempt, with no lock check
    async fn bump_lockout_count(&self, id: &str) -> Result<Account> {
        let mut accounts = self.accounts.lock().await;
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(UnknownUser))?;

        count_lockout_attempt(account, Timestamp::now_utc());
        Ok(account.clone())
    }

    /// Atomically reserve one attempt on an account that is not locked
    async fn reserve_lockout_attempt(&self, id: &str) -> Result<Account> {
        let now = Timestamp::now_utc();
        let mut accounts = self.accounts.lock().await;

        // A missing account is `LockedOut` too: the MongoDB filter cannot
        // tell it apart from a locked one, and the drivers must agree
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(LockedOut))?;

        // Refuse without any change, so a refused attempt never extends the
        // lockout
        if let Some(Lockout {
            expiry: Some(expiry),
            ..
        }) = &account.lockout
        {
            if *expiry > now {
                return Err(create_error!(LockedOut));
            }
        }

        count_lockout_attempt(account, now);
        Ok(account.clone())
    }

    /// Overwrite the lockout, and nothing else
    async fn set_lockout(&self, id: &str, lockout: Option<Lockout>) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(UnknownUser))?;

        account.lockout = lockout;
        Ok(())
    }

    /// Atomically remove one recovery code
    async fn consume_recovery_code(&self, id: &str, code: &str) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(InvalidToken))?;

        if !account.mfa.recovery_codes.iter().any(|stored| stored == code) {
            return Err(create_error!(InvalidToken));
        }

        // Every copy goes, as with MongoDB's `$pull`
        account.mfa.recovery_codes.retain(|stored| stored != code);
        Ok(())
    }

    /// Overwrite the password reset, and nothing else
    async fn set_password_reset(&self, id: &str, reset: Option<PasswordReset>) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(UnknownUser))?;

        account.password_reset = reset;
        Ok(())
    }

    /// Overwrite the email verification, and nothing else
    async fn set_email_verification(
        &self,
        id: &str,
        verification: &EmailVerification,
    ) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| create_error!(UnknownUser))?;

        account.verification = verification.clone();
        Ok(())
    }

    /// Atomically give an account that has no email its first address
    async fn set_account_email_if_absent(
        &self,
        id: &str,
        email: &str,
        email_normalised: &str,
    ) -> Result<bool> {
        // The same conditions as the MongoDB filter and its two unique
        // indexes, checked and applied under one lock
        let mut accounts = self.accounts.lock().await;

        let taken = accounts.values().any(|other| {
            other.id != id
                && (same_address(&other.email, email)
                    || same_address(&other.email_normalised, email_normalised))
        });
        if taken {
            return Ok(false);
        }

        match accounts.get_mut(id) {
            Some(account)
                if account.email_absent
                    && !matches!(account.deletion, Some(DeletionInfo::Deleted)) =>
            {
                account.email = email.to_string();
                account.email_normalised = email_normalised.to_string();
                account.email_absent = false;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Undo a failed sign-up: remove the account row it just inserted
    async fn rollback_signup_account(&self, id: &str) -> Result<bool> {
        let mut accounts = self.accounts.lock().await;

        // As the MongoDB filter: never an account that has a password
        if accounts.get(id).is_some_and(|account| account.password_absent) {
            accounts.remove(id);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Whether two addresses are the same to the unique email indexes, which
/// ignore letter case (collation strength 2)
fn same_address(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// Whether the account holds a pending deletion with this token that has not
/// expired. The expiry is inclusive, as MongoDB's `$gte` is.
fn pending_deletion_matches(account: &Account, token_to_match: &str, now: Timestamp) -> bool {
    matches!(
        &account.deletion,
        Some(DeletionInfo::WaitingForVerification { token, expiry })
            if token == token_to_match && *expiry >= now
    )
}

/// Count one failed attempt and set the expiry from the new count `n`:
/// `n >= 5` locks for 1 hour, `n == 4` for 5 minutes, `n == 3` for 1 minute,
/// and any other count keeps the current expiry
fn count_lockout_attempt(account: &mut Account, now: Timestamp) {
    let attempts = account
        .lockout
        .as_ref()
        .map(|lockout| lockout.attempts)
        .unwrap_or(0)
        .saturating_add(1);

    let expiry = if attempts >= 5 {
        Some(now + Duration::hours(1))
    } else if attempts == 4 {
        Some(now + Duration::minutes(5))
    } else if attempts == 3 {
        Some(now + Duration::minutes(1))
    } else {
        account.lockout.as_ref().and_then(|lockout| lockout.expiry)
    };

    account.lockout = Some(Lockout { attempts, expiry });
}
