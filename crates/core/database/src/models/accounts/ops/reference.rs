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
        let accounts = self.accounts.lock().await;
        accounts
            .values()
            .find(|account| {
                if let Some(DeletionInfo::WaitingForVerification { token, .. }) = &account.deletion
                {
                    token == token_to_match
                } else {
                    false
                }
            })
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

        // Lockout is written only through the lockout ops, so a stale
        // whole-document save cannot reset the counter. An update keeps the
        // stored lockout; an insert stores none, as the MongoDB driver does.
        account.lockout = accounts
            .get(&account.id)
            .and_then(|stored| stored.lockout.clone());

        accounts.insert(account.id.to_string(), account);
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
