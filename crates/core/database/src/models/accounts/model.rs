use iso8601_timestamp::{Duration, Timestamp};

use nanoid::nanoid;
use revolt_config::config;
use revolt_result::Result;
use serde_json::json;

use crate::{
    events::client::EventV1,
    util::{
        email::{email_templates, normalise_email, send_email},
        password::hash_password,
    },
    Database, MFATicket, Session, MFA_TICKET_MAX_ATTEMPTS,
};
use revolt_models::v0;

auto_derived_partial!(
    /// Account model
    pub struct Account {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,

        /// User's email
        pub email: String,

        /// Normalised email
        ///
        /// (see https://github.com/insertish/authifier/#how-does-authifier-work)
        pub email_normalised: String,

        /// Argon2 hashed password
        pub password: String,

        /// Whether the account is disabled
        #[serde(default)]
        pub disabled: bool,

        /// Email verification status
        pub verification: EmailVerification,

        /// Password reset information
        pub password_reset: Option<PasswordReset>,

        /// Account deletion information
        pub deletion: Option<DeletionInfo>,

        /// Account lockout
        ///
        /// Written only by the lockout ops, never by `save_account`
        #[serde(default)]
        pub lockout: Option<Lockout>,

        /// Multi-factor authentication information
        pub mfa: MultiFactorAuthentication,

        /// Google account id, if this account is linked to Google OAuth
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub google_id: Option<String>,

        /// Apple user id (id_token `sub`), if linked to Sign in with Apple
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub apple_id: Option<String>,
    },
    "PartialAccount"
);

auto_derived!(
    /// Email verification status
    #[serde(tag = "status")]
    pub enum EmailVerification {
        /// Account is verified
        Verified,
        /// Pending email verification
        Pending { token: String, expiry: Timestamp },
        /// Moving to a new email
        Moving {
            new_email: String,
            token: String,
            expiry: Timestamp,
        },
    }

    /// Password reset information
    pub struct PasswordReset {
        /// Token required to change password
        pub token: String,
        /// Time at which this token expires
        pub expiry: Timestamp,
    }

    /// Account deletion information
    #[serde(tag = "status")]
    pub enum DeletionInfo {
        /// The user must confirm deletion by email
        WaitingForVerification { token: String, expiry: Timestamp },
        /// The account is scheduled for deletion
        Scheduled { after: Timestamp },
        /// This account was deleted
        Deleted,
    }

    /// Lockout information
    pub struct Lockout {
        /// Attempt counter
        pub attempts: i32,
        /// Time at which this lockout expires
        pub expiry: Option<Timestamp>,
    }

    /// MFA configuration
    #[derive(Default)]
    pub struct MultiFactorAuthentication {
        /// Allow password-less email OTP login
        /// (1-Factor)
        // #[serde(skip_serializing_if = "is_false", default)]
        // pub enable_email_otp: bool,

        /// Allow trusted handover
        /// (1-Factor)
        // #[serde(skip_serializing_if = "is_false", default)]
        // pub enable_trusted_handover: bool,

        /// Allow email MFA
        /// (2-Factor)
        // #[serde(skip_serializing_if = "is_false", default)]
        // pub enable_email_mfa: bool,

        /// TOTP MFA token, enabled if present
        /// (2-Factor)
        #[serde(skip_serializing_if = "Totp::is_empty", default)]
        pub totp_token: Totp,

        /// Security Key MFA token, enabled if present
        /// (2-Factor)
        // #[serde(skip_serializing_if = "Option::is_none")]
        // pub security_key_token: Option<String>,

        /// Recovery codes
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub recovery_codes: Vec<String>,
    }

    /// MFA method
    #[derive(Hash)]
    pub enum MFAMethod {
        Password,
        Recovery,
        Totp,
    }

    #[derive(Default)]
    #[serde(tag = "status")]
    pub enum Totp {
        /// Disabled
        #[default]
        Disabled,
        /// Waiting for user activation
        Pending { secret: String },
        /// Required on account
        Enabled { secret: String },
    }
);

impl MultiFactorAuthentication {
    // Check whether MFA is in-use
    pub fn is_active(&self) -> bool {
        matches!(self.totp_token, Totp::Enabled { .. })
    }

    // Check whether there are still usable recovery codes
    pub fn has_recovery(&self) -> bool {
        !self.recovery_codes.is_empty()
    }

    // Get available MFA methods
    pub fn get_methods(&self) -> Vec<MFAMethod> {
        if let Totp::Enabled { .. } = self.totp_token {
            let mut methods = vec![MFAMethod::Totp];

            if self.has_recovery() {
                methods.push(MFAMethod::Recovery);
            }

            methods
        } else {
            vec![MFAMethod::Password]
        }
    }

    // Generate new recovery codes
    pub fn generate_recovery_codes(&mut self) {
        static ALPHABET: [char; 32] = [
            '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
            'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z',
        ];

        let mut codes = vec![];
        for _ in 1..=10 {
            codes.push(format!(
                "{}-{}",
                nanoid!(5, &ALPHABET),
                nanoid!(5, &ALPHABET)
            ));
        }

        self.recovery_codes = codes;
    }

    // Generate new TOTP secret
    pub fn generate_new_totp_secret(&mut self) -> Result<String> {
        if let Totp::Enabled { .. } = self.totp_token {
            return Err(create_error!(OperationFailed));
        }

        let secret: [u8; 10] = rand::random();
        let secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret);

        self.totp_token = Totp::Pending {
            secret: secret.clone(),
        };

        Ok(secret)
    }

    /// Enable TOTP using a given MFA response
    pub fn enable_totp(&mut self, response: v0::MFAResponse) -> Result<()> {
        if let v0::MFAResponse::Totp { totp_code } = response {
            let code = self.totp_token.generate_code()?;

            if code == totp_code {
                let mut totp = Totp::Disabled;
                std::mem::swap(&mut totp, &mut self.totp_token);

                if let Totp::Pending { secret } = totp {
                    self.totp_token = Totp::Enabled { secret };

                    Ok(())
                } else {
                    Err(create_error!(OperationFailed))
                }
            } else {
                Err(create_error!(InvalidToken))
            }
        } else {
            Err(create_error!(InvalidToken))
        }
    }
}

impl Totp {
    /// Whether TOTP information is empty
    pub fn is_empty(&self) -> bool {
        matches!(self, Totp::Disabled)
    }

    /// Whether TOTP is disabled
    pub fn is_disabled(&self) -> bool {
        !matches!(self, Totp::Enabled { .. })
    }

    // Generate a TOTP code from secret
    pub fn generate_code(&self) -> Result<String> {
        if let Totp::Enabled { secret } | Totp::Pending { secret } = &self {
            let seconds: u64 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            Ok(totp_lite::totp_custom::<totp_lite::Sha1>(
                totp_lite::DEFAULT_STEP,
                6,
                &base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
                    .expect("valid base32 secret"),
                seconds,
            ))
        } else {
            Err(create_error!(OperationFailed))
        }
    }
}

impl Account {
    /// Save model
    pub async fn save(&self, db: &Database) -> Result<()> {
        db.save_account(self).await
    }

    /// Create a new account
    pub async fn new(
        db: &Database,
        email: String,
        plaintext_password: String,
        verify_email: bool,
    ) -> Result<Account> {
        // Get a normalised representation of the user's email
        let email_normalised = normalise_email(email.clone());

        // Try to find an existing account
        if let Some(mut account) = db
            .fetch_account_by_normalised_email(&email_normalised)
            .await?
        {
            // Resend account verification or send password reset
            if let EmailVerification::Pending { .. } = &account.verification {
                account.start_email_verification(db).await?;
            } else {
                account.start_password_reset(db, true).await?;
            }

            Ok(account)
        } else {
            // Hash the user's password
            let password = hash_password(plaintext_password)?;

            // Create a new account
            let mut account = Account {
                id: ulid::Ulid::new().to_string(),

                email,
                email_normalised,
                password,

                disabled: false,
                verification: EmailVerification::Verified,
                password_reset: None,
                deletion: None,
                lockout: None,

                mfa: Default::default(),
                google_id: None,
                apple_id: None,
            };

            // Send email verification, then insert the account; the
            // targeted write in `start_email_verification` needs an
            // existing document, so the first write here stays a full save
            if verify_email {
                account.prepare_email_verification().await?;
            }

            account.save(db).await?;

            // Create and push event
            EventV1::CreateAccount {
                account: account.clone(),
            }
            .global()
            .await;

            Ok(account)
        }
    }

    /// Create a new account from a verified Google OAuth identity
    ///
    /// Unlike [`Account::new`], this never sends emails and never touches
    /// existing accounts — callers must have already checked for a match.
    /// The password is random and unusable; the password reset flow can
    /// set a real one later.
    pub async fn new_from_google(
        db: &Database,
        email: String,
        google_id: String,
    ) -> Result<Account> {
        Account::new_from_oauth(db, email, Some(google_id), None).await
    }

    /// Create a new account from a verified Sign in with Apple identity
    ///
    /// Same contract as [`Account::new_from_google`].
    pub async fn new_from_apple(
        db: &Database,
        email: String,
        apple_id: String,
    ) -> Result<Account> {
        Account::new_from_oauth(db, email, None, Some(apple_id)).await
    }

    /// Shared OAuth account construction
    async fn new_from_oauth(
        db: &Database,
        email: String,
        google_id: Option<String>,
        apple_id: Option<String>,
    ) -> Result<Account> {
        let email_normalised = normalise_email(email.clone());
        let password = hash_password(nanoid!(64))?;

        let account = Account {
            id: ulid::Ulid::new().to_string(),

            email,
            email_normalised,
            password,

            disabled: false,
            verification: EmailVerification::Verified,
            password_reset: None,
            deletion: None,
            lockout: None,

            mfa: Default::default(),
            google_id,
            apple_id,
        };

        account.save(db).await?;

        EventV1::CreateAccount {
            account: account.clone(),
        }
        .global()
        .await;

        Ok(account)
    }

    /// Create a new session
    pub async fn create_session(&self, db: &Database, name: String) -> Result<Session> {
        let config = config().await;

        let session = Session {
            id: ulid::Ulid::new().to_string(),
            token: nanoid!(64),

            user_id: self.id.clone(),
            name,

            last_seen: Timestamp::now_utc(),

            origin: Some(config.environment),
            subscription: None,
        };

        // Save to database
        db.save_session(&session).await?;

        // Create and push event
        EventV1::CreateSession {
            session: session.clone(),
        }
        .global()
        .await;

        Ok(session)
    }

    /// Send account verification email
    ///
    /// Writes only `verification`, so a stale copy cannot revert other fields
    pub async fn start_email_verification(&mut self, db: &Database) -> Result<()> {
        self.prepare_email_verification().await?;
        db.set_email_verification(&self.id, &self.verification).await
    }

    /// Send the verification email and update `verification` in memory
    async fn prepare_email_verification(&mut self) -> Result<()> {
        let config = config().await;

        if !config.api.smtp.host.is_empty() {
            let templates = email_templates().await;

            let token = nanoid!(32);
            let url = format!("{}{}", templates.verify.url, token);

            send_email(
                &config.api.smtp,
                self.email.clone(),
                &templates.verify,
                json!({
                    "email": self.email.clone(),
                    "url": url
                }),
            )?;

            self.verification = EmailVerification::Pending {
                token,
                expiry: Timestamp::now_utc()
                    .checked_add(Duration::seconds(
                        config.api.smtp.expiry.expire_verification,
                    ))
                    .unwrap(),
            };
        } else {
            self.verification = EmailVerification::Verified;
        }

        Ok(())
    }

    /// Send account verification to new email
    pub async fn start_email_move(&mut self, db: &Database, new_email: String) -> Result<()> {
        // This method should and will never be called on an unverified account,
        // but just validate this just in case.
        if let EmailVerification::Pending { .. } = self.verification {
            return Err(create_error!(UnverifiedAccount));
        }

        let config = config().await;

        if !config.api.smtp.host.is_empty() {
            let templates = email_templates().await;

            let token = nanoid!(32);
            let url = format!("{}{}", templates.verify.url, token);

            send_email(
                &config.api.smtp,
                new_email.clone(),
                &templates.verify,
                json!({
                    "email": self.email.clone(),
                    "url": url
                }),
            )?;

            self.verification = EmailVerification::Moving {
                new_email,
                token,
                expiry: Timestamp::now_utc()
                    .checked_add(Duration::seconds(
                        config.api.smtp.expiry.expire_verification,
                    ))
                    .unwrap(),
            };

            // Write only `verification`, so a stale copy held across the
            // SMTP round trip cannot revert other fields
            db.set_email_verification(&self.id, &self.verification).await
        } else {
            self.email_normalised = normalise_email(new_email.clone());
            self.email = new_email;

            // No targeted op covers the email fields, and no SMTP round
            // trip happens on this branch
            self.save(db).await
        }
    }

    /// Send password reset email
    pub async fn start_password_reset(
        &mut self,
        db: &Database,
        existing_account: bool,
    ) -> Result<()> {
        let config = config().await;

        if !config.api.smtp.host.is_empty() {
            let templates = email_templates().await;

            let template = if existing_account {
                &templates.reset_existing
            } else {
                &templates.reset
            };

            let token = nanoid!(32);
            let url = format!("{}{}", template.url, token);

            send_email(
                &config.api.smtp,
                self.email.clone(),
                template,
                json!({
                    "email": self.email.clone(),
                    "url": url
                }),
            )?;

            self.password_reset = Some(PasswordReset {
                token,
                expiry: Timestamp::now_utc()
                    .checked_add(Duration::seconds(
                        config.api.smtp.expiry.expire_password_reset,
                    ))
                    .unwrap(),
            });
        } else {
            return Err(create_error!(OperationFailed));
        }

        // Write only `password_reset`, so a stale copy held across the SMTP
        // round trip cannot revert the password, MFA or lockout
        db.set_password_reset(&self.id, self.password_reset.clone()).await
    }

    /// Begin account deletion process by sending confirmation email
    ///
    /// If email verification is not on, the account will be marked for deletion instantly
    pub async fn start_account_deletion(&mut self, db: &Database) -> Result<()> {
        let config = config().await;

        if !config.api.smtp.host.is_empty() {
            let templates = email_templates().await;

            let token = nanoid!(32);
            let url = format!("{}{}", templates.deletion.url, token);

            send_email(
                &config.api.smtp,
                self.email.clone(),
                &templates.deletion,
                json!({
                    "email": self.email.clone(),
                    "url": url
                }),
            )?;

            self.deletion = Some(DeletionInfo::WaitingForVerification {
                token,
                expiry: Timestamp::now_utc()
                    .checked_add(Duration::seconds(
                        config.api.smtp.expiry.expire_password_reset,
                    ))
                    .unwrap(),
            });

            self.save(db).await
        } else {
            self.schedule_deletion(db).await
        }
    }

    /// Verify a user's password is correct
    pub fn verify_password(&self, plaintext_password: &str) -> Result<()> {
        argon2::verify_encoded(&self.password, plaintext_password.as_bytes())
            .map(|v| {
                if v {
                    Ok(())
                } else {
                    Err(create_error!(InvalidCredentials))
                }
            })
            // To prevent user enumeration, we should ignore
            // the error and pretend the password is wrong.
            .map_err(|_| create_error!(InvalidCredentials))?
    }

    /// Validate an MFA response
    ///
    /// One ticket attempt (if a ticket is given) and one account lockout
    /// attempt are counted atomically BEFORE the response is verified, so
    /// concurrent guesses never share a stale counter. A failure deletes a
    /// ticket that has used its last attempt. A success claims the ticket
    /// (single use), consumes the recovery code if one was used and clears
    /// the lockout. The account document is never saved whole here.
    pub async fn consume_mfa_response(
        &mut self,
        db: &Database,
        response: v0::MFAResponse,
        ticket: Option<&MFATicket>,
    ) -> Result<()> {
        // Count one attempt against the ticket, and check that the driver
        // returned this ticket and that it belongs to this account
        let ticket = if let Some(ticket) = ticket {
            let reserved = db.reserve_ticket_attempt(&ticket.id).await?;
            if reserved.id != ticket.id || reserved.account_id != self.id {
                return Err(create_error!(InvalidToken));
            }

            Some(reserved)
        } else {
            None
        };

        let recovery_code = match self.verify_mfa_attempt(db, response, ticket.as_ref()).await {
            Ok(recovery_code) => recovery_code,
            Err(error) => {
                // Burn a ticket that has no attempts left
                if let Some(ticket) = &ticket {
                    if ticket.attempts >= MFA_TICKET_MAX_ATTEMPTS {
                        let _ = db.delete_ticket(&ticket.id).await;
                    }
                }

                return Err(error);
            }
        };

        // Single use: a request that loses the race for the ticket fails here
        if let Some(ticket) = &ticket {
            ticket.claim(db).await?;
        }

        // Atomic, so two requests cannot both spend the same recovery code
        if let Some(code) = recovery_code {
            db.consume_recovery_code(&self.id, &code).await?;
            self.mfa.recovery_codes.retain(|x| x != &code);
        }

        db.set_lockout(&self.id, None).await?;
        self.lockout = None;

        Ok(())
    }

    /// Count one lockout attempt, then verify an MFA response
    ///
    /// Returns the recovery code to consume if the response used one. Writes
    /// nothing besides the lockout attempt; the caller handles the rest.
    async fn verify_mfa_attempt(
        &self,
        db: &Database,
        response: v0::MFAResponse,
        ticket: Option<&MFATicket>,
    ) -> Result<Option<String>> {
        db.reserve_lockout_attempt(&self.id).await?;

        let allowed_methods = self.mfa.get_methods();

        match response {
            v0::MFAResponse::Password { password } => {
                if allowed_methods.contains(&MFAMethod::Password) {
                    self.verify_password(&password).map(|_| None)
                } else {
                    Err(create_error!(DisallowedMFAMethod))
                }
            }
            v0::MFAResponse::Totp { totp_code } => {
                // `get_methods` only offers TOTP while it is enabled
                if !allowed_methods.contains(&MFAMethod::Totp)
                    || self.mfa.totp_token.is_disabled()
                {
                    return Err(create_error!(DisallowedMFAMethod));
                }

                // Use TOTP code at generation if applicable
                if let Some(code) = ticket.and_then(|ticket| ticket.last_totp_code.as_ref()) {
                    if code == &totp_code {
                        return Ok(None);
                    }
                }

                // Otherwise read current TOTP token
                if self.mfa.totp_token.generate_code()? == totp_code {
                    Ok(None)
                } else {
                    Err(create_error!(InvalidToken))
                }
            }
            v0::MFAResponse::Recovery { recovery_code } => {
                if allowed_methods.contains(&MFAMethod::Recovery) {
                    // Membership only; the code is consumed on success
                    if self.mfa.recovery_codes.contains(&recovery_code) {
                        Ok(Some(recovery_code))
                    } else {
                        Err(create_error!(InvalidToken))
                    }
                } else {
                    Err(create_error!(DisallowedMFAMethod))
                }
            }
        }
    }

    /// Delete all sessions for an account
    pub async fn delete_all_sessions(
        &self,
        db: &Database,
        exclude_session_id: Option<String>,
    ) -> Result<()> {
        db.delete_all_sessions(&self.id, exclude_session_id.clone())
            .await?;

        // E2EE devices die with their sessions: revoke every device except
        // those bound to the surviving session
        for identity in db.fetch_e2ee_identities(&self.id).await? {
            if exclude_session_id.as_deref() != Some(identity.last_session_id.as_str()) {
                crate::E2EEIdentity::revoke_device(db, &self.id, &identity.device_id).await?;
            }
        }

        // Create and push event
        EventV1::DeleteAllSessions {
            user_id: self.id.clone(),
            exclude_session_id,
        }
        .private(self.id.clone())
        .await;

        Ok(())
    }

    /// Disable an account
    pub async fn disable(&mut self, db: &Database) -> Result<()> {
        self.disabled = true;
        self.delete_all_sessions(db, None).await?;
        self.save(db).await
    }

    /// Schedule an account for deletion
    pub async fn schedule_deletion(&mut self, db: &Database) -> Result<()> {
        self.deletion = Some(DeletionInfo::Scheduled {
            after: Timestamp::now_utc()
                .checked_add(Duration::weeks(1))
                .unwrap(),
        });

        self.disable(db).await
    }

    /// Removes all information from the account and marks it as fully deleted
    pub async fn mark_deleted(&mut self, db: &Database) -> Result<()> {
        self.email = format!("Deleted User {}", &self.id);
        self.email_normalised = format!("Deleted User {}", &self.id);
        self.deletion = Some(DeletionInfo::Deleted);

        self.save(db).await?;

        Ok(())
    }
}
