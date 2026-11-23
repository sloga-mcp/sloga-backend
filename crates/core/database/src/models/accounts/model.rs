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

        /// Whether the account has no usable password: it was created with a
        /// random one (OAuth) and none has been set since
        ///
        /// Always serialised: `save_account` writes a `$set`, which can only
        /// turn this off again if `false` is part of the document
        #[serde(default)]
        pub password_absent: bool,
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
        // Never returned by `get_methods`, so the login MFA step never offers it
        Passkey,
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

/// What an MFA response is being checked for
///
/// Every caller of [`Account::consume_mfa_response`] names one of these, and
/// the allowed methods follow from it. There is no default: a new caller has
/// to choose.
#[derive(Clone, Copy)]
pub enum MfaPurpose<'a> {
    /// The second step of a login, authorising this login ticket
    /// (`routes/session/login.rs`). Allowed methods are
    /// `account.mfa.get_methods()`, which never offers a passkey. One
    /// attempt is counted against the ticket, the code stored on it at
    /// creation is accepted, and a success claims it (single use).
    LoginStep(&'a MFATicket),
    /// Minting a validated ticket from a signed-in session, to confirm a
    /// sensitive action (`PUT /auth/mfa/ticket`,
    /// `routes/mfa/create_ticket.rs`). Allowed methods are
    /// [`Account::ticket_methods`]. No ticket exists yet, so none is
    /// counted or claimed.
    MintTicket,
}

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
                password_absent: false,
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
            // The hash above is of a random string nobody knows
            password_absent: true,
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
    ///
    /// Signing in cancels a pending account deletion. If the account's
    /// deletion has been confirmed (or the account deleted) by the time the
    /// session is stored, the session is removed again and the login fails
    /// with `InvalidSession`.
    pub async fn create_session(&self, db: &Database, name: String) -> Result<Session> {
        let config = config().await;

        // Cancel before any session exists; if this fails, so does the login.
        // An expired request was dead already, so only a live one is worth
        // telling the user about. The email waits until the login is known
        // to succeed.
        let cancelled = db.cancel_account_deletion(&self.id).await?;
        let notify_cancelled = matches!(
            &cancelled,
            Some(DeletionInfo::WaitingForVerification { expiry, .. })
                if *expiry >= Timestamp::now_utc()
        );

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

        // A confirm that claimed the deletion before the cancel above leaves
        // the account Scheduled (and disabled in the same write). Read it
        // again now that the session exists, so a login racing a confirm
        // can never keep a session. `disabled` alone is not checked here:
        // suspension is handled by the callers
        let deletion = match db.fetch_account(&self.id).await {
            Ok(account) => account.deletion,
            Err(error) => {
                Account::discard_session(db, &session.id).await;
                return Err(error);
            }
        };

        if matches!(
            deletion,
            Some(DeletionInfo::Scheduled { .. } | DeletionInfo::Deleted)
        ) {
            Account::discard_session(db, &session.id).await;
            return Err(create_error!(InvalidSession));
        }

        // Only now, with the session stored and the re-check passed, so a
        // refused login never tells the user their account was restored
        if notify_cancelled {
            self.send_deletion_cancelled_email().await;
        }

        // Create and push event
        EventV1::CreateSession {
            session: session.clone(),
        }
        .global()
        .await;

        Ok(session)
    }

    /// Remove a session a refused login stored, best-effort
    ///
    /// Its token was never handed out and no event announced it.
    async fn discard_session(db: &Database, session_id: &str) {
        if let Err(error) = db.delete_session(session_id).await {
            error!("Failed to remove session {session_id} after a refused login: {error:?}");
        }
    }

    /// Email the user that signing in cancelled their deletion request
    ///
    /// Best-effort and detached: the caller never waits on SMTP, and a
    /// failure is only logged. `send_email` blocks and can panic, so it runs
    /// on the blocking pool and its handle is awaited in a spawned task.
    async fn send_deletion_cancelled_email(&self) {
        let config = config().await;
        if config.api.smtp.host.is_empty() {
            return;
        }

        let template = email_templates().await.deletion_cancelled;
        let smtp = config.api.smtp;
        let email = self.email.clone();
        let account_id = self.id.clone();

        tokio::spawn(async move {
            let variables = json!({
                "email": email.clone(),
                "url": template.url.clone()
            });

            let sent =
                tokio::task::spawn_blocking(move || send_email(&smtp, email, &template, variables))
                    .await;

            match sent {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    error!(
                        "Failed to send the deletion cancelled email for {account_id}: {error:?}"
                    )
                }
                Err(error) => {
                    error!("The deletion cancelled email for {account_id} did not finish: {error}")
                }
            }
        });
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

            let deletion = DeletionInfo::WaitingForVerification {
                token,
                expiry: Timestamp::now_utc()
                    .checked_add(Duration::seconds(
                        config.api.smtp.expiry.expire_account_deletion,
                    ))
                    .unwrap(),
            };

            // Store the pending state before mailing the link, so a failed
            // write never leaves the user holding a link that cannot work.
            // The write is conditional: if a confirm claimed the deletion
            // since this copy was read (Scheduled and disabled), it is
            // refused with `InvalidOperation` and no email goes out, rather
            // than reviving a pending state that could never be confirmed
            // or purged.
            db.request_account_deletion(&self.id, deletion.clone())
                .await?;
            self.deletion = Some(deletion);

            send_email(
                &config.api.smtp,
                self.email.clone(),
                &templates.deletion,
                json!({
                    "email": self.email.clone(),
                    "url": url
                }),
            )
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

    /// The factors that may mint a ticket for this account, that is, confirm
    /// a sensitive action from a signed-in session
    ///
    /// Not the login second step: that keeps `self.mfa.get_methods()`, which
    /// never offers a passkey (old apps would render a blank row for it).
    ///
    /// | account                          | result                          |
    /// |----------------------------------|---------------------------------|
    /// | password                         | `[Password]`                    |
    /// | password + passkey               | `[Password, Passkey]`           |
    /// | TOTP (+ recovery codes)          | `[Totp, Recovery?]`             |
    /// | TOTP (+ recovery codes) + passkey| `[Totp, Recovery?, Passkey]`    |
    /// | no password, no passkey          | `[]`                            |
    /// | no password + passkey            | `[Passkey]`                     |
    ///
    /// A passkey may stand in for the authenticator code. `Passkey` is always
    /// last. The result MAY BE EMPTY (an account created through OAuth that
    /// has no passkey): such an account cannot mint a ticket at all.
    ///
    /// While passkeys are not usable (`PasskeyFeatures::usable`: switched
    /// off, or switched on with an invalid relying party or origin list) a
    /// stored passkey counts for nothing: each "+ passkey" row reads as the
    /// row without one. The passkey routes refuse on the same predicate.
    pub async fn ticket_methods(&self, db: &Database) -> Result<Vec<MFAMethod>> {
        let passkeys_available = config().await.features.passkeys.usable();

        self.ticket_methods_with(db, passkeys_available).await
    }

    /// [`Account::ticket_methods`] for a given state of the passkey switch.
    ///
    /// With the switch off nothing verifies a passkey, so listing one would
    /// offer a method that can never mint a ticket.
    async fn ticket_methods_with(
        &self,
        db: &Database,
        passkeys_available: bool,
    ) -> Result<Vec<MFAMethod>> {
        let mut methods = self.mfa.get_methods();

        if self.password_absent {
            methods.retain(|method| method != &MFAMethod::Password);
        }

        if passkeys_available && db.count_passkeys(&self.id).await? > 0 {
            methods.push(MFAMethod::Passkey);
        }

        Ok(methods)
    }

    /// The methods `verify_mfa_attempt` accepts for this call
    ///
    /// The caller states the purpose; nothing is inferred from what else it
    /// passes. See [`MfaPurpose`].
    async fn allowed_mfa_methods(
        &self,
        db: &Database,
        purpose: MfaPurpose<'_>,
    ) -> Result<Vec<MFAMethod>> {
        match purpose {
            // Login second step: unchanged, and never a passkey
            MfaPurpose::LoginStep(_) => Ok(self.mfa.get_methods()),
            MfaPurpose::MintTicket => self.ticket_methods(db).await,
        }
    }

    /// Validate an MFA response
    ///
    /// `purpose` says what the response is for, and with it which methods
    /// are allowed: `self.mfa.get_methods()` for the login second step,
    /// `ticket_methods` for minting a ticket (see [`MfaPurpose`]).
    ///
    /// One ticket attempt (for the login step) and one account lockout
    /// attempt are counted atomically BEFORE the response is verified, so
    /// concurrent guesses never share a stale counter. A response that is
    /// refused outright (see `verify_mfa_attempt`) counts the ticket attempt
    /// but no lockout attempt. A failure deletes a
    /// ticket that has used its last attempt. A success claims the ticket
    /// (single use), consumes the recovery code if one was used and clears
    /// the lockout. The account document is never saved whole here.
    pub async fn consume_mfa_response(
        &mut self,
        db: &Database,
        response: v0::MFAResponse,
        purpose: MfaPurpose<'_>,
    ) -> Result<()> {
        // Count one attempt against the ticket, and check that the driver
        // returned this ticket and that it belongs to this account. From
        // here on the login step works on the ticket as the driver returned
        // it
        let reserved;
        let purpose = match purpose {
            MfaPurpose::LoginStep(ticket) => {
                reserved = db.reserve_ticket_attempt(&ticket.id).await?;
                if reserved.id != ticket.id || reserved.account_id != self.id {
                    return Err(create_error!(InvalidToken));
                }

                MfaPurpose::LoginStep(&reserved)
            }
            MfaPurpose::MintTicket => MfaPurpose::MintTicket,
        };

        let recovery_code = match self.verify_mfa_attempt(db, response, purpose).await {
            Ok(recovery_code) => recovery_code,
            Err(error) => {
                // Burn a ticket that has no attempts left
                if let MfaPurpose::LoginStep(ticket) = purpose {
                    if ticket.attempts >= MFA_TICKET_MAX_ATTEMPTS {
                        let _ = db.delete_ticket(&ticket.id).await;
                    }
                }

                return Err(error);
            }
        };

        // Single use: a request that loses the race for the ticket fails here
        if let MfaPurpose::LoginStep(ticket) = purpose {
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
    ///
    /// Two responses are refused before the lockout attempt is counted, so
    /// they write nothing at all: a password on an account that has none
    /// (there is nothing to guess, and counting it would let anyone lock the
    /// owner out), and a passkey, which is never verified here.
    async fn verify_mfa_attempt(
        &self,
        db: &Database,
        response: v0::MFAResponse,
        purpose: MfaPurpose<'_>,
    ) -> Result<Option<String>> {
        match &response {
            v0::MFAResponse::Password { .. } if self.password_absent => {
                return Err(create_error!(DisallowedMFAMethod));
            }
            // Refused for both purposes, for good. A passkey that mints a
            // ticket is verified in delta (`routes/mfa/create_ticket.rs`),
            // which takes that response itself and never passes it here.
            // What does arrive here is a passkey offered to the login second
            // step, and that step must never accept one (plan rule R8). No
            // lockout attempt is counted for it.
            v0::MFAResponse::Passkey { .. } => {
                return Err(create_error!(DisallowedMFAMethod));
            }
            v0::MFAResponse::Password { .. }
            | v0::MFAResponse::Totp { .. }
            | v0::MFAResponse::Recovery { .. } => {}
        }

        // Read before the attempt is counted: if the passkey count cannot be
        // read, the request fails without costing the account an attempt
        let allowed_methods = self.allowed_mfa_methods(db, purpose).await?;

        db.reserve_lockout_attempt(&self.id).await?;

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
                if let MfaPurpose::LoginStep(ticket) = purpose {
                    if ticket.last_totp_code.as_ref() == Some(&totp_code) {
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
            // Refused above, before the lockout attempt was counted
            v0::MFAResponse::Passkey { .. } => Err(create_error!(DisallowedMFAMethod)),
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
        let deletion = Some(DeletionInfo::Scheduled {
            after: Timestamp::now_utc()
                .checked_add(Duration::weeks(1))
                .unwrap(),
        });

        // `save_account` never writes `deletion`, so it goes through the
        // targeted op; `disable` then saves the rest
        db.set_account_deletion(&self.id, deletion.clone()).await?;
        self.deletion = deletion;

        self.disable(db).await
    }

    /// Removes all information from the account and marks it as fully deleted
    pub async fn mark_deleted(&mut self, db: &Database) -> Result<()> {
        self.email = format!("Deleted User {}", &self.id);
        self.email_normalised = format!("Deleted User {}", &self.id);

        self.save(db).await?;

        // The Google and Apple ids go too, or a returning user's OAuth
        // sign-in finds this dead account forever. `save_account` cannot
        // clear them (it leaves a `None` id out), so this is a targeted
        // write. Before `Deleted` is stored: if it fails, the account stays
        // due and the next sweep runs all of this again.
        db.unlink_account_oauth(&self.id).await?;
        self.google_id = None;
        self.apple_id = None;

        // A deleted account keeps no credential. `User::delete` removes the
        // passkeys too; this covers an account that reaches here another
        // way. Before `Deleted` is stored, for the same reason as above.
        // `password_absent` is left as it is: the password hash is not
        // touched here either, and the flag only describes that hash.
        db.delete_passkeys_for_user(&self.id).await?;

        // `save_account` never writes `deletion`
        db.set_account_deletion(&self.id, Some(DeletionInfo::Deleted))
            .await?;
        self.deletion = Some(DeletionInfo::Deleted);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_models::v0;
    use revolt_result::ErrorType;

    use crate::{
        util::password::hash_password, Account, DeletionInfo, E2EEIdentity, E2EESignedKey,
        EmailVerification, MFAMethod, MFATicket, MfaPurpose, Passkey, Totp,
    };

    /// An identity row for the session bookkeeping below; the keys are never
    /// verified on this path
    fn identity(user_id: &str, fill: &str, session_id: &str) -> E2EEIdentity {
        let device_id = fill.repeat(32);
        E2EEIdentity {
            id: E2EEIdentity::composite_id(user_id, &device_id),
            user_id: user_id.to_string(),
            device_id,
            protocol_version: 1,
            ed25519_key: "ZWQ".to_string(),
            curve25519_key: "Y3Vy".to_string(),
            signature: "c2ln".to_string(),
            fallback_key: E2EESignedKey {
                key_id: "f0".to_string(),
                key: "a2V5".to_string(),
                signature: "c2ln".to_string(),
            },
            previous_fallback_key: None,
            created_at: Timestamp::now_utc(),
            last_seen_at: Timestamp::now_utc(),
            last_session_id: session_id.to_string(),
        }
    }

    /// Multi-device D5 (audit M3), deliberate: a device a split left bound
    /// to `""` is still revoked by "log out other sessions" from the
    /// surviving session, so an injected device cannot split itself out of
    /// a log-out-everyone. The device bound to the surviving session stays
    #[tokio::test]
    async fn delete_all_sessions_still_revokes_an_unbound_device() {
        database_test!(|db| async move {
            let account = Account {
                id: "01JA00000000000000000ACCNT".to_string(),
                email: "unbound@example.com".to_string(),
                email_normalised: "unbound@example.com".to_string(),
                password: String::new(),
                disabled: false,
                verification: EmailVerification::Verified,
                password_reset: None,
                deletion: None,
                lockout: None,
                mfa: Default::default(),
                google_id: None,
                apple_id: None,
                password_absent: false,
            };

            let kept = identity(&account.id, "a", "S_current");
            let split_from = identity(&account.id, "b", "S_current");
            let elsewhere = identity(&account.id, "c", "S_other");
            for row in [&kept, &split_from, &elsewhere] {
                db.insert_e2ee_identity(row).await.unwrap();
            }

            assert!(E2EEIdentity::unbind_session_if(
                &db,
                &account.id,
                &split_from.device_id,
                "S_current"
            )
            .await
            .unwrap());

            account
                .delete_all_sessions(&db, Some("S_current".to_string()))
                .await
                .unwrap();

            let left: Vec<String> = db
                .fetch_e2ee_identities(&account.id)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.device_id)
                .collect();
            assert_eq!(
                left,
                vec![kept.device_id.clone()],
                "only the device bound to the surviving session may remain"
            );
        });
    }

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
        }
    }

    /// Millisecond-exact, so it survives the ISO string round trip
    fn far_future() -> Timestamp {
        Timestamp::parse("2099-01-01T00:00:00.000Z").expect("valid timestamp")
    }

    fn long_ago() -> Timestamp {
        Timestamp::parse("2000-01-01T00:00:00.000Z").expect("valid timestamp")
    }

    fn waiting(expiry: Timestamp) -> Option<DeletionInfo> {
        Some(DeletionInfo::WaitingForVerification {
            token: "pending-token".to_string(),
            expiry,
        })
    }

    /// Store an account with no deletion, then give it `deletion` through
    /// the targeted write, never through `save_account`
    async fn seed(db: &crate::Database, id: &str, deletion: Option<DeletionInfo>) -> Account {
        db.save_account(&account(id)).await.unwrap();
        db.set_account_deletion(id, deletion.clone()).await.unwrap();

        let stored = db.fetch_account(id).await.unwrap();
        assert_eq!(stored.deletion, deletion, "the control: the seed is stored");
        stored
    }

    async fn session_ids(db: &crate::Database, account_id: &str) -> Vec<String> {
        db.fetch_sessions(account_id)
            .await
            .unwrap()
            .into_iter()
            .map(|session| session.id)
            .collect()
    }

    /// Assert `actual` is `offset` after a moment between `before` and
    /// `after`. The slack covers the millisecond truncation of the stored
    /// ISO string.
    fn assert_offset_near(
        actual: Timestamp,
        before: Timestamp,
        after: Timestamp,
        offset: Duration,
    ) {
        let slack = Duration::seconds(1);
        assert!(
            actual >= before + offset - slack && actual <= after + offset + slack,
            "{actual:?} is not {offset:?} after [{before:?}, {after:?}]"
        );
    }

    #[tokio::test]
    async fn create_session_cancels_a_pending_deletion() {
        database_test!(|db| async move {
            let acct = seed(&db, "01ACCOUNTSIGNINPENDING0000", waiting(far_future())).await;

            let session = acct.create_session(&db, "web".to_string()).await.unwrap();

            assert_eq!(
                db.fetch_account(&acct.id).await.unwrap().deletion,
                None,
                "signing in must cancel a pending deletion"
            );
            assert_eq!(session.user_id, acct.id);
            assert_eq!(session_ids(&db, &acct.id).await, vec![session.id.clone()]);
            assert!(
                db.claim_account_deletion("pending-token").await.is_err(),
                "the emailed link must stop working"
            );
        });
    }

    #[tokio::test]
    async fn create_session_clears_an_expired_pending_deletion() {
        database_test!(|db| async move {
            let acct = seed(&db, "01ACCOUNTSIGNINEXPIRED0000", waiting(long_ago())).await;

            let session = acct.create_session(&db, "web".to_string()).await.unwrap();

            assert_eq!(db.fetch_account(&acct.id).await.unwrap().deletion, None);
            assert_eq!(session_ids(&db, &acct.id).await, vec![session.id.clone()]);
        });
    }

    /// A confirm that claimed the deletion first wins: the login is refused
    /// and the session it stored is gone again
    #[tokio::test]
    async fn create_session_refuses_a_confirmed_deletion() {
        database_test!(|db| async move {
            for (id, deletion) in [
                (
                    "01ACCOUNTSIGNINSCHEDULED00",
                    DeletionInfo::Scheduled {
                        after: far_future(),
                    },
                ),
                ("01ACCOUNTSIGNINDELETED0000", DeletionInfo::Deleted),
            ] {
                let acct = seed(&db, id, Some(deletion.clone())).await;

                let error = acct
                    .create_session(&db, "web".to_string())
                    .await
                    .expect_err("a confirmed deletion must refuse the login");
                assert!(
                    matches!(error.error_type, ErrorType::InvalidSession),
                    "{id}: expected InvalidSession, got {:?}",
                    error.error_type
                );
                assert!(
                    session_ids(&db, id).await.is_empty(),
                    "{id}: a refused login must leave no session"
                );
                assert_eq!(
                    db.fetch_account(id).await.unwrap().deletion,
                    Some(deletion),
                    "{id}: a refused login changes nothing"
                );
            }
        });
    }

    /// The re-check looks at the deletion only; refusing suspended accounts
    /// is the callers' job
    #[tokio::test]
    async fn create_session_does_not_check_disabled() {
        database_test!(|db| async move {
            let mut acct = account("01ACCOUNTSIGNINDISABLED000");
            acct.disabled = true;
            db.save_account(&acct).await.unwrap();

            let session = acct.create_session(&db, "web".to_string()).await.unwrap();
            assert_eq!(session_ids(&db, &acct.id).await, vec![session.id]);
        });
    }

    /// The re-read fails for an account that is not stored, and the session
    /// is removed rather than left behind
    #[tokio::test]
    async fn create_session_for_a_missing_account_leaves_no_session() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTSIGNINMISSING0000");

            let error = acct
                .create_session(&db, "web".to_string())
                .await
                .expect_err("a missing account must refuse the login");
            assert!(
                matches!(error.error_type, ErrorType::UnknownUser),
                "expected UnknownUser, got {:?}",
                error.error_type
            );
            assert!(session_ids(&db, &acct.id).await.is_empty());
        });
    }

    #[tokio::test]
    async fn start_account_deletion_stores_the_pending_state() {
        database_test!(|db| async move {
            let id = "01ACCOUNTSTARTDELETION0000";
            let mut stale = seed(&db, id, None).await;

            // Another write lands after this copy was read
            let mut newer = stale.clone();
            newer.password = "hash-newer".to_string();
            db.save_account(&newer).await.unwrap();

            let before = Timestamp::now_utc();
            let sent = stale.start_account_deletion(&db).await;
            let after = Timestamp::now_utc();

            let stored = db.fetch_account(id).await.unwrap();
            let Some(DeletionInfo::WaitingForVerification { token, expiry }) =
                stored.deletion.clone()
            else {
                panic!("expected a pending deletion, got {:?}", stored.deletion);
            };
            // MongoDB keeps milliseconds only, so compare the token
            let Some(DeletionInfo::WaitingForVerification {
                token: memory_token,
                ..
            }) = &stale.deletion
            else {
                panic!(
                    "expected a pending deletion in memory, got {:?}",
                    stale.deletion
                );
            };
            assert_eq!(memory_token, &token, "memory and storage must agree");

            let lifetime = revolt_config::config()
                .await
                .api
                .smtp
                .expiry
                .expire_account_deletion;
            assert_offset_near(expiry, before, after, Duration::seconds(lifetime));

            assert_eq!(
                db.fetch_account_with_deletion_token(&token)
                    .await
                    .unwrap()
                    .id,
                id
            );
            assert_eq!(
                stored.password, "hash-newer",
                "a deletion request must not revert other fields"
            );
            assert!(!stored.disabled);

            sent.expect("maildev on localhost:14025 must accept the deletion email");
        });
    }

    #[tokio::test]
    async fn schedule_deletion_stores_the_schedule() {
        database_test!(|db| async move {
            let id = "01ACCOUNTSCHEDULEDELETION0";
            let mut acct = seed(&db, id, None).await;
            acct.create_session(&db, "web".to_string()).await.unwrap();

            let before = Timestamp::now_utc();
            acct.schedule_deletion(&db).await.unwrap();
            let after = Timestamp::now_utc();

            let stored = db.fetch_account(id).await.unwrap();
            let Some(DeletionInfo::Scheduled { after: due }) = stored.deletion.clone() else {
                panic!("expected a scheduled deletion, got {:?}", stored.deletion);
            };
            assert_offset_near(due, before, after, Duration::weeks(1));
            assert!(
                matches!(acct.deletion, Some(DeletionInfo::Scheduled { .. })),
                "memory and storage must agree, got {:?}",
                acct.deletion
            );
            assert!(stored.disabled, "a scheduled account is disabled");
            assert!(session_ids(&db, id).await.is_empty());
        });
    }

    #[tokio::test]
    async fn mark_deleted_stores_deleted() {
        database_test!(|db| async move {
            let id = "01ACCOUNTMARKDELETED000000";
            let mut acct = seed(&db, id, Some(DeletionInfo::Scheduled { after: long_ago() })).await;

            acct.mark_deleted(&db).await.unwrap();

            let stored = db.fetch_account(id).await.unwrap();
            assert_eq!(stored.deletion, Some(DeletionInfo::Deleted));
            assert_eq!(stored.email, format!("Deleted User {id}"));
            assert_eq!(stored.email_normalised, format!("Deleted User {id}"));
            assert_eq!(acct.deletion, Some(DeletionInfo::Deleted));
        });
    }

    /// Final audit MAJOR (Amendment 9): a purged account must not keep its
    /// Google and Apple ids, or a returning user's OAuth sign-in finds the
    /// dead account (`disabled_account`) forever
    #[tokio::test]
    async fn mark_deleted_unlinks_oauth() {
        database_test!(|db| async move {
            let id = "01ACCOUNTMARKDELETEDOAUTH0";
            let google_id = "google-sub-mark-deleted";
            let apple_id = "apple-sub-mark-deleted";

            let mut linked = account(id);
            linked.google_id = Some(google_id.to_string());
            linked.apple_id = Some(apple_id.to_string());
            db.save_account(&linked).await.unwrap();
            db.set_account_deletion(id, Some(DeletionInfo::Scheduled { after: long_ago() }))
                .await
                .unwrap();

            // The control: both lookups find the account before the purge
            let mut acct = db
                .fetch_account_by_google_id(google_id)
                .await
                .unwrap()
                .expect("the control: the Google id is stored");
            assert_eq!(acct.id, id);
            assert_eq!(
                db.fetch_account_by_apple_id(apple_id)
                    .await
                    .unwrap()
                    .expect("the control: the Apple id is stored")
                    .id,
                id
            );

            acct.mark_deleted(&db).await.unwrap();

            let stored = db.fetch_account(id).await.unwrap();
            assert_eq!(stored.deletion, Some(DeletionInfo::Deleted));
            assert_eq!(stored.email, format!("Deleted User {id}"));
            assert_eq!(stored.email_normalised, format!("Deleted User {id}"));
            assert_eq!(stored.google_id, None);
            assert_eq!(stored.apple_id, None);
            assert!(
                db.fetch_account_by_google_id(google_id)
                    .await
                    .unwrap()
                    .is_none(),
                "the Google sign-in must not find the deleted account"
            );
            assert!(
                db.fetch_account_by_apple_id(apple_id)
                    .await
                    .unwrap()
                    .is_none(),
                "the Apple sign-in must not find the deleted account"
            );

            // Memory agrees, so a later save of this copy cannot relink them
            assert_eq!(acct.google_id, None);
            assert_eq!(acct.apple_id, None);
            assert_eq!(acct.deletion, Some(DeletionInfo::Deleted));
        });
    }

    /// Wave-2 audit MINOR 1: the request route loaded its copy before a
    /// confirm claimed the deletion. The request must be refused and must
    /// not turn Scheduled back into a pending deletion on a disabled
    /// account, which could then be neither confirmed nor purged.
    #[tokio::test]
    async fn start_account_deletion_refuses_a_claimed_deletion() {
        database_test!(|db| async move {
            assert!(
                !revolt_config::config().await.api.smtp.host.is_empty(),
                "the control: SMTP is configured, so the request takes the email branch"
            );

            let id = "01ACCOUNTSTARTCLAIMED00000";
            let mut stale = seed(&db, id, waiting(far_future())).await;

            // The confirm lands after the request route read its copy
            let claimed = db.claim_account_deletion("pending-token").await.unwrap();
            assert!(
                claimed.disabled,
                "the control: the claim disabled the account"
            );
            assert!(!stale.disabled, "the control: the copy predates the claim");

            let error = stale
                .start_account_deletion(&db)
                .await
                .expect_err("a request after a claim must be refused");
            assert!(
                matches!(error.error_type, ErrorType::InvalidOperation),
                "expected InvalidOperation, got {:?}",
                error.error_type
            );

            let stored = db.fetch_account(id).await.unwrap();
            assert!(
                matches!(stored.deletion, Some(DeletionInfo::Scheduled { .. })),
                "the account must stay Scheduled, got {:?}",
                stored.deletion
            );
            assert_eq!(stored.deletion, claimed.deletion);
            assert!(stored.disabled, "the account must stay disabled");
            assert_eq!(
                stale.deletion,
                waiting(far_future()),
                "a refused request must not change the copy in memory"
            );

            let due = db.fetch_accounts_due_for_deletion().await.unwrap();
            assert!(
                due.iter().any(|due| due.id == id),
                "the purge must still find the account"
            );
        });
    }

    fn password_response(password: &str) -> v0::MFAResponse {
        v0::MFAResponse::Password {
            password: password.to_string(),
        }
    }

    fn passkey_response() -> v0::MFAResponse {
        v0::MFAResponse::Passkey {
            passkey_response: v0::PasskeyTicketResponse {
                challenge_id: "01CHALLENGE".to_string(),
                credential: serde_json::json!({ "id": "abc", "type": "public-key" }),
            },
        }
    }

    async fn lockout_attempts(db: &crate::Database, id: &str) -> Option<i32> {
        db.fetch_account(id)
            .await
            .unwrap()
            .lockout
            .map(|lockout| lockout.attempts)
    }

    /// The control for the two tests below: a wrong password on an account
    /// that has one IS counted, so the lockout read can see a write
    #[tokio::test]
    async fn a_wrong_password_response_counts_a_lockout_attempt() {
        database_test!(|db| async move {
            let id = "01ACCOUNTMFAPASSWORDWRONG0";
            let mut acct = account(id);
            db.save_account(&acct).await.unwrap();
            assert_eq!(lockout_attempts(&db, id).await, None);

            let error = acct
                .consume_mfa_response(&db, password_response("guess"), MfaPurpose::MintTicket)
                .await
                .expect_err("a wrong password must be refused");
            assert!(
                matches!(error.error_type, ErrorType::InvalidCredentials),
                "expected InvalidCredentials, got {:?}",
                error.error_type
            );
            assert_eq!(lockout_attempts(&db, id).await, Some(1));
        });
    }

    /// R9: an account without a password refuses a password response
    /// before anything is counted, however often it is tried
    #[tokio::test]
    async fn a_password_response_without_a_password_writes_no_lockout() {
        database_test!(|db| async move {
            let id = "01ACCOUNTMFAPASSWORDABSENT";
            let mut acct = account(id);
            acct.password_absent = true;
            db.save_account(&acct).await.unwrap();

            for _ in 0..5 {
                let error = acct
                    .consume_mfa_response(&db, password_response("guess"), MfaPurpose::MintTicket)
                    .await
                    .expect_err("an account without a password must refuse one");
                assert!(
                    matches!(error.error_type, ErrorType::DisallowedMFAMethod),
                    "expected DisallowedMFAMethod, got {:?}",
                    error.error_type
                );
            }

            assert_eq!(lockout_attempts(&db, id).await, None);
        });
    }

    /// A passkey response is always refused here, like any method the
    /// account does not have, and counts nothing. The passkey ticket factor
    /// is verified in delta's `mfa/create_ticket.rs`, never by this function
    #[tokio::test]
    async fn a_passkey_response_is_refused_and_writes_no_lockout() {
        database_test!(|db| async move {
            for (id, password_absent) in [
                ("01ACCOUNTMFAPASSKEYPASSWD0", false),
                ("01ACCOUNTMFAPASSKEYABSENT0", true),
            ] {
                let mut acct = account(id);
                acct.password_absent = password_absent;
                db.save_account(&acct).await.unwrap();

                let error = acct
                    .consume_mfa_response(&db, passkey_response(), MfaPurpose::MintTicket)
                    .await
                    .expect_err("a passkey response is never verified here");
                assert!(
                    matches!(error.error_type, ErrorType::DisallowedMFAMethod),
                    "{id}: expected DisallowedMFAMethod, got {:?}",
                    error.error_type
                );
                assert_eq!(lockout_attempts(&db, id).await, None, "{id}");
            }
        });
    }

    /// The login MFA step keeps offering what it offered before (R8)
    #[test]
    fn get_methods_never_offers_a_passkey() {
        let mut acct = account("01ACCOUNTMFAGETMETHODS0000");
        acct.password_absent = true;
        assert_eq!(acct.mfa.get_methods(), vec![crate::MFAMethod::Password]);

        acct.mfa.totp_token = crate::Totp::Enabled {
            secret: "secret".to_string(),
        };
        acct.mfa.recovery_codes = vec!["abcde-fghjk".to_string()];
        assert_eq!(
            acct.mfa.get_methods(),
            vec![crate::MFAMethod::Totp, crate::MFAMethod::Recovery]
        );
    }

    /// Only the OAuth constructors store a password nobody knows
    #[tokio::test]
    async fn only_oauth_accounts_start_without_a_password() {
        database_test!(|db| async move {
            let google = Account::new_from_google(
                &db,
                "pk-google@example.test".to_string(),
                "google-sub-password-absent".to_string(),
            )
            .await
            .unwrap();
            let apple = Account::new_from_apple(
                &db,
                "pk-apple@example.test".to_string(),
                "apple-sub-password-absent".to_string(),
            )
            .await
            .unwrap();
            let plain = Account::new(
                &db,
                "pk-plain@example.test".to_string(),
                "password_insecure".to_string(),
                false,
            )
            .await
            .unwrap();

            for (acct, expected) in [(&google, true), (&apple, true), (&plain, false)] {
                assert_eq!(acct.password_absent, expected, "{}: in memory", acct.email);
                assert_eq!(
                    db.fetch_account(&acct.id).await.unwrap().password_absent,
                    expected,
                    "{}: stored",
                    acct.email
                );
            }
        });
    }

    /// An account document written before the field existed has a password
    #[test]
    fn a_stored_account_without_the_field_has_a_password() {
        let acct: Account = serde_json::from_value(serde_json::json!({
            "_id": "01ACCOUNTOLDDOCUMENT000000",
            "email": "old@example.test",
            "email_normalised": "old@example.test",
            "password": "hash",
            "verification": { "status": "Verified" },
            "mfa": {}
        }))
        .expect("an account document that predates the field");
        assert!(!acct.password_absent);

        // Written out as `false`, so a `$set` can turn the flag off again
        assert_eq!(
            serde_json::to_value(&acct).unwrap()["password_absent"],
            serde_json::Value::Bool(false)
        );
    }

    /// Store passkey `n` of `user_id`; the credential is never verified here
    async fn add_passkey(db: &crate::Database, user_id: &str, n: u32) {
        db.insert_passkey(&Passkey::new(
            user_id.to_string(),
            format!("credential-{user_id}-{n}"),
            format!("handle-{user_id}"),
            "{}".to_string(),
            format!("Passkey {n}"),
        ))
        .await
        .unwrap();
    }

    fn with_totp(mut acct: Account, recovery: bool) -> Account {
        acct.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        if recovery {
            acct.mfa.recovery_codes = vec!["abcde-fghjk".to_string()];
        }
        acct
    }

    fn without_password(mut acct: Account) -> Account {
        acct.password_absent = true;
        acct
    }

    /// The table in the `ticket_methods` doc comment, row by row, for both
    /// states of the passkey switch. The switch is passed in: this crate's
    /// tests cannot overwrite the config.
    ///
    /// Fails if: `ticket_methods_with` lists a passkey without
    /// `passkeys_available` (the second assertion of every "+ passkey" row).
    #[tokio::test]
    async fn ticket_methods_follow_the_table() {
        use MFAMethod::{Passkey as PasskeyMethod, Password, Recovery, Totp as TotpMethod};

        database_test!(|db| async move {
            // Somebody else's passkey, present throughout: it must never
            // show up in another account's list
            add_passkey(&db, "01ACCOUNTTICKETOTHER000000", 1).await;

            let cases: Vec<(Account, u32, Vec<MFAMethod>)> = vec![
                (account("01ACCOUNTTICKETPLAIN00000"), 0, vec![Password]),
                (
                    account("01ACCOUNTTICKETPLAINPK000"),
                    1,
                    vec![Password, PasskeyMethod],
                ),
                // Two passkeys are still one method
                (
                    account("01ACCOUNTTICKETPLAINPK2X0"),
                    2,
                    vec![Password, PasskeyMethod],
                ),
                (
                    with_totp(account("01ACCOUNTTICKETTOTP000000"), false),
                    0,
                    vec![TotpMethod],
                ),
                (
                    with_totp(account("01ACCOUNTTICKETTOTPREC000"), true),
                    0,
                    vec![TotpMethod, Recovery],
                ),
                (
                    with_totp(account("01ACCOUNTTICKETTOTPPK0000"), false),
                    1,
                    vec![TotpMethod, PasskeyMethod],
                ),
                (
                    with_totp(account("01ACCOUNTTICKETTOTPRECPK0"), true),
                    1,
                    vec![TotpMethod, Recovery, PasskeyMethod],
                ),
                (
                    without_password(account("01ACCOUNTTICKETABSENT0000")),
                    0,
                    vec![],
                ),
                (
                    without_password(account("01ACCOUNTTICKETABSENTPK00")),
                    1,
                    vec![PasskeyMethod],
                ),
                // TOTP does not depend on the password
                (
                    without_password(with_totp(account("01ACCOUNTTICKETABSENTTOTP"), true)),
                    1,
                    vec![TotpMethod, Recovery, PasskeyMethod],
                ),
            ];

            for (acct, passkeys, expected) in cases {
                for n in 0..passkeys {
                    add_passkey(&db, &acct.id, n).await;
                }

                assert_eq!(
                    acct.ticket_methods_with(&db, true).await.unwrap(),
                    expected,
                    "{}: passkeys on",
                    acct.id
                );

                // Switched off, a stored passkey is not a method, and
                // nothing else changes
                let without_passkey: Vec<MFAMethod> = expected
                    .iter()
                    .filter(|method| **method != PasskeyMethod)
                    .cloned()
                    .collect();
                assert_eq!(
                    acct.ticket_methods_with(&db, false).await.unwrap(),
                    without_passkey,
                    "{}: passkeys off",
                    acct.id
                );
            }
        });
    }

    /// `ticket_methods` takes the switch from `PasskeyFeatures::usable`.
    ///
    /// Fails if: `ticket_methods` passes a constant instead of the config
    /// value. (Seen only while the two states differ from that constant:
    /// the test config ships with passkeys off, so a hard-coded `true` fails
    /// here.)
    #[tokio::test]
    async fn ticket_methods_read_the_passkey_switch() {
        database_test!(|db| async move {
            let acct = account("01ACCOUNTTICKETSWITCH0000");
            add_passkey(&db, &acct.id, 1).await;

            // The control: for this account the two states differ
            assert_eq!(
                acct.ticket_methods_with(&db, true).await.unwrap(),
                vec![MFAMethod::Password, MFAMethod::Passkey]
            );
            assert_eq!(
                acct.ticket_methods_with(&db, false).await.unwrap(),
                vec![MFAMethod::Password]
            );

            let available = revolt_config::config().await.features.passkeys.usable();
            assert_eq!(
                acct.ticket_methods(&db).await.unwrap(),
                acct.ticket_methods_with(&db, available).await.unwrap(),
                "passkeys available: {available}"
            );
            assert_eq!(
                acct.allowed_mfa_methods(&db, MfaPurpose::MintTicket)
                    .await
                    .unwrap(),
                acct.ticket_methods_with(&db, available).await.unwrap(),
                "minting a ticket follows the switch too"
            );
        });
    }

    /// R8: the login second step's allowed methods are `get_methods()`
    /// whatever passkeys exist. The same account minting a ticket is offered
    /// the passkey, which is the control that the passkey is really stored.
    #[tokio::test]
    async fn the_login_step_allows_what_get_methods_offers() {
        database_test!(|db| async move {
            let totp = with_totp(account("01ACCOUNTLOGINSTEPTOTPPK0"), true);
            let absent = without_password(account("01ACCOUNTLOGINSTEPABSENTPK"));

            for acct in [&totp, &absent] {
                add_passkey(&db, &acct.id, 1).await;
                let ticket = MFATicket::new(acct.id.clone(), false);

                assert_eq!(
                    acct.allowed_mfa_methods(&db, MfaPurpose::LoginStep(&ticket))
                        .await
                        .unwrap(),
                    acct.mfa.get_methods(),
                    "{}: the login step",
                    acct.id
                );
                assert_eq!(
                    acct.allowed_mfa_methods(&db, MfaPurpose::MintTicket)
                        .await
                        .unwrap(),
                    acct.ticket_methods(&db).await.unwrap(),
                    "{}: minting a ticket",
                    acct.id
                );
            }

            // The control, with the switch passed in: minting a ticket now
            // follows `features.passkeys.available`, which is off in this
            // crate's test config
            assert_eq!(
                totp.ticket_methods_with(&db, true).await.unwrap(),
                vec![MFAMethod::Totp, MFAMethod::Recovery, MFAMethod::Passkey]
            );
            assert_eq!(
                absent.ticket_methods_with(&db, true).await.unwrap(),
                vec![MFAMethod::Passkey]
            );
        });
    }

    /// The login second step of a TOTP account that also has a passkey
    /// still passes on the authenticator code, and claims its ticket
    #[tokio::test]
    async fn the_login_step_still_verifies_totp_with_a_passkey_stored() {
        database_test!(|db| async move {
            let id = "01ACCOUNTLOGINSTEPTOTPOK00";
            let mut acct = with_totp(account(id), true);
            db.save_account(&acct).await.unwrap();
            add_passkey(&db, id, 1).await;

            // As the login route builds it. The code sent is the one stored
            // on the ticket, so a 30-second boundary cannot fail the test
            let mut ticket = MFATicket::new(id.to_string(), false);
            ticket.populate(&acct.mfa).await;
            ticket.save(&db).await.unwrap();
            let totp_code = ticket.last_totp_code.clone().expect("a TOTP code");

            // A passkey is not a login second step, and costs the account
            // nothing
            let error = acct
                .consume_mfa_response(&db, passkey_response(), MfaPurpose::LoginStep(&ticket))
                .await
                .expect_err("the login step takes no passkey");
            assert!(
                matches!(error.error_type, ErrorType::DisallowedMFAMethod),
                "expected DisallowedMFAMethod, got {:?}",
                error.error_type
            );
            assert_eq!(lockout_attempts(&db, id).await, None);

            acct.consume_mfa_response(
                &db,
                v0::MFAResponse::Totp { totp_code },
                MfaPurpose::LoginStep(&ticket),
            )
            .await
            .expect("the authenticator code must pass");

            assert!(
                db.fetch_ticket_by_token(&ticket.token).await.is_err(),
                "the login ticket is single use"
            );
            assert_eq!(lockout_attempts(&db, id).await, None);
            assert_eq!(
                db.count_passkeys(id).await.unwrap(),
                1,
                "the control: the passkey was stored all along"
            );
        });
    }

    /// Adding a passkey takes nothing away: the password still mints a
    /// ticket on an account without TOTP
    #[tokio::test]
    async fn a_password_still_mints_a_ticket_with_a_passkey_stored() {
        database_test!(|db| async move {
            let id = "01ACCOUNTMINTPASSWORDPK000";
            let mut acct = account(id);
            acct.password = hash_password("password_insecure".to_string()).unwrap();
            db.save_account(&acct).await.unwrap();
            add_passkey(&db, id, 1).await;
            assert_eq!(
                acct.ticket_methods_with(&db, true).await.unwrap(),
                vec![MFAMethod::Password, MFAMethod::Passkey]
            );

            // The control: the password is really checked
            let error = acct
                .consume_mfa_response(&db, password_response("guess"), MfaPurpose::MintTicket)
                .await
                .expect_err("a wrong password must be refused");
            assert!(
                matches!(error.error_type, ErrorType::InvalidCredentials),
                "expected InvalidCredentials, got {:?}",
                error.error_type
            );
            assert_eq!(lockout_attempts(&db, id).await, Some(1));

            acct.consume_mfa_response(
                &db,
                password_response("password_insecure"),
                MfaPurpose::MintTicket,
            )
            .await
            .expect("the password must still be allowed");
            assert_eq!(lockout_attempts(&db, id).await, None);
        });
    }

    /// A passkey does not bring the password back on a TOTP account
    #[tokio::test]
    async fn a_password_mints_no_ticket_on_a_totp_account_with_a_passkey() {
        database_test!(|db| async move {
            let id = "01ACCOUNTMINTTOTPPASSWORD0";
            let mut acct = with_totp(account(id), false);
            acct.password = hash_password("password_insecure".to_string()).unwrap();
            db.save_account(&acct).await.unwrap();
            add_passkey(&db, id, 1).await;

            let error = acct
                .consume_mfa_response(
                    &db,
                    password_response("password_insecure"),
                    MfaPurpose::MintTicket,
                )
                .await
                .expect_err("TOTP is on, so the password is not a ticket method");
            assert!(
                matches!(error.error_type, ErrorType::DisallowedMFAMethod),
                "expected DisallowedMFAMethod, got {:?}",
                error.error_type
            );
        });
    }

    /// A deleted account keeps no credential, and nobody else loses theirs
    #[tokio::test]
    async fn mark_deleted_removes_the_accounts_passkeys() {
        database_test!(|db| async move {
            let id = "01ACCOUNTMARKDELETEDPK0000";
            let other = "01ACCOUNTMARKDELETEDPKOTHR";

            let mut oauth = without_password(account(id));
            oauth.google_id = Some("google-sub-mark-deleted-pk".to_string());
            db.save_account(&oauth).await.unwrap();
            db.set_account_deletion(id, Some(DeletionInfo::Scheduled { after: long_ago() }))
                .await
                .unwrap();

            add_passkey(&db, id, 1).await;
            add_passkey(&db, id, 2).await;
            add_passkey(&db, other, 1).await;
            assert_eq!(
                db.count_passkeys(id).await.unwrap(),
                2,
                "the control: the passkeys are stored"
            );

            let mut acct = db.fetch_account(id).await.unwrap();
            acct.mark_deleted(&db).await.unwrap();

            assert_eq!(db.count_passkeys(id).await.unwrap(), 0);
            assert!(db.fetch_passkeys(id).await.unwrap().is_empty());
            assert!(
                db.fetch_passkey_by_credential_id(&format!("credential-{id}-1"))
                    .await
                    .unwrap()
                    .is_none(),
                "a passkey login must not resolve to the deleted account"
            );
            assert_eq!(
                db.count_passkeys(other).await.unwrap(),
                1,
                "another account's passkey was removed"
            );

            let stored = db.fetch_account(id).await.unwrap();
            assert_eq!(stored.deletion, Some(DeletionInfo::Deleted));
            // The password hash is left alone, and so is the flag about it
            assert_eq!(stored.password, "hash-original");
            assert!(stored.password_absent);
            assert!(acct.ticket_methods(&db).await.unwrap().is_empty());
        });
    }
}
