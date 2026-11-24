//! Delete an account.
//! POST /account/delete
use iso8601_timestamp::{Duration, Timestamp};
use nanoid::nanoid;
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use revolt_result::{create_error, ErrorType, Result};
use revolt_database::{Database, Account, DeletionInfo, ValidatedTicket};
use serde::Deserialize;

/// How long the stand-in for the mailed link lives. It is claimed in the
/// same request, a moment after it is stored.
const NO_EMAIL_CLAIM_SECONDS: i64 = 60;

/// # Delete Account Data
///
/// Optional. Only an account with no email address needs it.
#[derive(Deserialize, JsonSchema)]
pub struct DataDeleteAccount {
    /// The account's username, typed out to confirm. Required from an
    /// account that has no email address, which gets no confirmation link;
    /// ignored from every other account.
    #[serde(default)]
    username: Option<String>,
}

/// # Delete Account
///
/// Request to have an account deleted. This emails a confirmation link;
/// nothing is deleted until that link is confirmed.
///
/// The request needs an MFA ticket, except from an account linked to Google
/// or Apple sign-in that has no MFA enabled: such an account's password is
/// random and unusable, so it could never pass the password step. The email
/// link is still required. An account that owns servers is refused; it must
/// transfer or delete them first.
///
/// An account with no email address cannot be sent the link. It must send
/// an MFA ticket and its username in the body, and that is final: the
/// account is disabled and signed out everywhere at once, as confirming the
/// link does for the others.
#[openapi(tag = "Account")]
#[post("/delete", data = "<data>")]
pub async fn delete_account(
    db: &State<Database>,
    mut account: Account,
    ticket: Option<ValidatedTicket>,
    data: Option<Json<DataDeleteAccount>>,
) -> Result<EmptyResponse> {
    // Owners first, so the refusal is the same with or without a ticket
    if !db.fetch_owned_servers(&account.id).await?.is_empty() {
        return Err(create_error!(InvalidOperation));
    }

    // No mailbox, so no link: the ticket and the typed username stand in
    // for it. Nothing below this branch runs for such an account.
    if account.real_email().is_none() {
        let typed = data.and_then(|data| data.into_inner().username);
        return delete_without_email(db, &account, ticket.is_some(), typed).await;
    }

    // `Option` turns every ticket guard failure into `None`: no header, an
    // unknown, unvalidated or already used ticket, or one minted on another
    // account (`ValidatedTicket` binds it to this session). All of them land
    // here, so a bad ticket never gets further than no ticket at all.
    if ticket.is_none() {
        let oauth_linked = account.google_id.is_some() || account.apple_id.is_some();

        if !oauth_linked || account.mfa.is_active() {
            return Err(create_error!(NotPrivileged));
        }
    }

    account
        .start_account_deletion(db)
        .await
        .map(|_| EmptyResponse)
}

/// Delete an account that has no email address: no link is mailed, so the
/// request itself is the confirmation.
///
/// `has_ticket` is whether the `ValidatedTicket` guard passed (a validated
/// ticket of this account, claimed by the guard). There is no exception to
/// it here, whatever the account is linked to. `typed` is the username from
/// the body, which must equal the account's current username exactly.
///
/// Then the same two writes the mailed link leads to, with a token made
/// here that never leaves the server: the pending deletion is stored
/// (refused for an account that is disabled or already scheduled) and
/// claimed at once, which disables the account and schedules the purge in
/// one write. The sessions are removed after that, as on confirm.
async fn delete_without_email(
    db: &Database,
    account: &Account,
    has_ticket: bool,
    typed: Option<String>,
) -> Result<EmptyResponse> {
    if !has_ticket {
        return Err(create_error!(NotPrivileged));
    }

    // Case and all: the point is that it was typed out
    let user = db.fetch_user(&account.id).await?;
    if typed.as_deref() != Some(user.username.as_str()) {
        return Err(create_error!(FailedValidation {
            error: "username does not match".to_string()
        }));
    }

    let token = nanoid!(32);
    db.request_account_deletion(
        &account.id,
        DeletionInfo::WaitingForVerification {
            token: token.clone(),
            expiry: Timestamp::now_utc() + Duration::seconds(NO_EMAIL_CLAIM_SECONDS),
        },
    )
    .await?;

    // A sign-in that slipped in between cancels a pending deletion, and the
    // claim then finds nothing. Nothing was deleted; the caller asks again.
    let account = db
        .claim_account_deletion(&token)
        .await
        .map_err(|error| match error.error_type {
            ErrorType::InvalidToken => create_error!(InvalidOperation),
            _ => error,
        })?;

    // The claim has committed and crond will purge the account, so a failure
    // to sign out is logged rather than reported
    if let Err(err) = account.delete_all_sessions(db, None).await {
        log::error!(
            "delete_account: account {} is scheduled for deletion but its sessions were not revoked: {err:?}",
            account.id
        );
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{DeletionInfo, MFATicket, Session, Totp};
    use revolt_result::{Error, ErrorType};
    use rocket::http::{Header, Status};

    /// `expire_account_deletion` (24 h)
    const DAY: i64 = 86400;
    /// Allowed drift either side of the expected expiry
    const SLACK: i64 = 300;

    /// POST /auth/account/delete with `session`, and `ticket` as the
    /// `X-MFA-Ticket` header if given. The error type comes back on failure.
    async fn request_deletion(
        harness: &TestHarness,
        session: &Session,
        ticket: Option<&str>,
    ) -> (Status, Option<ErrorType>) {
        let mut request = harness
            .client
            .post("/auth/account/delete")
            .header(Header::new("X-Session-Token", session.token.clone()));

        if let Some(ticket) = ticket {
            request = request.header(Header::new("X-MFA-Ticket", ticket.to_string()));
        }

        let res = request.dispatch().await;
        let status = res.status();
        let error = if status == Status::NoContent {
            None
        } else {
            res.into_json::<Error>().await.map(|error| error.error_type)
        };

        (status, error)
    }

    async fn validated_ticket(harness: &TestHarness, account_id: &str) -> MFATicket {
        let ticket = MFATicket::new(account_id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();
        ticket
    }

    /// The stored deletion is `WaitingForVerification`, expiring about 24 h
    /// after the request, and the account is still enabled. Returns the token.
    async fn assert_pending(harness: &TestHarness, account_id: &str, sent_at: Timestamp) -> String {
        let now = Timestamp::now_utc();
        let account = harness.db.fetch_account(account_id).await.unwrap();

        assert!(!account.disabled, "a deletion request disabled the account");

        match account.deletion {
            Some(DeletionInfo::WaitingForVerification { token, expiry }) => {
                let earliest = sent_at.checked_add(Duration::seconds(DAY - SLACK)).unwrap();
                let latest = now.checked_add(Duration::seconds(DAY + SLACK)).unwrap();

                assert!(
                    expiry >= earliest && expiry <= latest,
                    "deletion expiry {:?} is not about 24 h after the request ({:?}..{:?})",
                    expiry,
                    earliest,
                    latest
                );

                token
            }
            other => panic!("expected a pending deletion, found {:?}", other),
        }
    }

    /// A refused request left no deletion behind and did not disable.
    async fn assert_not_started(harness: &TestHarness, account_id: &str) {
        let account = harness.db.fetch_account(account_id).await.unwrap();

        assert!(
            account.deletion.is_none(),
            "a refused request started a deletion: {:?}",
            account.deletion
        );
        assert!(!account.disabled, "a refused request disabled the account");
    }

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    /// With a ticket: the link is emailed and the deletion waits for it
    async fn success_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.email = "delete_account@smtp.test".to_string();
        account.save(&harness.db).await.unwrap();

        let ticket = validated_ticket(&harness, &account.id).await;

        let sent_at = Timestamp::now_utc();
        let (status, error) = request_deletion(&harness, &session, Some(&ticket.token)).await;

        assert_eq!(status, Status::NoContent, "{:?}", error);

        let token = assert_pending(&harness, &account.id, sent_at).await;

        let (_, code) = harness.assert_email("delete_account@smtp.test").await;
        assert_eq!(code, token, "the emailed link does not carry the stored token");
    }

    #[test]
    fn oauth_without_ticket() {
        crate::util::test::rt().block_on(oauth_without_ticket_case())
    }

    /// A Google-linked account with no MFA needs no ticket, and still gets
    /// the link by email
    async fn oauth_without_ticket_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let mailbox = format!("delete_account_oauth_{}@smtp.test", TestHarness::rand_string());
        account.email = mailbox.clone();
        account.google_id = Some(format!("google-{}", TestHarness::rand_string()));
        account.save(&harness.db).await.unwrap();

        let sent_at = Timestamp::now_utc();
        let (status, error) = request_deletion(&harness, &session, None).await;

        assert_eq!(status, Status::NoContent, "{:?}", error);

        let token = assert_pending(&harness, &account.id, sent_at).await;

        let (_, code) = harness.assert_email(&mailbox).await;
        assert_eq!(code, token, "the emailed link does not carry the stored token");
    }

    #[test]
    fn apple_without_ticket() {
        crate::util::test::rt().block_on(apple_without_ticket_case())
    }

    /// The same for an Apple-linked account
    async fn apple_without_ticket_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.apple_id = Some(format!("apple-{}", TestHarness::rand_string()));
        account.save(&harness.db).await.unwrap();

        let sent_at = Timestamp::now_utc();
        let (status, error) = request_deletion(&harness, &session, None).await;

        assert_eq!(status, Status::NoContent, "{:?}", error);
        assert_pending(&harness, &account.id, sent_at).await;
    }

    #[test]
    fn password_account_without_ticket() {
        crate::util::test::rt().block_on(password_account_without_ticket_case())
    }

    /// A password account must bring a ticket. A ticket header that does not
    /// validate counts as none, so it is refused the same way.
    async fn password_account_without_ticket_case() {
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;

        let (status, error) = request_deletion(&harness, &session, None).await;

        assert_eq!(status, Status::Forbidden);
        assert!(matches!(error, Some(ErrorType::NotPrivileged)), "{:?}", error);
        assert_not_started(&harness, &account.id).await;

        let (status, error) = request_deletion(&harness, &session, Some("not-a-ticket")).await;

        assert_eq!(status, Status::Forbidden);
        assert!(matches!(error, Some(ErrorType::NotPrivileged)), "{:?}", error);
        assert_not_started(&harness, &account.id).await;
    }

    #[test]
    fn oauth_with_mfa_without_ticket() {
        crate::util::test::rt().block_on(oauth_with_mfa_without_ticket_case())
    }

    /// An OAuth-linked account that turned TOTP on must bring a ticket
    async fn oauth_with_mfa_without_ticket_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.google_id = Some(format!("google-{}", TestHarness::rand_string()));
        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let (status, error) = request_deletion(&harness, &session, None).await;

        assert_eq!(status, Status::Forbidden);
        assert!(matches!(error, Some(ErrorType::NotPrivileged)), "{:?}", error);
        assert_not_started(&harness, &account.id).await;
    }

    #[test]
    fn owner_is_refused() {
        crate::util::test::rt().block_on(owner_is_refused_case())
    }

    /// A server owner is refused even with a valid ticket
    async fn owner_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, session, user) = harness.new_user().await;
        harness.new_server(&user).await;

        let ticket = validated_ticket(&harness, &account.id).await;
        let (status, error) = request_deletion(&harness, &session, Some(&ticket.token)).await;

        assert_eq!(status, Status::BadRequest);
        assert!(matches!(error, Some(ErrorType::InvalidOperation)), "{:?}", error);
        assert_not_started(&harness, &account.id).await;
    }

    #[test]
    fn re_request_replaces_token() {
        crate::util::test::rt().block_on(re_request_replaces_token_case())
    }

    /// Asking again while a request is pending issues a new token, so only
    /// the newest link works
    async fn re_request_replaces_token_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.google_id = Some(format!("google-{}", TestHarness::rand_string()));
        account.save(&harness.db).await.unwrap();

        let sent_at = Timestamp::now_utc();
        let (status, error) = request_deletion(&harness, &session, None).await;
        assert_eq!(status, Status::NoContent, "{:?}", error);
        let first = assert_pending(&harness, &account.id, sent_at).await;

        let sent_at = Timestamp::now_utc();
        let (status, error) = request_deletion(&harness, &session, None).await;
        assert_eq!(status, Status::NoContent, "{:?}", error);
        let second = assert_pending(&harness, &account.id, sent_at).await;

        assert_ne!(first, second, "a second request kept the first token");
    }

    /// As `request_deletion`, with `username` typed into the body if given
    async fn request_deletion_typed(
        harness: &TestHarness,
        session: &Session,
        ticket: Option<&str>,
        username: Option<&str>,
    ) -> (Status, Option<ErrorType>) {
        let mut request = harness
            .client
            .post("/auth/account/delete")
            .header(Header::new("X-Session-Token", session.token.clone()));

        if let Some(ticket) = ticket {
            request = request.header(Header::new("X-MFA-Ticket", ticket.to_string()));
        }

        if let Some(username) = username {
            request = request
                .header(rocket::http::ContentType::JSON)
                .body(json!({ "username": username }).to_string());
        }

        let res = request.dispatch().await;
        let status = res.status();
        let error = if status == Status::NoContent {
            None
        } else {
            res.into_json::<Error>().await.map(|error| error.error_type)
        };

        (status, error)
    }

    /// The account is exactly as a refused request must leave it, and its
    /// session still works
    async fn assert_untouched(harness: &TestHarness, account_id: &str, session: &Session) {
        assert_not_started(harness, account_id).await;
        assert!(
            harness.db.fetch_session(&session.id).await.is_ok(),
            "a refused request removed the session"
        );
    }

    #[test]
    fn no_email_account_without_the_username_is_refused() {
        crate::util::test::rt().block_on(no_email_account_without_the_username_is_refused_case())
    }

    /// Fails if: an account with no email is scheduled for deletion on a
    /// ticket alone (no body, an empty body, or a body with no username),
    /// or the request silently answers 204 while storing nothing.
    async fn no_email_account_without_the_username_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_no_email_user().await;
        assert!(account.real_email().is_none(), "the control: no email");

        // No body at all
        let ticket = validated_ticket(&harness, &account.id).await;
        let (status, error) =
            request_deletion_typed(&harness, &session, Some(&ticket.token), None).await;
        assert_eq!(status, Status::BadRequest, "{:?}", error);
        assert!(
            matches!(error, Some(ErrorType::FailedValidation { .. })),
            "{:?}",
            error
        );
        assert_untouched(&harness, &account.id, &session).await;

        // A body that carries no username
        let ticket = validated_ticket(&harness, &account.id).await;
        let res = harness
            .client
            .post("/auth/account/delete")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token.clone()))
            .header(rocket::http::ContentType::JSON)
            .body("{}")
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::BadRequest);
        assert_untouched(&harness, &account.id, &session).await;
    }

    #[test]
    fn no_email_account_with_a_wrong_username_is_refused() {
        crate::util::test::rt().block_on(no_email_account_with_a_wrong_username_is_refused_case())
    }

    /// Fails if: a username other than the account's own schedules the
    /// deletion, the comparison ignores case or surrounding space, another
    /// user's username is accepted, or the right username works without a
    /// ticket.
    async fn no_email_account_with_a_wrong_username_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, session, user) = harness.new_no_email_user().await;
        let (_, _, someone_else) = harness.new_user().await;

        // The harness makes lowercase names, so this differs by case only
        let other_case = user.username.to_uppercase();
        assert_ne!(other_case, user.username, "the control: the case differs");

        let wrong = [
            format!("{}x", user.username),
            other_case,
            format!(" {} ", user.username),
            format!("{}#{}", user.username, user.discriminator),
            someone_else.username.clone(),
            account.id.clone(),
            String::new(),
        ];

        for typed in &wrong {
            let ticket = validated_ticket(&harness, &account.id).await;
            let (status, error) =
                request_deletion_typed(&harness, &session, Some(&ticket.token), Some(typed)).await;
            assert_eq!(status, Status::BadRequest, "`{}`: {:?}", typed, error);
            assert!(
                matches!(error, Some(ErrorType::FailedValidation { .. })),
                "`{}`: {:?}",
                typed,
                error
            );
            assert_untouched(&harness, &account.id, &session).await;
        }

        // The right username, with no ticket and with one that is no ticket
        for ticket in [None, Some("not-a-ticket")] {
            let (status, error) =
                request_deletion_typed(&harness, &session, ticket, Some(&user.username)).await;
            assert_eq!(status, Status::Forbidden, "{:?}", error);
            assert!(matches!(error, Some(ErrorType::NotPrivileged)), "{:?}", error);
            assert_untouched(&harness, &account.id, &session).await;
        }

        // Nor with a validated ticket of another account
        let (other_account, _, _) = harness.new_user().await;
        let foreign = validated_ticket(&harness, &other_account.id).await;
        let (status, error) =
            request_deletion_typed(&harness, &session, Some(&foreign.token), Some(&user.username))
                .await;
        assert_eq!(status, Status::Forbidden, "{:?}", error);
        assert_untouched(&harness, &account.id, &session).await;
    }

    #[test]
    fn no_email_account_with_ticket_and_username_is_scheduled() {
        crate::util::test::rt().block_on(no_email_account_with_ticket_and_username_is_scheduled_case())
    }

    /// Fails if: an account with no email cannot delete itself, is left
    /// waiting for a link nobody can receive, keeps a session, is not
    /// disabled, or is scheduled later than a confirmed link schedules.
    async fn no_email_account_with_ticket_and_username_is_scheduled_case() {
        let harness = TestHarness::new().await;
        let (account, session, user) = harness.new_no_email_user().await;
        let second = account
            .create_session(&harness.db, String::new())
            .await
            .unwrap();

        let ticket = validated_ticket(&harness, &account.id).await;
        let (status, error) =
            request_deletion_typed(&harness, &session, Some(&ticket.token), Some(&user.username))
                .await;
        assert_eq!(status, Status::NoContent, "{:?}", error);

        let stored = harness.db.fetch_account(&account.id).await.unwrap();
        assert!(stored.disabled, "the account must be disabled at once");
        match stored.deletion {
            Some(DeletionInfo::Scheduled { after }) => assert!(
                after <= Timestamp::now_utc(),
                "scheduled for {:?}, later than a confirmed link schedules",
                after
            ),
            other => panic!("expected a scheduled deletion, found {:?}", other),
        }

        for gone in [&session.id, &second.id] {
            assert!(
                harness.db.fetch_session(gone).await.is_err(),
                "a session survived the deletion"
            );
        }
    }

    #[test]
    fn no_email_owner_is_refused() {
        crate::util::test::rt().block_on(no_email_owner_is_refused_case())
    }

    /// Fails if: the no-email branch runs ahead of the owner check.
    async fn no_email_owner_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, session, user) = harness.new_no_email_user().await;
        harness.new_server(&user).await;

        let ticket = validated_ticket(&harness, &account.id).await;
        let (status, error) =
            request_deletion_typed(&harness, &session, Some(&ticket.token), Some(&user.username))
                .await;

        assert_eq!(status, Status::BadRequest);
        assert!(matches!(error, Some(ErrorType::InvalidOperation)), "{:?}", error);
        assert_untouched(&harness, &account.id, &session).await;
    }

    #[test]
    fn ordinary_account_ignores_the_username() {
        crate::util::test::rt().block_on(ordinary_account_ignores_the_username_case())
    }

    /// Fails if: an account that has an email is scheduled straight away
    /// when it types its username, is refused for typing a wrong one, or
    /// gets past the ticket by typing the right one.
    async fn ordinary_account_ignores_the_username_case() {
        let harness = TestHarness::new().await;
        let (account, session, user) = harness.new_user().await;

        // No ticket: refused as before, right username or not
        let (status, error) =
            request_deletion_typed(&harness, &session, None, Some(&user.username)).await;
        assert_eq!(status, Status::Forbidden);
        assert!(matches!(error, Some(ErrorType::NotPrivileged)), "{:?}", error);
        assert_not_started(&harness, &account.id).await;

        // With a ticket the link flow starts, whatever was typed
        for typed in [user.username.as_str(), "someone else"] {
            let ticket = validated_ticket(&harness, &account.id).await;
            let sent_at = Timestamp::now_utc();
            let (status, error) =
                request_deletion_typed(&harness, &session, Some(&ticket.token), Some(typed)).await;
            assert_eq!(status, Status::NoContent, "{:?}", error);
            assert_pending(&harness, &account.id, sent_at).await;
            assert!(
                harness.db.fetch_session(&session.id).await.is_ok(),
                "a pending deletion removed the session"
            );
        }
    }

    #[test]
    fn claimed_deletion_is_refused() {
        crate::util::test::rt().block_on(claimed_deletion_is_refused_case())
    }

    /// Wave-2 audit MINOR 1: a session outlives a confirm (whose session
    /// revoke is best-effort and runs after the claim) and asks again. The
    /// account is Scheduled and disabled. The request must be refused and
    /// leave it so; a new pending deletion on a disabled account could be
    /// neither confirmed nor purged.
    async fn claimed_deletion_is_refused_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        // What a claim leaves behind, seeded through the targeted write
        // (`save_account` never writes `deletion`); the session is kept
        account.disabled = true;
        account.save(&harness.db).await.unwrap();
        let scheduled = DeletionInfo::Scheduled {
            after: Timestamp::parse("2099-01-01T00:00:00.000Z").expect("valid timestamp"),
        };
        harness
            .db
            .set_account_deletion(&account.id, Some(scheduled.clone()))
            .await
            .unwrap();

        // The control: the 400 below cannot come from the owner check
        assert!(harness
            .db
            .fetch_owned_servers(&account.id)
            .await
            .unwrap()
            .is_empty());

        let ticket = validated_ticket(&harness, &account.id).await;
        let (status, error) = request_deletion(&harness, &session, Some(&ticket.token)).await;

        assert_eq!(status, Status::BadRequest, "{:?}", error);
        assert!(
            matches!(error, Some(ErrorType::InvalidOperation)),
            "{:?}",
            error
        );

        let stored = harness.db.fetch_account(&account.id).await.unwrap();
        assert_eq!(
            stored.deletion,
            Some(scheduled),
            "a refused request replaced the scheduled deletion"
        );
        assert!(stored.disabled, "a refused request re-enabled the account");
    }
}
