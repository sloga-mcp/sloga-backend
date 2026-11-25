//! Delete an account.
//! POST /account/delete
use rocket::State;
use rocket_empty::EmptyResponse;
use revolt_result::{create_error, Result};
use revolt_database::{Database, Account, ValidatedTicket};
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
#[openapi(tag = "Account")]
#[post("/delete")]
pub async fn delete_account(
    db: &State<Database>,
    mut account: Account,
    ticket: Option<ValidatedTicket>,
) -> Result<EmptyResponse> {
    // Owners first, so the refusal is the same with or without a ticket
    if !db.fetch_owned_servers(&account.id).await?.is_empty() {
        return Err(create_error!(InvalidOperation));
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
