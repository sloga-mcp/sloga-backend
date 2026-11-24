//! Verify an account
//! POST /verify/<code>
use rocket::{serde::json::Json, State};
use revolt_database::{
    util::email::{is_placeholder_email, normalise_email},
    Account, Database, EmailVerification, MFATicket,
};
use revolt_result::{create_error, Result};
use revolt_models::v0;

/// # Verify Email
///
/// Verify an email address.
#[openapi(tag = "Account")]
#[post("/verify/<code>")]
pub async fn verify_email(
    db: &State<Database>,
    code: String,
) -> Result<Json<v0::ResponseVerify>> {
    // Find the account
    let mut account = db
        .fetch_account_with_email_verification(&code)
        .await?;

    // This link is for accounts that already have an email (password and
    // OAuth accounts). An account with no email gets its first address
    // through a code typed into the app, never through a link, and is never
    // waiting on one: should a token be found on such an account anyway, it
    // answers as an unknown token does. No email is moved onto it and no
    // login ticket is handed out.
    if account.real_email().is_none() {
        return Err(create_error!(InvalidToken));
    }

    // Whether this confirms a move to a new address, not a first address
    let moved = matches!(account.verification, EmailVerification::Moving { .. });

    // Update account email
    let response = if let EmailVerification::Moving { new_email, .. } = &account.verification {
        // Nobody moves to a stand-in address
        if is_placeholder_email(new_email) {
            return Err(create_error!(InvalidToken));
        }

        // Another account may have taken the address since the link was
        // mailed. Saving would then fail on the unique index with a server
        // error (and the reference driver has no such index at all), so
        // look first and answer as an unknown token does.
        if let Some(holder) = Account::fetch_by_email(db, new_email).await? {
            if holder.id != account.id {
                return Err(create_error!(InvalidToken));
            }
        }

        account.email = new_email.clone();
        account.email_normalised = normalise_email(new_email.clone());
        v0::ResponseVerify::NoTicket
    } else {
        let mut ticket = MFATicket::new(account.id.to_string(), false);
        ticket.authorised = true;
        ticket.save(db).await?;
        v0::ResponseVerify::WithTicket { ticket: ticket.into() }
    };

    // Mark as verified
    account.verification = EmailVerification::Verified;

    // Save to database
    account.save(db).await?;

    // A passkey recovery link mailed to the old address must not outlive
    // the move. The move is already stored, so a failure here is logged
    // and the request still succeeds: the link runs out on its own within
    // half an hour.
    if moved
        && crate::util::passkey_signup::revoke_recover_tokens(&account.id)
            .await
            .is_err()
    {
        log::error!(
            "passkeys: could not withdraw the recovery link of {} after its email moved",
            account.id
        );
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Timestamp, Duration};
    use revolt_database::{Account, EmailVerification};
    use crate::{rocket, util::test::TestHarness};
    use rocket::http::{ContentType, Status};
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};
    
    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (mut account, _, _) = harness.new_user().await;

        account.verification = EmailVerification::Pending {
            token: "token".into(),
            expiry: Timestamp::now_utc() + Duration::seconds(100),
        };

        account.save(&harness.db).await.unwrap();

        let res = harness.client.post("/auth/account/verify/token").dispatch().await;

        assert_eq!(res.status(), Status::Ok);

        // Make sure it was used and can't be used again
        assert!(harness.db
            .fetch_account_with_email_verification("token")
            .await
            .is_err());

        // Check that we can login using the received MFA ticket
        let response = res.into_json::<v0::ResponseVerify>().await
            .expect("`ResponseVerify`");

        if let v0::ResponseVerify::WithTicket { ticket } = response {
            let res = harness.client
                .post("/auth/session/login")
                .header(ContentType::JSON)
                .body(json!({ "mfa_ticket": ticket.token }).to_string())
                .dispatch()
                .await;

            assert_eq!(res.status(), Status::Ok);
            assert!(res.into_json::<v0::Session>().await.is_some());
        } else {
            panic!("Expected `ResponseVerify::WithTicket`");
        }
    }

    #[test]
    fn fail_invalid_token() {
        crate::util::test::rt().block_on(fail_invalid_token_case())
    }

    async fn fail_invalid_token_case() {
        let harness = TestHarness::new().await;

        let res = harness.client.post("/auth/account/verify/token").dispatch().await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidToken,
        ));
    }

    /// Status and raw body of following the link for `token`
    async fn verify_answer(harness: &TestHarness, token: &str) -> (Status, String) {
        let res = harness
            .client
            .post(format!("/auth/account/verify/{token}"))
            .dispatch()
            .await;

        let status = res.status();
        (status, res.into_string().await.unwrap_or_default())
    }

    fn soon() -> Timestamp {
        Timestamp::now_utc() + Duration::seconds(100)
    }

    /// The answer an unknown token gets, checked to be `InvalidToken`
    async fn unknown_token_answer(harness: &TestHarness) -> (Status, String) {
        let unknown = verify_answer(harness, &TestHarness::rand_string()).await;
        assert_eq!(unknown.0, Status::Unauthorized);
        assert!(matches!(
            serde_json::from_str::<Error>(&unknown.1).unwrap().error_type,
            ErrorType::InvalidToken,
        ));
        unknown
    }

    /// Fails if: a link token found on an account with no email moves an
    /// address onto it (`Moving`) or hands out a login ticket for it
    /// (`Pending`), changes anything stored on it, or answers differently
    /// from an unknown token.
    #[test]
    fn a_no_email_account_is_never_touched() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let unknown = unknown_token_answer(&harness).await;

            let moving_to = format!("{}@stoat.chat", TestHarness::rand_string());
            for (row, verification) in [
                (
                    "moving",
                    EmailVerification::Moving {
                        new_email: moving_to.clone(),
                        token: TestHarness::rand_string(),
                        expiry: soon(),
                    },
                ),
                (
                    "pending",
                    EmailVerification::Pending {
                        token: TestHarness::rand_string(),
                        expiry: soon(),
                    },
                ),
            ] {
                let token = match &verification {
                    EmailVerification::Moving { token, .. }
                    | EmailVerification::Pending { token, .. } => token.clone(),
                    EmailVerification::Verified => unreachable!(),
                };

                let mut account = Account::new_passkey_signup(None).expect("a no-email account");
                account.verification = verification;
                account.save(&harness.db).await.unwrap();

                let before = harness.db.fetch_account(&account.id).await.unwrap();
                assert!(before.email_absent, "{}: the seed must be stored", row);
                assert_eq!(
                    harness
                        .db
                        .fetch_account_with_email_verification(&token)
                        .await
                        .expect("the control: the token is stored and found")
                        .id,
                    account.id,
                    "{row}"
                );

                assert_eq!(verify_answer(&harness, &token).await, unknown, "{row}");

                let after = harness.db.fetch_account(&account.id).await.unwrap();
                assert!(after.email_absent, "{}", row);
                assert_eq!(after.email, before.email, "{row}");
                assert_eq!(after.email_normalised, before.email_normalised, "{row}");
                assert!(
                    !matches!(after.verification, EmailVerification::Verified),
                    "{}: nothing is written, so the planted state is still there",
                    row
                );
                assert!(
                    Account::fetch_by_email(&harness.db, &moving_to)
                        .await
                        .unwrap()
                        .is_none(),
                    "{}: no account holds the address",
                    row
                );
            }
        })
    }

    /// Fails if: confirming a move to an address another account took in
    /// the meantime answers with a server error (the unique index refusing
    /// the save) or, on the reference driver, stores the same address on two
    /// accounts, instead of answering as an unknown token does and leaving
    /// both accounts as they were.
    #[test]
    fn a_move_to_a_taken_address_is_an_invalid_token() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let unknown = unknown_token_answer(&harness).await;

            let (mut mover, _, _) = harness.new_user().await;
            let (holder, _, _) = harness.new_user().await;

            let token = TestHarness::rand_string();
            mover.verification = EmailVerification::Moving {
                new_email: holder.email.to_uppercase(),
                token: token.clone(),
                expiry: soon(),
            };
            mover.save(&harness.db).await.unwrap();
            let before = harness.db.fetch_account(&mover.id).await.unwrap();

            assert_eq!(verify_answer(&harness, &token).await, unknown);

            let after = harness.db.fetch_account(&mover.id).await.unwrap();
            assert_eq!(after.email, before.email);
            assert_eq!(after.email_normalised, before.email_normalised);
            assert_eq!(
                Account::fetch_by_email(&harness.db, &holder.email)
                    .await
                    .unwrap()
                    .expect("the holder keeps the address")
                    .id,
                holder.id
            );
        })
    }

    /// Fails if: the taken-address check refuses an ordinary move to a free
    /// address, or a move back to the account's own address in another case.
    #[test]
    fn a_move_to_a_free_address_still_works() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            for own_address in [false, true] {
                let (mut mover, _, _) = harness.new_user().await;
                let new_email = if own_address {
                    mover.email.to_uppercase()
                } else {
                    format!("{}@stoat.chat", TestHarness::rand_string())
                };

                let token = TestHarness::rand_string();
                mover.verification = EmailVerification::Moving {
                    new_email: new_email.clone(),
                    token: token.clone(),
                    expiry: soon(),
                };
                mover.save(&harness.db).await.unwrap();

                let (status, body) = verify_answer(&harness, &token).await;
                assert_eq!(status, Status::Ok, "{new_email}: {body}");

                let after = harness.db.fetch_account(&mover.id).await.unwrap();
                assert_eq!(after.email, new_email);
                assert!(matches!(after.verification, EmailVerification::Verified));
            }
        })
    }

    /// Whether a passkey recovery token still finds its account
    async fn recover_token_is_live(token: &str) -> bool {
        match crate::util::passkey_signup::peek_recover_token(token).await {
            Ok(_) => true,
            Err(error) => {
                assert!(
                    matches!(error.error_type, ErrorType::InvalidToken),
                    "expected `InvalidToken`, got {:?}",
                    error.error_type
                );
                false
            }
        }
    }

    /// Fails if: a passkey recovery link mailed before an email move still
    /// works once the move is confirmed (it went to the old mailbox); or
    /// the move withdraws another account's link; or a first verification,
    /// which moves nothing, withdraws the account's own.
    #[test]
    fn a_confirmed_move_withdraws_the_recovery_link() {
        crate::util::test::rt().block_on(async {
            use crate::util::passkey_signup::issue_recover_token;

            let harness = TestHarness::new().await;

            let (mut mover, _, _) = harness.new_user().await;
            let (bystander, _, _) = harness.new_user().await;
            let (mut newcomer, _, _) = harness.new_user().await;

            let mut tokens = vec![];
            for account in [&mover, &bystander, &newcomer] {
                let token = issue_recover_token(&account.id)
                    .await
                    .expect("redis")
                    .expect("the first token of the account");
                assert!(
                    recover_token_is_live(&token).await,
                    "the control: the token is live"
                );
                tokens.push(token);
            }

            let move_token = TestHarness::rand_string();
            let new_email = format!("{}@stoat.chat", TestHarness::rand_string());
            mover.verification = EmailVerification::Moving {
                new_email: new_email.clone(),
                token: move_token.clone(),
                expiry: soon(),
            };
            mover.save(&harness.db).await.unwrap();

            let first_token = TestHarness::rand_string();
            newcomer.verification = EmailVerification::Pending {
                token: first_token.clone(),
                expiry: soon(),
            };
            newcomer.save(&harness.db).await.unwrap();

            // A pending move withdraws nothing yet
            assert!(recover_token_is_live(&tokens[0]).await);

            for token in [&move_token, &first_token] {
                let (status, body) = verify_answer(&harness, token).await;
                assert_eq!(status, Status::Ok, "{body}");
            }
            assert_eq!(
                harness.db.fetch_account(&mover.id).await.unwrap().email,
                new_email,
                "the control: the move happened"
            );

            assert!(
                !recover_token_is_live(&tokens[0]).await,
                "the link mailed to the old address still works"
            );
            assert!(
                recover_token_is_live(&tokens[1]).await,
                "another account's link was withdrawn"
            );
            assert!(
                recover_token_is_live(&tokens[2]).await,
                "a first verification withdrew the link"
            );
        })
    }
}
