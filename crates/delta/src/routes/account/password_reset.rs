//! Confirm a password reset.
//! PATCH /account/reset_password
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use revolt_database::util::password::{hash_password, assert_safe};
use revolt_database::{Database, EmailVerification};
use revolt_models::v0;
use revolt_result::{create_error, Result};

/// # Password Reset
///
/// Confirm password reset and change the password.
///
/// Every completed reset removes the account's passkeys and its MFA
/// tickets, and withdraws a lost-passkey link mailed before it. Its
/// sessions are removed only when `remove_sessions` is set.
#[openapi(tag = "Account")]
#[patch("/reset_password", data = "<data>")]
pub async fn password_reset(
    db: &State<Database>,
    data: Json<v0::DataPasswordReset>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

    // Find the relevant account
    let mut account = db
        .fetch_account_with_password_reset(&data.token)
        .await?;

    // A reset token is proof of a mailbox, and an account with no email has
    // none: `start_password_reset` never stores a token for it. Should one
    // be found on such an account anyway, it answers as an unknown token
    // does, before the password is looked at, and nothing is written.
    if account.real_email().is_none() {
        return Err(create_error!(InvalidToken));
    }

    // Verify password can be used
    assert_safe(&data.password)
        .await?;

    // Update the account
    account.password = hash_password(data.password)?;
    account.password_reset = None;

    // The account has a password its owner knows from here on. Cleared in
    // the same save as the hash, so the flag and the hash it describes
    // never disagree in storage
    account.password_absent = false;

    // The token was mailed to `account.email` (the account has one, checked
    // above), so using it proves the same thing the verification link does.
    // Without this an unverified account could reset its password and still
    // be refused at login. A pending move to a new address is left alone:
    // nothing here proves that address.
    if let EmailVerification::Pending { .. } = account.verification {
        account.verification = EmailVerification::Verified;
    }

    // Note the purge before anything is written. A session that outlives
    // this reset could otherwise finish registering a passkey right after
    // the purge below; `register/finish` takes such a passkey back when the
    // session is older than this stamp. Without the stamp that check sees
    // nothing, so the reset fails here, with the token still good for
    // another try.
    crate::util::passkey::mark_passkeys_purged(&account.id).await?;

    // Commit to database
    account.save(db).await?;

    // Each purge below is tried even when the one before it failed, so one
    // failure does not spare the others.

    // A lost-passkey link mailed before the reset stops working: it would
    // register a new passkey on the account after this one took them away
    let recover_tokens_removed =
        crate::util::passkey_signup::revoke_recover_tokens(&account.id).await;

    // A reset always removes the account's passkeys, whatever
    // `remove_sessions` says: one planted by whoever got into the account
    // would otherwise still sign in. Whatever the passkey switch says too,
    // so none is left for later. First of the three database purges: a
    // passkey sign-in, or a ticket minted with a passkey, that races the
    // reset then finds no passkey, and cannot put back a ticket or a
    // session after those were removed.
    let passkeys_removed = db.delete_passkeys_for_user(&account.id).await;

    // A validated ticket minted before the reset must not outlive it: with
    // a kept session it would still open the routes that ask for one
    let tickets_removed = db.delete_mfa_tickets_for_account(&account.id).await;

    // Delete all sessions if required
    let sessions_removed = if data.remove_sessions {
        account.delete_all_sessions(db, None).await
    } else {
        Ok(())
    };

    // Saving never writes the lockout, so clear it directly. Together with
    // `remove_sessions` this is the way back in for an account locked out
    // by someone holding one of its sessions. It runs after the purges, and
    // also when one of them failed: the password is already changed, and
    // its owner must be able to sign in with it.
    let lockout_cleared = db.set_lockout(&account.id, None).await;

    // The first error is the answer
    recover_tokens_removed
        .and(passkeys_removed)
        .and(tickets_removed)
        .and(sessions_removed)
        .and(lockout_cleared)?;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Timestamp, Duration};
    use revolt_database::{Account, PasswordReset};
    use revolt_models::v0;
    use revolt_result::{ErrorType, Error};
    use crate::{rocket, util::test::TestHarness};
    use rocket::http::{ContentType, Header, Status};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.password_reset = Some(PasswordReset {
            token: "token".into(),
            expiry: Timestamp::now_utc() + Duration::seconds(100),
        });

        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .patch("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": "token",
                    "password": "valid-password",
                    "remove_sessions": true
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        // Make sure it was used and can't be used again
        assert!(harness.db
            .fetch_account_with_password_reset("token")
            .await
            .is_err());

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": account.email.clone(),
                    "password": "valid-password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::Session>().await.is_some());

        // Ensure sessions were deleted
        assert!(matches!(
            harness
                .db
                .fetch_session(&session.id)
                .await
                .unwrap_err().error_type,
            ErrorType::UnknownUser
        ));
    }

    /// An account created through Google has no password. Once the reset
    /// sets one, the stored flag is cleared and that password mints a ticket
    #[test]
    fn reset_gives_an_oauth_account_a_password() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            let mut account = Account::new_from_google(
                &harness.db,
                format!("{}@stoat.chat", TestHarness::rand_string()),
                format!("google-sub-{}", TestHarness::rand_string()),
            )
            .await
            .unwrap();

            let token = TestHarness::rand_string();
            account.password_reset = Some(PasswordReset {
                token: token.clone(),
                expiry: Timestamp::now_utc() + Duration::seconds(100),
            });
            account.save(&harness.db).await.unwrap();

            let session = account
                .create_session(&harness.db, String::new())
                .await
                .unwrap();

            // The controls: the flag is stored, and nothing mints a ticket
            assert!(
                harness
                    .db
                    .fetch_account(&account.id)
                    .await
                    .unwrap()
                    .password_absent,
                "the control: the account starts without a password"
            );
            let res = harness
                .client
                .put("/auth/mfa/ticket")
                .header(Header::new("X-Session-Token", session.token.clone()))
                .body(json!({ "password": "valid-password" }).to_string())
                .dispatch()
                .await;
            assert_eq!(res.status(), Status::BadRequest);
            assert!(matches!(
                res.into_json::<Error>().await.unwrap().error_type,
                ErrorType::DisallowedMFAMethod
            ));

            let res = harness
                .client
                .patch("/auth/account/reset_password")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "token": token,
                        "password": "valid-password",
                        "remove_sessions": false
                    })
                    .to_string(),
                )
                .dispatch()
                .await;
            assert_eq!(res.status(), Status::NoContent);

            assert!(
                !harness
                    .db
                    .fetch_account(&account.id)
                    .await
                    .unwrap()
                    .password_absent,
                "a completed reset must clear the stored flag"
            );

            let res = harness
                .client
                .put("/auth/mfa/ticket")
                .header(Header::new("X-Session-Token", session.token.clone()))
                .body(json!({ "password": "valid-password" }).to_string())
                .dispatch()
                .await;
            assert_eq!(res.status(), Status::Ok);
            assert!(res.into_json::<v0::MFATicket>().await.unwrap().validated);
        })
    }

    /// Store a passkey for `user_id`; the credential is never verified here
    async fn add_passkey(harness: &TestHarness, user_id: &str) {
        harness
            .db
            .insert_passkey(&revolt_database::Passkey::new(
                user_id.to_string(),
                format!("credential-{}", TestHarness::rand_string()),
                webauthn_rs::prelude::Uuid::new_v4().to_string(),
                "{}".to_string(),
                "Phone".to_string(),
            ))
            .await
            .unwrap();
    }

    /// An account with two passkeys and a live reset token, next to another
    /// account with one passkey. Returns (account id, other id, token).
    async fn reset_setup(harness: &TestHarness) -> (String, String, String) {
        let (mut account, _, _) = harness.new_user().await;
        let (other, _, _) = harness.new_user().await;

        add_passkey(harness, &account.id).await;
        add_passkey(harness, &account.id).await;
        add_passkey(harness, &other.id).await;

        let token = TestHarness::rand_string();
        account.password_reset = Some(PasswordReset {
            token: token.clone(),
            expiry: Timestamp::now_utc() + Duration::seconds(100),
        });
        account.save(&harness.db).await.unwrap();

        assert_eq!(
            harness.db.count_passkeys(&account.id).await.unwrap(),
            2,
            "the control: the passkeys are stored"
        );

        (account.id, other.id, token)
    }

    async fn reset(harness: &TestHarness, token: &str, remove_sessions: bool) -> Status {
        harness
            .client
            .patch("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": token,
                    "password": "valid-password",
                    "remove_sessions": remove_sessions
                })
                .to_string(),
            )
            .dispatch()
            .await
            .status()
    }

    /// Fails if: a reset that removes the sessions stops deleting the
    /// account's passkeys, or deletes another account's.
    #[test]
    fn removing_sessions_removes_the_passkeys() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, other, token) = reset_setup(&harness).await;

            assert_eq!(reset(&harness, &token, true).await, Status::NoContent);

            assert_eq!(harness.db.count_passkeys(&account).await.unwrap(), 0);
            assert!(harness.db.fetch_passkeys(&account).await.unwrap().is_empty());
            assert_eq!(
                harness.db.count_passkeys(&other).await.unwrap(),
                1,
                "another account's passkey was removed"
            );
        })
    }

    /// Fails if: a reset that keeps the sessions keeps the passkeys too, or
    /// deletes another account's.
    #[test]
    fn keeping_sessions_still_removes_the_passkeys() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, other, token) = reset_setup(&harness).await;

            assert_eq!(reset(&harness, &token, false).await, Status::NoContent);

            assert_eq!(harness.db.count_passkeys(&account).await.unwrap(), 0);
            assert!(harness.db.fetch_passkeys(&account).await.unwrap().is_empty());
            assert_eq!(
                harness.db.count_passkeys(&other).await.unwrap(),
                1,
                "another account's passkey was removed"
            );
        })
    }

    /// Fails if: a reset with `remove_sessions: false` removes a session,
    /// leaves a passkey, or leaves the lockout in place.
    #[test]
    fn a_reset_that_keeps_sessions_keeps_them_and_removes_the_passkeys() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (mut account, session, _) = harness.new_user().await;
            let second = account
                .create_session(&harness.db, String::new())
                .await
                .unwrap();

            add_passkey(&harness, &account.id).await;
            add_passkey(&harness, &account.id).await;

            let token = TestHarness::rand_string();
            account.password_reset = Some(PasswordReset {
                token: token.clone(),
                expiry: Timestamp::now_utc() + Duration::seconds(100),
            });
            account.save(&harness.db).await.unwrap();
            harness
                .db
                .set_lockout(
                    &account.id,
                    Some(revolt_database::Lockout {
                        attempts: 9,
                        expiry: Some(Timestamp::now_utc() + Duration::seconds(3600)),
                    }),
                )
                .await
                .unwrap();

            assert_eq!(
                harness.db.count_passkeys(&account.id).await.unwrap(),
                2,
                "the control: the passkeys are stored"
            );

            assert_eq!(reset(&harness, &token, false).await, Status::NoContent);

            for kept in [&session.id, &second.id] {
                assert!(
                    harness.db.fetch_session(kept).await.is_ok(),
                    "a session was removed without `remove_sessions`"
                );
            }
            assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 0);
            assert!(
                harness
                    .db
                    .fetch_account(&account.id)
                    .await
                    .unwrap()
                    .lockout
                    .is_none(),
                "the lockout is cleared"
            );
        })
    }

    /// No seam makes the stamp or one purge fail in a test, so the order is
    /// pinned on the source instead.
    ///
    /// What it pins, in this order: the purge stamp, the save, the recovery
    /// link, the passkeys, the MFA tickets, the sessions (only with
    /// `remove_sessions`), the lockout clear, then the first error. The
    /// passkeys go before the tickets and the sessions so that a passkey
    /// sign-in, or a ticket minted with a passkey, racing the reset finds
    /// no passkey once those two purges have run.
    ///
    /// Fails if: the purge stamp is written after the account is saved or
    /// its failure no longer ends the reset (`?`); the recovery link is no
    /// longer withdrawn, or is withdrawn before the save; the passkey purge
    /// moves after the ticket or the session purge, or under
    /// `remove_sessions`; a purge returns early (`?`) before the ones after
    /// it are tried; the lockout clear moves ahead of a purge; an error is
    /// returned before the lockout clear was tried; or a purge is left out
    /// of the answer.
    #[test]
    fn every_purge_and_the_lockout_clear_are_tried_before_an_error_is_returned() {
        use crate::util::test::{without_comments, without_whitespace};

        let source = include_str!("password_reset.rs");
        let route = source
            .split("#[cfg(test)]")
            .next()
            .expect("the code above the tests");
        let code = without_whitespace(&without_comments(route));

        const STAMP: &str = "crate::util::passkey::mark_passkeys_purged(&account.id).await?;";
        const SAVE: &str = "account.save(db).await?;";
        const RECOVER: &str = "letrecover_tokens_removed=\
            crate::util::passkey_signup::revoke_recover_tokens(&account.id).await;";
        const PASSKEYS: &str =
            "letpasskeys_removed=db.delete_passkeys_for_user(&account.id).await;";
        const TICKETS: &str =
            "lettickets_removed=db.delete_mfa_tickets_for_account(&account.id).await;";
        const SESSIONS: &str = "letsessions_removed=ifdata.remove_sessions{\
            account.delete_all_sessions(db,None).await}else{Ok(())};";
        const LOCKOUT: &str = "letlockout_cleared=db.set_lockout(&account.id,None).await;";
        const ANSWER: &str = "recover_tokens_removed.and(passkeys_removed)\
            .and(tickets_removed).and(sessions_removed).and(lockout_cleared)?;";

        let at = |needle: &str| {
            assert_eq!(code.matches(needle).count(), 1, "`{}` once", needle);
            code.find(needle).unwrap()
        };

        assert!(at(STAMP) < at(SAVE));
        assert!(at(SAVE) < at(RECOVER));
        assert!(at(RECOVER) < at(PASSKEYS));
        assert!(at(PASSKEYS) < at(TICKETS));
        assert!(at(TICKETS) < at(SESSIONS));
        assert!(at(SESSIONS) < at(LOCKOUT));
        assert!(at(LOCKOUT) < at(ANSWER));

        // Nothing between the save and the answer may return early
        let between = &code[at(SAVE) + SAVE.len()..at(ANSWER)];
        assert!(!between.contains('?'), "an early return: {}", between);
        assert!(!between.contains("return"), "an early return: {}", between);

        assert_eq!(code.matches("mark_passkeys_purged(").count(), 1);
        assert_eq!(code.matches("revoke_recover_tokens(").count(), 1);
        assert_eq!(code.matches("delete_passkeys_for_user(").count(), 1);
        assert_eq!(code.matches("delete_mfa_tickets_for_account(").count(), 1);
        assert_eq!(code.matches("delete_all_sessions(").count(), 1);
        assert_eq!(code.matches("set_lockout(").count(), 1);
    }

    /// Fails if: a completed reset leaves the account's lost-passkey link
    /// working (with or without `remove_sessions`), or withdraws another
    /// account's.
    #[test]
    fn a_reset_withdraws_the_recovery_link() {
        crate::util::test::rt().block_on(async {
            use crate::util::passkey_signup::{issue_recover_token, peek_recover_token};

            let harness = TestHarness::new().await;

            for remove_sessions in [false, true] {
                let (account, other, token) = reset_setup(&harness).await;

                let link = issue_recover_token(&account)
                    .await
                    .expect("issue")
                    .expect("the first token of the account");
                let theirs = issue_recover_token(&other)
                    .await
                    .expect("issue")
                    .expect("the first token of the other account");
                assert_eq!(
                    peek_recover_token(&link).await.expect("peek"),
                    account,
                    "the control: the link works before the reset"
                );

                assert_eq!(
                    reset(&harness, &token, remove_sessions).await,
                    Status::NoContent
                );

                let after = peek_recover_token(&link).await;
                assert!(
                    matches!(
                        after.as_ref().map_err(|error| &error.error_type),
                        Err(ErrorType::InvalidToken)
                    ),
                    "remove_sessions {}: the link outlived the reset: {:?}",
                    remove_sessions,
                    after
                );
                assert_eq!(
                    peek_recover_token(&theirs).await.expect("peek"),
                    other,
                    "remove_sessions {}: another account's link was withdrawn",
                    remove_sessions
                );
            }
        })
    }

    fn unix_ms_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis() as u64
    }

    /// Fails if: a completed reset writes no purge stamp for the account,
    /// stamps a time outside the reset, stamps another account, or the
    /// stamp is not newer than a session that existed before the reset
    /// (`register/finish` compares the two to take a late passkey back).
    #[test]
    fn a_reset_stamps_the_purge() {
        crate::util::test::rt().block_on(async {
            use crate::util::passkey::purged_since;

            let harness = TestHarness::new().await;
            let (account, other, token) = reset_setup(&harness).await;

            let kept = harness
                .db
                .fetch_account(&account)
                .await
                .unwrap()
                .create_session(&harness.db, String::new())
                .await
                .unwrap();
            let session_ms = ulid::Ulid::from_string(&kept.id)
                .expect("a session id is a ULID")
                .timestamp_ms();

            assert_eq!(
                purged_since(&account).await.expect("read"),
                None,
                "the control: no stamp before the reset"
            );

            // A ULID and the stamp share a millisecond clock: let it move
            // on, so "older than the stamp" is not decided by a tie
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;

            let before = unix_ms_now();
            assert_eq!(reset(&harness, &token, false).await, Status::NoContent);
            let after = unix_ms_now();

            let stamp = purged_since(&account)
                .await
                .expect("read")
                .expect("the reset stamped the purge");
            assert!(
                (before..=after).contains(&stamp),
                "{} not in {}..={}",
                stamp,
                before,
                after
            );
            assert!(session_ms < stamp, "the kept session is older than the stamp");
            assert!(harness.db.fetch_session(&kept.id).await.is_ok());

            assert_eq!(purged_since(&other).await.expect("read"), None);
        })
    }

    /// Fails if: a completed reset leaves one of the account's MFA tickets
    /// (validated or not) usable, with or without `remove_sessions`, or
    /// deletes another account's ticket.
    #[test]
    fn a_reset_removes_the_mfa_tickets() {
        crate::util::test::rt().block_on(async {
            use revolt_database::MFATicket;

            let harness = TestHarness::new().await;

            for remove_sessions in [false, true] {
                let (account, other, token) = reset_setup(&harness).await;

                let mut own = vec![];
                for validated in [true, false, true] {
                    let ticket = MFATicket::new(account.clone(), validated);
                    ticket.save(&harness.db).await.unwrap();
                    own.push(ticket);
                }
                let foreign = MFATicket::new(other.clone(), true);
                foreign.save(&harness.db).await.unwrap();

                for ticket in &own {
                    assert!(
                        harness.db.fetch_ticket_by_token(&ticket.token).await.is_ok(),
                        "the control: the ticket is stored"
                    );
                }

                assert_eq!(
                    reset(&harness, &token, remove_sessions).await,
                    Status::NoContent
                );

                for ticket in &own {
                    assert!(
                        harness
                            .db
                            .fetch_ticket_by_token(&ticket.token)
                            .await
                            .is_err(),
                        "remove_sessions {}: a ticket outlived the reset",
                        remove_sessions
                    );
                }
                assert!(
                    harness
                        .db
                        .fetch_ticket_by_token(&foreign.token)
                        .await
                        .is_ok(),
                    "remove_sessions {}: another account's ticket was removed",
                    remove_sessions
                );
            }
        })
    }

    /// Status and raw body of a reset with `token`
    async fn reset_answer(harness: &TestHarness, token: &str) -> (Status, String) {
        let res = harness
            .client
            .patch("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": token,
                    "password": "valid-password",
                    "remove_sessions": true
                })
                .to_string(),
            )
            .dispatch()
            .await;

        let status = res.status();
        (status, res.into_string().await.unwrap_or_default())
    }

    /// Fails if: a reset token found on an account with no email sets a
    /// password on it (which would give a passkey-only account a password
    /// login nobody proved a mailbox for), answers differently from an
    /// unknown token, removes its passkeys or sessions, or stamps a purge.
    #[test]
    fn a_no_email_account_is_never_reset() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            let mut account = Account::new_passkey_signup(None).expect("a no-email account");
            let token = TestHarness::rand_string();
            account.password_reset = Some(PasswordReset {
                token: token.clone(),
                expiry: Timestamp::now_utc() + Duration::seconds(100),
            });
            account.save(&harness.db).await.unwrap();
            add_passkey(&harness, &account.id).await;
            let session = account
                .create_session(&harness.db, String::new())
                .await
                .unwrap();

            let before = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(before.email_absent, "the seed must be stored");
            assert!(
                harness
                    .db
                    .fetch_account_with_password_reset(&token)
                    .await
                    .is_ok(),
                "the control: the token is stored and found"
            );

            let unknown = reset_answer(&harness, &TestHarness::rand_string()).await;
            assert_eq!(unknown.0, Status::Unauthorized);
            assert_eq!(reset_answer(&harness, &token).await, unknown);

            let after = harness.db.fetch_account(&account.id).await.unwrap();
            assert_eq!(after.password, before.password, "the password is untouched");
            assert!(after.password_absent);
            assert!(after.email_absent);
            assert_eq!(after.email, before.email);
            assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);
            assert!(
                harness.db.fetch_session(&session.id).await.is_ok(),
                "the session is kept"
            );
            assert_eq!(
                crate::util::passkey::purged_since(&account.id)
                    .await
                    .expect("read"),
                None,
                "a refused reset stamps no purge"
            );
        })
    }

    #[test]
    fn fail_invalid_token() {
        crate::util::test::rt().block_on(fail_invalid_token_case())
    }

    async fn fail_invalid_token_case() {
        let harness = TestHarness::new().await;

        let res = harness.client
            .patch("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": "invalid",
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidToken
        ));
    }
}
