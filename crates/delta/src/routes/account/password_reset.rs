//! Confirm a password reset.
//! PATCH /account/reset_password
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use revolt_database::util::password::{hash_password, assert_safe};
use revolt_database::{Database, EmailVerification};
use revolt_models::v0;
use revolt_result::Result;

/// # Password Reset
///
/// Confirm password reset and change the password.
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

    // The token was mailed to `account.email`, so using it proves the same
    // thing the verification link does. Without this an unverified account
    // could reset its password and still be refused at login. A pending move
    // to a new address is left alone: nothing here proves that address.
    if let EmailVerification::Pending { .. } = account.verification {
        account.verification = EmailVerification::Verified;
    }

    // Commit to database
    account.save(db).await?;

    // Delete all sessions if required
    if data.remove_sessions {
        account.delete_all_sessions(db, None).await?;

        // "Sign me out everywhere" has to cover passkeys too: one planted
        // by whoever got into the account would otherwise still sign in.
        // Whatever the passkey switch says, so none is left for later.
        db.delete_passkeys_for_user(&account.id).await?;
    }

    // Saving never writes the lockout, so clear it directly. Together with
    // `remove_sessions` this is the way back in for an account locked out
    // by someone holding one of its sessions. It runs after the purge so a
    // failure here cannot leave those sessions alive.
    db.set_lockout(&account.id, None).await?;

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

    /// Fails if: the reset stops deleting the account's passkeys when it
    /// removes the sessions, or deletes another account's.
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

    /// Fails if: the reset deletes passkeys when it was not asked to remove
    /// the sessions.
    #[test]
    fn keeping_sessions_keeps_the_passkeys() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, other, token) = reset_setup(&harness).await;

            assert_eq!(reset(&harness, &token, false).await, Status::NoContent);

            assert_eq!(harness.db.count_passkeys(&account).await.unwrap(), 2);
            assert_eq!(harness.db.count_passkeys(&other).await.unwrap(), 1);
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
