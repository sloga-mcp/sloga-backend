//! Change account password.
//! PATCH /account/change/password
use revolt_database::{
    util::password::{assert_safe, hash_password},
    Account, Database, ValidatedTicket,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Change Password
///
/// Change the current account password.
#[openapi(tag = "Account")]
#[patch("/change/password", data = "<data>")]
pub async fn change_password(
    db: &State<Database>,
    validated_ticket: Option<ValidatedTicket>,
    mut account: Account,
    data: Json<v0::DataChangePassword>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

    if account.mfa.is_active() && validated_ticket.is_none() {
        return Err(create_error!(InvalidCredentials));
    }

    // Verify password can be used
    assert_safe(&data.password).await?;

    // Ensure given password is correct
    account.verify_password(&data.current_password)?;

    // Hash and replace password
    account.password = hash_password(data.password)?;

    // Commit to database
    account.save(db).await.map(|_| EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{MFATicket, Totp};
    use rocket::http::{ContentType, Header, Status};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "new password",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token))
            .body(
                json!({
                    "password": "sussy password",
                    "current_password": "new password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
    }

    #[test]
    fn success_mfa() {
        crate::util::test::rt().block_on(success_mfa_case())
    }

    async fn success_mfa_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .body(
                json!({
                    "password": "new password",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
    }

    #[test]
    fn fail_mfa_no_ticket() {
        crate::util::test::rt().block_on(fail_mfa_no_ticket_case())
    }

    async fn fail_mfa_no_ticket_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "new password",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
    }

    #[test]
    fn fail_mfa_invalid_password() {
        crate::util::test::rt().block_on(fail_mfa_invalid_password_case())
    }

    async fn fail_mfa_invalid_password_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let mut ticket = MFATicket::new(account.id.to_string(), true);
        ticket.last_totp_code = Some("token from earlier".into());
        ticket.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .body(
                json!({
                    "password": "new password",
                    "current_password": "incorrect password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
    }
}
