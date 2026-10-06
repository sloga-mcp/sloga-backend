//! Create a validated MFA ticket for the current session.
//! PUT /mfa/ticket
use revolt_result::Result;
use revolt_database::{Account, Database, MFATicket};
use revolt_models::v0;
use rocket::serde::json::Json;
use rocket::State;


/// # Create MFA ticket
///
/// Verify an MFA response for the account of the current session and
/// create a new validated ticket.
#[openapi(tag = "MFA")]
#[put("/ticket", data = "<data>")]
pub async fn create_ticket(
    db: &State<Database>,
    mut account: Account,
    data: Json<v0::MFAResponse>,
) -> Result<Json<v0::MFATicket>> {
    // Validate the MFA response; this counts an account lockout attempt
    account
        .consume_mfa_response(db, data.into_inner(), None)
        .await?;

    // Create a new ticket for this account
    let ticket = MFATicket::new(account.id, true);
    ticket.save(db).await?;
    Ok(Json(ticket.into()))
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{MFATicket, Totp};
    use rocket::http::{Header, Status};
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::MFATicket>().await.unwrap().validated);
    }

    #[test]
    fn success_totp() {
        crate::util::test::rt().block_on(success_totp_case())
    }

    async fn success_totp_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "totp_code": Totp::Enabled {
                        secret: "secret".to_string(),
                    }.generate_code().unwrap()
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::MFATicket>().await.is_some());
    }

    #[test]
    fn failure_totp() {
        crate::util::test::rt().block_on(failure_totp_case())
    }

    async fn failure_totp_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "totp_code": "000000"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidToken,
        ));
    }

    #[test]
    fn failure_no_totp() {
        crate::util::test::rt().block_on(failure_no_totp_case())
    }

    async fn failure_no_totp_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "this is the wrong mfa method"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::DisallowedMFAMethod,
        ));
    }

    #[test]
    fn failure_unvalidated_ticket_without_session() {
        crate::util::test::rt().block_on(failure_unvalidated_ticket_without_session_case())
    }

    /// A login ticket alone no longer stands in for a session: the request
    /// is refused before the response is checked, and the ticket is intact.
    async fn failure_unvalidated_ticket_without_session_case() {
        let harness = TestHarness::new().await;
        let (mut account, _, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let ticket = MFATicket::new(account.id.to_string(), false);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-MFA-Ticket", ticket.token.clone()))
            .body(
                json!({
                    "totp_code": totp.generate_code().unwrap()
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(harness
            .db
            .fetch_ticket_by_token(&ticket.token)
            .await
            .is_ok());
    }
}
