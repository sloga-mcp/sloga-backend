//! Revoke all sessions
//! DELETE /session/all
use revolt_database::{Account, Database, Session, ValidatedTicket};
use revolt_result::Result;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Delete All Sessions
///
/// Delete all active sessions, optionally including current one.
#[openapi(tag = "Session")]
#[delete("/all?<revoke_self>")]
pub async fn revoke_all(
    db: &State<Database>,
    _ticket: ValidatedTicket,
    session: Session,
    account: Account,
    revoke_self: Option<bool>,
) -> Result<EmptyResponse> {
    let ignore = if revoke_self.unwrap_or(false) {
        None
    } else {
        Some(session.id)
    };

    account
        .delete_all_sessions(db, ignore)
        .await
        .map(|_| EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{MFATicket, Totp};
    use rocket::http::{Header, Status};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;

        for i in 1..=3 {
            account
                .create_session(&harness.db, format!("session{}", i))
                .await
                .unwrap();
        }

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .delete("/auth/session/all?revoke_self=true")
            .header(Header::new("X-Session-Token", session.token))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
        assert!(harness.db
            .fetch_sessions(&session.user_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn success_not_including_self() {
        crate::util::test::rt().block_on(success_not_including_self_case())
    }

    async fn success_not_including_self_case() {
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;

        for i in 1..=3 {
            account
                .create_session(&harness.db, format!("session{}", i))
                .await
                .unwrap();
        }

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .delete("/auth/session/all?revoke_self=false")
            .header(Header::new("X-Session-Token", session.token))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
        let sessions = harness.db
                .fetch_sessions(&session.user_id)
                .await
                .unwrap();

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, session.id);
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

        for i in 1..=3 {
            account
                .create_session(&harness.db, format!("session{}", i))
                .await
                .unwrap();
        }

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .delete("/auth/session/all?revoke_self=true")
            .header(Header::new("X-Session-Token", session.token))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
        assert!(harness.db
            .fetch_sessions(&session.user_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn success_not_including_self_mfa() {
        crate::util::test::rt().block_on(success_not_including_self_mfa_case())
    }

    async fn success_not_including_self_mfa_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        for i in 1..=3 {
            account
                .create_session(&harness.db, format!("session{}", i))
                .await
                .unwrap();
        }

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .delete("/auth/session/all?revoke_self=false")
            .header(Header::new("X-Session-Token", session.token))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
        let sessions = harness.db
                .fetch_sessions(&session.user_id)
                .await
                .unwrap();

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, session.id);
    }

    #[test]
    fn fail_mfa() {
        crate::util::test::rt().block_on(fail_mfa_case())
    }

    async fn fail_mfa_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .delete("/auth/session/all")
            .header(Header::new("X-Session-Token", session.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
    }
}
