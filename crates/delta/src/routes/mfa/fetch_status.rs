//! Fetch MFA status of an account.
//! GET /mfa
use revolt_database::{Account, Database};
use revolt_result::Result;
use revolt_models::v0;
use rocket::serde::json::Json;
use rocket::State;

/// # MFA Status
///
/// Fetch MFA status of an account.
#[openapi(tag = "MFA")]
#[get("/")]
pub async fn fetch_status(
    db: &State<Database>,
    account: Account,
) -> Result<Json<v0::MultiFactorStatus>> {
    // Reported only while passkeys are usable, the predicate the passkey
    // routes refuse on: otherwise a client would offer a factor nothing
    // verifies. Not usable, not counted.
    let security_key_mfa = revolt_config::config().await.features.passkeys.usable()
        && db.count_passkeys(&account.id).await? > 0;
    let password_absent = account.password_absent;

    // The conversion knows the `mfa` block only; the passkeys live in their
    // own collection and the password flag on the account
    let mut status: v0::MultiFactorStatus = account.mfa.into();
    status.security_key_mfa = security_key_mfa;
    status.password_absent = password_absent;

    Ok(Json(status))
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Passkey, Totp};
    use rocket::http::{Header, Status};
    use revolt_models::v0;

    /// Switch passkeys on with a valid relying party. Process-wide and set
    /// once, before the harness: a test that needs them off must not call
    /// this (nextest runs one process per test).
    async fn passkeys_on() {
        revolt_config::overwrite_config(|settings| {
            let passkeys = &mut settings.features.passkeys;
            passkeys.available = true;
            passkeys.rp_id = "app.sloga.gg".to_string();
            passkeys.origins = vec!["https://app.sloga.gg".to_string()];
        })
        .await;

        assert!(
            revolt_config::config().await.features.passkeys.usable(),
            "the control: passkeys are usable"
        );
    }

    /// Store a passkey for `user_id`; the credential is never verified here
    async fn add_passkey(harness: &TestHarness, user_id: &str) {
        harness
            .db
            .insert_passkey(&Passkey::new(
                user_id.to_string(),
                format!("credential-{}", TestHarness::rand_string()),
                webauthn_rs::prelude::Uuid::new_v4().to_string(),
                "{}".to_string(),
                "Phone".to_string(),
            ))
            .await
            .unwrap();
    }

    /// The response body as sent, so the wire form itself is compared
    async fn status_body(harness: &TestHarness, token: String) -> String {
        let res = harness.client
            .get("/auth/mfa")
            .header(Header::new("X-Session-Token", token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        res.into_string().await.unwrap()
    }

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let res = harness.client
            .get("/auth/mfa")
            .header(Header::new("X-Session-Token", session.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::MultiFactorStatus>().await.is_some());
    }

    #[test]
    fn old_account_body_is_unchanged() {
        crate::util::test::rt().block_on(old_account_body_is_unchanged_case())
    }

    /// An account with a password and no passkey gets the body it got
    /// before passkeys: neither new key is present, whoever else has a
    /// passkey
    async fn old_account_body_is_unchanged_case() {
        // On, so the other account's passkey is one the route would count
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;
        let (other, _, _) = harness.new_user().await;
        add_passkey(&harness, &other.id).await;

        assert_eq!(status_body(&harness, session.token.clone()).await, "{}");

        account.mfa.totp_token = Totp::Enabled {
            secret: "some".to_string(),
        };
        account.mfa.generate_recovery_codes();
        account.save(&harness.db).await.unwrap();

        assert_eq!(
            status_body(&harness, session.token).await,
            r#"{"totp_mfa":true,"recovery_active":true}"#
        );
    }

    #[test]
    fn a_passkey_reports_security_key_mfa() {
        crate::util::test::rt().block_on(a_passkey_reports_security_key_mfa_case())
    }

    /// Fails if: the route stops counting passkeys, or reports them under
    /// another key.
    async fn a_passkey_reports_security_key_mfa_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        add_passkey(&harness, &account.id).await;

        assert_eq!(
            status_body(&harness, session.token).await,
            r#"{"security_key_mfa":true}"#
        );
    }

    #[test]
    fn an_account_without_a_password_reports_it() {
        crate::util::test::rt().block_on(an_account_without_a_password_reports_it_case())
    }

    async fn an_account_without_a_password_reports_it_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.password_absent = true;
        account.save(&harness.db).await.unwrap();

        assert_eq!(
            status_body(&harness, session.token.clone()).await,
            r#"{"password_absent":true}"#
        );

        add_passkey(&harness, &account.id).await;
        assert_eq!(
            status_body(&harness, session.token).await,
            r#"{"security_key_mfa":true,"password_absent":true}"#
        );
    }

    #[test]
    fn a_passkey_is_not_reported_while_passkeys_are_off() {
        crate::util::test::rt().block_on(a_passkey_is_not_reported_while_passkeys_are_off_case())
    }

    /// Fails if: the route reports a stored passkey without asking whether
    /// passkeys are usable. (`password_absent` does not depend on the
    /// switch and is still reported.)
    async fn a_passkey_is_not_reported_while_passkeys_are_off_case() {
        let harness = TestHarness::new().await;
        assert!(
            !revolt_config::config().await.features.passkeys.usable(),
            "the control: passkeys are off in the test config"
        );

        let (mut account, session, _) = harness.new_user().await;
        add_passkey(&harness, &account.id).await;
        assert_eq!(
            harness.db.count_passkeys(&account.id).await.unwrap(),
            1,
            "the control: the passkey is stored"
        );

        assert_eq!(status_body(&harness, session.token.clone()).await, "{}");

        account.password_absent = true;
        account.save(&harness.db).await.unwrap();

        assert_eq!(
            status_body(&harness, session.token).await,
            r#"{"password_absent":true}"#
        );
    }
}
