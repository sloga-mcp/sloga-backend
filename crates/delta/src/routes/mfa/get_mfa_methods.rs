//! Fetch available MFA methods.
//! GET /mfa/methods
use revolt_database::{Account, Database};
use revolt_models::v0;
use revolt_result::Result;
use rocket::serde::json::Json;
use rocket::State;

/// # Get MFA Methods
///
/// Fetch the methods that can confirm a sensitive action on this account
/// (create an MFA ticket). The list ends with `Passkey` if the account has
/// one and passkeys are usable on this server, and is empty for an account
/// that has neither a password nor a passkey.
#[openapi(tag = "MFA")]
#[get("/methods")]
pub async fn get_mfa_methods(
    db: &State<Database>,
    account: Account,
) -> Result<Json<Vec<v0::MFAMethod>>> {
    // Not `account.mfa.get_methods()`: that is the login second step's list
    Ok(Json(
        account
            .ticket_methods(db)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
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
    async fn methods_body(harness: &TestHarness, token: String) -> String {
        let res = harness.client
            .get("/auth/mfa/methods")
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
            .get("/auth/mfa/methods")
            .header(Header::new("X-Session-Token", session.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert_eq!(
            res.into_json::<Vec<v0::MFAMethod>>().await.unwrap(),
            vec![v0::MFAMethod::Password]
        );
    }

    #[test]
    fn success_has_recovery_and_totp() {
        crate::util::test::rt().block_on(success_has_recovery_and_totp_case())
    }

    async fn success_has_recovery_and_totp_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "some".to_string(),
        };
        account.mfa.generate_recovery_codes();
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .get("/auth/mfa/methods")
            .header(Header::new("X-Session-Token", session.token))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert_eq!(
            res.into_json::<Vec<v0::MFAMethod>>().await.unwrap(),
            vec![v0::MFAMethod::Totp, v0::MFAMethod::Recovery]
        );
    }

    #[test]
    fn plain_account_wire_is_unchanged() {
        crate::util::test::rt().block_on(plain_account_wire_is_unchanged_case())
    }

    /// An account without a passkey gets the body it got before passkeys,
    /// whoever else has one
    async fn plain_account_wire_is_unchanged_case() {
        // On, so the other account's passkey is one the list would offer
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let (other, _, _) = harness.new_user().await;
        add_passkey(&harness, &other.id).await;

        assert_eq!(
            methods_body(&harness, session.token).await,
            r#"["Password"]"#
        );
    }

    #[test]
    fn passkey_is_listed_last() {
        crate::util::test::rt().block_on(passkey_is_listed_last_case())
    }

    async fn passkey_is_listed_last_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        add_passkey(&harness, &account.id).await;

        assert_eq!(
            methods_body(&harness, session.token).await,
            r#"["Password","Passkey"]"#
        );
    }

    #[test]
    fn no_password_and_no_passkey_is_empty() {
        crate::util::test::rt().block_on(no_password_and_no_passkey_is_empty_case())
    }

    async fn no_password_and_no_passkey_is_empty_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.password_absent = true;
        account.save(&harness.db).await.unwrap();

        assert_eq!(
            methods_body(&harness, session.token.clone()).await,
            "[]"
        );

        // With a passkey, that is the one method
        add_passkey(&harness, &account.id).await;
        assert_eq!(
            methods_body(&harness, session.token).await,
            r#"["Passkey"]"#
        );
    }

    #[test]
    fn totp_and_passkey() {
        crate::util::test::rt().block_on(totp_and_passkey_case())
    }

    async fn totp_and_passkey_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "some".to_string(),
        };
        account.save(&harness.db).await.unwrap();
        add_passkey(&harness, &account.id).await;

        // No recovery codes yet
        assert_eq!(
            methods_body(&harness, session.token.clone()).await,
            r#"["Totp","Passkey"]"#
        );

        account.mfa.generate_recovery_codes();
        account.save(&harness.db).await.unwrap();

        assert_eq!(
            methods_body(&harness, session.token).await,
            r#"["Totp","Recovery","Passkey"]"#
        );
    }

    #[test]
    fn a_passkey_is_not_listed_while_passkeys_are_off() {
        crate::util::test::rt().block_on(a_passkey_is_not_listed_while_passkeys_are_off_case())
    }

    /// Fails if: `ticket_methods` lists a stored passkey without asking
    /// whether passkeys are usable.
    async fn a_passkey_is_not_listed_while_passkeys_are_off_case() {
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

        assert_eq!(
            methods_body(&harness, session.token.clone()).await,
            r#"["Password"]"#
        );

        // Without a password either, nothing is left to offer
        account.password_absent = true;
        account.save(&harness.db).await.unwrap();

        assert_eq!(methods_body(&harness, session.token).await, "[]");
    }
}
