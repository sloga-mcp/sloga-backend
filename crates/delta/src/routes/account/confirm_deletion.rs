//! Confirm an account deletion.
//! PUT /account/delete
use revolt_database::Database;
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Confirm Account Deletion
///
/// Delete an account by confirming the token from the deletion email.
/// `confirm` must be true. Confirming is final: the account is disabled and
/// signed out everywhere at once, and its data is purged within about a
/// minute. Refused while the account still owns servers.
#[openapi(tag = "Account")]
#[put("/delete", data = "<data>")]
pub async fn confirm_deletion(
    db: &State<Database>,
    data: Json<v0::DataAccountDeletion>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

    // Only the confirm page's button sends `confirm: true`, so an old page
    // that confirms on load cannot delete an account
    if !data.confirm {
        return Err(create_error!(InvalidOperation));
    }

    // Find the relevant account
    let account = db.fetch_account_with_deletion_token(&data.token).await?;

    // Server owners must transfer or delete their servers first. This
    // changes nothing, so the token stays valid for after they have.
    if !db.fetch_owned_servers(&account.id).await?.is_empty() {
        return Err(create_error!(InvalidOperation));
    }

    // Atomically disable the account and schedule it for deletion now. This
    // fails if the token was used or cancelled (by signing in) meanwhile.
    let account = db.claim_account_deletion(&data.token).await?;

    // The claim has committed and crond will purge the account, so a failure
    // to sign out is logged rather than reported
    if let Err(err) = account.delete_all_sessions(db, None).await {
        log::error!(
            "confirm_deletion: account {} is scheduled for deletion but its sessions were not revoked: {err:?}",
            account.id
        );
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{Account, Database, DeletionInfo};
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Status};

    /// What a refused confirm must leave untouched
    #[derive(Debug, PartialEq)]
    struct Snapshot {
        deletion: Option<DeletionInfo>,
        disabled: bool,
        sessions: Vec<String>,
    }

    async fn snapshot(db: &Database, account_id: &str) -> Snapshot {
        let account = db.fetch_account(account_id).await.unwrap();
        let mut sessions: Vec<String> = db
            .fetch_sessions(account_id)
            .await
            .unwrap()
            .into_iter()
            .map(|session| session.id)
            .collect();
        sessions.sort();

        Snapshot {
            deletion: account.deletion,
            disabled: account.disabled,
            sessions,
        }
    }

    /// A user with two sessions and a pending deletion, plus its token
    ///
    /// The deletion is seeded through `set_account_deletion` (`save_account`
    /// never writes it) and after the sessions exist, since creating a
    /// session cancels a pending deletion.
    async fn pending_user(harness: &TestHarness, expiry: Timestamp) -> (Account, String) {
        let (account, _, user) = harness.new_user().await;
        account
            .create_session(&harness.db, "second".to_string())
            .await
            .unwrap();

        let token = TestHarness::rand_string();
        harness
            .db
            .set_account_deletion(
                &user.id,
                Some(DeletionInfo::WaitingForVerification {
                    token: token.clone(),
                    expiry,
                }),
            )
            .await
            .unwrap();

        let account = harness.db.fetch_account(&user.id).await.unwrap();
        assert!(matches!(
            account.deletion,
            Some(DeletionInfo::WaitingForVerification { .. })
        ));
        assert_eq!(harness.db.fetch_sessions(&user.id).await.unwrap().len(), 2);

        (account, token)
    }

    fn soon() -> Timestamp {
        Timestamp::now_utc() + Duration::seconds(100)
    }

    async fn confirm(harness: &TestHarness, token: &str, confirm: bool) -> (Status, Option<Error>) {
        let res = harness
            .client
            .put("/auth/account/delete")
            .json(&v0::DataAccountDeletion {
                token: token.to_string(),
                confirm,
            })
            .dispatch()
            .await;

        let status = res.status();
        let error = if status == Status::NoContent {
            None
        } else {
            res.into_json::<Error>().await
        };

        (status, error)
    }

    fn assert_invalid_token(status: Status, error: Option<Error>) {
        assert_eq!(status, Status::Unauthorized);
        let error = error.expect("error body").error_type;
        assert!(matches!(error, ErrorType::InvalidToken), "{error:?}");
    }

    fn assert_invalid_operation(status: Status, error: Option<Error>) {
        assert_eq!(status, Status::BadRequest);
        let error = error.expect("error body").error_type;
        assert!(matches!(error, ErrorType::InvalidOperation), "{error:?}");
    }

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (account, token) = pending_user(&harness, soon()).await;

        let (status, error) = confirm(&harness, &token, true).await;
        assert_eq!(status, Status::NoContent, "{error:?}");

        let after = harness.db.fetch_account(&account.id).await.unwrap();
        assert!(after.disabled, "the account is disabled");
        assert!(
            matches!(after.deletion, Some(DeletionInfo::Scheduled { .. })),
            "the deletion is scheduled: {:?}",
            after.deletion
        );

        assert!(
            harness
                .db
                .fetch_sessions(&account.id)
                .await
                .unwrap()
                .is_empty(),
            "every session is revoked"
        );

        let due = harness.db.fetch_accounts_due_for_deletion().await.unwrap();
        assert!(
            due.iter().any(|due| due.id == account.id),
            "crond will purge it on its next sweep"
        );
    }

    #[test]
    fn confirm_false_is_refused() {
        crate::util::test::rt().block_on(confirm_false_is_refused_case())
    }

    async fn confirm_false_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, token) = pending_user(&harness, soon()).await;
        let before = snapshot(&harness.db, &account.id).await;

        let (status, error) = confirm(&harness, &token, false).await;
        assert_invalid_operation(status, error);

        assert_eq!(snapshot(&harness.db, &account.id).await, before);
    }

    #[test]
    fn missing_confirm_is_refused() {
        crate::util::test::rt().block_on(missing_confirm_is_refused_case())
    }

    /// The body an old cached confirm page sends on load
    async fn missing_confirm_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, token) = pending_user(&harness, soon()).await;
        let before = snapshot(&harness.db, &account.id).await;

        let res = harness
            .client
            .put("/auth/account/delete")
            .header(ContentType::JSON)
            .body(json!({ "token": token }).to_string())
            .dispatch()
            .await;

        // Fails to deserialize before the route runs: 422 Unprocessable Entity
        assert!(res.status().class().is_client_error(), "{}", res.status());
        assert_eq!(res.status(), Status::UnprocessableEntity);
        drop(res);

        assert_eq!(snapshot(&harness.db, &account.id).await, before);
    }

    #[test]
    fn expired_token_is_refused() {
        crate::util::test::rt().block_on(expired_token_is_refused_case())
    }

    async fn expired_token_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, token) =
            pending_user(&harness, Timestamp::now_utc() - Duration::seconds(100)).await;
        let before = snapshot(&harness.db, &account.id).await;

        let (status, error) = confirm(&harness, &token, true).await;
        assert_invalid_token(status, error);

        assert_eq!(snapshot(&harness.db, &account.id).await, before);
    }

    #[test]
    fn wrong_token_is_refused() {
        crate::util::test::rt().block_on(wrong_token_is_refused_case())
    }

    async fn wrong_token_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, _) = pending_user(&harness, soon()).await;
        let before = snapshot(&harness.db, &account.id).await;

        let (status, error) = confirm(&harness, &TestHarness::rand_string(), true).await;
        assert_invalid_token(status, error);

        assert_eq!(snapshot(&harness.db, &account.id).await, before);
    }

    #[test]
    fn double_confirm_is_refused() {
        crate::util::test::rt().block_on(double_confirm_is_refused_case())
    }

    async fn double_confirm_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, token) = pending_user(&harness, soon()).await;

        let (status, error) = confirm(&harness, &token, true).await;
        assert_eq!(status, Status::NoContent, "{error:?}");
        let before = snapshot(&harness.db, &account.id).await;

        let (status, error) = confirm(&harness, &token, true).await;
        assert_invalid_token(status, error);

        assert_eq!(snapshot(&harness.db, &account.id).await, before);
    }

    #[test]
    fn server_owner_is_refused() {
        crate::util::test::rt().block_on(server_owner_is_refused_case())
    }

    async fn server_owner_is_refused_case() {
        let harness = TestHarness::new().await;
        let (account, token) = pending_user(&harness, soon()).await;
        let user = harness.db.fetch_user(&account.id).await.unwrap();
        harness.new_server(&user).await;
        assert!(!harness
            .db
            .fetch_owned_servers(&account.id)
            .await
            .unwrap()
            .is_empty());
        let before = snapshot(&harness.db, &account.id).await;

        let (status, error) = confirm(&harness, &token, true).await;
        assert_invalid_operation(status, error);

        let after = snapshot(&harness.db, &account.id).await;
        assert_eq!(after, before);
        assert!(matches!(
            after.deletion,
            Some(DeletionInfo::WaitingForVerification { .. })
        ));
        assert!(!after.disabled);
        assert_eq!(after.sessions.len(), 2);
    }
}
