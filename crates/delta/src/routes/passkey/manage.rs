//! List, rename and remove the account's passkeys.
//! GET /passkey
//! PATCH /passkey/:id
//! DELETE /passkey/:id
use revolt_database::{Account, Database, Passkey, ValidatedTicket};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

use crate::util::passkey;

/// Whether removing one passkey would leave the account with no way to sign
/// in: no usable password, no Google or Apple sign-in, and no other passkey
fn removal_leaves_no_sign_in(password_absent: bool, oauth_linked: bool, passkeys: u64) -> bool {
    password_absent && !oauth_linked && passkeys <= 1
}

/// The same rule read after the delete: `remaining` passkeys are left. True
/// when two removals raced past the check above and took the last ones.
fn removal_left_no_sign_in(password_absent: bool, oauth_linked: bool, remaining: u64) -> bool {
    removal_leaves_no_sign_in(password_absent, oauth_linked, remaining.saturating_add(1))
}

/// # List Passkeys
///
/// Fetch the passkeys of this account, oldest first.
#[openapi(tag = "Passkey")]
#[get("/")]
pub async fn list(db: &State<Database>, account: Account) -> Result<Json<Vec<v0::PasskeyInfo>>> {
    passkey::assert_available().await?;

    let passkeys = db.fetch_passkeys(&account.id).await?;

    Ok(Json(passkeys.iter().map(passkey::passkey_info).collect()))
}

/// # Rename Passkey
///
/// Change the name of one of this account's passkeys.
#[openapi(tag = "Passkey")]
#[patch("/<id>", data = "<data>")]
pub async fn rename(
    db: &State<Database>,
    account: Account,
    id: String,
    data: Json<v0::DataPasskeyRename>,
) -> Result<Json<v0::PasskeyInfo>> {
    passkey::assert_available().await?;

    // A rename to nothing is refused; registering with no name gets the
    // default instead. Past that, one rule for both.
    if data.name.trim().is_empty() {
        return Err(create_error!(FailedValidation {
            error: "passkey name is empty".to_string()
        }));
    }
    let name = passkey::normalise_passkey_name(Some(data.name.as_str()))?;

    // Both calls match on this account's id as well, so an unknown id and
    // another account's passkey are the same NotFound
    db.rename_passkey(&account.id, &id, &name).await?;
    let stored = db.fetch_passkey(&account.id, &id).await?;

    Ok(Json(passkey::passkey_info(&stored)))
}

/// # Remove Passkey
///
/// Delete one of this account's passkeys. Always needs an MFA ticket.
///
/// Refused when it is the only way left to sign in: the account has no
/// usable password, no Google or Apple sign-in, and no other passkey.
#[openapi(tag = "Passkey")]
#[delete("/<id>")]
pub async fn remove(
    db: &State<Database>,
    account: Account,
    _ticket: ValidatedTicket,
    id: String,
) -> Result<EmptyResponse> {
    passkey::assert_available().await?;

    // NotFound for an unknown id and for another account's passkey alike
    let row = db.fetch_passkey(&account.id, &id).await?;

    let oauth_linked = account.google_id.is_some() || account.apple_id.is_some();
    let passkeys = db.count_passkeys(&account.id).await?;
    if removal_leaves_no_sign_in(account.password_absent, oauth_linked, passkeys) {
        return Err(create_error!(InvalidOperation));
    }

    db.delete_passkey(&account.id, &id).await?;

    // The count and the delete are not one step: two removals can both see
    // two passkeys and take one each. Look again, and put this one back if
    // nothing is left to sign in with. (Both racers may put theirs back.)
    // A count that cannot be read is taken as none left
    let remaining = db.count_passkeys(&account.id).await.unwrap_or(0);
    if removal_left_no_sign_in(account.password_absent, oauth_linked, remaining) {
        return put_back(db, &row).await;
    }

    Ok(EmptyResponse)
}

/// Undo a removal that turned out to take the last way in, and refuse it.
/// Tried twice. If the row cannot be written back the database error is the
/// answer: the passkey is gone and the caller must not be told otherwise.
async fn put_back(db: &Database, row: &Passkey) -> Result<EmptyResponse> {
    let mut written = db.insert_passkey(row).await;
    if written.is_err() {
        written = db.insert_passkey(row).await;
    }

    match written {
        Ok(()) => Err(create_error!(InvalidOperation)),
        Err(error) => {
            log::error!(
                "passkeys: could not put back the last passkey of account {} after a removal race",
                row.user_id
            );
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use revolt_database::MFATicket;
    use rocket::http::{ContentType, Status};
    use rocket::local::asynchronous::LocalRequest;

    use super::super::fixtures::{
        harness_with_passkeys_on, keys, kind, seed_passkey, send, switched_off_kind, ticket_for,
        STORED_CREDENTIAL_MARKER,
    };
    use super::{put_back, removal_leaves_no_sign_in, removal_left_no_sign_in};
    use revolt_result::ErrorType;

    use crate::util::passkey::MAX_PASSKEY_NAME_LEN;
    use crate::util::test::{rt, TestHarness};

    const LIST: &str = "/auth/passkey";

    fn one(id: &str) -> String {
        format!("/auth/passkey/{}", id)
    }

    fn rename<'c>(harness: &'c TestHarness, id: &str, name: &str) -> LocalRequest<'c> {
        harness
            .client
            .patch(one(id))
            .header(ContentType::JSON)
            .body(json!({ "name": name }).to_string())
    }

    fn remove<'c>(harness: &'c TestHarness, id: &str) -> LocalRequest<'c> {
        harness.client.delete(one(id))
    }

    #[test]
    fn last_way_in_table() {
        // (no password, oauth, passkeys) -> refused
        for (password_absent, oauth_linked, passkeys, refused) in [
            (true, false, 1, true),
            // Cannot happen through the route (the passkey was found), and
            // must not read as "something else is left"
            (true, false, 0, true),
            (true, false, 2, false),
            (true, true, 1, false),
            (false, false, 1, false),
            (false, true, 1, false),
            (false, false, 2, false),
            (true, true, 2, false),
        ] {
            assert_eq!(
                removal_leaves_no_sign_in(password_absent, oauth_linked, passkeys),
                refused,
                "{:?}",
                (password_absent, oauth_linked, passkeys)
            );
        }
    }

    #[test]
    fn last_way_in_after_the_delete_table() {
        // (no password, oauth, passkeys left) -> the removal is undone
        for (password_absent, oauth_linked, remaining, undone) in [
            // Two removals raced and nothing is left
            (true, false, 0, true),
            // The usual case: one of two went
            (true, false, 1, false),
            (true, false, 9, false),
            (true, true, 0, false),
            (false, false, 0, false),
            (false, true, 0, false),
            // No overflow at the top
            (true, false, u64::MAX, false),
        ] {
            assert_eq!(
                removal_left_no_sign_in(password_absent, oauth_linked, remaining),
                undone,
                "{:?}",
                (password_absent, oauth_linked, remaining)
            );
        }
    }

    #[test]
    fn a_removal_that_took_the_last_way_in_is_put_back() {
        rt().block_on(a_removal_that_took_the_last_way_in_is_put_back_case())
    }

    /// The undo step, on what a lost race leaves: the row already deleted
    async fn a_removal_that_took_the_last_way_in_is_put_back_case() {
        let harness = TestHarness::new().await;
        let (account, _, _) = harness.new_user().await;

        let row = seed_passkey(&harness, &account, "Phone").await;
        harness
            .db
            .delete_passkey(&account.id, &row.id)
            .await
            .unwrap();
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 0);

        let refused = match put_back(&harness.db, &row).await {
            Err(error) => error,
            Ok(_) => panic!("the removal is refused"),
        };
        assert!(
            matches!(refused.error_type, ErrorType::InvalidOperation),
            "{:?}",
            refused
        );

        // The same row is back, credential and all
        let back = harness
            .db
            .fetch_passkey(&account.id, &row.id)
            .await
            .expect("the passkey is back");
        assert_eq!(back.credential_id, row.credential_id);
        assert_eq!(back.credential, row.credential);
        assert_eq!(back.user_handle, row.user_handle);
        assert_eq!(back.name, "Phone");
    }

    #[test]
    fn refused_with_the_feature_off() {
        rt().block_on(refused_with_the_feature_off_case())
    }

    /// Passkeys ship off: every route answers with the switch's own refusal
    /// and nothing stored moves
    async fn refused_with_the_feature_off_case() {
        let harness = TestHarness::new().await;
        let off = switched_off_kind().await;

        let (account, session, _) = harness.new_user().await;
        let stored = seed_passkey(&harness, &account, "Phone").await;

        let (status, body) = send(harness.client.get(LIST), &session, None).await;
        assert_ne!(status, Status::NotFound, "the route is mounted");
        assert_ne!(status, Status::Ok);
        assert_eq!(kind(&body), off, "{}", body);
        assert!(!body.to_string().contains(&stored.id), "{}", body);

        let (status, body) = send(rename(&harness, &stored.id, "Renamed"), &session, None).await;
        assert_ne!(status, Status::Ok);
        assert_eq!(kind(&body), off, "{}", body);

        let ticket = ticket_for(&harness, &account).await;
        let (status, body) = send(remove(&harness, &stored.id), &session, Some(&ticket)).await;
        assert_ne!(status, Status::NoContent);
        assert_eq!(kind(&body), off, "{}", body);

        let after = harness
            .db
            .fetch_passkey(&account.id, &stored.id)
            .await
            .expect("the passkey is still there");
        assert_eq!(after.name, "Phone");
    }

    #[test]
    fn list_shows_only_this_accounts_passkeys_and_no_secrets() {
        rt().block_on(list_shows_only_this_accounts_passkeys_and_no_secrets_case())
    }

    async fn list_shows_only_this_accounts_passkeys_and_no_secrets_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, session, _) = harness.new_user().await;
        let (other, other_session, _) = harness.new_user().await;
        let (empty, empty_session, _) = harness.new_user().await;

        let first = seed_passkey(&harness, &account, "Phone").await;
        let second = seed_passkey(&harness, &account, "Laptop").await;
        let foreign = seed_passkey(&harness, &other, "Someone else's").await;

        let (status, body) = send(harness.client.get(LIST), &session, None).await;
        assert_eq!(status, Status::Ok, "{}", body);

        let rows = body.as_array().expect("a list");
        let mut listed: Vec<&str> = rows.iter().map(|row| row["id"].as_str().unwrap()).collect();
        listed.sort_unstable();
        let mut expected = vec![first.id.as_str(), second.id.as_str()];
        expected.sort_unstable();
        assert_eq!(listed, expected);

        // Never used, so `last_used_at` is absent; nothing else is ever sent
        for row in rows {
            assert_eq!(keys(row), ["created_at", "id", "name"], "{}", row);
        }

        let text = body.to_string();
        for secret in [
            STORED_CREDENTIAL_MARKER,
            first.credential_id.as_str(),
            first.user_handle.as_str(),
            second.credential_id.as_str(),
            second.user_handle.as_str(),
            foreign.id.as_str(),
            "Someone else's",
        ] {
            assert!(!text.contains(secret), "the list carries `{}`", secret);
        }

        // The other account sees its own row only
        let (status, body) = send(harness.client.get(LIST), &other_session, None).await;
        assert_eq!(status, Status::Ok, "{}", body);
        let rows = body.as_array().expect("a list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], foreign.id.as_str());

        // An account with none gets an empty list
        let (status, body) = send(harness.client.get(LIST), &empty_session, None).await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(body, json!([]));
        assert_eq!(harness.db.count_passkeys(&empty.id).await.unwrap(), 0);
    }

    #[test]
    fn rename_bounds_and_ownership() {
        rt().block_on(rename_bounds_and_ownership_case())
    }

    async fn rename_bounds_and_ownership_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, session, _) = harness.new_user().await;
        let (other, _, _) = harness.new_user().await;

        let stored = seed_passkey(&harness, &account, "Phone").await;
        let foreign = seed_passkey(&harness, &other, "Theirs").await;

        // Trimmed, stored, and returned as the updated passkey
        let (status, body) = send(
            rename(&harness, &stored.id, "  Work laptop  "),
            &session,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(keys(&body), ["created_at", "id", "name"]);
        assert_eq!(body["id"], stored.id.as_str());
        assert_eq!(body["name"], "Work laptop");
        assert!(!body.to_string().contains(STORED_CREDENTIAL_MARKER));

        let name_of = |id: String, user: String| {
            let db = harness.db.clone();
            async move { db.fetch_passkey(&user, &id).await.unwrap().name }
        };
        assert_eq!(
            name_of(stored.id.clone(), account.id.clone()).await,
            "Work laptop"
        );

        // Empty after trimming, one character too long, and a control
        // character inside the name (the rule registering uses)
        let too_long = "é".repeat(MAX_PASSKEY_NAME_LEN + 1);
        for name in ["", "   ", too_long.as_str(), "Work\u{7}laptop", "\u{0}"] {
            let (status, body) = send(rename(&harness, &stored.id, name), &session, None).await;
            assert_eq!(status, Status::BadRequest, "{}", body);
            assert_eq!(kind(&body), "FailedValidation");
        }
        assert_eq!(
            name_of(stored.id.clone(), account.id.clone()).await,
            "Work laptop"
        );

        // The longest name, counted in characters and not in bytes
        let longest = "é".repeat(MAX_PASSKEY_NAME_LEN);
        let (status, body) = send(rename(&harness, &stored.id, &longest), &session, None).await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(body["name"], longest.as_str());

        // Another account's passkey and an id nobody has: the same answer
        let (foreign_status, foreign_body) =
            send(rename(&harness, &foreign.id, "Stolen"), &session, None).await;
        let (unknown_status, unknown_body) = send(
            rename(&harness, "01PASSKEYNOBODYHAS00000000", "Stolen"),
            &session,
            None,
        )
        .await;

        assert_eq!(foreign_status, Status::NotFound, "{}", foreign_body);
        assert_eq!(kind(&foreign_body), "NotFound");
        assert_eq!(unknown_status, foreign_status);
        assert_eq!(kind(&unknown_body), kind(&foreign_body));

        assert_eq!(
            name_of(foreign.id.clone(), other.id.clone()).await,
            "Theirs"
        );
    }

    #[test]
    fn remove_needs_a_ticket() {
        rt().block_on(remove_needs_a_ticket_case())
    }

    async fn remove_needs_a_ticket_case() {
        let harness = harness_with_passkeys_on().await;
        // A password account: the last-way-in rule is not what refuses here
        let (account, session, _) = harness.new_user().await;
        let (other, _, _) = harness.new_user().await;
        let stored = seed_passkey(&harness, &account, "Phone").await;

        // These refusals come from the `ValidatedTicket` guard, before the
        // route runs. A guard failure is answered by Rocket's default
        // catcher, so there is a status to pin and no error `type`.

        // No ticket: 401 (the guard's `MissingHeaders`)
        let (status, body) = send(remove(&harness, &stored.id), &session, None).await;
        assert_eq!(status, Status::Unauthorized, "{}", body);
        assert_eq!(kind(&body), "", "{}", body);

        // A token that is no ticket: 401 (`InvalidToken`)
        let (status, body) =
            send(remove(&harness, &stored.id), &session, Some("not-a-ticket")).await;
        assert_eq!(status, Status::Unauthorized, "{}", body);
        assert_eq!(kind(&body), "", "{}", body);

        // A ticket that was never validated: 403
        let unvalidated = MFATicket::new(account.id.to_string(), false);
        unvalidated.save(&harness.db).await.unwrap();
        let (status, body) = send(
            remove(&harness, &stored.id),
            &session,
            Some(&unvalidated.token),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "{}", body);
        assert_eq!(kind(&body), "", "{}", body);

        // A validated ticket of another account: 403, and it is not burned
        let foreign_ticket = ticket_for(&harness, &other).await;
        let (status, body) = send(
            remove(&harness, &stored.id),
            &session,
            Some(&foreign_ticket),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "{}", body);
        assert_eq!(kind(&body), "", "{}", body);
        assert!(
            harness
                .db
                .fetch_ticket_by_token(&foreign_ticket)
                .await
                .is_ok(),
            "a foreign ticket was claimed"
        );

        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);

        // The control: this account's validated ticket removes it
        let ticket = ticket_for(&harness, &account).await;
        let (status, body) = send(remove(&harness, &stored.id), &session, Some(&ticket)).await;
        assert_eq!(status, Status::NoContent, "{}", body);
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 0);

        // The ticket was spent by that: it is gone, so 401 as for no ticket
        let again = seed_passkey(&harness, &account, "Tablet").await;
        let (status, body) = send(remove(&harness, &again.id), &session, Some(&ticket)).await;
        assert_eq!(status, Status::Unauthorized, "{}", body);
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);
    }

    #[test]
    fn remove_of_an_unknown_or_foreign_passkey_is_not_found() {
        rt().block_on(remove_of_an_unknown_or_foreign_passkey_is_not_found_case())
    }

    async fn remove_of_an_unknown_or_foreign_passkey_is_not_found_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, session, _) = harness.new_user().await;
        let (other, _, _) = harness.new_user().await;

        seed_passkey(&harness, &account, "Mine").await;
        let foreign = seed_passkey(&harness, &other, "Theirs").await;

        let ticket = ticket_for(&harness, &account).await;
        let (foreign_status, foreign_body) =
            send(remove(&harness, &foreign.id), &session, Some(&ticket)).await;

        let ticket = ticket_for(&harness, &account).await;
        let (unknown_status, unknown_body) = send(
            remove(&harness, "01PASSKEYNOBODYHAS00000000"),
            &session,
            Some(&ticket),
        )
        .await;

        assert_eq!(foreign_status, Status::NotFound, "{}", foreign_body);
        assert_eq!(kind(&foreign_body), "NotFound");
        assert_eq!(unknown_status, foreign_status);
        assert_eq!(kind(&unknown_body), kind(&foreign_body));

        // Nothing was removed on either account
        assert_eq!(harness.db.count_passkeys(&other.id).await.unwrap(), 1);
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);
    }

    #[test]
    fn the_last_way_in_cannot_be_removed() {
        rt().block_on(the_last_way_in_cannot_be_removed_case())
    }

    async fn the_last_way_in_cannot_be_removed_case() {
        let harness = harness_with_passkeys_on().await;
        let (mut account, session, _) = harness.new_user().await;
        account.password_absent = true;
        account.save(&harness.db).await.unwrap();

        let first = seed_passkey(&harness, &account, "Phone").await;
        let second = seed_passkey(&harness, &account, "Laptop").await;

        // With two, one may go
        let ticket = ticket_for(&harness, &account).await;
        let (status, body) = send(remove(&harness, &first.id), &session, Some(&ticket)).await;
        assert_eq!(status, Status::NoContent, "{}", body);

        // The last one may not: no password, no Google or Apple sign-in
        let ticket = ticket_for(&harness, &account).await;
        let (status, body) = send(remove(&harness, &second.id), &session, Some(&ticket)).await;
        assert_eq!(status, Status::BadRequest, "{}", body);
        assert_eq!(kind(&body), "InvalidOperation");
        assert!(
            harness
                .db
                .fetch_passkey(&account.id, &second.id)
                .await
                .is_ok(),
            "the last passkey was removed"
        );

        // Linked to Google there is another way in, so it may go
        account.google_id = Some(format!("google-{}", TestHarness::rand_string()));
        account.save(&harness.db).await.unwrap();

        let ticket = ticket_for(&harness, &account).await;
        let (status, body) = send(remove(&harness, &second.id), &session, Some(&ticket)).await;
        assert_eq!(status, Status::NoContent, "{}", body);
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 0);

        // An account with a password may remove its only passkey
        let (with_password, with_password_session, _) = harness.new_user().await;
        let only = seed_passkey(&harness, &with_password, "Phone").await;
        let ticket = ticket_for(&harness, &with_password).await;
        let (status, body) = send(
            remove(&harness, &only.id),
            &with_password_session,
            Some(&ticket),
        )
        .await;
        assert_eq!(status, Status::NoContent, "{}", body);
    }
}
