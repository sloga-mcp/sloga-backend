use revolt_database::{
    now_ms, util::audit_reason::AuditLogReason, Database, User, ValidatedTicket,
};
use revolt_models::v0::{self, UserFlags};
use revolt_payments::engine;
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// Largest adjustment either way, in Prot (1 Prot = 1 US cent)
const MAX_ADJUST_PROT: u64 = 1_000_000;

/// # Adjust Prot Wallet
///
/// Credit (positive `amount`) or debit (negative) a user's Prot wallet. A
/// debit never takes the wallet below 0. The `nonce` makes a retry safe: the
/// same nonce with the same user and amount is applied once, and with
/// anything else it is refused. The ledger row records the staff member and
/// the reason. Staff cannot credit their own wallet (`SelfAdjust`); a debit
/// of it is allowed.
///
/// Requires a privileged account, an MFA ticket and `X-Audit-Log-Reason`.
/// Works while Prot is switched off.
#[openapi(tag = "Payments")]
#[post("/prot/adjust", data = "<data>")]
pub async fn adjust_prot(
    db: &State<Database>,
    user: User,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    data: Json<v0::DataProtAdjust>,
) -> Result<Json<v0::ProtAdjustResponse>> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    // Bind the MFA ticket to this user
    if ticket.account_id != user.id {
        return Err(create_error!(InvalidToken));
    }

    let reason = reason.validated()?.ok_or_else(|| {
        create_error!(FailedValidation {
            error: "AuditLogReasonRequired".to_string()
        })
    })?;

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // `unsigned_abs`: `i64::MIN` has no positive counterpart
    if data.amount == 0 || data.amount.unsigned_abs() > MAX_ADJUST_PROT {
        return Err(create_error!(FailedValidation {
            error: format!("amount must be non-zero and at most {MAX_ADJUST_PROT} either way")
        }));
    }

    // The nonce goes into the ledger key and the audit line
    if !super::is_plain_id(&data.nonce) {
        return Err(create_error!(FailedValidation {
            error: "nonce may only contain letters, digits, '-' and '_'".to_string()
        }));
    }

    // Staff never credit their own wallet; taking Prot out of it (a
    // correction) stays possible
    if data.amount > 0 && data.user == user.id {
        return Err(create_error!(FailedValidation {
            error: "SelfAdjust".to_string()
        }));
    }

    let target = match db.fetch_user(&data.user).await {
        Ok(target) if target.flags.unwrap_or_default() & UserFlags::Deleted as i32 == 0 => target,
        Ok(_) => return Err(create_error!(UnknownUser)),
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => {
            return Err(create_error!(UnknownUser))
        }
        Err(err) => return Err(err),
    };

    log::info!(
        "AUDIT prot_adjust: actor={} target={} amount={} nonce={} reason={:?}",
        user.id,
        target.id,
        data.amount,
        data.nonce,
        reason
    );

    // An account deleted after the check above still never keeps a credit:
    // the engine re-checks after it commits and forfeits the wallet
    Ok(Json(
        engine::prot::admin_prot_adjust(db, &user.id, &data, reason, now_ms()).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{error_type, new_staff, validated_ticket, with_own_ticket};
    use crate::util::test::TestHarness;
    use revolt_database::{
        events::client::EventV1, prot_key_admin, prot_user_account, PartialUser, Session,
        PROT_SYS_ADJUST,
    };
    use revolt_models::v0::{self, UserFlags};
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalResponse;
    use serde_json::json;

    /// `POST /admin/prot/adjust` with `body`, as `session`'s user with a fresh
    /// ticket of their own and `reason`
    async fn adjust<'c>(
        harness: &'c TestHarness,
        session: &Session,
        reason: Option<&str>,
        body: serde_json::Value,
    ) -> LocalResponse<'c> {
        let request = harness
            .client
            .post("/admin/prot/adjust")
            .header(ContentType::JSON)
            .body(body.to_string());
        with_own_ticket(harness, request, session, reason)
            .await
            .dispatch()
            .await
    }

    async fn balance(harness: &TestHarness, user_id: &str) -> Option<i64> {
        harness
            .db
            .fetch_prot_account(&prot_user_account(user_id))
            .await
            .expect("account")
            .map(|account| account.balance)
    }

    async fn ledger_row_exists(harness: &TestHarness, admin_id: &str, nonce: &str) -> bool {
        harness
            .db
            .fetch_prot_entry_by_key(&prot_key_admin(admin_id, nonce))
            .await
            .expect("ledger read")
            .is_some()
    }

    #[test]
    fn adjust_refuses_a_non_privileged_user() {
        crate::util::test::rt().block_on(adjust_refuses_a_non_privileged_user_case())
    }

    async fn adjust_refuses_a_non_privileged_user_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        assert!(!user.privileged);

        // Their own valid ticket and a reason: only the privilege is missing.
        // Crediting themselves is the point of the attempt.
        let response = adjust(
            &harness,
            &session,
            Some("free%20money"),
            json!({ "user": user.id, "amount": 5000, "nonce": "self" }),
        )
        .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(error_type(response).await, "NotPrivileged");
        assert_eq!(balance(&harness, &user.id).await, None);
        assert!(!ledger_row_exists(&harness, &user.id, "self").await);
    }

    #[test]
    fn adjust_needs_the_sessions_own_ticket() {
        crate::util::test::rt().block_on(adjust_needs_the_sessions_own_ticket_case())
    }

    async fn adjust_needs_the_sessions_own_ticket_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;
        let (_, _, target) = harness.new_user().await;
        let body = json!({ "user": target.id, "amount": 500, "nonce": "n1" });

        // No ticket
        let response = harness
            .client
            .post("/admin/prot/adjust")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("X-Audit-Log-Reason", "goodwill"))
            .body(body.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized, "no ticket");

        // A validated ticket of another account, with the staff session
        let (attacker, _, _) = harness.new_user().await;
        let foreign = validated_ticket(&harness, &attacker.id).await;
        let response = harness
            .client
            .post("/admin/prot/adjust")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("x-mfa-ticket", foreign.token.clone()))
            .header(Header::new("X-Audit-Log-Reason", "goodwill"))
            .body(body.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden, "foreign ticket");
        assert!(
            harness
                .db
                .fetch_ticket_by_token(&foreign.token)
                .await
                .is_ok(),
            "a ticket that could not authorize the request was consumed"
        );

        // An unvalidated ticket of the staff member's own
        let unvalidated = revolt_database::MFATicket::new(staff.id.clone(), false);
        unvalidated.save(&harness.db).await.expect("`MFATicket`");
        let response = harness
            .client
            .post("/admin/prot/adjust")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("x-mfa-ticket", unvalidated.token.clone()))
            .header(Header::new("X-Audit-Log-Reason", "goodwill"))
            .body(body.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden, "unvalidated ticket");

        // A ticket is single use: the first request claims it, so the second
        // finds no such ticket (the MFATicket guard's 401)
        let ticket = validated_ticket(&harness, &staff.id).await;
        let mut statuses = vec![];
        for nonce in ["once", "twice"] {
            let response = harness
                .client
                .post("/admin/prot/adjust")
                .header(ContentType::JSON)
                .header(Header::new("x-session-token", session.token.clone()))
                .header(Header::new("x-mfa-ticket", ticket.token.clone()))
                .header(Header::new("X-Audit-Log-Reason", "goodwill"))
                .body(json!({ "user": target.id, "amount": 500, "nonce": nonce }).to_string())
                .dispatch()
                .await;
            statuses.push(response.status());
        }
        assert_eq!(
            statuses,
            vec![Status::Ok, Status::Unauthorized],
            "reused ticket"
        );

        assert_eq!(balance(&harness, &target.id).await, Some(500));
        assert!(!ledger_row_exists(&harness, &staff.id, "n1").await);
        assert!(!ledger_row_exists(&harness, &staff.id, "twice").await);
    }

    #[test]
    fn adjust_needs_a_reason() {
        crate::util::test::rt().block_on(adjust_needs_a_reason_case())
    }

    async fn adjust_needs_a_reason_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;
        let (_, _, target) = harness.new_user().await;

        // No header, and one that sanitizes to nothing (space, zero-width
        // space, newline)
        for reason in [None, Some("%20%E2%80%8B%0A")] {
            let response = adjust(
                &harness,
                &session,
                reason,
                json!({ "user": target.id, "amount": 500, "nonce": "n1" }),
            )
            .await;
            assert_eq!(response.status(), Status::BadRequest, "reason {:?}", reason);
            let body = response.into_string().await.expect("body");
            assert!(
                body.contains("AuditLogReasonRequired"),
                "reason {:?}: {}",
                reason,
                body
            );
        }

        let too_long = "a".repeat(513);
        let response = adjust(
            &harness,
            &session,
            Some(&too_long),
            json!({ "user": target.id, "amount": 500, "nonce": "n1" }),
        )
        .await;
        assert_eq!(response.status(), Status::BadRequest, "long reason");
        let body = response.into_string().await.expect("body");
        assert!(body.contains("AuditLogReasonTooLong"), "{}", body);

        assert_eq!(balance(&harness, &target.id).await, None);
        assert!(!ledger_row_exists(&harness, &staff.id, "n1").await);
    }

    #[test]
    fn adjust_refuses_a_bad_amount_or_nonce() {
        crate::util::test::rt().block_on(adjust_refuses_a_bad_amount_or_nonce_case())
    }

    async fn adjust_refuses_a_bad_amount_or_nonce_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;
        let (_, _, target) = harness.new_user().await;

        for (amount, nonce) in [
            (json!(0), "n1"),
            (json!(1_000_001), "n1"),
            (json!(-1_000_001), "n1"),
            (json!(i64::MIN), "n1"),
            (json!(500), ""),
            (json!(500), "has space"),
            (json!(500), "two\nlines"),
            (json!(500), "a:b"),
        ] {
            let response = adjust(
                &harness,
                &session,
                Some("goodwill"),
                json!({ "user": target.id, "amount": amount, "nonce": nonce }),
            )
            .await;
            assert_eq!(
                response.status(),
                Status::BadRequest,
                "amount {} nonce {:?}",
                amount,
                nonce
            );
            assert_eq!(error_type(response).await, "FailedValidation");
        }

        // The bounds themselves are accepted
        for (amount, nonce) in [(1_000_000, "max"), (-1_000_000, "min")] {
            let response = adjust(
                &harness,
                &session,
                Some("goodwill"),
                json!({ "user": target.id, "amount": amount, "nonce": nonce }),
            )
            .await;
            assert_eq!(response.status(), Status::Ok, "amount {}", amount);
        }
        assert_eq!(balance(&harness, &target.id).await, Some(0));
    }

    #[test]
    fn adjust_refuses_an_unknown_or_deleted_target() {
        crate::util::test::rt().block_on(adjust_refuses_an_unknown_or_deleted_target_case())
    }

    async fn adjust_refuses_an_unknown_or_deleted_target_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;
        let (_, _, mut deleted) = harness.new_user().await;
        deleted
            .update(
                &harness.db,
                PartialUser {
                    flags: Some(UserFlags::Deleted as i32),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("mark deleted");

        for target in [ulid::Ulid::new().to_string(), deleted.id.clone()] {
            let response = adjust(
                &harness,
                &session,
                Some("goodwill"),
                json!({ "user": target, "amount": 500, "nonce": "n1" }),
            )
            .await;
            assert_eq!(response.status(), Status::NotFound, "{}", target);
            assert_eq!(error_type(response).await, "UnknownUser", "{}", target);
            assert_eq!(balance(&harness, &target).await, None);
        }
    }

    #[test]
    fn adjust_credits_and_debits_with_the_admin_on_the_row() {
        crate::util::test::rt().block_on(adjust_credits_and_debits_with_the_admin_on_the_row_case())
    }

    async fn adjust_credits_and_debits_with_the_admin_on_the_row_case() {
        let mut harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;
        let (_, _, target) = harness.new_user().await;
        let wallet = prot_user_account(&target.id);

        // Credit 500
        let response = adjust(
            &harness,
            &session,
            Some("goodwill%20credit%20%E2%80%94%20ticket%2042"),
            json!({ "user": target.id, "amount": 500, "nonce": "credit-1" }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let credit = response
            .into_json::<v0::ProtAdjustResponse>()
            .await
            .expect("`ProtAdjustResponse`");
        assert_eq!(credit.balance, 500);
        assert!(!credit.already_applied);

        let row = harness
            .db
            .fetch_prot_entry_by_key(&prot_key_admin(&staff.id, "credit-1"))
            .await
            .expect("ledger read")
            .expect("the credit's row");
        assert_eq!(row.id, credit.entry_id);
        assert_eq!(row.kind, v0::ProtEntryKind::AdminAdjust);
        assert_eq!(
            (row.debit.as_str(), row.credit.as_str()),
            (PROT_SYS_ADJUST, wallet.as_str())
        );
        assert_eq!(row.amount, 500);
        // The audit record: who did it, and why (decoded)
        assert_eq!(row.actor, staff.id);
        assert_eq!(
            row.reason.as_deref(),
            Some("goodwill credit \u{2014} ticket 42")
        );

        // The owner's private topic hears the new balance
        let event = harness
            .wait_for_event(&format!("{}!", target.id), |event| {
                matches!(event, EventV1::ProtBalanceUpdate { balance: 500, .. })
            })
            .await;
        assert!(matches!(event, EventV1::ProtBalanceUpdate { .. }));

        // A retry (another reason, a new ticket) is applied once
        let response = adjust(
            &harness,
            &session,
            Some("retry"),
            json!({ "user": target.id, "amount": 500, "nonce": "credit-1" }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let retry = response
            .into_json::<v0::ProtAdjustResponse>()
            .await
            .expect("`ProtAdjustResponse`");
        assert!(retry.already_applied);
        assert_eq!(retry.entry_id, credit.entry_id);
        assert_eq!(retry.balance, 500);

        // The same nonce for another amount is a conflict, not a second credit
        let response = adjust(
            &harness,
            &session,
            Some("retry"),
            json!({ "user": target.id, "amount": 900, "nonce": "credit-1" }),
        )
        .await;
        assert_eq!(response.status(), Status::Conflict);
        assert_eq!(error_type(response).await, "ProtIdempotencyConflict");
        assert_eq!(balance(&harness, &target.id).await, Some(500));

        // Debit 200
        let response = adjust(
            &harness,
            &session,
            Some("correction"),
            json!({ "user": target.id, "amount": -200, "nonce": "debit-1" }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let debit = response
            .into_json::<v0::ProtAdjustResponse>()
            .await
            .expect("`ProtAdjustResponse`");
        assert_eq!(debit.balance, 300);
        let row = harness
            .db
            .fetch_prot_entry_by_key(&prot_key_admin(&staff.id, "debit-1"))
            .await
            .expect("ledger read")
            .expect("the debit's row");
        assert_eq!(
            (row.debit.as_str(), row.credit.as_str()),
            (wallet.as_str(), PROT_SYS_ADJUST)
        );
        assert_eq!(row.amount, 200);
        assert_eq!(row.actor, staff.id);

        // A debit beyond the balance moves nothing
        let response = adjust(
            &harness,
            &session,
            Some("correction"),
            json!({ "user": target.id, "amount": -301, "nonce": "debit-2" }),
        )
        .await;
        assert_eq!(response.status(), Status::Conflict);
        let body = response.into_string().await.expect("body");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            (&value["type"], &value["needed"], &value["available"]),
            (&json!("InsufficientProt"), &json!(301), &json!(300)),
            "{}",
            body
        );
        assert_eq!(balance(&harness, &target.id).await, Some(300));
        assert!(!ledger_row_exists(&harness, &staff.id, "debit-2").await);
    }

    #[test]
    fn adjust_refuses_a_credit_to_the_staff_members_own_wallet() {
        crate::util::test::rt()
            .block_on(adjust_refuses_a_credit_to_the_staff_members_own_wallet_case())
    }

    /// A credit to the caller's own wallet is refused (SelfAdjust) and writes
    /// nothing; a debit of it goes through
    async fn adjust_refuses_a_credit_to_the_staff_members_own_wallet_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;
        let (other_session, _) = new_staff(&harness).await;

        let response = adjust(
            &harness,
            &session,
            Some("goodwill"),
            json!({ "user": staff.id, "amount": 500, "nonce": "self-1" }),
        )
        .await;
        assert_eq!(response.status(), Status::BadRequest);
        let body = response.into_string().await.expect("body");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            (&value["type"], &value["error"]),
            (&json!("FailedValidation"), &json!("SelfAdjust")),
            "{}",
            body
        );
        assert_eq!(balance(&harness, &staff.id).await, None);
        assert!(!ledger_row_exists(&harness, &staff.id, "self-1").await);

        // Another staff member may credit them, and they may debit themselves
        let response = adjust(
            &harness,
            &other_session,
            Some("goodwill"),
            json!({ "user": staff.id, "amount": 500, "nonce": "credit-1" }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let response = adjust(
            &harness,
            &session,
            Some("correction"),
            json!({ "user": staff.id, "amount": -200, "nonce": "self-2" }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(balance(&harness, &staff.id).await, Some(300));
        assert!(ledger_row_exists(&harness, &staff.id, "self-2").await);
    }
}
