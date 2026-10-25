use revolt_database::{util::audit_reason::AuditLogReason, Database, User, ValidatedTicket};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch Prot Order
///
/// What a payment order credited and clawed back in Prot, and the buyer's
/// unspent balance. For a Cipher order of the buyer's current membership it
/// also shows that membership's posted Prot, target and shortfall. Support
/// reads this before refunding an order in the Stripe Dashboard.
///
/// Requires a privileged account, an MFA ticket and `X-Audit-Log-Reason`.
/// Works while Prot is switched off.
#[openapi(tag = "Payments")]
#[get("/prot/orders/<order_id>")]
pub async fn fetch_prot_order(
    db: &State<Database>,
    user: User,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    order_id: String,
) -> Result<Json<v0::ProtAdminOrder>> {
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

    // Order ids are ULIDs: anything else names no order, and is never
    // copied into the audit line
    if !super::is_plain_id(&order_id) {
        return Err(create_error!(NotFound));
    }

    log::info!(
        "AUDIT prot_order_read: actor={} order={} reason={:?}",
        user.id,
        order_id,
        reason
    );

    Ok(Json(engine::prot::admin_prot_order(db, &order_id).await?))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{error_type, new_staff, with_own_ticket};
    use crate::util::test::TestHarness;
    use revolt_database::{
        now_ms, prot_key_admin, prot_key_purchase, prot_user_account, CipherMembership,
        CipherProtSync, CipherRevokeReason, OrderState, PaymentOrder, PaymentProvider, ProtAmount,
        ProtApplyOutcome, ProtPosting, ProtRef, PROT_ACTOR_PAYMENTS, PROT_SYS_ADJUST,
        PROT_SYS_CLAWED, PROT_SYS_ISSUED,
    };
    use revolt_models::v0;
    use rocket::http::Status;
    use ulid::Ulid;

    fn order(id: &str, user_id: Option<&str>, sku: v0::Sku) -> PaymentOrder {
        let now = now_ms();
        PaymentOrder {
            id: id.to_string(),
            user_id: user_id.map(str::to_string),
            provider: PaymentProvider::Stripe,
            sku,
            amount_cents: 2500,
            currency: "usd".to_string(),
            checkout_session_id: None,
            checkout_url: None,
            session_expires_at: None,
            payment_intent_id: None,
            state: OrderState::Fulfilled,
            void_reason: None,
            region_blocked_country: None,
            reversal_pending: None,
            refund_settling_since: None,
            open_disputes: vec![],
            lease_until: None,
            version: 0,
            created_at: now,
            paid_at: Some(now),
            fulfilled_at: Some(now),
            reversed_at: None,
        }
    }

    fn posting(
        key: String,
        kind: v0::ProtEntryKind,
        debit: String,
        credit: String,
        amount: ProtAmount,
        order_id: Option<&str>,
    ) -> ProtPosting {
        ProtPosting {
            key,
            kind,
            debit,
            credit,
            amount,
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef {
                order_id: order_id.map(str::to_string),
                ..Default::default()
            },
            reason: None,
            created_at: now_ms(),
        }
    }

    /// `GET /admin/prot/orders/<order_id>` as staff with a reason
    async fn read_order(
        harness: &TestHarness,
        session: &revolt_database::Session,
        order_id: &str,
    ) -> v0::ProtAdminOrder {
        let request = harness
            .client
            .get(format!("/admin/prot/orders/{}", order_id));
        let response = with_own_ticket(harness, request, session, Some("refund%20check"))
            .await
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "read {}", order_id);
        response
            .into_json::<v0::ProtAdminOrder>()
            .await
            .expect("`ProtAdminOrder`")
    }

    #[test]
    fn order_read_refuses_a_non_privileged_user() {
        crate::util::test::rt().block_on(order_read_refuses_a_non_privileged_user_case())
    }

    async fn order_read_refuses_a_non_privileged_user_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        assert!(!user.privileged);

        let id = Ulid::new().to_string();
        harness
            .db
            .insert_payment_order(&order(
                &id,
                Some(&user.id),
                v0::Sku::ProtExact { prot: 2500 },
            ))
            .await
            .expect("order");

        // Their own valid ticket and a reason: only the privilege is missing
        let request = harness.client.get(format!("/admin/prot/orders/{}", id));
        let response = with_own_ticket(&harness, request, &session, Some("curious"))
            .await
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(error_type(response).await, "NotPrivileged");
    }

    #[test]
    fn order_read_needs_a_ticket_and_a_reason() {
        crate::util::test::rt().block_on(order_read_needs_a_ticket_and_a_reason_case())
    }

    async fn order_read_needs_a_ticket_and_a_reason_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;
        let id = Ulid::new().to_string();
        harness
            .db
            .insert_payment_order(&order(
                &id,
                Some(&staff.id),
                v0::Sku::ProtExact { prot: 2500 },
            ))
            .await
            .expect("order");
        let path = format!("/admin/prot/orders/{}", id);

        // No MFA ticket at all
        let response = harness
            .client
            .get(path.clone())
            .header(rocket::http::Header::new(
                "x-session-token",
                session.token.clone(),
            ))
            .header(rocket::http::Header::new("X-Audit-Log-Reason", "check"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized, "no ticket");

        // No reason, and a reason that sanitizes to nothing
        for reason in [None, Some("%20%E2%80%8B%0A")] {
            let response =
                with_own_ticket(&harness, harness.client.get(path.clone()), &session, reason)
                    .await
                    .dispatch()
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

        // With both, the read goes through
        read_order(&harness, &session, &id).await;
    }

    #[test]
    fn order_read_of_an_unknown_order_is_not_found() {
        crate::util::test::rt().block_on(order_read_of_an_unknown_order_is_not_found_case())
    }

    async fn order_read_of_an_unknown_order_is_not_found_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;

        for id in [Ulid::new().to_string(), "not%0Aan%20id".to_string()] {
            let request = harness.client.get(format!("/admin/prot/orders/{}", id));
            let response = with_own_ticket(&harness, request, &session, Some("check"))
                .await
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::NotFound, "{}", id);
            assert_eq!(error_type(response).await, "NotFound", "{}", id);
        }
    }

    #[test]
    fn order_read_sums_a_prot_order() {
        crate::util::test::rt().block_on(order_read_sums_a_prot_order_case())
    }

    async fn order_read_sums_a_prot_order_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;
        let (_, _, buyer) = harness.new_user().await;
        let wallet = prot_user_account(&buyer.id);

        let id = Ulid::new().to_string();
        let sku = v0::Sku::ProtPack {
            pack: "p25".to_string(),
            prot: 2600,
            cents: 2500,
        };
        harness
            .db
            .insert_payment_order(&order(&id, Some(&buyer.id), sku.clone()))
            .await
            .expect("order");

        // Credited 2,600; 600 spent (an admin debit); then the order is
        // reversed and its clawback recovers the 2,000 left
        for p in [
            posting(
                prot_key_purchase(&id),
                v0::ProtEntryKind::Purchase,
                PROT_SYS_ISSUED.to_string(),
                wallet.clone(),
                ProtAmount::Exact(2600),
                Some(&id),
            ),
            posting(
                prot_key_admin(&staff.id, "spend"),
                v0::ProtEntryKind::AdminAdjust,
                wallet.clone(),
                PROT_SYS_ADJUST.to_string(),
                ProtAmount::Exact(600),
                None,
            ),
        ] {
            harness.db.apply_prot_posting(&p).await.expect("posting");
        }

        let before = read_order(&harness, &session, &id).await;
        assert_eq!(before.order_id, id);
        assert_eq!(before.user_id.as_deref(), Some(buyer.id.as_str()));
        assert_eq!(before.sku, sku);
        assert_eq!(
            (before.credited, before.clawed_back, before.shortfall),
            (2600, 0, 0)
        );
        assert_eq!(before.unspent, Some(2000));

        let clawback = posting(
            revolt_database::prot_key_clawback(&id),
            v0::ProtEntryKind::Clawback,
            wallet.clone(),
            PROT_SYS_CLAWED.to_string(),
            ProtAmount::UpTo(2600),
            Some(&id),
        );
        harness
            .db
            .apply_prot_posting(&clawback)
            .await
            .expect("clawback");

        let after = read_order(&harness, &session, &id).await;
        assert_eq!(
            (after.credited, after.clawed_back, after.shortfall),
            (2600, 2000, 600)
        );
        assert_eq!(after.unspent, Some(0));
        // Not a Cipher order: no membership figures, and the keys are left out
        assert_eq!(
            (
                after.membership_posted,
                after.membership_target,
                after.membership_shortfall
            ),
            (None, None, None)
        );

        let request = harness.client.get(format!("/admin/prot/orders/{}", id));
        let body = with_own_ticket(&harness, request, &session, Some("check"))
            .await
            .dispatch()
            .await
            .into_string()
            .await
            .expect("body");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        for key in [
            "membership_posted",
            "membership_target",
            "membership_shortfall",
        ] {
            assert!(value.get(key).is_none(), "{} serialized: {}", key, body);
        }
    }

    #[test]
    fn order_read_shows_the_current_cipher_membership() {
        crate::util::test::rt().block_on(order_read_shows_the_current_cipher_membership_case())
    }

    async fn order_read_shows_the_current_cipher_membership_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;
        let (_, _, buyer) = harness.new_user().await;
        let wallet = prot_user_account(&buyer.id);
        let sku = v0::Sku::CipherNew {
            tier: v0::CipherTier::T149,
        };

        // `old` belongs to an earlier incarnation (an older ULID than the
        // current membership's base order)
        let now = now_ms();
        let old = Ulid::from_parts(now as u64 - 60_000, 1).to_string();
        let base = Ulid::from_parts(now as u64, 1).to_string();
        assert!(old < base);
        for id in [&old, &base] {
            harness
                .db
                .insert_payment_order(&order(id, Some(&buyer.id), sku.clone()))
                .await
                .expect("order");
        }

        let membership = CipherMembership {
            user_id: buyer.id.clone(),
            number: 7,
            tier: v0::CipherTier::T149,
            prot_grant: 33_000,
            orders: vec![base.clone()],
            disputed_orders: vec![],
            granted_at: now,
            revoked_at: None,
            revoke_reason: None,
            prot_posted_at: None,
            version: 0,
        };
        assert!(harness
            .db
            .insert_cipher_membership(&membership)
            .await
            .expect("membership"));
        let synced = harness
            .db
            .sync_cipher_prot(&buyer.id, now)
            .await
            .expect("sync");
        assert!(
            matches!(synced, CipherProtSync::Posted(ProtApplyOutcome::Applied(_))),
            "{:?}",
            synced
        );

        let read = read_order(&harness, &session, &base).await;
        assert_eq!(read.sku, sku);
        assert_eq!(
            (read.credited, read.clawed_back, read.shortfall),
            (33_000, 0, 0)
        );
        assert_eq!(read.unspent, Some(33_000));
        assert_eq!(
            (
                read.membership_posted,
                read.membership_target,
                read.membership_shortfall
            ),
            (Some(33_000), Some(33_000), Some(0))
        );

        // An order of a replaced incarnation never shows today's membership
        let stale = read_order(&harness, &session, &old).await;
        assert_eq!(
            (stale.credited, stale.clawed_back, stale.shortfall),
            (0, 0, 0)
        );
        assert_eq!(stale.unspent, Some(33_000));
        assert_eq!(
            (
                stale.membership_posted,
                stale.membership_target,
                stale.membership_shortfall
            ),
            (None, None, None)
        );

        // 1,000 is spent, then the membership is revoked and clawed back:
        // 32,000 recovered, 1,000 short, settled to a target of 0
        harness
            .db
            .apply_prot_posting(&posting(
                prot_key_admin(&staff.id, "spend"),
                v0::ProtEntryKind::AdminAdjust,
                wallet.clone(),
                PROT_SYS_ADJUST.to_string(),
                ProtAmount::Exact(1000),
                None,
            ))
            .await
            .expect("spend");
        let mut revoked = harness
            .db
            .fetch_cipher_membership(&buyer.id)
            .await
            .expect("fetch")
            .expect("membership");
        let expected = revoked.version;
        revoked.revoked_at = Some(now_ms());
        revoked.revoke_reason = Some(CipherRevokeReason::Refund);
        assert!(harness
            .db
            .update_cipher_membership_if_version(&revoked, expected)
            .await
            .expect("revoke"));
        let clawed = harness
            .db
            .clawback_cipher_prot(&buyer.id, &base, now_ms())
            .await
            .expect("clawback")
            .expect("a clawback row");
        assert_eq!(clawed.entry().amount, 32_000);

        let read = read_order(&harness, &session, &base).await;
        assert_eq!(
            (read.credited, read.clawed_back, read.shortfall),
            (33_000, 32_000, 1_000)
        );
        assert_eq!(read.unspent, Some(0));
        assert_eq!(
            (
                read.membership_posted,
                read.membership_target,
                read.membership_shortfall
            ),
            (Some(0), Some(0), Some(1_000))
        );
    }
}
