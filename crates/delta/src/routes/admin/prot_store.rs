use std::sync::Arc;

use revolt_database::{
    is_store_purchase_id, now_ms, util::audit_reason::AuditLogReason, Database, User,
    ValidatedTicket,
};
use revolt_models::v0::{self, UserFlags};
use revolt_payments::engine;
use revolt_payments::settings::{ProtSalesSettings, ProtStoreSettings};
use revolt_payments::store::{AppleStoreApi, PlayStoreApi};
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// The S5 staff guards, in order: a privileged account, the MFA ticket bound
/// to this user, a non-empty `X-Audit-Log-Reason` (returned, sanitized)
fn staff_reason(user: &User, ticket: &ValidatedTicket, reason: AuditLogReason) -> Result<String> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    // Bind the MFA ticket to this user
    if ticket.account_id != user.id {
        return Err(create_error!(InvalidToken));
    }

    reason.validated()?.ok_or_else(|| {
        create_error!(FailedValidation {
            error: "AuditLogReasonRequired".to_string()
        })
    })
}

/// Store purchase ids carry `:` (`apple:prod:…`, `apple:sandbox:…`,
/// `play:…`), so `is_plain_id` would refuse every one. Anything else names no
/// purchase and is never copied into the audit line.
fn check_purchase_id(id: &str) -> Result<()> {
    if is_store_purchase_id(id) {
        Ok(())
    } else {
        Err(create_error!(NotFound))
    }
}

/// # Fetch Prot Store Purchase
///
/// One App Store or Google Play purchase of Prot: its row, every ledger row
/// it moved (oldest first) and the buyer's current balance. Ids look like
/// `apple:prod:<transactionId>`, `apple:sandbox:<transactionId>` or
/// `play:<sha256 of the purchase token>`.
///
/// Requires a privileged account, an MFA ticket and `X-Audit-Log-Reason`.
/// Works while Prot and the stores are switched off.
#[openapi(tag = "Payments")]
#[get("/prot/store/<id>")]
pub async fn fetch_prot_store_purchase(
    db: &State<Database>,
    user: User,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
) -> Result<Json<v0::ProtStoreAdminPurchase>> {
    let reason = staff_reason(&user, &ticket, reason)?;
    check_purchase_id(&id)?;

    log::info!(
        "AUDIT prot_store_read: actor={} id={} reason={:?}",
        user.id,
        id,
        reason
    );

    Ok(Json(
        engine::prot_store::admin_store_purchase(db, &id).await?,
    ))
}

/// # List Prot Store Work Items
///
/// The store purchases that need staff action (an unbound purchase, a
/// reversal that re-credited nothing, a Play refund review, a Play credit
/// still unconsumed), newest first, at most 100. Only the work list is
/// served: `needs_action=true` is required.
///
/// Requires a privileged account, an MFA ticket and `X-Audit-Log-Reason`.
/// Works while Prot and the stores are switched off.
#[openapi(tag = "Payments")]
#[get("/prot/store?<needs_action>")]
pub async fn list_prot_store_needs_action(
    db: &State<Database>,
    user: User,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    needs_action: Option<bool>,
) -> Result<Json<Vec<v0::ProtStorePurchaseView>>> {
    let reason = staff_reason(&user, &ticket, reason)?;

    // No unfiltered listing of purchases
    if needs_action != Some(true) {
        return Err(create_error!(FailedValidation {
            error: "only the work list is served: pass needs_action=true".to_string()
        }));
    }

    log::info!(
        "AUDIT prot_store_list: actor={} id=- reason={:?}",
        user.id,
        reason
    );

    Ok(Json(
        engine::prot_store::admin_store_needs_action(db).await?,
    ))
}

/// # Assign Prot Store Purchase
///
/// Credit a purchase that no purchase intent binds (`rejected`, reason
/// `unbound`) to the account support identified. The target must exist and
/// be a live, non-bot account other than the staff member's own. The
/// purchase is looked up at the store first: unknown there, refunded,
/// voided or cancelled → `InvalidOperation` (a refund is recorded on the
/// row); a failed lookup → 500, nothing written. A test purchase or one with
/// no Prot is never assigned. While store credits are paused the purchase is
/// recorded held instead of credited.
///
/// Requires a privileged account, an MFA ticket and `X-Audit-Log-Reason`.
/// Works while Prot and the stores are closed for sale.
#[openapi(tag = "Payments")]
#[post("/prot/store/<id>/assign", data = "<data>")]
#[allow(clippy::too_many_arguments)]
pub async fn assign_prot_store_purchase(
    db: &State<Database>,
    apple: &State<Arc<dyn AppleStoreApi>>,
    play: &State<Arc<dyn PlayStoreApi>>,
    user: User,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
    data: Json<v0::DataProtStoreAssign>,
) -> Result<Json<v0::ProtStoreAdminPurchase>> {
    let reason = staff_reason(&user, &ticket, reason)?;
    check_purchase_id(&id)?;

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // The target goes into the audit line: a value no account id can be
    // names no account
    if !super::is_plain_id(&data.user_id) {
        return Err(create_error!(NotFound));
    }

    log::info!(
        "AUDIT prot_store_assign: actor={} id={} target={} reason={:?}",
        user.id,
        id,
        data.user_id,
        reason
    );

    // Staff never assign a purchase to their own account (owner, S6 Q4)
    if data.user_id == user.id {
        return Err(create_error!(InvalidOperation));
    }

    let target = match db.fetch_user(&data.user_id).await {
        Ok(target) => target,
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => {
            return Err(create_error!(NotFound))
        }
        Err(err) => return Err(err),
    };
    if target.bot.is_some() || target.flags.unwrap_or_default() & UserFlags::Deleted as i32 != 0 {
        return Err(create_error!(InvalidOperation));
    }

    // Loaded, never defaulted: nothing is credited under a config that does
    // not validate. Only the credit pause and the store credentials are
    // read; the open-for-sale flags are not.
    let ps = ProtSalesSettings::load().await?;
    let st = ProtStoreSettings::load().await?;
    let apple: &dyn AppleStoreApi = &**apple.inner();
    let play: &dyn PlayStoreApi = &**play.inner();

    // The engine checks the target again, asks the store and moves the row
    Ok(Json(
        engine::prot_store::admin_assign_store_purchase(
            db,
            &ps,
            &st,
            apple,
            play,
            &user.id,
            &id,
            &target.id,
            now_ms(),
        )
        .await?,
    ))
}

/// # Resolve Prot Store Work Item
///
/// Clear a purchase's `reversed_unpaid` or `chargeback_review` work item
/// once support has handled it. `kind` must be the item the purchase holds;
/// anything else is `InvalidOperation`. No Prot moves.
///
/// Requires a privileged account, an MFA ticket and `X-Audit-Log-Reason`.
/// Works while Prot and the stores are switched off.
#[openapi(tag = "Payments")]
#[post("/prot/store/<id>/resolve", data = "<data>")]
pub async fn resolve_prot_store_purchase(
    db: &State<Database>,
    user: User,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
    data: Json<v0::DataProtStoreResolve>,
) -> Result<Json<v0::ProtStoreAdminPurchase>> {
    let reason = staff_reason(&user, &ticket, reason)?;
    check_purchase_id(&id)?;

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    log::info!(
        "AUDIT prot_store_resolve: actor={} id={} reason={:?}",
        user.id,
        id,
        reason
    );

    Ok(Json(
        engine::prot_store::admin_resolve_store_purchase(db, &user.id, &id, &data.kind, now_ms())
            .await?,
    ))
}

/// # Release Over-Cap Prot Store Purchase
///
/// Credit a purchase held because crediting it would have taken its buyer's
/// Prot wallet over the cap (`held`, hold reason `over_cap`), ignoring the
/// cap. Anything else is `InvalidOperation`, as is a buyer who is the staff
/// member, a bot, deleted or gone, and any release while store credits are
/// paused. The purchase is looked up at the store first: refunded, voided
/// or cancelled → the refund is recorded on the row, nothing is credited,
/// `InvalidOperation`; unknown there → `InvalidOperation`; a failed lookup
/// → 500, nothing written. A Google Play purchase is consumed after its
/// credit. The `over_cap_review` work item is cleared.
///
/// Requires a privileged account, an MFA ticket and `X-Audit-Log-Reason`.
/// Works while Prot and the stores are closed for sale.
#[openapi(tag = "Payments")]
#[post("/prot/store/<id>/release")]
pub async fn release_prot_store_purchase(
    db: &State<Database>,
    apple: &State<Arc<dyn AppleStoreApi>>,
    play: &State<Arc<dyn PlayStoreApi>>,
    user: User,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
) -> Result<Json<v0::ProtStoreAdminPurchase>> {
    let reason = staff_reason(&user, &ticket, reason)?;
    check_purchase_id(&id)?;

    log::info!(
        "AUDIT prot_store_release: actor={} id={} reason={:?}",
        user.id,
        id,
        reason
    );

    // Loaded, never defaulted (R64): only the credit pause and the store
    // credentials are read; the open-for-sale flags are not
    let st = ProtStoreSettings::load().await?;
    let apple: &dyn AppleStoreApi = &**apple.inner();
    let play: &dyn PlayStoreApi = &**play.inner();

    // The engine refuses self, bots and deleted buyers, asks the store and
    // moves the row
    Ok(Json(
        engine::prot_store::admin_release_store_purchase(
            db,
            &st,
            apple,
            play,
            &user.id,
            &id,
            now_ms(),
        )
        .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{error_type, new_staff, with_own_ticket};
    use crate::util::test::{without_comments, TestHarness};
    use revolt_database::util::prot_store_alert::{
        PROT_STORE_NEEDS_CHARGEBACK, PROT_STORE_NEEDS_OVER_CAP, PROT_STORE_NEEDS_REVERSED_UNPAID,
        PROT_STORE_NEEDS_UNBOUND,
    };
    use revolt_database::{
        build_store_move, now_ms, plan_store_move, prot_store_key_purchase, prot_user_account,
        BotInformation, PartialUser, ProtStoreApple, ProtStoreEvent, ProtStoreIntent,
        ProtStoreMoveOutcome, ProtStorePlay, ProtStorePurchase, ProtStoreVerdict, Session,
    };
    use revolt_models::v0::{self, UserFlags};
    use revolt_payments::store::{
        PlayLineItem, PlayOfferDetails, PlayPurchase, PlayStateContext, StoreApiError,
        PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED, PLAY_PURCHASE_STATE_CANCELLED,
        PLAY_PURCHASE_STATE_PURCHASED,
    };
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalResponse;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use ulid::Ulid;

    /// A Play product of the test config (500 Prot)
    const P5: &str = "gg.sloga.prot.p5";
    const P5_PROT: i64 = 500;

    /// A fresh purchase token
    fn token() -> String {
        format!("l2g-token.{}", Ulid::new())
    }

    /// The purchase id of a Play purchase token
    fn play_id(token: &str) -> String {
        let hash: String = Sha256::digest(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("play:{hash}")
    }

    /// A Play purchase of `P5` as first seen
    fn play_seed(token: &str, environment: v0::ProtStoreEnvironment) -> ProtStorePurchase {
        let now = now_ms();
        ProtStorePurchase {
            id: play_id(token),
            store: v0::ProtStore::Play,
            user_id: None,
            intent_id: None,
            product_id: P5.to_string(),
            prot: P5_PROT,
            quantity: 1,
            environment,
            storefront: None,
            country: None,
            state: v0::ProtStoreState::Rejected,
            reject_reason: None,
            hold_reason: None,
            refund_gen: 0,
            refunds: vec![],
            unreinstated_reversals: 0,
            apple: None,
            play: Some(ProtStorePlay {
                purchase_token: token.to_string(),
                order_id: Some("GPA.L2G".to_string()),
                obfuscated_account_id: None,
                consumed_at: None,
                test: environment == v0::ProtStoreEnvironment::Sandbox,
                region_code: Some("US".to_string()),
            }),
            credited_at: None,
            unconsumed: None,
            revoked_at: None,
            revocation_reason: None,
            assigned_by: None,
            needs_action: None,
            alerted: vec![],
            created_at: now,
            updated_at: now,
            version: 0,
        }
    }

    /// An App Store purchase as first seen (`apple:prod:<transaction_id>`)
    fn apple_seed(transaction_id: &str) -> ProtStorePurchase {
        let now = now_ms();
        ProtStorePurchase {
            id: format!("apple:prod:{transaction_id}"),
            store: v0::ProtStore::Apple,
            play: None,
            apple: Some(ProtStoreApple {
                transaction_id: transaction_id.to_string(),
                original_transaction_id: transaction_id.to_string(),
                app_account_token: None,
                signed_date: now,
                purchase_date: now,
            }),
            product_id: P5.to_string(),
            ..play_seed("unused", v0::ProtStoreEnvironment::Production)
        }
    }

    /// `seed` written as a purchase no intent binds (Rejected{Unbound}, work
    /// item `unbound`), through the planner, the move builder and the
    /// one-transaction move, as the engine writes it
    async fn unbound(harness: &TestHarness, seed: &ProtStorePurchase) -> ProtStorePurchase {
        let event = ProtStoreEvent::Seen(ProtStoreVerdict::Reject {
            reason: v0::ProtStoreRejectReason::Unbound,
            user_id: None,
            intent_id: None,
        });
        let plan = plan_store_move(None, &event, 0);
        let m = build_store_move(None, seed, &event, &plan, 0, now_ms()).expect("a move");
        match harness
            .db
            .apply_store_purchase_move(&m)
            .await
            .expect("store move")
        {
            ProtStoreMoveOutcome::Applied { row, .. } => {
                assert_eq!(row.state, v0::ProtStoreState::Rejected);
                assert_eq!(row.reject_reason, Some(v0::ProtStoreRejectReason::Unbound));
                assert_eq!(row.needs_action.as_deref(), Some(PROT_STORE_NEEDS_UNBOUND));
                row
            }
            ProtStoreMoveOutcome::Conflict => panic!("a first write conflicted"),
        }
    }

    /// `seed` written as the engine writes a purchase held over the wallet
    /// cap for `buyer` (R63: Held, hold reason `over_cap`, work item
    /// `over_cap_review`), through a fresh Open intent of the buyer
    async fn over_cap(
        harness: &TestHarness,
        seed: &ProtStorePurchase,
        buyer: &str,
    ) -> ProtStorePurchase {
        let now = now_ms();
        let intent = ProtStoreIntent {
            id: Ulid::new().to_string(),
            user_id: Some(buyer.to_string()),
            store: seed.store,
            product_id: seed.product_id.clone(),
            prot: seed.prot,
            token: format!("r63-intent.{}", Ulid::new()),
            state: v0::ProtStoreIntentState::Open,
            purchase_id: None,
            created_at: now,
            expires_at: now + 86_400_000,
        };
        harness
            .db
            .insert_prot_store_intent(&intent)
            .await
            .expect("intent");
        let event = ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
            user_id: buyer.to_string(),
            intent_id: intent.id.clone(),
            reason: v0::ProtStoreHoldReason::OverCap,
        });
        let plan = plan_store_move(None, &event, 0);
        let m = build_store_move(None, seed, &event, &plan, 0, now).expect("a move");
        match harness
            .db
            .apply_store_purchase_move(&m)
            .await
            .expect("store move")
        {
            ProtStoreMoveOutcome::Applied { row, .. } => {
                assert_eq!(row.state, v0::ProtStoreState::Held);
                assert_eq!(row.hold_reason, Some(v0::ProtStoreHoldReason::OverCap));
                assert_eq!(row.needs_action.as_deref(), Some(PROT_STORE_NEEDS_OVER_CAP));
                row
            }
            ProtStoreMoveOutcome::Conflict => panic!("a first write conflicted"),
        }
    }

    /// What Play answers for a purchase of `P5` in `state`
    fn at_play(state: &str) -> PlayPurchase {
        PlayPurchase {
            product_line_item: vec![PlayLineItem {
                product_id: P5.to_string(),
                product_offer_details: PlayOfferDetails {
                    quantity: Some(1),
                    refundable_quantity: Some(1),
                    consumption_state: Some(PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED.to_string()),
                },
            }],
            purchase_state_context: PlayStateContext {
                purchase_state: state.to_string(),
            },
            test_purchase_context: None,
            order_id: Some("GPA.L2G".to_string()),
            obfuscated_external_account_id: None,
            region_code: Some("US".to_string()),
            purchase_completion_time: None,
            acknowledgement_state: None,
        }
    }

    async fn stored(harness: &TestHarness, id: &str) -> ProtStorePurchase {
        harness
            .db
            .fetch_prot_store_purchase(id)
            .await
            .expect("row read")
            .expect("the row")
    }

    async fn balance(harness: &TestHarness, user_id: &str) -> Option<i64> {
        harness
            .db
            .fetch_prot_account(&prot_user_account(user_id))
            .await
            .expect("account")
            .map(|account| account.balance)
    }

    async fn credited(harness: &TestHarness, id: &str) -> bool {
        harness
            .db
            .fetch_prot_entry_by_key(&prot_store_key_purchase(id))
            .await
            .expect("ledger read")
            .is_some()
    }

    /// The row did not move: same version, same state, no user, no credit
    async fn assert_untouched(harness: &TestHarness, before: &ProtStorePurchase) {
        let after = stored(harness, &before.id).await;
        assert_eq!(&after, before, "{}: the row moved", before.id);
        assert!(
            !credited(harness, &before.id).await,
            "{}: credited",
            before.id
        );
    }

    /// `GET path` as `session`'s user with a fresh ticket of their own and
    /// `reason`
    async fn get<'c>(
        harness: &'c TestHarness,
        session: &Session,
        reason: Option<&str>,
        path: &str,
    ) -> LocalResponse<'c> {
        let request = harness.client.get(path.to_string());
        with_own_ticket(harness, request, session, reason)
            .await
            .dispatch()
            .await
    }

    /// `POST path` with a JSON `body`, as `get`
    async fn post<'c>(
        harness: &'c TestHarness,
        session: &Session,
        reason: Option<&str>,
        path: &str,
        body: serde_json::Value,
    ) -> LocalResponse<'c> {
        let request = harness
            .client
            .post(path.to_string())
            .header(ContentType::JSON)
            .body(body.to_string());
        with_own_ticket(harness, request, session, reason)
            .await
            .dispatch()
            .await
    }

    async fn assign<'c>(
        harness: &'c TestHarness,
        session: &Session,
        id: &str,
        user_id: &str,
    ) -> LocalResponse<'c> {
        post(
            harness,
            session,
            Some("unbound%20purchase%20ticket%2042"),
            &format!("/admin/prot/store/{}/assign", id),
            json!({ "user_id": user_id }),
        )
        .await
    }

    async fn resolve<'c>(
        harness: &'c TestHarness,
        session: &Session,
        id: &str,
        kind: &str,
    ) -> LocalResponse<'c> {
        post(
            harness,
            session,
            Some("handled"),
            &format!("/admin/prot/store/{}/resolve", id),
            json!({ "kind": kind }),
        )
        .await
    }

    async fn release<'c>(
        harness: &'c TestHarness,
        session: &Session,
        id: &str,
    ) -> LocalResponse<'c> {
        post(
            harness,
            session,
            Some("over%20cap%20ticket%2077"),
            &format!("/admin/prot/store/{}/release", id),
            json!({}),
        )
        .await
    }

    async fn purchase_of(response: LocalResponse<'_>) -> v0::ProtStoreAdminPurchase {
        assert_eq!(response.status(), Status::Ok);
        response
            .into_json::<v0::ProtStoreAdminPurchase>()
            .await
            .expect("`ProtStoreAdminPurchase`")
    }

    #[test]
    fn store_admin_refuses_a_non_privileged_user() {
        crate::util::test::rt().block_on(store_admin_refuses_a_non_privileged_user_case())
    }

    async fn store_admin_refuses_a_non_privileged_user_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        assert!(!user.privileged);

        let token = token();
        let row = unbound(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));
        harness
            .db
            .set_prot_store_needs_action(&row.id, PROT_STORE_NEEDS_REVERSED_UNPAID, now_ms())
            .await
            .expect("work item");
        let row = stored(&harness, &row.id).await;

        // Their own valid ticket and a reason each time: only the privilege is
        // missing. Assigning the purchase to themselves is the point.
        let responses = [
            get(
                &harness,
                &session,
                Some("curious"),
                &format!("/admin/prot/store/{}", row.id),
            )
            .await,
            get(
                &harness,
                &session,
                Some("curious"),
                "/admin/prot/store?needs_action=true",
            )
            .await,
            assign(&harness, &session, &row.id, &user.id).await,
            resolve(
                &harness,
                &session,
                &row.id,
                PROT_STORE_NEEDS_REVERSED_UNPAID,
            )
            .await,
        ];
        for response in responses {
            assert_eq!(response.status(), Status::Forbidden);
            assert_eq!(error_type(response).await, "NotPrivileged");
        }

        assert_untouched(&harness, &row).await;
        assert_eq!(balance(&harness, &user.id).await, None);
        assert!(harness.play.calls().is_empty(), "the store was asked");
    }

    #[test]
    fn store_admin_needs_a_ticket_and_a_reason() {
        crate::util::test::rt().block_on(store_admin_needs_a_ticket_and_a_reason_case())
    }

    async fn store_admin_needs_a_ticket_and_a_reason_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;
        let (_, _, target) = harness.new_user().await;
        let token = token();
        let row = unbound(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));
        let read_path = format!("/admin/prot/store/{}", row.id);
        let assign_path = format!("/admin/prot/store/{}/assign", row.id);
        let assign_body = json!({ "user_id": target.id }).to_string();

        // No MFA ticket at all
        let response = harness
            .client
            .get(read_path.clone())
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("X-Audit-Log-Reason", "check"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized, "read, no ticket");
        let response = harness
            .client
            .post(assign_path.clone())
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("X-Audit-Log-Reason", "check"))
            .body(assign_body.clone())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized, "assign, no ticket");

        // No reason, and a reason that sanitizes to nothing, on every route
        for reason in [None, Some("%20%E2%80%8B%0A")] {
            let responses = [
                get(&harness, &session, reason, &read_path).await,
                get(
                    &harness,
                    &session,
                    reason,
                    "/admin/prot/store?needs_action=true",
                )
                .await,
                post(
                    &harness,
                    &session,
                    reason,
                    &assign_path,
                    json!({ "user_id": target.id }),
                )
                .await,
                post(
                    &harness,
                    &session,
                    reason,
                    &format!("/admin/prot/store/{}/resolve", row.id),
                    json!({ "kind": PROT_STORE_NEEDS_REVERSED_UNPAID }),
                )
                .await,
            ];
            for response in responses {
                assert_eq!(response.status(), Status::BadRequest, "reason {:?}", reason);
                let body = response.into_string().await.expect("body");
                assert!(
                    body.contains("AuditLogReasonRequired"),
                    "reason {:?}: {}",
                    reason,
                    body
                );
            }
        }

        assert_untouched(&harness, &row).await;
        assert_eq!(balance(&harness, &target.id).await, None);
        assert!(harness.play.calls().is_empty(), "the store was asked");

        // With both, the read goes through
        let read = purchase_of(get(&harness, &session, Some("check"), &read_path).await).await;
        assert_eq!(read.purchase.id, row.id);
    }

    #[test]
    fn store_admin_takes_store_purchase_ids() {
        crate::util::test::rt().block_on(store_admin_takes_store_purchase_ids_case())
    }

    /// Every store id carries `:`; `is_plain_id` would answer 404 for each
    async fn store_admin_takes_store_purchase_ids_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;

        let apple = unbound(&harness, &apple_seed("2000000000000001")).await;
        let play = unbound(
            &harness,
            &play_seed(&token(), v0::ProtStoreEnvironment::Production),
        )
        .await;
        assert!(apple.id.contains(':') && play.id.contains(':'));

        for (path_id, id) in [
            (apple.id.clone(), &apple.id),
            (apple.id.replace(':', "%3A"), &apple.id),
            (play.id.clone(), &play.id),
        ] {
            let read = purchase_of(
                get(
                    &harness,
                    &session,
                    Some("check"),
                    &format!("/admin/prot/store/{}", path_id),
                )
                .await,
            )
            .await;
            assert_eq!(&read.purchase.id, id, "{}", path_id);
            assert_eq!(read.purchase.state, v0::ProtStoreState::Rejected);
            assert_eq!(
                read.purchase.needs_action.as_deref(),
                Some(PROT_STORE_NEEDS_UNBOUND)
            );
            assert!(read.ledger.is_empty());
            assert_eq!(read.unspent, None, "no buyer");
        }

        // Well-formed but unknown, and ids no store purchase can have
        for path_id in [
            "apple:prod:2000000000000999".to_string(),
            format!("play:{}", "0".repeat(64)),
            Ulid::new().to_string(),
            "apple:prod:12a".to_string(),
            format!("play:{}", "A".repeat(64)),
            "apple:prod:1%0AAUDIT%20forged".to_string(),
        ] {
            let path = format!("/admin/prot/store/{}", path_id);
            let response = get(&harness, &session, Some("check"), &path).await;
            assert_eq!(response.status(), Status::NotFound, "{}", path_id);
            assert_eq!(error_type(response).await, "NotFound", "{}", path_id);

            let response = resolve(&harness, &session, &path_id, PROT_STORE_NEEDS_CHARGEBACK).await;
            assert_eq!(response.status(), Status::NotFound, "resolve {}", path_id);
        }
    }

    #[test]
    fn assign_credits_an_unbound_purchase() {
        crate::util::test::rt().block_on(assign_credits_an_unbound_purchase_case())
    }

    async fn assign_credits_an_unbound_purchase_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;
        let (_, _, buyer) = harness.new_user().await;

        let token = token();
        let row = unbound(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));

        let assigned = purchase_of(assign(&harness, &session, &row.id, &buyer.id).await).await;
        assert_eq!(assigned.purchase.id, row.id);
        assert_eq!(assigned.purchase.state, v0::ProtStoreState::Credited);
        assert_eq!(assigned.purchase.reject_reason, None);
        assert_eq!(
            assigned.purchase.user_id.as_deref(),
            Some(buyer.id.as_str())
        );
        assert_eq!(
            assigned.purchase.assigned_by.as_deref(),
            Some(staff.id.as_str())
        );
        // The unbound work item is done; Play is consumed after the credit
        assert_eq!(assigned.purchase.needs_action, None);
        assert_eq!(assigned.purchase.consumed, Some(true));
        assert_eq!(assigned.ledger.len(), 1, "{:?}", assigned.ledger);
        assert_eq!(assigned.ledger[0].kind, v0::ProtEntryKind::Purchase);
        assert_eq!(assigned.ledger[0].amount, P5_PROT);
        assert_eq!(assigned.unspent, Some(P5_PROT));
        assert_eq!(balance(&harness, &buyer.id).await, Some(P5_PROT));
        assert!(credited(&harness, &row.id).await);

        // Looked up fresh, then consumed
        let lookup = format!("product_purchase {}", &row.id["play:".len()..]);
        let consume = format!("consume {} {}", P5, &row.id["play:".len()..]);
        assert_eq!(harness.play.calls(), vec![lookup, consume]);

        // The read shows the same
        let read = purchase_of(
            get(
                &harness,
                &session,
                Some("check"),
                &format!("/admin/prot/store/{}", row.id),
            )
            .await,
        )
        .await;
        assert_eq!(read, assigned);

        // A second assign never credits twice, to anyone
        let (_, _, other) = harness.new_user().await;
        for user_id in [&buyer.id, &other.id] {
            let response = assign(&harness, &session, &row.id, user_id).await;
            assert_eq!(response.status(), Status::BadRequest, "{}", user_id);
            assert_eq!(error_type(response).await, "InvalidOperation");
        }
        assert_eq!(balance(&harness, &buyer.id).await, Some(P5_PROT));
        assert_eq!(balance(&harness, &other.id).await, None);
        let after = stored(&harness, &row.id).await;
        assert_eq!(after.user_id.as_deref(), Some(buyer.id.as_str()));
        assert_eq!(after.state, v0::ProtStoreState::Credited);
    }

    #[test]
    fn assign_refuses_self() {
        crate::util::test::rt().block_on(assign_refuses_self_case())
    }

    async fn assign_refuses_self_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;

        let token = token();
        let row = unbound(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));

        let response = assign(&harness, &session, &row.id, &staff.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");

        assert_untouched(&harness, &row).await;
        assert_eq!(balance(&harness, &staff.id).await, None);
        assert!(harness.play.calls().is_empty(), "the store was asked");
    }

    #[test]
    fn assign_refuses_a_bot_or_deleted_target() {
        crate::util::test::rt().block_on(assign_refuses_a_bot_or_deleted_target_case())
    }

    async fn assign_refuses_a_bot_or_deleted_target_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;

        let (_, _, mut bot) = harness.new_user().await;
        bot.update(
            &harness.db,
            PartialUser {
                bot: Some(BotInformation {
                    owner: staff.id.clone(),
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("flag the bot");
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

        let token = token();
        let row = unbound(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));

        for user_id in [&bot.id, &deleted.id] {
            let response = assign(&harness, &session, &row.id, user_id).await;
            assert_eq!(response.status(), Status::BadRequest, "{}", user_id);
            assert_eq!(
                error_type(response).await,
                "InvalidOperation",
                "{}",
                user_id
            );
            assert_eq!(balance(&harness, user_id).await, None);
        }

        // No such account, and values no account id can be
        for user_id in [
            Ulid::new().to_string(),
            "a:b".to_string(),
            "one\nAUDIT prot_store_assign: actor=x".to_string(),
        ] {
            let response = assign(&harness, &session, &row.id, &user_id).await;
            assert_eq!(response.status(), Status::NotFound, "{:?}", user_id);
            assert_eq!(error_type(response).await, "NotFound", "{:?}", user_id);
        }

        assert_untouched(&harness, &row).await;
        assert!(harness.play.calls().is_empty(), "the store was asked");
    }

    #[test]
    fn assign_refuses_a_revoked_row() {
        crate::util::test::rt().block_on(assign_refuses_a_revoked_row_case())
    }

    async fn assign_refuses_a_revoked_row_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;
        let (_, _, buyer) = harness.new_user().await;

        // Play shows the purchase cancelled when support assigns it
        let token = token();
        let row = unbound(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_CANCELLED)));

        let response = assign(&harness, &session, &row.id, &buyer.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");

        // The cancellation is recorded, nothing is credited
        let revoked = stored(&harness, &row.id).await;
        assert_eq!(revoked.state, v0::ProtStoreState::Revoked);
        assert!(revoked.revoked_at.is_some());
        assert_eq!(revoked.user_id, None);
        assert!(!credited(&harness, &row.id).await);
        assert_eq!(balance(&harness, &buyer.id).await, None);

        // A Revoked row stays refused even when the store answers paid again
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));
        let response = assign(&harness, &session, &row.id, &buyer.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
        assert_untouched(&harness, &revoked).await;
        assert_eq!(balance(&harness, &buyer.id).await, None);
    }

    #[test]
    fn assign_refuses_what_the_store_cannot_confirm() {
        crate::util::test::rt().block_on(assign_refuses_what_the_store_cannot_confirm_case())
    }

    /// Unknown at the store → 400; a failed lookup → 500; no credentials →
    /// 503; a test purchase is never assigned. The row never moves.
    async fn assign_refuses_what_the_store_cannot_confirm_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;
        let (_, _, buyer) = harness.new_user().await;

        // Play does not know the token
        let unknown = unbound(
            &harness,
            &play_seed(&token(), v0::ProtStoreEnvironment::Production),
        )
        .await;
        let response = assign(&harness, &session, &unknown.id, &buyer.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
        assert_untouched(&harness, &unknown).await;

        // The lookup fails
        let token = token();
        let failing = unbound(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
        )
        .await;
        for error in [
            StoreApiError::Transient("timeout".to_string()),
            StoreApiError::Rejected { status: 403 },
        ] {
            harness.play.set_purchase(&token, Err(error.clone()));
            let response = assign(&harness, &session, &failing.id, &buyer.id).await;
            assert_eq!(
                response.status(),
                Status::InternalServerError,
                "{:?}",
                error
            );
            assert_eq!(error_type(response).await, "InternalError");
            assert_untouched(&harness, &failing).await;
        }

        // A test purchase, even one Play shows paid
        let test_token = self::token();
        let test = unbound(
            &harness,
            &play_seed(&test_token, v0::ProtStoreEnvironment::Sandbox),
        )
        .await;
        harness
            .play
            .set_purchase(&test_token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));
        let response = assign(&harness, &session, &test.id, &buyer.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
        assert_untouched(&harness, &test).await;

        // No Play credentials on this deployment (last: it sticks)
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));
        harness.play.unconfigured();
        let response = assign(&harness, &session, &failing.id, &buyer.id).await;
        assert_eq!(response.status(), Status::ServiceUnavailable);
        assert_eq!(error_type(response).await, "ProtStoreUnavailable");
        assert_untouched(&harness, &failing).await;

        assert_eq!(balance(&harness, &buyer.id).await, None);
    }

    #[test]
    fn resolve_clears_only_the_named_kind() {
        crate::util::test::rt().block_on(resolve_clears_only_the_named_kind_case())
    }

    async fn resolve_clears_only_the_named_kind_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;

        let row = unbound(
            &harness,
            &play_seed(&token(), v0::ProtStoreEnvironment::Production),
        )
        .await;
        assert!(harness
            .db
            .set_prot_store_needs_action(&row.id, PROT_STORE_NEEDS_REVERSED_UNPAID, now_ms())
            .await
            .expect("work item"));
        let held = stored(&harness, &row.id).await;
        assert_eq!(
            held.needs_action.as_deref(),
            Some(PROT_STORE_NEEDS_REVERSED_UNPAID)
        );

        // Another resolvable kind, a kind resolve never clears, a made-up one
        for kind in [
            PROT_STORE_NEEDS_CHARGEBACK,
            PROT_STORE_NEEDS_UNBOUND,
            "anything",
        ] {
            let response = resolve(&harness, &session, &row.id, kind).await;
            assert_eq!(response.status(), Status::BadRequest, "{}", kind);
            assert_eq!(error_type(response).await, "InvalidOperation", "{}", kind);
            assert_untouched(&harness, &held).await;
        }

        // An empty or overlong kind fails validation
        for kind in [String::new(), "x".repeat(33)] {
            let response = resolve(&harness, &session, &row.id, &kind).await;
            assert_eq!(response.status(), Status::BadRequest, "{:?}", kind);
            assert_eq!(error_type(response).await, "FailedValidation");
            assert_untouched(&harness, &held).await;
        }

        // The named kind clears, and nothing else changes
        let resolved = purchase_of(
            resolve(
                &harness,
                &session,
                &row.id,
                PROT_STORE_NEEDS_REVERSED_UNPAID,
            )
            .await,
        )
        .await;
        assert_eq!(resolved.purchase.needs_action, None);
        assert_eq!(resolved.purchase.state, v0::ProtStoreState::Rejected);
        assert_eq!(resolved.purchase.user_id, None);
        assert!(resolved.ledger.is_empty(), "a resolve moved Prot");
        assert!(!credited(&harness, &row.id).await);

        // Done once: a second resolve has nothing to clear
        let response = resolve(
            &harness,
            &session,
            &row.id,
            PROT_STORE_NEEDS_REVERSED_UNPAID,
        )
        .await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
    }

    #[test]
    fn needs_action_list_serves_only_the_work_list() {
        crate::util::test::rt().block_on(needs_action_list_serves_only_the_work_list_case())
    }

    async fn needs_action_list_serves_only_the_work_list_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;

        let open = unbound(
            &harness,
            &play_seed(&token(), v0::ProtStoreEnvironment::Production),
        )
        .await;
        let review = unbound(&harness, &apple_seed("2000000000000002")).await;
        assert!(harness
            .db
            .set_prot_store_needs_action(&review.id, PROT_STORE_NEEDS_CHARGEBACK, now_ms())
            .await
            .expect("work item"));
        let done = unbound(
            &harness,
            &play_seed(&token(), v0::ProtStoreEnvironment::Production),
        )
        .await;
        assert!(harness
            .db
            .clear_prot_store_needs_action(&done.id, PROT_STORE_NEEDS_UNBOUND, now_ms())
            .await
            .expect("clear"));

        let response = get(
            &harness,
            &session,
            Some("triage"),
            "/admin/prot/store?needs_action=true",
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let list = response
            .into_json::<Vec<v0::ProtStorePurchaseView>>()
            .await
            .expect("work list");
        let kind_of = |id: &str| {
            list.iter()
                .find(|view| view.id == id)
                .map(|view| view.needs_action.clone())
        };
        assert_eq!(
            kind_of(open.id.as_str()),
            Some(Some(PROT_STORE_NEEDS_UNBOUND.to_string()))
        );
        assert_eq!(
            kind_of(review.id.as_str()),
            Some(Some(PROT_STORE_NEEDS_CHARGEBACK.to_string()))
        );
        assert_eq!(
            kind_of(done.id.as_str()),
            None,
            "a row with no work item is listed"
        );
        assert!(list.iter().all(|view| view.needs_action.is_some()));

        // Nothing but the work list: no flag, or false
        for path in ["/admin/prot/store", "/admin/prot/store?needs_action=false"] {
            let response = get(&harness, &session, Some("triage"), path).await;
            assert_eq!(response.status(), Status::BadRequest, "{}", path);
            assert_eq!(error_type(response).await, "FailedValidation", "{}", path);
        }
    }

    #[test]
    fn release_credits_an_over_cap_hold() {
        crate::util::test::rt().block_on(release_credits_an_over_cap_hold_case())
    }

    /// R63: staff release a purchase held over the cap: credited to its
    /// buyer, looked up fresh, then consumed; the work item is cleared; a
    /// second release credits nothing
    async fn release_credits_an_over_cap_hold_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;
        let (_, _, buyer) = harness.new_user().await;

        let token = token();
        let row = over_cap(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
            &buyer.id,
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));

        let released = purchase_of(release(&harness, &session, &row.id).await).await;
        assert_eq!(released.purchase.state, v0::ProtStoreState::Credited);
        assert_eq!(released.purchase.hold_reason, None);
        assert_eq!(released.purchase.needs_action, None);
        assert_eq!(
            released.purchase.user_id.as_deref(),
            Some(buyer.id.as_str())
        );
        assert_eq!(released.purchase.consumed, Some(true));
        assert_eq!(released.ledger.len(), 1, "{:?}", released.ledger);
        assert_eq!(released.ledger[0].amount, P5_PROT);
        assert_eq!(released.unspent, Some(P5_PROT));
        assert_eq!(balance(&harness, &buyer.id).await, Some(P5_PROT));

        let lookup = format!("product_purchase {}", &row.id["play:".len()..]);
        let consume = format!("consume {} {}", P5, &row.id["play:".len()..]);
        assert_eq!(harness.play.calls(), vec![lookup, consume]);

        let response = release(&harness, &session, &row.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
        assert_eq!(balance(&harness, &buyer.id).await, Some(P5_PROT));
    }

    #[test]
    fn release_needs_staff_a_ticket_and_a_reason() {
        crate::util::test::rt().block_on(release_needs_staff_a_ticket_and_a_reason_case())
    }

    /// The S5 staff guards: a non-privileged buyer cannot release their own
    /// hold; no ticket → 401; no reason, or one that sanitizes to nothing →
    /// 400. Nothing moves and the store is never asked.
    async fn release_needs_staff_a_ticket_and_a_reason_case() {
        let harness = TestHarness::new().await;
        let (staff_session, _) = new_staff(&harness).await;
        let (_, buyer_session, buyer) = harness.new_user().await;
        assert!(!buyer.privileged);

        let token = token();
        let row = over_cap(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
            &buyer.id,
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));
        let path = format!("/admin/prot/store/{}/release", row.id);

        let response = release(&harness, &buyer_session, &row.id).await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(error_type(response).await, "NotPrivileged");

        let response = harness
            .client
            .post(path.clone())
            .header(Header::new("x-session-token", staff_session.token.clone()))
            .header(Header::new("X-Audit-Log-Reason", "check"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized, "no ticket");

        for reason in [None, Some("%20%E2%80%8B%0A")] {
            let response = post(&harness, &staff_session, reason, &path, json!({})).await;
            assert_eq!(response.status(), Status::BadRequest, "reason {:?}", reason);
            let body = response.into_string().await.expect("body");
            assert!(body.contains("AuditLogReasonRequired"), "{}", body);
        }

        assert_untouched(&harness, &row).await;
        assert_eq!(balance(&harness, &buyer.id).await, None);
        assert!(harness.play.calls().is_empty(), "the store was asked");
    }

    #[test]
    fn release_refuses_self_and_a_bot_or_deleted_buyer() {
        crate::util::test::rt().block_on(release_refuses_self_and_a_bot_or_deleted_buyer_case())
    }

    /// Staff never release their own hold; a bot's or a deleted account's
    /// hold is never released. Each refusal comes before any store lookup.
    async fn release_refuses_self_and_a_bot_or_deleted_buyer_case() {
        let harness = TestHarness::new().await;
        let (session, staff) = new_staff(&harness).await;

        let (_, _, mut bot) = harness.new_user().await;
        bot.update(
            &harness.db,
            PartialUser {
                bot: Some(BotInformation {
                    owner: staff.id.clone(),
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("flag the bot");
        let (_, _, mut deleted) = harness.new_user().await;

        let mut rows = Vec::new();
        for buyer in [&staff.id, &bot.id, &deleted.id] {
            let token = token();
            harness
                .play
                .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));
            rows.push(
                over_cap(
                    &harness,
                    &play_seed(&token, v0::ProtStoreEnvironment::Production),
                    buyer,
                )
                .await,
            );
        }
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

        for row in &rows {
            let response = release(&harness, &session, &row.id).await;
            assert_eq!(response.status(), Status::BadRequest, "{:?}", row.user_id);
            assert_eq!(error_type(response).await, "InvalidOperation");
            assert_untouched(&harness, row).await;
        }
        for user_id in [&staff.id, &bot.id, &deleted.id] {
            assert_eq!(balance(&harness, user_id).await, None);
        }
        assert!(harness.play.calls().is_empty(), "the store was asked");
    }

    #[test]
    fn release_refuses_anything_but_an_over_cap_hold() {
        crate::util::test::rt().block_on(release_refuses_anything_but_an_over_cap_hold_case())
    }

    /// An unbound purchase is not releasable (400, no lookup); an id that
    /// names no purchase is 404
    async fn release_refuses_anything_but_an_over_cap_hold_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;

        let token = token();
        let row = unbound(
            &harness,
            &play_seed(&token, v0::ProtStoreEnvironment::Production),
        )
        .await;
        harness
            .play
            .set_purchase(&token, Ok(at_play(PLAY_PURCHASE_STATE_PURCHASED)));
        let response = release(&harness, &session, &row.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
        assert_untouched(&harness, &row).await;
        assert!(harness.play.calls().is_empty(), "the store was asked");

        for path_id in [
            format!("play:{}", "0".repeat(64)),
            Ulid::new().to_string(),
            "apple:prod:1%0AAUDIT%20forged".to_string(),
        ] {
            let response = release(&harness, &session, &path_id).await;
            assert_eq!(response.status(), Status::NotFound, "{}", path_id);
        }
    }

    /// The release writes its AUDIT line, as every staff route does
    #[test]
    fn release_route_logs_its_audit_line() {
        let source = include_str!("prot_store.rs");
        let route = source.split("#[cfg(test)]").next().expect("route code");
        let release = route
            .split("pub async fn release_prot_store_purchase")
            .nth(1)
            .expect("release");
        assert!(release.contains("\"AUDIT prot_store_release: actor={} id={} reason={:?}\""));
        assert!(release.contains("staff_reason(&user, &ticket, reason)?"));
        assert!(release.contains("check_purchase_id(&id)?"));
    }

    /// Support must reach store purchases while Prot and the stores are
    /// closed for sale: no route reads an open flag, and only assign and
    /// release read the settings at all (for the credit pause and the
    /// credentials)
    #[test]
    fn store_admin_routes_are_not_gated_on_the_flags() {
        let source = include_str!("prot_store.rs");
        let route = source.split("#[cfg(test)]").next().expect("route code");
        let code = without_comments(route);
        assert!(
            code.contains("#[openapi(tag = \"Payments\")]"),
            "the route code was not found"
        );

        for gate in &[
            "protection",
            "PaymentsSettings",
            "config()",
            "ProtDisabled",
            "PaymentsDisabled",
            "ProtStoreClosed",
            ".enabled",
            "sales_open",
            "checkout_open",
            "apple_open",
            "play_open",
            "store_offered_to",
            "load_or_closed",
        ] {
            assert!(
                !code.contains(gate),
                "the store admin routes read `{}`; they must work while Prot is off",
                gate
            );
        }

        // R64: the store settings are loaded exactly twice, once in assign
        // and once in release, each after the privileged + MFA checks; the
        // sales settings once, in assign
        let body_of = |name: &str| {
            code.split(&format!("pub async fn {}", name))
                .nth(1)
                .and_then(|rest| rest.split("pub async fn").next())
                .expect(name)
                .to_string()
        };
        let assign = body_of("assign_prot_store_purchase");
        let release = body_of("release_prot_store_purchase");
        assert_eq!(code.matches("ProtSalesSettings::load()").count(), 1);
        assert!(
            assign.contains("ProtSalesSettings::load()"),
            "ProtSalesSettings::load() outside assign"
        );
        assert_eq!(code.matches("ProtStoreSettings::load()").count(), 2);
        for (name, body) in [("assign", &assign), ("release", &release)] {
            assert_eq!(
                body.matches("ProtStoreSettings::load()").count(),
                1,
                "{}",
                name
            );
            let guards = body.find("staff_reason(").expect(name);
            let load = body.find("ProtStoreSettings::load()").expect(name);
            assert!(
                guards < load,
                "{} loads the settings before the staff guards",
                name
            );
        }
    }
}
