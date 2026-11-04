use revolt_database::{
    now_ms, util::audit_reason::AuditLogReason, Database, User, ValidatedTicket,
};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Terminate Prot Tank
///
/// End a channel's fuel tank for abuse. The tank's leftover balance is
/// forfeited, never handed back; held pledges of its open goals go back to
/// their pledgers. The channel's content is purged and the channel stays
/// protected (a terminated channel never turns into a plaintext one). The
/// forfeit's ledger row records the staff member and the reason.
///
/// A tank whose launch never landed has nothing to terminate: its goal is
/// cancelled with every pledge returned, and the answer is `NotFound`.
///
/// Requires a privileged account, an MFA ticket and `X-Audit-Log-Reason`.
/// Works while Prot is switched off.
#[openapi(tag = "Payments")]
#[post("/prot/tanks/<tank_id>/terminate")]
pub async fn terminate_prot_tank(
    db: &State<Database>,
    user: User,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    tank_id: String,
) -> Result<Json<v0::ProtTankSummary>> {
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

    // Tank ids are ULIDs, and the id goes into the audit line
    if !super::is_plain_id(&tank_id) {
        return Err(create_error!(FailedValidation {
            error: "tank_id may only contain letters, digits, '-' and '_'".to_string()
        }));
    }

    log::info!(
        "AUDIT prot_terminate: actor={} tank={} reason={:?}",
        user.id,
        tank_id,
        reason
    );

    Ok(Json(
        engine::tank::terminate_prot_tank(db, &user.id, &tank_id, reason, now_ms()).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{error_type, new_staff, with_own_ticket};
    use crate::util::test::{without_comments, TestHarness, FIXTURE_DEVICE_CAP, OWNER_DEVICE_SEED};
    use revolt_database::{
        now_ms, prot_key_admin, prot_key_forfeit_tank, prot_tank_account, prot_user_account,
        Channel, ChannelEntitlementState, ProtAmount, ProtGoal, ProtLaunchInput, ProtPledgeInput,
        ProtPosting, ProtRef, ProtTank, ProtTankRules, Session, User, PROT_SYS_ADJUST,
        PROT_SYS_FORFEITED,
    };
    use revolt_models::v0;
    use rocket::http::Status;
    use rocket::local::asynchronous::LocalResponse;
    use ulid::Ulid;

    const DAY: i64 = 86_400_000;
    /// A 10-slot, 30-day launch goal at the default 40 Prot a day
    const TARGET: i64 = 1_200;
    /// The actor of the test's own wallet credits
    const FUNDER: &str = "01TERMINATETESTFUNDER00000";

    /// Self-serve on and no burn: a launched tank holds exactly its pledges
    fn rules() -> ProtTankRules {
        ProtTankRules {
            self_serve: true,
            burning: false,
            ..ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())
                .expect("the default Prot config is valid")
        }
    }

    async fn balance(harness: &TestHarness, account: &str) -> i64 {
        harness
            .db
            .fetch_prot_account(account)
            .await
            .expect("account")
            .map_or(0, |account| account.balance)
    }

    /// An admin credit of `amount` to the wallet of `user_id`
    async fn fund(harness: &TestHarness, user_id: &str, amount: i64, now: i64) {
        harness
            .db
            .apply_prot_posting(&ProtPosting {
                key: prot_key_admin(FUNDER, &Ulid::new().to_string()),
                kind: v0::ProtEntryKind::AdminAdjust,
                debit: PROT_SYS_ADJUST.to_string(),
                credit: prot_user_account(user_id),
                amount: ProtAmount::Exact(amount),
                debit_floor: 0,
                actor: FUNDER.to_string(),
                reference: ProtRef::default(),
                reason: Some("terminate test".to_string()),
                created_at: now - 1_000,
            })
            .await
            .expect("fund");
    }

    /// What [`launched_tank`] built
    struct Launched {
        channel: Channel,
        tank: ProtTank,
        goal: ProtGoal,
        /// The one pledger, who pledged all of [`TARGET`]
        backer: User,
    }

    /// A funded 10-slot launch goal of a fresh server, launched on a fresh
    /// channel (tank Launching). With `protect` the owner then protects the
    /// channel and the pledges are captured: the tank is Active and holds
    /// [`TARGET`].
    async fn launched_tank(harness: &TestHarness, protect: bool) -> Launched {
        let db = &harness.db;
        let rules = rules();
        let now = now_ms();
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        let (_, _, backer) = harness.new_user().await;
        harness.join_server(&server, &backer).await;

        let daily_cost = rules.daily_cost(10).expect("10 is a slot tier");
        assert_eq!(30 * daily_cost, TARGET);
        let goal = db
            .create_prot_goal(&ProtGoal {
                id: Ulid::new().to_string(),
                kind: v0::ProtGoalKind::Launch,
                server_id: server.id.clone(),
                channel_id: None,
                tank_id: None,
                created_by: owner.id.clone(),
                create_nonce: Ulid::new().to_string(),
                slots: 10,
                days: Some(30),
                daily_cost,
                base_daily_cost: None,
                target_prot: TARGET,
                pledged_total: 0,
                state: v0::ProtGoalState::Funding,
                deadline_at: now + 30 * DAY,
                funded_at: None,
                launch_deadline_at: None,
                launched_at: None,
                closed_at: None,
                refund7_done: false,
                open_key: Some(format!("launch:{}", server.id)),
                version: 0,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("launch goal");

        fund(harness, &backer.id, TARGET, now).await;
        let pledged = db
            .pledge_prot(&ProtPledgeInput {
                user_id: backer.id.clone(),
                goal_id: goal.id.clone(),
                amount: TARGET,
                nonce: Ulid::new().to_string(),
                rules: rules.clone(),
                now,
            })
            .await
            .expect("pledge");
        assert_eq!(pledged.goal.state, v0::ProtGoalState::Funded);

        let (goal, tank) = db
            .launch_prot_goal(&ProtLaunchInput {
                goal_id: goal.id.clone(),
                channel_id: channel.id().to_string(),
                owner_id: owner.id.clone(),
                rules: rules.clone(),
                now,
            })
            .await
            .expect("launch");
        assert_eq!(tank.stage, v0::ProtTankStage::Launching);

        if !protect {
            return Launched {
                channel,
                tank,
                goal,
                backer,
            };
        }

        let device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        let seats = [owner.id.clone()];
        let request = device.protect_request(channel.id(), FIXTURE_DEVICE_CAP, &seats);
        harness.protect_with_db(&channel, &request).await;

        let tank = db
            .capture_launch_pledges(channel.id(), now, &rules)
            .await
            .expect("capture")
            .expect("a protected Launching tank is captured");
        assert_eq!(tank.stage, v0::ProtTankStage::Active);
        assert_eq!(balance(harness, &prot_tank_account(&tank.id)).await, TARGET);

        let goal = db
            .fetch_prot_goal(&goal.id)
            .await
            .expect("goal read")
            .expect("the launch goal");
        let channel = db
            .fetch_channel(channel.id())
            .await
            .expect("the protected channel");
        assert!(channel.is_protected());

        Launched {
            channel,
            tank,
            goal,
            backer,
        }
    }

    /// `POST /admin/prot/tanks/<tank_id>/terminate` as `session`'s user with
    /// a fresh ticket of their own and `reason`
    async fn terminate<'c>(
        harness: &'c TestHarness,
        session: &Session,
        reason: Option<&str>,
        tank_id: &str,
    ) -> LocalResponse<'c> {
        let request = harness
            .client
            .post(format!("/admin/prot/tanks/{tank_id}/terminate"));
        with_own_ticket(harness, request, session, reason)
            .await
            .dispatch()
            .await
    }

    /// The launched tank of `launched` as it was: Active with all of
    /// [`TARGET`], no forfeit row, the channel protected and its
    /// entitlement Active
    async fn assert_untouched(harness: &TestHarness, launched: &Launched) {
        let db = &harness.db;
        let tank = db
            .fetch_prot_tank(&launched.tank.id)
            .await
            .expect("tank read")
            .expect("the tank");
        assert_eq!(tank.stage, v0::ProtTankStage::Active);
        assert_eq!(tank.terminated_by, None);
        assert_eq!(
            balance(harness, &prot_tank_account(&launched.tank.id)).await,
            TARGET
        );
        assert!(db
            .fetch_prot_entry_by_key(&prot_key_forfeit_tank(&launched.tank.id))
            .await
            .expect("ledger read")
            .is_none());
        assert!(db
            .fetch_channel(launched.channel.id())
            .await
            .expect("the channel")
            .is_protected());
        assert_eq!(
            db.fetch_channel_entitlement(launched.channel.id())
                .await
                .expect("entitlement read")
                .map(|entitlement| entitlement.state),
            Some(ChannelEntitlementState::Active)
        );
    }

    #[test]
    fn terminate_needs_privilege_and_a_reason() {
        crate::util::test::rt().block_on(terminate_needs_privilege_and_a_reason_case())
    }

    async fn terminate_needs_privilege_and_a_reason_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;
        let (_, user_session, user) = harness.new_user().await;
        assert!(!user.privileged);
        let launched = launched_tank(&harness, true).await;

        // Their own valid ticket and a reason: only the privilege is missing
        let response = terminate(&harness, &user_session, Some("abuse"), &launched.tank.id).await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(error_type(response).await, "NotPrivileged");

        // No header, and one that sanitizes to nothing (space, zero-width
        // space, newline)
        for reason in [None, Some("%20%E2%80%8B%0A")] {
            let response = terminate(&harness, &session, reason, &launched.tank.id).await;
            assert_eq!(response.status(), Status::BadRequest, "reason {:?}", reason);
            let body = response.into_string().await.expect("body");
            assert!(
                body.contains("AuditLogReasonRequired"),
                "reason {:?}: {}",
                reason,
                body
            );
        }

        assert_untouched(&harness, &launched).await;
    }

    #[test]
    fn terminate_refuses_a_malformed_or_unknown_tank_id() {
        crate::util::test::rt().block_on(terminate_refuses_a_malformed_or_unknown_tank_id_case())
    }

    /// The id goes into the audit line: anything but a plain id is refused
    /// before it is logged or looked up
    async fn terminate_refuses_a_malformed_or_unknown_tank_id_case() {
        let harness = TestHarness::new().await;
        let (session, _) = new_staff(&harness).await;
        let launched = launched_tank(&harness, true).await;

        let too_long = "a".repeat(65);
        for tank_id in ["a%3Ab", "two%0Alines", "has%20space", too_long.as_str()] {
            let response = terminate(&harness, &session, Some("abuse"), tank_id).await;
            assert_eq!(response.status(), Status::BadRequest, "{:?}", tank_id);
            assert_eq!(
                error_type(response).await,
                "FailedValidation",
                "{:?}",
                tank_id
            );
        }

        let response = terminate(&harness, &session, Some("abuse"), &Ulid::new().to_string()).await;
        assert_eq!(response.status(), Status::NotFound);
        assert_eq!(error_type(response).await, "NotFound");

        assert_untouched(&harness, &launched).await;
    }

    #[test]
    fn terminate_forfeits_the_tank_and_keeps_the_channel_protected() {
        crate::util::test::rt()
            .block_on(terminate_forfeits_the_tank_and_keeps_the_channel_protected_case())
    }

    /// 9.5: the leftover is forfeited (never returned to the backer), the
    /// forfeit's row names the staff member and the decoded reason, the
    /// entitlement is Deleted and the channel stays protected
    async fn terminate_forfeits_the_tank_and_keeps_the_channel_protected_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (session, staff) = new_staff(&harness).await;
        let launched = launched_tank(&harness, true).await;
        assert_eq!(launched.goal.state, v0::ProtGoalState::Launched);
        assert_eq!(
            balance(&harness, &prot_user_account(&launched.backer.id)).await,
            0
        );

        let response = terminate(
            &harness,
            &session,
            Some("spam%20ring%20%E2%80%94%20report%2042"),
            &launched.tank.id,
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let summary = response
            .into_json::<v0::ProtTankSummary>()
            .await
            .expect("`ProtTankSummary`");
        assert_eq!(summary.tank_id, launched.tank.id);
        assert_eq!(summary.channel_id, launched.channel.id());
        assert_eq!(summary.stage, v0::ProtTankStage::Terminated);

        let tank = db
            .fetch_prot_tank(&launched.tank.id)
            .await
            .expect("tank read")
            .expect("the terminated tank is kept");
        assert_eq!(tank.stage, v0::ProtTankStage::Terminated);
        assert_eq!(tank.terminated_by.as_deref(), Some(staff.id.as_str()));

        let row = db
            .fetch_prot_entry_by_key(&prot_key_forfeit_tank(&launched.tank.id))
            .await
            .expect("ledger read")
            .expect("the forfeit's row");
        assert_eq!(row.kind, v0::ProtEntryKind::ForfeitTank);
        assert_eq!(
            (row.debit.as_str(), row.credit.as_str()),
            (
                prot_tank_account(&launched.tank.id).as_str(),
                PROT_SYS_FORFEITED
            )
        );
        assert_eq!(row.amount, TARGET);
        // The audit record: who did it, and why (decoded)
        assert_eq!(row.actor, staff.id);
        assert_eq!(row.reason.as_deref(), Some("spam ring \u{2014} report 42"));

        assert_eq!(
            balance(&harness, &prot_tank_account(&launched.tank.id)).await,
            0
        );
        assert_eq!(
            balance(&harness, &prot_user_account(&launched.backer.id)).await,
            0,
            "a terminated tank's leftover went back to a contributor"
        );

        // Never plaintext: the channel keeps its protection, under a Deleted
        // entitlement
        assert!(db
            .fetch_channel(launched.channel.id())
            .await
            .expect("the channel")
            .is_protected());
        assert_eq!(
            db.fetch_channel_entitlement(launched.channel.id())
                .await
                .expect("entitlement read")
                .map(|entitlement| entitlement.state),
            Some(ChannelEntitlementState::Deleted)
        );
    }

    #[test]
    fn terminate_of_an_unlaunched_tank_returns_the_pledges() {
        crate::util::test::rt().block_on(terminate_of_an_unlaunched_tank_returns_the_pledges_case())
    }

    /// 9.5 (audit 8): a Launching tank whose channel never got protected has
    /// nothing to terminate. Its goal is cancelled with the pledge returned,
    /// the tank is removed, and the answer is NotFound.
    async fn terminate_of_an_unlaunched_tank_returns_the_pledges_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (session, _) = new_staff(&harness).await;
        let launched = launched_tank(&harness, false).await;
        assert!(!launched.channel.is_protected());
        assert_eq!(
            balance(&harness, &prot_user_account(&launched.backer.id)).await,
            0
        );

        let response = terminate(&harness, &session, Some("abuse"), &launched.tank.id).await;
        assert_eq!(response.status(), Status::NotFound);
        assert_eq!(error_type(response).await, "NotFound");

        let goal = db
            .fetch_prot_goal(&launched.goal.id)
            .await
            .expect("goal read")
            .expect("the launch goal");
        assert_eq!(goal.state, v0::ProtGoalState::Cancelled);
        assert_eq!(
            balance(&harness, &prot_user_account(&launched.backer.id)).await,
            TARGET
        );
        assert!(db
            .fetch_prot_tank(&launched.tank.id)
            .await
            .expect("tank read")
            .is_none());
        assert!(db
            .fetch_prot_entry_by_key(&prot_key_forfeit_tank(&launched.tank.id))
            .await
            .expect("ledger read")
            .is_none());
        assert!(!db
            .fetch_channel(launched.channel.id())
            .await
            .expect("the channel")
            .is_protected());
    }

    /// Support must be able to end a tank while Prot is switched off, so the
    /// route reads neither the Prot nor the payments settings (the same rule
    /// as `prot_admin_routes_are_not_gated_on_the_prot_flags`)
    #[test]
    fn terminate_route_is_not_gated_on_the_prot_flags() {
        let source = include_str!("prot_terminate.rs");
        let route = source.split("#[cfg(test)]").next().expect("route code");
        let code = without_comments(route);
        assert!(
            code.contains("#[openapi(tag = \"Payments\")]"),
            "the route code was not found"
        );

        for gate in &[
            "protection",
            "ProtSalesSettings",
            "PaymentsSettings",
            "config()",
            "ProtDisabled",
        ] {
            assert!(
                !code.contains(gate),
                "the route reads `{}`; staff routes must work while Prot is off",
                gate
            );
        }
    }
}
