use revolt_database::{now_ms, Database, User};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_result::Result;
use rocket::{serde::json::Json, State};

use super::{read_rules, refuse_bots, validate, write_rules};

/// # Create Upgrade Goal
///
/// The server owner opens a goal to move the channel's tank to a bigger
/// slot tier. The server prices it from the tank's balance and the cost
/// table; members pledge towards it and the tier moves once it is funded.
#[openapi(tag = "Prot")]
#[post("/channels/<channel_id>/goals", data = "<data>")]
pub async fn create_prot_upgrade_goal(
    db: &State<Database>,
    user: User,
    channel_id: &str,
    data: Json<v0::DataProtUpgradeGoal>,
) -> Result<Json<v0::ProtGoalView>> {
    refuse_bots(&user)?;
    let rules = write_rules().await?;
    let data = data.into_inner();
    validate(&data)?;

    // Visibility, self-serve, the owner, the tier and the price: engine
    Ok(Json(
        engine::tank::create_prot_upgrade_goal(db, &user, channel_id, data, &rules, now_ms())
            .await?,
    ))
}

/// # Fetch Server Launch Goals
///
/// The server's open launch goals: what they would buy, how far they are
/// funded, their contributors (hidden ones as Anonymous) and the caller's
/// own pledges. Members who can see the server; readable while Prot is
/// switched off.
#[openapi(tag = "Prot")]
#[get("/servers/<server_id>/goals")]
pub async fn fetch_prot_server_goals(
    db: &State<Database>,
    user: User,
    server_id: &str,
) -> Result<Json<Vec<v0::ProtGoalView>>> {
    refuse_bots(&user)?;
    let rules = read_rules().await?;

    Ok(Json(
        engine::tank::fetch_prot_server_goals(db, &user, server_id, &rules, now_ms()).await?,
    ))
}

/// # Create Launch Goal
///
/// The server owner opens a goal to fund a new Protected channel for a
/// number of slots and days. The server prices it from the cost table. One
/// open launch goal per server; the same `nonce` answers with the goal it
/// created.
#[openapi(tag = "Prot")]
#[post("/servers/<server_id>/goals", data = "<data>")]
pub async fn create_prot_launch_goal(
    db: &State<Database>,
    user: User,
    server_id: &str,
    data: Json<v0::DataProtLaunchGoal>,
) -> Result<Json<v0::ProtGoalView>> {
    refuse_bots(&user)?;
    let rules = write_rules().await?;
    let data = data.into_inner();
    validate(&data)?;

    // Visibility, self-serve, the owner, slots, days and the price: engine
    Ok(Json(
        engine::tank::create_prot_launch_goal(db, &user, server_id, data, &rules, now_ms()).await?,
    ))
}

/// # Fetch Goal
///
/// One launch or upgrade goal, for anyone who can see its channel (or, for
/// a launch goal not launched yet, its server). Readable while Prot is
/// switched off.
#[openapi(tag = "Prot")]
#[get("/goals/<goal_id>")]
pub async fn fetch_prot_goal(
    db: &State<Database>,
    user: User,
    goal_id: &str,
) -> Result<Json<v0::ProtGoalView>> {
    refuse_bots(&user)?;
    let rules = read_rules().await?;

    Ok(Json(
        engine::tank::fetch_prot_goal(db, &user, goal_id, &rules, now_ms()).await?,
    ))
}

/// # Pledge to Goal
///
/// Hold Prot from the caller's wallet for a goal. A pledge never reserves a
/// seat. It is capped at what the goal still needs; it can be withdrawn
/// until shortly before the deadline and goes back in full if the goal does
/// not happen. The `nonce` makes a retry safe.
#[openapi(tag = "Prot")]
#[post("/goals/<goal_id>/pledges", data = "<data>")]
pub async fn pledge_prot(
    db: &State<Database>,
    user: User,
    goal_id: &str,
    data: Json<v0::DataProtContribute>,
) -> Result<Json<v0::ProtPledgeResponse>> {
    refuse_bots(&user)?;
    let rules = write_rules().await?;
    let data = data.into_inner();
    validate(&data)?;

    // Visibility, D6 eligibility, the goal's state and deadline, the amount
    // and the purchase hold: engine
    Ok(Json(
        engine::tank::pledge_prot(db, &user, goal_id, data, &rules, now_ms()).await?,
    ))
}

/// # Withdraw Pledge
///
/// The pledger takes a held pledge back into their wallet, while the goal
/// is still funding and before the withdraw cutoff. Another user's pledge,
/// and a pledge of another goal, are `NotFound`.
#[openapi(tag = "Prot")]
#[delete("/goals/<goal_id>/pledges/<pledge_id>")]
pub async fn withdraw_prot_pledge(
    db: &State<Database>,
    user: User,
    goal_id: &str,
    pledge_id: &str,
) -> Result<Json<v0::ProtPledgeView>> {
    refuse_bots(&user)?;
    let rules = write_rules().await?;

    Ok(Json(
        engine::tank::withdraw_prot_pledge(db, &user, goal_id, pledge_id, &rules, now_ms()).await?,
    ))
}

/// # Cancel Goal
///
/// The server owner cancels an open goal. Every held pledge goes back to
/// its pledger.
#[openapi(tag = "Prot")]
#[post("/goals/<goal_id>/cancel")]
pub async fn cancel_prot_goal(
    db: &State<Database>,
    user: User,
    goal_id: &str,
) -> Result<Json<v0::ProtGoalView>> {
    refuse_bots(&user)?;
    let rules = write_rules().await?;

    Ok(Json(
        engine::tank::cancel_prot_goal(db, &user, goal_id, &rules, now_ms()).await?,
    ))
}

/// # Launch Goal
///
/// The server owner puts a funded launch goal onto an empty text channel of
/// the same server. The channel gets its tank; the pledges move into it
/// once the owner's device protects the channel.
#[openapi(tag = "Prot")]
#[post("/goals/<goal_id>/launch", data = "<data>")]
pub async fn launch_prot_goal(
    db: &State<Database>,
    user: User,
    goal_id: &str,
    data: Json<v0::DataProtGoalLaunch>,
) -> Result<Json<v0::ProtGoalView>> {
    refuse_bots(&user)?;
    let rules = write_rules().await?;
    let data = data.into_inner();
    validate(&data)?;

    // Visibility, self-serve, the owner, the goal's state and the channel
    // (an empty, unprotected text channel of the goal's server): engine
    Ok(Json(
        engine::tank::launch_prot_goal(db, &user, goal_id, data, &rules, now_ms()).await?,
    ))
}

#[cfg(test)]
mod tests {
    use revolt_database::prot_tank_account;
    use revolt_models::v0::{self, PROT_SEAT_NOTICE};
    use rocket::http::{Method, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use super::super::tests::{
        balance, call, goal, ok_json, refused, tank, wallet, Caller, World, FUNDS, TARGET,
    };

    fn goal_view(body: Value) -> v0::ProtGoalView {
        serde_json::from_value(body).expect("`ProtGoalView`")
    }

    /// A launch goal end to end through the routes: only the owner creates
    /// it, priced by the server (forged price fields are not read) within
    /// the configured days; the same nonce is a retry and a second open goal
    /// is refused. Members list it, pledge (capped at the target, the notice
    /// on every answer), read it and withdraw their own pledge only. The
    /// owner launches it only onto an empty text channel of the same server
    /// and can cancel it again, which returns every pledge.
    #[test]
    fn launch_goal_through_the_routes() {
        crate::util::test::rt().block_on(launch_goal_through_the_routes_case())
    }

    async fn launch_goal_through_the_routes_case() {
        let w = World::new().await;
        let h = &w.harness;
        let goals = w.server_path("goals");
        let nonce = Ulid::new().to_string();
        let create = json!({
            "slots": 10,
            "days": 30,
            "nonce": nonce,
            // Forged: never read
            "target_prot": 1,
            "daily_cost": 1
        });

        let response = call(h, &w.member, Method::Post, &goals, Some(create.clone())).await;
        refused(response, Status::Forbidden, "NotOwner").await;
        for (slots, days) in [(30, 30), (10, 29), (10, 366)] {
            let body = json!({ "slots": slots, "days": days, "nonce": Ulid::new().to_string() });
            let response = call(h, &w.owner, Method::Post, &goals, Some(body)).await;
            refused(response, Status::BadRequest, "FailedValidation").await;
        }

        let created = goal_view(
            ok_json(call(h, &w.owner, Method::Post, &goals, Some(create.clone())).await).await,
        );
        assert_eq!(created.kind, v0::ProtGoalKind::Launch);
        assert_eq!(created.server_id, w.server.id);
        assert_eq!(created.state, v0::ProtGoalState::Funding);
        assert_eq!(created.slots, 10);
        assert_eq!(created.days, Some(30));
        assert_eq!(created.daily_cost, 40);
        assert_eq!(created.target_prot, TARGET);
        assert_eq!(created.pledged_total, 0);
        assert_eq!(created.channel_id, None);
        assert_eq!(created.notice, PROT_SEAT_NOTICE);

        // A retry answers with the same goal; another goal is refused while
        // this one is open (one open launch goal per server)
        let retried =
            goal_view(ok_json(call(h, &w.owner, Method::Post, &goals, Some(create)).await).await);
        assert_eq!(retried.id, created.id);
        let other = json!({ "slots": 25, "days": 30, "nonce": Ulid::new().to_string() });
        let response = call(h, &w.owner, Method::Post, &goals, Some(other)).await;
        refused(response, Status::Conflict, "ProtGoalClosed").await;

        let listed = ok_json(call(h, &w.member, Method::Get, &goals, None).await).await;
        let listed: Vec<v0::ProtGoalView> =
            serde_json::from_value(listed).expect("`Vec<ProtGoalView>`");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.id);

        // A pledge
        let pledges = format!("/prot/goals/{}/pledges", created.id);
        let body = json!({ "amount": 100, "nonce": Ulid::new().to_string() });
        let pledged = ok_json(call(h, &w.member, Method::Post, &pledges, Some(body)).await).await;
        let pledged: v0::ProtPledgeResponse =
            serde_json::from_value(pledged).expect("`ProtPledgeResponse`");
        assert!(!pledged.already_applied);
        assert_eq!(pledged.pledge.amount, 100);
        assert_eq!(pledged.pledge.state, v0::ProtPledgeState::Held);
        assert_eq!(pledged.goal.pledged_total, 100);
        assert_eq!(pledged.balance, FUNDS - 100);
        assert_eq!(pledged.notice, PROT_SEAT_NOTICE);
        assert_eq!(pledged.goal.notice, PROT_SEAT_NOTICE);

        let path = format!("/prot/goals/{}", created.id);
        let read = goal_view(ok_json(call(h, &w.member, Method::Get, &path, None).await).await);
        assert_eq!(read.your_pledges.len(), 1);
        assert_eq!(read.your_pledges[0].id, pledged.pledge.id);
        assert_eq!(read.contributors.len(), 1);
        assert!(read.contributors[0].you);
        assert_eq!(read.contributors[0].amount, 100);

        // Only the pledger withdraws a pledge
        let withdraw = format!("/prot/goals/{}/pledges/{}", created.id, pledged.pledge.id);
        let response = call(h, &w.backer, Method::Delete, &withdraw, None).await;
        refused(response, Status::NotFound, "NotFound").await;
        assert_eq!(wallet(h, &w.member.user.id).await, FUNDS - 100);
        let withdrawn = ok_json(call(h, &w.member, Method::Delete, &withdraw, None).await).await;
        let withdrawn: v0::ProtPledgeView =
            serde_json::from_value(withdrawn).expect("`ProtPledgeView`");
        assert_eq!(withdrawn.state, v0::ProtPledgeState::Withdrawn);
        assert_eq!(wallet(h, &w.member.user.id).await, FUNDS);
        assert_eq!(goal(h, &created.id).await.pledged_total, 0);

        // More than the goal needs is capped at the target and funds it
        let body = json!({ "amount": TARGET + 300, "nonce": Ulid::new().to_string() });
        let funded = ok_json(call(h, &w.member, Method::Post, &pledges, Some(body)).await).await;
        let funded: v0::ProtPledgeResponse =
            serde_json::from_value(funded).expect("`ProtPledgeResponse`");
        assert_eq!(funded.pledge.amount, TARGET);
        assert_eq!(funded.goal.state, v0::ProtGoalState::Funded);
        assert_eq!(wallet(h, &w.member.user.id).await, FUNDS - TARGET);

        // Launch: not by a member, not onto another server's channel, not
        // onto a protected channel
        let launch = format!("/prot/goals/{}/launch", created.id);
        let body = json!({ "channel_id": w.empty.id() });
        let response = call(h, &w.member, Method::Post, &launch, Some(body)).await;
        refused(response, Status::Forbidden, "NotOwner").await;
        let elsewhere = Caller::new(h).await;
        let (_, foreign) = h.new_protectable_channel(&elsewhere.user).await;
        let body = json!({ "channel_id": foreign.id() });
        let response = call(h, &w.owner, Method::Post, &launch, Some(body)).await;
        refused(response, Status::NotFound, "NotFound").await;
        let body = json!({ "channel_id": w.channel.id() });
        let response = call(h, &w.owner, Method::Post, &launch, Some(body)).await;
        refused(response, Status::BadRequest, "InvalidOperation").await;
        assert_eq!(goal(h, &created.id).await.state, v0::ProtGoalState::Funded);
        assert!(h
            .db
            .fetch_prot_tank_by_channel(foreign.id())
            .await
            .expect("tank read")
            .is_none());

        let body = json!({ "channel_id": w.empty.id() });
        let launched =
            goal_view(ok_json(call(h, &w.owner, Method::Post, &launch, Some(body)).await).await);
        assert_eq!(launched.state, v0::ProtGoalState::Launching);
        assert_eq!(launched.channel_id.as_deref(), Some(w.empty.id()));
        let new_tank =
            h.db.fetch_prot_tank_by_channel(w.empty.id())
                .await
                .expect("tank read")
                .expect("the Launching tank");
        assert_eq!(new_tank.stage, v0::ProtTankStage::Launching);

        // Cancelled before the protect landed: the launch is abandoned and
        // every pledge goes back
        let cancel = format!("/prot/goals/{}/cancel", created.id);
        let response = call(h, &w.member, Method::Post, &cancel, None).await;
        refused(response, Status::Forbidden, "NotOwner").await;
        let cancelled =
            goal_view(ok_json(call(h, &w.owner, Method::Post, &cancel, None).await).await);
        assert_eq!(cancelled.state, v0::ProtGoalState::Cancelled);
        assert_eq!(wallet(h, &w.member.user.id).await, FUNDS);
        assert!(h
            .db
            .fetch_prot_tank_by_channel(w.empty.id())
            .await
            .expect("tank read")
            .is_none());
        let path = format!("/prot/channels/{}/tank", w.empty.id());
        let response = call(h, &w.member, Method::Get, &path, None).await;
        refused(response, Status::NotFound, "NotFound").await;
    }

    /// An upgrade goal: only the owner opens it, priced by the server from
    /// the tank's balance ((90 - 40) x 30 days = 1,500); the tank view lists
    /// it; the tier is locked while it is open; members pledge; the owner
    /// cancels it and the pledges go back with the tier unchanged.
    #[test]
    fn upgrade_goal_through_the_routes() {
        crate::util::test::rt().block_on(upgrade_goal_through_the_routes_case())
    }

    async fn upgrade_goal_through_the_routes_case() {
        let w = World::new().await;
        let h = &w.harness;
        let path = w.tank_path("goals");
        let create = json!({ "slots": 25, "nonce": Ulid::new().to_string(), "target_prot": 1 });

        let response = call(h, &w.member, Method::Post, &path, Some(create.clone())).await;
        refused(response, Status::Forbidden, "NotOwner").await;
        let body = json!({ "slots": 10, "nonce": Ulid::new().to_string() });
        let response = call(h, &w.owner, Method::Post, &path, Some(body)).await;
        refused(response, Status::BadRequest, "InvalidOperation").await;

        let created =
            goal_view(ok_json(call(h, &w.owner, Method::Post, &path, Some(create)).await).await);
        assert_eq!(created.kind, v0::ProtGoalKind::Upgrade);
        assert_eq!(created.channel_id.as_deref(), Some(w.channel.id()));
        assert_eq!(created.tank_id.as_deref(), Some(w.tank.id.as_str()));
        assert_eq!(created.slots, 25);
        assert_eq!(created.days, None);
        assert_eq!(created.daily_cost, 90);
        assert_eq!(created.target_prot, 1_500);
        assert_eq!(created.state, v0::ProtGoalState::Funding);
        assert_eq!(created.notice, PROT_SEAT_NOTICE);

        let view = ok_json(call(h, &w.member, Method::Get, &w.tank_path("tank"), None).await).await;
        let view: v0::ProtTankView = serde_json::from_value(view).expect("`ProtTankView`");
        assert_eq!(view.goals.len(), 1);
        assert_eq!(view.goals[0].id, created.id);

        // The tier cannot move under an open upgrade goal
        let body = json!({ "slots": 50, "nonce": Ulid::new().to_string() });
        let response = call(h, &w.owner, Method::Put, &w.tank_path("tier"), Some(body)).await;
        refused(response, Status::BadRequest, "InvalidOperation").await;
        assert_eq!(tank(h, &w.tank.id).await.slot_tier, 10);

        let pledges = format!("/prot/goals/{}/pledges", created.id);
        let body = json!({ "amount": 100, "nonce": Ulid::new().to_string() });
        let pledged = ok_json(call(h, &w.member, Method::Post, &pledges, Some(body)).await).await;
        let pledged: v0::ProtPledgeResponse =
            serde_json::from_value(pledged).expect("`ProtPledgeResponse`");
        assert_eq!(pledged.goal.pledged_total, 100);
        assert_eq!(pledged.notice, PROT_SEAT_NOTICE);
        assert_eq!(wallet(h, &w.member.user.id).await, FUNDS - 100);

        let cancel = format!("/prot/goals/{}/cancel", created.id);
        let response = call(h, &w.member, Method::Post, &cancel, None).await;
        refused(response, Status::Forbidden, "NotOwner").await;
        let cancelled =
            goal_view(ok_json(call(h, &w.owner, Method::Post, &cancel, None).await).await);
        assert_eq!(cancelled.state, v0::ProtGoalState::Cancelled);
        assert_eq!(wallet(h, &w.member.user.id).await, FUNDS);
        let after = tank(h, &w.tank.id).await;
        assert_eq!(after.slot_tier, 10);
        assert_eq!(after.daily_cost, 40);
        assert_eq!(balance(h, &prot_tank_account(&w.tank.id)).await, TARGET);
    }
}
