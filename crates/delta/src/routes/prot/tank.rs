use revolt_database::{now_ms, Database, User};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_result::Result;
use rocket::{serde::json::Json, State};

use super::{read_rules, refuse_bots, validate, write_rules};

/// # Fetch Channel Tank
///
/// The fuel tank of a Protected channel as its viewers see it: the stage,
/// the balance and the dates, the slots in use, the contributors (hidden
/// ones as Anonymous), the open goals, what the caller put in and whether
/// they may top up now. Readable while Prot is switched off.
///
/// A missing channel, a channel the caller cannot view and a channel with no
/// tank (an admin-granted protected channel, an abandoned launch) all get
/// the same 404.
#[openapi(tag = "Prot")]
#[get("/channels/<channel_id>/tank")]
pub async fn fetch_prot_tank(
    db: &State<Database>,
    user: User,
    channel_id: &str,
) -> Result<Json<v0::ProtTankView>> {
    refuse_bots(&user)?;
    let rules = read_rules().await?;

    Ok(Json(
        engine::tank::fetch_prot_tank(db, &user, channel_id, &rules, now_ms()).await?,
    ))
}

/// # Top Up Channel Tank
///
/// Put Prot from the caller's wallet into the channel's tank. Contributing
/// supports the server; it never reserves a seat. Prot bought within the
/// purchase hold cannot go in yet. The `nonce` makes a retry safe: the same
/// nonce answers with the stored contribution.
#[openapi(tag = "Prot")]
#[post("/channels/<channel_id>/contribute", data = "<data>")]
pub async fn contribute_prot(
    db: &State<Database>,
    user: User,
    channel_id: &str,
    data: Json<v0::DataProtContribute>,
) -> Result<Json<v0::ProtContributionResponse>> {
    refuse_bots(&user)?;
    let rules = write_rules().await?;
    let data = data.into_inner();
    validate(&data)?;

    // Visibility, D6 eligibility, the amount, the purchase hold and the
    // tank's stage: engine
    Ok(Json(
        engine::tank::contribute_prot(db, &user, channel_id, data, &rules, now_ms()).await?,
    ))
}

/// # Change Channel Tank Tier
///
/// The server owner moves the tank to another slot tier. An upgrade is
/// charged pro rata for the rest of today from the tank; a downgrade below
/// the seats in use waits until cooldowns free them. Refused while an
/// upgrade goal of the tank is open.
#[openapi(tag = "Prot")]
#[put("/channels/<channel_id>/tier", data = "<data>")]
pub async fn change_prot_tier(
    db: &State<Database>,
    user: User,
    channel_id: &str,
    data: Json<v0::DataProtTier>,
) -> Result<Json<v0::ProtTankSummary>> {
    refuse_bots(&user)?;
    let rules = write_rules().await?;
    let data = data.into_inner();
    validate(&data)?;

    // Visibility, self-serve, the owner and the tier: engine
    Ok(Json(
        engine::tank::change_prot_tier(db, &user, channel_id, data, &rules, now_ms()).await?,
    ))
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{prot_tank_account, PartialMember};
    use revolt_models::v0::{self, PROT_SEAT_NOTICE};
    use rocket::http::{Method, Status};
    use serde_json::json;
    use ulid::Ulid;

    use super::super::tests::{
        balance, call, ok_json, refused, tank, wallet, World, FUNDS, TARGET,
    };

    /// A viewer reads the tank: the stage and balance (every viewer sees the
    /// balance, owner answer 9), the seats in use, the contributors with the
    /// caller marked, the verbatim notice; `is_owner` only for the owner. A
    /// channel without a tank (an empty channel, an admin-granted protected
    /// channel) answers exactly like a missing one.
    #[test]
    fn viewers_read_the_tank() {
        crate::util::test::rt().block_on(viewers_read_the_tank_case())
    }

    async fn viewers_read_the_tank_case() {
        let w = World::new().await;
        let h = &w.harness;

        let body = ok_json(call(h, &w.backer, Method::Get, &w.tank_path("tank"), None).await).await;
        let view: v0::ProtTankView = serde_json::from_value(body).expect("`ProtTankView`");
        assert_eq!(view.tank.tank_id, w.tank.id);
        assert_eq!(view.tank.channel_id, w.channel.id());
        assert_eq!(view.tank.stage, v0::ProtTankStage::Active);
        assert_eq!(view.tank.slot_tier, 10);
        assert_eq!(view.tank.daily_cost, 40);
        assert_eq!(view.tank.balance, TARGET);
        assert!(view.tank.protected_until.is_some());
        assert_eq!(view.seats_used, 1);
        assert!(!view.is_owner);
        assert!(view.can_contribute);
        assert_eq!(view.you_contributed, TARGET);
        assert_eq!(view.notice, PROT_SEAT_NOTICE);
        assert!(view.goals.is_empty());
        assert_eq!(view.contributors.len(), 1);
        let line = &view.contributors[0];
        assert_eq!(line.user_id.as_deref(), Some(w.backer.user.id.as_str()));
        assert_eq!(line.amount, TARGET);
        assert!(line.you && !line.hidden && !line.deleted);

        let body = ok_json(call(h, &w.owner, Method::Get, &w.tank_path("tank"), None).await).await;
        let view: v0::ProtTankView = serde_json::from_value(body).expect("`ProtTankView`");
        assert!(view.is_owner);
        assert_eq!(view.you_contributed, 0);
        assert!(!view.contributors[0].you);
        assert_eq!(
            view.contributors[0].user_id.as_deref(),
            Some(w.backer.user.id.as_str())
        );

        let missing = format!("/prot/channels/{}/tank", Ulid::new());
        let missing_body = refused(
            call(h, &w.member, Method::Get, &missing, None).await,
            Status::NotFound,
            "NotFound",
        )
        .await;

        // An empty channel the member sees has no tank
        let path = format!("/prot/channels/{}/tank", w.empty.id());
        let body = refused(
            call(h, &w.member, Method::Get, &path, None).await,
            Status::NotFound,
            "NotFound",
        )
        .await;
        assert_eq!(body, missing_body);

        // Nor has a channel protected by an admin grant, even for its owner
        let (owner_account, owner_session, owner) = h.new_user().await;
        let granted = h.new_protected_channel(&owner, &owner_session, &[]).await;
        assert!(granted.channel.is_protected());
        let granted_owner = super::super::tests::Caller {
            account: owner_account,
            user: owner,
        };
        let path = format!("/prot/channels/{}/tank", granted.channel.id());
        let body = refused(
            call(h, &granted_owner, Method::Get, &path, None).await,
            Status::NotFound,
            "NotFound",
        )
        .await;
        assert_eq!(body, missing_body);
    }

    /// A member tops the tank up: the response carries the tank, the wallet
    /// after the posting and the verbatim notice; the same nonce again is
    /// the stored contribution, applied once. Amounts outside the rules and
    /// a bad nonce are refused before anything moves; a timed-out member is
    /// not eligible (D6).
    #[test]
    fn members_top_up_the_tank_once_per_nonce() {
        crate::util::test::rt().block_on(members_top_up_the_tank_once_per_nonce_case())
    }

    async fn members_top_up_the_tank_once_per_nonce_case() {
        let w = World::new().await;
        let h = &w.harness;
        let path = w.tank_path("contribute");
        let tank_account = prot_tank_account(&w.tank.id);
        let nonce = Ulid::new().to_string();
        let body = json!({ "amount": 100, "nonce": nonce });

        let first =
            ok_json(call(h, &w.member, Method::Post, &path, Some(body.clone())).await).await;
        let first: v0::ProtContributionResponse =
            serde_json::from_value(first).expect("`ProtContributionResponse`");
        assert!(!first.already_applied);
        assert_eq!(first.balance, FUNDS - 100);
        assert_eq!(first.tank.tank_id, w.tank.id);
        assert_eq!(first.tank.balance, TARGET + 100);
        assert_eq!(first.notice, PROT_SEAT_NOTICE);

        // A retry: the stored contribution, nothing moves again
        let again = ok_json(call(h, &w.member, Method::Post, &path, Some(body)).await).await;
        let again: v0::ProtContributionResponse =
            serde_json::from_value(again).expect("`ProtContributionResponse`");
        assert!(again.already_applied);
        assert_eq!(again.entry_id, first.entry_id);
        assert_eq!(again.balance, FUNDS - 100);
        assert_eq!(again.notice, PROT_SEAT_NOTICE);
        assert_eq!(wallet(h, &w.member.user.id).await, FUNDS - 100);
        assert_eq!(balance(h, &tank_account).await, TARGET + 100);

        // Below the minimum (50), none, more than any rule allows, and
        // nonces the validator refuses
        for body in [
            json!({ "amount": 49, "nonce": Ulid::new().to_string() }),
            json!({ "amount": 0, "nonce": Ulid::new().to_string() }),
            json!({ "amount": -100, "nonce": Ulid::new().to_string() }),
            json!({ "amount": 1_000_001, "nonce": Ulid::new().to_string() }),
            json!({ "amount": 100, "nonce": "" }),
            json!({ "amount": 100, "nonce": "n".repeat(65) }),
        ] {
            let response = call(h, &w.member, Method::Post, &path, Some(body.clone())).await;
            refused(response, Status::BadRequest, "FailedValidation").await;
        }

        // D6: a member in timeout may not put Prot in
        let mut row =
            h.db.fetch_member(&w.server.id, &w.member.user.id)
                .await
                .expect("member read");
        row.update(
            &h.db,
            PartialMember {
                timeout: Some(Timestamp::now_utc() + Duration::minutes(60)),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("time the member out");
        let body = json!({ "amount": 100, "nonce": Ulid::new().to_string() });
        let response = call(h, &w.member, Method::Post, &path, Some(body)).await;
        refused(response, Status::Forbidden, "ProtNotEligible").await;

        assert_eq!(wallet(h, &w.member.user.id).await, FUNDS - 100);
        assert_eq!(balance(h, &tank_account).await, TARGET + 100);
    }

    /// Only the server owner changes the tier. A member who can see the
    /// channel gets `NotOwner` and the tank is untouched; the owner's
    /// upgrade (no burn in the test config, so no charge) moves the tier
    /// and the price to the server's cost table. A tier outside the table is
    /// refused.
    #[test]
    fn only_the_owner_changes_the_tier() {
        crate::util::test::rt().block_on(only_the_owner_changes_the_tier_case())
    }

    async fn only_the_owner_changes_the_tier_case() {
        let w = World::new().await;
        let h = &w.harness;
        let path = w.tank_path("tier");
        let before = tank(h, &w.tank.id).await;

        let body = json!({ "slots": 25, "nonce": Ulid::new().to_string() });
        let response = call(h, &w.member, Method::Put, &path, Some(body)).await;
        refused(response, Status::Forbidden, "NotOwner").await;
        let unchanged = tank(h, &w.tank.id).await;
        assert_eq!(unchanged.slot_tier, 10);
        assert_eq!(unchanged.version, before.version);

        let body = json!({ "slots": 30, "nonce": Ulid::new().to_string() });
        let response = call(h, &w.owner, Method::Put, &path, Some(body)).await;
        refused(response, Status::BadRequest, "FailedValidation").await;

        // A daily cost in the body is not read: the server prices the tier
        let body = json!({ "slots": 25, "nonce": Ulid::new().to_string(), "daily_cost": 1 });
        let summary = ok_json(call(h, &w.owner, Method::Put, &path, Some(body)).await).await;
        let summary: v0::ProtTankSummary =
            serde_json::from_value(summary).expect("`ProtTankSummary`");
        assert_eq!(summary.tank_id, w.tank.id);
        assert_eq!(summary.slot_tier, 25);
        assert_eq!(summary.daily_cost, 90);
        assert_eq!(summary.balance, TARGET);

        let changed = tank(h, &w.tank.id).await;
        assert_eq!(changed.slot_tier, 25);
        assert_eq!(changed.daily_cost, 90);
        assert_eq!(
            h.db.fetch_channel_entitlement(w.channel.id())
                .await
                .expect("entitlement read")
                .map(|entitlement| entitlement.slot_cap),
            Some(25)
        );
    }
}
