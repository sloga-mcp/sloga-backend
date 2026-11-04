//! Prot fuel tanks and goals (S5b): contributions, tiers, launch and upgrade
//! goals, pledges and the hide-name preference.
//!
//! Every route is a thin wrapper over the `revolt_payments::engine::tank`
//! function of the same name (contracts 11.2, 11.7). A route refuses bots,
//! loads the tank rules (a config that fails validation refuses the
//! request), runs the body's validator and, for a write, checks that Prot is
//! switched on. The engine decides everything else, in this order: a caller
//! who cannot see the channel, server or goal gets `NotFound` (the answer a
//! missing one gets, 11.1), then self-serve, the owner check, D6 eligibility,
//! amounts and prices. The checks before the engine call never read the
//! target, so none of them tells a hidden channel from a missing one.
use revolt_config::ProtectionFeatures;
use revolt_database::{ProtTankRules, User};
use revolt_result::{create_error, Result};
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;
use validator::Validate;

mod goals;
mod prefs;
mod tank;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        // A channel's tank
        tank::fetch_prot_tank,
        tank::contribute_prot,
        tank::change_prot_tier,
        // Goals
        goals::create_prot_upgrade_goal,
        goals::fetch_prot_server_goals,
        goals::create_prot_launch_goal,
        goals::fetch_prot_goal,
        goals::pledge_prot,
        goals::withdraw_prot_pledge,
        goals::cancel_prot_goal,
        goals::launch_prot_goal,
        // Contributor preferences
        prefs::set_prot_contributor_prefs,
    ]
}

/// Bots never read tanks, contribute or pledge (11.1)
fn refuse_bots(user: &User) -> Result<()> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }
    Ok(())
}

/// The tank rules for a read. Reads are NOT gated on `enabled` (BR17, owner
/// answer 3): they report state that still binds.
async fn read_rules() -> Result<ProtTankRules> {
    ProtTankRules::load().await
}

/// The tank rules for a write, which also needs Prot switched on. The
/// engine has no such gate of its own.
async fn write_rules() -> Result<ProtTankRules> {
    let rules = ProtTankRules::load().await?;
    require_enabled(&revolt_config::config().await.features.boosts.protection)?;
    Ok(rules)
}

/// `[features.boosts.protection] enabled`, else `ProtDisabled`, for every
/// caller (11.1)
fn require_enabled(protection: &ProtectionFeatures) -> Result<()> {
    if !protection.enabled {
        return Err(create_error!(ProtDisabled));
    }
    Ok(())
}

/// Run the body's validator (nonce and channel id lengths)
fn validate<T: Validate>(data: &T) -> Result<()> {
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })
}

/// Shared fixtures for the Prot route tests, and the tests that cover every
/// route at once. Each request gets a fresh session: writes share the
/// `prot_write` bucket (3 per 10 s per session).
#[cfg(test)]
mod tests {
    use revolt_config::ProtectionFeatures;
    use revolt_database::{
        now_ms, prot_key_admin, prot_tank_account, prot_user_account, Account, Bot, Channel,
        PartialMember, PartialUser, ProtAmount, ProtGoal, ProtLaunchInput, ProtPledge,
        ProtPledgeInput, ProtPosting, ProtRef, ProtTank, ProtTankRules, Server, User,
        PROT_SYS_ADJUST,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Method, Status};
    use rocket::local::asynchronous::LocalResponse;
    use serde_json::{json, Value};
    use ulid::Ulid;

    use crate::util::test::{TestHarness, FIXTURE_DEVICE_CAP, OWNER_DEVICE_SEED};

    pub(super) const DAY: i64 = 86_400_000;
    /// A 10-slot, 30-day launch goal at the default 40 Prot a day
    pub(super) const TARGET: i64 = 1_200;
    /// What every funded caller other than the backer holds
    pub(super) const FUNDS: i64 = 2_000;
    /// The actor of the tests' own wallet credits
    const FUNDER: &str = "01PROTROUTESTESTFUNDER0000";

    /// Self-serve on and no burn (the test config's switches): a launched
    /// tank holds exactly its pledges
    pub(super) fn rules() -> ProtTankRules {
        ProtTankRules {
            self_serve: true,
            burning: false,
            ..ProtTankRules::from_config(&ProtectionFeatures::default())
                .expect("the default Prot config is valid")
        }
    }

    /// A user with their account, so each request can open a new session
    pub(super) struct Caller {
        pub account: Account,
        pub user: User,
    }

    impl Caller {
        pub(super) async fn new(harness: &TestHarness) -> Caller {
            let (account, _, user) = harness.new_user().await;
            Caller { account, user }
        }

        /// A new session's header
        pub(super) async fn auth(&self, harness: &TestHarness) -> Header<'static> {
            let session = self
                .account
                .create_session(&harness.db, String::new())
                .await
                .expect("`Session`");
            Header::new("x-session-token", session.token)
        }
    }

    pub(super) async fn send<'c>(
        harness: &'c TestHarness,
        auth: Header<'static>,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> LocalResponse<'c> {
        let mut request = harness.client.req(method, path.to_string()).header(auth);
        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }
        request.dispatch().await
    }

    /// `method path` as `caller`, from a new session
    pub(super) async fn call<'c>(
        harness: &'c TestHarness,
        caller: &Caller,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> LocalResponse<'c> {
        let auth = caller.auth(harness).await;
        send(harness, auth, method, path, body).await
    }

    /// The 200 body
    pub(super) async fn ok_json(response: LocalResponse<'_>) -> Value {
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(status, Status::Ok, "{body}");
        serde_json::from_str(&body).unwrap_or_else(|_| panic!("body is not JSON: {}", body))
    }

    /// The refusal's raw body, after checking its status and error type
    pub(super) async fn refused(
        response: LocalResponse<'_>,
        status: Status,
        error_type: &str,
    ) -> String {
        let actual = response.status();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(actual, status, "expected {error_type}: {body}");
        let value: Value = serde_json::from_str(&body)
            .unwrap_or_else(|_| panic!("error body is not JSON: {}", body));
        assert_eq!(value["type"], error_type, "{body}");
        body
    }

    /// An admin credit of `amount` (never held: D17 holds only purchases)
    pub(super) async fn fund(harness: &TestHarness, user_id: &str, amount: i64) {
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
                reason: Some("prot route test".to_string()),
                created_at: now_ms() - 60_000,
            })
            .await
            .expect("fund");
    }

    pub(super) async fn balance(harness: &TestHarness, account: &str) -> i64 {
        harness
            .db
            .fetch_prot_account(account)
            .await
            .expect("account read")
            .map_or(0, |account| account.balance)
    }

    pub(super) async fn wallet(harness: &TestHarness, user_id: &str) -> i64 {
        balance(harness, &prot_user_account(user_id)).await
    }

    pub(super) async fn goal(harness: &TestHarness, goal_id: &str) -> ProtGoal {
        harness
            .db
            .fetch_prot_goal(goal_id)
            .await
            .expect("goal read")
            .expect("the goal")
    }

    pub(super) async fn tank(harness: &TestHarness, tank_id: &str) -> ProtTank {
        harness
            .db
            .fetch_prot_tank(tank_id)
            .await
            .expect("tank read")
            .expect("the tank")
    }

    /// A Funding launch goal of `server` for `slots` slots over 30 days,
    /// written through the database
    pub(super) async fn new_launch_goal(
        harness: &TestHarness,
        server: &Server,
        owner: &User,
        slots: u32,
    ) -> ProtGoal {
        let rules = rules();
        let now = now_ms();
        let daily_cost = rules.daily_cost(slots).expect("a slot tier");
        harness
            .db
            .create_prot_goal(&ProtGoal {
                id: Ulid::new().to_string(),
                kind: v0::ProtGoalKind::Launch,
                server_id: server.id.clone(),
                channel_id: None,
                tank_id: None,
                created_by: owner.id.clone(),
                create_nonce: Ulid::new().to_string(),
                slots,
                days: Some(30),
                daily_cost,
                base_daily_cost: None,
                target_prot: 30 * daily_cost,
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
            .expect("launch goal")
    }

    /// A pledge written through the database
    pub(super) async fn db_pledge(
        harness: &TestHarness,
        user_id: &str,
        goal_id: &str,
        amount: i64,
    ) -> ProtPledge {
        harness
            .db
            .pledge_prot(&ProtPledgeInput {
                user_id: user_id.to_string(),
                goal_id: goal_id.to_string(),
                amount,
                nonce: Ulid::new().to_string(),
                rules: rules(),
                now: now_ms(),
            })
            .await
            .expect("pledge")
            .pledge
    }

    /// One server with a crowdfunded Protected channel (tank Active, holding
    /// [`TARGET`], the owner seated) and the callers the tests need
    pub(super) struct World {
        pub harness: TestHarness,
        pub owner: Caller,
        /// Pledged all of [`TARGET`]; their wallet is empty
        pub backer: Caller,
        /// A member holding [`FUNDS`]
        pub member: Caller,
        /// A member holding [`FUNDS`] whose role denies ViewChannel on the
        /// server (so on every channel)
        pub hidden: Caller,
        /// Not a member; holds [`FUNDS`]
        pub stranger: Caller,
        pub server: Server,
        /// Protected; its tank is [`World::tank`]
        pub channel: Channel,
        /// An empty, unprotected text channel of the server
        pub empty: Channel,
        pub tank: ProtTank,
        /// The launch goal that funded the tank (Launched)
        pub launched: ProtGoal,
    }

    impl World {
        pub(super) async fn new() -> World {
            let harness = TestHarness::new().await;
            let rules = rules();
            let (owner_account, owner_session, owner_user) = harness.new_user().await;
            let owner = Caller {
                account: owner_account,
                user: owner_user,
            };
            let (server, channel) = harness.new_protectable_channel(&owner.user).await;

            let backer = Caller::new(&harness).await;
            let member = Caller::new(&harness).await;
            let hidden = Caller::new(&harness).await;
            let stranger = Caller::new(&harness).await;
            for caller in [&backer, &member, &hidden] {
                harness.join_server(&server, &caller.user).await;
            }
            fund(&harness, &backer.user.id, TARGET).await;
            for caller in [&member, &hidden, &stranger] {
                fund(&harness, &caller.user.id, FUNDS).await;
            }

            // A server-level deny reaches every channel: the channel
            // calculus starts from the server's permissions
            let role = harness
                .new_role(
                    &server,
                    1,
                    Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                )
                .await;
            let mut row = harness
                .db
                .fetch_member(&server.id, &hidden.user.id)
                .await
                .expect("member read");
            row.update(
                &harness.db,
                PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("assign the role");

            // Fund, launch, protect, capture: the owner's flow, through the
            // database
            let goal_row = new_launch_goal(&harness, &server, &owner.user, 10).await;
            assert_eq!(goal_row.target_prot, TARGET);
            db_pledge(&harness, &backer.user.id, &goal_row.id, TARGET).await;
            let (_, launching) = harness
                .db
                .launch_prot_goal(&ProtLaunchInput {
                    goal_id: goal_row.id.clone(),
                    channel_id: channel.id().to_string(),
                    owner_id: owner.user.id.clone(),
                    rules: rules.clone(),
                    now: now_ms(),
                })
                .await
                .expect("launch");
            assert_eq!(launching.stage, v0::ProtTankStage::Launching);

            let device = harness
                .new_e2ee_device(&owner.user, &owner_session.id, OWNER_DEVICE_SEED)
                .await;
            let seats = [owner.user.id.clone()];
            let request = device.protect_request(channel.id(), FIXTURE_DEVICE_CAP, &seats);
            harness.protect_with_db(&channel, &request).await;
            let tank = harness
                .db
                .capture_launch_pledges(channel.id(), now_ms(), &rules)
                .await
                .expect("capture")
                .expect("a protected Launching tank is captured");
            assert_eq!(tank.stage, v0::ProtTankStage::Active);
            assert_eq!(
                balance(&harness, &prot_tank_account(&tank.id)).await,
                TARGET
            );

            let channel = harness
                .db
                .fetch_channel(channel.id())
                .await
                .expect("the protected channel");
            assert!(channel.is_protected());
            let empty = harness.new_channel(&server).await;
            let server = harness.db.fetch_server(&server.id).await.expect("`Server`");
            let launched = goal(&harness, &goal_row.id).await;
            assert_eq!(launched.state, v0::ProtGoalState::Launched);

            World {
                harness,
                owner,
                backer,
                member,
                hidden,
                stranger,
                server,
                channel,
                empty,
                tank,
                launched,
            }
        }

        pub(super) fn tank_path(&self, leaf: &str) -> String {
            format!("/prot/channels/{}/{leaf}", self.channel.id())
        }

        pub(super) fn server_path(&self, leaf: &str) -> String {
            format!("/prot/servers/{}/{leaf}", self.server.id)
        }
    }

    /// Every Prot route as mounted under `/prot`, with a body each would
    /// accept
    fn every_route(
        channel_id: &str,
        server_id: &str,
        goal_id: &str,
        pledge_id: &str,
    ) -> Vec<(Method, String, Option<Value>)> {
        let contribute = json!({ "amount": 100, "nonce": Ulid::new().to_string() });
        vec![
            (
                Method::Get,
                format!("/prot/channels/{channel_id}/tank"),
                None,
            ),
            (
                Method::Post,
                format!("/prot/channels/{channel_id}/contribute"),
                Some(contribute.clone()),
            ),
            (
                Method::Put,
                format!("/prot/channels/{channel_id}/tier"),
                Some(json!({ "slots": 25, "nonce": "tier" })),
            ),
            (
                Method::Post,
                format!("/prot/channels/{channel_id}/goals"),
                Some(json!({ "slots": 25, "nonce": "upgrade" })),
            ),
            (
                Method::Get,
                format!("/prot/servers/{server_id}/goals"),
                None,
            ),
            (
                Method::Post,
                format!("/prot/servers/{server_id}/goals"),
                Some(json!({ "slots": 10, "days": 30, "nonce": "launch" })),
            ),
            (
                Method::Put,
                format!("/prot/servers/{server_id}/contributor"),
                Some(json!({ "hidden": true })),
            ),
            (Method::Get, format!("/prot/goals/{goal_id}"), None),
            (
                Method::Post,
                format!("/prot/goals/{goal_id}/pledges"),
                Some(contribute),
            ),
            (
                Method::Delete,
                format!("/prot/goals/{goal_id}/pledges/{pledge_id}"),
                None,
            ),
            (Method::Post, format!("/prot/goals/{goal_id}/cancel"), None),
            (
                Method::Post,
                format!("/prot/goals/{goal_id}/launch"),
                Some(json!({ "channel_id": channel_id })),
            ),
        ]
    }

    /// The twelve routes of 11.2, each once, with the method and path the
    /// contracts pin (`/prot` is the mount point)
    #[test]
    fn prot_routes_are_the_contracted_twelve() {
        let (routes, _) = super::routes();
        let mut actual: Vec<(String, String)> = routes
            .iter()
            .map(|route| (route.method.to_string(), route.uri.path().to_string()))
            .collect();
        actual.sort();
        let mut expected: Vec<(String, String)> = [
            ("GET", "/channels/<channel_id>/tank"),
            ("POST", "/channels/<channel_id>/contribute"),
            ("PUT", "/channels/<channel_id>/tier"),
            ("POST", "/channels/<channel_id>/goals"),
            ("GET", "/servers/<server_id>/goals"),
            ("POST", "/servers/<server_id>/goals"),
            ("PUT", "/servers/<server_id>/contributor"),
            ("GET", "/goals/<goal_id>"),
            ("POST", "/goals/<goal_id>/pledges"),
            ("DELETE", "/goals/<goal_id>/pledges/<pledge_id>"),
            ("POST", "/goals/<goal_id>/cancel"),
            ("POST", "/goals/<goal_id>/launch"),
        ]
        .iter()
        .map(|(method, path)| (method.to_string(), path.to_string()))
        .collect();
        expected.sort();
        assert_eq!(actual, expected);
    }

    /// Prot off refuses a write for every caller; the test config turns it
    /// on, so the routes below cannot show this end to end
    #[test]
    fn writes_need_prot_enabled() {
        let off = ProtectionFeatures::default();
        assert!(!off.enabled);
        match super::require_enabled(&off) {
            Err(error) => assert!(
                matches!(error.error_type, revolt_result::ErrorType::ProtDisabled),
                "{:?}",
                error
            ),
            Ok(()) => panic!("a write went through with Prot off"),
        }
        let on = ProtectionFeatures {
            enabled: true,
            ..Default::default()
        };
        assert!(super::require_enabled(&on).is_ok());
    }

    /// Every route refuses bots first; every write then needs Prot on
    /// (`write_rules`), every read is open while it is off (`read_rules`,
    /// BR17). A source pin, because `overwrite_config` works once per
    /// process and the test config has Prot on. Control: call
    /// `read_rules()` in `withdraw_prot_pledge` and this fails.
    #[test]
    fn every_write_route_checks_prot_is_on() {
        let sources = [
            include_str!("tank.rs"),
            include_str!("goals.rs"),
            include_str!("prefs.rs"),
        ];
        let mut reads = 0;
        let mut writes = 0;
        for source in sources {
            let routes = source.split("#[cfg(test)]").next().expect("the route half");
            for route in routes.split("#[openapi(tag = \"Prot\")]").skip(1) {
                let name = route
                    .split("pub async fn ")
                    .nth(1)
                    .and_then(|rest| rest.split('(').next())
                    .expect("a route fn");
                let bots = route
                    .find("refuse_bots(&user)?;")
                    .unwrap_or_else(|| panic!("{} does not refuse bots", name));
                let read = route.find("read_rules().await?");
                let write = route.find("write_rules().await?");
                if route.trim_start().starts_with("#[get(") {
                    reads += 1;
                    let read = read.unwrap_or_else(|| panic!("{} does not load the rules", name));
                    assert!(write.is_none(), "{} is a read gated on `enabled`", name);
                    assert!(bots < read, "{}", name);
                } else {
                    writes += 1;
                    let write =
                        write.unwrap_or_else(|| panic!("{} does not check Prot is on", name));
                    assert!(read.is_none(), "{} is a write that skips `enabled`", name);
                    assert!(bots < write, "{}", name);
                }
            }
        }
        assert_eq!((reads, writes), (3, 9));
    }

    /// A caller who cannot see the channel (a member whose role denies
    /// ViewChannel) or the server (not a member) gets the same 404 as a
    /// missing channel, server or goal on EVERY route, and nothing is
    /// written. The first request is the hidden member's tank read: with the
    /// ViewChannel check dropped (the L5c control, in `visible_channel` of
    /// `engine/tank.rs`) it answers 200 and this fails.
    #[test]
    fn non_viewer_gets_not_found() {
        crate::util::test::rt().block_on(non_viewer_gets_not_found_case())
    }

    async fn non_viewer_gets_not_found_case() {
        let w = World::new().await;
        let h = &w.harness;

        // A Funding launch goal of the server with one of the member's
        // pledges in it: a target for the goal routes
        let open = new_launch_goal(h, &w.server, &w.owner.user, 10).await;
        let pledge = db_pledge(h, &w.member.user.id, &open.id, 100).await;
        let before = tank(h, &w.tank.id).await;

        // The control's tripwire comes first
        let response = call(h, &w.hidden, Method::Get, &w.tank_path("tank"), None).await;
        let hidden_body = refused(response, Status::NotFound, "NotFound").await;

        // The same body as a channel that does not exist
        let missing = format!("/prot/channels/{}/tank", Ulid::new());
        let response = call(h, &w.member, Method::Get, &missing, None).await;
        let missing_body = refused(response, Status::NotFound, "NotFound").await;
        assert_eq!(hidden_body, missing_body);

        // Every route: the protected channel, the server, the open goal
        for caller in [&w.hidden, &w.stranger] {
            for (method, path, body) in
                every_route(w.channel.id(), &w.server.id, &open.id, &pledge.id)
            {
                let response = call(h, caller, method, &path, body).await;
                let status = response.status();
                let text = response.into_string().await.unwrap_or_default();
                assert_eq!(status, Status::NotFound, "{method} {path}: {text}");
                assert_eq!(text, missing_body, "{method} {path}");
            }
            // The launched goal is seen through its channel
            let path = format!("/prot/goals/{}", w.launched.id);
            let response = call(h, caller, Method::Get, &path, None).await;
            refused(response, Status::NotFound, "NotFound").await;
        }

        // A missing server and a missing goal answer alike
        let missing_server = format!("/prot/servers/{}/goals", Ulid::new());
        let response = call(h, &w.member, Method::Get, &missing_server, None).await;
        assert_eq!(
            refused(response, Status::NotFound, "NotFound").await,
            missing_body
        );
        let missing_goal = format!("/prot/goals/{}", Ulid::new());
        let response = call(h, &w.member, Method::Get, &missing_goal, None).await;
        assert_eq!(
            refused(response, Status::NotFound, "NotFound").await,
            missing_body
        );

        // Nothing moved and nothing was recorded
        for caller in [&w.hidden, &w.stranger] {
            assert_eq!(wallet(h, &caller.user.id).await, FUNDS);
        }
        assert_eq!(balance(h, &prot_tank_account(&w.tank.id)).await, TARGET);
        let after = tank(h, &w.tank.id).await;
        assert_eq!(after.slot_tier, 10);
        assert_eq!(after.version, before.version);
        let open_after = goal(h, &open.id).await;
        assert_eq!(open_after.state, v0::ProtGoalState::Funding);
        assert_eq!(open_after.pledged_total, 100);
        assert_eq!(open_after.channel_id, None);
        let pledges =
            h.db.fetch_prot_pledges_by_goal(&open.id)
                .await
                .expect("pledges");
        assert_eq!(pledges.len(), 1);
        assert_eq!(pledges[0].state, v0::ProtPledgeState::Held);
        assert_eq!(pledges[0].remaining, 100);
        assert_eq!(
            h.db.fetch_open_prot_goals_by_server(&w.server.id)
                .await
                .expect("open goals")
                .len(),
            1
        );
        assert!(h
            .db
            .fetch_open_prot_goals_by_tank(&w.tank.id)
            .await
            .expect("open goals")
            .is_empty());
        let prefs =
            h.db.fetch_prot_contributor_prefs(
                &w.server.id,
                &[w.hidden.user.id.clone(), w.stranger.user.id.clone()],
            )
            .await
            .expect("prefs");
        assert!(prefs.is_empty(), "{:?}", prefs);
    }

    /// Staff see every channel through the permission calculus, but without
    /// a member row of their own they are refused like any non-member
    /// (11.3): reads and writes alike, nothing written
    #[test]
    fn staff_without_a_member_row_are_refused() {
        crate::util::test::rt().block_on(staff_without_a_member_row_are_refused_case())
    }

    async fn staff_without_a_member_row_are_refused_case() {
        let w = World::new().await;
        let h = &w.harness;
        let mut staff = Caller::new(h).await;
        staff
            .user
            .update(
                &h.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("promote staff");
        assert!(staff.user.privileged);
        fund(h, &staff.user.id, FUNDS).await;

        let response = call(h, &staff, Method::Get, &w.tank_path("tank"), None).await;
        refused(response, Status::NotFound, "NotFound").await;
        let body = json!({ "amount": 100, "nonce": Ulid::new().to_string() });
        let response = call(
            h,
            &staff,
            Method::Post,
            &w.tank_path("contribute"),
            Some(body),
        )
        .await;
        refused(response, Status::NotFound, "NotFound").await;
        let response = call(h, &staff, Method::Get, &w.server_path("goals"), None).await;
        refused(response, Status::NotFound, "NotFound").await;

        assert_eq!(wallet(h, &staff.user.id).await, FUNDS);
        assert_eq!(balance(h, &prot_tank_account(&w.tank.id)).await, TARGET);
    }

    /// A bot is refused with `IsBot` before anything else, on reads and
    /// writes, even as a funded member of the server (this also proves the
    /// paths are mounted: an unmounted path is a plain 404). Bot requests
    /// carry no session, so they share one per-address bucket: three writes
    /// fit one window.
    #[test]
    fn prot_routes_refuse_bots() {
        crate::util::test::rt().block_on(prot_routes_refuse_bots_case())
    }

    async fn prot_routes_refuse_bots_case() {
        let w = World::new().await;
        let h = &w.harness;
        let (bot, _) = Bot::create(&h.db, TestHarness::rand_string(), &w.owner.user, None)
            .await
            .expect("`Bot`");
        let auth = || Header::new("x-bot-token", bot.token.clone());
        let bot_user = h.db.fetch_user(&bot.id).await.expect("the bot's user");
        h.join_server(&w.server, &bot_user).await;
        fund(h, &bot.id, FUNDS).await;

        let goal_path = format!("/prot/goals/{}", w.launched.id);
        let contribute = json!({ "amount": 100, "nonce": Ulid::new().to_string() });
        for (method, path, body) in [
            (Method::Get, w.tank_path("tank"), None),
            (Method::Get, w.server_path("goals"), None),
            (Method::Get, goal_path.clone(), None),
            (
                Method::Post,
                w.tank_path("contribute"),
                Some(contribute.clone()),
            ),
            (
                Method::Post,
                format!("{goal_path}/pledges"),
                Some(contribute),
            ),
            (
                Method::Put,
                w.server_path("contributor"),
                Some(json!({ "hidden": true })),
            ),
        ] {
            let response = send(h, auth(), method, &path, body).await;
            refused(response, Status::BadRequest, "IsBot").await;
        }

        assert_eq!(wallet(h, &bot.id).await, FUNDS);
        assert_eq!(balance(h, &prot_tank_account(&w.tank.id)).await, TARGET);
        assert!(h
            .db
            .fetch_prot_contributor_prefs(&w.server.id, std::slice::from_ref(&bot.id))
            .await
            .expect("prefs")
            .is_empty());
    }
}
