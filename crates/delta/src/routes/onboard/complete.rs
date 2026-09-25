use once_cell::sync::Lazy;
use regex::Regex;
use revolt_config::config;
use revolt_database::{
    Database, Invite, Member, PartialUser, Referral, ReferralSource, Session, User,
};
use revolt_models::v0::{self, UserFlags};
use revolt_result::{create_error, ErrorType, Result};

use rocket::{serde::json::Json, State};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// Regex for valid usernames
///
/// Block zero width space
/// Block lookalike characters
pub static RE_USERNAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\p{L}|[\d_.-])+$").unwrap());

/// # New User Data
#[derive(Validate, Serialize, Deserialize, JsonSchema)]
pub struct DataOnboard {
    /// New username which will be used to identify the user on the platform
    #[validate(length(min = 2, max = 32), regex = "RE_USERNAME")]
    username: String,
    /// Referral code of the user who invited this one
    #[validate(length(min = 1, max = 32))]
    referral_code: Option<String>,
    /// Server invite code this user signed up through
    #[validate(length(min = 1, max = 128))]
    invite_code: Option<String>,
}

/// Whether a user can be credited with a referral
fn can_refer(user: &User) -> bool {
    user.bot.is_none() && user.flags.unwrap_or_default() & UserFlags::Deleted as i32 == 0
}

/// Creator of a server invite, if they can be credited with a referral
///
/// Any failure gives no referrer; an invite code never blocks signup.
async fn referrer_from_invite(db: &Database, input: &str) -> Option<(String, ReferralSource)> {
    let Ok(Invite::Server { creator, code, .. }) = db.fetch_invite(input).await else {
        return None;
    };

    let creator = db.fetch_user(&creator).await.ok()?;
    if !can_refer(&creator) {
        return None;
    }

    Some((creator.id, ReferralSource::ServerInvite { code }))
}

/// # Complete Onboarding
///
/// This sets a new username, completes onboarding and allows a user to start using Revolt.
#[openapi(tag = "Onboarding")]
#[post("/complete", data = "<data>")]
pub async fn complete(
    db: &State<Database>,
    session: Session,
    user: Option<User>,
    data: Json<DataOnboard>,
) -> Result<Json<v0::User>> {
    if user.is_some() {
        return Err(create_error!(AlreadyOnboarded));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let DataOnboard {
        username,
        referral_code,
        invite_code,
    } = data;

    // Resolve the referrer before the user exists, so an unknown referral
    // code is rejected without creating anything
    let referral = if let Some(input) = referral_code {
        let referrer_id = Referral::resolve_code(db, &input)
            .await?
            .ok_or_else(|| create_error!(InvalidReferralCode))?;

        let referrer = match db.fetch_user(&referrer_id).await {
            Ok(referrer) => referrer,
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
                return Err(create_error!(InvalidReferralCode))
            }
            Err(error) => return Err(error),
        };

        if !can_refer(&referrer) {
            return Err(create_error!(InvalidReferralCode));
        }

        Some((referrer.id, ReferralSource::Code))
    } else if let Some(input) = invite_code {
        referrer_from_invite(db, &input).await
    } else {
        None
    };

    let user = User::create(
        db,
        username,
        session.user_id,
        referral.as_ref().map(|_| PartialUser {
            referral_pending: Some(true),
            ..Default::default()
        }),
    )
    .await?;

    // Best-effort: a pending flag left without a referral is cleared by
    // the qualification sweep
    if let Some((referrer, source)) = referral {
        if let Err(err) = Referral::create_for_invitee(db, &user.id, &referrer, source).await {
            log::warn!(
                "Failed to record referral of {} by {referrer}: {err:?}",
                user.id
            );
        }
    }

    // Auto-join the configured welcome / landing-spot server, if one is set.
    // Best-effort: onboarding must never fail because of this. We ignore a
    // missing/misconfigured server id, an existing membership, a ban, etc.
    if let Some(welcome_id) = config()
        .await
        .features
        .welcome_server
        .as_deref()
        .filter(|id| !id.is_empty())
    {
        match db.fetch_server(welcome_id).await {
            Ok(server) => {
                if let Err(err) = Member::create(db, &server, &user, None).await {
                    log::warn!(
                        "Failed to auto-join user {} to welcome server {welcome_id}: {err:?}",
                        user.id
                    );
                }
            }
            Err(err) => {
                log::warn!("welcome_server {welcome_id} is set but could not be fetched: {err:?}")
            }
        }
    }

    Ok(Json(user.into_self(false).await))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        Bot, Invite, PartialUser, Referral, ReferralSource, ReferralStatus, User,
    };
    use revolt_models::v0::UserFlags;
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalResponse;
    use serde_json::json;

    /// Account and session with no user yet, as right after signup
    async fn signed_up(harness: &TestHarness) -> (String, String) {
        let id = ulid::Ulid::new().to_string();
        let (_, session) = harness.account_from_user(id.clone()).await;
        (id, session.token)
    }

    async fn onboard<'a>(
        harness: &'a TestHarness,
        token: &str,
        body: serde_json::Value,
    ) -> LocalResponse<'a> {
        harness
            .client
            .post("/onboard/complete")
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await
    }

    #[test]
    fn referral_code_records_pending_referral() {
        crate::util::test::rt().block_on(referral_code_records_pending_referral_case())
    }

    async fn referral_code_records_pending_referral_case() {
        let harness = TestHarness::new().await;
        let (_, _, referrer) = harness.new_user().await;
        let code = Referral::code_for_user(&harness.db, &referrer.id)
            .await
            .expect("code");

        let (id, token) = signed_up(&harness).await;
        let response = onboard(
            &harness,
            &token,
            json!({
                "username": TestHarness::rand_string(),
                "referral_code": format!("sloga-{}", code.to_lowercase())
            }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let user = harness.db.fetch_user(&id).await.expect("user");
        assert_eq!(user.referral_pending, Some(true));

        let referral = harness
            .db
            .fetch_referral(&id)
            .await
            .expect("fetch")
            .expect("referral");
        assert_eq!(referral.referrer, referrer.id);
        assert_eq!(referral.status, ReferralStatus::Pending);
        assert!(matches!(referral.source, ReferralSource::Code));
    }

    #[test]
    fn unknown_referral_code_is_rejected_before_signup() {
        crate::util::test::rt().block_on(unknown_referral_code_is_rejected_before_signup_case())
    }

    async fn unknown_referral_code_is_rejected_before_signup_case() {
        let harness = TestHarness::new().await;
        let (id, token) = signed_up(&harness).await;

        for code in ["ZZZZ", "not a code"] {
            let response = onboard(
                &harness,
                &token,
                json!({ "username": TestHarness::rand_string(), "referral_code": code }),
            )
            .await;
            assert_eq!(response.status(), Status::BadRequest);
            let error: Error = response.into_json().await.expect("error");
            assert!(matches!(error.error_type, ErrorType::InvalidReferralCode));
        }

        assert!(harness.db.fetch_user(&id).await.is_err());
    }

    #[test]
    fn deleted_or_bot_referrer_is_rejected() {
        crate::util::test::rt().block_on(deleted_or_bot_referrer_is_rejected_case())
    }

    async fn deleted_or_bot_referrer_is_rejected_case() {
        let harness = TestHarness::new().await;
        let deleted = User::create(
            &harness.db,
            TestHarness::rand_string(),
            None,
            PartialUser {
                flags: Some(UserFlags::Deleted as i32),
                ..Default::default()
            },
        )
        .await
        .expect("user");
        let (_, _, owner) = harness.new_user().await;
        let (_, bot) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("bot");

        let (id, token) = signed_up(&harness).await;
        for referrer in [&deleted, &bot] {
            let code = Referral::code_for_user(&harness.db, &referrer.id)
                .await
                .expect("code");
            let response = onboard(
                &harness,
                &token,
                json!({ "username": TestHarness::rand_string(), "referral_code": code }),
            )
            .await;
            assert_eq!(response.status(), Status::BadRequest);
            let error: Error = response.into_json().await.expect("error");
            assert!(matches!(error.error_type, ErrorType::InvalidReferralCode));
        }

        assert!(harness.db.fetch_user(&id).await.is_err());
    }

    #[test]
    fn server_invite_credits_its_creator() {
        crate::util::test::rt().block_on(server_invite_credits_its_creator_case())
    }

    async fn server_invite_credits_its_creator_case() {
        let harness = TestHarness::new().await;
        let (_, _, creator) = harness.new_user().await;
        harness
            .db
            .insert_invite(&Invite::Server {
                code: "referralinvite".to_string(),
                server: "server".to_string(),
                creator: creator.id.clone(),
                channel: "channel".to_string(),
            })
            .await
            .expect("invite");

        let (id, token) = signed_up(&harness).await;
        let response = onboard(
            &harness,
            &token,
            json!({ "username": TestHarness::rand_string(), "invite_code": "referralinvite" }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let referral = harness
            .db
            .fetch_referral(&id)
            .await
            .expect("fetch")
            .expect("referral");
        assert_eq!(referral.referrer, creator.id);
        assert!(matches!(
            referral.source,
            ReferralSource::ServerInvite { ref code } if code == "referralinvite"
        ));
    }

    #[test]
    fn unusable_invite_is_ignored() {
        crate::util::test::rt().block_on(unusable_invite_is_ignored_case())
    }

    async fn unusable_invite_is_ignored_case() {
        let harness = TestHarness::new().await;
        let (id, token) = signed_up(&harness).await;
        let response = onboard(
            &harness,
            &token,
            json!({ "username": TestHarness::rand_string(), "invite_code": "missing" }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let user = harness.db.fetch_user(&id).await.expect("user");
        assert_eq!(user.referral_pending, None);
        assert!(harness
            .db
            .fetch_referral(&id)
            .await
            .expect("fetch")
            .is_none());
    }
}
