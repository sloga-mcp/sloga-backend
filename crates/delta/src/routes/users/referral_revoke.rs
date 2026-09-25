use revolt_database::{
    util::reference::Reference, Database, FieldsUser, PartialUser, ReferralStatus, User,
};
use revolt_models::v0::UserFlags;
use revolt_result::{create_error, ErrorType, Result};
use rocket_empty::EmptyResponse;

use rocket::State;

/// # Revoke Referral
///
/// Withdraw the referral that brought a user in; the target is the
/// invitee. Requires a privileged account. The invitee loses the welcome
/// badge and trial, and the referrer's qualified count is recomputed.
#[openapi(tag = "User Information")]
#[post("/<target>/referral/revoke")]
pub async fn revoke_referral(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let referral = db
        .fetch_referral(target.id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    if referral.status == ReferralStatus::Revoked {
        return Err(create_error!(InvalidOperation));
    }

    log::info!(
        "AUDIT referral_revoke: actor={} invitee={} referrer={} previous_status={:?}",
        user.id,
        referral.id,
        referral.referrer,
        referral.status
    );

    // The invitee is cleaned up before the status write: until the referral
    // reads Revoked, a failed request can simply be retried. The account may
    // be gone, in which case only the referral itself is revoked.
    clear_invitee(db, &referral.id).await?;

    db.update_referral_status(&referral.id, ReferralStatus::Revoked, None)
        .await?;

    // The qualification sweep only writes while the referral is Pending, but
    // it may have qualified and welcomed the invitee between the cleanup and
    // the status write. Now that the row reads Revoked the sweep can no
    // longer qualify them, so clear once more. Best-effort like the recount
    // below: a leftover welcome is not repaired by the orphan pass.
    match clear_invitee(db, &referral.id).await {
        Ok(true) => log::warn!("referral_revoke: invitee was welcomed during revocation, cleared"),
        Ok(false) => {}
        Err(error) => log::warn!("referral_revoke: second invitee cleanup failed: {error:?}"),
    }

    // Best-effort: the revocation has committed. The count is recomputed
    // from scratch, never decremented, so the referrer's next recount (a
    // qualification or another revocation) corrects a stale value.
    if let Err(error) = recount_referrer(db, &referral.referrer).await {
        log::warn!(
            "referral_revoke: recount failed for {}: {error:?}",
            referral.referrer
        );
    }

    Ok(EmptyResponse)
}

/// Fetch a user, treating a missing account as None
async fn fetch_user_if_exists(db: &Database, id: &str) -> Result<Option<User>> {
    match db.fetch_user(id).await {
        Ok(user) => Ok(Some(user)),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Remove the invitee's welcome and pending referral flag, returning whether
/// anything was set; a missing account is left alone and nothing is written
/// when both are already clear
async fn clear_invitee(db: &Database, invitee_id: &str) -> Result<bool> {
    let Some(mut invitee) = fetch_user_if_exists(db, invitee_id).await? else {
        return Ok(false);
    };

    let mut remove = Vec::new();
    if invitee.welcomed_at.is_some() {
        remove.push(FieldsUser::WelcomedAt);
    }
    if invitee.referral_pending.is_some() {
        remove.push(FieldsUser::ReferralPending);
    }
    if remove.is_empty() {
        return Ok(false);
    }

    invitee.update(db, PartialUser::default(), remove).await?;
    Ok(true)
}

/// Recompute a referrer's qualified count; missing and deleted accounts
/// are left alone
async fn recount_referrer(db: &Database, referrer_id: &str) -> Result<()> {
    let Some(mut referrer) = fetch_user_if_exists(db, referrer_id).await? else {
        return Ok(());
    };
    if referrer.flags.unwrap_or_default() & UserFlags::Deleted as i32 != 0 {
        return Ok(());
    }

    let n = db
        .count_referrals_by_referrer(&referrer.id, ReferralStatus::Qualified)
        .await?;
    if Some(n as i32) != referrer.referral_count {
        referrer
            .update(
                db,
                PartialUser {
                    referral_count: Some(n as i32),
                    ..Default::default()
                },
                vec![],
            )
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{now_ms, PartialUser, Referral, ReferralSource, ReferralStatus, User};
    use rocket::http::{Header, Status};

    async fn revoke(harness: &TestHarness, token: &str, invitee: &str) -> Status {
        harness
            .client
            .post(format!("/users/{invitee}/referral/revoke"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await
            .status()
    }

    async fn promote(harness: &TestHarness, user: &mut User) {
        user.update(
            &harness.db,
            PartialUser {
                privileged: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("promote staff");
    }

    async fn status_of(harness: &TestHarness, invitee: &str) -> ReferralStatus {
        harness
            .db
            .fetch_referral(invitee)
            .await
            .expect("fetch referral")
            .expect("referral exists")
            .status
    }

    #[test]
    fn revoke_qualified_referral() {
        crate::util::test::rt().block_on(revoke_qualified_referral_case())
    }

    async fn revoke_qualified_referral_case() {
        let harness = TestHarness::new().await;
        let (_, staff_session, mut staff) = harness.new_user().await;
        let (_, _, mut referrer) = harness.new_user().await;
        let (_, invitee_session, mut invitee) = harness.new_user().await;
        promote(&harness, &mut staff).await;

        assert!(Referral::create_for_invitee(
            &harness.db,
            &invitee.id,
            &referrer.id,
            ReferralSource::Code
        )
        .await
        .expect("create referral"));
        harness
            .db
            .update_referral_status(&invitee.id, ReferralStatus::Qualified, Some(now_ms()))
            .await
            .expect("qualify");
        invitee
            .update(
                &harness.db,
                PartialUser {
                    welcomed_at: Some(now_ms()),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("welcome invitee");
        referrer
            .update(
                &harness.db,
                PartialUser {
                    referral_count: Some(1),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("count referrer");

        // Not privileged: nothing changes
        assert_eq!(
            revoke(&harness, &invitee_session.token, &invitee.id).await,
            Status::Forbidden
        );
        assert_eq!(
            status_of(&harness, &invitee.id).await,
            ReferralStatus::Qualified
        );

        assert_eq!(
            revoke(&harness, &staff_session.token, &invitee.id).await,
            Status::NoContent
        );
        assert_eq!(
            status_of(&harness, &invitee.id).await,
            ReferralStatus::Revoked
        );

        let invitee = harness.db.fetch_user(&invitee.id).await.expect("invitee");
        assert_eq!(invitee.welcomed_at, None);
        assert_eq!(invitee.referral_pending, None);
        let referrer = harness.db.fetch_user(&referrer.id).await.expect("referrer");
        assert_eq!(referrer.referral_count, Some(0));

        // A second revocation is refused
        assert_eq!(
            revoke(&harness, &staff_session.token, &invitee.id).await,
            Status::BadRequest
        );

        // A user who was never referred
        assert_eq!(
            revoke(&harness, &staff_session.token, &staff.id).await,
            Status::NotFound
        );
    }

    #[test]
    fn revoke_referral_of_missing_invitee() {
        crate::util::test::rt().block_on(revoke_referral_of_missing_invitee_case())
    }

    async fn revoke_referral_of_missing_invitee_case() {
        let harness = TestHarness::new().await;
        let (_, staff_session, mut staff) = harness.new_user().await;
        let (_, _, referrer) = harness.new_user().await;
        promote(&harness, &mut staff).await;

        let gone = ulid::Ulid::new().to_string();
        assert!(Referral::create_for_invitee(
            &harness.db,
            &gone,
            &referrer.id,
            ReferralSource::Code
        )
        .await
        .expect("create referral"));

        assert_eq!(
            revoke(&harness, &staff_session.token, &gone).await,
            Status::NoContent
        );
        assert_eq!(status_of(&harness, &gone).await, ReferralStatus::Revoked);

        let referrer = harness.db.fetch_user(&referrer.id).await.expect("referrer");
        assert_eq!(referrer.referral_count, Some(0));
    }

    #[test]
    fn clear_invitee_removes_a_repeated_welcome() {
        crate::util::test::rt().block_on(clear_invitee_removes_a_repeated_welcome_case())
    }

    async fn clear_invitee_removes_a_repeated_welcome_case() {
        let harness = TestHarness::new().await;
        let (_, _, mut invitee) = harness.new_user().await;
        let (_, _, bystander) = harness.new_user().await;

        // The sweep welcomed the invitee after the first cleanup
        invitee
            .update(
                &harness.db,
                PartialUser {
                    welcomed_at: Some(now_ms()),
                    referral_pending: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("welcome invitee");

        assert!(super::clear_invitee(&harness.db, &invitee.id)
            .await
            .expect("clear invitee"));
        let invitee = harness.db.fetch_user(&invitee.id).await.expect("invitee");
        assert_eq!(invitee.welcomed_at, None);
        assert_eq!(invitee.referral_pending, None);

        // Nothing set: no write
        assert!(!super::clear_invitee(&harness.db, &bystander.id)
            .await
            .expect("clear bystander"));
        let bystander = harness.db.fetch_user(&bystander.id).await.expect("user");
        assert_eq!(bystander.welcomed_at, None);
        assert_eq!(bystander.referral_pending, None);

        // A missing account
        let gone = ulid::Ulid::new().to_string();
        assert!(!super::clear_invitee(&harness.db, &gone)
            .await
            .expect("clear missing"));
    }
}
