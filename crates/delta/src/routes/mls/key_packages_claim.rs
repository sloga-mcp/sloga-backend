use std::time::Duration;

use revolt_database::{
    is_valid_device_id, is_valid_group_id, util::reference::Reference, Database, RatelimitEvent,
    RatelimitEventType, Session, User, MAX_MLS_GROUP_MEMBERS,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use crate::routes::e2ee::require_e2ee_fetch_eligible;

use super::MAX_CLAIMS_PER_TARGET_PER_MINUTE;

/// # Claim MLS KeyPackages
///
/// Atomically consume one KeyPackage per target device (admission, plan
/// §1.4 step 2). At one-time exhaustion the reusable last-resort package is
/// served, flagged `reused`; a device with no packages at all reports
/// `exhausted` and admission fails LOUDLY — never weakly.
///
/// Eligibility per target: own devices always; otherwise the pair must not
/// be blocked AND either share access to the claimed group's channel
/// (call co-presence — the class that admits strangers in a server voice
/// channel) or satisfy the text-E2EE fetch gates (friends / mutual /
/// shared group DM).
///
/// The claimer MUST verify each returned binding signature against its own
/// pinned identity for the target — the server relay is never the trust
/// decision.
#[openapi(tag = "MLS")]
#[post("/key_packages/claim", data = "<data>")]
pub async fn claim_key_packages(
    db: &State<Database>,
    user: User,
    session: Session,
    data: Json<v0::DataClaimMlsKeyPackages>,
) -> Result<Json<v0::ResponseClaimMlsKeyPackages>> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();

    if !is_valid_group_id(&data.group_id) {
        return Err(create_error!(FailedValidation {
            error: "invalid group id".to_string()
        }));
    }

    if data.targets.is_empty() || data.targets.len() > MAX_MLS_GROUP_MEMBERS {
        return Err(create_error!(FailedValidation {
            error: format!("between 1 and {MAX_MLS_GROUP_MEMBERS} targets per request")
        }));
    }

    if data
        .targets
        .iter()
        .any(|target| !is_valid_device_id(&target.device_id))
    {
        return Err(create_error!(FailedValidation {
            error: "invalid target device id".to_string()
        }));
    }

    // The claiming session must be bound to a registered device of the
    // caller (web/stolen tokens cannot claim key material)
    let claimer_identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "claiming device is not registered".to_string()
            })
        })?;
    claimer_identity.assert_bound_session(&session.id)?;

    // The claim is scoped to an OPEN group whose channel the claimer can
    // access — this anchors the co-presence eligibility class
    let group = db.fetch_mls_group(&data.group_id).await?;
    if !group.open {
        return Err(create_error!(NotFound));
    }
    let channel = Reference::from_unchecked(&group.channel_id)
        .as_channel(db)
        .await?;
    super::require_channel_access(db, &user, &channel).await?;

    let mut results = Vec::with_capacity(data.targets.len());

    for target in data.targets {
        // Per-pair rate limit (plan §1.4 racing-admitter accounting): a
        // contested join costs one claim per RACING admitter, so the budget
        // is small but non-unit
        let pair = format!("{}:{}:{}", user.id, target.user_id, target.device_id);
        if db
            .has_ratelimited(
                &pair,
                RatelimitEventType::MlsKeyPackageClaim,
                Duration::from_secs(60),
                MAX_CLAIMS_PER_TARGET_PER_MINUTE,
            )
            .await?
        {
            return Err(create_error!(InSlowmode { retry_after: 60 }));
        }
        RatelimitEvent::create(db, pair, RatelimitEventType::MlsKeyPackageClaim).await?;

        // Eligibility. NotFound deliberately covers unknown device AND
        // ineligible pair — a claim must not become a probe for device
        // inventories the caller couldn't otherwise see.
        let eligible = if target.user_id == user.id {
            true
        } else {
            match db.fetch_user(&target.user_id).await {
                Ok(target_user) => {
                    // Call co-presence: the target can access the group's
                    // channel too. Blocked pairs are refused (claim is
                    // fetch-like, slice-5 asymmetry) — require_e2ee_fetch_
                    // eligible rejects them on the fallback path, and the
                    // co-presence path checks explicitly below.
                    let blocked = matches!(
                        user.relationship_with(&target.user_id),
                        revolt_database::RelationshipStatus::Blocked
                            | revolt_database::RelationshipStatus::BlockedOther
                    );

                    if blocked {
                        false
                    } else {
                        super::require_channel_access(db, &target_user, &channel)
                            .await
                            .is_ok()
                            || require_e2ee_fetch_eligible(db, &user, &target_user)
                                .await
                                .is_ok()
                    }
                }
                Err(_) => false,
            }
        };

        if !eligible {
            results.push(v0::MlsClaimResult {
                user_id: target.user_id,
                device_id: target.device_id,
                status: v0::MlsClaimStatus::NotFound,
            });
            continue;
        }

        // Unknown/revoked devices report NotFound (device changes are loud)
        if db
            .fetch_e2ee_identity(&target.user_id, &target.device_id)
            .await
            .is_err()
        {
            results.push(v0::MlsClaimResult {
                user_id: target.user_id,
                device_id: target.device_id,
                status: v0::MlsClaimStatus::NotFound,
            });
            continue;
        }

        // Atomic consume; last-resort at exhaustion (flagged so the client
        // can prefer re-claiming a one-time package later — plan §2.2.1)
        let status = match db
            .consume_mls_key_package(&target.user_id, &target.device_id)
            .await?
        {
            Some(package) => v0::MlsClaimStatus::Claimed {
                key_package_ref: package.key_package_ref,
                key_package: package.key_package,
                mls_signature_key: package.mls_signature_key,
                binding_signature: package.binding_signature,
                reused: false,
            },
            None => match db
                .fetch_mls_last_resort_key_package(&target.user_id, &target.device_id)
                .await?
            {
                Some(package) => v0::MlsClaimStatus::Claimed {
                    key_package_ref: package.key_package_ref,
                    key_package: package.key_package,
                    mls_signature_key: package.mls_signature_key,
                    binding_signature: package.binding_signature,
                    reused: true,
                },
                None => v0::MlsClaimStatus::Exhausted,
            },
        };

        results.push(v0::MlsClaimResult {
            user_id: target.user_id,
            device_id: target.device_id,
            status,
        });
    }

    Ok(Json(v0::ResponseClaimMlsKeyPackages { results }))
}
