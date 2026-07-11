use revolt_database::{Database, E2EEIdentity, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::MAX_COMMITS_PER_FETCH;

/// # Fetch MLS Commits
///
/// Gap refetch for desynced members (plan §2.3): the stored winning commits
/// from `from_epoch` upward, ascending. The commits are opaque ciphertext,
/// but their metadata (`committer` / `added` / `removed` `(user, device)`
/// lists) is the per-device join/leave history of the call — which the plan
/// keeps OFF channel co-members (§3.5). So access requires actual GROUP
/// MEMBERSHIP, not merely channel view: only a participant already in the
/// roster (a desynced member re-securing) may read it (media-e2ee gate
/// finding, slice 6.1).
#[openapi(tag = "MLS")]
#[get("/groups/<group_id>/commits?<from_epoch>")]
pub async fn fetch_commits(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    from_epoch: i64,
) -> Result<Json<v0::ResponseFetchMlsCommits>> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    if from_epoch < 0 {
        return Err(create_error!(FailedValidation {
            error: "from_epoch must be non-negative".to_string()
        }));
    }

    // Any of the caller's registered devices qualifies (the desynced device
    // is re-fetching; it is device-bound like every E2EE surface)
    E2EEIdentity::require_device_bound_session(db, &user.id, &session.id).await?;

    let (group, _channel) = super::fetch_authorized_group(db, &user, &group_id).await?;

    // Channel access is necessary but NOT sufficient: the caller must be a
    // current member of the group, else the per-device roster history would
    // leak to any channel viewer (device ids stay off co-members, §3.5).
    // NotFound (not Forbidden) so a non-member cannot even probe existence.
    if group.member_device_of(&user.id).is_none() {
        return Err(create_error!(NotFound));
    }

    let commits = db
        .fetch_mls_commits_from(&group.id, from_epoch, MAX_COMMITS_PER_FETCH)
        .await?;

    Ok(Json(v0::ResponseFetchMlsCommits {
        commits: commits
            .into_iter()
            .map(|commit| v0::MlsCommitInfo {
                group_id: commit.group_id,
                epoch: commit.epoch,
                committer: v0::MlsMemberDevice {
                    user_id: commit.committer.user_id,
                    device_id: commit.committer.device_id,
                },
                commit: commit.commit,
                added: commit
                    .added
                    .into_iter()
                    .map(|member| v0::MlsMemberDevice {
                        user_id: member.user_id,
                        device_id: member.device_id,
                    })
                    .collect(),
                removed: commit
                    .removed
                    .into_iter()
                    .map(|member| v0::MlsMemberDevice {
                        user_id: member.user_id,
                        device_id: member.device_id,
                    })
                    .collect(),
            })
            .collect(),
        current_epoch: group.current_epoch,
    }))
}
