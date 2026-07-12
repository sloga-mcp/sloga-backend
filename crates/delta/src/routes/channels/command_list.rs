use std::collections::HashSet;

use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    ApplicationCommand, Channel, Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::Result;
use rocket::{serde::json::Json, State};

/// # Fetch Channel Commands
///
/// Fetch the slash commands invocable in this channel: commands of bots that
/// are members of the channel's server (or recipients of the group), merged
/// from the server scope and the global scope.
///
/// Returns an empty list for DMs and saved-message channels — interactions
/// are structurally excluded there (E2EE fail-closed rule).
#[openapi(tag = "Interactions")]
#[get("/<target>/commands")]
pub async fn fetch_channel_commands(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<Vec<v0::ApplicationCommand>>> {
    let channel = target.as_channel(db).await?;

    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let commands: Vec<ApplicationCommand> = match &channel {
        // Fail closed: no interactions in (potentially E2EE) DMs or notes.
        Channel::SavedMessages { .. } | Channel::DirectMessage { .. } => vec![],
        // Forum containers have no composer; posts (threads) do.
        Channel::Forum { .. } => vec![],
        Channel::Group { recipients, .. } => {
            // Bots must be recipients of the group. Identify which
            // recipients are bots, then pull their global commands.
            let users = db.fetch_users(recipients).await?;
            let bot_ids: Vec<String> = users
                .into_iter()
                .filter(|u| u.bot.is_some())
                .map(|u| u.id)
                .collect();

            if bot_ids.is_empty() {
                vec![]
            } else {
                db.fetch_global_commands_by_bots(&bot_ids).await?
            }
        }
        Channel::TextChannel { server, .. } | Channel::Thread { server, .. } => {
            let candidates = db.fetch_commands_for_server(server).await?;

            // Batched membership check: one members query over the distinct
            // bot ids, then retain only commands of bots actually present.
            let bot_ids: Vec<String> = candidates
                .iter()
                .map(|command| command.bot_id.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if bot_ids.is_empty() {
                vec![]
            } else {
                let members: HashSet<String> = db
                    .fetch_members(server, &bot_ids)
                    .await?
                    .into_iter()
                    .map(|member| member.id.user)
                    .collect();

                candidates
                    .into_iter()
                    .filter(|command| members.contains(&command.bot_id))
                    .collect()
            }
        }
    };

    Ok(Json(commands.into_iter().map(Into::into).collect()))
}
