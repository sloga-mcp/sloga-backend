use bson::Document;
use revolt_result::Result;

use crate::MongoDb;
use crate::{ApplicationCommand, PartialApplicationCommand};

use super::AbstractApplicationCommands;

static COL: &str = "application_commands";

#[async_trait]
impl AbstractApplicationCommands for MongoDb {
    /// Insert a new command.
    async fn insert_command(&self, command: &ApplicationCommand) -> Result<()> {
        query!(self, insert_one, COL, &command).map(|_| ())
    }

    /// Fetch a command by its id.
    async fn fetch_command(&self, id: &str) -> Result<ApplicationCommand> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch a command by its unique (bot, scope, name) triple.
    async fn fetch_command_by_name(
        &self,
        bot_id: &str,
        server: Option<&str>,
        name: &str,
    ) -> Result<Option<ApplicationCommand>> {
        // Global commands have no `server` key; `null` matches missing too.
        query!(
            self,
            find_one,
            COL,
            doc! {
                "bot_id": bot_id,
                "server": server,
                "name": name
            }
        )
    }

    /// Fetch all commands registered by a bot.
    async fn fetch_commands_by_bot(&self, bot_id: &str) -> Result<Vec<ApplicationCommand>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "bot_id": bot_id
            }
        )
    }

    /// Count a bot's commands within one scope (None = global scope).
    async fn count_commands(&self, bot_id: &str, server: Option<&str>) -> Result<usize> {
        self.col::<Document>(COL)
            .count_documents(doc! {
                "bot_id": bot_id,
                "server": server
            })
            .await
            .map(|count| count as usize)
            .map_err(|_| create_database_error!("count_documents", COL))
    }

    /// Fetch all commands visible in a server: server-scoped ones plus every
    /// bot's global commands.
    async fn fetch_commands_for_server(&self, server_id: &str) -> Result<Vec<ApplicationCommand>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "$or": [
                    { "server": server_id },
                    { "server": null }
                ]
            }
        )
    }

    /// Fetch the global commands of the given bots (Group channel picker).
    async fn fetch_global_commands_by_bots(
        &self,
        bot_ids: &[String],
    ) -> Result<Vec<ApplicationCommand>> {
        if bot_ids.is_empty() {
            return Ok(vec![]);
        }

        query!(
            self,
            find,
            COL,
            doc! {
                "bot_id": { "$in": bot_ids },
                "server": null
            }
        )
    }

    /// Update a command.
    async fn update_command(&self, id: &str, partial: &PartialApplicationCommand) -> Result<()> {
        query!(
            self,
            update_one_by_id,
            COL,
            id,
            partial,
            Vec::<&dyn crate::IntoDocumentPath>::new(),
            None
        )
        .map(|_| ())
    }

    /// Delete a command by its id.
    async fn delete_command(&self, id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, id).map(|_| ())
    }

    /// Delete all commands registered by a bot (bot-deletion cascade).
    async fn delete_commands_by_bot(&self, bot_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .delete_many(doc! {
                "bot_id": bot_id
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
