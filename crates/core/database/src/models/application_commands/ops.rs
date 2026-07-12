use revolt_result::Result;

use crate::{ApplicationCommand, PartialApplicationCommand};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractApplicationCommands: Sync + Send {
    /// Insert a new command.
    ///
    /// Callers pre-check name uniqueness via [`fetch_command_by_name`]; on
    /// MongoDB the unique `(bot_id, server, name)` index is the backstop
    /// against a create/create race.
    async fn insert_command(&self, command: &ApplicationCommand) -> Result<()>;

    /// Fetch a command by its id.
    async fn fetch_command(&self, id: &str) -> Result<ApplicationCommand>;

    /// Fetch a command by its unique (bot, scope, name) triple.
    async fn fetch_command_by_name(
        &self,
        bot_id: &str,
        server: Option<&str>,
        name: &str,
    ) -> Result<Option<ApplicationCommand>>;

    /// Fetch all commands registered by a bot.
    async fn fetch_commands_by_bot(&self, bot_id: &str) -> Result<Vec<ApplicationCommand>>;

    /// Count a bot's commands within one scope (None = global scope).
    async fn count_commands(&self, bot_id: &str, server: Option<&str>) -> Result<usize>;

    /// Fetch all commands visible in a server: server-scoped ones plus every
    /// bot's global commands. Callers filter by bot membership afterwards.
    async fn fetch_commands_for_server(&self, server_id: &str) -> Result<Vec<ApplicationCommand>>;

    /// Fetch the global commands of the given bots (Group channel picker).
    async fn fetch_global_commands_by_bots(
        &self,
        bot_ids: &[String],
    ) -> Result<Vec<ApplicationCommand>>;

    /// Update a command.
    async fn update_command(&self, id: &str, partial: &PartialApplicationCommand) -> Result<()>;

    /// Delete a command by its id.
    async fn delete_command(&self, id: &str) -> Result<()>;

    /// Delete all commands registered by a bot (bot-deletion cascade).
    async fn delete_commands_by_bot(&self, bot_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractApplicationCommands;
    use crate::ApplicationCommand;

    #[tokio::test]
    async fn crud_and_scoping() {
        database_test!(|db| async move {
            let global = ApplicationCommand {
                id: "01CMDGLOBAL0000000000000000".to_string(),
                bot_id: "01BOT0000000000000000000000".to_string(),
                server: None,
                name: "ping".to_string(),
                description: "Ping the bot".to_string(),
                options: vec![],
            };
            let scoped = ApplicationCommand {
                id: "01CMDSCOPED0000000000000000".to_string(),
                bot_id: "01BOT0000000000000000000000".to_string(),
                server: Some("01SERVER0000000000000000000".to_string()),
                name: "ping".to_string(),
                description: "Server-scoped ping".to_string(),
                options: vec![],
            };

            db.insert_command(&global).await.unwrap();
            db.insert_command(&scoped).await.unwrap();

            // Same name in different scopes coexists
            assert_eq!(
                db.fetch_command_by_name(&global.bot_id, None, "ping")
                    .await
                    .unwrap()
                    .expect("global ping")
                    .id,
                global.id
            );
            assert_eq!(
                db.fetch_command_by_name(
                    &global.bot_id,
                    Some("01SERVER0000000000000000000"),
                    "ping"
                )
                .await
                .unwrap()
                .expect("scoped ping")
                .id,
                scoped.id
            );

            // Scope counts are independent
            assert_eq!(db.count_commands(&global.bot_id, None).await.unwrap(), 1);
            assert_eq!(
                db.count_commands(&global.bot_id, Some("01SERVER0000000000000000000"))
                    .await
                    .unwrap(),
                1
            );

            // Server view returns scoped + global
            let for_server = db
                .fetch_commands_for_server("01SERVER0000000000000000000")
                .await
                .unwrap();
            assert_eq!(for_server.len(), 2);

            // A different server only sees the global command
            let other = db.fetch_commands_for_server("01OTHER00000000000000000000").await.unwrap();
            assert_eq!(other.len(), 1);
            assert_eq!(other[0].id, global.id);

            // Group picker path
            let globals = db
                .fetch_global_commands_by_bots(&[global.bot_id.clone()])
                .await
                .unwrap();
            assert_eq!(globals.len(), 1);
            assert_eq!(globals[0].id, global.id);

            // Bot-deletion cascade removes everything
            db.delete_commands_by_bot(&global.bot_id).await.unwrap();
            assert!(db
                .fetch_commands_by_bot(&global.bot_id)
                .await
                .unwrap()
                .is_empty());
        });
    }
}
