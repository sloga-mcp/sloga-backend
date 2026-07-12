use revolt_result::Result;

use crate::ReferenceDb;
use crate::{ApplicationCommand, PartialApplicationCommand};

use super::AbstractApplicationCommands;

#[async_trait]
impl AbstractApplicationCommands for ReferenceDb {
    /// Insert a new command.
    async fn insert_command(&self, command: &ApplicationCommand) -> Result<()> {
        let mut commands = self.application_commands.lock().await;
        if commands
            .values()
            .any(|c| c.bot_id == command.bot_id && c.server == command.server && c.name == command.name)
        {
            return Err(create_database_error!("insert", "application_commands"));
        }

        if commands
            .insert(command.id.to_string(), command.clone())
            .is_some()
        {
            Err(create_database_error!("insert", "application_commands"))
        } else {
            Ok(())
        }
    }

    /// Fetch a command by its id.
    async fn fetch_command(&self, id: &str) -> Result<ApplicationCommand> {
        let commands = self.application_commands.lock().await;
        commands
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch a command by its unique (bot, scope, name) triple.
    async fn fetch_command_by_name(
        &self,
        bot_id: &str,
        server: Option<&str>,
        name: &str,
    ) -> Result<Option<ApplicationCommand>> {
        let commands = self.application_commands.lock().await;
        Ok(commands
            .values()
            .find(|c| c.bot_id == bot_id && c.server.as_deref() == server && c.name == name)
            .cloned())
    }

    /// Fetch all commands registered by a bot.
    async fn fetch_commands_by_bot(&self, bot_id: &str) -> Result<Vec<ApplicationCommand>> {
        let commands = self.application_commands.lock().await;
        Ok(commands
            .values()
            .filter(|c| c.bot_id == bot_id)
            .cloned()
            .collect())
    }

    /// Count a bot's commands within one scope (None = global scope).
    async fn count_commands(&self, bot_id: &str, server: Option<&str>) -> Result<usize> {
        let commands = self.application_commands.lock().await;
        Ok(commands
            .values()
            .filter(|c| c.bot_id == bot_id && c.server.as_deref() == server)
            .count())
    }

    /// Fetch all commands visible in a server: server-scoped ones plus every
    /// bot's global commands.
    async fn fetch_commands_for_server(&self, server_id: &str) -> Result<Vec<ApplicationCommand>> {
        let commands = self.application_commands.lock().await;
        Ok(commands
            .values()
            .filter(|c| c.server.is_none() || c.server.as_deref() == Some(server_id))
            .cloned()
            .collect())
    }

    /// Fetch the global commands of the given bots (Group channel picker).
    async fn fetch_global_commands_by_bots(
        &self,
        bot_ids: &[String],
    ) -> Result<Vec<ApplicationCommand>> {
        let commands = self.application_commands.lock().await;
        Ok(commands
            .values()
            .filter(|c| c.server.is_none() && bot_ids.contains(&c.bot_id))
            .cloned()
            .collect())
    }

    /// Update a command.
    async fn update_command(&self, id: &str, partial: &PartialApplicationCommand) -> Result<()> {
        let mut commands = self.application_commands.lock().await;
        if let Some(command) = commands.get_mut(id) {
            command.apply_options(partial.clone());
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Delete a command by its id.
    async fn delete_command(&self, id: &str) -> Result<()> {
        let mut commands = self.application_commands.lock().await;
        if commands.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Delete all commands registered by a bot (bot-deletion cascade).
    async fn delete_commands_by_bot(&self, bot_id: &str) -> Result<()> {
        let mut commands = self.application_commands.lock().await;
        commands.retain(|_, c| c.bot_id != bot_id);
        Ok(())
    }
}
