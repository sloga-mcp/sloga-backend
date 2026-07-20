use revolt_result::Result;

use crate::ReferenceDb;
use crate::{FieldsRole, FieldsServer, PartialRole, PartialServer, Role, Server};

use super::AbstractServers;

#[async_trait]
impl AbstractServers for ReferenceDb {
    /// Insert a new server into database
    async fn insert_server(&self, server: &Server) -> Result<()> {
        let mut servers = self.servers.lock().await;
        if servers.contains_key(&server.id) {
            Err(create_database_error!("insert", "server"))
        } else {
            servers.insert(server.id.to_string(), server.clone());
            Ok(())
        }
    }

    /// Fetch a server by its id
    async fn fetch_server(&self, id: &str) -> Result<Server> {
        let servers = self.servers.lock().await;
        servers
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch a servers by their ids
    async fn fetch_servers<'a>(&self, ids: &'a [String]) -> Result<Vec<Server>> {
        let servers = self.servers.lock().await;
        ids.iter()
            .map(|id| {
                servers
                    .get(id)
                    .cloned()
                    .ok_or_else(|| create_error!(NotFound))
            })
            .collect()
    }

    async fn fetch_owned_servers(&self, user_id: &str) -> Result<Vec<Server>> {
        let servers = self.servers.lock().await;

        Ok(servers
            .values()
            .filter(|server| server.owner == user_id)
            .cloned()
            .collect())
    }

    /// Update a server with new information
    async fn update_server(
        &self,
        id: &str,
        partial: &PartialServer,
        remove: Vec<FieldsServer>,
    ) -> Result<()> {
        let mut servers = self.servers.lock().await;
        if let Some(server) = servers.get_mut(id) {
            for field in remove {
                #[allow(clippy::disallowed_methods)]
                server.remove_field(&field);
            }

            server.apply_options(partial.clone());
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Delete a server by its id
    ///
    /// Unlike the MongoDb driver, this deliberately cascades NOTHING (no
    /// channels, members, bans — and likewise no server-scoped
    /// application_commands): the reference mock only models the row itself.
    async fn delete_server(&self, id: &str) -> Result<()> {
        let mut servers = self.servers.lock().await;
        if servers.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Fetch a page of publicly discoverable servers plus the total match count
    async fn fetch_discoverable_servers(
        &self,
        query: Option<&str>,
        skip: u64,
        limit: i64,
    ) -> Result<(Vec<Server>, u64)> {
        let servers = self.servers.lock().await;
        let needle = query
            .filter(|q| !q.is_empty())
            .map(|q| q.to_lowercase());

        let mut matches: Vec<Server> = servers
            .values()
            .filter(|server| server.discoverable && !server.nsfw)
            .filter(|server| {
                needle.as_ref().map_or(true, |needle| {
                    server.name.to_lowercase().contains(needle)
                        || server
                            .description
                            .as_ref()
                            .is_some_and(|d| d.to_lowercase().contains(needle))
                })
            })
            .cloned()
            .collect();

        // Newest first (ulid ids sort chronologically)
        matches.sort_by(|a, b| b.id.cmp(&a.id));
        let total = matches.len() as u64;

        Ok((
            matches
                .into_iter()
                .skip(skip as usize)
                .take(limit.max(0) as usize)
                .collect(),
            total,
        ))
    }

    /// Fetch a page of servers with a pending discovery listing request
    async fn fetch_discovery_requests(&self, skip: u64, limit: i64) -> Result<Vec<Server>> {
        let servers = self.servers.lock().await;
        let mut matches: Vec<Server> = servers
            .values()
            .filter(|server| server.discovery_requested && !server.discoverable)
            .cloned()
            .collect();

        matches.sort_by(|a, b| b.id.cmp(&a.id));

        Ok(matches
            .into_iter()
            .skip(skip as usize)
            .take(limit.max(0) as usize)
            .collect())
    }

    async fn fetch_server_ids_with_boost_counts(&self) -> Result<Vec<String>> {
        let servers = self.servers.lock().await;
        let mut ids: Vec<String> = servers
            .values()
            .filter(|server| server.boost_count.unwrap_or(0) > 0)
            .map(|server| server.id.clone())
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// Insert a new role into server object
    async fn insert_role(&self, server_id: &str, role: &Role) -> Result<()> {
        let mut servers = self.servers.lock().await;
        if let Some(server) = servers.get_mut(server_id) {
            server.roles.insert(role.id.clone(), role.clone());
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Update an existing role on a server
    async fn update_role(
        &self,
        server_id: &str,
        role_id: &str,
        partial: &PartialRole,
        remove: Vec<FieldsRole>,
    ) -> Result<()> {
        let mut servers = self.servers.lock().await;
        if let Some(server) = servers.get_mut(server_id) {
            if let Some(role) = server.roles.get_mut(role_id) {
                for field in remove {
                    #[allow(clippy::disallowed_methods)]
                    role.remove_field(&field);
                }

                role.apply_options(partial.clone());
                Ok(())
            } else {
                Err(create_error!(NotFound))
            }
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Delete a role from a server
    ///
    /// Also updates channels and members.
    async fn delete_role(&self, server_id: &str, role_id: &str) -> Result<()> {
        let mut servers = self.servers.lock().await;
        if let Some(server) = servers.get_mut(server_id) {
            if server.roles.remove(role_id).is_some() {
                Ok(())
            } else {
                Err(create_error!(NotFound))
            }
        } else {
            Err(create_error!(NotFound))
        }
    }
}
