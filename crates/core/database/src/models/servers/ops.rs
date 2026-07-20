use revolt_result::Result;

use crate::{FieldsRole, FieldsServer, PartialRole, PartialServer, Role, Server};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractServers: Sync + Send {
    /// Insert a new server into database
    async fn insert_server(&self, server: &Server) -> Result<()>;

    /// Fetch a server by its id
    async fn fetch_server(&self, id: &str) -> Result<Server>;

    /// Fetch a servers by their ids
    async fn fetch_servers<'a>(&self, ids: &'a [String]) -> Result<Vec<Server>>;

    async fn fetch_owned_servers(&self, user_id: &str) -> Result<Vec<Server>>;

    /// Update a server with new information
    async fn update_server(
        &self,
        id: &str,
        partial: &PartialServer,
        remove: Vec<FieldsServer>,
    ) -> Result<()>;

    /// Delete a server by its id
    async fn delete_server(&self, id: &str) -> Result<()>;

    /// Fetch a page of publicly discoverable servers plus the total match
    /// count (public directory: `discoverable == true`, not nsfw, optional
    /// case-insensitive substring match on name/description), newest first.
    ///
    /// NOTE (Mongo): `discoverable` / `nsfw` use `skip_serializing_if =
    /// if_false`, so false is an ABSENT field — filters must use
    /// `{"$ne": true}` semantics, never `{field: false}`.
    async fn fetch_discoverable_servers(
        &self,
        query: Option<&str>,
        skip: u64,
        limit: i64,
    ) -> Result<(Vec<Server>, u64)>;

    /// Fetch a page of servers with a pending discovery listing request
    /// (`discovery_requested == true && discoverable != true`), newest first.
    async fn fetch_discovery_requests(&self, skip: u64, limit: i64) -> Result<Vec<Server>>;

    /// Ids of servers whose stored `boost_count` is positive (crond
    /// self-heal sweep: covers servers whose LAST slot vanished without a
    /// successful recount — those no longer appear in `server_boosts` at
    /// all, so a distinct over that collection can never find them)
    async fn fetch_server_ids_with_boost_counts(&self) -> Result<Vec<String>>;

    /// Insert a new role into server object
    async fn insert_role(&self, server_id: &str, role: &Role) -> Result<()>;

    /// Update an existing role on a server
    async fn update_role(
        &self,
        server_id: &str,
        role_id: &str,
        partial: &PartialRole,
        remove: Vec<FieldsRole>,
    ) -> Result<()>;

    /// Delete a role from a server
    ///
    /// Also updates channels and members.
    async fn delete_role(&self, server_id: &str, role_id: &str) -> Result<()>;
}
