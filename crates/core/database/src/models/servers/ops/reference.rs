use revolt_result::Result;

use crate::ReferenceDb;
use crate::{Channel, FieldsRole, FieldsServer, PartialRole, PartialServer, Role, Server};

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
    /// Also updates channels and members, matching the MongoDb driver: the
    /// role is stripped from every member of the server and its override is
    /// unset on every channel of the server. A missing server or role answers
    /// NotFound and mutates nothing.
    ///
    /// Each map is locked on its own and released before the next is taken,
    /// so this never holds two locks at once.
    async fn delete_role(&self, server_id: &str, role_id: &str) -> Result<()> {
        let mut servers = self.servers.lock().await;
        let removed = servers
            .get_mut(server_id)
            .map(|server| server.roles.remove(role_id).is_some());
        drop(servers);

        if removed != Some(true) {
            return Err(create_error!(NotFound));
        }

        let mut server_members = self.server_members.lock().await;
        for member in server_members.values_mut() {
            if member.id.server == server_id {
                member.roles.retain(|id| id != role_id);
            }
        }
        drop(server_members);

        let mut channels = self.channels.lock().await;
        for channel in channels.values_mut() {
            match channel {
                Channel::TextChannel {
                    server,
                    role_permissions,
                    ..
                }
                | Channel::Forum {
                    server,
                    role_permissions,
                    ..
                } if *server == server_id => {
                    role_permissions.remove(role_id);
                }
                _ => {}
            }
        }

        Ok(())
    }
}

/// `delete_role` parity between the two drivers.
///
/// Only the Reference leg runs here: it calls the real `delete_role` on a
/// `ReferenceDb`. The MongoDb driver is held by a text pin on its source.
/// Running the Mongo leg for real needs `TEST_DB=MONGODB` against a live
/// Mongo; it is on the never-run CI list.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use revolt_permissions::OverrideField;
    use revolt_result::ErrorType;
    use serde_json::json;

    use super::AbstractServers;
    use crate::{Channel, Member, MemberCompositeKey, ReferenceDb, Server};

    const SERVER: &str = "01SERVERA000000000000000000";
    const OTHER_SERVER: &str = "01SERVERB000000000000000000";
    const ROLE: &str = "01ROLE0000000000000000000000";
    const KEEP: &str = "01KEEP0000000000000000000000";

    fn role_json(id: &str) -> serde_json::Value {
        json!({ "_id": id, "name": id, "permissions": { "a": 1, "d": 2 } })
    }

    fn server(id: &str) -> Server {
        serde_json::from_value(json!({
            "_id": id,
            "owner": "01OWNER000000000000000000000",
            "name": id,
            "channels": [],
            "default_permissions": 0,
            "roles": { ROLE: role_json(ROLE), KEEP: role_json(KEEP) },
        }))
        .expect("server fixture")
    }

    fn channel(kind: &str, id: &str, server: &str, roles: &[&str]) -> Channel {
        let overrides: HashMap<String, OverrideField> = roles
            .iter()
            .map(|role| (role.to_string(), OverrideField { a: 1, d: 2 }))
            .collect();
        serde_json::from_value(json!({
            "channel_type": kind,
            "_id": id,
            "server": server,
            "name": id,
            "role_permissions": overrides,
        }))
        .expect("channel fixture")
    }

    fn member(server: &str, user: &str, roles: &[&str]) -> Member {
        Member {
            id: MemberCompositeKey {
                server: server.to_string(),
                user: user.to_string(),
            },
            roles: roles.iter().map(|role| role.to_string()).collect(),
            ..Default::default()
        }
    }

    fn overrides(channel: &Channel) -> &HashMap<String, OverrideField> {
        match channel {
            Channel::TextChannel {
                role_permissions, ..
            }
            | Channel::Forum {
                role_permissions, ..
            } => role_permissions,
            _ => panic!("fixture channel carries no role overrides"),
        }
    }

    /// Two servers, each holding the same role key on two members and on a
    /// text channel and a forum.
    async fn seeded() -> ReferenceDb {
        let db = ReferenceDb::default();

        let mut servers = db.servers.lock().await;
        for id in [SERVER, OTHER_SERVER] {
            servers.insert(id.to_string(), server(id));
        }
        drop(servers);

        let mut members = db.server_members.lock().await;
        for (server, user, roles) in [
            (SERVER, "01USER1", &[ROLE, KEEP][..]),
            (SERVER, "01USER2", &[ROLE][..]),
            (OTHER_SERVER, "01USER1", &[ROLE, KEEP][..]),
            (OTHER_SERVER, "01USER3", &[ROLE][..]),
        ] {
            let member = member(server, user, roles);
            members.insert(member.id.clone(), member);
        }
        drop(members);

        let mut channels = db.channels.lock().await;
        for (kind, id, server) in [
            ("TextChannel", "01CHANA_TEXT", SERVER),
            ("Forum", "01CHANA_FORUM", SERVER),
            ("TextChannel", "01CHANB_TEXT", OTHER_SERVER),
            ("Forum", "01CHANB_FORUM", OTHER_SERVER),
        ] {
            channels.insert(id.to_string(), channel(kind, id, server, &[ROLE, KEEP]));
        }
        drop(channels);

        db
    }

    #[tokio::test]
    async fn delete_role_strips_members_and_channel_overrides_of_that_server_only() {
        let db = seeded().await;

        let other_server = db.servers.lock().await[OTHER_SERVER].clone();
        let other_members: Vec<Member> = db
            .server_members
            .lock()
            .await
            .values()
            .filter(|member| member.id.server == OTHER_SERVER)
            .cloned()
            .collect();
        let other_channels: HashMap<String, Channel> = db
            .channels
            .lock()
            .await
            .iter()
            .filter(|(id, _)| id.starts_with("01CHANB"))
            .map(|(id, channel)| (id.clone(), channel.clone()))
            .collect();
        assert_eq!(other_members.len(), 2);
        assert_eq!(other_channels.len(), 2);

        db.delete_role(SERVER, ROLE).await.expect("delete_role");

        // The role itself is gone from its server, and only that role.
        let servers = db.servers.lock().await;
        let mut roles: Vec<&String> = servers[SERVER].roles.keys().collect();
        roles.sort();
        assert_eq!(roles, vec![KEEP]);
        assert_eq!(servers[OTHER_SERVER], other_server);
        drop(servers);

        // No member of the server holds the role; other roles survive.
        let members = db.server_members.lock().await;
        let key = |user: &str| MemberCompositeKey {
            server: SERVER.to_string(),
            user: user.to_string(),
        };
        assert_eq!(members[&key("01USER1")].roles, vec![KEEP.to_string()]);
        assert!(members[&key("01USER2")].roles.is_empty());
        assert_eq!(
            members
                .values()
                .filter(|member| member.id.server == SERVER)
                .count(),
            2
        );

        // Members of the other server are untouched, same role key included.
        for member in &other_members {
            assert_eq!(&members[&member.id], member);
        }
        drop(members);

        // No channel of the server keeps its override for the role, on
        // every channel shape that carries overrides.
        let channels = db.channels.lock().await;
        for id in ["01CHANA_TEXT", "01CHANA_FORUM"] {
            let mut keys: Vec<&String> = overrides(&channels[id]).keys().collect();
            keys.sort();
            assert_eq!(keys, vec![KEEP], "{id} kept the deleted role's override");
        }

        // Channels of the other server are untouched.
        for (id, channel) in &other_channels {
            assert_eq!(&channels[id], channel);
            assert!(overrides(channel).contains_key(ROLE));
        }
    }

    #[tokio::test]
    async fn delete_role_not_found_mutates_nothing() {
        let db = seeded().await;

        let servers = db.servers.lock().await.clone();
        let members = db.server_members.lock().await.clone();
        let channels = db.channels.lock().await.clone();

        for (server, role) in [
            (SERVER, "01MISSINGROLE"),
            ("01MISSINGSERVER", ROLE),
        ] {
            let error = db
                .delete_role(server, role)
                .await
                .expect_err("a missing server or role must answer NotFound");
            assert!(
                matches!(error.error_type, ErrorType::NotFound),
                "{server}/{role}: {error:?}"
            );
        }

        assert_eq!(*db.servers.lock().await, servers);
        assert_eq!(*db.server_members.lock().await, members);
        assert_eq!(*db.channels.lock().await, channels);
    }

    /// The MongoDb `delete_role` must unset the role override on EVERY
    /// channel of the server. `update_one` clears only the first match.
    #[test]
    fn mongodb_delete_role_unsets_channel_overrides_with_update_many() {
        let source = include_str!("mongodb.rs");
        let start = source
            .find("async fn delete_role(")
            .expect("mongodb.rs defines delete_role");
        let body = &source[start..];
        let body = &body[..body.find("\n    }\n").expect("end of delete_role")];
        assert!(body.contains("\"role_permissions.\""));

        let channel_ops: Vec<&str> = body
            .split("self.col::<Document>(")
            .filter_map(|op| op.strip_prefix("\"channels\")"))
            .collect();
        assert_eq!(
            channel_ops.len(),
            1,
            "delete_role should touch the channels collection exactly once"
        );

        for op in channel_ops {
            assert!(
                op.trim_start().starts_with(".update_many("),
                "delete_role must use update_many on channels"
            );
            assert!(op.contains("create_database_error!(\"update_many\", \"channels\")"));
            assert!(
                !op.contains("update_one"),
                "delete_role must not use update_one on channels"
            );
        }
    }
}
