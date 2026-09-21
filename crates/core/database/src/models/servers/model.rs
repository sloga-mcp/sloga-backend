use std::collections::{HashMap, HashSet};

use revolt_models::v0::{self, DataCreateServerChannel};
use revolt_permissions::{OverrideField, DEFAULT_PERMISSION_SERVER};
use revolt_result::{ErrorType, Result};
use ulid::Ulid;

use crate::{events::client::EventV1, Channel, Database, File, User};

auto_derived_partial!(
    /// Server
    pub struct Server {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// User id of the owner
        pub owner: String,

        /// Name of the server
        pub name: String,
        /// Description for the server
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,

        /// Channels within this server
        // TODO: investigate if this is redundant and can be removed
        pub channels: Vec<String>,
        /// Categories for this server
        #[serde(skip_serializing_if = "Option::is_none")]
        pub categories: Option<Vec<Category>>,
        /// Configuration for sending system event messages
        #[serde(skip_serializing_if = "Option::is_none")]
        pub system_messages: Option<SystemMessageChannels>,

        /// Roles for this server
        #[serde(
            default = "HashMap::<String, Role>::new",
            skip_serializing_if = "HashMap::<String, Role>::is_empty"
        )]
        pub roles: HashMap<String, Role>,
        /// Default set of server and channel permissions
        pub default_permissions: i64,

        /// Icon attachment
        #[serde(skip_serializing_if = "Option::is_none")]
        pub icon: Option<File>,
        /// Banner attachment
        #[serde(skip_serializing_if = "Option::is_none")]
        pub banner: Option<File>,

        /// Bitfield of server flags
        #[serde(skip_serializing_if = "Option::is_none")]
        pub flags: Option<i32>,

        /// Whether this server is flagged as not safe for work
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub nsfw: bool,
        /// Whether to enable analytics
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub analytics: bool,
        /// Whether this server should be publicly discoverable
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub discoverable: bool,
        /// Whether the owner has requested a public discovery listing
        /// (pending until a platform admin sets `discoverable`)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub discovery_requested: bool,

        /// Denormalized count of active boost slots — written ONLY by
        /// authoritative recounts (ServerBoost::recount_for_server), never
        /// incrementally and never from client input
        #[serde(skip_serializing_if = "Option::is_none")]
        pub boost_count: Option<i32>,
        /// Denormalized boost perk tier (0-3), derived from `boost_count`
        /// and the configured thresholds by the same recount path
        #[serde(skip_serializing_if = "Option::is_none")]
        pub boost_tier: Option<i32>,

        /// Preferred LiveKit node for this server's voice channels (a key of
        /// `config.api.livekit.nodes`). Consulted only when a room is opened:
        /// an already-pinned room keeps its node. Absent = Auto (the client
        /// picks by latency).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub voice_region: Option<String>,

        /// Id of this server's AFK voice channel, if one is designated.
        /// At most one per server — the pointer lives here rather than as a
        /// per-channel flag so "exactly one" is unrepresentable otherwise.
        /// May go stale (the channel can be deleted or lose its voice
        /// information), so every reader must resolve-then-check.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub afk_channel_id: Option<String>,
        /// Idle timeout in SECONDS before a member is moved to the AFK
        /// channel. Absent = no auto-move.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub afk_timeout: Option<u32>,
    },
    "PartialServer"
);

auto_derived_partial!(
    /// Role
    pub struct Role {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Role name
        pub name: String,
        /// Permissions available to this role
        pub permissions: OverrideField,
        /// Colour used for this role
        ///
        /// This can be any valid CSS colour
        #[serde(skip_serializing_if = "Option::is_none")]
        pub colour: Option<String>,
        /// Whether this role should be shown separately on the member sidebar
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub hoist: bool,
        /// Ranking of this role
        #[serde(default)]
        pub rank: i64,
        /// Custom icon attachment
        #[serde(skip_serializing_if = "Option::is_none")]
        pub icon: Option<File>,
    },
    "PartialRole"
);

auto_derived!(
    /// Channel category
    pub struct Category {
        /// Unique ID for this category
        pub id: String,
        /// Title for this category
        pub title: String,
        /// Channels in this category
        pub channels: Vec<String>,
    }

    /// System message channel assignments
    pub struct SystemMessageChannels {
        /// ID of channel to send user join messages in
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_joined: Option<String>,
        /// ID of channel to send user left messages in
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_left: Option<String>,
        /// ID of channel to send user kicked messages in
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_kicked: Option<String>,
        /// ID of channel to send user banned messages in
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_banned: Option<String>,
    }

    /// Optional fields on server object
    pub enum FieldsServer {
        Description,
        Categories,
        SystemMessages,
        Icon,
        Banner,
        VoiceRegion,
        AfkChannel,
        AfkTimeout,
    }

    /// Optional fields on server object
    pub enum FieldsRole {
        Colour,
        Icon,
    }
);

#[allow(clippy::disallowed_methods)]
impl Server {
    /// Create a server
    pub async fn create(
        db: &Database,
        data: v0::DataCreateServer,
        owner: &User,
        create_default_channels: bool,
    ) -> Result<(Server, Vec<Channel>)> {
        let mut server = Server {
            id: ulid::Ulid::new().to_string(),
            owner: owner.id.to_string(),
            name: data.name,
            description: data.description,
            channels: vec![],
            nsfw: data.nsfw.unwrap_or(false),
            default_permissions: *DEFAULT_PERMISSION_SERVER as i64,

            analytics: false,
            banner: None,
            boost_count: None,
            boost_tier: None,
            categories: None,
            discoverable: false,
            discovery_requested: false,
            flags: None,
            icon: None,
            roles: HashMap::new(),
            system_messages: None,
            voice_region: None,
            afk_channel_id: None,
            afk_timeout: None,
        };

        let channels: Vec<Channel> = if create_default_channels {
            vec![
                Channel::create_server_channel(
                    db,
                    &mut server,
                    DataCreateServerChannel {
                        channel_type: v0::LegacyServerChannelType::Text,
                        name: "General".to_string(),
                        ..Default::default()
                    },
                    false,
                )
                .await?,
            ]
        } else {
            vec![]
        };

        server.channels = channels.iter().map(|c| c.id().to_string()).collect();
        db.insert_server(&server).await?;
        Ok((server, channels))
    }

    /// Update server data
    pub async fn update(
        &mut self,
        db: &Database,
        partial: PartialServer,
        remove: Vec<FieldsServer>,
    ) -> Result<()> {
        for field in &remove {
            self.remove_field(field);
        }

        self.apply_options(partial.clone());

        db.update_server(&self.id, &partial, remove.clone()).await?;

        EventV1::ServerUpdate {
            id: self.id.clone(),
            data: partial.into(),
            clear: remove.into_iter().map(|v| v.into()).collect(),
        }
        .p(self.id.clone())
        .await;

        Ok(())
    }

    /// Delete a server
    pub async fn delete(self, db: &Database) -> Result<()> {
        // Calendar cascade (slice F): without this, a deleted server's events keep
        // matching crond's cross-server reminder scan until their `series_end`.
        // Runs BEFORE the ServerDelete broadcast so a cascade failure aborts the
        // deletion without having announced it.
        db.delete_calendar_for_server(&self.id).await?;

        // Scheduled-message cascade: cancel pending rows LOUDLY (release
        // claimed attachments + notify each author privately) before the
        // channels are dropped wholesale — the Mongo bulk cascade cannot
        // notify or release. Rows carry `server`, so threads are covered.
        crate::ScheduledMessage::cancel_all_for_server(db, &self.id).await?;

        // Announcement-follow cascade: the bulk server-delete path never runs
        // Channel::delete, so follows touching this server on either side —
        // and the far-side webhooks living in OTHER, surviving servers'
        // channels — must be severed here, before the channels are dropped.
        crate::ChannelFollow::cleanup_for_deleted_server(db, &self.id).await?;

        // Boost cascade: return every allocated boost slot to its owner's
        // inventory — otherwise the slots stay pinned to a dead server id
        // forever and the owners can never re-spend them.
        db.deallocate_all_server_boosts_for_server(&self.id).await?;

        EventV1::ServerDelete {
            id: self.id.clone(),
        }
        .p(self.id.clone())
        .await;

        db.delete_server(&self.id).await
    }

    /// Remove a field from Server
    pub fn remove_field(&mut self, field: &FieldsServer) {
        match field {
            FieldsServer::Description => self.description = None,
            FieldsServer::Categories => self.categories = None,
            FieldsServer::SystemMessages => self.system_messages = None,
            FieldsServer::Icon => self.icon = None,
            FieldsServer::Banner => self.banner = None,
            FieldsServer::VoiceRegion => self.voice_region = None,
            FieldsServer::AfkChannel => self.afk_channel_id = None,
            FieldsServer::AfkTimeout => self.afk_timeout = None,
        }
    }

    /// Allowed AFK idle timeouts, in SECONDS.
    ///
    /// 1/5/15/30/60 minutes, matching Discord's choices. A closed preset set
    /// rather than a free range: the client renders a select from it, and no
    /// caller can ask for a 1-second timeout that would have a sweep move
    /// every member on every tick.
    pub const AFK_TIMEOUT_CHOICES: [u32; 5] = [60, 300, 900, 1800, 3600];

    /// Resolve and validate a proposed AFK channel for this server.
    ///
    /// Shared by every writer of `afk_channel_id` so the three conditions live
    /// in exactly one place. Returns the resolved channel because callers need
    /// it to drive `sync_voice_permissions` on the incoming designation.
    ///
    /// Fails closed on all three cases:
    /// - the id does not resolve -> `UnknownChannel`
    /// - the channel is not in this server, including a channel with no server
    ///   at all (DM, group, saved messages) -> `UnknownChannel`, matching the
    ///   cross-server check on `member_edit`'s move path
    /// - the channel is not a voice channel -> `InvalidProperty`
    ///
    /// There is no `VoiceChannel` type - migration 46 removed it. A voice
    /// channel is a `TextChannel` carrying `voice: Some(..)`, and
    /// `Channel::voice()` is the only discriminator. It also returns `None`
    /// when `voice.disabled` is set, which is the behaviour we want here: a
    /// channel with calling turned off must not be designated AFK.
    ///
    /// This validates at write time only. The pointer can still go stale
    /// afterwards (the channel can be deleted, or lose its voice information),
    /// so every reader must resolve-then-check rather than trust it.
    pub async fn validate_afk_channel(
        db: &Database,
        server_id: &str,
        channel_id: &str,
    ) -> Result<Channel> {
        let channel = db
            .fetch_channel(channel_id)
            .await
            .map_err(|_| create_error!(UnknownChannel))?;

        if channel.server().is_none_or(|id| id != server_id) {
            return Err(create_error!(UnknownChannel));
        }

        if channel.voice().is_none() {
            return Err(create_error!(InvalidProperty));
        }

        Ok(channel)
    }

    /// Validate a proposed AFK idle timeout against `AFK_TIMEOUT_CHOICES`.
    ///
    /// Anything outside the preset set is rejected; there is no clamping, so a
    /// bad value never lands as a silently different one.
    pub fn validate_afk_timeout(timeout: u32) -> Result<()> {
        if Server::AFK_TIMEOUT_CHOICES.contains(&timeout) {
            Ok(())
        } else {
            Err(create_error!(InvalidProperty))
        }
    }

    /// Clear this server's AFK designation, but only if it currently points at
    /// `channel_id`.
    ///
    /// D1 stores the AFK channel as a server-level pointer, which is what makes
    /// "exactly one AFK channel per server" unrepresentable rather than merely
    /// enforced by code. The accepted cost of that shape is that routes which
    /// never touch the server document can invalidate the pointer: deleting the
    /// channel, or removing/disabling its voice information. Both of those
    /// paths funnel through here so the "is this still ours?" comparison and
    /// the clear itself live in exactly one place.
    ///
    /// The clear MUST go through `FieldsServer::AfkChannel` /
    /// `FieldsServer::AfkTimeout` in the `remove` vector. `Server` is declared
    /// inside `auto_derived_partial!` with `opt_some_priority`, and because
    /// `afk_channel_id` is already an `Option<T>` the generated partial field
    /// stays `Option<T>` and the generated assigner reads
    /// `if let Some(v) = partial.afk_channel_id { self.afk_channel_id.replace(v) }`.
    /// Writing `afk_channel_id: None` into a `PartialServer` is therefore a
    /// silent no-op. `Server::update` also carries `remove` into the
    /// `EventV1::ServerUpdate` `clear` array, so going through `remove` is what
    /// fans the clear out to clients. This is the `voice_region` precedent.
    ///
    /// The timeout is cleared alongside the channel: it only has meaning
    /// relative to a destination, so leaving it set would orphan it.
    ///
    /// Takes ids rather than a `&Server` or `&mut Server` because neither
    /// caller has a server in hand - `Channel::delete` and `channel_edit` both
    /// hold only a channel - and `Server::update` needs an owned `&mut Server`
    /// anyway. A borrowed parameter would force both callers to do the fetch
    /// themselves and then repeat the equality check.
    ///
    /// A server that no longer resolves is a no-op rather than an error: there
    /// is no pointer left to go stale, and letting a concurrently deleted
    /// server abort a channel deletion would be a new failure mode, not a
    /// safety gain. Every other database error still propagates.
    pub async fn clear_afk_channel_if_pointing_at(
        db: &Database,
        server_id: &str,
        channel_id: &str,
    ) -> Result<()> {
        let mut server = match db.fetch_server(server_id).await {
            Ok(server) => server,
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };

        if server.afk_channel_id.as_deref() != Some(channel_id) {
            return Ok(());
        }

        server
            .update(
                db,
                PartialServer::default(),
                vec![FieldsServer::AfkChannel, FieldsServer::AfkTimeout],
            )
            .await
    }

    /// Ordered roles list
    pub fn ordered_roles(&self) -> Vec<(String, Role)> {
        let mut ordered_roles = self.roles.clone().into_iter().collect::<Vec<_>>();
        ordered_roles.sort_by(|(_, role_a), (_, role_b)| role_a.rank.cmp(&role_b.rank));
        ordered_roles
    }

    /// Set role permission on a server
    pub async fn set_role_permission(
        &mut self,
        db: &Database,
        role_id: &str,
        permissions: OverrideField,
    ) -> Result<()> {
        if let Some(role) = self.roles.get_mut(role_id) {
            role.update(
                db,
                &self.id,
                PartialRole {
                    permissions: Some(permissions),
                    ..Default::default()
                },
                vec![],
            )
            .await?;

            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Reorders the server's roles rankings
    pub async fn set_role_ordering(&mut self, db: &Database, new_order: Vec<String>) -> Result<()> {
        // New order must always contain every role
        debug_assert_eq!(self.roles.len(), new_order.len());

        // Set the role's ranks to the positions in the vec
        for (rank, id) in new_order.iter().enumerate() {
            self.roles.get_mut(id).unwrap().rank = rank as i64;
        }

        db.update_server(
            &self.id,
            &PartialServer {
                roles: Some(self.roles.clone()),
                ..Default::default()
            },
            Vec::new(),
        )
        .await?;

        // Publish bulk update event
        EventV1::ServerRoleRanksUpdate {
            id: self.id.clone(),
            ranks: new_order,
        }
        .p(self.id.clone())
        .await;

        Ok(())
    }
}

impl Role {
    /// Into optional struct
    pub fn into_optional(self) -> PartialRole {
        PartialRole {
            id: Some(self.id),
            name: Some(self.name),
            permissions: Some(self.permissions),
            colour: self.colour,
            hoist: Some(self.hoist),
            rank: Some(self.rank),
            icon: self.icon,
        }
    }

    /// Create a role
    pub async fn create(db: &Database, server: &Server, name: String) -> Result<Self> {
        let role = Role {
            id: Ulid::new().to_string(),
            name,
            // Rank of the new role should be below the lowest role
            rank: server.roles.len() as i64,
            colour: None,
            hoist: false,
            permissions: Default::default(),
            icon: None,
        };

        db.insert_role(&server.id, &role).await?;

        EventV1::ServerRoleUpdate {
            id: server.id.clone(),
            role_id: role.id.clone(),
            data: role.clone().into_optional().into(),
            clear: vec![],
        }
        .p(server.id.clone())
        .await;

        Ok(role)
    }

    /// Update server data
    pub async fn update(
        &mut self,
        db: &Database,
        server_id: &str,
        partial: PartialRole,
        remove: Vec<FieldsRole>,
    ) -> Result<()> {
        for field in &remove {
            self.remove_field(field);
        }

        self.apply_options(partial.clone());

        db.update_role(server_id, &self.id, &partial, remove.clone())
            .await?;

        EventV1::ServerRoleUpdate {
            id: server_id.to_string(),
            role_id: self.id.clone(),
            data: partial.into(),
            clear: remove.into_iter().map(Into::into).collect(),
        }
        .p(server_id.to_string())
        .await;

        Ok(())
    }

    /// Remove field from Role
    pub fn remove_field(&mut self, field: &FieldsRole) {
        match field {
            FieldsRole::Colour => self.colour = None,
            FieldsRole::Icon => self.icon = None,
        }
    }

    /// Delete a role
    pub async fn delete(self, db: &Database, server_id: &str) -> Result<()> {
        EventV1::ServerRoleDelete {
            id: server_id.to_string(),
            role_id: self.id.clone(),
        }
        .p(server_id.to_string())
        .await;

        db.delete_role(server_id, &self.id).await
    }
}

impl SystemMessageChannels {
    pub fn into_channel_ids(self) -> HashSet<String> {
        let mut ids = HashSet::new();

        if let Some(id) = self.user_joined {
            ids.insert(id);
        }

        if let Some(id) = self.user_left {
            ids.insert(id);
        }

        if let Some(id) = self.user_kicked {
            ids.insert(id);
        }

        if let Some(id) = self.user_banned {
            ids.insert(id);
        }

        ids
    }
}

#[cfg(test)]
mod tests {
    use revolt_permissions::{calculate_server_permissions, ChannelPermission};

    use crate::{fixture, util::permissions::DatabasePermissionQuery};

    #[tokio::test]
    async fn permissions() {
        database_test!(|db| async move {
            fixture!(db, "server_with_roles",
                owner user 0
                moderator user 1
                user user 2
                server server 4);

            let mut query = DatabasePermissionQuery::new(&db, &owner).server(&server);
            assert!(calculate_server_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::GrantAllSafe));

            let mut query = DatabasePermissionQuery::new(&db, &moderator).server(&server);
            assert!(calculate_server_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::BanMembers));

            let mut query = DatabasePermissionQuery::new(&db, &user).server(&server);
            assert!(!calculate_server_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::BanMembers));
        });
    }
}
