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
    /// Shared by every writer of `afk_channel_id` so the four conditions live
    /// in exactly one place. Returns the resolved channel because callers need
    /// it to drive `sync_voice_permissions` on the incoming designation.
    ///
    /// Fails closed on all four cases, checked in this order:
    /// - the id does not resolve -> `UnknownChannel`
    /// - the channel is not in this server, including a channel with no server
    ///   at all (DM, group, saved messages) -> `UnknownChannel`, matching the
    ///   cross-server check on `member_edit`'s move path
    /// - the channel is not a voice channel -> `InvalidProperty`
    /// - the channel is behind a client gate (age, spoiler or password,
    ///   `Channel::has_client_gate`) -> `InvalidProperty`. Idle members are
    ///   moved into the AFK channel without being asked, so it must never be
    ///   a channel some of them have not been let into. The server cannot
    ///   tell who has passed a gate, so any gate refuses.
    ///
    /// There is no `VoiceChannel` type - migration 46 removed it. A voice
    /// channel is a `TextChannel` carrying `voice: Some(..)`, and
    /// `Channel::voice()` is the only discriminator. It also returns `None`
    /// when `voice.disabled` is set, which is the behavior we want here: a
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

        if channel.has_client_gate() {
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
    /// THE RULE FOR THE PAIR, stated once here because five writers touch it
    /// and they used to disagree: **`afk_timeout` is meaningless without
    /// `afk_channel_id`.** It names how long a member idles before being moved
    /// to the AFK channel, so with no channel designated there is nothing for
    /// it to mean. The five are this helper, `server_edit`, `channel_create`,
    /// the Discord import worker and the revision-72 migration. Concretely:
    ///
    /// - clearing the channel clears the timeout - this helper, and the
    ///   `remove: ["AfkChannel"]` path in `server_edit`, which appends
    ///   `AfkTimeout` to `remove` for exactly this reason;
    /// - setting a timeout requires a channel to be designated once the edit
    ///   lands, either already on the server or arriving in the same request -
    ///   `server_edit::validate_afk_edit` rejects the rest with
    ///   `InvalidProperty`;
    /// - `channel_create` with `afk: true` always designates a channel, so any
    ///   timeout it writes (or any timeout the server already carried) has a
    ///   destination by construction;
    /// - the Discord import writes a timeout only alongside the AFK channel it
    ///   maps, and the revision-72 migration writes the channel and never a
    ///   timeout.
    ///
    /// Of the five, only the two routes re-sync live LiveKit grants
    /// (`voice::sync_afk_designation_change`, whose doc says why the other
    /// three need not). This helper needs no sync because both routes that
    /// reach it tear the channel's call down right after it: `channel_delete`
    /// (through `Channel::delete`) and `channel_edit`'s de-voice block each
    /// call `delete_voice_channel`, so no room is left holding a grant minted
    /// under the old designation.
    ///
    /// That is also why putting a client gate on the designated channel is
    /// REFUSED in `channel_edit` rather than cleared through here: gating a
    /// channel does not tear its room down, so a clear on that path would
    /// need a live re-sync to lift the hard mute from everyone still in it.
    /// Removing the designation first goes through `server_edit`, which
    /// re-syncs both sides.
    ///
    /// Nothing enforces the rule at the database layer - `PartialServer` can
    /// still carry a timeout on its own - so it is an invariant the route
    /// layer maintains, not one the type system holds.
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

    /// Every channel id that can hold this server's messages: `self.channels`
    /// (verbatim, dangling ids included) followed by every thread / forum post
    /// hanging off them, which are never listed in `Server.channels`.
    ///
    /// Anything that scopes a message sweep to "this server" (the ban purge,
    /// the prune exemption) must use this rather than `self.channels`, or a
    /// thread's messages fall outside the sweep.
    ///
    /// The ids are never resolved through `fetch_channels`: the Reference
    /// driver fails the whole lookup with NotFound on one dangling id, which
    /// would abort the caller. A dangling id is harmless here; it matches no
    /// thread and no message. Threads are found by parent, archived and
    /// locked ones included. Their order is not guaranteed.
    pub async fn message_channel_ids(&self, db: &Database) -> Result<Vec<String>> {
        let mut ids = self.channels.clone();
        ids.extend(db.fetch_thread_ids_by_parents(&self.channels).await?);
        Ok(ids)
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
    use std::collections::HashSet;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use revolt_models::v0::{self, DataCreateServer, DataCreateServerChannel};
    use revolt_permissions::{calculate_server_permissions, ChannelPermission};
    use revolt_result::ErrorType;
    use ulid::Ulid;

    use crate::{
        fixture, util::permissions::DatabasePermissionQuery, Channel, Database, FieldsChannel,
        File, FileUsedFor, FileUsedForType, Message, Metadata, PartialChannel, PartialServer,
        Server, User,
    };

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

    // ---------------------------------------------------------------------
    // AFK designation.
    //
    // Wave 2 shipped the writers and the two cascades with no tests at all.
    // These pin the rules that have no other guard, in particular the delete
    // cascade: the plan put `Server::clear_afk_channel_if_pointing_at` ABOVE
    // the driver split precisely because `Reference::delete_channel` does
    // almost none of `MongoDb::delete_channel`'s cleanup, and a future
    // refactor pushing the clear back down into `ops/mongodb.rs` would pass on
    // Mongo and silently do nothing on Reference. These run under
    // TEST_DB=REFERENCE, which is the half that would break.
    // ---------------------------------------------------------------------

    async fn new_server(db: &Database, owner_name: &str) -> Server {
        let owner = User::create(db, owner_name.to_string(), None, None)
            .await
            .expect("`User`");

        Server::create(
            db,
            DataCreateServer {
                name: "Server".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0
    }

    async fn new_channel(
        db: &Database,
        server: &mut Server,
        name: &str,
        channel_type: v0::LegacyServerChannelType,
        voice: Option<v0::VoiceInformation>,
    ) -> Channel {
        Channel::create_server_channel(
            db,
            server,
            DataCreateServerChannel {
                channel_type,
                name: name.to_string(),
                voice,
                ..Default::default()
            },
            true,
        )
        .await
        .expect("`Channel`")
    }

    async fn designate(db: &Database, server: &mut Server, channel_id: &str) {
        server
            .update(
                db,
                PartialServer {
                    afk_channel_id: Some(channel_id.to_string()),
                    afk_timeout: Some(300),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("designation");
    }

    /// `Server::validate_afk_channel` is the shared rule for every writer of
    /// `afk_channel_id`. All four rejection arms, plus the accepting case so a
    /// blanket refusal cannot read as a pass.
    ///
    /// The DM case is why the checks are ordered server-first: `Channel::voice()`
    /// returns `Some` for a DM (they are always callable), so a voice-first
    /// check would wave a DM straight through. Asserted below rather than
    /// assumed.
    #[tokio::test]
    async fn validate_afk_channel_rejects_everything_that_is_not_ours() {
        database_test!(|db| async move {
            let mut server = new_server(&db, "AfkValidateOwner").await;
            let mut other_server = new_server(&db, "AfkValidateOther").await;

            let voice = new_channel(
                &db,
                &mut server,
                "Voice",
                v0::LegacyServerChannelType::Voice,
                None,
            )
            .await;
            let text = new_channel(
                &db,
                &mut server,
                "Text",
                v0::LegacyServerChannelType::Text,
                None,
            )
            .await;
            let disabled = new_channel(
                &db,
                &mut server,
                "Disabled",
                v0::LegacyServerChannelType::Voice,
                Some(v0::VoiceInformation {
                    max_users: None,
                    disabled: true,
                }),
            )
            .await;
            let elsewhere = new_channel(
                &db,
                &mut other_server,
                "Voice",
                v0::LegacyServerChannelType::Voice,
                None,
            )
            .await;

            let a = User::create(&db, "AfkDmOne".to_string(), None, None)
                .await
                .expect("`User`");
            let b = User::create(&db, "AfkDmTwo".to_string(), None, None)
                .await
                .expect("`User`");
            let dm = Channel::create_dm(&db, &a, &b).await.expect("`Channel`");

            // The premise of the check ORDER: a DM is a callable channel, so
            // only the "is it in this server" test can reject it.
            assert!(dm.voice().is_some());
            assert!(dm.server().is_none());

            // An id that does not resolve at all.
            let error = Server::validate_afk_channel(&db, &server.id, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
                .await
                .expect_err("an unknown id is not a designation");
            assert!(matches!(error.error_type, ErrorType::UnknownChannel));

            // A DM - no server at all.
            let error = Server::validate_afk_channel(&db, &server.id, dm.id())
                .await
                .expect_err("a DM is not in any server");
            assert!(matches!(error.error_type, ErrorType::UnknownChannel));

            // A voice channel in a DIFFERENT server.
            let error = Server::validate_afk_channel(&db, &server.id, elsewhere.id())
                .await
                .expect_err("a channel in another server is not ours to designate");
            assert!(matches!(error.error_type, ErrorType::UnknownChannel));

            // A plain text channel in this server.
            let error = Server::validate_afk_channel(&db, &server.id, text.id())
                .await
                .expect_err("a text channel has no voice information");
            assert!(matches!(error.error_type, ErrorType::InvalidProperty));

            // A voice channel in this server with calling turned off.
            // `Channel::voice()` returns None for a disabled one, which is the
            // whole discriminator.
            assert!(disabled.voice().is_none());
            let error = Server::validate_afk_channel(&db, &server.id, disabled.id())
                .await
                .expect_err("a disabled voice channel is not a voice channel");
            assert!(matches!(error.error_type, ErrorType::InvalidProperty));

            // And the one that should work.
            let resolved = Server::validate_afk_channel(&db, &server.id, voice.id())
                .await
                .expect("a voice channel in this server is a valid designation");
            assert_eq!(resolved.id(), voice.id());
        });
    }

    /// The timeout preset set is closed and never clamped, so a rejected value
    /// can never land as a silently different one.
    #[tokio::test]
    async fn validate_afk_timeout_accepts_only_the_presets() {
        for timeout in Server::AFK_TIMEOUT_CHOICES {
            assert!(Server::validate_afk_timeout(timeout).is_ok());
        }

        // Zero, a value just off a preset, and something absurd.
        for timeout in [0, 1, 59, 61, 299, 3601, u32::MAX] {
            let error = Server::validate_afk_timeout(timeout)
                .expect_err("out-of-set timeouts are rejected, not clamped");
            assert!(matches!(error.error_type, ErrorType::InvalidProperty));
        }
    }

    /// Delete cascade. `Server.afk_channel_id` lives on the server document,
    /// so `delete_channel` has no way to notice it; left behind it names a
    /// channel that no longer exists. The clear sits in `Channel::delete`,
    /// above the driver split - this test is what stops it being pushed back
    /// down into `MongoDb::delete_channel`, where REFERENCE would silently
    /// lose it.
    ///
    /// The timeout goes with the channel: it is meaningless on its own.
    #[tokio::test]
    async fn deleting_the_afk_channel_clears_the_designation() {
        database_test!(|db| async move {
            let mut server = new_server(&db, "AfkDeleteOwner").await;
            let voice = new_channel(
                &db,
                &mut server,
                "AFK",
                v0::LegacyServerChannelType::Voice,
                None,
            )
            .await;

            designate(&db, &mut server, voice.id()).await;
            let fetched = db.fetch_server(&server.id).await.expect("`Server`");
            assert_eq!(fetched.afk_channel_id.as_deref(), Some(voice.id()));
            assert_eq!(fetched.afk_timeout, Some(300));

            voice.delete(&db).await.expect("delete");

            let fetched = db.fetch_server(&server.id).await.expect("`Server`");
            assert_eq!(fetched.afk_channel_id, None);
            assert_eq!(fetched.afk_timeout, None);
        });
    }

    /// The other half of the cascade: the clear is conditional on the pointer
    /// naming THIS channel. Without this, a cascade written as an
    /// unconditional clear would pass the test above and quietly un-designate
    /// the AFK channel every time any other channel in the server was deleted.
    #[tokio::test]
    async fn deleting_an_unrelated_channel_leaves_the_designation_alone() {
        database_test!(|db| async move {
            let mut server = new_server(&db, "AfkDeleteOtherOwner").await;
            let afk = new_channel(
                &db,
                &mut server,
                "AFK",
                v0::LegacyServerChannelType::Voice,
                None,
            )
            .await;
            let bystander = new_channel(
                &db,
                &mut server,
                "General",
                v0::LegacyServerChannelType::Text,
                None,
            )
            .await;

            designate(&db, &mut server, afk.id()).await;

            bystander.delete(&db).await.expect("delete");

            let fetched = db.fetch_server(&server.id).await.expect("`Server`");
            assert_eq!(fetched.afk_channel_id.as_deref(), Some(afk.id()));
            assert_eq!(fetched.afk_timeout, Some(300));
        });
    }

    /// De-voicing cascade, at the model layer.
    ///
    /// HONESTY NOTE: this exercises the helper and the `channel.voice().is_none()`
    /// condition that `channel_edit` branches on, in the same order
    /// `channel_edit` runs them - it does NOT exercise the route wiring
    /// itself, which needs the Rocket harness (redis + rabbitmq) and could not
    /// be run on this box. Both shapes `channel_edit` can produce are covered:
    /// `remove: ["Voice"]` and `voice: { disabled: true }`.
    #[tokio::test]
    async fn de_voicing_the_afk_channel_clears_the_designation() {
        database_test!(|db| async move {
            for remove_outright in [true, false] {
                let mut server = new_server(
                    &db,
                    if remove_outright {
                        "AfkDevoiceRemove"
                    } else {
                        "AfkDevoiceDisable"
                    },
                )
                .await;
                let mut afk = new_channel(
                    &db,
                    &mut server,
                    "AFK",
                    v0::LegacyServerChannelType::Voice,
                    None,
                )
                .await;

                designate(&db, &mut server, afk.id()).await;

                if remove_outright {
                    afk.update(&db, PartialChannel::default(), vec![FieldsChannel::Voice])
                        .await
                        .expect("de-voice");
                } else {
                    afk.update(
                        &db,
                        PartialChannel {
                            voice: Some(crate::VoiceInformation {
                                max_users: None,
                                disabled: true,
                            }),
                            ..Default::default()
                        },
                        vec![],
                    )
                    .await
                    .expect("disable calling");
                }

                // This is the condition `channel_edit` branches on.
                assert!(afk.voice().is_none());

                let Channel::TextChannel {
                    server: server_id,
                    id,
                    ..
                } = &afk
                else {
                    panic!("a server voice channel is a TextChannel carrying voice information");
                };
                Server::clear_afk_channel_if_pointing_at(&db, server_id, id)
                    .await
                    .expect("clear");

                let fetched = db.fetch_server(&server.id).await.expect("`Server`");
                assert_eq!(fetched.afk_channel_id, None);
                assert_eq!(fetched.afk_timeout, None);
            }
        });
    }

    // ---- Client gates (wave BG) --------------------------------------------

    async fn new_voice_channel(
        db: &Database,
        server: &mut Server,
        name: &str,
        nsfw: Option<bool>,
        spoiler: Option<bool>,
        description: Option<String>,
    ) -> Channel {
        Channel::create_server_channel(
            db,
            server,
            DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Voice,
                name: name.to_string(),
                nsfw,
                spoiler,
                description,
                ..Default::default()
            },
            true,
        )
        .await
        .expect("`Channel`")
    }

    /// Idle members are moved into the AFK channel without being asked, so a
    /// channel behind a client gate (age, spoiler, password) is never a valid
    /// designation. Each gate on its own is refused with `InvalidProperty`.
    ///
    /// A marker on a line that is NOT the last is no password (the client
    /// reads only the last line), so that channel is accepted: a refusal of
    /// every description would fail here. And the server check still comes
    /// first, so a gated channel in another server stays `UnknownChannel`.
    #[tokio::test]
    async fn validate_afk_channel_refuses_a_gated_voice_channel() {
        database_test!(|db| async move {
            use crate::{CHANNEL_PASSWORD_PREFIX, CHANNEL_PASSWORD_SUFFIX};

            let mut server = new_server(&db, "AfkGatedOwner").await;
            let mut other_server = new_server(&db, "AfkGatedOther").await;
            let hash = "0123456789abcdef".repeat(4);
            let password = [
                CHANNEL_PASSWORD_PREFIX,
                hash.as_str(),
                CHANNEL_PASSWORD_SUFFIX,
            ]
            .concat();

            let gated = [
                ("Mature", Some(true), None, None),
                ("Spoiler", None, Some(true), None),
                (
                    "Password",
                    None,
                    None,
                    Some(["Welcome\n", password.as_str()].concat()),
                ),
            ];
            for (name, nsfw, spoiler, description) in gated {
                let channel =
                    new_voice_channel(&db, &mut server, name, nsfw, spoiler, description).await;
                assert!(channel.voice().is_some(), "{name} is a voice channel");

                let error = Server::validate_afk_channel(&db, &server.id, channel.id())
                    .await
                    .expect_err("a gated channel is not a designation");
                assert!(
                    matches!(error.error_type, ErrorType::InvalidProperty),
                    "{name}: {error:?}"
                );
            }

            let open = new_voice_channel(
                &db,
                &mut server,
                "Open",
                Some(false),
                Some(false),
                Some([password.as_str(), "\nWelcome"].concat()),
            )
            .await;
            let resolved = Server::validate_afk_channel(&db, &server.id, open.id())
                .await
                .expect("a marker that is not on the last line is no password");
            assert_eq!(resolved.id(), open.id());

            let elsewhere =
                new_voice_channel(&db, &mut other_server, "Mature", Some(true), None, None).await;
            let error = Server::validate_afk_channel(&db, &server.id, elsewhere.id())
                .await
                .expect_err("a channel in another server is not ours to designate");
            assert!(matches!(error.error_type, ErrorType::UnknownChannel));
        });
    }

    /// The order the doc promises: server, then voice, then gate. Server first
    /// because a DM is callable (see above); the gate last, so a gated text
    /// channel keeps the not-a-voice-channel refusal it always had. Control:
    /// the gate arm moved above the voice arm.
    #[test]
    fn validate_afk_channel_checks_server_then_voice_then_gate() {
        const SOURCE: &str = include_str!("model.rs");

        let at = SOURCE
            .find("pub async fn validate_afk_channel(")
            .expect("the validator");
        let end = at
            + SOURCE[at..]
                .find("\n    }\n")
                .expect("the end of the validator");
        let body = &SOURCE[at..end];

        let position = |needle: &str| {
            assert_eq!(body.matches(needle).count(), 1, "`{needle}`: {body}");
            body.find(needle).expect("counted above")
        };
        let server = position("if channel.server().is_none_or(");
        let voice = position("if channel.voice().is_none()");
        let gate = position("if channel.has_client_gate()");

        assert!(server < voice, "{body}");
        assert!(voice < gate, "{body}");
    }

    // ---- Message scope (ban purge) -----------------------------------------
    //
    // `Server.channels` lists top-level channels only. Threads and forum posts
    // hold messages too but are never listed there, so a purge scoped to
    // `server.channels` left everything a banned user wrote in a thread
    // behind. Control for both tests: `message_channel_ids` returning
    // `self.channels.clone()`.

    const MCI_P1: &str = "01MCIPARENTTEXT";
    const MCI_P2: &str = "01MCIPARENTFORUM";
    const MCI_DANGLING: &str = "01MCIDANGLINGCHANNEL";
    const MCI_T1: &str = "01MCITHREAD1";
    const MCI_T2: &str = "01MCITHREAD2ARCHIVEDLOCKED";
    const MCI_Q1: &str = "01MCIOTHERPARENT";
    const MCI_U1: &str = "01MCIOTHERTHREAD";
    const MCI_A: &str = "01MCIAUTHORA";
    const MCI_B: &str = "01MCIAUTHORB";
    const MCI_FILE_PURGED: &str = "01MCIFILEPURGED";
    const MCI_FILE_KEPT: &str = "01MCIFILEKEPT";

    fn mci_text_channel(id: &str, server: &str) -> Channel {
        Channel::TextChannel {
            id: id.to_string(),
            server: server.to_string(),
            name: "text".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: Default::default(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
        }
    }

    fn mci_thread(id: &str, server: &str, parent: &str, archived: bool, locked: bool) -> Channel {
        Channel::Thread {
            id: id.to_string(),
            server: server.to_string(),
            parent_channel: parent.to_string(),
            name: "thread".to_string(),
            creator: MCI_A.to_string(),
            origin_message_id: None,
            last_message_id: None,
            archived,
            archived_timestamp: None,
            auto_archive_minutes: Channel::default_auto_archive_minutes(),
            locked,
            applied_tags: vec![],
        }
    }

    fn mci_file(id: &str, message_id: &str) -> File {
        File {
            id: id.to_string(),
            tag: "attachments".to_string(),
            filename: "note.txt".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: Some(MCI_A.to_string()),
            used_for: Some(FileUsedFor {
                object_type: FileUsedForType::Message,
                id: message_id.to_string(),
            }),
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "text/plain".to_string(),
            size: 1,
            message_id: Some(message_id.to_string()),
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    /// Server S lists [P1 text, P2 forum, a dangling id]. T1 and T2 (archived
    /// and locked) hang off P1, post T3 off P2. Server S2 lists Q1, with
    /// thread U1. Returns S re-fetched, as the ban route holds a fetched one,
    /// plus T3's id.
    ///
    /// A forum post's starter message shares the post's id, so T3 is a real
    /// ULID minted now: that message has to fall inside a purge window.
    async fn mci_fixture(db: &Database) -> (Server, String) {
        let server = new_server(db, "MciOwner").await;
        let other = new_server(db, "MciOther").await;
        let t3 = Ulid::new().to_string();

        db.insert_channel(&mci_text_channel(MCI_P1, &server.id))
            .await
            .expect("P1");
        db.insert_channel(&Channel::Forum {
            id: MCI_P2.to_string(),
            server: server.id.clone(),
            name: "forum".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: Default::default(),
            nsfw: false,
            spoiler: false,
            tags: vec![],
            require_tag: false,
            default_sort: Default::default(),
            force_sort: false,
            default_auto_archive_minutes: Channel::default_forum_auto_archive_minutes(),
        })
        .await
        .expect("P2");
        db.insert_channel(&mci_text_channel(MCI_Q1, &other.id))
            .await
            .expect("Q1");

        for thread in [
            mci_thread(MCI_T1, &server.id, MCI_P1, false, false),
            mci_thread(MCI_T2, &server.id, MCI_P1, true, true),
            mci_thread(&t3, &server.id, MCI_P2, false, false),
            mci_thread(MCI_U1, &other.id, MCI_Q1, false, false),
        ] {
            db.insert_channel(&thread).await.expect("thread");
        }

        for (id, channels) in [
            (&server.id, vec![MCI_P1, MCI_P2, MCI_DANGLING]),
            (&other.id, vec![MCI_Q1]),
        ] {
            db.update_server(
                id,
                &PartialServer {
                    channels: Some(channels.into_iter().map(String::from).collect()),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("channels");
        }

        let server = db.fetch_server(&server.id).await.expect("`Server`");
        assert_eq!(server.channels, [MCI_P1, MCI_P2, MCI_DANGLING]);
        (server, t3)
    }

    /// `self.channels` leads verbatim and in order, the dangling id included,
    /// then exactly this server's threads and posts, archived and locked ones
    /// included. Another server's thread never leaks in.
    #[tokio::test]
    async fn message_channel_ids_appends_this_servers_threads_and_posts() {
        database_test!(|db| async move {
            let (server, t3) = mci_fixture(&db).await;

            let ids = server
                .message_channel_ids(&db)
                .await
                .expect("message channel ids");

            let listed = server.channels.len();
            assert!(ids.len() >= listed, "{ids:?}");
            assert_eq!(
                ids[..listed],
                server.channels[..],
                "W2A-i: server.channels must lead, verbatim and in order"
            );

            let appended: HashSet<&str> = ids[listed..].iter().map(String::as_str).collect();
            assert_eq!(
                appended,
                HashSet::from([MCI_T1, MCI_T2, t3.as_str()]),
                "W2A-i: every thread and forum post of this server must follow: {ids:?}"
            );
            assert_eq!(ids.len(), listed + 3, "W2A-i: no duplicates: {ids:?}");
            assert!(
                !ids.iter().any(|id| id == MCI_U1),
                "W2A-i: another server's thread leaked in: {ids:?}"
            );
        });
    }

    /// Composition with the ban purge, the way the ban route calls it. Only
    /// A's recent messages in this server go: in a parent channel, a thread,
    /// an archived and locked thread, and a forum starter (id = post id). The
    /// thread message's attachment is marked deleted. A's old message, B's
    /// message and A's message in another server's thread all stay, and so
    /// does the post channel itself.
    #[tokio::test]
    async fn ban_purge_over_message_channel_ids_reaches_threads_and_posts() {
        database_test!(|db| async move {
            let (server, t3) = mci_fixture(&db).await;

            let threshold = SystemTime::now() - Duration::from_secs(3600);
            let old_ms = threshold
                .duration_since(UNIX_EPOCH)
                .expect("after the epoch")
                .as_millis() as u64
                - 86_400_000;

            let mk = |id: String, channel: &str, author: &str, file: Option<File>| Message {
                id,
                channel: channel.to_string(),
                author: author.to_string(),
                content: Some("purge scope".to_string()),
                attachments: file.map(|file| vec![file]),
                ..Default::default()
            };

            let in_t1 = Ulid::new().to_string();
            let old_in_t1 = Ulid::from_parts(old_ms, 0).to_string();
            let purged_file = mci_file(MCI_FILE_PURGED, &in_t1);
            let kept_file = mci_file(MCI_FILE_KEPT, &old_in_t1);

            let purged = [
                mk(Ulid::new().to_string(), MCI_P1, MCI_A, None),
                mk(in_t1.clone(), MCI_T1, MCI_A, Some(purged_file.clone())),
                mk(Ulid::new().to_string(), MCI_T2, MCI_A, None),
                mk(t3.clone(), t3.as_str(), MCI_A, None),
            ];
            let kept = [
                mk(old_in_t1.clone(), MCI_T1, MCI_A, Some(kept_file.clone())),
                mk(Ulid::new().to_string(), MCI_T1, MCI_B, None),
                mk(Ulid::new().to_string(), MCI_U1, MCI_A, None),
            ];

            for file in [&purged_file, &kept_file] {
                db.insert_attachment(file).await.expect("attachment");
            }
            for message in purged.iter().chain(kept.iter()) {
                db.insert_message(message).await.expect("message");
            }

            Message::bulk_delete_by_author_since(
                &db,
                &server.message_channel_ids(&db).await.expect("ids"),
                MCI_A,
                threshold,
            )
            .await
            .expect("purge");

            for message in &purged {
                let error = db.fetch_message(&message.id).await.expect_err(&format!(
                    "W2A-ii: A's recent message in {} survived the purge",
                    message.channel
                ));
                assert!(matches!(error.error_type, ErrorType::NotFound), "{error:?}");
            }
            for message in &kept {
                db.fetch_message(&message.id).await.unwrap_or_else(|error| {
                    panic!(
                        "W2A-ii: out-of-scope message {} in {} was purged: {error:?}",
                        message.id, message.channel
                    )
                });
            }

            let file = db
                .fetch_attachment("attachments", MCI_FILE_PURGED)
                .await
                .expect("purged attachment row");
            assert_eq!(
                file.deleted,
                Some(true),
                "W2A-ii: the thread message's attachment must be marked deleted"
            );
            let file = db
                .fetch_attachment("attachments", MCI_FILE_KEPT)
                .await
                .expect("kept attachment row");
            assert_ne!(file.deleted, Some(true), "W2A-ii: kept attachment marked deleted");

            let post = db
                .fetch_channel(&t3)
                .await
                .expect("W2A-ii: the post channel must survive its starter's purge");
            assert!(matches!(post, Channel::Thread { .. }), "{post:?}");
        });
    }
}
