use std::collections::{HashMap, HashSet};

use futures::future::join_all;
use redis_kiss::AsyncCommands;
use revolt_database::{
    events::client::{EventV1, ReadyPayloadFields},
    util::permissions::DatabasePermissionQuery,
    util::unreads::fetch_unreads_with_summary,
    voice::{get_channel_voice_state, UserVoiceChannel},
    Channel, Database, Member, MemberCompositeKey, Presence, RelationshipStatus,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_presence::filter_online;
use revolt_result::Result;

use super::state::{Cache, State};

/// Cache Manager
impl Cache {
    /// Check whether the current user can view a channel
    pub async fn can_view_channel(&self, db: &Database, channel: &Channel) -> bool {
        #[allow(deprecated)]
        match &channel {
            Channel::TextChannel { server, .. } | Channel::Forum { server, .. } => {
                let member = self.members.get(server);
                let server = self.servers.get(server);
                let mut query =
                    DatabasePermissionQuery::new(db, self.users.get(&self.user_id).unwrap())
                        .channel(channel);
                // let mut perms = perms(self.users.get(&self.user_id).unwrap()).channel(channel);

                if let Some(member) = member {
                    query = query.member(member);
                }

                if let Some(server) = server {
                    query = query.server(server);
                }

                calculate_channel_permissions(&mut query)
                    .await
                    .has_channel_permission(ChannelPermission::ViewChannel)
            }
            Channel::Thread {
                server,
                parent_channel,
                ..
            } => {
                // A thread's visibility is exactly its parent channel's
                // visibility (text channel, or forum for forum posts).
                // Resolve the parent from cache, falling back to the
                // database, and fail closed if it is missing or is not a
                // thread-capable channel — a thread must never leak past a
                // hidden parent.
                let parent = if let Some(parent) = self.channels.get(parent_channel) {
                    parent.clone()
                } else if let Ok(parent) = db.fetch_channel(parent_channel).await {
                    parent
                } else {
                    return false;
                };

                if !matches!(
                    parent,
                    Channel::TextChannel { .. } | Channel::Forum { .. }
                ) {
                    return false;
                }

                let member = self.members.get(server);
                let server = self.servers.get(server);
                let mut query =
                    DatabasePermissionQuery::new(db, self.users.get(&self.user_id).unwrap())
                        .channel(&parent);

                if let Some(member) = member {
                    query = query.member(member);
                }

                if let Some(server) = server {
                    query = query.server(server);
                }

                calculate_channel_permissions(&mut query)
                    .await
                    .has_channel_permission(ChannelPermission::ViewChannel)
            }
            _ => true,
        }
    }

    /// Filter a given vector of channels to only include the ones we can access
    pub async fn filter_accessible_channels(
        &self,
        db: &Database,
        channels: Vec<Channel>,
    ) -> Vec<Channel> {
        let mut viewable_channels = vec![];
        for channel in channels {
            if self.can_view_channel(db, &channel).await {
                viewable_channels.push(channel);
            }
        }

        viewable_channels
    }

    /// Check whether we can subscribe to another user
    pub fn can_subscribe_to_user(&self, user_id: &str) -> bool {
        if let Some(user) = self.users.get(&self.user_id) {
            match user.relationship_with(user_id) {
                RelationshipStatus::Friend
                | RelationshipStatus::Incoming
                | RelationshipStatus::Outgoing
                | RelationshipStatus::User => true,
                _ => {
                    let user_id = &user_id.to_string();
                    for channel in self.channels.values() {
                        match channel {
                            Channel::DirectMessage { recipients, .. }
                            | Channel::Group { recipients, .. } => {
                                if recipients.contains(user_id) {
                                    return true;
                                }
                            }
                            _ => {}
                        }
                    }

                    false
                }
            }
        } else {
            false
        }
    }
}

/// State Manager
impl State {
    /// Generate a Ready packet for the current user
    pub async fn generate_ready_payload(
        &mut self,
        db: &Database,
        fields: &ReadyPayloadFields,
    ) -> Result<EventV1> {
        let user = self.clone_user();
        self.cache.is_bot = user.bot.is_some();

        // Fetch pending policy changes.
        let policy_changes = if user.bot.is_some() || !fields.policy_changes {
            None
        } else {
            Some(
                db.fetch_policy_changes()
                    .await?
                    .into_iter()
                    .filter(|policy| policy.created_time > user.last_acknowledged_policy_change)
                    .map(Into::into)
                    .collect(),
            )
        };

        // Find all relationships to the user.
        let mut user_ids: HashSet<String> = user
            .relations
            .as_ref()
            .map(|arr| arr.iter().map(|x| x.id.to_string()).collect())
            .unwrap_or_default();

        // Fetch all memberships with their corresponding servers.
        let mut members: Vec<Member> = db.fetch_all_memberships(&user.id).await?;

        let server_ids: Vec<String> = members.iter().map(|x| x.id.server.clone()).collect();
        let servers = db.fetch_servers(&server_ids).await?;
        self.cache.servers = servers.iter().cloned().map(|x| (x.id.clone(), x)).collect();

        // Collect channel ids from servers.
        let mut channel_ids = vec![];
        for server in &servers {
            channel_ids.append(&mut server.channels.clone());
        }

        // Fetch DMs and server channels.
        let mut channels = db.find_direct_messages(&user.id).await?;
        channels.append(&mut db.fetch_channels(&channel_ids).await?);

        // Filter server channels by permission.
        let mut channels = self.cache.filter_accessible_channels(db, channels).await;

        // Append known user IDs from DMs.
        for channel in &channels {
            match channel {
                Channel::DirectMessage { recipients, .. } | Channel::Group { recipients, .. } => {
                    user_ids.extend(&mut recipients.clone().into_iter());
                }
                _ => {}
            }
        }

        let voice_states = if fields.voice_states {
            let mut voice_state_server_members: HashMap<String, HashSet<String>> = HashMap::new();

            // fetch voice states for all the channels we can see
            let mut voice_states = Vec::new();

            for channel in channels.iter().filter(|c| {
                matches!(
                    c,
                    Channel::DirectMessage { .. }
                        | Channel::Group { .. }
                        | Channel::TextChannel { voice: Some(_), .. }
                )
            }) {
                if let Ok(Some(voice_state)) =
                    get_channel_voice_state(&UserVoiceChannel::from_channel(channel)).await
                {
                    if let Some(server) = channel.server() {
                        let set = voice_state_server_members
                            .entry(server.to_string())
                            .or_default();

                        for participant in &voice_state.participants {
                            user_ids.insert(participant.id.clone());
                            set.insert(participant.id.clone());
                        }
                    } else {
                        for participant in &voice_state.participants {
                            user_ids.insert(participant.id.clone());
                        }
                    }

                    voice_states.push(voice_state);
                }
            }

            // Fetch all the members for for the participants who are in a server
            for (server, user_ids) in voice_state_server_members {
                let user_ids = user_ids.into_iter().collect::<Vec<_>>();
                let voice_members = db.fetch_members(&server, &user_ids).await?;

                members.extend(voice_members);
            }

            Some(voice_states)
        } else {
            None
        };

        // Fetch presence data for known users.
        let online_ids = filter_online(&user_ids.iter().cloned().collect::<Vec<String>>()).await;

        // Fetch user data.
        let users = db
            .fetch_users(
                &user_ids
                    .into_iter()
                    .filter(|x| x != &user.id)
                    .collect::<Vec<String>>(),
            )
            .await?;

        self.cache.members = members
            .iter()
            .cloned()
            .map(|x| (x.id.server.clone(), x))
            .collect();

        // Fetch customisations.
        let server_ids: Vec<String> = servers.iter().map(|x| x.id.to_string()).collect();

        let emojis = if fields.emojis {
            Some(
                db.fetch_emoji_by_parent_ids(&server_ids)
                    .await?
                    .into_iter()
                    .map(|emoji| emoji.into())
                    .collect(),
            )
        } else {
            None
        };

        let stickers = if fields.emojis {
            Some(
                db.fetch_stickers_by_server_ids(&server_ids)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.into())
                    .collect(),
            )
        } else {
            None
        };

        // Fetch user settings
        let user_settings = if !fields.user_settings.is_empty() {
            Some(
                db.fetch_user_settings(&user.id, &fields.user_settings)
                    .await?,
            )
        } else {
            None
        };

        // Fetch channel unreads, each stamped with its unread-tail summary so
        // the sidebar can draw a count rather than a bare dot
        let channel_unreads = if fields.channel_unreads {
            Some(fetch_unreads_with_summary(db, &user.id).await?)
        } else {
            None
        };

        // Include threads the user has joined so they are re-subscribed and
        // rendered on reconnect. Threads are not part of `Server.channels`, so
        // they are not fetched with the server's channels above; `members` is
        // now cached, so the visibility filter has the user's roles in context.
        let mut joined_thread_ids: Vec<String> = vec![];
        for server in &servers {
            if let Ok(ids) = db.fetch_joined_thread_ids(&user.id, &server.id).await {
                joined_thread_ids.extend(ids);
            }
        }
        if !joined_thread_ids.is_empty() {
            if let Ok(threads) = db.fetch_channels(&joined_thread_ids).await {
                let viewable = self.cache.filter_accessible_channels(db, threads).await;
                channels.extend(viewable);
            }
        }

        // Copy data into local state cache.
        self.cache.users = users.iter().cloned().map(|x| (x.id.clone(), x)).collect();
        self.cache
            .users
            .insert(self.cache.user_id.clone(), user.clone());
        self.cache.channels = channels
            .iter()
            .cloned()
            .map(|x| (x.id().to_string(), x))
            .collect();

        // Make all users appear from our perspective.
        let mut users: Vec<v0::User> = join_all(users.into_iter().map(|other_user| async {
            let is_online = online_ids.contains(&other_user.id);
            other_user.into_known(&user, is_online).await
        }))
        .await;

        // Make sure we see our own user correctly.
        users.push(user.into_self(true).await);

        // Set subscription state internally.
        self.reset_state().await;
        self.insert_subscription(self.private_topic.clone()).await;

        for user in &users {
            self.insert_subscription(user.id.clone()).await;
        }

        for server in &servers {
            self.insert_subscription(server.id.clone()).await;

            if self.cache.is_bot {
                self.insert_subscription(format!("{}u", server.id)).await;
            }
        }

        for channel in &channels {
            self.insert_subscription(channel.id().to_string()).await;
        }

        Ok(EventV1::Ready {
            users: if fields.users { Some(users) } else { None },
            servers: if fields.servers {
                Some(servers.into_iter().map(Into::into).collect())
            } else {
                None
            },
            channels: if fields.channels {
                Some(channels.into_iter().map(Into::into).collect())
            } else {
                None
            },
            members: if fields.members {
                Some(members.into_iter().map(Into::into).collect())
            } else {
                None
            },
            voice_states,

            emojis,
            stickers,
            user_settings,
            channel_unreads,

            policy_changes,
        })
    }

    /// Re-determine the currently accessible server channels
    pub async fn recalculate_server(&mut self, db: &Database, id: &str, event: &mut EventV1) {
        if let Some(server) = self.cache.servers.get(id) {
            let mut channel_ids = HashSet::new();
            let mut added_channels = vec![];
            let mut removed_channels = vec![];

            let id = &id.to_string();
            for (channel_id, channel) in &self.cache.channels {
                if channel.server() == Some(id) {
                    channel_ids.insert(channel_id.clone());

                    if self.cache.can_view_channel(db, channel).await {
                        added_channels.push(channel_id.clone());
                    } else {
                        removed_channels.push(channel_id.clone());
                    }
                }
            }

            let known_ids = server.channels.iter().cloned().collect::<HashSet<String>>();

            let mut bulk_events = vec![];

            for id in added_channels {
                self.insert_subscription(id).await;
            }

            for id in removed_channels {
                self.remove_subscription(&id).await;
                self.cache.channels.remove(&id);

                bulk_events.push(EventV1::ChannelDelete { id });
            }

            // * NOTE: currently all channels should be cached
            // * provided that a server was loaded from payload
            let unknowns = known_ids
                .difference(&channel_ids)
                .cloned()
                .collect::<Vec<String>>();

            if !unknowns.is_empty() {
                if let Ok(channels) = db.fetch_channels(&unknowns).await {
                    let viewable_channels =
                        self.cache.filter_accessible_channels(db, channels).await;

                    for channel in viewable_channels {
                        self.cache
                            .channels
                            .insert(channel.id().to_string(), channel.clone());

                        self.insert_subscription(channel.id().to_string()).await;
                        bulk_events.push(EventV1::ChannelCreate(channel.into()));
                    }
                }
            }

            if !bulk_events.is_empty() {
                let mut new_event = EventV1::Bulk { v: bulk_events };
                std::mem::swap(&mut new_event, event);

                if let EventV1::Bulk { v } = event {
                    v.push(new_event);
                }
            }
        }
    }

    /// Push presence change to the user and all associated server topics
    pub async fn broadcast_presence_change(&self, target: bool) {
        let config = revolt_config::config().await;
        if config.disable_events_dont_use {
            return;
        }

        if if let Some(status) = &self.cache.users.get(&self.cache.user_id).unwrap().status {
            status.presence != Some(Presence::Invisible)
        } else {
            true
        } {
            let event = EventV1::UserUpdate {
                id: self.cache.user_id.clone(),
                data: v0::PartialUser {
                    online: Some(target),
                    ..Default::default()
                },
                clear: vec![],
                event_id: Some(ulid::Ulid::new().to_string()),
            };

            for server in self.cache.servers.keys() {
                event.clone().p(server.clone()).await;
            }

            event.p(self.cache.user_id.clone()).await;
        }
    }

    /// Handle an incoming event for protocol version 1
    pub async fn handle_incoming_event_v1(&mut self, db: &Database, event: &mut EventV1) -> bool {
        /* Superseded by private topics.
          if match event {
            EventV1::UserRelationship { id, .. }
            | EventV1::UserSettingsUpdate { id, .. }
            | EventV1::ChannelAck { id, .. } => id != &self.cache.user_id,
            EventV1::ServerCreate { server, .. } => server.owner != self.cache.user_id,
            EventV1::ChannelCreate(channel) => match channel {
                Channel::SavedMessages { user, .. } => user != &self.cache.user_id,
                Channel::DirectMessage { recipients, .. } | Channel::Group { recipients, .. } => {
                    !recipients.contains(&self.cache.user_id)
                }
                _ => false,
            },
            _ => false,
        } {
            return false;
        }*/

        // An event may trigger recalculation of an entire server's permission.
        // Keep track of whether we need to do anything.
        let mut queue_server = None;

        // It may also need to sub or unsub a single value.
        let mut queue_add = None;
        let mut queue_remove = None;

        match event {
            EventV1::ChannelCreate(channel) => {
                let db_channel: Channel = channel.clone().into();
                let id = db_channel.id().to_string();

                // Threads are announced to the entire server topic. Only
                // subscribe (and forward the event) if we can view the parent
                // channel — otherwise a member denied ViewChannel on a private
                // parent would receive the thread and all of its messages.
                // Other channel types retain their existing behaviour.
                let can_view = if matches!(db_channel, Channel::Thread { .. }) {
                    self.cache.can_view_channel(db, &db_channel).await
                } else {
                    true
                };

                self.cache.channels.insert(id.clone(), db_channel);

                if can_view {
                    self.insert_subscription(id).await;
                } else {
                    return false;
                }
            }
            EventV1::ChannelUpdate {
                id, data, clear, ..
            } => {
                let could_view: bool = if let Some(channel) = self.cache.channels.get(id) {
                    self.cache.can_view_channel(db, channel).await
                } else {
                    false
                };

                // Capture each child thread's prior visibility BEFORE the parent
                // is mutated — a parent permission change must propagate to the
                // threads that delegate their permissions to it, or a newly
                // denied user keeps live thread subscriptions until reconnect.
                let mut thread_prior: Vec<(String, bool)> = vec![];
                for (child_id, channel) in &self.cache.channels {
                    if matches!(channel, Channel::Thread { parent_channel, .. } if parent_channel == id)
                    {
                        thread_prior
                            .push((child_id.clone(), self.cache.can_view_channel(db, channel).await));
                    }
                }

                if let Some(channel) = self.cache.channels.get_mut(id) {
                    for field in clear {
                        channel.remove_field(&field.clone().into());
                    }

                    channel.apply_options(data.clone().into());
                }

                if !self.cache.channels.contains_key(id) {
                    if let Ok(channel) = db.fetch_channel(id).await {
                        self.cache.channels.insert(id.clone(), channel);
                    }
                }

                if let Some(channel) = self.cache.channels.get(id) {
                    let can_view = self.cache.can_view_channel(db, channel).await;
                    if could_view != can_view {
                        if can_view {
                            queue_add = Some(id.clone());
                            *event = EventV1::ChannelCreate(channel.clone().into());
                        } else {
                            queue_remove = Some(id.clone());
                            *event = EventV1::ChannelDelete { id: id.clone() };
                        }
                    } else if !can_view {
                        // Hidden before AND after the update: drop the event
                        // entirely — ChannelUpdate is published to the server
                        // topic, so without this a member denied ViewChannel
                        // receives hidden-channel metadata (renames,
                        // description edits) over their socket.
                        return false;
                    }
                } else {
                    // The channel cannot be resolved at all; fail closed
                    // rather than forwarding an update we cannot authorise.
                    return false;
                }

                // Propagate the parent's (possibly) changed visibility to its
                // child threads, emitting synthetic ChannelCreate/Delete so the
                // client's cache and subscriptions stay correct.
                let mut thread_events: Vec<EventV1> = vec![];
                for (thread_id, could_view) in thread_prior {
                    let can_view = if let Some(channel) = self.cache.channels.get(&thread_id) {
                        self.cache.can_view_channel(db, channel).await
                    } else {
                        false
                    };

                    if could_view != can_view {
                        if can_view {
                            self.insert_subscription(thread_id.clone()).await;
                            if let Some(channel) = self.cache.channels.get(&thread_id) {
                                thread_events.push(EventV1::ChannelCreate(channel.clone().into()));
                            }
                        } else {
                            self.remove_subscription(&thread_id).await;
                            thread_events.push(EventV1::ChannelDelete { id: thread_id.clone() });
                        }
                    }
                }

                if !thread_events.is_empty() {
                    let mut new_event = EventV1::Bulk { v: thread_events };
                    std::mem::swap(&mut new_event, event);

                    if let EventV1::Bulk { v } = event {
                        v.push(new_event);
                    }
                }
            }
            EventV1::ChannelDelete { id } => {
                self.remove_subscription(id).await;
                self.cache.channels.remove(id);
            }
            EventV1::ChannelGroupJoin { user, .. } => {
                self.insert_subscription(user.clone()).await;
            }
            EventV1::ChannelGroupLeave { id, user, .. } => {
                if user == &self.cache.user_id {
                    self.remove_subscription(id).await;
                } else if !self.cache.can_subscribe_to_user(user) {
                    self.remove_subscription(user).await;
                }
            }

            EventV1::ServerCreate {
                id,
                server,
                channels,
                emojis: _,
                stickers: _,
                voice_states: _,
            } => {
                self.insert_subscription(id.clone()).await;

                if self.cache.is_bot {
                    self.insert_subscription(format!("{}u", id)).await;
                }

                self.cache.servers.insert(id.clone(), server.clone().into());
                let member = Member {
                    id: MemberCompositeKey {
                        server: server.id.clone(),
                        user: self.cache.user_id.clone(),
                    },
                    ..Default::default()
                };
                self.cache.members.insert(id.clone(), member);

                for channel in channels {
                    self.cache
                        .channels
                        .insert(channel.id().to_string(), channel.clone().into());
                }

                queue_server = Some(id.clone());
            }
            EventV1::ServerUpdate {
                id, data, clear, ..
            } => {
                if let Some(server) = self.cache.servers.get_mut(id) {
                    for field in clear {
                        server.remove_field(&field.clone().into());
                    }

                    server.apply_options(data.clone().into());
                }

                if data.default_permissions.is_some() {
                    queue_server = Some(id.clone());
                }
            }
            EventV1::ServerMemberJoin { .. } => {
                // We will always receive ServerCreate when joining a new server.
            }
            EventV1::ServerMemberLeave { id, user, .. } => {
                if user == &self.cache.user_id {
                    self.remove_subscription(id).await;

                    if let Some(server) = self.cache.servers.remove(id) {
                        for channel in &server.channels {
                            self.remove_subscription(channel).await;
                            self.cache.channels.remove(channel);
                        }
                    }
                    self.cache.members.remove(id);
                }
            }
            EventV1::ServerDelete { id } => {
                self.remove_subscription(id).await;

                if let Some(server) = self.cache.servers.remove(id) {
                    for channel in &server.channels {
                        self.remove_subscription(channel).await;
                        self.cache.channels.remove(channel);
                    }
                }
                self.cache.members.remove(id);
            }
            EventV1::ServerMemberUpdate { id, data, clear } => {
                if id.user == self.cache.user_id {
                    if let Some(member) = self.cache.members.get_mut(&id.server) {
                        for field in &clear.clone() {
                            member.remove_field(&field.clone().into());
                        }

                        member.apply_options(data.clone().into());
                    }

                    if data.roles.is_some() || clear.contains(&v0::FieldsMember::Roles) {
                        queue_server = Some(id.server.clone());
                    }
                }
            }
            EventV1::ServerRoleUpdate {
                id,
                role_id,
                data,
                clear,
                ..
            } => {
                if let Some(server) = self.cache.servers.get_mut(id) {
                    if let Some(role) = server.roles.get_mut(role_id) {
                        for field in &clear.clone() {
                            role.remove_field(&field.clone().into());
                        }

                        role.apply_options(data.clone().into());
                    }
                }

                if data.rank.is_some() || data.permissions.is_some() {
                    if let Some(member) = self.cache.members.get(id) {
                        if member.roles.contains(role_id) {
                            queue_server = Some(id.clone());
                        }
                    }
                }
            }
            EventV1::ServerRoleDelete { id, role_id } => {
                if let Some(server) = self.cache.servers.get_mut(id) {
                    server.roles.remove(role_id);
                }

                if let Some(member) = self.cache.members.get(id) {
                    if member.roles.contains(role_id) {
                        queue_server = Some(id.clone());
                    }
                }
            }

            EventV1::UserUpdate { event_id, .. } => {
                if let Some(id) = event_id {
                    if self.cache.seen_events.contains(id) {
                        return false;
                    }

                    self.cache.seen_events.put(id.to_string(), ());
                }

                *event_id = None;
            }
            EventV1::UserRelationship { id, user, .. } => {
                self.cache.users.insert(id.clone(), user.clone().into());

                if self.cache.can_subscribe_to_user(id) {
                    self.insert_subscription(id.clone()).await;
                } else {
                    self.remove_subscription(id).await;
                }
            }

            EventV1::Message(message) => {
                // Since Message events are fanned out to many clients,
                // we must reconstruct the relationship value at this end.
                if let Some(user) = &mut message.user {
                    user.relationship = self
                        .cache
                        .users
                        .get(&self.cache.user_id)
                        .expect("missing self?")
                        .relationship_with(&message.author)
                        .into();
                }
            }

            _ => {}
        }

        // Calculate server permissions if requested.
        if let Some(server_id) = queue_server {
            self.recalculate_server(db, &server_id, event).await;
        }

        // Sub / unsub accordingly.
        if let Some(id) = queue_add {
            self.insert_subscription(id).await;
        }

        if let Some(id) = queue_remove {
            self.remove_subscription(&id).await;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use revolt_database::{
        events::client::EventV1, Channel, DatabaseInfo, Member, MemberCompositeKey, Server, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use std::collections::HashMap;

    use super::super::state::State;

    /// Build a state for `user` who is a plain (role-less) member of `server`.
    fn member_state(user: User, server: &Server) -> State {
        let mut state = State::from(user, "session".to_string());
        state.cache.servers.insert(server.id.clone(), server.clone());
        state.cache.members.insert(
            server.id.clone(),
            Member {
                id: MemberCompositeKey {
                    server: server.id.clone(),
                    user: state.cache.user_id.clone(),
                },
                ..Default::default()
            },
        );
        state
    }

    /// A ChannelUpdate for a channel the member cannot view — before or
    /// after the update — must be dropped, not forwarded: it is published
    /// to the server topic and would otherwise leak hidden-channel
    /// metadata (renames, description edits) to denied members' sockets.
    #[tokio::test]
    async fn hidden_channel_update_is_dropped_for_denied_member() {
        let db = DatabaseInfo::Test("bonfire_hidden_channel_update".to_string())
            .connect()
            .await
            .expect("database");

        let member_user = User {
            id: "01USER000000000000000MEMBER".to_string(),
            username: "member".to_string(),
            ..Default::default()
        };

        let server = Server {
            id: "01SERVER00000000000000000A".to_string(),
            owner: "01USER0000000000000000OWNER".to_string(),
            name: "server".to_string(),
            description: None,
            channels: vec![
                "01CHANNEL000000000000HIDDEN".to_string(),
                "01CHANNEL00000000000VISIBLE".to_string(),
            ],
            categories: None,
            system_messages: None,
            roles: HashMap::new(),
            default_permissions: ChannelPermission::ViewChannel as i64,
            icon: None,
            banner: None,
            flags: None,
            nsfw: false,
            analytics: false,
            discoverable: false,
            discovery_requested: false,
            boost_count: None,
            boost_tier: None,
        };

        // Hidden: channel override denies ViewChannel for everyone.
        let hidden = Channel::TextChannel {
            id: "01CHANNEL000000000000HIDDEN".to_string(),
            server: server.id.clone(),
            name: "hidden".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: Some(OverrideField {
                a: 0,
                d: ChannelPermission::ViewChannel as i64,
            }),
            role_permissions: HashMap::new(),
            nsfw: false,
            voice: None,
            slowmode: None,
            announcement: None,
        };
        db.insert_channel(&hidden).await.expect("insert hidden");

        let visible = Channel::TextChannel {
            id: "01CHANNEL00000000000VISIBLE".to_string(),
            server: server.id.clone(),
            name: "visible".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            voice: None,
            slowmode: None,
            announcement: None,
        };
        db.insert_channel(&visible).await.expect("insert visible");

        // The denied member's Ready excluded the hidden channel, so it is
        // NOT in their cache; bonfire resolves it from the database.
        let mut state = member_state(member_user, &server);
        state
            .cache
            .channels
            .insert(visible.id().to_string(), visible.clone());

        let mut event = EventV1::ChannelUpdate {
            id: hidden.id().to_string(),
            data: v0::PartialChannel {
                name: Some("renamed secret".to_string()),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(
            !state.handle_incoming_event_v1(&db, &mut event).await,
            "hidden-channel update must be dropped for a denied member"
        );

        // Control: an update to a channel the member CAN view is forwarded
        // untouched.
        let mut event = EventV1::ChannelUpdate {
            id: visible.id().to_string(),
            data: v0::PartialChannel {
                name: Some("renamed public".to_string()),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "visible-channel update must still be forwarded"
        );
        assert!(
            matches!(event, EventV1::ChannelUpdate { .. }),
            "forwarded event must remain a ChannelUpdate"
        );
    }
}
