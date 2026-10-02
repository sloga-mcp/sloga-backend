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
use revolt_result::{ErrorType, Result};

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
    ///
    /// A cached server channel is subscribed exactly when the client has been
    /// told about it, so the subscription set is the prior visibility. Hidden
    /// channels stay cached unsubscribed: a thread created under a hidden
    /// parent is cached that way by `ChannelCreate`, and since threads are not
    /// in `Server.channels`, the cache is the only place a later grant can
    /// find it.
    pub async fn recalculate_server(&mut self, db: &Database, id: &str, event: &mut EventV1) {
        if let Some(server) = self.cache.servers.get(id) {
            let mut channel_ids = HashSet::new();
            let mut revealed_channels = vec![];
            let mut hidden_channels = vec![];

            let id = &id.to_string();
            let prior: Vec<(String, bool)> = {
                let subscribed = self.subscribed.read().await;
                self.cache
                    .channels
                    .iter()
                    .filter(|(_, channel)| channel.server() == Some(id))
                    .map(|(channel_id, _)| (channel_id.clone(), subscribed.contains(channel_id)))
                    .collect()
            };

            // A thread is visible exactly when its parent is, and an uncached
            // parent costs a database read, so resolve each parent once.
            let mut parent_visibility: HashMap<String, bool> = HashMap::new();
            for (channel_id, could_view) in prior {
                let Some(channel) = self.cache.channels.get(&channel_id) else {
                    continue;
                };

                let can_view = match channel {
                    Channel::Thread { parent_channel, .. } => {
                        match parent_visibility.get(parent_channel) {
                            Some(can_view) => *can_view,
                            None => {
                                let can_view = self.cache.can_view_channel(db, channel).await;
                                parent_visibility.insert(parent_channel.clone(), can_view);
                                can_view
                            }
                        }
                    }
                    _ => self.cache.can_view_channel(db, channel).await,
                };

                if can_view && !could_view {
                    revealed_channels.push(channel_id.clone());
                } else if could_view && !can_view {
                    hidden_channels.push(channel_id.clone());
                }
                channel_ids.insert(channel_id);
            }

            let known_ids = server.channels.iter().cloned().collect::<HashSet<String>>();

            let mut bulk_events = vec![];
            let revealed_events = self.reveal_channels(db, revealed_channels).await;

            for id in hidden_channels {
                self.remove_subscription(&id).await;
                bulk_events.push(EventV1::ChannelDelete { id });
            }

            // Server channels the member could not see at Ready or at
            // ChannelCreate are not cached; they are picked up here.
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

            // After the unknowns, which are where a revealed thread's parent
            // usually comes from.
            bulk_events.extend(revealed_events);

            if !bulk_events.is_empty() {
                let mut new_event = EventV1::Bulk { v: bulk_events };
                std::mem::swap(&mut new_event, event);

                if let EventV1::Bulk { v } = event {
                    v.push(new_event);
                }
            }
        }
    }

    /// Subscribe to cached channels the client has not been told about, and
    /// return the ChannelCreates that tell it, top-level channels before
    /// threads so a thread never arrives ahead of its parent.
    ///
    /// Re-reads the channels first, in one query: a thread deleted while
    /// hidden publishes its ChannelDelete only to its own topic, which we were
    /// not subscribed to, so a cached copy may be a ghost. Channels the read
    /// does not return are dropped from the cache. If the read fails, nothing
    /// is revealed and the next recalculation tries again.
    async fn reveal_channels(&mut self, db: &Database, ids: Vec<String>) -> Vec<EventV1> {
        if ids.is_empty() {
            return vec![];
        }

        let mut fresh: HashMap<String, Channel> = match db.fetch_channels(&ids).await {
            Ok(channels) => channels
                .into_iter()
                .map(|channel| (channel.id().to_string(), channel))
                .collect(),
            // The reference driver fails the whole read when one id is
            // missing; find the survivors one at a time.
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
                let mut channels = HashMap::new();
                for id in &ids {
                    if let Ok(channel) = db.fetch_channel(id).await {
                        channels.insert(id.clone(), channel);
                    }
                }
                channels
            }
            Err(_) => return vec![],
        };

        let mut events = vec![];
        let mut thread_events = vec![];
        for id in ids {
            let Some(channel) = fresh.remove(&id) else {
                self.cache.channels.remove(&id);
                continue;
            };

            let can_view = self.cache.can_view_channel(db, &channel).await;
            self.cache.channels.insert(id.clone(), channel.clone());
            if !can_view {
                continue;
            }

            self.insert_subscription(id).await;
            if matches!(channel, Channel::Thread { .. }) {
                thread_events.push(EventV1::ChannelCreate(channel.into()));
            } else {
                events.push(EventV1::ChannelCreate(channel.into()));
            }
        }

        events.extend(thread_events);
        events
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

    /// Drop every cached thread / forum post of `server_id`. They are never listed in
    /// `Server.channels`, so the per-channel loops in the leave / delete arms would
    /// leave them subscribed: Ready subscribes joined threads, and `ChannelCreate`
    /// caches a thread even when it is not viewable.
    ///
    /// Matches on `Channel::server()` rather than on the `Thread` variant, so any
    /// other cached channel of the server that is missing from `Server.channels`
    /// goes too. Ids are collected first, since unsubscribing needs `&mut self`.
    async fn drop_server_threads(&mut self, server_id: &str) {
        let ids: Vec<String> = self
            .cache
            .channels
            .iter()
            .filter(|(_, channel)| channel.server() == Some(server_id))
            .map(|(id, _)| id.clone())
            .collect();

        for id in ids {
            self.remove_subscription(&id).await;
            self.cache.channels.remove(&id);
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

                // Server channels and threads are announced to the entire
                // server topic. Only subscribe (and forward the event) if we
                // can view the channel (a thread: its parent). A new channel
                // has no overrides, so on a server whose default permissions
                // lack ViewChannel every member without a granting role would
                // otherwise receive it and all of its messages. DMs, groups
                // and saved messages are always viewable here.
                if self.cache.can_view_channel(db, &db_channel).await {
                    self.cache.channels.insert(id.clone(), db_channel);
                    self.insert_subscription(id).await;
                } else {
                    // A hidden thread stays cached: threads are not in
                    // `Server.channels`, so the cache is the only place a
                    // later grant can find it. A hidden server channel is
                    // left uncached, as Ready leaves it; recalculate_server
                    // finds it in `Server.channels` as an unknown once it
                    // becomes visible. (A later ChannelUpdate may cache it;
                    // both states are handled there.)
                    if matches!(db_channel, Channel::Thread { .. }) {
                        self.cache.channels.insert(id, db_channel);
                    }

                    return false;
                }
            }
            EventV1::ChannelUpdate {
                id, data, clear, ..
            } => {
                // For a server channel, whether the client was told about it
                // (see recalculate_server); it can be cached while hidden.
                let could_view: bool = match self.cache.channels.get(id) {
                    Some(channel) if channel.server().is_some() => {
                        self.subscribed.read().await.contains(id)
                    }
                    Some(channel) => self.cache.can_view_channel(db, channel).await,
                    None => false,
                };

                // Capture each child thread's prior visibility BEFORE the parent
                // is mutated — a parent permission change must propagate to the
                // threads that delegate their permissions to it, or a newly
                // denied user keeps live thread subscriptions until reconnect.
                //
                // Prior visibility is whether the client was told about the
                // thread (it is subscribed exactly then), not a permission
                // check: a hidden parent is usually uncached, and resolving it
                // from the database would read the already-updated row.
                let mut thread_prior: Vec<(String, bool)> = vec![];
                {
                    let subscribed = self.subscribed.read().await;
                    for (child_id, channel) in &self.cache.channels {
                        if matches!(channel, Channel::Thread { parent_channel, .. } if parent_channel == id)
                        {
                            thread_prior.push((child_id.clone(), subscribed.contains(child_id)));
                        }
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
                let mut revealed_threads = vec![];
                for (thread_id, could_view) in thread_prior {
                    let can_view = if let Some(channel) = self.cache.channels.get(&thread_id) {
                        self.cache.can_view_channel(db, channel).await
                    } else {
                        false
                    };

                    if could_view != can_view {
                        if can_view {
                            revealed_threads.push(thread_id);
                        } else {
                            self.remove_subscription(&thread_id).await;
                            thread_events.push(EventV1::ChannelDelete { id: thread_id.clone() });
                        }
                    }
                }
                thread_events.extend(self.reveal_channels(db, revealed_threads).await);

                // The parent's own event goes first, so a revealed thread
                // never reaches the client ahead of its parent.
                if !thread_events.is_empty() {
                    let parent_event = std::mem::replace(event, EventV1::Bulk { v: vec![] });
                    let mut v = vec![parent_event];
                    v.extend(thread_events);
                    *event = EventV1::Bulk { v };
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

                // The carried channels are already filtered to the ones we
                // can view, and the client learns them from this event, so
                // subscribe them now; recalculate_server would otherwise see
                // them as newly revealed and announce each one twice.
                for channel in channels {
                    let channel: Channel = channel.clone().into();
                    let channel_id = channel.id().to_string();
                    self.cache.channels.insert(channel_id.clone(), channel);
                    self.insert_subscription(channel_id).await;
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
                    // Outside the block above: threads can be cached for a
                    // server that is not.
                    self.drop_server_threads(id).await;
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
                self.drop_server_threads(id).await;
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

            // Thread membership events are published to the server topic, so
            // every member receives them. Our own join is also where a thread
            // joined mid-session gets subscribed: Ready only subscribes the
            // threads joined before it.
            EventV1::ThreadMemberJoin { id, user } if *user == self.cache.user_id => {
                // Own statement: the read guard must be released before
                // reveal_channels takes the write lock to subscribe.
                let already = self.subscribed.read().await.contains(id.as_str());
                if !already {
                    // Only a thread can be revealed by a join. Checked before
                    // reveal_channels, which caches and subscribes; removing
                    // the subscription afterwards would still leave a Redis
                    // SUBSCRIBE queued.
                    match db.fetch_channel(id).await {
                        Ok(Channel::Thread { .. }) => {}
                        _ => return false,
                    }

                    // Visibility comes from the parent. A hidden or deleted
                    // thread is neither subscribed nor announced.
                    let revealed = self.reveal_channels(db, vec![id.clone()]).await;
                    if revealed.is_empty() {
                        return false;
                    }

                    // The client drops membership events for channels it has
                    // not cached, so the ChannelCreate goes first.
                    let original = std::mem::replace(event, EventV1::Bulk { v: vec![] });
                    let mut v = revealed;
                    v.push(original);
                    *event = EventV1::Bulk { v };
                }
            }
            // Anyone else's membership change, and our own leave, is only
            // forwarded for a thread the client was told about (it is then
            // subscribed); otherwise a hidden thread's id and members leak.
            // Our own leave keeps the subscription, as for a visible thread we
            // never joined, so an open view keeps updating.
            EventV1::ThreadMemberJoin { id, .. } | EventV1::ThreadMemberLeave { id, .. } => {
                let subscribed_now = self.subscribed.read().await.contains(id.as_str());
                if !subscribed_now {
                    return false;
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
        events::client::EventV1, Channel, Database, DatabaseInfo, Member, MemberCompositeKey,
        PartialChannel, Role, Server, User,
    };
    use revolt_models::v0::{self, RemovalIntention};
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
        let db = test_db().await;

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
            voice_region: None,
            boost_count: None,
            boost_tier: None,
            afk_channel_id: None,
            afk_timeout: None,
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
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
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
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
        };
        db.insert_channel(&visible).await.expect("insert visible");

        // The denied member's Ready excluded the hidden channel, so it is
        // NOT in their cache; bonfire resolves it from the database.
        // Ready caches and subscribes the visible channel.
        let mut state = member_state(member_user, &server);
        state
            .cache
            .channels
            .insert(visible.id().to_string(), visible.clone());
        state.insert_subscription(visible.id().to_string()).await;
        state.apply_state().await;

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

    const SELF_ID: &str = "01USER00000000000000000SELF";
    const OTHER_ID: &str = "01USER0000000000000000OTHER";
    const SERVER_S: &str = "01SERVER00000000000000000S";
    const SERVER_X: &str = "01SERVER00000000000000000X";
    /// Text channel of S, listed in `S.channels`.
    const TEXT_S: &str = "01CHANNEL0000000000000TEXTS";
    /// Thread of S. Threads are never listed in `Server.channels`.
    const THREAD_S: &str = "01CHANNEL00000000000THREADS";
    /// Text channel of X, the parent of `THREAD_X`.
    const TEXT_X: &str = "01CHANNEL0000000000000TEXTX";
    /// Thread of another server X; must survive leaving S.
    const THREAD_X: &str = "01CHANNEL00000000000THREADX";

    fn plain_server(id: &str, channels: &[&str]) -> Server {
        Server {
            id: id.to_string(),
            owner: OTHER_ID.to_string(),
            name: "server".to_string(),
            description: None,
            channels: channels.iter().map(|c| c.to_string()).collect(),
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
            voice_region: None,
            boost_count: None,
            boost_tier: None,
            afk_channel_id: None,
            afk_timeout: None,
        }
    }

    fn text_channel(id: &str, server: &str) -> Channel {
        Channel::TextChannel {
            id: id.to_string(),
            server: server.to_string(),
            name: "text".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
        }
    }

    fn thread(id: &str, server: &str, parent_channel: &str) -> Channel {
        Channel::Thread {
            id: id.to_string(),
            server: server.to_string(),
            parent_channel: parent_channel.to_string(),
            name: "thread".to_string(),
            creator: OTHER_ID.to_string(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: Channel::default_auto_archive_minutes(),
            locked: false,
            applied_tags: vec![],
        }
    }

    /// A member of S and X with the text channel and a thread of S, plus a
    /// thread of X, cached and subscribed. With `cache_server_s` false, S
    /// itself is absent from `cache.servers` while its thread stays cached.
    ///
    /// `State::from` starts in `Reset`, where `remove_subscription` panics,
    /// so the seeded subscriptions are flushed with `apply_state` first.
    async fn seeded_state(cache_server_s: bool) -> State {
        let user = User {
            id: SELF_ID.to_string(),
            username: "self".to_string(),
            ..Default::default()
        };

        let server_s = plain_server(SERVER_S, &[TEXT_S]);
        let server_x = plain_server(SERVER_X, &[TEXT_X]);

        let mut state = member_state(user, &server_s);
        if !cache_server_s {
            state.cache.servers.remove(SERVER_S);
        }
        state.cache.servers.insert(SERVER_X.to_string(), server_x);

        for channel in [
            text_channel(TEXT_S, SERVER_S),
            thread(THREAD_S, SERVER_S, TEXT_S),
            text_channel(TEXT_X, SERVER_X),
            thread(THREAD_X, SERVER_X, TEXT_X),
        ] {
            state
                .cache
                .channels
                .insert(channel.id().to_string(), channel);
        }

        for topic in [SERVER_S, SERVER_X, TEXT_S, THREAD_S, TEXT_X, THREAD_X] {
            state.insert_subscription(topic.to_string()).await;
        }
        state.apply_state().await;

        {
            let subscribed = state.subscribed.read().await;
            for topic in [SERVER_S, SERVER_X, TEXT_S, THREAD_S, TEXT_X, THREAD_X] {
                assert!(
                    subscribed.contains(topic),
                    "precondition: {topic} subscribed"
                );
            }
        }
        assert!(state.cache.channels.contains_key(THREAD_S));

        state
    }

    /// After leaving / losing S: every channel of S is unsubscribed and
    /// uncached, threads included, and X is untouched.
    async fn assert_server_s_dropped(state: &State, case: &str) {
        {
            let subscribed = state.subscribed.read().await;
            assert!(
                !subscribed.contains(THREAD_S),
                "{case}: thread of the left server must be unsubscribed"
            );
            assert!(
                !subscribed.contains(TEXT_S),
                "{case}: text channel of the left server must be unsubscribed"
            );
            assert!(
                !subscribed.contains(SERVER_S),
                "{case}: the left server's topic must be unsubscribed"
            );
            for topic in [SERVER_X, TEXT_X, THREAD_X] {
                assert!(
                    subscribed.contains(topic),
                    "{case}: {topic} of another server must stay subscribed"
                );
            }
        }

        assert!(
            !state.cache.channels.contains_key(THREAD_S),
            "{case}: thread of the left server must be uncached"
        );
        assert!(
            !state.cache.channels.contains_key(TEXT_S),
            "{case}: text channel of the left server must be uncached"
        );
        assert!(
            state.cache.channels.contains_key(THREAD_X)
                && state.cache.channels.contains_key(TEXT_X),
            "{case}: channels of another server must stay cached"
        );
        assert!(!state.cache.servers.contains_key(SERVER_S));
        assert!(!state.cache.members.contains_key(SERVER_S));
    }

    fn self_leave() -> EventV1 {
        EventV1::ServerMemberLeave {
            id: SERVER_S.to_string(),
            user: SELF_ID.to_string(),
            reason: RemovalIntention::Ban,
        }
    }

    /// Being banned / kicked / leaving S drops S's threads from the socket,
    /// not only the channels listed in `S.channels`; otherwise live thread
    /// messages keep arriving until reconnect.
    #[tokio::test]
    async fn self_member_leave_drops_server_threads() {
        let db = DatabaseInfo::Reference.connect().await.expect("database");
        let mut state = seeded_state(true).await;

        // Another member leaving S changes nothing for us.
        let mut event = EventV1::ServerMemberLeave {
            id: SERVER_S.to_string(),
            user: OTHER_ID.to_string(),
            reason: RemovalIntention::Leave,
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(
            state.subscribed.read().await.contains(THREAD_S),
            "another member's leave must not drop our threads"
        );
        assert!(state.cache.channels.contains_key(THREAD_S));

        let mut event = self_leave();
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "the leave event must still be forwarded to the client"
        );
        assert!(matches!(event, EventV1::ServerMemberLeave { .. }));
        assert_server_s_dropped(&state, "self ServerMemberLeave").await;
    }

    /// Same for a deleted server.
    #[tokio::test]
    async fn server_delete_drops_server_threads() {
        let db = DatabaseInfo::Reference.connect().await.expect("database");
        let mut state = seeded_state(true).await;

        let mut event = EventV1::ServerDelete {
            id: SERVER_S.to_string(),
        };
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "the delete event must still be forwarded to the client"
        );
        assert!(matches!(event, EventV1::ServerDelete { .. }));
        assert_server_s_dropped(&state, "ServerDelete").await;
    }

    /// A thread can be cached for a server that is not (`ChannelCreate`
    /// caches threads unconditionally), so the drop must not depend on S
    /// being in `cache.servers`.
    #[tokio::test]
    async fn self_member_leave_drops_threads_of_uncached_server() {
        let db = DatabaseInfo::Reference.connect().await.expect("database");
        let mut state = seeded_state(false).await;

        let mut event = self_leave();
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);

        let subscribed = state.subscribed.read().await;
        assert!(
            !subscribed.contains(THREAD_S),
            "uncached server: thread of the left server must be unsubscribed"
        );
        assert!(
            !state.cache.channels.contains_key(THREAD_S),
            "uncached server: thread of the left server must be uncached"
        );
        assert!(
            subscribed.contains(THREAD_X) && state.cache.channels.contains_key(THREAD_X),
            "uncached server: thread of another server must survive"
        );
    }

    /// Grants ViewChannel on `PRIVATE_S`.
    const ROLE_R: &str = "01ROLE0000000000000000000R";
    /// Text channel of S that only holders of `ROLE_R` can view.
    const PRIVATE_S: &str = "01CHANNEL00000000000PRIVATE";
    /// Thread under `PRIVATE_S`.
    const PRIVATE_THREAD_S: &str = "01CHANNEL0000000000PTHREADS";
    /// A second thread under `PRIVATE_S`, only in the database where a test
    /// adds it.
    const PRIVATE_THREAD2_S: &str = "01CHANNEL000000000PTHREAD2S";

    /// A throwaway database named like the ones `DatabaseInfo::Auto` makes, so
    /// `scripts/drop-test-databases.sh` sweeps it after a `TEST_DB=MONGODB` run.
    async fn test_db() -> Database {
        use rand::Rng;
        DatabaseInfo::Test(format!(
            "revolt_test_{}",
            rand::thread_rng().gen_range(1_000_000..10_000_000)
        ))
        .connect()
        .await
        .expect("database")
    }

    fn private_channel() -> Channel {
        Channel::TextChannel {
            id: PRIVATE_S.to_string(),
            server: SERVER_S.to_string(),
            name: "private".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: Some(OverrideField {
                a: 0,
                d: ChannelPermission::ViewChannel as i64,
            }),
            role_permissions: HashMap::from([(
                ROLE_R.to_string(),
                OverrideField {
                    a: ChannelPermission::ViewChannel as i64,
                    d: 0,
                },
            )]),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
        }
    }

    /// S with a public and a private text channel, and the role that unlocks
    /// the private one.
    fn server_with_private_channel() -> Server {
        let mut server = plain_server(SERVER_S, &[TEXT_S, PRIVATE_S]);
        server.roles.insert(
            ROLE_R.to_string(),
            Role {
                id: ROLE_R.to_string(),
                name: "r".to_string(),
                permissions: OverrideField { a: 0, d: 0 },
                colour: None,
                hoist: false,
                rank: 1,
                icon: None,
            },
        );
        server
    }

    /// The database rows a live server would have: both text channels and the
    /// thread under the private one.
    #[allow(clippy::disallowed_methods)]
    async fn private_channel_db() -> Database {
        let db = test_db().await;
        for channel in [
            text_channel(TEXT_S, SERVER_S),
            private_channel(),
            thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S),
        ] {
            db.insert_channel(&channel).await.expect("insert channel");
        }
        db
    }

    /// A member of S holding `roles`, with what Ready would have given them:
    /// every channel in `visible` cached and subscribed. Flushed out of the
    /// `Reset` state, where `remove_subscription` panics.
    async fn private_channel_state(roles: &[&str], visible: &[Channel]) -> State {
        let user = User {
            id: SELF_ID.to_string(),
            username: "self".to_string(),
            ..Default::default()
        };
        let mut state = member_state(user, &server_with_private_channel());
        state.cache.members.get_mut(SERVER_S).expect("member").roles =
            roles.iter().map(|r| r.to_string()).collect();

        state.insert_subscription(SERVER_S.to_string()).await;
        for channel in visible {
            state
                .cache
                .channels
                .insert(channel.id().to_string(), channel.clone());
            state.insert_subscription(channel.id().to_string()).await;
        }
        state.apply_state().await;
        state
    }

    /// Our own roles change to `roles`.
    fn set_roles(roles: &[&str]) -> EventV1 {
        EventV1::ServerMemberUpdate {
            id: v0::MemberCompositeKey {
                server: SERVER_S.to_string(),
                user: SELF_ID.to_string(),
            },
            data: v0::PartialMember {
                roles: Some(roles.iter().map(|r| r.to_string()).collect()),
                ..Default::default()
            },
            clear: vec![],
        }
    }

    /// The channel ids announced by `ChannelCreate` / `ChannelDelete` inside a
    /// forwarded event, plus the event recalculate_server wrapped (the last
    /// entry of the Bulk), or the event itself when nothing was added.
    fn split_bulk(event: &EventV1) -> (Vec<String>, Vec<String>, &EventV1) {
        let mut created = vec![];
        let mut deleted = vec![];
        let EventV1::Bulk { v } = event else {
            return (created, deleted, event);
        };
        let (original, generated) = v.split_last().expect("non-empty bulk");
        for event in generated {
            match event {
                EventV1::ChannelCreate(channel) => {
                    let channel: Channel = channel.clone().into();
                    created.push(channel.id().to_string());
                }
                EventV1::ChannelDelete { id } => deleted.push(id.clone()),
                other => panic!("unexpected generated event {other:?}"),
            }
        }
        (created, deleted, original)
    }

    /// A thread created while its parent is hidden is cached but neither
    /// forwarded nor subscribed. The grant that reveals the parent must
    /// announce the thread too, or its messages reach a client that never
    /// cached the channel: no notifications, no sidebar entry.
    #[tokio::test]
    async fn role_grant_reveals_thread_created_while_parent_hidden() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(&[], &[text_channel(TEXT_S, SERVER_S)]).await;

        let mut event =
            EventV1::ChannelCreate(thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S).into());
        assert!(
            !state.handle_incoming_event_v1(&db, &mut event).await,
            "precondition: a thread under a hidden parent is not forwarded"
        );
        assert!(state.cache.channels.contains_key(PRIVATE_THREAD_S));
        assert!(!state.subscribed.read().await.contains(PRIVATE_THREAD_S));

        let mut event = set_roles(&[ROLE_R]);
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);

        let (created, deleted, original) = split_bulk(&event);
        assert!(matches!(original, EventV1::ServerMemberUpdate { .. }));
        assert!(deleted.is_empty(), "nothing was hidden: {deleted:?}");
        assert_eq!(
            created,
            vec![PRIVATE_S.to_string(), PRIVATE_THREAD_S.to_string()],
            "the parent and then its thread are announced once each, the \
             already visible channel not at all"
        );

        let subscribed = state.subscribed.read().await;
        assert!(subscribed.contains(PRIVATE_S));
        assert!(subscribed.contains(PRIVATE_THREAD_S));
        assert!(subscribed.contains(TEXT_S));
    }

    /// The same reveal through an override on the parent instead of a role.
    /// The hidden parent is uncached, so its visibility before the update
    /// cannot be re-derived: the database already holds the new override.
    #[tokio::test]
    async fn parent_override_grant_reveals_thread_created_while_hidden() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(&[], &[text_channel(TEXT_S, SERVER_S)]).await;

        let mut event =
            EventV1::ChannelCreate(thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S).into());
        assert!(!state.handle_incoming_event_v1(&db, &mut event).await);

        // As the route does it: write the row, then publish the update.
        let open = OverrideField { a: 0, d: 0 };
        db.update_channel(
            PRIVATE_S,
            &PartialChannel {
                default_permissions: Some(open),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("update channel");

        let mut event = EventV1::ChannelUpdate {
            id: PRIVATE_S.to_string(),
            data: v0::PartialChannel {
                default_permissions: Some(open),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);

        // The update itself became the parent's ChannelCreate, ahead of the
        // thread's.
        assert_eq!(
            bulk_creates(&event),
            vec![PRIVATE_S.to_string(), PRIVATE_THREAD_S.to_string()]
        );

        let subscribed = state.subscribed.read().await;
        assert!(subscribed.contains(PRIVATE_S));
        assert!(subscribed.contains(PRIVATE_THREAD_S));
    }

    /// The ids of a Bulk made only of ChannelCreates, in order.
    fn bulk_creates(event: &EventV1) -> Vec<String> {
        let EventV1::Bulk { v } = event else {
            panic!("expected a Bulk: {event:?}");
        };
        v.iter()
            .map(|event| match event {
                EventV1::ChannelCreate(channel) => {
                    let channel: Channel = channel.clone().into();
                    channel.id().to_string()
                }
                other => panic!("expected only ChannelCreate, got {other:?}"),
            })
            .collect()
    }

    /// After a role revoke the hidden parent and thread stay cached. An edit
    /// to the parent must stay silent, and the override that opens it must
    /// announce the parent and the thread.
    #[tokio::test]
    async fn parent_update_after_role_revoke_follows_what_the_client_knows() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(
            &[ROLE_R],
            &[
                text_channel(TEXT_S, SERVER_S),
                private_channel(),
                thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S),
            ],
        )
        .await;

        let mut event = set_roles(&[]);
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);

        let mut event = EventV1::ChannelUpdate {
            id: PRIVATE_S.to_string(),
            data: v0::PartialChannel {
                name: Some("renamed secret".to_string()),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(
            !state.handle_incoming_event_v1(&db, &mut event).await,
            "an edit to the hidden parent must be dropped"
        );

        let open = OverrideField { a: 0, d: 0 };
        db.update_channel(
            PRIVATE_S,
            &PartialChannel {
                default_permissions: Some(open),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("update channel");

        let mut event = EventV1::ChannelUpdate {
            id: PRIVATE_S.to_string(),
            data: v0::PartialChannel {
                default_permissions: Some(open),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert_eq!(
            bulk_creates(&event),
            vec![PRIVATE_S.to_string(), PRIVATE_THREAD_S.to_string()]
        );

        let subscribed = state.subscribed.read().await;
        assert!(subscribed.contains(PRIVATE_S));
        assert!(subscribed.contains(PRIVATE_THREAD_S));
    }

    /// If bonfire's permission view moved without a recalculation, the next
    /// update to the channel reconciles against what the client was told: a
    /// subscribed channel that is no longer viewable is deleted, not left
    /// subscribed with the update dropped.
    #[tokio::test]
    async fn parent_update_heals_subscription_drift() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(
            &[ROLE_R],
            &[text_channel(TEXT_S, SERVER_S), private_channel()],
        )
        .await;
        state.cache.members.get_mut(SERVER_S).expect("member").roles = vec![];

        let mut event = EventV1::ChannelUpdate {
            id: PRIVATE_S.to_string(),
            data: v0::PartialChannel {
                name: Some("renamed".to_string()),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(
            matches!(&event, EventV1::ChannelDelete { id } if id == PRIVATE_S),
            "the update must become a ChannelDelete: {event:?}"
        );
        assert!(!state.subscribed.read().await.contains(PRIVATE_S));
    }

    /// A recalculation that leaves the parent hidden must not announce the
    /// never-shown thread's deletion, nor forget it: threads are not in
    /// `Server.channels`, so an uncached thread could never be revealed by
    /// the grant that comes later.
    #[tokio::test]
    async fn hidden_thread_survives_unrelated_recalculation() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(&[], &[text_channel(TEXT_S, SERVER_S)]).await;

        let mut event =
            EventV1::ChannelCreate(thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S).into());
        assert!(!state.handle_incoming_event_v1(&db, &mut event).await);

        // Recalculates S without changing what we can see.
        let mut event = set_roles(&[]);
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(
            matches!(event, EventV1::ServerMemberUpdate { .. }),
            "a recalculation that changes nothing adds nothing, and never \
             names a hidden channel: {event:?}"
        );
        assert!(state.cache.channels.contains_key(PRIVATE_THREAD_S));
        assert!(!state.subscribed.read().await.contains(PRIVATE_THREAD_S));

        let mut event = set_roles(&[ROLE_R]);
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        let (created, _, _) = split_bulk(&event);
        assert!(
            created.contains(&PRIVATE_THREAD_S.to_string()),
            "the later grant still reveals the thread: {created:?}"
        );
        assert!(state.subscribed.read().await.contains(PRIVATE_THREAD_S));
    }

    /// Losing the role hides the parent and its thread; getting it back must
    /// announce both again.
    #[tokio::test]
    async fn role_revoke_then_regrant_round_trips_thread() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(
            &[ROLE_R],
            &[
                text_channel(TEXT_S, SERVER_S),
                private_channel(),
                thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S),
            ],
        )
        .await;

        let mut event = set_roles(&[]);
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        let (created, mut deleted, _) = split_bulk(&event);
        deleted.sort();
        assert!(
            created.is_empty(),
            "revoke announces nothing new: {created:?}"
        );
        assert_eq!(
            deleted,
            vec![PRIVATE_S.to_string(), PRIVATE_THREAD_S.to_string()]
        );
        {
            let subscribed = state.subscribed.read().await;
            assert!(!subscribed.contains(PRIVATE_S));
            assert!(!subscribed.contains(PRIVATE_THREAD_S));
            assert!(subscribed.contains(TEXT_S));
        }

        let mut event = set_roles(&[ROLE_R]);
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        let (created, deleted, _) = split_bulk(&event);
        assert!(deleted.is_empty(), "regrant hides nothing: {deleted:?}");
        assert_eq!(
            created,
            vec![PRIVATE_S.to_string(), PRIVATE_THREAD_S.to_string()]
        );
        let subscribed = state.subscribed.read().await;
        assert!(subscribed.contains(PRIVATE_S));
        assert!(subscribed.contains(PRIVATE_THREAD_S));
    }

    /// A thread deleted while hidden publishes its ChannelDelete only to its
    /// own topic, which we were not subscribed to. The grant must not
    /// resurrect it from the stale cache entry, and must still reveal its
    /// live sibling (the reference driver fails a batch read on any missing
    /// id).
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn role_grant_skips_thread_deleted_while_hidden() {
        let db = private_channel_db().await;
        let sibling = thread(PRIVATE_THREAD2_S, SERVER_S, PRIVATE_S);
        db.insert_channel(&sibling).await.expect("insert sibling");
        let mut state = private_channel_state(&[], &[text_channel(TEXT_S, SERVER_S)]).await;

        let hidden_thread = thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S);
        for channel in [&hidden_thread, &sibling] {
            let mut event = EventV1::ChannelCreate(channel.clone().into());
            assert!(!state.handle_incoming_event_v1(&db, &mut event).await);
        }
        db.delete_channel(&hidden_thread)
            .await
            .expect("delete thread");

        let mut event = set_roles(&[ROLE_R]);
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        let (created, _, _) = split_bulk(&event);
        assert_eq!(
            created,
            vec![PRIVATE_S.to_string(), PRIVATE_THREAD2_S.to_string()],
            "the parent and the live thread are announced, not the deleted one"
        );
        assert!(!state.cache.channels.contains_key(PRIVATE_THREAD_S));
        let subscribed = state.subscribed.read().await;
        assert!(!subscribed.contains(PRIVATE_THREAD_S));
        assert!(subscribed.contains(PRIVATE_THREAD2_S));
    }

    /// ServerCreate carries the channels the client may see; recalculation
    /// must not announce any of them a second time.
    #[tokio::test]
    async fn server_create_announces_no_channel_twice() {
        let db = private_channel_db().await;
        let user = User {
            id: SELF_ID.to_string(),
            username: "self".to_string(),
            ..Default::default()
        };
        let mut state = State::from(user, "session".to_string());
        state.apply_state().await;

        let mut event = EventV1::ServerCreate {
            id: SERVER_S.to_string(),
            server: server_with_private_channel().into(),
            channels: vec![text_channel(TEXT_S, SERVER_S).into()],
            emojis: vec![],
            stickers: vec![],
            voice_states: vec![],
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(
            matches!(event, EventV1::ServerCreate { .. }),
            "nothing is added to ServerCreate: {event:?}"
        );
        let subscribed = state.subscribed.read().await;
        assert!(subscribed.contains(SERVER_S));
        assert!(subscribed.contains(TEXT_S));
        assert!(!subscribed.contains(PRIVATE_S));
    }

    /// Leave, then rejoin in the same session. The client swept the server's
    /// threads on leave; the socket must neither keep delivering them nor
    /// bring them back as stale state on the ServerCreate.
    #[tokio::test]
    async fn rejoin_after_leave_carries_no_stale_thread() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(
            &[],
            &[
                text_channel(TEXT_S, SERVER_S),
                thread(THREAD_S, SERVER_S, TEXT_S),
            ],
        )
        .await;

        let mut event =
            EventV1::ChannelCreate(thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S).into());
        assert!(!state.handle_incoming_event_v1(&db, &mut event).await);

        let mut event = self_leave();
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);

        let mut event = EventV1::ServerCreate {
            id: SERVER_S.to_string(),
            server: server_with_private_channel().into(),
            channels: vec![text_channel(TEXT_S, SERVER_S).into()],
            emojis: vec![],
            stickers: vec![],
            voice_states: vec![],
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(
            matches!(event, EventV1::ServerCreate { .. }),
            "rejoin adds nothing to ServerCreate: {event:?}"
        );

        let subscribed = state.subscribed.read().await;
        assert!(subscribed.contains(TEXT_S));
        for id in [THREAD_S, PRIVATE_THREAD_S] {
            assert!(!subscribed.contains(id), "{id} must not be subscribed");
            assert!(
                !state.cache.channels.contains_key(id),
                "{id} must not be cached"
            );
        }
    }

    /// Server whose default permissions lack ViewChannel: only `ROLE_VIEW`
    /// holders can see a channel without overrides.
    const SERVER_G: &str = "01SERVER00000000000000000G";
    /// Grants ViewChannel server-wide on `SERVER_G`.
    const ROLE_VIEW: &str = "01ROLE0000000000000000VIEW";
    const NEW_TEXT: &str = "01CHANNEL000000000000NEWTEXT";
    const NEW_FORUM: &str = "01CHANNEL00000000000NEWFORUM";

    fn role_gated_server(channels: &[&str]) -> Server {
        let mut server = plain_server(SERVER_G, channels);
        server.default_permissions = 0;
        server.roles.insert(
            ROLE_VIEW.to_string(),
            Role {
                id: ROLE_VIEW.to_string(),
                name: "viewer".to_string(),
                permissions: OverrideField {
                    a: ChannelPermission::ViewChannel as i64,
                    d: 0,
                },
                colour: None,
                hoist: false,
                rank: 0,
                icon: None,
            },
        );
        server
    }

    fn forum(id: &str, server: &str) -> Channel {
        Channel::Forum {
            id: id.to_string(),
            server: server.to_string(),
            name: "forum".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            tags: vec![],
            require_tag: false,
            default_sort: Default::default(),
            force_sort: false,
            default_layout: Default::default(),
            default_auto_archive_minutes: Channel::default_forum_auto_archive_minutes(),
        }
    }

    /// A member of `server` holding `roles`, subscribed to the server topic,
    /// with the subscriptions flushed (see `seeded_state`).
    async fn member_with_roles(server: &Server, roles: &[&str]) -> State {
        let user = User {
            id: SELF_ID.to_string(),
            username: "self".to_string(),
            ..Default::default()
        };

        let mut state = member_state(user, server);
        state
            .cache
            .members
            .get_mut(&server.id)
            .expect("member")
            .roles = roles.iter().map(|r| r.to_string()).collect();
        state.insert_subscription(server.id.clone()).await;
        state.apply_state().await;
        state
    }

    /// `create_server_channel` publishes ChannelCreate to the server topic,
    /// and the new channel has no overrides, so its visibility is the
    /// server-level permission. A member without a role granting ViewChannel
    /// must neither receive it nor be subscribed to its messages.
    #[tokio::test]
    async fn channel_create_hidden_by_server_permissions_is_dropped() {
        let db = test_db().await;
        let server = role_gated_server(&[NEW_TEXT, NEW_FORUM]);

        for channel in [text_channel(NEW_TEXT, SERVER_G), forum(NEW_FORUM, SERVER_G)] {
            let id = channel.id().to_string();

            let mut state = member_with_roles(&server, &[]).await;
            let mut event = EventV1::ChannelCreate(channel.clone().into());
            assert!(
                !state.handle_incoming_event_v1(&db, &mut event).await,
                "{id}: ChannelCreate must be dropped for a member who cannot view it"
            );
            assert!(
                !state.subscribed.read().await.contains(&id),
                "{id}: a hidden new channel must not be subscribed"
            );
            assert!(
                !state.cache.channels.contains_key(&id),
                "{id}: a hidden new server channel must not be cached"
            );

            let mut state = member_with_roles(&server, &[ROLE_VIEW]).await;
            let mut event = EventV1::ChannelCreate(channel.clone().into());
            assert!(
                state.handle_incoming_event_v1(&db, &mut event).await,
                "{id}: a member whose role grants ViewChannel must receive the ChannelCreate"
            );
            assert!(matches!(event, EventV1::ChannelCreate(_)));
            assert!(
                state.subscribed.read().await.contains(&id),
                "{id}: a visible new channel must be subscribed"
            );
            assert!(state.cache.channels.contains_key(&id));
        }
    }

    /// The common case: default permissions grant ViewChannel, so a member
    /// with no roles still receives and subscribes to the new channel.
    #[tokio::test]
    async fn channel_create_visible_by_default_is_forwarded() {
        let db = test_db().await;
        let server = plain_server(SERVER_G, &[NEW_TEXT]);
        let mut state = member_with_roles(&server, &[]).await;

        let mut event = EventV1::ChannelCreate(text_channel(NEW_TEXT, SERVER_G).into());
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "ChannelCreate must be forwarded when the default permissions grant ViewChannel"
        );
        assert!(matches!(event, EventV1::ChannelCreate(_)));
        assert!(state.subscribed.read().await.contains(NEW_TEXT));
        assert!(state.cache.channels.contains_key(NEW_TEXT));
    }

    /// The gate must not catch channels that are always viewable, nor a
    /// member the server permissions do not bind: the owner sees a new
    /// channel on a server whose default permissions hide it.
    #[tokio::test]
    async fn channel_create_forwarded_to_owner_and_for_private_channels() {
        let db = test_db().await;

        let mut owned = role_gated_server(&[NEW_TEXT]);
        owned.owner = SELF_ID.to_string();
        let mut state = member_with_roles(&owned, &[]).await;
        let mut event = EventV1::ChannelCreate(text_channel(NEW_TEXT, SERVER_G).into());
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "the owner must receive a new channel the default permissions hide"
        );
        assert!(state.subscribed.read().await.contains(NEW_TEXT));

        let mut state = member_with_roles(&role_gated_server(&[]), &[]).await;
        for channel in [
            Channel::SavedMessages {
                id: "01CHANNEL0000000000000SAVED".to_string(),
                user: SELF_ID.to_string(),
            },
            Channel::DirectMessage {
                id: "01CHANNEL000000000000000DM".to_string(),
                active: true,
                recipients: vec![SELF_ID.to_string(), OTHER_ID.to_string()],
                last_message_id: None,
            },
        ] {
            let id = channel.id().to_string();
            let mut event = EventV1::ChannelCreate(channel.into());
            assert!(
                state.handle_incoming_event_v1(&db, &mut event).await,
                "{id}: ChannelCreate of a private channel must be forwarded"
            );
            assert!(
                state.subscribed.read().await.contains(&id),
                "{id}: a private channel must be subscribed"
            );
            assert!(state.cache.channels.contains_key(&id));
        }
    }

    /// A channel dropped at creation must still be announced, once, when a
    /// later role grant makes it visible. It is uncached, as Ready leaves a
    /// hidden server channel, so the recalculation finds it among
    /// `Server.channels` and sends ChannelCreate with the subscription.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn hidden_channel_create_is_announced_on_role_grant() {
        let db = test_db().await;
        let channel = text_channel(NEW_TEXT, SERVER_G);
        db.insert_channel(&channel).await.expect("insert channel");

        let mut state = member_with_roles(&role_gated_server(&[]), &[]).await;

        // create_server_channel publishes the new channel list first.
        let mut event = EventV1::ServerUpdate {
            id: SERVER_G.to_string(),
            data: v0::PartialServer {
                channels: Some(vec![NEW_TEXT.to_string()]),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);

        let mut event = EventV1::ChannelCreate(channel.clone().into());
        assert!(
            !state.handle_incoming_event_v1(&db, &mut event).await,
            "ChannelCreate must be dropped before the grant"
        );

        let mut event = EventV1::ServerMemberUpdate {
            id: v0::MemberCompositeKey {
                server: SERVER_G.to_string(),
                user: SELF_ID.to_string(),
            },
            data: v0::PartialMember {
                roles: Some(vec![ROLE_VIEW.to_string()]),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);

        let (created, deleted, original) = split_bulk(&event);
        assert!(
            matches!(original, EventV1::ServerMemberUpdate { .. }),
            "the member update itself must still be delivered"
        );
        assert!(deleted.is_empty(), "nothing was hidden: {deleted:?}");
        assert_eq!(
            created,
            vec![NEW_TEXT.to_string()],
            "the role grant must announce the hidden channel exactly once"
        );
        assert!(
            state.subscribed.read().await.contains(NEW_TEXT),
            "the revealed channel must be subscribed"
        );
        assert!(state.cache.channels.contains_key(NEW_TEXT));
    }

    /// The "create, then make private" flow: on a server where everyone can
    /// view, the new channel is visible until the override lands. The
    /// override's ChannelUpdate (server topic) must then hide it from a member
    /// it now denies: a ChannelDelete instead of the update, and unsubscribed.
    #[tokio::test]
    async fn override_after_create_hides_the_new_channel() {
        let db = test_db().await;
        let server = plain_server(SERVER_G, &[NEW_TEXT]);
        let mut state = member_with_roles(&server, &[]).await;

        let mut event = EventV1::ChannelCreate(text_channel(NEW_TEXT, SERVER_G).into());
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(state.subscribed.read().await.contains(NEW_TEXT));

        let mut event = EventV1::ChannelUpdate {
            id: NEW_TEXT.to_string(),
            data: v0::PartialChannel {
                default_permissions: Some(OverrideField {
                    a: 0,
                    d: ChannelPermission::ViewChannel as i64,
                }),
                ..Default::default()
            },
            clear: vec![],
        };
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(
            matches!(&event, EventV1::ChannelDelete { id } if id == NEW_TEXT),
            "the override must reach the member as a ChannelDelete, got {event:?}"
        );
        assert!(
            !state.subscribed.read().await.contains(NEW_TEXT),
            "the now-private channel must be unsubscribed"
        );
    }

    fn thread_join(user: &str, id: &str) -> EventV1 {
        EventV1::ThreadMemberJoin {
            id: id.to_string(),
            user: user.to_string(),
        }
    }

    fn thread_leave(user: &str, id: &str) -> EventV1 {
        EventV1::ThreadMemberLeave {
            id: id.to_string(),
            user: user.to_string(),
        }
    }

    /// The topics an `apply_state` flush queues for Redis to subscribe and
    /// unsubscribe. The fixtures are flushed out of `Reset` first, so a
    /// `Reset` here means the test is broken.
    fn queued_changes(
        change: super::super::state::SubscriptionStateChange,
    ) -> (Vec<String>, Vec<String>) {
        use super::super::state::SubscriptionStateChange;
        match change {
            SubscriptionStateChange::None => (vec![], vec![]),
            SubscriptionStateChange::Change { add, remove } => (add, remove),
            SubscriptionStateChange::Reset => panic!("fixture was not flushed"),
        }
    }

    /// Joining a thread after Ready (a reply, an explicit join) must
    /// subscribe it, or its live messages never reach this socket. A client
    /// that never cached it learns it from a ChannelCreate placed ahead of
    /// the join, which the client would otherwise drop.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn thread_member_self_join_reveals_and_subscribes_uncached_thread() {
        let db = private_channel_db().await;
        db.insert_channel(&thread(THREAD_S, SERVER_S, TEXT_S))
            .await
            .expect("insert thread");
        let mut state = private_channel_state(&[], &[text_channel(TEXT_S, SERVER_S)]).await;

        let mut event = thread_join(SELF_ID, THREAD_S);
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "our own join of a visible thread must be forwarded"
        );

        let (created, deleted, original) = split_bulk(&event);
        assert_eq!(
            created,
            vec![THREAD_S.to_string()],
            "the thread is announced ahead of the join: {event:?}"
        );
        assert!(deleted.is_empty(), "nothing was hidden: {deleted:?}");
        assert!(
            matches!(original, EventV1::ThreadMemberJoin { id, user } if id == THREAD_S && user == SELF_ID),
            "the join itself comes last, unchanged: {original:?}"
        );

        assert!(state.cache.channels.contains_key(THREAD_S));
        assert!(state.subscribed.read().await.contains(THREAD_S));
        let (add, _) = queued_changes(state.apply_state().await);
        assert!(
            add.contains(&THREAD_S.to_string()),
            "the Redis subscribe must be queued: {add:?}"
        );
    }

    /// A join of a thread the socket already follows is forwarded as is and
    /// reads nothing: with the row gone from the database, a re-reveal would
    /// drop the join and uncache the thread.
    #[tokio::test]
    async fn thread_member_self_join_of_subscribed_thread_is_forwarded_unchanged() {
        let db = test_db().await;
        let mut state = private_channel_state(
            &[],
            &[
                text_channel(TEXT_S, SERVER_S),
                thread(THREAD_S, SERVER_S, TEXT_S),
            ],
        )
        .await;

        let mut event = thread_join(SELF_ID, THREAD_S);
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "a join of a subscribed thread must be forwarded"
        );
        assert!(
            matches!(&event, EventV1::ThreadMemberJoin { id, user } if id == THREAD_S && user == SELF_ID),
            "the join must be forwarded unchanged: {event:?}"
        );
        assert!(
            state.cache.channels.contains_key(THREAD_S),
            "the thread must stay cached"
        );
        assert!(state.subscribed.read().await.contains(THREAD_S));
    }

    /// Our own join of a thread under a parent we cannot view is dropped and
    /// subscribes nothing. A later grant still reveals the thread, as a
    /// ChannelCreate only: the dropped join is not replayed.
    #[tokio::test]
    async fn thread_member_self_join_under_hidden_parent_is_dropped() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(&[], &[text_channel(TEXT_S, SERVER_S)]).await;

        let mut event = thread_join(SELF_ID, PRIVATE_THREAD_S);
        assert!(
            !state.handle_incoming_event_v1(&db, &mut event).await,
            "a join of a thread under a hidden parent must be dropped"
        );
        assert!(!state.subscribed.read().await.contains(PRIVATE_THREAD_S));
        let (add, _) = queued_changes(state.apply_state().await);
        assert!(
            !add.contains(&PRIVATE_THREAD_S.to_string()),
            "no Redis subscribe for a hidden thread: {add:?}"
        );

        let mut event = set_roles(&[ROLE_R]);
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        let (created, deleted, original) = split_bulk(&event);
        assert!(matches!(original, EventV1::ServerMemberUpdate { .. }));
        assert!(deleted.is_empty(), "nothing was hidden: {deleted:?}");
        assert_eq!(
            created,
            vec![PRIVATE_S.to_string(), PRIVATE_THREAD_S.to_string()],
            "the grant announces the parent and then the thread"
        );
        let EventV1::Bulk { v } = &event else {
            panic!("expected a Bulk: {event:?}");
        };
        assert!(
            !v.iter()
                .any(|event| matches!(event, EventV1::ThreadMemberJoin { .. })),
            "the dropped join is not replayed by the grant: {v:?}"
        );

        assert!(state.subscribed.read().await.contains(PRIVATE_THREAD_S));
        let (add, _) = queued_changes(state.apply_state().await);
        assert!(
            add.contains(&PRIVATE_THREAD_S.to_string()),
            "the grant queues the Redis subscribe: {add:?}"
        );
    }

    /// A join of a thread that is not in the database is dropped, and
    /// neither caches nor subscribes it.
    #[tokio::test]
    async fn thread_member_self_join_of_missing_thread_is_dropped() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(&[], &[text_channel(TEXT_S, SERVER_S)]).await;

        let mut event = thread_join(SELF_ID, THREAD_S);
        assert!(
            !state.handle_incoming_event_v1(&db, &mut event).await,
            "a join of a missing thread must be dropped"
        );
        assert!(!state.cache.channels.contains_key(THREAD_S));
        assert!(!state.subscribed.read().await.contains(THREAD_S));
        let (add, _) = queued_changes(state.apply_state().await);
        assert!(!add.contains(&THREAD_S.to_string()), "{add:?}");
    }

    /// Another member's join or leave is forwarded only for a thread this
    /// socket was told about. Membership events go to the whole server
    /// topic, so without this every member learns the ids and members of
    /// threads under parents they cannot view.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn thread_member_events_of_other_users_follow_subscription() {
        let db = private_channel_db().await;
        db.insert_channel(&thread(THREAD_S, SERVER_S, TEXT_S))
            .await
            .expect("insert thread");
        let mut state = private_channel_state(&[], &[text_channel(TEXT_S, SERVER_S)]).await;

        // Cached while hidden, as ChannelCreate leaves it.
        let mut event =
            EventV1::ChannelCreate(thread(PRIVATE_THREAD_S, SERVER_S, PRIVATE_S).into());
        assert!(!state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(state.cache.channels.contains_key(PRIVATE_THREAD_S));

        // A hidden thread, then a visible thread this socket never cached.
        for id in [PRIVATE_THREAD_S, THREAD_S] {
            for mut event in [thread_join(OTHER_ID, id), thread_leave(OTHER_ID, id)] {
                assert!(
                    !state.handle_incoming_event_v1(&db, &mut event).await,
                    "{id}: another member's {event:?} must be dropped"
                );
            }
        }
        assert!(
            !state.cache.channels.contains_key(THREAD_S),
            "another member's join must not cache the thread"
        );
        {
            let subscribed = state.subscribed.read().await;
            assert!(!subscribed.contains(THREAD_S));
            assert!(!subscribed.contains(PRIVATE_THREAD_S));
        }

        // Once the thread is announced, its membership events flow.
        let mut event = EventV1::ChannelCreate(thread(THREAD_S, SERVER_S, TEXT_S).into());
        assert!(state.handle_incoming_event_v1(&db, &mut event).await);
        assert!(state.subscribed.read().await.contains(THREAD_S));

        let mut event = thread_join(OTHER_ID, THREAD_S);
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "another member's join of a subscribed thread must be forwarded"
        );
        assert!(
            matches!(&event, EventV1::ThreadMemberJoin { id, user } if id == THREAD_S && user == OTHER_ID),
            "forwarded unchanged: {event:?}"
        );

        let mut event = thread_leave(OTHER_ID, THREAD_S);
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "another member's leave of a subscribed thread must be forwarded"
        );
        assert!(
            matches!(&event, EventV1::ThreadMemberLeave { id, user } if id == THREAD_S && user == OTHER_ID),
            "forwarded unchanged: {event:?}"
        );
    }

    /// Leaving a thread keeps it subscribed, as a visible thread we never
    /// joined is, so an open view keeps receiving its messages. A leave of a
    /// thread the socket does not follow is dropped.
    #[tokio::test]
    async fn thread_member_self_leave_keeps_subscription() {
        let db = private_channel_db().await;
        let mut state = private_channel_state(
            &[],
            &[
                text_channel(TEXT_S, SERVER_S),
                thread(THREAD_S, SERVER_S, TEXT_S),
            ],
        )
        .await;

        let mut event = thread_leave(SELF_ID, THREAD_S);
        assert!(
            state.handle_incoming_event_v1(&db, &mut event).await,
            "our own leave of a subscribed thread must be forwarded"
        );
        assert!(
            matches!(&event, EventV1::ThreadMemberLeave { id, user } if id == THREAD_S && user == SELF_ID),
            "forwarded unchanged: {event:?}"
        );
        assert!(
            state.subscribed.read().await.contains(THREAD_S),
            "leaving must keep the subscription"
        );
        assert!(state.cache.channels.contains_key(THREAD_S));
        let (_, remove) = queued_changes(state.apply_state().await);
        assert!(
            !remove.contains(&THREAD_S.to_string()),
            "no Redis unsubscribe on leave: {remove:?}"
        );

        let mut event = thread_leave(SELF_ID, PRIVATE_THREAD_S);
        assert!(
            !state.handle_incoming_event_v1(&db, &mut event).await,
            "our own leave of an unsubscribed thread must be dropped"
        );
    }

    /// A join naming a channel that is not a thread reveals nothing, even
    /// one we may view: a text channel the socket was not told about, or a
    /// DM, which `can_view_channel` treats as viewable.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn thread_member_self_join_of_non_thread_channel_is_dropped() {
        let db = private_channel_db().await;
        let dm = Channel::DirectMessage {
            id: "01CHANNEL000000000000000DM".to_string(),
            active: true,
            recipients: vec![SELF_ID.to_string(), OTHER_ID.to_string()],
            last_message_id: None,
        };
        db.insert_channel(&dm).await.expect("insert dm");
        let mut state = private_channel_state(&[], &[]).await;

        for id in [TEXT_S, dm.id()] {
            let mut event = thread_join(SELF_ID, id);
            assert!(
                !state.handle_incoming_event_v1(&db, &mut event).await,
                "{id}: a join of a non-thread channel must be dropped"
            );
            assert!(
                !state.cache.channels.contains_key(id),
                "{id}: must not be cached"
            );
            assert!(
                !state.subscribed.read().await.contains(id),
                "{id}: must not be subscribed"
            );
            let (add, _) = queued_changes(state.apply_state().await);
            assert!(
                !add.contains(&id.to_string()),
                "{id}: no Redis subscribe: {add:?}"
            );
        }
    }
}
