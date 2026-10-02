use iso8601_timestamp::Timestamp;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use crate::{
    events::client::EventV1, util::permissions::DatabasePermissionQuery, Channel, Database, File,
    Server, SystemMessage, User,
};

fn default_true() -> bool {
    true
}

fn is_true(x: &bool) -> bool {
    *x
}

auto_derived_partial!(
    /// Server Member
    pub struct Member {
        /// Unique member id
        #[serde(rename = "_id")]
        pub id: MemberCompositeKey,

        /// Time at which this user joined the server
        pub joined_at: Timestamp,

        /// Member's nickname
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nickname: Option<String>,
        /// Member's pronouns
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pronouns: Option<String>,
        /// Avatar attachment
        #[serde(skip_serializing_if = "Option::is_none")]
        pub avatar: Option<File>,

        /// Member's roles
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub roles: Vec<String>,
        /// Timestamp this member is timed out until
        #[serde(skip_serializing_if = "Option::is_none")]
        pub timeout: Option<Timestamp>,

        /// Whether the member is server-wide voice muted
        #[serde(skip_serializing_if = "is_true", default = "default_true")]
        pub can_publish: bool,
        /// Whether the member is server-wide voice deafened
        #[serde(skip_serializing_if = "is_true", default = "default_true")]
        pub can_receive: bool,
        // This value only exists in the database, not the models.
        // If it is not-None, the database layer should return None to member fetching queries.
        // pub pending_deletion_at: Option<Timestamp>
    },
    "PartialMember"
);

auto_derived!(
    /// Composite primary key consisting of server and user id
    #[derive(Hash, Default)]
    pub struct MemberCompositeKey {
        /// Server Id
        pub server: String,
        /// User Id
        pub user: String,
    }

    /// Optional fields on server member object
    pub enum FieldsMember {
        Nickname,
        Pronouns,
        Avatar,
        Roles,
        Timeout,
        CanReceive,
        CanPublish,
        JoinedAt,
        VoiceChannel,
    }

    /// Member removal intention
    pub enum RemovalIntention {
        Leave,
        Kick,
        Ban,
    }
);

impl Default for Member {
    fn default() -> Self {
        Self {
            id: Default::default(),
            joined_at: Timestamp::now_utc(),
            nickname: None,
            pronouns: None,
            avatar: None,
            roles: vec![],
            timeout: None,
            can_publish: true,
            can_receive: true,
        }
    }
}

#[allow(clippy::disallowed_methods)]
impl Member {
    /// Create a new member in a server
    pub async fn create(
        db: &Database,
        server: &Server,
        user: &User,
        channels: Option<Vec<Channel>>,
    ) -> Result<(Member, Vec<Channel>)> {
        if db.fetch_ban(&server.id, &user.id).await.is_ok() {
            return Err(create_error!(Banned));
        }

        if db.fetch_member(&server.id, &user.id).await.is_ok() {
            return Err(create_error!(AlreadyInServer));
        }

        let mut member = Member {
            id: MemberCompositeKey {
                server: server.id.to_string(),
                user: user.id.to_string(),
            },
            ..Default::default()
        };

        if let Some(updated) = db.insert_or_merge_member(&member).await? {
            member = updated;
        }

        let should_fetch = channels.is_none();
        let mut channels = channels.unwrap_or_default();

        if should_fetch {
            let query = DatabasePermissionQuery::new(db, user).server(server);
            let existing_channels = db.fetch_channels(&server.channels).await?;

            for channel in existing_channels {
                let mut channel_query = query.clone().channel(&channel);

                if calculate_channel_permissions(&mut channel_query)
                    .await
                    .has_channel_permission(ChannelPermission::ViewChannel)
                {
                    channels.push(channel);
                }
            }
        }

        let emojis = db.fetch_emoji_by_parent_id(&server.id).await?;
        let stickers = db.fetch_stickers_by_server_id(&server.id).await.unwrap_or_default();

        #[allow(unused_mut)]
        let mut voice_states = Vec::new();

        #[cfg(feature = "voice")]
        for channel in &channels {
            if let Ok(Some(voice_state)) = crate::voice::get_channel_voice_state(
                &crate::voice::UserVoiceChannel::from_channel(channel),
            )
            .await
            {
                voice_states.push(voice_state)
            }
        }

        EventV1::ServerMemberJoin {
            id: server.id.clone(),
            user: user.id.clone(),
            member: member.clone().into(),
        }
        .p(server.id.clone())
        .await;

        EventV1::ServerCreate {
            id: server.id.clone(),
            server: server.clone().into(),
            channels: channels
                .clone()
                .into_iter()
                .map(|channel| channel.into())
                .collect(),
            emojis: emojis.into_iter().map(|emoji| emoji.into()).collect(),
            stickers: stickers.into_iter().map(|s| s.into()).collect(),
            voice_states,
        }
        .private(user.id.clone())
        .await;

        if let Some(id) = server
            .system_messages
            .as_ref()
            .and_then(|x| x.user_joined.as_ref())
        {
            SystemMessage::UserJoined {
                id: user.id.clone(),
            }
            .into_message(id.to_string())
            .send_without_notifications(db, None, None, false, false, false)
            .await
            .ok();
        }

        Ok((member, channels))
    }

    /// Update member data
    pub async fn update(
        &mut self,
        db: &Database,
        partial: PartialMember,
        remove: Vec<FieldsMember>,
    ) -> Result<()> {
        for field in &remove {
            self.remove_field(field);
        }

        self.apply_options(partial.clone());

        db.update_member(&self.id, &partial, remove.clone()).await?;

        EventV1::ServerMemberUpdate {
            id: self.id.clone().into(),
            data: partial.into(),
            clear: remove.into_iter().map(|field| field.into()).collect(),
        }
        .p(self.id.server.clone())
        .await;

        Ok(())
    }

    pub fn remove_field(&mut self, field: &FieldsMember) {
        match field {
            FieldsMember::JoinedAt => {}
            FieldsMember::Avatar => self.avatar = None,
            FieldsMember::Nickname => self.nickname = None,
            FieldsMember::Pronouns => self.pronouns = None,
            FieldsMember::Roles => self.roles.clear(),
            FieldsMember::Timeout => self.timeout = None,
            FieldsMember::CanReceive => self.can_receive = true,
            FieldsMember::CanPublish => self.can_publish = true,
            FieldsMember::VoiceChannel => {}
        }
    }

    /// Get this user's current ranking
    ///
    /// Lower is higher. The owner outranks every role, whatever roles they
    /// hold: an owner with no roles used to rank `i64::MAX`, the very bottom,
    /// so anyone with a moderation permission passed the rank check against them.
    pub fn get_ranking(&self, server: &Server) -> i64 {
        if self.id.user == server.owner {
            return i64::MIN;
        }

        let mut value = i64::MAX;
        for role in &self.roles {
            if let Some(role) = server.roles.get(role) {
                if role.rank < value {
                    value = role.rank;
                }
            }
        }

        value
    }

    /// Check whether this member is in timeout
    pub fn in_timeout(&self) -> bool {
        if let Some(timeout) = self.timeout {
            *timeout > *Timestamp::now_utc()
        } else {
            false
        }
    }

    /// Remove member from server
    pub async fn remove(
        self,
        db: &Database,
        server: &Server,
        intention: RemovalIntention,
        silent: bool,
    ) -> Result<()> {
        // Thread membership cascade: drop the member's thread rows in this server
        // so a departed member stops being a thread push target. This is hygiene,
        // not the gate: the thread push path filters recipients by live server
        // membership itself. Runs before the soft delete and propagates errors, so
        // a failure leaves the member in place and a retried removal redoes it.
        for thread_id in db
            .fetch_joined_thread_ids(&self.id.user, &self.id.server)
            .await?
        {
            db.leave_thread(&thread_id, &self.id.user).await?;
            EventV1::ThreadMemberLeave {
                id: thread_id,
                user: self.id.user.to_string(),
            }
            .p(self.id.server.to_string())
            .await;
        }

        db.soft_delete_member(&self.id).await?;

        // Calendar cascade (slice F): drop the member's RSVP rows for this server so
        // they stop appearing as attendees/counts. Best-effort — a leave/kick/ban must
        // never fail on calendar cleanup; crond reminder + cancel delivery also
        // live-filter by membership as the safety net for exactly this window.
        db.delete_rsvps_for_member(&self.id.server, &self.id.user)
            .await
            .ok();

        // Boost cascade (Discord parity): a departing member's boosts return
        // to their inventory. Best-effort like the RSVP cascade — a
        // leave/kick/ban must never fail on boost cleanup; the crond
        // self-heal recount is the safety net.
        if let Ok(freed) = db
            .deallocate_server_boosts(&self.id.user, &self.id.server, None)
            .await
        {
            if freed > 0 {
                crate::ServerBoost::recount_for_server(db, &self.id.server)
                    .await
                    .ok();
            }
        }

        EventV1::ServerMemberLeave {
            id: self.id.server.to_string(),
            user: self.id.user.to_string(),
            reason: intention.clone().into(),
        }
        .p(self.id.server.to_string())
        .await;

        if !silent {
            if let Some(id) = server
                .system_messages
                .as_ref()
                .and_then(|x| match intention {
                    RemovalIntention::Leave => x.user_left.as_ref(),
                    RemovalIntention::Kick => x.user_kicked.as_ref(),
                    RemovalIntention::Ban => x.user_banned.as_ref(),
                })
            {
                match intention {
                    RemovalIntention::Leave => SystemMessage::UserLeft { id: self.id.user },
                    RemovalIntention::Kick => SystemMessage::UserKicked { id: self.id.user },
                    RemovalIntention::Ban => SystemMessage::UserBanned { id: self.id.user },
                }
                .into_message(id.to_string())
                // TODO: support notifications here in the future?
                .send_without_notifications(db, None, None, false, false, false)
                .await
                .ok();
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_models::v0::DataCreateServer;

    use crate::{Channel, Member, PartialMember, RemovalIntention, Server, User};

    #[tokio::test]
    async fn muted_member_rejoin() {
        database_test!(|db| async move {
            match db {
                crate::Database::Reference(_) => return,
                crate::Database::MongoDb(_) => (),
            }
            let owner = User::create(&db, "Server Owner".to_string(), None, None)
                .await
                .unwrap();

            let kickable_user = User::create(&db, "Member".to_string(), None, None)
                .await
                .unwrap();

            let server = Server::create(
                &db,
                DataCreateServer {
                    name: "Server".to_string(),
                    description: None,
                    nsfw: None,
                },
                &owner,
                false,
            )
            .await
            .unwrap()
            .0;

            Member::create(&db, &server, &owner, None).await.unwrap();
            let mut kickable_member = Member::create(&db, &server, &kickable_user, None)
                .await
                .unwrap()
                .0;

            kickable_member
                .update(
                    &db,
                    PartialMember {
                        timeout: Some(Timestamp::now_utc() + Duration::minutes(5)),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .unwrap();

            assert!(kickable_member.in_timeout());

            kickable_member
                .remove(&db, &server, RemovalIntention::Kick, false)
                .await
                .unwrap();

            let kickable_member = Member::create(&db, &server, &kickable_user, None)
                .await
                .unwrap()
                .0;

            assert!(kickable_member.in_timeout())
        });
    }

    /// Removing a member drops their thread rows in that server (so they stop
    /// being a thread push target) and leaves their rows in other servers alone.
    #[tokio::test]
    async fn remove_drops_thread_memberships_in_that_server_only() {
        database_test!(|db| async move {
            let owner = User::create(&db, "01MRT Owner".to_string(), None, None)
                .await
                .unwrap();
            let user = User::create(&db, "01MRT Member".to_string(), None, None)
                .await
                .unwrap();

            let new_server = |name: &str| DataCreateServer {
                name: name.to_string(),
                description: None,
                nsfw: None,
            };
            let server = Server::create(&db, new_server("01MRT S"), &owner, false)
                .await
                .unwrap()
                .0;
            let other_server = Server::create(&db, new_server("01MRT S2"), &owner, false)
                .await
                .unwrap()
                .0;

            let thread = |id: &str, server: &str| Channel::Thread {
                id: id.to_string(),
                server: server.to_string(),
                parent_channel: "01MRTPARENT".to_string(),
                name: id.to_string(),
                creator: owner.id.clone(),
                origin_message_id: None,
                last_message_id: None,
                archived: false,
                archived_timestamp: None,
                auto_archive_minutes: Channel::default_auto_archive_minutes(),
                locked: false,
                applied_tags: vec![],
            };
            for channel in [
                thread("01MRTTHREAD1", &server.id),
                thread("01MRTTHREAD2", &server.id),
                thread("01MRTTHREAD9", &other_server.id),
            ] {
                db.insert_channel(&channel).await.unwrap();
            }

            // No timeout on either membership: the reference driver panics on
            // soft-deleting a timed-out member.
            let member = Member::create(&db, &server, &user, None).await.unwrap().0;
            Member::create(&db, &other_server, &user, None)
                .await
                .unwrap();

            for thread_id in ["01MRTTHREAD1", "01MRTTHREAD2", "01MRTTHREAD9"] {
                assert!(db.join_thread_if_absent(thread_id, &user.id).await.unwrap());
            }

            let joined: HashSet<String> = db
                .fetch_joined_thread_ids(&user.id, &server.id)
                .await
                .unwrap()
                .into_iter()
                .collect();
            assert_eq!(
                joined,
                HashSet::from(["01MRTTHREAD1".to_string(), "01MRTTHREAD2".to_string()]),
                "precondition: the user has joined both threads in S"
            );

            member
                .remove(&db, &server, RemovalIntention::Ban, false)
                .await
                .unwrap();

            assert!(
                db.fetch_joined_thread_ids(&user.id, &server.id)
                    .await
                    .unwrap()
                    .is_empty(),
                "removal must drop the member's thread rows in S"
            );
            assert!(
                !db.fetch_thread_members("01MRTTHREAD1")
                    .await
                    .unwrap()
                    .iter()
                    .any(|row| row.id.user == user.id),
                "removal must drop the member from T1's member list"
            );
            assert_eq!(
                db.fetch_joined_thread_ids(&user.id, &other_server.id)
                    .await
                    .unwrap(),
                vec!["01MRTTHREAD9".to_string()],
                "thread rows in another server must survive"
            );
        });
    }
}
