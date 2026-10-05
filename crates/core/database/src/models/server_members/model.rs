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

        // Protected channels (6.3, decision 11 (W2)): a non-member never
        // legitimately holds a seat. One can be left behind by a removal whose
        // second release failed; it is released before the membership exists,
        // so a rejoin cannot quietly hand decryption access back. Runs after
        // the membership check, so a current member's seats are never touched.
        db.release_channel_seats_for_user(&user.id, Some(&server.id), Timestamp::now_utc())
            .await?;

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
        // Protected channels (6.3, decision 11 (W2)), first release: the user's
        // seats in this server's protected channels, plus a pending removal on
        // each open Text group they are in. It runs before every other step, so
        // a failure has no side effect at all: the membership, the thread rows
        // and every event stay as they were.
        db.release_channel_seats_for_user(
            &self.id.user,
            Some(&self.id.server),
            Timestamp::now_utc(),
        )
        .await?;

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

        // Second release: a seat PUT that landed between the first release and
        // the soft delete could have seated the user again (from here on its
        // membership claim matches nothing). The result is kept, not returned
        // yet: `ServerMemberLeave` below is the only thing that unsubscribes the
        // removed user's live socket, so it must go out once the membership is
        // gone. The error is returned at the very end.
        let released = db
            .release_channel_seats_for_user(
                &self.id.user,
                Some(&self.id.server),
                Timestamp::now_utc(),
            )
            .await;

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

        // A failed second release fails the removal (500, never "removed"),
        // though the membership is gone and the leave event went out. The seat
        // shows to the owner as `seated_without_access`; a ban releases it with
        // no member needed, and a rejoin releases it first (`Member::create`).
        released?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_models::v0::DataCreateServer;
    use revolt_result::ErrorType;

    use crate::{
        Channel, ChannelEntitlement, ChannelEntitlementSource, ChannelEntitlementState,
        ChannelSeat, Database, Member, PartialMember, RemovalIntention, Server, User,
    };

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

    // ---- protected channels: seat release on removal and rejoin ----------
    // (design 6.3, decision 11 (W2))

    const SEATED_HERE: &str = "01J9Z3K4M5N6P7Q8R9S0TMRS01";
    const SEATED_ELSEWHERE: &str = "01J9Z3K4M5N6P7Q8R9S0TMRS02";
    const SEATED_LATER: &str = "01J9Z3K4M5N6P7Q8R9S0TMRS03";

    fn new_server(name: &str) -> DataCreateServer {
        DataCreateServer {
            name: name.to_string(),
            description: None,
            nsfw: None,
        }
    }

    /// An active entitlement for `channel_id` in `server_id`: a server-scoped
    /// release finds the server's protected channels by it
    async fn entitle(db: &Database, channel_id: &str, server_id: &str) {
        let now = Timestamp::now_utc();
        db.upsert_channel_entitlement(
            &ChannelEntitlement {
                id: ulid::Ulid::new().to_string(),
                channel_id: channel_id.to_string(),
                server_id: server_id.to_string(),
                source: ChannelEntitlementSource::AdminGrant,
                slot_cap: 10,
                device_cap: None,
                state: ChannelEntitlementState::Active,
                granted_by: "admin".to_string(),
                created_at: now,
            },
            now,
        )
        .await
        .unwrap();
    }

    /// An ACTIVE seat row written straight to the store, bypassing the seat
    /// PUT (which refuses to seat a non-member)
    async fn seat_raw(db: &Database, channel_id: &str, user_id: &str) {
        let seat = ChannelSeat {
            id: ChannelSeat::composite_id(channel_id, user_id),
            channel_id: channel_id.to_string(),
            user_id: user_id.to_string(),
            seated_at: Timestamp::now_utc(),
            released_at: None,
            cooldown_until: None,
        };
        match db {
            Database::Reference(reference) => {
                reference
                    .channel_seats
                    .lock()
                    .await
                    .insert(seat.id.clone(), seat);
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                mongo
                    .col::<ChannelSeat>("channel_seats")
                    .insert_one(&seat)
                    .await
                    .unwrap();
            }
        }
    }

    /// The user's seat row in `channel_id`
    async fn seat_of(db: &Database, channel_id: &str, user_id: &str) -> ChannelSeat {
        db.fetch_channel_seats_for_user(user_id)
            .await
            .unwrap()
            .into_iter()
            .find(|seat| seat.channel_id == channel_id)
            .expect("a seat row")
    }

    /// A kick releases the member's seat in that server's protected channels
    /// (active to cooling) and leaves their seat in another server alone.
    /// Mutation: both releases removed from `remove`.
    #[tokio::test]
    async fn a_kick_releases_the_seat_in_that_server_only() {
        database_test!(|db| async move {
            let owner = User::create(&db, "01MRS Owner".to_string(), None, None)
                .await
                .unwrap();
            let user = User::create(&db, "01MRS Member".to_string(), None, None)
                .await
                .unwrap();
            let server = Server::create(&db, new_server("01MRS S"), &owner, false)
                .await
                .unwrap()
                .0;
            let other_server = Server::create(&db, new_server("01MRS S2"), &owner, false)
                .await
                .unwrap()
                .0;

            // No timeout on the membership: the reference driver panics on
            // soft-deleting a timed-out member.
            let member = Member::create(&db, &server, &user, None).await.unwrap().0;
            Member::create(&db, &other_server, &user, None)
                .await
                .unwrap();

            entitle(&db, SEATED_HERE, &server.id).await;
            entitle(&db, SEATED_ELSEWHERE, &other_server.id).await;
            seat_raw(&db, SEATED_HERE, &user.id).await;
            seat_raw(&db, SEATED_ELSEWHERE, &user.id).await;

            member
                .remove(&db, &server, RemovalIntention::Kick, false)
                .await
                .unwrap();

            let released = seat_of(&db, SEATED_HERE, &user.id).await;
            assert!(
                !released.is_active(),
                "the kick must release the seat in S: {released:?}"
            );
            assert!(
                released.is_cooling(Timestamp::now_utc()),
                "a released seat cools down: {released:?}"
            );
            assert!(
                seat_of(&db, SEATED_ELSEWHERE, &user.id).await.is_active(),
                "the seat in another server must survive"
            );
            assert!(
                db.fetch_member(&server.id, &user.id).await.is_err(),
                "the member is removed"
            );
        });
    }

    /// A non-member never holds a seat: a rejoin releases one left behind (by
    /// a removal whose second release failed), and a repeated join by a
    /// CURRENT member is refused without touching their seats. Mutations: the
    /// release dropped from `create`; the release moved above the membership
    /// check.
    #[tokio::test]
    async fn a_rejoin_releases_a_seat_left_behind() {
        database_test!(|db| async move {
            let owner = User::create(&db, "01MRJ Owner".to_string(), None, None)
                .await
                .unwrap();
            let user = User::create(&db, "01MRJ Member".to_string(), None, None)
                .await
                .unwrap();
            let server = Server::create(&db, new_server("01MRJ S"), &owner, false)
                .await
                .unwrap()
                .0;

            entitle(&db, SEATED_HERE, &server.id).await;
            entitle(&db, SEATED_LATER, &server.id).await;
            seat_raw(&db, SEATED_HERE, &user.id).await;
            assert!(
                db.fetch_member(&server.id, &user.id).await.is_err(),
                "precondition: the seated user is not a member"
            );

            Member::create(&db, &server, &user, None).await.unwrap();

            let left_behind = seat_of(&db, SEATED_HERE, &user.id).await;
            assert!(
                !left_behind.is_active(),
                "the rejoin must release the seat left behind: {left_behind:?}"
            );

            // Now a member, seated legitimately: a repeated join is refused
            // and releases nothing
            seat_raw(&db, SEATED_LATER, &user.id).await;
            let error = Member::create(&db, &server, &user, None).await.unwrap_err();
            assert!(
                matches!(error.error_type, ErrorType::AlreadyInServer),
                "a repeated join is refused: {error:?}"
            );
            assert!(
                seat_of(&db, SEATED_LATER, &user.id).await.is_active(),
                "a current member's seat must survive a repeated join"
            );
        });
    }

    /// A first release that fails (an undecodable seat row) fails the removal
    /// with no side effect: the membership and the thread rows stay, so no
    /// `ThreadMemberLeave` went out (each one follows a successful thread
    /// leave). MONGODB only: the reference store cannot hold an undecodable
    /// row. Mutation: the first release placed after the thread loop.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn a_failed_first_release_leaves_the_member_and_thread_rows_intact() {
        database_test!(|db| async move {
            let Database::MongoDb(mongo) = &db else {
                return;
            };

            let owner = User::create(&db, "01MRF Owner".to_string(), None, None)
                .await
                .unwrap();
            let user = User::create(&db, "01MRF Member".to_string(), None, None)
                .await
                .unwrap();
            let server = Server::create(&db, new_server("01MRF S"), &owner, false)
                .await
                .unwrap()
                .0;

            let thread = |id: &str| Channel::Thread {
                id: id.to_string(),
                server: server.id.clone(),
                parent_channel: "01MRFPARENT".to_string(),
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
            for id in ["01MRFTHREAD1", "01MRFTHREAD2"] {
                db.insert_channel(&thread(id)).await.unwrap();
            }

            let member = Member::create(&db, &server, &user, None).await.unwrap().0;
            for thread_id in ["01MRFTHREAD1", "01MRFTHREAD2"] {
                assert!(db.join_thread_if_absent(thread_id, &user.id).await.unwrap());
            }

            // `seated_at` is not a timestamp, so every read of the row fails
            entitle(&db, SEATED_HERE, &server.id).await;
            mongo
                .col::<bson::Document>("channel_seats")
                .insert_one(bson::doc! {
                    "_id": ChannelSeat::composite_id(SEATED_HERE, &user.id),
                    "channel_id": SEATED_HERE,
                    "user_id": &user.id,
                    "seated_at": true,
                })
                .await
                .unwrap();
            let precondition = db
                .release_channel_seats_for_user(&user.id, Some(&server.id), Timestamp::now_utc())
                .await;
            assert!(
                precondition.is_err(),
                "precondition: the corrupt row fails a release"
            );

            let removed = member
                .remove(&db, &server, RemovalIntention::Kick, false)
                .await;
            assert!(removed.is_err(), "a failed release must fail the removal");

            assert!(
                db.fetch_member(&server.id, &user.id).await.is_ok(),
                "a failed release must leave the member in place"
            );
            let joined: HashSet<String> = db
                .fetch_joined_thread_ids(&user.id, &server.id)
                .await
                .unwrap()
                .into_iter()
                .collect();
            assert_eq!(
                joined,
                HashSet::from(["01MRFTHREAD1".to_string(), "01MRFTHREAD2".to_string()]),
                "a failed release must leave the thread rows in place"
            );
            assert!(
                db.fetch_thread_members("01MRFTHREAD1")
                    .await
                    .unwrap()
                    .iter()
                    .any(|row| row.id.user == user.id),
                "a failed release must leave the member in T1's member list"
            );
        });
    }

    /// `Member::remove`'s body: comment lines dropped, and whitespace kept
    /// only between two identifier characters, so the needles below do not
    /// depend on line breaks or a trailing comma
    fn remove_body() -> String {
        const SOURCE: &str = include_str!("model.rs");
        let at = SOURCE
            .find("pub async fn remove(")
            .expect("remove is defined");
        let open = at + SOURCE[at..].find('{').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let text = SOURCE[open..=close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ");

        let ident = |ch: char| ch.is_alphanumeric() || ch == '_';
        let chars: Vec<char> = text.chars().collect();
        let mut body = String::new();
        for (i, &ch) in chars.iter().enumerate() {
            if !ch.is_whitespace() {
                body.push(ch);
                continue;
            }
            let before = body.chars().last();
            let after = chars[i + 1..].iter().copied().find(|c| !c.is_whitespace());
            if before.is_some_and(ident) && after.is_some_and(ident) {
                body.push(' ');
            }
        }
        body.replace(",)", ")")
    }

    /// Decision 11 (W2) on `remove`'s text. Fault injection cannot reach the
    /// SECOND release (a corrupt row fails the first one first), so its
    /// handling is held here. In order: the first release, returned, before
    /// the thread loop; the soft delete; the second release KEPT (no `?`, no
    /// `.ok()`); the leave event; the kept result returned as the last
    /// statement before `Ok(())`, with nothing between the two able to return
    /// early. Exactly two releases, and no feature flag. Mutations: `?` on the
    /// second release; the kept result dropped.
    #[test]
    fn remove_releases_first_and_returns_the_kept_second_release_last() {
        const CALL: &str = "release_channel_seats_for_user(";
        const RELEASE: &str = "db.release_channel_seats_for_user(&self.id.user,\
             Some(&self.id.server),Timestamp::now_utc()).await";
        const THREADS: &str = "fetch_joined_thread_ids(";
        const SOFT_DELETE: &str = "db.soft_delete_member(&self.id).await?;";
        const LEAVE: &str = "EventV1::ServerMemberLeave";

        let body = remove_body();
        assert_eq!(
            body.matches(CALL).count(),
            2,
            "remove must release exactly twice: {body}"
        );
        let calls: Vec<usize> = body.match_indices(CALL).map(|(at, _)| at).collect();
        let statement = |at: usize| {
            let start = body[..at]
                .rfind(|c| matches!(c, ';' | '{' | '}'))
                .map_or(0, |i| i + 1);
            let end = at + body[at..].find(';').expect("a statement end") + 1;
            (end, &body[start..end])
        };

        // 1. The first release returns its error, before the thread loop
        let (_, first) = statement(calls[0]);
        assert_eq!(
            first,
            format!("{RELEASE}?;"),
            "the first release must return its error: {body}"
        );
        let threads = body.find(THREADS).expect("the thread loop");
        assert!(
            calls[0] < threads,
            "the first release must run before the thread loop: {body}"
        );

        // 2. The soft delete, after the loop and before the second release
        assert_eq!(
            body.matches(SOFT_DELETE).count(),
            1,
            "one soft delete: {body}"
        );
        let soft_delete = body.find(SOFT_DELETE).expect("counted above");
        assert!(
            threads < soft_delete && soft_delete < calls[1],
            "the soft delete sits between the thread loop and the second release: {body}"
        );

        // 3. The second release is kept: neither returned nor dropped
        let (second_end, second) = statement(calls[1]);
        assert!(
            !second.contains('?') && !second.contains(".ok()"),
            "the second release must be kept, not returned or dropped: {second}"
        );
        let kept = second
            .strip_prefix("let ")
            .and_then(|rest| rest.strip_suffix(format!("={RELEASE};").as_str()))
            .filter(|kept| {
                *kept != "_"
                    && !kept.is_empty()
                    && kept.chars().all(|c| c.is_alphanumeric() || c == '_')
            });
        let Some(kept) = kept else {
            panic!("the second release must be bound, whole, to a name: {second}");
        };

        // 4. The leave event goes out after it
        assert_eq!(body.matches(LEAVE).count(), 1, "one leave event: {body}");
        assert!(
            calls[1] < body.find(LEAVE).expect("counted above"),
            "the leave event follows the second release: {body}"
        );

        // 5. The kept result is the last statement before `Ok(())`, and nothing
        // between the two can return early and skip the leave event
        let tail = format!("{kept}?;Ok(())}}");
        assert!(
            body.ends_with(&tail),
            "the kept second release must be returned last, before `Ok(())`: {body}"
        );
        let between = &body[second_end..body.len() - tail.len()];
        assert!(between.contains(LEAVE), "the leave event is in between");
        for early in ["?", "return"] {
            assert!(
                !between.contains(early),
                "nothing after the second release may return early (`{early}`): {between}"
            );
        }

        // No feature flag gates a release
        for flag in ["config(", "protected_channels"] {
            assert!(
                !body.contains(flag),
                "no flag may gate the removal's releases (`{flag}`): {body}"
            );
        }
    }
}
