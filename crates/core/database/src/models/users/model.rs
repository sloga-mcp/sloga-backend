use std::{collections::HashSet, str::FromStr, time::Duration};

use crate::{
    credential_lookup_error,
    events::client::EventV1,
    is_invalid_session,
    util::email::{email_templates, send_email},
    util::name_filter::contains_blocked_slur,
    Database, File, RatelimitEvent, AMQP,
};

use futures::future::join_all;
use iso8601_timestamp::Timestamp;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use regex::{Regex, RegexBuilder};
use revolt_config::{config, FeaturesLimits};
use revolt_models::v0::{self, UserBadges, UserFlags, UserPerks, USER_BADGES_DYNAMIC_MASK};
use revolt_presence::filter_online;
use revolt_result::{create_error, Result};
use serde_json::json;
use ulid::Ulid;

auto_derived_partial!(
    /// # User
    pub struct User {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Username
        pub username: String,
        /// Discriminator
        pub discriminator: String,
        /// Display name
        #[serde(skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// User's pronouns
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub pronouns: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        /// Avatar attachment
        pub avatar: Option<File>,
        /// Relationships with other users
        #[serde(skip_serializing_if = "Option::is_none")]
        pub relations: Option<Vec<Relationship>>,

        /// Bitfield of user badges
        #[serde(skip_serializing_if = "Option::is_none")]
        pub badges: Option<i32>,
        /// User's current status
        #[serde(skip_serializing_if = "Option::is_none")]
        pub status: Option<UserStatus>,
        /// User's profile page
        #[serde(skip_serializing_if = "Option::is_none")]
        pub profile: Option<UserProfile>,
        /// Who may fetch the user's profile page; absent means everyone
        /// who can already see the user
        #[serde(skip_serializing_if = "Option::is_none")]
        pub profile_visibility: Option<ProfileVisibility>,

        /// Enum of user flags
        #[serde(skip_serializing_if = "Option::is_none")]
        pub flags: Option<i32>,
        /// Whether this user is privileged
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub privileged: bool,
        /// Bot information
        #[serde(skip_serializing_if = "Option::is_none")]
        pub bot: Option<BotInformation>,

        /// Whether this user has opted in to E2EE DMs
        ///
        /// UI hint ONLY — clients derive actual E2EE capability from a
        /// fetched, signature-verified key bundle, never from this flag
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub e2ee_enabled: bool,

        /// Linked streaming channels (public denormalized copy; tokens live
        /// ONLY in the private user_stream_connections collection)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub connections: Option<Vec<UserConnection>>,

        /// Chosen name styling; only the parts the user's current perks
        /// allow are ever sent to clients
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name_style: Option<v0::NameStyle>,
        /// Custom profile badge, set by privileged routes only
        #[serde(skip_serializing_if = "Option::is_none")]
        pub custom_badge: Option<CustomBadge>,
        /// Public Cipher badge, set by the payments fulfil path only and
        /// present only while the membership is active and undisputed
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub cipher: Option<v0::UserCipher>,

        /// Number of qualified referrals (recomputed, never incremented)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub referral_count: Option<i32>,
        /// Whether this user is a pending invitee whose activity is tracked
        #[serde(skip_serializing_if = "Option::is_none")]
        pub referral_pending: Option<bool>,
        /// Epoch ms the user joined through a referral
        #[serde(skip_serializing_if = "Option::is_none")]
        pub welcomed_at: Option<i64>,
        /// Donation state (private, never on the v0 user)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub supporter: Option<Supporter>,
        /// Anti-spam DM state (private, never on the v0 user)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub dm_guard: Option<DmGuard>,

        /// Time until user is unsuspended
        #[serde(skip_serializing_if = "Option::is_none")]
        pub suspended_until: Option<Timestamp>,
        /// Last acknowledged policy change
        pub last_acknowledged_policy_change: Timestamp,
    },
    "PartialUser"
);

auto_derived!(
    /// Optional fields on user object
    pub enum FieldsUser {
        Avatar,
        StatusText,
        StatusPresence,
        StatusActivity,
        ProfileContent,
        ProfileBackground,
        ProfileLinks,
        DisplayName,
        Pronouns,
        Connections,
        NameStyle,
        CustomBadge,

        // internal fields
        Suspension,
        Supporter,
        ReferralPending,
        WelcomedAt,
        ReferralCount,
        DmGuard,
        None,

        // public fields, server-set only
        Cipher,
    }

    /// Platform of a linked streaming channel
    pub enum ConnectionPlatform {
        Twitch,
        YouTube,
        Kick,
    }

    /// Public denormalized copy of a linked streaming channel; never
    /// carries tokens
    pub struct UserConnection {
        pub platform: ConnectionPlatform,
        pub handle: String,
        pub display_name: String,
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub live: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub live_title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub live_since: Option<Timestamp>,
    }

    /// Donation state of a user
    pub struct Supporter {
        /// Sum of claimed USD donations, in cents
        #[serde(default)]
        pub lifetime_usd_cents: i64,
        /// Epoch ms until which the monthly subscription counts as active
        #[serde(skip_serializing_if = "Option::is_none")]
        pub monthly_until: Option<i64>,
        /// Keyed HMACs of the payer emails used to auto-attach renewals
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub payer_hmacs: Vec<String>,
        /// Whether supporter badges are shown (on unless opted out)
        #[serde(default = "show_badges_default")]
        pub show_badges: bool,
    }

    /// Private anti-spam state set by the copy-paste DM detector; never
    /// exposed through any API type
    pub struct DmGuard {
        /// Id of the system report filed when the guard was set
        pub report_id: String,
        /// When the detector flagged the user
        pub flagged_at: Timestamp,
        /// Whether new DMs are paused
        pub paused: bool,
        /// When staff cleared the pause
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cleared_at: Option<Timestamp>,
        /// Distinct recipients that received the repeated content
        pub recipients: u32,
        /// Fingerprint of the repeated content
        pub fingerprint: String,
    }

    /// Custom profile badge
    pub struct CustomBadge {
        /// Badge image
        pub image: File,
        /// Badge label
        pub label: String,
    }

    /// User's relationship with another user (or themselves)
    pub enum RelationshipStatus {
        None,
        User,
        Friend,
        Outgoing,
        Incoming,
        Blocked,
        BlockedOther,
    }

    /// Who may fetch a user's profile page
    pub enum ProfileVisibility {
        /// Anyone who can already see the user (default)
        Everyone,
        /// Friends only
        Friends,
    }

    /// Relationship entry indicating current status with other user
    pub struct Relationship {
        #[serde(rename = "_id")]
        pub id: String,
        pub status: RelationshipStatus,
        /// Note attached to the friend request, only ever present on the
        /// receiving side of a pending request
        #[serde(skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    /// Presence status
    pub enum Presence {
        /// User is online
        Online,
        /// User is not currently available
        Idle,
        /// User is focusing / will only receive mentions
        Focus,
        /// User is busy / will not receive any notifications
        Busy,
        /// User is looking for a group to play with
        LookingForGroup,
        /// User is in a group and looking for more players
        LookingForMore,
        /// User appears to be offline
        Invisible,
    }

    /// User's active status
    #[derive(Default)]
    pub struct UserStatus {
        /// Custom status text
        #[serde(skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        /// Current presence option
        #[serde(skip_serializing_if = "Option::is_none")]
        pub presence: Option<Presence>,
        /// Game or application the user is currently playing, shown to friends
        #[serde(skip_serializing_if = "Option::is_none")]
        pub activity: Option<UserActivity>,
    }

    /// Information about a game or application a user is playing
    pub struct UserActivity {
        /// Name of the game or application being played
        pub name: String,
        /// When the user started playing
        #[serde(skip_serializing_if = "Option::is_none")]
        pub started_at: Option<Timestamp>,
    }

    /// Platform of a self-declared game-account link
    pub enum LinkPlatform {
        Steam,
        EpicGames,
        Rockstar,
        UbisoftConnect,
        Activision,
        BattleNet,
        Xbox,
        PlayStation,
        Nintendo,
        RiotGames,
        EaApp,
        Gog,
        GrindingGearGames,
    }

    /// A self-declared game-account handle shown on the profile.
    ///
    /// Display-only strings — no verification, no OAuth (unlike streaming
    /// connections, which live in their own private collection).
    pub struct ProfileLink {
        /// Platform the handle belongs to
        pub platform: LinkPlatform,
        /// Account handle / player Id on that platform
        pub handle: String,
    }

    /// User's profile
    #[derive(Default)]
    pub struct UserProfile {
        /// Text content on user's profile
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content: Option<String>,
        /// Background visible on user's profile
        #[serde(skip_serializing_if = "Option::is_none")]
        pub background: Option<File>,
        /// Self-declared game-account links
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub links: Vec<ProfileLink>,
    }

    /// Bot information for if the user is a bot
    pub struct BotInformation {
        /// Id of the owner of this bot
        pub owner: String,
    }

    /// Enumeration providing a hint to the type of user we are handling
    pub enum UserHint {
        /// Could be either a user or a bot
        Any,
        /// Only match bots
        Bot,
        /// Only match users
        User,
    }
);

pub static DISCRIMINATOR_SEARCH_SPACE: Lazy<HashSet<String>> = Lazy::new(|| {
    let mut set = (2..9999)
        .map(|v| format!("{:0>4}", v))
        .collect::<HashSet<String>>();

    for discrim in [
        123, 1234, 1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888, 9999, 1488,
    ] {
        set.remove(&format!("{:0>4}", discrim));
    }

    set.into_iter().collect()
});

static BLOCKED_USERNAME_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new("`{3}|(discord|rvlt|guilded|stt)\\.gg|(revolt|stoat|acutest)\\.chat|https?:\\/\\/")
        .case_insensitive(true)
        .build()
        .unwrap()
});

/// Supporter badges are shown unless the user opted out
fn show_badges_default() -> bool {
    true
}

#[allow(clippy::derivable_impls)]
impl Default for User {
    fn default() -> Self {
        Self {
            id: Default::default(),
            username: Default::default(),
            discriminator: Default::default(),
            display_name: Default::default(),
            pronouns: Default::default(),
            avatar: Default::default(),
            relations: Default::default(),
            badges: Default::default(),
            status: Default::default(),
            profile: Default::default(),
            profile_visibility: Default::default(),
            flags: Default::default(),
            privileged: Default::default(),
            bot: Default::default(),
            e2ee_enabled: Default::default(),
            connections: Default::default(),
            name_style: Default::default(),
            custom_badge: Default::default(),
            cipher: Default::default(),
            referral_count: Default::default(),
            referral_pending: Default::default(),
            welcomed_at: Default::default(),
            supporter: Default::default(),
            dm_guard: Default::default(),
            suspended_until: Default::default(),
            last_acknowledged_policy_change: Timestamp::UNIX_EPOCH,
        }
    }
}

#[allow(clippy::disallowed_methods)]
impl User {
    /// Create a new user
    pub async fn create<I, D>(
        db: &Database,
        username: String,
        account_id: I,
        data: D,
    ) -> Result<User>
    where
        I: Into<Option<String>>,
        D: Into<Option<PartialUser>>,
    {
        let new_username = User::sanitise_username(&username).await?;
        User::validate_username(&new_username)?;

        let mut user = User {
            id: account_id.into().unwrap_or_else(|| Ulid::new().to_string()),
            discriminator: User::find_discriminator(db, &new_username, None).await?,
            username: new_username.clone(),
            last_acknowledged_policy_change: Timestamp::now_utc(),
            ..Default::default()
        };

        if let Some(data) = data.into() {
            user.apply_options(data);
        }

        db.insert_user(&user).await?;
        Ok(user)
    }

    /// Get limits for this user
    pub async fn limits(&self) -> FeaturesLimits {
        let config = config().await;

        // The upload perk lays its sizes over `default`, so it also beats
        // `new_user`; it stays off until the config has a `perk` table.
        if let Some(perk) = &config.features.limits.perk {
            if self.perks(crate::now_ms()) & UserPerks::UploadPerk as u32 != 0 {
                let mut limits = config.features.limits.default.clone();
                for (tag, size) in &perk.file_upload_size_limit {
                    limits.file_upload_size_limit.insert(tag.clone(), *size);
                }

                return limits;
            }
        }

        if ulid::Ulid::from_str(&self.id)
            .expect("`ulid`")
            .datetime()
            .elapsed()
            .expect("time went backwards")
            <= Duration::from_secs(3600u64 * config.features.limits.global.new_user_hours as u64)
        {
            config.features.limits.new_user
        } else {
            config.features.limits.default
        }
    }

    /// Get the relationship with another user
    pub fn relationship_with(&self, user_b: &str) -> RelationshipStatus {
        if self.id == user_b {
            return RelationshipStatus::User;
        }

        if let Some(relations) = &self.relations {
            if let Some(relationship) = relations.iter().find(|x| x.id == user_b) {
                return relationship.status.clone();
            }
        }

        RelationshipStatus::None
    }

    pub fn is_friends_with(&self, user_b: &str) -> bool {
        matches!(
            self.relationship_with(user_b),
            RelationshipStatus::Friend | RelationshipStatus::User
        )
    }

    /// Whether new DMs from this user are paused by the anti-spam guard
    pub fn is_dm_paused(&self) -> bool {
        matches!(&self.dm_guard, Some(g) if g.paused && g.cleared_at.is_none())
    }

    /// Check whether two users have a mutual connection
    ///
    /// This will check if user and user_b share a server or a group.
    pub async fn has_mutual_connection(&self, db: &Database, user_b: &str) -> Result<bool> {
        Ok(!db
            .fetch_mutual_server_ids(&self.id, user_b)
            .await?
            .is_empty()
            || !db
                .fetch_mutual_channel_ids(&self.id, user_b)
                .await?
                .is_empty())
    }

    /// Check if this user can acquire another server
    pub async fn can_acquire_server(&self, db: &Database) -> Result<()> {
        // Called BEFORE the join/create: a user already AT the limit must be
        // rejected (`<=` allowed limit+1 servers).
        if db.fetch_server_count(&self.id).await? < self.limits().await.servers {
            Ok(())
        } else {
            Err(create_error!(TooManyServers {
                max: self.limits().await.servers
            }))
        }
    }

    /// Validate a username
    ///
    /// This will check if the username is a blocked name, contains a blocked
    /// pattern, or contains a slur.
    fn validate_username(username: &str) -> Result<()> {
        let username_lowercase = username.to_lowercase();

        // Reserved so nobody can impersonate the platform or its staff.
        //
        // Matching is EXACT against the lowercased name, so near-misses have to
        // be listed individually — blocking "admin" does not block
        // "adminsloga". sanitise_username() runs before this at both call
        // sites, so homoglyph spellings are normalised before we compare.
        //
        // revolt/stoat/acutest are kept: they are the upstream projects and the
        // original working name, and impersonating those is just as confusing.
        const BLOCKED_USERNAMES: &[&str] = &[
            "admin",
            "administrator",
            "moderator",
            "sloga",
            "slogaadmin",
            "adminsloga",
            "slogaadministrator",
            "administratorsloga",
            "slogamod",
            "slogallc",
            "revolt",
            "stoat",
            "acutest",
        ];

        if BLOCKED_USERNAMES.contains(&username_lowercase.as_str())
            || BLOCKED_USERNAME_PATTERNS.is_match(username)
            || contains_blocked_slur(username)
        {
            return Err(create_error!(InvalidUsername));
        }

        Ok(())
    }

    /// Sanitise a username
    ///
    /// This will clean up Unicode homoglyphs and pad to the min username length with underscores.
    async fn sanitise_username(username: &str) -> Result<String> {
        let options = decancer::Options::default().retain_capitalization();
        let mut username = decancer::cure(username, options)
            .map_err(|_| create_error!(InvalidUsername))?
            .to_string();

        let config = revolt_config::config().await;
        let username_length_diff = config
            .api
            .users
            .min_username_length
            .saturating_sub(username.len());
        if username_length_diff > 0 {
            username.push_str(&"_".repeat(username_length_diff))
        }

        Ok(username)
    }

    /// Find a user and session ID from a given token and hint
    #[async_recursion]
    pub async fn from_token(db: &Database, token: &str, hint: UserHint) -> Result<(User, String)> {
        match hint {
            UserHint::Bot => {
                let bot = db
                    .fetch_bot_by_token(token)
                    .await
                    .map_err(credential_lookup_error)?;
                let user = db
                    .fetch_user(&bot.id)
                    .await
                    .map_err(credential_lookup_error)?;
                Ok((user, String::new()))
            }
            UserHint::User => {
                let session = db
                    .fetch_session_by_token(token)
                    .await
                    .map_err(credential_lookup_error)?;
                let user = db
                    .fetch_user(&session.user_id)
                    .await
                    .map_err(credential_lookup_error)?;
                Ok((user, session.id))
            }
            UserHint::Any => match User::from_token(db, token, UserHint::User).await {
                // The bot fallback is only for a token that is not a session
                Err(error) if is_invalid_session(&error) => {
                    User::from_token(db, token, UserHint::Bot).await
                }
                result => result,
            },
        }
    }

    /// Helper function to fetch many users as a mutually connected user
    /// (while optimising the online ID query)
    pub async fn fetch_many_ids_as_mutuals(
        db: &Database,
        perspective: &User,
        ids: &[String],
    ) -> Result<Vec<v0::User>> {
        let online_ids = filter_online(ids).await;

        Ok(
            join_all(db.fetch_users(ids).await?.into_iter().map(|user| async {
                let is_online = online_ids.contains(&user.id);
                user.into_known(perspective, is_online).await
            }))
            .await,
        )
    }

    /// Find a free discriminator for a given username
    pub async fn find_discriminator(
        db: &Database,
        username: &str,
        preferred: Option<(String, String)>,
    ) -> Result<String> {
        let search_space: &HashSet<String> = &DISCRIMINATOR_SEARCH_SPACE;
        let used_discriminators: HashSet<String> = db
            .fetch_discriminators_in_use(username)
            .await?
            .into_iter()
            .collect();

        let available_discriminators: Vec<&String> =
            search_space.difference(&used_discriminators).collect();

        if available_discriminators.is_empty() {
            return Err(create_error!(UsernameTaken));
        }

        if let Some((preferred, target_id)) = preferred {
            if available_discriminators.contains(&&preferred) {
                return Ok(preferred);
            } else {
                if db
                    .has_ratelimited(
                        &target_id,
                        crate::RatelimitEventType::DiscriminatorChange,
                        Duration::from_secs(60 * 60 * 24),
                        1,
                    )
                    .await?
                {
                    return Err(create_error!(DiscriminatorChangeRatelimited));
                }

                RatelimitEvent::create(
                    db,
                    target_id,
                    crate::RatelimitEventType::DiscriminatorChange,
                )
                .await?;
            }
        }

        let mut rng = rand::thread_rng();
        Ok(available_discriminators
            .choose(&mut rng)
            .expect("we can assert this has an element")
            .to_string())
    }

    /// Update a user's username
    pub async fn update_username(&mut self, db: &Database, username: String) -> Result<()> {
        let new_username = User::sanitise_username(&username).await?;
        User::validate_username(&new_username)?;

        if self.username.to_lowercase() == new_username.to_lowercase() {
            self.update(
                db,
                PartialUser {
                    username: Some(new_username),
                    ..Default::default()
                },
                vec![],
            )
            .await
        } else {
            self.update(
                db,
                PartialUser {
                    discriminator: Some(
                        User::find_discriminator(
                            db,
                            &new_username,
                            Some((self.discriminator.to_string(), self.id.clone())),
                        )
                        .await?,
                    ),
                    username: Some(new_username),
                    ..Default::default()
                },
                vec![],
            )
            .await
        }
    }

    /// Set a relationship to another user
    pub async fn set_relationship(
        &mut self,
        db: &Database,
        user_b: &User,
        status: RelationshipStatus,
        note: Option<String>,
    ) -> Result<()> {
        db.set_relationship(&self.id, &user_b.id, &status, note.as_deref())
            .await?;

        if let RelationshipStatus::None | RelationshipStatus::User = status {
            if let Some(relations) = &mut self.relations {
                relations.retain(|relation| relation.id != user_b.id);
            }
        } else {
            let relation = Relationship {
                id: user_b.id.to_string(),
                status,
                note,
            };

            if let Some(relations) = &mut self.relations {
                relations.retain(|relation| relation.id != user_b.id);
                relations.push(relation);
            } else {
                self.relations = Some(vec![relation]);
            }
        }

        Ok(())
    }

    /// Apply a certain relationship between two users
    ///
    /// The note, if any, lands on the target's side of the relationship.
    pub async fn apply_relationship(
        &mut self,
        db: &Database,
        target: &mut User,
        local: RelationshipStatus,
        remote: RelationshipStatus,
        note: Option<String>,
    ) -> Result<()> {
        target.set_relationship(db, self, remote, note).await?;
        self.set_relationship(db, target, local, None).await?;

        EventV1::UserRelationship {
            id: target.id.clone(),
            user: self.clone().into(db, Some(&*target)).await,
        }
        .private(target.id.clone())
        .await;

        EventV1::UserRelationship {
            id: self.id.clone(),
            user: target.clone().into(db, Some(&*self)).await,
        }
        .private(self.id.clone())
        .await;

        Ok(())
    }

    /// Add another user as a friend
    ///
    /// The note, if any, is attached to the target's incoming request and
    /// is discarded again once the request leaves the pending state.
    pub async fn add_friend(
        &mut self,
        db: &Database,
        amqp: &AMQP,
        target: &mut User,
        note: Option<String>,
    ) -> Result<()> {
        match self.relationship_with(&target.id) {
            RelationshipStatus::User => Err(create_error!(NoEffect)),
            RelationshipStatus::Friend => Err(create_error!(AlreadyFriends)),
            RelationshipStatus::Outgoing => Err(create_error!(AlreadySentRequest)),
            RelationshipStatus::Blocked => Err(create_error!(Blocked)),
            RelationshipStatus::BlockedOther => Err(create_error!(BlockedByOther)),
            RelationshipStatus::Incoming => {
                // Accept incoming friend request
                _ = amqp.friend_request_accepted(self, target).await;

                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::Friend,
                    RelationshipStatus::Friend,
                    None,
                )
                .await
            }
            RelationshipStatus::None => {
                // Get this user's current count of outgoing friend requests
                let count = self
                    .relations
                    .as_ref()
                    .map(|relations| {
                        relations
                            .iter()
                            .filter(|r| matches!(r.status, RelationshipStatus::Outgoing))
                            .count()
                    })
                    .unwrap_or_default();

                // If we're over the limit, don't allow creating more requests
                if count >= self.limits().await.outgoing_friend_requests {
                    return Err(create_error!(TooManyPendingFriendRequests {
                        max: self.limits().await.outgoing_friend_requests
                    }));
                }

                _ = amqp.friend_request_received(target, self).await;

                // Send the friend request
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::Outgoing,
                    RelationshipStatus::Incoming,
                    note,
                )
                .await
            }
        }
    }

    /// Remove another user as a friend
    pub async fn remove_friend(&mut self, db: &Database, target: &mut User) -> Result<()> {
        match self.relationship_with(&target.id) {
            RelationshipStatus::Friend
            | RelationshipStatus::Outgoing
            | RelationshipStatus::Incoming => {
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::None,
                    RelationshipStatus::None,
                    None,
                )
                .await
            }
            _ => Err(create_error!(NoEffect)),
        }
    }

    /// Block another user
    pub async fn block_user(&mut self, db: &Database, target: &mut User) -> Result<()> {
        match self.relationship_with(&target.id) {
            RelationshipStatus::User | RelationshipStatus::Blocked => Err(create_error!(NoEffect)),
            RelationshipStatus::BlockedOther => {
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::Blocked,
                    RelationshipStatus::Blocked,
                    None,
                )
                .await?;

                db.delete_respect_between(&self.id, &target.id).await
            }
            RelationshipStatus::None
            | RelationshipStatus::Friend
            | RelationshipStatus::Incoming
            | RelationshipStatus::Outgoing => {
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::Blocked,
                    RelationshipStatus::BlockedOther,
                    None,
                )
                .await?;

                // A block is hostile: neither party's respect stays on the
                // other's wall. (A plain unfriend keeps entries — friendly
                // drift — and either party can still delete their side.)
                db.delete_respect_between(&self.id, &target.id).await
            }
        }
    }

    /// Unblock another user
    pub async fn unblock_user(&mut self, db: &Database, target: &mut User) -> Result<()> {
        match self.relationship_with(&target.id) {
            RelationshipStatus::Blocked => match target.relationship_with(&self.id) {
                RelationshipStatus::Blocked => {
                    self.apply_relationship(
                        db,
                        target,
                        RelationshipStatus::BlockedOther,
                        RelationshipStatus::Blocked,
                        None,
                    )
                    .await
                }
                RelationshipStatus::BlockedOther => {
                    self.apply_relationship(
                        db,
                        target,
                        RelationshipStatus::None,
                        RelationshipStatus::None,
                        None,
                    )
                    .await
                }
                _ => Err(create_error!(InternalError)),
            },
            _ => Err(create_error!(NoEffect)),
        }
    }

    /// Whether an update touches the inputs of the computed badges and perks,
    /// and of the name style, as `(perk_inputs, style_inputs)`
    ///
    /// Badges, perks and name style are computed, so any change to their
    /// inputs has to go out as the computed values, never the stored ones.
    /// Flags count because a deleted account earns none of them.
    fn perk_event_inputs(partial: &PartialUser, remove: &[FieldsUser]) -> (bool, bool) {
        let style_inputs = partial.name_style.is_some()
            || partial.referral_count.is_some()
            || partial.welcomed_at.is_some()
            || partial.supporter.is_some()
            || partial.flags.is_some()
            || remove.iter().any(|field| {
                matches!(
                    field,
                    FieldsUser::Supporter | FieldsUser::WelcomedAt | FieldsUser::ReferralCount
                )
            });
        let perk_inputs =
            style_inputs || partial.badges.is_some() || partial.custom_badge.is_some();

        (perk_inputs, style_inputs)
    }

    /// Update user data
    pub async fn update(
        &mut self,
        db: &Database,
        partial: PartialUser,
        remove: Vec<FieldsUser>,
    ) -> Result<()> {
        for field in &remove {
            self.remove_field(field);
        }

        self.apply_options(partial.clone());
        db.update_user(&self.id, &partial, remove.clone()).await?;

        let (perk_inputs, style_inputs) = Self::perk_event_inputs(&partial, &remove);

        let now = crate::now_ms();
        let mut clear: Vec<v0::FieldsUser> = remove.into_iter().map(|v| v.into()).collect();
        let mut data: v0::PartialUser = partial.into();

        // The stored badge mirrors the membership, but what goes out is the
        // public one (as on every read): while it is hidden (supporter
        // badges opted out, or a deleted account) the event clears it
        // instead of carrying it
        if data.cipher.is_some() && self.public_cipher().is_none() {
            data.cipher = None;
            if !clear.contains(&v0::FieldsUser::Cipher) {
                clear.push(v0::FieldsUser::Cipher);
            }
        }

        if perk_inputs {
            data.badges = Some(self.badges_at(now).await);
            if style_inputs {
                Self::put_name_style(&mut data, &mut clear, self.filtered_name_style(now));
            }
        }

        // Perks are private to the owner, so they never ride the event that
        // fans out to everyone who can see this user
        data.perks = None;

        EventV1::UserUpdate {
            id: self.id.clone(),
            data,
            clear,
            event_id: Some(Ulid::new().to_string()),
        }
        .p_user(self.id.clone(), db)
        .await;

        if perk_inputs {
            self.publish_private_perks(self.perks(now)).await;
        }

        Ok(())
    }

    /// Emit the computed badges, name style and perks without writing
    /// anything, for when a trial or subscription lapses on its own
    pub async fn publish_perks_update(&self, db: &Database) {
        let now = crate::now_ms();
        self.publish_public_perks(db, self.badges_at(now).await, self.filtered_name_style(now))
            .await;
        self.publish_private_perks(self.perks(now)).await;
    }

    /// Like `publish_perks_update`, but each event only goes out if what it
    /// carries differs from the snapshot taken before the change
    pub async fn publish_perks_update_if_changed(
        &self,
        db: &Database,
        before_badges: u32,
        before_style: Option<v0::NameStyle>,
        before_perks: u32,
    ) {
        let now = crate::now_ms();
        let badges = self.badges_at(now).await;
        let name_style = self.filtered_name_style(now);
        if badges != before_badges || name_style != before_style {
            self.publish_public_perks(db, badges, name_style).await;
        }

        let perks = self.perks(now);
        if perks != before_perks {
            self.publish_private_perks(perks).await;
        }
    }

    /// Emit the public Cipher badge to everyone who can see this user if it
    /// differs from `before` (what they saw): the badge when it shows, a
    /// clear when it no longer does. For changes that move the public badge
    /// without touching the stored one (the supporter `show_badges` toggle).
    pub async fn publish_public_cipher_if_changed(
        &self,
        db: &Database,
        before: Option<v0::UserCipher>,
    ) {
        let cipher = self.public_cipher();
        if cipher == before {
            return;
        }

        let clear = if cipher.is_none() {
            vec![v0::FieldsUser::Cipher]
        } else {
            vec![]
        };

        EventV1::UserUpdate {
            id: self.id.clone(),
            data: v0::PartialUser {
                cipher,
                ..Default::default()
            },
            clear,
            event_id: Some(Ulid::new().to_string()),
        }
        .p_user(self.id.clone(), db)
        .await;
    }

    /// Emit the computed badges and filtered name style to everyone who
    /// can see this user
    async fn publish_public_perks(
        &self,
        db: &Database,
        badges: u32,
        name_style: Option<v0::NameStyle>,
    ) {
        let mut data = v0::PartialUser {
            badges: Some(badges),
            ..Default::default()
        };
        let mut clear = Vec::new();
        Self::put_name_style(&mut data, &mut clear, name_style);

        EventV1::UserUpdate {
            id: self.id.clone(),
            data,
            clear,
            event_id: Some(Ulid::new().to_string()),
        }
        .p_user(self.id.clone(), db)
        .await;
    }

    /// Emit the perks to the owner's sessions only
    async fn publish_private_perks(&self, perks: u32) {
        EventV1::UserUpdate {
            id: self.id.clone(),
            data: v0::PartialUser {
                perks: Some(perks),
                ..Default::default()
            },
            clear: vec![],
            event_id: Some(Ulid::new().to_string()),
        }
        .private(self.id.clone())
        .await;
    }

    /// Put the filtered name style on an outgoing user update, clearing it
    /// when nothing is left
    fn put_name_style(
        data: &mut v0::PartialUser,
        clear: &mut Vec<v0::FieldsUser>,
        name_style: Option<v0::NameStyle>,
    ) {
        if name_style.is_none() && !clear.contains(&v0::FieldsUser::NameStyle) {
            clear.push(v0::FieldsUser::NameStyle);
        }
        data.name_style = name_style;
    }

    /// Whether the account has been deleted
    fn is_deleted(&self) -> bool {
        self.flags.unwrap_or_default() & UserFlags::Deleted as i32 != 0
    }

    /// The public Cipher badge: None for a deleted account even if a stale
    /// stored copy outlived `mark_deleted`, and None while the user hides
    /// their supporter badges (`supporter.show_badges`, as for the donation
    /// badges in `compute_badges`). The stored `cipher` keeps mirroring the
    /// membership either way, so turning badges back on shows it again.
    pub fn public_cipher(&self) -> Option<v0::UserCipher> {
        if self.is_deleted() {
            return None;
        }

        if self
            .supporter
            .as_ref()
            .is_some_and(|supporter| !supporter.show_badges)
        {
            return None;
        }

        self.cipher.clone()
    }

    /// Bitfield of perks the user holds at `now_ms`
    ///
    /// The OR of the referral tiers, the donation tiers and the welcome
    /// trial's name color. A deleted account holds none.
    pub fn perks(&self, now_ms: i64) -> u32 {
        if self.is_deleted() {
            return 0;
        }

        let mut perks =
            crate::perks_for_referrals(self.referral_count.unwrap_or_default().max(0) as u32);

        if let Some(supporter) = &self.supporter {
            perks |= crate::perks_for_donations(
                supporter.lifetime_usd_cents,
                supporter.monthly_until.is_some_and(|until| until > now_ms),
            );
        }

        if let Some(welcomed_at) = self.welcomed_at {
            if welcomed_at.saturating_add(crate::WELCOME_TRIAL_DAYS * crate::DAY_MS) > now_ms {
                perks |= UserPerks::NameColour as u32;
            }
        }

        perks
    }

    /// The parts of the stored name style the user's perks allow at
    /// `now_ms`, or None if nothing is left
    ///
    /// The stored choice is kept, so it comes back if the perk returns.
    pub fn filtered_name_style(&self, now_ms: i64) -> Option<v0::NameStyle> {
        let style = self.name_style.as_ref()?;
        let perks = self.perks(now_ms);
        let allowed = |perk: UserPerks| perks & perk as u32 != 0;

        let filtered = v0::NameStyle {
            colour: style
                .colour
                .clone()
                .filter(|_| allowed(UserPerks::NameColour)),
            font: style.font.clone().filter(|_| allowed(UserPerks::NameFont)),
            effect: style
                .effect
                .clone()
                .filter(|_| allowed(UserPerks::NameEffect)),
        };

        if filtered.colour.is_none() && filtered.font.is_none() && filtered.effect.is_none() {
            None
        } else {
            Some(filtered)
        }
    }

    /// Remove a field from User object
    pub fn remove_field(&mut self, field: &FieldsUser) {
        match field {
            FieldsUser::Avatar => self.avatar = None,
            FieldsUser::StatusText => {
                if let Some(x) = self.status.as_mut() {
                    x.text = None;
                }
            }
            FieldsUser::StatusPresence => {
                if let Some(x) = self.status.as_mut() {
                    x.presence = None;
                }
            }
            FieldsUser::StatusActivity => {
                if let Some(x) = self.status.as_mut() {
                    x.activity = None;
                }
            }
            FieldsUser::ProfileContent => {
                if let Some(x) = self.profile.as_mut() {
                    x.content = None;
                }
            }
            FieldsUser::ProfileBackground => {
                if let Some(x) = self.profile.as_mut() {
                    x.background = None;
                }
            }
            FieldsUser::ProfileLinks => {
                if let Some(x) = self.profile.as_mut() {
                    x.links = Vec::new();
                }
            }
            FieldsUser::DisplayName => self.display_name = None,
            FieldsUser::Pronouns => self.pronouns = None,
            FieldsUser::Connections => self.connections = None,
            FieldsUser::NameStyle => self.name_style = None,
            FieldsUser::CustomBadge => self.custom_badge = None,
            FieldsUser::Suspension => self.suspended_until = None,
            FieldsUser::Supporter => self.supporter = None,
            FieldsUser::ReferralPending => self.referral_pending = None,
            FieldsUser::WelcomedAt => self.welcomed_at = None,
            FieldsUser::ReferralCount => self.referral_count = None,
            FieldsUser::DmGuard => self.dm_guard = None,
            FieldsUser::None => {}
            FieldsUser::Cipher => self.cipher = None,
        }
    }

    /// Suspend the user
    ///
    /// - If a duration is specified, the user will be automatically unsuspended after the given time.
    /// - If a reason is specified, an email will be sent.
    pub async fn suspend(
        &mut self,
        db: &Database,
        duration_days: Option<usize>,
        reason: Option<Vec<String>>,
    ) -> Result<()> {
        let mut account = db.fetch_account(&self.id).await?;

        account.disable(db).await?;

        account.delete_all_sessions(db, None).await?;

        self.update(
            db,
            PartialUser {
                flags: Some(UserFlags::SuspendedUntil as i32),
                suspended_until: duration_days.and_then(|dur| {
                    Timestamp::now_utc().checked_add(iso8601_timestamp::Duration::days(dur as i64))
                }),
                ..Default::default()
            },
            vec![],
        )
        .await?;

        if let Some(reason) = reason {
            let config = config().await;

            if !config.api.smtp.host.is_empty() {
                let templates = email_templates().await;

                send_email(
                    &config.api.smtp,
                    account.email.clone(),
                    &templates.suspension,
                    json!({
                        "email": account.email,
                        "list": reason.join(", "),
                        "duration": duration_days,
                        "duration_display": if duration_days.is_some() {
                            "block"
                        } else {
                            "none"
                        }
                    }),
                )
                .map_err(|_| create_error!(InternalError))?;
            }
        }

        Ok(())
    }

    /// Unsuspend the user
    pub async fn unsuspend(&mut self, db: &Database) -> Result<()> {
        // Re-enable the account so the user can log in again
        let mut account = db.fetch_account(&self.id).await?;
        account.disabled = false;
        account.save(db).await?;

        self.update(
            db,
            PartialUser {
                flags: Some(0),
                suspended_until: None,
                ..Default::default()
            },
            vec![FieldsUser::Suspension],
        )
        .await
    }

    /// Permanently ban the user
    ///
    /// - If a reason is specified, an email will be sent.
    pub async fn ban(&mut self, _db: &Database, _reason: Option<String>) -> Result<()> {
        // Send ban email (if reason provided)
        unimplemented!()
    }

    /// Mark as deleted
    pub async fn mark_deleted(&mut self, db: &Database) -> Result<()> {
        self.update(
            db,
            PartialUser {
                username: Some(format!("Deleted User {}", self.id)),
                discriminator: Some("0000".to_string()),
                flags: Some(2),
                relations: Some(Vec::new()),
                ..Default::default()
            },
            vec![
                FieldsUser::Avatar,
                FieldsUser::StatusText,
                FieldsUser::StatusPresence,
                FieldsUser::ProfileContent,
                FieldsUser::ProfileBackground,
                // Links, display name and pronouns are PII the same way the
                // bio is — a deleted account must not keep advertising its
                // Steam handle or name.
                FieldsUser::ProfileLinks,
                FieldsUser::DisplayName,
                FieldsUser::Pronouns,
                FieldsUser::Connections,
                FieldsUser::Suspension,
                FieldsUser::NameStyle,
                FieldsUser::CustomBadge,
                FieldsUser::Supporter,
                FieldsUser::ReferralPending,
                FieldsUser::WelcomedAt,
                FieldsUser::ReferralCount,
                // A deleted account never keeps a public Cipher badge
                FieldsUser::Cipher,
            ],
        )
        .await
    }

    /// Gets the user's badges along with calculating any dynamic badges
    pub async fn get_badges(&self) -> u32 {
        self.badges_at(crate::now_ms()).await
    }

    /// The user's badges at `now_ms`
    async fn badges_at(&self, now_ms: i64) -> u32 {
        let config = config().await;
        self.compute_badges(config.api.users.early_adopter_cutoff, now_ms)
    }

    /// Stored badges with every dynamic bit stripped, then the dynamic
    /// badges recomputed from scratch, so a stale stored copy of one can
    /// never outlive what it was earned by
    ///
    /// A deleted account earns no dynamic badges.
    fn compute_badges(&self, early_adopter_cutoff: Option<u64>, now_ms: i64) -> u32 {
        let mut badges = (self.badges.unwrap_or_default() as u32) & !USER_BADGES_DYNAMIC_MASK;

        if self.is_deleted() {
            return badges;
        }

        if let Some(cutoff) = early_adopter_cutoff {
            if Ulid::from_string(&self.id).is_ok_and(|id| id.timestamp_ms() < cutoff) {
                badges |= UserBadges::EarlyAdopter as u32;
            }
        }

        badges |=
            crate::badges_for_referrals(self.referral_count.unwrap_or_default().max(0) as u32);

        if self.welcomed_at.is_some() {
            badges |= UserBadges::Welcomed as u32;
        }

        if let Some(supporter) = &self.supporter {
            if supporter.show_badges {
                badges |= crate::badges_for_donations(
                    supporter.lifetime_usd_cents,
                    supporter.monthly_until.is_some_and(|until| until > now_ms),
                );
            }
        }

        badges
    }

    /// Removes all relationships which include the user
    pub async fn clear_relationships(&self, db: &Database) -> Result<()> {
        let user_ids = self
            .relations
            .iter()
            .flatten()
            .map(|relation| relation.id.clone())
            .collect();

        db.clear_user_relationships(&self.id, user_ids).await
    }

    /// Removes user from all joined groups
    pub async fn remove_from_all_groups(&self, db: &Database) -> Result<()> {
        let mut generator = db.find_group_message_channels(&self.id).await?;

        while let Some(groups) = generator.next_n(100).await? {
            let ids = groups
                .into_iter()
                .map(|channel| channel.id().to_string())
                .collect();

            db.remove_user_from_groups(ids, &self.id).await?;
        }

        Ok(())
    }

    /// Deletes the user along with:
    /// - deletes owned bots, servers and messages
    /// - removes user from all groups
    /// - releases the user's seat in every protected channel (and queues
    ///   their removal from each open Text group) BEFORE clearing their
    ///   server memberships; a failed release aborts the deletion with the
    ///   memberships intact. A second release after the memberships are
    ///   cleared catches a seat granted in between; its failure aborts the
    ///   deletion too
    /// - clears relationships
    pub async fn delete(&mut self, db: &Database) -> Result<()> {
        for bot in db.fetch_bots_by_user(&self.id).await? {
            bot.delete(db).await?;
        }

        for server in db.fetch_owned_servers(&self.id).await? {
            server.delete(db).await?;
        }

        self.remove_from_all_groups(db).await?;

        // Protected channels (design 6.3): `clear_memberships` bypasses
        // `Member::remove`, so release here, across every server (`None`),
        // and before the memberships go, so a failure never leaves a
        // non-member holding a seat. Servers this account owns, and their
        // protected channels, were deleted above. The released seat rows
        // are kept.
        db.release_channel_seats_for_user(&self.id, None, Timestamp::now_utc())
            .await?;
        db.clear_memberships(&self.id).await?;
        // Second release, as `Member::remove` runs one (decision 11 (W2),
        // audit C6): a seat PUT that landed between the first release and
        // `clear_memberships` could have seated the user again. It fails
        // closed: the deletion stops with the memberships gone, the account
        // is not marked deleted, and the retry (crond's next run) releases
        // first again. Unlike `Member::remove`'s, its error is not kept:
        // `clear_memberships` sends no leave event that has to go out first.
        db.release_channel_seats_for_user(&self.id, None, Timestamp::now_utc())
            .await?;
        // Calendar cascade (slice F): `clear_memberships` bypasses `Member::remove`,
        // so the per-server RSVP cascade never runs — drop every RSVP row the account
        // holds, or attendee lists would keep a ghost user id forever.
        db.delete_rsvps_for_user(&self.id).await?;

        // Boost cascade: `clear_memberships` bypasses `Member::remove` too,
        // so delete every slot this account owns here and recount the
        // servers that held allocations — otherwise phantom boosts from a
        // nonexistent user keep propping up perk tiers forever.
        for server_id in db.delete_server_boosts_by_user(&self.id).await? {
            crate::ServerBoost::recount_for_server(db, &server_id)
                .await
                .ok();
        }

        // Referral and donation cascade: the account's code goes, a referral
        // it is still pending on as the invitee goes (settled ones stay, the
        // referrer earned them), donations are unlinked with their payer
        // HMACs wiped, and unused claim codes and the badge image go.
        db.delete_referral_codes_by_user(&self.id).await?;
        if let Some(referral) = db.fetch_referral(&self.id).await? {
            if referral.status == crate::ReferralStatus::Pending {
                db.delete_referral(&self.id).await?;
            }
        }
        db.unlink_donations_by_user(&self.id).await?;
        db.delete_claim_codes_by_user(&self.id).await?;
        if let Some(badge) = &self.custom_badge {
            // Best-effort: a vanished file row must not block the deletion
            db.mark_attachment_as_deleted(&badge.image.id).await.ok();
        }

        self.clear_relationships(db).await?;

        // Respect cascade: drop every wall entry the account appears in, on
        // either side — rows on a deleted target's wall would be
        // undeletable, and rows authored by the account would ghost-attribute
        // "Deleted User" forever.
        db.delete_respect_involving(&self.id).await?;

        db.delete_messages_by_user(&self.id).await?;

        // E2EE cascade: remove all device identities, prekeys and queued
        // envelopes, notifying peers of each removed device
        for device_id in db.delete_all_e2ee_devices(&self.id).await? {
            crate::E2EEIdentity::broadcast_device_change(
                db,
                &self.id,
                crate::events::client::EventV1::E2EEDeviceDelete {
                    user_id: self.id.to_string(),
                    device_id,
                },
            )
            .await;
        }

        // Key backups are NOT removed by device revocation (a lost device
        // must keep its recovery path), so the account-deletion cascade is
        // where they die — the ONLY implicit deletion of a backup (design §5).
        db.delete_all_e2ee_backups(&self.id).await?;

        // Streaming connections hold YouTube refresh tokens — revoke
        // (best-effort) and delete here or they outlive the account and the
        // live poller keeps touching a deleted user.
        crate::StreamConnection::delete_all_for_user(db, &self.id, true).await?;

        self.mark_deleted(db).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use revolt_models::v0::{self, UserBadges, UserFlags, UserPerks, USER_BADGES_DYNAMIC_MASK};

    use crate::{FieldsUser, PartialUser, Supporter, User};

    #[test]
    fn username_validation_blocked_names() {
        // Mixed case on purpose: matching is done on the lowercased name.
        for blocked in [
            "Admin",
            "Administrator",
            "Moderator",
            "Sloga",
            "SlogaAdmin",
            "adminsloga",
            "slogaadministrator",
            "AdministratorSloga",
            "slogamod",
            "SlogaLLC",
            "Revolt",
            "Stoat",
            "Acutest",
        ] {
            assert!(
                User::validate_username(blocked).is_err(),
                "expected {blocked:?} to be reserved"
            );
        }

        // Names that merely contain a reserved word are still allowed; the
        // match is exact, and over-blocking would catch innocent usernames.
        for allowed in ["Allowed", "Slogan", "SlogaFan", "modest"] {
            assert!(
                User::validate_username(allowed).is_ok(),
                "expected {allowed:?} to be allowed"
            );
        }
    }

    #[test]
    fn username_validation_blocked_patterns() {
        let username_grave = "```_test";
        let username_discord = "discord.gg_test";
        let username_rvlt = "rvlt.gg_test";
        let username_guilded = "guilded.gg_test";
        let username_stt = "stt.gg_test";
        let username_revolt = "revolt.chat_test";
        let username_stoat = "stoat.chat_test";
        let username_http = "http://_test";
        let username_https = "https://_test";

        assert!(User::validate_username(username_grave).is_err());
        assert!(User::validate_username(username_discord).is_err());
        assert!(User::validate_username(username_rvlt).is_err());
        assert!(User::validate_username(username_guilded).is_err());
        assert!(User::validate_username(username_stt).is_err());
        assert!(User::validate_username(username_revolt).is_err());
        assert!(User::validate_username(username_stoat).is_err());
        assert!(User::validate_username(username_http).is_err());
        assert!(User::validate_username(username_https).is_err());
    }

    #[tokio::test]
    async fn username_sanitisation_clean() {
        let username_clean = "Test";

        let username_clean_sanitised = User::sanitise_username(username_clean).await;

        assert!(username_clean_sanitised.is_ok());
        assert_eq!(username_clean, username_clean_sanitised.unwrap());
    }

    #[tokio::test]
    async fn username_sanitisation_homoglyphs() {
        let username_homoglyphs = "𝔽𝕌Ňℕｙ";

        let username_homoglyphs_sanitised =
            User::sanitise_username(username_homoglyphs).await.unwrap();

        assert_ne!(username_homoglyphs, username_homoglyphs_sanitised);
        assert_eq!("funny", username_homoglyphs_sanitised);
    }

    #[test]
    fn username_validation_slurs() {
        // The filter itself is covered in `util::name_filter`; this pins the
        // fact that usernames actually go through it.
        assert!(User::validate_username("N1gg3r").is_err());
        assert!(User::validate_username("Spicy").is_ok());
    }

    #[tokio::test]
    async fn username_sanitisation_padding() {
        let username_padding = "a";

        let username = User::sanitise_username(username_padding).await.unwrap();

        assert_eq!("a_", username);
    }

    const NOW: i64 = 1_800_000_000_000;

    fn supporter(
        lifetime_usd_cents: i64,
        monthly_until: Option<i64>,
        show_badges: bool,
    ) -> Supporter {
        Supporter {
            lifetime_usd_cents,
            monthly_until,
            payer_hmacs: vec![],
            show_badges,
        }
    }

    fn full_style() -> v0::NameStyle {
        v0::NameStyle {
            colour: Some("#ff0000".to_string()),
            font: Some(v0::NameFont::Mono),
            effect: Some(v0::NameEffect::Glow),
        }
    }

    #[test]
    fn perks_none_by_default() {
        assert_eq!(User::default().perks(NOW), 0);

        // A corrupt negative count must not wrap into a huge tier
        let user = User {
            referral_count: Some(-5),
            ..Default::default()
        };
        assert_eq!(user.perks(NOW), 0);
    }

    #[test]
    fn perks_from_referrals() {
        let user = User {
            referral_count: Some(crate::TIER_NAME_COLOUR as i32),
            ..Default::default()
        };
        assert_eq!(user.perks(NOW), UserPerks::NameColour as u32);

        let user = User {
            referral_count: Some(crate::TIER_NAME_COLOUR as i32 - 1),
            ..Default::default()
        };
        assert_eq!(user.perks(NOW) & UserPerks::NameColour as u32, 0);
    }

    #[test]
    fn perks_welcome_trial_expires() {
        let trial = crate::WELCOME_TRIAL_DAYS * crate::DAY_MS;

        let fresh = User {
            welcomed_at: Some(NOW - trial + 1),
            ..Default::default()
        };
        assert_eq!(fresh.perks(NOW), UserPerks::NameColour as u32);

        let lapsed = User {
            welcomed_at: Some(NOW - trial),
            ..Default::default()
        };
        assert_eq!(lapsed.perks(NOW), 0);
    }

    #[test]
    fn perks_from_monthly_support_lapse() {
        let active = User {
            supporter: Some(supporter(0, Some(NOW + 1), true)),
            ..Default::default()
        };
        assert_ne!(active.perks(NOW) & UserPerks::NameColour as u32, 0);

        let lapsed = User {
            supporter: Some(supporter(0, Some(NOW), true)),
            ..Default::default()
        };
        assert_eq!(lapsed.perks(NOW), 0);

        // Hiding badges never takes perks away
        let hidden = User {
            supporter: Some(supporter(0, Some(NOW + 1), false)),
            ..Default::default()
        };
        assert_eq!(hidden.perks(NOW), active.perks(NOW));
    }

    #[test]
    fn name_style_filtered_by_perks() {
        let no_perks = User {
            name_style: Some(full_style()),
            ..Default::default()
        };
        assert_eq!(no_perks.filtered_name_style(NOW), None);

        let colour_only = User {
            name_style: Some(full_style()),
            referral_count: Some(crate::TIER_NAME_COLOUR as i32),
            ..Default::default()
        };
        assert_eq!(
            colour_only.filtered_name_style(NOW),
            Some(v0::NameStyle {
                colour: Some("#ff0000".to_string()),
                font: None,
                effect: None,
            })
        );

        let everything = User {
            name_style: Some(full_style()),
            referral_count: Some(crate::TIER_NAME_EFFECT as i32),
            ..Default::default()
        };
        assert_eq!(everything.filtered_name_style(NOW), Some(full_style()));

        // A font alone, without the font perk, leaves nothing
        let font_only = User {
            name_style: Some(v0::NameStyle {
                colour: None,
                font: Some(v0::NameFont::Serif),
                effect: None,
            }),
            referral_count: Some(crate::TIER_NAME_COLOUR as i32),
            ..Default::default()
        };
        assert_eq!(font_only.filtered_name_style(NOW), None);

        let unset = User {
            referral_count: Some(crate::TIER_NAME_EFFECT as i32),
            ..Default::default()
        };
        assert_eq!(unset.filtered_name_style(NOW), None);
    }

    #[test]
    fn badges_strip_stored_dynamic_bits() {
        let dynamic = UserBadges::Supporter as u32
            | UserBadges::ActiveSupporter as u32
            | UserBadges::EarlyAdopter as u32
            | UserBadges::Welcomed as u32
            | UserBadges::Recruiter as u32
            | UserBadges::RecruiterElite as u32
            | UserBadges::Patron as u32;
        assert_eq!(dynamic, USER_BADGES_DYNAMIC_MASK);

        let user = User {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            badges: Some((dynamic | UserBadges::Developer as u32) as i32),
            ..Default::default()
        };
        assert_eq!(user.compute_badges(None, NOW), UserBadges::Developer as u32);
    }

    #[test]
    fn badges_early_adopter_is_ored_not_added() {
        // 01ARZ3NDEKTSV4RRFFQ69G5FAV was minted at 1469922850259 ms
        let user = User {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            badges: Some(UserBadges::EarlyAdopter as i32),
            ..Default::default()
        };
        assert_eq!(
            user.compute_badges(Some(1_500_000_000_000), NOW),
            UserBadges::EarlyAdopter as u32
        );
        assert_eq!(user.compute_badges(Some(1_400_000_000_000), NOW), 0);
    }

    #[test]
    fn badges_malformed_id_fails_closed() {
        // `I`, `L`, `O` and `U` are not Crockford base32, so this id does not
        // decode; it must fall through to the stored badges, never panic
        let user = User {
            id: "01USER0000000000000000BIT1".to_string(),
            badges: Some(UserBadges::Developer as i32),
            ..Default::default()
        };
        assert!(ulid::Ulid::from_string(&user.id).is_err());
        assert_eq!(
            user.compute_badges(Some(u64::MAX), NOW),
            UserBadges::Developer as u32
        );
    }

    #[test]
    fn badges_computed_from_referrals_and_support() {
        let user = User {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            referral_count: Some(crate::TIER_BADGE as i32),
            welcomed_at: Some(0),
            supporter: Some(supporter(crate::DONATION_PATRON_CENTS, Some(NOW + 1), true)),
            ..Default::default()
        };
        let badges = user.compute_badges(None, NOW);
        for bit in [
            UserBadges::Recruiter,
            UserBadges::Welcomed,
            UserBadges::Supporter,
            UserBadges::Patron,
            UserBadges::ActiveSupporter,
        ] {
            assert_ne!(badges & bit as u32, 0);
        }

        // Opting out hides every donation badge but keeps the rest
        let hidden = User {
            supporter: Some(supporter(
                crate::DONATION_PATRON_CENTS,
                Some(NOW + 1),
                false,
            )),
            ..user
        };
        assert_eq!(
            hidden.compute_badges(None, NOW),
            UserBadges::Recruiter as u32 | UserBadges::Welcomed as u32
        );
    }

    #[test]
    fn deleted_user_has_no_perks_or_computed_badges() {
        let user = User {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            badges: Some((USER_BADGES_DYNAMIC_MASK | UserBadges::Developer as u32) as i32),
            flags: Some(UserFlags::Deleted as i32),
            name_style: Some(full_style()),
            referral_count: Some(crate::TIER_CUSTOM_BADGE as i32),
            welcomed_at: Some(NOW),
            supporter: Some(supporter(crate::DONATION_PATRON_CENTS, Some(NOW + 1), true)),
            ..Default::default()
        };

        assert_eq!(user.perks(NOW), 0);
        assert_eq!(user.filtered_name_style(NOW), None);
        // Stored non-dynamic badges still pass through the mask
        assert_eq!(
            user.compute_badges(Some(1_500_000_000_000), NOW),
            UserBadges::Developer as u32
        );

        // Other flags leave everything alone
        let suspended = User {
            flags: Some(UserFlags::SuspendedUntil as i32),
            ..user
        };
        assert_ne!(suspended.perks(NOW), 0);
        assert_ne!(
            suspended.compute_badges(None, NOW) & UserBadges::Recruiter as u32,
            0
        );
    }

    #[test]
    fn cipher_hidden_for_deleted_user_and_cleared_on_remove() {
        let badge = v0::UserCipher {
            number: 42,
            tier: v0::CipherTier::T299,
        };

        let mut user = User {
            cipher: Some(badge.clone()),
            ..Default::default()
        };
        assert_eq!(user.public_cipher(), Some(badge.clone()));

        // A stale stored copy never shows on a deleted account
        let deleted = User {
            flags: Some(UserFlags::Deleted as i32),
            ..user.clone()
        };
        assert_eq!(deleted.public_cipher(), None);

        // Other flags leave it alone
        let suspended = User {
            flags: Some(UserFlags::SuspendedUntil as i32),
            ..user.clone()
        };
        assert_eq!(suspended.public_cipher(), Some(badge));

        user.remove_field(&FieldsUser::Cipher);
        assert_eq!(user.cipher, None);
        assert_eq!(user.public_cipher(), None);
    }

    #[test]
    fn cipher_follows_the_show_badges_preference() {
        let badge = v0::UserCipher {
            number: 7,
            tier: v0::CipherTier::T99,
        };
        let supporter = |show_badges| Supporter {
            lifetime_usd_cents: 0,
            monthly_until: None,
            payer_hmacs: vec![],
            show_badges,
        };

        // Never a supporter: shown
        let user = User {
            cipher: Some(badge.clone()),
            ..Default::default()
        };
        assert_eq!(user.public_cipher(), Some(badge.clone()));

        // Opted out: hidden from the public projection, still stored
        let hidden = User {
            supporter: Some(supporter(false)),
            ..user.clone()
        };
        assert_eq!(hidden.public_cipher(), None);
        assert_eq!(hidden.cipher, Some(badge.clone()));

        // Opted back in: shown again
        let shown = User {
            supporter: Some(supporter(true)),
            ..user
        };
        assert_eq!(shown.public_cipher(), Some(badge));
    }

    #[test]
    fn perk_event_inputs_include_flags() {
        let inputs =
            |partial: PartialUser, remove: &[FieldsUser]| User::perk_event_inputs(&partial, remove);

        // Deleting an account zeroes its perks and dynamic badges
        assert_eq!(
            inputs(
                PartialUser {
                    flags: Some(UserFlags::Deleted as i32),
                    ..Default::default()
                },
                &[]
            ),
            (true, true)
        );

        // Unrelated fields emit nothing extra
        assert_eq!(
            inputs(
                PartialUser {
                    display_name: Some("Name".to_string()),
                    ..Default::default()
                },
                &[FieldsUser::DisplayName]
            ),
            (false, false)
        );

        // Existing triggers are unchanged
        assert_eq!(
            inputs(
                PartialUser {
                    referral_count: Some(1),
                    ..Default::default()
                },
                &[]
            ),
            (true, true)
        );
        assert_eq!(
            inputs(Default::default(), &[FieldsUser::Supporter]),
            (true, true)
        );
        assert_eq!(
            inputs(
                PartialUser {
                    badges: Some(1),
                    ..Default::default()
                },
                &[]
            ),
            (true, false)
        );
    }

    #[test]
    fn supporter_show_badges_defaults_on() {
        let parsed: Supporter = serde_json::from_str(r#"{"lifetime_usd_cents":1000}"#).unwrap();
        assert!(parsed.show_badges);
        assert!(parsed.payer_hmacs.is_empty());
        assert_eq!(parsed.monthly_until, None);

        // A record created by an HMAC claim before any total was written
        let parsed: Supporter =
            serde_json::from_str(r#"{"payer_hmacs":["abc"],"show_badges":false}"#).unwrap();
        assert_eq!(parsed.lifetime_usd_cents, 0);
        assert_eq!(parsed.payer_hmacs, vec!["abc".to_string()]);
        assert!(!parsed.show_badges);
        assert_eq!(parsed.monthly_until, None);
    }

    #[tokio::test]
    async fn create_user() {
        use revolt_result::Result;

        database_test!(|db| async move {
            let mut created_clean = User::create(&db, "Test".to_string(), None, None)
                .await
                .unwrap();

            assert_eq!("Test", created_clean.username);

            created_clean
                .update_username(&db, "Test2".to_string())
                .await
                .unwrap();

            assert_eq!("Test2", created_clean.username);

            let created_invalid_result: Result<_> =
                User::create(&db, "stoat.chat".to_string(), None, None).await;

            assert!(created_invalid_result.is_err());

            let mut updated_invalid = User::create(&db, "Test".to_string(), None, None)
                .await
                .unwrap();

            let updated_invalid_update_result = updated_invalid
                .update_username(&db, "http://test".to_string())
                .await;

            assert!(updated_invalid_update_result.is_err());
        });
    }

    fn from_token_session(id: &str, user_id: &str, token: &str) -> crate::Session {
        crate::Session {
            id: id.to_string(),
            user_id: user_id.to_string(),
            token: token.to_string(),
            name: "test".to_string(),
            last_seen: iso8601_timestamp::Timestamp::now_utc(),
            origin: None,
            subscription: None,
        }
    }

    fn from_token_assert_invalid_session(
        result: revolt_result::Result<(User, String)>,
        case: &str,
    ) {
        match result {
            Err(error) => assert!(
                matches!(error.error_type, revolt_result::ErrorType::InvalidSession),
                "{case}: expected InvalidSession, got {:?}",
                error.error_type
            ),
            Ok((user, session_id)) => panic!(
                "{case}: expected InvalidSession, got user {} session {session_id:?}",
                user.id
            ),
        }
    }

    #[tokio::test]
    async fn from_token_unknown_token_is_invalid_session() {
        use crate::UserHint;

        database_test!(|db| async move {
            for hint in [UserHint::Any, UserHint::User, UserHint::Bot] {
                let case = format!("{hint:?}");
                from_token_assert_invalid_session(
                    User::from_token(&db, "token-that-does-not-exist", hint).await,
                    &case,
                );
            }
        });
    }

    #[tokio::test]
    async fn from_token_any_accepts_a_session() {
        use crate::UserHint;

        database_test!(|db| async move {
            let user = User::create(&db, "Session".to_string(), None, None)
                .await
                .unwrap();
            let session = from_token_session(
                "01SESSIONFROMTOKENVALID0000",
                &user.id,
                "token-from-token-valid-session",
            );
            db.save_session(&session).await.unwrap();

            let (found, session_id) = User::from_token(&db, &session.token, UserHint::Any)
                .await
                .unwrap();
            assert_eq!(found.id, user.id);
            assert_eq!(session_id, session.id);
        });
    }

    #[tokio::test]
    async fn from_token_any_accepts_a_bot() {
        use crate::{Bot, PartialBot, UserHint};

        database_test!(|db| async move {
            let owner = User::create(&db, "Owner".to_string(), None, None)
                .await
                .unwrap();
            let (bot, _) = Bot::create(&db, "Bot".to_string(), &owner, None::<PartialBot>)
                .await
                .unwrap();

            let (found, session_id) = User::from_token(&db, &bot.token, UserHint::Any)
                .await
                .unwrap();
            assert_eq!(found.id, bot.id);
            assert!(session_id.is_empty());
        });
    }

    #[tokio::test]
    async fn from_token_orphaned_session_user_hint_is_invalid_session() {
        use crate::UserHint;

        database_test!(|db| async move {
            // The session's user doc never existed
            let session = from_token_session(
                "01SESSIONFROMTOKENORPHANU00",
                "01USERFROMTOKENMISSING00000",
                "token-from-token-orphaned-session-user",
            );
            db.save_session(&session).await.unwrap();

            from_token_assert_invalid_session(
                User::from_token(&db, &session.token, UserHint::User).await,
                "User",
            );
        });
    }

    #[tokio::test]
    async fn from_token_orphaned_session_any_hint_is_invalid_session() {
        use crate::UserHint;

        database_test!(|db| async move {
            // The session's user doc never existed
            let session = from_token_session(
                "01SESSIONFROMTOKENORPHANA00",
                "01USERFROMTOKENMISSING00000",
                "token-from-token-orphaned-session-any",
            );
            db.save_session(&session).await.unwrap();

            from_token_assert_invalid_session(
                User::from_token(&db, &session.token, UserHint::Any).await,
                "Any",
            );
        });
    }

    #[tokio::test]
    async fn from_token_orphaned_bot_is_invalid_session() {
        use crate::{Bot, PartialBot, UserHint};

        database_test!(|db| async move {
            let owner = User::create(&db, "Owner".to_string(), None, None)
                .await
                .unwrap();
            let (bot, _) = Bot::create(&db, "Bot".to_string(), &owner, None::<PartialBot>)
                .await
                .unwrap();
            db.delete_user(&bot.id).await.unwrap();

            from_token_assert_invalid_session(
                User::from_token(&db, &bot.token, UserHint::Bot).await,
                "Bot",
            );
            from_token_assert_invalid_session(
                User::from_token(&db, &bot.token, UserHint::Any).await,
                "Any",
            );
        });
    }

    /// Fixtures for the protected-channel cascade of `User::delete`
    /// (design 6.3)
    mod protected {
        use std::collections::HashMap;

        use iso8601_timestamp::{Duration, Timestamp};

        use crate::{
            Channel, ChannelEntitlement, ChannelEntitlementSource, ChannelEntitlementState,
            Database, Member, MemberCompositeKey, SeatListBody, SeatListSubmission, Server, User,
        };

        pub const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";
        pub const SERVER: &str = "01HZXSERVERSERVERSERVERSER";
        /// Owns `SERVER` and signs its seat list
        pub const OWNER: &str = "01HZXAAAAAAAAAAAAAAAAAAAAA";
        /// A seated member of `SERVER` who owns nothing: the deleted account
        pub const SEATED: &str = "01HZXBBBBBBBBBBBBBBBBBBBBB";
        const OWNER_DEVICE: &str = "00112233445566778899aabbccddeeff";

        /// Fixed, whole-millisecond time: Mongo stores Int64 milliseconds
        fn at_base() -> Timestamp {
            Timestamp::UNIX_EPOCH
                .checked_add(Duration::milliseconds(1_790_812_800_000))
                .unwrap()
        }

        /// `SERVER` (owned by `OWNER`, members `OWNER` and `SEATED`) with
        /// `CHANNEL` protected and both users seated. Returns the stored
        /// `SEATED` user.
        pub async fn seated_user(db: &Database) -> User {
            let server: Server = serde_json::from_value(serde_json::json!({
                "_id": SERVER,
                "owner": OWNER,
                "name": "protected",
                "channels": [CHANNEL],
                "default_permissions": 0,
            }))
            .unwrap();
            db.insert_server(&server).await.unwrap();

            for user in [OWNER, SEATED] {
                db.insert_or_merge_member(&Member {
                    id: MemberCompositeKey {
                        server: SERVER.to_string(),
                        user: user.to_string(),
                    },
                    ..Default::default()
                })
                .await
                .unwrap();
            }

            db.insert_channel(&Channel::TextChannel {
                id: CHANNEL.to_string(),
                server: SERVER.to_string(),
                name: "protected".to_string(),
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
            })
            .await
            .unwrap();

            db.upsert_channel_entitlement(
                &ChannelEntitlement {
                    id: ulid::Ulid::new().to_string(),
                    channel_id: CHANNEL.to_string(),
                    server_id: SERVER.to_string(),
                    source: ChannelEntitlementSource::AdminGrant,
                    slot_cap: 10,
                    device_cap: None,
                    state: ChannelEntitlementState::Active,
                    granted_by: "admin".to_string(),
                    created_at: at_base(),
                },
                at_base(),
            )
            .await
            .unwrap();

            let submission = SeatListSubmission {
                body: SeatListBody {
                    channel_id: CHANNEL.to_string(),
                    version: 1,
                    device_cap: 5,
                    issued_at: 1_790_812_800_000,
                    signer_user_id: OWNER.to_string(),
                    signer_device_id: OWNER_DEVICE.to_string(),
                    seats: vec![OWNER.to_string(), SEATED.to_string()],
                }
                .build()
                .unwrap(),
                // The DB layer checks only the encoding: canonical unpadded
                // b64 of 64 bytes
                signature: format!("B{}", "A".repeat(85)),
                signer_device_id: OWNER_DEVICE.to_string(),
                handover: None,
            };
            db.protect_channel(CHANNEL, &submission, at_base())
                .await
                .unwrap();

            let user = User {
                id: SEATED.to_string(),
                username: "Seated".to_string(),
                discriminator: "1001".to_string(),
                last_acknowledged_policy_change: at_base(),
                ..Default::default()
            };
            db.insert_user(&user).await.unwrap();

            let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
            assert_eq!(seats.len(), 2);
            assert!(seats.iter().all(|seat| seat.is_active()));

            user
        }
    }

    #[tokio::test]
    async fn delete_releases_protected_seats_and_clears_memberships() {
        use protected::{CHANNEL, OWNER, SEATED, SERVER};

        database_test!(|db| async move {
            let mut user = protected::seated_user(&db).await;

            user.delete(&db).await.unwrap();

            let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
            let seat = |user_id: &str| {
                seats
                    .iter()
                    .find(|seat| seat.user_id == user_id)
                    .expect("seat rows are kept")
            };
            assert!(
                !seat(SEATED).is_active(),
                "a deleted account still holds an active seat"
            );
            assert!(seat(SEATED).cooldown_until.is_some());
            assert!(seat(OWNER).is_active(), "another user's seat was released");

            assert!(db.fetch_all_memberships(SEATED).await.unwrap().is_empty());
            assert!(db.fetch_member(SERVER, OWNER).await.is_ok());
        });
    }

    /// A release that fails aborts the deletion before the memberships are
    /// cleared. Mongo only: the Reference driver cannot hold an undecodable
    /// row, so there the test returns early.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn delete_keeps_memberships_when_the_seat_release_fails() {
        use protected::{CHANNEL, SEATED};

        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };
            use bson::{doc, Document};
            use revolt_result::ErrorType;

            let mut user = protected::seated_user(&db).await;

            // An Int32 `channel_id` cannot decode into `ChannelSeat`, and the
            // row matches the unscoped release's `{user_id, released_at: null}`
            // filter. Its channel id is not `CHANNEL`, so `fetch_channel_seats`
            // below never reads it.
            mongo
                .col::<Document>("channel_seats")
                .insert_one(doc! {
                    "_id": "corrupt",
                    "channel_id": 5_i32,
                    "user_id": SEATED,
                    "seated_at": 0_i64,
                })
                .await
                .expect("insert the undecodable seat row");

            let err = user
                .delete(&db)
                .await
                .expect_err("an undecodable seat row must fail the deletion");
            assert!(
                matches!(
                    &err.error_type,
                    ErrorType::DatabaseError { operation, collection }
                        if operation == "find" && collection == "channel_seats"
                ),
                "{err:?}"
            );

            assert_eq!(
                db.fetch_all_memberships(SEATED).await.unwrap().len(),
                1,
                "memberships were cleared although the seat release failed"
            );
            let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
            assert!(seats
                .iter()
                .any(|seat| seat.user_id == SEATED && seat.is_active()));
        });
    }

    /// The SECOND release, after `clear_memberships` (decision 11 (W2)
    /// symmetry, audit C6), fails closed: with the first release's group
    /// claim let through and the next one refused, the deletion answers the
    /// release's error with the memberships already cleared (so the failing
    /// release is the one AFTER them) and the seat released by the first.
    /// Once the claim goes through again, a retried deletion succeeds.
    /// Mongo only: the reference store cannot fail a write. Mutations: the
    /// second release dropped or its error dropped (the first deletion
    /// succeeds); both releases before `clear_memberships` (the memberships
    /// survive the error).
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn delete_fails_closed_when_the_second_seat_release_fails() {
        use protected::{CHANNEL, SEATED};

        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };
            use bson::{doc, Document};
            use revolt_result::ErrorType;

            const GROUP: &str = "01C6DELETEGROUP";

            let mut user = protected::seated_user(&db).await;

            let device = crate::MlsMemberDevice {
                user_id: SEATED.to_string(),
                device_id: "01C6DEVICE".to_string(),
            };
            mongo
                .col::<crate::MlsGroup>("mls_groups")
                .insert_one(&crate::MlsGroup {
                    id: GROUP.to_string(),
                    channel_id: CHANNEL.to_string(),
                    open: true,
                    created_by: device.clone(),
                    created_at: iso8601_timestamp::Timestamp::now_utc(),
                    current_epoch: 0,
                    members: vec![device],
                    closed_at: None,
                    superseded_by: None,
                    kind: crate::MlsGroupKind::Text,
                    generation: Some(0),
                    seat_list_ad_sha256: None,
                    pending_removals: vec![],
                    member_added: vec![],
                })
                .await
                .unwrap();

            // Every release opens by claiming the open Text groups the user
            // is in (`$inc` of `txn_serial`); this validator lets the first
            // claim through and refuses the second
            let validator = |validator: Document| {
                doc! {
                    "collMod": "mls_groups",
                    "validator": validator,
                    "validationLevel": "strict",
                    "validationAction": "error",
                }
            };
            mongo
                .db()
                .run_command(validator(doc! { "$or": [
                    { "txn_serial": { "$exists": false } },
                    { "txn_serial": { "$lte": 1_i64 } },
                ] }))
                .await
                .unwrap();

            let err = user
                .delete(&db)
                .await
                .expect_err("a failed second release must fail the deletion");
            assert!(
                matches!(
                    &err.error_type,
                    ErrorType::DatabaseError { collection, .. } if collection == "mls_groups"
                ),
                "{err:?}"
            );
            assert!(
                db.fetch_all_memberships(SEATED).await.unwrap().is_empty(),
                "the failing release must be the one after `clear_memberships`"
            );
            let seats = db.fetch_channel_seats(CHANNEL).await.unwrap();
            assert!(
                seats
                    .iter()
                    .any(|seat| seat.user_id == SEATED && !seat.is_active()),
                "the first release reached the seat: {seats:?}"
            );

            mongo.db().run_command(validator(doc! {})).await.unwrap();
            user.delete(&db)
                .await
                .expect("the retried deletion succeeds");
        });
    }
}
