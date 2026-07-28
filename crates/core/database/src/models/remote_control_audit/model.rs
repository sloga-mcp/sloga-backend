use iso8601_timestamp::Timestamp;

auto_derived!(
    /// Audit row for the remote-control grant lifecycle (remote-control
    /// plan §1/§8). One row per lifecycle transition — offered, declined,
    /// accepted, ended — so abuse review can reconstruct who offered
    /// control of their machine to whom, and what became of it.
    ///
    /// Server-written and server-read: this is an abuse/moderation record,
    /// not a security control (a hostile server could fabricate it; the
    /// plan's rev-8 notes are explicit that only local, native-held state
    /// defends against that party).
    pub struct RemoteControlAuditEntry {
        /// Unique id (ULID; encodes creation time)
        #[serde(rename = "_id")]
        pub id: String,
        /// Channel the control session belongs to
        pub channel_id: String,
        /// Server, when the channel is a server channel
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server_id: Option<String>,
        /// The sharer — the party offering control of their own machine
        pub sharer_id: String,
        /// The (would-be) controller — the named target of the offer
        pub controller_id: String,
        /// Offer id, for rows tied to an offer
        #[serde(skip_serializing_if = "Option::is_none")]
        pub offer_id: Option<String>,
        /// Grant id, for rows tied to an active grant
        #[serde(skip_serializing_if = "Option::is_none")]
        pub grant_id: Option<String>,
        /// Lifecycle transition: "offered", "declined", "accepted",
        /// "grant_failed" (SFU refused at accept time) or "ended"
        pub action: String,
        /// For "ended" rows: why the grant ended ("released",
        /// "revoked_by_moderator", "expired", "permissions_changed",
        /// "participant_left", "screenshare_ended", "call_ended",
        /// "reconnected", "disabled")
        #[serde(skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// When the transition happened
        pub created_at: Timestamp,
    }
);
