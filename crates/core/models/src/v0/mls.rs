use iso8601_timestamp::Timestamp;

auto_derived!(
    /// A (user, device) pair — the unit of MLS group membership, KeyPackage
    /// claims and envelope fan-out (media E2EE)
    pub struct MlsMemberDevice {
        /// User id
        pub user_id: String,
        /// E2EE device id (128-bit lowercase hex)
        pub device_id: String,
    }

    /// One opaque KeyPackage being published
    pub struct MlsKeyPackageUpload {
        /// Client-computed OpenMLS KeyPackageRef, unpadded standard base64
        pub key_package_ref: String,
        /// Opaque KeyPackage bytes, unpadded standard base64 — the server
        /// never parses these
        pub key_package: String,
    }

    /// Publish (or replenish) MLS KeyPackages for the current device
    ///
    /// The binding signature is the credential binding (one per device, not
    /// per package): Ed25519 by the device identity key over the canonical
    /// `acutest:e2ee:mls-credential:v1` payload binding `mls_signature_key`
    /// to this (user, device). Verified server-side like one-time-key
    /// publish; clients re-verify the credential inside the KeyPackage at
    /// Welcome time — the server is outside the trust boundary.
    pub struct DataPublishMlsKeyPackages {
        /// Device id (must be a registered E2EE device of the caller)
        pub device_id: String,
        /// MLS Ed25519 signature PUBLIC key, unpadded standard base64
        pub mls_signature_key: String,
        /// Credential binding signature (see above)
        pub binding_signature: String,
        /// One-time KeyPackages to add
        #[serde(default)]
        pub key_packages: Vec<MlsKeyPackageUpload>,
        /// Replace the device's reusable last-resort KeyPackage (short-lived
        /// by design — reuse weakens Welcome forward secrecy)
        #[serde(default)]
        pub last_resort: Option<MlsKeyPackageUpload>,
    }

    /// Response to publishing KeyPackages
    pub struct ResponsePublishMlsKeyPackages {
        /// One-time KeyPackages now stored for this device (excludes the
        /// last-resort package). Drives the client's low-water replenish.
        pub key_package_count: u64,
    }

    /// Claim KeyPackages for target devices (admission — plan §1.4 step 2)
    pub struct DataClaimMlsKeyPackages {
        /// The claiming (admitting) device
        pub device_id: String,
        /// Group this claim is for. Enables the call-co-presence eligibility
        /// class: strangers sharing the group's voice channel may claim.
        pub group_id: String,
        /// Devices to claim one KeyPackage each for
        pub targets: Vec<MlsMemberDevice>,
    }

    /// Outcome of one KeyPackage claim
    #[serde(tag = "status")]
    pub enum MlsClaimStatus {
        /// A package was claimed
        Claimed {
            /// KeyPackage reference
            key_package_ref: String,
            /// Opaque KeyPackage bytes
            key_package: String,
            /// The device's MLS signature public key
            mls_signature_key: String,
            /// The device's credential binding signature — the claimer MUST
            /// verify it against its pinned identity for the target
            binding_signature: String,
            /// True when this is the reusable last-resort package (one-time
            /// packages were exhausted): the admitter should prefer
            /// re-claiming a one-time package later if the join can wait
            reused: bool,
        },
        /// The device has no packages left (not even a last-resort one) —
        /// the joiner must republish; admission fails LOUDLY, never weakly
        Exhausted,
        /// Unknown device, or the claimer is not eligible for this target
        NotFound,
    }

    /// Per-target claim result
    pub struct MlsClaimResult {
        /// Target user
        pub user_id: String,
        /// Target device
        pub device_id: String,
        /// Outcome
        #[serde(flatten)]
        pub status: MlsClaimStatus,
    }

    /// Response to claiming KeyPackages
    pub struct ResponseClaimMlsKeyPackages {
        /// One entry per requested target, same order
        pub results: Vec<MlsClaimResult>,
    }

    /// What an MLS group secures (protected channels design §2.5). Groups
    /// stored before this field existed are call groups.
    #[derive(Default)]
    pub enum MlsGroupKind {
        /// Per-call media E2EE group
        #[default]
        Call,
        /// Protected text channel group
        Text,
    }

    /// A stored signed join intent that justified a rejoin-case Remove,
    /// carried on a commit (protected channels design §8.1). The wire shape
    /// is exactly native `wire::MlsJoinRequest`. `channel_id` is not part of
    /// the stored row: the server fills it from the group's channel. The
    /// signature does not cover `channel_id`; receivers check it against the
    /// commit's own group and channel.
    pub struct MlsRejoinIntentInfo {
        /// Group the intent targets
        pub group_id: String,
        /// Channel of that group
        pub channel_id: String,
        /// Joining user
        pub user_id: String,
        /// Joining device
        pub device_id: String,
        /// KeyPackage reference the joiner nominated
        pub key_package_ref: String,
        /// Join-intent signature
        pub signature: String,
    }

    /// Register an MLS group: a per-call group (plan §1.2) or a protected
    /// channel's Text group (protected channels design §7.2)
    pub struct DataCreateMlsGroup {
        /// Client-derived group id: 64 lowercase hex chars
        /// (`hash(channel_id || call_start_ulid)` for a call group, design
        /// §3.1 for a Text group)
        pub group_id: String,
        /// Channel this group secures
        pub channel_id: String,
        /// The creating device
        pub device_id: String,
        /// Poisoned-epoch successor flow (plan §1.4): atomically close this
        /// group and register the new one in its place
        #[serde(default)]
        pub supersedes: Option<String>,
        /// Group kind. Absent means `Call`, so existing callers (and their
        /// request bodies) are unchanged
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<MlsGroupKind>,
        /// Text only: the group-id generation (design §3.1). Required for
        /// `Text`, refused for `Call`
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<u32>,
    }

    /// Response to registering a group — 200 on create, 409 on conflict
    /// (the create-race arbitration: the loser joins the open group instead)
    #[serde(tag = "result")]
    pub enum ResponseCreateMlsGroup {
        /// The group was registered (epoch 0, creator only)
        Created,
        /// Another open group exists for this channel — join THAT one
        Conflict {
            /// The channel's open group id
            open_group_id: String,
            /// The channel_id the open group is bound to, from the group
            /// record — the client compares its route-truth channel against
            /// this before signing a join intent (T-15 client-leg, §1.4)
            channel_id: String,
        },
    }

    /// Signal intent to join a group (plan §1.4 step 1). The signature is
    /// Ed25519 by the device identity key over the canonical
    /// `acutest:e2ee:mls-join:v1` payload; admitting members re-verify it
    /// against their own pins — the server check is defense in depth.
    pub struct DataMlsJoinIntent {
        /// The joining device
        pub device_id: String,
        /// Fresh KeyPackage reference admitters should claim
        pub key_package_ref: String,
        /// Join-intent signature
        pub signature: String,
    }

    /// Submit a commit for the next epoch (plan §2.2.3 arbitration)
    pub struct DataSubmitMlsCommit {
        /// The committing device
        pub device_id: String,
        /// Epoch this commit establishes — must be exactly the group's
        /// `current_epoch + 1`
        pub epoch: i64,
        /// Opaque commit ciphertext (MLS PrivateMessage), unpadded standard
        /// base64; fanned out to every member device
        pub commit: String,
        /// Opaque Welcome, unpadded standard base64; required when `added`
        /// is non-empty, delivered to each added device
        #[serde(default)]
        pub welcome: Option<String>,
        /// Devices ADDED by this commit (fan-out list; committer-asserted)
        #[serde(default)]
        pub added: Vec<MlsMemberDevice>,
        /// Devices REMOVED by this commit
        #[serde(default)]
        pub removed: Vec<MlsMemberDevice>,
    }

    /// A stored winning commit
    pub struct MlsCommitInfo {
        /// Group
        pub group_id: String,
        /// Epoch the commit establishes
        pub epoch: i64,
        /// Committing device (server-stamped at submission)
        pub committer: MlsMemberDevice,
        /// Opaque commit ciphertext
        pub commit: String,
        /// Devices added by the commit
        pub added: Vec<MlsMemberDevice>,
        /// Devices removed by the commit
        pub removed: Vec<MlsMemberDevice>,
        /// Signed join intents that justified a rejoin-case Remove in this
        /// commit (Text groups only; always empty on Call commits)
        #[serde(default)]
        pub rejoin_intents: Vec<MlsRejoinIntentInfo>,
    }

    /// Response to a commit submission — 200 on win, 409 on lose (the loser
    /// rebases onto the winning commit carried in the body)
    #[serde(tag = "result")]
    pub enum ResponseSubmitMlsCommit {
        /// This commit won the epoch; envelopes are queued and pushed
        Won,
        /// Another commit won this epoch first
        Lost {
            /// The winning commit to rebase onto
            winning: MlsCommitInfo,
        },
    }

    /// Response to the commit gap-refetch
    pub struct ResponseFetchMlsCommits {
        /// Stored winning commits, ascending by epoch
        pub commits: Vec<MlsCommitInfo>,
        /// The group's current epoch (so a fully caught-up client knows it)
        pub current_epoch: i64,
    }

    /// Send an MLS application message to the group roster (plan §3.4 —
    /// the downgrade ctl-announce). The ciphertext is an opaque MLS
    /// PrivateMessage encrypted+authenticated by the group; the server
    /// relays it to every member device except the sender's. It never
    /// advances an epoch.
    pub struct DataSendMlsMessage {
        /// The sending device (must be a group member device of the caller)
        pub device_id: String,
        /// Opaque application-message ciphertext, unpadded standard base64
        pub ciphertext: String,
    }

    /// The channel's open MLS group, if any — the pre-join mode probe
    /// (plan §3.4 compose-time rule + A3 cap pre-warning). Reveals only
    /// metadata the server already holds (§5.6) to channel-access holders.
    pub struct ResponseOpenMlsGroup {
        /// The open group's id
        pub group_id: String,
        /// Current roster size (device count) — pre-join cap warning input
        pub member_count: usize,
    }

    /// A user whose devices must leave a Text group (protected channels
    /// design §2.5, §7.2)
    pub struct MlsPendingRemovalInfo {
        /// User whose member devices are to be removed
        pub user_id: String,
        /// When the pending removal was recorded
        pub created_at: Timestamp,
    }

    /// A member device's latest Add to a Text group (design §7.2
    /// `member_added`, W0-fix7). A liveness aid for the joining bridge only
    pub struct MlsMemberAddedInfo {
        /// Added user
        pub user_id: String,
        /// Added device
        pub device_id: String,
        /// Epoch the Add established (0 = the creator at group create)
        pub epoch: i64,
        /// Server-stamped time of the Add
        pub at: Timestamp,
    }

    /// The channel's open Text group
    /// (`GET /mls/channels/:channel_id/text_group`, design §7.2)
    pub struct ResponseTextGroup {
        /// Text group id (64 lowercase hex chars)
        pub group_id: String,
        /// Channel the group secures
        pub channel_id: String,
        /// Group-id generation (design §3.1); joiners check exactly this one
        pub generation: u32,
        /// Highest arbitrated epoch
        pub current_epoch: i64,
        /// Member devices
        pub members: Vec<MlsMemberDevice>,
        /// Users whose devices must be removed before any Add
        pub pending_removals: Vec<MlsPendingRemovalInfo>,
        /// Each member device's latest Add
        pub member_added: Vec<MlsMemberAddedInfo>,
    }
);

#[cfg(test)]
mod tests {
    use super::{DataCreateMlsGroup, MlsGroupKind, ResponseTextGroup};

    /// The 7.2 text group example, with concrete values in its placeholders
    const TEXT_GROUP_EXAMPLE: &str = r#"{"group_id":"0000000000000000000000000000000000000000000000000000000000000001","channel_id":"01JA0000000000000000CHANNEL","generation":0,"current_epoch":7,"members":[{"user_id":"01JA00000000000000000USERA","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"pending_removals":[{"user_id":"01JA00000000000000000USERB","created_at":"2026-10-04T12:00:00.000Z"}],"member_added":[{"user_id":"01JA00000000000000000USERA","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","epoch":5,"at":"2026-10-04T11:00:00.000Z"}]}"#;

    /// A group-create body exactly as `996641f1` serialized it
    const CREATE_AT_996641F1: &str = r#"{"group_id":"0000000000000000000000000000000000000000000000000000000000000001","channel_id":"01JA0000000000000000CHANNEL","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","supersedes":null}"#;

    #[test]
    fn text_group_response_round_trips_the_example() {
        let parsed: ResponseTextGroup = serde_json::from_str(TEXT_GROUP_EXAMPLE).unwrap();
        assert_eq!(parsed.generation, 0);
        assert_eq!(parsed.current_epoch, 7);
        assert_eq!(parsed.pending_removals.len(), 1);
        assert_eq!(parsed.member_added[0].epoch, 5);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), TEXT_GROUP_EXAMPLE);
    }

    /// An existing caller's body (no `kind`, no `generation`) still parses as
    /// a call group create, and a call create serializes as it did before
    #[test]
    fn create_group_kind_and_generation_are_optional() {
        let parsed: DataCreateMlsGroup = serde_json::from_str(CREATE_AT_996641F1).unwrap();
        assert_eq!(parsed.kind, None);
        assert_eq!(parsed.generation, None);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), CREATE_AT_996641F1);

        let text = DataCreateMlsGroup {
            kind: Some(MlsGroupKind::Text),
            generation: Some(0),
            ..parsed
        };
        let value = serde_json::to_value(&text).unwrap();
        assert_eq!(value["kind"], "Text");
        assert_eq!(value["generation"], 0);
        assert_eq!(
            serde_json::from_value::<DataCreateMlsGroup>(value).unwrap(),
            text
        );

        // Unknown keys are ignored, like every neighboring request body
        let extra = CREATE_AT_996641F1.replace("\"supersedes\"", "\"future\":1,\"supersedes\"");
        assert!(serde_json::from_str::<DataCreateMlsGroup>(&extra).is_ok());
    }
}
