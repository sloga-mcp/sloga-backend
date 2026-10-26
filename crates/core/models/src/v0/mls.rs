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
    /// commit's own group and channel. An intent signed over the Text join
    /// payload (design §3.13, v2 lists) carries `generation` and `issued_at`,
    /// and its signature covers `channel_id` too.
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
        /// Text join payload only: the signed group-id generation
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<u32>,
        /// Text join payload only: the signed issue time (ms)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<i64>,
    }

    /// Which Remove rule (protected channels design §3.12.2, §6.1) the
    /// server found admitting a removed device. Several rules can admit one
    /// device; the strongest is stamped (S1 order: `pending_removal` >
    /// `off_list` > `revoked` > `own_user` > `rejoin`). ADVISORY ONLY: the
    /// server is untrusted, so receivers decide from signed material
    #[derive(Copy)]
    #[serde(rename_all = "snake_case")]
    pub enum MlsRemovalReason {
        /// The device belongs to the committer's own user
        OwnUser,
        /// The device's user is pending removal from the group
        PendingRemoval,
        /// The device's user is off the newest seat list and the committer
        /// is the list signer's device
        OffList,
        /// The device has no registered identity
        Revoked,
        /// The device's own outstanding rejoin intent
        Rejoin,
        /// The device is pending removal on its own (rule 3a, S2)
        PendingDevice,
        /// [S2b] The device has been idle past the configured window
        Idle,
        /// A value this build does not know (design §3.13 rollout, #219).
        /// Decode-only: the server never stamps it
        #[serde(other)]
        Unknown,
    }

    /// The server's advisory reason for one device a Text commit removed
    pub struct MlsRemovedReasonInfo {
        /// Removed user
        pub user_id: String,
        /// Removed device
        pub device_id: String,
        /// The strongest admitting rule
        pub reason: MlsRemovalReason,
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
    /// `acutest:e2ee:mls-join:v1` payload, or, for a Text intent on a
    /// channel whose list is v2, over the `sloga-text-join-v1` payload
    /// (protected channels design §3.13); admitting members re-verify it
    /// against their own pins — the server check is defense in depth.
    pub struct DataMlsJoinIntent {
        /// The joining device
        pub device_id: String,
        /// Fresh KeyPackage reference admitters should claim
        pub key_package_ref: String,
        /// Join-intent signature
        pub signature: String,
        /// Text join payload only: the signed group-id generation
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<u32>,
        /// Text join payload only: the signed issue time (ms)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<i64>,
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
        /// Text groups only: one advisory reason per removed device
        /// (absent = empty; never present on Call commits)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub removed_reasons: Vec<MlsRemovedReasonInfo>,
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
        /// Text groups only: the epoch of the oldest stored commit (design
        /// §6.1 "Commit fetch", S2-D30); absent when not reported
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub oldest_epoch: Option<i64>,
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

    /// An outstanding join intent of a seated user (design §6.3 "Async Text
    /// join", §7.2 `join_requests`). Carries every signed field so members
    /// can rebuild the signed payload (§3.13)
    pub struct MlsJoinRequestInfo {
        /// Joining user
        pub user_id: String,
        /// Joining device
        pub device_id: String,
        /// Text join payload only: the signed group-id generation
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<u32>,
        /// KeyPackage reference the joiner nominated
        pub key_package_ref: String,
        /// Join-intent signature
        pub signature: String,
        /// Text join payload only: the signed issue time (ms)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<i64>,
        /// Server-stamped submission time
        pub created_at: Timestamp,
        /// Whether the device already holds a leaf (a rejoin)
        pub rejoin: bool,
    }

    /// A single member device that must leave a Text group (design §2.5,
    /// S2-D17a)
    pub struct MlsPendingDeviceRemovalInfo {
        /// User of the device
        pub user_id: String,
        /// Device to be removed
        pub device_id: String,
        /// When the pending removal was recorded
        pub created_at: Timestamp,
    }

    /// Why the current seat list's signer device is lost (design §6.3
    /// "Owner signing device lost", #222)
    #[derive(Copy)]
    #[serde(rename_all = "snake_case")]
    pub enum MlsSignerLostCause {
        /// The signer device was revoked (the stored cause)
        DeviceRevoked,
        /// The signer user's account is suspended, deleted or banned
        /// (derived at read time, never stored)
        AccountUnavailable,
    }

    /// The device that signed the current seat list is lost (design §2.5,
    /// S2-D17d)
    pub struct MlsSignerLostInfo {
        /// Signer user
        pub user_id: String,
        /// Signer device
        pub device_id: String,
        /// Why it is lost
        pub cause: MlsSignerLostCause,
        /// When it was recorded
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
        /// Outstanding join intents (seated callers only; absent = empty)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub join_requests: Vec<MlsJoinRequestInfo>,
        /// Single devices that must be removed (seated callers only;
        /// absent = empty)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub pending_device_removals: Vec<MlsPendingDeviceRemovalInfo>,
        /// The current list's signer device is lost (seated callers only;
        /// absent = none)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signer_lost: Option<MlsSignerLostInfo>,
    }

    /// A device's stored Welcome
    /// (`GET /mls/groups/:group_id/welcome?device_id=`, design §7.2)
    pub struct ResponseTextWelcome {
        /// Text group id
        pub group_id: String,
        /// Epoch of the commit that added the device
        pub epoch: i64,
        /// The stored Welcome, unpadded standard base64
        pub welcome: String,
    }
);

#[cfg(test)]
mod tests {
    use super::{
        DataCreateMlsGroup, DataMlsJoinIntent, MlsCommitInfo, MlsGroupKind, MlsRejoinIntentInfo,
        MlsRemovalReason, MlsRemovedReasonInfo, MlsSignerLostCause, MlsSignerLostInfo,
        ResponseFetchMlsCommits, ResponseTextGroup, ResponseTextWelcome,
    };

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

    /// A commit info exactly as `4206add3` serialized it (no
    /// `removed_reasons` key)
    const COMMIT_INFO_AT_4206ADD3: &str = r#"{"group_id":"0000000000000000000000000000000000000000000000000000000000000001","epoch":2,"committer":{"user_id":"01JA00000000000000000USERA","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"commit":"Y29tbWl0","added":[],"removed":[{"user_id":"01JA00000000000000000USERB","device_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"rejoin_intents":[]}"#;

    /// B48: an empty `removed_reasons` is never serialized (Call commits keep
    /// the earlier shape), an old body without it parses as empty, and each
    /// reason is snake_case on the wire
    #[test]
    fn removed_reasons_are_optional_and_snake_case() {
        let parsed: MlsCommitInfo = serde_json::from_str(COMMIT_INFO_AT_4206ADD3).unwrap();
        assert!(parsed.removed_reasons.is_empty());
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            COMMIT_INFO_AT_4206ADD3
        );

        for (reason, wire) in [
            (MlsRemovalReason::OwnUser, "own_user"),
            (MlsRemovalReason::PendingRemoval, "pending_removal"),
            (MlsRemovalReason::OffList, "off_list"),
            (MlsRemovalReason::Revoked, "revoked"),
            (MlsRemovalReason::Rejoin, "rejoin"),
        ] {
            let info = MlsCommitInfo {
                removed_reasons: vec![MlsRemovedReasonInfo {
                    user_id: "01JA00000000000000000USERB".to_string(),
                    device_id: "b".repeat(32),
                    reason,
                }],
                ..parsed.clone()
            };
            let value = serde_json::to_value(&info).unwrap();
            assert_eq!(
                value["removed_reasons"],
                serde_json::json!([{
                    "user_id": "01JA00000000000000000USERB",
                    "device_id": "b".repeat(32),
                    "reason": wire
                }])
            );
            assert_eq!(
                serde_json::from_value::<MlsCommitInfo>(value).unwrap(),
                info
            );
        }
    }

    /// Every reason the server can stamp, and its wire value
    const KNOWN_REASONS: [(MlsRemovalReason, &str); 7] = [
        (MlsRemovalReason::OwnUser, "own_user"),
        (MlsRemovalReason::PendingRemoval, "pending_removal"),
        (MlsRemovalReason::OffList, "off_list"),
        (MlsRemovalReason::Revoked, "revoked"),
        (MlsRemovalReason::Rejoin, "rejoin"),
        (MlsRemovalReason::PendingDevice, "pending_device"),
        (MlsRemovalReason::Idle, "idle"),
    ];

    /// #219: every known reason round-trips under its snake_case value, and
    /// a value this build does not know decodes as `Unknown` instead of
    /// failing the whole commit (an S1 reader meeting S2 values, a rollback)
    #[test]
    fn removal_reasons_round_trip_and_unknown_decodes() {
        for (reason, wire) in KNOWN_REASONS {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                serde_json::json!(wire)
            );
            assert_eq!(
                serde_json::from_value::<MlsRemovalReason>(serde_json::json!(wire)).unwrap(),
                reason
            );
        }

        for unknown in ["user_removed", "PendingDevice", ""] {
            assert_eq!(
                serde_json::from_value::<MlsRemovalReason>(serde_json::json!(unknown)).unwrap(),
                MlsRemovalReason::Unknown,
                "{unknown:?}"
            );
        }

        // Inside a commit: the unknown reason does not fail the row
        let with_future = COMMIT_INFO_AT_4206ADD3.replace(
            r#""rejoin_intents":[]"#,
            r#""rejoin_intents":[],"removed_reasons":[{"user_id":"01JA00000000000000000USERB","device_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","reason":"from_the_future"}]"#,
        );
        let parsed: MlsCommitInfo = serde_json::from_str(&with_future).unwrap();
        assert_eq!(parsed.removed_reasons[0].reason, MlsRemovalReason::Unknown);
    }

    /// An S2 text group response with every S2 field set
    const TEXT_GROUP_S2: &str = r#"{"group_id":"0000000000000000000000000000000000000000000000000000000000000001","channel_id":"01JA0000000000000000CHANNEL","generation":1,"current_epoch":7,"members":[{"user_id":"01JA00000000000000000USERA","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"pending_removals":[],"member_added":[],"join_requests":[{"user_id":"01JA00000000000000000USERC","device_id":"cccccccccccccccccccccccccccccccc","generation":1,"key_package_ref":"a3ByZWY","signature":"c2ln","issued_at":1760000000000,"created_at":"2026-10-04T12:00:00.000Z","rejoin":false},{"user_id":"01JA00000000000000000USERD","device_id":"dddddddddddddddddddddddddddddddd","key_package_ref":"a3A","signature":"c2ln","created_at":"2026-10-04T12:00:00.000Z","rejoin":true}],"pending_device_removals":[{"user_id":"01JA00000000000000000USERB","device_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","created_at":"2026-10-04T13:00:00.000Z"}],"signer_lost":{"user_id":"01JA00000000000000000USERA","device_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","cause":"device_revoked","at":"2026-10-04T14:00:00.000Z"}}"#;

    /// S2 (design §7.2): the new text group fields round-trip under their
    /// exact keys; an S1 intent row (no `generation` / `issued_at`) omits
    /// them; an unseated caller's empty fields are absent, so the response
    /// is byte-identical to S1 (`text_group_response_round_trips_the_example`)
    #[test]
    fn text_group_s2_fields_round_trip() {
        let parsed: ResponseTextGroup = serde_json::from_str(TEXT_GROUP_S2).unwrap();
        assert_eq!(parsed.join_requests.len(), 2);
        assert_eq!(parsed.join_requests[0].generation, Some(1));
        assert_eq!(parsed.join_requests[0].issued_at, Some(1_760_000_000_000));
        assert_eq!(parsed.join_requests[1].generation, None);
        assert_eq!(parsed.join_requests[1].issued_at, None);
        assert!(parsed.join_requests[1].rejoin);
        assert_eq!(parsed.pending_device_removals[0].device_id, "b".repeat(32));
        assert_eq!(
            parsed.signer_lost.as_ref().unwrap().cause,
            MlsSignerLostCause::DeviceRevoked
        );
        assert_eq!(serde_json::to_string(&parsed).unwrap(), TEXT_GROUP_S2);

        let unseated = ResponseTextGroup {
            join_requests: vec![],
            pending_device_removals: vec![],
            signer_lost: None,
            ..parsed
        };
        let value = serde_json::to_value(&unseated).unwrap();
        for key in ["join_requests", "pending_device_removals", "signer_lost"] {
            assert!(value.get(key).is_none(), "{key} must be absent when empty");
        }

        for (cause, wire) in [
            (MlsSignerLostCause::DeviceRevoked, "device_revoked"),
            (
                MlsSignerLostCause::AccountUnavailable,
                "account_unavailable",
            ),
        ] {
            let lost = MlsSignerLostInfo {
                user_id: "01JA00000000000000000USERA".to_string(),
                device_id: "e".repeat(32),
                cause,
                at: iso8601_timestamp::Timestamp::UNIX_EPOCH,
            };
            let value = serde_json::to_value(&lost).unwrap();
            assert_eq!(value["cause"], wire);
            assert_eq!(
                serde_json::from_value::<MlsSignerLostInfo>(value).unwrap(),
                lost
            );
        }
    }

    /// A join intent body exactly as an S1 client sends it
    const JOIN_INTENT_S1: &str = r#"{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key_package_ref":"a3ByZWY","signature":"c2ln"}"#;

    /// §3.13 carriers: the S1 body still parses (both fields `None`) and
    /// serializes unchanged; the Text join fields travel under exactly
    /// `generation` and `issued_at`, on the request and on a commit's
    /// rejoin intent
    #[test]
    fn join_intent_text_fields_are_optional() {
        let parsed: DataMlsJoinIntent = serde_json::from_str(JOIN_INTENT_S1).unwrap();
        assert_eq!(parsed.generation, None);
        assert_eq!(parsed.issued_at, None);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), JOIN_INTENT_S1);

        let text = DataMlsJoinIntent {
            generation: Some(0),
            issued_at: Some(9_007_199_254_740_991),
            ..parsed
        };
        let value = serde_json::to_value(&text).unwrap();
        assert_eq!(value["generation"], 0);
        assert_eq!(value["issued_at"], 9_007_199_254_740_991i64);
        assert_eq!(
            serde_json::from_value::<DataMlsJoinIntent>(value).unwrap(),
            text
        );

        // The commit's stored intent: S1 rows keep their shape
        let commit: MlsCommitInfo = serde_json::from_str(COMMIT_INFO_AT_4206ADD3).unwrap();
        let intent = MlsRejoinIntentInfo {
            group_id: commit.group_id.clone(),
            channel_id: "01JA0000000000000000CHANNEL".to_string(),
            user_id: "01JA00000000000000000USERB".to_string(),
            device_id: "b".repeat(32),
            key_package_ref: "a3ByZWY".to_string(),
            signature: "c2ln".to_string(),
            generation: None,
            issued_at: None,
        };
        let value = serde_json::to_value(&intent).unwrap();
        assert!(value.get("generation").is_none());
        assert!(value.get("issued_at").is_none());
        let text = MlsRejoinIntentInfo {
            generation: Some(2),
            issued_at: Some(1),
            ..intent
        };
        let value = serde_json::to_value(&text).unwrap();
        assert_eq!(value["generation"], 2);
        assert_eq!(value["issued_at"], 1);
        assert_eq!(
            serde_json::from_value::<MlsRejoinIntentInfo>(value).unwrap(),
            text
        );
    }

    /// A commit fetch response exactly as S1 served it
    const COMMITS_FETCH_S1: &str = r#"{"commits":[],"current_epoch":3}"#;

    /// S2-D30: `oldest_epoch` is absent unless reported, so the S1 shape
    /// (and every Call fetch) is unchanged
    #[test]
    fn commits_fetch_oldest_epoch_is_optional() {
        let parsed: ResponseFetchMlsCommits = serde_json::from_str(COMMITS_FETCH_S1).unwrap();
        assert_eq!(parsed.oldest_epoch, None);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), COMMITS_FETCH_S1);

        let reported = ResponseFetchMlsCommits {
            oldest_epoch: Some(2),
            ..parsed
        };
        assert_eq!(
            serde_json::to_string(&reported).unwrap(),
            r#"{"commits":[],"current_epoch":3,"oldest_epoch":2}"#
        );
    }

    /// S2-D29: the Welcome route answers exactly `{ group_id, epoch, welcome }`
    #[test]
    fn text_welcome_response_shape() {
        let wire = r#"{"group_id":"0000000000000000000000000000000000000000000000000000000000000001","epoch":4,"welcome":"d2VsY29tZQ"}"#;
        let ResponseTextWelcome {
            group_id,
            epoch,
            welcome,
        } = serde_json::from_str(wire).unwrap();
        assert_eq!(epoch, 4);
        assert_eq!(welcome, "d2VsY29tZQ");
        assert_eq!(
            serde_json::to_string(&ResponseTextWelcome {
                group_id,
                epoch,
                welcome
            })
            .unwrap(),
            wire
        );
    }
}
