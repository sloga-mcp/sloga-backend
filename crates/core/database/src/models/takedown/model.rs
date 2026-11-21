use iso8601_timestamp::Timestamp;

auto_derived!(
    /// Where a Take It Down request is in its review
    pub enum TakedownStatus {
        Received,
        NeedsInfo,
        UnderReview,
        Removed,
        PartiallyRemoved,
        Declined,
        Closed,
    }

    /// How a request reached Sloga
    #[serde(tag = "type")]
    pub enum TakedownSource {
        /// The public form on sloga.gg
        Web,
        /// An in-app report with the Take It Down fields filled in
        InApp { report_id: String },
    }

    /// Why a reviewer declined a request
    pub enum TakedownDeclineReason {
        NotIntimate,
        NotFound,
        NotOnSloga,
        Duplicate,
        BadFaith,
        Other,
    }

    /// Why a submitted location could not be turned into a Sloga object
    pub enum UnresolvableKind {
        /// Looked like a Sloga link, but nothing exists there
        NotFound,
        /// A private conversation (DM or group) with no stored message:
        /// deleted, encrypted, or never existed
        PrivateConversation,
        /// A link to another website
        External,
        /// Not a link shape Sloga can act on
        Unrecognized,
    }

    /// A Sloga object a request points at, resolved server-side
    #[serde(tag = "type")]
    pub enum TakedownTarget {
        Message {
            channel: String,
            message: String,
        },
        File {
            file: String,
        },
        User {
            user: String,
        },
        Server {
            server: String,
        },
        Emoji {
            emoji: String,
        },
        Unresolvable {
            /// Index into `TakedownRequest.locations`
            location_index: usize,
            kind: UnresolvableKind,
        },
    }

    /// A file a request holds, and its flags before the request touched it
    pub struct HeldFile {
        pub id: String,
        /// Unhide must leave a file that was already deleted deleted
        pub was_deleted: bool,
        /// Hold release must leave a file that was already reported reported
        pub was_reported: bool,
    }

    /// Who filed the request
    pub enum TakedownRole {
        /// The person shown
        Depicted,
        /// Someone authorized to act for the person shown
        Authorized,
    }
);

/// A Take It Down removal request.
///
/// Requester personal data lives only in `sealed`. Every other field is
/// ids, flags, timestamps or the raw locations as submitted.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TakedownRequest {
    /// Unique id (ULID)
    #[serde(rename = "_id")]
    pub id: String,
    pub status: TakedownStatus,
    pub source: TakedownSource,
    pub received_at: Timestamp,
    /// 48 hours after the earliest linked request was received
    pub deadline_at: Timestamp,
    /// Sealed `SealedRequester` JSON
    pub sealed: String,
    /// Keyed fingerprint of the contact email
    pub contact_fp: String,
    /// Hash of the status-page token
    pub status_token_hash: String,
    /// Raw links or ids as submitted (at most 20, each at most 2048 chars)
    pub locations: Vec<String>,
    pub minor_claimed: bool,
    #[serde(default)]
    pub resolved: bool,
    #[serde(default)]
    pub targets: Vec<TakedownTarget>,
    #[serde(default)]
    pub linked_request_ids: Vec<String>,
    /// Files this request put in the hidden-but-kept state, with the
    /// flags they had before
    #[serde(default)]
    pub held_files: Vec<HeldFile>,
    /// Ids of auto-hidden files (a subset of `held_files`)
    #[serde(default)]
    pub auto_hidden_file_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_until: Option<Timestamp>,
    /// Open-ended hold; never restorable
    #[serde(default)]
    pub child_safety: bool,
    #[serde(default)]
    pub bad_faith: bool,
    #[serde(default)]
    pub throttled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<TakedownDeclineReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_opened_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<Timestamp>,
    #[serde(default)]
    pub requester_purged: bool,
    /// Reviewer's internal note (at most 1000 chars); never in `staff_audit`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_note: Option<String>,
    /// Bumped by every `replace_takedown_request`; a replace from a stale
    /// copy is refused
    #[serde(default)]
    pub revision: u64,
    /// Once-only side effects already done. Written only by
    /// `claim_takedown_marker`; `replace_takedown_request` never touches it.
    #[serde(default)]
    pub markers: Vec<String>,
}

impl std::fmt::Debug for TakedownRequest {
    /// Ids, flags and dates only; never sealed data, fingerprints, raw locations or notes
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let TakedownRequest {
            id,
            status,
            source,
            received_at,
            deadline_at,
            sealed,
            contact_fp,
            status_token_hash,
            locations,
            minor_claimed,
            resolved,
            targets,
            linked_request_ids,
            held_files,
            auto_hidden_file_ids,
            hold_until,
            child_safety,
            bad_faith,
            throttled,
            decline_reason,
            first_opened_at,
            removed_at,
            closed_at,
            requester_purged,
            reviewer_note,
            revision,
            markers,
        } = self;

        f.debug_struct("TakedownRequest")
            .field("id", id)
            .field("status", status)
            .field("source", source)
            .field("received_at", received_at)
            .field("deadline_at", deadline_at)
            .field("sealed", &redact(sealed))
            .field("contact_fp", &redact(contact_fp))
            .field("status_token_hash", &redact(status_token_hash))
            .field("locations", &locations.len())
            .field("minor_claimed", minor_claimed)
            .field("resolved", resolved)
            .field("targets", targets)
            .field("linked_request_ids", linked_request_ids)
            .field("held_files", held_files)
            .field("auto_hidden_file_ids", auto_hidden_file_ids)
            .field("hold_until", hold_until)
            .field("child_safety", child_safety)
            .field("bad_faith", bad_faith)
            .field("throttled", throttled)
            .field("decline_reason", decline_reason)
            .field("first_opened_at", first_opened_at)
            .field("removed_at", removed_at)
            .field("closed_at", closed_at)
            .field("requester_purged", requester_purged)
            .field("reviewer_note", &redact_option(reviewer_note))
            .field("revision", revision)
            .field("markers", markers)
            .finish()
    }
}

/// The requester's personal data. Only ever stored sealed.
///
/// Outside `auto_derived!` so `Debug` can be hand-written: it never prints
/// personal data.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SealedRequester {
    pub role: TakedownRole,
    pub authority_note: Option<String>,
    /// The given name, or the signature when none was given
    pub name: String,
    pub signature: String,
    pub email: String,
    pub description: String,
    pub extra: Option<String>,
    /// Later additions from the status page
    #[serde(default)]
    pub added_info: Vec<String>,
}

impl std::fmt::Debug for SealedRequester {
    /// Prints the role and which fields are filled in, never their content
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // deliberately printed or redacted here
        let SealedRequester {
            role,
            authority_note,
            name,
            signature,
            email,
            description,
            extra,
            added_info,
        } = self;

        f.debug_struct("SealedRequester")
            .field("role", role)
            .field("authority_note", &redact_option(authority_note))
            .field("name", &redact(name))
            .field("signature", &redact(signature))
            .field("email", &redact(email))
            .field("description", &redact(description))
            .field("extra", &redact_option(extra))
            .field("added_info", &added_info.len())
            .finish()
    }
}

fn redact(value: &str) -> &'static str {
    if value.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}

fn redact_option(value: &Option<String>) -> &'static str {
    match value {
        Some(value) => redact(value),
        None => "<none>",
    }
}

impl TakedownStatus {
    /// Received, NeedsInfo and UnderReview are open; the rest are outcomes
    pub fn is_open(&self) -> bool {
        matches!(
            self,
            TakedownStatus::Received | TakedownStatus::NeedsInfo | TakedownStatus::UnderReview
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SealedRequester, TakedownRole, TakedownSource, TakedownStatus, TakedownTarget,
        UnresolvableKind,
    };

    #[test]
    fn tagged_enums_use_a_type_field() {
        assert_eq!(
            serde_json::to_value(TakedownSource::InApp {
                report_id: "R".to_string()
            })
            .unwrap(),
            serde_json::json!({ "type": "InApp", "report_id": "R" })
        );
        assert_eq!(
            serde_json::to_value(TakedownSource::Web).unwrap(),
            serde_json::json!({ "type": "Web" })
        );
        assert_eq!(
            serde_json::to_value(TakedownTarget::Unresolvable {
                location_index: 3,
                kind: UnresolvableKind::PrivateConversation
            })
            .unwrap(),
            serde_json::json!({
                "type": "Unresolvable",
                "location_index": 3,
                "kind": "PrivateConversation"
            })
        );
    }

    #[test]
    fn sealed_requester_debug_prints_no_personal_data() {
        let requester = SealedRequester {
            role: TakedownRole::Authorized,
            authority_note: Some("NOTE-SECRET".to_string()),
            name: "NAME-SECRET".to_string(),
            signature: "SIGNATURE-SECRET".to_string(),
            email: "EMAIL-SECRET@example.com".to_string(),
            description: "DESCRIPTION-SECRET".to_string(),
            extra: Some("EXTRA-SECRET".to_string()),
            added_info: vec!["ADDED-SECRET".to_string()],
        };

        let printed = format!("{requester:?} {requester:#?}");
        assert!(!printed.contains("SECRET"), "{printed}");
        assert!(printed.contains("Authorized"));
        assert!(printed.contains("<redacted>"));

        // The serialized form (what gets sealed) still carries everything.
        let json = serde_json::to_string(&requester).unwrap();
        assert!(json.contains("EMAIL-SECRET@example.com"));
        assert!(json.contains("ADDED-SECRET"));
    }

    #[test]
    fn new_fields_default_when_absent() {
        let request: super::TakedownRequest = serde_json::from_value(serde_json::json!({
            "_id": "01TD0000000000000000000001",
            "status": "Received",
            "source": { "type": "Web" },
            "received_at": "2026-11-11T00:00:00Z",
            "deadline_at": "2026-11-13T00:00:00Z",
            "sealed": "",
            "contact_fp": "",
            "status_token_hash": "",
            "locations": [],
            "minor_claimed": false
        }))
        .unwrap();
        assert_eq!(request.revision, 0);
        assert!(request.held_files.is_empty());
        assert_eq!(request.reviewer_note, None);
        assert!(request.markers.is_empty());
    }

    #[test]
    fn open_statuses() {
        assert!(TakedownStatus::Received.is_open());
        assert!(TakedownStatus::NeedsInfo.is_open());
        assert!(TakedownStatus::UnderReview.is_open());
        assert!(!TakedownStatus::Removed.is_open());
        assert!(!TakedownStatus::PartiallyRemoved.is_open());
        assert!(!TakedownStatus::Declined.is_open());
        assert!(!TakedownStatus::Closed.is_open());
    }
}
