#[cfg(feature = "validator")]
use validator::{Validate, ValidationError};

/// Default for the removal options that are on unless turned off
fn yes() -> bool {
    true
}

/// Up to 20 locations, each 1 to 2048 characters
#[cfg(feature = "validator")]
pub(crate) fn validate_takedown_locations(locations: &[String]) -> Result<(), ValidationError> {
    if locations.len() > 20 {
        return Err(ValidationError::new("too_many_locations"));
    }
    if locations
        .iter()
        .any(|location| location.is_empty() || location.chars().count() > 2048)
    {
        return Err(ValidationError::new("location_length"));
    }
    Ok(())
}

/// A box the requester must tick
#[cfg(feature = "validator")]
pub(crate) fn validate_ticked(value: &bool) -> Result<(), ValidationError> {
    if *value {
        Ok(())
    } else {
        Err(ValidationError::new("must_be_true"))
    }
}

auto_derived!(
    /// Who is filing a Take It Down request
    pub enum TakedownRole {
        /// The person shown
        Depicted,
        /// Someone authorized to act for the person shown
        Authorized,
    }

    /// A stored request's public reference
    pub struct TakedownSubmitted {
        /// `TD-<ULID>`
        pub reference: String,
    }

    /// Request state as shown on the status page
    pub enum TakedownPublicState {
        Received,
        NeedsInfo,
        UnderReview,
        Removed,
        PartiallyRemoved,
        Declined,
        Closed,
    }

    /// Decline reason as shown to the requester (bad faith shows as Other)
    pub enum TakedownPublicDecline {
        NotIntimate,
        NotFound,
        NotOnSloga,
        Duplicate,
        Other,
    }

    /// What the status page shows
    pub struct TakedownPublicStatus {
        pub reference: String,
        pub state: TakedownPublicState,
        pub decline: Option<TakedownPublicDecline>,
        /// RFC 3339
        pub received_at: String,
    }

    /// Whether the public form is available
    pub struct TakedownPublicConfig {
        pub enabled: bool,
        pub captcha_sitekey: Option<String>,
    }

    /// One row of the staff queue
    pub struct TakedownSummary {
        pub id: String,
        pub reference: String,
        pub status: String,
        pub received_at: String,
        pub deadline_at: String,
        pub minor_claimed: bool,
        pub in_app: bool,
        pub targets: usize,
        pub opened: bool,
        pub child_safety: bool,
        pub throttled: bool,
        pub bad_faith_history: bool,
        pub auto_hidden: usize,
    }

    /// A file a target carries
    pub struct TakedownFileView {
        pub id: String,
        pub tag: String,
        pub content_type: String,
        pub size: isize,
        /// Identical copies elsewhere on Sloga
        pub copies: u64,
        pub hidden: bool,
    }

    /// A resolved target as reviewers see it
    pub struct TakedownTargetView {
        pub index: usize,
        /// Message, File, User, Server, Emoji or Unresolvable
        pub kind: String,
        pub id: Option<String>,
        pub channel_id: Option<String>,
        pub server_id: Option<String>,
        pub author_id: Option<String>,
        pub created_at: Option<String>,
        pub encrypted: bool,
        pub unresolvable: Option<String>,
        pub files: Vec<TakedownFileView>,
    }

    /// A staff audit row
    pub struct StaffAuditView {
        pub id: String,
        pub created_at: String,
        pub actor: Option<String>,
        pub action: String,
        pub target_ids: Vec<String>,
        pub count: Option<u64>,
        pub note: Option<String>,
    }

    /// Everything a reviewer sees for one request
    pub struct TakedownDetail {
        pub summary: TakedownSummary,
        /// `None` once the requester's details have been purged
        pub requester: Option<TakedownRequesterView>,
        pub locations: Vec<String>,
        pub targets: Vec<TakedownTargetView>,
        pub linked: Vec<String>,
        pub audit: Vec<StaffAuditView>,
    }

    /// Remove targets
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataTakedownRemove {
        /// Indexes into the request's targets
        #[cfg_attr(feature = "validator", validate(length(max = 100)))]
        pub targets: Vec<usize>,
        #[serde(default)]
        pub whole_message: bool,
        #[serde(default = "yes")]
        pub include_copies: bool,
        #[serde(default = "yes")]
        pub block_reuploads: bool,
        /// The copy count the reviewer confirmed, when over the threshold
        pub confirm_copies: Option<u64>,
    }

    /// What a removal did
    pub struct TakedownRemoveResult {
        pub removed_files: usize,
        pub deleted_messages: usize,
        pub copies: u64,
        pub blocked: usize,
    }

    /// Decline a request
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataTakedownDecline {
        pub reason: TakedownPublicDecline,
        #[serde(default)]
        pub bad_faith: bool,
        /// Internal note (stored as the request's `reviewer_note`); never
        /// sent to the requester
        #[cfg_attr(feature = "validator", validate(length(max = 1000)))]
        pub note: Option<String>,
    }

    /// Files to unhide
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataTakedownFileIds {
        #[cfg_attr(feature = "validator", validate(length(max = 200)))]
        pub files: Vec<String>,
    }
);

/// Status lookup; the token comes from the status link's fragment
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[cfg_attr(feature = "validator", derive(Validate))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataTakedownLookup {
    #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
    pub reference: String,
    /// Works like a password for the request; never printed
    #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
    pub token: String,
}

impl std::fmt::Debug for DataTakedownLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let DataTakedownLookup { reference, token } = self;
        f.debug_struct("DataTakedownLookup")
            .field("reference", reference)
            .field("token", &redact(token))
            .finish()
    }
}

/// More information added from the status page
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[cfg_attr(feature = "validator", derive(Validate))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataTakedownAddInfo {
    #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
    pub reference: String,
    #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
    pub token: String,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(
        feature = "validator",
        validate(custom = "validate_takedown_locations")
    )]
    pub locations: Vec<String>,
    #[cfg_attr(feature = "validator", validate(length(max = 4000)))]
    pub extra: Option<String>,
}

impl std::fmt::Debug for DataTakedownAddInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let DataTakedownAddInfo {
            reference,
            token,
            locations,
            extra,
        } = self;
        f.debug_struct("DataTakedownAddInfo")
            .field("reference", reference)
            .field("token", &redact(token))
            .field("locations", &locations.len())
            .field("extra", &redact_option(extra))
            .finish()
    }
}

// The structs below carry requester personal data. They are outside
// `auto_derived!` so `Debug` can be hand-written to never print it.

/// Public Take It Down request (no account)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[cfg_attr(feature = "validator", derive(Validate))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataCreateTakedownRequest {
    /// Captcha verification code
    pub captcha: Option<String>,
    pub role: TakedownRole,
    /// How the requester is authorized to act for the person shown
    #[cfg_attr(feature = "validator", validate(length(max = 1000)))]
    pub authority_note: Option<String>,
    /// Where the image is and what it shows
    #[cfg_attr(feature = "validator", validate(length(min = 1, max = 4000)))]
    pub description: String,
    /// Links or ids as given by the requester
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(
        feature = "validator",
        validate(custom = "validate_takedown_locations")
    )]
    pub locations: Vec<String>,
    /// The good-faith statement was ticked
    #[cfg_attr(feature = "validator", validate(custom = "validate_ticked"))]
    pub statement_ack: bool,
    /// Anything else that helps
    #[cfg_attr(feature = "validator", validate(length(max = 4000)))]
    pub extra: Option<String>,
    /// Contact email (format only)
    #[cfg_attr(feature = "validator", validate(length(max = 254), email))]
    pub email: String,
    /// Optional; the signature stands in for it when absent
    #[cfg_attr(feature = "validator", validate(length(max = 200)))]
    pub name: Option<String>,
    /// Typed full name used as the electronic signature
    #[cfg_attr(feature = "validator", validate(length(min = 1, max = 200)))]
    pub signature: String,
    /// "Typing my name is my electronic signature" was ticked
    #[cfg_attr(feature = "validator", validate(custom = "validate_ticked"))]
    pub signature_ack: bool,
    /// The person shown was under 18 (requester's claim)
    #[cfg_attr(feature = "serde", serde(default))]
    pub minor: bool,
}

impl std::fmt::Debug for DataCreateTakedownRequest {
    /// Prints flags and which fields are filled in, never their content
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // deliberately printed or redacted here
        let DataCreateTakedownRequest {
            captcha,
            role,
            authority_note,
            description,
            locations,
            statement_ack,
            extra,
            email,
            name,
            signature,
            signature_ack,
            minor,
        } = self;

        f.debug_struct("DataCreateTakedownRequest")
            .field("captcha", &redact_option(captcha))
            .field("role", role)
            .field("authority_note", &redact_option(authority_note))
            .field("description", &redact(description))
            .field("locations", &locations.len())
            .field("statement_ack", statement_ack)
            .field("extra", &redact_option(extra))
            .field("email", &redact(email))
            .field("name", &redact_option(name))
            .field("signature", &redact(signature))
            .field("signature_ack", signature_ack)
            .field("minor", minor)
            .finish()
    }
}

/// The requester's details, for reviewers only
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct TakedownRequesterView {
    pub role: TakedownRole,
    pub authority_note: Option<String>,
    pub name: String,
    pub signature: String,
    pub email: String,
    pub description: String,
    pub extra: Option<String>,
    pub added_info: Vec<String>,
}

impl std::fmt::Debug for TakedownRequesterView {
    /// Prints the role and which fields are filled in, never their content
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let TakedownRequesterView {
            role,
            authority_note,
            name,
            signature,
            email,
            description,
            extra,
            added_info,
        } = self;

        f.debug_struct("TakedownRequesterView")
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

/// What a redacting `Debug` prints for a personal-data string
pub(crate) fn redact(value: &str) -> &'static str {
    if value.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}

/// `redact` for an optional string
pub(crate) fn redact_option(value: &Option<String>) -> &'static str {
    match value {
        Some(value) => redact(value),
        None => "<none>",
    }
}

#[cfg(test)]
mod tests {
    use super::{DataTakedownRemove, TakedownRole};

    #[test]
    fn removal_options_default_on() {
        let remove: DataTakedownRemove =
            serde_json::from_value(serde_json::json!({ "targets": [0, 2] })).unwrap();
        assert_eq!(remove.targets, vec![0, 2]);
        assert!(!remove.whole_message);
        assert!(remove.include_copies);
        assert!(remove.block_reuploads);
        assert_eq!(remove.confirm_copies, None);
    }

    #[test]
    fn debug_prints_no_personal_data() {
        use super::{DataCreateTakedownRequest, TakedownRequesterView};

        let request = DataCreateTakedownRequest {
            captcha: Some("CAPTCHA-SECRET".to_string()),
            role: TakedownRole::Depicted,
            authority_note: Some("NOTE-SECRET".to_string()),
            description: "DESCRIPTION-SECRET".to_string(),
            locations: vec!["https://LOCATION-SECRET".to_string()],
            statement_ack: true,
            extra: Some("EXTRA-SECRET".to_string()),
            email: "EMAIL-SECRET@example.com".to_string(),
            name: Some("NAME-SECRET".to_string()),
            signature: "SIGNATURE-SECRET".to_string(),
            signature_ack: true,
            minor: false,
        };
        let printed = format!("{request:?} {request:#?}");
        assert!(!printed.contains("SECRET"), "{printed}");
        assert!(printed.contains("Depicted"));

        let view = TakedownRequesterView {
            role: TakedownRole::Authorized,
            authority_note: Some("NOTE-SECRET".to_string()),
            name: "NAME-SECRET".to_string(),
            signature: "SIGNATURE-SECRET".to_string(),
            email: "EMAIL-SECRET@example.com".to_string(),
            description: "DESCRIPTION-SECRET".to_string(),
            extra: None,
            added_info: vec!["ADDED-SECRET".to_string()],
        };
        let printed = format!("{view:?}");
        assert!(!printed.contains("SECRET"), "{printed}");

        // Still serialized in full for the reviewer.
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains("EMAIL-SECRET@example.com"));
    }

    #[test]
    fn role_names() {
        assert_eq!(
            serde_json::to_value(TakedownRole::Authorized).unwrap(),
            serde_json::json!("Authorized")
        );
    }

    #[cfg(feature = "validator")]
    mod validation {
        use validator::Validate;

        use crate::v0::{DataCreateTakedownRequest, DataTakedownAddInfo, TakedownRole};

        fn valid() -> DataCreateTakedownRequest {
            DataCreateTakedownRequest {
                captcha: None,
                role: TakedownRole::Depicted,
                authority_note: None,
                description: "A photo of me in a server".to_string(),
                locations: vec!["https://app.sloga.gg/channel/A/B".to_string()],
                statement_ack: true,
                extra: None,
                email: "person@example.com".to_string(),
                name: Some("Jane Doe".to_string()),
                signature: "Jane Doe".to_string(),
                signature_ack: true,
                minor: false,
            }
        }

        #[test]
        fn a_complete_request_validates() {
            assert!(valid().validate().is_ok());

            // Links are optional; a description alone is enough.
            let mut no_links = valid();
            no_links.locations = vec![];
            assert!(no_links.validate().is_ok());
        }

        #[test]
        fn both_ticks_are_required() {
            let mut request = valid();
            request.statement_ack = false;
            assert!(request.validate().is_err());

            let mut request = valid();
            request.signature_ack = false;
            assert!(request.validate().is_err());
        }

        #[test]
        fn field_limits() {
            let mut request = valid();
            request.description = String::new();
            assert!(request.validate().is_err());

            let mut request = valid();
            request.signature = String::new();
            assert!(request.validate().is_err());

            // The name is optional; only the four legal elements are required.
            let mut request = valid();
            request.name = None;
            assert!(request.validate().is_ok());

            let mut request = valid();
            request.name = Some("x".repeat(201));
            assert!(request.validate().is_err());

            let mut request = valid();
            request.email = "not an email".to_string();
            assert!(request.validate().is_err());

            let mut request = valid();
            request.locations = vec!["x".to_string(); 21];
            assert!(request.validate().is_err());

            let mut request = valid();
            request.locations = vec!["x".to_string(); 20];
            assert!(request.validate().is_ok());

            let mut request = valid();
            request.locations = vec![String::new()];
            assert!(request.validate().is_err());

            let mut request = valid();
            request.locations = vec!["x".repeat(2049)];
            assert!(request.validate().is_err());
        }

        #[test]
        fn staff_body_caps() {
            use crate::v0::{
                DataTakedownDecline, DataTakedownFileIds, DataTakedownRemove, TakedownPublicDecline,
            };

            let remove = |count: usize| DataTakedownRemove {
                targets: vec![0; count],
                whole_message: false,
                include_copies: true,
                block_reuploads: true,
                confirm_copies: None,
            };
            assert!(remove(100).validate().is_ok());
            assert!(remove(101).validate().is_err());

            let decline = |note: Option<String>| DataTakedownDecline {
                reason: TakedownPublicDecline::Other,
                bad_faith: false,
                note,
            };
            assert!(decline(None).validate().is_ok());
            assert!(decline(Some("x".repeat(1000))).validate().is_ok());
            assert!(decline(Some("x".repeat(1001))).validate().is_err());

            let files = |count: usize| DataTakedownFileIds {
                files: vec!["F".to_string(); count],
            };
            assert!(files(200).validate().is_ok());
            assert!(files(201).validate().is_err());
        }

        #[test]
        fn add_info_limits() {
            let info = DataTakedownAddInfo {
                reference: "TD-01TD0000000000000000000001".to_string(),
                token: "token".to_string(),
                locations: vec!["x".to_string(); 21],
                extra: None,
            };
            assert!(info.validate().is_err());
        }
    }
}
