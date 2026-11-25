use iso8601_timestamp::Timestamp;
#[cfg(feature = "validator")]
use validator::Validate;

#[cfg(feature = "validator")]
use super::takedown::validate_ticked;
use super::takedown::{redact, redact_option};
use super::TakedownRole;

auto_derived!(
    /// User-generated platform moderation report
    pub struct Report {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the user creating this report
        pub author_id: String,
        /// Reported content
        pub content: ReportedContent,
        /// Additional report context
        pub additional_context: String,
        /// Status of the report
        #[serde(flatten)]
        pub status: ReportStatus,
        /// Additional notes included on the report
        #[serde(default)]
        pub notes: String,
    }

    /// Reason for reporting content (message or server)
    pub enum ContentReportReason {
        /// No reason has been specified
        NoneSpecified,

        /// Illegal content catch-all reason
        Illegal,

        /// Selling or facilitating use of drugs or other illegal goods
        IllegalGoods,

        /// Extortion or blackmail
        IllegalExtortion,

        /// Legacy: revenge or underage pornography; sent by older clients
        IllegalPornography,

        /// Illegal hacking activity
        IllegalHacking,

        /// Extreme violence, gore, or animal cruelty
        /// With exception to violence potrayed in media / creative arts
        ExtremeViolence,

        /// Content that promotes harm to others / self
        PromotesHarm,

        /// Unsolicited advertisements
        UnsolicitedSpam,

        /// This is a raid
        Raid,

        /// Spam or platform abuse
        SpamAbuse,

        /// Scams or fraud
        ScamsFraud,

        /// Distribution of malware or malicious links
        Malware,

        /// Harassment or abuse targeted at another user
        Harassment,

        /// Intimate images shared without consent
        NonConsensualIntimateImage,

        /// Child sexual abuse material
        ChildSexualAbuseMaterial,
    }

    /// Reason for reporting a user
    pub enum UserReportReason {
        /// No reason has been specified
        NoneSpecified,

        /// Unsolicited advertisements
        UnsolicitedSpam,

        /// User is sending spam or otherwise abusing the platform
        SpamAbuse,

        /// User's profile contains inappropriate content for a general audience
        InappropriateProfile,

        /// User is impersonating another user
        Impersonation,

        /// User is evading a ban
        BanEvasion,

        /// User is not of minimum age to use the platform
        Underage,

        /// Intimate images shared without consent
        NonConsensualIntimateImage,
    }

    /// The content being reported
    #[serde(tag = "type")]
    pub enum ReportedContent {
        /// Report a message
        Message {
            /// ID of the message
            id: String,
            /// Reason for reporting message
            report_reason: ContentReportReason,
        },
        /// Report a server
        Server {
            /// ID of the server
            id: String,
            /// Reason for reporting server
            report_reason: ContentReportReason,
        },
        /// Report a user
        User {
            /// ID of the user
            id: String,
            /// Reason for reporting a user
            report_reason: UserReportReason,
            /// Message context
            message_id: Option<String>,
        },
    }

    /// Status of the report
    #[serde(tag = "status")]
    pub enum ReportStatus {
        /// Report is waiting for triage / action
        Created {},

        /// Report was rejected
        Rejected {
            rejection_reason: String,
            closed_at: Option<Timestamp>,
        },

        /// Report was actioned and resolved
        Resolved { closed_at: Option<Timestamp> },
    }

    /// Just the status of the report
    pub enum ReportStatusString {
        /// Report is waiting for triage / action
        Created,

        /// Report was rejected
        Rejected,

        /// Report was actioned and resolved
        Resolved,
    }

    /// Reporter-supplied copy of a message, captured on the reporter's
    /// device at the time of reporting. Stands alone from server-side data
    /// so reports keep working for conversations the server cannot read
    /// (end-to-end encrypted DMs).
    pub struct ReportedMessageSnapshot {
        /// Id of the message
        pub id: String,
        /// Channel the message was sent in
        pub channel: String,
        /// Id of the message author
        pub author: String,
        /// Message content as rendered on the reporter's device
        pub content: String,
        /// Whether this content was end-to-end encrypted: the plaintext was
        /// attached by the reporter from their local store and was NEVER
        /// server-visible (provenance for the moderation team).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        pub encrypted: bool,
    }
);

/// Take It Down fields sent with an in-app report. They go only into the
/// linked Take It Down request, never into the report or its event.
///
/// Outside `auto_derived!` so `Debug` can be hand-written: it never prints
/// personal data.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[cfg_attr(feature = "validator", derive(Validate))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataInAppTakedown {
    pub role: TakedownRole,
    /// How the reporter is authorized to act for the person shown
    #[cfg_attr(feature = "validator", validate(length(max = 1000)))]
    pub authority_note: Option<String>,
    /// Typed full name used as the electronic signature
    #[cfg_attr(feature = "validator", validate(length(min = 1, max = 200)))]
    pub signature: String,
    #[cfg_attr(feature = "validator", validate(custom = "validate_ticked"))]
    pub signature_ack: bool,
    #[cfg_attr(feature = "validator", validate(custom = "validate_ticked"))]
    pub statement_ack: bool,
    /// Contact email; the account's email when absent
    #[cfg_attr(feature = "validator", validate(length(max = 254), email))]
    pub email: Option<String>,
    #[cfg_attr(feature = "validator", validate(length(max = 4000)))]
    pub extra: Option<String>,
}

impl std::fmt::Debug for DataInAppTakedown {
    /// Prints flags and which fields are filled in, never their content
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // deliberately printed or redacted here
        let DataInAppTakedown {
            role,
            authority_note,
            signature,
            signature_ack,
            statement_ack,
            email,
            extra,
        } = self;

        f.debug_struct("DataInAppTakedown")
            .field("role", role)
            .field("authority_note", &redact_option(authority_note))
            .field("signature", &redact(signature))
            .field("signature_ack", signature_ack)
            .field("statement_ack", statement_ack)
            .field("email", &redact_option(email))
            .field("extra", &redact_option(extra))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::DataInAppTakedown;
    use crate::v0::TakedownRole;

    #[test]
    fn in_app_takedown_debug_prints_no_personal_data() {
        let takedown = DataInAppTakedown {
            role: TakedownRole::Authorized,
            authority_note: Some("NOTE-SECRET".to_string()),
            signature: "SIGNATURE-SECRET".to_string(),
            signature_ack: true,
            statement_ack: true,
            email: Some("EMAIL-SECRET@example.com".to_string()),
            extra: Some("EXTRA-SECRET".to_string()),
        };
        let printed = format!("{takedown:?} {takedown:#?}");
        assert!(!printed.contains("SECRET"), "{printed}");
        assert!(printed.contains("Authorized"));
    }
}
