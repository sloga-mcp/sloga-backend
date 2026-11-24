auto_derived!(
    /// # Account Deletion Token
    pub struct DataAccountDeletion {
        /// Deletion token
        pub token: String,
        /// Must be true. Sent only by the confirm page's 'Delete permanently'
        /// button, so an old cached page that confirms on load (sending just
        /// the token) is refused.
        // Required in JSON on purpose (no `#[serde(default)]`): a body
        // without it fails to deserialize before the route runs.
        pub confirm: bool,
    }

    /// # Account Data
    pub struct DataCreateAccount {
        /// Valid email address
        pub email: String,
        /// Password
        pub password: String,
        /// Invite code
        pub invite: Option<String>,
        /// Captcha verification code
        pub captcha: Option<String>,
    }

    pub struct AccountInfo {
        #[serde(rename = "_id")]
        pub id: String,
        /// Email address; empty when the account has none
        pub email: String,
        /// Whether the account has no email address
        #[serde(default)]
        pub email_absent: bool,
    }

    /// # Password Reset
    pub struct DataPasswordReset {
        /// Reset token
        pub token: String,

        /// New password
        pub password: String,

        /// Whether to logout all sessions
        #[serde(default)]
        pub remove_sessions: bool,
    }

    /// # Resend Information
    pub struct DataResendVerification {
        /// Email associated with the account
        pub email: String,
        /// Captcha verification code
        pub captcha: Option<String>,
    }

    /// # Reset Information
    pub struct DataSendPasswordReset {
        /// Email associated with the account
        pub email: String,
        /// Captcha verification code
        pub captcha: Option<String>,
    }

    /// # Add an Email
    ///
    /// Starts giving an account that has no email its first address: a code
    /// is mailed to it
    pub struct DataEmailAddStart {
        /// Valid email address
        pub email: String,
    }
);

/// # Confirm the Added Email
///
/// Every derive `auto_derived!` gives except `Debug`, which is written by
/// hand so the code can never be printed or logged.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataEmailAddFinish {
    /// The code from the email
    pub code: String,
}

impl std::fmt::Debug for DataEmailAddFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let DataEmailAddFinish { code: _ } = self;
        f.debug_struct("DataEmailAddFinish")
            .field("code", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountInfo, DataAccountDeletion, DataEmailAddFinish, DataEmailAddStart};
    use serde_json::json;

    /// Fails if: `email_absent` stops being additive (an answer from an
    /// older server must parse, as having an email) or stops being sent.
    #[test]
    fn account_info_email_absent_is_additive() {
        let old: AccountInfo =
            serde_json::from_value(json!({ "_id": "01ACCOUNT", "email": "a@example.test" }))
                .expect("an older answer");
        assert!(!old.email_absent);
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            json!({ "_id": "01ACCOUNT", "email": "a@example.test", "email_absent": false })
        );

        let absent = AccountInfo {
            id: "01ACCOUNT".to_string(),
            email: String::new(),
            email_absent: true,
        };
        let value = serde_json::to_value(&absent).unwrap();
        assert_eq!(
            value,
            json!({ "_id": "01ACCOUNT", "email": "", "email_absent": true })
        );
        assert_eq!(serde_json::from_value::<AccountInfo>(value).unwrap(), absent);
    }

    /// Fails if: the add-email bodies change shape, or `Debug` prints the
    /// code.
    #[test]
    fn add_email_bodies_parse_and_the_code_is_never_printed() {
        let start: DataEmailAddStart =
            serde_json::from_value(json!({ "email": "a@example.test" })).unwrap();
        assert_eq!(start.email, "a@example.test");
        assert!(serde_json::from_value::<DataEmailAddStart>(json!({})).is_err());

        let finish: DataEmailAddFinish =
            serde_json::from_value(json!({ "code": "CODE-MARKER-01234567" })).unwrap();
        assert_eq!(finish.code, "CODE-MARKER-01234567");
        assert!(serde_json::from_value::<DataEmailAddFinish>(json!({})).is_err());

        for printed in [format!("{finish:?}"), format!("{finish:#?}")] {
            assert!(!printed.contains("CODE-MARKER"), "{printed}");
            assert!(printed.contains("<redacted>"), "{printed}");
        }
    }

    /// An old cached confirm page sends only the token; that body must not
    /// deserialize, so the confirm route never runs for it
    #[test]
    fn account_deletion_without_confirm_is_refused() {
        assert!(serde_json::from_str::<DataAccountDeletion>(r#"{"token":"x"}"#).is_err());
    }

    /// The confirm page's button sends the token and `confirm: true`
    #[test]
    fn account_deletion_with_confirm_deserializes() {
        let data: DataAccountDeletion =
            serde_json::from_str(r#"{"token":"x","confirm":true}"#).unwrap();
        assert_eq!(
            data,
            DataAccountDeletion {
                token: "x".to_string(),
                confirm: true,
            }
        );
    }
}