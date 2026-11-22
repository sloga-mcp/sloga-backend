auto_derived!(
    /// # Change Email Data
    pub struct DataChangeEmail {
        /// Valid email address
        pub email: String,
        /// Current password
        pub current_password: String,
    }

    /// # Change Data
    pub struct DataChangePassword {
        /// New password
        pub password: String,
        /// Current password
        pub current_password: String,
    }

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
        pub email: String,
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
);

#[cfg(test)]
mod tests {
    use super::DataAccountDeletion;

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