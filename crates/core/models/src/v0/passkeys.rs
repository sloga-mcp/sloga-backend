use iso8601_timestamp::Timestamp;

auto_derived!(
    /// # Passkey
    ///
    /// A passkey registered on the account. The stored credential itself is
    /// never part of the API model.
    pub struct PasskeyInfo {
        /// Unique Id
        pub id: String,

        /// Name the user gave this passkey
        pub name: String,

        /// When this passkey was registered
        pub created_at: Timestamp,

        /// When this passkey was last used, if ever
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub last_used_at: Option<Timestamp>,
    }

    /// # Passkey Ceremony Options
    ///
    /// Returned when a passkey ceremony starts
    pub struct ResponsePasskeyOptions {
        /// Id of the challenge, handed back when the ceremony finishes
        pub challenge_id: String,

        /// WebAuthn options, passed as is to the platform credential API
        pub options: serde_json::Value,
    }

    /// # Rename Passkey
    pub struct DataPasskeyRename {
        /// New name for the passkey
        pub name: String,
    }

    /// # Add Passkey Options
    ///
    /// Returned when adding a passkey to a signed-in account starts:
    /// `ResponsePasskeyOptions` plus whether the finish step will ask for
    /// an MFA ticket
    pub struct ResponsePasskeyRegisterStart {
        /// Id of the challenge, handed back when the ceremony finishes
        pub challenge_id: String,

        /// WebAuthn options, passed as is to the platform credential API
        pub options: serde_json::Value,

        /// Whether the finish step needs an MFA ticket. An answer without
        /// the field (an older server) reads as true
        #[serde(default = "ticket_required_default")]
        pub ticket_required: bool,
    }

    /// # Lost Passkey
    ///
    /// Asks for a recovery link. The answer is the same whether or not the
    /// address has an account
    pub struct DataPasskeyRecoverSend {
        /// Email associated with the account
        pub email: String,
    }

    /// # Passkey Recovery Options
    ///
    /// Returned for a valid recovery link. The challenge is bound to the
    /// link's token as well as to its id, and the account's existing
    /// passkeys are not listed
    pub struct ResponsePasskeyRecoverStart {
        /// Id of the challenge, handed back when the recovery finishes
        pub challenge_id: String,

        /// WebAuthn options, passed as is to the platform credential API
        pub options: serde_json::Value,

        /// Whether the finish step also needs an authenticator code or a
        /// recovery code
        pub second_factor_required: bool,
    }
);

/// A register-start answer with no `ticket_required` asks for a ticket
fn ticket_required_default() -> bool {
    true
}

/// What `Debug` prints in place of a credential or a challenge id
const REDACTED: &str = "<redacted>";

// The two types below carry what the device signed. They get every derive
// `auto_derived!` gives except `Debug`, which is written by hand so the
// credential and the challenge id can never be printed or logged.

/// # Finish Passkey Ceremony
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataPasskeyFinish {
    /// Id of the challenge the ceremony was started with
    pub challenge_id: String,

    /// WebAuthn credential, as returned by the platform credential API
    pub credential: serde_json::Value,

    /// Name for a newly registered passkey
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub name: Option<String>,
}

impl std::fmt::Debug for DataPasskeyFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let DataPasskeyFinish {
            challenge_id: _,
            credential: _,
            name,
        } = self;
        f.debug_struct("DataPasskeyFinish")
            .field("challenge_id", &REDACTED)
            .field("credential", &REDACTED)
            .field("name", name)
            .finish()
    }
}

/// # Passkey Ticket Response
///
/// A passkey assertion given as an MFA response
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct PasskeyTicketResponse {
    /// Id of the challenge the assertion was started with
    pub challenge_id: String,

    /// WebAuthn assertion, as returned by the platform credential API
    pub credential: serde_json::Value,
}

impl std::fmt::Debug for PasskeyTicketResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let PasskeyTicketResponse {
            challenge_id: _,
            credential: _,
        } = self;
        f.debug_struct("PasskeyTicketResponse")
            .field("challenge_id", &REDACTED)
            .field("credential", &REDACTED)
            .finish()
    }
}

// Passkey sign-up and recovery bodies. Each carries a pending sign-up id, a
// code, a link token, a captcha answer, an invite or a credential, so each
// gets a hand-written `Debug` as above. An optional secret prints as
// `Some("<redacted>")` or `None`.

fn redacted_option(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

/// # Start Passkey Sign-Up
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataPasskeySignupStart {
    /// Username for the new account
    pub username: String,

    /// Email address. Left out to sign up with no email
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub email: Option<String>,

    /// Must be true when no email is given: the person was told the account
    /// cannot be recovered if the passkey is lost
    #[cfg_attr(feature = "serde", serde(default))]
    pub no_email_ack: bool,

    /// Account invite code, where sign-up is invite-only
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub invite: Option<String>,

    /// Referral code
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub referral_code: Option<String>,

    /// Server invite the person arrived through
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub invite_code: Option<String>,

    /// Captcha verification code
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub captcha: Option<String>,
}

impl std::fmt::Debug for DataPasskeySignupStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let DataPasskeySignupStart {
            username,
            email,
            no_email_ack,
            invite,
            referral_code,
            invite_code,
            captcha,
        } = self;
        f.debug_struct("DataPasskeySignupStart")
            .field("username", username)
            .field("email", &redacted_option(email))
            .field("no_email_ack", no_email_ack)
            .field("invite", &redacted_option(invite))
            .field("referral_code", referral_code)
            .field("invite_code", &redacted_option(invite_code))
            .field("captcha", &redacted_option(captcha))
            .finish()
    }
}

/// # Passkey Sign-Up Started
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct ResponsePasskeySignupStart {
    /// Id of the pending sign-up, handed back at each later step
    pub signup_id: String,

    /// Whether a code was mailed and has to be confirmed before the passkey
    /// can be created
    pub email_code_required: bool,
}

impl std::fmt::Debug for ResponsePasskeySignupStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let ResponsePasskeySignupStart {
            signup_id: _,
            email_code_required,
        } = self;
        f.debug_struct("ResponsePasskeySignupStart")
            .field("signup_id", &REDACTED)
            .field("email_code_required", email_code_required)
            .finish()
    }
}

/// # Confirm Passkey Sign-Up Email
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataPasskeySignupCode {
    /// Id of the pending sign-up
    pub signup_id: String,

    /// The code from the email
    pub code: String,
}

impl std::fmt::Debug for DataPasskeySignupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let DataPasskeySignupCode {
            signup_id: _,
            code: _,
        } = self;
        f.debug_struct("DataPasskeySignupCode")
            .field("signup_id", &REDACTED)
            .field("code", &REDACTED)
            .finish()
    }
}

/// # Passkey Sign-Up Options
///
/// Asks for the WebAuthn options of a pending sign-up; answered with
/// `ResponsePasskeyOptions`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataPasskeySignupOptions {
    /// Id of the pending sign-up
    pub signup_id: String,
}

impl std::fmt::Debug for DataPasskeySignupOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let DataPasskeySignupOptions { signup_id: _ } = self;
        f.debug_struct("DataPasskeySignupOptions")
            .field("signup_id", &REDACTED)
            .finish()
    }
}

/// # Finish Passkey Sign-Up
///
/// Everything else about the new account was fixed when the sign-up
/// started; answered with `ResponseLogin`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataPasskeySignupFinish {
    /// Id of the challenge the options were answered with
    pub challenge_id: String,

    /// WebAuthn credential, as returned by the platform credential API
    pub credential: serde_json::Value,

    /// Friendly name used for the session
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub friendly_name: Option<String>,
}

impl std::fmt::Debug for DataPasskeySignupFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let DataPasskeySignupFinish {
            challenge_id: _,
            credential: _,
            friendly_name,
        } = self;
        f.debug_struct("DataPasskeySignupFinish")
            .field("challenge_id", &REDACTED)
            .field("credential", &REDACTED)
            .field("friendly_name", friendly_name)
            .finish()
    }
}

/// # Open a Passkey Recovery Link
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataPasskeyRecoverStart {
    /// The token from the recovery link
    pub token: String,
}

impl std::fmt::Debug for DataPasskeyRecoverStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let DataPasskeyRecoverStart { token: _ } = self;
        f.debug_struct("DataPasskeyRecoverStart")
            .field("token", &REDACTED)
            .finish()
    }
}

/// # Finish Passkey Recovery
///
/// Registers the new passkey; answered with `ResponseLogin`. At most one
/// of `totp_code` and `recovery_code`, and one of them is needed when the
/// start step said so
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Clone, Eq, PartialEq)]
pub struct DataPasskeyRecoverFinish {
    /// The token from the recovery link
    pub token: String,

    /// Id of the challenge the start step answered with
    pub challenge_id: String,

    /// WebAuthn credential, as returned by the platform credential API
    pub credential: serde_json::Value,

    /// Authenticator code
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub totp_code: Option<String>,

    /// MFA recovery code
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub recovery_code: Option<String>,
}

impl std::fmt::Debug for DataPasskeyRecoverFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field has to be dealt with here
        let DataPasskeyRecoverFinish {
            token: _,
            challenge_id: _,
            credential: _,
            totp_code,
            recovery_code,
        } = self;
        f.debug_struct("DataPasskeyRecoverFinish")
            .field("token", &REDACTED)
            .field("challenge_id", &REDACTED)
            .field("credential", &REDACTED)
            .field("totp_code", &redacted_option(totp_code))
            .field("recovery_code", &redacted_option(recovery_code))
            .finish()
    }
}

#[cfg(test)]
mod signup_and_recovery_tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "SECRET-MARKER";

    /// Fails if: `ticket_required` stops being additive. An answer from an
    /// older server has no such field and must read as "a ticket is needed",
    /// which is what that server enforces.
    #[test]
    fn ticket_required_defaults_to_true_and_is_always_sent() {
        let old: ResponsePasskeyRegisterStart =
            serde_json::from_value(json!({ "challenge_id": "c1", "options": {} }))
                .expect("an older answer");
        assert!(old.ticket_required);

        for ticket_required in [false, true] {
            let answer = ResponsePasskeyRegisterStart {
                challenge_id: "c1".to_string(),
                options: json!({ "publicKey": {} }),
                ticket_required,
            };
            let value = serde_json::to_value(&answer).unwrap();
            assert_eq!(value["ticket_required"], json!(ticket_required));
            assert_eq!(
                serde_json::from_value::<ResponsePasskeyRegisterStart>(value.clone()).unwrap(),
                answer
            );

            // An older app reads the same answer as plain options
            let plain: ResponsePasskeyOptions = serde_json::from_value(value).unwrap();
            assert_eq!(plain.challenge_id, "c1");
            assert_eq!(plain.options, json!({ "publicKey": {} }));
        }
    }

    /// Fails if: a sign-up start body needs more than a username, the
    /// acknowledgement stops defaulting to false, or an absent optional
    /// field is written out.
    #[test]
    fn signup_start_needs_only_a_username() {
        let start: DataPasskeySignupStart =
            serde_json::from_value(json!({ "username": "alice" })).unwrap();
        assert_eq!(
            start,
            DataPasskeySignupStart {
                username: "alice".to_string(),
                email: None,
                no_email_ack: false,
                invite: None,
                referral_code: None,
                invite_code: None,
                captcha: None,
            }
        );
        assert_eq!(
            serde_json::to_value(&start).unwrap(),
            json!({ "username": "alice", "no_email_ack": false })
        );
        assert!(serde_json::from_value::<DataPasskeySignupStart>(json!({})).is_err());

        let full: DataPasskeySignupStart = serde_json::from_value(json!({
            "username": "alice",
            "email": "alice@example.test",
            "no_email_ack": true,
            "invite": "account-invite",
            "referral_code": "REFER",
            "invite_code": "server-invite",
            "captcha": "captcha-answer"
        }))
        .unwrap();
        assert_eq!(full.email.as_deref(), Some("alice@example.test"));
        assert!(full.no_email_ack);
        assert_eq!(full.invite.as_deref(), Some("account-invite"));
        assert_eq!(full.referral_code.as_deref(), Some("REFER"));
        assert_eq!(full.invite_code.as_deref(), Some("server-invite"));
        assert_eq!(full.captcha.as_deref(), Some("captcha-answer"));
    }

    /// Fails if: a later step parses without the field that binds it to the
    /// pending sign-up, the challenge or the link.
    #[test]
    fn the_later_steps_need_their_binding_fields() {
        assert!(serde_json::from_value::<DataPasskeySignupCode>(json!({ "code": "1" })).is_err());
        assert!(
            serde_json::from_value::<DataPasskeySignupCode>(json!({ "signup_id": "s" })).is_err()
        );
        assert!(serde_json::from_value::<DataPasskeySignupOptions>(json!({})).is_err());
        assert!(
            serde_json::from_value::<DataPasskeySignupFinish>(json!({ "credential": {} })).is_err()
        );
        assert!(
            serde_json::from_value::<DataPasskeySignupFinish>(json!({ "challenge_id": "c" }))
                .is_err()
        );
        assert!(serde_json::from_value::<DataPasskeyRecoverSend>(json!({})).is_err());
        assert!(serde_json::from_value::<DataPasskeyRecoverStart>(json!({})).is_err());
        assert!(
            serde_json::from_value::<DataPasskeyRecoverFinish>(json!({ "credential": {} }))
                .is_err()
        );
        assert!(serde_json::from_value::<DataPasskeyRecoverFinish>(
            json!({ "token": "t", "credential": {} })
        )
        .is_err());
        assert!(serde_json::from_value::<DataPasskeyRecoverFinish>(
            json!({ "challenge_id": "c", "credential": {} })
        )
        .is_err());

        let finish: DataPasskeySignupFinish =
            serde_json::from_value(json!({ "challenge_id": "c", "credential": { "id": "x" } }))
                .unwrap();
        assert_eq!(finish.friendly_name, None);
        assert_eq!(finish.credential, json!({ "id": "x" }));

        let recover: DataPasskeyRecoverFinish = serde_json::from_value(
            json!({ "token": "t", "challenge_id": "c", "credential": { "id": "x" } }),
        )
        .unwrap();
        assert_eq!(recover.challenge_id, "c");
        assert_eq!(recover.totp_code, None);
        assert_eq!(recover.recovery_code, None);

        assert!(serde_json::from_value::<ResponsePasskeyRecoverStart>(
            json!({ "options": { "publicKey": {} }, "second_factor_required": true })
        )
        .is_err());
        let options: ResponsePasskeyRecoverStart = serde_json::from_value(json!({
            "challenge_id": "c",
            "options": { "publicKey": {} },
            "second_factor_required": true
        }))
        .unwrap();
        assert_eq!(options.challenge_id, "c");
        assert!(options.second_factor_required);

        let started: ResponsePasskeySignupStart =
            serde_json::from_value(json!({ "signup_id": "s", "email_code_required": true }))
                .unwrap();
        assert_eq!(
            serde_json::to_value(&started).unwrap(),
            json!({ "signup_id": "s", "email_code_required": true })
        );
    }

    /// Fails if: any of these goes back to a derived `Debug`, or its own
    /// prints a sign-up id, code, token, captcha answer, invite, email or
    /// credential. Plain and `{:#?}` alike.
    #[test]
    fn debug_prints_no_id_code_token_or_credential() {
        let secret = || SECRET.to_string();
        let credential = json!({ "id": SECRET, "response": { "signature": [SECRET] } });

        let start = DataPasskeySignupStart {
            username: "alice".to_string(),
            email: Some(secret()),
            no_email_ack: true,
            invite: Some(secret()),
            referral_code: Some("REFER".to_string()),
            invite_code: Some(secret()),
            captcha: Some(secret()),
        };
        let started = ResponsePasskeySignupStart {
            signup_id: secret(),
            email_code_required: true,
        };
        let code = DataPasskeySignupCode {
            signup_id: secret(),
            code: secret(),
        };
        let options = DataPasskeySignupOptions {
            signup_id: secret(),
        };
        let finish = DataPasskeySignupFinish {
            challenge_id: secret(),
            credential: credential.clone(),
            friendly_name: Some("Laptop".to_string()),
        };
        let recover_start = DataPasskeyRecoverStart { token: secret() };
        let recover_finish = DataPasskeyRecoverFinish {
            token: secret(),
            challenge_id: secret(),
            credential: credential.clone(),
            totp_code: Some(secret()),
            recovery_code: Some(secret()),
        };

        // The control: the marker is in every value
        for wire in [
            serde_json::to_string(&start).unwrap(),
            serde_json::to_string(&started).unwrap(),
            serde_json::to_string(&code).unwrap(),
            serde_json::to_string(&options).unwrap(),
            serde_json::to_string(&finish).unwrap(),
            serde_json::to_string(&recover_start).unwrap(),
            serde_json::to_string(&recover_finish).unwrap(),
        ] {
            assert!(wire.contains(SECRET), "{wire}");
        }

        for printed in [
            format!("{start:?}"),
            format!("{start:#?}"),
            format!("{started:?}"),
            format!("{started:#?}"),
            format!("{code:?}"),
            format!("{code:#?}"),
            format!("{options:?}"),
            format!("{options:#?}"),
            format!("{finish:?}"),
            format!("{finish:#?}"),
            format!("{recover_start:?}"),
            format!("{recover_start:#?}"),
            format!("{recover_finish:?}"),
            format!("{recover_finish:#?}"),
            format!("{:?}", Some(&code)),
            format!("{:?}", vec![recover_finish.clone()]),
        ] {
            assert!(!printed.contains(SECRET), "{printed}");
            assert!(printed.contains("<redacted>"), "{printed}");
        }

        // What is not a secret stays readable
        let printed = format!("{start:?}");
        assert!(printed.contains(r#"username: "alice""#), "{printed}");
        assert!(printed.contains(r#"referral_code: Some("REFER")"#), "{printed}");
        assert!(printed.contains("no_email_ack: true"), "{printed}");
        assert!(format!("{finish:?}").contains(r#"friendly_name: Some("Laptop")"#));

        // An absent optional secret prints as absent, not as redacted
        let bare = DataPasskeyRecoverFinish {
            totp_code: None,
            recovery_code: None,
            ..recover_finish
        };
        let printed = format!("{bare:?}");
        assert!(printed.contains("totp_code: None"), "{printed}");
        assert!(printed.contains("recovery_code: None"), "{printed}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn passkey_info_omits_an_unused_timestamp() {
        let info: PasskeyInfo = serde_json::from_value(json!({
            "id": "01PASSKEY",
            "name": "Phone",
            "created_at": "2026-11-22T00:00:00.000Z"
        }))
        .expect("a passkey that was never used");
        assert_eq!(info.id, "01PASSKEY");
        assert_eq!(info.last_used_at, None);

        let value = serde_json::to_value(&info).unwrap();
        assert_eq!(value["id"], "01PASSKEY");
        assert!(value.get("last_used_at").is_none());
    }

    #[test]
    fn finish_keeps_the_credential_verbatim_and_the_name_is_optional() {
        let credential = json!({
            "id": "abc",
            "type": "public-key",
            "response": { "clientDataJSON": "e30" }
        });

        let finish: DataPasskeyFinish = serde_json::from_value(json!({
            "challenge_id": "c1",
            "credential": credential.clone()
        }))
        .expect("a finish body without a name");
        assert_eq!(finish.challenge_id, "c1");
        assert_eq!(finish.credential, credential);
        assert_eq!(finish.name, None);
    }

    /// Text that stands for the secret parts in the `Debug` tests
    const CHALLENGE: &str = "CHALLENGE-ID-MARKER";
    const SIGNED: &str = "SIGNED-CREDENTIAL-MARKER";

    fn marked_credential() -> serde_json::Value {
        json!({
            "id": SIGNED,
            "type": "public-key",
            "response": { "clientDataJSON": SIGNED, "signature": [SIGNED] }
        })
    }

    /// Fails if: either type goes back to a derived `Debug`, or its own
    /// prints the credential or the challenge id. Plain and `{:#?}` alike.
    #[test]
    fn debug_prints_neither_the_credential_nor_the_challenge_id() {
        let finish = DataPasskeyFinish {
            challenge_id: CHALLENGE.to_string(),
            credential: marked_credential(),
            name: Some("Phone".to_string()),
        };
        let ticket = PasskeyTicketResponse {
            challenge_id: CHALLENGE.to_string(),
            credential: marked_credential(),
        };

        // The control: the markers are in the values, and a derived `Debug`
        // (the credential's own) does print them
        assert!(format!("{:?}", finish.credential).contains(SIGNED));
        assert!(serde_json::to_string(&finish).unwrap().contains(CHALLENGE));
        assert!(serde_json::to_string(&ticket).unwrap().contains(SIGNED));

        for printed in [
            format!("{:?}", finish),
            format!("{:#?}", finish),
            format!("{:?}", ticket),
            format!("{:#?}", ticket),
            format!("{:?}", Some(&ticket)),
            format!("{:?}", vec![finish.clone()]),
        ] {
            assert!(!printed.contains(SIGNED), "{printed}");
            assert!(!printed.contains(CHALLENGE), "{printed}");
            assert!(!printed.contains("public-key"), "{printed}");
            assert!(printed.contains(r#"credential: "<redacted>""#), "{printed}");
            assert!(printed.contains(r#"challenge_id: "<redacted>""#), "{printed}");
        }

        // The name is not a secret and stays readable
        assert!(format!("{:?}", finish).contains(r#"name: Some("Phone")"#));
    }

    /// The hand-written derives leave the wire form as it was
    #[test]
    fn the_wire_form_is_unchanged() {
        let finish = DataPasskeyFinish {
            challenge_id: "c1".to_string(),
            credential: json!({ "id": "abc" }),
            name: None,
        };
        assert_eq!(
            serde_json::to_value(&finish).unwrap(),
            json!({ "challenge_id": "c1", "credential": { "id": "abc" } }),
            "an absent name is left out"
        );

        let named = DataPasskeyFinish {
            name: Some("Phone".to_string()),
            ..finish.clone()
        };
        let value = serde_json::to_value(&named).unwrap();
        assert_eq!(value["name"], "Phone");
        assert_eq!(
            serde_json::from_value::<DataPasskeyFinish>(value).unwrap(),
            named
        );

        let ticket = PasskeyTicketResponse {
            challenge_id: "c1".to_string(),
            credential: json!({ "id": "abc" }),
        };
        let value = serde_json::to_value(&ticket).unwrap();
        assert_eq!(
            value,
            json!({ "challenge_id": "c1", "credential": { "id": "abc" } })
        );
        assert_eq!(
            serde_json::from_value::<PasskeyTicketResponse>(value).unwrap(),
            ticket
        );
    }

    #[test]
    fn a_ticket_response_needs_both_fields() {
        assert!(
            serde_json::from_value::<PasskeyTicketResponse>(json!({ "challenge_id": "c1" }))
                .is_err(),
            "a missing credential must not parse"
        );
        assert!(
            serde_json::from_value::<PasskeyTicketResponse>(json!({ "credential": {} })).is_err(),
            "a missing challenge id must not parse"
        );
    }
}
