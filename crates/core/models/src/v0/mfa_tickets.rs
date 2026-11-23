use crate::v0::PasskeyTicketResponse;

auto_derived!(
    pub struct MFATicket {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,

        /// Account Id
        pub account_id: String,

        /// Unique Token
        pub token: String,

        /// Whether this ticket has been validated
        /// (can be used for account actions)
        pub validated: bool,

        /// Whether this ticket is authorised
        /// (can be used to log a user in)
        pub authorised: bool,

        /// TOTP code at time of ticket creation
        pub last_totp_code: Option<String>,
    }

    #[serde(untagged)]
    pub enum ResponseVerify {
        NoTicket,
        WithTicket {
            /// Authorised MFA ticket, can be used to log in
            ticket: MFATicket,
        },
    }

    /// MFA response
    ///
    /// Untagged: serde takes the FIRST variant whose required field is
    /// present and ignores every other key, so the order here is part of the
    /// wire contract. Each variant has one required field no other variant
    /// has; `Passkey` stays last so a body an old app can send parses exactly
    /// as it did before.
    #[serde(untagged)]
    pub enum MFAResponse {
        Password { password: String },
        Recovery { recovery_code: String },
        Totp { totp_code: String },
        Passkey { passkey_response: PasskeyTicketResponse },
    }

    #[derive(Default)]
    pub struct MultiFactorStatus {
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub email_otp: bool,
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub trusted_handover: bool,
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub email_mfa: bool,
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub totp_mfa: bool,
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub security_key_mfa: bool,
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub recovery_active: bool,
        /// The account has no usable password (created through OAuth or a
        /// passkey and never given one)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub password_absent: bool,
    }

    pub enum MFAMethod {
        Password,
        Recovery,
        Totp,
        // Never offered in `ResponseLogin::MFA.allowed_methods`
        Passkey,
    }

    /// # Totp Secret
    pub struct ResponseTotpSecret {
        pub secret: String,
    }
);
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(body: serde_json::Value) -> MFAResponse {
        serde_json::from_value(body).expect("a valid MFA response")
    }

    fn passkey_body() -> serde_json::Value {
        json!({
            "challenge_id": "01CHALLENGE",
            "credential": { "id": "abc", "type": "public-key" }
        })
    }

    /// The three bodies old apps send keep their own variant
    #[test]
    fn existing_bodies_keep_their_variant() {
        assert_eq!(
            parse(json!({ "password": "hunter2" })),
            MFAResponse::Password {
                password: "hunter2".to_string()
            }
        );
        assert_eq!(
            parse(json!({ "totp_code": "123456" })),
            MFAResponse::Totp {
                totp_code: "123456".to_string()
            }
        );
        assert_eq!(
            parse(json!({ "recovery_code": "abcde-fghjk" })),
            MFAResponse::Recovery {
                recovery_code: "abcde-fghjk".to_string()
            }
        );
    }

    #[test]
    fn a_passkey_body_parses_to_passkey() {
        assert_eq!(
            parse(json!({ "passkey_response": passkey_body() })),
            MFAResponse::Passkey {
                passkey_response: PasskeyTicketResponse {
                    challenge_id: "01CHALLENGE".to_string(),
                    credential: json!({ "id": "abc", "type": "public-key" }),
                }
            }
        );
    }

    /// Every variant survives a round trip under its own key
    #[test]
    fn every_variant_round_trips() {
        for body in [
            json!({ "password": "hunter2" }),
            json!({ "totp_code": "123456" }),
            json!({ "recovery_code": "abcde-fghjk" }),
            json!({ "passkey_response": passkey_body() }),
        ] {
            let parsed = parse(body.clone());
            assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
        }
    }

    /// A passkey response nested under a key is never mistaken for one of
    /// the string factors, and a malformed one matches nothing
    #[test]
    fn a_malformed_passkey_body_matches_no_variant() {
        for body in [
            json!({ "passkey_response": "not-an-object" }),
            json!({ "passkey_response": { "challenge_id": "01CHALLENGE" } }),
            json!({ "passkey_response": { "credential": {} } }),
            json!({ "passkey_response": { "challenge_id": 7, "credential": {} } }),
            json!({ "challenge_id": "01CHALLENGE", "credential": {} }),
            json!({}),
        ] {
            assert!(
                serde_json::from_value::<MFAResponse>(body.clone()).is_err(),
                "{body} must not parse"
            );
        }
    }

    /// Pins the order: a body carrying an old factor AND a passkey response
    /// resolves to the old factor, as it would on a server that predates
    /// passkeys. Moving `Passkey` up changes this and fails here.
    #[test]
    fn an_old_factor_wins_over_a_passkey_in_the_same_body() {
        let with_passkey = |mut body: serde_json::Value| {
            body["passkey_response"] = passkey_body();
            parse(body)
        };

        assert!(matches!(
            with_passkey(json!({ "password": "hunter2" })),
            MFAResponse::Password { .. }
        ));
        assert!(matches!(
            with_passkey(json!({ "totp_code": "123456" })),
            MFAResponse::Totp { .. }
        ));
        assert!(matches!(
            with_passkey(json!({ "recovery_code": "abcde-fghjk" })),
            MFAResponse::Recovery { .. }
        ));
    }

    /// A string factor of the wrong type falls through to a valid passkey
    /// response instead of failing the whole body
    #[test]
    fn a_wrongly_typed_old_factor_does_not_shadow_a_passkey() {
        assert!(matches!(
            parse(json!({ "password": 7, "passkey_response": passkey_body() })),
            MFAResponse::Passkey { .. }
        ));
    }

    #[test]
    fn methods_keep_their_wire_names() {
        assert_eq!(
            serde_json::to_value([
                MFAMethod::Password,
                MFAMethod::Recovery,
                MFAMethod::Totp,
                MFAMethod::Passkey,
            ])
            .unwrap(),
            json!(["Password", "Recovery", "Totp", "Passkey"])
        );
    }

    /// `MFAResponse` derives `Debug`, so its passkey variant prints what
    /// `PasskeyTicketResponse` prints: neither the credential nor the
    /// challenge id.
    ///
    /// Fails if: `PasskeyTicketResponse` goes back to a derived `Debug`,
    /// or the variant holds the credential in a field of its own.
    #[test]
    fn debug_of_a_passkey_response_is_redacted() {
        let response = parse(json!({
            "passkey_response": {
                "challenge_id": "CHALLENGE-ID-MARKER",
                "credential": {
                    "id": "SIGNED-CREDENTIAL-MARKER",
                    "type": "public-key",
                    "response": { "signature": "SIGNED-CREDENTIAL-MARKER" }
                }
            }
        }));

        // The control: the markers are in the value
        let wire = serde_json::to_string(&response).unwrap();
        assert!(wire.contains("CHALLENGE-ID-MARKER"));
        assert!(wire.contains("SIGNED-CREDENTIAL-MARKER"));

        for printed in [format!("{:?}", response), format!("{:#?}", response)] {
            assert!(printed.contains("Passkey"), "{printed}");
            assert!(printed.contains(r#"credential: "<redacted>""#), "{printed}");
            assert!(!printed.contains("SIGNED-CREDENTIAL-MARKER"), "{printed}");
            assert!(!printed.contains("CHALLENGE-ID-MARKER"), "{printed}");
            assert!(!printed.contains("public-key"), "{printed}");
        }
    }

    /// Additive: a status from an older server parses, and false is left out
    #[test]
    fn password_absent_is_additive() {
        let old: MultiFactorStatus =
            serde_json::from_value(json!({ "totp_mfa": true })).expect("an older status");
        assert!(old.totp_mfa);
        assert!(!old.password_absent);
        assert!(serde_json::to_value(&old)
            .unwrap()
            .get("password_absent")
            .is_none());

        let absent = MultiFactorStatus {
            password_absent: true,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&absent).unwrap(),
            json!({ "password_absent": true })
        );
    }
}
