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
);

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
