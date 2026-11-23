use iso8601_timestamp::Timestamp;

/// A WebAuthn passkey registered to an account (collection `passkeys`).
///
/// Credentials live in their own collection, never on the account document.
/// `credential` is opaque to this crate: the route layer serializes whatever
/// its WebAuthn verifier needs and reads it back, so the database crate
/// carries no WebAuthn dependency.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Passkey {
    /// Unique id (ULID)
    #[serde(rename = "_id")]
    pub id: String,
    /// Owning account / user id
    pub user_id: String,
    /// WebAuthn credential id, base64url. Unique across all accounts; a
    /// discoverable login resolves the account from it.
    pub credential_id: String,
    /// The account's WebAuthn user handle: a random UUID string, the same on
    /// every passkey of one account, and NEVER the public user id. Never
    /// printed by `Debug`.
    pub user_handle: String,
    /// Serialized verifier state (JSON text), which includes the signature
    /// counter. Never printed by `Debug`.
    pub credential: String,
    /// Name the user gave this passkey
    pub name: String,
    /// When the passkey was registered
    pub created_at: Timestamp,
    /// When the passkey last passed an assertion
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_used_at: Option<Timestamp>,
}

impl std::fmt::Debug for Passkey {
    /// Ids, name and dates only; the user handle and the stored credential
    /// are redacted
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured in full, so a new field has to be placed here on purpose
        let Passkey {
            id,
            user_id,
            credential_id,
            user_handle: _,
            credential: _,
            name,
            created_at,
            last_used_at,
        } = self;

        f.debug_struct("Passkey")
            .field("id", id)
            .field("user_id", user_id)
            .field("credential_id", credential_id)
            .field("user_handle", &"<redacted>")
            .field("credential", &"<redacted>")
            .field("name", name)
            .field("created_at", created_at)
            .field("last_used_at", last_used_at)
            .finish()
    }
}

impl Passkey {
    /// A new passkey with a fresh id, registered now and never used
    pub fn new(
        user_id: String,
        credential_id: String,
        user_handle: String,
        credential: String,
        name: String,
    ) -> Passkey {
        Passkey {
            id: ulid::Ulid::new().to_string(),
            user_id,
            credential_id,
            user_handle,
            credential,
            name,
            created_at: Timestamp::now_utc(),
            last_used_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;

    use super::Passkey;

    fn passkey() -> Passkey {
        Passkey {
            id: "01PASSKEY00000000000000001".to_string(),
            user_id: "01USER00000000000000000001".to_string(),
            credential_id: "credential-id-b64url".to_string(),
            user_handle: "4f0e1c1e-7d0c-4a55-9d0b-0d6f1f3f2a10".to_string(),
            credential: "{\"counter\":7,\"key\":\"VERIFIER-STATE-MARKER\"}".to_string(),
            name: "Phone".to_string(),
            created_at: Timestamp::UNIX_EPOCH,
            last_used_at: None,
        }
    }

    #[test]
    fn debug_redacts_the_stored_credential() {
        let passkey = passkey();
        let printed = format!("{passkey:?}");
        let pretty = format!("{passkey:#?}");

        for text in [&printed, &pretty] {
            assert!(!text.contains("VERIFIER-STATE-MARKER"), "{text}");
            assert!(!text.contains("counter"), "{text}");
            assert!(!text.contains("4f0e1c1e"), "the user handle: {text}");
            assert_eq!(text.matches("<redacted>").count(), 2, "{text}");
            // The control: the rest of the row is still printed
            assert!(text.contains("01PASSKEY00000000000000001"), "{text}");
            assert!(text.contains("credential-id-b64url"), "{text}");
        }
    }

    #[test]
    fn last_used_at_is_skipped_until_first_use() {
        let mut passkey = passkey();
        let stored = serde_json::to_value(&passkey).unwrap();
        assert!(stored.get("last_used_at").is_none(), "{stored}");
        assert_eq!(
            stored.get("_id").and_then(|id| id.as_str()),
            Some("01PASSKEY00000000000000001")
        );

        // A row written before first use reads back as never used
        let read: Passkey = serde_json::from_value(stored).unwrap();
        assert_eq!(read, passkey);

        passkey.last_used_at = Some(Timestamp::UNIX_EPOCH);
        let stored = serde_json::to_value(&passkey).unwrap();
        assert!(stored.get("last_used_at").is_some(), "{stored}");
    }

    #[test]
    fn new_starts_unused_with_a_ulid() {
        let passkey = Passkey::new(
            "user".to_string(),
            "credential-id".to_string(),
            "handle".to_string(),
            "{}".to_string(),
            "Laptop".to_string(),
        );

        assert!(ulid::Ulid::from_string(&passkey.id).is_ok());
        assert_eq!(passkey.user_id, "user");
        assert_eq!(passkey.credential_id, "credential-id");
        assert_eq!(passkey.user_handle, "handle");
        assert_eq!(passkey.credential, "{}");
        assert_eq!(passkey.name, "Laptop");
        assert_eq!(passkey.last_used_at, None);
    }
}
