use iso8601_timestamp::Timestamp;

auto_derived!(
    /// A legal hold on a server (design 2.9; the stub until S9). A hold is
    /// set while a row exists; it blocks every history wipe of the server's
    /// protected channels. Admin-only: no client route writes it.
    pub struct ServerLegalHold {
        /// The server id
        #[serde(rename = "_id")]
        pub id: String,
        /// When the hold was set
        pub set_at: Timestamp,
        /// The privileged user who set it
        pub set_by: String,
        /// Free text for the operator, never shown to users
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }
);

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::ServerLegalHold;

    /// A row with no note decodes, and a hold without one serializes with no
    /// `note` key at all (the stored row stays `_id`, `set_at`, `set_by`).
    #[test]
    fn a_hold_without_a_note_omits_the_key() {
        let hold: ServerLegalHold = serde_json::from_value(json!({
            "_id": "01SERVER00000000000000000000",
            "set_at": "2026-09-01T00:00:00.000Z",
            "set_by": "01ADMIN000000000000000000000",
        }))
        .expect("a row without `note` decodes");
        assert_eq!(hold.id, "01SERVER00000000000000000000");
        assert_eq!(hold.note, None);

        let value = serde_json::to_value(&hold).expect("encode");
        let keys: Vec<&String> = value.as_object().expect("an object").keys().collect();
        assert_eq!(keys, ["_id", "set_at", "set_by"]);
        assert_eq!(
            serde_json::from_value::<ServerLegalHold>(value).expect("re-decode"),
            hold
        );

        let noted = ServerLegalHold {
            note: Some("case 7".to_string()),
            ..hold
        };
        let value = serde_json::to_value(&noted).expect("encode");
        assert_eq!(value["note"], "case 7");
    }
}
