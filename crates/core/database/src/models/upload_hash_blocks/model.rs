use iso8601_timestamp::Timestamp;

auto_derived!(
    /// An upload hash Sloga refuses after a Take It Down removal
    pub struct UploadHashBlock {
        /// `upload_hash_block_key(kind, hash)`
        #[serde(rename = "_id")]
        pub id: String,
        /// The request whose removal added the block
        pub request_id: String,
        pub created_at: Timestamp,
        /// Other requests whose removal blocked the same key later. The block
        /// stays until every request holding it lets go (a restore), so one
        /// request's restore never lifts another request's block.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub also_request_ids: Vec<String>,
    }
);

/// Block key for a hash: `kind` is `"orig"` (original bytes), `"proc"`
/// (post-processing) or `"chunk"` (chunked-upload composite). Pass the hash
/// exactly as stored on the file row; it is not normalized.
pub fn upload_hash_block_key(kind: &str, hash: &str) -> String {
    format!("{kind}:{hash}")
}

#[cfg(test)]
mod tests {
    use super::upload_hash_block_key;

    #[test]
    fn key_is_kind_colon_hash() {
        assert_eq!(upload_hash_block_key("orig", "ab12"), "orig:ab12");
        assert_eq!(upload_hash_block_key("proc", "ab12"), "proc:ab12");
        assert_eq!(upload_hash_block_key("chunk", "ab12"), "chunk:ab12");
    }
}
