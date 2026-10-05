use iso8601_timestamp::Timestamp;

use crate::File;

auto_derived_partial!(
    /// File hash
    pub struct FileHash {
        /// Sha256 hash of the file
        #[serde(rename = "_id")]
        pub id: String,
        /// Sha256 hash of file after it has been processed
        pub processed_hash: String,

        /// When this file was created in system
        pub created_at: Timestamp,

        /// The bucket this file is stored in
        pub bucket_id: String,
        /// The path at which this file exists in
        pub path: String,
        /// Cryptographic nonce used to encrypt this file
        pub iv: String,
        /// On-S3 storage format version.
        ///
        /// ABSENT (`None`) = legacy whole-file AES-256-GCM in one shot (or
        /// plaintext passthrough when `iv` is empty) — every row written
        /// before chunked uploads, and every small single-POST upload since.
        /// The legacy read path must stay for as long as such rows exist.
        ///
        /// `Some(2)` = segmented STREAM-AEAD: 1 MiB AES-256-GCM segments
        /// under the nonce schedule `prefix(7) ‖ BE32(i) ‖ last_flag`, with
        /// `iv` holding the base64 7-byte prefix and `size` the PLAINTEXT
        /// size. Never renumber; add new versions additively.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub format_version: Option<u32>,
        /// Id of the server file key this object is encrypted under.
        ///
        /// ABSENT (`None`) = the "legacy" key: every row written before file
        /// key rotation. The field never holds the literal "legacy".
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub key_id: Option<String>,

        /// Parsed metadata of this file
        pub metadata: Metadata,
        /// Raw content type of this file
        pub content_type: String,
        /// Size of this file (in bytes)
        pub size: isize,
    },
    "PartialFileHash"
);

auto_derived!(
    /// Metadata associated with a file
    #[serde(tag = "type")]
    #[derive(Default)]
    pub enum Metadata {
        /// File is just a generic uncategorised file
        #[default]
        File,
        /// File contains textual data and should be displayed as such
        Text,
        /// File is an image with specific dimensions
        Image {
            width: isize,
            height: isize,
            thumbhash: Option<Vec<u8>>,
            animated: Option<bool>,
        },
        /// File is a video with specific dimensions
        Video { width: isize, height: isize },
        /// File is audio
        Audio,
    }
);

impl FileHash {
    /// Fresh unique object key for a (re-)written blob: `rk/<key_id|legacy>/<ulid>`
    ///
    /// Every writer takes its object key from here, so an object key is never
    /// reused; `hash.id` is never used as an object key.
    pub fn new_object_path(key_id: Option<&str>) -> String {
        format!("rk/{}/{}", key_id.unwrap_or("legacy"), ulid::Ulid::new())
    }

    /// Create a file from a file hash
    pub fn into_file(
        &self,
        id: String,
        tag: String,
        filename: String,
        uploader_id: String,
    ) -> File {
        File {
            id,
            tag,
            filename,
            hash: Some(self.id.clone()),

            uploaded_at: Some(Timestamp::now_utc()),
            uploader_id: Some(uploader_id),

            used_for: None,

            deleted: None,
            reported: None,

            // TODO: remove this data
            metadata: self.metadata.clone(),
            content_type: self.content_type.clone(),
            size: self.size,

            // TODO: superseded by "used_for"
            message_id: None,
            object_id: None,
            server_id: None,
            user_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FileHash;

    #[test]
    fn new_object_path_is_namespaced_by_key_and_unique() {
        let legacy = FileHash::new_object_path(None);
        assert!(legacy.starts_with("rk/legacy/"), "{legacy}");

        let rotated = FileHash::new_object_path(Some("k1"));
        assert!(rotated.starts_with("rk/k1/"), "{rotated}");

        assert_ne!(
            FileHash::new_object_path(Some("k1")),
            FileHash::new_object_path(Some("k1"))
        );
    }
}
