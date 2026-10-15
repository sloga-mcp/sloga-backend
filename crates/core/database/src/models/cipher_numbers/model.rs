auto_derived!(
    /// One sellable Cipher number. The table is pre-seeded with `1..=cap`,
    /// and a row is claimed by setting `order_id`.
    pub struct CipherNumber {
        /// The number itself.
        ///
        /// bson 2.x serializes a `u32` as Int64, so the stored `_id` is an
        /// Int64 and every hand-built filter or seed document uses `i64`.
        #[serde(rename = "_id")]
        pub number: u32,
        /// Order that claimed this number. Never cleared, so a number whose
        /// membership was revoked stays retired and still counts as claimed.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub order_id: Option<String>,
    }
);
