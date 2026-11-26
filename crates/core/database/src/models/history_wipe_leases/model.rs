auto_derived!(
    /// The `history_wipes` job's per-channel lease (design 7.5 "S4"). The
    /// replica holding an unexpired lease runs that channel's wipe; an
    /// expired or released one lets another replica resume it. The row
    /// carries the running count of deleted rows, kept across a release so
    /// a wipe stopped by a legal hold resumes its count.
    pub struct HistoryWipeLease {
        /// The channel id
        #[serde(rename = "_id")]
        pub id: String,
        /// The job run holding the lease
        pub holder: String,
        /// When the lease lapses, unix ms; `0` once released
        pub expires_at: i64,
        /// Rows deleted over every run. A lower bound: the job deletes a
        /// batch before it advances the lease, so a crash between the two
        /// loses that batch's count.
        pub count: i64,
    }
);
