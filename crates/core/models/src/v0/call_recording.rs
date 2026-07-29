auto_derived!(
    /// Outcome of a call-recording claim (call-recording plan §1).
    ///
    /// Both routes are idempotent, so this reports the resulting STATE rather
    /// than whether anything changed — a client that retries gets the same
    /// answer and needs no special case.
    ///
    /// This is the caller's own self-reported flag. It says the indicator is
    /// now lit (or cleared) for everyone in the call; it does not attest that
    /// any capture is or is not running, which the server cannot know.
    pub struct CallRecordingResponse {
        /// Whether this user is now flagged as recording the call
        pub recording: bool,
    }
);
