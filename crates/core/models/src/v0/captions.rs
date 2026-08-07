#[cfg(feature = "validator")]
use validator::Validate;

auto_derived!(
    /// One finalized caption line spoken in a voice call.
    ///
    /// The server relays this to the call's current participants and stores
    /// nothing — captions are transient by construction. Only FINALIZED
    /// utterances travel this route: interim recognizer results stay on the
    /// speaker's own screen, which bounds the request rate to utterance
    /// boundaries (~1/s worst case) instead of keystroke-rate updates.
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataSendCaption {
        /// Recognized transcript in the speaker's own language.
        ///
        /// The `max` here is an abuse bound, not the display cap: the route
        /// additionally clamps to the 240 characters the client renders, so a
        /// slightly-over-length utterance is truncated rather than dropped.
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 2000)))]
        pub text: String,
        /// BCP-47 language the speaker was recognized in (e.g. `en-US`), which
        /// the receiver uses to translate into their own caption language.
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 32)))]
        pub lang: String,
    }
);
