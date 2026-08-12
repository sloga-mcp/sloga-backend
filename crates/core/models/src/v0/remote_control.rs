auto_derived!(
    /// Offer remote control of one's own machine to a named call participant
    /// (remote-control plan §1; sharer-initiated "Give control").
    ///
    /// Both byte fields are OPAQUE to the server (slice-1 scope boundary):
    /// the ephemeral public key and session id are transported verbatim for
    /// the slice-3 key agreement, never interpreted. They are REQUIRED and
    /// length-checked server-side — a missing or wrong-length key is a hard
    /// reject, never an `Option` "for compat" (the typed stoat-api client
    /// sends `{}` for unknown routes and would silently drop them).
    pub struct DataRemoteControlOffer {
        /// User id of the participant being offered control (the would-be
        /// controller). Must be a live participant of this call; never the
        /// caller themselves.
        pub target: String,
        /// The sharer's ephemeral X25519 public key: base64 (standard, no
        /// padding), exactly 32 bytes decoded. Opaque bytes in slice 1.
        pub sharer_ephemeral_pub: String,
        /// Control-session id minted by the sharer's native layer: base64
        /// (standard, no padding), exactly 32 bytes decoded. Opaque bytes.
        pub rc_session_id: String,
    }

    /// Response to a control offer (target only, offer-addressed)
    pub struct DataRemoteControlRespond {
        /// Whether the offer is accepted
        pub accept: bool,
        /// The controller's ephemeral X25519 public key: base64 (standard,
        /// no padding), exactly 32 bytes decoded. REQUIRED when accepting
        /// (hard reject otherwise); ignored on decline.
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub controller_ephemeral_pub: Option<String>,
    }

    /// A created control offer
    pub struct RemoteControlOfferResponse {
        /// Offer id — the respond route is addressed by this (a target may
        /// hold offers from several sharers at once)
        pub offer_id: String,
    }

    /// Outcome of responding to a control offer
    pub struct RemoteControlRespondResponse {
        /// Grant id when the offer was accepted (the release route is
        /// addressed by this); absent on decline
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub grant_id: Option<String>,
    }

    /// Ask a streaming participant for a control turn (pass-the-controller
    /// plan §2.4 "ask for a turn").
    ///
    /// Carries ONLY the addressee. The requester's identity is stamped
    /// server-side from the authenticated user — a request body is never an
    /// identity source, or anyone could put words (or raised hands) in
    /// someone else's name. The relayed event is a suggestion the sharer's
    /// client shows; it grants nothing and joins no queue by itself.
    pub struct DataControlRequest {
        /// User id of the participant being asked (the sharer). Must be a
        /// live participant of this call publishing screen video; never the
        /// caller themselves.
        pub sharer: String,
    }
);
