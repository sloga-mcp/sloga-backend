#[cfg(feature = "validator")]
use validator::Validate;

auto_derived!(
    /// One drawn stroke on a screen-sharer's surface (tech-support-mode plan
    /// §2). A stroke is a PICTURE, never an input event: it carries no
    /// injection authority and must never share a code path with the
    /// remote-control seal/inject surface (plan §0.3).
    ///
    /// Coordinates are normalized to the shared surface's content box as
    /// FIXED-POINT integers (0..=10000 on both axes — divide by 10000 for
    /// the unit square), flattened as x,y pairs. Integers rather than
    /// floats deliberately: exact equality, no NaN/infinity to police, and
    /// a smaller wire form. Color is an INDEX into the client's fixed
    /// branded palette — raw colors never cross the wire, so a hostile
    /// client cannot smuggle OS-chrome grays past the palette (plan §2.4);
    /// the same for width, a class index rather than pixels.
    pub struct AnnotationStroke {
        /// Flattened x,y pairs, each 0..=10000 (fixed-point over the unit
        /// square). At most 64 points (128 values); the route validates
        /// length, parity and range.
        pub points: Vec<u16>,
        /// Palette index (route-validated `< ANNOTATION_PALETTE_SIZE`).
        pub color: u8,
        /// Width class index (route-validated `< ANNOTATION_WIDTH_CLASSES`).
        pub width: u8,
    }

    /// Draw on a screen-sharing participant's shared surface.
    ///
    /// Carries only the ADDRESSEE and the ink. The annotator's identity is
    /// stamped server-side from the authenticated user (the captions-route
    /// rule) — receiving clients attribute strokes and the "is drawing"
    /// banner by it, so a caller-supplied one would let anyone draw in
    /// someone else's name. Whether the caller may draw at all is enforced
    /// server-side against the target's consent allowlist; a client-side
    /// toggle alone would be no gate (plan §2.2).
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataSendAnnotation {
        /// User id of the sharer whose surface is being drawn on. Must be a
        /// live participant of this call publishing screen video, and must
        /// have allowlisted the caller.
        pub target: String,
        /// Strokes accumulated since the client's last coalescing tick
        /// (≤10 Hz batching is the client-side contract; the `annotations`
        /// ratelimit bucket bounds a hostile client).
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 8)))]
        pub strokes: Vec<AnnotationStroke>,
        /// Monotonic per-annotator sequence number so receivers can drop
        /// late-arriving batches after a clear.
        pub seq: u32,
    }

    /// Allow one named participant to draw on the caller's shared screen.
    pub struct DataAnnotationAllow {
        /// User id being granted draw permission. Scoped to a NAMED
        /// participant, never "anyone in the call" (plan §2.4).
        pub user: String,
    }

    /// Draw-consent state for one active sharer in a voice channel.
    pub struct AnnotationConsentEntry {
        /// The sharer this allowlist belongs to.
        pub sharer_id: String,
        /// User ids the sharer currently allows to draw.
        pub allowed: Vec<String>,
    }

    /// Response to fetching a channel's draw-consent state — one entry per
    /// sharer with a non-empty allowlist. Exists so a LATE JOINER can learn
    /// standing consent from a roster read instead of a missed event (the
    /// pass-the-controller slice-0 backfill lesson).
    pub struct AnnotationConsentResponse {
        pub sharers: Vec<AnnotationConsentEntry>,
    }
);
