use std::fmt::Display;
use std::panic::Location;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(feature = "schemas")]
#[macro_use]
extern crate schemars;

#[cfg(feature = "utoipa")]
#[macro_use]
extern crate utoipa;

#[cfg(feature = "rocket")]
pub mod rocket;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "okapi")]
pub mod okapi;

/// Result type with custom Error
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error information
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Debug, Clone)]
pub struct Error {
    /// Type of error and additional information
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub error_type: ErrorType,

    /// Where this error occurred
    pub location: String,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} occurred in {}", self.error_type, self.location)
    }
}

impl std::error::Error for Error {}

/// Possible error types
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type"))]
#[cfg_attr(feature = "schemas", derive(JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[derive(Debug, Clone)]
pub enum ErrorType {
    /// This error was not labeled :(
    LabelMe,

    // ? Onboarding related errors
    AlreadyOnboarded,

    // ? User related errors
    UsernameTaken,
    InvalidUsername,
    /// A display name or server nickname contains something we don't allow
    /// people to be called on the platform
    DisallowedName,
    DiscriminatorChangeRatelimited,
    UnknownUser,
    AlreadyFriends,
    AlreadySentRequest,
    Blocked,
    BlockedByOther,
    NotFriends,
    /// The user limits their profile to friends only
    ProfileIsPrivate,
    TooManyPendingFriendRequests {
        max: usize,
    },

    // ? Channel related errors
    UnknownChannel,
    UnknownAttachment,
    UnknownMessage,
    CannotDeleteMessage,
    CannotEditMessage,
    CannotJoinCall,
    TooManyAttachments {
        max: usize,
    },
    TooManyEmbeds {
        max: usize,
    },
    TooManyReplies {
        max: usize,
    },
    TooManyChannels {
        max: usize,
    },
    EmptyMessage,
    PayloadTooLarge,
    CannotRemoveYourself,
    GroupTooLarge {
        max: usize,
    },
    AlreadyInGroup,
    NotInGroup,
    ThreadAlreadyExists,
    AlreadyPinned,
    NotPinned,
    InSlowmode {
        retry_after: u64,
    },

    // ? Server related errors
    CantCreateServers,
    UnknownServer,
    InvalidRole,
    Banned,
    TooManyServers {
        max: usize,
    },
    /// A server import is already queued or running for this user
    ImportAlreadyInProgress,
    TooManyEmoji {
        max: usize,
    },
    TooManyStickers {
        max: usize,
    },
    TooManySounds {
        max: usize,
    },
    TooManyRoles {
        max: usize,
    },
    AlreadyInServer,
    CannotTimeoutYourself,

    // ? Server boost errors
    /// The caller does not have enough unallocated boost slots
    NotEnoughBoosts {
        available: usize,
    },
    /// The caller is at the per-user-per-server boost cap
    TooManyBoosts {
        max: usize,
    },

    // ? Bot related errors
    ReachedMaximumBots,
    IsBot,
    IsNotBot,
    BotIsPrivate,
    TooManyCommands {
        max: usize,
    },
    BotOffline,
    InteractionExpired,
    InteractionAlreadyResponded,

    // ? Poll errors
    PollClosed,

    // ? Soft-reserve errors
    /// Raid id not present in the static loot catalog
    UnknownRaid,
    /// Edition id not present in the static loot catalog
    UnknownEdition,
    /// A sheet's raids must all belong to its declared edition
    SoftResMixedEditions,
    /// More raids on one sheet than allowed
    TooManySoftResRaids {
        max: usize,
    },
    /// The sheet is locked — reserves can no longer change
    SoftResLocked,
    /// One or more item ids are not reservable on this sheet (not in the
    /// sheet's raids, hard-reserved, or duplicated when not allowed)
    SoftResInvalidItems,
    /// The sheet restricts reserves to classes that can use the item
    SoftResClassRestricted,
    /// The per-item reserve cap has been reached for an item
    SoftResItemCapReached,
    /// Recurring events cannot be linked to a sheet (v1)
    SoftResRecurringEvent,
    /// The event already has a linked sheet (one sheet per event)
    SoftResEventAlreadyLinked,

    // ? Scheduled message errors
    TooManyScheduledMessages {
        max: usize,
    },

    // ? Announcement channel / follow errors
    /// The source channel is not an announcement channel (cannot be
    /// followed or published from).
    NotAnAnnouncementChannel,
    /// This message has already been published (or is itself a delivered
    /// crosspost copy) — it cannot be crossposted again.
    AlreadyCrossposted,
    /// The source announcement channel is at its follower ceiling.
    TooManyFollowers {
        max: usize,
    },
    /// The source announcement channel has hit its hourly publish cap.
    TooManyCrossposts {
        max: usize,
    },

    // ? User safety related errors
    CannotReportYourself,

    // ? Permission errors
    MissingPermission {
        permission: String,
    },
    MissingUserPermission {
        permission: String,
    },
    NotElevated,
    NotPrivileged,
    CannotGiveMissingPermissions,
    NotOwner,
    IsElevated,

    // ? General errors
    DatabaseError {
        operation: String,
        collection: String,
    },
    InternalError,
    InvalidOperation,
    InvalidCredentials,
    InvalidProperty,
    InvalidSession,
    InvalidFlagValue,
    NotAuthenticated,
    DuplicateNonce,
    NotFound,
    NoEffect,
    FailedValidation {
        error: String,
    },
    OperationFailed,
    IncorrectData {
        with: String,
    },

    // ? Voice errors
    LiveKitUnavailable,
    NotAVoiceChannel,
    NotInVoiceChannel,
    AlreadyConnected,
    NotConnected,
    UnknownNode,
    // ? Remote control errors
    /// The sharer already has a pending control offer in this channel — a
    /// second offer must not silently overwrite the first while the target's
    /// dialog is open (remote-control plan §1)
    RemoteControlOfferPending,
    /// A party already holds an active control grant (at most one grant per
    /// sharer per channel, and at most one per controller across channels)
    RemoteControlGrantActive,
    // ? Micro-service errors
    ProxyError,
    FileTooSmall,
    FileTooLarge {
        max: usize,
    },
    FileTypeNotAllowed,
    // ? Chunked upload errors
    /// Another request holds this part / the session state forbids this
    /// operation right now (retry after a status GET)
    UploadSessionConflict,
    ///  called before every part was recorded
    UploadIncomplete,
    /// Per-user cap on concurrently open upload sessions
    TooManyUploadSessions {
        max: usize,
    },
    ImageProcessingFailed,
    NoEmbedData,

    // ? Legacy errors
    VosoUnavailable,

    // ? Feature flag disabled in the config
    FeatureDisabled {
        feature: String,
    },

    // ? Authentication
    RenderFail,
    MissingHeaders,
    CaptchaFailed,
    BlockedByShield,
    UnverifiedAccount,
    EmailFailed,
    InvalidToken,
    MissingInvite,
    InvalidInvite,

    CompromisedPassword,
    ShortPassword,
    Blacklisted,
    LockedOut,

    TotpAlreadyEnabled,
    DisallowedMFAMethod,

    // ? Media E2EE (MLS) errors
    /// The call's MLS group is at the roster ceiling — a NEW member cannot
    /// join encrypted (the call stays E2EE; plan A3). Rejoins of existing
    /// members are exempt.
    MlsCallFull {
        max: usize,
    },

    /// A video call is at the video-participant ceiling
    /// (`MAX_VIDEO_PARTICIPANTS`) — a NEW member cannot join a video-active
    /// call, or a member cannot enable video, once the cap is reached. Product
    /// gate (all calls; plan D12 / A3(b)), independent of E2EE. Self-reconnect
    /// and existing members are exempt.
    VideoCallFull {
        max: usize,
    },
}

#[macro_export]
macro_rules! create_error {
    ( $error: ident $( $tt:tt )? ) => {
        $crate::Error {
            error_type: $crate::ErrorType::$error $( $tt )?,
            location: format!("{}:{}:{}", file!(), line!(), column!()),
        }
    };
}

#[macro_export]
macro_rules! create_database_error {
    ( $operation: expr, $collection: expr ) => {
        $crate::create_error!(DatabaseError {
            operation: $operation.to_string(),
            collection: $collection.to_string()
        })
    };
}

#[macro_export]
#[cfg(debug_assertions)]
macro_rules! query {
    ( $self: ident, $type: ident, $collection: expr, $($rest:expr),+ ) => {
        Ok($self.$type($collection, $($rest),+).await.unwrap())
    };
}

#[macro_export]
#[cfg(not(debug_assertions))]
macro_rules! query {
    ( $self: ident, $type: ident, $collection: expr, $($rest:expr),+ ) => {
        $self.$type($collection, $($rest),+).await
            .map_err(|_| create_database_error!(stringify!($type), $collection))
    };
}

pub trait ToRevoltError<T> {
    #[track_caller]
    fn to_internal_error(self) -> Result<T, Error>;
}

impl<T, E: std::fmt::Debug + std::error::Error> ToRevoltError<T> for Result<T, E> {
    #[track_caller]
    fn to_internal_error(self) -> Result<T, Error> {
        let loc = Location::caller();

        self.map_err(|e| {
            log::error!("{e:?}");
            #[cfg(feature = "sentry")]
            sentry::capture_error(&e);

            Error {
                error_type: ErrorType::InternalError,
                location: format!("{}:{}:{}", loc.file(), loc.line(), loc.column()),
            }
        })
    }
}

impl<T> ToRevoltError<T> for Option<T> {
    #[track_caller]
    fn to_internal_error(self) -> Result<T, Error> {
        let loc = Location::caller();

        self.ok_or_else(|| Error {
            error_type: ErrorType::InternalError,
            location: format!("{}:{}:{}", loc.file(), loc.line(), loc.column()),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ErrorType;

    #[test]
    fn use_macro_to_construct_error() {
        let error = create_error!(LabelMe);
        assert!(matches!(error.error_type, ErrorType::LabelMe));
    }

    #[test]
    fn use_macro_to_construct_complex_error() {
        let error = create_error!(LabelMe);
        assert!(matches!(error.error_type, ErrorType::LabelMe));
    }
}
