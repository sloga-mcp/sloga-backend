use std::io::Cursor;

use rocket::{
    http::{ContentType, Status},
    response::{self, Responder},
    Request, Response,
};

use crate::{Error, ErrorType};

/// HTTP response builder for Error enum
impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let status = match self.error_type {
            ErrorType::LabelMe => Status::InternalServerError,

            ErrorType::AlreadyOnboarded => Status::Forbidden,

            ErrorType::UnknownUser => Status::NotFound,
            ErrorType::InvalidUsername => Status::BadRequest,
            ErrorType::DisallowedName => Status::BadRequest,
            ErrorType::UsernameTaken => Status::Conflict,
            ErrorType::DiscriminatorChangeRatelimited => Status::TooManyRequests,
            ErrorType::AlreadyFriends => Status::Conflict,
            ErrorType::AlreadySentRequest => Status::Conflict,
            ErrorType::Blocked => Status::Conflict,
            ErrorType::BlockedByOther => Status::Forbidden,
            ErrorType::NotFriends => Status::Forbidden,
            ErrorType::DirectMessagesPaused => Status::Forbidden,
            ErrorType::ProfileIsPrivate => Status::Forbidden,
            ErrorType::TooManyPendingFriendRequests { .. } => Status::BadRequest,

            ErrorType::UnknownChannel => Status::NotFound,
            ErrorType::UnknownMessage => Status::NotFound,
            ErrorType::UnknownAttachment => Status::BadRequest,
            ErrorType::CannotDeleteMessage => Status::Forbidden,
            ErrorType::CannotEditMessage => Status::Forbidden,
            ErrorType::CannotJoinCall => Status::BadRequest,
            ErrorType::TooManyAttachments { .. } => Status::BadRequest,
            ErrorType::TooManyReplies { .. } => Status::BadRequest,
            ErrorType::EmptyMessage => Status::UnprocessableEntity,
            ErrorType::PayloadTooLarge => Status::UnprocessableEntity,
            ErrorType::CannotRemoveYourself => Status::BadRequest,
            ErrorType::GroupTooLarge { .. } => Status::Forbidden,
            ErrorType::AlreadyInGroup => Status::Conflict,
            ErrorType::NotInGroup => Status::NotFound,
            ErrorType::ThreadAlreadyExists => Status::Conflict,
            ErrorType::AlreadyPinned => Status::BadRequest,
            ErrorType::NotPinned => Status::BadRequest,
            ErrorType::InSlowmode { retry_after: _ } => Status::TooManyRequests,
            ErrorType::InvalidFlagValue => Status::BadRequest,

            ErrorType::CantCreateServers => Status::Forbidden,
            ErrorType::UnknownServer => Status::NotFound,
            ErrorType::InvalidRole => Status::NotFound,
            ErrorType::Banned => Status::Forbidden,
            ErrorType::AlreadyInServer => Status::Conflict,
            ErrorType::CannotTimeoutYourself => Status::BadRequest,
            ErrorType::ImportAlreadyInProgress => Status::Conflict,
            ErrorType::ImportSourceNotFound => Status::NotFound,
            ErrorType::ImportVerificationMissing => Status::Forbidden,
            ErrorType::ImportBotNotInServer => Status::NotFound,
            ErrorType::ImportUpstreamUnavailable => Status::ServiceUnavailable,
            ErrorType::ImportSourceUnavailable => Status::BadRequest,

            ErrorType::TooManyServers { .. } => Status::BadRequest,
            ErrorType::TooManyEmbeds { .. } => Status::BadRequest,
            ErrorType::TooManyEmoji { .. } => Status::BadRequest,
            ErrorType::TooManyStickers { .. } => Status::BadRequest,
            ErrorType::TooManySounds { .. } => Status::BadRequest,
            ErrorType::TooManyChannels { .. } => Status::BadRequest,
            ErrorType::TooManyRoles { .. } => Status::BadRequest,
            ErrorType::NotEnoughBoosts { .. } => Status::BadRequest,
            ErrorType::TooManyBoosts { .. } => Status::BadRequest,

            ErrorType::PerkRequired => Status::Forbidden,
            ErrorType::InvalidReferralCode => Status::BadRequest,
            ErrorType::InvalidClaim => Status::Conflict,

            ErrorType::ReachedMaximumBots => Status::BadRequest,
            ErrorType::IsBot => Status::BadRequest,
            ErrorType::IsNotBot => Status::BadRequest,
            ErrorType::BotIsPrivate => Status::Forbidden,
            ErrorType::TooManyCommands { .. } => Status::BadRequest,
            ErrorType::BotOffline => Status::BadRequest,
            ErrorType::InteractionExpired => Status::Gone,
            ErrorType::InteractionAlreadyResponded => Status::Conflict,
            ErrorType::PollClosed => Status::Gone,
            ErrorType::UnknownRaid => Status::BadRequest,
            ErrorType::UnknownEdition => Status::BadRequest,
            ErrorType::SoftResMixedEditions => Status::BadRequest,
            ErrorType::TooManySoftResRaids { .. } => Status::BadRequest,
            ErrorType::SoftResLocked => Status::Gone,
            ErrorType::SoftResInvalidItems => Status::BadRequest,
            ErrorType::SoftResClassRestricted => Status::BadRequest,
            ErrorType::SoftResItemCapReached => Status::Conflict,
            ErrorType::SoftResRecurringEvent => Status::BadRequest,
            ErrorType::SoftResEventAlreadyLinked => Status::Conflict,
            ErrorType::TooManyScheduledMessages { .. } => Status::BadRequest,
            ErrorType::NotAnAnnouncementChannel => Status::BadRequest,
            ErrorType::AlreadyCrossposted => Status::BadRequest,
            ErrorType::TooManyFollowers { .. } => Status::BadRequest,
            ErrorType::TooManyCrossposts { .. } => Status::TooManyRequests,

            ErrorType::CannotReportYourself => Status::BadRequest,

            ErrorType::MissingPermission { .. } => Status::Forbidden,
            ErrorType::MissingUserPermission { .. } => Status::Forbidden,
            ErrorType::NotElevated => Status::Forbidden,
            ErrorType::NotPrivileged => Status::Forbidden,
            ErrorType::CannotGiveMissingPermissions => Status::Forbidden,
            ErrorType::NotOwner => Status::Forbidden,
            ErrorType::IsElevated => Status::Forbidden,

            ErrorType::DatabaseError { .. } => Status::InternalServerError,
            ErrorType::InternalError => Status::InternalServerError,
            ErrorType::InvalidOperation => Status::BadRequest,
            ErrorType::InvalidCredentials => Status::Unauthorized,
            ErrorType::InvalidProperty => Status::BadRequest,
            ErrorType::InvalidSession => Status::Unauthorized,
            ErrorType::NotAuthenticated => Status::Unauthorized,
            ErrorType::DuplicateNonce => Status::Conflict,
            ErrorType::NotFound => Status::NotFound,
            ErrorType::NoEffect => Status::BadRequest,
            ErrorType::FailedValidation { .. } => Status::BadRequest,
            ErrorType::LiveKitUnavailable => Status::BadRequest,
            ErrorType::NotAVoiceChannel => Status::BadRequest,
            ErrorType::NotInVoiceChannel => Status::BadRequest,
            ErrorType::AlreadyConnected => Status::BadRequest,
            ErrorType::NotConnected => Status::BadRequest,
            ErrorType::UnknownNode => Status::BadRequest,
            ErrorType::RemoteControlOfferPending => Status::Conflict,
            ErrorType::RemoteControlGrantActive => Status::Conflict,
            ErrorType::WatchSessionExists => Status::Conflict,
            ErrorType::NotWatchHost => Status::Forbidden,
            ErrorType::FeatureDisabled { .. } => Status::BadRequest,

            ErrorType::ProxyError => Status::BadRequest,
            ErrorType::FileTooSmall => Status::UnprocessableEntity,
            ErrorType::FileTooLarge { .. } => Status::UnprocessableEntity,
            ErrorType::FileTypeNotAllowed => Status::BadRequest,
            ErrorType::UploadSessionConflict => Status::Conflict,
            ErrorType::UploadIncomplete => Status::BadRequest,
            ErrorType::TooManyUploadSessions { .. } => Status::TooManyRequests,
            ErrorType::ImageProcessingFailed => Status::InternalServerError,
            ErrorType::NoEmbedData => Status::BadRequest,
            ErrorType::VosoUnavailable => Status::BadRequest,

            ErrorType::RenderFail => Status::InternalServerError,
            ErrorType::MissingHeaders => Status::BadRequest,
            ErrorType::CaptchaFailed => Status::BadRequest,
            ErrorType::BlockedByShield => Status::BadRequest,
            ErrorType::UnverifiedAccount => Status::Forbidden,
            ErrorType::EmailFailed => Status::InternalServerError,
            ErrorType::InvalidToken => Status::Unauthorized,
            ErrorType::MissingInvite => Status::BadRequest,
            ErrorType::InvalidInvite => Status::BadRequest,
            ErrorType::CompromisedPassword => Status::BadRequest,
            ErrorType::ShortPassword => Status::BadRequest,
            ErrorType::Blacklisted => {
                // Fail blacklisted email addresses.
                const RESP: &str = "{\"type\":\"DisallowedContactSupport\", \"note\":\"If you see this messages right here, you're probably doing something you shouldn't be.\"}";

                return Response::build()
                    .status(Status::Unauthorized)
                    .sized_body(RESP.len(), std::io::Cursor::new(RESP))
                    .ok();
            }
            ErrorType::LockedOut => Status::Forbidden,
            ErrorType::TotpAlreadyEnabled => Status::BadRequest,
            ErrorType::DisallowedMFAMethod => Status::BadRequest,
            ErrorType::OperationFailed => Status::InternalServerError,
            ErrorType::IncorrectData { .. } => Status::BadRequest,
            ErrorType::MlsCallFull { .. } => Status::Conflict,
            ErrorType::VideoCallFull { .. } => Status::Conflict,

            ErrorType::PaymentsDisabled => Status::BadRequest,
            ErrorType::CipherSalesClosed => Status::Forbidden,
            ErrorType::CipherSoldOut => Status::Conflict,
            ErrorType::CipherRegionUnavailable => Status::BadRequest,
            ErrorType::CipherTierInvalid => Status::BadRequest,
            ErrorType::PaymentPending => Status::Conflict,
            ErrorType::PaymentProviderError => Status::BadGateway,

            ErrorType::ProtectedChannelResecuring { .. } => Status::Conflict,
            ErrorType::NotSeated => Status::Forbidden,
            ErrorType::SeatCapReached { .. } => Status::BadRequest,
            ErrorType::DeviceCapReached { .. } => Status::BadRequest,
            ErrorType::ChannelProtected => Status::BadRequest,
            ErrorType::ProtectedFieldRefused { .. } => Status::BadRequest,
        };

        // The body no longer carries the location, so log it for server
        // errors
        if status.code >= 500 {
            log::warn!("{self}");
        }

        // Serialize the error data structure into JSON.
        let string = serde_json::to_string(&self).unwrap();

        // Build and send the request.
        Response::build()
            .sized_body(string.len(), Cursor::new(string))
            .header(ContentType::new("application", "json"))
            .status(status)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use rocket::{
        http::{ContentType, Status},
        local::{asynchronous::Client as AsyncClient, blocking::Client},
        response::Responder,
    };

    use crate::{create_error, Error};

    /// Pins the import errors' statuses; `axum.rs` pins the same table
    #[test]
    fn import_error_statuses() {
        let client = Client::untracked(rocket::build()).unwrap();
        let request = client.get("/");

        let cases: [(Error, u16); 5] = [
            (create_error!(ImportSourceNotFound), 404),
            (create_error!(ImportVerificationMissing), 403),
            (create_error!(ImportBotNotInServer), 404),
            (create_error!(ImportUpstreamUnavailable), 503),
            (create_error!(ImportSourceUnavailable), 400),
        ];

        for (error, code) in cases {
            let name = format!("{:?}", error.error_type);
            let response = error.respond_to(request.inner()).unwrap();
            assert_eq!(response.status().code, code, "{name}");
        }
    }

    /// Pins the payment errors' statuses; `axum.rs` pins the same table
    #[test]
    fn payment_error_statuses() {
        let client = Client::untracked(rocket::build()).unwrap();
        let request = client.get("/");

        let cases: [(Error, u16); 7] = [
            (create_error!(PaymentsDisabled), 400),
            (create_error!(CipherSalesClosed), 403),
            (create_error!(CipherSoldOut), 409),
            (create_error!(CipherRegionUnavailable), 400),
            (create_error!(CipherTierInvalid), 400),
            (create_error!(PaymentPending), 409),
            (create_error!(PaymentProviderError), 502),
        ];

        for (error, code) in cases {
            let name = format!("{:?}", error.error_type);
            let response = error.respond_to(request.inner()).unwrap();
            assert_eq!(response.status().code, code, "{name}");
        }
    }

    #[rocket::async_test]
    async fn device_cap_reached_is_bad_request_with_max_in_body() {
        let client = AsyncClient::untracked(rocket::build())
            .await
            .expect("local rocket client");
        let request = client.get("/");
        let mut response = crate::create_error!(DeviceCapReached { max: 5 })
            .respond_to(request.inner())
            .expect("error responder");

        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        let body = response.body_mut().to_string().await.expect("body");
        let body: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
        assert_eq!(body["type"], "DeviceCapReached");
        assert_eq!(body["max"], 5);

        let mut keys: Vec<&str> = body
            .as_object()
            .expect("JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        // The error's `location` stays out of the body
        assert_eq!(keys, ["max", "type"]);
    }
}
