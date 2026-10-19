//! A database error must never be reported as a dead session: the client
//! would sign the user out. Only a credential that was not found is one.
use revolt_result::{Error, ErrorType};

/// The credential lookup found nothing: `InvalidSession` (session fetch) or `NotFound` (bot/user fetch).
fn is_credential_not_found(error: &Error) -> bool {
    matches!(error.error_type, ErrorType::InvalidSession | ErrorType::NotFound)
}

/// True only for `ErrorType::InvalidSession`.
pub fn is_invalid_session(error: &Error) -> bool {
    matches!(error.error_type, ErrorType::InvalidSession)
}

/// Not found becomes `InvalidSession`; anything else is logged and becomes `InternalError`.
pub fn credential_lookup_error(error: Error) -> Error {
    if is_credential_not_found(&error) {
        create_error!(InvalidSession)
    } else {
        // `query!` has already reported driver errors to Sentry in release
        error!("Credential lookup failed: {error:?}");
        create_error!(InternalError)
    }
}

/// 401 for `InvalidSession`, 500 for everything else.
#[cfg(feature = "rocket-impl")]
pub fn credential_error_status(error: &Error) -> rocket::http::Status {
    if is_invalid_session(error) {
        rocket::http::Status::Unauthorized
    } else {
        rocket::http::Status::InternalServerError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(error: Error) -> ErrorType {
        credential_lookup_error(error).error_type
    }

    #[test]
    fn not_found_maps_to_invalid_session() {
        assert!(matches!(
            lookup(create_error!(InvalidSession)),
            ErrorType::InvalidSession
        ));
        assert!(matches!(
            lookup(create_error!(NotFound)),
            ErrorType::InvalidSession
        ));
    }

    #[test]
    fn other_errors_map_to_internal_error() {
        assert!(matches!(
            lookup(create_database_error!("find_one", "sessions")),
            ErrorType::InternalError
        ));
        assert!(matches!(
            lookup(create_error!(InternalError)),
            ErrorType::InternalError
        ));
        assert!(matches!(
            lookup(create_error!(UnknownUser)),
            ErrorType::InternalError
        ));
    }

    #[test]
    fn not_found_predicate() {
        assert!(is_credential_not_found(&create_error!(InvalidSession)));
        assert!(is_credential_not_found(&create_error!(NotFound)));
        assert!(!is_credential_not_found(&create_database_error!(
            "find_one", "sessions"
        )));
        assert!(!is_credential_not_found(&create_error!(InternalError)));
        assert!(!is_credential_not_found(&create_error!(UnknownUser)));
    }

    #[test]
    fn invalid_session_predicate() {
        assert!(is_invalid_session(&create_error!(InvalidSession)));
        assert!(!is_invalid_session(&create_database_error!(
            "find_one", "sessions"
        )));
        assert!(!is_invalid_session(&create_error!(InternalError)));
        assert!(!is_invalid_session(&create_error!(NotFound)));
    }

    #[cfg(feature = "rocket-impl")]
    #[test]
    fn status_for_errors() {
        use rocket::http::Status;

        assert_eq!(
            credential_error_status(&create_error!(InvalidSession)),
            Status::Unauthorized
        );
        assert_eq!(
            credential_error_status(&create_error!(InternalError)),
            Status::InternalServerError
        );
        assert_eq!(
            credential_error_status(&create_database_error!("find_one", "sessions")),
            Status::InternalServerError
        );
    }
}
