use revolt_database::{
    util::e2ee_only::{self, SIDE_SENDER},
    Database, E2EEIdentity, PartialUser, Session, User, ValidatedTicket,
};
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};
use serde::{Deserialize, Serialize};

/// # Encrypted-only Chats Request
#[derive(Deserialize, JsonSchema, Debug)]
pub struct DataSetE2EEOnly {
    /// Whether the account only takes end-to-end encrypted direct and group
    /// messages
    pub enabled: bool,
}

/// # Encrypted-only Chats Setting
#[derive(Serialize, JsonSchema, Debug)]
pub struct ResponseSetE2EEOnly {
    /// The account's setting after the request
    pub e2ee_only: bool,
}

/// # Set Encrypted-only Chats
///
/// Turn the current account's Encrypted-only setting on or off. While it is
/// on, the server refuses unencrypted messages in the account's direct
/// messages and groups. The setting is public.
///
/// Needs a validated MFA ticket, which the guard consumes before the body is
/// read, so check the node advert (`features.e2ee.only`) and the device
/// before asking for one.
///
/// Turning it on needs E2EE on this node, the setting to be available
/// (`[features.e2ee] only_available`) and a session bound to one of the
/// account's published devices (else `EncryptionRequired` with side
/// `sender`). Turning it off needs the ticket only, from
/// any session, whatever the node's switches say.
///
/// Asking for the value the account already has changes nothing. Bots are
/// refused.
#[openapi(tag = "E2EE")]
#[put("/only", data = "<data>")]
pub async fn set_only(
    db: &State<Database>,
    mut user: User,
    session: Session,
    ticket: ValidatedTicket,
    data: Json<DataSetE2EEOnly>,
) -> Result<Json<ResponseSetE2EEOnly>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // The guard already binds the ticket to the session's account
    if ticket.account_id != user.id {
        return Err(create_error!(InvalidToken));
    }

    let enabled = data.into_inner().enabled;

    if enabled {
        super::require_e2ee_enabled().await?;

        if !revolt_config::config().await.features.e2ee.only_available {
            return Err(create_error!(FeatureDisabled {
                feature: "e2ee_only".to_string()
            }));
        }

        // No published device behind this session reads as "set up
        // encryption here first", not as a dead session (as at group creation)
        match E2EEIdentity::require_device_bound_session(db, &user.id, &session.id).await {
            Ok(()) => {}
            Err(error) if matches!(error.error_type, ErrorType::NotAuthenticated) => {
                return Err(e2ee_only::refused(SIDE_SENDER));
            }
            Err(error) => return Err(error),
        }
    }

    if user.e2ee_only != enabled {
        // The UserUpdate carries an explicit `true` or `false`, so a contact
        // can tell "turned off" from "not sent"
        user.update(
            db,
            PartialUser {
                e2ee_only: Some(enabled),
                ..Default::default()
            },
            vec![],
        )
        .await?;
    }

    Ok(Json(ResponseSetE2EEOnly { e2ee_only: enabled }))
}
