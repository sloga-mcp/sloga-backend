use iso8601_timestamp::Timestamp;
use revolt_database::{
    is_valid_device_id, Database, E2EEBackup, Session, User, E2EE_MAX_BACKUP_SIZE,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use revolt_rocket_okapi::{gen::OpenApiGenerator, request::OpenApiFromData};
use rocket::{
    data::{self, Data, FromData, ToByteUnit},
    http::Status,
    serde::json::Json,
    Request, State,
};

use super::MAX_BACKUP_HEADER_LENGTH;

/// Body limit for this route only. Delta's global JSON limit is Rocket's
/// 1 MiB default, far below `E2EE_MAX_BACKUP_SIZE` (8 MiB decoded, about
/// 10.7 MiB as base64), so a plain `Json<..>` guard refused every backup
/// above roughly 750 KiB with a 413 before the route's own cap was reached.
/// 12 MiB covers the cap plus the header and JSON framing; anything larger
/// is still refused (413) before it is parsed. No other route changes.
pub const BACKUP_BODY_LIMIT_MIB: u64 = 12;

/// `Json<DataPutE2EEBackup>` read with [`BACKUP_BODY_LIMIT_MIB`] instead of
/// the global JSON limit. Status mapping matches Rocket's `Json`: too large
/// is 413; an unreadable body or malformed JSON is 400; well-formed JSON
/// that does not fit the type is 422.
pub struct BackupBody(pub v0::DataPutE2EEBackup);

#[rocket::async_trait]
impl<'r> FromData<'r> for BackupBody {
    type Error = ();

    async fn from_data(_req: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
        let body = match data
            .open(BACKUP_BODY_LIMIT_MIB.mebibytes())
            .into_string()
            .await
        {
            Ok(body) => body,
            Err(_) => return data::Outcome::Error((Status::BadRequest, ())),
        };
        if !body.is_complete() {
            return data::Outcome::Error((Status::PayloadTooLarge, ()));
        }
        match serde_json::from_str::<v0::DataPutE2EEBackup>(&body.into_inner()) {
            Ok(parsed) => data::Outcome::Success(BackupBody(parsed)),
            Err(e) if e.is_syntax() || e.is_eof() => {
                data::Outcome::Error((Status::BadRequest, ()))
            }
            Err(_) => data::Outcome::Error((Status::UnprocessableEntity, ())),
        }
    }
}

impl<'r> OpenApiFromData<'r> for BackupBody {
    fn request_body(
        gen: &mut OpenApiGenerator,
    ) -> revolt_rocket_okapi::Result<revolt_rocket_okapi::revolt_okapi::openapi3::RequestBody> {
        <Json<v0::DataPutE2EEBackup> as OpenApiFromData<'r>>::request_body(gen)
    }
}

/// # Upload E2EE Key Backup
///
/// Upsert this device's recovery-code-encrypted key-backup blob (design §5).
///
/// Requires a session bound to the asserted device (int-H3 parity — only a
/// device that has proven its identity key can write its own backup). The
/// server stores the blob OPAQUELY: it parses the header solely to
/// range-check KDF params and to cross-check that the header-bound generation
/// equals the body generation (so the two duplicated copies can never
/// diverge); it can never read the backed-up keys or history.
///
/// `generation` must strictly exceed the stored generation — a stale-or-equal
/// upload is refused (echoing the stored generation), which makes the PUT
/// idempotency-safe and refuses a replayed old upload bundle server-side.
#[openapi(tag = "E2EE")]
#[put("/backup", data = "<data>")]
pub async fn put_backup(
    db: &State<Database>,
    user: User,
    session: Session,
    data: BackupBody,
) -> Result<Json<v0::ResponsePutE2EEBackup>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.0;

    if !is_valid_device_id(&data.device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    // Only a session bound to THIS device may write its backup
    let identity = db.fetch_e2ee_identity(&user.id, &data.device_id).await?;
    identity.assert_bound_session(&session.id)?;

    // Size caps (header cap is checked inside validate_header; ciphertext is
    // base64, decoded length ~ 3/4 of encoded)
    let decoded_len = data.ciphertext.len() / 4 * 3;
    if decoded_len > E2EE_MAX_BACKUP_SIZE {
        return Err(create_error!(FailedValidation {
            error: "backup ciphertext exceeds the size cap".to_string()
        }));
    }

    if data.header.len() > MAX_BACKUP_HEADER_LENGTH {
        return Err(create_error!(FailedValidation {
            error: "backup header too large".to_string()
        }));
    }

    // Parse + validate the header: KDF params in range (DoS guard), and the
    // header's bound user/device/generation match this request (M1 + M2)
    E2EEBackup::validate_header(&data.header, &user.id, &data.device_id, data.generation)?;

    // Strict generation monotonicity (replay defense). First write: any
    // generation >= 1 is accepted.
    let existing = db.fetch_e2ee_backup(&user.id, &data.device_id).await?;
    if data.generation < 1 {
        return Err(create_error!(FailedValidation {
            error: "generation must be positive".to_string()
        }));
    }

    // Bound the generation MAGNITUDE (M2 defence-in-depth): a compromised
    // webview cannot jump the stored generation to `i64::MAX` to permanently
    // wedge every future (legitimately-incrementing) PUT. Legit generations
    // step by 1 per refresh, so a jump beyond this bound over the previous
    // value (0 for a first write) is a tamper signal. Recovery from a
    // wedged blob is the explicit MFA-gated DELETE + re-create.
    let floor = existing.as_ref().map(|e| e.generation).unwrap_or(0);
    if data.generation > floor.saturating_add(super::MAX_BACKUP_GENERATION_JUMP) {
        return Err(create_error!(FailedValidation {
            error: "generation increment too large".to_string()
        }));
    }

    if let Some(existing) = &existing {
        if data.generation <= existing.generation {
            // Echo the stored generation so the caller can resync
            return Ok(Json(v0::ResponsePutE2EEBackup {
                generation: existing.generation,
            }));
        }
    }

    let now = Timestamp::now_utc();
    let created_at = existing.as_ref().map(|b| b.created_at).unwrap_or(now);

    let backup = E2EEBackup {
        id: E2EEBackup::composite_id(&user.id, &data.device_id),
        user_id: user.id.clone(),
        device_id: data.device_id.clone(),
        header: data.header,
        ciphertext: data.ciphertext,
        generation: data.generation,
        created_at,
        updated_at: now,
    };

    db.upsert_e2ee_backup(&backup).await?;

    Ok(Json(v0::ResponsePutE2EEBackup {
        generation: data.generation,
    }))
}
