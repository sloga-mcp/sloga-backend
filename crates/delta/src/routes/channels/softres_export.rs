use std::io::Write;

use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, SoftResReserveRow, SoftResSheet, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

use crate::util::softres::authorize_manage_sheet;

/// The shared JSON body of the Gargul and raidres flavors, built
/// EXCLUSIVELY via serde_json — raider-controlled names/notes must never
/// be string-formatted into a payload.
///
/// Gargul's SoftRes.lua performs structural validation only
/// (`metadata.id` + a `softreserves` table — verified against its
/// parser); there is no origin signature, so third-party blobs import
/// fine. `url` is set explicitly: Gargul reconstructs a bogus
/// legacy.softres.it link when it is absent.
fn export_json(sheet: &SoftResSheet, rows: &[SoftResReserveRow], app_url: &str) -> serde_json::Value {
    // A trailing slash on the configured host would produce `//` links.
    let app_url = app_url.trim_end_matches('/');
    let sheet_url = match &sheet.server {
        Some(server) => format!(
            "{}/server/{}/channel/{}/{}",
            app_url, server, sheet.channel, sheet.message
        ),
        None => format!("{}/channel/{}/{}", app_url, sheet.channel, sheet.message),
    };

    serde_json::json!({
        "metadata": {
            "id": sheet.id,
            "instance": sheet.raids.join("+"),
            "createdAt": sheet.created_at / 1000,
            "updatedAt": sheet.edited_at.unwrap_or(sheet.created_at) / 1000,
            "url": sheet_url,
            "hidden": sheet.hidden,
            "discordUrl": "",
        },
        "softreserves": rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "name": row.character_name,
                    "class": row.class.as_str(),
                    "note": row.note.as_deref().unwrap_or(""),
                    "plusOnes": row.plus_ones,
                    "items": row
                        .items
                        .iter()
                        .map(|id| serde_json::json!({ "id": id }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
        "hardreserves": sheet
            .hard_reserves
            .iter()
            .map(|hr| {
                serde_json::json!({
                    "id": hr.item_id,
                    "for": hr.reserved_for,
                    "note": hr.note.as_deref().unwrap_or(""),
                })
            })
            .collect::<Vec<_>>(),
    })
}

/// Gargul import string: base64(zlib(JSON)).
fn gargul_payload(
    sheet: &SoftResSheet,
    rows: &[SoftResReserveRow],
    app_url: &str,
) -> Result<String> {
    let json = serde_json::to_vec(&export_json(sheet, rows, app_url))
        .map_err(|_| create_error!(InternalError))?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&json)
        .and_then(|_| encoder.finish())
        .map(|compressed| STANDARD.encode(compressed))
        .map_err(|_| create_error!(InternalError))
}

/// raidres / RollFor (Turtle-WoW flavor) import string: plain
/// base64(JSON).
fn raidres_payload(
    sheet: &SoftResSheet,
    rows: &[SoftResReserveRow],
    app_url: &str,
) -> Result<String> {
    let json = serde_json::to_vec(&export_json(sheet, rows, app_url))
        .map_err(|_| create_error!(InternalError))?;
    Ok(STANDARD.encode(json))
}

/// One CSV field, RFC-4180 encoded with spreadsheet-formula
/// neutralization:
/// - embedded CR/LF are flattened to spaces (multi-line notes must not
///   break rows);
/// - a leading `=`, `+`, `-`, `@` or tab gets a `'` prefix (CSV formula
///   injection via raider notes/names — the export lands in Excel);
/// - fields containing commas or quotes are quote-wrapped with embedded
///   quotes doubled.
fn csv_field(value: &str) -> String {
    let flattened: String = value
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect();

    let neutralized = if flattened.starts_with(['=', '+', '-', '@', '\t']) {
        format!("'{flattened}")
    } else {
        flattened
    };

    if neutralized.contains([',', '"']) {
        format!("\"{}\"", neutralized.replace('"', "\"\""))
    } else {
        neutralized
    }
}

/// CSV flavor (LootReserve import): `ItemId,Name,Class,Note,Plus`, one
/// row per (reserve × item).
fn csv_payload(rows: &[SoftResReserveRow]) -> String {
    let mut out = String::from("ItemId,Name,Class,Note,Plus\r\n");
    for row in rows {
        for item in &row.items {
            out.push_str(&format!(
                "{},{},{},{},{}\r\n",
                csv_field(&item.to_string()),
                csv_field(&row.character_name),
                csv_field(row.class.as_str()),
                csv_field(row.note.as_deref().unwrap_or("")),
                csv_field(&row.plus_ones.to_string()),
            ));
        }
    }
    out
}

/// # Export Soft-Reserve Sheet
///
/// Renders an addon-importable export of the sheet's FULL reserve data —
/// always gated to the creator / ManageMessages, because the export
/// ignores the `hidden` setting by design.
#[openapi(tag = "Soft Reserves")]
#[get("/<target>/softres/<sheet_id>/export?<format>")]
pub async fn softres_export(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sheet_id: String,
    format: Option<String>,
) -> Result<Json<v0::SoftResExportResponse>> {
    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let sheet = db.fetch_sheet(&sheet_id).await?;
    if sheet.channel != channel.id() {
        return Err(create_error!(NotFound));
    }

    authorize_manage_sheet(&sheet, &user.id, &permissions)?;

    let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;
    let app_url = revolt_config::config().await.hosts.app;

    let format = format.unwrap_or_else(|| "gargul".to_string());
    let payload = match format.as_str() {
        "gargul" => gargul_payload(&sheet, &rows, &app_url)?,
        "raidres" => raidres_payload(&sheet, &rows, &app_url)?,
        "csv" => csv_payload(&rows),
        _ => return Err(create_error!(InvalidProperty)),
    };

    Ok(Json(v0::SoftResExportResponse { format, payload }))
}

#[cfg(test)]
mod unit {
    use super::*;
    use flate2::read::ZlibDecoder;
    use revolt_models::v0;
    use std::io::Read;

    fn sheet() -> SoftResSheet {
        SoftResSheet {
            id: "01SRS0000000000000000000000".to_string(),
            message: "01MSG0000000000000000000000".to_string(),
            channel: "01CHAN000000000000000000000".to_string(),
            server: Some("01SRV0000000000000000000000".to_string()),
            event: None,
            creator: "01LEAD000000000000000000000".to_string(),
            title: "Sunday MC".to_string(),
            edition: "classic".to_string(),
            raids: vec!["mc".to_string(), "onyxia".to_string()],
            reserves_per_user: 2,
            per_item_cap: None,
            allow_duplicates: false,
            class_restriction: false,
            hidden: true,
            lock_at_event_start: false,
            locks_at: None,
            note: None,
            hard_reserves: vec![v0::HardReserve {
                item_id: 17204,
                reserved_for: "Guild bank".to_string(),
                note: None,
            }],
            locked: false,
            created_at: 1_753_500_000_000,
            edited_at: Some(1_753_500_600_000),
        }
    }

    fn rows() -> Vec<SoftResReserveRow> {
        vec![
            SoftResReserveRow {
                id: "01SRS0000000000000000000000:01USERA".to_string(),
                sheet: "01SRS0000000000000000000000".to_string(),
                user: "01USERA".to_string(),
                channel: "01CHAN000000000000000000000".to_string(),
                character_name: "Leeroy".to_string(),
                class: v0::WowClass::Paladin,
                items: vec![18563, 18564],
                note: None,
                plus_ones: 0,
                edited_at: 0,
            },
            SoftResReserveRow {
                id: "01SRS0000000000000000000000:01USERB".to_string(),
                sheet: "01SRS0000000000000000000000".to_string(),
                user: "01USERB".to_string(),
                channel: "01CHAN000000000000000000000".to_string(),
                character_name: "Jenkins".to_string(),
                class: v0::WowClass::DeathKnight,
                // Hostile note: quotes, commas, newlines, and a formula.
                items: vec![19019],
                note: Some("=WEBSERVICE(\"evil\"),\r\nsecond line".to_string()),
                plus_ones: 0,
                edited_at: 0,
            },
        ]
    }

    /// The Gargul blob round-trips base64 → zlib → JSON with the shape
    /// its SoftRes.lua parser checks for.
    #[test]
    fn gargul_round_trip() {
        let payload = gargul_payload(&sheet(), &rows(), "https://app.sloga.gg").unwrap();

        let compressed = STANDARD.decode(payload).expect("valid base64");
        let mut json = String::new();
        ZlibDecoder::new(compressed.as_slice())
            .read_to_string(&mut json)
            .expect("valid zlib");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        assert_eq!(value["metadata"]["id"], "01SRS0000000000000000000000");
        assert_eq!(value["metadata"]["instance"], "mc+onyxia");
        assert_eq!(value["metadata"]["hidden"], true);
        // Seconds, not milliseconds.
        assert_eq!(value["metadata"]["createdAt"], 1_753_500_000);
        assert_eq!(value["metadata"]["updatedAt"], 1_753_500_600);
        // Explicit url — Gargul fabricates a legacy.softres.it link
        // when it is absent.
        assert_eq!(
            value["metadata"]["url"],
            "https://app.sloga.gg/server/01SRV0000000000000000000000/channel/01CHAN000000000000000000000/01MSG0000000000000000000000"
        );

        let reserves = value["softreserves"].as_array().expect("array");
        assert_eq!(reserves.len(), 2);
        assert_eq!(reserves[0]["name"], "Leeroy");
        assert_eq!(reserves[0]["class"], "paladin");
        assert_eq!(reserves[0]["plusOnes"], 0);
        assert_eq!(reserves[0]["items"][0]["id"], 18563);
        assert_eq!(reserves[1]["class"], "deathknight");
        // The hostile note is data in JSON — serde encodes it, nothing to
        // neutralize here.
        assert!(reserves[1]["note"].as_str().unwrap().contains("WEBSERVICE"));

        let hard = value["hardreserves"].as_array().expect("array");
        assert_eq!(hard[0]["id"], 17204);
        assert_eq!(hard[0]["for"], "Guild bank");
    }

    /// The raidres flavor is the same JSON, plain-base64.
    #[test]
    fn raidres_is_plain_base64_of_the_same_json() {
        let payload = raidres_payload(&sheet(), &rows(), "https://app.sloga.gg").unwrap();
        let json = STANDARD.decode(payload).expect("valid base64");
        let value: serde_json::Value = serde_json::from_slice(&json).expect("valid JSON");
        assert_eq!(value["metadata"]["instance"], "mc+onyxia");
    }

    /// CSV: RFC-4180 quoting, flattened newlines, and formula-prefix
    /// neutralization over the hostile note.
    #[test]
    fn csv_neutralizes_hostile_fields() {
        let csv = csv_payload(&rows());
        let lines: Vec<&str> = csv.split("\r\n").filter(|l| !l.is_empty()).collect();

        assert_eq!(lines[0], "ItemId,Name,Class,Note,Plus");
        // One row per (reserve × item): 2 items + 1 item.
        assert_eq!(lines.len(), 1 + 3);
        assert_eq!(lines[1], "18563,Leeroy,paladin,,0");

        // The hostile row: quote-wrapped, embedded quotes doubled, the
        // leading '=' neutralized, and the newline flattened.
        let hostile = lines[3];
        assert!(hostile.starts_with("19019,Jenkins,deathknight,"));
        assert!(hostile.contains("\"'=WEBSERVICE(\"\"evil\"\"),"), "{hostile}");
        assert!(!hostile.contains('\n'));
    }

    /// Every field goes through the encoder — including a note that is
    /// pure whitespace trickery.
    #[test]
    fn csv_field_rules() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("+plus"), "'+plus");
        assert_eq!(csv_field("-minus"), "'-minus");
        assert_eq!(csv_field("@at"), "'@at");
        assert_eq!(csv_field("\ttab"), "'\ttab");
        assert_eq!(csv_field("line1\r\nline2"), "line1  line2");
    }

    /// A DM/group sheet (no server) still gets a working deep link.
    #[test]
    fn dm_sheet_url_has_no_server_segment() {
        let mut dm_sheet = sheet();
        dm_sheet.server = None;
        let value = export_json(&dm_sheet, &[], "https://app.sloga.gg");
        assert_eq!(
            value["metadata"]["url"],
            "https://app.sloga.gg/channel/01CHAN000000000000000000000/01MSG0000000000000000000000"
        );
    }
}
