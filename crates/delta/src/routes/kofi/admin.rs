use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, Utc};
use revolt_config::config;
use revolt_database::{parse_amount_cents, Database, Donation, KofiPayload, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::data::ToByteUnit;
use rocket::{serde::json::Json, Data, State};
use rocket_empty::EmptyResponse;
use serde::Serialize;
use validator::Validate;

/// Largest CSV body the import accepts
const IMPORT_LIMIT_MIB: u64 = 5;

/// Header aliases, matched case-insensitively; the first alias found wins
const TXN_COLUMNS: &[&str] = &["TransactionId", "Transaction Id", "kofi_transaction_id"];
const TIME_COLUMNS: &[&str] = &["DateTime (UTC)", "DateTime", "Date", "timestamp"];
const AMOUNT_COLUMNS: &[&str] = &["Received", "Amount"];
const CURRENCY_COLUMNS: &[&str] = &["Currency"];
const EMAIL_COLUMNS: &[&str] = &["BuyerEmail", "Buyer Email", "Email"];
const KIND_COLUMNS: &[&str] = &["TransactionType", "Type"];
const NAME_COLUMNS: &[&str] = &["From"];

/// # Ko-fi Import Summary
#[derive(Serialize, JsonSchema, Debug, Default)]
pub struct KofiImportSummary {
    /// Rows stored as new donations
    pub inserted: u32,
    /// Rows whose transaction was already stored
    pub duplicates: u32,
    /// Rows that could not be imported, as `<transaction id>: <reason>`
    pub failed: Vec<String>,
}

/// # Assign Donation
///
/// Attribute a Ko-fi donation to a user, optionally with the USD value it
/// counts for. Requires a privileged account.
#[openapi(tag = "Ko-fi")]
#[post("/donations/<txn>/assign", data = "<data>")]
pub async fn assign_donation(
    db: &State<Database>,
    user: User,
    txn: String,
    data: Json<v0::DataAssignDonation>,
) -> Result<EmptyResponse> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let target = db.fetch_user(&data.user).await?;

    log::info!(
        "AUDIT donation_assign: actor={} txn={} target={} usd_cents={:?}",
        user.id,
        txn,
        target.id,
        data.usd_cents
    );

    Donation::assign(db, &txn, &target.id, data.usd_cents).await?;
    Ok(EmptyResponse)
}

/// # Revoke Donation
///
/// Mark a Ko-fi donation as refunded or charged back, so it no longer counts
/// towards anyone's supporter totals. Requires a privileged account.
#[openapi(tag = "Ko-fi")]
#[post("/donations/<txn>/revoke")]
pub async fn revoke_donation(
    db: &State<Database>,
    user: User,
    txn: String,
) -> Result<EmptyResponse> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    log::info!("AUDIT donation_revoke: actor={} txn={}", user.id, txn);

    Donation::revoke(db, &txn).await?;
    Ok(EmptyResponse)
}

/// # Import Donations
///
/// Backfill past payments from a Ko-fi CSV export. Rows already stored are
/// skipped, and a bad row is reported without stopping the import. Messages
/// are never imported. Requires a privileged account.
#[openapi(tag = "Ko-fi")]
#[post("/import", data = "<data>")]
pub async fn import_donations(
    db: &State<Database>,
    user: User,
    data: Data<'_>,
) -> Result<Json<KofiImportSummary>> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let config = config().await;
    let hmac_key = &config.api.kofi.email_hmac_key;
    if hmac_key.is_empty() {
        return Err(create_error!(NotFound));
    }

    let body = data
        .open(IMPORT_LIMIT_MIB.mebibytes())
        .into_string()
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "could not read the CSV as UTF-8".to_string()
            })
        })?;
    if !body.is_complete() {
        return Err(create_error!(FailedValidation {
            error: format!("CSV is larger than {IMPORT_LIMIT_MIB} MiB")
        }));
    }

    let summary = import_csv(db, &body.into_inner(), hmac_key).await?;

    log::info!(
        "AUDIT donation_import: actor={} inserted={} duplicates={} failed={}",
        user.id,
        summary.inserted,
        summary.duplicates,
        summary.failed.len()
    );

    Ok(Json(summary))
}

/// Store every row of a Ko-fi CSV export that is not stored yet
async fn import_csv(db: &Database, csv: &str, hmac_key: &str) -> Result<KofiImportSummary> {
    let records = parse_csv(csv.trim_start_matches('\u{feff}'))
        .map_err(|error| create_error!(FailedValidation { error }))?;

    let mut records = records.into_iter();
    let header = records.next().ok_or_else(|| {
        create_error!(FailedValidation {
            error: "CSV is empty".to_string()
        })
    })?;

    let columns = find_columns(&header).map_err(|missing| {
        create_error!(FailedValidation {
            error: format!("CSV is missing required columns: {}", missing.join(", "))
        })
    })?;

    let mut summary = KofiImportSummary::default();
    for (index, row) in records.enumerate() {
        if row.iter().all(|value| value.trim().is_empty()) {
            continue;
        }

        let txn = cell(&row, columns.txn).to_string();
        if txn.is_empty() {
            summary
                .failed
                .push(format!("row {}: missing transaction id", index + 1));
            continue;
        }

        match db.fetch_donation(&txn).await {
            Ok(Some(_)) => {
                summary.duplicates += 1;
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                summary
                    .failed
                    .push(format!("{txn}: {:?}", error.error_type));
                continue;
            }
        }

        let payload = match row_payload(&columns, &row, &txn) {
            Ok(payload) => payload,
            Err(reason) => {
                summary.failed.push(format!("{txn}: {reason}"));
                continue;
            }
        };

        match Donation::ingest(db, &payload, hmac_key).await {
            // A row stored in the meantime (by the webhook) comes back under
            // its own message id
            Ok(donation) if donation.message_id == payload.message_id => summary.inserted += 1,
            Ok(_) => summary.duplicates += 1,
            Err(error) => summary
                .failed
                .push(format!("{txn}: {:?}", error.error_type)),
        }
    }

    Ok(summary)
}

/// Positions of the columns the import reads
#[derive(Debug, PartialEq, Eq)]
struct Columns {
    txn: usize,
    time: usize,
    amount: usize,
    currency: usize,
    email: Option<usize>,
    kind: Option<usize>,
    name: Option<usize>,
}

/// Position of the first alias present in the header
fn find_column(header: &[String], aliases: &[&str]) -> Option<usize> {
    aliases.iter().find_map(|alias| {
        header
            .iter()
            .position(|name| name.trim().eq_ignore_ascii_case(alias))
    })
}

/// Locate every column, or name the required ones that are missing
fn find_columns(header: &[String]) -> std::result::Result<Columns, Vec<&'static str>> {
    let mut missing = Vec::new();
    let mut required = |aliases: &[&'static str]| {
        let position = find_column(header, aliases);
        if position.is_none() {
            missing.push(aliases[0]);
        }
        position
    };

    let txn = required(TXN_COLUMNS);
    let time = required(TIME_COLUMNS);
    let amount = required(AMOUNT_COLUMNS);
    let currency = required(CURRENCY_COLUMNS);

    match (txn, time, amount, currency) {
        (Some(txn), Some(time), Some(amount), Some(currency)) => Ok(Columns {
            txn,
            time,
            amount,
            currency,
            email: find_column(header, EMAIL_COLUMNS),
            kind: find_column(header, KIND_COLUMNS),
            name: find_column(header, NAME_COLUMNS),
        }),
        _ => Err(missing),
    }
}

/// Trimmed cell value; a short row reads as empty
fn cell(row: &[String], index: usize) -> &str {
    row.get(index).map(|value| value.trim()).unwrap_or("")
}

/// Trimmed cell value of an optional column, None when absent or empty
fn optional_cell(row: &[String], index: Option<usize>) -> Option<&str> {
    index
        .map(|index| cell(row, index))
        .filter(|value| !value.is_empty())
}

/// Whether a Ko-fi payment type is a membership payment
fn is_subscription_kind(kind: &str) -> bool {
    let kind = kind.to_lowercase();
    kind.contains("subscription") || kind.contains("membership")
}

/// Convert an export timestamp to the RFC 3339 form `Donation::ingest`
/// parses. Times without an offset are UTC. Day/month orders other than
/// year-first are rejected rather than guessed.
fn normalise_timestamp(value: &str) -> Option<String> {
    let value = value.trim();
    let at = if let Ok(at) = DateTime::parse_from_rfc3339(value) {
        at.with_timezone(&Utc)
    } else if let Some(at) = [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
    ]
    .iter()
    .find_map(|format| NaiveDateTime::parse_from_str(value, format).ok())
    {
        at.and_utc()
    } else {
        NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .ok()?
            .and_hms_opt(0, 0, 0)?
            .and_utc()
    };

    Some(at.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Build the webhook payload for one CSV row. The timestamp and amount are
/// checked here: `Donation::ingest` would store an unparseable timestamp as
/// the time of import and an unparseable amount as zero, and a re-import
/// could not correct either.
fn row_payload(
    columns: &Columns,
    row: &[String],
    txn: &str,
) -> std::result::Result<KofiPayload, String> {
    let timestamp = normalise_timestamp(cell(row, columns.time)).ok_or("unrecognized timestamp")?;

    let amount = cell(row, columns.amount);
    if parse_amount_cents(amount).is_none() {
        return Err("unrecognized amount".to_string());
    }

    let currency = cell(row, columns.currency);
    if currency.is_empty() {
        return Err("missing currency".to_string());
    }

    let kind = optional_cell(row, columns.kind).unwrap_or("Donation");

    Ok(KofiPayload {
        verification_token: String::new(),
        message_id: format!("import:{txn}"),
        timestamp,
        kind: kind.to_string(),
        is_public: false,
        from_name: optional_cell(row, columns.name).map(str::to_string),
        message: None,
        amount: amount.to_string(),
        currency: currency.to_string(),
        email: optional_cell(row, columns.email).map(str::to_string),
        kofi_transaction_id: txn.to_string(),
        is_subscription_payment: is_subscription_kind(kind),
        is_first_subscription_payment: false,
        tier_name: None,
    })
}

/// RFC 4180 CSV: quoted fields may hold commas, newlines and doubled
/// quotes; records end in LF or CRLF.
fn parse_csv(input: &str) -> std::result::Result<Vec<Vec<String>>, String> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => in_quotes = false,
                _ => field.push(c),
            }
            continue;
        }

        match c {
            '"' if field.is_empty() => in_quotes = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\r' | '\n' => {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }

    if in_quotes {
        return Err("CSV has an unterminated quoted field".to_string());
    }

    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_database::{DonationState, ReferenceDb};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn columns() -> Columns {
        find_columns(&strings(&[
            "DateTime (UTC)",
            "From",
            "Message",
            "Item",
            "Received",
            "Given",
            "Currency",
            "TransactionType",
            "TransactionId",
            "BuyerEmail",
        ]))
        .unwrap()
    }

    #[test]
    fn csv_parses_plain_rows() {
        assert_eq!(
            parse_csv("a,b,c\n1,2,3\n").unwrap(),
            vec![strings(&["a", "b", "c"]), strings(&["1", "2", "3"])]
        );
        assert_eq!(parse_csv("a,,c").unwrap(), vec![strings(&["a", "", "c"])]);
        assert!(parse_csv("").unwrap().is_empty());
    }

    #[test]
    fn csv_quoted_field_keeps_commas() {
        assert_eq!(
            parse_csv("\"Smith, Jane\",5.00\n").unwrap(),
            vec![strings(&["Smith, Jane", "5.00"])]
        );
    }

    #[test]
    fn csv_doubled_quotes_unescape() {
        assert_eq!(
            parse_csv("\"say \"\"hi\"\"\",x\n\"\"\"\",\"\"\n").unwrap(),
            vec![strings(&["say \"hi\"", "x"]), strings(&["\"", ""])]
        );
    }

    #[test]
    fn csv_quoted_field_keeps_newlines() {
        assert_eq!(
            parse_csv("\"line one\nline two\",b\r\nc,d").unwrap(),
            vec![strings(&["line one\nline two", "b"]), strings(&["c", "d"])]
        );
    }

    #[test]
    fn csv_crlf_line_endings() {
        assert_eq!(
            parse_csv("a,b\r\n1,2\r\n").unwrap(),
            vec![strings(&["a", "b"]), strings(&["1", "2"])]
        );
    }

    #[test]
    fn csv_unterminated_quote_is_an_error() {
        assert!(parse_csv("a,\"b\n1,2\n").is_err());
    }

    #[test]
    fn header_aliases_match_case_insensitively() {
        let found = find_columns(&strings(&[
            " transaction id ",
            "DATETIME",
            "amount",
            "currency",
            "email",
            "type",
        ]))
        .unwrap();
        assert_eq!(
            found,
            Columns {
                txn: 0,
                time: 1,
                amount: 2,
                currency: 3,
                email: Some(4),
                kind: Some(5),
                name: None,
            }
        );

        let webhook_names = find_columns(&strings(&[
            "kofi_transaction_id",
            "timestamp",
            "Amount",
            "Currency",
        ]))
        .unwrap();
        assert_eq!(webhook_names.txn, 0);
        assert_eq!(webhook_names.time, 1);
    }

    #[test]
    fn header_first_alias_wins() {
        let found = columns();
        assert_eq!(found.time, 0);
        assert_eq!(found.amount, 4);
        assert_eq!(found.name, Some(1));

        let both = find_columns(&strings(&[
            "TransactionId",
            "Date",
            "DateTime (UTC)",
            "Amount",
            "Received",
            "Currency",
        ]))
        .unwrap();
        assert_eq!(both.time, 2);
        assert_eq!(both.amount, 4);
    }

    #[test]
    fn missing_required_columns_are_named() {
        assert_eq!(
            find_columns(&strings(&["From", "Currency", "Message"])),
            Err(vec!["TransactionId", "DateTime (UTC)", "Received"])
        );
        assert_eq!(
            find_columns(&[]),
            Err(vec![
                "TransactionId",
                "DateTime (UTC)",
                "Received",
                "Currency"
            ])
        );
    }

    #[test]
    fn subscription_kinds_detected() {
        assert!(is_subscription_kind("Subscription"));
        assert!(is_subscription_kind("Monthly MEMBERSHIP"));
        assert!(!is_subscription_kind("Donation"));
        assert!(!is_subscription_kind("Shop Order"));
        assert!(!is_subscription_kind(""));
    }

    #[test]
    fn timestamps_normalise_to_rfc3339() {
        assert_eq!(
            normalise_timestamp("2026-09-01T12:00:00Z").as_deref(),
            Some("2026-09-01T12:00:00.000Z")
        );
        assert_eq!(
            normalise_timestamp("2026-09-01T14:00:00+02:00").as_deref(),
            Some("2026-09-01T12:00:00.000Z")
        );
        assert_eq!(
            normalise_timestamp(" 2024-01-15 14:32:05 ").as_deref(),
            Some("2024-01-15T14:32:05.000Z")
        );
        assert_eq!(
            normalise_timestamp("2024-01-15 14:32:05.250").as_deref(),
            Some("2024-01-15T14:32:05.250Z")
        );
        assert_eq!(
            normalise_timestamp("2024-01-15T14:32:05").as_deref(),
            Some("2024-01-15T14:32:05.000Z")
        );
        assert_eq!(
            normalise_timestamp("2024-01-15 14:32").as_deref(),
            Some("2024-01-15T14:32:00.000Z")
        );
        assert_eq!(
            normalise_timestamp("2024-01-15").as_deref(),
            Some("2024-01-15T00:00:00.000Z")
        );
        assert_eq!(normalise_timestamp("01/15/2024 14:32"), None);
        assert_eq!(normalise_timestamp("15/01/2024"), None);
        assert_eq!(normalise_timestamp("yesterday"), None);
        assert_eq!(normalise_timestamp(""), None);
    }

    #[test]
    fn row_payload_builds_an_import_payload() {
        let row = strings(&[
            "2024-01-15 14:32:05",
            "Jane",
            "a private note",
            "",
            "5.00",
            "",
            "usd",
            "Subscription",
            "TXN-1",
            " jane@example.com ",
        ]);
        let payload = row_payload(&columns(), &row, "TXN-1").unwrap();

        assert_eq!(payload.message_id, "import:TXN-1");
        assert_eq!(payload.kofi_transaction_id, "TXN-1");
        assert_eq!(payload.verification_token, "");
        assert_eq!(payload.timestamp, "2024-01-15T14:32:05.000Z");
        assert_eq!(payload.amount, "5.00");
        assert_eq!(payload.currency, "usd");
        assert_eq!(payload.kind, "Subscription");
        assert!(payload.is_subscription_payment);
        assert!(!payload.is_first_subscription_payment);
        assert!(!payload.is_public);
        assert_eq!(payload.message, None);
        assert_eq!(payload.tier_name, None);
        assert_eq!(payload.from_name.as_deref(), Some("Jane"));
        assert_eq!(payload.email.as_deref(), Some("jane@example.com"));
    }

    #[test]
    fn row_payload_defaults_and_rejections() {
        let minimal =
            find_columns(&strings(&["TransactionId", "Date", "Amount", "Currency"])).unwrap();

        let payload = row_payload(&minimal, &strings(&["T", "2024-01-15", "3"]), "T");
        assert_eq!(payload.unwrap_err(), "missing currency");

        let payload =
            row_payload(&minimal, &strings(&["T", "2024-01-15", "3", "GBP"]), "T").unwrap();
        assert_eq!(payload.kind, "Donation");
        assert!(!payload.is_subscription_payment);
        assert_eq!(payload.email, None);
        assert_eq!(payload.from_name, None);

        let bad_time = row_payload(&minimal, &strings(&["T", "15/01/2024", "3", "USD"]), "T");
        assert_eq!(bad_time.unwrap_err(), "unrecognized timestamp");

        let bad_amount = row_payload(
            &minimal,
            &strings(&["T", "2024-01-15", "£3.00", "GBP"]),
            "T",
        );
        assert_eq!(bad_amount.unwrap_err(), "unrecognized amount");

        let refund = row_payload(
            &minimal,
            &strings(&["T", "2024-01-15", "-3.00", "USD"]),
            "T",
        );
        assert_eq!(refund.unwrap_err(), "unrecognized amount");
    }

    #[test]
    fn import_counts_inserted_duplicates_and_failures() {
        crate::util::test::rt().block_on(import_counts_inserted_duplicates_and_failures_case())
    }

    async fn import_counts_inserted_duplicates_and_failures_case() {
        let db = Database::Reference(ReferenceDb::default());
        let csv = "\u{feff}DateTime (UTC),From,Message,Received,Currency,TransactionType,TransactionId,BuyerEmail\r\n\
            2024-01-15 14:32:05,Jane,\"thanks, KOFI-7QM2XR\",5.00,USD,Subscription,T1,jane@example.com\r\n\
            2024-02-01 09:00:00,Sam,,10.00,EUR,Donation,T2,\r\n\
            \r\n\
            not a date,Kim,,3.00,USD,Donation,T3,\r\n\
            2024-03-01 10:00:00,Lee,,4.00,USD,Donation,,\r\n\
            2024-01-15 14:32:05,Jane,,5.00,USD,Subscription,T1,jane@example.com\r\n";

        let summary = import_csv(&db, csv, "test-key").await.unwrap();
        assert_eq!(summary.inserted, 2);
        assert_eq!(summary.duplicates, 1);
        assert_eq!(
            summary.failed,
            vec![
                "T3: unrecognized timestamp".to_string(),
                "row 5: missing transaction id".to_string()
            ]
        );

        let first = db.fetch_donation("T1").await.unwrap().unwrap();
        assert_eq!(first.message_id, "import:T1");
        assert_eq!(first.state, DonationState::Unclaimed);
        assert_eq!(first.amount_cents, 500);
        assert_eq!(first.timestamp, 1_705_329_125_000);
        assert!(first.is_subscription);
        assert!(first.payer_hmac.is_some());

        let second = db.fetch_donation("T2").await.unwrap().unwrap();
        assert_eq!(second.state, DonationState::NeedsReview);
        assert_eq!(second.currency, "EUR");
        assert_eq!(second.payer_hmac, None);

        assert!(db.fetch_donation("T3").await.unwrap().is_none());

        let again = import_csv(&db, csv, "test-key").await.unwrap();
        assert_eq!(again.inserted, 0);
        assert_eq!(again.duplicates, 3);
    }

    #[test]
    fn import_rejects_missing_columns() {
        crate::util::test::rt().block_on(import_rejects_missing_columns_case())
    }

    async fn import_rejects_missing_columns_case() {
        let db = Database::Reference(ReferenceDb::default());

        let error = import_csv(&db, "From,Currency\nJane,USD\n", "test-key")
            .await
            .unwrap_err();
        match error.error_type {
            revolt_result::ErrorType::FailedValidation { error } => {
                assert!(error.contains("TransactionId"));
                assert!(error.contains("DateTime (UTC)"));
                assert!(error.contains("Received"));
                assert!(!error.contains("Currency"));
            }
            other => panic!("unexpected error: {:?}", other),
        }

        assert!(import_csv(&db, "", "test-key").await.is_err());
    }
}
