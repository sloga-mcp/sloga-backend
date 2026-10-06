use revolt_result::{create_error, Result};

/// Request header carrying the moderator-supplied reason for an audited action.
///
/// Clients percent-encode the value (`encodeURIComponent`) so that non-ASCII
/// text survives the header encoding.
pub const AUDIT_LOG_REASON_HEADER: &str = "X-Audit-Log-Reason";

/// Maximum length of an audit log reason, counted in `char`s after sanitizing.
pub const AUDIT_LOG_REASON_MAX_CHARS: usize = 512;

/// Raw audit log reason taken from the `X-Audit-Log-Reason` header.
///
/// The value is percent-decoded but NOT yet validated. Routes call
/// [`AuditLogReason::validated`] before using it. As a request guard this
/// never fails: delta has no error catcher, so a guard failure would reach
/// clients as Rocket's default error body instead of a typed error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditLogReason(Option<String>);

impl AuditLogReason {
    /// No reason supplied (tests and internal callers).
    pub fn none() -> Self {
        Self(None)
    }

    /// Build from a raw header value, percent-decoding it leniently.
    pub fn from_raw(value: Option<&str>) -> Self {
        Self(value.map(percent_decode_lenient))
    }

    /// Strip control characters and invisible bidi/format characters, then
    /// trim. An empty result is `None`; more than
    /// [`AUDIT_LOG_REASON_MAX_CHARS`] chars is `AuditLogReasonTooLong`.
    pub fn validated(self) -> Result<Option<String>> {
        let Some(raw) = self.0 else {
            return Ok(None);
        };

        let stripped: String = raw
            .chars()
            .filter(|c| !c.is_control() && !is_invisible_format(*c))
            .collect();
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        if trimmed.chars().count() > AUDIT_LOG_REASON_MAX_CHARS {
            return Err(create_error!(FailedValidation {
                error: "AuditLogReasonTooLong".to_string(),
            }));
        }

        Ok(Some(trimmed.to_string()))
    }
}

/// Bidi marks/overrides/isolates, zero-width characters and the Unicode line
/// and paragraph separators. They are not `char::is_control`, but they can
/// make a reason display differently from what it contains (Trojan Source
/// style spoofing in the audit log UI).
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode `%XX` (two hex digits) to that byte. Any other `%` (lone, trailing,
/// or followed by non-hex) is kept literally. Bytes that do not form valid
/// UTF-8 are replaced with U+FFFD.
fn percent_decode_lenient(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }

        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(feature = "rocket-impl")]
use revolt_rocket_okapi::{
    gen::OpenApiGenerator,
    request::{OpenApiFromRequest, RequestHeaderInput},
    revolt_okapi::openapi3::{Parameter, ParameterValue},
};

#[cfg(feature = "rocket-impl")]
use schemars::schema::{InstanceType, SchemaObject, SingleOrVec};

#[cfg(feature = "rocket-impl")]
impl OpenApiFromRequest<'_> for AuditLogReason {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> revolt_rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::Parameter(Parameter {
            name: AUDIT_LOG_REASON_HEADER.to_string(),
            description: Some(
                "Percent-encoded reason recorded in the server audit log (max 512 characters)"
                    .to_string(),
            ),
            allow_empty_value: false,
            required: false,
            deprecated: false,
            extensions: schemars::Map::new(),
            location: "header".to_string(),
            value: ParameterValue::Schema {
                allow_reserved: false,
                example: None,
                examples: None,
                explode: None,
                style: None,
                schema: SchemaObject {
                    instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
                    ..Default::default()
                },
            },
        }))
    }
}

#[cfg(feature = "rocket-impl")]
use rocket::request::{FromRequest, Outcome};

#[cfg(feature = "rocket-impl")]
#[async_trait]
impl<'r> FromRequest<'r> for AuditLogReason {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(AuditLogReason::from_raw(
            request.headers().get_one(AUDIT_LOG_REASON_HEADER),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_result::ErrorType;

    fn check(raw: Option<&str>) -> Result<Option<String>> {
        AuditLogReason::from_raw(raw).validated()
    }

    fn is_too_long(result: Result<Option<String>>) -> bool {
        match result {
            Err(err) => matches!(
                &err.error_type,
                ErrorType::FailedValidation { error } if error == "AuditLogReasonTooLong"
            ),
            Ok(_) => false,
        }
    }

    #[test]
    fn missing_header_is_none() {
        assert_eq!(check(None).unwrap(), None);
        assert_eq!(AuditLogReason::none().validated().unwrap(), None);
        assert_eq!(AuditLogReason::none(), AuditLogReason::from_raw(None));
    }

    #[test]
    fn plain_ascii_passes_through() {
        assert_eq!(
            check(Some("spamming invites")).unwrap(),
            Some("spamming invites".to_string())
        );
    }

    #[test]
    fn percent_encoded_utf8_decodes() {
        assert_eq!(
            check(Some("%E2%9C%93")).unwrap(),
            Some("\u{2713}".to_string())
        );
        assert_eq!(
            check(Some("rule%201%3A%20no%20spam")).unwrap(),
            Some("rule 1: no spam".to_string())
        );
        assert_eq!(
            check(Some("%e2%9c%93")).unwrap(),
            Some("\u{2713}".to_string())
        );
    }

    #[test]
    fn invalid_sequences_are_kept_literally() {
        assert_eq!(check(Some("%ZZ")).unwrap(), Some("%ZZ".to_string()));
        assert_eq!(check(Some("100%")).unwrap(), Some("100%".to_string()));
        assert_eq!(check(Some("50%2")).unwrap(), Some("50%2".to_string()));
        assert_eq!(check(Some("a%G1b")).unwrap(), Some("a%G1b".to_string()));
        assert_eq!(check(Some("%%41")).unwrap(), Some("%A".to_string()));
    }

    #[test]
    fn invalid_utf8_is_lossy() {
        assert_eq!(
            check(Some("a%FFb")).unwrap(),
            Some("a\u{FFFD}b".to_string())
        );
    }

    #[test]
    fn control_characters_are_stripped() {
        assert_eq!(
            check(Some("line1%0Aline2%09tab%00nul%7F")).unwrap(),
            Some("line1line2tabnul".to_string())
        );
        assert_eq!(check(Some("a\tb")).unwrap(), Some("ab".to_string()));
    }

    #[test]
    fn bidi_and_invisible_format_chars_are_stripped() {
        assert_eq!(
            check(Some("ban\u{202E}reason\u{200B}x")).unwrap(),
            Some("banreasonx".to_string())
        );
        // U+202E and U+200B arriving percent-encoded from the client.
        assert_eq!(
            check(Some("%E2%80%AEabc%E2%80%8B")).unwrap(),
            Some("abc".to_string())
        );
        for c in [
            '\u{200B}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2060}', '\u{2064}', '\u{2066}',
            '\u{2069}', '\u{FEFF}',
        ] {
            assert_eq!(
                check(Some(&format!("a{c}b"))).unwrap(),
                Some("ab".to_string())
            );
        }
        // Neighbours outside the ranges are ordinary text and survive.
        for c in ['\u{200A}', '\u{2010}', '\u{2070}', '\u{FEFE}', '\u{E9}'] {
            assert_eq!(
                check(Some(&format!("a{c}b"))).unwrap(),
                Some(format!("a{c}b"))
            );
        }
    }

    #[test]
    fn arabic_letter_mark_and_unicode_separators_are_stripped() {
        for c in ['\u{061C}', '\u{2028}', '\u{2029}'] {
            assert_eq!(
                check(Some(&format!("a{c}b"))).unwrap(),
                Some("ab".to_string())
            );
        }
        // U+061C, U+2028, U+2029 arriving percent-encoded from the client.
        assert_eq!(
            check(Some("x%D8%9Cy%E2%80%A8z%E2%80%A9")).unwrap(),
            Some("xyz".to_string())
        );
        assert_eq!(check(Some("\u{061C}\u{2028}\u{2029}")).unwrap(), None);
        // Neighbours outside the set are ordinary text and survive.
        for c in ['\u{061B}', '\u{061D}', '\u{2027}', '\u{202F}'] {
            assert_eq!(
                check(Some(&format!("a{c}b"))).unwrap(),
                Some(format!("a{c}b"))
            );
        }
    }

    #[test]
    fn only_invisible_format_chars_is_none() {
        assert_eq!(check(Some("\u{202E}\u{200B}")).unwrap(), None);
        assert_eq!(check(Some(" \u{FEFF} \u{2066}\u{2069} ")).unwrap(), None);
    }

    #[test]
    fn whitespace_only_is_none() {
        assert_eq!(check(Some("")).unwrap(), None);
        assert_eq!(check(Some("   ")).unwrap(), None);
        assert_eq!(check(Some("%20%20%0A%20")).unwrap(), None);
        assert_eq!(
            check(Some("  trimmed  ")).unwrap(),
            Some("trimmed".to_string())
        );
    }

    #[test]
    fn exactly_max_multibyte_chars_is_ok() {
        let reason = "\u{2713}".repeat(AUDIT_LOG_REASON_MAX_CHARS);
        assert!(reason.len() > AUDIT_LOG_REASON_MAX_CHARS);
        assert_eq!(check(Some(&reason)).unwrap(), Some(reason.clone()));

        let encoded = "%E2%9C%93".repeat(AUDIT_LOG_REASON_MAX_CHARS);
        assert_eq!(check(Some(&encoded)).unwrap(), Some(reason));
    }

    #[test]
    fn over_max_chars_is_too_long() {
        let reason = "\u{2713}".repeat(AUDIT_LOG_REASON_MAX_CHARS + 1);
        assert!(is_too_long(check(Some(&reason))));

        let ascii = "a".repeat(AUDIT_LOG_REASON_MAX_CHARS + 1);
        assert!(is_too_long(check(Some(&ascii))));
    }

    #[test]
    fn length_is_measured_after_trimming() {
        let padded = format!("  {}  ", "a".repeat(AUDIT_LOG_REASON_MAX_CHARS));
        assert_eq!(
            check(Some(&padded)).unwrap(),
            Some("a".repeat(AUDIT_LOG_REASON_MAX_CHARS))
        );
    }
}
