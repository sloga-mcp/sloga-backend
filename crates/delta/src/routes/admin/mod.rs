//! Staff routes: support tools for privileged accounts.
//!
//! Every route here needs a privileged account, an MFA ticket bound to the
//! session user and an `X-Audit-Log-Reason`. There is no staff audit-log
//! collection: each call logs an `AUDIT ...` line, and a write is also
//! recorded by its own ledger row (actor and reason). The Prot routes are
//! not gated on `[features.boosts.protection]`, so support can inspect and
//! correct wallets while Prot is switched off.
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod prot_adjust;
mod prot_orders;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![prot_orders::fetch_prot_order, prot_adjust::adjust_prot]
}

/// Whether `value` looks like an id the server hands out or a client nonce:
/// 1 to 64 ASCII letters, digits, `-` or `_`. Such a value cannot break the
/// `admin:` ledger key or forge a second line in the audit log.
fn is_plain_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::is_plain_id;
    use crate::util::test::{without_comments, TestHarness};
    use revolt_database::{MFATicket, PartialUser, Session, User};
    use rocket::http::Header;
    use rocket::local::asynchronous::{LocalRequest, LocalResponse};

    /// A fresh user promoted to staff, with their session
    pub(super) async fn new_staff(harness: &TestHarness) -> (Session, User) {
        let (_, session, mut staff) = harness.new_user().await;
        staff
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("promote staff");
        assert!(staff.privileged);

        (session, staff)
    }

    /// A validated MFA ticket for `account_id`. The guard claims a ticket, so
    /// every request needs a new one.
    pub(super) async fn validated_ticket(harness: &TestHarness, account_id: &str) -> MFATicket {
        let ticket = MFATicket::new(account_id.to_string(), true);
        ticket.save(&harness.db).await.expect("`MFATicket`");
        ticket
    }

    /// `request` as `session`'s user with a fresh validated ticket of their
    /// own and, when given, an `X-Audit-Log-Reason` header (sent as it is, so
    /// pass it percent-encoded)
    pub(super) async fn with_own_ticket<'c>(
        harness: &TestHarness,
        request: LocalRequest<'c>,
        session: &Session,
        reason: Option<&str>,
    ) -> LocalRequest<'c> {
        let ticket = validated_ticket(harness, &session.user_id).await;
        let request = request
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("x-mfa-ticket", ticket.token.clone()));

        match reason {
            Some(reason) => request.header(Header::new("X-Audit-Log-Reason", reason.to_string())),
            None => request,
        }
    }

    /// The `type` of an error response's body
    pub(super) async fn error_type(response: LocalResponse<'_>) -> String {
        let body = response.into_string().await.expect("body");
        let value: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|_| panic!("error body is not JSON: {}", body));
        value["type"]
            .as_str()
            .unwrap_or_else(|| panic!("error body has no type: {}", body))
            .to_string()
    }

    #[test]
    fn plain_ids_are_ulid_like() {
        assert!(is_plain_id("01JADMINNONCE0000000000000"));
        assert!(is_plain_id("nonce-1_a"));
        assert!(is_plain_id(&"a".repeat(64)));

        assert!(!is_plain_id(""));
        assert!(!is_plain_id(&"a".repeat(65)));
        assert!(!is_plain_id("one\nAUDIT prot_adjust: actor=x"));
        assert!(!is_plain_id("a:b"));
        assert!(!is_plain_id("a b"));
        assert!(!is_plain_id("caf\u{e9}"));
    }

    /// Support must be able to read and correct wallets while Prot is
    /// switched off, so neither route reads the Prot or payments settings
    #[test]
    fn prot_admin_routes_are_not_gated_on_the_prot_flags() {
        let routes = [
            ("prot_orders.rs", include_str!("prot_orders.rs")),
            ("prot_adjust.rs", include_str!("prot_adjust.rs")),
        ];

        for (file, source) in routes.iter() {
            let route = source.split("#[cfg(test)]").next().expect("route code");
            let code = without_comments(route);
            assert!(
                code.contains("#[openapi(tag = \"Payments\")]"),
                "{}: the route code was not found",
                file
            );

            for gate in &[
                "protection",
                "ProtSalesSettings",
                "PaymentsSettings",
                "config()",
                "ProtDisabled",
            ] {
                assert!(
                    !code.contains(gate),
                    "{}: the route reads `{}`; staff routes must work while Prot is off",
                    file,
                    gate
                );
            }
        }
    }
}
