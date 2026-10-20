//! Stripe event envelopes
//!
//! A webhook delivery (and a `GET /v1/events/{id}` re-drive) is an event
//! envelope:
//!
//! ```text
//! {"id": "evt_...", "object": "event", "type": "charge.refunded",
//!  "livemode": false, "created": 1700000000, "data": {"object": {...}}, ...}
//! ```
//!
//! Only the envelope fields the payment engine needs are kept. `data.object`
//! stays raw JSON because its shape depends on the event type (a checkout
//! session, a charge, a dispute); the helpers below read it defensively.
//!
//! Parsing fails closed: a missing or mistyped envelope field is a
//! [`StripeError::Decode`], never a default. Error text never quotes the
//! payload, since it can carry buyer details.
use serde_json::Value;

use super::client::{is_valid_stripe_id, StripeError};

/// `checkout.session.completed`: the buyer finished checkout
pub const CHECKOUT_SESSION_COMPLETED: &str = "checkout.session.completed";
/// `checkout.session.expired`: the session timed out unpaid
pub const CHECKOUT_SESSION_EXPIRED: &str = "checkout.session.expired";
/// `checkout.session.async_payment_succeeded`: a delayed payment method
/// paid a session that completed unpaid
pub const CHECKOUT_SESSION_ASYNC_PAYMENT_SUCCEEDED: &str =
    "checkout.session.async_payment_succeeded";
/// `checkout.session.async_payment_failed`: a delayed payment method did
/// not pay a session that completed unpaid
pub const CHECKOUT_SESSION_ASYNC_PAYMENT_FAILED: &str = "checkout.session.async_payment_failed";
/// `charge.refunded`: a full or partial refund (ours or the dashboard's)
pub const CHARGE_REFUNDED: &str = "charge.refunded";
/// `charge.refund.updated`: a refund changed, e.g. from `pending` to
/// `succeeded` or `failed` (`data.object` is the Refund)
pub const CHARGE_REFUND_UPDATED: &str = "charge.refund.updated";
/// `charge.dispute.created`: the buyer opened a dispute
pub const CHARGE_DISPUTE_CREATED: &str = "charge.dispute.created";
/// `charge.dispute.closed`: a dispute ended; see `status` on the object
pub const CHARGE_DISPUTE_CLOSED: &str = "charge.dispute.closed";
/// Every `charge.dispute.*` event (created, updated, closed, funds_*). Their
/// payload status is not trusted: the dispute is re-fetched and its current
/// status applied, so out-of-order deliveries converge.
pub const CHARGE_DISPUTE_PREFIX: &str = "charge.dispute.";

/// The parts of a Stripe event the payment engine reads
#[derive(Debug, Clone, PartialEq)]
pub struct StripeEvent {
    /// Event id (`evt_...`), the dedupe key in `payment_events`
    pub id: String,
    /// Event type, e.g. `checkout.session.completed`
    pub event_type: String,
    /// Whether the event came from live mode
    pub livemode: bool,
    /// Creation time, in seconds since the Unix epoch
    pub created: i64,
    /// `data.object`: the resource the event is about (always a JSON object)
    pub object: Value,
}

/// Parse a raw event body (a webhook delivery, after its signature has been
/// verified).
///
/// Required: `id` (a well-formed Stripe id), a non-empty string `type`, a
/// boolean `livemode`, an integer `created` and an object `data.object`.
/// When `object` is present on the envelope it must be `"event"`.
pub fn parse_event(raw: &[u8]) -> Result<StripeEvent, StripeError> {
    let value: Value = serde_json::from_slice(raw)
        .map_err(|_| StripeError::Decode("event body is not valid JSON".to_string()))?;
    event_from_value(&value)
}

/// [`parse_event`] for an already-decoded body (the `GET /v1/events/{id}`
/// response).
pub fn event_from_value(value: &Value) -> Result<StripeEvent, StripeError> {
    if !value.is_object() {
        return Err(decode("event is not a JSON object"));
    }

    if let Some(kind) = value.get("object") {
        if kind.as_str() != Some("event") {
            return Err(decode("not an event object"));
        }
    }

    let id = obj_str(value, "id").ok_or_else(|| decode("event has no id"))?;
    if !is_valid_stripe_id(id) {
        return Err(decode("event id is malformed"));
    }

    let event_type = obj_str(value, "type")
        .filter(|t| !t.is_empty())
        .ok_or_else(|| decode("event has no type"))?;

    let livemode = obj_bool(value, "livemode").ok_or_else(|| decode("event has no livemode"))?;
    let created = obj_i64(value, "created").ok_or_else(|| decode("event has no created time"))?;

    let object = value
        .get("data")
        .and_then(|data| data.get("object"))
        .filter(|object| object.is_object())
        .cloned()
        .ok_or_else(|| decode("event has no data.object"))?;

    Ok(StripeEvent {
        id: id.to_string(),
        event_type: event_type.to_string(),
        livemode,
        created,
        object,
    })
}

/// `o[key]` when it is present and a string; `None` when absent, `null` or
/// any other type.
pub fn obj_str<'a>(o: &'a Value, key: &str) -> Option<&'a str> {
    o.get(key).and_then(Value::as_str)
}

/// `o[key]` when it is present and an integer that fits an `i64`
pub fn obj_i64(o: &Value, key: &str) -> Option<i64> {
    o.get(key).and_then(Value::as_i64)
}

/// `o[key]` when it is present and a boolean
pub fn obj_bool(o: &Value, key: &str) -> Option<bool> {
    o.get(key).and_then(Value::as_bool)
}

/// The id behind an expandable field such as `payment_intent` or `charge`:
/// the string itself, or `id` of the object when the field was expanded.
/// `None` when absent, `null`, empty or of any other shape.
pub fn obj_expandable_id<'a>(o: &'a Value, key: &str) -> Option<&'a str> {
    let id = match o.get(key)? {
        Value::String(id) => id.as_str(),
        expanded @ Value::Object(_) => obj_str(expanded, "id")?,
        _ => return None,
    };
    (!id.is_empty()).then_some(id)
}

/// `o.metadata.order_id`, when it is a non-empty string.
///
/// Checkout sessions carry it from `metadata[order_id]`, payment intents
/// from `payment_intent_data[metadata][order_id]`. Charges and disputes do
/// NOT copy payment-intent metadata, so for those resolve through
/// `payment_intent` instead.
pub fn obj_metadata_order_id(o: &Value) -> Option<String> {
    o.get("metadata")
        .and_then(|metadata| obj_str(metadata, "order_id"))
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

/// A Checkout Session's `customer_details.address.country`, when it is a
/// non-empty string: the billing country the buyer entered. `None` when
/// any level is absent, `null` or of another type.
pub fn obj_billing_country(o: &Value) -> Option<String> {
    o.get("customer_details")
        .and_then(|details| details.get("address"))
        .and_then(|address| obj_str(address, "country"))
        .filter(|country| !country.is_empty())
        .map(str::to_string)
}

fn decode(message: &str) -> StripeError {
    StripeError::Decode(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::client::CheckoutSession;

    /// Trimmed from a real test-mode `checkout.session.completed` delivery
    const SESSION_COMPLETED: &str = r#"{
      "id": "evt_1QAbCdEfGhIjKlMn",
      "object": "event",
      "api_version": "2024-06-20",
      "created": 1729000000,
      "data": {
        "object": {
          "id": "cs_test_a1B2c3D4e5F6",
          "object": "checkout.session",
          "amount_subtotal": 9900,
          "amount_total": 9900,
          "client_reference_id": "01JA0000000000000000000USR",
          "created": 1728999000,
          "currency": "usd",
          "customer_details": {
            "email": "buyer@example.com",
            "name": "Test Buyer",
            "address": {
              "city": "Dublin", "country": "IE", "line1": "1 Main Street", "line2": null,
              "postal_code": "D01 F5P2", "state": null
            }
          },
          "expires_at": 1729001100,
          "livemode": false,
          "metadata": {"order_id": "01JA0000000000000000000ORD"},
          "mode": "payment",
          "payment_intent": "pi_3QAbCdEfGhIjKlMn0",
          "payment_method_types": ["card"],
          "payment_status": "paid",
          "status": "complete",
          "success_url": "https://sloga.gg/cipher/thanks",
          "url": null
        }
      },
      "livemode": false,
      "pending_webhooks": 1,
      "request": {"id": null, "idempotency_key": null},
      "type": "checkout.session.completed"
    }"#;

    const CHARGE_REFUNDED_EVENT: &str = r#"{
      "id": "evt_3QAbCdEfGhIjKlMn1",
      "object": "event",
      "created": 1729100000,
      "data": {
        "object": {
          "id": "ch_3QAbCdEfGhIjKlMn0",
          "object": "charge",
          "amount": 9900,
          "amount_captured": 9900,
          "amount_refunded": 9900,
          "currency": "usd",
          "livemode": false,
          "metadata": {},
          "paid": true,
          "payment_intent": "pi_3QAbCdEfGhIjKlMn0",
          "refunded": true,
          "status": "succeeded"
        },
        "previous_attributes": {"amount_refunded": 0, "refunded": false}
      },
      "livemode": false,
      "pending_webhooks": 1,
      "request": {"id": "req_AbCdEf", "idempotency_key": "void-01JA0000000000000000000ORD"},
      "type": "charge.refunded"
    }"#;

    fn dispute_event(event_type: &str, status: &str) -> String {
        format!(
            r#"{{
              "id": "evt_1QDispute{status}",
              "object": "event",
              "created": 1729200000,
              "data": {{
                "object": {{
                  "id": "du_1QAbCdEfGhIjKlMn",
                  "object": "dispute",
                  "amount": 9900,
                  "charge": "ch_3QAbCdEfGhIjKlMn0",
                  "currency": "usd",
                  "is_charge_refundable": false,
                  "livemode": true,
                  "metadata": {{}},
                  "payment_intent": "pi_3QAbCdEfGhIjKlMn0",
                  "reason": "fraudulent",
                  "status": "{status}"
                }}
              }},
              "livemode": true,
              "pending_webhooks": 1,
              "request": {{"id": null, "idempotency_key": null}},
              "type": "{event_type}"
            }}"#
        )
    }

    #[test]
    fn parses_a_checkout_session_completed_event() {
        let event = parse_event(SESSION_COMPLETED.as_bytes()).unwrap();
        assert_eq!(event.id, "evt_1QAbCdEfGhIjKlMn");
        assert_eq!(event.event_type, CHECKOUT_SESSION_COMPLETED);
        assert!(!event.livemode);
        assert_eq!(event.created, 1729000000);
        assert_eq!(obj_str(&event.object, "id"), Some("cs_test_a1B2c3D4e5F6"));
        assert_eq!(
            obj_expandable_id(&event.object, "payment_intent"),
            Some("pi_3QAbCdEfGhIjKlMn0")
        );
        assert_eq!(
            obj_metadata_order_id(&event.object).as_deref(),
            Some("01JA0000000000000000000ORD")
        );

        // The same object maps onto the client's session struct
        let session = CheckoutSession::from_stripe_json(&event.object).unwrap();
        assert_eq!(session.id, "cs_test_a1B2c3D4e5F6");
        assert_eq!(session.url, None);
        assert_eq!(session.status.as_deref(), Some("complete"));
        assert_eq!(session.payment_status.as_deref(), Some("paid"));
        assert_eq!(
            session.payment_intent.as_deref(),
            Some("pi_3QAbCdEfGhIjKlMn0")
        );
        assert_eq!(session.amount_total, Some(9900));
        assert_eq!(session.currency.as_deref(), Some("usd"));
        assert!(!session.livemode);
        assert_eq!(
            session.client_reference_id.as_deref(),
            Some("01JA0000000000000000000USR")
        );
        assert_eq!(
            session.metadata_order_id.as_deref(),
            Some("01JA0000000000000000000ORD")
        );
        assert_eq!(session.expires_at, Some(1729001100));
        assert_eq!(session.billing_country.as_deref(), Some("IE"));
        assert_eq!(obj_billing_country(&event.object).as_deref(), Some("IE"));
    }

    #[test]
    fn parses_a_charge_refunded_event() {
        let event = parse_event(CHARGE_REFUNDED_EVENT.as_bytes()).unwrap();
        assert_eq!(event.id, "evt_3QAbCdEfGhIjKlMn1");
        assert_eq!(event.event_type, CHARGE_REFUNDED);
        assert_eq!(event.created, 1729100000);
        assert_eq!(obj_str(&event.object, "object"), Some("charge"));
        assert_eq!(
            obj_expandable_id(&event.object, "payment_intent"),
            Some("pi_3QAbCdEfGhIjKlMn0")
        );
        assert_eq!(obj_i64(&event.object, "amount_refunded"), Some(9900));
        assert_eq!(obj_bool(&event.object, "refunded"), Some(true));
        // Charge metadata is empty: resolution has to go through the intent
        assert_eq!(obj_metadata_order_id(&event.object), None);
    }

    #[test]
    fn parses_dispute_created_and_closed_events() {
        let created = dispute_event(CHARGE_DISPUTE_CREATED, "needs_response");
        let event = parse_event(created.as_bytes()).unwrap();
        assert_eq!(event.event_type, CHARGE_DISPUTE_CREATED);
        assert!(event.livemode);
        assert_eq!(obj_str(&event.object, "object"), Some("dispute"));
        assert_eq!(obj_str(&event.object, "status"), Some("needs_response"));
        assert_eq!(
            obj_expandable_id(&event.object, "payment_intent"),
            Some("pi_3QAbCdEfGhIjKlMn0")
        );

        for status in ["won", "lost", "warning_closed"] {
            let closed = dispute_event(CHARGE_DISPUTE_CLOSED, status);
            let event = parse_event(closed.as_bytes()).unwrap();
            assert_eq!(event.event_type, CHARGE_DISPUTE_CLOSED);
            assert_eq!(obj_str(&event.object, "status"), Some(status));
            assert_eq!(
                obj_expandable_id(&event.object, "payment_intent"),
                Some("pi_3QAbCdEfGhIjKlMn0")
            );
        }
    }

    #[test]
    fn expandable_ids_accept_an_expanded_object() {
        let object = serde_json::json!({
            "payment_intent": {"id": "pi_expanded", "object": "payment_intent"},
            "charge": "",
            "other": 5,
            "nothing": null
        });
        assert_eq!(
            obj_expandable_id(&object, "payment_intent"),
            Some("pi_expanded")
        );
        assert_eq!(obj_expandable_id(&object, "charge"), None);
        assert_eq!(obj_expandable_id(&object, "other"), None);
        assert_eq!(obj_expandable_id(&object, "nothing"), None);
        assert_eq!(obj_expandable_id(&object, "absent"), None);
    }

    #[test]
    fn helpers_reject_wrong_types() {
        let object = serde_json::json!({
            "s": "x", "n": 5, "b": true, "null": null,
            "metadata": {"order_id": 7}
        });
        assert_eq!(obj_str(&object, "s"), Some("x"));
        assert_eq!(obj_str(&object, "n"), None);
        assert_eq!(obj_str(&object, "null"), None);
        assert_eq!(obj_str(&object, "absent"), None);
        assert_eq!(obj_i64(&object, "s"), None);
        assert_eq!(obj_bool(&object, "n"), None);
        assert_eq!(obj_metadata_order_id(&object), None);

        let empty = serde_json::json!({"metadata": {"order_id": ""}});
        assert_eq!(obj_metadata_order_id(&empty), None);
        let no_metadata = serde_json::json!({"metadata": null});
        assert_eq!(obj_metadata_order_id(&no_metadata), None);
    }

    fn is_decode(result: Result<StripeEvent, StripeError>) -> bool {
        matches!(result, Err(StripeError::Decode(_)))
    }

    fn mutate(f: impl Fn(&mut serde_json::Map<String, Value>)) -> Result<StripeEvent, StripeError> {
        let mut value: Value = serde_json::from_str(SESSION_COMPLETED).unwrap();
        f(value.as_object_mut().unwrap());
        event_from_value(&value)
    }

    #[test]
    fn rejects_malformed_envelopes() {
        let base: Value = serde_json::from_str(SESSION_COMPLETED).unwrap();
        assert!(event_from_value(&base).is_ok());

        assert!(is_decode(mutate(|m| {
            m.remove("id");
        })));
        assert!(is_decode(mutate(|m| {
            m.insert("id".into(), Value::from("evt_../../x"));
        })));
        assert!(is_decode(mutate(|m| {
            m.insert("id".into(), Value::from(""));
        })));
        assert!(is_decode(mutate(|m| {
            m.insert("type".into(), Value::from(""));
        })));
        assert!(is_decode(mutate(|m| {
            m.remove("type");
        })));
        assert!(is_decode(mutate(|m| {
            m.remove("livemode");
        })));
        assert!(is_decode(mutate(|m| {
            m.insert("livemode".into(), Value::from("false"));
        })));
        assert!(is_decode(mutate(|m| {
            m.remove("created");
        })));
        assert!(is_decode(mutate(|m| {
            m.insert("created".into(), Value::from("1729000000"));
        })));
        assert!(is_decode(mutate(|m| {
            m.insert("object".into(), Value::from("checkout.session"));
        })));
        assert!(is_decode(mutate(|m| {
            m.remove("data");
        })));
        assert!(is_decode(mutate(|m| {
            m.insert("data".into(), serde_json::json!({"object": "cs_test_x"}));
        })));
        assert!(is_decode(mutate(|m| {
            m.insert("data".into(), serde_json::json!({"object": null}));
        })));

        // An envelope without `object` is accepted (older fixtures omit it)
        assert!(mutate(|m| {
            m.remove("object");
        })
        .is_ok());
    }

    #[test]
    fn rejects_bodies_that_are_not_json_objects() {
        assert!(is_decode(parse_event(b"")));
        assert!(is_decode(parse_event(b"not json")));
        assert!(is_decode(parse_event(b"[]")));
        assert!(is_decode(parse_event(b"\"evt_1\"")));
        assert!(is_decode(parse_event(b"null")));
    }

    #[test]
    fn decode_errors_do_not_quote_the_payload() {
        let mut value: Value = serde_json::from_str(SESSION_COMPLETED).unwrap();
        value.as_object_mut().unwrap().remove("type");
        let raw = serde_json::to_vec(&value).unwrap();
        match parse_event(&raw) {
            Err(StripeError::Decode(message)) => {
                assert!(!message.contains("buyer@example.com"));
                assert!(!message.contains("cs_test_a1B2c3D4e5F6"));
            }
            other => panic!("expected a decode error, got {other:?}"),
        }
    }
}
