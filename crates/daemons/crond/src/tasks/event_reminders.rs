use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{
    events::rabbit::{CalendarEventNotification, CalendarEventPayload},
    reminders_due_for_event, Database, ReminderSentKey, RsvpStatus, AMQP, REMINDER_GRACE_MS,
    REMINDER_OFFSETS_MS,
};
use revolt_result::Result;
use tokio::time::sleep;

/// How often the reminder scan runs. The scan tolerates missing a tick up to
/// `REMINDER_GRACE_MS` (design §9), so a minute cadence is comfortably safe.
const REMINDER_TICK: Duration = Duration::from_secs(60);

/// Reminder markers are retained a day past their occurrence, then swept. This is
/// far beyond the grace window in which a reminder could still fire, so a swept
/// marker can never cause a stale re-send.
const RETENTION_MS: i64 = 24 * 60 * 60 * 1000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Per-occurrence event reminders (design §9, finding H3).
///
/// Each tick scans every non-cancelled series whose occurrences could have a
/// reminder due now, expands them (skipping exceptions), and for every `Going`
/// attendee sends one push per `(event, user, occurrence, offset)`. Delivery is
/// driven off the RSVP rows by **user id**, never channel membership, so a `Going`
/// attendee who has since lost `ViewChannel` — and is therefore off the channel WS
/// topic — is still reminded (design §8/§9). Idempotency is mark-then-send: the
/// marker is written first and only a newly-written marker sends, so a crond
/// re-run or reconnect never double-fires.
pub async fn task(db: Database, amqp: AMQP) -> Result<()> {
    loop {
        let now = now_ms();
        // Coarse candidate set: the largest lead offset bounds how far ahead an
        // occurrence may be to have a due trigger; the grace window bounds how far a
        // series may have ended. Precise per-occurrence filtering happens below.
        let max_offset = REMINDER_OFFSETS_MS.iter().copied().max().unwrap_or(0);
        let events = db
            .fetch_events_in_reminder_window(now + max_offset, now - REMINDER_GRACE_MS)
            .await?;

        let mut sent = 0usize;
        for event in events {
            let due = reminders_due_for_event(&event, now);
            if due.is_empty() {
                continue;
            }

            // Only attendees who are currently Going get reminders. Fetch once per event.
            let going: Vec<String> = match db.fetch_rsvps_for_event(&event.id).await {
                Ok(rsvps) => rsvps
                    .into_iter()
                    .filter(|r| matches!(r.status, RsvpStatus::Going))
                    .map(|r| r.id.user)
                    .collect(),
                Err(err) => {
                    revolt_config::capture_error(&err);
                    continue;
                }
            };
            if going.is_empty() {
                continue;
            }

            // Drop attendees who have fully left / been banned from the server. RSVP
            // rows ARE cascaded on member removal (slice F), but only best-effort —
            // this live check is the defense-in-depth for a missed cascade. A member
            // who merely lost `ViewChannel` is still a member and is intentionally
            // still reminded (design §8/§9).
            let mut recipients = Vec::with_capacity(going.len());
            for user in going {
                if db.fetch_member(&event.server, &user).await.is_ok() {
                    recipients.push(user);
                }
            }
            if recipients.is_empty() {
                continue;
            }

            for (occurrence, offset) in due {
                for user in &recipients {
                    let key = ReminderSentKey {
                        event: event.id.clone(),
                        user: user.clone(),
                        occurrence,
                        offset,
                    };
                    match db.mark_reminder_sent_if_absent(&key).await {
                        // Newly marked → send exactly once.
                        Ok(true) => {
                            let payload = CalendarEventPayload {
                                user: user.clone(),
                                event_id: event.id.clone(),
                                server_id: event.server.clone(),
                                title: event.title.clone(),
                                kind: CalendarEventNotification::Reminder,
                                occurrence_start: Some(occurrence),
                            };
                            if let Err(err) = amqp.calendar_event_notify(&payload).await {
                                // At-most-once: the marker stays, so we do not retry.
                                log::error!("failed to enqueue event reminder: {err:?}");
                            } else {
                                sent += 1;
                            }
                        }
                        // Already reminded for this (event, user, occurrence, offset).
                        Ok(false) => {}
                        Err(err) => {
                            revolt_config::capture_error(&err);
                        }
                    }
                }
            }
        }

        if sent > 0 {
            log::info!("Enqueued {sent} event reminders");
        }

        // Retention sweep of long-past markers (bounded storage).
        if let Err(err) = db.delete_reminders_sent_before(now - RETENTION_MS).await {
            revolt_config::capture_error(&err);
        }

        sleep(REMINDER_TICK).await
    }
}
