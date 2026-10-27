//! Hourly sweep that deletes the accounts whose scheduled deletion is due.
//!
//! Each account goes through the payments cascade
//! (`revolt_payments::engine::on_account_deleted`) before `User::delete`
//! anonymises it: open orders are voided (a Paid one refunded), every order
//! is unlinked from the user and the Cipher membership is deleted.
//! `revolt-database` cannot call the payments crate (payments depends on it),
//! so the cascade is hooked here, at the only place an account is deleted.
//!
//! The Stripe half of the cascade (voiding and refunding open orders) is
//! best-effort: deleting an account must not wait on Stripe or on the
//! payments config, and what it leaves behind heals on its own (see
//! `on_account_deleted`): a Paid order that is not voided is voided and
//! refunded by the payments reconcile sweep, because fulfilment voids an
//! order whose buyer is unlinked or deleted.
//!
//! Unlinking the orders and deleting the membership must succeed
//! (`engine::unlink_account_payments`, run even without a payments config):
//! when either fails, the account is NOT deleted this run. It stays due, so
//! the next hourly run tries the whole cascade again; once the account is
//! marked deleted nothing would ever unlink its orders. Any other failed
//! step of one account (reading its user, `User::delete`, marking it
//! deleted) is handled the same way, so it never stops the rest of the run.
//!
//! The Stripe secret key is only handed to the client; it is never logged.

use std::time::Duration;

use std::future::Future;

use revolt_database::{Account, Database};
use revolt_payments::{
    engine,
    settings::PaymentsSettings,
    stripe::{ReqwestStripe, StripeApi},
};
use revolt_result::Result;
use tokio::time::sleep;

/// The payments config and Stripe client the cascade runs with; None skips
/// the cascade
type Payments<'a> = Option<(&'a PaymentsSettings, &'a dyn StripeApi)>;

pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let accounts = db.fetch_accounts_due_for_deletion().await?;
        let count = accounts.len();

        let deleted = if accounts.is_empty() {
            0
        } else {
            let payments = payments_settings().await.map(|s| {
                let stripe = ReqwestStripe::new(s.secret_key.clone());
                (s, stripe)
            });
            let payments = payments
                .as_ref()
                .map(|(s, stripe)| (s, stripe as &dyn StripeApi));

            delete_accounts(&db, payments, accounts).await?
        };

        log::info!("Deleted {deleted} of {count} accounts due for deletion.");

        sleep(Duration::from_hours(1)).await
    }
}

/// The payments config for the cascade
///
/// The cascade runs whether or not payments are enabled: unlinking orders
/// and deleting the membership is data hygiene, and a Paid order is refunded
/// either way. When the config does not validate (only the sale fields can
/// fail: the cap or the close date), the cascade still runs, with the sale
/// fields at their defaults and the configured `[api.stripe]`; no sale field
/// bears on voiding, refunding or unlinking. None only if even that fails.
async fn payments_settings() -> Option<PaymentsSettings> {
    match PaymentsSettings::load().await {
        Ok(settings) => Some(settings),
        Err(err) => {
            // `PaymentsSettings::from_parts` has already logged which field
            // is wrong; the error itself carries no config values
            log::error!(
                "Account deletion: the payments config is invalid ({err:?}); running the \
                 payments cascade with the sale settings at their defaults"
            );
            let config = revolt_config::config().await;
            match PaymentsSettings::for_settlement(&config.api.stripe) {
                Ok(settings) => Some(settings),
                Err(err) => {
                    log::error!(
                        "Account deletion: no usable payments config ({err:?}); the payments \
                         cascade is skipped"
                    );
                    None
                }
            }
        }
    }
}

/// Delete `accounts`: the payments cascade first, then the user, then the
/// account. The number deleted (see [`delete_accounts_with`])
async fn delete_accounts(
    db: &Database,
    payments: Payments<'_>,
    accounts: Vec<Account>,
) -> Result<usize> {
    delete_accounts_with(db, accounts, |user_id| async move {
        payments_cascade(db, payments, &user_id).await
    })
    .await
}

/// [`delete_accounts`] with the payments cascade passed in (tests inject a
/// failing one). The number of accounts deleted.
///
/// Each account is isolated: when any of its steps fails (reading the user,
/// the cascade, `User::delete`, marking the account deleted), the failure is
/// logged and reported with the account id only, the account is skipped, not
/// marked deleted, and stays due, so the next run tries it again from the
/// start; the accounts after it still go ahead. One account that cannot be
/// deleted (for example one whose protected-channel seat release fails on an
/// undecodable seat row, design 6.3) must not hold up every deletion queued
/// behind it. Every step is safe to run again on that retry.
async fn delete_accounts_with<F, Fut>(
    db: &Database,
    accounts: Vec<Account>,
    cascade: F,
) -> Result<usize>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let mut deleted = 0;

    for mut account in accounts {
        let mut user = match db.fetch_user(&account.id).await {
            Ok(user) => user,
            Err(err) => {
                skip_account(&account.id, "its user could not be read", &err);
                continue;
            }
        };

        // Before `User::delete`: the open orders are still linked to the
        // user, so they can be found, voided and refunded
        if let Err(err) = cascade(user.id.clone()).await {
            log::error!(
                "Account deletion of {}: its payment orders could not be unlinked or its \
                 membership deleted; not deleting the account this run, retrying next run: \
                 {err:?}",
                user.id
            );
            report_skip(
                &account.id,
                "its payment orders could not be unlinked or its membership deleted",
                &err,
            );
            continue;
        }

        // A failure part way through can leave the user partly deleted (its
        // bots and owned servers gone, say); the retry runs it again
        if let Err(err) = user.delete(db).await {
            skip_account(&account.id, "deleting its user failed", &err);
            continue;
        }

        if let Err(err) = account.mark_deleted(db).await {
            skip_account(
                &account.id,
                "its user was deleted but the account could not be marked deleted",
                &err,
            );
            continue;
        }

        deleted += 1;
    }

    Ok(deleted)
}

/// Log and report (account id only, never account content) that the
/// deletion of `account_id` failed at `step` and is retried next run
fn skip_account(account_id: &str, step: &str, err: &revolt_result::Error) {
    log::error!(
        "Account deletion of {account_id}: {step}; not marking the account deleted this run, \
         retrying next run: {err:?}"
    );
    report_skip(account_id, step, err);
}

/// Report to Sentry that the deletion of `account_id` was skipped at
/// `step`. The event carries the account id (audit C11: the error alone
/// does not say which account to look at) and the error, and nothing else
/// of the account. crond has no Sentry scope API of its own, so the id goes
/// in the message; one account failing hourly reports once an hour.
fn report_skip(account_id: &str, step: &str, err: &revolt_result::Error) {
    revolt_config::capture_message(
        &skip_report(account_id, step, err),
        revolt_config::Level::Error,
    );
}

/// The Sentry message of [`report_skip`]
fn skip_report(account_id: &str, step: &str, err: &revolt_result::Error) -> String {
    format!("Account deletion of {account_id} skipped, retried next run: {step}: {err:?}")
}

/// The payments cascade for `user_id`. The voids are best-effort (logged by
/// the engine); Err only when unlinking the orders or deleting the
/// membership failed, which must stop the deletion. Without a usable
/// payments config only that unlink part runs.
async fn payments_cascade(db: &Database, payments: Payments<'_>, user_id: &str) -> Result<()> {
    let Some((settings, stripe)) = payments else {
        log::error!(
            "Account deletion of {user_id}: no usable payments config, so its open orders are \
             not voided now (the reconcile sweep refunds a Paid one); unlinking them"
        );
        return engine::unlink_account_payments(db, user_id).await;
    };

    let now_ms = revolt_database::now_ms();
    engine::on_account_deleted(db, stripe, settings, user_id, now_ms).await
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;
    use revolt_config::{ApiStripe, FeaturePayments};
    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{
        DatabaseInfo, DeletionInfo, EmailVerification, OrderState, PaymentOrder, User, VoidReason,
    };
    use revolt_models::v0::{CipherReturnTo, CipherTier, UserFlags};
    use revolt_payments::{
        catalog::CIPHER_CAP_MAX,
        dispatch,
        engine::{FulfilOutcome, LEASE_MS},
        stripe::{CheckoutSession, MockStripe, StripeError},
    };
    use revolt_result::create_error;

    use super::*;

    async fn reference_db() -> Database {
        let db = DatabaseInfo::Reference.connect().await.expect("database");
        db.seed_cipher_numbers(CIPHER_CAP_MAX).await.unwrap();
        db
    }

    fn settings() -> PaymentsSettings {
        let payments = FeaturePayments {
            enabled: true,
            cipher_sales_open: true,
            ..FeaturePayments::default()
        };
        PaymentsSettings::from_parts(&payments, &ApiStripe::default()).unwrap()
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_user(db: &Database, id: &str) {
        db.insert_user(&User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    /// An account whose deletion is due now
    async fn schedule_deletion(db: &Database, id: &str) {
        db.save_account(&Account {
            id: id.to_string(),
            email: format!("{id}@example.com"),
            email_normalised: format!("{id}@example.com"),
            password: String::new(),
            disabled: true,
            verification: EmailVerification::Verified,
            password_reset: None,
            deletion: Some(DeletionInfo::Scheduled {
                after: Timestamp::now_utc(),
            }),
            lockout: None,
            mfa: Default::default(),
            google_id: None,
            apple_id: None,
        })
        .await
        .unwrap();
    }

    /// The sweep body over the accounts that are due, with `stripe`
    async fn sweep(db: &Database, stripe: &MockStripe, s: &PaymentsSettings) {
        let accounts = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(accounts.len(), 1, "one account is due for deletion");
        delete_accounts(db, Some((s, stripe as &dyn StripeApi)), accounts)
            .await
            .unwrap();
    }

    /// Start a checkout; the Pending order it created
    async fn checkout(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        user: &str,
        tier: CipherTier,
    ) -> PaymentOrder {
        let url = engine::create_cipher_checkout(
            db,
            stripe,
            s,
            user,
            tier,
            CipherReturnTo::Web,
            revolt_database::now_ms(),
        )
        .await
        .unwrap();
        db.fetch_payment_orders_by_user(user, &[OrderState::Pending])
            .await
            .unwrap()
            .into_iter()
            .find(|o| o.checkout_url.as_deref() == Some(url.as_str()))
            .expect("the checkout's Pending order")
    }

    /// The buyer pays the order's session with `payment_intent`
    fn pay(stripe: &MockStripe, order: &PaymentOrder, payment_intent: &str) -> CheckoutSession {
        let id = order.checkout_session_id.clone().expect("session id");
        let mut session = stripe.session(&id).expect("session at Stripe");
        session.status = Some("complete".to_string());
        session.payment_status = Some("paid".to_string());
        session.payment_intent = Some(payment_intent.to_string());
        stripe.set_session(session.clone());
        session
    }

    async fn order(db: &Database, id: &str) -> PaymentOrder {
        db.fetch_payment_order(id).await.unwrap().unwrap()
    }

    /// Checkout, pay and fulfil; the Fulfilled order
    async fn buy(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        user: &str,
        payment_intent: &str,
    ) -> PaymentOrder {
        let pending = checkout(db, stripe, s, user, CipherTier::T99).await;
        let session = pay(stripe, &pending, payment_intent);
        let now = revolt_database::now_ms();
        assert_eq!(
            engine::fulfil_order(db, stripe, s, &pending.id, &session, now)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        let fulfilled = order(db, &pending.id).await;
        assert_eq!(fulfilled.state, OrderState::Fulfilled);
        fulfilled
    }

    /// Checkout and pay; a fulfilment recorded the payment and died before
    /// applying it (its lease released). The Paid order.
    async fn stranded_paid(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        user: &str,
        payment_intent: &str,
    ) -> PaymentOrder {
        let pending = checkout(db, stripe, s, user, CipherTier::T99).await;
        pay(stripe, &pending, payment_intent);

        let now = revolt_database::now_ms();
        let until = now + LEASE_MS;
        let mut leased = db
            .acquire_payment_order_lease(&pending.id, now, until)
            .await
            .unwrap()
            .expect("lease");
        leased.state = OrderState::Paid;
        leased.payment_intent_id = Some(payment_intent.to_string());
        assert!(db
            .update_payment_order_if_state(&leased, OrderState::Pending)
            .await
            .unwrap());
        db.release_payment_order_lease(&pending.id, until)
            .await
            .unwrap();

        let stored = order(db, &pending.id).await;
        assert_eq!(stored.state, OrderState::Paid);
        assert_eq!(stored.lease_until, None);
        stored
    }

    /// `(payment intent, idempotency key)` of every refund call
    fn refund_calls(stripe: &MockStripe) -> Vec<(String, Option<String>)> {
        stripe
            .calls()
            .into_iter()
            .filter(|(method, _, _)| method == "create_refund")
            .map(|(_, payment_intent, key)| (payment_intent, key))
            .collect()
    }

    /// The user is anonymised (no public badge) and the account is marked
    /// deleted
    async fn assert_deleted(db: &Database, id: &str) {
        let user = db.fetch_user(id).await.unwrap();
        assert_ne!(
            user.flags.unwrap_or_default() & UserFlags::Deleted as i32,
            0,
            "the user is flagged deleted"
        );
        assert_eq!(user.cipher, None, "a deleted account has no public badge");

        let account = db.fetch_account(id).await.unwrap();
        assert_eq!(account.deletion, Some(DeletionInfo::Deleted));
    }

    #[tokio::test]
    async fn a_member_loses_the_membership_and_their_orders_are_unlinked() {
        let db = reference_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let first = buy(&db, &stripe, &s, "u1", "pi_1").await;
        let other = buy(&db, &stripe, &s, "u2", "pi_2").await;
        assert!(db.fetch_user("u1").await.unwrap().cipher.is_some());
        schedule_deletion(&db, "u1").await;

        sweep(&db, &stripe, &s).await;

        assert_deleted(&db, "u1").await;
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());

        // The payment record stays, unlinked and not refunded
        let kept = order(&db, &first.id).await;
        assert_eq!(kept.state, OrderState::Fulfilled);
        assert_eq!(kept.user_id, None);
        assert!(refund_calls(&stripe).is_empty());

        // Only the deleted account's rows are touched
        let other_member = db
            .fetch_cipher_membership("u2")
            .await
            .unwrap()
            .expect("u2 keeps the membership");
        assert_eq!(other_member.orders, vec![other.id.clone()]);
        assert_eq!(order(&db, &other.id).await.user_id.as_deref(), Some("u2"));
        assert!(db.fetch_user("u2").await.unwrap().cipher.is_some());
    }

    #[tokio::test]
    async fn a_paid_order_is_voided_and_refunded_under_the_void_key() {
        let db = reference_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let paid = stranded_paid(&db, &stripe, &s, "u1", "pi_paid").await;
        let open = checkout(&db, &stripe, &s, "u1", CipherTier::T149).await;
        schedule_deletion(&db, "u1").await;

        sweep(&db, &stripe, &s).await;

        assert_deleted(&db, "u1").await;

        let voided = order(&db, &paid.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::AccountDeleted));
        assert_eq!(voided.user_id, None);
        assert_eq!(
            refund_calls(&stripe),
            vec![("pi_paid".to_string(), Some(format!("void-{}", paid.id)))]
        );
        assert_eq!(stripe.refund_count_for("pi_paid"), 1);

        // The open checkout is voided too, and not refunded (nothing was paid)
        let closed = order(&db, &open.id).await;
        assert_eq!(closed.state, OrderState::Voided);
        assert_eq!(closed.void_reason, Some(VoidReason::AccountDeleted));
        assert_eq!(closed.user_id, None);
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_failed_refund_does_not_block_the_deletion_and_reconcile_refunds_later() {
        let db = reference_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let paid = stranded_paid(&db, &stripe, &s, "u1", "pi_paid").await;
        schedule_deletion(&db, "u1").await;

        // Stripe is down during the deletion
        stripe.fail_next(
            "create_refund",
            StripeError::Transport("connection refused".to_string()),
        );
        sweep(&db, &stripe, &s).await;

        assert_deleted(&db, "u1").await;
        let stranded = order(&db, &paid.id).await;
        assert_eq!(stranded.state, OrderState::Paid, "the void did not happen");
        assert_eq!(stranded.user_id, None, "but the order is unlinked");
        assert_eq!(stripe.refund_count_for("pi_paid"), 0);

        // The reconcile sweep picks the unlinked Paid order up and refunds it
        dispatch::reconcile(&db, &stripe, &s, revolt_database::now_ms() + 1)
            .await
            .unwrap();

        let voided = order(&db, &paid.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::AccountDeleted));
        assert_eq!(stripe.refund_count_for("pi_paid"), 1);
        assert_eq!(
            refund_calls(&stripe).last(),
            Some(&("pi_paid".to_string(), Some(format!("void-{}", paid.id))))
        );
    }

    #[tokio::test]
    async fn the_deletion_goes_ahead_without_a_payments_config() {
        let db = reference_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let member = buy(&db, &stripe, &s, "u1", "pi_member").await;
        schedule_deletion(&db, "u1").await;

        let accounts = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(accounts.len(), 1);
        delete_accounts(&db, None, accounts).await.unwrap();

        assert_deleted(&db, "u1").await;
        // The unlink half still ran: no Stripe call is needed for it
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        assert_eq!(order(&db, &member.id).await.user_id, None);
    }

    /// A failed unlink (or membership delete) stops the deletion of that
    /// account only: it is not anonymised or marked deleted, stays due,
    /// and the next run deletes it
    #[tokio::test]
    async fn a_failed_unlink_keeps_the_account_for_the_next_run() {
        let db = reference_db().await;
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        schedule_deletion(&db, "u1").await;
        schedule_deletion(&db, "u2").await;

        // The database refuses u1's unlink this run
        let accounts = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(accounts.len(), 2);
        delete_accounts_with(&db, accounts, |user_id| async move {
            if user_id == "u1" {
                Err(create_error!(InternalError))
            } else {
                Ok(())
            }
        })
        .await
        .unwrap();

        // u2 went ahead; u1 did not
        assert_deleted(&db, "u2").await;
        let kept = db.fetch_user("u1").await.unwrap();
        assert_eq!(
            kept.flags.unwrap_or_default() & UserFlags::Deleted as i32,
            0,
            "u1 is not anonymised"
        );
        assert!(matches!(
            db.fetch_account("u1").await.unwrap().deletion,
            Some(DeletionInfo::Scheduled { .. })
        ));
        let due = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(
            due.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["u1"],
            "u1 is still due"
        );

        // Next run: the cascade succeeds and the account is deleted
        delete_accounts_with(&db, due, |_| async { Ok(()) })
            .await
            .unwrap();
        assert_deleted(&db, "u1").await;
    }

    /// A fresh database on the driver `TEST_DB` names (it must be set:
    /// `DatabaseInfo::Test` panics without it rather than reach the
    /// configured database), in the harness name shape the guard drops when
    /// the test ends, panics included
    async fn test_db() -> (Database, TestDatabaseGuard) {
        let suffix = 1_000_000 + (ulid::Ulid::new().random() % 9_000_000);
        let db = DatabaseInfo::Test(format!("revolt_test_{suffix}"))
            .connect()
            .await
            .expect("test database");
        let guard = TestDatabaseGuard::arm(&db).await;
        (db, guard)
    }

    /// The accounts due for deletion, in the order of `ids` (the failing
    /// account first, so a run that stops at it never reaches the others)
    async fn due_in_order(db: &Database, ids: &[&str]) -> Vec<Account> {
        let mut due = db.fetch_accounts_due_for_deletion().await.unwrap();
        due.sort_by_key(|account| ids.iter().position(|id| *id == account.id));
        assert_eq!(
            due.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ids,
            "the accounts due for deletion"
        );
        due
    }

    /// The account `id` was not marked deleted and is still due
    async fn assert_still_due(db: &Database, id: &str) {
        assert!(
            matches!(
                db.fetch_account(id).await.unwrap().deletion,
                Some(DeletionInfo::Scheduled { .. })
            ),
            "{id} is still scheduled for deletion"
        );
        let due = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert!(due.iter().any(|a| a.id == id), "{id} is still due");
    }

    async fn assert_not_anonymised(db: &Database, id: &str) {
        let user = db.fetch_user(id).await.unwrap();
        assert_eq!(
            user.flags.unwrap_or_default() & UserFlags::Deleted as i32,
            0,
            "{id} is not anonymised"
        );
    }

    /// An account whose user cannot be read (here it has none) is skipped
    /// and stays due; the account after it is still deleted, and the next
    /// run deletes the skipped one once its user can be read. Both drivers.
    #[tokio::test]
    async fn an_unreadable_user_does_not_block_the_next_account() {
        let (db, _guard) = test_db().await;
        schedule_deletion(&db, "u1").await;
        insert_user(&db, "u2").await;
        schedule_deletion(&db, "u2").await;

        let due = due_in_order(&db, &["u1", "u2"]).await;
        let deleted = delete_accounts_with(&db, due, |_| async { Ok(()) }).await;

        assert_deleted(&db, "u2").await;
        assert_eq!(deleted.unwrap(), 1, "only u2 was deleted");
        assert_still_due(&db, "u1").await;

        insert_user(&db, "u1").await;
        let due = due_in_order(&db, &["u1"]).await;
        let deleted = delete_accounts_with(&db, due, |_| async { Ok(()) }).await;
        assert_eq!(deleted.unwrap(), 1);
        assert_deleted(&db, "u1").await;
    }

    /// `User::delete` fails for one account: an undecodable `channel_seats`
    /// row of that user makes its protected-channel seat release fail
    /// (design 6.3). That account is skipped, not anonymised, and stays due;
    /// the account after it is still deleted. The next run retries it (and
    /// fails again while the row is corrupt); once the row is repaired, the
    /// next run deletes it. Mongo only: the Reference driver cannot hold an
    /// undecodable row, so there the test returns early.
    #[tokio::test]
    async fn a_failed_seat_release_does_not_block_the_next_account() {
        use revolt_database::mongodb::bson::{doc, Document};
        use revolt_result::ErrorType;

        let (db, _guard) = test_db().await;
        let Database::MongoDb(mongo) = &db else {
            eprintln!(
                "NOTE a_failed_seat_release_does_not_block_the_next_account: Mongo only, \
                 skipped under TEST_DB=REFERENCE"
            );
            return;
        };
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        schedule_deletion(&db, "u1").await;
        schedule_deletion(&db, "u2").await;

        // An Int32 `channel_id` cannot decode into `ChannelSeat`, and the
        // row matches the unscoped release's `{user_id, released_at: null}`
        let seats = mongo.col::<Document>("channel_seats");
        seats
            .insert_one(doc! {
                "_id": "corrupt",
                "channel_id": 5_i32,
                "user_id": "u1",
                "seated_at": 0_i64,
            })
            .await
            .expect("insert the undecodable seat row");
        let err = db
            .release_channel_seats_for_user("u1", None, Timestamp::now_utc())
            .await
            .expect_err("u1's seat release fails");
        assert!(
            matches!(
                &err.error_type,
                ErrorType::DatabaseError { collection, .. } if collection == "channel_seats"
            ),
            "{err:?}"
        );

        let due = due_in_order(&db, &["u1", "u2"]).await;
        let deleted = delete_accounts_with(&db, due, |_| async { Ok(()) }).await;

        assert_deleted(&db, "u2").await;
        assert_eq!(deleted.unwrap(), 1, "only u2 was deleted");
        assert_not_anonymised(&db, "u1").await;
        assert_still_due(&db, "u1").await;

        // Retried next run; the row is still corrupt, so it is kept again
        let due = due_in_order(&db, &["u1"]).await;
        let deleted = delete_accounts_with(&db, due, |_| async { Ok(()) }).await;
        assert_eq!(deleted.unwrap(), 0);
        assert_not_anonymised(&db, "u1").await;
        assert_still_due(&db, "u1").await;

        // The operator repair (design 6.3): delete the corrupt row
        seats
            .delete_one(doc! { "_id": "corrupt" })
            .await
            .expect("delete the corrupt seat row");
        let due = due_in_order(&db, &["u1"]).await;
        let deleted = delete_accounts_with(&db, due, |_| async { Ok(()) }).await;
        assert_eq!(deleted.unwrap(), 1);
        assert_deleted(&db, "u1").await;
    }

    /// Marking one account deleted fails after its user was deleted
    /// (injected: a unique `email_normalised` index, as production has, and
    /// another account already holding the `Deleted User <id>` address
    /// `Account::mark_deleted` writes). That account stays due and the
    /// account after it is still deleted; the next run runs the whole
    /// deletion again, `User::delete` included, and marks it deleted. Mongo
    /// only: a Reference save never fails, so there the test returns early.
    #[tokio::test]
    async fn a_failed_mark_deleted_does_not_block_the_next_account() {
        use revolt_database::mongodb::{
            bson::{doc, Document},
            options::IndexOptions,
            IndexModel,
        };

        let (db, _guard) = test_db().await;
        let Database::MongoDb(mongo) = &db else {
            eprintln!(
                "NOTE a_failed_mark_deleted_does_not_block_the_next_account: Mongo only, \
                 skipped under TEST_DB=REFERENCE"
            );
            return;
        };
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        schedule_deletion(&db, "u1").await;
        schedule_deletion(&db, "u2").await;

        let accounts = mongo.col::<Document>("accounts");
        accounts
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "email_normalised": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await
            .expect("unique email_normalised index");
        accounts
            .insert_one(doc! { "_id": "decoy", "email_normalised": "Deleted User u1" })
            .await
            .expect("insert the decoy account");

        let due = due_in_order(&db, &["u1", "u2"]).await;
        let deleted = delete_accounts_with(&db, due, |_| async { Ok(()) }).await;

        assert_deleted(&db, "u2").await;
        assert_eq!(deleted.unwrap(), 1, "only u2 was deleted");
        assert_still_due(&db, "u1").await;

        accounts
            .delete_one(doc! { "_id": "decoy" })
            .await
            .expect("delete the decoy account");
        let due = due_in_order(&db, &["u1"]).await;
        let deleted = delete_accounts_with(&db, due, |_| async { Ok(()) }).await;
        assert_eq!(deleted.unwrap(), 1);
        assert_deleted(&db, "u1").await;
    }

    /// Audit C11: the Sentry report of a skipped account names the account
    /// (the error alone does not) and the step, and carries the error.
    /// Both skip paths (the payments cascade and `skip_account`) report
    /// through `report_skip`. Mutation: the id dropped from the message.
    #[test]
    fn a_skipped_account_is_reported_with_its_id() {
        let err = create_error!(InternalError);
        let report = skip_report("01ACCOUNTID", "deleting its user failed", &err);
        for needle in ["01ACCOUNTID", "deleting its user failed", "InternalError"] {
            assert!(
                report.contains(needle),
                "the report must carry `{needle}`: {report}"
            );
        }

        const SOURCE: &str = include_str!("delete_accounts.rs");
        let shipping = &SOURCE[..SOURCE.find("#[cfg(test)]").expect("the tests")];
        assert_eq!(
            shipping.matches("report_skip(").count(),
            3,
            "the cascade branch and `skip_account` report through `report_skip` \
             (plus its definition): {shipping}"
        );
        assert!(
            !shipping.contains("capture_error("),
            "no skip may be reported without the account id"
        );
    }
}
