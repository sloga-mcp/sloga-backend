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
//! marked deleted nothing would ever unlink its orders.
//!
//! The Prot wallet is forfeited after `User::delete`
//! (`engine::prot::forfeit_wallet_on_deletion`, whatever the Prot flags
//! say): the delete cascade (the owner's servers among it) runs first, so
//! anything it pays back into the wallet is forfeited with the rest, and the
//! user is already flagged deleted, so a credit that lands after the forfeit
//! is forfeited by the engine's second pass (`forfeit:{user_id}:{n}`). The
//! forfeit must succeed too: when it fails the account is not marked deleted
//! and stays due, and the next run repeats the cascade and the forfeit.
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

        if !accounts.is_empty() {
            let payments = payments_settings().await.map(|s| {
                let stripe = ReqwestStripe::new(s.secret_key.clone());
                (s, stripe)
            });
            let payments = payments
                .as_ref()
                .map(|(s, stripe)| (s, stripe as &dyn StripeApi));

            delete_accounts(&db, payments, accounts).await?;
        }

        log::info!("Deleted {count} accounts.");

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
/// account
async fn delete_accounts(
    db: &Database,
    payments: Payments<'_>,
    accounts: Vec<Account>,
) -> Result<()> {
    delete_accounts_with(db, accounts, |user_id| async move {
        payments_cascade(db, payments, &user_id).await
    })
    .await
}

/// [`delete_accounts`] with the payments cascade passed in (tests inject a
/// failing one). An account whose cascade fails is skipped, not deleted:
/// it stays due and the next run tries again. So is one whose Prot wallet
/// could not be forfeited (after `User::delete`, so that run has already
/// anonymised the user).
async fn delete_accounts_with<F, Fut>(
    db: &Database,
    accounts: Vec<Account>,
    cascade: F,
) -> Result<()>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    for mut account in accounts {
        let mut user = db.fetch_user(&account.id).await?;

        // Before `User::delete`: the open orders are still linked to the
        // user, so they can be found, voided and refunded
        if let Err(err) = cascade(user.id.clone()).await {
            log::error!(
                "Account deletion of {}: its payment orders could not be unlinked or its \
                 membership deleted; not deleting the account this run, retrying next run: \
                 {err:?}",
                user.id
            );
            revolt_config::capture_error(&err);
            continue;
        }

        user.delete(db).await?;
        // Prot (D11): the wallet is forfeited AFTER the delete cascade (S5b: settlements and
        // goal cancellations pay the owner's own share into the wallet first). Must succeed: on
        // failure the account stays due and the next run repeats the cascade (as a failed
        // mark_deleted does today).
        if let Err(err) =
            engine::prot::forfeit_wallet_on_deletion(db, &user.id, revolt_database::now_ms()).await
        {
            log::error!(
                "Account deletion of {}: its Prot wallet could not be forfeited; retrying next \
                 run: {err:?}",
                user.id
            );
            revolt_config::capture_error(&err);
            continue;
        }
        account.mark_deleted(db).await?;
    }

    Ok(())
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

    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{
        prot_key_admin, prot_key_forfeit, prot_key_purchase, prot_user_account, ProtAmount,
        ProtPosting, ProtRef, Server, PROT_ACTOR_DELETION, PROT_ACTOR_PAYMENTS, PROT_SYS_ADJUST,
        PROT_SYS_FORFEITED, PROT_SYS_ISSUED,
    };
    use revolt_models::v0::{DataCreateServer, ProtEntryKind};

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

    /// A fresh test database on the driver `TEST_DB` names (which must be
    /// set: `DatabaseInfo::Test` panics without it rather than reach the
    /// configured database). Migrated, so MongoDB has the Prot indexes (the
    /// ledger's unique key among them). The guard drops it when the test
    /// ends, panics included.
    async fn test_db() -> (Database, TestDatabaseGuard) {
        let suffix = 1_000_000 + (ulid::Ulid::new().random() % 9_000_000);
        let db = DatabaseInfo::Test(format!("revolt_test_{suffix}"))
            .connect()
            .await
            .expect("test database");
        let guard = TestDatabaseGuard::arm(&db).await;
        db.migrate_database().await.expect("schema");
        (db, guard)
    }

    /// Credit `amount` Prot to `user`'s wallet under `key`, as a purchase
    async fn credit_prot(db: &Database, user: &str, key: &str, amount: i64) {
        db.apply_prot_posting(&ProtPosting {
            key: key.to_string(),
            kind: ProtEntryKind::Purchase,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account(user),
            amount: ProtAmount::Exact(amount),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef::default(),
            reason: None,
            created_at: revolt_database::now_ms(),
        })
        .await
        .unwrap();
    }

    /// Support takes `amount` Prot out of `user`'s wallet by hand
    async fn debit_by_admin(db: &Database, user: &str, nonce: &str, amount: i64) {
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_admin("01ADMIN0000000000000000000", nonce),
            kind: ProtEntryKind::AdminAdjust,
            debit: prot_user_account(user),
            credit: PROT_SYS_ADJUST.to_string(),
            amount: ProtAmount::Exact(amount),
            debit_floor: 0,
            actor: "01ADMIN0000000000000000000".to_string(),
            reference: ProtRef::default(),
            reason: Some("settled by hand".to_string()),
            created_at: revolt_database::now_ms(),
        })
        .await
        .unwrap();
    }

    /// `user`'s wallet balance (0 without a wallet)
    async fn wallet(db: &Database, user: &str) -> i64 {
        db.fetch_prot_account(&prot_user_account(user))
            .await
            .unwrap()
            .map_or(0, |account| account.balance)
    }

    /// How many forfeit rows debit `user`'s wallet
    async fn forfeit_rows(db: &Database, user: &str) -> usize {
        db.fetch_prot_entries_by_account(&prot_user_account(user), None, 100)
            .await
            .unwrap()
            .into_iter()
            .filter(|row| row.kind == ProtEntryKind::Forfeit)
            .count()
    }

    /// Forfeit pass `n` of `user`'s wallet moved `amount` to sys:forfeited
    async fn assert_forfeited(db: &Database, user: &str, n: u64, amount: i64) {
        let row = db
            .fetch_prot_entry_by_key(&prot_key_forfeit(user, n))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("forfeit pass {n} of {user}"));
        assert_eq!(row.kind, ProtEntryKind::Forfeit);
        assert_eq!(row.debit, prot_user_account(user));
        assert_eq!(row.credit, PROT_SYS_FORFEITED);
        assert_eq!(row.amount, amount);
        assert_eq!(row.actor, PROT_ACTOR_DELETION);
    }

    /// An owner holding Prot: the delete cascade removes their server, then
    /// the whole wallet is forfeited in one pass. The forfeit runs without a
    /// payments config too, and another user's wallet is not touched.
    #[tokio::test]
    async fn an_owner_holding_prot_loses_their_server_and_forfeits_the_wallet() {
        let (db, _teardown) = test_db().await;
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        let owner = db.fetch_user("u1").await.unwrap();
        let (server, _) = Server::create(
            &db,
            DataCreateServer {
                name: "Owned".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            true,
        )
        .await
        .unwrap();
        credit_prot(&db, "u1", &prot_key_purchase("01ORDERU1"), 1_250).await;
        credit_prot(&db, "u2", &prot_key_purchase("01ORDERU2"), 300).await;
        schedule_deletion(&db, "u1").await;

        let accounts = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(accounts.len(), 1);
        delete_accounts(&db, None, accounts).await.unwrap();

        assert_deleted(&db, "u1").await;
        assert!(
            db.fetch_server(&server.id).await.is_err(),
            "the owned server is deleted"
        );
        assert_forfeited(&db, "u1", 1, 1_250).await;
        assert_eq!(forfeit_rows(&db, "u1").await, 1);
        assert_eq!(wallet(&db, "u1").await, 0);

        // Only the deleted account's wallet moves
        assert_eq!(wallet(&db, "u2").await, 300);
        assert_eq!(forfeit_rows(&db, "u2").await, 0);
    }

    /// A forfeit that fails stops the deletion of that account only. The
    /// cascade has already run (the user is anonymised), but the account is
    /// not marked deleted and stays due; the next run repeats the cascade on
    /// the anonymised user and, once the forfeit goes through, deletes it.
    #[tokio::test]
    async fn a_failed_forfeit_keeps_the_account_due_for_the_next_run() {
        let (db, _teardown) = test_db().await;
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        // A row with another payload already holds u1's first forfeit key, so
        // its forfeit pass is refused (ProtIdempotencyConflict) on any run
        credit_prot(&db, "u1", &prot_key_forfeit("u1", 1), 500).await;
        credit_prot(&db, "u2", &prot_key_purchase("01ORDERU2"), 200).await;
        schedule_deletion(&db, "u1").await;
        schedule_deletion(&db, "u2").await;

        let accounts = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(accounts.len(), 2);
        delete_accounts_with(&db, accounts, |_| async { Ok(()) })
            .await
            .unwrap();

        // u2 went ahead
        assert_deleted(&db, "u2").await;
        assert_forfeited(&db, "u2", 1, 200).await;
        assert_eq!(wallet(&db, "u2").await, 0);

        // u1 is anonymised but not marked deleted, and keeps its Prot
        let kept = db.fetch_user("u1").await.unwrap();
        assert_ne!(
            kept.flags.unwrap_or_default() & UserFlags::Deleted as i32,
            0,
            "the delete cascade ran before the forfeit"
        );
        assert!(matches!(
            db.fetch_account("u1").await.unwrap().deletion,
            Some(DeletionInfo::Scheduled { .. })
        ));
        assert_eq!(wallet(&db, "u1").await, 500);
        assert_eq!(forfeit_rows(&db, "u1").await, 0);
        let due = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(
            due.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["u1"],
            "u1 is still due"
        );

        // Support empties the wallet by hand; the next run has nothing to
        // forfeit and deletes the account
        debit_by_admin(&db, "u1", "settle", 500).await;
        delete_accounts_with(&db, due, |_| async { Ok(()) })
            .await
            .unwrap();
        assert_deleted(&db, "u1").await;
        assert_eq!(wallet(&db, "u1").await, 0);
        assert_eq!(forfeit_rows(&db, "u1").await, 0);
        assert!(db
            .fetch_accounts_due_for_deletion()
            .await
            .unwrap()
            .is_empty());
    }

    /// Prot credited to a wallet after an earlier forfeit pass (a run that
    /// forfeited it and then failed to mark the account deleted), while the
    /// account is still due: the next run forfeits it under the next key
    #[tokio::test]
    async fn prot_credited_after_an_earlier_forfeit_pass_is_forfeited_under_the_next_key() {
        let (db, _teardown) = test_db().await;
        insert_user(&db, "u1").await;
        schedule_deletion(&db, "u1").await;
        credit_prot(&db, "u1", &prot_key_purchase("01ORDERA"), 400).await;
        let first = db
            .forfeit_prot_wallet("u1", revolt_database::now_ms())
            .await
            .unwrap()
            .expect("the first pass");
        assert_eq!(first.entry().key, prot_key_forfeit("u1", 1));
        credit_prot(&db, "u1", &prot_key_purchase("01ORDERB"), 150).await;

        let accounts = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(accounts.len(), 1);
        delete_accounts_with(&db, accounts, |_| async { Ok(()) })
            .await
            .unwrap();

        assert_deleted(&db, "u1").await;
        assert_forfeited(&db, "u1", 1, 400).await;
        assert_forfeited(&db, "u1", 2, 150).await;
        assert_eq!(forfeit_rows(&db, "u1").await, 2);
        assert_eq!(wallet(&db, "u1").await, 0);
    }

    /// No wallet, or an emptied one: nothing is written to the ledger and the
    /// deletion goes ahead
    #[tokio::test]
    async fn an_account_without_prot_is_deleted_without_a_ledger_row() {
        let (db, _teardown) = test_db().await;
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        credit_prot(&db, "u2", &prot_key_purchase("01ORDERU2"), 100).await;
        debit_by_admin(&db, "u2", "empty", 100).await;
        schedule_deletion(&db, "u1").await;
        schedule_deletion(&db, "u2").await;

        let accounts = db.fetch_accounts_due_for_deletion().await.unwrap();
        assert_eq!(accounts.len(), 2);
        delete_accounts_with(&db, accounts, |_| async { Ok(()) })
            .await
            .unwrap();

        assert_deleted(&db, "u1").await;
        assert_deleted(&db, "u2").await;
        assert!(db
            .fetch_prot_account(&prot_user_account("u1"))
            .await
            .unwrap()
            .is_none());
        assert_eq!(forfeit_rows(&db, "u1").await, 0);
        assert_eq!(forfeit_rows(&db, "u2").await, 0);
        assert!(db
            .fetch_prot_entry_by_key(&prot_key_forfeit("u2", 1))
            .await
            .unwrap()
            .is_none());
    }
}
