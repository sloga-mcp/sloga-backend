use revolt_result::Result;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// The `history_wipes` job's per-channel lease (design 7.5 "S4"; the
/// `scheduled_messages` claim precedent). No client route reaches these.
/// Times are unix milliseconds from the caller's clock.
#[async_trait]
pub trait AbstractHistoryWipeLeases: Sync + Send {
    /// Claim the channel's lease for `holder` until `now_ms + ttl_ms`, when
    /// the row is absent, expired (`expires_at <= now_ms`) or already held
    /// by `holder`. Returns the running count, `Some(0)` for a new row, or
    /// `None` while another holder's lease is unexpired.
    async fn claim_history_wipe_lease(
        &self,
        channel_id: &str,
        holder: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<Option<u64>>;

    /// Add `add` to the count and renew the lease until `now_ms + ttl_ms`,
    /// only while `holder` holds it; returns whether it did. `false` means
    /// the lease was lost (or never existed).
    async fn advance_history_wipe_lease(
        &self,
        channel_id: &str,
        holder: &str,
        add: u64,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<bool>;

    /// Release the lease (`expires_at = 0`) while `holder` holds it, KEEPING
    /// the count, so a wipe stopped by a legal hold resumes it
    async fn release_history_wipe_lease(&self, channel_id: &str, holder: &str) -> Result<()>;

    /// Delete the channel's lease row (after `Done`); no row is not an error
    async fn delete_history_wipe_lease(&self, channel_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use crate::{Database, HistoryWipeLease};

    const CHANNEL: &str = "01WIPELEASECHANNEL00000000";
    const A: &str = "holder-a";
    const B: &str = "holder-b";
    const TTL: i64 = 100;

    /// The stored lease row of `CHANNEL`, read past the trait
    async fn stored(db: &Database) -> Option<HistoryWipeLease> {
        stored_of(db, CHANNEL).await
    }

    /// The stored lease row of `channel_id`, read past the trait
    async fn stored_of(db: &Database, channel_id: &str) -> Option<HistoryWipeLease> {
        match db {
            Database::Reference(reference) => reference
                .history_wipe_leases
                .lock()
                .await
                .get(channel_id)
                .cloned(),
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => mongo
                .col::<HistoryWipeLease>("history_wipe_leases")
                .find_one(doc! { "_id": channel_id })
                .await
                .unwrap(),
        }
    }

    fn lease(holder: &str, expires_at: i64, count: i64) -> Option<HistoryWipeLease> {
        Some(HistoryWipeLease {
            id: CHANNEL.to_string(),
            holder: holder.to_string(),
            expires_at,
            count,
        })
    }

    /// A claim succeeds on an absent row (count 0), on its own live lease,
    /// and on an expired one (taking over the count); it is `None` while
    /// another holder's lease is live and then writes nothing.
    ///
    /// Control: the claim ignores expiry (each driver).
    #[tokio::test]
    async fn a_lease_is_claimed_when_absent_expired_or_own() {
        database_test!(|db| async move {
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, A, 1_000, TTL)
                    .await
                    .unwrap(),
                Some(0),
                "absent"
            );
            assert_eq!(stored(&db).await, lease(A, 1_100, 0));

            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, A, 1_050, TTL)
                    .await
                    .unwrap(),
                Some(0),
                "own, live"
            );
            assert_eq!(stored(&db).await, lease(A, 1_150, 0));
            assert!(db
                .advance_history_wipe_lease(CHANNEL, A, 5, 1_060, TTL)
                .await
                .unwrap());

            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, B, 1_100, TTL)
                    .await
                    .unwrap(),
                None,
                "another holder's live lease"
            );
            assert_eq!(stored(&db).await, lease(A, 1_160, 5));

            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, B, 1_160, TTL)
                    .await
                    .unwrap(),
                Some(5),
                "expired: taken over with its count"
            );
            assert_eq!(stored(&db).await, lease(B, 1_260, 5));
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, A, 1_200, TTL)
                    .await
                    .unwrap(),
                None,
                "the old holder lost it"
            );
        });
    }

    /// Advancing adds to the count and renews the lease for its holder only;
    /// another holder's advance (or one on no row) is `false` and writes
    /// nothing.
    ///
    /// Control: the advance ignores the holder (each driver).
    #[tokio::test]
    async fn a_lease_advances_only_for_its_holder() {
        database_test!(|db| async move {
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, A, 1_000, TTL)
                    .await
                    .unwrap(),
                Some(0)
            );
            assert!(db
                .advance_history_wipe_lease(CHANNEL, A, 3, 1_050, TTL)
                .await
                .unwrap());
            assert_eq!(stored(&db).await, lease(A, 1_150, 3));

            assert!(!db
                .advance_history_wipe_lease(CHANNEL, B, 7, 1_060, TTL)
                .await
                .unwrap());
            assert_eq!(stored(&db).await, lease(A, 1_150, 3));

            // Renewed: past the first expiry, still A's
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, B, 1_120, TTL)
                    .await
                    .unwrap(),
                None
            );
            assert!(db
                .advance_history_wipe_lease(CHANNEL, A, 2, 1_100, TTL)
                .await
                .unwrap());
            assert_eq!(stored(&db).await, lease(A, 1_200, 5));

            assert!(!db
                .advance_history_wipe_lease("01WIPELEASEMISSING00000000", A, 1, 1_100, TTL)
                .await
                .unwrap());
        });
    }

    /// A release by the holder zeroes the expiry and keeps the row and its
    /// count, so the next claim (by anyone, before the old expiry) resumes
    /// the count; a release by another holder changes nothing.
    ///
    /// Control: the release deletes the row (each driver).
    #[tokio::test]
    async fn a_released_lease_keeps_its_count() {
        database_test!(|db| async move {
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, A, 1_000, TTL)
                    .await
                    .unwrap(),
                Some(0)
            );
            assert!(db
                .advance_history_wipe_lease(CHANNEL, A, 4, 1_010, TTL)
                .await
                .unwrap());

            db.release_history_wipe_lease(CHANNEL, B)
                .await
                .expect("a foreign release");
            assert_eq!(stored(&db).await, lease(A, 1_110, 4));
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, B, 1_020, TTL)
                    .await
                    .unwrap(),
                None
            );

            db.release_history_wipe_lease(CHANNEL, A)
                .await
                .expect("release");
            assert_eq!(stored(&db).await, lease(A, 0, 4));
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, B, 1_030, TTL)
                    .await
                    .unwrap(),
                Some(4),
                "the count resumes"
            );
            assert_eq!(stored(&db).await, lease(B, 1_130, 4));
        });
    }

    /// A deleted lease is gone: the next claim starts a new row at 0, and
    /// deleting no row succeeds.
    #[tokio::test]
    async fn a_deleted_lease_starts_over() {
        database_test!(|db| async move {
            db.delete_history_wipe_lease(CHANNEL)
                .await
                .expect("delete with no row");
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, A, 1_000, TTL)
                    .await
                    .unwrap(),
                Some(0)
            );
            assert!(db
                .advance_history_wipe_lease(CHANNEL, A, 9, 1_010, TTL)
                .await
                .unwrap());

            db.delete_history_wipe_lease(CHANNEL).await.expect("delete");
            assert_eq!(stored(&db).await, None);
            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, B, 1_020, TTL)
                    .await
                    .unwrap(),
                Some(0)
            );
            assert_eq!(stored(&db).await, lease(B, 1_120, 0));
        });
    }

    /// The channel-delete cascade (`delete_protected_channel_data`) deletes
    /// the channel's lease row, even a released one that keeps its count,
    /// and leaves another channel's lease alone.
    ///
    /// Control: the lease delete dropped from the cascade (each driver).
    #[tokio::test]
    async fn the_delete_cascade_removes_the_lease() {
        database_test!(|db| async move {
            const OTHER: &str = "01WIPELEASEOTHER0000000000";

            assert_eq!(
                db.claim_history_wipe_lease(CHANNEL, A, 1_000, TTL)
                    .await
                    .unwrap(),
                Some(0)
            );
            assert!(db
                .advance_history_wipe_lease(CHANNEL, A, 6, 1_010, TTL)
                .await
                .unwrap());
            db.release_history_wipe_lease(CHANNEL, A)
                .await
                .expect("release");
            assert_eq!(
                db.claim_history_wipe_lease(OTHER, B, 1_000, TTL)
                    .await
                    .unwrap(),
                Some(0)
            );
            // The row is really there, so the assertion below is not vacuous
            assert_eq!(stored(&db).await, lease(A, 0, 6));

            db.delete_protected_channel_data(CHANNEL)
                .await
                .expect("cascade");

            assert_eq!(stored(&db).await, None);
            assert_eq!(
                stored_of(&db, OTHER).await,
                Some(HistoryWipeLease {
                    id: OTHER.to_string(),
                    holder: B.to_string(),
                    expires_at: 1_100,
                    count: 0,
                })
            );

            // No lease row: the cascade still succeeds
            db.delete_protected_channel_data(CHANNEL)
                .await
                .expect("cascade with no row");
        });
    }
}
