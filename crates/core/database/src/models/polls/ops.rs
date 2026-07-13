use std::collections::HashMap;

use revolt_result::Result;

use crate::{Poll, PollVote};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractPolls: Sync + Send {
    /// Insert a new poll.
    async fn insert_poll(&self, poll: &Poll) -> Result<()>;

    /// Fetch a poll by its id.
    async fn fetch_poll(&self, id: &str) -> Result<Poll>;

    /// Fetch several polls by id (bulk hydration for a page of messages).
    async fn fetch_polls(&self, ids: &[String]) -> Result<Vec<Poll>>;

    /// Insert or replace a user's ballot, returning the previous ballot's
    /// answer ids if one existed (drives the count deltas).
    async fn upsert_poll_vote(&self, vote: &PollVote) -> Result<Option<Vec<u8>>>;

    /// Remove a user's ballot, returning its answer ids if it existed.
    async fn remove_poll_vote(&self, poll: &str, user: &str) -> Result<Option<Vec<u8>>>;

    /// Fetch a single user's ballot on a poll, if any.
    async fn fetch_poll_vote(&self, poll: &str, user: &str) -> Result<Option<PollVote>>;

    /// Fetch one user's ballots across several polls (bulk hydration).
    async fn fetch_poll_votes_for_user(
        &self,
        poll_ids: &[String],
        user: &str,
    ) -> Result<Vec<PollVote>>;

    /// Fetch every ballot on a poll (authoritative recount at close).
    async fn fetch_poll_votes(&self, poll: &str) -> Result<Vec<PollVote>>;

    /// Fetch a page of ballots that include the given answer, ordered by
    /// ballot id, strictly after the given cursor.
    async fn fetch_poll_voters_page(
        &self,
        poll: &str,
        answer_id: u8,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PollVote>>;

    /// Apply live count deltas after a vote change. `deltas` is keyed by
    /// stringified answer id; `ballot_delta` adjusts the ballot total
    /// (+1 new ballot, 0 replaced ballot, -1 retracted ballot).
    async fn apply_poll_count_deltas(
        &self,
        poll: &str,
        deltas: &HashMap<String, i64>,
        ballot_delta: i64,
    ) -> Result<()>;

    /// Overwrite the stored counts with an authoritative recount.
    async fn set_poll_counts(
        &self,
        poll: &str,
        counts: &HashMap<String, i64>,
        total_votes: i64,
    ) -> Result<()>;

    /// Atomically flip `closed` false→true; returns whether THIS caller
    /// won the flip (exactly-once close arbitration).
    async fn close_poll_if_open(&self, id: &str) -> Result<bool>;

    /// Fetch open polls whose expiry instant has passed (crond scan).
    async fn fetch_expired_open_polls(&self, now_ms: i64) -> Result<Vec<Poll>>;

    /// Delete the polls carried by the given messages, and their ballots
    /// (message-deletion cascade, single and bulk paths).
    async fn delete_polls_for_messages(&self, message_ids: &[String]) -> Result<()>;

    /// Delete every poll and ballot in a channel (channel-deletion cascade).
    async fn delete_polls_for_channel(&self, channel: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractPolls;
    use crate::{Poll, PollVote};
    use revolt_models::v0;
    use std::collections::HashMap;

    fn poll(id: &str, message: &str) -> Poll {
        Poll {
            id: id.to_string(),
            message: message.to_string(),
            channel: "01CHAN000000000000000000000".to_string(),
            server: None,
            author: "01AUTHOR00000000000000000000".to_string(),
            question: "Best crab?".to_string(),
            answers: vec![
                v0::PollAnswer {
                    id: 0,
                    text: "Ferris".to_string(),
                    emoji: None,
                },
                v0::PollAnswer {
                    id: 1,
                    text: "Sebastian".to_string(),
                    emoji: None,
                },
            ],
            allow_multiselect: false,
            expires_at: 2_000_000,
            closed: false,
            counts: HashMap::new(),
            total_votes: 0,
        }
    }

    fn ballot(poll_id: &str, user: &str, answer_ids: Vec<u8>) -> PollVote {
        PollVote {
            id: Poll::vote_key(poll_id, user),
            poll: poll_id.to_string(),
            user: user.to_string(),
            channel: "01CHAN000000000000000000000".to_string(),
            answer_ids,
        }
    }

    #[tokio::test]
    async fn vote_upsert_returns_previous_ballot() {
        database_test!(|db| async move {
            let row = poll("01POLL000000000000000000000", "01MSG0000000000000000000000");
            db.insert_poll(&row).await.unwrap();

            let user = "01USER000000000000000000000";

            // First ballot: no previous
            let previous = db
                .upsert_poll_vote(&ballot(&row.id, user, vec![0]))
                .await
                .unwrap();
            assert_eq!(previous, None);

            // Replacing ballot: previous returned
            let previous = db
                .upsert_poll_vote(&ballot(&row.id, user, vec![1]))
                .await
                .unwrap();
            assert_eq!(previous, Some(vec![0]));

            // Retract: previous returned, second retract is a no-op
            let removed = db.remove_poll_vote(&row.id, user).await.unwrap();
            assert_eq!(removed, Some(vec![1]));
            let removed = db.remove_poll_vote(&row.id, user).await.unwrap();
            assert_eq!(removed, None);
        });
    }

    #[tokio::test]
    async fn count_deltas_and_recount() {
        database_test!(|db| async move {
            let row = poll("01POLL000000000000000000001", "01MSG0000000000000000000001");
            db.insert_poll(&row).await.unwrap();

            let mut deltas = HashMap::new();
            deltas.insert("0".to_string(), 1);
            db.apply_poll_count_deltas(&row.id, &deltas, 1).await.unwrap();

            let fetched = db.fetch_poll(&row.id).await.unwrap();
            assert_eq!(fetched.counts.get("0"), Some(&1));
            assert_eq!(fetched.total_votes, 1);

            // Authoritative overwrite
            let mut counts = HashMap::new();
            counts.insert("1".to_string(), 5);
            db.set_poll_counts(&row.id, &counts, 5).await.unwrap();
            let fetched = db.fetch_poll(&row.id).await.unwrap();
            assert_eq!(fetched.counts.get("0"), None);
            assert_eq!(fetched.counts.get("1"), Some(&5));
            assert_eq!(fetched.total_votes, 5);
        });
    }

    #[tokio::test]
    async fn close_is_exactly_once_and_expiry_scan_finds_open_polls() {
        database_test!(|db| async move {
            let row = poll("01POLL000000000000000000002", "01MSG0000000000000000000002");
            db.insert_poll(&row).await.unwrap();

            // Expired and open → in scan
            let due = db.fetch_expired_open_polls(2_000_000).await.unwrap();
            assert!(due.iter().any(|p| p.id == row.id));

            // Not yet expired → not in scan
            let due = db.fetch_expired_open_polls(1_999_999).await.unwrap();
            assert!(!due.iter().any(|p| p.id == row.id));

            // First close wins, second loses
            assert!(db.close_poll_if_open(&row.id).await.unwrap());
            assert!(!db.close_poll_if_open(&row.id).await.unwrap());

            // Closed → out of scan
            let due = db.fetch_expired_open_polls(2_000_000).await.unwrap();
            assert!(!due.iter().any(|p| p.id == row.id));
        });
    }

    #[tokio::test]
    async fn voters_page_filters_by_answer() {
        database_test!(|db| async move {
            let row = poll("01POLL000000000000000000003", "01MSG0000000000000000000003");
            db.insert_poll(&row).await.unwrap();

            db.upsert_poll_vote(&ballot(&row.id, "01USERA00000000000000000000", vec![0]))
                .await
                .unwrap();
            db.upsert_poll_vote(&ballot(&row.id, "01USERB00000000000000000000", vec![0, 1]))
                .await
                .unwrap();
            db.upsert_poll_vote(&ballot(&row.id, "01USERC00000000000000000000", vec![1]))
                .await
                .unwrap();

            let page = db
                .fetch_poll_voters_page(&row.id, 0, None, 10)
                .await
                .unwrap();
            let users: Vec<&str> = page.iter().map(|vote| vote.user.as_str()).collect();
            assert_eq!(
                users,
                vec!["01USERA00000000000000000000", "01USERB00000000000000000000"]
            );

            // Cursor pagination: after the first ballot id
            let page = db
                .fetch_poll_voters_page(&row.id, 0, Some(&page[0].id), 10)
                .await
                .unwrap();
            assert_eq!(page.len(), 1);
            assert_eq!(page[0].user, "01USERB00000000000000000000");
        });
    }

    #[tokio::test]
    async fn cascades_remove_polls_and_ballots() {
        database_test!(|db| async move {
            let row = poll("01POLL000000000000000000004", "01MSG0000000000000000000004");
            db.insert_poll(&row).await.unwrap();
            db.upsert_poll_vote(&ballot(&row.id, "01USERA00000000000000000000", vec![0]))
                .await
                .unwrap();

            // Message cascade
            db.delete_polls_for_messages(&[row.message.clone()])
                .await
                .unwrap();
            assert!(db.fetch_poll(&row.id).await.is_err());
            assert_eq!(
                db.fetch_poll_vote(&row.id, "01USERA00000000000000000000")
                    .await
                    .unwrap(),
                None
            );

            // Channel cascade
            let row = poll("01POLL000000000000000000005", "01MSG0000000000000000000005");
            db.insert_poll(&row).await.unwrap();
            db.upsert_poll_vote(&ballot(&row.id, "01USERB00000000000000000000", vec![1]))
                .await
                .unwrap();
            db.delete_polls_for_channel(&row.channel).await.unwrap();
            assert!(db.fetch_poll(&row.id).await.is_err());
            assert_eq!(
                db.fetch_poll_vote(&row.id, "01USERB00000000000000000000")
                    .await
                    .unwrap(),
                None
            );
        });
    }
}
