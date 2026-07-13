use std::collections::HashMap;

use revolt_models::v0;
use revolt_result::Result;

use crate::events::client::EventV1;
use crate::Database;

auto_derived!(
    /// The server-side record of a poll.
    ///
    /// The immutable definition (question / answers / multiselect / expiry)
    /// is snapshotted here AND embedded in the carrying message; the live
    /// `counts` / `total_votes` / `closed` state lives ONLY here so votes
    /// never republish the message.
    pub struct Poll {
        /// Poll id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the message carrying this poll (unique — one poll per message)
        pub message: String,
        /// Id of the channel the poll was created in
        pub channel: String,
        /// Id of the server, when the channel is a server channel
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server: Option<String>,
        /// Id of the poll author
        pub author: String,
        /// The question being asked
        pub question: String,
        /// Answer snapshot (immutable after creation)
        pub answers: Vec<v0::PollAnswer>,
        /// Whether voters may pick more than one answer
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub allow_multiselect: bool,
        /// When the poll automatically closes (ms since epoch, UTC)
        pub expires_at: i64,
        /// Whether the poll is closed
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub closed: bool,
        /// Live per-answer counts, keyed by stringified answer id
        /// (BSON document keys must be strings)
        #[serde(skip_serializing_if = "HashMap::is_empty", default)]
        pub counts: HashMap<String, i64>,
        /// Number of ballots cast (voters, not answer-selections)
        #[serde(skip_serializing_if = "crate::if_zero_i64", default)]
        pub total_votes: i64,
    }

    /// One user's ballot on a poll. `_id` is `"{poll}:{user}"`, so a user
    /// can never hold two ballots — re-voting replaces.
    pub struct PollVote {
        /// Composite id: `"{poll}:{user}"`
        #[serde(rename = "_id")]
        pub id: String,
        /// Poll id
        pub poll: String,
        /// Voting user's id
        pub user: String,
        /// Channel the poll lives in (channel-deletion cascade)
        pub channel: String,
        /// Selected answer ids
        pub answer_ids: Vec<u8>,
    }
);

impl Poll {
    /// Composite ballot key.
    pub fn vote_key(poll: &str, user: &str) -> String {
        format!("{poll}:{user}")
    }

    /// Whether the poll's expiry instant has passed.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at <= now_ms
    }

    /// Aggregate counts for every answer (zeroes included), ordered by
    /// answer id — the wire shape shared by REST responses and WS events.
    pub fn counts_vec(&self) -> Vec<v0::PollAnswerCount> {
        self.answers
            .iter()
            .map(|answer| v0::PollAnswerCount {
                answer_id: answer.id,
                count: self
                    .counts
                    .get(&answer.id.to_string())
                    .copied()
                    .unwrap_or(0),
            })
            .collect()
    }

    /// The immutable definition embedded in the carrying message.
    pub fn definition(&self) -> v0::PollDefinition {
        v0::PollDefinition {
            id: self.id.clone(),
            question: self.question.clone(),
            answers: self.answers.clone(),
            allow_multiselect: self.allow_multiselect,
            expires_at: self.expires_at,
        }
    }

    /// API model with hidden-by-choice gating applied server-side:
    /// counts / totals are included only when the requester has voted, is
    /// the author, has ManageMessages, or the poll is closed.
    pub fn into_model(self, my_votes: Option<Vec<u8>>, include_counts: bool) -> v0::Poll {
        let (counts, total_votes) = if include_counts {
            (Some(self.counts_vec()), Some(self.total_votes))
        } else {
            (None, None)
        };

        v0::Poll {
            id: self.id,
            message_id: self.message,
            channel_id: self.channel,
            author_id: self.author,
            closed: self.closed,
            expires_at: self.expires_at,
            counts,
            total_votes,
            my_votes,
        }
    }

    /// Authoritative recount from the ballots themselves: overwrite the
    /// live `$inc` counters with counts derived from the stored ballots.
    /// Used by the close winner and by the vote routes' after-close
    /// compensation, so any transient drift is healed from one source of
    /// truth. Returns the recounted wire counts and ballot total.
    pub async fn recount(&self, db: &Database) -> Result<(Vec<v0::PollAnswerCount>, i64)> {
        let votes = db.fetch_poll_votes(&self.id).await?;
        let mut counts: HashMap<String, i64> = HashMap::new();
        for vote in &votes {
            for answer_id in &vote.answer_ids {
                *counts.entry(answer_id.to_string()).or_insert(0) += 1;
            }
        }
        let total_votes = votes.len() as i64;
        db.set_poll_counts(&self.id, &counts, total_votes).await?;

        Ok((
            self.answers
                .iter()
                .map(|answer| v0::PollAnswerCount {
                    answer_id: answer.id,
                    count: counts.get(&answer.id.to_string()).copied().unwrap_or(0),
                })
                .collect(),
            total_votes,
        ))
    }

    /// Close this poll exactly once and publish `PollClose` with
    /// authoritative final results.
    ///
    /// Every close path (expiry daemon, lazy close in routes, manual /end)
    /// funnels through here: the atomic flip decides a single winner, the
    /// winner recounts from the ballots (so any drift in the live `$inc`
    /// counters cannot survive into the final results) and publishes the
    /// event. Losers get `Ok(None)` and publish nothing.
    pub async fn close(&self, db: &Database) -> Result<Option<(Vec<v0::PollAnswerCount>, i64)>> {
        if !db.close_poll_if_open(&self.id).await? {
            return Ok(None);
        }

        let (final_counts, total_votes) = self.recount(db).await?;

        EventV1::PollClose {
            id: self.id.clone(),
            channel_id: self.channel.clone(),
            message_id: self.message.clone(),
            counts: final_counts.clone(),
            total_votes,
        }
        .p(self.channel.clone())
        .await;

        Ok(Some((final_counts, total_votes)))
    }
}
