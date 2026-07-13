use std::collections::HashMap;

use revolt_result::Result;

use crate::ReferenceDb;
use crate::{Poll, PollVote};

use super::AbstractPolls;

#[async_trait]
impl AbstractPolls for ReferenceDb {
    /// Insert a new poll.
    async fn insert_poll(&self, poll: &Poll) -> Result<()> {
        let mut polls = self.polls.lock().await;
        if polls.insert(poll.id.to_string(), poll.clone()).is_some() {
            Err(create_database_error!("insert", "polls"))
        } else {
            Ok(())
        }
    }

    /// Fetch a poll by its id.
    async fn fetch_poll(&self, id: &str) -> Result<Poll> {
        let polls = self.polls.lock().await;
        polls.get(id).cloned().ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch several polls by id.
    async fn fetch_polls(&self, ids: &[String]) -> Result<Vec<Poll>> {
        let polls = self.polls.lock().await;
        Ok(ids.iter().filter_map(|id| polls.get(id).cloned()).collect())
    }

    /// Insert or replace a user's ballot, returning the previous ballot's
    /// answer ids if one existed.
    async fn upsert_poll_vote(&self, vote: &PollVote) -> Result<Option<Vec<u8>>> {
        let mut votes = self.poll_votes.lock().await;
        Ok(votes
            .insert(vote.id.to_string(), vote.clone())
            .map(|previous| previous.answer_ids))
    }

    /// Remove a user's ballot, returning its answer ids if it existed.
    async fn remove_poll_vote(&self, poll: &str, user: &str) -> Result<Option<Vec<u8>>> {
        let mut votes = self.poll_votes.lock().await;
        Ok(votes
            .remove(&Poll::vote_key(poll, user))
            .map(|previous| previous.answer_ids))
    }

    /// Fetch a single user's ballot on a poll, if any.
    async fn fetch_poll_vote(&self, poll: &str, user: &str) -> Result<Option<PollVote>> {
        let votes = self.poll_votes.lock().await;
        Ok(votes.get(&Poll::vote_key(poll, user)).cloned())
    }

    /// Fetch one user's ballots across several polls.
    async fn fetch_poll_votes_for_user(
        &self,
        poll_ids: &[String],
        user: &str,
    ) -> Result<Vec<PollVote>> {
        let votes = self.poll_votes.lock().await;
        Ok(poll_ids
            .iter()
            .filter_map(|poll| votes.get(&Poll::vote_key(poll, user)).cloned())
            .collect())
    }

    /// Fetch every ballot on a poll.
    async fn fetch_poll_votes(&self, poll: &str) -> Result<Vec<PollVote>> {
        let votes = self.poll_votes.lock().await;
        Ok(votes
            .values()
            .filter(|vote| vote.poll == poll)
            .cloned()
            .collect())
    }

    /// Fetch a page of ballots that include the given answer, ordered by
    /// ballot id, strictly after the given cursor.
    async fn fetch_poll_voters_page(
        &self,
        poll: &str,
        answer_id: u8,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PollVote>> {
        let votes = self.poll_votes.lock().await;
        let mut page: Vec<PollVote> = votes
            .values()
            .filter(|vote| {
                vote.poll == poll
                    && vote.answer_ids.contains(&answer_id)
                    && after.is_none_or(|after| vote.id.as_str() > after)
            })
            .cloned()
            .collect();
        page.sort_by(|a, b| a.id.cmp(&b.id));
        page.truncate(limit.max(0) as usize);
        Ok(page)
    }

    /// Apply live count deltas after a vote change.
    async fn apply_poll_count_deltas(
        &self,
        poll: &str,
        deltas: &HashMap<String, i64>,
        ballot_delta: i64,
    ) -> Result<()> {
        let mut polls = self.polls.lock().await;
        if let Some(poll) = polls.get_mut(poll) {
            for (answer_id, delta) in deltas {
                let count = poll.counts.entry(answer_id.clone()).or_insert(0);
                *count += delta;
                if *count == 0 {
                    poll.counts.remove(answer_id);
                }
            }
            poll.total_votes += ballot_delta;
        }
        Ok(())
    }

    /// Overwrite the stored counts with an authoritative recount.
    async fn set_poll_counts(
        &self,
        poll: &str,
        counts: &HashMap<String, i64>,
        total_votes: i64,
    ) -> Result<()> {
        let mut polls = self.polls.lock().await;
        if let Some(poll) = polls.get_mut(poll) {
            poll.counts = counts.clone();
            poll.total_votes = total_votes;
        }
        Ok(())
    }

    /// Atomically flip `closed` false→true. The mutex makes check-and-set
    /// atomic on this driver.
    async fn close_poll_if_open(&self, id: &str) -> Result<bool> {
        let mut polls = self.polls.lock().await;
        match polls.get_mut(id) {
            Some(poll) if !poll.closed => {
                poll.closed = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Fetch open polls whose expiry instant has passed.
    async fn fetch_expired_open_polls(&self, now_ms: i64) -> Result<Vec<Poll>> {
        let polls = self.polls.lock().await;
        Ok(polls
            .values()
            .filter(|poll| !poll.closed && poll.expires_at <= now_ms)
            .cloned()
            .collect())
    }

    /// Delete the polls carried by the given messages, and their ballots.
    async fn delete_polls_for_messages(&self, message_ids: &[String]) -> Result<()> {
        let mut polls = self.polls.lock().await;
        let poll_ids: Vec<String> = polls
            .values()
            .filter(|poll| message_ids.contains(&poll.message))
            .map(|poll| poll.id.clone())
            .collect();

        if poll_ids.is_empty() {
            return Ok(());
        }

        polls.retain(|id, _| !poll_ids.contains(id));

        let mut votes = self.poll_votes.lock().await;
        votes.retain(|_, vote| !poll_ids.contains(&vote.poll));
        Ok(())
    }

    /// Delete every poll and ballot in a channel.
    async fn delete_polls_for_channel(&self, channel: &str) -> Result<()> {
        let mut polls = self.polls.lock().await;
        polls.retain(|_, poll| poll.channel != channel);

        let mut votes = self.poll_votes.lock().await;
        votes.retain(|_, vote| vote.channel != channel);
        Ok(())
    }
}
