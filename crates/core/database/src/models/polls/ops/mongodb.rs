use std::collections::HashMap;

use bson::Document;
use futures::StreamExt;
use mongodb::options::{FindOneAndUpdateOptions, ReturnDocument};
use revolt_result::Result;

use crate::MongoDb;
use crate::{Poll, PollVote};

use super::AbstractPolls;

static COL: &str = "polls";
static COL_VOTES: &str = "poll_votes";

#[async_trait]
impl AbstractPolls for MongoDb {
    /// Insert a new poll.
    async fn insert_poll(&self, poll: &Poll) -> Result<()> {
        query!(self, insert_one, COL, &poll).map(|_| ())
    }

    /// Fetch a poll by its id.
    async fn fetch_poll(&self, id: &str) -> Result<Poll> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch several polls by id.
    async fn fetch_polls(&self, ids: &[String]) -> Result<Vec<Poll>> {
        Ok(self
            .col::<Poll>(COL)
            .find(doc! {
                "_id": {
                    "$in": ids
                }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Insert or replace a user's ballot, returning the previous ballot's
    /// answer ids if one existed.
    async fn upsert_poll_vote(&self, vote: &PollVote) -> Result<Option<Vec<u8>>> {
        let answer_ids: Vec<i32> = vote.answer_ids.iter().map(|id| *id as i32).collect();

        self.col::<PollVote>(COL_VOTES)
            .find_one_and_update(
                doc! {
                    "_id": &vote.id
                },
                doc! {
                    "$set": {
                        "poll": &vote.poll,
                        "user": &vote.user,
                        "channel": &vote.channel,
                        "answer_ids": answer_ids
                    }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .upsert(true)
                    .return_document(ReturnDocument::Before)
                    .build(),
            )
            .await
            .map(|previous| previous.map(|vote| vote.answer_ids))
            .map_err(|_| create_database_error!("find_one_and_update", COL_VOTES))
    }

    /// Remove a user's ballot, returning its answer ids if it existed.
    async fn remove_poll_vote(&self, poll: &str, user: &str) -> Result<Option<Vec<u8>>> {
        self.col::<PollVote>(COL_VOTES)
            .find_one_and_delete(doc! {
                "_id": Poll::vote_key(poll, user)
            })
            .await
            .map(|previous| previous.map(|vote| vote.answer_ids))
            .map_err(|_| create_database_error!("find_one_and_delete", COL_VOTES))
    }

    /// Fetch a single user's ballot on a poll, if any.
    async fn fetch_poll_vote(&self, poll: &str, user: &str) -> Result<Option<PollVote>> {
        query!(self, find_one_by_id, COL_VOTES, &Poll::vote_key(poll, user))
    }

    /// Fetch one user's ballots across several polls.
    async fn fetch_poll_votes_for_user(
        &self,
        poll_ids: &[String],
        user: &str,
    ) -> Result<Vec<PollVote>> {
        let keys: Vec<String> = poll_ids
            .iter()
            .map(|poll| Poll::vote_key(poll, user))
            .collect();

        Ok(self
            .col::<PollVote>(COL_VOTES)
            .find(doc! {
                "_id": {
                    "$in": keys
                }
            })
            .await
            .map_err(|_| create_database_error!("find", COL_VOTES))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Fetch every ballot on a poll.
    async fn fetch_poll_votes(&self, poll: &str) -> Result<Vec<PollVote>> {
        Ok(self
            .col::<PollVote>(COL_VOTES)
            .find(doc! {
                "poll": poll
            })
            .await
            .map_err(|_| create_database_error!("find", COL_VOTES))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Fetch a page of ballots that include the given answer.
    async fn fetch_poll_voters_page(
        &self,
        poll: &str,
        answer_id: u8,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PollVote>> {
        let mut filter = doc! {
            "poll": poll,
            "answer_ids": answer_id as i32
        };
        if let Some(after) = after {
            filter.insert("_id", doc! { "$gt": after });
        }

        Ok(self
            .col::<PollVote>(COL_VOTES)
            .find(filter)
            .sort(doc! { "_id": 1_i32 })
            .limit(limit)
            .await
            .map_err(|_| create_database_error!("find", COL_VOTES))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Apply live count deltas after a vote change.
    async fn apply_poll_count_deltas(
        &self,
        poll: &str,
        deltas: &HashMap<String, i64>,
        ballot_delta: i64,
    ) -> Result<()> {
        let mut inc = Document::new();
        for (answer_id, delta) in deltas {
            inc.insert(format!("counts.{answer_id}"), *delta);
        }
        inc.insert("total_votes", ballot_delta);

        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": poll
                },
                doc! {
                    "$inc": inc
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Overwrite the stored counts with an authoritative recount.
    async fn set_poll_counts(
        &self,
        poll: &str,
        counts: &HashMap<String, i64>,
        total_votes: i64,
    ) -> Result<()> {
        let mut counts_doc = Document::new();
        for (answer_id, count) in counts {
            counts_doc.insert(answer_id.clone(), *count);
        }

        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": poll
                },
                doc! {
                    "$set": {
                        "counts": counts_doc,
                        "total_votes": total_votes
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Atomically flip `closed` false→true.
    async fn close_poll_if_open(&self, id: &str) -> Result<bool> {
        // `closed: false` is stored as a MISSING key (skip_serializing_if),
        // so match on "not true" rather than "false".
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "closed": { "$ne": true }
                },
                doc! {
                    "$set": { "closed": true }
                },
            )
            .await
            .map(|result| result.modified_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Fetch open polls whose expiry instant has passed.
    async fn fetch_expired_open_polls(&self, now_ms: i64) -> Result<Vec<Poll>> {
        Ok(self
            .col::<Poll>(COL)
            .find(doc! {
                "closed": { "$ne": true },
                "expires_at": { "$lte": now_ms }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Delete the polls carried by the given messages, and their ballots.
    async fn delete_polls_for_messages(&self, message_ids: &[String]) -> Result<()> {
        let polls: Vec<Poll> = self
            .col::<Poll>(COL)
            .find(doc! {
                "message": {
                    "$in": message_ids
                }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        if polls.is_empty() {
            return Ok(());
        }

        let poll_ids: Vec<&str> = polls.iter().map(|poll| poll.id.as_str()).collect();

        self.col::<Document>(COL_VOTES)
            .delete_many(doc! {
                "poll": {
                    "$in": &poll_ids
                }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_VOTES))?;

        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id": {
                    "$in": &poll_ids
                }
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }

    /// Delete every poll and ballot in a channel.
    async fn delete_polls_for_channel(&self, channel: &str) -> Result<()> {
        self.col::<Document>(COL_VOTES)
            .delete_many(doc! {
                "channel": channel
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_VOTES))?;

        self.col::<Document>(COL)
            .delete_many(doc! {
                "channel": channel
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
