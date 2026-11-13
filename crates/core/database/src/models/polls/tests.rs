//! S4 protect and history-wipe helpers (7.4 "S4", 7.2 "S4"):
//! `Poll::close_open_for_channel` and `Poll::delete_for_messages`.

use std::collections::HashMap;

use revolt_models::v0;

use crate::{Poll, PollVote};

const CHAN_A: &str = "01CHANA0000000000000000000";
const CHAN_B: &str = "01CHANB0000000000000000000";
const USER_1: &str = "01USER10000000000000000000";
const USER_2: &str = "01USER20000000000000000000";

fn poll(id: &str, message: &str, channel: &str, closed: bool) -> Poll {
    Poll {
        id: id.to_string(),
        message: message.to_string(),
        channel: channel.to_string(),
        server: None,
        author: "01AUTHOR000000000000000000".to_string(),
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
        expires_at: 4_000_000_000_000,
        closed,
        counts: HashMap::new(),
        total_votes: 0,
    }
}

fn ballot(poll: &Poll, user: &str, answer_ids: Vec<u8>) -> PollVote {
    PollVote {
        id: Poll::vote_key(&poll.id, user),
        poll: poll.id.clone(),
        user: user.to_string(),
        channel: poll.channel.clone(),
        answer_ids,
    }
}

fn ids(polls: &[Poll]) -> Vec<String> {
    polls.iter().map(|poll| poll.id.clone()).collect()
}

fn ballot_ids(votes: &[PollVote]) -> Vec<String> {
    let mut ids: Vec<String> = votes.iter().map(|vote| vote.id.clone()).collect();
    ids.sort();
    ids
}

/// Channel A: two open polls and one closed poll whose stored counts
/// disagree with its ballot (a recount would overwrite them, so an
/// untouched row proves no second close ran). Channel B: one open poll and
/// one closed poll.
fn two_channels() -> (Poll, Poll, Poll, Poll, Poll) {
    let a_open_1 = poll(
        "01POLLA1000000000000000000",
        "01MSGA10000000000000000000",
        CHAN_A,
        false,
    );
    let a_open_2 = poll(
        "01POLLA2000000000000000000",
        "01MSGA20000000000000000000",
        CHAN_A,
        false,
    );
    let mut a_closed = poll(
        "01POLLA3000000000000000000",
        "01MSGA30000000000000000000",
        CHAN_A,
        true,
    );
    a_closed.counts = HashMap::from([("0".to_string(), 7)]);
    a_closed.total_votes = 7;
    let b_open = poll(
        "01POLLB1000000000000000000",
        "01MSGB10000000000000000000",
        CHAN_B,
        false,
    );
    let b_closed = poll(
        "01POLLB2000000000000000000",
        "01MSGB20000000000000000000",
        CHAN_B,
        true,
    );
    (a_open_1, a_open_2, a_closed, b_open, b_closed)
}

#[tokio::test]
async fn open_poll_scan_is_scoped_to_the_channel_and_skips_closed_polls() {
    database_test!(|db| async move {
        let (a_open_1, a_open_2, a_closed, b_open, b_closed) = two_channels();
        for row in [&a_open_1, &a_open_2, &a_closed, &b_open, &b_closed] {
            db.insert_poll(row).await.unwrap();
        }

        let open = db.fetch_open_polls_for_channel(CHAN_A).await.unwrap();
        assert_eq!(ids(&open), vec![a_open_1.id.clone(), a_open_2.id.clone()]);
        let open = db.fetch_open_polls_for_channel(CHAN_B).await.unwrap();
        assert_eq!(ids(&open), vec![b_open.id.clone()]);
        let open = db
            .fetch_open_polls_for_channel("01CHANC0000000000000000000")
            .await
            .unwrap();
        assert!(open.is_empty());
    });
}

#[tokio::test]
async fn close_open_for_channel_closes_only_that_channels_open_polls() {
    database_test!(|db| async move {
        let (a_open_1, a_open_2, a_closed, b_open, b_closed) = two_channels();
        for row in [&a_open_1, &a_open_2, &a_closed, &b_open, &b_closed] {
            db.insert_poll(row).await.unwrap();
        }

        db.upsert_poll_vote(&ballot(&a_open_1, USER_1, vec![0]))
            .await
            .unwrap();
        db.upsert_poll_vote(&ballot(&a_open_1, USER_2, vec![1]))
            .await
            .unwrap();
        db.upsert_poll_vote(&ballot(&a_closed, USER_1, vec![1]))
            .await
            .unwrap();
        // Drift the live counters; the close must heal them from the ballots.
        db.apply_poll_count_deltas(&a_open_1.id, &HashMap::from([("0".to_string(), 5)]), 5)
            .await
            .unwrap();

        let closed = Poll::close_open_for_channel(&db, CHAN_A).await.unwrap();
        assert_eq!(closed, vec![a_open_1.id.clone(), a_open_2.id.clone()]);

        // Closed with the recount `Poll::close` writes.
        let row = db.fetch_poll(&a_open_1.id).await.unwrap();
        assert!(row.closed);
        assert_eq!(row.total_votes, 2);
        let counts: Vec<(u8, i64)> = row
            .counts_vec()
            .iter()
            .map(|count| (count.answer_id, count.count))
            .collect();
        assert_eq!(counts, vec![(0, 1), (1, 1)]);
        assert!(db.fetch_poll(&a_open_2.id).await.unwrap().closed);

        // The already-closed poll and the other channel are untouched.
        assert_eq!(db.fetch_poll(&a_closed.id).await.unwrap(), a_closed);
        assert_eq!(db.fetch_poll(&b_open.id).await.unwrap(), b_open);
        assert_eq!(db.fetch_poll(&b_closed.id).await.unwrap(), b_closed);

        // A second run finds nothing open and returns nothing.
        assert!(db
            .fetch_open_polls_for_channel(CHAN_A)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            Poll::close_open_for_channel(&db, CHAN_A).await.unwrap(),
            Vec::<String>::new()
        );

        // The other channel's run returns exactly its own open poll.
        assert_eq!(
            Poll::close_open_for_channel(&db, CHAN_B).await.unwrap(),
            vec![b_open.id.clone()]
        );
    });
}

#[tokio::test]
async fn close_listed_skips_a_poll_closed_after_the_scan() {
    database_test!(|db| async move {
        let first = poll(
            "01POLLC1000000000000000000",
            "01MSGC10000000000000000000",
            CHAN_A,
            false,
        );
        let mut second = poll(
            "01POLLC2000000000000000000",
            "01MSGC20000000000000000000",
            CHAN_A,
            false,
        );
        // No ballots behind these counts: a recount would zero them.
        second.counts = HashMap::from([("1".to_string(), 3)]);
        second.total_votes = 3;
        db.insert_poll(&first).await.unwrap();
        db.insert_poll(&second).await.unwrap();

        let snapshot = db.fetch_open_polls_for_channel(CHAN_A).await.unwrap();
        assert_eq!(ids(&snapshot), vec![first.id.clone(), second.id.clone()]);

        // Another closer (expiry daemon, `/end`) wins `second` between the
        // scan and the flip.
        assert!(db.close_poll_if_open(&second.id).await.unwrap());

        assert_eq!(
            Poll::close_listed(&db, &snapshot).await,
            vec![first.id.clone()]
        );

        // The loser neither recounted nor reopened anything.
        let mut expected = second.clone();
        expected.closed = true;
        assert_eq!(db.fetch_poll(&second.id).await.unwrap(), expected);

        // Everything is closed now: the same list closes nothing.
        assert_eq!(
            Poll::close_listed(&db, &snapshot).await,
            Vec::<String>::new()
        );
    });
}

#[tokio::test]
async fn delete_for_messages_removes_only_the_listed_polls_and_ballots() {
    database_test!(|db| async move {
        let gone_open = poll(
            "01POLLD1000000000000000000",
            "01MSGD10000000000000000000",
            CHAN_A,
            false,
        );
        let gone_closed = poll(
            "01POLLD2000000000000000000",
            "01MSGD20000000000000000000",
            CHAN_A,
            true,
        );
        let kept_same_channel = poll(
            "01POLLD3000000000000000000",
            "01MSGD30000000000000000000",
            CHAN_A,
            false,
        );
        let kept_other_channel = poll(
            "01POLLD4000000000000000000",
            "01MSGD40000000000000000000",
            CHAN_B,
            false,
        );
        let all = [
            &gone_open,
            &gone_closed,
            &kept_same_channel,
            &kept_other_channel,
        ];
        for row in all {
            db.insert_poll(row).await.unwrap();
            db.upsert_poll_vote(&ballot(row, USER_1, vec![0]))
                .await
                .unwrap();
            db.upsert_poll_vote(&ballot(row, USER_2, vec![1]))
                .await
                .unwrap();
        }

        // An empty list deletes nothing.
        Poll::delete_for_messages(&db, &[]).await.unwrap();
        for row in all {
            assert_eq!(&db.fetch_poll(&row.id).await.unwrap(), row);
            assert_eq!(db.fetch_poll_votes(&row.id).await.unwrap().len(), 2);
        }

        Poll::delete_for_messages(
            &db,
            &[
                gone_open.message.clone(),
                gone_closed.message.clone(),
                "01MSGNOPOLL000000000000000".to_string(),
            ],
        )
        .await
        .unwrap();

        for row in [&gone_open, &gone_closed] {
            assert!(db.fetch_poll(&row.id).await.is_err());
            assert!(db.fetch_poll_votes(&row.id).await.unwrap().is_empty());
            assert_eq!(db.fetch_poll_vote(&row.id, USER_1).await.unwrap(), None);
            assert_eq!(db.fetch_poll_vote(&row.id, USER_2).await.unwrap(), None);
        }

        for row in [&kept_same_channel, &kept_other_channel] {
            assert_eq!(&db.fetch_poll(&row.id).await.unwrap(), row);
            assert_eq!(
                ballot_ids(&db.fetch_poll_votes(&row.id).await.unwrap()),
                vec![
                    Poll::vote_key(&row.id, USER_1),
                    Poll::vote_key(&row.id, USER_2)
                ]
            );
        }
    });
}

/// MongoDB only (the Reference driver stores typed rows): a poll row that no
/// longer decodes as a `Poll` is still deleted with its ballots, so the
/// history wipe cannot leave poll text behind.
#[tokio::test]
async fn delete_for_messages_removes_a_poll_row_that_does_not_decode() {
    database_test!(|db| async move {
        #[cfg(feature = "mongodb")]
        {
            if let crate::Database::MongoDb(mongo) = &db {
                let id = "01POLLE1000000000000000000";
                let message = "01MSGE10000000000000000000";
                let raw = mongo.col::<bson::Document>("polls");
                raw.insert_one(bson::doc! {
                    "_id": id,
                    "message": message,
                    "channel": CHAN_A,
                    "question": "Best crab?",
                    "answers": "not a list"
                })
                .await
                .unwrap();
                // Proof of the fixture: the typed read cannot decode it.
                assert!(mongo
                    .col::<Poll>("polls")
                    .find_one(bson::doc! { "_id": id })
                    .await
                    .is_err());

                let stub = poll(id, message, CHAN_A, false);
                db.upsert_poll_vote(&ballot(&stub, USER_1, vec![0]))
                    .await
                    .unwrap();

                Poll::delete_for_messages(&db, &[message.to_string()])
                    .await
                    .unwrap();

                assert!(raw
                    .find_one(bson::doc! { "_id": id })
                    .await
                    .unwrap()
                    .is_none());
                assert!(db.fetch_poll_votes(id).await.unwrap().is_empty());
            }
        }
    });
}
