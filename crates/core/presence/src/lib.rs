#[macro_use]
extern crate log;

use once_cell::sync::Lazy;
use rand::Rng;
use redis_kiss::{get_connection, AsyncCommands};
use std::collections::HashSet;

mod operations;
use operations::{
    __add_to_set_string, __add_to_set_u32, __delete_key, __get_set_members_as_string,
    __get_set_size, __remove_from_set_string, __remove_from_set_u32,
};

pub static REGION_ID: Lazy<u16> = Lazy::new(|| {
    std::env::var("REGION_ID")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap()
});

pub static REGION_KEY: Lazy<String> = Lazy::new(|| format!("region{}", &*REGION_ID));
pub static ONLINE_SET: &str = "online";

pub static FLAG_BITS: u32 = 0b1;

/// Create a new presence session, returns the ID of this session
pub async fn create_session(user_id: &str, flags: u8) -> (bool, u32) {
    info!("Creating a presence session for {user_id} with flags {flags}");

    if let Ok(mut conn) = get_connection().await {
        // Check whether this is the first session
        let was_empty = __get_set_size(&mut conn, user_id).await == 0;

        // A session ID is comprised of random data and any flags ORed to the end
        let session_id = {
            let mut rng = rand::thread_rng();
            (rng.gen::<u32>() & !FLAG_BITS) | (flags as u32 & FLAG_BITS)
        };

        // Add session to user's sessions and to the region
        __add_to_set_u32(&mut conn, user_id, session_id).await;
        __add_to_set_string(&mut conn, ONLINE_SET, user_id).await;
        __add_to_set_string(&mut conn, &REGION_KEY, &format!("{user_id}:{session_id}")).await;
        info!("Created session for {user_id}, assigned them a session ID of {session_id}.");

        (was_empty, session_id)
    } else {
        // Fail through
        (false, 0)
    }
}

/// Delete existing presence session
pub async fn delete_session(user_id: &str, session_id: u32) -> bool {
    delete_session_internal(user_id, session_id, false).await
}

/// Delete existing presence session (but also choose whether to skip region)
async fn delete_session_internal(user_id: &str, session_id: u32, skip_region: bool) -> bool {
    info!("Deleting presence session for {user_id} with id {session_id}");

    if let Ok(mut conn) = get_connection().await {
        // Remove the session
        __remove_from_set_u32(&mut conn, user_id, session_id).await;

        // Remove from the region
        if !skip_region {
            __remove_from_set_string(&mut conn, &REGION_KEY, &format!("{user_id}:{session_id}"))
                .await;
        }

        // Return whether this was the last session
        let is_empty = __get_set_size(&mut conn, user_id).await == 0;
        if is_empty {
            __remove_from_set_string(&mut conn, ONLINE_SET, user_id).await;
            info!("User ID {} just went offline.", &user_id);
        }

        is_empty
    } else {
        // Fail through
        false
    }
}

/// Check whether a given user ID is online
pub async fn is_online(user_id: &str) -> bool {
    if let Ok(mut conn) = get_connection().await {
        conn.exists(user_id).await.unwrap_or(false)
    } else {
        false
    }
}

/// Check whether a set of users is online, returns a set of the online user IDs
#[cfg(feature = "redis-is-patched")]
pub async fn filter_online(user_ids: &'_ [String]) -> HashSet<String> {
    // Ignore empty list immediately, to save time.
    let mut set = HashSet::new();
    if user_ids.is_empty() {
        return set;
    }

    // NOTE: at the point that we need mobile indicators
    // you can interpret the data here and return a new data
    // structure like HashMap<String /* id */, u8 /* flags */>

    // We need to handle a special case where only one is present
    // as for some reason or another, Redis does not like us sending
    // a list of just one ID to the server.
    if user_ids.len() == 1 {
        if is_online(&user_ids[0]).await {
            set.insert(user_ids[0].to_string());
        }

        return set;
    }

    // Otherwise, go ahead as normal.
    if let Ok(mut conn) = get_connection().await {
        // SMISMEMBER comes from the Redis patch in our forked repository;
        // if it goes missing, investigate what happened to it.
        set = online_from_flags(user_ids, conn.smismember(ONLINE_SET, user_ids).await);
    }

    set
}

/// Map an SMISMEMBER reply onto the set of online user IDs.
///
/// This never panics: its callers include long-lived tasks (the ack worker,
/// pushd consumers, bonfire). A Redis error means "treat nobody as online",
/// the same as failing to get a connection, and a short reply only covers
/// the IDs it has flags for.
#[cfg(feature = "redis-is-patched")]
fn online_from_flags<E: std::fmt::Debug>(
    user_ids: &[String],
    res: Result<Vec<bool>, E>,
) -> HashSet<String> {
    match res {
        Ok(data) => user_ids
            .iter()
            .zip(data)
            .filter(|(_, online)| *online)
            .map(|(id, _)| id.clone())
            .collect(),
        Err(err) => {
            error!(
                "Failed to check online status of {} users: {err:?}",
                user_ids.len()
            );
            HashSet::new()
        }
    }
}

/// Check whether a set of users is online, returns a set of the online user IDs
#[cfg(not(feature = "redis-is-patched"))]
pub async fn filter_online(user_ids: &'_ [String]) -> HashSet<String> {
    if user_ids.is_empty() {
        HashSet::new()
    } else if let Ok(mut conn) = get_connection().await {
        let members: Vec<String> = conn.smembers(ONLINE_SET).await.unwrap_or_default();
        let members: HashSet<&String> = members.iter().collect();
        let user_ids: HashSet<&String> = user_ids.iter().collect();

        members
            .intersection(&user_ids)
            .map(|x| x.to_string())
            .collect()
    } else {
        HashSet::new()
    }
}

/// Reset any stale presence data
pub async fn clear_region(region_id: Option<&str>) {
    let region_id = region_id.unwrap_or(&*REGION_KEY);
    let mut conn = get_connection().await.expect("Redis connection");

    let sessions = __get_set_members_as_string(&mut conn, region_id).await;
    if !sessions.is_empty() {
        info!(
            "Cleaning up {} sessions, this may take a while...",
            sessions.len()
        );

        // Iterate and delete each session, this will
        // also send out any relevant events.
        for session in sessions {
            let parts = session.split(':').collect::<Vec<&str>>();
            if let (Some(user_id), Some(session_id)) = (parts.first(), parts.get(1)) {
                if let Ok(session_id) = session_id.parse() {
                    delete_session_internal(user_id, session_id, true).await;
                }
            }
        }

        // Then clear the set in Redis.
        __delete_key(&mut conn, region_id).await;

        info!("Clean up complete.");
    }
}

#[cfg(test)]
mod tests {
    use crate::{clear_region, create_session, delete_session, filter_online, is_online};
    use rand::Rng;

    #[tokio::test]
    async fn it_works() {
        revolt_config::config().await;

        // Clear the region before we start the tests:
        clear_region(None).await;

        // Generate some data we'll use:
        let user_id = rand::thread_rng().gen::<u32>().to_string();
        let other_id = rand::thread_rng().gen::<u32>().to_string();
        let flags = 1;

        // Create a session
        let (first_session, session_id) = create_session(&user_id, flags).await;
        assert!(first_session);
        assert_ne!(session_id, 0);
        assert_eq!(session_id as u8 & flags, flags);

        // Check if the user is online
        assert!(is_online(&user_id).await);

        let user_ids = filter_online(&[user_id.to_string()]).await;
        assert_eq!(user_ids.len(), 1);
        assert!(user_ids.contains(&user_id));

        // Create a few more sessions
        let (first_session, second_session_id) = create_session(&user_id, 0).await;
        assert!(!first_session);
        assert_eq!(second_session_id as u8 & 1, 0);

        let (first_session, other_session_id) = create_session(&other_id, 0).await;
        assert!(first_session);

        let user_ids = filter_online(&[user_id.to_string(), other_id.to_string()]).await;
        assert_eq!(user_ids.len(), 2);
        assert!(user_ids.contains(&user_id));
        assert!(user_ids.contains(&other_id));

        // Remove sessions
        delete_session(&user_id, session_id).await;
        delete_session(&other_id, other_session_id).await;
        assert!(!is_online(&other_id).await);

        // Check if we can wipe everything too
        clear_region(None).await;
        assert!(!is_online(&user_id).await);

        let user_ids = filter_online(&[user_id.to_string(), other_id.to_string()]).await;
        assert!(user_ids.is_empty())
    }
}

#[cfg(all(test, feature = "redis-is-patched"))]
mod online_from_flags_tests {
    use crate::online_from_flags;
    use std::collections::HashSet;

    fn ids() -> Vec<String> {
        vec!["id0".to_string(), "id1".to_string(), "id2".to_string()]
    }

    #[test]
    fn online_from_flags_err_is_empty() {
        let set = online_from_flags(&ids(), Err::<Vec<bool>, &str>("boom"));
        assert!(set.is_empty());
    }

    #[test]
    fn online_from_flags_short_vec_does_not_panic() {
        let set = online_from_flags(&ids(), Ok::<_, &str>(vec![true]));
        assert_eq!(set, HashSet::from(["id0".to_string()]));
    }

    #[test]
    fn online_from_flags_maps_flags() {
        let set = online_from_flags(&ids(), Ok::<_, &str>(vec![true, false, true]));
        assert_eq!(set, HashSet::from(["id0".to_string(), "id2".to_string()]));
    }
}
