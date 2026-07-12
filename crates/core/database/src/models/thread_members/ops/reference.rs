use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{Channel, ReferenceDb, ThreadMember, ThreadMemberCompositeKey};

use super::AbstractThreadMembers;

#[async_trait]
impl AbstractThreadMembers for ReferenceDb {
    /// Join a user to a thread if they are not already a member (idempotent).
    async fn join_thread_if_absent(&self, thread_id: &str, user_id: &str) -> Result<bool> {
        let mut thread_members = self.thread_members.lock().await;
        let key = ThreadMemberCompositeKey {
            thread: thread_id.to_string(),
            user: user_id.to_string(),
        };

        if thread_members.contains_key(&key) {
            Ok(false)
        } else {
            thread_members.insert(
                key.clone(),
                ThreadMember {
                    id: key,
                    joined_at: Timestamp::now_utc(),
                },
            );

            Ok(true)
        }
    }

    /// Remove a user's membership of a thread.
    async fn leave_thread(&self, thread_id: &str, user_id: &str) -> Result<()> {
        let mut thread_members = self.thread_members.lock().await;
        thread_members.remove(&ThreadMemberCompositeKey {
            thread: thread_id.to_string(),
            user: user_id.to_string(),
        });

        Ok(())
    }

    /// Fetch all members of a thread.
    async fn fetch_thread_members(&self, thread_id: &str) -> Result<Vec<ThreadMember>> {
        let thread_members = self.thread_members.lock().await;
        Ok(thread_members
            .values()
            .filter(|member| member.id.thread == thread_id)
            .cloned()
            .collect())
    }

    /// Fetch the ids of all threads within a given server the user has joined.
    async fn fetch_joined_thread_ids(
        &self,
        user_id: &str,
        server_id: &str,
    ) -> Result<Vec<String>> {
        let thread_ids = {
            let thread_members = self.thread_members.lock().await;
            thread_members
                .values()
                .filter(|member| member.id.user == user_id)
                .map(|member| member.id.thread.clone())
                .collect::<Vec<String>>()
        };

        let channels = self.channels.lock().await;
        Ok(thread_ids
            .into_iter()
            .filter(|thread_id| {
                matches!(
                    channels.get(thread_id),
                    Some(Channel::Thread { server, .. }) if server == server_id
                )
            })
            .collect())
    }

    /// Delete all membership rows for a thread.
    async fn delete_all_thread_memberships(&self, thread_id: &str) -> Result<()> {
        let mut thread_members = self.thread_members.lock().await;
        thread_members.retain(|key, _| key.thread != thread_id);

        Ok(())
    }
}
