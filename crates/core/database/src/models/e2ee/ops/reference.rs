use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{
    AbstractE2EE, E2EEBackup, E2EEBlob, E2EEEnvelope, E2EEIdentity, E2EEOneTimeKey, ReferenceDb,
};

#[async_trait]
impl AbstractE2EE for ReferenceDb {
    async fn fetch_e2ee_identity(&self, user_id: &str, device_id: &str) -> Result<E2EEIdentity> {
        let identities = self.e2ee_identities.lock().await;
        identities
            .get(&E2EEIdentity::composite_id(user_id, device_id))
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_e2ee_identities(&self, user_id: &str) -> Result<Vec<E2EEIdentity>> {
        let identities = self.e2ee_identities.lock().await;
        let mut result: Vec<E2EEIdentity> = identities
            .values()
            .filter(|identity| identity.user_id == user_id)
            .cloned()
            .collect();
        result.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        Ok(result)
    }

    async fn insert_e2ee_identity(&self, identity: &E2EEIdentity) -> Result<()> {
        let mut identities = self.e2ee_identities.lock().await;
        if identities.contains_key(&identity.id) {
            return Err(create_error!(InvalidOperation));
        }

        identities.insert(identity.id.clone(), identity.clone());
        Ok(())
    }

    async fn replace_e2ee_identity(&self, identity: &E2EEIdentity) -> Result<()> {
        let mut identities = self.e2ee_identities.lock().await;
        if !identities.contains_key(&identity.id) {
            return Err(create_error!(NotFound));
        }

        identities.insert(identity.id.clone(), identity.clone());
        Ok(())
    }

    async fn update_e2ee_identity_session(
        &self,
        user_id: &str,
        device_id: &str,
        session_id: &str,
        at: Timestamp,
    ) -> Result<()> {
        let mut identities = self.e2ee_identities.lock().await;
        let identity = identities
            .get_mut(&E2EEIdentity::composite_id(user_id, device_id))
            .ok_or_else(|| create_error!(NotFound))?;

        identity.last_session_id = session_id.to_string();
        identity.last_seen_at = at;
        Ok(())
    }

    async fn delete_e2ee_device(&self, user_id: &str, device_id: &str) -> Result<bool> {
        let existed = {
            let mut identities = self.e2ee_identities.lock().await;
            identities
                .remove(&E2EEIdentity::composite_id(user_id, device_id))
                .is_some()
        };

        {
            let mut keys = self.e2ee_one_time_keys.lock().await;
            keys.retain(|_, key| !(key.user_id == user_id && key.device_id == device_id));
        }

        {
            let mut queue = self.e2ee_queue.lock().await;
            queue.retain(|_, envelope| {
                !(envelope.recipient_user_id == user_id
                    && envelope.recipient_device_id == device_id)
            });
        }

        Ok(existed)
    }

    async fn delete_all_e2ee_devices(&self, user_id: &str) -> Result<Vec<String>> {
        let device_ids: Vec<String> = {
            let identities = self.e2ee_identities.lock().await;
            identities
                .values()
                .filter(|identity| identity.user_id == user_id)
                .map(|identity| identity.device_id.clone())
                .collect()
        };

        for device_id in &device_ids {
            self.delete_e2ee_device(user_id, device_id).await?;
        }

        Ok(device_ids)
    }

    async fn insert_e2ee_one_time_keys(&self, new_keys: &[E2EEOneTimeKey]) -> Result<()> {
        let mut keys = self.e2ee_one_time_keys.lock().await;
        for key in new_keys {
            keys.insert(key.id.clone(), key.clone());
        }
        Ok(())
    }

    async fn delete_e2ee_one_time_keys(&self, user_id: &str, device_id: &str) -> Result<usize> {
        let mut keys = self.e2ee_one_time_keys.lock().await;
        let before = keys.len();
        keys.retain(|_, key| !(key.user_id == user_id && key.device_id == device_id));
        Ok(before - keys.len())
    }

    async fn count_e2ee_one_time_keys(&self, user_id: &str, device_id: &str) -> Result<u64> {
        let keys = self.e2ee_one_time_keys.lock().await;
        Ok(keys
            .values()
            .filter(|key| key.user_id == user_id && key.device_id == device_id)
            .count() as u64)
    }

    async fn count_e2ee_one_time_keys_among(
        &self,
        user_id: &str,
        device_id: &str,
        key_ids: &[String],
    ) -> Result<u64> {
        let keys = self.e2ee_one_time_keys.lock().await;
        Ok(key_ids
            .iter()
            .filter(|key_id| {
                keys.contains_key(&E2EEOneTimeKey::composite_id(user_id, device_id, key_id))
            })
            .count() as u64)
    }

    async fn consume_e2ee_one_time_key(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<E2EEOneTimeKey>> {
        // The mutex makes take-and-remove atomic, matching Mongo's
        // find_one_and_delete
        let mut keys = self.e2ee_one_time_keys.lock().await;
        let id = keys
            .values()
            .filter(|key| key.user_id == user_id && key.device_id == device_id)
            .map(|key| key.id.clone())
            .min();

        Ok(id.and_then(|id| keys.remove(&id)))
    }

    async fn insert_e2ee_envelopes(&self, envelopes: &[E2EEEnvelope]) -> Result<()> {
        let mut queue = self.e2ee_queue.lock().await;
        for envelope in envelopes {
            queue.insert(envelope.id.clone(), envelope.clone());
        }
        Ok(())
    }

    async fn count_e2ee_envelopes(
        &self,
        recipient_user_id: &str,
        recipient_device_id: &str,
    ) -> Result<u64> {
        let queue = self.e2ee_queue.lock().await;
        Ok(queue
            .values()
            .filter(|envelope| {
                envelope.recipient_user_id == recipient_user_id
                    && envelope.recipient_device_id == recipient_device_id
            })
            .count() as u64)
    }

    async fn fetch_e2ee_envelopes(
        &self,
        recipient_user_id: &str,
        recipient_device_id: &str,
        limit: i64,
    ) -> Result<Vec<E2EEEnvelope>> {
        let queue = self.e2ee_queue.lock().await;
        let mut envelopes: Vec<E2EEEnvelope> = queue
            .values()
            .filter(|envelope| {
                envelope.recipient_user_id == recipient_user_id
                    && envelope.recipient_device_id == recipient_device_id
            })
            .cloned()
            .collect();

        envelopes.sort_by(|a, b| a.id.cmp(&b.id));
        envelopes.truncate(limit.max(0) as usize);
        Ok(envelopes)
    }

    async fn delete_e2ee_envelope(
        &self,
        id: &str,
        recipient_user_id: &str,
        recipient_device_id: &str,
    ) -> Result<bool> {
        let mut queue = self.e2ee_queue.lock().await;
        match queue.get(id) {
            Some(envelope)
                if envelope.recipient_user_id == recipient_user_id
                    && envelope.recipient_device_id == recipient_device_id =>
            {
                queue.remove(id);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn delete_e2ee_envelopes_before(&self, threshold_id: &str) -> Result<usize> {
        let mut queue = self.e2ee_queue.lock().await;
        let before = queue.len();
        queue.retain(|id, _| id.as_str() >= threshold_id);
        Ok(before - queue.len())
    }

    async fn insert_e2ee_blob(&self, blob: &E2EEBlob) -> Result<()> {
        let mut blobs = self.e2ee_blobs.lock().await;
        if blobs.contains_key(&blob.id) {
            return Err(create_error!(InvalidOperation));
        }

        blobs.insert(blob.id.clone(), blob.clone());
        Ok(())
    }

    async fn fetch_e2ee_blob(&self, id: &str) -> Result<E2EEBlob> {
        let blobs = self.e2ee_blobs.lock().await;
        blobs
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn mark_e2ee_blob_fetched(
        &self,
        id: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<E2EEBlob> {
        // The mutex makes check-and-set atomic, matching Mongo's
        // find_one_and_update with an array filter
        let mut blobs = self.e2ee_blobs.lock().await;
        let blob = blobs.get_mut(id).ok_or_else(|| create_error!(NotFound))?;

        let recipient = blob
            .recipients
            .iter_mut()
            .find(|recipient| recipient.user_id == user_id && recipient.device_id == device_id)
            .ok_or_else(|| create_error!(NotFound))?;

        recipient.fetched = true;
        Ok(blob.clone())
    }

    async fn delete_e2ee_blob(&self, id: &str) -> Result<bool> {
        let mut blobs = self.e2ee_blobs.lock().await;
        Ok(blobs.remove(id).is_some())
    }

    async fn fetch_expired_e2ee_blobs(
        &self,
        threshold_id: &str,
        min_size: isize,
    ) -> Result<Vec<E2EEBlob>> {
        let blobs = self.e2ee_blobs.lock().await;
        let mut expired: Vec<E2EEBlob> = blobs
            .values()
            .filter(|blob| blob.id.as_str() < threshold_id && blob.size > min_size)
            .cloned()
            .collect();
        expired.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(expired)
    }

    async fn fetch_e2ee_backup(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<E2EEBackup>> {
        let backups = self.e2ee_backups.lock().await;
        Ok(backups
            .get(&E2EEBackup::composite_id(user_id, device_id))
            .cloned())
    }

    async fn fetch_e2ee_backups(&self, user_id: &str) -> Result<Vec<E2EEBackup>> {
        let backups = self.e2ee_backups.lock().await;
        let mut result: Vec<E2EEBackup> = backups
            .values()
            .filter(|backup| backup.user_id == user_id)
            .cloned()
            .collect();
        result.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        Ok(result)
    }

    async fn upsert_e2ee_backup(&self, backup: &E2EEBackup) -> Result<()> {
        let mut backups = self.e2ee_backups.lock().await;
        backups.insert(backup.id.clone(), backup.clone());
        Ok(())
    }

    async fn delete_e2ee_backup(&self, user_id: &str, device_id: &str) -> Result<bool> {
        let mut backups = self.e2ee_backups.lock().await;
        Ok(backups
            .remove(&E2EEBackup::composite_id(user_id, device_id))
            .is_some())
    }

    async fn delete_all_e2ee_backups(&self, user_id: &str) -> Result<usize> {
        let mut backups = self.e2ee_backups.lock().await;
        let before = backups.len();
        backups.retain(|_, backup| backup.user_id != user_id);
        Ok(before - backups.len())
    }
}
