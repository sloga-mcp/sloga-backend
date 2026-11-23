use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{Passkey, ReferenceDb};

use super::AbstractPasskeys;

#[async_trait]
impl AbstractPasskeys for ReferenceDb {
    async fn insert_passkey(&self, passkey: &Passkey) -> Result<()> {
        // Mirrors the unique indexes on `_id` and `credential_id`. The lock
        // is held across the check and the insert.
        let mut passkeys = self.passkeys.lock().await;
        if passkeys.contains_key(&passkey.id)
            || passkeys
                .values()
                .any(|row| row.credential_id == passkey.credential_id)
        {
            Err(create_database_error!("insert", "passkeys"))
        } else {
            passkeys.insert(passkey.id.clone(), passkey.clone());
            Ok(())
        }
    }

    async fn fetch_passkey(&self, user_id: &str, id: &str) -> Result<Passkey> {
        let passkeys = self.passkeys.lock().await;
        passkeys
            .get(id)
            .filter(|row| row.user_id == user_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_passkeys(&self, user_id: &str) -> Result<Vec<Passkey>> {
        let passkeys = self.passkeys.lock().await;
        let mut rows: Vec<Passkey> = passkeys
            .values()
            .filter(|row| row.user_id == user_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(rows)
    }

    async fn fetch_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<Passkey>> {
        let passkeys = self.passkeys.lock().await;
        Ok(passkeys
            .values()
            .find(|row| row.credential_id == credential_id)
            .cloned())
    }

    async fn count_passkeys(&self, user_id: &str) -> Result<u64> {
        let passkeys = self.passkeys.lock().await;
        Ok(passkeys
            .values()
            .filter(|row| row.user_id == user_id)
            .count() as u64)
    }

    async fn update_passkey_after_use(
        &self,
        id: &str,
        expected_credential: &str,
        credential: &str,
        last_used_at: Timestamp,
    ) -> Result<bool> {
        // The lock is held across the comparison and the write
        let mut passkeys = self.passkeys.lock().await;
        match passkeys.get_mut(id) {
            Some(row) if row.credential == expected_credential => {
                row.credential = credential.to_string();
                row.last_used_at = Some(last_used_at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn rename_passkey(&self, user_id: &str, id: &str, name: &str) -> Result<()> {
        let mut passkeys = self.passkeys.lock().await;
        match passkeys.get_mut(id) {
            Some(row) if row.user_id == user_id => {
                row.name = name.to_string();
                Ok(())
            }
            _ => Err(create_error!(NotFound)),
        }
    }

    async fn delete_passkey(&self, user_id: &str, id: &str) -> Result<()> {
        let mut passkeys = self.passkeys.lock().await;
        if passkeys.get(id).is_some_and(|row| row.user_id == user_id) {
            passkeys.remove(id);
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_passkeys_for_user(&self, user_id: &str) -> Result<()> {
        let mut passkeys = self.passkeys.lock().await;
        passkeys.retain(|_, row| row.user_id != user_id);
        Ok(())
    }
}
