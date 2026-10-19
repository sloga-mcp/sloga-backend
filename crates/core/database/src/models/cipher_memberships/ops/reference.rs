use revolt_result::Result;

use crate::CipherMembership;
use crate::ReferenceDb;

use super::AbstractCipherMemberships;

#[async_trait]
impl AbstractCipherMemberships for ReferenceDb {
    async fn insert_cipher_membership(&self, m: &CipherMembership) -> Result<bool> {
        let mut memberships = self.cipher_memberships.lock().await;
        if memberships.contains_key(&m.user_id) {
            return Ok(false);
        }

        // Mirrors the unique `number` index on MongoDB
        if memberships.values().any(|row| row.number == m.number) {
            return Err(create_database_error!("insert", "cipher_membership"));
        }

        memberships.insert(m.user_id.clone(), m.clone());
        Ok(true)
    }

    async fn fetch_cipher_membership(&self, user_id: &str) -> Result<Option<CipherMembership>> {
        let memberships = self.cipher_memberships.lock().await;
        Ok(memberships.get(user_id).cloned())
    }

    async fn update_cipher_membership_if_version(
        &self,
        m: &CipherMembership,
        expected: u64,
    ) -> Result<bool> {
        let next = expected
            .checked_add(1)
            .ok_or_else(|| create_database_error!("replace", "cipher_membership"))?;

        // The check and the write run while the map mutex is held, which is
        // this driver's equivalent of Mongo's filtered replace_one
        let mut memberships = self.cipher_memberships.lock().await;
        if memberships
            .get(&m.user_id)
            .is_none_or(|row| row.version != expected)
        {
            return Ok(false);
        }

        // Mirrors the unique `number` index on MongoDB
        if memberships
            .values()
            .any(|row| row.user_id != m.user_id && row.number == m.number)
        {
            return Err(create_database_error!("replace", "cipher_membership"));
        }

        memberships.insert(
            m.user_id.clone(),
            CipherMembership {
                version: next,
                ..m.clone()
            },
        );
        Ok(true)
    }

    async fn delete_cipher_membership(&self, user_id: &str) -> Result<()> {
        let mut memberships = self.cipher_memberships.lock().await;
        memberships.remove(user_id);
        Ok(())
    }

    async fn delete_cipher_membership_if_version(
        &self,
        user_id: &str,
        expected: u64,
    ) -> Result<bool> {
        // The check and the removal run while the map mutex is held
        let mut memberships = self.cipher_memberships.lock().await;
        if memberships
            .get(user_id)
            .is_none_or(|row| row.version != expected)
        {
            return Ok(false);
        }

        memberships.remove(user_id);
        Ok(true)
    }
}
