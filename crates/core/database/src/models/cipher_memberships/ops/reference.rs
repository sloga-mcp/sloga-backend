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

    async fn update_cipher_membership(&self, m: &CipherMembership) -> Result<()> {
        let mut memberships = self.cipher_memberships.lock().await;
        match memberships.get_mut(&m.user_id) {
            Some(row) => {
                *row = m.clone();
                Ok(())
            }
            None => Err(create_error!(NotFound)),
        }
    }

    async fn delete_cipher_membership(&self, user_id: &str) -> Result<()> {
        let mut memberships = self.cipher_memberships.lock().await;
        memberships.remove(user_id);
        Ok(())
    }
}
