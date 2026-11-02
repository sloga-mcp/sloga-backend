use revolt_result::Result;
use std::collections::HashMap;

use crate::CipherMembership;
use crate::ReferenceDb;

use super::AbstractCipherMemberships;
use super::MEMBERSHIPS_PAGE_MAX;

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

    async fn fetch_cipher_membership_by_number(
        &self,
        number: u32,
    ) -> Result<Option<CipherMembership>> {
        let memberships = self.cipher_memberships.lock().await;
        Ok(memberships
            .values()
            .find(|row| row.number == number)
            .cloned())
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

    async fn fetch_cipher_memberships_page(
        &self,
        after_user_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CipherMembership>> {
        // Refused as on MongoDB
        if !(1..=MEMBERSHIPS_PAGE_MAX).contains(&limit) {
            return Err(create_error!(InternalError));
        }

        let memberships = self.cipher_memberships.lock().await;
        let mut rows: Vec<CipherMembership> = memberships
            .values()
            .filter(|row| after_user_id.is_none_or(|after| row.user_id.as_str() > after))
            .cloned()
            .collect();

        // Byte order, as Mongo compares the string `_id`s
        rows.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        rows.truncate(limit.try_into().unwrap_or(usize::MAX));
        Ok(rows)
    }
}

/// The Reference twin of bump_cipher_membership_version_in, on a map the caller has locked
///
/// Changes only `version`, to `expected + 1`, when the user's row is at
/// `expected`; false when the version moved or the row is gone (never
/// inserts). A version that cannot be bumped any further is false too (the
/// MongoDB method errors there; neither is reachable in practice).
pub(crate) fn bump_cipher_membership_version_locked(
    memberships: &mut HashMap<String, CipherMembership>,
    user_id: &str,
    expected: u64,
) -> bool {
    match memberships.get_mut(user_id) {
        Some(row) if row.version == expected => match expected.checked_add(1) {
            Some(next) => {
                row.version = next;
                true
            }
            None => false,
        },
        _ => false,
    }
}
