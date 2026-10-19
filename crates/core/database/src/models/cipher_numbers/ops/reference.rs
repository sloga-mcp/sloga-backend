use revolt_result::Result;

use crate::CipherNumber;
use crate::ReferenceDb;

use super::AbstractCipherNumbers;

/// Convert a row count to the trait's `u32`
fn count_to_u32(count: usize) -> Result<u32> {
    u32::try_from(count).map_err(|_| create_database_error!("count", "cipher_numbers"))
}

#[async_trait]
impl AbstractCipherNumbers for ReferenceDb {
    async fn claim_cipher_number(&self, order_id: &str, cap: u32) -> Result<Option<u32>> {
        // A zero cap is a misconfiguration, never "sold out"
        if cap == 0 {
            return Err(create_database_error!(
                "claim (cipher_cap is 0)",
                "cipher_numbers"
            ));
        }

        // The whole find-then-claim runs while the map mutex is held, which
        // is this driver's equivalent of Mongo's find_one_and_update.
        let mut numbers = self.cipher_numbers.lock().await;

        // Resume: an order that already holds a number keeps it (the Mongo
        // driver's unique partial order_id index gives the same guarantee)
        if let Some(row) = numbers
            .values()
            .find(|row| row.order_id.as_deref() == Some(order_id))
        {
            return Ok(Some(row.number));
        }

        let next = numbers
            .values()
            .filter(|row| row.number <= cap && row.order_id.is_none())
            .map(|row| row.number)
            .min();

        let Some(number) = next else {
            return Ok(None);
        };

        let row = numbers
            .get_mut(&number)
            .expect("claimed number was just read from this map");
        row.order_id = Some(order_id.to_string());

        Ok(Some(number))
    }

    async fn fetch_cipher_number_by_order(&self, order_id: &str) -> Result<Option<u32>> {
        let numbers = self.cipher_numbers.lock().await;
        Ok(numbers
            .values()
            .find(|row| row.order_id.as_deref() == Some(order_id))
            .map(|row| row.number))
    }

    async fn fetch_cipher_number_row_by_order(
        &self,
        order_id: &str,
    ) -> Result<Option<CipherNumber>> {
        let numbers = self.cipher_numbers.lock().await;
        Ok(numbers
            .values()
            .find(|row| row.order_id.as_deref() == Some(order_id))
            .cloned())
    }

    async fn mark_cipher_number_release(&self, order_id: &str, at: i64) -> Result<bool> {
        // Find and set while the map mutex is held; the first time stays
        let mut numbers = self.cipher_numbers.lock().await;
        match numbers
            .values_mut()
            .find(|row| row.order_id.as_deref() == Some(order_id))
        {
            Some(row) => {
                row.release_pending_at.get_or_insert(at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn cancel_cipher_number_release(&self, order_id: &str) -> Result<bool> {
        // Find and unset while the map mutex is held; `order_id` stays
        let mut numbers = self.cipher_numbers.lock().await;
        Ok(numbers
            .values_mut()
            .find(|row| row.order_id.as_deref() == Some(order_id))
            .and_then(|row| row.release_pending_at.take())
            .is_some())
    }

    async fn release_cipher_number(&self, order_id: &str) -> Result<bool> {
        // Find and unset while the map mutex is held, as in claim
        let mut numbers = self.cipher_numbers.lock().await;
        match numbers
            .values_mut()
            .find(|row| row.order_id.as_deref() == Some(order_id))
        {
            Some(row) => {
                row.order_id = None;
                row.release_pending_at = None;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn fetch_cipher_numbers_release_pending(&self, limit: i64) -> Result<Vec<CipherNumber>> {
        let numbers = self.cipher_numbers.lock().await;
        let mut pending: Vec<CipherNumber> = numbers
            .values()
            .filter(|row| row.order_id.is_some() && row.release_pending_at.is_some())
            .cloned()
            .collect();
        pending.sort_by_key(|row| (row.release_pending_at, row.number));
        pending.truncate(usize::try_from(limit.max(0)).unwrap_or(usize::MAX));
        Ok(pending)
    }

    async fn count_claimed_cipher_numbers(&self) -> Result<u32> {
        let numbers = self.cipher_numbers.lock().await;
        count_to_u32(
            numbers
                .values()
                .filter(|row| row.order_id.is_some())
                .count(),
        )
    }

    async fn count_cipher_numbers(&self) -> Result<u32> {
        let numbers = self.cipher_numbers.lock().await;
        count_to_u32(numbers.len())
    }

    async fn seed_cipher_numbers(&self, cap: u32) -> Result<()> {
        let mut numbers = self.cipher_numbers.lock().await;
        for number in 1..=cap {
            // An existing row, claimed or not, is left as it is
            numbers.entry(number).or_insert(CipherNumber {
                number,
                order_id: None,
                release_pending_at: None,
            });
        }
        Ok(())
    }
}
