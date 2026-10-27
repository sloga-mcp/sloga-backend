#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[cfg(feature = "mongodb")]
pub(crate) use mongodb::{protected_nonce_index, PROTECTED_NONCE_INDEX_NAME};

#[async_trait]
pub trait AbstractMigrations: Sync + Send {
    #[cfg(test)]
    /// Drop the database
    async fn drop_database(&self);

    /// Migrate the database
    async fn migrate_database(&self) -> Result<(), ()>;
}
