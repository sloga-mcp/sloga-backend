#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[cfg(all(test, feature = "mongodb"))]
pub(crate) use self::mongodb::{create_prot_indexes, PROT_COLLECTIONS};

#[async_trait]
pub trait AbstractMigrations: Sync + Send {
    #[cfg(test)]
    /// Drop the database
    async fn drop_database(&self);

    /// Migrate the database
    async fn migrate_database(&self) -> Result<(), ()>;
}
