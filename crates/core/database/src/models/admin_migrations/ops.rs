#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[cfg(all(test, feature = "mongodb"))]
pub(crate) use self::mongodb::{
    create_prot_indexes, create_prot_store_indexes, create_prot_tank_indexes, PROT_COLLECTIONS,
    PROT_STORE_COLLECTIONS, PROT_TANK_COLLECTIONS,
};
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
