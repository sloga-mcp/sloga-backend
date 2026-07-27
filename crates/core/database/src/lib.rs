#[macro_use]
extern crate serde;

#[macro_use]
extern crate async_recursion;

#[macro_use]
extern crate async_trait;

#[macro_use]
extern crate log;

#[macro_use]
extern crate revolt_optional_struct;

#[macro_use]
extern crate revolt_result;

pub use iso8601_timestamp;

#[cfg(feature = "mongodb")]
pub use mongodb;

#[cfg(feature = "mongodb")]
#[macro_use]
extern crate bson;

#[cfg(not(feature = "tokio-runtime"))]
compile_error!("tokio-runtime feature must be enabled.");

#[macro_export]
#[cfg(debug_assertions)]
macro_rules! query {
    ( $self: ident, $type: ident, $collection: expr, $($rest:expr),+ ) => {
        Ok($self.$type($collection, $($rest),+).await.unwrap())
    };
}

#[macro_export]
#[cfg(not(debug_assertions))]
macro_rules! query {
    ( $self: ident, $type: ident, $collection: expr, $($rest:expr),+ ) => {
        $self.$type($collection, $($rest),+).await
            .map_err(|err| {
                revolt_config::capture_internal_error!(err);
                create_database_error!(stringify!($type), $collection)
            })
    };
}

macro_rules! database_derived {
    ( $( $item:item )+ ) => {
        $(
            #[derive(Clone)]
            $item
        )+
    };
}

macro_rules! auto_derived {
    ( $( $item:item )+ ) => {
        $(
            #[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
            $item
        )+
    };
}

macro_rules! auto_derived_partial {
    ( $item:item, $name:expr ) => {
        #[derive(OptionalStruct, Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
        #[optional_derive(Serialize, Deserialize, Debug, Clone, Default, Eq, PartialEq)]
        #[optional_name = $name]
        #[opt_skip_serializing_none]
        #[opt_some_priority]
        $item
    };
}

mod drivers;
pub use drivers::*;

#[cfg(test)]
macro_rules! database_test {
    ( | $db: ident | $test:expr ) => {
        let db = $crate::DatabaseInfo::Test(format!(
            "{}:{}",
            file!().replace('/', "_").replace(".rs", ""),
            line!()
        ))
        .connect()
        .await
        .expect("Database connection failed.");

        db.drop_database().await;

        // The trailing `drop_database()` below never runs when the test body
        // panics; this guard covers the unwind path.
        //
        // It cannot cover the other leak: the database is named after this
        // invocation's line number, so moving the call orphans the old
        // database under a name no later run will ever regenerate. Sweep
        // those with `scripts/drop-test-databases.sh`.
        let guard = $crate::test_teardown::TestDatabaseGuard::arm(&db).await;

        #[allow(clippy::redundant_closure_call)]
        (|$db: $crate::Database| $test)(db.clone()).await;

        db.drop_database().await;
        guard.disarm();
    };
}

/// Deleting the throwaway databases the test harnesses create. Gated so that
/// nothing able to drop a database is linked into a production binary.
#[cfg(any(test, feature = "test-teardown"))]
pub mod test_teardown;

mod models;
pub mod util;
pub use models::*;

pub mod events;
#[cfg(feature = "tasks")]
pub mod tasks;

mod amqp;
pub use amqp::amqp::AMQP;

#[cfg(feature = "voice")]
pub mod voice;


/// Utility function to check if a boolean value is false
pub fn if_false(t: &bool) -> bool {
    !t
}

/// Utility function to check if an option doesnt contain true
pub fn if_option_false(t: &Option<bool>) -> bool {
    t != &Some(true)
}

/// Utility function to check if a u32 is zero
pub fn if_zero_u32(t: &u32) -> bool {
    t == &0
}

/// Utility function to check if an i64 is zero
pub fn if_zero_i64(t: &i64) -> bool {
    *t == 0
}
