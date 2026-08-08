//! One-off ops tool: rename a user account, for moderation.
//!
//! Goes through `User::update_username` rather than writing the collection
//! directly. That matters for three reasons a raw update would miss: the new
//! name is validated (including against the slur filter), the discriminator is
//! reassigned out of the free pool instead of colliding, and a `UserUpdate`
//! event reaches connected clients so nobody keeps seeing the old name.
//!
//! Usage: rename_user <user_id> <expected_current_username> <new_username>
//! Run from the stoatchat root so Revolt.toml / Revolt.overrides.toml resolve.

use revolt_database::DatabaseInfo;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let usage = "usage: rename_user <user_id> <expected_current_username> <new_username>";
    let user_id = args.next().expect(usage);
    let expected = args.next().expect(usage);
    let new_username = args.next().expect(usage);

    // This tool exists to edit production. `DatabaseInfo::Auto` branches on
    // TEST_DB, so leaving it set would quietly point the rename at a throwaway
    // database and then report success against nothing.
    if std::env::var("TEST_DB").is_ok() {
        eprintln!("TEST_DB is set — refusing to run against a throwaway database");
        std::process::exit(1);
    }

    let db = DatabaseInfo::Auto.connect().await.expect("database");
    let mut user = db.fetch_user(&user_id).await.expect("user");

    // A mistyped id would otherwise rename an uninvolved account, which is
    // far worse than the rename not happening.
    if user.username != expected {
        eprintln!(
            "refusing: {user_id} is currently '{}#{}', expected '{expected}'",
            user.username, user.discriminator
        );
        std::process::exit(1);
    }

    println!("before: {}#{}", user.username, user.discriminator);

    user.update_username(&db, new_username)
        .await
        .expect("rename");

    let after = db.fetch_user(&user_id).await.expect("re-fetch");
    println!("after:  {}#{}", after.username, after.discriminator);
}
