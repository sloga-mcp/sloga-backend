//! One-off ops tool: provision the first-party Sloga Helper bot without a
//! session token (email verification is live, so throwaway operator sessions
//! are no longer mintable; same no-token pattern as seed_stickers). Creates
//! the bot under an existing owner account, marks it public, and writes the
//! daemon env file directly — the token is NEVER printed.
//!
//! Usage: provision_sloga_helper <owner_user_id> <username> <env_out_path>
//! Run from the stoatchat root so Revolt.toml / Revolt.overrides.toml resolve.

use revolt_database::{Bot, DatabaseInfo, PartialBot};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let owner_id = args
        .next()
        .expect("usage: provision_sloga_helper <owner_user_id> <username> <env_out_path>");
    let username = args.next().expect("missing bot username");
    let env_out = args.next().expect("missing env output path");

    // Claim the env file BEFORE any DB side effect: create_new = atomic
    // no-clobber (an existing provisioned bot's credentials are never
    // overwritten), 0600 from birth (write+chmod would leave a umask
    // window on the token), and a refused run must not orphan a live bot
    // whose token was never recorded.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&env_out).unwrap_or_else(|error| {
        eprintln!("cannot create {env_out} ({error}) — refusing to overwrite an existing file");
        std::process::exit(1);
    });

    let db = DatabaseInfo::Auto.connect().await.expect("database");
    let owner = db.fetch_user(&owner_id).await.expect("owner user");

    let (mut bot, user) = Bot::create(&db, username, &owner, None)
        .await
        .expect("bot create");

    bot.update(
        &db,
        PartialBot {
            public: Some(true),
            ..Default::default()
        },
        vec![],
    )
    .await
    .expect("mark public");

    let env = format!(
        "SLOGA_HELPER_BOT_ID={}\nSLOGA_HELPER_TOKEN={}\n",
        bot.id, bot.token
    );
    use std::io::Write;
    file.write_all(env.as_bytes()).expect("write env file");

    // Id only — the token lives solely in the env file.
    println!("provisioned bot '{}' with id {}", user.username, bot.id);
    println!("env written to {env_out}");
    println!("next: add [[api.apps.catalog]] entry with bot_id = \"{}\"", bot.id);
}
