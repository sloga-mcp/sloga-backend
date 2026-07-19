use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::Result;
use rocket::{serde::json::Json, State};

/// # List App Catalog
///
/// Authenticated: the operator-curated list of first-party bots shown in the
/// client's "Add apps" panel. Entries that fail to resolve or are not public
/// are skipped fail-soft — a misconfigured catalog id must never break the
/// endpoint for everyone.
#[openapi(tag = "Discovery")]
#[get("/apps")]
pub async fn apps(db: &State<Database>, _user: User) -> Result<Json<v0::AppCatalogResponse>> {
    let catalog = revolt_config::config().await.api.apps.catalog;

    let mut apps = Vec::with_capacity(catalog.len());
    for entry in catalog {
        let Ok(bot) = db.fetch_bot(&entry.bot_id).await else {
            continue;
        };
        if !bot.public {
            continue;
        }
        let Ok(bot_user) = db.fetch_user(&bot.id).await else {
            continue;
        };

        apps.push(v0::AppCatalogEntry {
            tagline: entry.tagline,
            bot: bot.into_public_bot(bot_user),
        });
    }

    Ok(Json(v0::AppCatalogResponse { apps }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_config::ApiAppCatalogEntry;
    use revolt_database::{Bot, BotInformation, PartialUser, User};
    use revolt_models::v0;
    use rocket::http::{Header, Status};
    use ulid::Ulid;

    /// The catalog config references bot ids, but `overwrite_config` is
    /// once-per-process and must run BEFORE the harness primes the config
    /// cache — so the ids are pre-generated here and the bot rows are
    /// inserted manually afterwards (`Bot::create` mints its own id).
    /// Process isolation comes from nextest.
    #[rocket::async_test]
    async fn catalog_serves_public_bots_and_skips_bad_entries() {
        let public_id = Ulid::new().to_string();
        let private_id = Ulid::new().to_string();
        let dangling_id = Ulid::new().to_string();

        revolt_config::overwrite_config(|settings| {
            settings.api.apps.catalog = vec![
                ApiAppCatalogEntry {
                    bot_id: public_id.clone(),
                    tagline: Some("Giveaways and fun".to_string()),
                },
                ApiAppCatalogEntry {
                    bot_id: private_id.clone(),
                    tagline: None,
                },
                ApiAppCatalogEntry {
                    bot_id: dangling_id.clone(),
                    tagline: None,
                },
            ];
        })
        .await;

        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;

        for (id, public) in [(&public_id, true), (&private_id, false)] {
            User::create(
                &harness.db,
                TestHarness::rand_string(),
                Some(id.to_string()),
                Some(PartialUser {
                    bot: Some(BotInformation {
                        owner: owner.id.to_string(),
                    }),
                    ..Default::default()
                }),
            )
            .await
            .expect("bot `User`");

            harness
                .db
                .insert_bot(&Bot {
                    id: id.to_string(),
                    owner: owner.id.to_string(),
                    token: TestHarness::rand_string(),
                    public,
                    ..Default::default()
                })
                .await
                .expect("`Bot`");
        }

        // Unauthenticated requests are rejected — this is a client surface,
        // not a public directory.
        let response = harness.client.get("/discover/apps").dispatch().await;
        assert_eq!(response.status(), Status::Unauthorized);

        let response = harness
            .client
            .get("/discover/apps")
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Raw JSON so absent-field assertions cover the wire shape, not the
        // typed struct.
        let body: serde_json::Value =
            serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
        let apps = body["apps"].as_array().expect("apps array");

        // Only the public bot serves; the private and dangling entries are
        // skipped without failing the route.
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0]["bot"]["_id"].as_str(), Some(public_id.as_str()));
        assert_eq!(apps[0]["tagline"].as_str(), Some("Giveaways and fun"));

        // Strict whitelist: no token / owner / interactions_url on the wire.
        let bot = apps[0]["bot"].as_object().expect("bot object");
        for leaked in ["token", "owner", "interactions_url"] {
            assert!(!bot.contains_key(leaked), "leaked field: {leaked}");
        }

        // Typed round-trip stays valid.
        serde_json::from_value::<v0::AppCatalogResponse>(body).expect("typed response");
    }
}
