use revolt_database::{now_ms, Database, User};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_result::Result;
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

use super::{refuse_bots, write_rules};

/// # Set Contributor Preferences
///
/// Hide or show the caller's name on this server's tanks and goals. A hidden
/// contributor shows as Anonymous to everyone, the server owner included.
/// One setting per server (BR10), so it carries over when a launch goal
/// becomes a tank. Members who can see the server.
#[openapi(tag = "Prot")]
#[put("/servers/<server_id>/contributor", data = "<data>")]
pub async fn set_prot_contributor_prefs(
    db: &State<Database>,
    user: User,
    server_id: &str,
    data: Json<v0::DataProtContributorPrefs>,
) -> Result<EmptyResponse> {
    refuse_bots(&user)?;
    // The engine takes no rules here; the load still refuses an invalid
    // config, like every other Prot route (11.1)
    write_rules().await?;

    engine::tank::set_prot_contributor_prefs(db, &user, server_id, data.into_inner(), now_ms())
        .await?;
    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use revolt_models::v0;
    use rocket::http::{Method, Status};
    use serde_json::json;

    use super::super::tests::{call, ok_json, refused, World, TARGET};

    async fn contributors(
        w: &World,
        caller: &super::super::tests::Caller,
    ) -> Vec<v0::ProtContributorView> {
        let body =
            ok_json(call(&w.harness, caller, Method::Get, &w.tank_path("tank"), None).await).await;
        let view: v0::ProtTankView = serde_json::from_value(body).expect("`ProtTankView`");
        view.contributors
    }

    /// Hiding is per server and binds the owner too: a hidden contributor's
    /// line keeps its amount but carries no id, for the owner and for other
    /// members; the contributor still sees their own line marked. Showing
    /// the name again restores it. A non-member is refused like a missing
    /// server.
    #[test]
    fn hidden_contributors_are_anonymous_even_to_the_owner() {
        crate::util::test::rt().block_on(hidden_contributors_are_anonymous_even_to_the_owner_case())
    }

    async fn hidden_contributors_are_anonymous_even_to_the_owner_case() {
        let w = World::new().await;
        let h = &w.harness;
        let path = w.server_path("contributor");

        let response = call(
            h,
            &w.backer,
            Method::Put,
            &path,
            Some(json!({ "hidden": true })),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);

        for caller in [&w.owner, &w.member] {
            let lines = contributors(&w, caller).await;
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0].user_id, None);
            assert!(lines[0].hidden);
            assert!(!lines[0].you);
            assert_eq!(lines[0].amount, TARGET);
        }
        let own = contributors(&w, &w.backer).await;
        assert_eq!(own[0].user_id, None);
        assert!(own[0].hidden && own[0].you);

        let response = call(
            h,
            &w.backer,
            Method::Put,
            &path,
            Some(json!({ "hidden": false })),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
        let lines = contributors(&w, &w.owner).await;
        assert_eq!(lines[0].user_id.as_deref(), Some(w.backer.user.id.as_str()));
        assert!(!lines[0].hidden);

        let response = call(
            h,
            &w.stranger,
            Method::Put,
            &path,
            Some(json!({ "hidden": true })),
        )
        .await;
        refused(response, Status::NotFound, "NotFound").await;
        assert!(h
            .db
            .fetch_prot_contributor_prefs(&w.server.id, std::slice::from_ref(&w.stranger.user.id))
            .await
            .expect("prefs")
            .is_empty());
    }
}
