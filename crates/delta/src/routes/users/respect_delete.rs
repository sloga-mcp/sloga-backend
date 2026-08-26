use revolt_database::{util::reference::Reference, Database, User};
use revolt_result::{create_error, Result};
use rocket::State;

/// # Delete Respect
///
/// Delete a respect entry from a user's wall. Allowed for the entry's
/// author (retract your words — even after unfriending), the wall's owner
/// (curate your own wall), and platform moderation.
///
/// Idempotent: deleting an entry that does not exist succeeds.
#[openapi(tag = "Respect")]
#[delete("/<target>/respect/<author>")]
pub async fn respect_delete(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    author: Reference<'_>,
) -> Result<()> {
    // Authorization is on raw path ids — no user fetch needed, and no
    // existence oracle for unauthorized callers.
    if user.id != author.id && user.id != target.id && !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    if let Some(entry) = db.fetch_respect(target.id, author.id).await? {
        db.delete_respect(&entry.id).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_database::Respect;
    use rocket::http::Status;

    #[test]
    fn owner_curates_stranger_cannot() {
        crate::util::test::rt().block_on(owner_curates_stranger_cannot_case())
    }

    async fn owner_curates_stranger_cannot_case() {
        let harness = TestHarness::new().await;
        let (_, session_owner, owner) = harness.new_user().await;
        let (_, _session_author, author) = harness.new_user().await;
        let (_, session_stranger, _stranger) = harness.new_user().await;

        harness
            .db
            .insert_respect(&Respect {
                id: "01RSPCTDEL00000000000000001".to_string(),
                target_id: owner.id.clone(),
                author_id: author.id.clone(),
                content: "solid".to_string(),
                updated_at: 1_000,
            })
            .await
            .expect("insert");

        // An unrelated user may not delete it.
        let response = TestHarness::with_session(
            session_stranger,
            harness
                .client
                .delete(format!("/users/{}/respect/{}", owner.id, author.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Forbidden);

        // The wall's owner may delete anything on their wall.
        let response = TestHarness::with_session(
            session_owner.clone(),
            harness
                .client
                .delete(format!("/users/{}/respect/{}", owner.id, author.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        assert!(harness
            .db
            .fetch_respect(&owner.id, &author.id)
            .await
            .expect("fetch")
            .is_none());

        // Idempotent: deleting again still succeeds.
        let response = TestHarness::with_session(
            session_owner,
            harness
                .client
                .delete(format!("/users/{}/respect/{}", owner.id, author.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
    }
}
