use revolt_database::{
    util::reference::Reference, CustomBadge, Database, FieldsUser, File, PartialUser, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket_empty::EmptyResponse;
use validator::Validate;

use rocket::{serde::json::Json, State};

/// # Set Custom Badge
///
/// Set a user's custom profile badge. Requires a privileged account.
/// Replacing the image marks the old one deleted; sending the current
/// image again keeps it and only changes the label.
#[openapi(tag = "User Information")]
#[put("/<target>/custom_badge", data = "<data>")]
pub async fn set_custom_badge(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataSetCustomBadge>,
) -> Result<EmptyResponse> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut target_user = target.as_user(db).await?;
    if target_user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // The deletion cascade has already run, so a badge set now would
    // never be cleaned up
    if target_user.flags.unwrap_or_default() & v0::UserFlags::Deleted as i32 != 0 {
        return Err(create_error!(NotFound));
    }

    let previous_id = target_user
        .custom_badge
        .as_ref()
        .map(|badge| badge.image.id.clone());

    log::info!(
        "AUDIT custom_badge_set: actor={} target={} image={} previous={:?} label={:?}",
        user.id,
        target_user.id,
        data.image,
        previous_id,
        data.label
    );

    // A file can only be claimed once, so the current image is reused as is
    let image = match &target_user.custom_badge {
        Some(badge) if badge.image.id == data.image => badge.image.clone(),
        _ => File::use_custom_badge(db, &data.image, &target_user.id, &user.id).await?,
    };

    let replaced = previous_id.filter(|id| *id != image.id);

    target_user
        .update(
            db,
            PartialUser {
                custom_badge: Some(CustomBadge {
                    image,
                    label: data.label,
                }),
                ..Default::default()
            },
            vec![],
        )
        .await?;

    if let Some(id) = replaced {
        // Best-effort: the new badge is already saved
        db.mark_attachment_as_deleted(&id).await.ok();
    }

    Ok(EmptyResponse)
}

/// # Delete Custom Badge
///
/// Remove a user's custom profile badge and mark its image deleted.
/// Requires a privileged account.
#[openapi(tag = "User Information")]
#[delete("/<target>/custom_badge")]
pub async fn delete_custom_badge(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let mut target_user = target.as_user(db).await?;
    let Some(image_id) = target_user
        .custom_badge
        .as_ref()
        .map(|badge| badge.image.id.clone())
    else {
        return Err(create_error!(NotFound));
    };

    log::info!(
        "AUDIT custom_badge_delete: actor={} target={} image={}",
        user.id,
        target_user.id,
        image_id
    );

    target_user
        .update(db, PartialUser::default(), vec![FieldsUser::CustomBadge])
        .await?;

    // Best-effort: the badge is already removed
    db.mark_attachment_as_deleted(&image_id).await.ok();

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_database::{File, Metadata, PartialUser, User};
    use rocket::http::{ContentType, Status};
    use serde_json::json;

    /// Seed an unclaimed file in the `icons` bucket, as Autumn leaves one
    /// after an upload
    async fn upload_icon(harness: &TestHarness, uploader: &User) -> String {
        use iso8601_timestamp::Timestamp;
        let id = ulid::Ulid::new().to_string();
        harness
            .db
            .insert_attachment(&File {
                id: id.clone(),
                tag: "icons".to_string(),
                filename: "badge.png".to_string(),
                hash: None,
                uploaded_at: Some(Timestamp::now_utc()),
                uploader_id: Some(uploader.id.clone()),
                used_for: None,
                deleted: None,
                reported: None,
                metadata: Metadata::File,
                content_type: "image/png".to_string(),
                size: 10,
                message_id: None,
                user_id: None,
                server_id: None,
                object_id: None,
            })
            .await
            .expect("insert icon");
        id
    }

    async fn is_deleted(harness: &TestHarness, id: &str) -> bool {
        harness
            .db
            .fetch_attachment("icons", id)
            .await
            .expect("fetch icon")
            .deleted
            .unwrap_or_default()
    }

    #[test]
    fn set_replace_and_delete() {
        crate::util::test::rt().block_on(set_replace_and_delete_case())
    }

    async fn set_replace_and_delete_case() {
        let harness = TestHarness::new().await;
        let (_, staff_session, mut staff) = harness.new_user().await;
        let (_, user_session, target) = harness.new_user().await;

        staff
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("privileged staff");

        let first = upload_icon(&harness, &staff).await;
        let path = format!("/users/{}/custom_badge", target.id);

        // An unprivileged account may not set a badge, not even its own
        let response = TestHarness::with_session(
            user_session,
            harness
                .client
                .put(path.clone())
                .header(ContentType::JSON)
                .body(json!({ "image": first, "label": "Founder" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::Forbidden);

        let response = TestHarness::with_session(
            staff_session.clone(),
            harness
                .client
                .put(path.clone())
                .header(ContentType::JSON)
                .body(json!({ "image": first, "label": "Founder" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);

        let badge = harness
            .db
            .fetch_user(&target.id)
            .await
            .expect("target")
            .custom_badge
            .expect("badge set");
        assert_eq!(badge.image.id, first);
        assert_eq!(badge.label, "Founder");

        // The same image again only changes the label
        let response = TestHarness::with_session(
            staff_session.clone(),
            harness
                .client
                .put(path.clone())
                .header(ContentType::JSON)
                .body(json!({ "image": first, "label": "Legend" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);

        let badge = harness
            .db
            .fetch_user(&target.id)
            .await
            .expect("target")
            .custom_badge
            .expect("badge kept");
        assert_eq!(badge.image.id, first);
        assert_eq!(badge.label, "Legend");
        assert!(!is_deleted(&harness, &first).await);

        // A new image replaces the old one, which is marked deleted
        let second = upload_icon(&harness, &staff).await;
        let response = TestHarness::with_session(
            staff_session.clone(),
            harness
                .client
                .put(path.clone())
                .header(ContentType::JSON)
                .body(json!({ "image": second, "label": "Legend" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
        assert!(is_deleted(&harness, &first).await);
        assert!(!is_deleted(&harness, &second).await);

        // A file claimed elsewhere cannot be reused
        let response = TestHarness::with_session(
            staff_session.clone(),
            harness
                .client
                .put(path.clone())
                .header(ContentType::JSON)
                .body(json!({ "image": first, "label": "Legend" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::NotFound);

        let response =
            TestHarness::with_session(staff_session.clone(), harness.client.delete(path.clone()))
                .await;
        assert_eq!(response.status(), Status::NoContent);
        assert!(harness
            .db
            .fetch_user(&target.id)
            .await
            .expect("target")
            .custom_badge
            .is_none());
        assert!(is_deleted(&harness, &second).await);

        // Nothing left to delete
        let response =
            TestHarness::with_session(staff_session, harness.client.delete(path.clone())).await;
        assert_eq!(response.status(), Status::NotFound);
    }
}
