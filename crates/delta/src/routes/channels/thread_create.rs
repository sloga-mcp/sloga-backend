use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Create Thread
///
/// Create a new thread under a server text channel.
///
/// The target channel must be a `TextChannel`; threads cannot be created under
/// DMs, groups or other threads.
#[openapi(tag = "Threads")]
#[post("/<target>/threads", data = "<data>")]
pub async fn create_thread(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataCreateThread>,
) -> Result<Json<v0::Channel>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;
    // Permissions are always evaluated against the parent text channel.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    let thread = Channel::create_thread(db, &channel, &user, None, data).await?;
    Ok(Json(thread.into()))
}

/// # Create Thread From Message
///
/// Create a new thread anchored to an existing message in a server text
/// channel. The message is stamped with the new thread's id.
#[openapi(tag = "Threads")]
#[post("/<target>/messages/<msg>/threads", data = "<data>")]
pub async fn create_thread_from_message(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    data: Json<v0::DataCreateThread>,
) -> Result<Json<v0::Channel>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;
    // Permissions are always evaluated against the parent text channel.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Ensure the message actually belongs to the target channel.
    let message = msg.as_message_in_channel(db, channel.id()).await?;
    let thread = Channel::create_thread(db, &channel, &user, Some(&message), data).await?;
    Ok(Json(thread.into()))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        util::bulk_permissions::BulkDatabasePermissionQuery, Channel, Member, PartialChannel,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::ErrorType;

    #[rocket::async_test]
    async fn create_thread_auto_joins_creator_and_delegates_permissions() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let thread = Channel::create_thread(
            &harness.db,
            &channel,
            &user,
            None,
            v0::DataCreateThread {
                name: "My Thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("thread created");

        // The thread hangs off the parent text channel.
        assert!(
            matches!(&thread, Channel::Thread { parent_channel, .. } if parent_channel == channel.id()),
            "thread should point at its parent channel"
        );

        // The creator is auto-joined.
        let members = harness
            .db
            .fetch_thread_members(thread.id())
            .await
            .expect("fetch members");
        assert!(
            members.iter().any(|member| member.id.user == user.id),
            "creator should be auto-joined to the thread"
        );

        // Permission checks delegate to the parent channel.
        let target = thread
            .permission_target(&harness.db)
            .await
            .expect("permission target");
        assert_eq!(
            target.id(),
            channel.id(),
            "a thread's permission target must be its parent channel"
        );
    }

    /// Exercises the exact bulk-permission path the pushd mass-mention
    /// consumer uses for a role/everyone mention inside a thread: the query is
    /// built from the THREAD's id, must not panic, and must evaluate the
    /// PARENT channel's overrides (a member denied ViewChannel on the parent
    /// must not be pushed for a thread mass mention).
    #[rocket::async_test]
    async fn thread_mass_mention_visibility_uses_parent_overrides() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, _, outsider) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&owner).await;
        let mut channel = harness.new_channel(&server).await;

        // Deny ViewChannel by default on the parent channel.
        channel
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view on parent");

        let thread = Channel::create_thread(
            &harness.db,
            &channel,
            &owner,
            None,
            v0::DataCreateThread {
                name: "Hidden Thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("thread created");

        // A plain member with no roles cannot see the (hidden) parent.
        let (member, _) = Member::create(&harness.db, &server, &outsider, None)
            .await
            .expect("member created");

        // Mirror pushd's mass-mention query shape: built from the thread id.
        let members = [member];
        let visibility = BulkDatabasePermissionQuery::from_server_id(&harness.db, &server.id)
            .await
            .from_channel_id(thread.id().to_string())
            .await
            .members(&members)
            .members_can_see_channel()
            .await;

        assert_eq!(
            visibility.get(&outsider.id),
            Some(&false),
            "member denied ViewChannel on the parent must not see the thread"
        );
    }

    #[rocket::async_test]
    async fn thread_cannot_double_anchor_a_message() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let (channel, _member, message) = harness.new_message(&user, &server, channels).await;

        // First thread anchored to the message succeeds.
        Channel::create_thread(
            &harness.db,
            &channel,
            &user,
            Some(&message),
            v0::DataCreateThread {
                name: "First".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("first thread");

        // Re-fetch so the message carries the stamped thread_id.
        let message = harness
            .db
            .fetch_message(&message.id)
            .await
            .expect("refetch message");

        // Anchoring a second thread to the same message is rejected.
        let error = Channel::create_thread(
            &harness.db,
            &channel,
            &user,
            Some(&message),
            v0::DataCreateThread {
                name: "Second".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect_err("second thread should be rejected");
        assert!(
            matches!(error.error_type, ErrorType::ThreadAlreadyExists),
            "expected ThreadAlreadyExists, got {:?}",
            error.error_type
        );
    }
}
