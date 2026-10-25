use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod afk_idle;
mod annotations_consent;
mod annotations_send;
mod call_recording;
mod captions_send;
mod channel_ack;
mod control_request;
mod channel_delete;
mod channel_edit;
mod channel_fetch;
mod channel_protect;
mod command_list;
mod follow_create;
mod follow_delete;
mod followers_fetch;
mod forum_post_create;
mod forum_posts_fetch;
mod interaction_autocomplete;
mod interaction_create;
mod message_crosspost;
mod group_add_member;
mod group_create;
mod group_remove_member;
mod invite_create;
mod members_fetch;
mod message_bulk_delete;
mod message_clear_reactions;
mod message_delete;
mod message_edit;
mod message_fetch;
mod message_forward;
mod message_interact;
mod message_pin;
mod message_query;
mod message_react;
mod message_roll;
mod message_schedule;
mod message_search;
mod message_send;
mod message_unpin;
mod message_unreact;
mod rc_capable;
mod remote_control;
mod permissions_set;
mod permissions_set_default;
mod poll_create;
mod poll_end;
mod poll_fetch;
mod poll_vote;
mod poll_voters;
mod protected_entitlement_grant;
pub(crate) mod protected_seat_validation;
mod scheduled_message_delete;
mod scheduled_messages_list;
mod seats_fetch;
mod seats_put;
mod softres_create;
mod softres_export;
mod softres_fetch;
mod softres_manage;
mod softres_reserve;
mod thread_create;
mod thread_list;
mod thread_members;
mod soundboard_trigger;
mod voice_join;
mod voice_screen_leg;
mod voice_stop_ring;
mod watch;
mod webhook_create;
mod webhook_fetch_all;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        channel_ack::ack,
        channel_fetch::fetch,
        members_fetch::fetch_members,
        channel_delete::delete,
        channel_edit::edit,
        invite_create::create_invite,
        message_send::message_send,
        message_roll::message_roll,
        message_forward::message_forward,
        message_crosspost::message_crosspost,
        follow_create::follow_channel,
        follow_delete::unfollow_channel,
        followers_fetch::fetch_followers,
        message_schedule::message_schedule,
        scheduled_messages_list::scheduled_messages_list,
        scheduled_message_delete::scheduled_message_delete,
        message_query::query,
        message_search::search,
        message_pin::message_pin,
        message_fetch::fetch,
        message_edit::edit,
        message_bulk_delete::bulk_delete_messages,
        message_delete::delete,
        message_unpin::message_unpin,
        group_create::create_group,
        group_add_member::add_member,
        group_remove_member::remove_member,
        voice_join::call,
        voice_screen_leg::screen_leg,
        voice_stop_ring::stop_ring,
        soundboard_trigger::trigger_sound,
        captions_send::send_caption,
        annotations_send::send_annotation,
        annotations_consent::annotation_allow,
        annotations_consent::annotation_revoke,
        annotations_consent::annotation_consent_fetch,
        call_recording::recording_start,
        call_recording::recording_stop,
        remote_control::control_offer,
        remote_control::control_respond,
        remote_control::control_release,
        remote_control::control_heartbeat,
        control_request::control_request,
        rc_capable::rc_capable_announce,
        afk_idle::afk_idle_set,
        afk_idle::afk_idle_clear,
        watch::watch_create,
        watch::watch_update,
        watch::watch_end,
        watch::watch_fetch,
        watch::watch_host,
        watch::watching_set,
        permissions_set::set_role_permissions,
        permissions_set_default::set_default_channel_permissions,
        message_react::react_message,
        message_unreact::unreact_message,
        message_clear_reactions::clear_reactions,
        webhook_create::create_webhook,
        webhook_fetch_all::fetch_webhooks,
        thread_create::create_thread,
        thread_create::create_thread_from_message,
        thread_list::fetch_threads,
        thread_members::join_thread,
        thread_members::leave_thread,
        thread_members::fetch_thread_members,
        forum_post_create::create_forum_post,
        forum_posts_fetch::fetch_forum_posts,
        command_list::fetch_channel_commands,
        interaction_create::interaction_create,
        interaction_autocomplete::interaction_autocomplete,
        message_interact::message_interact,
        poll_create::poll_create,
        poll_vote::poll_vote,
        poll_vote::poll_unvote,
        poll_fetch::poll_fetch,
        poll_fetch::polls_fetch_bulk,
        poll_voters::poll_voters,
        poll_end::poll_end,
        softres_create::softres_create,
        softres_reserve::softres_reserve,
        softres_reserve::softres_unreserve,
        softres_fetch::softres_fetch,
        softres_fetch::softres_fetch_bulk,
        softres_manage::softres_edit,
        softres_manage::softres_lock,
        softres_manage::softres_unlock,
        softres_export::softres_export,
        protected_entitlement_grant::grant_entitlement,
        channel_protect::protect_channel,
        seats_put::put_seats,
        seats_fetch::fetch_seats,
    ]
}

/// OpenAPI completeness for every route protected channels added (W2c C1):
/// each one is in the generated spec under its path and method, with its
/// tag, and Rocket gets the handler. A route left out of the
/// `openapi_get_routes_spec!` list is neither documented nor mounted.
#[cfg(test)]
mod protected_openapi_completeness {
    use revolt_rocket_okapi::revolt_okapi::openapi3::{OpenApi, Operation};
    use rocket::Route;

    #[derive(Clone, Copy, Debug)]
    enum Method {
        Get,
        Put,
        Post,
    }

    /// (method, path relative to the mount point, handler name, tag)
    const CHANNELS: &[(Method, &str, &str, &str)] = &[
        (
            Method::Put,
            "/{target}/protected_entitlement",
            "grant_entitlement",
            "E2EE",
        ),
        (Method::Put, "/{target}/protect", "protect_channel", "E2EE"),
        (Method::Put, "/{target}/seats", "put_seats", "E2EE"),
        (Method::Get, "/{target}/seats", "fetch_seats", "E2EE"),
    ];

    /// The MLS routes W2 gave a Text path (mounted under `/mls`)
    const MLS: &[(Method, &str, &str, &str)] = &[
        (
            Method::Put,
            "/key_packages",
            "publish_key_packages",
            "MLS",
        ),
        (
            Method::Post,
            "/key_packages/claim",
            "claim_key_packages",
            "MLS",
        ),
        (Method::Post, "/groups", "create_group", "MLS"),
        (
            Method::Post,
            "/groups/{group_id}/join_intent",
            "join_intent",
            "MLS",
        ),
        (
            Method::Post,
            "/groups/{group_id}/commits",
            "submit_commit",
            "MLS",
        ),
        (
            Method::Get,
            "/groups/{group_id}/commits",
            "fetch_commits",
            "MLS",
        ),
        (
            Method::Post,
            "/groups/{group_id}/messages",
            "send_message",
            "MLS",
        ),
        (
            Method::Get,
            "/channels/{channel_id}/text_group",
            "fetch_text_group",
            "MLS",
        ),
    ];

    fn operation<'a>(spec: &'a OpenApi, method: Method, path: &str) -> Option<&'a Operation> {
        let item = spec.paths.get(path)?;
        match method {
            Method::Get => item.get.as_ref(),
            Method::Put => item.put.as_ref(),
            Method::Post => item.post.as_ref(),
        }
    }

    fn assert_complete(
        area: &str,
        (routes, spec): (Vec<Route>, OpenApi),
        expected: &[(Method, &str, &str, &str)],
    ) {
        let paths: Vec<&String> = spec.paths.keys().collect();
        for (method, path, handler, tag) in expected {
            // Edition 2018: a one-argument panic! does not interpolate, so
            // every message here passes its arguments explicitly
            let operation = operation(&spec, *method, path).unwrap_or_else(|| {
                panic!(
                    "{}: {:?} {} is missing from the OpenAPI spec; paths: {:?}",
                    area, method, path, paths
                )
            });
            assert!(
                operation.tags.iter().any(|t| t == tag),
                "{area}: {method:?} {path} is not tagged {tag}: {:?}",
                operation.tags
            );
            assert!(
                routes
                    .iter()
                    .any(|route| route.name.as_deref() == Some(*handler)),
                "{}: handler {} is not mounted",
                area,
                handler
            );
        }
    }

    #[test]
    fn every_protected_channel_route_is_in_the_openapi_spec() {
        assert_complete("/channels", super::routes(), CHANNELS);
    }

    #[test]
    fn every_mls_text_route_is_in_the_openapi_spec() {
        assert_complete("/mls", crate::routes::mls::routes(), MLS);
    }
}
