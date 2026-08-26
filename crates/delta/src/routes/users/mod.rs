use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod add_friend;
mod block_user;
mod boost_grant;
mod boost_revoke;
mod change_username;
mod connections_authorize;
mod connections_complete;
mod connections_unlink;
mod edit_user;
mod fetch_dms;
mod fetch_profile;
mod fetch_self;
mod fetch_user;
mod fetch_user_boosts;
mod fetch_user_flags;
mod find_mutual;
mod get_default_avatar;
mod open_dm;
mod remove_friend;
mod respect_delete;
mod respect_fetch;
mod respect_set;
mod send_friend_request;
mod unblock_user;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        // User Information
        fetch_self::fetch,
        fetch_user::fetch,
        fetch_user_flags::fetch_user_flags,
        edit_user::edit,
        change_username::change_username,
        get_default_avatar::default_avatar,
        fetch_profile::profile,
        // Streaming connections
        connections_authorize::connections_authorize,
        connections_complete::connections_complete,
        connections_unlink::connections_unlink,
        // Direct Messaging
        fetch_dms::direct_messages,
        open_dm::open_dm,
        // Relationships
        find_mutual::mutual,
        add_friend::add,
        remove_friend::remove,
        block_user::block,
        unblock_user::unblock,
        send_friend_request::send_friend_request,
        // Server Boosts
        fetch_user_boosts::fetch_user_boosts,
        boost_grant::boost_grant,
        boost_revoke::boost_revoke,
        // Respect (profile wall)
        respect_set::respect_set,
        respect_fetch::respect_fetch,
        respect_delete::respect_delete,
    ]
}
