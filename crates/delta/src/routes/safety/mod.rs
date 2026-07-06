use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod report_content;
mod user_suspend;
mod user_unsuspend;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        // Reports
        report_content::report_content,
        // Moderation
        user_suspend::user_suspend,
        user_unsuspend::user_unsuspend,
    ]
}
