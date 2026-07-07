use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod report_content;
mod report_fetch;
mod report_list;
mod report_review;
mod user_suspend;
mod user_unsuspend;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        // Reports
        report_content::report_content,
        report_list::report_list,
        report_fetch::report_fetch,
        report_review::report_review,
        // Moderation
        user_suspend::user_suspend,
        user_unsuspend::user_unsuspend,
    ]
}
