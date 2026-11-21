use revolt_models::v0;
use revolt_result::Result;
use rocket::serde::json::Json;

/// # Take It Down Form Configuration
///
/// Whether the public request form is available, and the captcha site key
/// when a captcha is required.
#[openapi(tag = "User Safety")]
#[get("/config")]
pub async fn takedown_config() -> Result<Json<v0::TakedownPublicConfig>> {
    let config = revolt_config::config().await;
    let captcha = &config.api.security.captcha;

    // A site key only when the server also checks the answer
    let required = !captcha.hcaptcha_key.is_empty() && !captcha.hcaptcha_sitekey.is_empty();
    let captcha_sitekey = required.then(|| captcha.hcaptcha_sitekey.clone());

    Ok(Json(v0::TakedownPublicConfig {
        enabled: config.features.takedown.active(),
        captcha_sitekey,
    }))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use rocket::http::Status;

    #[test]
    fn config_reports_the_feature_on() {
        crate::util::test::rt().block_on(async {
            super::super::test_support::enable_takedown().await;

            let harness = TestHarness::new().await;
            let response = harness.client.get("/takedown/config").dispatch().await;
            assert_eq!(response.status(), Status::Ok);

            let body: serde_json::Value =
                serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
            assert_eq!(body["enabled"], serde_json::json!(true));
            // The test config has no hCaptcha secret, so no site key
            assert!(body["captcha_sitekey"].is_null(), "{body}");
        })
    }

    #[test]
    fn config_reports_the_feature_off_by_default() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let response = harness.client.get("/takedown/config").dispatch().await;
            assert_eq!(response.status(), Status::Ok);

            let body: serde_json::Value =
                serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
            assert_eq!(body["enabled"], serde_json::json!(false));
        })
    }
}
