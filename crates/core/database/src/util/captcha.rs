use reqwest::Client;
use revolt_config::config;
use revolt_result::Result;
use std::{sync::LazyLock, time::Duration};

// Bounded so a hung hCaptcha cannot stall signup/resend/reset; a timeout
// fails closed as CaptchaFailed. A build failure is logged and also fails
// closed at use (Client::new would panic on the same failure).
static CLIENT: LazyLock<Option<Client>> = LazyLock::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .inspect_err(|err| error!("Failed to build hCaptcha HTTP client: {err}"))
        .ok()
});

#[derive(Serialize, Deserialize)]
struct CaptchaResponse {
    success: bool,
}

pub async fn check_captcha(token: Option<&str>) -> Result<()> {
    let config = config().await;

    if !config.api.security.captcha.hcaptcha_key.is_empty() {
        let Some(token) = token else {
            return Err(create_error!(CaptchaFailed));
        };

        let Some(client) = CLIENT.as_ref() else {
            return Err(create_error!(CaptchaFailed));
        };

        let response = client
            .post("https://hcaptcha.com/siteverify")
            .form(&[
                ("secret", config.api.security.captcha.hcaptcha_key.as_str()),
                ("response", token),
            ])
            .send()
            .await
            .map_err(|_| create_error!(CaptchaFailed))?
            .json::<CaptchaResponse>()
            .await
            .map_err(|_| create_error!(CaptchaFailed))?;

        if response.success {
            Ok(())
        } else {
            Err(create_error!(CaptchaFailed))
        }
    } else {
        Ok(())
    }
}
