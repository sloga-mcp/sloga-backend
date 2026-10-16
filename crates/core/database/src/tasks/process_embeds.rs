use crate::{models::Message, AppendMessage, Database};

use futures::future::join_all;
use linkify::{LinkFinder, LinkKind};
use regex::Regex;
use revolt_config::config;
use revolt_result::{ErrorType, Result};

use async_lock::Semaphore;
use deadqueue::limited::Queue;
use once_cell::sync::Lazy;
use revolt_models::v0::Embed;
use std::{collections::HashSet, sync::Arc};
use tokio::task::spawn;

use isahc::prelude::*;

/// Task information
#[derive(Debug)]
struct EmbedTask {
    /// Channel we're processing the event in
    channel: String,
    /// ID of the message we're processing
    id: String,
    /// Content of the message
    content: String,
}

static Q: Lazy<Queue<EmbedTask>> = Lazy::new(|| Queue::new(10_000));

/// Queue a new task for a worker
pub async fn queue(channel: String, id: String, content: String) {
    Q.try_push(EmbedTask {
        channel,
        id,
        content,
    })
    .ok();

    info!("Queue is using {} slots from {}.", Q.len(), Q.capacity());
}

/// Start a new worker
pub async fn worker(db: Database) {
    let semaphore = Arc::new(Semaphore::new(
        config().await.api.workers.max_concurrent_connections,
    ));

    loop {
        let task = Q.pop().await;
        let db = db.clone();
        let semaphore = semaphore.clone();

        spawn(async move {
            let config = config().await;
            let embeds = generate(
                task.content,
                &config.hosts.january,
                &config.api.gamedata.internal_key,
                config.features.limits.global.message_embeds,
                semaphore,
            )
            .await;

            if let Ok(embeds) = embeds {
                match Message::append(
                    &db,
                    task.id.clone(),
                    task.channel,
                    AppendMessage {
                        embeds: Some(embeds),
                    },
                )
                .await
                {
                    Ok(()) => {}
                    Err(err) if matches!(err.error_type, ErrorType::NotFound) => debug!(
                        "Message {} was deleted before its embeds resolved; dropping them",
                        task.id
                    ),
                    Err(err) => {
                        error!("Encountered an error appending to message: {:?}", err);
                    }
                }
            }
        });
    }
}

static RE_CODE: Lazy<Regex> = Lazy::new(|| Regex::new("```(?:.|\n)+?```|`(?:.|\n)+?`").unwrap());
static RE_IGNORED: Lazy<Regex> = Lazy::new(|| Regex::new("(<http.+>)").unwrap());

/// Header that lets January build game cards (and spend the shared game
/// data budget) for the worker's requests
const INTERNAL_KEY_HEADER: &str = "X-Internal-Key";

/// January `/embed` request for `link`. The internal key is sent only when
/// one is configured; the header is marked sensitive so it is never printed.
fn embed_request(host: &str, link: &str, internal_key: &str) -> Option<isahc::Request<()>> {
    let mut builder = isahc::Request::get(format!(
        "{host}/embed?url={}",
        url_escape::encode_component(link)
    ));

    if !internal_key.trim().is_empty() {
        if let Ok(mut value) = isahc::http::HeaderValue::from_str(internal_key) {
            value.set_sensitive(true);
            builder = builder.header(INTERNAL_KEY_HEADER, value);
        }
    }

    builder.body(()).ok()
}

pub async fn generate(
    content: String,
    host: &str,
    internal_key: &str,
    max_embeds: usize,
    semaphore: Arc<Semaphore>,
) -> Result<Vec<Embed>> {
    // Ignore code blocks.
    let content = RE_CODE.replace_all(&content, "");

    // Ignore all content between angle brackets starting with http.
    let content = RE_IGNORED.replace_all(&content, "");

    let content = content
        // Ignore quoted lines.
        .split('\n')
        .map(|v| {
            if let Some(c) = v.chars().next() {
                if c == '>' {
                    return "";
                }
            }

            v
        })
        .collect::<Vec<&str>>()
        .join("\n");

    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Url]);

    // Process all links, stripping anchors and
    // only taking up to `max_embeds` of links.
    let links: Vec<String> = finder
        .links(&content)
        .map(|x| {
            x.as_str()
                .chars()
                .take_while(|&ch| ch != '#')
                .collect::<String>()
        })
        .collect::<HashSet<String>>()
        .into_iter()
        .take(max_embeds)
        .collect();

    // If no links, fail out.
    if links.is_empty() {
        return Err(create_error!(LabelMe));
    }

    // TODO: batch request to january
    let mut tasks = Vec::new();

    for link in links {
        let semaphore = semaphore.clone();
        let request = embed_request(host, &link, internal_key);
        tasks.push(spawn(async move {
            let request = request?;
            let guard = semaphore.acquire().await;

            if let Ok(mut response) = request.send_async().await {
                drop(guard);
                let status_ok = response.status().is_success();
                keep_embed(status_ok, response.json::<Embed>().await.ok())
            } else {
                None
            }
        }));
    }

    let embeds = join_all(tasks)
        .await
        .into_iter()
        .flatten()
        .flatten()
        .collect::<Vec<Embed>>();

    // Prevent database update when no embeds are found.
    if !embeds.is_empty() {
        Ok(embeds)
    } else {
        Err(create_error!(LabelMe))
    }
}

/// Keep a january response only if it succeeded and carries a real embed.
/// Unknown embed types decode as `Embed::None`, and so does january's
/// `{"type":"NoEmbedData"}` error body, so `None` must be filtered out.
fn keep_embed(status_ok: bool, embed: Option<Embed>) -> Option<Embed> {
    if !status_ok {
        return None;
    }

    embed.filter(|e| !matches!(e, Embed::None))
}

#[cfg(test)]
mod tests {
    use super::{embed_request, keep_embed, INTERNAL_KEY_HEADER};
    use revolt_models::v0::{Embed, Image, ImageSize};

    const LINK: &str = "https://store.steampowered.com/app/620/?a=1&b=2";
    const URI: &str =
        "http://january:14705/embed?url=https%3A%2F%2Fstore.steampowered.com%2Fapp%2F620%2F%3Fa%3D1%26b%3D2";

    #[test]
    fn internal_key_is_sent_when_configured() {
        let request = embed_request("http://january:14705", LINK, "s3cret").expect("request");
        assert_eq!(request.uri().to_string(), URI);
        let value = request
            .headers()
            .get(INTERNAL_KEY_HEADER)
            .expect("internal key header");
        assert_eq!(value.to_str().unwrap(), "s3cret");
        assert!(value.is_sensitive());
        assert!(!format!("{request:?}").contains("s3cret"));
    }

    #[test]
    fn no_internal_key_header_without_a_configured_key() {
        for key in ["", "   "] {
            let request = embed_request("http://january:14705", LINK, key).expect("request");
            assert_eq!(request.uri().to_string(), URI);
            assert!(request.headers().get(INTERNAL_KEY_HEADER).is_none(), "{key:?}");
            assert!(request.headers().is_empty(), "{key:?}");
        }
    }

    fn image() -> Embed {
        Embed::Image(Image {
            url: "https://example.com/a.png".to_string(),
            width: 1,
            height: 1,
            size: ImageSize::Large,
        })
    }

    #[test]
    fn non_success_status_is_dropped() {
        assert!(keep_embed(false, Some(image())).is_none());
    }

    #[test]
    fn none_embed_is_dropped() {
        assert!(keep_embed(true, Some(Embed::None)).is_none());
    }

    #[test]
    fn real_embed_is_kept() {
        assert!(matches!(
            keep_embed(true, Some(image())),
            Some(Embed::Image(_))
        ));
    }

    #[test]
    fn january_error_body_is_dropped() {
        let body = serde_json::from_str::<Embed>(r#"{"type":"NoEmbedData","location":"x"}"#).ok();
        assert!(matches!(body, Some(Embed::None)));
        assert!(keep_embed(true, body).is_none());
    }
}
