//! A scripted import-source API on a loopback port, for tests that must not
//! reach a real one. Replies are keyed by the request target (path and
//! query); every request's headers are recorded.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use revolt_config::ApiImportBotSource;
use rocket::tokio::io::{AsyncReadExt, AsyncWriteExt};
use rocket::tokio::net::TcpListener;

pub const BOT_TOKEN: &str = "fake-bot-token";

/// One request the fake received
#[derive(Clone, Debug)]
pub struct Seen {
    pub path: String,
    /// The `x-bot-token` header (Stoat's bot auth), if sent
    pub bot_token: Option<String>,
    /// Every header in the order sent, names lowercased, values trimmed
    pub headers: Vec<(String, String)>,
}

impl Seen {
    /// The first value sent for header `name` (any case)
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(seen, _)| seen.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// How a reply's body is framed on the wire
#[derive(Clone, Copy)]
pub enum Framing {
    /// `content-length` = the body, then close
    Length,
    /// `transfer-encoding: chunked`, no declared length, then close
    Chunked,
    /// `content-length: <n>` with only the body sent, then the
    /// connection held open: a reader that trusts the declared length
    /// waits for bytes that never come
    DeclaredButHeld(usize),
}

#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    location: Option<String>,
    framing: Framing,
}

pub struct FakeUpstream {
    pub api_url: String,
    replies: HashMap<String, Reply>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// The name the Stoat tests use
pub type FakeStoat = FakeUpstream;

impl FakeUpstream {
    pub fn new() -> FakeUpstream {
        FakeUpstream {
            api_url: String::new(),
            replies: HashMap::new(),
            seen: Arc::new(Mutex::new(vec![])),
        }
    }

    /// Answer `path` with `status` and a JSON `body`
    pub fn reply(self, path: &str, status: u16, body: serde_json::Value) -> FakeUpstream {
        self.reply_framed(path, status, body, Framing::Length)
    }

    /// Answer `path` with `status` and a JSON `body` framed as `framing`
    pub fn reply_framed(
        mut self,
        path: &str,
        status: u16,
        body: serde_json::Value,
        framing: Framing,
    ) -> FakeUpstream {
        self.replies.insert(
            path.to_string(),
            Reply {
                status,
                body: body.to_string(),
                location: None,
                framing,
            },
        );
        self
    }

    /// Answer `path` with a 302 to `location`
    pub fn redirect(mut self, path: &str, location: &str) -> FakeUpstream {
        self.replies.insert(
            path.to_string(),
            Reply {
                status: 302,
                body: String::new(),
                location: Some(location.to_string()),
                framing: Framing::Length,
            },
        );
        self
    }

    /// Start serving; unscripted paths get 404
    pub async fn start(mut self) -> FakeUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        self.api_url = format!("http://{}", listener.local_addr().expect("addr"));

        let replies = self.replies.clone();
        let seen = self.seen.clone();
        rocket::tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let replies = replies.clone();
                let seen = seen.clone();
                rocket::tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 65536 {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }

                    let head = String::from_utf8_lossy(&head).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                    // The header block: after the request line, up to the
                    // blank line
                    let headers: Vec<(String, String)> = head
                        .lines()
                        .skip(1)
                        .take_while(|line| !line.is_empty())
                        .filter_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
                        })
                        .collect();
                    let bot_token = headers
                        .iter()
                        .find(|(name, _)| name == "x-bot-token")
                        .map(|(_, value)| value.clone());
                    seen.lock().unwrap().push(Seen {
                        path: path.clone(),
                        bot_token,
                        headers,
                    });

                    let reply = replies.get(&path).cloned().unwrap_or(Reply {
                        status: 404,
                        body: r#"{"type":"NotFound"}"#.to_string(),
                        location: None,
                        framing: Framing::Length,
                    });
                    let location = reply
                        .location
                        .map(|to| format!("location: {to}\r\n"))
                        .unwrap_or_default();
                    let head = format!(
                        "HTTP/1.1 {} Scripted\r\ncontent-type: application/json\r\n{location}connection: close\r\n",
                        reply.status
                    );
                    let response = match reply.framing {
                        Framing::Length => format!(
                            "{head}content-length: {}\r\n\r\n{}",
                            reply.body.len(),
                            reply.body
                        ),
                        Framing::DeclaredButHeld(declared) => {
                            format!("{head}content-length: {declared}\r\n\r\n{}", reply.body)
                        }
                        Framing::Chunked => {
                            let mut out = format!("{head}transfer-encoding: chunked\r\n\r\n");
                            for chunk in reply.body.as_bytes().chunks(64 * 1024) {
                                out.push_str(&format!("{:x}\r\n", chunk.len()));
                                out.push_str(std::str::from_utf8(chunk).expect("ascii body"));
                                out.push_str("\r\n");
                            }
                            out.push_str("0\r\n\r\n");
                            out
                        }
                    };
                    let _ = socket.write_all(response.as_bytes()).await;
                    if let Framing::DeclaredButHeld(_) = reply.framing {
                        rocket::tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                    }
                    let _ = socket.shutdown().await;
                });
            }
        });

        self
    }

    /// Requests received so far, in order
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// A ready-looking `[api.import.stoat]` pointing at this fake
    pub fn source_config(&self) -> ApiImportBotSource {
        ApiImportBotSource {
            enabled: true,
            api_url: self.api_url.clone(),
            app_url: "https://stoat.example".to_string(),
            cdn_url: "https://cdn.stoat.example".to_string(),
            bot_id: "01BOT000000000000000000000".to_string(),
            bot_token: BOT_TOKEN.to_string(),
            reconcile_after_hours: 24,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::upstream_http::{build_client, Transport, USER_AGENT};
    use super::*;

    /// Any header a client sends is recorded and found by name in any case,
    /// not only Stoat's `x-bot-token`
    #[test]
    fn captures_every_request_header() {
        crate::util::test::rt().block_on(async {
            let fake = FakeUpstream::new()
                .reply("/v1/guilds/1/roles?limit=5", 200, json!([]))
                .start()
                .await;
            let client = build_client(Transport::LoopbackTest, "test").expect("client");
            let response = client
                .get(format!("{}/v1/guilds/1/roles?limit=5", fake.api_url))
                .header("Authorization", "Bot some-token")
                .header("X-Arbitrary-Thing", "  padded value ")
                .send()
                .await
                .expect("sent");
            assert_eq!(response.status().as_u16(), 200);

            let seen = fake.seen();
            assert_eq!(seen.len(), 1, "{seen:?}");
            assert_eq!(seen[0].path, "/v1/guilds/1/roles?limit=5");
            assert_eq!(seen[0].header("authorization"), Some("Bot some-token"));
            assert_eq!(seen[0].header("AUTHORIZATION"), Some("Bot some-token"));
            assert_eq!(seen[0].header("x-arbitrary-thing"), Some("padded value"));
            // The client's own headers are recorded too
            assert_eq!(seen[0].header("user-agent"), Some(USER_AGENT));
            assert!(seen[0].header("host").is_some());
            assert_eq!(seen[0].header("x-not-sent"), None);
            assert_eq!(seen[0].bot_token, None);
        })
    }
}
