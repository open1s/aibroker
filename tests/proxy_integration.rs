//! End-to-end tests over real TCP sockets.
//!
//! These run the actual pingora proxy against a mock upstream, which is the
//! only way to verify the two behaviours that matter most and cannot be
//! unit-tested: that a 429 rotates onto another key *within* the same request,
//! and that the model decides which provider is used.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aibroker::config::{ApiKeyConfig, Config, ProviderConfig, RouteConfig, ServerConfig};
use aibroker::core::runtime::Runtime;
use aibroker::core::runtime::shared;
use aibroker::proxy::pingora_backend::run_server;
use aibroker::proxy::admin::AdminRouter;
use aibroker::proxy::pingora_backend::ProxyService;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;

/// What the mock upstream recorded about one request.
#[derive(Debug, Clone)]
struct SeenRequest {
    path: String,
    body: String,
    authorization: Option<String>,
    api_key: Option<String>,
    user_agent: Option<String>,
}

/// A mock upstream that answers with a scripted sequence of statuses.
struct MockUpstream {
    /// Status codes to return, consumed one per request; the last repeats.
    script: Vec<u16>,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    counter: Arc<AtomicUsize>,
}

struct MockCtx;

#[async_trait]
impl ProxyHttp for MockUpstream {
    type CTX = MockCtx;

    fn new_ctx(&self) -> Self::CTX {
        MockCtx
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let header = session.req_header();
        let header_value = |name: &str| {
            header
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };
        let seen = SeenRequest {
            path: header.uri.path().to_string(),
            body: String::new(),
            authorization: header_value("authorization"),
            api_key: header_value("x-api-key"),
            user_agent: header_value("user-agent"),
        };
        self.seen.lock().expect("seen lock").push(seen);
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(chunk) = body.as_deref()
            && let (Ok(text), Some(last)) = (
                std::str::from_utf8(chunk),
                self.seen.lock().expect("seen lock").last_mut(),
            )
        {
            last.body.push_str(text);
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        Err(pingora::Error::new_down(pingora::ErrorType::new(
            "MockHasNoUpstream",
        )))
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        _resp: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let index = self.counter.fetch_add(1, Ordering::SeqCst);
        let status = self
            .script
            .get(index)
            .copied()
            .or_else(|| self.script.last().copied())
            .unwrap_or(200);

        let body = match status {
            200 => br#"{"id":"mock","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":11,"completion_tokens":22}}"#.to_vec(),
            429 => br#"{"error":{"message":"rate limited","type":"rate_limit_error"}}"#.to_vec(),
            _ => br#"{"error":{"message":"upstream boom"}}"#.to_vec(),
        };

        let mut header = ResponseHeader::build(status, None)?;
        header.insert_header("Content-Type", "application/json")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        if status == 429 {
            header.insert_header("Retry-After", "0")?;
        }
        session.set_keepalive(None);
        session
            .write_response_header(Box::new(header), body.is_empty())
            .await?;
        if !body.is_empty() {
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
        }
        Ok(())
    }
}

/// Reserve a free TCP port.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn base_config(proxy_port: u16, providers: Vec<ProviderConfig>, routes: Vec<RouteConfig>) -> Config {
    Config {
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: proxy_port,
            threads: Some(1),
            daemon: false,
            pid_file: None,
            user: None,
            group: None,
            connect_timeout_ms: 2_000,
            idle_timeout_ms: Some(5_000),
            max_retries: 3,
        },
        proxy_type: None,
        providers,
        routes,
        default_route: None,
        load_balancing: Default::default(),
        health: Default::default(),
        observability: Default::default(),
        admin: Default::default(),
    }
}

fn provider(name: &str, base_url: String, keys: &[(&str, &str)]) -> ProviderConfig {
    ProviderConfig {
        name: name.into(),
        base_url: Some(base_url),
        path_prefix: None,
        auth: None,
        auth_query_param: None,
        default_models: vec![],
        max_rpm: None,
        max_tpm: None,
        max_concurrency: None,
        api_keys: keys
            .iter()
            .map(|(id, secret)| ApiKeyConfig {
                id: (*id).into(),
                key: (*secret).into(),
                enabled: true,
                models: vec!["test-model".into()],
                weight: 1,
                max_rpm: None,
                max_tpm: None,
                max_concurrency: None,
                model_map: None,
            })
            .collect(),
    }
}

/// Start the broker proxy on `port` in a background thread.
fn spawn_broker(config: Config, port: u16) {
    let runtime = shared(Runtime::new(config.clone(), None).expect("runtime"));
    // Touch the metrics/admin plumbing so the same code path as production is
    // exercised, even though these tests do not call the control plane.
    let _ = ProxyService::new(
        Arc::clone(&runtime),
        Some(AdminRouter::new(Arc::clone(&runtime), Some("t".into()), false)),
    );

    std::thread::spawn(move || {
        let _ = run_server(config, runtime);
    });

    wait_for_port(port);
}

/// Start the mock upstream on `port`.
fn spawn_mock(port: u16, script: Vec<u16>) -> Arc<Mutex<Vec<SeenRequest>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let upstream = MockUpstream {
        script,
        seen: Arc::clone(&seen),
        counter: Arc::new(AtomicUsize::new(0)),
    };

    std::thread::spawn(move || {
        let mut server = Server::new(None).expect("mock server");
        server.bootstrap();
        let mut service = pingora::proxy::http_proxy_service(&server.configuration, upstream);
        service.add_tcp(&format!("127.0.0.1:{port}"));
        server.add_service(service);
        server.run_forever();
    });

    wait_for_port(port);
    seen
}

/// Block until something accepts connections on `port`.
fn wait_for_port(port: u16) {
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("nothing listening on port {port}");
}

/// A minimal HTTP/1.1 client: enough for a POST with a JSON body.
struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

fn post(port: u16, path: &str, body: &str) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to broker");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("write request");
    stream.flush().ok();
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body = raw[split + 4..].to_vec();

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.contains("chunked"))
    {
        dechunk(&body)
    } else {
        String::from_utf8_lossy(&body).to_string()
    };

    HttpResponse {
        status,
        headers,
        body,
    }
}

/// Decode a chunked body.
fn dechunk(raw: &[u8]) -> String {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < raw.len() {
        let Some(line_end) = raw[cursor..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&raw[cursor..cursor + line_end]).to_string();
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        cursor += line_end + 2;
        if size == 0 {
            break;
        }
        if cursor + size > raw.len() {
            break;
        }
        out.extend_from_slice(&raw[cursor..cursor + size]);
        cursor += size + 2;
    }
    String::from_utf8_lossy(&out).to_string()
}

const CHAT_BODY: &str = r#"{"model":"test-model","messages":[{"role":"user","content":"hello"}]}"#;

#[test]
fn rate_limited_key_is_rotated_within_the_same_request() {
    let upstream_port = free_port();
    let proxy_port = free_port();
    // First upstream call: 429. Second: success.
    let seen = spawn_mock(upstream_port, vec![429, 200]);

    let config = base_config(
        proxy_port,
        vec![
            provider(
                "primary",
                format!("http://127.0.0.1:{upstream_port}"),
                &[("key-a", "sk-key-a"), ("key-b", "sk-key-b")],
            ),
        ],
        vec![RouteConfig {
            model: "test-model".into(),
            providers: vec!["primary".into()],
            strategy: None,
            rewrite: false,
        }],
    );
    spawn_broker(config, proxy_port);

    let response = post(proxy_port, "/v1/chat/completions", CHAT_BODY);
    assert_eq!(
        response.status, 200,
        "the request must succeed on the second key, got body: {}",
        response.body
    );
    assert!(
        response.body.contains("\"id\":\"mock\""),
        "the success body must reach the client: {}",
        response.body
    );

    let requests = seen.lock().expect("seen lock").clone();
    assert_eq!(
        requests.len(),
        2,
        "the broker must have tried twice, got {requests:?}"
    );
    let first = requests[0]
        .authorization
        .clone()
        .expect("first attempt carries a credential");
    let second = requests[1]
        .authorization
        .clone()
        .expect("second attempt carries a credential");
    assert_ne!(
        first, second,
        "the retry must use a different key (both were {first})"
    );
    assert!(
        first == "Bearer sk-key-a" || first == "Bearer sk-key-b",
        "unexpected credential {first}"
    );
    assert!(
        second == "Bearer sk-key-a" || second == "Bearer sk-key-b",
        "unexpected credential {second}"
    );
    // The client's model must reach the upstream unchanged.
    assert_eq!(requests[0].path, "/v1/chat/completions");
    assert!(
        requests[0].body.contains("test-model"),
        "the request body must be replayed on retry: {}",
        requests[0].body
    );
    assert!(
        requests[1].body.contains("test-model"),
        "the retried body must be intact: {}",
        requests[1].body
    );
}

#[test]
fn model_routing_selects_the_provider_that_serves_it() {
    let primary_port = free_port();
    let secondary_port = free_port();
    let proxy_port = free_port();
    // Neither upstream should see a 429 here.
    let primary_seen = spawn_mock(primary_port, vec![200]);
    let secondary_seen = spawn_mock(secondary_port, vec![200]);

    let mut primary = provider(
        "primary",
        format!("http://127.0.0.1:{primary_port}"),
        &[("key-a", "sk-primary")],
    );
    // `primary` only serves a different model, so routing must skip it.
    primary.api_keys[0].models = vec!["other-model".into()];
    let secondary = provider(
        "secondary",
        format!("http://127.0.0.1:{secondary_port}"),
        &[("key-b", "sk-secondary")],
    );

    let config = base_config(proxy_port, vec![primary, secondary], vec![]);
    spawn_broker(config, proxy_port);

    let response = post(proxy_port, "/v1/chat/completions", CHAT_BODY);
    assert_eq!(response.status, 200, "body: {}", response.body);

    assert!(
        primary_seen.lock().expect("lock").is_empty(),
        "the provider that does not serve the model must not be called"
    );
    let hits = secondary_seen.lock().expect("lock").clone();
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].authorization.as_deref(),
        Some("Bearer sk-secondary")
    );
}

#[test]
fn exhausted_keys_produce_a_429_with_retry_after() {
    let upstream_port = free_port();
    let proxy_port = free_port();
    // Both upstream attempts are rate limited.
    let _seen = spawn_mock(upstream_port, vec![429]);

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "primary",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key-a", "sk-key-a"), ("key-b", "sk-key-b")],
        )],
        vec![],
    );
    config.server.max_retries = 2;
    spawn_broker(config, proxy_port);

    let response = post(proxy_port, "/v1/chat/completions", CHAT_BODY);
    assert_eq!(
        response.status, 429,
        "the upstream 429 must surface once every key is tried: {}",
        response.body
    );
    let retry_after = response
        .headers
        .get("retry-after")
        .expect("a retry hint must be forwarded");
    assert!(
        retry_after.parse::<u64>().is_ok(),
        "Retry-After must be a number of seconds, got `{retry_after}`"
    );
}

#[test]
fn unknown_model_is_refused_without_touching_an_upstream() {
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200]);

    let config = base_config(
        proxy_port,
        vec![provider(
            "primary",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key-a", "sk-key-a")],
        )],
        vec![],
    );
    spawn_broker(config, proxy_port);

    let body = r#"{"model":"no-such-model","messages":[]}"#;
    let response = post(proxy_port, "/v1/chat/completions", body);
    assert_eq!(
        response.status, 503,
        "an unroutable model is a configuration problem, got: {}",
        response.body
    );
    assert!(seen.lock().expect("lock").is_empty());
}

#[test]
fn concurrent_requests_spread_across_the_key_pool() {
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200; 64]);

    let config = base_config(
        proxy_port,
        vec![provider(
            "primary",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key-a", "sk-key-a"), ("key-b", "sk-key-b")],
        )],
        vec![],
    );
    spawn_broker(config, proxy_port);

    let mut handles = Vec::new();
    for _ in 0..8 {
        handles.push(std::thread::spawn(move || {
            post(proxy_port, "/v1/chat/completions", CHAT_BODY).status
        }));
    }
    for handle in handles {
        assert_eq!(handle.join().expect("thread"), 200);
    }

    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests.len(), 8);
    let mut by_key: HashMap<String, usize> = HashMap::new();
    for request in &requests {
        if let Some(auth) = &request.authorization {
            *by_key.entry(auth.clone()).or_default() += 1;
        }
    }
    assert_eq!(
        by_key.len(),
        2,
        "round robin must use both keys, distribution: {by_key:?}"
    );
    assert!(
        by_key.values().all(|count| *count == 4),
        "round robin must be even, distribution: {by_key:?}"
    );
}
