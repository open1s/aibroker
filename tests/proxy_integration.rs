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
use aibroker::proxy::admin::AdminRouter;
use aibroker::proxy::pingora_backend::ProxyService;
use aibroker::proxy::pingora_backend::run_server;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;

/// What the mock upstream recorded about one request.
#[derive(Debug, Clone)]
struct SeenRequest {
    path: String,
    body: String,
    authorization: Option<String>,
    #[allow(dead_code)]
    api_key: Option<String>,
    #[allow(dead_code)]
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

        // Read the whole request body before answering: this mock is the end
        // of the line, so the body has nowhere else to go.
        let mut body = String::new();
        loop {
            match session.downstream_session.read_request_body().await {
                Ok(Some(chunk)) => body.push_str(&String::from_utf8_lossy(&chunk)),
                Ok(None) => break,
                Err(error) => {
                    eprintln!("mock failed to read its request body: {error}");
                    break;
                }
            }
        }
        if let Some(last) = self.seen.lock().expect("seen lock").last_mut() {
            last.body = body;
        }

        let index = self.counter.fetch_add(1, Ordering::SeqCst);
        let status = self
            .script
            .get(index)
            .copied()
            .or_else(|| self.script.last().copied())
            .unwrap_or(200);

        let payload = match status {
            200 => r#"{"id":"mock","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":11,"completion_tokens":22}}"#.to_string(),
            429 => r#"{"error":{"message":"rate limited","type":"rate_limit_error"}}"#.to_string(),
            _ => r#"{"error":{"message":"upstream boom"}}"#.to_string(),
        };

        let mut header = ResponseHeader::build(status, None)?;
        header.insert_header("Content-Type", "application/json")?;
        header.insert_header("Content-Length", payload.len().to_string())?;
        if status == 429 {
            header.insert_header("Retry-After", "1")?;
        }
        // Ask the broker to close this connection after the reply, the way
        // endpoints behind a rolling deploy do.
        header.insert_header("Connection", "close")?;
        session.set_keepalive(None);
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(payload)), true)
            .await?;
        Ok(true)
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
}

/// Reserve a free TCP port.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn base_config(
    proxy_port: u16,
    providers: Vec<ProviderConfig>,
    routes: Vec<RouteConfig>,
) -> Config {
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
            read_timeout_ms: None,
            write_timeout_ms: None,
            max_retries: 3,
            graceful_shutdown_secs: aibroker::config::DEFAULT_GRACE_PERIOD_SECS,
        },
        proxy_type: None,
        providers,
        routes,
        default_route: None,
        load_balancing: Default::default(),
        health: Default::default(),
        observability: Default::default(),
        admin: Default::default(),
        clients: Vec::new(),
        dump: Default::default(),
        content_guard: Default::default(),
        policy: Default::default(),
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

/// Assert that a refused request never delivered its *content* to a provider.
///
/// The invariant is about content, not connections. A local refusal happens
/// after pingora has chosen the upstream peer, so the provider may see request
/// headers before the refusal lands -- and whether it does is a timing race: an
/// `is_empty()` assertion held on macOS and failed on Linux CI. Asserting that
/// no body arrived states the property that matters and is stable.
fn assert_nothing_was_forwarded(seen: &Arc<Mutex<Vec<SeenRequest>>>, why: &str) {
    let requests = seen.lock().expect("lock").clone();
    for request in &requests {
        assert!(
            request.body.is_empty(),
            "{why}: the body reached the provider in {}: {}",
            request.path,
            request.body
        );
    }
}

/// Start the broker proxy on `port` in a background thread.
///
/// Returns the shared runtime so a test can assert on the registry a request
/// actually wrote to -- a counter is the only way to prove a diagnostic path
/// ran, when by design it changes no response.
fn spawn_broker_with_runtime(config: Config, port: u16) -> aibroker::core::runtime::SharedRuntime {
    let runtime = shared(Runtime::new(config.clone(), None).expect("runtime"));
    // Touch the metrics/admin plumbing so the same code path as production is
    // exercised, even though these tests do not call the control plane.
    let _ = ProxyService::new(
        Arc::clone(&runtime),
        Some(AdminRouter::new(
            Arc::clone(&runtime),
            Some("t".into()),
            false,
        )),
    );

    let for_server = Arc::clone(&runtime);
    std::thread::spawn(move || {
        let _ = run_server(
            config,
            for_server,
            aibroker::proxy::dump::DumpConfig::default(),
        );
    });

    wait_for_port(port);
    runtime
}

/// Start the broker proxy on `port`, discarding the runtime.
fn spawn_broker(config: Config, port: u16) {
    let _ = spawn_broker_with_runtime(config, port);
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
    status_line: String,
    headers: HashMap<String, String>,
    body: String,
}

/// POST with an optional client credential, to exercise the edge check.
fn post_as_client(
    port: u16,
    path: &str,
    body: &str,
    model: Option<&str>,
    token: Option<&str>,
) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to broker");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");

    let model_header = match model {
        Some(model) => format!("x-llm-model: {model}\r\n"),
        None => String::new(),
    };
    let auth_header = match token {
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n{model_header}{auth_header}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().ok();

    let mut buffered: Vec<u8> = Vec::new();
    let header_end = loop {
        if let Some(position) = find_subslice(&buffered, b"\r\n\r\n") {
            break position;
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).expect("read response");
        if read == 0 {
            break buffered.len();
        }
        buffered.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffered[..header_end]).to_string();
    let status_line = head.lines().next().unwrap_or_default().to_string();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let mut response_body = buffered[header_end + 4..].to_vec();

    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while response_body.len() < content_length {
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => response_body.extend_from_slice(&chunk[..read]),
        }
    }

    let mut headers = HashMap::new();
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    HttpResponse {
        status,
        status_line,
        headers,
        body: String::from_utf8_lossy(&response_body).to_string(),
    }
}

fn post_with_model(port: u16, path: &str, body: &str, model: Option<&str>) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to broker");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");

    let model_header = match model {
        Some(model) => format!("x-llm-model: {model}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n{model_header}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().ok();

    // Read the status line and headers, then exactly as much body as the
    // framing says. A real client never half-closes before reading, and doing
    // so would make the broker see a downstream error instead of a response.
    let mut buffered: Vec<u8> = Vec::new();
    let header_end = loop {
        if let Some(position) = find_subslice(&buffered, b"\r\n\r\n") {
            break position + 4;
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).expect("read header");
        assert!(read > 0, "connection closed before the response headers");
        buffered.extend_from_slice(&chunk[..read]);
    };

    let mut response = parse_response(&buffered[..header_end]);
    let declared = response
        .headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok());

    let mut raw_body = buffered[header_end..].to_vec();
    match declared {
        Some(length) => {
            while raw_body.len() < length {
                let mut chunk = [0u8; 8192];
                let read = stream.read(&mut chunk).expect("read body");
                assert!(read > 0, "connection closed before the body was complete");
                raw_body.extend_from_slice(&chunk[..read]);
            }
            raw_body.truncate(length);
            response.body = String::from_utf8_lossy(&raw_body).to_string();
        }
        None => {
            // No framing header: read until the peer closes.
            let mut chunk = [0u8; 8192];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => raw_body.extend_from_slice(&chunk[..read]),
                    Err(_) => break,
                }
            }
            response.body = dechunk(&raw_body);
        }
    }
    response
}

/// Locate `needle` inside `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parse the status line and headers out of a header block.
fn parse_response(raw: &[u8]) -> HttpResponse {
    let head = String::from_utf8_lossy(raw).to_string();
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default().to_string();
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

    HttpResponse {
        status,
        status_line,
        headers,
        body: String::new(),
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
        vec![provider(
            "primary",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key-a", "sk-key-a"), ("key-b", "sk-key-b")],
        )],
        vec![RouteConfig {
            model: "test-model".into(),
            providers: vec!["primary".into()],
            strategy: None,
            rewrite: false,
        }],
    );
    spawn_broker(config, proxy_port);

    let response = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
    );
    assert_eq!(
        response.status, 200,
        "the request must succeed on the second key: {} | headers {:?} | body {}",
        response.status_line, response.headers, response.body
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

    let response = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
    );
    assert_eq!(response.status, 200, "body: {}", response.body);

    assert_nothing_was_forwarded(
        &primary_seen,
        "the provider that does not serve the model must not be called",
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

    let response = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
    );
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
fn a_model_no_key_declares_is_forwarded_rather_than_refused() {
    // A key's `models` list is a preference, not a gate, so a model nothing
    // declares is forwarded. The assertion is on what the upstream *received*,
    // not on a status: the old test asserted 503 and nothing forwarded, and a
    // status-only rewrite would pass whether or not the body was passed on.
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
    let response = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        body,
        Some("no-such-model"),
    );
    assert_eq!(
        response.status, 200,
        "an undeclared model must be forwarded, got: {}",
        response.body
    );

    let requests = seen.lock().expect("lock").clone();
    assert_eq!(
        requests.len(),
        1,
        "the request must reach the provider exactly once"
    );
    assert!(
        requests[0].body.contains("no-such-model"),
        "the provider must receive the model the client asked for, got: {}",
        requests[0].body
    );
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
            post_with_model(
                proxy_port,
                "/v1/chat/completions",
                CHAT_BODY,
                Some("test-model"),
            )
            .status
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

#[test]
fn glob_routes_pick_the_matching_provider_end_to_end() {
    let gpt_port = free_port();
    let claude_port = free_port();
    let proxy_port = free_port();
    let gpt_seen = spawn_mock(gpt_port, vec![200]);
    let claude_seen = spawn_mock(claude_port, vec![200]);

    let mut gpt = provider(
        "gpt",
        format!("http://127.0.0.1:{gpt_port}"),
        &[("gpt-key", "sk-gpt")],
    );
    gpt.api_keys[0].models = vec!["gpt-4o".into()];
    let mut claude = provider(
        "claude",
        format!("http://127.0.0.1:{claude_port}"),
        &[("claude-key", "sk-claude")],
    );
    claude.api_keys[0].models = vec!["claude-3-5-sonnet".into()];

    // Both providers accept everything they are given, so only the routes
    // decide which one is used.
    for provider in [&mut gpt, &mut claude] {
        provider.api_keys[0].models.clear();
    }

    let mut config = base_config(proxy_port, vec![gpt, claude], vec![]);
    config.routes = vec![
        RouteConfig {
            model: "gpt-*".into(),
            providers: vec!["gpt".into()],
            strategy: None,
            rewrite: false,
        },
        RouteConfig {
            model: "claude-*".into(),
            providers: vec!["claude".into()],
            strategy: None,
            rewrite: false,
        },
    ];
    spawn_broker(config, proxy_port);

    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
    let response = post_with_model(proxy_port, "/v1/chat/completions", body, Some("gpt-4o"));
    assert_eq!(response.status, 200, "{}", response.status_line);
    assert_nothing_was_forwarded(&claude_seen, "the claude route must not serve a gpt model");
    let hits = gpt_seen.lock().expect("lock").clone();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].authorization.as_deref(), Some("Bearer sk-gpt"));

    let body = r#"{"model":"claude-3-5-sonnet","messages":[]}"#;
    let response = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        body,
        Some("claude-3-5-sonnet"),
    );
    assert_eq!(response.status, 200, "{}", response.status_line);
    let hits = claude_seen.lock().expect("lock").clone();
    assert_eq!(hits.len(), 1, "claude hits: {hits:?}");
    // The `claude` provider name selects the `x-api-key` convention, so the
    // credential must arrive in that header rather than as a bearer token.
    assert_eq!(hits[0].api_key.as_deref(), Some("sk-claude"));
    assert!(
        hits[0].authorization.is_none(),
        "a non-bearer provider must not receive an Authorization header: {hits:?}"
    );
    assert_eq!(
        gpt_seen.lock().expect("lock").len(),
        1,
        "the gpt provider must not receive the claude request"
    );
}

#[test]
fn a_rate_limited_key_is_skipped_by_the_next_request() {
    let upstream_port = free_port();
    let proxy_port = free_port();
    // First call 429s, everything after succeeds.
    let seen = spawn_mock(upstream_port, vec![429, 200]);

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

    // Request 1 rotates off the rate-limited key.
    let first = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
    );
    assert_eq!(first.status, 200, "{}", first.status_line);

    // Request 2 must not start on the key that just 429'd.
    let second = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
    );
    assert_eq!(second.status, 200, "{}", second.status_line);

    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests.len(), 3, "expected one rotation then a clean call");
    let first_key = requests[0].authorization.clone().unwrap();
    let third_key = requests[2].authorization.clone().unwrap();
    assert_ne!(
        first_key, third_key,
        "the cooled-down key must not be picked again immediately"
    );
}

// ---------------------------------------------------------------------------
// Data security: who may send what, proven over the wire.
// ---------------------------------------------------------------------------

fn client_config(
    name: &str,
    token: &str,
    models: &[&str],
    providers: &[&str],
) -> aibroker::config::ClientConfig {
    aibroker::config::ClientConfig {
        name: name.into(),
        token: token.into(),
        enabled: true,
        allowed_models: models.iter().map(|m| (*m).to_string()).collect(),
        allowed_providers: providers.iter().map(|p| (*p).to_string()).collect(),
        max_rpm: None,
        max_tpm: None,
        max_concurrency: None,
    }
}

/// A broker with clients configured and one healthy upstream.
fn secured_broker(
    clients: Vec<aibroker::config::ClientConfig>,
) -> (u16, Arc<Mutex<Vec<SeenRequest>>>) {
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200, 200, 200, 200, 200, 200, 200, 200]);

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.clients = clients;
    spawn_broker(config, proxy_port);
    (proxy_port, seen)
}

#[test]
fn a_request_without_a_client_token_is_refused_before_it_is_forwarded() {
    let (port, seen) = secured_broker(vec![client_config("laptop", "tok-good", &[], &[])]);
    let response = post_as_client(
        port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
        None,
    );

    assert_eq!(response.status, 401, "{}", response.status_line);
    assert_eq!(
        response.headers.get("www-authenticate").map(String::as_str),
        Some("Bearer realm=\"LLM Broker\""),
        "a client needs to know how to authenticate"
    );
    assert_nothing_was_forwarded(
        &seen,
        "an unauthenticated request must never reach the provider",
    );
}

#[test]
fn an_unknown_client_token_is_refused_without_reaching_the_provider() {
    let (port, seen) = secured_broker(vec![client_config("laptop", "tok-good", &[], &[])]);
    let response = post_as_client(
        port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
        Some("tok-guessed"),
    );

    assert_eq!(response.status, 401, "{}", response.status_line);
    assert!(
        !response.body.contains("tok-guessed"),
        "the refusal must not echo the presented token"
    );
    assert_nothing_was_forwarded(&seen, "refused before reaching a provider");
}

#[test]
fn a_permitted_client_is_proxied_normally() {
    let (port, seen) = secured_broker(vec![client_config("laptop", "tok-good", &["test-*"], &[])]);
    let response = post_as_client(
        port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
        Some("tok-good"),
    );

    assert_eq!(response.status, 200, "{}", response.status_line);
    assert_eq!(
        seen.lock().expect("lock").len(),
        1,
        "the request should have been forwarded exactly once"
    );
}

#[test]
fn a_model_outside_the_client_allow_list_never_leaves_the_machine() {
    // The whole point: content for a forbidden model must not be uploaded.
    let (port, seen) = secured_broker(vec![client_config(
        "laptop",
        "tok-good",
        &["claude-*"],
        &[],
    )]);
    let response = post_as_client(
        port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
        Some("tok-good"),
    );

    assert_eq!(response.status, 403, "{}", response.status_line);
    assert_nothing_was_forwarded(&seen, "a forbidden model must not be forwarded");
    assert_eq!(
        response
            .headers
            .get("x-llm-broker-error")
            .map(String::as_str),
        Some("model_forbidden")
    );
}

#[test]
fn two_clients_get_their_own_rules() {
    let (port, _seen) = secured_broker(vec![
        client_config("restricted", "tok-a", &["claude-*"], &[]),
        client_config("allowed", "tok-b", &["test-*"], &[]),
    ]);

    let restricted = post_as_client(
        port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
        Some("tok-a"),
    );
    assert_eq!(restricted.status, 403, "{}", restricted.status_line);

    let allowed = post_as_client(
        port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
        Some("tok-b"),
    );
    assert_eq!(
        allowed.status, 200,
        "client B's rules must not be affected by client A: {}",
        allowed.status_line
    );
}

#[test]
fn an_open_proxy_needs_no_token() {
    // The single-user default must keep working: no clients configured.
    let (port, seen) = secured_broker(vec![]);
    let response = post_as_client(
        port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
        None,
    );

    assert_eq!(response.status, 200, "{}", response.status_line);
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

#[test]
fn a_policy_denial_is_enforced_and_explained() {
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200]);

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    // A policy that refuses this specific model, and says why.
    config.policy = aibroker::config::PolicyConfig {
        enabled: true,
        files: vec![],
        inline: r#"package llm.authz
import rego.v1
default allow := false
allow if input.request.model != "test-model"
reason := "test-model is not permitted by policy" if input.request.model == "test-model"
"#
        .to_string(),
        inline_name: "test.rego".to_string(),
        ..Default::default()
    };
    spawn_broker(config, proxy_port);

    let response = post_as_client(
        proxy_port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
        None,
    );

    assert_eq!(response.status, 403, "{}", response.status_line);
    assert!(
        response
            .body
            .contains("test-model is not permitted by policy"),
        "the policy's own reason should reach the caller: {}",
        response.body
    );

    assert_nothing_was_forwarded(&seen, "a policy denial must not forward the body");
}

#[test]
fn a_broken_policy_refuses_traffic_instead_of_forwarding_it() {
    // Fail closed: a policy that cannot be evaluated must not become an
    // open door. `Runtime::new` rejects an invalid policy outright, so this
    // asserts the refusal at construction time.
    let upstream_port = free_port();
    let mut config = base_config(
        free_port(),
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.policy = aibroker::config::PolicyConfig {
        enabled: true,
        files: vec![],
        inline: "package llm.authz\nthis is not valid rego\n".to_string(),
        inline_name: "broken.rego".to_string(),
        ..Default::default()
    };

    let error = match Runtime::new(config, None) {
        Ok(_) => panic!("a broken policy must fail the runtime"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("invalid policy"), "{error}");
}

// ---------------------------------------------------------------------------
// Both OpenAI API dialects.
// ---------------------------------------------------------------------------

const RESPONSES_BODY: &str = r#"{"model":"test-model","input":"hello","max_output_tokens":64}"#;

/// A broker with one healthy upstream, for dialect tests.
fn plain_broker() -> (u16, Arc<Mutex<Vec<SeenRequest>>>) {
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200, 200, 200, 200, 200, 200]);
    let config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    spawn_broker(config, proxy_port);
    (proxy_port, seen)
}

#[test]
fn the_responses_api_is_proxied_when_the_model_is_declared() {
    // `/v1/responses` has no model in its path and pingora cannot peek the body
    // before routing, so the client declares it. Everything after routing is
    // dialect-independent, which this proves.
    let (port, seen) = plain_broker();
    let response = post_with_model(port, "/v1/responses", RESPONSES_BODY, Some("test-model"));

    assert_eq!(response.status, 200, "{}", response.status_line);
    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests.len(), 1, "the request should reach the upstream");
    assert_eq!(
        requests[0].path, "/v1/responses",
        "the path must be forwarded untouched, not rewritten to chat/completions"
    );
}

#[test]
fn the_responses_api_accepts_the_model_as_a_query_parameter() {
    // A caller that cannot set a header can put it in the URL instead.
    let (port, seen) = plain_broker();
    let response = post_with_model(port, "/v1/responses?model=test-model", RESPONSES_BODY, None);

    assert_eq!(response.status, 200, "{}", response.status_line);
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

#[test]
fn the_responses_api_is_proxied_without_a_declared_model() {
    // The JSON `model` field cannot be read before the body streams, but the
    // request must not be refused for that: the body is forwarded untouched, so
    // the provider still receives `model` and serves the right model. The broker
    // simply has less to route on, exactly as for a chat completion that omits
    // `x-llm-model`.
    let (port, seen) = plain_broker();
    let response = post_with_model(port, "/v1/responses", RESPONSES_BODY, None);

    assert_eq!(response.status, 200, "{}", response.status_line);
    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests.len(), 1, "the request should reach the upstream");
    assert_eq!(requests[0].path, "/v1/responses");
    assert!(
        requests[0].body.contains(r#""model":"test-model""#),
        "the body must reach the provider unchanged, model included: {}",
        requests[0].body
    );
}

#[test]
fn chat_completions_still_works_after_adding_the_second_dialect() {
    // The regression guard for the dialect work: the original format must be
    // untouched.
    let (port, seen) = plain_broker();
    let response = post_with_model(port, "/v1/chat/completions", CHAT_BODY, Some("test-model"));

    assert_eq!(response.status, 200, "{}", response.status_line);
    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests[0].path, "/v1/chat/completions");
}

#[test]
fn a_decoy_model_in_the_body_is_not_picked_up() {
    // Scope note, because the name could over-promise: the body-derived model
    // does *not* drive routing. pingora chooses the upstream peer before the
    // body is streamed, so `resolve_model` runs afterwards, for logging, metrics
    // and the per-model counters. What this asserts is that a decoy nested
    // object cannot reach any of those, nor be forwarded in place of the real
    // model. The claim that the parser prefers the top-level field is proven by
    // the unit tests in `proxy::payload`, which can call it directly.
    let (port, seen) = plain_broker();
    let body = r#"{"metadata":{"model":"decoy-model"},"messages":[{"role":"user","content":"hi"}],"model":"test-model"}"#;

    let response = post_with_model(port, "/v1/chat/completions", body, None);
    assert_eq!(response.status, 200, "{}", response.status_line);

    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests.len(), 1, "the request should be forwarded once");
    assert!(
        requests[0].body.contains(r#""model":"test-model""#),
        "the real model must be forwarded: {}",
        requests[0].body
    );
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer sk-mock-1"),
        "the provider's own key must be the credential, not anything from the body"
    );
}

#[test]
fn a_healthy_pool_shares_load_evenly_under_least_latency() {
    // End-to-end guard for a measured defect. `least_latency` ranked an
    // unmeasured key as infinitely slow, so after the first request measured
    // key1, keys 2 and 3 were never tried again: 30/0/0 over three runs. It then
    // ignored capacity, so when the favourite's quota ran out the broker spent
    // its retries rotating off exhausted keys.
    //
    // The assertion is deliberately loose. Exact equality would depend on
    // timing, and this is about the gross failure (one key taking everything),
    // not about a perfect split.
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200; 60]);

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[
                ("key1", "sk-mock-1"),
                ("key2", "sk-mock-2"),
                ("key3", "sk-mock-3"),
            ],
        )],
        vec![],
    );
    config.load_balancing.strategy = "least_latency".to_string();
    spawn_broker(config, proxy_port);

    let total = 30usize;
    for _ in 0..total {
        let response = post_with_model(
            proxy_port,
            "/v1/chat/completions",
            CHAT_BODY,
            Some("test-model"),
        );
        assert_eq!(response.status, 200, "{}", response.status_line);
    }

    let requests = seen.lock().expect("lock").clone();
    assert_eq!(requests.len(), total, "every request should be served once");

    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for request in &requests {
        let key = request.authorization.clone().unwrap_or_default();
        *counts.entry(key).or_insert(0) += 1;
    }

    assert_eq!(counts.len(), 3, "all three keys should be used: {counts:?}");
    // A third of 30 is 10; allow a wide band, but not a monopoly.
    for (key, count) in &counts {
        assert!(
            (4..=16).contains(count),
            "{key} received {count} of {total} requests, which is not a share: {counts:?}"
        );
    }
}

#[test]
fn a_shadow_policy_reports_but_never_blocks() {
    // The point of a shadow policy: find out what a candidate policy *would*
    // do to real traffic without letting it break anything. Everything here is
    // denied by the shadow policy and must still be served.
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200; 12]);

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    // The enforcing policy allows everything; the shadow policy denies
    // everything with an explanatory reason.
    config.policy = aibroker::config::PolicyConfig {
        enabled: true,
        inline: r#"package llm.authz
import rego.v1
default allow := true
"#
        .to_string(),
        inline_name: "allow-all.rego".to_string(),
        dry_run_inline: Some(
            r#"package llm.authz
import rego.v1
default allow := false
reason := "the shadow policy denies everything"
"#
            .to_string(),
        ),
        ..Default::default()
    };
    let runtime = spawn_broker_with_runtime(config, proxy_port);

    let before = runtime
        .read()
        .metrics()
        .shadow_policy_blocks
        .load(std::sync::atomic::Ordering::Relaxed);

    for _ in 0..5 {
        let response = post_with_model(
            proxy_port,
            "/v1/chat/completions",
            CHAT_BODY,
            Some("test-model"),
        );
        assert_eq!(
            response.status, 200,
            "a shadow policy must never change the outcome: {}",
            response.status_line
        );
    }

    assert_eq!(
        seen.lock().expect("lock").len(),
        5,
        "every request should have reached the provider"
    );

    // The report is the whole value of the feature: without this assertion the
    // test would pass even if the shadow policy were never evaluated.
    let after = runtime
        .read()
        .metrics()
        .shadow_policy_blocks
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        after - before,
        5,
        "every request should have been reported as a would-be denial"
    );
}

#[test]
fn an_enforcing_policy_still_blocks_while_a_shadow_one_runs() {
    // The mirror of the test above, proving the two are independent: same
    // policy content, but this time it is the enforcing one.
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200; 12]);

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.policy = aibroker::config::PolicyConfig {
        enabled: true,
        inline: r#"package llm.authz
import rego.v1
default allow := false
reason := "this policy denies everything"
"#
        .to_string(),
        inline_name: "deny-all.rego".to_string(),
        ..Default::default()
    };
    spawn_broker(config, proxy_port);

    let response = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        CHAT_BODY,
        Some("test-model"),
    );
    assert_eq!(response.status, 403, "{}", response.status_line);
    assert!(
        response.body.contains("this policy denies everything"),
        "{}",
        response.body
    );
    assert_nothing_was_forwarded(&seen, "a denied request must not be forwarded");
}

#[test]
fn a_broken_shadow_policy_fails_at_startup() {
    // A shadow policy is still configuration; a syntax error should be found
    // when the broker starts, not silently ignored.
    let upstream_port = free_port();
    let mut config = base_config(
        free_port(),
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.policy = aibroker::config::PolicyConfig {
        enabled: true,
        dry_run_inline: Some("package llm.authz\nthis is not rego\n".to_string()),
        ..Default::default()
    };

    let error = match Runtime::new(config, None) {
        Ok(_) => panic!("a broken shadow policy must fail the runtime"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("invalid policy"), "{error}");
}

// ---------------------------------------------------------------------------
// Content inspection: what is inside the prompt.
// ---------------------------------------------------------------------------

const SECRET_BODY: &str = r#"{"model":"test-model","messages":[{"role":"user","content":"my key is AKIAIOSFODNN7EXAMPLE"}]}"#;

fn content_config(action: &str) -> aibroker::config::ContentGuardConfig {
    aibroker::config::ContentGuardConfig {
        enabled: true,
        action: Some(action.to_string()),
        patterns: vec![aibroker::config::ContentPattern {
            name: "aws-key".into(),
            pattern: r"AKIA[0-9A-Z]{16}".into(),
        }],
        allow: vec![],
    }
}

fn guarded_broker(
    action: &str,
) -> (
    u16,
    Arc<Mutex<Vec<SeenRequest>>>,
    aibroker::core::runtime::SharedRuntime,
) {
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200; 12]);

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.content_guard = content_config(action);
    let runtime = spawn_broker_with_runtime(config, proxy_port);
    (proxy_port, seen, runtime)
}

#[test]
fn a_secret_in_a_prompt_is_refused_before_it_is_forwarded() {
    // The whole point of inspecting content: this body never reaches the
    // provider.
    let (port, seen, _runtime) = guarded_broker("deny");
    let response = post_with_model(
        port,
        "/v1/chat/completions",
        SECRET_BODY,
        Some("test-model"),
    );

    assert_eq!(response.status, 403, "{}", response.status_line);
    // The upstream request *headers* may already have been written when the
    // body filter refuses -- pingora streams the body after the header -- so the
    // property to assert is not "no connection", it is "the content never left".
    // Measured: the mock sees the path with an empty body.
    assert_nothing_was_forwarded(&seen, "the guard must withhold the body");
    let requests = seen.lock().expect("lock").clone();
    for request in &requests {
        assert!(
            !request.body.contains("AKIAIOSFODNN7EXAMPLE"),
            "the secret reached the provider in {}: {}",
            request.path,
            request.body
        );
    }

    eprintln!(
        "PROBE status={} broker_error={:?} body={}",
        response.status,
        response.headers.get("x-llm-broker-error"),
        response.body
    );
    assert!(
        response.body.contains("aws-key"),
        "the refusal should name the rule: {}",
        response.body
    );
    assert!(
        !response.body.contains("AKIAIOSFODNN7EXAMPLE"),
        "the refusal must never echo the secret: {}",
        response.body
    );
}

#[test]
fn a_rego_content_rule_refuses_what_the_config_only_reports() {
    // `[content_guard] action = "report"` says "watch this, do not block it".
    // The policy disagrees for one rule and the request must not leave.
    //
    // This is the end-to-end version of `content_verdict`, and it asserts the
    // same way the guard's own tests do: on what the upstream received, not on
    // the status code. A 403 with the secret already in the body would satisfy a
    // status-only assertion and fail the actual requirement.
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200; 12]);

    // Two packages, so two files: one answers the admission question the broker
    // always asks, the other decides what to do about the finding.
    let dir = std::env::temp_dir().join(format!("aibroker-content-policy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp rules dir");
    std::fs::write(
        dir.join("10-authz.rego"),
        "package llm.authz\nimport rego.v1\nallow := true\n",
    )
    .expect("write authz policy");
    std::fs::write(
        dir.join("20-content.rego"),
        "package llm.content\nimport rego.v1\n\
         action := \"deny\" if { input.rule == \"aws-key\" }\n\
         reason := \"an AWS key is never allowed in a prompt\" if { input.rule == \"aws-key\" }\n\
         action := \"report\" if { input.rule != \"aws-key\" }\n",
    )
    .expect("write content policy");

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.content_guard = content_config("report");
    config.policy = aibroker::config::PolicyConfig {
        enabled: true,
        rules_dir: dir.to_string_lossy().to_string(),
        ..Default::default()
    };
    let _runtime = spawn_broker_with_runtime(config, proxy_port);

    let response = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        SECRET_BODY,
        Some("test-model"),
    );

    assert_eq!(
        response.status, 403,
        "the policy must escalate report to a refusal: {}",
        response.status_line
    );
    assert_nothing_was_forwarded(&seen, "a policy denial must withhold the body");
    for request in seen.lock().expect("lock").iter() {
        assert!(
            !request.body.contains("AKIAIOSFODNN7EXAMPLE"),
            "the secret reached the provider in {}: {}",
            request.path,
            request.body
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_policy_that_cannot_answer_the_content_question_refuses() {
    // The policy defines `action`, but only for a rule that never fires here.
    // At runtime the value is *undefined* for this finding, which is not "no
    // opinion" -- it is a broken policy.
    //
    // Fail closed: the configured action is `report`, so falling back to it
    // would forward the secret while the broker believed it was protected. The
    // only acceptable outcome is a refusal.
    let upstream_port = free_port();
    let proxy_port = free_port();
    let seen = spawn_mock(upstream_port, vec![200; 12]);

    let dir = std::env::temp_dir().join(format!("aibroker-broken-policy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp rules dir");
    std::fs::write(
        dir.join("10-authz.rego"),
        "package llm.authz\nimport rego.v1\nallow := true\n",
    )
    .expect("write authz policy");
    std::fs::write(
        dir.join("20-content.rego"),
        "package llm.content\nimport rego.v1\n\
         action := \"deny\" if { input.rule == \"some-rule-that-never-fires\" }\n",
    )
    .expect("write content policy");

    let mut config = base_config(
        proxy_port,
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.content_guard = content_config("report");
    config.policy = aibroker::config::PolicyConfig {
        enabled: true,
        rules_dir: dir.to_string_lossy().to_string(),
        ..Default::default()
    };
    let _runtime = spawn_broker_with_runtime(config, proxy_port);

    let response = post_with_model(
        proxy_port,
        "/v1/chat/completions",
        SECRET_BODY,
        Some("test-model"),
    );

    assert_eq!(
        response.status, 403,
        "an unanswerable content policy must refuse: {}",
        response.status_line
    );
    assert_nothing_was_forwarded(&seen, "a policy error must withhold the body");
    for request in seen.lock().expect("lock").iter() {
        assert!(
            !request.body.contains("AKIAIOSFODNN7EXAMPLE"),
            "the secret reached the provider in {}: {}",
            request.path,
            request.body
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_clean_prompt_is_forwarded_normally() {
    let (port, seen, _runtime) = guarded_broker("deny");
    let response = post_with_model(port, "/v1/chat/completions", CHAT_BODY, Some("test-model"));

    assert_eq!(response.status, 200, "{}", response.status_line);
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

#[test]
fn report_mode_counts_a_finding_and_still_forwards() {
    // The honest default: find out what the patterns match against real traffic
    // before letting them refuse anything.
    let (port, seen, runtime) = guarded_broker("report");
    let before = runtime
        .read()
        .metrics()
        .content_findings
        .load(std::sync::atomic::Ordering::Relaxed);

    let response = post_with_model(
        port,
        "/v1/chat/completions",
        SECRET_BODY,
        Some("test-model"),
    );
    assert_eq!(response.status, 200, "{}", response.status_line);
    assert_eq!(
        seen.lock().expect("lock").len(),
        1,
        "report mode must still forward"
    );

    let after = runtime
        .read()
        .metrics()
        .content_findings
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(after - before, 1, "the finding should have been counted");
}

#[test]
fn a_pattern_that_matches_nothing_reports_nothing() {
    let (port, _seen, runtime) = guarded_broker("report");
    let before = runtime
        .read()
        .metrics()
        .content_findings
        .load(std::sync::atomic::Ordering::Relaxed);

    let response = post_with_model(port, "/v1/chat/completions", CHAT_BODY, Some("test-model"));
    assert_eq!(response.status, 200, "{}", response.status_line);

    let after = runtime
        .read()
        .metrics()
        .content_findings
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(after, before, "a clean body must not be reported");
}

#[test]
fn a_guard_without_patterns_is_a_configuration_error() {
    // Enabling the guard and listing nothing would look like protection while
    // inspecting nothing.
    let upstream_port = free_port();
    let mut config = base_config(
        free_port(),
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.content_guard = aibroker::config::ContentGuardConfig {
        enabled: true,
        action: None,
        patterns: vec![],
        allow: vec![],
    };

    let error = match Runtime::new(config, None) {
        Ok(_) => panic!("an empty guard must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("no patterns"), "{error}");
}

#[test]
fn an_unknown_guard_action_is_a_configuration_error() {
    // Silently falling back to `report` would leave an operator believing
    // traffic is blocked when it is only counted.
    let upstream_port = free_port();
    let mut config = base_config(
        free_port(),
        vec![provider(
            "test-provider",
            format!("http://127.0.0.1:{upstream_port}"),
            &[("key1", "sk-mock-1")],
        )],
        vec![],
    );
    config.content_guard = content_config("blck");

    let error = match Runtime::new(config, None) {
        Ok(_) => panic!("a misspelled action must be rejected"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("not `report` or `deny`"),
        "{error}"
    );
}
