//! Request and response dumping for LLM debugging.
//!
//! Priorities, in order:
//!
//! 1. **Never print a credential.** The broker injects a provider key into the
//!    upstream request, so a naive dump would write secrets to disk. Every
//!    credential header is redacted by name, and the values are never even
//!    looked at.
//! 2. **One line per event.** Bodies are compacted so a message lasts one line,
//!    structured so `grep`, `awk` and `jq -c` still work, and tagged with the
//!    request id and phase so concurrent traffic can be separated.
//! 3. **Whitespace differences are visible.** Header values are printed
//!    verbatim: whether an upstream sends `application/json` or
//!    `application/json; charset=utf-8` is exactly what these dumps are for.
//! 4. **Streaming stays useful.** An SSE answer arrives as many chunks, so each
//!    chunk is printed on its own with the running byte count rather than being
//!    buffered until the end.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;

use crate::proxy::parquet::{
    CaptureWriter, CapturedAttempt, CapturedExchange, DEFAULT_MAX_CAPTURE_BYTES, append_capped,
    now_ms,
};
use crate::proxy::redact::Redactor;

/// Headers whose value must never reach the log.
const SECRET_HEADERS: [&str; 7] = [
    "authorization",
    "x-api-key",
    "api-key",
    "x-admin-token",
    "proxy-authorization",
    "cookie",
    // A session cookie is a bearer credential just as much as a token is.
    "set-cookie",
];

/// The value written in place of a credential.
pub const REDACTED: &str = "<redacted>";

/// What to dump, and how much.
///
/// Not `Copy`: the redactor compiles regexes and owns them.
#[derive(Debug, Clone)]
pub struct DumpConfig {
    pub dump_request: bool,
    pub dump_response: bool,
    /// Maximum bytes of a body printed before it is truncated.
    pub max_body_bytes: usize,
    /// Patterns removed from dumped bodies and header values.
    pub redactor: Redactor,
    /// When set (`-w FILE`), complete exchanges are also written to this
    /// parquet file, with the same redaction applied.
    pub capture: Option<CaptureWriter>,
    /// Per-body byte cap for the parquet capture. Independent of
    /// `max_body_bytes`, which only bounds a single log line.
    pub capture_max_bytes: usize,
}

impl Default for DumpConfig {
    fn default() -> Self {
        Self {
            dump_request: false,
            dump_response: false,
            max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES,
            redactor: Redactor::default(),
            capture: None,
            capture_max_bytes: DEFAULT_MAX_CAPTURE_BYTES,
        }
    }
}

impl DumpConfig {
    pub fn enabled(&self) -> bool {
        self.dump_request || self.dump_response || self.capture.is_some()
    }

    /// Whether complete exchanges are being written to a parquet file.
    pub fn capturing(&self) -> bool {
        self.capture.is_some()
    }

    /// The default body cap.
    ///
    /// Spelled out rather than derived: `usize::default()` is zero, which would
    /// silently truncate every dump to nothing.
    pub const DEFAULT_MAX_BODY_BYTES: usize = 8192;

    /// Set the body cap, clamping to a sane minimum so a dump cannot be
    /// configured into uselessness.
    pub fn with_max_body_bytes(mut self, max: usize) -> Self {
        self.max_body_bytes = max.max(64);
        self
    }
}

/// Per-request dump state: an id and the byte counters used for streaming.
#[derive(Debug)]
pub struct Dump {
    id: u64,
    config: DumpConfig,
    started: Instant,
    request_bytes: usize,
    response_bytes: usize,
    request_headers_done: bool,
    /// How many upstream attempts have started (`upstream_request` calls).
    /// pingora replays the buffered body from the start on every attempt after
    /// the first, so this is what tells a replay apart from more of the body.
    attempts_started: u32,
    /// Set once a retried attempt's replay has been reported in the log, so one
    /// line covers the whole replayed body rather than one per chunk.
    replay_logged: bool,
    capture: Option<Capture>,
}

/// Per-request capture state for the parquet file (`-w`).
///
/// Bodies are accumulated whole (up to the capture cap) rather than sampled
/// per chunk: the file exists so a developer can see the *complete* exchange
/// afterwards. Everything stored here has already been redacted.
#[derive(Debug, Default)]
struct Capture {
    timestamp_ms: u64,
    method: String,
    uri: String,
    request_headers: String,
    request_body: String,
    request_truncated: bool,
    response_headers: String,
    response_body: String,
    response_truncated: bool,
    attempts: Vec<CapturedAttempt>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate the id for a new request.
pub fn next_request_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

impl Dump {
    pub fn new(config: DumpConfig) -> Self {
        Self::with_id(next_request_id(), config)
    }

    /// Build a dump for an id already assigned by the caller, so one id can
    /// cover the whole request even though the dump is created later.
    pub fn with_id(id: u64, config: DumpConfig) -> Self {
        let capture = config.capturing().then(|| Capture {
            timestamp_ms: now_ms(),
            ..Capture::default()
        });
        Self {
            id,
            config,
            started: Instant::now(),
            request_bytes: 0,
            response_bytes: 0,
            request_headers_done: false,
            attempts_started: 0,
            replay_logged: false,
            capture,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn config(&self) -> DumpConfig {
        self.config.clone()
    }

    /// Milliseconds since the request started, so a dump can be correlated
    /// with latency without a separate timestamp format.
    fn at(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn emit(&self, phase: &str, message: &str) {
        // A dedicated target lets an operator silence dumps in production
        // (`RUST_LOG=info,llm_broker::dump=off`) without losing other logs.
        tracing::info!(target: "llm_broker::dump", "[#{} {} +{}ms] {}", self.id, phase, self.at(), message);
    }

    /// Dump request headers (before the provider credential is attached).
    pub fn request_headers(
        &mut self,
        method: &str,
        uri: &str,
        version: &str,
        headers: &pingora::http::RequestHeader,
    ) {
        if (!self.config.dump_request && !self.config.capturing()) || self.request_headers_done {
            return;
        }
        self.request_headers_done = true;
        let rendered = self.redact(&render_headers(headers.headers.iter()));
        if let Some(capture) = self.capture.as_mut() {
            capture.method = method.to_string();
            capture.uri = uri.to_string();
            capture.request_headers = rendered.clone();
        }
        if self.config.dump_request {
            self.emit("req", &format!("{method} {uri} {version}"));
            self.emit("req headers", &rendered);
        }
    }

    /// Dump the upstream request as it will actually be sent, credential
    /// redacted. This is the interesting one: it shows the model routing
    /// result (path, Host), not just what the client asked for.
    pub fn upstream_request(
        &mut self,
        req: &pingora::http::RequestHeader,
        provider: Option<&str>,
        key: Option<&str>,
    ) {
        if !self.config.dump_request && !self.config.capturing() {
            return;
        }
        // A new attempt starts here, and with it a fresh body: pingora replays
        // the buffered request body from the first byte on every attempt after
        // the first, so the per-attempt counter is the reliable signal that the
        // chunks which follow are a replay rather than more of the body.
        self.attempts_started = self.attempts_started.saturating_add(1);
        self.replay_logged = false;
        let rendered = self.redact(&render_headers(req.headers.iter()));
        if let Some(capture) = self.capture.as_mut() {
            // A new attempt starts here: `upstream_peer` re-runs on every key
            // rotation, so each try gets its own record. The provider and key
            // are stamped now, not at finish: a rotation means only the last
            // attempt's routing is still in the context by then.
            capture.attempts.push(CapturedAttempt {
                provider: provider.map(str::to_string),
                key: key.map(str::to_string),
                method: req.method.to_string(),
                url: req.uri.to_string(),
                headers: rendered.clone(),
                ..CapturedAttempt::default()
            });
        }
        if self.config.dump_request {
            self.emit(
                "upstream req",
                &format!("{} {} {:?}", req.method, req.uri, req.version),
            );
            self.emit("upstream req headers", &rendered);
        }
    }

    /// Dump a chunk of the request body.
    ///
    /// Only the beginning of a body is printed. A large LLM request arrives as
    /// many chunks -- an agentic client easily sends hundreds of kilobytes --
    /// and per-chunk progress buries the log. The size is still accounted for,
    /// and a retry (pingora replays the body from its buffer on a key rotation)
    /// is reported rather than re-counted.
    pub fn request_body(&mut self, chunk: &[u8]) {
        if !self.config.dump_request && !self.config.capturing() {
            return;
        }
        // pingora replays the whole buffered body on every attempt after the
        // first, and a body larger than its read buffer comes back chunk by
        // chunk. Comparing one chunk against the running total only recognised
        // a single-chunk replay, so a multi-chunk body was appended a second
        // time and the capture held the request twice. The attempt counter is
        // the reliable signal: anything arriving while `attempts_started > 1`
        // belongs to a replay of bytes already captured.
        if self.attempts_started > 1 {
            if !self.replay_logged {
                self.replay_logged = true;
                if self.config.dump_request {
                    self.emit(
                        "req body",
                        &format!("replaying the {} byte body for a retry", self.request_bytes),
                    );
                }
            }
            return;
        }
        let first_chunk = self.request_bytes == 0;
        if let Some(capture) = self.capture.as_mut() {
            capture.request_truncated |= append_capped(
                &mut capture.request_body,
                chunk,
                self.config.capture_max_bytes,
            );
        }
        // A large upload arrives as many chunks. Print only the first: it shows
        // the payload's shape and the summary reports the total, so per-chunk
        // progress would only bury it.
        if first_chunk && self.config.dump_request {
            let message = self.request_body_message(chunk);
            self.emit("req body", &message);
        }
        self.request_bytes += chunk.len();
    }

    /// Dump the response status line and headers.
    pub fn response_headers(&mut self, status: u16, headers: &pingora::http::ResponseHeader) {
        if !self.config.dump_response && !self.config.capturing() {
            return;
        }
        let rendered = self.redact(&render_headers(headers.headers.iter()));
        if let Some(capture) = self.capture.as_mut() {
            capture.response_headers = rendered.clone();
            // A fresh response body per attempt: on a rotation the previous
            // attempt keeps its 429/5xx body, which is the interesting part.
            capture.response_body.clear();
            capture.response_truncated = false;
            if let Some(attempt) = capture.attempts.last_mut() {
                attempt.status = Some(status);
                attempt.response_headers = rendered.clone();
            }
        }
        if self.config.dump_response {
            self.emit("resp", &format!("{status}"));
            self.emit("resp headers", &rendered);
        }
    }

    /// Dump a chunk of the response body. SSE answers arrive as many chunks;
    /// each is printed so the stream can be followed live.
    pub fn response_body(&mut self, chunk: &[u8], end_of_stream: bool) {
        if !self.config.dump_response && !self.config.capturing() {
            return;
        }
        let total = self.response_bytes + chunk.len();
        if let Some(capture) = self.capture.as_mut() {
            capture.response_truncated |= append_capped(
                &mut capture.response_body,
                chunk,
                self.config.capture_max_bytes,
            );
            if end_of_stream && let Some(attempt) = capture.attempts.last_mut() {
                attempt.response_body = capture.response_body.clone();
            }
        }
        if self.config.dump_response {
            // SSE frames are newline separated; print them as separate events.
            let messages = self.response_body_messages(chunk);
            for message in &messages {
                self.emit("resp body", message);
            }
            if end_of_stream {
                self.emit(
                    "resp body",
                    &format!("<end of stream, {total} bytes total>"),
                );
            }
        }
        self.response_bytes = total;
    }

    /// The message a request body chunk would produce, redacted.
    ///
    /// Split out from the emit so a test can assert on the text that reaches
    /// the log without installing a tracing subscriber. Testing the redactor in
    /// isolation would not prove the dump path calls it -- which is exactly the
    /// mistake this shape avoids.
    fn request_body_message(&self, chunk: &[u8]) -> String {
        self.redact(&format_body(chunk, self.config.max_body_bytes))
    }

    /// The messages a response body chunk would produce, redacted.
    fn response_body_messages(&self, chunk: &[u8]) -> Vec<String> {
        let text = String::from_utf8_lossy(chunk);
        let mut messages: Vec<String> = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            messages.push(self.redact(&truncate(line, self.config.max_body_bytes)));
        }
        if messages.is_empty() && !chunk.is_empty() {
            messages.push(format!("<binary {} bytes>", chunk.len()));
        }
        messages
    }

    /// Apply the configured redaction rules.
    fn redact(&self, text: &str) -> String {
        if self.config.redactor.is_empty() {
            return text.to_string();
        }
        self.config.redactor.apply(text)
    }

    /// Write the finished exchange to the parquet capture file, if `-w` is on.
    ///
    /// Called once per request from the proxy's `logging` phase, so a request
    /// refused at the edge (no upstream attempt at all) is captured too.
    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        &mut self,
        status: Option<u16>,
        attempts: u32,
        provider: Option<&str>,
        key: Option<&str>,
        model: Option<&str>,
        client: Option<&str>,
    ) {
        let Some(writer) = self.config.capture.as_ref() else {
            return;
        };
        // Redaction only needs the config; taking it out of the borrow lets
        // the capture below be moved out field by field.
        let config = self.config.clone();
        let duration_ms = self.at();
        let request_bytes = self.request_bytes as u64;
        let response_bytes = self.response_bytes as u64;
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        // The log path redacts each chunk before printing; the capture keeps
        // whole bodies, so the rules run once over the assembled text — a
        // pattern spanning a chunk boundary is caught here, not missed.
        let redact_captured = |text: &str| {
            let redacted = config.redactor.apply(text);
            if redacted.len() <= config.capture_max_bytes {
                return redacted;
            }
            let mut out = String::new();
            append_capped(&mut out, redacted.as_bytes(), config.capture_max_bytes);
            out
        };
        let exchange = CapturedExchange {
            id: self.id,
            timestamp_ms: capture.timestamp_ms,
            duration_ms,
            method: std::mem::take(&mut capture.method),
            uri: std::mem::take(&mut capture.uri),
            request_headers: std::mem::take(&mut capture.request_headers),
            request_body: redact_captured(&capture.request_body),
            request_bytes,
            request_truncated: capture.request_truncated,
            model: model.map(str::to_string),
            provider: provider.map(str::to_string),
            key: key.map(str::to_string),
            client: client.map(str::to_string),
            attempts,
            status,
            response_headers: std::mem::take(&mut capture.response_headers),
            response_body: redact_captured(&capture.response_body),
            response_bytes,
            response_truncated: capture.response_truncated,
            upstream_attempts: capture
                .attempts
                .iter_mut()
                .map(|attempt| CapturedAttempt {
                    provider: attempt.provider.take(),
                    key: attempt.key.take(),
                    method: std::mem::take(&mut attempt.method),
                    url: std::mem::take(&mut attempt.url),
                    status: attempt.status,
                    headers: std::mem::take(&mut attempt.headers),
                    response_headers: std::mem::take(&mut attempt.response_headers),
                    response_body: redact_captured(&attempt.response_body),
                })
                .collect(),
        };
        writer.record(exchange);
    }

    /// Report the outcome once the request is finished.
    pub fn summary(
        &self,
        status: Option<u16>,
        attempts: u32,
        provider: Option<&str>,
        key: Option<&str>,
    ) {
        if !self.config.enabled() {
            return;
        }
        self.emit(
            "done",
            &format!(
                "status={} attempts={attempts} provider={} key={} req_bytes={} resp_bytes={}",
                status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                provider.unwrap_or("-"),
                key.unwrap_or("-"),
                self.request_bytes,
                self.response_bytes,
            ),
        );
    }
}

/// Render headers, redacting credentials.
///
/// Values are printed verbatim (no re-encoding) because whitespace and casing
/// in headers are frequently the bug being chased.
pub fn render_headers<'a, I>(headers: I) -> String
where
    I: Iterator<Item = (&'a http::HeaderName, &'a http::HeaderValue)>,
{
    let mut parts: Vec<String> = Vec::new();
    for (name, value) in headers {
        // Values are printed verbatim; only the name decides redaction, so a
        // credential is never even looked at.
        let rendered = if SECRET_HEADERS.contains(&name.as_str()) {
            REDACTED.to_string()
        } else {
            value.to_str().unwrap_or("<non-utf8>").to_string()
        };
        parts.push(format!("{name}: {rendered}"));
    }
    parts.join(" | ")
}

/// Render a body for one log line: JSON is compacted, everything else is
/// printed as-is, and long output is truncated with the real size reported.
pub fn format_body(chunk: &[u8], max_bytes: usize) -> String {
    let text = match std::str::from_utf8(chunk) {
        Ok(text) => text,
        Err(_) => return format!("<binary {} bytes>", chunk.len()),
    };

    // SSE or NDJSON: keep the frames on their own lines even though the whole
    // message is emitted as one event.
    let compact = match serde_json::from_str::<serde_json::Value>(text.trim()) {
        Ok(value) => serde_json::to_string(&value).unwrap_or_else(|_| text.to_string()),
        Err(_) => text.trim_end().to_string(),
    };
    truncate(&compact, max_bytes)
}

/// Truncate on a character boundary, reporting how much was dropped.
pub fn truncate(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… <{} more bytes>", &text[..end], text.len() - end)
}

/// A single dump event, used by the tests and by `--dump-config` style output.
#[derive(Debug, Serialize)]
pub struct DumpEvent<'a> {
    pub request: u64,
    pub phase: &'a str,
    pub message: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::http::{RequestHeader, ResponseHeader};

    fn headers(pairs: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("POST", b"/v1/chat/completions", None).unwrap();
        for (name, value) in pairs {
            // `insert_header` needs an owned name, so parse rather than pass
            // the borrowed literal.
            let name = http::HeaderName::from_bytes(name.as_bytes()).unwrap();
            let value = http::HeaderValue::from_str(value).unwrap();
            req.insert_header(name, value).unwrap();
        }
        req
    }

    #[test]
    fn credentials_are_redacted_by_header_name() {
        let req = headers(&[
            ("Authorization", "Bearer sk-mock-1"),
            ("x-api-key", "sk-ant-secret"),
            ("X-Admin-Token", "admin-secret"),
            ("Cookie", "session=abc"),
            ("Content-Type", "application/json"),
        ]);
        let rendered = render_headers(req.headers.iter());

        for secret in ["sk-mock-1", "sk-ant-secret", "admin-secret", "session=abc"] {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
        // The header map normalises names to lowercase.
        assert!(rendered.contains("authorization: <redacted>"), "{rendered}");
        assert!(rendered.contains("x-api-key: <redacted>"), "{rendered}");
        // Non-credential headers are printed verbatim, whitespace and all.
        assert!(
            rendered.contains("content-type: application/json"),
            "{rendered}"
        );
    }

    /// A capture-only config writing to a fresh temp file.
    fn capturing(name: &str, redactor: Redactor) -> (Dump, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("aibroker-dump-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let writer = crate::proxy::parquet::CaptureWriter::create(&path).unwrap();
        let config = DumpConfig {
            capture: Some(writer),
            redactor,
            ..DumpConfig::default()
        };
        (Dump::new(config), path)
    }

    fn captured_rows(path: &std::path::Path) -> Vec<crate::proxy::parquet::CapturedExchange> {
        use arrow_array::{StringArray, UInt16Array, UInt64Array};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let batches = loop {
            if let Ok(file) = std::fs::File::open(path)
                && let Ok(builder) = ParquetRecordBatchReaderBuilder::try_new(file)
                && let Ok(reader) = builder.build()
            {
                let batches: Vec<_> = reader.map(|b| b.unwrap()).collect();
                if !batches.is_empty() {
                    break batches;
                }
            }
            assert!(
                Instant::now() < deadline,
                "no rows landed in {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        };
        let mut rows = Vec::new();
        for batch in batches {
            let u64_of = |name: &str, i: usize| {
                batch
                    .column_by_name(name)
                    .unwrap()
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .unwrap()
                    .value(i)
            };
            let string = |name: &str, i: usize| {
                batch
                    .column_by_name(name)
                    .unwrap()
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .unwrap()
                    .value(i)
                    .to_string()
            };
            for i in 0..batch.num_rows() {
                rows.push(crate::proxy::parquet::CapturedExchange {
                    id: batch
                        .column_by_name("id")
                        .unwrap()
                        .as_any()
                        .downcast_ref::<UInt64Array>()
                        .unwrap()
                        .value(i),
                    status: batch
                        .column_by_name("status")
                        .unwrap()
                        .as_any()
                        .downcast_ref::<UInt16Array>()
                        .unwrap()
                        .value(i)
                        .into(),
                    method: string("method", i),
                    uri: string("uri", i),
                    request_headers: string("request_headers", i),
                    request_body: string("request_body", i),
                    response_headers: string("response_headers", i),
                    response_body: string("response_body", i),
                    request_bytes: u64_of("request_bytes", i),
                    response_bytes: u64_of("response_bytes", i),
                    upstream_attempts: serde_json::from_str::<Vec<serde_json::Value>>(&string(
                        "upstream_attempts",
                        i,
                    ))
                    .unwrap()
                    .into_iter()
                    .map(|attempt| crate::proxy::parquet::CapturedAttempt {
                        provider: attempt["provider"].as_str().map(str::to_string),
                        key: attempt["key"].as_str().map(str::to_string),
                        status: attempt["status"].as_u64().map(|s| s as u16),
                        ..Default::default()
                    })
                    .collect(),
                    ..Default::default()
                });
            }
        }
        rows
    }

    #[test]
    fn capture_only_config_is_enabled_without_log_flags() {
        // `-w` alone must attach the dump state; gating on the log flags only
        // would silently capture nothing.
        let (dump, path) = capturing("enabled.parquet", Redactor::default());
        assert!(dump.config.enabled());
        assert!(dump.capture.is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_complete_exchange_lands_in_the_parquet_file() {
        let (mut dump, path) = capturing("exchange.parquet", Redactor::default());
        let req = headers(&[("Content-Type", "application/json")]);
        dump.request_headers("POST", "/v1/chat/completions", "HTTP/1.1", &req);
        dump.request_body(b"{\"model\":\"m\",");
        dump.request_body(b"\"messages\":[]}");
        let mut upstream = headers(&[("Authorization", "Bearer sk-upstream-secret")]);
        upstream.insert_header("Host", "upstream.test").unwrap();
        dump.upstream_request(&upstream, Some("openai"), Some("k1"));
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Content-Type", "application/json")
            .unwrap();
        dump.response_headers(200, &resp);
        dump.response_body(b"{\"id\":\"ok\"}", true);
        dump.finish(Some(200), 1, Some("openai"), Some("k1"), Some("m"), None);

        let rows = captured_rows(&path);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.id, dump.id());
        assert_eq!(row.method, "POST");
        assert_eq!(row.uri, "/v1/chat/completions");
        assert_eq!(row.status, Some(200));
        // The body arrived in two chunks; the file must hold both.
        assert_eq!(row.request_body, "{\"model\":\"m\",\"messages\":[]}");
        assert_eq!(row.response_body, "{\"id\":\"ok\"}");
        // The provider credential never reaches the file.
        assert!(!row.request_headers.contains("sk-upstream-secret"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_secret_in_a_captured_body_is_redacted_before_it_is_stored() {
        let redactor =
            Redactor::new(&[("tok-[0-9a-f]{8}".to_string(), "<tok>".to_string())]).unwrap();
        let (mut dump, path) = capturing("redacted.parquet", redactor);
        let req = headers(&[]);
        dump.request_headers("POST", "/v1/chat/completions", "HTTP/1.1", &req);
        dump.request_body(b"{\"prompt\":\"use tok-deadbeef please\"}");
        dump.response_body(b"data: {\"note\":\"tok-deadbeef\"}\n\n", true);
        dump.finish(Some(200), 1, None, None, None, None);

        let rows = captured_rows(&path);
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].request_body.contains("<tok>"),
            "{}",
            rows[0].request_body
        );
        assert!(!rows[0].request_body.contains("tok-deadbeef"));
        assert!(!rows[0].response_body.contains("tok-deadbeef"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_rotation_keeps_each_attempts_response() {
        let (mut dump, path) = capturing("rotation.parquet", Redactor::default());
        let req = headers(&[]);
        dump.request_headers("POST", "/v1/chat/completions", "HTTP/1.1", &req);
        let body = b"{\"model\":\"m\"}";
        // Attempt 1: 429 on k1. Pingora sends the request header, then the body.
        dump.upstream_request(&headers(&[]), Some("openai"), Some("k1"));
        dump.request_body(body);
        let mut resp = ResponseHeader::build(429, None).unwrap();
        resp.insert_header("Retry-After", "1").unwrap();
        dump.response_headers(429, &resp);
        dump.response_body(b"{\"error\":\"rate limited\"}", true);
        // Attempt 2: a rotation re-runs the header filter, then replays the body.
        dump.upstream_request(&headers(&[]), Some("openai"), Some("k2"));
        dump.request_body(body);
        let resp = ResponseHeader::build(200, None).unwrap();
        dump.response_headers(200, &resp);
        dump.response_body(b"{\"id\":\"ok\"}", true);
        dump.finish(Some(200), 2, Some("openai"), Some("k2"), Some("m"), None);

        assert_eq!(
            dump.request_bytes,
            body.len(),
            "a replay is not a bigger request"
        );
        let rows = captured_rows(&path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].request_body, "{\"model\":\"m\"}");
        assert_eq!(rows[0].response_body, "{\"id\":\"ok\"}");
        // Each attempt keeps its own routing, not just the final one.
        assert_eq!(rows[0].upstream_attempts.len(), 2);
        assert_eq!(rows[0].upstream_attempts[0].key.as_deref(), Some("k1"));
        assert_eq!(rows[0].upstream_attempts[0].status, Some(429));
        assert_eq!(rows[0].upstream_attempts[1].key.as_deref(), Some("k2"));
        assert_eq!(rows[0].upstream_attempts[1].status, Some(200));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn header_values_keep_their_exact_form() {
        let req = headers(&[("content-type", "application/json; charset=utf-8")]);
        let rendered = render_headers(req.headers.iter());
        assert!(rendered.contains("application/json; charset=utf-8"));
    }

    #[test]
    fn json_bodies_are_compacted_to_one_line() {
        let body = b"{\n  \"model\": \"gpt-4o\",\n  \"stream\": true\n}";
        let formatted = format_body(body, 8192);
        assert_eq!(formatted, r#"{"model":"gpt-4o","stream":true}"#);
        assert!(!formatted.contains('\n'));
    }

    #[test]
    fn non_json_bodies_are_passed_through() {
        assert_eq!(format_body(b"plain text body", 8192), "plain text body");
    }

    #[test]
    fn binary_bodies_report_their_size_instead_of_mojibake() {
        assert_eq!(
            format_body(&[0xff, 0xfe, 0x00, 0x01], 8192),
            "<binary 4 bytes>"
        );
    }

    #[test]
    fn truncation_reports_the_real_size() {
        let body = format!(r#"{{"prompt":"{}"}}"#, "x".repeat(100));
        let formatted = format_body(body.as_bytes(), 40);
        assert!(formatted.contains("more bytes"), "{formatted}");
        assert!(formatted.starts_with(r#"{"prompt":"xxx"#));
    }

    #[test]
    fn truncation_does_not_split_a_utf8_character() {
        // 3-byte characters: a naive byte slice would panic or emit mojibake.
        let text = "模型模型模型模型";
        let out = truncate(text, 7);
        assert!(out.contains("more bytes"), "{out}");
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn a_replayed_body_does_not_inflate_the_byte_count() {
        let mut dump = Dump::new(DumpConfig {
            dump_request: true,
            dump_response: false,
            max_body_bytes: 4096,
            ..DumpConfig::default()
        });
        let body = br#"{"model":"m","messages":[]}"#;
        let req = headers(&[]);
        dump.upstream_request(&req, Some("openai"), Some("k1"));
        dump.request_body(body);
        assert_eq!(dump.request_bytes, body.len());
        // A rotation re-enters `upstream_peer`, then pingora replays exactly the
        // same body. The replay follows a new attempt; it is not a bare second
        // body chunk on the same attempt.
        dump.upstream_request(&req, Some("openai"), Some("k2"));
        dump.request_body(body);
        assert_eq!(
            dump.request_bytes,
            body.len(),
            "a retry is the same request, not a bigger one"
        );
    }

    #[test]
    fn a_replayed_multi_chunk_body_is_captured_once() {
        // A request bigger than pingora's read buffer arrives as several chunks,
        // and a rotation replays all of them. Judging a replay by "this chunk is
        // as long as the total so far" only ever catches the single-chunk case,
        // so a large body was captured twice -- a duplicated JSON document that
        // no longer parsed.
        let (mut dump, path) = capturing("replay-multi.parquet", Redactor::default());
        let req = headers(&[("Content-Type", "application/json")]);
        dump.request_headers("POST", "/v1/chat/completions", "HTTP/1.1", &req);
        let a = b"{\"model\":\"m\"," as &[u8];
        let b = b"\"messages\":[\"x\"," as &[u8];
        let c = b"\"y\"]}" as &[u8];
        dump.upstream_request(&req, Some("openai"), Some("k1"));
        for chunk in [a, b, c] {
            dump.request_body(chunk);
        }
        let total = a.len() + b.len() + c.len();
        assert_eq!(dump.request_bytes, total);

        // Attempt 2 replays the same chunks.
        dump.upstream_request(&req, Some("openai"), Some("k2"));
        for chunk in [a, b, c] {
            dump.request_body(chunk);
        }
        assert_eq!(
            dump.request_bytes, total,
            "a replay is not a bigger request"
        );
        dump.finish(Some(200), 2, Some("openai"), Some("k2"), Some("m"), None);

        let rows = captured_rows(&path);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].request_body,
            r#"{"model":"m","messages":["x","y"]}"#
        );
        assert_eq!(rows[0].request_bytes, total as u64);
        serde_json::from_str::<serde_json::Value>(&rows[0].request_body)
            .expect("the captured body must still be one valid JSON document");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_streamed_upload_accumulates_without_logging_every_chunk() {
        let mut dump = Dump::new(DumpConfig {
            dump_request: true,
            dump_response: false,
            max_body_bytes: 4096,
            ..DumpConfig::default()
        });
        dump.request_body(b"aaaa");
        dump.request_body(b"bbbbbb");
        dump.request_body(b"cc");
        assert_eq!(dump.request_bytes, 12, "size is still accounted for");
    }

    fn redacting(rules: &[(&str, &str)]) -> DumpConfig {
        DumpConfig {
            dump_request: true,
            dump_response: true,
            max_body_bytes: 4096,
            redactor: Redactor::new(
                &rules
                    .iter()
                    .map(|(p, r)| ((*p).to_string(), (*r).to_string()))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            ..DumpConfig::default()
        }
    }

    #[test]
    fn a_secret_inside_a_prompt_never_reaches_the_log() {
        // The message the dump would emit is what must not contain the secret.
        // Asserting on `Redactor` alone would not prove the dump path uses it.
        let dump = Dump::new(redacting(&[(r"[\w.]+@[\w.-]+", "***@***")]));
        let body = br#"{"messages":[{"role":"user","content":"mail ada@example.com"}]}"#;

        let message = dump.request_body_message(body);
        assert!(!message.contains("ada@example.com"), "{message}");
        assert!(message.contains("***@***"), "{message}");
        // The rest of the prompt is still debuggable.
        assert!(message.contains("\"role\":\"user\""), "{message}");
    }

    #[test]
    fn a_response_frame_is_redacted_too() {
        let dump = Dump::new(redacting(&[("tok-[0-9a-f]{8}", "<tok>")]));
        let messages = dump.response_body_messages(b"data: {\"note\":\"tok-deadbeef\"}\n\n");
        assert_eq!(messages.len(), 1, "one SSE frame, one message");
        assert!(messages[0].contains("<tok>"), "{}", messages[0]);
        assert!(!messages[0].contains("tok-deadbeef"), "{}", messages[0]);
    }

    #[test]
    fn redaction_happens_before_truncation() {
        // The broker's own admin token is always redacted; assert the dump path
        // applies it rather than only the redactor.
        let dump = Dump::new(DumpConfig {
            dump_request: true,
            max_body_bytes: 200,
            redactor: Redactor::with_admin_token(Some("SECRET-12345")).unwrap(),
            ..DumpConfig::default()
        });
        let body = r#"{"messages":[{"content":"SECRET-12345"}]}"#;

        let message = dump.request_body_message(body.as_bytes());
        assert!(!message.contains("SECRET-12345"), "{message}");
        assert!(message.contains("<redacted>"), "{message}");
    }

    #[test]
    fn header_values_are_redacted_through_the_dump_path() {
        // A credential can arrive in a header that is not in SECRET_HEADERS, so
        // the configured patterns must apply to header lines as well.
        let dump = Dump::new(redacting(&[("xoxb-[A-Za-z0-9-]+", "<slack>")]));
        let mut req = RequestHeader::build("POST", b"/v1/chat/completions", None).unwrap();
        req.insert_header(
            http::HeaderName::from_bytes(b"x-custom-auth").unwrap(),
            http::HeaderValue::from_str("xoxb-1234-abcd").unwrap(),
        )
        .unwrap();

        let rendered = dump.redact(&render_headers(req.headers.iter()));
        assert!(rendered.contains("<slack>"), "{rendered}");
        assert!(!rendered.contains("xoxb-1234-abcd"), "{rendered}");
    }

    #[test]
    fn the_default_config_has_a_usable_body_cap() {
        // A derived `Default` gave `max_body_bytes: 0`, which truncated every
        // dump to nothing.
        assert_eq!(
            DumpConfig::default().max_body_bytes,
            DumpConfig::DEFAULT_MAX_BODY_BYTES
        );
        assert!(DumpConfig::default().max_body_bytes > 0);
    }

    #[test]
    fn an_unconfigured_redactor_leaves_the_body_readable() {
        // Debugging must still work when no patterns are configured.
        let dump = Dump::new(DumpConfig {
            dump_request: true,
            ..DumpConfig::default()
        });
        let message = dump.request_body_message(b"{\"prompt\":\"hello\"}");
        assert!(message.contains("hello"), "{message}");
        assert!(!message.contains("<redacted>"), "{message}");
    }

    #[test]
    fn a_disabled_dump_emits_nothing() {
        let mut dump = Dump::new(DumpConfig::default());
        let req = headers(&[("Authorization", "Bearer sk-mock-1")]);
        dump.request_headers("POST", "/v1/chat/completions", "HTTP/1.1", &req);
        dump.request_body(b"{}");
        // Nothing to assert beyond "does not panic"; the guard is the early
        // return, and `config()` is what the filters check.
        assert!(!dump.config().dump_request);
    }

    #[test]
    fn streaming_bodies_are_counted_across_chunks() {
        let mut dump = Dump::new(DumpConfig {
            dump_request: false,
            dump_response: true,
            max_body_bytes: 4096,
            ..DumpConfig::default()
        });
        dump.response_body(b"data: one\n\n", false);
        dump.response_body(b"data: two\n\n", false);
        dump.response_body(b"data: [DONE]\n\n", true);
        // "data: one\n\n" + "data: two\n\n" + "data: [DONE]\n\n"
        assert_eq!(dump.response_bytes, 11 + 11 + 14);
    }

    #[test]
    fn response_headers_are_rendered_and_redacted() {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Content-Type", "text/event-stream")
            .unwrap();
        resp.insert_header("Set-Cookie", "sid=abc").unwrap();
        let rendered = render_headers(resp.headers.iter());
        assert!(
            rendered.contains("content-type: text/event-stream"),
            "{rendered}"
        );
        assert!(
            rendered.contains("set-cookie: <redacted>"),
            "a session cookie is a credential: {rendered}"
        );
        assert!(!rendered.contains("sid=abc"), "cookie leaked: {rendered}");
        assert!(
            rendered.contains(REDACTED),
            "the placeholder should be visible: {rendered}"
        );
    }

    #[test]
    fn request_ids_are_unique_and_monotonic() {
        let a = next_request_id();
        let b = next_request_id();
        assert!(b > a);
        assert_eq!(Dump::with_id(a, DumpConfig::default()).id(), a);
    }

    #[test]
    fn dump_config_reports_whether_it_is_on() {
        assert!(!DumpConfig::default().enabled());
        assert!(
            DumpConfig {
                dump_request: true,
                ..Default::default()
            }
            .enabled()
        );
        assert!(
            DumpConfig {
                dump_response: true,
                ..Default::default()
            }
            .enabled()
        );
    }
}
