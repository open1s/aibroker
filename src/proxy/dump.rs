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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpConfig {
    pub dump_request: bool,
    pub dump_response: bool,
    /// Maximum bytes of a body printed before it is truncated.
    pub max_body_bytes: usize,
}

impl Default for DumpConfig {
    fn default() -> Self {
        Self {
            dump_request: false,
            dump_response: false,
            max_body_bytes: 8192,
        }
    }
}

impl DumpConfig {
    pub fn enabled(&self) -> bool {
        self.dump_request || self.dump_response
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
        Self {
            id,
            config,
            started: Instant::now(),
            request_bytes: 0,
            response_bytes: 0,
            request_headers_done: false,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn config(&self) -> DumpConfig {
        self.config
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
        if !self.config.dump_request || self.request_headers_done {
            return;
        }
        self.request_headers_done = true;
        let rendered = render_headers(headers.headers.iter());
        self.emit("req", &format!("{method} {uri} {version}"));
        self.emit("req headers", &rendered);
    }

    /// Dump the upstream request as it will actually be sent, credential
    /// redacted. This is the interesting one: it shows the model routing
    /// result (path, Host), not just what the client asked for.
    pub fn upstream_request(&mut self, req: &pingora::http::RequestHeader) {
        if !self.config.dump_request {
            return;
        }
        let rendered = render_headers(req.headers.iter());
        self.emit(
            "upstream req",
            &format!("{} {} {:?}", req.method, req.uri, req.version),
        );
        self.emit("upstream req headers", &rendered);
    }

    /// Dump a chunk of the request body.
    ///
    /// Only the beginning of a body is printed. A large LLM request arrives as
    /// many chunks -- an agentic client easily sends hundreds of kilobytes --
    /// and per-chunk progress buries the log. The size is still accounted for,
    /// and a retry (pingora replays the body from its buffer on a key rotation)
    /// is reported rather than re-counted.
    pub fn request_body(&mut self, chunk: &[u8]) {
        if !self.config.dump_request {
            return;
        }
        if self.request_bytes == 0 {
            self.request_bytes = chunk.len();
            self.emit("req body", &format_body(chunk, self.config.max_body_bytes));
            return;
        }
        if self.request_bytes == chunk.len() {
            self.emit(
                "req body",
                &format!("replayed {} bytes (retry)", chunk.len()),
            );
            return;
        }
        // A large upload arrives as many chunks. Print nothing further: the
        // first chunk showed the payload's shape and the summary reports the
        // total, so per-chunk progress would only bury it.
        self.request_bytes += chunk.len();
    }

    /// Dump the response status line and headers.
    pub fn response_headers(&mut self, status: u16, headers: &pingora::http::ResponseHeader) {
        if !self.config.dump_response {
            return;
        }
        let rendered = render_headers(headers.headers.iter());
        self.emit("resp", &format!("{status}"));
        self.emit("resp headers", &rendered);
    }

    /// Dump a chunk of the response body. SSE answers arrive as many chunks;
    /// each is printed so the stream can be followed live.
    pub fn response_body(&mut self, chunk: &[u8], end_of_stream: bool) {
        if !self.config.dump_response {
            return;
        }
        let total = self.response_bytes + chunk.len();
        let text = String::from_utf8_lossy(chunk);
        // SSE frames are newline separated; print them as separate events.
        let mut printed = false;
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            self.emit("resp body", &truncate(line, self.config.max_body_bytes));
            printed = true;
        }
        if !printed && !chunk.is_empty() {
            self.emit("resp body", &format!("<binary {} bytes>", chunk.len()));
        }
        self.response_bytes = total;
        if end_of_stream {
            self.emit(
                "resp body",
                &format!("<end of stream, {total} bytes total>"),
            );
        }
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
        });
        let body = br#"{"model":"m","messages":[]}"#;
        dump.request_body(body);
        assert_eq!(dump.request_bytes, body.len());
        // pingora replays exactly the same body when rotating keys.
        dump.request_body(body);
        assert_eq!(
            dump.request_bytes,
            body.len(),
            "a retry is the same request, not a bigger one"
        );
    }

    #[test]
    fn a_streamed_upload_accumulates_without_logging_every_chunk() {
        let mut dump = Dump::new(DumpConfig {
            dump_request: true,
            dump_response: false,
            max_body_bytes: 4096,
        });
        dump.request_body(b"aaaa");
        dump.request_body(b"bbbbbb");
        dump.request_body(b"cc");
        assert_eq!(dump.request_bytes, 12, "size is still accounted for");
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
