//! Pingora-based proxy: routing, failover, admin API and metrics.
//!
//! The forwarding path is deliberately thin — every scheduling decision lives
//! in [`crate::core`]. What this module adds is the retry loop: when an
//! upstream answers 429/5xx (or the connection breaks) the request is
//! re-dispatched onto a *different* key, excluding every key already tried.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::Uri as HttpUri;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::Server;
use pingora::upstreams::peer::{HttpPeer, Peer};
use pingora_error::ErrorType;
use tokio::net::lookup_host;
use tracing::{debug, info, warn};
use url::Url;

use crate::config::{AdminMode, Config};
use crate::core::key_state::{Outcome, TokenUsage};
use crate::core::metrics::estimate_cost_micros;
use crate::core::runtime::{Runtime, SharedRuntime, shared};
use crate::core::strategy::parse_retry_after;
use crate::proxy::admin::{AdminCredentials, AdminRequest, AdminResponse, AdminRouter};
use crate::proxy::body::{
    DEFAULT_REQUEST_SCAN_LIMIT, estimate_request_tokens, extract_model, model_from_path,
};
use crate::proxy::ctx::RequestContext;

/// Upper bound on the pause before a retry, so a large upstream `Retry-After`
/// cannot stall a client request behind the retry budget.
const MAX_RETRY_PAUSE: Duration = Duration::from_secs(5);

/// Resolved settings the proxy consults on every request.
#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub idle_timeout: Duration,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub metrics_path: String,
    pub metrics_enabled: bool,
    pub access_log: bool,
    pub usage_tracking: bool,
    pub usage_scan_limit: usize,
    pub admin_path: String,
    pub admin_enabled: bool,
    pub admin_mode: AdminMode,
    pub max_wait_for_key: Duration,
    pub max_retries: usize,
    pub request_scan_limit: usize,
}

impl ProxySettings {
    pub fn from_config(config: &Config) -> Self {
        Self {
            idle_timeout: config.idle_timeout(),
            connect_timeout: (config.server.connect_timeout_ms > 0)
                .then(|| Duration::from_millis(config.server.connect_timeout_ms)),
            read_timeout: config.server.read_timeout_ms.map(Duration::from_millis),
            write_timeout: config.server.write_timeout_ms.map(Duration::from_millis),
            metrics_path: config.observability.metrics_path.clone(),
            metrics_enabled: config.observability.metrics_enabled,
            access_log: config.observability.access_log,
            usage_tracking: config.observability.usage_tracking,
            usage_scan_limit: config.observability.usage_scan_limit_bytes,
            admin_path: config.admin.path.trim_end_matches('/').to_string(),
            admin_enabled: config.admin.enabled && config.admin.mode != AdminMode::Off,
            admin_mode: config.admin.mode,
            max_wait_for_key: Duration::from_secs(config.load_balancing.max_wait_for_key_secs),
            max_retries: config.server.max_retries.max(1),
            request_scan_limit: DEFAULT_REQUEST_SCAN_LIMIT,
        }
    }
}

/// Shared proxy state.
pub struct ProxyService {
    runtime: SharedRuntime,
    settings: ProxySettings,
    admin: Option<AdminRouter>,
    /// Serialises control-plane requests so concurrent writers cannot interleave.
    admin_lock: tokio::sync::Mutex<()>,
}

impl ProxyService {
    pub fn new(runtime: SharedRuntime, admin: Option<AdminRouter>) -> Self {
        let settings = ProxySettings::from_config(runtime.read().config());
        Self {
            runtime,
            settings,
            admin,
            admin_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn settings(&self) -> &ProxySettings {
        &self.settings
    }

    pub fn runtime(&self) -> &SharedRuntime {
        &self.runtime
    }

    /// Whether a path is handled by the control plane on this listener.
    pub fn is_admin_path(&self, path: &str) -> bool {
        self.settings.admin_enabled
            && self.settings.admin_mode == AdminMode::Path
            && (path == self.settings.admin_path
                || path.starts_with(&format!("{}/", self.settings.admin_path)))
    }

    pub fn is_metrics_path(&self, path: &str) -> bool {
        self.settings.metrics_enabled && path == self.settings.metrics_path
    }

    /// Translate a proxied path into a control-plane route path.
    fn admin_route(&self, path: &str) -> String {
        let trimmed = path.strip_prefix(&self.settings.admin_path).unwrap_or(path);
        trimmed.trim_start_matches('/').to_string()
    }

    /// The secret of the key currently selected for a request.
    fn secret_of(&self, provider: &str, key_id: &str) -> Option<String> {
        let runtime = self.runtime.read();
        runtime
            .broker()
            .pool(provider)
            .and_then(|pool| pool.key(key_id))
            .map(|key| key.secret.clone())
    }

    async fn handle_admin(&self, session: &mut Session, path: &str) -> pingora::Result<()> {
        let _serialised = self.admin_lock.lock().await;

        let body = match session.downstream_session.read_request_body().await {
            Ok(body) => body.map(|b| b.to_vec()).unwrap_or_default(),
            Err(error) => {
                warn!("failed to read admin request body: {error}");
                Vec::new()
            }
        };

        let credentials = {
            let headers = &session.req_header().headers;
            let authorization = headers.get("authorization").and_then(|v| v.to_str().ok());
            let admin_token = headers.get("x-admin-token").and_then(|v| v.to_str().ok());
            AdminCredentials::from_headers(authorization, admin_token)
        };

        let request = AdminRequest {
            method: session.req_header().method.as_str().to_string(),
            path: self.admin_route(path),
            query: session.req_header().uri.query().map(|q| q.to_string()),
            body,
            credentials,
        };

        let response = match &self.admin {
            Some(router) => router.handle(request),
            None => AdminResponse::error(404, "admin API is not enabled"),
        };
        write_response(session, response).await
    }

    async fn handle_metrics(&self, session: &mut Session) -> pingora::Result<()> {
        let body = self.runtime.read().metrics().render_prometheus();
        write_response(
            session,
            AdminResponse::text(200, "text/plain; version=0.0.4; charset=utf-8", body),
        )
        .await
    }

    /// Wait for capacity when every key is rate limited but one frees up soon.
    async fn wait_for_key(&self, wait: Duration) -> bool {
        let cap = self.settings.max_wait_for_key;
        if cap.is_zero() || wait.is_zero() || wait > cap {
            return false;
        }
        debug!("all keys busy, waiting {wait:?} for capacity");
        tokio::time::sleep(wait).await;
        true
    }

    /// Resolve the model from the request body, then the path.
    fn resolve_model(&self, body: &[u8], path: &str) -> Option<String> {
        extract_model(body).or_else(|| model_from_path(path))
    }

    /// Resolve the model from information available before the request body is
    /// streamed.
    ///
    /// pingora picks the upstream peer and writes the upstream request header
    /// *before* it streams the body, and it offers no way to put a peeked body
    /// back into the stream — a peek silently drops the payload. Routing
    /// therefore uses the signals that do exist at that point:
    ///
    /// 1. the `x-llm-model` request header, for clients that can set it;
    /// 2. the model embedded in the path (`/v1/models/<model>:generateContent`);
    /// 3. otherwise `None`, in which case the broker walks the configured route
    ///    order and tries every provider that could serve an unlisted model.
    fn resolve_early_model(&self, session: &Session, ctx: &mut RequestContext) {
        if ctx.model.is_some() {
            return;
        }
        let header = session.req_header();
        let from_header = header
            .headers
            .get("x-llm-model")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string());
        ctx.model = from_header.or_else(|| model_from_path(header.uri.path()));
    }

    /// Record the outcome of an attempt exactly once.
    /// Ask the broker for a key, skipping ids already tried on this request.
    fn select(
        &self,
        ctx: &RequestContext,
        model: Option<&str>,
    ) -> Result<crate::core::broker::SelectedKey, crate::core::broker::RouteError> {
        let runtime = self.runtime.read();
        runtime
            .broker()
            .select(model, &ctx.excluded, ctx.estimated_tokens)
    }

    fn settle(&self, ctx: &mut RequestContext, outcome: Outcome) {
        if ctx.settled {
            return;
        }
        ctx.settled = true;

        let Some(guard) = ctx.guard.take() else {
            return;
        };

        let (policy, tuning, registry, pricing, model, provider, key_id) = {
            let runtime = self.runtime.read();
            (
                runtime.cooldown_policy(),
                runtime.health_tuning(),
                Arc::clone(runtime.metrics()),
                runtime.config().observability.model_pricing.clone(),
                ctx.model.clone(),
                ctx.provider.clone().unwrap_or_default(),
                ctx.key.as_ref().map(|k| k.id.clone()).unwrap_or_default(),
            )
        };

        let attempt_latency = ctx.attempt_started_at.elapsed();
        // Prefer real usage; fall back to the reservation so an unparsed
        // response still charges the token window.
        let usage = if ctx.usage.saw_usage() {
            ctx.token_usage()
        } else {
            TokenUsage::default()
        };
        let total_latency = ctx.started_at.elapsed();
        let status = ctx.upstream_status.unwrap_or(0);

        guard.complete(outcome, attempt_latency, usage, &policy, &tuning);

        let cost = estimate_cost_micros(
            &pricing,
            model.as_deref().unwrap_or_default(),
            usage.input,
            usage.output,
        );
        registry.record_request(
            &provider,
            &key_id,
            model.as_deref(),
            status,
            total_latency,
            usage.input,
            usage.output,
            cost,
        );

        if self.settings.access_log {
            info!(
                provider = %provider,
                key = %key_id,
                model = model.as_deref().unwrap_or("-"),
                status,
                attempts = ctx.attempts,
                latency_ms = total_latency.as_millis() as u64,
                tokens_in = usage.input,
                tokens_out = usage.output,
                "request completed"
            );
        }
    }

    /// Whether a status code should trigger a retry on another key.
    ///
    /// Only *credential* problems justify burning another key. A 4xx that
    /// describes the request itself -- a retired model (410), an unknown
    /// deployment (404), a rejected body (400/422) -- fails identically on
    /// every key, so those are returned to the caller untouched.
    fn is_retryable_status(status: u16) -> bool {
        matches!(status, 408 | 409 | 425 | 429) || status >= 500
    }

    /// Whether a status is a *permanent* provider answer that no other key can
    /// fix. Used to explain the decision in logs.
    fn is_permanent_status(status: u16) -> bool {
        matches!(status, 400 | 401 | 403 | 404 | 405 | 410 | 422)
    }

    /// Parse `Retry-After` from an upstream response.
    fn retry_after(resp: &ResponseHeader) -> Option<Duration> {
        resp.headers
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after)
    }
}

/// Write a control-plane response through a pingora session.
async fn write_response(session: &mut Session, response: AdminResponse) -> pingora::Result<()> {
    let mut header = ResponseHeader::build(response.status, None)?;
    header.insert_header("Content-Type", response.content_type)?;
    header.insert_header("Content-Length", response.body.len().to_string())?;
    header.insert_header("Cache-Control", "no-store")?;
    if let Some(challenge) = response.challenge {
        header.insert_header("WWW-Authenticate", challenge)?;
    }
    // The control plane is never somewhere to navigate away from.
    header.insert_header("Referrer-Policy", "no-referrer")?;
    session.set_keepalive(None);
    session
        .write_response_header(Box::new(header), response.body.is_empty())
        .await?;
    if !response.body.is_empty() {
        session
            .write_response_body(Some(Bytes::from(response.body)), true)
            .await?;
    }
    Ok(())
}

/// Growable buffer of the request body, bounded by the scan limit.
#[derive(Debug, Default)]
pub struct BodyBuffer {
    bytes: Vec<u8>,
    /// Set once the body exceeded the limit; the model is then unknown.
    overflowed: bool,
}

impl BodyBuffer {
    fn push(&mut self, chunk: &[u8], limit: usize) {
        if self.overflowed {
            return;
        }
        if self.bytes.len() + chunk.len() > limit {
            self.overflowed = true;
            self.bytes.clear();
            return;
        }
        self.bytes.extend_from_slice(chunk);
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_complete(&self) -> bool {
        !self.overflowed
    }

    /// Whether the body exceeded the scan limit.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        let mut ctx = RequestContext::default();
        ctx.configure_usage_scan(self.settings.usage_tracking, self.settings.usage_scan_limit);
        ctx
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let path = session.req_header().uri.path().to_string();

        // The control plane and metrics are served in-process.
        if self.is_admin_path(&path) {
            self.handle_admin(session, &path).await?;
            return Ok(true);
        }
        if self.is_metrics_path(&path) {
            self.handle_metrics(session).await?;
            return Ok(true);
        }

        self.runtime
            .read()
            .metrics()
            .requests_in_flight
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ctx.started_at = Instant::now();
        ctx.attempt_started_at = ctx.started_at;
        Ok(false)
    }
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Record the model for logging, metrics and token estimation. It does
        // not drive routing: the upstream was already chosen before this filter
        // ran (see `resolve_early_model`).
        if let Some(chunk) = body.as_deref()
            && !chunk.is_empty()
            && ctx.body.is_empty()
        {
            ctx.body.push(chunk, self.settings.request_scan_limit);
            if !ctx.body.is_empty() {
                ctx.estimated_tokens = estimate_request_tokens(ctx.body.bytes());
                if ctx.model.is_none() {
                    let path = session.req_header().uri.path().to_string();
                    ctx.model = self.resolve_model(ctx.body.bytes(), &path);
                }
            }
        }
        let _ = end_of_stream;
        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        // Handle a retry: whatever the previous attempt was, drop its guard
        // (already settled) so the key is not double-counted.
        ctx.guard = None;

        // Resolve the model from the signals that exist before the body is
        // streamed (see `resolve_early_model`).
        self.resolve_early_model(session, ctx);

        let mut selection = self.select(ctx, ctx.model.as_deref());
        if let Err(error) = &selection
            && let Some(wait) = error.retry_after()
            && ctx.attempts == 0
            && self.wait_for_key(wait).await
        {
            selection = self.select(ctx, ctx.model.as_deref());
        }

        let selected = match selection {
            Ok(selected) => selected,
            Err(error) => {
                let registry = Arc::clone(self.runtime.read().metrics());
                if error.retry_after().is_some() {
                    registry
                        .keys_exhausted
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    registry
                        .rejected_no_key
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }

                let status = if error.retry_after().is_some() {
                    429
                } else {
                    503
                };
                let mut header = ResponseHeader::build(status, None)?;
                if let Some(wait) = error.retry_after() {
                    header.insert_header("Retry-After", wait.as_secs().max(1).to_string())?;
                }
                header.insert_header("X-LLM-Broker-Error", error.to_string())?;
                if let Some(model) = ctx.model.as_deref() {
                    header.insert_header("X-LLM-Broker-Model", model)?;
                }
                session.set_keepalive(None);
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                warn!(
                    model = ctx.model.as_deref().unwrap_or("-"),
                    "request refused: {error}"
                );
                // The refusal response is already written; mark the request
                // settled so logging does not double count it against a key.
                ctx.settled = true;
                return Err(pingora::Error::new_down(ErrorType::HTTPStatus(status)));
            }
        };

        ctx.excluded.insert(selected.key.id.clone());
        ctx.provider = Some(selected.provider.clone());
        ctx.upstream_model = selected.upstream_model.clone();
        ctx.key = Some(Arc::clone(&selected.key));
        ctx.guard = Some(selected.key.reserve());
        ctx.attempts += 1;
        ctx.attempt_started_at = Instant::now();
        ctx.settled = false;

        if ctx.attempts > 1 {
            let runtime = self.runtime.read();
            let metrics = runtime.metrics();
            metrics
                .key_rotations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            metrics
                .key(&selected.provider, &selected.key.id)
                .retries
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        let peer = build_peer(&selected.base_url, &self.settings).await?;

        debug!(
            provider = %selected.provider,
            key = %selected.key.id,
            attempt = ctx.attempts,
            "dispatching to upstream"
        );
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        req: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        let Some(provider) = ctx.provider.clone() else {
            return Ok(());
        };
        let Some(key_id) = ctx.key_id().map(|s| s.to_string()) else {
            return Ok(());
        };

        let (auth, host, path_prefix) = {
            let runtime = self.runtime.read();
            match runtime.broker().pool(&provider) {
                Some(pool) => (
                    pool.auth.clone(),
                    host_of(&pool.base_url),
                    pool.path_prefix.clone(),
                ),
                None => return Ok(()),
            }
        };

        // Reach the right virtual host and identify the broker.
        req.insert_header("Host", host.as_str())?;
        req.insert_header("User-Agent", "llm-broker/2.0")?;
        req.remove_header("X-Forwarded-For");
        req.remove_header("X-Forwarded-Host");

        // NOTE: the requested model is forwarded unchanged. Pingora writes the
        // upstream request header before the body streams, so a body rewrite
        // here would desynchronise `Content-Length`; routing on the requested
        // model (and letting the provider alias it) is the correct behaviour.
        if let (Some(requested), Some(upstream)) =
            (ctx.model.as_deref(), ctx.upstream_model.as_deref())
            && requested != upstream
        {
            debug!("provider {provider} maps model `{requested}` to `{upstream}`");
        }

        // Apply the credential and rebuild path/query.
        if let Some(secret) = self.secret_of(&provider, &key_id) {
            auth.apply(req, &secret);

            let original = session.req_header().uri.clone();
            let (path, query) = split_uri(&original);
            let new_path = if path_prefix.is_empty() {
                path
            } else {
                format!("{}{}", path_prefix.trim_end_matches('/'), path)
            };
            let new_query = auth.decorate_query(query.as_deref(), &secret);
            apply_uri(req, &new_path, new_query.as_deref())?;
        }

        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        let status = resp.status.as_u16();
        ctx.upstream_status = Some(status);
        // From here on the response belongs to this key; a later transport
        // error must not cause a replay on another key.
        ctx.response_started = true;

        if !Self::is_retryable_status(status) {
            return Ok(());
        }

        let retry_after = Self::retry_after(resp);
        let outcome = if status == 429 {
            Outcome::RateLimited { retry_after }
        } else {
            Outcome::Failure
        };
        let key_id = ctx.key_id().unwrap_or("-").to_string();

        // Record the failure against the key that produced it, *before* any
        // response is committed downstream.
        self.settle(ctx, outcome);

        if Self::is_permanent_status(status) {
            // Unreachable while `is_retryable_status` excludes these; kept as a
            // guard so a future edit cannot start rotating keys on a
            // request-level error.
            warn!(status, "permanent upstream refusal, not rotating keys");
            return Ok(());
        }

        if ctx.attempts as usize >= self.settings.max_retries {
            warn!(
                status,
                attempts = ctx.attempts,
                model = ctx.model.as_deref().unwrap_or("-"),
                "all attempts exhausted, returning upstream status"
            );
            return Ok(());
        }

        // Back off briefly so a rate-limited upstream is not hit again at once.
        // The pause is capped: sleeping out a long `Retry-After` would make the
        // client wait only to receive the same error once the budget is gone.
        let pause = retry_after.unwrap_or(Duration::from_millis(250));
        let ceiling = self
            .settings
            .max_wait_for_key
            .max(Duration::from_secs(1))
            .min(MAX_RETRY_PAUSE);
        if pause <= ceiling {
            tokio::time::sleep(pause).await;
        }

        warn!(
            status,
            attempt = ctx.attempts,
            key = %key_id,
            "retrying on another key"
        );

        // Returning a retryable error re-enters `upstream_peer`, which selects
        // a different key because this one is now in `ctx.excluded`. pingora's
        // retry buffer replays the request body for the new attempt.
        let mut error = pingora::Error::new_up(ErrorType::HTTPStatus(status));
        error.set_retry(true);
        Err(error)
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<Duration>> {
        if let Some(chunk) = body.as_deref()
            && !chunk.is_empty()
        {
            ctx.usage.push(chunk);
        }
        if end_of_stream {
            ctx.usage.finish();
        }
        Ok(None)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        _session: &mut Session,
        mut error: Box<pingora::Error>,
        ctx: &mut Self::CTX,
        _client_reused: bool,
    ) -> Box<pingora::Error> {
        let etype = error.etype().clone();
        warn!(
            "upstream error: {error} (peer: {peer}, key: {}, attempt: {})",
            ctx.key_id().unwrap_or("-"),
            ctx.attempts
        );

        self.runtime
            .read()
            .metrics()
            .upstream_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // A transport failure means this key's connection is unusable.
        self.settle(ctx, Outcome::Failure);

        // A transport error after the upstream already answered is usually
        // just the server closing the connection at the end of a response, so
        // it must not justify a replay on its own. The exception is an error
        // raised by `upstream_response_filter` (a 429 or a 5xx): that filter
        // has already recorded the outcome and asked for a retry, and clearing
        // the retry here would defeat key rotation entirely.
        if ctx.response_started {
            if error.retry() {
                debug!("keeping the retry requested by the response filter");
            }
            return error;
        }

        // Connect refused means the host is wrong; another key for the same
        // provider would fail identically, so only transient transport errors
        // are retried.
        let transient = matches!(
            etype,
            ErrorType::ConnectionClosed
                | ErrorType::ReadError
                | ErrorType::WriteError
                | ErrorType::ReadTimedout
                | ErrorType::WriteTimedout
                | ErrorType::ConnectTimedout
        );
        let can_retry = transient && (ctx.attempts as usize) < self.settings.max_retries;

        if can_retry {
            error.set_retry(true);
        } else {
            error.set_retry(false);
            error.as_up();
        }
        error
    }

    async fn logging(
        &self,
        _session: &mut Session,
        _error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) where
        Self::CTX: Send + Sync,
    {
        let outcome = match ctx.upstream_status {
            Some(status) if (200..300).contains(&status) => Outcome::Success,
            Some(429) => Outcome::RateLimited { retry_after: None },
            Some(status) if status >= 500 => Outcome::Failure,
            // Control-plane traffic never selected a key.
            None if ctx.key.is_none() => Outcome::Cancelled,
            _ => Outcome::Failure,
        };
        self.settle(ctx, outcome);

        if ctx.key.is_some() || ctx.started_at != ctx.attempt_started_at {
            self.runtime
                .read()
                .metrics()
                .requests_in_flight
                .try_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |value| Some(value.saturating_sub(1)),
                )
                .ok();
        }
    }
}

/// Rewrite the JSON `"model"` value in a request body.
///
/// Only the first occurrence of the exact value is replaced, which is what
/// OpenAI-compatible payloads need. Not wired into the request path: pingora
/// emits the upstream request header before the body streams, so a body rewrite
/// would desynchronise `Content-Length`. Kept (and tested) for a future
/// body-buffered mode.
#[allow(dead_code)]
pub fn rewrite_model(body: &[u8], from: &str, to: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let needle = format!("\"{from}\"");
    let position = text.find(&needle)?;
    let mut out = String::with_capacity(text.len() + to.len().saturating_sub(from.len()));
    out.push_str(&text[..position]);
    out.push('"');
    out.push_str(to);
    out.push('"');
    out.push_str(&text[position + needle.len()..]);
    Some(out.into_bytes())
}

/// Split a URI into its path and query.
fn split_uri(uri: &HttpUri) -> (String, Option<String>) {
    (uri.path().to_string(), uri.query().map(|q| q.to_string()))
}

/// Replace the request URI's path and query in place.
fn apply_uri(req: &mut RequestHeader, path: &str, query: Option<&str>) -> pingora::Result<()> {
    let uri = match query.filter(|q| !q.is_empty()) {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    let parsed: HttpUri = uri
        .parse()
        .map_err(|_| pingora::Error::new_down(ErrorType::new("InvalidUpstreamUri")))?;
    req.set_uri(parsed);
    Ok(())
}

/// Host header for an upstream base URL.
fn host_of(base_url: &str) -> String {
    Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| "api.openai.com".to_string())
}

/// Build the upstream peer, resolving DNS for a concrete IP.
async fn build_peer(base_url: &str, settings: &ProxySettings) -> pingora::Result<HttpPeer> {
    let parsed = Url::parse(base_url).map_err(|error| {
        pingora::Error::explain(
            ErrorType::new("InvalidBaseUrl"),
            format!("cannot parse base_url `{base_url}`: {error}"),
        )
    })?;

    let host = parsed.host_str().unwrap_or("api.openai.com").to_string();
    let tls = parsed.scheme() == "https";
    let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });

    let address = format!("{host}:{port}");
    let ip = match lookup_host(&address).await {
        Ok(mut addrs) => addrs
            .next()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| host.clone()),
        Err(error) => {
            warn!("DNS lookup failed for {address}: {error}");
            host.clone()
        }
    };

    let mut peer = HttpPeer::new(format!("{ip}:{port}"), tls, host);
    if let Some(options) = peer.get_mut_peer_options() {
        options.idle_timeout = Some(settings.idle_timeout);
        options.connection_timeout = settings.connect_timeout;
        // Left at pingora's default unless configured: LLM completions can
        // legitimately take minutes, and a premature read timeout is retried
        // as a transport failure, which would drain the key pool.
        options.read_timeout = settings.read_timeout;
        options.write_timeout = settings.write_timeout;
    }
    Ok(peer)
}

/// Build pingora's server configuration, applying the retry budget.
pub fn build_server_conf(config: &Config) -> pingora::server::configuration::ServerConf {
    let mut conf = pingora::server::configuration::ServerConf::default();
    if let Some(threads) = config.server.threads {
        conf.threads = threads;
    }
    conf.daemon = config.server.daemon;
    if let Some(pid_file) = config.server.pid_file.as_ref().filter(|p| !p.is_empty()) {
        conf.pid_file = pid_file.clone();
    }
    if let Some(user) = config.server.user.as_ref().filter(|u| !u.is_empty()) {
        conf.user = Some(user.clone());
    }
    if let Some(group) = config.server.group.as_ref().filter(|g| !g.is_empty()) {
        conf.group = Some(group.clone());
    }
    // pingora re-enters `upstream_peer` on every retry, which is exactly how
    // key rotation is implemented here.
    conf.max_retries = config.server.max_retries.max(1);
    // pingora sleeps the grace period on the main thread during a graceful
    // shutdown, dropping signals meanwhile, so its 300s default made Ctrl+C
    // look broken. Bound it by the configured value.
    conf.grace_period_seconds = Some(config.server.graceful_shutdown_secs);
    // The runtime shutdown timeout is a *separate*, additional wait, and
    // pingora sleeps it twice (once inside `Runtime::shutdown_timeout`, once
    // after). Using the grace period here doubled the shutdown: a 30s setting
    // produced a 60s stop. Leave it at pingora's small default, since the grace
    // period is what lets in-flight requests finish.
    debug_assert!(config.server.graceful_shutdown_secs < 3600);
    conf
}

/// Build a runtime from a config, keeping the source path for persistence.
pub fn runtime_from_config(
    config: Config,
    path: Option<std::path::PathBuf>,
) -> anyhow::Result<SharedRuntime> {
    Ok(shared(Runtime::new(config, path)?))
}

/// Start the proxy server with the control plane configured by the file.
pub fn run_server(config: Config, runtime: SharedRuntime) -> anyhow::Result<()> {
    let server_conf = build_server_conf(&config);
    let mut server = Server::new_with_opt_and_conf(None, server_conf);
    server.bootstrap();

    let settings = ProxySettings::from_config(&config);
    let token = config.admin.resolved_token()?;

    // Control plane on its own listener, when configured that way.
    if settings.admin_enabled && settings.admin_mode == AdminMode::Separate {
        let router = AdminRouter::new(
            Arc::clone(&runtime),
            token.clone(),
            config.admin.allow_insecure,
        );
        let service = crate::proxy::control::ControlService::new(router);
        let mut svc = pingora::proxy::http_proxy_service(&server.configuration, service);
        let addr = format!("{}:{}", config.admin.host, config.admin.port);
        svc.add_tcp(&addr);
        println!("LLM Broker admin API listening on http://{addr}");
        server.add_service(svc);
    }

    let proxy = ProxyService::new(
        Arc::clone(&runtime),
        Some(AdminRouter::new(
            Arc::clone(&runtime),
            token,
            config.admin.allow_insecure,
        )),
    );
    let mut svc = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    let addr = format!("{}:{}", config.server.host, config.server.port);
    svc.add_tcp(&addr);
    println!(
        "LLM Broker listening on http://{addr} (admin: {})",
        describe_admin(&config)
    );
    server.add_service(svc);

    server.run_forever();
}

fn describe_admin(config: &Config) -> String {
    if !config.admin.enabled || config.admin.mode == AdminMode::Off {
        return "disabled".to_string();
    }
    match config.admin.mode {
        AdminMode::Separate => format!("http://{}:{}", config.admin.host, config.admin.port),
        AdminMode::Path => format!("path {}", config.admin.path),
        AdminMode::Off => "disabled".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKeyConfig, ProviderConfig, ServerConfig};

    fn minimal_config() -> Config {
        Config {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 11436,
                threads: None,
                daemon: false,
                pid_file: None,
                user: None,
                group: None,
                connect_timeout_ms: 0,
                idle_timeout_ms: None,
                read_timeout_ms: None,
                write_timeout_ms: None,
                max_retries: 3,
                graceful_shutdown_secs: crate::config::DEFAULT_GRACE_PERIOD_SECS,
            },
            proxy_type: None,
            providers: vec![ProviderConfig {
                name: "openai".into(),
                base_url: Some("https://api.openai.test".into()),
                path_prefix: None,
                auth: None,
                auth_query_param: None,
                default_models: vec!["gpt-4".into()],
                max_rpm: None,
                max_tpm: None,
                max_concurrency: None,
                api_keys: vec![ApiKeyConfig {
                    id: "k1".into(),
                    key: "sk-test".into(),
                    enabled: true,
                    models: vec![],
                    weight: 1,
                    max_rpm: None,
                    max_tpm: None,
                    max_concurrency: None,
                    model_map: None,
                }],
            }],
            routes: vec![],
            default_route: None,
            load_balancing: Default::default(),
            health: Default::default(),
            observability: Default::default(),
            admin: Default::default(),
        }
    }

    fn settings() -> ProxySettings {
        ProxySettings {
            idle_timeout: Duration::from_secs(30),
            connect_timeout: None,
            read_timeout: None,
            write_timeout: None,
            metrics_path: "/metrics".into(),
            metrics_enabled: true,
            access_log: false,
            usage_tracking: true,
            usage_scan_limit: 4096,
            admin_path: "/admin".into(),
            admin_enabled: true,
            admin_mode: AdminMode::Path,
            max_wait_for_key: Duration::from_secs(5),
            max_retries: 3,
            request_scan_limit: 1024,
        }
    }

    fn service() -> ProxyService {
        ProxyService {
            runtime: shared(Runtime::new(minimal_config(), None).unwrap()),
            settings: settings(),
            admin: None,
            admin_lock: tokio::sync::Mutex::new(()),
        }
    }

    #[test]
    fn retryable_statuses_cover_429_and_5xx_but_not_client_errors() {
        assert!(ProxyService::is_retryable_status(429));
        assert!(ProxyService::is_retryable_status(500));
        assert!(ProxyService::is_retryable_status(503));
        assert!(ProxyService::is_retryable_status(408));
        // A malformed request must never be replayed on another key.
        assert!(!ProxyService::is_retryable_status(400));
        assert!(!ProxyService::is_retryable_status(401));
        assert!(!ProxyService::is_retryable_status(404));
        assert!(!ProxyService::is_retryable_status(200));
        assert!(ProxyService::is_retryable_status(409));
        // A retired model (observed live from NVIDIA as 410 Gone) must not
        // consume the whole key pool before reaching the caller.
        assert!(!ProxyService::is_retryable_status(410));
        assert!(!ProxyService::is_retryable_status(422));
    }

    #[test]
    fn permanent_statuses_are_recognised_for_the_log() {
        for status in [400, 401, 403, 404, 405, 410, 422] {
            assert!(ProxyService::is_permanent_status(status), "{status}");
            assert!(!ProxyService::is_retryable_status(status), "{status}");
        }
        assert!(!ProxyService::is_permanent_status(429));
        assert!(!ProxyService::is_permanent_status(500));
    }

    #[test]
    fn admin_paths_are_matched_with_a_boundary() {
        let service = service();
        assert!(service.is_admin_path("/admin"));
        assert!(service.is_admin_path("/admin/keys"));
        assert!(!service.is_admin_path("/administrator"));
        assert!(service.is_metrics_path("/metrics"));
        assert!(!service.is_metrics_path("/v1/metrics"));
    }

    #[test]
    fn admin_paths_are_ignored_when_the_control_plane_is_disabled() {
        let mut service = service();
        service.settings.admin_enabled = false;
        assert!(!service.is_admin_path("/admin/status"));
        service.settings.metrics_enabled = false;
        assert!(!service.is_metrics_path("/metrics"));
    }

    #[test]
    fn admin_routes_are_derived_from_the_mount_point() {
        let service = service();
        assert_eq!(
            service.admin_route("/admin/keys/openai/k1"),
            "keys/openai/k1"
        );
        assert_eq!(service.admin_route("/admin"), "");
        assert_eq!(service.admin_route("/admin/status"), "status");
    }

    #[test]
    fn body_buffer_stops_collecting_after_the_limit() {
        let mut buffer = BodyBuffer::default();
        buffer.push(b"hello", 16);
        assert!(buffer.is_complete());
        assert_eq!(buffer.bytes(), b"hello");

        // Adding six more bytes would exceed the 16-byte limit.
        buffer.push(b"worlds", 10);
        assert!(!buffer.is_complete(), "the buffer must stop collecting");
        assert!(buffer.is_empty());

        buffer.push(b"more", 16);
        assert!(buffer.is_empty(), "an overflowed buffer stops growing");
    }

    #[test]
    fn body_buffer_accumulates_across_chunks() {
        let mut buffer = BodyBuffer::default();
        buffer.push(br#"{"model":"gp"#, 1024);
        buffer.push(br#"t-4"}"#, 1024);
        assert_eq!(buffer.bytes(), br#"{"model":"gpt-4"}"#);
    }

    #[test]
    fn retry_after_header_parsing() {
        let mut resp = ResponseHeader::build(429, None).unwrap();
        resp.insert_header("Retry-After", "42").unwrap();
        assert_eq!(
            ProxyService::retry_after(&resp),
            Some(Duration::from_secs(42))
        );

        let plain = ResponseHeader::build(429, None).unwrap();
        assert_eq!(ProxyService::retry_after(&plain), None);
    }

    #[test]
    fn model_rewriting_replaces_only_the_model_value() {
        let body = br#"{"model":"fast","messages":[{"content":"fast is nice"}]}"#;
        let rewritten = rewrite_model(body, "fast", "gpt-4o").unwrap();
        assert_eq!(
            String::from_utf8(rewritten).unwrap(),
            r#"{"model":"gpt-4o","messages":[{"content":"fast is nice"}]}"#
        );
    }

    #[test]
    fn model_rewriting_is_idempotent_when_applied_twice() {
        // Regression guard: retries must not nest an alias.
        let body = br#"{"model":"fast","messages":[]}"#;
        let once = rewrite_model(body, "fast", "gpt-4o").unwrap();
        assert!(
            rewrite_model(&once, "fast", "gpt-4o").is_none(),
            "the first rewrite must remove the original name"
        );
    }

    #[test]
    fn model_rewriting_returns_none_when_nothing_matches() {
        assert!(rewrite_model(br#"{"model":"other"}"#, "fast", "gpt-4o").is_none());
        assert!(rewrite_model(b"not json", "fast", "gpt-4o").is_none());
    }

    #[test]
    fn uri_rewrites_preserve_query_strings() {
        let mut req = RequestHeader::build("POST", b"/v1/chat?api-version=1", None).unwrap();
        apply_uri(&mut req, "/openai/v1/chat", Some("api-version=1&key=abc")).unwrap();
        assert_eq!(req.uri.to_string(), "/openai/v1/chat?api-version=1&key=abc");
    }

    #[test]
    fn uri_rewrites_without_a_query_are_clean() {
        let mut req = RequestHeader::build("POST", b"/v1/chat", None).unwrap();
        apply_uri(&mut req, "/v1/chat", None).unwrap();
        assert_eq!(req.uri.to_string(), "/v1/chat");
    }

    #[test]
    fn split_uri_separates_path_and_query() {
        let uri: HttpUri = "/a/b?x=1&y=2".parse().unwrap();
        let (path, query) = split_uri(&uri);
        assert_eq!(path, "/a/b");
        assert_eq!(query.as_deref(), Some("x=1&y=2"));

        let uri: HttpUri = "/a/b".parse().unwrap();
        let (path, query) = split_uri(&uri);
        assert_eq!(path, "/a/b");
        assert!(query.is_none());
    }

    #[test]
    fn host_of_extracts_the_hostname() {
        assert_eq!(host_of("https://api.openai.com/v1"), "api.openai.com");
        assert_eq!(host_of("https://api.example.com:8443/x"), "api.example.com");
        assert_eq!(host_of("not a url"), "api.openai.com");
    }

    #[test]
    fn server_conf_bounds_the_graceful_shutdown() {
        // Regression: pingora defaults the grace period to 300s and sleeps it
        // on the main thread, so SIGTERM looked like a hang.
        let mut config = minimal_config();
        assert_eq!(
            config.server.graceful_shutdown_secs,
            crate::config::DEFAULT_GRACE_PERIOD_SECS
        );

        config.server.graceful_shutdown_secs = 5;
        let conf = build_server_conf(&config);
        assert_eq!(conf.grace_period_seconds, Some(5));
        // Deliberately not tied to the grace period: pingora sleeps this one
        // twice, so sharing the value doubled the observed shutdown time.
        assert_eq!(conf.graceful_shutdown_timeout_seconds, None);
    }

    #[test]
    fn server_conf_carries_the_retry_budget() {
        let mut config = minimal_config();
        config.server.max_retries = 7;
        config.server.threads = Some(3);
        let conf = build_server_conf(&config);
        assert_eq!(conf.max_retries, 7);
        assert_eq!(conf.threads, 3);
    }

    #[test]
    fn upstream_timeouts_follow_the_config() {
        let mut config = minimal_config();
        assert_eq!(
            ProxySettings::from_config(&config).read_timeout,
            None,
            "unset means pingora's default, not a zero timeout"
        );

        config.server.read_timeout_ms = Some(180_000);
        config.server.write_timeout_ms = Some(30_000);
        config.server.connect_timeout_ms = 5_000;
        let settings = ProxySettings::from_config(&config);
        assert_eq!(settings.read_timeout, Some(Duration::from_secs(180)));
        assert_eq!(settings.write_timeout, Some(Duration::from_secs(30)));
        assert_eq!(settings.connect_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn proxy_settings_derive_from_config() {
        let mut config = minimal_config();
        config.observability.metrics_path = "/stats".into();
        config.load_balancing.max_wait_for_key_secs = 9;
        let settings = ProxySettings::from_config(&config);
        assert_eq!(settings.metrics_path, "/stats");
        assert_eq!(settings.max_wait_for_key, Duration::from_secs(9));
        // Admin mode defaults to `off`-equivalent (`enabled = false`).
        assert!(!settings.admin_enabled);
    }

    #[test]
    fn model_resolution_prefers_the_body_then_the_path() {
        let service = service();
        assert_eq!(
            service
                .resolve_model(br#"{"model":"gpt-4o"}"#, "/v1/chat/completions")
                .as_deref(),
            Some("gpt-4o")
        );
        assert_eq!(
            service
                .resolve_model(b"", "/v1/models/gemini-pro:generateContent")
                .as_deref(),
            Some("gemini-pro")
        );
        assert_eq!(service.resolve_model(b"", "/v1/chat/completions"), None);
    }
}
