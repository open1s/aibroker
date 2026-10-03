//! Per-request state shared across the proxy filters.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::core::key_state::{KeyGuard, KeyState, TokenUsage};
use crate::proxy::body::UsageAccumulator;
use crate::proxy::pingora_backend::BodyBuffer;

/// Everything the filters need to remember about one request.
pub struct RequestContext {
    /// Model requested by the client, used for routing.
    pub model: Option<String>,
    /// Model name to forward upstream (alias/rewrite applied).
    pub upstream_model: Option<String>,
    /// Buffered request body, used to find the model and to rewrite it.
    pub body: BodyBuffer,
    /// Provider that owns the selected key.
    pub provider: Option<String>,
    /// Key currently serving the request.
    pub key: Option<Arc<KeyState>>,
    /// Keeps the key's in-flight counter honest if the request is cancelled.
    pub guard: Option<KeyGuard>,
    /// Ids already tried, so a retry never reuses a failed key.
    pub excluded: HashSet<String>,
    /// Number of upstream attempts made.
    pub attempts: u32,
    /// When the request entered the proxy.
    pub started_at: Instant,
    /// When the current attempt was dispatched.
    pub attempt_started_at: Instant,
    /// Estimated tokens for the request, charged against TPM.
    pub estimated_tokens: u64,
    /// Set once the request body has been inspected for the model, so the
    /// peek in `upstream_peer` happens at most once per request.
    pub body_inspected: bool,
    /// Upstream status of the attempt that produced the final response.
    pub upstream_status: Option<u16>,
    /// Whether the upstream response has been sent downstream already.
    pub response_started: bool,
    /// Token usage extracted from the response body.
    pub usage: UsageAccumulator,
    /// Set once the outcome has been recorded, so it is recorded exactly once.
    pub settled: bool,
    /// Set when the client closed the connection early.
    pub client_gone: bool,
}

impl std::fmt::Debug for RequestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestContext")
            .field("model", &self.model)
            .field("provider", &self.provider)
            .field("key", &self.key.as_ref().map(|k| k.id.clone()))
            .field("attempts", &self.attempts)
            .field("estimated_tokens", &self.estimated_tokens)
            .field("upstream_status", &self.upstream_status)
            .finish()
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            model: None,
            upstream_model: None,
            body: BodyBuffer::default(),
            provider: None,
            key: None,
            guard: None,
            excluded: HashSet::new(),
            attempts: 0,
            started_at: now,
            attempt_started_at: now,
            estimated_tokens: 0,
            body_inspected: false,
            upstream_status: None,
            response_started: false,
            usage: UsageAccumulator::new(true, 64 * 1024),
            settled: false,
            client_gone: false,
        }
    }
}

impl RequestContext {
    /// Id of the key currently selected, if any.
    pub fn key_id(&self) -> Option<&str> {
        self.key.as_ref().map(|k| k.id.as_str())
    }

    /// Provider of the current attempt.
    pub fn provider_name(&self) -> Option<&str> {
        self.provider.as_deref()
    }

    /// Usage observed so far.
    pub fn token_usage(&self) -> TokenUsage {
        self.usage.usage()
    }

    /// Configure how much of the response body is scanned for usage.
    pub fn configure_usage_scan(&mut self, enabled: bool, limit: usize) {
        self.usage = UsageAccumulator::new(enabled, limit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_is_empty() {
        let ctx = RequestContext::default();
        assert!(ctx.model.is_none());
        assert!(ctx.key.is_none());
        assert_eq!(ctx.attempts, 0);
        assert!(ctx.token_usage().is_empty());
        assert!(!ctx.settled);
        assert!(!ctx.body_inspected);
    }

    #[test]
    fn token_usage_reflects_the_accumulator() {
        let mut ctx = RequestContext::default();
        ctx.usage
            .push(br#"{"usage":{"prompt_tokens":3,"completion_tokens":4}}"#);
        assert_eq!(ctx.token_usage().input, 3);
        assert_eq!(ctx.token_usage().output, 4);
    }

    #[test]
    fn usage_scan_can_be_disabled_per_request() {
        let mut ctx = RequestContext::default();
        ctx.configure_usage_scan(false, 4096);
        assert!(!ctx.usage.push(br#"{"usage":{"prompt_tokens":9}}"#));
        assert!(ctx.token_usage().is_empty());
    }
}
