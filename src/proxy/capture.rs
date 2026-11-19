//! Bounded in-memory capture of recent proxied exchanges.
//!
//! The parquet file (`-w FILE`) is the durable capture; this is the *live* one,
//! read back over MCP by an agent that is debugging its own traffic: "what did
//! the broker actually send for that request, and what came back?".
//!
//! Two rules shape it:
//!
//! 1. **Only redacted text ever lands here.** An exchange is built by
//!    [`crate::proxy::dump::Dump::finish`], which redacts credential headers by
//!    name and runs the configured body patterns before anything is buffered.
//!    This module never sees a raw secret, and must not accept one.
//! 2. **Memory is bounded on purpose.** The broker is a long-running process,
//!    so the ring holds at most `capacity` exchanges and each body is capped
//!    again here. Bodies are the biggest field by far, and an agent reading a
//!    truncated body with an explicit `request_truncated` flag is better served
//!    than by a process that grew to hold every prompt it ever proxied.

use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;

use crate::proxy::parquet::CapturedExchange;

/// Default number of recent exchanges retained for MCP readers.
pub const DEFAULT_CAPTURE_CAPACITY: usize = crate::config::DEFAULT_MCP_CAPTURE_CAPACITY;

/// Default per-body cap for the in-memory store.
///
/// Independent of the parquet capture's cap: that one exists to keep a complete
/// exchange on disk, while this one exists to keep the heap predictable.
pub const DEFAULT_STORE_BODY_BYTES: usize = crate::config::DEFAULT_MCP_CAPTURE_BYTES;

/// A fixed-capacity ring of recent, already-redacted exchanges.
///
/// Cheap to clone: every clone shares the same ring, which is what lets the
/// proxy's dump state and the MCP service see the same traffic.
///
/// The storage is a preallocated slot vector with a write cursor, not a
/// `VecDeque`: a push never reallocates or shifts, it either fills an empty slot
/// or overwrites the oldest one in place. With two readers (list and get) on
/// the same ring, O(1) per operation and a stable heap matter more than the
/// convenience of a growable container.
#[derive(Debug, Clone)]
pub struct CaptureStore {
    inner: Arc<Mutex<Inner>>,
    body_max_bytes: usize,
}

/// Upper bound on `[mcp] capture_capacity`.
///
/// The slots hold whole exchanges, so an unbounded value from a config file is
/// an unbounded allocation at startup. 1000 is far more than an agent can
/// usefully page through, and the value is clamped rather than rejected so an
/// over-eager config still starts.
pub const MAX_CAPTURE_CAPACITY: usize = 1000;

/// Upper bound on `[mcp] capture_max_bytes`.
///
/// `capture_capacity * capture_max_bytes` is the worst-case heap the ring can
/// hold (twice that, for request and response). A config value of gigabytes
/// would turn a typo into an OOM in a long-running proxy, so it is clamped to
/// the same order as the parquet capture's own 1 MiB cap.
pub const MAX_STORE_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug)]
struct Inner {
    /// Exactly `capacity` slots; `None` is an unwritten slot.
    slots: Vec<Option<CapturedExchange>>,
    /// Where the next push writes, wrapping at `capacity`.
    next: usize,
    /// Occupied slots (never more than `capacity`).
    len: usize,
    /// Exchanges that were evicted (or refused when capacity is zero). An agent
    /// asking for an id that is gone deserves to know why.
    dropped: u64,
}

impl Inner {
    /// Slot index of the `nth` most recent exchange (`0` is the newest).
    fn index_of(&self, nth: usize) -> usize {
        debug_assert!(nth < self.len);
        (self.next + self.slots.len() - 1 - nth) % self.slots.len()
    }

    fn iter_newest_first(&self) -> impl Iterator<Item = &CapturedExchange> {
        (0..self.len).filter_map(move |nth| self.slots[self.index_of(nth)].as_ref())
    }
}

impl CaptureStore {
    pub fn new(capacity: usize) -> Self {
        Self::with_body_cap(capacity, DEFAULT_STORE_BODY_BYTES)
    }

    pub fn with_body_cap(capacity: usize, body_max_bytes: usize) -> Self {
        let capacity = capacity.min(MAX_CAPTURE_CAPACITY);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                slots: std::iter::repeat_with(|| None).take(capacity).collect(),
                next: 0,
                len: 0,
                dropped: 0,
            })),
            body_max_bytes: body_max_bytes.clamp(1, MAX_STORE_BODY_BYTES),
        }
    }

    /// Record one finished exchange, overwriting the oldest slot when full.
    pub fn push(&self, mut exchange: CapturedExchange) {
        cap_body(
            &mut exchange.request_body,
            Some(&mut exchange.request_truncated),
            self.body_max_bytes,
        );
        cap_body(
            &mut exchange.response_body,
            Some(&mut exchange.response_truncated),
            self.body_max_bytes,
        );
        for attempt in &mut exchange.upstream_attempts {
            cap_body(&mut attempt.response_body, None, self.body_max_bytes);
        }

        let mut inner = self.inner.lock();
        if inner.slots.is_empty() {
            inner.dropped = inner.dropped.saturating_add(1);
            return;
        }
        if inner.slots[inner.next].is_some() {
            // The slot about to be overwritten held the oldest exchange.
            inner.dropped = inner.dropped.saturating_add(1);
        } else {
            inner.len += 1;
        }
        let index = inner.next;
        inner.slots[index] = Some(exchange);
        inner.next = (index + 1) % inner.slots.len();
    }

    /// The `limit` most recent exchanges, newest first.
    pub fn list(&self, limit: usize) -> Vec<CaptureSummary> {
        let inner = self.inner.lock();
        inner
            .iter_newest_first()
            .take(limit)
            .map(CaptureSummary::from)
            .collect()
    }

    /// One exchange by id, or `None` if it has already been overwritten.
    pub fn get(&self, id: u64) -> Option<CapturedExchange> {
        self.inner
            .lock()
            .iter_newest_first()
            .find(|exchange| exchange.id == id)
            .cloned()
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.slots.fill(None);
        inner.next = 0;
        inner.len = 0;
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The slot count actually in effect (after clamping).
    pub fn capacity(&self) -> usize {
        self.inner.lock().slots.len()
    }

    pub fn dropped(&self) -> u64 {
        self.inner.lock().dropped
    }

    /// The per-body cap actually in effect (after clamping).
    ///
    /// Reported at startup so an operator can see that a value was clamped
    /// rather than silently getting a different bound than the config said.
    pub fn body_cap(&self) -> usize {
        self.body_max_bytes
    }
}

/// Metadata for one captured exchange.
///
/// Deliberately excludes the bodies: an agent lists first and fetches the one
/// exchange it needs, so a list call does not multiply every stored prompt by
/// the page size.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureSummary {
    pub id: u64,
    pub timestamp_ms: u64,
    pub duration_ms: u64,
    pub method: String,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The *identifier* of the provider key, never its value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The authenticated client, when client authentication is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub attempts: u32,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub request_truncated: bool,
    pub response_truncated: bool,
}

impl From<&CapturedExchange> for CaptureSummary {
    fn from(exchange: &CapturedExchange) -> Self {
        Self {
            id: exchange.id,
            timestamp_ms: exchange.timestamp_ms,
            duration_ms: exchange.duration_ms,
            method: exchange.method.clone(),
            uri: exchange.uri.clone(),
            model: exchange.model.clone(),
            provider: exchange.provider.clone(),
            key_id: exchange.key.clone(),
            client: exchange.client.clone(),
            status: exchange.status,
            attempts: exchange.attempts,
            request_bytes: exchange.request_bytes,
            response_bytes: exchange.response_bytes,
            request_truncated: exchange.request_truncated,
            response_truncated: exchange.response_truncated,
        }
    }
}

/// Truncate `text` to `cap` bytes on a UTF-8 boundary, flagging the truncation.
fn cap_body(text: &mut String, truncated: Option<&mut bool>, cap: usize) {
    if text.len() <= cap {
        return;
    }
    let mut end = cap;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    if let Some(flag) = truncated {
        *flag = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::parquet::{CapturedAttempt, CapturedExchange};

    fn exchange(id: u64) -> CapturedExchange {
        CapturedExchange {
            id,
            method: "POST".into(),
            uri: "/v1/chat/completions".into(),
            request_headers: "authorization: <redacted>".into(),
            request_body: "{\"model\":\"m\"}".into(),
            response_headers: "content-type: application/json".into(),
            response_body: "{\"id\":\"ok\"}".into(),
            status: Some(200),
            ..CapturedExchange::default()
        }
    }

    #[test]
    fn the_ring_evicts_the_oldest_and_counts_it() {
        let store = CaptureStore::new(2);
        store.push(exchange(1));
        store.push(exchange(2));
        store.push(exchange(3));

        assert_eq!(store.len(), 2);
        assert_eq!(store.dropped(), 1);
        assert!(store.get(1).is_none(), "the oldest exchange is evicted");
        assert!(store.get(2).is_some());
        assert!(store.get(3).is_some());
    }

    #[test]
    fn the_write_cursor_wraps_without_reallocating() {
        // Several times around the ring: order must stay "newest first" and the
        // dropped count must account for every overwritten slot.
        let store = CaptureStore::new(3);
        for id in 1..=11 {
            store.push(exchange(id));
        }

        assert_eq!(store.len(), 3);
        assert_eq!(store.capacity(), 3);
        assert_eq!(store.dropped(), 8);
        let listed: Vec<u64> = store.list(10).iter().map(|s| s.id).collect();
        assert_eq!(listed, vec![11, 10, 9]);
        assert!(store.get(8).is_none());
        assert!(store.get(9).is_some());
    }

    #[test]
    fn list_is_newest_first_and_limited() {
        let store = CaptureStore::new(10);
        for id in 1..=5 {
            store.push(exchange(id));
        }

        let listed: Vec<u64> = store.list(3).iter().map(|s| s.id).collect();
        assert_eq!(listed, vec![5, 4, 3]);
    }

    #[test]
    fn a_summary_carries_the_key_id_but_no_body() {
        let store = CaptureStore::new(4);
        let mut item = exchange(7);
        item.key = Some("openai-1".into());
        item.model = Some("gpt-4o".into());
        item.client = Some("support".into());
        store.push(item);

        let summary = &store.list(1)[0];
        assert_eq!(summary.key_id.as_deref(), Some("openai-1"));
        // Which client sent it is useful in a multi-tenant setup and is not a
        // credential; the bodies stay out of the listing.
        assert_eq!(summary.client.as_deref(), Some("support"));
        // Serialised summaries cannot accidentally include a body field.
        let json = serde_json::to_string(summary).unwrap();
        assert!(!json.contains("request_body"), "{json}");
        assert!(!json.contains("authorization"), "{json}");
    }

    #[test]
    fn a_zero_capacity_store_keeps_nothing_and_says_so() {
        let store = CaptureStore::new(0);
        store.push(exchange(1));
        assert!(store.is_empty());
        assert_eq!(store.dropped(), 1);
    }

    #[test]
    fn capacity_is_clamped_to_the_allocation_bound() {
        let store = CaptureStore::new(usize::MAX);
        assert_eq!(store.capacity(), MAX_CAPTURE_CAPACITY);
    }

    #[test]
    fn the_body_cap_is_clamped_at_both_ends() {
        // A zero cap would make capture useless; a huge one turns a config
        // typo into unbounded heap in a long-running process.
        assert_eq!(CaptureStore::with_body_cap(1, 0).body_cap(), 1);
        assert_eq!(
            CaptureStore::with_body_cap(1, usize::MAX).body_cap(),
            MAX_STORE_BODY_BYTES
        );
        assert_eq!(
            CaptureStore::with_body_cap(1, MAX_STORE_BODY_BYTES + 1).body_cap(),
            MAX_STORE_BODY_BYTES
        );
    }

    #[test]
    fn bodies_are_capped_on_a_character_boundary() {
        let store = CaptureStore::with_body_cap(4, 8);
        let mut item = exchange(1);
        // Multi-byte characters at the cap boundary must not panic or produce
        // invalid UTF-8.
        item.request_body = "模型模型模型".into();
        item.response_body = "x".repeat(64);
        item.upstream_attempts = vec![CapturedAttempt {
            response_body: "y".repeat(64),
            ..CapturedAttempt::default()
        }];
        store.push(item);

        let stored = store.get(1).unwrap();
        assert!(stored.request_body.len() <= 8);
        assert!(
            stored
                .request_body
                .is_char_boundary(stored.request_body.len())
        );
        assert!(stored.request_truncated);
        assert_eq!(stored.response_body.len(), 8);
        assert!(stored.response_truncated);
        assert_eq!(stored.upstream_attempts[0].response_body.len(), 8);
    }

    #[test]
    fn clearing_leaves_capacity_intact() {
        let store = CaptureStore::new(3);
        store.push(exchange(1));
        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.capacity(), 3);
    }
}
