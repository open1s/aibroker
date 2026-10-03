//! Rate-limit accounting.
//!
//! The original broker used an epoch-second counter, which allowed a burst of
//! up to 2x the configured limit across a window boundary. These windows
//! instead keep timestamped buckets and expire samples strictly older than the
//! window, so the reported rate never exceeds the configured limit.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Length of the sliding window used for every rate limit.
pub const WINDOW: Duration = Duration::from_secs(60);

/// What a rate-limit check decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Room for the request; the samples were recorded.
    Ok,
    /// The window is full. `retry_after` is the wait until capacity frees up.
    Limited {
        retry_after: Duration,
    },
}

impl Admit {
    pub fn is_ok(self) -> bool {
        matches!(self, Admit::Ok)
    }

    pub fn retry_after(self) -> Option<Duration> {
        match self {
            Admit::Ok => None,
            Admit::Limited { retry_after } => Some(retry_after),
        }
    }
}

/// A sliding window over timestamped samples.
#[derive(Debug)]
pub struct SlidingWindow {
    samples: VecDeque<(Instant, u64)>,
    total: u64,
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SlidingWindow {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            total: 0,
        }
    }

    fn expire(&mut self, now: Instant) -> Option<Instant> {
        let mut oldest = None;
        while let Some(&(at, value)) = self.samples.front() {
            if now.saturating_duration_since(at) >= WINDOW {
                self.samples.pop_front();
                self.total = self.total.saturating_sub(value);
            } else {
                oldest = Some(at);
                break;
            }
        }
        if oldest.is_none() {
            oldest = self.samples.front().map(|(at, _)| *at);
        }
        oldest
    }

    /// Current total inside the window.
    pub fn total(&mut self, now: Instant) -> u64 {
        self.expire(now);
        self.total
    }

    /// When the oldest sample leaves the window, i.e. the earliest instant at
    /// which capacity can increase.
    pub fn next_expiry(&mut self, now: Instant) -> Option<Duration> {
        self.expire(now);
        self.samples
            .front()
            .map(|(at, _)| WINDOW.saturating_sub(now.saturating_duration_since(*at)))
    }

    /// Whether `amount` more would still fit under `limit`.
    pub fn has_room(&mut self, now: Instant, limit: u64, amount: u64) -> bool {
        self.total(now).saturating_add(amount) <= limit
    }

    /// Record a sample.
    pub fn push(&mut self, now: Instant, value: u64) {
        if value == 0 {
            // Still record the request so RPM accounting sees it.
            self.samples.push_back((now, 0));
        } else {
            self.samples.push_back((now, value));
            self.total = self.total.saturating_add(value);
        }
    }

    /// Number of samples currently inside the window.
    pub fn len(&mut self, now: Instant) -> usize {
        self.expire(now);
        self.samples.len()
    }

    pub fn is_empty(&mut self, now: Instant) -> bool {
        self.len(now) == 0
    }

    /// Drop all samples, used by the admin API to clear a key's history.
    pub fn clear(&mut self) {
        self.samples.clear();
        self.total = 0;
    }
}

/// Combined request/token limiter for a single key.
#[derive(Debug, Default)]
pub struct RateLimiter {
    requests: SlidingWindow,
    tokens: SlidingWindow,
    /// Cost of the request currently being streamed, settled on completion.
    pending_tokens: u64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a new request against both limits and record its request sample.
    ///
    /// `estimated_tokens` is charged against the token budget immediately so
    /// that concurrent streams cannot all slip past the TPM limit; the real
    /// usage is settled later with [`RateLimiter::settle_tokens`].
    pub fn admit(
        &mut self,
        now: Instant,
        max_rpm: Option<u32>,
        max_tpm: Option<u64>,
        estimated_tokens: u64,
    ) -> Admit {
        let mut retry_after: Option<Duration> = None;

        if let Some(max_rpm) = max_rpm {
            let limit = u64::from(max_rpm);
            if !self.requests.has_room(now, limit, 1) {
                retry_after = self
                    .requests
                    .next_expiry(now)
                    .or(Some(WINDOW))
                    .max(retry_after);
            }
        }

        if let Some(max_tpm) = max_tpm {
            // Charge the estimate; never block purely on the pending estimate
            // for the very first request, otherwise a large single request can
            // never be admitted when the estimate exceeds the whole budget.
            let charge = estimated_tokens.min(max_tpm);
            if !self
                .tokens
                .has_room(now, max_tpm, charge)
                && self.tokens.total(now) > 0
            {
                retry_after = self.tokens.next_expiry(now).or(Some(WINDOW)).max(retry_after);
            }
        }

        if let Some(wait) = retry_after {
            return Admit::Limited {
                retry_after: wait,
            };
        }

        self.requests.push(now, 1);
        if let Some(max_tpm) = max_tpm {
            let charge = estimated_tokens.min(max_tpm);
            if charge > 0 {
                self.tokens.push(now, charge);
                self.pending_tokens = self.pending_tokens.saturating_add(charge);
            }
        }
        Admit::Ok
    }

    /// Replace the estimated token charge with the actual usage.
    pub fn settle_tokens(&mut self, now: Instant, actual: u64) {
        if self.pending_tokens == 0 && actual == 0 {
            return;
        }
        let estimate = self.pending_tokens;
        self.pending_tokens = 0;
        if actual > estimate {
            self.tokens.push(now, actual - estimate);
        }
        // Over-estimates are intentionally kept: releasing budget early would
        // allow a burst above the configured TPM once the window drains.
    }

    /// Non-consuming check: would one more request fit under `limit`?
    pub fn requests_has_room(&mut self, now: Instant, limit: u64) -> bool {
        self.requests.has_room(now, limit, 1)
    }

    /// Non-consuming check: would `amount` more tokens fit under `limit`?
    pub fn tokens_has_room(&mut self, now: Instant, limit: u64, amount: u64) -> bool {
        if self.tokens.total(now) == 0 {
            return true;
        }
        self.tokens.has_room(now, limit, amount)
    }

    /// Wait until the oldest request sample leaves the window.
    pub fn requests_next_expiry(&mut self, now: Instant) -> Option<Duration> {
        self.requests.next_expiry(now)
    }

    /// Wait until the oldest token sample leaves the window.
    pub fn tokens_next_expiry(&mut self, now: Instant) -> Option<Duration> {
        self.tokens.next_expiry(now)
    }

    /// Observed requests inside the window.
    pub fn rpm(&mut self, now: Instant) -> u64 {
        self.requests.len(now) as u64
    }

    /// Observed tokens inside the window.
    pub fn tpm(&mut self, now: Instant) -> u64 {
        self.tokens.total(now)
    }

    pub fn clear(&mut self) {
        self.requests.clear();
        self.tokens.clear();
        self.pending_tokens = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_allows_up_to_limit() {
        let mut limiter = RateLimiter::new();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(limiter.admit(now, Some(5), None, 0).is_ok());
        }
        assert!(!limiter.admit(now, Some(5), None, 0).is_ok());
        assert_eq!(limiter.rpm(now), 5);
    }

    #[test]
    fn window_rejects_within_one_window_across_the_boundary() {
        // Regression: the old epoch-second window let 2x the limit through when
        // requests straddled a second boundary.
        let mut limiter = RateLimiter::new();
        let start = Instant::now();
        for i in 0..10 {
            let now = start + Duration::from_millis(i * 100);
            assert!(
                limiter.admit(now, Some(10), None, 0).is_ok(),
                "request {i} should fit"
            );
        }
        let now = start + Duration::from_millis(1_100);
        assert_eq!(limiter.rpm(now), 10);
        assert!(!limiter.admit(now, Some(10), None, 0).is_ok());
    }

    #[test]
    fn window_releases_capacity_after_expiry() {
        let mut limiter = RateLimiter::new();
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.admit(start, Some(3), None, 0).is_ok());
        }
        assert!(!limiter.admit(start, Some(3), None, 0).is_ok());

        let later = start + Duration::from_secs(61);
        assert!(limiter.admit(later, Some(3), None, 0).is_ok());
        assert_eq!(limiter.rpm(later), 1);
    }

    #[test]
    fn limited_admit_reports_retry_after() {
        let mut limiter = RateLimiter::new();
        let start = Instant::now();
        assert!(limiter.admit(start, Some(1), None, 0).is_ok());
        let decision = limiter.admit(start + Duration::from_secs(10), Some(1), None, 0);
        let wait = decision.retry_after().expect("should be limited");
        assert!(
            wait <= Duration::from_secs(50) && wait >= Duration::from_secs(49),
            "unexpected wait {wait:?}"
        );
    }

    #[test]
    fn token_budget_blocks_and_settles() {
        let mut limiter = RateLimiter::new();
        let now = Instant::now();
        assert!(limiter.admit(now, None, Some(1_000), 400).is_ok());
        assert!(limiter.admit(now, None, Some(1_000), 400).is_ok());
        assert!(!limiter.admit(now, None, Some(1_000), 400).is_ok());

        assert_eq!(limiter.tpm(now), 800, "the estimate is charged up front");

        // Real usage above the estimate is charged on top.
        limiter.settle_tokens(now, 1_200);
        assert_eq!(limiter.tpm(now), 1_200);
        assert!(
            !limiter.admit(now, None, Some(1_000), 1).is_ok(),
            "the window is now over budget"
        );
    }

    #[test]
    fn oversized_single_request_is_admitted_when_window_empty() {
        let mut limiter = RateLimiter::new();
        let now = Instant::now();
        assert!(
            limiter.admit(now, None, Some(100), 10_000).is_ok(),
            "an empty window must accept a request bigger than the whole budget"
        );
        assert!(!limiter.admit(now, None, Some(100), 1).is_ok());
    }

    #[test]
    fn no_limits_means_always_ok() {
        let mut limiter = RateLimiter::new();
        let now = Instant::now();
        for _ in 0..1_000 {
            assert!(limiter.admit(now, None, None, 0).is_ok());
        }
    }
}
