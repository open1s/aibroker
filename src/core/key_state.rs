//! Per-key runtime state: health, cooldown, concurrency and rate limits.
//!
//! This is the heart of key management. Every key owns its own circuit breaker
//! and exact rate-limit accounting, and all of it is interior-mutable so the
//! scheduler only ever needs `&KeyState`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::config::ApiKeyConfig;
use crate::core::ratelimit::{Admit, RateLimiter};
use crate::error::Result;

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Key is serving traffic normally.
    Closed,
    /// Key has been tripped; requests are steered elsewhere.
    Open,
    /// Cooldown elapsed; a limited number of probe requests are allowed.
    HalfOpen,
}

impl HealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthState::Closed => "closed",
            HealthState::Open => "open",
            HealthState::HalfOpen => "half_open",
        }
    }
}

/// Rolling health statistics for a key, exposed by `/metrics`.
#[derive(Debug, Clone, Copy)]
pub struct HealthSnapshot {
    pub state: HealthState,
    pub score: f64,
    pub latency_ms: Option<f64>,
    pub success: u64,
    pub failure: u64,
    pub consecutive_failures: u32,
}

/// Why a key rejected a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    Disabled,
    Cooldown,
    CircuitOpen,
    RateLimited,
    Concurrency,
}

impl UnavailableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            UnavailableReason::Disabled => "disabled",
            UnavailableReason::Cooldown => "cooldown",
            UnavailableReason::CircuitOpen => "circuit_open",
            UnavailableReason::RateLimited => "rate_limited",
            UnavailableReason::Concurrency => "concurrency",
        }
    }
}

impl std::fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Exponential-backoff cooldown bookkeeping.
#[derive(Debug, Clone, Copy, Default)]
struct Cooldown {
    until: Option<Instant>,
    /// Number of times this key has been tripped since its last success.
    level: u32,
}

/// A single credential with all of its runtime state.
pub struct KeyState {
    pub id: String,
    pub provider: String,
    /// Secret exactly as configured (possibly `env:NAME` before resolution).
    pub secret: String,
    /// Model allow-list; empty means "all models of this provider".
    pub models: Vec<String>,
    /// Configurable selection weight.
    pub weight: u32,
    /// Per-key model alias map, `client model` -> `upstream model`.
    pub model_map: std::collections::HashMap<String, String>,

    enabled: AtomicBool,
    max_rpm: Option<u32>,
    max_tpm: Option<u64>,
    max_concurrency: Option<u32>,

    limiter: Mutex<RateLimiter>,
    cooldown: RwLock<Cooldown>,
    health: RwLock<HealthStats>,

    in_flight: AtomicU32,
    selections: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    rate_limit_hits: AtomicU64,
    tokens_in: AtomicU64,
    tokens_out: AtomicU64,
    latency_us: AtomicU64,
    /// End of the window the counters above belong to (unix millis).
    window_ends_at_ms: AtomicI64,
    window_rpm_peak: AtomicU64,
    window_tpm_peak: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct HealthStats {
    score: f64,
    latency_ms: Option<f64>,
    consecutive_failures: u32,
    half_open_probe_in_flight: bool,
    half_open_successes: u32,
}

impl Default for HealthStats {
    fn default() -> Self {
        Self {
            score: 1.0,
            latency_ms: None,
            consecutive_failures: 0,
            half_open_probe_in_flight: false,
            half_open_successes: 0,
        }
    }
}

/// Tunables copied out of the config so key state does not depend on it.
#[derive(Debug, Clone, Copy)]
pub struct HealthTuning {
    pub enabled: bool,
    pub latency_alpha: f64,
    pub slow_latency_ms: u64,
    pub unhealthy_threshold: f64,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
}

impl Default for HealthTuning {
    fn default() -> Self {
        Self {
            enabled: true,
            latency_alpha: 0.2,
            slow_latency_ms: 5_000,
            unhealthy_threshold: 0.3,
            failure_threshold: 3,
            recovery_threshold: 2,
        }
    }
}

/// Cooldown ramp, copied from `load_balancing`.
#[derive(Debug, Clone, Copy)]
pub struct CooldownPolicy {
    pub initial: Duration,
    pub max: Duration,
    pub multiplier: f64,
    pub jitter: f64,
}

impl Default for CooldownPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(60),
            max: Duration::from_secs(1500),
            multiplier: 5.0,
            jitter: 0.2,
        }
    }
}

/// Build the cooldown policy from a config.
impl CooldownPolicy {
    pub fn from_config(cfg: &crate::config::LoadBalancingConfig) -> Self {
        Self {
            initial: Duration::from_secs(cfg.initial_cooldown_secs.max(1)),
            max: Duration::from_secs(cfg.max_cooldown_secs.max(1)),
            multiplier: cfg.cooldown_multiplier.max(1.0),
            jitter: cfg.cooldown_jitter.clamp(0.0, 1.0),
        }
    }
}

impl std::fmt::Debug for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyState")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("enabled", &self.is_enabled())
            .field("in_flight", &self.in_flight())
            .field("health", &self.health_state())
            .finish_non_exhaustive()
    }
}

impl KeyState {
    /// Build a key from its config entry. `env:NAME` secrets are resolved.
    pub fn from_config(provider: &str, cfg: &ApiKeyConfig) -> Result<Arc<Self>> {
        let secret = crate::config::resolve_secret(&cfg.key)?;
        Ok(Arc::new(Self::new(provider, cfg, secret)))
    }

    fn new(provider: &str, cfg: &ApiKeyConfig, secret: String) -> Self {
        Self {
            id: cfg.id.clone(),
            provider: provider.to_string(),
            secret,
            models: cfg.models.clone(),
            weight: cfg.weight.max(1),
            model_map: cfg.model_map.clone().unwrap_or_default(),
            enabled: AtomicBool::new(cfg.enabled),
            max_rpm: cfg.max_rpm,
            max_tpm: cfg.max_tpm,
            max_concurrency: cfg.max_concurrency,
            limiter: Mutex::new(RateLimiter::new()),
            cooldown: RwLock::new(Cooldown::default()),
            health: RwLock::new(HealthStats::default()),
            in_flight: AtomicU32::new(0),
            selections: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            rate_limit_hits: AtomicU64::new(0),
            tokens_in: AtomicU64::new(0),
            tokens_out: AtomicU64::new(0),
            latency_us: AtomicU64::new(0),
            window_ends_at_ms: AtomicI64::new(0),
            window_rpm_peak: AtomicU64::new(0),
            window_tpm_peak: AtomicU64::new(0),
        }
    }

    // -- simple accessors -------------------------------------------------

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn selections(&self) -> u64 {
        self.selections.load(Ordering::Relaxed)
    }

    pub fn successes(&self) -> u64 {
        self.successes.load(Ordering::Relaxed)
    }

    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    pub fn rate_limit_hits(&self) -> u64 {
        self.rate_limit_hits.load(Ordering::Relaxed)
    }

    pub fn tokens_in(&self) -> u64 {
        self.tokens_in.load(Ordering::Relaxed)
    }

    pub fn tokens_out(&self) -> u64 {
        self.tokens_out.load(Ordering::Relaxed)
    }

    pub fn max_rpm(&self) -> Option<u32> {
        self.max_rpm
    }

    pub fn max_tpm(&self) -> Option<u64> {
        self.max_tpm
    }

    pub fn max_concurrency(&self) -> Option<u32> {
        self.max_concurrency
    }

    pub fn supports_model(&self, model: &str) -> bool {
        self.models.is_empty() || self.models.iter().any(|m| m == model)
    }

    /// Map a client-facing model name to the upstream name for this key.
    pub fn upstream_model(&self, model: &str) -> String {
        self.model_map
            .get(model)
            .cloned()
            .unwrap_or_else(|| model.to_string())
    }

    /// Current EWMA latency in milliseconds.
    pub fn latency_ms(&self) -> Option<f64> {
        let us = self.latency_us.load(Ordering::Relaxed);
        (us > 0).then(|| us as f64 / 1000.0)
    }

    /// Current health score in `0.0..=1.0`.
    pub fn health_score(&self) -> f64 {
        self.health.read().score
    }

    /// Circuit breaker state, accounting for an elapsed cooldown.
    pub fn health_state(&self) -> HealthState {
        let now = Instant::now();
        let cooldown = *self.cooldown.read();
        match cooldown.until {
            Some(until) if until > now => HealthState::Open,
            _ => {
                if self.health.read().consecutive_failures > 0 {
                    HealthState::HalfOpen
                } else {
                    HealthState::Closed
                }
            }
        }
    }

    pub fn health_snapshot(&self) -> HealthSnapshot {
        let health = *self.health.read();
        HealthSnapshot {
            state: self.health_state(),
            score: health.score,
            latency_ms: self.latency_ms(),
            success: self.successes(),
            failure: self.failures(),
            consecutive_failures: health.consecutive_failures,
        }
    }

    /// Remaining cooldown, if the key is currently parked.
    pub fn cooldown_remaining(&self) -> Option<Duration> {
        let now = Instant::now();
        self.cooldown
            .read()
            .until
            .map(|until| until.saturating_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    /// Observed requests/tokens inside the current window.
    pub fn observed_rates(&self) -> (u64, u64) {
        let now = Instant::now();
        let mut limiter = self.limiter.lock();
        (limiter.rpm(now), limiter.tpm(now))
    }

    /// Peak observed requests/tokens over completed windows.
    pub fn peak_rates(&self) -> (u64, u64) {
        (
            self.window_rpm_peak.load(Ordering::Relaxed),
            self.window_tpm_peak.load(Ordering::Relaxed),
        )
    }

    // -- rate limits ------------------------------------------------------

    /// Whether this key could take a request right now, without recording it.
    pub fn is_available(&self) -> bool {
        self.availability(0).is_ok()
    }

    /// Whether this key could take a request of `estimated_tokens`.
    pub fn is_available_for(&self, estimated_tokens: u64) -> bool {
        self.availability(estimated_tokens).is_ok()
    }

    /// Availability check with a reason, used for diagnostics and metrics.
    pub fn availability(
        &self,
        estimated_tokens: u64,
    ) -> std::result::Result<(), UnavailableReason> {
        if !self.is_enabled() {
            return Err(UnavailableReason::Disabled);
        }

        let now = Instant::now();
        let cooldown = *self.cooldown.read();
        if let Some(until) = cooldown.until
            && until > now
        {
            return Err(UnavailableReason::Cooldown);
        }

        if let Some(max) = self.max_concurrency
            && self.in_flight() >= max
        {
            return Err(UnavailableReason::Concurrency);
        }

        // The circuit is open when health collapsed or recent failures are
        // stacking up; half-open probes are allowed through.
        let health = *self.health.read();
        if health.score < 0.3 && health.consecutive_failures >= 2 {
            return Err(UnavailableReason::CircuitOpen);
        }

        let mut limiter = self.limiter.lock();
        match limiter.admit(now, self.max_rpm, self.max_tpm, estimated_tokens) {
            Admit::Ok => Ok(()),
            Admit::Limited { .. } => Err(UnavailableReason::RateLimited),
        }
    }

    /// Like [`KeyState::availability`] but does not consume rate-limit budget.
    /// Used by metrics and by the "would this ever work" fast path.
    pub fn probe_availability(
        &self,
        estimated_tokens: u64,
    ) -> std::result::Result<(), UnavailableReason> {
        if !self.is_enabled() {
            return Err(UnavailableReason::Disabled);
        }
        if self.cooldown_remaining().is_some() {
            return Err(UnavailableReason::Cooldown);
        }
        if let Some(max) = self.max_concurrency
            && self.in_flight() >= max
        {
            return Err(UnavailableReason::Concurrency);
        }
        let now = Instant::now();
        let mut limiter = self.limiter.lock();
        if let Some(max_rpm) = self.max_rpm
            && !limiter.requests_has_room(now, u64::from(max_rpm))
        {
            return Err(UnavailableReason::RateLimited);
        }
        if let Some(max_tpm) = self.max_tpm
            && !limiter.tokens_has_room(now, max_tpm, estimated_tokens)
        {
            return Err(UnavailableReason::RateLimited);
        }
        Ok(())
    }

    /// When this key would next become available, if it is currently blocked
    /// only by time-based limits.
    pub fn available_at(&self) -> Option<Instant> {
        if !self.is_enabled() {
            return None;
        }
        let now = Instant::now();
        let mut at: Option<Instant> = None;
        if let Some(until) = self.cooldown.read().until
            && until > now
        {
            at = Some(until);
        }
        let mut limiter = self.limiter.lock();
        if let Some(max_rpm) = self.max_rpm
            && !limiter.requests_has_room(now, u64::from(max_rpm))
            && let Some(wait) = limiter.requests_next_expiry(now)
        {
            let candidate = now + wait;
            at = Some(at.map_or(candidate, |cur| cur.max(candidate)));
        }
        if let Some(max_tpm) = self.max_tpm
            && !limiter.tokens_has_room(now, max_tpm, 0)
            && let Some(wait) = limiter.tokens_next_expiry(now)
        {
            let candidate = now + wait;
            at = Some(at.map_or(candidate, |cur| cur.max(candidate)));
        }
        at
    }

    /// Charge the actual token usage once a request has been accounted.
    pub fn settle_tokens(&self, tokens: u64) {
        if tokens == 0 {
            return;
        }
        self.limiter.lock().settle_tokens(Instant::now(), tokens);
    }

    // -- lifecycle --------------------------------------------------------

    /// Reserve the key for one request: bumps in-flight and selection count.
    ///
    /// Returns a guard that releases the reservation when dropped, which keeps
    /// the in-flight counter correct even when the request is cancelled.
    pub fn reserve(self: &Arc<Self>) -> KeyGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.selections.fetch_add(1, Ordering::Relaxed);
        KeyGuard {
            key: Arc::clone(self),
            settled: false,
        }
    }

    /// Release one in-flight slot without recording an outcome.
    pub fn release(&self) {
        // Saturating: a double release must never wrap the counter.
        let _ = self
            .in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Record a successful request and close the circuit when recovered.
    pub fn record_success(
        &self,
        latency: Duration,
        tokens_in: u64,
        tokens_out: u64,
        tuning: &HealthTuning,
    ) {
        self.successes.fetch_add(1, Ordering::Relaxed);
        if tokens_in > 0 {
            self.tokens_in.fetch_add(tokens_in, Ordering::Relaxed);
        }
        if tokens_out > 0 {
            self.tokens_out.fetch_add(tokens_out, Ordering::Relaxed);
        }

        let millis = latency.as_secs_f64() * 1000.0;
        let micros = (millis * 1000.0).min(u64::MAX as f64) as u64;

        // EWMA latency so a single slow response does not dominate.
        let previous = self.latency_us.load(Ordering::Relaxed);
        let alpha = tuning.latency_alpha.clamp(0.0, 1.0);
        let next = if previous == 0 {
            micros
        } else {
            let blended = previous as f64 * (1.0 - alpha) + micros as f64 * alpha;
            blended.min(u64::MAX as f64) as u64
        };
        self.latency_us.store(next, Ordering::Relaxed);

        let latency_factor = if next == 0 {
            1.0
        } else {
            let slow = tuning.slow_latency_ms.max(1) as f64;
            let observed = next as f64 / 1000.0;
            (1.0 - (observed / slow)).clamp(0.0, 1.0)
        };
        self.window_roll_over();

        let mut health = self.health.write();
        // Successes lift the score quickly; latency drags it down smoothly.
        // The target is the latency factor itself, so a fast key recovers to
        // a perfect score within a few requests.
        let target = latency_factor.min(1.0);
        health.score = (health.score + (target - health.score) * 0.3).clamp(0.0, 1.0);
        health.consecutive_failures = 0;
        health.half_open_probe_in_flight = false;
        health.half_open_successes = health.half_open_successes.saturating_add(1);
        let _ = tuning.recovery_threshold; // recovery is driven by failure reset
    }

    /// Record a failure and escalate the cooldown.
    pub fn record_failure(&self, policy: &CooldownPolicy, tuning: &HealthTuning) {
        self.failures.fetch_add(1, Ordering::Relaxed);

        let mut health = self.health.write();
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.half_open_probe_in_flight = false;
        health.half_open_successes = 0;
        if tuning.enabled {
            // Each consecutive failure removes a fifth of the remaining score.
            health.score = (health.score * 0.8).clamp(0.0, 1.0);
        }
        let consecutive = health.consecutive_failures;
        let score = health.score;
        drop(health);

        let should_cool = !tuning.enabled
            || score < tuning.unhealthy_threshold
            || consecutive >= tuning.failure_threshold;

        if should_cool {
            self.escalate_cooldown(policy);
        }
    }

    /// Trip the key for `policy.initial * multiplier^level`, capped and jittered.
    pub fn escalate_cooldown(&self, policy: &CooldownPolicy) {
        let mut cooldown = self.cooldown.write();
        let level = cooldown.level;
        let base = policy
            .initial
            .as_secs_f64()
            .max(1.0)
            .mul_add(policy.multiplier.powi(level as i32), 0.0);
        let capped = base.min(policy.max.as_secs_f64());
        let jitter = if policy.jitter > 0.0 {
            1.0 + (rand_unit() * 2.0 - 1.0) * policy.jitter
        } else {
            1.0
        };
        let seconds = (capped * jitter).max(1.0);
        cooldown.until = Some(Instant::now() + Duration::from_secs_f64(seconds));
        cooldown.level = cooldown.level.saturating_add(1);
    }

    /// Park the key for an explicit duration, e.g. from `Retry-After`.
    pub fn cooldown_for(&self, duration: Duration) {
        let mut cooldown = self.cooldown.write();
        cooldown.until = Some(Instant::now() + duration);
        cooldown.level = cooldown.level.saturating_add(1);
    }

    /// Record that the upstream answered 429.
    pub fn record_rate_limited(&self, retry_after: Option<Duration>, policy: &CooldownPolicy) {
        self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
        // A 429 is proof the key is exhausted, so ramp the cooldown from at
        // least one initial step even if the key looked healthy.
        match retry_after {
            Some(duration) if !duration.is_zero() => self.cooldown_for(duration),
            _ => self.escalate_cooldown(policy),
        }
    }

    /// Clear cooldown, failure streak and rate-limit history.
    pub fn reset(&self) {
        {
            let mut cooldown = self.cooldown.write();
            cooldown.until = None;
            cooldown.level = 0;
        }
        {
            let mut health = self.health.write();
            *health = HealthStats::default();
        }
        self.limiter.lock().clear();
    }

    /// Apply a new `enabled` flag, returning the previous value.
    pub fn toggle_enabled(&self, enabled: bool) -> bool {
        self.enabled.swap(enabled, Ordering::Relaxed)
    }

    /// Capture live state so it can survive a broker rebuild.
    pub fn snapshot(&self) -> KeySnapshot {
        let cooldown = *self.cooldown.read();
        let health = *self.health.read();
        KeySnapshot {
            cooldown_until: cooldown.until,
            cooldown_level: cooldown.level,
            score: health.score,
            latency_ms: self.latency_ms(),
            consecutive_failures: health.consecutive_failures,
            half_open_successes: health.half_open_successes,
        }
    }

    /// Apply a snapshot to a freshly constructed key.
    ///
    /// Only *live* state is transferred: cooldown, health score, observed
    /// latency and the failure streak. Cumulative counters and rate-limit
    /// windows are deliberately left alone — their samples are anchored to
    /// `Instant`s that cannot be replayed, and restoring counters would undo an
    /// operator's `reset` (or any other admin action) by writing the
    /// pre-rebuild values back over it.
    pub fn restore(&self, snapshot: &KeySnapshot) {
        // `enabled` is deliberately *not* restored: it is owned by the
        // configuration, so disabling a key through the admin API sticks even
        // though the rebuild snapshots and restores runtime state.
        {
            let mut cooldown = self.cooldown.write();
            // Only carry a cooldown that has not already elapsed.
            cooldown.until = snapshot
                .cooldown_until
                .filter(|until| *until > Instant::now());
            cooldown.level = snapshot.cooldown_level;
        }
        {
            let mut health = self.health.write();
            health.score = snapshot.score.clamp(0.0, 1.0);
            health.latency_ms = snapshot.latency_ms;
            health.consecutive_failures = snapshot.consecutive_failures;
            health.half_open_successes = snapshot.half_open_successes;
            health.half_open_probe_in_flight = false;
        }
        if let Some(latency) = snapshot.latency_ms {
            let micros = (latency * 1000.0).max(0.0).min(u64::MAX as f64) as u64;
            self.latency_us.store(micros, Ordering::Relaxed);
        }
    }

    fn window_roll_over(&self) {
        let now_ms = unix_millis();
        let ends = self.window_ends_at_ms.load(Ordering::Relaxed);
        if now_ms < ends {
            return;
        }
        // Publish the finished window's peaks.
        let (rpm, tpm) = self.observed_rates();
        bump_peak(&self.window_rpm_peak, rpm);
        bump_peak(&self.window_tpm_peak, tpm);
        self.window_ends_at_ms.store(
            now_ms + crate::core::ratelimit::WINDOW.as_millis() as i64,
            Ordering::Relaxed,
        );
    }
}

fn bump_peak(slot: &AtomicU64, value: u64) {
    let mut current = slot.load(Ordering::Relaxed);
    while value > current {
        match slot.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Cheap pseudo-random in `0.0..1.0`, avoiding a dependency on `rand`.
pub fn rand_unit() -> f64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0) };
    }
    STATE.with(|state| {
        let mut seed = state.get();
        if seed == 0 {
            seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E37_79B9_7F4A_7C15)
                | 1;
        }
        // xorshift64*
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        state.set(seed);
        let value = seed.wrapping_mul(0x2545_F491_4F6C_DD1D);
        (value >> 11) as f64 / (1u64 << 53) as f64
    })
}

/// Live state of a key, captured so it survives a broker rebuild.
#[derive(Debug, Clone)]
pub struct KeySnapshot {
    pub cooldown_until: Option<Instant>,
    pub cooldown_level: u32,
    pub score: f64,
    pub latency_ms: Option<f64>,
    pub consecutive_failures: u32,
    pub half_open_successes: u32,
}

/// RAII guard holding one in-flight slot on a key.
pub struct KeyGuard {
    key: Arc<KeyState>,
    settled: bool,
}

impl KeyGuard {
    pub fn key(&self) -> &Arc<KeyState> {
        &self.key
    }

    /// Report the outcome and release the slot exactly once.
    pub fn complete(
        mut self,
        outcome: Outcome,
        latency: Duration,
        tokens: TokenUsage,
        policy: &CooldownPolicy,
        tuning: &HealthTuning,
    ) {
        self.settled = true;
        self.key.settle_tokens(tokens.total());
        match outcome {
            Outcome::Success => {
                self.key
                    .record_success(latency, tokens.input, tokens.output, tuning)
            }
            Outcome::Failure => self.key.record_failure(policy, tuning),
            Outcome::RateLimited { retry_after } => {
                self.key.record_rate_limited(retry_after, policy)
            }
            Outcome::Cancelled => {}
        }
        self.key.release();
    }
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        if !self.settled {
            self.key.release();
        }
    }
}

/// Result of a proxied request, recorded against the key that served it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    RateLimited { retry_after: Option<Duration> },
    Cancelled,
}

/// Token accounting for a single request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    pub input: u64,
    pub output: u64,
}

impl TokenUsage {
    pub fn total(&self) -> u64 {
        self.input.saturating_add(self.output)
    }

    pub fn is_empty(&self) -> bool {
        self.input == 0 && self.output == 0
    }
}

/// Convenience for tests and admin code: a key with sane defaults.
#[allow(dead_code)]
pub(crate) fn test_key(id: &str, provider: &str, models: &[&str]) -> Arc<KeyState> {
    let cfg = ApiKeyConfig {
        id: id.to_string(),
        key: format!("sk-{id}"),
        enabled: true,
        models: models.iter().map(|m| m.to_string()).collect(),
        weight: 1,
        max_rpm: None,
        max_tpm: None,
        max_concurrency: None,
        model_map: None,
    };
    KeyState::from_config(provider, &cfg).expect("test key should build")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering as O;

    fn key_with(max_rpm: Option<u32>, max_tpm: Option<u64>) -> Arc<KeyState> {
        let cfg = ApiKeyConfig {
            id: "k1".into(),
            key: "sk-test".into(),
            enabled: true,
            models: vec![],
            weight: 1,
            max_rpm,
            max_tpm,
            max_concurrency: None,
            model_map: None,
        };
        KeyState::from_config("openai", &cfg).unwrap()
    }

    #[test]
    fn availability_consumes_token_budget_exactly_once() {
        let key = key_with(Some(2), None);
        assert!(key.is_available());
        assert!(key.is_available());
        // Regression: the old code ignored the limiter result, so this third
        // check used to succeed and keep handing out the same key.
        assert!(!key.is_available(), "third request must be refused");
        assert_eq!(
            key.availability(0).unwrap_err(),
            UnavailableReason::RateLimited
        );
    }

    #[test]
    fn disabled_keys_are_never_available() {
        let key = key_with(None, None);
        key.set_enabled(false);
        assert!(!key.is_available());
        assert_eq!(
            key.availability(0).unwrap_err(),
            UnavailableReason::Disabled
        );
    }

    #[test]
    fn cooldown_escalates_exponentially_and_is_capped() {
        let key = key_with(None, None);
        let policy = CooldownPolicy {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(25),
            multiplier: 5.0,
            jitter: 0.0,
        };

        key.escalate_cooldown(&policy);
        let first = key.cooldown_remaining().unwrap();
        assert!(first <= Duration::from_secs(1), "first cooldown {first:?}");

        key.escalate_cooldown(&policy);
        let second = key.cooldown_remaining().unwrap();
        assert!(
            second > first,
            "second cooldown {second:?} must exceed {first:?}"
        );

        for _ in 0..10 {
            key.escalate_cooldown(&policy);
        }
        let capped = key.cooldown_remaining().unwrap();
        assert!(
            capped <= Duration::from_secs(25),
            "cooldown {capped:?} must respect the cap"
        );
    }

    #[test]
    fn default_policy_matches_documented_backoff() {
        let cfg = crate::config::LoadBalancingConfig::default();
        let policy = CooldownPolicy::from_config(&cfg);
        assert_eq!(policy.initial, Duration::from_secs(60));
        assert_eq!(policy.max, Duration::from_secs(1500));
        // 60 -> 300 -> 1500 (capped), i.e. 1min -> 5min -> 25min.
        assert!((policy.initial.as_secs_f64() * policy.multiplier) == 300.0);
        assert!((300.0 * policy.multiplier) == 1500.0);
    }

    #[test]
    fn retry_after_overrides_escalation() {
        let key = key_with(None, None);
        let policy = CooldownPolicy::default();
        key.record_rate_limited(Some(Duration::from_secs(7)), &policy);
        let remaining = key.cooldown_remaining().unwrap();
        assert!(remaining <= Duration::from_secs(7) && remaining > Duration::from_secs(6));
        assert_eq!(key.rate_limit_hits(), 1);
        assert_eq!(key.health_state(), HealthState::Open);
    }

    #[test]
    fn success_resets_failure_streak_and_health() {
        let key = key_with(None, None);
        let policy = CooldownPolicy::default();
        let tuning = HealthTuning::default();
        let baseline = key.health_score();
        key.record_failure(&policy, &tuning);
        key.record_failure(&policy, &tuning);
        assert!(
            key.health_score() < baseline,
            "failures must lower the score"
        );
        assert!(key.health_score() < 0.7);

        // A success clears the failure streak and starts lifting the score.
        key.record_success(Duration::from_millis(50), 10, 20, &tuning);
        assert!(key.health_score() > 0.7, "score {}", key.health_score());
        assert_eq!(key.tokens_in(), 10);
        assert_eq!(key.tokens_out(), 20);

        // Repeated fast successes fully restore the key.
        for _ in 0..10 {
            key.record_success(Duration::from_millis(20), 0, 0, &tuning);
        }
        assert!(key.health_score() > 0.95, "score {}", key.health_score());
        assert_eq!(key.health_snapshot().consecutive_failures, 0);
    }

    #[test]
    fn guard_releases_in_flight_even_without_completion() {
        let key = key_with(None, None);
        {
            let _guard = key.reserve();
            assert_eq!(key.in_flight(), 1);
            assert_eq!(key.selections(), 1);
        }
        assert_eq!(key.in_flight(), 0);
    }

    #[test]
    fn guard_completion_releases_exactly_one_slot() {
        let key = key_with(None, None);
        let guard = key.reserve();
        assert_eq!(key.in_flight(), 1);
        guard.complete(
            Outcome::Success,
            Duration::from_millis(10),
            TokenUsage {
                input: 1,
                output: 1,
            },
            &CooldownPolicy::default(),
            &HealthTuning::default(),
        );
        assert_eq!(key.in_flight(), 0);
        assert_eq!(key.successes(), 1);
    }

    #[test]
    fn concurrency_limit_is_enforced_and_released() {
        let cfg = ApiKeyConfig {
            id: "k".into(),
            key: "sk".into(),
            enabled: true,
            models: vec![],
            weight: 1,
            max_rpm: None,
            max_tpm: None,
            max_concurrency: Some(1),
            model_map: None,
        };
        let key = KeyState::from_config("openai", &cfg).unwrap();
        let guard = key.reserve();
        assert_eq!(
            key.availability(0).unwrap_err(),
            UnavailableReason::Concurrency
        );
        drop(guard);
        assert!(key.is_available());
    }

    #[test]
    fn in_flight_never_underflows() {
        let key = key_with(None, None);
        key.release();
        key.release();
        assert_eq!(key.in_flight.load(O::Relaxed), 0);
    }

    #[test]
    fn model_support_and_alias_mapping() {
        let cfg = ApiKeyConfig {
            id: "k".into(),
            key: "sk".into(),
            enabled: true,
            models: vec!["gpt-4".into()],
            weight: 1,
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
            model_map: Some(
                [("fast".to_string(), "gpt-4".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };
        let key = KeyState::from_config("openai", &cfg).unwrap();
        assert!(key.supports_model("gpt-4"));
        assert!(!key.supports_model("claude-3"));
        assert_eq!(key.upstream_model("fast"), "gpt-4");
        assert_eq!(key.upstream_model("gpt-4"), "gpt-4");
    }

    #[test]
    fn available_at_reports_cooldown_expiry() {
        let key = key_with(None, None);
        key.cooldown_for(Duration::from_secs(30));
        let at = key.available_at().expect("cooldown should schedule");
        let wait = at.saturating_duration_since(Instant::now());
        assert!(wait <= Duration::from_secs(30) && wait > Duration::from_secs(29));
    }

    #[test]
    fn rand_unit_stays_in_range_and_varies() {
        let mut seen_low = false;
        let mut seen_high = false;
        for _ in 0..200 {
            let v = rand_unit();
            assert!((0.0..1.0).contains(&v), "out of range: {v}");
            if v < 0.25 {
                seen_low = true;
            }
            if v > 0.75 {
                seen_high = true;
            }
        }
        assert!(seen_low && seen_high, "generator does not vary");
    }
}
