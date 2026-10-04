//! Request-scoped and process-wide metrics.
//!
//! Everything is a plain atomic counter so recording a metric never blocks a
//! request path. `/metrics` renders these in Prometheus text format.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Latency buckets in milliseconds, matching the usual LLM latency ranges.
pub const LATENCY_BUCKETS_MS: [u64; 10] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000,
];

/// Counters for one key.
#[derive(Debug, Default)]
pub struct KeyMetrics {
    pub requests: AtomicU64,
    pub successes: AtomicU64,
    pub failures: AtomicU64,
    pub rate_limited: AtomicU64,
    pub retries: AtomicU64,
    pub tokens_in: AtomicU64,
    pub tokens_out: AtomicU64,
    pub latency_us_sum: AtomicU64,
    pub latency_us_max: AtomicU64,
    latency_buckets: [AtomicU64; LATENCY_BUCKETS_MS.len()],
    pub cost_micros: AtomicU64,
}

impl KeyMetrics {
    /// Record one sample in the first bucket that fits it.
    fn observe_latency(&self, millis: u64) {
        let index = LATENCY_BUCKETS_MS
            .iter()
            .position(|bound| millis <= *bound)
            .unwrap_or(LATENCY_BUCKETS_MS.len() - 1);
        self.latency_buckets[index].fetch_add(1, Ordering::Relaxed);
    }

    pub fn latency_bucket(&self, index: usize) -> u64 {
        self.latency_buckets
            .get(index)
            .map(|b| b.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Process-wide counters.
#[derive(Debug)]
pub struct Registry {
    pub requests_total: AtomicU64,
    pub responses_2xx: AtomicU64,
    pub responses_4xx: AtomicU64,
    pub responses_5xx: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub key_rotations: AtomicU64,
    pub keys_exhausted: AtomicU64,
    pub rejected_no_key: AtomicU64,
    pub rejected_admin_auth: AtomicU64,
    /// Requests refused by client authentication or the egress policy.
    pub rejected_client_auth: AtomicU64,
    pub rejected_policy: AtomicU64,
    /// Requests a *shadow* policy would have refused. They were served.
    pub shadow_policy_blocks: AtomicU64,
    pub requests_in_flight: AtomicU64,
    pub config_reloads: AtomicU64,
    pub tokens_in_total: AtomicU64,
    pub tokens_out_total: AtomicU64,
    pub cost_micros_total: AtomicU64,
    /// Per `"provider/key"` counters.
    keys: Mutex<BTreeMap<String, Arc<KeyMetrics>>>,
    /// Per `"provider/model"` counters.
    models: Mutex<BTreeMap<String, Arc<KeyMetrics>>>,
    /// Client denials by reason (`missing_credential`, `model_forbidden`, ...).
    client_denials: Mutex<BTreeMap<String, u64>>,
    /// Requests by API dialect (`chat_completions`, `responses`, ...), so an
    /// operator can see which traffic shape is actually in use.
    api_formats: Mutex<BTreeMap<String, u64>>,
    started_at: std::time::Instant,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            responses_2xx: AtomicU64::new(0),
            responses_4xx: AtomicU64::new(0),
            responses_5xx: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            key_rotations: AtomicU64::new(0),
            keys_exhausted: AtomicU64::new(0),
            rejected_no_key: AtomicU64::new(0),
            rejected_admin_auth: AtomicU64::new(0),
            rejected_client_auth: AtomicU64::new(0),
            rejected_policy: AtomicU64::new(0),
            shadow_policy_blocks: AtomicU64::new(0),
            client_denials: Mutex::new(BTreeMap::new()),
            api_formats: Mutex::new(BTreeMap::new()),
            requests_in_flight: AtomicU64::new(0),
            config_reloads: AtomicU64::new(0),
            tokens_in_total: AtomicU64::new(0),
            tokens_out_total: AtomicU64::new(0),
            cost_micros_total: AtomicU64::new(0),
            keys: Mutex::new(BTreeMap::new()),
            models: Mutex::new(BTreeMap::new()),
            started_at: std::time::Instant::now(),
        }
    }

    pub fn uptime_seconds(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64()
    }

    /// Fetch (or create) the counters for a key.
    pub fn key(&self, provider: &str, key_id: &str) -> Arc<KeyMetrics> {
        let name = format!("{provider}/{key_id}");
        let mut keys = self.keys.lock().expect("metrics mutex poisoned");
        Arc::clone(
            keys.entry(name)
                .or_insert_with(|| Arc::new(KeyMetrics::default())),
        )
    }

    /// Fetch (or create) the counters for a model.
    pub fn model(&self, provider: &str, model: &str) -> Arc<KeyMetrics> {
        let name = format!("{provider}/{model}");
        let mut models = self.models.lock().expect("metrics mutex poisoned");
        Arc::clone(
            models
                .entry(name)
                .or_insert_with(|| Arc::new(KeyMetrics::default())),
        )
    }

    /// Drop counters for keys that no longer exist.
    pub fn retain_keys(&self, provider: &str, alive: &dyn Fn(&str) -> bool) {
        let mut keys = self.keys.lock().expect("metrics mutex poisoned");
        keys.retain(|name, _| match name.split_once('/') {
            Some((owner, id)) if owner == provider => alive(id),
            _ => true,
        });
    }

    /// Forget a model's counters.
    pub fn forget_model(&self, provider: &str, model: &str) {
        let mut models = self.models.lock().expect("metrics mutex poisoned");
        models.remove(&format!("{provider}/{model}"));
    }

    /// Snapshot of every key's counters.
    pub fn key_snapshot(&self) -> Vec<(String, Arc<KeyMetrics>)> {
        self.keys
            .lock()
            .expect("metrics mutex poisoned")
            .iter()
            .map(|(name, metrics)| (name.clone(), Arc::clone(metrics)))
            .collect()
    }

    /// Snapshot of every model's counters.
    pub fn model_snapshot(&self) -> Vec<(String, Arc<KeyMetrics>)> {
        self.models
            .lock()
            .expect("metrics mutex poisoned")
            .iter()
            .map(|(name, metrics)| (name.clone(), Arc::clone(metrics)))
            .collect()
    }

    /// Count a completed request against a key.
    #[allow(clippy::too_many_arguments)]
    pub fn record_request(
        &self,
        provider: &str,
        key_id: &str,
        model: Option<&str>,
        status: u16,
        latency: std::time::Duration,
        tokens_in: u64,
        tokens_out: u64,
        cost_micros: u64,
    ) {
        let millis = latency.as_millis() as u64;
        let micros = latency.as_micros() as u64;

        for metric in [
            Some(self.key(provider, key_id)),
            model.map(|m| self.model(provider, m)),
        ]
        .into_iter()
        .flatten()
        {
            metric.requests.fetch_add(1, Ordering::Relaxed);
            metric.latency_us_sum.fetch_add(micros, Ordering::Relaxed);
            bump_max(&metric.latency_us_max, micros);
            metric.observe_latency(millis);
            if (200..300).contains(&status) {
                metric.successes.fetch_add(1, Ordering::Relaxed);
            } else if status >= 500 || status == 0 {
                metric.failures.fetch_add(1, Ordering::Relaxed);
            }
            if status == 429 {
                metric.rate_limited.fetch_add(1, Ordering::Relaxed);
            }
            if tokens_in > 0 {
                metric.tokens_in.fetch_add(tokens_in, Ordering::Relaxed);
            }
            if tokens_out > 0 {
                metric.tokens_out.fetch_add(tokens_out, Ordering::Relaxed);
            }
            if cost_micros > 0 {
                metric.cost_micros.fetch_add(cost_micros, Ordering::Relaxed);
            }
        }

        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.tokens_in_total.fetch_add(tokens_in, Ordering::Relaxed);
        self.tokens_out_total
            .fetch_add(tokens_out, Ordering::Relaxed);
        self.cost_micros_total
            .fetch_add(cost_micros, Ordering::Relaxed);
        if (200..300).contains(&status) {
            self.responses_2xx.fetch_add(1, Ordering::Relaxed);
        } else if (400..500).contains(&status) {
            self.responses_4xx.fetch_add(1, Ordering::Relaxed);
        } else if status >= 500 {
            self.responses_5xx.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a refused request against its reason.
    ///
    /// The reason is a fixed set in [`crate::core::security::DenyReason`], so
    /// the label cardinality is bounded.
    pub fn record_denial(&self, reason: &str) {
        *self
            .client_denials
            .lock()
            .expect("metrics mutex poisoned")
            .entry(reason.to_string())
            .or_insert(0) += 1;
    }

    /// Count a request against its API dialect.
    pub fn record_api_format(&self, format: &str) {
        *self
            .api_formats
            .lock()
            .expect("metrics mutex poisoned")
            .entry(format.to_string())
            .or_insert(0) += 1;
    }

    /// Request counts by API dialect.
    pub fn api_formats(&self) -> BTreeMap<String, u64> {
        self.api_formats
            .lock()
            .expect("metrics mutex poisoned")
            .clone()
    }

    /// Denial counts by reason.
    pub fn client_denials(&self) -> BTreeMap<String, u64> {
        self.client_denials
            .lock()
            .expect("metrics mutex poisoned")
            .clone()
    }

    /// Render Prometheus text format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(8 * 1024);
        let inc = |v: u64| v.to_string();

        macro_rules! counter {
            ($name:literal, $help:literal, $value:expr) => {{
                out.push_str(concat!("# HELP ", $name, " ", $help, "\n"));
                out.push_str(concat!("# TYPE ", $name, " counter\n"));
                out.push_str($name);
                out.push(' ');
                out.push_str(&inc($value));
                out.push('\n');
            }};
        }

        macro_rules! gauge {
            ($name:literal, $help:literal, $value:expr) => {{
                out.push_str(concat!("# HELP ", $name, " ", $help, "\n"));
                out.push_str(concat!("# TYPE ", $name, " gauge\n"));
                out.push_str($name);
                out.push(' ');
                out.push_str(&inc($value));
                out.push('\n');
            }};
        }

        counter!(
            "llm_broker_requests_total",
            "Requests received by the proxy.",
            self.requests_total.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_responses_2xx_total",
            "Upstream responses with a 2xx status.",
            self.responses_2xx.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_responses_4xx_total",
            "Upstream responses with a 4xx status.",
            self.responses_4xx.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_responses_5xx_total",
            "Upstream responses with a 5xx status.",
            self.responses_5xx.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_upstream_failures_total",
            "Connection or transport failures talking to an upstream.",
            self.upstream_failures.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_key_rotations_total",
            "Times a request was retried on a different key.",
            self.key_rotations.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_keys_exhausted_total",
            "Requests refused because every key was unusable.",
            self.keys_exhausted.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_rejected_no_key_total",
            "Requests refused because no key matched the model.",
            self.rejected_no_key.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_admin_auth_failures_total",
            "Admin API requests rejected for a bad token.",
            self.rejected_admin_auth.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_client_auth_failures_total",
            "Proxy requests rejected for a missing or unknown client token.",
            self.rejected_client_auth.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_shadow_policy_blocks_total",
            "Requests a shadow (dry-run) policy would have refused. These were served.",
            self.shadow_policy_blocks.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_policy_denials_total",
            "Requests refused by the egress policy (model, provider or budget).",
            self.rejected_policy.load(Ordering::Relaxed)
        );
        let formats = self.api_formats();
        if !formats.is_empty() {
            out.push_str(
                "# HELP llm_broker_requests_by_api_total Proxied requests, by OpenAI API dialect.\n",
            );
            out.push_str("# TYPE llm_broker_requests_by_api_total counter\n");
            for (format, count) in formats {
                debug_assert!(
                    format
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                    "unexpected characters in an api format label: {format}"
                );
                out.push_str(&format!(
                    "llm_broker_requests_by_api_total{{api=\"{format}\"}} {count}\n"
                ));
            }
        }

        let denials = self.client_denials();
        if !denials.is_empty() {
            out.push_str(
                "# HELP llm_broker_client_denials_total Client requests refused, by reason.\n",
            );
            out.push_str("# TYPE llm_broker_client_denials_total counter\n");
            for (reason, count) in denials {
                // Reasons come from a fixed enum, so no label escaping is
                // needed; assert that rather than trusting it silently.
                debug_assert!(
                    reason
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                    "unexpected characters in a denial reason: {reason}"
                );
                out.push_str(&format!(
                    "llm_broker_client_denials_total{{reason=\"{reason}\"}} {count}\n"
                ));
            }
        }
        counter!(
            "llm_broker_config_reloads_total",
            "Successful configuration reloads.",
            self.config_reloads.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_tokens_input_total",
            "Prompt tokens observed across all responses.",
            self.tokens_in_total.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_tokens_output_total",
            "Completion tokens observed across all responses.",
            self.tokens_out_total.load(Ordering::Relaxed)
        );
        counter!(
            "llm_broker_cost_micros_total",
            "Estimated upstream spend in millionths of a currency unit.",
            self.cost_micros_total.load(Ordering::Relaxed)
        );
        gauge!(
            "llm_broker_requests_in_flight",
            "Requests currently being proxied.",
            self.requests_in_flight.load(Ordering::Relaxed)
        );
        out.push_str("# HELP llm_broker_uptime_seconds Seconds since the process started.\n");
        out.push_str("# TYPE llm_broker_uptime_seconds gauge\n");
        out.push_str(&format!(
            "llm_broker_uptime_seconds {:.3}\n",
            self.uptime_seconds()
        ));

        let render_family = |out: &mut String,
                             name: &str,
                             label: &str,
                             help: &str,
                             rows: &[(String, Arc<KeyMetrics>)]| {
            if rows.is_empty() {
                return;
            }
            out.push_str(&format!("# HELP {name} {help}\n"));
            out.push_str(&format!("# TYPE {name} counter\n"));
            for (key, metric) in rows {
                out.push_str(&format!(
                    "{name}{{{label}=\"{key}\"}} {}\n",
                    metric.requests.load(Ordering::Relaxed)
                ));
            }
        };

        let keys = self.key_snapshot();
        let models = self.model_snapshot();

        render_family(
            &mut out,
            "llm_broker_key_requests_total",
            "provider_key",
            "Requests dispatched per provider key.",
            &keys,
        );
        render_family(
            &mut out,
            "llm_broker_model_requests_total",
            "provider_model",
            "Requests dispatched per provider model.",
            &models,
        );

        if !keys.is_empty() {
            out.push_str(
                "# HELP llm_broker_key_rate_limited_total 429 responses observed per key.\n",
            );
            out.push_str("# TYPE llm_broker_key_rate_limited_total counter\n");
            for (key, metric) in &keys {
                out.push_str(&format!(
                    "llm_broker_key_rate_limited_total{{provider_key=\"{key}\"}} {}\n",
                    metric.rate_limited.load(Ordering::Relaxed)
                ));
            }

            out.push_str("# HELP llm_broker_key_retries_total Retries charged to a key.\n");
            out.push_str("# TYPE llm_broker_key_retries_total counter\n");
            for (key, metric) in &keys {
                out.push_str(&format!(
                    "llm_broker_key_retries_total{{provider_key=\"{key}\"}} {}\n",
                    metric.retries.load(Ordering::Relaxed)
                ));
            }

            out.push_str("# HELP llm_broker_key_tokens_total Tokens observed per key.\n");
            out.push_str("# TYPE llm_broker_key_tokens_total counter\n");
            for (key, metric) in &keys {
                out.push_str(&format!(
                    "llm_broker_key_tokens_total{{provider_key=\"{key}\",direction=\"input\"}} {}\n",
                    metric.tokens_in.load(Ordering::Relaxed)
                ));
                out.push_str(&format!(
                    "llm_broker_key_tokens_total{{provider_key=\"{key}\",direction=\"output\"}} {}\n",
                    metric.tokens_out.load(Ordering::Relaxed)
                ));
            }

            out.push_str("# HELP llm_broker_key_latency_milliseconds Request latency per key.\n");
            out.push_str("# TYPE llm_broker_key_latency_milliseconds histogram\n");
            for (key, metric) in &keys {
                for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
                    let count = metric.latency_bucket(index);
                    out.push_str(&format!(
                        "llm_broker_key_latency_milliseconds_bucket{{provider_key=\"{key}\",le=\"{bound}\"}} {count}\n"
                    ));
                }
                out.push_str(&format!(
                    "llm_broker_key_latency_milliseconds_bucket{{provider_key=\"{key}\",le=\"+Inf\"}} {}\n",
                    metric.requests.load(Ordering::Relaxed)
                ));
                out.push_str(&format!(
                    "llm_broker_key_latency_milliseconds_sum{{provider_key=\"{key}\"}} {}\n",
                    metric.latency_us_sum.load(Ordering::Relaxed) as f64 / 1000.0
                ));
                out.push_str(&format!(
                    "llm_broker_key_latency_milliseconds_count{{provider_key=\"{key}\"}} {}\n",
                    metric.requests.load(Ordering::Relaxed)
                ));
            }
        }

        out
    }
}

fn bump_max(slot: &AtomicU64, value: u64) {
    let mut current = slot.load(Ordering::Relaxed);
    while value > current {
        match slot.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

/// Estimate the cost of a request in millionths of a currency unit.
pub fn estimate_cost_micros(
    pricing: &[crate::config::ModelPricing],
    model: &str,
    tokens_in: u64,
    tokens_out: u64,
) -> u64 {
    let Some(price) = pricing.iter().find(|p| p.model == model) else {
        return 0;
    };
    let input = price.input_per_million * tokens_in as f64 / 1_000_000.0 * 1_000_000.0;
    let output = price.output_per_million * tokens_out as f64 / 1_000_000.0 * 1_000_000.0;
    (input + output).max(0.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn counters_accumulate_per_key_and_model() {
        let registry = Registry::new();
        registry.record_request(
            "openai",
            "k1",
            Some("gpt-4"),
            200,
            Duration::from_millis(120),
            10,
            20,
            0,
        );
        registry.record_request(
            "openai",
            "k1",
            Some("gpt-4"),
            429,
            Duration::from_millis(30),
            0,
            0,
            0,
        );

        let key = registry.key("openai", "k1");
        assert_eq!(key.requests.load(Ordering::Relaxed), 2);
        assert_eq!(key.successes.load(Ordering::Relaxed), 1);
        assert_eq!(key.rate_limited.load(Ordering::Relaxed), 1);
        assert_eq!(key.tokens_in.load(Ordering::Relaxed), 10);
        assert_eq!(key.tokens_out.load(Ordering::Relaxed), 20);

        let model = registry.model("openai", "gpt-4");
        assert_eq!(model.requests.load(Ordering::Relaxed), 2);
        assert_eq!(registry.responses_2xx.load(Ordering::Relaxed), 1);
        assert_eq!(registry.responses_4xx.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn histogram_buckets_place_values_in_the_first_fitting_bucket() {
        let registry = Registry::new();
        registry.record_request("p", "k", None, 200, Duration::from_millis(120), 0, 0, 0);
        let key = registry.key("p", "k");
        // 120ms only fits in buckets >= 250ms, and in exactly one of them.
        assert_eq!(key.latency_bucket(0), 0, "50ms bucket must be empty");
        assert_eq!(key.latency_bucket(1), 0, "100ms bucket must be empty");
        assert_eq!(key.latency_bucket(2), 1, "250ms bucket must be filled");
        assert_eq!(
            (0..LATENCY_BUCKETS_MS.len())
                .map(|i| key.latency_bucket(i))
                .sum::<u64>(),
            1,
            "a sample must be counted in exactly one bucket"
        );

        registry.record_request("p", "k", None, 200, Duration::from_millis(20), 0, 0, 0);
        assert_eq!(key.latency_bucket(0), 1, "20ms fits the first bucket");
        assert_eq!(key.latency_bucket(2), 1, "the 120ms sample is unchanged");
    }

    #[test]
    fn retain_keys_drops_only_dead_keys_of_that_provider() {
        let registry = Registry::new();
        registry.key("openai", "keep");
        registry.key("openai", "drop");
        registry.key("other", "drop");
        registry.retain_keys("openai", &|id| id == "keep");
        let names: Vec<String> = registry
            .key_snapshot()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(names.contains(&"openai/keep".to_string()));
        assert!(!names.contains(&"openai/drop".to_string()));
        assert!(names.contains(&"other/drop".to_string()));
    }

    #[test]
    fn prometheus_output_contains_expected_series() {
        let registry = Registry::new();
        registry.record_request(
            "openai",
            "k1",
            Some("gpt-4"),
            200,
            Duration::from_millis(75),
            5,
            7,
            42,
        );
        let text = registry.render_prometheus();
        assert!(text.contains("llm_broker_requests_total 1"));
        assert!(text.contains("llm_broker_key_requests_total{provider_key=\"openai/k1\"} 1"));
        assert!(
            text.contains("llm_broker_model_requests_total{provider_model=\"openai/gpt-4\"} 1")
        );
        assert!(text.contains(
            "llm_broker_key_tokens_total{provider_key=\"openai/k1\",direction=\"input\"} 5"
        ));
        assert!(
            text.contains(
                "llm_broker_key_latency_milliseconds_count{provider_key=\"openai/k1\"} 1"
            )
        );
        assert!(text.contains("# TYPE llm_broker_requests_total counter"));
    }

    #[test]
    fn prometheus_output_is_valid_when_empty() {
        let registry = Registry::new();
        let text = registry.render_prometheus();
        assert!(text.contains("llm_broker_requests_total 0"));
        assert!(!text.contains("llm_broker_key_requests_total"));
    }

    #[test]
    fn cost_estimation_uses_matching_pricing_only() {
        let pricing = vec![crate::config::ModelPricing {
            model: "gpt-4".into(),
            input_per_million: 10.0,
            output_per_million: 30.0,
        }];
        // 1M input + 1M output at 10 + 30 = 40 currency units = 40_000_000 micros.
        assert_eq!(
            estimate_cost_micros(&pricing, "gpt-4", 1_000_000, 1_000_000),
            40_000_000
        );
        assert_eq!(estimate_cost_micros(&pricing, "unknown", 1_000_000, 0), 0);
    }
}
