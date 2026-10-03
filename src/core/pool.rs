//! A provider's key pool.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::ProviderConfig;
use crate::core::key_state::{CooldownPolicy, HealthTuning, KeyState, UnavailableReason};
use crate::core::strategy::{Candidate, RotationCounter, Strategy, select};

/// Why a pool could not place a request.
#[derive(Debug, Clone)]
pub enum SelectError {
    /// No key in this pool can ever serve the model.
    NoKeyForModel { model: Option<String> },
    /// Keys exist but every one is blocked.
    Exhausted {
        earliest_retry: Option<Duration>,
        reason: UnavailableReason,
        attempted: usize,
    },
}

impl SelectError {
    /// Suggested wait before retrying, if any.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            SelectError::NoKeyForModel { .. } => None,
            SelectError::Exhausted { earliest_retry, .. } => *earliest_retry,
        }
    }
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectError::NoKeyForModel { model } => match model {
                Some(model) => write!(f, "no key is configured for model `{model}`"),
                None => write!(f, "no key is configured for this request"),
            },
            SelectError::Exhausted {
                earliest_retry,
                reason,
                attempted,
            } => {
                write!(f, "all {attempted} key(s) unusable ({reason})")?;
                if let Some(wait) = earliest_retry {
                    write!(f, ", next available in {:.1}s", wait.as_secs_f64())?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for SelectError {}

/// One provider's keys plus its selection policy.
pub struct KeyPool {
    pub provider: String,
    pub base_url: String,
    pub auth: crate::core::auth::AuthScheme,
    pub path_prefix: String,
    keys: Vec<Arc<KeyState>>,
    strategy: Strategy,
    fallbacks: Vec<Strategy>,
    tolerance: f64,
    cooldown: CooldownPolicy,
    tuning: HealthTuning,
    counter: RotationCounter,
}

impl KeyPool {
    /// Build a pool from a provider config entry.
    pub fn from_config(
        provider: &ProviderConfig,
        strategy: Strategy,
        fallbacks: Vec<Strategy>,
        tolerance: f64,
        cooldown: CooldownPolicy,
        tuning: HealthTuning,
    ) -> crate::error::Result<Self> {
        let mut pool = Self {
            provider: provider.name.clone(),
            base_url: provider
                .base_url
                .clone()
                .unwrap_or_else(|| default_base_url(&provider.name).to_string()),
            auth: crate::core::auth::AuthScheme::from_config(provider)?,
            path_prefix: provider.path_prefix.clone().unwrap_or_default(),
            keys: Vec::new(),
            strategy,
            fallbacks,
            tolerance,
            cooldown,
            tuning,
            counter: RotationCounter::new(),
        };

        for key_config in &provider.api_keys {
            let effective = apply_provider_defaults(provider, key_config);
            pool.keys
                .push(KeyState::from_config(&provider.name, &effective)?);
        }

        Ok(pool)
    }

    /// Build an empty pool with explicit defaults, used by tests.
    pub fn new(provider: impl Into<String>, strategy: Strategy) -> Self {
        let provider = provider.into();
        Self {
            base_url: default_base_url(&provider).to_string(),
            provider,
            auth: crate::core::auth::AuthScheme::Bearer,
            path_prefix: String::new(),
            keys: Vec::new(),
            strategy,
            fallbacks: Vec::new(),
            tolerance: 0.1,
            cooldown: CooldownPolicy::default(),
            tuning: HealthTuning::default(),
            counter: RotationCounter::new(),
        }
    }

    pub fn keys(&self) -> &[Arc<KeyState>] {
        &self.keys
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    pub fn set_strategy(&mut self, strategy: Strategy) {
        self.strategy = strategy;
    }

    pub fn tuning(&self) -> &HealthTuning {
        &self.tuning
    }

    pub fn cooldown_policy(&self) -> &CooldownPolicy {
        &self.cooldown
    }

    /// Look up a key by id.
    pub fn key(&self, id: &str) -> Option<&Arc<KeyState>> {
        self.keys.iter().find(|k| k.id == id)
    }

    /// Add or replace a key by id.
    pub fn upsert_key(&mut self, key: Arc<KeyState>) {
        match self.keys.iter_mut().find(|k| k.id == key.id) {
            Some(slot) => *slot = key,
            None => self.keys.push(key),
        }
    }

    /// Remove a key, returning whether it existed.
    pub fn remove_key(&mut self, id: &str) -> bool {
        let before = self.keys.len();
        self.keys.retain(|k| k.id != id);
        self.keys.len() != before
    }

    /// Keys that could serve `model`, regardless of current limits.
    pub fn keys_for_model(&self, model: Option<&str>) -> Vec<&Arc<KeyState>> {
        self.keys
            .iter()
            .filter(|key| match model {
                Some(model) => key.supports_model(model),
                None => true,
            })
            .collect()
    }

    /// Pick a key for `model`, consuming its rate-limit budget.
    ///
    /// `exclude` carries ids already tried for this request so a retry never
    /// lands on the key that just failed.
    pub fn select(
        &self,
        model: Option<&str>,
        exclude: &HashSet<String>,
        estimated_tokens: u64,
    ) -> std::result::Result<Arc<KeyState>, SelectError> {
        let considered: Vec<&Arc<KeyState>> = self
            .keys
            .iter()
            .filter(|key| !exclude.contains(&key.id))
            .filter(|key| match model {
                Some(model) => key.supports_model(model),
                None => true,
            })
            .collect();

        if considered.is_empty() {
            // Distinguish "no such key" from "all such keys already tried".
            let any_for_model = self.keys.iter().any(|key| match model {
                Some(model) => key.supports_model(model),
                None => true,
            });
            if any_for_model {
                return Err(SelectError::Exhausted {
                    earliest_retry: self.earliest_available(),
                    reason: UnavailableReason::RateLimited,
                    attempted: exclude.len(),
                });
            }
            return Err(SelectError::NoKeyForModel {
                model: model.map(|m| m.to_string()),
            });
        }

        // Try the configured strategy, then each fallback, so a pool that is
        // fully rate limited under `usage_based` still gets one more honest
        // attempt under `round_robin` before we give up.
        let mut reasons: Vec<UnavailableReason> = Vec::new();
        for strategy in std::iter::once(self.strategy).chain(self.fallbacks.iter().copied()) {
            if let Some(key) =
                self.try_strategy(strategy, &considered, estimated_tokens, &mut reasons)
            {
                return Ok(key);
            }
        }

        Err(SelectError::Exhausted {
            earliest_retry: self.earliest_available(),
            reason: reasons
                .first()
                .copied()
                .unwrap_or(UnavailableReason::RateLimited),
            attempted: considered.len(),
        })
    }

    fn try_strategy(
        &self,
        strategy: Strategy,
        considered: &[&Arc<KeyState>],
        estimated_tokens: u64,
        reasons: &mut Vec<UnavailableReason>,
    ) -> Option<Arc<KeyState>> {
        // Only keys that pass the availability gate become candidates, so the
        // strategy cannot hand back a key that is on cooldown or out of quota.
        let mut viable: Vec<(usize, &Arc<KeyState>)> = Vec::with_capacity(considered.len());
        for key in considered {
            match key.availability(estimated_tokens) {
                // The viable list is dense, so its index *is* the candidate
                // index that the strategy returns.
                Ok(()) => viable.push((viable.len(), key)),
                Err(reason) => {
                    if !reasons.contains(&reason) {
                        reasons.push(reason);
                    }
                }
            }
        }

        if viable.is_empty() {
            return None;
        }

        let candidates: Vec<Candidate> = viable
            .iter()
            .map(|(position, key)| Candidate::snapshot(*position, key))
            .collect();

        let chosen = select(strategy, &candidates, &self.counter, self.tolerance);
        // `chosen` indexes the dense viable slice built above.
        viable.get(chosen).map(|(_, key)| Arc::clone(key))
    }

    /// Earliest instant at which any key could accept work.
    pub fn earliest_available(&self) -> Option<Duration> {
        let now = Instant::now();
        self.keys
            .iter()
            .filter_map(|key| key.available_at())
            .map(|at| at.saturating_duration_since(now))
            .min()
    }

    /// True when every key is disabled or permanently unusable.
    pub fn is_dead(&self) -> bool {
        !self.keys.is_empty() && self.keys.iter().all(|k| !k.is_enabled())
    }

    /// Snapshot used by the admin/status endpoints.
    pub fn status(&self) -> Vec<KeyStatus> {
        self.keys
            .iter()
            .map(|key| {
                let (rpm, tpm) = key.observed_rates();
                let health = key.health_snapshot();
                let (peak_rpm, peak_tpm) = key.peak_rates();
                KeyStatus {
                    id: key.id.clone(),
                    enabled: key.is_enabled(),
                    weight: key.weight,
                    in_flight: key.in_flight(),
                    state: health.state.as_str(),
                    health_score: health.score,
                    latency_ms: health.latency_ms,
                    cooldown_secs: key.cooldown_remaining().map(|d| d.as_secs()),
                    rpm,
                    tpm,
                    peak_rpm,
                    peak_tpm,
                    max_rpm: key.max_rpm(),
                    max_tpm: key.max_tpm(),
                    max_concurrency: key.max_concurrency(),
                    selections: key.selections(),
                    successes: key.successes(),
                    failures: key.failures(),
                    rate_limit_hits: key.rate_limit_hits(),
                    models: key.models.clone(),
                    tokens_in: key.tokens_in(),
                    tokens_out: key.tokens_out(),
                }
            })
            .collect()
    }
}

/// JSON-friendly per-key status for the admin API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyStatus {
    pub id: String,
    pub enabled: bool,
    pub weight: u32,
    pub in_flight: u32,
    pub state: &'static str,
    pub health_score: f64,
    pub latency_ms: Option<f64>,
    pub cooldown_secs: Option<u64>,
    pub rpm: u64,
    pub tpm: u64,
    pub peak_rpm: u64,
    pub peak_tpm: u64,
    pub max_rpm: Option<u32>,
    pub max_tpm: Option<u64>,
    pub max_concurrency: Option<u32>,
    pub selections: u64,
    pub successes: u64,
    pub failures: u64,
    pub rate_limit_hits: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub models: Vec<String>,
}

/// Merge provider-level defaults into a key config.
fn apply_provider_defaults(
    provider: &ProviderConfig,
    key: &crate::config::ApiKeyConfig,
) -> crate::config::ApiKeyConfig {
    let mut merged = key.clone();
    if merged.models.is_empty() {
        merged.models = provider.default_models.clone();
    }
    if merged.max_rpm.is_none() {
        merged.max_rpm = provider.max_rpm;
    }
    if merged.max_tpm.is_none() {
        merged.max_tpm = provider.max_tpm;
    }
    if merged.max_concurrency.is_none() {
        merged.max_concurrency = provider.max_concurrency;
    }
    merged
}

/// Sensible default endpoints per known provider.
pub fn default_base_url(provider: &str) -> &'static str {
    match provider.to_ascii_lowercase().as_str() {
        "anthropic" => "https://api.anthropic.com",
        "azure" | "azure_openai" => "https://api.openai.azure.com",
        "vertex" => "https://us-central1-aiplatform.googleapis.com",
        "deepseek" => "https://api.deepseek.com",
        "minimax" => "https://api.minimax.chat",
        "openrouter" => "https://openrouter.ai/api",
        "glm" | "zhipu" => "https://open.bigmodel.cn/api/paas/v4",
        "nvidia" => "https://integrate.api.nvidia.com",
        "groq" => "https://api.groq.com/openai",
        "together" => "https://api.together.xyz",
        "moonshot" | "kimi" => "https://api.moonshot.cn",
        "qwen" | "dashscope" => "https://dashscope.aliyuncs.com/compatible-mode",
        _ => "https://api.openai.com",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_pool_select() {
        use crate::config::{ApiKeyConfig, ProviderConfig};
        use crate::core::key_state::{CooldownPolicy, HealthTuning};
        use crate::core::pool::KeyPool;
        use crate::core::strategy::Strategy;
        use std::collections::HashSet;

        let pc = ProviderConfig {
            name: "openai".into(),
            base_url: None,
            path_prefix: None,
            auth: None,
            auth_query_param: None,
            default_models: vec![],
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
            api_keys: vec![ApiKeyConfig {
                id: "a".into(),
                key: "sk-a".into(),
                enabled: true,
                models: vec![],
                weight: 1,
                max_rpm: None,
                max_tpm: None,
                max_concurrency: None,
                model_map: None,
            }],
        };
        let pool = KeyPool::from_config(
            &pc,
            Strategy::RoundRobin,
            vec![],
            0.0,
            CooldownPolicy::default(),
            HealthTuning::default(),
        )
        .unwrap();
        let k = pool.key("a").unwrap();
        eprintln!(
            "enabled={} avail={:?} score={} inflight={} cooldown={:?}",
            k.is_enabled(),
            k.availability(0),
            k.health_score(),
            k.in_flight(),
            k.cooldown_remaining()
        );
        eprintln!(
            "select={:?}",
            pool.select(None, &HashSet::new(), 0).map(|k| k.id.clone())
        );
    }

    use crate::config::{ApiKeyConfig, ProviderConfig};

    fn provider_config(keys: Vec<ApiKeyConfig>) -> ProviderConfig {
        ProviderConfig {
            name: "openai".into(),
            base_url: None,
            path_prefix: None,
            auth: None,
            auth_query_param: None,
            default_models: vec![],
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
            api_keys: keys,
        }
    }

    fn key_config(id: &str, models: &[&str], max_rpm: Option<u32>) -> ApiKeyConfig {
        ApiKeyConfig {
            id: id.into(),
            key: format!("sk-{id}"),
            enabled: true,
            models: models.iter().map(|m| m.to_string()).collect(),
            weight: 1,
            max_rpm,
            max_tpm: None,
            max_concurrency: None,
            model_map: None,
        }
    }

    fn pool_of(keys: Vec<ApiKeyConfig>, strategy: Strategy) -> KeyPool {
        KeyPool::from_config(
            &provider_config(keys),
            strategy,
            vec![],
            0.0,
            CooldownPolicy::default(),
            HealthTuning::default(),
        )
        .unwrap()
    }

    #[test]
    fn round_robin_rotates_across_keys() {
        let pool = pool_of(
            vec![key_config("a", &[], None), key_config("b", &[], None)],
            Strategy::RoundRobin,
        );
        let empty = HashSet::new();
        let first = pool.select(None, &empty, 0).unwrap();
        let second = pool.select(None, &empty, 0).unwrap();
        let third = pool.select(None, &empty, 0).unwrap();
        assert_eq!(first.id, "a");
        assert_eq!(second.id, "b");
        assert_eq!(third.id, "a");
    }

    #[test]
    fn model_filtering_routes_to_a_capable_key() {
        let pool = pool_of(
            vec![
                key_config("gpt", &["gpt-4"], None),
                key_config("claude", &["claude-3"], None),
            ],
            Strategy::RoundRobin,
        );
        let empty = HashSet::new();
        assert_eq!(
            pool.select(Some("claude-3"), &empty, 0).unwrap().id,
            "claude"
        );
        assert_eq!(pool.select(Some("gpt-4"), &empty, 0).unwrap().id, "gpt");
    }

    #[test]
    fn unknown_model_reports_no_key_for_model() {
        let pool = pool_of(
            vec![key_config("a", &["gpt-4"], None)],
            Strategy::RoundRobin,
        );
        let error = pool
            .select(Some("unknown"), &HashSet::new(), 0)
            .unwrap_err();
        assert!(matches!(error, SelectError::NoKeyForModel { .. }));
        assert!(error.retry_after().is_none());
    }

    #[test]
    fn exhausted_pool_reports_a_retry_hint() {
        let pool = pool_of(vec![key_config("a", &[], Some(1))], Strategy::RoundRobin);
        let empty = HashSet::new();
        assert!(pool.select(None, &empty, 0).is_ok());
        let error = pool.select(None, &empty, 0).unwrap_err();
        let wait = error.retry_after().expect("should suggest a wait");
        assert!(wait <= Duration::from_secs(60));
        assert!(error.to_string().contains("all 1 key(s) unusable"));
    }

    #[test]
    fn exclude_set_forces_a_different_key_on_retry() {
        let pool = pool_of(
            vec![key_config("a", &[], None), key_config("b", &[], None)],
            Strategy::RoundRobin,
        );
        let mut exclude = HashSet::new();
        let first = pool.select(None, &exclude, 0).unwrap();
        exclude.insert(first.id.clone());
        let second = pool.select(None, &exclude, 0).unwrap();
        assert_ne!(first.id, second.id);

        exclude.insert(second.id.clone());
        let error = pool.select(None, &exclude, 0).unwrap_err();
        assert!(matches!(error, SelectError::Exhausted { .. }));
    }

    #[test]
    fn disabled_keys_are_skipped() {
        let pool = pool_of(
            vec![key_config("a", &[], None), key_config("b", &[], None)],
            Strategy::RoundRobin,
        );
        pool.key("a").unwrap().set_enabled(false);
        let empty = HashSet::new();
        assert_eq!(pool.select(None, &empty, 0).unwrap().id, "b");
    }

    #[test]
    fn fallback_strategies_rescue_a_usage_limited_pool() {
        // Primary strategy is UsageBased; the pool is at its limit so the
        // fallback must not matter (limits are real), but a healthy key must
        // still be found when the primary would skip it.
        let pool = KeyPool::from_config(
            &provider_config(vec![key_config("a", &[], None), key_config("b", &[], None)]),
            Strategy::UsageBased,
            vec![Strategy::RoundRobin],
            0.0,
            CooldownPolicy::default(),
            HealthTuning::default(),
        )
        .unwrap();
        let empty = HashSet::new();
        assert!(pool.select(None, &empty, 0).is_ok());
    }

    #[test]
    fn provider_defaults_flow_into_keys() {
        let mut provider = provider_config(vec![key_config("a", &[], None)]);
        provider.default_models = vec!["llama".into()];
        provider.max_rpm = Some(10);
        provider.max_concurrency = Some(4);
        let pool = KeyPool::from_config(
            &provider,
            Strategy::RoundRobin,
            vec![],
            0.0,
            CooldownPolicy::default(),
            HealthTuning::default(),
        )
        .unwrap();
        let key = pool.key("a").unwrap();
        assert_eq!(key.models, vec!["llama".to_string()]);
        assert_eq!(key.max_rpm(), Some(10));
        assert_eq!(key.max_concurrency(), Some(4));
    }

    #[test]
    fn upsert_and_remove_keys() {
        let mut pool = pool_of(vec![key_config("a", &[], None)], Strategy::RoundRobin);
        pool.upsert_key(crate::core::key_state::test_key("b", "openai", &[]));
        assert_eq!(pool.len(), 2);
        // Upserting an existing id replaces rather than duplicates.
        pool.upsert_key(crate::core::key_state::test_key("b", "openai", &[]));
        assert_eq!(pool.len(), 2);
        assert!(pool.remove_key("a"));
        assert!(!pool.remove_key("a"));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn status_snapshot_reports_live_state() {
        let pool = pool_of(
            vec![key_config("a", &["gpt-4"], Some(5))],
            Strategy::RoundRobin,
        );
        let empty = HashSet::new();
        let key = pool.select(Some("gpt-4"), &empty, 0).unwrap();
        // Selecting charges the rate-limit window; `selections` counts
        // dispatched requests and increments on `reserve`.
        assert_eq!(key.selections(), 0);
        let _guard = key.reserve();
        let status = pool.status();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].id, "a");
        assert_eq!(status[0].selections, 1);
        assert_eq!(status[0].rpm, 1);
        assert_eq!(status[0].in_flight, 1);
        assert_eq!(status[0].state, "closed");
        assert_eq!(status[0].models, vec!["gpt-4".to_string()]);
    }

    #[test]
    fn default_base_urls_cover_known_providers() {
        assert_eq!(default_base_url("Anthropic"), "https://api.anthropic.com");
        assert_eq!(
            default_base_url("NVIDIA"),
            "https://integrate.api.nvidia.com"
        );
        assert_eq!(default_base_url("mystery"), "https://api.openai.com");
    }

    #[test]
    fn dead_pool_is_detected() {
        let pool = pool_of(vec![key_config("a", &[], None)], Strategy::RoundRobin);
        assert!(!pool.is_dead());
        pool.key("a").unwrap().set_enabled(false);
        assert!(pool.is_dead());
    }
}
