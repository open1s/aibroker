//! Model routing and key selection across providers.
//!
//! This is the layer that fixes the original broker's biggest routing defect:
//! a request is matched to a provider by the model it asks for, not by
//! whichever pool happens to come first in a hash map.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Config, RouteConfig};
use crate::core::key_state::{CooldownPolicy, HealthTuning, KeyState};
use crate::core::pool::{KeyPool, SelectError};
use crate::core::strategy::Strategy;

/// Why a request could not be placed.
#[derive(Debug, Clone)]
pub enum RouteError {
    /// No provider is configured for the requested model.
    Unroutable { model: Option<String> },
    /// Providers match but every key is currently unusable.
    Exhausted {
        retry_after: Option<Duration>,
        detail: String,
    },
    /// Every provider matching the model is entirely out of keys.
    NoKeys { model: Option<String> },
}

impl RouteError {
    /// Suggested `Retry-After` for the client.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            RouteError::Exhausted { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    pub fn model(&self) -> Option<&str> {
        match self {
            RouteError::Unroutable { model } | RouteError::NoKeys { model } => model.as_deref(),
            RouteError::Exhausted { .. } => None,
        }
    }
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::Unroutable { model } => match model {
                Some(model) => write!(f, "no provider serves model `{model}`"),
                None => write!(f, "no provider serves this request"),
            },
            RouteError::Exhausted { detail, .. } => write!(f, "{detail}"),
            RouteError::NoKeys { model } => match model {
                Some(model) => write!(f, "no keys configured for model `{model}`"),
                None => write!(f, "no keys configured"),
            },
        }
    }
}

impl std::error::Error for RouteError {}

/// A key chosen to serve a request.
#[derive(Debug, Clone)]
pub struct SelectedKey {
    pub provider: String,
    pub key: Arc<KeyState>,
    /// Model name to send upstream, after alias and rewrite mapping.
    pub upstream_model: Option<String>,
    /// Endpoint the provider's keys point at.
    pub base_url: String,
    /// Path segment appended to `base_url`.
    pub path_prefix: String,
    /// Where this provider expects the credential.
    pub auth: crate::core::auth::AuthScheme,
}

/// Compiled routing table plus every provider pool.
pub struct Broker {
    pools: BTreeMap<String, Arc<KeyPool>>,
    routes: Vec<CompiledRoute>,
    default_provider: Option<String>,
    strategy: Strategy,
    fallbacks: Vec<Strategy>,
}

struct CompiledRoute {
    pattern: ModelPattern,
    providers: Vec<String>,
    strategy: Option<Strategy>,
    rewrite: bool,
    /// Specificity for ordering: exact beats glob beats catch-all.
    rank: u8,
}

/// Model matcher supporting exact names and `*`/`?` globs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelPattern {
    Any,
    Exact(String),
    Glob(String),
}

impl ModelPattern {
    pub fn parse(pattern: &str) -> Self {
        let trimmed = pattern.trim();
        if trimmed == "*" {
            ModelPattern::Any
        } else if trimmed.contains('*') || trimmed.contains('?') {
            ModelPattern::Glob(trimmed.to_ascii_lowercase())
        } else {
            ModelPattern::Exact(trimmed.to_ascii_lowercase())
        }
    }

    pub fn matches(&self, model: &str) -> bool {
        match self {
            ModelPattern::Any => true,
            ModelPattern::Exact(name) => model.eq_ignore_ascii_case(name),
            ModelPattern::Glob(pattern) => glob_match(pattern, &model.to_ascii_lowercase()),
        }
    }

    fn rank(&self) -> u8 {
        match self {
            ModelPattern::Exact(_) => 0,
            ModelPattern::Glob(_) => 1,
            ModelPattern::Any => 2,
        }
    }
}

/// Iterative glob matcher supporting `*` and `?`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

impl Broker {
    /// Compile a config into an immutable routing table.
    pub fn from_config(config: &Config) -> crate::error::Result<Self> {
        let strategy = Strategy::parse(&config.load_balancing.strategy).unwrap_or_default();
        let fallbacks: Vec<Strategy> = config
            .load_balancing
            .fallback_strategies
            .iter()
            .filter_map(|s| Strategy::parse(s))
            .filter(|s| *s != strategy)
            .collect();

        let cooldown = CooldownPolicy::from_config(&config.load_balancing);
        let tuning = HealthTuning {
            enabled: config.health.enabled,
            latency_alpha: config.health.latency_alpha,
            slow_latency_ms: config.health.slow_latency_ms,
            unhealthy_threshold: config.health.unhealthy_threshold,
            failure_threshold: config.health.failure_threshold,
            recovery_threshold: config.health.recovery_threshold,
        };

        let mut pools = BTreeMap::new();
        for provider in &config.providers {
            let pool = KeyPool::from_config(
                provider,
                strategy,
                fallbacks.clone(),
                config.load_balancing.weighted_random_tolerance,
                cooldown,
                tuning,
            )?;
            pools.insert(provider.name.clone(), Arc::new(pool));
        }

        let mut routes: Vec<CompiledRoute> = config.routes.iter().map(compile_route).collect();
        // Most specific first.
        routes.sort_by_key(|route| route.rank);

        Ok(Self {
            pools,
            routes,
            default_provider: config.default_route.clone(),
            strategy,
            fallbacks,
        })
    }

    pub fn pools(&self) -> &BTreeMap<String, Arc<KeyPool>> {
        &self.pools
    }

    pub fn pool(&self, provider: &str) -> Option<&Arc<KeyPool>> {
        self.pools.get(provider)
    }

    /// Replace a pool, used by the admin API after mutating keys.
    pub fn set_pool(&mut self, pool: Arc<KeyPool>) {
        self.pools.insert(pool.provider.clone(), pool);
    }

    /// Recompute the provider order for a model.
    ///
    /// Order of preference:
    /// 1. explicit routes matching the model (most specific first),
    /// 2. providers whose keys explicitly list the model,
    /// 3. the configured `default_route`,
    /// 4. every remaining provider.
    pub fn route_candidates(&self, model: Option<&str>) -> Vec<String> {
        let mut order: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        let push = |name: &str, order: &mut Vec<String>, seen: &mut HashSet<String>| {
            if self.pools.contains_key(name) && seen.insert(name.to_string()) {
                order.push(name.to_string());
            }
        };

        if let Some(model) = model {
            // Explicit routes come first...
            for route in &self.routes {
                if route.pattern.matches(model) {
                    for provider in &route.providers {
                        push(provider, &mut order, &mut seen);
                    }
                }
            }

            // ...then any provider that explicitly declares the model...
            for (name, pool) in &self.pools {
                let lists_model = pool
                    .keys()
                    .iter()
                    .any(|key| !key.models.is_empty() && key.supports_model(model));
                if lists_model {
                    push(name, &mut order, &mut seen);
                }
            }
        }

        // ...then the configured default...
        if let Some(default) = &self.default_provider {
            push(default, &mut order, &mut seen);
        }

        // ...and finally anything else, so an unlisted model can still be
        // served by a provider whose keys accept everything.
        for name in self.pools.keys() {
            push(name, &mut order, &mut seen);
        }

        order
    }

    /// The strategy override for a model, if a route pins one.
    pub fn strategy_for_model(&self, model: Option<&str>) -> Strategy {
        if let Some(model) = model {
            for route in &self.routes {
                if route.pattern.matches(model)
                    && let Some(strategy) = route.strategy
                {
                    return strategy;
                }
            }
        }
        self.strategy
    }

    /// Whether a route asks for the model name to be rewritten upstream.
    pub fn rewrites_model(&self, model: Option<&str>) -> bool {
        let Some(model) = model else {
            return false;
        };
        self.routes
            .iter()
            .find(|route| route.pattern.matches(model))
            .map(|route| route.rewrite)
            .unwrap_or(false)
    }

    /// Select a key for `model`, skipping ids in `exclude`.
    ///
    /// Exhaustion is sticky: if any provider had a matching-but-blocked key we
    /// report `Exhausted` rather than `Unroutable`, because that distinction
    /// decides between "retry later" and "this model does not exist here".
    pub fn select(
        &self,
        model: Option<&str>,
        exclude: &HashSet<String>,
        estimated_tokens: u64,
    ) -> Result<SelectedKey, RouteError> {
        let mut best_exhausted: Option<RouteError> = None;
        let mut saw_matching_key = false;

        for provider in self.route_candidates(model) {
            let Some(pool) = self.pools.get(&provider) else {
                continue;
            };

            if !pool.keys_for_model(model).is_empty() {
                saw_matching_key = true;
            }

            match pool.select(model, exclude, estimated_tokens) {
                Ok(key) => {
                    let upstream_model = model.map(|m| key.upstream_model(m));
                    return Ok(SelectedKey {
                        provider,
                        key,
                        upstream_model,
                        base_url: pool.base_url.clone(),
                        path_prefix: pool.path_prefix.clone(),
                        auth: pool.auth.clone(),
                    });
                }
                Err(error) => {
                    let candidate = match error {
                        SelectError::NoKeyForModel { .. } => continue,
                        SelectError::Exhausted {
                            earliest_retry,
                            reason,
                            attempted,
                        } => RouteError::Exhausted {
                            retry_after: earliest_retry,
                            detail: format!(
                                "provider `{provider}`: all {attempted} key(s) unusable ({reason})"
                            ),
                        },
                    };
                    // Prefer the soonest retry hint across providers.
                    best_exhausted = match (best_exhausted, candidate) {
                        (None, candidate) => Some(candidate),
                        (Some(current), candidate) => {
                            let current_wait = current.retry_after();
                            let candidate_wait = candidate.retry_after();
                            match (current_wait, candidate_wait) {
                                (Some(a), Some(b)) if b < a => Some(candidate),
                                (None, Some(_)) => Some(candidate),
                                _ => Some(current),
                            }
                        }
                    };
                }
            }
        }

        if let Some(error) = best_exhausted {
            return Err(error);
        }
        if saw_matching_key {
            // Keys exist for this model but every one was excluded, which only
            // happens mid-retry after the whole matching pool has failed.
            return Err(RouteError::Exhausted {
                retry_after: None,
                detail: "every matching key has already been tried for this request".to_string(),
            });
        }
        if self.pools.is_empty() || self.pools.values().all(|pool| pool.is_empty()) {
            return Err(RouteError::NoKeys {
                model: model.map(|m| m.to_string()),
            });
        }
        Err(RouteError::Unroutable {
            model: model.map(|m| m.to_string()),
        })
    }

    /// Models advertised by the config, with their provider order.
    pub fn routes(&self) -> Vec<RouteView> {
        self.routes
            .iter()
            .map(|route| RouteView {
                pattern: match &route.pattern {
                    ModelPattern::Any => "*".to_string(),
                    ModelPattern::Exact(name) => name.clone(),
                    ModelPattern::Glob(glob) => glob.clone(),
                },
                providers: route.providers.clone(),
                strategy: route.strategy.map(|s| s.as_str().to_string()),
                rewrite: route.rewrite,
            })
            .collect()
    }

    pub fn strategies(&self) -> (Strategy, Vec<Strategy>) {
        (self.strategy, self.fallbacks.clone())
    }
}

fn compile_route(route: &RouteConfig) -> CompiledRoute {
    let pattern = ModelPattern::parse(&route.model);
    let rank = pattern.rank();
    CompiledRoute {
        pattern,
        providers: route.providers.clone(),
        strategy: route.strategy.as_deref().and_then(Strategy::parse),
        rewrite: route.rewrite,
        rank,
    }
}

/// JSON-friendly view of a compiled route.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RouteView {
    pub pattern: String,
    pub providers: Vec<String>,
    pub strategy: Option<String>,
    pub rewrite: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKeyConfig, ProviderConfig};

    fn key(id: &str, models: &[&str]) -> ApiKeyConfig {
        ApiKeyConfig {
            id: id.into(),
            key: format!("sk-{id}"),
            enabled: true,
            models: models.iter().map(|m| m.to_string()).collect(),
            weight: 1,
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
            model_map: None,
        }
    }

    fn provider(name: &str, keys: Vec<ApiKeyConfig>) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
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

    fn config(providers: Vec<ProviderConfig>, routes: Vec<RouteConfig>) -> Config {
        Config {
            server: crate::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 0,
                threads: None,
                daemon: false,
                pid_file: None,
                user: None,
                group: None,
                connect_timeout_ms: 0,
                idle_timeout_ms: None,
                max_retries: 3,
            },
            proxy_type: None,
            providers,
            routes,
            default_route: None,
            load_balancing: Default::default(),
            health: Default::default(),
            observability: Default::default(),
            admin: Default::default(),
        }
    }

    fn route(model: &str, providers: &[&str]) -> RouteConfig {
        RouteConfig {
            model: model.into(),
            providers: providers.iter().map(|p| p.to_string()).collect(),
            strategy: None,
            rewrite: false,
        }
    }

    #[test]
    fn glob_matcher_handles_wildcards() {
        assert!(glob_match("claude-*", "claude-3-opus"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("gpt-?.*", "gpt-4.5"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("claude-*", "gpt-4"));
        assert!(!glob_match("gpt-?", "gpt-44"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
    }

    #[test]
    fn model_routing_skips_providers_without_the_model() {
        // Regression: the old code picked an arbitrary pool and could send a
        // gpt-4 request to a provider that only serves llama.
        let cfg = config(
            vec![
                provider("nvidia", vec![key("nv", &["llama-3"])]),
                provider("openai", vec![key("oa", &["gpt-4"])]),
            ],
            vec![],
        );
        let broker = Broker::from_config(&cfg).unwrap();
        let selected = broker.select(Some("gpt-4"), &HashSet::new(), 0).unwrap();
        assert_eq!(selected.provider, "openai");
        assert_eq!(selected.key.id, "oa");
    }

    #[test]
    fn explicit_routes_take_priority() {
        let cfg = config(
            vec![
                provider("a", vec![key("ka", &["shared"])]),
                provider("b", vec![key("kb", &["shared"])]),
            ],
            vec![route("shared", &["b"])],
        );
        let broker = Broker::from_config(&cfg).unwrap();
        let selected = broker.select(Some("shared"), &HashSet::new(), 0).unwrap();
        assert_eq!(selected.provider, "b");
    }

    #[test]
    fn glob_routes_match_model_families() {
        let cfg = config(
            vec![
                provider("anthropic", vec![key("ka", &[])]),
                provider("openai", vec![key("ko", &[])]),
            ],
            vec![route("claude-*", &["anthropic"])],
        );
        let broker = Broker::from_config(&cfg).unwrap();
        assert_eq!(
            broker
                .select(Some("claude-3-5-sonnet"), &HashSet::new(), 0)
                .unwrap()
                .provider,
            "anthropic"
        );
        // `anthropic`'s key accepts every model, so it is tried before
        // `openai` for a model nothing explicitly claims.
        assert_eq!(
            broker
                .select(Some("gpt-4"), &HashSet::new(), 0)
                .unwrap()
                .provider,
            "anthropic"
        );
    }

    #[test]
    fn unroutable_models_are_reported_distinctly() {
        let cfg = config(
            vec![provider("openai", vec![key("oa", &["gpt-4"])])],
            vec![],
        );
        let broker = Broker::from_config(&cfg).unwrap();
        let error = broker
            .select(Some("does-not-exist"), &HashSet::new(), 0)
            .unwrap_err();
        // No provider claims that model, which is a routing failure rather
        // than an exhausted pool — the distinction decides 503 vs 429.
        assert!(
            matches!(error, RouteError::Unroutable { .. }),
            "got {error:?}"
        );
        assert!(error.retry_after().is_none());
    }

    #[test]
    fn exhausted_pools_surface_a_retry_hint() {
        let mut limited = key("oa", &["gpt-4"]);
        limited.max_rpm = Some(1);
        let cfg = config(vec![provider("openai", vec![limited])], vec![]);
        let broker = Broker::from_config(&cfg).unwrap();
        let exclude = HashSet::new();
        assert!(broker.select(Some("gpt-4"), &exclude, 0).is_ok());
        let error = broker.select(Some("gpt-4"), &exclude, 0).unwrap_err();
        assert!(
            matches!(error, RouteError::Exhausted { .. }),
            "got {error:?}"
        );
        assert!(error.retry_after().is_some());
    }

    #[test]
    fn retry_exclusion_forces_a_different_provider() {
        let cfg = config(
            vec![
                provider("a", vec![key("ka", &["m"])]),
                provider("b", vec![key("kb", &["m"])]),
            ],
            vec![],
        );
        let broker = Broker::from_config(&cfg).unwrap();
        let mut exclude = HashSet::new();
        let first = broker.select(Some("m"), &exclude, 0).unwrap();
        exclude.insert(first.key.id.clone());
        let second = broker.select(Some("m"), &exclude, 0).unwrap();
        assert_ne!(first.key.id, second.key.id);
        assert_ne!(first.provider, second.provider);
    }

    #[test]
    fn fallback_provider_is_used_when_the_preferred_pool_is_exhausted() {
        let mut limited = key("ka", &["m"]);
        limited.max_rpm = Some(1);
        let cfg = config(
            vec![
                provider("a", vec![limited]),
                provider("b", vec![key("kb", &["m"])]),
            ],
            vec![route("m", &["a", "b"])],
        );
        let broker = Broker::from_config(&cfg).unwrap();
        let exclude = HashSet::new();
        assert_eq!(broker.select(Some("m"), &exclude, 0).unwrap().provider, "a");
        // `a` is now rate limited, so the request must fail over to `b`.
        let second = broker.select(Some("m"), &exclude, 0).unwrap();
        assert_eq!(second.provider, "b");
    }

    #[test]
    fn no_keys_at_all_reports_no_keys() {
        let cfg = config(vec![provider("empty", vec![])], vec![]);
        let broker = Broker::from_config(&cfg).unwrap();
        let error = broker
            .select(Some("gpt-4"), &HashSet::new(), 0)
            .unwrap_err();
        assert!(matches!(error, RouteError::NoKeys { .. }), "got {error:?}");
    }

    #[test]
    fn route_views_expose_compiled_routes() {
        let cfg = config(
            vec![provider("a", vec![key("ka", &[])])],
            vec![route("gpt-*", &["a"])],
        );
        let broker = Broker::from_config(&cfg).unwrap();
        let views = broker.routes();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].pattern, "gpt-*");
        assert_eq!(views[0].providers, vec!["a".to_string()]);
    }

    #[test]
    fn model_rewrite_flag_is_visible() {
        let mut rewrite_route = route("fast", &["a"]);
        rewrite_route.rewrite = true;
        let cfg = config(
            vec![provider("a", vec![key("ka", &[])])],
            vec![rewrite_route],
        );
        let broker = Broker::from_config(&cfg).unwrap();
        assert!(broker.rewrites_model(Some("fast")));
        assert!(!broker.rewrites_model(Some("other")));
    }

    #[test]
    fn strategy_override_per_route() {
        let mut pinned = route("m", &["a"]);
        pinned.strategy = Some("least_busy".into());
        let cfg = config(vec![provider("a", vec![key("ka", &[])])], vec![pinned]);
        let broker = Broker::from_config(&cfg).unwrap();
        assert_eq!(broker.strategy_for_model(Some("m")), Strategy::LeastBusy);
        assert_eq!(broker.strategy_for_model(Some("x")), Strategy::RoundRobin);
    }
}
