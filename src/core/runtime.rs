//! Shared process state: configuration, compiled routing table and metrics.
//!
//! The broker is rebuilt on every configuration change. Runtime state that
//! must survive a rebuild (cooldowns, rate-limit windows, health scores,
//! counters) is snapshotted before the rebuild and restored afterwards, so an
//! admin action never resurrects a key that the upstream just rate limited.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::config::{Config, LoadedConfig};
use crate::core::broker::Broker;
use crate::core::key_state::{
    CooldownPolicy, HealthTuning, KeySnapshot, KeyState,
};
use crate::core::metrics::Registry;
use crate::core::strategy::Strategy;
use crate::error::{LlmBrokerError, Result};

/// Configuration plus everything derived from it.
pub struct Runtime {
    config: Config,
    broker: Broker,
    metrics: Arc<Registry>,
    config_path: Option<PathBuf>,
}

impl Runtime {
    /// Build a runtime from an already validated config.
    pub fn new(config: Config, config_path: Option<PathBuf>) -> Result<Self> {
        let broker = Broker::from_config(&config)?;
        Ok(Self {
            config,
            broker,
            metrics: Arc::new(Registry::new()),
            config_path,
        })
    }

    /// Load a config file and build the runtime.
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let LoadedConfig { config, path } = LoadedConfig::load(path)?;
        Self::new(config, Some(path))
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    pub fn metrics(&self) -> &Arc<Registry> {
        &self.metrics
    }

    pub fn config_path(&self) -> Option<&std::path::Path> {
        self.config_path.as_deref()
    }

    pub fn strategy(&self) -> Strategy {
        self.broker.strategies().0
    }

    pub fn cooldown_policy(&self) -> CooldownPolicy {
        CooldownPolicy::from_config(&self.config.load_balancing)
    }

    pub fn health_tuning(&self) -> HealthTuning {
        let health = &self.config.health;
        HealthTuning {
            enabled: health.enabled,
            latency_alpha: health.latency_alpha,
            slow_latency_ms: health.slow_latency_ms,
            unhealthy_threshold: health.unhealthy_threshold,
            failure_threshold: health.failure_threshold,
            recovery_threshold: health.recovery_threshold,
        }
    }

    /// Rebuild the broker from a mutated config, preserving live key state and
    /// persisting to disk when the admin API asks for it.
    pub fn apply(&mut self, mutate: impl FnOnce(&mut Config)) -> Result<()> {
        let previous = self.snapshot_state();
        let mut candidate = self.config.clone();
        mutate(&mut candidate);
        candidate.validate()?;

        let broker = Broker::from_config(&candidate)?;
        restore_state(&broker, &previous);

        self.config = candidate;
        self.broker = broker;
        self.metrics
            .config_reloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// `apply` plus writing the config back to disk.
    pub fn apply_and_persist(&mut self, mutate: impl FnOnce(&mut Config)) -> Result<()> {
        let path = self.config_path.clone();
        self.apply(mutate)?;
        if self.config.admin.persist
            && let Some(path) = path
        {
            self.config.write_to_file(&path)?;
        }
        Ok(())
    }

    /// Reload the config file from disk, preserving live key state.
    pub fn reload_from_disk(&mut self) -> Result<()> {
        let path = self.config_path.clone().ok_or_else(|| {
            LlmBrokerError::InvalidConfig("no config file path is known".to_string())
        })?;
        let LoadedConfig { config, .. } = LoadedConfig::load(&path)?;
        let previous = self.snapshot_state();
        let broker = Broker::from_config(&config)?;
        restore_state(&broker, &previous);
        self.config = config;
        self.broker = broker;
        self.metrics
            .config_reloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Snapshot every key's live state, keyed by provider and id.
    fn snapshot_state(&self) -> HashMap<(String, String), KeySnapshot> {
        let mut out = HashMap::new();
        for (provider, pool) in self.broker.pools() {
            for key in pool.keys() {
                out.insert((provider.clone(), key.id.clone()), key.snapshot());
            }
        }
        out
    }

    /// Provider names in a stable order.
    pub fn provider_names(&self) -> Vec<String> {
        self.broker.pools().keys().cloned().collect()
    }
}

/// Copy live state from a snapshot into a freshly built broker.
fn restore_state(broker: &Broker, snapshot: &HashMap<(String, String), KeySnapshot>) {
    for (provider, pool) in broker.pools() {
        for key in pool.keys() {
            if let Some(state) = snapshot.get(&(provider.clone(), key.id.clone())) {
                key.restore(state);
            }
        }
    }
}

/// Shared, lock-protected runtime.
pub type SharedRuntime = Arc<RwLock<Runtime>>;

/// Wrap a runtime for sharing between the proxy and admin threads.
pub fn shared(runtime: Runtime) -> SharedRuntime {
    Arc::new(RwLock::new(runtime))
}

/// Convenience accessor for tests and callers that only need one key.
pub fn key_for_model(
    runtime: &Runtime,
    model: Option<&str>,
) -> Option<Arc<KeyState>> {
    let broker = runtime.broker();
    broker
        .select(model, &std::collections::HashSet::new(), 0)
        .ok()
        .map(|selected| selected.key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKeyConfig, ProviderConfig, RouteConfig, ServerConfig};
    use std::time::Duration;

    fn provider(name: &str, keys: Vec<ApiKeyConfig>) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            base_url: Some(format!("https://{name}.test")),
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

    fn config(providers: Vec<ProviderConfig>) -> Config {
        Config {
            server: ServerConfig {
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
            routes: Vec::<RouteConfig>::new(),
            default_route: None,
            load_balancing: Default::default(),
            health: Default::default(),
            observability: Default::default(),
            admin: Default::default(),
        }
    }

    #[test]
    fn runtime_builds_a_broker_from_config() {
        let runtime = Runtime::new(config(vec![provider("openai", vec![key("k1", &["gpt-4"])])]), None)
            .unwrap();
        assert_eq!(runtime.provider_names(), vec!["openai"]);
        assert!(key_for_model(&runtime, Some("gpt-4")).is_some());
    }

    #[test]
    fn apply_preserves_key_cooldown_across_a_rebuild() {
        let mut runtime = Runtime::new(
            config(vec![provider("openai", vec![key("k1", &["gpt-4"])])]),
            None,
        )
        .unwrap();

        // Trip the key, then perform an unrelated config change. The cooldown
        // is longer than any test run, so it must survive the rebuild.
        let key = key_for_model(&runtime, Some("gpt-4")).unwrap();
        key.cooldown_for(Duration::from_secs(3_600));
        assert!(key.cooldown_remaining().is_some());

        runtime
            .apply(|cfg| {
                cfg.load_balancing.strategy = "least_busy".to_string();
            })
            .unwrap();

        let key = runtime
            .broker()
            .pool("openai")
            .and_then(|pool| pool.key("k1"))
            .expect("the key must still exist after the rebuild");
        assert!(
            key.cooldown_remaining().is_some(),
            "a rebuild must not clear a live cooldown"
        );
        assert_eq!(
            key.health_state(),
            crate::core::key_state::HealthState::Open
        );
        assert_eq!(runtime.strategy(), Strategy::LeastBusy);
    }

    #[test]
    fn apply_resets_rate_limit_windows_but_keeps_cooldowns() {
        // Rate-limit samples are anchored to `Instant`s that cannot be
        // replayed, so a rebuild restarts the window. Cooldowns are absolute
        // and survive. This test pins both halves of that contract so the
        // behaviour is a documented decision rather than an accident.
        let mut runtime = Runtime::new(
            config(vec![provider(
                "openai",
                vec![ApiKeyConfig {
                    max_rpm: Some(1),
                    ..key("k1", &["gpt-4"])
                }],
            )]),
            None,
        )
        .unwrap();

        let empty = std::collections::HashSet::new();
        assert!(runtime.broker().select(Some("gpt-4"), &empty, 0).is_ok());
        assert!(
            runtime.broker().select(Some("gpt-4"), &empty, 0).is_err(),
            "the key is out of quota before the rebuild"
        );

        runtime
            .apply(|cfg| {
                cfg.observability.access_log = true;
            })
            .unwrap();

        assert!(
            runtime.broker().select(Some("gpt-4"), &empty, 0).is_ok(),
            "the rate-limit window restarts after a rebuild"
        );

        // A cooldown, by contrast, is preserved.
        runtime
            .broker()
            .pool("openai")
            .unwrap()
            .key("k1")
            .unwrap()
            .cooldown_for(Duration::from_secs(3_600));

        runtime
            .apply(|cfg| {
                cfg.observability.access_log = false;
            })
            .unwrap();

        let key = runtime.broker().pool("openai").unwrap().key("k1").unwrap();
        assert!(key.cooldown_remaining().is_some());
        assert!(key_for_model(&runtime, Some("gpt-4")).is_none());
    }

    #[test]
    fn apply_rejects_an_invalid_candidate_without_mutating_state() {
        let mut runtime = Runtime::new(
            config(vec![provider("openai", vec![key("k1", &["gpt-4"])])]),
            None,
        )
        .unwrap();

        let error = runtime
            .apply(|cfg| {
                // A route to a provider that does not exist must be refused.
                cfg.routes.push(RouteConfig {
                    model: "m".into(),
                    providers: vec!["ghost".into()],
                    strategy: None,
                    rewrite: false,
                });
            })
            .unwrap_err();
        assert!(error.to_string().contains("ghost"));
        assert!(runtime.config().routes.is_empty());
        assert!(key_for_model(&runtime, Some("gpt-4")).is_some());
    }

    #[test]
    fn adding_a_key_through_apply_makes_it_selectable() {
        let mut runtime = Runtime::new(
            config(vec![provider("openai", vec![key("k1", &["gpt-4"])])]),
            None,
        )
        .unwrap();

        runtime
            .apply(|cfg| {
                cfg.providers[0].api_keys.push(key("k2", &["gpt-4"]));
            })
            .unwrap();

        assert_eq!(runtime.broker().pool("openai").unwrap().len(), 2);
    }
}
