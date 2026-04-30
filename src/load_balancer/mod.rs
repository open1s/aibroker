pub mod key_info;

use crate::error::{LlmBrokerError, Result};
use crate::load_balancer::key_info::{KeyInfo, Provider, RotationStrategy};
use std::collections::HashMap;
use std::sync::Arc;

pub struct KeyPool {
    provider: Provider,
    keys: Vec<Arc<KeyInfo>>,
    strategy: RotationStrategy,
    current_index: std::sync::atomic::AtomicUsize,
}

impl KeyPool {
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
            keys: Vec::new(),
            strategy: RotationStrategy::default(),
            current_index: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn with_strategy(mut self, strategy: RotationStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn add_key(&mut self, key: KeyInfo) {
        self.keys.push(Arc::new(key));
    }

    pub fn provider(&self) -> &Provider {
        &self.provider
    }

    pub fn strategy(&self) -> &RotationStrategy {
        &self.strategy
    }

    pub fn keys(&self) -> &[Arc<KeyInfo>] {
        &self.keys
    }

    pub fn available_keys(&self) -> Vec<Arc<KeyInfo>> {
        self.keys
            .iter()
            .filter(|k| k.is_available())
            .cloned()
            .collect()
    }

    pub fn available_keys_for_model(&self, model: &str) -> Vec<Arc<KeyInfo>> {
        self.keys
            .iter()
            .filter(|k| k.is_available_for_model(model))
            .cloned()
            .collect()
    }

    pub fn rate_limited_keys(&self) -> Vec<Arc<KeyInfo>> {
        self.keys
            .iter()
            .filter(|k| k.is_rate_limited())
            .cloned()
            .collect()
    }

    pub fn has_rate_limited_keys(&self) -> bool {
        self.keys.iter().any(|k| k.is_rate_limited())
    }

    pub fn all_keys_rate_limited(&self) -> bool {
        !self.keys.is_empty() && self.keys.iter().all(|k| k.is_rate_limited())
    }

    pub fn all_keys_unavailable(&self) -> bool {
        !self.keys.is_empty() && self.keys.iter().all(|k| !k.is_available())
    }

    pub fn select_key(&self, model: Option<&str>) -> Result<Arc<KeyInfo>> {
        let candidates = match model {
            Some(m) => self.available_keys_for_model(m),
            None => self.available_keys(),
        };

        if candidates.is_empty() {
            return Err(LlmBrokerError::NoKeysAvailable(format!(
                "{:?}",
                self.provider
            )));
        }

        let key = match self.strategy {
            RotationStrategy::RoundRobin => self.select_round_robin(&candidates),
            RotationStrategy::WeightedRandom => self.select_weighted_random(&candidates),
            RotationStrategy::LeastUsed => self.select_least_used(&candidates),
            RotationStrategy::LatencyBased => self.select_round_robin(&candidates),
        };

        key.mark_used();
        Ok(key)
    }

    fn select_round_robin(&self, candidates: &[Arc<KeyInfo>]) -> Arc<KeyInfo> {
        let idx = self
            .current_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        candidates[idx % candidates.len()].clone()
    }

    fn select_weighted_random(&self, candidates: &[Arc<KeyInfo>]) -> Arc<KeyInfo> {
        let total_weight: u32 = candidates.iter().map(|k| k.weight).sum();
        let mut rng = rand_u32() % total_weight;

        for key in candidates {
            if rng < key.weight {
                return key.clone();
            }
            rng -= key.weight;
        }

        candidates[0].clone()
    }

    fn select_least_used(&self, candidates: &[Arc<KeyInfo>]) -> Arc<KeyInfo> {
        candidates
            .iter()
            .min_by_key(|k| k.usage_count())
            .unwrap()
            .clone()
    }

    pub fn mark_key_failed(&self, key_id: &str, cooldown_duration: std::time::Duration) {
        if let Some(key) = self.keys.iter().find(|k| k.id == key_id) {
            key.set_cooldown(cooldown_duration);
        }
    }
}

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    nanos.wrapping_mul(1103515245).wrapping_add(12345)
}

pub struct LoadBalancer {
    pools: HashMap<Provider, KeyPool>,
    default_strategy: RotationStrategy,
}

impl LoadBalancer {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
            default_strategy: RotationStrategy::default(),
        }
    }

    pub fn with_strategy(mut self, strategy: RotationStrategy) -> Self {
        self.default_strategy = strategy;
        self
    }

    pub fn get_or_create_pool(&mut self, provider: Provider) -> &mut KeyPool {
        self.pools
            .entry(provider.clone())
            .or_insert_with(|| KeyPool::new(provider).with_strategy(self.default_strategy))
    }

    pub fn pool(&self, provider: &Provider) -> Option<&KeyPool> {
        self.pools.get(provider)
    }

    pub fn pools(&self) -> &HashMap<Provider, KeyPool> {
        &self.pools
    }

    pub fn select_key(&self, provider: &Provider, model: Option<&str>) -> Result<Arc<KeyInfo>> {
        self.pools
            .get(provider)
            .ok_or_else(|| LlmBrokerError::NoKeysAvailable(format!("{:?}", provider)))?
            .select_key(model)
    }

    pub fn mark_failure(&self, provider: &Provider, key_id: &str, cooldown: std::time::Duration) {
        if let Some(pool) = self.pools.get(provider) {
            pool.mark_key_failed(key_id, cooldown);
        }
    }
}

impl Default for LoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin_selection() {
        let mut pool = KeyPool::new(Provider::OpenAI).with_strategy(RotationStrategy::RoundRobin);
        pool.add_key(KeyInfo::new(
            "key1".to_string(),
            "sk-xxx1".to_string(),
            Provider::OpenAI,
        ));
        pool.add_key(KeyInfo::new(
            "key2".to_string(),
            "sk-xxx2".to_string(),
            Provider::OpenAI,
        ));

        let key1 = pool.select_key(None).unwrap();
        let key2 = pool.select_key(None).unwrap();
        let key3 = pool.select_key(None).unwrap();

        assert_eq!(key1.id, "key1");
        assert_eq!(key2.id, "key2");
        assert_eq!(key3.id, "key1");
    }

    #[test]
    fn test_least_used_skips_busy_key() {
        let mut pool = KeyPool::new(Provider::OpenAI).with_strategy(RotationStrategy::LeastUsed);
        pool.add_key(KeyInfo::new(
            "key1".to_string(),
            "sk-xxx1".to_string(),
            Provider::OpenAI,
        ));
        pool.add_key(KeyInfo::new(
            "key2".to_string(),
            "sk-xxx2".to_string(),
            Provider::OpenAI,
        ));

        pool.mark_key_failed("key1", std::time::Duration::from_secs(60));

        let key = pool.select_key(None).unwrap();
        assert_eq!(
            key.id, "key2",
            "least_used should skip key1 which is in cooldown"
        );
    }

    #[test]
    fn test_no_available_keys_error() {
        let pool = KeyPool::new(Provider::OpenAI);
        let result = pool.select_key(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_keys_rate_limited() {
        let mut pool = KeyPool::new(Provider::OpenAI);
        pool.add_key(
            KeyInfo::new("key1".to_string(), "sk-xxx1".to_string(), Provider::OpenAI)
                .with_max_rpm(Some(2)),
        );

        assert!(
            !pool.all_keys_rate_limited(),
            "Should not be rate limited initially"
        );

        pool.select_key(None).unwrap();
        pool.select_key(None).unwrap();

        assert!(
            pool.all_keys_rate_limited(),
            "After 2 requests, key should be rate limited (count=2, max=2)"
        );

        let result = pool.select_key(None);
        assert!(
            result.is_err(),
            "3rd request should fail - key rate limited"
        );
    }

    #[test]
    fn test_all_keys_unavailable_due_to_rate_limit() {
        let mut pool = KeyPool::new(Provider::OpenAI);
        pool.add_key(
            KeyInfo::new("key1".to_string(), "sk-xxx1".to_string(), Provider::OpenAI)
                .with_max_rpm(Some(2)),
        );

        pool.select_key(None).unwrap();
        pool.select_key(None).unwrap();
        assert!(
            pool.all_keys_unavailable(),
            "Key should be unavailable due to rate limit"
        );
        assert!(
            pool.all_keys_rate_limited(),
            "Key should also show as rate limited"
        );

        let result = pool.select_key(None);
        assert!(
            result.is_err(),
            "select_key should fail when all keys rate limited"
        );
    }
}
