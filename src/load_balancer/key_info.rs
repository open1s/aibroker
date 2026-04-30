use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Provider {
    OpenAI,
    Anthropic,
    Azure,
    Vertex,
    DeepSeek,
    MiniMax,
    OpenRouter,
    GLM,
    NVIDIA,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub enum RotationStrategy {
    #[default]
    RoundRobin,
    WeightedRandom,
    LeastUsed,
    LatencyBased,
}

pub struct KeyInfo {
    pub id: String,
    pub key: String,
    pub provider: Provider,
    pub models: Vec<String>,
    pub weight: u32,
    pub base_url: Option<String>,
    pub max_rpm: Option<u32>,
    usage_count: Arc<AtomicU64>,
    cooldown_until: parking_lot::RwLock<Option<Instant>>,
    last_used: parking_lot::RwLock<Option<Instant>>,
    rate_limit_window: parking_lot::RwLock<Instant>,
    requests_in_window: parking_lot::RwLock<u32>,
}

impl KeyInfo {
    pub fn new(id: String, key: String, provider: Provider) -> Self {
        Self {
            id,
            key,
            provider,
            models: Vec::new(),
            weight: 1,
            base_url: None,
            max_rpm: None,
            usage_count: Arc::new(AtomicU64::new(0)),
            cooldown_until: parking_lot::RwLock::new(None),
            last_used: parking_lot::RwLock::new(None),
            rate_limit_window: parking_lot::RwLock::new(Instant::now()),
            requests_in_window: parking_lot::RwLock::new(0),
        }
    }

    pub fn with_models(mut self, models: Vec<String>) -> Self {
        self.models = models;
        self
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn with_base_url(mut self, base_url: Option<String>) -> Self {
        self.base_url = base_url;
        self
    }

    pub fn with_max_rpm(mut self, max_rpm: Option<u32>) -> Self {
        self.max_rpm = max_rpm;
        self
    }

    pub fn is_available(&self) -> bool {
        let cooldown = self.cooldown_until.read();
        if matches!(*cooldown, Some(instant) if instant > Instant::now()) {
            return false;
        }
        self.check_rate_limit()
    }

    pub fn is_available_for_model(&self, model: &str) -> bool {
        self.is_available() && (self.models.is_empty() || self.models.iter().any(|m| m == model))
    }

    pub fn mark_used(&self) {
        self.usage_count.fetch_add(1, Ordering::Relaxed);
        *self.last_used.write() = Some(Instant::now());
    }

    pub fn usage_count(&self) -> u64 {
        self.usage_count.load(Ordering::Relaxed)
    }

    pub fn set_cooldown(&self, duration: Duration) {
        let cooldown = Duration::from_secs(60).min(duration * 2);
        *self.cooldown_until.write() = Some(Instant::now() + cooldown);
    }

    pub fn clear_cooldown(&self) {
        *self.cooldown_until.write() = None;
    }

    pub fn cooldown_remaining(&self) -> Option<Duration> {
        let cooldown = self.cooldown_until.read();
        cooldown
            .map(|instant| instant.saturating_duration_since(Instant::now()))
            .filter(|d| !d.is_zero())
    }

    pub fn check_rate_limit(&self) -> bool {
        let Some(max_rpm) = self.max_rpm else {
            return true;
        };

        let mut window = self.rate_limit_window.write();
        let mut count = self.requests_in_window.write();
        let now = Instant::now();

        if now.duration_since(*window).as_secs() >= 60 {
            *window = now;
            *count = 0;
        }

        if *count >= max_rpm {
            return false;
        }

        *count += 1;
        true
    }

    pub fn is_rate_limited(&self) -> bool {
        let Some(max_rpm) = self.max_rpm else {
            return false;
        };

        let window = self.rate_limit_window.read();
        let count = self.requests_in_window.read();
        let now = Instant::now();

        if now.duration_since(*window).as_secs() >= 60 {
            return false;
        }

        *count >= max_rpm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_available_when_not_in_cooldown() {
        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI);
        assert!(key.is_available());
    }

    #[test]
    fn test_key_unavailable_during_cooldown() {
        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI);
        key.set_cooldown(Duration::from_secs(60));
        assert!(!key.is_available());
    }

    #[test]
    fn test_model_filtering() {
        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI)
            .with_models(vec!["gpt-4".to_string(), "gpt-3.5-turbo".to_string()]);

        assert!(key.is_available_for_model("gpt-4"));
        assert!(key.is_available_for_model("gpt-3.5-turbo"));
        assert!(!key.is_available_for_model("claude-3"));
    }

    #[test]
    fn test_empty_model_list_accepts_all() {
        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI);
        assert!(key.is_available_for_model("any-model"));
    }

    #[test]
    fn test_check_rate_limit_allows_requests_under_limit() {
        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI)
            .with_max_rpm(Some(5));

        for i in 1..=5 {
            assert!(
                key.check_rate_limit(),
                "Request {} should be allowed (limit is 5)",
                i
            );
        }
    }

    #[test]
    fn test_check_rate_limit_blocks_requests_over_limit() {
        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI)
            .with_max_rpm(Some(3));

        key.check_rate_limit();
        key.check_rate_limit();
        key.check_rate_limit();

        assert!(
            !key.check_rate_limit(),
            "Request 4 should be blocked (limit is 3)"
        );
        assert!(!key.check_rate_limit(), "Request 5 should also be blocked");
    }

    #[test]
    fn test_is_rate_limited_does_not_increment() {
        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI)
            .with_max_rpm(Some(2));

        assert!(
            !key.is_rate_limited(),
            "Should not be rate limited initially"
        );

        assert!(
            !key.is_rate_limited(),
            "Calling is_rate_limited should not increment"
        );
        assert!(
            !key.is_rate_limited(),
            "Calling is_rate_limited should not increment"
        );

        let available = key.check_rate_limit();
        let available2 = key.check_rate_limit();
        assert!(
            available && available2,
            "Should still have 2 requests available"
        );
    }

    #[test]
    fn test_no_max_rpm_means_never_rate_limited() {
        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI);

        assert!(
            !key.is_rate_limited(),
            "Key without max_rpm should not be rate limited"
        );
        assert!(
            key.check_rate_limit(),
            "check_rate_limit should always return true without max_rpm"
        );
    }

    #[test]
    fn test_rate_limit_tracks_per_key_independently() {
        let key1 = KeyInfo::new("key1".to_string(), "sk-xxx1".to_string(), Provider::OpenAI)
            .with_max_rpm(Some(2));
        let key2 = KeyInfo::new("key2".to_string(), "sk-xxx2".to_string(), Provider::OpenAI)
            .with_max_rpm(Some(5));

        key1.check_rate_limit();
        key1.check_rate_limit();
        key2.check_rate_limit();
        key2.check_rate_limit();
        key2.check_rate_limit();

        assert!(
            key1.is_rate_limited(),
            "key1 (limit 2) should be rate limited after 2 requests"
        );
        assert!(
            !key2.is_rate_limited(),
            "key2 (limit 5) should not be rate limited after 3 requests"
        );

        assert!(!key1.check_rate_limit(), "key1 should be blocked");
        assert!(
            key2.check_rate_limit(),
            "key2 should allow one more request"
        );
    }

    #[test]
    fn test_rate_limit_window_resets_on_expire() {
        use crate::load_balancer::KeyPool;

        let key = KeyInfo::new("test".to_string(), "sk-xxx".to_string(), Provider::OpenAI)
            .with_max_rpm(Some(2));

        key.check_rate_limit();
        key.check_rate_limit();
        assert!(
            key.is_rate_limited(),
            "Should be rate limited after 2 requests"
        );

        let mut pool = KeyPool::new(Provider::OpenAI);
        pool.add_key(key);
        let reset_key = pool.keys().first().unwrap();
        use std::sync::Arc;
        let key_arc = Arc::clone(reset_key);
        drop(pool);

        {
            let mut window = key_arc.rate_limit_window.write();
            let mut count = key_arc.requests_in_window.write();
            *window = Instant::now() - Duration::from_secs(61);
            *count = 2;
        }

        assert!(
            !key_arc.is_rate_limited(),
            "Should not be rate limited after window expires"
        );
        assert!(
            key_arc.check_rate_limit(),
            "check_rate_limit should allow request after window reset"
        );
    }
}
