use serde::Deserialize;
use std::path::Path;

use crate::load_balancer::LoadBalancer;
use crate::load_balancer::key_info::{KeyInfo, Provider, RotationStrategy};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub proxy_type: Option<String>,
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub load_balancing: LoadBalancingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub threads: Option<usize>,
    #[serde(default)]
    pub daemon: bool,
    #[serde(default)]
    pub pid_file: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    #[serde(default)]
    pub base_url: Option<String>,
    pub api_keys: Vec<ApiKeyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyConfig {
    pub id: String,
    pub key: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub max_rpm: Option<u32>,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LoadBalancingConfig {
    #[serde(default)]
    pub strategy: String,
    #[serde(default = "default_cooldown")]
    pub initial_cooldown_secs: u64,
}

fn default_cooldown() -> u64 {
    60
}

impl ServerConfig {
    pub fn to_pingora_conf(&self) -> pingora::server::configuration::ServerConf {
        use pingora::server::configuration::ServerConf;

        let mut conf = ServerConf::default();

        if let Some(threads) = self.threads {
            conf.threads = threads;
        }

        if self.daemon {
            conf.daemon = self.daemon;
        }

        if let Some(ref pid_file) = self.pid_file
            && !pid_file.is_empty() {
                conf.pid_file = pid_file.clone();
            }

        if let Some(ref user) = self.user
            && !user.is_empty() {
                conf.user = Some(user.clone());
            }

        if let Some(ref group) = self.group
            && !group.is_empty() {
                conf.group = Some(group.clone());
            }

        conf
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    pub fn load_balancer(&self) -> LoadBalancer {
        let strategy = match self.load_balancing.strategy.to_lowercase().as_str() {
            "weighted_random" => RotationStrategy::WeightedRandom,
            "least_used" => RotationStrategy::LeastUsed,
            "latency_based" => RotationStrategy::LatencyBased,
            _ => RotationStrategy::RoundRobin,
        };

        let mut lb = LoadBalancer::new().with_strategy(strategy);

        for provider_config in &self.providers {
            let provider = match provider_config.name.to_lowercase().as_str() {
                "openai" => Provider::OpenAI,
                "anthropic" => Provider::Anthropic,
                "azure" => Provider::Azure,
                "vertex" => Provider::Vertex,
                "deepseek" => Provider::DeepSeek,
                "minimax" => Provider::MiniMax,
                "openrouter" => Provider::OpenRouter,
                "glm" => Provider::GLM,
                "nvidia" => Provider::NVIDIA,
                _ => Provider::Other,
            };

            let pool = lb.get_or_create_pool(provider.clone());

            for key_config in &provider_config.api_keys {
                let mut key = KeyInfo::new(
                    key_config.id.clone(),
                    key_config.key.clone(),
                    provider.clone(),
                )
                .with_weight(key_config.weight)
                .with_base_url(provider_config.base_url.clone())
                .with_max_rpm(key_config.max_rpm);

                if !key_config.models.is_empty() {
                    key = key.with_models(key_config.models.clone());
                }

                pool.add_key(key);
            }
        }

        lb
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let config_str = r#"
[server]
host = "0.0.0.0"
port = 8080

[[providers]]
name = "openai"

[[providers.api_keys]]
id = "key1"
key = "sk-test123"
models = ["gpt-4", "gpt-3.5-turbo"]
weight = 2

[load_balancing]
strategy = "round_robin"
initial_cooldown_secs = 60
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].api_keys.len(), 1);
    }
}
