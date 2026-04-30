use thiserror::Error;

#[derive(Error, Debug)]
pub enum LlmBrokerError {
    #[error("No available keys for provider {0}")]
    NoKeysAvailable(String),

    #[error("All keys in cooldown for provider {0}")]
    AllKeysInCooldown(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, LlmBrokerError>;
