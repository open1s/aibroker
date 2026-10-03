use thiserror::Error;

/// Errors raised by the broker's own layers.
///
/// HTTP-facing failures are represented by the `RouteError` / `SelectError`
/// types in [`crate::core`]; this enum covers configuration, persistence and
/// administrative failures.
#[derive(Error, Debug)]
pub enum LlmBrokerError {
    /// Configuration could not be parsed, validated or persisted.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// A referenced key does not exist.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// A referenced provider does not exist.
    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    /// The admin API refused the caller.
    #[error("admin authentication failed: {0}")]
    AdminAuth(String),

    /// A management operation was rejected by validation.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// An underlying I/O failure.
    #[error("io error: {0}")]
    Io(String),

    /// A serialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<std::io::Error> for LlmBrokerError {
    fn from(error: std::io::Error) -> Self {
        LlmBrokerError::Io(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, LlmBrokerError>;
