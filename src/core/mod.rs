//! Framework-independent broker core.
//!
//! Everything in here is free of HTTP/proxy concerns: key state, rate limits,
//! selection strategies, routing and metrics. The pingora backend is a thin
//! adapter over these types, which keeps the load-balancing logic testable
//! without a network.

pub mod auth;
pub mod broker;
pub mod key_state;
pub mod metrics;
pub mod pool;
pub mod ratelimit;
pub mod runtime;
pub mod strategy;

pub use broker::{Broker, RouteError, SelectedKey};
pub use key_state::{CooldownPolicy, HealthState, HealthTuning, KeyState, Outcome, TokenUsage};
pub use pool::{KeyPool, KeyStatus, SelectError};
pub use runtime::{Runtime, SharedRuntime};
pub use strategy::Strategy;
