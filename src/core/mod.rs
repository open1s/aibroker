//! Framework-independent broker core.
//!
//! Everything in here is free of HTTP/proxy concerns: key state, rate limits,
//! selection strategies, routing and metrics. The pingora backend is a thin
//! adapter over these types, which keeps the load-balancing logic testable
//! without a network.

pub mod api;
pub mod auth;
pub mod broker;
pub mod content;
pub mod key_state;
pub mod metrics;
pub mod pattern;
pub mod policy;
pub mod pool;
pub mod ratelimit;
pub mod runtime;
pub mod security;
pub mod strategy;

pub use api::ApiFormat;
pub use broker::{Broker, RouteError, SelectedKey};
pub use content::{ContentGuard, Finding, GuardAction};
pub use key_state::{CooldownPolicy, HealthState, HealthTuning, KeyState, Outcome, TokenUsage};
pub use policy::{PolicyDecision, PolicyEngine, PolicySource, RequestFacts};
pub use pool::{KeyPool, KeyStatus, SelectError};
pub use runtime::{Runtime, SharedRuntime};
pub use security::{ClientAccess, ClientDecision, ClientRegistry, ClientStatus, DenyReason};
pub use strategy::Strategy;
