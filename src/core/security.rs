//! Client authentication, egress access control and audit classification.
//!
//! Request balancing decides *which* upstream key serves a request. This module
//! decides whether the request may leave the machine at all, and on whose
//! behalf — the data-security half of the broker.
//!
//! Three questions are answered per request:
//!
//! 1. **Who is calling?** A token identifies a named client. Tokens are
//!    compared in constant time and are never logged.
//! 2. **May they send this?** Each client carries allow-lists for models and
//!    providers. A request for anything else is refused *before* it is
//!    forwarded, so disallowed content never reaches a provider.
//! 3. **How much may they send?** An optional per-client RPM and concurrency
//!    budget stops one runaway client from consuming the whole pool.
//!
//! With no `[[clients]]` configured the proxy stays open, which keeps the
//! single-user setup working and is reported by `/admin/status` so an operator
//! can see that it is unauthenticated rather than assume otherwise.

use std::collections::HashMap;
use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::ClientConfig;
use crate::core::ratelimit::{Admit, RateLimiter};

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyReason {
    /// No credential was presented and clients are configured.
    MissingCredential,
    /// The credential does not match any configured client.
    UnknownCredential,
    /// The client is configured but disabled.
    ClientDisabled,
    /// The model is outside the client's allow-list.
    ModelForbidden,
    /// The provider is outside the client's allow-list.
    ProviderForbidden,
    /// The client exceeded its request budget.
    RateLimited,
    /// The client exceeded its concurrency budget.
    TooManyInFlight,
    /// The policy engine failed; traffic is refused rather than forwarded.
    PolicyError,
    /// The request body matched a configured content rule.
    ContentForbidden,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::MissingCredential => "missing_credential",
            DenyReason::UnknownCredential => "unknown_credential",
            DenyReason::ClientDisabled => "client_disabled",
            DenyReason::ModelForbidden => "model_forbidden",
            DenyReason::ProviderForbidden => "provider_forbidden",
            DenyReason::RateLimited => "rate_limited",
            DenyReason::TooManyInFlight => "too_many_in_flight",
            DenyReason::PolicyError => "policy_error",
            DenyReason::ContentForbidden => "content_forbidden",
        }
    }

    /// HTTP status to answer with.
    pub fn status(self) -> u16 {
        match self {
            DenyReason::MissingCredential | DenyReason::UnknownCredential => 401,
            DenyReason::ClientDisabled
            | DenyReason::ModelForbidden
            | DenyReason::ProviderForbidden => 403,
            DenyReason::RateLimited | DenyReason::TooManyInFlight => 429,
            DenyReason::PolicyError => 500,
            DenyReason::ContentForbidden => 403,
        }
    }

    /// Whether the caller may retry the same request later.
    pub fn retryable(self) -> bool {
        matches!(self, DenyReason::RateLimited | DenyReason::TooManyInFlight)
    }

    /// A message safe to return to the caller.
    ///
    /// Deliberately vague for credential failures: telling a caller whether a
    /// token exists is a probing oracle.
    pub fn message(self) -> &'static str {
        match self {
            DenyReason::MissingCredential => "a client token is required",
            DenyReason::UnknownCredential => "invalid client token",
            DenyReason::ClientDisabled => "this client is disabled",
            DenyReason::ModelForbidden => "this client may not use that model",
            DenyReason::ProviderForbidden => "this client may not use that provider",
            DenyReason::RateLimited => "client request budget exhausted",
            DenyReason::TooManyInFlight => "client concurrency budget exhausted",
            DenyReason::PolicyError => "the egress policy could not be evaluated",
            DenyReason::ContentForbidden => "the request body matched a content rule",
        }
    }

    /// Whether the refusal is worth an audit line above the default level.
    pub fn is_security_event(self) -> bool {
        matches!(
            self,
            DenyReason::UnknownCredential | DenyReason::ClientDisabled
        )
    }
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A lookup failure, carrying the reason and a retry hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    pub reason: DenyReason,
    pub retry_after: Option<Duration>,
}

impl Denied {
    fn new(reason: DenyReason) -> Self {
        Self {
            reason,
            retry_after: None,
        }
    }
}

/// Compiled per-client rules and live counters.
pub struct ClientAccess {
    pub name: String,
    /// Literal token, already resolved from `env:`/`file:`.
    token: String,
    enabled: bool,
    allowed_models: Vec<String>,
    allowed_providers: Vec<String>,
    max_rpm: Option<u32>,
    max_tpm: Option<u64>,
    max_concurrency: Option<u32>,

    limiter: Mutex<RateLimiter>,
    in_flight: AtomicU64,
    /// Requests admitted, for `/admin/clients`.
    admitted: AtomicU64,
    denied: AtomicU64,
}

/// Snapshot for the admin API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientStatus {
    pub name: String,
    pub enabled: bool,
    pub allowed_models: Vec<String>,
    pub allowed_providers: Vec<String>,
    pub max_rpm: Option<u32>,
    pub max_tpm: Option<u64>,
    pub max_concurrency: Option<u32>,
    pub in_flight: u64,
    pub rpm: u64,
    pub tpm: u64,
    pub admitted: u64,
    pub denied: u64,
}

impl std::fmt::Debug for ClientAccess {
    /// Never prints the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAccess")
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("allowed_models", &self.allowed_models)
            .field("allowed_providers", &self.allowed_providers)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ClientRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRegistry")
            .field("clients", &self.clients)
            .finish()
    }
}

impl ClientAccess {
    /// Build a client from config, resolving its token.
    pub fn from_config(config: &ClientConfig) -> crate::error::Result<Self> {
        let token = crate::config::resolve_secret(&config.token)?;
        if token.trim().is_empty() {
            return Err(crate::error::LlmBrokerError::InvalidConfig(format!(
                "client `{}` has an empty token",
                config.name
            )));
        }
        Ok(Self {
            name: config.name.clone(),
            token,
            enabled: config.enabled,
            allowed_models: config.allowed_models.clone(),
            allowed_providers: config.allowed_providers.clone(),
            max_rpm: config.max_rpm,
            max_tpm: config.max_tpm,
            max_concurrency: config.max_concurrency,
            limiter: Mutex::new(RateLimiter::new()),
            in_flight: AtomicU64::new(0),
            admitted: AtomicU64::new(0),
            denied: AtomicU64::new(0),
        })
    }

    /// Whether a model name is permitted.
    ///
    /// An empty allow-list means "any model"; patterns may use `*`/`?` so a
    /// client can be scoped to a family (`claude-*`) instead of a moving list.
    pub fn allows_model(&self, model: Option<&str>) -> bool {
        if self.allowed_models.is_empty() {
            return true;
        }
        match model {
            Some(model) => self
                .allowed_models
                .iter()
                .any(|pattern| pattern_matches(pattern, model)),
            // An unknown model cannot be shown to be allowed.
            None => false,
        }
    }

    /// Whether a provider name is permitted.
    pub fn allows_provider(&self, provider: &str) -> bool {
        self.allowed_providers.is_empty()
            || self
                .allowed_providers
                .iter()
                .any(|pattern| pattern_matches(pattern, provider))
    }

    /// Whether this client may ever reach a provider, used for failover hints.
    pub fn allows_any_provider(&self) -> bool {
        true
    }

    /// Check and consume the request budget.
    pub fn admit(&self, estimated_tokens: u64) -> Result<(), Denied> {
        if !self.enabled {
            return Err(Denied::new(DenyReason::ClientDisabled));
        }

        if let Some(max) = self.max_concurrency
            && self.in_flight.load(Ordering::Relaxed) >= u64::from(max)
        {
            return Err(Denied::new(DenyReason::TooManyInFlight));
        }

        let now = Instant::now();
        let mut limiter = self.limiter.lock();
        match limiter.admit(now, self.max_rpm, self.max_tpm, estimated_tokens) {
            Admit::Ok => Ok(()),
            Admit::Limited { retry_after } => Err(Denied {
                reason: DenyReason::RateLimited,
                retry_after: Some(retry_after),
            }),
        }
    }

    /// Record that a request was admitted and is now in flight.
    pub fn begin(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.admitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Release an in-flight slot.
    pub fn end(&self) {
        let _ = self
            .in_flight
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    fn record_denied(&self) {
        self.denied.fetch_add(1, Ordering::Relaxed);
    }

    /// Live counters for the admin API.
    pub fn status(&self) -> ClientStatus {
        let now = Instant::now();
        let mut limiter = self.limiter.lock();
        ClientStatus {
            name: self.name.clone(),
            enabled: self.enabled,
            allowed_models: self.allowed_models.clone(),
            allowed_providers: self.allowed_providers.clone(),
            max_rpm: self.max_rpm,
            max_tpm: self.max_tpm,
            max_concurrency: self.max_concurrency,
            in_flight: self.in_flight.load(Ordering::Relaxed),
            rpm: limiter.rpm(now),
            tpm: limiter.tpm(now),
            admitted: self.admitted.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
        }
    }

    /// The configured token, for authentication only. Never log this.
    fn token(&self) -> &str {
        &self.token
    }

    pub fn allowed_models(&self) -> &[String] {
        &self.allowed_models
    }

    pub fn allowed_providers(&self) -> &[String] {
        &self.allowed_providers
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether a model name satisfies this client's allow-list.
    pub fn permits_model(&self, model: Option<&str>) -> bool {
        if self.allowed_models.is_empty() {
            return true;
        }
        match model {
            Some(model) => self
                .allowed_models
                .iter()
                .any(|pattern| pattern_matches(pattern, model)),
            // An unidentified model cannot be shown to be permitted.
            None => false,
        }
    }

    /// Whether *any* provider on the route is permitted.
    pub fn permits_any_provider<'p, I>(&self, providers: I) -> bool
    where
        I: IntoIterator<Item = &'p str>,
    {
        if self.allowed_providers.is_empty() {
            return true;
        }
        providers.into_iter().any(|provider| {
            self.allowed_providers
                .iter()
                .any(|pattern| pattern_matches(pattern, provider))
        })
    }

    /// Record a denial attributed to this client.
    pub fn record_policy_denial(&self) {
        self.record_denied();
    }
}

pub use crate::core::pattern::pattern_matches;

/// The configured clients, indexed by token.
pub struct ClientRegistry {
    clients: Vec<StdArc<ClientAccess>>,
    /// Denials by reason across every client.
    ///
    /// Registry-wide on purpose: a request presenting an unknown token cannot
    /// be attributed to a client, and that is exactly the event an operator
    /// most wants to see.
    denials: Mutex<HashMap<DenyReason, u64>>,
}

/// The outcome of authenticating and admitting a request.
pub enum ClientDecision {
    /// A configured client was authenticated and admitted.
    Allowed(StdArc<ClientAccess>),
    /// The proxy is unauthenticated (no clients configured).
    Open,
    /// The request was refused.
    Denied(Denied),
}

impl ClientRegistry {
    /// Compile a registry from config.
    pub fn from_config(configs: &[ClientConfig]) -> crate::error::Result<Self> {
        let mut clients: Vec<StdArc<ClientAccess>> = Vec::with_capacity(configs.len());

        for config in configs {
            let access = ClientAccess::from_config(config)?;
            // Two clients sharing a token would make identity ambiguous, and
            // the second would be silently unreachable.
            if clients.iter().any(|c| c.token() == access.token()) {
                return Err(crate::error::LlmBrokerError::InvalidConfig(format!(
                    "client `{}` reuses a token that is already configured",
                    config.name
                )));
            }
            clients.push(StdArc::new(access));
        }

        Ok(Self {
            clients,
            denials: Mutex::new(HashMap::new()),
        })
    }

    /// An empty registry: the proxy accepts any caller.
    pub fn open() -> Self {
        Self {
            clients: Vec::new(),
            denials: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.clients.is_empty()
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// All clients, for the admin API.
    pub fn statuses(&self) -> Vec<ClientStatus> {
        self.clients.iter().map(|c| c.status()).collect()
    }

    /// Authenticate a presented token and check its budget.
    ///
    /// Access rules for the model and provider are applied separately, once the
    /// model is known.
    pub fn authenticate(&self, token: Option<&str>) -> ClientDecision {
        if !self.is_configured() {
            return ClientDecision::Open;
        }

        let Some(token) = token.filter(|t| !t.is_empty()) else {
            return ClientDecision::Denied(self.record(DenyReason::MissingCredential));
        };

        // Constant-time lookup: compare against every candidate without
        // short-circuiting, so response timing does not reveal a valid prefix.
        let mut found: Option<usize> = None;
        for (index, client) in self.clients.iter().enumerate() {
            if constant_time_eq(client.token(), token) {
                found = Some(index);
            }
        }

        let Some(index) = found else {
            return ClientDecision::Denied(self.record(DenyReason::UnknownCredential));
        };
        let client = StdArc::clone(&self.clients[index]);
        match client.admit(0) {
            Ok(()) => ClientDecision::Allowed(client),
            Err(denied) => {
                client.record_denied();
                self.count(denied.reason);
                ClientDecision::Denied(denied)
            }
        }
    }

    /// Record a denial and return it, for use in `?`.
    fn record(&self, reason: DenyReason) -> Denied {
        self.count(reason);
        Denied::new(reason)
    }

    fn count(&self, reason: DenyReason) {
        *self.denials.lock().entry(reason).or_insert(0) += 1;
    }

    /// Denials by reason, for metrics and the admin API.
    pub fn denials(&self) -> HashMap<DenyReason, u64> {
        self.denials.lock().clone()
    }

    /// Record a denial the policy decided at the edge.
    ///
    /// The policy runs after `authenticate`, so the registry never sees these;
    /// without this the admin view and the metric would under-report exactly
    /// the denials an operator cares about (a client reaching for a model it is
    /// not cleared for).
    pub fn record_edge_denial(&self, reason: DenyReason, client: Option<&ClientAccess>) {
        self.count(reason);
        if let Some(client) = client {
            client.record_denied();
        }
    }

    /// Find a client by name, for the admin API.
    pub fn by_name(&self, name: &str) -> Option<&StdArc<ClientAccess>> {
        self.clients.iter().find(|c| c.name == name)
    }
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self::open()
    }
}

/// Extract the token a request presents.
///
/// Accepts the same shapes as the admin API so a single client configuration
/// works for both, plus `x-api-key` because OpenAI-compatible tools send that.
pub fn presented_token<'a>(
    authorization: Option<&'a str>,
    api_key: Option<&'a str>,
) -> Option<&'a str> {
    if let Some(value) = api_key.map(str::trim).filter(|v| !v.is_empty()) {
        return Some(value);
    }
    let value = authorization?.trim();
    let (scheme, rest) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let rest = rest.trim();
        return (!rest.is_empty()).then_some(rest);
    }
    None
}

/// Constant-time string comparison.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(name: &str, token: &str) -> ClientConfig {
        ClientConfig {
            name: name.into(),
            token: token.into(),
            enabled: true,
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
        }
    }

    fn registry(clients: Vec<ClientConfig>) -> ClientRegistry {
        ClientRegistry::from_config(&clients).expect("registry")
    }

    #[test]
    fn an_empty_registry_leaves_the_proxy_open() {
        let registry = registry(vec![]);
        assert!(!registry.is_configured());
        assert!(matches!(registry.authenticate(None), ClientDecision::Open));
    }

    #[test]
    fn a_valid_token_is_admitted() {
        let registry = registry(vec![client("laptop", "tok-1"), client("ci", "tok-2")]);
        match registry.authenticate(Some("tok-2")) {
            ClientDecision::Allowed(access) => assert_eq!(access.name, "ci"),
            other => panic!("expected admission, got {:?}", discriminant(&other)),
        }
    }

    #[test]
    fn a_missing_token_is_unauthorized() {
        let registry = registry(vec![client("laptop", "tok-1")]);
        match registry.authenticate(None) {
            ClientDecision::Denied(denied) => {
                assert_eq!(denied.reason, DenyReason::MissingCredential);
                assert_eq!(denied.reason.status(), 401);
            }
            _ => panic!("expected a denial"),
        }
    }

    #[test]
    fn an_unknown_token_is_unauthorized_and_does_not_echo_the_token() {
        let registry = registry(vec![client("laptop", "tok-1")]);
        match registry.authenticate(Some("sk-wrong")) {
            ClientDecision::Denied(denied) => {
                assert_eq!(denied.reason, DenyReason::UnknownCredential);
                // The message must not confirm or deny whether a token exists.
                assert!(!denied.reason.message().contains("sk-wrong"));
                assert!(denied.reason.is_security_event());
            }
            _ => panic!("expected a denial"),
        }
    }

    #[test]
    fn a_disabled_client_is_refused_with_403() {
        let mut config = client("laptop", "tok-1");
        config.enabled = false;
        let registry = registry(vec![config]);
        match registry.authenticate(Some("tok-1")) {
            ClientDecision::Denied(denied) => {
                assert_eq!(denied.reason, DenyReason::ClientDisabled);
                assert_eq!(denied.reason.status(), 403);
            }
            _ => panic!("expected a denial"),
        }
    }

    #[test]
    fn duplicate_tokens_are_a_configuration_error() {
        let error = ClientRegistry::from_config(&[client("a", "same"), client("b", "same")]);
        assert!(error.is_err(), "two clients must not share a token");
        let message = error.unwrap_err().to_string();
        assert!(message.contains('b'), "{message}");
    }

    #[test]
    fn empty_tokens_are_rejected() {
        assert!(ClientRegistry::from_config(&[client("a", "")]).is_err());
        assert!(ClientRegistry::from_config(&[client("a", "   ")]).is_err());
    }

    #[test]
    fn model_allow_lists_support_globs_and_default_to_everything() {
        let mut config = client("a", "tok");
        config.allowed_models = vec!["claude-*".into(), "gpt-4o".into()];
        let access = ClientAccess::from_config(&config).unwrap();

        assert!(access.allows_model(Some("claude-3-5-sonnet")));
        assert!(
            access.allows_model(Some("GPT-4O")),
            "exact match is case-insensitive"
        );
        assert!(!access.allows_model(Some("llama-3")));
        // A model we could not identify cannot be shown to be allowed.
        assert!(!access.allows_model(None));

        let open = ClientAccess::from_config(&client("b", "tok")).unwrap();
        assert!(open.allows_model(None));
        assert!(open.allows_model(Some("anything")));
    }

    #[test]
    fn provider_allow_lists_scope_egress() {
        let mut config = client("a", "tok");
        config.allowed_providers = vec!["openai".into(), "azure-*".into()];
        let access = ClientAccess::from_config(&config).unwrap();

        assert!(access.allows_provider("openai"));
        assert!(access.allows_provider("azure-eu"));
        assert!(!access.allows_provider("anthropic"));
    }

    #[test]
    fn the_request_budget_is_enforced_per_client() {
        let mut config = client("a", "tok");
        config.max_rpm = Some(2);
        let registry = registry(vec![config]);

        for i in 1..=2 {
            match registry.authenticate(Some("tok")) {
                ClientDecision::Allowed(_) => {}
                _ => panic!("request {i} should be admitted"),
            }
        }
        match registry.authenticate(Some("tok")) {
            ClientDecision::Denied(denied) => {
                assert_eq!(denied.reason, DenyReason::RateLimited);
                assert_eq!(denied.reason.status(), 429);
                assert!(denied.reason.retryable());
                assert!(
                    denied.retry_after.is_some(),
                    "must tell the client when to retry"
                );
            }
            _ => panic!("the third request must be refused"),
        }
    }

    #[test]
    fn one_client_exhausting_its_budget_does_not_affect_another() {
        let mut limited = client("limited", "tok-1");
        limited.max_rpm = Some(1);
        let registry = registry(vec![limited, client("other", "tok-2")]);

        assert!(matches!(
            registry.authenticate(Some("tok-1")),
            ClientDecision::Allowed(_)
        ));
        assert!(matches!(
            registry.authenticate(Some("tok-1")),
            ClientDecision::Denied(_)
        ));
        assert!(
            matches!(
                registry.authenticate(Some("tok-2")),
                ClientDecision::Allowed(_)
            ),
            "a different client has its own budget"
        );
    }

    #[test]
    fn the_concurrency_budget_is_enforced_and_released() {
        let mut config = client("a", "tok");
        config.max_concurrency = Some(1);
        let registry = registry(vec![config]);

        let ClientDecision::Allowed(access) = registry.authenticate(Some("tok")) else {
            panic!("first request should be admitted");
        };
        access.begin();

        assert!(
            matches!(registry.authenticate(Some("tok")), ClientDecision::Denied(denied)
                if denied.reason == DenyReason::TooManyInFlight),
            "a second concurrent request must be refused"
        );

        access.end();
        assert!(
            matches!(
                registry.authenticate(Some("tok")),
                ClientDecision::Allowed(_)
            ),
            "releasing the slot must re-admit"
        );
    }

    #[test]
    fn denials_are_counted_by_reason_at_the_registry_level() {
        // An unknown token cannot be attributed to a client, so the count must
        // live on the registry or the event would be invisible.
        let registry = registry(vec![client("a", "tok")]);
        let _ = registry.authenticate(Some("wrong"));
        let _ = registry.authenticate(None);

        let denials = registry.denials();
        assert_eq!(denials.get(&DenyReason::UnknownCredential), Some(&1));
        assert_eq!(denials.get(&DenyReason::MissingCredential), Some(&1));
        // The configured client was never reached, so its own counter is zero.
        assert_eq!(registry.statuses()[0].denied, 0);
    }

    #[test]
    fn a_budget_denial_is_counted_on_the_client_and_the_registry() {
        let mut config = client("a", "tok");
        config.max_rpm = Some(1);
        let registry = registry(vec![config]);
        assert!(matches!(
            registry.authenticate(Some("tok")),
            ClientDecision::Allowed(_)
        ));
        assert!(matches!(
            registry.authenticate(Some("tok")),
            ClientDecision::Denied(_)
        ));

        assert_eq!(registry.statuses()[0].denied, 1, "attributed to the client");
        assert_eq!(
            registry.denials().get(&DenyReason::RateLimited),
            Some(&1),
            "and visible in aggregate"
        );
    }

    #[test]
    fn an_edge_denial_is_counted_against_the_client_and_the_registry() {
        // The policy runs after `authenticate`, so these denials would be
        // invisible without an explicit record.
        let registry = registry(vec![client("a", "tok")]);
        let ClientDecision::Allowed(access) = registry.authenticate(Some("tok")) else {
            panic!("should be admitted");
        };
        registry.record_edge_denial(DenyReason::ModelForbidden, Some(&access));

        assert_eq!(registry.statuses()[0].denied, 1);
        assert_eq!(
            registry.denials().get(&DenyReason::ModelForbidden),
            Some(&1)
        );
    }

    #[test]
    fn status_never_exposes_the_token() {
        let registry = registry(vec![client("a", "super-secret")]);
        let rendered = serde_json::to_string(&registry.statuses()).unwrap();
        assert!(!rendered.contains("super-secret"), "{rendered}");
    }

    #[test]
    fn tokens_may_come_from_a_file() {
        let dir = std::env::temp_dir().join(format!("broker-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "file-token\n").unwrap();

        let mut config = client("a", &format!("file:{}", path.display()));
        config.token = format!("file:{}", path.display());
        let registry = registry(vec![config]);
        assert!(matches!(
            registry.authenticate(Some("file-token")),
            ClientDecision::Allowed(_)
        ));
        // A trailing newline in the file must not become part of the secret.
        assert!(matches!(
            registry.authenticate(Some("file-token\n")),
            ClientDecision::Denied(_)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unreadable_secret_file_is_a_configuration_error() {
        let config = client("a", "file:/nonexistent/definitely/not/here");
        let error = ClientAccess::from_config(&config).unwrap_err();
        assert!(
            error.to_string().contains("cannot read secret file"),
            "{error}"
        );
    }

    #[test]
    fn tokens_are_read_from_the_expected_headers() {
        assert_eq!(presented_token(Some("Bearer abc"), None), Some("abc"));
        assert_eq!(presented_token(Some("bearer abc"), None), Some("abc"));
        assert_eq!(presented_token(Some("  Bearer   abc  "), None), Some("abc"));
        assert_eq!(presented_token(None, Some("xyz")), Some("xyz"));
        // api-key wins when both are present, matching OpenAI tooling.
        assert_eq!(
            presented_token(Some("Bearer abc"), Some("xyz")),
            Some("xyz")
        );
        assert_eq!(presented_token(Some("Basic abc"), None), None);
        assert_eq!(presented_token(Some("Bearer "), None), None);
        assert_eq!(presented_token(Some("garbage"), None), None);
        assert_eq!(presented_token(None, None), None);
    }

    #[test]
    fn constant_time_comparison_is_correct() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
    }

    fn discriminant(decision: &ClientDecision) -> &'static str {
        match decision {
            ClientDecision::Allowed(_) => "allowed",
            ClientDecision::Open => "open",
            ClientDecision::Denied(_) => "denied",
        }
    }
}
