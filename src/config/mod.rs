//! Configuration schema, loading, validation and key mutation.
//!
//! The schema is a strict superset of the original broker config: existing
//! `config.toml` files keep working, every new section has a default, and new
//! keys can be added or toggled at runtime through the admin API and written
//! back to disk.

use indexmap::IndexMap;
use serde::de::value::{MapAccessDeserializer, SeqAccessDeserializer};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::{LlmBrokerError, Result};

pub const DEFAULT_PROXY_PORT: u16 = 11436;
/// Seconds a graceful shutdown waits for in-flight requests (see
/// [`ServerConfig::graceful_shutdown_secs`]).
pub const DEFAULT_GRACE_PERIOD_SECS: u64 = 30;
pub const DEFAULT_ADMIN_PORT: u16 = 11437;

/// Root configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,

    /// Kept for backwards compatibility; the proxy implementation is now always
    /// the pingora backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_type: Option<String>,

    /// `[[providers]]` (a list) and `[providers.<name>]` (a map) are the same
    /// thing; see [`ProvidersField`].
    #[serde(default, deserialize_with = "deserialize_providers")]
    pub providers: Vec<ProviderConfig>,

    /// Explicit model -> provider routing. Models without a route fall back to
    /// "any provider that has a key for the model".
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Route used when a request carries no recognisable model.
    #[serde(default)]
    pub default_route: Option<String>,

    #[serde(default)]
    pub load_balancing: LoadBalancingConfig,

    #[serde(default)]
    pub health: HealthConfig,

    #[serde(default)]
    pub observability: ObservabilityConfig,

    #[serde(default)]
    pub admin: AdminConfig,

    /// Callers allowed to use the proxy. Empty means "no client
    /// authentication", which is the single-user default.
    #[serde(default)]
    pub clients: Vec<ClientConfig>,

    /// Egress policy, written in Rego.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Request/response dumping for LLM debugging.
    #[serde(default)]
    pub dump: DumpSection,

    /// Inspection of request *content* before it is forwarded.
    #[serde(default)]
    pub content_guard: ContentGuardConfig,
}

/// The two shapes `providers` accepts.
///
/// The array form is the 1.x shape and stays supported. The map form puts the
/// provider's name in the table path, which is what makes the association
/// explicit: `[[providers.openai.api_keys]]` cannot attach to the wrong
/// provider, where the array form attaches to whichever `[[providers]]` entry
/// came last. The name comes from the table key, so the map form omits
/// `name = ...`.
///
/// **Order is document order in both forms, and provider order is the failover
/// order.** That is why `indexmap` and `toml`'s `preserve_order` are load
/// bearing: without them the map form deserialises through a sorted table and
/// silently reorders the pool alphabetically, which is a behaviour change no
/// one would think to look for.
#[derive(Debug, Clone)]
enum ProvidersField {
    List(Vec<ProviderConfig>),
    Map(IndexMap<String, ProviderConfig>),
}

impl ProvidersField {
    fn into_vec(self) -> std::result::Result<Vec<ProviderConfig>, String> {
        match self {
            Self::List(list) => Ok(list),
            Self::Map(map) => map
                .into_iter()
                .map(|(name, mut provider)| {
                    if !provider.name.is_empty() && provider.name != name {
                        return Err(format!(
                            "`[providers.{name}]` also declares `name = \"{}\"`. In the map \
                             form the name is the table key; remove the field.",
                            provider.name
                        ));
                    }
                    provider.name = name;
                    Ok(provider)
                })
                .collect(),
        }
    }
}

impl<'de> Deserialize<'de> for ProvidersField {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProvidersVisitor;

        impl<'de> Visitor<'de> for ProvidersVisitor {
            type Value = ProvidersField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "a list of providers (`[[providers]]`) or a map keyed by provider name \
                     (`[providers.<name>]`)",
                )
            }

            fn visit_seq<A>(self, seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let list = Vec::<ProviderConfig>::deserialize(SeqAccessDeserializer::new(seq))?;
                Ok(ProvidersField::List(list))
            }

            fn visit_map<A>(self, map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let map = IndexMap::<String, ProviderConfig>::deserialize(
                    MapAccessDeserializer::new(map),
                )?;
                Ok(ProvidersField::Map(map))
            }
        }

        deserializer.deserialize_any(ProvidersVisitor)
    }
}

fn deserialize_providers<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ProviderConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    ProvidersField::deserialize(deserializer)?
        .into_vec()
        .map_err(serde::de::Error::custom)
}

/// `[content_guard]` — what must not appear inside a prompt.
///
/// Metadata checks (which client, which model, which provider) cannot see an API
/// key pasted into a prompt or a customer's email in a diff. This section lists
/// the shapes worth catching, and what to do when one appears.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `report` (default) only counts and logs findings; `deny` refuses the
    /// request with 403 before the body is forwarded.
    #[serde(default)]
    pub action: Option<String>,
    /// Named patterns, applied in order. The first match is reported.
    #[serde(default)]
    pub patterns: Vec<ContentPattern>,
    /// Bodies matching any of these are skipped entirely, so a documentation
    /// example or a test fixture does not train people to ignore the guard.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// One named content pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPattern {
    /// Stable name, used in logs and metrics and never replaced by the match.
    pub name: String,
    /// The regex.
    pub pattern: String,
}

/// `[dump]` — the debug dump, and what to hide inside it.
///
/// A dump is the one place prompt content reaches durable storage, so the
/// redaction patterns belong in the config next to it rather than only on a
/// command line that a shell history records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DumpSection {
    /// Patterns removed from dumped bodies and header values, each either
    /// `PATTERN` or `PATTERN=REPLACEMENT`.
    #[serde(default)]
    pub redact: Vec<String>,
}

/// A caller of the proxy.
///
/// The token identifies the caller; the allow-lists are the rules the built-in
/// policy applies. Both are exposed to a custom Rego policy as `input.client`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    /// `env:NAME`, `file:/path`, or a literal token.
    pub token: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Model patterns (`gpt-*`); empty means any model.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Provider patterns; empty means any provider.
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rpm: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tpm: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
}

/// Rego policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// When false, the built-in default policy decides.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Rego files, in load order.
    #[serde(default)]
    pub files: Vec<String>,
    /// Inline Rego, for a policy too small to be worth a file.
    #[serde(default)]
    pub inline: String,
    /// Name given to the inline policy in error messages.
    #[serde(default = "default_inline_name")]
    pub inline_name: String,

    /// A candidate policy to **evaluate without enforcing**, as a file.
    ///
    /// Writing a policy is risky: `default allow := false` with a typo blocks
    /// every request. Syntax checking proves nothing about behaviour. A shadow
    /// policy is evaluated against live traffic, its would-be denials are
    /// counted and logged, and the request proceeds on the enforcing policy's
    /// verdict -- so "this would have blocked 30% of today's traffic" is
    /// answerable before the policy is switched on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<String>,

    /// Inline shadow policy, for a rule too small to be worth a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run_inline: Option<String>,

    /// A directory of `.rego` files, loaded in sorted order of their relative
    /// path, before `files`.
    ///
    /// A policy outgrows a single file quickly, and a directory can be reviewed
    /// in pieces: `10-clients.rego`, `20-models.rego`, `30-content.rego`.
    /// Regorus merges modules by *package*, so several files may contribute to
    /// `package llm.authz`, and one file may define a package another
    /// references through `data`. An unreadable directory, or one holding no
    /// `.rego` files, is a startup error rather than a silently empty policy.
    #[serde(default)]
    pub rules_dir: String,

    /// The Rego rule that decides a **content finding's** action. Defaults to
    /// `data.llm.content.action` when empty.
    ///
    /// This is the one decision the admission policy cannot make, because a
    /// finding is discovered after that policy has already run. The matched
    /// text never reaches Rego -- only the rule name, the field and the request
    /// facts do -- so a policy can vary the verdict by client, route or rule
    /// name without the engine ever holding the secret.
    ///
    /// Empty means "use the rule if the policy happens to define it, otherwise
    /// keep the configured `[content_guard] action`", so a policy written
    /// before content control existed keeps working. Naming a rule here makes it
    /// **required**: a missing rule then fails at startup instead of silently
    /// falling back to the config.
    #[serde(default)]
    pub content_rule: String,
}

fn default_inline_name() -> String {
    "inline.rego".to_string()
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            files: Vec::new(),
            inline: String::new(),
            inline_name: default_inline_name(),
            dry_run: None,
            dry_run_inline: None,
            rules_dir: String::new(),
            content_rule: String::new(),
        }
    }
}

/// Downstream listener settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<usize>,
    #[serde(default)]
    pub daemon: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Upstream connect timeout in milliseconds (0 = pingora default).
    #[serde(default)]
    pub connect_timeout_ms: u64,
    /// Upstream idle timeout in milliseconds. `None` falls back to
    /// `load_balancing.idle_timeout_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_ms: Option<u64>,
    /// Per-attempt read timeout in milliseconds. `None` keeps pingora's
    /// default (60s).
    ///
    /// LLM answers routinely take longer than that -- a long completion, or a
    /// reasoning model that thinks before it writes, can exceed a minute on its
    /// own. When this fires the attempt is recorded as a transport failure and
    /// the request is retried on another key, so too small a value turns normal
    /// slow answers into exhausted key pools. Raise it for LLM traffic, or set
    /// a generous value and rely on the client's own timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_timeout_ms: Option<u64>,
    /// Per-attempt write timeout in milliseconds. `None` keeps pingora's
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_timeout_ms: Option<u64>,
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    /// How long a graceful shutdown (`SIGTERM`) waits for in-flight requests
    /// before tearing the runtimes down.
    ///
    /// pingora's default is 300s, and it implements the wait as a plain sleep
    /// on the main thread. Ctrl+C does not interrupt it, so the process looks
    /// wedged for five minutes and the operator keeps pressing Ctrl+C. LLM
    /// requests can be long, hence a real wait rather than none, but a local
    /// proxy does not need five minutes.
    #[serde(default = "default_grace_period")]
    pub graceful_shutdown_secs: u64,
}

/// A provider endpoint plus its key pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Taken from the table key in the `[providers.<name>]` form, so it is
    /// optional there and required in the `[[providers]]` form. Validation
    /// rejects an empty one rather than letting a nameless provider through.
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Key appended verbatim to the path (edge cases only; prefer
    /// `base_url`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// `bearer` (default) | `x-api-key` | `api-key` | `query` | custom header name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// When the auth style is `query`, the query parameter carrying the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_query_param: Option<String>,
    /// Provider-wide default models, used when a key does not list any.
    #[serde(default)]
    pub default_models: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rpm: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tpm: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
}

/// A single credential in a provider pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    pub id: String,
    /// The secret itself. `env:NAME` reads the value from the environment.
    pub key: String,
    /// Whether this key may serve requests.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rpm: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tpm: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
    /// Optional per-key model alias map (`client model` -> `upstream model`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_map: Option<std::collections::HashMap<String, String>>,
}

/// Explicit model routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Model name, glob pattern (`claude-*`), or `*` for catch-all.
    pub model: String,
    /// One or more provider names, tried in order.
    pub providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// When true, the model is rewritten to the upstream provider's canonical
    /// name before the request is forwarded.
    #[serde(default)]
    pub rewrite: bool,
}

/// Provider-wide model pricing used for `/metrics` cost accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    pub model: String,
    #[serde(default)]
    pub input_per_million: f64,
    #[serde(default)]
    pub output_per_million: f64,
}

/// Load balancing and failover behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancingConfig {
    #[serde(default = "default_strategy")]
    pub strategy: String,
    #[serde(default = "default_weighted_random_tolerance")]
    pub weighted_random_tolerance: f64,
    #[serde(default = "default_initial_cooldown")]
    pub initial_cooldown_secs: u64,
    #[serde(default = "default_max_cooldown")]
    pub max_cooldown_secs: u64,
    #[serde(default = "default_cooldown_multiplier")]
    pub cooldown_multiplier: f64,
    /// Jitter ratio applied to cooldowns to avoid thundering herds (0.0-1.0).
    #[serde(default = "default_cooldown_jitter")]
    pub cooldown_jitter: f64,
    /// Wait this long for the earliest key to leave cooldown before giving up
    /// when every key is exhausted (0 = fail fast).
    #[serde(default = "default_max_wait")]
    pub max_wait_for_key_secs: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Strategies queried in order when the primary strategy cannot place the
    /// request (e.g. every key is at its rate limit).
    #[serde(default)]
    pub fallback_strategies: Vec<String>,
}

/// Health scoring and circuit breaker behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// EWMA weight for latency observations (0.0-1.0, higher = more reactive).
    #[serde(default = "default_latency_alpha")]
    pub latency_alpha: f64,
    /// `health_score` below this opens the circuit.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: f64,
    /// Consecutive failures that immediately open the circuit.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
}

/// Metrics and logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,
    /// Path serving Prometheus text format.
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
    /// Log one structured line per completed request.
    #[serde(default)]
    pub access_log: bool,
    /// Inspect response bodies for `usage` objects to track TPM and cost.
    #[serde(default = "default_true")]
    pub usage_tracking: bool,
    /// Cap on bytes buffered per response while scanning for usage.
    #[serde(default = "default_usage_scan_limit")]
    pub usage_scan_limit_bytes: usize,
    #[serde(default)]
    pub model_pricing: Vec<ModelPricing>,
}

/// Admin API surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_admin_port")]
    pub port: u16,
    /// Separate listener or a path prefix on the proxy port.
    #[serde(default)]
    pub mode: AdminMode,
    /// Path prefix used when `mode = "path"`.
    #[serde(default = "default_admin_path")]
    pub path: String,
    /// Bearer token. `env:NAME` reads the value from the environment. When
    /// empty the admin API is refuse-all unless `allow_insecure` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Explicitly allow an unauthenticated admin API (loopback only).
    #[serde(default)]
    pub allow_insecure: bool,
    /// Write key changes back to the config file.
    #[serde(default = "default_true")]
    pub persist: bool,
}

/// How the admin API is exposed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminMode {
    /// Own listener on `admin.host:admin.port`.
    #[default]
    Separate,
    /// Served under `admin.path` on the proxy listener.
    Path,
    Off,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_proxy_port() -> u16 {
    DEFAULT_PROXY_PORT
}
fn default_admin_port() -> u16 {
    DEFAULT_ADMIN_PORT
}
fn default_max_retries() -> usize {
    3
}
fn default_grace_period() -> u64 {
    DEFAULT_GRACE_PERIOD_SECS
}
fn default_true() -> bool {
    true
}
fn default_weight() -> u32 {
    1
}
fn default_strategy() -> String {
    "round_robin".to_string()
}
fn default_weighted_random_tolerance() -> f64 {
    0.1
}
fn default_initial_cooldown() -> u64 {
    60
}
fn default_max_cooldown() -> u64 {
    1500
}
fn default_cooldown_multiplier() -> f64 {
    5.0
}
fn default_cooldown_jitter() -> f64 {
    0.2
}
fn default_max_wait() -> u64 {
    15
}
fn default_idle_timeout() -> u64 {
    120
}
fn default_latency_alpha() -> f64 {
    0.2
}
fn default_unhealthy_threshold() -> f64 {
    0.3
}
fn default_failure_threshold() -> u32 {
    3
}
fn default_metrics_path() -> String {
    "/metrics".to_string()
}
fn default_usage_scan_limit() -> usize {
    64 * 1024
}
fn default_admin_path() -> String {
    "/admin".to_string()
}

impl Default for LoadBalancingConfig {
    fn default() -> Self {
        Self {
            strategy: default_strategy(),
            weighted_random_tolerance: default_weighted_random_tolerance(),
            initial_cooldown_secs: default_initial_cooldown(),
            max_cooldown_secs: default_max_cooldown(),
            cooldown_multiplier: default_cooldown_multiplier(),
            cooldown_jitter: default_cooldown_jitter(),
            max_wait_for_key_secs: default_max_wait(),
            idle_timeout_secs: default_idle_timeout(),
            fallback_strategies: Vec::new(),
        }
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            latency_alpha: default_latency_alpha(),
            unhealthy_threshold: default_unhealthy_threshold(),
            failure_threshold: default_failure_threshold(),
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            metrics_path: default_metrics_path(),
            access_log: false,
            usage_tracking: true,
            usage_scan_limit_bytes: default_usage_scan_limit(),
            model_pricing: Vec::new(),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_host(),
            port: default_admin_port(),
            mode: AdminMode::default(),
            path: default_admin_path(),
            token: None,
            allow_insecure: false,
            persist: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Secret resolution
// ---------------------------------------------------------------------------

/// The placeholder written in place of a credential.
pub const REDACTED_SECRET: &str = "<redacted>";

/// Replace credential values in a serialised config.
///
/// Works line by line on the key name rather than on a parsed document, because
/// the values are exactly what must not be inspected. A key that holds a
/// reference (`env:NAME`, `file:/path`) is left alone: it is not the secret, and
/// seeing which reference is configured is the point of dumping the config.
///
/// Recognised keys: `token`, `key`, and `api_key` wherever they appear, which
/// covers `[[clients]] token`, `[[providers.api_keys]] key` and `[admin] token`.
pub fn redact_secrets_in_toml(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        match trimmed.split_once('=') {
            Some((key, value)) if is_credential_key(key.trim()) => {
                // The serialised value still carries its quotes; the reference
                // check has to see the text inside them.
                let value = value.trim().trim_matches('"');
                // A reference is not a secret: `env:`/`file:` say where the real
                // value lives, and which reference is configured is worth seeing
                // in a dump.
                if value.starts_with("env:") || value.starts_with("file:") {
                    out.push_str(line);
                } else {
                    out.push_str(indent);
                    out.push_str(key.trim());
                    out.push_str(" = \"");
                    out.push_str(REDACTED_SECRET);
                    out.push('"');
                }
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

/// Whether a config key holds a credential value.
fn is_credential_key(key: &str) -> bool {
    matches!(key, "token" | "key" | "api_key" | "password" | "secret")
}

/// Resolve a secret reference.
///
/// - `env:NAME` reads the process environment;
/// - `file:/path` reads the first line of a file, which is how container and
///   Kubernetes deployments usually mount a secret without putting it in the
///   environment (visible to `ps`, `/proc`, crash dumps and child processes);
/// - anything else is a literal value.
///
/// The file form trims only the trailing newline, so a secret that ends in a
/// space is preserved.
pub fn resolve_secret(value: &str) -> Result<String> {
    if let Some(name) = value.strip_prefix("env:") {
        return std::env::var(name).map_err(|_| {
            LlmBrokerError::InvalidConfig(format!(
                "secret `env:{name}` is set in the config but the environment variable is missing"
            ))
        });
    }

    if let Some(path) = value.strip_prefix("file:") {
        if path.is_empty() {
            return Err(LlmBrokerError::InvalidConfig(
                "secret `file:` is missing a path".to_string(),
            ));
        }
        let contents = std::fs::read_to_string(path).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot read secret file `{path}`: {e}"))
        })?;
        let secret = contents.strip_suffix('\n').unwrap_or(&contents);
        if secret.is_empty() {
            return Err(LlmBrokerError::InvalidConfig(format!(
                "secret file `{path}` is empty"
            )));
        }
        return Ok(secret.to_string());
    }

    Ok(value.to_string())
}

impl AdminConfig {
    /// Effective bearer token, if any.
    pub fn resolved_token(&self) -> Result<Option<String>> {
        match self.token.as_deref() {
            None | Some("") => Ok(None),
            Some(value) => resolve_secret(value).map(Some),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl Config {
    /// Load and structurally validate a config file.
    ///
    /// Secret *values* are not resolved here so that `--check` and
    /// [`Config::to_toml`] work on a machine where the environment variables
    /// are not exported. [`Config::validate_secrets`] performs that step at
    /// startup and on reload.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot read {}: {e}", path.display()))
        })?;
        let config: Config = toml::from_str(&content).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot parse {}: {e}", path.display()))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Serialize the current document, used for admin-driven persistence.
    /// Serialise for **display**.
    ///
    /// Every credential is replaced with a placeholder. This is the function
    /// behind `--dump-config` and `GET /admin/config`, and it used to return the
    /// document verbatim -- so a single token-gated request printed every live
    /// API key the broker held. Redacting here rather than at each call site
    /// means a new endpoint cannot forget to.
    ///
    /// Use [`Config::to_toml_with_secrets`] when the real values are required,
    /// which is only ever for writing the file back to disk.
    pub fn to_toml(&self) -> Result<String> {
        self.to_toml_with_secrets(false)
    }

    /// Serialise the document, optionally including real credentials.
    pub fn to_toml_with_secrets(&self, include_secrets: bool) -> Result<String> {
        let mut body = toml::to_string_pretty(self)
            .map_err(|e| LlmBrokerError::InvalidConfig(format!("cannot serialize config: {e}")))?;
        if !include_secrets {
            body = redact_secrets_in_toml(&body);
        }
        Ok(body)
    }

    /// Write the current document back to `path` atomically.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        // The file must keep the real secrets, or a reload would lose them.
        let body = self.to_toml_with_secrets(true)?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, body).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot write {}: {e}", tmp.display()))
        })?;
        std::fs::rename(&tmp, path).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot replace {}: {e}", path.display()))
        })?;
        Ok(())
    }

    /// Reject documents that would misbehave at runtime.
    pub fn validate(&self) -> Result<()> {
        if self.providers.is_empty() {
            return Err(LlmBrokerError::InvalidConfig(
                "at least one [[providers]] entry is required".to_string(),
            ));
        }

        let mut provider_names = HashSet::new();
        for provider in &self.providers {
            if provider.name.trim().is_empty() {
                return Err(LlmBrokerError::InvalidConfig(
                    "a provider has no name: give its `[[providers]]` entry a `name`, or use \
                     the map form `[providers.<name>]`, where the name is the table key"
                        .to_string(),
                ));
            }

            // A provider with no keys can never serve a request, so a config
            // that has one is a config that cannot work. This is not a
            // hypothetical: `[[openai.api_keys]]` is valid TOML, and the broker
            // used to parse it, find no keys and start anyway -- so the mistake
            // looked like a working proxy that failed every request.
            if provider.api_keys.is_empty() {
                return Err(LlmBrokerError::InvalidConfig(format!(
                    "provider `{}` has no keys. If you wrote `[[{}.api_keys]]`, nest it \
                     under the provider instead: `[providers.{}]` with \
                     `[[providers.{}.api_keys]]`, or a `[[providers.api_keys]]` block below \
                     its `[[providers]]` entry.",
                    provider.name, provider.name, provider.name, provider.name
                )));
            }

            if !provider_names.insert(provider.name.clone()) {
                return Err(LlmBrokerError::InvalidConfig(format!(
                    "duplicate provider name `{}`",
                    provider.name
                )));
            }

            let mut key_ids = HashSet::new();
            for key in &provider.api_keys {
                if !key_ids.insert(key.id.clone()) {
                    return Err(LlmBrokerError::InvalidConfig(format!(
                        "duplicate key id `{}` in provider `{}`",
                        key.id, provider.name
                    )));
                }
                if key.key.trim().is_empty() {
                    return Err(LlmBrokerError::InvalidConfig(format!(
                        "key `{}` in provider `{}` has an empty secret",
                        key.id, provider.name
                    )));
                }
                if key.key.starts_with("env:") && key.key.len() == 4 {
                    return Err(LlmBrokerError::InvalidConfig(format!(
                        "key `{}` in provider `{}` uses `env:` without a variable name",
                        key.id, provider.name
                    )));
                }
            }
        }

        for route in &self.routes {
            if route.providers.is_empty() {
                return Err(LlmBrokerError::InvalidConfig(format!(
                    "route `{}` lists no providers",
                    route.model
                )));
            }
            for name in &route.providers {
                if !provider_names.contains(name) {
                    return Err(LlmBrokerError::InvalidConfig(format!(
                        "route `{}` references unknown provider `{}`",
                        route.model, name
                    )));
                }
            }
        }

        if let Some(default_route) = &self.default_route
            && !provider_names.contains(default_route)
        {
            return Err(LlmBrokerError::InvalidConfig(format!(
                "default_route references unknown provider `{default_route}`"
            )));
        }

        for strategy in std::iter::once(&self.load_balancing.strategy)
            .chain(self.load_balancing.fallback_strategies.iter())
        {
            crate::core::strategy::Strategy::parse(strategy).ok_or_else(|| {
                LlmBrokerError::InvalidConfig(format!(
                    "unknown load balancing strategy `{strategy}`"
                ))
            })?;
        }

        if self.load_balancing.cooldown_multiplier < 1.0 {
            return Err(LlmBrokerError::InvalidConfig(
                "load_balancing.cooldown_multiplier must be >= 1.0".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.load_balancing.cooldown_jitter) {
            return Err(LlmBrokerError::InvalidConfig(
                "load_balancing.cooldown_jitter must be between 0.0 and 1.0".to_string(),
            ));
        }

        if self.admin.enabled && self.admin.mode != AdminMode::Off {
            let has_token = self.admin.resolved_token()?.is_some();
            if !has_token && !self.admin.allow_insecure {
                return Err(LlmBrokerError::InvalidConfig(
                    "admin.enabled requires admin.token (or admin.allow_insecure = true)"
                        .to_string(),
                ));
            }
        }

        if self.observability.metrics_enabled && !self.observability.metrics_path.starts_with('/') {
            return Err(LlmBrokerError::InvalidConfig(
                "observability.metrics_path must start with `/`".to_string(),
            ));
        }

        Ok(())
    }

    /// Resolve every `env:` secret reference, failing with the variable name
    /// that is missing.
    pub fn validate_secrets(&self) -> Result<()> {
        for provider in &self.providers {
            for key in &provider.api_keys {
                if let Err(error) = resolve_secret(&key.key) {
                    // Unwrap the inner message so the report reads as one
                    // sentence rather than nesting "invalid configuration".
                    let detail = match error {
                        LlmBrokerError::InvalidConfig(message) => message,
                        other => other.to_string(),
                    };
                    return Err(LlmBrokerError::InvalidConfig(format!(
                        "provider `{}` key `{}`: {detail}",
                        provider.name, key.id
                    )));
                }
            }
        }
        Ok(())
    }

    /// All models known to the config, used by `/admin/models`.
    pub fn known_models(&self) -> Vec<String> {
        let mut models = Vec::new();
        for provider in &self.providers {
            for model in &provider.default_models {
                if !models.contains(model) {
                    models.push(model.clone());
                }
            }
            for key in &provider.api_keys {
                for model in &key.models {
                    if !models.contains(model) {
                        models.push(model.clone());
                    }
                }
            }
        }
        models
    }

    /// Resolve the provider entry by name.
    pub fn provider(&self, name: &str) -> Option<&ProviderConfig> {
        self.providers.iter().find(|p| p.name == name)
    }

    /// Resolve the provider entry by name, mutably.
    pub fn provider_mut(&mut self, name: &str) -> Option<&mut ProviderConfig> {
        self.providers.iter_mut().find(|p| p.name == name)
    }

    /// Effective idle timeout for upstream connections.
    pub fn idle_timeout(&self) -> std::time::Duration {
        let ms = self
            .server
            .idle_timeout_ms
            .unwrap_or(self.load_balancing.idle_timeout_secs.saturating_mul(1000));
        std::time::Duration::from_millis(ms)
    }
}

/// Config plus the path it came from, so the admin API can persist changes.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub path: PathBuf,
}

impl LoadedConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let config = Config::from_file(&path)?;
        Ok(Self { config, path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal config; `Config` has no `Default` because every field is
    /// required to be considered.
    fn base_config() -> Config {
        Config {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 11436,
                threads: None,
                daemon: false,
                pid_file: None,
                user: None,
                group: None,
                connect_timeout_ms: 2_000,
                idle_timeout_ms: None,
                read_timeout_ms: None,
                write_timeout_ms: None,
                max_retries: 3,
                graceful_shutdown_secs: DEFAULT_GRACE_PERIOD_SECS,
            },
            proxy_type: None,
            providers: Vec::new(),
            routes: Vec::new(),
            default_route: None,
            load_balancing: LoadBalancingConfig::default(),
            health: HealthConfig::default(),
            observability: ObservabilityConfig::default(),
            admin: AdminConfig::default(),
            clients: Vec::new(),
            policy: PolicyConfig::default(),
            dump: DumpSection::default(),
            content_guard: ContentGuardConfig::default(),
        }
    }

    fn provider_with_key(secret: &str) -> ProviderConfig {
        ProviderConfig {
            name: "p".into(),
            base_url: Some("http://127.0.0.1".into()),
            path_prefix: None,
            auth: None,
            auth_query_param: None,
            default_models: vec!["m".into()],
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
            api_keys: vec![ApiKeyConfig {
                id: "k1".into(),
                key: secret.into(),
                enabled: true,
                models: vec!["m".into()],
                weight: 1,
                max_rpm: None,
                max_tpm: None,
                max_concurrency: None,
                model_map: None,
            }],
        }
    }

    #[test]
    fn serialising_for_display_redacts_every_credential() {
        // `GET /admin/config` and `--dump-config` both go through `to_toml`, so
        // a regression here leaks every key the broker holds in one request.
        let mut config = base_config();
        config
            .providers
            .push(provider_with_key("nvapi-super-secret-value"));
        config.admin.token = Some("admin-super-secret".into());
        config.clients.push(ClientConfig {
            name: "laptop".into(),
            token: "client-super-secret".into(),
            enabled: true,
            allowed_models: vec![],
            allowed_providers: vec![],
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
        });

        let shown = config.to_toml().expect("serialize");
        for secret in [
            "nvapi-super-secret-value",
            "admin-super-secret",
            "client-super-secret",
        ] {
            assert!(!shown.contains(secret), "leaked {secret}:\n{shown}");
        }
        assert!(shown.contains(REDACTED_SECRET), "{shown}");
        // The structure stays visible; that is what the dump is for.
        assert!(shown.contains("laptop"), "{shown}");
        assert!(shown.contains("k1"), "{shown}");
    }

    #[test]
    fn persistence_keeps_the_real_credentials() {
        // Redacting on the way to disk would lose the keys on the next reload.
        let mut config = base_config();
        config
            .providers
            .push(provider_with_key("nvapi-super-secret-value"));

        let written = config.to_toml_with_secrets(true).expect("serialize");
        assert!(written.contains("nvapi-super-secret-value"), "{written}");
        assert!(!written.contains(REDACTED_SECRET), "{written}");
    }

    #[test]
    fn a_secret_reference_is_shown_rather_than_redacted() {
        // `env:NAME` and `file:/path` are not the secret; seeing which reference
        // is configured is exactly what a config dump is for.
        for reference in ["env:MY_ADMIN_TOKEN", "file:/run/secrets/admin"] {
            let mut config = base_config();
            config.admin.token = Some(reference.into());
            let shown = config.to_toml().unwrap();
            // Match the assignment, not the bare text: `admin_token` in another
            // key's *name* would otherwise satisfy the assertion by accident.
            assert!(
                shown.contains(&format!("token = \"{reference}\"")),
                "{shown}"
            );
            assert!(!shown.contains(REDACTED_SECRET), "{shown}");
        }
    }

    #[test]
    fn the_redactor_leaves_unrelated_keys_alone() {
        let body = "[server]\nport = 11436\nmodel = \"gpt-4o\"\nkey = \"secret\"\n";
        let redacted = redact_secrets_in_toml(body);
        assert!(redacted.contains("port = 11436"), "{redacted}");
        assert!(redacted.contains("model = \"gpt-4o\""), "{redacted}");
        assert!(redacted.contains("key = \"<redacted>\""), "{redacted}");
        assert!(!redacted.contains("\"secret\""), "{redacted}");
    }

    #[test]
    fn a_config_using_removed_health_knobs_still_loads() {
        // `slow_latency_ms` and `recovery_threshold` are gone: the first made
        // health depend on latency, which reported working keys as unhealthy,
        // and the second was read and then discarded, so it never did anything.
        // Removing a key must not break an existing config file, so this pins
        // that serde ignores the unknown ones.
        let toml = r#"
[server]
port = 11436

[health]
enabled = true
slow_latency_ms = 5000
recovery_threshold = 2
unhealthy_threshold = 0.3

[[providers]]
name = "p"
base_url = "http://127.0.0.1:1"
[[providers.api_keys]]
id = "k"
key = "s"
models = ["m"]
"#;
        let config: Config = toml::from_str(toml).expect("an older config must still load");
        assert_eq!(config.health.unhealthy_threshold, 0.3);
        assert!(config.health.enabled);
    }

    #[test]
    fn every_credential_spelling_is_recognised() {
        for key in ["token", "key", "api_key", "password", "secret"] {
            assert!(is_credential_key(key), "{key} should be redacted");
        }
        for key in ["port", "model", "host", "strategy", "path", "name"] {
            assert!(!is_credential_key(key), "{key} should not be redacted");
        }
    }

    // --- providers: the two accepted shapes --------------------------------

    /// The array form is the 1.x shape and must keep working unchanged.
    #[test]
    fn the_list_form_still_parses() {
        let config: Config = toml::from_str(
            r#"
[server]
host = "127.0.0.1"
port = 11436

[[providers]]
name = "openai"
base_url = "https://api.openai.com"

[[providers.api_keys]]
id = "k1"
key = "sk-test"
"#,
        )
        .expect("a list-form config must load");
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].name, "openai");
        assert_eq!(config.providers[0].api_keys.len(), 1);
    }

    /// The map form carries the name in the table path, so `name` is absent
    /// from the table and has to come from the key.
    #[test]
    fn the_map_form_takes_the_name_from_the_table_key() {
        let config: Config = toml::from_str(
            r#"
[server]
host = "127.0.0.1"
port = 11436

[providers.openai]
base_url = "https://api.openai.com"

[[providers.openai.api_keys]]
id = "k1"
key = "sk-test"
"#,
        )
        .expect("a map-form config must load");
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].name, "openai");
        assert_eq!(config.providers[0].api_keys[0].id, "k1");
    }

    /// Provider order is the failover order, and a map that deserialised
    /// through a sorted table would silently reorder the pool alphabetically.
    /// `zebra` is declared first and must stay first -- this is the test that
    /// catches a dropped `preserve_order` or a `BTreeMap` substitution, both
    /// of which look like nothing at all until traffic fails over wrongly.
    #[test]
    fn the_map_form_keeps_document_order() {
        let config: Config = toml::from_str(
            r#"
[server]
host = "127.0.0.1"
port = 11436

[providers.zebra]
base_url = "https://zebra.test"
[[providers.zebra.api_keys]]
id = "z1"
key = "sk-z"

[providers.alpha]
base_url = "https://alpha.test"
[[providers.alpha.api_keys]]
id = "a1"
key = "sk-a"
"#,
        )
        .expect("a map-form config must load");
        let names: Vec<&str> = config.providers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["zebra", "alpha"],
            "provider order must be document order"
        );
    }

    /// Naming the provider twice, with two different answers, is ambiguous
    /// rather than helpful.
    #[test]
    fn the_map_form_rejects_a_conflicting_name() {
        let error = toml::from_str::<Config>(
            r#"
[server]
host = "127.0.0.1"
port = 11436

[providers.zebra]
name = "alpha"
base_url = "https://zebra.test"
[[providers.zebra.api_keys]]
id = "z1"
key = "sk-z"
"#,
        )
        .expect_err("a mismatched name must be refused");
        assert!(error.to_string().contains("table key"), "{error}");
    }

    /// A provider with no keys can never serve a request, so a config holding
    /// one does not work. `[[openai.api_keys]]` is why this matters: it is
    /// valid TOML, it attaches nothing, and the broker used to start anyway
    /// and fail every request through an empty pool.
    #[test]
    fn a_provider_with_no_keys_is_refused() {
        let config: Config = toml::from_str(
            r#"
[server]
host = "127.0.0.1"
port = 11436

[[providers]]
name = "openai"
base_url = "https://api.openai.com"

[[openai.api_keys]]
id = "k1"
key = "sk-test"
"#,
        )
        .expect("the document parses; it is validation that refuses it");
        let error = config
            .validate()
            .expect_err("an empty pool must be refused");
        let message = error.to_string();
        assert!(message.contains("has no keys"), "{message}");
        // The message must name the syntax that works, because the author's
        // mistake is believing their own does.
        assert!(
            message.contains("[[providers.openai.api_keys]]"),
            "{message}"
        );
    }

    /// The list form has no table key to fall back on, so a missing `name`
    /// becomes a nameless provider rather than a parse error.
    #[test]
    fn a_nameless_list_provider_is_refused() {
        let config: Config = toml::from_str(
            r#"
[server]
host = "127.0.0.1"
port = 11436

[[providers]]
base_url = "https://api.openai.com"
[[providers.api_keys]]
id = "k1"
key = "sk-test"
"#,
        )
        .expect("the document parses");
        let error = config
            .validate()
            .expect_err("a nameless provider must be refused");
        assert!(error.to_string().contains("no name"), "{error}");
    }
}
