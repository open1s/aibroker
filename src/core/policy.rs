//! Egress policy, evaluated as Rego.
//!
//! Every request that is about to leave the machine is decided by a Rego
//! policy rather than by hardcoded rules. That matters for the security half of
//! the broker: "may this client send this model to this provider" is an
//! organisational question that changes per deployment, and a policy language
//! lets an operator read, review and test it — and hand it to someone who does
//! not write Rust.
//!
//! The engine is [`regorus`], Microsoft's Rego implementation. The policy
//! receives the facts of the request as `input` and answers with
//! `data.llm.authz.allow`. Facts are deliberately *decisions already made* plus
//! the raw request attributes, so policy cannot be used to bypass constant-time
//! token comparison:
//!
//! ```json
//! {
//!   "auth":    { "ok": true, "scheme": "bearer" },
//!   "client":  { "name": "laptop", "enabled": true,
//!                "allowed_models": ["gpt-*"], "allowed_providers": ["openai"] },
//!   "request": { "model": "gpt-4o", "path": "/v1/chat/completions",
//!                "stream": true, "estimated_tokens": 1200 },
//!   "route":   { "providers": ["openai"], "matched": "gpt-*" },
//!   "budget":  { "allowed": true }
//! }
//! ```
//!
//! A policy error is treated as a **denial**: a broker that forwards traffic
//! when its policy engine is broken is worse than one that returns 500.

use std::path::Path;
use std::sync::Mutex;

use regorus::Engine;
use serde::Serialize;

use crate::config::PolicyConfig;
use crate::error::{LlmBrokerError, Result};

/// Where the decision came from, for audit lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    /// No policy configured: the built-in default decides.
    Default,
    /// A configured Rego policy decided.
    Rego,
}

/// The policy's answer.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub allowed: bool,
    /// Short machine-facing reason, e.g. `model_not_allowed`.
    pub reason: String,
    pub source: PolicySource,
}

impl PolicyDecision {
    fn allow(reason: impl Into<String>, source: PolicySource) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
            source,
        }
    }

    fn deny(reason: impl Into<String>, source: PolicySource) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            source,
        }
    }

    pub fn is_denied(&self) -> bool {
        !self.allowed
    }
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self::allow("default", PolicySource::Default)
    }
}

/// Facts handed to the policy.
#[derive(Debug, Clone, Serialize)]
pub struct RequestFacts<'a> {
    pub auth: AuthFacts,
    pub client: ClientFacts<'a>,
    pub request: RequestInfo<'a>,
    pub route: RouteFacts<'a>,
    pub budget: BudgetFacts,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthFacts {
    /// Whether the caller passed client authentication.
    pub ok: bool,
    /// `none`, `bearer`, or `api-key`.
    pub scheme: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientFacts<'a> {
    pub name: Option<&'a str>,
    pub enabled: bool,
    /// The configured patterns, for a policy that wants to see them.
    pub allowed_models: &'a [String],
    pub allowed_providers: &'a [String],
    /// Whether the requested model satisfies the client's allow-list.
    ///
    /// Computed in Rust rather than in Rego on purpose: pattern matching is
    /// already implemented and tested in [`crate::core::broker::glob_match`],
    /// and the policy receives the *result*, so a policy cannot disagree with
    /// the rest of the broker about what a pattern means.
    pub model_allowed: bool,
    /// Whether any provider on the route satisfies the client's allow-list.
    pub provider_allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestInfo<'a> {
    pub model: Option<&'a str>,
    pub path: &'a str,
    pub method: &'a str,
    pub stream: bool,
    pub estimated_tokens: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteFacts<'a> {
    /// Providers the route would try, in order.
    pub providers: &'a [String],
    /// The route pattern that matched, if any.
    pub matched: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BudgetFacts {
    /// Whether the client's rate/concurrency budget allowed the request.
    pub allowed: bool,
}

/// The query a policy must answer.
const DECISION_QUERY: &str = "data.llm.authz.allow";

/// Built-in policy, used when the config declares none.
///
/// Mirrors the previous hardcoded behaviour exactly, so upgrading does not
/// change who can reach what: an unauthenticated setup stays open, an
/// authenticated client is held to its allow-lists, and a client over budget is
/// refused.
pub const DEFAULT_POLICY: &str = r#"package llm.authz

import rego.v1

default allow := false

# No clients are configured: the proxy is open, matching earlier behaviour.
#
# `is_string` rather than a bare truthiness test: Rego treats a present `null`
# as defined, so `not input.client.name` is false when the field exists but is
# null, which is exactly what the broker sends for an unauthenticated setup.
allow if {
    not is_string(input.client.name)
}

# An authenticated, enabled client, within budget.
allow if {
    is_string(input.client.name)
    input.client.enabled
    input.auth.ok
    input.budget.allowed
    model_allowed
    provider_allowed
}

# The allow-list verdicts are computed by the broker and passed in as facts,
# so a `*` pattern means the same thing everywhere (and `gpt-*` matches
# `deepseek-ai/deepseek-v4.1-flash`, which OPA's `glob.match` would not: its
# default delimiter is `.`). A policy that needs its own matching can still use
# `glob.match`/`regex.match` -- both builtins are compiled in.
model_allowed if {
    input.client.model_allowed
}

provider_allowed if {
    input.client.provider_allowed
}
"#;

/// A compiled policy, ready to evaluate.
pub struct PolicyEngine {
    engine: Mutex<Engine>,
    source: PolicySource,
    /// Where the policy came from, for the admin API.
    description: String,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The compiled engine is not Debug; the provenance is what matters in
        // a test failure or a log line.
        f.debug_struct("PolicyEngine")
            .field("source", &self.source)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

impl PolicyEngine {
    /// Compile the policy from config.
    ///
    /// Files are read in the order given and may `import` each other by
    /// package; the built-in default is *not* included when a policy is
    /// configured, so an operator's policy is the whole story.
    pub fn from_config(config: &PolicyConfig) -> Result<Self> {
        if !config.enabled {
            return Self::builtin();
        }

        if config.files.is_empty() && config.inline.trim().is_empty() {
            return Self::builtin();
        }

        // regorus 0.12 parses Rego v1 by default; `set_rego_v0` is the opt-out.
        let mut engine = Engine::new();
        let mut sources = Vec::new();
        for path in &config.files {
            let source = std::fs::read_to_string(path).map_err(|e| {
                LlmBrokerError::InvalidConfig(format!("cannot read policy file `{path}`: {e}"))
            })?;
            engine
                .add_policy(path.clone(), source)
                .map_err(|e| policy_error(path, &e))?;
            sources.push(path.clone());
        }

        if !config.inline.trim().is_empty() {
            let name = config.inline_name.clone();
            engine
                .add_policy(name.clone(), config.inline.clone())
                .map_err(|e| policy_error(&name, &e))?;
            sources.push(name);
        }

        // Compile once here so a syntax or reference error fails at startup,
        // not on the first request.
        engine
            .eval_bool_query(DECISION_QUERY.to_string(), false)
            .map_err(|e| policy_error(&sources.join(", "), &e))?;

        Ok(Self {
            engine: Mutex::new(engine),
            source: PolicySource::Rego,
            description: sources.join(", "),
        })
    }

    /// The built-in default policy.
    pub fn builtin() -> Result<Self> {
        let mut engine = Engine::new();
        engine
            .add_policy("builtin.rego".to_string(), DEFAULT_POLICY.to_string())
            .map_err(|e| policy_error("builtin.rego", &e))?;
        Ok(Self {
            engine: Mutex::new(engine),
            source: PolicySource::Default,
            description: "built-in default".to_string(),
        })
    }

    /// Compile a **shadow** policy: evaluated on live traffic, never enforced.
    ///
    /// `None` when nothing is configured, so the caller has nothing to skip.
    pub fn from_dry_run(config: &PolicyConfig) -> Result<Option<Self>> {
        let from_file = config.dry_run.as_deref().filter(|p| !p.trim().is_empty());
        let from_inline = config
            .dry_run_inline
            .as_deref()
            .filter(|p| !p.trim().is_empty());
        if from_file.is_none() && from_inline.is_none() {
            return Ok(None);
        }

        let mut engine = Engine::new();
        let mut sources = Vec::new();
        if let Some(path) = from_file {
            let source = std::fs::read_to_string(path).map_err(|e| {
                LlmBrokerError::InvalidConfig(format!(
                    "cannot read shadow policy file `{path}`: {e}"
                ))
            })?;
            engine
                .add_policy(path.to_string(), source)
                .map_err(|e| policy_error(path, &e))?;
            sources.push(path.to_string());
        }
        if let Some(source) = from_inline {
            let name = format!("{}.shadow", config.inline_name);
            engine
                .add_policy(name.clone(), source.to_string())
                .map_err(|e| policy_error(&name, &e))?;
            sources.push(name);
        }
        // Compile now: a shadow policy with a syntax error is a configuration
        // mistake, and finding it at startup is the point.
        engine
            .eval_bool_query(DECISION_QUERY.to_string(), false)
            .map_err(|e| policy_error(&sources.join(", "), &e))?;

        Ok(Some(Self {
            engine: Mutex::new(engine),
            source: PolicySource::Rego,
            description: sources.join(", "),
        }))
    }

    /// Load and compile a policy from a file, for tests and tooling.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_string_lossy().to_string();
        Self::from_config(&PolicyConfig {
            enabled: true,
            files: vec![path],
            ..PolicyConfig::default()
        })
    }

    /// Compile an in-memory policy, for tests.
    pub fn from_source(source: &str) -> Result<Self> {
        Self::from_config(&PolicyConfig {
            enabled: true,
            inline: source.to_string(),
            ..PolicyConfig::default()
        })
    }

    pub fn source(&self) -> PolicySource {
        self.source
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    /// Evaluate the policy for one request.
    pub fn check(&self, facts: &RequestFacts<'_>) -> Result<PolicyDecision> {
        let input = serde_json::to_string(facts).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot encode policy input: {e}"))
        })?;

        let mut engine = self.engine.lock().expect("policy engine poisoned");
        engine
            .set_input_json(&input)
            .map_err(|e| LlmBrokerError::InvalidConfig(format!("cannot set policy input: {e}")))?;
        let allowed = engine
            .eval_bool_query(DECISION_QUERY.to_string(), false)
            .map_err(|e| policy_error(&self.description, &e))?;

        // A policy may explain itself with `data.llm.authz.reason`; otherwise
        // the broker derives a reason from which client rule failed.
        let reason = engine
            .eval_rule("data.llm.authz.reason".to_string())
            .ok()
            .and_then(|value| match value {
                regorus::Value::String(s) => Some(s.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| derive_reason(facts, allowed).to_string());

        Ok(if allowed {
            PolicyDecision::allow(reason, self.source)
        } else {
            PolicyDecision::deny(reason, self.source)
        })
    }
}

/// Build the facts for a request from the authenticated client and the route.
///
/// This is the bridge between Rust-side mechanics (authentication, budgets,
/// pattern matching) and the Rego policy. `auth_ok` and `budget_ok` are
/// decisions Rust already made; the policy may deny on top of them but cannot
/// use them to bypass constant-time token comparison.
#[allow(clippy::too_many_arguments)]
pub fn build_facts<'a>(
    client: Option<&'a crate::core::security::ClientAccess>,
    auth_ok: bool,
    auth_scheme: &'static str,
    model: Option<&'a str>,
    path: &'a str,
    method: &'a str,
    stream: bool,
    estimated_tokens: u64,
    providers: &'a [String],
    matched: Option<&'a str>,
    budget_ok: bool,
) -> RequestFacts<'a> {
    const EMPTY: &[String] = &[];
    let (allowed_models, allowed_providers) = match client {
        Some(client) => (client.allowed_models(), client.allowed_providers()),
        None => (EMPTY, EMPTY),
    };
    let model_allowed = match client {
        Some(client) => client.permits_model(model),
        None => true,
    };
    let provider_allowed = match client {
        Some(client) => client.permits_any_provider(providers.iter().map(String::as_str)),
        None => true,
    };

    RequestFacts {
        auth: AuthFacts {
            ok: auth_ok,
            scheme: auth_scheme,
        },
        client: ClientFacts {
            name: client.map(|c| c.name.as_str()),
            enabled: client.map(|c| c.is_enabled()).unwrap_or(true),
            allowed_models,
            allowed_providers,
            model_allowed,
            provider_allowed,
        },
        request: RequestInfo {
            model,
            path,
            method,
            stream,
            estimated_tokens,
        },
        route: RouteFacts { providers, matched },
        budget: BudgetFacts { allowed: budget_ok },
    }
}

/// Explain a decision when the policy does not.
///
/// The two directions are separate on purpose. This used to describe only why a
/// request was *refused*, and was then also used for the allowed case, so a
/// successful request was audited with `reason="denied_by_policy"` -- a log line
/// that contradicted its own status code.
fn derive_reason(facts: &RequestFacts<'_>, allowed: bool) -> &'static str {
    if allowed {
        return if facts.client.name.is_some() {
            "client_admitted"
        } else {
            "open_proxy"
        };
    }

    if !facts.budget.allowed {
        return "client_budget_exhausted";
    }
    if facts.client.name.is_some() && !facts.auth.ok {
        return "client_not_authenticated";
    }
    if facts.client.name.is_some() && !facts.client.enabled {
        return "client_disabled";
    }
    // The allow-list verdicts name the actual rule that failed. Without these
    // a refusal for a model read `denied_by_policy`, which tells an operator
    // nothing about what to change.
    if !facts.client.model_allowed {
        return "model_forbidden";
    }
    if !facts.client.provider_allowed {
        return "provider_forbidden";
    }
    if facts.request.model.is_none() && !facts.client.allowed_models.is_empty() {
        return "model_unknown";
    }
    if facts.route.providers.is_empty() {
        return "no_provider_available";
    }
    "denied_by_policy"
}

fn policy_error(source: &str, error: &impl std::fmt::Display) -> LlmBrokerError {
    LlmBrokerError::InvalidConfig(format!("invalid policy `{source}`: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn facts<'a>(
        client: Option<&'a str>,
        enabled: bool,
        allowed_models: &'a [String],
        allowed_providers: &'a [String],
        model: Option<&'a str>,
        providers: &'a [String],
        auth_ok: bool,
        budget_ok: bool,
    ) -> RequestFacts<'a> {
        RequestFacts {
            auth: AuthFacts {
                ok: auth_ok,
                scheme: if auth_ok { "bearer" } else { "none" },
            },
            client: ClientFacts {
                name: client,
                enabled,
                allowed_models,
                allowed_providers,
                model_allowed: allowed_models.is_empty()
                    || model.is_some_and(|m| {
                        allowed_models
                            .iter()
                            .any(|p| crate::core::security::pattern_matches(p, m))
                    }),
                provider_allowed: allowed_providers.is_empty()
                    || providers.iter().any(|p| {
                        allowed_providers
                            .iter()
                            .any(|pattern| crate::core::security::pattern_matches(pattern, p))
                    }),
            },
            request: RequestInfo {
                model,
                path: "/v1/chat/completions",
                method: "POST",
                stream: false,
                estimated_tokens: 10,
            },
            route: RouteFacts {
                providers,
                matched: None,
            },
            budget: BudgetFacts { allowed: budget_ok },
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn the_default_policy_keeps_a_single_user_setup_open() {
        let policy = PolicyEngine::builtin().unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);
        let facts = facts(
            None,
            true,
            &empty,
            &empty,
            Some("gpt-4o"),
            &providers,
            false,
            true,
        );
        let decision = policy.check(&facts).unwrap();
        assert!(decision.allowed, "an unconfigured proxy must stay usable");
        assert_eq!(decision.source, PolicySource::Default);
    }

    #[test]
    fn the_default_policy_admits_an_authenticated_client() {
        let policy = PolicyEngine::builtin().unwrap();
        let models = strings(&["gpt-*"]);
        let providers = strings(&["openai", "azure"]);
        let client_providers = strings(&["openai"]);
        let facts = facts(
            Some("laptop"),
            true,
            &models,
            &client_providers,
            Some("gpt-4o"),
            &providers,
            true,
            true,
        );
        assert!(policy.check(&facts).unwrap().allowed);
    }

    #[test]
    fn the_default_policy_matches_model_patterns_across_separators() {
        // Regression: `glob.match`'s default delimiter is `.`, so real model
        // names (which contain `/`, `-` and `.`) never matched a `*` pattern.
        let policy = PolicyEngine::builtin().unwrap();
        let providers = strings(&["nvidia"]);

        for (pattern, model, expected) in [
            ("gpt-*", "gpt-4o", true),
            ("gpt-*", "gpt-4o-mini", true),
            ("deepseek*", "deepseek-ai/deepseek-v4.1-flash", true),
            ("*v4*", "deepseek-ai/deepseek-v4.1-flash", true),
            ("claude-?", "claude-3", true),
            ("claude-?", "claude-35", false),
            ("gpt-*", "claude-3", false),
            ("GPT-4O", "gpt-4o", true),
        ] {
            let models = strings(&[pattern]);
            let facts = facts(
                Some("c"),
                true,
                &models,
                &providers,
                Some(model),
                &providers,
                true,
                true,
            );
            let allowed = policy.check(&facts).unwrap().allowed;
            assert_eq!(allowed, expected, "pattern `{pattern}` vs `{model}`");
        }
    }

    #[test]
    fn a_policy_pattern_is_not_treated_as_a_regex() {
        // A pattern containing regex metacharacters must be matched literally.
        let policy = PolicyEngine::builtin().unwrap();
        let providers = strings(&["openai"]);
        let models = strings(&["gpt-4o"]);

        let literal = facts(
            Some("c"),
            true,
            &models,
            &providers,
            Some("gpt-4o"),
            &providers,
            true,
            true,
        );
        assert!(policy.check(&literal).unwrap().allowed);

        // `gpt-4o` must not match `gptX4o`, which a `.` left as a regex would.
        let dot_as_wildcard = facts(
            Some("c"),
            true,
            &models,
            &providers,
            Some("gptX4o"),
            &providers,
            true,
            true,
        );
        assert!(policy.check(&dot_as_wildcard).unwrap().is_denied());
    }

    #[test]
    fn the_default_policy_denies_a_model_outside_the_allow_list() {
        let policy = PolicyEngine::builtin().unwrap();
        let models = strings(&["gpt-*"]);
        let providers = strings(&["openai"]);
        let facts = facts(
            Some("laptop"),
            true,
            &models,
            &providers,
            Some("claude-3-5-sonnet"),
            &providers,
            true,
            true,
        );
        let decision = policy.check(&facts).unwrap();
        assert!(decision.is_denied());
        // The reason names the rule that failed, not a generic denial.
        assert_eq!(decision.reason, "model_forbidden");
    }

    #[test]
    fn the_default_policy_denies_a_provider_outside_the_allow_list() {
        let policy = PolicyEngine::builtin().unwrap();
        let empty: Vec<String> = Vec::new();
        let allowed = strings(&["openai"]);
        let providers = strings(&["anthropic"]);
        let facts = facts(
            Some("laptop"),
            true,
            &empty,
            &allowed,
            Some("claude-3"),
            &providers,
            true,
            true,
        );
        assert!(policy.check(&facts).unwrap().is_denied());
    }

    #[test]
    fn the_default_policy_denies_an_unauthenticated_client() {
        let policy = PolicyEngine::builtin().unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);
        let facts = facts(
            Some("laptop"),
            true,
            &empty,
            &empty,
            Some("gpt-4o"),
            &providers,
            false,
            true,
        );
        let decision = policy.check(&facts).unwrap();
        assert!(decision.is_denied());
        assert_eq!(decision.reason, "client_not_authenticated");
    }

    #[test]
    fn the_default_policy_denies_a_client_over_budget() {
        let policy = PolicyEngine::builtin().unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);
        let facts = facts(
            Some("laptop"),
            true,
            &empty,
            &empty,
            Some("gpt-4o"),
            &providers,
            true,
            false,
        );
        let decision = policy.check(&facts).unwrap();
        assert!(decision.is_denied());
        assert_eq!(decision.reason, "client_budget_exhausted");
    }

    #[test]
    fn the_default_policy_denies_a_disabled_client() {
        let policy = PolicyEngine::builtin().unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);
        let facts = facts(
            Some("laptop"),
            false,
            &empty,
            &empty,
            Some("gpt-4o"),
            &providers,
            true,
            true,
        );
        assert!(policy.check(&facts).unwrap().is_denied());
    }

    #[test]
    fn a_policy_can_deny_everything() {
        let policy = PolicyEngine::from_source(
            r#"package llm.authz
import rego.v1
default allow := false
"#,
        )
        .unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);
        let facts = facts(
            None,
            true,
            &empty,
            &empty,
            Some("gpt-4o"),
            &providers,
            true,
            true,
        );
        let decision = policy.check(&facts).unwrap();
        assert!(decision.is_denied());
        assert_eq!(decision.source, PolicySource::Rego);
    }

    #[test]
    fn a_policy_can_allow_everything() {
        let policy = PolicyEngine::from_source(
            r#"package llm.authz
import rego.v1
default allow := true
"#,
        )
        .unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);
        let facts = facts(None, true, &empty, &empty, None, &providers, false, false);
        assert!(policy.check(&facts).unwrap().allowed);
    }

    #[test]
    fn a_policy_can_explain_its_denial() {
        let policy = PolicyEngine::from_source(
            r#"package llm.authz
import rego.v1
default allow := false
reason := "only gpt-4o is permitted" if {
    input.request.model != "gpt-4o"
}
"#,
        )
        .unwrap();
        let empty: Vec<String> = Vec::new();
        // `empty` is used below via `&empty`; keep the binding meaningful.
        let providers = strings(&["openai"]);
        let facts = facts(
            None,
            true,
            &empty,
            &empty,
            Some("gpt-3.5"),
            &providers,
            true,
            true,
        );
        let decision = policy.check(&facts).unwrap();
        assert!(decision.is_denied());
        assert_eq!(decision.reason, "only gpt-4o is permitted");
    }

    #[test]
    fn a_policy_can_scope_by_estimated_tokens() {
        // A size ceiling: a data-security control, e.g. keep large contexts
        // away from a third-party provider.
        let policy = PolicyEngine::from_source(
            r#"package llm.authz
import rego.v1
default allow := false
allow if input.request.estimated_tokens <= 1000
reason := "context too large" if input.request.estimated_tokens > 1000
"#,
        )
        .unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);

        let mut small = facts(
            None,
            true,
            &empty,
            &empty,
            Some("m"),
            &providers,
            true,
            true,
        );
        small.request.estimated_tokens = 500;
        assert!(policy.check(&small).unwrap().allowed);

        let mut large = facts(
            None,
            true,
            &empty,
            &empty,
            Some("m"),
            &providers,
            true,
            true,
        );
        large.request.estimated_tokens = 5000;
        let decision = policy.check(&large).unwrap();
        assert!(decision.is_denied());
        assert_eq!(decision.reason, "context too large");
    }

    #[test]
    fn a_policy_can_restrict_streaming() {
        let policy = PolicyEngine::from_source(
            r#"package llm.authz
import rego.v1
default allow := false
allow if not input.request.stream
reason := "streaming is not permitted" if input.request.stream
"#,
        )
        .unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);

        let buffered = facts(
            None,
            true,
            &empty,
            &empty,
            Some("m"),
            &providers,
            true,
            true,
        );
        assert!(policy.check(&buffered).unwrap().allowed);

        let mut streamed = facts(
            None,
            true,
            &empty,
            &empty,
            Some("m"),
            &providers,
            true,
            true,
        );
        streamed.request.stream = true;
        assert!(policy.check(&streamed).unwrap().is_denied());
    }

    #[test]
    fn an_invalid_policy_fails_at_construction_not_per_request() {
        let error = PolicyEngine::from_source("package llm.authz\nthis is not rego")
            .expect_err("a broken policy must be rejected up front");
        assert!(error.to_string().contains("invalid policy"), "{error}");
    }

    #[test]
    fn a_policy_missing_the_allow_rule_is_rejected() {
        // Silently defaulting here would be a fail-open bug.
        let error = PolicyEngine::from_source("package llm.authz\nimport rego.v1\nx := 1\n")
            .expect_err("a policy without `allow` must not compile into a decision");
        assert!(error.to_string().contains("invalid policy"), "{error}");
    }

    #[test]
    fn the_shipped_example_policy_compiles_and_behaves() {
        // `policy.example.rego` is documentation, and documentation rots. This
        // compiles the real file with the real engine, so a change to the
        // builtins or a typo in an example is caught here.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.example.rego");
        let policy = PolicyEngine::from_file(&path).expect("the example policy must compile");

        // Its rules 1 and 2 mirror the default policy.
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);

        let unauthenticated = facts(
            None,
            true,
            &empty,
            &empty,
            Some("gpt-4o"),
            &providers,
            false,
            true,
        );
        assert!(policy.check(&unauthenticated).unwrap().allowed);

        let models = strings(&["gpt-*"]);
        let client_providers = strings(&["openai"]);
        let admitted = facts(
            Some("laptop"),
            true,
            &models,
            &client_providers,
            Some("gpt-4o"),
            &providers,
            true,
            true,
        );
        assert!(policy.check(&admitted).unwrap().allowed);

        // And it explains a model refusal in words.
        let refused = facts(
            Some("laptop"),
            true,
            &models,
            &client_providers,
            Some("claude-3"),
            &providers,
            true,
            true,
        );
        let decision = policy.check(&refused).unwrap();
        assert!(decision.is_denied());
        assert_eq!(decision.reason, "this client may not use that model");
    }

    #[test]
    fn an_allowed_decision_is_never_described_as_a_denial() {
        // Regression: the audit reason for a 200 read `denied_by_policy`,
        // contradicting the status it was logged beside.
        let policy = PolicyEngine::builtin().unwrap();
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);

        let open = facts(
            None,
            true,
            &empty,
            &empty,
            Some("m"),
            &providers,
            false,
            true,
        );
        let decision = policy.check(&open).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.reason, "open_proxy");

        let models = strings(&["gpt-*"]);
        let admitted = facts(
            Some("laptop"),
            true,
            &models,
            &providers,
            Some("gpt-4o"),
            &providers,
            true,
            true,
        );
        let decision = policy.check(&admitted).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.reason, "client_admitted");
        assert!(!decision.reason.contains("denied"), "{}", decision.reason);
    }

    #[test]
    fn a_disabled_policy_config_uses_the_builtin() {
        let config = PolicyConfig {
            enabled: false,
            ..PolicyConfig::default()
        };
        let policy = PolicyEngine::from_config(&config).unwrap();
        assert_eq!(policy.source(), PolicySource::Default);
    }

    #[test]
    fn policy_state_is_isolated_between_evaluations() {
        // Two different inputs must not leak into each other through the
        // reused engine.
        let policy = PolicyEngine::builtin().unwrap();
        let models = strings(&["gpt-4o"]);
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);

        let allowed = facts(
            Some("c"),
            true,
            &models,
            &empty,
            Some("gpt-4o"),
            &providers,
            true,
            true,
        );
        let denied = facts(
            Some("c"),
            true,
            &models,
            &empty,
            Some("llama-3"),
            &providers,
            true,
            true,
        );

        assert!(policy.check(&allowed).unwrap().allowed);
        assert!(policy.check(&denied).unwrap().is_denied());
        assert!(policy.check(&allowed).unwrap().allowed, "state leaked");
    }
}
