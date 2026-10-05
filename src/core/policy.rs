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

/// The rule a policy uses to decide what to do about a content finding.
///
/// A *path*, not a compiled rule, because the broker does not require it: a
/// policy written before content control existed keeps working, and the
/// configured `[content_guard] action` decides. Declaring the path in the
/// config (`policy.content_rule`) makes its absence a startup error instead.
pub const CONTENT_QUERY: &str = "data.llm.content.action";

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
/// Read every `*.rego` under `dir`, in a deterministic order, as
/// `(relative path, source)` pairs.
///
/// A directory beats one growing file for review: `10-clients.rego`,
/// `20-models.rego`, `30-content.rego` can be owned and diffed separately.
/// Regorus merges modules by *package*, so several files may contribute to
/// `package llm.authz` and a file may hold its own package that others
/// reference through `data`.
///
/// The order is the sorted relative path, so two runs compile the same way and
/// a failure names the file rather than a line number in a concatenation that
/// exists nowhere on disk. Only the extension is considered: hidden files and
/// editors' backup files are skipped, since a stray `.#policy.rego` symlink
/// would otherwise be read as an empty or looping module.
pub fn load_rego_dir(dir: &Path) -> Result<Vec<(String, String)>> {
    fn walk(dir: &Path, prefix: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!(
                "cannot read policy directory `{}`: {e}",
                dir.display()
            ))
        })?;
        // Collect first so the order does not depend on the filesystem.
        let mut paths: Vec<std::path::PathBuf> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                LlmBrokerError::InvalidConfig(format!(
                    "cannot read policy directory `{}`: {e}",
                    dir.display()
                ))
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                continue;
            }
            paths.push(entry.path());
        }
        paths.sort();
        for path in paths {
            let relative = prefix.join(path.file_name().unwrap_or_default());
            let meta = std::fs::symlink_metadata(&path).map_err(|e| {
                LlmBrokerError::InvalidConfig(format!(
                    "cannot inspect policy entry `{}`: {e}",
                    path.display()
                ))
            })?;
            // `symlink_metadata` does not follow the link, so a directory
            // symlink loop cannot trap the walk.
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                walk(&path, &relative, out)?;
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rego") {
                continue;
            }
            let source = std::fs::read_to_string(&path).map_err(|e| {
                LlmBrokerError::InvalidConfig(format!(
                    "cannot read policy file `{}`: {e}",
                    path.display()
                ))
            })?;
            out.push((relative.to_string_lossy().replace('\\', "/"), source));
        }
        Ok(())
    }

    if !dir.exists() {
        return Err(LlmBrokerError::InvalidConfig(format!(
            "policy directory `{}` does not exist",
            dir.display()
        )));
    }
    let mut out = Vec::new();
    walk(dir, Path::new(""), &mut out)?;
    if out.is_empty() {
        return Err(LlmBrokerError::InvalidConfig(format!(
            "policy directory `{}` contains no .rego files",
            dir.display()
        )));
    }
    Ok(out)
}

/// What the policy decided about a content finding.
#[derive(Debug, Clone)]
pub struct ContentVerdict {
    /// The action the policy named.
    pub action: crate::core::content::GuardAction,
    /// The policy's own explanation, if it gave one.
    pub reason: Option<String>,
}

/// The facts a content verdict is decided from.
///
/// **The matched text is deliberately absent.** Rego would receive it, the
/// engine keeps its input, and a policy can stringify anything it can see — so
/// passing the match in would turn the policy layer into a second copy of the
/// secret. A policy judges *which* rule matched, in which field, for which
/// client; judging the value itself is the pattern's job.
#[derive(Debug, Serialize)]
pub struct ContentFacts<'a> {
    pub rule: &'a str,
    pub field: &'a str,
    /// The action the config would apply, so a policy sees what it overrides.
    pub configured: &'static str,
    pub client: ContentClientFacts<'a>,
    pub request: ContentRequestFacts<'a>,
}

#[derive(Debug, Serialize)]
pub struct ContentClientFacts<'a> {
    pub name: Option<&'a str>,
    pub authenticated: bool,
}

#[derive(Debug, Serialize)]
pub struct ContentRequestFacts<'a> {
    pub model: Option<&'a str>,
    pub path: &'a str,
}

impl<'a> ContentFacts<'a> {
    pub fn new(
        finding: &'a crate::core::content::Finding,
        configured: crate::core::content::GuardAction,
        client: Option<&'a str>,
        authenticated: bool,
        model: Option<&'a str>,
        path: &'a str,
    ) -> Self {
        Self {
            rule: &finding.rule,
            field: &finding.field,
            configured: configured.as_str(),
            client: ContentClientFacts {
                name: client,
                authenticated,
            },
            request: ContentRequestFacts { model, path },
        }
    }
}

pub struct PolicyEngine {
    engine: Mutex<Engine>,
    source: PolicySource,
    /// Where the policy came from, for the admin API.
    description: String,
    /// The rule path that decides a content finding, when the policy defines
    /// one. `None` means the policy says nothing about content, so the
    /// configured `[content_guard] action` decides.
    content_path: Option<String>,
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

        // A directory of Rego is a policy too. Leaving `rules_dir` out of this
        // check meant an operator could point the broker at a directory of rules
        // and silently get the built-in default policy instead -- fail-open, and
        // invisible, because the broker still starts and still allows traffic.
        if config.files.is_empty()
            && config.inline.trim().is_empty()
            && config.rules_dir.trim().is_empty()
        {
            return Self::builtin();
        }

        let (engine, sources, content) = compile(config, None)?;
        Ok(Self {
            engine: Mutex::new(engine),
            source: PolicySource::Rego,
            description: sources.join(", "),
            content_path: content,
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
            // The default policy decides admission only. Content findings take
            // the configured action, which is what every deployment did before
            // a policy could speak about them.
            content_path: None,
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

        // A shadow is compiled on its own terms: only the candidate source, so
        // it cannot inherit the enforcing policy's rules and quietly agree with
        // the thing it is supposed to be testing.
        let (engine, sources, _) = compile(config, Some((from_file, from_inline)))?;
        Ok(Some(Self {
            engine: Mutex::new(engine),
            source: PolicySource::Rego,
            description: sources.join(", "),
            // A shadow never decides anything, so it carries no content rule.
            content_path: None,
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

    /// Ask the policy what to do about a content finding.
    ///
    /// `Ok(None)` means the policy says nothing about content, so the caller
    /// keeps the configured `[content_guard] action`. An `Err` is a **refusal**:
    /// this is a security decision, and a policy engine that cannot answer is
    /// not a reason to let the body through.
    ///
    /// The matched text is never passed in -- only the rule name, the field and
    /// the request facts -- so the engine cannot become a second copy of the
    /// secret it is judging.
    pub fn content_verdict(&self, facts: &ContentFacts<'_>) -> Result<Option<ContentVerdict>> {
        let Some(path) = self.content_path.as_deref() else {
            return Ok(None);
        };

        let input = serde_json::to_string(facts).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot encode content facts: {e}"))
        })?;
        let mut engine = self.engine.lock().expect("policy engine poisoned");
        engine.set_input_json(&input).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot set content policy input: {e}"))
        })?;

        let action = match engine.eval_rule(path.to_string()) {
            Ok(regorus::Value::String(action)) => action.to_string(),
            // No `default` and no branch matched this finding. Refusing is the
            // fail-closed answer, and the startup message already says a
            // `default` is what prevents this.
            Ok(regorus::Value::Undefined) | Ok(regorus::Value::Object(_)) => {
                return Err(LlmBrokerError::InvalidConfig(format!(
                    "content rule `{path}` is undefined for `{}`; give it a `default`",
                    facts.rule
                )));
            }
            Ok(other) => {
                return Err(LlmBrokerError::InvalidConfig(format!(
                    "content rule `{path}` returned {other:?}, expected a string action"
                )));
            }
            Err(e) => return Err(policy_error(&self.description, &e)),
        };

        let Some(action) = crate::core::content::GuardAction::parse(&action) else {
            return Err(LlmBrokerError::InvalidConfig(format!(
                "content rule `{path}` returned `{action}`, expected `report` or `deny`"
            )));
        };

        // `data.llm.content.action` -> `data.llm.content.reason`, so a policy can
        // explain itself without a second config knob.
        let reason = path
            .rsplit_once('.')
            .map(|(head, _)| format!("{head}.reason"))
            .and_then(|reason_path| {
                engine
                    .eval_rule(reason_path)
                    .ok()
                    .and_then(|value| match value {
                        regorus::Value::String(s) => Some(s.to_string()),
                        _ => None,
                    })
            });

        Ok(Some(ContentVerdict { action, reason }))
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

/// Build a regorus engine from the config: `files`, the `rules_dir`, and inline
/// source, then prove the decision rule exists.
///
/// Both the enforcing and the shadow engine come through here, so they cannot
/// disagree about which files a policy is made of. The shadow passes its own
/// file and inline source as `override_`, which replaces the enforcing ones.
///
/// A syntax error or a missing `allow` fails at startup, not on the first
/// request: a policy that silently fails open is the bug this module exists to
/// prevent.
fn compile(
    config: &PolicyConfig,
    override_: Option<(Option<&str>, Option<&str>)>,
) -> Result<(Engine, Vec<String>, Option<String>)> {
    // regorus 0.12 parses Rego v1 by default; `set_rego_v0` is the opt-out.
    let mut engine = Engine::new();
    let mut sources = Vec::new();

    // A shadow policy stands alone: it *replaces* the enforcing one rather than
    // extending it, so `rules_dir` is deliberately not loaded for it. Merging
    // the two would OR their `allow` bodies together, and the shadow would then
    // answer for the union of both policies instead of for the candidate.
    let shadow = override_.is_some();

    let files: Vec<String> = match override_ {
        Some((Some(path), _)) => vec![path.to_string()],
        Some((None, Some(_))) => Vec::new(),
        _ => config.files.clone(),
    };

    // The directory first: a policy split across files is the documented way to
    // grow one, and later sources may reference earlier packages.
    let dir = config.rules_dir.trim();
    if !dir.is_empty() && !shadow {
        for (name, source) in load_rego_dir(Path::new(dir))? {
            engine
                .add_policy(name.clone(), source)
                .map_err(|e| policy_error(&format!("{dir}/{name}"), &e))?;
            sources.push(format!("{dir}/{name}"));
        }
    }

    for path in &files {
        let source = std::fs::read_to_string(path).map_err(|e| {
            LlmBrokerError::InvalidConfig(format!("cannot read policy file `{path}`: {e}"))
        })?;
        engine
            .add_policy(path.clone(), source)
            .map_err(|e| policy_error(path, &e))?;
        sources.push(path.clone());
    }

    let inline = match override_ {
        Some((_, Some(source))) => Some(source.to_string()),
        _ => Some(config.inline.clone()),
    };
    if let Some(source) = inline.filter(|s| !s.trim().is_empty()) {
        let name = if shadow {
            format!("{}.shadow", config.inline_name)
        } else {
            config.inline_name.clone()
        };
        engine
            .add_policy(name.clone(), source)
            .map_err(|e| policy_error(&name, &e))?;
        sources.push(name);
    }

    engine
        .eval_bool_query(DECISION_QUERY.to_string(), false)
        .map_err(|e| policy_error(&sources.join(", "), &e))?;

    let content = discover_content_rule(&mut engine, config, &sources)?;
    Ok((engine, sources, content))
}

/// Decide whether the loaded policy speaks about content findings.
///
/// Regorus distinguishes "no such rule path" (an error) from "the rule exists
/// but its body did not match" (an `Undefined` value). Only the first is a
/// missing rule; the second is a policy whose conditions simply did not hold,
/// and inventing an action there would be a guess.
///
/// Absence is a fallback by default — a policy written before content control
/// existed keeps working on the configured action — but naming `content_rule`
/// in the config turns absence into a startup error, because then the operator
/// asked for something that is not there.
fn discover_content_rule(
    engine: &mut Engine,
    config: &PolicyConfig,
    sources: &[String],
) -> Result<Option<String>> {
    let required = !config.content_rule.trim().is_empty();
    let path = if required {
        config.content_rule.trim()
    } else {
        CONTENT_QUERY
    };

    // A representative input, so a rule carrying a `default` or an
    // unconditional body reads as present. A rule reachable only for one
    // specific rule name is still discovered here by its path, which is what
    // matters: the runtime call uses the real finding.
    let probe = serde_json::json!({
        "rule": "probe",
        "field": "probe",
        "configured": "report",
        "client": { "name": null, "authenticated": false },
        "request": { "model": null, "path": "/v1/chat/completions" },
    });
    engine
        .set_input_json(&probe.to_string())
        .map_err(|e| policy_error(&sources.join(", "), &e))?;
    // `Ok` means the *path* is valid, even when the value is `Undefined`
    // because no body matched this probe input: regorus reports a path that does
    // not exist as an `Err` instead. So a rule written without a `default` is
    // still discovered as "this policy speaks about content", and the runtime
    // refuses when it cannot answer.
    //
    // Treating `Undefined` as absent was the fail-open version, and it is worth
    // naming: the policy would silently fall back to the configured action, so a
    // rule that only ever denied *some* findings would look like it was working
    // while denying nothing.
    let found = match engine.eval_rule(path.to_string()) {
        Ok(_) => Some(path.to_string()),
        Err(error) => {
            let message = error.to_string();
            // An absent rule path is the one benign case: this policy simply
            // says nothing about content.
            if message.contains("not a valid rule path") {
                None
            } else {
                // Anything else is a broken rule in a package the admission
                // query never touched -- regorus compiles lazily, so an invalid
                // `default` in `llm.content` is invisible to the `allow` query.
                // Surfacing it here is the difference between a startup error
                // and a surprise on the first real finding.
                return Err(policy_error(&sources.join(", "), &error));
            }
        }
    };

    if found.is_none() && required {
        return Err(LlmBrokerError::InvalidConfig(format!(
            "policy `{}` does not define the content rule `{}`; either remove \
             `policy.content_rule` or add it (with a `default`, or it will be \
             undefined when its conditions do not hold)",
            sources.join(", "),
            path
        )));
    }
    Ok(found)
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

    use crate::core::content::{Finding, GuardAction};

    /// A temp directory of policy files, removed when the test ends.
    ///
    /// Named per test because tests share a process id and run in parallel.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str, files: &[(&str, &str)]) -> Self {
            let dir =
                std::env::temp_dir().join(format!("aibroker-policy-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("temp dir");
            for (file, source) in files {
                let path = dir.join(file);
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::write(&path, source).expect("write policy file");
            }
            Self(dir)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn finding(rule: &str) -> Finding {
        Finding {
            rule: rule.to_string(),
            field: "messages".to_string(),
        }
    }

    fn content_facts<'a>(
        finding: &'a Finding,
        configured: GuardAction,
        client: Option<&'a str>,
    ) -> ContentFacts<'a> {
        ContentFacts::new(
            finding,
            configured,
            client,
            client.is_some(),
            Some("gpt-4o"),
            "/v1/chat/completions",
        )
    }

    fn rules_dir_config(dir: &TempDir) -> PolicyConfig {
        PolicyConfig {
            enabled: true,
            rules_dir: dir.path().to_string_lossy().to_string(),
            ..PolicyConfig::default()
        }
    }

    const AUTHZ_ONLY: &str = "package llm.authz\nimport rego.v1\nallow := true\n";

    #[test]
    fn the_shipped_rules_directory_compiles_and_decides() {
        // `policy.example.d/` is documentation, and documentation rots. This
        // compiles the real files with the real engine and asks them real
        // questions, so a typo or a regorus change is caught here rather than by
        // an operator at 3am.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.example.d");
        let policy = PolicyEngine::from_config(&PolicyConfig {
            enabled: true,
            rules_dir: dir.to_string_lossy().to_string(),
            ..PolicyConfig::default()
        })
        .expect("the example rules directory must compile");

        // The admission half still answers.
        let empty: Vec<String> = Vec::new();
        let providers = strings(&["openai"]);
        let anonymous = facts(None, true, &empty, &empty, None, &providers, true, true);
        assert!(
            policy.check(&anonymous).unwrap().allowed,
            "a single-user setup stays open"
        );

        // A credential is refused whoever is asking...
        let credential = finding("openai-key");
        let verdict = policy
            .content_verdict(&content_facts(&credential, GuardAction::Report, None))
            .unwrap()
            .expect("the example policy speaks about content");
        assert_eq!(verdict.action, GuardAction::Deny);
        assert!(verdict.reason.is_some(), "and explains itself");

        // ...the per-client exception the config alone cannot express...
        let email = finding("email-address");
        let triage = policy
            .content_verdict(&content_facts(
                &email,
                GuardAction::Deny,
                Some("support-triage"),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(
            triage.action,
            GuardAction::Report,
            "support-triage may discuss customer identifiers"
        );
        let other = policy
            .content_verdict(&content_facts(&email, GuardAction::Report, Some("laptop")))
            .unwrap()
            .unwrap();
        assert_eq!(other.action, GuardAction::Deny, "nobody else may");

        // ...and a rule no branch mentions follows the config, because the
        // example's `default` is `input.configured`.
        let unlisted = finding("some-rule-nobody-wrote-a-branch-for");
        let verdict = policy
            .content_verdict(&content_facts(&unlisted, GuardAction::Report, None))
            .unwrap()
            .unwrap();
        assert_eq!(verdict.action, GuardAction::Report);
    }

    #[test]
    fn a_policy_without_a_content_rule_keeps_the_configured_action() {
        // A policy written before content control existed must keep working, and
        // must not silently change the verdict the config asked for.
        let policy = PolicyEngine::from_source(AUTHZ_ONLY).unwrap();
        let f = finding("openai-key");
        assert!(
            policy
                .content_verdict(&content_facts(&f, GuardAction::Deny, None))
                .unwrap()
                .is_none(),
            "a policy with no content rule says nothing about content"
        );
    }

    #[test]
    fn a_policy_can_tighten_or_loosen_the_configured_content_action() {
        let dir = TempDir::new(
            "override",
            &[
                ("10-authz.rego", AUTHZ_ONLY),
                (
                    "20-content.rego",
                    // A Rego `default` must be a constant, so "follow the
                    // configured action" is a catch-all body rather than a
                    // default -- which also keeps `action` defined for every
                    // finding.
                    "package llm.content\nimport rego.v1\n\
                     action := input.configured if { not overridden }\n\
                     overridden if { input.rule == \"strict\" }\n\
                     overridden if { input.rule == \"relaxed\" }\n\
                     action := \"deny\" if { input.rule == \"strict\" }\n\
                     action := \"report\" if { input.rule == \"relaxed\" }\n\
                     reason := \"strict is denied by policy\" if { input.rule == \"strict\" }\n",
                ),
            ],
        );
        let policy = PolicyEngine::from_config(&rules_dir_config(&dir)).unwrap();

        let verdict = policy
            .content_verdict(&content_facts(
                &finding("strict"),
                GuardAction::Report,
                None,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(verdict.action, GuardAction::Deny, "tightened");
        assert_eq!(
            verdict.reason.as_deref(),
            Some("strict is denied by policy")
        );

        let verdict = policy
            .content_verdict(&content_facts(&finding("relaxed"), GuardAction::Deny, None))
            .unwrap()
            .unwrap();
        assert_eq!(verdict.action, GuardAction::Report, "loosened");

        let verdict = policy
            .content_verdict(&content_facts(&finding("other"), GuardAction::Deny, None))
            .unwrap()
            .unwrap();
        assert_eq!(verdict.action, GuardAction::Deny, "and left the rest alone");
    }

    #[test]
    fn the_content_facts_carry_no_matched_text() {
        // The engine retains its input, so a match passed in would become a
        // second copy of the secret being judged. This pins the *shape* of what
        // crosses the boundary: add a field carrying the value and it fails.
        let f = finding("openai-key");
        let facts = content_facts(&f, GuardAction::Report, Some("laptop"));
        let json = serde_json::to_value(&facts).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["client", "configured", "field", "request", "rule"],
            "the finding contributes a rule name and a field, and nothing else"
        );
    }

    #[test]
    fn naming_a_content_rule_that_does_not_exist_fails_at_startup() {
        let error = PolicyEngine::from_config(&PolicyConfig {
            enabled: true,
            inline: AUTHZ_ONLY.to_string(),
            // The operator asked for a rule that is not there. Falling back
            // silently is the fail-open bug this module exists to prevent.
            content_rule: "data.llm.content.action".to_string(),
            ..PolicyConfig::default()
        })
        .expect_err("a named content rule that is missing must not compile");
        assert!(error.to_string().contains("content rule"), "{error}");
    }

    #[test]
    fn a_content_rule_with_no_default_refuses_a_finding_it_does_not_cover() {
        // This is the case that a probe-input discovery check got wrong: the
        // rule exists but its body does not match the probe, so treating
        // `Undefined` as "absent" would silently fall back to the config and the
        // policy would appear to work while denying nothing.
        let dir = TempDir::new(
            "no-default",
            &[
                ("10-authz.rego", AUTHZ_ONLY),
                (
                    "20-content.rego",
                    "package llm.content\nimport rego.v1\n\
                     action := \"deny\" if { input.rule == \"only-this\" }\n",
                ),
            ],
        );
        let policy = PolicyEngine::from_config(&rules_dir_config(&dir)).unwrap();

        let named = finding("only-this");
        assert_eq!(
            policy
                .content_verdict(&content_facts(&named, GuardAction::Report, None))
                .unwrap()
                .unwrap()
                .action,
            GuardAction::Deny,
            "the rule it names is decided"
        );

        let other = finding("something-else");
        let error = policy
            .content_verdict(&content_facts(&other, GuardAction::Report, None))
            .expect_err("a finding the rule does not cover must be refused");
        assert!(error.to_string().contains("undefined"), "{error}");
    }

    #[test]
    fn an_action_that_is_not_report_or_deny_is_refused() {
        let dir = TempDir::new(
            "bad-action",
            &[
                ("10-authz.rego", AUTHZ_ONLY),
                (
                    "20-content.rego",
                    "package llm.content\nimport rego.v1\ndefault action := \"maybe\"\n",
                ),
            ],
        );
        let policy = PolicyEngine::from_config(&rules_dir_config(&dir)).unwrap();
        let error = policy
            .content_verdict(&content_facts(
                &finding("anything"),
                GuardAction::Report,
                None,
            ))
            .expect_err("an unknown action must be refused, not guessed at");
        assert!(error.to_string().contains("maybe"), "{error}");
    }

    #[test]
    fn a_missing_rules_directory_is_an_error() {
        let error = load_rego_dir(std::path::Path::new("/nonexistent/aibroker/policy"))
            .expect_err("a missing directory must not read as 'no policy'");
        assert!(error.to_string().contains("does not exist"), "{error}");
    }

    #[test]
    fn a_rules_directory_without_rego_files_is_an_error() {
        let dir = TempDir::new("empty-dir", &[("notes.txt", "not a policy")]);
        let error = load_rego_dir(dir.path()).expect_err("an empty directory is a mistake");
        assert!(error.to_string().contains("no .rego files"), "{error}");
    }

    #[test]
    fn the_directory_is_sorted_and_skips_hidden_and_other_files() {
        let dir = TempDir::new(
            "sorted",
            &[
                ("b.rego", "package b\nimport rego.v1\nx := 1\n"),
                ("a.rego", "package a\nimport rego.v1\nx := 1\n"),
                (".hidden.rego", "package hidden\nimport rego.v1\nx := 1\n"),
                ("notes.txt", "ignored"),
                ("nested/c.rego", "package c\nimport rego.v1\nx := 1\n"),
            ],
        );
        let found = load_rego_dir(dir.path()).unwrap();
        let names: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            ["a.rego", "b.rego", "nested/c.rego"],
            "sorted by relative path; hidden and non-.rego files skipped"
        );
    }

    #[test]
    fn a_syntax_error_names_the_file_it_came_from() {
        // The point of a directory: a failure points at a file that exists,
        // unlike a line number in a concatenation nobody has on disk.
        let dir = TempDir::new(
            "syntax",
            &[
                ("10-ok.rego", AUTHZ_ONLY),
                (
                    "20-broken.rego",
                    "package llm.content\nimport rego.v1\nthis is not rego\n",
                ),
            ],
        );
        let error = PolicyEngine::from_config(&rules_dir_config(&dir))
            .expect_err("a syntax error must fail at startup");
        assert!(
            error.to_string().contains("20-broken.rego"),
            "the error must name the file, got: {error}"
        );
    }
}
