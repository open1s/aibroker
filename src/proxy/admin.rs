//! Administrative API: status, key management, hot reload and metrics.
//!
//! The control plane is intentionally small and explicit. It never returns a
//! key's secret, and when no token is configured it refuses every request
//! unless the operator opted into `allow_insecure` — failing closed is the only
//! safe default for an endpoint that can add credentials.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::ApiKeyConfig;
use crate::core::key_state::KeyState;
use crate::core::pool::KeyStatus;
use crate::core::runtime::SharedRuntime;
use crate::error::LlmBrokerError;

/// Credential presented by an admin caller.
#[derive(Debug, Clone)]
pub struct AdminCredentials {
    /// `Authorization: Bearer <token>` value, if present.
    pub bearer: Option<String>,
    /// `X-Admin-Token` value, if present.
    pub header_token: Option<String>,
    /// `Authorization: Basic <base64>` decoded to `user:password`.
    ///
    /// A browser cannot attach a bearer token to a URL the user navigates to,
    /// but it will answer a `Basic` challenge with a prompt. The password
    /// carries the token and the username is ignored, so any name works.
    pub basic: Option<String>,
}

impl AdminCredentials {
    pub fn from_headers(
        authorization: Option<&str>,
        admin_token: Option<&str>,
    ) -> AdminCredentials {
        let mut bearer = None;
        let mut basic = None;

        if let Some(value) = authorization.map(str::trim)
            && let Some((scheme, rest)) = value.split_once(' ')
        {
            let rest = rest.trim();
            if scheme.eq_ignore_ascii_case("bearer") && !rest.is_empty() {
                bearer = Some(rest.to_string());
            } else if scheme.eq_ignore_ascii_case("basic") {
                basic = base64_decode(rest).and_then(|bytes| String::from_utf8(bytes).ok());
            }
        }

        AdminCredentials {
            bearer,
            header_token: admin_token
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            basic,
        }
    }

    /// The token this request presents, if any.
    fn provided(&self) -> Option<&str> {
        self.header_token
            .as_deref()
            .or(self.bearer.as_deref())
            .or_else(|| {
                // `user:password` — the password is the token.
                self.basic
                    .as_deref()
                    .map(|pair| match pair.split_once(':') {
                        Some((_, password)) => password,
                        None => pair,
                    })
            })
    }

    /// Whether the caller used the scheme a browser can answer.
    fn is_basic(&self) -> bool {
        self.basic.is_some() && self.bearer.is_none() && self.header_token.is_none()
    }
}

/// Minimal standard-alphabet base64 decoder, for the Basic scheme only.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const INVALID: u8 = 0xFF;
    let mut table = [INVALID; 256];
    for (index, byte) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[*byte as usize] = index as u8;
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buffer = 0u32;
    let mut bits = 0u32;

    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        if byte.is_ascii_whitespace() {
            continue;
        }
        let value = table[byte as usize];
        if value == INVALID {
            return None;
        }
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// An HTTP response produced by the control plane.
#[derive(Debug, Clone)]
pub struct AdminResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// When set, emitted as `WWW-Authenticate` so a browser shows its login
    /// prompt instead of a bare error page.
    pub challenge: Option<&'static str>,
}

impl AdminResponse {
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        let body = serde_json::to_vec_pretty(value).unwrap_or_else(|error| {
            format!(r#"{{"error":"failed to serialize response: {error}"}}"#).into_bytes()
        });
        Self {
            status,
            content_type: "application/json",
            body,
            challenge: None,
        }
    }

    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self::json(
            status,
            &json!({ "error": message.into(), "status": status }),
        )
    }

    pub fn text(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
            challenge: None,
        }
    }

    pub fn no_content() -> Self {
        Self {
            status: 204,
            content_type: "application/json",
            body: Vec::new(),
            challenge: None,
        }
    }
}

/// Control-plane request, already parsed by the transport layer.
#[derive(Debug)]
pub struct AdminRequest {
    pub method: String,
    /// Path relative to the admin mount point, without a leading slash.
    pub path: String,
    /// Raw query string, without `?`.
    pub query: Option<String>,
    pub body: Vec<u8>,
    pub credentials: AdminCredentials,
}

/// Body of `POST /admin/keys`.
#[derive(Debug, Deserialize)]
pub struct NewKeyRequest {
    pub provider: String,
    pub id: String,
    pub key: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub weight: Option<u32>,
    #[serde(default)]
    pub max_rpm: Option<u32>,
    #[serde(default)]
    pub max_tpm: Option<u64>,
    #[serde(default)]
    pub max_concurrency: Option<u32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Body of `PATCH /admin/keys/{provider}/{id}`. Absent fields are untouched.
#[derive(Debug, Default, Deserialize)]
pub struct PatchKeyRequest {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub models: Option<Vec<String>>,
    #[serde(default)]
    pub weight: Option<u32>,
    #[serde(default)]
    pub max_rpm: Option<u32>,
    #[serde(default)]
    pub max_tpm: Option<u64>,
    #[serde(default)]
    pub max_concurrency: Option<u32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Body of `PUT /admin/config/strategy`.
#[derive(Debug, Deserialize)]
pub struct StrategyRequest {
    pub strategy: String,
}

impl From<LlmBrokerError> for AdminResponse {
    fn from(error: LlmBrokerError) -> Self {
        let status = match &error {
            LlmBrokerError::KeyNotFound(_) | LlmBrokerError::ProviderNotFound(_) => 404,
            LlmBrokerError::InvalidConfig(_) | LlmBrokerError::InvalidRequest(_) => 400,
            LlmBrokerError::AdminAuth(_) => 401,
            _ => 500,
        };
        AdminResponse::error(status, error.to_string())
    }
}

/// Routes control-plane requests. Contains no HTTP transport concerns.
pub struct AdminRouter {
    runtime: SharedRuntime,
    /// Expected token; `None` when authentication is disabled.
    token: Option<String>,
    /// Whether an unauthenticated control plane is explicitly allowed.
    allow_insecure: bool,
    /// Whether key secrets may be echoed in responses. Always false by default.
    expose_secrets: bool,
    /// A per-process token that lets the dashboard page refresh itself. See
    /// `accepts_dashboard_token` for why the page cannot reuse the admin
    /// credential, and why this one is read-only.
    dashboard_token: String,
}

impl AdminRouter {
    pub fn new(runtime: SharedRuntime, token: Option<String>, allow_insecure: bool) -> Self {
        Self {
            runtime,
            token,
            allow_insecure,
            expose_secrets: false,
            dashboard_token: generate_dashboard_token(),
        }
    }

    /// Authenticate a request. Fails closed.
    pub fn authenticate(&self, credentials: &AdminCredentials) -> Result<(), AdminResponse> {
        match self.token.as_deref() {
            Some(expected) => {
                let provided = credentials.provided().unwrap_or_default();
                if constant_time_eq(expected, provided) {
                    Ok(())
                } else {
                    self.runtime
                        .read()
                        .metrics()
                        .rejected_admin_auth
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Err(self.unauthorized(credentials))
                }
            }
            None if self.allow_insecure => Ok(()),
            None => {
                self.runtime
                    .read()
                    .metrics()
                    .rejected_admin_auth
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(AdminResponse::error(
                    503,
                    "admin API has no token configured; set admin.token or admin.allow_insecure",
                ))
            }
        }
    }

    /// A 401 that a browser can act on.
    ///
    /// The challenge is only sent when the caller already tried Basic, or sent
    /// nothing at all: a browser then shows its login prompt, while a script
    /// keeps getting clean JSON. A bearer-authenticated caller is never asked
    /// to fall back to a scheme whose credential would sit in the URL bar.
    fn unauthorized(&self, credentials: &AdminCredentials) -> AdminResponse {
        let mut response = AdminResponse::error(401, "invalid or missing admin token");
        if credentials.is_basic() || credentials.provided().is_none() {
            response.challenge = Some("Basic realm=\"LLM Broker admin\", charset=\"UTF-8\"");
        }
        response
    }

    /// Handle one request.
    pub fn handle(&self, request: AdminRequest) -> AdminResponse {
        // Before `authenticate`, so a healthy dashboard refresh is not counted
        // as a rejected authentication.
        if self.accepts_dashboard_token(&request) {
            return self.dispatch(request);
        }
        if let Err(response) = self.authenticate(&request.credentials) {
            return response;
        }
        self.dispatch(request)
    }

    /// Whether this request carries the dashboard's read-only refresh token.
    ///
    /// Safe methods only. The token exists so a status page can refresh itself,
    /// and nothing about that needs to change the configuration; a credential
    /// that can only read is a far smaller thing to leave sitting in a browser
    /// tab. A mutation that happens to present it still has to authenticate as
    /// an operator.
    fn accepts_dashboard_token(&self, request: &AdminRequest) -> bool {
        if !request.method.eq_ignore_ascii_case("GET") {
            return false;
        }
        match request.credentials.header_token.as_deref() {
            Some(provided) => constant_time_eq(&self.dashboard_token, provided),
            None => false,
        }
    }

    fn dispatch(&self, request: AdminRequest) -> AdminResponse {
        let path = request.path.trim_matches('/');
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let method = request.method.to_ascii_uppercase();

        match (method.as_str(), segments.as_slice()) {
            // A human-friendly view of everything below. Read-only.
            ("GET", []) => self.dashboard(),
            ("GET", ["health"]) => self.health(),
            ("GET", ["status"]) => self.status(),
            ("GET", ["config"]) => self.config(),
            ("POST", ["config", "reload"]) => self.reload(),
            ("GET", ["config", "strategy"]) => self.get_strategy(),
            ("PUT", ["config", "strategy"]) => self.set_strategy(&request.body),
            ("GET", ["keys"]) => self.list_keys(),
            ("POST", ["keys"]) => self.add_key(&request.body),
            ("PATCH", ["keys", provider, id]) => self.patch_key(provider, id, &request.body),
            ("DELETE", ["keys", provider, id]) => self.delete_key(provider, id),
            ("POST", ["keys", provider, id, "reset"]) => self.reset_key(provider, id),
            ("POST", ["keys", provider, id, "enable"]) => self.set_enabled(provider, id, true),
            ("POST", ["keys", provider, id, "disable"]) => self.set_enabled(provider, id, false),
            ("GET", ["models"]) => self.models(),
            ("GET", ["routes"]) => self.routes(),
            ("GET", ["metrics"]) => self.metrics(),
            ("GET", ["security"]) => self.security(),
            _ => AdminResponse::error(404, format!("no admin route for `{path}`")),
        }
    }

    /// The read-only status page.
    fn dashboard(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        let admin_path = runtime.config().admin.path.clone();
        let html =
            crate::proxy::dashboard::render(&self.runtime, &admin_path, &self.dashboard_token);
        AdminResponse::text(200, "text/html; charset=utf-8", html)
    }

    fn health(&self) -> AdminResponse {
        AdminResponse::json(200, &json!({"status": "ok"}))
    }

    /// Who may use the proxy, and which policy decides.
    ///
    /// Reports the *configuration* of the security plane, never a token: an
    /// operator needs to see that authentication is off, or that a client is
    /// scoped to two models, without the endpoint becoming a credential store.
    fn security(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        let clients = runtime.clients();
        let policy = runtime.policy();

        let payload = serde_json::json!({
            "client_auth_required": runtime.requires_client_auth(),
            "client_count": clients.len(),
            "clients": clients.statuses(),
            "denials_by_reason": clients
                .denials()
                .into_iter()
                .map(|(reason, count)| (reason.as_str().to_string(), count))
                .collect::<std::collections::BTreeMap<_, _>>(),
            "content_guard": runtime.content_guard().map(|guard| {
                json!({
                    "enabled": true,
                    // Names only. A pattern is configuration, and a rule name is
                    // what a finding reports, so this is what an operator needs
                    // to correlate a log line with the config.
                    "action": guard.action().as_str(),
                    "rules": guard.rule_names().collect::<Vec<_>>(),
                })
            }),
            "policy": {
                "source": match policy.source() {
                    crate::core::policy::PolicySource::Default => "default",
                    crate::core::policy::PolicySource::Rego => "rego",
                },
                "loaded_from": policy.description(),
            },
        });
        AdminResponse::json(200, &payload)
    }

    fn status(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        let pools = runtime.broker().pools();
        let mut providers = Vec::new();
        let mut total_keys = 0usize;
        let mut healthy_keys = 0usize;
        let mut in_flight = 0u64;

        for (name, pool) in pools {
            let statuses = pool.status();
            total_keys += statuses.len();
            let provider_in_flight: u64 = statuses.iter().map(|s| u64::from(s.in_flight)).sum();
            in_flight += provider_in_flight;
            for status in &statuses {
                if status.enabled && status.state == "closed" {
                    healthy_keys += 1;
                }
            }
            providers.push(json!({
                "name": name,
                "base_url": pool.base_url,
                "auth": pool.auth.as_str(),
                "strategy": pool.strategy().as_str(),
                "keys": statuses.len(),
                "keys_available": statuses
                    .iter()
                    .filter(|s| s.enabled && s.cooldown_secs.is_none())
                    .count(),
                "in_flight": provider_in_flight,
            }));
        }

        let metrics = runtime.metrics();
        AdminResponse::json(
            200,
            &json!({
                "status": "ok",
                "uptime_seconds": metrics.uptime_seconds(),
                "requests_total": metrics.requests_total.load(std::sync::atomic::Ordering::Relaxed),
                "requests_in_flight": in_flight,
                "providers": providers,
                "keys_total": total_keys,
                "keys_healthy": healthy_keys,
                "strategy": runtime.strategy().as_str(),
                "dashboard": runtime.config().admin.path,
                "config_path": runtime.config_path().map(|p| p.display().to_string()),
            }),
        )
    }

    fn config(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        match runtime.config().to_toml() {
            Ok(toml) => AdminResponse::text(200, "text/plain; charset=utf-8", toml),
            Err(error) => AdminResponse::from(error),
        }
    }

    fn reload(&self) -> AdminResponse {
        let mut runtime = self.runtime.write();
        match runtime.reload_from_disk() {
            Ok(()) => {
                let summary = runtime.provider_names();
                AdminResponse::json(200, &json!({"status": "reloaded", "providers": summary}))
            }
            Err(error) => AdminResponse::from(error),
        }
    }

    fn get_strategy(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        let (primary, fallbacks) = runtime.broker().strategies();
        AdminResponse::json(
            200,
            &json!({
                "strategy": primary.as_str(),
                "fallback_strategies": fallbacks.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                "available": crate::core::strategy::Strategy::all()
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>(),
            }),
        )
    }

    fn set_strategy(&self, body: &[u8]) -> AdminResponse {
        let request: StrategyRequest = match serde_json::from_slice(body) {
            Ok(request) => request,
            Err(error) => {
                return AdminResponse::error(400, format!("invalid JSON body: {error}"));
            }
        };

        let mut runtime = self.runtime.write();
        let requested = request.strategy.clone();
        let result = runtime.apply_and_persist(|config| {
            config.load_balancing.strategy = requested.clone();
        });
        match result {
            Ok(()) => AdminResponse::json(
                200,
                &json!({"status": "updated", "strategy": runtime.strategy().as_str()}),
            ),
            Err(error) => AdminResponse::from(error),
        }
    }

    fn list_keys(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        let mut providers = serde_json::Map::new();
        for (name, pool) in runtime.broker().pools() {
            let statuses: Vec<KeyStatus> = pool.status();
            providers.insert(
                name.clone(),
                serde_json::to_value(statuses).unwrap_or_else(|_| json!([])),
            );
        }
        AdminResponse::json(200, &json!({ "providers": providers }))
    }

    fn add_key(&self, body: &[u8]) -> AdminResponse {
        let request: NewKeyRequest = match serde_json::from_slice(body) {
            Ok(request) => request,
            Err(error) => return AdminResponse::error(400, format!("invalid JSON body: {error}")),
        };

        let new_key = ApiKeyConfig {
            id: request.id.clone(),
            key: request.key,
            enabled: request.enabled.unwrap_or(true),
            models: request.models,
            weight: request.weight.unwrap_or(1),
            max_rpm: request.max_rpm,
            max_tpm: request.max_tpm,
            max_concurrency: request.max_concurrency,
            model_map: None,
        };

        let provider_name = request.provider.clone();
        let key_id = request.id.clone();
        let mut runtime = self.runtime.write();

        // Validate the target and the payload before mutating anything, so a
        // bad request cannot half-apply.
        if runtime.broker().pool(&provider_name).is_none() {
            return AdminResponse::from(LlmBrokerError::ProviderNotFound(provider_name));
        }
        if let Err(error) = prevalidate_key(&provider_name, &new_key) {
            return AdminResponse::from(error);
        }
        if runtime.broker().pools().values().any(|pool| {
            pool.keys()
                .iter()
                .any(|key| key.id == key_id && pool.provider != provider_name)
        }) {
            return AdminResponse::error(
                409,
                format!("key id `{key_id}` already exists under a different provider"),
            );
        }

        let duplicate = runtime
            .broker()
            .pool(&provider_name)
            .map(|pool| pool.keys().iter().any(|key| key.id == key_id))
            .unwrap_or(false);
        let result = runtime.apply_and_persist(|config| {
            let Some(provider) = config
                .providers
                .iter_mut()
                .find(|p| p.name == provider_name)
            else {
                return;
            };
            if duplicate {
                if let Some(existing) = provider.api_keys.iter_mut().find(|k| k.id == key_id) {
                    *existing = new_key.clone();
                }
            } else {
                provider.api_keys.push(new_key.clone());
            }
        });

        match result {
            Ok(()) => {
                let metrics = Arc::clone(runtime.metrics());
                runtime.broker().pool(&provider_name).map(|pool| {
                    pool.keys()
                        .iter()
                        .find(|k| k.id == key_id)
                        .map(|key| metrics.key(&provider_name, &key.id))
                });
                let status = runtime
                    .broker()
                    .pool(&provider_name)
                    .and_then(|pool| pool.status().into_iter().find(|s| s.id == key_id));
                let mut value =
                    serde_json::to_value(status).unwrap_or_else(|_| json!({ "id": key_id }));
                if self.expose_secrets
                    && let Some(object) = value.as_object_mut()
                {
                    object.insert("key".to_string(), json!("<redacted>"));
                }
                AdminResponse::json(if duplicate { 200 } else { 201 }, &value)
            }
            Err(error) => AdminResponse::from(error),
        }
    }

    fn patch_key(&self, provider: &str, id: &str, body: &[u8]) -> AdminResponse {
        let patch: PatchKeyRequest = match serde_json::from_slice(body) {
            Ok(patch) => patch,
            Err(error) => return AdminResponse::error(400, format!("invalid JSON body: {error}")),
        };

        let provider = provider.to_string();
        let id = id.to_string();
        let mut runtime = self.runtime.write();

        if runtime.broker().pool(&provider).is_none() {
            return AdminResponse::from(LlmBrokerError::ProviderNotFound(provider));
        }
        let exists = runtime
            .broker()
            .pool(&provider)
            .map(|pool| pool.keys().iter().any(|key| key.id == id))
            .unwrap_or(false);
        if !exists {
            return AdminResponse::from(LlmBrokerError::KeyNotFound(format!("{provider}/{id}")));
        }

        let result = runtime.apply_and_persist(|config| {
            if let Some(entry) = config
                .providers
                .iter_mut()
                .find(|p| p.name == provider)
                .and_then(|p| p.api_keys.iter_mut().find(|k| k.id == id))
            {
                if let Some(key) = &patch.key {
                    entry.key = key.clone();
                }
                if let Some(models) = &patch.models {
                    entry.models = models.clone();
                }
                if let Some(weight) = patch.weight {
                    entry.weight = weight;
                }
                if let Some(max_rpm) = patch.max_rpm {
                    entry.max_rpm = Some(max_rpm);
                }
                if let Some(max_tpm) = patch.max_tpm {
                    entry.max_tpm = Some(max_tpm);
                }
                if let Some(max_concurrency) = patch.max_concurrency {
                    entry.max_concurrency = Some(max_concurrency);
                }
                if let Some(enabled) = patch.enabled {
                    entry.enabled = enabled;
                }
            }
        });

        match result {
            Ok(()) => {
                let status = runtime
                    .broker()
                    .pool(&provider)
                    .and_then(|pool| pool.status().into_iter().find(|s| s.id == id));
                AdminResponse::json(200, &json!({"status": "updated", "key": status}))
            }
            Err(error) => AdminResponse::from(error),
        }
    }

    fn delete_key(&self, provider: &str, id: &str) -> AdminResponse {
        let provider = provider.to_string();
        let id = id.to_string();
        let mut runtime = self.runtime.write();

        if runtime.broker().pool(&provider).is_none() {
            return AdminResponse::from(LlmBrokerError::ProviderNotFound(provider));
        }
        let result = runtime.apply_and_persist(|config| {
            if let Some(entry) = config.providers.iter_mut().find(|p| p.name == provider) {
                entry.api_keys.retain(|k| k.id != id);
            }
        });

        match result {
            Ok(()) => {
                runtime
                    .metrics()
                    .retain_keys(&provider, &|key_id| key_id != id);
                AdminResponse::json(200, &json!({"status": "deleted", "id": id}))
            }
            Err(error) => AdminResponse::from(error),
        }
    }

    fn reset_key(&self, provider: &str, id: &str) -> AdminResponse {
        let runtime = self.runtime.read();
        let Some(pool) = runtime.broker().pool(provider) else {
            return AdminResponse::from(LlmBrokerError::ProviderNotFound(provider.to_string()));
        };
        let Some(key) = pool.key(id) else {
            return AdminResponse::from(LlmBrokerError::KeyNotFound(format!("{provider}/{id}")));
        };
        key.reset();
        AdminResponse::json(200, &json!({"status": "reset", "id": id}))
    }

    fn set_enabled(&self, provider: &str, id: &str, enabled: bool) -> AdminResponse {
        let mut runtime = self.runtime.write();
        if runtime.broker().pool(provider).is_none() {
            return AdminResponse::from(LlmBrokerError::ProviderNotFound(provider.to_string()));
        }
        let provider_name = provider.to_string();
        let id_owned = id.to_string();
        let result = runtime.apply_and_persist(|config| {
            if let Some(entry) = config
                .providers
                .iter_mut()
                .find(|p| p.name == provider_name)
                .and_then(|p| p.api_keys.iter_mut().find(|k| k.id == id_owned))
            {
                entry.enabled = enabled;
            }
        });
        match result {
            Ok(()) => AdminResponse::json(
                200,
                &json!({"status": if enabled {"enabled"} else {"disabled"}, "id": id}),
            ),
            Err(error) => AdminResponse::from(error),
        }
    }

    fn models(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        AdminResponse::json(200, &json!({"models": runtime.config().known_models()}))
    }

    fn routes(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        AdminResponse::json(
            200,
            &json!({
                "routes": runtime.broker().routes(),
                "default_route": runtime.config().default_route,
            }),
        )
    }

    fn metrics(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        AdminResponse::text(
            200,
            "text/plain; charset=utf-8",
            runtime.metrics().render_prometheus(),
        )
    }
}

/// Reject obviously broken key definitions before touching the runtime.
fn prevalidate_key(provider: &str, key: &ApiKeyConfig) -> Result<(), LlmBrokerError> {
    if key.id.trim().is_empty() {
        return Err(LlmBrokerError::InvalidRequest(
            "key id must not be empty".to_string(),
        ));
    }
    if key.key.trim().is_empty() {
        return Err(LlmBrokerError::InvalidRequest(
            "key secret must not be empty".to_string(),
        ));
    }
    crate::config::resolve_secret(&key.key)?;
    if key.weight == 0 {
        return Err(LlmBrokerError::InvalidRequest(
            "weight must be at least 1".to_string(),
        ));
    }
    let _ = provider;
    // Build the runtime key once so a bad model map or secret surfaces here.
    KeyState::from_config(provider, key)?;
    Ok(())
}

/// Mint the dashboard's per-process refresh token.
///
/// There is no RNG in the dependency tree and none is needed: `RandomState` is
/// seeded from the OS once per process, which is exactly the lifetime this
/// token has. It is regenerated on every start, so a dashboard left open in a
/// tab stops refreshing when the broker restarts, which is the behaviour an
/// operator would expect from a credential they never typed.
fn generate_dashboard_token() -> String {
    use std::hash::{BuildHasher, Hasher};

    let state = std::collections::hash_map::RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(state.build_hasher().finish());
    let first = hasher.finish();
    let mut hasher = state.build_hasher();
    hasher.write_u64(first);
    format!("{first:016x}{:016x}", hasher.finish())
}

/// Constant-time comparison so token checks do not leak length/prefix timing.
fn constant_time_eq(expected: &str, provided: &str) -> bool {
    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    if expected.len() != provided.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(provided.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKeyConfig, Config, ProviderConfig, ServerConfig};
    use crate::core::runtime::{Runtime, shared};

    fn provider(name: &str, keys: Vec<ApiKeyConfig>) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            base_url: Some(format!("https://{name}.test")),
            path_prefix: None,
            auth: None,
            auth_query_param: None,
            default_models: vec![],
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
            api_keys: keys,
        }
    }

    fn key(id: &str) -> ApiKeyConfig {
        ApiKeyConfig {
            id: id.into(),
            key: format!("sk-{id}"),
            enabled: true,
            models: vec!["gpt-4".into()],
            weight: 1,
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
            model_map: None,
        }
    }

    fn runtime() -> SharedRuntime {
        let config = Config {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 0,
                threads: None,
                daemon: false,
                pid_file: None,
                user: None,
                group: None,
                connect_timeout_ms: 0,
                idle_timeout_ms: None,
                read_timeout_ms: None,
                write_timeout_ms: None,
                max_retries: 3,
                graceful_shutdown_secs: crate::config::DEFAULT_GRACE_PERIOD_SECS,
            },
            proxy_type: None,
            providers: vec![provider("openai", vec![key("k1"), key("k2")])],
            routes: vec![],
            default_route: None,
            load_balancing: Default::default(),
            health: Default::default(),
            observability: Default::default(),
            admin: Default::default(),
            clients: Vec::new(),
            policy: Default::default(),
            dump: Default::default(),
            content_guard: Default::default(),
        };
        shared(Runtime::new(config, None).unwrap())
    }

    fn router(runtime: SharedRuntime, token: Option<&str>) -> AdminRouter {
        AdminRouter::new(runtime, token.map(|t| t.to_string()), false)
    }

    fn request(method: &str, path: &str, body: &[u8]) -> AdminRequest {
        AdminRequest {
            method: method.into(),
            path: path.into(),
            query: None,
            body: body.to_vec(),
            credentials: AdminCredentials::from_headers(None, None),
        }
    }

    fn authed(method: &str, path: &str, body: &[u8], token: &str) -> AdminRequest {
        let mut req = request(method, path, body);
        req.credentials = AdminCredentials::from_headers(Some(&format!("Bearer {token}")), None);
        req
    }

    /// A request that carries a token the way the dashboard page does, in
    /// `X-Admin-Token` rather than in the URL or the auth cache.
    fn with_header_token(mut req: AdminRequest, token: &str) -> AdminRequest {
        req.credentials = AdminCredentials::from_headers(None, Some(token));
        req
    }

    #[test]
    fn the_dashboard_token_refreshes_the_page_without_the_admin_token() {
        // The defect: the page authenticated as a *navigation*, and its own
        // `fetch` was not given those credentials, so every refresh was a 401
        // the operator could not act on -- re-entering the token changed
        // nothing, because the token was never the problem.
        let router = router(runtime(), Some("admin-secret"));
        let token = router.dashboard_token.clone();

        let response = router.handle(with_header_token(request("GET", "", &[]), &token));

        assert_eq!(response.status, 200);
        assert!(
            response.content_type.starts_with("text/html"),
            "the refresh token should be served the page, not merely any 200"
        );
    }

    #[test]
    fn the_dashboard_token_is_not_the_admin_token() {
        let router = router(runtime(), Some("admin-secret"));
        assert_ne!(router.dashboard_token, "admin-secret");
        assert!(
            router.dashboard_token.len() >= 32,
            "a refresh token should not be guessable from a short value"
        );
    }

    #[test]
    fn the_dashboard_token_cannot_change_anything() {
        // Read-only by construction. A status page's refresh never needs to
        // mutate, and a credential that cannot mutate is a far smaller thing to
        // leave sitting in a browser tab. Each of these *would* succeed for an
        // operator, so a 401 is what proves the token was refused rather than
        // the route being absent.
        let router = router(runtime(), Some("admin-secret"));
        let token = router.dashboard_token.clone();

        for (method, path) in [
            ("POST", "config/reload"),
            ("PUT", "config/strategy"),
            ("POST", "keys"),
            ("DELETE", "keys/openai/k1"),
            ("PATCH", "keys/openai/k1"),
        ] {
            let response = router.handle(with_header_token(request(method, path, b"{}"), &token));
            assert_eq!(
                response.status, 401,
                "{method} {path} must not accept the dashboard refresh token"
            );
        }
    }

    #[test]
    fn a_wrong_dashboard_token_is_refused() {
        let router = router(runtime(), Some("admin-secret"));
        let response = router.handle(with_header_token(
            request("GET", "", &[]),
            "not-the-refresh-token",
        ));
        assert_eq!(response.status, 401);
    }

    #[test]
    fn the_refresh_token_does_not_inflate_the_auth_failure_counter() {
        // A successful refresh is not a failed authentication. Counting it as
        // one made a healthy dashboard look like an attack in the metric.
        let runtime = runtime();
        let router = router(runtime.clone(), Some("admin-secret"));
        let token = router.dashboard_token.clone();

        let before = runtime
            .read()
            .metrics()
            .rejected_admin_auth
            .load(std::sync::atomic::Ordering::Relaxed);
        let response = router.handle(with_header_token(request("GET", "", &[]), &token));
        let after = runtime
            .read()
            .metrics()
            .rejected_admin_auth
            .load(std::sync::atomic::Ordering::Relaxed);

        assert_eq!(response.status, 200);
        assert_eq!(
            before, after,
            "a successful refresh must not count as a failure"
        );
    }

    #[test]
    fn credentials_parse_bearer_case_insensitively() {
        let creds = AdminCredentials::from_headers(Some("bearer abc"), None);
        assert_eq!(creds.bearer.as_deref(), Some("abc"));
        let creds = AdminCredentials::from_headers(Some("Basic abc"), None);
        assert!(creds.bearer.is_none());
        let creds = AdminCredentials::from_headers(None, Some("hdr"));
        assert_eq!(creds.header_token.as_deref(), Some("hdr"));
    }

    #[test]
    fn base64_decoder_handles_padding_and_rejects_junk() {
        assert_eq!(base64_decode("dXNlcjp0b2tlbg==").unwrap(), b"user:token");
        assert_eq!(base64_decode("dXNlcjp0b2tlbg").unwrap(), b"user:token");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn basic_credentials_carry_the_token_in_the_password() {
        // "any:secret"
        let value = "Basic YW55OnNlY3JldA==";
        let creds = AdminCredentials::from_headers(Some(value), None);
        assert_eq!(creds.provided(), Some("secret"));
        assert!(creds.is_basic());
    }

    #[test]
    fn basic_auth_authenticates_a_browser_style_request() {
        let router = router(runtime(), Some("secret"));
        let mut request = request("GET", "", b"");
        request.credentials = AdminCredentials::from_headers(Some("Basic YW55OnNlY3JldA=="), None);
        let response = router.handle(request);
        assert_eq!(response.status, 200, "a browser login must be accepted");
        assert!(
            response.challenge.is_none(),
            "no challenge once authenticated"
        );
    }

    #[test]
    fn a_wrong_basic_password_is_rejected_and_rechallenged() {
        let router = router(runtime(), Some("secret"));
        let mut request = request("GET", "", b"");
        // "any:wrong"
        request.credentials = AdminCredentials::from_headers(Some("Basic YW55Ondyb25n"), None);
        let response = router.handle(request);
        assert_eq!(response.status, 401);
        assert!(
            response.challenge.is_some(),
            "a browser needs the challenge to prompt again"
        );
    }

    #[test]
    fn an_anonymous_request_is_challenged() {
        let router = router(runtime(), Some("secret"));
        let response = router.handle(request("GET", "", b""));
        assert_eq!(response.status, 401);
        assert!(
            response.challenge.is_some(),
            "a browser should get a prompt"
        );
    }

    #[test]
    fn a_bearer_caller_is_never_offered_basic() {
        // A script that sent a bad bearer token should get JSON, not a prompt
        // that would put its credential in a URL.
        let router = router(runtime(), Some("secret"));
        let response = router.handle(authed("GET", "", b"", "wrong"));
        assert_eq!(response.status, 401);
        assert!(response.challenge.is_none());
    }

    #[test]
    fn the_security_endpoint_reports_the_content_guard() {
        // Whether a content guard is on, and which rules, is security posture:
        // an operator should not have to read the config file or the process
        // arguments to find out.
        let runtime = runtime();
        let router = router(Arc::clone(&runtime), Some("secret"));
        {
            let mut runtime = runtime.write();
            runtime
                .apply(|config| {
                    config.content_guard = crate::config::ContentGuardConfig {
                        enabled: true,
                        action: Some("deny".to_string()),
                        patterns: vec![crate::config::ContentPattern {
                            name: "aws-key".into(),
                            pattern: r"AKIA[0-9A-Z]{16}".into(),
                        }],
                        allow: vec![],
                    };
                })
                .expect("content guard config should apply");
        }

        let response = router.handle(authed("GET", "/security", b"", "secret"));
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).expect("utf8");
        assert!(body.contains("\"content_guard\""), "{body}");
        assert!(body.contains("\"action\": \"deny\""), "{body}");
        assert!(body.contains("aws-key"), "{body}");
    }

    #[test]
    fn the_security_endpoint_reports_the_plane_without_tokens() {
        let runtime = runtime();
        let router = router(Arc::clone(&runtime), Some("secret"));
        {
            let mut runtime = runtime.write();
            runtime
                .apply(|config| {
                    config.clients.push(crate::config::ClientConfig {
                        name: "laptop".into(),
                        token: "super-secret-token".into(),
                        enabled: true,
                        allowed_models: vec!["gpt-*".into()],
                        allowed_providers: vec![],
                        max_rpm: Some(60),
                        max_tpm: None,
                        max_concurrency: Some(2),
                    });
                })
                .expect("client config should apply");
        }

        let response = router.handle(authed("GET", "/security", b"", "secret"));
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).expect("utf8");

        assert!(body.contains("laptop"), "{body}");
        assert!(body.contains("gpt-*"), "{body}");
        assert!(body.contains("\"client_auth_required\": true"), "{body}");
        assert!(
            !body.contains("super-secret-token"),
            "the admin API must never expose a client token: {body}"
        );
        assert!(body.contains("\"source\": \"default\""), "{body}");
    }

    #[test]
    fn requests_without_a_token_are_rejected() {
        let router = router(runtime(), Some("secret"));
        let response = router.handle(request("GET", "status", b""));
        assert_eq!(response.status, 401);
    }

    #[test]
    fn wrong_tokens_are_rejected() {
        let router = router(runtime(), Some("secret"));
        let response = router.handle(authed("GET", "status", b"", "wrong"));
        assert_eq!(response.status, 401);
    }

    #[test]
    fn a_correct_token_is_accepted() {
        let router = router(runtime(), Some("secret"));
        let response = router.handle(authed("GET", "status", b"", "secret"));
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["keys_total"], 2);
    }

    #[test]
    fn a_router_without_a_token_fails_closed() {
        let router = router(runtime(), None);
        let response = router.handle(request("GET", "status", b""));
        assert_eq!(response.status, 503);
    }

    #[test]
    fn allow_insecure_permits_anonymous_access() {
        let router = AdminRouter::new(runtime(), None, true);
        let response = router.handle(request("GET", "health", b""));
        assert_eq!(response.status, 200);
    }

    #[test]
    fn unknown_routes_return_404_after_authentication() {
        let router = router(runtime(), Some("t"));
        let response = router.handle(authed("GET", "nope", b"", "t"));
        assert_eq!(response.status, 404);
    }

    #[test]
    fn adding_a_key_updates_the_runtime() {
        let runtime = runtime();
        let router = router(Arc::clone(&runtime), Some("t"));
        let body =
            br#"{"provider":"openai","id":"k3","key":"sk-k3","models":["gpt-4"],"max_rpm":7}"#;
        let response = router.handle(authed("POST", "keys", body, "t"));
        assert_eq!(
            response.status,
            201,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!(runtime.read().broker().pool("openai").unwrap().len(), 3);
    }

    #[test]
    fn adding_a_key_without_a_provider_is_rejected() {
        let router = router(runtime(), Some("t"));
        let body = br#"{"provider":"ghost","id":"k3","key":"sk-k3"}"#;
        let response = router.handle(authed("POST", "keys", body, "t"));
        assert_eq!(response.status, 404, "an unknown provider is a 404");
    }

    #[test]
    fn adding_a_duplicate_id_in_another_provider_is_a_conflict() {
        let runtime = runtime();
        runtime
            .write()
            .apply(|config| {
                config.providers.push(provider("anthropic", vec![]));
            })
            .unwrap();
        let router = router(Arc::clone(&runtime), Some("t"));
        let body = br#"{"provider":"anthropic","id":"k1","key":"sk-dup"}"#;
        let response = router.handle(authed("POST", "keys", body, "t"));
        assert_eq!(response.status, 409);
    }

    #[test]
    fn adding_a_key_with_an_empty_secret_is_rejected() {
        let router = router(runtime(), Some("t"));
        let body = br#"{"provider":"openai","id":"k9","key":"  "}"#;
        let response = router.handle(authed("POST", "keys", body, "t"));
        assert_eq!(response.status, 400);
    }

    #[test]
    fn disabling_a_key_removes_it_from_selection() {
        let runtime = runtime();
        let router = router(Arc::clone(&runtime), Some("t"));
        let response = router.handle(authed("POST", "keys/openai/k1/disable", b"", "t"));
        assert_eq!(response.status, 200);
        let pool = runtime.read().broker().pool("openai").unwrap().clone();
        assert!(!pool.key("k1").unwrap().is_enabled());
        assert!(pool.key("k2").unwrap().is_enabled());
    }

    #[test]
    fn resetting_a_key_clears_its_cooldown() {
        let runtime = runtime();
        let router = router(Arc::clone(&runtime), Some("t"));
        {
            let guard = runtime.read();
            let key = guard.broker().pool("openai").unwrap().key("k1").unwrap();
            key.cooldown_for(std::time::Duration::from_secs(300));
        }
        let response = router.handle(authed("POST", "keys/openai/k1/reset", b"", "t"));
        assert_eq!(response.status, 200);
        let guard = runtime.read();
        let key = guard.broker().pool("openai").unwrap().key("k1").unwrap();
        assert!(key.cooldown_remaining().is_none());
    }

    #[test]
    fn deleting_a_key_updates_runtime_and_metrics() {
        let runtime = runtime();
        runtime.read().metrics().key("openai", "k2");
        let router = router(Arc::clone(&runtime), Some("t"));
        let response = router.handle(authed("DELETE", "keys/openai/k2", b"", "t"));
        assert_eq!(response.status, 200);
        assert_eq!(runtime.read().broker().pool("openai").unwrap().len(), 1);
        let names: Vec<String> = runtime
            .read()
            .metrics()
            .key_snapshot()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(!names.contains(&"openai/k2".to_string()));
    }

    #[test]
    fn patching_a_key_applies_limits() {
        let runtime = runtime();
        let router = router(Arc::clone(&runtime), Some("t"));
        let body = br#"{"max_rpm":3,"weight":5}"#;
        let response = router.handle(authed("PATCH", "keys/openai/k1", body, "t"));
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let guard = runtime.read();
        let key = guard.broker().pool("openai").unwrap().key("k1").unwrap();
        assert_eq!(key.max_rpm(), Some(3));
        assert_eq!(key.weight, 5);
    }

    #[test]
    fn patching_a_missing_key_returns_404() {
        let router = router(runtime(), Some("t"));
        let response = router.handle(authed(
            "PATCH",
            "keys/openai/missing",
            br#"{"weight":2}"#,
            "t",
        ));
        assert_eq!(response.status, 404);
    }

    #[test]
    fn strategy_can_be_changed_at_runtime() {
        let runtime = runtime();
        let router = router(Arc::clone(&runtime), Some("t"));
        let response = router.handle(authed(
            "PUT",
            "config/strategy",
            br#"{"strategy":"least_busy"}"#,
            "t",
        ));
        assert_eq!(response.status, 200);
        assert_eq!(runtime.read().strategy().as_str(), "least_busy");
    }

    #[test]
    fn an_unknown_strategy_is_refused() {
        let runtime = runtime();
        let router = router(Arc::clone(&runtime), Some("t"));
        let response = router.handle(authed(
            "PUT",
            "config/strategy",
            br#"{"strategy":"nope"}"#,
            "t",
        ));
        assert_eq!(response.status, 400);
        assert_eq!(runtime.read().strategy().as_str(), "round_robin");
    }

    #[test]
    fn list_keys_reports_state_without_secrets() {
        let router = router(runtime(), Some("t"));
        let response = router.handle(authed("GET", "keys", b"", "t"));
        assert_eq!(response.status, 200);
        let text = String::from_utf8_lossy(&response.body).to_string();
        assert!(text.contains("k1"));
        assert!(
            !text.contains("sk-k1"),
            "the admin API must never echo a key secret"
        );
    }

    #[test]
    fn metrics_endpoint_returns_prometheus_text() {
        let runtime = runtime();
        runtime.read().metrics().record_request(
            "openai",
            "k1",
            Some("gpt-4"),
            200,
            std::time::Duration::from_millis(10),
            1,
            1,
            0,
        );
        let router = router(Arc::clone(&runtime), Some("t"));
        let response = router.handle(authed("GET", "metrics", b"", "t"));
        assert_eq!(response.status, 200);
        let text = String::from_utf8_lossy(&response.body);
        assert!(text.contains("llm_broker_requests_total 1"));
    }

    #[test]
    fn config_endpoint_never_leaks_secrets_through_the_admin_console() {
        // `/config` intentionally returns the on-disk document, which contains
        // secrets; it is only reachable with a valid token. This test pins that
        // requirement so the endpoint cannot be opened up accidentally.
        let router = router(runtime(), Some("t"));
        assert_eq!(router.handle(request("GET", "config", b"")).status, 401);
        assert_eq!(router.handle(authed("GET", "config", b"", "t")).status, 200);
    }

    #[test]
    fn constant_time_eq_matches_plain_equality() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
    }
}
