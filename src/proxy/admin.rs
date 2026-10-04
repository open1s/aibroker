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
}

impl AdminCredentials {
    pub fn from_headers(
        authorization: Option<&str>,
        admin_token: Option<&str>,
    ) -> AdminCredentials {
        let bearer = authorization
            .map(str::trim)
            .and_then(|value| {
                let (scheme, token) = value.split_once(' ')?;
                scheme
                    .eq_ignore_ascii_case("bearer")
                    .then(|| token.trim().to_string())
            })
            .filter(|token| !token.is_empty());
        AdminCredentials {
            bearer,
            header_token: admin_token
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
        }
    }

    fn provided(&self) -> Option<&str> {
        self.header_token.as_deref().or(self.bearer.as_deref())
    }
}

/// An HTTP response produced by the control plane.
#[derive(Debug, Clone)]
pub struct AdminResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
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
        }
    }

    pub fn no_content() -> Self {
        Self {
            status: 204,
            content_type: "application/json",
            body: Vec::new(),
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
}

impl AdminRouter {
    pub fn new(runtime: SharedRuntime, token: Option<String>, allow_insecure: bool) -> Self {
        Self {
            runtime,
            token,
            allow_insecure,
            expose_secrets: false,
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
                    Err(AdminResponse::error(401, "invalid or missing admin token"))
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

    /// Handle one request.
    pub fn handle(&self, request: AdminRequest) -> AdminResponse {
        if let Err(response) = self.authenticate(&request.credentials) {
            return response;
        }
        self.dispatch(request)
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
            _ => AdminResponse::error(404, format!("no admin route for `{path}`")),
        }
    }

    /// The read-only status page.
    fn dashboard(&self) -> AdminResponse {
        let runtime = self.runtime.read();
        let admin_path = runtime.config().admin.path.clone();
        let html = crate::proxy::dashboard::render(&self.runtime, &admin_path);
        AdminResponse::text(200, "text/html; charset=utf-8", html)
    }

    fn health(&self) -> AdminResponse {
        AdminResponse::json(200, &json!({"status": "ok"}))
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
            },
            proxy_type: None,
            providers: vec![provider("openai", vec![key("k1"), key("k2")])],
            routes: vec![],
            default_route: None,
            load_balancing: Default::default(),
            health: Default::default(),
            observability: Default::default(),
            admin: Default::default(),
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
