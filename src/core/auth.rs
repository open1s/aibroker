//! Provider authentication conventions.
//!
//! Different providers expect the credential in different places: OpenAI and
//! most compatible gateways want `Authorization: Bearer`, Anthropic wants
//! `x-api-key`, Azure wants `api-key`, and a few gateways want a query
//! parameter. The old code hard-coded three of those; this makes the scheme
//! explicit and configurable.

use http::{HeaderName, HeaderValue};
use pingora::http::RequestHeader;

use crate::config::ProviderConfig;
use crate::error::{LlmBrokerError, Result};

/// Where a provider expects the credential.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <key>`.
    #[default]
    Bearer,
    /// `x-api-key: <key>`.
    XApiKey,
    /// `api-key: <key>`.
    ApiKey,
    /// An arbitrary header, e.g. `x-goog-api-key`.
    Header(String),
    /// A query parameter, e.g. `?key=...`.
    Query(String),
    /// No credential is attached (local/self-hosted upstreams).
    None,
}

impl AuthScheme {
    /// Build the scheme for a provider, applying per-provider conventions when
    /// the config does not state one explicitly.
    pub fn from_config(provider: &ProviderConfig) -> Result<Self> {
        let Some(raw) = provider.auth.as_deref() else {
            return Ok(Self::default_for_provider(&provider.name));
        };

        let normalized = raw.trim().to_ascii_lowercase();
        let scheme = match normalized.as_str() {
            "bearer" | "authorization" => AuthScheme::Bearer,
            "x-api-key" | "x_api_key" => AuthScheme::XApiKey,
            "api-key" | "api_key" => AuthScheme::ApiKey,
            "none" | "off" | "disabled" => AuthScheme::None,
            "query" => AuthScheme::Query(
                provider
                    .auth_query_param
                    .clone()
                    .unwrap_or_else(|| "key".to_string()),
            ),
            "" => return Ok(Self::default_for_provider(&provider.name)),
            other => {
                // A bare token is treated as a custom header name, but only if
                // it looks like one; anything else is a config error.
                if other.contains(|c: char| c.is_whitespace() || c == ':') {
                    return Err(LlmBrokerError::InvalidConfig(format!(
                        "provider `{}` has invalid auth scheme `{raw}`",
                        provider.name
                    )));
                }
                AuthScheme::Header(other.to_string())
            }
        };
        Ok(scheme)
    }

    /// Provider-specific defaults matching documented APIs.
    pub fn default_for_provider(provider: &str) -> Self {
        match provider.to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => AuthScheme::XApiKey,
            "azure" | "azure_openai" => AuthScheme::ApiKey,
            "vertex" | "google" | "gemini" => AuthScheme::Header("x-goog-api-key".to_string()),
            _ => AuthScheme::Bearer,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            AuthScheme::Bearer => "bearer",
            AuthScheme::XApiKey => "x-api-key",
            AuthScheme::ApiKey => "api-key",
            AuthScheme::Header(name) => name,
            AuthScheme::Query(param) => param,
            AuthScheme::None => "none",
        }
    }

    /// True when the credential travels in the query string.
    pub fn is_query(&self) -> bool {
        matches!(self, AuthScheme::Query(_))
    }

    /// Attach the credential to an outgoing request.
    ///
    /// Any client-supplied credential header is removed first so credentials
    /// configured for the broker can never leak upstream and a client cannot
    /// pin a specific key.
    pub fn apply(&self, req: &mut RequestHeader, key: &str) {
        req.remove_header("authorization");
        req.remove_header("x-api-key");
        req.remove_header("api-key");
        req.remove_header("x-goog-api-key");

        match self {
            AuthScheme::Bearer => {
                if let Ok(value) = format!("Bearer {key}").parse::<HeaderValue>() {
                    req.insert_header("authorization", value).ok();
                }
            }
            AuthScheme::XApiKey => {
                if let Ok(value) = key.parse::<HeaderValue>() {
                    req.insert_header("x-api-key", value).ok();
                }
            }
            AuthScheme::ApiKey => {
                if let Ok(value) = key.parse::<HeaderValue>() {
                    req.insert_header("api-key", value).ok();
                }
            }
            AuthScheme::Header(name) => {
                // `insert_header` needs an owned name with a `'static`
                // lifetime, so parse the configured header name.
                if let (Ok(header), Ok(value)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    key.parse::<HeaderValue>(),
                ) {
                    req.insert_header(header, value).ok();
                }
            }
            AuthScheme::Query(_) | AuthScheme::None => {}
        }
    }

    /// Append the credential to a query string, if this scheme needs it.
    pub fn decorate_query(&self, query: Option<&str>, key: &str) -> Option<String> {
        let AuthScheme::Query(param) = self else {
            return query.map(|q| q.to_string());
        };
        let encoded = urlencode(key);
        let mut parts: Vec<String> = Vec::new();
        if let Some(query) = query.filter(|q| !q.is_empty()) {
            // Drop a client-supplied value for the same parameter so the
            // broker's key always wins.
            let prefix = format!("{param}=");
            for pair in query.split('&') {
                if !pair.starts_with(&prefix) {
                    parts.push(pair.to_string());
                }
            }
        }
        parts.push(format!("{param}={encoded}"));
        Some(parts.join("&"))
    }
}

/// Minimal percent-encoding for query values.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::http::RequestHeader;

    fn provider(name: &str, auth: Option<&str>, query_param: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            base_url: None,
            path_prefix: None,
            auth: auth.map(|a| a.to_string()),
            auth_query_param: query_param.map(|p| p.to_string()),
            default_models: vec![],
            max_rpm: None,
            max_tpm: None,
            max_concurrency: None,
            api_keys: vec![],
        }
    }

    fn header_value(req: &RequestHeader, name: &str) -> Option<String> {
        req.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    #[test]
    fn provider_defaults_follow_documented_apis() {
        assert_eq!(
            AuthScheme::from_config(&provider("anthropic", None, None)).unwrap(),
            AuthScheme::XApiKey
        );
        assert_eq!(
            AuthScheme::from_config(&provider("azure", None, None)).unwrap(),
            AuthScheme::ApiKey
        );
        assert_eq!(
            AuthScheme::from_config(&provider("openai", None, None)).unwrap(),
            AuthScheme::Bearer
        );
    }

    #[test]
    fn explicit_scheme_overrides_the_default() {
        let scheme = AuthScheme::from_config(&provider("openai", Some("X-Api-Key"), None)).unwrap();
        assert_eq!(scheme, AuthScheme::XApiKey);
        let custom =
            AuthScheme::from_config(&provider("openai", Some("X-Custom-Auth"), None)).unwrap();
        assert_eq!(custom, AuthScheme::Header("x-custom-auth".to_string()));
    }

    #[test]
    fn query_scheme_uses_the_configured_parameter() {
        let scheme =
            AuthScheme::from_config(&provider("gateway", Some("query"), Some("api_key"))).unwrap();
        assert_eq!(scheme, AuthScheme::Query("api_key".to_string()));
        assert!(scheme.is_query());
    }

    #[test]
    fn apply_replaces_client_credentials_rather_than_appending() {
        let mut req = RequestHeader::build("POST", b"/v1/chat/completions", None).unwrap();
        req.insert_header("authorization", "Bearer client-key")
            .unwrap();
        req.insert_header("x-api-key", "client-key").unwrap();

        AuthScheme::Bearer.apply(&mut req, "broker-key");
        assert_eq!(
            header_value(&req, "authorization").as_deref(),
            Some("Bearer broker-key")
        );
        assert_eq!(
            header_value(&req, "x-api-key"),
            None,
            "client credential must be stripped"
        );
    }

    #[test]
    fn apply_sets_the_right_header_per_scheme() {
        let mut req = RequestHeader::build("POST", b"/v1/messages", None).unwrap();
        AuthScheme::XApiKey.apply(&mut req, "sk-ant");
        assert_eq!(header_value(&req, "x-api-key").as_deref(), Some("sk-ant"));

        let mut req = RequestHeader::build("POST", b"/v1/messages", None).unwrap();
        AuthScheme::ApiKey.apply(&mut req, "sk-azure");
        assert_eq!(header_value(&req, "api-key").as_deref(), Some("sk-azure"));

        let mut req = RequestHeader::build("POST", b"/v1/models", None).unwrap();
        AuthScheme::Header("x-goog-api-key".into()).apply(&mut req, "goog");
        assert_eq!(
            header_value(&req, "x-goog-api-key").as_deref(),
            Some("goog")
        );
    }

    #[test]
    fn none_scheme_strips_credentials_and_adds_nothing() {
        let mut req = RequestHeader::build("POST", b"/v1/chat", None).unwrap();
        req.insert_header("authorization", "Bearer client").unwrap();
        AuthScheme::None.apply(&mut req, "ignored");
        assert_eq!(header_value(&req, "authorization"), None);
    }

    #[test]
    fn query_decoration_preserves_other_parameters() {
        let scheme = AuthScheme::Query("key".to_string());
        let query = scheme.decorate_query(Some("api-version=2024-02-01&key=client"), "broker");
        assert_eq!(
            query.as_deref(),
            Some("api-version=2024-02-01&key=broker"),
            "client-supplied key must be dropped"
        );
    }

    #[test]
    fn query_decoration_handles_empty_query() {
        let scheme = AuthScheme::Query("key".to_string());
        assert_eq!(
            scheme.decorate_query(None, "abc").as_deref(),
            Some("key=abc")
        );
        assert_eq!(
            scheme.decorate_query(Some(""), "abc").as_deref(),
            Some("key=abc")
        );
    }

    #[test]
    fn query_decoration_escapes_reserved_characters() {
        let scheme = AuthScheme::Query("key".to_string());
        let query = scheme.decorate_query(None, "a/b+c=d").unwrap();
        assert_eq!(query, "key=a%2Fb%2Bc%3Dd");
    }

    #[test]
    fn non_query_schemes_pass_the_query_through_untouched() {
        assert_eq!(
            AuthScheme::Bearer
                .decorate_query(Some("a=1"), "k")
                .as_deref(),
            Some("a=1")
        );
        assert_eq!(AuthScheme::Bearer.decorate_query(None, "k"), None);
    }

    #[test]
    fn invalid_scheme_names_are_rejected() {
        let error = AuthScheme::from_config(&provider("openai", Some("bad scheme"), None));
        assert!(error.is_err());
    }
}
