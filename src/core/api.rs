//! Which OpenAI API dialect a request speaks.
//!
//! Two very similar APIs are in use, and they differ in the places the broker
//! cares about:
//!
//! | | Chat Completions | Responses |
//! |---|---|---|
//! | path | `POST /v1/chat/completions` | `POST /v1/responses` |
//! | token cap | `max_tokens` / `max_completion_tokens` | `max_output_tokens` |
//! | usage | `prompt_tokens` / `completion_tokens` | `input_tokens` / `output_tokens` |
//! | stream | one `data:` line per chunk, `[DONE]` | typed events, `response.completed` |
//!
//! The request `model` field is the same in both. What differs is *where the
//! model can be found before the body is read*: only the URL path and headers
//! are available to `upstream_peer` (pingora cannot re-inject a peeked body), so
//! for `/v1/responses` -- which has no model in its path -- the broker needs
//! either an `x-llm-model` header or a `?model=` query parameter.
//!
//! This lives in `core/` so the classification can be unit-tested and reused
//! without dragging in a transport.

/// The API dialect of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiFormat {
    /// `POST /v1/chat/completions`
    ChatCompletions,
    /// `POST /v1/responses`
    Responses,
    /// Completions, embeddings, or anything else passed through untouched.
    Other,
}

impl ApiFormat {
    /// Stable label for logs and metrics labels.
    pub fn as_str(self) -> &'static str {
        match self {
            ApiFormat::ChatCompletions => "chat_completions",
            ApiFormat::Responses => "responses",
            ApiFormat::Other => "other",
        }
    }

    /// Classify a request path, ignoring any query string.
    pub fn from_path(path: &str) -> Self {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let path = path.trim_end_matches('/');
        // Accept a provider-specific prefix (Azure deployments, gateways that
        // mount the API under `/openai`) by matching the tail.
        if path.ends_with("/v1/chat/completions") || path == "/chat/completions" {
            return ApiFormat::ChatCompletions;
        }
        if path.ends_with("/v1/responses") || path == "/responses" {
            return ApiFormat::Responses;
        }
        ApiFormat::Other
    }

    /// Whether this dialect can supply the model in the URL path.
    ///
    /// Chat Completions cannot (the path is fixed); providers that put the model
    /// in the path (`/v1/models/<m>:generateContent`) are [`ApiFormat::Other`]
    /// and are handled by the path parser.
    pub fn model_is_in_path(self) -> bool {
        matches!(self, ApiFormat::Other)
    }
}

impl std::fmt::Display for ApiFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extract a `model` query parameter, for calls that cannot send a header.
///
/// The OpenAI SDK cannot be told to add a header per request without a custom
/// HTTP client, but `client.responses.create(..., extra_query={"model": ...})`
/// is awkward too -- the header is the better path. This exists so a plain
/// `curl` works:
///
/// ```text
/// POST /v1/responses?model=gpt-4o
/// ```
///
/// The parameter is left in the upstream URL: it is not part of the OpenAI API,
/// so providers ignore it, and rewriting the query risks breaking a provider
/// that does use it.
pub fn model_from_query(query: Option<&str>) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key.eq_ignore_ascii_case("model") {
            let value = percent_decode(value);
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Decode `%XX` escapes and `+`, which is what a query string uses.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Token-cap field names, per dialect.
///
/// A caller that omits the cap asks for the provider's default, which can be
/// large; the estimate falls back to a conservative constant in that case.
pub const CHAT_TOKEN_CAP_KEYS: [&str; 3] = ["max_tokens", "max_completion_tokens", "maxTokens"];
pub const RESPONSES_TOKEN_CAP_KEYS: [&str; 2] = ["max_output_tokens", "maxTokens"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_completions_is_recognised() {
        assert_eq!(
            ApiFormat::from_path("/v1/chat/completions"),
            ApiFormat::ChatCompletions
        );
        assert_eq!(
            ApiFormat::from_path("/chat/completions"),
            ApiFormat::ChatCompletions
        );
        // A gateway prefix (Azure, LiteLLM, this broker behind another one).
        assert_eq!(
            ApiFormat::from_path("/openai/deployments/gpt4/v1/chat/completions"),
            ApiFormat::ChatCompletions
        );
        // A trailing slash and a query string are both tolerated.
        assert_eq!(
            ApiFormat::from_path("/v1/chat/completions/?foo=1"),
            ApiFormat::ChatCompletions
        );
    }

    #[test]
    fn the_responses_api_is_recognised() {
        assert_eq!(ApiFormat::from_path("/v1/responses"), ApiFormat::Responses);
        assert_eq!(ApiFormat::from_path("/responses"), ApiFormat::Responses);
        assert_eq!(
            ApiFormat::from_path("/openai/v1/responses?model=gpt-4o"),
            ApiFormat::Responses
        );
    }

    #[test]
    fn other_paths_stay_other() {
        for path in [
            "/v1/models",
            "/v1/models/gpt-4o:generateContent",
            "/v1/embeddings",
            "/health",
        ] {
            assert_eq!(ApiFormat::from_path(path), ApiFormat::Other, "{path}");
        }
    }

    #[test]
    fn a_path_that_merely_ends_in_responses_is_not_the_api() {
        // `/v1/responses_batch` must not be classified as the Responses API,
        // or it would take the wrong model-resolution path.
        assert_eq!(
            ApiFormat::from_path("/v1/responses_batch"),
            ApiFormat::Other
        );
        assert_eq!(ApiFormat::from_path("/v1/responsesfoo"), ApiFormat::Other);
    }

    #[test]
    fn only_non_openai_paths_report_the_model_as_being_in_the_path() {
        assert!(!ApiFormat::ChatCompletions.model_is_in_path());
        assert!(!ApiFormat::Responses.model_is_in_path());
        assert!(ApiFormat::Other.model_is_in_path());
    }

    #[test]
    fn labels_are_stable_because_they_are_metric_labels() {
        assert_eq!(ApiFormat::ChatCompletions.as_str(), "chat_completions");
        assert_eq!(ApiFormat::Responses.as_str(), "responses");
        assert_eq!(ApiFormat::Other.as_str(), "other");
    }

    #[test]
    fn a_model_query_parameter_is_read() {
        assert_eq!(
            model_from_query(Some("model=gpt-4o")),
            Some("gpt-4o".to_string())
        );
        assert_eq!(
            model_from_query(Some("foo=1&model=claude-3-5-sonnet&bar=2")),
            Some("claude-3-5-sonnet".to_string())
        );
        // Case-insensitive key, percent-encoded value.
        assert_eq!(
            model_from_query(Some("MODEL=deepseek-ai%2Fdeepseek-v4%3Aflash")),
            Some("deepseek-ai/deepseek-v4:flash".to_string())
        );
        assert_eq!(model_from_query(Some("model=a+b")), Some("a b".to_string()));
    }

    #[test]
    fn a_missing_or_empty_model_parameter_is_none() {
        assert_eq!(model_from_query(None), None);
        assert_eq!(model_from_query(Some("")), None);
        assert_eq!(model_from_query(Some("other=1")), None);
        assert_eq!(model_from_query(Some("model=")), None);
        assert_eq!(model_from_query(Some("model=%20")), None);
    }

    #[test]
    fn a_malformed_escape_does_not_panic_or_lose_text() {
        // A stray `%` must survive rather than truncating the value.
        assert_eq!(
            model_from_query(Some("model=100%")),
            Some("100%".to_string())
        );
        assert_eq!(model_from_query(Some("model=%zz")), Some("%zz".to_string()));
    }
}
