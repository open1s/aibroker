//! Request-payload inspection, by JSON parsing.
//!
//! The broker needs a few things out of a request body: the model to route on,
//! the output-token cap to reserve TPM, and which OpenAI dialect the payload
//! speaks. These were previously recovered with a targeted string scan, which is
//! fast but *wrong* on realistic input: a decoy nested object wins over the real
//! top-level field.
//!
//! ```text
//! {"metadata":{"model":"decoy"},"model":"gpt-4o"}   ->  scanned "decoy"
//! ```
//!
//! That is not a cosmetic problem. The value is used to choose a provider and is
//! forwarded upstream as the model, so a hijacked value routes the request to
//! the wrong place or asks a provider for a model that does not exist. Parsing
//! costs a few hundred microseconds on a large prompt and removes the whole
//! class of error, so it is the right trade.
//!
//! Parsing is bounded: a body larger than [`MAX_PARSE_BYTES`] is not parsed at
//! all. The cap exists so a pathological payload cannot turn into an allocation
//! spike, and it is generous enough that no real prompt hits it.

use serde_json::Value;

use crate::core::api::ApiFormat;

/// Largest body this module will parse.
///
/// An agentic client can send a few hundred kilobytes of context; a megabyte is
/// comfortably above that while still bounding the work.
pub const MAX_PARSE_BYTES: usize = 1024 * 1024;

/// A parsed request body, or the reason it was not parsed.
#[derive(Debug, Clone)]
pub enum Payload {
    /// Parsed as a JSON object.
    Json(Box<Value>),
    /// Not JSON, or not an object: forwarded untouched, routed by other signals.
    Unparsed,
}

impl Payload {
    /// Parse a request body, refusing anything oversized or non-object.
    pub fn parse(body: &[u8]) -> Self {
        if body.is_empty() || body.len() > MAX_PARSE_BYTES {
            return Payload::Unparsed;
        }
        match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(map)) => Payload::Json(Box::new(Value::Object(map))),
            Ok(_) => Payload::Unparsed,
            Err(_) => Payload::Unparsed,
        }
    }

    pub fn value(&self) -> Option<&Value> {
        match self {
            Payload::Json(value) => Some(value),
            Payload::Unparsed => None,
        }
    }

    /// The top-level `model` string.
    ///
    /// Only the top level: a nested `model` belongs to a tool schema, a
    /// metadata blob or an embedded provider config, and none of those describe
    /// what this request is asking for.
    pub fn model(&self) -> Option<&str> {
        self.string_at(&["model"])
            // Some gateways spell it differently at the top level.
            .or_else(|| self.string_at(&["model_id"]))
            .or_else(|| self.string_at(&["modelId"]))
    }

    /// The requested output-token cap, across both dialects.
    pub fn token_cap(&self) -> Option<u64> {
        for key in [
            "max_output_tokens",
            "max_completion_tokens",
            "max_tokens",
            "maxTokens",
            "maxOutputTokens",
        ] {
            if let Some(value) = self.u64_at(&[key]) {
                return Some(value);
            }
        }
        None
    }

    /// A rough prompt size in tokens, from the serialised body.
    pub fn estimated_prompt_tokens(&self, body_len: usize) -> u64 {
        (body_len as u64).div_ceil(4)
    }

    /// Which dialect this request's *shape* indicates.
    ///
    /// The endpoint already tells the broker a lot, so this only speaks up when
    /// the body is unambiguous and contradicts it -- a Responses payload posted
    /// to the chat path, or the reverse. `detect_format` combines the two.
    pub fn format_from_shape(&self) -> Option<ApiFormat> {
        let value = self.value()?;

        // The Responses API takes `input`; Chat Completions takes `messages`.
        let has_input = value.get("input").is_some();
        let has_messages = value.get("messages").is_some();
        // `max_output_tokens` is Responses-only; `max_tokens` is chat-only.
        let responses_cap = value.get("max_output_tokens").is_some();
        let chat_cap = value.get("max_tokens").is_some();
        // `instructions` is the Responses system prompt; `response_format` is
        // chat-only (Responses spells it `text.format`).
        let has_instructions = value.get("instructions").is_some();
        let has_response_format = value.get("response_format").is_some();

        let responses_score =
            u8::from(has_input) + u8::from(responses_cap) + u8::from(has_instructions);
        let chat_score =
            u8::from(has_messages) + u8::from(chat_cap) + u8::from(has_response_format);

        match responses_score.cmp(&chat_score) {
            std::cmp::Ordering::Greater => Some(ApiFormat::Responses),
            std::cmp::Ordering::Less => Some(ApiFormat::ChatCompletions),
            // A tie means the body does not distinguish them (`{"model":"m"}`),
            // so the endpoint's verdict must stand.
            std::cmp::Ordering::Equal => None,
        }
    }

    /// The top-level `stream` flag.
    pub fn is_streaming(&self) -> bool {
        self.value()
            .and_then(|v| v.get("stream"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn string_at(&self, path: &[&str]) -> Option<&str> {
        let mut current = self.value()?;
        for key in path {
            current = current.get(*key)?;
        }
        current.as_str().filter(|s| !s.trim().is_empty())
    }

    fn u64_at(&self, path: &[&str]) -> Option<u64> {
        let mut current = self.value()?;
        for key in path {
            current = current.get(*key)?;
        }
        current.as_u64()
    }
}

/// Combine the endpoint's verdict with the body's shape.
///
/// The path is authoritative when the body is silent or absent: `/v1/responses`
/// is the Responses API no matter how sparse the payload is. When the body
/// contradicts the path -- which happens when a client posts a Responses payload
/// to `/v1/chat/completions`, or a proxy rewrites the path -- the body wins,
/// because the fields it contains are what the provider will actually read.
pub fn detect_format(path_format: ApiFormat, payload: Option<&Payload>) -> ApiFormat {
    if path_format != ApiFormat::Other {
        if let Some(from_body) = payload.and_then(Payload::format_from_shape)
            && from_body != path_format
        {
            return from_body;
        }
        return path_format;
    }
    // An unrecognised path: trust the body if it is unambiguous. This is what
    // makes a gateway that mounts the API somewhere unusual still work.
    payload
        .and_then(Payload::format_from_shape)
        .unwrap_or(ApiFormat::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(body: &str) -> Payload {
        Payload::parse(body.as_bytes())
    }

    #[test]
    fn the_top_level_model_is_found() {
        assert_eq!(
            json(r#"{"model":"gpt-4o","messages":[]}"#).model(),
            Some("gpt-4o")
        );
        // Key order must not matter.
        assert_eq!(
            json(r#"{"messages":[],"model":"claude-3-5-sonnet"}"#).model(),
            Some("claude-3-5-sonnet")
        );
    }

    #[test]
    fn a_nested_decoy_model_does_not_hijack_routing() {
        // The regression this module exists for: the old string scan returned
        // "decoy" here, which would route the request to the wrong provider.
        assert_eq!(
            json(r#"{"metadata":{"model":"decoy"},"model":"gpt-4o"}"#).model(),
            Some("gpt-4o")
        );
        assert_eq!(
            json(r#"{"tools":[{"function":{"parameters":{"model":"decoy"}}}],"model":"gpt-4o"}"#)
                .model(),
            Some("gpt-4o")
        );
        // A decoy with no top-level model must yield nothing, not the decoy.
        assert_eq!(json(r#"{"metadata":{"model":"decoy"}}"#).model(), None);
    }

    #[test]
    fn a_model_embedded_in_prompt_content_is_not_the_model() {
        assert_eq!(
            json(r#"{"messages":[{"content":"my {\"model\": \"gpt-3.5\"} config"}],"model":"gpt-4o"}"#)
                .model(),
            Some("gpt-4o")
        );
        assert_eq!(
            json(r#"{"input":"set the \"model\" field","model":"gpt-4o"}"#).model(),
            Some("gpt-4o")
        );
    }

    #[test]
    fn an_empty_or_blank_model_is_not_a_model() {
        assert_eq!(json(r#"{"model":"","messages":[]}"#).model(), None);
        assert_eq!(json(r#"{"model":"   ","messages":[]}"#).model(), None);
        assert_eq!(json(r#"{"model":null}"#).model(), None);
        assert_eq!(json(r#"{"model":42}"#).model(), None);
    }

    #[test]
    fn the_token_cap_is_read_in_both_dialects() {
        assert_eq!(json(r#"{"max_tokens":4096}"#).token_cap(), Some(4096));
        assert_eq!(
            json(r#"{"max_completion_tokens":2048}"#).token_cap(),
            Some(2048)
        );
        assert_eq!(
            json(r#"{"max_output_tokens":8192}"#).token_cap(),
            Some(8192)
        );
        assert_eq!(json(r#"{"model":"m"}"#).token_cap(), None);
    }

    #[test]
    fn the_shape_distinguishes_the_two_dialects() {
        assert_eq!(
            json(r#"{"model":"m","messages":[]}"#).format_from_shape(),
            Some(ApiFormat::ChatCompletions)
        );
        assert_eq!(
            json(r#"{"model":"m","input":"hi"}"#).format_from_shape(),
            Some(ApiFormat::Responses)
        );
        // `max_tokens` is chat-only; `max_output_tokens` is Responses-only.
        assert_eq!(
            json(r#"{"model":"m","max_tokens":5}"#).format_from_shape(),
            Some(ApiFormat::ChatCompletions)
        );
        assert_eq!(
            json(r#"{"model":"m","max_output_tokens":5}"#).format_from_shape(),
            Some(ApiFormat::Responses)
        );
        assert_eq!(
            json(r#"{"model":"m","instructions":"be terse"}"#).format_from_shape(),
            Some(ApiFormat::Responses)
        );
        assert_eq!(
            json(r#"{"model":"m","messages":[],"response_format":{"type":"json_object"}}"#)
                .format_from_shape(),
            Some(ApiFormat::ChatCompletions)
        );
    }

    #[test]
    fn an_ambiguous_body_does_not_pick_a_side() {
        // `{"model":"m"}` is legal in both dialects, so the endpoint decides.
        assert_eq!(json(r#"{"model":"m"}"#).format_from_shape(), None);
        assert_eq!(
            json(r#"{"model":"m","stream":true}"#).format_from_shape(),
            None
        );
    }

    #[test]
    fn a_contradicting_body_beats_the_path() {
        // A Responses payload posted to the chat path: the provider would read
        // `input` and ignore `messages`, so the body is the truth.
        let payload = json(r#"{"model":"m","input":"hi"}"#);
        assert_eq!(
            detect_format(ApiFormat::ChatCompletions, Some(&payload)),
            ApiFormat::Responses
        );

        let chat = json(r#"{"model":"m","messages":[]}"#);
        assert_eq!(
            detect_format(ApiFormat::Responses, Some(&chat)),
            ApiFormat::ChatCompletions
        );
    }

    #[test]
    fn the_path_is_authoritative_when_the_body_is_silent() {
        let ambiguous = json(r#"{"model":"m"}"#);
        assert_eq!(
            detect_format(ApiFormat::Responses, Some(&ambiguous)),
            ApiFormat::Responses
        );
        // No body at all (a GET, an oversized payload).
        assert_eq!(
            detect_format(ApiFormat::ChatCompletions, None),
            ApiFormat::ChatCompletions
        );
        assert_eq!(
            detect_format(ApiFormat::Responses, None),
            ApiFormat::Responses
        );
    }

    #[test]
    fn an_unknown_path_can_be_rescued_by_the_body() {
        // A gateway that mounts the API under its own prefix.
        let payload = json(r#"{"model":"m","input":"hi"}"#);
        assert_eq!(
            detect_format(ApiFormat::Other, Some(&payload)),
            ApiFormat::Responses
        );
        let chat = json(r#"{"model":"m","messages":[]}"#);
        assert_eq!(
            detect_format(ApiFormat::Other, Some(&chat)),
            ApiFormat::ChatCompletions
        );
        // Unknown path and uninformative body stays unknown.
        assert_eq!(
            detect_format(ApiFormat::Other, Some(&json(r#"{"model":"m"}"#))),
            ApiFormat::Other
        );
    }

    #[test]
    fn non_json_and_non_object_bodies_are_unparsed() {
        assert!(matches!(Payload::parse(b"not json"), Payload::Unparsed));
        assert!(matches!(Payload::parse(b"[1,2,3]"), Payload::Unparsed));
        assert!(matches!(Payload::parse(b""), Payload::Unparsed));
        assert!(matches!(
            Payload::parse(b"{\"model\":\"m\"}"),
            Payload::Json(_)
        ));
    }

    #[test]
    fn an_oversized_body_is_not_parsed() {
        // Bounded work: the cap is what stops a pathological payload from
        // becoming an allocation spike.
        let big = format!(r#"{{"model":"m","pad":"{}"}}"#, "x".repeat(MAX_PARSE_BYTES));
        assert!(matches!(Payload::parse(big.as_bytes()), Payload::Unparsed));
        assert_eq!(MAX_PARSE_BYTES, 1024 * 1024);
    }

    #[test]
    fn the_stream_flag_is_read() {
        assert!(json(r#"{"stream":true}"#).is_streaming());
        assert!(!json(r#"{"stream":false}"#).is_streaming());
        assert!(!json(r#"{"model":"m"}"#).is_streaming());
    }
}
