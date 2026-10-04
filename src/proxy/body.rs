//! Request and response body inspection.
//!
//! The broker needs the `model` field to route a request and the `usage`
//! object to account tokens. Both are extracted with a small targeted scanner
//! rather than a full JSON parse, because LLM payloads include large message
//! arrays that we have no reason to materialise.

use std::collections::BTreeMap;

use crate::core::key_state::TokenUsage;

/// Largest request body we buffer while looking for `model`.
///
/// The peek stops as soon as the model is known, so this is an upper bound for
/// pathological bodies rather than a typical allocation.
pub const DEFAULT_REQUEST_SCAN_LIMIT: usize = 256 * 1024;

/// Field names carrying prompt tokens, across provider dialects.
const INPUT_TOKEN_KEYS: [&str; 5] = [
    "prompt_tokens",
    "input_tokens",
    "promptTokens",
    "prompt_eval_count",
    "promptTokenCount",
];

/// Field names carrying completion tokens, across provider dialects.
const OUTPUT_TOKEN_KEYS: [&str; 5] = [
    "completion_tokens",
    "output_tokens",
    "completionTokens",
    "eval_count",
    "candidatesTokenCount",
];

/// Object names that carry usage, used as a cheap pre-filter.
const USAGE_OBJECT_KEYS: [&str; 3] = ["usage", "usageMetadata", "prompt_eval_count"];

/// Find a numeric field anywhere in `text`.
fn number_field(text: &str, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let needle = format!("\"{key}\"");
        let mut search_from = 0usize;
        while let Some(offset) = text[search_from..].find(&needle) {
            let position = search_from + offset + needle.len();
            if let Some(value) = number_value_after(&text[position..]) {
                return Some(value);
            }
            search_from = position;
        }
    }
    None
}

/// Parse `: 123` or `: "123"` starting at `text`.
fn number_value_after(text: &str) -> Option<u64> {
    let mut chars = text.chars().peekable();
    loop {
        match chars.next() {
            Some(c) if c.is_whitespace() => continue,
            Some(':') => break,
            _ => return None,
        }
    }

    while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
        chars.next();
    }

    let quoted = chars.peek() == Some(&'"');
    if quoted {
        chars.next();
    }

    let mut digits = String::new();
    while let Some(c) = chars.peek().copied() {
        if c.is_ascii_digit() {
            digits.push(c);
            chars.next();
        } else {
            break;
        }
    }

    if digits.is_empty() {
        return None;
    }
    if quoted && chars.next() != Some('"') {
        return None;
    }
    digits.parse().ok()
}

/// Accumulates token usage across a streamed or buffered response body.
#[derive(Debug, Default)]
pub struct UsageAccumulator {
    /// Trailing bytes of an incomplete JSON object.
    carry: Vec<u8>,
    input: u64,
    output: u64,
    seen: bool,
    limit: usize,
    enabled: bool,
    total_bytes: usize,
}

impl UsageAccumulator {
    pub fn new(enabled: bool, limit: usize) -> Self {
        Self {
            carry: Vec::new(),
            input: 0,
            output: 0,
            seen: false,
            limit: limit.max(1024),
            enabled,
            total_bytes: 0,
        }
    }

    /// Feed a body chunk. Returns true when a usage object was completed.
    pub fn push(&mut self, chunk: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }
        self.total_bytes = self.total_bytes.saturating_add(chunk.len());
        self.carry.extend_from_slice(chunk);

        let parsed = std::str::from_utf8(&self.carry).ok().and_then(parse_usage);
        if let Some(usage) = parsed {
            self.input = self.input.max(usage.input);
            self.output = self.output.max(usage.output);
            self.seen = true;
            // Consume the parsed object so a later chunk cannot re-report it.
            self.trim_after_usage();
        }

        self.enforce_limit();
        self.seen
    }

    /// Keep only what follows the `usage` object we just parsed.
    fn trim_after_usage(&mut self) {
        let Ok(text) = std::str::from_utf8(&self.carry) else {
            self.carry.clear();
            return;
        };
        let Some(start) = text.find("\"usage") else {
            self.carry.clear();
            return;
        };
        // Skip to the end of the balanced object that started at `start`.
        let bytes = self.carry.clone();
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escaped = false;
        let mut end = None;
        for (offset, byte) in bytes[start..].iter().enumerate() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == b'"' {
                    in_string = false;
                }
                continue;
            }
            match byte {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(start + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let keep_from = end.unwrap_or(start);
        if keep_from >= self.carry.len() {
            self.carry.clear();
        } else {
            self.carry.drain(..keep_from);
        }
    }

    /// Trim whole leading objects until the carry fits the limit.
    fn enforce_limit(&mut self) {
        if self.carry.len() <= self.limit {
            return;
        }
        let excess = self.carry.len() - self.limit;
        let start = match self.carry[excess..].iter().position(|b| *b == b'{') {
            // Resume at a JSON object boundary so parsing stays valid.
            Some(offset) => excess + offset,
            None => excess,
        };
        self.carry.drain(..start);
    }

    /// Finish the stream and return whatever usage was observed.
    pub fn finish(&mut self) -> TokenUsage {
        if self.enabled
            && !self.seen
            && let Ok(text) = std::str::from_utf8(&self.carry)
            && let Some(usage) = parse_usage(text)
        {
            self.input = self.input.max(usage.input);
            self.output = self.output.max(usage.output);
            self.seen = true;
        }
        self.usage()
    }

    pub fn usage(&self) -> TokenUsage {
        TokenUsage {
            input: self.input,
            output: self.output,
        }
    }

    pub fn saw_usage(&self) -> bool {
        self.seen
    }

    /// Bytes inspected so far, reported in the access log.
    pub fn bytes_seen(&self) -> usize {
        self.total_bytes
    }
}

/// Pull `usage` (or `usageMetadata`) token counts out of a JSON document.
pub fn parse_usage(text: &str) -> Option<TokenUsage> {
    if !USAGE_OBJECT_KEYS
        .iter()
        .any(|key| text.contains(&format!("\"{key}")))
    {
        return None;
    }
    let input = number_field(text, &INPUT_TOKEN_KEYS);
    let output = number_field(text, &OUTPUT_TOKEN_KEYS);
    if input.is_none() && output.is_none() {
        return None;
    }
    Some(TokenUsage {
        input: input.unwrap_or(0),
        output: output.unwrap_or(0),
    })
}

/// Parse the `model` from a path such as `/v1/models/gpt-4:generateContent`.
pub fn model_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    let rest = trimmed.strip_prefix("v1/")?;
    let rest = rest.strip_prefix("models/")?;
    let name = rest
        .split(['/', ':', '?'])
        .next()
        .filter(|s| !s.is_empty())?;
    if name == "chat" || name == "completions" || name == "embeddings" {
        // Standard OpenAI paths put the model in the body instead.
        return None;
    }
    Some(name.to_string())
}

/// Rough token estimate used to reserve TPM budget before the real usage is
/// known. Deliberately conservative: ~4 characters per token plus the output
/// tokens requested by `max_tokens`.
pub fn estimate_request_tokens(body: &[u8]) -> u64 {
    let chars = body.len() as u64;
    let prompt = chars.div_ceil(4);
    let max_tokens = std::str::from_utf8(body)
        .ok()
        .and_then(|text| number_field(text, &TOKEN_CAP_KEYS))
        .unwrap_or(512);
    prompt.saturating_add(max_tokens)
}

/// Token-cap field names across both OpenAI dialects.
///
/// `max_output_tokens` is the Responses API spelling; `max_tokens` and
/// `max_completion_tokens` are Chat Completions. Reading only the chat names
/// would make every Responses call reserve the 512-token fallback and
/// under-count its TPM.
const TOKEN_CAP_KEYS: [&str; 5] = [
    "max_tokens",
    "max_completion_tokens",
    "max_output_tokens",
    "maxTokens",
    "maxOutputTokens",
];

/// Count of key/value pairs observed, used only for diagnostics.
pub fn json_field_count(text: &str) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for part in text.split("\":").take(64) {
        let key = part
            .rsplit('"')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if !key.is_empty() {
            *counts.entry(key).or_insert(0) += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_usage_reads_openai_shape() {
        let text =
            r#"{"id":"x","usage":{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46}}"#;
        let usage = parse_usage(text).expect("usage should parse");
        assert_eq!(usage.input, 12);
        assert_eq!(usage.output, 34);
        assert_eq!(usage.total(), 46);
    }

    #[test]
    fn parse_usage_reads_anthropic_shape() {
        let text = r#"{"usage":{"input_tokens":"100","output_tokens":"250"}}"#;
        let usage = parse_usage(text).expect("usage should parse");
        assert_eq!(usage.input, 100);
        assert_eq!(usage.output, 250);
    }

    #[test]
    fn parse_usage_reads_ollama_shape() {
        let ollama = r#"{"done":true,"prompt_eval_count":11,"eval_count":22}"#;
        let usage = parse_usage(ollama).expect("ollama fields should parse");
        assert_eq!(usage.input, 11);
        assert_eq!(usage.output, 22);
    }

    #[test]
    fn parse_usage_reads_gemini_metadata() {
        let gemini = r#"{"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":9,"totalTokenCount":14}}"#;
        let usage = parse_usage(gemini).expect("gemini metadata should parse");
        assert_eq!(usage.input, 5);
        assert_eq!(usage.output, 9);
        // `totalTokenCount` must not be mistaken for either direction.
        assert_eq!(usage.total(), 14);
    }

    #[test]
    fn parse_usage_returns_none_without_usage_keys() {
        assert!(parse_usage(r#"{"id":"x","choices":[]}"#).is_none());
        assert!(parse_usage(r#"{"usage":{}}"#).is_none());
    }

    #[test]
    fn accumulator_handles_usage_split_across_chunks() {
        let mut acc = UsageAccumulator::new(true, 64 * 1024);
        acc.push(br#"{"id":"a","usage":{"prompt_to"#);
        acc.push(br#"kens":10,"completion_tokens":20}}"#);
        let usage = acc.finish();
        assert_eq!(usage.input, 10);
        assert_eq!(usage.output, 20);
        assert!(acc.saw_usage());
    }

    #[test]
    fn accumulator_handles_sse_streaming_chunks() {
        let mut acc = UsageAccumulator::new(true, 64 * 1024);
        acc.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n");
        acc.push(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,");
        acc.push(b"\"completion_tokens\":3}}\n\n");
        acc.push(b"data: [DONE]\n\n");
        let usage = acc.finish();
        assert_eq!(usage.input, 7);
        assert_eq!(usage.output, 3);
    }

    #[test]
    fn accumulator_is_disabled_cleanly() {
        let mut acc = UsageAccumulator::new(false, 4096);
        assert!(!acc.push(br#"{"usage":{"prompt_tokens":5}}"#));
        assert!(acc.finish().is_empty());
    }

    #[test]
    fn accumulator_bounds_memory_for_huge_bodies() {
        let chunk = br#"{"pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#;
        let mut acc = UsageAccumulator::new(true, 2048);
        for _ in 0..200 {
            acc.push(chunk);
        }
        assert!(
            acc.carry.len() <= 2048,
            "carry grew to {} bytes",
            acc.carry.len()
        );
        assert_eq!(acc.bytes_seen(), 200 * chunk.len());
    }

    #[test]
    fn accumulator_keeps_the_tail_so_late_usage_is_still_seen() {
        let mut acc = UsageAccumulator::new(true, 4096);
        // A large message payload followed by a small usage object.
        for _ in 0..100 {
            acc.push(br#"{"pad":"yyyyyyyyyyyyyyyyyyyyyyyyyyyyy"}"#);
        }
        acc.push(br#","usage":{"prompt_tokens":1,"completion_tokens":2}}"#);
        let usage = acc.finish();
        assert_eq!(usage.input, 1);
        assert_eq!(usage.output, 2);
    }

    #[test]
    fn accumulator_takes_the_largest_usage_across_chunks() {
        let mut acc = UsageAccumulator::new(true, 64 * 1024);
        acc.push(br#"{"usage":{"prompt_tokens":5,"completion_tokens":5}}"#);
        acc.push(br#"{"usage":{"prompt_tokens":9,"completion_tokens":9}}"#);
        let usage = acc.finish();
        assert_eq!(usage.input, 9);
        assert_eq!(usage.output, 9);
    }

    #[test]
    fn model_from_path_reads_gemini_style_paths() {
        assert_eq!(
            model_from_path("/v1/models/gemini-pro:generateContent").as_deref(),
            Some("gemini-pro")
        );
        assert_eq!(
            model_from_path("/v1/models/gpt-4").as_deref(),
            Some("gpt-4")
        );
        assert_eq!(model_from_path("/v1/chat/completions"), None);
        assert_eq!(model_from_path("/v1/embeddings"), None);
        assert_eq!(model_from_path("/health"), None);
    }

    #[test]
    fn estimate_request_tokens_uses_max_tokens_when_present() {
        let small = estimate_request_tokens(br#"{"model":"m"}"#);
        assert!(small >= 512, "got {small}");

        let with_cap = estimate_request_tokens(br#"{"model":"m","max_tokens":4096}"#);
        assert!(with_cap >= 4096, "got {with_cap}");

        let big_prompt = estimate_request_tokens(&vec![b'a'; 40_000]);
        assert!(big_prompt >= 10_000, "got {big_prompt}");
    }

    #[test]
    fn estimate_request_tokens_understands_the_responses_dialect() {
        // `max_output_tokens` is the Responses API spelling. Reading only the
        // chat names would reserve the 512-token fallback and under-count TPM
        // for every Responses call.
        let responses = estimate_request_tokens(br#"{"model":"gpt-4o","max_output_tokens":4096}"#);
        let chat = estimate_request_tokens(br#"{"model":"gpt-4o","max_tokens":4096}"#);
        let completion =
            estimate_request_tokens(br#"{"model":"gpt-4o","max_completion_tokens":4096}"#);

        for (label, value) in [
            ("max_output_tokens", responses),
            ("max_tokens", chat),
            ("max_completion_tokens", completion),
        ] {
            assert!(
                (4096..4200).contains(&value),
                "{label}: expected ~4096 + prompt, got {value}"
            );
        }
    }

    #[test]
    fn a_response_body_usage_from_either_dialect_is_parsed() {
        // Chat Completions.
        let chat = parse_usage(
            r#"{"usage":{"prompt_tokens":11,"completion_tokens":22,"total_tokens":33}}"#,
        )
        .expect("chat usage");
        assert_eq!((chat.input, chat.output), (11, 22));

        // Responses: `input_tokens` / `output_tokens`, and a `total_tokens` that
        // is not the sum of the two when reasoning tokens are involved.
        let responses = parse_usage(
            r#"{"usage":{"input_tokens":36,"output_tokens":24,"total_tokens":60,"output_tokens_details":{"reasoning_tokens":24}}}"#,
        )
        .expect("responses usage");
        assert_eq!((responses.input, responses.output), (36, 24));
    }

    #[test]
    fn number_field_prefers_the_first_occurrence() {
        let text = r#"{"usage":{"prompt_tokens":3},"other":{"prompt_tokens":99}}"#;
        assert_eq!(number_field(text, &INPUT_TOKEN_KEYS), Some(3));
    }

    #[test]
    fn number_field_ignores_non_numeric_values() {
        let text = r#"{"prompt_tokens":"abc"}"#;
        assert_eq!(number_field(text, &INPUT_TOKEN_KEYS), None);
    }
}
