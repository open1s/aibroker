//! Redaction for dump output.
//!
//! Dumps are how an LLM integration gets debugged, and they are also the one
//! place where prompt content is written to durable storage — an agent's system
//! prompt carries workspace paths, repository URLs, file contents and whatever
//! the user pasted. Credentials are already redacted by header name, but a
//! secret inside a *body* (a key pasted into a prompt, a customer identifier, an
//! internal hostname) needs configured patterns.
//!
//! Rules that shape this module:
//!
//! - **Off unless configured.** A redactor that guesses invents false
//!   confidence, and silently mangling a debug dump is its own bug.
//! - **Patterns are compiled at startup.** A typo must fail when the operator
//!   starts the broker, not quietly stop protecting traffic an hour later.
//! - **An admin token is redacted even without patterns.** The broker's own
//!   control-plane token can appear in a dumped `Authorization` header or in a
//!   query string, and its exposure is our fault rather than the operator's.
//! - **Matched text is never echoed.** A replacement says *what* was hidden and
//!   how much, never any of the match itself.

use regex::Regex;

/// What a redacted span is replaced with, when the operator does not name it.
pub const DEFAULT_MASK: &str = "<redacted>";

/// A compiled redaction rule.
#[derive(Debug, Clone)]
pub struct RedactionRule {
    pub pattern: String,
    pub replacement: String,
    regex: Regex,
}

/// Applies the configured rules to dump text.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    rules: Vec<RedactionRule>,
}

impl Redactor {
    /// Compile rules from `(pattern, replacement)` pairs.
    ///
    /// A pattern that names a capture group can keep part of the match visible,
    /// which is what makes a redacted dump still useful for debugging an
    /// identifier: `(".+@(.+\\..+)", "***@$1")` hides the local part.
    pub fn new(rules: &[(String, String)]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(rules.len());
        for (pattern, replacement) in rules {
            let regex = compile_pattern(pattern)?;
            compiled.push(RedactionRule {
                pattern: pattern.clone(),
                replacement: if replacement.trim().is_empty() {
                    DEFAULT_MASK.to_string()
                } else {
                    replacement.clone()
                },
                regex,
            });
        }
        Ok(Self { rules: compiled })
    }

    /// A redactor whose only rule is the broker's own admin token.
    ///
    /// Always applied, even with no patterns configured: leaking our own
    /// control-plane credential into a log we wrote is our defect.
    pub fn with_admin_token(token: Option<&str>) -> Result<Self, String> {
        match token.filter(|t| !t.trim().is_empty()) {
            Some(token) => {
                // `regex::escape` because a token is arbitrary text, not a
                // pattern, and a token containing `+` or `(` would otherwise
                // produce either a compile error or a wrong match.
                Self::new(&[(regex::escape(token), DEFAULT_MASK.to_string())])
            }
            None => Ok(Self::default()),
        }
    }

    /// Add the admin-token rule to an existing redactor.
    pub fn plus_admin_token(mut self, token: Option<&str>) -> Result<Self, String> {
        if let Some(token) = token.filter(|t| !t.trim().is_empty()) {
            let extra = Self::new(&[(regex::escape(token), DEFAULT_MASK.to_string())])?;
            self.rules.extend(extra.rules);
        }
        Ok(self)
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// The patterns in force, for the startup banner. Never the replacements'
    /// matches, obviously — just the patterns.
    pub fn patterns(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.pattern.as_str())
    }

    /// Apply every rule to `text`.
    pub fn apply(&self, text: &str) -> String {
        let mut out = text.to_string();
        for rule in &self.rules {
            // `replace_all` with a `&str` replacement expands `$1` style
            // references, so an operator can keep a suffix of an identifier.
            out = rule
                .regex
                .replace_all(&out, rule.replacement.as_str())
                .into_owned();
        }
        out
    }
}

/// Compile a user-supplied regex, rejecting the pathological cases.
///
/// Shared with the content guard so both features agree on what a usable
/// pattern is, and so both fail at startup rather than on the first request.
///
/// A pattern that can match the empty string is rejected: for redaction it
/// would rewrite an entire dump, and for scanning it would "detect" every
/// request ever made, which is worse than useless in a security control.
pub fn compile_pattern(pattern: &str) -> Result<Regex, String> {
    let regex = Regex::new(pattern).map_err(|e| format!("invalid pattern `{pattern}`: {e}"))?;
    if regex.is_match("") {
        return Err(format!(
            "pattern `{pattern}` matches empty, so it matches everything"
        ));
    }
    Ok(regex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(rules: &[(&str, &str)]) -> Vec<(String, String)> {
        rules
            .iter()
            .map(|(p, r)| ((*p).to_string(), (*r).to_string()))
            .collect()
    }

    #[test]
    fn an_empty_redactor_changes_nothing() {
        let redactor = Redactor::default();
        assert!(redactor.is_empty());
        assert_eq!(redactor.apply("hello world"), "hello world");
    }

    #[test]
    fn a_configured_pattern_is_masked() {
        let redactor = Redactor::new(&pairs(&[(r"\d{3}-\d{2}-\d{4}", "")])).unwrap();
        let out = redactor.apply("ssn 123-45-6789 here");
        assert_eq!(out, "ssn <redacted> here");
        assert!(!out.contains("123-45-6789"));
    }

    #[test]
    fn a_replacement_may_keep_part_of_the_match() {
        // The useful case: hide the local part of an address, keep the domain so
        // the dump still says which vendor it was.
        let redactor = Redactor::new(&pairs(&[(r"([\w.]+)@([\w.-]+)", "***@$2")])).unwrap();
        let out = redactor.apply("contact ada@example.com now");
        assert_eq!(out, "contact ***@example.com now");
        assert!(!out.contains("ada@"));
    }

    #[test]
    fn several_rules_all_apply() {
        let redactor = Redactor::new(&pairs(&[
            (r"AKIA[0-9A-Z]{16}", "<aws-key>"),
            (r"ghp_[A-Za-z0-9]{20,}", "<gh-token>"),
        ]))
        .unwrap();
        let out = redactor.apply("keys AKIAIOSFODNN7EXAMPLE and ghp_EXAMPLENOTAREALKEY00000000");
        assert!(out.contains("<aws-key>"), "{out}");
        assert!(out.contains("<gh-token>"), "{out}");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "{out}");
    }

    #[test]
    fn a_bad_pattern_fails_at_construction() {
        // The whole point: an operator learns at startup, not when the traffic
        // is already being logged unredacted.
        let error = Redactor::new(&pairs(&[("(unclosed", "")])).unwrap_err();
        assert!(error.contains("invalid pattern"), "{error}");
        assert!(error.contains("(unclosed"), "{error}");
    }

    #[test]
    fn a_pattern_matching_the_empty_string_is_rejected() {
        // `a*` matches "" and would insert the mask between every character.
        let error = Redactor::new(&pairs(&[("a*", "")])).unwrap_err();
        assert!(error.contains("matches everything"), "{error}");
        // The pattern is named, so an operator can find it.
        assert!(error.contains("a*"), "{error}");
    }

    #[test]
    fn the_admin_token_is_redacted_without_any_configuration() {
        let redactor = Redactor::with_admin_token(Some("llmb-super-secret")).unwrap();
        let out = redactor.apply("Authorization: Bearer llmb-super-secret");
        assert_eq!(out, "Authorization: Bearer <redacted>");
        assert!(!out.contains("llmb-super-secret"));
    }

    #[test]
    fn a_token_full_of_regex_metacharacters_is_matched_literally() {
        // Without escaping, `(` would be a compile error and `+` would change
        // what matches -- turning a security control into a silent no-op.
        let token = "a+b(c)[d]|e$f^g";
        let redactor = Redactor::with_admin_token(Some(token)).unwrap();
        let out = redactor.apply("token=a+b(c)[d]|e$f^g&x=1");
        assert!(out.contains("<redacted>"), "{out}");
        assert!(!out.contains(token), "{out}");
    }

    #[test]
    fn no_admin_token_means_no_rule() {
        let redactor = Redactor::with_admin_token(None).unwrap();
        assert!(redactor.is_empty());
        let blank = Redactor::with_admin_token(Some("   ")).unwrap();
        assert!(blank.is_empty());
    }

    #[test]
    fn an_explicit_replacement_is_used_verbatim() {
        let redactor = Redactor::new(&pairs(&[("secret", "[hidden]")])).unwrap();
        assert_eq!(redactor.apply("a secret thing"), "a [hidden] thing");
    }
}
