//! Request-body inspection: what is inside the prompt about to be sent.
//!
//! Everything else in the security plane looks at *metadata* — who is calling,
//! which model, which provider, how many tokens. This module looks at the
//! content, which is the part that actually leaves the building: an API key
//! pasted into a prompt, a customer's email, a national ID number, a private
//! key in a diff.
//!
//! Design decisions worth stating, because a naive scanner here is worse than
//! none:
//!
//! - **Patterns are explicit.** There is no attempt to guess what "sensitive"
//!   means. An operator lists the shapes they care about, and the shipped
//!   examples are the obvious credentials rather than a guess at someone's PII
//!   policy.
//! - **`report` is a first-class action.** The honest default for content
//!   inspection is to *find out* before blocking: a false positive that refuses
//!   a request is a broken tool. `deny` is available once the patterns have been
//!   watched against real traffic.
//! - **An allow-list runs first, by masking.** A pattern that matches test
//!   fixtures or documentation examples produces noise that trains people to
//!   ignore the guard — but only the matched spans are blanked, never the whole
//!   body. Skipping the body was a bypass: one `example.com` in a `git config`
//!   line suppressed every finding in the request.
//! - **Findings never include the match.** The report names the pattern, not the
//!   secret — otherwise the security log becomes the leak.

use regex::Regex;

use crate::proxy::redact::compile_pattern;

/// What to do when a pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GuardAction {
    /// Report the finding and forward the request.
    ///
    /// The default on purpose: a content scanner needs to be watched against
    /// real traffic before it is allowed to refuse anything.
    #[default]
    Report,
    /// Refuse the request with 403. The body is not forwarded.
    Deny,
}

impl GuardAction {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "report" | "warn" | "log" | "shadow" => GuardAction::Report,
            "deny" | "block" | "refuse" | "enforce" => GuardAction::Deny,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            GuardAction::Report => "report",
            GuardAction::Deny => "deny",
        }
    }
}

/// A named pattern, so a finding can be reported without its match.
#[derive(Debug, Clone)]
struct GuardRule {
    /// Stable identifier, used as a label and in findings.
    name: String,
    regex: Regex,
}

/// A content finding, deliberately without the matched text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule that matched.
    pub rule: String,
    /// Which field of the payload it was found in, e.g. `messages`.
    pub field: String,
}

impl Finding {
    /// A line safe to log: it names what matched, never what was matched.
    pub fn describe(&self) -> String {
        format!("{} in `{}`", self.rule, self.field)
    }
}

/// The content guard: patterns and an allow-list, compiled once.
#[derive(Debug, Default)]
pub struct ContentGuard {
    rules: Vec<GuardRule>,
    allow: Vec<Regex>,
    action: GuardAction,
}

impl ContentGuard {
    /// Compile a guard from `(name, pattern)` rules and allow-list patterns.
    ///
    /// Fails on a bad pattern so the operator hears about it at startup.
    pub fn new(
        rules: &[(String, String)],
        allow: &[String],
        action: GuardAction,
    ) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(rules.len());
        for (name, pattern) in rules {
            let regex =
                compile_pattern(pattern).map_err(|e| format!("content rule `{name}`: {e}"))?;
            compiled.push(GuardRule {
                name: name.clone(),
                regex,
            });
        }
        let mut allow_compiled = Vec::with_capacity(allow.len());
        for pattern in allow {
            let regex =
                compile_pattern(pattern).map_err(|e| format!("content allow-list pattern: {e}"))?;
            allow_compiled.push(regex);
        }
        Ok(Self {
            rules: compiled,
            allow: allow_compiled,
            action,
        })
    }

    pub fn action(&self) -> GuardAction {
        self.action
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Rule names, for the admin API and the startup banner.
    pub fn rule_names(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.name.as_str())
    }

    /// Scan a request body.
    ///
    /// Returns the first finding, or `None`. Only the first is reported: a body
    /// with three secrets in it is one problem, and listing them all buries the
    /// signal.
    ///
    /// Allow-listed spans are *blanked out*, not used to skip the request.
    ///
    /// Skipping the whole body when any allow pattern matched was a bypass. A
    /// realistic agent request contains an address like `dev@example.com` in a
    /// `git config` line, so a body that also carried a live `sk-proj-...` key
    /// reported **nothing** — the allow-list matched first and the scan never
    /// ran. Measured on a 6.5 KB request: the guard saw 0 findings while the key
    /// was redacted from the log, which is exactly the "looks like it works"
    /// failure this module is supposed to prevent.
    ///
    /// Masking keeps the intent — a documentation example should not raise an
    /// alert — without letting one benign string disable inspection of the rest.
    /// The replacement is a same-byte-length filler so offsets and the
    /// surrounding JSON stay intact.
    pub fn scan(&self, body: &[u8]) -> Option<Finding> {
        if self.rules.is_empty() {
            return None;
        }
        let mut text = std::str::from_utf8(body).ok()?.to_string();
        for pattern in &self.allow {
            let spans: Vec<(usize, usize)> = pattern
                .find_iter(&text)
                .map(|m| (m.start(), m.end()))
                .collect();
            if spans.is_empty() {
                continue;
            }
            let mut masked = String::with_capacity(text.len());
            let mut cursor = 0usize;
            for (start, end) in spans {
                masked.push_str(&text[cursor..start]);
                // Same byte length, so every other offset is unaffected.
                for _ in 0..(end - start) {
                    masked.push(' ');
                }
                cursor = end;
            }
            masked.push_str(&text[cursor..]);
            text = masked;
        }
        for rule in &self.rules {
            if let Some(found) = rule.regex.find(&text) {
                return Some(Finding {
                    rule: rule.name.clone(),
                    field: field_around(&text, found.start()),
                });
            }
        }
        None
    }
}

/// Name the JSON-ish field a match sits in, for the report.
///
/// Walks back to the nearest `"key":` before the match. This is best-effort by
/// design: the point is to tell an operator *which* part of the payload to look
/// at, and a wrong guess costs a glance rather than correctness.
fn field_around(text: &str, offset: usize) -> String {
    let prefix = &text[..offset];
    let mut name = None;
    for (index, _) in prefix.match_indices('"') {
        let rest = &prefix[index + 1..];
        let Some(end) = rest.find('"') else { break };
        let candidate = &rest[..end];
        // A key is followed by `:` once whitespace is skipped.
        let after = rest[end + 1..].trim_start();
        if after.starts_with(':') && !candidate.is_empty() && candidate.len() < 64 {
            name = Some(candidate.to_string());
        }
    }
    // `messages`/`input` are the interesting ones; anything nested inside them
    // (a `content` field) is more useful than nothing.
    name.unwrap_or_else(|| "body".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(rules: &[(&str, &str)]) -> ContentGuard {
        ContentGuard::new(
            &rules
                .iter()
                .map(|(n, p)| ((*n).to_string(), (*p).to_string()))
                .collect::<Vec<_>>(),
            &[],
            GuardAction::Report,
        )
        .unwrap()
    }

    #[test]
    fn a_pasted_credential_is_found() {
        let guard = guard(&[
            ("aws-key", r"AKIA[0-9A-Z]{16}"),
            ("github-token", r"ghp_[A-Za-z0-9]{20,}"),
        ]);
        let body = br#"{"messages":[{"role":"user","content":"use AKIAIOSFODNN7EXAMPLE please"}]}"#;
        let finding = guard.scan(body).expect("the key should be found");
        assert_eq!(finding.rule, "aws-key");
        assert!(
            !finding.describe().contains("AKIA"),
            "the finding must not carry the secret: {}",
            finding.describe()
        );
    }

    #[test]
    fn a_clean_body_produces_nothing() {
        let guard = guard(&[("aws-key", r"AKIA[0-9A-Z]{16}")]);
        assert!(
            guard
                .scan(br#"{"messages":[{"content":"hello"}]}"#)
                .is_none()
        );
    }

    #[test]
    fn every_rule_is_checked_and_the_first_match_wins() {
        let guard = guard(&[("first", r"FIRST-SECRET"), ("second", r"SECOND-SECRET")]);
        assert_eq!(guard.scan(b"FIRST-SECRET").unwrap().rule, "first");
        assert_eq!(guard.scan(b"SECOND-SECRET").unwrap().rule, "second");
    }

    #[test]
    fn an_allow_list_suppresses_a_known_benign_match() {
        // Documentation and test fixtures contain example keys; without this the
        // guard cries wolf until nobody reads it.
        let allow = vec![r"EXAMPLE".to_string()];
        let guard = ContentGuard::new(
            &[("aws-key".to_string(), r"AKIA[0-9A-Z]{16}".to_string())],
            &allow,
            GuardAction::Report,
        )
        .unwrap();

        assert!(
            guard
                .scan(br#"{"content":"AKIAIOSFODNN7EXAMPLE"}"#)
                .is_none(),
            "the allow-list should suppress this"
        );
        assert!(
            // Deliberately does not contain the allow-listed word, and is
            // obviously not a credential: a synthetic value that *did* contain
            // it would be suppressed by the allow-list and prove nothing.
            guard
                .scan(br#"{"content":"AKIAFAKEKEYFAKEKEY12"}"#)
                .is_some(),
            "and only the allow-listed one is suppressed"
        );
    }

    #[test]
    fn an_allow_listed_string_does_not_disable_the_rest_of_the_scan() {
        // The bypass this replaces: the allow-list was applied to the whole
        // body, so one benign `example.com` in a `git config` line suppressed
        // every finding in a 6.5 KB request -- including a live API key. It
        // looked like the guard was working, because the redactor (a separate
        // list) still scrubbed the key from the log.
        let guard = ContentGuard::new(
            &[(
                "openai-key".to_string(),
                r"sk-proj-[A-Za-z0-9_-]{20,}".to_string(),
            )],
            &[r"example\.com".to_string()],
            GuardAction::Report,
        )
        .unwrap();

        let body = br#"{"messages":[{"content":"git config user.email dev@example.com && export KEY=sk-proj-EXAMPLE-NOT-A-REAL-KEY-0001"}]}"#;
        let finding = guard
            .scan(body)
            .expect("the key must still be found when an example is also present");
        assert_eq!(finding.rule, "openai-key");
    }

    #[test]
    fn an_allow_listed_value_alone_is_still_suppressed() {
        // The masking must not defeat the allow-list's purpose.
        let guard = ContentGuard::new(
            &[("aws-key".to_string(), r"AKIA[0-9A-Z]{16}".to_string())],
            &[r"EXAMPLE".to_string()],
            GuardAction::Report,
        )
        .unwrap();

        assert!(
            guard
                .scan(br#"{"content":"AKIAIOSFODNN7EXAMPLE"}"#)
                .is_none(),
            "an allow-listed example should not raise a finding"
        );
    }

    #[test]
    fn masking_preserves_offsets_for_the_field_lookup() {
        // The filler is the same byte length as the match, so the reported
        // field still points at the right key.
        let guard = ContentGuard::new(
            &[("key".to_string(), r"SECRET-[0-9]+".to_string())],
            &[r"benign-very-long-placeholder".to_string()],
            GuardAction::Report,
        )
        .unwrap();
        let body = br#"{"a":"benign-very-long-placeholder","content":"SECRET-42"}"#;
        let finding = guard.scan(body).expect("found");
        assert_eq!(finding.rule, "key");
        assert_eq!(finding.field, "content");
    }

    #[test]
    fn the_finding_names_the_field_it_was_in() {
        let guard = guard(&[("email", r"[\w.]+@[\w.-]+\.\w+")]);
        let body =
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"mail ada@example.com"}]}"#;
        let finding = guard.scan(body).unwrap();
        assert_eq!(finding.rule, "email");
        // `content` is the nearest key before the match.
        assert_eq!(finding.field, "content");
    }

    #[test]
    fn a_body_with_no_json_still_scans() {
        // A non-JSON body (a provider-specific format) must not evade the guard.
        let guard = guard(&[("phone", r"\d{3}-\d{3}-\d{4}")]);
        let finding = guard.scan(b"call 555-123-4567 now").unwrap();
        assert_eq!(finding.rule, "phone");
        assert_eq!(finding.field, "body");
    }

    #[test]
    fn an_empty_guard_scans_nothing() {
        let guard = ContentGuard::default();
        assert!(guard.is_empty());
        assert!(guard.scan(b"AKIAIOSFODNN7EXAMPLE").is_none());
    }

    #[test]
    fn a_bad_pattern_fails_at_construction() {
        let error = ContentGuard::new(
            &[("broken".to_string(), "(unclosed".to_string())],
            &[],
            GuardAction::Report,
        )
        .unwrap_err();
        assert!(error.contains("broken"), "{error}");
        assert!(error.contains("invalid pattern"), "{error}");
    }

    #[test]
    fn a_pattern_matching_everything_is_rejected() {
        // `.*` would report every request; a security control that fires on
        // everything is indistinguishable from one that is broken.
        let error = ContentGuard::new(
            &[("greedy".to_string(), ".*".to_string())],
            &[],
            GuardAction::Report,
        )
        .unwrap_err();
        assert!(error.contains("matches everything"), "{error}");
    }

    #[test]
    fn binary_bodies_do_not_panic() {
        let guard = guard(&[("secret", r"SECRET")]);
        assert!(guard.scan(&[0xff, 0xfe, 0x00]).is_none());
        assert!(guard.scan(b"SECRET").is_some());
    }

    #[test]
    fn the_action_parses_both_spellings_and_defaults_to_reporting() {
        assert_eq!(GuardAction::default(), GuardAction::Report);
        for value in ["report", "warn", "log", "shadow", "REPORT"] {
            assert_eq!(
                GuardAction::parse(value),
                Some(GuardAction::Report),
                "{value}"
            );
        }
        for value in ["deny", "block", "refuse", "enforce", "Deny"] {
            assert_eq!(
                GuardAction::parse(value),
                Some(GuardAction::Deny),
                "{value}"
            );
        }
        assert_eq!(GuardAction::parse("nonsense"), None);
    }

    /// The credential patterns shipped in `config.example.toml`, paired with a
    /// realistic value each one is supposed to catch.
    ///
    /// This exists because a pattern that misses the real format is
    /// indistinguishable from a working guard: it reports zero findings and
    /// looks healthy. The `openai-key` rule shipped as `sk-[A-Za-z0-9]{20,}`,
    /// which does **not** match a modern `sk-proj-...` key because of the
    /// hyphen, and nothing noticed until a body containing one was sent through
    /// a live broker.
    const SHIPPED_RULES: &[(&str, &str, &str)] = &[
        ("aws-key", r"AKIA[0-9A-Z]{16}", "AKIAIOSFODNN7EXAMPLE"),
        (
            "private-key",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
        ),
        (
            "github-token",
            r"ghp_[A-Za-z0-9]{20,}",
            "ghp_EXAMPLENOTAREALKEY00000000",
        ),
        (
            "openai-key",
            r"sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}",
            "sk-proj-EXAMPLE-NOT-A-REAL-KEY-0001",
        ),
        (
            "anthropic-key",
            r"sk-ant-[A-Za-z0-9_-]{20,}",
            "sk-ant-EXAMPLE-NOT-A-REAL-KEY-0001",
        ),
        (
            "nvidia-key",
            r"nvapi-[A-Za-z0-9_-]{20,}",
            "nvapi-EXAMPLE-NOT-A-REAL-KEY-0000001",
        ),
        (
            "slack-token",
            r"xox[baprs]-[A-Za-z0-9-]{10,}",
            "xoxb-EXAMPLE-NOT-A-REAL-TOKEN-0001",
        ),
        ("email", r"[\w.+-]+@[\w-]+\.[\w.]+", "ada@example.com"),
    ];

    #[test]
    fn every_shipped_pattern_matches_a_realistic_value() {
        for (name, pattern, sample) in SHIPPED_RULES {
            let guard = ContentGuard::new(
                &[(name.to_string(), pattern.to_string())],
                &[],
                GuardAction::Report,
            )
            .unwrap_or_else(|e| panic!("rule `{name}` does not compile: {e}"));

            assert!(
                guard.scan(sample.as_bytes()).is_some(),
                "rule `{name}` ({pattern}) does not match `{sample}`, so it would \
                 report nothing while appearing to protect"
            );
        }
    }

    #[test]
    fn the_shipped_patterns_are_the_ones_in_the_example_config() {
        // Guards against the example and this list drifting apart: if someone
        // edits a pattern in one place, this fails rather than silently leaving
        // the documented rule broken.
        let example = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml"),
        )
        .expect("the example config should be readable");

        for (name, pattern, _) in SHIPPED_RULES {
            let expected = format!("# pattern = \"{}\"", pattern.replace('\\', "\\\\"));
            assert!(
                example.contains(&expected),
                "config.example.toml does not contain the {name} pattern this test \
                 verifies; expected a line `{expected}`"
            );
        }
    }

    #[test]
    fn a_prefix_only_rule_would_miss_a_hyphenated_key() {
        // The exact defect, kept as a test so the reasoning is not lost: this is
        // the pattern that shipped and reported nothing.
        let broken = guard(&[("openai-key", r"sk-[A-Za-z0-9]{20,}")]);
        assert!(
            broken
                .scan(b"sk-proj-EXAMPLE-NOT-A-REAL-KEY-0001")
                .is_none(),
            "the old pattern is expected to miss a hyphenated key"
        );

        let fixed = guard(&[("openai-key", r"sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}")]);
        assert!(
            fixed.scan(b"sk-proj-EXAMPLE-NOT-A-REAL-KEY-0001").is_some(),
            "the corrected pattern must match"
        );
    }

    #[test]
    fn rule_names_are_available_for_reporting() {
        let guard = guard(&[("aws-key", r"AKIA[0-9A-Z]{16}"), ("email", r"a@b\.c")]);
        let names: Vec<&str> = guard.rule_names().collect();
        assert_eq!(names, vec!["aws-key", "email"]);
        assert_eq!(guard.len(), 2);
    }
}
