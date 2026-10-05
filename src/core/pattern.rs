//! Glob matching, in exactly one place.
//!
//! This lives in a leaf module because three layers need it and they sit in a
//! dependency chain: `security` -> `broker` -> `pool` -> `key_state`. Reaching
//! for a matcher across that chain would mean `key_state` depending on
//! `security` and closing the cycle.
//!
//! One implementation is the point, not tidiness. A client's `allowed_models`,
//! a key's `models` and a routing pattern must agree about what `deepseek-*`
//! means, or the broker forwards a model it told the policy it would refuse.

/// Iterative glob matcher supporting `*` and `?`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Glob match that also accepts an exact name case-insensitively.
///
/// Public because the policy bridge passes the verdict to Rego as a fact: one
/// implementation means a policy cannot disagree with the broker about what a
/// pattern means.
pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.contains('*') || pattern.contains('?') {
        glob_match(&pattern.to_ascii_lowercase(), &value.to_ascii_lowercase())
    } else {
        pattern.eq_ignore_ascii_case(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matcher_handles_wildcards() {
        assert!(glob_match("claude-*", "claude-3-opus"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("gpt-?.*", "gpt-4.5"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("claude-*", "gpt-4"));
        assert!(!glob_match("gpt-?", "gpt-44"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
    }
    #[test]
    fn a_bare_star_matches_everything_including_empty() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("*", ""));
    }

    #[test]
    fn exact_names_ignore_case_but_globs_are_case_insensitive_too() {
        assert!(pattern_matches("DeepSeek-V4", "deepseek-v4"));
        assert!(pattern_matches("DeepSeek-*", "deepseek-v4.1-flash"));
        assert!(!pattern_matches("deepseek-*", "kimi-k3"));
    }
}
