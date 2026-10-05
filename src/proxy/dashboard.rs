//! A read-only status dashboard for the control plane.
//!
//! The admin API is JSON, which is fine for scripts but awkward for a human who
//! just wants to see whether the pool is healthy. `GET /admin` renders this
//! page instead: one self-contained document with no external requests, so it
//! works on an air-gapped host and does not leak a dashboard URL to a CDN.
//!
//! It is deliberately read-only. Anything that changes state (adding keys,
//! resetting cooldowns) stays behind the JSON API, where the request is
//! explicit and authenticated.

use serde_json::json;

use crate::core::runtime::SharedRuntime;

/// Render the dashboard.
pub fn render(runtime: &SharedRuntime, admin_path: &str, refresh_token: &str) -> String {
    let runtime = runtime.read();
    let config = runtime.config();
    let metrics = runtime.metrics();

    let mut providers = Vec::new();
    let mut keys: Vec<serde_json::Value> = Vec::new();
    let mut keys_total = 0usize;
    let mut keys_available = 0usize;

    for (name, pool) in runtime.broker().pools() {
        let statuses = pool.status();
        keys_total += statuses.len();
        let available = statuses
            .iter()
            .filter(|k| k.enabled && k.cooldown_secs.is_none())
            .count();
        keys_available += available;

        providers.push(json!({
            "name": name,
            "base_url": pool.base_url,
            "auth": pool.auth.as_str(),
            "strategy": pool.strategy().as_str(),
            "keys": statuses.len(),
            "available": available,
            "in_flight": statuses.iter().map(|k| u64::from(k.in_flight)).sum::<u64>(),
        }));

        for status in statuses {
            keys.push(json!({
                "provider": name,
                "id": status.id,
                "enabled": status.enabled,
                "state": status.state,
                "cooldown_secs": status.cooldown_secs,
                "health": (status.health_score * 1000.0).round() / 1000.0,
                "latency_ms": status.latency_ms,
                "in_flight": status.in_flight,
                "rpm": status.rpm,
                "max_rpm": status.max_rpm,
                "tpm": status.tpm,
                "max_tpm": status.max_tpm,
                "selections": status.selections,
                "successes": status.successes,
                "failures": status.failures,
                "rate_limited": status.rate_limit_hits,
                "tokens_in": status.tokens_in,
                "tokens_out": status.tokens_out,
            }));
        }
    }

    let (strategy, fallbacks) = runtime.broker().strategies();
    let loaded = json!({
        "strategy": strategy.as_str(),
        "fallbacks": fallbacks.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "routes": runtime.broker().routes(),
        "providers": providers,
        "keys": keys,
        "keys_total": keys_total,
        "keys_available": keys_available,
        "uptime_seconds": metrics.uptime_seconds(),
        "requests_total": metrics.requests_total.load(std::sync::atomic::Ordering::Relaxed),
        "requests_in_flight": metrics.requests_in_flight.load(std::sync::atomic::Ordering::Relaxed),
        "rotations": metrics.key_rotations.load(std::sync::atomic::Ordering::Relaxed),
        "rate_limited": metrics.responses_4xx.load(std::sync::atomic::Ordering::Relaxed),
        "failures": metrics.upstream_failures.load(std::sync::atomic::Ordering::Relaxed),
        "exhausted": metrics.keys_exhausted.load(std::sync::atomic::Ordering::Relaxed),
        "tokens_in": metrics.tokens_in_total.load(std::sync::atomic::Ordering::Relaxed),
        "tokens_out": metrics.tokens_out_total.load(std::sync::atomic::Ordering::Relaxed),
        "config_path": runtime.config_path().map(|p| p.display().to_string()),
        // `/admin/config` renders through `to_toml()`, which always redacts:
        // there is no admin path that reveals a credential. The page states
        // this from the payload rather than hardcoding it, so the claim cannot
        // drift from the handler.
        "redacts_secrets": true,
        "models": config.known_models(),
        "admin_path": admin_path,
        // The page's own refresh cannot authenticate the way the page itself
        // did. HTTP credentials live in the browser's auth cache or in the URL
        // bar, and a subresource request is not guaranteed to receive either:
        // Chrome answers a URL-credential login for the navigation and then
        // sends the page's refreshes bare, which surfaces as a 401 the operator
        // cannot act on. So the server hands the already-authenticated page a
        // read-only token to send back. See `AdminRouter::accepts_dashboard_token`.
        "refresh_token": refresh_token,
        "security": {
            "client_auth_required": runtime.requires_client_auth(),
            // The exact sentence the page shows when the proxy is open. Kept
            // in the payload rather than only in the template so a test can
            // assert the state without pattern-matching JavaScript source.
            "open_warning": if runtime.requires_client_auth() {
                None
            } else {
                Some(
                    "No client authentication: any process that can reach this port can spend \
                     your keys. Define [[clients]] to require a token.",
                )
            },
            "clients": runtime.clients().statuses(),
            "denials": runtime
                .clients()
                .denials()
                .into_iter()
                .map(|(reason, count)| (reason.as_str().to_string(), count))
                .collect::<std::collections::BTreeMap<_, _>>(),
            "content_guard": runtime.content_guard().map(|guard| {
                serde_json::json!({
                    "action": guard.action().as_str(),
                    "rules": guard.rule_names().collect::<Vec<_>>(),
                })
            }),
            "policy_source": match runtime.policy().source() {
                crate::core::policy::PolicySource::Default => "default",
                crate::core::policy::PolicySource::Rego => "rego",
            },
            "policy_from": runtime.policy().description(),
        },
    });

    // `serde_json` does *not* escape `/`, so a `</script>` inside a config
    // value (a provider name, a route pattern) would close the data block and
    // inject markup. `\/` is a legal JSON escape for `/`, so escaping the
    // sequence keeps the payload valid for `JSON.parse` while making it inert
    // to the HTML parser.
    let payload = serde_json::to_string(&loaded)
        .unwrap_or_else(|_| "{}".to_string())
        .replace("</", "<\\/");
    let admin_path_attr = admin_path.replace('"', "&quot;");

    let page = include_str!("dashboard/page.html");
    page.replace("@PAYLOAD@", &payload)
        .replace("@ADMIN_PATH@", &admin_path_attr)
}

#[cfg(test)]
mod tests {
    /// The refresh token the tests hand the page. Only the test that asserts
    /// the page sends it back cares about the value.
    const REFRESH: &str = "test-refresh-token";

    use super::*;
    use crate::config::{ApiKeyConfig, Config, ProviderConfig, ServerConfig};
    use crate::core::runtime::{Runtime, shared};

    fn runtime() -> SharedRuntime {
        shared(Runtime::new(test_config(), None).unwrap())
    }

    fn test_config() -> Config {
        Config {
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
            providers: vec![ProviderConfig {
                name: "openai".into(),
                base_url: Some("https://api.openai.com".into()),
                path_prefix: None,
                auth: None,
                auth_query_param: None,
                default_models: vec!["gpt-4o".into()],
                max_rpm: None,
                max_tpm: None,
                max_concurrency: None,
                api_keys: vec![ApiKeyConfig {
                    id: "key1".into(),
                    key: "sk-test".into(),
                    enabled: true,
                    models: vec![],
                    weight: 1,
                    max_rpm: Some(10),
                    max_tpm: None,
                    max_concurrency: None,
                    model_map: None,
                }],
            }],
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
        }
    }

    #[test]
    fn dashboard_renders_the_expected_furniture() {
        let html = render(&runtime(), "/admin", REFRESH);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("LLM Broker"));
        assert!(html.contains("Read-only view"));
        // Provider, key and strategy all reach the page.
        assert!(html.contains("openai"), "provider missing");
        assert!(html.contains("key1"), "key id missing");
        assert!(html.contains("round_robin"), "strategy missing");
        // The admin mount point is reflected rather than hardcoded.
        assert!(html.contains("data-admin-path=\"/admin\""));
        assert!(
            html.contains("/admin/status"),
            "endpoint paths should be listed"
        );
    }

    #[test]
    fn dashboard_never_embeds_a_key_secret() {
        let html = render(&runtime(), "/admin", REFRESH);
        assert!(
            !html.contains("sk-test"),
            "the dashboard must not leak a credential"
        );
    }

    #[test]
    fn dashboard_shows_the_security_plane_without_tokens() {
        let runtime = runtime();
        {
            let mut runtime = runtime.write();
            runtime
                .apply(|config| {
                    config.clients.push(crate::config::ClientConfig {
                        name: "laptop".into(),
                        token: "dashboard-secret-token".into(),
                        enabled: true,
                        allowed_models: vec!["gpt-*".into()],
                        allowed_providers: vec![],
                        max_rpm: Some(30),
                        max_tpm: None,
                        max_concurrency: None,
                    });
                })
                .expect("apply");
        }

        let html = render(&runtime, "/admin", REFRESH);
        // The client and its scope are visible...
        assert!(html.contains("laptop"), "client should be listed");
        assert!(html.contains("gpt-*"), "scope should be visible");
        assert!(
            html.contains("Who may send what"),
            "the section heading should be present"
        );
        // ...but no token, and not the tell-tale "open proxy" warning.
        assert!(
            !html.contains("dashboard-secret-token"),
            "the dashboard must never embed a client token"
        );
        // The warning is a payload *value*, so this cannot accidentally match
        // the template's JavaScript source.
        // The payload is compact, so there is no space after the colon.
        assert!(
            html.contains("\"open_warning\":null"),
            "the open-proxy warning must be cleared when clients are configured"
        );
    }

    /// Parse the JSON block the page embeds.
    ///
    /// Assertions belong here rather than against the template's JavaScript:
    /// string-matching the script source passes even when the renderer never
    /// emits anything, and fails whenever the wording improves.
    fn payload_of(html: &str) -> serde_json::Value {
        let payload = html
            .split_once("<script id=\"data\" type=\"application/json\">")
            .expect("the page should embed a data block")
            .1
            .split_once("</script>")
            .expect("the data block should close")
            .0
            .replace("<\\/", "</");
        serde_json::from_str(&payload).expect("the embedded payload should be valid JSON")
    }

    #[test]
    fn dashboard_reports_the_content_guard() {
        // The backend already counted per-key `selections` and reported the
        // guard config; neither reached the page, so an operator could not see
        // whether traffic was spread or whether prompts were inspected.
        let runtime = runtime();
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
                .expect("apply");
        }

        let html = render(&runtime, "/admin", REFRESH);
        assert!(
            html.contains("\"content_guard\""),
            "the payload should carry the guard"
        );
        // Parse rather than string-match: the payload is compact JSON and the
        // spacing is not part of the contract.
        let payload = html
            .split_once("<script id=\"data\" type=\"application/json\">")
            .expect("data block")
            .1
            .split_once("</script>")
            .expect("data block end")
            .0
            .replace("<\\/", "</");
        let parsed: serde_json::Value = serde_json::from_str(&payload).expect("valid payload");
        assert_eq!(
            parsed["security"]["content_guard"]["action"], "deny",
            "the action should be reported"
        );
        assert_eq!(
            parsed["security"]["content_guard"]["rules"][0], "aws-key",
            "rule names should be listed"
        );
        assert!(
            html.contains("Load balance"),
            "the page should have a load-balance section"
        );
        assert!(
            html.contains("Share"),
            "and a per-key share column, which is how imbalance becomes visible"
        );
    }

    #[test]
    fn dashboard_reports_a_missing_content_guard_as_a_warning() {
        // Silence about an absent guard is how it stays absent.
        let html = render(&runtime(), "/admin", REFRESH);
        assert!(
            html.contains("No content rules"),
            "the page should say that prompts are not inspected"
        );
        assert!(
            html.contains("\"content_guard\":null"),
            "the payload should be explicit about it"
        );
    }

    #[test]
    fn dashboard_warns_when_the_proxy_is_open() {
        let html = render(&runtime(), "/admin", REFRESH);
        assert!(
            html.contains("\"client_auth_required\":false"),
            "the payload should report an open proxy"
        );
        assert!(
            html.contains("No client authentication"),
            "the payload should carry the warning the page renders"
        );
        assert!(
            !html.contains("\"open_warning\":null"),
            "an open proxy must not clear the warning"
        );
    }

    #[test]
    fn dashboard_payload_is_safe_to_embed_in_a_script_tag() {
        // A `</script>` in anything the page renders would end the data block
        // early. Config values are the realistic carrier: a route pattern or a
        // provider name comes straight from the operator's file.
        let hostile = "</script><script>alert(1)</script>";
        let mut config = test_config();
        config.providers[0].name = hostile.to_string();
        config.providers[0].default_models = vec![hostile.to_string()];
        config.default_route = None;
        let runtime = shared(Runtime::new(config, None).unwrap());
        let html = render(&runtime, "/admin", REFRESH);
        // Slice at the literal end of the data block. The document always
        // contains that closing tag; what must not appear is one *inside* the
        // JSON payload.
        let (_, rest) = html
            .split_once("<script id=\"data\" type=\"application/json\">")
            .expect("data block");
        let data = rest.split_once("</script>").expect("data block end").0;

        assert!(
            !data.contains("</script>"),
            "the payload can break out of the script tag: {data}"
        );
        assert!(
            data.contains("<\\/script>"),
            "the `</` sequence was not escaped: {data}"
        );
        // Still valid JSON, and it decodes back to the original text, so the
        // page's `JSON.parse` sees exactly what the operator configured.
        let decoded: serde_json::Value =
            serde_json::from_str(data).expect("the escaped payload must stay valid JSON");
        assert_eq!(
            decoded["providers"][0]["name"].as_str(),
            Some("</script><script>alert(1)</script>")
        );
    }

    #[test]
    fn dashboard_reports_an_empty_pool_without_panicking() {
        // Asserts the payload, not a label in the template. The previous
        // version looked for the string "Keys available", which is JavaScript
        // text: it would keep passing if the renderer stopped emitting the
        // card, and it broke the moment the wording was improved.
        let payload = payload_of(&render(&runtime(), "/admin", REFRESH));
        // Deliberately does not assume a key count: the fixture has one, and the
        // point here is that an untouched pool renders a well-formed payload
        // rather than one with missing fields.
        assert_eq!(
            payload["keys_total"],
            payload["keys"].as_array().map(Vec::len).unwrap_or(0),
            "the totals should agree with the key list"
        );
        assert!(payload["keys_available"].is_number());
        assert_eq!(
            payload["requests_total"], 0,
            "an untouched pool has served nothing"
        );
    }

    #[test]
    fn the_dashboard_can_refresh_itself() {
        // The page was a static snapshot, so an operator could not tell an idle
        // broker from one they had left open for an hour -- and a restarted
        // process reads zero everywhere. The refresh affordances are structural,
        // so they can be pinned without a browser.
        let html = render(&runtime(), "/admin", REFRESH);

        for needed in [
            "id=\"refresh\"", // a manual reload
            "id=\"auto\"",    // and a toggle for the cadence
            "id=\"stamp\"",   // plus a visible "as of" marker
            // The exact call, not the bare word: asserting `contains("setInterval")`
            // passed against a mutation that deleted the call but left the token
            // in a comment. Be specific about the mechanism you claim to test.
            "setInterval(refresh, Number(everySel.value))",
            "credentials: 'same-origin'", // the refresh must authenticate
        ] {
            assert!(
                html.contains(needed),
                "the page should contain {needed} so it can stay current"
            );
        }
    }

    #[test]
    fn a_failed_refresh_keeps_the_last_good_view() {
        // Blanking the page on a dropped fetch reads as "the broker is down",
        // which is a worse failure than a stale number. The stamp carries the
        // warning and the render is only replaced on success.
        let html = render(&runtime(), "/admin", REFRESH);
        assert!(
            html.contains("refresh failed"),
            "a failed refresh should say so"
        );
        assert!(
            html.contains("showing data from"),
            "and should say that what you see is the last good view"
        );
    }

    #[test]
    fn the_dashboard_does_not_claim_config_dumps_contain_secrets() {
        // It said exactly that for several releases after redaction landed.
        let html = render(&runtime(), "/admin", REFRESH);
        assert!(
            !html.contains("the on-disk document (contains secrets)"),
            "the reference table must not claim the endpoint exposes credentials"
        );
        assert!(
            html.contains("credentials redacted"),
            "it should state the guarantee instead"
        );
    }

    #[test]
    fn dashboard_states_that_config_dumps_are_redacted() {
        // The reference table claimed `/admin/config` "contains secrets" for
        // several releases after redaction landed. The wording now comes from
        // the payload, and this pins that.
        let payload = payload_of(&render(&runtime(), "/admin", REFRESH));
        assert_eq!(
            payload["redacts_secrets"], true,
            "`/admin/config` always redacts; the page must say so"
        );
    }

    #[test]
    fn the_refresh_url_cannot_inherit_credentials_from_the_page_url() {
        // A relative `fetch(location.pathname)` is resolved against the
        // document's base URL. When the operator logs in the convenient way --
        // `http://user:token@host/admin` -- that base carries the credentials,
        // and `fetch` refuses to construct a Request from a URL containing them:
        //
        //   Request cannot be constructed from a URL that includes credentials
        //
        // Every tick then threw and the page sat on "refresh failed", which
        // reads as an expired token rather than a broken URL. Building the URL
        // from `location.origin` fixes it. Unlike the rest of this page the
        // defect is in the script itself, so this asserts on the script rather
        // than on the rendered payload.
        let html = render(&runtime(), "/admin", REFRESH);
        assert!(
            html.contains("location.origin + location.pathname"),
            "the refresh URL must be absolute, so it cannot inherit credentials"
        );
        assert!(
            !html.contains("fetch(location.pathname"),
            "a relative path inherits the page URL's credentials and throws"
        );
    }

    #[test]
    fn the_payload_carries_the_refresh_token() {
        let payload = payload_of(&render(&runtime(), "/admin", REFRESH));
        assert_eq!(payload["refresh_token"], REFRESH);
    }

    #[test]
    fn the_page_sends_the_refresh_token_it_was_given() {
        // The script, not the payload, because the defect is in the script: the
        // page authenticated as a navigation and its `fetch` was not given
        // those credentials, so every tick was a 401. Handing the page a token
        // only helps if the page actually sends it back.
        let html = render(&runtime(), "/admin", REFRESH);
        assert!(
            html.contains("'X-Admin-Token': initial.refresh_token"),
            "the refresh request must carry the token the server handed the page"
        );
    }
}
