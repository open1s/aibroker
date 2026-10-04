# AGENTS.md — LLM Broker

## Project Overview

**Goal**: A local LLM proxy that load-balances across a pool of API keys,
rotates onto another key when one is rate limited, and exposes the pool for
runtime management.

**Tech stack**: Rust (edition 2024) + [pingora](https://github.com/cloudflare/pingora)
as the HTTP proxy foundation. There is exactly **one** backend: pingora. The
old reqwest/axum backend was removed deliberately — two implementations of key
rotation drift apart.

## Build & Run

```bash
cargo build --offline          # dependencies are already in the local registry
cargo test  --offline          # 143 unit + 7 end-to-end tests
cargo fmt --all
cargo clippy --offline --all-targets   # must stay warning-free
cargo run -- --config config.toml
cargo run -- --config config.toml --check   # validate config and env secrets
```

Sandbox note: the DSH file sandbox blocks writes to the global mise cargo
registry, so a plain `cargo build` can fail while *downloading*. Everything is
fetched already; prefer `--offline`. For a genuinely new dependency, either
fetch outside the sandbox or use a workspace-local cargo home:

```bash
CARGO_HOME=.cargo-home cargo build
```

## Architecture

```
src/
  main.rs                  CLI, config loading, startup
  config/mod.rs            Schema, validation, persistence, `env:` secrets
  core/                    Framework-independent; no HTTP types
    key_state.rs           Per-key health, cooldown, limits, counters, KeyGuard
    ratelimit.rs           Sliding-window RPM/TPM limiter
    pool.rs                KeyPool: availability gate + strategy dispatch
    strategy.rs            The seven selection strategies
    broker.rs              Model -> provider routing, failover order
    auth.rs                Per-provider credential conventions
    metrics.rs             Prometheus registry
    runtime.rs             Config + Broker + metrics; hot reload with state transfer
  proxy/
    pingora_backend.rs     ProxyHttp adapter: routing, retry, in-process admin/metrics
    admin.rs               Control-plane routing + authentication (transport-free)
    control.rs             Control-plane listener for `admin.mode = "separate"`
    body.rs                Model and `usage` extraction from bodies
tests/proxy_integration.rs Real proxy + mock upstream over TCP
```

### Layering rules

- **Scheduling decisions belong in `core/`.** The pingora layer must not
  implement selection, health or rate-limit logic; it translates HTTP into core
  calls and back.
- **`core/` must not depend on pingora, axum or any transport.** It is the part
  that is cheap to test, so keep it that way.
- **`config/` owns everything the operator can change.** Runtime state that is
  not configuration (cooldowns, counters) lives in `core/key_state.rs`.

## Key invariants (do not regress)

These are all covered by tests. Break one and a test should fail — if it does
not, add the test.

1. **Availability is checked before selection and the token budget is consumed
   exactly once.** `KeyPool::try_strategy` filters with
   `KeyState::availability` and only then hands the survivors to a strategy, so
   a strategy can never return a cooling-down or over-quota key. The original
   1.x code discarded the limiter result and leaked tokens.
2. **`reserve()` gates in-flight accounting.** `select` charges the rate-limit
   window; `reserve()` returns a `KeyGuard` that releases exactly one in-flight
   slot even if the request is dropped.
3. **`KeySnapshot` never restores `enabled`.** `enabled` belongs to the config;
   restoring it from a pre-rebuild snapshot silently re-enabled keys that an
   operator had just disabled.
4. **Config invalidation is atomic.** `Runtime::apply` validates a clone and
   only then swaps in the new broker, so a rejected change leaves the running
   configuration untouched.
5. **A transport error after a response has started must not trigger a replay**
   — unless the error came from `upstream_response_filter` (429/5xx), in which
   case the retry decision is deliberate and must be preserved. Both halves have
   burned us: retrying on a normal end-of-response close duplicated requests,
   and clearing the flag defeated key rotation entirely.
6. **Admin auth fails closed.** No token and no `allow_insecure` means refuse,
   with a constant-time comparison.
7. **Secrets never appear in admin responses.** `/admin/keys` and `/admin/status`
   expose state, never `key`. `/admin/config` is the documented exception and is
   token-gated.

## Load balancing strategies

| Strategy | Behaviour |
|----------|-----------|
| `round_robin` | Deterministic rotation |
| `weighted_random` | Weight × headroom × health, tolerance-adjusted |
| `least_busy` | Fewest in-flight, ties broken by health |
| `least_latency` | Lowest EWMA latency |
| `usage_based` | Lowest current RPM/TPM utilisation |
| `power_of_two` | Best of two random candidates by effective weight |
| `fallback` | First viable key in config order |

`least_used` and `latency_based` are accepted aliases for 1.x configs.
`load_balancing.fallback_strategies` lists strategies tried in order when the
primary one cannot place the request.

## Key rotation

Cooldown follows `initial * multiplier^level`, capped at `max_cooldown_secs`
and jittered by `cooldown_jitter`. Defaults give 1min → 5min → 25min. An
upstream `Retry-After` overrides the escalation for that key. The failure score
is an exponential decay (`score *= 0.8` per failure) and a success clears the
streak and starts lifting the score back toward `1.0`.

## pingora constraints worth knowing

- `upstream_peer` runs **before** the request body is streamed, and pingora
  offers no way to re-inject a peeked body. Do not call
  `Session::read_request_body` there: it consumes the payload and the upstream
  receives an empty body. Routing signals are limited to headers and the path
  (`x-llm-model` and `ProxyService::resolve_early_model`).
- A filter that returns `Err` propagates through `error_while_proxy`, which is
  where retry decisions can be overwritten. See invariant 5.
- `ServerConf::max_retries` bounds the retry loop; `build_server_conf` maps
  `server.max_retries` onto it. Each retry re-enters `upstream_peer`.
- `ResponseHeader::build` takes the status as a `u16`; `error_while_proxy` must
  always call `set_retry` explicitly (pingora panics otherwise).

## Testing

- Unit tests live beside their modules and cover selection, rate limits, health,
  routing, auth schemes, body parsing and the admin API.
- `tests/proxy_integration.rs` runs the real proxy against a mock upstream and
  is the only place end-to-end failover is proven: 429 → different key → 200,
  with the body replayed. Extend it rather than trusting a unit test for
  anything involving the retry loop.
- The mock upstream must read its request body **before** answering; a pingora
  service that replies without draining the body makes the client see a 400.
- Test clients must not half-close the connection (no `shutdown(Write)`) and
  must read the body according to `Content-Length`/chunked framing. A
  `Connection: close` request header makes pingora skip the body.

## Conventions

- `thiserror` for library errors; `anyhow` only in `main`.
- No `unwrap` on anything reachable from a request path.
- `parking_lot` for synchronous locks; `tokio::sync` only when a lock is held
  across an `await` (see the admin serialisation lock).
- New config fields need a `#[serde(default)]` and a sensible default so
  existing configs keep loading.
- Keep `clippy --all-targets` clean; CI treats warnings as failures.
- **Never commit a literal secret.** `config.toml`, `test-real-config.toml`
  and `*.log` are gitignored; `config.example.toml` uses `env:NAME` for every
  credential. Before every push, run
  `git grep -nE "nvapi-|sk-[A-Za-z0-9]{20,}"` over the tree and confirm it is
  empty. A secret that reaches a public remote must be rotated, not just
  deleted: it stays in the object store until the history is rewritten.
