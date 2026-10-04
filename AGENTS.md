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

**Toolchain is pinned in `rust-toolchain.toml`** (currently 1.99.0) and CI
installs that same channel. Do not switch CI back to
`dtolnay/rust-toolchain@stable`: it floats, so a Rust release can turn the
build red with no source change. Rust 1.99 deprecating `Atomic::fetch_update`
in favour of `try_update` did exactly that, and `-D warnings` turned the
deprecation into a failure.

Bumping the pin is a deliberate change:

```bash
# 1. install and select the new channel (mise manages the toolchains here)
mise install rust@<version>
# 2. update channel in rust-toolchain.toml and the `toolchain:` values in
#    BOTH .github/workflows/ci.yml and .github/workflows/release.yml
# 3. fix fallout, then prove it on that toolchain
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
# 4. prove a cross target still builds the way CI does
cargo build --release --target x86_64-apple-darwin
```

Two traps when touching this:

- **Keep the workflows and the file in step.** `rust-toolchain.toml` wins over
  the action's `toolchain:` input, so a workflow left on `@stable` installs a
  different compiler than the one being tested. That mismatch is what broke the
  release job: `@stable` installed 1.99.0 in `release.yml` while the file pinned
  the same channel but with different targets.
- **`rust-toolchain.toml` also overrides the action's `targets:` input.**
  Cross targets then have to be installed explicitly, or the build fails with
  `can't find crate for \`core\``. `release.yml` does this with a dedicated
  `rustup target add` step; keep that step when editing the workflow.

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
    security.rs            Client tokens, egress scopes, per-client budgets
    policy.rs              Rego egress policy (regorus); builds policy facts
    api.rs                 API dialect classification; ?model= parsing
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
    dashboard.rs           Read-only status page served at the admin mount point
    dashboard/page.html    The page template (static asset, embedded via include_str!)
    control.rs             Control-plane listener for `admin.mode = "separate"`
    body.rs                `usage` extraction; token estimation
    payload.rs             JSON request parsing: model, token cap, dialect
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

## Data security (what may leave the machine)

Balancing picks the key; `core/security.rs` and `core/policy.rs` decide whether
the request may be forwarded at all. Enforcement happens once per request in
`upstream_peer`, *before* the body streams, so disallowed content is never
uploaded, and the client's in-flight slot is released in `logging`.

- **Tokens** are compared in constant time, and must never be logged, echoed in
  a refusal, or returned by the admin API. `/admin/security` reports scopes and
  budgets only; a test asserts the payload contains no token.
- **Pattern matching lives in Rust**, and the verdict reaches the policy as
  `client.model_allowed`. OPA's `glob.match` cannot match `gpt-4o` against
  `gpt-*` (its default delimiter is `.`), and one implementation keeps the
  policy and the broker from disagreeing about what a pattern means. regorus
  also ships no string builtins unless the `glob`/`regex` features are on.
- **A policy failure refuses the request.** A broker that forwards traffic when
  its policy engine is broken is worse than one that returns 500. An invalid
  policy fails at `Runtime::new`, not on the first request.
- **Denials are counted twice**: per client, and registry-wide by reason. An
  unknown token cannot be attributed to a client, and a policy denial happens
  after `authenticate`, so both counters are needed or the events vanish.
- **Empty `[[clients]]` means open**, which keeps the single-user setup
  working. Do not change that default silently.

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

**A strategy must share an identical pool.** `fallback` is the documented
exception: it is ordered failover, so pinning is its contract. Every other
strategy is expected to spread, and two shipped with defects that pinned traffic
instead — both found by *measuring* the distribution through a running proxy
rather than by reading the code, and both invisible to the existing unit tests:

- `least_latency` ranked an unmeasured key as infinitely slow. Once one key was
  measured it won forever, so the rest were never tried: 30/0/0.
- `least_busy` mixed health into the same float as in-flight at a magnitude
  larger than `best_by`'s tie tolerance, so equal keys were never "tied" and
  rotation never ran: 2/25/3.

When adding or changing a strategy, measure it. A unit test on `select` proves
which candidate a scoring function prefers; it does not prove that a pool shares
load, and both bugs above passed every unit test they had. `Score` is a trait so
a ranking can order lexicographically — do not compress two independent
decisions (explored? / how fast?) into one `f64`.

## Key rotation

Cooldown follows `initial * multiplier^level`, capped at `max_cooldown_secs`
and jittered by `cooldown_jitter`. Defaults give 1min → 5min → 25min. An
upstream `Retry-After` overrides the escalation for that key. The failure score
is an exponential decay (`score *= 0.8` per failure) and a success clears the
streak and starts lifting the score back toward `1.0`.

## Signals

`main.rs` owns `SIGINT` and `SIGTERM` instead of leaving them to pingora,
because pingora's graceful shutdown is a `thread::sleep` on the main thread and
signals arriving during that sleep are dropped: the process looked wedged for
the entire grace period and the only escape was `kill -9`.

- `SIGINT` exits immediately (an operator pressing Ctrl+C means now).
- `SIGTERM` is graceful, bounded by `server.graceful_shutdown_secs`
  (default 30s, not pingora's 300s).
- A second signal of either kind calls `_exit`, so no shutdown can become
  uninterruptible. The handler only touches an atomic and `_exit`; keep it
  async-signal-safe.

## Dumping for LLM debugging

`--dump-request` / `--dump-response` (plus `--dump-max-bytes`) print the
exchange via the `llm_broker::dump` tracing target. `proxy/dump.rs` owns the
formatting and is unit-tested; the filters only call it.

Rules for anything added here:

- **Never print a credential.** The broker injects a provider key into the
  upstream request, so `SECRET_HEADERS` redaction is load-bearing, not
  cosmetic. Add new credential headers to that list rather than special-casing
  a call site, and never print a value before checking its name.
- **One line per event**, tagged `[#id phase +Nms]`, so concurrent requests stay
  separable and a rotation is visible as two upstream attempts under one id.
- **A retry replays the same body.** `request_body` recognises the pingora
  retry buffer and reports a replay instead of reprinting, so the byte counters
  describe the client's request rather than how many times we sent it.
- **Dumps are sensitive.** Content the upstream returns is printed verbatim.

## API dialects

`core/api.rs` classifies a request as Chat Completions, Responses or Other;
`proxy/payload.rs` parses the body. Rules:

- **The model must come from the path, the query or a header** — never the body,
  for either dialect. pingora picks the peer before the body streams, so a
  body-derived model only reaches logging, metrics and policy. Do not claim
  otherwise in a test name: an integration test cannot prove body routing
  because the code path does not exist.
- **Parse the body as JSON.** The previous string scan for `"model"` matched a
  decoy nested object (`{"metadata":{"model":"decoy"},"model":"gpt-4o"}`) and
  used it as the model, which routes wrongly and forwards a name that is not a
  model. Do not reintroduce a document-wide scan.
- **Both dialects forward untouched.** Never rewrite the path, the body or the
  model field: the upstream must see what the client sent.
- **Per-dialect details**: token cap (`max_output_tokens` vs `max_tokens`) and
  usage keys (`input_tokens`/`output_tokens` vs `prompt_tokens`/
  `completion_tokens`). Adding a dialect means covering both.
- The body filter parses the **first** chunk only. A body fragmented across
  chunks falls back to the path-derived signals; that is a known bound, not an
  accident.

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
