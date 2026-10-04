# LLM Broker

A local LLM proxy that spreads traffic across a pool of API keys, rotates onto
another key the moment one is rate limited, and exposes the pool for runtime
management.

```
client ──▶ LLM Broker ──┬──▶ provider A ──▶ key pool
                        ├──▶ provider B ──▶ key pool
                        └──▶ provider C ──▶ key pool
                              ▲
                     /metrics · /admin
```

## What it does

- **Key rotation inside a single request.** A `429` or `5xx` from one key is
  recorded against that key and the request is immediately replayed on a
  *different* key, excluding every key already tried. The client sees one
  request; the broker may use several keys.
- **Model routing.** Requests are matched to a provider by model name — exact,
  glob (`claude-*`) or catch-all — with `x-llm-model` or the URL path as the
  pre-body signal. Providers that cannot serve the model are never called.
- **Real rate limiting.** Sliding-window RPM *and* TPM accounting per key, plus
  concurrency caps. The window cannot burst past the configured limit.
- **Health scoring and circuit breaking.** EWMA latency, an exponential
  failure score, and cooldowns that really ramp (1min → 5min → 25min by
  default, jittered) and honour an upstream `Retry-After`.
- **Seven selection strategies** including least-busy, latency-based,
  usage-based and power-of-two-choices, with configurable fallbacks.
- **Runtime key management.** Add, patch, disable, delete and reset keys over
  the admin API, persisted back to the config file, with no restart.
- **Observability.** Prometheus `/metrics`, per-key and per-model counters, and
  optional structured access logs.

## Quick start

```bash
cargo build --release

# Start from the annotated example.
cp config.example.toml config.toml
$EDITOR config.toml

./target/release/aibroker --config config.toml --check   # validate first
./target/release/aibroker --config config.toml
```

Point any OpenAI-compatible client at `http://127.0.0.1:11436`:

```bash
curl http://127.0.0.1:11436/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

The `Authorization` header from the client is ignored: the broker always
replaces it with a credential from its own pool.

## CLI

| Flag | Meaning |
|------|---------|
| `--config <path>` | Config file (default `config.toml`, then `~/.config/aibroker/config.toml`) |
| `--check` | Validate the config *and* that every `env:` secret resolves, then exit |
| `--dump-config` | Print the effective config as TOML and exit |

## Configuration

See [`config.example.toml`](config.example.toml) for an annotated, validated
file. The essentials:

```toml
[server]
host = "0.0.0.0"
port = 11436
max_retries = 3          # total attempts per client request

[[providers]]
name = "openai"
base_url = "https://api.openai.com"
auth = "bearer"          # bearer | x-api-key | api-key | query | <header>

[[providers.api_keys]]
id = "openai-1"
key = "env:OPENAI_API_KEY_1"   # or a literal secret
weight = 2
max_rpm = 500
max_tpm = 2_000_000

[[routes]]
model = "gpt-*"
providers = ["openai"]         # ordered failover list

[load_balancing]
strategy = "usage_based"
fallback_strategies = ["least_busy", "round_robin"]

[admin]
enabled = true
mode = "path"
path = "/admin"
token = "env:LLM_BROKER_ADMIN_TOKEN"
```

1.x configs keep working: every new section has a default, and `models`,
`weight` and `max_rpm` mean what they always did.

### Routing order

For a request the broker tries providers in this order, stopping at the first
one that yields a usable key:

1. `[[routes]]` whose pattern matches, most specific first (exact, then glob,
   then `*`), in the order written;
2. providers whose keys explicitly list the model;
3. `default_route`;
4. every remaining provider, so an unlisted model can still be served by a pool
   that accepts anything.

### Load balancing strategies

| Strategy | Picks |
|----------|-------|
| `round_robin` | Deterministic rotation |
| `weighted_random` | Weighted roll, tolerance-adjustable |
| `least_busy` | Fewest in-flight requests |
| `least_latency` | Lowest EWMA latency (alias `latency_based`) |
| `usage_based` | Lowest current RPM/TPM utilisation |
| `power_of_two` | Best of two random keys by health and headroom |
| `fallback` | Always the first healthy key, in config order |

`least_used` and `latency_based` from 1.x are accepted as aliases.

### Failure handling

| Upstream result | Broker behaviour |
|-----------------|------------------|
| `429` | Key is parked (honouring `Retry-After` when present, capped at 5s) and the request is replayed on another key |
| `5xx` | Key health drops and escalates its cooldown; request retried on another key |
| `408`, `409`, `425` | Retried on another key |
| Transport error **before** a response | Retried on another key |
| Transport error **after** a response | Not retried — the upstream already answered; a late socket close is normal |
| `4xx` describing the request (`400`, `401`, `403`, `404`, `405`, `410`, `422`) | Returned straight to the caller and **never** replayed: every key would fail identically. A retired model answering `410 Gone` costs exactly one attempt |
| Every key unusable | `429` with `Retry-After`, or `503` when no key matches the model |

### Upstream timeouts

`server.connect_timeout_ms`, `server.read_timeout_ms` and
`server.write_timeout_ms` map onto pingora's per-attempt deadlines, and
`server.idle_timeout_ms` (or `load_balancing.idle_timeout_secs`) controls
keep-alive. The read timeout is the one to watch: pingora defaults it to 60s,
but LLM answers routinely take longer, and a read timeout is treated as a
transport failure that rotates to another key. A 60s ceiling therefore turns a
slow-but-healthy provider into an exhausted pool. Set `read_timeout_ms`
generously (10 minutes is reasonable) and let the client decide when to give
up.

### Key state

Each key tracks, per provider: enabled flag, weight, model allow-list, RPM/TPM
windows, concurrency, EWMA latency, health score, circuit state and cooldown
level, plus request, token, retry and rate-limit counters.

## Admin API

The control plane can add credentials, so it **fails closed**: with no
`admin.token` configured, every request is refused unless
`admin.allow_insecure` is set explicitly. Send the token as
`Authorization: Bearer <token>` or `X-Admin-Token`.

### Viewing it

Three ways in, depending on what you want:

**Browser dashboard** — `GET /admin` (or `/` on a `mode = "separate"`
listener) renders a read-only page: available keys, per-key health, cooldown,
latency, RPM/TPM against their limits, token counters, the routing table and
the live strategy. It makes no external requests and holds no state of its own,
so it is safe on an air-gapped host. Everything that *changes* state stays on
the JSON API below, where the request is explicit.

```bash
# Path mode: browse http://127.0.0.1:11436/admin
# Separate mode: browse http://127.0.0.1:11437/
curl -H 'Authorization: Bearer <token>' http://127.0.0.1:11436/admin | less
```

**CLI** — the binary can query a running broker directly, which is handy over
SSH or in a script:

```bash
aibroker --check-admin http://127.0.0.1:11436/admin/status \
  --admin-token "$LLM_BROKER_ADMIN_TOKEN"
aibroker --check-admin http://127.0.0.1:11436/admin/keys      # per-key state
aibroker --check-admin http://127.0.0.1:11436/metrics         # Prometheus text
```

The token may also come from `LLM_BROKER_ADMIN_TOKEN`.

**Raw JSON** — every route below, with `curl` and `jq`:

```bash
TOKEN=...; BASE=http://127.0.0.1:11436/admin
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/status" | jq .
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/keys"   | jq '.providers'
```

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/health` | Liveness |
| `GET` | `/admin/status` | Providers, key counts, in-flight, strategy |
| `GET` | `/admin/keys` | Per-key state (never the secret) |
| `POST` | `/admin/keys` | Add a key |
| `PATCH` | `/admin/keys/{provider}/{id}` | Change secret, models, limits, weight |
| `DELETE` | `/admin/keys/{provider}/{id}` | Remove a key |
| `POST` | `/admin/keys/{provider}/{id}/enable`\|`disable` | Take a key in or out of rotation |
| `POST` | `/admin/keys/{provider}/{id}/reset` | Clear cooldown, failures and rate-limit history |
| `GET`\|`PUT` | `/admin/config/strategy` | Read or change the selection strategy |
| `POST` | `/admin/config/reload` | Re-read the config file, preserving live key state |
| `GET` | `/admin/config` | The on-disk document (contains secrets — token required) |
| `GET` | `/admin/models` | Models the config knows about |
| `GET` | `/admin/routes` | Compiled routing table |
| `GET` | `/admin/metrics` | Prometheus text (same as `/metrics`) |

```bash
# Take a rate-limited key out of rotation and clear its history.
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11436/admin/keys/openai/openai-2/disable

# Add capacity without a restart.
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"provider":"openai","id":"openai-3","key":"env:OPENAI_API_KEY_3","max_rpm":500}' \
  http://127.0.0.1:11436/admin/keys
```

`mode = "separate"` moves the whole control plane to its own listener
(`admin.host`/`admin.port`) so it is unreachable from the proxy port at all.

## Metrics

`GET /metrics` returns Prometheus text:

- `llm_broker_requests_total`, `llm_broker_responses_{2xx,4xx,5xx}_total`
- `llm_broker_key_requests_total{provider_key}`, `..._model_requests_total{provider_model}`
- `llm_broker_key_rate_limited_total`, `llm_broker_key_retries_total`
- `llm_broker_key_tokens_total{direction}`, `..._key_latency_milliseconds` histogram
- `llm_broker_key_rotations_total`, `llm_broker_keys_exhausted_total`
- `llm_broker_requests_in_flight`, `llm_broker_uptime_seconds`

Token counts come from the response `usage` object when it is present
(OpenAI, Anthropic, Gemini and Ollama field names are recognised), which also
feeds TPM accounting and optional cost estimates.

## Testing against a live broker

`tests/manual/` holds a black-box test harness that drives a real broker
process over HTTP:

```bash
cargo build --release --offline

# 55 checks: rotation, retry budget, exhaustion, streaming, metrics, admin API
python3 tests/manual/run_feature_tests.py --profile mock

# 18 checks against a real provider configured in test-real-config.toml:
# a genuine completion, token accounting, round-robin and 410 fail-fast
python3 tests/manual/run_feature_tests.py --profile real
```

The mock profile starts `tests/manual/mock_upstream.py`, a scripted upstream
that rate limits its first caller so the rotation path can be observed, and
asserts on the credential each attempt used. The real profile needs live keys;
it validates that a completion flows end to end and that a retired model is
refused after a single attempt.

## Architecture

```
src/
  main.rs                  CLI, config loading, server startup
  config/                  Schema, validation, persistence, secret resolution
  core/                    Framework-independent broker logic
    key_state.rs           Per-key health, cooldown, rate limits, counters
    ratelimit.rs           Sliding-window RPM/TPM limiter
    pool.rs                Key pool: availability gate + selection
    strategy.rs            Selection strategies
    broker.rs              Model routing, provider failover
    auth.rs                Per-provider credential conventions
    metrics.rs             Prometheus registry
    runtime.rs             Shared config + broker + metrics, hot reload
  proxy/
    pingora_backend.rs     pingora adapter: routing, retry, admin, metrics
    admin.rs               Control-plane routing and authentication
    body.rs                Model and `usage` extraction
tests/
  proxy_integration.rs     End-to-end: real proxy, mock upstream, real rotation
```

The core has no HTTP dependencies, so selection, health and rate limiting are
tested directly; the pingora layer is a thin adapter over it.

### Request path

1. `request_filter` serves `/admin/*` and `/metrics` in-process, otherwise
   counts the request.
2. `upstream_peer` resolves the model (`x-llm-model`, then the path), asks the
   broker for a key, and may briefly wait when a cooldown is about to expire.
3. `upstream_request_filter` rewrites the path, applies the provider's
   credential and forces the upstream `Host`.
4. `upstream_response_filter` inspects the status: a `429`/`5xx` is recorded
   against the key and, while attempts remain, the request is retried on the
   next key.
5. `logging` records the outcome exactly once, per key and per model.

### Known limitations

- **Model-based routing happens before the body is read.** pingora selects the
  upstream and writes the request header before it streams the body, and offers
  no way to put a peeked body back into the stream. Routing therefore uses
  `x-llm-model` and the URL path; for clients that can only put the model in the
  JSON body, the broker walks the configured route order and tries each
  candidate provider. The body *is* read afterwards for usage accounting and
  logs. Prefer `x-llm-model` (or path-embedded models) when routing precision
  matters.
- **Rate-limit windows restart on a broker rebuild.** Samples are anchored to
  `Instant`s that cannot be replayed, so an admin change resets them. Cooldowns,
  health scores and counters are preserved.

## Development

```bash
cargo build
cargo test                 # 143 unit + 7 end-to-end tests
cargo fmt
cargo clippy --all-targets
```

Dependencies are already fetched in the local registry, so an offline build
works:

```bash
cargo build --offline
cargo test  --offline
```

If a new dependency is needed and the sandbox blocks the global cargo registry,
either fetch outside the sandbox or set a workspace-local `CARGO_HOME`:

```bash
CARGO_HOME=.cargo-home cargo build
```

## License

MIT — see [LICENSE](LICENSE).
