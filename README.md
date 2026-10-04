# LLM Broker

[![CI](https://github.com/open1s/aibroker/actions/workflows/ci.yml/badge.svg)](https://github.com/open1s/aibroker/actions/workflows/ci.yml)
[![Release](https://github.com/open1s/aibroker/actions/workflows/release.yml/badge.svg)](https://github.com/open1s/aibroker/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Point every client at one local URL and let a pool of API keys absorb the
rate limits.**

A local proxy for LLM APIs that spreads traffic across many keys, and when one
of them hits a `429`, replays the *same request* on another key before your
client ever notices. Drop-in for anything that speaks the OpenAI API — coding
agents, scripts, notebooks, your own services.

```
      your client / agent
              │  one base URL, one key that never rotates
              ▼
        ┌─────────────┐
        │ LLM Broker  │   routing · retries · health · metrics
        └──────┬──────┘
               │
   ┌───────────┼───────────┬───────────┐
   ▼           ▼           ▼           ▼
provider A  provider B  provider C   …    each with a pool of keys
   │           │           │
 key key     key key     key key         rate limited? parked and skipped
```

## Why this exists

If you run an agent or a batch job against a metered LLM API, you have probably
hit one of these:

- an evening of work stops because one key hit its rate limit;
- you keep several keys around, and switching between them is a manual edit;
- a provider starts returning errors and you only notice when the run dies;
- you cannot answer "which key is actually being used, and how close is it to
  its quota?"

Doing this by hand — retry loops, key juggling, watching dashboards — is
exactly the job a proxy should do. LLM Broker is that proxy, and nothing else:
one binary, one config file, no database, no control plane to run.

**Why not a hosted gateway?** Your prompts are your code. This runs on your
machine, keys never leave your host, and it keeps working when your network to
a SaaS control plane does not. Everything is one small Rust binary.

## Who it is for

- **Coding-agent users** (Codex CLI, Claude Code, Cline, Aider, Continue, …)
  who have several keys and want the tool to just keep going. Point the tool's
  base URL at the broker; the agent keeps its own key, which the broker ignores
  and replaces.
- **Anyone running batches or evaluations** that must survive a rate limit
  rather than die on it.
- **Teams with per-developer or per-team keys**, who want quotas visible and
  manageable without handing keys around by chat.

## Get started in a minute

```bash
# 1. Build (or grab a binary from Releases)
cargo build --release

# 2. Describe your keys
cp config.example.toml config.toml   # annotated, every option explained
$EDITOR config.toml                  # add keys as env:NAME references

# 3. Check it, then run it
./target/release/aibroker --config config.toml --check
./target/release/aibroker --config config.toml
```

Now point any OpenAI-compatible client at it:

```bash
curl http://127.0.0.1:11436/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

The `Authorization` header from the client is ignored — the broker always
substitutes a key from its own pool. That is what lets an existing tool work
unchanged: no code, no SDK, no wrapper script.

Then watch it work:

- <http://127.0.0.1:11436/admin> — read-only dashboard (key health, cooldowns,
  RPM/TPM against limits, token counters, routing table);
- <http://127.0.0.1:11436/metrics> — Prometheus;
- `--dump-request --dump-response` — the full exchange, one line per event,
  credentials redacted, which is how you debug an integration;
- `aibroker --check-admin http://127.0.0.1:11436/admin/status` — the same from a
  shell.

## Is it production-ready?

It is a local tool, and it is honest about that: no clustering, no shared state
between instances, config in one TOML file. What it does have is tests — 183 of
them, including end-to-end tests that prove a `429` really does rotate onto
another key with the body replayed — a pinned toolchain, and a clean
`clippy -D warnings` build on Linux, macOS and Windows. Every release ships
prebuilt binaries for five targets.

## Comparison

|  | LLM Broker | by hand / wrapper script | hosted gateway |
|---|---|---|---|
| Key rotation on `429` | inside the request | your retry code | usually |
| Prompts leave your machine | **no** | no | yes |
| Setup | one binary + TOML | code you maintain | account + config |
| Works offline / air-gapped | **yes** | yes | no |
| Per-key quotas and metrics | built in | build it | built in |
| Multi-tenant, billing, SSO | not a goal | no | yes |

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

## Both OpenAI API dialects

The broker proxies **Chat Completions** and the newer **Responses** API. Point
either client at the same port:

| | endpoint |
|---|---|
| Chat Completions | `POST /v1/chat/completions` |
| Responses | `POST /v1/responses` |

```bash
# Chat Completions — the model can also be declared in the body alone
curl http://127.0.0.1:11436/v1/chat/completions \
  -H 'Content-Type: application/json' -H 'x-llm-model: gpt-4o' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'

# Responses
curl http://127.0.0.1:11436/v1/responses \
  -H 'Content-Type: application/json' -H 'x-llm-model: gpt-4o' \
  -d '{"model":"gpt-4o","input":"hi","max_output_tokens":64}'
```

Both paths forward **untouched** — the broker never rewrites the endpoint, the
body or the model field — so the upstream sees exactly what the client sent.

Two details are handled per dialect: the output-token cap (`max_tokens` /
`max_completion_tokens` versus `max_output_tokens`), so TPM is reserved
correctly, and the `usage` object (`prompt_tokens`/`completion_tokens` versus
`input_tokens`/`output_tokens`), so accounting is the same for both.

### Declaring the model before the body

pingora chooses the upstream and writes the request header **before** the body
streams, and offers no way to put a peeked body back. The model therefore has to
come from the URL or a header. Precedence:

1. `x-llm-model` header — works for any dialect, and what an SDK should use via
   `default_headers`;
2. `?model=` query parameter — for a plain `curl` or a client that cannot set a
   header: `POST /v1/responses?model=gpt-4o`;
3. the path, for providers that put the model there
   (`/v1/models/<model>:generateContent`).

If none is present the request is still proxied (the body's own `model` field is
what the provider reads), but the broker has less to route on: it may pick a key
that does not declare that model, and its per-model counters and policy see no
model. **Chat Completions and Responses are equal here** — the model has never
been derivable from the body before routing, for either dialect.

### Format detection

The endpoint normally settles it, but the body wins when the two disagree, since
the provider reads the body. A Responses payload posted to
`/v1/chat/completions` — a gateway rewriting the path, say — is detected as
Responses. The body is parsed as JSON with `serde_json` rather than scanned for
`"model"`, because a decoy nested object would otherwise be picked up:

```json
{"metadata":{"model":"decoy"},"model":"gpt-4o"}   /* parsed: gpt-4o */
```

The detected dialect appears in the audit log as `api=` and in
`llm_broker_requests_by_api_total{api=...}`, so you can see which shape is
actually flowing.

## Who may use it, and what may leave

Balancing decides *which* key serves a request. Two more layers decide whether
the request should leave the machine at all — the part that matters when the
broker sits between your source code and a third-party API.

**Clients** authenticate the caller. Without any `[[clients]]` the proxy is
open, which is the right default for one person on their own laptop. Add them
and every request needs a token:

```toml
[[clients]]
name = "laptop"
token = "file:/run/secrets/laptop-token"   # or env:NAME, or a literal
allowed_models = ["gpt-4o", "claude-3-5-*"]  # empty = any
allowed_providers = ["openai"]
max_rpm = 120
max_concurrency = 4
```

A client token is compared in constant time, never logged, never echoed in a
refusal, and never returned by the admin API. `file:` keeps it out of the
environment, where `ps` and every child process can read it.

**Policy** decides the rest, in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/),
evaluated in-process by [regorus](https://github.com/microsoft/regorus). Every
request that is about to be forwarded is described to the policy as `input`,
and the policy answers `data.llm.authz.allow`:

```rego
package llm.authz

import rego.v1

default allow := false

# Authenticated clients, within their configured scope.
allow if {
	input.client.name
	input.auth.ok
	input.budget.allowed
	input.client.model_allowed
	input.client.provider_allowed
}

# A data-security rule the config cannot express: long prompts stay on-prem.
allow if {
	input.client.name == "laptop"
	input.request.estimated_tokens <= 4000
	input.route.providers[_] == "on-prem"
}

reason := "prompts over 4000 tokens must stay on-prem" if {
	input.request.estimated_tokens > 4000
}
```

Point `[policy] files = ["policy.rego"]` at it. [policy.example.rego](policy.example.rego)
documents every fact the policy can see and includes worked examples; a test
compiles it with the real engine, so it cannot silently rot.

What this buys you:

- a request for a model or provider a client is not cleared for is refused
  **before the body is uploaded**, so the content never reaches anyone;
- policy is data, not code: review it in a pull request, diff it, hand it to
  whoever owns the data-classification rules;
- a policy that fails to evaluate **refuses** the request rather than forwarding
  it — a broken policy is never an open door;
- `GET /admin/security` shows the live configuration (client scopes, budgets,
  denial counts by reason, which policy is loaded) without exposing a token.

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

Open it in a browser and log in with **any username** and your admin token as
the password — the dashboard answers an anonymous request with a `Basic`
challenge, so the browser prompts for you:

```
path mode:      http://127.0.0.1:11436/admin
separate mode:  http://127.0.0.1:11437/
```

A script keeps using the header form, which is never offered the `Basic`
fallback (that would put a credential in a URL):

```bash
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
- `llm_broker_client_auth_failures_total` — requests refused for a missing or
  unknown client token
- `llm_broker_policy_denials_total` — requests refused by the egress policy
- `llm_broker_client_denials_total{reason}` — the same refusals broken down by
  `missing_credential`, `unknown_credential`, `client_disabled`,
  `model_forbidden`, `provider_forbidden`, `rate_limited`,
  `too_many_in_flight`, `policy_error`. This is the series to alert on: a spike
  in `unknown_credential` is someone probing the port, and any
  `policy_error` means traffic is being refused because a policy broke.

Token counts come from the response `usage` object when it is present
(OpenAI, Anthropic, Gemini and Ollama field names are recognised), which also
feeds TPM accounting and optional cost estimates.

## Debugging a request

`--dump-request` and `--dump-response` print the full exchange, which is the
quickest way to answer "why is my client getting that?":

```bash
aibroker --config config.toml --dump-request --dump-response
# optionally cap the printed body (default 8192 bytes)
aibroker --config config.toml --dump-request --dump-max-bytes 2000
```

Each event is one line, tagged with a request id and the elapsed milliseconds,
so concurrent traffic stays separable and a key rotation is visible as two
upstream attempts under one id:

```
[#1 req +0ms] POST /v1/chat/completions HTTP/1.1
[#1 req headers +0ms] host: 127.0.0.1:11436 | content-type: application/json | x-llm-model: gpt-4o
[#1 upstream req +0ms] POST /v1/chat/completions HTTP/1.1
[#1 upstream req headers +0ms] host: api.openai.com | authorization: <redacted> | content-length: 84
[#1 req body +1ms] {"messages":[{"content":"hello","role":"user"}],"model":"gpt-4o"}
[#1 resp +3ms] 429
[#1 resp headers +3ms] retry-after: 1 | content-type: application/json
[#1 upstream req +1006ms] POST /v1/chat/completions HTTP/1.1      <- rotated key
[#1 resp +1007ms] 200
[#1 resp body +1007ms] data: {"choices":[{"delta":{"content":"he"}}]}
[#1 done +1007ms] status=200 attempts=2 provider=openai key=openai-2 req_bytes=84 resp_bytes=246
```

What it gives you:

- the **upstream** request, not just the client's: the rewritten path, the
  `Host`, and how the request was routed, next to what the client actually sent;
- **both attempts** of a rotation under one id, with the elapsed time, which is
  what makes an unexplained retry obvious;
- streaming answers **frame by frame** as they arrive, not buffered until the
  end;
- JSON bodies compacted to one line so `grep`, `awk` and `jq -c` still work.

Credentials are **always redacted** (`authorization`, `x-api-key`, `api-key`,
`x-admin-token`, `cookie`, `set-cookie`), because the broker injects a provider
key into the upstream request and a naive dump would write secrets to disk.
Bodies are printed as they are otherwise — including a provider that echoes
something secret inside its *content* — so treat dump output as sensitive.

Dumps go to the `llm_broker::dump` tracing target, which means they can be
switched off without losing the rest of the log:

```bash
RUST_LOG=info,llm_broker::dump=off aibroker --dump-request
```

## Stopping it

`Ctrl+C` exits immediately. `SIGTERM` (what a supervisor or `docker stop`
sends) is graceful: it stops accepting, lets in-flight requests finish, and
tears the runtimes down. Because an LLM request can be long, that wait is
bounded by `server.graceful_shutdown_secs`, which defaults to **30s** rather
than pingora's 300s — a five-minute window where the process ignores further
signals reads as a hang.

Any repeated signal exits unconditionally, so a shutdown can always be
interrupted:

```bash
Ctrl+C            # immediate
docker stop       # SIGTERM: in-flight requests get up to graceful_shutdown_secs
Ctrl+C Ctrl+C     # either way, the second signal kills it now
```

## Testing against a live broker

`tests/manual/` holds a black-box test harness that drives a real broker
process over HTTP:

```bash
cargo build --release --offline

# 55 checks: rotation, retry budget, exhaustion, streaming, metrics, admin API
python3 tests/manual/run_feature_tests.py --profile mock

# 18 checks against a real provider. Copy config.example.toml to
# test-real-config.toml (gitignored: it holds live keys), point it at a
# provider, then either let the harness start a broker or --port attach to one
# you already have running.
python3 tests/manual/run_feature_tests.py --profile real
python3 tests/manual/run_feature_tests.py --profile real --port 11436 --admin-token "$TOKEN"
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
