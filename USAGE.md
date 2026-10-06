# Using LLM Broker in detail

A walkthrough of everything you can do with the broker, in the order you will
actually do it. [README.md](README.md) is the overview and the design rationale;
this file is the operator's manual. Every command here was written against a
running broker.

---

## 1. Install

**From Releases** — prebuilt binaries for five targets:

```bash
# Apple silicon
curl -LO https://github.com/open1s/aibroker/releases/latest/download/aibroker-aarch64-apple-darwin.tar.gz
tar -xzf aibroker-aarch64-apple-darwin.tar.gz && ./aibroker --version
```

Targets: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`.

**From source:**

```bash
cargo build --release          # the toolchain is pinned in rust-toolchain.toml
./target/release/aibroker --version
```

---

## 2. Write the config

The only *required* fields are `server.host`, `server.port` and one provider
with one key. Everything else has a default, so start small:

```toml
[server]
host = "127.0.0.1"     # loopback unless you mean to serve other hosts
port = 11436

[providers.openai]
base_url = "https://api.openai.com"

[[providers.openai.api_keys]]
id = "openai-1"
key = "env:OPENAI_API_KEY"
```

That is a working proxy: one key, no rotation (there is nothing to rotate to),
no client authentication, admin API on `/admin` behind a token you must set
(see step 6).

The provider's name *is* the table key, which is why there is no `name = ...`:
a key block can only attach to the provider it names. The 1.x array form is
exactly equivalent and still loads unchanged, so an existing config needs no
edit:

```toml
[[providers]]
name = "openai"
base_url = "https://api.openai.com"

[[providers.api_keys]]        # attaches to the `[[providers]]` entry above
id = "openai-1"
key = "env:OPENAI_API_KEY"
```

Both keep document order, and provider order is the failover order — the array
form attaches keys to whichever `[[providers]]` entry came last, which is the
one sharp edge of that shape. A provider with no keys is a config that cannot
serve, so it is refused at startup rather than started as an empty pool.

Then grow it. Every field is explained in
[`config.example.toml`](config.example.toml); the sections you are most likely
to change, in the order they usually matter:

| Section | Why you touch it |
|---------|------------------|
| `[providers.<name>]` | Add a key pool. `auth` is `bearer`, `x-api-key`, `api-key`, `query` or a header name; `max_rpm`/`max_tpm`/`max_concurrency` are provider-wide defaults for keys that do not set their own. |
| `[[providers.<name>.api_keys]]` | The keys. `weight` biases weighted strategies, `max_rpm`/`max_tpm` cap that key, `enabled = false` parks it, and `models` declares what it is *for* (below). |
| `[[routes]]` | Which provider serves which model. `providers` is an ordered failover list. |
| `[load_balancing]` | The selection strategy and its fallbacks. |
| `[server]` | Timeouts. `read_timeout_ms` is the one to watch — see the note below. |
| `[[clients]]` | Require a token to use the proxy, and scope what each caller may send. |
| `[admin]` | The control plane: where it lives, its token, whether changes persist. |
| `[content_guard]` | Scan prompt bodies for secrets/PII before they leave. |
| `[policy]` | Rego egress policy, when allow-lists are not enough. |

**Secrets**: `key = "env:NAME"` reads the environment, `key = "file:/path"`
reads a file. Both keep the literal value out of the repository and out of
`--dump-config`. `file:` also keeps it out of the environment, where `ps` and
every child process can read it.

**A key's `models` list is a preference, not a gate.**

```toml
[[providers.deepseek.api_keys]]
id = "deepseek-1"
key = "env:DEEPSEEK_API_KEY"
models = ["deepseek-*"]        # globs, same syntax as a client's allowed_models
```

Keys that declare the model are tried **first**; if none of them can serve, the
rest of the pool is tried anyway. So `models = ["deepseek-*"]` means "try me
first for these" — declare what a key is *for* rather than everything it could
technically answer. An empty list declares everything, which is why a 1.x config
still routes. A request for a model **no** key declared is still forwarded: the
provider is the authority on its own models, and refusing at the broker would
break a model added upstream after the config was written.

**`read_timeout_ms` is the one timeout that bites.** pingora defaults it to 60s,
and an LLM answer routinely takes longer — a reasoning model can think for a
minute before it writes a token. A read timeout is treated as a transport
failure, which rotates to another key, so a 60s ceiling turns slow-but-healthy
providers into an exhausted pool. Set it generously (`600_000` is reasonable)
and let the *client* decide when to give up.

Validate before you start:

```bash
aibroker --config config.toml --check
```

This parses the file **and** resolves every `env:`/`file:` secret, so a typo or
a missing variable is a startup error rather than a 500 on the first request.

---

## 3. Run it

```bash
# Foreground — what you want while integrating
aibroker --config config.toml

# Background
nohup aibroker --config config.toml > aibroker.log 2>&1 &
```

As a systemd service (Linux):

```ini
[Unit]
Description=LLM Broker
After=network-online.target

[Service]
ExecStart=/usr/local/bin/aibroker --config /etc/aibroker/config.toml
EnvironmentFile=/etc/aibroker/env
Restart=on-failure
# SIGTERM is graceful: in-flight requests get up to graceful_shutdown_secs.

[Install]
WantedBy=multi-user.target
```

In a container, `docker stop`/`podman stop` send `SIGTERM`, which is the
graceful path.

**Signals:**

| Signal | Behaviour |
|--------|-----------|
| `Ctrl+C` (`SIGINT`) | Exits immediately |
| `SIGTERM` | Graceful: stops accepting, lets in-flight requests finish, bounded by `server.graceful_shutdown_secs` (default **30s**, not pingora's 300s) |
| A second signal of either kind | Exits unconditionally, so a shutdown can always be interrupted |

---

## 4. Point clients at it

The one rule that makes this drop-in: **the `Authorization` header your client
sends is ignored and replaced** with a key from the pool. No code, no SDK
change, no wrapper script.

```bash
curl http://127.0.0.1:11436/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer anything-you-like' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

**OpenAI Python SDK:**

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:11436/v1", api_key="not-used")
```

**Codex CLI** (`~/.codex/config.toml`):

```toml
model_provider = "broker"
model = "gpt-4o"

[model_providers.broker]
name = "broker"
base_url = "http://127.0.0.1:11436/v1"
# the key the CLI holds is ignored; the broker substitutes its own
```

**Claude Code** and similar agents: set the base URL to
`http://127.0.0.1:11436` (or `/v1`, depending on what the tool appends) and any
placeholder key.

### Which model a request is routed on

pingora picks the upstream **before** the body streams, so the model must come
from somewhere other than the body. In precedence order:

1. **`x-llm-model` header** — works for any dialect, and what an SDK should set
   via `default_headers`;
2. **`?model=` query parameter** — for a plain `curl` or a client that cannot
   set headers: `POST /v1/responses?model=gpt-4o`;
3. **the path**, for providers that embed the model
   (`/v1/models/<model>:generateContent`).

If none is present the request is still proxied — the body's own `model` field
is what the provider reads — but the broker has less to route on: it may pick a
key that does not declare that model, and its per-model counters and policy see
no model. Chat Completions and Responses are equal here.

Both dialects are proxied and both are forwarded **untouched** — the endpoint,
the body and the model field are never rewritten:

| Dialect | Endpoint |
|---------|----------|
| Chat Completions | `POST /v1/chat/completions` |
| Responses | `POST /v1/responses` |

---

## 5. The dashboard

Open <http://127.0.0.1:11436/admin> and log in with **any username** and your
admin token as the password — the dashboard answers an anonymous request with a
`Basic` challenge, so the browser prompts for you.

```
path mode:      http://127.0.0.1:11436/admin
separate mode:  http://127.0.0.1:11437/
```

What it shows: available keys against the total, per-key health, cooldown (and
how long is left on it), latency, RPM/TPM against each key's limits, **each
key's share of traffic** (so an uneven pool is visible rather than inferred),
token counters, the routing table, the live strategy, and the security posture —
whether client authentication is on, the clients and their scopes, and whether
prompt content is being inspected. It makes no external requests and holds no
state of its own, so it is safe on an air-gapped host.

### How the dashboard authenticates

The page itself is served behind the admin token. Its own **auto-refresh** is a
different problem: a browser does not attach HTTP credentials to a page's
`fetch` — they live in the browser's auth cache or in the URL bar — so the
broker hands the page a **read-only token** to send back as `X-Admin-Token`.

What that means in practice:

- **You do nothing.** Load the page once and the refresh works from then on,
  however you logged in — the prompt, a URL with the token in it, or a header.
- **The token cannot write.** It is accepted for `GET` and nothing else; a
  mutation that presents it still has to authenticate as an operator.
- **It is regenerated when the broker restarts.** A dashboard left open in a
  tab stops working across a restart — expected, since it is a credential you
  never typed. The page notices the first `401`, reloads once to pick up a
  fresh token, and carries on. A broker that is genuinely refusing the page
  will not be reloaded in a loop.
- **The admin token never appears in a response.** The refresh token is the one
  credential a response carries, and it is read-only by construction.

If a refresh does fail, the page keeps the last good view and says so in the
stamp — `refresh failed (…) — showing data from 12:09` — rather than blanking,
because a blank page reads as "the broker is down" when it may only be a token
problem.

A script keeps using the header form:

```bash
curl -H "Authorization: Bearer $LLM_BROKER_ADMIN_TOKEN" \
  http://127.0.0.1:11436/admin | less
```

---

## 6. Manage keys at runtime

Every route below takes the admin token as `Authorization: Bearer <token>` or
`X-Admin-Token`. `BASE` is `http://127.0.0.1:11436/admin`.

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
| `GET` | `/admin/config` | The effective config, **redacted** |
| `GET` | `/admin/models` | Models the config knows about |
| `GET` | `/admin/routes` | Compiled routing table |
| `GET` | `/admin/security` | Client scopes, budgets, denial counts, policy, content rules |
| `GET` | `/admin/metrics` | Prometheus text (same as `/metrics`) |

Worked examples:

```bash
BASE=http://127.0.0.1:11436/admin
H="Authorization: Bearer $LLM_BROKER_ADMIN_TOKEN"

# Add capacity without a restart. With admin.persist = true this is written
# back to the config file, so it survives a restart.
curl -X POST -H "$H" -H 'Content-Type: application/json' \
  -d '{"provider":"openai","id":"openai-3","key":"env:OPENAI_API_KEY_3","max_rpm":500}' \
  "$BASE/keys"

# Take a rate-limited key out of rotation, clear its history, put it back.
curl -X POST -H "$H" "$BASE/keys/openai/openai-2/disable"
curl -X POST -H "$H" "$BASE/keys/openai/openai-2/reset"
curl -X POST -H "$H" "$BASE/keys/openai/openai-2/enable"

# Patch one field. Absent fields are untouched.
curl -X PATCH -H "$H" -H 'Content-Type: application/json' \
  -d '{"max_rpm":1000}' "$BASE/keys/openai/openai-1"

# Change the strategy live.
curl -X PUT -H "$H" -H 'Content-Type: application/json' \
  -d '{"strategy":"least_busy"}' "$BASE/config/strategy"

# Pick up an edited config file, keeping live key state.
curl -X POST -H "$H" "$BASE/config/reload"
```

With `admin.persist = true`, changes made over the API are written back to the
config file. Cooldowns, health scores and counters survive a reload; rate-limit
windows restart (their samples are anchored to `Instant`s that cannot be
replayed).

The control plane can add credentials, so it **fails closed**: with no
`admin.token` configured, every request is refused unless
`admin.allow_insecure = true` is set explicitly — and that flag is only for a
loopback-only machine you trust.

---

## 7. Control what may leave the machine

Balancing decides *which* key serves a request. Two more layers decide whether
the request should leave at all.

### Clients

Without any `[[clients]]` the proxy is open — right for one person on their own
laptop, and worth changing the moment anything else can reach the port:

```toml
[[clients]]
name = "laptop"
token = "file:/run/secrets/laptop-token"
allowed_models = ["gpt-4o", "claude-3-5-*"]   # empty = any
allowed_providers = ["openai"]
max_rpm = 120
max_concurrency = 4
```

Every request then needs `Authorization: Bearer <client token>`. A client token
is compared in constant time, never logged, never echoed in a refusal, and
never returned by the admin API.

### Content guard — scan the body, not the metadata

Metadata checks cannot see an API key pasted into a prompt. `[content_guard]`
scans the request body itself, before it is forwarded:

```toml
[content_guard]
enabled = true
action = "report"            # report (default) | deny
allow = ["EXAMPLE"]          # bodies matching these are skipped

[[content_guard.patterns]]
name = "aws-key"
pattern = "AKIA[0-9A-Z]{16}"
```

**Start in `report` and watch it against real traffic** — it counts findings
(`llm_broker_content_findings_total`) and logs the rule name — then switch to
`deny`, which refuses with `403` before the body reaches the provider. A finding
names the rule, never the matched text. Enabling the guard with no patterns is a
startup error, because protection that inspects nothing is worse than being off.
The scan covers the first 256 KiB of a body; a larger body is reported as
`body-over-scan-limit` rather than silently passing.

### Policy — when allow-lists are not enough

Egress policy is [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/),
evaluated in-process by [regorus](https://github.com/microsoft/regorus). Every
request about to be forwarded is described to the policy as `input`, and it
answers `data.llm.authz.allow`. See
[policy.example.rego](policy.example.rego) and
[policy.example.d/](policy.example.d) for worked examples that are compiled and
exercised by tests.

A candidate policy can be attached in **shadow mode** first: it is evaluated
against live traffic, its would-be denials are counted and logged, and every
request is served on the enforcing policy's verdict:

```toml
[policy]
enabled = true
inline = "..."          # enforcing
dry_run = "candidate.rego"   # reports; cannot block
```

```bash
curl -s localhost:11436/metrics | grep shadow_policy_blocks
```

---

## 8. Watch it

`GET /metrics` returns Prometheus text. The series worth alerting on:

| Series | Meaning |
|--------|---------|
| `llm_broker_client_denials_total{reason}` | Refusals by reason. A spike in `unknown_credential` is someone probing the port; any `policy_error` means traffic is being refused because a policy broke. |
| `llm_broker_keys_exhausted_total` | Every key for a model was unavailable. Usually a rate limit, sometimes a timeout ceiling. |
| `llm_broker_key_rate_limited_total{provider_key}` | Which keys are absorbing 429s. |
| `llm_broker_key_rotations_total` | How often traffic moved between keys. |
| `llm_broker_admin_auth_failures_total` | Admin requests refused for a missing or unknown token. A steady climb with no one typing anything is worth investigating — but note that a dashboard tab left open across a restart contributes one failure before it recovers. |

`llm_broker_client_auth_failures_total` counts the same refusals registry-wide.

---

## 9. Debug

```bash
# The config as the broker sees it, credentials redacted
aibroker --config config.toml --dump-config

# ...with the real values, when you are sure you want them on screen
aibroker --config config.toml --dump-config --dump-config-reveal-secrets

# The full exchange, one line per event
aibroker --config config.toml --dump-request --dump-response

# Cap the printed body (default 8192 bytes)
aibroker --config config.toml --dump-request --dump-max-bytes 2000

# Scrub a shape the built-in redaction does not know about (repeatable)
aibroker --config config.toml --dump-request --redact 'ghp_[A-Za-z0-9]{20,}'

# Query a running broker from a shell
aibroker --check-admin http://127.0.0.1:11436/admin/status --admin-token "$TOKEN"
```

A dump shows the **upstream** request next to what the client sent, both
attempts of a rotation under one request id with the elapsed time, and streaming
answers frame by frame. Credentials are always redacted
(`authorization`, `x-api-key`, `api-key`, `x-admin-token`, `cookie`,
`set-cookie`) — but bodies are printed as they are, including a provider that
echoes something secret inside its *content*, so treat dump output as sensitive.

### Symptom → cause

| Symptom | Likely cause | Check |
|---------|--------------|-------|
| `refresh failed (HTTP 401)` in the dashboard | The broker restarted and the page's token is stale | It reloads itself once; if it keeps failing, the admin token changed — reload the page |
| `429` with every key exhausted | Rate limits, or `read_timeout_ms` too small | `/admin/keys` for cooldowns; the dump for where the time went |
| Everything goes to one key | `fallback` strategy (by design), or an identical-pool defect | The dashboard's share column; `GET /admin/config/strategy` |
| A model is not routed | No `x-llm-model`/`?model=` and the path does not carry it | `GET /admin/routes`; the dump's `api=` line |
| `403` on a completion | The content guard, in `deny` mode | The log names the rule; `/admin/security` lists the active rules |
| `401` from the proxy itself | Client authentication is on and the token is missing/unknown | `[[clients]]` in the config; `/admin/security` |
| `503` "no admin token configured" | The admin API has no token and `allow_insecure` is unset | Set `admin.token` |
| A long completion fails after ~60s | pingora's default read timeout | Set `server.read_timeout_ms` generously |

---

## 10. Stop it

```bash
Ctrl+C            # immediate
docker stop       # SIGTERM: in-flight requests get up to graceful_shutdown_secs
Ctrl+C Ctrl+C     # the second signal kills it now, either way
```

---

## 11. Test the deployment

`tests/manual/` drives a real broker process over HTTP:

```bash
cargo build --release --offline

# 55 checks: rotation, retry budget, exhaustion, streaming, metrics, admin API
python3 tests/manual/run_feature_tests.py --profile mock

# Against a real provider: copy config.example.toml to test-real-config.toml
# (gitignored — it holds live keys), then either let the harness start a broker
# or attach to one you already have running.
python3 tests/manual/run_feature_tests.py --profile real
python3 tests/manual/run_feature_tests.py --profile real --port 11436 --admin-token "$TOKEN"
```
