# LLM Broker

An LLM API proxy that load-balances across multiple API keys, automatically switching keys when quota limits are reached.

## Features

- **Multi-provider support**: OpenAI, Anthropic, Azure, DeepSeek, MiniMax, OpenRouter, GLM, NVIDIA, Vertex
- **Key rotation**: Automatic failover when keys hit rate limits
- **Load balancing strategies**: Round-robin, weighted random, least used, latency-based
- **Exponential backoff**: Cooldown periods (1min → 5min → 25min) after 429/5xx errors
- **Two proxy implementations**: Pingora (production) or Reqwest (simple)

## Quick Start

```bash
cargo build --release
./target/release/aibroker --config config.toml
```

## Configuration

Create `config.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080

[[providers]]
name = "openai"
base_url = "https://api.openai.com/v1"

[[providers.api_keys]]
id = "key1"
key = "sk-..."
models = ["gpt-4", "gpt-3.5-turbo"]
weight = 2
max_rpm = 500

[[providers.api_keys]]
id = "key2"
key = "sk-..."
models = ["gpt-4"]
weight = 1

[load_balancing]
strategy = "weighted_random"
initial_cooldown_secs = 60
```

### Server Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | "0.0.0.0" | Listen address |
| `port` | u16 | 8080 | Listen port |
| `threads` | usize | auto | Worker threads (pingora only) |
| `daemon` | bool | false | Run as daemon (pingora only) |

### Provider Options

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Provider name (openai, anthropic, azure, etc.) |
| `base_url` | string | Optional custom endpoint |

### API Key Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | string | required | Unique key identifier |
| `key` | string | required | API key value |
| `models` | list | all | Supported models |
| `weight` | u32 | 1 | Selection weight |
| `max_rpm` | u32 | unlimited | Rate limit (requests/minute) |

### Load Balancing Options

| Field | Default | Description |
|-------|---------|-------------|
| `strategy` | round_robin | Strategy: round_robin, weighted_random, least_used, latency_based |
| `initial_cooldown_secs` | 60 | Initial cooldown after failure |

## Usage

```bash
# Default (pingora proxy)
aibroker --config config.toml

# Reqwest proxy
aibroker --config config.toml --proxy reqwest

# Debug mode (log requests/responses)
aibroker --config config.toml --dump
```

## API

Proxy forwards to upstream providers. Compatible with OpenAI Chat Completions API:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $ANY_CONFIGURED_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        LLM Broker                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌───────────────┐    │
│  │   Server    │───▶│  Load       │───▶│   Upstream    │    │
│  │  (pingora)  │    │  Balancer   │    │   Providers   │    │
│  └─────────────┘    └─────────────┘    └───────────────┘    │
│                           │                    │            │
│                           ▼                    ▼            │
│                    ┌─────────────┐      ┌─────────────┐     │
│                    │  Key Pools  │◀─────│   Failure   │     │
│                    │ (per        │      │   Tracking  │     │
│                    │  provider)  │      │  + Cooldown │     │
│                    └─────────────┘      └─────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Error Handling

| Error | Behavior |
|-------|----------|
| 429 Rate Limited | Mark key as cooldown, rotate to next |
| 5xx Upstream Error | Mark key as cooldown, rotate to next |
| Connection Closed | Retry with same key (connection may be stale) |
| Connect Refused | Mark key as cooldown immediately |