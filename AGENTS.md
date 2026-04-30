# AGENTS.md — LLM Broker

## Project Overview

**Goal**: LLM API proxy that load-balances across multiple API keys, automatically switching keys when quota limits are reached.

**Tech Stack**: Rust + [pingora](https://github.com/cloudflare/pingora) (Cloudflare's async HTTP proxy framework)

## Build & Run Commands

```bash
cargo build          # Build the project
cargo run            # Run in development
cargo test           # Run tests
cargo check          # Type check without full build
cargo fmt            # Format code
cargo clippy         # Lint
```

## Architecture

- **pingora**: Used as the HTTP proxy server foundation (not a web framework)
- **LLM Providers**: Support OpenAI-compatible APIs with quota tracking
- **Load Balancing**: Round-robin, weighted random, or least-busy distribution across API keys
- **Key Rotation**: Automatic failover when quota is exhausted (cooldown: 1min → 5min → 25min exponential backoff on 429)

### Load Balancing Strategies

| Strategy | Behavior | Best For |
|----------|----------|----------|
| `simple-shuffle` | Random selection | General distribution |
| `least-busy` | Fewest active requests | High concurrency |
| `latency-based-routing` | Fastest responding | Latency-sensitive |
| `usage-based-routing` | Lowest current RPM/TPM | Rate limit respect |

### Key Rotation Patterns

- **Selection**: Deterministic least-used, weighted random (rotation_tolerance), or sequential
- **On 429/5xx**: Mark key as throttled, set cooldown, rotate to next available key
- **Per-key state**: `key`, `weight`, `usage_count`, `cooldown_until`, `models_allowed`

### Reference Implementations (for patterns)

- [VoidLLM](https://github.com/voidmind-io/voidllm) (Rust) — multi-deployment LB, automatic failover
- [LiteLLM](https://github.com/lorenhsu1128/litellm) (Python) — 100+ providers, retry/fallback, Redis coordination
- [GPT-Load](https://github.com/tbphp/gpt-load) (Go) — key pool management, hot-reload config
- [GPROXY](https://github.com/LeenHawk/gproxy) (Rust) — multi-provider routing, per-tenant auth

## Key Patterns

- Use `pingora` for the proxy server, not Actix/Warp/Axum
- Async runtime: `tokio`
- HTTP client: `pingora` built-in or `reqwest`
- Configuration: TOML for API keys and provider settings

## Cargo.toml Note

Edition 2024 is used (not 2021). Ensure Rust toolchain supports it:
```bash
rustup update stable
rustup show
```

## File Structure (target)

```
src/
  main.rs           # Entry point
  proxy/            # Proxy server setup
  load_balancer/    # Key selection and rotation
  providers/        # LLM provider implementations
  config/           # Configuration loading
```

## Testing

Write unit tests alongside modules. Integration tests go in `tests/` directory.

## Conventions

- Follow Rust idioms and `clippy` suggestions
- Use `thiserror` for error handling
- Async functions should document error cases