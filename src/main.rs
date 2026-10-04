//! Entry point for the LLM broker.

use std::path::PathBuf;

use aibroker::config::Config;
use aibroker::core::runtime::{Runtime, shared};
use aibroker::proxy::dump::DumpConfig;
use aibroker::proxy::pingora_backend::run_server;
use aibroker::proxy::redact::Redactor;
use clap::Parser;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "aibroker")]
#[command(about = "Local LLM proxy with load balancing and key management")]
#[command(version)]
struct Args {
    /// Path to the configuration file.
    #[arg(long, default_value = "config.toml")]
    config: String,

    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,

    /// Print the effective configuration (including secrets) and exit.
    #[arg(long)]
    dump_config: bool,

    /// Dump every request (line, headers, body) to the log.
    ///
    /// Credentials are always redacted. Pair with `--dump-response` for a full
    /// picture when debugging an LLM integration.
    #[arg(long)]
    dump_request: bool,

    /// Dump every upstream response (status, headers, body) to the log.
    ///
    /// Streaming answers are printed frame by frame as they arrive.
    #[arg(long)]
    dump_response: bool,

    /// Maximum bytes of a body to print in a dump (default 8192).
    #[arg(long, value_name = "BYTES", default_value_t = 8192)]
    dump_max_bytes: usize,

    /// Redact a pattern from dumped bodies and header values. Repeatable.
    ///
    /// Either `PATTERN` (replaced with `<redacted>`) or `PATTERN=REPLACEMENT`,
    /// where the replacement may reference capture groups as `$1`. Patterns are
    /// regexes, so quote anything your shell would interpret.
    ///
    /// Example: --redact 'ghp_[A-Za-z0-9]{20,}' --redact '([\w.]+)@([\w.-]+)=***@$2'
    #[arg(long, value_name = "PATTERN[=REPLACEMENT]")]
    redact: Vec<String>,

    /// Query a running broker's admin API and print the result, then exit.
    ///
    /// Example: `aibroker --check-admin http://127.0.0.1:11436/admin/status`
    #[arg(long, value_name = "URL")]
    check_admin: Option<String>,

    /// Bearer token for --check-admin (or set LLM_BROKER_ADMIN_TOKEN).
    #[arg(long, value_name = "TOKEN")]
    admin_token: Option<String>,
}

fn main() {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    if let Some(url) = args.check_admin.clone() {
        match query_admin(&url, args.admin_token.as_deref()) {
            Ok(body) => {
                println!("{body}");
                std::process::exit(0);
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }

    let path = resolve_config_path(&args.config);
    let config = match Config::from_file(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load config from `{}`: {error}", path.display());
            std::process::exit(1);
        }
    };

    if args.check {
        // `--check` is also a startup preflight, so resolve `env:` secrets.
        if let Err(error) = config.validate_secrets() {
            eprintln!("failed to load config from `{}`: {error}", path.display());
            std::process::exit(1);
        }
        println!("configuration `{}` is valid", path.display());
        println!("providers: {}", config.providers.len());
        for provider in &config.providers {
            println!(
                "  - {} ({} keys, endpoint {})",
                provider.name,
                provider.api_keys.len(),
                provider.base_url.as_deref().unwrap_or("<default>")
            );
        }
        return;
    }

    if args.dump_config {
        match config.to_toml() {
            Ok(toml) => println!("{toml}"),
            Err(error) => {
                eprintln!("failed to serialize config: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    let runtime = match Runtime::new(config.clone(), Some(path.clone())) {
        Ok(runtime) => shared(runtime),
        Err(error) => {
            eprintln!("failed to build the broker runtime: {error}");
            std::process::exit(1);
        }
    };

    install_signal_handlers();

    let redactor = match build_redactor(&config, &args) {
        Ok(redactor) => redactor,
        Err(error) => {
            eprintln!("redaction pattern is unusable: {error}");
            std::process::exit(1);
        }
    };

    if args.dump_request || args.dump_response {
        eprintln!(
            "[dump] request={} response={} max_body_bytes={} redaction_patterns={} \
             (filter with RUST_LOG=info,llm_broker::dump=off)",
            args.dump_request,
            args.dump_response,
            args.dump_max_bytes,
            redactor.len()
        );
    }
    if (args.dump_request || args.dump_response) && redactor.is_empty() {
        // Worth saying out loud: a dump is the one place prompt content reaches
        // durable storage, and `-rw-r--r--` is the usual outcome of a shell
        // redirect.
        eprintln!(
            "[dump] warning: no redaction patterns are configured, so prompt content is \
             written to the log verbatim. Add --redact PATTERN (or `redact` under \
             [dump] in the config) to mask secrets inside bodies."
        );
    }

    let dump = DumpConfig {
        dump_request: args.dump_request,
        dump_response: args.dump_response,
        max_body_bytes: args.dump_max_bytes,
        redactor,
    };

    if let Err(error) = run_server(config, runtime, dump) {
        eprintln!("server error: {error}");
        std::process::exit(1);
    }
}

/// Compile the redaction rules from the config and the command line.
///
/// The admin token is always included: it is the broker's own credential, and
/// it can legitimately appear in a dumped header or query string, so leaking it
/// into a log we wrote would be our defect rather than the operator's.
fn build_redactor(config: &Config, args: &Args) -> Result<Redactor, String> {
    let mut rules: Vec<(String, String)> = Vec::new();
    for pattern in &config.dump.redact {
        rules.push(split_redaction(pattern));
    }
    for pattern in &args.redact {
        rules.push(split_redaction(pattern));
    }

    let admin_token = config
        .admin
        .token
        .as_deref()
        .and_then(|token| aibroker::config::resolve_secret(token).ok());

    Redactor::new(&rules)?.plus_admin_token(admin_token.as_deref())
}

/// Split `PATTERN=REPLACEMENT`, tolerating a replacement-less pattern.
fn split_redaction(spec: &str) -> (String, String) {
    match spec.split_once('=') {
        Some((pattern, replacement)) => (pattern.to_string(), replacement.to_string()),
        None => (spec.to_string(), String::new()),
    }
}

/// Process-wide count of shutdown signals received.
///
/// Unix-only: on other platforms [`install_signal_handlers`] is a no-op, and an
/// unused static is a hard error under `-D warnings`.
#[cfg(unix)]
static SHUTDOWN_SIGNALS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Handler for the shutdown signals.
///
/// # Safety
///
/// Only async-signal-safe operations happen here: an atomic increment, and
/// `_exit` on the repeated signal. No allocation, no logging, no locks.
#[cfg(unix)]
extern "C" fn on_signal(signal: libc::c_int) {
    use std::sync::atomic::Ordering;
    let count = SHUTDOWN_SIGNALS.fetch_add(1, Ordering::SeqCst) + 1;
    // A repeated signal means "stop now": either a second Ctrl+C, or another
    // SIGTERM while a graceful shutdown is already waiting out its grace
    // period on the main thread. pingora cannot see these -- its handler has
    // already run and the signal is no longer pending -- so it would otherwise
    // look wedged for the whole grace period.
    if count >= 2 {
        // SAFETY: `_exit` is async-signal-safe and never returns.
        unsafe { libc::_exit(128 + signal) };
    }
}

/// Make Ctrl+C behave, including during a graceful shutdown.
///
/// pingora's own handlers make `SIGTERM` graceful and `SIGINT` quick, and a
/// graceful shutdown is implemented as a sleep on the main thread. Signals
/// arriving during that sleep are dropped, so the operator has no way out
/// until the grace period expires. Own both signals instead:
///
/// - `SIGINT` (Ctrl+C) exits immediately, which is what an operator pressing
///   it means.
/// - `SIGTERM` exits immediately too, because the operator asked for it. The
///   configurable grace period still bounds how long in-flight requests get
///   when the broker is stopped by a signal.
/// - a *second* signal of either kind exits unconditionally, so a stuck
///   shutdown is always interruptible.
#[cfg(unix)]
fn install_signal_handlers() {
    // SAFETY: installing handlers for these signals is async-signal safe, and
    // `on_signal` only touches an atomic and `_exit`.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}

/// Non-Unix platforms keep the default disposition, which already terminates
/// the process on Ctrl+C.
#[cfg(not(unix))]
fn install_signal_handlers() {}

/// Fetch an admin endpoint and pretty-print the response.
///
/// Kept deliberately simple: a blocking client, no retries, and the body
/// printed verbatim when it is not JSON (handy for `/admin` and `/metrics`).
fn query_admin(url: &str, token: Option<&str>) -> Result<String, String> {
    let token = token
        .map(|t| t.to_string())
        .or_else(|| std::env::var("LLM_BROKER_ADMIN_TOKEN").ok())
        .unwrap_or_default();

    // The broker is expected to be local, so a plain TCP request avoids
    // pulling a TLS stack into the CLI path.
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid url `{url}`: {e}"))?;
    if parsed.scheme() != "http" {
        return Err(format!(
            "only http:// is supported for --check-admin (got `{}`)",
            parsed.scheme()
        ));
    }
    let host = parsed.host_str().unwrap_or("127.0.0.1");
    let port = parsed.port().unwrap_or(80);
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let path_and_query = match parsed.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };

    let mut stream = std::net::TcpStream::connect((host, port))
        .map_err(|e| format!("cannot reach {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();

    let request = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    use std::io::{Read, Write};
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("failed to send the request: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("failed to read the response: {e}"))?;

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed response (no header terminator)".to_string())?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body = String::from_utf8_lossy(&raw[split + 4..]).to_string();

    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    if status == 0 {
        return Err("malformed status line".to_string());
    }

    // Chunked bodies are what the proxy uses for larger responses.
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(&body)
    } else {
        body
    };

    if status >= 400 {
        return Err(format!("HTTP {status}: {}", body.trim()));
    }

    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(value) => serde_json::to_string_pretty(&value)
            .map_err(|e| format!("failed to format the response: {e}")),
        Err(_) => Ok(body),
    }
}

/// Decode an HTTP/1.1 chunked body.
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, remainder)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        if size == 0 {
            break;
        }
        if remainder.len() < size {
            out.push_str(remainder);
            break;
        }
        out.push_str(&remainder[..size]);
        rest = remainder[size..].trim_start_matches("\r\n");
    }
    out
}

/// Use the given path, falling back to the user config directory.
fn resolve_config_path(requested: &str) -> PathBuf {
    let candidate = PathBuf::from(requested);
    if candidate.exists() {
        return candidate;
    }
    if let Some(home) = dirs::home_dir() {
        let fallback = home.join(".config").join("aibroker").join("config.toml");
        if fallback.exists() {
            return fallback;
        }
    }
    candidate
}
