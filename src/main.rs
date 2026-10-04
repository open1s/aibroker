//! Entry point for the LLM broker.

use std::path::PathBuf;

use aibroker::config::Config;
use aibroker::core::runtime::{Runtime, shared};
use aibroker::proxy::pingora_backend::run_server;
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

    if let Err(error) = run_server(config, runtime) {
        eprintln!("server error: {error}");
        std::process::exit(1);
    }
}

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
