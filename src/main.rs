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
}

fn main() {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

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
