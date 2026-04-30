use clap::Parser;
use aibroker::config::Config;
use aibroker::proxy::pingora_backend::run_pingora_server;
use aibroker::proxy::reqwest_backend::run_reqwest_server;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "aibroker")]
#[command(version = "1.0.0")]
struct Args {
    #[arg(long, help = "Dump request/response to stdout")]
    dump: bool,

    #[arg(long, default_value = "config.toml", help = "Path to config file")]
    config: String,

    #[arg(long, help = "Proxy type: pingora or reqwest")]
    proxy: Option<String>,
}

fn main() {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if args.dump {
        eprintln!("[DUMP] Request/response logging enabled");
    }

    let config_path = if std::path::Path::new(&args.config).exists() {
        args.config.clone()
    } else if let Ok(home) = std::env::var("HOME") {
        let config_dir = std::path::Path::new(&home).join(".config").join("aibroker").join("config.toml");
        config_dir.to_string_lossy().to_string()
    } else {
        args.config.clone()
    };

    let config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config from '{}': {}", config_path, e);
            std::process::exit(1);
        }
    };

    let proxy_type = args
        .proxy
        .unwrap_or(config.proxy_type.clone().unwrap_or("pingora".to_string()));

    if proxy_type == "pingora" {
        tracing::info!("Starting Pingora-based proxy server");
        let config_clone = config.clone();
        std::thread::spawn(move || {
            run_pingora_server(config_clone, args.dump);
        });
        std::thread::sleep(std::time::Duration::from_secs(1));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            tokio::signal::ctrl_c().await.ok();
        });
    } else {
        tracing::info!("Starting Reqwest-based proxy server");
        let rt = tokio::runtime::Runtime::new().unwrap();
        if let Err(e) = rt.block_on(run_reqwest_server(config)) {
            eprintln!("Reqwest server error: {}", e);
        }
    }
}
