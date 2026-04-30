use axum::{
    Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
};
use reqwest::Client;
use std::sync::Arc;

use crate::config::Config;
use crate::load_balancer::LoadBalancer;
use crate::load_balancer::key_info::Provider;

pub struct ReqwestProxy {
    load_balancer: Arc<LoadBalancer>,
    client: Client,
    initial_cooldown_secs: u64,
}

impl ReqwestProxy {
    pub fn new(load_balancer: LoadBalancer, initial_cooldown_secs: u64) -> Self {
        let client = Client::builder()
            .user_agent("llm-broker/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            load_balancer: Arc::new(load_balancer),
            client,
            initial_cooldown_secs,
        }
    }

    fn select_any_key(&self) -> Option<(Arc<crate::load_balancer::key_info::KeyInfo>, Provider)> {
        for (provider, pool) in self.load_balancer.pools() {
            if let Ok(key) = pool.select_key(None) {
                return Some((key, provider.clone()));
            }
        }
        None
    }

    pub async fn proxy_request(
        &self,
        req: Request,
    ) -> Result<Response<Body>, (StatusCode, String)> {
        let (key, provider) = self.select_any_key().ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "No available keys".to_string(),
        ))?;

        let base_url = key.base_url.as_deref().unwrap_or("https://api.openai.com");
        let upstream_url = format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("")
        );

        let mut upstream_req = self.client.request(req.method().clone(), &upstream_url);

        match provider {
            Provider::Anthropic => {
                upstream_req = upstream_req.header("x-api-key", key.key.as_bytes());
            }
            Provider::Azure => {
                upstream_req = upstream_req.header("api-key", key.key.as_bytes());
            }
            Provider::NVIDIA => {
                upstream_req = upstream_req.header("Authorization", format!("Bearer {}", key.key));
            }
            _ => {
                upstream_req = upstream_req.header("Authorization", format!("Bearer {}", key.key));
            }
        }

        for (name, value) in req.headers() {
            if name != "host" && name != "authorization" && name != "x-api-key" && name != "api-key"
            {
                upstream_req = upstream_req.header(name, value);
            }
        }

        if let Some(url_str) = &key.base_url
            && let Ok(url) = url::Url::parse(url_str)
                && let Some(host) = url.host_str() {
                    upstream_req = upstream_req.header("Host", host);
                }

        let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read body: {}", e),
                )
            })?;

        upstream_req = upstream_req.body(body_bytes);

        let upstream_resp = upstream_req.send().await.map_err(|e| {
            let cooldown = std::time::Duration::from_secs(self.initial_cooldown_secs);
            self.load_balancer
                .mark_failure(&provider, &key.id, cooldown);
            (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e))
        })?;

        let status = upstream_resp.status();
        let mut response_builder = Response::builder().status(status);

        for (name, value) in upstream_resp.headers() {
            response_builder = response_builder.header(name, value);
        }

        let body = upstream_resp.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to read response body: {}", e),
            )
        })?;

        Ok(response_builder.body(Body::from(body)).unwrap())
    }
}

async fn handler(
    axum::extract::State(proxy): axum::extract::State<Arc<ReqwestProxy>>,
    req: Request,
) -> impl IntoResponse {
    match proxy.proxy_request(req).await {
        Ok(resp) => resp,
        Err((status, msg)) => (status, msg).into_response(),
    }
}

pub fn create_reqwest_router(config: Config) -> Router {
    let load_balancer = config.load_balancer();
    let proxy = Arc::new(ReqwestProxy::new(
        load_balancer,
        config.load_balancing.initial_cooldown_secs,
    ));

    Router::new()
        .route("/{*path}", any(handler))
        .with_state(proxy)
}

pub async fn run_reqwest_server(config: Config) -> anyhow::Result<()> {
    let app = create_reqwest_router(config.clone());

    let addr = format!("{}:{}", config.server.host, config.server.port);
    println!("LLM Broker (Reqwest) listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
