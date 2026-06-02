use async_trait::async_trait;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::ProxyHttp;
use pingora::server::Server;
use pingora::upstreams::peer::{HttpPeer, Peer};
use pingora_error::ErrorType;
use pingora_proxy::http_proxy_service;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::lookup_host;
use tracing::{info, warn};
use url::Url;

use crate::config::Config;
use crate::load_balancer::LoadBalancer;
use crate::load_balancer::key_info::Provider;

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

fn timestamp() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = d.as_secs() as i64;
    let days = total_secs / 86400;
    let t = total_secs % 86400;
    let (y, mo, day) = civil_from_days(days);
    let h = t / 3600;
    let m = t % 3600 / 60;
    let s = t % 60;
    format!(
        "{y:04}-{mo:02}-{day:02}T{h:02}:{m:02}:{s:02}.{:03}",
        d.subsec_millis()
    )
}

/// DNS cache entry with TTL
struct DnsCacheEntry {
    ip: String,
    expires_at: Instant,
}

const DNS_CACHE_TTL_SECS: u64 = 30;

pub struct PingoraProxy {
    load_balancer: Arc<LoadBalancer>,
    initial_cooldown_secs: u64,
    idle_timeout: Option<Duration>,
    dns_cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    dump_request: bool,
    dump_response: bool,
}

impl PingoraProxy {
    pub fn new(
        load_balancer: LoadBalancer,
        initial_cooldown_secs: u64,
        idle_timeout: Option<Duration>,
        dump_request: bool,
        dump_response: bool,
    ) -> Self {
        Self {
            load_balancer: Arc::new(load_balancer),
            initial_cooldown_secs,
            idle_timeout,
            dns_cache: Arc::new(RwLock::new(HashMap::new())),
            dump_request,
            dump_response,
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
}

#[derive(Default)]
pub struct PingoraProxyCtx {
    pub key_id: Option<String>,
    pub api_key: Option<String>,
    pub provider: Option<Provider>,
    pub upstream_host: Option<String>,
}

#[async_trait]
impl ProxyHttp for PingoraProxy {
    type CTX = PingoraProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        PingoraProxyCtx::default()
    }

    async fn request_filter(
        &self,
        session: &mut pingora_proxy::Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let all_keys_rate_limited = self
            .load_balancer
            .pools()
            .values()
            .all(|pool| pool.all_keys_rate_limited());

        if all_keys_rate_limited {
            let (key_id, max_rpm) = self
                .load_balancer
                .pools()
                .values()
                .find(|pool| !pool.keys().is_empty())
                .and_then(|pool| {
                    pool.keys()
                        .first()
                        .map(|k| (k.id.clone(), k.max_rpm.unwrap_or(0)))
                })
                .unwrap_or_else(|| ("unknown".to_string(), 0));

            let mut header = ResponseHeader::build(429, None).unwrap();
            header
                .insert_header("X-RateLimit-Limit", max_rpm.to_string())
                .ok();
            header.insert_header("X-RateLimit-Remaining", "0").ok();
            header.insert_header("Retry-After", "60").ok();
            header.insert_header("X-RateLimit-Key", &key_id).ok();
            session.set_keepalive(None);
            session
                .write_response_header(Box::new(header), true)
                .await?;
            warn!(
                "All API keys rate-limited (key: {}, limit: {} rpm)",
                key_id, max_rpm
            );
            return Ok(true);
        }

        if self.dump_request {
            let req = session.req_header();
            let headers_str = req
                .headers
                .iter()
                .map(|(k, v)| format!("  {}: {}", k, v.to_str().unwrap_or("<binary>")))
                .collect::<Vec<_>>()
                .join("\n");
            println!(
                "[{}] [REQUEST] {} {}\n{}",
                timestamp(),
                req.method,
                req.uri,
                headers_str
            );
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut pingora_proxy::Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let (key, provider) = self
            .select_any_key()
            .ok_or_else(|| pingora::Error::new_up(ErrorType::new("NoKeyAvailable")))?;

        let base_url = key.base_url.as_deref().unwrap_or("https://api.openai.com");
        let parsed = match Url::parse(base_url) {
            Ok(url) => url,
            Err(e) => {
                warn!(
                    "Failed to parse base_url '{}' for key {}: {}. Falling back to default.",
                    base_url, key.id, e
                );
                Url::parse("https://api.openai.com").expect("default URL is always valid")
            }
        };

        let host = parsed.host_str().unwrap_or("api.openai.com").to_string();
        let port = parsed.port().unwrap_or(443);
        let tls = parsed.scheme() == "https";

        ctx.key_id = Some(key.id.clone());
        ctx.api_key = Some(key.key.clone());
        ctx.provider = Some(provider);
        ctx.upstream_host = Some(host.clone());

        let address = format!("{}:{}", host, port);
        let ip_addr = {
            let cache_key = address.clone();
            let now = Instant::now();

            if let Ok(cache) = self.dns_cache.read() {
                if let Some(entry) = cache.get(&cache_key) {
                    if entry.expires_at > now {
                        let ip = entry.ip.clone();
                        drop(cache);
                        if let Ok(mut write_cache) = self.dns_cache.write() {
                            write_cache.insert(
                                cache_key,
                                DnsCacheEntry {
                                    ip: ip.clone(),
                                    expires_at: now + Duration::from_secs(DNS_CACHE_TTL_SECS),
                                },
                            );
                        }
                        ip
                    } else {
                        drop(cache);
                        String::new()
                    }
                } else {
                    drop(cache);
                    String::new()
                }
            } else {
                String::new()
            }
        };

        let ip_addr = if ip_addr.is_empty() {
            match lookup_host(&address).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        let ip = addr.ip().to_string();
                        if let Ok(mut cache) = self.dns_cache.write() {
                            cache.insert(
                                address.clone(),
                                DnsCacheEntry {
                                    ip: ip.clone(),
                                    expires_at: Instant::now()
                                        + Duration::from_secs(DNS_CACHE_TTL_SECS),
                                },
                            );
                        }
                        ip
                    } else {
                        warn!("DNS lookup returned no addresses for {}", address);
                        host.clone()
                    }
                }
                Err(e) => {
                    warn!("DNS lookup failed for {}: {}", address, e);
                    host.clone()
                }
            }
        } else {
            ip_addr
        };

        let mut peer = HttpPeer::new(format!("{}:{}", ip_addr, port), tls, host.clone());
        if let Some(timeout) = self.idle_timeout
            && let Some(opts) = peer.get_mut_peer_options()
        {
            opts.idle_timeout = Some(timeout);
        }

        info!("proxying to {}:{} (sni: {})", ip_addr, port, host);

        Ok(Box::new(peer))
    }

    async fn request_body_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if self.dump_request
            && let Some(bytes) = body.as_deref()
            && !bytes.is_empty()
        {
            const MAX_LOG_LEN: usize = 512;

            if let Ok(body_str) = std::str::from_utf8(bytes) {
                let json_str = body_str.strip_prefix("data: ").unwrap_or(body_str);
                let pretty = match serde_json::from_str::<Value>(json_str) {
                    Ok(v) => match serde_json::to_string_pretty(&v) {
                        Ok(s) => s,
                        Err(_) => body_str.to_string(),
                    },
                    Err(_) => body_str.to_string(),
                };

                let output = if pretty.len() > MAX_LOG_LEN {
                    format!(
                        "{}\n... (truncated, {} bytes total)",
                        pretty.chars().take(MAX_LOG_LEN).collect::<String>(),
                        pretty.len()
                    )
                } else {
                    pretty
                };

                println!("[{}] [REQUEST BODY]\n---\n{}\n---", timestamp(), output);
            } else {
                println!(
                    "[{}] [REQUEST BODY] <binary {} bytes>",
                    timestamp(),
                    bytes.len()
                );
            }
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        req: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if let Some(ref host) = ctx.upstream_host {
            req.insert_header("Host", host.as_str()).ok();
        }

        req.insert_header("User-Agent", "llm-broker/1.0").ok();

        if let (Some(api_key), Some(provider)) = (&ctx.api_key, &ctx.provider) {
            match provider {
                Provider::Anthropic => {
                    req.insert_header("x-api-key", api_key.as_bytes()).ok();
                }
                Provider::Azure => {
                    req.insert_header("api-key", api_key.as_bytes()).ok();
                }
                _ => {
                    req.insert_header("Authorization", format!("Bearer {}", api_key).as_bytes())
                        .ok();
                }
            }
        }

        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        let status = resp.status.as_u16();
        if (status == 429 || status >= 500)
            && let (Some(key_id), Some(provider)) = (&ctx.key_id, &ctx.provider)
        {
            let cooldown = Duration::from_secs(self.initial_cooldown_secs);
            self.load_balancer.mark_failure(provider, key_id, cooldown);
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        resp: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if self.dump_response {
            let headers_str = resp
                .headers
                .iter()
                .map(|(k, v)| format!("  {}: {}", k, v.to_str().unwrap_or("<binary>")))
                .collect::<Vec<_>>()
                .join("\n");
            println!(
                "[{}] [RESPONSE] {}\n{}",
                timestamp(),
                resp.status,
                headers_str
            );
        }
        Ok(())
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<std::time::Duration>> {
        if self.dump_response
            && let Some(bytes) = body.as_deref()
        {
            if let Ok(body_str) = std::str::from_utf8(bytes) {
                const MAX_LOG_LEN: usize = 512;
                let json_str = body_str.strip_prefix("data: ").unwrap_or(body_str);
                let pretty = match serde_json::from_str::<Value>(json_str) {
                    Ok(v) => {
                        serde_json::to_string_pretty(&v).unwrap_or_else(|_| body_str.to_string())
                    }
                    Err(_) => body_str.to_string(),
                };

                let output = if pretty.len() > MAX_LOG_LEN {
                    format!(
                        "{}\n... (truncated, {} bytes total)",
                        pretty.chars().take(MAX_LOG_LEN).collect::<String>(),
                        pretty.len()
                    )
                } else {
                    pretty
                };

                println!("[{}] [RESPONSE BODY]\n---\n{}\n---", timestamp(), output);
            } else {
                println!(
                    "[{}] [RESPONSE BODY] <binary {} bytes>",
                    timestamp(),
                    bytes.len()
                );
            }
        }
        Ok(None)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut pingora_proxy::Session,
        mut e: Box<pingora::Error>,
        ctx: &mut Self::CTX,
        _client_reused: bool,
    ) -> Box<pingora::Error> {
        let etype = e.etype().clone();
        warn!(
            "proxy error: {} (peer: {}, uri: {:?})",
            e,
            peer,
            session.req_header().uri
        );

        let should_mark_failure = matches!(etype, ErrorType::ConnectRefused);
        if should_mark_failure && let (Some(key_id), Some(provider)) = (&ctx.key_id, &ctx.provider)
        {
            let cooldown = Duration::from_secs(self.initial_cooldown_secs);
            self.load_balancer.mark_failure(provider, key_id, cooldown);
        }

        let should_retry = !matches!(
            etype,
            ErrorType::ConnectRefused | ErrorType::ConnectionClosed
        );
        let mark_as_upstream = matches!(etype, ErrorType::ConnectRefused);

        // Must explicitly set retry decision - pingora panics if not set
        if should_retry {
            e.set_retry(true);
        } else {
            e.set_retry(false);
            if mark_as_upstream {
                e.as_up();
            }
        }

        e
    }
}

pub fn run_pingora_server(config: Config, dump_request: bool, dump_response: bool) {
    let server_conf = config.server.to_pingora_conf();

    let mut server = Server::new_with_opt_and_conf(None, server_conf);
    server.bootstrap();

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let load_balancer = config.load_balancer();
    let idle_timeout = Some(Duration::from_secs(config.load_balancing.idle_timeout_secs));
    let proxy = PingoraProxy::new(
        load_balancer,
        config.load_balancing.initial_cooldown_secs,
        idle_timeout,
        dump_request,
        dump_response,
    );

    let mut http_proxy = http_proxy_service(&server.configuration, proxy);
    http_proxy.add_tcp(&addr);

    println!("LLM Broker (Pingora) listening on {}", addr);

    server.add_service(http_proxy);
    server.run_forever();
}
