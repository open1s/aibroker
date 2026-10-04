//! Control-plane listener.
//!
//! When `admin.mode = "separate"` the control plane gets its own port. It is a
//! pingora service in its own right so it can never be reached through the
//! forwarding path, and it reuses the same [`AdminRouter`] as the path-mounted
//! variant.

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use tracing::warn;

use crate::proxy::admin::{AdminCredentials, AdminRequest, AdminResponse, AdminRouter};

/// Serves the admin API on a dedicated listener.
pub struct ControlService {
    router: AdminRouter,
}

impl ControlService {
    pub fn new(router: AdminRouter) -> Self {
        Self { router }
    }

    pub fn router(&self) -> &AdminRouter {
        &self.router
    }

    /// Build the admin request from a downstream session.
    async fn build_request(&self, session: &mut Session) -> AdminRequest {
        let body = match session.downstream_session.read_request_body().await {
            Ok(body) => body.map(|b| b.to_vec()).unwrap_or_default(),
            Err(error) => {
                warn!("failed to read admin request body: {error}");
                Vec::new()
            }
        };

        let credentials = {
            let headers = &session.req_header().headers;
            let authorization = headers.get("authorization").and_then(|v| v.to_str().ok());
            let admin_token = headers.get("x-admin-token").and_then(|v| v.to_str().ok());
            AdminCredentials::from_headers(authorization, admin_token)
        };

        AdminRequest {
            method: session.req_header().method.as_str().to_string(),
            path: session
                .req_header()
                .uri
                .path()
                .trim_start_matches('/')
                .to_string(),
            query: session.req_header().uri.query().map(|q| q.to_string()),
            body,
            credentials,
        }
    }
}

/// Write a control-plane response through a pingora session.
pub async fn write_response(session: &mut Session, response: AdminResponse) -> pingora::Result<()> {
    let mut header = ResponseHeader::build(response.status, None)?;
    header.insert_header("Content-Type", response.content_type)?;
    header.insert_header("Content-Length", response.body.len().to_string())?;
    header.insert_header("Cache-Control", "no-store")?;
    if let Some(challenge) = response.challenge {
        header.insert_header("WWW-Authenticate", challenge)?;
    }
    // The control plane is never somewhere to navigate away from.
    header.insert_header("Referrer-Policy", "no-referrer")?;
    session.set_keepalive(None);
    session
        .write_response_header(Box::new(header), response.body.is_empty())
        .await?;
    if !response.body.is_empty() {
        session
            .write_response_body(Some(Bytes::from(response.body)), true)
            .await?;
    }
    Ok(())
}

#[async_trait]
impl ProxyHttp for ControlService {
    /// Minimal context: the control plane never talks to an upstream.
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let path = session
            .req_header()
            .uri
            .path()
            .trim_start_matches('/')
            .to_string();

        // Unknown paths are rejected before the body is read, so they cannot
        // force a large upload to be buffered.
        let response = if is_known_route(&path) {
            let request = self.build_request(session).await;
            self.router.handle(request)
        } else {
            AdminResponse::error(404, format!("no admin route for `{path}`"))
        };

        write_response(session, response).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<pingora::upstreams::peer::HttpPeer>> {
        // Unreachable: every request is answered in `request_filter`.
        Err(pingora::Error::new_down(pingora::ErrorType::new(
            "AdminHasNoUpstream",
        )))
    }
}

/// Whether a path could match an admin route, used for early 404s.
fn is_known_route(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segments.as_slice(),
        // `GET /` on the admin listener is the dashboard.
        [] | ["health"]
            | ["status"]
            | ["config"]
            | ["config", "reload"]
            | ["config", "strategy"]
            | ["keys"]
            | ["keys", _, _]
            | ["keys", _, _, "reset"]
            | ["keys", _, _, "enable"]
            | ["keys", _, _, "disable"]
            | ["models"]
            | ["routes"]
            | ["metrics"]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_routes_cover_the_admin_surface() {
        for path in [
            "health",
            "status",
            "config",
            "config/reload",
            "config/strategy",
            "keys",
            "keys/openai/k1",
            "keys/openai/k1/reset",
            "keys/openai/k1/enable",
            "keys/openai/k1/disable",
            "models",
            "routes",
            "metrics",
        ] {
            assert!(is_known_route(path), "`{path}` should be a known route");
        }
    }

    #[test]
    fn unknown_routes_are_rejected_early() {
        for path in [
            "nope",
            "keys/openai",
            "keys/openai/k1/delete",
            "config/unknown",
        ] {
            assert!(!is_known_route(path), "`{path}` should not be known");
        }
    }

    #[test]
    fn the_root_serves_the_dashboard() {
        assert!(is_known_route(""));
        assert!(is_known_route("/"));
    }

    #[test]
    fn leading_and_trailing_slashes_are_ignored() {
        assert!(is_known_route("/status"));
        assert!(is_known_route("status/"));
        assert!(is_known_route("/keys/openai/k1/"));
    }
}
