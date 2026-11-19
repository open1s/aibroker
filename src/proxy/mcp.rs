//! MCP-over-HTTP service: lets an agent read back what the broker proxied.
//!
//! The Model Context Protocol endpoint exposes a bounded ring of recent
//! request/response exchanges ([`CaptureStore`]) plus the broker's registered
//! tools and resources. Its purpose is diagnosis: an agent that just sent a
//! request through the proxy can ask "what did you actually forward, and what
//! came back?" without needing shell access to the parquet capture file.
//!
//! Security rules, in order:
//!
//! 1. **A credential never enters the ring.** Exchanges are built by
//!    [`crate::proxy::dump::Dump::finish`], which redacts credential headers by
//!    *name* and applies the configured body patterns before anything is
//!    buffered. The MCP layer only ever reads that redacted value; it never
//!    formats raw headers itself.
//! 2. **Fails closed.** Without `mcp.token` (and without an explicit
//!    `allow_insecure`), every request is refused, and tokens are compared in
//!    constant time.
//! 3. **Loopback by default.** The endpoint serves prompt bodies, so the
//!    default bind address is `127.0.0.1`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::config::McpConfig;
use crate::core::runtime::SharedRuntime;
use crate::core::security::constant_time_eq;
use crate::proxy::capture::CaptureStore;

/// Tool name for listing recent exchanges.
pub const CAPTURE_LIST_TOOL: &str = "capture_list";
/// Tool name for fetching one exchange.
pub const CAPTURE_GET_TOOL: &str = "capture_get";

/// Largest JSON-RPC request body the MCP endpoint will read.
///
/// MCP messages are small (a tool call with arguments), so an authenticated
/// client sending more than this is either broken or probing for an OOM. The
/// bound is checked against `Content-Length` before reading and against the
/// assembled body afterwards, because a chunked request has no length to trust.
pub const MAX_MCP_BODY_BYTES: usize = 1024 * 1024;

/// Tool definition as per MCP specification
///
/// The spec wire names are camelCase (`inputSchema`). Serde's default
/// snake_case produced `input_schema`, which a client that validates
/// `tools/list` against the spec treats as a tool with no argument schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    /// Unique identifier for the tool
    pub name: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Input schema (JSON Schema)
    pub input_schema: Value,
}

/// Resource definition as per MCP specification
///
/// `mimeType` is the spec spelling; `handle_resources_list` builds its JSON
/// by hand, but serialising the struct must not disagree with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResource {
    /// URI template for the resource
    pub uri: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// MIME type of the resource
    #[serde(default = "default_resource_mime")]
    pub mime_type: String,
}

fn default_resource_mime() -> String {
    "application/json".to_string()
}

/// Registered tool with its execution endpoint
#[derive(Debug, Clone)]
pub struct RegisteredTool {
    /// The tool definition
    pub tool: McpTool,
    /// The provider and model to route through
    pub provider: String,
    pub model: String,
    /// Optional HTTP method override (default POST)
    pub method: Option<String>,
    /// Optional custom path prefix
    pub path_prefix: Option<String>,
}

/// Registered resource with its source
#[derive(Debug, Clone)]
pub struct RegisteredResource {
    /// The resource definition
    pub resource: McpResource,
    /// The provider and model to route through
    pub provider: String,
    pub model: String,
}

/// MCP service state
#[derive(Debug, Clone, Default)]
pub struct McpState {
    /// Registered tools, keyed by name
    tools: HashMap<String, RegisteredTool>,
    /// Registered resources, keyed by URI
    resources: HashMap<String, RegisteredResource>,
    /// Last initialization timestamp
    initialized_at: Option<String>,
}

impl McpState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_tool(&mut self, tool: RegisteredTool) {
        self.tools.insert(tool.tool.name.clone(), tool);
    }

    pub fn unregister_tool(&mut self, name: &str) -> bool {
        self.tools.remove(name).is_some()
    }

    pub fn list_tools(&self) -> Vec<&RegisteredTool> {
        self.tools.values().collect()
    }

    pub fn get_tool(&self, name: &str) -> Option<&RegisteredTool> {
        self.tools.get(name)
    }

    pub fn register_resource(&mut self, resource: RegisteredResource) {
        self.resources
            .insert(resource.resource.uri.clone(), resource);
    }

    pub fn list_resources(&self) -> Vec<&RegisteredResource> {
        self.resources.values().collect()
    }
}

/// MCP request
#[derive(Debug, Clone, Deserialize)]
pub struct McpRequest {
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    /// Absent on a JSON-RPC *notification* (e.g. `notifications/initialized`,
    /// which every spec-compliant client sends right after `initialize`).
    /// Making this mandatory rejected that notification with HTTP 400, which
    /// failed the whole handshake even though authentication had succeeded.
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

/// MCP response
#[derive(Debug, Clone, Serialize)]
pub struct McpResponse {
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl McpResponse {
    pub fn success(id: Value, result: impl Serialize) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(serde_json::to_value(result).unwrap_or_else(|_| json!({}))),
            error: None,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(McpError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// The tools a capture-enabled endpoint advertises.
///
/// Kept as a free function so a test can assert the advertised shape without
/// building a runtime: a tool the model cannot see is a tool it will not call.
pub fn capture_tool_definitions() -> Vec<McpTool> {
    vec![
        McpTool {
            name: CAPTURE_LIST_TOOL.to_string(),
            description: Some(
                "List recent HTTP exchanges proxied by the broker, newest first. \
                 Credentials are redacted; bodies are omitted (fetch one with capture_get)."
                    .to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 20,
                        "description": "How many exchanges to list, newest first."
                    }
                },
                "additionalProperties": false
            }),
        },
        McpTool {
            name: CAPTURE_GET_TOOL.to_string(),
            description: Some(
                "Fetch one captured exchange by id: request and response headers and \
                 bodies, routing (provider, key id, attempts), status and latency. \
                 Credential headers are redacted before capture; body secrets follow \
                 the [dump] redact patterns."
                    .to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "The exchange id returned by capture_list."
                    }
                },
                "required": ["id"],
                "additionalProperties": false
            }),
        },
    ]
}

/// Handle a capture tool call, or return `None` if `name` is not one of ours.
///
/// Free-standing so the ring-to-agent path is testable without a proxy or a
/// `SharedRuntime`. The store only holds redacted exchanges, so everything
/// returned here is safe to show an agent. Tool-level failures (missing id,
/// evicted exchange) are returned as `isError` results rather than JSON-RPC
/// errors: the call was well formed, and the message is for the model.
fn capture_tool_call(store: &CaptureStore, name: &str, arguments: &Value) -> Option<Value> {
    match name {
        CAPTURE_LIST_TOOL => {
            let requested = argument_u64(arguments, "limit").unwrap_or(20).clamp(1, 100) as usize;
            let limit = requested.min(store.capacity().max(1));
            Some(tool_text(json!({
                "retained": store.len(),
                "capacity": store.capacity(),
                "dropped": store.dropped(),
                "exchanges": store.list(limit),
            })))
        }
        CAPTURE_GET_TOOL => {
            let Some(id) = argument_u64(arguments, "id") else {
                return Some(tool_error(
                    "Missing required parameter: id (the integer returned by capture_list)",
                ));
            };
            match store.get(id) {
                Some(exchange) => {
                    let value = serde_json::to_value(exchange).unwrap_or_else(|_| json!({}));
                    Some(tool_text(value))
                }
                None => Some(tool_error(format!(
                    "No captured exchange with id {id}; it may have been evicted \
                     (the ring holds at most {} exchanges)",
                    store.capacity()
                ))),
            }
        }
        _ => None,
    }
}

/// Read a non-negative integer argument, accepting the string form that some
/// clients and models send for an integer field.
fn argument_u64(arguments: &Value, key: &str) -> Option<u64> {
    let value = arguments.get(key)?;
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse().ok())
}

/// Wrap a JSON value in the MCP tool-result envelope.
fn tool_text(value: Value) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&value).unwrap_or_default()
        }],
        "isError": false
    })
}

/// Wrap a human-readable failure in the MCP tool-result envelope.
fn tool_error(message: impl Into<String>) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": message.into()
        }],
        "isError": true
    })
}

/// Extract the credential from a `Bearer` authorization header.
///
/// The scheme is case-insensitive per RFC 6750 and may be followed by more than
/// one space, so `bearer  <token>` has to mean the same thing as
/// `Bearer <token>`. Anything that is not a `Bearer` credential is `None`; the
/// caller never logs or echoes the value.
fn bearer_token(headers: &pingora::http::RequestHeader) -> Option<&str> {
    let value = headers.headers.get("authorization")?.to_str().ok()?;
    let (scheme, credentials) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let credentials = credentials.trim();
    (!credentials.is_empty()).then_some(credentials)
}

/// Constant-time bearer-token check, failing closed when no token is configured.
fn bearer_allowed(
    expected: Option<&str>,
    allow_insecure: bool,
    headers: &pingora::http::RequestHeader,
) -> bool {
    if allow_insecure {
        return true;
    }
    let Some(expected) = expected else {
        return false;
    };
    match bearer_token(headers) {
        Some(provided) => constant_time_eq(expected, provided),
        None => false,
    }
}

/// MCP service HTTP handler
pub struct McpService {
    /// Shared runtime for broker access
    runtime: SharedRuntime,
    /// MCP state (tools, resources)
    state: Arc<RwLock<McpState>>,
    /// Recent redacted exchanges; `None` means capture is off.
    capture: Option<CaptureStore>,
    /// Resolved bearer token.
    token: Option<String>,
    /// Whether to allow insecure access.
    allow_insecure: bool,
}

impl McpService {
    pub fn new(
        runtime: SharedRuntime,
        config: &McpConfig,
        capture: Option<CaptureStore>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            runtime,
            state: Arc::new(RwLock::new(McpState::new())),
            // A zero-capacity ring retains nothing. Keeping it would advertise
            // capture tools and an initialize note that promise an agent data
            // the broker has already decided not to keep.
            capture: capture.filter(|store| store.capacity() > 0),
            token: config.resolved_token()?,
            allow_insecure: config.allow_insecure,
        })
    }

    pub fn with_state(mut self, state: McpState) -> Self {
        self.state = Arc::new(RwLock::new(state));
        self
    }

    pub fn state(&self) -> Arc<RwLock<McpState>> {
        Arc::clone(&self.state)
    }

    fn authenticate(&self, headers: &pingora::http::RequestHeader) -> bool {
        bearer_allowed(self.token.as_deref(), self.allow_insecure, headers)
    }

    fn current_timestamp_ms() -> String {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        format!("{}", duration.as_millis())
    }

    async fn handle_initialize(&self, _params: &Value) -> Result<Value, McpError> {
        let mut response = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {}
            },
            "serverInfo": {
                "name": "llm-broker-mcp",
                "version": env!("CARGO_PKG_VERSION")
            }
        });
        // Tell the agent what the ring is for. A tool it does not know about is
        // a tool it will not call, and this is the cheapest place to say it.
        if self.capture.is_some() {
            response["instructions"] = json!(
                "This server can inspect traffic proxied by the LLM broker. \
                 Use capture_list for recent exchanges (newest first) and \
                 capture_get with an id for headers, bodies and routing. \
                 Credential headers are redacted before capture."
            );
        }

        let mut state = self.state.write().await;
        state.initialized_at = Some(Self::current_timestamp_ms());

        Ok(response)
    }

    async fn handle_tools_list(&self) -> Result<Value, McpError> {
        let state = self.state.read().await;
        let mut tools: Vec<Value> = Vec::new();
        if self.capture.is_some() {
            tools.extend(
                capture_tool_definitions()
                    .into_iter()
                    .map(|tool| serde_json::to_value(&tool).unwrap_or_else(|_| json!({}))),
            );
        }
        tools.extend(
            state
                .tools
                .values()
                .map(|t| serde_json::to_value(&t.tool).unwrap_or_else(|_| json!({}))),
        );

        Ok(json!({
            "tools": tools
        }))
    }

    async fn handle_tool_call(&self, params: &Value) -> Result<Value, McpError> {
        let tool_name = params.get("name").and_then(|v| v.as_str());
        let arguments = params.get("arguments").unwrap_or(&Value::Null);

        let tool_name = match tool_name {
            Some(n) => n.to_string(),
            None => {
                return Err(McpError {
                    code: -32602,
                    message: "Missing required parameter: name".to_string(),
                    data: None,
                });
            }
        };

        // Built-in capture tools take precedence: they are served from the
        // redacted ring and need no provider/model registration.
        if let Some(store) = self.capture.as_ref()
            && let Some(result) = capture_tool_call(store, &tool_name, arguments)
        {
            return Ok(result);
        }

        let state = self.state.read().await;
        let registered = state.get_tool(&tool_name).ok_or_else(|| McpError {
            code: -32601,
            message: format!("Tool not found: {}", tool_name),
            data: None,
        })?;

        // Build the request body to forward to the LLM
        let _request_body = json!({
            "model": registered.model,
            "messages": [
                {
                    "role": "user",
                    "content": format!("Execute tool: {} with arguments: {}", tool_name, serde_json::to_string_pretty(arguments).unwrap_or_default())
                }
            ],
            "tools": [registered.tool.clone()],
            "tool_choice": {
                "type": "function",
                "function": {
                    "name": tool_name
                }
            }
        });

        // Get the provider's base URL
        let config = self.runtime.read().config().clone();
        let provider = config
            .providers
            .iter()
            .find(|p| p.name == registered.provider);

        let _provider = match provider {
            Some(p) => p,
            None => {
                return Err(McpError {
                    code: -32602,
                    message: format!("Provider not found: {}", registered.provider),
                    data: None,
                });
            }
        };

        // For now, return a placeholder response
        // In a full implementation, this would forward to the LLM endpoint
        Ok(json!({
            "tool_use": {
                "name": tool_name,
                "arguments": arguments,
                "status": "pending"
            }
        }))
    }

    async fn handle_resources_list(&self) -> Result<Value, McpError> {
        let state = self.state.read().await;
        let resources: Vec<Value> = state
            .resources
            .values()
            .map(|r| {
                let res = &r.resource;
                json!({
                    "uri": res.uri,
                    "name": res.name,
                    "description": res.description,
                    "mimeType": res.mime_type
                })
            })
            .collect();

        Ok(json!({
            "resources": resources
        }))
    }

    async fn handle_resource_read(&self, params: &Value) -> Result<Value, McpError> {
        let uri = params.get("uri").and_then(|v| v.as_str());

        let uri = match uri {
            Some(u) => u.to_string(),
            None => {
                return Err(McpError {
                    code: -32602,
                    message: "Missing required parameter: uri".to_string(),
                    data: None,
                });
            }
        };

        let state = self.state.read().await;
        let resource = state.resources.get(&uri).ok_or_else(|| McpError {
            code: -32601,
            message: format!("Resource not found: {}", uri),
            data: None,
        })?;

        // Build the request body to forward to the LLM
        let _request_body = json!({
            "model": resource.model,
            "messages": [
                {
                    "role": "user",
                    "content": format!("Read resource at URI: {}", uri)
                }
            ]
        });

        // Get the provider's base URL
        let config = self.runtime.read().config().clone();
        let provider = config
            .providers
            .iter()
            .find(|p| p.name == resource.provider);

        let _provider = match provider {
            Some(p) => p,
            None => {
                return Err(McpError {
                    code: -32602,
                    message: format!("Provider not found: {}", resource.provider),
                    data: None,
                });
            }
        };

        // For now, return a placeholder response
        Ok(json!({
            "contents": [{
                "uri": uri,
                "mimeType": resource.resource.mime_type,
                "text": "Resource content placeholder - LLM would be called here"
            }]
        }))
    }
}

#[async_trait]
impl ProxyHttp for McpService {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let req_header = session.req_header();

        // MCP Streamable HTTP is JSON-RPC over POST. We do not offer the
        // optional GET/SSE stream, so answer 405 as the spec prescribes
        // instead of trying to parse a body a GET does not have.
        if req_header.method.as_str() != "POST" {
            respond_empty(session, 405, &[("Allow", "POST")]).await?;
            return Ok(true);
        }

        // Check authentication
        if !self.authenticate(req_header) {
            respond_empty(
                session,
                401,
                &[("WWW-Authenticate", "Bearer realm=\"MCP Server\"")],
            )
            .await?;
            return Ok(true);
        }

        // Reject an oversized body before reading it when the length is known.
        // A chunked request has no length to trust, so the assembled body is
        // checked again below.
        let declared_len = req_header
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if declared_len.is_some_and(|len| len > MAX_MCP_BODY_BYTES) {
            respond_empty(session, 413, &[]).await?;
            return Ok(true);
        }

        // Parse the MCP request. `read_request_body` yields one chunk per
        // call, so a body larger than pingora's read buffer used to be parsed
        // from its first chunk only and failed with a misleading syntax error.
        // Accumulate until the stream ends, and stop at the cap without
        // buffering the rest: the bound must hold for a chunked request too,
        // not just for one that declares `Content-Length`.
        let mut body_bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = session.downstream_session.read_request_body().await? {
            if body_bytes.len() + chunk.len() > MAX_MCP_BODY_BYTES {
                respond_empty(session, 413, &[]).await?;
                return Ok(true);
            }
            body_bytes.extend_from_slice(&chunk);
        }

        // A batch is valid JSON but not a single JSON-RPC request. Naming it
        // is more useful to a client than a parse error that blames syntax.
        if body_bytes.first() == Some(&b'[') {
            let response =
                McpResponse::error(Value::Null, -32600, "Batch requests are not supported");
            respond_json(session, 200, &response).await?;
            return Ok(true);
        }

        let request: McpRequest = match serde_json::from_slice(&body_bytes) {
            Ok(req) => req,
            Err(e) => {
                let response = McpResponse::error(Value::Null, -32700, format!("Parse error: {e}"));
                respond_json(session, 400, &response).await?;
                return Ok(true);
            }
        };

        info!(
            target: "llm_broker::mcp",
            method = %request.method,
            id = ?request.id,
            "Received MCP request"
        );

        // A JSON-RPC notification has no `id` and must not receive a response
        // body. This is the second half of the handshake: after `initialize`,
        // clients send `notifications/initialized`, and answering it with a
        // JSON-RPC error made the connection fail even with correct auth.
        let id = request.id.clone();
        if request.jsonrpc != "2.0" {
            let response = McpResponse::error(
                id.unwrap_or(Value::Null),
                -32600,
                "Unsupported JSON-RPC version (expected \"2.0\")",
            );
            respond_json(session, 200, &response).await?;
            return Ok(true);
        }
        let Some(id) = id else {
            debug!(
                target: "llm_broker::mcp",
                method = %request.method,
                "Accepted MCP notification"
            );
            respond_empty(session, 202, &[]).await?;
            return Ok(true);
        };

        // Route the request
        let response = match request.method.as_str() {
            // MCP defines `ping` so a client can check liveness without
            // touching tools. Answering -32601 worked, but it reads as a
            // broken server to a client that probes before use.
            "ping" => McpResponse::success(id, json!({})),
            "initialize" => {
                let params = request.params.unwrap_or(json!({}));
                match self.handle_initialize(&params).await {
                    Ok(result) => McpResponse::success(id, result),
                    Err(error) => McpResponse::error(id, error.code, error.message),
                }
            }
            "tools/list" => match self.handle_tools_list().await {
                Ok(result) => McpResponse::success(id, result),
                Err(error) => McpResponse::error(id, error.code, error.message),
            },
            "tools/call" => {
                let params = request.params.unwrap_or(json!({}));
                match self.handle_tool_call(&params).await {
                    Ok(result) => McpResponse::success(id, result),
                    Err(error) => McpResponse::error(id, error.code, error.message),
                }
            }
            "resources/list" => match self.handle_resources_list().await {
                Ok(result) => McpResponse::success(id, result),
                Err(error) => McpResponse::error(id, error.code, error.message),
            },
            "resources/read" => {
                let params = request.params.unwrap_or(json!({}));
                match self.handle_resource_read(&params).await {
                    Ok(result) => McpResponse::success(id, result),
                    Err(error) => McpResponse::error(id, error.code, error.message),
                }
            }
            _ => {
                debug!(
                    target: "llm_broker::mcp",
                    method = %request.method,
                    "Unknown MCP method"
                );
                McpResponse::error(id, -32601, format!("Method not found: {}", request.method))
            }
        };

        respond_json(session, 200, &response).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        // MCP service handles all requests internally
        Err(pingora::Error::new_down(pingora::ErrorType::new(
            "McpHasNoUpstream",
        )))
    }
}

/// Write a response with no body, plus any caller-supplied headers.
async fn respond_empty(
    session: &mut Session,
    status: u16,
    headers: &[(&str, &str)],
) -> pingora::Result<()> {
    let mut resp = ResponseHeader::build(status, None)?;
    for (name, value) in headers {
        // `IntoCaseHeaderName` only takes `&'static str`, so a dynamic name
        // must be passed as a String; these responses have at most two.
        resp.insert_header((*name).to_string(), *value)?;
    }
    resp.insert_header("Content-Length", 0)?;
    session.set_keepalive(None);
    session.write_response_header(Box::new(resp), true).await?;
    Ok(())
}

/// Write a JSON-RPC response. A serialization failure is ours, not the
/// client's, so it becomes a 500 rather than an empty 200.
async fn respond_json(
    session: &mut Session,
    status: u16,
    response: &McpResponse,
) -> pingora::Result<()> {
    let body = match serde_json::to_vec(response) {
        Ok(body) => body,
        Err(e) => {
            error!(
                target: "llm_broker::mcp",
                error = %e,
                "Failed to serialize MCP response"
            );
            return respond_empty(session, 500, &[]).await;
        }
    };

    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("Content-Type", "application/json")?;
    resp.insert_header("Content-Length", body.len())?;
    session.set_keepalive(None);
    session
        .write_response_header(Box::new(resp), body.is_empty())
        .await?;
    if !body.is_empty() {
        session.write_response_body(Some(body.into()), true).await?;
    }
    Ok(())
}

/// Add the MCP endpoint to the proxy's pingora server.
///
/// Deliberately a second *service* on the same [`Server`] rather than a second
/// `Server`: pingora's global setup belongs to one instance, and two servers in
/// one process fight over it.
pub fn add_mcp_service(
    server: &mut Server,
    runtime: SharedRuntime,
    config: &McpConfig,
    capture: Option<CaptureStore>,
) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    // The service owns one clone; the startup banner reports from the caller's
    // copy.
    let service = McpService::new(runtime, config, capture.clone())?;
    let mut svc = pingora::proxy::http_proxy_service(&server.configuration, service);
    let addr = format!("{}:{}", config.host, config.port);
    svc.add_tcp(&addr);

    println!("LLM Broker MCP endpoint listening on http://{addr}/");
    match capture.as_ref() {
        Some(store) if store.capacity() == 0 => {
            println!("[mcp] capture disabled (capture_capacity = 0)");
        }
        Some(store) => {
            println!(
                "[mcp] capture enabled: {} exchanges, {} KiB per body",
                store.capacity(),
                store.body_cap() / 1024
            );
        }
        None => {}
    }
    if config.allow_insecure {
        eprintln!(
            "[mcp] warning: allow_insecure = true; anyone who can reach {addr} can read \
             recent request and response bodies"
        );
    }

    server.add_service(svc);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::dump::{Dump, DumpConfig};
    use crate::proxy::parquet::CapturedExchange;
    use pingora::http::RequestHeader;

    fn header_with_token(token: Option<&str>) -> RequestHeader {
        let mut req = RequestHeader::build("POST", b"/mcp", None).unwrap();
        if let Some(token) = token {
            req.insert_header("Authorization", format!("Bearer {token}"))
                .unwrap();
        }
        req
    }

    #[test]
    fn a_matching_bearer_token_is_accepted() {
        let req = header_with_token(Some("llmb-secret"));
        assert!(bearer_allowed(Some("llmb-secret"), false, &req));
    }

    #[test]
    fn the_bearer_scheme_is_case_insensitive_and_tolerates_spaces() {
        // RFC 6750 makes the scheme case-insensitive and allows more than one
        // space before the credential. Rejecting `bearer` was a compatibility
        // trap with no security value.
        let mut req = RequestHeader::build("POST", b"/mcp", None).unwrap();
        req.insert_header("Authorization", "bearer   llmb-secret")
            .unwrap();
        assert!(bearer_allowed(Some("llmb-secret"), false, &req));

        let mut wrong_scheme = RequestHeader::build("POST", b"/mcp", None).unwrap();
        wrong_scheme
            .insert_header("Authorization", "Basic llmb-secret")
            .unwrap();
        assert!(!bearer_allowed(Some("llmb-secret"), false, &wrong_scheme));

        let mut empty = RequestHeader::build("POST", b"/mcp", None).unwrap();
        empty.insert_header("Authorization", "Bearer    ").unwrap();
        assert!(!bearer_allowed(Some("llmb-secret"), false, &empty));
    }

    #[test]
    fn a_wrong_or_missing_token_is_refused() {
        assert!(!bearer_allowed(
            Some("llmb-secret"),
            false,
            &header_with_token(Some("other"))
        ));
        assert!(!bearer_allowed(
            Some("llmb-secret"),
            false,
            &header_with_token(None)
        ));
    }

    #[test]
    fn no_token_fails_closed_unless_insecure_is_explicit() {
        // A capture endpoint with no token must not be open by accident: the
        // bodies it serves are prompt content.
        assert!(!bearer_allowed(None, false, &header_with_token(None)));
        assert!(bearer_allowed(None, true, &header_with_token(None)));
    }

    #[test]
    fn the_capture_tools_are_advertised_with_schemas() {
        let tools = capture_tool_definitions();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec![CAPTURE_LIST_TOOL, CAPTURE_GET_TOOL]);
        for tool in &tools {
            assert_eq!(tool.input_schema["type"], "object");
            assert!(tool.description.is_some());
        }
    }

    #[test]
    fn a_tool_is_advertised_with_the_specs_camel_case_schema_name() {
        // The MCP schema is `inputSchema`. Serde's default snake_case emitted
        // `input_schema`, which a strict client reads as "no argument schema"
        // and then calls the tool with the wrong shape (or refuses to).
        let tools = capture_tool_definitions();
        let value = serde_json::to_value(&tools[0]).unwrap();
        assert!(value.get("inputSchema").is_some(), "{value}");
        assert!(value.get("input_schema").is_none(), "{value}");

        let resource = McpResource {
            uri: "test://resource".into(),
            name: "Test".into(),
            description: None,
            mime_type: "text/plain".into(),
        };
        let value = serde_json::to_value(&resource).unwrap();
        assert!(value.get("mimeType").is_some(), "{value}");
        assert!(value.get("mime_type").is_none(), "{value}");
    }

    #[test]
    fn capture_unknown_tool_falls_through() {
        let store = CaptureStore::new(2);
        assert!(capture_tool_call(&store, "something_else", &json!({})).is_none());
    }

    #[test]
    fn capture_list_is_limited_and_reports_the_ring() {
        let store = CaptureStore::new(3);
        for id in 1..=3 {
            store.push(CapturedExchange {
                id,
                method: "POST".into(),
                uri: "/v1/chat/completions".into(),
                ..CapturedExchange::default()
            });
        }
        let result = capture_tool_call(&store, CAPTURE_LIST_TOOL, &json!({ "limit": 2 })).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["retained"], 3);
        assert_eq!(parsed["capacity"], 3);
        assert_eq!(parsed["exchanges"].as_array().unwrap().len(), 2);
        // Newest first.
        assert_eq!(parsed["exchanges"][0]["id"], 3);
        assert_eq!(result["isError"], false);
    }

    #[test]
    fn capture_tool_failures_are_tool_errors_not_protocol_errors() {
        // A missing or evicted id is a tool-level failure: the call itself was
        // well formed, so the agent should see `isError` and the message
        // instead of a JSON-RPC error that hides it.
        let store = CaptureStore::new(1);
        let missing = capture_tool_call(&store, CAPTURE_GET_TOOL, &json!({})).unwrap();
        assert_eq!(missing["isError"], true);
        assert!(
            missing["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Missing required parameter: id")
        );

        let evicted = capture_tool_call(&store, CAPTURE_GET_TOOL, &json!({ "id": 99 })).unwrap();
        assert_eq!(evicted["isError"], true);
        assert!(
            evicted["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("evicted")
        );
    }

    #[test]
    fn capture_get_accepts_an_id_sent_as_a_string() {
        // Models frequently stringify integers in tool arguments; refusing
        // that would turn a valid request into "missing parameter".
        let store = CaptureStore::new(2);
        store.push(CapturedExchange {
            id: 9,
            method: "POST".into(),
            uri: "/v1/chat/completions".into(),
            ..CapturedExchange::default()
        });

        let result = capture_tool_call(&store, CAPTURE_GET_TOOL, &json!({ "id": "9" })).unwrap();
        assert_eq!(result["isError"], false);
        let parsed: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(parsed["id"], 9);
    }

    /// The end-to-end security claim: a provider credential injected into the
    /// upstream request must not be readable through the MCP tool.
    ///
    /// Asserting on `render_headers` alone would not prove the ring and the MCP
    /// envelope keep it out, so this drives a real `Dump` through
    /// `finish` into the store and out through `capture_get`.
    #[test]
    fn the_provider_key_never_reaches_the_mcp_reader() {
        let store = CaptureStore::new(4);
        let mut dump = Dump::new(DumpConfig {
            capture_store: Some(store.clone()),
            ..DumpConfig::default()
        });

        let client = RequestHeader::build("POST", b"/v1/chat/completions", None).unwrap();
        dump.request_headers("POST", "/v1/chat/completions", "HTTP/1.1", &client);
        dump.request_body(br#"{"model":"gpt-4o","messages":[]}"#);

        let mut upstream = RequestHeader::build("POST", b"/v1/chat/completions", None).unwrap();
        upstream
            .insert_header("Authorization", "Bearer sk-live-SECRET-VALUE")
            .unwrap();
        upstream
            .insert_header("x-api-key", "sk-ant-SECRET-VALUE")
            .unwrap();
        dump.upstream_request(&upstream, Some("openai"), Some("openai-1"));

        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header("Content-Type", "application/json")
            .unwrap();
        dump.response_headers(200, &response);
        dump.response_body(br#"{"id":"ok"}"#, true);
        dump.finish(
            Some(200),
            1,
            Some("openai"),
            Some("openai-1"),
            Some("gpt-4o"),
            None,
        );

        let result =
            capture_tool_call(&store, CAPTURE_GET_TOOL, &json!({ "id": dump.id() })).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();

        assert!(!text.contains("sk-live-SECRET-VALUE"), "{text}");
        assert!(!text.contains("sk-ant-SECRET-VALUE"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        // The key id is still useful for diagnosis, and is not the credential.
        assert!(text.contains("openai-1"), "{text}");
        assert!(text.contains("\"model\": \"gpt-4o\""), "{text}");
    }

    #[test]
    fn mcp_tool_serialization() {
        let tool = McpTool {
            name: "test_tool".to_string(),
            description: Some("A test tool".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "param": {"type": "string"}
                }
            }),
        };

        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("test_tool"));
        assert!(json.contains("A test tool"));
    }

    #[test]
    fn mcp_resource_serialization() {
        let resource = McpResource {
            uri: "test://resource".to_string(),
            name: "Test Resource".to_string(),
            description: Some("A test resource".to_string()),
            mime_type: "application/json".to_string(),
        };

        let json = serde_json::to_string(&resource).unwrap();
        assert!(json.contains("test://resource"));
        assert!(json.contains("Test Resource"));
    }

    #[test]
    fn mcp_response_success() {
        let response = McpResponse::success(json!(1), json!({"result": "ok"}));
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn mcp_response_error() {
        let response = McpResponse::error(json!(1), -32601, "Method not found");
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_none());
        assert!(response.error.is_some());
    }

    #[test]
    fn a_jsonrpc_notification_parses_without_an_id() {
        // `notifications/initialized` is sent immediately after `initialize`
        // and carries no `id`. Requiring one made the broker answer HTTP 400,
        // which failed the handshake even when authentication was correct.
        let notification: McpRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .expect("a notification must parse");
        assert!(notification.id.is_none());
        assert_eq!(notification.method, "notifications/initialized");

        // An ordinary request still carries its id through.
        let request: McpRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#)
                .expect("a request must parse");
        assert_eq!(request.id, Some(json!(7)));
    }
}
