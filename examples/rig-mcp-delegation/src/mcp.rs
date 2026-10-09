//! In-process MCP server that enforces Tenuo on `tools/call`.
//!
//! Tool names and arguments follow the official GitHub MCP server:
//! `search_issues`, `list_issues`, `get_issue`, `add_issue_comment`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ErrorData, Implementation,
    ListToolsResult, Meta, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo,
    Tool,
};
use rmcp::service::{RequestContext, RoleClient, RoleServer, RunningService};
use rmcp::ServiceExt;
use serde_json::{json, Map, Value};
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::{decode_meta, encode_meta_from_authorized, strip_tenuo};
use tenuo::{constraints, Exact, Pattern, Wildcard};
use tokio::io::duplex;

pub type McpClient = Arc<RunningService<RoleClient, ()>>;

pub fn enforcement_guard(root: tenuo::PublicKey) -> Result<Guard> {
    Tenuo::enforcement()
        .trusted_root(root)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(600),
        })
        .build()
        .map_err(|e| anyhow!(e.to_string()))
}

pub struct GithubServer {
    guard: Guard,
}

impl GithubServer {
    pub fn new(guard: Guard) -> Self {
        Self { guard }
    }
}

fn object_schema(value: Value) -> Arc<Map<String, Value>> {
    Arc::new(value.as_object().cloned().expect("schema object"))
}

impl ServerHandler for GithubServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(Implementation::new("github", "0.1.0"))
            .with_instructions("GitHub issues. Authorization is on params._meta.tenuo.")
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        async move {
            Ok(ListToolsResult::with_all_items(vec![
                Tool::new(
                    "search_issues",
                    "Search issues with a GitHub query",
                    object_schema(json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string" },
                            "owner": { "type": "string" },
                            "repo": { "type": "string" }
                        },
                        "required": ["query"]
                    })),
                ),
                Tool::new(
                    "list_issues",
                    "List issues in a repository",
                    object_schema(json!({
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" }
                        },
                        "required": ["owner", "repo"]
                    })),
                ),
                Tool::new(
                    "get_issue",
                    "Get one issue",
                    object_schema(json!({
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "issue_number": { "type": "integer" }
                        },
                        "required": ["owner", "repo", "issue_number"]
                    })),
                ),
                Tool::new(
                    "add_issue_comment",
                    "Comment on an issue",
                    object_schema(json!({
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "issue_number": { "type": "integer" },
                            "body": { "type": "string" }
                        },
                        "required": ["owner", "repo", "issue_number", "body"]
                    })),
                ),
            ]))
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, ErrorData>> + Send + '_ {
        async move {
            let name = request.name.to_string();
            let args = Value::Object(request.arguments.unwrap_or_default());

            // rmcp 2 lifts wire `_meta` into RequestContext and strips it from params.
            let mut meta = request
                .meta
                .as_ref()
                .or(Some(&context.meta))
                .map(|m| Value::Object(m.0.clone()))
                .unwrap_or_else(|| json!({}));
            let Some(tenuo) = meta.get("tenuo").cloned() else {
                println!("   mcp server rejected {name}: missing _meta.tenuo");
                return Err(ErrorData::invalid_params(
                    "missing params._meta.tenuo",
                    None,
                ));
            };
            strip_tenuo(&mut meta);

            let owned = decode_meta(&tenuo)
                .map_err(|e| ErrorData::invalid_params(format!("tenuo decode: {e}"), None))?;
            let received = owned
                .as_received()
                .map_err(|e| ErrorData::invalid_params(format!("tenuo authority: {e}"), None))?;
            let call = Call::try_from_json(&name, &args)
                .map_err(|e| ErrorData::invalid_params(format!("arguments: {e}"), None))?;

            match self
                .guard
                .guard_received(&received, &call, |_| run_tool(&name, &args))
            {
                Ok(result) => Ok(CallToolResult::success(vec![ContentBlock::text(
                    result.into_inner(),
                )])),
                Err(GuardError::Denied(denial)) => {
                    println!(
                        "   mcp server denied {name} [{}]: {}",
                        denial.code(),
                        denial
                    );
                    Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "tenuo denied [{}]",
                        denial.code()
                    ))]))
                }
                Err(GuardError::Operation(err)) => {
                    Err(ErrorData::internal_error(err.to_string(), None))
                }
            }
        }
    }
}

fn run_tool(name: &str, args: &Value) -> Result<String, String> {
    match name {
        "search_issues" => {
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            let owner = args.get("owner").and_then(Value::as_str).unwrap_or("");
            let repo = args.get("repo").and_then(Value::as_str).unwrap_or("");
            println!("   mcp server ran search_issues {owner}/{repo} query={query:?}");
            Ok(if repo == "web" || query.contains("checkout") {
                "[#42] checkout timeout on Safari (acme/web)".into()
            } else {
                format!("no hits for {query:?}")
            })
        }
        "list_issues" => {
            let owner = arg(args, "owner")?;
            let repo = arg(args, "repo")?;
            println!("   mcp server ran list_issues {owner}/{repo}");
            Ok(match (owner.as_str(), repo.as_str()) {
                ("acme", "web") => "[#42] checkout timeout on Safari".into(),
                ("acme", "payroll") => "[#7] salary export failing".into(),
                _ => format!("no issues in {owner}/{repo}"),
            })
        }
        "get_issue" => {
            let owner = arg(args, "owner")?;
            let repo = arg(args, "repo")?;
            let n = args
                .get("issue_number")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            println!("   mcp server ran get_issue {owner}/{repo}#{n}");
            Ok(match (owner.as_str(), repo.as_str(), n) {
                ("acme", "web", 42) => {
                    "acme/web#42: Checkout times out on Safari 17. Repro on /cart.".into()
                }
                ("acme", "payroll", 7) => {
                    "acme/payroll#7: Nightly salary CSV export failed (PII).".into()
                }
                _ => format!("{owner}/{repo}#{n} not found"),
            })
        }
        "add_issue_comment" => {
            let owner = arg(args, "owner")?;
            let repo = arg(args, "repo")?;
            let n = args
                .get("issue_number")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            println!("   mcp server ran add_issue_comment {owner}/{repo}#{n}");
            Ok(format!("commented on {owner}/{repo}#{n}"))
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

fn arg(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{key} required"))
}

pub struct McpPair {
    pub client: RunningService<RoleClient, ()>,
    /// Must stay alive: dropping it closes the duplex and tears down `_meta`.
    pub _server: RunningService<RoleServer, GithubServer>,
}

pub async fn spawn_pair(guard: Guard) -> Result<McpPair> {
    let (server_io, client_io) = duplex(64 * 1024);
    let (s_read, s_write) = tokio::io::split(server_io);
    let (c_read, c_write) = tokio::io::split(client_io);

    let server_fut = GithubServer::new(guard).serve((s_read, s_write));
    let client_fut = ().serve((c_read, c_write));
    let (server, client) = tokio::join!(server_fut, client_fut);
    Ok(McpPair {
        client: client.context("mcp client handshake")?,
        _server: server.context("mcp server handshake")?,
    })
}

/// Authorize, encode `_meta.tenuo`, then `tools/call`.
///
/// `Guard::guard`'s closure is sync, so the network call stays outside it.
/// A deny never produces a request.
pub async fn call_guarded(
    guard: &Guard,
    authority: &PresentedAuthority,
    client: &RunningService<RoleClient, ()>,
    tool: &str,
    arguments: Value,
) -> Result<String> {
    let call = Call::try_from_json(tool, &arguments)?;
    let encoded = guard
        .guard(authority, &call, |authorized| {
            encode_meta_from_authorized(authorized).map_err(|e| e.to_string())
        })
        .map_err(|e| anyhow!("client {tool}: {e}"))?;

    let mut meta = Meta::new();
    meta.0.insert("tenuo".into(), encoded.into_inner());

    let mut params = CallToolRequestParams::new(tool.to_string());
    if let Some(object) = arguments.as_object() {
        params = params.with_arguments(object.clone());
    }
    params.meta = Some(meta);

    let result = client
        .call_tool(params)
        .await
        .with_context(|| format!("mcp tools/call {tool}"))?;

    let text = result
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    if result.is_error == Some(true) {
        return Err(anyhow!("{text}"));
    }
    Ok(text)
}

/// Sign `_meta.tenuo` for one call. Does not send.
pub fn encode_tenuo_meta(
    guard: &Guard,
    authority: &PresentedAuthority,
    tool: &str,
    arguments: &Value,
) -> Result<Value> {
    let call = Call::try_from_json(tool, arguments)?;
    Ok(guard
        .guard(authority, &call, |authorized| {
            encode_meta_from_authorized(authorized).map_err(|e| e.to_string())
        })
        .map_err(|e| anyhow!("sign {tool}: {e}"))?
        .into_inner())
}

/// `tools/call` with caller-supplied `_meta`. Skips the client guard.
///
/// Use this to show the MCP server is the enforcement point: a replayed or
/// missing warrant still dies before `run_tool`.
pub async fn call_raw(
    client: &RunningService<RoleClient, ()>,
    tool: &str,
    arguments: Value,
    tenuo_meta: Option<Value>,
) -> Result<String> {
    let mut params = CallToolRequestParams::new(tool.to_string());
    if let Some(object) = arguments.as_object() {
        params = params.with_arguments(object.clone());
    }
    if let Some(encoded) = tenuo_meta {
        let mut meta = Meta::new();
        meta.0.insert("tenuo".into(), encoded);
        params.meta = Some(meta);
    }

    let result = client
        .call_tool(params)
        .await
        .with_context(|| format!("mcp tools/call {tool}"))?;

    let text = result
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    if result.is_error == Some(true) {
        return Err(anyhow!("{text}"));
    }
    Ok(text)
}

fn acme_repo(repo: impl Into<tenuo::Constraint>) -> tenuo::ConstraintSet {
    constraints! {
        "owner" => Exact::new("acme"),
        "repo" => repo,
    }
}

fn acme_issue(repo: impl Into<tenuo::Constraint>) -> tenuo::ConstraintSet {
    let mut set = acme_repo(repo);
    set.insert("issue_number", Wildcard);
    set
}

fn acme_comment(repo: impl Into<tenuo::Constraint>) -> tenuo::ConstraintSet {
    let mut set = acme_issue(repo);
    set.insert("body", Wildcard);
    set
}

fn acme_search(repo: impl Into<tenuo::Constraint>) -> tenuo::ConstraintSet {
    let mut set = acme_repo(repo);
    set.insert("query", Wildcard);
    set
}

/// Parent: any `acme/*` repo, plus comments.
pub fn mint_orchestrator(
    issuer: &tenuo::SigningKey,
    holder: &tenuo::SigningKey,
) -> Result<tenuo::Warrant> {
    let any = Pattern::new("*")?;
    Ok(tenuo::Warrant::builder()
        .capability("search_issues", acme_search(any.clone()))
        .capability("list_issues", acme_repo(any.clone()))
        .capability("get_issue", acme_issue(any.clone()))
        .capability("add_issue_comment", acme_comment(any))
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .max_depth(8)
        .build(issuer)?)
}

/// Child: `acme/web` only. No comments. Terminal.
pub fn researcher_profile() -> Result<DelegationProfile> {
    let web = Exact::new("web");
    Ok(DelegationProfile::new()
        .capability("search_issues", acme_search(web.clone()))
        .capability("list_issues", acme_repo(web.clone()))
        .capability("get_issue", acme_issue(web))
        .ttl(Duration::from_secs(120))
        .terminal())
}
