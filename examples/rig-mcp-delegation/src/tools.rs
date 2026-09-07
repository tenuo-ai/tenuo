//! Rig tools that wrap an MCP client.
//!
//! Sign inside `call`, after the model has chosen a name and arguments.
//! A `ToolContext` `Meta` set before `prompt()` is too early for Tenuo PoP.

use std::sync::Arc;

use rig_agent::tool::{DynamicTool, ToolContext, ToolExecutionError, ToolOutput};
use serde_json::{json, Value};
use tenuo::sdk::prelude::*;

use crate::mcp::{self, McpClient};

pub fn guarded_mcp_tool(
    name: &'static str,
    description: &str,
    schema: Value,
    guard: Guard,
    authority: PresentedAuthority,
    client: McpClient,
) -> DynamicTool {
    DynamicTool::new(
        name,
        description,
        schema,
        move |_ctx: &mut ToolContext, args: Value| {
            let guard = guard.clone();
            let authority = authority.clone();
            let client = Arc::clone(&client);
            Box::pin(async move {
                match mcp::call_guarded(&guard, &authority, &client, name, args).await {
                    Ok(text) => Ok(ToolOutput::text(text)),
                    Err(err) => Err(ToolExecutionError::refused(err.to_string())),
                }
            })
        },
    )
}

pub fn search_issues_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" },
            "owner": { "type": "string" },
            "repo": { "type": "string" }
        },
        "required": ["query"]
    })
}

pub fn list_issues_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "owner": { "type": "string" },
            "repo": { "type": "string" }
        },
        "required": ["owner", "repo"]
    })
}

pub fn get_issue_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "owner": { "type": "string" },
            "repo": { "type": "string" },
            "issue_number": { "type": "integer" }
        },
        "required": ["owner", "repo", "issue_number"]
    })
}
