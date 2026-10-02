//! Rig orchestrator → researcher + GitHub-shaped MCP tools under Tenuo.
//!
//! ```text
//! cargo run --manifest-path examples/rig-mcp-delegation/Cargo.toml
//! ```

mod mcp;
mod tools;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rig_agent::agent::AgentBuilder;
use rig_agent::completion::Prompt;
use rig_agent::test_utils::{MockCompletionModel, MockTurn};
use serde_json::json;
use tenuo::sdk::prelude::*;

use crate::mcp::{
    call_guarded, call_raw, encode_tenuo_meta, enforcement_guard, mint_orchestrator,
    researcher_profile, spawn_pair,
};
use crate::tools::{get_issue_schema, guarded_mcp_tool, list_issues_schema, search_issues_schema};

#[tokio::main]
async fn main() -> Result<()> {
    println!("Tenuo × Rig — GitHub MCP, multi-agent\n");

    let issuer = SigningKey::generate();
    let orchestrator_key = SigningKey::generate();

    let parent_warrant = mint_orchestrator(&issuer, &orchestrator_key)?;
    let (client_guard, parent) = Tenuo::local()
        .trusted_root(issuer.public_key())
        .chain(vec![parent_warrant])
        .signer(orchestrator_key)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(600),
        })
        .build()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let server_guard = enforcement_guard(issuer.public_key())?;
    let mcp = spawn_pair(server_guard).await?;
    let mcp_client = Arc::new(mcp.client);
    let _mcp_server = mcp._server;

    println!("1. orchestrator delegates acme/web (no comments) to the researcher");
    let researcher = client_guard
        .delegate(&parent, &researcher_profile()?)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    println!(
        "   parent depth={} → child depth={}",
        parent.chain().len(),
        researcher.chain().len()
    );

    println!("\n2. cannot add create_pull_request — parent never had it");
    let widen =
        DelegationProfile::new().capability("create_pull_request", tenuo::ConstraintSet::new());
    match client_guard.delegate(&parent, &widen) {
        Err(err) => println!("   rejected: {err}"),
        Ok(_) => anyhow::bail!("widening delegation must fail"),
    }

    println!("\n3. researcher reads acme/web#42 over MCP");
    let issue = call_guarded(
        &client_guard,
        &researcher,
        &mcp_client,
        "get_issue",
        json!({ "owner": "acme", "repo": "web", "issue_number": 42 }),
    )
    .await?;
    println!("   {issue}");

    println!("\n4. Rig manager-worker: researcher searches and lists issues");
    let researcher_agent = AgentBuilder::new(MockCompletionModel::new([
        MockTurn::tool_call(
            "c1",
            "search_issues",
            json!({
                "query": "checkout timeout",
                "owner": "acme",
                "repo": "web"
            }),
        ),
        MockTurn::tool_call(
            "c2",
            "list_issues",
            json!({ "owner": "acme", "repo": "web" }),
        ),
        MockTurn::text("Researcher: acme/web#42 is a Safari checkout timeout."),
    ]))
    .name("researcher")
    .description("Reads GitHub issues in acme/web.")
    .default_max_turns(4)
    .dynamic_tool(guarded_mcp_tool(
        "search_issues",
        "Search issues with a GitHub query",
        search_issues_schema(),
        client_guard.clone(),
        researcher.clone(),
        Arc::clone(&mcp_client),
    ))
    .dynamic_tool(guarded_mcp_tool(
        "list_issues",
        "List issues in a repository",
        list_issues_schema(),
        client_guard.clone(),
        researcher.clone(),
        Arc::clone(&mcp_client),
    ))
    .dynamic_tool(guarded_mcp_tool(
        "get_issue",
        "Get one issue",
        get_issue_schema(),
        client_guard.clone(),
        researcher.clone(),
        Arc::clone(&mcp_client),
    ))
    .build();

    let orchestrator = AgentBuilder::new(MockCompletionModel::new([
        MockTurn::tool_call(
            "c3",
            "researcher",
            json!({ "prompt": "What is broken in acme/web?" }),
        ),
        MockTurn::text("Orchestrator: researcher found acme/web#42 (Safari checkout)."),
    ]))
    .name("orchestrator")
    .description("Plans the task. Does not call GitHub itself.")
    .dynamic_tool(researcher_agent.into_tool())
    .build();

    let answer = orchestrator
        .prompt("What is broken in acme/web?")
        .max_turns(6)
        .await
        .context("rig agent loop")?;
    println!("   rig final: {answer}");
    println!("   (final sentence is scripted; the MCP calls above are not)");

    println!("\n5. researcher cannot list acme/payroll (parent still can)");
    match call_guarded(
        &client_guard,
        &researcher,
        &mcp_client,
        "list_issues",
        json!({ "owner": "acme", "repo": "payroll" }),
    )
    .await
    {
        Err(err) => println!("   denied: {err}"),
        Ok(text) => anyhow::bail!("expected deny, got {text}"),
    }

    println!("\n6. researcher cannot comment — that tool was not delegated");
    match call_guarded(
        &client_guard,
        &researcher,
        &mcp_client,
        "add_issue_comment",
        json!({
            "owner": "acme",
            "repo": "web",
            "issue_number": 42,
            "body": "looking into this"
        }),
    )
    .await
    {
        Err(err) => println!("   denied: {err}"),
        Ok(text) => anyhow::bail!("expected deny, got {text}"),
    }

    println!("\n7. replay researcher PoP for web#42 on payroll#7 — only the server can stop this");
    let signed_for_web = encode_tenuo_meta(
        &client_guard,
        &researcher,
        "get_issue",
        &json!({ "owner": "acme", "repo": "web", "issue_number": 42 }),
    )?;
    match call_raw(
        &mcp_client,
        "get_issue",
        json!({ "owner": "acme", "repo": "payroll", "issue_number": 7 }),
        Some(signed_for_web),
    )
    .await
    {
        Err(err) => println!("   server denied: {err}"),
        Ok(text) => anyhow::bail!("expected server deny, got {text}"),
    }

    println!("\n8. tools/call with no _meta.tenuo — server refuses before the tool");
    match call_raw(
        &mcp_client,
        "list_issues",
        json!({ "owner": "acme", "repo": "payroll" }),
        None,
    )
    .await
    {
        Err(err) => println!("   server rejected: {err}"),
        Ok(text) => anyhow::bail!("expected missing-meta reject, got {text}"),
    }

    println!("\n9. orchestrator comments on acme/web#42");
    let comment = call_guarded(
        &client_guard,
        &parent,
        &mcp_client,
        "add_issue_comment",
        json!({
            "owner": "acme",
            "repo": "web",
            "issue_number": 42,
            "body": "researcher confirmed Safari checkout timeout"
        }),
    )
    .await?;
    println!("   {comment}");

    println!("\ndone.");
    Ok(())
}
