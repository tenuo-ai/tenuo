# Rig + MCP with Tenuo

A Rig orchestrator hands a researcher a **narrower** GitHub warrant, then
the researcher calls a GitHub-shaped MCP server. Each `tools/call` carries
`_meta.tenuo`. The server checks it before the tool runs.

The tools match the official [GitHub MCP server](https://github.com/github/github-mcp-server):
`search_issues`, `list_issues`, `get_issue`, `add_issue_comment`.

```
control plane
    │  issues warrant: acme/*, plus comments
    ▼
orchestrator  ── attenuate ──►  researcher
    │                             │
    │  Rig agent-as-tool          │  search / list / get on acme/web only
    ▼                             ▼
                              MCP tools/call
                                  │
                                  ▼
                              GitHub MCP
                              Guard::guard_received
```

The orchestrator can use any `acme/*` repo and can comment. The researcher
can only search, list, and read issues in `acme/web`. Listing `acme/payroll`
or posting a comment is denied on the client — those requests never leave
the agent. Adding `create_pull_request` to the child is rejected —
authority can only shrink.

The MCP server is the enforcement point. A well-behaved client is not
enough: replaying a valid `get_issue` proof for `acme/web#42` against
`acme/payroll#7`, or calling with no `_meta.tenuo`, is denied on the
server before the tool runs.

## Run

```bash
cargo run --manifest-path examples/rig-mcp-delegation/Cargo.toml
```

No API key. The agent loop is scripted with Rig's `MockCompletionModel`.
Warrants, delegation, and the MCP hop are real. The in-process server
returns fixture issues (`acme/web#42`, `acme/payroll#7`) so the run stays
offline.

## Use it in your agent

Sign inside the tool `call`, after the model has chosen a name and
arguments. A `ToolContext` `Meta` set before `prompt()` is too early —
Tenuo binds the proof to that specific invocation.

```rust
// Client: authorize, then send. Deny never reaches the wire.
let encoded = guard.guard(&authority, &call, |authorized| {
    encode_meta_from_authorized(authorized)
})?;

let mut meta = Meta::new();
meta.0.insert("tenuo".into(), encoded.into_inner());
params.meta = Some(meta);
client.call_tool(params).await?;
```

```rust
// Server: rmcp 2 puts wire `_meta` on the request context.
let tenuo = context.meta.0.get("tenuo").ok_or(...)?;
let received = decode_meta(tenuo)?.as_received()?;
guard.guard_received(&received, &call, |_| run_tool())?;
```

`DynamicTool` in this example is the whole adapter: each MCP tool is a Rig
tool that wraps `call_guarded`. Point the same wrapper at a real GitHub MCP
server and swap `MockCompletionModel` for your provider.

Requires [Rig](https://rig.rs) 0.42 and [rmcp](https://crates.io/crates/rmcp) 2.
