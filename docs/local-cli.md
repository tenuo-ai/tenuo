---
title: Local CLI
description: Prepare local identities, trust, and signed revocation lists
---

# Local controller files

The Python package includes `tenuo-cli` alongside the existing `tenuo` command.
No account or running service is required. From an unreleased source checkout,
use `PYTHONPATH=tenuo-python python -m tenuo.local_cli` instead of `tenuo-cli`.
Controller file locking currently supports macOS and Linux.

```bash
pip install tenuo
tenuo-cli init --dev
tenuo-cli key list
tenuo-cli trust list
tenuo-cli doctor
```

`init --dev` automatically prepares three separate identities: the controller
(`issuer`), the agent, and an approver. It trusts the local controller and creates
an empty signed revocation list. Plain `init` creates the layout without keys or
trust. Initialization refuses an existing directory; it never rotates keys.

The default workspace is `.tenuo/`. Change it with `TENUO_HOME` or `--home PATH`.

| Path | Purpose |
| --- | --- |
| `config.yaml` | Strict versioned configuration, defaulting to enforcement |
| `keys/issuer.key` | Controller private key: grants authority |
| `keys/agent.key` | Agent private key: proves it is the recipient |
| `keys/approver.key` | Approver private key: signs held calls |
| `keys/*.pub` | Public keys to exchange after verifying fingerprints |
| `trust/*.pub` | Issuers the verifier accepts |
| `revocations.srl` | Core signed revocation list in native CBOR |
| `warrants/` | Issued warrant chains |
| `sessions/` | Explicit operator-controlled session attachments |
| `requests/`, `approvals/` | Portable requests and responses |

Private files are created with mode `0600`. The workspace ignores its contents
in Git. No signing secrets are written to the application's `.env`. Separate
files under one OS user are **not process isolation**. A deployed agent receives
only its key, warrants and public verification data. Keep controller and approver
private keys outside its runtime mounts and credentials.

## Keys and trust

```bash
tenuo-cli key new another-agent
tenuo-cli trust add --file ./another-issuer.pub
```

Key readers accept base64, hex and PEM. Commands display fingerprints, never
private key bytes. Compare public-key fingerprints through a trusted channel
before adding trust.

## Revocation

```bash
tenuo-cli revocations show
tenuo-cli revocations add --id tnu_wrt_REPLACE_WITH_REAL_ID
```

Updates preserve revoked IDs and increment the signed list version. Writes are
atomic; concurrent local controller updates are serialized. Readers also accept
legacy base64-encoded lists. A missing or invalid configured list is an error.
Revocation takes effect when a verifier receives the updated list; the CLI does
not distribute files to other machines.

Global `--json` emits one JSON object to stdout; human output uses stderr.
`doctor` checks trust, signed revocation data and private-key permissions and
explains development isolation limits. Errors return a nonzero exit status.

## YAML templates and one-off requests

```bash
tenuo-cli template new --out orders.yaml
tenuo-cli template validate --file orders.yaml
tenuo-cli template show --file orders.yaml --expanded
```

The [example template](../tenuo-python/examples/local_cli/orders.yaml) describes
one order and a bounded refund. Use real registered tool and argument names.
Loading a template does not grant any authority. Changing it does not change
previously issued warrants.

```yaml
version: 2
name: refunds
ttl: 30m
capabilities:
  refund: {order_id: A-1001, amount_cents: 1..12000}
approvals:
  keys: [.tenuo/keys/approver.pub]
  required:
    refund: {unless: {amount_cents: 1..5000}}
```

The signed warrant allows refunds through 12000 cents, but requires one listed
approver for amounts outside the exempt range of 1–5000. An approval cannot
permit a call outside the warrant's capabilities. `required: {refund: always}`
gates every refund. Approver paths are relative to the YAML file. Local key
names are convenience labels, not verified identities.

For a standalone request, add `kind: warrant-request` and `holder: agent` (or a
public key path). An optional `reason` helps review. No registered policy is
required. Requests are unsigned proposals, not warrants.

Constraints support `any`, strings for exact matching, string lists for one-of,
and numeric ranges such as `1..12000`, `..5000`, or `1..`. Explicit forms include
`{exact: any}` for the literal string `any`, `{range: {min: 1, max: 5000}}`,
`{subpath: /data}`, `{pattern: '*.txt'}`, `{regex: '^order-'}`, and
`{url_pattern: 'https://api.example.com/*'}`. Numeric limits use ranges; booleans,
nulls, unknown fields, duplicate keys, YAML anchors and aliases are rejected.
URL matching alone does not provide SSRF protection.

Python code uses the same parser and native SDK builders:

```python
from tenuo import WarrantTemplate

template = WarrantTemplate.load("orders.yaml")
warrant = template.mint(controller_key, agent_public_key)
```

Issuance needs only the recipient's public key. Gates and approvers are embedded
in the signed warrant; verifiers do not trust the YAML file at runtime.

## Issue, inspect and replace warrants

```bash
tenuo-cli warrant issue --template orders.yaml --holder agent --out .tenuo/agent.warrant
tenuo-cli warrant issue --request one-task.yaml
tenuo-cli warrant list
tenuo-cli warrant show --file .tenuo/agent.warrant
tenuo-cli warrant verify --file .tenuo/agent.warrant
```

Issuance saves a native root-first warrant stack in `warrants/<id>.warrant`.
`--out` also writes a delivery copy; `--no-store --out PATH` writes only that
copy. Existing paths are never overwritten. Holder paths in a YAML request are
relative to that document; `holder: agent` resolves the workspace's public key.
The controller does not read the agent's private key.

`show --file PATH` or `show --id ID` decodes the signed authority without trust.
`show --file -` accepts a pasted stack on stdin. `verify` separately checks the
full chain against current local trust, expiry and the signed revocation list.
It exits 3 when verification fails. `list` inventories this workspace's files;
it is not a global inventory of every issued warrant.

```bash
tenuo-cli warrant reissue --id tnu_wrt_REAL_ID --ttl 1h
tenuo-cli warrant issue --from .tenuo/agent.warrant --key agent --request narrowed-task.yaml
```

Reissuance signs a new warrant with a new ID; it never extends or edits the old
warrant. The old warrant remains valid until it expires or is revoked.
Automatic reissue currently accepts only simple root execution warrants whose
claims can be copied exactly. For approval-gated or other richer warrants,
issue explicitly from the reviewed YAML again. Delegation uses the parent
holder's key and native attenuation: tools, limits, approvals and lifetime
cannot exceed the parent. The output always carries its complete chain.

Issuing a warrant does not attach it to a running session or workflow. Deliver
the selected file through the integration's explicit warrant configuration.
Nothing automatically selects the newest warrant or combines stored grants.

## Approve a held call using files

An integration writes an `approval-request` YAML file containing the complete
warrant chain, exact tool arguments, request hash and expiry. Send that file to
an approver. They need their own private key and independently configured trust
and revocation data; the request does not establish trust.

```bash
tenuo-cli approval show --file request.yaml
tenuo-cli approval approve --file request.yaml --out response.yaml --yes
# Or refuse that exact call with a signed reason:
tenuo-cli approval deny --file request.yaml --reason 'Duplicate refund' --out refusal.yaml --yes
```

Return the response file to the integration. `--key` selects an approver key by
name or path. Names are local labels; only a public key embedded in the signed
warrant is accepted. `--ttl 10m` overrides the default `approvals.ttl` of five
minutes, capped at both request and warrant expiry. Noninteractive signing
requires `--yes`; interactive signing displays the request and asks first.

The issuer does not participate in approving an already permitted call. Approval
does not widen its capabilities, extend its lifetime or undo revocation.
Responses use native `SignedApproval` artifacts. Refusals bind the reason under
a distinct local domain and cannot authorize the original call. An approval is
reusable for the same warrant, holder, tool and arguments until it expires;
there is no one-use tracking or changed Temporal retry-expiry behavior.

## LangChain and LangGraph

Install `tenuo[langchain]` (and `tenuo[langgraph]` for a graph). Issue a warrant
to the agent and select its delivery file explicitly:

```python
from langchain_core.tools import tool
from tenuo.langchain import TenuoTool

@tool
def get_order(order_id: str) -> str:
    """Look up an order."""
    return f"Order {order_id} is ready"

protected = TenuoTool.local(get_order, warrant=".tenuo/agent.warrant")
print(protected.invoke({"order_id": "A-1001"}))
# An order outside the YAML scope raises before get_order runs:
protected.invoke({"order_id": "OTHER"})
```

Give only protected tools to your agent. A LangGraph `ToolNode([protected])`
uses the same check on both sync and async dispatch; no warrant or key registry
is required in graph state. A graph checkpointer does not automatically suspend
for file approvals: return the request to an operator and retry after their
signed response arrives.

`path=` chooses the workspace and `key=` the agent key name or path. Before
each call the adapter reloads the selected warrant, trust and revocation files,
verifies the full chain, and checks the holder. Missing or malformed data denies
that call. Rollbacks below the accepted SRL version are refused for the lifetime
of that adapter; this does not persist a version floor across process restarts.
Replacing the selected file therefore needs no agent restart. Updating files
is an external controller action: an agent must not be able to edit them.

Approval-gated calls write requests under `.tenuo/requests/`. The approval CLI's
default response path is `.tenuo/approvals/<request_hash>.yaml`; retrying the
same call reads and verifies it. Decisions generate native signed receipts in
the configured `receipts.jsonl` using the existing SDK receipt machinery.
Local adapters currently support enforcement mode only and never read the
controller or approver private key. This is an in-process guardrail: expose
effects through a separately protected service if agent code can bypass wrappers.

## MCP client and server

The client selects a warrant file; the server independently loads public trust
and the signed revocation list. The verifier never needs the agent's private key.

```python
from tenuo.mcp import SecureMCPClient

async with SecureMCPClient.local(
    warrant=".tenuo/agent.warrant", command="python", args=["server.py"]
) as client:
    await client.call_tool("get_order", {"order_id": "A-1001"})
```

On a FastMCP server, protect dispatch through the existing middleware:

```python
from fastmcp import FastMCP
from tenuo.mcp import MCPVerifier, TenuoMiddleware

verifier = MCPVerifier.local(path="/run/tenuo-public")
server = FastMCP("orders", middleware=[TenuoMiddleware(verifier)])
```

Provision that server directory with `config.yaml`, `trust/*.pub` and
`revocations.srl`. Do not copy private keys from the client or controller.
For signed server receipts, create a separate server identity and pass its
name or private-key path as `MCPVerifier.local(key=...)`. Without it the server
still verifies calls but does not produce local signed receipts.

Both paths reread verification files per call and fail closed. The local client
always enforces and presents its authority; it refuses `warrant_context=False`
and disabled warrant injection. File approvals acquired on the client are
forwarded to the server as native signed approvals. A client check alone is an
in-process guardrail; server mediation protects the MCP dispatch path. Neither
prevents arbitrary code in the server process from accessing its own resources.

## Temporal

Install `tenuo[temporal]`. Worker configuration uses the same local files:

```python
from tenuo.local import load_warrant_chain
from tenuo.temporal import TenuoPluginConfig, TenuoTemporalPlugin, start_workflow_authorized

config = TenuoPluginConfig.local(activity_fns=[get_order])
plugin = TenuoTemporalPlugin(config)
# Connect the Temporal client with plugins=[plugin], and create its worker.
handle = await start_workflow_authorized(
    client=client,
    workflow_run_fn=OrderWorkflow.run,
    workflow_id="order-diagnostics",
    warrant=load_warrant_chain(".tenuo/agent.warrant"),
    key_id="agent",
    args=["A-1001"],
    task_queue="orders",
)
```

Use the existing `tenuo_execute_activity` helper inside the workflow. Workflow
start headers carry the complete warrant chain. Protected activity ingress
rereads trust and revocations before each call and refuses missing or invalid
files. A worker that only verifies incoming activity calls can use
`TenuoPluginConfig.local(key=None)` without any private key. A worker hosting
workflows that sign downstream calls needs its own matching holder key.

The factory refuses settings that disable warrant enforcement or local-activity
protection. It does not change approval expiry or retry semantics. Dynamic
Nexus trust refresh and attaching replacement warrants to running workflows are
separate lifecycle features; this adapter does not claim to implement them.
Issuing another file leaves an already running workflow's warrant unchanged.

`tenuo.local` exposes shared key/public-key/SRL readers and
`load_warrant_chain`; they use the same implementation as the common CLI.
Local signed receipt delivery reports storage failures in logs rather than
turning a completed effect into a retry. Receipts are decision evidence, not
proof that an authorized effect completed.

## Session attachments

For a session-based agent, issuance and attachment are different operations:

```bash
tenuo-cli session attach --session chat-a --file .tenuo/agent.warrant
tenuo-cli session list
tenuo-cli session show --session chat-a
tenuo-cli session detach --session chat-a --id tnu_wrt_REAL_ID
```

Use the session identifier reported by the integration. Attachment verifies the
chain and the selected agent's **public** key (`--holder agent` by default),
then references the stored full chain in a strict YAML manifest. It never
activates, extends or signs a warrant. A session can reference several warrants;
each call must fit one complete warrant, without combining partial grants.
Attachments survive conversational turns. A new child session needs its own
attachment; it does not inherit a parent's grants automatically.

Detachment removes one session's reference. It does not revoke a warrant used
elsewhere. Revocation changes validity wherever a verifier checks the updated
signed list. Keep session manifests, warrant storage, trust and revocations
read-only to the agent. Only requests, memory and the agent's audit destination
need writable state. Mount verification directories rather than individual files
when controllers publish changes by atomic replacement.

## Inspect local decisions

```bash
tenuo-cli audit list
tenuo-cli audit list --denied
tenuo-cli audit list --warrant tnu_wrt_REAL_ID --limit 20
tenuo-cli audit verify
```

The reader uses native signature verification and the existing SDK receipt-chain
verifier. It displays tool, decision, warrant ID, time, signer fingerprint and
revocation version. `--since` accepts a timezone-qualified ISO timestamp.
`--file` chooses a rotated file; inspection is limited to 64 MiB per file.

Verification recognizes public keys in the workspace's `keys/`. Use repeated
`--authorizer NAME_OR_PUBLIC_KEY_FILE` to choose a narrower set or recognize a
separate server identity. Recognition is an operator trust decision, not a
verified human identity.

The command checks signatures and recorded predecessor links. It does **not**
prove a complete history: adapter instances and restarts can start new streams,
and missing unlinked streams or a removed tail cannot be detected from that
file alone. Receipts commit to arguments; they do not include all raw arguments
or prove that an allowed effect completed. Use the integration's log or tool
result for detailed arguments and the denial message.
