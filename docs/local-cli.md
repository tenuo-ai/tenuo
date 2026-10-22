---
title: Local CLI
description: Prepare local identities, trust, and signed revocation lists
---

# Local CLI

The Python package includes `tenuo-cli` alongside the existing `tenuo` command.
No account or running service is required. From an unreleased source checkout,
use `PYTHONPATH=tenuo-python python -m tenuo.local_cli` instead of `tenuo-cli`.
Workspace file locking currently supports macOS and Linux.

```bash
pip install tenuo
tenuo-cli init --dev
tenuo-cli key list
tenuo-cli trust list
tenuo-cli doctor
```

`init --dev` automatically prepares three separate identities: the issuer (the
root that signs warrants), the agent, and an approver. It trusts the issuer and creates
an empty signed revocation list. Plain `init` creates the layout without keys or
trust. Initialization refuses an existing directory; it never rotates keys.

The default workspace is `~/.tenuo/`, outside your project. Change it with
`TENUO_HOME` or `--home PATH`.

| Path | Purpose |
| --- | --- |
| `config.yaml` | Strict versioned configuration: `mode` is `enforce` (default) or `observe` |
| `keys/issuer.key` | Issuer (root) private key: signs warrants |
| `keys/agent.key` | Agent holder key: proves possession of its warrants |
| `keys/approver.key` | Approver private key: signs held calls |
| `keys/*.pub` | Public keys to exchange after verifying fingerprints |
| `trust/*.pub` | Trusted roots: issuer public keys the verifier accepts |
| `revocations.srl` | Core signed revocation list in native CBOR |
| `warrants/` | Issued warrant chains |
| `sessions/` | Session attachments, managed by the integration (e.g. `hermes-tenuo session`) |
| `requests/`, `approvals/` | Portable requests and responses |
| `observations.jsonl` | Calls recorded in observe mode, with argument values |

Private files are created with mode `0600`, and the workspace ignores its
contents in Git. No signing secrets are written to the application's `.env`.

## Keep the issuer key out of the agent's reach

Anyone who can read `keys/issuer.key` can sign warrants, including new ones for
themselves, and can re-sign `revocations.srl` to undo a revocation. Every
verifier that trusts that issuer accepts the result, on this machine or any
other. `keys/approver.key` does the same for held calls. The agent needs only
its own holder key, its warrants, `trust/` and `revocations.srl`.

File permissions don't separate these on their own. Mode `0600` stops other
users, not the user the agent runs as, and the same is true of a keychain item
or an environment variable the agent's process can read. Locally, the agent's
own warrant is what keeps it away from the keys:

- The workspace defaults to `~/.tenuo`, outside your project. Keep it there.
  For a separate workspace per project, point `TENUO_HOME` at another path
  outside the project.
- Scope the agent's file tools to the project with `subpath`. It normalizes
  `..`, so a path that climbs out of the project is denied. Keeping the workspace
  outside the allowed root is safer than excluding it with `pattern` or `regex`,
  which match the string and don't normalize paths.
- `subpath` checks the path string and doesn't follow symlinks, so a link inside
  the project that points into `~/.tenuo` gets through. Have file tools open
  paths with [`path_jail`](https://github.com/tenuo-ai/path_jail), which refuses
  links that leave the project, and don't give the agent a tool that creates
  links.
- Don't give the agent a tool that runs arbitrary commands or code. A shell
  that allows `cat` or `python` reads any file the user can, whatever the
  warrant says about paths. List the exact commands it may run instead.

```yaml
capabilities:
  read_file: {path: {subpath: /Users/me/project}}
  run_command: {cmd: [pytest, git status]}
```

This is a guardrail for local development. If the agent can run code that
Tenuo doesn't check, separate the keys by OS user, container or machine: run
`tenuo-cli` as a different user, or leave the issuer's workspace out of the
agent's container mounts. `doctor` warns when the current user can read the
issuer or approver key.

## Keys and trust

```bash
tenuo-cli key new another-agent
tenuo-cli trust add --file ./another-issuer.pub
```

Key readers accept base64, hex and PEM. Untagged public keys must have a `.pub`
filename; public-key PEM files can use other names. Private `.key` paths,
including symlinks to them, are rejected as public inputs. Public and private
Ed25519 values can both contain 32 bytes, so byte length alone cannot distinguish
them. Keep the generated filenames and exchange only the `.pub` files.
Commands display fingerprints, never private key bytes. Compare public-key
fingerprints through a trusted channel before adding trust.

## Revocation

```bash
tenuo-cli revocations show
tenuo-cli revocations add --id tnu_wrt_REPLACE_WITH_REAL_ID
```

Updates preserve revoked IDs and increment the signed list version. Writes are
atomic; concurrent local updates are serialized. Readers also accept
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

A plain string is an exact value, so `order_id: A-*` matches only the literal
`A-*`. `template validate` warns about a plain string or `one_of` entry that
contains `*` or `?`; write `{pattern: A-*}` to match by pattern.

Every argument a template names must be present, and arguments it doesn't name
are refused. Wrap an argument a tool may leave out in `optional`: it can be
omitted, and if it's sent it must match, e.g. `limit: {optional: 1..10}` or
`action: {optional: send}`. A list may hold integers for numeric IDs such as
`pullNumber: [57, 58]`.

```yaml
version: 2
name: refunds
ttl: 30m
capabilities:
  refund: {order_id: A-1001, amount_cents: 1..12000}
approvals:
  keys: [~/.tenuo/keys/approver.pub]
  required:
    refund: {unless: {amount_cents: 1..5000}}
```

The signed warrant allows refunds through 12000 cents, but requires one listed
approver for amounts outside the exempt range of 1–5000. An approval cannot
permit a call outside the warrant's capabilities. `required: {refund: always}`
gates every refund. Relative approver paths resolve from the YAML file. Local key
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
warrant = template.mint(issuer_key, agent_public_key)
```

Issuance needs only the recipient's public key. Gates and approvers are embedded
in the signed warrant; verifiers do not trust the YAML file at runtime.

## Issue, inspect and replace warrants

```bash
tenuo-cli warrant issue --template orders.yaml --holder agent --out ~/.tenuo/agent.warrant
tenuo-cli warrant issue --request one-task.yaml
tenuo-cli warrant list
tenuo-cli warrant show --file ~/.tenuo/agent.warrant
tenuo-cli warrant verify --file ~/.tenuo/agent.warrant
```

Issuance saves a native root-first warrant stack in `warrants/<id>.warrant`.
`--out` also writes a delivery copy; `--no-store --out PATH` writes only that
copy. Existing paths are never overwritten. Holder paths in a YAML request are
relative to that document; a `--holder` path resolves from the current
directory. `holder: agent` resolves the workspace's public key. Issuance never
reads the agent's private key.

`show --file PATH` or `show --id ID` decodes the signed authority without trust.
`show --file -` accepts a pasted stack on stdin. `verify` separately checks the
full chain against current local trust, expiry and the signed revocation list.
It exits 3 when verification fails. `list` inventories this workspace's files;
it is not a global inventory of every issued warrant.

```bash
tenuo-cli warrant reissue --id tnu_wrt_REAL_ID --ttl 1h
tenuo-cli warrant issue --from ~/.tenuo/agent.warrant --key agent --request narrowed-task.yaml
```

Reissuance signs a new warrant with a new ID; it never extends or edits the old
warrant. The old warrant remains valid until it expires or is revoked.
Reissue refuses a revoked ID. Revoking the old ID after a reissue does not
cover the new warrant, which is a new root, so revoke both. Automatic reissue
currently accepts only simple root execution warrants whose claims can be
copied exactly. For approval-gated or other richer warrants,
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

protected = TenuoTool.local(get_order, warrant="~/.tenuo/agent.warrant")
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
Replacing the selected file therefore needs no agent restart:
`tenuo-cli warrant issue --template T.yaml --holder agent --out agent.warrant --replace`
swaps it atomically, and the next call uses the new warrant. Updating files
is an operator action: an agent must not be able to edit them.

Approval-gated calls write requests under `~/.tenuo/requests/`. The approval CLI's
default response path is `~/.tenuo/approvals/<request_hash>.yaml`; retrying the
same call reads and verifies it. Decisions generate native signed receipts in
the configured `receipts.jsonl` using the existing SDK receipt machinery.
Local adapters never read the issuer or approver private key. To see what an
agent calls before writing its warrant, start in [observe mode](#observe-first). This is an in-process guardrail: expose
effects through a separately protected service if agent code can bypass wrappers.

## MCP client and server

The client selects a warrant file; the server independently loads public trust
and the signed revocation list. The verifier never needs the agent's private key.

```python
from tenuo.mcp import SecureMCPClient

async with SecureMCPClient.local(
    warrant="~/.tenuo/agent.warrant", command="python", args=["server.py"]
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
`revocations.srl`. Do not copy private keys from the client or issuer.
For signed server receipts, create a separate server identity and pass its
name or private-key path as `MCPVerifier.local(key=...)`. Without it the server
still verifies calls but does not produce local signed receipts.

Both paths reread verification files per call and fail closed. In enforce mode
the local client always checks and presents its authority; it refuses `warrant_context=False`
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
    warrant=load_warrant_chain("~/.tenuo/agent.warrant"),
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

## Observe first

Before you have a warrant, run the agent with the workspace in observe mode.
Local adapters then block nothing. Each call is recorded, with its arguments and
the decision enforcement would have made, so you can draft a warrant from what
the agent actually did.

```bash
tenuo-cli mode observe
# run the agent for a few tasks
tenuo-cli calls summary
tenuo-cli calls list --tool get_order
```

In observe mode the LangChain tool and the MCP client may be created without
`warrant=`. Calls recorded without one have `"decision": null` and
`"reason": "no_warrant"`. With a warrant, a call outside its scope runs and is
recorded as `"deny"` with the reason, such as a violated constraint, an expired
or revoked warrant, or `approval_required`. No approval request is written.
An `MCPVerifier.local` server in observe mode runs calls whether or not they
carry a warrant; when both client and server use the workspace, each records
the call it saw. `TenuoPluginConfig.local` maps observe mode onto `dry_run` and
records each activity decision with its argument values.

Calls go to `observations.jsonl` in the workspace, one JSON object per line,
created readable by its owner only because it holds argument values. Each line
has `run`, `step`, `tool` and `args`, the format
[warrantgen](https://github.com/RajanChavada/warrantgen) reads to draft
a template from recorded calls, plus `decision`, `reason`, `warrant_id`,
`argument` (for a constraint denial, the name of the argument that failed) and
`observed_at`. `run` is one process, or the Temporal workflow run; set
`TENUO_RUN_ID` to group calls differently, for example one value per task in a
long-lived agent.
Pass `step=` to `TenuoTool.local`, `SecureMCPClient.local` or
`MCPVerifier.local` to group calls that will share one warrant.

`tenuo-cli calls summary` counts the recorded calls per tool: how many ran, in
how many runs, what enforcement would have decided and why, and which
arguments denials failed on (`denied_on`). For each argument it shows how many
distinct values it took, the minimum and maximum of numbers, the values
themselves when there are five or fewer strings and any prefix they share, and
whether every run used the same values (`same_in_every_run`). An argument some
calls leave out shows how many (`absent_in_calls`); it needs `{optional: …}` in
the template, since every listed argument is otherwise required. An argument that
differs between runs usually belongs in the warrant issued for each task; one
that never changes can be fixed in the template. Strings with whitespace are
marked `free_text`; they're still listed when there are five or fewer short
ones (a handful of shell commands is exactly what a command allowlist needs),
and otherwise the row points to `tenuo-cli calls list --tool NAME`. A prefix
shared by paths stops at a folder. The summary is plain counting over the file;
it does not suggest a policy. It ends with the commands for each recorded step:
`tenuo-cli template new` to write a template from the summary, then validate,
issue and enforce. Drafting from the log with
[warrantgen](https://github.com/RajanChavada/warrantgen) is optional and
installed separately; its commands are printed as comments
(`uvx --from git+https://github.com/RajanChavada/warrantgen warrantgen template …`):
`--standing` drafts one warrant that covers every run seen (a cron job, a shared
server, a long chat), `--from-run` a warrant for one run's task.
`tenuo-cli calls list` shows the recorded calls themselves.

Observe mode writes no signed receipts: receipts don't yet record the mode, so
an observed denial would read as an enforced one.

When the warrant is ready, switch back:

```bash
tenuo-cli mode enforce
```

LangChain, MCP client and MCP server adapters read the mode before every call,
so the switch applies to the next call. Temporal fixes `dry_run` when the worker
starts: after a switch the worker refuses protected activities until it is
restarted. `tenuo-cli doctor` warns while the workspace is in observe mode.

`tenuo.local` exposes shared key/public-key/SRL readers and
`load_warrant_chain`; they use the same implementation as the common CLI.
Local signed receipt delivery reports storage failures in logs rather than
turning a completed effect into a retry. Receipts are decision evidence, not
proof that an authorized effect completed.

## Rotation

Before rotating an issuer, generate and trust the replacement public key,
then advance the existing signed revocation list using that key:

```bash
tenuo-cli key new next-issuer
tenuo-cli trust add --file ~/.tenuo/keys/next-issuer.pub --name next-issuer
tenuo-cli revocations add --key next-issuer --id tnu_wrt_RETIRED_GRANT
tenuo-cli warrant issue --template orders.yaml --holder agent --key next-issuer
```

Deliver the new warrant, public trust and list, update `issuer:` in the
issuer workspace's `config.yaml`, then remove the retired public key from `trust/`.
Update `dev_roots` when rotating development identities. The new list preserves
revoked IDs and advances the version; a verifier's cached old issuer is used
only for its version floor, never restored to live warrant trust.

For holder rotation, create a new agent identity, issue to its public key,
update the runtime key selection and deliver the new grants. Revoke known old
warrant IDs explicitly. Rotating a key does not revoke unknown grants elsewhere;
they remain bounded by their signed expiry and the verifiers' revocation data.

## Session attachments

For a session-based agent, issuance and attachment are different operations.
Sessions belong to the integration, so the integration's CLI manages them; for
Hermes that's `hermes-tenuo session attach|list|show|detach` (see hermes-tenuo).
Code uses `tenuo.local.attach`, `detach`, `read_session` and `list_sessions`.

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
when the operator publishes changes by atomic replacement.

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
prove a complete history. Calls in one process form one chain; each process
or restart starts a new one, and `verify` reports how many (`chains`). A missing
chain or a removed tail can't be detected from that file alone. Receipts commit to arguments; they do not include all raw arguments
or prove that an allowed effect completed. Use the integration's log or tool
result for detailed arguments and the denial message.
