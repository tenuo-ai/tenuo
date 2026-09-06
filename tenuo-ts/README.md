# Tenuo TypeScript SDK

Tenuo gives AI agents narrowly scoped, cryptographically verifiable authority to
call tools. The TypeScript SDK wraps ordinary tool functions and asks the Tenuo
Rust core, compiled to WebAssembly, whether each call is allowed before the
function can run.

The current beta requires Node.js 20 or newer and supports Node.js servers. This
version does not support browsers, edge runtimes, or Cloudflare Workers.

Run the SDK with a control plane you operate, or pair it with
[Tenuo Cloud](#where-tenuo-cloud-fits) for managed warrant issuance, approvals,
revocation, and audit operations. Authorization decisions stay local in either
model.

- [Install](#install)
- [Protect your first tool](#protect-your-first-tool)
- [Mental model](#mental-model)
- [Production setup](#production-setup)
- [Production patterns](#production-patterns)
- [Where Tenuo Cloud fits](#where-tenuo-cloud-fits)
- [Authorization outcomes](#handle-authorization-outcomes)
- [Receipts and revocation](#receipts-and-revocation)
- [MCP](#mcp)
- [Develop the SDK](#develop-the-sdk)
- [Security boundaries](#security-boundaries)

## Install

Install the core package from the npm `beta` tag:

```bash
npm install @tenuo/core@beta
```

For an MCP server using the official v2 SDK, also install the adapter and its
peer dependency:

```bash
npm install @tenuo/mcp@beta @modelcontextprotocol/server
```

## Protect your first tool

This example creates a development issuer, protects a file-reading function,
and gives a session access to files under `/data`.

Set `NODE_ENV=development` before running it. Development roots are intentionally
disabled when `NODE_ENV` is unset or set to production.

```ts
import {
  AuthorizationDeniedError,
  createTenuo,
  under,
} from "@tenuo/core";

const tenuo = createTenuo({ root: createTenuo.devRoot() });

const readFile = tenuo.tool(
  {
    execute: async ({ path }: { path: string }) => `contents of ${path}`,
  },
  {
    capability: "read_file",
    allow: { path: under("/data") },
  },
);

const session = tenuo.session({ tools: [readFile] });

const contents = await tenuo.withSession(session, () =>
  readFile.execute({ path: "/data/q3.pdf" }),
);

console.log(contents);

try {
  await tenuo.withSession(session, () =>
    readFile.execute({ path: "/etc/passwd" }),
  );
} catch (error) {
  if (error instanceof AuthorizationDeniedError) {
    console.error(error.code, error.field);
  } else {
    throw error;
  }
}
```

The first call runs. The second is rejected with
`TENUO_CONSTRAINT_VIOLATION`; the original `execute` function is never called.

You can also pass a session explicitly when ambient session context is not a
good fit:

```ts
await readFile.execute(
  { path: "/data/q3.pdf" },
  { session },
);
```

## Mental model

Every protected call has three relevant inputs:

1. The host schema decides whether the arguments are structurally valid.
2. The tool policy defines the host's maximum allowed behavior.
3. The session warrant defines what this agent has been delegated.

The Rust core evaluates the intersection of the tool policy and the session.
TypeScript does not make the authorization decision, and schemas such as Zod
are never treated as authorization policy.

```text
valid arguments + tool ceiling + session authority
                         |
                         v
                 Rust authorization
                    /          \
                 allow         deny
                   |             |
             execute runs   execute never runs
```

### Policies are fail-closed

A non-empty `allow` policy is zero-trust: every argument in the call must be
named in the policy. For example, this policy:

```ts
{ path: under("/data") }
```

rejects `{ path: "/data/a.txt", encoding: "utf8" }` until `encoding` is also
covered, for example with `pattern("*")`, or removed from the call.

An empty tool policy, `allow: {}`, adds no host ceiling. The session warrant
still applies; it does not mean “allow everything.”

### Sessions carry delegated authority

`session({ tools })` builds the session policy from protected tools, so the
capability map does not have to be written twice:

```ts
const session = tenuo.session({ tools: [readFile] });
```

You can also define the capability map directly:

```ts
const session = tenuo.session({
  allow: {
    read_file: { path: under("/data") },
  },
  ttlSeconds: 15 * 60,
});
```

Narrowing creates a child session with less authority. It cannot widen the
parent:

```ts
const reports = tenuo.narrow(session, {
  path: under("/data/reports"),
});
```

To hand that narrower authority to a different agent, bind the child to that
agent's key. See [Delegate to another agent](#delegate-to-another-agent).

## Production setup

Development puts issuance and enforcement in one process. Production separates
them:

```text
Control plane                 Agent process
-------------                 -------------
holds the issuer key          holds its own holder key
issues short-lived warrants   receives a warrant for the task
publishes revocations         verifies locally before tools run
collects receipts             emits signed decision receipts
```

The issuer key is the root of authority and should stay in a dedicated control
plane or signing service. Each agent has a different holder key. The control
plane binds a warrant to the agent's public key; the agent combines that warrant
with its private holder key to prove possession on each call.

The agent process needs three production inputs:

- The control plane's trusted public key.
- A short-lived warrant scoped to the current task.
- The agent's holder key, loaded locally from protected key storage and never
  sent with the warrant.

Do not use a development root in production. Construct a verifier from the
trusted public key, then import each issued warrant with the local holder key:

```ts
import { createTenuo } from "@tenuo/core";

type Task = {
  id: string;
  tenuoWarrant: string | readonly string[];
  reportPath: string;
};

const tenuo = createTenuo({
  trustedRoots: [
    createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY"),
  ],
});

// Load the worker's key from its local secret provider, not from the task.
const holderKey = createTenuo.holderKeyFromEnv("TENUO_HOLDER_SECRET");

async function handleTask(task: Task) {
  const session = tenuo.sessionFromWire({
    warrant: task.tenuoWarrant,
    holderKey,
  });

  return tenuo.withSession(session, () =>
    readFile.execute({ path: task.reportPath }, {
      requestId: task.id,
      onReceipt: enqueueReceipt,
    }),
  );
}
```

Authorization still happens locally in the Rust core. The agent does not call
the control plane for every tool invocation, so an issuance-service outage does
not turn into an allow decision or silently bypass enforcement.

`createTenuo.devRoot()` only works when `NODE_ENV` is `development` or `test`,
when `TENUO_ALLOW_DEV=1`, or when the caller explicitly opts in with
`devRoot({ allowInProduction: true })`. The last two options are escape hatches
for controlled development environments, not production configuration.

## Production patterns

### Issue authority per task

The recommended pattern is to request or receive a fresh, narrowly scoped
warrant when a task starts. Give it only the tools, argument constraints, and
lifetime required by that task. Import it at the agent boundary and let it
expire when the task is over.

Avoid one broad warrant stored in a process-wide singleton. Long-lived ambient
authority makes unrelated jobs share the same permissions and weakens the
value of task-level audit trails.

### Narrow before a smaller unit of work

Use `tenuo.narrow()` when a planner or orchestrator hands a smaller job to code
running under the same holder identity:

```ts
const reportSession = tenuo.narrow(taskSession, {
  read_file: { path: under("/data/reports") },
});

await tenuo.withSession(reportSession, runReportAgent);
```

The child can remove tools and tighten argument constraints; it cannot widen
the parent, and it never outlives the parent warrant.
`toWire()` exports only the warrant chain. It never exports the holder secret.

### Delegate to another agent

When the smaller job runs under a different agent, with its own key, pass that
agent's public key as the holder. The current holder signs the child; the child
belongs to the next agent. Every agent generates its own holder key once and
shares only the public half:

```ts
// In each agent's process, once. The secret never leaves it.
const holderKey = createTenuo.generateHolderKey();
const publicKey = createTenuo.publicKeyFromHolderKey(holderKey);
```

```ts
// Orchestrator: narrow and rebind. `handed` cannot authorize here — it has no
// holder secret — but it can be exported and sent.
const handed = tenuo.narrow(
  taskSession,
  { read_file: { path: under("/data/reports") } },
  { holder: workerPublicKey, ttlSeconds: 5 * 60 },
);
sendToWorker(handed.toWire());

// Worker: import with its own key, then use it like any session.
const mine = tenuo.sessionFromWire({ warrant: received, holderKey });
await tenuo.withSession(mine, runReportAgent);
```

Two checks make this a handoff of *less* authority rather than a shared
credential:

- Core rejects the child at `narrow()` time, before a token exists, if it names
  a tool the parent lacks, widens a constraint, outlives the parent, or exceeds
  the depth ceiling. The error carries `TENUO_CHAIN_INVALID` (or
  `TENUO_DEPTH_EXCEEDED`).
- A copied chain is not authority. `sessionFromWire()` with any other holder key
  fails with `TENUO_INVALID_POP`, and a server verifying the proof-of-possession
  fails the same way.

### Limit how far authority travels

A delegator can mark what it hands on as the end of the line, and the root can
cap the whole chain. Neither can be undone by anyone below:

```ts
// The worker may use this; it may not hand it to anyone.
const handed = tenuo.narrow(taskSession, allow, { holder: workerPublicKey, terminal: true });

// Issued authority may be delegated at most twice below the root.
const root = tenuo.session({ allow, holder: orchestratorPublicKey, maxDepth: 2 });
```

A holder that tries to narrow a terminal session gets `TENUO_DEPTH_EXCEEDED`.
An intermediate can lower `maxDepth` for its children and cannot raise it.

### Issue directly to an agent from a control plane

A development issuer can bind a fresh session to another agent's key. Agents
trust the issuer's public key and nothing else, so a warrant any agent mints for
itself is rejected as `TENUO_UNTRUSTED_ROOT` before a single constraint is
checked:

```ts
const controlPlane = createTenuo({ root: createTenuo.devRoot() });
const root = controlPlane.issuerPublicKey();

const agent = createTenuo({ trustedRoots: [root] });

const issued = controlPlane.session({
  allow: { read_file: { path: under("/data") } },
  holder: agentPublicKey,
  ttlSeconds: 30 * 60,
});
sendToAgent(issued.toWire());
```

`issuerPublicKey()` is a public key. Sharing it grants nothing.

### Inspect a session

`session.inspect()` reports the leaf's holder public key, depth, ceiling,
lifetime, tools, and whether this process can authorize with it. It never
includes the holder secret. Use it for audit views and to explain a denial:

```ts
const info = handed.inspect();
// { kind, holderPublicKey, rootPublicKey, depth: 1, maxDepth, terminal, expiresAt,
//   tools: ["read_file"], warrantIds: [...], canAuthorize: false,
//   clearance?, sessionId?, agentId?, requiredApprovers?, minApprovals?, approvalGatedTools }
```

### Explain a decision

`tenuo.explain(session, tool, args)` reports what the session would decide,
field by field, without running the tool and without signing
proof-of-possession, so it works on a session issued to someone else:

```ts
const why = tenuo.explain(session, "read_file", { path: "/etc/passwd", mode: "r" });
// { outcome: "deny", code: "TENUO_CONSTRAINT_VIOLATION", field: "path",
//   toolGranted: true, chainValid: true, expired: false,
//   fields: [{ field: "path", kind: "Subpath", satisfied: false, value: "/etc/passwd", reason: "..." },
//            { field: "mode", kind: "OneOf", satisfied: true, value: "r" }],
//   unknownFields: [], missingFields: [] }
```

### Run a control plane in Node

A stable issuer key makes this process the root of authority. It trusts its
own key plus any `trustedRoots`, works outside `NODE_ENV=development`, and
its public key is what agents put in their `trustedRoots`:

```ts
const controlPlane = createTenuo({
  root: createTenuo.issuerKeyFromEnv("TENUO_ISSUER_SECRET"),
});
const root = controlPlane.issuerPublicKey();

const issued = controlPlane.session({
  allow: { read_file: { path: under("/data") } },
  holder: agentPublicKey,
  ttlSeconds: 30 * 60,
  clearance: "internal",
  sessionId: "task-42",
  agentId: "report-worker",
});
```

Generate a key once with `createTenuo.generateIssuerKey()` and keep the hex in
a secret store. Never put it in an agent process.

### Delegate the right to issue

An issuer session cannot call tools. Its holder can mint execution sessions
for the tools in `issuableTools`, inside `constraintBounds`, without ever
holding the root key. Core checks every issued session against those bounds:

```ts
// Control plane, once per orchestrator.
const issuer = controlPlane.session({
  kind: "issuer",
  issuableTools: ["read_file", "search"],
  constraintBounds: { path: under("/data") },
  maxIssueDepth: 2,
  holder: orchestratorPublicKey,
  ttlSeconds: 8 * 3600,
});

// Orchestrator, per task. No root key in this process.
const worker = tenuo.issue(mine, {
  allow: { read_file: { path: under("/data/reports") } },
  holder: workerPublicKey,
  ttlSeconds: 300,
});
```

Issuing `delete_file`, or `path: under("/")`, fails with `TENUO_CHAIN_INVALID`.

### The full constraint set

Every constraint is evaluated in the Rust core and attenuates monotonically.

| Helper | Meaning |
|---|---|
| `under(root, { caseSensitive?, allowEqual? })` | Path inside a directory, traversal-safe |
| `pattern(glob)`, `regex(source)` | String shape |
| `exact(value)`, `oneOf(values)`, `notOneOf(values)` | Value sets |
| `max(n)`, `min(n)`, `range({ min, max, minExclusive?, maxExclusive? })` | Numeric bounds |
| `email({ domain })` | Address on a domain |
| `cidr("10.0.0.0/8")` | IP inside a network |
| `urlPattern("https://*.example.com/api/*")` | URL glob, parsed as a URL |
| `urlSafe({ schemes?, allowDomains?, denyDomains? })` | SSRF-aware URL check; private and link-local hosts rejected |
| `shlex(["ls", "cat"])` | Shell command whose first word is allowed, parsed with shell quoting |
| `contains(values)`, `subset(values)` | List arguments |
| `anyOf([...])`, `all([...])`, `not(c)` | Composition; `not` cannot be narrowed further, prefer `notOneOf` |
| `wildcard()` | Any value; names an argument in a zero-trust policy without constraining it |
| `cel("value < 10000")` | Common Expression Language over the value |

Every named field is required. `wildcard()` admits any value, not the absence
of one.

### Approvals end to end

Gate a tool, or only some of its arguments, on signed human approval:

```ts
const session = tenuo.session({
  allow: { transfer: { amount: max(100_000) } },
  requireApproval: {
    approvers: [financePublicKey, cfoPublicKey],
    min: 1,
    gates: {
      transfer: {
        message: "Transfers of 1,000 or more need sign-off",
        args: { amount: { when: min(1000) } },   // or "all", or { exempt: c }
      },
    },
  },
});
```

When a gate fires, `execute` throws `ApprovalRequiredError` whose `request`
is what an approval service needs. The approver signs the request hash and
never sees the warrant or the holder key; the approval binds the exact call:

```ts
try {
  await transfer.execute({ amount: 5000 }, { session });
} catch (error) {
  if (error instanceof ApprovalRequiredError && error.request) {
    const body = createTenuo.controlPlaneApprovalRequestV1(error.request, {
      attestation: tenuo.attestApprovalRequest(session, "transfer", { amount: 5000 }),
    });
    const response = await postToApprovalService(body);            // same v1 shape the Python SDK sends
    const approvals = createTenuo.signedApprovalsFromResponseV1(response);
    await transfer.execute({ amount: 5000 }, { session, approvals });
  }
}

// An approver service, anywhere:
const envelope = createTenuo.signApproval(request, approverSecret, { externalId: "cfo@example.com" });
createTenuo.inspectApproval(envelope); // { approverPublicKey, requestHash, externalId, expiresAt, signatureValid }
```

Delegation can add approvers and raise the threshold with
`narrow(session, allow, { addApprovers, minApprovals })`; it can never remove
or lower them.

### Revocation lists

An issuer signs a list of warrant ids; verifiers load it and refuse those
chains from then on:

```ts
const list = controlPlane.revocationList({ revoke: [warrantId], version: 2 });
createTenuo.inspectRevocationList(list); // { version, issuedAt, issuerPublicKey, revokedIds, signatureValid }

agent.revoke(list);            // now TENUO_REVOKED for that chain
```

`createTenuo.signRevocationList(input, issuerSecret)` does the same with an
explicit secret. Version numbers only go up.

### Present authority across any boundary

`mcp.attach()` and `mcp.verify()` are one instance of a general pattern:
authorize locally, send the chain plus a proof-of-possession, verify at the
other side. The same pair works over HTTP, a queue, or a workflow engine:

```ts
// Caller
const presented = tenuo.present(session, "read_file", { path: "/data/q3.pdf" });
await fetch(url, { method: "POST", body: JSON.stringify({ args, presented }) });

// Service, trusting only the root
const args = await service.verify(presented, "read_file", body.args, { allow: { path: under("/data") } });
```

Tampered arguments fail `TENUO_INVALID_POP`; the host ceiling in `allow`
applies on top of the warrant.

### Enforce again at service boundaries

Local protection stops an agent from calling an in-process tool outside its
warrant. When the tool lives in another service, send the warrant and
proof-of-possession with the request and verify them again at that service.
`tenuo.mcp.attach()` and `@tenuo/mcp` implement this pattern for MCP.

The receiving service is an enforcement point: it has trusted issuer public
keys and its own immutable tool ceiling, but it does not receive the caller's
holder secret.

### Treat revocation, approvals, and receipts as control-plane flows

- Distribute newer signed revocation lists to long-running enforcement
  processes and load them with `tenuo.revoke()`.
- For replay-sensitive or approval-gated MCP actions, use a shared production
  `NonceStore`; the in-memory store only protects one process.
- Route `ApprovalRequiredError` to an approval service and retry only with the
  resulting signed approval envelopes.
- Send receipts to a durable queue or collector. Keep receipt hooks lightweight;
  they are evidence callbacks, not authorization hooks.
- On missing, expired, revoked, or invalid authority, fail the task. Do not fall
  back to an unprotected tool call.

### Production checklist

- [ ] Root issuer keys live outside agent processes.
- [ ] Every agent has its own holder identity and protected key storage.
- [ ] Every enforcement point has an explicit trusted-root set.
- [ ] Warrants are scoped per task and use short lifetimes.
- [ ] Remote tool boundaries verify the warrant and proof-of-possession.
- [ ] Signed revocation lists are refreshed and applied.
- [ ] Approval-gated or replay-sensitive actions use a shared nonce store.
- [ ] Receipts carry a request ID and reach durable storage.
- [ ] Missing issuance or approval inputs fail closed; there is no unprotected
      fallback.
- [ ] `devRoot()` and `TENUO_ALLOW_DEV` are absent from production manifests.

## Where Tenuo Cloud fits

`@tenuo/core` implements the open protocol and local enforcement path. It can be
run entirely with infrastructure and keys you manage; no Tenuo Cloud account is
required.

[Tenuo Cloud](https://cloud.tenuo.ai) is the optional managed control plane for
teams that do not want to build the operational layer around that enforcement:

- Agent and service-account registration
- Policy and short-lived warrant issuance
- Root-key management and rotation
- Signed revocation-list distribution
- Human approval routing
- Receipt collection and searchable audit history

The authorization decision remains local: Cloud manages and observes authority,
while the Rust core enforces it next to the tool. That preserves fail-closed,
offline verification on the call path.

Tenuo Cloud is currently in early access and beta. The current TypeScript
packages do not include a dedicated Cloud client, but they can consume warrants,
revocation lists, and signed approvals obtained through the Cloud REST API or
your own control plane.

**[Request early access](https://tenuo.ai/early-access.html)** or read the
**[Tenuo Cloud documentation](https://docs.tenuo.ai)**.

## Handle authorization outcomes

Tenuo distinguishes hard denials from calls that could proceed after receiving
signed approvals:

```ts
import {
  ApprovalRequiredError,
  AuthorizationDeniedError,
} from "@tenuo/core";

try {
  await protectedTool.execute(args, { session });
} catch (error) {
  if (error instanceof ApprovalRequiredError) {
    console.log(error.tool, error.required, error.received);
  } else if (error instanceof AuthorizationDeniedError) {
    console.log(error.code, error.field);
  } else {
    throw error;
  }
}
```

| Outcome | Does `execute` run? | SDK behavior |
|---|---:|---|
| Allowed | Yes, with normalized arguments | Returns the tool result |
| Denied | No | Throws `AuthorizationDeniedError` |
| Approval required | No | Throws `ApprovalRequiredError` |

An approval is a signed Tenuo approval envelope. A boolean such as
`userApproved: true` is not authorization evidence.

## Receipts and revocation

Use `onReceipt` to persist signed evidence of an authorization decision, and
load signed revocation lists when previously issued authority must stop working:

```ts
const tenuo = createTenuo({
  trustedRoots: [
    createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY"),
  ],
  revocationList: process.env.TENUO_SRL,
});

tenuo.revoke(updatedRevocationList);

await readFile.execute(
  { path: "/data/q3.pdf" },
  {
    session,
    requestId: "request-42",
    onReceipt: (receipt) => persist(receipt),
  },
);
```

Receipts are evidence, not permission: verifying a receipt does not authorize a
new call. Receipt-hook exceptions are isolated and never change the decision or
prevent an allowed tool from running.

Verify them anywhere:

```ts
createTenuo.verifyReceipt(receipt);
// { authentic: true, signerKey, outcome, action, requestId, requestHash?, srlHash?, ... }
createTenuo.verifyReceiptChain(receipt, [rootPublicKey]);
// { chainValid, outcome, decisionCode?, rootIssuer?, leafHolder?, corroboratesDenial? }
```

The first checks the enforcement point's signature. The second checks the
embedded warrant chain against roots you trust, at the receipt's own decision
instant, and needs no trust in the signer.

## MCP

For MCP, the client attaches the warrant and a proof-of-possession to
`_meta.tenuo`. The server verifies that envelope before invoking the tool
handler.

Client:

```ts
const call = tenuo.mcp.attach(
  session,
  "read_file",
  { path: "/data/q3.pdf" },
);

await mcpClient.callTool({
  name: call.name,
  arguments: call.arguments,
  _meta: call._meta,
});
```

Official v2 server:

```ts
import { McpServer } from "@modelcontextprotocol/server";
import { createTenuo, under } from "@tenuo/core";
import { guardTools } from "@tenuo/mcp";
import { z } from "zod";

const tenuo = createTenuo({
  trustedRoots: [
    createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY"),
  ],
});

const server = new McpServer({ name: "reports", version: "1.0.0" });
const tools = guardTools(tenuo, server);

tools.register(
  "read_file",
  {
    description: "Read a file",
    inputSchema: z.object({ path: z.string() }),
    allow: { path: under("/data") },
  },
  async ({ path }) => ({
    content: [{ type: "text", text: await readFileFromDisk(path) }],
  }),
);
```

`attach()` authorizes locally before sending the call. `verify()` or the guarded
handler is the enforcement point on the server. The server needs trusted public
keys, never the client's holder secret.

Proof-of-possession v1 is replayable within its validity window unless a nonce
store is configured. Use `memoryNonceStore()` for one-process deployments or
provide an async `NonceStore` backed by shared storage. A nonce-store failure
fails closed.

See the [`@tenuo/mcp` README](packages/mcp/README.md) for handler behavior,
error mapping, and replay protection. A complete multi-agent scenario lives in
[`packages/core/examples/mcp`](packages/core/examples/mcp/README.md).

## Packages and compatibility

| Package | Purpose |
|---|---|
| `@tenuo/core` | Protected tools, sessions, constraints, receipts, revocation, and framework-free MCP wire helpers |
| `@tenuo/mcp` | Adapter for the official `@modelcontextprotocol/server` v2 package |

The SDK currently has no supported Vercel AI SDK, Mastra, FastMCP, browser, or
edge-runtime adapter. `tenuo.tool()` can wrap any object with an `execute`
function, but compatibility with a framework is not a supported integration
until it has an adapter and integration tests.

For the legacy `@modelcontextprotocol/sdk` v1 API, use the maintained recipe in
[`packages/core/examples/mcp/host.ts`](packages/core/examples/mcp/host.ts).

## Develop the SDK

See the repository's
[TypeScript contributor workflow](../CONTRIBUTING.md#typescript-and-javascript-sdk)
for installation, focused tests, examples, Node.js WASM rebuilding, and package
smoke tests. That contributor guide is the canonical source for development
commands.

Publishing is performed by the GitHub Actions release workflow so npm can
attach provenance. Both TypeScript packages remain on the `beta` dist-tag until
their public APIs are declared stable.

## Security boundaries

The following are deliberate design constraints:

- The original tool implementation never runs before an allow decision.
- Rust/WASM makes authorization decisions; TypeScript adapters do not recreate
  the policy engine.
- Host schemas validate data but do not grant authority.
- Hooks, tool filtering, and dry-run or audit-only modes are not security
  boundaries.
- Signing keys are not placed on request context.
- Tests use the real authorizer rather than a permissive mock.

For protocol details and security guidance, see the repository's
[`docs/spec`](../docs/spec/README.md) and [`docs/security.md`](../docs/security.md).
