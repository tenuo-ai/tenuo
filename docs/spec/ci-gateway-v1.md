# Tenuo for GitHub Actions (v1)

**Status:** Draft for implementation
**Product:** Tenuo for GitHub Actions — task-scoped warrants for agents in CI
**Audience:** Contributors building the open-source package; the Cloud team, for the contract in section 9
**Scope:** The open-source product a platform team deploys next to its runners. Cloud is an optional control-plane upgrade. This document is the path to that product, not only the target architecture.

This is an implementation specification, not a protocol specification. Wire formats, receipt encoding, and verification algorithms are normative in [protocol-spec-v1.md](protocol-spec-v1.md), [wire-format-v1.md](wire-format-v1.md), and [receipt-v1.md](receipt-v1.md). This document specifies the components that carry those primitives into GitHub Actions, the invariants a deployment must satisfy, and the build sequence that produces a shippable package.

The protocol is not the blocker. Warrants, proof of possession, monotonicity, receipts, and generic MCP verification already exist in `tenuo` / `tenuo-python`. What this document specifies is the product those primitives are not yet packaged as.

---

## 1. Product

### 1.1 What ships

One public repo, one version, one `uses:` line.

| Surface | Name |
|---|---|
| Product | Tenuo for GitHub Actions |
| Repo | `tenuo-ai/github-actions` |
| Marketplace action | `tenuo-ai/github-actions@v1` |
| Image | `ghcr.io/tenuo-ai/github-actions` |
| Chart | `oci://ghcr.io/tenuo-ai/charts/tenuo-github-actions` |
| GitHub App | Tenuo (org install; manifest in the repo) |

The action tag, image tag, chart version, and holder/shim binary are the same semver. The action pins the image digest for that tag. Buyers never pin SDK × binary × image themselves.

Until the product repo is cut, the package lives in-tree at `tenuo-ai/tenuo/github-actions`. Protocol and SDK work stay in `tenuo` / `tenuo-python`. v1 still ships as `tenuo-ai/github-actions` with a published `tenuo` wheel, pinned. GitHub-specific components do not land in the core CLI or next to `charts/tenuo-authorizer` (a different product: an HTTP sidecar).

```text
tenuo-ai/tenuo/github-actions   # in-tree until the product repo is cut
  action.yml
  index.mjs / cleanup.mjs       # JavaScript wrapper + post step
  tenuo_gha/                    # exchange, gateway, holder, shim, action
  requirements.lock             # hashed third-party pins for the JavaScript action
```

v1 ship form (unchanged contract, different packaging): one public repo, one semver, `uses: tenuo-ai/github-actions@v1`, image + chart + a digest-pinned holder/shim binary or zipapp. The socket protocol does not change when that binary replaces `python -m tenuo_gha`.

There is no `tenuo-broker` PyPI package, no `tenuo issue-run` on the core CLI, and no `tenuo-ai/setup` action name.

### 1.2 Who deploys it

| Role | What they do |
|---|---|
| Platform | Install the GitHub App, `helm install` the chart with two workload identities, allowlist the action by SHA, set `TENUO_GATEWAY_URL`, `TENUO_EXCHANGE_URL`, `TENUO_EXCHANGE_AUDIENCE`, and `TENUO_TRUSTED_ROOTS` |
| App team | Add the action and point the existing agent action at `mcp_config` |
| Security | Review App permissions, custody profile (`kms` / I10 recommended, `secret` supported), containment check |

A typical app team does not stand up a gateway. Per-job Docker that starts a gateway on the runner is not part of v1. It cannot satisfy I10 and it is not an enterprise install.

### 1.3 What the buyer types

```yaml
permissions:
  id-token: write
  contents: none
  issues: none
  pull-requests: none

steps:
  - uses: tenuo-ai/tenuo/github-actions@<sha>   # pin a commit until v1 is tagged
    id: tenuo
    with:
      gateway_url: ${{ vars.TENUO_GATEWAY_URL }}
      exchange_url: ${{ vars.TENUO_EXCHANGE_URL }}
      audience: ${{ vars.TENUO_EXCHANGE_AUDIENCE }}
      trusted_roots: ${{ vars.TENUO_TRUSTED_ROOTS }}

  - uses: anthropics/claude-code-action@<sha>
    with:
      mcp_config: ${{ steps.tenuo.outputs.mcp_config }}
```

Customer-gateway configuration is these four fields. `gateway_url` is the customer box (never Cloud). `exchange_url` is Cloud or the self-hosted exchange. `audience` is `exchange.audience`, or Cloud `tenuo:org/<tenant>`. `trusted_roots` are deploy-time keys: the action checks advertised `root_public_keys` against them; the gateway `trust.root_public_keys` is the Authorizer trust anchor. A run-provided root is never installed.

`task` is inferred from the event (`issues` / `issue_comment` → `github.get_issue`, `github.list_issue_comments`, `github.add_comment` bound to that issue). A YAML capability block is a power-user input, not the onboarding path.

### 1.4 Goals

- A hijacked agent can act only on the triggering object, with the tools the warrant names, for the life of the job.
- The credential that reaches GitHub never enters the runner. No private key or token is at rest in the job (I1, I4).
- Every decision produces a signed receipt that verifies offline.
- A platform team deploys once; every workflow in the org uses the same gateway.
- A containment check replays the incident-shaped attacks and reports what was refused, including the custody profile.
- The open-source package is complete without Cloud. Cloud is an upgrade for hosted issuance, org-wide receipt ingest, revocation push, and denial alerting.

### 1.5 Non-goals

- Preventing prompt injection. The package assumes the agent is compromised and bounds what it can do.
- Validating agent output consumed by later shell steps. That is script injection.
- Sandboxing the runner. A runner-level compromise is a different threat.
- Hosting the gateway as a Tenuo service. Cloud stays on the control path (issuance, receipts, revocation) and off the GitHub data path.
- Holding model API keys. A model proxy is out of this package.
- Replacing GitHub safe outputs. The action composes with them: safe outputs remove the write token; the warrant binds the read and the triggering object.

---

## 2. Current state

In-tree at `github-actions/` and `charts/tenuo-github-actions`. The warrant is the program; the gateway is the interpreter. Cloud is issuer / receipts / revocation only.

| Present | Not yet |
|---|---|
| `MCPVerifier`, holder process, stdio shim, action, file receipts | Product repo, Marketplace listing, published image digest |
| Secret-mount App JWT, in-memory installation token, `github-triage` recipes | KMS `Sign` (I10). The image and chart refuse `signing.profile=kms` |
| Self-hosted `/v1/exchange` and Cloud-compatible stack | Cluster custody scan in `github-actions check` |
| Helm chart: two identities, `secret` profile, NetworkPolicy | OCI chart publish, image digest pin, holder/shim binary |
| Concierge compose box + doctor | Distroless image, one wheel pin for action and image |

`tenuo/authorizer` is a different product (HTTP sidecar). Do not reuse it as this gateway.

---

## 3. Threat model and invariants

### 3.1 Assumptions

- **A1.** Untrusted content (issue bodies, pull request text, comments, file contents) reaches the model, and the model may adopt any instruction in it.
- **A2.** The agent process is fully controlled by the attacker after A1. It may call any tool it can see, with any arguments, read its own environment and filesystem, and attempt any network connection.
- **A3.** The runner host is not compromised at the kernel or container-runtime level. The shared-gateway topology is the reason this assumption is acceptable: the GitHub credential is not on the runner.
- **A4.** GitHub's OIDC provider, the gateway's host, and the custody backend are trusted. For `kms` (I10) that backend is the organization's KMS (or Cloud HSM). For `secret` it is the Kubernetes Secret and the secrets manager that syncs it.
- **A5.** Two workload identities. Neither role has the other's signing material. On `kms`, the exchange role is the only principal that may call `kms:Sign` on the issuer key; the gateway role is the only principal that may call `kms:Sign` on the App and receipt keys. On `secret`, the exchange Deployment mounts only the issuer Secret; the gateway Deployment mounts only the App and receipt Secret.

### 3.2 Invariants

Each authorization invariant is testable and is exercised by the containment check (section 7.2). A deployment that violates any of I1–I9 is not a correct deployment. Custody is a profile, not a precondition of a correct deploy: `kms` is recommended and `secret` is supported. I10 is the name of the strict profile.

| ID | Invariant | Enforced by |
|---|---|---|
| **I1** | The agent process holds no credential. No holder key, warrant secret, GitHub token, App key, cloud credential, or model API key is present in its environment, filesystem, or mounted volumes. The shim is not a credential. | Action guardrails; holder process; gateway holds derived GitHub tokens in memory only |
| **I2** | The agent process cannot open a network connection to any host other than the gateway (and the model endpoint the agent action already uses). It cannot reach `api.github.com`. Enforced on ARC and other self-hosted runners that apply a network policy. On GitHub-hosted runners, not enforced: I1 still denies the agent any token; residual risk is exfiltration to arbitrary hosts, which the allowed model endpoint permits anyway. | Runner network policy where one exists; gateway is the only GitHub egress |
| **I3** | No tool call is authorized unless the gateway verified a warrant chain to a trusted root, verified proof of possession by the leaf holder, and found the arguments within the warrant's constraints. The gateway does not apply a second catalog, pack, repository, or tripwire ACL after allow. A name with no HTTP recipe is authorized but cannot execute. | Tenuo MCP verifier in the gateway |
| **I4** | A warrant issued for a run is bound to a key generated in that run, has a TTL not exceeding the job's timeout, and its holder secret never leaves the holder process. It is not written to env, disk, `GITHUB_OUTPUT`, or an artifact. The holder process is started by the action, survives the step boundary, and is not a child of the agent. | Action; holder process + Unix socket; no cross-job key transfer in v1 |
| **I5** | A child warrant is never wider than its parent. Any attempt to derive one fails before signing. | Core monotonicity check |
| **I6** | Every allow and every deny at the gateway produces a signed receipt, chained, verifiable offline with `tenuo receipt verify` against the trusted public keys. | Gateway receipt emitter |
| **I7** | The gateway's trust anchor is configured at deploy time, never accepted from a run. | Gateway config; chart values |
| **I8** | Issuance verifies the run's OIDC token (signature, issuer, audience, expiry, repository and owner by numeric id, workflow ref pinned to a branch) before minting. | Exchange `/v1/exchange` or Cloud exchange |
| **I9** | On any failure to obtain, verify, or transport authority, the job fails closed with a message naming the fix. No fallback to a broader credential exists anywhere in the path. | All components |
| **I10** | The `kms` custody profile. No process in the deploy has a long-lived credential on its filesystem, in its environment, or in the cluster secret store. Root and receipt keys are generated in KMS (or Cloud HSM). The App key is imported once and the PEM destroyed. GitHub authentication is an installation token minted in memory from a KMS-signed App JWT. Warrant and receipt signatures are KMS. A config that supplies a PEM, a PAT, or `GITHUB_TOKEN` is a startup error. | Chart; exchange and gateway startup; containment check |

Ephemeral material in RAM is allowed on every profile: the holder private key (holder process, job-scoped), the OIDC JWT (minutes), the installation token (≤ 1 hour, repo-scoped). Those are not stored secrets if they are never written and cannot outlive the process or the TTL. Under A2 the agent can still request envelopes from the holder process, which is no worse than holding the key; the warrant bounds those requests either way. The holder process exists so the key cannot be ptraced from the agent and cannot be taken off the runner.

### 3.3 Custody profiles

I1–I9 do not depend on which profile is selected. Both refuse a PAT, `GITHUB_TOKEN`, or a private key in the environment or the ConfigMap. Both mint installation tokens in memory and never log key material. A file-on-disk key outside the profile's allowed location is a startup error on both.

| Profile | Status | What it is |
|---|---|---|
| **`kms`** | Recommended. This is **I10**. | Root and receipt keys generated in KMS (or Cloud HSM). App key imported, PEM destroyed. Nothing at rest in the cluster. Signatures are `kms:Sign`; key bytes are never loaded. |
| **`secret`** | Supported. Not I10. | Keys live in a Kubernetes Secret, ideally synced from a secrets manager the team already runs. Each role loads its keys at start from that mount, never logs them, and refuses to run if a private key appears as a file on disk outside the Secret mount. |

`secret` is for teams that already operate External Secrets, Vault Agent, or Secrets Store CSI and are not ready to grant `kms:Sign` to the chart's ServiceAccounts. It is a correct supported deploy. It is not the strict profile.

---

## 4. Architecture

### 4.1 Components

| Component | Form | Responsibility |
|---|---|---|
| **Exchange** | Same image, `ROLE=exchange` | `POST /v1/exchange` (OIDC → warrant). Signs only with the issuer key. No GitHub API, no App key, no receipt key. |
| **Gateway** | Same image, `ROLE=gateway` | Interpret the warrant; signed App JWT → installation token; execute GitHub API; emit receipts. Signs only with the App and receipt keys. |
| **Holder + shim** | Static binary, two modes, release asset of the same version | Holder process keeps warrant + holder key behind a Unix socket. Shim is stdio MCP: forwards `tools/call` to the socket, never sees the secret. |
| **Action** | `tenuo-ai/github-actions@v1` | Guardrails; OIDC; exchange; start holder process; write `mcp_config` that launches the shim; job summary; post-job teardown |
| **Containment check** | `github-actions check` in the image | Incident-shaped attacks + custody-profile scans; I2 fail on ARC, report-only on hosted |
| **Helm chart** | `charts/tenuo-github-actions` | Two Deployments, two ServiceAccounts, beside ARC; `kms` has no key Secrets; `secret` mounts a per-role Secret |
| **Catalog** | Declarative YAML in the image | `github-triage` in v1; `github-review` next; `github-fix` later |

### 4.2 Topology (v1 is shared gateway only)

```text
job   permissions: id-token: write
  │
  │  1. OIDC JWT (audience = exchange, or Cloud)
  │  2. holder keypair in the holder process (not a child of the agent)
  │
  ├─ POST /v1/exchange  ──►  exchange         (or Cloud; same body)
  │     Bearer: OIDC
  │     body: holder pubkey + task
  │                          verify OIDC against GitHub JWKS
  │                          KMS-sign the run warrant (issuer key only)
  │
  action starts holder process (daemonized; reparented to init)
  mcp_config → shim (stdio) ── Unix socket ──► holder
                                                 derive leaf, sign PoP
       shim  ── HTTPS ──►  gateway  ──►  api.github.com
                            verify chain + PoP
                            KMS-sign App JWT (App key only)
                            mint installation token (RAM, this repo)
                            emit receipt (receipt key only)
```

The credential never touches a runner. Authority is the warrant. Receipts leave from one place.

A second job that needs authority does its own OIDC exchange. v1 does not transfer holder keys across jobs.

### 4.3 Authority model

The warrant is the program. The gateway is the interpreter. A local catalog, pack list, tripwire table, or repository list after allow is a second policy in the box and is not authorization.

Cloud templates (for example "Issue triage") expand **into the warrant** at issue time. The self-hosted exchange does the same for the inferred issue-triage request (open comment body + digest). The box does not re-enforce those templates after allow. `infer_capabilities` is the job's request, not a hard ceiling.

```text
issuance policy (OIDC identity + Cloud template or requested capabilities)
  └─ run warrant                    the program; issued before the agent reads input
       holder: run-generated key    ttl ≤ job timeout
       tools: named on the warrant  constraints: bound to the triggering object
         └─ per-call terminal leaf  derived by the holder process for each call
              holder: fresh key     ttl: seconds
              constraints: exact arguments of this call
```

Per-call attenuation is the default, not an option. The leaf presented to the gateway authorizes exactly one call with exactly these arguments. The offline monotonicity check catches every widening attempt before a network round-trip. After allow, the gateway does mechanics: mint an installation token, HTTP to `api_url` when a recipe exists, emit a receipt. A name with no path cannot execute; that is not a deny.

### 4.4 Key custody (profiles)

Custody is selected at deploy time. I10 is the `kms` profile. `secret` is supported. The job-side holder key and the in-memory installation token are the same on both.

| Key | `kms` (I10, recommended) | `secret` (supported) |
|---|---|---|
| Root (issuer) private | Customer KMS or Cloud HSM. Generated there. `kms:Sign` from the **exchange** role only; never loaded as bytes. | Exchange Secret only, ideally synced from the team's secrets manager. Loaded at start; never logged. |
| Root public | ConfigMap / org variable. Verify only (both roles). | Same. |
| GitHub App RSA | Customer KMS. PEM imported once, then destroyed. `kms:Sign` of the App JWT from the **gateway** role. | Gateway Secret only. Loaded at start; never logged. |
| Receipt signing | Customer KMS or Cloud HSM. `kms:Sign` from the **gateway** role. | Gateway Secret only. Loaded at start; never logged. |
| Holder | Holder process started by the action. Generated in that process; `mlock` if available; served over a Unix socket; discarded when the process exits. Never an fd across a step, never in the shim or the agent. | Same. |
| Installation token | Gateway memory. Minted per repo, cached until five minutes before expiry, never logged. | Same. |

**`kms`.** Nothing at rest in the cluster. The cluster stores public keys, the GitHub App id, KMS key identifiers, and two ServiceAccounts bound to two cloud roles. GitHub only emits an App PEM; the install procedure is generate, import into KMS, delete the PEM, rotate if that PEM ever touched a laptop. The chart has no `secrets.existingSecret` for keys.

**`secret`.** Keys live in a Kubernetes Secret. The recommended source is a secrets manager the team already runs (External Secrets, Vault Agent, Secrets Store CSI), not a hand-applied manifest. Each role mounts only its Secret at a fixed path. The process loads those files at start, holds the material in memory, and never logs it. A private key as a file on disk outside that mount, in the environment, or in the ConfigMap is a startup error. Inline values (`app_private_key`, `signing_key`, `token`, `token_env`) are a parse error on both profiles.

`signing.profile: memory` exists only for unit tests and requires `TENUO_ALLOW_INSECURE_MEMORY_KEYS=1`. Production images refuse that env. `signing.provider` is not a profile; it is the KMS backend under `signing.profile: kms`.

AWS, GCP, Azure, and Vault Transit all sign Ed25519 and RSA. The gateway's `Sign` callback must emit RFC 8032 Ed25519 (AWS: `ED25519_SHA_512` + `MessageType: RAW`). HashEdDSA / Ed25519ph is a startup error: those signatures will not verify in `tenuo-core`.

---

## 5. Exchange and gateway

One image, two roles. `TENUO_ROLE=exchange|gateway` selects the process. The chart runs two Deployments. A combined process (`TENUO_ROLE=both`) is a test escape only; production images refuse it.

**Runtime.** Python 3.12, FastMCP with `TenuoMiddleware`, the Tenuo Python SDK at the version pinned in the image. Streamable HTTP on port 8000. Non-root, read-only root filesystem, no shell in the final layer.

**Configuration.** One YAML file, mounted read-only. Key material is never inlined. `kms` names KMS objects. `secret` names files under the Secret mount.

```yaml
version: 1
trust:
  root_public_keys: [ "${TENUO_ROOT_PUBLIC_KEY}" ]   # keyring; ≥1 required
  revocation:
    source: control_plane | url | file | none
    refresh_seconds: 60
  clock_tolerance_seconds: 30
  require_pop: true
  replay:
    store: none | memory | redis_iam
    url: "${TENUO_REPLAY_REDIS_URL}"                 # IAM auth only; password in URL is a startup error
signing:
  profile: kms                                       # kms = I10 (recommended); secret = supported; memory = tests only
  kms:
    provider: aws | gcp | azure | vault
    issuer_key_id: "${TENUO_KMS_ISSUER_KEY_ID}"      # exchange role only; gateway refuses this
    receipt_key_id: "${TENUO_KMS_RECEIPT_KEY_ID}"    # gateway role only; exchange refuses this
    github_app_key_id: "${TENUO_KMS_GITHUB_APP_KEY_ID}"  # gateway role only; exchange refuses this
  secret:
    mount: /var/run/secrets/tenuo                    # the only allowed path for private key files
    issuer_key: issuer.pem                           # exchange role only; gateway refuses this
    receipt_key: receipt.pem                         # gateway role only; exchange refuses this
    github_app_key: app.pem                          # gateway role only; exchange refuses this
credentials:
  github:
    provider: app                                    # the only provider
    app_id: "${TENUO_GITHUB_APP_ID}"
    api_url: https://api.github.com                  # GHES: https://github.example.com/api/v3
exchange:
  audience: tenuo:org/acme                           # OIDC audience the job must request
  ttl_max: 15m
ceiling:
  repositories: [ ]                                  # issuance identity (I8); empty = any repo that passes OIDC conditions
tools:
  packs: [ github-triage ]                           # HTTP recipes + MCP registration, not an ACL
receipts:
  sink: file | webhook | control_plane | otlp | both
  path: /state/receipts.jsonl
  webhook_url: "${TENUO_RECEIPT_WEBHOOK_URL}"
limits:
  max_warrant_bytes: 65536
  max_request_bytes: 1048576
  request_timeout_seconds: 20
  rate_limit_per_minute: 600
```

**Endpoints.**

| Path | Served by | Role |
|---|---|---|
| `POST /v1/exchange` | exchange | I8. Verify GitHub OIDC, mint run warrant to the presented holder key, refuse rather than trim |
| `/mcp` | gateway | MCP (streamable HTTP) |
| `/health` | both | Liveness |
| `/ready` | both | Ready only after that role's public keys load, its sign self-test (KMS or Secret-loaded key), and (gateway, if configured) the first revocation fetch |
| `/metrics` | both | OpenTelemetry per [telemetry-otel-v1.md](telemetry-otel-v1.md) |

`POST /v1/exchange` is the same request and response as Cloud (section 9.1). The action does not know which backend signed. Neither process accepts a private key in the body.

Exchange refuses to start if an App or receipt key id or Secret file is configured, or if `credentials.github` is present. Gateway refuses to start if an issuer key id or Secret file is configured. That is how a mis-mounted ConfigMap cannot collapse A5. A `kms` process refuses to start if a key Secret is mounted. A `secret` process refuses to start if a private key file exists outside `signing.secret.mount`.

**OIDC checks (I8).** Signature against GitHub's JWKS (or GHES equivalent), issuer, audience, expiry, `repository_id` and `repository_owner_id` as numeric ids, `job_workflow_ref` pinned to a branch, `event_name`. JWT id cached for its lifetime; reuse is `403 token_reused`. The exchange binds `repository` from the OIDC subject. It does not filter tool names against the local pack list. Cloud templates expand into the warrant at issue time.

**GitHub App provider.** For each mutating or reading call, the gateway signs an App JWT (KMS under I10; Secret-loaded key under `secret`), exchanges it for an installation token scoped to the repository in the request, and caches that token until five minutes before expiry. The token is never written, logged, or returned in a tool result. Provider failure returns an error on the affected tool; there is no fallback credential.

**Tool catalog.** Each tool is a declarative HTTP recipe. Handlers are generated from entries; hand-written handlers exist only for operations that need more than one API call. The catalog is not an allow-list.

```yaml
github.add_comment:
  description: Add a comment to an issue or pull request.
  request:
    method: POST
    path: /repos/{repository}/issues/{issue}/comments
    body: { body: "{body}" }
  arguments:
    repository: { type: string }
    issue:      { type: integer }
    body:       { type: string }
    body_sha256: { type: string, derived: sha256(body) }
  response: { comment_id: id, html_url: html_url }
  mutating: true
```

Rules: `repository` is required on every GitHub tool. Mutating tools with free-text bodies carry a derived digest so a warrant can bind an exact body. A name with no `path` cannot execute (`executed: false`); that is not unauthorized. Containment fixtures (workflow dispatch, workflow file writes, secrets, deploy keys, releases) are tool names with no recipe. They are not registered and not a deny list: authorization is whether the warrant names them.

**Packs.**

| Pack | v1 | Tools |
|---|---|---|
| `github-triage` | Required | `get_issue`, `list_issue_comments`, `add_comment`, `add_labels`, `remove_label`, `close_issue` (`state_reason` one_of) |
| `github-review` | Next minor | `get_pull_request`, `list_pull_request_files`, `get_file_contents` (path prefix, ref), `add_review_comment`, `submit_review` (event one_of, never `APPROVE` by default) |
| `github-fix` | Later | `create_branch` (name pattern), `commit_files` (path prefix, never `.github/`, no override), `create_pull_request` (base one_of, head pattern, draft true by default) |

**Receipts.** Every decision, allow or deny, is emitted through the SDK receipt path, signed via the configured `Sign` callback, chained, and delivered to the configured sink. Emission is non-blocking and never affects the decision. A sink failure is logged and counted, not raised.

**Failure behavior.** Missing public key or the signing material **this role** needs: refuse to start. Sign self-test failure: refuse to become ready. PEM, PAT, or `GITHUB_TOKEN` in the environment: refuse to start on both profiles. A private key file outside the Secret mount: refuse to start (`secret`). A key Secret mounted on a `kms` Deployment: refuse to start (I10). Revocation source unreachable at start: gateway refuses ready. Unreachable later: continue with the last list, warn, refuse to serve if older than `refresh_seconds × 10`.

---

## 6. Holder, shim, and action

The agent action launches whatever `mcp_config` names, in a later step, as a child of the agent. A file descriptor from the Tenuo action does not survive that boundary, and a child of the agent is ptrace-able by the agent under the default Yama scope (`ptrace_scope=1`). Fd inheritance is therefore not the holder design.

### 6.1 Holder process

Today: `python -m tenuo_gha hold` (same module as the shim). The action starts it, daemonized, so it is reparented to init and is not a descendant of the agent. v1: the same two modes as a digest-pinned release asset, not a PyPI package.

**What it holds.** The run warrant and the holder private key, in memory, `mlock`ed when the OS allows. The key is generated in this process. It is never written to env, disk, `GITHUB_OUTPUT`, or an artifact. `TENUO_HOLDER_SECRET` is a startup error.

**How it is reached.** A Unix socket whose path includes the run id so a later job on a persistent runner cannot reuse it. The socket accepts tool-call requests and returns a Tenuo envelope (stack + PoP). It does not accept a request for the raw key. Fd inheritance is not the holder design.

**Behavior on each request.**

1. Build the per-call terminal leaf with exact-argument constraints via core grant (Exact for strings, `Range(n, n)` for integers, Subset for lists). If Exact(body) is not monotonic with the parent, copy the parent's body constraint from the warrant and bind `body_sha256`. If derivation fails, return a denial envelope that still presents the parent so the gateway can emit a signed denial receipt.
2. Sign the proof of possession over that leaf.
3. Return the envelope. Never log arguments or holder material.

**Lifetime.** Started in the action step. The holder exits itself when the warrant expires, so a leftover daemon on a persistent runner does not keep a live key past the TTL. The JavaScript wrapper's post step stops the holder and removes the socket, pid, and mcp_config immediately. A second job does its own holder process. v1 does not transfer holder keys across jobs.

**UID.** Not being a child of the agent is the load-bearing control (default Yama). A dedicated OS user is optional hardening when the job has no `sudo`. Hosted runners often have passwordless `sudo`; then another UID is not a barrier under A2. Do not document a separate user as the reason I4 holds.

### 6.2 Shim

Same module (today) or binary (v1), mode `shim`. This is what `mcp_config` launches: a stdio MCP server, the mechanism every current agent action supports.

**Inputs.** `TENUO_GATEWAY_URL`, `TENUO_HOLDER_SOCKET`, `TENUO_ROOT_PUBLIC_KEY` (local pre-check). No warrant, no holder key, no `TENUO_HOLDER_FD`. `TENUO_HOLDER_SECRET` is a startup error. There is no tool allowlist: the warrant names the tools.

**Behavior.**

1. On start, ask the holder process for the advertised tool set (the names on the warrant). Tools the warrant does not name are not advertised.
2. On `tools/call`, forward arguments to the socket, attach the returned envelope via `SecureMCPClient` (`_meta.tenuo`), and POST to the gateway.
3. Map outcomes: allow → tool result; deny → MCP error with `isError: true` and `DENIED (<TENUO_*>): <reason>`.
4. Log one JSON line to stderr (tool, outcome, code, leaf id). Never log arguments.

The shim is a child of the agent and is therefore untrusted under A2. It must be possible to replace it with any other stdio client that speaks the socket protocol; nothing in the shim is a secret.

### 6.3 Action

**Inputs.**

| Input | Required | Meaning |
|---|---|---|
| `gateway_url` | yes | Customer gateway (MCP). The action never starts a gateway. Never Cloud. |
| `exchange_url` | no | Cloud or self-hosted `POST /v1/exchange`. Omitted: `gateway_url` (single-process tests only). |
| `audience` | no | OIDC audience. Self-hosted `exchange.audience`, or Cloud `tenuo:org/<tenant>`. |
| `trusted_roots` | no | Deploy-time roots. Checks advertised `root_public_keys`. Never the gateway trust anchor. |
| `ttl` | no | Default `900`, capped at the job timeout and the exchange `ttl_max` |

No `issuer_key`, `github_credential`, `model_proxy`, or `cloud_audience` inputs exist. Cloud is selected by pointing `exchange_url` at Cloud and `audience` at `tenuo:org/<tenant>`.

**Outputs.** `mcp_config`, `warrant_id`, `expires_at`, `gateway_url`. The socket path is not an output the later step needs beyond `mcp_config`.

**Steps.**

1. **Guardrails.** Fail if the job's effective permissions include any write scope, if a prior checkout persisted credentials, or if the environment names `GITHUB_TOKEN`, `GH_TOKEN`, `TENUO_*_KEY`, or any `*_API_KEY`. Each message names the line to change.
2. **Identity.** Request the OIDC token with `audience`.
3. **Holder process.** Today: start `python -m tenuo_gha hold` on a socket under `${RUNNER_TEMP}/tenuo/${GITHUB_RUN_ID}`. v1: download the version-pinned binary by digest. Generate the keypair in that process. Register public material with `::add-mask::`. Never write the secret to env, `GITHUB_OUTPUT`, or an artifact. Third-party Python deps, when used, are installed from `requirements.lock` with `--require-hashes`.
4. **Authority.** `POST {exchange}/v1/exchange` (exchange Deployment or Cloud) with the OIDC bearer, holder public key, ttl, and inferred or explicit capabilities. The holder process receives the warrant; the action does not keep it.
5. **Shim config.** Write `mcp-config.json` that execs the same binary in `shim` mode with `TENUO_HOLDER_SOCKET` and `TENUO_GATEWAY_URL`. Export the path.
6. **Summary.** "This run may:" (tools, constraints, TTL, run id) and a blast-radius line: App installation reach vs this warrant.
7. **Post-job.** Stop the holder process, verify the receipt journal (or the webhook echo), append the decision table, delete the config file and the socket. Do not upload holder material.

An org reusable workflow lives at `tenuo-ai/github-actions/.github/workflows/agent.yml` so platform can say "use this" instead of inventing inputs.

---

## 7. Chart, containment, observability

### 7.1 Helm chart

`charts/tenuo-github-actions` (in-tree). OCI publish and `appVersion` = image digest come at the product cut.

Two Deployments, two ServiceAccounts, one image. `exchange` has `TENUO_ROLE=exchange` and signing material for the issuer key only. `gateway` has `TENUO_ROLE=gateway` and signing material for the receipt and App keys only. There is no values knob that merges them into one workload identity. The chart fails closed if `signing.profile` is not `secret`, if a required Secret is missing, or if both roles name the same Secret.

Values today: `image` (registry + tag or digest), `trust.rootPublicKeys`, `exchange` / `gateway` (replicas, Services, `existingSecret`, ServiceAccount annotations), `github.appId` / `apiUrl`, `tools.packs` (HTTP recipes), `networkPolicy.enabled` (default true; DNS + 443), `podDisruptionBudget`, `resources`. `kms` key ids are not accepted.

`secret` requires a per-role Secret (or CSI) mounted at `signing.secret.mount`. The Secret is ideally synced from the secrets manager the team already runs; a hand-applied key manifest is supported and is still not I10.

Pod security: non-root, read-only filesystem, no capabilities, seccomp `RuntimeDefault`. Config `version: 1`; either role refuses an unsupported version.

### 7.2 Containment check

```text
github-actions check --gateway URL --exchange URL --root KEY --socket PATH [--fixture NAME]
```

Runs, in order:

1. Custody scan of both Deployments, profile-aware. Common: no `*_KEY` / PEM / `ghs_` / `github_pat_` in the environment, config does not name a token provider, neither role has the other's signing material. `kms` (I10): no Secret volume mounts for keys; exchange SA cannot `kms:Sign` the App or receipt keys; gateway SA cannot `kms:Sign` the issuer key. `secret`: private key files exist only under the Secret mount; a file outside it fails; exchange mounts only the issuer Secret; gateway mounts only the App and receipt Secret.
2. Job scan (I1 / I4, every profile): no `GITHUB_TOKEN`, holder bytes absent from the agent and shim `/proc/<pid>/environ` and from `/proc/self/environ` of the check process. The holder process is not a child of the agent.
3. I2: direct egress from the agent/shim namespace to the GitHub API host. On ARC (or any runner with a network policy): must fail. On GitHub-hosted runners: report `I2 not enforced (hosted)` and do not fail the check for this row.
4. The allowed read.
5. Each fixture's attack calls (cross-repository read, unsafe path read, workflow dispatch, package install).
6. Argument-widening delegation, call with no envelope, call with a tampered body.
7. The allowed label and the allowed comment.
8. Receipt journal verified.

Prints expected versus actual, exits non-zero on any mismatch other than a reported I2-hosted row. Fixtures are the three incident shapes (GitLost, Gemini workflow pivot, Clinejection) and ship in the image. A deploy that fails I1–I9 is not a correct deploy. Custody is reported as a profile: `kms` (I10, recommended) or `secret` (supported). A file-on-disk or env-var key that matches neither profile fails the check. A hosted-runner job that reports I2 as not enforced can still be a correct deploy; an ARC job that fails I2 cannot.

### 7.3 Observability

- **Receipts** are the primary audit record: decision, tool, argument commitment, leaf and chain ids, run id (stamped at issuance), signer.
- **Job summary** is the per-run product surface: blast radius, "This run may:", denials with `TENUO_*` codes.
- **Metrics:** decisions by outcome and code, receipt emission failures, revocation list age, sign latency, installation-token mint latency, tool latency.
- **Denial alerting** is Cloud, over receipt ingest. In file/webhook mode the summary and the containment check are the signal.

---

## 8. Open-source SDK changes (in `tenuo`, target 0.2.5)

These unblock the gateway. They land in the core repo and are released before the product repo tags v1.

| Change | Why |
|---|---|
| `MCPVerifier` emits denial receipts through the same emitter as allows, retaining the presented chain and arguments on a denial result | I6. The replay gateway carries a shim for this today. `@guard` already keeps `presented_chain` |
| Python `ReceiptSigner` that does not require a control-plane client, taking a `Sign` callback (bytes or KMS) plus a sink | File/webhook sinks and both custody profiles. Rust already has `ReceiptSigner` / `LocalReceiptSigner` |
| KMS signer implementations: AWS, GCP, Azure, Vault Transit, behind one `Sign` trait | I10 (`kms`). Temporal's secret *fetch* is not this. `secret` uses the same callback with bytes loaded from the mount |
| `SecureMCPClient.derive_terminal_leaf(tool, args)` | Holder process and containment check share one mapping |
| Denial results carry stable codes: `TENUO_TOOL_NOT_AUTHORIZED`, `TENUO_CONSTRAINT_VIOLATION`, `TENUO_INVALID_POP`, `TENUO_REVOKED`, `TENUO_WARRANT_EXPIRED` | Shim mapping and the summary table |
| Document `Range(n, n)` as the exact-match form for integers; `Exact` is for strings and booleans | Every catalog entry relies on it |

---

## 9. What we need from Cloud

Cloud is built in parallel. The open-source package ships a complete self-hosted path (exchange `/v1/exchange` + gateway MCP + `kms` or `secret` custody + file/webhook receipts). The action treats Cloud as an alternative exchange URL, not a second product.

OSS owns the client. Cloud owns hosted `/v1/exchange`, receipt ingest, and revocation. The action talks to Cloud when `exchange_url` is the Cloud API and `audience` is `tenuo:org/<tenant>`.

### 9.1 Exchange (required for the Cloud upgrade)

`POST /v1/exchange`  
Authorization: `Bearer <GitHub OIDC JWT, audience = the org's Tenuo audience>`

Cloud may also expose `POST /v1/exchange/github` as an alias. The action has one request/response model and always calls `/v1/exchange`. The body is identifier-free: no tenant id and no policy id.

```json
{ "holder_public_key": "<hex>", "holder_proof": "<base64url>", "ttl_seconds": 900,
  "capabilities": { "github.get_issue": { "issue": 4127 }, "github.add_comment": { "issue": 4127 } },
  "task_binding": { "type": "issue", "number": 4127 } }
```

`task_binding` is only `{type, number}`. Assurance is assigned by Cloud and must not be runner-supplied. Unknown fields (`task_context`, tenant id, policy id) are rejected.

`holder_proof` is an Ed25519 signature over Cloud's compact GitHub exchange commitment (`tenuo-warrant-exchange-v1 || 0x00 || hex(request_sha256)`). The holder process signs it; the private key never leaves the socket. The hash is SHA-256 of compact JSON with recursively sorted object keys:

`{"version":1,"issuer":...,"jti":...,"holder_public_key":...,"ttl_seconds":...,"capabilities":...,"task_binding":...}`

The shared golden vector is `a6e5f6e8d6f2454c167343e57cbe1ce0dcfef675a969c1607c82a4ba589568ae`.

Response `200`: `{ "warrant": "<base64 stack>", "warrant_id": "...", "expires_at": "...", "root_public_keys": ["<hex>"] }`  
Response `403`: `{ "error": "outside_ceiling" | "untrusted_workflow" | "token_reused" | "holder_proof_invalid", "detail": "..." }`

The `warrant` field is a complete warrant stack (policy issuer → run warrant on Cloud; a one-element stack on the self-hosted exchange). The holder decodes the stack, retains every parent, derives the per-call terminal leaf from the last warrant, and presents the full chain to the gateway.

`root_public_keys` is checked against deploy-time trust. A run-provided root is never installed as the gateway trust anchor.

GitHub OIDC does not attest the issue number. The action does not send assurance. Cloud labels issue bindings `runner_asserted` and may independently verify pull-request bindings when GitHub's run API exposes the PR, then upgrade assurance to `provider_verified`.

Cloud verifies the JWT against GitHub's JWKS, matches the trust policy (numeric owner and repository ids, workflow ref and branch, event names), expands the selected template into the warrant, refuses rather than trims, caches the JWT id for its lifetime, stamps run id and workflow ref into the warrant, and returns a stack bound to the holder key. The run warrant binds repository and issue; comment body size is a policy CEL on the warrant when the template says so. The holder's per-call leaf keeps that CEL and binds `body_sha256`. The box does not re-apply the template.

The self-hosted exchange Deployment implements the same schema so the action has one client.

Cloud does **not** mint GitHub installation tokens or proxy `api.github.com`. That would put Cloud on the credential path and the data path. The gateway role remains the GitHub credential.

### 9.2 Receipt ingest (required for org-wide audit)

`POST /v1/receipts` — newline-delimited receipt hex; idempotent on receipt hash. The existing control-plane client's forwarding path is acceptable if it already does this.

### 9.3 Revocation (required for hosted SRL)

`GET /v1/revocation` — current signed revocation list. The gateway polls per `refresh_seconds`. Prefer this over a customer-hosted URL when Cloud is configured.

### 9.4 Trust policy (Cloud-side issuance templates)

Cloud packs and overrides are issuance templates. They expand into the warrant at issue time. The OSS box does not re-enforce them as a local ACL.

```yaml
trust:
  issuer: https://token.actions.githubusercontent.com
  audience: tenuo:org/acme
  conditions:
    repository_owner_id: "123456"
    repository_id: ["7890", "7891"]
    job_workflow_ref: "acme/*/.github/workflows/triage.yml@refs/heads/main"
    event_name: [issues, pull_request]
templates:
  ttl_max: 15m
  packs: [github-triage]          # expands into the warrant; not a gateway ACL
  overrides:
    github.add_labels: { labels: { subset: [bug, question, needs-info] } }
```

### 9.5 Not required to ship OSS v1

| Cloud feature | OSS stand-in |
|---|---|
| Hosted issuer (customer does not want to manage signing keys) | Exchange `/v1/exchange` + `kms` or `secret` |
| Denial alerting | Job summary + containment check |
| Org receipt dashboard | File / webhook sink |
| Verified task binding (App confirms issue/PR) | Event-derived constraints in the action (weaker; noted in the summary) |
| ID-JAG / non-GitHub OIDC | Out of v1 |

---

## 10. Path to product

M2–M5 and the `secret` chart are in-tree. Remaining for a published v1: KMS signers (I10), image digest, OCI chart, cluster custody in `check`, one wheel pin.

Build in this order. Each milestone is independently testable. Later milestones do not reopen earlier ones.

| Milestone | Where | What | Done when | Estimate |
|---|---|---|---|---|
| **M1 — SDK 0.2.5** | `tenuo` | Section 8: MCP denial receipts, Python `ReceiptSigner` + `Sign` callback, `derive_terminal_leaf`, `TENUO_*` codes, `Range(n,n)` docs. KMS implementations may land as a follow-on in M3 if the callback is stable. | Unit tests green; replay shim deleted | 2–3 days |
| **M2 — Verify-only gateway** | `github-actions` | FastMCP image, tripwire catalog, file receipts, no GitHub App yet. Forwards nothing to GitHub. | Containment fixtures that must deny, deny; I3/I6 hold | 3–4 days |
| **M3 — Custody and exchange** | `github-actions` + `tenuo` | `signing.profile` (`kms` / `secret` / memory); KMS signers; Secret-mount load; `/v1/exchange` as a module that runs as `ROLE=exchange` (same process only under a test escape); memory keys refuse to start without the test escape. | OIDC from a fixture JWT mints a warrant; PEM env is a startup error; `secret` refuses a key file outside the mount; `kms` refuses a key Secret; exchange refuses App/receipt material | 4–5 days |
| **M4 — App provider + triage** | `github-actions` | Signed App JWT, in-memory installation token, declarative `github-triage`, mock + live GitHub. Gateway role only. | Allowed comment on the bound issue; cross-repo read denied with a receipt | 4–5 days |
| **M5 — Action + holder** | `github-actions` | Holder process + stdio shim, socket not fd, guardrails, summary, Claude Code action conformance. | The YAML in §1.3 runs a real triage issue end to end; holder is not a child of the agent | 4–5 days |
| **M6 — Chart + custody profiles** | `github-actions` | Helm with two Deployments and two ServiceAccounts, WI annotations, network policy, `kms` and `secret` values, containment reports the profile (I10 for `kms`) and I2-hosted-report, digest pins, GHES `api_url`. | `helm install` + `github-actions check` green for `kms` (no key Secrets, split signing grants) and for `secret` (per-role Secret mounts only) | 3–4 days |

v1 release is M6 plus the docs in section 11. `github-review` is the first minor after v1. `github-fix` is not scheduled until the containment check is boring on triage and review.

Roughly five to six weeks for one engineer to a design-partner install; three to four with two engineers (M1+M2+M3 and M4+M5 in parallel after M1, M6 last).

**Acceptance for v1.** A platform team with no prior Tenuo deployment installs the App, chooses a custody profile, installs the chart (two identities), allowlists the action, runs the containment check green (I1–I9 plus the selected profile, with I2 reported not enforced if the check ran on a hosted runner), and runs one real triage workflow. `kms` (I10) does that without placing a PEM in GitHub or in the cluster. `secret` does it with keys only in a per-role Secret, never in the environment or as a file outside the mount.

---

## 11. Testing, release, docs

### 11.1 Testing

| Level | What | Gate |
|---|---|---|
| Unit | Constraint mapping, catalog validation, config parse, custody-profile refuse-to-start, OIDC claim checks | Every commit |
| Integration | Gateway against a mock GitHub API; shim + holder against the gateway; Cloud-compatible `POST /v1/exchange` (stack, terminal leaf, one GitHub call, root trust, revocation, receipts); receipts via `tenuo receipt verify` | Every commit |
| Live Cloud | Opt-in `TENUO_LIVE_CLOUD=1`: real Cloud `/v1/exchange`, stack verify, terminal leaf, one GitHub call, deploy-time root trust, receipts | Release / partner |
| End to end | Containment check, I1–I9 plus the selected custody profile (I2 report-only on hosted), on every release candidate | Release |
| Agent conformance | Shim under `anthropics/claude-code-action` for v1; Codex and Gemini on the first minor | Release (Claude); next minor (the rest) |

Live-model trials of the compromised profile remain informational beyond the invariant: attack calls allowed must be 0.

### 11.2 Release

- Image tagged by semver and digest, cosign-signed, SBOM attached, base pinned by digest.
- Chart version-locked to the image; `image.registry` so the customer can copy to their registry.
- Action internal `uses:` pinned by SHA; Marketplace listing is "Tenuo for GitHub Actions".
- Compatibility in the README is three columns only: this product version, minimum `tenuo` SDK, agent actions conformance has been run against.
- Dependabot, provenance attestations, no network during image build beyond the pinned index.

### 11.3 Docs in the product repo

1. Platform install: App, custody profile (`kms` import-and-destroy, or `secret` synced from the existing secrets manager), chart (two identities), WI, network policy, allowlist.
2. App-team quickstart: the YAML in §1.3.
3. Catalog reference, generated from pack definitions.
4. Containment check: what each attempt proves, how to read receipts, custody profiles (I10 = `kms`), I2 on hosted vs ARC.
5. Security overview: threat model, I1–I9, custody profiles, holder process, what is not covered, compose-with-safe-outputs.
6. Cloud upgrade: point `exchange_url` and `audience` at Cloud; the customer gateway still talks to GitHub.

---

## 12. Closed decisions

v1 does not include a Node broker (static binary), a `token` provider, a per-job gateway, an issuer PEM in GitHub secrets, `github-fix`, or ID-JAG.

**Holder process, not fd inheritance.** The agent action starts the MCP server in a later step. A memfd from the Tenuo action does not survive that boundary. The action starts a holder process; `mcp_config` launches a stdio shim over a Unix socket. Not being a child of the agent is what makes I4 true under default Yama. A separate OS user is optional and is not claimed on hosted runners that grant `sudo`.

**Custody is a profile, not a precondition.** I1–I9 are required of every correct deploy. I10 is the name of the recommended `kms` profile: root and receipt keys generated in KMS, App key imported, nothing at rest in the cluster. `secret` is supported: keys live in a Kubernetes Secret, ideally synced from a secrets manager the team already runs; each role loads them at start, never logs them, and refuses a private key file outside the Secret mount. A PAT, `GITHUB_TOKEN`, or inline PEM is a startup error on both.

**Exchange and gateway are separate identities.** One image, two Deployments, two ServiceAccounts. Only the exchange role signs the issuer key. Only the gateway role signs the App and receipt keys. `TENUO_ROLE=both` is a test escape.

**I2 on hosted runners.** Network policy exists on ARC and other self-hosted installs. GitHub-hosted runners have none. The containment check fails I2 on ARC and reports it as not enforced on hosted. I1 still denies the agent a token.

**Task binding.** The action binds the issue or PR from `GITHUB_EVENT_PATH`. I8 pins `job_workflow_ref` to a branch, so a run cannot pick a different workflow file than the one the org allowed. Lying about the triggering object requires changing that pinned workflow. The exchange does not re-fetch the Actions API for the run. Cloud may add verified task binding (section 9.5) as an upgrade.

**Installation discovery.** The gateway lists installations at start with the App JWT, maps account id → installation id, and refreshes periodically. `installation_id` in config is an optional pin for a single-org deploy.
