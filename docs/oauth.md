# OAuth access tokens and task-scoped warrants

`tenuo.oauth` is a JWT access-token resource-server adapter. It authenticates a
caller, verifies an agent holder proof, invokes your task policy, and issues an
ordinary Tenuo warrant. It is not an authorization server, OAuth Token Exchange,
RAR endpoint, or AAT implementation.

Install `tenuo[oauth]`. Run [the Keycloak example](../tenuo-python/examples/oauth/README.md)
for a complete browser-to-tool test. Python 3.9+ supports the adapter; the MCP
browser example requires Python 3.10+ and the separately installed example dependencies.

## Configure the trusted credential source

```python
from tenuo.oauth import OAuthAccessTokens

credentials = OAuthAccessTokens(
    issuer="https://identity.example.com/realms/company",
    audience="tenuo-authority",
    jwks_url="https://identity.example.com/realms/company/protocol/openid-connect/certs",
    allowed_clients=frozenset({"support-app"}),
    profile="keycloak",
    tenant_claim="tenant_id",
)
```

The audience must name this issuance resource. A valid token intended for a
different API is refused. The caller identity includes issuer, subject, client,
tenant, scopes, and expiry. It is produced only after signature validation.
Register the resource/audience with your provider; the adapter does not change
provider configuration automatically. Only explicitly allowed clients can issue.

Supported profiles:

| Profile | Token contract |
|---|---|
| `keycloak` | Header `typ=JWT`, payload `typ=Bearer`, `azp` client identity, explicitly mapped tenant claim |
| `rfc9068` | Header `typ=at+jwt`, `client_id`, standard access-token claims, explicitly mapped tenant claim |

Both support RS256 (RSA >= 2048 bits) and ES256 (P-256), with an explicit key ID.
They reject ID tokens, unsigned tokens, duplicate JSON members, unsupported
headers, and unrecognized algorithms. Opaque tokens, encrypted JWTs,
sender-constrained (`cnf`) tokens, and actor/delegation-chain claims are not
supported and are rejected. Application login/refresh/consent remains with your
existing OAuth client. Never interpret client credentials as user consent.

## Author a reusable task template

```python
from tenuo.oauth import ExactFrom, MaximumFrom, TaskTemplate

refund = TaskTemplate(
    tool="refund",
    arguments={
        "operation_id": ExactFrom("task_id"),
        "payment_id": ExactFrom("payment_id"),
        "currency": ExactFrom("currency"),
        "amount_cents": MaximumFrom("max_amount_cents"),
    },
    required_scopes=frozenset({"refunds:write"}),
    ttl_seconds=120,
    max_depth=1,
)

def policy(caller, task_id):
    record = task_database.lookup(caller.tenant_id, task_id)
    if record is None:
        return None
    return refund.compile(caller, task_id, record)
```

`task_database` is your application's trusted database. The record must carry
`task_id`, `issuer`, `subject`, `tenant_id`, `status="approved"`, integer
`expires_at`, and the template's referenced fields. The template compares
ownership with the verified caller; it never accepts agent-supplied authority.
Required fields must exist. Integer limits reject booleans and values outside
the exact interoperable integer range. Templates are user-task oriented;
machine/client-only authorization requires an explicit custom policy.

`MaximumFrom` is a per-invocation bound, not cumulative accounting. Use a
transactional business ledger for total budgets and one-time approvals. Template
bindings do not discover tool schemas: maintain the mapping alongside your tool
schema and test allowed and denied arguments whenever that schema changes.

## Serve and request warrants

```python
from tenuo.oauth import OAuthWarrantIssuer, OAuthWarrantIssuerApp, SQLiteReplayStore

issuer = OAuthWarrantIssuer(
    credentials=credentials,
    signing_key=issuer_signing_key,
    policy=policy,
    replay_store=SQLiteReplayStore("/var/lib/tenuo/oauth-proofs.sqlite"),
    audit=write_durable_audit_record,
)
app = OAuthWarrantIssuerApp(issuer)
```

Load `issuer_signing_key` from your protected application configuration. Supply a
durable audit callback; failure prevents release of the warrant. Run `app` with
an ASGI server behind HTTPS or mount it in an existing application. The agent uses:

```python
from tenuo.oauth import request_warrant_oauth

warrant = request_warrant_oauth(
    "https://authority.example.com/warrants",
    token=access_token,
    audience="tenuo-authority",
    issuer_key=trusted_issuer_public_key,
    holder_key=agent_holder_key,
    task_id="refund-123",
)
```

The helper signs a fresh issuance proof and checks the returned warrant's
signature, validity and holder. `arequest_warrant_oauth` runs the same operation
in a worker thread. Tokens and private keys must never enter model prompts or
logs. The access token is a bearer credential: warrant holder binding does not
stop a thief with that token from requesting their own warrant if policy allows it.

## HTTP and proof contract

POST JSON to `/warrants`, with exactly one `Authorization: Bearer` header:
`{"v":1,"holder":"<base64 raw Ed25519 public key>","task":"<ID>",
"timestamp":<Unix seconds>,"nonce":"<base64 16 bytes>","signature":"<base64>"}`.
The signed bytes are the ASCII context `tenuo.oauth.holder-binding.v1` followed
by a zero byte, SHA-256(token UTF-8), SHA-256(audience UTF-8), SHA-256(task UTF-8),
32 holder bytes, unsigned big-endian 64-bit timestamp, and 16 nonce bytes.
Proofs have a 30-second clock window. All fields are bound; signature bytes are
not the replay identity. A proof is consumed before policy runs and remains
consumed on failure. Retry with a fresh proof. This does not make tasks single-use.

Success is `200 {"warrant":"<base64>"}` with `Cache-Control: no-store`.
Errors are 400 malformed request, 401 rejected credential, 403 rejected proof or
grant, 408 body timeout, 413 body too large, 415 unsupported content type, or
503 overload/dependency/internal failure. Clients must not blindly retry grants
for side-effecting workflows without business idempotency.

## Operational boundaries

- JWT verification is local while the configured JWKS cache is fresh (default
  five minutes). Unknown-key refresh is throttled. Expired cache plus refresh
  failure denies issuance; receiving malformed bytes does not renew freshness.
  An accepted refresh replaces the complete key set, including withdrawals.
  `credentials.refresh()` applies an operator-requested refresh immediately.
- JWKS URLs are explicit configuration. No untrusted discovery, token-provided
  URLs, environment proxies, or credential-bearing redirects are followed.
- Warrant expiry is bounded by token expiry, task expiry, grant TTL, and the
  issuer's maximum TTL. Revoking an OAuth session or modifying a task does not
  revoke already-issued warrants automatically. Choose short lifetimes or add
  your verifier-side revocation mechanism. The task decision is a snapshot.
- SQLite replay state supports restarts and multiple processes on **one host**.
  Multi-host deployments must supply a transactional shared `ReplayStore.claim`
  implementation. Never put the SQLite file on a network filesystem.
- HTTP work and body reads share one bounded concurrency limit. Cancellation
  keeps a slot until running work completes. Policy/audit callbacks must enforce
  their own database/network deadlines. Put per-client/IP rate limiting and
  endpoint authentication controls at your ingress as appropriate.
- Audit callbacks receive verified caller, task, holder, warrant ID and expiry;
  they do not receive raw tokens. This adapter does not provide an audit backend,
  key-management service, metrics backend, or immediate token revocation.
- Shut down the ASGI app and close `credentials` when the host application exits.

The smoke tests establish interoperability with the pinned Keycloak and
node-oidc-provider configurations,
not universal OAuth-provider compatibility or a complete production certification.
Production deployments still own ingress TLS, protected signing keys, policy
data, audit durability, rate limits, business idempotency, and revocation SLOs.
The tenant claim must come from administrator-controlled identity data; users
must not be able to edit the attribute that determines their tenant authority.
