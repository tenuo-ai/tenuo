# OAuth tokens and task-scoped warrants

Your agents already sign in with OAuth 2.0 or OpenID Connect: through Keycloak,
through an API gateway, or as a CI run. The token says who is calling, and its
scope is usually broad (`refunds:write` covers every refund).

`tenuo.oauth` lets each task carry only what that task needs. The agent
presents the token it already has and names a task. Your policy looks the task
up in your own records. The agent gets back a warrant for that task: this
payment, up to this amount, for two minutes, bound to a key the agent holds.

Your identity provider, your login flow and your gateway stay as they are. You
add one service, the issuer, and a warrant check where the tool runs.

```text
agent ── token + task ID + holder proof ──▶ issuer ──▶ your policy(identity, task)
agent ◀───────────── warrant ────────────── issuer
agent ── call + warrant + signature ──▶ tool or gateway (checks the warrant)
```

The token carries no Tenuo permissions. It says who is asking, and nothing
else is read from it. What a caller may do comes from your approved task.

## Install and try it

```sh
pip install 'tenuo[oauth]'
```

Python 3.9 or later. Three examples run against real software, and CI runs all
of them on every change to this adapter:

| Example | What it shows |
|---|---|
| [Gateway recipe](../tenuo-python/examples/oauth/gateway/README.md) | An Envoy gateway that keeps checking Keycloak tokens and also checks warrants, with one filter and one route added |
| [Browser login to MCP tools](../tenuo-python/examples/oauth/README.md) | A person signs in with Authorization Code and PKCE; an agent refunds and sends email through MCP servers that check warrants |
| [GitHub Actions run](../tenuo-python/tests/e2e/test_oauth_github_actions.py) | A workflow run exchanges its own OIDC token for a warrant scoped to its repository |

## Step 1: Say whose tokens you trust

A `Trust` is the whole trust decision in one place: the issuer, the audience
the token must be for, where the signing keys are, how that provider writes
its tokens, and which claim values are required.

```python
from tenuo.oauth import KEYCLOAK, OAuthTokens, Trust

people = OAuthTokens(
    Trust(
        issuer="https://identity.example.com/realms/company",
        audience="tenuo-authority",
        jwks_url="https://identity.example.com/realms/company/protocol/openid-connect/certs",
        claims=KEYCLOAK,
        clients=frozenset({"support-app"}),
        tenant_claim="tenant_id",
    )
)
```

- `audience` names this issuer. A valid token meant for another API is
  refused. Register the audience with your provider; nothing here changes
  provider configuration.
- `clients` lists the OAuth clients allowed to ask for warrants.
- `where` lists further claims that must match: one value, or one of a set.
  Claims are compared as strings. A claim that is missing, or is not a string,
  does not match.
- `tenant_claim` names the claim holding the caller's tenant, if you have
  tenants. It must be data an administrator controls. If a user can edit the
  attribute behind it, they can choose their tenant.
- `required_scopes` are scopes every caller must hold.

The key location is configuration. It is never read from a token, there is no
discovery, and redirects are not followed.

### Providers

These four are tested against the real provider in CI:

| Preset | Token it accepts |
|---|---|
| `KEYCLOAK` | Keycloak access tokens: header `typ: JWT`, payload `typ: Bearer`, client in `azp`. An ID token is refused. |
| `RFC9068` | JWT access tokens as [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) defines them: header `typ: at+jwt`, `client_id`, `jti`. Tested with node-oidc-provider. |
| `GITHUB_ACTIONS` | The OIDC token GitHub gives a workflow run. No client and no scopes: `where` says which runs you trust. |
| `ENTRA_ID` | Microsoft Entra ID version 2.0 access tokens for an application acting as itself (client credentials). Client in `azp`; application roles are read as scopes. |

Any other provider is a `ClaimMap` you write from one of its tokens. Okta,
Auth0 and Cognito are not tested in this repository, so no preset for them
is shipped. Decode one of your tokens and fill in what you see:

```python
from tenuo.oauth import ClaimMap

# An example of the shape, not a statement about any vendor.
MY_PROVIDER = ClaimMap(
    client=("cid", "azp"),  # The first of these claims that is present names the client.
    scopes=("scp", "permissions"),  # A space-separated string or a list of strings.
    header_type="JWT",  # The exact `typ` header.
    constants={"token_use": "access"},  # Claims that must have exactly this value.
)
```

Then test it with a real token from your tenant, and with an ID token from the
same tenant, which must be refused.

A `ClaimMap` cannot describe every provider. A token must carry `iss`, `sub`,
`aud`, `iat` and `exp`. Amazon Cognito access tokens have no `aud` claim, so
they are refused today.

All providers: RS256 (RSA of 2048 bits or more) or ES256, with a key ID. The
only headers accepted are `alg`, `kid`, `typ` and those the preset names.
Refused: opaque tokens, encrypted tokens, unsigned tokens, tokens with
duplicate JSON members, sender-constrained tokens (`cnf`), and tokens with an
actor chain (`act`, `may_act`).

## Step 2: Say what a task allows

A policy is a function from a verified identity and a task ID to a grant, or
`None` to deny. `TaskTemplate` covers the common case: an approval record in
your database becomes argument constraints.

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
)


def policy(identity, task_id):
    record = task_database.lookup(identity.tenant_id, task_id)  # Your database. None if there is no such task.
    return refund.compile(identity, task_id, record)
```

The record carries `task_id`, `status` (`"approved"`), an integer
`expires_at`, the owner fields, and the fields the arguments refer to.
`compile` returns `None` when there is no record, or it is not this caller's
approved and unexpired task. It raises when the record itself is unusable (a
field missing or of the wrong type): that is a fault in your data, and the
endpoint answers 503 and logs it rather than blaming the caller.

`owner` says whose task it is. By default it is a person's task: the record's
`issuer` and `subject` must be the caller's, and its `tenant_id` too when the
trust has a `tenant_claim`. For a service acting for itself, use
`owner=("issuer", "client_id")`. An identity that lacks an attribute the owner
names owns nothing.

Arguments the template does not name stay unauthorized. `MaximumFrom` is a
limit per call, not a running total: keep totals in your own ledger. The
template does not read tool schemas, so test allowed and refused arguments
whenever a tool's schema changes.

For anything a template does not cover, return a `TaskGrant` yourself:

```python
from tenuo import Exact
from tenuo.oauth import TaskGrant


def policy(identity, task_id):
    if identity.claims.get("repository") == "acme/backend" and task_id == "deploy-staging":
        return TaskGrant({"deploy": {"environment": Exact("staging")}}, ttl_seconds=60)
    return None
```

`identity.claims` holds the token's other string claims. Everything in it was
signed by the provider; nothing was supplied by the agent.

Every tool in a grant needs at least one argument constraint. A call with an
argument the grant does not list is refused, unless the grant also sets the
core's `"_allow_unknown": True` for that tool.

## Step 3: Run the issuer

```python
from tenuo.oauth import OAuthWarrantIssuer, OAuthWarrantIssuerApp, SQLiteProofStore

issuer = OAuthWarrantIssuer(
    credentials=people,
    signing_key=issuer_signing_key,
    policy=policy,
    audit=write_audit_record,
    proof_store=SQLiteProofStore("/var/lib/tenuo/oauth-proofs.sqlite"),
)
app = OAuthWarrantIssuerApp(issuer)
```

`app` is an ASGI application: run it with any ASGI server behind HTTPS, or
mount it in an existing one. Load `issuer_signing_key` from wherever you keep
secrets. `audit` is required and runs before a warrant is released: if it
raises, no warrant is issued. It receives the verified identity, the task, the
holder key, and the warrant's ID and expiry, never the token.

To trust several providers at once, pass a list
(`credentials=[people, services, ci_runs]`). A token is judged by the trust
for the issuer it names, and by no other.

## Step 4: Request a warrant in the agent

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

The helper signs a fresh holder proof, sends the request over verified HTTPS,
and returns the warrant only if it is signed by `issuer_key` and bound to
`holder_key`. `timeout` bounds the whole call. `arequest_warrant_oauth` does
the same from async code. Keep the token and the holder key out of model
prompts and logs.

## Step 5: Check the warrant where the tool runs

A warrant is an ordinary Tenuo warrant, so every enforcement point works:

- **At your gateway.** The [gateway recipe](../tenuo-python/examples/oauth/gateway/README.md)
  adds the Tenuo authorizer to an Envoy that already checks OAuth tokens. See
  [Proxy configurations](enforcement.md#proxy-configurations) for Istio and nginx.
- **In an MCP server.** See the [browser-to-MCP example](../tenuo-python/examples/oauth/README.md).
- **In process**, with `Authorizer` or any framework adapter.

## Behind an OAuth gateway

If a gateway already validates tokens for your APIs, nothing about that
changes. You add:

1. A route to the issuer (`POST /warrants`). The gateway checks the token as
   it does for any route, and the issuer checks it again for its own audience.
   The gateway must pass the `Authorization` header through to the issuer.
2. A warrant check on the routes that act: an `ext_authz` filter pointing at
   the Tenuo authorizer, which maps each request to a tool and its arguments.

A caller then needs both: the token your gateway has always required, and a
warrant for this call signed with the agent's key. A valid token alone no
longer moves money. The [recipe](../tenuo-python/examples/oauth/gateway/README.md)
has the Envoy configuration and a script that checks each of these claims
against real Keycloak, Envoy and the authorizer.

## GitHub Actions

A workflow run can ask GitHub for a signed token that says which repository,
branch and workflow it is. Trust it by those claims:

```python
from tenuo.oauth import GITHUB_ACTIONS, OAuthTokens, Trust

ci_runs = OAuthTokens(
    Trust(
        issuer="https://token.actions.githubusercontent.com",
        audience="tenuo-authority",
        jwks_url="https://token.actions.githubusercontent.com/.well-known/jwks",
        claims=GITHUB_ACTIONS,
        where={"repository": "acme/backend", "ref": "refs/heads/main"},
    )
)
```

In the workflow, the job needs `permissions: id-token: write`, and the agent
fetches its token like this:

```python
import json
import os
import urllib.request

request = urllib.request.Request(
    os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=tenuo-authority",
    headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]},
)
with urllib.request.urlopen(request, timeout=30) as response:
    token = json.load(response)["value"]
```

Things to know:

- Repository and owner names can be reassigned after a rename or a deletion.
  `repository_id` and `repository_owner_id` cannot: add them to `where`.
- A pull request from a fork gets no token.
- `environment` is present only for jobs that run in an environment, and
  `where` refuses a token that lacks a claim it names.
- The policy reads the rest from `identity.claims`: `workflow`, `sha`,
  `run_id`, `actor`, `event_name`.

## Microsoft Entra ID

```python
from tenuo.oauth import ENTRA_ID, OAuthTokens, Trust

tenant = "00000000-0000-0000-0000-000000000000"  # Your tenant ID.
services = OAuthTokens(
    Trust(
        issuer=f"https://login.microsoftonline.com/{tenant}/v2.0",
        audience="11111111-1111-1111-1111-111111111111",  # The client ID of the API's app registration.
        jwks_url=f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
        claims=ENTRA_ID,
        clients=frozenset({"22222222-2222-2222-2222-222222222222"}),  # The calling application's client ID.
        required_scopes=frozenset({"Warrants.Request"}),  # An application role on the API.
    )
)
```

Things to know:

- Register the issuer as an API of its own (an app registration with an
  Application ID URI), and set `requestedAccessTokenVersion` to `2` in its
  manifest. Version 1.0 tokens have another issuer and client claim, and
  are refused.
- The audience of a version 2.0 token is the API's client ID, not its URI.
- An application's permissions are application roles, in the `roles` claim.
  Grant the role to the calling application with admin consent, and require
  it with `required_scopes`. Without a role an application in your tenant can
  still get a token for the API, so `clients` matters too.
- Tested with tokens an application gets for itself. Tokens issued for a
  signed-in user carry `scp` instead of `roles` and are not tested here.
- A CI job needs no stored secret: Entra accepts the job's GitHub Actions
  token as the client assertion (workload identity federation). The
  [test](../tenuo-python/tests/e2e/test_oauth_entra.py) does exactly that.

## OAuth 2.0 Token Exchange request shape

For callers and gateways that already speak [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693),
the same endpoint accepts a token-exchange request. The task and the holder
proof travel as one [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)
authorization detail of type `tenuo_task`:

```text
POST /warrants
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<the access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:tenuo:params:oauth:token-type:warrant
&authorization_details=[{"type":"tenuo_task","task":"refund-123","holder":"<base64>",
   "timestamp":<unix seconds>,"nonce":"<base64>","signature":"<base64>"}]
```

(Values are form-encoded on the wire.) The answer is a token response:

```json
{"access_token": "<the warrant>",
 "issued_token_type": "urn:tenuo:params:oauth:token-type:warrant",
 "token_type": "N_A",
 "expires_in": 119}
```

`token_type` is `N_A` because a warrant is not a bearer token: presenting it
takes a signature from the holder key. Errors use the token-endpoint form,
`{"error": ..., "error_description": ...}`: `invalid_grant` for a token that
is not accepted, `invalid_authorization_details` for a task that is not
granted or a proof that is refused, `invalid_request` for a malformed request.

What this is not: the issuer is not an authorization server. It accepts
exactly the five parameters above and refuses any other (`scope`, `audience`,
`actor_token`), so nothing is accepted and then ignored. The authorization
detail names a task. It cannot ask for permissions.

The token is the `subject_token`. Through a gateway that checks a bearer
token the request carries an `Authorization` header as well, and it must be
`Bearer` with that same token; any other `Authorization` header is refused.

In this shape the token is in the body, so the body is read before the caller
is known. Such requests get a quarter of the endpoint's places until their
token has been checked, so they cannot crowd out callers whose token is
checked first.

## Wire protocol

The compact shape, which `request_warrant_oauth` sends:

```text
POST /warrants
Authorization: Bearer <token>
Content-Type: application/json

{"v": 1, "holder": "<base64 Ed25519 public key>", "task": "<task ID>",
 "timestamp": <unix seconds>, "nonce": "<base64, 16 bytes>",
 "signature": "<base64>"}
```

The token is checked before the body is read. Success is
`200 {"warrant": "<base64>"}` with `Cache-Control: no-store`.

The holder signs, with Ed25519: the ASCII bytes
`tenuo.oauth.holder-binding.v1`, one zero byte, SHA-256 of the token, SHA-256
of the audience, SHA-256 of the task ID, the 32 holder key bytes, the
timestamp as 8 big-endian bytes, and the 16 nonce bytes. A proof is accepted
for 60 seconds either side of the issuer's clock, and once. It is reserved
while the request runs and kept only if a warrant is issued, so a request that
was denied or failed can be sent again.

| Status | Meaning |
|---|---|
| 400 | Malformed request, including JSON with a duplicated member |
| 401 | Token not accepted |
| 403 | Task not granted, or holder proof refused |
| 408, 413, 415 | Body too slow, too large (64 KiB), or not `application/json` |
| 503 | A limit was reached, signing keys are unavailable, or a policy or audit callback failed |

## Limits and defaults

| What | Default | Change it with |
|---|---|---|
| Warrant lifetime | The shortest of the grant's `ttl_seconds`, the token's expiry, the task approval's expiry and 120 seconds | `OAuthWarrantIssuer(max_ttl_seconds=)` |
| Signing keys kept after a fetch | 300 seconds | `OAuthTokens(cache_seconds=)` |
| Fetch for a key ID not yet known | At most one every 5 seconds | `OAuthTokens(refresh_interval=)` |
| Clock leeway on token times | 5 seconds | `Trust(leeway_seconds=)` |
| Requests in progress | 256, and 16 for one identity | `OAuthWarrantIssuerApp(max_concurrent=, max_per_identity=)` |
| Proofs remembered | 16384 in a process, a quarter of them for one identity | `proof_store=` |

- **Keys.** A token signed by a key already fetched is checked locally and is
  never held up by a fetch. From half of `cache_seconds` the keys are fetched
  again in the background. With the provider unreachable, known keys work
  until `cache_seconds` runs out, and then tokens are refused.
- **Tokens that need a fetch.** A token with a key ID not yet known, or one
  that arrives when there are no usable keys, sends its own caller to fetch:
  one at a time for each provider, and at most every `refresh_interval`.
  Nobody waits for another caller's fetch. While one is under way, or after
  one failed, such a token gets 503 at once and should be sent again; it gets
  401 only when a fetch succeeded and the key was not in it. The caller that
  fetches waits at most a second past `timeout`, even when the fetch is stuck
  on something that cannot be interrupted, such as a name lookup. So a
  provider that does not answer costs one request at a time, and callers of
  your other providers are not held up. The bundled endpoint fetches every
  provider's keys before the server takes requests (ASGI lifespan start-up).
  If you mount it without lifespan events or call the issuer directly, call
  `OAuthTokens.refresh()` at start-up.
- **Withdrawing a key.** A fetched key set replaces the one before it, so a
  withdrawn key stops working at the next fetch. `OAuthTokens.refresh()`
  fetches at once, and a fetch that began before it cannot bring the key
  back.
- **Key sets.** An entry this adapter has no use for (another algorithm or
  curve, an encryption key, an RSA key under 2048 bits, no key ID) is passed
  over, and a token signed by it is not accepted. A key ID listed twice, or
  private key material, refuses the whole set.
- **Several processes or hosts.** `SQLiteProofStore` shares proof memory
  between processes on one host and keeps it across restarts. Do not put the
  file on a network filesystem. For several hosts, implement `ProofStore`
  (`claim` and `release`) on a store that claims atomically across them.
  Without one, each replica remembers its own proofs.
- **Callbacks.** Policy and audit are plain functions, not `async` ones. They
  run in worker threads and must set their own deadlines on what they call. Whatever they raise is the issuer failing: it
  is logged in full and the caller is told only `Issuer error`. The same goes
  for a grant the policy returns that cannot be used, such as a tool with no
  argument constraints.
- **Revocation.** Revoking a token or changing a task does not revoke a
  warrant already issued. Lifetimes are short for that reason.
- **The token is a bearer credential.** The warrant is bound to the agent's
  key, but someone who steals the token before it expires can ask for a
  warrant of their own for any task approved for that identity. Keep token
  lifetimes short and treat every hop that sees the token as trusted.

## What this adapter does not do

- It is not an authorization server. It does not log users in, ask for
  consent, refresh tokens, or issue OAuth access tokens.
- It does not accept sender-constrained tokens (DPoP, mTLS-bound). The
  holder proof binds the warrant, not the token.
- It does not introspect opaque tokens or check token revocation lists.
- It does not provide an audit backend, key management, or rate limiting by
  network address. Put those at your ingress and in your own services.
- The four tested providers are evidence about those providers as tested
  (pinned versions where there is one). They are not a claim about every OAuth deployment.

The SPIFFE adapter's JWT-SVID and forwarded-identity endpoints run on the same
issuance code as this one. See [the SPIFFE guide](spiffe.md) if your workloads
have SVIDs instead of OAuth tokens.
