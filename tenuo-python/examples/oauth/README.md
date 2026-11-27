# OAuth login to task-scoped refunds and email

This example uses a real Keycloak server, browser Authorization Code + PKCE
login, Tenuo's HTTP warrant issuer, and separate FastMCP payments and mail
processes. The upstream payments service is simulated with real SQLite writes;
email is delivered to a local SMTP sink. Denied calls must never enter the tool body.

## Run

Requires Docker, Python 3.10+, and a Rust toolchain to build the checkout.
From the repository root:

```sh
python -m venv .venv-oauth
.venv-oauth/bin/python -m pip install './tenuo-python[oauth,fastmcp]' uvicorn playwright aiosmtpd pytest pytest-asyncio
.venv-oauth/bin/python -m playwright install chromium
PYTHONPATH=tenuo-python .venv-oauth/bin/python tenuo-python/examples/oauth/smoke.py
```

On Linux, use `playwright install --with-deps chromium`. The smoke harness
starts a digest-pinned Keycloak 26.8.2 container on a random loopback port,
imports the checked-in realm with an exact callback URI, and drives Chromium.
It removes its container, servers, browser contexts, and temporary databases
on exit. It does not use or modify your real identity provider or Docker volumes.
The realm's users/passwords are local fixtures; never import it into production.
The password grant is used only to bootstrap this disposable server's admin
configuration. All tested application tokens come from browser login with PKCE.

To invoke the same test via pytest:

```sh
TENUO_KEYCLOAK_SMOKE=1 PYTHONPATH=tenuo-python .venv-oauth/bin/python -m pytest tenuo-python/tests/e2e/test_oauth_keycloak.py -q --override-ini='addopts='
```

## What runs

1. Browser login, state validation, OIDC ID-token/nonce validation, and code
   exchange. Wrong PKCE verifier and reused authorization codes are refused.
2. The issuer validates an **access token** whose audience is `tenuo-authority`.
   The ID token is never accepted as an API credential.
3. `refund_policy.py` loads a server-owned task and binds its payment, currency,
   operation ID and maximum cents to actual warrant constraints. Ownership is
   checked using issuer + subject + tenant; the token also needs `refunds:write`.
4. The agent proves possession of its holder key. The issuer reserves that
   proof in SQLite, runs policy, caps lifetime, signs, and records issuance.
5. The MCP server receives only the issuer public key. Its middleware verifies
   the warrant and proof before calling the refund function.
6. Wrong payment, currency, amount, holder and missing warrant are denied with
   no tool-body calls. Unknown/unapproved/cross-tenant tasks, wrong-audience,
   expired and ID tokens, missing scope, and repeated issuance proofs fail.
   The same warrant request also succeeds as an OAuth 2.0 Token Exchange
   (RFC 8693) with Keycloak's token as the subject token.
7. A narrower child warrant succeeds; an attempted broader child is rejected.
8. The actual Keycloak signing key rotates. Issuance discovers the new key.
   A paused provider works only within the existing JWKS cache lifetime; an
   expired cache fails closed and recovers after the provider returns.

The refund limit is **per call**, not a cumulative budget. An exact operation
ID and atomic ledger transaction make this example a single refund: identical
retries return the existing outcome, and conflicting retries are refused.
This also prevents captured invocations from duplicating effects; it does not
claim that the underlying MCP PoP format rejects every replay cryptographically.

## Bring your provider

Start with [the adapter guide](../../../docs/oauth.md). A `Trust` names the
issuer, the audience, the key location, the allowed clients and how the
provider writes its tokens. Keycloak, RFC 9068 and GitHub Actions have tested
presets; for another provider you write a `ClaimMap` from one of its tokens and
test it. Changing a URL is not a claim of vendor compatibility.

If your tokens are validated at an API gateway, see the
[gateway recipe](gateway/README.md): it adds warrant checks to an Envoy that
already checks Keycloak tokens.

Keep task records and issuer signing keys on the server. Replace the fixture
policy loader and audit list with your application database and durable audit
sink. Keep the holder key in the agent's trusted runtime, outside model-visible
context. Production endpoints require HTTPS; loopback HTTP is an explicit
development opt-in. Do not pass a user's token to an unrelated agent service.

## Second workflow: approved customer email

The same command also runs a separate `mail-support` client using real browser
login with `mail:send` scope. The refund client has no mail scope and cannot
obtain an email warrant. `email_policy.py` binds the exact recipient, subject,
body, empty attachment field, and operation ID from a trusted approval record.
The mail task does not permit delegation.

A separate MCP process sends through Python's SMTP client to a real loopback
`aiosmtpd` server. No external email is sent. The test inspects the received SMTP
envelope and MIME message, not just a mocked tool return. It verifies:

- Recipient substitution, multiple recipients, CRLF header injection, changed
  subject/body, attachments, extra BCC, and invented operation IDs fail before
  the tool body runs.
- Wrong holders and missing warrants cannot send; another tenant cannot obtain
  authority for the task.
- Approved content arrives once; captured calls and concurrent fresh retries
  do not duplicate delivery, including after the tool process restarts.
- A sink that records receipt but returns an SMTP error leaves the operation
  `pending`. A later retry must not resend it.

**SMTP cannot provide an atomic transaction with the operation database.** This
example reserves an operation before sending. A crash before delivery can leave
an unsent operation pending; a lost acknowledgement can leave a delivered one
pending. Both require reconciliation. It deliberately does not promise exactly
once delivery or automatic recovery. A production mail provider's idempotency
API and delivery-status lookup would be preferable where available.

This tests OAuth at the Tenuo issuance boundary, with an SMTP backend. It does
not test Gmail/Microsoft Graph OAuth consent, refresh tokens, or vendor APIs.


## Independent provider: no Keycloak or Docker

`oidc_smoke.py` uses the independent [node-oidc-provider](https://github.com/panva/node-oidc-provider)
authorization server, pinned to 9.15.1 with an npm lockfile. It exercises the
adapter's `rfc9068` profile with the provider's actual `at+jwt` access tokens.
It reuses both task templates and MCP tools without changing the adapter.

After installing the Python/browser dependencies above, install Node.js 22+
and run from the repository root:

```sh
npm ci --ignore-scripts --no-audit --no-fund --prefix tenuo-python/examples/oauth/oidc-provider-fixture
PYTHONPATH=tenuo-python .venv-oauth/bin/python tenuo-python/examples/oauth/oidc_smoke.py
```

Or use the CI entrypoint:

```sh
TENUO_OIDC_SMOKE=1 PYTHONPATH=tenuo-python .venv-oauth/bin/python -m pytest tenuo-python/tests/e2e/test_oauth_oidc_provider.py -q --override-ini='addopts='
```

The server, browser, warrant issuer and tool processes use loopback endpoints
and ephemeral state. The provider uses its **development-only login UI** with
fixture Alice/Bob accounts; this is not a production user-authentication setup.
Authorization codes, PKCE, consent, JWT signing, JWKS and refresh grants are
handled by the actual provider implementation. No tokens are minted by the
Python test, and no cloud account or external email delivery is involved.

Checks include both enforced business workflows, OAuth state/response issuer,
ID-token signature/nonce, wrong PKCE verifier, authorization-code replay,
refresh-token rotation/reuse, wrong audience, missing tenant claims and opaque
token rejection. Refund-only and mail-only clients have distinct scopes.

A provider-specific finding: authorization-code replay invalidates its associated
refresh grant. The destructive replay test therefore uses a separate login from
the success path. JWT signature validation alone does not learn about provider
session revocation; existing tokens/warrants can remain locally valid until
expiry. This example does not add introspection or immediate revocation.

CI runs Keycloak and this provider as independent matrix jobs. Passing this test
does not establish Auth0, Entra ID, Okta, Gmail or Graph compatibility.
