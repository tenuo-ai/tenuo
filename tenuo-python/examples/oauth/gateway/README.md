# An OAuth gateway that also checks warrants

You run a gateway that validates OAuth tokens. An agent with a valid token and
the `refunds:write` scope can refund any payment, for any amount, until the
token expires.

This recipe keeps that gateway and its token check exactly as they are, and
adds two things: a route to a warrant issuer, and a warrant check on the route
that moves money. Afterwards the agent can refund the one payment its task was
approved for, up to the approved amount, and a valid token alone refunds
nothing.

```text
                 ┌────────────── Envoy ──────────────┐
agent ──────────▶│ jwt_authn (unchanged)             │
  token          │   POST /warrants ─────────────────┼──▶ warrant issuer (Python)
  + warrant      │   POST /refunds ── ext_authz ─────┼──▶ Tenuo authorizer
  + signature    │                  └─ if allowed ───┼──▶ payments service
                 └───────────────────────────────────┘
```

Everything is real except the payments service, which is an echo server:
Keycloak issues the tokens, Envoy validates them, and the Tenuo authorizer
checks the warrants.

## Run it

Requires Docker with Compose, Python 3.9 or later, and a Rust toolchain to
build this checkout. From the repository root:

```sh
python -m venv .venv-gateway
.venv-gateway/bin/python -m pip install './tenuo-python[oauth]' uvicorn
PYTHONPATH=tenuo-python .venv-gateway/bin/python tenuo-python/examples/oauth/gateway/check.py
```

The script starts the containers, runs the issuer, acts as two agents, prints
one line per check, and removes what it started. It uses ports 18180
(gateway), 18181 (issuer) and 18190 (Keycloak) on this machine. Add `--keep`
to leave it running and try requests by hand.

## What changed in the gateway

[`envoy.yaml`](envoy.yaml) marks the two additions:

1. **A route to the issuer.** `POST /warrants` goes to the issuer like any
   other upstream. The gateway checks the token first, as it does for every
   route, and the issuer checks it again for its own audience. `forward: true`
   on the token provider keeps the `Authorization` header on the request,
   because the issuer needs it.
2. **A warrant check.** The `ext_authz` filter sends each request the token
   check let through to the Tenuo authorizer. [`gateway.yaml`](gateway.yaml)
   tells the authorizer that `POST /refunds` is the tool `refund`, with
   `payment_id`, `currency` and `amount_cents` read from the JSON body. The
   access token is not forwarded to the authorizer.

The token check, the payments route and the identity provider are untouched.

## What the issuer decides

[`issuer.py`](issuer.py) trusts the same Keycloak realm, for the audience
`tenuo-authority`, and only for the client `support-agent`. A task belongs to
the service approved to carry it out, and the approval record supplies the
payment, the currency and the limit. The agent's request names a task ID and
nothing else.

## What the script checks

- No token, or an altered one: the gateway refuses, as before.
- A valid token and no warrant: refused. This is the change.
- The approved refund, with the token, the warrant and the agent's signature:
  reaches the payments service.
- A larger amount, another payment, another currency: refused by the
  authorizer before the payments service sees the request.
- The warrant with someone else's key: refused. The warrant without a token:
  refused by the gateway.
- A pending task, an unknown task, and a client the issuer does not trust: no
  warrant.
- The same warrant request as an OAuth 2.0 Token Exchange (RFC 8693).
- The authorizer stopped: the gateway refuses the refund.

## Limits

- The authorizer checks the fields `gateway.yaml` maps. A field it does not
  map reaches the backend unchecked. Map every field that changes what the
  call does, and have the backend refuse fields it does not know.
- `amount_cents` is a limit per call. The recipe has no running total and no
  single-use rule: keep those in the payments service.
- The warrant and the token are checked separately. The warrant is bound to
  the agent's key, not to the token.
- The issuer runs on the host so that the recipe needs no image build. In a
  deployment it is one more service next to your others, over HTTPS.
- `debug_mode` in `gateway.yaml` returns the reason for a denial to the
  caller. Turn it off outside a recipe.
- The realm's client secrets are fixtures for this recipe. Never import the
  realm anywhere else.
- Tested with Keycloak 26.8, Envoy 1.39 and the authorizer image the compose
  file names. Other gateways that can call an external authorizer follow the
  same two steps; see [Proxy configurations](../../../../docs/enforcement.md#proxy-configurations).

See [the OAuth guide](../../../../docs/oauth.md) for the adapter itself.
