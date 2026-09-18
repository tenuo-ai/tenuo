# Python integration

Use this reference only for projects using the current `tenuo` Python package. Confirm the resolved package version and inspect its shipped API, framework module, and tests before generating code; adapters evolve faster than the core warrant types.

## Choose the boundary

- Use a `GuardBuilder` or `@guard` wrapper for an in-process guardrail when that matches the threat model.
- Use `Authorizer` at a server or worker boundary for independent warrant, trust-chain, PoP, capability, and constraint verification.
- For MCP, prefer `MCPVerifier` with the integration's middleware so verification occurs before the tool handler.

Do not generate ephemeral issuer keys at a production enforcement point. Load trusted issuer public keys from independent configuration. Keep issuer and holder signing keys in the principal that owns them; do not serialize bound warrants or private-key-bearing objects into agent or workflow state.

## Current MCP server pattern

```python
from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier, TenuoMiddleware

root = PublicKey.from_env("TENUO_ROOT_PUBLIC_KEY")
verifier = MCPVerifier(
    authorizer=Authorizer(trusted_roots=[root]),
    require_warrant=True,
)
mcp = FastMCP("reports", middleware=[TenuoMiddleware(verifier)])

@mcp.tool()
async def scale_cluster(cluster: str, replicas: int) -> str:
    return await platform.scale_cluster(cluster=cluster, replicas=replicas)
```

Confirm how the installed middleware maps and canonicalizes arguments. When raw handlers are used, call `MCPVerifier.verify` or `verify_or_raise` before the effect and execute with the returned clean arguments.

`require_warrant=False` is a migration mode that permits unwarranted calls. It is not equivalent to enforcement. If used temporarily, name the fallback authorization mechanism and test both warranted and unwarranted paths.

## Current low-level pattern

```python
from tenuo import Authorizer, PublicKey, Warrant

authorizer = Authorizer(
    trusted_roots=[PublicKey.from_env("TENUO_ROOT_PUBLIC_KEY")]
)
warrant = Warrant(received_warrant)

# Construct the PoP exactly as required by the installed SDK/transport.
# Verify before the effect and use the verified argument representation.
authorizer.authorize_one(
    warrant,
    "transfer",
    args,
    signature=pop_signature,
)
perform_transfer(**args)
```

Do not replace full verification with `allows()` or another policy-only convenience check at a security boundary. Use the installed SDK's full validation path that checks trust and holder proof.

## Policy behavior

Once a capability has constrained arguments, keep unknown arguments rejected. Use `Wildcard()` only for a named field intentionally left broad. `_allow_unknown=True` weakens this protection across the capability and requires explicit justification.

For delegation, the current holder signs the child authority. Bind the child to the recipient's public key, reduce TTL where appropriate, and use terminal authority for a leaf. Verify the installed API rather than assuming `grant`, `grant_builder`, or context-manager syntax.

## Test shape

Use a fake effect that records invocations:

```python
calls = []

def effect(**args):
    calls.append(args)

with pytest.raises(AuthorizationError):
    invoke_with_invalid_authority(effect)

assert calls == []
```

Exercise missing and malformed warrants, untrusted roots, wrong holder proof, expiry, wrong capability, every important constraint boundary, wider delegation, bypass paths, and replay if one-use behavior is claimed.
