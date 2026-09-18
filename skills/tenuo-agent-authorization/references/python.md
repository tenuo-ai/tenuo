# Python integration

Use this reference only for projects using the current `tenuo` Python package. Confirm the resolved package version and inspect its shipped API, framework module, and tests before generating code; adapters evolve faster than the core warrant types.

Do not treat this reference as an API specification. First locate the importable `tenuo` package and its distribution metadata, then inspect the modules used by the project. Python wheels do not reliably include this repository's top-level examples. If local source is insufficient, compare the resolved package with the Python entry in the [release contract](../release.json). Use these immutable sources only when the versions match:

- [MCP server effect-boundary patterns](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-python/examples/mcp_server.py), covered by the repository-wide [example API checks](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-python/tests/examples/test_examples.py) and [MCP integration tests](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-python/tests/adapters/test_mcp_integration.py)
- [Issuer, holder, delegation, PoP, and trusted-root verification](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-python/examples/mcp/mcp_delegation_demo.py), covered by the example API checks and [MCP delegation tests](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-python/tests/adapters/test_mcp_delegation.py)
- [Pinned Python SDK guide](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-python/README.md)

For another version, verify that a `v<version>` tag exists and that `tenuo-python/pyproject.toml` at that tag declares the resolved version before using its examples. Pre-release and language-package versions do not always map mechanically to repository tags.

## Choose the boundary

- Use the top-level `@guard` wrapper for a generic in-process guardrail when that matches the threat model. `GuardBuilder` is not a top-level `tenuo` export; use it only from a supported adapter module, such as `tenuo.openai`, `tenuo.crewai`, `tenuo.autogen`, or `tenuo.google_adk`, after checking the installed adapter API.
- Use `Authorizer` at a server or worker boundary for independent warrant, trust-chain, PoP, capability, and constraint verification.
- For MCP, prefer `MCPVerifier` with the integration's middleware so verification occurs before the tool handler.

Do not generate ephemeral issuer keys at a production enforcement point. Load trusted issuer public keys from independent configuration. Keep issuer and holder signing keys in the principal that owns them; do not serialize bound warrants or private-key-bearing objects into agent or workflow state.

## Current MCP server pattern

Confirm how the installed middleware maps and canonicalizes arguments. When raw handlers are used, call `MCPVerifier.verify` or `verify_or_raise` before the effect and execute with the returned clean arguments.

`require_warrant=False` is a migration mode that permits unwarranted calls. It is not equivalent to enforcement. If used temporarily, name the fallback authorization mechanism and test both warranted and unwarranted paths.

## Current low-level pattern

Do not replace full verification with `allows()` or another policy-only convenience check at a security boundary. Use the installed SDK's full validation path that checks trust and holder proof.

## Policy behavior

Once a capability has constrained arguments, keep unknown arguments rejected. Use `Wildcard()` only for a named field intentionally left broad. `_allow_unknown=True` weakens this protection across the capability and requires explicit justification.

For delegation, the current holder signs the child authority. Bind the child to the recipient's public key, reduce TTL where appropriate, and use terminal authority for a leaf. Verify the installed API rather than assuming `grant`, `grant_builder`, or context-manager syntax.

## Test shape

Use a fake effect that records invocations and assert the record remains empty for every denial. Exercise missing and malformed warrants, untrusted roots, wrong holder proof, expiry, wrong capability, every important constraint boundary, wider delegation, bypass paths, and replay if one-use behavior is claimed.
