# Local authority lifecycle (unreleased)

Read this for local setup, YAML warrant requests, issuance, renewal, approvals,
session attachments or local inspection. These helpers are an unreleased Python
SDK feature, not part of the pinned release contract. Verify the actual imported
checkout, native artifact and `tenuo-cli --help` before using them. A `0.3.2`
version string alone does not distinguish the released wheel from a checkout.
If unavailable, use the installed SDK's supported code-first APIs or offer an
explicit source evaluation; do not silently install a branch or invent commands.

## Get to an allowed and denied call

Use the matching checkout's `docs/local-cli.md` and
`tenuo-python/examples/local_cli/orders.yaml` for command/schema details. Keep
API examples in that tested source rather than reimplementing them in a skill.

1. `tenuo-cli init --dev` prepares separate controller, agent and approver keys,
   local trust and an empty signed revocation list. It refuses an existing
   workspace. Developers need not generate or copy private key bytes manually.
2. Use the SDK's shared version-2 YAML parser. A template describes TTL,
   capabilities and optional gates. An ad-hoc request adds `kind: warrant-request`
   and `holder`. Validate with `template validate --file FILE`. Use only the
   constraint forms the parser supports; it does not expose every SDK constraint.
3. `warrant issue --template FILE --holder agent` or `--request FILE` signs a
   grant. The controller needs only the holder's public key. YAML is a proposal;
   editing it does not alter existing signed authority.
4. Explicitly select the warrant in the integration. Prove one real allowed
   effect and an out-of-scope denial with zero effects, using its actual
   dispatcher. An unrelated configuration error is not that demonstration.

Generated untagged public key files use `.pub`; private files use `.key`.
Never pass a private key file as a holder/approver public input or print private
material. Raw Ed25519 public and private values can both contain 32 bytes.
For deployment, give the agent only its own key and public verification data;
keep controller/approver private keys outside its runtime. Separate files under
one user are a development loop, not OS isolation.

## Lifecycle choices

- **Inspect:** `warrant show` decodes; `warrant verify` separately checks the full
  chain, trust, expiry and current SRL. `warrant list` inventories local files,
  not every grant issued anywhere. `audit list`/`audit verify` inspect native
  signed receipts; decision evidence is not proof of completed effects or
  complete history.
- **Renew or change scope:** issue a new warrant. Reissue has a new ID and
  currently supports only simple root grants; richer grants use reviewed YAML
  again. Old grants remain valid until expiry or revocation. No automatic
  renewal or newest-file selection is implied.
- **Delegate:** use `warrant issue --from WARRANT --key HOLDER --request FILE`
  only with the current holder's key. Present the full root-first chain; do not
  add intermediates to root trust to repair missing transport.
- **Approve:** a gated call writes an exact-call request file. An external
  approver uses `approval show`, then `approval approve` or `approval deny` with
  their own key and independently configured trust. Signed warrant keys determine
  eligible approvers. Names are labels, not verified identities. Return the
  response to the runtime's indicated path and retry. Approval cannot widen
  scope, extend the warrant or bypass revocation; it is reusable for the same
  call until expiry, not inherently one-use.
- **Attach:** Hermes shared-local mode reports its session ID on a blocked call.
  An operator uses `session attach --session ID --file WARRANT`; attachments
  survive turns and reload without gateway restart. A child session needs its
  own attachment. Several grants cannot be unioned to authorize one call.
  Attachment routes signed authority; it does not activate it.
- **Revoke:** `revocations add --id ID` updates a signed list. Deliver that list
  to every relevant verifier. Detaching removes one session reference and does
  not invalidate the warrant elsewhere. Rotation and revocation are distinct.

## Integration limits

Check each factory independently before choosing it: `TenuoTool.local` for
LangChain/LangGraph, `SecureMCPClient.local` plus server `MCPVerifier.local`,
`TenuoPluginConfig.local` for Temporal, and Hermes-Tenuo's `local_home` setting
in a matching plugin checkout. The plugin has its own version/installation.

Local adapters require enforcement mode and refresh verification data before
protected calls. Client-only/in-process checks remain bypassable by direct
resource access. A public-only verifier does not need the agent private key.
Issuing a file does not replace a running Temporal workflow's warrant or
implement dynamic Nexus trust refresh. File delivery is operator-controlled;
SRL version floors are in memory, not persisted across restart. Receipt I/O
failure is logged without retrying a possibly completed effect.

These workflows require no Cloud account. Cloud can later manage issuance,
distribution and identities without changing the issuer/holder/verifier split.
