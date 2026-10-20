---
title: Local CLI
description: Prepare local identities, trust, and signed revocation lists
---

# Local controller files

The Python package includes `tenuo-cli` alongside the existing `tenuo` command.
No account or running service is required. From an unreleased source checkout,
use `PYTHONPATH=tenuo-python python -m tenuo.local_cli` instead of `tenuo-cli`.
Controller file locking currently supports macOS and Linux.

```bash
pip install tenuo
tenuo-cli init --dev
tenuo-cli key list
tenuo-cli trust list
tenuo-cli doctor
```

`init --dev` automatically prepares three separate identities: the controller
(`issuer`), the agent, and an approver. It trusts the local controller and creates
an empty signed revocation list. Plain `init` creates the layout without keys or
trust. Initialization refuses an existing directory; it never rotates keys.

The default workspace is `.tenuo/`. Change it with `TENUO_HOME` or `--home PATH`.

| Path | Purpose |
| --- | --- |
| `config.yaml` | Strict versioned configuration, defaulting to enforcement |
| `keys/issuer.key` | Controller private key: grants authority |
| `keys/agent.key` | Agent private key: proves it is the recipient |
| `keys/approver.key` | Approver private key: signs held calls |
| `keys/*.pub` | Public keys to exchange after verifying fingerprints |
| `trust/*.pub` | Issuers the verifier accepts |
| `revocations.srl` | Core signed revocation list in native CBOR |
| `warrants/` | Issued warrant chains |
| `requests/`, `approvals/` | Portable requests and responses |

Private files are created with mode `0600`. The workspace ignores its contents
in Git. No signing secrets are written to the application's `.env`. Separate
files under one OS user are **not process isolation**. A deployed agent receives
only its key, warrants and public verification data. Keep controller and approver
private keys outside its runtime mounts and credentials.

## Keys and trust

```bash
tenuo-cli key new another-agent
tenuo-cli trust add --file ./another-issuer.pub
```

Key readers accept base64, hex and PEM. Commands display fingerprints, never
private key bytes. Compare public-key fingerprints through a trusted channel
before adding trust.

## Revocation

```bash
tenuo-cli revocations show
tenuo-cli revocations add --id tnu_wrt_REPLACE_WITH_REAL_ID
```

Updates preserve revoked IDs and increment the signed list version. Writes are
atomic; concurrent local controller updates are serialized. Readers also accept
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

```yaml
version: 2
name: refunds
ttl: 30m
capabilities:
  refund: {order_id: A-1001, amount_cents: 1..12000}
approvals:
  keys: [.tenuo/keys/approver.pub]
  required:
    refund: {unless: {amount_cents: 1..5000}}
```

The signed warrant allows refunds through 12000 cents, but requires one listed
approver for amounts outside the exempt range of 1–5000. An approval cannot
permit a call outside the warrant's capabilities. `required: {refund: always}`
gates every refund. Approver paths are relative to the YAML file. Local key
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
warrant = template.mint(controller_key, agent_public_key)
```

Issuance needs only the recipient's public key. Gates and approvers are embedded
in the signed warrant; verifiers do not trust the YAML file at runtime.

## Issue, inspect and replace warrants

```bash
tenuo-cli warrant issue --template orders.yaml --holder agent --out .tenuo/agent.warrant
tenuo-cli warrant issue --request one-task.yaml
tenuo-cli warrant list
tenuo-cli warrant show --file .tenuo/agent.warrant
tenuo-cli warrant verify --file .tenuo/agent.warrant
```

Issuance saves a native root-first warrant stack in `warrants/<id>.warrant`.
`--out` also writes a delivery copy; `--no-store --out PATH` writes only that
copy. Existing paths are never overwritten. Holder paths in a YAML request are
relative to that document; `holder: agent` resolves the workspace's public key.
The controller does not read the agent's private key.

`show --file PATH` or `show --id ID` decodes the signed authority without trust.
`show --file -` accepts a pasted stack on stdin. `verify` separately checks the
full chain against current local trust, expiry and the signed revocation list.
It exits 3 when verification fails. `list` inventories this workspace's files;
it is not a global inventory of every issued warrant.

```bash
tenuo-cli warrant reissue --id tnu_wrt_REAL_ID --ttl 1h
tenuo-cli warrant issue --from .tenuo/agent.warrant --key agent --request narrowed-task.yaml
```

Reissuance signs a new warrant with a new ID; it never extends or edits the old
warrant. The old warrant remains valid until it expires or is revoked.
Automatic reissue currently accepts only simple root execution warrants whose
claims can be copied exactly. For approval-gated or other richer warrants,
issue explicitly from the reviewed YAML again. Delegation uses the parent
holder's key and native attenuation: tools, limits, approvals and lifetime
cannot exceed the parent. The output always carries its complete chain.

Issuing a warrant does not attach it to a running session or workflow. Deliver
the selected file through the integration's explicit warrant configuration.
Nothing automatically selects the newest warrant or combines stored grants.
