---
title: Local CLI
description: Prepare local identities, trust, and signed revocation lists
---

# Local controller files

The Python package includes `tenuo-cli` alongside the existing `tenuo` command.
No account or running service is required. From an unreleased source checkout,
use `PYTHONPATH=tenuo-python python -m tenuo.local_cli` instead of `tenuo-cli`.

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
