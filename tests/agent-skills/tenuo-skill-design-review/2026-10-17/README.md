# Adjacent skill design review

This source review covers `tenuo-warrant` and `tenuo-audit`. It supplements the
integration evaluations; these probes do not certify a framework adapter or
an effect boundary. No historical model evaluation was re-fingerprinted.

## Findings corrected

| Severity | Finding | Correction and evidence |
| --- | --- | --- |
| High | The Python issuance example and API reference called nonexistent `MintBuilder.max_depth()`. The terminal instruction also encouraged calling `terminal()` on any builder. | Executed the actual revised Markdown snippet with installed `tenuo==0.3.2`. Its root uses the existing default depth ceiling; the narrower worker child is terminal. Direct probes confirm the two methods are absent from the released high-level mint builder. Current main `tenuo-python/tenuo/builder.py` agrees. A root depth ceiling is not silently claimed. |
| High | Cloud example invented `AsyncTenuoCloudClient.fire_trigger()`. It also described managed issuance as child delegation without establishing a parent link. | Inspected current Cloud `origin/main` client at the recorded commit. Removed the unsupported call, require the resolved client/server issuance contract, and distinguish new root issuance from attenuation. No proprietary implementation copied into this repo. |
| High | Both skills said `_allow_unknown=True` bypassed all declared constraints. | Actual released verifier admits an additional field but still rejects an out-of-range or missing declared amount. Guidance now states precisely which inputs are unchecked. |
| High | Audit procedure could claim a chain valid based on decoded fields without an independently trusted root, signatures or complete chain. It treated static inspection as sufficient evidence of holder proof. | Require real SDK verification of the complete root-to-leaf chain and separate invocation-proof checks. Explicitly reject repairing a missing chain by trusting its intermediate key. Missing-chain, wrong-root and exact-challenge wrong-holder probes fail with valid positive controls. |
| Medium | TypeScript reference conflated top-level empty `allow` with a per-tool empty policy. | On installed `@tenuo/core@0.3.2-beta.0`, `session({allow:{}})` rejects; `allow:{ping:{}}` admits arbitrary `ping` arguments. Wording and executable diagnostics now distinguish them. |
| Medium | Routing depended on developer/security persona instead of requested work. | A developer can request a review; a security engineer can request authority creation. Separate integration work is explicitly handed to the authorization skill. Blind routing validation is recorded separately by the parent reviewer. |
| Medium | Shell/path/URL prose implied constraints alone supplied process or network containment. Audit included an invalid IAM `aws:SourceIp` analogy for UrlSafe and equated Tenuo proof with RFC 9449's wire format. | Narrow claims to the constrained values, explain binary flags and filesystem/network resolution requirements, and label external-system comparisons conceptual. Observe-mode denials and signed receipts are not proof of a blocked/completed effect. |
| Low | Regex wording incorrectly said it could never narrow; example counted three nodes as three delegation hops. | Explain identical-regex/Exact narrowing and root depth 0. |

The example now illustrates task autonomy: same payment tool, approved invoice
and bank account, parent $500 authority, terminal worker $250 authority. The
receiving verifier rejects a signed bank diversion and a signed $400 worker
attempt; the parent can still authorize $400. The snippet itself is issuance
code, and does not pretend to install receiving enforcement.

## Validation

`source-review-results.json` records exact versions, native/declaration hashes,
reviewed source commits and final skill hashes. No private signing material is
persisted. Tests execute the actual Markdown example rather than a copied
approximation:

```bash
/path/to/released-python-venv/bin/python \
  tests/agent-skills/tenuo-skill-design-review/2026-10-17/test_released_warrant_guidance.py

NODE_ENV=test node \
  tests/agent-skills/tenuo-skill-design-review/2026-10-17/test_typescript_guidance.mjs \
  /path/to/project-with-core-0.3.2-beta.0
```

Python: **11 passed**. TypeScript: **5 passed**. Both skill-creator structural
checks and owned-file whitespace checks pass. A grader-development assertion
initially compared the Python `parent_hash` hex string with digest bytes; the
grader was corrected to compare hexadecimal values. No SDK change was needed.

Limits: no installed Cloud runtime or live Cloud API tested; local CLI/source
review does not replace the separate CLI behavior tests; SDK diagnostic calls
do not establish deny-before-effect in a framework. A fresh blind routing pass
is coordinated by the parent reviewer against the final skill files.
