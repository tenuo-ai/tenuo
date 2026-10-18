# Independent local-first review

This round records executable checks and source review after the user made local
Tenuo the primary onboarding experience, with optional Cloud use/migration. It is
not a renewal of historical coding-agent evaluations. See results.json for exact
inputs, tested leaf and limitations.

72 script tests, 38 rebuilt-main dispatch cases, 8 quickstart test methods
(including five real framework commands), 11 released Python warrant probes and
5 installed TypeScript probes passed. The independent local-CLI leaf run passed
89 focused cases plus 3 live Temporal cases. independent_cli_demo.py invokes the
actual CLI before testing a real LangChain tool boundary; its temporary keys and
workspace are deleted on completion.

Two fresh routing attempts selected tenuo-warrant for issuance and tenuo-audit
for review-only work, then hit the account usage limit. They did not finish and
are not passing behavior evidence. Existing behavioral results remain stale, so
distribution readiness remains NOT READY. No Cloud or provider/model API called.

The first native rebuild failed during wheel decompression while two builds used
the same source output location. Its log is retained; a sequential rebuild
passed. New runner attestations bind exact native bytes to source fingerprints.

The new CLI head changes workspace placement; that delta was inspected, but the
recorded tests apply to the exact older leaf in results.json. Same-user paths
outside a project do not establish OS isolation.
