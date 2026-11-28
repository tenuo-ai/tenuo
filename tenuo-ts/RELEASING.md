# npm release policy

This policy covers the public `@tenuo/core` and `@tenuo/mcp` packages. The two
packages release in lockstep and use the same npm channel.

## Dist-tags

| Package version | npm dist-tag | Meaning |
|---|---|---|
| `X.Y.Z-beta.N` | `beta` | Public preview; APIs may still change within the documented beta contract. |
| `X.Y.Z-rc.N` | `next` | Stable candidate undergoing final compatibility and packaging qualification. |
| `X.Y.Z` | `latest` | Stable release. |

Other prerelease identifiers fail closed. In particular, no prerelease may be
published on `latest`. `scripts/npm-release-policy.mjs` is the shared executable
contract used by tests, package publish commands, and the release workflow.
Release versions must not contain build metadata because npm strips it during
publication, which would make post-publish verification ambiguous.

The registry historically pointed `latest` at a beta. npm cannot delete
`latest`, so that legacy tag stays until the first stable release replaces it;
release runs warn about it. Release automation will never move a prerelease to
`latest` again, and fails if a published prerelease resolves there.

## Supported runtime and MCP versions

- Node.js 20 is the minimum supported runtime; CI also qualifies Node.js 22 and
  24, plus packed-package installation on Windows.
- `@tenuo/mcp` supports `@modelcontextprotocol/server` v2 according to the peer
  range in its published `package.json`.
- `@tenuo/mcp` must declare a peer range containing the exact `@tenuo/core`
  version being released. Core is published and confirmed visible before MCP.

## Every npm release

- [ ] `@tenuo/core` and `@tenuo/mcp` have the same valid semantic version.
- [ ] `pnpm test:release-policy` passes, including the negative beta-to-latest case.
- [ ] The coordinated repository release tag matches the package version or its
      stable base version. A release whose tag does not match skips npm only
      when both packages are already published at their current version.
- [ ] `TypeScript SDK`, `TypeScript SDK (Node 22)`, `TypeScript SDK (Node 24)`,
      and `TypeScript SDK (Windows pack smoke)` are green.
- [ ] `TypeScript Red Team Tests`, `TypeScript Differential Security`, and
      `TypeScript Mutation Security` are green.
- [ ] Rebuilt public WASM bindings have no generated drift.
- [ ] Core and MCP packed-package smoke tests install their tarballs as external
      consumers and pass.
- [ ] The runnable Node/MCP examples and compatibility lanes are green.
- [ ] Open runnable-example and compatibility blockers are resolved or
      explicitly waived: [#580](https://github.com/tenuo-ai/tenuo/issues/580),
      [#585](https://github.com/tenuo-ai/tenuo/issues/585), and
      [#640](https://github.com/tenuo-ai/tenuo/issues/640).
- [ ] Publishing uses npm provenance and the derived dist-tag.
- [ ] Registry verification confirms both packages resolved on the intended tag.

The named compatibility, packaging, and generated-WASM checks above are
enforced by `.github/workflows/ci.yml`; the three TypeScript security checks
are enforced by `.github/workflows/security.yml`. The version/channel check, packed
consumer smoke tests, provenance-enabled publish, publication ordering, and
registry verification are enforced again by `.github/workflows/release.yml`.
Before a stable publish, the release workflow also requires successful Node 20,
Node 22, Node 24, Windows pack-smoke, and TypeScript security check runs from
GitHub Actions for the exact tagged commit, waiting up to 30 minutes for them
to finish.

## Additional stable-release gate

Before changing the package versions to stable `X.Y.Z`:

- [ ] Public API changes are reviewed for semantic-version compatibility and
      documented in the changelog and package READMEs.
- [ ] The supported Node and MCP ranges above are still accurate.
- [ ] All security, differential, mutation, compatibility, and packed-consumer
      checks named above are required and green on the release commit.
- [ ] The published tarballs contain only the declared `files`, include licenses
      and type declarations, and load without the monorepo present.
- [ ] The generated WASM and JavaScript adapter correspond to the release commit.
- [ ] A release dry run reports `latest` for the stable version and refuses
      `latest` for a representative beta version.
- [ ] The release owner verifies the provenance attestations and final registry
      dist-tags for both packages.

Product adoption targets and private launch criteria are intentionally outside
this package-release gate.

## 0.3.8-beta.0 release scope

For the coordinated 0.3.8 release, the release owner explicitly deferred
[#580](https://github.com/tenuo-ai/tenuo/issues/580),
[#585](https://github.com/tenuo-ai/tenuo/issues/585), and
[#640](https://github.com/tenuo-ai/tenuo/issues/640) on 2026-11-24.
This satisfies the explicit-waiver option in the checklist for this release
only. The issues remain open for later work. Both npm packages remain on the
`beta` channel at `0.3.8-beta.0`; this does not qualify a stable npm release
or waive the CI, security, packaging, or provenance checks above.

## 0.3.9-beta.0 release scope

The coordinated 0.3.9 release retains the Node.js beta scope. The release
owner agreed on 2026-11-27 to defer the broader example and new-runtime
backlog: #580 (wrapped-tool example), #585 (Cloudflare Workers), and #640
(Hono Node example). These remain open and are not blockers for this release.
This does not waive CI, security, packaging, or provenance checks, and neither
package is promoted to the stable npm channel.
