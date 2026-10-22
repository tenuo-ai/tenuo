# TypeScript warrant issuance and delegation

Use this reference only after confirming the resolved `@tenuo/core` version.
The installed `dist/index.d.ts`, shipped README, and `dist/build-info.json` (when
present) are authoritative for that package. Do not combine APIs from `main`
with a released package.

## Vocabulary

| Intent | Current TypeScript API |
|---|---|
| Create an issuer | `createTenuo({ root: createTenuo.issuerKeyFromEnv(...) })` |
| Mint an execution session | `tenuo.session({ allow, holder, ttlSeconds, maxDepth })` |
| Delegate a narrower child | `tenuo.narrow(parent, allow, { holder, ttlSeconds, terminal })` |
| `Subpath(root)` | `under(root)` |
| `Pattern(glob)` | `pattern(glob)` |
| `All([...])` | `all([...])` |
| `UrlSafe(...)` | `urlSafe(...)` |
| `UrlPattern(glob)` | `urlPattern(glob)` |
| `.ttl(seconds)` | `ttlSeconds: seconds` |
| `.terminal()` | `terminal: true` |

In reviewed `@tenuo/core@0.3.2-beta.0`, a per-tool empty policy such as
`allow: { ping: {} }` grants `ping` with arbitrary arguments; it does not mean
a zero-argument capability. Top-level `session({ allow: {} })` without tools
is rejected. Use only zero-argument APIs confirmed in the installed declarations;
pending zero-argument policy work does not change the installed package.

## Grounding checklist

1. Read the resolved package version from the lockfile.
2. Read its shipped README and `dist/index.d.ts`.
3. If `dist/build-info.json` exists, record its `sourceCommit` and `wasmSha256`.
   `sourceCommit` locates the source only when `sourceClean` is true. When
   `wasmMatchesCommit` is false the packed WASM came from a local build rather
   than from that commit. In either case the installed declarations are
   authoritative over anything you read at that commit.
4. Confirm `session()` and `narrow()` option names in the declarations.
5. Generate only issuance or delegation code; enforcement belongs to the
   `tenuo-agent-authorization` skill.
