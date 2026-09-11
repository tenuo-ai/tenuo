# Contributing to Tenuo

Thank you for contributing to Tenuo. This repository contains Rust, Python, and
TypeScript projects with different development requirements. You only need the
toolchain for the part you are changing.

## Before you start

Except for small typo fixes and obvious documentation corrections, open an
issue before writing code. Describe the problem and expected behavior so we can
align on the approach and avoid duplicate work.

Good places to begin:

- [`good first issue`](https://github.com/tenuo-ai/tenuo/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22)
- [`help wanted`](https://github.com/tenuo-ai/tenuo/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22help%20wanted%22)
- [`typescript`](https://github.com/tenuo-ai/tenuo/issues?q=is%3Aissue%20state%3Aopen%20label%3Atypescript)

Security vulnerabilities should not be filed as public issues. Follow
[`SECURITY.md`](SECURITY.md) instead.

## Clone the repository

```bash
git clone https://github.com/tenuo-ai/tenuo.git
cd tenuo
```

Choose the setup below for the project you are changing.

## TypeScript and JavaScript SDK

The TypeScript workspace publishes two Node.js packages:

```text
tenuo-ts/
  packages/core/   @tenuo/core — tools, sessions, policies, and WASM enforcement
  packages/mcp/    @tenuo/mcp  — official MCP v2 server adapter
```

Start with the [TypeScript SDK guide](tenuo-ts/README.md) for the public API and
security model.

### Prerequisites

- Node.js 20 or newer
- pnpm 9.15.9, as pinned by `tenuo-ts/package.json`

Rust and `wasm-pack` are not required for ordinary TypeScript-only changes. The
generated Node.js WASM package is committed so contributors can install, test,
and run examples without compiling Rust first.

### Install

Node.js 20 through 24 normally include Corepack:

```bash
cd tenuo-ts
corepack enable
```

Corepack is no longer distributed with Node.js 25 and newer. On those versions,
or when `corepack` is unavailable, install the pinned pnpm version directly:

```bash
npm install --global pnpm@9.15.9
```

Then install the workspace dependencies:

```bash
cd tenuo-ts
pnpm install
```

Run all subsequent TypeScript commands from `tenuo-ts/`.

> The root Makefile targets are not substitutes for these commands.
> `make build-wasm` builds the Explorer's browser target, not the Node.js WASM
> package under `packages/core/src/generated/`, and `make test-ts` skips when
> `tenuo-ts/node_modules` is absent. For the Node.js SDK, install dependencies
> first and use the `pnpm` commands below, including `pnpm build:wasm`.

### Fast development loop

For changes to TypeScript source, tests, examples, or documentation:

```bash
pnpm typecheck
pnpm --filter @tenuo/core test
pnpm --filter @tenuo/mcp test
```

Run a single test file while iterating:

```bash
pnpm --filter @tenuo/core exec vitest run test/core.test.ts
pnpm --filter @tenuo/mcp exec vitest run test/guard.test.ts
```

Run one named test or suite:

```bash
pnpm --filter @tenuo/core exec vitest run test/core.test.ts -t "narrow"
```

Vitest watch mode is also available in either package:

```bash
pnpm --filter @tenuo/core test:watch
pnpm --filter @tenuo/mcp test:watch
```

Security-sensitive TypeScript changes should also run the randomized boundary
suite and mutation gate. The Python binding must be importable for the
cross-runtime differential test; CI builds it automatically.

```bash
pnpm --filter @tenuo/core exec vitest run test/wasm-boundary.property.test.ts
pnpm --filter @tenuo/core exec vitest run test/differential.property.test.ts
pnpm test:mutation
```

Property failures report a replayable fast-check seed. Set `FC_SEED` to replay
it locally; `FC_RUNS` and `FC_BOUNDARY_RUNS` control the run counts.

### Full WASM-backed validation

Run the full workspace test before opening a pull request that changes runtime
behavior:

```bash
pnpm test
```

This rebuilds `tenuo-wasm`, then runs both package suites. It additionally
requires:

- The latest stable Rust toolchain
- The `wasm32-unknown-unknown` Rust target
- `wasm-pack`

One possible setup is:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

Rebuild the generated package directly after changing `tenuo-wasm`:

```bash
pnpm build:wasm
```

Do not edit files under `packages/core/src/generated/` by hand. Commit generated
changes only when the Rust/WASM source changed.

### Build and test package tarballs

Changes to exports, public types, package metadata, WASM loading, or MCP peer
dependencies should also test the packages as an external consumer:

```bash
pnpm --filter @tenuo/core build
pnpm --filter @tenuo/core pack:smoke
pnpm --filter @tenuo/mcp build
pnpm --filter @tenuo/mcp pack:smoke
```

The smoke scripts create temporary projects and install packed tarballs. They
catch problems that workspace imports can hide.

Published source maps follow one policy in both packages, and the smoke
scripts fail when it drifts. JavaScript maps embed the original TypeScript
(`inlineSources`), because the tarball ships `dist` only and the `../src/*.ts`
paths inside a map point at files consumers never receive. Declaration maps
(`.d.ts.map`) are not emitted: TypeScript 5.8 does not embed source in them,
and shipping `src` just to serve editor navigation would also ship build
inputs. Editors fall back to the published `.d.ts` files.

### Run the MCP scenarios

```bash
pnpm example:mcp          # quarterly-close wire scenario
pnpm example:mcp:host     # official MCP v1 recipe
pnpm example:mcp:adapter  # @tenuo/mcp v2 adapter tests
```

### TypeScript contribution rules

- Keep `@tenuo/core` independent of agent frameworks and MCP framework
  packages. Framework-specific code belongs in an adapter package.
- Authorization decisions must continue to run in Rust/WASM. TypeScript may
  validate configuration and adapt transports, but it must not recreate the
  policy engine.
- A protected tool implementation must never run before an allow decision.
- Treat host schemas such as Zod as validation, not authorization policy.
- Preserve fail-closed behavior for missing sessions, invalid warrants,
  untrusted roots, replay-store failures, and malformed inputs.
- Do not add passthrough, audit-and-run, or mock-authorizer paths.
- Public API changes need type-level tests as well as runtime tests.
- Keep error messages useful without exposing secrets or original handler
  exceptions to remote clients.

If a proposed change affects warrant formats, canonicalization, signatures,
delegation, approvals, revocation, receipts, or replay protection, call that out
on the issue before implementation. Those changes require protocol and security
review.

## Rust core

### Prerequisites

- Latest stable Rust toolchain, installed with [rustup](https://rustup.rs/)

Run formatting, linting, and tests from the repository root:

```bash
cd tenuo-core
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Changes shared with the TypeScript SDK may also require rebuilding
`tenuo-wasm`; see [Full WASM-backed validation](#full-wasm-backed-validation).

## Python SDK

### Prerequisites

- Python 3.9 or newer
- Latest stable Rust toolchain
- `uv` and `maturin`

Create an environment from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install uv
uv pip install -e "./tenuo-python[dev]"
cd tenuo-python
maturin develop
```

Run the Python tests from `tenuo-python/`:

```bash
python -m pytest
```

The repository-level check script runs the broader Rust, Python, and Explorer
validation:

```bash
cd ..
./scripts/check.sh --check
```

It is intentionally broader than the TypeScript workflow and requires the
corresponding toolchains.

## Framework integrations

Before adding or changing an integration:

- Review the [Python Integration Guide](tenuo-python/docs/integration-guide.md)
  for enforcement patterns and invariants.
- Study a maintained integration with a similar lifecycle.
- Keep authorization at the actual dispatch boundary.
- Test fail-closed behavior, expiry, narrowing, and handler non-execution after
  denial.
- Add a compatibility test for the supported upstream version range.

Upstream API changes are monitored through Dependabot, the compatibility
matrix, and release-monitor workflows. When responding to a breaking change:

1. Review the upstream changelog.
2. Reproduce the failure with a focused compatibility test.
3. Update the integration without weakening enforcement.
4. Update `docs/compatibility-matrix.md` when the supported range changes.
5. Run the relevant examples and package tests.

## Pull request process

1. Start from the latest `main` and create a focused branch.
2. Keep the pull request scoped to one issue or closely related change.
3. Add tests for behavior and public type changes.
4. Run the checks for the project you changed.
5. Update examples and documentation when the public experience changes.
6. Reference the issue in the pull request description, for example
   `Closes #123`.
7. Explain any security-boundary or compatibility implications explicitly.

CI runs additional cross-language, integration, packaging, and security checks.
A contributor is not expected to install every repository toolchain for a
change confined to one project.

## Code style

- Rust: `rustfmt` and Clippy
- Python: Ruff and mypy
- TypeScript: the repository TypeScript configuration and existing local style

Avoid unrelated formatting or cleanup in a focused pull request.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache-2.0 License](LICENSE).
