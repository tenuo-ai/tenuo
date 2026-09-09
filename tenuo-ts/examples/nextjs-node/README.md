# Next.js Node-runtime example

This minimal App Router application protects a server-side operation with `@tenuo/core`. The route allows reads under `/data` and returns an authorization denial for other paths.

## Run the example

Use Node.js 20.9 or newer. No external credentials or Tenuo service are required.

```sh
cd tenuo-ts/examples/nextjs-node
npm install
npm run dev
```

Open `http://localhost:3000` and follow the allowed and denied request links.

The application sets `runtime = "nodejs"` on the route and configures `serverExternalPackages: ["@tenuo/core"]`. `@tenuo/core` is a Node.js WASM package in the current beta; browser and Edge runtimes are not supported. Consumers import only from `@tenuo/core` and do not import generated WASM files or run `wasm-pack`.

## Verify the local packed package

From `tenuo-ts`, build `@tenuo/core`, then run the isolated production check:

```sh
pnpm --filter @tenuo/core build
node examples/nextjs-node/scripts/verify-packed.mjs
```

The check packs the local `@tenuo/core`, installs its tarball into a temporary copy of this example (never a workspace link), runs TypeScript and `next build`, starts `next start`, and verifies both the allowed `200` and denied `403` responses. Temporary dependencies and build output are removed afterward.
