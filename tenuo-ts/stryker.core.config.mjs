/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  plugins: ["@stryker-mutator/vitest-runner", "@stryker-mutator/typescript-checker"],
  testRunner: "vitest",
  checkers: ["typescript"],
  tsconfigFile: "packages/core/tsconfig.json",
  mutate: [
    "packages/core/src/client.ts:283-310",
    "packages/core/src/mcp.ts:84-92",
  ],
  testFiles: [
    "packages/core/test/core.test.ts",
    "packages/core/test/mcp.test.ts",
  ],
  vitest: {
    configFile: "packages/core/vitest.config.ts",
    related: false,
  },
  concurrency: 2,
  timeoutMS: 10_000,
  mutator: { excludedMutations: ["StringLiteral", "ObjectLiteral"] },
  reporters: ["clear-text", "progress"],
  thresholds: { high: 95, low: 90, break: 90 },
};
