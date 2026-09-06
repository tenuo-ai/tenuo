/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  plugins: ["@stryker-mutator/vitest-runner", "@stryker-mutator/typescript-checker"],
  testRunner: "vitest",
  checkers: ["typescript"],
  tsconfigFile: "packages/mcp/tsconfig.json",
  mutate: ["packages/mcp/src/guard.ts:188-207"],
  testFiles: ["packages/mcp/test/guard.test.ts"],
  vitest: {
    configFile: "packages/mcp/vitest.config.ts",
    related: false,
  },
  concurrency: 2,
  timeoutMS: 10_000,
  mutator: { excludedMutations: ["StringLiteral", "ObjectLiteral"] },
  reporters: ["clear-text", "progress"],
  thresholds: { high: 95, low: 90, break: 90 },
};
