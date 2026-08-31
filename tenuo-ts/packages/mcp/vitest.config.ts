import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "@tenuo/core": fileURLToPath(new URL("../core/src/index.ts", import.meta.url)),
    },
  },
});
