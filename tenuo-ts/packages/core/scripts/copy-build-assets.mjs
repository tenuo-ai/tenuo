import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const generatedDir = join(coreDir, "src", "generated");
const outputDir = join(coreDir, "dist", "generated");

mkdirSync(outputDir, { recursive: true });
for (const file of [
  "package.json",
  "tenuo_wasm.js",
  "tenuo_wasm.d.ts",
  "tenuo_wasm_bg.wasm",
  "tenuo_wasm_bg.wasm.d.ts",
]) {
  copyFileSync(join(generatedDir, file), join(outputDir, file));
}
copyFileSync(join(coreDir, "..", "..", "..", "LICENSE"), join(coreDir, "LICENSE"));
