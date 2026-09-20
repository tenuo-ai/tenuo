import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(coreDir, "package.json"), "utf8"));
const sourceCommit = process.env.TENUO_SOURCE_COMMIT
  ?? execFileSync("git", ["rev-parse", "HEAD"], { cwd: coreDir, encoding: "utf8" }).trim();

if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
  throw new Error("TENUO_SOURCE_COMMIT must be a full 40-character Git commit");
}

const wasm = readFileSync(join(coreDir, "dist", "generated", "tenuo_wasm_bg.wasm"));
writeFileSync(
  join(coreDir, "dist", "build-info.json"),
  `${JSON.stringify({
    package: packageJson.name,
    version: packageJson.version,
    sourceCommit,
    wasmSha256: createHash("sha256").update(wasm).digest("hex"),
  }, null, 2)}\n`,
);
