import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  committedWasmSha256,
  resolveSourceCommit,
  sha256,
  sourceIsClean,
} from "./build-provenance.mjs";

const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(coreDir, "package.json"), "utf8"));
const sourceCommit = resolveSourceCommit(coreDir);

const wasm = readFileSync(join(coreDir, "dist", "generated", "tenuo_wasm_bg.wasm"));
const wasmSha256 = sha256(wasm);

writeFileSync(
  join(coreDir, "dist", "build-info.json"),
  `${JSON.stringify(
    {
      package: packageJson.name,
      version: packageJson.version,
      sourceCommit,
      // Qualifies sourceCommit. A build from a dirty tree still names a
      // commit, and without these two flags it would name it as if the
      // artifact came from it.
      sourceClean: sourceIsClean(coreDir),
      wasmSha256,
      wasmMatchesCommit: wasmSha256 === committedWasmSha256(coreDir, sourceCommit),
    },
    null,
    2,
  )}\n`,
);
