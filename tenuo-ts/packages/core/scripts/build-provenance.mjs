import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

/** Path of the checked-in WASM binary, relative to the repository root. */
export const WASM_SOURCE_PATH = "tenuo-ts/packages/core/src/generated/tenuo_wasm_bg.wasm";

/**
 * Trees whose contents reach the published artifact. `tenuo-core` and
 * `tenuo-wasm` are in the list because the packed WASM is compiled from them.
 */
const SOURCE_PATHS = ["tenuo-ts/packages/core", "tenuo-wasm", "tenuo-core"];

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function git(args, cwd, encoding = "utf8") {
  return execFileSync("git", args, { cwd, encoding, maxBuffer: 256 * 1024 * 1024 });
}

/**
 * The commit the artifact claims to come from. Both the writer and the pack
 * smoke test resolve it here so a `TENUO_SOURCE_COMMIT` build cannot produce
 * an artifact the smoke test then rejects.
 */
export function resolveSourceCommit(cwd) {
  const commit = process.env.TENUO_SOURCE_COMMIT ?? git(["rev-parse", "HEAD"], cwd).trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error("TENUO_SOURCE_COMMIT must be a full 40-character Git commit");
  }
  return commit;
}

/** Whether the trees that feed this artifact have uncommitted changes. */
export function sourceIsClean(cwd) {
  const repoRoot = git(["rev-parse", "--show-toplevel"], cwd).trim();
  return git(["status", "--porcelain", "--", ...SOURCE_PATHS], repoRoot).trim().length === 0;
}

/**
 * Digest of the WASM binary as committed at `commit`.
 *
 * `build` copies the checked-in binary rather than recompiling it, so without
 * this comparison `sourceCommit` and `wasmSha256` only agree with each other.
 * A mismatch is not by itself an error: `pnpm test` recompiles the binary and
 * wasm-pack is not byte-reproducible. It means the packed WASM came from a
 * local build rather than from the commit the artifact names.
 */
export function committedWasmSha256(cwd, commit) {
  const repoRoot = git(["rev-parse", "--show-toplevel"], cwd).trim();
  try {
    return sha256(git(["show", `${commit}:${WASM_SOURCE_PATH}`], repoRoot, null));
  } catch (cause) {
    throw new Error(
      `cannot read ${WASM_SOURCE_PATH} at ${commit}; a full checkout is required to tie the packed WASM to that commit`,
      { cause },
    );
  }
}
