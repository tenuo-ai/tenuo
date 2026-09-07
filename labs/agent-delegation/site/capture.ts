/**
 * Run the real CLI and keep what it printed, so the "what you should see"
 * panels on the site are never typed by hand and never drift from the code.
 *
 * Each run gets a throwaway state directory (TENUO_LAB_HOME) and, when an
 * answer file is given, runs that instead of the exercise as shipped
 * (TENUO_LAB_ANSWER). Nothing the participant has on disk is touched.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ROOT } from "../src/state.ts";

const ANSI = /\x1b\[[0-9;]*m/g;
const cache = new Map<string, string>();

export function capture(cmd: string, stage: number, answer?: string): string {
  const key = `${cmd}:${stage}:${answer ?? ""}`;
  const hit = cache.get(key);
  if (hit !== undefined) {
    return hit;
  }
  const home = mkdtempSync(join(tmpdir(), "tenuo-lab-site-"));
  try {
    const result = spawnSync(process.execPath, [join(ROOT, "node_modules", "tsx", "dist", "cli.mjs"), join(ROOT, "src", "cli", "index.ts"), cmd, "--stage", String(stage)], {
      cwd: ROOT,
      env: {
        ...process.env,
        TENUO_LAB_HOME: home,
        ...(answer !== undefined ? { TENUO_LAB_ANSWER: answer } : {}),
        // Captured pages must not send events, whatever the builder's own install says.
        TENUO_LAB_EVENTS_URL: "http://127.0.0.1:9/",
        NODE_ENV: "development",
      },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 120_000,
    });
    if (result.status !== 0) {
      throw new Error(`capture ${key} failed (exit ${result.status}):\n${result.stderr}`);
    }
    const text = (result.stdout + result.stderr)
      .replace(ANSI, "")
      // Fresh keys every run: keep the pages stable.
      .replace(/https:\/\/tenuo\.ai\/explorer\/\?s=[A-Za-z0-9+/=]+/g, "https://tenuo.ai/explorer/?s=…")
      .replace(/tnu_wrt_[0-9a-f]+/g, "tnu_wrt_…")
      .replace(/\b[0-9a-f]{12}(?:[0-9a-f]{52})?…?/g, "…")
      .replace(/[ \t]+$/gm, "")
      .replace(/\s+$/, "");
    cache.set(key, text);
    return text;
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}
