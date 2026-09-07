import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ROOT, type LabState } from "../src/state.ts";

const homes: string[] = [];
const ANSI = /\x1b\[[0-9;]*m/g;

function home(): string {
  const path = mkdtempSync(join(tmpdir(), "tenuo-lab-cli-test-"));
  homes.push(path);
  return path;
}

function cli(labHome: string, command: string, stage?: number, answer?: string): string {
  const args = [join(ROOT, "node_modules", "tsx", "dist", "cli.mjs"), join(ROOT, "src", "cli", "index.ts"), command];
  if (stage !== undefined) args.push("--stage", String(stage));
  const result = spawnSync(process.execPath, args, {
    cwd: ROOT,
    env: {
      ...process.env,
      TENUO_LAB_HOME: labHome,
      ...(answer !== undefined ? { TENUO_LAB_ANSWER: answer } : {}),
      NODE_ENV: "development",
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120_000,
  });
  expect(result.status, result.stderr).toBe(0);
  return `${result.stdout}${result.stderr}`.replace(ANSI, "");
}

afterEach(() => {
  for (const path of homes.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("participant CLI", () => {
  it("leads every stage with the wallet, rogue count, and four-star HUD", () => {
    const labHome = home();
    for (let stage = 1; stage <= 7; stage += 1) {
      const output = cli(labHome, "lab", stage);
      expect(output).toContain("WALLET");
      expect(output).toMatch(/ROGUE ATTEMPTS BLOCKED\s+\d+ \/ \d+/);
      expect(output).toContain("STARS");
      expect(output).toContain("Trip booked");
      expect(output).toContain("Rogue stopped");
      expect(output).toContain("Tight handoff");
      expect(output).toContain("No spare authority");
      if (stage === 1) expect(output).toMatch(/ROGUE ATTEMPTS BLOCKED\s+0 \/ 7/);
    }
  }, 120_000);

  it("records Stage 5 lab attempts but accepts first-green only from the complete attack", () => {
    const labHome = home();
    cli(labHome, "lab", 5);
    let state = JSON.parse(readFileSync(join(labHome, "state.json"), "utf8")) as LabState;
    expect(state.attempts?.["5"]?.count).toBe(1);
    expect(state.attempts?.["5"]?.firstGreen).toBeUndefined();

    cli(labHome, "attack", 5, "answers/05-tenuo/chain.ts");
    state = JSON.parse(readFileSync(join(labHome, "state.json"), "utf8")) as LabState;
    expect(state.attempts?.["5"]?.count).toBe(2);
    expect(state.attempts?.["5"]?.firstGreen).toBeDefined();
    expect(state.attempts?.["5"]?.firstAttempt).not.toEqual(state.attempts?.["5"]?.firstGreen);

    const share = cli(labHome, "share", 5, "answers/05-tenuo/chain.ts");
    expect(share).toMatch(/ROGUE ATTEMPTS BLOCKED \(2 SCENARIOS\)\s+14 \/ 14/);
  }, 120_000);

  it("marks observation stages complete when the documented next command advances them", () => {
    const labHome = home();
    cli(labHome, "next");
    cli(labHome, "next");
    const state = JSON.parse(readFileSync(join(labHome, "state.json"), "utf8")) as LabState;
    expect(state.stage).toBe(3);
    expect(state.completed).toEqual([1, 2]);
  });

  it("does not claim an unreachable stolen-warrant probe was verified", () => {
    const output = cli(home(), "lab", 6, "answers/06-extensions/chain.ts");
    expect(output).toMatch(/ROGUE ATTEMPTS BLOCKED\s+7 \/ 8\s+1 not reached/);
  });

  it("keeps the explorer payload out of normal terminal output", () => {
    const labHome = home();
    const output = cli(labHome, "lab", 5, "answers/05-tenuo/chain.ts");
    expect(output).not.toContain("https://tenuo.ai/explorer/?s=");
    expect(output).toContain("npm run trace -- --open-explorer");
    expect(existsSync(join(labHome, "explorer-stage-5.url"))).toBe(true);
  });
});

describe("generated Stage 5 guide", () => {
  it("keeps the public landing-page promise and one reset command", () => {
    const page = readFileSync(join(ROOT, "..", "..", "docs", "lab", "index.md"), "utf8");
    expect(page).toContain("AI Agent Delegation Security Challenge");
    expect(page).toContain("Book the trip. Stop the rogue agent.");
    expect(page).toContain("A ninety-minute security game");
    expect(page.match(/npm run reset/g)).toHaveLength(1);
  });

  it("keeps the reference implementation out of the page body", () => {
    const page = readFileSync(join(ROOT, "..", "..", "docs", "lab", "stage-5.md"), "utf8");
    expect(page).toContain('<details class="lab-reveal answer"><summary>Show a reference solution</summary>');
    expect(page).toContain("Open the Stage 5 reference on GitHub");
    expect(page).not.toContain("answers/05-tenuo/chain.ts</span>");
  });
});
