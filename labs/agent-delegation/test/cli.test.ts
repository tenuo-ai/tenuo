import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ROOT, type AttemptSnapshot, type LabState } from "../src/state.ts";

const homes: string[] = [];
const ANSI = /\x1b\[[0-9;]*m/g;

function home(): string {
  const path = mkdtempSync(join(tmpdir(), "tenuo-lab-cli-test-"));
  homes.push(path);
  return path;
}

function cli(labHome: string, command: string, stage?: number, answer?: string): string {
  // Use Node's loader entry directly: unlike the tsx CLI it does not need an
  // IPC socket, so this end-to-end test also runs in locked-down CI sandboxes.
  const args = ["--import", "tsx", join(ROOT, "src", "cli", "index.ts"), command];
  if (stage !== undefined) args.push("--stage", String(stage));
  const result = spawnSync(process.execPath, args, {
    cwd: ROOT,
    env: {
      ...process.env,
      TENUO_LAB_HOME: labHome,
      TENUO_LAB_EVENTS_URL: "off",
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

    const attack = cli(labHome, "attack", 5, "answers/05-tenuo/chain.ts");
    expect(attack).toContain("npm run star");
    expect(attack).toContain("works locally and in Codespaces");
    state = JSON.parse(readFileSync(join(labHome, "state.json"), "utf8")) as LabState;
    expect(state.attempts?.["5"]?.count).toBe(2);
    expect(state.attempts?.["5"]?.firstGreen).toBeDefined();
    expect(state.attempts?.["5"]?.firstAttempt).not.toEqual(state.attempts?.["5"]?.firstGreen);

    const share = cli(labHome, "share", 5, "answers/05-tenuo/chain.ts");
    expect(share).toMatch(/ROGUE ATTEMPTS BLOCKED \(2 SCENARIOS\)\s+14 \/ 14/);
    expect(share).toContain("npm run star");
    expect(share).toContain("works locally and in Codespaces");
    const report = JSON.parse(readFileSync(join(labHome, "share-stage-5.json"), "utf8")) as {
      schema: string;
      sessionId: string;
      challengeVersion: string;
      sdkVersion: string;
      stage: number;
      runtime: { nodeMajor: number; platform: string };
      attempts: { count: number; firstAttempt: AttemptSnapshot; firstGreen?: AttemptSnapshot };
    };
    expect(report.schema).toBe("tenuo-lab-share-v2");
    expect(report.stage).toBe(5);
    expect(report).toMatchObject({
      challengeVersion: "0.2.0",
      sdkVersion: "0.2.5-beta.0",
      runtime: { nodeMajor: expect.any(Number), platform: expect.any(String) },
    });
    expect(report.sessionId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(report.attempts.count).toBe(2);
    expect(report.attempts.firstAttempt.starsMissing.length).toBeGreaterThan(0);
    const firstGreen = report.attempts.firstGreen;
    expect(firstGreen).toBeDefined();
    if (firstGreen === undefined) throw new Error("share artifact omitted the first green attempt");
    expect(firstGreen.starsMissing).toEqual([]);
    for (const attempt of [report.attempts.firstAttempt, firstGreen]) {
      const handoffs = attempt.handoffs;
      expect(handoffs).toBeDefined();
      if (handoffs === undefined) throw new Error("share artifact omitted handoff telemetry");
      expect(Object.keys(handoffs)).toEqual(["flight-to-checkin", "checkin-to-boarding"]);
      for (const handoff of Object.values(handoffs)) {
        if (handoff === "missing" || handoff === null) continue;
        expect(Object.keys(handoff).sort()).toEqual(["constraintChecks", "holderBound", "tools", "ttl"]);
      }
    }
    const serialized = JSON.stringify(report);
    expect(serialized).not.toMatch(/Alice|Cancún|source|privateKey|publicKey|timestamp/i);
    expect(serialized).not.toMatch(/[0-9a-f]{64}/i);
    expect(share).toContain("Submission disabled; no data left this machine.");
    expect(share).toContain("--username YOUR_GITHUB_USERNAME");
  }, 120_000);

  it("shares the Stage 5 handoff history from the final boss level", () => {
    const labHome = home();
    cli(labHome, "lab", 5);
    cli(labHome, "attack", 5, "answers/05-tenuo/chain.ts");

    const share = cli(labHome, "share", 7, "answers/07-incident/chain.ts");
    expect(share).toContain("Sharing the Stage 5 first-attempt → first-green handoff scorecard.");
    expect(share).toMatch(/ROGUE ATTEMPTS BLOCKED \(2 SCENARIOS\)\s+14 \/ 14/);
    expect(existsSync(join(labHome, "share-stage-7.json"))).toBe(false);

    const report = JSON.parse(readFileSync(join(labHome, "share-stage-5.json"), "utf8")) as {
      stage: number;
      attempts: { firstAttempt?: AttemptSnapshot; firstGreen?: AttemptSnapshot };
    };
    expect(report.stage).toBe(5);
    expect(report.attempts.firstAttempt?.handoffs).toBeDefined();
    expect(report.attempts.firstGreen?.handoffs).toBeDefined();
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

  it("explains the decision and expectation symbols in the attack output", () => {
    const output = cli(home(), "attack", 1);
    expect(output).toContain("ALLOWED / DENIED = authorization decision");
    expect(output).toContain("✓ = expected result");
    expect(output).toContain("✗ = unexpected result");
  });

  it("treats the deliberately broken Stage 6 handoff as an outcome, not a zero score", () => {
    const output = cli(home(), "score", 6, "answers/06-extensions/chain.ts");
    expect(output).toContain("TERMINAL HANDOFF");
    expect(output).toContain("deliberately terminal link blocked");
    expect(output).toContain("not scored out of 100");
    expect(output).toContain("Stage 6 done.");
    expect(output).not.toContain("gated");
    expect(output).not.toContain("/ 100");
  });

  it("sends participants to the wrap-up after the final stage", () => {
    const labHome = home();
    for (let stage = 1; stage < 7; stage += 1) cli(labHome, "next");
    const output = cli(labHome, "next");
    expect(output).toContain("Challenge complete.");
    expect(output).toContain("https://tenuo.ai/lab/wrap-up");
    expect(output).toContain("npm run share");
    expect(output).toContain("npm run star");
    expect(output).not.toContain("Stages run 1 to 7");
  });

  it("keeps the explorer payload out of normal terminal output", () => {
    const labHome = home();
    const output = cli(labHome, "lab", 5, "answers/05-tenuo/chain.ts");
    expect(output).not.toContain("https://tenuo.ai/explorer/?s=");
    expect(output).toContain("npm run trace -- --open-explorer");
    expect(existsSync(join(labHome, "explorer-stage-5.url"))).toBe(true);
  });
});

describe("generated lab guide", () => {
  it("keeps the public landing-page promise and one reset command", () => {
    const page = readFileSync(join(ROOT, "..", "..", "docs", "lab", "index.md"), "utf8");
    expect(page).toContain("AI Agent Delegation Security Challenge");
    expect(page).toContain("Book the trip. Stop the rogue agent.");
    expect(page).toContain("A ninety-minute security challenge");
    expect(page).not.toMatch(/security (?:game|lab)/);
    expect(page).toContain("The core challenge runs locally");
    expect(page).toContain("only <code>npm run share</code> and the optional star command use the network");
    expect(page).not.toContain("skip if you are not signed in");
    expect(page).toContain('<details class="lab-reveal lab-expect">');
    expect(page).toContain("5 stages · about 90 min · 2 optional bosses");
    expect(page).toContain("Retries are free, speed is not scored");
    expect(page.match(/npm run reset/g)).toHaveLength(1);
    const deployWorkflow = readFileSync(join(ROOT, "..", "..", ".github", "workflows", "docs.yml"), "utf8");
    expect(deployWorkflow).toContain("A ninety-minute security challenge");
    expect(deployWorkflow).not.toMatch(/A ninety-minute security (?:game|lab)/);
  });

  it("keeps the first action focused on setup and offers the optional star in both terminals", () => {
    const page = readFileSync(join(ROOT, "..", "..", "docs", "lab", "index.md"), "utf8");
    const layout = readFileSync(join(ROOT, "..", "..", "docs", "_layouts", "lab.html"), "utf8");
    expect(page).not.toContain("Run the breach");
    expect(page).not.toContain("data-lab-browser-run");
    expect(layout).not.toContain("lab-browser-run");
    expect(page.match(/npm run star/g)).toHaveLength(2);
    expect(page).toMatch(/git clone[\s\S]*npm install[\s\S]*npm run star[\s\S]*npm run lab/);
    expect(page).toMatch(/At the Codespaces terminal:[\s\S]*npm run star[\s\S]*npm run lab/);
  });

  it("uses the challenge artwork on the homepage and its social card", () => {
    const page = readFileSync(join(ROOT, "..", "..", "docs", "lab", "index.md"), "utf8");
    const layout = readFileSync(join(ROOT, "..", "..", "docs", "_layouts", "default.html"), "utf8");
    const artwork = readFileSync(join(ROOT, "..", "..", "docs", "images", "challenge-image.svg"), "utf8");
    expect(page).toContain('og_title: "Security Challenge: Stop a Rogue AI Agent From Ruining Your Trip"');
    expect(page).toContain('description: "Give each agent only the authority its part of the trip needs. A free, hands-on lab in AI agent delegation security."');
    expect(page).toContain('og_image: "/images/challenge-image.png"');
    expect(page).toContain("og_image_width: 1200");
    expect(page).toContain("og_image_height: 630");
    expect(page).toContain('<img src="/images/challenge-image.svg" width="1200" height="630"');
    expect(page.indexOf("challenge-image.svg")).toBeLessThan(page.indexOf("git clone"));
    expect(existsSync(join(ROOT, "..", "..", "docs", "images", "challenge-image.png"))).toBe(true);
    expect(existsSync(join(ROOT, "..", "..", "docs", "images", "challenge-image.svg"))).toBe(true);
    expect(artwork).toContain("#040a0f");
    expect(artwork).toContain("#38bdf8");
    expect(artwork).not.toContain("#137a76");
    expect(artwork).toContain('width="620" height="310"');
    expect(layout).toContain('<meta property="og:title" content="{{ social_title }}">');
    expect(layout).toContain('<meta name="twitter:title" content="{{ social_title }}">');
  });

  it("links the IETF draft and repeats star and share at the end of the lab", () => {
    const wrapUp = readFileSync(join(ROOT, "..", "..", "docs", "lab", "wrap-up.md"), "utf8");
    const contribute = readFileSync(join(ROOT, "..", "..", "docs", "lab", "contribute.md"), "utf8");
    expect(wrapUp).toContain('href="https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/"');
    expect(wrapUp).toContain("npm run star");
    expect(wrapUp).toContain("npm run share");
    expect(contribute).toContain("npm run star");
  });

  it("states both secure Stage 4 branches and names their intentional over-grant", () => {
    const overview = readFileSync(join(ROOT, "..", "..", "docs", "lab", "index.md"), "utf8");
    const stage4 = readFileSync(join(ROOT, "..", "..", "docs", "lab", "stage-4.md"), "utf8");
    expect(overview).toContain("either per-task identities backed by a registry or a policy service");
    expect(stage4).toContain("Whichever secure fix you use");
    expect(stage4).not.toContain("Whichever fix you use");
    expect(stage4).toContain("checkin-agent:trip-alice-cun");
    expect(stage4).toContain("Act 2 exploits exactly this over-grant");
  });

  it("keeps the reference implementation out of the page body", () => {
    const page = readFileSync(join(ROOT, "..", "..", "docs", "lab", "stage-5.md"), "utf8");
    expect(page).toContain('<details class="lab-reveal answer"><summary>Show a reference solution</summary>');
    expect(page).toContain("Open the Stage 5 reference on GitHub");
    expect(page).not.toContain("answers/05-tenuo/chain.ts</span>");
  });

  it("connects every stage to a familiar infrastructure pattern", () => {
    const pages = Array.from({ length: 7 }, (_, index) => readFileSync(join(ROOT, "..", "..", "docs", "lab", `stage-${index + 1}.md`), "utf8"));
    for (const page of pages) expect(page).toContain("How this maps to familiar infrastructure");
    expect(pages[1]).toMatch(/service account, workload identity, or IAM role/);
    expect(pages[4]).toContain("Copying the permission alone is not enough to use it");
    expect(pages[5]).toContain("the permission works only for the agent that holds the matching private key");
    expect(pages[5]).toContain("prevents it from passing that authority to another agent");
  });
});
