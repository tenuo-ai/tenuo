/**
 * The commands.
 *
 *   npm run lab        start or resume where you left off
 *   npm run trace      watch the agents work, with every decision shown
 *   npm run attack     run the rogue behavior and the security tests
 *   npm run score      see your score and why
 *   npm run audit      what every agent can currently do
 *   npm run next       move to the next stage
 *   npm run share      write an anonymized score breakdown you can hand to your host
 *   npm run reset      back to stage 1
 */
process.env.NODE_ENV ??= "development";

import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { runBattery, type ProbeResult } from "../harness/attacks.ts";
import { checkFunctionality, type Functionality } from "../harness/functionality.ts";
import { measureMargin, type Margin } from "../harness/margin.ts";
import { runScenario, type Built } from "../harness/run.ts";
import { score, type Score } from "../harness/score.ts";
import type { AuditRecord } from "../audit.ts";
import { AGENTS } from "../mission.ts";
import { LAB_HOME, loadState, ROOT, saveState } from "../state.ts";
import { STAGES, stage as stageDef, type Scenario, type StageDef } from "../stages.ts";
import { recordAttempt, snapshot } from "../telemetry.ts";

const SITE = "https://tenuo.ai";

function guideUrl(n: number): string {
  const params = new URLSearchParams();
  const done = [...loadState().completed].sort((a, b) => a - b);
  if (done.length > 0) params.set("done", done.join(","));
  const query = params.toString();
  return `${SITE}/lab/stage-${n}${query.length > 0 ? `?${query}` : ""}`;
}

function openInBrowser(url: string): void {
  const [bin, pre] = process.platform === "darwin" ? ["open", []] : process.platform === "win32" ? ["cmd", ["/c", "start", ""]] : ["xdg-open", []];
  try {
    spawn(bin, [...pre, url], { detached: true, stdio: "ignore" }).on("error", () => undefined).unref();
  } catch {
    // No browser here (CI, a container): the link is printed anyway.
  }
}

const args = process.argv.slice(2);
const command = args[0] ?? "lab";
const flag = (name: string): string | undefined => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
const pad = (s: string, n: number) => (s.length >= n ? s : s + " ".repeat(n - s.length));

function header(def: StageDef, scenario: Scenario): void {
  console.log("");
  console.log(bold(`Stage ${def.n} of ${STAGES.length}: ${def.title}`) + dim(`   mode=${def.mode}  scenario=${scenario}`));
  console.log(dim(`  guide: ${guideUrl(def.n)}`));
  console.log("");
}

function explorerLink(built: Built): string | undefined {
  const tenuo = built.runtime.tenuo;
  const trip = built.plan.trips[0];
  if (tenuo === undefined || trip === undefined) return undefined;
  const session = tenuo.session("boarding-agent", trip.taskId) ?? tenuo.session("checkin-agent", trip.taskId) ?? tenuo.session("flight-agent", trip.taskId);
  if (session === undefined) return undefined;
  const chain = session.toWire();
  const state = {
    chain,
    warrant: chain[chain.length - 1],
    rootKey: session.inspect().rootPublicKey,
    tool: "issue_boarding_pass",
    args: JSON.stringify({ reservation: trip.expectedReservation }),
  };
  return `${SITE}/explorer/?s=${Buffer.from(JSON.stringify(state)).toString("base64")}`;
}

function printExplorerLink(built: Built): void {
  const url = explorerLink(built);
  if (url !== undefined) {
    mkdirSync(LAB_HOME, { recursive: true });
    const file = join(LAB_HOME, `explorer-stage-${built.runtime.stage.n}.url`);
    writeFileSync(file, `${url}\n`);
    if (args.includes("--open-explorer")) {
      openInBrowser(url);
      console.log(dim("  Opened the held warrant chain in the explorer."));
    } else {
      console.log(dim(`  Explorer link saved as ${basename(file)} in the lab state directory.`));
      console.log(dim("  Run npm run trace -- --open-explorer to open it."));
    }
    console.log("");
  }
}

function walletLine(built: Built): string {
  return built.plan.trips
    .map((t) => `${t.traveler.split(" ")[0]}: $${built.runtime.world.balance(t.taskId)} of $${t.budget}`)
    .join("   ");
}

function blockedCount(probes: readonly ProbeResult[]): { blocked: number; total: number; unverified: number } {
  const rogue = probes.filter((probe) => probe.category === "blocked");
  return {
    blocked: rogue.filter((probe) => probe.ok && probe.actual === "DENIED").length,
    total: rogue.length,
    unverified: rogue.filter((probe) => !probe.ok && probe.actual === "DENIED").length,
  };
}

function printHud(wallet: string, probes: readonly ProbeResult[], s?: Score, scenarios = 1): void {
  const rogue = blockedCount(probes);
  console.log(bold("WALLET  ") + wallet);
  const scope = scenarios > 1 ? ` (${scenarios} SCENARIOS)` : "";
  const unverified = rogue.unverified > 0 ? dim(`   ${rogue.unverified} not reached`) : "";
  console.log(bold(`ROGUE ATTEMPTS BLOCKED${scope}  `) + `${rogue.blocked} / ${rogue.total}${unverified}`);
  if (s !== undefined) {
    const stars = s.stars.map((star) => star.earned ? green("★") : dim("☆")).join("");
    console.log(bold("STARS   ") + stars);
    for (const star of s.stars) console.log(`  ${star.earned ? green("★") : dim("☆")} ${star.label}`);
  }
  console.log("");
}

function printExerciseError(built: Built): boolean {
  const error = built.exercise?.error;
  if (error === undefined) {
    return false;
  }
  console.log(red(`Your file did not load: ${built.exercise?.path}`));
  console.log("");
  console.log(`  ${error.split("\n")[0]}`);
  console.log("");
  return true;
}

function decisionMark(r: AuditRecord): string {
  return r.decision === "ALLOWED" ? green("ALLOWED") : red("DENIED ");
}

function printTrace(records: readonly AuditRecord[], full: boolean): void {
  for (const r of records) {
    if (!full && r.source === "probe") continue;
    const src = r.source === "injected" ? yellow("injected") : r.source === "probe" ? dim("probe   ") : r.source === "handoff" ? "handoff " : "trip    ";
    const cc = r.centralCalls > 0 ? dim(`  central_calls: ${r.centralCalls}`) : "";
    console.log(`  ${pad(String(r.seq), 3)} ${src} ${pad(r.agent, 15)} ${pad(r.task, 15)} ${pad(r.action, 28)} ${pad(r.resource, 15)} ${decisionMark(r)}${cc}`);
    if (r.decision === "DENIED" || full) {
      console.log(dim(`      reason: ${r.reason}${r.code !== undefined ? `  [${r.code}]` : ""}`));
    }
  }
}

function printFunctionality(f: Functionality): void {
  console.log(bold("THE TRIP"));
  for (const s of f.steps) {
    console.log(`  ${s.ok ? green("✓") : red("✗")} ${pad(s.trip, 15)} ${s.step}${s.ok ? "" : dim(`   ${s.detail}`)}`);
  }
  if (f.damage.length > 0) {
    console.log("");
    console.log(bold(yellow("WHAT ELSE HAPPENED")));
    for (const d of f.damage) {
      console.log(`  ${yellow("!")} ${d}`);
    }
  }
  console.log("");
}

function printBattery(results: readonly ProbeResult[]): void {
  let section = "";
  for (const r of results) {
    if (r.section !== section) {
      section = r.section;
      console.log(bold(section));
    }
    const verdict = r.actual === "ALLOWED" ? green("ALLOWED") : red("DENIED ");
    const mark = r.ok ? green("✓") : red("✗");
    console.log(`  ${pad(r.label, 56)} ${verdict}  ${mark}`);
    if (!r.ok || r.actual === "DENIED") {
      console.log(dim(`      ${r.ok ? "reason" : `expected ${r.expected}`}: ${r.reason}${r.code !== undefined ? `  [${r.code}]` : ""}`));
    }
    if (r.keyBinding !== undefined) {
      console.log(dim(`      warrant.bound_key             ${r.keyBinding.warrantBoundKey}`));
      console.log(dim(`      activity holder_key.public   ${r.keyBinding.presenterPublicKey}`));
      console.log(dim("      comparison                    holder_key != warrant.bound_key"));
      console.log(dim("      Ed25519 signature             FAILED"));
    }
  }
  console.log("");
}

function centralCallsLine(built: Built): string {
  return dim(`  central_calls during the trip: ${built.runtime.audit.centralCalls()}   (calls to a component outside the acting agent)`);
}

async function runStage(def: StageDef, scenario: Scenario): Promise<Built> {
  // The site builder runs the reference answers to capture what a finished stage prints.
  return runScenario(def, scenario, process.env["TENUO_LAB_ANSWER"]);
}

const WARMUP: ReadonlyArray<readonly [string, string]> = [
  [
    "What does a warrant let an agent do?",
    "Call the tools it names, with the argument values it allows, for the key it was issued to, until it expires. Nothing else.",
  ],
  [
    "What has to be true of a warrant an agent passes to another agent?",
    "It has to fit inside the one the passing agent holds: fewer tools, tighter values, no longer a lifetime. It can only narrow, and that is checked when it is made and again when it is used.",
  ],
  [
    "Who checks a warrant, and do they need to call a server to do it?",
    "The code right next to the tool checks it, using the issuer's public key. No server, no network: it works when the control plane is down.",
  ],
];

async function warmup(): Promise<void> {
  const state = loadState();
  if (state.warmupDone === true || state.stage !== 1 || !process.stdin.isTTY) {
    return;
  }
  console.log("");
  console.log(bold("Warm-up (not graded)"));
  console.log("");
  WARMUP.forEach(([q], i) => console.log(`  ${i + 1}. ${q}`));
  console.log("");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  await rl.question(dim("  Answer each in one line in your head, or just read them. Press enter to see the answers and start stage 1. "));
  rl.close();
  console.log("");
  WARMUP.forEach(([q, a], i) => {
    console.log(`  ${i + 1}. ${q}`);
    console.log(dim(`     ${a}`));
  });
  console.log("");
  saveState({ ...state, warmupDone: true });
}

async function cmdLab(def: StageDef): Promise<void> {
  await warmup();
  const scenario = def.scenario;
  header(def, scenario);
  if (args.includes("--open")) openInBrowser(guideUrl(def.n));
  for (const line of def.blurb) console.log(`  ${line}`);
  console.log("");
  const built = await runStage(def, scenario);
  if (printExerciseError(built)) {
    return;
  }
  const wallet = walletLine(built);
  const functionality = checkFunctionality(built.plan, built.runtime.audit.records, built.runtime.world);
  const probes = await runBattery(built.runtime, built.plan);
  const margin = await measureMargin(built.runtime);
  const scored = score(functionality, probes, margin);
  printHud(wallet, probes, scored);
  if (def.n === 5) {
    recordAttempt(def.n, snapshot({ runs: [{ built, probes, functionality }], functionality, probes, margin, score: scored }), { acceptGreen: false });
  }
  printTrace(built.runtime.audit.records, false);
  console.log("");
  console.log(centralCallsLine(built));
  console.log("");
  printFunctionality(functionality);
  printExplorerLink(built);
  if (def.breaksTrip === true) {
    console.log(dim("  The terminal link breaks the trip on purpose. Notice where, and who decided."));
    console.log("");
  }
  console.log(dim("  npm run attack   the rogue behavior and the tests      npm run score   points and why"));
  console.log(dim("  npm run trace    every decision with its reason        npm run next    when you are done here"));
  console.log("");
}

async function cmdTrace(def: StageDef): Promise<void> {
  const scenarios: Scenario[] = def.alsoRun !== undefined ? [def.scenario, def.alsoRun] : [def.scenario];
  for (const scenario of scenarios) {
    header(def, scenario);
    const built = await runStage(def, scenario);
    if (printExerciseError(built)) return;
    printTrace(built.runtime.audit.records, true);
    console.log("");
    console.log(centralCallsLine(built));
    console.log("");
    printExplorerLink(built);
  }
}

interface Evaluated {
  readonly built: Built;
  readonly probes: ProbeResult[];
  readonly functionality: Functionality;
}

async function attackAll(def: StageDef): Promise<Evaluated[]> {
  const scenarios: Scenario[] = def.alsoRun !== undefined ? [def.scenario, def.alsoRun] : [def.scenario];
  const out: Evaluated[] = [];
  for (const scenario of scenarios) {
    const built = await runStage(def, scenario);
    if (built.exercise?.error !== undefined) {
      out.push({ built, probes: [], functionality: { ok: false, steps: [], damage: [] } });
      continue;
    }
    const functionality = checkFunctionality(built.plan, built.runtime.audit.records, built.runtime.world);
    const probes = await runBattery(built.runtime, built.plan);
    out.push({ built, probes, functionality });
  }
  return out;
}

async function cmdAttack(def: StageDef): Promise<void> {
  const evaluated = await evaluateStage(def);
  if (evaluated === undefined) {
    const built = await runStage(def, def.scenario);
    printExerciseError(built);
    return;
  }
  recordAttempt(def.n, snapshot(evaluated));
  for (const { built, probes, functionality } of evaluated.runs) {
    header(def, built.plan.name);
    if (printExerciseError(built)) {
      return;
    }
    printHud(walletLine(built), probes, evaluated.score);
    printFunctionality(functionality);
    const handoffs = built.runtime.audit.records.filter((r) => r.source === "handoff");
    if (handoffs.length > 0) {
      console.log(bold("HANDOFFS"));
      for (const r of handoffs) {
        console.log(`  ${pad(`${r.agent}: ${r.action}`, 45)} ${pad(r.resource, 12)} ${decisionMark(r)}`);
        console.log(dim(`      ${r.reason}${r.code !== undefined ? `  [${r.code}]` : ""}`));
      }
      console.log("");
    }
    printBattery(probes);
    const failed = probes.filter((p) => !p.ok).length;
    console.log(failed === 0 ? green(`  clean: all ${probes.length} checks landed as expected`) : yellow(`  ${failed} of ${probes.length} checks did not land as expected`));
    console.log(centralCallsLine(built));
    console.log("");
  }
  if (def.starAsk === true) {
    console.log(dim("  That check ran locally, in the agent's own process, with no server to ask."));
    console.log(dim("  The code that did it is open source: github.com/tenuo-ai/tenuo"));
    console.log(dim("  A star helps other people find it."));
    console.log("");
  }
}

async function evaluateStage(def: StageDef): Promise<{ runs: Evaluated[]; functionality: Functionality; probes: ProbeResult[]; margin: Margin; score: Score } | undefined> {
  const runs = await attackAll(def);
  const first = runs[0];
  if (first === undefined || first.built.exercise?.error !== undefined) {
    return undefined;
  }
  const probes = runs.flatMap((r) => r.probes);
  const functionality: Functionality = {
    ok: runs.every((r) => r.functionality.ok),
    steps: runs.flatMap((r) => r.functionality.steps),
    damage: runs.flatMap((r) => r.functionality.damage),
  };
  const margin = await measureMargin(first.built.runtime);
  return { runs, functionality, probes, margin, score: score(functionality, probes, margin) };
}

async function cmdScore(def: StageDef): Promise<void> {
  header(def, def.scenario);
  const e = await evaluateStage(def);
  if (e === undefined) {
    const built = await runStage(def, def.scenario);
    printExerciseError(built);
    return;
  }
  recordAttempt(def.n, snapshot(e));
  const { functionality, probes, margin, score: s } = e;
  printHud(walletLine(e.runs[0]!.built), probes, s);
  const row = (label: string, points: number, max: number, note: string) =>
    console.log(`  ${pad(label, 44)} ${pad(`${points}`, 3)} / ${pad(String(max), 3)} ${dim(note)}`);
  row("Trip booked", s.functionality.points, 25, s.functionality.ok ? "" : "the trip is incomplete");
  row("Rogue stopped", s.blocked.points, 30, `${s.blocked.passed} of ${s.blocked.total} checks`);
  row("Tight handoff", s.handoffs.points, 25, `${s.handoffs.passed} of ${s.handoffs.total} checks`);
  row("No spare authority", s.margin.points, 20, `${s.margin.findings.length} finding${s.margin.findings.length === 1 ? "" : "s"}, capped at -5 per agent`);
  console.log(`  ${pad("", 44)} ${bold(pad(String(s.total), 3))} / 100${s.gated ? red("   gated") : ""}`);
  console.log("");
  if (!functionality.ok) {
    printFunctionality(functionality);
  }
  const failed = probes.filter((p) => !p.ok);
  if (failed.length > 0) {
    console.log(bold("DID NOT LAND AS EXPECTED"));
    for (const p of failed) {
      console.log(`  ${red("✗")} ${pad(p.label, 56)} expected ${p.expected}, got ${p.actual}`);
      console.log(dim(`      ${p.reason}`));
    }
    console.log("");
  }
  if (margin.findings.length > 0) {
    console.log(bold("GRANTED BUT NOT REQUIRED BY THE MISSION"));
    for (const agent of AGENTS) {
      const mine = margin.findings.filter((f) => f.agent === agent);
      if (mine.length === 0) continue;
      console.log(`  ${bold(pad(agent, 15))} -${margin.perAgent[agent]}${mine.reduce((n, f) => n + f.cost, 0) > margin.perAgent[agent] ? dim(" (capped)") : ""}`);
      for (const f of mine) {
        console.log(dim(`      -${f.cost} ${f.label}`));
      }
    }
    console.log("");
  }
  if (functionality.ok && def.breaksTrip !== true) {
    const state = loadState();
    if (!state.completed.includes(def.n)) {
      state.completed.push(def.n);
      saveState(state);
      console.log(green(`  Stage ${def.n} done.`) + (def.n < STAGES.length ? dim(`  Next: npm run next, then ${guideUrl(def.n + 1)}`) : ""));
      console.log("");
    }
  }
}

async function cmdShare(def: StageDef): Promise<void> {
  const e = await evaluateStage(def);
  if (e === undefined) {
    console.log("Your exercise file does not load; fix that first (npm run lab shows the error).");
    return;
  }
  const report = {
    schema: "tenuo-lab-share-v1",
    stage: def.n,
    stars: Object.fromEntries(e.score.stars.map((star) => [star.id, star.earned])),
    attempts: loadState().attempts?.[String(def.n)] ?? { count: 0 },
  };
  const dir = LAB_HOME;
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `share-stage-${def.n}.json`);
  writeFileSync(file, JSON.stringify(report, null, 2));
  printHud(walletLine(e.runs[0]!.built), e.probes, e.score, e.runs.length);
  console.log(dim(`  Anonymous local artifact: ${file}`));
}

async function cmdAudit(def: StageDef): Promise<void> {
  header(def, def.scenario);
  const built = await runStage(def, def.scenario);
  if (printExerciseError(built)) return;
  const described = await built.runtime.mode.describe({ world: built.runtime.world, audit: built.runtime.audit });
  console.log(bold("WHAT EACH AGENT CAN CURRENTLY DO"));
  for (const [identity, grant] of Object.entries(described)) {
    console.log(`  ${bold(identity)}`);
    const text = JSON.stringify(grant, null, 2).split("\n").slice(1, -1).map((l) => `    ${l.trim()}`);
    for (const line of text) console.log(dim(line));
  }
  console.log("");
}

async function cmdNext(): Promise<void> {
  const state = loadState();
  const to = flag("stage") !== undefined ? Number(flag("stage")) : state.stage + 1;
  if (!Number.isInteger(to) || to < 1 || to > STAGES.length) {
    console.log(`Stages run 1 to ${STAGES.length}. You are on ${state.stage}.`);
    return;
  }
  const completed = [...state.completed];
  // Stages 1 and 2 are observation levels with no editable solution to score.
  // Following their documented `next` flow is completion.
  if (flag("stage") === undefined && to === state.stage + 1 && state.stage <= 2 && !completed.includes(state.stage)) {
    completed.push(state.stage);
  }
  saveState({ ...state, stage: to, completed });
  console.log(`Now on stage ${to}: ${stageDef(to).title}. Run npm run lab.`);
  console.log(dim(`  guide: ${guideUrl(to)}`));
  if (args.includes("--open")) openInBrowser(guideUrl(to));
}

async function cmdReset(): Promise<void> {
  const backups = join(LAB_HOME, "reset-backups");
  mkdirSync(backups, { recursive: true });
  let n = 1;
  while (existsSync(join(backups, String(n)))) n += 1;
  const backup = join(backups, String(n));
  cpSync(join(ROOT, "exercises"), backup, { recursive: true });
  const restored = spawnSync("git", ["restore", "--source=HEAD", "--", "exercises"], { cwd: ROOT, encoding: "utf8" });
  if (restored.status !== 0) {
    console.log(red(`Could not restore starter exercises: ${restored.stderr.trim() || "git restore failed"}`));
    console.log(dim(`  Your exercise backup is safe at ${backup}`));
    return;
  }
  saveState({ stage: 1, completed: [] });
  console.log("Back to stage 1. Progress, attempt history, and every starter exercise were restored.");
  console.log(dim(`  Your previous exercise files are recoverable at ${backup}`));
}

function cmdAmbassador(): void {
  const sub = args[1];
  if (sub === "answers") {
    const n = Number(args[2]);
    const files: Record<number, string[]> = {
      3: ["answers/03-scoped/policy.ts"],
      4: ["answers/04-two-travelers/quick-fix.ts", "answers/04-two-travelers/per-task.ts", "answers/04-two-travelers/policy-service.ts"],
      5: ["answers/05-tenuo/chain.ts"],
      6: ["answers/06-extensions/chain.ts"],
      7: ["answers/07-incident/chain.ts"],
    };
    for (const f of files[n] ?? []) {
      console.log(bold(`── ${f}`));
      console.log(readFileSync(join(ROOT, f), "utf8"));
    }
    if ((files[n] ?? []).length === 0) console.log("Stages 1 and 2 have nothing to configure.");
    return;
  }
  if (sub === "stage") {
    void cmdNext();
    return;
  }
  const state = loadState();
  console.log(bold("PROGRESS"));
  console.log(`  on stage ${state.stage}; scored a working trip on: ${state.completed.length === 0 ? "none yet" : state.completed.sort((a, b) => a - b).join(", ")}`);
  console.log("");
  console.log(bold("COMMANDS"));
  console.log("  npm run ambassador -- answers N          print the reference solution for stage N");
  console.log("  npm run ambassador -- stage --stage N    move this machine to stage N");
  console.log("");
  console.log(bold("DISCUSSION PROMPTS"));
  for (const p of [
    "Where else in software does a component hold more authority than the task it is doing needs?",
    "The injected instruction lived in a data field. What other fields would an agent read and treat as trustworthy?",
    "Stage 5 showed that passing a credential downward gives away everything you hold. What do humans do instead?",
    "If the agent is going to be wrong sometimes, where would you rather the check happen: before the action or after it?",
    "Your stage 4 fix put something central in the path of every call. What happens to the trip when that component is down? And in stage 6?",
    "What did the least-privilege score cost you, and what would you grant differently if you ran it again?",
  ]) {
    console.log(`  - ${p}`);
  }
  console.log("");
}

async function main(): Promise<void> {
  const state = loadState();
  const n = flag("stage") !== undefined && command !== "next" && command !== "ambassador" ? Number(flag("stage")) : state.stage;
  const def = stageDef(n);
  if (args.includes("--live")) {
    console.log(yellow("  --live is not wired in this build: the lab runs its recorded, deterministic agents. Every test and score is real."));
  }
  switch (command) {
    case "lab": return cmdLab(def);
    case "trace": return cmdTrace(def);
    case "attack": return cmdAttack(def);
    case "score": return cmdScore(def);
    case "share": return cmdShare(def);
    case "audit": return cmdAudit(def);
    case "next": return cmdNext();
    case "reset": return cmdReset();
    case "ambassador": return cmdAmbassador();
    default:
      console.log(`unknown command ${command}. Try: lab, trace, attack, score, share, audit, next, reset, ambassador`);
  }
}

main().catch((error) => {
  console.error(red(`The lab hit an unexpected error:`));
  console.error(error);
  process.exitCode = 1;
});
