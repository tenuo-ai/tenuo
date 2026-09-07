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
 *   npm run telemetry  on | off | status: opt-in anonymous progress events
 *   npm run reset      back to stage 1
 */
process.env.NODE_ENV ??= "development";

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { runBattery, type ProbeResult } from "../harness/attacks.ts";
import { checkFunctionality, type Functionality } from "../harness/functionality.ts";
import { measureMargin, type Margin } from "../harness/margin.ts";
import { runScenario, type Built } from "../harness/run.ts";
import { score, type Score } from "../harness/score.ts";
import type { AuditRecord } from "../audit.ts";
import { AGENTS } from "../mission.ts";
import { loadState, ROOT, saveState } from "../state.ts";
import { STAGES, stage as stageDef, type Scenario, type StageDef } from "../stages.ts";
import { CONSENT_LINES, emit, enterStage, eventsUrl, setTelemetry, telemetry } from "../telemetry.ts";

const SITE = "https://tenuo.ai";
/** The stage page, with the stages this install has completed, so the site's progress matches the terminal. */
function guideUrl(n: number): string {
  const done = [...loadState().completed].sort((a, b) => a - b);
  return `${SITE}/lab/stage-${n}${done.length > 0 ? `?done=${done.join(",")}` : ""}`;
}

/** Open a URL in the default browser without blocking or failing the command. */
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

/** A link that opens the explorer on the chain Boarding Agent holds, so students can see every hop. */
function explorerLink(built: Built): string | undefined {
  const tenuo = built.runtime.tenuo;
  const trip = built.plan.trips[0];
  if (tenuo === undefined || trip === undefined) {
    return undefined;
  }
  const session = tenuo.session("boarding-agent", trip.taskId) ?? tenuo.session("checkin-agent", trip.taskId) ?? tenuo.session("flight-agent", trip.taskId);
  if (session === undefined) {
    return undefined;
  }
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
    console.log(dim("  See the chain the agents are holding, hop by hop, in the explorer:"));
    console.log(dim(`  ${url}`));
    console.log("");
  }
}

/** One-time question, TTY only. Silence is a no. */
async function consent(): Promise<void> {
  const state = loadState();
  if (state.telemetry !== undefined || !process.stdin.isTTY) {
    return;
  }
  console.log("");
  for (const line of CONSENT_LINES) console.log(`  ${line}`);
  console.log("");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await rl.question(dim("  Share? [y/N] "))).trim().toLowerCase();
  rl.close();
  const yes = answer === "y" || answer === "yes";
  setTelemetry(yes, flag("cohort"));
  console.log(dim(yes ? "  Thank you. npm run telemetry -- off stops it at any time." : "  Nothing will be sent. npm run telemetry -- on if you change your mind."));
  console.log("");
  if (yes) {
    await emit("opt_in", state.stage);
  }
}

function walletLine(built: Built): string {
  return built.plan.trips
    .map((t) => `${t.traveler.split(" ")[0]}: $${built.runtime.world.balance(t.taskId)} of $${t.budget}`)
    .join("   ");
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
  console.log(bold("Warm-up (from the three sections you read, not graded)"));
  console.log("");
  WARMUP.forEach(([q], i) => console.log(`  ${i + 1}. ${q}`));
  console.log("");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  await rl.question(dim("  Answer each in one line in your head, then press enter to see the answers and start stage 1. "));
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
  await consent();
  await enterStage(def.n);
  const scenario = def.scenario;
  header(def, scenario);
  if (args.includes("--open")) openInBrowser(guideUrl(def.n));
  for (const line of def.blurb) console.log(`  ${line}`);
  console.log("");
  const built = await runStage(def, scenario);
  if (printExerciseError(built)) {
    await emit("run", def.n, { command: "lab", scenario, exerciseLoadError: true });
    return;
  }
  console.log(bold("WALLET  ") + walletLine(built));
  console.log("");
  printTrace(built.runtime.audit.records, false);
  console.log("");
  console.log(centralCallsLine(built));
  console.log("");
  const functionality = checkFunctionality(built.plan, built.runtime.audit.records, built.runtime.world);
  printFunctionality(functionality);
  printExplorerLink(built);
  await emit("run", def.n, { command: "lab", scenario, functionalityOk: functionality.ok, centralCalls: built.runtime.audit.centralCalls() });
  if (def.n === 8) {
    console.log(dim("  This stage is supposed to break the trip. Notice where, and who decided."));
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
  await enterStage(def.n);
  for (const { built, probes, functionality } of await attackAll(def)) {
    header(def, built.plan.name);
    if (printExerciseError(built)) {
      await emit("run", def.n, { command: "attack", scenario: built.plan.name, exerciseLoadError: true });
      return;
    }
    console.log(bold("WALLET  ") + walletLine(built));
    console.log("");
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
    printExplorerLink(built);
    await emit("run", def.n, {
      command: "attack",
      scenario: built.plan.name,
      functionalityOk: functionality.ok,
      failedChecks: probes.filter((p) => !p.ok).map((p) => p.label),
      centralCalls: built.runtime.audit.centralCalls(),
    });
  }
  if (def.n === 6) {
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
  await enterStage(def.n);
  header(def, def.scenario);
  const e = await evaluateStage(def);
  if (e === undefined) {
    const built = await runStage(def, def.scenario);
    printExerciseError(built);
    await emit("run", def.n, { command: "score", scenario: def.scenario, exerciseLoadError: true });
    return;
  }
  const { functionality, probes, margin, score: s } = e;
  const row = (label: string, points: number, max: number, note: string) =>
    console.log(`  ${pad(label, 44)} ${pad(`${points}`, 3)} / ${pad(String(max), 3)} ${dim(note)}`);
  row("The trip completes correctly", s.functionality.points, 25, s.functionality.ok ? "" : "the functionality gate: nothing else counts until the trip works");
  row("Unauthorized actions are blocked", s.blocked.points, 30, `${s.blocked.passed} of ${s.blocked.total} checks`);
  row("Handoffs pass along only what's needed", s.handoffs.points, 25, `${s.handoffs.passed} of ${s.handoffs.total} checks`);
  row("You didn't grant more than the job required", s.margin.points, 20, `${s.margin.findings.length} finding${s.margin.findings.length === 1 ? "" : "s"}, capped at -5 per agent`);
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
  if (functionality.ok && def.n !== 8) {
    const state = loadState();
    if (!state.completed.includes(def.n)) {
      state.completed.push(def.n);
      saveState(state);
      console.log(green(`  Stage ${def.n} done.`) + (def.n < STAGES.length ? dim(`  Next: npm run next, then ${guideUrl(def.n + 1)}`) : ""));
      console.log("");
    }
  }
  await emit("run", def.n, {
    command: "score",
    scenario: def.scenario,
    functionalityOk: functionality.ok,
    score: s.total,
    failedChecks: failed.map((p) => p.label),
    ...(e.runs[0] !== undefined ? { centralCalls: e.runs[0].built.runtime.audit.centralCalls() } : {}),
  });
}

async function cmdShare(def: StageDef): Promise<void> {
  const e = await evaluateStage(def);
  if (e === undefined) {
    console.log("Your exercise file does not load; fix that first (npm run lab shows the error).");
    return;
  }
  const report = {
    stage: def.n,
    total: e.score.total,
    gated: e.score.gated,
    functionality: e.score.functionality.points,
    blocked: `${e.score.blocked.passed}/${e.score.blocked.total}`,
    handoffs: `${e.score.handoffs.passed}/${e.score.handoffs.total}`,
    margin: e.score.margin.points,
    marginPerAgent: e.margin.perAgent,
    failedChecks: e.probes.filter((p) => !p.ok).map((p) => p.label),
    centralCalls: e.runs.map((r) => ({ scenario: r.built.plan.name, count: r.built.runtime.audit.centralCalls() })),
    generatedAt: new Date().toISOString(),
  };
  const dir = join(ROOT, ".lab");
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `share-stage-${def.n}.json`);
  writeFileSync(file, JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
  console.log("");
  const t = telemetry();
  if (t?.enabled === true) {
    await emit("share", def.n, { command: "share", scenario: def.scenario, functionalityOk: !e.score.gated, score: e.score.total, failedChecks: report.failedChecks });
    console.log(dim(`  Written to ${file}, and the same breakdown was sent as an anonymous event (npm run telemetry -- status).`));
  } else {
    console.log(dim(`  Written to ${file}. Nothing was sent anywhere. Hand the file to your session host if you want to; it carries no name, no key, and no code.`));
  }
}

function cmdTelemetry(): void {
  const sub = args[1] ?? "status";
  if (sub === "on" || sub === "off") {
    const t = setTelemetry(sub === "on", flag("cohort"));
    console.log(sub === "on" ? `Anonymous progress events are on (session ${t.sessionId.slice(0, 8)}…). npm run telemetry -- off stops them.` : "Anonymous progress events are off. Nothing is sent.");
    void emit(sub === "on" ? "opt_in" : "opt_out", loadState().stage);
    return;
  }
  const t = telemetry();
  if (t === undefined) {
    console.log("Not decided yet: the first npm run lab asks. Nothing has been sent.");
  } else {
    console.log(`${t.enabled ? "On" : "Off"}. session ${t.sessionId.slice(0, 8)}…${t.cohort !== undefined ? `, cohort ${t.cohort}` : ""}, endpoint ${eventsUrl()}`);
  }
  console.log("");
  for (const line of CONSENT_LINES.slice(2, 6)) console.log(`  ${line}`);
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
  saveState({ ...state, stage: to });
  console.log(`Now on stage ${to}: ${stageDef(to).title}. Run npm run lab.`);
  console.log(dim(`  guide: ${guideUrl(to)}`));
  if (args.includes("--open")) openInBrowser(guideUrl(to));
  await enterStage(to);
}

function cmdReset(): void {
  saveState({ stage: 1, completed: [] });
  console.log("Back to stage 1. Your edits in exercises/ are untouched; `git checkout exercises` restores the originals.");
}

function cmdAmbassador(): void {
  const sub = args[1];
  if (sub === "answers") {
    const n = Number(args[2]);
    const files: Record<number, string[]> = {
      3: ["answers/03-scoped/policy.ts"],
      4: ["answers/04-two-travelers/per-task.ts", "answers/04-two-travelers/policy-service.ts"],
      5: ["answers/04-two-travelers/per-task.ts"],
      6: ["answers/06-tenuo/chain.ts"],
      7: ["answers/06-tenuo/chain.ts"],
      8: ["answers/08-terminal/chain.ts"],
      9: ["answers/09-incident/chain.ts"],
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
  if (flag("cohort") !== undefined && state.telemetry !== undefined) {
    setTelemetry(state.telemetry.enabled, flag("cohort"));
  }
  if (args.includes("--live")) {
    console.log(yellow("  --live is not wired in this build: the lab runs its recorded, deterministic agents. Every test and score is real."));
  }
  switch (command) {
    case "lab": return cmdLab(def);
    case "trace": return cmdTrace(def);
    case "attack": return cmdAttack(def);
    case "score": return cmdScore(def);
    case "share": return cmdShare(def);
    case "telemetry": return cmdTelemetry();
    case "audit": return cmdAudit(def);
    case "next": return cmdNext();
    case "reset": return cmdReset();
    case "ambassador": return cmdAmbassador();
    default:
      console.log(`unknown command ${command}. Try: lab, trace, attack, score, share, telemetry, audit, next, reset, ambassador`);
  }
}

main().catch((error) => {
  console.error(red(`The lab hit an unexpected error:`));
  console.error(error);
  process.exitCode = 1;
});
