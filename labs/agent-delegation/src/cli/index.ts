/**
 * The five commands, plus `next`, `reset`, and `ambassador`.
 *
 *   npm run lab        start or resume where you left off
 *   npm run trace      watch the agents work, with every decision shown
 *   npm run attack     run the rogue behavior and the security tests
 *   npm run score      see your score and why
 *   npm run audit      what every agent can currently do
 *   npm run next       move to the next stage
 *   npm run reset      back to stage 1
 */
process.env.NODE_ENV ??= "development";

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { runBattery, type ProbeResult } from "../harness/attacks.ts";
import { checkFunctionality, type Functionality } from "../harness/functionality.ts";
import { measureMargin } from "../harness/margin.ts";
import { runScenario, type Built } from "../harness/run.ts";
import { score } from "../harness/score.ts";
import type { AuditRecord } from "../audit.ts";
import { loadState, ROOT, saveState } from "../state.ts";
import { STAGES, stage as stageDef, type Scenario, type StageDef } from "../stages.ts";

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
  console.log("");
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
    const rt = r.roundTrips > 0 ? dim(`  round_trips: ${r.roundTrips}`) : "";
    console.log(`  ${pad(String(r.seq), 3)} ${src} ${pad(r.agent, 15)} ${pad(r.task, 15)} ${pad(r.action, 28)} ${pad(r.resource, 15)} ${decisionMark(r)}${rt}`);
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

async function runStage(def: StageDef, scenario: Scenario): Promise<Built> {
  return runScenario(def, scenario);
}

async function cmdLab(def: StageDef): Promise<void> {
  const scenario = def.scenario;
  header(def, scenario);
  for (const line of def.blurb) console.log(`  ${line}`);
  console.log("");
  const built = await runStage(def, scenario);
  if (printExerciseError(built)) return;
  console.log(bold("WALLET  ") + walletLine(built));
  console.log("");
  printTrace(built.runtime.audit.records, false);
  console.log("");
  printFunctionality(checkFunctionality(built.plan, built.runtime.audit.records, built.runtime.world));
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
    console.log(dim(`  round trips to a central service: ${built.runtime.audit.roundTrips()}`));
    console.log("");
  }
}

async function attackAll(def: StageDef): Promise<{ built: Built; probes: ProbeResult[]; functionality: Functionality }[]> {
  const scenarios: Scenario[] = def.alsoRun !== undefined ? [def.scenario, def.alsoRun] : [def.scenario];
  const out = [];
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
  for (const { built, probes, functionality } of await attackAll(def)) {
    header(def, built.plan.name);
    if (printExerciseError(built)) return;
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
    console.log(dim(`  round trips to a central service during the trip: ${built.runtime.audit.records.filter((r) => r.source !== "probe").reduce((n, r) => n + r.roundTrips, 0)}`));
    console.log("");
  }
  if (def.n === 6) {
    console.log(dim("  That check ran locally, in the agent's own process, with no server to ask."));
    console.log(dim("  The code that did it is open source: github.com/tenuo-ai/tenuo"));
    console.log(dim("  A star helps other people find it."));
    console.log("");
  }
}

async function cmdScore(def: StageDef): Promise<void> {
  const runs = await attackAll(def);
  const first = runs[0];
  if (first === undefined) return;
  header(def, def.scenario);
  if (printExerciseError(first.built)) return;
  const probes = runs.flatMap((r) => r.probes);
  const functionality: Functionality = {
    ok: runs.every((r) => r.functionality.ok),
    steps: runs.flatMap((r) => r.functionality.steps),
    damage: runs.flatMap((r) => r.functionality.damage),
  };
  const margin = await measureMargin(first.built.runtime);
  const s = score(functionality, probes, margin);
  const row = (label: string, points: number, max: number, note: string) =>
    console.log(`  ${pad(label, 44)} ${pad(`${points}`, 3)} / ${pad(String(max), 3)} ${dim(note)}`);
  row("The trip completes correctly", s.functionality.points, 25, s.functionality.ok ? "" : "the functionality gate: nothing else counts until the trip works");
  row("Unauthorized actions are blocked", s.blocked.points, 30, `${s.blocked.passed} of ${s.blocked.total} checks`);
  row("Handoffs pass along only what's needed", s.handoffs.points, 25, `${s.handoffs.passed} of ${s.handoffs.total} checks`);
  row("You didn't grant more than the job required", s.margin.points, 20, `${s.margin.findings.length} finding${s.margin.findings.length === 1 ? "" : "s"}`);
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
    for (const f of margin.findings) {
      console.log(`  -${f.cost} ${pad(f.agent, 15)} ${f.label}`);
    }
    console.log("");
  }
  if (functionality.ok && def.n !== 8) {
    const state = loadState();
    if (!state.completed.includes(def.n)) {
      state.completed.push(def.n);
      saveState(state);
    }
  }
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

function cmdNext(): void {
  const state = loadState();
  const to = flag("stage") !== undefined ? Number(flag("stage")) : state.stage + 1;
  if (!Number.isInteger(to) || to < 1 || to > STAGES.length) {
    console.log(`Stages run 1 to ${STAGES.length}. You are on ${state.stage}.`);
    return;
  }
  saveState({ ...state, stage: to });
  console.log(`Now on stage ${to}: ${stageDef(to).title}. Run npm run lab.`);
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
    cmdNext();
    return;
  }
  const state = loadState();
  console.log(bold("PROGRESS"));
  console.log(`  on stage ${state.stage}; scored a working trip on: ${state.completed.length === 0 ? "none yet" : state.completed.sort((a, b) => a - b).join(", ")}`);
  console.log("");
  console.log(bold("COMMANDS"));
  console.log("  npm run ambassador -- answers N     print the reference solution for stage N");
  console.log("  npm run ambassador -- stage --stage N   move this machine to stage N");
  console.log("");
  console.log(bold("DISCUSSION PROMPTS"));
  for (const p of [
    "Where else in software does a component hold more authority than the task it is doing needs?",
    "The injected instruction lived in a data field. What other fields would an agent read and treat as trustworthy?",
    "Stage 5 showed that passing a credential downward gives away everything you hold. What do humans do instead?",
    "If the agent is going to be wrong sometimes, where would you rather the check happen: before the action or after it?",
    "Your stage 4 fix needed a service on every call. What happens to the trip when that service is down? And in stage 6?",
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
    case "audit": return cmdAudit(def);
    case "next": return cmdNext();
    case "reset": return cmdReset();
    case "ambassador": return cmdAmbassador();
    default:
      console.log(`unknown command ${command}. Try: lab, trace, attack, score, audit, next, reset, ambassador`);
  }
}

main().catch((error) => {
  console.error(red(`The lab hit an unexpected error:`));
  console.error(error);
  process.exitCode = 1;
});
