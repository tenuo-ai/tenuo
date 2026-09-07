/**
 * Opt-in, anonymous progress events.
 *
 * What is sent: stage numbers, which command ran, whether the trip worked,
 * the score, the labels of checks that did not land, the central-call count,
 * which stage 4 fix was used, which agents were over-granted, the lab version,
 * whether the lab runs locally or in Codespaces, how long since the previous
 * event, and (from the hosted guide, under the same id) which pages, hints,
 * and reference solutions were opened. What is never sent: your code, your
 * exercise files, your name, your machine's identity, or anything you typed.
 *
 * Nothing is sent unless you said yes to the one-time question, and
 * `npm run telemetry -- off` stops it. Sending never blocks or fails the lab:
 * a dead endpoint is silently ignored.
 */
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadState, ROOT, saveState, type LabState } from "./state.ts";

/** Override with TENUO_LAB_EVENTS_URL. */
export const DEFAULT_EVENTS_URL = "https://lab-events.tenuo.ai/v1/events";

export interface TelemetryState {
  readonly enabled: boolean;
  /** Random per install. Not derived from anything about the machine or the person. */
  readonly sessionId: string;
  /** Optional code a session host hands out so a room's events group together. */
  readonly cohort?: string;
  readonly lastEventAt?: number;
  readonly lastStage?: number;
}

export type EventName =
  | "opt_in"
  | "opt_out"
  | "stage_enter"
  | "run"
  | "share"
  // Sent by the hosted guide, under the same session id, when the CLI's link carried it.
  | "page_view"
  | "hint_open"
  | "answer_open"
  | "mark_done";

export type LabEnv = "local" | "codespaces" | "web";
export type Fix = "per-task" | "policy-service";

export interface LabEvent {
  readonly v: 1;
  readonly session: string;
  readonly cohort?: string;
  readonly sentAt: string;
  readonly event: EventName;
  readonly stage: number;
  /** Package version plus the short commit, so cohorts can be compared across changes to the lab. */
  readonly labVersion: string;
  readonly env: LabEnv;
  readonly command?: string;
  readonly scenario?: string;
  readonly functionalityOk?: boolean;
  readonly score?: number;
  readonly failedChecks?: readonly string[];
  readonly centralCalls?: number;
  readonly exerciseLoadError?: boolean;
  readonly elapsedMs?: number;
  /** Which stage 4 repair the policy file uses. */
  readonly fix?: Fix;
  readonly marginPoints?: number;
  /** Agents the least-privilege check found over-granted. */
  readonly marginAgents?: readonly string[];
  readonly platform: string;
  readonly node: number;
}

export function eventsUrl(): string {
  const override = process.env["TENUO_LAB_EVENTS_URL"];
  return override !== undefined && override.length > 0 ? override : DEFAULT_EVENTS_URL;
}

let cachedVersion: string | undefined;

/** "0.1.0+1a2b3c4", or just the package version when git is not around. */
export function labVersion(): string {
  if (cachedVersion !== undefined) return cachedVersion;
  let version = "0.0.0";
  try {
    version = String((JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version?: string }).version ?? version);
  } catch {
    // Keep the placeholder.
  }
  let sha = "";
  try {
    const r = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: ROOT, encoding: "utf8", timeout: 2000 });
    if (r.status === 0) sha = r.stdout.trim();
  } catch {
    // No git: the version alone still says which release this is.
  }
  cachedVersion = sha.length > 0 ? `${version}+${sha}` : version;
  return cachedVersion;
}

export function labEnv(): LabEnv {
  return process.env["CODESPACES"] === "true" ? "codespaces" : "local";
}

export function telemetry(): TelemetryState | undefined {
  return loadState().telemetry;
}

/** The session id, when events are on, so the hosted guide can file its own events under it. */
export function sessionParam(): string | undefined {
  const t = telemetry();
  return t !== undefined && t.enabled ? t.sessionId : undefined;
}

export function setTelemetry(enabled: boolean, cohort?: string): TelemetryState {
  const state = loadState();
  const previous = state.telemetry;
  const next: TelemetryState = {
    enabled,
    sessionId: previous?.sessionId ?? randomUUID(),
    ...(cohort !== undefined ? { cohort } : previous?.cohort !== undefined ? { cohort: previous.cohort } : {}),
    ...(previous?.lastEventAt !== undefined ? { lastEventAt: previous.lastEventAt } : {}),
    ...(previous?.lastStage !== undefined ? { lastStage: previous.lastStage } : {}),
  };
  saveState({ ...state, telemetry: next });
  return next;
}

function nodeMajor(): number {
  const major = Number(process.versions.node.split(".")[0]);
  return Number.isFinite(major) ? major : 0;
}

export type EventFields = Omit<Partial<LabEvent>, "v" | "session" | "cohort" | "sentAt" | "event" | "stage" | "platform" | "node" | "labVersion" | "env">;

/**
 * Send one event if telemetry is on. Fire and forget: resolves quickly, never
 * throws, never delays the command that called it.
 */
export async function emit(event: EventName, stage: number, fields: EventFields = {}): Promise<void> {
  const state: LabState = loadState();
  const t = state.telemetry;
  if (t === undefined || !t.enabled) {
    return;
  }
  const now = Date.now();
  const elapsed = t.lastEventAt !== undefined ? now - t.lastEventAt : undefined;
  const payload: LabEvent = {
    v: 1,
    session: t.sessionId,
    ...(t.cohort !== undefined ? { cohort: t.cohort } : {}),
    sentAt: new Date(now).toISOString(),
    event,
    stage,
    labVersion: labVersion(),
    env: labEnv(),
    ...(elapsed !== undefined ? { elapsedMs: elapsed } : {}),
    platform: process.platform,
    node: nodeMajor(),
    ...strip(fields),
  };
  saveState({ ...state, telemetry: { ...t, lastEventAt: now, lastStage: stage } });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1500);
  try {
    await fetch(eventsUrl(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
  } catch {
    // A dead or slow endpoint must never be the participant's problem.
  } finally {
    clearTimeout(timer);
  }
}

/** Emit `stage_enter` once per stage change. */
export async function enterStage(stage: number): Promise<void> {
  const t = telemetry();
  if (t === undefined || !t.enabled || t.lastStage === stage) {
    return;
  }
  await emit("stage_enter", stage);
}

function strip<T extends object>(obj: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) {
      (out as Record<string, unknown>)[k] = v;
    }
  }
  return out;
}

/** The consent text, kept here so the CLI and the README say the same thing. */
export const CONSENT_LINES = [
  "Share anonymous progress with the Tenuo team, to make the lab better?",
  "",
  "  Sent: stage numbers, which command ran, whether the trip worked, the score,",
  "        the names of checks that did not land, time between runs, the lab",
  "        version, whether you run locally or in Codespaces, and which guide",
  "        pages and hints you open from the links the lab prints.",
  "  Never: your code, your files, your name, or anything about your machine",
  "        beyond OS and Node version.",
  "",
  "  Change your mind any time: npm run telemetry -- off",
];
