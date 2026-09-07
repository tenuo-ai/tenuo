/**
 * Opt-in, anonymous progress events.
 *
 * What is sent: stage numbers, which command ran, whether the trip worked,
 * the score, the labels of checks that did not land, the central-call count,
 * and how long since the previous run. What is never sent: your code, your
 * exercise files, your name, your machine's identity, or anything you typed.
 *
 * Nothing is sent unless you said yes to the one-time question, and
 * `npm run telemetry -- off` stops it. Sending never blocks or fails the lab:
 * a dead endpoint is silently ignored.
 */
import { randomUUID } from "node:crypto";
import { loadState, saveState, type LabState } from "./state.ts";

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

export type EventName = "opt_in" | "opt_out" | "stage_enter" | "run" | "share";

export interface LabEvent {
  readonly v: 1;
  readonly session: string;
  readonly cohort?: string;
  readonly sentAt: string;
  readonly event: EventName;
  readonly stage: number;
  readonly command?: string;
  readonly scenario?: string;
  readonly functionalityOk?: boolean;
  readonly score?: number;
  readonly failedChecks?: readonly string[];
  readonly centralCalls?: number;
  readonly exerciseLoadError?: boolean;
  readonly elapsedMs?: number;
  readonly platform: string;
  readonly node: number;
}

export function eventsUrl(): string {
  const override = process.env["TENUO_LAB_EVENTS_URL"];
  return override !== undefined && override.length > 0 ? override : DEFAULT_EVENTS_URL;
}

export function telemetry(): TelemetryState | undefined {
  return loadState().telemetry;
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

/**
 * Send one event if telemetry is on. Fire and forget: resolves quickly, never
 * throws, never delays the command that called it.
 */
export async function emit(
  event: EventName,
  stage: number,
  fields: Omit<Partial<LabEvent>, "v" | "session" | "cohort" | "sentAt" | "event" | "stage" | "platform" | "node"> = {},
): Promise<void> {
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
  "        the names of checks that did not land, and time between runs.",
  "  Never: your code, your files, your name, or anything about your machine",
  "        beyond OS and Node version.",
  "",
  "  Change your mind any time: npm run telemetry -- off",
];
