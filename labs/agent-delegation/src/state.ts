import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TOOLS } from "./mission.ts";
import { STAGES } from "./stages.ts";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
/** Override for the site builder and tests, so a captured run never touches a participant's state. */
export const LAB_HOME = process.env["TENUO_LAB_HOME"] ?? join(ROOT, ".lab");
const STATE_FILE = join(LAB_HOME, "state.json");

export interface LabState {
  stage: number;
  /** Random local challenge-session identifier used only on explicit share. */
  sessionId?: string;
  /** Stages the participant has scored full functionality on. */
  completed: number[];
  /** The warm-up questions were shown once. */
  warmupDone?: boolean;
  /** Local-only, source-free play history used by the opt-in share artifact. */
  attempts?: Record<string, StageAttempts>;
}

export interface HandoffSnapshot {
  readonly tools: readonly string[];
  readonly constraintChecks: { readonly passed: number; readonly total: number };
  readonly holderBound: boolean;
  readonly ttl: "missing" | "under-3m" | "under-6m" | "under-15m" | "over-15m";
}

export interface AttemptSnapshot {
  readonly starsMissing: readonly string[];
  readonly checks: { readonly passed: number; readonly total: number };
  readonly handoffs?: Record<string, HandoffSnapshot | "missing">;
}

export interface StageAttempts {
  readonly count: number;
  readonly firstAttempt: AttemptSnapshot;
  readonly firstGreen?: AttemptSnapshot;
}

const STAR_IDS = new Set(["trip-booked", "rogue-stopped", "tight-handoff", "no-spare-authority"]);
const TTL_BUCKETS = new Set(["missing", "under-3m", "under-6m", "under-15m", "over-15m"]);
const TOOL_NAMES = new Set<string>(Object.values(TOOLS));

function finiteCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;
}

function parseChecks(value: unknown): AttemptSnapshot["checks"] | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const raw = value as Record<string, unknown>;
  const passed = finiteCount(raw["passed"]);
  const total = finiteCount(raw["total"]);
  return passed !== undefined && total !== undefined && passed <= total ? { passed, total } : undefined;
}

function parseHandoff(value: unknown): HandoffSnapshot | "missing" | undefined {
  if (value === "missing") return value;
  if (value === null || typeof value !== "object") return undefined;
  const raw = value as Record<string, unknown>;
  const checks = parseChecks(raw["constraintChecks"]);
  const tools = Array.isArray(raw["tools"])
    ? raw["tools"].filter((tool): tool is string => typeof tool === "string" && TOOL_NAMES.has(tool))
    : undefined;
  if (tools === undefined || checks === undefined || typeof raw["holderBound"] !== "boolean" || !TTL_BUCKETS.has(String(raw["ttl"]))) {
    return undefined;
  }
  return {
    tools,
    constraintChecks: checks,
    holderBound: raw["holderBound"],
    ttl: raw["ttl"] as HandoffSnapshot["ttl"],
  };
}

function parseSnapshot(value: unknown): AttemptSnapshot | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const raw = value as Record<string, unknown>;
  const checks = parseChecks(raw["checks"]);
  if (checks === undefined || !Array.isArray(raw["starsMissing"])) return undefined;
  const starsMissing = raw["starsMissing"].filter((id): id is string => typeof id === "string" && STAR_IDS.has(id));
  const handoffsRaw = raw["handoffs"];
  if (handoffsRaw === undefined) return { starsMissing, checks };
  if (handoffsRaw === null || typeof handoffsRaw !== "object") return undefined;
  const source = handoffsRaw as Record<string, unknown>;
  const flight = parseHandoff(source["flight-to-checkin"]);
  const boarding = parseHandoff(source["checkin-to-boarding"]);
  if (flight === undefined || boarding === undefined) return undefined;
  return { starsMissing, checks, handoffs: { "flight-to-checkin": flight, "checkin-to-boarding": boarding } };
}

export function sanitizeAttempts(value: unknown): Record<string, StageAttempts> | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const out: Record<string, StageAttempts> = {};
  for (const [key, stageValue] of Object.entries(value as Record<string, unknown>)) {
    const stage = Number(key);
    if (!Number.isInteger(stage) || stage < 1 || stage > STAGES.length || stageValue === null || typeof stageValue !== "object") continue;
    const raw = stageValue as Record<string, unknown>;
    const count = finiteCount(raw["count"]);
    const firstAttempt = parseSnapshot(raw["firstAttempt"]);
    const firstGreen = raw["firstGreen"] === undefined ? undefined : parseSnapshot(raw["firstGreen"]);
    if (count === undefined || count < 1 || firstAttempt === undefined || (raw["firstGreen"] !== undefined && firstGreen === undefined)) continue;
    out[key] = { count, firstAttempt, ...(firstGreen !== undefined ? { firstGreen } : {}) };
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

export function loadState(): LabState {
  if (!existsSync(STATE_FILE)) {
    return { stage: 1, completed: [] };
  }
  try {
    const parsed = JSON.parse(readFileSync(STATE_FILE, "utf8")) as Partial<LabState>;
    const attempts = sanitizeAttempts(parsed.attempts);
    return {
      stage: typeof parsed.stage === "number" && parsed.stage >= 1 && parsed.stage <= STAGES.length ? parsed.stage : 1,
      completed: Array.isArray(parsed.completed) ? parsed.completed.filter((n): n is number => typeof n === "number") : [],
      ...(typeof parsed.sessionId === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(parsed.sessionId) ? { sessionId: parsed.sessionId } : {}),
      ...(parsed.warmupDone === true ? { warmupDone: true } : {}),
      ...(attempts !== undefined ? { attempts } : {}),
    };
  } catch {
    return { stage: 1, completed: [] };
  }
}

export function getOrCreateSessionId(): string {
  const state = loadState();
  if (state.sessionId !== undefined) return state.sessionId;
  const sessionId = randomUUID();
  saveState({ ...state, sessionId });
  return sessionId;
}

export function saveState(state: LabState): void {
  mkdirSync(LAB_HOME, { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}
