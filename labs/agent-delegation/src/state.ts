import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
/** Override for the site builder and tests, so a captured run never touches a participant's state. */
const STATE_DIR = process.env["TENUO_LAB_HOME"] ?? join(ROOT, ".lab");
const STATE_FILE = join(STATE_DIR, "state.json");

export interface LabState {
  stage: number;
  /** Stages the participant has scored full functionality on. */
  completed: number[];
  /** The warm-up questions were shown once. */
  warmupDone?: boolean;
  /** Opt-in progress events. Absent until the participant has been asked. */
  telemetry?: {
    enabled: boolean;
    sessionId: string;
    cohort?: string;
    lastEventAt?: number;
    lastStage?: number;
  };
}

export function loadState(): LabState {
  if (!existsSync(STATE_FILE)) {
    return { stage: 1, completed: [] };
  }
  try {
    const parsed = JSON.parse(readFileSync(STATE_FILE, "utf8")) as Partial<LabState>;
    return {
      stage: typeof parsed.stage === "number" && parsed.stage >= 1 && parsed.stage <= 9 ? parsed.stage : 1,
      completed: Array.isArray(parsed.completed) ? parsed.completed.filter((n): n is number => typeof n === "number") : [],
      ...(parsed.warmupDone === true ? { warmupDone: true } : {}),
      ...(parsed.telemetry !== undefined && typeof parsed.telemetry === "object" && typeof parsed.telemetry.sessionId === "string"
        ? { telemetry: parsed.telemetry }
        : {}),
    };
  } catch {
    return { stage: 1, completed: [] };
  }
}

export function saveState(state: LabState): void {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}
