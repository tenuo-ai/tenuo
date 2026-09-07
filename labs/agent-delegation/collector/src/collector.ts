/**
 * The event collector, as a pure function over a store, so it can be tested
 * without Cloudflare and deployed as a Worker with a one-line adapter.
 *
 * Accepts the events `src/telemetry.ts` sends. Rejects anything else. Stores
 * exactly the fields it knows and nothing it does not. There is no identity
 * here: `session` is a random id the participant's install generated.
 */

export interface StoredEvent {
  readonly session: string;
  readonly cohort: string | null;
  readonly sentAt: string;
  readonly receivedAt: string;
  readonly event: string;
  readonly stage: number;
  readonly command: string | null;
  readonly scenario: string | null;
  readonly functionalityOk: boolean | null;
  readonly score: number | null;
  readonly failedChecks: readonly string[];
  readonly centralCalls: number | null;
  readonly exerciseLoadError: boolean | null;
  readonly elapsedMs: number | null;
  readonly platform: string | null;
  readonly node: number | null;
}

export interface EventStore {
  insert(event: StoredEvent): Promise<void>;
  /** Per stage, how many sessions entered it and how many recorded a working trip there. */
  summary(cohort?: string): Promise<StageSummary[]>;
}

export interface StageSummary {
  readonly stage: number;
  readonly sessionsEntered: number;
  readonly sessionsWithWorkingTrip: number;
  readonly runs: number;
}

const EVENTS = new Set(["opt_in", "opt_out", "stage_enter", "run", "share"]);
const MAX_BODY_BYTES = 16 * 1024;
const MAX_LABEL = 120;
const MAX_LABELS = 40;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const COHORT = /^[A-Za-z0-9_-]{1,32}$/;

export class RejectedEvent extends Error {}

function str(v: unknown, max: number): string | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== "string" || v.length === 0 || v.length > max) throw new RejectedEvent("bad string field");
  return v;
}

function int(v: unknown, min: number, max: number): number | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max) throw new RejectedEvent("bad numeric field");
  return Math.round(v);
}

function bool(v: unknown): boolean | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== "boolean") throw new RejectedEvent("bad boolean field");
  return v;
}

/** Validate one incoming event. Throws RejectedEvent on anything off-shape. */
export function validate(raw: unknown, receivedAt: Date): StoredEvent {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new RejectedEvent("event must be an object");
  const e = raw as Record<string, unknown>;
  if (e["v"] !== 1) throw new RejectedEvent("unsupported version");
  if (typeof e["session"] !== "string" || !UUID.test(e["session"])) throw new RejectedEvent("bad session id");
  if (e["cohort"] !== undefined && (typeof e["cohort"] !== "string" || !COHORT.test(e["cohort"]))) throw new RejectedEvent("bad cohort");
  if (typeof e["event"] !== "string" || !EVENTS.has(e["event"])) throw new RejectedEvent("unknown event");
  const stage = int(e["stage"], 1, 10);
  if (stage === null) throw new RejectedEvent("stage required");
  const sentAt = typeof e["sentAt"] === "string" && !Number.isNaN(Date.parse(e["sentAt"])) ? new Date(e["sentAt"]).toISOString() : null;
  if (sentAt === null) throw new RejectedEvent("bad sentAt");
  let failed: readonly string[] = [];
  if (e["failedChecks"] !== undefined) {
    if (!Array.isArray(e["failedChecks"]) || e["failedChecks"].length > MAX_LABELS) throw new RejectedEvent("bad failedChecks");
    failed = e["failedChecks"].map((x) => {
      if (typeof x !== "string" || x.length === 0 || x.length > MAX_LABEL) throw new RejectedEvent("bad check label");
      return x;
    });
  }
  return {
    session: e["session"].toLowerCase(),
    cohort: typeof e["cohort"] === "string" ? e["cohort"] : null,
    sentAt,
    receivedAt: receivedAt.toISOString(),
    event: e["event"],
    stage,
    command: str(e["command"], 32),
    scenario: str(e["scenario"], 32),
    functionalityOk: bool(e["functionalityOk"]),
    score: int(e["score"], 0, 100),
    failedChecks: failed,
    centralCalls: int(e["centralCalls"], 0, 100_000),
    exerciseLoadError: bool(e["exerciseLoadError"]),
    elapsedMs: int(e["elapsedMs"], 0, 7 * 24 * 3600 * 1000),
    platform: str(e["platform"], 16),
    node: int(e["node"], 0, 999),
  };
}

export interface CollectorResponse {
  readonly status: number;
  readonly body: unknown;
}

/** Route one request. Framework-free so the Worker adapter is a few lines. */
export async function handle(
  method: string,
  path: string,
  bodyText: string | null,
  query: URLSearchParams,
  store: EventStore,
  now: () => Date = () => new Date(),
): Promise<CollectorResponse> {
  if (method === "POST" && path === "/v1/events") {
    if (bodyText === null || bodyText.length === 0) return { status: 400, body: { error: "empty body" } };
    if (bodyText.length > MAX_BODY_BYTES) return { status: 413, body: { error: "body too large" } };
    let parsed: unknown;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      return { status: 400, body: { error: "invalid json" } };
    }
    const items = Array.isArray(parsed) ? parsed : [parsed];
    if (items.length > 50) return { status: 413, body: { error: "too many events" } };
    let accepted = 0;
    for (const item of items) {
      try {
        await store.insert(validate(item, now()));
        accepted += 1;
      } catch (error) {
        if (error instanceof RejectedEvent) continue;
        throw error;
      }
    }
    return { status: 202, body: { accepted, rejected: items.length - accepted } };
  }
  if (method === "GET" && path === "/v1/summary") {
    const cohort = query.get("cohort");
    if (cohort !== null && !COHORT.test(cohort)) return { status: 400, body: { error: "bad cohort" } };
    return { status: 200, body: { stages: await store.summary(cohort ?? undefined) } };
  }
  if (method === "GET" && path === "/healthz") {
    return { status: 200, body: { ok: true } };
  }
  return { status: 404, body: { error: "not found" } };
}

/** In-memory store, for tests and local runs. */
export class MemoryStore implements EventStore {
  readonly events: StoredEvent[] = [];

  async insert(event: StoredEvent): Promise<void> {
    this.events.push(event);
  }

  async summary(cohort?: string): Promise<StageSummary[]> {
    const rows = cohort === undefined ? this.events : this.events.filter((e) => e.cohort === cohort);
    const out: StageSummary[] = [];
    for (let stage = 1; stage <= 10; stage += 1) {
      const mine = rows.filter((e) => e.stage === stage);
      out.push({
        stage,
        sessionsEntered: new Set(mine.map((e) => e.session)).size,
        sessionsWithWorkingTrip: new Set(mine.filter((e) => e.functionalityOk === true).map((e) => e.session)).size,
        runs: mine.filter((e) => e.event === "run").length,
      });
    }
    return out;
  }
}
