/**
 * The event collector, as a pure function over a store, so it can be tested
 * without Cloudflare and deployed as a Worker with a one-line adapter.
 *
 * Accepts the events `src/telemetry.ts` sends, from the CLI and from the
 * hosted guide. Rejects anything else. Stores exactly the fields it knows
 * and nothing it does not. There is no identity here: `session` is a random
 * id the participant's install generated.
 */

export interface StoredEvent {
  readonly session: string;
  readonly cohort: string | null;
  readonly sentAt: string;
  readonly receivedAt: string;
  readonly event: string;
  readonly stage: number;
  readonly labVersion: string | null;
  readonly env: string | null;
  readonly command: string | null;
  readonly scenario: string | null;
  readonly functionalityOk: boolean | null;
  readonly score: number | null;
  readonly failedChecks: readonly string[];
  readonly centralCalls: number | null;
  readonly exerciseLoadError: boolean | null;
  readonly elapsedMs: number | null;
  readonly fix: string | null;
  readonly marginPoints: number | null;
  readonly marginAgents: readonly string[];
  readonly platform: string | null;
  readonly node: number | null;
}

export interface EventStore {
  insert(event: StoredEvent): Promise<void>;
  /** Every stored event, optionally for one cohort. Classrooms are small; the summary is computed in memory. */
  all(cohort?: string): Promise<StoredEvent[]>;
}

export interface StageSummary {
  readonly stage: number;
  readonly sessionsEntered: number;
  readonly sessionsWithWorkingTrip: number;
  readonly runs: number;
  /** Median runs (lab, attack, score) a session needed before its first working trip here. */
  readonly medianAttemptsToWorkingTrip: number | null;
  /** Median minutes from a session's first event in this stage to its first event in a later one. */
  readonly medianMinutes: number | null;
  /** Median of each session's last score here. */
  readonly medianScore: number | null;
  readonly topFailedChecks: ReadonlyArray<{ readonly label: string; readonly sessions: number }>;
  readonly pageViews: number;
  readonly hintOpens: number;
  readonly answerOpens: number;
  readonly markedDone: number;
}

export interface Summary {
  readonly sessions: number;
  readonly optIns: number;
  readonly envs: Record<string, number>;
  readonly versions: Record<string, number>;
  readonly fixes: Record<string, number>;
  readonly stages: StageSummary[];
}

const EVENTS = new Set(["opt_in", "opt_out", "stage_enter", "run", "share", "page_view", "hint_open", "answer_open", "mark_done"]);
const ENVS = new Set(["local", "codespaces", "web"]);
const FIXES = new Set(["per-task", "policy-service"]);
const MAX_BODY_BYTES = 16 * 1024;
const MAX_LABEL = 120;
const MAX_LABELS = 40;
const STAGE_COUNT = 8;
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

function labels(v: unknown, what: string): readonly string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > MAX_LABELS) throw new RejectedEvent(`bad ${what}`);
  return v.map((x) => {
    if (typeof x !== "string" || x.length === 0 || x.length > MAX_LABEL) throw new RejectedEvent(`bad ${what} label`);
    return x;
  });
}

function oneOf(v: unknown, set: Set<string>, what: string): string | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== "string" || !set.has(v)) throw new RejectedEvent(`bad ${what}`);
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
  // Stage 0 is the guide's index and wrap-up pages.
  const stage = int(e["stage"], 0, 10);
  if (stage === null) throw new RejectedEvent("stage required");
  const sentAt = typeof e["sentAt"] === "string" && !Number.isNaN(Date.parse(e["sentAt"])) ? new Date(e["sentAt"]).toISOString() : null;
  if (sentAt === null) throw new RejectedEvent("bad sentAt");
  return {
    session: e["session"].toLowerCase(),
    cohort: typeof e["cohort"] === "string" ? e["cohort"] : null,
    sentAt,
    receivedAt: receivedAt.toISOString(),
    event: e["event"],
    stage,
    labVersion: str(e["labVersion"], 64),
    env: oneOf(e["env"], ENVS, "env"),
    command: str(e["command"], 32),
    scenario: str(e["scenario"], 32),
    functionalityOk: bool(e["functionalityOk"]),
    score: int(e["score"], 0, 100),
    failedChecks: labels(e["failedChecks"], "failedChecks"),
    centralCalls: int(e["centralCalls"], 0, 100_000),
    exerciseLoadError: bool(e["exerciseLoadError"]),
    elapsedMs: int(e["elapsedMs"], 0, 7 * 24 * 3600 * 1000),
    fix: oneOf(e["fix"], FIXES, "fix"),
    marginPoints: int(e["marginPoints"], 0, 20),
    marginAgents: labels(e["marginAgents"], "marginAgents"),
    platform: str(e["platform"], 16),
    node: int(e["node"], 0, 999),
  };
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const m = sorted.length % 2 === 1 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
  return Math.round(m * 10) / 10;
}

function count(values: Iterable<string | null>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const v of values) {
    if (v === null) continue;
    out[v] = (out[v] ?? 0) + 1;
  }
  return out;
}

const RUN_COMMANDS = new Set(["lab", "attack", "score"]);

/** Everything the summary endpoint reports, from the raw rows. */
export function summarize(rows: readonly StoredEvent[]): Summary {
  const bySession = new Map<string, StoredEvent[]>();
  for (const r of rows) {
    const list = bySession.get(r.session);
    if (list === undefined) bySession.set(r.session, [r]);
    else list.push(r);
  }
  for (const list of bySession.values()) list.sort((a, b) => a.sentAt.localeCompare(b.sentAt));

  const perSessionLast = (pick: (r: StoredEvent) => string | null): Iterable<string | null> =>
    [...bySession.values()].map((list) => {
      for (let i = list.length - 1; i >= 0; i -= 1) {
        const v = pick(list[i]!);
        if (v !== null) return v;
      }
      return null;
    });

  const stages: StageSummary[] = [];
  for (let stage = 1; stage <= STAGE_COUNT; stage += 1) {
    const entered = new Set<string>();
    const working = new Set<string>();
    const attempts: number[] = [];
    const minutes: number[] = [];
    const scores: number[] = [];
    const failed = new Map<string, Set<string>>();
    const views = new Set<string>();
    const hints = new Set<string>();
    const answers = new Set<string>();
    const done = new Set<string>();
    let runs = 0;
    for (const [session, list] of bySession) {
      const here = list.filter((r) => r.stage === stage);
      if (here.length === 0) continue;
      entered.add(session);
      let tries = 0;
      let firstWorking: number | null = null;
      let lastScore: number | null = null;
      for (const r of here) {
        if (r.event === "run") {
          runs += 1;
          if (r.command !== null && RUN_COMMANDS.has(r.command)) {
            tries += 1;
            if (firstWorking === null && r.functionalityOk === true) firstWorking = tries;
          }
          if (r.score !== null) lastScore = r.score;
          for (const label of r.failedChecks) {
            const set = failed.get(label) ?? new Set<string>();
            set.add(session);
            failed.set(label, set);
          }
        }
        if (r.functionalityOk === true) working.add(session);
        if (r.event === "page_view") views.add(session);
        if (r.event === "hint_open") hints.add(session);
        if (r.event === "answer_open") answers.add(session);
        if (r.event === "mark_done") done.add(session);
      }
      if (firstWorking !== null) attempts.push(firstWorking);
      if (lastScore !== null) scores.push(lastScore);
      const first = Date.parse(here[0]!.sentAt);
      const later = list.find((r) => r.stage > stage && Date.parse(r.sentAt) > first);
      const end = later !== undefined ? Date.parse(later.sentAt) : Date.parse(here[here.length - 1]!.sentAt);
      if (end > first) minutes.push((end - first) / 60_000);
    }
    stages.push({
      stage,
      sessionsEntered: entered.size,
      sessionsWithWorkingTrip: working.size,
      runs,
      medianAttemptsToWorkingTrip: median(attempts),
      medianMinutes: median(minutes),
      medianScore: median(scores),
      topFailedChecks: [...failed.entries()]
        .map(([label, sessions]) => ({ label, sessions: sessions.size }))
        .sort((a, b) => b.sessions - a.sessions || a.label.localeCompare(b.label))
        .slice(0, 5),
      pageViews: views.size,
      hintOpens: hints.size,
      answerOpens: answers.size,
      markedDone: done.size,
    });
  }
  return {
    sessions: bySession.size,
    optIns: rows.filter((r) => r.event === "opt_in").length,
    // The CLI's env, never the guide's: a session that ran anything reports local or codespaces.
    envs: count(perSessionLast((r) => (r.env !== null && r.env !== "web" ? r.env : null))),
    versions: count(perSessionLast((r) => r.labVersion)),
    fixes: count(perSessionLast((r) => r.fix)),
    stages,
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
    return { status: 200, body: summarize(await store.all(cohort ?? undefined)) };
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

  async all(cohort?: string): Promise<StoredEvent[]> {
    return cohort === undefined ? [...this.events] : this.events.filter((e) => e.cohort === cohort);
  }
}
