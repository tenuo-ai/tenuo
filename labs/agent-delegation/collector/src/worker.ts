/**
 * Cloudflare Worker adapter over `collector.ts`, backed by D1.
 *
 *   wrangler d1 create lab-events
 *   wrangler d1 execute lab-events --file=schema.sql
 *   wrangler deploy
 *
 * Point the CLI at it with TENUO_LAB_EVENTS_URL, or change DEFAULT_EVENTS_URL
 * in src/telemetry.ts once the route is live. The hosted guide posts to the
 * same address from the browser, so responses carry CORS headers.
 */
import { handle, type EventStore, type StoredEvent } from "./collector.ts";

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  run(): Promise<unknown>;
  all<T>(): Promise<{ results: T[] }>;
}
interface D1Database {
  prepare(sql: string): D1PreparedStatement;
}
interface Env {
  readonly DB: D1Database;
}

interface Row {
  session: string;
  cohort: string | null;
  sent_at: string;
  received_at: string;
  event: string;
  stage: number;
  lab_version: string | null;
  env: string | null;
  command: string | null;
  scenario: string | null;
  functionality_ok: number | null;
  score: number | null;
  failed_checks: string;
  central_calls: number | null;
  exercise_load_error: number | null;
  elapsed_ms: number | null;
  fix: string | null;
  margin_points: number | null;
  margin_agents: string;
  platform: string | null;
  node: number | null;
}

function flag(v: boolean | null): number | null {
  return v === null ? null : v ? 1 : 0;
}

function fromRow(r: Row): StoredEvent {
  return {
    session: r.session,
    cohort: r.cohort,
    sentAt: r.sent_at,
    receivedAt: r.received_at,
    event: r.event,
    stage: r.stage,
    labVersion: r.lab_version,
    env: r.env,
    command: r.command,
    scenario: r.scenario,
    functionalityOk: r.functionality_ok === null ? null : r.functionality_ok === 1,
    score: r.score,
    failedChecks: JSON.parse(r.failed_checks) as string[],
    centralCalls: r.central_calls,
    exerciseLoadError: r.exercise_load_error === null ? null : r.exercise_load_error === 1,
    elapsedMs: r.elapsed_ms,
    fix: r.fix,
    marginPoints: r.margin_points,
    marginAgents: JSON.parse(r.margin_agents) as string[],
    platform: r.platform,
    node: r.node,
  };
}

class D1Store implements EventStore {
  constructor(private readonly db: D1Database) {}

  async insert(e: StoredEvent): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO events (session, cohort, sent_at, received_at, event, stage, lab_version, env, command, scenario, functionality_ok, score, failed_checks, central_calls, exercise_load_error, elapsed_ms, fix, margin_points, margin_agents, platform, node)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)`,
      )
      .bind(
        e.session, e.cohort, e.sentAt, e.receivedAt, e.event, e.stage, e.labVersion, e.env, e.command, e.scenario,
        flag(e.functionalityOk), e.score, JSON.stringify(e.failedChecks), e.centralCalls, flag(e.exerciseLoadError),
        e.elapsedMs, e.fix, e.marginPoints, JSON.stringify(e.marginAgents), e.platform, e.node,
      )
      .run();
  }

  async all(cohort?: string): Promise<StoredEvent[]> {
    const stmt = this.db.prepare(cohort === undefined ? "SELECT * FROM events ORDER BY sent_at" : "SELECT * FROM events WHERE cohort = ?1 ORDER BY sent_at");
    const { results } = await (cohort === undefined ? stmt : stmt.bind(cohort)).all<Row>();
    return results.map(fromRow);
  }
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, GET, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "86400",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }
    const url = new URL(request.url);
    const body = request.method === "POST" ? await request.text() : null;
    const result = await handle(request.method, url.pathname, body, url.searchParams, new D1Store(env.DB));
    return new Response(JSON.stringify(result.body), {
      status: result.status,
      headers: { ...CORS, "content-type": "application/json", "cache-control": "no-store" },
    });
  },
};
