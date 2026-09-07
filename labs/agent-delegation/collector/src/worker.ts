/**
 * Cloudflare Worker adapter over `collector.ts`, backed by D1.
 *
 *   wrangler d1 create lab-events
 *   wrangler d1 execute lab-events --file=schema.sql
 *   wrangler deploy
 *
 * Point the CLI at it with TENUO_LAB_EVENTS_URL, or change DEFAULT_EVENTS_URL
 * in src/telemetry.ts once the route is live.
 */
import { handle, type EventStore, type StageSummary, type StoredEvent } from "./collector.ts";

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

class D1Store implements EventStore {
  constructor(private readonly db: D1Database) {}

  async insert(e: StoredEvent): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO events (session, cohort, sent_at, received_at, event, stage, command, scenario, functionality_ok, score, failed_checks, central_calls, exercise_load_error, elapsed_ms, platform, node)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)`,
      )
      .bind(
        e.session, e.cohort, e.sentAt, e.receivedAt, e.event, e.stage, e.command, e.scenario,
        e.functionalityOk === null ? null : e.functionalityOk ? 1 : 0,
        e.score, JSON.stringify(e.failedChecks), e.centralCalls,
        e.exerciseLoadError === null ? null : e.exerciseLoadError ? 1 : 0,
        e.elapsedMs, e.platform, e.node,
      )
      .run();
  }

  async summary(cohort?: string): Promise<StageSummary[]> {
    const where = cohort === undefined ? "" : "WHERE cohort = ?1";
    const stmt = this.db.prepare(
      `SELECT stage,
              COUNT(DISTINCT session) AS sessions_entered,
              COUNT(DISTINCT CASE WHEN functionality_ok = 1 THEN session END) AS sessions_with_working_trip,
              SUM(CASE WHEN event = 'run' THEN 1 ELSE 0 END) AS runs
       FROM events ${where}
       GROUP BY stage ORDER BY stage`,
    );
    const bound = cohort === undefined ? stmt : stmt.bind(cohort);
    const { results } = await bound.all<{ stage: number; sessions_entered: number; sessions_with_working_trip: number; runs: number }>();
    return results.map((r) => ({
      stage: r.stage,
      sessionsEntered: r.sessions_entered,
      sessionsWithWorkingTrip: r.sessions_with_working_trip,
      runs: r.runs,
    }));
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const body = request.method === "POST" ? await request.text() : null;
    const result = await handle(request.method, url.pathname, body, url.searchParams, new D1Store(env.DB));
    return new Response(JSON.stringify(result.body), {
      status: result.status,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  },
};
