/**
 * Concurrent session isolation.
 *
 * This file answers one question for Node.js server authors: when two
 * requests run at the same time and both call the same protected tool, can
 * one request ever act with the other request's authority? It cannot, and
 * the functions here show why in a form a test can assert.
 *
 * `tenuo.withSession()` scopes a session with Node's AsyncLocalStorage. Two
 * request flows that share one protected tool and interleave their awaits
 * each keep their own session: a flow reads only under its own root, and a
 * denied call never reaches the tool implementation.
 *
 * The interleaving is forced with a turn token rather than timers. Timers
 * would leave the order to the scheduler and the test could flake; the token
 * fixes the order, so every run yields the same event sequence.
 *
 * A plain closure does not capture its creation-time session. If a worker
 * invokes it without an ambient session, the call needs an explicit
 * `{ session }`. `runQueuedJobs()` demonstrates this with an unbound queue;
 * context-aware queues can propagate context themselves.
 *
 * Driven by `test/session-isolation.test.ts`. Run: `pnpm example:sessions`.
 */
import {
  AuthorizationDeniedError,
  createTenuo,
  TenuoError,
  under,
  type ProtectedTool,
  type Session,
  type Tenuo,
} from "../src/index.ts";

/** The two simulated requests. Each owns one directory under `/data`. */
export type FlowName = "reports" | "finance";

/** What a denial reports. Tests assert these stable fields, never message text. */
export type Denied = {
  readonly code: string;
  readonly field: string | undefined;
};

/**
 * What one flow observed. The reads happen in this order with the other flow
 * running in between, so isolation is checked both before and after the other
 * flow has had its turn.
 */
export type FlowResult = {
  readonly name: FlowName;
  /** Own path, read before the other flow runs. */
  readonly own: string;
  /** The other flow's path, attempted while that flow is mid-request. */
  readonly crossed: Denied | "allowed";
  /** Own path again, after the other flow has run in between. */
  readonly ownAgain: string;
};

/** Everything one `runConcurrentFlows()` execution produced, so a test can check it end to end. */
export type ConcurrentRun = {
  readonly results: readonly [FlowResult, FlowResult];
  /** Paths the tool implementation actually ran with, in order. A denied call never appears. */
  readonly executed: readonly string[];
  /** The order in which the two flows took their steps. */
  readonly log: readonly string[];
};

/**
 * Result of one queued job. Structured rather than a joined string so a test
 * can assert `code` and `message` separately, the way the SDK reports errors
 * everywhere else.
 */
export type JobOutcome =
  | { readonly ok: true; readonly value: string }
  | {
      readonly ok: false;
      readonly name: string;
      readonly code: string | undefined;
      readonly message: string;
    };

/** Both jobs from `runQueuedJobs()`: the same call without and with `{ session }`. */
export type QueuedRun = {
  /** Outcome of the job that relied on the ambient session. */
  readonly ambient: JobOutcome;
  /** Outcome of the same job with `{ session }` passed on the call. */
  readonly explicit: JobOutcome;
};

type ReadFile = {
  execute: (args: { path: string }) => Promise<string>;
};

/**
 * The fixture every scenario runs against: one client, one protected tool,
 * two sessions. `executed` is the evidence that a denied call never ran.
 */
export type Harness = {
  readonly tenuo: Tenuo;
  readonly readFile: ProtectedTool<ReadFile>;
  readonly sessions: Readonly<Record<FlowName, Session>>;
  /** Every path the implementation ran with. Denied calls never appear here. */
  readonly executed: string[];
};

/**
 * One file per flow. Both sit under `/data`, which the tool itself allows, so
 * when a cross-path read is denied the session is the only layer that could
 * have denied it.
 */
export const PATHS: Readonly<Record<FlowName, string>> = {
  reports: "/data/reports/q3.pdf",
  finance: "/data/finance/ledger.csv",
};

const OTHER: Readonly<Record<FlowName, FlowName>> = {
  reports: "finance",
  finance: "reports",
};

/**
 * Builds the fixture. The tool ceiling is all of `/data` on purpose: it admits
 * both flows' paths, so a denial can only come from the session. The dev root
 * keeps the example free of key material; vitest sets `NODE_ENV=test`, which
 * the dev root requires.
 */
export function createHarness(): Harness {
  const tenuo = createTenuo({ root: createTenuo.devRoot() });
  const executed: string[] = [];
  const readFile = tenuo.tool(
    {
      execute: async ({ path }: { path: string }) => {
        executed.push(path);
        return `contents:${path}`;
      },
    },
    { capability: "read_file", allow: { path: under("/data") } },
  );
  const sessions: Readonly<Record<FlowName, Session>> = {
    reports: tenuo.session({ allow: { read_file: { path: under("/data/reports") } } }),
    finance: tenuo.session({ allow: { read_file: { path: under("/data/finance") } } }),
  };
  return { tenuo, readFile, sessions, executed };
}

/**
 * Hands a single turn back and forth between two flows.
 *
 * Timers would leave the interleaving to the scheduler. A turn token makes it
 * exact: a flow parks until the other flow passes, so at every step one flow
 * is provably mid-request while the other acts. `current` records whose turn
 * it is, so a `pass()` that arrives before the peer has called `wait()` is
 * not lost.
 */
class Turns {
  private current: FlowName;
  private readonly waiting = new Map<FlowName, () => void>();

  constructor(first: FlowName) {
    this.current = first;
  }

  /** Resolves at once if it is already `name`'s turn, otherwise parks until `pass(name)`. */
  wait(name: FlowName): Promise<void> {
    if (this.current === name) {
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      this.waiting.set(name, resolve);
    });
  }

  /** Gives the turn to `next` and wakes it if it is parked. */
  pass(next: FlowName): void {
    this.current = next;
    const wake = this.waiting.get(next);
    if (wake !== undefined) {
      this.waiting.delete(next);
      wake();
    }
  }
}

/**
 * One simulated request. Three reads in a fixed order, own path, then the
 * other flow's path, then own path again, so isolation is checked both before
 * and after the other flow has run in between.
 */
async function flow(harness: Harness, name: FlowName, turns: Turns, log: string[]): Promise<FlowResult> {
  const { tenuo, readFile, sessions } = harness;
  const other = OTHER[name];
  return tenuo.withSession(sessions[name], async () => {
    await turns.wait(name);
    log.push(`${name}: read own`);
    const own = await readFile.execute({ path: PATHS[name] });
    turns.pass(other);

    // The other flow wakes this one from inside its own withSession() scope.
    // The continuation below still runs under this flow's session, because
    // AsyncLocalStorage follows the awaiting code, not the code that resolved
    // the promise.
    await turns.wait(name);
    log.push(`${name}: try other`);
    const crossed = await readFile.execute({ path: PATHS[other] }).then(
      (): FlowResult["crossed"] => "allowed",
      (error: unknown): FlowResult["crossed"] => {
        if (error instanceof AuthorizationDeniedError) {
          return { code: error.code, field: error.field };
        }
        throw error;
      },
    );
    turns.pass(other);

    await turns.wait(name);
    log.push(`${name}: read own again`);
    const ownAgain = await readFile.execute({ path: PATHS[name] });
    turns.pass(other);

    return { name, own, crossed, ownAgain };
  });
}

/**
 * Two flows, one tool, fixed interleaving. `Promise.all` starts both flows
 * synchronously, so the second flow registers its waiter before the first
 * takes a step. From there every hand-off wakes exactly one parked flow, so
 * the order is fixed with no dependence on timers or the scheduler.
 */
export async function runConcurrentFlows(harness: Harness): Promise<ConcurrentRun> {
  const turns = new Turns("reports");
  const log: string[] = [];
  const results = await Promise.all([
    flow(harness, "reports", turns, log),
    flow(harness, "finance", turns, log),
  ]);
  return { results, executed: [...harness.executed], log };
}

/** Records why a job failed in fields a test can assert one by one. */
function failure(error: unknown): JobOutcome {
  return {
    ok: false,
    name: error instanceof Error ? error.name : "unknown",
    code: error instanceof TenuoError ? error.code : undefined,
    message: error instanceof Error ? error.message : String(error),
  };
}

/**
 * Jobs enqueued inside withSession() and run by a worker outside it. The job
 * that relies on ambient context fails closed; the job that carries
 * `{ session }` runs. The jobs are two named fields rather than an array
 * because this package compiles with `noUncheckedIndexedAccess`, under which
 * array destructuring yields possibly-undefined values.
 */
export async function runQueuedJobs(harness: Harness): Promise<QueuedRun> {
  const { tenuo, readFile, sessions } = harness;
  const session = sessions.reports;
  type Job = () => Promise<string>;
  const queued: { ambient?: Job; explicit?: Job } = {};

  tenuo.withSession(session, () => {
    queued.ambient = () => readFile.execute({ path: PATHS.reports });
    queued.explicit = () => readFile.execute({ path: PATHS.reports }, { session });
  });

  if (queued.ambient === undefined || queued.explicit === undefined) {
    throw new Error("jobs were not enqueued");
  }
  // This is the worker: it runs outside any withSession() scope.
  const run = (job: Job): Promise<JobOutcome> =>
    job().then((value): JobOutcome => ({ ok: true, value }), failure);
  const [ambient, explicit] = await Promise.all([run(queued.ambient), run(queued.explicit)]);
  return { ambient, explicit };
}
