/**
 * Concurrent session isolation.
 *
 * `tenuo.withSession()` scopes a session with Node's AsyncLocalStorage. Two
 * request flows that share one protected tool and interleave their awaits
 * each keep their own session: a flow reads only under its own root, and a
 * denied call never reaches the tool implementation.
 *
 * The interleaving is forced with a turn token rather than timers, so the
 * order of events is fixed and every run produces the same log.
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

export type FlowName = "reports" | "finance";

export type Denied = {
  readonly code: string;
  readonly field: string | undefined;
};

export type FlowResult = {
  readonly name: FlowName;
  /** Own path, read before the other flow runs. */
  readonly own: string;
  /** The other flow's path, attempted while that flow is mid-request. */
  readonly crossed: Denied | "allowed";
  /** Own path again, after the other flow has run in between. */
  readonly ownAgain: string;
};

export type ConcurrentRun = {
  readonly results: readonly [FlowResult, FlowResult];
  /** Paths the tool implementation actually ran with, in order. */
  readonly executed: readonly string[];
  /** Interleaving of the two flows, in order. */
  readonly log: readonly string[];
};

export type QueuedRun = {
  /** Outcome of the job that relied on the ambient session. */
  readonly ambient: string;
  /** Outcome of the same job with `{ session }` passed on the call. */
  readonly explicit: string;
};

type ReadFile = {
  execute: (args: { path: string }) => Promise<string>;
};

export type Harness = {
  readonly tenuo: Tenuo;
  readonly readFile: ProtectedTool<ReadFile>;
  readonly sessions: Readonly<Record<FlowName, Session>>;
  /** Every path the implementation ran with. Denied calls never appear here. */
  readonly executed: string[];
};

export const PATHS: Readonly<Record<FlowName, string>> = {
  reports: "/data/reports/q3.pdf",
  finance: "/data/finance/ledger.csv",
};

const OTHER: Readonly<Record<FlowName, FlowName>> = {
  reports: "finance",
  finance: "reports",
};

/** One dev-root client, one recording tool, two sessions with different roots. */
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

/** Hands a single turn back and forth between two flows. */
class Turns {
  private current: FlowName;
  private readonly waiting = new Map<FlowName, () => void>();

  constructor(first: FlowName) {
    this.current = first;
  }

  wait(name: FlowName): Promise<void> {
    if (this.current === name) {
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      this.waiting.set(name, resolve);
    });
  }

  pass(next: FlowName): void {
    this.current = next;
    const wake = this.waiting.get(next);
    if (wake !== undefined) {
      this.waiting.delete(next);
      wake();
    }
  }
}

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

/** Two flows, one tool, fixed interleaving. */
export async function runConcurrentFlows(harness: Harness): Promise<ConcurrentRun> {
  const turns = new Turns("reports");
  const log: string[] = [];
  const results = await Promise.all([
    flow(harness, "reports", turns, log),
    flow(harness, "finance", turns, log),
  ]);
  return { results, executed: [...harness.executed], log };
}

function describeError(error: unknown): string {
  if (error instanceof TenuoError) {
    return `${error.name}:${error.code}`;
  }
  return error instanceof Error ? error.name : String(error);
}

/**
 * Jobs enqueued inside withSession() and run by a worker outside it. The job
 * that relies on ambient context fails closed; the job that carries
 * `{ session }` runs.
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
  const run = (job: Job): Promise<string> => job().then((value) => `ok:${value}`, describeError);
  const [ambient, explicit] = await Promise.all([run(queued.ambient), run(queued.explicit)]);
  return { ambient, explicit };
}
