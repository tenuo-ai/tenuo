import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT, getOrCreateSessionId, type AttemptSnapshot, type StageAttempts } from "./state.ts";

export const SHARE_SCHEMA = "tenuo-lab-share-v2";
export const DEFAULT_SHARE_ENDPOINT = "https://api.tenuo.ai/v1/lab/submissions";

const USERNAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

interface ShareHandoff {
  readonly tools: readonly string[];
  readonly constraintChecks: { readonly passed: number; readonly total: number };
  readonly holderBound: boolean;
  readonly ttl: string;
}

interface ShareAttempt {
  readonly starsMissing: readonly string[];
  readonly checks: { readonly passed: number; readonly total: number };
  readonly handoffs?: Record<string, ShareHandoff | null>;
}

export interface ShareReport {
  readonly schema: typeof SHARE_SCHEMA;
  readonly sessionId: string;
  readonly challengeVersion: string;
  readonly sdkVersion: string;
  readonly stage: number;
  readonly stars: Record<string, boolean>;
  readonly attempts: { readonly count: number; readonly firstAttempt?: ShareAttempt; readonly firstGreen?: ShareAttempt };
  readonly runtime: { readonly nodeMajor: number; readonly platform: "darwin" | "linux" | "win32" };
  readonly username?: string;
}

export interface ShareReceipt {
  readonly receiptId: string;
  readonly leaderboardEligible: boolean;
}

function packageVersions(): { challengeVersion: string; sdkVersion: string } {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
    version?: unknown;
    dependencies?: Record<string, unknown>;
  };
  const challengeVersion = typeof pkg.version === "string" ? pkg.version : "unknown";
  const sdk = pkg.dependencies?.["@tenuo/core"];
  const sdkVersion = typeof sdk === "string" ? sdk.replace(/^[^0-9]*/, "") : "unknown";
  return { challengeVersion, sdkVersion };
}

export function normalizeUsername(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const username = value.trim();
  if (!USERNAME.test(username) || username.includes("--")) {
    throw new Error("--username must be a GitHub-style username (1–39 letters, numbers, or single hyphens)");
  }
  return username;
}

function shareAttempt(attempt: AttemptSnapshot): ShareAttempt {
  if (attempt.handoffs === undefined) {
    return { starsMissing: attempt.starsMissing, checks: attempt.checks };
  }
  return {
    ...attempt,
    handoffs: Object.fromEntries(Object.entries(attempt.handoffs).map(([name, handoff]) => [
      name,
      handoff === "missing" ? null : handoff,
    ])),
  };
}

function shareAttempts(attempts: StageAttempts | undefined): ShareReport["attempts"] {
  if (attempts === undefined) return { count: 0 };
  return {
    count: attempts.count,
    firstAttempt: shareAttempt(attempts.firstAttempt),
    ...(attempts.firstGreen === undefined ? {} : { firstGreen: shareAttempt(attempts.firstGreen) }),
  };
}

export function buildShareReport(
  stage: number,
  stars: Record<string, boolean>,
  attempts: StageAttempts | undefined,
  usernameValue?: string,
): ShareReport {
  const username = normalizeUsername(usernameValue);
  const versions = packageVersions();
  const platform = process.platform;
  if (platform !== "darwin" && platform !== "linux" && platform !== "win32") {
    throw new Error(`sharing is not supported on platform ${platform}`);
  }
  return {
    schema: SHARE_SCHEMA,
    sessionId: getOrCreateSessionId(),
    ...versions,
    stage,
    stars,
    attempts: shareAttempts(attempts),
    runtime: { nodeMajor: Number(process.versions.node.split(".")[0]), platform },
    ...(username === undefined ? {} : { username }),
  };
}

export async function submitShareReport(
  report: ShareReport,
  options: { endpoint?: string; fetch?: typeof fetch; timeoutMs?: number } = {},
): Promise<ShareReceipt | undefined> {
  const configured = options.endpoint ?? process.env["TENUO_LAB_EVENTS_URL"]?.trim() ?? DEFAULT_SHARE_ENDPOINT;
  if (configured === "off") return undefined;
  const endpoint = new URL(configured);
  if (endpoint.protocol !== "https:" && endpoint.hostname !== "localhost" && endpoint.hostname !== "127.0.0.1") {
    throw new Error("share endpoint must use HTTPS");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 8_000);
  try {
    const response = await (options.fetch ?? fetch)(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`receiver returned HTTP ${response.status}`);
    const body = await response.json() as Partial<ShareReceipt>;
    if (typeof body.receiptId !== "string" || typeof body.leaderboardEligible !== "boolean") {
      throw new Error("receiver returned an invalid receipt");
    }
    return { receiptId: body.receiptId, leaderboardEligible: body.leaderboardEligible };
  } finally {
    clearTimeout(timer);
  }
}
