/** Privacy-preserving, local-only play history. No source, key, name, or timestamp. */
import type { Session } from "@tenuo/core";
import type { AgentId } from "./mission.ts";
import { loadState, saveState, type AttemptSnapshot, type HandoffSnapshot } from "./state.ts";
import type { ProbeResult } from "./harness/attacks.ts";
import type { Functionality } from "./harness/functionality.ts";
import type { Margin } from "./harness/margin.ts";
import type { Built } from "./harness/run.ts";
import type { Score } from "./harness/score.ts";

interface EvaluatedRun {
  readonly built: Built;
  readonly probes: readonly ProbeResult[];
  readonly functionality: Functionality;
}

export interface EvaluatedStage {
  readonly runs: readonly EvaluatedRun[];
  readonly functionality: Functionality;
  readonly probes: readonly ProbeResult[];
  readonly margin: Margin;
  readonly score: Score;
}

function ttlBucket(session: Session): HandoffSnapshot["ttl"] {
  const seconds = Math.max(0, session.inspect().expiresAt - Math.floor(Date.now() / 1000));
  if (seconds <= 2 * 60) return "under-3m";
  if (seconds <= 5 * 60) return "under-6m";
  if (seconds <= 15 * 60) return "under-15m";
  return "over-15m";
}

function handoff(e: EvaluatedStage, agent: AgentId): HandoffSnapshot | "missing" {
  const first = e.runs[0];
  const session = first?.built.runtime.tenuo?.session(agent, first.built.plan.trips[0]?.taskId ?? "");
  const expected = first?.built.runtime.tenuo?.fleet[agent].publicKey.hex;
  if (session === undefined || expected === undefined) return "missing";
  const info = session.inspect();
  // These are behavioral constraint checks for this exact receiver, not a
  // duplicated aggregate of the whole stage. They disclose no argument
  // values while still showing whether a participant tightened this hop.
  const constraints = e.probes.filter((probe) => agent === "boarding-agent"
    ? probe.section === "BOARDING AGENT AFTER THE HANDOFF"
    : probe.section !== "BOARDING AGENT AFTER THE HANDOFF" &&
      probe.section !== "TERMINAL" &&
      probe.section !== "STOLEN: activity-agent presents boarding-agent's warrant");
  return {
    tools: [...info.tools].sort(),
    constraintChecks: {
      passed: constraints.filter((probe) => probe.ok).length,
      total: constraints.length,
    },
    holderBound: info.holderPublicKey === expected,
    ttl: ttlBucket(session),
  };
}

export function snapshot(e: EvaluatedStage): AttemptSnapshot {
  const checks = e.probes.filter((probe) => probe.category !== "sanity");
  const base = {
    starsMissing: e.score.stars.filter((star) => !star.earned).map((star) => star.id),
    checks: { passed: checks.filter((probe) => probe.ok).length, total: checks.length },
  };
  if (e.runs[0]?.built.runtime.stage.n === 5) {
    return {
      ...base,
      handoffs: {
        "flight-to-checkin": handoff(e, "checkin-agent"),
        "checkin-to-boarding": handoff(e, "boarding-agent"),
      },
    };
  }
  return base;
}

export function recordAttempt(
  stage: number,
  value: AttemptSnapshot,
  options: { readonly acceptGreen?: boolean } = {},
): void {
  const state = loadState();
  const attempts = { ...(state.attempts ?? {}) };
  const previous = attempts[String(stage)];
  const green = options.acceptGreen !== false && value.starsMissing.length === 0;
  attempts[String(stage)] = previous === undefined
    ? { count: 1, firstAttempt: value, ...(green ? { firstGreen: value } : {}) }
    : {
        ...previous,
        count: previous.count + 1,
        ...(previous.firstGreen === undefined && green ? { firstGreen: value } : {}),
      };
  saveState({ ...state, attempts });
}
