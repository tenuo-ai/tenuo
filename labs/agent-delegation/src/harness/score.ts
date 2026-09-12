/**
 * 100 points, with a gate. The trip has to work; blocking everything is not
 * a solution, it is a broken travel service.
 */
import type { ProbeResult } from "./attacks.ts";
import type { Functionality } from "./functionality.ts";
import type { Margin } from "./margin.ts";

export interface Score {
  readonly gated: boolean;
  readonly functionality: { readonly points: number; readonly max: 25; readonly ok: boolean };
  readonly blocked: { readonly points: number; readonly max: 30; readonly passed: number; readonly total: number };
  readonly handoffs: { readonly points: number; readonly max: 25; readonly passed: number; readonly total: number };
  readonly margin: { readonly points: number; readonly max: 20; readonly findings: Margin["findings"] };
  readonly stars: readonly Star[];
  readonly total: number;
}

export type StarId = "trip-booked" | "rogue-stopped" | "tight-handoff" | "no-spare-authority";

export interface Star {
  readonly id: StarId;
  readonly label: string;
  readonly earned: boolean;
}

function rate(results: readonly ProbeResult[], max: number): { points: number; passed: number; total: number } {
  const total = results.length;
  const passed = results.filter((r) => r.ok).length;
  const points = total === 0 ? max : Math.round((max * passed) / total);
  return { points, passed, total };
}

export function score(functionality: Functionality, probes: readonly ProbeResult[], margin: Margin): Score {
  const blocked = rate(probes.filter((p) => p.category === "blocked"), 30);
  const handoffs = rate(probes.filter((p) => p.category === "handoff" || p.category === "cross-task"), 25);
  const gated = !functionality.ok;
  const fPoints = functionality.ok ? 25 : 0;
  const total = gated ? 0 : fPoints + blocked.points + handoffs.points + margin.points;
  const stars: readonly Star[] = [
    { id: "trip-booked", label: "Trip booked", earned: functionality.ok },
    { id: "rogue-stopped", label: "Rogue stopped", earned: blocked.total > 0 && blocked.passed === blocked.total },
    { id: "tight-handoff", label: "Tight handoff", earned: handoffs.total > 0 && handoffs.passed === handoffs.total },
    { id: "no-spare-authority", label: "No spare authority", earned: margin.findings.length === 0 },
  ];
  return {
    gated,
    functionality: { points: fPoints, max: 25, ok: functionality.ok },
    blocked: { ...blocked, max: 30 },
    handoffs: { ...handoffs, max: 25 },
    margin: { points: margin.points, max: 20, findings: margin.findings },
    stars,
    total,
  };
}
