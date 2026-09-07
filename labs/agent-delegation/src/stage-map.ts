/**
 * The public lab map. CLI stages and hosted pages both read this file so the
 * number, title, mode, timing, and main-game/boss split cannot drift.
 */
export type LabMode = "shared" | "identity" | "scoped" | "tenuo";
export type StageTier = "main" | "boss";

export interface StageMeta {
  readonly n: number;
  readonly title: string;
  readonly mode: LabMode;
  readonly minutes: number;
  readonly tier: StageTier;
  readonly goal: string;
}

export const STAGE_MAP = [
  {
    n: 1,
    title: "One key for everyone",
    mode: "shared",
    minutes: 5,
    tier: "main",
    goal: "See what a rogue agent can do when every agent shares one credential.",
  },
  {
    n: 2,
    title: "Every agent gets its own account",
    mode: "identity",
    minutes: 5,
    tier: "main",
    goal: "Give each agent its own credential and see which damage that removes and which damage remains.",
  },
  {
    n: 3,
    title: "Rules that fit the job",
    mode: "scoped",
    minutes: 15,
    tier: "main",
    goal: "Write permissions narrow enough that every rogue action is blocked and the trip still books.",
  },
  {
    n: 4,
    title: "Two travelers, then a handoff",
    mode: "scoped",
    minutes: 30,
    tier: "main",
    goal: "First isolate Alice from Bob; then observe why passing a whole credential gives the next agent too much.",
  },
  {
    n: 5,
    title: "Access that travels with the work",
    mode: "tenuo",
    minutes: 25,
    tier: "main",
    goal: "Complete one narrowing handoff so the trip works, the rogue stops, and no central lookup is needed.",
  },
  {
    n: 6,
    title: "Boss: stolen authority",
    mode: "tenuo",
    minutes: 15,
    tier: "boss",
    goal: "See why a copied permission cannot be used by another agent, then deliberately end a delegation chain.",
  },
  {
    n: 7,
    title: "Boss: contain the incident",
    mode: "tenuo",
    minutes: 20,
    tier: "boss",
    goal: "Contain a compromised Hotel Agent while legitimate bookings keep working.",
  },
] as const satisfies readonly StageMeta[];

export const MAIN_STAGE_COUNT = STAGE_MAP.filter((stage) => stage.tier === "main").length;
export const TOTAL_STAGE_COUNT = STAGE_MAP.length;

export function stageMeta(n: number): StageMeta {
  const found = STAGE_MAP.find((stage) => stage.n === n);
  if (found === undefined) throw new Error(`no stage ${n}`);
  return found;
}

/** Optional next step, intentionally outside the numbered game. */
export const EPILOGUE = {
  slug: "contribute",
  title: "Contribute to Tenuo",
  goal: "Optional: take what you used in the lab and open a small pull request.",
} as const;
