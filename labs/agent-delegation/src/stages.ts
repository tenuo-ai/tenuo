/**
 * Seven stages. Each is a system, a rogue agent, and a set of tests. The
 * participant changes how permissions work, then runs the tests again.
 */
import { stageMeta, type LabMode } from "./stage-map.ts";

export type Mode = LabMode;
export type Scenario = "spring-break" | "two-travelers" | "incident";

export interface StageDef {
  readonly n: number;
  readonly title: string;
  readonly mode: Mode;
  readonly scenario: Scenario;
  /** How Check-in Agent hands work to Boarding Agent in modes 1 to 3. */
  readonly handoff: "own-identity" | "pass-credential";
  /** File the participant edits, relative to the repo root. */
  readonly exercise?: string;
  /** Second scenario to run after the first, without touching any file. */
  readonly alsoRun?: Scenario;
  /** Extra probes the attack battery runs for this stage. */
  readonly probes?: readonly ("escalation" | "stolen" | "terminal")[];
  /** The stage is meant to break the trip, so completing it is not scored. */
  readonly breaksTrip?: true;
  /** The first stage where a Tenuo check ran locally; the CLI mentions the repository once here. */
  readonly starAsk?: true;
  readonly blurb: readonly string[];
}

const meta = (n: number) => {
  const { title, mode } = stageMeta(n);
  return { n, title, mode };
};

export const STAGES: readonly StageDef[] = [
  {
    ...meta(1),
    scenario: "spring-break",
    handoff: "own-identity",
    blurb: [
      "Every agent carries the same credential. It opens flights, hotels, activities, the wallet,",
      "the traveler's personal details, and the calendar.",
      "",
      "There is no setup here. Run `npm run attack` and look at the wallet.",
    ],
  },
  {
    ...meta(2),
    scenario: "spring-break",
    handoff: "own-identity",
    blurb: [
      "Each agent has its own credential with permissions that match its role.",
      "",
      "Run `npm run attack` and compare with stage 1. The actions that still succeed are all",
      "actions Check-in Agent's role includes. What separates the ones you want from the ones",
      "you do not?",
    ],
  },
  {
    ...meta(3),
    scenario: "spring-break",
    handoff: "own-identity",
    exercise: "exercises/03-scoped/policy.ts",
    blurb: [
      "Now you write the permissions. Open exercises/03-scoped/policy.ts.",
      "",
      "Narrow the rules until `npm run attack` is clean and the trip still books.",
    ],
  },
  {
    ...meta(4),
    scenario: "two-travelers",
    handoff: "pass-credential",
    exercise: "exercises/04-two-travelers/policy.ts",
    probes: ["escalation"],
    blurb: [
      "ACT 1 — ISOLATE THE TRIPS",
      "Bob is going to Seattle through the same agents. Alice's policy assumptions reject",
      "several parts of his trip. Fix them, then make sure Alice's agent cannot touch Bob's",
      "reservation (and vice versa).",
      "",
      "ACT 2 — WATCH THE HANDOFF LEAK",
      "The red handoff checks are intentional; your Act 1 solution is not broken. Check-in Agent",
      "hands Boarding Agent its whole credential because that is all it has to give.",
      "",
      "Find `central_calls` in `npm run trace` and write down, in one sentence, what your fix",
      "depends on.",
    ],
  },
  {
    ...meta(5),
    scenario: "spring-break",
    handoff: "own-identity",
    exercise: "exercises/05-tenuo/chain.ts",
    alsoRun: "two-travelers",
    probes: ["escalation"],
    starAsk: true,
    blurb: [
      "Switch to Tenuo and complete the chain in exercises/05-tenuo/chain.ts. Flight → Check-in",
      "is a complete, annotated tutorial. Copy its narrow() shape for the one TODO below it.",
      "",
      "Each agent now has its own key. A control plane, separate from all six, signs the first",
      "permission. Agents can narrow what they hold. None can sign one from scratch.",
      "",
      "Then look at the escalation attempt from stage 4, where it stopped, and at `central_calls`.",
      "The two-traveler run happens here too, with no policy file to edit.",
    ],
  },
  {
    ...meta(6),
    scenario: "spring-break",
    handoff: "own-identity",
    exercise: "exercises/06-extensions/chain.ts",
    probes: ["escalation", "stolen", "terminal"],
    breaksTrip: true,
    blurb: [
      "Two short extensions. First, exercises/06-extensions/steal.ts copies Boarding Agent's",
      "permission into Activity Agent, which tries to use it. Run `npm run attack` and read the",
      "reason on the STOLEN WARRANT line.",
      "",
      "Then open exercises/06-extensions/chain.ts and mark what Flight Agent hands to Check-in",
      "Agent as terminal. Run the trip. Notice what fails and who decided it would. Check-in",
      "Agent did not agree to this restriction and cannot remove it.",
    ],
  },
  {
    ...meta(7),
    scenario: "incident",
    handoff: "own-identity",
    exercise: "exercises/07-incident/chain.ts",
    blurb: [
      "Hotel Agent has been compromised. The travel system has to stay online. Legitimate",
      "bookings have to keep working.",
      "",
      "Configure exercises/07-incident/chain.ts so that one attempt works and seven fail, and",
      "keep an eye on your least-privilege score.",
    ],
  },
];

export function stage(n: number): StageDef {
  const found = STAGES.find((s) => s.n === n);
  if (found === undefined) {
    throw new Error(`no stage ${n}`);
  }
  return found;
}
