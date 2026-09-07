/**
 * Seven stages. Each is a system, a rogue agent, and a set of tests. The
 * participant changes how permissions work, then runs the tests again.
 */
export type Mode = "shared" | "identity" | "scoped" | "tenuo";
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

export const STAGES: readonly StageDef[] = [
  {
    n: 1,
    title: "One key for everyone",
    mode: "shared",
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
    n: 2,
    title: "Every agent gets its own account",
    mode: "identity",
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
    n: 3,
    title: "Rules that fit the job",
    mode: "scoped",
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
    n: 4,
    title: "A second traveler, and a handoff",
    mode: "scoped",
    scenario: "two-travelers",
    handoff: "pass-credential",
    exercise: "exercises/04-two-travelers/policy.ts",
    probes: ["escalation"],
    blurb: [
      "Bob is going to Seattle, at the same time, through the same agents. Something will break.",
      "Fix it in exercises/04-two-travelers/policy.ts the quick way, then read CROSS-TASK in",
      "`npm run attack`. The README next to the file shows a fix that holds up.",
      "",
      "Then look at BOARDING AGENT AFTER THE HANDOFF: Check-in Agent hands Boarding Agent its",
      "whole credential, because that is all it has. The rogue then asks your policy component",
      "for more than it holds itself. Should it say yes? What would it need to know to say no?",
      "",
      "Find `central_calls` in `npm run trace` and write down, in one sentence, what your fix",
      "depends on.",
    ],
  },
  {
    n: 5,
    title: "Access that travels with the work",
    mode: "tenuo",
    scenario: "spring-break",
    handoff: "own-identity",
    exercise: "exercises/05-tenuo/chain.ts",
    alsoRun: "two-travelers",
    probes: ["escalation"],
    starAsk: true,
    blurb: [
      "Switch to Tenuo and complete the chain in exercises/05-tenuo/chain.ts. The first four",
      "links are written for you; you write the last two.",
      "",
      "Each agent now has its own key. A control plane, separate from all six, signs the first",
      "permission. Agents can narrow what they hold. None can sign one from scratch.",
      "",
      "Then look at the escalation attempt from stage 4, where it stopped, and at `central_calls`.",
      "The two-traveler run happens here too, with no policy file to edit.",
    ],
  },
  {
    n: 6,
    title: "A stolen permission, and the end of the line",
    mode: "tenuo",
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
    n: 7,
    title: "The incident",
    mode: "tenuo",
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
