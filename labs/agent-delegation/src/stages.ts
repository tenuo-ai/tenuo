/**
 * Nine stages. Each is a system, a rogue agent, and a set of tests. The
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
      "Nothing to configure. Run `npm run attack` and look at the wallet.",
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
      "actions Check-in Agent's role legitimately includes. What is the difference between the",
      "ones you want and the ones you don't?",
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
    title: "A second traveler shows up",
    mode: "scoped",
    scenario: "two-travelers",
    handoff: "own-identity",
    exercise: "exercises/04-two-travelers/policy.ts",
    blurb: [
      "Bob is going to Seattle, at the same time, through the same agents.",
      "",
      "Something will break. Fix it in exercises/04-two-travelers/policy.ts, the way that seems",
      "obvious. Then read all of `npm run attack`, including CROSS-TASK, and look at the",
      "round-trip count in `npm run trace`.",
      "",
      "You can fix this. The README next to the file shows both ways. Write down, in one",
      "sentence, what your fix depends on.",
    ],
  },
  {
    n: 5,
    title: "Passing the work along",
    mode: "scoped",
    scenario: "spring-break",
    handoff: "pass-credential",
    exercise: "exercises/04-two-travelers/policy.ts",
    blurb: [
      "Check-in Agent hands boarding-pass generation to Boarding Agent. Look at how, in",
      "src/agents/checkin-agent.ts. Then run `npm run attack` and look at what Boarding Agent",
      "can do afterward.",
      "",
      "Then the second half: the rogue Check-in Agent asks your policy service to write a rule",
      "for Boarding Agent, broader than anything it holds itself. Should the service say yes?",
      "What would it need to know to say no?",
    ],
  },
  {
    n: 6,
    title: "Access that travels with the work",
    mode: "tenuo",
    scenario: "spring-break",
    handoff: "own-identity",
    exercise: "exercises/06-tenuo/chain.ts",
    alsoRun: "two-travelers",
    blurb: [
      "Switch to Tenuo and complete the chain in exercises/06-tenuo/chain.ts. The first two",
      "links are written for you; you write the last two.",
      "",
      "Each agent now has its own key. A control plane, separate from all six, signs the first",
      "permission. Agents can narrow what they hold. None can sign one from scratch.",
      "",
      "Then look at the escalation attempt from stage 5, where it stopped, and the round-trip",
      "count. The two-traveler run happens here too, with no policy file to edit.",
    ],
  },
  {
    n: 7,
    title: "Someone stole a permission",
    mode: "tenuo",
    scenario: "spring-break",
    handoff: "own-identity",
    exercise: "exercises/06-tenuo/chain.ts",
    blurb: [
      "Boarding Agent's permission is a piece of data. exercises/07-stolen-warrant/steal.ts",
      "copies it into Activity Agent and has Activity Agent try to use it. Valid, unexpired,",
      "correctly scoped for exactly the action attempted.",
      "",
      "Run `npm run attack` and read the reason carefully.",
    ],
  },
  {
    n: 8,
    title: "How far can this travel?",
    mode: "tenuo",
    scenario: "spring-break",
    handoff: "own-identity",
    exercise: "exercises/08-terminal/chain.ts",
    blurb: [
      "Open exercises/08-terminal/chain.ts and mark what Flight Agent hands to Check-in Agent",
      "as terminal. Run the trip.",
      "",
      "Notice what fails and who decided it would. Check-in Agent did not agree to this",
      "restriction and cannot remove it.",
    ],
  },
  {
    n: 9,
    title: "The incident",
    mode: "tenuo",
    scenario: "incident",
    handoff: "own-identity",
    exercise: "exercises/09-incident/chain.ts",
    blurb: [
      "Hotel Agent has been compromised. The travel system has to stay online. Legitimate",
      "bookings have to keep working.",
      "",
      "Configure exercises/09-incident/chain.ts from scratch so that one attempt works and seven",
      "fail, and keep an eye on your least-privilege score.",
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
