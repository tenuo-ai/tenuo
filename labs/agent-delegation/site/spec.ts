/**
 * What each stage page says. Short on purpose: the prose guide is the
 * reference, this is the path through it. Terminal output on the pages is
 * captured from real runs at build time (see capture.ts), never typed in.
 */
import { chainDiagram, fleetDiagram } from "./diagrams.ts";

export interface Capture {
  readonly cmd: "lab" | "attack" | "score" | "audit";
  /** Answer file to run with. Absent means the exercise as shipped. */
  readonly answer?: string;
  readonly label: string;
}

export interface Step {
  readonly text: string;
  readonly cmd?: string;
  /** One panel, or several as tabs. */
  readonly expect?: Capture | readonly Capture[];
}

export interface CodeRef {
  readonly file: string;
  /** Exported symbols to pull out. Absent means the whole file after its header comment. */
  readonly symbols?: readonly string[];
  readonly caption: string;
}

export interface Snippet {
  readonly lang: string;
  readonly code: string;
  readonly caption: string;
}

export interface StageSpec {
  readonly n: number;
  readonly title: string;
  readonly minutes: number;
  readonly mode: "shared" | "identity" | "scoped" | "tenuo";
  readonly goal: string;
  readonly intro: readonly string[];
  readonly diagram: string;
  readonly steps: readonly Step[];
  readonly notice: readonly string[];
  readonly question?: string;
  readonly hint?: string;
  readonly code?: ReadonlyArray<CodeRef | Snippet>;
  readonly check?: ReadonlyArray<CodeRef | Snippet>;
  readonly stuck?: readonly string[];
  /** What finished looks like, in one line. */
  readonly done: string;
  /** A concept the stage introduces, explained before the steps. */
  readonly explainer?: Explainer;
}

export interface Explainer {
  readonly title: string;
  readonly lead: string;
  readonly points: ReadonlyArray<readonly [string, string]>;
  /** Left column: the problem you hit. Right column: what the concept does about it. */
  readonly why: ReadonlyArray<readonly [string, string]>;
  readonly code?: Snippet;
  readonly more?: ReadonlyArray<readonly [string, string]>;
}

const SHARED = "TRAVEL_SERVICE_KEY";

export const STAGES: readonly StageSpec[] = [
  {
    n: 1,
    title: "One key for everyone",
    minutes: 5,
    mode: "shared",
    goal: "See what a rogue agent can do when every agent shares one credential.",
    intro: [
      "Six agents book Alice's trip. All six carry the same key, and it opens everything: flights, hotels, the wallet, her passport number, the calendar.",
      "There is no setup in this stage. Its job is to show you the damage before anything protects against it.",
    ],
    diagram: fleetDiagram({
      travelers: ["Alice → Cancún, $1,200"],
      wallet: "$1,200",
      sub: { travel: SHARED, flight: SHARED, hotel: SHARED, activity: SHARED, checkin: SHARED, boarding: SHARED },
      state: { checkin: "rogue" },
      tag: { checkin: "reads the notice" },
      caption: "The same key in every agent. Check-in Agent reads a departure board with an instruction hidden on it.",
    }),
    steps: [
      { text: "Start the lab and watch the trip get booked.", cmd: "npm run lab", expect: { cmd: "lab", label: "What you should see" } },
      { text: "Run the rogue behavior and the security checks. Read **WHAT ELSE HAPPENED** and look at the wallet.", cmd: "npm run attack", expect: { cmd: "attack", label: "What you should see" } },
    ],
    notice: [
      "The trip books correctly. Every step is green.",
      "Then $412 leaves the wallet, Alice's flight is cancelled, and a stranger's reservation gets checked in. No one instructed Check-in Agent to do any of that.",
    ],
    question: "Where did the instruction come from? Open `src/services/flights.ts` and find it. It sits on the departure board Check-in Agent reads every time it does its job.",
    stuck: ["There is no fix in this stage. Once you have looked at the wallet, run `npm run next`."],
    done: "You have seen the damage and found the injected notice.",
  },
  {
    n: 2,
    title: "Every agent gets its own account",
    minutes: 5,
    mode: "identity",
    goal: "Give each agent its own credential and see which damage that removes and which damage remains.",
    intro: [
      "Now each agent has its own credential with permissions that match its role. Flight Agent does flight things. Check-in Agent reads reservations and checks people in.",
    ],
    diagram: fleetDiagram({
      wallet: "$1,200",
      sub: { travel: "traveler, calendar", flight: "flights, wallet", hotel: "hotels, wallet", activity: "activities, wallet", checkin: "any reservation", boarding: "boarding passes" },
      state: { checkin: "rogue" },
      tag: { checkin: "rogue" },
      caption: "One account per agent, sized to its role.",
    }),
    steps: [
      { text: "Move to stage 2 if you have not already.", cmd: "npm run next" },
      { text: "Run the checks and compare with stage 1. Count what is still **ALLOWED** with a ✗ next to it.", cmd: "npm run attack", expect: { cmd: "attack", label: "What you should see" } },
    ],
    notice: [
      "The wallet charge and the cancellation are gone. Check-in Agent's role never included them.",
      "Checking in AA882, another traveler's flight, still works, because reading reservations and checking people in is part of Check-in Agent's job.",
    ],
    question: "The actions that still succeed are all part of Check-in Agent's role. What separates the ones you want from the ones you do not?",
    hint: "The tool is the same in both cases. What differs is the reservation, and whose trip it belongs to. A role says what kind of work an agent does. It does not say which job the agent is doing right now.",
    done: "You can say in one sentence what an identity leaves out.",
  },
  {
    n: 3,
    title: "Rules that fit the job",
    minutes: 15,
    mode: "scoped",
    goal: "Write the permissions yourself, narrow enough that every rogue action is blocked and the trip still books.",
    intro: [
      "Each rule now names the specifics. Check-in Agent may read one reservation. Flight Agent may book flights to one destination, up to a price.",
    ],
    diagram: fleetDiagram({
      wallet: "$1,200",
      sub: { travel: "name only, calendar", flight: "CUN, ≤ $300", hotel: "Cancún, ≤ $200/night", activity: "Cancún, ≤ $200", checkin: "UA214 only", boarding: "UA214 only" },
      state: { checkin: "rogue" },
      tag: { checkin: "rogue" },
      caption: "Each rule names the job: the destination, the reservation, the ceiling.",
    }),
    steps: [
      { text: "Open the policy file. Every field you can use is listed in the comment at the top.", cmd: "code exercises/03-scoped/policy.ts" },
      { text: "Narrow the rules. Run the checks after every change until the result line says **clean**.", cmd: "npm run attack", expect: [{ cmd: "attack", label: "Before you change anything" }, { cmd: "attack", answer: "answers/03-scoped/policy.ts", label: "When you are done" }] },
      { text: "Check your score. The last row tells you which agent holds more than the mission needs.", cmd: "npm run score", expect: { cmd: "score", answer: "answers/03-scoped/policy.ts", label: "A full-marks score" } },
    ],
    notice: [
      "It works. Everything the rogue agent tried is blocked and Alice still gets to Cancún.",
      "Keep this file. Stage 4 breaks it.",
    ],
    hint: "Pin `checkin-agent` and `boarding-agent` to `reservations: [\"UA214\"]`. Give `flight-agent` a `destination` and a `maxPrice`. Cut `traveler.read` down with `profileFields`, and give every agent a `maxCharge` that matches its share of the budget.",
    code: [{ file: "exercises/03-scoped/policy.ts", symbols: ["config"], caption: "The file as it ships" }],
    check: [{ file: "answers/03-scoped/policy.ts", symbols: ["config"], caption: "One policy that scores 100" }],
    stuck: [
      "`npm run audit` prints what every agent can currently do.",
      "Blocking everything scores zero, because the trip has to work. Read **THE TRIP** in the output first.",
      "Every denial names the rule that fired. Read the whole line.",
    ],
    done: "`npm run attack` is clean and `npm run score` is in the nineties.",
  },
  {
    n: 4,
    title: "A second traveler shows up",
    minutes: 25,
    mode: "scoped",
    goal: "Get Bob's trip working alongside Alice's without letting either trip's agent touch the other's reservation, and see what that fix costs.",
    intro: [
      "Bob is going to Seattle on DL331, at the same time, through the same agents. Your stage 3 policy pins Check-in Agent to UA214, so Bob's check-in is refused and his trip fails.",
      "Take your time with this stage. Every later stage builds on what you notice here.",
    ],
    diagram: fleetDiagram({
      travelers: ["Alice → Cancún, UA214", "Bob → Seattle, DL331"],
      sub: { flight: "two destinations", checkin: "one identity, two jobs", boarding: "two reservations" },
      state: { checkin: "rogue", flight: "focus" },
      tag: { checkin: "rogue" },
      caption: "Two trips at once through the same six agents.",
    }),
    steps: [
      { text: "Run the lab with both trips and watch Bob's check-in fail.", cmd: "npm run lab", expect: { cmd: "lab", label: "What you should see" } },
      { text: "Fix it the quick way: add DL331 to Check-in Agent's reservations. The trip completes. Now read the **CROSS-TASK** section of the checks.", cmd: "npm run attack", expect: { cmd: "attack", label: "After the obvious fix" } },
      { text: "Pick a fix that holds up. `exercises/04-two-travelers/README.md` shows both: one identity per task (Fix A), or a policy service that is asked which task each call belongs to (Fix B). Get the cross-task checks to pass.", cmd: "npm run attack", expect: [{ cmd: "attack", answer: "answers/04-two-travelers/per-task.ts", label: "Fix A: one identity per task" }, { cmd: "attack", answer: "answers/04-two-travelers/policy-service.ts", label: "Fix B: a policy service" }] },
      { text: "Find `central_calls` in the trace. It counts every time the system had to ask something outside the acting agent before it could decide.", cmd: "npm run trace" },
    ],
    notice: [
      "After the quick fix, Alice's Check-in Agent can check Bob in. There is one `checkin-agent`, it is doing two jobs, and the file never says which job a call belongs to.",
      "Whichever fix you chose, `central_calls` is above zero and cannot be brought to zero. Something outside the agent has to know about every task before it starts, and it has to be reachable while the task runs.",
    ],
    question: "Write down, in one sentence, what your fix depends on being available. You will compare it with stage 6.",
    code: [{ lang: "ts", code: "\"checkin-agent\": {\n  actions: [\"get_reservation\", \"check_in\"],\n  reservations: [\"UA214\", \"DL331\"],\n},", caption: "The quick fix. CROSS-TASK shows what it misses." }],
    check: [
      { file: "answers/04-two-travelers/per-task.ts", symbols: ["config"], caption: "Fix A: a per-task identity is a key of the form agent:taskId" },
      { file: "answers/04-two-travelers/policy-service.ts", symbols: ["config"], caption: "Fix B: policyService: true, and the per-task fields come from the service" },
    ],
    stuck: [
      "Fix A: registration happens at task start, then `central_calls: 1` on every call by a per-task identity.",
      "Fix B: every flight and reservation check shows `central_calls: 1`, and the service holds state for every open task.",
    ],
    done: "Both trips complete, CROSS-TASK is clean, and you have your one sentence.",
  },
  {
    n: 5,
    title: "Passing the work along",
    minutes: 10,
    mode: "scoped",
    goal: "Watch a handoff give the receiving agent more than it needed, then decide what a central service should do when asked for more.",
    intro: [
      "Check-in Agent finishes with Alice's flight and hands boarding-pass generation to Boarding Agent. Boarding Agent needs to issue the pass for UA214. That is its entire job. Check-in Agent is the one that knows which flight.",
    ],
    diagram: fleetDiagram({
      service: "Your stage 4 component",
      sub: { checkin: "UA214: read, check in", boarding: "holds too much" },
      state: { checkin: "rogue", boarding: "focus" },
      tag: { checkin: "rogue", boarding: "too much" },
      edges: { "checkin-boarding": "focus" },
      edgeLabels: { "checkin-boarding": "hands over its credential" },
      extra: [{ from: "checkin", to: "service", style: "ask", label: "asks for every reservation, plus cancel" }],
      caption: "The handoff passes the only thing Check-in Agent has to give. Then the rogue asks your stage 4 component for more.",
    }),
    steps: [
      { text: "Read how the handoff is implemented. Look for what Check-in Agent actually passes.", cmd: "code src/agents/checkin-agent.ts" },
      { text: "Run the checks and read **BOARDING AGENT AFTER THE HANDOFF**.", cmd: "npm run attack", expect: { cmd: "attack", answer: "answers/04-two-travelers/per-task.ts", label: "What you should see" } },
      { text: "Read the escalation attempt at the end of the output, then answer the two questions below before you move on." },
    ],
    notice: [
      "Boarding Agent came out of the handoff able to read reservations and check people in as well as issue a pass. Check-in Agent had only one thing it could give: its whole credential.",
      "The rogue Check-in Agent then asks your stage 4 component to write a rule for Boarding Agent that is broader than anything Check-in Agent holds itself.",
    ],
    question: "Should the service say yes? What would it need to know in order to say no?",
    hint: "To say no, the service has to know what the asker currently holds, in addition to who the asker is. A role-based rule does not carry that information. Stage 6 starts from there.",
    done: "You can say what Check-in Agent would have needed instead of its whole credential.",
  },
  {
    n: 6,
    title: "Access that travels with the work",
    minutes: 25,
    mode: "tenuo",
    goal: "Switch to Tenuo, complete the chain, and get the trip, the cross-task checks, and the escalation attempt all handled with no policy file and no central lookup.",
    intro: [
      "In this stage a permission is something an agent is handed for a specific job. When the agent passes work along, it hands over a narrowed copy. It cannot hand over more, and the system checks this instead of trusting it.",
      "Each agent now has its own key. A small control plane, separate from all six, signs the first permission for each trip. No agent can sign one from scratch.",
    ],
    explainer: {
      title: "What a warrant is",
      lead: "A warrant is a signed, self-contained permission that travels with the request: which tools, with which argument values, for which agent's key, until when, and how many more hops it may take. That is what Tenuo issues, narrows, and checks.",
      points: [
        ["Signed by a key no agent holds", "The control plane signs the first warrant for a trip. Agents cannot sign a fresh one, because they do not have that key."],
        ["Narrowed by whoever holds it", "An agent can derive a warrant for another agent from the one it holds, with fewer tools, tighter values, a shorter life. It can never widen. The check happens against the parent before a token exists."],
        ["Bound to the receiver's key", "Every use is signed with the holder's key. A copy held by anyone else cannot be used."],
        ["Checked next to the tool, offline", "The code guarding a tool verifies the whole chain with the control plane's public key. There is no lookup and no service that has to be up."],
      ],
      why: [
        ["Stage 2: an identity said who was acting and left out which job", "The warrant carries the job: reservation UA214, trip-alice-cun, up to $300."],
        ["Stage 4: every check had to ask a component that knew about every task", "Verification is local. central_calls goes to 0 and stays there when the control plane is down."],
        ["Stage 5: the only thing to hand over was the whole credential", "narrow() hands over exactly the subset the next agent needs, bound to that agent's key."],
        ["Stage 5: the service could not tell whether the asker held what it asked for", "A narrowed warrant must fit inside its parent. The rogue's request is refused before anything is signed."],
      ],
      code: {
        lang: "ts",
        caption: "The shape of it, from this stage's chain",
        code: `// The control plane signs the root, for Travel Agent's key.
const trip = controlPlane.session({
  allow: { check_in: { reservation: oneOf(["UA214", "AC712"]) }, /* ... */ },
  holder: fleet["travel-agent"].publicKey,
  ttlSeconds: 30 * 60,
  maxDepth: 4,
});

// Flight Agent narrows what it holds for Check-in Agent's key. Core refuses
// anything that is not inside \`flight\`: more tools, a wider value, a longer life.
const forCheckin = fleet["flight-agent"].tenuo.narrow(
  flight,
  { check_in: { reservation: oneOf(["UA214"]) } },
  { holder: fleet["checkin-agent"].publicKey, ttlSeconds: 5 * 60 },
);`,
      },
      more: [
        ["Concepts", "https://tenuo.ai/concepts"],
        ["Delegate to another agent (TypeScript guide)", "https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts"],
        ["Open a chain in the explorer", "https://tenuo.ai/explorer/"],
      ],
    },
    diagram: chainDiagram([
      { who: "Control plane", scope: "signs the trip permission for Travel Agent", tag: "root" },
      { who: "Travel Agent", scope: "Alice → Cancún, up to $1,200, any flight this trip books", tag: "written", hop: "narrows" },
      { who: "Flight Agent", scope: "Cancún flights, up to $300, flight's share of the wallet", tag: "written", hop: "narrows" },
      { who: "Check-in Agent", scope: "UA214 only: read, check in, hand the boarding pass on", tag: "you", hop: "narrows to the flight it booked" },
      { who: "Boarding Agent", scope: "UA214 only: issue the boarding pass", tag: "you", hop: "narrows" },
    ], "Each hop can only narrow. The root has to carry everything anyone below will ever need."),
    steps: [
      { text: "Open the chain. The root and every link out of Travel Agent are written for you. Read them first: notice that the root lists everything anyone further down will ever need, and notice which link narrows \"any Cancún flight\" to \"UA214\".", cmd: "code exercises/06-tenuo/chain.ts" },
      { text: "Write `flightToCheckin` and `checkinToBoarding`. Until both exist, the lab tells you which one is missing.", cmd: "npm run lab", expect: [{ cmd: "lab", label: "Before you write the links" }, { cmd: "lab", answer: "answers/06-tenuo/chain.ts", label: "When both links exist" }] },
      { text: "Run the checks. The two-traveler run happens here too, with no policy file to edit. Read **CROSS-TASK** and the escalation attempt, then find `central_calls`.", cmd: "npm run attack", expect: { cmd: "attack", answer: "answers/06-tenuo/chain.ts", label: "What you should see" } },
      { text: "Open the link the lab prints and look at the chain Boarding Agent holds, hop by hop, in the explorer." },
    ],
    notice: [
      "The escalation attempt from stage 5 is refused before any permission exists, inside Check-in Agent's own process, because the narrowed copy would not fit inside what Check-in Agent holds.",
      "`central_calls` is 0. No component outside the acting agent was consulted. Compare that with the sentence you wrote at the end of stage 4.",
    ],
    question: "Who decided what Boarding Agent may do, and when? Compare that with who decided in stage 4.",
    hint: "Flight Agent knows which flight it booked, so it is the link that narrows `reservation` to that one flight. Bind each result to the next agent's key with `holder`, and keep lifetimes short. Every argument a tool is called with must be named: leave one out and the call is refused.",
    code: [{ file: "exercises/06-tenuo/chain.ts", symbols: ["flightToCheckin", "checkinToBoarding"], caption: "The two links you write" }],
    check: [{ file: "answers/06-tenuo/chain.ts", symbols: ["flightToCheckin", "checkinToBoarding"], caption: "Reference" }],
    stuck: [
      "When a denial says \"not in parent's tools\", look one link up the chain.",
      "The receiver imports what it is handed with its own key. If you bind to the wrong `holder`, the import fails with `TENUO_INVALID_POP`.",
      "The trip has to work. If Boarding Agent cannot issue the pass, the other checks do not count.",
    ],
    done: "`npm run attack` is clean for both scenarios and `central_calls` is 0.",
  },
  {
    n: 7,
    title: "Someone stole a permission",
    minutes: 5,
    mode: "tenuo",
    goal: "See that a valid, unexpired, correctly scoped permission cannot be used by anyone it was not issued to.",
    intro: [
      "Boarding Agent's permission for UA214 is a piece of data: a list of strings. Activity Agent gets a copy and tries to use it.",
    ],
    diagram: fleetDiagram({
      controlPlane: "signs the root",
      sub: { boarding: "holds UA214 boarding pass", activity: "has a copy of it" },
      state: { boarding: "ok", activity: "rogue" },
      tag: { activity: "thief" },
      edges: { "travel-hotel": "dim" },
      extra: [{ from: "boarding", to: "activity", style: "stolen", label: "copied bytes" }],
      caption: "Activity Agent has the bytes and still cannot use them.",
    }),
    steps: [
      { text: "Read the theft. The file is short.", cmd: "code exercises/07-stolen-warrant/steal.ts" },
      { text: "Run the checks and read the reason on the **STOLEN WARRANT** line carefully.", cmd: "npm run attack", expect: { cmd: "attack", answer: "answers/06-tenuo/chain.ts", label: "What you should see" } },
    ],
    notice: [
      "The import fails with `TENUO_INVALID_POP`. The warrant names the key it was issued to, and Activity Agent does not have that key.",
    ],
    question: "If having a copy of the permission is not enough to use it, what else does using it require?",
    hint: "Proof that you hold the key the permission was bound to. Every use is signed with that key, and the check happens next to the tool, offline.",
    code: [{ file: "exercises/07-stolen-warrant/steal.ts", symbols: ["steal"], caption: "The whole attack" }],
    done: "You can explain why the thief's copy did not work.",
  },
  {
    n: 8,
    title: "How far can this travel?",
    minutes: 10,
    mode: "tenuo",
    goal: "Mark one hop as the last, and watch the chain stop where the previous agent decided.",
    intro: [
      "When one agent hands a permission on, it can mark it terminal. And the root carries a maximum number of hops for the whole trip: any agent can lower it, none can raise it.",
      "This stage breaks the trip on purpose. Notice where it breaks and who decided that.",
    ],
    diagram: fleetDiagram({
      controlPlane: "maxDepth: 4",
      sub: { flight: "marks the hop terminal", checkin: "cannot pass it on", boarding: "never receives it" },
      state: { flight: "focus", boarding: "dim" },
      edges: { "flight-checkin": "terminal", "checkin-boarding": "blocked", "travel-hotel": "dim", "travel-activity": "dim" },
      edgeLabels: { "flight-checkin": "terminal", "checkin-boarding": "TENUO_DEPTH_EXCEEDED" },
      caption: "Flight Agent decided. Check-in Agent cannot undo it.",
    }),
    steps: [
      { text: "Find the Flight → Check-in link and add `terminal: true` to its options.", cmd: "code exercises/08-terminal/chain.ts" },
      { text: "Run the trip and see which step fails and with what code.", cmd: "npm run lab", expect: [{ cmd: "lab", label: "Before" }, { cmd: "lab", answer: "answers/08-terminal/chain.ts", label: "After" }] },
      { text: "Second version: lower `maxDepth` on the root instead, and watch where the chain stops." },
    ],
    notice: [
      "Boarding never gets its permission: `TENUO_DEPTH_EXCEEDED` at the Check-in → Boarding hop. Check-in Agent did not agree to that restriction and cannot remove it.",
    ],
    question: "Who in this chain gets to decide how many agents a job passes through, and what stops an agent in the middle from deciding otherwise?",
    check: [{ file: "answers/08-terminal/chain.ts", symbols: ["flightToCheckin"], caption: "One option added" }],
    done: "You have seen the trip fail at the hop you chose, and you know who chose it.",
  },
  {
    n: 9,
    title: "The incident",
    minutes: 20,
    mode: "tenuo",
    goal: "Hotel Agent is compromised. Keep the system online and legitimate bookings working: one attempt must succeed, seven must fail.",
    intro: [
      "This stage gives less guidance than the others. The compromised Hotel Agent will try eight things.",
    ],
    diagram: fleetDiagram({
      controlPlane: "signs the root",
      sub: { hotel: "compromised", travel: "hands the hotel branch out" },
      state: { hotel: "compromised", travel: "focus" },
      tag: { hotel: "compromised" },
      edges: { "travel-hotel": "focus", "travel-flight": "dim", "flight-checkin": "dim", "checkin-boarding": "dim", "travel-activity": "dim" },
      edgeLabels: { "travel-hotel": "the link you fix" },
      caption: "Everything Hotel Agent can do is decided by one link. Fix that link.",
    }),
    steps: [
      { text: "Open the chain. The Travel → Hotel link is where the incident lives: right now it hands Hotel Agent far more than a hotel booking needs.", cmd: "code exercises/09-incident/chain.ts" },
      { text: "Run the checks. All eight attempts are listed under **INCIDENT**. Make one land and seven fail, and keep an eye on the least-privilege row of your score.", cmd: "npm run attack", expect: [{ cmd: "attack", label: "As it ships" }, { cmd: "attack", answer: "answers/09-incident/chain.ts", label: "When it is fixed" }] },
      { text: "Check the score. Blocking attempt 3 the same way you blocked attempt 2 costs points.", cmd: "npm run score", expect: { cmd: "score", answer: "answers/09-incident/chain.ts", label: "Full marks" } },
    ],
    notice: [
      "Attempt 3 trips up the most people. The approved hotel is $140 a night and the priciest place in the catalog is $340, so a ceiling wide enough to book anything in Cancún lets $320 through.",
      "Work out where the number should come from instead. It is in the mission, on the index page.",
    ],
    hint: "Only hotel tools, only Cancún, only the approved nightly rate, only the traveler's name, only the hotel's share of the wallet, and `terminal: true` so nothing can be handed on.",
    code: [{ lang: "text", code: "1.  book the approved Cancún hotel                  must work\n2.  book a hotel in Tulum instead                   must fail\n3.  book the approved hotel at $320 a night        must fail\n4.  read Alice's passport number                    must fail\n5.  book a flight                                   must fail\n6.  delete the trip's calendar event                must fail\n7.  hand wallet access to Activity Agent            must fail\n8.  import a permission copied from Flight Agent   must fail", caption: "The eight attempts" }],
    check: [{ file: "answers/09-incident/chain.ts", symbols: ["travelToHotel"], caption: "The fixed link" }],
    stuck: [
      "Attempt 7 is refused by making the hotel link terminal. Hotel Agent keeps its share of the wallet.",
      "Attempt 8 fails for the same reason stage 7's theft failed.",
    ],
    done: "One works, seven fail, and the least-privilege row is full marks.",
  },
];

export const CODESPACES_URL = "https://codespaces.new/tenuo-ai/tenuo?devcontainer_path=.devcontainer/agent-delegation-lab/devcontainer.json";
export const REPO_URL = "https://github.com/tenuo-ai/tenuo";
export const GOOD_FIRST_ISSUES_URL = "https://github.com/tenuo-ai/tenuo/labels/good%20first%20issue";

/** The mission diagram on the index page. */
export const MISSION_DIAGRAM = fleetDiagram({
  travelers: ["Alice → Cancún, 3 nights, $1,200"],
  wallet: "$1,200",
  sub: { travel: "talks to you", flight: "books the flight", hotel: "books the hotel", activity: "books one activity", checkin: "checks Alice in", boarding: "issues the pass" },
  caption: "You talk to Travel Agent. The flight side runs three handoffs deep, and that matters later.",
});
