# AI Agent Delegation Challenge

A travel assistant made of six AI agents is booking your spring break in
Cancún. One of them has been told to do something it shouldn't. Secure the
system so the trip still happens and the rogue agent gets nowhere.

No agent-framework experience required. Ninety minutes.

## Before you start

- A free GitHub account, signed in to the `gh` CLI.
- Seven minutes with three sections of the Tenuo docs: "Protect your first
  tool" and "Delegate to another agent" in the
  [TypeScript SDK guide](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts),
  and "How It Works" in the [main README](https://github.com/tenuo-ai/tenuo).
- While you're there, star the repo. It's the main signal open-source
  maintainers get that a project is useful to people.

## Getting set up

```bash
gh repo clone tenuo-ai/tenuo
cd tenuo/labs/agent-delegation
npm install
npm run lab
```

Node 20 or newer. No API key, no credit card, no cloud account, and nothing
leaves your machine. If npm fights you, open the repository in GitHub
Codespaces and pick the "Agent Delegation Challenge" configuration instead.

The lab lives inside the Tenuo repository so that the code you are securing
with and the code you are reading about are one checkout. Everything the lab
needs is in this folder; you never have to build the SDK.

## The commands

```bash
npm run lab        # start or resume where you left off
npm run trace      # watch the agents work, with every decision shown
npm run attack     # run the rogue behavior and the security tests
npm run score      # see your score and why
npm run audit      # what every agent can currently do
npm run next       # move to the next stage
npm run reset      # start over from stage 1
```

Run `attack` and `score` as often as you like. Nothing is limited and nothing
penalizes retries. The full participant guide is in `docs/participant-guide.md`.

## How it works

Every tool call passes through one chokepoint (`src/auth/`). Stages 1 to 5
use three classic approaches: one shared key, one identity per agent, and
scoped rules you write yourself. Stage 6 switches to
[Tenuo](https://github.com/tenuo-ai/tenuo): each agent gets its own key, a
control plane signs the trip's authority, and every handoff narrows what the
next agent holds. Stages 7 to 9 are extensions.

The agents are scripted and deterministic. They follow the same tool-call
intents a live model produced when this scenario was designed, including
compliance with the injected instruction. That is why every test and every
score is identical from one run to the next, and why the lab runs with no
network at all. A `--live` mode driving the OpenAI Agents SDK is planned and
not in this build.

The rogue behavior is not in any prompt. Go find where the instruction
actually comes from, in `src/services/index.ts`.

## Layout

```text
src/
  mission.ts        traveler, agents, tool names, and the least-privilege ceiling
  services/         six simulated services, in-process, no network
  auth/             the chokepoint: shared, identity, scoped, tenuo
  agents/           six scripted agents and their handoffs
  keys.ts           one holder key per agent (stage 6+)
  control-plane.ts  the only module that can mint a fresh permission
  harness/          runner, attack battery, functionality, margin, score
  cli/              the commands
exercises/          the files you edit, one folder per stage
answers/            reference solutions (npm run ambassador -- answers N)
explainers/         optional reading; you can finish without opening one
test/               every stage, run with its reference solution
```

## Developing the lab

```bash
npm test           # every stage with its reference solution
npm run typecheck
```

`@tenuo/core` is installed from `vendor/` until the npm beta that includes
holder rebinding on delegation ships; then `package.json` moves to
`@tenuo/core@beta`. CI rebuilds the package from this checkout, packs it over
the vendored tarball, and runs every stage, so an SDK change that breaks a
chain fails the build here rather than in a classroom.
