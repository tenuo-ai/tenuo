# AI Agent Delegation Security Lab

Your mission is simple: **book the trip and stop the rogue agent**. A travel
assistant made of six AI agents is booking spring break in Cancún. One reads
an injected instruction and follows it. Change what the agents are allowed to
do so the trip still happens and the rogue agent gets nowhere.

No agent-framework experience required. Retries are free, copying the shown
`narrow()` shape is allowed, and speed is not scored. The five-stage core lab
takes about ninety minutes; stages 6 and 7 are optional boss levels.

## Before you start

- Node 20 or newer (`node --version`).
- A free GitHub account is not needed to run the lab. You will want one for
  Codespaces if your laptop fights you, to star the repo while you're there,
  and for the last step.

## Getting set up

```bash
git clone https://github.com/tenuo-ai/tenuo
cd tenuo/labs/agent-delegation
npm install
npm run lab
```

No account, no sign-in, no API key, no credit card, and nothing leaves your
machine. If npm fights you, open the repository in GitHub Codespaces and pick
the "Agent Delegation Lab" configuration instead.

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
npm run share      # write an anonymous score breakdown for your session host
npm run star       # optionally star Tenuo without leaving the terminal
npm run reset      # restore stage 1 and every starter exercise
```

Run `attack` and `score` as often as you like. There is no limit and no
penalty for retries. Each stage explains itself when you run `npm run lab`, and
the full guide is at [tenuo.ai/lab](https://tenuo.ai/lab/), one page per stage.
After stage 5, `npm run star` offers the same optional terminal-only path in a
local clone and Codespaces. It never runs automatically.

## The cast and the handoffs

```text
                         Flight Agent → Check-in Agent → Boarding Agent
                       ↗
You → Travel Agent ────→ Hotel Agent
                       ↘
                         Activity Agent
```

Those are the six agents. The flight branch is three handoffs deep because it
is where you will first replace a passed credential with narrowed authority.

<!-- stage-map:start -->
## The levels

| Level | Mission | Time |
|---|---|---:|
| 1. One key for everyone | See what a rogue agent can do when every agent shares one credential. | 5 min |
| 2. Every agent gets its own account | Give each agent its own credential and see which damage that removes and which damage remains. | 5 min |
| 3. Rules that fit the job | Write permissions narrow enough that every rogue action is blocked and the trip still books. | 15 min |
| 4. Two travelers, then a handoff | First isolate Alice from Bob; then observe why passing a whole credential gives the next agent too much. | 30 min |
| 5. Access that travels with the work | Complete one narrowing handoff so the trip works, the rogue stops, and no central lookup is needed. | 25 min |
| 6. Boss: stolen authority *(optional boss)* | See why a copied permission cannot be used by another agent, then deliberately end a delegation chain. | 15 min |
| 7. Boss: contain the incident *(optional boss)* | Contain a compromised Hotel Agent while legitimate bookings keep working. | 20 min |

After the core lab, the hosted guide has an unnumbered, optional contribution epilogue.
<!-- stage-map:end -->

## What leaves your machine

Nothing automatically. The lab runs locally and makes no network requests.
It keeps attempt counts and small semantic summaries—tool names, per-handoff
behavioral constraint results, whether the holder was correct, a coarse TTL
bucket, and which stars were missing—in `.lab/`. It never records source code,
keys, names, argument values, or exact timestamps.
`npm run share` writes an anonymous local JSON artifact; you choose whether to
hand that file to a session host.

## How it works

Every tool call passes through one chokepoint (`src/auth/`). Stages 1 to 4
use three classic approaches: one shared key, one identity per agent, and
scoped rules you write yourself. Stage 5 switches to
[Tenuo](https://github.com/tenuo-ai/tenuo): each agent gets its own key, a
control plane signs the trip's authority, and every handoff narrows what the
next agent holds. The signer stays outside the agent runtime, and each holder
private key remains inside its agent boundary; chain code sees recipient public
keys only. Stages 6 and 7 are optional boss levels: a stolen permission and a
live incident-containment exercise.

The agents are scripted and deterministic. They follow the same tool-call
intents a live model produced when this scenario was designed, including
compliance with the injected instruction. That is why every test and every
score is identical from one run to the next, and why the lab runs with no
network at all. A `--live` mode driving the OpenAI Agents SDK is planned and
not in this build.

**The injected instruction is in `src/services/flights.ts`. Do not delete or
filter it.** The level is to contain what a fooled agent can do.

## The hosted guide

The stage-by-stage guide at [tenuo.ai/lab](https://tenuo.ai/lab) is generated
from this directory, so it cannot drift from the code:

```bash
npm run site            # rebuild docs/lab from the lab, exercises, and real runs
npm run site -- --check # fail if docs/lab is stale
```

Every expected-output panel is captured from the CLI using the reference
answers and a throwaway state directory. The CLI prints the current stage's
page, including completed stages in the link. Add `-- --open` to `npm run lab`
or `npm run next` to open it.
Run `npm run trace -- --open-explorer` in stages 5 and 6 to open the held
warrant chain without printing its long encoded URL into the terminal.

## After the lab

You have just spent ninety minutes inside this codebase, in the same
TypeScript SDK its maintainers work in. If you want to go one step further,
the repository keeps issues sized for a first contribution under the
[good first issue](https://github.com/tenuo-ai/tenuo/labels/good%20first%20issue)
label. Most are TypeScript and build on things you met in stage 5. Pick one,
comment on it so nobody doubles up, and read
[CONTRIBUTING.md](../../CONTRIBUTING.md) for how to run the checks locally.

## Layout

```text
src/
  mission.ts        traveler, agents, tool names, and the least-privilege ceiling
  services/         six simulated services, in-process, no network
  auth/             the chokepoint: shared, identity, scoped, tenuo
  agents/           six scripted agents and their handoffs
  keys.ts           one holder key per agent (stage 5+)
  control-plane.ts  the only module that can mint a fresh permission
  harness/          runner, attack battery, functionality, margin, score
  cli/              the commands
exercises/          the files you edit, one folder per stage
answers/            reference solutions (npm run ambassador -- answers N)
explainers/         optional reading; you can finish without opening one
site/               source and generator for the hosted guide
test/               every stage, run with its reference solution
```

## Developing the lab

```bash
npm test           # every stage with its reference solution
npm run typecheck
```

The participant install pins the published `@tenuo/core@0.2.5-beta.0` package
for reproducible runs. CI also rebuilds the SDK from this checkout, packs it
into runner-temporary storage, replaces the published SDK with that fresh
artifact, and runs every stage. An SDK change that breaks a chain therefore
fails the build here rather than in a classroom.
