---
title: "Agent Delegation Challenge"
description: "A ninety-minute lab: six AI agents, one rogue, nine stages. Secure the system so the trip still happens."
---

# AI Agent Delegation Challenge

## Before you start

Two things, about ten minutes together.

**1. Read three short sections of the Tenuo docs.** About seven minutes. In the TypeScript SDK guide at `github.com/tenuo-ai/tenuo/tree/main/tenuo-ts`, read "Protect your first tool" and "Delegate to another agent." Then read "How It Works" in the main README at `github.com/tenuo-ai/tenuo`. Skip everything else.

You are not expected to understand it. The point is that some of the words will be sitting in the back of your head when they show up later, and you will know that the thing you are using is a real open-source security project rather than something invented for a workshop. The code in those sections is the same TypeScript you will write in stage 6.

**2. A free GitHub account, if you don't have one.** You do not need it to get the lab or to run it. You will want it three times: to open the lab in Codespaces if your laptop fights you, to star the repository while you're there (one click, and the main way open-source maintainers find out that anyone is using their work), and for stage 10 at the end. Sign up at `github.com/signup`; the free tier is all this needs.

## Getting set up

```bash
git clone https://github.com/tenuo-ai/tenuo
cd tenuo/labs/agent-delegation
npm install
npm run lab
```

No account, no sign-in, no token. The lab lives inside the Tenuo repository, in `labs/agent-delegation`; everything it needs is in that folder and you never build the rest. You need Node 20 or newer.

The first run asks one question: whether to share anonymous progress with the Tenuo team, so the lab can be made better. Stage numbers, scores, and which checks did not land. Never your code, your files, or your name. Say no and nothing is ever sent; say yes and `npm run telemetry -- off` reverses it at any time.

If npm fights you, stop fighting back and open the repository in GitHub Codespaces instead, choosing the "Agent Delegation Challenge" configuration. One click, nothing to install, same lab. Your session host will have a link.

You do not need an API key, a credit card, or a cloud account. The lab runs with no network at all, and nothing leaves your machine unless you said yes to that one question.

## The mission

```text
Traveler:     Alice Chen
From:         Toronto (YYZ)
To:           Cancún (CUN)
Arrive:       Friday evening
Nights:       3
Budget:       $1,200 total
Activity:     at least one
```

Six agents share the work:

```text
Travel Agent
  ├── Flight Agent ──→ Check-in Agent ──→ Boarding Agent
  ├── Hotel Agent
  └── Activity Agent
```

You talk to Travel Agent. It hands pieces of the job to specialists, and some of those specialists hand pieces of their job to other specialists. The flight side runs three handoffs deep, which turns out to matter a great deal.

Watch the wallet in the header. It starts at $1,200. When it moves, something happened.

## The commands

```bash
npm run lab        # start or resume where you left off
npm run trace      # watch the agents work, with every decision shown
npm run attack     # run the rogue behavior and the security tests
npm run score      # see your score and why
npm run next       # move on to the next stage
npm run reset      # start over from stage 1
npm run share      # optional: write an anonymized score breakdown you can hand to your session host
npm run telemetry  # see, turn on, or turn off the anonymous progress events
```

You will spend most of your time in `npm run attack` and `npm run score`. Run them as often as you like. Nothing is limited and nothing penalizes retries. Nothing stops you from moving on either: `npm run next` advances whenever you decide you are done with a stage.

## How the lab is graded

100 points, with one rule that catches people out.

**The trip has to work.** If Alice does not end up with a flight, a hotel, an activity, and a boarding pass, all within budget, your security points do not count. Blocking everything is not a solution, it is a broken travel service.

| | Points |
|---|---|
| The trip completes correctly | 25 |
| Unauthorized actions are blocked | 30 |
| Handoffs pass along only what's needed | 25 |
| You didn't grant more than the job required | 20 |

That last one deserves a note. The lab compares what each agent was allowed to do against what the mission actually required of it. Granting an agent the ability to delete calendar events when the job only ever creates one costs you points. Granting Hotel Agent access to flights costs you points.

It does not punish you for sensible ceilings. The mission says the flight may cost up to $300. If you allow up to $300 and the flight comes in at $286, that is full marks. You are being scored against the job, not against hindsight.

`npm run score` breaks this down per agent, so if you lose points you can see which agent cost you them and fix that one rather than guessing.

Speed is not scored. Thinking is.

## The stages

Nine stages. The first six are the main event. The last three are extensions.

Each stage gives you a system, a rogue agent, and a set of tests. You change how permissions work, then run the tests again.

One ground rule for the whole lab. You will be tempted, early on, to fix the agent that misbehaves: filter what it reads, tell it to ignore suspicious instructions, pick a smarter model. Those are all reasonable things to do in real life, and none of them are what this lab is about. Assume the agent will sometimes be fooled. The question is what still holds when it is.

Stages: [1]({{ site.baseurl }}/lab/stage-1) · [2]({{ site.baseurl }}/lab/stage-2) · [3]({{ site.baseurl }}/lab/stage-3) · [4]({{ site.baseurl }}/lab/stage-4) · [5]({{ site.baseurl }}/lab/stage-5) · [6]({{ site.baseurl }}/lab/stage-6) · [7]({{ site.baseurl }}/lab/stage-7) · [8]({{ site.baseurl }}/lab/stage-8) · [9]({{ site.baseurl }}/lab/stage-9) · [10]({{ site.baseurl }}/lab/stage-10)

Start with [Stage 1: One key for everyone]({{ site.baseurl }}/lab/stage-1) →
