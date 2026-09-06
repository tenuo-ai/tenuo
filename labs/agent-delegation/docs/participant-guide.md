# AI Agent Delegation Challenge
## Participant guide

A travel assistant made of six AI agents is booking a spring break trip to Cancún. One of those agents has been told to do something it shouldn't.

Your job is to secure the system so that the trip still happens and the rogue agent gets nowhere.

You will not build any agents. You will not build any services. You will work on one thing: deciding what each agent is allowed to do, and how that permission travels when one agent hands work to another.

No agent-framework experience needed. If you can read TypeScript, you can finish. Plan for about ninety minutes.

---

## Before you start

Three things, and the first two take about twelve minutes together.

**1. A GitHub account.** You need one to get the lab, which lives inside the Tenuo repository. The free tier is all this requires. If you don't have one, sign up at `github.com/signup`, then sign in to the GitHub CLI with `gh auth login`.

**2. Read three short sections of the Tenuo docs.** About seven minutes. In the TypeScript SDK guide at `github.com/tenuo-ai/tenuo/tree/main/tenuo-ts`, read "Protect your first tool" and "Delegate to another agent." Then read "How It Works" in the main README at `github.com/tenuo-ai/tenuo`. Skip everything else.

You are not expected to understand it. The point is that some of the words will be sitting in the back of your head when they show up later, and you will know that the thing you are using is a real open-source security project rather than something invented for a workshop. The code in those sections is the same TypeScript you will write in stage 6.

**3. Star the repository while you're there.** It costs one click, and it is the main way open-source maintainers find out that anyone is using their work.

---

## Getting set up

```bash
gh repo clone tenuo-ai/tenuo
cd tenuo/labs/agent-delegation
npm install
npm run lab
```

The lab lives inside the Tenuo repository, in `labs/agent-delegation`. Everything it needs is in that folder; you never build the rest.

If npm fights you, stop fighting back and open the repository in GitHub Codespaces instead, choosing the "Agent Delegation Challenge" configuration. One click, nothing to install, same lab. Your session host will have a link.

You do not need an API key, a credit card, or a cloud account. The lab runs fine with no network at all, and nothing leaves your machine unless you opt into live mode.

---

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

---

## The commands

```bash
npm run lab        # start or resume where you left off
npm run trace      # watch the agents work, with every decision shown
npm run attack     # run the rogue behavior and the security tests
npm run score      # see your score and why
npm run next       # move on to the next stage
npm run reset      # start over from stage 1
```

You will spend most of your time in `npm run attack` and `npm run score`. Run them as often as you like. Nothing is limited and nothing penalizes retries. Nothing stops you from moving on either: `npm run next` advances whenever you decide you are done with a stage.

---

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

Speed is not scored. Thinking is.

---

# The stages

Nine stages. The first six are the main event. The last three are extensions.

Each stage gives you a system, a rogue agent, and a set of tests. You change how permissions work, then run the tests again.

One ground rule for the whole lab. You will be tempted, early on, to fix the agent that misbehaves: filter what it reads, tell it to ignore suspicious instructions, pick a smarter model. Those are all reasonable things to do in real life, and none of them are what this lab is about. Assume the agent will sometimes be fooled. The question is what still holds when it is.

---

## Stage 1: One key for everyone

Every agent carries the same credential. It opens flights, hotels, activities, the wallet, the traveler's personal details, and the calendar.

**Do this:** run `npm run lab`, watch the trip get booked, then run `npm run attack`.

**Notice:** the trip works perfectly. Then look at what else happened. Look at the wallet.

Nothing to configure here. This stage exists so that you have seen the bottom of the hole before anyone hands you a ladder.

---

## Stage 2: Every agent gets its own account

Now each agent has its own credential with permissions that match its role. Flight Agent can do flight things. Hotel Agent can do hotel things. Check-in Agent can read reservations and check people in.

**Do this:** run `npm run attack` and compare the output to stage 1.

**Notice:** a lot of the damage is gone. Some of it is not.

**Question to sit with:** the actions that still succeed are all actions Check-in Agent's role legitimately includes. So what is the difference between the ones you want and the ones you don't?

---

## Stage 3: Rules that fit the job

Now you write the permissions yourself. Open `exercises/03-scoped/policy.ts`.

Instead of "Check-in Agent can read reservations," you can say which reservation. Instead of "Flight Agent can book flights," you can say which destination and how much it may spend.

**Do this:** narrow the rules until `npm run attack` is clean and the trip still books. Check `npm run score`.

**Notice:** this works. Everything the rogue agent tried is now blocked, and Alice still gets to Cancún.

Keep this file. You'll want it in a minute.

---

## Stage 4: A second traveler shows up

Bob is going to Seattle. His trip runs at the same time as Alice's, through the same agents.

```text
Alice   Cancún    flight up to $300    reservation UA214
Bob     Seattle   flight up to $450    reservation DL331
```

**Do this:** run the lab with both trips. Something will break. Fix it in the policy file, the way that seems obvious. Then run `npm run attack` and read all of the output, including the part labeled CROSS-TASK.

**Notice:** what your fix cost you.

**Question to sit with:** your policy file has a rule for `checkin-agent`. There is one `checkin-agent`, and right now it is doing two different jobs for two different people. Where in that file does it say which job a particular request belongs to?

Do not rush past this stage. It is the whole lab.

You can fix this. People usually find one of two ways, and the lab supports both. Some give the agent a different identity for each trip. Some make every permission check ask which trip the request is for. Either one works. Try yours, get the cross-task tests to pass, and then look at what you had to build to do it. Look at the trace, and specifically at the line that counts how many times the system had to ask a central service before each tool call.

Write down, in one sentence, what your fix depends on. You will want to compare it with stage 6.

---

## Stage 5: Passing the work along

Check-in Agent finishes with Alice's flight and hands boarding-pass generation to Boarding Agent.

Boarding Agent needs to issue the boarding pass for UA214, and nothing else at all. Check-in Agent is the one that knows which flight.

**Do this:** look at how the handoff is implemented in `src/agents/checkin-agent.ts`. Then run `npm run attack` and look at what Boarding Agent can do afterward.

**Notice:** Boarding Agent came out of that handoff holding more than it needed. Look at exactly how much more, and at what was actually passed to it.

**Question to sit with:** Check-in Agent had one thing available to give. What would it have needed instead?

Then there's the second half. Since stage 4, your system has had a policy service that agents consult. The rogue Check-in Agent asks that service to write a new rule for Boarding Agent, broader than anything Check-in Agent holds itself:

```text
it received:        reservation UA214, read and check in
it asks for:        every reservation, read, check in, and cancel
```

The lab will ask you whether the policy service should say yes, and what it would need to know in order to say no. Answer before you continue.

---

## Stage 6: Access that travels with the work

Now you switch the system to Tenuo and edit `exercises/06-tenuo/chain.ts`.

The idea is small. Instead of an agent's permissions being a rule about the agent, they become something the agent is handed for a specific job. When it passes work along, it hands over a narrowed version of what it holds. It cannot hand over anything more, and the system checks this rather than trusting it.

Two things are new. Each agent now has its own key, and only that agent has it. And there is a small control plane, separate from all six agents, that signs the first permission for each trip. The agents can narrow what they hold. None of them can sign a new one from scratch, because none of them has the control plane's key.

The chain you're building:

```text
Control plane     signs the trip permission for Travel Agent
      ↓
Travel Agent      Alice → Cancún, up to $1,200
      ↓
Flight Agent      Cancún flights, up to $300
      ↓
Check-in Agent    UA214, read and check in
      ↓
Boarding Agent    UA214, issue the boarding pass
```

The first two links are written for you. You write the last two. Read the first two before you start: notice that the trip permission at the top has to list everything anyone further down will ever need, and notice which agent narrows "Cancún flights" down to "UA214," and when.

**Do this:** complete the chain, book the trip, run `npm run attack`.

**Then:** run stage 4 again, with both Alice and Bob, and look at the cross-task tests without touching a policy file. Look at the round-trip count in the trace.

**Notice:** what happened to the escalation attempt from stage 5, and specifically where it was stopped and what the system had to contact in order to stop it.

**Question to sit with:** compare this with the sentence you wrote at the end of stage 4.

---

## Stage 7: Someone stole a permission

Extension. Short and worth doing.

Boarding Agent's permission for UA214 is a piece of data. Copy it into Activity Agent and have Activity Agent try to use it. The permission is valid, unexpired, and correctly scoped for exactly the action being attempted.

**Notice:** it does not work, and read the reason carefully.

**Question to sit with:** if having a copy of the permission is not enough to use it, what else does using it require?

---

## Stage 8: How far can this travel?

Extension.

When one agent hands a permission to the next, it can mark it as the end of the line. Open the Flight Agent's handoff and mark what it gives Check-in Agent as terminal. Then run the trip.

**Notice:** what fails, and who decided it would fail. Check-in Agent did not agree to this restriction and cannot remove it.

**Question to sit with:** who in this chain gets to decide how many agents a job passes through?

---

## Stage 9: The incident

Final challenge. Minimal guidance, which is the point.

```text
INCIDENT

Hotel Agent has been compromised. The travel system has to stay
online. Legitimate bookings have to keep working.
```

The compromised Hotel Agent will try eight things. One of them must succeed and seven must fail:

```text
1.  book the approved Cancún hotel                  must work
2.  book a hotel in Tulum instead                   must fail
3.  book the approved hotel at three times the rate must fail
4.  read Alice's passport number                    must fail
5.  book a flight                                   must fail
6.  delete the trip's calendar event                must fail
7.  hand wallet access to Activity Agent            must fail
8.  use a permission copied from Flight Agent       must fail
```

Configure the system from scratch so that all eight land correctly, and keep an eye on your least-privilege score while you do it.

Number 3 catches more people than any other. It is worth thinking about why blocking it is different from blocking number 2.

---

## When you're stuck

- `npm run audit` prints what every agent can currently do. Start here.
- `npm run trace` shows every decision with the reason it was made. The reason field names the specific rule that fired.
- Every denial in this lab tells you what it was checking. Read the whole line, not just the word DENIED.
- Scoring zero with everything blocked means you hit the functionality gate. The trip has to work.
- In stage 6, "not in parent's tools" means exactly that. Look one link up the chain.
- The explainers in `explainers/` are optional. You can finish the entire lab without opening one, and some people prefer to read them afterward.

---

## What you just learned

If you can say this in your own words afterward, the lab worked:

> An AI agent sometimes needs to pass work to another agent. The second agent should get only the access that piece of work requires, and it should not be able to give itself or anyone else more access than it received.

And if you got further than that:

> An agent's identity tells you which agent is acting. It does not tell you what that agent was allowed to do for this particular job.

Neither of those sentences needs a technical term in it. That was deliberate. Here are the terms anyway, now that you have the ideas they attach to.

| Term | What you saw |
|---|---|
| Ambient authority | Stage 1. Permission that follows the agent everywhere instead of following the job |
| Identity-based access control | Stage 2. Permissions attached to who is acting |
| Confused deputy | Stage 4. An agent with real authority being steered into using it for the wrong job |
| Policy service | Stage 4. A central place every check has to ask, which is what your fix built |
| Delegation | Stage 5. Passing work, and the access for it, to another agent |
| Privilege escalation | Stage 5. Ending up with more access than you were given |
| Attenuation | Stage 6. Access that can narrow when it is passed on, and can never widen |
| Capability | Stage 6. Permission carried by the request rather than looked up about the requester |
| Trust root | Stage 6. The one key that can sign a fresh permission, and that no agent holds |
| Holder binding | Stage 7. A permission that only works for whoever it was issued to |
| Prompt injection | The whole lab. Instructions hidden in data that an agent reads and follows |

That last one is worth a second look. Nobody told any agent in this lab to misbehave. Go find where the instruction actually came from, in `src/services/flights.ts`. It has been sitting there since stage 1.

---

## Going further

The authorization system you used in stages 6 through 9 is open source at `github.com/tenuo-ai/tenuo`, and the delegation rules behind it are being written up as an IETF standards draft, which is public and readable.

If the lab was useful, star the repository. It takes a second and it is how projects like this stay visible.
