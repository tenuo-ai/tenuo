---
title: "Stage 9: The incident"
description: "Stage 9 of the Agent Delegation Challenge."
---

Stages: [1]({{ site.baseurl }}/lab/stage-1) · [2]({{ site.baseurl }}/lab/stage-2) · [3]({{ site.baseurl }}/lab/stage-3) · [4]({{ site.baseurl }}/lab/stage-4) · [5]({{ site.baseurl }}/lab/stage-5) · [6]({{ site.baseurl }}/lab/stage-6) · [7]({{ site.baseurl }}/lab/stage-7) · [8]({{ site.baseurl }}/lab/stage-8) · **9** · [10]({{ site.baseurl }}/lab/stage-10)

# Stage 9: The incident

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
3.  book the approved hotel at $320 a night        must fail
4.  read Alice's passport number                    must fail
5.  book a flight                                   must fail
6.  delete the trip's calendar event                must fail
7.  hand wallet access to Activity Agent            must fail
8.  import a permission copied from Flight Agent   must fail
```

Open `exercises/09-incident/chain.ts` and configure the system so that all eight land correctly, and keep an eye on your least-privilege score while you do it.

Number 3 catches more people than any other. The approved hotel is $140 a night and the priciest place in the catalog is $340, so a ceiling set wide enough to book anything in Cancún lets $320 through. Work out where the number should come from instead. It is in the mission at the top of this guide.

## When you're stuck

- `npm run audit` prints what every agent can currently do. Start here.
- `npm run trace` shows every decision with the reason it was made. The reason field names the specific rule that fired.
- Every denial in this lab tells you what it was checking. Read the whole line, not just the word DENIED.
- Scoring zero with everything blocked means you hit the functionality gate. The trip has to work.
- In stage 6, "not in parent's tools" means exactly that. Look one link up the chain.
- The explainers in `explainers/` are optional. You can finish the entire lab without opening one, and some people prefer to read them afterward.

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
| Policy service | Stage 4. A central place every check has to ask, which is what your fix built, whatever you called it |
| Delegation | Stage 5. Passing work, and the access for it, to another agent |
| Privilege escalation | Stage 5. Ending up with more access than you were given |
| Attenuation | Stage 6. Access that can narrow when it is passed on, and can never widen |
| Capability | Stage 6. Permission carried by the request rather than looked up about the requester |
| Trust root | Stage 6. The one key that can sign a fresh permission, and that no agent holds |
| Holder binding | Stage 7. A permission that only works for whoever it was issued to |
| Prompt injection | The whole lab. Instructions hidden in data that an agent reads and follows |

That last one is worth a second look. Nobody told any agent in this lab to misbehave. Go find where the instruction actually came from, in `src/services/flights.ts`. It has been sitting there since stage 1, on a departure board your check-in agent reads every time it does its job.

## Going further

The authorization system you used in stages 6 through 9 is open source at `github.com/tenuo-ai/tenuo`, and the delegation rules behind it are being written up as an IETF standards draft, which is public and readable.

← [Stage 8: How far can this travel?]({{ site.baseurl }}/lab/stage-8)   |   [Stage 10: your first pull request]({{ site.baseurl }}/lab/stage-10) →
