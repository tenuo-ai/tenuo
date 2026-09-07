---
title: "Stage 6: Access that travels with the work"
description: "Stage 6 of the Agent Delegation Challenge."
---

Stages: [1]({{ site.baseurl }}/lab/stage-1) · [2]({{ site.baseurl }}/lab/stage-2) · [3]({{ site.baseurl }}/lab/stage-3) · [4]({{ site.baseurl }}/lab/stage-4) · [5]({{ site.baseurl }}/lab/stage-5) · **6** · [7]({{ site.baseurl }}/lab/stage-7) · [8]({{ site.baseurl }}/lab/stage-8) · [9]({{ site.baseurl }}/lab/stage-9) · [10]({{ site.baseurl }}/lab/stage-10)

# Stage 6: Access that travels with the work

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

The root and every link out of Travel Agent are written for you. You write the last two: Flight → Check-in and Check-in → Boarding. Read the written ones before you start: notice that the trip permission at the top has to list everything anyone further down will ever need, and notice which agent narrows "Cancún flights" down to "UA214," and when.

**Do this:** complete the chain, book the trip, run `npm run attack`.

**Then:** run stage 4 again, with both Alice and Bob, and look at the cross-task tests without touching a policy file. Look at `central_calls` in the trace and compare it with what you wrote down at the end of stage 4.

**Notice:** what happened to the escalation attempt from stage 5, and specifically where it was stopped and what the system had to contact in order to stop it.

**Question to sit with:** compare this with the sentence you wrote at the end of stage 4.

← [Stage 5: Passing the work along]({{ site.baseurl }}/lab/stage-5)   |   [Stage 7: Someone stole a permission]({{ site.baseurl }}/lab/stage-7) →
