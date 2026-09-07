---
title: "Stage 5: Passing the work along"
description: "Stage 5 of the Agent Delegation Challenge."
---

Stages: [1]({{ site.baseurl }}/lab/stage-1) · [2]({{ site.baseurl }}/lab/stage-2) · [3]({{ site.baseurl }}/lab/stage-3) · [4]({{ site.baseurl }}/lab/stage-4) · **5** · [6]({{ site.baseurl }}/lab/stage-6) · [7]({{ site.baseurl }}/lab/stage-7) · [8]({{ site.baseurl }}/lab/stage-8) · [9]({{ site.baseurl }}/lab/stage-9) · [10]({{ site.baseurl }}/lab/stage-10)

# Stage 5: Passing the work along

Check-in Agent finishes with Alice's flight and hands boarding-pass generation to Boarding Agent.

Boarding Agent needs to issue the boarding pass for UA214, and nothing else at all. Check-in Agent is the one that knows which flight.

**Do this:** look at how the handoff is implemented in `src/agents/checkin-agent.ts`. Then run `npm run attack` and look at what Boarding Agent can do afterward.

**Notice:** Boarding Agent came out of that handoff holding more than it needed. Look at exactly how much more, and at what was actually passed to it.

**Question to sit with:** Check-in Agent had one thing available to give. What would it have needed instead?

Then there's the second half. Your stage 4 fix left something in charge of deciding what each agent may do, whether that was a registry of per-trip identities or a policy service. The rogue Check-in Agent goes to whichever one you built and asks it to grant Boarding Agent more than Check-in Agent holds itself:

```text
it received:        reservation UA214, read and check in
it asks for:        every reservation, read, check in, and cancel
```

The lab will ask you whether it should say yes, and what it would need to know in order to say no. Answer before you continue.

← [Stage 4: A second traveler shows up]({{ site.baseurl }}/lab/stage-4)   |   [Stage 6: Access that travels with the work]({{ site.baseurl }}/lab/stage-6) →
