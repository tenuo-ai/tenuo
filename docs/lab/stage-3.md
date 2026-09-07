---
title: "Stage 3: Rules that fit the job"
description: "Stage 3 of the Agent Delegation Challenge."
---

Stages: [1]({{ site.baseurl }}/lab/stage-1) · [2]({{ site.baseurl }}/lab/stage-2) · **3** · [4]({{ site.baseurl }}/lab/stage-4) · [5]({{ site.baseurl }}/lab/stage-5) · [6]({{ site.baseurl }}/lab/stage-6) · [7]({{ site.baseurl }}/lab/stage-7) · [8]({{ site.baseurl }}/lab/stage-8) · [9]({{ site.baseurl }}/lab/stage-9) · [10]({{ site.baseurl }}/lab/stage-10)

# Stage 3: Rules that fit the job

Now you write the permissions yourself. Open `exercises/03-scoped/policy.ts`.

Instead of "Check-in Agent can read reservations," you can say which reservation. Instead of "Flight Agent can book flights," you can say which destination and how much it may spend.

**Do this:** narrow the rules until `npm run attack` is clean and the trip still books. Check `npm run score`.

**Notice:** this works. Everything the rogue agent tried is now blocked, and Alice still gets to Cancún.

Keep this file. You'll want it in a minute.

← [Stage 2: Every agent gets its own account]({{ site.baseurl }}/lab/stage-2)   |   [Stage 4: A second traveler shows up]({{ site.baseurl }}/lab/stage-4) →
