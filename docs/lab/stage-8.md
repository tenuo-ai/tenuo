---
title: "Stage 8: How far can this travel?"
description: "Stage 8 of the Agent Delegation Challenge."
---

Stages: [1]({{ site.baseurl }}/lab/stage-1) · [2]({{ site.baseurl }}/lab/stage-2) · [3]({{ site.baseurl }}/lab/stage-3) · [4]({{ site.baseurl }}/lab/stage-4) · [5]({{ site.baseurl }}/lab/stage-5) · [6]({{ site.baseurl }}/lab/stage-6) · [7]({{ site.baseurl }}/lab/stage-7) · **8** · [9]({{ site.baseurl }}/lab/stage-9) · [10]({{ site.baseurl }}/lab/stage-10)

# Stage 8: How far can this travel?

Extension.

When one agent hands a permission to the next, it can mark it as the end of the line. Open `exercises/08-terminal/chain.ts`, find the Flight → Check-in link, and mark what it gives Check-in Agent as terminal. Then run the trip.

There is a second version of this. The permission the control plane signs at the very top carries a maximum number of hops for the whole trip. Any agent along the way can lower it. None of them can raise it. Try setting it at the top and watch where the chain stops.

**Notice:** what fails, and who decided it would fail. Check-in Agent did not agree to this restriction and cannot remove it.

**Question to sit with:** who in this chain gets to decide how many agents a job passes through, and what stops an agent in the middle from deciding otherwise?

← [Stage 7: Someone stole a permission]({{ site.baseurl }}/lab/stage-7)   |   [Stage 9: The incident]({{ site.baseurl }}/lab/stage-9) →
