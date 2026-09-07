---
title: "Stage 2: Every agent gets its own account"
description: "Stage 2 of the Agent Delegation Challenge."
---

Stages: [1]({{ site.baseurl }}/lab/stage-1) · **2** · [3]({{ site.baseurl }}/lab/stage-3) · [4]({{ site.baseurl }}/lab/stage-4) · [5]({{ site.baseurl }}/lab/stage-5) · [6]({{ site.baseurl }}/lab/stage-6) · [7]({{ site.baseurl }}/lab/stage-7) · [8]({{ site.baseurl }}/lab/stage-8) · [9]({{ site.baseurl }}/lab/stage-9) · [10]({{ site.baseurl }}/lab/stage-10)

# Stage 2: Every agent gets its own account

Now each agent has its own credential with permissions that match its role. Flight Agent can do flight things. Hotel Agent can do hotel things. Check-in Agent can read reservations and check people in.

**Do this:** run `npm run attack` and compare the output to stage 1.

**Notice:** a lot of the damage is gone. Some of it is not.

**Question to sit with:** the actions that still succeed are all actions Check-in Agent's role legitimately includes. So what is the difference between the ones you want and the ones you don't?

← [Stage 1: One key for everyone]({{ site.baseurl }}/lab/stage-1)   |   [Stage 3: Rules that fit the job]({{ site.baseurl }}/lab/stage-3) →
