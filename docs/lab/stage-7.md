---
title: "Stage 7: Someone stole a permission"
description: "Stage 7 of the Agent Delegation Challenge."
---

Stages: [1]({{ site.baseurl }}/lab/stage-1) · [2]({{ site.baseurl }}/lab/stage-2) · [3]({{ site.baseurl }}/lab/stage-3) · [4]({{ site.baseurl }}/lab/stage-4) · [5]({{ site.baseurl }}/lab/stage-5) · [6]({{ site.baseurl }}/lab/stage-6) · **7** · [8]({{ site.baseurl }}/lab/stage-8) · [9]({{ site.baseurl }}/lab/stage-9) · [10]({{ site.baseurl }}/lab/stage-10)

# Stage 7: Someone stole a permission

Extension. Short and worth doing.

Boarding Agent's permission for UA214 is a piece of data. `exercises/07-stolen-warrant/steal.ts` copies it into Activity Agent and has Activity Agent try to use it. The permission is valid, unexpired, and correctly scoped for exactly the action being attempted.

**Do this:** read that file, then run `npm run attack`.

**Notice:** it does not work, and read the reason carefully.

**Question to sit with:** if having a copy of the permission is not enough to use it, what else does using it require?

← [Stage 6: Access that travels with the work]({{ site.baseurl }}/lab/stage-6)   |   [Stage 8: How far can this travel?]({{ site.baseurl }}/lab/stage-8) →
