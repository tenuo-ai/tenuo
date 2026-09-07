---
title: "Stage 4: A second traveler shows up"
description: "Stage 4 of the Agent Delegation Challenge."
---

Stages: [1]({{ site.baseurl }}/lab/stage-1) · [2]({{ site.baseurl }}/lab/stage-2) · [3]({{ site.baseurl }}/lab/stage-3) · **4** · [5]({{ site.baseurl }}/lab/stage-5) · [6]({{ site.baseurl }}/lab/stage-6) · [7]({{ site.baseurl }}/lab/stage-7) · [8]({{ site.baseurl }}/lab/stage-8) · [9]({{ site.baseurl }}/lab/stage-9) · [10]({{ site.baseurl }}/lab/stage-10)

# Stage 4: A second traveler shows up

Bob is going to Seattle. His trip runs at the same time as Alice's, through the same agents.

```text
Alice   Cancún    flight up to $300    reservation UA214
Bob     Seattle   flight up to $450    reservation DL331
```

**Do this:** run the lab with both trips. Something will break. Fix it in the policy file, the way that seems obvious. Then run `npm run attack` and read all of the output, including the part labeled CROSS-TASK.

**Notice:** what your fix cost you.

**Question to sit with:** your policy file has a rule for `checkin-agent`. There is one `checkin-agent`, and right now it is doing two different jobs for two different people. Where in that file does it say which job a particular request belongs to?

Do not rush past this stage. It is the whole lab.

You can fix this. People usually find one of two ways, and the lab supports both. Some give the agent a different identity for each trip. Some make every permission check ask which trip the request is for. Either one works, and neither is the wrong answer.

Try yours and get the cross-task tests to pass. Then look at what you had to build in order to get there, and find `central_calls` in the trace. That number counts every time the system had to ask something outside the acting agent before it could decide. Whichever fix you chose, it is not zero, and you cannot make it zero.

Write down, in one sentence, what your fix depends on being available. You will want to compare it with stage 6.

← [Stage 3: Rules that fit the job]({{ site.baseurl }}/lab/stage-3)   |   [Stage 5: Passing the work along]({{ site.baseurl }}/lab/stage-5) →
