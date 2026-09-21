---
title: "Jev in practice: typed decisions, scoped authority"
description: "How Jev's typed probabilistic decisions, LangGraph workflows, and Tenuo task-scoped warrants combine in a dependency upgrade agent."
layout: default
permalink: /blog/jev-scoped-authority.html
canonical_url: https://tenuo.ai/blog/jev-scoped-authority
og_image: /images/og-safe-agent-delegation-jev-langgraph-tenuo.png
og_image_alt: "Jev in practice: typed decisions, scoped authority"
author: "Tenuo Engineering"
date: 2026-09-21
tags: ["Jev", "LangGraph", "authorization", "AI agents"]
---

# Jev in practice: typed decisions, scoped authority

*Building safe agent delegation with Jev, LangGraph, and Tenuo*

> **TL;DR:** [`safe-upgrade`](https://github.com/tenuo-ai/safe-upgrade) is a dependency upgrade agent built on Jev, LangGraph, and Tenuo. Jev turns repository evidence into typed probabilistic decisions. LangGraph carries those decisions through a durable workflow. Tenuo gives each resulting action a task-scoped warrant. The design rule: keep judgment, control flow, and authority separate.

![Conceptual flow: repository evidence passes through Jev for a typed decision, LangGraph for workflow state, and Tenuo for a scoped warrant before an action runs.](/images/safe-agent-delegation-architecture.png)
{: .blog-image}

We started with a builder's question: what does a useful workflow look like when Jev, LangGraph, and Tenuo each address a distinct part of the system?

Dependency upgrades gave us a practical way to answer it because, as repository maintainers quickly learn, an apparently mechanical process can conceal difficult compatibility questions. You change a version, install the package, run the tests, and open a pull request, yet the release may have removed an API the repository calls, changed module format, or altered behavior that the existing suite does not exercise. Installation and CI can succeed while the application remains broken.

A useful upgrade agent has to interpret release evidence, relate it to an unfamiliar repository, decide what work is required, change code, and establish that the result is sound. It also receives access to source files, package installation, test commands, Git, and sometimes a remote repository.

This combination let us study both sides of agent development: making useful decisions from messy context and controlling the actions that follow them.

## Begin with a decision the program can use

Jev was our starting point because dependency upgrades contain semantic questions that ordinary rules handle poorly:

- Does this release note affect the way this repository uses the package?
- Would an existing test detect the reported break?
- Which currently eligible step would reduce the most risk?
- Does the final patch address each migration finding?

[Jev](https://docs.typesafe.ai/introduction) is a System One Model for decisions inside software, where a developer supplies state and typed questions. For a [Choice](https://docs.typesafe.ai/primitives/choice), the developer defines the available options and Jev returns the selected option, a probability distribution, and confidence that the program can use for routing.

In `safe-upgrade`, deterministic code first computes the eligible actions and a reason for each one. The production adapter then makes this TypeSafe SDK call:

```ts
import { choice, TypeSafeClient } from "@typesafe-ai/sdk";

const client = new TypeSafeClient();
const criteria = Object.fromEntries(
  input.eligibleActions.map(({ action, reason }) => [action, reason]),
);

const result = await client.systemOne({
  state: JSON.parse(JSON.stringify(input)),
  questions: {
    next: choice(
      "Choose the eligible action that most directly reduces the unresolved " +
        "risk in this upgrade. Every option is already permitted; pick the " +
        "most useful one.",
      criteria,
    ),
  },
});

const answer = result.answers.next;
```

The actual Choice response has this typed shape. The values below illustrate a run where adding a regression test is the strongest next step:

```json
{
  "type": "choice",
  "choice": "author_tests",
  "confidence": 0.82,
  "probabilities": {
    "author_tests": 0.74,
    "assess_verification": 0.18,
    "implement": 0.08
  }
}
```

The router validates the selected label against the original candidates and uses confidence in ordinary TypeScript:

```ts
const choice = validateRouteChoice(
  {
    action: answer.choice,
    confidence: answer.confidence,
    probabilities: answer.probabilities,
  },
  eligibleActions.map(({ action }) => action),
);

const selected = choice.confidence >= confidenceThreshold
  ? choice
  : deterministicFallback(input);

const worker = ACTION_WORKER[selected.action];
```

Jev is particularly useful here because rich repository state can remain rich while the result enters the graph as a small typed decision. Low confidence, a malformed response, or a transport failure sends the workflow through a deterministic route. The candidate set is established before the request, and the runtime validates the returned choice again afterward.

## From Jev's decision to a Tenuo warrant

The Jev response ends with a selected action and confidence. Execution begins when trusted routing code maps that action to a known worker. This creates the next architectural question: what authority should that worker receive for this invocation?

For `author_tests`, the answer is repository read tools, test-file writes, and test execution. In production, Tenuo is initialized with an explicitly trusted issuer public key, then imports an externally issued run warrant and its proof-of-possession holder key. The excerpt begins at that import step. Local demos use a development root and identify that mode in the command output.

The worker receives a short-lived terminal session narrowed from the run's parent warrant:

```ts
const parentSession = tenuo.sessionFromWire({
  warrant: process.env.TENUO_RUN_WARRANT!,
  holderKey: createTenuo.holderKeyFromEnv(
    "TENUO_RUN_HOLDER_SECRET",
  ),
});

const testAuthor = tighten(
  pick(ceilings, [
    ...READ_ONLY,
    "write_test_file",
    "run_check",
  ]),
  "run_check",
  "kind",
  oneOf(["test"]),
);

const childSession = tenuo.narrow(parentSession, testAuthor, {
  terminal: true,
  ttlSeconds: 600,
});
```

The parent warrant sets the maximum authority for the run. Narrowing selects a smaller tool set, tightens `run_check` to tests, shortens the lifetime, and makes the child terminal so it cannot delegate again.

The implementer receives a separate child session for source changes and the exact dependency update, with `write_test_file` excluded from its profile. If implementation code attempts to weaken a regression test, authorization runs before the write tool:

```ts
await broker.withWorker("implementer", "implement", (handle) =>
  handle.tools.write_test_file({
    path: "src/sneaky.test.ts",
    expectedBeforeHash: "absent",
    content: "test.skip('regression', () => {});",
  }),
);
```

The tested denial record begins:

```text
TENUO_TOOL_NOT_AUTHORIZED
worker: implementer
capability: write_test_file
```

The authorization test also confirms that the underlying write function never runs. The denial record includes the worker, capability, argument hash, and session identifier while omitting the attempted file contents. This turns the roles in the graph into enforced execution boundaries: the test author writes tests, the implementer writes source, and the verifier reads and runs checks with candidate files held read-only.

## LangGraph carries the result through the workflow

LangGraph holds the repository facts, findings, decisions, attempts, and evidence across the run. Each node receives explicit state and returns an update, while checkpoints preserve progress at meaningful boundaries.

```text
repository evidence
       |
       v
trusted code computes eligible transitions
       |
       v
Jev selects within that typed set
       |
       v
trusted code maps the action to a worker
       |
       v
Tenuo narrows a warrant for the worker
       |
       v
protected tools return evidence to LangGraph
```

An assessment uses only read-oriented workers and records affected files, migration findings, current checks, and verification gaps. Applying the assessment can add a focused test, migrate source, update the exact dependency, and verify the candidate in a disposable Git worktree. The assessment is bound to the commit, manifest, lockfile, and working-tree state it examined.

## Why this matters in CI

The same boundaries become more important when the agent runs unattended in GitHub Actions. A CI job may have a repository checkout, a package-manager cache, a GitHub token, and permission to comment on or open pull requests. Job-level permissions establish what the workflow identity can reach. They provide limited detail about why this particular run may change a specific package, branch, or file.

`safe-upgrade` can assess a Dependabot pull request from its event or open a verified upgrade as a draft. In production, the CI process imports a run warrant issued by a trusted root. That warrant can bind the run to the requested package and exact version, the temporary worktree, one branch, and draft-only publishing. Each graph node receives a narrower child warrant from that ceiling.

This gives the pipeline two levels of control:

- GitHub Actions permissions limit the workflow identity, such as `contents: read` and `pull-requests: write` for an assessment job.
- Tenuo warrants limit each delegated task, including the permitted tool, arguments, paths, package version, branch, and lifetime.

The distinction matters for any CI agent that can modify code or use repository credentials. A workflow identity answers which principal is running. A task-level warrant carries the authority of the specific upgrade through every delegated step.

## What “safe” means here

The architecture defines safety through properties that can be inspected:

- **Closed decisions.** Jev chooses among transitions that trusted code has already found eligible.
- **Scoped execution.** Every worker receives a short-lived warrant for its tools and arguments.
- **Separated duties.** Test authoring, implementation, verification, and publishing use different write permissions.
- **Independent evidence.** Verification evaluates every finding while candidate files remain read-only.
- **Contained processes.** Tenuo authorizes protected tool calls, while an operating-system sandbox limits what repository and package processes can access.
- **Explicit uncertainty.** Low confidence, stale state, policy violations, and incomplete evidence produce a qualified or stopped result.

Jev can still misread release prose, repository checks can omit important behavior, and trusted wrappers can encode a flawed policy. Narrow questions, confidence-aware routing, scoped warrants, and independent evidence make those uncertainties visible and limit the actions that can follow from them.

## The reusable pattern

The pattern extends beyond dependency upgrades:

1. Compute valid transitions from trusted state.
2. Ask Jev a bounded semantic question over those transitions.
3. Validate the typed response and map it to a known worker.
4. Delegate a Tenuo warrant narrowed to that worker's task.
5. Return evidence to LangGraph and verify it independently.

The stack rests on one principle:

> Keep the component that recommends an action separate from the component that defines its authority.

You can explore the implementation in the [`safe-upgrade` repository](https://github.com/tenuo-ai/safe-upgrade) or run it from npm:

```bash
npx @tenuo/safe-upgrade doctor
npx @tenuo/safe-upgrade assess --repository .
```

The implementation shown here was built against `@typesafe-ai/sdk` 0.6.0 and `@tenuo/core` 0.3.0-beta.0. We also verified the complete approval workflow against the live Jev API, and the repository includes the end-to-end smoke test.

Jev's request and response model is documented in the [TypeSafe quick start](https://docs.typesafe.ai/introduction/quickstart), and Tenuo is available on [GitHub](https://github.com/tenuo-ai/tenuo).

---

*`safe-upgrade` is an open-source dependency upgrade agent built with Jev, LangGraph, and Tenuo. The source and runnable examples are available in the [`safe-upgrade` repository](https://github.com/tenuo-ai/safe-upgrade).*
