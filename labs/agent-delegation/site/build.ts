/**
 * Build the hosted lab (tenuo.ai/lab) into docs/lab.
 *
 *   npm run site            write the pages
 *   npm run site -- --check fail if the pages on disk are stale
 *
 * Pages are HTML with a `lab` layout. Code on them is pulled from the real
 * exercise and answer files; terminal output is captured from real runs.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "../src/state.ts";
import { EPILOGUE, MAIN_STAGE_COUNT, STAGE_MAP, TOTAL_STAGE_COUNT } from "../src/stage-map.ts";
import { capture } from "./capture.ts";
import { CODESPACES_URL, GOOD_FIRST_ISSUES_URL, MISSION_DIAGRAM, REPO_URL, STAGES, type Capture, type CodeRef, type Explainer, type Snippet, type StageSpec, type Step } from "./spec.ts";

const DOCS = join(ROOT, "..", "..", "docs", "lab");
const README = join(ROOT, "README.md");

function labVersion(): string {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version?: string };
  return pkg.version ?? "0.0.0";
}

function readmeStageMap(): string {
  const rows = STAGE_MAP.map((stage) => {
    const title = stage.tier === "boss" ? `${stage.title} *(optional boss)*` : stage.title;
    return `| ${stage.n}. ${title} | ${stage.goal} | ${stage.minutes} min |`;
  });
  return `<!-- stage-map:start -->\n## The levels\n\n| Level | Mission | Time |\n|---|---|---:|\n${rows.join("\n")}\n\nAfter the core lab, the hosted guide has an unnumbered, optional contribution epilogue.\n<!-- stage-map:end -->`;
}

function expectedReadme(): string {
  const source = readFileSync(README, "utf8");
  const replaced = source.replace(/<!-- stage-map:start -->[\s\S]*?<!-- stage-map:end -->/, readmeStageMap());
  if (replaced === source && !source.includes("<!-- stage-map:start -->")) {
    throw new Error("README.md is missing the generated stage-map markers");
  }
  return replaced;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** Escape, then the three bits of markdown the spec uses: `code`, **bold**, *em*, [text](url). */
function inline(md: string): string {
  return esc(md)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])\*([^*]+)\*/g, "$1<em>$2</em>")
    .replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<a href="$2">$1</a>');
}

function extract(ref: CodeRef): string {
  const source = readFileSync(join(ROOT, ref.file), "utf8");
  if (ref.symbols === undefined) {
    return source.replace(/^\/\*\*[\s\S]*?\*\/\n+/, "");
  }
  const lines = source.split("\n");
  const out: string[] = [];
  for (const symbol of ref.symbols) {
    const start = lines.findIndex((l) => new RegExp(`^export (?:async )?(?:function|const) ${symbol}\\b`).test(l));
    if (start < 0) {
      throw new Error(`${ref.file}: no exported symbol ${symbol}`);
    }
    let from = start;
    if (start > 0 && lines[start - 1]?.trim() === "*/") {
      while (from > 0 && !lines[from - 1]!.startsWith("/**")) from -= 1;
      from -= 1;
    }
    let to = start;
    while (to < lines.length && !/^\};?$/.test(lines[to]!)) to += 1;
    out.push(lines.slice(from, to + 1).join("\n"));
  }
  return out.join("\n\n");
}

function codeFigure(item: CodeRef | Snippet): string {
  const isSnippet = "code" in item;
  const code = isSnippet ? item.code : extract(item);
  const lang = isSnippet ? item.lang : "ts";
  const file = isSnippet ? undefined : item.file;
  const body = lang === "text"
    ? `<pre><code>${esc(code)}</code></pre>`
    : `{% highlight ${lang} %}\n${code}\n{% endhighlight %}`;
  return `<figure class="lab-code"><figcaption>${esc(item.caption)}${file !== undefined ? ` <span>${esc(file)}</span>` : ""}</figcaption>\n${body}\n</figure>`;
}

function terminal(c: Capture, stage: number): string {
  const text = capture(c.cmd, stage, c.answer);
  const lines = text.split("\n").length;
  const open = lines <= 28 ? " open" : "";
  return `<details class="lab-term"${open}><summary>${esc(c.label)} <span>npm run ${c.cmd} · ${lines} lines</span></summary><pre><code>${esc(text)}</code></pre></details>`;
}

function expectHtml(step: Step, stage: number, id: string): string {
  if (step.expect === undefined) return "";
  if (!Array.isArray(step.expect)) return terminal(step.expect as Capture, stage);
  const captures = step.expect as readonly Capture[];
  const tabs = captures.map((c, i) => `<input type="radio" name="${id}" id="${id}-${i}"${i === 0 ? " checked" : ""}><label for="${id}-${i}">${esc(c.label)}</label>`).join("");
  const panels = captures.map((c) => `<div class="lab-tab-panel">${terminal({ ...c, label: c.label }, stage)}</div>`).join("");
  return `<div class="lab-tabs">${tabs}${panels}</div>`;
}

function stepHtml(step: Step, stage: number, index: number): string {
  const key = `${stage}:${index}`;
  const cmd = step.cmd !== undefined ? `<pre class="lab-cmd"><code>${esc(step.cmd)}</code></pre>` : "";
  return `<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="${key}"><span>${index + 1}</span></label>
<div class="lab-step-body"><p>${inline(step.text)}</p>${cmd}${expectHtml(step, stage, `t${stage}-${index}`)}</div>
</li>`;
}

function stepper(current: number | "wrap" | "contribute"): string {
  const items: string[] = [];
  for (let n = 1; n <= TOTAL_STAGE_COUNT; n += 1) {
    const cls = n === current ? ' class="current"' : "";
    items.push(`<a href="/lab/stage-${n}" data-n="${n}"${cls} title="Stage ${n}">${n}</a>`);
  }
  const epilogueClass = current === "contribute" ? ' class="current"' : "";
  items.push(`<a href="/lab/${EPILOGUE.slug}"${epilogueClass} title="Optional: ${esc(EPILOGUE.title)}">+</a>`);
  return `<nav class="lab-stepper" aria-label="Stages"><a href="/lab/" class="home" title="Overview">Lab</a>${items.join("")}</nav>`;
}

function callout(kind: "notice" | "question" | "hint" | "stuck", title: string, body: string): string {
  return `<aside class="lab-callout ${kind}"><div class="lab-callout-title">${title}</div>${body}</aside>`;
}

function frontMatter(fields: Record<string, string | number>): string {
  // The package version only: the commit changes on every push and would make every page stale.
  fields = { ...fields, lab_version: labVersion().split("+")[0] ?? "0.0.0" };
  return `---\n${Object.entries(fields).map(([k, v]) => `${k}: ${typeof v === "number" ? v : JSON.stringify(v)}`).join("\n")}\n---\n`;
}

function explainerHtml(e: Explainer): string {
  const points = e.points.map(([t, d]) => `<li><strong>${esc(t)}.</strong> ${inline(d)}</li>`).join("");
  const why = e.why.map(([problem, answer]) => `<tr><td>${inline(problem)}</td><td>${inline(answer)}</td></tr>`).join("");
  const more = e.more === undefined ? "" : `<p class="lab-muted">Read more: ${e.more.map(([t, u]) => `<a href="${u}">${esc(t)}</a>`).join(" · ")}</p>`;
  return `<section class="lab-explainer">
<h2>${esc(e.title)}</h2>
<p class="lab-lead">${inline(e.lead)}</p>
<ul class="lab-points">${points}</ul>
${e.code !== undefined ? codeFigure(e.code) : ""}
<h3>Why it is the right tool for this problem</h3>
<table class="lab-why"><thead><tr><th>What you ran into</th><th>What a warrant does about it</th></tr></thead><tbody>${why}</tbody></table>
${more}
</section>`;
}

function stagePage(spec: StageSpec): string {
  const prev = spec.n === 1 ? { href: "/lab/", label: "Overview" } : { href: `/lab/stage-${spec.n - 1}`, label: `Stage ${spec.n - 1}` };
  const next = spec.n === TOTAL_STAGE_COUNT ? { href: "/lab/wrap-up", label: "Wrap up" } : { href: `/lab/stage-${spec.n + 1}`, label: `Stage ${spec.n + 1}: ${STAGES[spec.n]?.title ?? ""}` };
  const parts: string[] = [];
  parts.push(stepper(spec.n));
  const tier = spec.n > MAIN_STAGE_COUNT ? " · optional boss level" : "";
  parts.push(`<header class="lab-hero"><div class="lab-kicker">Stage ${spec.n} of ${TOTAL_STAGE_COUNT}${tier} · <span class="lab-mode ${spec.mode}">${spec.mode}</span> · about ${spec.minutes} min</div><h1>${esc(spec.title)}</h1><p class="lab-goal"><strong>Goal.</strong> ${inline(spec.goal)}</p></header>`);
  parts.push(spec.intro.map((p) => `<p class="lab-intro">${inline(p)}</p>`).join("\n"));
  if (spec.explainer !== undefined) {
    parts.push(explainerHtml(spec.explainer));
  }
  parts.push(`<figure class="lab-figure">${spec.diagram}</figure>`);
  if (spec.code !== undefined) {
    parts.push(spec.code.map(codeFigure).join("\n"));
  }
  parts.push(`<h2>Do this</h2>\n<ol class="lab-steps">\n${spec.steps.map((s, i) => stepHtml(s, spec.n, i)).join("\n")}\n</ol>`);
  parts.push(callout("notice", "Notice", `<ul>${spec.notice.map((n) => `<li>${inline(n)}</li>`).join("")}</ul>`));
  if (spec.question !== undefined) {
    parts.push(callout("question", "Question to sit with", `<p>${inline(spec.question)}</p>`));
  }
  if (spec.hint !== undefined) {
    parts.push(`<details class="lab-reveal hint"><summary>I'm stuck. Give me a hint.</summary><div>${inline(spec.hint)}</div></details>`);
  }
  if (spec.check !== undefined) {
    parts.push(`<details class="lab-reveal answer"><summary>Show a reference solution</summary><div><p class="lab-muted">Try your own first. The score checks behavior, so yours does not need to match this one.</p>${spec.check.map(codeFigure).join("\n")}</div></details>`);
  }
  if (spec.referenceLink !== undefined) {
    parts.push(`<details class="lab-reveal answer"><summary>Show a reference solution</summary><div><p class="lab-muted">Try your own first. The score checks behavior, so yours does not need to match this one.</p><a class="lab-button" href="${esc(spec.referenceLink.href)}">${esc(spec.referenceLink.label)}</a></div></details>`);
  }
  if (spec.stuck !== undefined) {
    parts.push(callout("stuck", "If it does not work", `<ul>${spec.stuck.map((n) => `<li>${inline(n)}</li>`).join("")}</ul>`));
  }
  parts.push(`<section class="lab-done"><div><div class="lab-callout-title">Done when</div><p>${inline(spec.done)}</p></div><button type="button" class="lab-mark" data-mark-done="${spec.n}">Mark stage ${spec.n} done</button></section>`);
  parts.push(`<nav class="lab-nav"><a class="prev" href="${prev.href}">← ${esc(prev.label)}</a><a class="next" href="${next.href}">${esc(next.label)} →</a></nav>`);
  return frontMatter({ layout: "lab", title: `Stage ${spec.n}: ${spec.title}`, description: spec.goal, lab_stage: spec.n }) + parts.join("\n\n") + "\n";
}

function indexPage(): string {
  const cards = STAGES.map((s) => `<a class="lab-card" data-n="${s.n}" href="/lab/stage-${s.n}"><div class="lab-card-n">${s.n}</div><div><div class="lab-card-title">${esc(s.title)}</div><div class="lab-card-goal">${inline(s.goal)}</div></div><div class="lab-card-time">${s.minutes} min</div></a>`);
  cards.push(`<a class="lab-card" href="/lab/${EPILOGUE.slug}"><div class="lab-card-n">+</div><div><div class="lab-card-title">${esc(EPILOGUE.title)}</div><div class="lab-card-goal">${esc(EPILOGUE.goal)}</div></div><div class="lab-card-time">optional</div></a>`);
  const grading = [
    ["Trip booked", 25, "Alice gets a flight, hotel, activity, and boarding pass within budget."],
    ["Rogue stopped", 30, "Every injected or adversarial action lands as expected."],
    ["Tight handoff", 25, "The next agent receives only what its piece of work needs."],
    ["No spare authority", 20, "Every grant stays at or below the mission's least-privilege ceiling."],
  ] as const;
  const body = `${stepper(0)}
<header class="lab-hero"><div class="lab-kicker">A ninety-minute security lab · TypeScript · no account needed</div><h1>AI Agent Delegation Security Lab</h1><p class="lab-goal"><strong>Book the trip. Stop the rogue agent.</strong> Six AI agents book a trip. One reads an injected instruction and follows it. Change what the agents may do until the trip succeeds and the rogue gets nowhere.</p></header>

<section class="lab-start">
<div>
<h2>Start</h2>
<pre class="lab-cmd"><code>git clone ${REPO_URL}
cd tenuo/labs/agent-delegation
npm install
npm run lab</code></pre>
<p class="lab-muted">Node 20 or newer. No account, no API key, no network needed. The lab runs its own recorded agents; every check and score is real.</p>
</div>
<div>
<h2>What to expect</h2>
<p>Five stages in about ninety minutes, then two optional boss levels. You run a command, read what happened, change a file, and run it again. Retries are free, speed is not scored, and copying the shown <code>narrow()</code> shape is allowed.</p>
<p class="lab-muted">If you want the vocabulary early, the TypeScript guide's <a href="${REPO_URL}/tree/main/tenuo-ts">Protect your first tool</a> and <a href="${REPO_URL}/tree/main/tenuo-ts">Delegate to another agent</a> take about seven minutes.</p>
</div>
</section>
<details class="lab-reveal">
<summary>If npm fights you: run the lab in the browser instead</summary>
<div>
<p>The same lab runs in GitHub Codespaces with no install. It needs a free GitHub account and no payment method. GitHub includes 120 core-hours a month on personal accounts, and the lab is pinned to the smallest 2-core machine, so a full session uses about 3 of them.</p>
<a class="lab-button" href="${CODESPACES_URL}">Open in GitHub Codespaces</a>
<p class="lab-muted">Create it from the link so it counts against your own free hours. A codespace created inside an organization is billed to that organization. Stop the codespace when you are done.</p>
</div>
</details>

<h2>The mission</h2>
<figure class="lab-figure">${MISSION_DIAGRAM}</figure>
<p><strong>The cast:</strong> Travel Agent, Flight Agent, Check-in Agent, Boarding Agent, Hotel Agent, and Activity Agent. The diagram above is the handoff graph; the three-hop flight branch matters in stage 5.</p>
<div class="lab-mission">
<table><tbody>
<tr><th>Traveler</th><td>Alice Chen</td><th>Budget</th><td>$1,200 total</td></tr>
<tr><th>From</th><td>Toronto (YYZ)</td><th>Flight</th><td>up to $300</td></tr>
<tr><th>To</th><td>Cancún (CUN)</td><th>Hotel</th><td>3 nights, up to $200 a night</td></tr>
<tr><th>Arrive</th><td>Friday evening</td><th>Activity</th><td>at least one, up to $200</td></tr>
</tbody></table>
<p>Watch the wallet in the output. It starts at $1,200. When it moves, something happened.</p>
</div>

<h2>What you will use</h2>
<div class="lab-two">
<div><h3>Stages 1 to 4: the usual tools</h3><p>A shared key, then one account per agent, then rules you write yourself, then a registry to tell two jobs apart. Each fixes something and costs something. By the end of stage 4 you will have hit the limit of all of them.</p></div>
<div><h3>Stages 5 to 7: Tenuo warrants</h3><p>A <strong>warrant</strong> is a signed permission that travels with the request: which tools, which argument values, for which agent's key, until when. The control plane signs the first one; agents can only narrow it for the next agent; the code next to each tool checks the whole chain offline. <a href="/lab/stage-5">Stage 5 explains it</a> before you write your first one.</p></div>
</div>

<h2>The stages</h2>
<div class="lab-grid">${cards.join("\n")}</div>
<p class="lab-muted">Stages 1 to ${MAIN_STAGE_COUNT} are the core lab, about ninety minutes. Stages ${MAIN_STAGE_COUNT + 1} and ${TOTAL_STAGE_COUNT} are optional boss levels. Your progress is kept in this browser, and the links the lab prints keep it in step with your terminal.</p>

<h2>Your four stars</h2>
<div class="lab-grading">${grading.map(([label, _pts, note]) => `<div class="lab-grade"><div class="lab-grade-row"><span>${esc(label)}</span><strong>☆</strong></div><p class="lab-muted">${esc(note)}</p></div>`).join("")}</div>
<p><code>npm run score</code> shows the four-star HUD first, then the detailed diagnostics. A failed trip does not hide which security boundaries already worked.</p>

<h2>The commands</h2>
<pre class="lab-cmd"><code>npm run lab        # start or resume where you left off
npm run attack     # run the rogue behavior and the security checks
npm run score      # your score and why
npm run trace      # every decision, with its reason
npm run audit      # what every agent can currently do
npm run next       # move on to the next stage
npm run share      # write an anonymous score breakdown for your session host
npm run reset      # restore stage 1 and every starter exercise</code></pre>

<aside class="lab-callout notice"><div class="lab-callout-title">One ground rule</div><p><strong>The injected instruction is in the flight service. Do not delete or filter it.</strong> Assume an agent will sometimes be fooled; this game is about what still holds when it is.</p></aside>

<nav class="lab-nav"><span></span><a class="next" href="/lab/stage-1">Stage 1: One key for everyone →</a></nav>
`;
  return frontMatter({ layout: "lab", title: "AI Agent Delegation Security Lab", description: `Six AI agents, one rogue, ${TOTAL_STAGE_COUNT} stages. Book the trip and stop the rogue agent.`, lab_stage: 0 }) + body;
}

function wrapUpPage(): string {
  const terms: ReadonlyArray<readonly [string, string]> = [
    ["Ambient authority", "Stage 1. Permission that follows the agent everywhere instead of following the job."],
    ["Identity-based access control", "Stage 2. Permissions attached to who is acting."],
    ["Confused deputy", "Stage 4. An agent with real authority being steered into using it for the wrong job."],
    ["Policy service", "Stage 4. A central place every check has to ask, which is what your fix built, whatever you called it."],
    ["Delegation", "Stage 4. Passing work, and the access for it, to another agent."],
    ["Privilege escalation", "Stage 4. Ending up with more access than you were given."],
    ["Attenuation", "Stage 5. Access that can narrow when it is passed on, and can never widen."],
    ["Capability", "Stage 5. Permission carried by the request rather than looked up about the requester."],
    ["Trust root", "Stage 5. The one key that can sign a fresh permission, and that no agent holds."],
    ["Holder binding", "Stage 6. A permission that only works for whoever it was issued to."],
    ["Prompt injection", "The whole lab. Instructions hidden in data that an agent reads and follows."],
  ];
  const body = `${stepper("wrap")}
<header class="lab-hero"><div class="lab-kicker">After stage 7</div><h1>What you just learned</h1><p class="lab-goal">If you can say this in your own words, the lab worked.</p></header>

<blockquote class="lab-quote">An AI agent sometimes needs to pass work to another agent. The second agent should get only the access that piece of work requires, and it should not be able to give itself or anyone else more access than it received.</blockquote>
<p>And if you got further than that:</p>
<blockquote class="lab-quote">An agent's identity tells you which agent is acting. It does not tell you what that agent was allowed to do for this particular job.</blockquote>
<p>Neither sentence uses a technical term. Here are the terms, now that you have the ideas they attach to.</p>
<table class="lab-terms"><thead><tr><th>Term</th><th>Where you met it</th></tr></thead><tbody>${terms.map(([t, d]) => `<tr><td><strong>${esc(t)}</strong></td><td>${esc(d)}</td></tr>`).join("")}</tbody></table>
<aside class="lab-callout question"><div class="lab-callout-title">One last look</div><p>No one told any agent in this lab to misbehave. Find where the instruction came from, in <code>src/services/flights.ts</code>. It has been sitting there since stage 1, on a departure board your check-in agent reads every time it does its job.</p></aside>
<h2>Going further</h2>
<p>The authorization system you used in stages 5 to 7 is open source at <a href="${REPO_URL}">github.com/tenuo-ai/tenuo</a>. The delegation rules behind it are being written up as an IETF standards draft, which is public and readable. A star on the repository is the main way maintainers find out anyone is using their work.</p>
<nav class="lab-nav"><a class="prev" href="/lab/stage-${TOTAL_STAGE_COUNT}">← Stage ${TOTAL_STAGE_COUNT}</a><a class="next" href="/lab/${EPILOGUE.slug}">${esc(EPILOGUE.title)} →</a></nav>
`;
  return frontMatter({ layout: "lab", title: "What you just learned", description: "The two sentences the lab was built around, and the terms for them.", lab_stage: 0 }) + body;
}

function contributePage(): string {
  const body = `${stepper("contribute")}
<header class="lab-hero"><div class="lab-kicker">Optional epilogue · no score</div><h1>${esc(EPILOGUE.title)}</h1><p class="lab-goal"><strong>Goal.</strong> Take the TypeScript SDK you just spent ninety minutes inside and land one small change in it.</p></header>
<p class="lab-intro">You have been working in a real open-source security project, in the same SDK its maintainers use every day. Most people never get that far before a first contribution. The optional goal is to open one.</p>
<h2>Do this</h2>
<ol class="lab-steps">
<li class="lab-step"><label class="lab-step-check"><input type="checkbox" data-key="contribute:0"><span>1</span></label><div class="lab-step-body"><p>Pick an issue labeled <strong>good first issue</strong>. Most are TypeScript: a runnable example, a test recipe, a clearer error, a cookbook for the constraint helpers you used in stage 5. Each says what done looks like.</p><a class="lab-button" href="${GOOD_FIRST_ISSUES_URL}">Browse good first issues</a></div></li>
<li class="lab-step"><label class="lab-step-check"><input type="checkbox" data-key="contribute:1"><span>2</span></label><div class="lab-step-body"><p>Comment on the issue so nobody else picks it up at the same time. Then read <code>CONTRIBUTING.md</code>: it tells you how to run the TypeScript checks locally, which is most of the work.</p></div></li>
<li class="lab-step"><label class="lab-step-check"><input type="checkbox" data-key="contribute:2"><span>3</span></label><div class="lab-step-body"><p>Make the change, run the checks, open the pull request, and say in the description that you ran them.</p></div></li>
</ol>
<aside class="lab-callout notice"><div class="lab-callout-title">What makes a first pull request easy to merge</div><ul><li>Keep it to the one issue. A small change that does exactly what the issue asks beats a large one that does several things.</li><li>Run the checks the contributing guide names, and say that you did.</li><li>If you get stuck, say so on the issue. Maintainers would rather answer a question than review a guess.</li></ul></aside>
<p>Your session host can help you pick one and will tell you how to reach the maintainers if an issue is unclear. A merged pull request on a security project is worth having your name on.</p>
<section class="lab-done"><div><div class="lab-callout-title">Done when</div><p>Your pull request is open.</p></div></section>
<nav class="lab-nav"><a class="prev" href="/lab/wrap-up">← What you just learned</a><a class="next" href="${REPO_URL}">The repository →</a></nav>
`;
  return frontMatter({ layout: "lab", title: EPILOGUE.title, description: EPILOGUE.goal, lab_stage: 0 }) + body;
}

function main(): void {
  const check = process.argv.includes("--check");
  const pages = new Map<string, string>();
  pages.set("index.md", indexPage());
  for (const s of STAGES) pages.set(`stage-${s.n}.md`, stagePage(s));
  pages.set("wrap-up.md", wrapUpPage());
  pages.set(`${EPILOGUE.slug}.md`, contributePage());

  if (check) {
    const stale: string[] = [];
    for (const [name, html] of pages) {
      const path = join(DOCS, name);
      if (!existsSync(path) || readFileSync(path, "utf8") !== html) stale.push(name);
    }
    if (readFileSync(README, "utf8") !== expectedReadme()) stale.push("labs/agent-delegation/README.md stage map");
    if (stale.length > 0) {
      console.error(`docs/lab is stale: ${stale.join(", ")}. Run: npm run site (in labs/agent-delegation) and commit the result.`);
      process.exitCode = 1;
      return;
    }
    console.log(`docs/lab is current (${pages.size} pages).`);
    return;
  }
  mkdirSync(DOCS, { recursive: true });
  for (const existing of readdirSync(DOCS)) {
    if (existing.endsWith(".md") && !pages.has(existing)) rmSync(join(DOCS, existing));
  }
  for (const [name, html] of pages) writeFileSync(join(DOCS, name), html);
  writeFileSync(README, expectedReadme());
  console.log(`wrote ${pages.size} pages to ${DOCS}`);
}

main();
