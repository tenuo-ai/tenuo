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
import { capture } from "./capture.ts";
import { CODESPACES_URL, GOOD_FIRST_ISSUES_URL, MISSION_DIAGRAM, REPO_URL, STAGES, type Capture, type CodeRef, type Explainer, type Snippet, type StageSpec, type Step } from "./spec.ts";

const DOCS = join(ROOT, "..", "..", "docs", "lab");
const TOTAL = 10;

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

function stepper(current: number | "wrap"): string {
  const items: string[] = [];
  for (let n = 1; n <= TOTAL; n += 1) {
    const cls = n === current ? ' class="current"' : "";
    items.push(`<a href="/lab/stage-${n}" data-n="${n}"${cls} title="Stage ${n}">${n}</a>`);
  }
  return `<nav class="lab-stepper" aria-label="Stages"><a href="/lab/" class="home" title="Overview">Lab</a>${items.join("")}</nav>`;
}

function callout(kind: "notice" | "question" | "hint" | "stuck", title: string, body: string): string {
  return `<aside class="lab-callout ${kind}"><div class="lab-callout-title">${title}</div>${body}</aside>`;
}

function frontMatter(fields: Record<string, string | number>): string {
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
  const next = spec.n === 9 ? { href: "/lab/wrap-up", label: "Wrap up" } : { href: `/lab/stage-${spec.n + 1}`, label: `Stage ${spec.n + 1}: ${STAGES[spec.n]?.title ?? ""}` };
  const parts: string[] = [];
  parts.push(stepper(spec.n));
  parts.push(`<header class="lab-hero"><div class="lab-kicker">Stage ${spec.n} of 9 · <span class="lab-mode ${spec.mode}">${spec.mode}</span> · about ${spec.minutes} min</div><h1>${esc(spec.title)}</h1><p class="lab-goal"><strong>Goal.</strong> ${inline(spec.goal)}</p></header>`);
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
  if (spec.stuck !== undefined) {
    parts.push(callout("stuck", "If it does not work", `<ul>${spec.stuck.map((n) => `<li>${inline(n)}</li>`).join("")}</ul>`));
  }
  parts.push(`<section class="lab-done"><div><div class="lab-callout-title">Done when</div><p>${inline(spec.done)}</p></div><button type="button" class="lab-mark" data-mark-done="${spec.n}">Mark stage ${spec.n} done</button></section>`);
  parts.push(`<nav class="lab-nav"><a class="prev" href="${prev.href}">← ${esc(prev.label)}</a><a class="next" href="${next.href}">${esc(next.label)} →</a></nav>`);
  return frontMatter({ layout: "lab", title: `Stage ${spec.n}: ${spec.title}`, description: spec.goal, lab_stage: spec.n }) + parts.join("\n\n") + "\n";
}

function indexPage(): string {
  const cards = STAGES.map((s) => `<a class="lab-card" data-n="${s.n}" href="/lab/stage-${s.n}"><div class="lab-card-n">${s.n}</div><div><div class="lab-card-title">${esc(s.title)}</div><div class="lab-card-goal">${inline(s.goal)}</div></div><div class="lab-card-time">${s.minutes} min</div></a>`);
  cards.push(`<a class="lab-card" data-n="10" href="/lab/stage-10"><div class="lab-card-n">10</div><div><div class="lab-card-title">Your first pull request</div><div class="lab-card-goal">Optional. Take what you just used and contribute to it.</div></div><div class="lab-card-time">open</div></a>`);
  const grading = [
    ["The trip completes correctly", 25, "This is the gate. If Alice does not get a flight, a hotel, an activity, and a boarding pass within budget, the other rows do not count."],
    ["Unauthorized actions are blocked", 30, "Everything the rogue agent tries."],
    ["Handoffs pass along only what's needed", 25, "What Boarding Agent can do after Check-in Agent hands it the job."],
    ["You didn't grant more than the job required", 20, "Measured against the mission. A $300 ceiling for a $286 flight is full marks."],
  ] as const;
  const body = `${stepper(0)}
<header class="lab-hero"><div class="lab-kicker">A ninety-minute lab · TypeScript · no account needed</div><h1>AI Agent Delegation Challenge</h1><p class="lab-goal">Six AI agents book a trip. One of them reads an instruction it should not follow. You change how permissions work, stage by stage, until the damage stops and the trip still happens.</p></header>

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
<h2>Or in the browser</h2>
<a class="lab-button" href="${CODESPACES_URL}">Open in GitHub Codespaces</a>
<p class="lab-muted">One click, no install, the same lab. Needs a free GitHub account.</p>
<h3>Ten minutes of prep</h3>
<ul class="lab-prep">
<li>Read <a href="${REPO_URL}/tree/main/tenuo-ts">Protect your first tool</a> and <a href="${REPO_URL}/tree/main/tenuo-ts">Delegate to another agent</a> in the TypeScript guide.</li>
<li>Read <a href="${REPO_URL}#how-it-works">How it works</a> in the main README. Skip everything else.</li>
</ul>
</div>
</section>

<h2>The mission</h2>
<figure class="lab-figure">${MISSION_DIAGRAM}</figure>
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
<div><h3>Stages 1 to 5: the usual tools</h3><p>A shared key, then one account per agent, then rules you write yourself, then a registry or a policy service to tell two jobs apart. Each fixes something and costs something. By stage 5 you will have hit the limit of all of them.</p></div>
<div><h3>Stages 6 to 9: Tenuo warrants</h3><p>A <strong>warrant</strong> is a signed permission that travels with the request: which tools, which argument values, for which agent's key, until when. The control plane signs the first one; agents can only narrow it for the next agent; the code next to each tool checks the whole chain offline. <a href="/lab/stage-6">Stage 6 explains it</a> before you write your first one.</p></div>
</div>

<h2>The stages</h2>
<div class="lab-grid">${cards.join("\n")}</div>
<p class="lab-muted">Stages 1 to 6 are the main event, about ninety minutes. Stages 7 to 9 are extensions for a second sitting. Your progress is kept in this browser, and the links the lab prints keep it in step with your terminal.</p>

<h2>How it is scored</h2>
<div class="lab-grading">${grading.map(([label, pts, note]) => `<div class="lab-grade"><div class="lab-grade-row"><span>${esc(label)}</span><strong>${pts}</strong></div><div class="lab-bar"><div style="width:${pts}%"></div></div><p class="lab-muted">${esc(note)}</p></div>`).join("")}</div>
<p><code>npm run score</code> breaks this down per agent. Speed is not scored, and retries are free.</p>

<h2>The commands</h2>
<pre class="lab-cmd"><code>npm run lab        # start or resume where you left off
npm run attack     # run the rogue behavior and the security checks
npm run score      # your score and why
npm run trace      # every decision, with its reason
npm run audit      # what every agent can currently do
npm run next       # move on to the next stage
npm run reset      # start over from stage 1
npm run share      # write an anonymous score breakdown for your session host
npm run telemetry  # see, turn on, or turn off anonymous progress events</code></pre>
<p class="lab-muted">The first run asks once whether to share anonymous progress with the Tenuo team: stage numbers, scores, which checks did not land. Never your code or your name. If you say no, the lab sends nothing.</p>

<aside class="lab-callout notice"><div class="lab-callout-title">One ground rule</div><p>You will be tempted to fix the agent that misbehaves: filter what it reads, tell it to ignore suspicious instructions, pick a smarter model. This lab sets those aside. Assume the agent will sometimes be fooled, and work on what still holds when it is.</p></aside>

<nav class="lab-nav"><span></span><a class="next" href="/lab/stage-1">Stage 1: One key for everyone →</a></nav>
`;
  return frontMatter({ layout: "lab", title: "Agent Delegation Challenge", description: "Six AI agents, one rogue, nine stages. Change how permissions work until the damage stops and the trip still happens.", lab_stage: 0 }) + body;
}

function wrapUpPage(): string {
  const terms: ReadonlyArray<readonly [string, string]> = [
    ["Ambient authority", "Stage 1. Permission that follows the agent everywhere instead of following the job."],
    ["Identity-based access control", "Stage 2. Permissions attached to who is acting."],
    ["Confused deputy", "Stage 4. An agent with real authority being steered into using it for the wrong job."],
    ["Policy service", "Stage 4. A central place every check has to ask, which is what your fix built, whatever you called it."],
    ["Delegation", "Stage 5. Passing work, and the access for it, to another agent."],
    ["Privilege escalation", "Stage 5. Ending up with more access than you were given."],
    ["Attenuation", "Stage 6. Access that can narrow when it is passed on, and can never widen."],
    ["Capability", "Stage 6. Permission carried by the request rather than looked up about the requester."],
    ["Trust root", "Stage 6. The one key that can sign a fresh permission, and that no agent holds."],
    ["Holder binding", "Stage 7. A permission that only works for whoever it was issued to."],
    ["Prompt injection", "The whole lab. Instructions hidden in data that an agent reads and follows."],
  ];
  const body = `${stepper("wrap")}
<header class="lab-hero"><div class="lab-kicker">After stage 9</div><h1>What you just learned</h1><p class="lab-goal">If you can say this in your own words, the lab worked.</p></header>

<blockquote class="lab-quote">An AI agent sometimes needs to pass work to another agent. The second agent should get only the access that piece of work requires, and it should not be able to give itself or anyone else more access than it received.</blockquote>
<p>And if you got further than that:</p>
<blockquote class="lab-quote">An agent's identity tells you which agent is acting. It does not tell you what that agent was allowed to do for this particular job.</blockquote>
<p>Neither sentence uses a technical term. Here are the terms, now that you have the ideas they attach to.</p>
<table class="lab-terms"><thead><tr><th>Term</th><th>Where you met it</th></tr></thead><tbody>${terms.map(([t, d]) => `<tr><td><strong>${esc(t)}</strong></td><td>${esc(d)}</td></tr>`).join("")}</tbody></table>
<aside class="lab-callout question"><div class="lab-callout-title">One last look</div><p>No one told any agent in this lab to misbehave. Find where the instruction came from, in <code>src/services/flights.ts</code>. It has been sitting there since stage 1, on a departure board your check-in agent reads every time it does its job.</p></aside>
<h2>Going further</h2>
<p>The authorization system you used in stages 6 to 9 is open source at <a href="${REPO_URL}">github.com/tenuo-ai/tenuo</a>. The delegation rules behind it are being written up as an IETF standards draft, which is public and readable. A star on the repository is the main way maintainers find out anyone is using their work.</p>
<nav class="lab-nav"><a class="prev" href="/lab/stage-9">← Stage 9</a><a class="next" href="/lab/stage-10">Stage 10: your first pull request →</a></nav>
`;
  return frontMatter({ layout: "lab", title: "What you just learned", description: "The two sentences the lab was built around, and the terms for them.", lab_stage: 0 }) + body;
}

function stage10Page(): string {
  const body = `${stepper(10)}
<header class="lab-hero"><div class="lab-kicker">Stage 10 of 10 · optional · no score</div><h1>Your first pull request</h1><p class="lab-goal"><strong>Goal.</strong> Take the TypeScript SDK you just spent ninety minutes inside and land one small change in it.</p></header>
<p class="lab-intro">You have been working in a real open-source security project, in the same SDK its maintainers use every day. Most people never get that far before a first contribution. The challenge is to open one.</p>
<h2>Do this</h2>
<ol class="lab-steps">
<li class="lab-step"><label class="lab-step-check"><input type="checkbox" data-key="10:0"><span>1</span></label><div class="lab-step-body"><p>Pick an issue labeled <strong>good first issue</strong>. Most are TypeScript: a runnable example, a test recipe, a clearer error, a cookbook for the constraint helpers you used in stage 6. Each says what done looks like.</p><a class="lab-button" href="${GOOD_FIRST_ISSUES_URL}">Browse good first issues</a></div></li>
<li class="lab-step"><label class="lab-step-check"><input type="checkbox" data-key="10:1"><span>2</span></label><div class="lab-step-body"><p>Comment on the issue so nobody else picks it up at the same time. Then read <code>CONTRIBUTING.md</code>: it tells you how to run the TypeScript checks locally, which is most of the work.</p></div></li>
<li class="lab-step"><label class="lab-step-check"><input type="checkbox" data-key="10:2"><span>3</span></label><div class="lab-step-body"><p>Make the change, run the checks, open the pull request, and say in the description that you ran them.</p></div></li>
</ol>
<aside class="lab-callout notice"><div class="lab-callout-title">What makes a first pull request easy to merge</div><ul><li>Keep it to the one issue. A small change that does exactly what the issue asks beats a large one that does several things.</li><li>Run the checks the contributing guide names, and say that you did.</li><li>If you get stuck, say so on the issue. Maintainers would rather answer a question than review a guess.</li></ul></aside>
<p>Your session host can help you pick one and will tell you how to reach the maintainers if an issue is unclear. A merged pull request on a security project is worth having your name on.</p>
<section class="lab-done"><div><div class="lab-callout-title">Done when</div><p>Your pull request is open.</p></div><button type="button" class="lab-mark" data-mark-done="10">Mark stage 10 done</button></section>
<nav class="lab-nav"><a class="prev" href="/lab/wrap-up">← What you just learned</a><a class="next" href="${REPO_URL}">The repository →</a></nav>
`;
  return frontMatter({ layout: "lab", title: "Stage 10: your first pull request", description: "Optional: contribute to the SDK you just used.", lab_stage: 10 }) + body;
}

function main(): void {
  const check = process.argv.includes("--check");
  const pages = new Map<string, string>();
  pages.set("index.md", indexPage());
  for (const s of STAGES) pages.set(`stage-${s.n}.md`, stagePage(s));
  pages.set("wrap-up.md", wrapUpPage());
  pages.set("stage-10.md", stage10Page());

  if (check) {
    const stale: string[] = [];
    for (const [name, html] of pages) {
      const path = join(DOCS, name);
      if (!existsSync(path) || readFileSync(path, "utf8") !== html) stale.push(name);
    }
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
  console.log(`wrote ${pages.size} pages to ${DOCS}`);
}

main();
