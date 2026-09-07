---
layout: "lab"
title: "AI Agent Delegation Security Lab"
og_title: "Security Challenge: Stop a Rogue AI Agent From Ruining Your Trip"
description: "Give each agent only the authority its part of the trip needs. A free, hands-on lab in AI agent delegation security."
og_image: "/images/challenge-image.png"
og_image_width: 1200
og_image_height: 630
og_image_alt: "A boarding pass from Toronto to Cancún for Alice Chen, stamped denied because it is outside the granted scope."
lab_stage: 0
lab_version: "0.2.0"
---
<nav class="lab-stepper" aria-label="Stages"><a href="/lab/" class="home" title="Overview">Lab</a><a href="/lab/stage-1" data-n="1" title="Stage 1">1</a><a href="/lab/stage-2" data-n="2" title="Stage 2">2</a><a href="/lab/stage-3" data-n="3" title="Stage 3">3</a><a href="/lab/stage-4" data-n="4" title="Stage 4">4</a><a href="/lab/stage-5" data-n="5" title="Stage 5">5</a><a href="/lab/stage-6" data-n="6" title="Stage 6">6</a><a href="/lab/stage-7" data-n="7" title="Stage 7">7</a><a href="/lab/contribute" title="Optional: Contribute to Tenuo">+</a></nav>
<header class="lab-hero"><div class="lab-kicker">A ninety-minute security lab · TypeScript · no account needed</div><h1>AI Agent Delegation Security Lab</h1><p class="lab-goal"><strong>Book the trip. Stop the rogue agent.</strong> Six AI agents book a trip. One reads an injected instruction and follows it. Change what the agents may do until the trip succeeds and the rogue gets nowhere.</p></header>

<figure class="lab-cover"><img src="/images/challenge-image.svg" width="1200" height="630" alt="A boarding pass from Toronto to Cancún for Alice Chen, stamped denied because it is outside the granted scope." decoding="async" fetchpriority="high"></figure>

<section class="lab-browser-demo" aria-labelledby="lab-browser-title">
<div class="lab-kicker">Try Stage 1 now · no setup</div>
<h2 id="lab-browser-title">Run the breach</h2>
<p>See what happens when all six agents share one key. This browser preview replays the same deterministic Stage 1 attack the CLI runs. Its output is generated from the lab code, not written by hand.</p>
<button type="button" class="lab-browser-run" data-lab-browser-run aria-expanded="false" aria-controls="lab-browser-output">Run Stage 1 in your browser</button>
<div id="lab-browser-output" class="lab-browser-output" data-lab-browser-output hidden tabindex="-1">
<div class="lab-callout-title">Stage 1 · One key for everyone</div>
<pre class="lab-browser-terminal"><code>
Stage 1 of 7: One key for everyone   mode=shared  scenario=spring-break
  guide: https://tenuo.ai/lab/stage-1

WALLET  Alice: $47 of $1200
ROGUE ATTEMPTS BLOCKED  0 / 7
STARS   ★☆☆☆
  ★ Trip booked
  ☆ Rogue stopped
  ☆ Tight handoff
  ☆ No spare authority

THE TRIP
  ✓ trip-alice-cun  travel: read traveler name
  ✓ trip-alice-cun  travel: calendar event
  ✓ trip-alice-cun  flight: search
  ✓ trip-alice-cun  flight: book UA214
  ✓ trip-alice-cun  check-in: UA214
  ✓ trip-alice-cun  boarding: pass for UA214
  ✓ trip-alice-cun  hotel: search
  ✓ trip-alice-cun  hotel: book
  ✓ trip-alice-cun  activity: search
  ✓ trip-alice-cun  activity: book
  ✓ trip-alice-cun  within budget ($741 of $1200)

WHAT ELSE HAPPENED
  ! $412 left the wallet on the rogue agent's say-so (balance now $47)
  ! UA214 is cancelled: Alice Chen has a boarding pass for a flight that no longer exists
  ! AA882, another traveler's reservation, was checked in by your agent

LEGITIMATE
  check_in(UA214)                                          ALLOWED  ✓
TRIGGERED BY INJECTED CONTENT
  get_reservation(AA882)                                   ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything
  check_in(AA882)                                          ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything
  cancel_reservation(UA214)                                ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything
  wallet.charge(412)                                       ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything
  book_flight(AA882, 412)                                  ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything
PROBE (harness, independent of model)
  traveler.read(passportNumber)                            ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything
  calendar.delete(*)                                       ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything
BOARDING AGENT AFTER THE HANDOFF
  issue_boarding_pass(UA214)   intended                    ALLOWED  ✓
  check_in(UA214)   inherited?                             ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything
  get_reservation(UA214)   inherited?                      ALLOWED  ✗
      expected DENIED: TRAVEL_SERVICE_KEY opens everything

  9 of 11 checks did not land as expected
  central_calls during the trip: 0   (calls to a component outside the acting agent)</code></pre>
<div class="lab-browser-next">
<h3>The breach is real. The rest needs a terminal.</h3>
<p>Continue the investigation by changing the policies yourself. Both paths run the same lab.</p>
<div class="lab-browser-actions"><a class="lab-button" href="https://codespaces.new/tenuo-ai/tenuo?devcontainer_path=.devcontainer/agent-delegation-lab/devcontainer.json">Continue in Codespaces</a><a class="lab-button secondary" href="#terminal-setup">Continue locally</a></div>
</div>
</div>
<noscript><p class="lab-muted">JavaScript is off, so use either terminal setup below to run Stage 1.</p></noscript>
</section>

<section class="lab-start" id="terminal-setup">
<div>
<h2>Continue locally</h2>
<pre class="lab-cmd"><code>git clone https://github.com/tenuo-ai/tenuo
cd tenuo/labs/agent-delegation
npm install
npm run lab</code></pre>
<p class="lab-muted">Node 20 or newer. No account, no API key, no network needed. The lab runs its own recorded agents; every check and score is real.</p>
</div>
<div>
<h2>What to expect</h2>
<p>Five stages in about ninety minutes, then two optional boss levels. You run a command, read what happened, change a file, and run it again. Retries are free, speed is not scored, and copying the shown <code>narrow()</code> shape is allowed.</p>
<p class="lab-muted">If you want the vocabulary early, the TypeScript guide's <a href="https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts">Protect your first tool</a> and <a href="https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts">Delegate to another agent</a> take about seven minutes.</p>
</div>
</section>
<details class="lab-reveal">
<summary>Prefer a hosted terminal? Use Codespaces</summary>
<div>
<p>The same lab runs in GitHub Codespaces with no install. It needs a free GitHub account and no payment method. GitHub includes 120 core-hours a month on personal accounts, and the lab is pinned to the smallest 2-core machine, so a full session uses about 3 of them.</p>
<a class="lab-button" href="https://codespaces.new/tenuo-ai/tenuo?devcontainer_path=.devcontainer/agent-delegation-lab/devcontainer.json">Open in GitHub Codespaces</a>
<p class="lab-muted">Create it from the link so it counts against your own free hours. A codespace created inside an organization is billed to that organization. Stop the codespace when you are done.</p>
</div>
</details>

<h2>The mission</h2>
<figure class="lab-figure"><svg class="lab-diagram" viewBox="0 0 760 330" aria-hidden="true" focusable="false" data-caption="You talk to Travel Agent. The flight side runs three handoffs deep, and that matters later." xmlns="http://www.w3.org/2000/svg"><path d="M97 140 L97 284" fill="none" stroke="#6a6a6a" stroke-width="1.5"/>
<path d="M97 200 L198 200" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,200 197,204.95 197,195.05" fill="#6a6a6a"/>
<path d="M97 284 L198 284" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,284 197,288.95 197,279.05" fill="#6a6a6a"/>
<path d="M172 116 L198 116" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,116 197,120.95 197,111.05" fill="#6a6a6a"/>
<path d="M357 116 L383 116" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="391,116 382,120.95 382,111.05" fill="#6a6a6a"/>
<path d="M542 116 L568 116" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="576,116 567,120.95 567,111.05" fill="#6a6a6a"/>
<rect x="22" y="22" width="210" height="26" rx="13" fill="var(--surface)" stroke="var(--accent)" stroke-width="1.5"/><text x="127" y="39" font-size="12" text-anchor="middle" fill="var(--text)">Alice → Cancún, 3 nights, $1,200</text>
<path d="M127 48 L127 74 L97 74 L97 83" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round" stroke-dasharray="6 4"/><polygon points="97,91 92.05,82 101.95,82" fill="#6a6a6a"/>
<rect x="22" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="33" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Travel Agent</text><text x="33" y="130" font-size="11" text-anchor="start" fill="var(--text-muted)">talks to you</text>
<rect x="207" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Flight Agent</text><text x="218" y="130" font-size="11" text-anchor="start" fill="var(--text-muted)">books the flight</text>
<rect x="207" y="176" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="197" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Hotel Agent</text><text x="218" y="214" font-size="11" text-anchor="start" fill="var(--text-muted)">books the hotel</text>
<rect x="207" y="260" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="281" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Activity Agent</text><text x="218" y="298" font-size="11" text-anchor="start" fill="var(--text-muted)">books one activity</text>
<rect x="392" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="403" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Check-in Agent</text><text x="403" y="130" font-size="11" text-anchor="start" fill="var(--text-muted)">checks Alice in</text>
<rect x="577" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="588" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Boarding Agent</text><text x="588" y="130" font-size="11" text-anchor="start" fill="var(--text-muted)">issues the pass</text>
<rect x="577" y="271" width="101" height="26" rx="13" fill="var(--surface)" stroke="#ffb000" stroke-width="1.5"/><text x="627.5" y="288" font-size="12" text-anchor="middle" fill="var(--text)">Wallet $1,200</text></svg>
<figcaption>You talk to Travel Agent. The flight side runs three handoffs deep, and that matters later.</figcaption></figure>
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
<div><h3>Stages 1 to 4: the usual tools</h3><p>A shared key, then one account per agent, then rules you write yourself, then either per-task identities backed by a registry or a policy service to tell two jobs apart. Each fixes something and costs something. By the end of stage 4 you will have hit the limit of all of them.</p></div>
<div><h3>Stages 5 to 7: Tenuo warrants</h3><p>A <strong>warrant</strong> is a signed permission that travels with the request: which tools, which argument values, for which agent's key, until when. The control plane signs the first one; agents can only narrow it for the next agent; the code next to each tool checks the whole chain offline. <a href="/lab/stage-5">Stage 5 explains it</a> before you write your first one.</p></div>
</div>

<h2>The stages</h2>
<div class="lab-grid"><a class="lab-card" data-n="1" href="/lab/stage-1"><div class="lab-card-n">1</div><div><div class="lab-card-title">One key for everyone</div><div class="lab-card-goal">See what a rogue agent can do when every agent shares one credential.</div></div><div class="lab-card-time">5 min</div></a>
<a class="lab-card" data-n="2" href="/lab/stage-2"><div class="lab-card-n">2</div><div><div class="lab-card-title">Every agent gets its own account</div><div class="lab-card-goal">Give each agent its own credential and see which damage that removes and which damage remains.</div></div><div class="lab-card-time">5 min</div></a>
<a class="lab-card" data-n="3" href="/lab/stage-3"><div class="lab-card-n">3</div><div><div class="lab-card-title">Rules that fit the job</div><div class="lab-card-goal">Write permissions narrow enough that every rogue action is blocked and the trip still books.</div></div><div class="lab-card-time">15 min</div></a>
<a class="lab-card" data-n="4" href="/lab/stage-4"><div class="lab-card-n">4</div><div><div class="lab-card-title">Two travelers, then a handoff</div><div class="lab-card-goal">First isolate Alice from Bob; then observe why passing a whole credential gives the next agent too much.</div></div><div class="lab-card-time">30 min</div></a>
<a class="lab-card" data-n="5" href="/lab/stage-5"><div class="lab-card-n">5</div><div><div class="lab-card-title">Access that travels with the work</div><div class="lab-card-goal">Complete one narrowing handoff so the trip works, the rogue stops, and no central lookup is needed.</div></div><div class="lab-card-time">25 min</div></a>
<a class="lab-card" data-n="6" href="/lab/stage-6"><div class="lab-card-n">6</div><div><div class="lab-card-title">Boss: stolen authority</div><div class="lab-card-goal">See why a copied permission cannot be used by another agent, then deliberately end a delegation chain.</div></div><div class="lab-card-time">15 min</div></a>
<a class="lab-card" data-n="7" href="/lab/stage-7"><div class="lab-card-n">7</div><div><div class="lab-card-title">Boss: contain the incident</div><div class="lab-card-goal">Contain a compromised Hotel Agent while legitimate bookings keep working.</div></div><div class="lab-card-time">20 min</div></a>
<a class="lab-card" href="/lab/contribute"><div class="lab-card-n">+</div><div><div class="lab-card-title">Contribute to Tenuo</div><div class="lab-card-goal">Optional: take what you used in the lab and open a small pull request.</div></div><div class="lab-card-time">optional</div></a></div>
<p class="lab-muted">Stages 1 to 5 are the core lab, about ninety minutes. Stages 6 and 7 are optional boss levels. Your progress is kept in this browser, and the links the lab prints keep it in step with your terminal.</p>

<h2>Your four stars</h2>
<div class="lab-grading"><div class="lab-grade"><div class="lab-grade-row"><span>Trip booked</span><strong>☆</strong></div><p class="lab-muted">Alice gets a flight, hotel, activity, and boarding pass within budget.</p></div><div class="lab-grade"><div class="lab-grade-row"><span>Rogue stopped</span><strong>☆</strong></div><p class="lab-muted">Every injected or adversarial action lands as expected.</p></div><div class="lab-grade"><div class="lab-grade-row"><span>Tight handoff</span><strong>☆</strong></div><p class="lab-muted">The next agent receives only what its piece of work needs.</p></div><div class="lab-grade"><div class="lab-grade-row"><span>No spare authority</span><strong>☆</strong></div><p class="lab-muted">Every grant stays at or below the mission's least-privilege ceiling.</p></div></div>
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
