---
layout: "lab"
title: "Agent Delegation Challenge"
description: "Six AI agents, one rogue, nine stages. Change how permissions work until the damage stops and the trip still happens."
lab_stage: 0
---
<nav class="lab-stepper" aria-label="Stages"><a href="/lab/" class="home" title="Overview">Lab</a><a href="/lab/stage-1" data-n="1" title="Stage 1">1</a><a href="/lab/stage-2" data-n="2" title="Stage 2">2</a><a href="/lab/stage-3" data-n="3" title="Stage 3">3</a><a href="/lab/stage-4" data-n="4" title="Stage 4">4</a><a href="/lab/stage-5" data-n="5" title="Stage 5">5</a><a href="/lab/stage-6" data-n="6" title="Stage 6">6</a><a href="/lab/stage-7" data-n="7" title="Stage 7">7</a><a href="/lab/stage-8" data-n="8" title="Stage 8">8</a><a href="/lab/stage-9" data-n="9" title="Stage 9">9</a><a href="/lab/stage-10" data-n="10" title="Stage 10">10</a></nav>
<header class="lab-hero"><div class="lab-kicker">A ninety-minute lab · TypeScript · nothing to sign up for</div><h1>AI Agent Delegation Challenge</h1><p class="lab-goal">Six AI agents book a trip. One of them reads an instruction it should not follow. You change how permissions work, stage by stage, until the damage stops and the trip still happens.</p></header>

<section class="lab-start">
<div>
<h2>Start</h2>
<pre class="lab-cmd"><code>git clone https://github.com/tenuo-ai/tenuo
cd tenuo/labs/agent-delegation
npm install
npm run lab</code></pre>
<p class="lab-muted">Node 20 or newer. No account, no API key, no network needed. The lab runs its own recorded agents; every check and score is real.</p>
</div>
<div>
<h2>Or in the browser</h2>
<a class="lab-button" href="https://codespaces.new/tenuo-ai/tenuo?devcontainer_path=.devcontainer/agent-delegation-lab/devcontainer.json">Open in GitHub Codespaces</a>
<p class="lab-muted">One click, nothing to install, same lab. Needs a free GitHub account.</p>
<h3>Ten minutes of prep</h3>
<ul class="lab-prep">
<li>Read <a href="https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts">Protect your first tool</a> and <a href="https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts">Delegate to another agent</a> in the TypeScript guide.</li>
<li>Read <a href="https://github.com/tenuo-ai/tenuo#how-it-works">How it works</a> in the main README. Skip everything else.</li>
</ul>
</div>
</section>

<h2>The mission</h2>
<figure class="lab-figure"><svg class="lab-diagram" viewBox="0 0 760 362" role="img" aria-label="You talk to Travel Agent. The flight side runs three handoffs deep, which turns out to matter a great deal." xmlns="http://www.w3.org/2000/svg"><path d="M100 144 L100 288" fill="none" stroke="#5a5a5a" stroke-width="1.5"/><path d="M100 204 L215 204" fill="none" stroke="#5a5a5a" stroke-width="1.5"/><polygon points="215,204 207,199 207,209" fill="#5a5a5a"/><path d="M100 288 L215 288" fill="none" stroke="#5a5a5a" stroke-width="1.5"/><polygon points="215,288 207,283 207,293" fill="#5a5a5a"/><path d="M170 120 L215 120" fill="none" stroke="#5a5a5a" stroke-width="1.5"/><polygon points="215,120 207,115 207,125" fill="#5a5a5a"/><path d="M355 120 L400 120" fill="none" stroke="#5a5a5a" stroke-width="1.5"/><polygon points="400,120 392,115 392,125" fill="#5a5a5a"/><path d="M540 120 L585 120" fill="none" stroke="#5a5a5a" stroke-width="1.5"/><polygon points="585,120 577,115 577,125" fill="#5a5a5a"/><rect x="30" y="24" width="239.6" height="26" rx="13" fill="var(--surface)" stroke="var(--accent)" stroke-width="1.5"/><text x="149.8" y="41" font-size="12" text-anchor="middle" fill="var(--text)">Alice → Cancún, 3 nights, $1,200</text><path d="M90 50 L130 96" fill="none" stroke="#5a5a5a" stroke-width="1.5" stroke-dasharray="3 3"/><rect x="30" y="96" width="140" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="42" y="117" font-size="13" font-weight="600" fill="var(--text)">Travel Agent</text><text x="42" y="134" font-size="11" fill="var(--text-muted)">talks to you</text><rect x="215" y="96" width="140" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="227" y="117" font-size="13" font-weight="600" fill="var(--text)">Flight Agent</text><text x="227" y="134" font-size="11" fill="var(--text-muted)">books the flight</text><rect x="215" y="180" width="140" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="227" y="201" font-size="13" font-weight="600" fill="var(--text)">Hotel Agent</text><text x="227" y="218" font-size="11" fill="var(--text-muted)">books the hotel</text><rect x="215" y="264" width="140" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="227" y="285" font-size="13" font-weight="600" fill="var(--text)">Activity Agent</text><text x="227" y="302" font-size="11" fill="var(--text-muted)">books one activity</text><rect x="400" y="96" width="140" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="412" y="117" font-size="13" font-weight="600" fill="var(--text)">Check-in Agent</text><text x="412" y="134" font-size="11" fill="var(--text-muted)">checks Alice in</text><rect x="585" y="96" width="140" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="597" y="117" font-size="13" font-weight="600" fill="var(--text)">Boarding Agent</text><text x="597" y="134" font-size="11" fill="var(--text-muted)">issues the pass</text><rect x="585" y="274" width="110.39999999999999" height="26" rx="13" fill="var(--surface)" stroke="#ffb000" stroke-width="1.5"/><text x="640.2" y="291" font-size="12" text-anchor="middle" fill="var(--text)">Wallet $1,200</text><text x="380" y="354" font-size="12" text-anchor="middle" fill="var(--text-muted)">You talk to Travel Agent. The flight side runs three handoffs deep, which turns out to matter a great deal.</text></svg></figure>
<div class="lab-mission">
<table><tbody>
<tr><th>Traveler</th><td>Alice Chen</td><th>Budget</th><td>$1,200 total</td></tr>
<tr><th>From</th><td>Toronto (YYZ)</td><th>Flight</th><td>up to $300</td></tr>
<tr><th>To</th><td>Cancún (CUN)</td><th>Hotel</th><td>3 nights, up to $200 a night</td></tr>
<tr><th>Arrive</th><td>Friday evening</td><th>Activity</th><td>at least one, up to $200</td></tr>
</tbody></table>
<p>Watch the wallet in the output. It starts at $1,200. When it moves, something happened.</p>
</div>

<h2>The stages</h2>
<div class="lab-grid"><a class="lab-card" data-n="1" href="/lab/stage-1"><div class="lab-card-n">1</div><div><div class="lab-card-title">One key for everyone</div><div class="lab-card-goal">See what a rogue agent can do when every agent shares one credential.</div></div><div class="lab-card-time">5 min</div></a>
<a class="lab-card" data-n="2" href="/lab/stage-2"><div class="lab-card-n">2</div><div><div class="lab-card-title">Every agent gets its own account</div><div class="lab-card-goal">Give each agent its own credential and see how much damage that removes, and how much it does not.</div></div><div class="lab-card-time">5 min</div></a>
<a class="lab-card" data-n="3" href="/lab/stage-3"><div class="lab-card-n">3</div><div><div class="lab-card-title">Rules that fit the job</div><div class="lab-card-goal">Write the permissions yourself, narrow enough that every rogue action is blocked and the trip still books.</div></div><div class="lab-card-time">15 min</div></a>
<a class="lab-card" data-n="4" href="/lab/stage-4"><div class="lab-card-n">4</div><div><div class="lab-card-title">A second traveler shows up</div><div class="lab-card-goal">Get Bob's trip working alongside Alice's without letting either trip's agent touch the other's reservation, and see what that fix costs.</div></div><div class="lab-card-time">25 min</div></a>
<a class="lab-card" data-n="5" href="/lab/stage-5"><div class="lab-card-n">5</div><div><div class="lab-card-title">Passing the work along</div><div class="lab-card-goal">Watch a handoff give the receiving agent more than it needed, then decide what a central service should do when asked for more.</div></div><div class="lab-card-time">10 min</div></a>
<a class="lab-card" data-n="6" href="/lab/stage-6"><div class="lab-card-n">6</div><div><div class="lab-card-title">Access that travels with the work</div><div class="lab-card-goal">Switch to Tenuo, complete the chain, and get the trip, the cross-task checks, and the escalation attempt all handled with no policy file and no central lookup.</div></div><div class="lab-card-time">25 min</div></a>
<a class="lab-card" data-n="7" href="/lab/stage-7"><div class="lab-card-n">7</div><div><div class="lab-card-title">Someone stole a permission</div><div class="lab-card-goal">See that a valid, unexpired, correctly scoped permission is useless to anyone it was not issued to.</div></div><div class="lab-card-time">5 min</div></a>
<a class="lab-card" data-n="8" href="/lab/stage-8"><div class="lab-card-n">8</div><div><div class="lab-card-title">How far can this travel?</div><div class="lab-card-goal">Make one hop the end of the line and watch the chain stop where the <em>previous</em> agent decided it would.</div></div><div class="lab-card-time">10 min</div></a>
<a class="lab-card" data-n="9" href="/lab/stage-9"><div class="lab-card-n">9</div><div><div class="lab-card-title">The incident</div><div class="lab-card-goal">Hotel Agent is compromised. Keep the system online and legitimate bookings working: one attempt must succeed, seven must fail.</div></div><div class="lab-card-time">20 min</div></a>
<a class="lab-card" data-n="10" href="/lab/stage-10"><div class="lab-card-n">10</div><div><div class="lab-card-title">Your first pull request</div><div class="lab-card-goal">Optional. Take what you just used and contribute to it.</div></div><div class="lab-card-time">open</div></a></div>
<p class="lab-muted">Stages 1 to 6 are the main event, about ninety minutes. Stages 7 to 9 are extensions for a second sitting. Your progress is kept in this browser, and the links the lab prints keep it in step with your terminal.</p>

<h2>How it is scored</h2>
<div class="lab-grading"><div class="lab-grade"><div class="lab-grade-row"><span>The trip completes correctly</span><strong>25</strong></div><div class="lab-bar"><div style="width:25%"></div></div><p class="lab-muted">The gate. If Alice does not get a flight, a hotel, an activity, and a boarding pass within budget, nothing else counts.</p></div><div class="lab-grade"><div class="lab-grade-row"><span>Unauthorized actions are blocked</span><strong>30</strong></div><div class="lab-bar"><div style="width:30%"></div></div><p class="lab-muted">Everything the rogue agent tries.</p></div><div class="lab-grade"><div class="lab-grade-row"><span>Handoffs pass along only what's needed</span><strong>25</strong></div><div class="lab-bar"><div style="width:25%"></div></div><p class="lab-muted">What Boarding Agent can do after Check-in Agent hands it the job.</p></div><div class="lab-grade"><div class="lab-grade-row"><span>You didn't grant more than the job required</span><strong>20</strong></div><div class="lab-bar"><div style="width:20%"></div></div><p class="lab-muted">Compared against the mission, not against hindsight. A $300 ceiling for a $286 flight is full marks.</p></div></div>
<p><code>npm run score</code> breaks this down per agent. Speed is not scored. Retries are free.</p>

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
<p class="lab-muted">The first run asks once whether to share anonymous progress with the Tenuo team: stage numbers, scores, which checks did not land. Never your code or your name. Say no and nothing is ever sent.</p>

<aside class="lab-callout notice"><div class="lab-callout-title">One ground rule</div><p>You will be tempted to fix the agent that misbehaves: filter what it reads, tell it to ignore suspicious instructions, pick a smarter model. None of that is what this lab is about. Assume the agent will sometimes be fooled. The question is what still holds when it is.</p></aside>

<nav class="lab-nav"><span></span><a class="next" href="/lab/stage-1">Stage 1: One key for everyone →</a></nav>
