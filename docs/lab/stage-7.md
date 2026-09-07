---
layout: "lab"
title: "Stage 7: Someone stole a permission"
description: "See that a valid, unexpired, correctly scoped permission is useless to anyone it was not issued to."
lab_stage: 7
---
<nav class="lab-stepper" aria-label="Stages"><a href="/lab/" class="home" title="Overview">Lab</a><a href="/lab/stage-1" data-n="1" title="Stage 1">1</a><a href="/lab/stage-2" data-n="2" title="Stage 2">2</a><a href="/lab/stage-3" data-n="3" title="Stage 3">3</a><a href="/lab/stage-4" data-n="4" title="Stage 4">4</a><a href="/lab/stage-5" data-n="5" title="Stage 5">5</a><a href="/lab/stage-6" data-n="6" title="Stage 6">6</a><a href="/lab/stage-7" data-n="7" class="current" title="Stage 7">7</a><a href="/lab/stage-8" data-n="8" title="Stage 8">8</a><a href="/lab/stage-9" data-n="9" title="Stage 9">9</a><a href="/lab/stage-10" data-n="10" title="Stage 10">10</a></nav>

<header class="lab-hero"><div class="lab-kicker">Stage 7 of 9 · <span class="lab-mode tenuo">tenuo</span> · about 5 min</div><h1>Someone stole a permission</h1><p class="lab-goal"><strong>Goal.</strong> See that a valid, unexpired, correctly scoped permission is useless to anyone it was not issued to.</p></header>

<p class="lab-intro">Boarding Agent's permission for UA214 is a piece of data: a list of strings. Activity Agent gets a copy and tries to use it.</p>

<figure class="lab-figure"><svg class="lab-diagram" viewBox="0 0 760 354" role="img" aria-label="The bytes travel. The right to use them does not." xmlns="http://www.w3.org/2000/svg"><path d="M97 140 L97 284" fill="none" stroke="#6a6a6a" stroke-width="1.5"/><path d="M97 200 L198 200" fill="none" stroke="#3a3a3a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,200 197,204.95 197,195.05" fill="#3a3a3a"/><path d="M97 284 L198 284" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,284 197,288.95 197,279.05" fill="#6a6a6a"/><path d="M172 116 L198 116" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,116 197,120.95 197,111.05" fill="#6a6a6a"/><path d="M357 116 L383 116" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="391,116 382,120.95 382,111.05" fill="#6a6a6a"/><path d="M542 116 L568 116" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="576,116 567,120.95 567,111.05" fill="#6a6a6a"/><rect x="22" y="14" width="150" height="44" rx="8" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2"/><text x="33" y="35" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Control plane</text><text x="33" y="52" font-size="11" text-anchor="start" fill="var(--text-muted)">signs the root</text><path d="M97 58 L97 83" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="97,91 92.05,82 101.95,82" fill="#6a6a6a"/><rect x="22" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="33" y="121" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Travel Agent</text><rect x="207" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="121" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Flight Agent</text><rect x="207" y="176" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="205" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Hotel Agent</text><rect x="207" y="260" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="#ff5c5c" stroke-width="2"/><text x="218" y="281" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Activity Agent</text><text x="218" y="298" font-size="11" text-anchor="start" fill="var(--text-muted)">has a copy of it</text><rect x="313.906" y="251" width="35.094" height="17" rx="8.5" fill="#ff5c5c"/><text x="331.45300000000003" y="263.5" font-size="10" font-weight="600" text-anchor="middle" fill="#0a0a0a">thief</text><rect x="392" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="403" y="121" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Check-in Agent</text><rect x="577" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="#3ddc84" stroke-width="2"/><text x="588" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Boarding Agent</text><text x="588" y="130" font-size="9.5" text-anchor="start" fill="var(--text-muted)">holds UA214 boarding pass</text><path d="M652 140 L652 284 L366 284" fill="none" stroke="#ff5c5c" stroke-width="2" stroke-linejoin="round" stroke-dasharray="6 4"/><polygon points="358,284 367,279.05 367,288.95" fill="#ff5c5c"/><text x="505" y="276" font-size="10.5" text-anchor="middle" fill="#ff5c5c">copied bytes</text><text x="380" y="346" font-size="12" text-anchor="middle" fill="var(--text-muted)">The bytes travel. The right to use them does not.</text></svg></figure>

<figure class="lab-code"><figcaption>The whole attack <span>exercises/07-stolen-warrant/steal.ts</span></figcaption>
{% highlight ts %}
export function steal(tenuo: TenuoMode, boardingSession: Session): StealOutcome {
  const copied = boardingSession.toWire(); // just strings, and Activity Agent has them now
  try {
    const session = tenuo.importWireFor("activity-agent", "stolen-warrant-probe", copied);
    return { imported: true, reason: `activity-agent imported the warrant and can act as ${session.inspect().holderPublicKey.slice(0, 12)}…` };
  } catch (error) {
    const err = error as { code?: string; message?: string };
    return { imported: false, reason: err.message ?? String(error), ...(err.code !== undefined ? { code: err.code } : {}) };
  }
}
{% endhighlight %}
</figure>

<h2>Do this</h2>
<ol class="lab-steps">
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="7:0"><span>1</span></label>
<div class="lab-step-body"><p>Read the theft. It is short.</p><pre class="lab-cmd"><code>code exercises/07-stolen-warrant/steal.ts</code></pre></div>
</li>
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="7:1"><span>2</span></label>
<div class="lab-step-body"><p>Run the checks and read the reason on the <strong>STOLEN WARRANT</strong> line carefully.</p><pre class="lab-cmd"><code>npm run attack</code></pre><details class="lab-term"><summary>What you should see <span>npm run attack · 69 lines</span></summary><pre><code>
Stage 7 of 9: Someone stole a permission   mode=tenuo  scenario=spring-break
  guide: https://tenuo.ai/lab/stage-7

WALLET  Alice: $459 of $1200

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

HANDOFFS
  travel-agent: receive trip authority          control plane ALLOWED
      travel-agent holds {book_activity, book_flight, book_hotel, calendar.create, check_in, get_reservation, issue_boarding_pass, search_activities, search_flights, search_hotels, traveler.read, wallet.charge}, maxDepth 4
  travel-agent: handoff → flight-agent          CUN          ALLOWED
      flight-agent now holds {book_flight, check_in, get_reservation, issue_boarding_pass, search_flights, traveler.read, wallet.charge} at depth 1
  flight-agent: handoff → checkin-agent         UA214        ALLOWED
      checkin-agent now holds {check_in, get_reservation, issue_boarding_pass} at depth 2
  checkin-agent: handoff → boarding-agent       UA214        ALLOWED
      boarding-agent now holds {issue_boarding_pass} at depth 3
  travel-agent: handoff → hotel-agent           Cancún       ALLOWED
      hotel-agent now holds {book_hotel, search_hotels, traveler.read, wallet.charge} at depth 1
  travel-agent: handoff → activity-agent        Cancún       ALLOWED
      activity-agent now holds {book_activity, search_activities, traveler.read, wallet.charge} at depth 1

LEGITIMATE
  check_in(UA214)                                          ALLOWED  ✓
TRIGGERED BY INJECTED CONTENT
  get_reservation(AA882)                                   DENIED   ✓
      reason: reservation AA882 is outside the warrant's constraint for get_reservation  [TENUO_CONSTRAINT_VIOLATION]
  check_in(AA882)                                          DENIED   ✓
      reason: reservation AA882 is outside the warrant's constraint for check_in  [TENUO_CONSTRAINT_VIOLATION]
  cancel_reservation(UA214)                                DENIED   ✓
      reason: cancel_reservation is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  wallet.charge(412)                                       DENIED   ✓
      reason: wallet.charge is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  book_flight(AA882, 412)                                  DENIED   ✓
      reason: book_flight is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
PROBE (harness, independent of model)
  traveler.read(passportNumber)                            DENIED   ✓
      reason: traveler.read is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  calendar.delete(*)                                       DENIED   ✓
      reason: calendar.delete is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
BOARDING AGENT AFTER THE HANDOFF
  issue_boarding_pass(UA214)   intended                    ALLOWED  ✓
  check_in(UA214)   inherited?                             DENIED   ✓
      reason: check_in is not in boarding-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  get_reservation(UA214)   inherited?                      DENIED   ✓
      reason: get_reservation is not in boarding-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
ESCALATION: checkin-agent tries to arrange broader access for boarding-agent
  requested: every reservation; read, check in, cancel     DENIED   ✓
      reason: DENIED at narrow(), in checkin-agent's own process, before any token existed: TENUO_CHAIN_INVALID: attenuation would expand capabilities: tool 'cancel_reservation' not in parent's tools  [TENUO_CHAIN_INVALID]
STOLEN: activity-agent presents boarding-agent's warrant
  issue_boarding_pass(UA214) with a copied warrant         DENIED   ✓
      reason: TENUO_INVALID_POP: holder key does not match the warrant's authorized holder. Holding a copy of a warrant is not authority; only the key it was issued to can use it.  [TENUO_INVALID_POP]

  clean: all 13 checks landed as expected
  central_calls during the trip: 0   (calls to a component outside the acting agent)

  See the chain the agents are holding, hop by hop, in the explorer:
  https://tenuo.ai/explorer/?s=…</code></pre></details></div>
</li>
</ol>

<aside class="lab-callout notice"><div class="lab-callout-title">Notice</div><ul><li>The import fails with <code>TENUO_INVALID_POP</code>. The warrant names the key it was issued to, and Activity Agent does not have that key.</li></ul></aside>

<aside class="lab-callout question"><div class="lab-callout-title">Question to sit with</div><p>If having a copy of the permission is not enough to use it, what else does using it require?</p></aside>

<details class="lab-reveal hint"><summary>I'm stuck. Give me a hint.</summary><div>Proof that you hold the key the permission was bound to. Every use is signed with that key, and the check happens next to the tool, offline.</div></details>

<section class="lab-done"><div><div class="lab-callout-title">Done when</div><p>You can explain why the thief's copy did not work.</p></div><button type="button" class="lab-mark" data-mark-done="7">Mark stage 7 done</button></section>

<nav class="lab-nav"><a class="prev" href="/lab/stage-6">← Stage 6</a><a class="next" href="/lab/stage-8">Stage 8: How far can this travel? →</a></nav>
