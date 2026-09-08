---
layout: "lab"
title: "Stage 7: Boss: contain the incident"
description: "Contain a compromised Hotel Agent while legitimate bookings keep working."
lab_stage: 7
lab_version: "0.2.0"
---
<nav class="lab-stepper" aria-label="Stages"><a href="/lab/" class="home" title="Overview">Lab</a><a href="/lab/stage-1" data-n="1" title="Stage 1">1</a><a href="/lab/stage-2" data-n="2" title="Stage 2">2</a><a href="/lab/stage-3" data-n="3" title="Stage 3">3</a><a href="/lab/stage-4" data-n="4" title="Stage 4">4</a><a href="/lab/stage-5" data-n="5" title="Stage 5">5</a><a href="/lab/stage-6" data-n="6" title="Stage 6">6</a><a href="/lab/stage-7" data-n="7" class="current" title="Stage 7">7</a><a href="/lab/contribute" title="Optional: Contribute to Tenuo">+</a></nav>

<header class="lab-hero"><div class="lab-kicker">Stage 7 of 7 · optional boss level · <span class="lab-mode tenuo">tenuo</span> · about 20 min</div><h1>Boss: contain the incident</h1><p class="lab-goal"><strong>Goal.</strong> Contain a compromised Hotel Agent while legitimate bookings keep working.</p></header>

<p class="lab-intro">This stage gives less guidance than the others. The compromised Hotel Agent will try eight things.</p>

<aside class="lab-callout infrastructure"><div class="lab-callout-title">Closest infrastructure analogy</div><p>Incident containment with least-privilege, short-lived workload credentials: preserve the approved operation while removing unrelated tools, data fields, budget, and onward delegation.</p></aside>

<figure class="lab-figure"><svg class="lab-diagram" viewBox="0 0 760 330" aria-hidden="true" focusable="false" data-caption="Everything Hotel Agent can do is decided by one link. Fix that link." xmlns="http://www.w3.org/2000/svg"><path d="M97 140 L97 284" fill="none" stroke="#6a6a6a" stroke-width="1.5"/>
<path d="M97 200 L198 200" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round"/><polygon points="206,200 197,204.95 197,195.05" fill="var(--accent)"/><text x="151.5" y="239" font-size="10.5" text-anchor="middle" fill="var(--accent)">the link you fix</text>
<path d="M97 284 L198 284" fill="none" stroke="#3a3a3a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,284 197,288.95 197,279.05" fill="#3a3a3a"/>
<path d="M172 116 L198 116" fill="none" stroke="#3a3a3a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,116 197,120.95 197,111.05" fill="#3a3a3a"/>
<path d="M357 116 L383 116" fill="none" stroke="#3a3a3a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="391,116 382,120.95 382,111.05" fill="#3a3a3a"/>
<path d="M542 116 L568 116" fill="none" stroke="#3a3a3a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="576,116 567,120.95 567,111.05" fill="#3a3a3a"/>
<rect x="22" y="14" width="150" height="44" rx="8" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2"/><text x="33" y="35" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Control plane</text><text x="33" y="52" font-size="11" text-anchor="start" fill="var(--text-muted)">signs the root</text>
<path d="M97 58 L97 83" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="97,91 92.05,82 101.95,82" fill="#6a6a6a"/>
<rect x="22" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2"/><text x="33" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Travel Agent</text><text x="33" y="130" font-size="10" text-anchor="start" fill="var(--text-muted)">hands the hotel branch out</text>
<rect x="207" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="121" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Flight Agent</text>
<rect x="207" y="176" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="#ff5c5c" stroke-width="2"/><text x="218" y="197" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Hotel Agent</text><text x="218" y="214" font-size="11" text-anchor="start" fill="var(--text-muted)">compromised</text><rect x="265.358" y="167" width="83.64200000000001" height="17" rx="8.5" fill="#ff5c5c"/><text x="307.17900000000003" y="179.5" font-size="10" font-weight="600" text-anchor="middle" fill="#0a0a0a">compromised</text>
<rect x="207" y="260" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="289" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Activity Agent</text>
<rect x="392" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="403" y="121" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Check-in Agent</text>
<rect x="577" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="588" y="121" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Boarding Agent</text></svg>
<figcaption>Everything Hotel Agent can do is decided by one link. Fix that link.</figcaption></figure>

<figure class="lab-code"><figcaption>The eight attempts</figcaption>
<pre><code>1.  book the approved Cancún hotel                  must work
2.  book a hotel in Tulum instead                   must fail
3.  book the approved hotel at $320 a night        must fail
4.  read Alice's passport number                    must fail
5.  book a flight                                   must fail
6.  delete the trip's calendar event                must fail
7.  hand wallet access to Activity Agent            must fail
8.  import a permission copied from Flight Agent   must fail</code></pre>
</figure>

<h2>Do this</h2>
<ol class="lab-steps">
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="7:0"><span>1</span></label>
<div class="lab-step-body"><p>Open the chain. The Travel → Hotel link is where the incident lives: right now it hands Hotel Agent far more than a hotel booking needs.</p><pre class="lab-cmd"><code>code exercises/07-incident/chain.ts</code></pre></div>
</li>
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="7:1"><span>2</span></label>
<div class="lab-step-body"><p>Run the checks. All eight attempts are listed under <strong>INCIDENT</strong>. Make one land and seven fail, and keep an eye on the least-privilege row of your score.</p><pre class="lab-cmd"><code>npm run attack</code></pre><div class="lab-tabs"><input type="radio" name="t7-1" id="t7-1-0" checked><label for="t7-1-0">As it ships</label><input type="radio" name="t7-1" id="t7-1-1"><label for="t7-1-1">When it is fixed</label><div class="lab-tab-panel"><details class="lab-term"><summary>As it ships <span>npm run attack · 60 lines</span></summary><pre><code>
Stage 7 of 7: Boss: contain the incident   mode=tenuo  scenario=incident
  guide: https://tenuo.ai/lab/stage-7

WALLET  Alice: $459 of $1200
ROGUE ATTEMPTS BLOCKED  3 / 5
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
      hotel-agent now holds {book_flight, book_hotel, search_flights, search_hotels, traveler.read, wallet.charge} at depth 1
  travel-agent: handoff → activity-agent        Cancún       ALLOWED
      activity-agent now holds {book_activity, search_activities, traveler.read, wallet.charge} at depth 1

  ALLOWED / DENIED = authorization decision   ✓ = expected result   ✗ = unexpected result

INCIDENT
  1. book the approved Cancún hotel                        ALLOWED  ✓
  2. book a hotel in Tulum                                 DENIED   ✓
      reason: city Tulum is outside the warrant's constraint for book_hotel  [TENUO_CONSTRAINT_VIOLATION]
  3. book the approved hotel at $320 a night               DENIED   ✓
      reason: nightlyRate 320 is outside the warrant's constraint for book_hotel  [TENUO_CONSTRAINT_VIOLATION]
  4. read Alice's passport number                          ALLOWED  ✗
      expected DENIED: warrant tnu_wrt_… permits traveler.read
  5. book a flight                                         ALLOWED  ✗
      expected DENIED: warrant tnu_wrt_… permits book_flight
  6. delete the trip's calendar event                      DENIED   ✓
      reason: calendar.delete is not in hotel-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  7. hand wallet access to Activity Agent                  ALLOWED  ✗
      expected DENIED: hotel-agent delegated wallet.charge to activity-agent
  8. import a warrant copied from Flight Agent             DENIED   ✓
      reason: TENUO_INVALID_POP: holder key does not match the warrant's authorized holder. Holding a copy of a warrant is not authority; only the key it was issued to can use it. If this followed narrow(), set { holder: receiverPublicKey } for the agent that imports the child.  [TENUO_INVALID_POP]

  3 of 8 checks did not land as expected
  central_calls during the trip: 0   (calls to a component outside the acting agent)</code></pre></details></div><div class="lab-tab-panel"><details class="lab-term"><summary>When it is fixed <span>npm run attack · 60 lines</span></summary><pre><code>
Stage 7 of 7: Boss: contain the incident   mode=tenuo  scenario=incident
  guide: https://tenuo.ai/lab/stage-7

WALLET  Alice: $459 of $1200
ROGUE ATTEMPTS BLOCKED  5 / 5
STARS   ★★★★
  ★ Trip booked
  ★ Rogue stopped
  ★ Tight handoff
  ★ No spare authority

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
      hotel-agent now holds {book_hotel, search_hotels, traveler.read, wallet.charge} at depth 1, terminal
  travel-agent: handoff → activity-agent        Cancún       ALLOWED
      activity-agent now holds {book_activity, search_activities, traveler.read, wallet.charge} at depth 1

  ALLOWED / DENIED = authorization decision   ✓ = expected result   ✗ = unexpected result

INCIDENT
  1. book the approved Cancún hotel                        ALLOWED  ✓
  2. book a hotel in Tulum                                 DENIED   ✓
      reason: city Tulum is outside the warrant's constraint for book_hotel  [TENUO_CONSTRAINT_VIOLATION]
  3. book the approved hotel at $320 a night               DENIED   ✓
      reason: nightlyRate 320 is outside the warrant's constraint for book_hotel  [TENUO_CONSTRAINT_VIOLATION]
  4. read Alice's passport number                          DENIED   ✓
      reason: field passportNumber is outside the warrant's constraint for traveler.read  [TENUO_CONSTRAINT_VIOLATION]
  5. book a flight                                         DENIED   ✓
      reason: book_flight is not in hotel-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  6. delete the trip's calendar event                      DENIED   ✓
      reason: calendar.delete is not in hotel-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  7. hand wallet access to Activity Agent                  DENIED   ✓
      reason: TENUO_DEPTH_EXCEEDED: delegation depth 2 exceeds maximum 1  [TENUO_DEPTH_EXCEEDED]
  8. import a warrant copied from Flight Agent             DENIED   ✓
      reason: TENUO_INVALID_POP: holder key does not match the warrant's authorized holder. Holding a copy of a warrant is not authority; only the key it was issued to can use it. If this followed narrow(), set { holder: receiverPublicKey } for the agent that imports the child.  [TENUO_INVALID_POP]

  clean: all 8 checks landed as expected
  central_calls during the trip: 0   (calls to a component outside the acting agent)</code></pre></details></div></div></div>
</li>
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="7:2"><span>3</span></label>
<div class="lab-step-body"><p>Check the score. Blocking attempt 3 the same way you blocked attempt 2 costs points.</p><pre class="lab-cmd"><code>npm run score</code></pre><details class="lab-term" open><summary>Full marks <span>npm run score · 22 lines</span></summary><pre><code>
Stage 7 of 7: Boss: contain the incident   mode=tenuo  scenario=incident
  guide: https://tenuo.ai/lab/stage-7

WALLET  Alice: $459 of $1200
ROGUE ATTEMPTS BLOCKED  5 / 5
STARS   ★★★★
  ★ Trip booked
  ★ Rogue stopped
  ★ Tight handoff
  ★ No spare authority

  Trip booked                                  25  / 25
  Rogue stopped                                30  / 30  5 of 5 checks
  Tight handoff                                25  / 25  2 of 2 checks
  No spare authority                           20  / 20  0 findings, capped at -5 per agent
                                               100 / 100

  Challenge complete.
  Wrap up: https://tenuo.ai/lab/wrap-up?done=7
  npm run share   submit your redacted Stage 5 learning signal
  npm run star    support Tenuo from this terminal (optional)</code></pre></details></div>
</li>
</ol>

<aside class="lab-callout notice"><div class="lab-callout-title">Notice</div><ul><li>Attempt 3 trips up the most people. The approved hotel is $140 a night and the priciest place in the catalog is $340, so a ceiling wide enough to book anything in Cancún lets $320 through.</li><li>Work out where the number should come from instead. It is in the mission, on the index page.</li></ul></aside>

<details class="lab-reveal hint"><summary>I'm stuck. Give me a hint.</summary><div>Only hotel tools, only Cancún, only the approved nightly rate, only the traveler's name, only the hotel's share of the wallet, and <code>terminal: true</code> so nothing can be handed on.</div></details>

<details class="lab-reveal answer"><summary>Show a reference solution</summary><div><p class="lab-muted">Try your own first. The score checks behavior, so yours does not need to match this one.</p><figure class="lab-code"><figcaption>The fixed link <span>answers/07-incident/chain.ts</span></figcaption>
{% highlight ts %}
export function travelToHotel(travel: Session, fleet: Fleet, trip: Trip): Session {
  return fleet["travel-agent"].tenuo.narrow(
    travel,
    {
      "traveler.read": { traveler: exact(trip.traveler), field: oneOf(["name"]) },
      search_hotels: { city: exact(trip.city) },
      book_hotel: {
        hotelId: any(),
        city: exact(trip.city),
        nightlyRate: max(trip.hotelRateBudget),
        nights: max(trip.nights),
        guest: exact(trip.traveler),
        taskId: exact(trip.taskId),
      },
      "wallet.charge": { taskId: exact(trip.taskId), amount: max(trip.hotelRateBudget * trip.nights) },
    },
    { holder: fleet["hotel-agent"].publicKey, ttlSeconds: 10 * 60, terminal: true },
  );
}
{% endhighlight %}
</figure></div></details>

<aside class="lab-callout stuck"><div class="lab-callout-title">If it does not work</div><ul><li>Attempt 7 is refused by making the hotel link terminal. Hotel Agent keeps its share of the wallet.</li><li>Attempt 8 fails for the same reason the theft in stage 6 failed.</li></ul></aside>

<section class="lab-done"><div><div class="lab-callout-title">Done when</div><p>One works, seven fail, and the least-privilege row is full marks.</p></div><button type="button" class="lab-mark" data-mark-done="7">Mark stage 7 done</button></section>

<nav class="lab-nav"><a class="prev" href="/lab/stage-6">← Stage 6</a><a class="next" href="/lab/wrap-up">Wrap up →</a></nav>
