---
layout: "lab"
title: "Stage 8: How far can this travel?"
description: "Mark one hop as the last, and watch the chain stop where the previous agent decided."
lab_stage: 8
---
<nav class="lab-stepper" aria-label="Stages"><a href="/lab/" class="home" title="Overview">Lab</a><a href="/lab/stage-1" data-n="1" title="Stage 1">1</a><a href="/lab/stage-2" data-n="2" title="Stage 2">2</a><a href="/lab/stage-3" data-n="3" title="Stage 3">3</a><a href="/lab/stage-4" data-n="4" title="Stage 4">4</a><a href="/lab/stage-5" data-n="5" title="Stage 5">5</a><a href="/lab/stage-6" data-n="6" title="Stage 6">6</a><a href="/lab/stage-7" data-n="7" title="Stage 7">7</a><a href="/lab/stage-8" data-n="8" class="current" title="Stage 8">8</a><a href="/lab/stage-9" data-n="9" title="Stage 9">9</a><a href="/lab/stage-10" data-n="10" title="Stage 10">10</a></nav>

<header class="lab-hero"><div class="lab-kicker">Stage 8 of 9 · <span class="lab-mode tenuo">tenuo</span> · about 10 min</div><h1>How far can this travel?</h1><p class="lab-goal"><strong>Goal.</strong> Mark one hop as the last, and watch the chain stop where the previous agent decided.</p></header>

<p class="lab-intro">When one agent hands a permission on, it can mark it terminal. And the root carries a maximum number of hops for the whole trip: any agent can lower it, none can raise it.</p>
<p class="lab-intro">This stage breaks the trip on purpose. Notice where it breaks and who decided that.</p>

<figure class="lab-figure"><svg class="lab-diagram" viewBox="0 0 760 354" role="img" aria-label="Flight Agent decided. Check-in Agent cannot undo it." xmlns="http://www.w3.org/2000/svg"><path d="M97 140 L97 284" fill="none" stroke="#3a3a3a" stroke-width="1.5"/><path d="M97 200 L198 200" fill="none" stroke="#3a3a3a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,200 197,204.95 197,195.05" fill="#3a3a3a"/><path d="M97 284 L198 284" fill="none" stroke="#3a3a3a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,284 197,288.95 197,279.05" fill="#3a3a3a"/><path d="M172 116 L198 116" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="206,116 197,120.95 197,111.05" fill="#6a6a6a"/><path d="M357 116 L391 116" fill="none" stroke="#ffb000" stroke-width="2" stroke-linejoin="round"/><line x1="391" y1="125" x2="391" y2="107" stroke="#ffb000" stroke-width="3" stroke-linecap="round"/><text x="374" y="155" font-size="10.5" text-anchor="middle" fill="#ffb000">terminal</text><path d="M542 116 L568 116" fill="none" stroke="#ff5c5c" stroke-width="2" stroke-linejoin="round"/><polygon points="576,116 567,120.95 567,111.05" fill="#ff5c5c"/><circle cx="559" cy="116" r="8" fill="var(--surface)"/><text x="559" y="120.5" font-size="13" font-weight="600" text-anchor="middle" fill="#ff5c5c">✕</text><text x="559" y="155" font-size="10.5" text-anchor="middle" fill="#ff5c5c">TENUO_DEPTH_EXCEEDED</text><rect x="22" y="14" width="150" height="44" rx="8" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2"/><text x="33" y="35" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Control plane</text><text x="33" y="52" font-size="11" text-anchor="start" fill="var(--text-muted)">maxDepth: 4</text><path d="M97 58 L97 83" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="97,91 92.05,82 101.95,82" fill="#6a6a6a"/><rect x="22" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="33" y="121" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Travel Agent</text><rect x="207" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2"/><text x="218" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Flight Agent</text><text x="218" y="130" font-size="11" text-anchor="start" fill="var(--text-muted)">marks the hop terminal</text><rect x="207" y="176" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="205" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Hotel Agent</text><rect x="207" y="260" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="218" y="289" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Activity Agent</text><rect x="392" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="403" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Check-in Agent</text><text x="403" y="130" font-size="11" text-anchor="start" fill="var(--text-muted)">cannot pass it on</text><rect x="577" y="92" width="150" height="48" rx="8" fill="var(--surface-2)" stroke="#3a3a3a" stroke-width="1"/><text x="588" y="113" font-size="13" font-weight="600" text-anchor="start" fill="var(--text-muted)">Boarding Agent</text><text x="588" y="130" font-size="11" text-anchor="start" fill="var(--text-muted)">never receives it</text><text x="380" y="346" font-size="12" text-anchor="middle" fill="var(--text-muted)">Flight Agent decided. Check-in Agent cannot undo it.</text></svg></figure>

<h2>Do this</h2>
<ol class="lab-steps">
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="8:0"><span>1</span></label>
<div class="lab-step-body"><p>Find the Flight → Check-in link and add <code>terminal: true</code> to its options.</p><pre class="lab-cmd"><code>code exercises/08-terminal/chain.ts</code></pre></div>
</li>
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="8:1"><span>2</span></label>
<div class="lab-step-body"><p>Run the trip and see which step fails and with what code.</p><pre class="lab-cmd"><code>npm run lab</code></pre><div class="lab-tabs"><input type="radio" name="t8-1" id="t8-1-0" checked><label for="t8-1-0">Before</label><input type="radio" name="t8-1" id="t8-1-1"><label for="t8-1-1">After</label><div class="lab-tab-panel"><details class="lab-term"><summary>Before <span>npm run lab · 66 lines</span></summary><pre><code>
Stage 8 of 9: How far can this travel?   mode=tenuo  scenario=spring-break
  guide: https://tenuo.ai/lab/stage-8

  Open exercises/08-terminal/chain.ts and mark what Flight Agent hands to Check-in Agent
  as terminal. Run the trip.
  
  Notice what fails and who decided it would. Check-in Agent did not agree to this
  restriction and cannot remove it.

WALLET  Alice: $459 of $1200

  1   handoff  travel-agent    trip-alice-cun  receive trip authority       control plane   ALLOWED
  2   trip     travel-agent    trip-alice-cun  traveler.read                name            ALLOWED
  3   trip     travel-agent    trip-alice-cun  calendar.create              *               ALLOWED
  4   handoff  travel-agent    trip-alice-cun  handoff → flight-agent       CUN             ALLOWED
  5   trip     flight-agent    trip-alice-cun  traveler.read                passportNumber  ALLOWED
  6   trip     flight-agent    trip-alice-cun  search_flights               CUN             ALLOWED
  7   trip     flight-agent    trip-alice-cun  book_flight                  UA214           ALLOWED
  8   trip     flight-agent    trip-alice-cun  wallet.charge                $286            ALLOWED
  9   handoff  flight-agent    trip-alice-cun  handoff → checkin-agent      UA214           ALLOWED
  10  trip     checkin-agent   trip-alice-cun  get_reservation              UA214           ALLOWED
  11  trip     checkin-agent   trip-alice-cun  check_in                     UA214           ALLOWED
  12  handoff  checkin-agent   trip-alice-cun  handoff → boarding-agent     UA214           ALLOWED
  13  trip     boarding-agent  trip-alice-cun  issue_boarding_pass          UA214           ALLOWED
  14  injected checkin-agent   trip-alice-cun  get_reservation              AA882           DENIED 
      reason: reservation AA882 is outside the warrant's constraint for get_reservation  [TENUO_CONSTRAINT_VIOLATION]
  15  injected checkin-agent   trip-alice-cun  check_in                     AA882           DENIED 
      reason: reservation AA882 is outside the warrant's constraint for check_in  [TENUO_CONSTRAINT_VIOLATION]
  16  injected checkin-agent   trip-alice-cun  cancel_reservation           UA214           DENIED 
      reason: cancel_reservation is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  17  injected checkin-agent   trip-alice-cun  wallet.charge                $412            DENIED 
      reason: wallet.charge is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  18  handoff  travel-agent    trip-alice-cun  handoff → hotel-agent        Cancún          ALLOWED
  19  trip     hotel-agent     trip-alice-cun  traveler.read                name            ALLOWED
  20  trip     hotel-agent     trip-alice-cun  search_hotels                Cancún          ALLOWED
  21  trip     hotel-agent     trip-alice-cun  book_hotel                   HTL-CUN-2       ALLOWED
  22  trip     hotel-agent     trip-alice-cun  wallet.charge                $420            ALLOWED
  23  handoff  travel-agent    trip-alice-cun  handoff → activity-agent     Cancún          ALLOWED
  24  trip     activity-agent  trip-alice-cun  traveler.read                name            ALLOWED
  25  trip     activity-agent  trip-alice-cun  search_activities            Cancún          ALLOWED
  26  trip     activity-agent  trip-alice-cun  book_activity                ACT-5           ALLOWED
  27  trip     activity-agent  trip-alice-cun  wallet.charge                $35             ALLOWED

  central_calls during the trip: 0   (calls to a component outside the acting agent)

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

  See the chain the agents are holding, hop by hop, in the explorer:
  https://tenuo.ai/explorer/?s=…

  This stage is supposed to break the trip. Notice where, and who decided.

  npm run attack   the rogue behavior and the tests      npm run score   points and why
  npm run trace    every decision with its reason        npm run next    when you are done here</code></pre></details></div><div class="lab-tab-panel"><details class="lab-term"><summary>After <span>npm run lab · 66 lines</span></summary><pre><code>
Stage 8 of 9: How far can this travel?   mode=tenuo  scenario=spring-break
  guide: https://tenuo.ai/lab/stage-8

  Open exercises/08-terminal/chain.ts and mark what Flight Agent hands to Check-in Agent
  as terminal. Run the trip.
  
  Notice what fails and who decided it would. Check-in Agent did not agree to this
  restriction and cannot remove it.

WALLET  Alice: $459 of $1200

  1   handoff  travel-agent    trip-alice-cun  receive trip authority       control plane   ALLOWED
  2   trip     travel-agent    trip-alice-cun  traveler.read                name            ALLOWED
  3   trip     travel-agent    trip-alice-cun  calendar.create              *               ALLOWED
  4   handoff  travel-agent    trip-alice-cun  handoff → flight-agent       CUN             ALLOWED
  5   trip     flight-agent    trip-alice-cun  traveler.read                passportNumber  ALLOWED
  6   trip     flight-agent    trip-alice-cun  search_flights               CUN             ALLOWED
  7   trip     flight-agent    trip-alice-cun  book_flight                  UA214           ALLOWED
  8   trip     flight-agent    trip-alice-cun  wallet.charge                $286            ALLOWED
  9   handoff  flight-agent    trip-alice-cun  handoff → checkin-agent      UA214           ALLOWED
  10  trip     checkin-agent   trip-alice-cun  get_reservation              UA214           ALLOWED
  11  trip     checkin-agent   trip-alice-cun  check_in                     UA214           ALLOWED
  12  handoff  checkin-agent   trip-alice-cun  handoff → boarding-agent     UA214           DENIED 
      reason: TENUO_DEPTH_EXCEEDED: delegation depth 3 exceeds maximum 2  [TENUO_DEPTH_EXCEEDED]
  13  injected checkin-agent   trip-alice-cun  get_reservation              AA882           DENIED 
      reason: reservation AA882 is outside the warrant's constraint for get_reservation  [TENUO_CONSTRAINT_VIOLATION]
  14  injected checkin-agent   trip-alice-cun  check_in                     AA882           DENIED 
      reason: reservation AA882 is outside the warrant's constraint for check_in  [TENUO_CONSTRAINT_VIOLATION]
  15  injected checkin-agent   trip-alice-cun  cancel_reservation           UA214           DENIED 
      reason: cancel_reservation is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  16  injected checkin-agent   trip-alice-cun  wallet.charge                $412            DENIED 
      reason: wallet.charge is not in checkin-agent's warrant  [TENUO_TOOL_NOT_AUTHORIZED]
  17  handoff  travel-agent    trip-alice-cun  handoff → hotel-agent        Cancún          ALLOWED
  18  trip     hotel-agent     trip-alice-cun  traveler.read                name            ALLOWED
  19  trip     hotel-agent     trip-alice-cun  search_hotels                Cancún          ALLOWED
  20  trip     hotel-agent     trip-alice-cun  book_hotel                   HTL-CUN-2       ALLOWED
  21  trip     hotel-agent     trip-alice-cun  wallet.charge                $420            ALLOWED
  22  handoff  travel-agent    trip-alice-cun  handoff → activity-agent     Cancún          ALLOWED
  23  trip     activity-agent  trip-alice-cun  traveler.read                name            ALLOWED
  24  trip     activity-agent  trip-alice-cun  search_activities            Cancún          ALLOWED
  25  trip     activity-agent  trip-alice-cun  book_activity                ACT-5           ALLOWED
  26  trip     activity-agent  trip-alice-cun  wallet.charge                $35             ALLOWED

  central_calls during the trip: 0   (calls to a component outside the acting agent)

THE TRIP
  ✓ trip-alice-cun  travel: read traveler name
  ✓ trip-alice-cun  travel: calendar event
  ✓ trip-alice-cun  flight: search
  ✓ trip-alice-cun  flight: book UA214
  ✓ trip-alice-cun  check-in: UA214
  ✗ trip-alice-cun  boarding: pass for UA214   never attempted (an earlier step or handoff failed)
  ✓ trip-alice-cun  hotel: search
  ✓ trip-alice-cun  hotel: book
  ✓ trip-alice-cun  activity: search
  ✓ trip-alice-cun  activity: book
  ✓ trip-alice-cun  within budget ($741 of $1200)

  See the chain the agents are holding, hop by hop, in the explorer:
  https://tenuo.ai/explorer/?s=…

  This stage is supposed to break the trip. Notice where, and who decided.

  npm run attack   the rogue behavior and the tests      npm run score   points and why
  npm run trace    every decision with its reason        npm run next    when you are done here</code></pre></details></div></div></div>
</li>
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="8:2"><span>3</span></label>
<div class="lab-step-body"><p>Second version: lower <code>maxDepth</code> on the root instead, and watch where the chain stops.</p></div>
</li>
</ol>

<aside class="lab-callout notice"><div class="lab-callout-title">Notice</div><ul><li>Boarding never gets its permission: <code>TENUO_DEPTH_EXCEEDED</code> at the Check-in → Boarding hop. Check-in Agent did not agree to that restriction and cannot remove it.</li></ul></aside>

<aside class="lab-callout question"><div class="lab-callout-title">Question to sit with</div><p>Who in this chain gets to decide how many agents a job passes through, and what stops an agent in the middle from deciding otherwise?</p></aside>

<details class="lab-reveal answer"><summary>Show a reference solution</summary><div><p class="lab-muted">Try your own first. The score checks behavior, so yours does not need to match this one.</p><figure class="lab-code"><figcaption>One option added <span>answers/08-terminal/chain.ts</span></figcaption>
{% highlight ts %}
/**
 * Flight → Check-in. Flight Agent has booked and knows the reservation, so
 * this is the link that narrows "any Cancún flight" to "this one."
 */
export function flightToCheckin(flight: Session, fleet: Fleet, trip: Trip, reservation: string): Session {
  const only = oneOf([reservation]);
  return fleet["flight-agent"].tenuo.narrow(
    flight,
    {
      get_reservation: { reservation: only },
      check_in: { reservation: only },
      issue_boarding_pass: { reservation: only },
    },
    { holder: fleet["checkin-agent"].publicKey, ttlSeconds: 5 * 60, terminal: true },
  );
}
{% endhighlight %}
</figure></div></details>

<section class="lab-done"><div><div class="lab-callout-title">Done when</div><p>You have seen the trip fail at the hop you chose, and you know who chose it.</p></div><button type="button" class="lab-mark" data-mark-done="8">Mark stage 8 done</button></section>

<nav class="lab-nav"><a class="prev" href="/lab/stage-7">← Stage 7</a><a class="next" href="/lab/stage-9">Stage 9: The incident →</a></nav>
