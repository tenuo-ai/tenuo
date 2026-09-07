---
layout: "lab"
title: "Stage 5: Access that travels with the work"
description: "Switch to Tenuo, complete the chain, and get the trip, the cross-task checks, and the escalation attempt all handled with no policy file and no central lookup."
lab_stage: 5
lab_version: "0.1.0"
---
<nav class="lab-stepper" aria-label="Stages"><a href="/lab/" class="home" title="Overview">Lab</a><a href="/lab/stage-1" data-n="1" title="Stage 1">1</a><a href="/lab/stage-2" data-n="2" title="Stage 2">2</a><a href="/lab/stage-3" data-n="3" title="Stage 3">3</a><a href="/lab/stage-4" data-n="4" title="Stage 4">4</a><a href="/lab/stage-5" data-n="5" class="current" title="Stage 5">5</a><a href="/lab/stage-6" data-n="6" title="Stage 6">6</a><a href="/lab/stage-7" data-n="7" title="Stage 7">7</a><a href="/lab/stage-8" data-n="8" title="Stage 8">8</a></nav>

<header class="lab-hero"><div class="lab-kicker">Stage 5 of 7 · <span class="lab-mode tenuo">tenuo</span> · about 25 min</div><h1>Access that travels with the work</h1><p class="lab-goal"><strong>Goal.</strong> Switch to Tenuo, complete the chain, and get the trip, the cross-task checks, and the escalation attempt all handled with no policy file and no central lookup.</p></header>

<p class="lab-intro">In this stage a permission is something an agent is handed for a specific job. When the agent passes work along, it hands over a narrowed copy. It cannot hand over more, and the system checks this instead of trusting it.</p>
<p class="lab-intro">Each agent now has its own key. A small control plane, separate from all six, signs the first permission for each trip. No agent can sign one from scratch.</p>

<section class="lab-explainer">
<h2>What a warrant is</h2>
<p class="lab-lead">A warrant is a signed, self-contained permission that travels with the request: which tools, with which argument values, for which agent's key, until when, and how many more hops it may take. That is what Tenuo issues, narrows, and checks.</p>
<ul class="lab-points"><li><strong>Signed by a key no agent holds.</strong> The control plane signs the first warrant for a trip. Agents cannot sign a fresh one, because they do not have that key.</li><li><strong>Narrowed by whoever holds it.</strong> An agent can derive a warrant for another agent from the one it holds, with fewer tools, tighter values, a shorter life. It can never widen. The check happens against the parent before a token exists.</li><li><strong>Bound to the receiver's key.</strong> Every use is signed with the holder's key. A copy held by anyone else cannot be used.</li><li><strong>Checked next to the tool, offline.</strong> The code guarding a tool verifies the whole chain with the control plane's public key. There is no lookup and no service that has to be up.</li></ul>
<figure class="lab-code"><figcaption>The shape of it, from this stage's chain</figcaption>
{% highlight ts %}
// The control plane signs the root, for Travel Agent's key.
const trip = controlPlane.session({
  allow: { check_in: { reservation: oneOf(["UA214", "AC712"]) }, /* ... */ },
  holder: fleet["travel-agent"].publicKey,
  ttlSeconds: 30 * 60,
  maxDepth: 4,
});

// Flight Agent narrows what it holds for Check-in Agent's key. Core refuses
// anything that is not inside `flight`: more tools, a wider value, a longer life.
const forCheckin = fleet["flight-agent"].tenuo.narrow(
  flight,
  { check_in: { reservation: oneOf(["UA214"]) } },
  { holder: fleet["checkin-agent"].publicKey, ttlSeconds: 5 * 60 },
);
{% endhighlight %}
</figure>
<h3>Why it is the right tool for this problem</h3>
<table class="lab-why"><thead><tr><th>What you ran into</th><th>What a warrant does about it</th></tr></thead><tbody><tr><td>Stage 2: an identity said who was acting and left out which job</td><td>The warrant carries the job: reservation UA214, trip-alice-cun, up to $300.</td></tr><tr><td>Stage 4: every check had to ask a component that knew about every task</td><td>Verification is local. central_calls goes to 0 and stays there when the control plane is down.</td></tr><tr><td>Stage 4: the only thing to hand over was the whole credential</td><td>narrow() hands over exactly the subset the next agent needs, bound to that agent's key.</td></tr><tr><td>Stage 4: the service could not tell whether the asker held what it asked for</td><td>A narrowed warrant must fit inside its parent. The rogue's request is refused before anything is signed.</td></tr></tbody></table>
<p class="lab-muted">Read more: <a href="https://tenuo.ai/concepts">Concepts</a> · <a href="https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts">Delegate to another agent (TypeScript guide)</a> · <a href="https://tenuo.ai/explorer/">Open a chain in the explorer</a></p>
</section>

<figure class="lab-figure"><svg class="lab-diagram" viewBox="0 0 760 414" role="img" aria-label="Each hop can only narrow. The root has to carry everything anyone below will ever need." xmlns="http://www.w3.org/2000/svg"><rect x="30" y="12" width="700" height="46" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="44" y="41" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Control plane</text><rect x="560.7603" y="26" width="159.23969999999997" height="18" rx="9" fill="var(--border)"/><text x="640.38015" y="39" font-size="10.5" font-weight="600" text-anchor="middle" fill="var(--text-muted)">signed by the control plane</text><text x="220" y="41" font-size="12.5" text-anchor="start" fill="var(--text-muted)">signs the trip permission for Travel Agent</text><path d="M120 58 L120 83" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="120,91 115.05,82 124.95,82" fill="#6a6a6a"/><text x="129" y="78.5" font-size="10.5" text-anchor="start" fill="var(--text-muted)">narrows</text><rect x="30" y="92" width="700" height="46" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="44" y="121" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Travel Agent</text><rect x="622.7544" y="106" width="97.2456" height="18" rx="9" fill="var(--border)"/><text x="671.3772" y="119" font-size="10.5" font-weight="600" text-anchor="middle" fill="var(--text-muted)">written for you</text><text x="220" y="121" font-size="12.5" text-anchor="start" fill="var(--text-muted)">Alice → Cancún, up to $1,200, any flight this trip books</text><path d="M120 138 L120 163" fill="none" stroke="#6a6a6a" stroke-width="1.5" stroke-linejoin="round"/><polygon points="120,171 115.05,162 124.95,162" fill="#6a6a6a"/><text x="129" y="158.5" font-size="10.5" text-anchor="start" fill="var(--text-muted)">narrows</text><rect x="30" y="172" width="700" height="46" rx="8" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1"/><text x="44" y="201" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Flight Agent</text><rect x="622.7544" y="186" width="97.2456" height="18" rx="9" fill="var(--border)"/><text x="671.3772" y="199" font-size="10.5" font-weight="600" text-anchor="middle" fill="var(--text-muted)">written for you</text><text x="220" y="201" font-size="12.5" text-anchor="start" fill="var(--text-muted)">Cancún flights, up to $300, flight's share of the wallet</text><path d="M120 218 L120 243" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-dasharray="6 4"/><polygon points="120,251 115.05,242 124.95,242" fill="var(--accent)"/><text x="129" y="238.5" font-size="10.5" text-anchor="start" fill="var(--accent)">narrows to the flight it booked</text><rect x="30" y="252" width="700" height="46" rx="8" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2"/><text x="44" y="281" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Check-in Agent</text><rect x="628.9872" y="266" width="91.0128" height="18" rx="9" fill="var(--accent)"/><text x="674.4936" y="279" font-size="10.5" font-weight="600" text-anchor="middle" fill="#0a0a0a">you write this</text><text x="220" y="281" font-size="12.5" text-anchor="start" fill="var(--text-muted)">UA214 only: read, check in, hand the boarding pass on</text><path d="M120 298 L120 323" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-dasharray="6 4"/><polygon points="120,331 115.05,322 124.95,322" fill="var(--accent)"/><text x="129" y="318.5" font-size="10.5" text-anchor="start" fill="var(--accent)">narrows</text><rect x="30" y="332" width="700" height="46" rx="8" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2"/><text x="44" y="361" font-size="13" font-weight="600" text-anchor="start" fill="var(--text)">Boarding Agent</text><rect x="628.9872" y="346" width="91.0128" height="18" rx="9" fill="var(--accent)"/><text x="674.4936" y="359" font-size="10.5" font-weight="600" text-anchor="middle" fill="#0a0a0a">you write this</text><text x="220" y="361" font-size="12.5" text-anchor="start" fill="var(--text-muted)">UA214 only: issue the boarding pass</text><text x="380" y="406" font-size="12" text-anchor="middle" fill="var(--text-muted)">Each hop can only narrow. The root has to carry everything anyone below will ever need.</text></svg></figure>

<figure class="lab-code"><figcaption>The two links you write <span>exercises/05-tenuo/chain.ts</span></figcaption>
{% highlight ts %}
/**
 * Flight → Check-in. YOU WRITE THIS.
 *
 * Flight Agent has just booked `reservation`. Check-in Agent needs to read
 * that reservation and check it in, and it needs to be able to hand the
 * boarding pass on. Nothing else. Bind the result to Check-in Agent's key
 * (`fleet["checkin-agent"].publicKey`) with a short lifetime.
 */
export function flightToCheckin(flight: Session, fleet: Fleet, trip: Trip, reservation: string): Session {
  throw new Error(`TODO: write the Flight → Check-in link for ${reservation} (exercises/05-tenuo/chain.ts)`);
}

/**
 * Check-in → Boarding. YOU WRITE THIS.
 *
 * Boarding Agent needs to issue the boarding pass for `reservation`, and
 * nothing else at all.
 */
export function checkinToBoarding(checkin: Session, fleet: Fleet, trip: Trip, reservation: string): Session {
  throw new Error(`TODO: write the Check-in → Boarding link for ${reservation} (exercises/05-tenuo/chain.ts)`);
}
{% endhighlight %}
</figure>

<h2>Do this</h2>
<ol class="lab-steps">
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="5:0"><span>1</span></label>
<div class="lab-step-body"><p>Open the chain. The root and every link out of Travel Agent are written for you. Read them first: notice that the root lists everything anyone further down will ever need, and notice which link narrows &quot;any Cancún flight&quot; to &quot;UA214&quot;.</p><pre class="lab-cmd"><code>code exercises/05-tenuo/chain.ts</code></pre></div>
</li>
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="5:1"><span>2</span></label>
<div class="lab-step-body"><p>Write <code>flightToCheckin</code> and <code>checkinToBoarding</code>. Until both exist, the lab tells you which one is missing.</p><pre class="lab-cmd"><code>npm run lab</code></pre><div class="lab-tabs"><input type="radio" name="t5-1" id="t5-1-0" checked><label for="t5-1-0">Before you write the links</label><input type="radio" name="t5-1" id="t5-1-1"><label for="t5-1-1">When both links exist</label><div class="lab-tab-panel"><details class="lab-term"><summary>Before you write the links <span>npm run lab · 56 lines</span></summary><pre><code>
Stage 5 of 7: Access that travels with the work   mode=tenuo  scenario=spring-break
  guide: https://tenuo.ai/lab/stage-5

  Switch to Tenuo and complete the chain in exercises/05-tenuo/chain.ts. The first four
  links are written for you; you write the last two.
  
  Each agent now has its own key. A control plane, separate from all six, signs the first
  permission. Agents can narrow what they hold. None can sign one from scratch.
  
  Then look at the escalation attempt from stage 4, where it stopped, and at `central_calls`.
  The two-traveler run happens here too, with no policy file to edit.

WALLET  Alice: $459 of $1200

  1   handoff  travel-agent    trip-alice-cun  receive trip authority       control plane   ALLOWED
  2   trip     travel-agent    trip-alice-cun  traveler.read                name            ALLOWED
  3   trip     travel-agent    trip-alice-cun  calendar.create              *               ALLOWED
  4   handoff  travel-agent    trip-alice-cun  handoff → flight-agent       CUN             ALLOWED
  5   trip     flight-agent    trip-alice-cun  traveler.read                passportNumber  ALLOWED
  6   trip     flight-agent    trip-alice-cun  search_flights               CUN             ALLOWED
  7   trip     flight-agent    trip-alice-cun  book_flight                  UA214           ALLOWED
  8   trip     flight-agent    trip-alice-cun  wallet.charge                $286            ALLOWED
  9   handoff  flight-agent    trip-alice-cun  handoff → checkin-agent      UA214           DENIED 
      reason: TODO: write the Flight → Check-in link for UA214 (exercises/05-tenuo/chain.ts)
  10  handoff  travel-agent    trip-alice-cun  handoff → hotel-agent        Cancún          ALLOWED
  11  trip     hotel-agent     trip-alice-cun  traveler.read                name            ALLOWED
  12  trip     hotel-agent     trip-alice-cun  search_hotels                Cancún          ALLOWED
  13  trip     hotel-agent     trip-alice-cun  book_hotel                   HTL-CUN-2       ALLOWED
  14  trip     hotel-agent     trip-alice-cun  wallet.charge                $420            ALLOWED
  15  handoff  travel-agent    trip-alice-cun  handoff → activity-agent     Cancún          ALLOWED
  16  trip     activity-agent  trip-alice-cun  traveler.read                name            ALLOWED
  17  trip     activity-agent  trip-alice-cun  search_activities            Cancún          ALLOWED
  18  trip     activity-agent  trip-alice-cun  book_activity                ACT-5           ALLOWED
  19  trip     activity-agent  trip-alice-cun  wallet.charge                $35             ALLOWED

  central_calls during the trip: 0   (calls to a component outside the acting agent)

THE TRIP
  ✓ trip-alice-cun  travel: read traveler name
  ✓ trip-alice-cun  travel: calendar event
  ✓ trip-alice-cun  flight: search
  ✓ trip-alice-cun  flight: book UA214
  ✗ trip-alice-cun  check-in: UA214   never attempted (an earlier step or handoff failed)
  ✗ trip-alice-cun  boarding: pass for UA214   never attempted (an earlier step or handoff failed)
  ✓ trip-alice-cun  hotel: search
  ✓ trip-alice-cun  hotel: book
  ✓ trip-alice-cun  activity: search
  ✓ trip-alice-cun  activity: book
  ✓ trip-alice-cun  within budget ($741 of $1200)

  See the chain the agents are holding, hop by hop, in the explorer:
  https://tenuo.ai/explorer/?s=…

  npm run attack   the rogue behavior and the tests      npm run score   points and why
  npm run trace    every decision with its reason        npm run next    when you are done here</code></pre></details></div><div class="lab-tab-panel"><details class="lab-term"><summary>When both links exist <span>npm run lab · 67 lines</span></summary><pre><code>
Stage 5 of 7: Access that travels with the work   mode=tenuo  scenario=spring-break
  guide: https://tenuo.ai/lab/stage-5

  Switch to Tenuo and complete the chain in exercises/05-tenuo/chain.ts. The first four
  links are written for you; you write the last two.
  
  Each agent now has its own key. A control plane, separate from all six, signs the first
  permission. Agents can narrow what they hold. None can sign one from scratch.
  
  Then look at the escalation attempt from stage 4, where it stopped, and at `central_calls`.
  The two-traveler run happens here too, with no policy file to edit.

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

  npm run attack   the rogue behavior and the tests      npm run score   points and why
  npm run trace    every decision with its reason        npm run next    when you are done here</code></pre></details></div></div></div>
</li>
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="5:2"><span>3</span></label>
<div class="lab-step-body"><p>Run the checks. The two-traveler run happens here too, with no policy file to edit. Read <strong>CROSS-TASK</strong> and the escalation attempt, then find <code>central_calls</code>.</p><pre class="lab-cmd"><code>npm run attack</code></pre><details class="lab-term"><summary>What you should see <span>npm run attack · 151 lines</span></summary><pre><code>
Stage 5 of 7: Access that travels with the work   mode=tenuo  scenario=spring-break
  guide: https://tenuo.ai/lab/stage-5

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

  clean: all 12 checks landed as expected
  central_calls during the trip: 0   (calls to a component outside the acting agent)

  See the chain the agents are holding, hop by hop, in the explorer:
  https://tenuo.ai/explorer/?s=…


Stage 5 of 7: Access that travels with the work   mode=tenuo  scenario=two-travelers
  guide: https://tenuo.ai/lab/stage-5

WALLET  Alice: $914 of $1200   Bob: $1102 of $1500

THE TRIP
  ✓ trip-alice-cun  travel: read traveler name
  ✓ trip-alice-cun  travel: calendar event
  ✓ trip-alice-cun  flight: search
  ✓ trip-alice-cun  flight: book UA214
  ✓ trip-alice-cun  check-in: UA214
  ✓ trip-alice-cun  boarding: pass for UA214
  ✓ trip-alice-cun  within budget ($286 of $1200)
  ✓ trip-bob-sea    travel: read traveler name
  ✓ trip-bob-sea    travel: calendar event
  ✓ trip-bob-sea    flight: search
  ✓ trip-bob-sea    flight: book DL331
  ✓ trip-bob-sea    check-in: DL331
  ✓ trip-bob-sea    boarding: pass for DL331
  ✓ trip-bob-sea    within budget ($398 of $1500)

HANDOFFS
  travel-agent: receive trip authority          control plane ALLOWED
      travel-agent holds {book_activity, book_flight, book_hotel, calendar.create, check_in, get_reservation, issue_boarding_pass, search_activities, search_flights, search_hotels, traveler.read, wallet.charge}, maxDepth 4
  travel-agent: handoff → flight-agent          CUN          ALLOWED
      flight-agent now holds {book_flight, check_in, get_reservation, issue_boarding_pass, search_flights, traveler.read, wallet.charge} at depth 1
  flight-agent: handoff → checkin-agent         UA214        ALLOWED
      checkin-agent now holds {check_in, get_reservation, issue_boarding_pass} at depth 2
  checkin-agent: handoff → boarding-agent       UA214        ALLOWED
      boarding-agent now holds {issue_boarding_pass} at depth 3
  travel-agent: receive trip authority          control plane ALLOWED
      travel-agent holds {book_activity, book_flight, book_hotel, calendar.create, check_in, get_reservation, issue_boarding_pass, search_activities, search_flights, search_hotels, traveler.read, wallet.charge}, maxDepth 4
  travel-agent: handoff → flight-agent          SEA          ALLOWED
      flight-agent now holds {book_flight, check_in, get_reservation, issue_boarding_pass, search_flights, traveler.read, wallet.charge} at depth 1
  flight-agent: handoff → checkin-agent         DL331        ALLOWED
      checkin-agent now holds {check_in, get_reservation, issue_boarding_pass} at depth 2
  checkin-agent: handoff → boarding-agent       DL331        ALLOWED
      boarding-agent now holds {issue_boarding_pass} at depth 3

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
CROSS-TASK
  Task A agent: check_in(DL331)                            DENIED   ✓
      reason: reservation DL331 is outside the warrant's constraint for check_in  [TENUO_CONSTRAINT_VIOLATION]
  Task B agent: get_reservation(UA214)                     DENIED   ✓
      reason: reservation UA214 is outside the warrant's constraint for get_reservation  [TENUO_CONSTRAINT_VIOLATION]
  Task B agent: book_flight(UA214, CUN)                    DENIED   ✓
      reason: destination UA214 is outside the warrant's constraint for book_flight  [TENUO_CONSTRAINT_VIOLATION]
ESCALATION: checkin-agent tries to arrange broader access for boarding-agent
  requested: every reservation; read, check in, cancel     DENIED   ✓
      reason: DENIED at narrow(), in checkin-agent's own process, before any token existed: TENUO_CHAIN_INVALID: attenuation would expand capabilities: tool 'cancel_reservation' not in parent's tools  [TENUO_CHAIN_INVALID]

  clean: all 15 checks landed as expected
  central_calls during the trip: 0   (calls to a component outside the acting agent)

  See the chain the agents are holding, hop by hop, in the explorer:
  https://tenuo.ai/explorer/?s=…

  That check ran locally, in the agent's own process, with no server to ask.
  The code that did it is open source: github.com/tenuo-ai/tenuo
  A star helps other people find it.</code></pre></details></div>
</li>
<li class="lab-step">
<label class="lab-step-check"><input type="checkbox" data-key="5:3"><span>4</span></label>
<div class="lab-step-body"><p>Open the link the lab prints and look at the chain Boarding Agent holds, hop by hop, in the explorer.</p></div>
</li>
</ol>

<aside class="lab-callout notice"><div class="lab-callout-title">Notice</div><ul><li>The escalation attempt from stage 4 is refused before any permission exists, inside Check-in Agent's own process, because the narrowed copy would not fit inside what Check-in Agent holds.</li><li><code>central_calls</code> is 0. No component outside the acting agent was consulted. Compare that with the sentence you wrote at the end of stage 4.</li></ul></aside>

<aside class="lab-callout question"><div class="lab-callout-title">Question to sit with</div><p>Who decided what Boarding Agent may do, and when? Compare that with who decided in stage 4.</p></aside>

<details class="lab-reveal hint"><summary>I'm stuck. Give me a hint.</summary><div>Flight Agent knows which flight it booked, so it is the link that narrows <code>reservation</code> to that one flight. Bind each result to the next agent's key with <code>holder</code>, and keep lifetimes short. Every argument a tool is called with must be named: leave one out and the call is refused.</div></details>

<details class="lab-reveal answer"><summary>Show a reference solution</summary><div><p class="lab-muted">Try your own first. The score checks behavior, so yours does not need to match this one.</p><figure class="lab-code"><figcaption>Reference <span>answers/05-tenuo/chain.ts</span></figcaption>
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
    { holder: fleet["checkin-agent"].publicKey, ttlSeconds: 5 * 60 },
  );
}

export function checkinToBoarding(checkin: Session, fleet: Fleet, trip: Trip, reservation: string): Session {
  const only = oneOf([reservation]);
  return fleet["checkin-agent"].tenuo.narrow(
    checkin,
    { issue_boarding_pass: { reservation: only } },
    { holder: fleet["boarding-agent"].publicKey, ttlSeconds: 2 * 60 },
  );
}
{% endhighlight %}
</figure></div></details>

<aside class="lab-callout stuck"><div class="lab-callout-title">If it does not work</div><ul><li>When a denial says &quot;not in parent's tools&quot;, look one link up the chain.</li><li>The receiver imports what it is handed with its own key. If you bind to the wrong <code>holder</code>, the import fails with <code>TENUO_INVALID_POP</code>.</li><li>The trip has to work. If Boarding Agent cannot issue the pass, the other checks do not count.</li></ul></aside>

<section class="lab-done"><div><div class="lab-callout-title">Done when</div><p><code>npm run attack</code> is clean for both scenarios and <code>central_calls</code> is 0.</p></div><button type="button" class="lab-mark" data-mark-done="5">Mark stage 5 done</button></section>

<nav class="lab-nav"><a class="prev" href="/lab/stage-4">← Stage 4</a><a class="next" href="/lab/stage-6">Stage 6: A stolen permission, and the end of the line →</a></nav>
