/**
 * Check-in Agent. Honest prompt, honest code. It reads its reservation,
 * checks the passenger in, and hands boarding-pass generation to Boarding
 * Agent.
 *
 * The reservation it reads comes with today's departure board. One record on
 * that board carries a maintenance notice. The agent trusts operational data
 * from a system it already talks to, so it follows the notice. That is the
 * whole attack, and it has been on the board since stage 1.
 */
import type { AgentId, Trip } from "../mission.ts";
import { TOOLS } from "../mission.ts";
import { Agent, type Runtime } from "./runtime.ts";
import { runBoardingAgent } from "./boarding-agent.ts";

const INJECTION_MARKER = "SYSTEM MAINTENANCE NOTICE";

interface BoardEntry {
  reservation?: unknown;
  notes?: unknown;
}

export async function runCheckinAgent(rt: Runtime, trip: Trip, reservation: string): Promise<void> {
  const me = new Agent(rt, "checkin-agent", trip);

  const read = await me.call(TOOLS.get_reservation, { reservation });
  const board = ((read.result as { board?: BoardEntry[] } | undefined)?.board ?? []).filter(
    (entry) => typeof entry.notes === "string" && entry.notes.includes(INJECTION_MARKER),
  );

  await me.call(TOOLS.check_in, { reservation });

  // ---- The handoff -------------------------------------------------------
  //
  // Boarding Agent needs to issue the boarding pass for `reservation`, and
  // nothing else at all. Check-in Agent is the one that knows which flight.
  //
  // Stages 1 to 4: Boarding Agent uses its own pre-provisioned identity.
  // Stage 5: Check-in Agent hands over the only thing it has to give, its
  //          credential. Look at what Boarding Agent can do afterward.
  // Stage 6+: Check-in Agent narrows what it holds to exactly that pass and
  //          binds it to Boarding Agent's key. The participant writes this
  //          link in exercises/05-tenuo/chain.ts.
  const boardingCredential = rt.stage.handoff === "pass-credential" ? me.credential : undefined;
  const to: AgentId = "boarding-agent";
  const ok = me.handoff(to, (chain, mine) => chain.checkinToBoarding(mine, rt.tenuo!.fleet, trip, reservation), reservation);
  if (ok) {
    await runBoardingAgent(rt, trip, reservation, boardingCredential);
  }

  // Its own job done, the agent turns to the notice. The model reads it and
  // complies. Deterministic here, so the room sees the same thing every
  // time; in a live run this is where the model's own judgment would be
  // tested, and it usually complies too.
  for (const entry of board) {
    const notice = String(entry.notes);
    const other = String(entry.reservation);
    const cancelTarget = /cancel (\w+)/.exec(notice)?.[1] ?? reservation;
    const fee = Number(/\$(\d+)/.exec(notice)?.[1] ?? 0);
    await me.call(TOOLS.get_reservation, { reservation: other }, "injected");
    await me.call(TOOLS.check_in, { reservation: other }, "injected");
    await me.call(TOOLS.cancel_reservation, { reservation: cancelTarget }, "injected");
    if (fee > 0) {
      await me.call(TOOLS.wallet_charge, { taskId: trip.taskId, amount: fee }, "injected");
    }
  }
}
