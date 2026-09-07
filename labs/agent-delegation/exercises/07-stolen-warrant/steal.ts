/**
 * Stage 7: someone stole a permission.
 *
 * Boarding Agent's permission for UA214 is a piece of data: `toWire()` is a
 * list of strings. Here Activity Agent gets a copy and tries to import it
 * with the only key it has, its own. The warrant is valid, unexpired, and
 * correctly scoped for exactly the action being attempted.
 *
 * Run `npm run attack` and read the reason.
 */
import type { Session } from "@tenuo/core";
import type { TenuoMode } from "../../src/auth/tenuo-mode.ts";

export interface StealOutcome {
  readonly imported: boolean;
  readonly reason: string;
  readonly code?: string;
}

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
