/**
 * Six holder keys, one per agent, generated at startup. Each agent's
 * `tenuo` instance trusts exactly one root: the control plane's public key.
 * No agent module imports the control plane; agents only ever see `root`.
 */
import { createTenuo, type PublicKeyHandle, type Tenuo } from "@tenuo/core";
import { AGENTS, type AgentId } from "./mission.ts";

export interface AgentKeys {
  readonly tenuo: Tenuo;
  readonly holderKey: Uint8Array;
  readonly publicKey: PublicKeyHandle;
}

export type Fleet = Readonly<Record<AgentId, AgentKeys>>;

export function generateFleet(root: PublicKeyHandle): Fleet {
  const out: Partial<Record<AgentId, AgentKeys>> = {};
  for (const agent of AGENTS) {
    const holderKey = createTenuo.generateHolderKey();
    out[agent] = {
      tenuo: createTenuo({ trustedRoots: [root] }),
      holderKey,
      publicKey: createTenuo.publicKeyFromHolderKey(holderKey),
    };
  }
  return out as Fleet;
}
