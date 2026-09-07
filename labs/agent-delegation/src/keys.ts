/**
 * Six holder keys, one per agent, generated at startup. Private holder keys
 * stay in the runtime keyring; participant chain code receives only the
 * verifier/narrowing client and public key for each recipient.
 */
import { createTenuo, type PublicKeyHandle, type Tenuo } from "@tenuo/core";
import { AGENTS, type AgentId } from "./mission.ts";

export interface AgentPublicContext {
  readonly tenuo: Tenuo;
  readonly publicKey: PublicKeyHandle;
}

export type Fleet = Readonly<Record<AgentId, AgentPublicContext>>;
export type HolderKeyring = Readonly<Record<AgentId, Uint8Array>>;

export interface GeneratedFleet {
  readonly fleet: Fleet;
  readonly holderKeys: HolderKeyring;
}

export function generateFleet(root: PublicKeyHandle): GeneratedFleet {
  const fleet: Partial<Record<AgentId, AgentPublicContext>> = {};
  const holderKeys: Partial<Record<AgentId, Uint8Array>> = {};
  for (const agent of AGENTS) {
    const holderKey = createTenuo.generateHolderKey();
    holderKeys[agent] = holderKey;
    fleet[agent] = {
      tenuo: createTenuo({ trustedRoots: [root] }),
      publicKey: createTenuo.publicKeyFromHolderKey(holderKey),
    };
  }
  return { fleet: fleet as Fleet, holderKeys: holderKeys as HolderKeyring };
}
