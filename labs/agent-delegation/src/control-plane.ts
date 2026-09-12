/**
 * The only thing in the lab that can mint a fresh permission. It lives here,
 * in one module, and no agent imports it. Agents get its public key and
 * nothing else. When a participant asks who holds the root key, this file
 * is the answer.
 */
import { createTenuo, type Tenuo } from "@tenuo/core";

process.env.NODE_ENV ??= "development";

export function createControlPlane(): Tenuo {
  return createTenuo({ root: createTenuo.devRoot() });
}
