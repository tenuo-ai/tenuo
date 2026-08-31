/**
 * Client role: mint a short-lived session and attach warrant + PoP to `_meta.tenuo`.
 *
 * After `npm i @tenuo/core`, change the import to `from "@tenuo/core"`.
 */
import { createTenuo, under, type Session, type Tenuo } from "../../src/index.ts";

export function createMcpClient(): { tenuo: Tenuo; session: Session } {
  const tenuo = createTenuo({ root: createTenuo.devRoot() });
  const session = tenuo.session({
    allow: { read_file: { path: under("/data") } },
  });
  return { tenuo, session };
}

export function attachRead(tenuo: Tenuo, session: Session, path: string) {
  return tenuo.mcp.attach(session, "read_file", { path });
}
