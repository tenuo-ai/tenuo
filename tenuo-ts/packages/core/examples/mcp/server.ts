/**
 * Server role: trusted root only. Verify `_meta.tenuo` before the handler runs.
 *
 * After `npm i @tenuo/core`, change the import to `from "@tenuo/core"`.
 * Production loads `TENUO_ROOT_PUBLIC_KEY` — the issuer public key you already have.
 */
import { createTenuo } from "../../src/index.ts";

export function createReadFileHandler(rootHex: string) {
  const tenuo = createTenuo({
    trustedRoots: [createTenuo.publicKeyFromHex(rootHex)],
  });
  return tenuo.mcp.handler("read_file", async ({ path }: { path: string }) => {
    return `contents of ${path}`;
  });
}
