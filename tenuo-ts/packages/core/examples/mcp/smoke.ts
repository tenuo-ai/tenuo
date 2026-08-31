/**
 * In-process MCP smoke: allow, deny at attach, forged args fail closed.
 *
 * Both roles share one process so this does not need the official MCP SDK.
 * The issuer public key is leaked only so the server can trust the same root.
 *
 *   cd tenuo-ts && pnpm example:mcp
 */
import { createTenuo } from "../../src/index.ts";
import { exportSession } from "../../src/testkit.ts";
import { attachRead, createMcpClient } from "./client.ts";
import { createReadFileHandler } from "./server.ts";

export async function runMcpSmoke(): Promise<void> {
  const { tenuo, session } = createMcpClient();
  const leaked = exportSession(session);
  const readFile = createReadFileHandler(leaked.root_hex);

  const allowed = attachRead(tenuo, session, "/data/q3.pdf");
  const ok = await readFile(allowed.arguments as { path: string }, { _meta: allowed._meta });
  if (ok !== "contents of /data/q3.pdf") {
    throw new Error(`expected allowed read, got ${String(ok)}`);
  }

  try {
    attachRead(tenuo, session, "/etc/passwd");
    throw new Error("denied path left the client");
  } catch (error) {
    if (error instanceof Error && error.message === "denied path left the client") {
      throw error;
    }
  }

  let executed = false;
  const server = createTenuo({
    trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
  });
  const guarded = server.mcp.handler("read_file", async ({ path }: { path: string }) => {
    executed = true;
    return path;
  });
  try {
    await guarded({ path: "/etc/passwd" }, { _meta: allowed._meta });
    throw new Error("forged args were accepted");
  } catch (error) {
    if (error instanceof Error && error.message === "forged args were accepted") {
      throw error;
    }
    const code = (error as { code?: string }).code;
    if (code !== "TENUO_INVALID_POP") {
      throw new Error(`expected TENUO_INVALID_POP, got ${String(code)}`);
    }
  }
  if (executed) {
    throw new Error("handler ran on a forged call");
  }
}

const launchedDirectly = process.argv[1]?.includes("examples/mcp/smoke");
if (launchedDirectly) {
  runMcpSmoke()
    .then(() => {
      process.stdout.write("mcp smoke: allow / deny / forged-args ok\n");
    })
    .catch((error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(1);
    });
}
