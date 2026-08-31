/**
 * Issuer + agent roles. Attach locally, then send warrant + PoP on `_meta.tenuo`.
 *
 * After `npm i @tenuo/core`, change the import to `from "@tenuo/core"`.
 */
import {
  createTenuo,
  email,
  pattern,
  under,
  type McpAttachOptions,
  type McpCallParams,
  type PublicKeyHandle,
  type Session,
  type Tenuo,
} from "../../src/index.ts";
import type { JsonRpcRequest } from "./server.ts";

export function createIssuer(): Tenuo {
  return createTenuo({ root: createTenuo.devRoot() });
}

/** Orchestrator may read the workspace, write drafts, and email @acme.com (gated). */
export function mintOrchestrator(issuer: Tenuo, financeApprover: PublicKeyHandle): Session {
  return issuer.session({
    allow: {
      list_directory: { path: under("/workspace") },
      read_file: { path: under("/workspace") },
      write_file: { path: under("/workspace/drafts"), content: pattern("*") },
      send_email: {
        to: email({ domain: "acme.com" }),
        subject: pattern("*"),
        body: pattern("*"),
      },
    },
    requireApproval: {
      approvers: [financeApprover],
      min: 1,
      tools: ["send_email"],
    },
    ttlSeconds: 900,
  });
}

/** Researcher: reports only. Write and email drop off the child warrant. */
export function narrowResearcher(issuer: Tenuo, orchestrator: Session): Session {
  return issuer.narrow(orchestrator, {
    list_directory: { path: under("/workspace/reports") },
    read_file: { path: under("/workspace/reports") },
  });
}

/** Writer: drafts only. */
export function narrowWriter(issuer: Tenuo, orchestrator: Session): Session {
  return issuer.narrow(orchestrator, {
    write_file: { path: under("/workspace/drafts"), content: pattern("*") },
  });
}

let nextId = 1;

/** Authorize on the client, then wrap as an MCP `tools/call` JSON-RPC request. */
export function toolsCall(
  tenuo: Tenuo,
  session: Session,
  name: string,
  args: Readonly<Record<string, unknown>>,
  options?: McpAttachOptions,
): JsonRpcRequest {
  const attached: McpCallParams = tenuo.mcp.attach(session, name, args, options);
  const id = nextId;
  nextId += 1;
  return {
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: {
      name: attached.name,
      arguments: attached.arguments,
      _meta: attached._meta,
    },
  };
}
