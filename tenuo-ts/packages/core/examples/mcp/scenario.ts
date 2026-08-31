/**
 * Quarterly close: orchestrator, researcher, and writer talk to one MCP server.
 *
 * Two process roles share this file so the demo does not need the official MCP SDK.
 * The issuer public key is published to the server the same way production would
 * set TENUO_ROOT_PUBLIC_KEY. The holder secret never leaves the client.
 */
import {
  ApprovalRequiredError,
  createTenuo,
  TenuoError,
  type Session,
  type Tenuo,
} from "../../src/index.ts";
import { exportSession, signApproval } from "../../src/testkit.ts";
import {
  createIssuer,
  mintOrchestrator,
  narrowResearcher,
  narrowWriter,
  toolsCall,
} from "./client.ts";
import { createReportsServer, type JsonRpcRequest, type JsonRpcResponse } from "./server.ts";

/** Published spec approver (seed 0x11). Demo only — not a production key. */
const FINANCE_APPROVER_PUB = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const FINANCE_APPROVER_SECRET = new Uint8Array(32).fill(0x11);

export type CloseDenial = {
  readonly step: string;
  readonly code: string;
  readonly rpc: number;
};

export type QuarterlyCloseResult = {
  readonly listed: string[];
  readonly revenue: string;
  readonly draft: { readonly path: string; readonly bytes: number };
  readonly emailed: { readonly to: string; readonly subject: string };
  readonly denials: readonly CloseDenial[];
};

export async function runQuarterlyClose(
  log: (line: string) => void = () => {},
): Promise<QuarterlyCloseResult> {
  const issuer = createIssuer();
  const orchestrator = mintOrchestrator(issuer, createTenuo.publicKeyFromHex(FINANCE_APPROVER_PUB));
  const published = exportSession(orchestrator);
  const server = createReportsServer(published.root_hex);
  const researcher = narrowResearcher(issuer, orchestrator);
  const writer = narrowWriter(issuer, orchestrator);
  const denials: CloseDenial[] = [];

  log("Quarterly close — MCP tools with per-agent warrants");
  log("Issuer minted a 15-minute orchestrator session.");
  log("  read/list /workspace · write /workspace/drafts · email @acme.com (approval-gated)");
  log("Server loaded the issuer public key only. No holder secret.");
  log("Researcher narrowed to /workspace/reports. Writer narrowed to /workspace/drafts.");

  const listed = await expectResult<string[]>(
    server.dispatch(toolsCall(issuer, researcher, "list_directory", { path: "/workspace/reports" })),
    "list reports",
  );
  log(`list_directory /workspace/reports → ${listed.join(", ")}`);

  const revenue = await expectResult<string>(
    server.dispatch(
      toolsCall(issuer, researcher, "read_file", { path: "/workspace/reports/q3-revenue.md" }),
    ),
    "read q3 revenue",
  );
  log("read_file /workspace/reports/q3-revenue.md → allowed");

  denials.push(
    clientRefused(issuer, researcher, "read_file", { path: "/workspace/hr/salaries.csv" }, log),
  );

  const draft = await expectResult<{ path: string; bytes: number }>(
    server.dispatch(
      toolsCall(issuer, writer, "write_file", {
        path: "/workspace/drafts/q3-summary.md",
        content: `${revenue}\n\nPrepared for finance.\n`,
      }),
    ),
    "write draft",
  );
  log(`write_file ${draft.path} → ${String(draft.bytes)} bytes`);

  denials.push(
    clientRefused(
      issuer,
      writer,
      "write_file",
      { path: "/workspace/reports/q3-revenue.md", content: "overwrite" },
      log,
    ),
  );

  const emailArgs = {
    to: "finance@acme.com",
    subject: "Q3 summary",
    body: "Draft is in /workspace/drafts/q3-summary.md",
  };
  denials.push(clientRefused(issuer, orchestrator, "send_email", emailArgs, log));

  const approval = signApproval(orchestrator, "send_email", emailArgs, FINANCE_APPROVER_SECRET);
  const emailed = await expectResult<{ to: string; subject: string }>(
    server.dispatch(toolsCall(issuer, orchestrator, "send_email", emailArgs, { approvals: [approval] })),
    "send email with approval",
  );
  log(`send_email ${emailed.to} → sent after 1 approval`);

  const honest = toolsCall(issuer, researcher, "read_file", {
    path: "/workspace/reports/q3-revenue.md",
  });
  const forged: JsonRpcRequest = {
    ...honest,
    params: {
      ...honest.params,
      arguments: { path: "/workspace/hr/salaries.csv" },
    },
  };
  const tampered = await server.dispatch(forged);
  denials.push(rpcDenial("forged args after attach", tampered, log));
  if (server.workspace.sent().length !== 1) {
    throw new Error("forged call must not send mail or mutate the workspace");
  }

  return { listed, revenue, draft, emailed, denials };
}

function clientRefused(
  tenuo: Tenuo,
  session: Session,
  name: string,
  args: Readonly<Record<string, unknown>>,
  log: (line: string) => void,
): CloseDenial {
  try {
    toolsCall(tenuo, session, name, args);
    throw new Error(`${name} left the client`);
  } catch (error) {
    if (error instanceof Error && error.message.endsWith("left the client")) {
      throw error;
    }
    const mapped = tenuo.mcp.jsonRpcError(error);
    const code = error instanceof TenuoError ? error.code : "TENUO_TOOL_NOT_AUTHORIZED";
    const expected =
      name === "send_email" ? "TENUO_APPROVAL_REQUIRED" : "TENUO_CONSTRAINT_VIOLATION";
    if (code !== expected) {
      throw new Error(`${name}: expected ${expected}, got ${code}`);
    }
    if (name === "send_email" && !(error instanceof ApprovalRequiredError)) {
      throw new Error("send_email must fail as ApprovalRequiredError before it leaves the client");
    }
    log(`${name} ${summarize(args)} → client refused ${code} (${String(mapped.code)})`);
    return { step: name, code, rpc: mapped.code };
  }
}

async function expectResult<T>(response: Promise<JsonRpcResponse>, step: string): Promise<T> {
  const resolved = await response;
  if ("error" in resolved) {
    throw new Error(`${step} failed: ${resolved.error.message}`);
  }
  return resolved.result as T;
}

function rpcDenial(step: string, response: JsonRpcResponse, log: (line: string) => void): CloseDenial {
  if (!("error" in response)) {
    throw new Error(`${step} was accepted`);
  }
  const code = response.error.data?.tenuo?.code ?? "TENUO_TOOL_NOT_AUTHORIZED";
  if (code !== "TENUO_INVALID_POP") {
    throw new Error(`${step}: expected TENUO_INVALID_POP, got ${code}`);
  }
  log(`${step} → server refused ${code} (${String(response.error.code)}); handler did not run`);
  return { step, code, rpc: response.error.code };
}

function summarize(args: Readonly<Record<string, unknown>>): string {
  if (typeof args.path === "string") {
    return args.path;
  }
  if (typeof args.to === "string") {
    return args.to;
  }
  return "";
}
