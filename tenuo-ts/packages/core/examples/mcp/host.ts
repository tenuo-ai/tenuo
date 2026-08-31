/**
 * v1 recipe (not a supported adapter): `@modelcontextprotocol/sdk` +
 * `tenuo.mcp.verify`. Dev-only — not a dependency of `@tenuo/core`.
 *
 * For `@modelcontextprotocol/server` v2, use `@tenuo/mcp` (`guardTools`).
 *
 * Zod here is the host schema (valid). `tenuo.mcp.verify({ allow })` is the ceiling.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  createTenuo,
  email,
  pattern,
  TenuoError,
  under,
  type AllowPolicy,
  type Tenuo,
} from "../../src/index.ts";
import { createWorkspace, type Workspace } from "./workspace.ts";

export type HostCallResult = {
  readonly isError: boolean;
  readonly text: string;
  readonly rpc?: { readonly code: number; readonly message: string; readonly data?: { readonly tenuo?: { readonly code: string } } };
};

export type ReportsHost = {
  readonly client: Client;
  readonly tenuo: Tenuo;
  readonly workspace: Workspace;
  readonly receipts: string[];
  readonly executed: string[];
  call(
    name: string,
    args: Readonly<Record<string, unknown>>,
    meta?: unknown,
  ): Promise<HostCallResult>;
  close(): Promise<void>;
};

export async function startReportsHost(options: {
  readonly rootHex: string;
  readonly revocationList?: string;
}): Promise<ReportsHost> {
  const tenuo = createTenuo({
    trustedRoots: [createTenuo.publicKeyFromHex(options.rootHex)],
    ...(options.revocationList !== undefined ? { revocationList: options.revocationList } : {}),
  });
  const workspace = createWorkspace();
  const receipts: string[] = [];
  const executed: string[] = [];

  const mcp = new McpServer({ name: "tenuo-reports", version: "0.2.3" });
  register(
    mcp,
    tenuo,
    "list_directory",
    { path: z.string() },
    { path: under("/workspace") },
    receipts,
    executed,
    async ({ path }) => workspace.list(String(path)),
  );
  register(
    mcp,
    tenuo,
    "read_file",
    { path: z.string() },
    { path: under("/workspace") },
    receipts,
    executed,
    async ({ path }) => workspace.read(String(path)),
  );
  register(
    mcp,
    tenuo,
    "write_file",
    { path: z.string(), content: z.string() },
    { path: under("/workspace/drafts"), content: pattern("*") },
    receipts,
    executed,
    async ({ path, content }) => workspace.write(String(path), String(content)),
  );
  register(
    mcp,
    tenuo,
    "send_email",
    { to: z.string(), subject: z.string(), body: z.string() },
    {
      to: email({ domain: "acme.com" }),
      subject: pattern("*"),
      body: pattern("*"),
    },
    receipts,
    executed,
    async ({ to, subject, body }) =>
      workspace.send({ to: String(to), subject: String(subject), body: String(body) }),
  );

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "tenuo-agent", version: "0.2.3" });
  await Promise.all([mcp.connect(serverTransport), client.connect(clientTransport)]);

  return {
    client,
    tenuo,
    workspace,
    receipts,
    executed,
    async call(name, args, meta) {
      const result = await client.callTool({
        name,
        arguments: { ...args },
        ...(meta !== undefined ? { _meta: meta as Record<string, unknown> } : {}),
      });
      const text = toolText(result);
      const isError = "isError" in result && result.isError === true;
      if (isError) {
        const rpc = parseRpc(text);
        return rpc !== undefined ? { isError: true, text, rpc } : { isError: true, text };
      }
      return { isError: false, text };
    },
    async close() {
      await Promise.all([client.close(), mcp.close()]);
    },
  };
}

function register(
  mcp: McpServer,
  tenuo: Tenuo,
  name: string,
  inputSchema: Record<string, z.ZodType>,
  allow: AllowPolicy,
  receipts: string[],
  executed: string[],
  run: (args: Record<string, unknown>) => Promise<unknown>,
): void {
  mcp.registerTool(
    name,
    {
      description: `Tenuo-guarded ${name}`,
      inputSchema,
    },
    async (args, extra) => {
      try {
        const authorized = await tenuo.mcp.verify(name, args as Record<string, unknown>, extra._meta, {
          allow,
          onReceipt: (receipt) => {
            receipts.push(receipt);
          },
        });
        executed.push(name);
        const value = await run(authorized);
        return {
          content: [{ type: "text" as const, text: stringify(value) }],
        };
      } catch (error) {
        if (error instanceof TenuoError) {
          return {
            isError: true,
            content: [{ type: "text" as const, text: JSON.stringify(tenuo.mcp.jsonRpcError(error)) }],
          };
        }
        return {
          isError: true,
          content: [{ type: "text" as const, text: "Tool execution failed" }],
        };
      }
    },
  );
}

function toolText(result: unknown): string {
  if (result === null || typeof result !== "object" || !("content" in result)) {
    return "";
  }
  const content = (result as { content?: unknown }).content;
  if (!Array.isArray(content) || content[0] === undefined || typeof content[0] !== "object") {
    return "";
  }
  const first = content[0] as { text?: unknown };
  return typeof first.text === "string" ? first.text : "";
}

function parseRpc(text: string): HostCallResult["rpc"] {
  try {
    return JSON.parse(text) as HostCallResult["rpc"];
  } catch {
    return undefined;
  }
}

function stringify(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}
