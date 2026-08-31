/**
 * MCP server process: trusted root only. Handlers do not run unless Rust allowed.
 *
 * After `npm i @tenuo/core`, change the import to `from "@tenuo/core"`.
 * Production loads `TENUO_ROOT_PUBLIC_KEY`. There is no MCP SDK dependency —
 * pass `params._meta` through from whatever host you use.
 */
import { createTenuo, email, pattern, under, type Tenuo } from "../../src/index.ts";
import { createWorkspace, type Workspace } from "./workspace.ts";

export type JsonRpcRequest = {
  readonly jsonrpc: "2.0";
  readonly id: number;
  readonly method: "tools/call";
  readonly params: {
    readonly name: string;
    readonly arguments: Readonly<Record<string, unknown>>;
    readonly _meta?: unknown;
  };
};

export type JsonRpcResponse =
  | { readonly jsonrpc: "2.0"; readonly id: number; readonly result: unknown }
  | {
      readonly jsonrpc: "2.0";
      readonly id: number;
      readonly error: ReturnType<Tenuo["mcp"]["jsonRpcError"]>;
    };

export type ReportsServer = {
  readonly tenuo: Tenuo;
  readonly workspace: Workspace;
  dispatch(request: JsonRpcRequest): Promise<JsonRpcResponse>;
};

export function createReportsServer(rootHex: string): ReportsServer {
  const tenuo = createTenuo({
    trustedRoots: [createTenuo.publicKeyFromHex(rootHex)],
  });
  const workspace = createWorkspace();

  const listDirectory = tenuo.mcp.handler(
    "list_directory",
    { allow: { path: under("/workspace") } },
    async ({ path }: { path: string }) => workspace.list(path),
  );
  const readFile = tenuo.mcp.handler(
    "read_file",
    { allow: { path: under("/workspace") } },
    async ({ path }: { path: string }) => workspace.read(path),
  );
  const writeFile = tenuo.mcp.handler(
    "write_file",
    { allow: { path: under("/workspace/drafts"), content: pattern("*") } },
    async ({ path, content }: { path: string; content: string }) => workspace.write(path, content),
  );
  const sendEmail = tenuo.mcp.handler(
    "send_email",
    {
      allow: {
        to: email({ domain: "acme.com" }),
        subject: pattern("*"),
        body: pattern("*"),
      },
    },
    async ({ to, subject, body }: { to: string; subject: string; body: string }) =>
      workspace.send({ to, subject, body }),
  );

  const tools: Record<
    string,
    (args: Record<string, unknown>, extra?: { readonly _meta?: unknown }) => Promise<unknown>
  > = {
    list_directory: (args, extra) => listDirectory(args as { path: string }, extra),
    read_file: (args, extra) => readFile(args as { path: string }, extra),
    write_file: (args, extra) => writeFile(args as { path: string; content: string }, extra),
    send_email: (args, extra) => sendEmail(args as { to: string; subject: string; body: string }, extra),
  };

  return {
    tenuo,
    workspace,
    async dispatch(request) {
      const tool = tools[request.params.name];
      if (tool === undefined) {
        return {
          jsonrpc: "2.0",
          id: request.id,
          error: { code: -32001, message: `unknown tool: ${request.params.name}` },
        };
      }
      try {
        const result = await tool(
          { ...request.params.arguments },
          { _meta: request.params._meta },
        );
        return { jsonrpc: "2.0", id: request.id, result };
      } catch (error) {
        return { jsonrpc: "2.0", id: request.id, error: tenuo.mcp.jsonRpcError(error) };
      }
    },
  };
}
