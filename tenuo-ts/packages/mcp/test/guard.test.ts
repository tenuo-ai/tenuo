import { afterEach, describe, expect, expectTypeOf, it } from "vitest";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { createTenuo, memoryNonceStore, TenuoConfigurationError, under } from "@tenuo/core";
import { guardHandler, guardTools, requestMeta, type InferToolArgs } from "../src/index.ts";

type Rpc = { code: number; data?: { tenuo?: { code: string } } };

type Harness = {
  close(): Promise<void>;
  call(
    name: string,
    args: Record<string, unknown>,
    meta?: unknown,
  ): Promise<{ isError: boolean; text: string; rpc?: Rpc }>;
};

const harnesses: Harness[] = [];

describe("@tenuo/mcp v2 adapter", () => {

  afterEach(async () => {
    await Promise.all(harnesses.splice(0).map((item) => item.close()));
  });

  it("allows an attached call and runs the handler with authorized args", async () => {
    const { issuer, session, host, executed } = await boot();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    const result = await host.call(call.name, { ...call.arguments }, call._meta);
    expect(result.isError).toBe(false);
    expect(result.text).toBe("/data/q3.pdf");
    expect(executed).toEqual(["/data/q3.pdf"]);
  });

  it("fails closed without _meta.tenuo and never runs the handler", async () => {
    const { host, executed } = await boot();
    const result = await host.call("read_file", { path: "/data/q3.pdf" });
    expect(result.isError).toBe(true);
    expect(result.rpc).toMatchObject({ code: -32001 });
    expect(executed).toEqual([]);
  });

  it("rejects forged arguments after attach", async () => {
    const { issuer, session, host, executed } = await boot();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    const result = await host.call(call.name, { path: "/etc/passwd" }, call._meta);
    expect(result.rpc).toMatchObject({
      code: -32001,
      data: { tenuo: { code: "TENUO_INVALID_POP" } },
    });
    expect(executed).toEqual([]);
  });

  it("ANDs register allow with a broader warrant", async () => {
    const { issuer, session, host, executed } = await boot({
      allow: { path: under("/data/reports") },
    });
    const outside = issuer.mcp.attach(session, "read_file", { path: "/data/other.txt" });
    const denied = await host.call(outside.name, { ...outside.arguments }, outside._meta);
    expect(denied.rpc).toMatchObject({
      code: -32001,
      data: { tenuo: { code: "TENUO_CONSTRAINT_VIOLATION" } },
    });
    expect(executed).toEqual([]);

    const inside = issuer.mcp.attach(session, "read_file", { path: "/data/reports/q3.pdf" });
    const allowed = await host.call(inside.name, { ...inside.arguments }, inside._meta);
    expect(allowed.isError).toBe(false);
    expect(allowed.text).toBe("/data/reports/q3.pdf");
    expect(executed).toEqual(["/data/reports/q3.pdf"]);
  });

  it("treats empty allow as no extra ceiling", async () => {
    const { issuer, session, host } = await boot({ allow: {} });
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/other.txt" });
    const result = await host.call(call.name, { ...call.arguments }, call._meta);
    expect(result.isError).toBe(false);
    expect(result.text).toBe("/data/other.txt");
  });

  it("wraps a raw registerTool callback with guardHandler", async () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const session = issuer.session({
      allow: { read_file: { path: under("/data") } },
    });
    const executed: string[] = [];
    const server = new McpServer({ name: "tenuo-raw", version: "0.2.3" });
    server.registerTool(
      "read_file",
      {
        description: "raw",
        inputSchema: z.object({ path: z.string() }),
      },
      guardHandler(issuer, "read_file", { allow: { path: under("/data") } }, async ({ path }) => {
        executed.push(path);
        return { content: [{ type: "text", text: path }] };
      }) as never,
    );
    const host = await connect(server);
    harnesses.push(host);
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    await expect(host.call(call.name, { ...call.arguments }, call._meta)).resolves.toMatchObject({
      isError: false,
      text: "/data/q3.pdf",
    });
    expect(executed).toEqual(["/data/q3.pdf"]);
  });

  it("forwards register onReceipt", async () => {
    const receipts: string[] = [];
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const session = issuer.session({
      allow: { read_file: { path: under("/data") } },
    });
    const server = new McpServer({ name: "tenuo-receipts", version: "0.2.3" });
    const tools = guardTools(issuer, server);
    tools.register(
      "read_file",
      {
        description: "Read a file",
        inputSchema: z.object({ path: z.string() }),
        allow: { path: under("/data") },
        onReceipt: (receipt) => { receipts.push(receipt); },
      },
      async ({ path }: { path: string }) => ({ content: [{ type: "text", text: path }] }),
    );
    const host = await connect(server);
    harnesses.push(host);
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    await host.call(call.name, { ...call.arguments }, call._meta);
    expect(receipts).toHaveLength(1);
  });

  it("sanitizes a handler throw so the official transport cannot see it", async () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const session = issuer.session({
      allow: { read_file: { path: under("/data") } },
    });
    const server = new McpServer({ name: "tenuo-leak", version: "0.2.3" });
    const tools = guardTools(issuer, server);
    tools.register(
      "read_file",
      {
        inputSchema: z.object({ path: z.string() }),
        allow: { path: under("/data") },
      },
      async () => {
        throw new Error("DB password=hunter2 at /srv/internal/db.ts:88");
      },
    );
    const host = await connect(server);
    harnesses.push(host);
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    const result = await host.call(call.name, { ...call.arguments }, call._meta);
    expect(result.isError).toBe(true);
    expect(result.text).toBe("Tool execution failed");
    expect(result.text).not.toMatch(/hunter2/);
    expect(result.rpc).toBeUndefined();
  });

  it("rejects option typos instead of asking for a handler", () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    expect(() =>
      guardHandler(issuer, "read_file", { allowed: { path: under("/data") } } as never, async () => ({
        content: [],
      })),
    ).toThrow(TenuoConfigurationError);
    expect(() =>
      guardHandler(issuer, "read_file", { allowed: { path: under("/data") } } as never, async () => ({
        content: [],
      })),
    ).toThrow(/unknown key 'allowed'/);
    expect(() =>
      guardHandler(
        issuer,
        "read_file",
        { allow: { path: under("/data") }, nonceStroe: memoryNonceStore() } as never,
        async () => ({ content: [] }),
      ),
    ).toThrow(/unknown key 'nonceStroe'/);
  });

  it("infers register handler args from a Zod inputSchema", () => {
    type Schema = ReturnType<typeof z.object<{ path: z.ZodString }>>;
    expectTypeOf<InferToolArgs<z.ZodObject<{ path: z.ZodString }>>>().toMatchTypeOf<{ path: string }>();
    expectTypeOf<InferToolArgs<Schema>>().toHaveProperty("path");
  });

  it("rejects a replayed envelope when nonceStore is set", async () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const session = issuer.session({
      allow: { read_file: { path: under("/data") } },
    });
    const store = memoryNonceStore();
    const handler = guardHandler(issuer, "read_file", { allow: { path: under("/data") }, nonceStore: store }, async ({
      path,
    }) => ({ content: [{ type: "text", text: path }] }));
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    const first = await handler(call.arguments as { path: string }, { mcpReq: { _meta: call._meta } });
    expect(first.isError).not.toBe(true);
    const second = await handler(call.arguments as { path: string }, { mcpReq: { _meta: call._meta } });
    expect(second.isError).toBe(true);
    expect(String(second.content?.[0]?.text)).toMatch(/replay/);
  });

  it("reads _meta from v2 ctx.mcpReq and v1 extra._meta", () => {
    const tenuo = { tenuo: { warrant: "w", signature: "s" } };
    expect(requestMeta({ mcpReq: { _meta: tenuo } })).toEqual(tenuo);
    expect(requestMeta({ _meta: tenuo })).toEqual(tenuo);
  });
});

async function boot(options?: { allow?: { path?: ReturnType<typeof under> } }): Promise<{
  issuer: ReturnType<typeof createTenuo>;
  session: ReturnType<ReturnType<typeof createTenuo>["session"]>;
  host: Harness;
  executed: string[];
}> {
  const issuer = createTenuo({ root: createTenuo.devRoot() });
  const session = issuer.session({
    allow: { read_file: { path: under("/data") } },
  });
  const executed: string[] = [];
  const server = new McpServer({ name: "tenuo-adapter", version: "0.2.3" });
  const tools = guardTools(issuer, server);
  tools.register(
    "read_file",
    {
      description: "Read a file",
      inputSchema: z.object({ path: z.string() }),
      ...(options?.allow !== undefined ? { allow: options.allow } : { allow: { path: under("/data") } }),
    },
    async ({ path }: { path: string }) => {
      executed.push(path);
      return { content: [{ type: "text", text: path }] };
    },
  );
  const host = await connect(server);
  harnesses.push(host);
  return { issuer, session, host, executed };
}

async function connect(server: McpServer): Promise<Harness> {
  const handler = createMcpHandler(() => server);
  const transport = new StreamableHTTPClientTransport(new URL("http://test.local/mcp"), {
    fetch: (url, init) => handler.fetch(new Request(url, init)),
  });
  const client = new Client({ name: "tenuo-adapter-test", version: "0.2.3" }, { versionNegotiation: { mode: "auto" } });
  await client.connect(transport);
  return {
    async call(name, args, meta) {
      const result = await client.callTool({
        name,
        arguments: args,
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
      await client.close();
      await handler.close();
    },
  };
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

function parseRpc(text: string): Rpc | undefined {
  try {
    return JSON.parse(text) as Rpc;
  } catch {
    return undefined;
  }
}
