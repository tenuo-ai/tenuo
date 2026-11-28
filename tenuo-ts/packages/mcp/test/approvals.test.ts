import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { createTenuo, max, memoryNonceStore, type NonceStore } from "@tenuo/core";
import { guardTools } from "../src/index.ts";

const closers: (() => Promise<void>)[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(closers.splice(0).map((close) => close()));
});

async function boot(nonceStore?: NonceStore) {
  const cp = createTenuo({ root: createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey()) });
  const serverTenuo = createTenuo({ trustedRoots: [cp.issuerPublicKey()] });
  const server = new McpServer({ name: "payments", version: "1" });
  const executed: number[] = [];
  guardTools(serverTenuo, server).register(
    "transfer",
    {
      description: "Send money",
      inputSchema: z.object({ amount: z.number() }),
      allow: { amount: max(100_000) },
      ...(nonceStore !== undefined ? { nonceStore } : {}),
    },
    async ({ amount }) => {
      executed.push(amount);
      return { content: [{ type: "text", text: "sent" }] };
    },
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "agent", version: "1" });
  await client.connect(clientTransport);
  closers.push(() => client.close());

  const approverKey = createTenuo.generateHolderKey();
  const holderKey = createTenuo.generateHolderKey();
  const agent = createTenuo({ trustedRoots: [cp.issuerPublicKey()] });
  const session = agent.sessionFromWire({
    warrant: cp
      .session({
        allow: { transfer: { amount: max(100_000) } },
        holder: createTenuo.publicKeyFromHolderKey(holderKey),
        requireApproval: {
          approvers: [createTenuo.publicKeyFromHolderKey(approverKey)],
          min: 1,
          tools: ["transfer"],
        },
      })
      .toWireString(),
    holderKey,
  });
  const approve = (amount: number) =>
    createTenuo.signApproval(agent.approvalRequest(session, "transfer", { amount }), approverKey, {
      externalId: "alice",
    });
  const approval = approve(5000);
  async function call(atMs: number, amount = 5000, approvals: readonly string[] = [approval]) {
    vi.spyOn(Date, "now").mockReturnValue(atMs);
    const attached = agent.mcp.attach(session, "transfer", { amount }, { approvals });
    const result = await client.callTool({ name: "transfer", arguments: attached.arguments, _meta: attached._meta });
    vi.restoreAllMocks();
    return { isError: result.isError === true, text: JSON.stringify(result.content) };
  }
  return { call, executed, approve };
}

describe("approval-gated MCP tools with a nonce store", () => {
  it("a freshly signed PoP over a used approval is refused; the handler runs once", async () => {
    const { call, executed } = await boot(memoryNonceStore());
    const now = Date.now();
    expect((await call(now)).isError).toBe(false);
    // Next 30-second PoP window: a new PoP signature, the same approval envelope.
    const replay = await call(now + 30_000);
    expect(replay.isError).toBe(true);
    expect(replay.text).toMatch(/TENUO_INSUFFICIENT_APPROVALS/);
    expect(executed).toEqual([5000]);
  });

  it("only consumes the approvals bound to the verified call", async () => {
    const { call, executed, approve } = await boot(memoryNonceStore());
    const now = Date.now();
    const forLater = approve(7000);
    expect((await call(now, 5000, [forLater, approve(5000)])).isError).toBe(false);
    expect((await call(now + 1000, 7000, [forLater])).isError).toBe(false);
    expect(executed).toEqual([5000, 7000]);
  });

  it("without a nonce store the approval is reusable in-window (documented default)", async () => {
    const { call, executed } = await boot();
    const now = Date.now();
    expect((await call(now)).isError).toBe(false);
    expect((await call(now + 30_000)).isError).toBe(false);
    expect(executed).toEqual([5000, 5000]);
  });
});
