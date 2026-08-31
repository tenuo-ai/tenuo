import { afterEach, describe, expect, it } from "vitest";
import {
  ApprovalRequiredError,
  AuthorizationDeniedError,
  createTenuo,
  under,
  type Session,
  type Tenuo,
} from "../src/index.ts";
import {
  createIssuer,
  mintOrchestrator,
  narrowResearcher,
  narrowWriter,
} from "../examples/mcp/client.ts";
import { startReportsHost, type ReportsHost } from "../examples/mcp/host.ts";
import {
  devContext,
  exportSession,
  signApproval,
  signRevocationList,
  verifyReceipt,
  warrantIds,
  wrapSession,
} from "../src/testkit.ts";
import { APPROVER1_PUB, APPROVER1_SECRET } from "./vectors/spec.ts";

const EMAIL = {
  to: "finance@acme.com",
  subject: "Q3 summary",
  body: "Draft is in /workspace/drafts/q3-summary.md",
};

describe("official MCP host smoke", () => {
  const hosts: ReportsHost[] = [];

  afterEach(async () => {
    await Promise.all(hosts.splice(0).map((host) => host.close()));
  });

  async function boot() {
    const issuer = createIssuer();
    const orchestrator = mintOrchestrator(issuer, createTenuo.publicKeyFromHex(APPROVER1_PUB));
    const published = exportSession(orchestrator);
    const host = await startReportsHost({ rootHex: published.root_hex });
    hosts.push(host);
    return { issuer, orchestrator, published, host };
  }

  it("discovers tools and allows an attached read through the real host", async () => {
    const { issuer, orchestrator, host } = await boot();
    const tools = await host.client.listTools();
    expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
      "list_directory",
      "read_file",
      "send_email",
      "write_file",
    ]);

    const researcher = narrowResearcher(issuer, orchestrator);
    const listed = await call(issuer, researcher, host, "list_directory", {
      path: "/workspace/reports",
    });
    expect(listed.isError).toBe(false);
    expect(JSON.parse(listed.text)).toEqual(["q3-customers.md", "q3-revenue.md"]);

    const revenue = await call(issuer, researcher, host, "read_file", {
      path: "/workspace/reports/q3-revenue.md",
    });
    expect(revenue.text).toContain("North America: $4.2M");
    expect(host.executed).toEqual(["list_directory", "read_file"]);
  });

  it("keeps out-of-scope and unapproved calls off the host", async () => {
    const { issuer, orchestrator } = await boot();
    const researcher = narrowResearcher(issuer, orchestrator);
    expect(() =>
      issuer.mcp.attach(researcher, "read_file", { path: "/workspace/hr/salaries.csv" }),
    ).toThrow(AuthorizationDeniedError);
    expect(() => issuer.mcp.attach(orchestrator, "send_email", EMAIL)).toThrow(ApprovalRequiredError);
  });

  it("narrows a writer, then sends email only after a signed approval", async () => {
    const { issuer, orchestrator, host } = await boot();
    const writer = narrowWriter(issuer, orchestrator);
    const wrote = await call(issuer, writer, host, "write_file", {
      path: "/workspace/drafts/q3-summary.md",
      content: "Prepared for finance.",
    });
    expect(wrote.isError).toBe(false);
    expect(JSON.parse(wrote.text)).toMatchObject({ path: "/workspace/drafts/q3-summary.md" });

    expect(() =>
      issuer.mcp.attach(writer, "write_file", {
        path: "/workspace/reports/q3-revenue.md",
        content: "overwrite",
      }),
    ).toThrow(AuthorizationDeniedError);

    const approval = signApproval(orchestrator, "send_email", EMAIL, APPROVER1_SECRET);
    const sent = await call(issuer, orchestrator, host, "send_email", EMAIL, [approval]);
    expect(sent.isError).toBe(false);
    expect(JSON.parse(sent.text)).toMatchObject({ to: "finance@acme.com" });
    expect(host.workspace.sent()).toHaveLength(1);
  });

  it("imports sessionFromWire and verifies a narrowed chain on the host", async () => {
    const { issuer, orchestrator, published, host } = await boot();
    const reports = issuer.narrow(orchestrator, {
      list_directory: { path: under("/workspace/reports") },
      read_file: { path: under("/workspace/reports") },
    });
    const tokens = reports.toWire();
    expect(tokens.length).toBeGreaterThan(1);

    const worker = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(published.root_hex)],
    });
    const imported = worker.sessionFromWire({
      warrant: tokens,
      holderKey: createTenuo.holderKeyFromHex(published.holder_hex),
    });
    const result = await call(worker, imported, host, "read_file", {
      path: "/workspace/reports/q3-customers.md",
    });
    expect(result.text).toContain("Acme Health");
  });

  it("fails closed on missing _meta and forged arguments", async () => {
    const { issuer, orchestrator, host } = await boot();
    const researcher = narrowResearcher(issuer, orchestrator);

    const missing = await host.call("read_file", { path: "/workspace/reports/q3-revenue.md" });
    expect(missing.rpc).toMatchObject({ code: -32001 });
    expect(host.executed).toEqual([]);

    const honest = issuer.mcp.attach(researcher, "read_file", {
      path: "/workspace/reports/q3-revenue.md",
    });
    const forged = await host.call(honest.name, { path: "/workspace/hr/salaries.csv" }, honest._meta);
    expect(forged.rpc).toMatchObject({
      code: -32001,
      data: { tenuo: { code: "TENUO_INVALID_POP" } },
    });
    expect(host.executed).toEqual([]);
  });

  it("denies a revoked warrant on the host and records a deny receipt", async () => {
    const ctx = devContext();
    const session = wrapSession(
      ctx.mint({ read_file: { path: { kind: "under", root: "/workspace/reports" } } }, 300),
    );
    const published = exportSession(session);
    const leafId = warrantIds(session)[0];
    if (leafId === undefined) {
      throw new Error("expected a warrant id");
    }
    const srl = signRevocationList(ctx, [leafId]);
    const host = await startReportsHost({
      rootHex: published.root_hex,
      revocationList: srl,
    });
    hosts.push(host);

    const worker = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(published.root_hex)],
    });
    const imported = worker.sessionFromWire({
      warrant: published.warrants,
      holderKey: createTenuo.holderKeyFromHex(published.holder_hex),
    });
    const call = worker.mcp.attach(imported, "read_file", {
      path: "/workspace/reports/q3-revenue.md",
    });
    const revoked = await host.call(call.name, call.arguments, call._meta);
    expect(revoked.rpc).toMatchObject({
      code: -32001,
      data: { tenuo: { code: "TENUO_REVOKED" } },
    });
    expect(host.executed).toEqual([]);
    expect(host.receipts).toHaveLength(1);
    expect(verifyReceipt(host.receipts[0]!)).toMatchObject({
      authentic: true,
      outcome: "deny",
    });
  });

  it("ANDs tenuo.tool allow with a wider session", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    let ran = 0;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }) => {
          ran += 1;
          return path;
        },
      },
      { capability: "read_file", allow: { path: under("/workspace/reports") } },
    );
    const session = tenuo.session({
      allow: { read_file: { path: under("/workspace") } },
    });
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/workspace/reports/q3.md" })),
    ).resolves.toBe("/workspace/reports/q3.md");
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/workspace/hr/salaries.csv" })),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
    expect(ran).toBe(1);
  });
});

async function call(
  tenuo: Tenuo,
  session: Session,
  host: ReportsHost,
  name: string,
  args: Readonly<Record<string, unknown>>,
  approvals?: readonly string[],
) {
  const attached =
    approvals !== undefined
      ? tenuo.mcp.attach(session, name, args, { approvals })
      : tenuo.mcp.attach(session, name, args);
  return host.call(attached.name, attached.arguments, attached._meta);
}
