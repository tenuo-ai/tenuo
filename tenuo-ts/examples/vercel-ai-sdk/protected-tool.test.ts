/**
 * Allow/deny coverage for the Vercel AI SDK protected-tool example.
 *
 * No model provider or credentials: the agent-loop tests drive
 * `generateText`/`streamText` with the SDK's mock language model from
 * `ai/test`. `executed` is the evidence — a denied call must never appear
 * in it, proving the underlying operation did not run after denial.
 */

// createHarness() mints a dev root, which refuses NODE_ENV=production
// unless opted in. demo.ts sets this before runDemo(); the suite needs it
// too, because verify-packed.mjs passes the full environment to npm test.
process.env.TENUO_ALLOW_DEV ??= "1";

import { generateText, streamText } from "ai";
import { MockLanguageModelV4, simulateReadableStream } from "ai/test";
import type { LanguageModelV4StreamPart } from "@ai-sdk/provider";
import { describe, expect, expectTypeOf, it } from "vitest";
import { AuthorizationDeniedError, under } from "@tenuo/core";
import { createHarness, runDemo } from "./protected-tool.ts";

/**
 * A mock model that emits a single `readFile` tool call for `path`,
 * for both `generateText` and `streamText`.
 */
function toolCallModel(path: string): MockLanguageModelV4 {
  const input = JSON.stringify({ path });
  const usage = {
    inputTokens: { total: 10, noCache: 10, cacheRead: undefined, cacheWrite: undefined },
    outputTokens: { total: 5, text: 0, reasoning: 0 },
  };
  return new MockLanguageModelV4({
    doGenerate: {
      content: [
        {
          type: "tool-call",
          toolCallId: "call-1",
          toolName: "readFile",
          input,
        },
      ],
      finishReason: { unified: "tool-calls", raw: "tool_calls" },
      usage,
      warnings: [],
    },
    doStream: {
      stream: simulateReadableStream({
        chunks: [
          { type: "stream-start", warnings: [] },
          {
            type: "tool-call",
            toolCallId: "call-1",
            toolName: "readFile",
            input,
          },
          {
            type: "finish",
            finishReason: { unified: "tool-calls", raw: "tool_calls" },
            usage,
          },
        ] satisfies LanguageModelV4StreamPart[],
      }),
    },
  });
}

describe("vercel-ai-sdk protected tool", () => {
  it("keeps the AI SDK tool shape: description and inputSchema pass through", () => {
    const { protectedReadFile } = createHarness();
    expect(protectedReadFile.description).toBe(
      "Read a UTF-8 text file and return its contents.",
    );
    // The SDK still validates inputs against this schema; Tenuo never treats
    // the host schema as authority.
    expect(protectedReadFile.inputSchema).toBeDefined();
  });

  it("preserves useful TypeScript input inference", () => {
    const { protectedReadFile } = createHarness();
    expectTypeOf(protectedReadFile.execute)
      .parameter(0)
      .toEqualTypeOf<{ path: string }>();
    expectTypeOf(protectedReadFile.execute).returns.resolves.toEqualTypeOf<string>();
  });

  it("allows a path under the session root and runs the operation", async () => {
    const { protectedReadFile, reportsSession, executed } = createHarness();
    const result = await protectedReadFile.execute(
      { path: "/data/reports/q3.pdf" },
      { session: reportsSession },
    );
    expect(result).toBe("Q3 revenue up 12% quarter over quarter.");
    expect(executed).toEqual(["/data/reports/q3.pdf"]);
  });

  it("denies a path outside the session root and never runs the operation", async () => {
    const { protectedReadFile, reportsSession, executed } = createHarness();
    const error = await protectedReadFile
      .execute({ path: "/data/finance/ledger.csv" }, { session: reportsSession })
      .then(
        () => "no-error",
        (cause: unknown) => cause,
      );
    expect(error).toBeInstanceOf(AuthorizationDeniedError);
    expect((error as AuthorizationDeniedError).code).toBe("TENUO_CONSTRAINT_VIOLATION");
    expect((error as AuthorizationDeniedError).field).toBe("path");
    // The denial happened before the operation: nothing executed.
    expect(executed).toEqual([]);
  });

  it("denies a path outside the tool ceiling even for a broader session", async () => {
    const { tenuo, protectedReadFile, executed } = createHarness();
    const broadSession = tenuo.session({
      allow: { read_file: { path: under("/etc") } },
    });
    const error = await protectedReadFile
      .execute({ path: "/etc/passwd" }, { session: broadSession })
      .then(
        () => "no-error",
        (cause: unknown) => cause,
      );
    expect(error).toBeInstanceOf(AuthorizationDeniedError);
    expect(executed).toEqual([]);
  });

  it("accepts the session from AsyncLocalStorage when options omit it", async () => {
    const { tenuo, protectedReadFile, reportsSession, executed } = createHarness();
    const result = await tenuo.withSession(reportsSession, () =>
      protectedReadFile.execute({ path: "/data/reports/q3.pdf" }),
    );
    expect(result).toBe("Q3 revenue up 12% quarter over quarter.");
    expect(executed).toEqual(["/data/reports/q3.pdf"]);
  });

  it("reports the allow/deny transcript via runDemo", async () => {
    const lines: string[] = [];
    await runDemo((line) => lines.push(line));
    expect(lines).toEqual([
      "allowed  /data/reports/q3.pdf -> Q3 revenue up 12% quarter over quarter.",
      "denied   /data/finance/ledger.csv -> TENUO_CONSTRAINT_VIOLATION (field path)",
      'tool executed for: ["/data/reports/q3.pdf"]',
    ]);
  });

  describe("real agent loop", () => {
    it("generateText runs the tool with the withSession() session", async () => {
      const { tenuo, protectedReadFile, reportsSession, executed } =
        createHarness();
      const result = await tenuo.withSession(reportsSession, () =>
        generateText({
          model: toolCallModel("/data/reports/q3.pdf"),
          tools: { readFile: protectedReadFile },
          prompt: "Read /data/reports/q3.pdf",
        }),
      );
      expect(executed).toEqual(["/data/reports/q3.pdf"]);
      expect(result.toolResults.map((t) => t.output)).toEqual([
        "Q3 revenue up 12% quarter over quarter.",
      ]);
    });

    it("streamText keeps the withSession() session while the stream is read after the callback returns", async () => {
      const { tenuo, protectedReadFile, reportsSession, executed } =
        createHarness();
      // In a route handler you return the stream response, so the tools run
      // while the stream is being read — after the withSession callback has
      // already returned. The session must survive that.
      const result = await tenuo.withSession(reportsSession, () =>
        streamText({
          model: toolCallModel("/data/reports/q3.pdf"),
          tools: { readFile: protectedReadFile },
          prompt: "Read /data/reports/q3.pdf",
        }),
      );
      // The stream is lazy: nothing has run yet.
      expect(executed).toEqual([]);

      const toolOutputs: unknown[] = [];
      for await (const part of result.fullStream) {
        if (part.type === "tool-result") toolOutputs.push(part.output);
      }
      expect(executed).toEqual(["/data/reports/q3.pdf"]);
      expect(toolOutputs).toEqual(["Q3 revenue up 12% quarter over quarter."]);
    });

    it("streamText surfaces the denial in-stream without running the operation", async () => {
      const { tenuo, protectedReadFile, reportsSession, executed } =
        createHarness();
      const result = await tenuo.withSession(reportsSession, () =>
        streamText({
          model: toolCallModel("/data/finance/ledger.csv"),
          tools: { readFile: protectedReadFile },
          prompt: "Read /data/finance/ledger.csv",
        }),
      );
      const toolErrors: unknown[] = [];
      for await (const part of result.fullStream) {
        if (part.type === "tool-error") toolErrors.push(part.error);
      }
      expect(toolErrors).toHaveLength(1);
      // The denial happened before the operation: nothing executed.
      expect(executed).toEqual([]);
    });
  });
});
