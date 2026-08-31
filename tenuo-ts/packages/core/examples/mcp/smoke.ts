/**
 * In-process run of the quarterly-close MCP scenario.
 *
 *   cd tenuo-ts && pnpm example:mcp
 */
import { runQuarterlyClose, type QuarterlyCloseResult } from "./scenario.ts";

export async function runMcpSmoke(): Promise<QuarterlyCloseResult> {
  const result = await runQuarterlyClose((line) => {
    process.stdout.write(`${line}\n`);
  });
  if (result.listed.join(",") !== "q3-customers.md,q3-revenue.md") {
    throw new Error(`unexpected listing: ${result.listed.join(",")}`);
  }
  if (!result.revenue.includes("North America: $4.2M")) {
    throw new Error("researcher did not read q3 revenue");
  }
  if (result.draft.path !== "/workspace/drafts/q3-summary.md") {
    throw new Error(`unexpected draft path: ${result.draft.path}`);
  }
  if (result.emailed.to !== "finance@acme.com") {
    throw new Error("approved email did not send");
  }
  const codes = result.denials.map((denial) => denial.code);
  if (
    codes[0] !== "TENUO_CONSTRAINT_VIOLATION" ||
    codes[1] !== "TENUO_CONSTRAINT_VIOLATION" ||
    codes[2] !== "TENUO_APPROVAL_REQUIRED" ||
    codes[3] !== "TENUO_INVALID_POP"
  ) {
    throw new Error(`unexpected denials: ${codes.join(", ")}`);
  }
  return result;
}

const launchedDirectly = process.argv[1]?.includes("examples/mcp/smoke");
if (launchedDirectly) {
  runMcpSmoke()
    .then(() => {
      process.stdout.write("mcp smoke: quarterly close ok\n");
    })
    .catch((error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(1);
    });
}
