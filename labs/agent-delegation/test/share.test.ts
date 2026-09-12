process.env.NODE_ENV = "development";

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

let labHome = "";

beforeAll(() => {
  labHome = mkdtempSync(join(tmpdir(), "tenuo-share-test-"));
  process.env.TENUO_LAB_HOME = labHome;
});

afterAll(() => rmSync(labHome, { recursive: true, force: true }));

describe("lab score submission", () => {
  it("submits only the fixed redacted contract and accepts a receipt", async () => {
    vi.resetModules();
    const { buildShareReport, submitShareReport } = await import("../src/share.ts");
    const report = buildShareReport(5, {
      "trip-booked": true,
      "rogue-stopped": true,
      "tight-handoff": false,
      "no-spare-authority": false,
    }, {
      count: 1,
      firstAttempt: {
        starsMissing: ["tight-handoff", "no-spare-authority"],
        checks: { passed: 12, total: 14 },
        handoffs: {
          "flight-to-checkin": {
            tools: ["get_reservation", "check_in"],
            constraintChecks: { passed: 6, total: 7 },
            holderBound: true,
            ttl: "under-6m",
          },
          "checkin-to-boarding": "missing",
        },
      },
    }, "octo-cat");
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
      receiptId: "receipt-1",
      leaderboardEligible: true,
    }), { status: 201, headers: { "Content-Type": "application/json" } }));
    await expect(submitShareReport(report, {
      endpoint: "http://localhost/v1/lab/submissions",
      fetch: fetchMock,
    })).resolves.toEqual({ receiptId: "receipt-1", leaderboardEligible: true });
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "attempts", "challengeVersion", "runtime", "schema", "sdkVersion", "sessionId", "stage", "stars", "username",
    ]);
    expect(JSON.stringify(body)).not.toMatch(/Alice|Cancún|source|privateKey|publicKey|timestamp/i);
    expect(JSON.stringify(body)).toContain('"checkin-to-boarding":null');
  });

  it("rejects names that cannot safely become leaderboard labels", async () => {
    vi.resetModules();
    const { normalizeUsername } = await import("../src/share.ts");
    expect(normalizeUsername("octo-cat")).toBe("octo-cat");
    expect(() => normalizeUsername("name with spaces")).toThrow(/GitHub-style username/);
    expect(() => normalizeUsername("two--hyphens")).toThrow(/GitHub-style username/);
  });

  it("requires HTTPS except for a local end-to-end receiver", async () => {
    vi.resetModules();
    const { submitShareReport } = await import("../src/share.ts");
    await expect(submitShareReport({} as never, { endpoint: "http://example.com/collect" })).rejects.toThrow(/HTTPS/);
  });
});
