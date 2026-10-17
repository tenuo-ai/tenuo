// Only the local development issuer is used; no external service or secrets.
process.env.TENUO_ALLOW_DEV ??= "1";

import { describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "./app.ts";

describe("Express request-scoped Tenuo authorization", () => {
  it("allows a request within the role's scope", async () => {
    const { app, executed } = createApp();
    const response = await request(app).get("/reports/read").query({
      path: "/workspace/reports/q3.txt",
    });
    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      allowed: true,
      result: "contents of /workspace/reports/q3.txt",
    });
    expect(executed).toEqual(["/workspace/reports/q3.txt"]);
  });

  it("rejects out-of-scope paths before calling the underlying operation", async () => {
    const { app, executed } = createApp();
    const response = await request(app).get("/reports/read").query({
      path: "/workspace/finance/payroll.txt",
    });
    expect(response.status).toBe(403);
    expect(response.body).toMatchObject({
      allowed: false,
      code: "TENUO_CONSTRAINT_VIOLATION",
    });
    expect(executed).toEqual([]);
  });

  it("does not share authority between concurrent requests", async () => {
    const { app, executed } = createApp();
    const [reportsAllowed, financeAllowed, reportsDenied, financeDenied] =
      await Promise.all([
        request(app).get("/reports/read").query({ path: "/workspace/reports/a" }),
        request(app).get("/finance/read").query({ path: "/workspace/finance/b" }),
        request(app).get("/reports/read").query({ path: "/workspace/finance/c" }),
        request(app).get("/finance/read").query({ path: "/workspace/reports/d" }),
      ]);

    expect([reportsAllowed.status, financeAllowed.status]).toEqual([200, 200]);
    expect([reportsDenied.status, financeDenied.status]).toEqual([403, 403]);
    expect(executed.slice().sort()).toEqual([
      "/workspace/finance/b",
      "/workspace/reports/a",
    ]);
  });

  it("rejects malformed requests without executing the operation", async () => {
    const { app, executed } = createApp();
    const response = await request(app).get("/reports/read");
    expect(response.status).toBe(400);
    expect(executed).toEqual([]);
  });
});
