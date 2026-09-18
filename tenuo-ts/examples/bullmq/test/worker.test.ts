import { AuthorizationDeniedError } from "@tenuo/core";
import type { Job } from "bullmq";
import { describe, expect, it } from "vitest";
import { type ArchiveJobData, createArchiveWorker } from "../src/worker.ts";

// The processor only reads job.data, so these tests need no queue and no Redis.
const job = (data: ArchiveJobData) => ({ id: data.path, data }) as Job<ArchiveJobData>;

describe("archive worker", () => {
  it("archives a path inside the job's tenant", async () => {
    const archiver = createArchiveWorker();

    await expect(
      archiver.process(job({ tenantId: "acme", path: "/tenants/acme/q3.pdf" })),
    ).resolves.toBe("archived /tenants/acme/q3.pdf");
    expect(archiver.archived).toEqual(["/tenants/acme/q3.pdf"]);
  });

  it("denies another tenant's path without running the operation", async () => {
    const archiver = createArchiveWorker();

    await expect(
      archiver.process(job({ tenantId: "acme", path: "/tenants/globex/q3.pdf" })),
    ).rejects.toBeInstanceOf(AuthorizationDeniedError);
    expect(archiver.archived).toEqual([]);
  });

  it("keeps concurrent job sessions isolated", async () => {
    const archiver = createArchiveWorker();

    const settled = await Promise.allSettled([
      archiver.process(job({ tenantId: "acme", path: "/tenants/acme/q3.pdf" })),
      archiver.process(job({ tenantId: "globex", path: "/tenants/acme/q4.pdf" })),
      archiver.process(job({ tenantId: "globex", path: "/tenants/globex/q4.pdf" })),
    ]);

    expect(settled.map((result) => result.status)).toEqual([
      "fulfilled",
      "rejected",
      "fulfilled",
    ]);
    expect([...archiver.archived].sort()).toEqual([
      "/tenants/acme/q3.pdf",
      "/tenants/globex/q4.pdf",
    ]);
  });
});
