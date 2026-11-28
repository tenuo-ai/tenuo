import { AuthorizationDeniedError, createTenuo } from "@tenuo/core";
import type { Job } from "bullmq";
import { describe, expect, it } from "vitest";
import { createArchiveProducer } from "../src/producer.ts";
import { type ArchiveJobData, createArchiveWorker } from "../src/worker.ts";

// The processor only reads job.data, so these tests need no queue and no Redis.
const job = (data: ArchiveJobData) => ({ id: data.path, data }) as Job<ArchiveJobData>;

function setup() {
  const holderKey = createTenuo.generateHolderKey();
  const workerPublicKey = createTenuo.publicKeyFromHolderKey(holderKey);
  const producer = createArchiveProducer({ issuer: createTenuo.devRoot(), workerPublicKey });
  const archiver = createArchiveWorker({ rootPublicKey: producer.rootPublicKey, holderKey });
  return { workerPublicKey, producer, archiver };
}

describe("archive worker", () => {
  it("archives the path the warrant was signed for", async () => {
    const { producer, archiver } = setup();

    await expect(
      archiver.process(job(producer.jobFor("acme", "/tenants/acme/q3.pdf"))),
    ).resolves.toBe("archived /tenants/acme/q3.pdf");
    expect(archiver.archived).toEqual(["/tenants/acme/q3.pdf"]);
  });

  // Anyone who can write to the queue can rewrite `path`. The warrant still
  // covers only the path the producer signed.
  it.each(["/tenants/globex/q3.pdf", "/tenants/acme/payroll.pdf"])(
    "denies a job rewritten to %s without running the operation",
    async (path) => {
      const { producer, archiver } = setup();
      const signed = producer.jobFor("acme", "/tenants/acme/q3.pdf");

      await expect(archiver.process(job({ ...signed, path }))).rejects.toBeInstanceOf(
        AuthorizationDeniedError,
      );
      expect(archiver.archived).toEqual([]);
    },
  );

  it("rejects a warrant the trusted producer did not sign", async () => {
    const { workerPublicKey, archiver } = setup();
    // Anyone who can write to the queue can mint a warrant. Only the trusted root's are accepted.
    const forger = createArchiveProducer({ issuer: createTenuo.devRoot(), workerPublicKey });

    await expect(
      archiver.process(job(forger.jobFor("globex", "/tenants/globex/q3.pdf"))),
    ).rejects.toMatchObject({ code: "TENUO_UNTRUSTED_ROOT" });
    expect(archiver.archived).toEqual([]);
  });

  it.each(["", "..", "acme/../globex"])("refuses to mint for tenant id %j", (tenantId) => {
    const { producer } = setup();

    expect(() => producer.jobFor(tenantId, "/tenants/acme/q3.pdf")).toThrow("invalid tenant id");
  });

  it.each([
    "/tenants/globex/q3.pdf",
    "/tenants/acmecorp/q3.pdf",
    "/tenants/acme/../globex/q3.pdf",
    "/tenants/acme//q3.pdf",
    "/tenants/acme",
  ])("refuses to mint for path %j outside the tenant", (path) => {
    const { producer } = setup();

    expect(() => producer.jobFor("acme", path)).toThrow("outside tenant acme");
  });

  it("keeps concurrent jobs' authority isolated", async () => {
    const { producer, archiver } = setup();
    const acme = producer.jobFor("acme", "/tenants/acme/q3.pdf");

    const settled = await Promise.allSettled([
      archiver.process(job(acme)),
      archiver.process(job({ ...acme, path: "/tenants/globex/q4.pdf" })),
      archiver.process(job(producer.jobFor("globex", "/tenants/globex/q4.pdf"))),
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
