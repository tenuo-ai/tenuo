import { createTenuo, under, type PublicKeyHandle } from "@tenuo/core";
import type { ArchiveJobData } from "./worker.ts";

/** One tenant id, used as a single path segment. Rejects "", "/" and "..". */
const tenantSegment = /^[a-z0-9][a-z0-9-]*$/;

/**
 * The trusted side of the queue: the process that has authenticated the tenant.
 * It signs each job's authority, so the worker never trusts what a job claims.
 */
export function createArchiveProducer(workerPublicKey: PublicKeyHandle) {
  const tenuo = createTenuo({ root: createTenuo.devRoot() });

  function jobFor(tenantId: string, path: string): ArchiveJobData {
    if (!tenantSegment.test(tenantId)) {
      throw new Error(`invalid tenant id: ${JSON.stringify(tenantId)}`);
    }
    const session = tenuo.session({
      allow: { archive_document: { path: under(`/tenants/${tenantId}`) } },
      holder: workerPublicKey,
      ttlSeconds: 300,
      maxDepth: 0,
    });
    return { warrant: session.toWire(), path };
  }

  return { jobFor, rootPublicKey: tenuo.issuerPublicKey() };
}
