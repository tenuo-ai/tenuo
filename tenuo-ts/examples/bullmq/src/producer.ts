import { posix } from "node:path";
import { createTenuo, exact, type DevRoot, type IssuerKey, type PublicKeyHandle } from "@tenuo/core";
import type { ArchiveJobData } from "./worker.ts";

/** One tenant id, used as a single path segment. Rejects "", "/" and "..". */
const tenantSegment = /^[a-z0-9][a-z0-9-]*$/;

/**
 * The trusted side of the queue: the process that has authenticated the tenant.
 * It signs each job's authority, so the worker never trusts what a job claims.
 *
 * `issuer` is the key this producer signs with. In production that is an issuer
 * key loaded from configuration, such as `createTenuo.issuerKeyFromEnv(...)`.
 */
export function createArchiveProducer(options: {
  issuer: DevRoot | IssuerKey;
  workerPublicKey: PublicKeyHandle;
}) {
  const tenuo = createTenuo({ root: options.issuer });

  function jobFor(tenantId: string, path: string): ArchiveJobData {
    if (!tenantSegment.test(tenantId)) {
      throw new Error(`invalid tenant id: ${JSON.stringify(tenantId)}`);
    }
    // Only sign for a normalized path inside the tenant, so "..", "//" and
    // "/tenants/acmecorp" never get a warrant for tenant "acme".
    if (posix.normalize(path) !== path || !path.startsWith(`/tenants/${tenantId}/`)) {
      throw new Error(`path ${JSON.stringify(path)} is outside tenant ${tenantId}`);
    }
    // The warrant covers this one path, so a job rewritten in the queue
    // cannot reuse it for another document, even in the same tenant.
    const session = tenuo.session({
      allow: { archive_document: { path: exact(path) } },
      holder: options.workerPublicKey,
      ttlSeconds: 300,
      maxDepth: 0,
    });
    return { warrant: session.toWire(), path };
  }

  return { jobFor, rootPublicKey: tenuo.issuerPublicKey() };
}
