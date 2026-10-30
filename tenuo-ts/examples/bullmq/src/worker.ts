import { setTimeout as yieldToOtherJobs } from "node:timers/promises";
import { createTenuo, under, type PublicKeyHandle } from "@tenuo/core";
import type { Job } from "bullmq";

/** `warrant` is signed by the producer and bound to this worker's key. */
export type ArchiveJobData = { warrant: readonly string[]; path: string };

/**
 * One worker process. The tool ceiling is fixed at startup; the authority for
 * each call is the warrant the job carries, verified against the producer's key.
 */
export function createArchiveWorker(options: { rootPublicKey: PublicKeyHandle; holderKey: Uint8Array }) {
  const tenuo = createTenuo({ trustedRoots: [options.rootPublicKey] });
  const archived: string[] = [];

  const archiveDocument = tenuo.tool(
    {
      execute: async ({ path }: { path: string }) => {
        archived.push(path);
        return `archived ${path}`;
      },
    },
    { capability: "archive_document", allow: { path: under("/tenants") } },
  );

  async function process(job: Job<ArchiveJobData>): Promise<string> {
    // Throws for a warrant this worker's trusted root did not sign.
    const session = tenuo.sessionFromWire({ warrant: job.data.warrant, holderKey: options.holderKey });
    return tenuo.withSession(session, async () => {
      // Stands in for loading the document. Concurrent jobs interleave here,
      // each inside its own session, before the call is authorized.
      await yieldToOtherJobs(0);
      return archiveDocument.execute({ path: job.data.path });
    });
  }

  return { process, archived };
}
