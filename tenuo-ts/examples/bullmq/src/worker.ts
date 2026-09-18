import { setTimeout as yieldToOtherJobs } from "node:timers/promises";
import { createTenuo, under } from "@tenuo/core";
import type { Job } from "bullmq";

export type ArchiveJobData = { tenantId: string; path: string };

/**
 * One worker process. The tool ceiling is fixed at startup; the session that
 * actually authorizes a call is minted per job and discarded with it.
 */
export function createArchiveWorker() {
  const tenuo = createTenuo({ root: createTenuo.devRoot() });
  const archived: string[] = [];

  const archiveDocument = tenuo.tool(
    {
      execute: async ({ path }: { path: string }) => {
        // Stands in for the archive write. Concurrent jobs overlap here.
        await yieldToOtherJobs(0);
        archived.push(path);
        return `archived ${path}`;
      },
    },
    { capability: "archive_document", allow: { path: under("/tenants") } },
  );

  async function process(job: Job<ArchiveJobData>): Promise<string> {
    const session = tenuo.session({
      allow: { archive_document: { path: under(`/tenants/${job.data.tenantId}`) } },
      ttlSeconds: 60,
    });
    return tenuo.withSession(session, () => archiveDocument.execute({ path: job.data.path }));
  }

  return { process, archived };
}
