import { Queue, Worker } from "bullmq";
import { type ArchiveJobData, createArchiveWorker } from "./worker.ts";

const connection = { host: "127.0.0.1", port: 6379 };
const queueName = "archive";
const archiver = createArchiveWorker();

const worker = new Worker<ArchiveJobData, string>(queueName, (job) => archiver.process(job), {
  connection,
  concurrency: 4,
});

let settled = 0;
const bothSettled = new Promise<void>((resolve) => {
  const settle = () => {
    if (++settled === 2) resolve();
  };
  worker.on("completed", (job, result) => {
    console.log(`job ${job.id}: ${result}`);
    settle();
  });
  worker.on("failed", (job, error) => {
    console.log(`job ${job?.id}: ${error.message}`);
    settle();
  });
});

const queue = new Queue<ArchiveJobData>(queueName, { connection });
await queue.add("archive", { tenantId: "acme", path: "/tenants/acme/q3.pdf" });
await queue.add("archive", { tenantId: "acme", path: "/tenants/globex/q3.pdf" });

await bothSettled;
await worker.close();
await queue.close();
