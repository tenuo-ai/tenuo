import { createTenuo } from "@tenuo/core";
import { Queue, Worker } from "bullmq";
import { createArchiveProducer } from "./producer.ts";
import { type ArchiveJobData, createArchiveWorker } from "./worker.ts";

// The dev root refuses to run outside development. This opts the local demo in.
process.env.TENUO_ALLOW_DEV ??= "1";

const connection = { host: "127.0.0.1", port: 6379 };
const queueName = "archive";

// Both sides run in one process for the demo. In production the worker loads
// its holder key and the producer's public key from its own configuration.
const holderKey = createTenuo.generateHolderKey();
const producer = createArchiveProducer(createTenuo.publicKeyFromHolderKey(holderKey));
const archiver = createArchiveWorker({ rootPublicKey: producer.rootPublicKey, holderKey });

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
await queue.add("archive", producer.jobFor("acme", "/tenants/acme/q3.pdf"));
await queue.add("archive", producer.jobFor("acme", "/tenants/globex/q3.pdf"));

await bothSettled;
await worker.close();
await queue.close();
