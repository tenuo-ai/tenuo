# BullMQ job-authorization example

A BullMQ worker that authorizes a protected operation with job-scoped Tenuo authority. This is an
application example. Tenuo has no BullMQ adapter, and nothing here is queue transport or
control-plane behavior.

## Where the job's authority comes from

Anyone who can write to the queue controls everything in a job, so the worker never builds authority
from job fields. The job carries a warrant signed by a trusted producer, and the worker verifies it.

`createArchiveProducer()` (`src/producer.ts`) is the trusted side: the process that has already
authenticated the tenant. For each job it mints a warrant allowing `archive_document` only
`under("/tenants/<tenantId>")`, bound to the worker's public key, with a 300 second TTL and no further
delegation. It refuses a tenant id that is not a single path segment, so `""` can never become
`under("/tenants/")`.

`createArchiveWorker()` (`src/worker.ts`) runs once per worker process. It trusts only the producer's
public key, and its `archive_document` tool has a host ceiling of `under("/tenants")` that is fixed at
startup and is not job authority. For each job:

1. BullMQ hands the processor a job carrying `{ warrant, path }`.
2. `tenuo.sessionFromWire()` imports the warrant with the worker's holder key. A warrant from any
   other signer fails with `TENUO_UNTRUSTED_ROOT`, and a copy used under another key fails with
   `TENUO_INVALID_POP`.
3. `tenuo.withSession(session, ...)` makes that warrant the authority for the call, and only for that
   job's async context.

Authorization runs before `execute`. A path outside the warrant's tenant throws
`AuthorizationDeniedError` and the archive operation never runs, so the job fails in BullMQ the same
way any other processor rejection does. Concurrent jobs on the same worker (`concurrency: 4` in
`src/main.ts`) never see each other's authority.

## Tests

```sh
cd tenuo-ts/examples/bullmq
npm install
npm test
```

The tests call the processor directly with a plain object standing in for a BullMQ `Job`. They cover
an allowed job, a denied path that proves the operation never ran, a warrant from an untrusted
producer, tenant ids that are not one path segment, and concurrent jobs that interleave inside their
sessions before authorizing. No Redis and no external service.

## Run the worker against Redis

The runnable worker needs a Redis instance on `127.0.0.1:6379`.

```sh
docker run --rm -p 6379:6379 redis:8-alpine
npm start
```

It enqueues one allowed job and one job for another tenant's path, then prints the completion and
the denial. The demo runs the producer and the worker in one process with `createTenuo.devRoot()`,
opted in with `TENUO_ALLOW_DEV=1`. In production they are separate processes: the producer signs with
an issuer key, and the worker loads its holder key and the producer's public key from configuration.

## Verify against the local packed package

From `tenuo-ts`, build `@tenuo/core`, then run the isolated check:

```sh
pnpm --filter @tenuo/core build
node examples/bullmq/scripts/verify-packed.mjs
```

The check packs the local `@tenuo/core`, installs its tarball into a temporary copy of this example
rather than a workspace link, and runs the typecheck and the tests against it. This is what CI runs.
