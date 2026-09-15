# BullMQ job-authorization example

A BullMQ worker that authorizes a protected operation with job-scoped Tenuo authority. This is an
application example. Tenuo has no BullMQ adapter, and nothing here is queue transport or
control-plane behavior.

## Where the job's authority enters and leaves

`createArchiveWorker()` runs once per worker process. It builds the `archive_document` tool whose
`allow` is the host ceiling for every job this worker will ever run: paths `under("/tenants")`.
That ceiling is fixed at startup and is not job authority.

Job authority is minted inside the processor, after the job arrives:

1. BullMQ hands the processor a job carrying `{ tenantId, path }`.
2. The processor mints a session allowing `archive_document` only `under("/tenants/<tenantId>")`,
   with a 60 second TTL.
3. `tenuo.withSession(session, ...)` makes that session the authority for the call, and only for the
   duration of that call.
4. The session goes out of scope when the processor returns. Nothing about it survives into the next
   job, and a session that outlives its job expires on its own.

Authorization runs before `execute`. A path outside the job's tenant throws
`AuthorizationDeniedError` and the archive operation never runs, so the job fails in BullMQ the same
way any other processor rejection does.

Each job gets its own session, and `withSession` scopes it to that job's async context. Concurrent
jobs on the same worker (`concurrency: 4` in `src/main.ts`) never see each other's authority.

## Tests

```sh
cd tenuo-ts/examples/bullmq
npm install
npm test
```

The tests call the processor directly with a plain object standing in for a BullMQ `Job`. They cover
an allowed job, a denied job that proves the operation never ran, and concurrent jobs whose sessions
stay isolated. No Redis and no external service.

## Run the worker against Redis

The runnable worker needs a Redis instance on `127.0.0.1:6379`.

```sh
docker run --rm -p 6379:6379 redis:8-alpine
NODE_ENV=development npm start
```

It enqueues one allowed job and one job for another tenant's path, then prints the completion and
the denial. `createTenuo.devRoot()` requires `NODE_ENV=development` or `test`; production loads an
issued warrant and a trusted root instead.

## Verify against the local packed package

From `tenuo-ts`, build `@tenuo/core`, then run the isolated check:

```sh
pnpm --filter @tenuo/core build
node examples/bullmq/scripts/verify-packed.mjs
```

The check packs the local `@tenuo/core`, installs its tarball into a temporary copy of this example
rather than a workspace link, and runs the typecheck and the tests against it. This is what CI runs.
