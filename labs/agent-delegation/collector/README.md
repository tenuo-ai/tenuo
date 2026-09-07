# Lab event collector

Receives the opt-in, anonymous progress events the lab CLI sends (see
`src/telemetry.ts`). A Cloudflare Worker over D1; the logic is a pure
function in `src/collector.ts` so it is tested with the rest of the lab.

What arrives per event: a random per-install session id, an optional cohort
code, the stage, the lab version, local or Codespaces, the command, whether
the trip worked, the score, the labels of checks that did not land, the
central-call count, the stage 4 fix, the over-granted agents, and the time
since the previous event. The hosted guide sends page, hint, reference, and
mark-done events under the same id when the CLI's link carried it. Nothing
else is accepted; off-shape fields reject the event.

## Deploy

```bash
cd labs/agent-delegation/collector
npx wrangler d1 create lab-events            # paste the id into wrangler.toml
npx wrangler d1 execute lab-events --file=schema.sql
npx wrangler deploy
```

Then either route the Worker at the address in `DEFAULT_EVENTS_URL` or set
`TENUO_LAB_EVENTS_URL` for participants.

## Endpoints

- `POST /v1/events` — one event or an array of up to 50. Returns `{ accepted, rejected }`.
- `GET /v1/summary?cohort=CODE` — sessions, opt-ins, environments, versions, stage 4 fixes, and per stage: sessions entered, sessions with a working trip, runs, median attempts before the first working trip, median minutes in the stage, median score, the five most common failed checks, and how many sessions viewed the page, opened the hint, opened the reference, or marked the stage done.
- `GET /healthz`
