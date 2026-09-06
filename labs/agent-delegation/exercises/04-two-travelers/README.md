# Stage 4: two travelers, one agent

Bob is going to Seattle on DL331, with a flight budget of $450. His trip runs
through the same `flight-agent` and `checkin-agent` as Alice's, at the same
time.

Your stage 3 policy pins `checkin-agent` to `["UA214"]`, so Bob's check-in is
denied and the trip fails. The repair everyone reaches for first:

```ts
"checkin-agent": {
  actions: ["get_reservation", "check_in"],
  reservations: ["UA214", "DL331"],
},
```

The trip completes. Then read the CROSS-TASK section of `npm run attack`.
Alice's check-in agent can check Bob in. There is one `checkin-agent`, it is
doing two jobs, and nothing in this file says which job a given call belongs
to.

You can fix this. Two ways work, and the lab accepts both.

## Fix A: one identity per task

Give the agent a different identity for each trip. A key of the form
`agent:taskId` is used for that agent on that task instead of the plain entry:

```ts
"checkin-agent:trip-alice-cun": {
  actions: ["get_reservation", "check_in"],
  reservations: ["UA214"],
},
"checkin-agent:trip-bob-sea": {
  actions: ["get_reservation", "check_in"],
  reservations: ["DL331"],
},
```

Do the same for `flight-agent` (destination and budget differ) and
`boarding-agent`. It works. Now ask: who writes these entries, and when? In a
real system, the orchestrator writes them at the moment each task starts, and
every identity has to be registered somewhere before its first call.

## Fix B: ask a service which task this is

Flip `policyService: true`. Every flight and reservation check now asks a
policy service which task is calling: its destination, its flight budget, and
its reservations. Those fields in this file are ignored for that purpose, so
you can drop `destination` and `maxPrice` from `flight-agent` and
`reservations` from `checkin-agent` and `boarding-agent`. When a flight is
booked, the service is told, and the task's reservation narrows to that one.
It works. Look at `npm run trace`: every one of those calls now shows
`round_trips: 1`, and the service holds state for every open task.

## What both fixes have in common

Some central component has to be told about every task before it starts and
consulted for every call while it runs. Its availability now gates every tool
call. Write down, in one sentence, what your fix depends on. You will compare
it with stage 6.
