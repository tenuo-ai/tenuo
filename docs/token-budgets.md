# Token Budgets

> **Experimental.** Put a token budget in a warrant and have every model call counted against it.

A warrant can say how many tokens its holder may spend on model calls. The budget is signed with the rest of the warrant, a delegated warrant can only narrow it, and a meter at the HTTP layer counts each call's real usage and stops calls once the budget is spent.

Python only for now.

---

## Quick Start

```python
import tenuo.budget_http
from tenuo import SigningKey, Warrant
from tenuo.budget import llm_capability

issuer, agent = SigningKey.generate(), SigningKey.generate()

warrant = (
    Warrant.mint_builder()
    .capability("llm.chat", llm_capability(
        total_tokens=2_000_000,      # input + output, for the life of the warrant
        max_tokens=4096,             # most output one call may ask for
        models=["gpt-4o-mini"],
    ))
    .holder(agent.public_key)
    .ttl(86400)
    .mint(issuer)
)

tenuo.budget_http.install(
    warrant=warrant,
    signing_key=agent,
    trusted_roots=[issuer.public_key],
    budget_store="budgets.db",
)
```

After `install()`, model calls made by any `httpx` or `httpx2` client in the process are metered. SDKs and frameworks keep building their own clients; nothing else is wired.

For each model call the meter:

1. reserves the estimated input plus the output cap, and has the warrant authorize the call with the running total;
2. lowers the request's output cap to what the budget has left;
3. after the response (or at the end of its stream), replaces the reservation with the usage the provider reported.

A refused call is not sent.

---

## The budget is a constraint

`llm_capability()` returns ordinary constraints for a capability named `llm.chat`:

| Field | Constraint | Meaning |
|-------|------------|---------|
| `total_tokens` | `Range(min=0, max=N)` | Tokens the warrant, and everything delegated from it, may spend |
| `max_tokens` | `Range(min=0, max=N)` | Most output tokens one call may request |
| `model` | `OneOf([...])` | Models the warrant may call |

The caller does not supply `total_tokens`. The meter keeps a running total per warrant and passes that as the argument, so the warrant check decides and the store only counts.

A budget written by hand must have the same shape: a range that starts at 0 and has an upper bound. Model calls on a warrant whose `total_tokens` is anything else (an exact value, a list, a range starting above 0) are refused.

Because it is a constraint, delegation follows the usual rules: a child warrant cannot widen or drop the budget.

```python
worker = (
    warrant.grant_builder()
    .capability("llm.chat", llm_capability(total_tokens=200_000, max_tokens=4096, models=["gpt-4o-mini"]))
    .holder(worker_key.public_key)
    .ttl(3600)
    .grant(agent)
)
```

A call spends from its own warrant and from every parent presented with it, so workers that share a parent share its budget.

---

## Several agents in one process

Credentials passed to `install()` are the default. A call made inside `warrant_scope()` and `key_scope()` uses those instead, and `chain_scope()` supplies the parents:

```python
from tenuo import chain_scope, key_scope, warrant_scope

tenuo.budget_http.install(trusted_roots=[issuer.public_key], budget_store="budgets.db")

with warrant_scope(worker), key_scope(worker_key), chain_scope([warrant]):
    client.chat.completions.create(model="gpt-4o-mini", messages=messages)
```

With no warrant in scope and no default, a model call is refused.

---

## Metering one client

To meter a single client and leave the rest of the process alone, give it a metered HTTP client:

```python
import openai
from tenuo.budget_http import metered_client

http = metered_client(
    sdk=openai,
    warrant=worker,
    warrant_chain=[warrant],
    signing_key=worker_key,
    trusted_roots=[issuer.public_key],
    budget_store="budgets.db",
)
client = openai.OpenAI(http_client=http)
```

`sdk=` selects the HTTP library that SDK is built on and keeps its default timeouts. `metered_async_client()` is the async counterpart; give both the same `budget_store`.

`mounts=` and `proxy=` are not accepted on a metered client, since they give some requests a transport of their own. Configure a proxy on the transport passed as `transport=`, which the meter wraps.

---

## Refusals

A refused call is answered locally with HTTP 403 in the provider's own error shape, so each SDK raises its usual error type.

| Code | Meaning |
|------|---------|
| `token_budget_exceeded` | A budget in the chain is spent |
| `model_call_denied` | The warrant refuses for another reason (model, per-call cap, expiry, no warrant in scope) |
| `unmetered_endpoint` | A `POST` to a path the meter does not recognize |

```python
from tenuo.budget_http import is_budget_error

try:
    client.chat.completions.create(model="gpt-4o-mini", messages=messages)
except openai.PermissionDeniedError as e:
    if is_budget_error(e):
        ...  # out of budget
    else:
        raise
```

---

## Usage records

`audit_callback` receives a `MeterEvent` for every refusal and every finished call:

```python
def on_event(event):
    print(event.decision, event.model, event.usage)

tenuo.budget_http.install(..., audit_callback=on_event)
```

`event.usage` holds `input_tokens`, `output_tokens`, `total_tokens`, and `budget`: the running total and limit of each warrant the call spent from.

To record usage without refusing or capping anything, pass a meter with `enforce=False`:

```python
from tenuo.budget import TokenMeter

tenuo.budget_http.install(..., budget_store=TokenMeter("budgets.db", enforce=False))
```

In this mode requests go out exactly as written and nothing is refused, including endpoints the meter does not recognize. Usage is recorded when the response carries it, so a Chat Completions stream is counted only if the caller asks for usage itself (`stream_options={"include_usage": True}`).

---

## What is metered

Wire formats, recognized by request path:

- OpenAI Chat Completions, Completions and Responses (including OpenAI-compatible providers and gateways)
- Anthropic Messages
- Google `generateContent` and `streamGenerateContent`

`install()` only touches requests to known provider hosts (`tenuo.budget_http.DEFAULT_HOSTS`). Add a gateway or a self-hosted server with `hosts=["gateway.internal:8080"]`, or pass `hosts=["*"]`.

On a metered host, `GET` requests and token-counting endpoints pass through. Any other `POST` to an unrecognized path is refused unless its path ending is listed in `unmetered_paths`, whether or not a warrant is in scope.

---

## Stores

| Store | Scope |
|-------|-------|
| `BudgetStore()` | One process |
| `BudgetStore("budgets.db")` | Every process on the host that opens the file (SQLite in WAL mode, so keep it on a local disk) |
| `BudgetStore(backend=...)` | Anything implementing `BudgetBackend` (an atomic `add`) |

A total holds only where every call passes a meter on the same store.

With a store that can wait on another writer (anything but the in-memory one), async clients run their store operations off the event loop.

---

## Behavior to know

- **Input is estimated before the call.** The reservation uses a rough count of the prompt; the store is corrected to the provider's figure afterwards. A call can therefore pass a total by its estimate error, and the next call is refused. Pass `TokenMeter(input_estimator=...)` for a tokenizer-based estimate.
- **Output caps depend on the provider.** The meter sets the cap; a model that generates past it is still counted in full.
- **In-flight calls hold their reservation.** Concurrent calls near the end of a budget can be refused while tokens are reserved but not yet spent.
- **Failed requests.** An error response from the provider releases the reservation. A timeout or dropped connection keeps it as the charge.
- **Streams.** Chat Completions streams are asked for usage (`stream_options.include_usage`); the extra chunk is hidden unless the caller asked for it too. A stream that is closed, or dropped, before its final usage arrives keeps its reservation as the charge.
- **What the request does not show.** The input estimate comes from the request body. Context the provider holds on its side, such as a Responses call that continues from `previous_response_id`, is not in it: such a call is admitted on its visible input and counted in full afterwards.
- **Scope.** The meter covers `httpx` and `httpx2` clients in the process. `install()` switches the Google GenAI SDK's async calls to its `httpx` path while installed.

---

## See also

- [Constraints](constraints.md)
- [Enforcement Architecture](enforcement.md)
- Example: [`examples/openai/token_budget.py`](../tenuo-python/examples/openai/token_budget.py)
