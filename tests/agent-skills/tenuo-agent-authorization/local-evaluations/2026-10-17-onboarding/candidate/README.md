# Invoice agent with Tenuo

Run the installed SDK demo (no accounts, model keys, or real payments):

```sh
.venv/bin/python demo.py
```

It pays 20,000 USD cents on approved invoice INV-123, then blocks the same payment tool when an untrusted note diverts the bank account or the amount exceeds 1,420,000 cents. Each line prints the actual number of fake provider effects.

The agent can choose partial payment amounts autonomously within the trusted approval. `authority.issue_invoice()` is the reusable code-first issuance recipe: it reads trusted `approved_invoices.json`, binds a five-minute terminal warrant to the agent holder, and fixes invoice, payee and amount range. No YAML/template parser or Cloud integration is required.

Recommend an approval-service-owned issuer and the existing separately owned payment worker as verifier. Only the worker owns provider credentials; it verifies the full public warrant chain and holder proof over HTTP immediately before paying. Agent Python code cannot bypass this by posting unsigned requests directly to the worker. Production must actually protect the worker, approval records, issuer key and provider access from the agent.

This local run is a **development loop**: ephemeral keys and all source share one developer environment. Local cumulative invoice spending is locked and capped by the trusted approval, but resets on worker restart. Production needs durable atomic budget accounting and provider idempotency, protected keys, authenticated transport/root provisioning and approval/revocation freshness. Tenuo authorization alone does not prevent duplicate effects or prove invoice intent.

Run validation with `.venv/bin/python -m pytest -q`. See [REPORT.md](REPORT.md) for exact evidence and limits.
