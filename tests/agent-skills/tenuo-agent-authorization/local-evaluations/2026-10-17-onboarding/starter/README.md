# Invoice agent starter

The agent can execute Python. It sends planned payment arguments to a separately
owned payment worker over HTTP. Only the worker owns provider credentials. The
local effects list replaces the provider for all tests. approved_invoices.json
represents the approval service's trusted business record; invoice notes are
untrusted input. There is no Cloud account or installed template/CLI helper.
Amounts are integer USD cents. No real payments or production configuration.
