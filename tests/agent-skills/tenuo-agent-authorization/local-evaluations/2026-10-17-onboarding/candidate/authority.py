"""Trusted approval-service issuance recipe; never run inside the agent in production."""
import json
from pathlib import Path
from tenuo import Exact, Range, Warrant

RECORDS = Path(__file__).with_name('approved_invoices.json')
TOOL = 'pay_invoice'
MAX_EXACT_CENTS = 2**53 - 1


def issue_invoice(issuer_key, holder_public_key, invoice_id):
    """Reusable code-first template: all business limits come from trusted records."""
    record = json.loads(RECORDS.read_text())[invoice_id]
    if record['status'] != 'approved' or record['currency'] != 'USD':
        raise ValueError('invoice must be approved in USD')
    ceiling = record['approved_amount_cents']
    if type(ceiling) is not int or not 1 <= ceiling <= MAX_EXACT_CENTS:
        raise ValueError('invalid approved amount')
    limits = {'invoice_id': Exact(invoice_id),
              'bank_account': Exact(record['approved_bank_account']),
              'amount_cents': Range(min=1, max=ceiling)}
    # Installed direct issue() defaults to depth=64 and has no terminal option.
    # Use a bounded issuer warrant and its supported terminal execution builder.
    root = Warrant.issue_issuer([TOOL], issuer_key,
        constraint_bounds=limits, holder=issuer_key.public_key,
        ttl_seconds=360, max_issue_depth=1)
    leaf = (root.issue_execution().capability(TOOL, limits)
            .holder(holder_public_key).ttl(300).terminal().build(issuer_key))
    return [root, leaf]
