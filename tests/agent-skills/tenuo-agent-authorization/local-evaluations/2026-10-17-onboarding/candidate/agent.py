"""Holder-side transport. Issuer private keys never belong here."""
import base64
import json
import time
from urllib.request import Request, urlopen


def presentation(chain, holder_key, args, tool='pay_invoice'):
    return {'warrants': [w.to_base64() for w in chain],
            'proof': base64.b64encode(chain[-1].sign(
                holder_key, tool, args, int(time.time()))).decode('ascii')}


def pay_invoice(worker_url, invoice_id, bank_account, amount_cents, **transport):
    args = dict(invoice_id=invoice_id, bank_account=bank_account, amount_cents=amount_cents)
    request = Request(worker_url + '/pay', data=json.dumps({**args, **transport}).encode(),
                      headers={'Content-Type': 'application/json'})
    with urlopen(request, timeout=5) as response:
        return json.load(response)
