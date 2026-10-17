import json
from urllib.request import Request,urlopen

def pay_invoice(worker_url,invoice_id,bank_account,amount_cents,**transport):
    args=dict(invoice_id=invoice_id,bank_account=bank_account,amount_cents=amount_cents)
    request=Request(worker_url+'/pay',data=json.dumps({**args,**transport}).encode(),headers={'Content-Type':'application/json'})
    with urlopen(request) as response: return json.load(response)
