import json
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from tenuo import SigningKey
import worker
from authority import issue_invoice
from agent import presentation


@pytest.fixture
def live():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    chain = issue_invoice(issuer, holder.public_key, 'INV-123')
    worker.effects.clear()
    server = worker.serve(0, trusted_roots=[issuer.public_key])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield holder, chain, f'http://127.0.0.1:{server.server_port}/pay'
    finally:
        server.shutdown(); server.server_close()


def send(url, payload):
    request = Request(url, data=json.dumps(payload).encode(), headers={'Content-Type':'application/json'})
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def args(amount=20000, bank='verified-bank'):
    return dict(invoice_id='INV-123',bank_account=bank,amount_cents=amount)


def test_raw_http_receiving_boundary_and_changed_signed_values(live):
    holder, chain, url = live
    good=args()
    bad=args(bank='attacker-bank')
    status,reason=send(url,{**bad,**presentation(chain,holder,bad)})
    assert status==403 and reason['denied']=='ConstraintViolation'
    assert worker.effects==[]
    status,reason=send(url,{**args(20001),**presentation(chain,holder,good)})
    assert status==403 and any(term.lower() in reason['denied'].lower() for term in ['signature','proof','pop']),reason
    assert worker.effects==[]
    status,reason=send(url,{**good,**presentation(chain,SigningKey.generate(),good)})
    assert status==403 and any(term.lower() in reason['denied'].lower() for term in ['signature','proof','pop']),reason
    assert worker.effects==[]
    assert send(url,good)[0]==403  # Original unsigned direct worker route.
    assert send(url,{**good,**presentation(chain,holder,good),'trusted_roots':[]})[0]==403
    assert worker.effects==[]
    assert send(url,{**good,**presentation(chain,holder,good)})[0]==200
    assert worker.effects==[good]


def test_live_cumulative_limit_is_separate_from_warrant(live):
    holder,chain,url=live
    for amount in (1000000,420000):
        value=args(amount)
        assert send(url,{**value,**presentation(chain,holder,value)})[0]==200
    value=args(1)
    status,reason=send(url,{**value,**presentation(chain,holder,value)})
    assert status==403 and reason['denied']=='ValueError'
    assert sum(e['amount_cents'] for e in worker.effects)==1420000
    assert len(worker.effects)==2


def test_concurrent_payment_limit(live):
    holder,chain,url=live
    value=args(800000)
    payload={**value,**presentation(chain,holder,value)}
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:send(url,payload),range(2)))
    assert sorted(status for status,_ in results)==[200,403]
    assert worker.effects==[value]
