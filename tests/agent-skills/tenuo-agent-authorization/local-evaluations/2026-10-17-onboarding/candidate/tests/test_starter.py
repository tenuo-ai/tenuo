import base64
import json
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import pytest
from tenuo import Exact, Range, SigningKey, Warrant
import worker
from agent import pay_invoice, presentation
from authority import issue_invoice, TOOL


@pytest.fixture
def setup():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    chain = issue_invoice(issuer, holder.public_key, 'INV-123')
    worker.effects.clear()
    server = worker.serve(0, trusted_roots=[issuer.public_key])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield issuer, holder, chain, f'http://127.0.0.1:{server.server_port}'
    server.shutdown()
    server.server_close()


def args(**changes):
    return dict(invoice_id='INV-123', bank_account='verified-bank', amount_cents=20000, **changes)


def reject(url, values, transport, reason=None):
    before = len(worker.effects)
    with pytest.raises(HTTPError) as caught:
        pay_invoice(url, **values, **transport)
    assert caught.value.code == 403
    body = json.load(caught.value)
    if reason:
        assert body['denied'] == reason, body
    assert len(worker.effects) == before
    return body


def test_original_payment_path_now_requires_authority(setup):
    issuer, holder, chain, url = setup
    values = args()
    assert pay_invoice(url, **values, **presentation(chain, holder, values)) == {'paid': True}
    assert worker.effects == [values]
    reject(url, values, {}, 'ValueError')


@pytest.mark.parametrize('changes', [
    {'bank_account': 'attacker-bank'}, {'invoice_id': 'INV-999'},
    {'amount_cents': 1420001}, {'amount_cents': 0}, {'amount_cents': -1},
    {'amount_cents': True}, {'amount_cents': 1.1}, {'amount_cents': '20000'},
    {'amount_cents': 2**53},
])
def test_material_argument_limits(setup, changes):
    _, holder, chain, url = setup
    values = {**args(), **changes}
    result = reject(url, values, presentation(chain, holder, values))
    if changes.get('amount_cents', 1) == 1420001 or 'bank_account' in changes or 'invoice_id' in changes:
        assert result['denied'] == 'ConstraintViolation', result
    else:
        assert result['denied'] == 'ValueError', result


@pytest.mark.parametrize('amount', [1, 1420000])
def test_inclusive_amount_boundaries(setup, amount):
    _, holder, chain, url = setup
    values = {**args(), 'amount_cents': amount}
    assert pay_invoice(url, **values, **presentation(chain, holder, values)) == {'paid': True}
    assert worker.effects == [values]


def test_wrong_holder_missing_chain_wrong_capability_and_tamper(setup):
    _, holder, chain, url = setup
    values = args()
    wrong = SigningKey.generate()
    for transport in [presentation(chain, wrong, values),
                      presentation([chain[-1]], holder, values),
                      presentation(chain, holder, values, tool='other_tool')]:
        result = reject(url, values, transport)
        assert result['denied'] != 'TypeError', result
    # Same holder, same transport; mutate only a material argument after signing.
    reject(url, {**values, 'amount_cents': 20001}, presentation(chain, holder, values))
    bad = presentation(chain, holder, values)
    raw = bytearray(chain[-1].to_bytes()); raw[-1] ^= 1
    bad['warrants'][-1] = base64.b64encode(raw).decode()
    reject(url, values, bad)
    bad = presentation(chain, holder, values); bad['warrants'] = ['not-a-warrant']
    reject(url, values, bad)


def test_untrusted_issuer(setup):
    _, holder, _, url = setup
    other = issue_invoice(SigningKey.generate(), holder.public_key, 'INV-123')
    result = reject(url, args(), presentation(other, holder, args()))
    assert result['denied'] not in ('ValueError', 'TypeError'), result


def test_expiry_at_receiver(setup):
    issuer, holder, _, url = setup
    limits = {'invoice_id': Exact('INV-123'), 'bank_account': Exact('verified-bank'),
              'amount_cents': Range(min=1, max=1420000)}
    root = Warrant.issue_issuer([TOOL], issuer, constraint_bounds=limits, holder=issuer.public_key, ttl_seconds=60)
    short = root.issue_execution().capability(TOOL, limits).holder(holder.public_key).ttl(1).terminal().build(issuer)
    time.sleep(2)
    result = reject(url, args(), presentation([root, short], holder, args()))
    assert 'Expir' in result['denied'], result


def test_original_defining_handler_direct_http_route(setup):
    # Real dispatch invokes worker.Handler.do_POST from its original defining module.
    # Bypass agent.py entirely and POST an unsigned payment to the original endpoint.
    _, _, _, url = setup
    assert worker.Handler.do_POST.__module__ == 'worker'
    request = Request(url + '/pay', data=json.dumps(args()).encode(),
                      headers={'Content-Type': 'application/json'})
    with pytest.raises(HTTPError) as caught:
        urlopen(request, timeout=5)
    assert caught.value.code == 403
    assert worker.effects == []


def test_terminal_execution_and_widening_not_issuable(setup):
    issuer, holder, chain, url = setup
    assert chain[-1].is_terminal()
    # Positive control: the terminal execution warrant works through the receiver.
    assert pay_invoice(url, **args(), **presentation(chain, holder, args())) == {'paid': True}
    before = len(worker.effects)
    with pytest.raises(Exception) as terminal:
        chain[-1].grant_builder().holder(SigningKey.generate().public_key).ttl(60).grant(holder)
    assert 'terminal' in str(terminal.value).lower() or 'depth' in str(terminal.value).lower()
    wider = {'invoice_id': Exact('INV-123'), 'bank_account': Exact('verified-bank'),
             'amount_cents': Range(min=1, max=1420001)}
    with pytest.raises(Exception) as widening:
        (chain[0].issue_execution().capability(TOOL, wider).holder(holder.public_key)
         .ttl(60).terminal().build(issuer))
    assert 'range expanded' in str(widening.value).lower()
    assert len(worker.effects) == before


def test_valid_proof_wrong_capability_at_receiver(setup):
    issuer, holder, _, url = setup
    other = 'refund_invoice'
    root = Warrant.issue_issuer([other], issuer, holder=issuer.public_key, ttl_seconds=60)
    leaf = root.issue_execution().capability(other, {}).holder(holder.public_key).ttl(30).terminal().build(issuer)
    result = reject(url, args(), presentation([root, leaf], holder, args()))
    assert result['denied'] not in ('ValueError', 'TypeError'), result


def test_unexpected_argument_and_missing_proof(setup):
    _, holder, chain, url = setup
    transport = presentation(chain, holder, args())
    reject(url, args(), {**transport, 'currency': 'EUR'}, 'ValueError')
    del transport['proof']
    reject(url, args(), transport, 'ValueError')


def test_cumulative_local_invoice_ceiling(setup):
    _, holder, chain, url = setup
    full = {**args(), 'amount_cents': 1420000}
    assert pay_invoice(url, **full, **presentation(chain, holder, full)) == {'paid': True}
    extra = {**args(), 'amount_cents': 1}
    reject(url, extra, presentation(chain, holder, extra), 'ValueError')
    assert len(worker.effects) == 1
