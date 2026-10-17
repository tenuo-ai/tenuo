"""One-command deterministic development loop; fake effects, ephemeral local keys."""
import threading
from urllib.error import HTTPError
from tenuo import SigningKey
import worker
from agent import pay_invoice, presentation
from authority import issue_invoice


def main():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    chain = issue_invoice(issuer, holder.public_key, 'INV-123')
    server = worker.serve(0, trusted_roots=[issuer.public_key])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    print('Development loop: INV-123, verified-bank, USD cents 1..1420000, TTL 300s, terminal')
    try:
        for label, bank, amount in [('approved partial payment', 'verified-bank', 20000),
                                     ('injected bank diversion', 'attacker-bank', 20000),
                                     ('amount above approval', 'verified-bank', 1420001)]:
            args = dict(invoice_id='INV-123', bank_account=bank, amount_cents=amount)
            before = len(worker.effects)
            try:
                pay_invoice(url, **args, **presentation(chain, holder, args))
                status = 'ALLOW'
            except HTTPError as error:
                assert error.code == 403
                status = 'DENY'
            count = len(worker.effects) - before
            assert count == (1 if status == 'ALLOW' else 0)
            print(f'{status}: {label}; effects={count}')
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
