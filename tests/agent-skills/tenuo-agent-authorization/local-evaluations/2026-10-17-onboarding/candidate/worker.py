"""Public-proof-only verification at the existing HTTP payment effect boundary."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tenuo import Authorizer, Warrant
from authority import MAX_EXACT_CENTS, TOOL, RECORDS

effects = []  # Fake provider journal, owned by the trusted worker in deployment.


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            if self.path != '/pay':
                raise ValueError('unknown route')
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 65536:
                raise ValueError('invalid request size')
            request = json.loads(self.rfile.read(size))
            if set(request) != {'invoice_id', 'bank_account', 'amount_cents', 'warrants', 'proof'}:
                raise ValueError('missing authority or unexpected arguments')
            args = {k: request[k] for k in ('invoice_id', 'bank_account', 'amount_cents')}
            if not all(type(args[k]) is str and args[k] for k in ('invoice_id', 'bank_account')):
                raise ValueError('invalid payment identifiers')
            amount = args['amount_cents']
            if type(amount) is not int or not 1 <= amount <= MAX_EXACT_CENTS:
                raise ValueError('amount must be lossless positive integer cents')
            if type(request['warrants']) is not list or len(request['warrants']) != 2:
                raise ValueError('missing warrant chain')
            chain = [Warrant.from_base64(w) for w in request['warrants']]
            proof = base64.b64decode(request['proof'], validate=True)
            self.server.authorizer.check_chain(chain, TOOL, args, signature=proof)
            # Execute exactly the same values that were verified; no downstream coercion.
            with self.server.payment_lock:
                record = self.server.approvals[args['invoice_id']]
                if (record['status'] != 'approved' or record['currency'] != 'USD'
                        or record['approved_bank_account'] != args['bank_account']):
                    raise ValueError('payment does not match trusted approval')
                spent = self.server.paid_cents.get(args['invoice_id'], 0)
                if spent + amount > record['approved_amount_cents']:
                    raise ValueError('invoice approval exhausted')
                effects.append(args.copy())
                self.server.paid_cents[args['invoice_id']] = spent + amount
        except Exception as exc:
            # Local-only diagnostic type; do not reveal policy details over production HTTP.
            self.send_response(403)
            self.end_headers()
            self.wfile.write(json.dumps({'denied': type(exc).__name__}).encode())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"paid":true}')

    def log_message(self, *args):
        pass


def serve(port=8080, *, trusted_roots=()):
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.approvals = json.loads(RECORDS.read_text())
    server.payment_lock = threading.Lock()
    server.paid_cents = {}  # Development-only; production requires atomic durable state.
    server.authorizer = Authorizer(trusted_roots=list(trusted_roots), clock_tolerance_secs=0)
    return server


if __name__ == '__main__':
    raise SystemExit('Configure explicit public trust roots via serve(); run demo.py for the local demo.')
