import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

effects=[]
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        effects.append(request)  # Fake payment-provider call; no real credentials.
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"paid":true}')
    def log_message(self,*args): pass

def serve(port=8080):
    return ThreadingHTTPServer(('127.0.0.1',port),Handler)

if __name__=='__main__': serve().serve_forever()
