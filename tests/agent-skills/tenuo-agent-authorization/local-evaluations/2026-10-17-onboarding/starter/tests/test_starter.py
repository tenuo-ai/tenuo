import threading
import worker
from agent import pay_invoice

def test_original_payment_path():
    worker.effects.clear();server=worker.serve(0)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        assert pay_invoice('http://127.0.0.1:'+str(server.server_port),'INV-123','verified-bank',20000)=={'paid':True}
        assert len(worker.effects)==1
    finally:server.shutdown();server.server_close()

def test_direct_worker_route_exists():
    assert worker.Handler.do_POST
