"""Independent CLI issuance -> actual LangChain dispatch, fake effects only."""
from pathlib import Path
import subprocess, tempfile, sys
from langchain_core.tools import tool
from tenuo.langchain import TenuoTool
from tenuo.exceptions import ConstraintViolation

with tempfile.TemporaryDirectory(prefix='tenuo-cli-task-') as temp:
    project=Path(temp); home=project/'authority'; issued=project/'invoice.warrant'
    cli=Path(sys.executable).parent/'tenuo-cli'
    def run(*args):
        result=subprocess.run([str(cli),'--home',str(home),*args],capture_output=True,text=True)
        if result.returncode: raise RuntimeError(result.stdout+result.stderr)
    run('init','--dev')
    template=project/'invoice.yaml'
    template.write_text('version: 2\nname: invoice-task\nttl: 10m\ncapabilities:\n  pay_invoice:\n    invoice_id: INV-123\n    bank_account: verified-bank\n    amount_cents: 1..50000\n')
    run('template','validate','--file',str(template))
    run('warrant','issue','--template',str(template),'--holder','agent','--out',str(issued))
    run('warrant','verify','--file',str(issued))
    effects=[]
    @tool
    def pay_invoice(invoice_id: str,bank_account: str,amount_cents: int)->str:
        """Pay an approved invoice."""
        effects.append((invoice_id,bank_account,amount_cents));return 'paid'
    guarded=TenuoTool.local(pay_invoice,path=home,warrant=issued)
    allowed={'invoice_id':'INV-123','bank_account':'verified-bank','amount_cents':20000}
    assert guarded.invoke(allowed)=='paid' and len(effects)==1
    print('ALLOWED: INV-123, verified-bank, $200; effects=1')
    for changes in [{'bank_account':'attacker-bank'},{'invoice_id':'INV-999'},{'amount_cents':50001}]:
        before=len(effects)
        try:guarded.invoke({**allowed,**changes})
        except ConstraintViolation:pass
        else:raise AssertionError('Expected receiving constraint denial')
        assert len(effects)==before
        print('DENIED:',changes,'effects=0')
    # Removing the issuer secret cannot break receiving verification.
    (home/'keys/issuer.key').unlink()
    assert guarded.invoke(allowed)=='paid' and len(effects)==2
    print('ALLOWED after issuer secret removed; verifier uses public root; effects=1')
print('Development loop only: same-user key files are not OS isolation.')
