import pytest
from tenuo import SigningKey, Warrant, Exact, Range
from development import presentation
from client import call_refund, result_is_error

@pytest.mark.asyncio
async def test_independent_real_stdio_narrow_policy_and_signed_args(tmp_path):
    issuer,holder=SigningKey.generate(),SigningKey.generate()
    warrant=Warrant.issue(issuer,capabilities={"refund_order":{"order_id":Exact("123"),"amount_cents":Range(min=1,max=10000)}},ttl_seconds=120,holder=holder.public_key)
    root=issuer.public_key.to_bytes().hex()
    journal=tmp_path/'independent-effects'
    cases=[(10001,presentation(warrant,holder,"123",10001)),(5000,presentation(warrant,holder,"123",4000)),(5000,presentation(warrant,SigningKey.generate(),"123",5000))]
    for amount,meta in cases:
        result=await call_refund(journal,"123",amount,meta,trusted_root=root)
        assert result_is_error(result)
        assert not journal.exists() or journal.read_text()==''
    result=await call_refund(journal,"123",9999,presentation(warrant,holder,"123",9999),trusted_root=root)
    assert not result_is_error(result)
    assert journal.read_text()=='123:9999\n'
