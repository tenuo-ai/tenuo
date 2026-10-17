import pytest
from client import call_refund

@pytest.mark.asyncio
async def test_refund(tmp_path):
    journal = tmp_path / "refunds"
    await call_refund(journal,"123",20000)
    assert journal.read_text() == "123:20000\n"

@pytest.mark.asyncio
async def test_another_refund(tmp_path):
    journal = tmp_path / "refunds"
    await call_refund(journal,"123",10000)
    assert journal.read_text() == "123:10000\n"
