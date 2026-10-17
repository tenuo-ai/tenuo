import pytest
from dev_authority import authorize_refund, TRUSTED_ROOT
from refund_security import RefundVerifier
from temporalio.exceptions import ApplicationError

def test_independent_public_receiver_changed_arguments():
    receiver=RefundVerifier([TRUSTED_ROOT])
    proof=authorize_refund("123",200)
    for amount,authority in [(201,proof),(200,None),(True,proof)]:
        with pytest.raises(ApplicationError) as exc:
            receiver.verify("123",amount,authority)
        assert exc.value.non_retryable
        assert exc.value.type == "RefundAuthorizationDenied"
    assert receiver.verify("123",200,proof)=={"order_id":"123","amount_cents":200}
