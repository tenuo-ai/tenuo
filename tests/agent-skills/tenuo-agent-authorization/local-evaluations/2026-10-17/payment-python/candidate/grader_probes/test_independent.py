import importlib
import pytest
from tenuo import SigningKey
from payment_service import PaymentClient, Presentation, AuthorizationDenied, issue_transfer_authority, present_transfer, execute_transfer

@pytest.fixture
def flow():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    service = PaymentClient(issuer.public_key)
    chain = issue_transfer_authority(issuer, holder.public_key, recipient='independent-vendor', max_amount=725)
    return issuer, holder, service, chain

def test_independent_positive_control(flow):
    _, holder, service, chain = flow
    proof = present_transfer(chain, holder, 'independent-vendor', 724)
    execute_transfer('independent-vendor', 724, authority=proof, service=service)
    assert service.calls == [('independent-vendor', 724)]

@pytest.mark.parametrize('recipient,amount', [('other-vendor',724), ('independent-vendor',726)])
def test_receiver_constraint_cases(flow, recipient, amount):
    _, holder, service, chain = flow
    proof = present_transfer(chain, holder, recipient, amount)
    with pytest.raises(AuthorizationDenied) as exc:
        service.transfer(recipient,amount,authority=proof)
    assert 'constraint' in str(exc.value.__cause__).lower()
    assert service.calls == []

def test_proof_binds_executed_value(flow):
    _, holder, service, chain = flow
    proof = present_transfer(chain, holder, 'independent-vendor', 724)
    with pytest.raises(AuthorizationDenied) as exc:
        service.transfer('independent-vendor',723,authority=proof)
    assert 'proof' in str(exc.value.__cause__).lower()
    assert service.calls == []

def test_unconfigured_original_route_even_with_valid_authority(flow):
    _, holder, _, chain = flow
    original = importlib.import_module('payment_service.client')
    proof = present_transfer(chain,holder,'independent-vendor',724)
    for raw in [original.PaymentClient(),original.client]:
        with pytest.raises(AuthorizationDenied):
            raw.transfer('independent-vendor',724,authority=proof)
        assert raw.calls == []
    with pytest.raises(AuthorizationDenied):
        original.execute_transfer('independent-vendor',724,authority=proof)
    assert original.client.calls == []

def test_request_cannot_set_verification_time_or_key(flow):
    _, holder, service, chain = flow
    proof = present_transfer(chain,holder,'independent-vendor',724)
    for injected in [{'as_of':0},{'signing_key':holder}]:
        with pytest.raises(TypeError):
            service.transfer('independent-vendor',724,authority=proof,**injected)
        assert service.calls == []

def test_denial_does_not_contaminate_next_allowed_call(flow):
    _, holder, service, chain = flow
    bad=present_transfer(chain,holder,'independent-vendor',726)
    with pytest.raises(AuthorizationDenied):
        service.transfer('independent-vendor',726,authority=bad)
    assert service.calls == []
    good=present_transfer(chain,holder,'independent-vendor',725)
    service.transfer('independent-vendor',725,authority=good)
    assert service.calls == [('independent-vendor',725)]
