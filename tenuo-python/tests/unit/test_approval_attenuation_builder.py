"""Python attenuation exposes monotone Rust approval operations."""
import pytest

from tenuo import Authorizer, SigningKey, Warrant


@pytest.fixture
def authority():
    holder, first, second = [SigningKey.generate() for _ in range(3)]
    root = Warrant.issue(holder, capabilities={"transfer": {}}, holder=holder.public_key,
                         required_approvers=[first.public_key], min_approvals=1,
                         approval_gates={"transfer": None})
    return holder, first, second, root


@pytest.mark.parametrize("native", [False, True])
def test_add_approvers_and_raise_threshold(authority, native):
    holder, first, second, root = authority
    if native:
        builder = root.attenuate_builder()
        builder.inherit_all()
        builder.add_approvers([second.public_key, first.public_key, second.public_key])
        builder.raise_min_approvals(2)
        builder.raise_min_approvals(1)
        child = builder.delegate(holder)
    else:
        child = (root.grant_builder().inherit_all()
                 .add_approvers([second.public_key, first.public_key, second.public_key])
                 .raise_min_approvals(2).raise_min_approvals(1).grant(holder))
    child = Warrant.from_base64(child.to_base64())
    assert {key.to_bytes() for key in child.required_approvers()} == {
        first.public_key.to_bytes(), second.public_key.to_bytes(),
    }
    assert child.min_approvals() == 2
    assert child.verify(holder.public_key.to_bytes())
    Authorizer(trusted_roots=[holder.public_key]).verify_chain([root, child])
    assert root.min_approvals() == 1
    assert len(root.required_approvers()) == 1


def test_added_approvers_inherit_threshold_adjustment(authority):
    holder, _, second, root = authority
    child = root.grant_builder().inherit_all().add_approvers([second.public_key]).grant(holder)
    assert child.min_approvals() == 2


def test_unachievable_threshold_is_rejected(authority):
    holder, _, _, root = authority
    with pytest.raises(Exception):
        root.grant_builder().inherit_all().raise_min_approvals(2).grant(holder)


@pytest.mark.parametrize("count", [-1, 2**32])
def test_invalid_unsigned_threshold_does_not_modify_builder(authority, count):
    holder, _, _, root = authority
    builder = root.grant_builder().inherit_all()
    with pytest.raises(OverflowError):
        builder.raise_min_approvals(count)
    assert builder.grant(holder).min_approvals() == 1
