"""Every positional argument retains a unique, accurate authorization name."""

import pytest

pytest.importorskip("temporalio")

from tenuo.temporal._pop import _args_to_dict_by_fn  # noqa: E402
from tenuo.temporal.exceptions import TenuoContextError  # noqa: E402


def test_fallback_name_cannot_overwrite_a_real_parameter():
    def activity(arg1, *rest):
        return arg1

    with pytest.raises(TenuoContextError, match="argument name"):
        _args_to_dict_by_fn(("secret", "public"), activity)


def test_varargs_are_not_named_after_keyword_only_parameters():
    def activity(first, *rest, destination="private"):
        return first, rest, destination

    assert _args_to_dict_by_fn(("first", "extra"), activity) == {"first": "first", "arg1": "extra"}


def test_plain_parameter_named_self_is_preserved():
    def activity(self, destination):
        return self, destination

    assert _args_to_dict_by_fn(("first", "second"), activity) == {"self": "first", "destination": "second"}


def test_bound_method_uses_its_visible_signature():
    class Activities:
        def activity(self, destination):
            return destination

    assert _args_to_dict_by_fn(("public",), Activities().activity) == {"destination": "public"}


def test_plain_self_parameter_is_preserved_when_signing():
    from temporalio import activity

    @activity.defn
    def plain(self: str, destination: str):
        return self, destination

    assert _args_to_dict_by_fn(("first", "second"), plain, for_signing=True) == {"self": "first", "destination": "second"}


from temporalio import activity  # noqa: E402


class Activities:
    @activity.defn
    def method(self, destination: str):
        return destination

    @activity.defn
    def varargs(self, *values):
        return values

    @staticmethod
    @activity.defn
    def static(self: str, destination: str):
        return self, destination


def test_unbound_activity_method_matches_the_worker_bound_method():
    caller = _args_to_dict_by_fn(("public",), Activities.method, for_signing=True)
    worker = _args_to_dict_by_fn(("public",), Activities().method)
    assert caller == worker == {"destination": "public"}


def test_unbound_vararg_activity_keeps_every_argument():
    args = ("first", "second", "third")
    assert _args_to_dict_by_fn(args, Activities.varargs, for_signing=True) == _args_to_dict_by_fn(args, Activities().varargs)


def test_static_activity_preserves_its_explicit_self_parameter():
    args = ("first", "second")
    assert _args_to_dict_by_fn(args, Activities.static, for_signing=True) == {"self": "first", "destination": "second"}


def test_unresolvable_local_method_requires_a_worker_callable():
    class Local:
        @activity.defn
        def method(self, destination: str):
            return destination

    with pytest.raises(TenuoContextError, match="bound callable"):
        _args_to_dict_by_fn(("public",), Local.method, for_signing=True)
