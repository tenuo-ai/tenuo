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
