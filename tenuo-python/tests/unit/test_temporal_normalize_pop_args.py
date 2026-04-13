"""Unit tests for PoP arg normalization and warrant pre-validation.

Tests FINDING-002 fix (_normalize_args_for_pop, _normalize_pop_arg_value) and
FINDING-004 fix (_prevalidate_args_against_warrant) from the loan-underwriting
dogfooding exercise. See poc/loan-underwriting/FINDINGS.md for the original bugs.

These tests exercise the pure Python helpers in isolation — no Temporal worker,
no warrant signing, no Rust calls.
"""
from __future__ import annotations

import base64
import dataclasses
import json

import pytest

from tenuo.temporal import (
    TenuoArgNormalizationError,
    TenuoPreValidationError,
    _normalize_args_for_pop,
    _normalize_pop_arg_value,
    _prevalidate_args_against_warrant,
)


# =============================================================================
# Test fixtures — representative activity arg types
# =============================================================================


@dataclasses.dataclass
class SimpleModel:
    app_id: str
    loan_amount: float
    approved: bool


@dataclasses.dataclass
class NestedModel:
    application: SimpleModel
    credit_score: int


@dataclasses.dataclass
class EmptyModel:
    pass


# =============================================================================
# _normalize_pop_arg_value — individual value normalization
# =============================================================================


class TestNormalizePopArgValuePrimitives:
    """Primitives pass through unchanged — no normalization needed."""

    def test_str_unchanged(self):
        assert _normalize_pop_arg_value("hello", "field") == "hello"

    def test_int_unchanged(self):
        assert _normalize_pop_arg_value(42, "field") == 42

    def test_float_unchanged(self):
        assert _normalize_pop_arg_value(3.14, "field") == 3.14

    def test_bool_unchanged(self):
        assert _normalize_pop_arg_value(True, "field") is True
        assert _normalize_pop_arg_value(False, "field") is False

    def test_none_unchanged(self):
        assert _normalize_pop_arg_value(None, "field") is None


class TestNormalizePopArgValueDataclass:
    """Dataclasses → canonical JSON string via dataclasses.asdict()."""

    def test_simple_dataclass(self):
        model = SimpleModel(app_id="APP-001", loan_amount=100000.0, approved=True)
        result = _normalize_pop_arg_value(model, "application")

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["app_id"] == "APP-001"
        assert parsed["loan_amount"] == 100000.0
        assert parsed["approved"] is True

    def test_deterministic_across_two_calls(self):
        model = SimpleModel(app_id="APP-001", loan_amount=100000.0, approved=True)
        result1 = _normalize_pop_arg_value(model, "application")
        result2 = _normalize_pop_arg_value(model, "application")
        assert result1 == result2

    def test_nested_dataclass(self):
        inner = SimpleModel(app_id="APP-002", loan_amount=50000.0, approved=False)
        outer = NestedModel(application=inner, credit_score=720)
        result = _normalize_pop_arg_value(outer, "data")

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["credit_score"] == 720
        assert parsed["application"]["app_id"] == "APP-002"

    def test_sort_keys_canonical(self):
        """Two dicts with identical content but different insertion order must produce identical JSON."""
        # Build two dataclasses with the same values — asdict() preserves field declaration order,
        # but json.dumps(sort_keys=True) ensures canonical output regardless.
        m1 = SimpleModel(app_id="X", loan_amount=1.0, approved=True)
        m2 = SimpleModel(app_id="X", loan_amount=1.0, approved=True)
        assert _normalize_pop_arg_value(m1, "f") == _normalize_pop_arg_value(m2, "f")

    def test_empty_dataclass(self):
        result = _normalize_pop_arg_value(EmptyModel(), "empty")
        assert result == "{}"


class TestNormalizePopArgValueDict:
    """Dicts → canonical JSON string with sorted keys."""

    def test_simple_dict(self):
        d = {"b": 2, "a": 1}
        result = _normalize_pop_arg_value(d, "field")
        assert isinstance(result, str)
        # sort_keys=True: "a" before "b"
        assert result == '{"a": 1, "b": 2}'

    def test_nested_dict(self):
        d = {"outer": {"inner": "value"}}
        result = _normalize_pop_arg_value(d, "field")
        parsed = json.loads(result)
        assert parsed["outer"]["inner"] == "value"

    def test_deterministic_regardless_of_insertion_order(self):
        d1 = {"z": 1, "a": 2}
        d2 = {"a": 2, "z": 1}
        assert _normalize_pop_arg_value(d1, "f") == _normalize_pop_arg_value(d2, "f")


class TestNormalizePopArgValueListTuple:
    """Lists of primitives pass through as list; lists with complex items get stringified."""

    def test_list_of_primitives(self):
        result = _normalize_pop_arg_value([1, "two", True], "field")
        assert result == [1, "two", True]

    def test_tuple_of_primitives_becomes_list(self):
        result = _normalize_pop_arg_value((1, 2, 3), "field")
        assert result == [1, 2, 3]

    def test_list_of_dataclasses_each_element_normalized(self):
        items = [SimpleModel("A", 1.0, True), SimpleModel("B", 2.0, False)]
        result = _normalize_pop_arg_value(items, "field")
        # Each dataclass becomes a JSON string; the list itself stays as a list
        # of strings (which the Rust CBOR encoder accepts as a list of primitives).
        assert isinstance(result, list)
        assert len(result) == 2
        assert isinstance(result[0], str)
        assert json.loads(result[0])["app_id"] == "A"
        assert isinstance(result[1], str)
        assert json.loads(result[1])["app_id"] == "B"

    def test_empty_list(self):
        result = _normalize_pop_arg_value([], "field")
        assert result == []


class TestNormalizePopArgValueBytes:
    """bytes → base64-encoded ASCII string."""

    def test_bytes_base64_encoded(self):
        raw = b"\x00\x01\x02\xff"
        result = _normalize_pop_arg_value(raw, "field")
        assert isinstance(result, str)
        assert base64.b64decode(result) == raw

    def test_empty_bytes(self):
        result = _normalize_pop_arg_value(b"", "field")
        assert result == ""


class TestNormalizePopArgValueUnsupported:
    """Unsupported types raise TenuoArgNormalizationError, not silently stringify."""

    def test_set_raises(self):
        with pytest.raises(TenuoArgNormalizationError) as exc_info:
            _normalize_pop_arg_value({1, 2, 3}, "my_set")
        assert "my_set" in str(exc_info.value)
        assert "set" in str(exc_info.value)

    def test_custom_class_raises(self):
        class MyCustomClass:
            value = 42

        with pytest.raises(TenuoArgNormalizationError) as exc_info:
            _normalize_pop_arg_value(MyCustomClass(), "custom_field")
        assert "custom_field" in str(exc_info.value)
        assert "MyCustomClass" in str(exc_info.value)

    def test_datetime_raises(self):
        import datetime
        with pytest.raises(TenuoArgNormalizationError):
            _normalize_pop_arg_value(datetime.datetime.now(), "ts")

    def test_enum_raises(self):
        import enum

        class Color(enum.Enum):
            RED = 1

        with pytest.raises(TenuoArgNormalizationError):
            _normalize_pop_arg_value(Color.RED, "color")

    def test_error_message_includes_docs_link(self):
        with pytest.raises(TenuoArgNormalizationError) as exc_info:
            _normalize_pop_arg_value({1, 2}, "s")
        assert "docs/temporal.md" in str(exc_info.value)


class TestNormalizePopArgValueDepthGuard:
    """Pathologically deep nesting raises rather than stack-overflowing."""

    def test_list_nested_past_cap_raises(self):
        # Build a list-of-lists nested 40 levels deep — past the 32-level cap.
        # The depth guard fires when _normalize_pop_arg_value recurses element-wise
        # through nested lists. (Dicts are handled by json.dumps directly, which
        # has Python's own recursion limit as protection.)
        deep: list = []
        current = deep
        for _ in range(40):
            child: list = []
            current.append(child)
            current = child

        with pytest.raises((TenuoArgNormalizationError, RecursionError)):
            _normalize_pop_arg_value(deep, "deep_field")


# =============================================================================
# _normalize_args_for_pop — full dict normalization
# =============================================================================


class TestNormalizeArgsForPop:
    """Integration tests over the full args dict."""

    def test_all_primitives_unchanged(self):
        args = {"app_id": "X", "amount": 100, "rate": 3.5, "approved": True}
        result = _normalize_args_for_pop(args)
        assert result == args

    def test_mixed_primitive_and_dataclass(self):
        model = SimpleModel(app_id="APP-001", loan_amount=100000.0, approved=True)
        args = {"application_id": "APP-001", "application": model, "score": 95}
        result = _normalize_args_for_pop(args)

        assert result["application_id"] == "APP-001"
        assert result["score"] == 95
        assert isinstance(result["application"], str)
        assert json.loads(result["application"])["app_id"] == "APP-001"

    def test_preserves_key_order(self):
        args = {"a": 1, "b": 2, "c": 3}
        result = _normalize_args_for_pop(args)
        assert list(result.keys()) == ["a", "b", "c"]

    def test_empty_dict(self):
        assert _normalize_args_for_pop({}) == {}

    def test_raises_for_unsupported_type(self):
        args = {"good": "value", "bad": {1, 2, 3}}
        with pytest.raises(TenuoArgNormalizationError) as exc_info:
            _normalize_args_for_pop(args)
        assert "bad" in str(exc_info.value)


# =============================================================================
# _prevalidate_args_against_warrant — FINDING-004 pre-validation shim
# =============================================================================


def _make_mock_warrant(capabilities: dict) -> object:
    """Build a minimal mock warrant object with .capabilities dict."""
    class MockWarrant:
        pass
    w = MockWarrant()
    w.capabilities = capabilities
    return w


class TestPrevalidateArgsAgainstWarrant:
    """Pre-validation shim surfaces all field problems at once."""

    def test_valid_args_no_error(self):
        warrant = _make_mock_warrant({
            "score_risk": {"application_id": None, "credit_json": None}
        })
        # Exactly the declared fields — should pass silently.
        _prevalidate_args_against_warrant(
            warrant, "score_risk", {"application_id": "X", "credit_json": "{}"}
        )

    def test_single_unknown_field_raises(self):
        warrant = _make_mock_warrant({"score_risk": {"application_id": None}})
        with pytest.raises(TenuoPreValidationError) as exc_info:
            _prevalidate_args_against_warrant(
                warrant, "score_risk", {"application_id": "X", "extra_field": "oops"}
            )
        msg = str(exc_info.value)
        # Must preserve the core error phrase for substring-match compatibility.
        assert "unknown field not allowed (zero-trust mode)" in msg
        assert "extra_field" in msg

    def test_multiple_unknown_fields_all_listed(self):
        warrant = _make_mock_warrant({"score_risk": {"application_id": None}})
        with pytest.raises(TenuoPreValidationError) as exc_info:
            _prevalidate_args_against_warrant(
                warrant,
                "score_risk",
                {
                    "application_id": "X",
                    "application_json": "{}",
                    "credit_report_json": "{}",
                    "kyc_result_json": "{}",
                    "financial_analysis_json": "{}",
                },
            )
        msg = str(exc_info.value)
        # All four unknown fields must appear in one error.
        assert "application_json" in msg
        assert "credit_report_json" in msg
        assert "kyc_result_json" in msg
        assert "financial_analysis_json" in msg
        assert "unknown field not allowed (zero-trust mode)" in msg

    def test_missing_required_fields_listed(self):
        warrant = _make_mock_warrant({
            "score_risk": {"application_id": None, "credit_json": None, "kyc_json": None}
        })
        with pytest.raises(TenuoPreValidationError) as exc_info:
            # Passes only application_id; credit_json and kyc_json missing.
            _prevalidate_args_against_warrant(
                warrant, "score_risk", {"application_id": "X"}
            )
        msg = str(exc_info.value)
        assert "credit_json" in msg
        assert "kyc_json" in msg
        assert "missing" in msg.lower()

    def test_mixed_unknown_and_missing_both_reported(self):
        warrant = _make_mock_warrant({
            "score_risk": {"application_id": None, "required_field": None}
        })
        with pytest.raises(TenuoPreValidationError) as exc_info:
            _prevalidate_args_against_warrant(
                warrant,
                "score_risk",
                {"application_id": "X", "mystery_field": "?"},
                # required_field is missing, mystery_field is unknown
            )
        msg = str(exc_info.value)
        assert "mystery_field" in msg
        assert "required_field" in msg

    def test_tool_not_in_warrant_is_noop(self):
        """If the tool is not declared in the warrant, skip pre-validation (let core handle)."""
        warrant = _make_mock_warrant({"other_tool": {"x": None}})
        # No error raised — core will handle the missing-tool case.
        _prevalidate_args_against_warrant(
            warrant, "score_risk", {"application_id": "X"}
        )

    def test_empty_capability_is_noop(self):
        """Empty capability dict means no named constraints — allow_unknown effectively."""
        warrant = _make_mock_warrant({"score_risk": {}})
        _prevalidate_args_against_warrant(
            warrant, "score_risk", {"application_id": "X", "extra": "fine"}
        )

    def test_no_capabilities_attr_is_noop(self):
        """Warrant with no .capabilities attribute — fall through gracefully."""
        class BareWarrant:
            pass
        _prevalidate_args_against_warrant(BareWarrant(), "score_risk", {"x": 1})

    def test_non_dict_capabilities_is_noop(self):
        """Warrant with unexpected .capabilities type — fall through gracefully."""
        class WeirdWarrant:
            capabilities = "not-a-dict"
        _prevalidate_args_against_warrant(WeirdWarrant(), "score_risk", {"x": 1})

    def test_error_type_is_non_retryable_subclass(self):
        """TenuoPreValidationError inherits from TenuoContextError — caught as non-retryable."""
        from tenuo.temporal import TenuoContextError
        warrant = _make_mock_warrant({"tool": {"x": None}})
        with pytest.raises(TenuoPreValidationError) as exc_info:
            _prevalidate_args_against_warrant(warrant, "tool", {"unknown": 1})
        assert isinstance(exc_info.value, TenuoContextError)
