"""Unit tests for PoP arg normalization and warrant pre-validation.

Tests FINDING-002 fix (_normalize_args_for_pop, _normalize_pop_arg_value) and
FINDING-004 fix (_prevalidate_args_against_warrant) from the loan-underwriting
dogfooding exercise. See poc/loan-underwriting/FINDINGS.md for the original bugs.

Most tests exercise the pure Python helpers in isolation. A focused core
round-trip also proves that the normalized object and a JSON-looking string
produce distinct PoP inputs.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import time
from typing import Any

import pytest

from tenuo.temporal._pop import (
    _normalize_args_for_pop,
    _normalize_pop_arg_value,
    _prevalidate_args_against_warrant,
)
from tenuo.temporal.exceptions import (
    TenuoArgNormalizationError,
    TenuoPreValidationError,
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
        assert _normalize_pop_arg_value(-(2**63), "field") == -(2**63)
        assert _normalize_pop_arg_value(2**63 - 1, "field") == 2**63 - 1

    @pytest.mark.parametrize("value", [-(2**63) - 1, 2**63, 2**63 + 1])
    def test_int_outside_signed_core_range_is_refused(self, value):
        with pytest.raises(TenuoArgNormalizationError, match="signed 64-bit"):
            _normalize_pop_arg_value(value, "field")
        with pytest.raises(TenuoArgNormalizationError, match="signed 64-bit"):
            _normalize_pop_arg_value({"nested": value}, "field")

    def test_float_unchanged(self):
        assert _normalize_pop_arg_value(3.14, "field") == 3.14

    def test_bool_unchanged(self):
        assert _normalize_pop_arg_value(True, "field") is True
        assert _normalize_pop_arg_value(False, "field") is False

    def test_none_unchanged(self):
        assert _normalize_pop_arg_value(None, "field") is None


class TestNormalizePopArgValueDataclass:
    """Dataclasses become plain objects so their type cannot collide with text."""

    def test_simple_dataclass(self):
        model = SimpleModel(app_id="APP-001", loan_amount=100000.0, approved=True)
        result = _normalize_pop_arg_value(model, "application")

        assert result == {
            "app_id": "APP-001",
            "loan_amount": 100000.0,
            "approved": True,
        }

    def test_deterministic_across_two_calls(self):
        model = SimpleModel(app_id="APP-001", loan_amount=100000.0, approved=True)
        result1 = _normalize_pop_arg_value(model, "application")
        result2 = _normalize_pop_arg_value(model, "application")
        assert result1 == result2

    def test_nested_dataclass(self):
        inner = SimpleModel(app_id="APP-002", loan_amount=50000.0, approved=False)
        outer = NestedModel(application=inner, credit_score=720)
        result = _normalize_pop_arg_value(outer, "data")

        assert result["credit_score"] == 720
        assert result["application"]["app_id"] == "APP-002"

    def test_equal_values_normalize_equally(self):
        m1 = SimpleModel(app_id="X", loan_amount=1.0, approved=True)
        m2 = SimpleModel(app_id="X", loan_amount=1.0, approved=True)
        assert _normalize_pop_arg_value(m1, "f") == _normalize_pop_arg_value(m2, "f")

    def test_empty_dataclass(self):
        result = _normalize_pop_arg_value(EmptyModel(), "empty")
        assert result == {}


class TestNormalizePopArgValueDict:
    """Dicts remain objects; Rust canonicalization supplies stable ordering."""

    def test_simple_dict(self):
        d = {"b": 2, "a": 1}
        result = _normalize_pop_arg_value(d, "field")
        assert result == {"b": 2, "a": 1}

    def test_nested_dict(self):
        d = {"outer": {"inner": "value"}}
        result = _normalize_pop_arg_value(d, "field")
        assert result["outer"]["inner"] == "value"

    def test_deterministic_regardless_of_insertion_order(self):
        d1 = {"z": 1, "a": 2}
        d2 = {"a": 2, "z": 1}
        assert _normalize_pop_arg_value(d1, "f") == _normalize_pop_arg_value(d2, "f")


class TestNormalizePopArgValueListTuple:
    """Lists and tuples become recursively normalized lists."""

    def test_list_of_primitives(self):
        result = _normalize_pop_arg_value([1, "two", True], "field")
        assert result == [1, "two", True]

    def test_tuple_of_primitives_becomes_list(self):
        result = _normalize_pop_arg_value((1, 2, 3), "field")
        assert result == [1, 2, 3]

    def test_list_of_dataclasses_each_element_normalized(self):
        items = [SimpleModel("A", 1.0, True), SimpleModel("B", 2.0, False)]
        result = _normalize_pop_arg_value(items, "field")
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["app_id"] == "A"
        assert result[1]["app_id"] == "B"

    def test_empty_list(self):
        result = _normalize_pop_arg_value([], "field")
        assert result == []


class TestNormalizePopArgValueBytes:
    """Bare bytes fail closed because their wire form is converter-dependent."""

    def test_bytes_are_refused_instead_of_colliding_with_base64_text(self):
        raw = b"\x00\x01\x02\xff"
        with pytest.raises(TenuoArgNormalizationError, match="collide with a string"):
            _normalize_pop_arg_value(raw, "field")
        assert _normalize_pop_arg_value("AAEC/w==", "field") == "AAEC/w=="

    def test_empty_bytes(self):
        with pytest.raises(TenuoArgNormalizationError, match="bare bytes"):
            _normalize_pop_arg_value(b"", "field")


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
        assert "docs/temporal-reference.md" in str(exc_info.value)


class TestNormalizePopArgValueDepthGuard:
    """Pathologically deep nesting raises rather than stack-overflowing."""

    def test_list_nested_past_cap_raises(self):
        # Build a list-of-lists nested 40 levels deep — past the 32-level cap.
        # The shared normalizer enforces the same cap for every container type.
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
        assert result["application"]["app_id"] == "APP-001"

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
    """Build a minimal mock warrant exposing core-style diagnostics."""

    class MockWarrant:
        def diagnose_constraints(self, tool_name, args):
            tool_cap = capabilities.get(tool_name)
            if not isinstance(tool_cap, dict):
                return {
                    "closed_world": False,
                    "violations": [
                        {
                            "field": "tool",
                            "kind": "tool_not_authorized",
                            "reason": "tool not authorized",
                        }
                    ],
                }

            allow_unknown = tool_cap.get("_allow_unknown", False)
            declared = set(tool_cap) - {"_allow_unknown"}
            actual = set(args)
            violations = []
            if declared and not allow_unknown:
                violations.extend(
                    {
                        "field": field,
                        "kind": "unknown_field",
                        "reason": "unknown field not allowed (zero-trust mode)",
                    }
                    for field in sorted(actual - declared)
                )
            violations.extend(
                {
                    "field": field,
                    "kind": "missing_required",
                    "reason": "missing required argument",
                }
                for field in sorted(declared - actual)
            )
            return {
                "closed_world": bool(declared and not allow_unknown),
                "violations": violations,
            }

    w = MockWarrant()
    w.capabilities = capabilities
    return w


class TestPrevalidateArgsAgainstWarrant:
    """Pre-validation shim surfaces all field problems at once."""

    def test_valid_args_no_error(self):
        warrant = _make_mock_warrant({"score_risk": {"application_id": None, "credit_json": None}})
        # Exactly the declared fields — should pass silently.
        _prevalidate_args_against_warrant(warrant, "score_risk", {"application_id": "X", "credit_json": "{}"})

    def test_single_unknown_field_raises(self):
        warrant = _make_mock_warrant({"score_risk": {"application_id": None}})
        with pytest.raises(TenuoPreValidationError) as exc_info:
            _prevalidate_args_against_warrant(warrant, "score_risk", {"application_id": "X", "extra_field": "oops"})
        msg = str(exc_info.value)
        # Must preserve the core error phrase for substring-match compatibility.
        assert "unknown field not allowed (zero-trust mode)" in msg
        assert "extra_field" in msg
        assert "prefer Wildcard()" in msg
        assert "_allow_unknown=True" in msg
        assert "broad opt-out from closed-world checking" in msg

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
        warrant = _make_mock_warrant({"score_risk": {"application_id": None, "credit_json": None, "kyc_json": None}})
        with pytest.raises(TenuoPreValidationError) as exc_info:
            # Passes only application_id; credit_json and kyc_json missing.
            _prevalidate_args_against_warrant(warrant, "score_risk", {"application_id": "X"})
        msg = str(exc_info.value)
        assert "credit_json" in msg
        assert "kyc_json" in msg
        assert "missing" in msg.lower()
        assert "Provide every argument declared by the warrant capability" in msg
        assert "_allow_unknown=True" not in msg

    def test_mixed_unknown_and_missing_both_reported(self):
        warrant = _make_mock_warrant({"score_risk": {"application_id": None, "required_field": None}})
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
        _prevalidate_args_against_warrant(warrant, "score_risk", {"application_id": "X"})

    def test_empty_capability_is_noop(self):
        """Empty capability dict means no named constraints — allow_unknown effectively."""
        warrant = _make_mock_warrant({"score_risk": {}})
        _prevalidate_args_against_warrant(warrant, "score_risk", {"application_id": "X", "extra": "fine"})

    def test_allow_unknown_capability_permits_extra_fields(self):
        """The pre-validator honors core's per-capability allow-unknown bit."""
        warrant = _make_mock_warrant({"score_risk": {"application_id": None, "_allow_unknown": True}})

        _prevalidate_args_against_warrant(warrant, "score_risk", {"application_id": "X", "extra": "fine"})

    def test_allow_unknown_capability_still_requires_declared_fields(self):
        warrant = _make_mock_warrant({"score_risk": {"application_id": None}})
        warrant.allows_unknown_fields = lambda tool: tool == "score_risk"

        with pytest.raises(TenuoPreValidationError, match="application_id"):
            _prevalidate_args_against_warrant(warrant, "score_risk", {"extra": "fine"})

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
        from tenuo.temporal.exceptions import TenuoContextError

        warrant = _make_mock_warrant({"tool": {"x": None}})
        with pytest.raises(TenuoPreValidationError) as exc_info:
            _prevalidate_args_against_warrant(warrant, "tool", {"unknown": 1})
        assert isinstance(exc_info.value, TenuoContextError)


# ---------------------------------------------------------------------------
# Pydantic models: signed like dataclasses, not excluded from PoP
# ---------------------------------------------------------------------------


class TestNormalizePopArgValuePydantic:
    """Framework context objects are often Pydantic models; they're signed, not skipped."""

    def test_v2_model_is_plain_json_value_of_its_json_dump(self):
        pydantic = pytest.importorskip("pydantic")
        import datetime

        class Route(pydantic.BaseModel):
            topic: str
            partition: int

        class ToolContext(pydantic.BaseModel):
            run_id: str
            route: Route
            started: datetime.datetime

        ctx = ToolContext(
            run_id="r-1",
            route=Route(topic="events", partition=3),
            started=datetime.datetime(2026, 10, 22, 9, 30, tzinfo=datetime.timezone.utc),
        )
        result = _normalize_pop_arg_value(ctx, "tool_ctx")
        assert result == ctx.model_dump(mode="json")

    def test_v2_serialization_alias_matches_temporal_pydantic_converter(self):
        pydantic = pytest.importorskip("pydantic")
        converter_module = pytest.importorskip("temporalio.contrib.pydantic")

        class Ctx(pydantic.BaseModel):
            internal_name: str = pydantic.Field(serialization_alias="wireName")

        ctx = Ctx(internal_name="events")
        payload = converter_module.PydanticJSONPlainPayloadConverter().to_payload(ctx)
        assert payload is not None
        assert _normalize_pop_arg_value(ctx, "c") == json.loads(payload.data)
        assert _normalize_pop_arg_value(ctx, "c") == {"wireName": "events"}

    def test_same_model_values_sign_the_same_whatever_the_field_order(self):
        pydantic = pytest.importorskip("pydantic")

        class A(pydantic.BaseModel):
            x: int
            y: str

        class B(pydantic.BaseModel):
            y: str
            x: int

        assert _normalize_pop_arg_value(A(x=1, y="a"), "c") == _normalize_pop_arg_value(B(y="a", x=1), "c")

    def test_a_model_and_its_wire_dict_sign_the_same(self):
        # The workflow signs the model; a worker without a Pydantic converter
        # sees the decoded dict. Both must produce the same PoP input.
        pydantic = pytest.importorskip("pydantic")

        class Ctx(pydantic.BaseModel):
            topic: str
            retries: int

        ctx = Ctx(topic="events", retries=2)
        assert _normalize_pop_arg_value(ctx, "c") == _normalize_pop_arg_value(ctx.model_dump(mode="json"), "c")

    def test_v1_model(self):
        v1 = pytest.importorskip("pydantic.v1")

        class Ctx(v1.BaseModel):
            topic: str

        assert _normalize_pop_arg_value(Ctx(topic="events"), "c") == {"topic": "events"}

    @pytest.mark.parametrize("configured_on", ["field", "config"])
    def test_v1_inclusion_filters_that_hide_siblings_are_refused(self, configured_on):
        v1 = pytest.importorskip("pydantic.v1")

        if configured_on == "field":

            class Ctx(v1.BaseModel):
                visible: str = v1.Field(include=True)
                hidden: str

        else:

            class Ctx(v1.BaseModel):
                visible: str
                hidden: str

                class Config:
                    fields = {"visible": {"include": True}}

        original = Ctx(visible="same", hidden="one")
        substituted = Ctx(visible="same", hidden="two")
        assert original.dict() == substituted.dict() == {"visible": "same"}
        for value in (original, substituted):
            with pytest.raises(TenuoArgNormalizationError, match="inclusion-filtered"):
                _normalize_pop_arg_value(value, "c")

    def test_model_class_is_not_a_model_value(self):
        pydantic = pytest.importorskip("pydantic")

        class Ctx(pydantic.BaseModel):
            topic: str

        with pytest.raises(TenuoArgNormalizationError):
            _normalize_pop_arg_value(Ctx, "c")


def test_framework_args_declares_any_value_constraints():
    from tenuo import AnyValue
    from tenuo.temporal import framework_args

    declared = framework_args("tool_ctx", "run_meta")
    assert set(declared) == {"tool_ctx", "run_meta"}
    assert all(type(c) is type(AnyValue()) for c in declared.values())
    with pytest.raises(ValueError):
        framework_args()
    for reserved in ("_allow_unknown", "_workflow_id", "_workflow_namespace"):
        with pytest.raises(ValueError, match="reserved"):
            framework_args(reserved)


class TestSignedFormCoversWhatTheActivityReceives:
    def test_structured_value_cannot_impersonate_literal_json_text(self):
        structured = {"destination": "external"}
        literal = '{"destination": "external"}'
        assert _normalize_pop_arg_value(structured, "c") != _normalize_pop_arg_value(literal, "c")

    def test_pop_for_object_does_not_authorize_literal_json_text(self):
        from tenuo import AnyValue, Authorizer, SigningKey, Warrant
        from tenuo.exceptions import SignatureInvalid

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(holder.public_key)
            .capability("publish", payload=AnyValue())
            .ttl(60)
            .mint(issuer)
        )
        structured = {"payload": {"destination": "external"}}
        literal = {"payload": '{"destination":"external"}'}
        signature = warrant.sign(holder, "publish", structured, int(time.time()))
        authorizer = Authorizer(trusted_roots=[issuer.public_key])

        authorizer.authorize_one(warrant, "publish", structured, bytes(signature), [])
        with pytest.raises(SignatureInvalid):
            authorizer.authorize_one(warrant, "publish", literal, bytes(signature), [])

    def test_core_rejects_integer_overflow_instead_of_rounding_to_float(self):
        from tenuo import AnyValue, SigningKey, Warrant
        from tenuo.exceptions import ValidationError

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(holder.public_key)
            .capability("publish", payload=AnyValue())
            .ttl(60)
            .mint(issuer)
        )

        for value in (-(2**63) - 1, 2**63, 2**63 + 1):
            with pytest.raises(ValidationError, match="signed 64-bit"):
                warrant.sign(
                    holder,
                    "publish",
                    {"payload": value},
                    int(time.time()),
                )

    def test_nested_dataclass_signs_like_the_dict_the_worker_receives(self):
        @dataclasses.dataclass
        class Spec:
            topic: str
            limit: int

        signed = _normalize_pop_arg_value({"spec": Spec("events", 5), "tags": [Spec("a", 1)]}, "c")
        received = _normalize_pop_arg_value(
            {"spec": {"topic": "events", "limit": 5}, "tags": [{"topic": "a", "limit": 1}]}, "c"
        )
        assert signed == received

    @pytest.mark.parametrize("kind", ["excluded", "serializer", "secret"])
    def test_models_that_could_hide_a_value_are_refused(self, kind):
        pydantic = pytest.importorskip("pydantic")

        if kind == "excluded":

            class Ctx(pydantic.BaseModel):
                topic: str
                publish: bool = pydantic.Field(False, exclude=True)

            value = Ctx(topic="t", publish=True)
        elif kind == "serializer":

            class Ctx(pydantic.BaseModel):
                topic: str

                @pydantic.field_serializer("topic")
                def mask(self, v):
                    return "***"

            value = Ctx(topic="t")
        else:

            class Ctx(pydantic.BaseModel):
                topic: str
                token: pydantic.SecretStr

            value = Ctx(topic="t", token="s")
        with pytest.raises(TenuoArgNormalizationError, match="would not cover"):
            _normalize_pop_arg_value(value, "tool_ctx")

    @pytest.mark.parametrize("where", ["field", "list", "dict"])
    def test_a_nested_model_that_could_hide_a_value_is_refused(self, where):
        pydantic = pytest.importorskip("pydantic")

        class Child(pydantic.BaseModel):
            publish: bool = pydantic.Field(False, exclude=True)

        class Ctx(pydantic.BaseModel):
            child: Any

        child = Child(publish=True)
        nested = {"field": child, "list": [child], "dict": {"c": child}}[where]
        with pytest.raises(TenuoArgNormalizationError, match="would not cover"):
            _normalize_pop_arg_value(Ctx(child=nested), "tool_ctx")
        with pytest.raises(TenuoArgNormalizationError, match="would not cover"):
            _normalize_pop_arg_value({"ctx": nested}, "tool_ctx")

    def test_dict_keys_sign_as_json_transport_writes_them(self):
        sent = {True: "a", False: "b", 2: "d", 1.5: "e"}
        received = json.loads(json.dumps(sent))
        assert _normalize_pop_arg_value(sent, "c") == _normalize_pop_arg_value(received, "c")
        with pytest.raises(TenuoArgNormalizationError, match="None dictionary key"):
            _normalize_pop_arg_value({None: "converter-dependent"}, "c")
        with pytest.raises(TenuoArgNormalizationError, match="dict key"):
            _normalize_pop_arg_value({(1, 2): "x"}, "c")
        with pytest.raises(TenuoArgNormalizationError, match="both encode"):
            _normalize_pop_arg_value({1: "numeric", "1": "text"}, "c")

    def test_none_dict_key_differs_between_supported_temporal_converters(self):
        converter_module = pytest.importorskip("temporalio.contrib.pydantic")

        value = {None: "x"}
        standard = json.loads(json.dumps(value))
        payload = converter_module.PydanticJSONPlainPayloadConverter().to_payload(value)
        assert payload is not None
        pydantic_value = json.loads(payload.data)
        assert standard == {"null": "x"}
        assert pydantic_value == {"None": "x"}

    def test_colliding_pydantic_serialization_aliases_are_refused(self):
        pydantic = pytest.importorskip("pydantic")

        class Ctx(pydantic.BaseModel):
            destination: str
            marker: str = pydantic.Field("internal", serialization_alias="destination")

        original = Ctx(destination="internal", marker="masked")
        substituted = Ctx(destination="external", marker="masked")
        serializer = Ctx.__pydantic_serializer__
        assert serializer.to_python(original, mode="json", by_alias=True) == serializer.to_python(
            substituted, mode="json", by_alias=True
        )
        for value in (original, substituted):
            with pytest.raises(TenuoArgNormalizationError, match="serialized name"):
                _normalize_pop_arg_value(value, "c")

    @pytest.mark.parametrize("collision", ["extra", "computed"])
    def test_alias_collisions_with_extras_and_computed_fields_are_refused(self, collision):
        pydantic = pytest.importorskip("pydantic")

        if collision == "extra":

            class Ctx(pydantic.BaseModel):
                model_config = pydantic.ConfigDict(extra="allow")
                destination: str = pydantic.Field(serialization_alias="wire")

            value = Ctx(destination="external", wire="extra")
        else:

            class Ctx(pydantic.BaseModel):
                destination: str

                @pydantic.computed_field(alias="destination")
                @property
                def marker(self) -> str:
                    return "computed"

            value = Ctx(destination="external")

        with pytest.raises(TenuoArgNormalizationError, match="serialized name"):
            _normalize_pop_arg_value(value, "c")

    def test_conditional_exclusion_is_refused(self):
        pydantic = pytest.importorskip("pydantic")
        if "exclude_if" not in inspect.signature(pydantic.Field).parameters:
            pytest.skip("Pydantic version does not support Field(exclude_if=...)")

        class Ctx(pydantic.BaseModel):
            visible: str
            hidden: str = pydantic.Field("x-default", exclude_if=lambda value: value.startswith("x"))

        with pytest.raises(TenuoArgNormalizationError, match="excluded field"):
            _normalize_pop_arg_value(Ctx(visible="same", hidden="x-one"), "c")

    def test_overridden_model_dump_is_refused(self):
        pydantic = pytest.importorskip("pydantic")

        class Ctx(pydantic.BaseModel):
            visible: str
            hidden: str

            def model_dump(self, *args, **kwargs):
                return {"visible": self.visible}

        with pytest.raises(TenuoArgNormalizationError, match="overridden model_dump"):
            _normalize_pop_arg_value(Ctx(visible="same", hidden="secret"), "c")

    @pytest.mark.parametrize("kind", ["set", "frozenset"])
    def test_unordered_model_fields_are_refused(self, kind):
        pydantic = pytest.importorskip("pydantic")
        from typing import FrozenSet, Set

        if kind == "set":

            class Ctx(pydantic.BaseModel):
                tags: Set[str]

        else:

            class Ctx(pydantic.BaseModel):
                tags: FrozenSet[str]

        value = {"alpha", "beta"}
        if kind == "frozenset":
            value = frozenset(value)
        with pytest.raises(TenuoArgNormalizationError, match="unordered set"):
            _normalize_pop_arg_value(Ctx(tags=value), "c")

    def test_converter_dependent_nested_values_are_refused(self):
        import datetime

        with pytest.raises(TenuoArgNormalizationError, match="bare bytes"):
            _normalize_pop_arg_value({"blob": b"abc"}, "c")
        with pytest.raises(TenuoArgNormalizationError, match="unsupported nested type"):
            _normalize_pop_arg_value(
                {"when": datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)},
                "c",
            )

    @pytest.mark.parametrize("kind", ["annotated", "json_encoders", "secret_subclass", "typed_extra"])
    def test_other_ways_a_dump_can_hide_a_value_are_refused(self, kind):
        pydantic = pytest.importorskip("pydantic")
        from typing import Annotated, Dict

        if kind == "annotated":

            class Ctx(pydantic.BaseModel):
                topic: Annotated[str, pydantic.PlainSerializer(lambda v: "***")]

            value = Ctx(topic="t")
        elif kind == "json_encoders":

            class Ctx(pydantic.BaseModel):
                model_config = pydantic.ConfigDict(json_encoders={str: lambda v: "***"})
                topic: str

            value = Ctx(topic="t")
        elif kind == "secret_subclass":

            class ApiToken(pydantic.SecretStr):
                pass

            class Ctx(pydantic.BaseModel):
                token: ApiToken

            value = Ctx(token=ApiToken("s"))
        else:

            class Child(pydantic.BaseModel):
                publish: bool = pydantic.Field(False, exclude=True)

            class Ctx(pydantic.BaseModel):
                model_config = pydantic.ConfigDict(extra="allow")
                __pydantic_extra__: Dict[str, Child]

            value = Ctx(child={"publish": True})
        with pytest.raises(TenuoArgNormalizationError, match="would not cover"):
            _normalize_pop_arg_value(value, "tool_ctx")

    def test_a_secret_outside_any_model_is_refused(self):
        pydantic = pytest.importorskip("pydantic")

        with pytest.raises(TenuoArgNormalizationError, match="secret"):
            _normalize_pop_arg_value({"token": pydantic.SecretStr("s")}, "c")

    def test_faithful_builtin_types_still_sign(self):
        pydantic = pytest.importorskip("pydantic")
        import ipaddress
        from pathlib import Path

        class Ctx(pydantic.BaseModel):
            path: Path
            host: ipaddress.IPv4Address

        assert _normalize_pop_arg_value(Ctx(path=Path("/a"), host="10.0.0.1"), "c")
