"""Strict JSON-type check of tool arguments against a tool's input schema."""

import pytest

from tenuo._arg_types import argument_type_mismatches, tool_input_schema

SCHEMA = {
    "type": "object",
    "properties": {
        "env": {"type": "string"},
        "dry_run": {"type": "boolean", "default": True},
        "replicas": {"type": "integer"},
        "budget": {"type": "number"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "limit": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None},
        "port": {"type": ["integer", "null"]},
        "options": {"$ref": "#/$defs/Options"},
        "anything": {},
    },
    "$defs": {
        "Options": {
            "type": "object",
            "properties": {"force": {"type": "boolean"}},
        }
    },
}


def test_values_of_the_declared_types_pass():
    args = {
        "env": "prod",
        "dry_run": False,
        "replicas": 3,
        "budget": 5,
        "tags": ["a", "b"],
        "limit": None,
        "port": 22,
        "options": {"force": True},
        "anything": {"nested": ["x", 1]},
        "undeclared": "left to the closed-world check",
    }
    assert argument_type_mismatches(SCHEMA, args) == []
    # 22.0 is a JSON integer; 5.5 is a JSON number.
    assert argument_type_mismatches(SCHEMA, {"replicas": 22.0, "budget": 5.5}) == []


@pytest.mark.parametrize(
    "name, value",
    [
        ("dry_run", "off"),
        ("dry_run", "false"),
        ("dry_run", 0),
        ("dry_run", 1),
        ("replicas", "22"),
        ("replicas", " 22"),
        ("replicas", 22.5),
        ("replicas", True),
        ("budget", "5000"),
        ("budget", True),
        ("env", 5),
        ("env", ["prod"]),
        ("tags", '["a"]'),
        ("tags", ["a", 1]),
        ("limit", "5"),
        ("port", "22"),
        ("options", {"force": "yes"}),
        ("options", "{}"),
    ],
)
def test_values_the_tool_would_convert_are_reported(name, value):
    assert argument_type_mismatches(SCHEMA, {name: value}) == [name]


def test_mismatches_are_sorted_and_only_top_level_names():
    args = {"replicas": "1", "dry_run": "on", "env": "prod"}
    assert argument_type_mismatches(SCHEMA, args) == ["dry_run", "replicas"]


@pytest.mark.parametrize("schema", [None, {}, {"type": "object"}, "not a schema", {"properties": []}])
def test_missing_or_unreadable_schema_reports_nothing(schema):
    assert argument_type_mismatches(schema, {"replicas": "22"}) == []


def test_unresolvable_reference_denies_the_value():
    schema = {"properties": {"x": {"$ref": "#/$defs/Missing"}, "y": {"$ref": "http://example.com/s"}}}
    assert argument_type_mismatches(schema, {"x": "1", "y": 2}) == ["x", "y"]


def test_composite_object_schemas_and_sibling_rules_are_all_checked():
    schema = {"allOf": [{"properties": {"flag": {"type": "boolean"}}}]}
    assert argument_type_mismatches(schema, {"flag": "off"}) == ["flag"]
    assert argument_type_mismatches(schema, {"flag": False}) == []
    schema = {"properties": {"flag": {"anyOf": [{}], "type": "boolean"}}}
    assert argument_type_mismatches(schema, {"flag": "off"}) == ["flag"]
    schema = {"$defs": {"Any": {}}, "properties": {"flag": {"$ref": "#/$defs/Any", "type": "boolean"}}}
    assert argument_type_mismatches(schema, {"flag": "off"}) == ["flag"]


def test_union_must_match_the_whole_argument_object():
    schema = {"anyOf": [
        {"properties": {"x": {"type": "boolean"}, "y": {"type": "integer"}}},
        {"properties": {"x": {"type": "integer"}, "y": {"type": "boolean"}}},
    ]}
    assert argument_type_mismatches(schema, {"x": True, "y": 1}) == []
    assert argument_type_mismatches(schema, {"x": True, "y": True}) == ["x", "y"]


def test_pydantic_mapping_and_tuple_elements_are_checked():
    from typing import Dict, Tuple

    from pydantic import BaseModel

    class Args(BaseModel):
        flags: Dict[str, bool]
        pair: Tuple[bool, int]

    schema = Args.model_json_schema()
    converted = {"flags": {"enabled": "off"}, "pair": ["yes", "22"]}
    parsed = Args.model_validate(converted)
    assert parsed.flags == {"enabled": False}
    assert parsed.pair == (True, 22)
    assert argument_type_mismatches(schema, converted) == ["flags", "pair"]
    assert argument_type_mismatches(schema, {"flags": {"enabled": False}, "pair": [True, 22]}) == []


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_are_not_json_numbers(value):
    assert argument_type_mismatches(SCHEMA, {"budget": value}) == ["budget"]


def test_recursive_and_deep_schema_rules_fail_closed():
    schema = {"$defs": {"Loop": {"$ref": "#/$defs/Loop"}}, "properties": {"x": {"$ref": "#/$defs/Loop"}}}
    assert argument_type_mismatches(schema, {"x": "off"}) == ["x"]
    rule = {"type": "boolean"}
    for _ in range(20):
        rule = {"allOf": [rule]}
    assert argument_type_mismatches({"properties": {"x": rule}}, {"x": "off"}) == ["x"]


def test_literal_union_branch_cannot_hide_numeric_conversion():
    from typing import Literal, Union

    from pydantic import BaseModel

    class Args(BaseModel):
        limit: Union[Literal["auto"], int]

    schema = Args.model_json_schema()
    assert Args.model_validate({"limit": "22"}).limit == 22
    assert argument_type_mismatches(schema, {"limit": "22"}) == ["limit"]
    assert argument_type_mismatches(schema, {"limit": "auto"}) == []
    assert argument_type_mismatches(schema, {"limit": 22}) == []


def test_constrained_string_union_cannot_hide_numeric_conversion():
    from typing import Annotated, Union

    from pydantic import BaseModel, StringConstraints

    class Args(BaseModel):
        limit: Union[Annotated[str, StringConstraints(pattern="^auto$", min_length=4)], int]

    assert Args.model_validate({"limit": "22"}).limit == 22
    assert argument_type_mismatches(Args.model_json_schema(), {"limit": "22"}) == ["limit"]
    assert argument_type_mismatches(Args.model_json_schema(), {"limit": "auto"}) == []


def test_discriminated_union_checks_only_eligible_branches():
    from typing import Annotated, Literal, Union

    from pydantic import BaseModel, Field

    class Text(BaseModel):
        kind: Literal["text"]
        value: str

    class Number(BaseModel):
        kind: Literal["number"]
        value: int

    class Args(BaseModel):
        item: Annotated[Union[Text, Number], Field(discriminator="kind")]

    args = {"item": {"kind": "number", "value": "22"}}
    assert Args.model_validate(args).item.value == 22
    assert argument_type_mismatches(Args.model_json_schema(), args) == ["item"]
    assert argument_type_mismatches(Args.model_json_schema(), {"item": {"kind": "text", "value": "22"}}) == []


def test_old_tuple_and_pattern_property_schemas():
    schema = {"properties": {
        "pair": {"type": "array", "items": [{"type": "integer"}, {"type": "boolean"}]},
        "flags": {"type": "object", "patternProperties": {"^flag": {"type": "boolean"}}, "additionalProperties": {"type": "integer"}},
    }}
    assert argument_type_mismatches(schema, {"pair": ["22", "off"]}) == ["pair"]
    assert argument_type_mismatches(schema, {"flags": {"flag1": "off"}}) == ["flags"]
    assert argument_type_mismatches(schema, {"pair": [22, False], "flags": {"flag1": False, "other": 22}}) == []


def test_tool_input_schema_reads_common_tool_shapes():
    class JsonSchemaTool:
        params_json_schema = SCHEMA

    class ParametersTool:
        parameters = SCHEMA

    class DictArgsSchemaTool:
        args_schema = SCHEMA

    class NoSchemaTool:
        pass

    for tool in (JsonSchemaTool(), ParametersTool(), DictArgsSchemaTool()):
        assert tool_input_schema(tool) == SCHEMA
    assert tool_input_schema(NoSchemaTool()) is None
    assert tool_input_schema(None) is None


def test_tool_input_schema_reads_a_pydantic_args_schema():
    pydantic = pytest.importorskip("pydantic")

    class Args(pydantic.BaseModel):
        port: int
        force: bool = False

    class Tool:
        args_schema = Args

    schema = tool_input_schema(Tool())
    assert argument_type_mismatches(schema, {"port": 22, "force": True}) == []
    assert argument_type_mismatches(schema, {"port": "22", "force": "yes"}) == ["force", "port"]
