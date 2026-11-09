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


def test_unresolvable_reference_accepts_the_value():
    schema = {"properties": {"x": {"$ref": "#/$defs/Missing"}, "y": {"$ref": "http://example.com/s"}}}
    assert argument_type_mismatches(schema, {"x": "1", "y": 2}) == []


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
