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


@pytest.mark.parametrize("schema", [None, {}, {"type": "object"}, "not a schema"])
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
    assert argument_type_mismatches(schema, {"x": True, "y": 1}) == ["x", "y"]
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


def test_union_branch_value_requirements_cannot_mask_conversion():
    from typing import Annotated, List, Union

    from pydantic import BaseModel, Field, PositiveInt

    class Numeric(BaseModel):
        item: Union[PositiveInt, bool]

    assert Numeric.model_validate({"item": 0}).item is False
    assert argument_type_mismatches(Numeric.model_json_schema(), {"item": 0}) == ["item"]

    class Arrays(BaseModel):
        item: Union[Annotated[List[str], Field(min_length=2)], List[int]]

    assert Arrays.model_validate({"item": ["22"]}).item == [22]
    assert argument_type_mismatches(Arrays.model_json_schema(), {"item": ["22"]}) == ["item"]

    class Text(BaseModel):
        value: str
        required: str

    class Number(BaseModel):
        value: int

    class Objects(BaseModel):
        item: Union[Text, Number]

    assert Objects.model_validate({"item": {"value": "22"}}).item.value == 22
    assert argument_type_mismatches(Objects.model_json_schema(), {"item": {"value": "22"}}) == ["item"]


def test_union_validation_never_fetches_remote_references(monkeypatch):
    import urllib.request

    requests = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: requests.append(args))
    schema = {"properties": {"item": {"anyOf": [
        {"$ref": "https://example.test/schema"}, {"type": "integer"},
    ]}}}
    assert argument_type_mismatches(schema, {"item": "22"}) == ["item"]
    assert argument_type_mismatches(schema, {"item": 22}) == ["item"]
    assert requests == []


def test_another_strict_branch_cannot_hide_the_frameworks_selected_coercion():
    from typing import Union

    from pydantic import BaseModel, Field

    class Text(BaseModel):
        value: str

    class Number(BaseModel):
        value: int
        priority: int

    class Args(BaseModel):
        item: Union[Text, Number]

    args = {"item": {"value": "22", "priority": 1}}
    assert isinstance(Args.model_validate(args).item, Number)
    assert argument_type_mismatches(Args.model_json_schema(), args) == ["item"]

    class Scalar(BaseModel):
        item: Union[int, str] = Field(union_mode="left_to_right")

    assert Scalar.model_validate({"item": "22"}).item == 22
    assert argument_type_mismatches(Scalar.model_json_schema(), {"item": "22"}) == ["item"]


def test_nullable_and_same_type_unions_remain_usable():
    schema = {"properties": {
        "maybe": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
        "number": {"anyOf": [{"type": "integer"}, {"type": "number"}]},
    }}
    assert argument_type_mismatches(schema, {"maybe": None, "number": 22}) == []
    assert argument_type_mismatches(schema, {"maybe": 22, "number": 22.5}) == []


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


def test_supplied_unreadable_schema_is_denied():
    assert argument_type_mismatches({"properties": []}, {"replicas": "22"}) == ["replicas"]


def test_schema_regex_execution_is_bounded_in_all_validation_paths():
    import subprocess
    import sys

    script = r'''from tenuo._arg_types import argument_type_mismatches
text = "a" * 40000 + "!"
pattern = "^(a+)+$"
cases = [
    ({"properties": {"item": {"type": "string", "pattern": pattern}}}, text),
    ({"properties": {"item": {"type": "object", "patternProperties": {pattern: {}}, "additionalProperties": False}}}, {text: True}),
    ({"properties": {"item": {"anyOf": [{"$schema": "http://json-schema.org/draft-07/schema#", "type": "string", "pattern": pattern}, {"type": "null"}]}}}, text),
    ({"properties": {"item": {"anyOf": [{"type": "object", "patternProperties": {pattern: {}}, "additionalProperties": False}, {"type": "null"}]}}}, {text: True}),
]
for schema, value in cases:
    assert argument_type_mismatches(schema, {"item": value}) == ["item"]
'''
    subprocess.run([sys.executable, "-c", script], check=True, timeout=10)


def test_schema_metadata_does_not_erase_user_fields_or_literals():
    schema = {"properties": {"$schema": {"type": "boolean"}}}
    assert argument_type_mismatches(schema, {"$schema": "off"}) == ["$schema"]
    schema = {"properties": {"item": {"const": {"$schema": "literal"}}}}
    assert argument_type_mismatches(schema, {"item": {"$schema": "literal"}}) == []
    assert argument_type_mismatches(schema, {"item": {"$schema": "other"}}) == ["item"]


def test_regex_forms_unsupported_by_the_linear_matcher_fail_closed():
    schema = {"properties": {"item": {"pattern": "(?=a)a", "type": "string"}}}
    assert argument_type_mismatches(schema, {"item": "a"}) == ["item"]


def test_shared_reference_expansion_cannot_exhaust_a_worker():
    import subprocess
    import sys

    script = r'''from tenuo._arg_types import argument_type_mismatches
rules = {"leaf": {"const": "match"}}
previous = "leaf"
for index in range(20):
    name = "node" + str(index)
    rules[name] = {"anyOf": [{"$ref": "#/$defs/" + previous}] * 2}
    previous = name
schema = {"$defs": rules, "properties": {"item": {"anyOf": [{"$ref": "#/$defs/" + previous}, {"type": "null"}]}}}
assert argument_type_mismatches(schema, {"item": "miss"}) == ["item"]
'''
    subprocess.run([sys.executable, "-c", script], check=True, timeout=10)


def test_legacy_tuple_inside_union_preserves_types_and_additional_items():
    schema = {"$schema": "http://json-schema.org/draft-07/schema#", "properties": {
        "item": {"anyOf": [
            {"type": "array", "items": [{"type": "integer"}, {"type": "boolean"}], "additionalItems": False},
            {"type": "null"},
        ]},
    }}
    assert argument_type_mismatches(schema, {"item": [22, False]}) == []
    assert argument_type_mismatches(schema, {"item": None}) == []
    assert argument_type_mismatches(schema, {"item": ["22", "off"]}) == ["item"]
    assert argument_type_mismatches(schema, {"item": [22, False, True]}) == ["item"]


def test_extension_reference_cannot_switch_to_an_unsafe_validator():
    import subprocess
    import sys
    script = r'''from tenuo._arg_types import argument_type_mismatches
schema = {"x-schema": {"$schema": "http://json-schema.org/draft-07/schema#", "type": "string", "pattern": "^(a+)+$"}, "properties": {"item": {"anyOf": [{"$ref": "#/x-schema"}, {"type": "null"}]}}}
assert argument_type_mismatches(schema, {"item": "a" * 40000 + "!"}) == ["item"]
'''
    subprocess.run([sys.executable, "-c", script], check=True, timeout=10)


@pytest.mark.parametrize("bounded", [False, True])
def test_deduplicating_set_union_cannot_hide_item_coercion(bounded):
    from typing import Annotated, Union
    from pydantic import BaseModel, Field
    item_type = Annotated[set[int], Field(max_length=1)] if bounded else set[int]
    class Args(BaseModel):
        item: Union[item_type, list[str]] = Field(union_mode="left_to_right")
    raw = {"item": ["22", "22"]}
    assert Args.model_validate(raw).item == {22}
    assert argument_type_mismatches(Args.model_json_schema(), raw) == ["item"]


def test_numeric_literals_rule_out_impossible_union_branches():
    from typing import Literal, Union
    from pydantic import BaseModel, PositiveInt
    class Args(BaseModel):
        item: Union[Literal[-1], PositiveInt]
    schema = Args.model_json_schema()
    assert argument_type_mismatches(schema, {"item": 5}) == []
    assert argument_type_mismatches(schema, {"item": -1}) == []
    assert argument_type_mismatches(schema, {"item": "-1"}) == ["item"]
    schema = {"properties": {"item": {"anyOf": [{"enum": [-1, -2]}, {"type": "integer", "minimum": 1}]}}}
    assert argument_type_mismatches(schema, {"item": 5}) == []
    assert argument_type_mismatches(schema, {"item": "-2"}) == ["item"]
