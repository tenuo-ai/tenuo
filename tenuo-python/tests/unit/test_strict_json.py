"""The same duplicate-key bytes are rejected in every SDK that still has the text."""

import json
from pathlib import Path

import pytest

from tenuo.arguments import parse_strict_json
from tenuo.openai import MalformedToolCall, ToolCallBuffer

VECTOR = (
    Path(__file__).resolve().parents[3] / "tests" / "vectors" / "duplicate-argument-keys.json"
)


def test_duplicate_argument_key_vector_is_rejected():
    text = VECTOR.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        parse_strict_json(text)


def test_unique_keys_parse():
    assert parse_strict_json('{"path":"/data/ok","n":1}') == {"path": "/data/ok", "n": 1}


def test_numbers_match_the_host_parser():
    text = '{"n":0.58620900869382481}'
    host = json.loads(text)["n"]
    assert parse_strict_json(text)["n"] == host
    assert host != json.loads("0.5862090086938248")


def test_nested_duplicate_key_is_rejected():
    with pytest.raises(ValueError, match="duplicate JSON key"):
        parse_strict_json('{"meta":{"a":1,"a":2}}')


def test_openai_argument_buffer_rejects_duplicate_keys():
    buffer = ToolCallBuffer(id="call_0", name="read_file")
    buffer.arguments_buffer = VECTOR.read_text(encoding="utf-8")
    with pytest.raises(MalformedToolCall, match="duplicate JSON key"):
        buffer.get_arguments()
