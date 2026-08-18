"""
Cross-version behaviour of :mod:`tenuo.mcp._compat`.

These tests must hold on both MCP SDK lines, so they assert against the
behaviour the rest of ``tenuo.mcp`` relies on rather than against whichever
field names the installed SDK happens to use.
"""

from __future__ import annotations

import importlib.util

import pydantic
import pytest

pytest.importorskip("mcp", reason="requires the MCP SDK")

import mcp.types as mt  # noqa: E402

from tenuo.mcp._compat import (  # noqa: E402
    build_request_params_meta,
    call_tool_result_is_error,
    call_tool_result_structured_content,
    make_error_call_tool_result,
    request_params_meta_as_dict,
)


class _LegacyResult:
    """Stands in for an MCP 1.x ``CallToolResult``."""

    def __init__(self, is_error: bool, structured: object) -> None:
        self.isError = is_error
        self.structuredContent = structured


class _ModernResult:
    """Stands in for an MCP 2.x ``CallToolResult``."""

    def __init__(self, is_error: bool, structured: object) -> None:
        self.is_error = is_error
        self.structured_content = structured


class TestCallToolResultErrorFlag:
    """A renamed error field must never be read as "not an error".

    MCP 2.0 renamed ``isError`` to ``is_error``. Binding only one spelling
    would turn a server-side denial into an apparent success, so both are
    probed regardless of which SDK is installed.
    """

    @pytest.mark.parametrize("factory", [_LegacyResult, _ModernResult])
    def test_error_is_detected_under_either_field_name(self, factory) -> None:
        assert call_tool_result_is_error(factory(True, None)) is True

    @pytest.mark.parametrize("factory", [_LegacyResult, _ModernResult])
    def test_success_is_not_reported_as_error(self, factory) -> None:
        assert call_tool_result_is_error(factory(False, None)) is False

    def test_result_without_any_error_field_is_not_an_error(self) -> None:
        assert call_tool_result_is_error(object()) is False

    @pytest.mark.parametrize("factory", [_LegacyResult, _ModernResult])
    def test_structured_content_is_read_under_either_field_name(self, factory) -> None:
        payload = {"tenuo": {"code": -32001}}
        assert call_tool_result_structured_content(factory(True, payload)) == payload

    def test_structured_content_absent_returns_none(self) -> None:
        assert call_tool_result_structured_content(object()) is None


class TestErrorResultConstruction:
    def test_error_result_round_trips_through_the_accessors(self) -> None:
        """Whatever field names the SDK uses, our own readers must agree."""
        result = make_error_call_tool_result(
            content=[mt.TextContent(type="text", text="denied")],
            structured_content={"tenuo": {"code": -32001}},
        )
        assert call_tool_result_is_error(result) is True
        assert call_tool_result_structured_content(result) == {"tenuo": {"code": -32001}}

    def test_error_result_serializes_with_the_wire_field_names(self) -> None:
        """The JSON wire format is camelCase on both SDK lines."""
        result = make_error_call_tool_result(
            content=[mt.TextContent(type="text", text="denied")],
            structured_content={"tenuo": {"code": -32001}},
        )
        dumped = result.model_dump(by_alias=True)
        assert dumped["isError"] is True
        assert dumped["structuredContent"] == {"tenuo": {"code": -32001}}


class TestRequestParamsMeta:
    def test_tenuo_metadata_survives_a_round_trip(self) -> None:
        """The ``tenuo`` block is the warrant channel and must not be dropped."""
        built = build_request_params_meta({"tenuo": {"warrant": "abc"}})
        assert request_params_meta_as_dict(built) == {"tenuo": {"warrant": "abc"}}

    def test_empty_metadata_becomes_none(self) -> None:
        assert build_request_params_meta({}) is None

    def test_none_metadata_reads_as_empty_dict(self) -> None:
        assert request_params_meta_as_dict(None) == {}

    def test_built_metadata_is_assignable_to_call_tool_params(self) -> None:
        meta = build_request_params_meta({"tenuo": {"warrant": "abc"}})
        params = mt.CallToolRequestParams(name="read_file", arguments={"path": "/a"})
        updated = params.model_copy(update={"meta": meta})
        assert request_params_meta_as_dict(updated.meta)["tenuo"] == {"warrant": "abc"}

    def test_metadata_parsed_from_the_wire_is_readable(self) -> None:
        params = mt.CallToolRequestParams.model_validate(
            {
                "name": "read_file",
                "arguments": {"path": "/a"},
                "_meta": {"tenuo": {"warrant": "abc"}},
            }
        )
        assert request_params_meta_as_dict(params.meta)["tenuo"] == {"warrant": "abc"}


class TestVerifierAcceptsEitherMetaShape:
    """``MCPVerifier`` is handed ``params.meta``, whose type differs by SDK line.

    1.x parses ``_meta`` into a model and 2.x leaves it a dict, so the verifier
    normalises rather than making every handler convert.
    """

    @staticmethod
    def _both_shapes(envelope: dict) -> list:
        """A dict and a model carrying the same ``_meta``.

        Only one shape occurs on any given SDK line, so both are built here
        explicitly; taking ``params.meta`` would silently test the dict path
        twice when running on 2.x.
        """
        model = pydantic.create_model(
            "_Meta", __config__=pydantic.ConfigDict(extra="allow")
        ).model_validate(envelope)
        return [dict(envelope), model]

    @pytest.mark.parametrize("shape_index", [0, 1], ids=["dict", "model"])
    def test_either_shape_yields_the_same_dict(self, shape_index: int) -> None:
        from tenuo.mcp.server import _coerce_meta

        envelope = {"tenuo": {"warrant": "abc"}}
        meta = self._both_shapes(envelope)[shape_index]
        assert _coerce_meta(meta) == envelope

    def test_none_stays_none(self) -> None:
        from tenuo.mcp.server import _coerce_meta

        assert _coerce_meta(None) is None

    def test_unsupported_type_denies_rather_than_crashing(self) -> None:
        """Dropping the envelope denies the call; raising would surface as a 500."""
        from tenuo.mcp.server import _coerce_meta

        assert _coerce_meta("not-a-mapping") is None

    @pytest.mark.parametrize("shape_index", [0, 1], ids=["dict", "model"])
    def test_verifier_finds_the_warrant_under_either_shape(self, shape_index: int) -> None:
        """The end the caller sees: the envelope is located, not missed."""
        from tenuo.mcp.server import MCPVerifier

        meta = self._both_shapes({"tenuo": {"warrant": "bogus"}})[shape_index]
        verifier = MCPVerifier(authorizer=None, require_warrant=True)
        result = verifier.verify("read_file", {}, meta=meta)

        # The warrant is deliberately junk, so this denies either way. Failing on
        # the *decode* path rather than "No warrant provided" is what proves the
        # envelope was read.
        assert result.allowed is False
        assert "Malformed warrant" in (result.denial_reason or "")


class TestStreamableHttpTransport:
    def test_transport_helper_is_exported(self) -> None:
        """``client.py`` binds this name at import time, so it must exist."""
        from tenuo.mcp import _compat

        assert callable(_compat.open_streamable_http_transport)

    @pytest.mark.skipif(
        importlib.util.find_spec("mcp") is None, reason="requires the MCP SDK"
    )
    def test_sdk_http_module_is_resolvable(self) -> None:
        """MCP 2.0 vendors httpx as ``httpx2``; we must find whichever is in use."""
        from tenuo.mcp._compat import _sdk_httpx_module

        assert hasattr(_sdk_httpx_module(), "Timeout")

    def test_two_stream_yield_gains_a_session_id_accessor(self) -> None:
        """Only one SDK line yields two streams, so cover both arities directly."""
        from tenuo.mcp._compat import _as_transport_triple

        read, write, get_session_id = _as_transport_triple(("r", "w"))
        assert (read, write) == ("r", "w")
        assert get_session_id() is None

    def test_three_stream_yield_keeps_its_session_id_accessor(self) -> None:
        from tenuo.mcp._compat import _as_transport_triple

        sentinel = object()
        assert _as_transport_triple(("r", "w", sentinel)) == ("r", "w", sentinel)

    async def test_transport_yields_three_values(self) -> None:
        """``client.py`` unpacks three values from this transport.

        1.x yields ``(read, write, get_session_id)`` but 2.x yields only
        ``(read, write)``, so the shape is normalised here. Connecting to a
        closed port exercises the real SDK plumbing without needing a server:
        the streams are handed over before any request is sent.
        """
        from tenuo.mcp._compat import open_streamable_http_transport

        async with open_streamable_http_transport(
            url="http://127.0.0.1:1/mcp",
            headers={"x-test": "1"},
            timeout=1.0,
            sse_read_timeout=1.0,
            auth=None,
        ) as streams:
            read_stream, write_stream, get_session_id = streams

        assert read_stream is not None
        assert write_stream is not None
        assert callable(get_session_id)
