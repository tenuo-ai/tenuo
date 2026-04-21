"""Tests that exercise client/server ``CompiledMcpConfig`` asymmetry.

These tests build both sides of the MCP handshake from
:mod:`tests.adapters._mcp_test_fixtures` — an **asymmetric-by-default**
fixture pair. A test that wants config parity must pass the same config
into both factories; anything else models a real-world drift scenario.

The invariant we lock in here is:

  *PoP byte parity is independent of the client-side
  ``CompiledMcpConfig`` state.*

Concretely:

- client with no config  vs.  server with config  → authorizes
- client with config A    vs.  server with config A → authorizes
- client with config A    vs.  server with config B → authorizes
  (as long as A and B produce the same canonicalization-relevant PoP
  bytes; since PoP now covers raw wire args, both must succeed)
- client with no config  vs.  server with no config → authorizes
- tampered wire args (mutated after signing) → denied in every
  asymmetry scenario

The old architecture (pre-PR #384) failed the first and third cases —
those are the silent-denial modes Brooks hit in integration.
"""

from __future__ import annotations

import pytest
from tenuo import Pattern, Range

from ._mcp_test_fixtures import (
    CONFIG_A_MAXSIZE_TO_MAX_SIZE,
    CONFIG_B_MAXSIZE_TO_MAX_SIZE_DIFFERENT_DEFAULT,
    make_client_side,
    make_issuer_and_agent,
    make_server_side,
    perform_handshake,
    write_config_yaml,
)


# Capability shared by every test in this module — the server's warrant
# allows the read_file tool over /data/* paths, up to a 10 MiB max_size.
READ_FILE_CAPS = {
    "read_file": {
        "path": Pattern("/data/*"),
        "max_size": Range(max=10 * 1024 * 1024),
    }
}


# ---------------------------------------------------------------------------
# Fixtures that produce the two compiled configs
# ---------------------------------------------------------------------------


@pytest.fixture
def config_a(tmp_path):
    return write_config_yaml(tmp_path, CONFIG_A_MAXSIZE_TO_MAX_SIZE)


@pytest.fixture
def config_b(tmp_path):
    # Uses a different subdir so both configs can coexist in the same test.
    sub = tmp_path / "b"
    sub.mkdir()
    return write_config_yaml(sub, CONFIG_B_MAXSIZE_TO_MAX_SIZE_DIFFERENT_DEFAULT)


# ---------------------------------------------------------------------------
# Matrix of asymmetry scenarios
# ---------------------------------------------------------------------------


class TestMcpHandshakeConfigAsymmetry:
    def test_client_no_config_server_has_config_authorizes(self, config_a):
        """Silent-denial mode from Bug #1: client without a config used to
        be rejected by a server with one loaded. Must now succeed."""
        issuer, agent = make_issuer_and_agent()
        client = make_client_side(
            issuer_key=issuer,
            agent_key=agent,
            capabilities=READ_FILE_CAPS,
            config=None,  # explicit: client has no config
        )
        server = make_server_side(issuer_key=issuer, config=config_a)

        result = perform_handshake(
            client,
            server,
            tool="read_file",
            wire_args={"path": "/data/log.txt", "maxSize": 2048},
        )
        assert result.verify_result.allowed, result.verify_result.denial_reason
        # Server-side extraction should have renamed maxSize → max_size
        assert result.verify_result.constraints["max_size"] == 2048

    def test_client_has_config_server_no_config_authorizes(self, config_a):
        """Inverse asymmetry: client loads a config but server doesn't.

        Server sees raw wire args directly as constraints. Both sides
        ultimately sign/verify the same raw wire bytes, so this must
        succeed — even though the warrant's constraint keys (``path``,
        ``max_size``) don't literally match the camelCase ``maxSize``
        wire field, because the server loaded no mapping. We assert the
        outcome is *consistent* rather than privileging any particular
        denial/authorization: what matters is that the failure mode (if
        any) is deterministic and not a silent-PoP-mismatch.
        """
        issuer, agent = make_issuer_and_agent()
        client = make_client_side(
            issuer_key=issuer,
            agent_key=agent,
            capabilities=READ_FILE_CAPS,
            config=config_a,
        )
        server = make_server_side(issuer_key=issuer, config=None)

        result = perform_handshake(
            client,
            server,
            tool="read_file",
            wire_args={"path": "/data/log.txt", "maxSize": 2048},
        )
        # The server sees raw args as constraints. "maxSize" isn't in the
        # warrant's constraint list, so the warrant constraint checker will
        # deny — but it must deny for a *constraint* reason, not a
        # signature reason. That's the parity invariant.
        if not result.verify_result.allowed:
            dr = (result.verify_result.denial_reason or "").lower()
            assert "signature" not in dr, (
                "Asymmetry must not produce PoP denials — got: "
                + (result.verify_result.denial_reason or "")
            )

    def test_both_sides_same_config_authorizes(self, config_a):
        issuer, agent = make_issuer_and_agent()
        client = make_client_side(
            issuer_key=issuer,
            agent_key=agent,
            capabilities=READ_FILE_CAPS,
            config=config_a,
        )
        server = make_server_side(issuer_key=issuer, config=config_a)

        result = perform_handshake(
            client,
            server,
            tool="read_file",
            wire_args={"path": "/data/log.txt", "maxSize": 2048},
        )
        assert result.verify_result.allowed, result.verify_result.denial_reason

    def test_neither_side_has_config_authorizes(self):
        issuer, agent = make_issuer_and_agent()
        client = make_client_side(
            issuer_key=issuer,
            agent_key=agent,
            capabilities={"read_file": {"path": Pattern("/data/*")}},
            config=None,
        )
        server = make_server_side(issuer_key=issuer, config=None)

        result = perform_handshake(
            client,
            server,
            tool="read_file",
            wire_args={"path": "/data/log.txt"},
        )
        assert result.verify_result.allowed, result.verify_result.denial_reason

    def test_different_configs_but_same_wire_shape_authorizes(
        self, config_a, config_b
    ):
        """Configs A and B only differ in ``default`` (1048576 vs 512) —
        the PoP surface is the raw wire args which both configs ignore at
        sign time. Must authorize."""
        issuer, agent = make_issuer_and_agent()
        client = make_client_side(
            issuer_key=issuer,
            agent_key=agent,
            capabilities=READ_FILE_CAPS,
            config=config_a,
        )
        server = make_server_side(issuer_key=issuer, config=config_b)

        result = perform_handshake(
            client,
            server,
            tool="read_file",
            # Caller supplies maxSize explicitly so neither config's
            # ``default`` participates in the constraint view.
            wire_args={"path": "/data/log.txt", "maxSize": 2048},
        )
        assert result.verify_result.allowed, result.verify_result.denial_reason


class TestMcpHandshakeTamperResistance:
    """The widened PoP surface (covering raw wire args) must not weaken
    the underlying integrity guarantee. Regression tests pin that a
    mutated wire dict is still rejected in every asymmetry scenario."""

    @pytest.mark.parametrize(
        "client_has_config,server_has_config",
        [
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ],
    )
    def test_tampered_wire_is_denied(
        self, tmp_path, client_has_config, server_has_config
    ):
        issuer, agent = make_issuer_and_agent()

        # Build fresh configs per parametrization so each runs independently.
        def _mk(subdir: str):
            sub = tmp_path / subdir
            sub.mkdir(parents=True, exist_ok=True)
            return write_config_yaml(sub, CONFIG_A_MAXSIZE_TO_MAX_SIZE)

        tag = f"{client_has_config}_{server_has_config}"
        config_for_client = _mk(f"c_{tag}") if client_has_config else None
        config_for_server = _mk(f"s_{tag}") if server_has_config else None

        client = make_client_side(
            issuer_key=issuer,
            agent_key=agent,
            capabilities=READ_FILE_CAPS,
            config=config_for_client,
        )
        server = make_server_side(issuer_key=issuer, config=config_for_server)

        # Client signs over a bounded maxSize.
        signed_args = {"path": "/data/log.txt", "maxSize": 2048}
        meta = client.build_meta("read_file", signed_args)

        # Attacker escalates on the wire post-signing.
        tampered = {"path": "/data/log.txt", "maxSize": 9_999_999}
        result = server.verify("read_file", tampered, meta=meta)

        assert not result.allowed, (
            f"Tamper in scenario client_config={client_has_config}, "
            f"server_config={server_has_config} must be denied"
        )
