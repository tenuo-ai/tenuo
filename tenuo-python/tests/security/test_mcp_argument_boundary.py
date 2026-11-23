"""Tool-boundary policy coverage inspired by CVE-2026-134817.

https://github.com/Flux159/mcp-server-kubernetes/pull/390
This is a synthetic adapter contract, not a kubectl implementation or a
reproduction against the upstream server. No commands or files are accessed.
"""

import base64
import time
from unittest.mock import Mock

import pytest
from tenuo_core import Authorizer, Regex, SigningKey, Warrant

from tenuo.mcp.server import MCPAuthorizationError, MCPVerifier


# Every positional slot listed in upstream PR #390. This deliberately narrow
# example policy is not a complete Kubernetes resource-name schema.
SLOTS = [
    ("exec_in_pod", "name"),
    ("kubectl_patch", "resourceType"),
    ("kubectl_patch", "name"),
    ("kubectl_rollout", "subCommand"),
    ("kubectl_rollout", "resourceType"),
    ("kubectl_rollout", "name"),
    ("kubectl_logs", "name"),
    ("kubectl_create", "name"),
    ("kubectl_create", "secretType"),
    ("kubectl_create", "serviceType"),
    ("explain_resource", "resource"),
    ("node_management", "nodeName"),
    ("port_forward", "resourceType"),
]


def signed_call(tool, field, value, constraint=None):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    if constraint is None:
        constraint = Regex(r"^[a-z0-9][a-z0-9.-]*$")
    warrant = Warrant.issue(
        issuer,
        capabilities={tool: {field: constraint}},
        holder=holder.public_key,
    )
    args = {field: value}
    signature = warrant.sign(holder, tool, args, int(time.time()))
    meta = {
        "tenuo": {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(bytes(signature)).decode(),
        }
    }
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[issuer.public_key]))
    return verifier, args, meta


def dispatch(verifier, tool, args, meta, executor):
    # The handler must execute the verified arguments without later rewriting.
    clean = verifier.verify_or_raise(tool, args, meta=meta)
    return executor(**clean)


@pytest.mark.parametrize("tool,field", SLOTS)
@pytest.mark.parametrize(
    "value",
    [
        "--filename=/tmp/tenuo-fixture.yaml",
        "--filename",
        "-f",
        "--",
        " --filename=/tmp/tenuo-fixture.yaml",
        "\t-f",
        "pods\n",
    ],
)
def test_flag_shaped_operands_never_reach_executor(tool, field, value):
    verifier, args, meta = signed_call(tool, field, value)
    executor = Mock()
    with pytest.raises(MCPAuthorizationError):
        dispatch(verifier, tool, args, meta, executor)
    executor.assert_not_called()


@pytest.mark.parametrize("tool,field", SLOTS)
@pytest.mark.parametrize("value", ["pods", "api-server-0", "apps.v1"])
def test_valid_operands_reach_executor_unchanged(tool, field, value):
    verifier, args, meta = signed_call(tool, field, value)
    executor = Mock(return_value="ok")
    assert dispatch(verifier, tool, args, meta, executor) == "ok"
    executor.assert_called_once_with(**args)


def test_rewriting_signed_arguments_before_verification_is_denied():
    verifier, args, meta = signed_call("kubectl_logs", "name", "api-server-0")
    # Both names satisfy the policy; PoP must still bind the exact name.
    args["name"] = "api-server-1"
    executor = Mock()
    with pytest.raises(MCPAuthorizationError):
        dispatch(verifier, "kubectl_logs", args, meta, executor)
    executor.assert_not_called()


def test_broad_policy_and_valid_pop_do_not_prevent_flag_injection():
    verifier, args, meta = signed_call(
        "kubectl_logs",
        "name",
        "--filename=/tmp/tenuo-fixture.yaml",
        constraint=Regex(r"^.*$"),
    )
    executor = Mock()
    dispatch(verifier, "kubectl_logs", args, meta, executor)
    executor.assert_called_once_with(**args)


def test_normalize_before_signing_and_authorization():
    # An adapter that trims names must do so before the holder signs the call.
    normalized = " api-server-0 ".strip()
    verifier, args, meta = signed_call("kubectl_logs", "name", normalized)
    executor = Mock()
    dispatch(verifier, "kubectl_logs", args, meta, executor)
    executor.assert_called_once_with(name="api-server-0")


def test_normalizing_after_signing_invalidates_pop():
    verifier, args, meta = signed_call("kubectl_logs", "name", " api-server-0 ")
    args["name"] = args["name"].strip()
    executor = Mock()
    with pytest.raises(MCPAuthorizationError):
        dispatch(verifier, "kubectl_logs", args, meta, executor)
    executor.assert_not_called()
