"""One YAML-to-SDK parser for local warrant templates and requests.

Documents describe desired authority. Only the SDK's signed warrant grants it.
"""

from __future__ import annotations

import copy
import math
import re
from pathlib import Path

from .local_cli.files import DocumentError, check_public_material, fields, load_public_key, load_yaml

_RANGE = re.compile(r"(-?\d+(?:\.\d+)?)?\.\.(-?\d+(?:\.\d+)?)?")


def duration(value):
    """A positive whole-number duration, expressed in seconds, minutes, hours or days."""
    if not isinstance(value, str) or not re.fullmatch(r"[1-9]\d*[smhd]", value):
        raise DocumentError("duration must be positive, for example 30m or 1h")
    seconds = int(value[:-1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[value[-1]]
    from tenuo import MAX_WARRANT_TTL_SECS

    if seconds > MAX_WARRANT_TTL_SECS:
        raise DocumentError("duration exceeds the SDK warrant lifetime limit")
    return seconds


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or abs(value) > (1 << 53) - 1:
        raise DocumentError("range bounds must be finite numbers within the exact JSON integer range")
    return value


def expanded_constraint(value):
    if value == "any":
        return {"wildcard": True}
    if isinstance(value, str):
        match = _RANGE.fullmatch(value)
        if match and any(match.groups()):
            return {
                "range": {
                    k: float(v) if "." in v else int(v) for k, v in zip(("min", "max"), match.groups()) if v is not None
                }
            }
        return {"exact": value}
    if isinstance(value, list):
        return {"one_of": value}
    if not isinstance(value, dict) or len(value) != 1:
        raise DocumentError("constraint needs a string, a string list, or one explicit typed mapping")
    return copy.deepcopy(value)


def compile_constraint(value):
    """Compile readable syntax through existing native constraint constructors."""
    from tenuo import Exact, OneOf, Pattern, Range, Regex, Subpath, UrlPattern, Wildcard

    document = expanded_constraint(value)
    kind, argument = next(iter(document.items()))
    if kind == "wildcard" and argument is True:
        return Wildcard()
    if kind == "range":
        fields(argument, ["min", "max"], where="range")
        if not argument:
            raise DocumentError("range needs min or max")
        low = _number(argument["min"]) if "min" in argument else None
        high = _number(argument["max"]) if "max" in argument else None
        if low is not None and high is not None and low > high:
            raise DocumentError("range min must not exceed max")
        return Range(low, high)
    if kind == "one_of":
        if not isinstance(argument, list) or not argument or not all(isinstance(v, str) for v in argument):
            raise DocumentError("one_of needs a nonempty list of strings")
        return OneOf(argument)
    constructors = {"exact": Exact, "pattern": Pattern, "subpath": Subpath, "regex": Regex, "url_pattern": UrlPattern}
    if kind in constructors and isinstance(argument, str) and "\x00" not in argument:
        if kind == "subpath" and not argument.startswith("/"):
            raise DocumentError("subpath must be absolute")
        try:
            return constructors[kind](argument)
        except Exception:
            raise DocumentError(f"invalid {kind} constraint") from None
    raise DocumentError(f"unsupported or invalid constraint type: {kind}")


class WarrantTemplate:
    """A validated, immutable snapshot of a template or unsigned request."""

    def __init__(self, data, *, directory=None):
        directory = Path.cwd() if directory is None else Path(directory)
        fields(
            data,
            ["version", "name", "ttl", "capabilities", "approvals", "kind", "holder", "reason"],
            ["version", "ttl", "capabilities"],
        )
        if type(data["version"]) is not int or data["version"] != 2:
            raise DocumentError("template version must be 2")
        request = data.get("kind") == "warrant-request"
        if "kind" in data and not request:
            raise DocumentError("kind must be warrant-request")
        if request:
            if not isinstance(data.get("holder"), str) or not data["holder"].strip():
                raise DocumentError("warrant request needs a holder name or public key path")
        elif "holder" in data or "reason" in data:
            raise DocumentError("holder and reason belong in a warrant-request")
        if "name" in data and (not isinstance(data["name"], str) or not data["name"].strip()):
            raise DocumentError("name must be a nonempty string")
        if "reason" in data and not isinstance(data["reason"], str):
            raise DocumentError("reason must be a string")
        self.ttl_seconds = duration(data["ttl"])
        capabilities = data["capabilities"]
        fields(capabilities, capabilities if isinstance(capabilities, dict) else [], where="capabilities")
        if not capabilities:
            raise DocumentError("capabilities must include at least one tool")
        compiled = {}
        for tool, arguments in capabilities.items():
            if not isinstance(tool, str) or not tool.strip():
                raise DocumentError("tool names must be nonempty strings")
            fields(arguments, arguments if isinstance(arguments, dict) else [], where=f"capabilities.{tool}")
            compiled[tool] = {arg: compile_constraint(value) for arg, value in arguments.items()}
        self._capabilities = compiled
        self._gates = {}
        self._approvers = []
        if "approvals" in data:
            approvals = data["approvals"]
            fields(approvals, ["keys", "required"], ["keys", "required"], "approvals")
            keys = approvals["keys"]
            if not isinstance(keys, list) or not keys or len(keys) > 128:
                raise DocumentError("approvals.keys needs 1-128 public key file paths")
            for key in keys:
                if not isinstance(key, str) or not key:
                    raise DocumentError("approvals.keys needs public key file paths")
                path = Path(key).expanduser()
                self._approvers.append(load_public_key(path if path.is_absolute() else Path(directory) / path))
            if len({bytes(k.to_bytes()) for k in self._approvers}) != len(keys):
                raise DocumentError("approver keys must be distinct")
            gates = approvals["required"]
            fields(gates, compiled, where="approvals.required")
            if not gates:
                raise DocumentError("approvals.required must name a granted tool")
            for tool, gate in gates.items():
                if gate == "always":
                    self._gates[tool] = None
                else:
                    fields(gate, ["unless"], ["unless"], f"approvals.required.{tool}")
                    exempt = gate["unless"]
                    fields(exempt, compiled[tool], where=f"approvals.required.{tool}.unless")
                    if not exempt:
                        raise DocumentError("unless must contain at least one constrained argument")
                    self._gates[tool] = {arg: {"exempt": compile_constraint(value)} for arg, value in exempt.items()}
        self._data = copy.deepcopy(data)

    @classmethod
    def load(cls, path):
        path = Path(path).expanduser()
        return cls(load_yaml(path), directory=path.parent)

    @property
    def document(self):
        return copy.deepcopy(self._data)

    def expanded(self):
        data = self.document
        data["capabilities"] = {
            tool: {arg: expanded_constraint(value) for arg, value in arguments.items()}
            for tool, arguments in data["capabilities"].items()
        }
        return data

    def mint(self, issuer_key, holder):
        """Issue to a public key. The issuer never needs the holder's private key."""
        from tenuo import Warrant

        check_public_material(issuer_key, [holder, *self._approvers])
        builder = Warrant.mint_builder().holder(holder).ttl(self.ttl_seconds)
        for tool, constraints in self._capabilities.items():
            builder = builder.capability(tool, **constraints)
        if self._gates:
            builder = builder.approval_gates(self._gates).required_approvers(self._approvers).min_approvals(1)
        return builder.mint(issuer_key)
