"""One YAML-to-SDK parser for local warrant templates and requests.

Documents describe desired authority. Only the SDK's signed warrant grants it.
"""

from __future__ import annotations

import copy
import json
import math
import re
from pathlib import Path

from .local_cli.files import (
    DocumentError,
    StrictLoader,
    check_public_material,
    fields,
    load_public_key,
    load_yaml,
)

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
    if "optional" in value:
        inner = value["optional"]
        if isinstance(inner, dict) and "optional" in inner:
            raise DocumentError("optional cannot wrap another optional")
        return {"optional": expanded_constraint(inner)}
    return copy.deepcopy(value)


def constraint_document(constraint):
    """Template syntax for a native constraint, or its repr when templates can't express it."""
    name = type(constraint).__name__
    if name == "Optional":
        return {"optional": constraint_document(constraint.inner)}
    if name in ("Wildcard", "AnyValue"):
        return "any"
    if name == "Exact":
        value = constraint.value
        if isinstance(value, str) and expanded_constraint(value) == {"exact": value}:
            return value
        return {"exact": value}
    if name == "OneOf":
        values = list(constraint.values)
        plain = all(isinstance(v, (str, int)) and not isinstance(v, bool) for v in values)
        return values if plain else {"one_of": values}
    if name == "Range":
        bounds = [constraint.min, constraint.max]
        if all(b is None or float(b).is_integer() for b in bounds):
            return "..".join("" if b is None else str(int(b)) for b in bounds)
        return {"range": {k: v for k, v in zip(("min", "max"), bounds) if v is not None}}
    if name == "Subpath":
        return {"subpath": constraint.root}
    keys = {"Pattern": "pattern", "Regex": "regex", "UrlPattern": "url_pattern"}
    if name in keys:
        return {keys[name]: constraint.pattern}
    return repr(constraint)


def compile_constraint(value):
    """Compile readable syntax through existing native constraint constructors."""
    from tenuo import Exact, OneOf, Pattern, Range, Regex, Subpath, UrlPattern, Wildcard

    document = expanded_constraint(value)
    kind, argument = next(iter(document.items()))
    if kind == "optional":
        # The argument may be left out; if it is sent, it must satisfy the inner constraint.
        from tenuo import Optional

        return Optional(compile_constraint(argument))
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
        # Strings or integers: tools send IDs such as PR numbers as JSON numbers.
        if (not isinstance(argument, list) or not argument
                or not all(isinstance(v, str) or (isinstance(v, int) and not isinstance(v, bool)) for v in argument)):
            raise DocumentError("one_of needs a nonempty list of strings or integers")
        return OneOf(argument)
    if kind == "exact" and isinstance(argument, int) and not isinstance(argument, bool):
        return Exact(argument)
    constructors = {"exact": Exact, "pattern": Pattern, "subpath": Subpath, "regex": Regex, "url_pattern": UrlPattern}
    if kind in constructors and isinstance(argument, str) and "\x00" not in argument:
        if kind == "subpath" and not argument.startswith("/"):
            raise DocumentError("subpath must be absolute")
        try:
            return constructors[kind](argument)
        except Exception:
            raise DocumentError(f"invalid {kind} constraint") from None
    raise DocumentError(f"unsupported or invalid constraint type: {kind}")


_VAR = re.compile(r"\$\{([a-z_][a-z0-9_]*)\}")


def resolve_variables(data, values=None):
    """Substitute a template's declared ``vars`` into its values.

    ``vars`` maps each name to ``{description, default}`` (both optional).
    ``${name}`` as a whole value takes the variable's value, list or scalar;
    inside a longer string it is replaced as text. Every variable used must be
    declared, every ``--set`` must name a declared variable, and a variable
    with no default must be set. Returns the document without ``vars``.
    """
    values = dict(values or {})
    if not isinstance(data, dict):
        return data
    if "vars" not in data:
        if values:
            raise DocumentError(f"--set {sorted(values)[0]}: this template declares no vars")
        used = _placeholders(data)
        if used:
            raise DocumentError(f"${{{used[0]}}} is used but not declared under vars")
        return data
    declared = data["vars"]
    fields(declared, declared if isinstance(declared, dict) else [], where="vars")
    for name, spec in declared.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z_][a-z0-9_]*", name):
            raise DocumentError(f"vars.{name}: names are lowercase letters, digits and _")
        fields(spec if spec is not None else {}, ["description", "default"], where=f"vars.{name}")
    unknown = sorted(set(values) - set(declared))
    if unknown:
        raise DocumentError(f"--set {unknown[0]}: not one of this template's vars ({', '.join(declared)})")
    resolved = {}
    missing = []
    for name, spec in declared.items():
        spec = spec or {}
        if name in values:
            resolved[name] = values[name]
        elif "default" in spec:
            resolved[name] = spec["default"]
        else:
            missing.append(f"--set {name}=..." + (f"  ({spec['description']})" if spec.get("description") else ""))
    if missing:
        raise DocumentError("this template needs: " + "; ".join(missing))
    for name, value in resolved.items():
        nested = _placeholders(value)
        if nested:
            raise DocumentError(f"the value of {name} contains ${{{nested[0]}}}; values are used as written")

    def fill_mapping(mapping, fill_child):
        out = {}
        for key, item in mapping.items():
            resolved_key = substitute(key)
            if not isinstance(resolved_key, str):
                raise DocumentError(f"{key!r} must fill in as a name, not {resolved_key!r}")
            if resolved_key in out:
                raise DocumentError(f"{resolved_key!r} appears twice once vars are filled in")
            out[resolved_key] = fill_child(resolved_key, item)
        return out

    def substitute(value, constraint=False):
        """``constraint``: value sits where a shorthand constraint is read (an
        argument's value, or inside its ``optional``)."""
        if isinstance(value, dict):
            return fill_mapping(value, lambda key, item: substitute(item, constraint and key == "optional"))
        if isinstance(value, list):
            return [substitute(v) for v in value]
        if not isinstance(value, str):
            return value
        names = _VAR.findall(value)
        if not names:
            return value
        for name in names:
            if name not in resolved:
                raise DocumentError(f"${{{name}}} is used but not declared under vars")
        whole = _VAR.fullmatch(value)
        if whole:
            filled = copy.deepcopy(resolved[whole.group(1)])
        else:

            def text(match):
                part = resolved[match.group(1)]
                if isinstance(part, (dict, list)):
                    raise DocumentError(f"${{{match.group(1)}}} is a list; use it as a whole value")
                return str(part)

            filled = _VAR.sub(text, value)
        # A filled-in value is a literal: --set repo=any must not become a wildcard,
        # nor 1..9 a range, and --set pr=57 is that number. Only shorthand reads values that way.
        if constraint and isinstance(filled, str) and expanded_constraint(filled) != {"exact": filled}:
            return {"exact": filled}
        if constraint and isinstance(filled, int) and not isinstance(filled, bool):
            return {"exact": filled}
        return filled

    def fill_arguments(tool, arguments):
        if not isinstance(arguments, dict):
            return substitute(arguments)
        return fill_mapping(arguments, lambda argument, value: substitute(value, constraint=True))

    def fill_top(key, value):
        if key == "capabilities" and isinstance(value, dict):
            return fill_mapping(value, fill_arguments)
        return substitute(value)

    return fill_mapping({k: v for k, v in data.items() if k != "vars"}, fill_top)


def _placeholders(value):
    """Every ${name} in a value, at any depth, keys included."""
    if isinstance(value, dict):
        return [n for k, v in value.items() for n in _placeholders(k) + _placeholders(v)]
    if isinstance(value, list):
        return [n for v in value for n in _placeholders(v)]
    return _VAR.findall(value) if isinstance(value, str) else []


def parse_set(items):
    """``--set name=value`` pairs: ``[a, b]`` is a list, a whole number an integer
    (issue and PR numbers), ``"00123"`` in double quotes a string as written,
    anything else a string."""
    import yaml

    values = {}
    for item in items or ():
        name, sep, value = item.partition("=")
        if not sep or not name:
            raise DocumentError(f"--set {item}: use --set NAME=VALUE")
        if value.startswith("["):
            # The template's own loader, so a list item reads the same as it would in the file.
            try:
                values[name] = yaml.load(value, Loader=StrictLoader)
            except yaml.YAMLError:
                raise DocumentError(f"--set {item}: not a valid list") from None
        elif len(value) >= 2 and value[0] == value[-1] == '"':
            try:
                values[name] = json.loads(value)
            except ValueError:
                raise DocumentError(f"--set {item}: not a valid quoted string") from None
        elif re.fullmatch(r"-?\d+", value):
            values[name] = int(value)
        else:
            values[name] = value
    return values


class WarrantTemplate:
    """A validated, immutable snapshot of a template or unsigned request."""

    def __init__(self, data, *, directory=None, values=None):
        directory = Path.cwd() if directory is None else Path(directory)
        data = resolve_variables(data, values)
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
    def load(cls, path, values=None):
        path = Path(path).expanduser()
        return cls(load_yaml(path), directory=path.parent, values=values)

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
