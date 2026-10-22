"""Read the calls local adapters recorded in observe mode."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

from .files import DocumentError
from .runtime import OBSERVATIONS

MAX_OBSERVATION_BYTES = 64 * 1024 * 1024


def read_calls(workspace, path=None):
    path = Path(path) if path else workspace.path / OBSERVATIONS
    if not path.exists():
        return []
    with path.open("rb") as stream:
        raw = stream.read(MAX_OBSERVATION_BYTES + 1)
    if len(raw) > MAX_OBSERVATION_BYTES:
        raise DocumentError("observations exceed 64 MiB; move the file aside and pass it with --file")
    calls = []
    for number, line in enumerate(raw.decode().splitlines(), 1):
        if not line.strip():
            continue
        try:
            call = json.loads(line)
        except ValueError:
            raise DocumentError(f"{path}:{number}: not a JSON line") from None
        if (
            not isinstance(call, dict)
            or not isinstance(call.get("tool"), str)
            or not isinstance(call.get("args"), dict)
        ):
            raise DocumentError(f"{path}:{number}: expected a recorded call with tool and args")
        calls.append(call)
    return calls


def list_calls(workspace, *, path=None, tool=None, limit=100):
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise DocumentError("limit must be between 1 and 10000")
    calls = [call for call in read_calls(workspace, path) if tool is None or call["tool"] == tool]
    return {"calls": calls[-limit:], "matching_calls": len(calls)}


# Integrations whose sessions are attached with tenuo-cli <name> session attach.
KNOWN_INTEGRATIONS = {"hermes"}

MAX_LISTED_VALUES = 5
FREE_TEXT_LEN = 80


def summarize_calls(workspace, *, path=None, tool=None):
    """Per tool: how often it ran, what enforcement would have decided, and what each argument held.

    Deterministic counting over the recorded calls; nothing is inferred or
    suggested beyond the numbers. Write a template from them, or draft one with warrantgen.
    """
    tools = {}
    runs = set()
    steps = {}
    vias = {}
    calls_path = Path(path) if path else workspace.path / OBSERVATIONS
    for call in read_calls(workspace, path):
        if tool is not None and call["tool"] != tool:
            continue
        runs.add(call.get("run"))
        step = call.get("step") or "default"
        steps.setdefault(step, {})[call.get("run")] = call.get("observed_at") or ""
        vias.setdefault(step, set()).add(call.get("via"))
        entry = tools.setdefault(
            call["tool"],
            {
                "calls": 0,
                "runs": set(),
                "would_allow": 0,
                "would_deny": 0,
                "no_warrant": 0,
                "deny_reasons": {},
                "denied_on": {},
                "values": {},
            },
        )
        entry["calls"] += 1
        entry["runs"].add(call.get("run"))
        for name, value in call["args"].items():
            entry["values"].setdefault(name, []).append((call.get("run"), value))
        decision = call.get("decision")
        if decision == "allow":
            entry["would_allow"] += 1
        elif decision == "deny":
            entry["would_deny"] += 1
            reason = call.get("reason") or "denied"
            entry["deny_reasons"][reason] = entry["deny_reasons"].get(reason, 0) + 1
            argument = call.get("argument")
            if isinstance(argument, str) and argument:
                entry["denied_on"][argument] = entry["denied_on"].get(argument, 0) + 1
        else:
            entry["no_warrant"] += 1
    rows = []
    for name, entry in sorted(tools.items(), key=lambda item: (-item[1]["calls"], item[0])):
        row = {"tool": name, "calls": entry["calls"], "runs": len(entry["runs"])}
        for key in ("would_allow", "would_deny", "no_warrant"):
            if entry[key]:
                row[key] = entry[key]
        for key in ("deny_reasons", "denied_on"):
            if entry[key]:
                row[key] = dict(sorted(entry[key].items(), key=lambda item: (-item[1], item[0])))
        row["arguments"] = {
            arg: _describe(seen, runs=entry["runs"], calls=entry["calls"]) for arg, seen in sorted(entry["values"].items())
        }
        if any(arg.get("free_text") and "values" not in arg for arg in row["arguments"].values()):
            row["see"] = f"tenuo-cli calls list --tool {shlex.quote(name)}"
        rows.append(row)
    return {
        "tools": rows,
        "calls": sum(row["calls"] for row in rows),
        "runs": len(runs),
        "steps": [
            {"step": step, "runs": len(times), "latest_run": _latest(times),
             **({"via": sorted(v for v in vias[step] if v)[0]} if any(vias[step]) else {})}
            for step, times in sorted(steps.items())
        ],
        "next": _next_steps(calls_path, steps, vias),
    }


WARRANTGEN = "uvx --from git+https://github.com/RajanChavada/warrantgen warrantgen"


def _latest(run_times):
    return max(run_times.items(), key=lambda item: (item[1], str(item[0])))[0]


def _filename(step):
    """A safe file stem for a step name such as telegram:5550001."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", step).strip("-.") or "warrant"


def _session_key(step, latest):
    """A person (platform:id) or cron job step is attached as is; anything else by its latest session."""
    return step if (":" in step or step.startswith("cron_")) else latest


def _hand_off(via, step, latest, warrant):
    """How the warrant reaches the agent, for the integration that saw the calls."""
    if via in KNOWN_INTEGRATIONS:  # the integration manages sessions: tenuo-cli <name> session attach
        key = shlex.quote(str(_session_key(step, latest)))
        return f"tenuo-cli {via} session attach --session {key} --file {shlex.quote(warrant)}"
    client = {
        "mcp": f'SecureMCPClient.local(warrant="{warrant}", ...)',
        "mcp-server": f'the client that calls this server: SecureMCPClient.local(warrant="{warrant}", ...)',
        "langchain": f'TenuoTool.local(tool, warrant="{warrant}")',
        "temporal": f'start_workflow_authorized(..., warrant=load_warrant_chain("{warrant}"))',
    }.get(via, "your agent's Tenuo integration")
    return f"# give the warrant to {client}"


def _next_steps(calls_path, steps, vias):
    """The commands to write, check and issue a template per step, hand it over, then enforce.

    warrantgen is optional and installed separately, so its drafting commands are
    printed as comments under the step that works with tenuo alone.
    """
    if not steps:
        return ["Run your agent with tenuo-cli mode observe, then run tenuo-cli calls summary again"]
    out = []
    for step, run_times in sorted(steps.items()):
        latest = _latest(run_times)
        stem = _filename(step)
        template, warrant = f"{stem}.yaml", f"{stem}.warrant"
        base = ["template", str(calls_path), "--step", step]
        target = ["--out", template]
        out.append(f"tenuo-cli template new --out {shlex.quote(template)}   # fill in from the summary above")
        out.append(f"# or draft it from the log: {WARRANTGEN} " + _command(base + ["--standing", "--ttl", "7d"] + target)
                   + "   # one warrant for every run")
        if latest is not None and len(run_times) > 1:
            out.append(f"# or: {WARRANTGEN} " + _command(base + ["--from-run", str(latest)] + target)
                       + "   # a warrant per task")
        out.append(f"tenuo-cli template validate --file {shlex.quote(template)}")
        out.append(f"tenuo-cli warrant issue --template {shlex.quote(template)} --holder agent"
                   f" --out {shlex.quote(warrant)}")
        for via in sorted(v for v in vias.get(step, {None}) if v) or [None]:
            recipes = calls_path.parent / "recipes" / via if via else None
            if recipes is not None and recipes.is_dir():
                out.append(f"# or issue a recipe: tenuo-cli warrant issue --template {shlex.quote(str(recipes))}/RECIPE.yaml"
                           f" --holder agent --out {shlex.quote(warrant)}")
            out.append(_hand_off(via, step, latest, warrant))
    out.append("tenuo-cli mode enforce")
    return out


def _command(parts):
    return " ".join(shlex.quote(part) for part in parts)


def _describe(seen, *, runs=(), calls=None):
    """What one argument held across calls: distinct values, numeric bounds, and whether runs differ.

    ``runs`` and ``calls`` are the tool's, so an argument some calls leave out
    is reported as such (``absent_in_calls``) and never as the same in every run.
    """
    values = [value for _, value in seen]
    keys = {json.dumps(value, sort_keys=True, default=str) for value in values}
    out = {"distinct": len(keys)}
    if calls is not None and calls > len(seen):
        out["absent_in_calls"] = calls - len(seen)  # an optional argument
    by_run = {}
    for run, value in seen:
        by_run.setdefault(run, set()).add(json.dumps(value, sort_keys=True, default=str))
    all_runs = set(runs) | set(by_run)
    if len(all_runs) > 1:
        out["same_in_every_run"] = len(by_run) == len(all_runs) and len({frozenset(v) for v in by_run.values()}) == 1
    numbers = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if numbers and len(numbers) == len(values):
        out["min"], out["max"] = min(numbers), max(numbers)
    strings = sorted({v for v in values if isinstance(v, str)})
    if strings and len(strings) == len(keys):
        if any(_free_text(v) for v in strings):
            out["free_text"] = True
            if len(strings) <= MAX_LISTED_VALUES and all(len(v) <= FREE_TEXT_LEN for v in strings):
                out["values"] = strings  # a few short commands or queries: exactly what an allowlist needs
            return out
        if len(strings) <= MAX_LISTED_VALUES:
            out["values"] = strings
        prefix = _common_prefix(strings)
        if prefix and all("/" in v for v in strings):
            prefix = prefix[: prefix.rfind("/") + 1]  # a shared folder, not part of a name
        # Only a prefix that ends at a separator (ORD-, team/, light.) says anything.
        if len(strings) > 1 and prefix and prefix[-1] in "/._-:":
            out["common_prefix"] = prefix
    return out


def _free_text(value):
    """Prose rather than an identifier: whitespace, or long without a path separator."""
    return any(c.isspace() for c in value) or (len(value) > FREE_TEXT_LEN and "/" not in value)


def _common_prefix(strings):
    first, last = strings[0], strings[-1]
    size = 0
    while size < min(len(first), len(last)) and first[size] == last[size]:
        size += 1
    return first[:size]
