"""
Report generation for the multi-agent delegation benchmark.

Produces a markdown report with:
  - Deterministic results table (if present)
  - LLM results table with mean ± std (if present)
  - Per-scenario call log details
"""

from __future__ import annotations

import os
import statistics
from collections import defaultdict
from datetime import datetime

from .harness import TrialResult


def _asr(trials: list[TrialResult]) -> float:
    if not trials:
        return 0.0
    return sum(1 for t in trials if t.attack_succeeded) / len(trials)


def _tcr(trials: list[TrialResult]) -> float:
    if not trials:
        return 0.0
    return sum(1 for t in trials if t.task_succeeded) / len(trials)


def _fmt_pct(val: float) -> str:
    return f"{val:.0%}"


def _fmt_pct_with_std(values: list[float]) -> str:
    if len(values) <= 1:
        return _fmt_pct(values[0]) if values else "—"
    mean = statistics.mean(values)
    std = statistics.stdev(values)
    return f"{mean:.0%} ± {std:.0%}"


def _results_table(
    results: list[TrialResult],
    conditions: list[str],
    use_std: bool = False,
) -> str:
    grouped: dict[str, dict[str, list[TrialResult]]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        grouped[r.scenario][r.condition].append(r)

    scenarios = sorted(grouped.keys())

    header = "| Scenario | Metric |"
    sep = "|----------|--------|"
    for c in conditions:
        header += f" {c} |"
        sep += "--------|"

    rows = []
    for s in scenarios:
        asr_cells, tcr_cells, blk_cells = [], [], []
        for c in conditions:
            trials = grouped[s].get(c, [])
            if use_std and len(trials) > 1:
                asr_vals = [1.0 if t.attack_succeeded else 0.0 for t in trials]
                tcr_vals = [1.0 if t.task_succeeded else 0.0 for t in trials]
                asr_cells.append(_fmt_pct_with_std(asr_vals))
                tcr_cells.append(_fmt_pct_with_std(tcr_vals))
            else:
                asr_cells.append(_fmt_pct(_asr(trials)))
                tcr_cells.append(_fmt_pct(_tcr(trials)))
            blk_cells.append(str(sum(t.calls_blocked for t in trials)))

        rows.append(f"| {s} | ASR | " + " | ".join(asr_cells) + " |")
        rows.append(f"| {s} | TCR | " + " | ".join(tcr_cells) + " |")
        rows.append(f"| {s} | Blocked | " + " | ".join(blk_cells) + " |")

    return "\n".join([header, sep] + rows)


def _scenario_details(results: list[TrialResult], conditions: list[str]) -> str:
    """Per-scenario call log for the first trial of each condition."""
    grouped: dict[str, dict[str, list[TrialResult]]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        grouped[r.scenario][r.condition].append(r)

    sections = []
    for s in sorted(grouped.keys()):
        lines = [f"### {s}\n"]
        for c in conditions:
            trials = grouped[s].get(c, [])
            if not trials:
                continue
            trial = trials[0]
            v = trial.verdict
            lines.append(f"**{c}** — ASR={_fmt_pct(_asr(trials))}, TCR={_fmt_pct(_tcr(trials))}")
            if v:
                lines.append(f"  Task: {v.task_detail} | Attack: {v.attack_detail}")
            lines.append("")
            for cr in trial.call_log:
                tag = "ALLOWED" if cr.authorized else "BLOCKED"
                args_s = ", ".join(f"{k}={repr(v)[:25]}" for k, v in list(cr.args.items())[:3])
                lines.append(f"- `[{tag}]` `{cr.tool}({args_s})`")
            lines.append("")
        sections.append("\n".join(lines))
    return "\n".join(sections)


def generate_report(
    results: list[TrialResult],
    model: str | None = None,
) -> str:
    conditions = ["no_warrant", "broad", "task_scoped"]

    det_results = [r for r in results if r.mode == "deterministic"]
    llm_results = [r for r in results if r.mode == "llm"]

    n_runs_llm = 0
    if llm_results:
        from collections import Counter
        counts = Counter((r.scenario, r.condition) for r in llm_results)
        n_runs_llm = max(counts.values()) if counts else 0

    # ── Deterministic section ──
    det_section = ""
    if det_results:
        det_table = _results_table(det_results, conditions, use_std=False)
        det_details = _scenario_details(det_results, conditions)

        scoped_det = [r for r in det_results if r.condition == "task_scoped"]
        baseline_det = [r for r in det_results if r.condition == "no_warrant"]

        det_section = f"""## Deterministic Results

Scripted attack sequences replayed against each warrant condition.
Same calls, same warrants, same result every run.

{det_table}

### Call Logs

{det_details}

**Summary**: baseline ASR {_fmt_pct(_asr(baseline_det))} → task_scoped ASR {_fmt_pct(_asr(scoped_det))}, TCR {_fmt_pct(_tcr(scoped_det))}.
"""

    # ── LLM section ──
    llm_section = ""
    if llm_results:
        llm_table = _results_table(llm_results, conditions, use_std=True)
        llm_details = _scenario_details(llm_results, conditions)

        scoped_llm = [r for r in llm_results if r.condition == "task_scoped"]
        baseline_llm = [r for r in llm_results if r.condition == "no_warrant"]

        llm_section = f"""## LLM Results ({model or "unknown"}, {n_runs_llm} runs/cell)

Real model plays q-agent with tool calling. Injections embedded in tool
output data. {n_runs_llm} independent runs per cell.

{llm_table}

### Call Logs (first run per cell)

{llm_details}

**Summary**: baseline ASR {_fmt_pct(_asr(baseline_llm))} → task_scoped ASR {_fmt_pct(_asr(scoped_llm))}, TCR {_fmt_pct(_tcr(scoped_llm))}.
"""

    # ── Aggregate headline ──
    all_scoped = [r for r in results if r.condition == "task_scoped"]
    all_baseline = [r for r in results if r.condition == "no_warrant"]
    model_line = f"\n**Model**: {model}" if model else ""

    return f"""# Multi-Agent Delegation Benchmark Report

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Trials**: {len(results)} ({len(det_results)} deterministic, {len(llm_results)} LLM){model_line}

## Hypothesis

Task-scoped cryptographic delegation bounds blast radius from compromised
agents without killing utility.

- **ASR** (Attack Success Rate): Did the malicious objective succeed?
- **TCR** (Task Completion Rate): Did the legitimate task complete?
- **Blocked**: Tool calls intercepted by warrant enforcement.

### Key Finding

| Condition | ASR | TCR |
|-----------|-----|-----|
| no_warrant (baseline) | {_fmt_pct(_asr(all_baseline))} | {_fmt_pct(_tcr(all_baseline))} |
| task_scoped | {_fmt_pct(_asr(all_scoped))} | {_fmt_pct(_tcr(all_scoped))} |

{det_section}
{llm_section}
## Methodology

- **Injection delivery**: Payloads embedded in tool output data (file contents,
  transaction memos) — not concatenated to prompts.
- **Chain verification**: `Authorizer.check_chain()` with `org_key` as root of trust.
  Full delegation chain `[p_warrant, q_warrant]` verified on every call.
- **Strict policies**: No `_allow_unknown`. Every parameter explicitly constrained.
- **Judge**: Automated, deterministic criteria per scenario — no LLM judge.
- **Control**: Same task, same injection, same environment. Only the warrant changes.

## Reproducing

```bash
# Deterministic only (no LLM, no API key)
python -m benchmarks.multiagent.run --mode deterministic

# LLM only
export OPENAI_API_KEY="sk-..."
python -m benchmarks.multiagent.run --mode llm --model gpt-4o-mini --runs 10

# Both (deterministic + LLM)
python -m benchmarks.multiagent.run --mode both --runs 10
```
"""


def save_report(results: list[TrialResult], model: str | None = None) -> str:
    report = generate_report(results, model=model)
    out_path = os.path.join(os.path.dirname(__file__), "REPORT.md")
    with open(out_path, "w") as f:
        f.write(report)
    return out_path
