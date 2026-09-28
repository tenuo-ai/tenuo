"""Tenuo presets for the Temporal Agent Harness (``temporal-agent-harness``).

The harness (https://pypi.org/project/temporal-agent-harness/) runs agent
tool calls, model invocations, and MCP servers as ordinary Temporal
activities on top of the same Workflow/Activity primitives
``tenuo.temporal`` already protects. Three harness-specific shapes need a
little help from the plugin, all opt-in and all covered by the general
:class:`~tenuo.temporal.TenuoPluginConfig` fields — this module just ships
the harness's own values pre-filled:

1. **``@agent.activity_tool_defn`` tools** receive the model's own arguments
   plus a trailing ``tool_ctx: AgentToolContext`` the harness uses to
   publish ``tool_start``/``tool_end`` events. ``tool_ctx`` is not a
   primitive/dataclass/dict/list (it is a pydantic model wrapping a stream
   context and a call id) and carries no authority — see
   ``TenuoPluginConfig.pop_exclude_args`` and
   :data:`HARNESS_TOOL_CTX_EXCLUDE_ARGS`.
2. **Harness-internal activities** (model calls, the Jev auto-mode approval
   activity, Code Mode batches, MCP list/session activities, sandbox
   lifecycle) are not effects on a customer system and do not need a
   warrant — see ``TenuoPluginConfig.unwarranted_activities`` and
   :data:`HARNESS_INTERNAL_ACTIVITIES`. Real tool-call effects (including
   MCP call-tool) are never in this list.
3. **MCP tool calls** run as one activity per server,
   ``<server>-call-tool-v2``, wrapping ``{tool_name, arguments, meta}`` in a
   single argument. The warrant should name the wrapped MCP tool and
   constrain ``arguments``, not the wrapper — see
   ``TenuoPluginConfig.mcp_call_tool_activities`` and
   :data:`HARNESS_MCP_CALL_TOOL_ACTIVITIES`.

:func:`harness_plugin_config` builds a ``TenuoPluginConfig`` with all three
presets applied. :func:`warrant_evaluator` is a Tenuo auto-mode evaluator
for the harness's ``AutoApprovalDecision`` seam (see its docstring).

**No hard dependency.** Importing this module does not require
``temporal-agent-harness`` to be installed — the presets below are just
strings. ``temporal_agent_harness`` types are only imported inside
:func:`warrant_evaluator`, and only when you call it. Install both with the
``tenuo[temporal-harness]`` extra.

Everything here targets the harness's OpenAI Agents SDK integration
(``temporal_agent_harness.ai_sdks.openai_agents``), the path the harness's
own examples and the Tenuo refund-agent example use; the exact internal
activity names come from that integration's source, not from guessing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, FrozenSet, Optional, Sequence, Tuple

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from collections.abc import Awaitable, Callable

    from temporal_agent_harness.harness.agent import (
        AutoApprovalContext,
        AutoApprovalDecision,
    )

    from tenuo.temporal._config import TenuoPluginConfig

    Evaluator = Callable[[AutoApprovalContext], Awaitable[AutoApprovalDecision]]

# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

HARNESS_TOOL_CTX_EXCLUDE_ARGS: FrozenSet[str] = frozenset({"tool_ctx"})
"""``pop_exclude_args`` value for the harness: the ``AgentToolContext``
trailing argument every ``@agent.activity_tool_defn`` tool activity
receives (see ``temporal_agent_harness.harness.agent_workflow.activity_tool_defn``
and ``AgentToolContext``). It carries no capability a warrant should ever
constrain — only which turn/tool-call id to publish lifecycle events
against — and cannot be normalized for PoP (it's a pydantic model, not a
primitive/dataclass/dict/list)."""

HARNESS_INTERNAL_ACTIVITIES: Tuple[str, ...] = (
    # Model invocation (temporal_agent_harness.ai_sdks.openai_agents._invoke_model_activity)
    "invoke_model_activity",
    "invoke_model_activity_streaming",
    # Google GenAI SDK integration's model/file activities
    # (temporal_agent_harness.ai_sdks.google_genai_plugin) all share this prefix.
    "gemini_*",
    # Jev auto-mode tool-approval activity
    # (temporal_agent_harness.harness.jev_approvals.models.JEV_TOOL_APPROVAL_ACTIVITY)
    "jev_tool_approval",
    # Code Mode batch activities
    # (temporal_agent_harness.harness.code_mode.batch_models)
    "code_start_batch",
    "code_resume_batch",
    # Subagent turn activity
    # (temporal_agent_harness.harness.agent_protocol.subagent_interface.RUN_SUBAGENT_TURN_ACTIVITY)
    "run_subagent_turn",
    # MCP server plumbing — list/session/prompt activities, NOT the
    # call-tool-v2 effect activity (that stays protected; see
    # HARNESS_MCP_CALL_TOOL_ACTIVITIES). Exact suffixes from
    # temporal_agent_harness.ai_sdks.openai_agents._mcp
    # (StatelessMCPServerProvider / StatefulMCPServerProvider).
    "*-list-tools",
    "*-list-prompts",
    "*-get-prompt",
    "*-get-prompt-v2",
    "*-server-session",
    # Code Mode sandbox lifecycle
    # (temporal_agent_harness.ai_sdks.openai_agents.sandbox._sandbox_client_provider)
    "*-sandbox_*",
)
"""``unwarranted_activities`` preset: the harness's own internal plumbing.

None of these touch a customer system. Deliberately excludes the harness's
deprecated, non-wrapped ``<server>-call-tool`` activity (two loose
``tool_name``/``arguments`` parameters, no ``meta``) as well as
``<server>-call-tool-v2`` — both are real MCP tool-call effects and must
stay protected; the latter is unwrapped, not exempted, via
:data:`HARNESS_MCP_CALL_TOOL_ACTIVITIES`. Construction-time validation in
``TenuoPluginConfig.__post_init__`` additionally rejects any pattern here
that would match an MCP call-tool-v2-shaped name, so this list (or an
extension of it) can never silently swallow tool-call effects.
"""

HARNESS_MCP_CALL_TOOL_ACTIVITIES: Tuple[str, ...] = ("*-call-tool-v2",)
"""``mcp_call_tool_activities`` preset: the harness's one-activity-per-server
MCP tool-call wrapper (``temporal_agent_harness.ai_sdks.openai_agents._mcp``,
``_StatelessCallToolsArguments`` / ``_StatefulCallToolsArguments``:
``{tool_name: str, arguments: dict | None, meta: dict | None = None}``,
plus a ``factory_argument`` field the unwrap ignores along with ``meta``).
These activities ARE effects and stay protected — signing/verification
authorizes the inner ``tool_name``/``arguments``, not the wrapper."""


def harness_plugin_config(
    *,
    unwarranted_activities: Sequence[str] = (),
    pop_exclude_args: Sequence[str] = (),
    mcp_call_tool_activities: Sequence[str] = (),
    **kwargs: Any,
) -> "TenuoPluginConfig":
    """``TenuoPluginConfig`` pre-loaded with the Temporal Agent Harness presets.

    Equivalent to::

        TenuoPluginConfig(
            unwarranted_activities=HARNESS_INTERNAL_ACTIVITIES,
            pop_exclude_args=HARNESS_TOOL_CTX_EXCLUDE_ARGS,
            mcp_call_tool_activities=HARNESS_MCP_CALL_TOOL_ACTIVITIES,
            ...,
        )

    Any ``unwarranted_activities=``, ``pop_exclude_args=``, or
    ``mcp_call_tool_activities=`` you pass here are ADDED to the preset, not
    a replacement for it — you extend the harness defaults with your own
    internal activities or excluded arguments without having to also
    remember to re-list the harness's own. Every other
    :class:`~tenuo.temporal.TenuoPluginConfig` field (``key_resolver``,
    ``trusted_roots``, ``require_warrant``, ``activity_fns``, ...) passes
    straight through via ``**kwargs``.

    Use the **same** call (same extra activities/args, if any) to build both
    the workflow-worker and activity-worker config — ``pop_exclude_args``
    and ``mcp_call_tool_activities`` are applied symmetrically outbound and
    inbound and fail closed on any mismatch between the two.
    """
    from tenuo.temporal._config import TenuoPluginConfig as _TenuoPluginConfig

    merged_unwarranted = tuple(
        dict.fromkeys((*HARNESS_INTERNAL_ACTIVITIES, *unwarranted_activities))
    )
    merged_exclude = frozenset(HARNESS_TOOL_CTX_EXCLUDE_ARGS) | frozenset(pop_exclude_args)
    merged_mcp = tuple(
        dict.fromkeys((*HARNESS_MCP_CALL_TOOL_ACTIVITIES, *mcp_call_tool_activities))
    )

    return _TenuoPluginConfig(
        unwarranted_activities=merged_unwarranted,
        pop_exclude_args=merged_exclude,
        mcp_call_tool_activities=merged_mcp,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# warrant_evaluator — auto-mode evaluator gated by the task warrant
# ---------------------------------------------------------------------------


def warrant_evaluator(
    get_warrant: "Callable[[], Any]",
    next_evaluator: "Optional[Evaluator]" = None,
    *,
    review_above: "Optional[Dict[str, tuple]]" = None,
) -> "Evaluator":
    """Build a harness auto-mode evaluator that checks the task warrant first.

    The harness gives every gated tool call a durable seam: the call pauses
    in the workflow, an auto-mode evaluator may approve, deny, or escalate
    it, and anything escalated waits for a human. This evaluator puts the
    task warrant at the front of that seam:

    1. **Outside the warrant: DENY.** Wrong order, more than the customer
       paid, a different card, a tool the task was never given, or an
       expired ticket. The call never reaches the next evaluator or a
       human, and the model is told exactly which bound it hit so it can
       try something the warrant does allow.
    2. **Inside the warrant, above the operator's review threshold:**
       ESCALATE to the harness's human gate.
    3. **Inside the warrant, below the threshold:** hand the call to
       ``next_evaluator`` (e.g. ``agent.jev_evaluator()`` in production) for
       the judgment call the warrant cannot make — is this a *good* idea,
       not just an *allowed* one.

    Args:
        get_warrant: Returns the task warrant for the current workflow.
            Called in-workflow — keep it pure (e.g. read an attribute set on
            the workflow instance), since this evaluator itself is pure
            computation over workflow state and ``workflow.now()`` and must
            stay replay-safe.
        next_evaluator: Consulted for calls that are inside the warrant and
            under the review threshold. ``None`` approves them
            unconditionally (useful for a demo; pass a real evaluator in
            production).
        review_above: Per-tool review thresholds, ``{tool: (argument,
            limit)}``. A call whose ``argument`` exceeds ``limit`` is
            escalated to a human even though the warrant allows it. This is
            operator policy about who looks at a call, never a widening of
            what the call may do — the warrant bound above it is still
            enforced first.

    This is the *early* check, for the model's sake: a precise refusal it
    can act on, before anyone is asked to approve something that could
    never run anyway. The binding check still runs on the effects worker,
    where the Tenuo plugin verifies the warrant and a Proof-of-Possession
    signature over the exact arguments before the activity body starts — a
    call that reaches the worker by another route (a pre-approved tool, a
    human approval, a bug in an evaluator) is still held to the same
    bounds.
    """
    from temporalio import workflow

    with workflow.unsafe.imports_passed_through():
        from temporal_agent_harness.harness.agent import (
            AutoApprovalDecision,
            AutoApprovalVerdict,
        )
        from temporal_agent_harness.harness.agent_workflow import (
            AUTO_MODE_EVALUATOR_ATTR,
        )

    review_above = dict(review_above or {})

    async def _approve(ctx: Any) -> Any:
        return AutoApprovalDecision(
            AutoApprovalVerdict.APPROVE, reason="within the task warrant"
        )

    inner = next_evaluator or _approve

    async def evaluate(ctx: Any) -> Any:
        import datetime as _dt

        warrant = get_warrant()
        facts: Dict[str, Any] = {
            "warrant_id": warrant.id,
            "tool": ctx.tool_name,
        }

        expires_at = _dt.datetime.fromisoformat(warrant.expires_at())
        if workflow.now() >= expires_at:
            return AutoApprovalDecision(
                AutoApprovalVerdict.DENY,
                reason="The task warrant for this ticket has expired.",
                details={**facts, "denied_by": "tenuo", "bound": "expiry"},
            )

        violation = warrant.check_constraints(ctx.tool_name, dict(ctx.tool_input))
        if violation is not None:
            return AutoApprovalDecision(
                AutoApprovalVerdict.DENY,
                reason=f"Outside this ticket's warrant: {violation}",
                details={**facts, "denied_by": "tenuo", "bound": violation},
            )

        if ctx.tool_name in review_above:
            arg, limit = review_above[ctx.tool_name]
            value = ctx.tool_input.get(arg)
            if isinstance(value, (int, float)) and value > limit:
                return AutoApprovalDecision(
                    AutoApprovalVerdict.ESCALATE,
                    reason=(
                        f"Within the warrant, but {arg}={value} is above the "
                        f"review threshold of {limit}."
                    ),
                    details={**facts, "escalated_by": "tenuo", "threshold": limit},
                )

        decision = await inner(ctx)
        decision.details = {**facts, "within_warrant": True, **(decision.details or {})}
        return decision

    inner_label = getattr(inner, AUTO_MODE_EVALUATOR_ATTR, None) or getattr(
        inner, "__qualname__", "evaluator"
    )
    # Published as ``evaluator`` on every auto_approval_evaluation_* event.
    setattr(evaluate, AUTO_MODE_EVALUATOR_ATTR, f"tenuo -> {inner_label}")
    return evaluate


__all__ = [
    "HARNESS_TOOL_CTX_EXCLUDE_ARGS",
    "HARNESS_INTERNAL_ACTIVITIES",
    "HARNESS_MCP_CALL_TOOL_ACTIVITIES",
    "harness_plugin_config",
    "warrant_evaluator",
]
