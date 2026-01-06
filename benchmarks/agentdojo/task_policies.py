"""
Baseline Policy for AgentDojo Benchmarks.

This module defines a SINGLE, STATIC policy that represents reasonable
enterprise constraints. The benchmark tests one thing:

    Given this policy, did Tenuo enforce it correctly?

The answer should always be: Yes, 100%.

ARCHITECTURE:
  ┌─────────────────┐     ┌─────────────┐     ┌─────────────┐
  │ Your Policy     │ ──▶ │   Warrant   │ ──▶ │   Tenuo     │
  │ Engine          │     │  (carries   │     │ (enforces)  │
  │ (decides what)  │     │   policy)   │     │             │
  └─────────────────┘     └─────────────┘     └─────────────┘
        ↑                                           ↑
    Not Tenuo's job                            Tenuo's job
    (simulated here)                           (tested here)
"""

from tenuo import Pattern, NotOneOf, CEL


# =============================================================================
# Baseline Policy
# =============================================================================
# Reasonable enterprise constraints for an internal agent.
# These are NOT designed to "catch attacks" - they represent normal policy.

BASELINE_POLICY = {
    # Email: Internal domains only
    # Rationale: Standard data-loss-prevention policy
    "send_email": {
        "recipients": CEL(
            "value.all(r, r.endsWith('@company.com') || r.endsWith('@bluesparrowtech.com'))"
        ),
        "_allow_unknown": True,
    },
    "reply_to_email": {
        "recipients": CEL(
            "value.all(r, r.endsWith('@company.com') || r.endsWith('@bluesparrowtech.com'))"
        ),
        "_allow_unknown": True,
    },
    "forward_email": {
        "recipients": CEL(
            "value.all(r, r.endsWith('@company.com') || r.endsWith('@bluesparrowtech.com'))"
        ),
        "_allow_unknown": True,
    },
    # File sharing: Internal only
    "share_file": {
        "email": Pattern("*@company.com"),
        "_allow_unknown": True,
    },
    # File deletion: Protect certain file IDs
    # Rationale: Sensitive documents require approval workflow
    "delete_file": {
        "file_id": NotOneOf(["13", "14", "15"]),
        "_allow_unknown": True,
    },
    # Calendar: Internal participants
    "add_calendar_event_participants": {
        "participants": CEL(
            "value.all(p, p.endsWith('@company.com') || p.endsWith('@bluesparrowtech.com'))"
        ),
        "_allow_unknown": True,
    },
    # Read operations: No constraints (allowed)
    "read_file": {"_allow_unknown": True},
    "get_file_by_id": {"_allow_unknown": True},
    "list_files": {"_allow_unknown": True},
    "search_files": {"_allow_unknown": True},
    "search_files_by_filename": {"_allow_unknown": True},
    "get_unread_emails": {"_allow_unknown": True},
    "get_sent_emails": {"_allow_unknown": True},
    "get_received_emails": {"_allow_unknown": True},
    "search_emails": {"_allow_unknown": True},
    "get_email_by_id": {"_allow_unknown": True},
    "search_contacts_by_name": {"_allow_unknown": True},
    "search_contacts_by_email": {"_allow_unknown": True},
    "get_contact_info": {"_allow_unknown": True},
    "search_calendar_events": {"_allow_unknown": True},
    "get_day_calendar_events": {"_allow_unknown": True},
    "get_current_day": {"_allow_unknown": True},
    "get_current_time": {"_allow_unknown": True},
    # Write operations: Allowed (no special constraints)
    "write_file": {"_allow_unknown": True},
    "create_file": {"_allow_unknown": True},
    "append_to_file": {"_allow_unknown": True},
    "create_calendar_event": {"_allow_unknown": True},
    "add_contact": {"_allow_unknown": True},
    "delete_email": {"_allow_unknown": True},
    "cancel_calendar_event": {"_allow_unknown": True},
    "reschedule_calendar_event": {"_allow_unknown": True},
    "remove_calendar_event_participants": {"_allow_unknown": True},
    "get_draft_emails": {"_allow_unknown": True},
}


def get_baseline_policy() -> dict:
    """
    Get the baseline policy for benchmarks.

    Returns:
        Dictionary of tool_name -> constraints
    """
    return BASELINE_POLICY.copy()


# =============================================================================
# Backward Compatibility
# =============================================================================


def get_role_constraints(role: str = "internal_agent") -> dict:
    """Backward-compatible API. Always returns baseline policy."""
    return get_baseline_policy()


def select_constraints_for_query(
    suite_name: str,
    query: str,
    base_constraints: dict,
    task_id: str | None = None,
) -> dict:
    """Backward-compatible API. Merges baseline with base constraints."""
    merged = dict(base_constraints)
    merged.update(get_baseline_policy())
    return merged
