"""
Task-aware constraint policies for AgentDojo benchmarks.

This module defines per-task warrant policies that balance security with utility.
Instead of one-size-fits-all constraints, each task gets appropriate permissions.

PHILOSOPHY:
- Legitimate tasks get permissions they need
- Attack vectors are still blocked by constraint specificity
- JIT (Just-in-Time) warrants scoped to task requirements
"""

from typing import Optional
from tenuo import Pattern, Exact, Range, CEL, AnyOf, NotOneOf

# =============================================================================
# Task Context Detection
# =============================================================================

def detect_task_context(query: str, task_id: Optional[str] = None) -> str:
    """
    Detect the context/intent of a task from its query.
    
    Returns a context string used to select appropriate constraints.
    """
    query_lower = query.lower()
    
    # Email-related tasks
    if any(word in query_lower for word in ["email", "send", "reply", "forward"]):
        # Check if it's internal communication
        if any(word in query_lower for word in ["team", "colleague", "coworker", "manager"]):
            return "email_internal"
        # Check if it's customer-facing
        if any(word in query_lower for word in ["customer", "client", "support", "external"]):
            return "email_external"
        return "email_general"
    
    # Calendar tasks
    if any(word in query_lower for word in ["calendar", "meeting", "event", "schedule", "appointment"]):
        return "calendar"
    
    # File operations
    if any(word in query_lower for word in ["file", "document", "read", "write", "save"]):
        return "files"
    
    # Search/lookup
    if any(word in query_lower for word in ["search", "find", "look up", "who"]):
        return "search"
    
    return "general"


# =============================================================================
# Context-Specific Constraints
# =============================================================================

# Workspace suite task-aware policies
WORKSPACE_TASK_POLICIES = {
    # Internal email: Only to company domain
    "email_internal": {
        "send_email": {
            "recipients": CEL("value.all(r, r.endsWith('@company.com') || r.endsWith('@bluesparrowtech.com'))"),
            "_allow_unknown": True,
        },
        "reply_to_email": {
            "recipients": CEL("value.all(r, r.endsWith('@company.com') || r.endsWith('@bluesparrowtech.com'))"),
            "_allow_unknown": True,
        },
        "forward_email": {
            "recipients": CEL("value.all(r, r.endsWith('@company.com') || r.endsWith('@bluesparrowtech.com'))"),
            "_allow_unknown": True,
        },
    },
    
    # External email: Allow known external domains (customers, partners)
    "email_external": {
        "send_email": {
            # Allow internal + known external, but block suspicious free email
            "recipients": CEL("""
                value.all(r, 
                    r.endsWith('@company.com') || 
                    r.endsWith('@bluesparrowtech.com') ||
                    r.endsWith('@mainsail-tech.com') ||
                    r.endsWith('@industry-network.com') ||
                    !(r.endsWith('@gmail.com') || r.endsWith('@yahoo.com') || r.endsWith('@hotmail.com'))
                )
            """.strip().replace("\n", " ")),
            "_allow_unknown": True,
        },
        "reply_to_email": {"_allow_unknown": True},  # Replies are contextual
        "forward_email": {
            "recipients": CEL("value.all(r, !r.endsWith('@gmail.com'))"),
            "_allow_unknown": True,
        },
    },
    
    # General email: Moderate restrictions
    "email_general": {
        "send_email": {
            # Block obvious attack targets (free email services for exfiltration)
            "recipients": CEL("""
                value.all(r, 
                    !(r.contains('attacker') || r.contains('evil') || r.contains('hack'))
                )
            """.strip().replace("\n", " ")),
            "_allow_unknown": True,
        },
        "reply_to_email": {"_allow_unknown": True},
        "forward_email": {"_allow_unknown": True},
    },
    
    # Calendar: Standard access
    "calendar": {
        "search_calendar_events": {"_allow_unknown": True},
        "get_day_calendar_events": {"_allow_unknown": True},
        "create_calendar_event": {"_allow_unknown": True},
        "add_calendar_event_participants": {
            # Block adding external participants to internal meetings
            "participants": CEL("""
                value.all(p, 
                    p.endsWith('@company.com') || 
                    p.endsWith('@bluesparrowtech.com') ||
                    p.endsWith('@mainsail-tech.com')
                )
            """.strip().replace("\n", " ")),
            "_allow_unknown": True,
        },
    },
    
    # File operations: Protect sensitive files
    "files": {
        "read_file": {"_allow_unknown": True},
        "write_file": {"_allow_unknown": True},
        "create_file": {"_allow_unknown": True},
        "delete_file": {
            # Protect specific sensitive file IDs
            "file_id": NotOneOf(["13", "14", "15", "1", "2", "3"]),
            "_allow_unknown": True,
        },
        "share_file": {
            "email": Pattern("*@company.com"),
            "_allow_unknown": True,
        },
    },
    
    # Search: Open access
    "search": {
        "search_files": {"_allow_unknown": True},
        "search_emails": {"_allow_unknown": True},
        "search_contacts_by_name": {"_allow_unknown": True},
        "search_contacts_by_email": {"_allow_unknown": True},
    },
    
    # General: Baseline restrictions
    "general": {
        # Inherit from base constraints
    },
}


def get_task_constraints(
    suite_name: str, 
    context: str, 
    base_constraints: dict
) -> dict:
    """
    Get constraints for a specific task context.
    
    Merges task-specific policies with base constraints.
    Task-specific policies override base constraints for specified tools.
    """
    if suite_name != "workspace":
        return base_constraints
    
    task_policy = WORKSPACE_TASK_POLICIES.get(context, {})
    
    # Start with base constraints
    merged = dict(base_constraints)
    
    # Override with task-specific constraints
    for tool, constraints in task_policy.items():
        merged[tool] = constraints
    
    return merged


# =============================================================================
# Constraint Selection Logic
# =============================================================================

def select_constraints_for_query(
    suite_name: str,
    query: str,
    base_constraints: dict,
    task_id: Optional[str] = None,
) -> dict:
    """
    Select appropriate constraints based on the task query.
    
    This is the main entry point for JIT constraint selection.
    """
    context = detect_task_context(query, task_id)
    return get_task_constraints(suite_name, context, base_constraints)

