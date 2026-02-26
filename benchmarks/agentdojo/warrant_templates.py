"""
Warrant templates for AgentDojo task suites.

Defines constraint policies for different task types to demonstrate
Tenuo's capability-based authorization.

CONSTRAINT PHILOSOPHY:
- HIGH-RISK tools: Tight constraints (amounts, recipients, paths)
- MEDIUM-RISK tools: Limit-based constraints (pagination, scoping)
- LOW-RISK tools: No constraints beyond tool-level grant

_allow_unknown RATIONALE:
  Every constraint dict uses _allow_unknown=True because AgentDojo tools
  have many parameters (subject, body, email_id, etc.) that we don't
  constrain. Without it, Tenuo's zero-trust mode rejects any parameter
  not explicitly listed. The benchmark tests specific constraint axes
  (recipients, amounts, paths), not parameter completeness. A production
  deployment would enumerate all allowed fields or accept the gap.

AgentDojo Environments:
- Banking: 11 tools, 16 user tasks, 9 injection patterns
- Slack: 11 tools, 21 user tasks, 5 injection patterns
- Travel: 28 tools, 20 user tasks, 7 injection patterns
- Workspace: 24 tools, 40 user tasks, 6 injection patterns

Total: 97 user tasks, 629 security cases
"""

from tenuo import Pattern, Exact, Range, OneOf, AnyOf, NotOneOf, CEL


# =============================================================================
# Banking Suite (11 tools - names from AgentDojo)
# Attack vectors: Unauthorized transfers, balance disclosure, account manipulation
# =============================================================================
BANKING_CONSTRAINTS = {
    # HIGH-RISK: Financial operations with value transfer
    # AgentDojo tool name: send_money
    "send_money": {
        "amount": Range(min=0, max=1000),  # Max $1000 per transfer
        "recipient": Pattern("*"),  # Could narrow to known accounts
        "_allow_unknown": True,
    },
    # AgentDojo tool name: schedule_transaction
    "schedule_transaction": {
        "amount": Range(min=0, max=500),  # Lower limit for scheduled
        "recipient": Pattern("*"),
        "_allow_unknown": True,
    },
    "update_scheduled_transaction": {
        "amount": Range(min=0, max=500),
        "_allow_unknown": True,
    },
    # MEDIUM-RISK: Query operations
    "get_most_recent_transactions": {
        "n": Range(min=1, max=100),  # Prevent bulk export
        "_allow_unknown": True,
    },
    "get_scheduled_transactions": {"_allow_unknown": True},
    # MEDIUM-RISK: Account modifications
    "update_user_info": {"_allow_unknown": True},
    "update_password": {"_allow_unknown": True},
    # LOW-RISK: Safe read-only operations
    "get_balance": {"_allow_unknown": True},
    "get_iban": {"_allow_unknown": True},
    "get_user_info": {"_allow_unknown": True},
    "read_file": {"path": Pattern("*"), "_allow_unknown": True},
}


# =============================================================================
# Slack Suite (11 tools)
# Attack vectors: Data exfiltration via DMs, admin channel access, impersonation
# =============================================================================
SLACK_CONSTRAINTS = {
    # HIGH-RISK: Message sending (exfiltration vector)
    "post_message": {
        "channel": AnyOf(
            [
                Pattern("#general"),
                Pattern("#team-*"),
                Pattern("#project-*"),
            ]
        ),  # No admin, private, or DM channels
        "_allow_unknown": True,
    },
    "send_message": {
        "channel": AnyOf(
            [
                Pattern("#general"),
                Pattern("#team-*"),
                Pattern("#project-*"),
            ]
        ),
        "_allow_unknown": True,
    },
    "send_direct_message": {
        "recipient": Pattern("*@company.com"),  # Internal users only
        "_allow_unknown": True,
    },
    # HIGH-RISK: Channel creation
    "create_channel": {
        "name": Pattern("team-*"),  # Only team- prefixed
        "is_private": Exact("false"),  # No private channels
        "_allow_unknown": True,
    },
    # MEDIUM-RISK: Reading with scope limits
    "read_messages": {
        "channel": AnyOf(
            [
                Pattern("#general"),
                Pattern("#team-*"),
            ]
        ),
        "limit": Range(min=1, max=100),
        "_allow_unknown": True,
    },
    "get_channel_messages": {
        "channel": AnyOf(
            [
                Pattern("#general"),
                Pattern("#team-*"),
            ]
        ),
        "limit": Range(min=1, max=100),
        "_allow_unknown": True,
    },
    "search_messages": {
        "limit": Range(min=1, max=50),
        "_allow_unknown": True,
    },
    # LOW-RISK: Directory lookups
    "list_channels": {"_allow_unknown": True},
    "get_channel_info": {"_allow_unknown": True},
    "get_user_info": {"_allow_unknown": True},
    "list_users": {"_allow_unknown": True},
}


# =============================================================================
# Travel Suite (28 tools)
# Attack vectors: Premium bookings, price manipulation, unauthorized reservations
# =============================================================================
TRAVEL_CONSTRAINTS = {
    # HIGH-RISK: Booking operations with cost
    "book_flight": {
        "max_price": Range(min=0, max=500),
        "class": Exact("economy"),
        "_allow_unknown": True,
    },
    "book_hotel": {
        "max_price_per_night": Range(min=0, max=150),
        "stars": Range(min=1, max=3),
        "_allow_unknown": True,
    },
    "book_car": {
        "max_price_per_day": Range(min=0, max=75),
        "category": OneOf(["economy", "compact", "midsize"]),
        "_allow_unknown": True,
    },
    "process_payment": {
        "amount": Range(min=0, max=2000),
        "_allow_unknown": True,
    },
    "redeem_points": {
        "points": Range(min=0, max=50000),
        "_allow_unknown": True,
    },
    # MEDIUM-RISK: Search with price caps
    "search_flights": {
        "max_price": Range(min=0, max=2000),
        "_allow_unknown": True,
    },
    "search_hotels": {
        "max_price_per_night": Range(min=0, max=300),
        "_allow_unknown": True,
    },
    "search_cars": {
        "max_price_per_day": Range(min=0, max=100),
        "_allow_unknown": True,
    },
    # MEDIUM-RISK: Modifications
    "modify_reservation": {
        "change_type": OneOf(["date", "time"]),  # No class upgrades
        "_allow_unknown": True,
    },
    # LOW-RISK: Cancellations (user-initiated, reversible)
    "cancel_flight": {"_allow_unknown": True},
    "cancel_hotel": {"_allow_unknown": True},
    "cancel_car": {"_allow_unknown": True},
    # LOW-RISK: Read-only lookups
    "get_flight_info": {"_allow_unknown": True},
    "get_flight_status": {"_allow_unknown": True},
    "get_hotel_info": {"_allow_unknown": True},
    "get_car_info": {"_allow_unknown": True},
    "get_reservations": {"_allow_unknown": True},
    "get_reservation_details": {"_allow_unknown": True},
    "get_user_preferences": {"_allow_unknown": True},
    "get_payment_methods": {"_allow_unknown": True},
    "get_loyalty_points": {"_allow_unknown": True},
    "get_weather": {"_allow_unknown": True},
    "get_destination_info": {"_allow_unknown": True},
    "search_attractions": {"_allow_unknown": True},
    # LOW-RISK: Preference management
    "update_user_preferences": {"_allow_unknown": True},
    "add_payment_method": {"_allow_unknown": True},
}


# =============================================================================
# Workspace Suite (33 tools)
# Attack vectors: File exfiltration, email data theft, calendar manipulation
#
# CRITICAL: Parameter names MUST match AgentDojo tool signatures exactly!
# - send_email uses `recipients` (list), not `to`
# - share_file uses `email`, not `recipient`
# - file ops use `file_id` or `filename`, not `path`
# - calendar uses `participants` (list), not `participant`
#
# NOTE: For list arguments (recipients, participants), we use CEL expressions
# with .all() macro to validate each element matches the pattern.
# =============================================================================
WORKSPACE_CONSTRAINTS = {
    # === HIGH-RISK: Outbound data (exfiltration vectors) ===
    # AgentDojo: send_email(recipients: list[str], subject, body, ...)
    # CEL .all() validates each recipient ends with internal domain
    # NOTE: In CEL constraints, the field value is available as `value`
    "send_email": {
        "recipients": CEL("value.all(r, r.endsWith('@company.com'))"),
        "_allow_unknown": True,
    },
    "reply_to_email": {
        "recipients": CEL("value.all(r, r.endsWith('@company.com'))"),
        "_allow_unknown": True,
    },
    "forward_email": {
        "recipients": CEL("value.all(r, r.endsWith('@company.com'))"),
        "_allow_unknown": True,
    },
    # AgentDojo: share_file(file_id, email: str, permission)
    "share_file": {
        "email": Pattern("*@company.com"),  # Only internal sharing (scalar, not list)
        "_allow_unknown": True,
    },
    # === HIGH-RISK: File write operations ===
    # AgentDojo: create_file(filename: str, content: str)
    "write_file": {
        "filename": Pattern("*"),  # Allow writes (constraint by filename if needed)
        "_allow_unknown": True,
    },
    # AgentDojo: delete_file(file_id: str)
    "delete_file": {
        "file_id": NotOneOf(["13", "14", "15"]),  # Block deletion of sensitive file IDs
        "_allow_unknown": True,
    },
    # AgentDojo: create_file(filename: str, content: str)
    "create_file": {
        "filename": Pattern("*"),  # Allow file creation
        "_allow_unknown": True,
    },
    # AgentDojo: append_to_file(file_id: str, content: str)
    "append_to_file": {
        "file_id": Pattern("*"),  # Allow appending
        "_allow_unknown": True,
    },
    # === MEDIUM-RISK: File reads ===
    # AgentDojo: read_file uses file_id, get_file_by_id uses file_id
    "read_file": {
        "file_id": Pattern("*"),  # Allow reads
        "_allow_unknown": True,
    },
    # === MEDIUM-RISK: Calendar with external participants ===
    # AgentDojo: add_calendar_event_participants(event_id, participants: list[str])
    # CEL .all() validates each participant ends with internal domain
    "add_calendar_event_participants": {
        "participants": CEL("value.all(p, p.endsWith('@company.com'))"),
        "_allow_unknown": True,
    },
    # === LOW-RISK: Read-only file operations ===
    "get_file_by_id": {"_allow_unknown": True},
    "list_files": {"_allow_unknown": True},
    "search_files": {"_allow_unknown": True},
    "search_files_by_filename": {"_allow_unknown": True},
    # === LOW-RISK: Read-only email operations ===
    "get_unread_emails": {"_allow_unknown": True},
    "get_sent_emails": {"_allow_unknown": True},
    "get_received_emails": {"_allow_unknown": True},
    "get_draft_emails": {"_allow_unknown": True},
    "search_emails": {"_allow_unknown": True},
    "get_email_by_id": {"_allow_unknown": True},
    "delete_email": {"_allow_unknown": True},  # User action, not exfiltration
    # === LOW-RISK: Contacts ===
    "search_contacts_by_name": {"_allow_unknown": True},
    "search_contacts_by_email": {"_allow_unknown": True},
    "get_contact_info": {"_allow_unknown": True},
    "add_contact": {"_allow_unknown": True},
    # === LOW-RISK: Calendar read operations ===
    "get_current_day": {"_allow_unknown": True},
    "get_current_time": {"_allow_unknown": True},
    "search_calendar_events": {"_allow_unknown": True},
    "get_day_calendar_events": {"_allow_unknown": True},
    "create_calendar_event": {"_allow_unknown": True},  # Creating meetings is normal
    "cancel_calendar_event": {"_allow_unknown": True},
    "reschedule_calendar_event": {"_allow_unknown": True},
    "remove_calendar_event_participants": {"_allow_unknown": True},
}


# =============================================================================
# Suite Registry
# =============================================================================
SUITE_CONSTRAINTS = {
    "banking": BANKING_CONSTRAINTS,
    "slack": SLACK_CONSTRAINTS,
    "travel": TRAVEL_CONSTRAINTS,
    "workspace": WORKSPACE_CONSTRAINTS,
}


# =============================================================================
# Risk Classification
# =============================================================================
RISK_LEVELS = {
    "banking": {
        "high": ["send_money", "schedule_transaction", "update_scheduled_transaction"],
        "medium": [
            "get_most_recent_transactions",
            "get_scheduled_transactions",
            "update_user_info",
            "update_password",
        ],
        "low": [
            "get_balance",
            "get_iban",
            "get_user_info",
            "read_file",
        ],
    },
    "slack": {
        "high": [
            "post_message",
            "send_message",
            "send_direct_message",
            "create_channel",
        ],
        "medium": ["read_messages", "get_channel_messages", "search_messages"],
        "low": ["list_channels", "get_channel_info", "get_user_info", "list_users"],
    },
    "travel": {
        "high": [
            "book_flight",
            "book_hotel",
            "book_car",
            "process_payment",
            "redeem_points",
        ],
        "medium": [
            "search_flights",
            "search_hotels",
            "search_cars",
            "modify_reservation",
        ],
        "low": [
            "cancel_flight",
            "cancel_hotel",
            "cancel_car",
            "get_flight_info",
            "get_flight_status",
            "get_hotel_info",
            "get_car_info",
            "get_reservations",
            "get_reservation_details",
            "get_user_preferences",
            "get_payment_methods",
            "get_loyalty_points",
            "get_weather",
            "get_destination_info",
            "search_attractions",
            "update_user_preferences",
            "add_payment_method",
        ],
    },
    "workspace": {
        "high": [
            "send_email",
            "reply_to_email",
            "forward_email",
            "share_file",
            "write_file",
            "delete_file",
            "create_file",
            "append_to_file",
        ],
        "medium": ["read_file", "add_calendar_event_participants"],
        "low": [
            "get_file_by_id",
            "list_files",
            "search_files",
            "search_files_by_filename",
            "get_unread_emails",
            "get_sent_emails",
            "get_received_emails",
            "get_draft_emails",
            "search_emails",
            "get_email_by_id",
            "delete_email",
            "search_contacts_by_name",
            "search_contacts_by_email",
            "get_contact_info",
            "add_contact",
            "get_current_day",
            "get_current_time",
            "search_calendar_events",
            "get_day_calendar_events",
            "create_calendar_event",
            "cancel_calendar_event",
            "reschedule_calendar_event",
            "remove_calendar_event_participants",
        ],
    },
}


# =============================================================================
# Helper Functions
# =============================================================================


def get_constraints_for_suite(suite_name: str) -> dict:
    """Get constraint set for a given suite."""
    if suite_name not in SUITE_CONSTRAINTS:
        raise ValueError(
            f"Unknown suite: {suite_name}. Available: {list(SUITE_CONSTRAINTS.keys())}"
        )
    return SUITE_CONSTRAINTS[suite_name]


def get_constraints_for_tool(suite_name: str, tool_name: str) -> dict:
    """Get constraints for a specific tool in a suite."""
    suite_constraints = get_constraints_for_suite(suite_name)
    normalized = tool_name.lower()
    if normalized not in suite_constraints:
        return {}  # Unknown tool - allow but unconstrained
    return suite_constraints[normalized]


# =============================================================================
# Delegation Narrowing Rules
# =============================================================================
# When delegating from manager to assistant, these constraints narrow the scope.
# Each rule must be a SUBSET of the corresponding manager constraint.

DELEGATION_NARROWING = {
    "workspace": {
        # Manager: recipients=Pattern("*") → Assistant: internal only
        "send_email": {
            "recipients": Pattern("*@company.internal"),  # Narrower
            "subject": Pattern("*"),
            "body": Pattern("*"),
            "_allow_unknown": True,
        },
        # Manager: path=Pattern("/data/*") → Assistant: public only
        "create_file": {
            "path": Pattern("/data/drafts/*"),  # Narrower subdirectory
            "content": Pattern("*"),
            "_allow_unknown": True,
        },
    },
    "banking": {
        # Manager: amount=Range(0,1000) → Assistant: lower limit ($100 max)
        "send_money": {
            "amount": Range(min=0, max=100),  # $100 max vs manager's $1000
            "recipient": Pattern("*"),
            "_allow_unknown": True,
        },
        "schedule_transaction": {
            "amount": Range(min=0, max=50),  # $50 max vs manager's $500
            "recipient": Pattern("*"),
            "_allow_unknown": True,
        },
    },
    "slack": {
        # Manager: AnyOf channels → Assistant: only team channels
        "post_message": {
            "channel": Pattern("#team-*"),  # Narrower than manager's AnyOf
            "_allow_unknown": True,
        },
        "send_message": {
            "channel": Pattern("#team-*"),
            "_allow_unknown": True,
        },
    },
    "travel": {
        # No narrowing defined yet for travel suite
    },
}


def get_tool_risk_level(suite_name: str, tool_name: str) -> str:
    """Get risk level for a tool: 'high', 'medium', or 'low'."""
    if suite_name not in RISK_LEVELS:
        return "unknown"
    for level in ["high", "medium", "low"]:
        if tool_name.lower() in [
            t.lower() for t in RISK_LEVELS[suite_name].get(level, [])
        ]:
            return level
    return "unknown"


def get_all_tools_for_suite(suite_name: str) -> list[str]:
    """Get list of all tools with constraints in a suite."""
    return list(get_constraints_for_suite(suite_name).keys())


def _has_real_constraints(tool_constraints: dict) -> bool:
    """Check if a constraint dict has constraints beyond _allow_unknown."""
    return any(k != "_allow_unknown" for k in tool_constraints)


def get_suite_stats() -> dict:
    """Get statistics about constraint coverage by risk level."""
    stats = {}
    for suite_name, constraints in SUITE_CONSTRAINTS.items():
        constrained = len([c for c in constraints.values() if _has_real_constraints(c)])
        total = len(constraints)
        unconstrained = total - constrained
        stats[suite_name] = {
            "total_tools": total,
            "constrained_tools": constrained,
            "unconstrained_tools": unconstrained,
            "constraint_ratio": f"{constrained}/{total} ({100 * constrained // total if total else 0}%)",
        }
    return stats


if __name__ == "__main__":
    import json

    print("AgentDojo Constraint Coverage")
    print("=" * 60)
    print(json.dumps(get_suite_stats(), indent=2))

    print("\n\nRisk Classification:")
    print("=" * 60)
    for suite, levels in RISK_LEVELS.items():
        print(f"\n{suite.upper()}:")
        for level, tools in levels.items():
            print(f"  {level.upper()}: {len(tools)} tools")
