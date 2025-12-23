"""
Warrant templates for AgentDojo task suites.

Defines constraint policies for different task types to demonstrate
Tenuo's capability-based authorization.

CONSTRAINT PHILOSOPHY:
- HIGH-RISK tools: Tight constraints (amounts, recipients, paths)
- MEDIUM-RISK tools: Limit-based constraints (pagination, scoping)
- LOW-RISK tools: Empty {} (safe read-only, no sensitive params)

AgentDojo Environments:
- Banking: 11 tools, 16 user tasks, 9 injection patterns
- Slack: 11 tools, 21 user tasks, 5 injection patterns  
- Travel: 28 tools, 20 user tasks, 7 injection patterns
- Workspace: 24 tools, 40 user tasks, 6 injection patterns

Total: 97 user tasks, 629 security cases
"""

from tenuo import Pattern, Exact, Range, OneOf, AnyOf, NotOneOf


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
    },
    # AgentDojo tool name: schedule_transaction
    "schedule_transaction": {
        "amount": Range(min=0, max=500),  # Lower limit for scheduled
        "recipient": Pattern("*"),
    },
    "update_scheduled_transaction": {
        "amount": Range(min=0, max=500),
    },
    
    # MEDIUM-RISK: Query operations
    "get_most_recent_transactions": {
        "n": Range(min=1, max=100),  # Prevent bulk export
    },
    "get_scheduled_transactions": {},
    
    # MEDIUM-RISK: Account modifications
    "update_user_info": {},
    "update_password": {},
    
    # LOW-RISK: Safe read-only operations
    "get_balance": {},
    "get_iban": {},
    "get_user_info": {},
    "read_file": {"path": Pattern("*")},  # File read in banking context
}


# =============================================================================
# Slack Suite (11 tools)
# Attack vectors: Data exfiltration via DMs, admin channel access, impersonation
# =============================================================================
SLACK_CONSTRAINTS = {
    # HIGH-RISK: Message sending (exfiltration vector)
    "post_message": {
        "channel": AnyOf([
            Pattern("#general"),
            Pattern("#team-*"),
            Pattern("#project-*"),
        ]),  # No admin, private, or DM channels
    },
    "send_message": {
        "channel": AnyOf([
            Pattern("#general"),
            Pattern("#team-*"),
            Pattern("#project-*"),
        ]),
    },
    "send_direct_message": {
        "recipient": Pattern("*@company.com"),  # Internal users only
    },
    
    # HIGH-RISK: Channel creation
    "create_channel": {
        "name": Pattern("team-*"),  # Only team- prefixed
        "is_private": Exact("false"),  # No private channels
    },
    
    # MEDIUM-RISK: Reading with scope limits
    "read_messages": {
        "channel": AnyOf([
            Pattern("#general"),
            Pattern("#team-*"),
        ]),
        "limit": Range(min=1, max=100),
    },
    "get_channel_messages": {
        "channel": AnyOf([
            Pattern("#general"),
            Pattern("#team-*"),
        ]),
        "limit": Range(min=1, max=100),
    },
    "search_messages": {
        "limit": Range(min=1, max=50),
    },
    
    # LOW-RISK: Directory lookups
    "list_channels": {},  # Public channel list
    "get_channel_info": {},  # Channel metadata
    "get_user_info": {},  # User profiles
    "list_users": {},  # User directory
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
    },
    "book_hotel": {
        "max_price_per_night": Range(min=0, max=150),
        "stars": Range(min=1, max=3),
    },
    "book_car": {
        "max_price_per_day": Range(min=0, max=75),
        "category": OneOf(["economy", "compact", "midsize"]),
    },
    "process_payment": {
        "amount": Range(min=0, max=2000),
    },
    "redeem_points": {
        "points": Range(min=0, max=50000),
    },
    
    # MEDIUM-RISK: Search with price caps
    "search_flights": {
        "max_price": Range(min=0, max=2000),
    },
    "search_hotels": {
        "max_price_per_night": Range(min=0, max=300),
    },
    "search_cars": {
        "max_price_per_day": Range(min=0, max=100),
    },
    
    # MEDIUM-RISK: Modifications
    "modify_reservation": {
        "change_type": OneOf(["date", "time"]),  # No class upgrades
    },
    
    # LOW-RISK: Cancellations (user-initiated, reversible)
    "cancel_flight": {},
    "cancel_hotel": {},
    "cancel_car": {},
    
    # LOW-RISK: Read-only lookups
    "get_flight_info": {},
    "get_flight_status": {},
    "get_hotel_info": {},
    "get_car_info": {},
    "get_reservations": {},
    "get_reservation_details": {},
    "get_user_preferences": {},
    "get_payment_methods": {},
    "get_loyalty_points": {},
    "get_weather": {},
    "get_destination_info": {},
    "search_attractions": {},
    
    # LOW-RISK: Preference management
    "update_user_preferences": {},
    "add_payment_method": {},
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
# =============================================================================
WORKSPACE_CONSTRAINTS = {
    # === HIGH-RISK: Outbound data (exfiltration vectors) ===
    # AgentDojo: send_email(recipients: list[str], subject, body, ...)
    "send_email": {
        "recipients": Pattern("*@company.com"),  # BLOCKS external emails like @gmail.com
    },
    "reply_to_email": {
        "recipients": Pattern("*@company.com"),
    },
    "forward_email": {
        "recipients": Pattern("*@company.com"),  # Critical: no external forwarding
    },
    # AgentDojo: share_file(file_id, email: str, permission)
    "share_file": {
        "email": Pattern("*@company.com"),  # Only internal sharing
    },
    
    # === HIGH-RISK: File write operations ===
    # AgentDojo: create_file(filename: str, content: str)
    "write_file": {
        "filename": Pattern("*"),  # Allow writes (constraint by filename if needed)
    },
    # AgentDojo: delete_file(file_id: str)
    "delete_file": {
        "file_id": NotOneOf(["13", "14", "15"]),  # Block deletion of sensitive file IDs
    },
    # AgentDojo: create_file(filename: str, content: str)
    "create_file": {
        "filename": Pattern("*"),  # Allow file creation
    },
    # AgentDojo: append_to_file(file_id: str, content: str)
    "append_to_file": {
        "file_id": Pattern("*"),  # Allow appending
    },
    
    # === MEDIUM-RISK: File reads ===
    # AgentDojo: read_file uses file_id, get_file_by_id uses file_id
    "read_file": {
        "file_id": Pattern("*"),  # Allow reads
    },
    
    # === MEDIUM-RISK: Calendar with external participants ===
    # AgentDojo: add_calendar_event_participants(event_id, participants: list[str])
    "add_calendar_event_participants": {
        "participants": Pattern("*@company.com"),  # BLOCKS external participants
    },
    
    # === LOW-RISK: Read-only file operations ===
    "get_file_by_id": {},
    "list_files": {},
    "search_files": {},
    "search_files_by_filename": {},
    
    # === LOW-RISK: Read-only email operations ===
    "get_unread_emails": {},
    "get_sent_emails": {},
    "get_received_emails": {},
    "get_draft_emails": {},
    "search_emails": {},
    "get_email_by_id": {},
    "delete_email": {},  # User action, not exfiltration
    
    # === LOW-RISK: Contacts ===
    "search_contacts_by_name": {},
    "search_contacts_by_email": {},
    "get_contact_info": {},
    "add_contact": {},
    
    # === LOW-RISK: Calendar read operations ===
    "get_current_day": {},
    "get_current_time": {},
    "search_calendar_events": {},
    "get_day_calendar_events": {},
    "create_calendar_event": {},  # Creating meetings is normal
    "cancel_calendar_event": {},
    "reschedule_calendar_event": {},
    "remove_calendar_event_participants": {},
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
        "high": ["transfer_money", "schedule_transfer", "convert_currency"],
        "medium": ["update_account_info", "get_transactions", "get_transaction_history", "search_transactions"],
        "low": ["check_balance", "get_balance", "get_account_info", "get_exchange_rate"],
    },
    "slack": {
        "high": ["post_message", "send_message", "send_direct_message", "create_channel"],
        "medium": ["read_messages", "get_channel_messages", "search_messages"],
        "low": ["list_channels", "get_channel_info", "get_user_info", "list_users"],
    },
    "travel": {
        "high": ["book_flight", "book_hotel", "book_car", "process_payment", "redeem_points"],
        "medium": ["search_flights", "search_hotels", "search_cars", "modify_reservation"],
        "low": ["cancel_flight", "cancel_hotel", "cancel_car", "get_flight_info", 
                "get_flight_status", "get_hotel_info", "get_car_info", "get_reservations",
                "get_reservation_details", "get_user_preferences", "get_payment_methods",
                "get_loyalty_points", "get_weather", "get_destination_info", 
                "search_attractions", "update_user_preferences", "add_payment_method"],
    },
    "workspace": {
        "high": ["send_email", "reply_to_email", "forward_email", "share_file",
                 "write_file", "delete_file", "create_file", "append_to_file"],
        "medium": ["read_file", "add_calendar_event_participants"],
        "low": ["get_file_by_id", "list_files", "search_files", "search_files_by_filename",
                "get_unread_emails", "get_sent_emails", "get_received_emails", 
                "get_draft_emails", "search_emails", "get_email_by_id", "delete_email",
                "search_contacts_by_name", "search_contacts_by_email", "get_contact_info",
                "add_contact", "get_current_day", "get_current_time", "search_calendar_events",
                "get_day_calendar_events", "create_calendar_event", "cancel_calendar_event",
                "reschedule_calendar_event", "remove_calendar_event_participants"],
    },
}


# =============================================================================
# Helper Functions
# =============================================================================

def get_constraints_for_suite(suite_name: str) -> dict:
    """Get constraint set for a given suite."""
    if suite_name not in SUITE_CONSTRAINTS:
        raise ValueError(
            f"Unknown suite: {suite_name}. "
            f"Available: {list(SUITE_CONSTRAINTS.keys())}"
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
        },
        # Manager: path=Pattern("/data/*") → Assistant: public only
        "create_file": {
            "path": Pattern("/data/drafts/*"),  # Narrower subdirectory
            "content": Pattern("*"),
        },
    },
    "banking": {
        # Manager: amount=Range(0,1000) → Assistant: lower limit ($100 max)
        "send_money": {
            "amount": Range(min=0, max=100),  # $100 max vs manager's $1000
            "recipient": Pattern("*"),
        },
        "schedule_transaction": {
            "amount": Range(min=0, max=50),  # $50 max vs manager's $500
            "recipient": Pattern("*"),
        },
    },
    "slack": {
        # Manager: AnyOf channels → Assistant: only team channels
        "post_message": {
            "channel": Pattern("#team-*"),  # Narrower than manager's AnyOf
        },
        "send_message": {
            "channel": Pattern("#team-*"),
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
        if tool_name.lower() in [t.lower() for t in RISK_LEVELS[suite_name].get(level, [])]:
            return level
    return "unknown"


def get_all_tools_for_suite(suite_name: str) -> list[str]:
    """Get list of all tools with constraints in a suite."""
    return list(get_constraints_for_suite(suite_name).keys())


def get_suite_stats() -> dict:
    """Get statistics about constraint coverage by risk level."""
    stats = {}
    for suite_name, constraints in SUITE_CONSTRAINTS.items():
        high_risk = len([c for c in constraints.items() if c[1]])  # Has constraints
        low_risk = len([c for c in constraints.items() if not c[1]])  # Empty {}
        total = len(constraints)
        stats[suite_name] = {
            "total_tools": total,
            "constrained_tools": high_risk,
            "unconstrained_tools": low_risk,
            "constraint_ratio": f"{high_risk}/{total} ({100*high_risk//total}%)",
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
