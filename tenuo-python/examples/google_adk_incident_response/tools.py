"""
Mock tool implementations for incident response demo.

These simulate real security tools without requiring actual infrastructure.
"""

import time
from typing import Any, Dict


def read_logs(path: str) -> str:
    """
    Read log files from the filesystem.

    Simulates reading security logs and detecting suspicious patterns.

    Args:
        path: Log file path (e.g., "/var/log/access/app.log")

    Returns:
        Log content as string
    """
    # Simulate log content
    log_entries = [
        "2026-01-14 10:00:01 [INFO] User login: user@example.com from 192.168.1.100",
        "2026-01-14 10:00:15 [WARN] Failed login: admin from 203.0.113.5",
        "2026-01-14 10:00:16 [WARN] Failed login: root from 203.0.113.5",
        "2026-01-14 10:00:17 [WARN] Failed login: admin from 203.0.113.5",
        # ... repeated 124 more times
    ]

    # Simulate 127 failed logins from the same IP
    for i in range(124):
        log_entries.append(
            f"2026-01-14 10:00:{18+i:02d} [WARN] Failed login: admin from 203.0.113.5"
        )

    return "\n".join(log_entries)


def query_threat_db(query: str, table: str) -> Dict[str, Any]:
    """
    Query threat intelligence database.

    Simulates looking up IPs, domains, or indicators in a threat database.

    Args:
        query: Search query (e.g., IP address, domain)
        table: Database table to query ("threats", "users")

    Returns:
        Query results as dictionary
    """
    # Simulate threat intelligence data
    if table == "threats" and query == "203.0.113.5":
        return {
            "ip": "203.0.113.5",
            "score": 95,
            "category": "botnet",
            "first_seen": "2026-01-10T08:30:00Z",
            "last_seen": "2026-01-14T10:00:20Z",
            "signatures": ["mirai_variant_2024", "brute_force_ssh"],
            "confidence": "high"
        }
    elif table == "users":
        return {
            "user_id": query,
            "status": "active",
            "last_login": "2026-01-14T09:45:00Z"
        }
    else:
        return {"error": "not_found"}


def block_ip(ip: str, duration: int = 3600) -> Dict[str, Any]:
    """
    Block IP address at the firewall.

    Simulates adding a firewall rule to block traffic from a malicious IP.

    Args:
        ip: IP address to block
        duration: Block duration in seconds (default: 1 hour)

    Returns:
        Result dictionary with rule ID and expiration
    """
    rule_id = f"fw_rule_{int(time.time())}"
    expires_at = time.strftime("%Y-%m-%d %H:%M:%S",
                                time.localtime(time.time() + duration))

    return {
        "rule_id": rule_id,
        "ip": ip,
        "duration": duration,
        "expires_at": expires_at,
        "status": "active"
    }


def quarantine_user(user_id: str) -> Dict[str, Any]:
    """
    Quarantine a user account.

    Simulates suspending a compromised user account.

    Args:
        user_id: User identifier to quarantine

    Returns:
        Result dictionary with quarantine status
    """
    return {
        "user_id": user_id,
        "status": "quarantined",
        "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "reason": "security_incident",
        "can_appeal": True
    }
