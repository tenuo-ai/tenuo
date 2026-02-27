"""
Benchmark: Delegation Monotonicity

Demonstrates that delegated warrants cannot exceed their parent's authority -
a property that requires careful tracking in if-statement validation but is
cryptographically enforced in Tenuo.

Key insight: An orchestrator can delegate to a worker, but the worker's
capabilities are mathematically bounded by what the orchestrator has.
"""

import time

import pytest
from tenuo import SigningKey, Warrant, Pattern, Range, Exact
from tenuo import Authorizer



# ---------------------------------------------------------------------------
# Authorization helpers — require an explicit issuer_key so each test
# configures trust roots the same way production code does. No self-trust.
# ---------------------------------------------------------------------------

def _is_authorized(warrant, tool, args, sig, *, issuer_key):
    """Return True if authorized, False if denied. Uses explicit root-of-trust."""
    try:
        Authorizer(trusted_roots=[issuer_key]).authorize_one(
            warrant, tool, args,
            signature=sig if isinstance(sig, bytes) else bytes(sig)
        )
        return True
    except Exception:
        return False

def _assert_authorized(warrant, tool, args, sig, *, issuer_key):
    """Assert that authorization succeeds against an explicit trust root."""
    Authorizer(trusted_roots=[issuer_key]).authorize_one(
        warrant, tool, args,
        signature=sig if isinstance(sig, bytes) else bytes(sig)
    )

def _assert_denied(warrant, tool, args, sig, *, issuer_key):
    """Assert that authorization fails against an explicit trust root."""
    with pytest.raises(Exception):
        Authorizer(trusted_roots=[issuer_key]).authorize_one(
            warrant, tool, args,
            signature=sig if isinstance(sig, bytes) else bytes(sig)
        )


class TestDelegationMonotonicity:
    """
    Tests that prove delegation is monotonically decreasing in authority.

    This is CRITICAL for multi-agent systems where you don't want a
    compromised worker to escalate privileges.
    """

    @pytest.fixture
    def issuer_key(self):
        """The control plane that issues root warrants"""
        return SigningKey.generate()

    @pytest.fixture
    def orchestrator_key(self):
        """The orchestrator agent"""
        return SigningKey.generate()

    @pytest.fixture
    def worker_key(self):
        """A worker that receives delegated authority"""
        return SigningKey.generate()

    @pytest.fixture
    def root_warrant(self, issuer_key, orchestrator_key):
        """Orchestrator's root warrant with broad-ish permissions"""
        return (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 10000), currency=Exact("USD"))
            .capability("read_file", path=Pattern("/data/*"))
            .capability("send_email", recipient=Pattern("*@company.com"))
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

    def test_valid_narrowing_delegation(
        self, root_warrant, orchestrator_key, worker_key
    ):
        """
        Orchestrator can delegate with NARROWER constraints.

        This is the happy path: give worker less than you have.
        """
        # Delegate with tighter constraints (non-chainable API)
        # Note: must include all parent constraints or subset of them
        ab = root_warrant.attenuate_builder()
        ab.with_capability(
            "transfer",
            {"amount": Range(0, 1000), "currency": Exact("USD")},  # 1K, not 10K
        )
        ab.with_capability(
            "read_file", {"path": Pattern("/data/public/*")}
        )  # Subset of /data/*
        ab.with_holder(worker_key.public_key)
        ab.with_ttl(1800)  # 30 min, not 1 hour
        worker_warrant = ab.delegate(orchestrator_key)

        # Worker can use their limited capabilities
        # Note: must include all required fields (currency is required by zero-trust)
        sig = worker_warrant.sign(
            worker_key, "transfer", {"amount": 500, "currency": "USD"}, int(time.time())
        )
        # worker_warrant was delegated by orchestrator_key, so issuer = orchestrator_key
        _assert_authorized(worker_warrant,
            "transfer", {"amount": 500, "currency": "USD"}, bytes(sig),
            issuer_key=orchestrator_key.public_key
        )

        sig = worker_warrant.sign(
            worker_key, "transfer", {"amount": 5000, "currency": "USD"}, int(time.time())
        )
        _assert_denied(worker_warrant,
            "transfer", {"amount": 5000, "currency": "USD"}, bytes(sig),
            issuer_key=orchestrator_key.public_key
        )

    def test_cannot_escalate_amount(self, root_warrant, orchestrator_key, worker_key):
        """
        Worker cannot receive higher limits than orchestrator has.

        Attempting to delegate Range(0, 50000) when you only have Range(0, 10000)
        should fail at delegation time.
        """
        with pytest.raises(Exception):
            # This should fail - can't delegate more than you have
            ab = root_warrant.attenuate_builder()
            ab.with_capability(
                "transfer",
                {"amount": Range(0, 50000)},  # 50K > orchestrator's 10K
            )
            ab.with_holder(worker_key.public_key)
            ab.with_ttl(1800)
            ab.delegate(orchestrator_key)

    def test_cannot_add_new_capability(
        self, root_warrant, orchestrator_key, worker_key
    ):
        """
        Cannot delegate a capability the parent doesn't have.

        Orchestrator has: transfer, read_file, send_email
        Cannot delegate: delete_file (not in parent)
        """
        with pytest.raises(Exception):
            ab = root_warrant.attenuate_builder()
            ab.with_capability(
                "delete_file",
                {"path": Pattern("*")},  # Orchestrator doesn't have delete_file
            )
            ab.with_holder(worker_key.public_key)
            ab.with_ttl(1800)
            ab.delegate(orchestrator_key)

    def test_cannot_extend_ttl(self, root_warrant, orchestrator_key, worker_key):
        """
        Delegated warrant cannot live longer than parent.

        If parent expires in 1 hour, child cannot expire in 2 hours.
        """
        with pytest.raises(Exception):
            ab = root_warrant.attenuate_builder()
            ab.with_capability("transfer", {"amount": Range(0, 1000)})
            ab.with_holder(worker_key.public_key)
            ab.with_ttl(7200)  # 2 hours > parent's 1 hour
            ab.delegate(orchestrator_key)

    def test_cannot_widen_pattern(self, root_warrant, orchestrator_key, worker_key):
        """
        Cannot delegate a wider pattern than parent has.

        Parent: path=Pattern("/data/*")
        Cannot delegate: path=Pattern("/*")  (wider)
        """
        with pytest.raises(Exception):
            ab = root_warrant.attenuate_builder()
            ab.with_capability(
                "read_file", {"path": Pattern("/*")}
            )  # Wider than /data/*
            ab.with_holder(worker_key.public_key)
            ab.with_ttl(1800)
            ab.delegate(orchestrator_key)

    def test_cannot_change_exact_value(
        self, root_warrant, orchestrator_key, worker_key
    ):
        """
        If parent has Exact("USD"), child cannot change to Exact("EUR").
        """
        with pytest.raises(Exception):
            ab = root_warrant.attenuate_builder()
            ab.with_capability(
                "transfer",
                {
                    "amount": Range(0, 1000),
                    "currency": Exact("EUR"),  # Parent has USD only
                },
            )
            ab.with_holder(worker_key.public_key)
            ab.with_ttl(1800)
            ab.delegate(orchestrator_key)


class TestMultiLevelDelegation:
    """
    Tests delegation chains: Issuer -> Orchestrator -> Worker -> SubWorker

    Each level must be <= the previous level.
    """

    def test_three_level_delegation_chain(self):
        """
        Issuer gives Orchestrator $10K
        Orchestrator gives Worker $1K
        Worker gives SubWorker $100

        Each level is properly bounded.
        """
        issuer = SigningKey.generate()
        orchestrator = SigningKey.generate()
        worker = SigningKey.generate()
        subworker = SigningKey.generate()

        # Level 0: Issuer -> Orchestrator ($10K)
        orchestrator_warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 10000))
            .holder(orchestrator.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        # Level 1: Orchestrator -> Worker ($1K)
        ab1 = orchestrator_warrant.attenuate_builder()
        ab1.with_capability("transfer", {"amount": Range(0, 1000)})
        ab1.with_holder(worker.public_key)
        ab1.with_ttl(1800)
        worker_warrant = ab1.delegate(orchestrator)

        # Level 2: Worker -> SubWorker ($100)
        ab2 = worker_warrant.attenuate_builder()
        ab2.with_capability("transfer", {"amount": Range(0, 100)})
        ab2.with_holder(subworker.public_key)
        ab2.with_ttl(900)
        subworker_warrant = ab2.delegate(worker)

        # SubWorker can only do $100 max
        sig = subworker_warrant.sign(subworker, "transfer", {"amount": 50}, int(time.time()))
        # subworker_warrant was delegated by worker, so issuer = worker
        _assert_authorized(subworker_warrant, "transfer", {"amount": 50}, bytes(sig),
            issuer_key=worker.public_key
        )

        sig = subworker_warrant.sign(subworker, "transfer", {"amount": 150}, int(time.time()))
        _assert_denied(subworker_warrant, "transfer", {"amount": 150}, bytes(sig),
            issuer_key=worker.public_key
        )

    def test_chain_cannot_skip_levels(self):
        """
        SubWorker cannot try to delegate with orchestrator's limits.

        Even if subworker knows the original limits were $10K, they're
        bound by their immediate parent's $100 limit.
        """
        issuer = SigningKey.generate()
        orchestrator = SigningKey.generate()
        worker = SigningKey.generate()
        subworker = SigningKey.generate()
        evil_agent = SigningKey.generate()

        # Build the chain
        orchestrator_warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 10000))
            .holder(orchestrator.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        ab1 = orchestrator_warrant.attenuate_builder()
        ab1.with_capability("transfer", {"amount": Range(0, 1000)})
        ab1.with_holder(worker.public_key)
        ab1.with_ttl(1800)
        worker_warrant = ab1.delegate(orchestrator)

        ab2 = worker_warrant.attenuate_builder()
        ab2.with_capability("transfer", {"amount": Range(0, 100)})
        ab2.with_holder(subworker.public_key)
        ab2.with_ttl(900)
        subworker_warrant = ab2.delegate(worker)

        # SubWorker tries to delegate $5000 to evil_agent
        # This should fail - subworker only has $100
        with pytest.raises(Exception):
            ab3 = subworker_warrant.attenuate_builder()
            ab3.with_capability("transfer", {"amount": Range(0, 5000)})
            ab3.with_holder(evil_agent.public_key)
            ab3.with_ttl(300)
            ab3.delegate(subworker)


class TestDelegationWithZeroTrust:
    """
    Tests delegation behavior with zero-trust constraints.
    """

    def test_allow_unknown_not_inherited(self):
        """
        If parent has _allow_unknown=True, child does NOT automatically get it.

        This prevents a parent with permissive settings from accidentally
        granting permissive settings to children.
        """
        issuer = SigningKey.generate()
        orchestrator = SigningKey.generate()
        worker = SigningKey.generate()

        # Parent is permissive
        parent = (
            Warrant.mint_builder()
            .capability("api_call", method=Exact("GET"), _allow_unknown=True)
            .holder(orchestrator.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        # Child must explicitly opt-in to permissive mode
        # If they don't, they get zero-trust by default
        ab = parent.attenuate_builder()
        ab.with_capability("api_call", {"method": Exact("GET")})  # No _allow_unknown
        ab.with_holder(worker.public_key)
        ab.with_ttl(1800)
        child = ab.delegate(orchestrator)

        # Child with zero-trust will reject unknown fields
        sig = child.sign(worker, "api_call", {"method": "GET", "timeout": 30}, int(time.time()))
        # child was delegated by orchestrator, so issuer = orchestrator
        _assert_denied(child,
            "api_call", {"method": "GET", "timeout": 30}, bytes(sig),
            issuer_key=orchestrator.public_key
        )


class BenchmarkMetrics:
    """Collect metrics for delegation monotonicity benchmark."""

    @staticmethod
    def run_delegation_benchmark(num_attempts: int = 100) -> dict:
        """Test that all escalation attempts are blocked."""
        issuer = SigningKey.generate()
        parent_key = SigningKey.generate()
        child_key = SigningKey.generate()

        parent_warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 1000))
            .holder(parent_key.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        results = {
            "escalation_attempts": 0,
            "escalation_blocked": 0,
        }

        import random

        for _ in range(num_attempts):
            # Try to escalate by delegating higher limit
            escalated_value = random.randint(1001, 10000)
            results["escalation_attempts"] += 1

            try:
                ab = parent_warrant.attenuate_builder()
                ab.with_capability("action", {"value": Range(0, escalated_value)})
                ab.with_holder(child_key.public_key)
                ab.with_ttl(1800)
                ab.delegate(parent_key)
                # If we get here, escalation wasn't blocked (BAD)
            except Exception:
                # Escalation was blocked (GOOD)
                results["escalation_blocked"] += 1

        results["escalation_block_rate"] = (
            results["escalation_blocked"] / results["escalation_attempts"]
        )

        return results


if __name__ == "__main__":
    print("Running Delegation Monotonicity Benchmark")
    print("=" * 60)

    metrics = BenchmarkMetrics.run_delegation_benchmark(100)

    print(f"\nResults ({metrics['escalation_attempts']} escalation attempts):")
    print(f"  Escalation Block Rate: {metrics['escalation_block_rate']:.1%}")

    assert metrics["escalation_block_rate"] == 1.0

    print("\nAll escalation attempts blocked (100% enforcement)")
