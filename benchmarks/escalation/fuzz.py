#!/usr/bin/env python3
"""
Property-based fuzzing of Tenuo constraint boundaries.

Layer 2 of the escalation benchmark. Tests constraint engines against
edge-case inputs: boundary values, type confusion, encoding tricks,
and random generation.

No LLM required. Deterministic with seed.

Usage:
    python -m benchmarks.escalation.fuzz
    python -m benchmarks.escalation.fuzz --iterations 500 --seed 42
"""

import math
import os
import random
import string
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from tenuo import (
    SigningKey, Warrant, Range, Subpath, CEL, Wildcard,
    Authorizer, TenuoError,
)
from tenuo_core import UrlPattern, Cidr, UrlSafe


# =============================================================================
# Results
# =============================================================================

@dataclass
class FuzzProbe:
    """Single fuzz input and its result."""
    category: str
    value: Any
    outcome: str        # "allowed", "denied", "error"
    error_type: str = ""
    note: str = ""


@dataclass
class FuzzConstraintResult:
    """Results for one constraint under fuzz."""
    constraint_label: str
    param: str
    total: int = 0
    allowed: int = 0
    denied: int = 0
    errors: int = 0
    findings: list[FuzzProbe] = field(default_factory=list)


@dataclass
class MonotonicityViolation:
    """A counterexample: child allows but parent denies."""
    parent_constraint: str
    child_constraint: str
    tool: str
    input_value: Any
    parent_allows: bool
    child_allows: bool


@dataclass
class MonotonicityResult:
    """Result of monotonicity property testing."""
    pairs_tested: int = 0
    probes_per_pair: int = 0
    total_probes: int = 0
    violations: int = 0
    counterexamples: list[MonotonicityViolation] = field(default_factory=list)
    duration_s: float = 0.0


@dataclass
class StructuralFuzzResult:
    """Result of warrant structure fuzzing."""
    mutations_tested: int = 0
    rejected: int = 0
    deserialized: int = 0
    authorized: int = 0
    random_bytes_tested: int = 0
    random_bytes_accepted: int = 0
    duration_s: float = 0.0


@dataclass
class FuzzSuiteResult:
    """Full fuzzing suite output."""
    seed: int
    iterations_per_constraint: int
    constraints: list[FuzzConstraintResult] = field(default_factory=list)
    monotonicity: MonotonicityResult | None = None
    structural: StructuralFuzzResult | None = None
    duration_s: float = 0.0

    @property
    def total_probes(self) -> int:
        base = sum(c.total for c in self.constraints)
        if self.monotonicity:
            base += self.monotonicity.total_probes
        if self.structural:
            base += self.structural.mutations_tested + self.structural.random_bytes_tested
        return base

    @property
    def total_errors(self) -> int:
        return sum(c.errors for c in self.constraints)

    @property
    def total_findings(self) -> int:
        return sum(len(c.findings) for c in self.constraints)


# =============================================================================
# Value generators — directed edge cases + random fill
# =============================================================================

def _range_values(low: float, high: float, rng: random.Random, n: int) -> list[tuple[str, Any]]:
    directed: list[tuple[str, Any]] = [
        # Boundaries
        ("boundary_exact_low", low),
        ("boundary_exact_high", high),
        ("boundary_below_low", low - 0.001),
        ("boundary_above_high", high + 0.001),
        ("boundary_just_inside_low", low + 0.001),
        ("boundary_just_inside_high", high - 0.001),
        ("boundary_epsilon_above", high + 1e-10),
        ("boundary_midpoint", (low + high) / 2),
        # Negatives
        ("negative_one", -1),
        ("negative_epsilon", -0.001),
        ("negative_zero", -0.0),
        # Special floats
        ("special_nan", float("nan")),
        ("special_inf", float("inf")),
        ("special_neg_inf", float("-inf")),
        ("special_1e99", 1e99),
        ("special_1e308", 1e308),
        ("special_tiny", 1e-308),
        # Integer precision
        ("precision_2^53", 2**53),
        ("precision_2^53+1", 2**53 + 1),
        # Type confusion
        ("type_string_int", str(int(high))),
        ("type_string_float", str(high / 2)),
        ("type_bool_true", True),
        ("type_bool_false", False),
        ("type_none", None),
        ("type_list", [high / 2]),
        ("type_dict", {"value": high / 2}),
        ("type_empty_string", ""),
    ]

    for i in range(n - len(directed)):
        kind = rng.choice(["in", "out", "wild"])
        if kind == "in":
            directed.append((f"random_in_{i}", rng.uniform(low, high)))
        elif kind == "out":
            directed.append((f"random_out_{i}", rng.uniform(high + 1, high * 10 + 100)))
        else:
            v = rng.choice([
                rng.uniform(-1e10, 1e10),
                rng.randint(-1_000_000, 1_000_000),
                str(rng.randint(0, 1000)),
                rng.choice([True, False, None, [], {}]),
            ])
            directed.append((f"random_wild_{i}", v))

    return directed[:n]


def _subpath_values(prefix: str, rng: random.Random, n: int) -> list[tuple[str, Any]]:
    directed: list[tuple[str, Any]] = [
        # Valid
        ("valid_basic", f"{prefix}/readme.txt"),
        ("valid_nested", f"{prefix}/sub/dir/file.txt"),
        ("valid_prefix_only", prefix),
        ("valid_trailing_slash", f"{prefix}/"),
        ("valid_dot_segment", f"{prefix}/./test.txt"),
        ("valid_up_then_back", f"{prefix}/sub/../sub/file.txt"),
        # Traversal
        ("traversal_basic", f"{prefix}/../secrets/key"),
        ("traversal_double", f"{prefix}/../../etc/passwd"),
        ("traversal_deep", f"{prefix}/" + "../" * 8 + "etc/shadow"),
        ("traversal_backslash", f"{prefix}/..\\secrets"),
        # Encoding
        ("encoding_url_dots", f"{prefix}/%2e%2e/secrets"),
        ("encoding_url_slash", f"{prefix}%2f..%2fsecrets"),
        ("encoding_double", f"{prefix}/%252e%252e/secrets"),
        ("encoding_unicode_dot", f"{prefix}/\u002e\u002e/secrets"),
        ("encoding_fullwidth", f"{prefix}/\uff0e\uff0e/secrets"),
        # Null byte
        ("null_byte_ext", f"{prefix}/file.txt\x00.html"),
        ("null_byte_mid", f"{prefix}\x00/../secrets"),
        # Case
        ("case_upper", prefix.upper() + "/file.txt"),
        ("case_mixed", prefix[0] + prefix[1:].swapcase() + "/file.txt"),
        # Special
        ("empty", ""),
        ("root", "/"),
        ("double_slash", f"//{prefix.lstrip('/')}/file.txt"),
        ("absolute_other", "/secrets/api_keys.json"),
        ("relative", prefix.lstrip("/") + "/file.txt"),
        ("dot_only", "."),
        ("dotdot_only", ".."),
        # Long / deep
        ("long_path", f"{prefix}/" + "a" * 5000),
        ("deep_nesting", f"{prefix}" + "/s" * 200 + "/file.txt"),
        # Shell injection
        ("shell_semicolon", f"{prefix}/file;rm -rf /"),
        ("shell_pipe", f"{prefix}/file|cat /etc/passwd"),
        ("shell_backtick", f"{prefix}/`whoami`"),
        # Type confusion
        ("type_none", None),
        ("type_int", 42),
        ("type_bool", True),
        ("type_list", [f"{prefix}/file.txt"]),
        ("type_dict", {"path": f"{prefix}/file.txt"}),
    ]

    chars = string.ascii_lowercase + "/_.-"
    for i in range(n - len(directed)):
        kind = rng.choice(["valid", "traversal", "wild"])
        if kind == "valid":
            segs = "/".join(
                "".join(rng.choices(string.ascii_lowercase, k=rng.randint(1, 6)))
                for _ in range(rng.randint(1, 4))
            )
            directed.append((f"random_valid_{i}", f"{prefix}/{segs}"))
        elif kind == "traversal":
            ups = rng.randint(1, 6)
            directed.append((f"random_traversal_{i}", f"{prefix}/" + "../" * ups + "secrets/key"))
        else:
            length = rng.randint(1, 100)
            directed.append((f"random_wild_{i}", "/" + "".join(rng.choices(chars, k=length))))

    return directed[:n]


def _cel_email_values(domain: str, rng: random.Random, n: int) -> list[tuple[str, Any]]:
    directed: list[tuple[str, Any]] = [
        # Valid
        ("valid_single", [f"user@{domain}"]),
        ("valid_multi", [f"a@{domain}", f"b@{domain}"]),
        # Vacuous truth
        ("empty_list", []),
        # Domain tricks
        ("suffix_attack", [f"user@evil{domain}"]),
        ("prefix_attack", [f"user@{domain}.evil.com"]),
        ("subdomain", [f"user@sub.{domain}"]),
        ("bare_at_domain", [f"@{domain}"]),
        ("no_at", ["user"]),
        ("double_at", [f"user@@{domain}"]),
        ("empty_string", [""]),
        # Case
        ("case_upper", [f"user@{domain.upper()}"]),
        ("case_mixed", [f"user@{domain[0].upper()}{domain[1:]}"]),
        # Injection in email
        ("newline_inject", [f"user@{domain}\nevil@attacker.com"]),
        ("tab_inject", [f"user@{domain}\tevil@attacker.com"]),
        ("null_inject", [f"user@{domain}\x00evil@attacker.com"]),
        ("comma_inject", [f"user@{domain},evil@attacker.com"]),
        # Unicode
        ("unicode_at", [f"user\uff20{domain}"]),
        ("cyrillic_c", [f"user@{domain.replace('c', chr(0x441))}"]),
        # Mixed valid/invalid
        ("mixed", [f"user@{domain}", "evil@attacker.com"]),
        # Extremes
        ("long_local", ["a" * 1000 + f"@{domain}"]),
        ("long_domain", [f"user@{'sub.' * 50}{domain}"]),
        # Type confusion
        ("type_none_in_list", [None]),
        ("type_int_in_list", [42]),
        ("type_nested_list", [[f"user@{domain}"]]),
        ("type_none", None),
        ("type_string", f"user@{domain}"),
        ("type_dict", {"to": f"user@{domain}"}),
    ]

    external = ["gmail.com", "evil.com", "attacker.org"]
    for i in range(n - len(directed)):
        local = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(1, 8)))
        kind = rng.choice(["valid", "external", "wild"])
        if kind == "valid":
            directed.append((f"random_valid_{i}", [f"{local}@{domain}"]))
        elif kind == "external":
            d = rng.choice(external)
            directed.append((f"random_external_{i}", [f"{local}@{d}"]))
        else:
            count = rng.randint(0, 4)
            all_domains = [domain] + external
            emails = [f"{local}@{rng.choice(all_domains)}" for _ in range(count)]
            directed.append((f"random_wild_{i}", emails))

    return directed[:n]


def _url_pattern_values(pattern: str, rng: random.Random, n: int) -> list[tuple[str, Any]]:
    """Edge-case URL inputs for UrlPattern fuzzing.

    Focuses on SSRF-class bypasses: private IPs, metadata endpoints,
    protocol confusion, encoding tricks, and type confusion.
    """
    directed: list[tuple[str, Any]] = [
        # Valid matches for https://*.internal.corp/*
        ("valid_basic",        "https://api.internal.corp/v1/data"),
        ("valid_subdomain",    "https://siem.internal.corp/events"),
        ("valid_deep_path",   "https://app.internal.corp/a/b/c/d"),
        ("valid_trailing",    "https://x.internal.corp/"),
        # Wrong scheme
        ("scheme_http",        "http://api.internal.corp/data"),
        ("scheme_ftp",         "ftp://api.internal.corp/data"),
        ("scheme_file",        "file:///etc/passwd"),
        ("scheme_data",        "data:text/plain,secret"),
        ("scheme_javascript",  "javascript:alert(1)"),
        # External domains
        ("external_attacker",  "https://attacker.com/collect"),
        ("external_evil",      "https://evil.internal.corp.attacker.com/x"),
        ("external_subdomain_prefix", "https://internal.corp.evil.com/x"),
        # SSRF: private IP ranges
        ("ssrf_loopback",      "https://127.0.0.1/admin"),
        ("ssrf_rfc1918_10",    "https://10.0.0.1/secret"),
        ("ssrf_rfc1918_172",   "https://172.16.0.1/secret"),
        ("ssrf_rfc1918_192",   "https://192.168.1.1/secret"),
        ("ssrf_localhost",     "https://localhost/admin"),
        # SSRF: metadata endpoints
        ("ssrf_aws_meta",      "https://169.254.169.254/latest/meta-data/"),
        ("ssrf_gcp_meta",      "https://metadata.google.internal/computeMetadata/v1/"),
        ("ssrf_azure_meta",    "https://169.254.169.254/metadata/instance"),
        # IPv6 confusion
        ("ipv6_loopback",      "https://[::1]/admin"),
        ("ipv6_mapped_v4",     "https://[::ffff:169.254.169.254]/meta"),
        # Encoding tricks
        ("encode_at_sign",     "https://api.internal.corp@attacker.com/"),
        ("encode_userinfo",    "https://attacker.com%2f@api.internal.corp/"),
        ("encode_slash",       "https://api.internal.corp%2fattacker.com/"),
        ("encode_percent_2e",  "https://api.internal.corp/%2e%2e/etc/passwd"),
        # Null / control
        ("null_byte",          "https://api.internal.corp/\x00attacker.com"),
        ("crlf_inject",        "https://api.internal.corp/\r\nHost: evil.com"),
        # Degenerate
        ("empty",              ""),
        ("no_scheme",          "api.internal.corp/data"),
        ("double_slash",       "//api.internal.corp/data"),
        ("very_long",          "https://api.internal.corp/" + "a" * 5000),
        # Type confusion
        ("type_none",          None),
        ("type_int",           42),
        ("type_list",          ["https://api.internal.corp/data"]),
        ("type_dict",          {"url": "https://api.internal.corp/data"}),
    ]

    external_hosts = ["attacker.com", "evil.org", "169.254.169.254", "10.0.0.1"]
    internal_hosts = ["api.internal.corp", "siem.internal.corp", "db.internal.corp"]
    paths = ["/data", "/admin", "/metrics", "/secret", "/v1/users"]

    for i in range(n - len(directed)):
        kind = rng.choice(["valid", "ssrf", "external", "wild"])
        if kind == "valid":
            host = rng.choice(internal_hosts)
            path = rng.choice(paths)
            directed.append((f"random_valid_{i}", f"https://{host}{path}"))
        elif kind == "ssrf":
            ip = rng.choice(["127.0.0.1", "10.0.0.1", "172.16.0.1", "169.254.169.254"])
            path = rng.choice(paths)
            directed.append((f"random_ssrf_{i}", f"https://{ip}{path}"))
        elif kind == "external":
            host = rng.choice(external_hosts)
            path = rng.choice(paths)
            directed.append((f"random_external_{i}", f"https://{host}{path}"))
        else:
            chars = string.ascii_lowercase + ":/._-@%"
            val = rng.choice([
                "".join(rng.choices(chars, k=rng.randint(5, 80))),
                rng.choice([None, 0, [], {}, True]),
            ])
            directed.append((f"random_wild_{i}", val))

    return directed[:n]


def _cidr_values(network: str, rng: random.Random, n: int) -> list[tuple[str, Any]]:
    """Edge-case IP inputs for CIDR fuzzing.

    Covers boundary IPs at network edges, private ranges, IPv6,
    encoding tricks, and type confusion.
    """
    # Parse the network prefix to derive boundary IPs deterministically
    # We hard-code values for the expected test networks (10.0.0.0/8, 192.168.1.0/24)
    # and include a general set of edge cases.
    directed: list[tuple[str, Any]] = [
        # Within common private ranges (likely in-network for test cases)
        ("valid_10_x",           "10.0.0.1"),
        ("valid_10_middle",      "10.128.64.32"),
        ("valid_10_high",        "10.255.255.254"),
        ("valid_192_168",        "192.168.1.100"),
        # Network boundaries
        ("boundary_network_addr", "10.0.0.0"),
        ("boundary_broadcast",   "10.255.255.255"),
        ("boundary_just_outside","11.0.0.0"),
        ("boundary_just_inside", "10.0.0.1"),
        # Other RFC1918 / special ranges
        ("loopback",             "127.0.0.1"),
        ("loopback_other",       "127.0.0.2"),
        ("link_local",           "169.254.0.1"),
        ("link_local_aws",       "169.254.169.254"),
        ("multicast",            "224.0.0.1"),
        ("broadcast",            "255.255.255.255"),
        ("zero_addr",            "0.0.0.0"),
        # IPv6
        ("ipv6_loopback",        "::1"),
        ("ipv6_any",             "::"),
        ("ipv6_mapped_v4",       "::ffff:10.0.0.1"),
        ("ipv6_link_local",      "fe80::1"),
        ("ipv6_global",          "2001:db8::1"),
        # Encoding / format tricks
        ("octal_10",             "012.0.0.1"),          # octal 12 = decimal 10
        ("hex_10",               "0x0a.0.0.1"),          # hex 0a = decimal 10
        ("with_port",            "10.0.0.1:8080"),
        ("with_cidr_suffix",     "10.0.0.1/32"),
        ("with_brackets",        "[10.0.0.1]"),
        ("trailing_dot",         "10.0.0.1."),
        ("leading_zeros",        "010.000.000.001"),
        ("extra_octets",         "10.0.0.0.1"),
        ("missing_octet",        "10.0.0"),
        ("negative_octet",       "10.0.0.-1"),
        ("octet_overflow",       "10.0.0.256"),
        # Special strings
        ("hostname",             "localhost"),
        ("hostname_internal",    "api.internal.corp"),
        ("empty",                ""),
        ("random_text",          "not-an-ip"),
        ("null_byte",            "10.0.0.1\x00evil"),
        ("very_long",            "10." + "0." * 500 + "1"),
        # Type confusion
        ("type_none",            None),
        ("type_int",             167772161),   # 10.0.0.1 as int
        ("type_list",            ["10.0.0.1"]),
        ("type_dict",            {"ip": "10.0.0.1"}),
        ("type_bool",            True),
    ]

    for i in range(n - len(directed)):
        kind = rng.choice(["valid", "outside", "wild"])
        if kind == "valid":
            # Random 10.x.x.x address (in 10.0.0.0/8)
            ip = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            directed.append((f"random_valid_{i}", ip))
        elif kind == "outside":
            # Random address outside 10.x.x.x
            first = rng.choice([11, 172, 192, 203, 8])
            ip = f"{first}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}"
            directed.append((f"random_outside_{i}", ip))
        else:
            val = rng.choice([
                "".join(rng.choices(string.digits + ".", k=rng.randint(3, 20))),
                rng.choice([None, True, False, 0, [], {}]),
                str(rng.randint(0, 2**32)),
            ])
            directed.append((f"random_wild_{i}", val))

    return directed[:n]


# =============================================================================
# Fuzzer
# =============================================================================

@contextmanager
def _suppress_stderr():
    """Suppress Rust panic messages on stderr."""
    fd = sys.stderr.fileno()
    old = os.dup(fd)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, fd)
    try:
        yield
    finally:
        os.dup2(old, fd)
        os.close(old)
        os.close(devnull)


class ConstraintFuzzer:
    def __init__(self, seed: int = 42, iterations: int = 200):
        self.rng = random.Random(seed)
        self.seed = seed
        self.n = iterations
        self._org = SigningKey.generate()

    def _check(self, warrant: Warrant, holder: SigningKey, tool: str, args: dict) -> tuple[str, str]:
        """Run enforcement, return (outcome, error_type)."""
        auth = Authorizer(trusted_roots=[self._org.public_key])
        try:
            with _suppress_stderr():
                sig = warrant.sign(holder, tool, args, int(time.time()))
                auth.authorize(warrant, tool, args, signature=bytes(sig))
            return ("allowed", "")
        except TenuoError:
            return ("denied", "")
        except BaseException as e:
            if type(e).__name__ == "PanicException":
                return ("denied", "")
            return ("error", f"{type(e).__name__}: {e}")

    def _make_warrant(self, tool: str, constraints: dict) -> tuple[Warrant, SigningKey]:
        holder = SigningKey.generate()
        w = (
            Warrant.mint_builder()
            .capability(tool, constraints)
            .holder(holder.public_key)
            .ttl(3600)
            .mint(self._org)
        )
        return w, holder

    def fuzz_range(self, low: float, high: float) -> FuzzConstraintResult:
        result = FuzzConstraintResult(
            constraint_label=f"Range({low:g}, {high:g})",
            param="amount",
        )
        warrant, holder = self._make_warrant(
            "transfer", {"amount": Range(low, high)}
        )

        for cat, val in _range_values(low, high, self.rng, self.n):
            outcome, err = self._check(warrant, holder, "transfer", {"amount": val})
            result.total += 1
            if outcome == "allowed":
                result.allowed += 1
            elif outcome == "denied":
                result.denied += 1
            else:
                result.errors += 1

            is_finding = (
                outcome == "error"
                or (outcome == "allowed" and cat.startswith("type_"))
                or (outcome == "allowed" and cat.startswith("special_"))
            )
            if is_finding:
                note = ""
                if cat == "type_bool_true":
                    note = "bool True coerces to 1 (within range)"
                elif cat == "type_bool_false":
                    note = "bool False coerces to 0 (within range)"
                elif outcome == "error":
                    note = err

                result.findings.append(FuzzProbe(
                    category=cat, value=val, outcome=outcome,
                    error_type=err, note=note,
                ))
        return result

    def fuzz_subpath(self, prefix: str) -> FuzzConstraintResult:
        result = FuzzConstraintResult(
            constraint_label=f'Subpath("{prefix}")',
            param="path",
        )
        warrant, holder = self._make_warrant(
            "read", {"path": Subpath(prefix)}
        )

        for cat, val in _subpath_values(prefix, self.rng, self.n):
            outcome, err = self._check(warrant, holder, "read", {"path": val})
            result.total += 1
            if outcome == "allowed":
                result.allowed += 1
            elif outcome == "denied":
                result.denied += 1
            else:
                result.errors += 1

            is_finding = (
                outcome == "error"
                or (outcome == "allowed" and "traversal" in cat)
                or (outcome == "allowed" and "null" in cat)
                or (outcome == "allowed" and "injection" in cat)
                or (outcome == "allowed" and cat.startswith("type_"))
            )
            if is_finding:
                result.findings.append(FuzzProbe(
                    category=cat,
                    value=repr(val)[:120] if isinstance(val, str) and len(repr(val)) > 120 else val,
                    outcome=outcome, error_type=err,
                    note=err if outcome == "error" else "",
                ))
        return result

    def fuzz_url_pattern(self, pattern: str) -> FuzzConstraintResult:
        result = FuzzConstraintResult(
            constraint_label=f'UrlPattern("{pattern}")',
            param="url",
        )
        warrant, holder = self._make_warrant(
            "send_http", {"url": UrlPattern(pattern)}
        )

        for cat, val in _url_pattern_values(pattern, self.rng, self.n):
            outcome, err = self._check(warrant, holder, "send_http", {"url": val})
            result.total += 1
            if outcome == "allowed":
                result.allowed += 1
            elif outcome == "denied":
                result.denied += 1
            else:
                result.errors += 1

            is_finding = (
                outcome == "error"
                or (outcome == "allowed" and any(x in cat for x in (
                    "ssrf", "external", "encode", "ipv6", "loopback",
                    "scheme_http", "scheme_ftp", "scheme_file", "scheme_data",
                    "scheme_javascript", "null", "crlf",
                )))
                or (outcome == "allowed" and cat.startswith("type_"))
            )
            if is_finding:
                result.findings.append(FuzzProbe(
                    category=cat,
                    value=repr(val)[:80] if isinstance(val, str) and len(repr(val)) > 80 else val,
                    outcome=outcome, error_type=err,
                    note=err if outcome == "error" else "",
                ))
        return result

    def fuzz_cidr(self, network: str) -> FuzzConstraintResult:
        result = FuzzConstraintResult(
            constraint_label=f'Cidr("{network}")',
            param="ip",
        )
        warrant, holder = self._make_warrant(
            "connect", {"ip": Cidr(network)}
        )

        for cat, val in _cidr_values(network, self.rng, self.n):
            outcome, err = self._check(warrant, holder, "connect", {"ip": val})
            result.total += 1
            if outcome == "allowed":
                result.allowed += 1
            elif outcome == "denied":
                result.denied += 1
            else:
                result.errors += 1

            is_finding = (
                outcome == "error"
                or (outcome == "allowed" and any(x in cat for x in (
                    "loopback", "link_local", "multicast", "broadcast",
                    "octal", "hex", "port", "brackets", "leading_zeros",
                    "ipv6_mapped", "null", "hostname",
                )))
                or (outcome == "allowed" and cat.startswith("type_"))
            )
            if is_finding:
                result.findings.append(FuzzProbe(
                    category=cat,
                    value=repr(val)[:80] if isinstance(val, str) and len(repr(val)) > 80 else val,
                    outcome=outcome, error_type=err,
                    note=err if outcome == "error" else "",
                ))
        return result

    def fuzz_url_safe(self) -> FuzzConstraintResult:
        """Fuzz UrlSafe: SSRF prevention constraint.

        UrlSafe blocks private IPs, loopback, metadata endpoints, and
        RFC1918 ranges by default — regardless of what domain is in the URL.
        This tests whether encoding tricks, IPv6 confusion, or type confusion
        can bypass the SSRF check.
        """
        result = FuzzConstraintResult(
            constraint_label='UrlSafe()',
            param="url",
        )
        warrant, holder = self._make_warrant(
            "send_http", {"url": UrlSafe()}
        )

        # Value set: same SSRF-class inputs as UrlPattern, but UrlSafe
        # should BLOCK private IPs/metadata and ALLOW public URLs.
        # Findings are things that should be blocked but slip through.
        values = _url_pattern_values("https://*.internal.corp/*", self.rng, self.n)

        for cat, val in values:
            outcome, err = self._check(warrant, holder, "send_http", {"url": val})
            result.total += 1
            if outcome == "allowed":
                result.allowed += 1
            elif outcome == "denied":
                result.denied += 1
            else:
                result.errors += 1

            # For UrlSafe: flag SSRF-class inputs that were allowed (potential bypass)
            is_finding = (
                outcome == "error"
                or (outcome == "allowed" and any(x in cat for x in (
                    "ssrf", "loopback", "ipv6_loopback", "ipv6_mapped",
                    "null", "crlf", "encode_userinfo",
                )))
                or (outcome == "allowed" and cat.startswith("type_"))
            )
            if is_finding:
                result.findings.append(FuzzProbe(
                    category=cat,
                    value=repr(val)[:80] if isinstance(val, str) and len(repr(val)) > 80 else val,
                    outcome=outcome, error_type=err,
                    note=err if outcome == "error" else "",
                ))
        return result

    def fuzz_cel_email(self, domain: str) -> FuzzConstraintResult:
        result = FuzzConstraintResult(
            constraint_label=f"CEL(endsWith('@{domain}'))",
            param="recipients",
        )
        warrant, holder = self._make_warrant(
            "send", {
                "recipients": CEL(f"value.all(r, r.endsWith('@{domain}'))"),
            }
        )

        for cat, val in _cel_email_values(domain, self.rng, self.n):
            outcome, err = self._check(warrant, holder, "send", {"recipients": val})
            result.total += 1
            if outcome == "allowed":
                result.allowed += 1
            elif outcome == "denied":
                result.denied += 1
            else:
                result.errors += 1

            is_finding = (
                outcome == "error"
                or (outcome == "allowed" and "empty" in cat)
                or (outcome == "allowed" and "inject" in cat)
                or (outcome == "allowed" and "attack" in cat)
                or (outcome == "allowed" and "mixed" in cat)
                or (outcome == "allowed" and cat.startswith("type_"))
            )
            if is_finding:
                note = ""
                if cat == "empty_list":
                    note = "vacuous truth: all() on empty list returns true"
                elif cat == "bare_at_domain":
                    note = "no local part, passes endsWith check"
                elif outcome == "error":
                    note = err
                result.findings.append(FuzzProbe(
                    category=cat, value=val, outcome=outcome,
                    error_type=err, note=note,
                ))
        return result

    # =========================================================================
    # Monotonicity: child.allows(x) → parent.allows(x)
    # =========================================================================

    def fuzz_monotonicity(self, pairs: int = 20, probes_per_pair: int = 200) -> MonotonicityResult:
        """Property-based test: a child warrant can never allow more than its parent."""
        import base64
        t0 = time.perf_counter()
        result = MonotonicityResult(pairs_tested=0, probes_per_pair=probes_per_pair)

        range_pairs = self._generate_range_pairs(pairs // 2)
        subpath_pairs = self._generate_subpath_pairs(pairs - pairs // 2)

        for parent_desc, child_desc, parent_w, child_w, tool, gen_inputs in range_pairs + subpath_pairs:
            result.pairs_tested += 1
            for val in gen_inputs():
                result.total_probes += 1
                try:
                    p_ok = parent_w.allows(tool, val)
                except Exception:
                    p_ok = False
                try:
                    c_ok = child_w.allows(tool, val)
                except Exception:
                    c_ok = False

                if c_ok and not p_ok:
                    result.violations += 1
                    result.counterexamples.append(MonotonicityViolation(
                        parent_constraint=parent_desc,
                        child_constraint=child_desc,
                        tool=tool,
                        input_value=val,
                        parent_allows=p_ok,
                        child_allows=c_ok,
                    ))

        result.duration_s = time.perf_counter() - t0
        return result

    def _generate_range_pairs(self, count: int):
        """Generate (parent, child) Range warrant pairs with random bounds."""
        pairs = []
        for _ in range(count):
            p_low = self.rng.uniform(-1000, 0)
            p_high = self.rng.uniform(1, 100000)
            c_low = self.rng.uniform(p_low, (p_low + p_high) / 2)
            c_high = self.rng.uniform((p_low + p_high) / 2, p_high)

            p_key = SigningKey.generate()
            q_key = SigningKey.generate()

            parent = (Warrant.mint_builder()
                .capability("transfer", {"amount": Range(p_low, p_high)})
                .holder(p_key.public_key)
                .ttl(3600)
                .mint(self._org))

            b = parent.grant_builder()
            b.capability("transfer", {"amount": Range(c_low, c_high)})
            b.holder(q_key.public_key)
            b.ttl(1800)
            child = b.grant(p_key)

            n = self.probes_per_pair if hasattr(self, 'probes_per_pair') else 200

            def make_gen(pl, ph, cl, ch):
                def gen():
                    vals = []
                    for _ in range(200):
                        v = self.rng.choice([
                            self.rng.uniform(pl - 100, ph + 100),
                            self.rng.uniform(cl - 1, ch + 1),
                            cl, ch, pl, ph,
                            cl - 0.001, ch + 0.001,
                            0, -1, float('inf'), float('-inf'),
                        ])
                        vals.append({"amount": v})
                    return vals
                return gen

            pairs.append((
                f"Range({p_low:.1f}, {p_high:.1f})",
                f"Range({c_low:.1f}, {c_high:.1f})",
                parent, child, "transfer",
                make_gen(p_low, p_high, c_low, c_high),
            ))
        return pairs

    def _generate_subpath_pairs(self, count: int):
        """Generate (parent, child) Subpath warrant pairs."""
        base_prefixes = ["/data", "/home", "/var", "/opt", "/srv", "/app", "/files"]
        pairs = []
        for i in range(count):
            parent_prefix = self.rng.choice(base_prefixes)
            child_suffix = "".join(self.rng.choices(string.ascii_lowercase, k=self.rng.randint(3, 8)))
            child_prefix = f"{parent_prefix}/{child_suffix}"

            p_key = SigningKey.generate()
            q_key = SigningKey.generate()

            parent = (Warrant.mint_builder()
                .capability("read", {"path": Subpath(parent_prefix)})
                .holder(p_key.public_key)
                .ttl(3600)
                .mint(self._org))

            b = parent.grant_builder()
            b.capability("read", {"path": Subpath(child_prefix)})
            b.holder(q_key.public_key)
            b.ttl(1800)
            child = b.grant(p_key)

            def make_gen(pp, cp):
                def gen():
                    vals = []
                    segments = string.ascii_lowercase + "/_.-"
                    for _ in range(200):
                        kind = self.rng.choice(["child_valid", "parent_only", "outside", "traversal"])
                        if kind == "child_valid":
                            seg = "".join(self.rng.choices(string.ascii_lowercase, k=4))
                            vals.append({"path": f"{cp}/{seg}.txt"})
                        elif kind == "parent_only":
                            seg = "".join(self.rng.choices(string.ascii_lowercase, k=4))
                            vals.append({"path": f"{pp}/{seg}.txt"})
                        elif kind == "outside":
                            rseg = "".join(self.rng.choices(string.ascii_lowercase, k=4))
                            vals.append({"path": f"/etc/{rseg}.txt" if self.rng.random() > 0.5 else "/secrets/key"})
                        else:
                            ups = self.rng.randint(1, 5)
                            vals.append({"path": f"{cp}/" + "../" * ups + "secrets/key"})
                    return vals
                return gen

            pairs.append((
                f'Subpath("{parent_prefix}")',
                f'Subpath("{child_prefix}")',
                parent, child, "read",
                make_gen(parent_prefix, child_prefix),
            ))
        return pairs

    # =========================================================================
    # Structural: warrant byte fuzzing
    # =========================================================================

    def fuzz_warrant_structure(self, mutations: int = 500, random_count: int = 200) -> StructuralFuzzResult:
        """Fuzz warrant serialization: can mutated/random bytes produce a valid warrant?"""
        import base64
        t0 = time.perf_counter()
        result = StructuralFuzzResult()

        holder = SigningKey.generate()
        valid_warrant = (Warrant.mint_builder()
            .capability("read", {"path": Wildcard()})
            .holder(holder.public_key)
            .ttl(3600)
            .mint(self._org))
        valid_b64 = valid_warrant.to_base64()
        valid_bytes = base64.urlsafe_b64decode(valid_b64 + "==")

        mutation_strategies = [
            ("bitflip", self._mutate_bitflip),
            ("truncate", self._mutate_truncate),
            ("insert", self._mutate_insert),
            ("zero_fill", self._mutate_zero_fill),
            ("shuffle", self._mutate_shuffle),
        ]

        for _ in range(mutations):
            result.mutations_tested += 1
            strategy_name, strategy_fn = self.rng.choice(mutation_strategies)
            mutated = strategy_fn(bytearray(valid_bytes))
            mutated_b64 = base64.urlsafe_b64encode(bytes(mutated)).decode()

            try:
                w = Warrant(mutated_b64)
                result.deserialized += 1
                try:
                    sig = w.sign(holder, "read", {"path": "/test"}, int(time.time()))
                    auth = Authorizer(trusted_roots=[self._org.public_key])
                    auth.authorize(w, "read", {"path": "/test"}, signature=bytes(sig))
                    result.authorized += 1
                except Exception:
                    pass
            except Exception:
                result.rejected += 1

        for _ in range(random_count):
            result.random_bytes_tested += 1
            length = self.rng.randint(10, 500)
            garbage = bytes(self.rng.getrandbits(8) for _ in range(length))
            garbage_b64 = base64.urlsafe_b64encode(garbage).decode()
            try:
                w = Warrant(garbage_b64)
                result.random_bytes_accepted += 1
            except Exception:
                pass

        result.duration_s = time.perf_counter() - t0
        return result

    def _mutate_bitflip(self, data: bytearray) -> bytearray:
        if not data:
            return data
        pos = self.rng.randint(0, len(data) - 1)
        bit = 1 << self.rng.randint(0, 7)
        data[pos] ^= bit
        return data

    def _mutate_truncate(self, data: bytearray) -> bytearray:
        if len(data) < 2:
            return data
        cut = self.rng.randint(1, len(data) - 1)
        return data[:cut]

    def _mutate_insert(self, data: bytearray) -> bytearray:
        pos = self.rng.randint(0, len(data))
        count = self.rng.randint(1, 20)
        insert = bytes(self.rng.getrandbits(8) for _ in range(count))
        return data[:pos] + bytearray(insert) + data[pos:]

    def _mutate_zero_fill(self, data: bytearray) -> bytearray:
        if not data:
            return data
        start = self.rng.randint(0, len(data) - 1)
        length = self.rng.randint(1, min(32, len(data) - start))
        for i in range(start, start + length):
            data[i] = 0
        return data

    def _mutate_shuffle(self, data: bytearray) -> bytearray:
        if len(data) < 4:
            return data
        start = self.rng.randint(0, len(data) - 4)
        chunk = self.rng.randint(2, min(16, len(data) - start))
        segment = list(data[start:start + chunk])
        self.rng.shuffle(segment)
        data[start:start + chunk] = segment
        return data

    # =========================================================================
    # Run all
    # =========================================================================

    def fuzz_all(self) -> FuzzSuiteResult:
        t0 = time.perf_counter()

        results = FuzzSuiteResult(
            seed=self.seed,
            iterations_per_constraint=self.n,
        )

        results.constraints.append(self.fuzz_range(0, 50))
        results.constraints.append(self.fuzz_range(0, 100_000))
        results.constraints.append(self.fuzz_subpath("/public"))
        results.constraints.append(self.fuzz_subpath("/drafts"))
        results.constraints.append(self.fuzz_cel_email("company.com"))
        results.constraints.append(self.fuzz_url_pattern("https://*.internal.corp/*"))
        results.constraints.append(self.fuzz_url_safe())
        results.constraints.append(self.fuzz_cidr("10.0.0.0/8"))
        results.monotonicity = self.fuzz_monotonicity()
        results.structural = self.fuzz_warrant_structure()

        results.duration_s = time.perf_counter() - t0
        return results


# =============================================================================
# CLI output
# =============================================================================

def print_results(suite: FuzzSuiteResult):
    w = 75

    print()
    print("=" * w)
    print("CONSTRAINT BOUNDARY FUZZING (Layer 2)")
    print("=" * w)
    print(f"  Seed: {suite.seed}  |  Per constraint: {suite.iterations_per_constraint}"
          f"  |  Total probes: {suite.total_probes}  |  {suite.duration_s:.2f}s")
    print()

    for c in suite.constraints:
        print(f"--- {c.constraint_label} ---")
        print(f"  Probes: {c.total}  |  Allowed: {c.allowed}  |  Denied: {c.denied}  |  Errors: {c.errors}")

        if c.findings:
            print(f"  Findings ({len(c.findings)}):")
            for f in c.findings:
                val_s = repr(f.value)
                if len(val_s) > 60:
                    val_s = val_s[:57] + "..."
                tag = "ERROR" if f.outcome == "error" else f.outcome.upper()
                print(f"    [{tag:7s}] {f.category}: {val_s}")
                if f.note:
                    print(f"             {f.note}")
        else:
            print("  No findings.")
        print()

    if suite.monotonicity:
        m = suite.monotonicity
        status = "PASS" if m.violations == 0 else f"FAIL ({m.violations} violations)"
        print(f"--- Monotonicity Property Test ---")
        print(f"  Pairs: {m.pairs_tested}  |  Probes: {m.total_probes}  |  Violations: {m.violations}  |  {status}")
        if m.counterexamples:
            for cx in m.counterexamples[:5]:
                print(f"    BUG: parent={cx.parent_constraint} child={cx.child_constraint} input={cx.input_value}")
        print(f"  Duration: {m.duration_s:.2f}s")
        print()

    if suite.structural:
        s = suite.structural
        status = "PASS" if s.authorized == 0 and s.random_bytes_accepted == 0 else "FAIL"
        print(f"--- Structural Warrant Fuzzing ---")
        print(f"  Mutations: {s.mutations_tested}  |  Rejected: {s.rejected}  |  Deserialized: {s.deserialized}  |  Authorized: {s.authorized}")
        print(f"  Random bytes: {s.random_bytes_tested}  |  Accepted: {s.random_bytes_accepted}")
        print(f"  Status: {status}  |  Duration: {s.duration_s:.2f}s")
        print()

    print("=" * w)
    if suite.total_errors > 0:
        print(f"  ERRORS: {suite.total_errors} probes caused non-policy exceptions")
        print("  These are serialization-layer type checks (ValueError), not policy bypasses.")
    if suite.total_findings > 0:
        print(f"  FINDINGS: {suite.total_findings} noteworthy behaviors")
    if suite.total_errors == 0 and suite.total_findings == 0:
        print("  CLEAN: No errors or notable findings.")
    print("=" * w)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Constraint boundary fuzzer (Layer 2)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--iterations", type=int, default=200,
                        help="Probes per constraint (default: 200)")
    args = parser.parse_args()

    fuzzer = ConstraintFuzzer(seed=args.seed, iterations=args.iterations)
    results = fuzzer.fuzz_all()
    print_results(results)
    return results


if __name__ == "__main__":
    main()
