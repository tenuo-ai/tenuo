"""
Comprehensive tests for the UrlSafe SSRF-protection constraint.

Tests cover:
- Basic allow/deny cases
- SSRF vectors (metadata, private IPs, loopback)
- IP encoding bypasses (decimal, octal, hex, IPv6-mapped)
- Domain allowlist patterns
- Edge cases (null bytes, missing host, etc.)
"""

import pytest
from tenuo.openai import UrlSafe


class TestUrlSafeBasic:
    """Basic functionality tests for UrlSafe."""

    def test_allows_public_https_url(self):
        """Standard public HTTPS URLs should be allowed."""
        constraint = UrlSafe()
        assert constraint.matches("https://api.github.com/repos")
        assert constraint.matches("https://example.com/path/to/resource")
        assert constraint.matches("https://cdn.example.com/image.png")

    def test_allows_public_http_url(self):
        """Standard public HTTP URLs should be allowed by default."""
        constraint = UrlSafe()
        assert constraint.matches("http://example.com/api")
        assert constraint.matches("http://api.github.com/repos")

    def test_rejects_non_string(self):
        """Non-string values should be rejected."""
        constraint = UrlSafe()
        assert not constraint.matches(None)
        assert not constraint.matches(123)
        assert not constraint.matches(["https://example.com"])
        assert not constraint.matches({"url": "https://example.com"})


class TestUrlSafeMetadataBlocking:
    """Tests for cloud metadata endpoint blocking."""

    def test_blocks_aws_metadata(self):
        """Block AWS/Azure/DigitalOcean metadata endpoint."""
        constraint = UrlSafe()
        assert not constraint.matches("http://169.254.169.254/latest/meta-data/")
        assert not constraint.matches("http://169.254.169.254/latest/api/token")
        assert not constraint.matches("https://169.254.169.254/")

    def test_blocks_gcp_metadata(self):
        """Block GCP metadata endpoints."""
        constraint = UrlSafe()
        assert not constraint.matches("http://metadata.google.internal/computeMetadata/v1/")
        assert not constraint.matches("http://metadata.goog/")

    def test_blocks_alibaba_metadata(self):
        """Block Alibaba Cloud metadata endpoint."""
        constraint = UrlSafe()
        assert not constraint.matches("http://100.100.100.200/latest/meta-data/")

    def test_allows_metadata_when_disabled(self):
        """Metadata endpoints allowed when block_metadata=False."""
        constraint = UrlSafe(block_metadata=False, block_reserved=False)
        # Still blocked by reserved ranges (169.254.x.x is link-local)
        # Need to also disable block_reserved
        assert constraint.matches("http://169.254.169.254/latest/meta-data/")


class TestUrlSafePrivateIPBlocking:
    """Tests for private IP range blocking (RFC1918)."""

    def test_blocks_10_x_private_range(self):
        """Block 10.0.0.0/8 private range."""
        constraint = UrlSafe()
        assert not constraint.matches("http://10.0.0.1/admin")
        assert not constraint.matches("http://10.255.255.255/")
        assert not constraint.matches("https://10.1.2.3:8080/api")

    def test_blocks_172_16_private_range(self):
        """Block 172.16.0.0/12 private range."""
        constraint = UrlSafe()
        assert not constraint.matches("http://172.16.0.1/")
        assert not constraint.matches("http://172.31.255.255/")
        # 172.32.x.x is NOT in the private range
        assert constraint.matches("http://172.32.0.1/")

    def test_blocks_192_168_private_range(self):
        """Block 192.168.0.0/16 private range."""
        constraint = UrlSafe()
        assert not constraint.matches("http://192.168.1.1/admin")
        assert not constraint.matches("http://192.168.0.1/")
        assert not constraint.matches("https://192.168.255.255:443/")

    def test_allows_private_when_disabled(self):
        """Private IPs allowed when block_private=False."""
        constraint = UrlSafe(block_private=False)
        assert constraint.matches("http://10.0.0.1/admin")
        assert constraint.matches("http://192.168.1.1/")


class TestUrlSafeLoopbackBlocking:
    """Tests for loopback address blocking."""

    def test_blocks_localhost(self):
        """Block localhost hostname."""
        constraint = UrlSafe()
        assert not constraint.matches("http://localhost/")
        assert not constraint.matches("http://localhost:8080/api")
        assert not constraint.matches("https://localhost.localdomain/")

    def test_blocks_127_x_loopback(self):
        """Block 127.0.0.0/8 loopback range."""
        constraint = UrlSafe()
        assert not constraint.matches("http://127.0.0.1/")
        assert not constraint.matches("http://127.0.0.1:8080/admin")
        assert not constraint.matches("http://127.255.255.255/")

    def test_blocks_ipv6_loopback(self):
        """Block IPv6 loopback (::1)."""
        constraint = UrlSafe()
        assert not constraint.matches("http://[::1]/")
        assert not constraint.matches("http://[::1]:8080/admin")

    def test_allows_loopback_when_disabled(self):
        """Loopback allowed when block_loopback=False."""
        constraint = UrlSafe(block_loopback=False)
        assert constraint.matches("http://localhost/")
        assert constraint.matches("http://127.0.0.1/")


class TestUrlSafeIPEncodingBypasses:
    """Tests for IP encoding bypass attempts."""

    def test_blocks_url_encoded_ip(self):
        """Block URL-encoded IP addresses (SSRF bypass attempt).
        
        SECURITY: Python's urlparse does NOT decode hostnames, so an attacker
        could try http://%31%32%37%2e%30%2e%30%2e%31/ to bypass IP blocking.
        """
        constraint = UrlSafe()
        # %31%32%37%2e%30%2e%30%2e%31 = 127.0.0.1
        assert not constraint.matches("http://%31%32%37%2e%30%2e%30%2e%31/")
        # %31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34 = 169.254.169.254
        assert not constraint.matches("http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/")
        # %31%30%2e%30%2e%30%2e%31 = 10.0.0.1
        assert not constraint.matches("http://%31%30%2e%30%2e%30%2e%31/")
        # Mixed encoding: 192.%31%36%38.1.1
        assert not constraint.matches("http://192.%31%36%38.1.1/")

    def test_blocks_decimal_ip(self):
        """Block decimal IP notation (e.g., 2130706433 = 127.0.0.1)."""
        constraint = UrlSafe()
        # 2130706433 = 127.0.0.1
        assert not constraint.matches("http://2130706433/")
        # 3232235521 = 192.168.0.1
        assert not constraint.matches("http://3232235521/")
        # 2852039166 = 169.254.169.254
        assert not constraint.matches("http://2852039166/")

    def test_blocks_hex_ip(self):
        """Block hex IP notation (e.g., 0x7f000001 = 127.0.0.1)."""
        constraint = UrlSafe()
        # 0x7f000001 = 127.0.0.1
        assert not constraint.matches("http://0x7f000001/")
        # 0xA9FEA9FE = 169.254.169.254
        assert not constraint.matches("http://0xA9FEA9FE/")
        # Case insensitivity
        assert not constraint.matches("http://0X7F000001/")

    def test_blocks_octal_ip(self):
        """Block octal IP notation (e.g., 0177.0.0.1 = 127.0.0.1)."""
        constraint = UrlSafe()
        # 0177.0.0.1 = 127.0.0.1
        assert not constraint.matches("http://0177.0.0.1/")
        # 0177.0377.0377.0377 = 127.255.255.255 (still loopback)
        assert not constraint.matches("http://0177.0377.0377.0377/")

    def test_blocks_ipv6_mapped_ipv4(self):
        """Block IPv6-mapped IPv4 addresses."""
        constraint = UrlSafe()
        # ::ffff:127.0.0.1
        assert not constraint.matches("http://[::ffff:127.0.0.1]/")
        # ::ffff:169.254.169.254
        assert not constraint.matches("http://[::ffff:169.254.169.254]/")
        # ::ffff:192.168.1.1
        assert not constraint.matches("http://[::ffff:192.168.1.1]/")


class TestUrlSafeSchemeBlocking:
    """Tests for dangerous scheme blocking."""

    def test_blocks_file_scheme(self):
        """Block file:// protocol."""
        constraint = UrlSafe()
        assert not constraint.matches("file:///etc/passwd")
        assert not constraint.matches("file://localhost/etc/passwd")
        assert not constraint.matches("file:///C:/Windows/system32/config/sam")

    def test_blocks_gopher_scheme(self):
        """Block gopher:// protocol."""
        constraint = UrlSafe()
        assert not constraint.matches("gopher://evil.com/")

    def test_blocks_ftp_by_default(self):
        """FTP is not in default allowed schemes."""
        constraint = UrlSafe()
        assert not constraint.matches("ftp://files.example.com/")

    def test_custom_allowed_schemes(self):
        """Custom allowed schemes."""
        constraint = UrlSafe(allow_schemes=["https"])
        assert constraint.matches("https://example.com/")
        assert not constraint.matches("http://example.com/")

        constraint_ftp = UrlSafe(allow_schemes=["ftp", "https"])
        assert constraint_ftp.matches("ftp://files.example.com/")
        assert constraint_ftp.matches("https://example.com/")


class TestUrlSafeDomainAllowlist:
    """Tests for domain allowlist functionality."""

    def test_exact_domain_match(self):
        """Exact domain matching."""
        constraint = UrlSafe(allow_domains=["api.github.com"])
        assert constraint.matches("https://api.github.com/repos")
        assert not constraint.matches("https://github.com/")
        assert not constraint.matches("https://evil.api.github.com/")

    def test_wildcard_subdomain_match(self):
        """Wildcard subdomain matching (*.example.com)."""
        constraint = UrlSafe(allow_domains=["*.googleapis.com"])
        assert constraint.matches("https://storage.googleapis.com/bucket")
        assert constraint.matches("https://compute.googleapis.com/api")
        # Base domain should also match
        assert constraint.matches("https://googleapis.com/")
        # But not other TLDs
        assert not constraint.matches("https://googleapis.net/")

    def test_multiple_allowed_domains(self):
        """Multiple domains in allowlist."""
        constraint = UrlSafe(
            allow_domains=["api.github.com", "*.googleapis.com", "example.com"]
        )
        assert constraint.matches("https://api.github.com/")
        assert constraint.matches("https://storage.googleapis.com/")
        assert constraint.matches("https://example.com/")
        assert not constraint.matches("https://evil.com/")

    def test_domain_allowlist_still_blocks_ssrf(self):
        """Domain allowlist doesn't bypass IP blocking."""
        # IP addresses are checked before domain allowlist
        constraint = UrlSafe(allow_domains=["*"])
        # Even with wildcard domain, IPs are checked separately
        assert not constraint.matches("http://169.254.169.254/")
        assert not constraint.matches("http://127.0.0.1/")


class TestUrlSafePortBlocking:
    """Tests for port restriction functionality."""

    def test_allows_any_port_by_default(self):
        """Any port allowed when allow_ports is not set."""
        constraint = UrlSafe()
        assert constraint.matches("https://example.com/")
        assert constraint.matches("https://example.com:443/")
        assert constraint.matches("https://example.com:8443/")
        assert constraint.matches("http://example.com:8080/")

    def test_restricts_to_allowed_ports(self):
        """Only allowed ports pass when specified."""
        constraint = UrlSafe(allow_ports=[443, 8443])
        assert constraint.matches("https://example.com:443/")
        assert constraint.matches("https://example.com:8443/")
        assert not constraint.matches("https://example.com:8080/")
        assert not constraint.matches("http://example.com:80/")


class TestUrlSafeInternalTLDs:
    """Tests for internal TLD blocking."""

    def test_allows_internal_tlds_by_default(self):
        """Internal TLDs allowed by default (can't detect without DNS)."""
        constraint = UrlSafe()
        assert constraint.matches("http://internal.corp/")
        assert constraint.matches("http://server.local/")

    def test_blocks_internal_tlds_when_enabled(self):
        """Internal TLDs blocked when block_internal_tlds=True."""
        constraint = UrlSafe(block_internal_tlds=True)
        assert not constraint.matches("http://internal.corp/")
        assert not constraint.matches("http://server.local/")
        assert not constraint.matches("http://api.internal/")
        assert not constraint.matches("http://dev.localhost/")
        assert not constraint.matches("http://home.lan/")
        # But regular TLDs still work
        assert constraint.matches("https://example.com/")


class TestUrlSafeEdgeCases:
    """Tests for edge cases and malformed inputs."""

    def test_rejects_null_bytes(self):
        """Null bytes in URL should be rejected."""
        constraint = UrlSafe()
        assert not constraint.matches("https://evil.com\x00.trusted.com/")
        assert not constraint.matches("https://example.com/path\x00/hidden")

    def test_rejects_missing_host(self):
        """URLs without a host should be rejected."""
        constraint = UrlSafe()
        assert not constraint.matches("https:///path")
        assert not constraint.matches("http://")

    def test_rejects_empty_string(self):
        """Empty string should be rejected."""
        constraint = UrlSafe()
        assert not constraint.matches("")

    def test_handles_url_with_auth(self):
        """URLs with auth components should work."""
        constraint = UrlSafe()
        assert constraint.matches("https://user:pass@example.com/path")

    def test_handles_url_with_query_and_fragment(self):
        """URLs with query strings and fragments should work."""
        constraint = UrlSafe()
        assert constraint.matches("https://example.com/path?query=1#fragment")

    def test_case_insensitive_scheme(self):
        """Scheme matching should be case-insensitive."""
        constraint = UrlSafe()
        assert constraint.matches("HTTP://example.com/")
        assert constraint.matches("HTTPS://example.com/")
        assert constraint.matches("HtTpS://example.com/")

    def test_case_insensitive_host(self):
        """Host matching should be case-insensitive."""
        constraint = UrlSafe(allow_domains=["example.com"])
        assert constraint.matches("https://EXAMPLE.COM/")
        assert constraint.matches("https://Example.Com/")


class TestUrlSafeRepr:
    """Tests for string representation."""

    def test_default_repr(self):
        """Default UrlSafe has minimal repr."""
        constraint = UrlSafe()
        assert repr(constraint) == "UrlSafe()"

    def test_custom_options_repr(self):
        """Custom options appear in repr."""
        constraint = UrlSafe(
            allow_schemes=["https"],
            allow_domains=["example.com"],
            block_private=False,
        )
        r = repr(constraint)
        assert "allow_schemes=['https']" in r
        assert "allow_domains=['example.com']" in r
        assert "block_private=False" in r


class TestUrlSafeIntegration:
    """Integration tests with guard() function."""

    def test_with_guard_dict_style(self):
        """UrlSafe works as a constraint in guard()."""
        from tenuo.openai import check_constraint

        constraint = UrlSafe()
        # Should be recognized by check_constraint via matches() method
        assert check_constraint(constraint, "https://example.com/")
        assert not check_constraint(constraint, "http://169.254.169.254/")

    def test_constraint_violation_message(self):
        """ConstraintViolation has appropriate message for UrlSafe."""
        from tenuo.openai import _constraint_expected_type

        constraint = UrlSafe()
        expected_type = _constraint_expected_type(constraint)
        assert "safe URL" in expected_type.lower() or "ssrf" in expected_type.lower()


class TestUrlSafeSSRFVectorComprehensive:
    """Comprehensive SSRF vector tests matching the design document."""

    @pytest.mark.parametrize("url,should_allow", [
        # Public URLs - ALLOW
        ("https://api.github.com/repos", True),
        ("https://example.com/data", True),
        ("http://cdn.example.com/image.png", True),
        
        # AWS/Azure/DO metadata - DENY
        ("http://169.254.169.254/latest/meta-data/", False),
        ("http://169.254.169.254/latest/api/token", False),
        
        # GCP metadata - DENY
        ("http://metadata.google.internal/", False),
        ("http://metadata.goog/", False),
        
        # Private IPs - DENY
        ("http://10.0.0.1/admin", False),
        ("http://172.16.0.1/", False),
        ("http://192.168.1.1/admin", False),
        
        # Loopback - DENY
        ("http://127.0.0.1/", False),
        ("http://localhost/", False),
        ("http://[::1]/", False),
        
        # IP encoding bypasses - DENY
        ("http://2130706433/", False),  # Decimal 127.0.0.1
        ("http://0x7f000001/", False),  # Hex 127.0.0.1
        ("http://0177.0.0.1/", False),  # Octal 127.0.0.1
        ("http://[::ffff:127.0.0.1]/", False),  # IPv6-mapped
        ("http://%31%32%37%2e%30%2e%30%2e%31/", False),  # URL-encoded 127.0.0.1
        ("http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/", False),  # URL-encoded metadata
        
        # Dangerous schemes - DENY
        ("file:///etc/passwd", False),
        ("gopher://evil.com/", False),
        
        # Null byte injection - DENY
        ("http://evil.com\x00.trusted.com/", False),
    ])
    def test_ssrf_vectors(self, url, should_allow):
        """Comprehensive SSRF vector coverage."""
        constraint = UrlSafe()
        result = constraint.matches(url)
        assert result == should_allow, f"Expected {url} to be {'allowed' if should_allow else 'denied'}"
