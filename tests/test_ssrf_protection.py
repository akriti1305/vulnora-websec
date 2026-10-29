"""
tests/test_ssrf_protection.py -- Anti-SSRF & Network Boundary Unit Tests (Phase 14)
===================================================================================
Comprehensive regression testing of hardened ScopeGuard, IP validation,
IPv4-mapped IPv6 addresses, cloud metadata endpoints, DNS resolution,
redirect escapes, and SSRF transport layer.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import httpx

# Ensure aegisscan is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan")))

from scope import (
    validate_ip_address_not_internal,
    resolve_and_validate_hostname,
    ScopeGuard,
    OutOfScopeError,
    SSRFProtectTransport,
)


class TestSSRFProtection(unittest.TestCase):
    """Test suite validating all anti-SSRF defenses and IP classification."""

    def test_loopback_rejection(self):
        """Validates that IPv4 and IPv6 loopback addresses are strictly rejected."""
        loopbacks = ["127.0.0.1", "127.0.0.2", "127.1.2.3", "::1"]
        for ip in loopbacks:
            with self.assertRaises(OutOfScopeError, msg=f"Failed to reject loopback: {ip}"):
                validate_ip_address_not_internal(ip)

    def test_private_rfc1918_rejection(self):
        """Validates that RFC 1918 private subnets are strictly rejected."""
        privates = [
            "10.0.0.1", "10.255.255.254",
            "172.16.0.1", "172.31.255.254",
            "192.168.0.1", "192.168.1.100",
        ]
        for ip in privates:
            with self.assertRaises(OutOfScopeError, msg=f"Failed to reject private IP: {ip}"):
                validate_ip_address_not_internal(ip)

    def test_cloud_metadata_and_link_local_rejection(self):
        """Validates that link-local and cloud metadata IPs (AWS, GCP, Azure, Alibaba) are rejected."""
        metadata_ips = [
            "169.254.169.254",  # AWS/GCP/Azure instance metadata
            "169.254.1.1",      # General link-local
            "100.100.100.200",  # Alibaba Cloud metadata
            "fe80::1",          # IPv6 link-local
        ]
        for ip in metadata_ips:
            with self.assertRaises(OutOfScopeError, msg=f"Failed to reject metadata IP: {ip}"):
                validate_ip_address_not_internal(ip)

    def test_ipv4_mapped_ipv6_rejection(self):
        """Validates that IPv4-mapped IPv6 encapsulation cannot bypass checks."""
        mapped = [
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:192.168.1.1",
            "::ffff:10.0.0.1",
        ]
        for ip in mapped:
            with self.assertRaises(OutOfScopeError, msg=f"Failed to reject mapped IPv6: {ip}"):
                validate_ip_address_not_internal(ip)

    def test_special_purpose_and_reserved_rejection(self):
        """Validates rejection of 0.0.0.0, broadcast, multicast, and CGNAT."""
        special = [
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",    # Multicast
            "100.64.0.1",   # CGNAT RFC 6598
        ]
        for ip in special:
            with self.assertRaises(OutOfScopeError, msg=f"Failed to reject special IP: {ip}"):
                validate_ip_address_not_internal(ip)

    def test_public_ip_permitted(self):
        """Validates that genuine public routable IPs pass internal validation."""
        public_ips = ["93.184.216.34", "104.18.26.120", "151.101.1.140"]
        for ip in public_ips:
            # Should not raise
            validate_ip_address_not_internal(ip)

    def test_dns_resolution_and_validation(self):
        """Validates that hostname resolution checks all returned addresses."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            # Mock resolving to private IP
            mock_getaddrinfo.return_value = [
                (2, 1, 0, "", ("192.168.1.50", 443)),
            ]
            with self.assertRaises(OutOfScopeError):
                resolve_and_validate_hostname("attacker-domain.com", is_external=True)

            # Mock resolving to mixed public + private (DNS rebinding / multi-A record)
            mock_getaddrinfo.return_value = [
                (2, 1, 0, "", ("93.184.216.34", 443)),
                (2, 1, 0, "", ("127.0.0.1", 443)),
            ]
            with self.assertRaises(OutOfScopeError):
                resolve_and_validate_hostname("rebind-target.com", is_external=True)

    def test_external_mode_syntax_and_port_rules(self):
        """Validates external mode URL syntax, HTTPS scheme, and standard port 443."""
        guard = ScopeGuard(allowed_hosts={"example.com"}, mode="external")

        # HTTP scheme rejected for external targets
        with self.assertRaises(OutOfScopeError):
            guard.check("http://example.com/")

        # Non-443 port rejected for external targets
        with self.assertRaises(OutOfScopeError):
            guard.check("https://example.com:8443/")

        # Userinfo in URL rejected
        with self.assertRaises(OutOfScopeError):
            guard.check("https://admin:secret@example.com/")

        # Valid HTTPS port 443 permitted (with mocked DNS)
        with patch("scope.resolve_and_validate_hostname", return_value=["93.184.216.34"]):
            self.assertTrue(guard.is_allowed("https://example.com/"))

    def test_redirect_escape_hook_blocking(self):
        """Validates that the redirect event hook blocks destinations to off-scope or private hosts."""
        guard = ScopeGuard(allowed_hosts={"example.com"}, mode="external")

        # Mock request trying to redirect to private metadata IP
        req_bad = httpx.Request("GET", "https://example.com/redirect?to=metadata")
        resp_bad = httpx.Response(
            status_code=302,
            headers={"Location": "http://169.254.169.254/latest/meta-data"},
            request=req_bad
        )

        with self.assertRaises(OutOfScopeError):
            guard._check_redirect_event_hook(resp_bad)

        # Mock request redirecting to unapproved external domain
        req_unapproved = httpx.Request("GET", "https://example.com/redirect?to=evil")
        resp_unapproved = httpx.Response(
            status_code=302,
            headers={"Location": "https://unauthorized-evil.com/"},
            request=req_unapproved
        )

        with self.assertRaises(OutOfScopeError):
            guard._check_redirect_event_hook(resp_unapproved)

    def test_ssrf_transport_preflight(self):
        """Validates that SSRFProtectTransport checks URLs before opening connection."""
        guard = ScopeGuard(allowed_hosts={"example.com"}, mode="external")
        transport = SSRFProtectTransport(guard)

        req = httpx.Request("GET", "http://127.0.0.1:8000/api/secret")
        with self.assertRaises(OutOfScopeError):
            transport.handle_request(req)

    def test_local_lab_remains_functional(self):
        """Ensures that local lab mode continues to allow localhost and 127.0.0.1 for benchmark scans."""
        guard = ScopeGuard(mode="local_lab")
        self.assertTrue(guard.is_allowed("http://127.0.0.1:5001/"))
        self.assertTrue(guard.is_allowed("http://localhost:5001/assistant"))


if __name__ == "__main__":
    unittest.main()
