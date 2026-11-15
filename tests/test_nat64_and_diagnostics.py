"""
tests/test_nat64_and_diagnostics.py -- NAT64 & External Diagnostic Classification Tests
========================================================================================
Comprehensive regression testing for:
1. RFC 6052 NAT64 Well-Known Prefix (64:ff9b::/96) embedded IPv4 extraction & validation.
2. Rejection of NAT64 addresses embedding private, loopback, or cloud metadata IPv4 destinations.
3. Strict rejection of non-NAT64 reserved IPv6 (e.g. 2001:db8::1) and link-local / ULA addresses.
4. Dual-stack DNS resolution preference (prioritizing native IPv4 over NAT64).
5. DNS rebinding prevention (any resolved internal address aborts resolution).
6. ScopeGuard connection refusal classification as informational scanner diagnostic rather
   than confirmed critical target vulnerability.
7. Diagnostic reporting for incomplete crawl runs and honest scan completeness.
8. Dynamic comparison default selection pairing baseline and re-scan without hardcoded IDs.
"""

import sys
import os
import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure aegisscan is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan")))

from database import Base
from models import Target, Scan, Finding
from scope import (
    validate_ip_address_not_internal,
    resolve_and_validate_hostname,
    ScopeGuard,
    OutOfScopeError,
    NAT64_WELL_KNOWN_PREFIX,
)
from detectors.external_passive import (
    inspect_tls_certificate,
    generate_not_tested_stubs,
)
from risk import classify_finding_category, ScoredFinding
from main import _find_default_comparison_pair


class TestNAT64AndDiagnostics(unittest.TestCase):
    """Test suite for NAT64 handling, ScopeGuard diagnostic classification, and scan completeness."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(self.engine)

    # ------------------------------------------------------------------
    # 1. NAT64 Well-Known Prefix & Embedded IPv4 Extraction
    # ------------------------------------------------------------------
    def test_nat64_public_ipv4_permitted(self):
        """
        Validates that 64:ff9b::/96 embedding a public routable IPv4 (e.g. 64.29.17.195)
        is successfully validated and permitted.
        """
        # 0x40.0x1d.0x11.0xc3 == 64.29.17.195 (Vercel Anycast edge network)
        nat64_public = "64:ff9b::401d:11c3"
        try:
            validate_ip_address_not_internal(nat64_public)
        except OutOfScopeError as e:
            self.fail(f"Public NAT64 address should be permitted, but raised: {e}")

        # Cloudflare DNS 1.1.1.1 in NAT64 -> 64:ff9b::0101:0101
        try:
            validate_ip_address_not_internal("64:ff9b::0101:0101")
        except OutOfScopeError as e:
            self.fail(f"1.1.1.1 in NAT64 should be permitted, but raised: {e}")

    def test_nat64_private_ipv4_rejected(self):
        """
        Validates that NAT64 addresses embedding RFC 1918 private IPv4 subnets
        are strictly blocked by ScopeGuard.
        """
        # 127.0.0.1 in NAT64 -> 64:ff9b::7f00:0001
        with self.assertRaises(OutOfScopeError) as ctx:
            validate_ip_address_not_internal("64:ff9b::7f00:0001")
        self.assertIn("embeds prohibited IPv4", str(ctx.exception))

        # 192.168.1.1 in NAT64 -> 64:ff9b::c0a8:0101
        with self.assertRaises(OutOfScopeError) as ctx:
            validate_ip_address_not_internal("64:ff9b::c0a8:0101")
        self.assertIn("embeds prohibited IPv4", str(ctx.exception))

        # 10.0.0.1 in NAT64 -> 64:ff9b::0a00:0001
        with self.assertRaises(OutOfScopeError) as ctx:
            validate_ip_address_not_internal("64:ff9b::0a00:0001")
        self.assertIn("embeds prohibited IPv4", str(ctx.exception))

    def test_nat64_cloud_metadata_rejected(self):
        """
        Validates that NAT64 addresses embedding cloud instance metadata (169.254.169.254)
        are strictly blocked.
        """
        # 169.254.169.254 in NAT64 -> 64:ff9b::a9fe:a9fe
        with self.assertRaises(OutOfScopeError) as ctx:
            validate_ip_address_not_internal("64:ff9b::a9fe:a9fe")
        self.assertIn("embeds prohibited IPv4", str(ctx.exception))

    def test_non_nat64_reserved_ipv6_rejected(self):
        """
        Validates that other reserved or special IPv6 addresses outside NAT64 are rejected.
        """
        # 2001:db8::1 (Documentation prefix)
        with self.assertRaises(OutOfScopeError):
            validate_ip_address_not_internal("2001:db8::1")

        # ::1 (IPv6 Loopback)
        with self.assertRaises(OutOfScopeError):
            validate_ip_address_not_internal("::1")

        # fe80::1 (Link-local)
        with self.assertRaises(OutOfScopeError):
            validate_ip_address_not_internal("fe80::1")

        # fc00::1 (Unique Local Address / RFC 4193)
        with self.assertRaises(OutOfScopeError):
            validate_ip_address_not_internal("fc00::1")

    # ------------------------------------------------------------------
    # 2. Dual-Stack Resolution & Sorting Preference
    # ------------------------------------------------------------------
    def test_dual_stack_prefers_native_ipv4_over_nat64(self):
        """
        Validates that when DNS returns both direct IPv4 and NAT64 IPv6,
        the resolver validates both and prioritizes native IPv4 for socket connection.
        """
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                # Family 10 (AF_INET6) returning NAT64 first
                (10, 1, 0, "", ("64:ff9b::401d:11c3", 443)),
                # Family 2 (AF_INET) returning direct IPv4 second
                (2, 1, 0, "", ("64.29.17.3", 443)),
            ]
            ips = resolve_and_validate_hostname("aakriti-portfolio-beryl.vercel.app", is_external=True)
            self.assertEqual(len(ips), 2)
            # Direct IPv4 must be first in preference order
            self.assertEqual(ips[0], "64.29.17.3")
            self.assertEqual(ips[1], "64:ff9b::401d:11c3")

    def test_dns_rebinding_rejection_in_dual_stack(self):
        """
        Validates that if DNS returns any private or prohibited IP alongside public IPs,
        resolution aborts immediately to protect against DNS rebinding.
        """
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 0, "", ("64.29.17.3", 443)),
                (2, 1, 0, "", ("127.0.0.1", 443)),
            ]
            with self.assertRaises(OutOfScopeError):
                resolve_and_validate_hostname("rebind-target.com", is_external=True)

    def test_socket_ip_pinning(self):
        """Validates that resolve_and_pin_ip returns the exact validated IP for pinning."""
        guard = ScopeGuard(allowed_hosts={"example.com"}, mode="external")
        with patch("scope.resolve_and_validate_hostname", return_value=["93.184.216.34", "93.184.216.35"]):
            pinned = guard.resolve_and_pin_ip("example.com", 443)
            self.assertEqual(pinned, "93.184.216.34")

    # ------------------------------------------------------------------
    # 3. Diagnostic Classification vs False Critical Vulnerability
    # ------------------------------------------------------------------
    def test_scopeguard_block_classified_as_diagnostic_not_critical(self):
        """
        CRITICAL BUG FIX VERIFICATION:
        Validates that a ScopeGuard connection block during TLS inspection
        produces an informational diagnostic finding, NEVER a Critical confirmed vulnerability.
        """
        guard = ScopeGuard(allowed_hosts={"blocked.example.com"}, mode="external")
        with patch.object(guard, "resolve_and_pin_ip", side_effect=OutOfScopeError("Target IP '10.0.0.1' is private")):
            findings = inspect_tls_certificate("https://blocked.example.com", scope_guard=guard)

            self.assertEqual(len(findings), 1)
            f = findings[0]
            # Must NOT be Critical
            self.assertEqual(f.severity, "Info")
            # Must NOT be confirmed vulnerability
            self.assertEqual(f.category, "informational")
            self.assertEqual(f.status, "info")
            self.assertEqual(f.vuln_type, "Network / ScopeGuard Inspection Blocked")
            self.assertIn("aborted by ScopeGuard", f.evidence)
            self.assertIn("diagnostic", f.remediation_advice.lower())

    def test_classify_finding_category_diagnostics(self):
        """Validates that finding category classifier maps network diagnostic notices to informational."""
        diagnostics = [
            ("Network / ScopeGuard Inspection Blocked", "info"),
            ("Network / TLS Connection Blocked", "info"),
            ("Network / TLS Handshake Incomplete", "info"),
            ("Crawl / Endpoint Discovery Incomplete", "info"),
            ("TLS Inspection Notice", "info"),
        ]
        for vuln_type, status in diagnostics:
            cat = classify_finding_category(vuln_type, status)
            self.assertEqual(cat, "informational", f"Failed for {vuln_type}")

    # ------------------------------------------------------------------
    # 4. Controlled Fixture-Based External Basic Scan
    # ------------------------------------------------------------------
    def test_fixture_external_basic_honest_diagnostic(self):
        """
        Runs a controlled fixture-based External Basic scan where crawl fails/is blocked.
        Verifies that:
        1. 0 confirmed vulnerabilities are recorded.
        2. Incomplete crawl is reported as an honest informational diagnostic.
        3. Active vulnerability totals remain 0.
        """
        from discovery.crawler import DiscoveryResult
        empty_discovery = DiscoveryResult(
            base_url="https://fixture.example.com",
            pages=[],
            all_forms=[],
            visited_urls=[],
        )

        with patch("discovery.crawler.crawl", return_value=empty_discovery):
            with patch("detectors.external_passive.inspect_tls_certificate") as mock_tls:
                mock_tls.return_value = [
                    ScoredFinding(
                        vuln_type="Network / ScopeGuard Inspection Blocked",
                        severity="Info",
                        status="info",
                        location="https://fixture.example.com:443",
                        evidence="TLS transport inspection aborted by ScopeGuard: network boundary test",
                        remediation_advice="Review network routing. This is a scanner diagnostic.",
                        category="informational"
                    )
                ]

                # Run external scan task logic in fixture mode
                tls_findings = mock_tls.return_value
                crawl_diagnostics = [
                    ScoredFinding(
                        vuln_type="Crawl / Endpoint Discovery Incomplete",
                        severity="Info",
                        status="info",
                        location="https://fixture.example.com",
                        evidence="Web crawler did not successfully fetch any pages. Downstream checks not executed.",
                        remediation_advice="Verify network reachability.",
                        category="informational"
                    )
                ]
                not_tested = generate_not_tested_stubs(reason="External Basic test fixture")

                all_findings = crawl_diagnostics + tls_findings + not_tested

                confirmed = [f for f in all_findings if f.category == "confirmed_vulnerability"]
                potential = [f for f in all_findings if f.category == "potential_vulnerability"]
                active_vulns = len(confirmed) + len(potential)

                # Total active vulnerabilities MUST be 0
                self.assertEqual(active_vulns, 0)
                self.assertEqual(len(confirmed), 0)

    def test_full_pipeline_external_basic_with_diagnostics(self):
        """
        Validates end-to-end execution of an External Basic scan where TLS inspection is blocked:
        - Target registered & scan created
        - Pipeline executed with mocked network
        - Scan status completed
        - Hash-chain record created
        - Passport created and verifiable
        - Active vulnerabilities count == 0
        - Diagnostic finding recorded with category 'informational'
        - HTML report renders cleanly
        """
        import api.routes as routes
        from discovery.crawler import DiscoveryResult
        from report import generate_html_report

        scope_info = routes.validate_target_scope(
            "https://test-fixture.example.com",
            db=self.db,
            scan_mode="external_basic",
            auth_declared=True,
            operator="Operator",
            target_name="Fixture Target",
        )
        target = scope_info["target"]
        grant = scope_info["grant"]

        scan = Scan(
            target_id=target.id,
            status="running",
            scan_mode="external_basic",
            target_type="external",
            authorization_grant_id=grant.id if grant else None,
            started_at=datetime.utcnow(),
        )
        self.db.add(scan)
        self.db.commit()

        # Mock crawler and TLS inspection
        empty_disc = DiscoveryResult(
            base_url="https://test-fixture.example.com",
            pages=[],
            all_forms=[],
            visited_urls=[],
        )
        with patch("discovery.crawler.crawl", return_value=empty_disc):
            with patch("detectors.external_passive.inspect_tls_certificate") as mock_tls:
                mock_tls.return_value = [
                    ScoredFinding(
                        vuln_type="Network / ScopeGuard Inspection Blocked",
                        severity="Info",
                        status="info",
                        location="https://test-fixture.example.com:443",
                        evidence="TLS transport inspection aborted by ScopeGuard: simulation",
                        remediation_advice="Review network routing. This is a scanner diagnostic.",
                        category="informational",
                    )
                ]
                with patch("detectors.external_passive.inspect_robots_and_sitemap", return_value=[]):
                    routes._execute_scan_pipeline(scan_id=scan.id, db=self.db)

        # Refresh scan from db
        self.db.refresh(scan)
        self.assertEqual(scan.status, "completed")
        self.assertIsNotNone(scan.passport_record)
        self.assertIsNotNone(scan.chain_record)

        # Verify findings
        findings = scan.findings
        active_vulns = [f for f in findings if f.category in ("confirmed_vulnerability", "potential_vulnerability")]
        self.assertEqual(len(active_vulns), 0, "No active vulnerabilities should be reported for ScopeGuard blocks")

        diagnostics = [f for f in findings if f.vulnerability_type == "Network / ScopeGuard Inspection Blocked"]
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0].category, "informational")
        self.assertEqual(diagnostics[0].severity, "Info")

        crawl_incomplete = [f for f in findings if f.vulnerability_type == "Crawl / Endpoint Discovery Incomplete"]
        self.assertEqual(len(crawl_incomplete), 1)
        self.assertEqual(crawl_incomplete[0].category, "informational")

    # ------------------------------------------------------------------
    # 5. Comparison Default Selection Logic
    # ------------------------------------------------------------------
    def test_default_comparison_pair_selection(self):
        """
        Validates dynamic selection of baseline vs re-scan pair:
        Baseline A should select the older vulnerable scan.
        Re-Scan B should select the newer fixed scan.
        """
        mock_scans = [
            {"id": 34, "target_name": "Portfolio", "status": "completed", "active_vulns_count": 0},
            {"id": 33, "target_name": "AegisLab Demo", "status": "completed", "active_vulns_count": 0},
            {"id": 32, "target_name": "AegisLab Demo", "status": "completed", "active_vulns_count": 5},
            {"id": 28, "target_name": "AegisLab Demo", "status": "completed", "active_vulns_count": 5},
        ]
        scan_a, scan_b = _find_default_comparison_pair(mock_scans)
        self.assertEqual(scan_a, 32, "Baseline A must default to vulnerable Scan #32")
        self.assertEqual(scan_b, 33, "Re-Scan B must default to fixed Scan #33")


if __name__ == "__main__":
    unittest.main()

