"""
tests/test_external_scope_and_auth.py -- External Authorization & Scope Tests (Phase 14)
========================================================================================
Validates target registration, domain verification challenges, explicit authorization
declarations, subdomain isolation, ScanPolicy enforcement, mode branching, and
cryptographic provenance for external assessments.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import json
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure aegisscan is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan")))

from database import Base
from models import Target, VerificationChallenge, AuthorizationGrant, AuditEvent, Scan, Finding
from authorization import (
    normalize_target_url,
    register_target,
    get_or_create_challenge,
    get_challenge_instructions,
    verify_domain_ownership,
    create_authorization_grant,
    revoke_authorization,
    get_target_status_summary,
)
from policy import ScanPolicy
from scope import ScopeGuard, OutOfScopeError
from crypto import get_or_create_scan_passport, verify_scan_passport, record_scan_in_chain, verify_hash_chain
from detectors.external_passive import generate_not_tested_stubs


class TestExternalScopeAndAuth(unittest.TestCase):
    """Test suite for target registration, verification challenges, and scan policies."""

    def setUp(self):
        """Create an isolated in-memory SQLite database for each test."""
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(self.engine)

    def test_normalize_target_url(self):
        """Validates canonicalization rules for local testbeds and external domains."""
        # Localhost
        norm_local = normalize_target_url("127.0.0.1:5001")
        self.assertEqual(norm_local["target_type"], "local")
        self.assertEqual(norm_local["canonical_base"], "http://127.0.0.1:5001")

        # External domain
        norm_ext = normalize_target_url("https://aakriti-portfolio-beryl.vercel.app")
        self.assertEqual(norm_ext["target_type"], "external")
        self.assertEqual(norm_ext["hostname"], "aakriti-portfolio-beryl.vercel.app")
        self.assertEqual(norm_ext["canonical_base"], "https://aakriti-portfolio-beryl.vercel.app")

        # External without scheme defaults to https
        norm_ext_noscheme = normalize_target_url("portfolio.example.com")
        self.assertEqual(norm_ext_noscheme["canonical_base"], "https://portfolio.example.com")

        # External target with HTTP scheme rejected
        with self.assertRaises(ValueError):
            normalize_target_url("http://example.com")

        # External target with non-443 port rejected
        with self.assertRaises(ValueError):
            normalize_target_url("https://example.com:8443")

    def test_target_registration_and_challenge_generation(self):
        """Validates target registration and cryptographically secure challenge generation."""
        target = register_target(self.db, "https://portfolio.example.com", name="My Portfolio", authorized_by="Alice")
        self.assertEqual(target.target_type, "external")
        self.assertFalse(target.is_verified)

        # Active challenge was generated
        challenge = (
            self.db.query(VerificationChallenge)
            .filter(VerificationChallenge.target_id == target.id)
            .first()
        )
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.status, "pending")
        self.assertGreater(len(challenge.challenge_token), 32)
        self.assertTrue(challenge.expires_at > datetime.utcnow())

        # Instructions structure
        instructions = get_challenge_instructions(target, challenge)
        self.assertIn(".well-known/aegisscan-verification.txt", instructions["verification_url"])
        self.assertIn("Vercel", instructions["instructions_markdown"])

    def test_subdomain_isolation(self):
        """Validates that registering a subdomain isolates the challenge to that exact host."""
        t_sub = register_target(self.db, "https://sub.domain.com")
        t_parent = register_target(self.db, "https://domain.com")

        c_sub = get_or_create_challenge(self.db, t_sub.id)
        c_parent = get_or_create_challenge(self.db, t_parent.id)

        self.assertNotEqual(c_sub.challenge_token, c_parent.challenge_token)
        self.assertNotEqual(t_sub.id, t_parent.id)

    def test_verify_domain_ownership_success(self):
        """Validates successful domain verification when target serves exact token."""
        target = register_target(self.db, "https://portfolio.example.com")
        challenge = get_or_create_challenge(self.db, target.id)
        token = challenge.challenge_token

        # Mock client returning exact token
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.is_redirect = False
        mock_resp.text = token

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        result = verify_domain_ownership(self.db, target.id, custom_client=mock_client)
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])

        # Check DB persistence
        self.db.refresh(target)
        self.db.refresh(challenge)
        self.assertTrue(target.is_verified)
        self.assertEqual(target.verification_method, "http")
        self.assertEqual(challenge.status, "verified")

    def test_verify_domain_ownership_token_mismatch(self):
        """Validates verification failure on incorrect token."""
        target = register_target(self.db, "https://portfolio.example.com")
        challenge = get_or_create_challenge(self.db, target.id)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.is_redirect = False
        mock_resp.text = "incorrect-token-12345"

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        result = verify_domain_ownership(self.db, target.id, custom_client=mock_client)
        self.assertFalse(result["success"])
        self.assertFalse(result["verified"])

        self.db.refresh(target)
        self.assertFalse(target.is_verified)

    def test_verify_domain_ownership_rejects_redirects(self):
        """Validates that HTTP redirects during domain verification are strictly rejected."""
        target = register_target(self.db, "https://portfolio.example.com")
        challenge = get_or_create_challenge(self.db, target.id)

        mock_resp = MagicMock()
        mock_resp.status_code = 301
        mock_resp.is_redirect = True
        mock_resp.headers = {"location": "https://evil.com/fake-token"}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        result = verify_domain_ownership(self.db, target.id, custom_client=mock_client)
        self.assertFalse(result["success"])
        self.assertIn("rejected redirect", result["error"])

    def test_authorization_grant_workflow(self):
        """Validates creation and revocation of authorization grants."""
        target = register_target(self.db, "https://portfolio.example.com")
        
        # Grant creation fails if target unverified
        with self.assertRaises(ValueError):
            create_authorization_grant(self.db, target.id, authorized_by="Alice")

        # Manually mark verified for testing grant lifecycle
        target.is_verified = True
        self.db.commit()

        # Create valid grant
        grant = create_authorization_grant(
            self.db,
            target.id,
            authorized_by="Alice",
            scan_mode="external_basic",
            allowed_paths=["/", "/about"],
            excluded_paths=["/logout", "/delete"],
        )
        self.assertEqual(grant.status, "active")
        self.assertEqual(grant.approved_hostname, "portfolio.example.com")
        self.assertEqual(grant.scan_mode, "external_basic")

        # Status summary
        summary = get_target_status_summary(self.db, target.id)
        self.assertEqual(summary["authorization_status"], "active_grant")

        # Revoke grant
        revoked = revoke_authorization(self.db, target.id, reason="Testing revocation")
        self.assertTrue(revoked)
        self.db.refresh(grant)
        self.assertEqual(grant.status, "revoked")

    def test_scan_policy_boundaries(self):
        """Validates ScanPolicy path filtering, budgets, and exclusion rules."""
        policy = ScanPolicy(
            target_url="https://example.com",
            target_type="external",
            scan_mode="external_basic",
            allowed_hostname="example.com",
            allowed_paths=["/"],
            excluded_paths=["/logout", "/delete", "/payment"],
            request_budget=5,
        )

        # Allowed paths
        self.assertTrue(policy.is_path_allowed("/"))
        self.assertTrue(policy.is_path_allowed("/about"))
        self.assertTrue(policy.is_path_allowed("/projects/1"))

        # Excluded sensitive paths
        self.assertFalse(policy.is_path_allowed("/logout"))
        self.assertFalse(policy.is_path_allowed("/auth/logout"))
        self.assertFalse(policy.is_path_allowed("/api/delete"))
        self.assertFalse(policy.is_path_allowed("/billing/payment"))

        # Budget tracking
        for _ in range(5):
            self.assertTrue(policy.record_request())
        self.assertEqual(policy.requests_made, 5)
        # 6th request fails budget
        self.assertFalse(policy.record_request())

        # Cancellation
        self.assertFalse(policy.is_cancelled)
        policy.cancel("Operator aborted scan")
        self.assertTrue(policy.is_cancelled)
        self.assertFalse(policy.can_make_request())

    def test_not_tested_stubs_integrity(self):
        """Validates that honest 'not_tested' stubs are generated for external basic scans."""
        stubs = generate_not_tested_stubs(reason="External Basic mode does not inject active payloads.")
        types = [s.vuln_type for s in stubs]
        self.assertIn("SQL Injection", types)
        self.assertIn("Reflected XSS", types)
        self.assertIn("IDOR (Broken Access Control)", types)
        self.assertIn("Indirect Prompt Injection", types)

        for s in stubs:
            self.assertIn(s.category, ("not_tested", "informational"))
            self.assertIn(s.status, ("not_tested", "not_applicable"))

    def test_cryptographic_provenance_integration(self):
        """Validates Ed25519 passport creation and SHA-256 hash-chaining for external scan."""
        target = Target(name="Portfolio", base_url="https://portfolio.example.com", is_verified=True)
        self.db.add(target)
        self.db.commit()

        scan = Scan(
            target_id=target.id,
            status="completed",
            scan_mode="external_basic",
            target_type="external",
            started_at=datetime.utcnow() - timedelta(minutes=1),
            finished_at=datetime.utcnow(),
            requests_count=12,
        )
        self.db.add(scan)
        self.db.commit()

        # Add passive and honest findings
        finding1 = Finding(
            scan_id=scan.id,
            vulnerability_type="TLS Transport Security",
            status="verified",
            severity="Info",
            location="https://portfolio.example.com",
            evidence="TLS 1.3 verified.",
            remediation_advice="Maintain TLS 1.3",
            category="verified_control",
        )
        finding2 = Finding(
            scan_id=scan.id,
            vulnerability_type="SQL Injection",
            status="not_tested",
            severity="Info",
            location="External Target Scope",
            evidence="Active injection disabled in External Basic mode.",
            remediation_advice="Use ORM",
            category="not_tested",
        )
        self.db.add_all([finding1, finding2])
        self.db.commit()

        # Create passport
        passport, record = get_or_create_scan_passport(self.db, scan_id=scan.id, scan_mode="external_basic")
        self.assertEqual(passport["scan_mode"], "external_basic")
        self.assertIn("digital_signature", passport)

        # Verify signature
        verification = verify_scan_passport(passport)
        self.assertEqual(verification["status"], "VALID")
        self.assertTrue(verification["valid"])

        # Record in hash chain
        chain_record = record_scan_in_chain(self.db, scan_id=scan.id, payload_hash=passport["canonical_payload_hash"])
        self.assertIsNotNone(chain_record)
        self.assertEqual(chain_record.sequence_number, 1)

        # Verify chain integrity
        chain_audit = verify_hash_chain(self.db)
        self.assertEqual(chain_audit["status"], "VERIFIED")
        self.assertEqual(chain_audit["total_records"], 1)
        self.assertTrue(chain_audit["valid"])

    @patch("scope.resolve_and_validate_hostname", return_value=["93.184.216.34"])
    def test_external_basic_end_to_end_pipeline(self, mock_dns):
        """Exercises complete External Basic scanning pipeline with mock fixtures."""
        from api.routes import start_scan
        from discovery.crawler import DiscoveryResult, PageInfo

        # Create target, verify, authorize
        target = register_target(self.db, "https://secure-app.example.com", name="Secure App")
        target.is_verified = True
        self.db.commit()

        grant = create_authorization_grant(
            self.db,
            target.id,
            authorized_by="Lead Auditor",
            scan_mode="external_basic",
            allowed_paths=["/"],
            excluded_paths=["/logout", "/delete"],
        )

        mock_page = PageInfo(
            url="https://secure-app.example.com/",
            links=["https://secure-app.example.com/about"],
            forms=[],
            response_headers={"strict-transport-security": "max-age=31536000; includeSubDomains"},
            cookies={"session": "val; Secure; HttpOnly; SameSite=Strict"},
            status_code=200,
        )
        mock_discovery = DiscoveryResult(
            base_url="https://secure-app.example.com",
            pages=[mock_page],
            all_forms=[],
            visited_urls=["https://secure-app.example.com/"],
        )

        with patch("discovery.crawler.crawl", return_value=mock_discovery), \
             patch("detectors.external_passive.inspect_tls_certificate", return_value=[]), \
             patch("detectors.external_passive.inspect_robots_and_sitemap", return_value=[]):
            
            data = start_scan({
                "target_url": "https://secure-app.example.com",
                "scan_mode": "external_basic"
            }, db=self.db)

            self.assertEqual(data["scan_mode"], "external_basic")
            self.assertEqual(data["status"], "completed")
            self.assertIn("passport", data)
            self.assertIn("hash_chain", data)
            self.assertGreater(data["not_tested_count"], 0)


if __name__ == "__main__":
    unittest.main()
