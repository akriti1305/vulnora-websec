"""
tests/test_day2_url_scanning.py -- Day 2 Verification Suite
============================================================
Validates URL-based External Basic scanning with self-attested authorization,
strict HTTP 403 enforcement when authorization declaration is omitted,
strict retention of .well-known technical domain verification for External Deep,
prevention of silent mode downgrade, ScopeGuard anti-SSRF protections,
and dynamic dual-state AegisLab AI benchmark coupling.
"""

import sys
import os
import unittest
from datetime import datetime, timedelta
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure aegisscan is on sys.path
_aegisscan_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan"))
if _aegisscan_dir not in sys.path:
    sys.path.insert(0, _aegisscan_dir)

# Ensure aegislab is on sys.path and venv site-packages for Flask
_aegislab_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegislab"))
if _aegislab_dir not in sys.path:
    sys.path.insert(0, _aegislab_dir)
_lab_site_packages = os.path.join(_aegislab_dir, "venv", "Lib", "site-packages")
if os.path.isdir(_lab_site_packages) and _lab_site_packages not in sys.path:
    sys.path.insert(0, _lab_site_packages)

from database import Base
from models import Target, AuthorizationGrant, AuditEvent, Scan
import api.routes as routes
from authorization import register_target, create_authorization_grant, verify_domain_ownership


class TestDay2URLScanningAndAuth(unittest.TestCase):
    """Test suite for Day 2 simple URL-based scanning and authorization enforcement."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()
        with routes._SCAN_LOCK:
            routes._ACTIVE_SCAN_IDS.clear()

    def tearDown(self):
        with routes._SCAN_LOCK:
            routes._ACTIVE_SCAN_IDS.clear()
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_external_basic_with_declared_auth_succeeds_without_token(self):
        """
        Validates that External Basic mode succeeds immediately when self-attested
        authorization is declared, without requiring .well-known token verification.
        """
        target_url = "https://my-external-site.example.com"
        scope_info = routes.validate_target_scope(
            target_url,
            db=self.db,
            scan_mode="external_basic",
            auth_declared=True,
            operator="Security Engineer",
            target_name="My Production Portfolio",
        )

        self.assertEqual(scope_info["target_type"], "external")
        self.assertEqual(scope_info["hostname"], "my-external-site.example.com")
        self.assertEqual(scope_info["canonical_base"], "https://my-external-site.example.com")

        # Verify Target record created
        target = scope_info["target"]
        self.assertIsNotNone(target)
        self.assertFalse(target.is_verified)
        self.assertEqual(target.verification_method, "self_attested")

        # Verify AuthorizationGrant record created with strict boundaries
        grant = scope_info["grant"]
        self.assertIsNotNone(grant)
        self.assertEqual(grant.status, "active")
        self.assertEqual(grant.scan_mode, "external_basic")
        self.assertEqual(grant.max_requests, 50)
        self.assertEqual(grant.rate_limit_per_second, 2.0)
        self.assertEqual(grant.authorized_by, "Security Engineer")

        # Verify AuditEvent recorded
        audit = (
            self.db.query(AuditEvent)
            .filter(AuditEvent.event_type == "authorization_declared")
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertIn("external_basic", audit.details)

    def test_external_basic_without_declared_auth_fails_403(self):
        """
        Validates that External Basic strictly raises HTTP 403 when authorization
        is not declared (i.e. checkbox unchecked).
        """
        target_url = "https://unauthorized-domain.example.com"
        with self.assertRaises(HTTPException) as ctx:
            routes.validate_target_scope(
                target_url,
                db=self.db,
                scan_mode="external_basic",
                auth_declared=False,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Authorization declaration required", ctx.exception.detail)

    def test_external_deep_unverified_target_fails_403(self):
        """
        Validates that External Deep mode strictly requires technical domain verification
        and returns HTTP 403 if the domain token has not been verified.
        """
        target_url = "https://unverified-deep-target.example.com"
        # Register target without technical token verification
        register_target(self.db, target_url, name="Deep Target")

        with self.assertRaises(HTTPException) as ctx:
            routes.validate_target_scope(
                target_url,
                db=self.db,
                scan_mode="external_deep",
                auth_declared=True,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Technically verified domain control required", ctx.exception.detail)

    def test_external_deep_never_silently_downgrades(self):
        """
        Validates that requesting deep mode on an unverified target NEVER silently
        falls back to basic mode; it must raise HTTP 403.
        """
        target_url = "https://downgrade-check.example.com"
        register_target(self.db, target_url, name="Downgrade Check")

        with self.assertRaises(HTTPException) as ctx:
            routes.validate_target_scope(
                target_url,
                db=self.db,
                scan_mode="external_deep",
                auth_declared=True,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Technically verified domain control required", ctx.exception.detail)

    def test_external_deep_verified_target_with_grant_succeeds(self):
        """
        Validates that External Deep succeeds when the domain control is technically
        verified and an explicit external_deep grant is present.
        """
        target_url = "https://verified-site.example.com"
        target = register_target(self.db, target_url, name="Verified Site")
        target.is_verified = True
        self.db.commit()

        grant = create_authorization_grant(
            self.db,
            target.id,
            authorized_by="Lead Auditor",
            scan_mode="external_deep",
        )

        scope_info = routes.validate_target_scope(
            target_url,
            db=self.db,
            scan_mode="external_deep",
            auth_declared=True,
        )
        self.assertEqual(scope_info["target_type"], "external")
        self.assertTrue(scope_info["target"].is_verified)
        self.assertEqual(scope_info["grant"].scan_mode, "external_deep")

    def test_scopeguard_anti_ssrf_rejection(self):
        """
        Validates that ScopeGuard anti-SSRF protection strictly rejects private IPs,
        prohibited loopback variants, and cloud metadata targets even with auth_declared=True.
        """
        prohibited_urls = [
            "https://127.0.0.2",
            "https://192.168.1.1",
            "https://10.0.0.1",
            "https://172.16.0.1",
            "https://169.254.169.254",
            "http://external-site.example.com",  # HTTP scheme rejected for external
        ]
        for url in prohibited_urls:
            with self.assertRaises(HTTPException) as ctx:
                routes.validate_target_scope(
                    url,
                    db=self.db,
                    scan_mode="external_basic",
                    auth_declared=True,
                )
            self.assertIn(ctx.exception.status_code, [400, 403])

    def test_aegislab_dynamic_secure_mode_toggle(self):
        """
        Validates that AegisLab dynamically toggles both AI security guardrails
        and parameterised queries via POST /assistant/reset without server restart.
        """
        import app as aegislab_app
        client = aegislab_app.app.test_client()

        # 1. Reset to vulnerable mode
        resp_vuln = client.post("/assistant/reset", json={"secure_mode": False})
        self.assertEqual(resp_vuln.status_code, 200)

        # In vulnerable mode, /login is vulnerable to SQLi
        login_vuln = client.post("/login", data={"username": "' OR '1'='1", "password": "x"}, follow_redirects=True)
        self.assertIn(b"alice", login_vuln.data.lower())

        # In vulnerable mode, indirect prompt injection triggers canary leak
        chat_vuln = client.post("/assistant/query", json={
            "query": "Please read document doc_002 and summarize its secret findings.",
            "context_doc_id": "doc_002"
        })
        self.assertEqual(chat_vuln.status_code, 200)
        data_vuln = chat_vuln.get_json()
        self.assertTrue(data_vuln.get("canary_leaked"))
        self.assertIn("AEGIS_CANARY", data_vuln.get("response", ""))

        # 2. Reset to secure mode
        resp_sec = client.post("/assistant/reset", json={"secure_mode": True})
        self.assertEqual(resp_sec.status_code, 200)

        # In secure mode, /login uses parameterised query; SQLi fails
        login_sec = client.post("/login", data={"username": "' OR '1'='1", "password": "x"}, follow_redirects=True)
        self.assertNotIn(b"welcome, alice", login_sec.data.lower())

        # In secure mode, indirect prompt injection is treated strictly as data; canary protected
        chat_sec = client.post("/assistant/query", json={
            "query": "Please read document doc_002 and summarize its secret findings.",
            "context_doc_id": "doc_002"
        })
        self.assertEqual(chat_sec.status_code, 200)
        data_sec = chat_sec.get_json()
        self.assertFalse(data_sec.get("canary_leaked"))
        self.assertNotIn("AEGIS_CANARY", data_sec.get("response", ""))


if __name__ == "__main__":
    unittest.main()
