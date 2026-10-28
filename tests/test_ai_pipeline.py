"""
tests/test_ai_pipeline.py -- AegisScan 2.0 AI Pipeline Tests (Phases 8 & 9)
===========================================================================
Comprehensive unit and integration test suite covering:
  1. AI Feature and Manifest Discovery (Phase 8)
  2. Manifest schema validation and invalid manifest handling
  3. ScopeGuard enforcement and out-of-scope endpoint rejection
  4. Multi-vector Canary Token Validator (Phase 9)
  5. Canary evidence redaction
  6. False-positive resistance on benign decoy document (Scenario F)
  7. Indirect Prompt Injection detector in Vulnerable Mode (Scenario A)
  8. Indirect Prompt Injection detector in Fixed/Secure Mode
  9. Scan Mode support: Basic (passive) vs Deep (active authorized)
 10. End-to-end scanner API pipeline integration with database persistence
"""

import sys
import os
import unittest
import json
from datetime import datetime

# Path setups for aegisscan and aegislab
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_scan_dir = os.path.join(_root, "aegisscan")
_lab_dir = os.path.join(_root, "aegislab")
_lab_site = os.path.join(_lab_dir, "venv", "Lib", "site-packages")

for p in (_lab_site, _scan_dir, _lab_dir):
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app as aegislab_app
import ai_assistant
from database import Base, get_db
from models import Target, Scan, Finding, EvaluationRun
from scope import ScopeGuard, OutOfScopeError
from discovery.crawler import DiscoveryResult, PageInfo, PageForm, FormField
from detectors.ai_discovery import (
    detect_ai_features,
    parse_and_validate_manifest,
    AIDiscoveryResult,
    DiscoveredAIEndpoint
)
from detectors.canary_validator import (
    validate_canary_disclosure,
    redact_canary_text,
    CanaryValidationResult
)
from detectors.prompt_injection_detector import (
    detect_indirect_prompt_injection
)
from api.routes import start_scan


class TestAIPipeline(unittest.TestCase):

    def setUp(self):
        """Set up test environment and reset AegisLab AI assistant state."""
        self.app = aegislab_app.app
        self.app.config["TESTING"] = True
        self.transport = httpx.WSGITransport(app=self.app)
        self.base_url = "http://127.0.0.1:5001"

        # Scope guard configured to route to WSGI transport for local target
        self.guard = ScopeGuard()

        # In-memory test database for scan pipeline test
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

        # Reset lab state
        with httpx.Client(transport=self.transport, base_url=self.base_url) as client:
            client.post("/assistant/reset")

    def tearDown(self):
        """Clean up database and reset lab state."""
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        with httpx.Client(transport=self.transport, base_url=self.base_url) as client:
            client.post("/assistant/reset")

    def _get_mock_discovery(self) -> DiscoveryResult:
        """Helper building a minimal DiscoveryResult including assistant link and form."""
        p_home = PageInfo(
            url=self.base_url + "/",
            links=[self.base_url + "/assistant", self.base_url + "/login"],
            forms=[],
            response_headers={},
            cookies={},
            status_code=200
        )
        form_query = PageForm(
            page_url=self.base_url + "/assistant",
            action=self.base_url + "/assistant/query",
            method="POST",
            fields=[FormField(name="query", field_type="text")]
        )
        return DiscoveryResult(
            base_url=self.base_url,
            pages=[p_home],
            all_forms=[form_query],
            visited_urls=[p_home.url]
        )

    # -----------------------------------------------------------------------
    # 1. AI Feature & Manifest Discovery Tests (Phase 8)
    # -----------------------------------------------------------------------
    def test_ai_feature_discovery_and_manifest_parsing(self):
        """Verify discovery detects the AI manifest, endpoints, and sets capabilities."""
        # Custom ScopeGuard using WSGITransport
        guard = ScopeGuard()
        _orig_client = guard.client

        def _mock_client(**kwargs):
            kwargs["transport"] = self.transport
            return _orig_client(**kwargs)

        guard.client = _mock_client

        disc = self._get_mock_discovery()
        ai_res = detect_ai_features(disc, self.base_url, scan_mode="deep", scope_guard=guard)

        self.assertTrue(ai_res.is_ai_enabled)
        self.assertIsNotNone(ai_res.manifest)
        self.assertTrue(ai_res.manifest.is_valid)
        self.assertEqual(ai_res.manifest.application_name, "AegisLab AI Assistant")

        # Endpoints mapped correctly
        self.assertEqual(ai_res.query_endpoint, self.base_url + "/assistant/query")
        self.assertEqual(ai_res.upload_endpoint, self.base_url + "/assistant/upload")
        self.assertEqual(ai_res.assistant_ui_url, self.base_url + "/assistant")

        # Check findings generated
        types = [f.vuln_type for f in ai_res.findings]
        self.assertIn("AI Security Manifest Detected", types)
        self.assertIn("AI Assistant Discovered", types)

    def test_invalid_manifest_handling(self):
        """Verify malformed or invalid manifest data is handled gracefully."""
        guard = ScopeGuard()

        # Non-dict input
        res1 = parse_and_validate_manifest("not-a-dict", "http://127.0.0.1:5001/manifest", guard)
        self.assertFalse(res1.is_valid)
        self.assertIn("Manifest is not a valid JSON dictionary.", res1.validation_notes)

        # Missing endpoints dictionary
        res2 = parse_and_validate_manifest({"schema_version": "1.0"}, "http://127.0.0.1:5001/manifest", guard)
        self.assertFalse(res2.is_valid)

        # Manifest containing forbidden raw secret value
        res3 = parse_and_validate_manifest(
            {"endpoints": {"query": "/q"}, "secret": "AEGIS_CANARY_20261028_X7K9"},
            "http://127.0.0.1:5001/manifest", guard
        )
        self.assertFalse(res3.is_valid)
        self.assertTrue(any("Real secret canary" in note for note in res3.validation_notes))

    def test_out_of_scope_endpoint_rejection(self):
        """Verify endpoints and manifests on unauthorized hosts are rejected."""
        guard = ScopeGuard(allowed_hosts={"127.0.0.1", "localhost"})
        oos_url = "http://malicious-external-site.com/.well-known/aegisscan-ai.json"

        res = parse_and_validate_manifest({"endpoints": {"query": "/q"}}, oos_url, guard)
        self.assertFalse(res.is_valid)
        self.assertIn("outside authorized scope", res.validation_notes[0])

    # -----------------------------------------------------------------------
    # 2. Canary Validator Tests (Phase 9)
    # -----------------------------------------------------------------------
    def test_canary_validator_detection_vectors(self):
        """Test multi-vector canary detection: body, header, and tool events."""
        # 1. Response body disclosure
        res_body = validate_canary_disclosure(
            response_text="The confidential canary is AEGIS_CANARY_20261028_X7K9 here.",
            manifest_test_id="AEGIS_CANARY_TEST_ID_01"
        )
        self.assertTrue(res_body.detected)
        self.assertEqual(res_body.detection_vector, "response_body")
        self.assertNotIn("AEGIS_CANARY_20261028_X7K9", res_body.evidence_redacted)
        self.assertIn("REDACTED_VERIFIED", res_body.evidence_redacted)

        # 2. Telemetry header disclosure
        res_header = validate_canary_disclosure(
            response_text="Standard reply",
            response_headers={"X-Aegis-Canary-Found": "1", "X-Aegis-Canary-ID": "AEGIS_CANARY_TEST_ID_01"}
        )
        self.assertTrue(res_header.detected)
        self.assertEqual(res_header.detection_vector, "response_header")

        # 3. Tool event argument leak
        tool_events = [{
            "tool_name": "send_email",
            "arguments": {"body": "Here is token AEGIS_CANARY_20261028_X7K9"},
            "canary_leak_detected": True
        }]
        res_tool = validate_canary_disclosure(tool_events=tool_events)
        self.assertTrue(res_tool.detected)
        self.assertEqual(res_tool.detection_vector, "simulated_tool_call")

    def test_canary_validator_benign_decoy_rejection(self):
        """Test that educational/benign decoy text is NOT flagged as a leak."""
        decoy_text = (
            "This whitepaper discusses canary token architectures using samples "
            "like CANARY_SAMPLE_ALPHA for detection benchmarking."
        )
        res = validate_canary_disclosure(response_text=decoy_text)
        self.assertFalse(res.detected)
        self.assertTrue(res.is_decoy)
        self.assertIn("Benign canary token discussion", res.evidence_redacted)

    def test_canary_validator_redaction(self):
        """Verify raw secret tokens are properly redacted from report strings."""
        raw = "Leak confirmed: token is AEGIS_CANARY_20261028_X7K9."
        redacted = redact_canary_text(raw)
        self.assertNotIn("AEGIS_CANARY_20261028_X7K9", redacted)
        self.assertIn("AEGIS_CANARY_***[REDACTED_VERIFIED]", redacted)

    # -----------------------------------------------------------------------
    # 3. Indirect Prompt Injection Tests (Vulnerable vs Fixed)
    # -----------------------------------------------------------------------
    def test_indirect_prompt_injection_vulnerable_mode(self):
        """
        When AegisLab is in vulnerable mode, prompt injection probe succeeds,
        leaks the canary, and generates CONFIRMED Critical findings.
        """
        guard = ScopeGuard()
        _orig_client = guard.client

        def _mock_client(**kwargs):
            kwargs["transport"] = self.transport
            return _orig_client(**kwargs)

        guard.client = _mock_client

        disc = self._get_mock_discovery()
        ai_disc = detect_ai_features(disc, self.base_url, scan_mode="deep", scope_guard=guard)

        # Run detector in default vulnerable mode
        findings = detect_indirect_prompt_injection(disc, ai_disc, scope_guard=guard)

        # Must report confirmed Critical findings
        self.assertTrue(len(findings) >= 2)
        types = [f.vuln_type for f in findings]
        self.assertIn("Indirect Prompt Injection", types)
        self.assertIn("AI Canary Token Leakage", types)

        inj_finding = next(f for f in findings if f.vuln_type == "Indirect Prompt Injection")
        self.assertEqual(inj_finding.status, "confirmed")
        self.assertEqual(inj_finding.severity, "Critical")
        self.assertNotIn("AEGIS_CANARY_20261028_X7K9", inj_finding.evidence)
        self.assertIn("REDACTED", inj_finding.evidence)

    def test_indirect_prompt_injection_fixed_mode(self):
        """
        When AegisLab is in secure mode, prompt injection override is blocked,
        canary does NOT leak, and finding is marked not_reproducible.
        """
        guard = ScopeGuard()
        _orig_client = guard.client

        def _mock_client(**kwargs):
            kwargs["transport"] = self.transport
            return _orig_client(**kwargs)

        guard.client = _mock_client

        # Toggle AegisLab AI to secure mode
        with httpx.Client(transport=self.transport, base_url=self.base_url) as client:
            client.post("/assistant/config", json={"secure_mode": True})

        disc = self._get_mock_discovery()
        ai_disc = detect_ai_features(disc, self.base_url, scan_mode="deep", scope_guard=guard)

        findings = detect_indirect_prompt_injection(disc, ai_disc, scope_guard=guard)

        self.assertEqual(len(findings), 1)
        inj_finding = findings[0]
        self.assertEqual(inj_finding.vuln_type, "Indirect Prompt Injection")
        self.assertEqual(inj_finding.status, "not_reproducible")
        self.assertEqual(inj_finding.severity, "Info")
        self.assertIn("assistant maintained safety boundaries", inj_finding.evidence)

    def test_scan_mode_basic_skips_deep_testing(self):
        """In basic scan mode, deep testing is skipped and reported as not_tested."""
        guard = ScopeGuard()
        _orig_client = guard.client

        def _mock_client(**kwargs):
            kwargs["transport"] = self.transport
            return _orig_client(**kwargs)

        guard.client = _mock_client

        disc = self._get_mock_discovery()
        ai_disc = detect_ai_features(disc, self.base_url, scan_mode="basic", scope_guard=guard)

        findings = detect_indirect_prompt_injection(disc, ai_disc, scope_guard=guard)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "not_tested")
        self.assertEqual(findings[0].severity, "Info")

    # -----------------------------------------------------------------------
    # 4. End-to-End Scanner API Integration Test
    # -----------------------------------------------------------------------
    def test_start_scan_pipeline_with_ai_detectors(self):
        """
        Verifies that start_scan() runs the complete 8-step pipeline,
        persists AI findings to the database, and returns accurate breakdown counts.
        """
        # Patch ScopeGuard.client to route requests to WSGITransport for local AegisLab
        _real_client = ScopeGuard.client

        def _patched_client(self_guard, **kwargs):
            kwargs["transport"] = self.transport
            return _real_client(self_guard, **kwargs)

        ScopeGuard.client = _patched_client

        try:
            res = start_scan({
                "target_url": self.base_url,
                "target_name": "AegisLab Local Integration Test",
                "scan_mode": "deep"
            }, db=self.db)

            self.assertEqual(res["status"], "completed")
            self.assertTrue(res["findings_count"] > 0)
            self.assertIn("ai_discovery", res["breakdown"])
            self.assertIn("ai_injection", res["breakdown"])
            self.assertTrue(res["breakdown"]["ai_discovery"] >= 1)
            self.assertTrue(res["breakdown"]["ai_injection"] >= 1)

            # Check database persistence
            db_findings = self.db.query(Finding).filter(Finding.scan_id == res["scan_id"]).all()
            vuln_types = [f.vulnerability_type for f in db_findings]
            self.assertIn("AI Security Manifest Detected", vuln_types)
            self.assertIn("Indirect Prompt Injection", vuln_types)
            self.assertIn("AI Canary Token Leakage", vuln_types)

        finally:
            ScopeGuard.client = _real_client


if __name__ == "__main__":
    unittest.main()
