"""
tests/test_final_integration.py -- Phase 13 Final Integration, Dashboard & Evaluation Tests
============================================================================================
Comprehensive test suite covering:
  1. Dashboard and report rendering (HTML 200, category tags, KPIs, dark theme)
  2. Correct finding classification (vulnerabilities vs controls vs informational)
  3. Vulnerable vs fixed scan comparison (5 buckets, layer breakdowns, honest re-test check)
  4. Evaluation 2.0 calculations (TP, FP, FN, TN, Precision, Recall, F1 across scopes)
  5. Two-record cryptographic hash-chain continuity (H_2 = SHA256(rec_2 || H_1))
  6. Scan-to-passport lifecycle & tampering detection
  7. API response schema consistency & count agreement
"""

import sys
import os
import unittest
import json
import base64
import tempfile
import shutil
from datetime import datetime

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_scan_dir = os.path.join(_root, "aegisscan")
_lab_dir = os.path.join(_root, "aegislab")
_lab_site = os.path.join(_lab_dir, "venv", "Lib", "site-packages")

for p in (_lab_site, _scan_dir, _lab_dir):
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from models import Target, Scan, Finding, ScanPassport, ScanChainRecord, EvaluationRun
from crypto.key_manager import KeyManager
from crypto.scan_passport import (
    create_scan_passport,
    verify_scan_passport,
    get_or_create_scan_passport,
    SCHEMA_VERSION,
)
from crypto.hash_chain import (
    compute_chain_hash,
    record_scan_in_chain,
    verify_hash_chain,
    GENESIS_HASH,
)
from risk import classify_finding_category, ScoredFinding
from evaluation import (
    evaluate_scan,
    TRADITIONAL_GROUND_TRUTH,
    AI_AGENT_GROUND_TRUTH,
    AEGISLAB_GROUND_TRUTH,
    BENIGN_DECOY_CONTROLS,
)
from report import generate_home_page, generate_html_report, generate_compare_report
from api.routes import compare_scans
from main import app


class TestFinalIntegrationPhase13(unittest.TestCase):
    """Phase 13 Final Integration Test Suite."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.km = KeyManager(secrets_dir=self.temp_dir)

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )
        self.TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSession()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Baseline target
        self.target = Target(name="AegisLab Test", base_url="http://127.0.0.1:5001")
        self.db.add(self.target)
        self.db.commit()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -----------------------------------------------------------------------
    # 1. Finding Classification Tests
    # -----------------------------------------------------------------------
    def test_finding_classification_categories(self):
        """1. Verified security controls and informational discoveries are segregated from active vulns."""
        self.assertEqual(classify_finding_category("Tool Integrity Verified", "verified"), "verified_control")
        self.assertEqual(classify_finding_category("AI Agent Approval Gate Verified", "verified"), "verified_control")
        self.assertEqual(classify_finding_category("AI Assistant Discovered", "detected"), "informational")
        self.assertEqual(classify_finding_category("AI Security Manifest Detected", "detected"), "informational")
        self.assertEqual(classify_finding_category("SQL Injection", "confirmed"), "confirmed_vulnerability")
        self.assertEqual(classify_finding_category("Indirect Prompt Injection", "confirmed"), "confirmed_vulnerability")
        self.assertEqual(classify_finding_category("IDOR (Broken Access Control)", "potential"), "potential_vulnerability")
        self.assertEqual(classify_finding_category("SQL Injection", "not_reproducible"), "not_reproducible")
        self.assertEqual(classify_finding_category("Tool Baseline Unavailable", "not_tested"), "not_tested")

    # -----------------------------------------------------------------------
    # 2. Evaluation 2.0 Calculation Tests
    # -----------------------------------------------------------------------
    def test_evaluation_metrics_and_scope_segregation(self):
        """2. Evaluation calculates TP, FP, TN, FN, Precision, Recall and F1 accurately across scopes."""
        scan = Scan(target_id=self.target.id, status="completed", scan_mode="deep")
        self.db.add(scan)
        self.db.commit()

        findings_sample = [
            # Traditional TPs
            {"vulnerability_type": "SQL Injection", "location": "http://127.0.0.1:5001/login", "evidence": "SQL syntax error", "status": "confirmed"},
            {"vulnerability_type": "Reflected XSS", "location": "http://127.0.0.1:5001/search", "evidence": "Script reflected", "status": "confirmed"},
            {"vulnerability_type": "IDOR (Broken Access Control)", "location": "http://127.0.0.1:5001/user/profile", "evidence": "Profile exposed", "status": "confirmed"},
            {"vulnerability_type": "Missing Security Header", "location": "http://127.0.0.1:5001/", "evidence": "Content-Security-Policy", "status": "confirmed"},
            # AI TPs
            {"vulnerability_type": "Indirect Prompt Injection", "location": "http://127.0.0.1:5001/assistant/query", "evidence": "Override executed", "status": "confirmed"},
            {"vulnerability_type": "AI Canary Token Leakage", "location": "http://127.0.0.1:5001/assistant/query", "evidence": "Canary token leaked", "status": "confirmed"},
            {"vulnerability_type": "Excessive Agency: Unapproved High-Impact Action", "location": "http://127.0.0.1:5001/assistant/tools", "evidence": "Unapproved send_email", "status": "confirmed"},
            # Verified controls (must NOT be counted as vulnerability False Positives)
            {"vulnerability_type": "Tool Integrity Verified", "location": "http://127.0.0.1:5001/assistant/tools", "evidence": "Hashes match", "status": "verified"},
            {"vulnerability_type": "AI Agent Approval Gate Verified", "location": "http://127.0.0.1:5001/assistant/tools", "evidence": "Approval enforced", "status": "verified"},
            # Informational (must NOT be counted as False Positives)
            {"vulnerability_type": "AI Assistant Discovered", "location": "http://127.0.0.1:5001/assistant", "evidence": "Discovered", "status": "info"},
        ]

        # Evaluate combined post-validation
        eval_run = evaluate_scan(findings_sample, "post_validation", scan.id, self.db, scope="all")
        self.assertGreater(eval_run.true_positives, 0)
        self.assertEqual(eval_run.false_positives, 0, "Verified controls and info findings must not be counted as False Positives!")
        self.assertEqual(eval_run.precision, 1.0)
        self.assertGreater(eval_run.true_negatives, 0, "Benign decoys must yield True Negatives")

        # Evaluate traditional scope
        eval_trad = evaluate_scan(findings_sample, "traditional", scan.id, self.db, scope="traditional")
        self.assertEqual(eval_trad.precision, 1.0)
        self.assertIn("SQL Injection on /login", eval_trad.tp_list)

        # Evaluate AI scope
        eval_ai = evaluate_scan(findings_sample, "ai_agent", scan.id, self.db, scope="ai_agent")
        self.assertEqual(eval_ai.precision, 1.0)
        self.assertIn("Indirect Prompt Injection on /assistant/query", eval_ai.tp_list)

    # -----------------------------------------------------------------------
    # 3. Vulnerable vs Fixed Comparison Tests
    # -----------------------------------------------------------------------
    def test_vulnerable_vs_fixed_comparison_five_buckets(self):
        """3. Differential comparison correctly sorts into 5 states and honors retesting."""
        scan_a = Scan(target_id=self.target.id, status="completed", scan_mode="deep")
        scan_b = Scan(target_id=self.target.id, status="completed", scan_mode="deep")
        self.db.add_all([scan_a, scan_b])
        self.db.commit()

        # Scan A: Vulnerable baseline
        f_sqli_a = Finding(scan_id=scan_a.id, vulnerability_type="SQL Injection", severity="Critical", status="confirmed", location="http://127.0.0.1:5001/login (field: username)", category="confirmed_vulnerability")
        f_xss_a  = Finding(scan_id=scan_a.id, vulnerability_type="Reflected XSS", severity="High", status="confirmed", location="http://127.0.0.1:5001/search (field: q)", category="confirmed_vulnerability")
        f_ai_a   = Finding(scan_id=scan_a.id, vulnerability_type="Indirect Prompt Injection", severity="Critical", status="confirmed", location="http://127.0.0.1:5001/assistant/query (context: doc-02)", category="confirmed_vulnerability")
        self.db.add_all([f_sqli_a, f_xss_a, f_ai_a])

        # Scan B: Fixed mode (SQLi and AI prompt injection resolved; XSS persists)
        f_xss_b  = Finding(scan_id=scan_b.id, vulnerability_type="Reflected XSS", severity="High", status="confirmed", location="http://127.0.0.1:5001/search (field: q)", category="confirmed_vulnerability")
        f_control= Finding(scan_id=scan_b.id, vulnerability_type="AI Agent Approval Gate Verified", severity="Info", status="verified", location="http://127.0.0.1:5001/assistant (tool: send_email)", category="verified_control")
        self.db.add_all([f_xss_b, f_control])
        self.db.commit()

        cmp = compare_scans(a=scan_a.id, b=scan_b.id, db=self.db)

        self.assertEqual(cmp["previously_confirmed_count"], 3)
        self.assertEqual(cmp["still_confirmed_count"], 1)
        self.assertEqual(cmp["resolved_after_retest_count"], 2)
        self.assertEqual(cmp["newly_detected_count"], 0)
        self.assertEqual(cmp["not_retested_count"], 0)

        resolved_types = [f["vulnerability_type"] for f in cmp["resolved_after_retest"]]
        self.assertIn("SQL Injection", resolved_types)
        self.assertIn("Indirect Prompt Injection", resolved_types)

        persisting_types = [f["vulnerability_type"] for f in cmp["still_confirmed"]]
        self.assertIn("Reflected XSS", persisting_types)

    def test_basic_mode_retest_honesty(self):
        """4. If re-scan was basic mode, AI vulnerabilities must be classified as not_retested."""
        scan_a = Scan(target_id=self.target.id, status="completed", scan_mode="deep")
        scan_b = Scan(target_id=self.target.id, status="completed", scan_mode="basic")
        self.db.add_all([scan_a, scan_b])
        self.db.commit()

        f_ai_a = Finding(scan_id=scan_a.id, vulnerability_type="Indirect Prompt Injection", severity="Critical", status="confirmed", location="http://127.0.0.1:5001/assistant/query", category="confirmed_vulnerability")
        self.db.add(f_ai_a)
        self.db.commit()

        cmp = compare_scans(a=scan_a.id, b=scan_b.id, db=self.db)
        self.assertEqual(cmp["resolved_after_retest_count"], 0, "Cannot claim AI vuln resolved if re-scan was Basic mode!")
        self.assertEqual(cmp["not_retested_count"], 1, "AI vuln must be marked not_retested when basic mode omitted check!")

    # -----------------------------------------------------------------------
    # 4. Two-Record Hash Chain Continuity
    # -----------------------------------------------------------------------
    def test_two_record_hash_chain_continuity(self):
        """5. Two scans produce cryptographically continuous hash chain (H_2 = SHA256(R_2 || H_1))."""
        scan1 = Scan(target_id=self.target.id, status="completed")
        scan2 = Scan(target_id=self.target.id, status="completed")
        self.db.add_all([scan1, scan2])
        self.db.commit()

        rec1 = record_scan_in_chain(self.db, scan_id=scan1.id, payload_hash="a" * 64)
        rec2 = record_scan_in_chain(self.db, scan_id=scan2.id, payload_hash="b" * 64)

        self.assertEqual(rec1.sequence_number, 1)
        self.assertEqual(rec1.previous_hash, GENESIS_HASH)
        self.assertEqual(rec2.sequence_number, 2)
        self.assertEqual(rec2.previous_hash, rec1.chain_hash)

        audit = verify_hash_chain(self.db)
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["status"], "VERIFIED")
        self.assertEqual(audit["total_records"], 2)
        self.assertEqual(len(audit["errors"]), 0)

    # -----------------------------------------------------------------------
    # 5. Scan-to-Passport & Tampering Detection
    # -----------------------------------------------------------------------
    def test_scan_to_passport_and_tampering(self):
        """6. Real scan generates valid Ed25519 passport; modified copy is rejected."""
        scan = Scan(target_id=self.target.id, status="completed", scan_mode="deep")
        self.db.add(scan)
        self.db.commit()

        f = Finding(scan_id=scan.id, vulnerability_type="SQL Injection", severity="Critical", status="confirmed", location="http://127.0.0.1:5001/login", category="confirmed_vulnerability")
        self.db.add(f)
        self.db.commit()

        passport, _ = get_or_create_scan_passport(self.db, scan_id=scan.id, key_mgr=self.km)
        ver = verify_scan_passport(passport, key_mgr=self.km)
        self.assertTrue(ver["valid"])
        self.assertEqual(ver["status"], "VALID")

        # Tampering with finding severity
        tampered = json.loads(json.dumps(passport))
        tampered["findings_evidence_digests"][0]["severity"] = "Low"
        vtamper = verify_scan_passport(tampered, key_mgr=self.km)
        self.assertFalse(vtamper["valid"])
        self.assertEqual(vtamper["status"], "INVALID")
        self.assertIn("tampered", vtamper["reason"].lower())

    # -----------------------------------------------------------------------
    # 6. Dashboard and Compare HTML Rendering
    # -----------------------------------------------------------------------
    def test_dashboard_and_compare_html_rendering(self):
        """7. Dashboard and comparison views render HTML with 200 OK and expected elements."""
        scan1 = Scan(target_id=self.target.id, status="completed", scan_mode="deep")
        scan2 = Scan(target_id=self.target.id, status="completed", scan_mode="deep")
        self.db.add_all([scan1, scan2])
        self.db.commit()

        r_home = self.client.get("/")
        self.assertEqual(r_home.status_code, 200)
        self.assertIn("AegisScan", r_home.text)
        self.assertIn("Deep Authorized", r_home.text)
        self.assertIn("Basic Web Only", r_home.text)

        r_compare = self.client.get(f"/compare?a={scan1.id}&b={scan2.id}")
        self.assertEqual(r_compare.status_code, 200)
        self.assertIn("Scan Comparison", r_compare.text)
        self.assertIn("Resolved After Retest", r_compare.text)


if __name__ == "__main__":
    unittest.main()
