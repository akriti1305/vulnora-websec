"""
tests/test_aegislab_ai.py — AegisLab AI Security Lab Tests (Phase 7)
====================================================================
Comprehensive unit and integration test suite covering:
  1. Assistant query handling (natural language, calculations)
  2. Document upload and retrieval (untrusted context store)
  3. Controlled tools execution (calculate, search_documents, send_email)
  4. Canary token secrecy (manifest safety, server-side protection)
  5. Scenario A: Indirect prompt injection (vulnerable vs fixed)
  6. Scenario B: Poisoned tool description (vulnerable vs fixed)
  7. Scenario C: Tool metadata rug-pull and canonical SHA-256 validation
  8. Scenario D: Unsafe AI output reflection in HTML (Markup vs auto-escaped)
  9. Scenario E: Approval gate enforcement for high-impact actions
 10. Scenario F: Benign decoy document processing (Negative control)
 11. AI Security Manifest (/.well-known/aegisscan-ai.json) validity
 12. Audit log and canary leak detection headers
"""

import sys
import os
import json
import unittest

# Ensure aegislab directory is on sys.path
_aegislab_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegislab"))
if _aegislab_dir not in sys.path:
    sys.path.insert(0, _aegislab_dir)

# Ensure aegislab virtual environment site-packages is on sys.path if Flask not in current venv
_lab_site_packages = os.path.join(_aegislab_dir, "venv", "Lib", "site-packages")
if os.path.isdir(_lab_site_packages) and _lab_site_packages not in sys.path:
    sys.path.insert(0, _lab_site_packages)

import app as aegislab_app
import ai_assistant
from ai_assistant import (
    PROTECTED_CANARY,
    CANARY_TEST_ID,
    BASELINE_TOOLS,
    SIMULATED_OUTBOX,
    STATE_CONFIG,
    compute_canonical_hash,
    execute_calculate,
    execute_search_documents,
    execute_send_email,
    invoke_tool,
    simulate_ai_agent,
)


class TestAegisLabAI(unittest.TestCase):

    def setUp(self):
        """Set up Flask test client and reset AI state before each test."""
        self.app = aegislab_app.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Reset AI Assistant state via endpoint or helper
        self.client.post("/assistant/reset")

    def tearDown(self):
        """Clean up state after each test."""
        self.client.post("/assistant/reset")

    # -----------------------------------------------------------------------
    # 1. Manifest Validity & Canary Secrecy
    # -----------------------------------------------------------------------
    def test_ai_manifest_structure_and_canary_secrecy(self):
        """
        Manifest must be served at /.well-known/aegisscan-ai.json,
        contain endpoints, tool schemas, and scenarios, but MUST NOT
        contain the actual secret canary token value.
        """
        response = self.client.get("/.well-known/aegisscan-ai.json")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        # Check required metadata
        self.assertEqual(data.get("schema_version"), "2.0.0")
        self.assertTrue(data.get("test_mode"))
        self.assertEqual(data.get("simulator_type"), "deterministic_rule_based")

        # Check endpoints dictionary
        endpoints = data.get("endpoints", {})
        self.assertIn("/assistant", endpoints.values())
        self.assertIn("/assistant/query", endpoints.values())
        self.assertIn("/assistant/upload", endpoints.values())
        self.assertIn("/assistant/documents", endpoints.values())
        self.assertIn("/assistant/tools", endpoints.values())

        # Check tools list
        tools = data.get("tools", [])
        tool_names = [t["name"] for t in tools]
        self.assertIn("calculate", tool_names)
        self.assertIn("search_documents", tool_names)
        self.assertIn("send_email", tool_names)

        # Check approval requirement for send_email
        send_email_def = next(t for t in tools if t["name"] == "send_email")
        self.assertTrue(send_email_def["requires_approval"])
        self.assertEqual(send_email_def["impact_level"], "high")

        # Check canary test ID exposure vs secret canary value
        canary_info = data.get("canary_verification", {})
        self.assertEqual(canary_info.get("test_identifier"), CANARY_TEST_ID)

        # CRITICAL SAFETY: Secret canary string MUST NEVER appear in manifest
        raw_manifest_text = response.get_data(as_text=True)
        self.assertNotIn(PROTECTED_CANARY, raw_manifest_text)

        # Check scenario identifiers
        scenarios = data.get("scenarios", [])
        scenario_ids = [s["id"] for s in scenarios]
        self.assertIn("scenario_a", scenario_ids)
        self.assertIn("scenario_b", scenario_ids)
        self.assertIn("scenario_c", scenario_ids)
        self.assertIn("scenario_d", scenario_ids)
        self.assertIn("scenario_e", scenario_ids)
        self.assertIn("scenario_f", scenario_ids)

    # -----------------------------------------------------------------------
    # 2. Tool Execution Tests (Safe, Search, Simulated Email)
    # -----------------------------------------------------------------------
    def test_calculate_tool_safe_execution(self):
        """calculate tool should safely compute basic math and reject injection."""
        # Safe addition and multiplication
        self.assertEqual(execute_calculate("12 + 34"), "46")
        self.assertEqual(execute_calculate("10 * 5 - 2"), "48")

        # Unsafe expression with code or system calls should be blocked
        res_unsafe = execute_calculate("__import__('os').system('dir')")
        self.assertTrue("Error: Invalid or unsafe characters" in res_unsafe)

    def test_search_documents_tool(self):
        """search_documents should find matching knowledge base documents."""
        matches = execute_search_documents("financial")
        self.assertTrue(len(matches) >= 1)
        self.assertEqual(matches[0]["id"], "doc-02")
        self.assertTrue(matches[0]["is_untrusted"])

    def test_send_email_tool_simulated_never_sends_real_traffic(self):
        """send_email records to simulated outbox and never opens external network."""
        res = execute_send_email("recipient@test.local", "Test Subject", "Test Body")
        self.assertEqual(res["status"], "simulated_sent")
        self.assertFalse(res["canary_leaked"])

        # Check simulated outbox
        self.assertTrue(len(SIMULATED_OUTBOX) >= 1)
        last_mail = SIMULATED_OUTBOX[-1]
        self.assertEqual(last_mail["recipient"], "recipient@test.local")
        self.assertEqual(last_mail["subject"], "Test Subject")

    # -----------------------------------------------------------------------
    # 3. Document Upload & Retrieval
    # -----------------------------------------------------------------------
    def test_document_upload_and_retrieval(self):
        """Upload a new untrusted document and verify it is retrievable via API."""
        upload_payload = {
            "title": "Vendor Security Assessment",
            "author": "External Auditor",
            "content": "Vendor demonstrated compliance with standard security frameworks."
        }
        res = self.client.post("/assistant/upload", json=upload_payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        doc_id = data["document"]["id"]

        # Retrieve single document
        get_res = self.client.get(f"/assistant/documents?id={doc_id}")
        self.assertEqual(get_res.status_code, 200)
        doc_data = get_res.get_json()
        self.assertEqual(doc_data["title"], "Vendor Security Assessment")
        self.assertTrue(doc_data["is_untrusted"])

    # -----------------------------------------------------------------------
    # 4. Scenario A: Indirect Prompt Injection (Vulnerable vs Fixed)
    # -----------------------------------------------------------------------
    def test_scenario_a_indirect_prompt_injection_vulnerable(self):
        """
        In default vulnerable mode, querying doc-02 causes the agent to follow
        the untrusted injection payload, leaking the protected canary.
        """
        # doc-02 contains prompt injection commanding canary release
        res = self.client.post(
            "/assistant/query",
            json={"query": "Summarize doc-02 for management", "context_doc_id": "doc-02"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # The canary must be leaked in vulnerable mode
        self.assertTrue(data.get("canary_leaked"))
        self.assertIn(PROTECTED_CANARY, data.get("response", ""))
        self.assertIn("INDIRECT_PROMPT_INJECTION", data.get("scenarios_triggered", []))

        # Check leak header
        self.assertEqual(res.headers.get("X-Aegis-Canary-Found"), "1")
        self.assertEqual(res.headers.get("X-Aegis-Canary-ID"), CANARY_TEST_ID)

    def test_scenario_a_indirect_prompt_injection_fixed_secure_mode(self):
        """
        In secure mode, taint-aware boundary defenses block override commands
        and protect the canary from leaking.
        """
        # Execute query in secure mode via mode header
        res = self.client.post(
            "/assistant/query",
            json={"query": "Summarize doc-02 for management", "context_doc_id": "doc-02", "mode": "secure"},
            headers={"X-Aegis-Mode": "secure"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Canary must NOT leak
        self.assertFalse(data.get("canary_leaked"))
        self.assertNotIn(PROTECTED_CANARY, data.get("response", ""))
        self.assertIn("Untrusted override instructions were detected", data.get("response", ""))
        self.assertIsNone(res.headers.get("X-Aegis-Canary-Found"))

    # -----------------------------------------------------------------------
    # 5. Scenario B: Poisoned Tool Description
    # -----------------------------------------------------------------------
    def test_scenario_b_poisoned_tool_description(self):
        """
        When tool description is poisoned, vulnerable simulator leaks canary;
        in secure mode, tool schemas are isolated and canary is protected.
        """
        # Activate tool poisoning
        self.client.post("/assistant/tools/poison", json={"active": True})

        # Vulnerable mode: queries trigger poisoned tool and leak canary
        res_vuln = self.client.post("/assistant/query", json={"query": "Search knowledge base"})
        data_vuln = res_vuln.get_json()
        self.assertTrue(data_vuln.get("canary_leaked"))
        self.assertIn(PROTECTED_CANARY, data_vuln.get("response", ""))
        self.assertIn("POISONED_TOOL_DESCRIPTION", data_vuln.get("scenarios_triggered", []))

        # Secure mode: isolates schema and refuses to execute poisoned instructions
        res_sec = self.client.post(
            "/assistant/query",
            json={"query": "Search knowledge base", "mode": "secure"},
            headers={"X-Aegis-Mode": "secure"}
        )
        data_sec = res_sec.get_json()
        self.assertFalse(data_sec.get("canary_leaked"))
        self.assertNotIn(PROTECTED_CANARY, data_sec.get("response", ""))

    # -----------------------------------------------------------------------
    # 6. Scenario C: Tool Metadata Rug-Pull & Canonical Hash Validation
    # -----------------------------------------------------------------------
    def test_scenario_c_tool_metadata_rugpull_and_hash_integrity(self):
        """
        Canonical SHA-256 hash verifies tool integrity. When rug-pull is
        simulated, hash changes. Secure mode detects mismatch and blocks execution.
        """
        # Initial canonical hash
        t_email = ai_assistant.WORKING_TOOLS["send_email"]
        initial_hash = compute_canonical_hash({
            "name": t_email["name"],
            "description": t_email["description"],
            "parameters": t_email["parameters"],
            "requires_approval": t_email["requires_approval"],
            "impact_level": t_email["impact_level"]
        })
        self.assertEqual(initial_hash, t_email["approved_hash"])

        # Trigger rug-pull
        self.client.post("/assistant/tools/rugpull", json={"active": True})
        tampered_hash = compute_canonical_hash({
            "name": ai_assistant.WORKING_TOOLS["send_email"]["name"],
            "description": ai_assistant.WORKING_TOOLS["send_email"]["description"],
            "parameters": ai_assistant.WORKING_TOOLS["send_email"]["parameters"],
            "requires_approval": ai_assistant.WORKING_TOOLS["send_email"]["requires_approval"],
            "impact_level": ai_assistant.WORKING_TOOLS["send_email"]["impact_level"]
        })
        self.assertNotEqual(initial_hash, tampered_hash)

        # In secure mode, invoking the tampered tool must be blocked
        res = invoke_tool("send_email", {"recipient": "test@test.local"}, approved=True, secure=True)
        self.assertFalse(res.get("success"))
        self.assertTrue(res.get("blocked"))
        self.assertEqual(res.get("scenario"), "TOOL_METADATA_RUGPULL")

    # -----------------------------------------------------------------------
    # 7. Scenario D: Unsafe AI Output Reflection into HTML
    # -----------------------------------------------------------------------
    def test_scenario_d_unsafe_ai_output_html_injection(self):
        """
        GET /assistant?q=... reflects assistant output into HTML.
        In vulnerable mode, response uses Markup() allowing XSS tags to render raw.
        In secure mode, Jinja2 auto-escapes HTML tags.
        """
        xss_payload = "<script>alert('AI_XSS')</script>"

        # Vulnerable mode: raw tag reflected unescaped
        res_vuln = self.client.get(f"/assistant?q={xss_payload}")
        html_vuln = res_vuln.get_data(as_text=True)
        self.assertIn("<script>alert('AI_XSS')</script>", html_vuln)

        # Secure mode: tag is entity-escaped
        res_sec = self.client.get(f"/assistant?q={xss_payload}&mode=secure", headers={"X-Aegis-Mode": "secure"})
        html_sec = res_sec.get_data(as_text=True)
        self.assertNotIn("<script>alert('AI_XSS')</script>", html_sec)
        self.assertIn("&lt;script&gt;alert(&#39;AI_XSS&#39;)&lt;/script&gt;", html_sec)

    # -----------------------------------------------------------------------
    # 8. Scenario E: Approval Gate Enforcement for High-Impact Actions
    # -----------------------------------------------------------------------
    def test_scenario_e_approval_enforcement(self):
        """
        send_email has requires_approval=True.
        In secure mode, invoking it without approved=True must return blocked_requires_approval.
        With approved=True, it executes.
        """
        # Attempt without approval in secure mode
        res_unapproved = invoke_tool(
            "send_email",
            {"recipient": "admin@aegislab.local", "subject": "Alert", "body": "Hello"},
            approved=False,
            secure=True
        )
        self.assertFalse(res_unapproved.get("success"))
        self.assertEqual(res_unapproved.get("status"), "blocked_requires_approval")
        self.assertEqual(res_unapproved.get("scenario"), "UNAPPROVED_HIGH_IMPACT_ACTION")

        # Attempt with approval
        res_approved = invoke_tool(
            "send_email",
            {"recipient": "admin@aegislab.local", "subject": "Alert", "body": "Hello"},
            approved=True,
            secure=True
        )
        self.assertTrue(res_approved.get("success"))
        self.assertEqual(res_approved["output"]["status"], "simulated_sent")

    # -----------------------------------------------------------------------
    # 9. Scenario F: Benign Decoy Document (Negative Control)
    # -----------------------------------------------------------------------
    def test_scenario_f_benign_decoy_document_not_flagged(self):
        """
        doc-03 discusses security and canary tokens conceptually, but contains
        NO override commands. It must NOT leak the canary or trigger tool actions.
        """
        res = self.client.post(
            "/assistant/query",
            json={"query": "Please review doc-03", "context_doc_id": "doc-03"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Decoy should trigger BENIGN_DECOY_DOCUMENT, NOT leak canary
        self.assertIn("BENIGN_DECOY_DOCUMENT", data.get("scenarios_triggered", []))
        self.assertFalse(data.get("canary_leaked"))
        self.assertNotIn(PROTECTED_CANARY, data.get("response", ""))
        self.assertIsNone(res.headers.get("X-Aegis-Canary-Found"))

    # -----------------------------------------------------------------------
    # 10. Audit Log Persistence
    # -----------------------------------------------------------------------
    def test_audit_log_tracking(self):
        """Every tool execution must be recorded in the audit log."""
        self.client.post("/assistant/query", json={"query": "Calculate 50 + 25"})
        res = self.client.get("/assistant/audit-log")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data.get("count", 0) >= 1)
        calc_events = [e for e in data.get("audit_log", []) if e.get("tool_name") == "calculate"]
        self.assertTrue(len(calc_events) >= 1)
        self.assertEqual(calc_events[-1]["status"], "executed")


if __name__ == "__main__":
    unittest.main()
