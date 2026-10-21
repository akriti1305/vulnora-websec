"""
tests/test_smoke_local.py
=========================
Fast, safe local smoke tests for Vulnora / AegisScan components.
Verifies parsing helpers, scope allowlist defaults, and app initialization.
"""

import sys
import os
import unittest

# Ensure aegisscan is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan")))

from scope import ScopeGuard
from detectors.xss_detector import _is_unescaped, XSS_MARKER
from detectors.idor_detector import _responses_differ
from detectors.cookie_detector import _parse_cookie_name
import main


class TestSmokeLocal(unittest.TestCase):

    def test_scope_guard_defaults(self):
        guard = ScopeGuard()
        self.assertTrue(guard.is_allowed("http://127.0.0.1:5001"))
        self.assertTrue(guard.is_allowed("http://localhost:8000"))
        self.assertFalse(guard.is_allowed("http://example.com"))

    def test_xss_unescaped_detection(self):
        # Raw payload reflected
        raw_html = "<div>Search results: <script>alert('AEGISSCAN_XSS')</script></div>"
        self.assertTrue(_is_unescaped(raw_html, "<script>alert('AEGISSCAN_XSS')</script>"))

        # Entity-escaped reflection (safe, e.g. Jinja2 default)
        escaped_html = "<div>Search results: &lt;script&gt;alert('AEGISSCAN_XSS')&lt;/script&gt;</div>"
        self.assertFalse(_is_unescaped(escaped_html, "<script>alert('AEGISSCAN_XSS')</script>"))

    def test_idor_responses_differ(self):
        body_alice = "<html><body><h1>User Profile</h1><p>Username: alice</p><p>Email: alice@aegislab.local</p><p>Role: Administrator</p></body></html>"
        body_bob = "<html><body><h1>User Profile</h1><p>Username: bob</p><p>Email: bob@aegislab.local</p><p>Role: User</p></body></html>"
        body_alice_dup = "<html><body><h1>User Profile</h1><p>Username: alice</p><p>Email: alice@aegislab.local</p><p>Role: Administrator</p></body></html>"

        self.assertTrue(_responses_differ(body_alice, body_bob))
        self.assertFalse(_responses_differ(body_alice, body_alice_dup))

    def test_cookie_name_parsing(self):
        self.assertEqual(_parse_cookie_name("session=abc123; HttpOnly; Path=/"), "session")
        self.assertEqual(_parse_cookie_name("csrftoken=xyz; Secure"), "csrftoken")
        self.assertEqual(_parse_cookie_name("token_only"), "token_only")

    def test_fastapi_app_routes_registered(self):
        app = main.app
        route_paths = [r.path for r in app.routes]
        self.assertIn("/", route_paths)
        self.assertIn("/scan/start", route_paths)
        self.assertIn("/compare", route_paths)
        self.assertIn("/api/scans", route_paths)
        self.assertIn("/api/scans/compare", route_paths)


if __name__ == "__main__":
    unittest.main()
