"""
tests/test_cookie_scope.py
==========================
Unit tests verifying scope enforcement in cookie_detector.py.
Ensures:
  - Out-of-scope pages are skipped without outbound requests.
  - Form actions pointing out-of-scope are skipped without submitting credentials.
  - In-scope pages and forms are processed safely.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import httpx

# Ensure aegisscan is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan")))

from discovery.crawler import DiscoveryResult, PageInfo, PageForm, FormField
from detectors.cookie_detector import detect, CookieFinding


class TestCookieDetectorScope(unittest.TestCase):

    @patch("scope.ScopeGuard.is_allowed")
    def test_out_of_scope_page_skipped(self, mock_is_allowed):
        """Pages that are out of scope must not trigger a GET request."""
        # Only allow 127.0.0.1
        def allowed_side_effect(url):
            return "127.0.0.1" in url
        mock_is_allowed.side_effect = allowed_side_effect

        out_of_scope_page = PageInfo(
            url="http://malicious-external-site.com/profile",
            links=[],
            forms=[],
            response_headers={},
            cookies={},
            status_code=200
        )
        discovery = DiscoveryResult(
            base_url="http://127.0.0.1:5001",
            pages=[out_of_scope_page],
            all_forms=[],
            visited_urls=["http://malicious-external-site.com/profile"]
        )

        with patch("httpx.Client.get") as mock_get:
            findings = detect(discovery)
            mock_get.assert_not_called()
            self.assertEqual(findings, [])

    def test_out_of_scope_form_action_skipped(self):
        """Forms whose action points to an external site must not be submitted."""
        # Form pointing to evil.com
        external_form = PageForm(
            page_url="http://127.0.0.1:5001/phish",
            action="http://evil.com/steal-creds",
            method="POST",
            fields=[
                FormField(name="username", field_type="text"),
                FormField(name="password", field_type="password")
            ]
        )
        in_scope_page = PageInfo(
            url="http://127.0.0.1:5001/phish",
            links=[],
            forms=[external_form],
            response_headers={},
            cookies={},
            status_code=200
        )
        discovery = DiscoveryResult(
            base_url="http://127.0.0.1:5001",
            pages=[in_scope_page],
            all_forms=[external_form],
            visited_urls=["http://127.0.0.1:5001/phish"]
        )

        # Mock GET to return 200 without set-cookie
        mock_get_resp = MagicMock(spec=httpx.Response)
        mock_get_resp.headers = httpx.Headers({})
        mock_get_resp.is_redirect = False

        with patch("httpx.Client.get", return_value=mock_get_resp), \
             patch("httpx.Client.post") as mock_post:
            findings = detect(discovery)
            # The POST to evil.com must NEVER be called
            mock_post.assert_not_called()
            self.assertEqual(findings, [])

    def test_in_scope_form_submits_credentials(self):
        """Forms with valid in-scope action must be tested and cookies inspected."""
        in_scope_form = PageForm(
            page_url="http://127.0.0.1:5001/login",
            action="http://127.0.0.1:5001/login",
            method="POST",
            fields=[
                FormField(name="username", field_type="text"),
                FormField(name="password", field_type="password")
            ]
        )
        page = PageInfo(
            url="http://127.0.0.1:5001/login",
            links=[],
            forms=[in_scope_form],
            response_headers={},
            cookies={},
            status_code=200
        )
        discovery = DiscoveryResult(
            base_url="http://127.0.0.1:5001",
            pages=[page],
            all_forms=[in_scope_form],
            visited_urls=["http://127.0.0.1:5001/login"]
        )

        mock_get_resp = MagicMock(spec=httpx.Response)
        mock_get_resp.headers = httpx.Headers({})
        mock_get_resp.is_redirect = False

        mock_post_resp = MagicMock(spec=httpx.Response)
        # Header without HttpOnly or Secure
        mock_post_resp.headers = httpx.Headers([("Set-Cookie", "session=12345; Path=/")])
        mock_post_resp.is_redirect = False

        with patch("httpx.Client.get", return_value=mock_get_resp), \
             patch("httpx.Client.post", return_value=mock_post_resp) as mock_post:
            findings = detect(discovery)

            # POST was called to in-scope action
            mock_post.assert_called_once()
            called_action = mock_post.call_args[0][0]
            self.assertEqual(called_action, "http://127.0.0.1:5001/login")

            # Check that missing HttpOnly and Secure were flagged
            flags = {f.missing_flag for f in findings}
            self.assertIn("HttpOnly", flags)
            self.assertIn("Secure", flags)


if __name__ == "__main__":
    unittest.main()
