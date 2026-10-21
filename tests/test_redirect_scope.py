"""
tests/test_redirect_scope.py
============================
Unit tests for ScopeGuard redirect handling and host-based scope rules.
Verifies that:
  - Relative redirects (e.g. /profile) are resolved against response.url
  - Absolute in-scope redirects are permitted
  - Absolute out-of-scope and protocol-relative redirects are strictly blocked
"""

import sys
import os
import unittest
from unittest.mock import MagicMock
import httpx

# Ensure aegisscan is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan")))

from scope import ScopeGuard, OutOfScopeError


class TestScopeGuardRedirects(unittest.TestCase):

    def setUp(self):
        self.guard = ScopeGuard(allowed_hosts={"127.0.0.1", "localhost", "::1"})

    def test_host_allowlist(self):
        self.assertTrue(self.guard.is_allowed("http://127.0.0.1:5001/login"))
        self.assertTrue(self.guard.is_allowed("http://localhost:8000/"))
        self.assertTrue(self.guard.is_allowed("http://[::1]:8000/api"))
        self.assertFalse(self.guard.is_allowed("http://example.com/"))
        self.assertFalse(self.guard.is_allowed("http://192.168.1.1/admin"))
        self.assertFalse(self.guard.is_allowed("http://evil.com/steal"))

    def test_relative_redirect_allowed(self):
        """A relative redirect like Location: /profile must resolve to response.url and pass."""
        client = self.guard.client()
        # Retrieve the response event hook installed by ScopeGuard
        hooks = client.event_hooks.get("response", [])
        self.assertTrue(len(hooks) >= 1)
        hook = hooks[0]

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.is_redirect = True
        mock_resp.url = httpx.URL("http://127.0.0.1:5001/login")
        mock_resp.headers = {"location": "/profile"}

        # Should not raise OutOfScopeError because /profile resolves to http://127.0.0.1:5001/profile
        try:
            hook(mock_resp)
        except OutOfScopeError:
            self.fail("Hook raised OutOfScopeError unexpectedly on a valid relative redirect!")

    def test_absolute_in_scope_redirect_allowed(self):
        """An absolute redirect to an in-scope host must be permitted."""
        client = self.guard.client()
        hook = client.event_hooks["response"][0]

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.is_redirect = True
        mock_resp.url = httpx.URL("http://127.0.0.1:5001/login")
        mock_resp.headers = {"location": "http://127.0.0.1:5001/dashboard"}

        try:
            hook(mock_resp)
        except OutOfScopeError:
            self.fail("Hook raised OutOfScopeError on an in-scope absolute redirect!")

    def test_absolute_out_of_scope_redirect_blocked(self):
        """An absolute redirect to an external host must raise OutOfScopeError."""
        client = self.guard.client()
        hook = client.event_hooks["response"][0]

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.is_redirect = True
        mock_resp.url = httpx.URL("http://127.0.0.1:5001/login")
        mock_resp.headers = {"location": "http://attacker.com/steal"}

        with self.assertRaises(OutOfScopeError):
            hook(mock_resp)

    def test_protocol_relative_out_of_scope_redirect_blocked(self):
        """Protocol-relative redirects (//evil.com/test) must resolve and be blocked."""
        client = self.guard.client()
        hook = client.event_hooks["response"][0]

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.is_redirect = True
        mock_resp.url = httpx.URL("http://127.0.0.1:5001/login")
        mock_resp.headers = {"location": "//evil.com/test"}

        with self.assertRaises(OutOfScopeError):
            hook(mock_resp)

    def test_non_redirect_ignored(self):
        """Non-redirect responses must pass through the hook without action."""
        client = self.guard.client()
        hook = client.event_hooks["response"][0]

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.is_redirect = False
        mock_resp.headers = {"location": "http://evil.com/steal"}

        # Should do nothing since is_redirect is False
        hook(mock_resp)


if __name__ == "__main__":
    unittest.main()
