"""
scope.py -- AegisScan Scope Guard (shared utility)
===================================================
Central module that enforces host-based scope rules across the entire
scanner pipeline: crawler, detectors, validation, and any ad-hoc requests.

Usage
-----
from scope import ScopeGuard

guard = ScopeGuard(allowed_hosts={"127.0.0.1", "localhost"})
guard.check("http://127.0.0.1:5001/login")   # OK  -- returns None
guard.check("http://example.com/steal")       # raises OutOfScopeError

# httpx client that refuses to follow redirects off-scope:
with guard.client() as c:
    r = c.get("http://127.0.0.1:5001/search?q=test")

The guard.client() method returns a configured httpx.Client whose
event_hooks will log + block any redirect to an out-of-scope host.
"""

import os
import httpx
from urllib.parse import urlparse, urljoin


# ---------------------------------------------------------------------------
# Default allowed hosts (mirrors the API scope guard in routes.py)
# ---------------------------------------------------------------------------
DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class OutOfScopeError(Exception):
    """Raised when a URL's host is outside the allowed scope."""


def _get_allowed_hosts() -> set:
    """
    Build the set of permitted hosts from defaults + env var.
    Mirrors routes.get_allowed_hosts() so both use the same source of truth.
    """
    allowed = set(DEFAULT_ALLOWED_HOSTS)
    env_hosts = os.environ.get("AEGISSCAN_ALLOWED_HOSTS", "").strip()
    if env_hosts:
        for h in env_hosts.split(","):
            cleaned = h.strip().lower()
            if cleaned:
                allowed.add(cleaned)
    return allowed


class ScopeGuard:
    """
    Enforces host-based scope rules.

    Parameters
    ----------
    allowed_hosts : set | None
        Explicit set of allowed hostnames/IPs.
        If None, the set is built from DEFAULT_ALLOWED_HOSTS + the
        AEGISSCAN_ALLOWED_HOSTS environment variable.
    """

    def __init__(self, allowed_hosts=None):
        self.allowed_hosts = allowed_hosts if allowed_hosts is not None \
                             else _get_allowed_hosts()

    # ------------------------------------------------------------------
    # Core check
    # ------------------------------------------------------------------

    def is_allowed(self, url: str) -> bool:
        """Return True if url's host is within scope."""
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            hostname = ""
        return hostname.lower() in self.allowed_hosts

    def check(self, url: str, context: str = "") -> None:
        """
        Raise OutOfScopeError if url is out of scope.
        Also prints a standardised "skipped out-of-scope" log line.
        """
        if not self.is_allowed(url):
            msg = f"skipped out-of-scope: {url}"
            if context:
                msg = f"[{context}] {msg}"
            print(f"  [ScopeGuard] {msg}")
            raise OutOfScopeError(msg)

    # ------------------------------------------------------------------
    # Pre-configured httpx.Client
    # ------------------------------------------------------------------

    def client(self, **kwargs) -> httpx.Client:
        """
        Return an httpx.Client pre-configured with:
          - timeout=10
          - follow_redirects=True  (within scope only)
          - An event hook that raises OutOfScopeError if a redirect
            would take us to an out-of-scope host.

        Additional kwargs are forwarded to httpx.Client().
        """
        guard = self   # closure reference

        def _block_oos_redirect(response: httpx.Response) -> None:
            """
            Called by httpx before following each redirect.
            If the Location header points outside scope, raise immediately.
            """
            if response.is_redirect:
                location = response.headers.get("location", "")
                if location:
                    resolved_location = urljoin(str(response.url), location.strip())
                    if not guard.is_allowed(resolved_location):
                        print(f"  [ScopeGuard] skipped out-of-scope redirect: {location}")
                        raise OutOfScopeError(
                            f"Redirect blocked -- out-of-scope host: {location}"
                        )

        event_hooks = kwargs.pop("event_hooks", {})
        existing_response_hooks = list(event_hooks.get("response", []))
        event_hooks["response"] = [_block_oos_redirect] + existing_response_hooks

        return httpx.Client(
            timeout=kwargs.pop("timeout", 10),
            follow_redirects=kwargs.pop("follow_redirects", True),
            event_hooks=event_hooks,
            **kwargs,
        )
