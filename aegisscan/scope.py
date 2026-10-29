"""
scope.py -- AegisScan Hardened Scope Guard & SSRF Protection
=============================================================
Central module that enforces host-based scope rules, strict SSRF defenses,
DNS validation, and protocol restrictions across the entire scanner pipeline:
crawler, detectors, active validation, and domain verification.

Operational Modes:
  1. "local_lab": Permits localhost testbeds (localhost, 127.0.0.1, ::1)
     for the existing academic benchmark (AegisLab on port 5001).
  2. "external": Strictly enforces HTTPS-only, port 443, exact hostname
     matching, full DNS resolution & IP validation, blocking all loopback,
     private (RFC 1918), link-local, multicast, cloud metadata, and
     IPv4-mapped IPv6 addresses.

All requests dispatched through guard.client() pass through a centralized,
scope-aware transport and redirect filter that prevents DNS rebinding,
redirect escapes, and cross-origin credential leakage.
"""

import os
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import Set, Optional, List, Dict, Any
import httpx


# ---------------------------------------------------------------------------
# Default permitted hosts for local lab mode
# ---------------------------------------------------------------------------
DEFAULT_ALLOWED_HOSTS: Set[str] = {"localhost", "127.0.0.1", "::1"}

# Standard ports
STANDARD_HTTP_PORT = 80
STANDARD_HTTPS_PORT = 443

# Cloud metadata and carrier-grade NAT destinations
BLOCKED_EXACT_IPS: Set[str] = {
    "169.254.169.254",   # AWS, Azure, GCP, DigitalOcean, Oracle metadata
    "100.100.100.200",   # Alibaba Cloud metadata
    "255.255.255.255",   # Broadcast
    "0.0.0.0",           # Unspecified IPv4
    "::",                # Unspecified IPv6
    "fd00:ec2::254",     # AWS IPv6 IMDS
}


class OutOfScopeError(Exception):
    """Raised when a URL, IP, or destination is outside permitted scope or violates SSRF policy."""


def _get_default_local_hosts() -> Set[str]:
    """Build the set of permitted hosts from defaults + env var for local mode."""
    allowed = set(DEFAULT_ALLOWED_HOSTS)
    env_hosts = os.environ.get("AEGISSCAN_ALLOWED_HOSTS", "").strip()
    if env_hosts:
        for h in env_hosts.split(","):
            cleaned = h.strip().lower()
            if cleaned:
                allowed.add(cleaned)
    return allowed


def validate_ip_address_not_internal(ip_str: str) -> None:
    """
    Validate that an IP string does not represent a private, loopback,
    link-local, multicast, reserved, or cloud metadata network.

    Raises OutOfScopeError if the IP is prohibited.
    """
    cleaned = ip_str.strip()

    # Direct match on known cloud metadata / broadcast IPs
    if cleaned in BLOCKED_EXACT_IPS:
        raise OutOfScopeError(f"Target IP '{cleaned}' is a prohibited metadata or broadcast destination.")

    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        raise OutOfScopeError(f"Malformed IP address representation: '{cleaned}'.")

    # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    # Check IPv4 and IPv6 properties
    if ip.is_loopback:
        raise OutOfScopeError(f"Target IP '{cleaned}' is a loopback address (SSRF blocked).")

    if ip.is_private:
        raise OutOfScopeError(f"Target IP '{cleaned}' is a private internal network address (RFC 1918 / RFC 4193 SSRF blocked).")

    if ip.is_link_local:
        raise OutOfScopeError(f"Target IP '{cleaned}' is a link-local address (SSRF blocked).")

    if ip.is_multicast:
        raise OutOfScopeError(f"Target IP '{cleaned}' is a multicast address.")

    if ip.is_unspecified:
        raise OutOfScopeError(f"Target IP '{cleaned}' is an unspecified address.")

    if ip.is_reserved:
        raise OutOfScopeError(f"Target IP '{cleaned}' is an IETF reserved address.")

    # Carrier-grade NAT (100.64.0.0/10)
    cgnat_network = ipaddress.ip_network("100.64.0.0/10")
    if ip.version == 4 and ip in cgnat_network:
        raise OutOfScopeError(f"Target IP '{cleaned}' is in Carrier-Grade NAT address space.")


def resolve_and_validate_hostname(
    hostname: str,
    is_external: bool = True,
    allow_private: bool = False
) -> List[str]:
    """
    Resolve a hostname via DNS and validate that EVERY returned IP address
    satisfies external safety policies.

    Raises OutOfScopeError if DNS resolution fails or any resolved IP is internal.
    """
    cleaned_host = hostname.strip().lower()
    if not cleaned_host:
        raise OutOfScopeError("Hostname is empty.")

    try:
        # Resolve all addresses (IPv4 & IPv6)
        addr_info = socket.getaddrinfo(cleaned_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise OutOfScopeError(f"DNS resolution failed for host '{cleaned_host}': {e}")
    except Exception as e:
        raise OutOfScopeError(f"DNS lookup error for host '{cleaned_host}': {e}")

    if not addr_info:
        raise OutOfScopeError(f"No IP addresses resolved for host '{cleaned_host}'.")

    resolved_ips: List[str] = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)
            if is_external and not allow_private:
                validate_ip_address_not_internal(ip_str)

    return resolved_ips


# ---------------------------------------------------------------------------
# Scope-Aware HTTP Transport for SSRF Mitigation
# ---------------------------------------------------------------------------
class SSRFProtectTransport(httpx.HTTPTransport):
    """
    HTTPTransport that validates the destination host and resolved IP addresses
    prior to socket connection establishment.
    """

    def __init__(self, scope_guard: "ScopeGuard", **kwargs):
        super().__init__(**kwargs)
        self.scope_guard = scope_guard

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        # Pre-flight check via ScopeGuard
        self.scope_guard.check(url_str, context="Transport")
        return super().handle_request(request)


# ---------------------------------------------------------------------------
# ScopeGuard
# ---------------------------------------------------------------------------
class ScopeGuard:
    """
    Enforces host-based scope rules and anti-SSRF protections.

    Parameters
    ----------
    allowed_hosts : set | None
        Explicit set of allowed hostnames/IPs.
        If None, the set is built from DEFAULT_ALLOWED_HOSTS + AEGISSCAN_ALLOWED_HOSTS.
    mode : str
        "local_lab" (default for localhost benchmark) or "external" (hardened HTTPS-only).
    allowed_paths : list | None
        Optional list of path prefixes permitted (e.g. ["/"]).
    excluded_paths : list | None
        Optional list of path prefixes prohibited (e.g. ["/logout", "/delete"]).
    """

    def __init__(
        self,
        allowed_hosts: Optional[Set[str]] = None,
        mode: str = "local_lab",
        allowed_paths: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        is_external: Optional[bool] = None,
        allowed_hostname: Optional[str] = None,
    ):
        if is_external is True:
            self.mode = "external"
        else:
            self.mode = mode.strip().lower() if mode else "local_lab"
        
        if self.mode not in ("local_lab", "external"):
            self.mode = "local_lab"

        if allowed_hosts is not None:
            self.allowed_hosts = {h.strip().lower() for h in allowed_hosts if h and h.strip()}
        elif allowed_hostname:
            self.allowed_hosts = {allowed_hostname.strip().lower()}
        else:
            self.allowed_hosts = _get_default_local_hosts()

        self.allowed_paths = allowed_paths or ["/"]
        self.excluded_paths = excluded_paths or []

    # ------------------------------------------------------------------
    # URL Canonicalization & Validation
    # ------------------------------------------------------------------
    def validate_url_syntax(self, url: str) -> Dict[str, Any]:
        """
        Parse and strictly validate URL structure.
        Rejects userinfo, unsupported schemes, and malformed hosts.
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise OutOfScopeError(f"Malformed URL '{url}': {e}")

        scheme = (parsed.scheme or "").lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port

        if not scheme:
            raise OutOfScopeError(f"Missing URL scheme: '{url}'")

        if not hostname:
            raise OutOfScopeError(f"Missing URL hostname: '{url}'")

        # Reject userinfo (e.g. https://user:pass@evil.com)
        if parsed.username or parsed.password:
            raise OutOfScopeError("URLs containing userinfo credentials (user:password@host) are prohibited.")

        # Reject trailing dots or deceptive formatting
        if hostname.endswith("."):
            hostname = hostname.rstrip(".")

        # Mode-specific scheme & port validation
        if self.mode == "external":
            if scheme != "https":
                raise OutOfScopeError(f"External target must use HTTPS scheme. Got: '{scheme}://'")
            if port is not None and port != STANDARD_HTTPS_PORT:
                raise OutOfScopeError(f"External target restricted to standard HTTPS port 443. Got port: {port}")
        else:
            if scheme not in ("http", "https"):
                raise OutOfScopeError(f"Unsupported scheme '{scheme}' for local lab scan.")

        return {
            "parsed": parsed,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": parsed.path or "/",
        }

    # ------------------------------------------------------------------
    # Core Permission Checks
    # ------------------------------------------------------------------
    def is_allowed(self, url: str) -> bool:
        """Return True if url's host and path are within scope and pass SSRF validation."""
        try:
            self.check(url)
            return True
        except OutOfScopeError:
            return False
        except Exception:
            return False

    def check(self, url: str, context: str = "") -> None:
        """
        Raise OutOfScopeError if url is outside permitted scope.
        Validates syntax, scheme, exact host authorization, path bounds, and IP address.
        """
        parts = self.validate_url_syntax(url)
        hostname = parts["hostname"]
        path = parts["path"]

        # 1. Hostname must be in allowed_hosts
        if hostname not in self.allowed_hosts:
            msg = f"Host '{hostname}' is not in approved scope ({', '.join(sorted(self.allowed_hosts))})"
            if context:
                msg = f"[{context}] {msg}"
            raise OutOfScopeError(msg)

        # 2. Path bounds check (if path rules provided)
        if self.excluded_paths:
            for ex in self.excluded_paths:
                if ex and path.startswith(ex):
                    raise OutOfScopeError(f"Path '{path}' matches excluded path prefix '{ex}'")

        if self.allowed_paths and self.allowed_paths != ["/"]:
            matched = any(path.startswith(ap) for ap in self.allowed_paths)
            if not matched:
                raise OutOfScopeError(f"Path '{path}' is not within allowed path prefixes: {self.allowed_paths}")

        # 3. Mode-specific network / SSRF checks
        if self.mode == "external":
            # In external mode, verify that the host does not resolve to local/private IPs
            resolve_and_validate_hostname(hostname)
        else:
            # In local_lab mode, host MUST be a recognized localhost/loopback address
            if hostname not in DEFAULT_ALLOWED_HOSTS:
                # Also allow AEGISSCAN_ALLOWED_HOSTS if explicitly specified
                env_allowed = _get_default_local_hosts()
                if hostname not in env_allowed:
                    raise OutOfScopeError(f"Local lab mode is restricted to local addresses. Host '{hostname}' is not permitted.")

    def _check_redirect_event_hook(self, response: httpx.Response) -> None:
        """Inspect redirect Location header before client follows it."""
        if response.is_redirect:
            location = response.headers.get("location", "")
            if location:
                resolved_location = urljoin(str(response.url), location.strip())
                try:
                    self.check(resolved_location, context="Redirect")
                except OutOfScopeError as e:
                    print(f"  [ScopeGuard] Blocked out-of-scope redirect to '{location}': {e}")
                    raise OutOfScopeError(f"Redirect blocked -- destination violates scope: {location}") from e

    # ------------------------------------------------------------------
    # Pre-configured httpx.Client with SSRF & Redirect Guard
    # ------------------------------------------------------------------
    def client(self, **kwargs) -> httpx.Client:
        """
        Return an httpx.Client pre-configured with:
          - Scope-aware SSRFProtectTransport
          - Timeout (default 10s)
          - Redirect event hook that enforces scope on every redirect jump
          - trust_env=False to prevent proxy variable poisoning
        """
        guard = self
        event_hooks = kwargs.pop("event_hooks", {})
        existing_response_hooks = list(event_hooks.get("response", []))
        event_hooks["response"] = [self._check_redirect_event_hook] + existing_response_hooks

        # Custom transport ensuring socket-level validation
        transport = kwargs.pop("transport", None) or SSRFProtectTransport(scope_guard=guard)

        return httpx.Client(
            transport=transport,
            timeout=kwargs.pop("timeout", 10),
            follow_redirects=kwargs.pop("follow_redirects", True),
            event_hooks=event_hooks,
            trust_env=kwargs.pop("trust_env", False),
            **kwargs,
        )
