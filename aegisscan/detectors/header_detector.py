"""
detectors/header_detector.py -- AegisScan Missing Security Headers Detector
============================================================================
Checks the crawled pages for missing HTTP security headers.

Design (Phase 5 fix):
  Headers are a per-application setting, not per-page — if CSP is missing
  from one Flask route it is missing from ALL of them (because you add it
  once via a @app.after_request hook or flask-talisman, not per route).

  So we deduplicate GLOBALLY by header name:
    - We report each missing header ONCE, citing the first page that was
      missing it.
    - This gives a maximum of 4 findings, not 4 × N_pages.

Security headers checked:
  - Content-Security-Policy   → Missing = "Medium"
  - Strict-Transport-Security → Missing = "Medium"
  - X-Frame-Options           → Missing = "Low"
  - X-Content-Type-Options    → Missing = "Low"

No validation step needed: a missing header is directly observable.
"""

from dataclasses import dataclass
from typing import List, Dict
from urllib.parse import urlparse
from discovery.crawler import DiscoveryResult


# ---------------------------------------------------------------------------
# Required security headers catalogue
# ---------------------------------------------------------------------------
REQUIRED_HEADERS: Dict[str, Dict] = {
    "content-security-policy": {
        "display_name": "Content-Security-Policy",
        "severity": "Medium",
        "remediation": (
            "Add a Content-Security-Policy header to all responses. "
            "A safe starting point: Content-Security-Policy: default-src 'self'. "
            "In Flask: use flask-talisman or set "
            "response.headers['Content-Security-Policy'] = \"default-src 'self'\" "
            "inside an @app.after_request handler."
        ),
    },
    "strict-transport-security": {
        "display_name": "Strict-Transport-Security",
        "severity": "Medium",
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains "
            "to all HTTPS responses. "
            "Note: only set this on production HTTPS sites — not on local HTTP servers."
        ),
    },
    "x-frame-options": {
        "display_name": "X-Frame-Options",
        "severity": "Low",
        "remediation": (
            "Add: X-Frame-Options: DENY (or SAMEORIGIN if you need iframes on your own site). "
            "In Flask: response.headers['X-Frame-Options'] = 'DENY'."
        ),
    },
    "x-content-type-options": {
        "display_name": "X-Content-Type-Options",
        "severity": "Low",
        "remediation": (
            "Add: X-Content-Type-Options: nosniff to all responses. "
            "In Flask: response.headers['X-Content-Type-Options'] = 'nosniff'."
        ),
    },
}


@dataclass
class HeaderFinding:
    """
    One missing security header for the whole application.

    page_url    : first crawled page that was missing this header
    header_name : display name of the missing header
    severity    : Medium or Low
    remediation : how to add it
    evidence    : which headers ARE present (or "none at all")
    """
    page_url: str
    header_name: str
    severity: str
    remediation: str
    evidence: str


def detect(discovery: DiscoveryResult) -> List[HeaderFinding]:
    """
    Check all crawled pages for missing security headers.

    Deduplication rule: each header is reported ONCE per application,
    not once per page. We cite the first page that showed the header missing.

    Args:
        discovery: DiscoveryResult from crawler.crawl()

    Returns:
        List of HeaderFinding -- at most 4 items (one per header checked).
    """
    findings: List[HeaderFinding] = []

    # Keys of headers we have already reported (deduplicate globally)
    reported_headers: set = set()

    for page in discovery.pages:
        # Normalise path for logging — strip query string and trailing slash
        norm_path = urlparse(page.url).path.rstrip("/") or "/"

        headers_lower = {k.lower(): v for k, v in page.response_headers.items()}

        for header_key, info in REQUIRED_HEADERS.items():

            # Already found and reported this header as missing — skip
            if header_key in reported_headers:
                continue

            if header_key not in headers_lower:
                # Summarise which security headers ARE present on this page
                present = [
                    info2["display_name"]
                    for k2, info2 in REQUIRED_HEADERS.items()
                    if k2 in headers_lower
                ]
                if present:
                    evidence = (
                        f"'{info['display_name']}' absent from {page.url}. "
                        f"Headers present: {', '.join(present)}."
                    )
                else:
                    evidence = (
                        f"'{info['display_name']}' absent from {page.url}. "
                        f"No security headers at all detected in this response."
                    )

                findings.append(HeaderFinding(
                    page_url    = page.url,
                    header_name = info["display_name"],
                    severity    = info["severity"],
                    remediation = info["remediation"],
                    evidence    = evidence,
                ))
                reported_headers.add(header_key)

                print(
                    f"  [Headers] MISSING '{info['display_name']}' "
                    f"(first seen on {norm_path}) -> {info['severity']}"
                )

    if not findings:
        print("  [Headers] All required security headers present.")

    return findings