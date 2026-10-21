"""
detectors/xss_detector.py -- AegisScan Reflected XSS Detector
==============================================================
Tests every form and GET parameter found by the crawler for Reflected
Cross-Site Scripting (XSS).

How it works:
  1. For each form: inject an XSS payload as the field value, submit it,
     then check if the UNESCAPED payload appears in the response HTML.
  2. For each GET form: also build a URL with the payload in the query string.

"Unescaped" means the raw payload appears as-is (e.g. <script>),
NOT as HTML entities (e.g. &lt;script&gt; which is safe/escaped).

Returned as a list of XssRawFinding objects passed to the validator.

NOTE: No destructive actions. Payloads are read-only probes.
"""

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode
from dataclasses import dataclass
from typing import List
from discovery.crawler import DiscoveryResult, PageForm
from scope import ScopeGuard, OutOfScopeError


# ---------------------------------------------------------------------------
# XSS Payloads
# ---------------------------------------------------------------------------
# We use a unique marker string embedded inside a script tag.
# This makes it easy to check whether it was reflected unescaped:
#   - Unescaped (vulnerable): <script>alert('AEGISSCAN_XSS')</script>
#   - Escaped (safe):         &lt;script&gt;alert('AEGISSCAN_XSS')&lt;/script&gt;
#
XSS_PAYLOADS = [
    "<script>alert('AEGISSCAN_XSS')</script>",
    "<img src=x onerror=alert('AEGISSCAN_XSS')>",
    "\"'><script>alert('AEGISSCAN_XSS')</script>",
]

# The unique marker we look for in the raw (unparsed) HTML response
# We search for this in the raw text, not BeautifulSoup-parsed text,
# because BS4 would strip or modify the tags.
XSS_MARKER = "aegisscan_xss"


@dataclass
class XssRawFinding:
    """
    A potential XSS finding before validation.

    location  : the URL + parameter where the payload was injected
    payload   : the exact XSS string used
    field_name: the form field (or query param) that was injected
    evidence  : the snippet of raw HTML where the payload appeared
    method    : GET or POST (how the payload was delivered)
    form      : the PageForm object (or None for direct URL probes)
    """
    location: str
    payload: str
    field_name: str
    evidence: str
    method: str
    form: object   # PageForm or None


def detect(discovery: DiscoveryResult) -> List[XssRawFinding]:
    """
    Test all forms and GET parameters for Reflected XSS.

    Checks:
      - POST forms: inject into each text/search field
      - GET forms:  inject into each text/search field via query string

    Returns:
        List of XssRawFinding -- one per confirmed injection point.
    """
    findings: List[XssRawFinding] = []
    # Track which (action_url, field_name) pairs we already found
    # so we don't log duplicates for the same field
    seen = set()

    guard = ScopeGuard()
    with guard.client() as client:

        for form in discovery.all_forms:
            print(f"  [XSS] Testing form: {form.action} [{form.method}]")

            injectable = [
                f for f in form.fields
                if f.field_type in ("text", "search", "email", "url", "textarea")
            ]
            if not injectable:
                continue

            for payload in XSS_PAYLOADS:
                form_hit = False

                for target_field in injectable:
                    if form_hit:
                        break

                    dedup_key = (form.action, target_field.name)
                    if dedup_key in seen:
                        continue

                    # Build the data dict with the payload in one field
                    field_data = {}
                    for f in form.fields:
                        if f.field_type == "submit":
                            continue
                        field_data[f.name] = (
                            payload if f.name == target_field.name
                            else "test"
                        )

                    try:
                        if form.method == "POST":
                            response = client.post(form.action, data=field_data)
                        else:
                            # GET: send payload as query string
                            response = client.get(form.action, params=field_data)
                    except OutOfScopeError as e:
                        print(f"  [XSS]   Scope violation, skipping: {e}")
                        continue
                    except Exception as e:
                        print(f"  [XSS]   Request error: {e}")
                        continue

                    # Check the RAW html text (not BS4-parsed) for the marker
                    # Case-insensitive check for our unique marker string
                    raw_lower = response.text.lower()

                    if XSS_MARKER in raw_lower:
                        # Confirm it's unescaped -- look for < not &lt;
                        # A safe app would encode < as &lt;, > as &gt;
                        # We look for the literal < near our marker
                        if _is_unescaped(response.text, payload):
                            evidence = _extract_raw_snippet(response.text, XSS_MARKER)
                            loc = f"{form.action} (field: {target_field.name})"
                            findings.append(XssRawFinding(
                                location=loc,
                                payload=payload,
                                field_name=target_field.name,
                                evidence=evidence,
                                method=form.method,
                                form=form,
                            ))
                            seen.add(dedup_key)
                            form_hit = True
                            print(
                                f"  [XSS]   FOUND! field='{target_field.name}' "
                                f"payload='{payload[:40]}...'"
                            )

    if not findings:
        print("  [XSS] No Reflected XSS vulnerabilities detected.")

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_unescaped(html: str, payload: str) -> bool:
    """
    Return True if the payload appears UNESCAPED in the HTML.

    Distinguishes real reflected XSS from Jinja2/HTML-escaped reflections
    (e.g., when a SQL error echoes the input safely encoded as &lt;script&gt;).
    """
    html_lower = html.lower()
    payload_lower = payload.lower()

    # Exact payload reflected verbatim
    if payload_lower in html_lower:
        return True

    # If payload started with quote escapes like "'> or '>, check the core tag
    core_payload = payload_lower.lstrip("\"'> ")
    if core_payload and core_payload in html_lower:
        return True

    # Also check if the raw unescaped script or img tag with the marker is present
    if XSS_MARKER in html_lower:
        idx = html_lower.find(XSS_MARKER)
        last_lt = html_lower.rfind("<", 0, idx)
        last_entity_lt = html_lower.rfind("&lt;", 0, idx)
        if last_entity_lt > last_lt:
            return False
        if last_lt != -1:
            tag_prefix = html_lower[last_lt:idx]
            if tag_prefix.startswith("<script") or tag_prefix.startswith("<img"):
                return True

    return False


def _extract_raw_snippet(html: str, keyword: str, context: int = 300) -> str:
    """
    Return a short raw-HTML snippet around the keyword (case-insensitive).
    Keeps tags intact (not BS4-parsed) so the evidence shows the injection.
    """
    lower = html.lower()
    idx = lower.find(keyword)
    if idx == -1:
        return keyword

    start = max(0, idx - context // 2)
    end   = min(len(html), idx + len(keyword) + context // 2)
    return html[start:end].strip()[:500]