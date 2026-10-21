"""
detectors/cookie_detector.py -- AegisScan Insecure Cookie Detector
===================================================================
Checks every Set-Cookie header recorded by the crawler for missing
security flags.

Flags we check:
  - HttpOnly
      Prevents JavaScript from reading the cookie.
      Without it, an XSS attack can steal the session cookie.
      Missing = "High" severity.

  - Secure
      Ensures the cookie is only sent over HTTPS, never plain HTTP.
      Without it, the cookie can be intercepted by a network attacker.
      Missing = "Medium" severity.

How it works:
  The crawler records cookies via response.cookies (from httpx).
  However, httpx's cookie jar does NOT preserve flags like HttpOnly/Secure --
  it only stores name=value pairs.

  So instead, we re-request each page and parse the raw
  'set-cookie' header directly to inspect the flags.

No validation step needed:
  A missing flag on a cookie is directly observable from the header.
  We mark all findings "confirmed" immediately.
"""

import httpx
from dataclasses import dataclass
from typing import List, Dict
from discovery.crawler import DiscoveryResult
from scope import ScopeGuard, OutOfScopeError


@dataclass
class CookieFinding:
    """
    One insecure cookie flag finding.

    page_url    : the URL that set this cookie
    cookie_name : the name of the cookie (e.g. "session")
    missing_flag: which flag is absent ("HttpOnly" or "Secure")
    severity    : High (HttpOnly) or Medium (Secure)
    evidence    : the raw Set-Cookie header value
    remediation : how to fix it
    """
    page_url: str
    cookie_name: str
    missing_flag: str
    severity: str
    evidence: str
    remediation: str


# Remediation messages
HTTPONLY_REMEDIATION = (
    "Set the HttpOnly flag on all session cookies. "
    "This prevents JavaScript from reading the cookie, "
    "which protects against XSS-based session hijacking. "
    "In Flask: app.config['SESSION_COOKIE_HTTPONLY'] = True  (this is the default). "
    "Never explicitly set it to False."
)

SECURE_REMEDIATION = (
    "Set the Secure flag on all session cookies. "
    "This ensures the cookie is only transmitted over encrypted HTTPS connections, "
    "protecting it from network eavesdropping (man-in-the-middle attacks). "
    "In Flask: app.config['SESSION_COOKIE_SECURE'] = True. "
    "Note: this requires your site to be served over HTTPS."
)


def detect(discovery: DiscoveryResult) -> List[CookieFinding]:
    """
    Re-request each crawled page and inspect raw Set-Cookie headers
    for missing HttpOnly and Secure flags.

    Args:
        discovery: DiscoveryResult from crawler.crawl()

    Returns:
        List of CookieFinding -- one per (page, cookie_name, missing_flag).
    """
    findings: List[CookieFinding] = []
    seen: set = set()  # (cookie_name, missing_flag) already reported

    guard = ScopeGuard()
    with guard.client() as client:

        for page in discovery.pages:
            # Re-request the page to get fresh Set-Cookie headers
            # (the crawler's stored cookies dict strips flag info)
            if not guard.is_allowed(page.url):
                print(f"  [ScopeGuard] [Cookies] skipped out-of-scope page: {page.url}")
                continue

            try:
                response = client.get(page.url)
            except OutOfScopeError as e:
                print(f"  [ScopeGuard] [Cookies] redirect blocked: {e}")
                continue
            except Exception as e:
                print(f"  [Cookies] Error re-fetching {page.url}: {e}")
                continue

            # httpx stores all headers; Set-Cookie can appear multiple times
            set_cookie_headers = _get_all_set_cookie(response.headers)

            # Also probe POST forms on this page: session cookies are often
            # only set AFTER a successful login, not on a plain GET request.
            # We try submitting each POST form with test data so we can see
            # the Set-Cookie response header the server sends back.
            for form in page.forms:
                if form.method != "POST":
                    continue

                # Refuse to send credentials to out-of-scope form actions
                if not guard.is_allowed(form.action):
                    print(f"  [ScopeGuard] [Cookies] skipped out-of-scope form action: {form.action}")
                    continue

                form_data = {}
                for f in form.fields:
                    if f.field_type == "submit":
                        continue
                    # Use a known valid credential for AegisLab's login form
                    # so the server actually sets the session cookie on success
                    if f.name == "username":
                        form_data[f.name] = "alice"
                    elif f.name == "password":
                        form_data[f.name] = "password123"
                    else:
                        form_data[f.name] = "test"
                try:
                    post_resp = client.post(form.action, data=form_data)
                    post_cookies = _get_all_set_cookie(post_resp.headers)
                    set_cookie_headers.extend(post_cookies)
                except OutOfScopeError as e:
                    print(f"  [ScopeGuard] [Cookies] form redirect blocked: {e}")
                except Exception:
                    pass

            if not set_cookie_headers:
                continue


            for raw_cookie in set_cookie_headers:
                cookie_name = _parse_cookie_name(raw_cookie)
                raw_lower = raw_cookie.lower()

                print(f"  [Cookies] Found cookie '{cookie_name}' on {page.url}")

                # --- Check HttpOnly ---
                if "httponly" not in raw_lower:
                    dedup = (cookie_name, "HttpOnly")
                    if dedup not in seen:
                        seen.add(dedup)
                        findings.append(CookieFinding(
                            page_url     = page.url,
                            cookie_name  = cookie_name,
                            missing_flag = "HttpOnly",
                            severity     = "High",
                            evidence     = f"Set-Cookie: {raw_cookie}",
                            remediation  = HTTPONLY_REMEDIATION,
                        ))
                        print(f"  [Cookies]   MISSING HttpOnly flag -> severity: High")

                # --- Check Secure ---
                if "secure" not in raw_lower:
                    dedup = (cookie_name, "Secure")
                    if dedup not in seen:
                        seen.add(dedup)
                        findings.append(CookieFinding(
                            page_url     = page.url,
                            cookie_name  = cookie_name,
                            missing_flag = "Secure",
                            severity     = "Medium",
                            evidence     = f"Set-Cookie: {raw_cookie}",
                            remediation  = SECURE_REMEDIATION,
                        ))
                        print(f"  [Cookies]   MISSING Secure flag -> severity: Medium")

    if not findings:
        print("  [Cookies] All cookies have required security flags.")

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_cookie_name(raw: str) -> str:
    """
    Extract the cookie name from a raw Set-Cookie header value.

    Example: "session=abc123; HttpOnly; Path=/" -> "session"
    """
    # The cookie name=value pair is always first before the first semicolon
    first_part = raw.split(";")[0].strip()
    if "=" in first_part:
        return first_part.split("=", 1)[0].strip()
    return first_part


def _get_all_set_cookie(headers) -> List[str]:
    """
    Collect all Set-Cookie header values from an httpx Headers object.
    httpx deduplicates multi-value headers with a comma by default,
    but Set-Cookie must NOT be comma-joined (each is a separate directive).
    This helper uses the raw multi_items() method to get them individually.
    """
    result = []
    if hasattr(headers, "multi_items"):
        for name, value in headers.multi_items():
            if name.lower() == "set-cookie":
                result.append(value)
    else:
        # Fallback: try a single get
        v = headers.get("set-cookie", "")
        if v:
            result.append(v)
    return result