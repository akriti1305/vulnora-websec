"""
risk/__init__.py -- AegisScan Risk Scoring (Phase 4)
=====================================================
Assigns severity and remediation to every finding from all 5 detectors.

Severity scale (OWASP / CVSS inspired):
  Critical -- authentication bypass, all users' data exposed
  High     -- confirmed injection, session hijack possible
  Medium   -- missing security controls, unconfirmed findings
  Low      -- defence-in-depth headers missing (less exploitable alone)
  Info     -- informational only

This module provides one scoring function per detector type.
"""

from dataclasses import dataclass
from typing import List


# ---------------------------------------------------------------------------
# ScoredFinding -- universal output type for ALL detectors
# ---------------------------------------------------------------------------

@dataclass
class ScoredFinding:
    """
    A finding with severity and remediation attached.

    vuln_type         : e.g. "SQL Injection", "Reflected XSS" ...
    severity          : Critical / High / Medium / Low / Info
    status            : "confirmed" / "not_reproducible" / "potential"
    location          : URL + parameter or page URL
    evidence          : what the scanner observed
    remediation_advice: plain-English fix
    payload           : the payload used (empty string for passive checks)
    """
    vuln_type: str
    severity: str
    status: str
    location: str
    evidence: str
    remediation_advice: str
    payload: str = ""
    category: str = ""


# ---------------------------------------------------------------------------
# Finding Classification 2.0 (Phase 13)
# ---------------------------------------------------------------------------
def classify_finding_category(vuln_type: str, status: str) -> str:
    """
    Classifies a finding into one of:
      - 'confirmed_vulnerability'
      - 'potential_vulnerability'
      - 'informational'
      - 'verified_control'
      - 'not_reproducible'
      - 'not_tested'
    """
    v = (vuln_type or "").strip()
    s = (status or "").strip().lower()

    if s == "not_tested":
        return "not_tested"
    if s == "not_reproducible":
        return "not_reproducible"
    if v in ("Tool Integrity Verified", "AI Agent Approval Gate Verified") or s in ("verified", "verified_control"):
        return "verified_control"
    if v in ("AI Assistant Discovered", "AI Security Manifest Detected", "AI Tools Baselined", "Tool Baseline Unavailable"):
        return "informational"
    if s in ("info", "detected", "informational"):
        return "informational"
    if s == "potential":
        return "potential_vulnerability"
    if s == "confirmed":
        return "confirmed_vulnerability"
    return "informational" if s in ("info", "detected") else "potential_vulnerability"


# ---------------------------------------------------------------------------
# Remediation texts
# ---------------------------------------------------------------------------

SQLI_REMEDIATION = (
    "Use parameterised queries (prepared statements) instead of building SQL "
    "strings with string formatting. In Python + SQLite: "
    "db.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password)). "
    "Never concatenate user input directly into a SQL string. "
    "Consider using an ORM like SQLAlchemy which parameterises queries automatically."
)

XSS_REMEDIATION = (
    "Always HTML-escape user-supplied data before rendering it in a template. "
    "In Flask/Jinja2: never use Markup() on untrusted input -- Jinja2 auto-escapes "
    "by default. Remove any Markup() wrappers from user data. "
    "Optionally add a Content-Security-Policy header to reduce XSS impact."
)

IDOR_REMEDIATION = (
    "Always verify that the currently logged-in user is authorised to access "
    "the requested resource. In Flask: compare session['user_id'] against the "
    "requested id parameter. If they don't match, return a 403 Forbidden response. "
    "Never rely on the client to send the correct ID -- always enforce server-side."
)


# ---------------------------------------------------------------------------
# SQLi Scoring
# ---------------------------------------------------------------------------

def score_sqli_findings(validated_findings) -> List[ScoredFinding]:
    """Score validated SQLi findings."""
    scored = []
    for vf in validated_findings:
        raw = vf.raw
        if vf.status == "confirmed":
            severity = "Critical"
        elif vf.status == "not_reproducible":
            severity = "Medium"
        else:
            severity = "Low"

        print(f"  [Risk/SQLi] {raw.form.action} field={raw.field_name} -> {severity}")
        scored.append(ScoredFinding(
            vuln_type          = "SQL Injection",
            severity           = severity,
            status             = vf.status,
            location           = f"{raw.form.action} (field: {raw.field_name})",
            evidence           = raw.evidence,
            remediation_advice = SQLI_REMEDIATION,
            payload            = raw.payload,
        ))
    return scored


# ---------------------------------------------------------------------------
# XSS Scoring
# ---------------------------------------------------------------------------

def score_xss_findings(validated_findings) -> List[ScoredFinding]:
    """Score validated XSS findings."""
    scored = []
    for vf in validated_findings:
        raw = vf.raw
        severity = "High" if vf.status == "confirmed" else "Medium"

        print(f"  [Risk/XSS] {raw.location} -> {severity}")
        scored.append(ScoredFinding(
            vuln_type          = "Reflected XSS",
            severity           = severity,
            status             = vf.status,
            location           = raw.location,
            evidence           = raw.evidence,
            remediation_advice = XSS_REMEDIATION,
            payload            = raw.payload,
        ))
    return scored


# ---------------------------------------------------------------------------
# IDOR Scoring -- no validation step, direct findings
# ---------------------------------------------------------------------------

def score_idor_findings(idor_findings) -> List[ScoredFinding]:
    """Score IDOR findings (confirmed or potential)."""
    scored = []
    for f in idor_findings:
        sev = getattr(f, "severity", "Critical")
        stat = getattr(f, "status", "confirmed")
        note = getattr(f, "note", "")
        evidence = f.evidence
        if note:
            evidence = f"{evidence}\nNote: {note}"
        print(f"  [Risk/IDOR] {f.baseline_url} param={f.param_name} -> {sev} ({stat})")
        scored.append(ScoredFinding(
            vuln_type          = "IDOR (Broken Access Control)",
            severity           = sev,
            status             = stat,
            location           = f"{f.baseline_url} (param: {f.param_name})",
            evidence           = evidence,
            remediation_advice = IDOR_REMEDIATION,
            payload            = f"?{f.param_name}={f.probed_id}",
        ))
    return scored


# ---------------------------------------------------------------------------
# Missing Headers Scoring -- no validation step, direct findings
# ---------------------------------------------------------------------------

def score_header_findings(header_findings) -> List[ScoredFinding]:
    """Score missing security header findings."""
    scored = []
    for f in header_findings:
        print(f"  [Risk/Headers] {f.header_name} missing on {f.page_url} -> {f.severity}")
        scored.append(ScoredFinding(
            vuln_type          = "Missing Security Header",
            severity           = f.severity,
            status             = "confirmed",
            location           = f.page_url,
            evidence           = f.evidence,
            remediation_advice = f.remediation,
            payload            = "",
        ))
    return scored


# ---------------------------------------------------------------------------
# Insecure Cookie Scoring -- no validation step, direct findings
# ---------------------------------------------------------------------------

def score_cookie_findings(cookie_findings) -> List[ScoredFinding]:
    """Score insecure cookie findings."""
    scored = []
    for f in cookie_findings:
        print(f"  [Risk/Cookie] {f.cookie_name} missing {f.missing_flag} -> {f.severity}")
        scored.append(ScoredFinding(
            vuln_type          = "Insecure Cookie",
            severity           = f.severity,
            status             = "confirmed",
            location           = f"{f.page_url} (cookie: {f.cookie_name})",
            evidence           = f"Missing '{f.missing_flag}' flag on cookie '{f.cookie_name}'. Header: {f.evidence}",
            remediation_advice = f.remediation,
            payload            = "",
        ))
    return scored