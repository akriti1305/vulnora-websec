"""
detectors/external_passive.py -- Passive Security Analysis for External Targets (Phase 14)
===========================================================================================
Safe, non-invasive inspection for External Basic scans:
  - TLS certificate and transport security validation
  - robots.txt and sitemap.xml inspection
  - Safe form and endpoint inventory
  - Technology stack and hosting fingerprinting

All network operations use ScopeGuard's scope-aware transport.
Zero active injection payloads or state mutations.
"""

import ssl
import socket
from urllib.parse import urlparse
from typing import List, Dict, Optional
from risk import ScoredFinding
from scope import ScopeGuard


def inspect_tls_certificate(base_url: str, scope_guard: Optional[ScopeGuard] = None) -> List[ScoredFinding]:
    """
    Safely inspect the TLS certificate and transport security of an HTTPS target.
    """
    findings: List[ScoredFinding] = []
    parsed = urlparse(base_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append(ScoredFinding(
            vuln_type="Insecure Transport Scheme",
            severity="High",
            status="confirmed",
            location=base_url,
            evidence=f"External target is using unencrypted scheme: {parsed.scheme}://",
            remediation_advice="Enforce HTTPS across all pages with HTTP to HTTPS 301 redirects and HSTS.",
            payload="",
            category="confirmed_vulnerability"
        ))
        return findings

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                # Extract subject / issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Unknown")
                not_after = cert.get("notAfter", "")

                findings.append(ScoredFinding(
                    vuln_type="TLS Transport Security",
                    severity="Info",
                    status="verified",
                    location=f"https://{hostname}:{port}",
                    evidence=(
                        f"TLS connection verified ({tls_version}, {cipher[0] if cipher else 'unknown'}). "
                        f"Issuer: {issuer_name}. Valid until: {not_after}."
                    ),
                    remediation_advice="Maintain TLS 1.2+ and renew certificates before expiry.",
                    payload="",
                    category="verified_control"
                ))
    except ssl.SSLCertVerificationError as e:
        findings.append(ScoredFinding(
            vuln_type="Invalid TLS Certificate",
            severity="High",
            status="confirmed",
            location=f"https://{hostname}:{port}",
            evidence=f"TLS certificate validation failed: {e.verify_message}",
            remediation_advice="Install a valid SSL/TLS certificate issued by a trusted Certificate Authority.",
            payload="",
            category="confirmed_vulnerability"
        ))
    except Exception as e:
        findings.append(ScoredFinding(
            vuln_type="TLS Inspection Notice",
            severity="Info",
            status="info",
            location=f"https://{hostname}:{port}",
            evidence=f"Could not complete low-level TLS handshake: {e}",
            remediation_advice="Ensure HTTPS port 443 is open and serving valid TLS.",
            payload="",
            category="informational"
        ))

    return findings


def inspect_robots_and_sitemap(
    base_url: str,
    scope_guard: Optional[ScopeGuard] = None
) -> List[ScoredFinding]:
    """
    Safely inspect robots.txt and sitemap.xml for information disclosure or indexing policies.
    """
    findings: List[ScoredFinding] = []
    guard = scope_guard or ScopeGuard(is_external=True, allowed_hostname=urlparse(base_url).hostname)

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    with guard.client(timeout=5) as client:
        # Check robots.txt
        robots_url = f"{origin}/robots.txt"
        try:
            resp = client.get(robots_url)
            if resp.status_code == 200 and resp.text:
                lines = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")]
                disallow_rules = [l for l in lines if l.lower().startswith("disallow:")]
                findings.append(ScoredFinding(
                    vuln_type="Robots.txt Policy Discovered",
                    severity="Info",
                    status="info",
                    location=robots_url,
                    evidence=f"Discovered robots.txt ({len(lines)} directives, {len(disallow_rules)} disallow rules).",
                    remediation_advice="Ensure robots.txt does not inadvertently disclose sensitive or secret administrative URLs.",
                    payload="",
                    category="informational"
                ))
        except Exception:
            pass

        # Check sitemap.xml
        sitemap_url = f"{origin}/sitemap.xml"
        try:
            resp = client.get(sitemap_url)
            if resp.status_code == 200:
                findings.append(ScoredFinding(
                    vuln_type="XML Sitemap Discovered",
                    severity="Info",
                    status="info",
                    location=sitemap_url,
                    evidence="Discovered public sitemap.xml aiding discovery of published application endpoints.",
                    remediation_advice="Ensure sitemap only includes intentionally public routes.",
                    payload="",
                    category="informational"
                ))
        except Exception:
            pass

    return findings


def inventory_forms_and_technology(
    discovery_result,
    scope_guard: Optional[ScopeGuard] = None
) -> List[ScoredFinding]:
    """
    Inventories discovered forms, endpoints, and technology signatures non-invasively.
    """
    findings: List[ScoredFinding] = []

    # Technology Fingerprinting from headers and meta tags
    tech_detected = []
    for page in discovery_result.pages:
        headers = {k.lower(): v for k, v in page.response_headers.items()}
        if "server" in headers:
            tech_detected.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            tech_detected.append(f"X-Powered-By: {headers['x-powered-by']}")
        if "x-vercel-id" in headers or "x-vercel-cache" in headers:
            tech_detected.append("Platform: Vercel Edge Network")
        if "cf-ray" in headers:
            tech_detected.append("CDN: Cloudflare")
        if "x-nextjs-cache" in headers or "x-matched-path" in headers:
            tech_detected.append("Framework: Next.js")

    tech_set = sorted(list(set(tech_detected)))
    if tech_set:
        findings.append(ScoredFinding(
            vuln_type="Technology Stack Fingerprint",
            severity="Info",
            status="info",
            location=discovery_result.base_url,
            evidence="Identified public technology signatures: " + ", ".join(tech_set),
            remediation_advice="Disable disclosure of specific server versions in response headers where possible (e.g. Server, X-Powered-By).",
            payload="",
            category="informational"
        ))

    # Form Inventory (safe, non-invasive)
    if discovery_result.all_forms:
        form_summary = []
        for f in discovery_result.all_forms:
            fields_str = ", ".join([fld.name for fld in f.fields if fld.name]) or "none"
            form_summary.append(f"[{f.method}] {f.action} (inputs: {fields_str})")
        
        findings.append(ScoredFinding(
            vuln_type="Discovered Form Inventory",
            severity="Info",
            status="info",
            location=discovery_result.base_url,
            evidence=f"Cataloged {len(discovery_result.all_forms)} public form(s): " + "; ".join(form_summary[:5]),
            remediation_advice="Review form inputs and ensure CSRF protection and input validation are enforced on state-changing forms.",
            payload="",
            category="informational"
        ))

    return findings


def generate_not_tested_stubs(reason: str) -> List[ScoredFinding]:
    """
    Generates honest 'Not Tested' finding stubs for active detectors that are
    intentionally disabled during External Basic scanning.
    """
    stubs = [
        ScoredFinding(
            vuln_type="SQL Injection",
            severity="Info",
            status="not_tested",
            location="External Target Scope",
            evidence=f"Active SQL injection testing disabled. {reason}",
            remediation_advice="Ensure prepared statements are used for all database access.",
            payload="",
            category="not_tested"
        ),
        ScoredFinding(
            vuln_type="Reflected XSS",
            severity="Info",
            status="not_tested",
            location="External Target Scope",
            evidence=f"Active cross-site scripting payload injection disabled. {reason}",
            remediation_advice="Ensure contextual HTML output escaping is applied to all user input.",
            payload="",
            category="not_tested"
        ),
        ScoredFinding(
            vuln_type="IDOR (Broken Access Control)",
            severity="Info",
            status="not_tested",
            location="External Target Scope",
            evidence=f"IDOR numeric enumeration disabled. {reason}",
            remediation_advice="Enforce server-side authorization checks on all record access.",
            payload="",
            category="not_tested"
        ),
        ScoredFinding(
            vuln_type="Indirect Prompt Injection",
            severity="Info",
            status="not_applicable",
            location="External Target Scope",
            evidence="AI prompt injection testing not applicable: No interactive AI assistant detected on target.",
            remediation_advice="If an AI agent is added in the future, implement robust input sanitization and canary tokens.",
            payload="",
            category="informational"
        ),
        ScoredFinding(
            vuln_type="AI Tool Integrity & Anti-Rug-Pull",
            severity="Info",
            status="not_applicable",
            location="External Target Scope",
            evidence="Tool integrity monitoring not applicable: No AI agent tool manifest detected.",
            remediation_advice="Sign and pin tool schemas if deploying autonomous AI agents.",
            payload="",
            category="informational"
        ),
        ScoredFinding(
            vuln_type="Context Taint & Excessive Agency",
            severity="Info",
            status="not_applicable",
            location="External Target Scope",
            evidence="Excessive agency analysis not applicable: No autonomous AI agent actions detected.",
            remediation_advice="Enforce human-in-the-loop approval gates for high-impact actions.",
            payload="",
            category="informational"
        ),
    ]
    return stubs
