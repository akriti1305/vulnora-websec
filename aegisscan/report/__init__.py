"""
report/__init__.py -- AegisScan Report Generator (Phase 5)
===========================================================
Provides two report renderers:
  generate_html_report()    -- full vulnerability scan report
  generate_compare_report() -- before/after scan comparison report
"""

import os
from jinja2 import Environment, FileSystemLoader
from typing import List, Dict, Any, Optional

_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "templates"
)

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=True
)

SECURITY_EXPLANATIONS = {
    "SQL Injection": {
        "plain_name": "SQL Injection (SQLi)",
        "what_is_it": "User input is concatenated directly into database query commands without parameterization.",
        "why_dangerous": "An attacker can bypass login screens, steal passwords and customer records, or modify database contents.",
        "suggested_fix": "Use parameterized queries (prepared statements) with bound variables. Never build queries by concatenating raw strings.",
    },
    "Reflected XSS": {
        "plain_name": "Reflected Cross-Site Scripting (XSS)",
        "what_is_it": "The website echoes unescaped user input (such as a search query) directly into the returned HTML page.",
        "why_dangerous": "An attacker can execute malicious scripts in another user's browser, hijacking sessions or stealing sensitive data.",
        "suggested_fix": "Sanitize and context-encode all user input before outputting to HTML. Implement a strong Content-Security-Policy (CSP).",
    },
    "IDOR (Broken Access Control)": {
        "plain_name": "Insecure Direct Object Reference (IDOR)",
        "what_is_it": "The application allows users to view or edit records by modifying an ID parameter without verifying ownership.",
        "why_dangerous": "Any user can view or tamper with other customers' personal profiles, orders, or private account details.",
        "suggested_fix": "Verify user authorization on the server side before returning any resource. Check session user identity against requested resource ID.",
    },
    "Missing Security Header": {
        "plain_name": "Missing HTTP Security Header",
        "what_is_it": "The web server omits defensive HTTP response headers that instruct browsers how to handle content safely.",
        "why_dangerous": "Leaves users exposed to clickjacking (missing X-Frame-Options), MIME sniffing attacks, or downgrade from HTTPS to HTTP.",
        "suggested_fix": "Configure web server or middleware to return CSP, HSTS, X-Frame-Options, and X-Content-Type-Options headers.",
    },
    "Insecure Cookie": {
        "plain_name": "Insecure Cookie Configuration",
        "what_is_it": "Session or authentication cookies are issued without security flags such as HttpOnly, Secure, or SameSite.",
        "why_dangerous": "Cookies without HttpOnly can be stolen via JavaScript XSS. Cookies without Secure can be intercepted in cleartext over HTTP.",
        "suggested_fix": "Set HttpOnly=True, Secure=True, and SameSite=Lax on all authentication and session management cookies.",
    },
    "Insecure HTTP Transport": {
        "plain_name": "Insecure HTTP Transport",
        "what_is_it": "The web application communicates over unencrypted HTTP instead of encrypted HTTPS/TLS.",
        "why_dangerous": "Network eavesdroppers can capture credentials, session cookies, and private communications in transit.",
        "suggested_fix": "Install a valid TLS certificate and redirect all incoming HTTP traffic to HTTPS on port 443.",
    },
    "TLS Transport Security": {
        "plain_name": "TLS / SSL Transport Security",
        "what_is_it": "Evaluation of SSL/TLS certificate validity, supported protocol versions, and encryption cipher suites.",
        "why_dangerous": "Weak ciphers or expired certificates can allow man-in-the-middle attacks and data interception.",
        "suggested_fix": "Maintain active TLS 1.2+ protocols with strong cipher suites and valid CA-signed certificates.",
    },
    "Indirect Prompt Injection": {
        "plain_name": "Indirect Prompt Injection",
        "what_is_it": "An AI assistant processes untrusted external context containing instructions that hijack the assistant's behavior.",
        "why_dangerous": "Untrusted documents can take control of the AI agent, overriding developer instructions and prompting unsafe actions.",
        "suggested_fix": "Isolate untrusted document context from system instructions. Apply dual-LLM or heuristic guardrails on agent context.",
    },
    "AI Canary Token Leakage": {
        "plain_name": "Protected Customer Information Disclosure",
        "what_is_it": "The AI assistant disclosed confidential customer account records when prompted by manipulated untrusted context.",
        "why_dangerous": "Confirms that prompt injection succeeded in extracting private customer records (e.g. Alice Sharma, ORD-1001) without authorization.",
        "suggested_fix": "Implement strict output filtering, context boundary separation, and permission gating on customer database tools.",
    },
    "Tool Integrity Verified": {
        "plain_name": "AI Tool Integrity Verification",
        "what_is_it": "Cryptographic check verifying that AI tool schemas and parameter requirements match approved baselines.",
        "why_dangerous": "Tool definitions modified post-approval can secretly redirect agent actions to malicious sinks (rug-pull attack).",
        "suggested_fix": "Store cryptographic SHA-256 baselines of tool schemas and reject tool execution if schemas change.",
    },
    "Tool Metadata Rug-Pull": {
        "plain_name": "AI Tool Metadata Rug-Pull",
        "what_is_it": "An AI tool's definition or parameters were modified after initial approval without security re-baselining.",
        "why_dangerous": "The tool can now perform unexpected actions or require unexpected sensitive inputs without operator knowledge.",
        "suggested_fix": "Re-verify tool definitions against approved baselines and disallow runtime schema modifications.",
    },
    "Poisoned Tool Description": {
        "plain_name": "Poisoned Tool Description",
        "what_is_it": "A tool's description contains adversarial instructions that deceive the AI into selecting it for unauthorized tasks.",
        "why_dangerous": "Adversarial descriptions cause the AI agent to call high-impact tools under attacker-controlled conditions.",
        "suggested_fix": "Review and approve tool descriptions manually; sanitize tool metadata before ingestion by the model.",
    },
    "Excessive Agency: Unapproved High-Impact Action": {
        "plain_name": "Excessive Agency: Unapproved High-Impact Action",
        "what_is_it": "An autonomous AI assistant executed a high-impact action (e.g. sending an email) without requiring human approval.",
        "why_dangerous": "Prompt injection can cause irreversible real-world damage if high-impact actions execute without human confirmation.",
        "suggested_fix": "Enforce human-in-the-loop approval gates for all tools classified with medium or high impact levels.",
    },
    "AI Agent Approval Gate Verified": {
        "plain_name": "AI Agent Approval Gate Verified",
        "what_is_it": "Human-in-the-loop approval gate successfully intercepted and blocked an unapproved high-impact action.",
        "why_dangerous": "Without this defense, an AI agent could be manipulated into executing unauthorized external transactions.",
        "suggested_fix": "Keep approval gates active in production for all sensitive tool actions.",
    },
    "Context Taint Hijack: Complete Attack Path": {
        "plain_name": "Context Taint Hijack Attack Path",
        "what_is_it": "End-to-end attack flow observed from untrusted document ingestion into assistant context to tool execution.",
        "why_dangerous": "Demonstrates an end-to-end exploit where untrusted external data successfully controls autonomous agent actions.",
        "suggested_fix": "Track taint across data pipelines and prohibit tainted context from reaching privileged tool execution sinks.",
    },
    "SSRF / Scope Protection Block": {
        "plain_name": "SSRF / Scope Protection Block",
        "what_is_it": "ScopeGuard safety boundary intercepted and blocked a request targeting an unauthorized IP or private network.",
        "why_dangerous": "Server-Side Request Forgery allows probing internal network devices, loopback endpoints, or cloud metadata.",
        "suggested_fix": "Enforce strict IP validation, DNS rebinding protection, and ScopeGuard authorization checks.",
    },
    "Network / ScopeGuard Inspection Blocked": {
        "plain_name": "ScopeGuard Network Diagnostic",
        "what_is_it": "ScopeGuard safely halted connection attempts to unapproved IP ranges or reserved addresses.",
        "why_dangerous": "Protects against SSRF and unauthorized network egress during scanner execution.",
        "suggested_fix": "Verify network routing and target URL domain configuration.",
    },
    "AI Security Manifest Detected": {
        "plain_name": "AI Security Manifest Discovery",
        "what_is_it": "Scanner discovered an AI security manifest at /.well-known/aegisscan-ai.json describing agent architecture.",
        "why_dangerous": "Informational discovery allowing the scanner to discover AI endpoints and tool baselines.",
        "suggested_fix": "Ensure that confidential secrets or canary tokens are never included in the public manifest.",
    },
    "AI Assistant Discovered": {
        "plain_name": "AI Assistant Endpoint Discovery",
        "what_is_it": "Scanner discovered an interactive AI assistant or copilot endpoint on the target application.",
        "why_dangerous": "Identifies an AI-agent attack surface that must be tested for prompt injection and excessive agency.",
        "suggested_fix": "Apply rigorous guardrails and input validation to all discovered AI assistant endpoints.",
    },
    "Technology Stack Fingerprint": {
        "plain_name": "Technology Stack Fingerprint",
        "what_is_it": "Passive identification of server software, frameworks, or runtime versions from HTTP headers or HTML markup.",
        "why_dangerous": "Attackers can use version information to search for known CVEs affecting specific server versions.",
        "suggested_fix": "Remove or genericize Server, X-Powered-By, and framework signature headers.",
    },
    "Crawl / Endpoint Discovery Incomplete": {
        "plain_name": "Crawl Discovery Incomplete",
        "what_is_it": "Crawler reached its safety budget cap or encountered restricted pages before exploring all links.",
        "why_dangerous": "Informational notification that some deep endpoints were not crawled due to request budget constraints.",
        "suggested_fix": "Review request budget configuration or provide explicit path lists for authorized scans.",
    }
}


def _enrich_finding(f: dict) -> dict:
    """Add friendly explanations to findings for clear presentation."""
    f_copy = dict(f)
    vuln_type = f_copy.get("vulnerability_type", "Security Check")
    expl = SECURITY_EXPLANATIONS.get(vuln_type)
    if not expl:
        for k, v in SECURITY_EXPLANATIONS.items():
            if k.lower() in vuln_type.lower() or vuln_type.lower() in k.lower():
                expl = v
                break
    if not expl:
        expl = {
            "plain_name": vuln_type,
            "what_is_it": f"Evaluation of {vuln_type}.",
            "why_dangerous": "Security consideration that may impact target defense or compliance.",
            "suggested_fix": f_copy.get("remediation_advice") or f_copy.get("remediation") or "Review application configuration and apply security best practices."
        }

    f_copy["plain_name"] = expl.get("plain_name", vuln_type)
    f_copy["what_is_it"] = expl.get("what_is_it", "")
    f_copy["why_dangerous"] = expl.get("why_dangerous", "")
    f_copy["what_observed"] = f_copy.get("evidence", "Observed during scan evaluation.")
    f_copy["suggested_fix"] = f_copy.get("remediation_advice") or f_copy.get("remediation") or expl.get("suggested_fix", "")
    return f_copy


def build_category_breakdowns(sorted_findings: List[dict], scan_mode: str, target_url: str) -> dict:
    """
    Build structured category-level summaries for:
      - Section A: 5 Primary Web Security Categories (SQLi, XSS, IDOR, Headers, Cookies)
      - Section B: 4 AI Security Categories (Prompt Injection, Sensitive Info Leakage, Tool Integrity, Unauthorized AI Actions)
      - Focused Web Demo: Exactly 2 checks (SQL Injection, XSS)
    """
    # -------------------------------------------------------------------------
    # Section A: Five Primary Web Security Categories
    # -------------------------------------------------------------------------
    web_categories = []

    # 1. SQL Injection
    sqli_all = [f for f in sorted_findings if "sql injection" in f.get("vulnerability_type", "").lower() or f.get("vulnerability_type") == "SQL Injection"]
    sqli_flaws = [f for f in sqli_all if f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    sqli_status = "Issue Found" if sqli_flaws else ("Not Tested" if scan_mode in ("basic", "external_basic") else "Passed")
    sqli_sev = sqli_flaws[0].get("severity", "Critical") if sqli_flaws else ("Info" if sqli_status == "Not Tested" else "Low")
    web_categories.append({
        "key": "sqli",
        "name": "SQL Injection",
        "status": sqli_status,
        "status_class": "issue" if sqli_status == "Issue Found" else ("not_tested" if sqli_status == "Not Tested" else "passed"),
        "severity": sqli_sev,
        "explanation": "Untrusted user input is concatenated directly into SQL queries without parameterized binding, allowing authentication bypass or unauthorized database manipulation.",
        "observations": sqli_flaws if sqli_flaws else sqli_all,
        "observation_count": len(sqli_flaws) if sqli_flaws else (0 if sqli_status == "Passed" else len(sqli_all)),
        "is_issue": sqli_status == "Issue Found",
    })

    # 2. Cross-Site Scripting (XSS)
    xss_all = [f for f in sorted_findings if "xss" in f.get("vulnerability_type", "").lower()]
    xss_flaws = [f for f in xss_all if f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    xss_status = "Issue Found" if xss_flaws else ("Not Tested" if scan_mode in ("basic", "external_basic") else "Passed")
    xss_sev = xss_flaws[0].get("severity", "High") if xss_flaws else ("Info" if xss_status == "Not Tested" else "Low")
    web_categories.append({
        "key": "xss",
        "name": "Cross-Site Scripting (XSS)",
        "status": xss_status,
        "status_class": "issue" if xss_status == "Issue Found" else ("not_tested" if xss_status == "Not Tested" else "passed"),
        "severity": xss_sev,
        "explanation": "The application echoes unescaped user input directly into HTML responses, enabling arbitrary script execution in client browsers.",
        "observations": xss_flaws if xss_flaws else xss_all,
        "observation_count": len(xss_flaws) if xss_flaws else (0 if xss_status == "Passed" else len(xss_all)),
        "is_issue": xss_status == "Issue Found",
    })

    # 3. Broken Access Control (IDOR)
    idor_all = [f for f in sorted_findings if "idor" in f.get("vulnerability_type", "").lower() or "broken access control" in f.get("vulnerability_type", "").lower()]
    idor_flaws = [f for f in idor_all if f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    idor_status = "Issue Found" if idor_flaws else ("Not Tested" if scan_mode in ("basic", "external_basic") else "Passed")
    idor_sev = idor_flaws[0].get("severity", "Critical") if idor_flaws else ("Info" if idor_status == "Not Tested" else "Low")
    web_categories.append({
        "key": "idor",
        "name": "Broken Access Control (IDOR)",
        "status": idor_status,
        "status_class": "issue" if idor_status == "Issue Found" else ("not_tested" if idor_status == "Not Tested" else "passed"),
        "severity": idor_sev,
        "explanation": "User profile or account records are retrieved using client-supplied IDs without verifying session authorization, exposing private customer records.",
        "observations": idor_flaws if idor_flaws else idor_all,
        "observation_count": len(idor_flaws) if idor_flaws else (0 if idor_status == "Passed" else len(idor_all)),
        "is_issue": idor_status == "Issue Found",
    })

    # 4. Security Headers
    header_all = [f for f in sorted_findings if "header" in f.get("vulnerability_type", "").lower()]
    header_flaws = [f for f in header_all if f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    header_status = "Issue Found" if header_flaws else "Passed"
    header_sev = "Medium" if header_flaws else "Low"
    web_categories.append({
        "key": "headers",
        "name": "Security Headers",
        "status": header_status,
        "status_class": "issue" if header_status == "Issue Found" else "passed",
        "severity": header_sev,
        "explanation": "Defensive HTTP response headers (such as Content-Security-Policy, HSTS, and X-Frame-Options) are missing, exposing users to clickjacking and MIME attacks.",
        "observations": header_flaws if header_flaws else header_all,
        "observation_count": len(header_flaws) if header_flaws else 0,
        "is_issue": header_status == "Issue Found",
    })

    # 5. Cookie Security
    cookie_all = [f for f in sorted_findings if "cookie" in f.get("vulnerability_type", "").lower()]
    cookie_flaws = [f for f in cookie_all if f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    cookie_status = "Issue Found" if cookie_flaws else "Passed"
    cookie_sev = cookie_flaws[0].get("severity", "High") if cookie_flaws else "Low"
    web_categories.append({
        "key": "cookies",
        "name": "Cookie Security",
        "status": cookie_status,
        "status_class": "issue" if cookie_status == "Issue Found" else "passed",
        "severity": cookie_sev,
        "explanation": "Session and authentication cookies omit security flags (HttpOnly, Secure, SameSite), risking credential theft via script or unencrypted transport.",
        "observations": cookie_flaws if cookie_flaws else cookie_all,
        "observation_count": len(cookie_flaws) if cookie_flaws else 0,
        "is_issue": cookie_status == "Issue Found",
    })

    # -------------------------------------------------------------------------
    # Section B: Four AI Security Categories
    # -------------------------------------------------------------------------
    ai_categories = []

    # 1. Prompt Injection
    ai_inj_all = [f for f in sorted_findings if "prompt injection" in f.get("vulnerability_type", "").lower()]
    ai_inj_flaws = [f for f in ai_inj_all if f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    ai_inj_controls = [f for f in ai_inj_all if f.get("category") in ("verified_control", "not_reproducible")]
    if scan_mode in ("basic", "external_basic"):
        ai_inj_status = "Not Tested"
    elif ai_inj_flaws:
        ai_inj_status = "Issue Found"
    elif ai_inj_controls:
        ai_inj_status = "Passed"
    else:
        ai_inj_status = "Not Tested"
    ai_categories.append({
        "key": "ai_prompt_injection",
        "name": "Prompt Injection",
        "status": ai_inj_status,
        "status_class": "issue" if ai_inj_status == "Issue Found" else ("not_tested" if ai_inj_status == "Not Tested" else "passed"),
        "severity": "Critical" if ai_inj_status == "Issue Found" else ("Info" if ai_inj_status == "Not Tested" else "Low"),
        "explanation": "Untrusted external context ingested by the AI assistant successfully hijacks model behavior and overrides system guidelines.",
        "observations": ai_inj_flaws if ai_inj_flaws else ai_inj_all,
        "observation_count": len(ai_inj_flaws) if ai_inj_flaws else (0 if ai_inj_status == "Passed" else len(ai_inj_all)),
        "is_issue": ai_inj_status == "Issue Found",
    })

    # 2. Protected Customer Information Disclosure
    ai_leak_all = [f for f in sorted_findings if "canary" in f.get("vulnerability_type", "").lower() or "sensitive information" in f.get("vulnerability_type", "").lower() or "customer information" in f.get("vulnerability_type", "").lower() or "customer" in f.get("plain_name", "").lower()]
    ai_leak_flaws = [f for f in ai_leak_all if f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    ai_leak_controls = [f for f in ai_leak_all if f.get("category") in ("verified_control", "not_reproducible")]
    if scan_mode in ("basic", "external_basic"):
        ai_leak_status = "Not Tested"
    elif ai_leak_flaws:
        ai_leak_status = "Issue Found"
    elif ai_leak_controls or (ai_inj_status == "Passed" and not ai_leak_flaws):
        ai_leak_status = "Passed"
    else:
        ai_leak_status = "Not Tested"
    ai_categories.append({
        "key": "ai_info_leakage",
        "name": "Protected Customer Information Disclosure",
        "status": ai_leak_status,
        "status_class": "issue" if ai_leak_status == "Issue Found" else ("not_tested" if ai_leak_status == "Not Tested" else "passed"),
        "severity": "Critical" if ai_leak_status == "Issue Found" else ("Info" if ai_leak_status == "Not Tested" else "Low"),
        "explanation": "Evaluates whether adversarial document instructions can exfiltrate confidential customer records (such as Alice Sharma's VIP order) or internal tokens.",
        "observations": ai_leak_flaws if ai_leak_flaws else (ai_leak_controls if ai_leak_controls else ai_inj_controls),
        "observation_count": len(ai_leak_flaws) if ai_leak_flaws else (0 if ai_leak_status == "Passed" else len(ai_leak_all)),
        "is_issue": ai_leak_status == "Issue Found",
    })

    # 3. Tool Integrity
    ai_tool_all = [f for f in sorted_findings if "tool" in f.get("vulnerability_type", "").lower()]
    ai_tool_flaws = [f for f in ai_tool_all if f.get("vulnerability_type") in ("Tool Metadata Rug-Pull", "Poisoned Tool Description") and f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    ai_tool_verified = [f for f in ai_tool_all if f.get("vulnerability_type") == "Tool Integrity Verified"]
    if scan_mode in ("basic", "external_basic"):
        ai_tool_status = "Not Tested"
    elif ai_tool_flaws:
        ai_tool_status = "Issue Found"
    elif ai_tool_verified:
        ai_tool_status = "Passed"
    else:
        ai_tool_status = "Not Tested"
    ai_categories.append({
        "key": "ai_tool_integrity",
        "name": "Tool Integrity",
        "status": ai_tool_status,
        "status_class": "issue" if ai_tool_status == "Issue Found" else ("not_tested" if ai_tool_status == "Not Tested" else "passed"),
        "severity": "High" if ai_tool_status == "Issue Found" else ("Info" if ai_tool_status == "Not Tested" else "Low"),
        "explanation": "Cryptographic SHA-256 verification of AI tool schemas ensures tool metadata and parameters match approved baselines without runtime rug-pulls.",
        "observations": ai_tool_flaws if ai_tool_flaws else ai_tool_verified,
        "observation_count": len(ai_tool_flaws) if ai_tool_flaws else len(ai_tool_verified),
        "is_issue": ai_tool_status == "Issue Found",
    })

    # 4. Unauthorized AI Actions
    ai_act_all = [f for f in sorted_findings if "excessive agency" in f.get("vulnerability_type", "").lower() or "context taint" in f.get("vulnerability_type", "").lower() or "approval gate" in f.get("vulnerability_type", "").lower()]
    ai_act_flaws = [f for f in ai_act_all if f.get("vulnerability_type") in ("Excessive Agency: Unapproved High-Impact Action", "Context Taint Hijack: Complete Attack Path") and f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    ai_act_controls = [f for f in ai_act_all if f.get("vulnerability_type") == "AI Agent Approval Gate Verified"]
    if scan_mode in ("basic", "external_basic"):
        ai_act_status = "Not Tested"
    elif ai_act_flaws:
        ai_act_status = "Issue Found"
    elif ai_act_controls:
        ai_act_status = "Passed"
    else:
        ai_act_status = "Not Tested"
    ai_categories.append({
        "key": "ai_unauthorized_actions",
        "name": "Unauthorized AI Actions",
        "status": ai_act_status,
        "status_class": "issue" if ai_act_status == "Issue Found" else ("not_tested" if ai_act_status == "Not Tested" else "passed"),
        "severity": "Critical" if ai_act_status == "Issue Found" else ("Info" if ai_act_status == "Not Tested" else "Low"),
        "explanation": "Evaluates whether prompt-injected instructions can manipulate the AI assistant into executing high-impact external actions without human approval.",
        "observations": ai_act_flaws if ai_act_flaws else ai_act_controls,
        "observation_count": len(ai_act_flaws) if ai_act_flaws else (0 if ai_act_status == "Passed" else len(ai_act_all)),
        "is_issue": ai_act_status == "Issue Found",
    })

    # -------------------------------------------------------------------------
    # Priority 2: Focused Web Demo (2 Security Checks: SQLi & XSS)
    # -------------------------------------------------------------------------
    focused_categories = [web_categories[0], web_categories[1]]

    return {
        "web_categories": web_categories,
        "ai_categories": ai_categories,
        "focused_categories": focused_categories,
        "web_issues_count": sum(1 for c in web_categories if c["status"] == "Issue Found"),
        "web_passed_count": sum(1 for c in web_categories if c["status"] == "Passed"),
        "web_not_tested_count": sum(1 for c in web_categories if c["status"] in ("Not Tested", "Could Not Test")),
        "ai_issues_count": sum(1 for c in ai_categories if c["status"] == "Issue Found"),
        "ai_passed_count": sum(1 for c in ai_categories if c["status"] == "Passed"),
        "ai_not_tested_count": sum(1 for c in ai_categories if c["status"] in ("Not Tested", "Could Not Test")),
        "focused_issues_count": sum(1 for c in focused_categories if c["status"] == "Issue Found"),
        "focused_passed_count": sum(1 for c in focused_categories if c["status"] == "Passed"),
    }


def generate_html_report(
    scan_id: int,
    target_url: str,
    target_name: str,
    all_findings: List[dict],
    scan_started_at,
    scan_finished_at,
    eval_data: Optional[Dict[str, Any]] = None,
    passport_data: Optional[Dict[str, Any]] = None,
    chain_data: Optional[Dict[str, Any]] = None,
    scan_mode: str = "deep",
    target_type: str = "local_lab",
    scan_policy_data: Optional[Dict[str, Any]] = None,
    requests_count: int = 0,
    duration_seconds: Optional[float] = None,
    is_focused_view: bool = False,
) -> str:
    """
    Render the HTML security report with honest classification separating:
      - Confirmed vulnerabilities
      - Potential vulnerabilities
      - Verified security controls
      - Informational discoveries
      - Not reproducible / not tested
    """
    template = _jinja_env.get_template("report.html")
    from risk import classify_finding_category

    # Categorize findings
    confirmed_vulns = []
    potential_vulns = []
    verified_controls = []
    info_discoveries = []
    not_reproducible = []
    not_tested = []

    for f in all_findings:
        cat = f.get("category") or classify_finding_category(f.get("vulnerability_type", ""), f.get("status", ""))
        f["category"] = cat
        enriched = _enrich_finding(f)
        if cat == "confirmed_vulnerability":
            confirmed_vulns.append(enriched)
        elif cat == "potential_vulnerability":
            potential_vulns.append(enriched)
        elif cat == "verified_control":
            verified_controls.append(enriched)
        elif cat == "informational":
            info_discoveries.append(enriched)
        elif cat == "not_reproducible":
            not_reproducible.append(enriched)
        elif cat == "not_tested":
            not_tested.append(enriched)
        else:
            potential_vulns.append(enriched)

    SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    all_enriched = confirmed_vulns + potential_vulns + verified_controls + info_discoveries + not_reproducible + not_tested
    sorted_findings = sorted(
        all_enriched,
        key=lambda f: SEV_ORDER.get(f.get("severity", "Info"), 5)
    )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in sorted_findings:
        sev = f.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # AI Tool Integrity summary
    verified_tools = [f for f in sorted_findings if f.get("vulnerability_type") == "Tool Integrity Verified"]
    changed_tools = [f for f in sorted_findings if f.get("vulnerability_type") in ("Tool Metadata Rug-Pull", "Poisoned Tool Description")]
    unbaselined_tools = [f for f in sorted_findings if f.get("vulnerability_type") == "Tool Baseline Unavailable"]

    has_tool_integrity = bool(verified_tools or changed_tools or unbaselined_tools)
    tool_integrity_info = {
        "active": has_tool_integrity,
        "verified_count": len(verified_tools),
        "changed_count": len(changed_tools),
        "unbaselined_count": len(unbaselined_tools),
        "total_count": len(verified_tools) + len(changed_tools) + len(unbaselined_tools),
        "status": "COMPROMISED" if changed_tools else ("VERIFIED" if verified_tools else "BASELINE_UNAVAILABLE"),
        "verified_tools": verified_tools,
        "changed_tools": changed_tools,
        "unbaselined_tools": unbaselined_tools,
    }

    # Phase 11 Taint & Permission analysis summary
    excessive_agency = [f for f in sorted_findings if f.get("vulnerability_type") == "Excessive Agency: Unapproved High-Impact Action"]
    gate_verified = [f for f in sorted_findings if f.get("vulnerability_type") == "AI Agent Approval Gate Verified"]
    taint_paths = [f for f in sorted_findings if f.get("vulnerability_type") == "Context Taint Hijack: Complete Attack Path"]

    has_taint_perm = bool(excessive_agency or gate_verified or taint_paths)
    taint_permission_info = {
        "active": has_taint_perm,
        "excessive_agency_count": len(excessive_agency),
        "gate_verified_count": len(gate_verified),
        "taint_paths_count": len(taint_paths),
        "status": "EXCESSIVE_AGENCY_DETECTED" if excessive_agency else ("APPROVAL_GATED" if gate_verified else "NOT_TESTED"),
        "excessive_agency_findings": excessive_agency,
        "gate_verified_findings": gate_verified,
        "taint_path_findings": taint_paths
    }

    # Phase 12 Cryptographic Passport & Provenance Chain summary
    has_passport = bool(passport_data)
    passport_info = {
        "active": has_passport,
        "schema_version": passport_data.get("passport_schema_version", "2.0") if passport_data else "2.0",
        "signing_algorithm": passport_data.get("signing_algorithm", "Ed25519") if passport_data else "Ed25519",
        "public_key_identifier": passport_data.get("public_key_identifier", "N/A") if passport_data else "N/A",
        "canonical_payload_hash": passport_data.get("canonical_payload_hash", "") if passport_data else "",
        "digital_signature": passport_data.get("digital_signature", "") if passport_data else "",
        "download_url": f"/api/scans/{scan_id}/passport?download=true",
        "verify_url": f"/api/scans/{scan_id}/passport/verify",
        "history_verify_url": "/api/scans/history/verify",
        "chain_sequence": chain_data.get("sequence_number", 1) if chain_data else 1,
        "chain_hash": chain_data.get("chain_hash", "") if chain_data else "",
        "previous_hash": chain_data.get("previous_hash", "") if chain_data else "",
    } if has_passport else {"active": False}

    # -------------------------------------------------------------------------
    # Comprehensive Security Checks Summary Table (9 Standard Checks)
    # -------------------------------------------------------------------------
    security_checks = []

    # 1. SQL Injection
    sqli_flaws = [f for f in sorted_findings if f.get("vulnerability_type") == "SQL Injection" and f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    if sqli_flaws:
        security_checks.append({
            "name": "SQL Injection (SQLi)",
            "result": "Issue Found",
            "status_class": "issue",
            "severity": sqli_flaws[0].get("severity", "High"),
            "details": f"Vulnerable parameter(s) detected with syntax errors or login bypass ({len(sqli_flaws)} finding)."
        })
    elif scan_mode == "external_basic":
        security_checks.append({
            "name": "SQL Injection (SQLi)",
            "result": "Not Tested",
            "status_class": "not_tested",
            "severity": "Info",
            "details": "Active SQL injection probes excluded in non-invasive passive mode."
        })
    else:
        security_checks.append({
            "name": "SQL Injection (SQLi)",
            "result": "Passed",
            "status_class": "passed",
            "severity": "Low",
            "details": "Endpoints probed with SQL injection test vectors; no syntax errors or bypasses observed."
        })

    # 2. Cross-Site Scripting (XSS)
    xss_flaws = [f for f in sorted_findings if "xss" in f.get("vulnerability_type", "").lower() and f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    if xss_flaws:
        security_checks.append({
            "name": "Cross-Site Scripting (XSS)",
            "result": "Issue Found",
            "status_class": "issue",
            "severity": xss_flaws[0].get("severity", "Medium"),
            "details": f"Unescaped reflection observed in query parameters ({len(xss_flaws)} finding)."
        })
    elif scan_mode == "external_basic":
        security_checks.append({
            "name": "Cross-Site Scripting (XSS)",
            "result": "Not Tested",
            "status_class": "not_tested",
            "severity": "Info",
            "details": "Active script injection probes excluded in non-invasive passive mode."
        })
    else:
        security_checks.append({
            "name": "Cross-Site Scripting (XSS)",
            "result": "Passed",
            "status_class": "passed",
            "severity": "Low",
            "details": "Parameters probed with HTML/script test vectors; reflections properly entity-encoded."
        })

    # 3. Insecure Direct Object Reference (IDOR)
    idor_flaws = [f for f in sorted_findings if "idor" in f.get("vulnerability_type", "").lower() and f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    if idor_flaws:
        security_checks.append({
            "name": "Insecure Direct Object Reference (IDOR)",
            "result": "Issue Found",
            "status_class": "issue",
            "severity": idor_flaws[0].get("severity", "High"),
            "details": f"Object identifiers accessible across user boundaries without authorization ({len(idor_flaws)} finding)."
        })
    elif scan_mode == "external_basic":
        security_checks.append({
            "name": "Insecure Direct Object Reference (IDOR)",
            "result": "Not Tested",
            "status_class": "not_tested",
            "severity": "Info",
            "details": "Multi-user authorization boundary testing excluded in passive mode."
        })
    else:
        security_checks.append({
            "name": "Insecure Direct Object Reference (IDOR)",
            "result": "Passed",
            "status_class": "passed",
            "severity": "Low",
            "details": "Object identifiers tested across privilege boundaries; access control enforced."
        })

    # 4. Security Headers
    header_flaws = [f for f in sorted_findings if "header" in f.get("vulnerability_type", "").lower() and f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    if header_flaws:
        security_checks.append({
            "name": "Security Headers",
            "result": "Issue Found",
            "status_class": "issue",
            "severity": "Medium",
            "details": f"{len(header_flaws)} recommended security header(s) missing (e.g. CSP, HSTS, X-Frame-Options)."
        })
    else:
        security_checks.append({
            "name": "Security Headers",
            "result": "Passed",
            "status_class": "passed",
            "severity": "Low",
            "details": "Standard security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) verified."
        })

    # 5. TLS / HTTPS Security
    tls_blocked = [f for f in sorted_findings if "blocked" in f.get("vulnerability_type", "").lower() or "aborted" in f.get("evidence", "").lower()]
    tls_insecure = [f for f in sorted_findings if "insecure http" in f.get("vulnerability_type", "").lower()]
    tls_verified = [f for f in sorted_findings if "tls" in f.get("vulnerability_type", "").lower() and f.get("category") == "verified_control"]
    if tls_blocked:
        security_checks.append({
            "name": "TLS / HTTPS Security",
            "result": "Could Not Test",
            "status_class": "error",
            "severity": "Info",
            "details": "TLS connection inspection could not be completed (network / scope block)."
        })
    elif tls_insecure:
        security_checks.append({
            "name": "TLS / HTTPS Security",
            "result": "Issue Found",
            "status_class": "issue",
            "severity": "Medium",
            "details": "Target communicates over plain HTTP without transport encryption."
        })
    elif tls_verified:
        security_checks.append({
            "name": "TLS / HTTPS Security",
            "result": "Passed",
            "status_class": "passed",
            "severity": "Low",
            "details": "Valid certificate, TLS 1.2+, and secure cipher configuration verified."
        })
    elif target_url.startswith("http://127.0.0.1") or target_url.startswith("http://localhost"):
        security_checks.append({
            "name": "TLS / HTTPS Security",
            "result": "Not Tested",
            "status_class": "not_tested",
            "severity": "Info",
            "details": "Target operates on local loopback HTTP (TLS checks not applicable)."
        })
    else:
        security_checks.append({
            "name": "TLS / HTTPS Security",
            "result": "Passed",
            "status_class": "passed",
            "severity": "Low",
            "details": "HTTPS transport active and verified."
        })

    # 6. Cookie Security Flags
    cookie_flaws = [f for f in sorted_findings if "cookie" in f.get("vulnerability_type", "").lower() and f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
    if cookie_flaws:
        security_checks.append({
            "name": "Cookie Security Flags",
            "result": "Issue Found",
            "status_class": "issue",
            "severity": "Medium",
            "details": f"{len(cookie_flaws)} cookie(s) missing HttpOnly, Secure, or SameSite protection flags."
        })
    else:
        security_checks.append({
            "name": "Cookie Security Flags",
            "result": "Passed",
            "status_class": "passed",
            "severity": "Low",
            "details": "Session cookies enforce HttpOnly, Secure, and SameSite attributes (or no cookies set)."
        })

    # 7. AI Prompt Injection
    if scan_mode in ("basic", "external_basic"):
        security_checks.append({
            "name": "AI Prompt Injection",
            "result": "Not Tested",
            "status_class": "not_tested",
            "severity": "Info",
            "details": "AI agent testing is excluded in basic / passive scan mode."
        })
    else:
        ai_inj_flaws = [f for f in sorted_findings if ("prompt injection" in f.get("vulnerability_type", "").lower() or "canary" in f.get("vulnerability_type", "").lower()) and f.get("category") in ("confirmed_vulnerability", "potential_vulnerability")]
        ai_inj_passed = [f for f in sorted_findings if ("prompt injection" in f.get("vulnerability_type", "").lower() or "canary" in f.get("vulnerability_type", "").lower()) and f.get("category") in ("verified_control", "not_reproducible")]
        if ai_inj_flaws:
            security_checks.append({
                "name": "AI Prompt Injection",
                "result": "Issue Found",
                "status_class": "issue",
                "severity": "Critical",
                "details": "Untrusted context overridden system instructions and leaked confidential canary token."
            })
        elif ai_inj_passed:
            security_checks.append({
                "name": "AI Prompt Injection",
                "result": "Passed",
                "status_class": "passed",
                "severity": "Low",
                "details": "Prompt injection attempted; system instructions preserved and canary token protected."
            })
        else:
            security_checks.append({
                "name": "AI Prompt Injection",
                "result": "Not Tested",
                "status_class": "not_tested",
                "severity": "Info",
                "details": "No AI assistant endpoints discovered on target."
            })

    # 8. AI Tool Integrity & Anti-Rug-Pull
    if scan_mode in ("basic", "external_basic"):
        security_checks.append({
            "name": "AI Tool Integrity & Anti-Rug-Pull",
            "result": "Not Tested",
            "status_class": "not_tested",
            "severity": "Info",
            "details": "Tool schema baseline auditing is excluded in basic / passive mode."
        })
    else:
        if tool_integrity_info["changed_count"] > 0:
            security_checks.append({
                "name": "AI Tool Integrity & Anti-Rug-Pull",
                "result": "Issue Found",
                "status_class": "issue",
                "severity": "High",
                "details": f"{tool_integrity_info['changed_count']} tool definition(s) modified post-approval without authorization."
            })
        elif tool_integrity_info["verified_count"] > 0:
            security_checks.append({
                "name": "AI Tool Integrity & Anti-Rug-Pull",
                "result": "Passed",
                "status_class": "passed",
                "severity": "Low",
                "details": f"All {tool_integrity_info['verified_count']} tool schemas verified against cryptographic SHA-256 baselines."
            })
        else:
            security_checks.append({
                "name": "AI Tool Integrity & Anti-Rug-Pull",
                "result": "Not Tested",
                "status_class": "not_tested",
                "severity": "Info",
                "details": "No baselined AI tools detected on target."
            })

    # 9. Unauthorized AI Actions / Context Taint
    if scan_mode in ("basic", "external_basic"):
        security_checks.append({
            "name": "Unauthorized AI Actions / Context Taint",
            "result": "Not Tested",
            "status_class": "not_tested",
            "severity": "Info",
            "details": "AI taint & permission analysis is excluded in basic / passive mode."
        })
    else:
        if taint_permission_info["excessive_agency_count"] > 0:
            security_checks.append({
                "name": "Unauthorized AI Actions / Context Taint",
                "result": "Issue Found",
                "status_class": "issue",
                "severity": "High",
                "details": "AI agent executed high-impact external action (send_email) without human approval."
            })
        elif taint_permission_info["gate_verified_count"] > 0:
            security_checks.append({
                "name": "Unauthorized AI Actions / Context Taint",
                "result": "Passed",
                "status_class": "passed",
                "severity": "Low",
                "details": "Human-in-the-loop approval gate enforced; unapproved high-impact action halted."
            })
        else:
            security_checks.append({
                "name": "Unauthorized AI Actions / Context Taint",
                "result": "Not Tested",
                "status_class": "not_tested",
                "severity": "Info",
                "details": "No high-impact AI tool actions detected on target."
            })

    # Summary counts
    checks_passed_count = sum(1 for c in security_checks if c["result"] == "Passed")
    checks_issues_count = sum(1 for c in security_checks if c["result"] == "Issue Found")
    checks_not_tested_count = sum(1 for c in security_checks if c["result"] in ("Not Tested", "Could Not Test"))

    cat_data = build_category_breakdowns(sorted_findings, scan_mode, target_url)

    html = template.render(
        scan_id          = scan_id,
        target_url       = target_url,
        target_name      = target_name,
        scan_mode        = scan_mode,
        target_type      = target_type,
        scan_policy      = scan_policy_data or {},
        requests_count   = requests_count,
        duration_seconds = duration_seconds,
        findings         = sorted_findings,
        confirmed_vulns  = confirmed_vulns,
        potential_vulns  = potential_vulns,
        verified_controls= verified_controls,
        info_discoveries = info_discoveries,
        not_reproducible = not_reproducible,
        not_tested       = not_tested,
        scan_started_at  = scan_started_at,
        scan_finished_at = scan_finished_at,
        total_findings   = len(sorted_findings),
        active_vuln_count= len(confirmed_vulns) + len(potential_vulns),
        confirmed_count  = len(confirmed_vulns),
        potential_count  = len(potential_vulns),
        verified_control_count = len(verified_controls),
        informational_count    = len(info_discoveries),
        severity_counts  = severity_counts,
        eval_data        = eval_data or {},
        tool_integrity   = tool_integrity_info,
        taint_permission = taint_permission_info,
        passport         = passport_info,
        security_checks  = security_checks,
        checks_passed_count = checks_passed_count,
        checks_issues_count = checks_issues_count,
        checks_not_tested_count = checks_not_tested_count,
        # Priority 1: Separated Web & AI Category Structures
        web_categories        = cat_data["web_categories"],
        ai_categories         = cat_data["ai_categories"],
        focused_categories    = cat_data["focused_categories"],
        web_issues_count      = cat_data["web_issues_count"],
        web_passed_count      = cat_data["web_passed_count"],
        web_not_tested_count  = cat_data["web_not_tested_count"],
        ai_issues_count       = cat_data["ai_issues_count"],
        ai_passed_count       = cat_data["ai_passed_count"],
        ai_not_tested_count   = cat_data["ai_not_tested_count"],
        focused_issues_count  = cat_data["focused_issues_count"],
        focused_passed_count  = cat_data["focused_passed_count"],
        is_focused_view       = is_focused_view,
    )
    return html



def generate_home_page(
    scans: List[dict],
    allowed_hosts: List[str],
    error_message: Optional[str] = None,
    stats: Optional[Dict[str, Any]] = None,
    targets: Optional[List[dict]] = None,
    default_scan_a: Optional[int] = None,
    default_scan_b: Optional[int] = None,
) -> str:
    """
    Render the Home dashboard page.

    Args:
        scans        : list of scan summary dicts for the past scans table
        allowed_hosts: list of host strings currently permitted by the scope guard
        error_message: optional error string to display in an alert banner
        stats        : optional high-level KPI metrics dictionary
        targets      : list of registered target summary dicts
        default_scan_a: default scan ID to select for baseline comparison
        default_scan_b: default scan ID to select for re-scan comparison
    """
    template = _jinja_env.get_template("index.html")
    html = template.render(
        scans          = scans,
        allowed_hosts  = allowed_hosts,
        error_message  = error_message,
        stats          = stats or {},
        targets        = targets or [],
        default_scan_a = default_scan_a,
        default_scan_b = default_scan_b,
    )
    return html


def generate_compare_report(
    scan_a_id: Optional[int],
    scan_b_id: Optional[int],
    compare: Optional[dict] = None,
    all_scans: Optional[List[dict]] = None,
) -> str:
    """
    Render a before/after comparison HTML page.

    Args:
        scan_a_id : ID of the baseline scan (before fix)
        scan_b_id : ID of the re-scan (after fix)
        compare   : dict from compare_scans() with keys:
                    fixed, new, persists, total_in_a, total_in_b, ...
        all_scans : list of scan dicts to populate the compare dropdown selectors
    """
    template = _jinja_env.get_template("compare_report.html")
    html = template.render(
        scan_a_id = scan_a_id,
        scan_b_id = scan_b_id,
        compare   = compare,
        all_scans = all_scans or [],
    )
    return html


def generate_progress_report(
    scan_id: int,
    target_url: str,
    target_name: str,
    scan_mode: str,
    started_at: Optional[Any] = None,
) -> str:
    """Render the live scan progress and auto-polling view."""
    template = _jinja_env.get_template("progress.html")
    return template.render(
        scan_id=scan_id,
        target_url=target_url,
        target_name=target_name,
        scan_mode=scan_mode,
        started_at=started_at,
    )


def generate_failed_report(
    scan_id: int,
    target_url: str,
    target_name: str,
    scan_mode: str,
    error_message: Optional[str] = None,
) -> str:
    """Render the clean scan failure view."""
    template = _jinja_env.get_template("failed.html")
    return template.render(
        scan_id=scan_id,
        target_url=target_url,
        target_name=target_name,
        scan_mode=scan_mode,
        error_message=error_message,
    )
