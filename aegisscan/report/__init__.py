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
        if cat == "confirmed_vulnerability":
            confirmed_vulns.append(f)
        elif cat == "potential_vulnerability":
            potential_vulns.append(f)
        elif cat == "verified_control":
            verified_controls.append(f)
        elif cat == "informational":
            info_discoveries.append(f)
        elif cat == "not_reproducible":
            not_reproducible.append(f)
        elif cat == "not_tested":
            not_tested.append(f)
        else:
            potential_vulns.append(f)

    SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(
        all_findings,
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
    )
    return html



def generate_home_page(
    scans: List[dict],
    allowed_hosts: List[str],
    error_message: Optional[str] = None,
    stats: Optional[Dict[str, Any]] = None,
    targets: Optional[List[dict]] = None,
) -> str:
    """
    Render the Home dashboard page.

    Args:
        scans        : list of scan summary dicts for the past scans table
        allowed_hosts: list of host strings currently permitted by the scope guard
        error_message: optional error string to display in an alert banner
        stats        : optional high-level KPI metrics dictionary
        targets      : list of registered target summary dicts
    """
    template = _jinja_env.get_template("index.html")
    html = template.render(
        scans         = scans,
        allowed_hosts = allowed_hosts,
        error_message = error_message,
        stats         = stats or {},
        targets       = targets or [],
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