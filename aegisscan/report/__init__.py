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
) -> str:
    """
    Render the HTML security report.

    Args:
        scan_id, target_url, target_name : scan metadata
        all_findings  : list of finding dicts (vulnerability_type, severity,
                         status, location, evidence, payload, remediation)
        scan_started_at, scan_finished_at : datetime objects
        eval_data     : dict keyed by stage ("pre_validation"/"post_validation")
                        each value has precision, recall, f1, TP, FP, FN,
                        tp_list, fp_list, fn_list
    """
    template = _jinja_env.get_template("report.html")

    SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(
        all_findings,
        key=lambda f: SEV_ORDER.get(f.get("severity", "Info"), 5)
    )

    confirmed_count = sum(1 for f in sorted_findings if f.get("status") == "confirmed")
    severity_counts = {}
    for f in sorted_findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    html = template.render(
        scan_id          = scan_id,
        target_url       = target_url,
        target_name      = target_name,
        findings         = sorted_findings,
        scan_started_at  = scan_started_at,
        scan_finished_at = scan_finished_at,
        total_findings   = len(sorted_findings),
        confirmed_count  = confirmed_count,
        severity_counts  = severity_counts,
        eval_data        = eval_data or {},
    )
    return html


def generate_home_page(
    scans: List[dict],
    allowed_hosts: List[str],
    error_message: Optional[str] = None,
) -> str:
    """
    Render the Home dashboard page.

    Args:
        scans        : list of scan summary dicts for the past scans table
        allowed_hosts: list of host strings currently permitted by the scope guard
        error_message: optional error string to display in an alert banner
    """
    template = _jinja_env.get_template("index.html")
    html = template.render(
        scans         = scans,
        allowed_hosts = allowed_hosts,
        error_message = error_message,
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