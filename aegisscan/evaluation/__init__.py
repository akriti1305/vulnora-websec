"""
evaluation/__init__.py -- AegisScan Evaluation Harness
=======================================================
Measures the scanner's accuracy against AegisLab's known ground truth.

Ground truth (the "answer key"):
  These are the KNOWN vulnerabilities intentionally built into AegisLab.
  Every finding that matches one of these is a True Positive (TP).
  Every finding that does NOT match is a False Positive (FP).
  Every known flaw NOT found by the scanner is a False Negative (FN).

Matching rule:
  A finding matches a ground-truth item if BOTH match:
    - vulnerability_type  (e.g. "SQL Injection")
    - location path prefix (e.g. "/login")
  We use the path portion only (not query string, not full host)
  so the match works regardless of port, host, or query string.

Metrics computed:
  Precision = TP / (TP + FP)  -- of what the scanner reported, how much was right?
  Recall    = TP / (TP + FN)  -- of the known flaws, how many were found?
  F1        = 2 * P * R / (P + R)  -- harmonic mean (balance of P and R)

Called TWICE per scan:
  1. pre_validation  : using all raw findings (before control-request validation)
  2. post_validation : using only confirmed findings

This lets you see what the validation layer changed.
"""

import json
from urllib.parse import urlparse
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from models import EvaluationRun


# ---------------------------------------------------------------------------
# AegisLab Ground Truth -- the "answer key"
# ---------------------------------------------------------------------------
# Each entry is one known vulnerability in AegisLab.
# "path_prefix" matches any finding location that STARTS WITH this path.
# "type" must match finding.vulnerability_type exactly.
#
# HOW TO READ THIS:
#   If the scanner reports a finding with type="SQL Injection" and
#   location containing "/login", that is a True Positive.
#   If it reports type="SQL Injection" on "/search", that is a False Positive
#   (there is no SQLi in /search -- only XSS).
# ---------------------------------------------------------------------------
AEGISLAB_GROUND_TRUTH: List[Dict[str, str]] = [
    {
        "name": "SQL Injection on /login",
        "type": "SQL Injection",
        "path_prefix": "/login",
    },
    {
        "name": "Reflected XSS on /search",
        "type": "Reflected XSS",
        "path_prefix": "/search",
    },
    {
        "name": "IDOR on /user/profile",
        "type": "IDOR (Broken Access Control)",
        "path_prefix": "/user/profile",
    },
    {
        "name": "Missing Content-Security-Policy header",
        "type": "Missing Security Header",
        "path_prefix": "/",          # any page -- headers are app-wide
        "header_name": "Content-Security-Policy",
    },
    {
        "name": "Missing Strict-Transport-Security header",
        "type": "Missing Security Header",
        "path_prefix": "/",
        "header_name": "Strict-Transport-Security",
    },
    {
        "name": "Missing X-Frame-Options header",
        "type": "Missing Security Header",
        "path_prefix": "/",
        "header_name": "X-Frame-Options",
    },
    {
        "name": "Missing X-Content-Type-Options header",
        "type": "Missing Security Header",
        "path_prefix": "/",
        "header_name": "X-Content-Type-Options",
    },
    {
        "name": "Insecure Cookie: missing HttpOnly flag",
        "type": "Insecure Cookie",
        "path_prefix": "/",
        "flag": "HttpOnly",
    },
    {
        "name": "Insecure Cookie: missing Secure flag",
        "type": "Insecure Cookie",
        "path_prefix": "/",
        "flag": "Secure",
    },
]


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _location_path(location: str) -> str:
    """
    Extract the path from a finding location string.

    Handles formats like:
      "http://127.0.0.1:5001/login (field: username)"  -> "/login"
      "http://127.0.0.1:5001/search (field: q)"        -> "/search"
      "http://127.0.0.1:5001/"                          -> "/"
    """
    # Strip the "(field: ...)" or "(param: ...)" annotation
    clean = location.split(" (")[0].strip()
    try:
        return urlparse(clean).path or "/"
    except Exception:
        return "/"


def _matches_ground_truth(finding_type: str, finding_path: str,
                           finding_evidence: str, gt_item: Dict) -> bool:
    """
    Return True if a finding matches a ground-truth entry.

    Basic match: type AND path prefix both match.
    For header findings: also check evidence contains the header name.
    For cookie findings: also check evidence contains the flag name.
    """
    if finding_type != gt_item["type"]:
        return False

    if not finding_path.startswith(gt_item["path_prefix"]):
        return False

    # Extra specificity for header findings
    if "header_name" in gt_item:
        return gt_item["header_name"].lower() in (finding_evidence or "").lower()

    # Extra specificity for cookie findings
    if "flag" in gt_item:
        return gt_item["flag"].lower() in (finding_evidence or "").lower()

    return True


# ---------------------------------------------------------------------------
# Core evaluation function
# ---------------------------------------------------------------------------

def evaluate_scan(
    findings: List[Dict[str, Any]],
    stage: str,
    scan_id: int,
    db: Session,
) -> EvaluationRun:
    """
    Compare a list of findings against the AegisLab ground truth.

    Args:
        findings : list of dicts with keys:
                     vulnerability_type, location, evidence, status
        stage    : "pre_validation" or "post_validation"
        scan_id  : integer scan ID for the DB record
        db       : SQLAlchemy session for saving the EvaluationRun

    Returns:
        EvaluationRun object (already committed to DB)
    """
    # Track which ground-truth items were matched (to find FNs)
    matched_gt_indices: set = set()
    tp_names: List[str] = []
    fp_names: List[str] = []

    for f in findings:
        # Stage 2 (post_validation) evaluates confirmed findings only
        if stage == "post_validation" and f.get("status") != "confirmed":
            continue

        f_type     = f.get("vulnerability_type", "")
        f_path     = _location_path(f.get("location", ""))
        f_evidence = f.get("evidence", "")

        matched = False
        for idx, gt in enumerate(AEGISLAB_GROUND_TRUTH):
            if _matches_ground_truth(f_type, f_path, f_evidence, gt):
                if idx not in matched_gt_indices:
                    matched_gt_indices.add(idx)
                    tp_names.append(f"{gt['name']} [found at {f.get('location','?')[:60]}]")
                # If already matched this GT item, subsequent findings for it are FPs
                else:
                    fp_names.append(
                        f"{f_type} at {f.get('location','?')[:60]} "
                        f"(duplicate match for '{gt['name']}')"
                    )
                matched = True
                break

        if not matched:
            fp_names.append(f"{f_type} at {f.get('location','?')[:60]}")

    # False Negatives: ground-truth items never matched
    fn_names: List[str] = [
        AEGISLAB_GROUND_TRUTH[i]["name"]
        for i in range(len(AEGISLAB_GROUND_TRUTH))
        if i not in matched_gt_indices
    ]

    tp = len(tp_names)
    fp = len(fp_names)
    fn = len(fn_names)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    eval_run = EvaluationRun(
        scan_id         = scan_id,
        true_positives  = tp,
        false_positives = fp,
        false_negatives = fn,
        precision       = round(precision, 4),
        recall          = round(recall, 4),
        f1_score        = round(f1, 4),
        stage           = stage,
        tp_list         = json.dumps(tp_names),
        fp_list         = json.dumps(fp_names),
        fn_list         = json.dumps(fn_names),
    )
    db.add(eval_run)
    db.commit()
    db.refresh(eval_run)

    print(
        f"  [Eval/{stage}] TP={tp} FP={fp} FN={fn} "
        f"P={precision:.1%} R={recall:.1%} F1={f1:.1%}"
    )

    return eval_run
