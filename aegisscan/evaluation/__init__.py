"""
evaluation/__init__.py -- AegisScan Evaluation Harness 2.0 (Phase 13)
======================================================================
Measures the scanner's accuracy against AegisLab's known ground truth.

Ground Truth Architecture:
1. TRADITIONAL_GROUND_TRUTH:
   9 intentional Layer 1 web flaws (SQLi on /login, XSS on /search, IDOR on /user/profile,
   4 missing security headers, 2 insecure cookie flags).
2. AI_AGENT_GROUND_TRUTH:
   Intentional AI-agent vulnerabilities (Indirect Prompt Injection on /assistant/query,
   AI Canary Token Disclosure, Reflected XSS on /assistant, Excessive Agency Unapproved Actions,
   Tool Metadata Rug-Pull/Poisoning).
3. BENIGN_CONTROLS_GROUND_TRUTH:
   Known safe controls/decoys (Decoy login, Decoy product, Benign whitepaper doc-03, Calculate utility).
   Correctly rejecting/defending these contributes to True Negatives (TN).

Investigation of Pre- vs Post-Validation Precision:
- Prior reports noted an apparent decrease in precision from pre-validation (81.8%) to
  post-validation (56.2%).
- Root Cause Identified: Denominator mismatch & ground-truth omission.
  The pre-validation list only passed Layer 1 detectors, while post-validation passed all findings
  including AI features (Phase 7-11) and verified controls. Because the static ground-truth table
  only had Layer 1 vulnerabilities, real AI findings and verified security controls were incorrectly
  counted as False Positives.
- In Evaluation 2.0, findings are correctly classified, non-vulnerability controls are excluded from
  vulnerability false positives, and metrics are computed cleanly for Traditional, AI, and Combined scopes.
"""

import json
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Set, Tuple
from sqlalchemy.orm import Session

from models import EvaluationRun

# ---------------------------------------------------------------------------
# Finding Classification Types
# ---------------------------------------------------------------------------
INFORMATIONAL_TYPES = {
    "AI Assistant Discovered",
    "AI Security Manifest Detected",
    "Tool Baseline Unavailable",
}

VERIFIED_CONTROL_TYPES = {
    "Tool Integrity Verified",
    "AI Agent Approval Gate Verified",
}


# ---------------------------------------------------------------------------
# 1. Traditional Ground Truth (Layer 1 Web Flaws)
# ---------------------------------------------------------------------------
TRADITIONAL_GROUND_TRUTH: List[Dict[str, Any]] = [
    {
        "name": "SQL Injection on /login",
        "type": "SQL Injection",
        "path_prefix": "/login",
        "category": "traditional",
    },
    {
        "name": "Reflected XSS on /search",
        "type": "Reflected XSS",
        "path_prefix": "/search",
        "category": "traditional",
    },
    {
        "name": "IDOR on /user/profile",
        "type": "IDOR (Broken Access Control)",
        "path_prefix": "/user/profile",
        "category": "traditional",
    },
    {
        "name": "Missing Content-Security-Policy header",
        "type": "Missing Security Header",
        "path_prefix": "/",
        "header_name": "Content-Security-Policy",
        "category": "traditional",
    },
    {
        "name": "Missing Strict-Transport-Security header",
        "type": "Missing Security Header",
        "path_prefix": "/",
        "header_name": "Strict-Transport-Security",
        "category": "traditional",
    },
    {
        "name": "Missing X-Frame-Options header",
        "type": "Missing Security Header",
        "path_prefix": "/",
        "header_name": "X-Frame-Options",
        "category": "traditional",
    },
    {
        "name": "Missing X-Content-Type-Options header",
        "type": "Missing Security Header",
        "path_prefix": "/",
        "header_name": "X-Content-Type-Options",
        "category": "traditional",
    },
    {
        "name": "Insecure Cookie: missing HttpOnly flag",
        "type": "Insecure Cookie",
        "path_prefix": "/",
        "flag": "HttpOnly",
        "category": "traditional",
    },
    {
        "name": "Insecure Cookie: missing Secure flag",
        "type": "Insecure Cookie",
        "path_prefix": "/",
        "flag": "Secure",
        "category": "traditional",
    },
]


# ---------------------------------------------------------------------------
# 2. AI-Agent Ground Truth (Phase 7-11 AI Agent Security Flaws)
# ---------------------------------------------------------------------------
AI_AGENT_GROUND_TRUTH: List[Dict[str, Any]] = [
    {
        "name": "Reflected XSS on /assistant",
        "type": "Reflected XSS",
        "path_prefix": "/assistant",
        "category": "ai_agent",
    },
    {
        "name": "Indirect Prompt Injection on /assistant/query",
        "type": "Indirect Prompt Injection",
        "path_prefix": "/assistant",
        "category": "ai_agent",
    },
    {
        "name": "AI Canary Token Leakage on /assistant/query",
        "type": "AI Canary Token Leakage",
        "path_prefix": "/assistant",
        "category": "ai_agent",
    },
    {
        "name": "Excessive Agency: Unapproved High-Impact Action",
        "type": "Excessive Agency: Unapproved High-Impact Action",
        "path_prefix": "/assistant",
        "category": "ai_agent",
    },
    {
        "name": "Tool Metadata Rug-Pull on /assistant/tools",
        "type": "Tool Metadata Rug-Pull",
        "path_prefix": "/assistant",
        "category": "ai_agent",
    },
    {
        "name": "Poisoned Tool Description on /assistant/tools",
        "type": "Poisoned Tool Description",
        "path_prefix": "/assistant",
        "category": "ai_agent",
    },
]

# Combined Ground Truth (full answer key)
AEGISLAB_GROUND_TRUTH: List[Dict[str, Any]] = TRADITIONAL_GROUND_TRUTH + AI_AGENT_GROUND_TRUTH

# Known Benign Decoy Controls for True Negative (TN) Assessment
BENIGN_DECOY_CONTROLS: List[Dict[str, str]] = [
    {"name": "Decoy Login (/decoy/login)", "path": "/decoy/login"},
    {"name": "Decoy Product Catalogue (/decoy/product)", "path": "/decoy/product"},
    {"name": "Benign AI Document (doc-03 Whitepaper)", "path": "/assistant/documents"},
    {"name": "Safe Utility Tool (calculate)", "path": "/assistant/tools"},
]


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------
def _location_path(location: str) -> str:
    """Extract clean URL path from finding location string."""
    clean = (location or "").split(" (")[0].strip()
    try:
        return urlparse(clean).path or "/"
    except Exception:
        return "/"


def _matches_ground_truth(
    finding_type: str,
    finding_path: str,
    finding_evidence: str,
    gt_item: Dict[str, Any]
) -> bool:
    """Check if finding attributes match ground-truth entry."""
    if finding_type != gt_item["type"]:
        return False

    # Path prefix match
    path_prefix = gt_item.get("path_prefix", "/")
    if path_prefix != "/" and not finding_path.startswith(path_prefix):
        return False

    # Extra specificity for header findings
    if "header_name" in gt_item:
        if gt_item["header_name"].lower() not in (finding_evidence or "").lower():
            return False

    # Extra specificity for cookie findings
    if "flag" in gt_item:
        if gt_item["flag"].lower() not in (finding_evidence or "").lower():
            return False

    return True


# ---------------------------------------------------------------------------
# Evaluation Engine 2.0
# ---------------------------------------------------------------------------
def evaluate_scan(
    findings: List[Dict[str, Any]],
    stage: str,
    scan_id: int,
    db: Session,
    scope: str = "all",
) -> EvaluationRun:
    """
    Evaluates findings against AegisLab ground truth.

    Args:
        findings : list of finding dicts
        stage    : 'pre_validation', 'post_validation', 'traditional', or 'ai_agent'
        scan_id  : integer scan ID
        db       : database session
        scope    : 'all', 'traditional', or 'ai_agent'
    """
    # Select appropriate ground truth subset
    if scope == "traditional":
        ground_truth = TRADITIONAL_GROUND_TRUTH
    elif scope == "ai_agent":
        ground_truth = AI_AGENT_GROUND_TRUTH
    else:
        ground_truth = AEGISLAB_GROUND_TRUTH

    matched_gt_indices: Set[int] = set()
    tp_names: List[str] = []
    fp_names: List[str] = []

    # Separate findings by category
    for f in findings:
        f_type = f.get("vulnerability_type", "")
        f_status = f.get("status", "potential")
        f_path = _location_path(f.get("location", ""))
        f_evidence = f.get("evidence", "")

        # Skip informational discoveries & verified controls from vulnerability FP/TP counting
        if f_type in INFORMATIONAL_TYPES or f_type in VERIFIED_CONTROL_TYPES:
            continue

        # In post_validation, evaluate confirmed vulnerabilities only
        if stage in ("post_validation", "confirmed_only") and f_status != "confirmed":
            continue

        # If evaluating a specific scope, filter findings
        if scope == "traditional":
            if f_type in ("Indirect Prompt Injection", "AI Canary Token Leakage",
                           "Excessive Agency: Unapproved High-Impact Action",
                           "Tool Metadata Rug-Pull", "Poisoned Tool Description") or "/assistant" in f_path:
                continue
        elif scope == "ai_agent":
            if f_type in ("SQL Injection", "Reflected XSS", "IDOR (Broken Access Control)", "Missing Security Header", "Insecure Cookie") and "/assistant" not in f_path:
                continue

        matched = False
        for idx, gt in enumerate(ground_truth):
            if _matches_ground_truth(f_type, f_path, f_evidence, gt):
                if idx not in matched_gt_indices:
                    matched_gt_indices.add(idx)
                    tp_names.append(f"{gt['name']} [found at {f.get('location','?')[:60]}]")
                else:
                    fp_names.append(
                        f"{f_type} at {f.get('location','?')[:60]} (duplicate match for '{gt['name']}')"
                    )
                matched = True
                break

        if not matched:
            fp_names.append(f"{f_type} at {f.get('location','?')[:60]}")

    # False Negatives: Ground-truth items that were not detected
    fn_names: List[str] = [
        ground_truth[i]["name"]
        for i in range(len(ground_truth))
        if i not in matched_gt_indices
    ]

    # True Negatives: Known benign decoy controls that were defended/not reported as confirmed vulns
    tn_count = 0
    confirmed_locations = {
        _location_path(f.get("location", ""))
        for f in findings if f.get("status") == "confirmed"
    }
    for b in BENIGN_DECOY_CONTROLS:
        if b["path"] not in confirmed_locations:
            tn_count += 1

    tp = len(tp_names)
    fp = len(fp_names)
    fn = len(fn_names)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    eval_run = EvaluationRun(
        scan_id=scan_id,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn_count,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        stage=stage,
        tp_list=json.dumps(tp_names),
        fp_list=json.dumps(fp_names),
        fn_list=json.dumps(fn_names),
    )
    db.add(eval_run)
    db.commit()
    db.refresh(eval_run)

    print(
        f"  [Eval/{stage}:{scope}] TP={tp} FP={fp} FN={fn} TN={tn_count} "
        f"P={precision:.1%} R={recall:.1%} F1={f1:.1%}"
    )

    return eval_run
